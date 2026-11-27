/*
 * hx_compile.c - compile hx AST to bytecode
 *
 * Single recursive walk of the AST, emitting instructions into a
 * growable array.  Variable names are resolved to slot indices,
 * function names are looked up in the registry, and the four
 * output-role suffixes (`_bin`, `_hex`, `_b64`, `_mcf`, `_uc`) are stripped
 * and recorded as an `enum hx_role` value on the OP_CALL instruction.
 *
 * Suffix-validation: the registry entry advertises a `supported_roles`
 * bitmask; applying an unsupported suffix yields a compile-time error.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hx_ast.h"
#include "hx_vm.h"

/* ---- compiler state ---- */

typedef struct {
	hx_inst *code;
	int      ncode;
	int      code_cap;

	char   **strings;
	int     *strlens;
	int      nstrings;
	int      str_cap;

	char   **varnames;
	int      nvars;
	int      var_cap;

	int      depth;         /* current stack depth (for max_stack) */
	int      max_depth;
	int      has_emit;      /* set if emit() is called */
	int      uses_groups;   /* set if a loop iterates charsets() */
	int      text_loop;     /* set if a for ... in loop was unrolled */

	/* for cs in (...): the loop variables in scope and their current
	 * encoding names, innermost last (hx-functions.md 19.1) */
	const char *lv_name[16];
	const char *lv_val[16];
	int      nlv;
} compile_ctx;

/*
 * Does this AST node, when compiled as a statement, push a value onto
 * the runtime stack?  Used by HX_BLOCK compilation to know whether to
 * emit OP_POP after a statement.
 *
 * Value-producing: literals, variables, concatenations, function calls,
 * iter calls.
 *
 * Non-producing: assignments (STORE pops), control-flow (for, if), nested
 * blocks, raw binops (only valid inside conditions, never reached here).
 */
static int node_produces_value(const hx_node *n)
{
	if (!n) return 0;
	switch (n->type) {
	case HX_LITERAL:
	case HX_NUMBER:
	case HX_VARIABLE:
	case HX_CONCAT:
	case HX_FUNCALL:
	case HX_ITER:
		return 1;
	case HX_ASSIGN:
	case HX_FOR:
	case HX_IF:
	case HX_BLOCK:
	case HX_BINOP:
	default:
		return 0;
	}
}

static void emit(compile_ctx *c, hx_inst inst)
{
	if (c->ncode >= c->code_cap) {
		c->code_cap = c->code_cap ? c->code_cap * 2 : 64;
		c->code = realloc(c->code, c->code_cap * sizeof(hx_inst));
	}
	c->code[c->ncode++] = inst;
}

static int add_string(compile_ctx *c, const char *s, int len)
{
	int i;
	/* dedup */
	for (i = 0; i < c->nstrings; i++)
		if (c->strlens[i] == len && memcmp(c->strings[i], s, len) == 0)
			return i;

	if (c->nstrings >= c->str_cap) {
		c->str_cap = c->str_cap ? c->str_cap * 2 : 16;
		c->strings = realloc(c->strings, c->str_cap * sizeof(char *));
		c->strlens = realloc(c->strlens, c->str_cap * sizeof(int));
	}
	c->strings[c->nstrings] = strndup(s, len);
	c->strlens[c->nstrings] = len;
	return c->nstrings++;
}

static int resolve_var(compile_ctx *c, const char *name)
{
	int i;
	/* check built-ins */
	if (strcmp(name, "pass")   == 0) return HX_SLOT_PASS;
	if (strcmp(name, "salt")   == 0) return HX_SLOT_SALT;
	if (strcmp(name, "salt2")  == 0) return HX_SLOT_SALT2;
	if (strcmp(name, "pepper") == 0) return HX_SLOT_PEPPER;
	if (strcmp(name, "user")   == 0) return HX_SLOT_USERID;

	/* search existing user-defined vars */
	for (i = HX_SLOT_USERVARS; i < c->nvars; i++)
		if (strcmp(c->varnames[i], name) == 0)
			return i;

	/* allocate new slot */
	if (c->nvars >= c->var_cap) {
		c->var_cap = c->var_cap ? c->var_cap * 2 : 16;
		c->varnames = realloc(c->varnames, c->var_cap * sizeof(char *));
	}
	i = c->nvars++;
	c->varnames[i] = strdup(name);
	return i;
}

/* Track stack depth for max_stack estimate */
static void push(compile_ctx *c)
{
	c->depth++;
	if (c->depth > c->max_depth)
		c->max_depth = c->depth;
}

static void pop(compile_ctx *c, int n)
{
	c->depth -= n;
}

/*
 * Map a role enum to its short name (without the leading underscore).
 */
static const char *role_name(uint8_t role)
{
	switch (role) {
	case ROLE_BIN: return "bin";
	case ROLE_HEX: return "hex";
	case ROLE_B64: return "b64";
	case ROLE_MCF: return "mcf";
	case ROLE_UC:  return "uc";
	default:       return "default";
	}
}

/*
 * Render the bitmask of supported roles as a human-readable list,
 * for use in compile-time error messages.  Writes into a static
 * buffer (caller owns no memory; result valid until next call).
 */
static const char *role_caps_str(uint8_t caps)
{
	static char buf[64];
	int o = 0;
	buf[0] = '\0';
	if (caps == 0) {
		strcpy(buf, "(none — bare name only)");
		return buf;
	}
	if (caps & ROLE_CAP_BIN) o += snprintf(buf + o, sizeof(buf) - o,
	                                       "%s_bin", o ? ", " : "");
	if (caps & ROLE_CAP_HEX) o += snprintf(buf + o, sizeof(buf) - o,
	                                       "%s_hex", o ? ", " : "");
	if (caps & ROLE_CAP_B64) o += snprintf(buf + o, sizeof(buf) - o,
	                                       "%s_b64", o ? ", " : "");
	if (caps & ROLE_CAP_MCF) o += snprintf(buf + o, sizeof(buf) - o,
	                                       "%s_mcf", o ? ", " : "");
	if (caps & ROLE_CAP_UC)  o += snprintf(buf + o, sizeof(buf) - o,
	                                       "%s_uc", o ? ", " : "");
	return buf;
}

/*
 * Map the canonical default form for a function to a short name
 * (e.g. "default = bare name"). Returned string is for diagnostics.
 */
static const char *default_role_str(uint8_t default_role)
{
	switch (default_role) {
	case ROLE_BIN: return "raw bytes";
	case ROLE_HEX: return "hex";
	case ROLE_B64: return "base64";
	case ROLE_MCF: return "MCF string";
	default:       return "(transform — no canonical encoding)";
	}
}

/*
 * Resolve a function name and any output-role suffix.
 *
 * Suffix grammar (longest match): `_bin`, `_hex`, `_b64`, `_mcf`, `_uc`.
 * Only one suffix is allowed.  If a suffix is present, it is stripped
 * before registry lookup and *role is set accordingly.  If no suffix,
 * *role = ROLE_DEFAULT (the function's `default_role` is applied at
 * dispatch time).
 *
 * Returns NULL if the base name is not in the registry.  Caller must
 * still call validate_role() to enforce supported_roles.
 */
static hx_func_entry *resolve_func(const char *name, uint8_t *role)
{
	char base[128];
	int  len = strlen(name);
	hx_func_entry *e;
	uint8_t r = ROLE_DEFAULT;
	int suffix_len = 0;

	/* longest-match suffix scan: four candidates of length 4, then the
	 * length-3 `_uc`.  Longest first, so a hypothetical function whose
	 * name ends in `_uc` is still reachable through the fall-through
	 * below rather than being shadowed here. */
	if (len > 4 && name[len - 4] == '_') {
		const char *s = name + len - 3;
		if      (memcmp(s, "bin", 3) == 0) { r = ROLE_BIN; suffix_len = 4; }
		else if (memcmp(s, "hex", 3) == 0) { r = ROLE_HEX; suffix_len = 4; }
		else if (memcmp(s, "b64", 3) == 0) { r = ROLE_B64; suffix_len = 4; }
		else if (memcmp(s, "mcf", 3) == 0) { r = ROLE_MCF; suffix_len = 4; }
	}
	if (suffix_len == 0 && len > 3 && name[len - 3] == '_' &&
	    memcmp(name + len - 2, "uc", 2) == 0) {
		r = ROLE_UC; suffix_len = 3;
	}

	*role = r;

	if (suffix_len > 0) {
		int blen = len - suffix_len;
		if (blen >= (int)sizeof(base)) blen = sizeof(base) - 1;
		memcpy(base, name, blen);
		base[blen] = '\0';
		e = hx_func_lookup(base);
		if (e) return e;
		/*
		 * Suffix recognized, but the stripped base isn't a function.
		 * Fall through to try the full name (this preserves the
		 * possibility of a function literally named e.g. `abc_bin`,
		 * which is unlikely but not forbidden).
		 */
		*role = ROLE_DEFAULT;
	}

	/* try full name */
	return hx_func_lookup(name);
}

/*
 * Verify that the requested role is compatible with the function's
 * advertised supported_roles.  Emits a diagnostic and exits on failure.
 *
 * ROLE_DEFAULT is always permitted (it dispatches to default_role).
 */
static void validate_role(hx_func_entry *fe, uint8_t role,
                          const char *fname, int line)
{
	uint8_t cap;

	if (role == ROLE_DEFAULT) return;

	cap = (uint8_t)(1u << role);
	if (fe->supported_roles & cap) return;

	fprintf(stderr, "hx:%d: function '%s' does not support the '_%s' "
	                "suffix\n", line, fe->name, role_name(role));
	fprintf(stderr, "hx:%d:   supported: %s   (canonical form: %s)\n",
	        line, role_caps_str(fe->supported_roles),
	        default_role_str(fe->default_role));
	(void)fname;
	hx_compile_die();
}

/* ---- recursive compilation ---- */

static void compile_node(compile_ctx *c, hx_node *node);

/*
 * Compile a body block (the body of a for-loop or if-statement, or the
 * else-block of an if).  Every statement's stack value is discarded —
 * unlike the program-level HX_BLOCK which keeps its trailing value for
 * HALT.  Without this, a value-producing statement at the tail of a
 * loop body would leak one stack slot per iteration, eventually
 * overflowing the VM stack and corrupting the heap.
 *
 * If `body` is NULL or not a block, falls through to compile_node()
 * with a single-statement pop (defensive — grammar always passes a
 * block here).
 */
static void compile_body(compile_ctx *c, hx_node *body)
{
	hx_inst inst;
	int i;

	if (!body) return;

	memset(&inst, 0, sizeof(inst));

	if (body->type != HX_BLOCK) {
		/* single statement — compile and pop if it produces a value */
		compile_node(c, body);
		if (node_produces_value(body)) {
			inst.op = OP_POP;
			emit(c, inst);
			pop(c, 1);
		}
		return;
	}

	for (i = 0; i < body->u.block.nstmts; i++) {
		hx_node *stmt = body->u.block.stmts[i];
		compile_node(c, stmt);
		if (node_produces_value(stmt)) {
			inst.op = OP_POP;
			memset(&inst.u, 0, sizeof(inst.u));
			emit(c, inst);
			pop(c, 1);
		}
	}
}

/* ---- text programs: hx-functions.md section 19 ---- */

/* The encoding name a loop variable stands for here, or NULL. */
static const char *loop_value(compile_ctx *c, const char *name)
{
	int i;
	for (i = c->nlv - 1; i >= 0; i--)
		if (strcmp(c->lv_name[i], name) == 0) return c->lv_val[i];
	return NULL;
}

static void loop_misuse(compile_ctx *c, const char *name, int line)
{
	(void)c;
	fprintf(stderr, "hx:%d: '%s' is a loop over encoding names; it can be "
	        "used only as a convert(), valid() or roundtrip() encoding, or as "
	        "an emit() label\n", line, name);
	hx_compile_die();
}

/* A compile-time string: a literal with no NUL, or a loop variable.  NULL
 * for anything else. */
static const char *const_string(compile_ctx *c, const hx_node *a)
{
	if (a->type == HX_LITERAL && !memchr(a->u.literal.str, '\0', a->u.literal.len))
		return a->u.literal.str;
	if (a->type == HX_VARIABLE) return loop_value(c, a->u.varname);
	return NULL;
}

static void push_const(compile_ctx *c, const char *str)
{
	hx_inst inst;
	memset(&inst, 0, sizeof inst);
	inst.op = OP_PUSH_STR;
	inst.u.stridx = add_string(c, str, (int)strlen(str));
	emit(c, inst);
	push(c);
}

static void emit_call(compile_ctx *c, const char *fname, int nargs)
{
	hx_inst inst;
	memset(&inst, 0, sizeof inst);
	inst.op = OP_CALL;
	inst.u.call.entry = hx_func_lookup(fname);
	inst.u.call.nargs = nargs;
	inst.u.call.role  = ROLE_DEFAULT;
	if (!inst.u.call.entry) {
		fprintf(stderr, "hx: %s:%d: no registry entry for %s()\n",
		        __FILE__, __LINE__, fname);
		hx_compile_die();
	}
	emit(c, inst);
	pop(c, nargs);
	push(c);
}

/* An encoding-name argument of valid() or roundtrip(): its name, or a
 * compile error. */
static const char *enc_arg(compile_ctx *c, hx_node *node, int i)
{
	const char *v = const_string(c, node->u.call.args[i]);
	if (!v) {
		fprintf(stderr, "hx:%d: %s(): argument %d must be a string literal or "
		        "a loop variable naming an encoding\n", node->line,
		        node->u.call.name, i + 1);
		hx_compile_die();
	}
	if (!hx_conv_lookup(v)) {
		fprintf(stderr, "hx:%d: %s(): unknown encoding '%s'\n", node->line,
		        node->u.call.name, v);
		hx_compile_die();
	}
	return v;
}

/* convert() between two names, or a compile error naming the function */
static void check_pair(const char *fname, const char *a, const char *b, int line)
{
	hx_inst t;
	char err[256];
	if (hx_convert_build(a, b, NULL, 0, &t, err, sizeof err) < 0) {
		const char *e = strncmp(err, "convert(): ", 11) == 0 ? err + 11 : err;
		fprintf(stderr, "hx:%d: %s(): %s\n", line, fname, e);
		hx_compile_die();
	}
}

/*
 * valid(x, cs), roundtrip(x, a, b) -- section 19.2 -- and emit(x, label, ...)
 * -- section 19.3.  The names and labels are compile-time strings, pushed as
 * constants, so the program a loop unrolls to is an ordinary one.
 */
static void compile_text_call(compile_ctx *c, hx_node *node)
{
	const char *fname = node->u.call.name;
	int i, n = node->u.call.nargs;

	if (strcmp(fname, "valid") == 0) {
		const char *cs;
		hx_inst t;
		char err[256];
		if (n != 2) {
			fprintf(stderr, "hx:%d: valid() takes a value and an encoding\n",
			        node->line);
			hx_compile_die();
		}
		cs = enc_arg(c, node, 1);
		/* it must be decodable: utf7 and lowbyte16 are encode-only */
		if (hx_convert_build(cs, hx_conv_kind(hx_conv_lookup(cs)) == HXE_KIND_CHARSET
		                         ? "utf8" : "raw", NULL, 0, &t, err, sizeof err) < 0) {
			const char *e = strncmp(err, "convert(): ", 11) == 0 ? err + 11 : err;
			fprintf(stderr, "hx:%d: valid(): %s\n", node->line, e);
			hx_compile_die();
		}
		compile_node(c, node->u.call.args[0]);
		push_const(c, cs);
		emit_call(c, "valid", 2);
		return;
	}
	if (strcmp(fname, "roundtrip") == 0) {
		const char *a, *b;
		if (n != 3) {
			fprintf(stderr, "hx:%d: roundtrip() takes a value and two "
			        "encodings\n", node->line);
			hx_compile_die();
		}
		a = enc_arg(c, node, 1);
		b = enc_arg(c, node, 2);
		check_pair("roundtrip", a, b, node->line);
		check_pair("roundtrip", b, a, node->line);
		compile_node(c, node->u.call.args[0]);
		push_const(c, a);
		push_const(c, b);
		emit_call(c, "roundtrip", 3);
		return;
	}
	/* emit(x, label, ...) */
	{
		const char *lab[16];
		if (n - 1 > (int)(sizeof lab / sizeof lab[0])) {
			fprintf(stderr, "hx:%d: emit(): too many labels\n", node->line);
			hx_compile_die();
		}
		for (i = 1; i < n; i++)
			if (!(lab[i - 1] = const_string(c, node->u.call.args[i]))) {
				fprintf(stderr, "hx:%d: emit(): label %d must be a string "
				        "literal or a loop variable\n", node->line, i);
				hx_compile_die();
			}
		compile_node(c, node->u.call.args[0]);
		for (i = 1; i < n; i++) push_const(c, lab[i - 1]);
		c->has_emit = 1;
		emit_call(c, "emit", n);
	}
}

/*
 * for v in ("a", "b", ...) { body }, for v in charsets("group") { body }:
 * the body is compiled once per name with v bound to it (section 19.1).
 */
static void compile_forin(compile_ctx *c, hx_node *node)
{
	hx_node *in = node->u.forloop.in;
	const char *v = node->u.forloop.varname;
	const char *const *names;
	const char *one[64];
	int i, n = 0;

	if (loop_value(c, v)) {
		fprintf(stderr, "hx:%d: loop variable '%s' is already in use by an "
		        "enclosing loop\n", node->line, v);
		hx_compile_die();
	}
	if (c->nlv >= (int)(sizeof c->lv_name / sizeof c->lv_name[0])) {
		fprintf(stderr, "hx:%d: loops over encodings nested too deeply\n",
		        node->line);
		hx_compile_die();
	}
	if (in->u.call.name[0] == '\0') {
		if (in->u.call.nargs > (int)(sizeof one / sizeof one[0]) - 1) {
			fprintf(stderr, "hx:%d: for %s in (...): too many names; use "
			        "charsets()\n", node->line, v);
			hx_compile_die();
		}
		for (i = 0; i < in->u.call.nargs; i++) {
			hx_node *a = in->u.call.args[i];
			if (a->type != HX_LITERAL ||
			    memchr(a->u.literal.str, '\0', a->u.literal.len)) {
				fprintf(stderr, "hx:%d: for %s in (...): item %d must be a "
				        "string literal\n", node->line, v, i + 1);
				hx_compile_die();
			}
			if (!hx_conv_lookup(a->u.literal.str)) {
				fprintf(stderr, "hx:%d: for %s in (...): unknown encoding "
				        "'%s'\n", node->line, v, a->u.literal.str);
				hx_compile_die();
			}
			one[n++] = a->u.literal.str;
		}
		one[n] = NULL;
		names = one;
	} else {
		const hx_node *g;
		if (strcmp(in->u.call.name, "charsets") != 0) {
			fprintf(stderr, "hx:%d: for %s in %s(): only a list of names or "
			        "charsets(group) can follow 'in'\n", node->line, v,
			        in->u.call.name);
			hx_compile_die();
		}
		g = in->u.call.nargs == 1 ? in->u.call.args[0] : NULL;
		if (!g || g->type != HX_LITERAL) {
			fprintf(stderr, "hx:%d: charsets() takes one group name, a string "
			        "literal\n", node->line);
			hx_compile_die();
		}
		if (!(names = hx_charsets(g->u.literal.str))) {
			fprintf(stderr, "hx:%d: charsets(): unknown group '%s' (all, "
			        "windows, oem, iso8859, mac, ebcdic, cjk, unicode)\n",
			        node->line, g->u.literal.str);
			hx_compile_die();
		}
		c->uses_groups = 1;
	}
	c->text_loop = 1;
	c->lv_name[c->nlv] = v;
	c->nlv++;
	for (i = 0; names[i]; i++) {
		c->lv_val[c->nlv - 1] = names[i];
		compile_body(c, node->u.forloop.body);
	}
	c->nlv--;
}

/*
 * convert(x, "from", "to", "token", ...) -- hx-functions.md section 18.2.
 * Every argument after the first is a string literal and is consumed here at
 * compile time; only x is pushed.  Anything malformed is a compile error with
 * the line and the offending token.
 */
static void compile_convert(compile_ctx *c, hx_node *node)
{
	char *lit[16], err[256];
	hx_inst inst;
	int i, n = node->u.call.nargs;

	if (n < 3) {
		fprintf(stderr, "hx:%d: convert() takes a value, a source encoding "
		        "and a target encoding\n", node->line);
		hx_compile_die();
	}
	if (n - 1 > (int)(sizeof lit / sizeof lit[0])) {
		fprintf(stderr, "hx:%d: convert(): too many tokens\n", node->line);
		hx_compile_die();
	}
	for (i = 1; i < n; i++) {
		hx_node *a = node->u.call.args[i];
		const char *lv;
		/* from and to may be a loop variable (section 19.1); tokens may not */
		if (i <= 2 && a->type == HX_VARIABLE &&
		    (lv = loop_value(c, a->u.varname)) != NULL) {
			lit[i - 1] = strdup(lv);
			continue;
		}
		if (a->type == HX_VARIABLE && loop_value(c, a->u.varname))
			loop_misuse(c, a->u.varname, node->line);
		if (a->type != HX_LITERAL ||
		    memchr(a->u.literal.str, '\0', a->u.literal.len)) {
			fprintf(stderr, "hx:%d: convert(): argument %d must be a string "
			        "literal\n", node->line, i + 1);
			hx_compile_die();
		}
		lit[i - 1] = strndup(a->u.literal.str, a->u.literal.len);
	}
	if (hx_convert_build(lit[0], lit[1], (const char *const *)lit + 2, n - 3,
	                     &inst, err, sizeof err) < 0) {
		fprintf(stderr, "hx:%d: %s\n", node->line, err);
		hx_compile_die();
	}
	for (i = 0; i < n - 1; i++) free(lit[i]);
	compile_node(c, node->u.call.args[0]);
	emit(c, inst);       /* one value in, one out: depth unchanged */
}

/*
 * A legacy conversion function called with one argument and no output-role
 * suffix compiles to the OP_CONVERT its alias row names (section 18.6); any
 * other form stays the OP_CALL it always was.  Returns 1 and fills *inst.
 */
static int alias_convert(const char *name, int nargs, uint8_t role,
                         hx_inst *inst)
{
	if (nargs != 1 || role != ROLE_DEFAULT) return 0;
	return hx_convert_alias_inst(name, inst);
}

static void compile_node(compile_ctx *c, hx_node *node)
{
	hx_inst inst;
	int i, slot;
	uint8_t role;
	int addr_jump, addr_else;
	int addr_loop;
	hx_func_entry *fe;

	if (!node) return;

	memset(&inst, 0, sizeof(inst));

	switch (node->type) {

	case HX_LITERAL:
		inst.op = OP_PUSH_STR;
		inst.u.stridx = add_string(c, node->u.literal.str,
		                           node->u.literal.len);
		emit(c, inst);
		push(c);
		break;

	case HX_NUMBER:
		inst.op = OP_PUSH_INT;
		inst.u.ival = node->u.number;
		emit(c, inst);
		push(c);
		break;

	case HX_VARIABLE:
		if (loop_value(c, node->u.varname))
			loop_misuse(c, node->u.varname, node->line);
		inst.op = OP_PUSH_VAR;
		inst.u.slot = resolve_var(c, node->u.varname);
		emit(c, inst);
		push(c);
		break;

	case HX_CONCAT:
		compile_node(c, node->u.concat.left);
		compile_node(c, node->u.concat.right);
		inst.op = OP_CONCAT;
		emit(c, inst);
		pop(c, 1);   /* two values → one */
		break;

	case HX_FUNCALL:
		if (strcmp(node->u.call.name, "convert") == 0) {
			compile_convert(c, node);
			break;
		}
		if (strcmp(node->u.call.name, "valid") == 0 ||
		    strcmp(node->u.call.name, "roundtrip") == 0 ||
		    (strcmp(node->u.call.name, "emit") == 0 && node->u.call.nargs > 1)) {
			compile_text_call(c, node);
			break;
		}
		if (strcmp(node->u.call.name, "charsets") == 0) {
			fprintf(stderr, "hx:%d: charsets() can only follow 'in' in a for "
			        "loop\n", node->line);
			hx_compile_die();
		}

		/* push args left to right */
		for (i = 0; i < node->u.call.nargs; i++)
			compile_node(c, node->u.call.args[i]);

		fe = resolve_func(node->u.call.name, &role);
		if (!fe) {
			/* an alias with no registry entry: cp1252_to_utf8 ... */
			if (alias_convert(node->u.call.name, node->u.call.nargs,
			                  ROLE_DEFAULT, &inst)) {
				emit(c, inst);
				break;
			}
			fprintf(stderr, "hx:%d: unknown function '%s'\n",
			        node->line, node->u.call.name);
			hx_compile_die();
		}
		validate_role(fe, role, node->u.call.name, node->line);

		if (alias_convert(fe->name, node->u.call.nargs, role, &inst)) {
			emit(c, inst);
			break;
		}

		/* detect emit() calls */
		if (strcmp(node->u.call.name, "emit") == 0)
			c->has_emit = 1;

		inst.op = OP_CALL;
		inst.u.call.entry = fe;
		inst.u.call.nargs = node->u.call.nargs;
		inst.u.call.role  = role;
		emit(c, inst);
		pop(c, node->u.call.nargs);
		push(c);      /* result */
		break;

	case HX_ITER:
		if (strcmp(node->u.iter.name, "convert") == 0 ||
		    strcmp(node->u.iter.name, "valid") == 0 ||
		    strcmp(node->u.iter.name, "roundtrip") == 0 ||
		    strcmp(node->u.iter.name, "charsets") == 0) {
			fprintf(stderr, "hx:%d: %s() cannot be repeated with ^; "
			        "nest the calls\n", node->line, node->u.iter.name);
			hx_compile_die();
		}
		/* func^N(args) — push args, emit CALL in a loop */
		for (i = 0; i < node->u.iter.nargs; i++)
			compile_node(c, node->u.iter.args[i]);

		fe = resolve_func(node->u.iter.name, &role);
		{
			hx_inst conv;
			int is_conv = alias_convert(fe ? fe->name : node->u.iter.name,
			                            node->u.iter.nargs,
			                            fe ? role : ROLE_DEFAULT, &conv);
			if (!fe && !is_conv) {
				fprintf(stderr, "hx:%d: unknown function '%s'\n",
				        node->line, node->u.iter.name);
				hx_compile_die();
			}
			if (fe)
				validate_role(fe, role, node->u.iter.name, node->line);
			if (is_conv) {
				/* the same loop shape, with the conversion in
				 * place of both calls (all aliases take one
				 * argument, so the loop's call is the same) */
				int iter_slot, limit = node->u.iter.count;
				char tmpname[32];
				snprintf(tmpname, sizeof(tmpname), "__iter_%d",
				         c->ncode);
				iter_slot = resolve_var(c, tmpname);
				emit(c, conv);
				if (limit > 1) {
					inst.op = OP_PUSH_INT;
					inst.u.ival = 1;
					emit(c, inst);
					inst.op = OP_STORE;
					inst.u.slot = iter_slot;
					emit(c, inst);
					addr_loop = c->ncode;
					emit(c, conv);
					inst.op = OP_INC;
					inst.u.slot = iter_slot;
					emit(c, inst);
					inst.op = OP_PUSH_VAR;
					inst.u.slot = iter_slot;
					emit(c, inst);
					push(c);
					inst.op = OP_PUSH_INT;
					inst.u.ival = limit - 1;
					emit(c, inst);
					push(c);
					inst.op = OP_JUMP_LE;
					inst.u.addr = addr_loop;
					emit(c, inst);
					pop(c, 2);
				}
				break;
			}
		}

		/*
		 * For iter, we need a hidden loop counter.
		 * Allocate a temp variable slot for it.
		 */
		{
			char tmpname[32];
			int iter_slot, limit;

			snprintf(tmpname, sizeof(tmpname), "__iter_%d",
			         c->ncode);
			iter_slot = resolve_var(c, tmpname);
			limit = node->u.iter.count;

			/* First call: args already on stack */
			inst.op = OP_CALL;
			inst.u.call.entry = fe;
			inst.u.call.nargs = node->u.iter.nargs;
			inst.u.call.role  = role;
			emit(c, inst);
			pop(c, node->u.iter.nargs);
			push(c);

			if (limit > 1) {
				/* i = 1 (counts additional calls after the first) */
				inst.op = OP_PUSH_INT;
				inst.u.ival = 1;
				emit(c, inst);
				inst.op = OP_STORE;
				inst.u.slot = iter_slot;
				emit(c, inst);

				/* LOOP: result is on stack top */
				addr_loop = c->ncode;

				/* call fn(stack_top) — 1 arg (the previous result) */
				inst.op = OP_CALL;
				inst.u.call.entry = fe;
				inst.u.call.nargs = 1;
				inst.u.call.role  = role;
				emit(c, inst);
				/* stack: still has one value (old consumed, new pushed) */

				/* i++ */
				inst.op = OP_INC;
				inst.u.slot = iter_slot;
				emit(c, inst);

				/* push i, push limit-1 (we already did the first call) */
				inst.op = OP_PUSH_VAR;
				inst.u.slot = iter_slot;
				emit(c, inst);
				push(c);

				inst.op = OP_PUSH_INT;
				inst.u.ival = limit - 1;
				emit(c, inst);
				push(c);

				/* jump if i <= (limit-1) → LOOP */
				inst.op = OP_JUMP_LE;
				inst.u.addr = addr_loop;
				emit(c, inst);
				pop(c, 2);
			}
		}
		break;

	case HX_ASSIGN:
		if (loop_value(c, node->u.assign.varname))
			loop_misuse(c, node->u.assign.varname, node->line);
		compile_node(c, node->u.assign.expr);
		slot = resolve_var(c, node->u.assign.varname);
		/* DUP so the value remains as the statement's value */
		inst.op = OP_STORE;
		inst.u.slot = slot;
		emit(c, inst);
		pop(c, 1);
		break;

	case HX_FOR:
		/*
		 * for var = from to limit { body }
		 *
		 * The body is a block; its statements' values are discarded
		 * (the for-loop has no result).  compile_block_body() emits
		 * OP_POP after each value-producing statement so the runtime
		 * stack does not grow unboundedly across loop iterations.
		 *
		 * BUG HISTORY: prior to this fix, body statements that produced
		 * values (e.g., a trailing `emit(...)`) leaked one slot per
		 * iteration, causing the VM stack to overflow into adjacent
		 * heap memory after enough iterations.  The corruption typically
		 * surfaced as SIGFPE/SIGSEGV in OpenSSL's atexit cleanup
		 * (`ossl_ht_free`), since libcrypto's heap state was clobbered.
		 */
		if (node->u.forloop.in) {
			compile_forin(c, node);
			break;
		}
		if (loop_value(c, node->u.forloop.varname))
			loop_misuse(c, node->u.forloop.varname, node->line);
		slot = resolve_var(c, node->u.forloop.varname);

		/* var = from */
		compile_node(c, node->u.forloop.from);
		inst.op = OP_STORE;
		inst.u.slot = slot;
		emit(c, inst);
		pop(c, 1);

		/* LOOP: */
		addr_loop = c->ncode;

		/* body — values discarded */
		compile_body(c, node->u.forloop.body);

		/* var++ */
		inst.op = OP_INC;
		inst.u.slot = slot;
		emit(c, inst);

		/* push var, push limit */
		inst.op = OP_PUSH_VAR;
		inst.u.slot = slot;
		emit(c, inst);
		push(c);

		compile_node(c, node->u.forloop.to);

		/* if var <= limit, goto LOOP */
		inst.op = OP_JUMP_LE;
		inst.u.addr = addr_loop;
		emit(c, inst);
		pop(c, 2);
		break;

	case HX_IF:
		/* condition puts two values on stack */
		{
			hx_node *cond = node->u.ifstmt.cond;
			uint8_t jump_op;

			compile_node(c, cond->u.binop.left);
			compile_node(c, cond->u.binop.right);

			/* invert the condition for "jump over then-body" */
			switch (cond->u.binop.op) {
			case HX_OP_EQ: jump_op = OP_JUMP_NE; break;
			case HX_OP_NE: jump_op = OP_JUMP_EQ; break;
			case HX_OP_LT: jump_op = OP_JUMP_GE; break;
			case HX_OP_GT: jump_op = OP_JUMP_LE; break;
			case HX_OP_LE: jump_op = OP_JUMP_GT; break;
			case HX_OP_GE: jump_op = OP_JUMP_LT; break;
			default:
				fprintf(stderr, "hx:%d: unsupported condition op\n",
				        node->line);
				hx_compile_die();
			}

			/* placeholder jump — addr filled in after then-body */
			inst.op = jump_op;
			inst.u.addr = 0;
			addr_jump = c->ncode;
			emit(c, inst);
			pop(c, 2);

			/* then body — values discarded */
			compile_body(c, node->u.ifstmt.then_body);

			if (node->u.ifstmt.else_body) {
				/* jump over else */
				inst.op = OP_JUMP;
				inst.u.addr = 0;
				addr_else = c->ncode;
				emit(c, inst);

				/* patch the conditional jump to here */
				c->code[addr_jump].u.addr = c->ncode;

				/* else body — values discarded */
				compile_body(c, node->u.ifstmt.else_body);

				/* patch jump-over-else to here */
				c->code[addr_else].u.addr = c->ncode;
			} else {
				/* patch the conditional jump to here */
				c->code[addr_jump].u.addr = c->ncode;
			}
		}
		break;

	case HX_BLOCK:
		/*
		 * Top-level program block.  Compile each statement; pop the
		 * stack value of every statement except the last (whose value
		 * becomes the program's HALT result, in the !has_emit case).
		 *
		 * Nested blocks inside HX_FOR / HX_IF go through compile_body()
		 * instead, which discards every statement's value.
		 */
		for (i = 0; i < node->u.block.nstmts; i++) {
			hx_node *stmt = node->u.block.stmts[i];
			compile_node(c, stmt);
			if (i + 1 < node->u.block.nstmts &&
			    node_produces_value(stmt)) {
				inst.op = OP_POP;
				memset(&inst.u, 0, sizeof(inst.u));
				emit(c, inst);
				pop(c, 1);
			}
		}
		break;

	case HX_BINOP:
		/* should not appear standalone — handled by HX_IF */
		fprintf(stderr, "hx:%d: unexpected binop outside condition\n",
		        node->line);
		hx_compile_die();
	}
}

/* ---- public interface ---- */

hx_program *hx_compile(hx_node *ast)
{
	compile_ctx ctx;
	hx_program *prog;

	memset(&ctx, 0, sizeof(ctx));

	/* pre-allocate built-in variable slots */
	ctx.var_cap  = 16;
	ctx.varnames = calloc(ctx.var_cap, sizeof(char *));
	ctx.varnames[HX_SLOT_PASS]   = strdup("pass");
	ctx.varnames[HX_SLOT_SALT]   = strdup("salt");
	ctx.varnames[HX_SLOT_SALT2]  = strdup("salt2");
	ctx.varnames[HX_SLOT_PEPPER] = strdup("pepper");
	ctx.varnames[HX_SLOT_USERID] = strdup("user");
	ctx.nvars = HX_SLOT_USERVARS;

	/* compile */
	compile_node(&ctx, ast);

	/* emit HALT */
	{
		hx_inst halt;
		memset(&halt, 0, sizeof(halt));
		halt.op = OP_HALT;
		emit(&ctx, halt);
	}

	/* package into program */
	prog = calloc(1, sizeof(hx_program));
	prog->code      = ctx.code;
	prog->ncode     = ctx.ncode;
	prog->strings   = ctx.strings;
	prog->strlens   = ctx.strlens;
	prog->nstrings  = ctx.nstrings;
	prog->varnames  = ctx.varnames;
	prog->nvars     = ctx.nvars;
	prog->max_stack = ctx.max_depth + 8;  /* some headroom */
	prog->has_emit  = ctx.has_emit;
	prog->text_loop = ctx.text_loop;
	prog->uses_groups = ctx.uses_groups;

	return prog;
}

void hx_program_free(hx_program *prog)
{
	int i;
	if (!prog) return;
	free(prog->code);
	for (i = 0; i < prog->nstrings; i++)
		free(prog->strings[i]);
	free(prog->strings);
	free(prog->strlens);
	for (i = 0; i < prog->nvars; i++)
		free(prog->varnames[i]);
	free(prog->varnames);
	free(prog);
}

static void dump_code(hx_program *prog, hx_inst *code, int ncode);

void hx_program_dump(hx_program *prog)
{
	int i;

	fprintf(stderr, "--- hx bytecode: %d instructions, %d vars, "
	        "%d strings ---\n", prog->ncode, prog->nvars, prog->nstrings);

	for (i = 0; i < prog->nvars; i++)
		fprintf(stderr, "  var[%d] = %s\n", i, prog->varnames[i]);

	for (i = 0; i < prog->nstrings; i++)
		fprintf(stderr, "  str[%d] = \"%s\" (len=%d)\n",
		        i, prog->strings[i], prog->strlens[i]);

	dump_code(prog, prog->code, prog->ncode);

	/* what the VM runs, when fusion (hx-functions.md 18.7) changes it */
	if (prog->ncode > 0) {
		hx_inst *c = malloc(prog->ncode * sizeof *c);
		int n;
		if (!c) return;
		memcpy(c, prog->code, prog->ncode * sizeof *c);
		n = hx_convert_fuse(c, NULL, prog->ncode);
		if (n < prog->ncode) {
			fprintf(stderr, "--- fused for execution: %d instructions ---\n", n);
			dump_code(prog, c, n);
		}
		free(c);
	}
}

static void dump_code(hx_program *prog, hx_inst *code, int ncode)
{
	int i;
	static const char *opnames[] = {
		"PUSH_VAR", "PUSH_STR", "PUSH_INT", "STORE",
		"CALL", "CONCAT", "HALT", "JUMP",
		"INC", "JUMP_LE", "JUMP_LT", "JUMP_GT", "JUMP_GE",
		"JUMP_EQ", "JUMP_NE", "DUP", "POP", "CONVERT"
	};

	for (i = 0; i < ncode; i++) {
		hx_inst *ip = &code[i];
		fprintf(stderr, "  %3d  %-10s", i,
		        ip->op < sizeof opnames / sizeof opnames[0]
		        ? opnames[ip->op] : "???");
		switch (ip->op) {
		case OP_PUSH_VAR:
		case OP_STORE:
		case OP_INC:
			fprintf(stderr, " %d (%s)", ip->u.slot,
			        ip->u.slot < prog->nvars
			        ? prog->varnames[ip->u.slot] : "?");
			break;
		case OP_PUSH_STR:
			fprintf(stderr, " %d (\"%s\")", ip->u.stridx,
			        prog->strings[ip->u.stridx]);
			break;
		case OP_PUSH_INT:
			fprintf(stderr, " %lld", (long long)ip->u.ival);
			break;
		case OP_CALL: {
			static const char *role_short[] = {
				"", " [bin]", " [hex]", " [b64]", " [mcf]", " [uc]"
			};
			uint8_t r = ip->u.call.role;
			fprintf(stderr, " %s nargs=%d%s",
			        ip->u.call.entry->name,
			        ip->u.call.nargs,
			        r < 6 ? role_short[r] : " [?role]");
			break;
		}
		case OP_CONVERT: {
			char d[128];
			hx_convert_describe(ip, d, sizeof d);
			fprintf(stderr, " convert %s", d);
			break;
		}
		case OP_JUMP:
		case OP_JUMP_LE:
		case OP_JUMP_LT:
		case OP_JUMP_GT:
		case OP_JUMP_GE:
		case OP_JUMP_EQ:
		case OP_JUMP_NE:
			fprintf(stderr, " → %d", ip->u.addr);
			break;
		default:
			break;
		}
		fprintf(stderr, "\n");
	}
}
