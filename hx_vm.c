/*
 * hx_vm.c - bytecode interpreter for hx
 *
 * Stack-based VM.  All string data allocated from a per-password
 * arena that resets between runs.  Integer values (loop counters)
 * are stored inline in hx_val.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hx_vm.h"

/* ---- arena ---- */

struct hx_arena_blk {
	hx_arena_blk *next;
	char         *buf;
};

void hx_arena_init(hx_arena *a, int cap)
{
	a->buf  = malloc(cap);
	a->used = 0;
	a->cap  = cap;
	a->old  = NULL;
	a->emits = NULL;
	if (!a->buf) {
		fprintf(stderr, "hx: arena alloc failed (%d bytes)\n", cap);
		exit(1);
	}
}

char *hx_arena_alloc(hx_arena *a, int size)
{
	char *p;

	/* align to 8 bytes */
	size = (size + 7) & ~7;

	if (a->used + size > a->cap) {
		/* start a block of double the size (or more), keeping the full
		 * one: values already handed out live in it */
		hx_arena_blk *b = malloc(sizeof *b);
		int cap = a->cap > 0 ? a->cap : HX_ARENA_SIZE;
		while (size > cap)
			cap *= 2;
		cap *= 2;
		if (!b || !(p = malloc(cap))) {
			fprintf(stderr, "hx: arena alloc failed (%d bytes)\n", cap);
			exit(1);
		}
		b->buf  = a->buf;
		b->next = a->old;
		a->old  = b;
		a->buf  = p;
		a->cap  = cap;
		a->used = 0;
	}
	p = a->buf + a->used;
	a->used += size;
	return p;
}

static void hx_arena_free_old(hx_arena *a)
{
	while (a->old) {
		hx_arena_blk *b = a->old;
		a->old = b->next;
		free(b->buf);
		free(b);
	}
}

void hx_arena_reset(hx_arena *a)
{
	hx_arena_free_old(a);
	a->used = 0;
}

void hx_arena_free(hx_arena *a)
{
	hx_arena_free_old(a);
	free(a->buf);
	a->buf  = NULL;
	a->used = 0;
	a->cap  = 0;
}

/* ---- VM ---- */

int hx_vm_fuse = 1;

void hx_vm_init(hx_vm *vm, hx_program *prog)
{
	int i;
	memset(vm, 0, sizeof(*vm));
	vm->prog      = prog;
	hx_arena_init(&vm->arena, HX_ARENA_SIZE);
	vm->stack_cap = prog->max_stack;
	vm->stack     = calloc(vm->stack_cap, sizeof(hx_val));
	vm->vars      = calloc(prog->nvars, sizeof(hx_val));
	vm->code      = prog->code;
	/* run the fused program (hx-functions.md 18.7) when fusion changes it */
	for (i = 0; hx_vm_fuse && i + 1 < prog->ncode; i++)
		if (prog->code[i].op == OP_CONVERT && prog->code[i + 1].op == OP_CONVERT) {
			hx_inst *c = malloc(prog->ncode * sizeof(hx_inst));
			if (!c) { fprintf(stderr, "hx: out of memory\n"); exit(1); }
			memcpy(c, prog->code, prog->ncode * sizeof(hx_inst));
			if (hx_convert_fuse(c, NULL, prog->ncode) < prog->ncode)
				vm->code = vm->owncode = c;
			else
				free(c);
			break;
		}
}

void hx_vm_free(hx_vm *vm)
{
	hx_arena_free(&vm->arena);
	free(vm->stack);
	free(vm->vars);
	free(vm->owncode);
	vm->owncode = vm->code = NULL;
	free(vm->emits.v);
	memset(&vm->emits, 0, sizeof vm->emits);
}

/*
 * Compare two hx_val for equality.
 * Integers compare as integers; strings compare as bytes.
 */
static int val_equal(hx_val *a, hx_val *b)
{
	if (a->is_int && b->is_int)
		return a->ival == b->ival;
	if (a->is_int || b->is_int)
		return 0;       /* type mismatch */
	if (a->len != b->len)
		return 0;
	return memcmp(a->data, b->data, a->len) == 0;
}

/*
 * Compare two values, returning -1/0/+1 like memcmp.
 *
 * Semantics:
 *   int  vs int  : signed integer compare (ival - ival, clamped to {-1,0,+1})
 *   str  vs str  : memcmp on min(a.len, b.len); shorter prefix is less-than
 *   mixed        : runtime error — strict typing, no implicit coercion.
 *                  Catches user mistakes loudly rather than silently
 *                  returning a misleading ordering.
 *
 * The shorter-prefix-is-less-than tiebreak matches C strcmp,
 * Python bytes, and Perl cmp.
 */
static int val_compare(hx_val *a, hx_val *b)
{
	int n, c;

	if (a->is_int && b->is_int) {
		if (a->ival < b->ival) return -1;
		if (a->ival > b->ival) return  1;
		return 0;
	}
	if (a->is_int || b->is_int) {
		fprintf(stderr,
		    "hx: runtime error: cannot order int vs string "
		    "(no implicit type coercion)\n");
		exit(1);
	}
	n = a->len < b->len ? a->len : b->len;
	c = memcmp(a->data, b->data, n);
	if (c != 0)
		return c < 0 ? -1 : 1;
	if (a->len < b->len) return -1;
	if (a->len > b->len) return  1;
	return 0;
}

hx_val hx_vm_run(hx_vm *vm, const char *pass, int passlen,
                  const char *salt, int saltlen,
                  const char *salt2, int salt2len,
                  const char *pepper, int pepperlen,
                  const char *user, int userlen)
{
	hx_inst *code = vm->code ? vm->code : vm->prog->code;
	hx_val  *stack = vm->stack;
	hx_val  *vars  = vm->vars;
	int      sp = 0;        /* stack pointer (next free slot) */
	int      pc = 0;        /* program counter */
	hx_val   result;

	hx_arena_reset(&vm->arena);
	/* set at every run, not at init: hashpipe moves its hx_vm array */
	vm->arena.emits = vm->capture ? &vm->emits : NULL;
	vm->emits.n = 0;

	/* reset all variables */
	memset(vars, 0, vm->prog->nvars * sizeof(hx_val));

	/* set built-in variables */
	vars[HX_SLOT_PASS].data   = (char *)pass;
	vars[HX_SLOT_PASS].len    = passlen;
	vars[HX_SLOT_SALT].data   = (char *)salt;
	vars[HX_SLOT_SALT].len    = saltlen;
	vars[HX_SLOT_SALT2].data  = (char *)salt2;
	vars[HX_SLOT_SALT2].len   = salt2len;
	vars[HX_SLOT_PEPPER].data = (char *)pepper;
	vars[HX_SLOT_PEPPER].len  = pepperlen;
	vars[HX_SLOT_USERID].data = (char *)user;
	vars[HX_SLOT_USERID].len  = userlen;

	memset(&result, 0, sizeof(result));

	for (;;) {
		hx_inst *ip = &code[pc++];

		/*
		 * Stack-overflow guard: the compiler's max_stack estimate
		 * adds 8 slots of headroom.  If runtime sp ever exceeds
		 * stack_cap, something has gone wrong (compiler bug, or a
		 * pathological program shape).  Bail loudly rather than
		 * write past the buffer end and corrupt the heap.
		 */
		if (sp >= vm->stack_cap) {
			fprintf(stderr,
			    "hx: VM stack overflow (sp=%d cap=%d) at pc=%d op=%d\n",
			    sp, vm->stack_cap, (int)(pc - 1), ip->op);
			exit(1);
		}

		switch (ip->op) {

		case OP_PUSH_VAR:
			stack[sp++] = vars[ip->u.slot];
			break;

		case OP_PUSH_STR:
			stack[sp].data   = vm->prog->strings[ip->u.stridx];
			stack[sp].len    = vm->prog->strlens[ip->u.stridx];
			stack[sp].is_int = 0;
			sp++;
			break;

		case OP_PUSH_INT:
			stack[sp].ival   = ip->u.ival;
			stack[sp].is_int = 1;
			stack[sp].data   = NULL;
			stack[sp].len    = 0;
			sp++;
			break;

		case OP_STORE:
			vars[ip->u.slot] = stack[--sp];
			break;

		case OP_CALL: {
			int nargs    = ip->u.call.nargs;
			uint8_t role = ip->u.call.role;
			hx_val *args = &stack[sp - nargs];
			hx_val res;

			memset(&res, 0, sizeof(res));
			ip->u.call.entry->fn(ip->u.call.entry,
			    args, nargs, &res, &vm->arena, role);
			sp -= nargs;
			stack[sp++] = res;
			break;
		}

		case OP_CONVERT: {
			hx_val res;
			hx_convert_run(ip, &stack[sp - 1], &res, &vm->arena);
			stack[sp - 1] = res;
			break;
		}

		case OP_CONCAT: {
			hx_val *b = &stack[sp - 1];
			hx_val *a = &stack[sp - 2];
			int newlen = a->len + b->len;
			char *buf = hx_arena_alloc(&vm->arena, newlen + 1);

			memcpy(buf, a->data, a->len);
			memcpy(buf + a->len, b->data, b->len);
			buf[newlen] = '\0';

			sp--;
			stack[sp - 1].data   = buf;
			stack[sp - 1].len    = newlen;
			stack[sp - 1].is_int = 0;
			break;
		}

		case OP_HALT:
			if (sp > 0)
				result = stack[sp - 1];
			return result;

		case OP_JUMP:
			pc = ip->u.addr;
			break;

		case OP_INC:
			vars[ip->u.slot].ival++;
			vars[ip->u.slot].is_int = 1;
			break;

		case OP_JUMP_LE: {
			hx_val *b = &stack[sp - 1];
			hx_val *a = &stack[sp - 2];
			sp -= 2;
			if (val_compare(a, b) <= 0)
				pc = ip->u.addr;
			break;
		}

		case OP_JUMP_LT: {
			hx_val *b = &stack[sp - 1];
			hx_val *a = &stack[sp - 2];
			sp -= 2;
			if (val_compare(a, b) < 0)
				pc = ip->u.addr;
			break;
		}

		case OP_JUMP_GT: {
			hx_val *b = &stack[sp - 1];
			hx_val *a = &stack[sp - 2];
			sp -= 2;
			if (val_compare(a, b) > 0)
				pc = ip->u.addr;
			break;
		}

		case OP_JUMP_GE: {
			hx_val *b = &stack[sp - 1];
			hx_val *a = &stack[sp - 2];
			sp -= 2;
			if (val_compare(a, b) >= 0)
				pc = ip->u.addr;
			break;
		}

		case OP_JUMP_EQ: {
			hx_val *b = &stack[sp - 1];
			hx_val *a = &stack[sp - 2];
			sp -= 2;
			if (val_equal(a, b))
				pc = ip->u.addr;
			break;
		}

		case OP_JUMP_NE: {
			hx_val *b = &stack[sp - 1];
			hx_val *a = &stack[sp - 2];
			sp -= 2;
			if (!val_equal(a, b))
				pc = ip->u.addr;
			break;
		}

		case OP_DUP:
			stack[sp] = stack[sp - 1];
			sp++;
			break;

		case OP_POP:
			sp--;
			break;

		default:
			fprintf(stderr, "hx: unknown opcode %d at pc=%d\n",
			        ip->op, pc - 1);
			exit(1);
		}
	}
}
