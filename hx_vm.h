/*
 * hx_vm.h - bytecode VM types for the hx hash expression language
 *
 * Execution model: AST is compiled to a flat instruction stream once,
 * then the VM runs it per-password.  Function pointers and variable
 * slot indices are resolved at compile time.
 *
 * Values are byte strings (hash outputs, concatenations, literals)
 * or integers (loop counters).  All string data is bump-allocated
 * from a per-password arena that resets between runs.
 */

#ifndef HX_VM_H
#define HX_VM_H

#include <stdint.h>
#include "hx_ast.h"

/* ---- arena: bump allocator, reset per password ----
 * Every pointer it returns stays valid until the next reset: when the current
 * block is full a new, larger block is started and the full one is kept on
 * `old` (never realloc()ed, which moved every value already handed out).
 * Reset frees the old blocks and keeps the newest, largest one. */

#define HX_ARENA_SIZE  (256 * 1024)   /* 256 KB default */

typedef struct hx_arena_blk hx_arena_blk;

typedef struct hx_emits hx_emits;

typedef struct {
	char *buf;
	int   used;
	int   cap;
	hx_arena_blk *old;   /* full blocks still holding live values */
	hx_emits *emits;     /* non-NULL: emit() collects here instead of writing
	                      * stdout (hx_vm.capture); set by hx_vm_run */
} hx_arena;

void  hx_arena_init(hx_arena *a, int cap);
char *hx_arena_alloc(hx_arena *a, int size);
void  hx_arena_reset(hx_arena *a);
void  hx_arena_free(hx_arena *a);

/* ---- values ---- */

typedef struct {
	char   *data;       /* points into arena, string table, or input */
	int     len;
	int64_t ival;       /* valid when is_int=1 */
	uint8_t is_int;
} hx_val;

/*
 * ---- output-role enum ----
 *
 * Each call site selects one of five output roles via the function-name
 * suffix (`_bin`, `_hex`, `_b64`, `_mcf`, `_uc`).  The bare name (no suffix)
 * resolves to the function's `default_role` — typically ROLE_HEX for
 * digests/HMAC/KDF, ROLE_MCF for crypt-family built-ins (bcrypt, yescrypt).
 *
 * Per spec hx.1 §2.4 rev 1.5:
 *   ROLE_BIN — raw key material (bytes the algorithm derives)
 *   ROLE_HEX — lowercase hex of ROLE_BIN
 *   ROLE_B64 — RFC 4648 base64 (with `=` padding) of ROLE_BIN
 *   ROLE_MCF — full Modular Crypt Format string (crypt families only)
 *
 * Functions advertise which roles they support via `supported_roles`
 * (bitmask of ROLE_CAP_*).  Applying an unsupported suffix is a
 * compile-time error.  ROLE_DEFAULT is always allowed and dispatches
 * to the function's default_role internally.
 */
enum hx_role {
	ROLE_DEFAULT = 0,   /* no suffix — use entry->default_role */
	ROLE_BIN     = 1,
	ROLE_HEX     = 2,
	ROLE_B64     = 3,
	ROLE_MCF     = 4,
	ROLE_UC      = 5,   /* uppercase hex */
};

#define ROLE_CAP_BIN  (1u << ROLE_BIN)
#define ROLE_CAP_HEX  (1u << ROLE_HEX)
#define ROLE_CAP_B64  (1u << ROLE_B64)
#define ROLE_CAP_MCF  (1u << ROLE_MCF)
#define ROLE_CAP_UC   (1u << ROLE_UC)

/* ---- hash function registry ---- */

typedef struct hx_func_entry hx_func_entry;

/*
 * Hash function signature.
 * self:        pointer to this entry (for bridge functions to access ctx)
 * args/nargs:  input arguments (popped from stack)
 * result:      output value (caller provides; data from arena)
 * arena:       arena for allocating result data
 * role:        one of enum hx_role.  ROLE_DEFAULT means "use the
 *              function's default form"; ROLE_BIN/HEX/B64/MCF are the
 *              explicit forms requested via the `_bin/_hex/_b64/_mcf`
 *              suffix.  Each fn maps ROLE_DEFAULT to its canonical role
 *              (for digests/HMAC/KDF that's ROLE_HEX; for bcrypt/yescrypt
 *              it's ROLE_MCF).
 */
typedef void (*hx_hashfn)(hx_func_entry *self, hx_val *args, int nargs,
                          hx_val *result, hx_arena *arena, uint8_t role);

/*
 * Bridge function type: hashpipe's compute_* signature.
 * (pass, passlen, salt, saltlen, dest)
 */
typedef void (*hx_bridge_fn)(const unsigned char *pass, int passlen,
                             const unsigned char *salt, int saltlen,
                             unsigned char *dest);

struct hx_func_entry {
	const char  *name;       /* canonical name, e.g. "md5" */
	hx_hashfn    fn;
	int           max_out;   /* max output bytes (binary form) */
	/* bridge fields — used by hx_bridge_hash() for hashpipe integration */
	hx_bridge_fn  bridge;    /* hashpipe compute_* function, or NULL */
	int           bridge_bytes; /* digest size in bytes */
	/* role-capability metadata (see enum hx_role) */
	uint8_t       supported_roles; /* bitmask: ROLE_CAP_BIN|HEX|B64|MCF|UC */
	uint8_t       default_role;    /* ROLE_HEX, ROLE_MCF, or ROLE_DEFAULT */
};

/* Dynamic registry */
#define HX_MAX_FUNCS 1200
extern hx_func_entry hx_func_table[];
extern int           hx_func_count;

void hx_func_register(const char *name, hx_hashfn fn, int max_out,
                       hx_bridge_fn bridge, int bridge_bytes,
                       uint8_t supported_roles, uint8_t default_role);

/* Bridge wrapper: hashpipe compute_* → hx function */
void hx_bridge_hash(hx_func_entry *self, hx_val *args, int nargs,
                    hx_val *result, hx_arena *arena, uint8_t role);

hx_func_entry *hx_func_lookup(const char *name);

/* ---- opcodes ---- */

enum {
	OP_PUSH_VAR,    /* operand: slot index           → push var[slot]     */
	OP_PUSH_STR,    /* operand: string table index    → push constant     */
	OP_PUSH_INT,    /* operand: int64_t               → push integer      */
	OP_STORE,       /* operand: slot index     top →  store in var[slot]  */
	OP_CALL,        /* operand: func_entry*, nargs, binary                */
	OP_CONCAT,      /*                     a, b →  a.b                   */
	OP_HALT,        /* result = stack top                                 */
	OP_JUMP,        /* operand: addr                                      */
	OP_INC,         /* operand: slot index     var[slot]++               */
	OP_JUMP_LE,     /* operand: addr     a, b → jump if a <= b          */
	OP_JUMP_LT,     /* operand: addr     a, b → jump if a <  b          */
	OP_JUMP_GT,     /* operand: addr     a, b → jump if a >  b          */
	OP_JUMP_GE,     /* operand: addr     a, b → jump if a >= b          */
	OP_JUMP_EQ,     /* operand: addr     a, b → jump if a == b (string) */
	OP_JUMP_NE,     /* operand: addr     a, b → jump if a != b (string) */
	OP_DUP,         /* duplicate stack top                                */
	OP_POP,         /* discard stack top                                  */
	OP_CONVERT,     /* operand: conv {from,to,policy,premap}  x → x'     */
	                /* appended last: the numbering of the opcodes above  */
	                /* is serialized into codegen/hx_specs_data.c         */
};

/*
 * ---- OP_CONVERT: one instruction for every conversion ----
 *
 * hx-functions.md section 18.  Decode the input from `from`, apply `premap`,
 * encode into `to`.  `from` and `to` index one registry of charsets (text:
 * bytes <-> code points) and transfer encodings (bytes <-> ASCII text).  The
 * legacy conversion functions (utf16le, zext16, from_cp1252, hex, base64, ...)
 * are compiler aliases that emit this instruction; convert() exposes it.
 *
 * The registry numbers are serialized into the generated catalog, which is
 * regenerated on every build, but append new entries anyway.
 */
enum hx_conv_id {
	HXE_NONE = 0,
	/* charsets */
	HXE_UTF8, HXE_UTF16LE, HXE_UTF16BE, HXE_UTF7, HXE_LATIN1,
	HXE_CP1252, HXE_CP1251, HXE_CP37,
	/* transfer encodings */
	HXE_RAW, HXE_HEX, HXE_BASE64, HXE_BASE64URL, HXE_BASE32,
	HXE_CRYPT64, HXE_CRYPT64BE, HXE_BCRYPT64,
	/* phase 2: KOI8 and the remaining Windows code pages (section 18.3) */
	HXE_KOI8R, HXE_KOI8U,
	HXE_CP874, HXE_CP932, HXE_CP936, HXE_CP949, HXE_CP950,
	HXE_CP1250, HXE_CP1253, HXE_CP1254, HXE_CP1255, HXE_CP1256,
	HXE_CP1257, HXE_CP1258, HXE_CP1361,
	HXE_CP437, HXE_CP737, HXE_CP775, HXE_CP850, HXE_CP852, HXE_CP855,
	HXE_CP857, HXE_CP858, HXE_CP860, HXE_CP861, HXE_CP862, HXE_CP863,
	HXE_CP864, HXE_CP865, HXE_CP866, HXE_CP869,
	HXE_CP20866, HXE_CP21866, HXE_CP28591,
	HXE_CP1047, HXE_CP1140, HXE_CP1148, HXE_CP10000,
	/* phase 3 */
	HXE_LOWBYTE16,     /* encode only: the low byte of each UTF-16 unit */
	/* phase 4b: the remaining Windows pages (cpdump2) */
	HXE_CP500, HXE_CP708, HXE_CP720, HXE_CP875, HXE_CP1026, HXE_CP1141,
	HXE_CP1142, HXE_CP1143, HXE_CP1144, HXE_CP1145, HXE_CP1146, HXE_CP1147,
	HXE_CP1149, HXE_CP10001, HXE_CP10002, HXE_CP10003, HXE_CP10004,
	HXE_CP10005, HXE_CP10006, HXE_CP10007, HXE_CP10008, HXE_CP10010,
	HXE_CP10017, HXE_CP10021, HXE_CP10029, HXE_CP10079, HXE_CP10081,
	HXE_CP10082, HXE_CP20127, HXE_CP28592, HXE_CP28593, HXE_CP28594,
	HXE_CP28595, HXE_CP28596, HXE_CP28597, HXE_CP28598, HXE_CP28599,
	HXE_CP28603, HXE_CP28605,
	/* phase 4b: standard single-byte charsets, in hx_conv_tables.h SB order */
	HXE_SB_ISO8859_2, HXE_SB_ISO8859_3, HXE_SB_ISO8859_4, HXE_SB_ISO8859_5,
	HXE_SB_ISO8859_6, HXE_SB_ISO8859_7, HXE_SB_ISO8859_8, HXE_SB_ISO8859_9,
	HXE_SB_ISO8859_10, HXE_SB_ISO8859_11, HXE_SB_ISO8859_13,
	HXE_SB_ISO8859_14, HXE_SB_ISO8859_15, HXE_SB_ISO8859_16,
	HXE_SB_MAC_ROMAN, HXE_SB_MAC_CYRILLIC, HXE_SB_MAC_GREEK,
	HXE_SB_MAC_TURKISH, HXE_SB_MAC_CENTEURO, HXE_SB_MAC_ICELANDIC,
	HXE_SB_MAC_CROATIAN, HXE_SB_MAC_ROMANIAN, HXE_SB_MAC_ARABIC,
	HXE_SB_MAC_HEBREW, HXE_SB_MAC_THAI, HXE_SB_ADOBE_SYMBOL,
	HXE_SB_ADOBE_STANDARD, HXE_SB_JIS_X0201, HXE_SB_KZ1048, HXE_SB_VISCII,
	HXE_SB_HP_ROMAN8, HXE_SB_DEC_MCS, HXE_SB_ATASCII, HXE_SB_PETSCII,
	HXE_SB_PETSCII_SHIFTED, HXE_SB_ASCII, HXE_SB_CP864_IBMGRAPH,
	/* phase 4b: multi-byte charsets, in hx_conv_tables.h MB order */
	HXE_MB_SHIFT_JIS, HXE_MB_EUC_JP, HXE_MB_EUC_KR, HXE_MB_GB2312, HXE_MB_GB18030,
	HXE_MB_SHIFT_JIS_WEB, HXE_MB_EUC_JP_WEB, HXE_MB_EUC_KR_WEB, HXE_MB_BIG5_WEB,
	HXE_MB_GB18030_WEB, HXE_MB_GBK_WEB, HXE_MB_GSM0338, HXE_MB_T61,
	HXE_MB_EUC_JP_C1, HXE_MB_EUC_KR_C1,
	HXE_ISO2022JP, HXE_ISO2022JP_WEB,   /* stateful; the euc_jp tables */
	/* phase 4b: the remaining Unicode forms */
	HXE_UTF32LE, HXE_UTF32BE, HXE_UTF32, HXE_UTF16, HXE_CESU8,
	HXE_COUNT
};

#define HXE_KIND_CHARSET  1
#define HXE_KIND_TRANSFER 2
#define HXE_SB_FIRST HXE_SB_ISO8859_2   /* hx_conv_tables.h hxt_sb_* index 0 */
#define HXE_MB_FIRST HXE_MB_SHIFT_JIS   /* hx_conv_tables.h hxt_mb_* index 0 */

/* policy bits (section 18.4, plus the transfer-encoding format tokens).
 * Every group's default is 0, so naming a default token compiles to the same
 * instruction as naming none. */
#define HXCV_ILL_MASK    0x0003  /* ill-formed utf8 source: */
#define HXCV_ILL_KEEP    0x0000  /*   keep (default)        */
#define HXCV_ILL_NULL    0x0001  /*   null                  */
#define HXCV_ILL_LATIN1  0x0002  /*   latin1                */
#define HXCV_ILL_FFFD    0x0003  /*   fffd                  */
#define HXCV_SUR_MASK    0x000c  /* lone surrogate, utf16 source: */
#define HXCV_SUR_FFFD    0x0000  /*   fffd (default)              */
#define HXCV_SUR_Q       0x0004  /*   q                           */
#define HXCV_SUR_CESU    0x0008  /*   cesu                        */
#define HXCV_BESTFIT     0x0010  /* encode: strict (default) / bestfit */
#define HXCV_FAIL        0x0020  /* unmappable: default (default) / fail */
#define HXCV_UC          0x0040  /* hex target: uppercase */
#define HXCV_NOPAD       0x0080  /* base64/base64url/base32: no '=' padding */
#define HXCV_LENIENT     0x0100  /* hex/base64 source: fromhex()/frombase64()'s
                                  * decoding, never null (hx-support/phase2) */
#define HXCV_GLYPHS      0x0200  /* OEM cpNNN source: 0x00-0x1F and 0x7F decode
                                  * to their glyphs (MB_USEGLYPHCHARS) */

/* premap tokens (sections 18.5, 18.5a): 0 = none.  On transfer encodings
 * (bytes) only LOWER, UPPER, REV and ROT13 apply. */
#define HXPM_NONE      0
#define HXPM_LOWER     1   /* bytes: ASCII; characters: Unicode 18.0.0 simple */
#define HXPM_UPPER     2
#define HXPM_REV       3   /* bytes, or characters by the section 3 model */
#define HXPM_ROT13     4   /* ASCII letters only, in either domain */
#define HXPM_LOWER_WIN 5   /* Windows CharLowerW, BMP */
#define HXPM_UPPER_WIN 6   /* Windows CharUpperW, BMP */
#define HXPM_UPPER_OEM 7   /* Windows RtlUpcaseUnicodeToOemN, OEM cpNNN targets */
#define HXPM_LOWER_FULL 8  /* Unicode 18.0.0 full mapping (SpecialCasing), */
#define HXPM_UPPER_FULL 9  /*   with Final_Sigma, no language conditions   */
#define HXPM_NFC       10  /* UAX #15, Unicode 18.0.0 */
#define HXPM_NFD       11
#define HXPM_NFKC      12
#define HXPM_NFKD      13
#define HXPM_NFD_HFS   14  /* HFS+ decomposition (TN1150), as a real volume does */


/* ---- instruction ---- */

typedef struct {
	uint8_t op;
	union {
		int          slot;      /* PUSH_VAR, STORE, INC */
		int          stridx;    /* PUSH_STR */
		int64_t      ival;      /* PUSH_INT */
		int          addr;      /* JUMP, JUMP_LE/LT/GT/GE, JUMP_EQ, JUMP_NE */
		struct {
			hx_func_entry *entry;
			int            nargs;
			uint8_t        role;   /* enum hx_role */
		} call;
		struct {
			uint8_t        from;   /* enum hx_conv_id */
			uint8_t        to;     /* enum hx_conv_id */
			uint8_t        premap; /* HXPM_* */
			uint16_t       policy; /* HXCV_* bits */
		} conv;                 /* CONVERT */
	} u;
} hx_inst;

/* ---- compiled program ---- */

typedef struct {
	hx_inst *code;
	int      ncode;

	/* string constant table */
	char   **strings;
	int     *strlens;
	int      nstrings;

	/* variable slots: 0=pass, 1=salt, 2=salt2, 3=pepper, 4+=user */
	char   **varnames;
	int      nvars;

	int      max_stack;     /* estimated max stack depth */
	int      has_emit;      /* 1 if program contains emit() calls */
	int      text_loop;     /* 1 if a for ... in loop over encodings was
	                         * unrolled (hx-functions.md 19.1): CPU only */
	int      uses_groups;   /* 1 if a loop iterates a charsets() group,
	                         * whose members grow (hx-functions.md 19.4b) */
} hx_program;

/* ---- built-in variable slots ---- */

#define HX_SLOT_PASS    0
#define HX_SLOT_SALT    1
#define HX_SLOT_SALT2   2
#define HX_SLOT_PEPPER  3
#define HX_SLOT_USERID  4
#define HX_SLOT_USERVARS 5  /* first user-defined variable slot */

/* ---- compiler (AST → bytecode) ---- */

hx_program *hx_compile(hx_node *ast);
void        hx_program_free(hx_program *prog);
void        hx_program_dump(hx_program *prog);  /* debug */

/* ---- VM ---- */

/*
 * Run the compiled program with the given inputs.
 * Returns the result string (allocated from arena).
 * The caller must use/copy the result before the next hx_vm_run
 * call, as the arena is reset.
 */
typedef struct {
	hx_program *prog;
	hx_arena    arena;
	hx_val     *stack;
	int         stack_cap;
	hx_val     *vars;       /* variable slots */
	hx_inst    *code;       /* what runs: prog->code, or its fused copy */
	hx_inst    *owncode;    /* the fused copy (hx_vm_free frees it), or NULL */
	/* capture = 1 (set after hx_vm_init): emit() does not write stdout; each
	 * run collects what it emits in emits.v[0 .. emits.n-1], valid until the
	 * next run.  A value is collected in the text one-argument emit() would
	 * print: as is when every byte is 0x20-0x7e, else lowercase hex.  This
	 * is how mdxfind and hashpipe run a user type (hx-functions.md 19,
	 * decision 2: each emitted value is one candidate digest). */
	int         capture;
	struct hx_emits {
		hx_val *v;
		int     n, cap;
	} emits;
} hx_vm;

/* 1 (default): hx_vm_init fuses adjacent conversions (hx_convert_fuse) in
 * its own copy of the code.  The tests set 0 to run the unfused program. */
extern int hx_vm_fuse;

void    hx_vm_init(hx_vm *vm, hx_program *prog);
hx_val  hx_vm_run(hx_vm *vm, const char *pass, int passlen,
                   const char *salt, int saltlen,
                   const char *salt2, int salt2len,
                   const char *pepper, int pepperlen,
                   const char *user, int userlen);
void    hx_vm_free(hx_vm *vm);

/* ---- OP_CONVERT support (hx_func.c) ---- */

/* Registry lookups: id from name (0 if unknown), name and kind from id. */
int         hx_conv_lookup(const char *name);
const char *hx_conv_name(int id);
int         hx_conv_kind(int id);

/*
 * Build a CONVERT instruction from convert()'s string arguments: from, to and
 * any tokens.  Returns 0 and fills *ip, or -1 with a message in err naming
 * the offending token.
 */
int hx_convert_build(const char *from, const char *to,
                     const char *const *tokens, int ntokens,
                     hx_inst *ip, char *err, int errcap);

/* Compiler aliases: a named function that compiles to OP_CONVERT.  Returns 1
 * and fills *ip when name is one. */
int hx_convert_alias_inst(const char *name, hx_inst *ip);

/*
 * The legacy function a CONVERT instruction is identical to (utf16le, zext16,
 * from_cp1252, hex, ...), or NULL when it has none.  The stable shared id
 * hashes such an instruction exactly as that function's OP_CALL (nargs 1,
 * role 0), so no existing id moves.
 */
const char *hx_convert_legacy_name(const hx_inst *ip);

/*
 * Fusion (hx-functions.md 18.7): replace each pair of adjacent CONVERTs whose
 * composition is exactly one CONVERT by that one, in place, and return the
 * new instruction count.  names (may be NULL) is the parallel call-name
 * array, shifted with the code.  Jump targets are renumbered; an instruction
 * that is a jump target is never fused into the one before it.  Used by the
 * VM (hx_vm_init) and the dedup comparator, never by the compiler: the
 * stable shared id hashes the program before fusion.
 */
int hx_convert_fuse(hx_inst *code, const char **names, int n);

/* "cp1252->utf8 [bestfit,fail] premap=none" */
void hx_convert_describe(const hx_inst *ip, char *buf, int cap);

/* Execute: *out = convert(*in).  A null result is an empty string. */
void hx_convert_run(const hx_inst *ip, const hx_val *in, hx_val *out,
                    hx_arena *arena);

/* charsets(group), hx-functions.md 19.1: the members of a named group in
 * order, NULL-terminated, or NULL for an unknown group (hx_func.c). */
const char *const *hx_charsets(const char *group);

/* "Unicode 18.0.0 ..." and the table sources, for hx -V (hx_func.c). */
const char *hx_build_facts(void);

/* ---- high-level entry point (from hx.c) ---- */

hx_program *hx_compile_expr(const char *expr, const char *script_file);

/* hx_compile_expr_trapped: compile an expression as hx_compile_expr does, but
 * a parse or compile error returns NULL, after its diagnostic, instead of
 * ending the process.  The userdef loader uses it so that one broken stanza
 * is reported with its name and file, the rest of the file is still read,
 * and every broken stanza appears in one pass.  hx_compile_die() is how
 * every compile and parse error ends: it returns to the trapped caller when
 * there is one, and exits 1 otherwise. */
hx_program *hx_compile_expr_trapped(const char *expr);
void        hx_compile_die(void);

/* Diagnostics emitted by the lexer/parser; see hx.c. Reset to 0 before a
 * compile and test after it to detect an expression that lexed with errors
 * yet still produced a program. */
extern int hx_diag_count;

#endif /* HX_VM_H */
