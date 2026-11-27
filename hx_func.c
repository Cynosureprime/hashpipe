/*
 * hx_func.c - hash function registry for hx
 *
 * Two kinds of functions:
 * 1. Native hx functions (string transforms, encoding)
 * 2. Bridge functions that wrap hashpipe's compute_* via hx_bridge_hash()
 *
 * When compiled standalone (HX_STANDALONE), includes basic hash functions
 * via OpenSSL.  When linked into hashpipe, hash functions are registered
 * dynamically from hashpipe's type registry.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "hx_vm.h"

/* ---- shared helpers ---- */

static int val_to_int(hx_val *v)
{
	if (v->is_int) return (int)v->ival;
	if (v->data) return atoi(v->data);
	return 0;
}

/* ---- hex encoding helper ---- */

static const char hex_lc[] = "0123456789abcdef";
static const char hex_uc[] = "0123456789ABCDEF";

static void to_hex(const unsigned char *bin, int binlen, char *out)
{
	int i;
	for (i = 0; i < binlen; i++) {
		out[i * 2]     = hex_lc[bin[i] >> 4];
		out[i * 2 + 1] = hex_lc[bin[i] & 0x0f];
	}
	out[binlen * 2] = '\0';
}

/*
 * Uppercase hex, the ROLE_UC representation.  This is a representation of
 * the same digest, not a different digest, which is why it belongs with the
 * other output-role suffixes rather than being a function of its own: under
 * iteration the role is what feeds the next round, so md5_uc^N(pass) chains
 * uppercase where upper(md5^N(pass)) would only uppercase the final result.
 * The two agree at N=1 and diverge from N=2 onward.
 */
static void to_hex_uc(const unsigned char *bin, int binlen, char *out)
{
	int i;
	for (i = 0; i < binlen; i++) {
		out[i * 2]     = hex_uc[bin[i] >> 4];
		out[i * 2 + 1] = hex_uc[bin[i] & 0x0f];
	}
	out[binlen * 2] = '\0';
}

/* ================================================================
 * Base64 helper (RFC 4648 with `=` padding, used by bridge and KDFs)
 * ================================================================ */

static const char b64_std_alpha[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * Encode binlen raw bytes from `bin` into `out` as RFC 4648 base64
 * with `=` padding.  Returns the number of bytes written (excluding
 * the terminating NUL).  `out` must have room for at least
 * ((binlen + 2) / 3) * 4 + 1 bytes.
 */
static int to_b64(const unsigned char *bin, int binlen, char *out)
{
	int i, o = 0;
	for (i = 0; i < binlen; i += 3) {
		unsigned int a = bin[i];
		unsigned int b = (i + 1 < binlen) ? bin[i + 1] : 0;
		unsigned int c = (i + 2 < binlen) ? bin[i + 2] : 0;
		unsigned int triple = (a << 16) | (b << 8) | c;
		out[o++] = b64_std_alpha[(triple >> 18) & 0x3f];
		out[o++] = b64_std_alpha[(triple >> 12) & 0x3f];
		out[o++] = (i + 1 < binlen) ? b64_std_alpha[(triple >> 6) & 0x3f] : '=';
		out[o++] = (i + 2 < binlen) ? b64_std_alpha[triple & 0x3f] : '=';
	}
	out[o] = '\0';
	return o;
}

/* ================================================================
 * Bridge wrapper: adapts hashpipe's compute_*(pass,passlen,salt,
 * saltlen,dest) to hx's function signature.  The hashfn_t and
 * digest size are stored in the func_entry's bridge fields.
 *
 * Supported roles for bridged types: ROLE_BIN, ROLE_HEX, ROLE_B64.
 * ROLE_DEFAULT canonicalizes to ROLE_HEX (registered explicitly via
 * hx_register_hashpipe_types in hashpipe.c).  ROLE_MCF is rejected
 * at compile time via supported_roles.
 * ================================================================ */

void hx_bridge_hash(hx_func_entry *self, hx_val *args, int nargs,
                    hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char digest[128];
	const unsigned char *salt = NULL;
	int saltlen = 0;
	int n = self->bridge_bytes;

	(void)nargs;

	/* If 2 args, second is salt */
	if (nargs >= 2) {
		salt = (const unsigned char *)args[1].data;
		saltlen = args[1].len;
	}

	self->bridge((const unsigned char *)args[0].data, args[0].len,
	             salt, saltlen, digest);

	/* ROLE_DEFAULT for digests dispatches to ROLE_HEX */
	if (role == ROLE_DEFAULT) role = self->default_role;
	if (role == ROLE_DEFAULT) role = ROLE_HEX;  /* belt-and-braces */

	if (role == ROLE_BIN) {
		result->data = hx_arena_alloc(arena, n);
		memcpy(result->data, digest, n);
		result->len = n;
	} else if (role == ROLE_B64) {
		int max = ((n + 2) / 3) * 4 + 1;
		result->data = hx_arena_alloc(arena, max);
		result->len = to_b64(digest, n, result->data);
	} else if (role == ROLE_UC) {
		result->data = hx_arena_alloc(arena, n * 2 + 1);
		to_hex_uc(digest, n, result->data);
		result->len = n * 2;
	} else {
		/* ROLE_HEX (default) */
		result->data = hx_arena_alloc(arena, n * 2 + 1);
		to_hex(digest, n, result->data);
		result->len = n * 2;
	}
}

/*
 * Shared helper: emit a fixed-size digest in the requested role.
 * ROLE_DEFAULT canonicalizes to ROLE_HEX for digests/HMAC/KDF outputs.
 */
static void emit_digest(unsigned char *digest, int dlen, hx_val *result,
                        hx_arena *arena, uint8_t role)
{
	if (role == ROLE_DEFAULT) role = ROLE_HEX;

	if (role == ROLE_BIN) {
		result->data = hx_arena_alloc(arena, dlen);
		memcpy(result->data, digest, dlen);
		result->len = dlen;
	} else if (role == ROLE_B64) {
		int max = ((dlen + 2) / 3) * 4 + 1;
		result->data = hx_arena_alloc(arena, max);
		result->len = to_b64(digest, dlen, result->data);
	} else if (role == ROLE_UC) {
		result->data = hx_arena_alloc(arena, dlen * 2 + 1);
		to_hex_uc(digest, dlen, result->data);
		result->len = dlen * 2;
	} else {
		/* ROLE_HEX */
		result->data = hx_arena_alloc(arena, dlen * 2 + 1);
		to_hex(digest, dlen, result->data);
		result->len = dlen * 2;
	}
}

/* ================================================================
 * Standalone hash functions (used when HX_STANDALONE is defined)
 * ================================================================ */

#ifdef HX_STANDALONE
#include <openssl/md5.h>
#include <openssl/md4.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

static void fn_md5(hx_func_entry *self, hx_val *args, int nargs,
                   hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char digest[16];
	(void)self; (void)nargs;
	MD5((unsigned char *)args[0].data, args[0].len, digest);
	emit_digest(digest, 16, result, arena, role);
}

static void fn_md4(hx_func_entry *self, hx_val *args, int nargs,
                   hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char digest[16];
	(void)self; (void)nargs;
	MD4((unsigned char *)args[0].data, args[0].len, digest);
	emit_digest(digest, 16, result, arena, role);
}

static void fn_sha1(hx_func_entry *self, hx_val *args, int nargs,
                    hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char digest[20];
	(void)self; (void)nargs;
	SHA1((unsigned char *)args[0].data, args[0].len, digest);
	emit_digest(digest, 20, result, arena, role);
}

static void fn_sha256(hx_func_entry *self, hx_val *args, int nargs,
                      hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char digest[32];
	(void)self; (void)nargs;
	SHA256((unsigned char *)args[0].data, args[0].len, digest);
	emit_digest(digest, 32, result, arena, role);
}

static void fn_sha512(hx_func_entry *self, hx_val *args, int nargs,
                      hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char digest[64];
	(void)self; (void)nargs;
	SHA512((unsigned char *)args[0].data, args[0].len, digest);
	emit_digest(digest, 64, result, arena, role);
}

static void fn_hmac_sha1(hx_func_entry *self, hx_val *args, int nargs,
                         hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char digest[20];
	unsigned int dlen = 20;
	(void)self; (void)nargs;
	/* hx spells HMAC as hmac_X(MESSAGE, KEY): the second operand is the
	 * key. mdxfind takes it from the -u channel, hashpipe resolves the
	 * same name from its registered Hashtypes[] the same way, and the
	 * catalogs KPASS entries (e798 hmac_rmd160(salt, pass), "key is
	 * pass") only parse under that reading. This standalone copy had the
	 * operands the other way round, so hx_dedup_check and hx8_to_c
	 * evaluated every hmac expression with pass as the key -- disagreeing
	 * with both real engines for the same expression text. */
	HMAC(EVP_sha1(), args[1].data, args[1].len,
	     (unsigned char *)args[0].data, args[0].len, digest, &dlen);
	emit_digest(digest, 20, result, arena, role);
}

static void fn_hmac_sha256(hx_func_entry *self, hx_val *args, int nargs,
                           hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char digest[32];
	unsigned int dlen = 32;
	(void)self; (void)nargs;
	/* hx spells HMAC as hmac_X(MESSAGE, KEY): the second operand is the
	 * key. mdxfind takes it from the -u channel, hashpipe resolves the
	 * same name from its registered Hashtypes[] the same way, and the
	 * catalogs KPASS entries (e798 hmac_rmd160(salt, pass), "key is
	 * pass") only parse under that reading. This standalone copy had the
	 * operands the other way round, so hx_dedup_check and hx8_to_c
	 * evaluated every hmac expression with pass as the key -- disagreeing
	 * with both real engines for the same expression text. */
	HMAC(EVP_sha256(), args[1].data, args[1].len,
	     (unsigned char *)args[0].data, args[0].len, digest, &dlen);
	emit_digest(digest, 32, result, arena, role);
}
#endif /* HX_STANDALONE */

/* ================================================================
 * PBKDF2 (available with OpenSSL — both standalone and hashpipe)
 * ================================================================ */

#include <openssl/evp.h>

/*
 * pbkdf2_sha1(pass, salt, iterations, dklen)
 * pbkdf2_sha256(pass, salt, iterations, dklen)
 * pbkdf2_sha512(pass, salt, iterations, dklen)
 * pbkdf2_md5(pass, salt, iterations, dklen)
 *
 * Returns raw key bytes (or hex if no _bin suffix).
 * iterations and dklen are integer arguments.
 */
static void fn_pbkdf2(hx_func_entry *self, hx_val *args, int nargs,
                      hx_val *result, hx_arena *arena, uint8_t role,
                      const EVP_MD *md)
{
	int iterations = 1000, dklen = 32;
	unsigned char *dk;

	if (nargs >= 3) iterations = val_to_int(&args[2]);
	if (nargs >= 4) dklen = val_to_int(&args[3]);
	if (iterations < 1) iterations = 1;
	if (dklen < 1) dklen = 1;
	if (dklen > 1024) dklen = 1024;

	dk = (unsigned char *)hx_arena_alloc(arena, dklen);
	PKCS5_PBKDF2_HMAC(args[0].data, args[0].len,
	                   (unsigned char *)args[1].data, args[1].len,
	                   iterations, md, dklen, dk);
	emit_digest(dk, dklen, result, arena, role);
	(void)self;
}

static void fn_pbkdf2_sha1(hx_func_entry *self, hx_val *args, int nargs,
                            hx_val *result, hx_arena *arena, uint8_t role)
{ fn_pbkdf2(self, args, nargs, result, arena, role, EVP_sha1()); }

static void fn_pbkdf2_sha256(hx_func_entry *self, hx_val *args, int nargs,
                              hx_val *result, hx_arena *arena, uint8_t role)
{ fn_pbkdf2(self, args, nargs, result, arena, role, EVP_sha256()); }

static void fn_pbkdf2_sha512(hx_func_entry *self, hx_val *args, int nargs,
                              hx_val *result, hx_arena *arena, uint8_t role)
{ fn_pbkdf2(self, args, nargs, result, arena, role, EVP_sha512()); }

static void fn_pbkdf2_md5(hx_func_entry *self, hx_val *args, int nargs,
                           hx_val *result, hx_arena *arena, uint8_t role)
{ fn_pbkdf2(self, args, nargs, result, arena, role, EVP_md5()); }

/* ================================================================
 * KDF + crypt-family built-ins.
 *
 * Outer gate `!HX_STANDALONE || HX_HAS_KDF`: hashpipe (no HX_STANDALONE)
 * and mdxfind (HX_STANDALONE + HX_HAS_KDF) both get this whole section;
 * tools/hx8_to_c (HX_STANDALONE alone) skips it.  Per-function NESTED
 * guards `#ifndef HX_STANDALONE` carve out the few entries mdxfind
 * doesn't link (pomelo_hash, etc.) so they remain hashpipe-only.
 * ================================================================ */

#if !defined(HX_STANDALONE) || defined(HX_HAS_KDF)

#include "yescrypt/yescrypt.h"
#include "argon2/argon2.h"

extern char *crypt_rn(const char *key, const char *setting,
                      void *output, int size);
extern int crypto_scrypt(const uint8_t *passwd, size_t passwdlen,
                         const uint8_t *salt, size_t saltlen,
                         uint64_t N, uint32_t r, uint32_t p,
                         uint8_t *buf, size_t buflen);

/*
 * bcrypt-base64 inverse-decode: turn a 31-char bcrypt-base64 string
 * into 23 raw bytes.  bcrypt's output format encodes only 23 of the
 * 24 internal Blowfish bytes (the final byte is bug-compatibly
 * truncated; see crypt_blowfish.c, "only encode 23 of the 24 bytes").
 *
 * Returns 0 on success, -1 if a non-alphabet byte is encountered.
 *
 * Alphabet (matches `bcrypt_b64[]` defined later in this file):
 *   ./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
 */
static int bcrypt_b64_decode(const char *src, int srclen,
                             unsigned char *dst, int *dstlen)
{
	static signed char d[256];
	static int d_init = 0;
	int i, j;
	int outpos = 0;

	if (!d_init) {
		static const char alpha[] =
			"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		memset(d, -1, sizeof(d));
		for (j = 0; j < 64; j++) d[(unsigned char)alpha[j]] = j;
		d_init = 1;
	}

	for (i = 0; i + 1 < srclen; ) {
		int c1 = d[(unsigned char)src[i++]];
		int c2 = (i < srclen) ? d[(unsigned char)src[i++]] : 0;
		int c3 = (i < srclen) ? d[(unsigned char)src[i++]] : -1;
		int c4 = (i < srclen) ? d[(unsigned char)src[i++]] : -1;
		if (c1 < 0 || c2 < 0) return -1;
		dst[outpos++] = (unsigned char)((c1 << 2) | ((c2 & 0x30) >> 4));
		if (c3 < 0) break;
		dst[outpos++] = (unsigned char)(((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2));
		if (c4 < 0) break;
		dst[outpos++] = (unsigned char)(((c3 & 0x03) << 6) | c4);
	}
	*dstlen = outpos;
	return 0;
}

/*
 * bcrypt(pass, salt, cost)
 *
 * pass:  password string
 * salt:  16 bytes of raw salt (or 22-char bcrypt-base64 salt)
 * cost:  integer cost factor (4-31), default 12
 *
 * Output roles (per spec hx.1 §2.4 rev 1.5):
 *   ROLE_DEFAULT == ROLE_MCF — full $2b$CC$<22-salt><31-hash> string (60 chars)
 *   ROLE_BIN — 23 raw Blowfish output bytes (decoded from the 31-char hash)
 *              Note: bcrypt's wire format is bug-compatibly 23 bytes, NOT 24
 *              (the 24th byte is truncated by crypt_blowfish.c per the
 *              original OpenBSD implementation).  This is what mdxfind sees
 *              and what hashcat expects.
 *   ROLE_HEX — 46-char lowercase hex of the 23 raw bytes
 *   ROLE_B64 — 31-char bcrypt-base64 hash portion (the canonical "hash"
 *              field within an MCF entry — useful for splitting MCF lines)
 */
static void fn_bcrypt(hx_func_entry *self, hx_val *args, int nargs,
                      hx_val *result, hx_arena *arena, uint8_t role)
{
	char setting[64], output[128], *pass_z;
	int cost = 12;
	(void)self;

	if (role == ROLE_DEFAULT) role = ROLE_MCF;

	if (nargs >= 3) cost = val_to_int(&args[2]);
	if (cost < 4) cost = 4;
	if (cost > 31) cost = 31;

	/* Build the setting string: $2b$CC$<22-char bcrypt-base64 salt> */
	if (args[1].len >= 22 && (args[1].data[0] == '.' ||
	    (args[1].data[0] >= 'A' && args[1].data[0] <= 'Z') ||
	    (args[1].data[0] >= 'a' && args[1].data[0] <= 'z') ||
	    (args[1].data[0] >= '0' && args[1].data[0] <= '9'))) {
		/* salt is already bcrypt-base64 encoded */
		snprintf(setting, sizeof(setting), "$2b$%02d$%.22s", cost, args[1].data);
	} else {
		/* raw salt: bcrypt-base64 encode the first 16 bytes */
		char b64salt[25];
		const unsigned char *sb = (const unsigned char *)args[1].data;
		int slen = args[1].len > 16 ? 16 : args[1].len;
		int i, o = 0;
		static const char bc[] =
			"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		/* pad to 16 bytes */
		unsigned char sbuf[16];
		memset(sbuf, 0, 16);
		memcpy(sbuf, sb, slen);
		for (i = 0; i < 16; i += 3) {
			unsigned int v = (sbuf[i] << 16) |
			                 (sbuf[i+1] << 8) | sbuf[i+2];
			b64salt[o++] = bc[(v >> 18) & 0x3f];
			b64salt[o++] = bc[(v >> 12) & 0x3f];
			b64salt[o++] = bc[(v >> 6) & 0x3f];
			b64salt[o++] = bc[v & 0x3f];
		}
		/* bcrypt uses exactly 22 chars of base64 for 16 bytes */
		b64salt[22] = '\0';
		snprintf(setting, sizeof(setting), "$2b$%02d$%s", cost, b64salt);
	}

	/* null-terminate password for crypt_rn */
	pass_z = hx_arena_alloc(arena, args[0].len + 1);
	memcpy(pass_z, args[0].data, args[0].len);
	pass_z[args[0].len] = '\0';

	if (!crypt_rn(pass_z, setting, output, sizeof(output))) {
		/* bcrypt failed — return empty */
		result->data = hx_arena_alloc(arena, 1);
		result->data[0] = '\0';
		result->len = 0;
		return;
	}

	/*
	 * output now looks like "$2b$CC$<22-char salt><31-char hash>" (60 chars).
	 * The 31-char hash starts at output + 7 + 22 = output + 29.
	 */
	{
		char *hash_b64 = output + 7 + 22;
		int hlen = (int)strlen(hash_b64);

		if (role == ROLE_MCF) {
			int olen = (int)strlen(output);
			result->data = hx_arena_alloc(arena, olen + 1);
			memcpy(result->data, output, olen + 1);
			result->len = olen;
		} else if (role == ROLE_B64) {
			/* The bcrypt-base64 hash portion (canonical bcrypt hash field).
			 * Note: this is bcrypt-alphabet, NOT RFC 4648.  Documented as
			 * "the hash portion of the MCF" in the spec. */
			result->data = hx_arena_alloc(arena, hlen + 1);
			memcpy(result->data, hash_b64, hlen + 1);
			result->len = hlen;
		} else {
			/* ROLE_BIN or ROLE_HEX — decode the 31-char hash to raw bytes */
			unsigned char raw[24];
			int raw_len = 0;
			if (bcrypt_b64_decode(hash_b64, hlen, raw, &raw_len) != 0
			    || raw_len <= 0) {
				/* decode failed — return empty */
				result->data = hx_arena_alloc(arena, 1);
				result->data[0] = '\0';
				result->len = 0;
				return;
			}
			/* raw_len is 23 for a 31-char input (bcrypt's bug-compatible
			 * encoding only round-trips 23 bytes). */
			if (role == ROLE_BIN) {
				result->data = hx_arena_alloc(arena, raw_len);
				memcpy(result->data, raw, raw_len);
				result->len = raw_len;
			} else {
				/* ROLE_HEX */
				result->data = hx_arena_alloc(arena, raw_len * 2 + 1);
				to_hex(raw, raw_len, result->data);
				result->len = raw_len * 2;
			}
		}
	}
}

/*
 * scrypt(pass, salt, N, r, p, dklen)
 *
 * N:     CPU/memory cost (power of 2), default 16384
 * r:     block size, default 8
 * p:     parallelism, default 1
 * dklen: derived key length, default 32
 */
static void fn_scrypt(hx_func_entry *self, hx_val *args, int nargs,
                      hx_val *result, hx_arena *arena, uint8_t role)
{
	uint64_t N = 16384;
	uint32_t r = 8, p = 1;
	int dklen = 32;
	unsigned char *dk;
	(void)self;

	if (nargs >= 3) N = (uint64_t)val_to_int(&args[2]);
	if (nargs >= 4) r = (uint32_t)val_to_int(&args[3]);
	if (nargs >= 5) p = (uint32_t)val_to_int(&args[4]);
	if (nargs >= 6) dklen = val_to_int(&args[5]);
	if (dklen < 1) dklen = 1;
	if (dklen > 1024) dklen = 1024;

	dk = (unsigned char *)hx_arena_alloc(arena, dklen);

	if (crypto_scrypt((const uint8_t *)args[0].data, args[0].len,
	                   (const uint8_t *)args[1].data, args[1].len,
	                   N, r, p, dk, dklen) != 0) {
		memset(dk, 0, dklen);
	}

	emit_digest(dk, dklen, result, arena, role);
}

/*
 * argon2id(pass, salt, time_cost, memory_cost_kb, parallelism, dklen)
 * argon2i(pass, salt, time_cost, memory_cost_kb, parallelism, dklen)
 * argon2d(pass, salt, time_cost, memory_cost_kb, parallelism, dklen)
 *
 * time_cost:      iterations, default 3
 * memory_cost_kb: memory in KB, default 65536 (64 MB)
 * parallelism:    threads, default 4
 * dklen:          output length, default 32
 */
static void fn_argon2_generic(hx_func_entry *self, hx_val *args, int nargs,
                               hx_val *result, hx_arena *arena, uint8_t role,
                               argon2_type a2type)
{
	int t_cost = 3, m_cost = 65536, parallelism = 4, dklen = 32;
	unsigned char *dk;
	argon2_context ctx;
	(void)self;

	if (nargs >= 3) t_cost      = val_to_int(&args[2]);
	if (nargs >= 4) m_cost      = val_to_int(&args[3]);
	if (nargs >= 5) parallelism = val_to_int(&args[4]);
	if (nargs >= 6) dklen       = val_to_int(&args[5]);
	if (t_cost < 1) t_cost = 1;
	if (m_cost < 8) m_cost = 8;
	if (parallelism < 1) parallelism = 1;
	if (dklen < 1) dklen = 1;
	if (dklen > 1024) dklen = 1024;

	dk = (unsigned char *)hx_arena_alloc(arena, dklen);

	memset(&ctx, 0, sizeof(ctx));
	ctx.out      = dk;
	ctx.outlen   = dklen;
	ctx.pwd      = (uint8_t *)args[0].data;
	ctx.pwdlen   = args[0].len;
	ctx.salt     = (uint8_t *)args[1].data;
	ctx.saltlen  = args[1].len;
	ctx.t_cost   = t_cost;
	ctx.m_cost   = m_cost;
	ctx.lanes    = parallelism;
	ctx.threads  = 1;   /* single-threaded in hx */
	ctx.version  = ARGON2_VERSION_13;

	if (argon2_ctx(&ctx, a2type) != ARGON2_OK)
		memset(dk, 0, dklen);

	emit_digest(dk, dklen, result, arena, role);
}

static void fn_argon2id(hx_func_entry *self, hx_val *args, int nargs,
                        hx_val *result, hx_arena *arena, uint8_t role)
{ fn_argon2_generic(self, args, nargs, result, arena, role, Argon2_id); }

static void fn_argon2i(hx_func_entry *self, hx_val *args, int nargs,
                       hx_val *result, hx_arena *arena, uint8_t role)
{ fn_argon2_generic(self, args, nargs, result, arena, role, Argon2_i); }

static void fn_argon2d(hx_func_entry *self, hx_val *args, int nargs,
                       hx_val *result, hx_arena *arena, uint8_t role)
{ fn_argon2_generic(self, args, nargs, result, arena, role, Argon2_d); }

/*
 * yescrypt-base64 inverse-decode.  Alphabet:
 *   ./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
 *
 * Bit order is little-endian within each 24-bit group: 3 input bytes
 * are stuffed as byte[0] | (byte[1]<<8) | (byte[2]<<16), then 4 chars
 * are emitted low-6 first.  This matches yescrypt's `encode64()` in
 * yescrypt-common.c.
 *
 * Returns 0 on success, -1 on bad character.  *dstlen is set to the
 * number of bytes decoded (no trailing zero padding).
 */
static int yescrypt_b64_decode(const char *src, int srclen,
                               unsigned char *dst, int dstcap,
                               int *dstlen)
{
	static signed char d[256];
	static int d_init = 0;
	int i, j;
	int outpos = 0;

	if (!d_init) {
		static const char alpha[] =
			"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
		memset(d, -1, sizeof(d));
		for (j = 0; j < 64; j++) d[(unsigned char)alpha[j]] = j;
		d_init = 1;
	}

	for (i = 0; i < srclen; ) {
		uint32_t value = 0;
		int bits = 0;
		while (bits < 24 && i < srclen) {
			int v = d[(unsigned char)src[i++]];
			if (v < 0) return -1;
			value |= ((uint32_t)v) << bits;
			bits += 6;
		}
		/* emit floor(bits/8) bytes, little-endian */
		while (bits >= 8 && outpos < dstcap) {
			dst[outpos++] = (unsigned char)(value & 0xff);
			value >>= 8;
			bits -= 8;
		}
	}
	*dstlen = outpos;
	return 0;
}

/*
 * yescrypt(pass, salt)
 *
 * Uses yescrypt's crypt-style interface.
 * The salt argument should be a complete yescrypt setting string
 * (e.g., "$y$j9T$salt$").
 *
 * Output roles (per spec hx.1 §2.4 rev 1.5):
 *   ROLE_DEFAULT == ROLE_MCF — full $y$<flags>$<salt>$<hash> string
 *   ROLE_BIN — raw KDF bytes (decoded from the hash portion of the MCF)
 *   ROLE_HEX — lowercase hex of the raw KDF bytes
 *   ROLE_B64 — RFC 4648 base64 of the raw KDF bytes (NOT the embedded
 *              yescrypt-base64 hash portion — per user direction)
 */
static __thread yescrypt_local_t *hx_yescrypt_local;

static void fn_yescrypt(hx_func_entry *self, hx_val *args, int nargs,
                        hx_val *result, hx_arena *arena, uint8_t role)
{
	uint8_t result_buf[256];
	uint8_t *yresult;
	char *setting;
	(void)self; (void)nargs;

	if (role == ROLE_DEFAULT) role = ROLE_MCF;

	if (!hx_yescrypt_local) {
		hx_yescrypt_local = calloc(1, sizeof(yescrypt_local_t));
		yescrypt_init_local(hx_yescrypt_local);
	}

	/* null-terminate salt/setting for yescrypt */
	setting = hx_arena_alloc(arena, args[1].len + 1);
	memcpy(setting, args[1].data, args[1].len);
	setting[args[1].len] = '\0';

	yresult = yescrypt_r(NULL, hx_yescrypt_local,
	                     (const uint8_t *)args[0].data, args[0].len,
	                     (const uint8_t *)setting, NULL,
	                     result_buf, sizeof(result_buf));

	if (!yresult) {
		result->data = hx_arena_alloc(arena, 1);
		result->data[0] = '\0';
		result->len = 0;
		return;
	}

	if (role == ROLE_MCF) {
		/* full $y$... string verbatim */
		int rlen = (int)strlen((char *)yresult);
		result->data = hx_arena_alloc(arena, rlen + 1);
		memcpy(result->data, yresult, rlen + 1);
		result->len = rlen;
		return;
	}

	/*
	 * For BIN/HEX/B64: extract the hash portion (the substring after
	 * the final '$') and decode it from yescrypt-base64 to raw bytes.
	 */
	{
		char *yend = (char *)yresult + strlen((char *)yresult);
		char *hash_start = strrchr((char *)yresult, '$');
		unsigned char raw[64];
		int raw_len = 0;

		if (!hash_start || hash_start + 1 >= yend) {
			result->data = hx_arena_alloc(arena, 1);
			result->data[0] = '\0';
			result->len = 0;
			return;
		}
		hash_start++;  /* step past the '$' */

		if (yescrypt_b64_decode(hash_start, (int)(yend - hash_start),
		                        raw, sizeof(raw), &raw_len) != 0
		    || raw_len <= 0) {
			result->data = hx_arena_alloc(arena, 1);
			result->data[0] = '\0';
			result->len = 0;
			return;
		}

		emit_digest(raw, raw_len, result, arena, role);
	}
}

/* ================================================================
 * Crypt-family functions (md5crypt, apr1, sha256crypt, sha512crypt,
 * descrypt, phpass).  These produce MCF output by default and
 * support _bin/_hex/_b64 for the raw hash portion.
 *
 * Implemented directly using OpenSSL rather than hashpipe's WS-based
 * compute functions, so they work in both standalone and linked modes.
 * ================================================================ */

/* ---- itoa64 alphabet for md5crypt/sha*crypt ---- */
static const char itoa64_md5[] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void crypt_to64(char *s, unsigned int v, int n)
{
	while (--n >= 0) {
		*s++ = itoa64_md5[v & 0x3f];
		v >>= 6;
	}
}

/* ---- md5crypt / apr1 ---- */

static void do_hx_md5crypt(const char *pass, int passlen,
	const char *salt, int saltlen,
	const char *magic, int magiclen,
	char *result)
{
	MD5_CTX ctx, ctx1;
	unsigned char digest[16];
	int i;
	char *p;

	/* alt = MD5(pass + salt + pass) */
	MD5_Init(&ctx1);
	MD5_Update(&ctx1, pass, passlen);
	MD5_Update(&ctx1, salt, saltlen);
	MD5_Update(&ctx1, pass, passlen);
	MD5_Final(digest, &ctx1);

	/* ctx = MD5(pass + magic + salt + alt_bytes + bit_pattern) */
	MD5_Init(&ctx);
	MD5_Update(&ctx, pass, passlen);
	MD5_Update(&ctx, magic, magiclen);
	MD5_Update(&ctx, salt, saltlen);

	for (i = passlen; i > 0; i -= 16)
		MD5_Update(&ctx, digest, (i > 16) ? 16 : i);

	for (i = passlen; i > 0; i >>= 1) {
		if (i & 1)
			MD5_Update(&ctx, "", 1);
		else
			MD5_Update(&ctx, pass, 1);
	}
	MD5_Final(digest, &ctx);

	/* 1000 iterations */
	for (i = 0; i < 1000; i++) {
		MD5_Init(&ctx);
		if (i & 1) MD5_Update(&ctx, pass, passlen);
		else MD5_Update(&ctx, digest, 16);
		if (i % 3) MD5_Update(&ctx, salt, saltlen);
		if (i % 7) MD5_Update(&ctx, pass, passlen);
		if (i & 1) MD5_Update(&ctx, digest, 16);
		else MD5_Update(&ctx, pass, passlen);
		MD5_Final(digest, &ctx);
	}

	/* Build MCF output */
	p = result;
	memcpy(p, magic, magiclen); p += magiclen;
	memcpy(p, salt, saltlen); p += saltlen;
	*p++ = '$';

	crypt_to64(p, (digest[ 0]<<16) | (digest[ 6]<<8) | digest[12], 4); p += 4;
	crypt_to64(p, (digest[ 1]<<16) | (digest[ 7]<<8) | digest[13], 4); p += 4;
	crypt_to64(p, (digest[ 2]<<16) | (digest[ 8]<<8) | digest[14], 4); p += 4;
	crypt_to64(p, (digest[ 3]<<16) | (digest[ 9]<<8) | digest[15], 4); p += 4;
	crypt_to64(p, (digest[ 4]<<16) | (digest[10]<<8) | digest[ 5], 4); p += 4;
	crypt_to64(p,                     digest[11]                  , 2); p += 2;
	*p = '\0';
}

static void fn_md5crypt(hx_func_entry *self, hx_val *args, int nargs,
	hx_val *result, hx_arena *arena, uint8_t role)
{
	char output[128];
	char *salt_z;
	int saltlen;
	(void)self; (void)nargs;

	if (role == ROLE_DEFAULT) role = ROLE_MCF;

	/* salt */
	saltlen = args[1].len;
	if (saltlen > 8) saltlen = 8;
	salt_z = hx_arena_alloc(arena, saltlen + 1);
	memcpy(salt_z, args[1].data, saltlen);
	salt_z[saltlen] = '\0';

	do_hx_md5crypt(args[0].data, args[0].len, salt_z, saltlen,
		"$1$", 3, output);

	if (role == ROLE_MCF) {
		int olen = (int)strlen(output);
		result->data = hx_arena_alloc(arena, olen + 1);
		memcpy(result->data, output, olen + 1);
		result->len = olen;
	} else {
		/* Extract the 22-char hash after the last $ and decode */
		char *hash = strrchr(output, '$');
		unsigned char raw[16];
		if (hash) hash++;
		else hash = output;
		/* md5crypt hash is 22 itoa64 chars encoding 16 bytes */
		/* For _hex/_b64/_bin, emit the raw 16-byte digest */
		/* Simpler: just re-derive and emit the digest directly */
		/* We already have the digest in the do_ function but it's local.
		 * For simplicity, emit the MCF hash portion as-is for _b64,
		 * and the raw digest for _bin/_hex by re-running. */
		/* Actually, let's just re-run and capture the digest */
		{
			MD5_CTX ctx, ctx1;
			unsigned char digest[16];
			int i;

			MD5_Init(&ctx1);
			MD5_Update(&ctx1, args[0].data, args[0].len);
			MD5_Update(&ctx1, salt_z, saltlen);
			MD5_Update(&ctx1, args[0].data, args[0].len);
			MD5_Final(digest, &ctx1);

			MD5_Init(&ctx);
			MD5_Update(&ctx, args[0].data, args[0].len);
			MD5_Update(&ctx, "$1$", 3);
			MD5_Update(&ctx, salt_z, saltlen);
			for (i = args[0].len; i > 0; i -= 16)
				MD5_Update(&ctx, digest, (i > 16) ? 16 : i);
			for (i = args[0].len; i > 0; i >>= 1) {
				if (i & 1) MD5_Update(&ctx, "", 1);
				else MD5_Update(&ctx, args[0].data, 1);
			}
			MD5_Final(digest, &ctx);

			for (i = 0; i < 1000; i++) {
				MD5_Init(&ctx);
				if (i & 1) MD5_Update(&ctx, args[0].data, args[0].len);
				else MD5_Update(&ctx, digest, 16);
				if (i % 3) MD5_Update(&ctx, salt_z, saltlen);
				if (i % 7) MD5_Update(&ctx, args[0].data, args[0].len);
				if (i & 1) MD5_Update(&ctx, digest, 16);
				else MD5_Update(&ctx, args[0].data, args[0].len);
				MD5_Final(digest, &ctx);
			}
			emit_digest(digest, 16, result, arena, role);
		}
	}
}

static void fn_apr1(hx_func_entry *self, hx_val *args, int nargs,
	hx_val *result, hx_arena *arena, uint8_t role)
{
	char output[128];
	char *salt_z;
	int saltlen;
	(void)self; (void)nargs;

	if (role == ROLE_DEFAULT) role = ROLE_MCF;

	saltlen = args[1].len;
	if (saltlen > 8) saltlen = 8;
	salt_z = hx_arena_alloc(arena, saltlen + 1);
	memcpy(salt_z, args[1].data, saltlen);
	salt_z[saltlen] = '\0';

	do_hx_md5crypt(args[0].data, args[0].len, salt_z, saltlen,
		"$apr1$", 6, output);

	if (role == ROLE_MCF) {
		int olen = (int)strlen(output);
		result->data = hx_arena_alloc(arena, olen + 1);
		memcpy(result->data, output, olen + 1);
		result->len = olen;
	} else {
		/* Same as md5crypt but with apr1 magic — raw digest is identical algo */
		MD5_CTX ctx, ctx1;
		unsigned char digest[16];
		int i;

		MD5_Init(&ctx1);
		MD5_Update(&ctx1, args[0].data, args[0].len);
		MD5_Update(&ctx1, salt_z, saltlen);
		MD5_Update(&ctx1, args[0].data, args[0].len);
		MD5_Final(digest, &ctx1);

		MD5_Init(&ctx);
		MD5_Update(&ctx, args[0].data, args[0].len);
		MD5_Update(&ctx, "$apr1$", 6);
		MD5_Update(&ctx, salt_z, saltlen);
		for (i = args[0].len; i > 0; i -= 16)
			MD5_Update(&ctx, digest, (i > 16) ? 16 : i);
		for (i = args[0].len; i > 0; i >>= 1) {
			if (i & 1) MD5_Update(&ctx, "", 1);
			else MD5_Update(&ctx, args[0].data, 1);
		}
		MD5_Final(digest, &ctx);

		for (i = 0; i < 1000; i++) {
			MD5_Init(&ctx);
			if (i & 1) MD5_Update(&ctx, args[0].data, args[0].len);
			else MD5_Update(&ctx, digest, 16);
			if (i % 3) MD5_Update(&ctx, salt_z, saltlen);
			if (i % 7) MD5_Update(&ctx, args[0].data, args[0].len);
			if (i & 1) MD5_Update(&ctx, digest, 16);
			else MD5_Update(&ctx, args[0].data, args[0].len);
			MD5_Final(digest, &ctx);
		}
		emit_digest(digest, 16, result, arena, role);
	}
}

/* ---- sha256crypt ($5$) ---- */

/* Drepper's SHA-256-crypt implemented directly with OpenSSL SHA256 */

static void fn_sha256crypt(hx_func_entry *self, hx_val *args, int nargs,
	hx_val *result, hx_arena *arena, uint8_t role)
{
	SHA256_CTX ctx, alt_ctx;
	unsigned char digest[32], alt_digest[32], temp[32];
	char *pass_z, *salt_z;
	int passlen, saltlen, rounds = 5000;
	int i;
	static const char b64t[] =
		"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	(void)self;

	if (role == ROLE_DEFAULT) role = ROLE_MCF;

	passlen = args[0].len;
	pass_z = args[0].data;

	saltlen = args[1].len;
	if (saltlen > 16) saltlen = 16;
	salt_z = hx_arena_alloc(arena, saltlen + 1);
	memcpy(salt_z, args[1].data, saltlen);
	salt_z[saltlen] = '\0';

	if (nargs >= 3) rounds = val_to_int(&args[2]);
	if (rounds < 1000) rounds = 1000;
	if (rounds > 999999999) rounds = 999999999;

	/* Step 1-3: alt_digest = SHA256(pass + salt + pass) */
	SHA256_Init(&alt_ctx);
	SHA256_Update(&alt_ctx, pass_z, passlen);
	SHA256_Update(&alt_ctx, salt_z, saltlen);
	SHA256_Update(&alt_ctx, pass_z, passlen);
	SHA256_Final(alt_digest, &alt_ctx);

	/* Step 4-8 */
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, pass_z, passlen);
	SHA256_Update(&ctx, salt_z, saltlen);
	for (i = passlen; i > 32; i -= 32)
		SHA256_Update(&ctx, alt_digest, 32);
	SHA256_Update(&ctx, alt_digest, i);

	for (i = passlen; i > 0; i >>= 1) {
		if (i & 1)
			SHA256_Update(&ctx, alt_digest, 32);
		else
			SHA256_Update(&ctx, pass_z, passlen);
	}
	SHA256_Final(digest, &ctx);

	/* P_bytes */
	SHA256_Init(&alt_ctx);
	for (i = 0; i < passlen; i++)
		SHA256_Update(&alt_ctx, pass_z, passlen);
	SHA256_Final(temp, &alt_ctx);

	{
		unsigned char *p_bytes = hx_arena_alloc(arena, passlen);
		for (i = 0; i + 32 <= passlen; i += 32)
			memcpy(p_bytes + i, temp, 32);
		if (i < passlen)
			memcpy(p_bytes + i, temp, passlen - i);

		/* S_bytes */
		SHA256_Init(&alt_ctx);
		for (i = 0; i < 16 + (unsigned char)digest[0]; i++)
			SHA256_Update(&alt_ctx, salt_z, saltlen);
		SHA256_Final(temp, &alt_ctx);

		unsigned char *s_bytes = hx_arena_alloc(arena, saltlen);
		for (i = 0; i + 32 <= saltlen; i += 32)
			memcpy(s_bytes + i, temp, 32);
		if (i < saltlen)
			memcpy(s_bytes + i, temp, saltlen - i);

		/* Rounds */
		for (i = 0; i < rounds; i++) {
			SHA256_Init(&ctx);
			if (i & 1) SHA256_Update(&ctx, p_bytes, passlen);
			else SHA256_Update(&ctx, digest, 32);
			if (i % 3) SHA256_Update(&ctx, s_bytes, saltlen);
			if (i % 7) SHA256_Update(&ctx, p_bytes, passlen);
			if (i & 1) SHA256_Update(&ctx, digest, 32);
			else SHA256_Update(&ctx, p_bytes, passlen);
			SHA256_Final(digest, &ctx);
		}
	}

	if (role != ROLE_MCF) {
		emit_digest(digest, 32, result, arena, role);
		return;
	}

	/* Build MCF */
	{
		char mcf[256], *p = mcf;
		if (rounds == 5000)
			p += snprintf(p, sizeof(mcf), "$5$%s$", salt_z);
		else
			p += snprintf(p, sizeof(mcf), "$5$rounds=%d$%s$", rounds, salt_z);

#define B64_FROM_24BIT(b2, b1, b0, n) \
	{ unsigned int w = ((unsigned)(b2) << 16) | ((unsigned)(b1) << 8) | (b0); \
	  int nn = (n); while (nn-- > 0) { *p++ = b64t[w & 0x3f]; w >>= 6; } }

		B64_FROM_24BIT(digest[ 0], digest[10], digest[20], 4);
		B64_FROM_24BIT(digest[21], digest[ 1], digest[11], 4);
		B64_FROM_24BIT(digest[12], digest[22], digest[ 2], 4);
		B64_FROM_24BIT(digest[ 3], digest[13], digest[23], 4);
		B64_FROM_24BIT(digest[24], digest[ 4], digest[14], 4);
		B64_FROM_24BIT(digest[15], digest[25], digest[ 5], 4);
		B64_FROM_24BIT(digest[ 6], digest[16], digest[26], 4);
		B64_FROM_24BIT(digest[27], digest[ 7], digest[17], 4);
		B64_FROM_24BIT(digest[18], digest[28], digest[ 8], 4);
		B64_FROM_24BIT(digest[ 9], digest[19], digest[29], 4);
		B64_FROM_24BIT(0,          digest[31], digest[30], 3);
#undef B64_FROM_24BIT
		*p = '\0';

		int mlen = (int)(p - mcf);
		result->data = hx_arena_alloc(arena, mlen + 1);
		memcpy(result->data, mcf, mlen + 1);
		result->len = mlen;
	}
}

/* ---- sha512crypt ($6$) ---- */

/* Drepper's SHA-512-crypt — implement directly using OpenSSL SHA512 */

static void fn_sha512crypt(hx_func_entry *self, hx_val *args, int nargs,
	hx_val *result, hx_arena *arena, uint8_t role)
{
	SHA512_CTX ctx, alt_ctx;
	unsigned char digest[64], alt_digest[64], temp[64];
	char *pass_z, *salt_z;
	int passlen, saltlen, rounds = 5000;
	int i;
	static const char b64t[] =
		"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	(void)self;

	if (role == ROLE_DEFAULT) role = ROLE_MCF;

	passlen = args[0].len;
	pass_z = args[0].data;

	saltlen = args[1].len;
	if (saltlen > 16) saltlen = 16;
	salt_z = hx_arena_alloc(arena, saltlen + 1);
	memcpy(salt_z, args[1].data, saltlen);
	salt_z[saltlen] = '\0';

	if (nargs >= 3) rounds = val_to_int(&args[2]);
	if (rounds < 1000) rounds = 1000;
	if (rounds > 999999999) rounds = 999999999;

	/* Step 1-3: alt_digest = SHA512(pass + salt + pass) */
	SHA512_Init(&alt_ctx);
	SHA512_Update(&alt_ctx, pass_z, passlen);
	SHA512_Update(&alt_ctx, salt_z, saltlen);
	SHA512_Update(&alt_ctx, pass_z, passlen);
	SHA512_Final(alt_digest, &alt_ctx);

	/* Step 4-8: digest = SHA512(pass + salt + alt_bytes + bit_pattern) */
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, pass_z, passlen);
	SHA512_Update(&ctx, salt_z, saltlen);
	for (i = passlen; i > 64; i -= 64)
		SHA512_Update(&ctx, alt_digest, 64);
	SHA512_Update(&ctx, alt_digest, i);

	for (i = passlen; i > 0; i >>= 1) {
		if (i & 1)
			SHA512_Update(&ctx, alt_digest, 64);
		else
			SHA512_Update(&ctx, pass_z, passlen);
	}
	SHA512_Final(digest, &ctx);

	/* Step 9-11: P_bytes = SHA512(pass repeated passlen times) */
	SHA512_Init(&alt_ctx);
	for (i = 0; i < passlen; i++)
		SHA512_Update(&alt_ctx, pass_z, passlen);
	SHA512_Final(temp, &alt_ctx);

	{
		unsigned char *p_bytes = hx_arena_alloc(arena, passlen);
		for (i = 0; i + 64 <= passlen; i += 64)
			memcpy(p_bytes + i, temp, 64);
		if (i < passlen)
			memcpy(p_bytes + i, temp, passlen - i);

		/* Step 12-14: S_bytes = SHA512(salt repeated 16+digest[0] times) */
		SHA512_Init(&alt_ctx);
		for (i = 0; i < 16 + (unsigned char)digest[0]; i++)
			SHA512_Update(&alt_ctx, salt_z, saltlen);
		SHA512_Final(temp, &alt_ctx);

		unsigned char *s_bytes = hx_arena_alloc(arena, saltlen);
		for (i = 0; i + 64 <= saltlen; i += 64)
			memcpy(s_bytes + i, temp, 64);
		if (i < saltlen)
			memcpy(s_bytes + i, temp, saltlen - i);

		/* Step 15-21: rounds iterations */
		for (i = 0; i < rounds; i++) {
			SHA512_Init(&ctx);
			if (i & 1) SHA512_Update(&ctx, p_bytes, passlen);
			else SHA512_Update(&ctx, digest, 64);
			if (i % 3) SHA512_Update(&ctx, s_bytes, saltlen);
			if (i % 7) SHA512_Update(&ctx, p_bytes, passlen);
			if (i & 1) SHA512_Update(&ctx, digest, 64);
			else SHA512_Update(&ctx, p_bytes, passlen);
			SHA512_Final(digest, &ctx);
		}
	}

	if (role != ROLE_MCF) {
		emit_digest(digest, 64, result, arena, role);
		return;
	}

	/* Build MCF: $6$[rounds=N$]salt$hash */
	{
		char mcf[256], *p = mcf;
		if (rounds == 5000)
			p += snprintf(p, sizeof(mcf), "$6$%s$", salt_z);
		else
			p += snprintf(p, sizeof(mcf), "$6$rounds=%d$%s$", rounds, salt_z);

		/* sha512crypt base64 encoding (permuted byte order) */
#define B64_FROM_24BIT(b2, b1, b0, n) \
	{ unsigned int w = ((unsigned)(b2) << 16) | ((unsigned)(b1) << 8) | (b0); \
	  int nn = (n); while (nn-- > 0) { *p++ = b64t[w & 0x3f]; w >>= 6; } }

		B64_FROM_24BIT(digest[ 0], digest[21], digest[42], 4);
		B64_FROM_24BIT(digest[22], digest[43], digest[ 1], 4);
		B64_FROM_24BIT(digest[44], digest[ 2], digest[23], 4);
		B64_FROM_24BIT(digest[ 3], digest[24], digest[45], 4);
		B64_FROM_24BIT(digest[25], digest[46], digest[ 4], 4);
		B64_FROM_24BIT(digest[47], digest[ 5], digest[26], 4);
		B64_FROM_24BIT(digest[ 6], digest[27], digest[48], 4);
		B64_FROM_24BIT(digest[28], digest[49], digest[ 7], 4);
		B64_FROM_24BIT(digest[50], digest[ 8], digest[29], 4);
		B64_FROM_24BIT(digest[ 9], digest[30], digest[51], 4);
		B64_FROM_24BIT(digest[31], digest[52], digest[10], 4);
		B64_FROM_24BIT(digest[53], digest[11], digest[32], 4);
		B64_FROM_24BIT(digest[12], digest[33], digest[54], 4);
		B64_FROM_24BIT(digest[34], digest[55], digest[13], 4);
		B64_FROM_24BIT(digest[56], digest[14], digest[35], 4);
		B64_FROM_24BIT(digest[15], digest[36], digest[57], 4);
		B64_FROM_24BIT(digest[37], digest[58], digest[16], 4);
		B64_FROM_24BIT(digest[59], digest[17], digest[38], 4);
		B64_FROM_24BIT(digest[18], digest[39], digest[60], 4);
		B64_FROM_24BIT(digest[40], digest[61], digest[19], 4);
		B64_FROM_24BIT(digest[62], digest[20], digest[41], 4);
		B64_FROM_24BIT(0,          0,          digest[63], 2);
#undef B64_FROM_24BIT
		*p = '\0';

		int mlen = (int)(p - mcf);
		result->data = hx_arena_alloc(arena, mlen + 1);
		memcpy(result->data, mcf, mlen + 1);
		result->len = mlen;
	}
}

/* ---- descrypt (traditional 13-char DES crypt) ---- */

struct des_info;  /* opaque, from crypt-des.c */
extern char *bsd_crypt_des(const char *key, const char *setting,
	char *output, struct des_info *di);

static void fn_descrypt(hx_func_entry *self, hx_val *args, int nargs,
	hx_val *result, hx_arena *arena, uint8_t role)
{
	char output[128], setting[3], *pass_z;
	char passbuf[9];
	struct des_info *di;
	char *res;
	(void)self; (void)nargs;

	if (role == ROLE_DEFAULT) role = ROLE_MCF;

	/* 2-char salt from first arg */
	setting[0] = (args[1].len > 0) ? args[1].data[0] : '.';
	setting[1] = (args[1].len > 1) ? args[1].data[1] : '.';
	setting[2] = '\0';

	/* DES crypt only uses first 8 bytes of password */
	memset(passbuf, 0, sizeof(passbuf));
	memcpy(passbuf, args[0].data,
		args[0].len > 8 ? 8 : args[0].len);

	di = calloc(1, 65536);  /* des_info is large */
	res = bsd_crypt_des(passbuf, setting, output, di);
	free(di);

	if (!res) {
		result->data = hx_arena_alloc(arena, 1);
		result->data[0] = '\0';
		result->len = 0;
		return;
	}

	if (role == ROLE_MCF) {
		int rlen = (int)strlen(res);
		result->data = hx_arena_alloc(arena, rlen + 1);
		memcpy(result->data, res, rlen + 1);
		result->len = rlen;
	} else {
		/* Hash portion is chars 2..12 (11 chars encoding 8 bytes) */
		char *hash = res + 2;
		int hlen = (int)strlen(hash);
		if (role == ROLE_B64) {
			result->data = hx_arena_alloc(arena, hlen + 1);
			memcpy(result->data, hash, hlen + 1);
			result->len = hlen;
		} else {
			result->data = hx_arena_alloc(arena, hlen * 2 + 1);
			to_hex((unsigned char *)hash, hlen, result->data);
			result->len = hlen * 2;
		}
	}
}

/* ---- phpass ($H$ / $P$) ---- */

static void fn_phpass(hx_func_entry *self, hx_val *args, int nargs,
	hx_val *result, hx_arena *arena, uint8_t role)
{
	MD5_CTX ctx;
	unsigned char digest[16];
	char *salt_z, *pass_z;
	int saltlen, count, i;
	int log2_count = 11;  /* default: 2^11 = 2048 iterations */
	static const char itoa64_php[] =
		"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	(void)self;

	if (role == ROLE_DEFAULT) role = ROLE_MCF;

	if (nargs >= 3) log2_count = val_to_int(&args[2]);
	if (log2_count < 7) log2_count = 7;
	if (log2_count > 30) log2_count = 30;
	count = 1 << log2_count;

	saltlen = args[1].len;
	if (saltlen > 8) saltlen = 8;
	salt_z = hx_arena_alloc(arena, saltlen + 1);
	memcpy(salt_z, args[1].data, saltlen);
	salt_z[saltlen] = '\0';

	pass_z = args[0].data;

	/* Initial: MD5(salt + password) */
	MD5_Init(&ctx);
	MD5_Update(&ctx, salt_z, saltlen);
	MD5_Update(&ctx, pass_z, args[0].len);
	MD5_Final(digest, &ctx);

	/* Iterate: MD5(digest + password) */
	for (i = 0; i < count; i++) {
		MD5_Init(&ctx);
		MD5_Update(&ctx, digest, 16);
		MD5_Update(&ctx, pass_z, args[0].len);
		MD5_Final(digest, &ctx);
	}

	if (role == ROLE_MCF) {
		char mcf[64], *p;
		/* $H$<log2char><8-char salt><22-char hash> */
		p = mcf;
		*p++ = '$'; *p++ = 'H'; *p++ = '$';
		*p++ = itoa64_php[log2_count];
		memcpy(p, salt_z, saltlen); p += saltlen;
		/* Encode 16 bytes as 22 phpass-base64 chars */
		for (i = 0; i < 16; i += 3) {
			unsigned int v = digest[i];
			*p++ = itoa64_php[v & 0x3f];
			v |= (i + 1 < 16) ? ((unsigned)digest[i+1] << 8) : 0;
			*p++ = itoa64_php[(v >> 6) & 0x3f];
			if (i + 1 >= 16) break;
			v |= (i + 2 < 16) ? ((unsigned)digest[i+2] << 16) : 0;
			*p++ = itoa64_php[(v >> 12) & 0x3f];
			if (i + 2 >= 16) break;
			*p++ = itoa64_php[(v >> 18) & 0x3f];
		}
		*p = '\0';
		result->data = hx_arena_alloc(arena, (int)(p - mcf) + 1);
		memcpy(result->data, mcf, (int)(p - mcf) + 1);
		result->len = (int)(p - mcf);
	} else {
		emit_digest(digest, 16, result, arena, role);
	}
}

/* ---- pomelo(pass, salt, t_cost, m_cost) ----
 * mdxfind doesn't link pomelo_hash; hashpipe-only.  See v1.527 KDF
 * gating note at the top of this file. */
#ifndef HX_STANDALONE

extern int pomelo_hash(void *out, size_t outlen, const void *in, size_t inlen,
	const void *salt, size_t saltlen,
	unsigned int t_cost, unsigned int m_cost);

static void fn_pomelo(hx_func_entry *self, hx_val *args, int nargs,
	hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char digest[32];
	int t_cost = 2, m_cost = 3;
	(void)self;

	if (role == ROLE_DEFAULT) role = ROLE_HEX;

	if (nargs >= 3) t_cost = val_to_int(&args[2]);
	if (nargs >= 4) m_cost = val_to_int(&args[3]);

	if (pomelo_hash(digest, 32, args[0].data, args[0].len,
	    args[1].data, args[1].len, t_cost, m_cost) != 0) {
		result->data = hx_arena_alloc(arena, 1);
		result->data[0] = '\0';
		result->len = 0;
		return;
	}

	emit_digest(digest, 32, result, arena, role);
}

/* ---- rc4_hmac_md5(pass, data) — Kerberos etype 23 core ----
 * Computes the RC4-HMAC-MD5 key derivation used in Kerberos etype 23:
 *   NTLM = MD4(UTF16LE(pass))
 *   K1 = HMAC-MD5(NTLM, usage_type_le32)
 *   K3 = HMAC-MD5(K1, checksum_from_data)
 *   plaintext = RC4(K3, encrypted_portion)
 * This is an opaque primitive for the KRB5PA23/KRB5TGS23 types.
 * In hx, returns the NTLM hash (the password-derived key); the
 * full protocol exchange (RC4 encrypt/decrypt) is verification-only.
 * For hx purposes, rc4_hmac_md5(pass) = HMAC-MD5(MD4(UTF16LE(pass)), 0x01000000)
 */
static void fn_rc4_hmac_md5(hx_func_entry *self, hx_val *args, int nargs,
	hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char u16[2048], ntlm[16], k1[16];
	unsigned int hmac_len = 16;
	unsigned char usage[4] = {1, 0, 0, 0};
	int i, passlen = args[0].len;
	(void)self; (void)nargs;

	if (role == ROLE_DEFAULT) role = ROLE_HEX;

	/* UTF16LE encode the password (blind zero-extension) */
	if (passlen > 1024) passlen = 1024;
	for (i = 0; i < passlen; i++) {
		u16[i*2] = (unsigned char)args[0].data[i];
		u16[i*2+1] = 0;
	}

	/* NTLM = MD4(UTF16LE(pass)) */
	{ MD4_CTX ctx;
	  MD4_Init(&ctx);
	  MD4_Update(&ctx, u16, passlen * 2);
	  MD4_Final(ntlm, &ctx);
	}

	/* K1 = HMAC-MD5(NTLM, usage=1) */
	HMAC(EVP_md5(), ntlm, 16, usage, 4, k1, &hmac_len);

	emit_digest(k1, 16, result, arena, role);
}

/* ---- aes_cts_hmac_sha1(pass, salt, etype) — Kerberos etype 17/18 core ----
 * Kerberos string-to-key for AES128-CTS-HMAC-SHA1-96 (etype 17) and
 * AES256-CTS-HMAC-SHA1-96 (etype 18):
 *   key = PBKDF2-SHA1(pass, salt, 4096, keylen)
 *   where keylen = 16 (etype 17) or 32 (etype 18)
 *   then DK(key, usage) via AES-CBC (omitted here — just the base key)
 */
static void fn_aes128_cts_hmac_sha1(hx_func_entry *self, hx_val *args, int nargs,
	hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char dk[16];
	(void)self; (void)nargs;

	if (role == ROLE_DEFAULT) role = ROLE_HEX;

	PKCS5_PBKDF2_HMAC_SHA1(args[0].data, args[0].len,
		(unsigned char *)args[1].data, args[1].len,
		4096, 16, dk);

	emit_digest(dk, 16, result, arena, role);
}

static void fn_aes256_cts_hmac_sha1(hx_func_entry *self, hx_val *args, int nargs,
	hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char dk[32];
	(void)self; (void)nargs;

	if (role == ROLE_DEFAULT) role = ROLE_HEX;

	PKCS5_PBKDF2_HMAC_SHA1(args[0].data, args[0].len,
		(unsigned char *)args[1].data, args[1].len,
		4096, 32, dk);

	emit_digest(dk, 32, result, arena, role);
}

/* ---- sm3crypt ($sm3$) — Drepper-pattern crypt with SM3 (32-byte digest) ---- */

typedef struct { uint32_t h[8]; uint8_t buf[64]; uint64_t total; } hp_sm3_ctx;
extern void hp_sm3_init(hp_sm3_ctx *ctx);
extern void hp_sm3_update(hp_sm3_ctx *ctx, const uint8_t *data, size_t len);
extern void hp_sm3_final(hp_sm3_ctx *ctx, uint8_t *out);

static void fn_sm3crypt(hx_func_entry *self, hx_val *args, int nargs,
	hx_val *result, hx_arena *arena, uint8_t role)
{
	hp_sm3_ctx ctx, alt_ctx;
	unsigned char digest[32], alt_digest[32], temp[32];
	char *pass_z, *salt_z;
	int passlen, saltlen, rounds = 5000;
	int i;
	static const char b64t[] =
		"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	(void)self;

	if (role == ROLE_DEFAULT) role = ROLE_MCF;

	passlen = args[0].len;
	pass_z = args[0].data;
	saltlen = args[1].len;
	if (saltlen > 16) saltlen = 16;
	salt_z = hx_arena_alloc(arena, saltlen + 1);
	memcpy(salt_z, args[1].data, saltlen);
	salt_z[saltlen] = '\0';
	if (nargs >= 3) rounds = val_to_int(&args[2]);
	if (rounds < 1000) rounds = 1000;
	if (rounds > 999999999) rounds = 999999999;

	/* Drepper algorithm (same structure as sha256crypt, SM3 = 32 bytes) */
	hp_sm3_init(&alt_ctx);
	hp_sm3_update(&alt_ctx, (uint8_t *)pass_z, passlen);
	hp_sm3_update(&alt_ctx, (uint8_t *)salt_z, saltlen);
	hp_sm3_update(&alt_ctx, (uint8_t *)pass_z, passlen);
	hp_sm3_final(&alt_ctx, alt_digest);

	hp_sm3_init(&ctx);
	hp_sm3_update(&ctx, (uint8_t *)pass_z, passlen);
	hp_sm3_update(&ctx, (uint8_t *)salt_z, saltlen);
	for (i = passlen; i > 32; i -= 32)
		hp_sm3_update(&ctx, alt_digest, 32);
	hp_sm3_update(&ctx, alt_digest, i);
	for (i = passlen; i > 0; i >>= 1) {
		if (i & 1) hp_sm3_update(&ctx, alt_digest, 32);
		else hp_sm3_update(&ctx, (uint8_t *)pass_z, passlen);
	}
	hp_sm3_final(&ctx, digest);

	/* P_bytes */
	hp_sm3_init(&alt_ctx);
	for (i = 0; i < passlen; i++)
		hp_sm3_update(&alt_ctx, (uint8_t *)pass_z, passlen);
	hp_sm3_final(&alt_ctx, temp);
	{
		unsigned char *p_bytes = hx_arena_alloc(arena, passlen);
		for (i = 0; i + 32 <= passlen; i += 32) memcpy(p_bytes + i, temp, 32);
		if (i < passlen) memcpy(p_bytes + i, temp, passlen - i);

		/* S_bytes */
		hp_sm3_init(&alt_ctx);
		for (i = 0; i < 16 + (unsigned char)digest[0]; i++)
			hp_sm3_update(&alt_ctx, (uint8_t *)salt_z, saltlen);
		hp_sm3_final(&alt_ctx, temp);
		unsigned char *s_bytes = hx_arena_alloc(arena, saltlen);
		for (i = 0; i + 32 <= saltlen; i += 32) memcpy(s_bytes + i, temp, 32);
		if (i < saltlen) memcpy(s_bytes + i, temp, saltlen - i);

		for (i = 0; i < rounds; i++) {
			hp_sm3_init(&ctx);
			if (i & 1) hp_sm3_update(&ctx, p_bytes, passlen);
			else hp_sm3_update(&ctx, digest, 32);
			if (i % 3) hp_sm3_update(&ctx, s_bytes, saltlen);
			if (i % 7) hp_sm3_update(&ctx, p_bytes, passlen);
			if (i & 1) hp_sm3_update(&ctx, digest, 32);
			else hp_sm3_update(&ctx, p_bytes, passlen);
			hp_sm3_final(&ctx, digest);
		}
	}

	if (role != ROLE_MCF) {
		emit_digest(digest, 32, result, arena, role);
		return;
	}
	/* MCF: $sm3$[rounds=N$]salt$hash — same base64 permutation as sha256crypt */
	{
		char mcf[256], *p = mcf;
		if (rounds == 5000)
			p += snprintf(p, sizeof(mcf), "$sm3$%s$", salt_z);
		else
			p += snprintf(p, sizeof(mcf), "$sm3$rounds=%d$%s$", rounds, salt_z);
#define B64_FROM_24BIT(b2, b1, b0, n) \
	{ unsigned int w = ((unsigned)(b2) << 16) | ((unsigned)(b1) << 8) | (b0); \
	  int nn = (n); while (nn-- > 0) { *p++ = b64t[w & 0x3f]; w >>= 6; } }
		B64_FROM_24BIT(digest[ 0], digest[10], digest[20], 4);
		B64_FROM_24BIT(digest[21], digest[ 1], digest[11], 4);
		B64_FROM_24BIT(digest[12], digest[22], digest[ 2], 4);
		B64_FROM_24BIT(digest[ 3], digest[13], digest[23], 4);
		B64_FROM_24BIT(digest[24], digest[ 4], digest[14], 4);
		B64_FROM_24BIT(digest[15], digest[25], digest[ 5], 4);
		B64_FROM_24BIT(digest[ 6], digest[16], digest[26], 4);
		B64_FROM_24BIT(digest[27], digest[ 7], digest[17], 4);
		B64_FROM_24BIT(digest[18], digest[28], digest[ 8], 4);
		B64_FROM_24BIT(digest[ 9], digest[19], digest[29], 4);
		B64_FROM_24BIT(0,          digest[31], digest[30], 3);
#undef B64_FROM_24BIT
		*p = '\0';
		int mlen = (int)(p - mcf);
		result->data = hx_arena_alloc(arena, mlen + 1);
		memcpy(result->data, mcf, mlen + 1);
		result->len = mlen;
	}
}

/* ---- gost12_512crypt ($gost12512hash$) — Drepper-pattern with Streebog-512 ---- */

/* Streebog-512 from gosthash/gost2012.a */
typedef struct streebog_ctx streebog_ctx;
extern void streebog_init(streebog_ctx *ctx, int hashlen);
extern void streebog_update(streebog_ctx *ctx, const unsigned char *data, size_t len);
extern void streebog_final(unsigned char *out, streebog_ctx *ctx);

/* streebog_final outputs bytes in reversed order vs GOST standard;
 * this wrapper reverses to canonical byte order */
static void streebog_final_rev(unsigned char *out, streebog_ctx *ctx)
{
	unsigned char tmp[64];
	int i;
	streebog_final(tmp, ctx);
	for (i = 0; i < 64; i++) out[i] = tmp[63 - i];
}

static void fn_gost12_512crypt(hx_func_entry *self, hx_val *args, int nargs,
	hx_val *result, hx_arena *arena, uint8_t role)
{
	/* Streebog context is large — allocate from arena */
	streebog_ctx *ctx = (streebog_ctx *)hx_arena_alloc(arena, 512);
	streebog_ctx *alt_ctx = (streebog_ctx *)hx_arena_alloc(arena, 512);
	unsigned char digest[64], alt_digest[64], temp[64];
	char *pass_z, *salt_z;
	int passlen, saltlen, rounds = 5000;
	int i;
	static const char b64t[] =
		"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	(void)self;

	if (role == ROLE_DEFAULT) role = ROLE_MCF;

	passlen = args[0].len;
	pass_z = args[0].data;
	saltlen = args[1].len;
	if (saltlen > 16) saltlen = 16;
	salt_z = hx_arena_alloc(arena, saltlen + 1);
	memcpy(salt_z, args[1].data, saltlen);
	salt_z[saltlen] = '\0';
	if (nargs >= 3) rounds = val_to_int(&args[2]);
	if (rounds < 1000) rounds = 1000;
	if (rounds > 999999999) rounds = 999999999;

	/* Drepper algorithm with Streebog-512 (64-byte digest) */
	streebog_init(alt_ctx, 64);
	streebog_update(alt_ctx, (unsigned char *)pass_z, passlen);
	streebog_update(alt_ctx, (unsigned char *)salt_z, saltlen);
	streebog_update(alt_ctx, (unsigned char *)pass_z, passlen);
	streebog_final_rev(alt_digest, alt_ctx);

	streebog_init(ctx, 64);
	streebog_update(ctx, (unsigned char *)pass_z, passlen);
	streebog_update(ctx, (unsigned char *)salt_z, saltlen);
	for (i = passlen; i > 64; i -= 64)
		streebog_update(ctx, alt_digest, 64);
	streebog_update(ctx, alt_digest, i);
	for (i = passlen; i > 0; i >>= 1) {
		if (i & 1) streebog_update(ctx, alt_digest, 64);
		else streebog_update(ctx, (unsigned char *)pass_z, passlen);
	}
	streebog_final_rev(digest, ctx);

	/* P_bytes */
	streebog_init(alt_ctx, 64);
	for (i = 0; i < passlen; i++)
		streebog_update(alt_ctx, (unsigned char *)pass_z, passlen);
	streebog_final_rev(temp, alt_ctx);
	{
		unsigned char *p_bytes = hx_arena_alloc(arena, passlen);
		for (i = 0; i + 64 <= passlen; i += 64) memcpy(p_bytes + i, temp, 64);
		if (i < passlen) memcpy(p_bytes + i, temp, passlen - i);

		/* S_bytes */
		streebog_init(alt_ctx, 64);
		for (i = 0; i < 16 + (unsigned char)digest[0]; i++)
			streebog_update(alt_ctx, (unsigned char *)salt_z, saltlen);
		streebog_final_rev(temp, alt_ctx);
		unsigned char *s_bytes = hx_arena_alloc(arena, saltlen);
		for (i = 0; i + 64 <= saltlen; i += 64) memcpy(s_bytes + i, temp, 64);
		if (i < saltlen) memcpy(s_bytes + i, temp, saltlen - i);

		for (i = 0; i < rounds; i++) {
			streebog_init(ctx, 64);
			if (i & 1) streebog_update(ctx, p_bytes, passlen);
			else streebog_update(ctx, digest, 64);
			if (i % 3) streebog_update(ctx, s_bytes, saltlen);
			if (i % 7) streebog_update(ctx, p_bytes, passlen);
			if (i & 1) streebog_update(ctx, digest, 64);
			else streebog_update(ctx, p_bytes, passlen);
			streebog_final_rev(digest, ctx);
		}
	}

	if (role != ROLE_MCF) {
		emit_digest(digest, 64, result, arena, role);
		return;
	}
	/* MCF: $gost12512hash$[rounds=N$]salt$hash — sha512crypt permutation */
	{
		char mcf[512], *p = mcf;
		if (rounds == 5000)
			p += snprintf(p, sizeof(mcf), "$gost12512hash$%s$", salt_z);
		else
			p += snprintf(p, sizeof(mcf), "$gost12512hash$rounds=%d$%s$", rounds, salt_z);
#define B64_FROM_24BIT(b2, b1, b0, n) \
	{ unsigned int w = ((unsigned)(b2) << 16) | ((unsigned)(b1) << 8) | (b0); \
	  int nn = (n); while (nn-- > 0) { *p++ = b64t[w & 0x3f]; w >>= 6; } }
		B64_FROM_24BIT(digest[ 0], digest[21], digest[42], 4);
		B64_FROM_24BIT(digest[22], digest[43], digest[ 1], 4);
		B64_FROM_24BIT(digest[44], digest[ 2], digest[23], 4);
		B64_FROM_24BIT(digest[ 3], digest[24], digest[45], 4);
		B64_FROM_24BIT(digest[25], digest[46], digest[ 4], 4);
		B64_FROM_24BIT(digest[47], digest[ 5], digest[26], 4);
		B64_FROM_24BIT(digest[ 6], digest[27], digest[48], 4);
		B64_FROM_24BIT(digest[28], digest[49], digest[ 7], 4);
		B64_FROM_24BIT(digest[50], digest[ 8], digest[29], 4);
		B64_FROM_24BIT(digest[ 9], digest[30], digest[51], 4);
		B64_FROM_24BIT(digest[31], digest[52], digest[10], 4);
		B64_FROM_24BIT(digest[53], digest[11], digest[32], 4);
		B64_FROM_24BIT(digest[12], digest[33], digest[54], 4);
		B64_FROM_24BIT(digest[34], digest[55], digest[13], 4);
		B64_FROM_24BIT(digest[56], digest[14], digest[35], 4);
		B64_FROM_24BIT(digest[15], digest[36], digest[57], 4);
		B64_FROM_24BIT(digest[37], digest[58], digest[16], 4);
		B64_FROM_24BIT(digest[59], digest[17], digest[38], 4);
		B64_FROM_24BIT(digest[18], digest[39], digest[60], 4);
		B64_FROM_24BIT(digest[40], digest[61], digest[19], 4);
		B64_FROM_24BIT(digest[62], digest[20], digest[41], 4);
		B64_FROM_24BIT(0,          0,          digest[63], 2);
#undef B64_FROM_24BIT
		*p = '\0';
		int mlen = (int)(p - mcf);
		result->data = hx_arena_alloc(arena, mlen + 1);
		memcpy(result->data, mcf, mlen + 1);
		result->len = mlen;
	}
}

#endif /* !HX_STANDALONE — close fn_pomelo..fn_gost12_512crypt block */

#endif /* !HX_STANDALONE || HX_HAS_KDF */

/* ================================================================
 * siphash(pass, key) — SipHash-2-4 with 16-byte key
 * murmur3(pass, seed) — MurmurHash3_x86_32
 * pbkdf1_sha1(pass, salt, iter, dklen) — PBKDF1 with SHA-1
 * These work in both standalone and linked modes.
 * ================================================================ */

/* ---- SipHash-2-4 ---- */

static uint64_t hx_siphash24(const unsigned char *in, int inlen,
	const unsigned char *key)
{
	uint64_t v0 = 0x736f6d6570736575ULL;
	uint64_t v1 = 0x646f72616e646f6dULL;
	uint64_t v2 = 0x6c7967656e657261ULL;
	uint64_t v3 = 0x7465646279746573ULL;
	uint64_t k0, k1, m;
	int i, blocks;

	memcpy(&k0, key, 8);
	memcpy(&k1, key + 8, 8);
	v3 ^= k1; v2 ^= k0; v1 ^= k1; v0 ^= k0;

	blocks = inlen / 8;
	for (i = 0; i < blocks; i++) {
		memcpy(&m, in + i * 8, 8);
		v3 ^= m;
#define SIPROUND \
		v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; \
		v0 = (v0 << 32) | (v0 >> 32); \
		v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2; \
		v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0; \
		v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; \
		v2 = (v2 << 32) | (v2 >> 32);
		SIPROUND; SIPROUND;
		v0 ^= m;
	}

	m = ((uint64_t)inlen) << 56;
	switch (inlen & 7) {
		case 7: m |= (uint64_t)in[blocks*8+6] << 48; /* fall through */
		case 6: m |= (uint64_t)in[blocks*8+5] << 40; /* fall through */
		case 5: m |= (uint64_t)in[blocks*8+4] << 32; /* fall through */
		case 4: m |= (uint64_t)in[blocks*8+3] << 24; /* fall through */
		case 3: m |= (uint64_t)in[blocks*8+2] << 16; /* fall through */
		case 2: m |= (uint64_t)in[blocks*8+1] << 8;  /* fall through */
		case 1: m |= (uint64_t)in[blocks*8+0];
	}
	v3 ^= m;
	SIPROUND; SIPROUND;
	v0 ^= m;

	v2 ^= 0xff;
	SIPROUND; SIPROUND; SIPROUND; SIPROUND;
#undef SIPROUND
	return v0 ^ v1 ^ v2 ^ v3;
}

static void fn_siphash(hx_func_entry *self, hx_val *args, int nargs,
	hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char key[16];
	uint64_t hash;
	unsigned char raw[8];
	(void)self; (void)nargs;

	if (role == ROLE_DEFAULT) role = ROLE_HEX;

	/* Key is arg[1], padded/truncated to 16 bytes */
	memset(key, 0, 16);
	if (args[1].len >= 16) memcpy(key, args[1].data, 16);
	else memcpy(key, args[1].data, args[1].len);

	hash = hx_siphash24((unsigned char *)args[0].data, args[0].len, key);
	memcpy(raw, &hash, 8);

	emit_digest(raw, 8, result, arena, role);
}

/* ---- MurmurHash3_x86_32 ---- */

static void fn_murmur3(hx_func_entry *self, hx_val *args, int nargs,
	hx_val *result, hx_arena *arena, uint8_t role)
{
	const unsigned char *data = (unsigned char *)args[0].data;
	int len = args[0].len;
	uint32_t seed = 0;
	const uint32_t c1 = 0xcc9e2d51, c2 = 0x1b873593;
	uint32_t h1;
	int nblocks, i;
	unsigned char raw[4];
	(void)self;

	if (role == ROLE_DEFAULT) role = ROLE_HEX;

	if (nargs >= 2) seed = (uint32_t)val_to_int(&args[1]);
	h1 = seed;
	nblocks = len / 4;

	for (i = 0; i < nblocks; i++) {
		uint32_t k1;
		memcpy(&k1, data + i * 4, 4);
		k1 *= c1; k1 = (k1 << 15) | (k1 >> 17); k1 *= c2;
		h1 ^= k1; h1 = (h1 << 13) | (h1 >> 19); h1 = h1 * 5 + 0xe6546b64;
	}
	{ const uint8_t *tail = data + nblocks * 4;
	  uint32_t k1 = 0;
	  switch (len & 3) {
		case 3: k1 ^= (uint32_t)tail[2] << 16; /* fall through */
		case 2: k1 ^= (uint32_t)tail[1] << 8;  /* fall through */
		case 1: k1 ^= tail[0];
		        k1 *= c1; k1 = (k1 << 15) | (k1 >> 17); k1 *= c2;
		        h1 ^= k1;
	  }
	}
	h1 ^= (uint32_t)len;
	h1 ^= h1 >> 16; h1 *= 0x85ebca6b;
	h1 ^= h1 >> 13; h1 *= 0xc2b2ae35;
	h1 ^= h1 >> 16;

	/* Big-endian output (matches hashpipe convention) */
	raw[0] = (h1 >> 24) & 0xff; raw[1] = (h1 >> 16) & 0xff;
	raw[2] = (h1 >> 8) & 0xff;  raw[3] = h1 & 0xff;

	emit_digest(raw, 4, result, arena, role);
}

/* ---- PBKDF1-SHA1 ---- */

static void fn_pbkdf1_sha1(hx_func_entry *self, hx_val *args, int nargs,
	hx_val *result, hx_arena *arena, uint8_t role)
{
	SHA_CTX ctx;
	unsigned char digest[20];
	int iter = 1000, dklen = 20, i;
	(void)self;

	if (role == ROLE_DEFAULT) role = ROLE_HEX;

	if (nargs >= 3) iter = val_to_int(&args[2]);
	if (nargs >= 4) dklen = val_to_int(&args[3]);
	if (iter < 1) iter = 1;
	if (dklen < 1) dklen = 1;
	if (dklen > 20) dklen = 20;  /* PBKDF1 limited to hash output size */

	/* Step 1: SHA1(pass + salt) */
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, args[0].data, args[0].len);
	SHA1_Update(&ctx, args[1].data, args[1].len);
	SHA1_Final(digest, &ctx);

	/* Steps 2..iter: SHA1(digest) */
	for (i = 1; i < iter; i++) {
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, digest, 20);
		SHA1_Final(digest, &ctx);
	}

	emit_digest(digest, dklen, result, arena, role);
}

/* ---- argon2 (alias for argon2id) ---- */

#if !defined(HX_STANDALONE) || defined(HX_HAS_KDF)
static void fn_argon2(hx_func_entry *self, hx_val *args, int nargs,
	hx_val *result, hx_arena *arena, uint8_t role)
{
	/* Dispatch to argon2id as the default variant */
	extern void fn_argon2id(hx_func_entry *, hx_val *, int,
		hx_val *, hx_arena *, uint8_t);
	fn_argon2id(self, args, nargs, result, arena, role);
}
#endif

/* ================================================================
 * Output function
 * ================================================================ */

/*
 * emit(x) — write value to stdout with a newline.
 * Returns the value unchanged (passthrough).
 * When a program contains emit() calls, the automatic
 * final-value output is suppressed.
 *
 * emit(x, label, ...) — hx-functions.md 19.3: the labels, then the value,
 * separated by tabs, one line.  Each field is written as is when it is
 * non-empty, every byte is 0x20-0x7e and it does not begin "$HEX[";
 * otherwise as $HEX[lowercase hex] -- mdxfind's convention (fmt_saltfield),
 * so a tab or newline in a value never breaks the line.  An empty field is
 * written empty, as mdxfind writes an empty plaintext.  The compiler allows
 * only string literals and loop variables as labels.
 *
 * Under hx_vm.capture (mdxfind and hashpipe user types) nothing is written:
 * the value is collected, labels ignored, in the text the one-argument form
 * prints (hx_vm.h).
 */
static int emit_printable(const unsigned char *d, int n)
{
	int i;
	for (i = 0; i < n; i++)
		if (d[i] < 0x20 || d[i] > 0x7e) return 0;
	return 1;
}

static void emit_field(const hx_val *v)
{
	const unsigned char *d = (const unsigned char *)v->data;
	int i, n = v->data ? v->len : 0;
	if (emit_printable(d, n) && !(n >= 5 && memcmp(d, "$HEX[", 5) == 0)) {
		fwrite(d, 1, n, stdout);
		return;
	}
	fputs("$HEX[", stdout);
	for (i = 0; i < n; i++) printf("%02x", d[i]);
	putchar(']');
}

static void fn_emit(hx_func_entry *self, hx_val *args, int nargs,
                    hx_val *result, hx_arena *arena, uint8_t role)
{
	(void)self; (void)role;

	if (arena->emits) {
		hx_emits *e = arena->emits;
		hx_val t = args[0];
		if (!t.data) t.len = 0;
		if (t.len > 0 &&
		    !emit_printable((const unsigned char *)t.data, t.len)) {
			char *hex = hx_arena_alloc(arena, t.len * 2 + 1);
			to_hex((unsigned char *)t.data, t.len, hex);
			t.data = hex;
			t.len *= 2;
		}
		if (e->n == e->cap) {
			int cap = e->cap ? e->cap * 2 : 16;
			hx_val *nv = realloc(e->v, cap * sizeof *nv);
			if (!nv) {
				fprintf(stderr, "hx: %s:%d: emit(): out of memory\n",
				        __FILE__, __LINE__);
				exit(1);
			}
			e->v = nv;
			e->cap = cap;
		}
		e->v[e->n++] = t;
		*result = args[0];
		return;
	}

	if (nargs > 1) {
		int i;
		/* an empty label writes nothing, not even its tab: emit(x, "") is
		 * the value alone, with the $HEX[] rule of the labelled form */
		for (i = 1; i < nargs; i++) {
			if (!args[i].data || args[i].len == 0) continue;
			emit_field(&args[i]);
			putchar('\t');
		}
		emit_field(&args[0]);
		putchar('\n');
		*result = args[0];
		return;
	}

	if (args[0].data && args[0].len > 0) {
		/*
		 * Auto-detect binary data: if any byte is not
		 * printable ASCII (0x20-0x7e), hex-encode the output.
		 * This handles the case where emit() receives the
		 * output of a _bin function.
		 */
		int i, is_binary = 0;
		for (i = 0; i < args[0].len; i++) {
			unsigned char c = (unsigned char)args[0].data[i];
			if (c < 0x20 || c > 0x7e) { is_binary = 1; break; }
		}
		if (is_binary) {
			char *hex = hx_arena_alloc(arena, args[0].len * 2 + 1);
			to_hex((unsigned char *)args[0].data,
			       args[0].len, hex);
			fwrite(hex, 1, args[0].len * 2, stdout);
		} else {
			fwrite(args[0].data, 1, args[0].len, stdout);
		}
	}
	putchar('\n');
	*result = args[0];
}

/* ================================================================
 * String transform functions (always available)
 * ================================================================ */




static void fn_cut(hx_func_entry *self, hx_val *args, int nargs,
                   hx_val *result, hx_arena *arena, uint8_t role)
{
	int inlen = args[0].len;
	int start = 0, len;
	(void)self; (void)role;

	if (nargs >= 2) start = val_to_int(&args[1]);
	if (start < 0) { start = inlen + start; if (start < 0) start = 0; }
	if (start > inlen) start = inlen;
	if (nargs >= 3) { len = val_to_int(&args[2]); if (len < 0) len = 0; }
	else len = inlen - start;
	if (start + len > inlen) len = inlen - start;

	result->data = hx_arena_alloc(arena, len + 1);
	memcpy(result->data, args[0].data + start, len);
	result->data[len] = '\0';
	result->len = len;
}

/*
 * pad(x, length) — null-pad x to exactly length bytes.
 * If x is shorter, the result is x followed by zero bytes.
 * If x is longer, the result is truncated to length.
 * Used for fixed-width fields (e.g., RADMIN2 pads to 100 bytes).
 */
static void fn_pad(hx_func_entry *self, hx_val *args, int nargs,
                   hx_val *result, hx_arena *arena, uint8_t role)
{
	int padlen;
	(void)self; (void)nargs; (void)role;

	padlen = val_to_int(&args[1]);
	if (padlen < 0) padlen = 0;
	if (padlen > 65536) padlen = 65536;

	result->data = hx_arena_alloc(arena, padlen + 1);
	if (args[0].len >= padlen) {
		memcpy(result->data, args[0].data, padlen);
	} else {
		memcpy(result->data, args[0].data, args[0].len);
		memset(result->data + args[0].len, 0, padlen - args[0].len);
	}
	result->data[padlen] = '\0';
	result->len = padlen;
}

static void fn_trunc(hx_func_entry *self, hx_val *args, int nargs,
                     hx_val *result, hx_arena *arena, uint8_t role)
{
	hx_val cut_args[3];
	(void)nargs;
	cut_args[0] = args[0];
	cut_args[1].is_int = 1; cut_args[1].ival = 0;
	cut_args[2] = args[1];
	fn_cut(self, cut_args, 3, result, arena, role);
}


/* ---- bswap32(x) — reverse byte order within each 4-byte group ---- */

static void fn_bswap32(hx_func_entry *self, hx_val *args, int nargs,
                       hx_val *result, hx_arena *arena, uint8_t role)
{
	int i, len;
	unsigned char *out;
	const unsigned char *in;
	(void)self; (void)nargs; (void)role;

	len = args[0].len;
	out = (unsigned char *)hx_arena_alloc(arena, len + 1);
	in = (const unsigned char *)args[0].data;

	/* Swap bytes within each 4-byte group */
	for (i = 0; i + 3 < len; i += 4) {
		out[i]     = in[i + 3];
		out[i + 1] = in[i + 2];
		out[i + 2] = in[i + 1];
		out[i + 3] = in[i];
	}
	/* Copy any trailing bytes that don't fill a full group */
	for (; i < len; i++)
		out[i] = in[i];
	out[len] = '\0';
	result->data = (char *)out;
	result->len = len;
}

/* ---- cap (capitalize) ---- */

/*
 * cap(x)     — capitalize the first lowercase letter [a-z] in x
 * cap(x, N)  — capitalize the character at position N (0-based)
 *
 * Only affects ASCII lowercase letters (a-z → A-Z).
 * Returns a copy; the original is not modified.
 */
/*
 * rotate(x, N) — rotate a string by N positions.
 * Positive N rotates right: last N chars move to front.
 * Negative N rotates left: first |N| chars move to end.
 * rotate("abcdef", 2) → "efabcd"
 * rotate("abcdef", -2) → "cdefab"
 */
static void fn_rotate(hx_func_entry *self, hx_val *args, int nargs,
                      hx_val *result, hx_arena *arena, uint8_t role)
{
	int len, n, split;
	(void)self; (void)nargs; (void)role;

	len = args[0].len;
	if (len == 0) { *result = args[0]; return; }

	n = val_to_int(&args[1]);
	/* normalize: positive = rotate right */
	n = n % len;
	if (n < 0) n += len;

	/* split point: for right rotation by n, split at len-n */
	split = len - n;

	result->data = hx_arena_alloc(arena, len + 1);
	memcpy(result->data, args[0].data + split, n);
	memcpy(result->data + n, args[0].data, split);
	result->data[len] = '\0';
	result->len = len;
}

static void fn_cap(hx_func_entry *self, hx_val *args, int nargs,
                   hx_val *result, hx_arena *arena, uint8_t role)
{
	int i, len, pos;
	(void)self; (void)role;

	len = args[0].len;
	result->data = hx_arena_alloc(arena, len + 1);
	memcpy(result->data, args[0].data, len);
	result->data[len] = '\0';
	result->len = len;

	if (nargs >= 2) {
		/* positional: capitalize at position N */
		pos = val_to_int(&args[1]);
		if (pos < 0) pos = len + pos;
		if (pos >= 0 && pos < len) {
			unsigned char c = (unsigned char)result->data[pos];
			if (c >= 'a' && c <= 'z')
				result->data[pos] = c - 32;
		}
	} else {
		/* default: first lowercase letter */
		for (i = 0; i < len; i++) {
			unsigned char c = (unsigned char)result->data[i];
			if (c >= 'a' && c <= 'z') {
				result->data[i] = c - 32;
				break;
			}
		}
	}
}



/* ---- frombase64 (base64 decode, RFC 4648) ---- */

/*
 * The "lenient" base64 decoder: frombase64() and convert(x, "base64", "raw",
 * "lenient") are both this function, so they cannot drift apart.  It never
 * gives null.  In groups of up to four characters a b c d, from the start:
 *   - the loop runs while at least two characters remain; a single final
 *     character is ignored;
 *   - a and b are always consumed; c is consumed unless it is '=' or the end,
 *     and so is d; a consumed character outside the alphabet reads as -1;
 *   - if a or b is outside the alphabet, decoding stops (bytes so far kept);
 *   - otherwise a<<2 | b>>4 is written; then, if c >= 0, (b&15)<<4 | c>>2;
 *     then, if d >= 0, (c&3)<<6 | d -- with c = -1 that is 0xC0 | d;
 *   - an '=' is never consumed, so the next group starts on it and stops.
 * Writes at most inlen bytes into out and returns the count.
 */
static int hx_frombase64_lenient(const unsigned char *in, int inlen, unsigned char *out)
{
	static const signed char d64[256] = {
		[0 ... 255] = -1,
		['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,
		['E'] = 4,  ['F'] = 5,  ['G'] = 6,  ['H'] = 7,
		['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11,
		['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15,
		['Q'] = 16, ['R'] = 17, ['S'] = 18, ['T'] = 19,
		['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
		['Y'] = 24, ['Z'] = 25,
		['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29,
		['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33,
		['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37,
		['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41,
		['q'] = 42, ['r'] = 43, ['s'] = 44, ['t'] = 45,
		['u'] = 46, ['v'] = 47, ['w'] = 48, ['x'] = 49,
		['y'] = 50, ['z'] = 51,
		['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55,
		['4'] = 56, ['5'] = 57, ['6'] = 58, ['7'] = 59,
		['8'] = 60, ['9'] = 61, ['+'] = 62, ['/'] = 63,
	};
	int i, o = 0;

	for (i = 0; i + 1 < inlen; ) {
		int a = d64[in[i++]];
		int b = (i < inlen) ? d64[in[i++]] : 0;
		int c = (i < inlen && in[i] != '=') ? d64[in[i++]] : -1;
		int d = (i < inlen && in[i] != '=') ? d64[in[i++]] : -1;
		if (a < 0 || b < 0) break;
		out[o++] = (a << 2) | (b >> 4);
		if (c >= 0) out[o++] = ((b & 0xf) << 4) | (c >> 2);
		if (d >= 0) out[o++] = ((c & 0x3) << 6) | d;
	}
	return o;
}


/* ---- fromhex (hex decode) ---- */

/*
 * The "lenient" hex decoder: fromhex() and convert(x, "hex", "raw",
 * "lenient") are both this function.  It never gives null: byte i is
 * nib(in[2i]) << 4 | nib(in[2i+1]), where nib is the value of 0-9, a-f, A-F
 * and 0 for any other byte, and a final odd character is ignored.  Writes
 * inlen / 2 bytes into out and returns that count.
 */
static int hx_fromhex_lenient(const unsigned char *in, int inlen, unsigned char *out)
{
	int outlen = inlen / 2, i;
	for (i = 0; i < outlen; i++) {
		int hi, lo;
		unsigned char c;
		c = in[i * 2];
		hi = (c >= '0' && c <= '9') ? c - '0' :
		     (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
		     (c >= 'A' && c <= 'F') ? c - 'A' + 10 : 0;
		c = in[i * 2 + 1];
		lo = (c >= '0' && c <= '9') ? c - '0' :
		     (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
		     (c >= 'A' && c <= 'F') ? c - 'A' + 10 : 0;
		out[i] = (hi << 4) | lo;
	}
	return outlen;
}


/* ---- basic math (return integers with string representation) ---- */

static void fn_math_result(hx_val *result, hx_arena *arena, int64_t val)
{
	char *buf = hx_arena_alloc(arena, 24);
	result->is_int = 1;
	result->ival   = val;
	result->len    = sprintf(buf, "%lld", (long long)val);
	result->data   = buf;
}

/*
 * wperm(x, w0, w1, w2, w3) — permute 4-byte words within a byte sequence.
 * The input is divided into 4-byte words (padded with zero if needed).
 * The arguments w0-w3 are indices (0-based) specifying the new order.
 *
 * Example: MD5 produces 16 bytes = 4 words [a,b,c,d].
 *   wperm(md5_bin(pass), 3, 2, 0, 1)  → words [d,c,a,b] = "dcab"
 *   wperm(md5_bin(pass), 1, 2, 0, 3)  → words [b,c,a,d] = "bcad"
 */
static void fn_wperm(hx_func_entry *self, hx_val *args, int nargs,
                     hx_val *result, hx_arena *arena, uint8_t role)
{
	const unsigned char *in = (const unsigned char *)args[0].data;
	int inlen = args[0].len;
	int nwords = (inlen + 3) / 4;
	int outlen = nwords * 4;
	char *out;
	int i;
	(void)self; (void)role;

	/* need at least the data + one index argument */
	if (nargs < 2) {
		*result = args[0];
		return;
	}

	out = hx_arena_alloc(arena, outlen + 1);
	memset(out, 0, outlen);

	/* apply permutation: for each output position, copy the word
	   from the index specified by the corresponding argument */
	for (i = 0; i < nargs - 1 && i < nwords; i++) {
		int src = val_to_int(&args[i + 1]);
		if (src >= 0 && src < nwords) {
			int soff = src * 4;
			int doff = i * 4;
			int j;
			for (j = 0; j < 4 && soff + j < inlen; j++)
				out[doff + j] = in[soff + j];
		}
	}
	/* copy remaining words unchanged if not enough arguments */
	for (; i < nwords; i++) {
		int off = i * 4;
		int j;
		for (j = 0; j < 4 && off + j < inlen; j++)
			out[off + j] = in[off + j];
	}
	out[outlen] = '\0';
	result->data = out;
	result->len  = outlen;
}

static void fn_add(hx_func_entry *self, hx_val *args, int nargs,
                   hx_val *result, hx_arena *arena, uint8_t role)
{
	(void)self; (void)nargs; (void)role;
	fn_math_result(result, arena, val_to_int(&args[0]) + val_to_int(&args[1]));
}

static void fn_sub(hx_func_entry *self, hx_val *args, int nargs,
                   hx_val *result, hx_arena *arena, uint8_t role)
{
	(void)self; (void)nargs; (void)role;
	fn_math_result(result, arena, val_to_int(&args[0]) - val_to_int(&args[1]));
}

static void fn_mul(hx_func_entry *self, hx_val *args, int nargs,
                   hx_val *result, hx_arena *arena, uint8_t role)
{
	(void)self; (void)nargs; (void)role;
	fn_math_result(result, arena, (int64_t)val_to_int(&args[0]) * val_to_int(&args[1]));
}

static void fn_mod(hx_func_entry *self, hx_val *args, int nargs,
                   hx_val *result, hx_arena *arena, uint8_t role)
{
	int b = val_to_int(&args[1]);
	(void)self; (void)nargs; (void)role;
	if (b == 0) { fn_math_result(result, arena, 0); return; }
	fn_math_result(result, arena, val_to_int(&args[0]) % b);
}


/* ---- des(key, plaintext) — single-DES ECB encrypt ----
 * key:       1..8 bytes (longer truncated, shorter zero-padded)
 * plaintext: 8 bytes (longer truncated, shorter zero-padded)
 * returns:   8 bytes; default rendering is 16-char lowercase hex
 */
static void fn_des(hx_func_entry *self, hx_val *args, int nargs,
                   hx_val *result, hx_arena *arena, uint8_t role)
{
	DES_cblock keyblk, ptblk, ctblk;
	DES_key_schedule ks;
	int klen = args[0].len, plen = args[1].len;
	(void)self; (void)nargs;

	memset(keyblk, 0, 8);
	memset(ptblk, 0, 8);
	memcpy(keyblk, args[0].data, klen < 8 ? klen : 8);
	memcpy(ptblk,  args[1].data, plen < 8 ? plen : 8);

	DES_set_key_unchecked(&keyblk, &ks);
	DES_ecb_encrypt(&ptblk, &ctblk, &ks, DES_ENCRYPT);

	emit_digest((unsigned char *)ctblk, 8, result, arena, role);
}

/* ---- des3(key, plaintext) — 3DES (EDE) ECB encrypt ----
 * key:       1..24 bytes — split into three 8-byte sub-keys k1|k2|k3
 *            (each sub-key zero-padded if the source segment is short)
 * plaintext: 8 bytes
 * returns:   8 bytes; default rendering is 16-char lowercase hex
 */
static void fn_des3(hx_func_entry *self, hx_val *args, int nargs,
                    hx_val *result, hx_arena *arena, uint8_t role)
{
	DES_cblock k1, k2, k3, ptblk, ctblk;
	DES_key_schedule ks1, ks2, ks3;
	int klen = args[0].len, plen = args[1].len;
	const char *kdata = args[0].data;
	(void)self; (void)nargs;

	memset(k1, 0, 8);
	memset(k2, 0, 8);
	memset(k3, 0, 8);
	memset(ptblk, 0, 8);

	if (klen >= 8)  memcpy(k1, kdata,    8);             else memcpy(k1, kdata, klen);
	if (klen > 8)  { if (klen >= 16) memcpy(k2, kdata+8,  8);  else memcpy(k2, kdata+8,  klen-8);  }
	if (klen > 16) { if (klen >= 24) memcpy(k3, kdata+16, 8);  else memcpy(k3, kdata+16, klen-16); }
	memcpy(ptblk, args[1].data, plen < 8 ? plen : 8);

	DES_set_key_unchecked(&k1, &ks1);
	DES_set_key_unchecked(&k2, &ks2);
	DES_set_key_unchecked(&k3, &ks3);
	DES_ecb3_encrypt(&ptblk, &ctblk, &ks1, &ks2, &ks3, DES_ENCRYPT);

	emit_digest((unsigned char *)ctblk, 8, result, arena, role);
}

/* ---- des_block(key7, plaintext) — DES with 7-byte key expansion ----
 * key7:      7 bytes — expanded to 8 bytes with DES parity bits
 *            (used by NTLMv1 challenge-response)
 * plaintext: 8 bytes
 * returns:   8 bytes; default rendering is 16-char lowercase hex
 */
static void hx_des7(const unsigned char *raw7, const unsigned char *ptblk,
                    unsigned char *out);

static void fn_des_block(hx_func_entry *self, hx_val *args, int nargs,
                         hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char raw7[7], ptblk[8], ct[8];
	int klen = args[0].len, plen = args[1].len;
	(void)self; (void)nargs;

	memset(raw7, 0, 7);
	memset(ptblk, 0, 8);
	memcpy(raw7,  args[0].data, klen < 7 ? klen : 7);
	memcpy(ptblk, args[1].data, plen < 8 ? plen : 8);
	hx_des7(raw7, ptblk, ct);
	emit_digest((unsigned char *)ct, 8, result, arena, role);
}

/* DES-encrypt one block under a 7-byte key expanded to 8 (the LM and NTLMv1
 * key schedule): des_block() and lm_cpNNN(). */
static void hx_des7(const unsigned char *raw7, const unsigned char *ptblk,
                    unsigned char *out)
{
	DES_cblock key, ct;
	DES_key_schedule ks;

	/* 7→8 byte DES key expansion with parity */
	key[0] = (raw7[0] >> 1);
	key[1] = ((raw7[0] & 0x01) << 6) | (raw7[1] >> 2);
	key[2] = ((raw7[1] & 0x03) << 5) | (raw7[2] >> 3);
	key[3] = ((raw7[2] & 0x07) << 4) | (raw7[3] >> 4);
	key[4] = ((raw7[3] & 0x0F) << 3) | (raw7[4] >> 5);
	key[5] = ((raw7[4] & 0x1F) << 2) | (raw7[5] >> 6);
	key[6] = ((raw7[5] & 0x3F) << 1) | (raw7[6] >> 7);
	key[7] = raw7[6] & 0x7F;
	{ int i; for (i = 0; i < 8; i++) key[i] = (key[i] << 1) & 0xfe; }

	DES_set_key_unchecked((const_DES_cblock *)&key, &ks);
	DES_ecb_encrypt((const_DES_cblock *)ptblk, &ct, &ks, DES_ENCRYPT);
	memcpy(out, ct, 8);
}

/* ---- juniper_encode (Juniper NetScreen / ScreenOS 30-char format) ----
 * Input:  16 raw bytes (typically an MD5 digest)
 * Output: 30-char ASCII string with 24 base64 data chars and 6 literal
 *         signature chars "nrcstn" interleaved at positions 0,6,12,17,23,29.
 * Bit layout: each 32-bit big-endian word splits into hi/lo 16-bit halves,
 *             each half encoded as 3 base64 chars at bit offsets {12,6,0}
 *             (groups of 4+6+6 = 16 bits).
 * Mirrors mdxfind.c:2140 (juniper_encode); keep in sync if that diverges.
 */
static void fn_juniper_encode(hx_func_entry *self, hx_val *args, int nargs,
                              hx_val *result, hx_arena *arena, uint8_t role)
{
	static const char b64alpha[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	static const char sig[] = "nrcstn";
	static const int  sigpos[] = {0, 6, 12, 17, 23, 29};
	unsigned char buf[16];
	char data[24];
	char *out;
	int copylen = args[0].len < 16 ? args[0].len : 16;
	int w, p, si = 0, di = 0;
	unsigned int hi, lo;
	(void)self; (void)nargs; (void)role;

	memset(buf, 0, 16);
	memcpy(buf, args[0].data, copylen);

	for (w = 0; w < 4; w++) {
		hi = (buf[w*4+0] << 8) | buf[w*4+1];
		lo = (buf[w*4+2] << 8) | buf[w*4+3];
		data[w*6+0] = b64alpha[(hi >> 12) & 0x3f];
		data[w*6+1] = b64alpha[(hi >>  6) & 0x3f];
		data[w*6+2] = b64alpha[(hi      ) & 0x3f];
		data[w*6+3] = b64alpha[(lo >> 12) & 0x3f];
		data[w*6+4] = b64alpha[(lo >>  6) & 0x3f];
		data[w*6+5] = b64alpha[(lo      ) & 0x3f];
	}

	out = hx_arena_alloc(arena, 31);
	for (p = 0; p < 30; p++) {
		if (si < 6 && p == sigpos[si])
			out[p] = sig[si++];
		else
			out[p] = data[di++];
	}
	out[30] = '\0';

	result->data = out;
	result->len  = 30;
}

/* ---- Lotus/Domino algorithm support ----
 * Mirrors mdxfind.c:
 *   - lotus_magic_table[256]   at 2213
 *   - lotus64[] alphabet       at 2311
 *   - lotus64_encode           at 2556
 *   - lotus_mix                at 2579
 *   - lotus_transform_password at 2591
 *   - domino5_transform        at 2603
 * Keep in sync with mdxfind if any of those diverge.
 */
static const unsigned char lotus_magic_table[256] = {
  0xbd,0x56,0xea,0xf2,0xa2,0xf1,0xac,0x2a,0xb0,0x93,0xd1,0x9c,0x1b,0x33,0xfd,0xd0,
  0x30,0x04,0xb6,0xdc,0x7d,0xdf,0x32,0x4b,0xf7,0xcb,0x45,0x9b,0x31,0xbb,0x21,0x5a,
  0x41,0x9f,0xe1,0xd9,0x4a,0x4d,0x9e,0xda,0xa0,0x68,0x2c,0xc3,0x27,0x5f,0x80,0x36,
  0x3e,0xee,0xfb,0x95,0x1a,0xfe,0xce,0xa8,0x34,0xa9,0x13,0xf0,0xa6,0x3f,0xd8,0x0c,
  0x78,0x24,0xaf,0x23,0x52,0xc1,0x67,0x17,0xf5,0x66,0x90,0xe7,0xe8,0x07,0xb8,0x60,
  0x48,0xe6,0x1e,0x53,0xf3,0x92,0xa4,0x72,0x8c,0x08,0x15,0x6e,0x86,0x00,0x84,0xfa,
  0xf4,0x7f,0x8a,0x42,0x19,0xf6,0xdb,0xcd,0x14,0x8d,0x50,0x12,0xba,0x3c,0x06,0x4e,
  0xec,0xb3,0x35,0x11,0xa1,0x88,0x8e,0x2b,0x94,0x99,0xb7,0x71,0x74,0xd3,0xe4,0xbf,
  0x3a,0xde,0x96,0x0e,0xbc,0x0a,0xed,0x77,0xfc,0x37,0x6b,0x03,0x79,0x89,0x62,0xc6,
  0xd7,0xc0,0xd2,0x7c,0x6a,0x8b,0x22,0xa3,0x5b,0x05,0x5d,0x02,0x75,0xd5,0x61,0xe3,
  0x18,0x8f,0x55,0x51,0xad,0x1f,0x0b,0x5e,0x85,0xe5,0xc2,0x57,0x63,0xca,0x3d,0x6c,
  0xb4,0xc5,0xcc,0x70,0xb2,0x91,0x59,0x0d,0x47,0x20,0xc8,0x4f,0x58,0xe0,0x01,0xe2,
  0x16,0x38,0xc4,0x6f,0x3b,0x0f,0x65,0x46,0xbe,0x7e,0x2d,0x7b,0x82,0xf9,0x40,0xb5,
  0x1d,0x73,0xf8,0xeb,0x26,0xc7,0x87,0x97,0x25,0x54,0xb1,0x28,0xaa,0x98,0x9d,0xa5,
  0x64,0x6d,0x7a,0xd4,0x10,0x81,0x44,0xef,0x49,0xd6,0xae,0x2e,0xdd,0x76,0x5c,0x2f,
  0xa7,0x1c,0xc9,0x09,0x69,0x9a,0x83,0xcf,0x29,0x39,0xb9,0xe9,0x4c,0xff,0x43,0xab
};

static const char lotus64_alpha[] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

static void hx_lotus_mix(unsigned char *state)
{
	int p = 0, i, k;
	for (i = 0; i < 18; i++) {
		for (k = 0; k < 48; k++) {
			p = (p + (48 - k)) & 0xff;
			p = state[k] ^ lotus_magic_table[p];
			state[k] = p;
		}
	}
}

static void hx_lotus_transform_password(const unsigned char *block,
                                        unsigned char *checksum)
{
	unsigned char t = checksum[15];
	int i;
	for (i = 0; i < 16; i++) {
		t = checksum[i] ^ lotus_magic_table[block[i] ^ t];
		checksum[i] = t;
	}
}

static void hx_domino5_transform(const unsigned char *input, int inlen,
                                 unsigned char *output)
{
	unsigned char state[48], padded[512], checksum[16];
	int padlen, nblocks, i, j;

	padlen = 16 - (inlen % 16);
	if (padlen == 0) padlen = 16;
	if (inlen + padlen > (int)sizeof(padded)) {
		memset(output, 0, 16);
		return;
	}
	memcpy(padded, input, inlen);
	memset(padded + inlen, padlen, padlen);
	nblocks = (inlen + padlen) / 16;

	memset(state, 0, 48);
	memset(checksum, 0, 16);

	for (i = 0; i < nblocks; i++) {
		unsigned char *block = padded + i * 16;
		for (j = 0; j < 16; j++) {
			state[16 + j] = block[j];
			state[32 + j] = block[j] ^ state[j];
		}
		hx_lotus_mix(state);
		hx_lotus_transform_password(block, checksum);
	}
	for (j = 0; j < 16; j++) {
		state[16 + j] = checksum[j];
		state[32 + j] = checksum[j] ^ state[j];
	}
	hx_lotus_mix(state);
	memcpy(output, state, 16);
}

static int hx_lotus64_encode(const unsigned char *in, int inlen, char *out)
{
	int i, j = 0;
	for (i = 0; i + 2 < inlen; i += 3) {
		out[j++] = lotus64_alpha[in[i] >> 2];
		out[j++] = lotus64_alpha[((in[i] & 3) << 4) | (in[i+1] >> 4)];
		out[j++] = lotus64_alpha[((in[i+1] & 0xf) << 2) | (in[i+2] >> 6)];
		out[j++] = lotus64_alpha[in[i+2] & 0x3f];
	}
	if (i < inlen) {
		out[j++] = lotus64_alpha[in[i] >> 2];
		if (i + 1 < inlen) {
			out[j++] = lotus64_alpha[((in[i] & 3) << 4) | (in[i+1] >> 4)];
			out[j++] = lotus64_alpha[(in[i+1] & 0xf) << 2];
		} else {
			out[j++] = lotus64_alpha[(in[i] & 3) << 4];
		}
	}
	out[j] = 0;
	return j;
}

/* ---- domino5(pass) — 16-byte Lotus/Domino 5 hash ---- */
static void fn_domino5(hx_func_entry *self, hx_val *args, int nargs,
                       hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char digest[16];
	(void)self; (void)nargs;

	if (args[0].len > 256) {
		memset(digest, 0, 16);
	} else {
		hx_domino5_transform((const unsigned char *)args[0].data,
		                     args[0].len, digest);
	}
	emit_digest(digest, 16, result, arena, role);
}

/* ---- lotus64_encode(bytes) — Lotus 0123...XYZabc...xyz+/ alphabet ----
 * Returns ASCII text (4 chars per 3 bytes; partial groups handled).
 */
static void fn_lotus64_encode(hx_func_entry *self, hx_val *args, int nargs,
                              hx_val *result, hx_arena *arena, uint8_t role)
{
	int outmax = ((args[0].len + 2) / 3) * 4 + 1;
	char *out;
	(void)self; (void)nargs; (void)role;

	out = hx_arena_alloc(arena, outmax);
	result->len  = hx_lotus64_encode((const unsigned char *)args[0].data,
	                                 args[0].len, out);
	result->data = out;
}

/* ---- domino6(pass, salt) — full Lotus/Domino 6 (G…) format ----
 * salt:  5 raw bytes (call as `domino6(pass, fromhex(salt))` if salt comes
 *        from mdxfind output as 10 hex chars).
 * Output: 22-char string "(G" + 19 lotus64 chars + ")".
 * Mirrors mdxfind.c:19754-19796.
 */
static void fn_domino6(hx_func_entry *self, hx_val *args, int nargs,
                       hx_val *result, hx_arena *arena, uint8_t role)
{
	static const char hexUC[] = "0123456789ABCDEF";
	unsigned char h1[16], buf[48], h2[16], raw[14];
	char *out;
	int x;
	(void)self; (void)nargs; (void)role;

	if (args[0].len > 256 || args[1].len < 5) {
		out = hx_arena_alloc(arena, 23);
		memcpy(out, "(G", 2);
		memset(out + 2, '0', 19);
		out[21] = ')';
		out[22] = '\0';
		result->data = out;
		result->len  = 22;
		return;
	}

	hx_domino5_transform((const unsigned char *)args[0].data,
	                     args[0].len, h1);

	memcpy(buf, args[1].data, 5);
	buf[5] = '(';
	for (x = 0; x < 14; x++) {
		buf[6 + x*2]     = hexUC[(h1[x] >> 4) & 0xf];
		buf[6 + x*2 + 1] = hexUC[ h1[x]       & 0xf];
	}
	hx_domino5_transform(buf, 34, h2);

	memcpy(raw, args[1].data, 5);
	memcpy(raw + 5, h2, 9);
	raw[3] += 4;                /* Lotus encoding quirk */

	out = hx_arena_alloc(arena, 23);
	out[0] = '(';
	out[1] = 'G';
	hx_lotus64_encode(raw, 14, out + 2);
	out[21] = ')';
	out[22] = '\0';
	result->data = out;
	result->len  = 22;
}

/* ---- a2e[]: ASCII → EBCDIC (CP037 / IBM-037 / EBCDIC-US) lookup ----
 * Mirrors mdxfind.c:2232 byte-for-byte; used by RACF, AS/400, and the
 * ebcdic() primitive.
 */
static const unsigned char hx_a2e[256] = {
  0x00,0x01,0x02,0x03,0x37,0x2d,0x2e,0x2f,0x16,0x05,0x25,0x0b,0x0c,0x0d,0x0e,0x0f,
  0x10,0x11,0x12,0x13,0x3c,0x3d,0x32,0x26,0x18,0x19,0x3f,0x27,0x1c,0x1d,0x1e,0x1f,
  0x40,0x5a,0x7f,0x7b,0x5b,0x6c,0x50,0x7d,0x4d,0x5d,0x5c,0x4e,0x6b,0x60,0x4b,0x61,
  0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0x7a,0x5e,0x4c,0x7e,0x6e,0x6f,
  0x7c,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,
  0xd7,0xd8,0xd9,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xad,0xe0,0xbd,0x5f,0x6d,
  0x79,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x91,0x92,0x93,0x94,0x95,0x96,
  0x97,0x98,0x99,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xc0,0x4f,0xd0,0xa1,0x07,
  0x20,0x21,0x22,0x23,0x24,0x15,0x06,0x17,0x28,0x29,0x2a,0x2b,0x2c,0x09,0x0a,0x1b,
  0x30,0x31,0x1a,0x33,0x34,0x35,0x36,0x08,0x38,0x39,0x3a,0x3b,0x04,0x14,0x3e,0xe1,
  0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x51,0x52,0x53,0x54,0x55,0x56,0x57,
  0x58,0x59,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x70,0x71,0x72,0x73,0x74,0x75,
  0x76,0x77,0x78,0x80,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,0x90,0x9a,0x9b,0x9c,0x9d,0x9e,
  0x9f,0xa0,0xaa,0xab,0xac,0x4a,0xae,0xaf,0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,
  0xb8,0xb9,0xba,0xbb,0xbc,0xa1,0xbe,0xbf,0xca,0xcb,0xcc,0xcd,0xce,0xcf,0xda,0xdb,
  0xdc,0xdd,0xde,0xdf,0xea,0xeb,0xec,0xed,0xee,0xef,0xfa,0xfb,0xfc,0xfd,0xfe,0xff
};

/* ---- a2e_pc[]: ASCII → EBCDIC-PC (CP1047 variant) ----
 * Mirrors mdxfind.c:2252; used by AS/400 DES password→key derivation.
 */
static const unsigned char hx_a2e_pc[256] = {
  0x2a,0xa8,0xae,0xad,0xc4,0xf1,0xf7,0xf4,0x86,0xa1,0xe0,0xbc,0xb3,0xb0,0xb6,0xb5,
  0x8a,0x89,0x8f,0x8c,0xd3,0xd0,0xce,0xe6,0x9b,0x98,0xd5,0xe5,0x92,0x91,0x97,0x94,
  0x2a,0x34,0x54,0x5d,0x1c,0x73,0x0b,0x51,0x31,0x10,0x13,0x37,0x7c,0x6b,0x3d,0x68,
  0x4a,0x49,0x4f,0x4c,0x43,0x40,0x46,0x45,0x5b,0x58,0x5e,0x16,0x32,0x57,0x76,0x75,
  0x52,0x29,0x2f,0x2c,0x23,0x20,0x26,0x25,0x3b,0x38,0x08,0x0e,0x0d,0x02,0x01,0x07,
  0x04,0x1a,0x19,0x6e,0x6d,0x62,0x61,0x67,0x64,0x7a,0x79,0x3e,0x6b,0x1f,0x15,0x70,
  0x58,0xa8,0xae,0xad,0xa2,0xa1,0xa7,0xa4,0xba,0xb9,0x89,0x8f,0x8c,0x83,0x80,0x86,
  0x85,0x9b,0x98,0xef,0xec,0xe3,0xe0,0xe6,0xe5,0xfb,0xf8,0x2a,0x7f,0x0b,0xe9,0xa4,
  0xea,0xe9,0xef,0xec,0xe3,0x80,0xa7,0x85,0xfb,0xf8,0xfe,0xfd,0xf2,0xb9,0xbf,0x9d,
  0xcb,0xc8,0x9e,0xcd,0xc2,0xc1,0xc7,0xba,0xda,0xd9,0xdf,0xdc,0xa2,0x83,0xd6,0x68,
  0x29,0x2f,0x2c,0x23,0x20,0x26,0x25,0x3b,0x38,0x08,0x0e,0x0d,0x02,0x01,0x07,0x04,
  0x1a,0x19,0x6e,0x6d,0x62,0x61,0x67,0x64,0x7a,0x79,0x4a,0x49,0x4f,0x4c,0x43,0x40,
  0x46,0x45,0x5b,0xab,0xbf,0xbc,0xb3,0xb0,0xb6,0xb5,0x8a,0x9e,0x9d,0x92,0x91,0x97,
  0x94,0xea,0xfe,0xfd,0xf2,0xf1,0xf7,0xf4,0xcb,0xc8,0xce,0xcd,0xc2,0xc1,0xc7,0xc4,
  0xda,0xd9,0xdf,0xdc,0xd3,0xd0,0xd6,0xd5,0x3e,0x3d,0x32,0x31,0x37,0x34,0x1f,0x1c,
  0x13,0x10,0x16,0x15,0x7f,0x7c,0x73,0x70,0x76,0x75,0x5e,0x5d,0x52,0x51,0x57,0x54
};

/* ---- SAP BCODE tables (mdxfind.c:2272 sapb_trans_tbl, 2291 bcodeArray) ---- */
static const unsigned char hx_sapb_trans_tbl[256] = {
    0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0x3f,0x40,0x41,0x50,0x43,0x44,0x45,0x4b,0x47,0x48,0x4d,0x4e,0x54,0x51,0x53,0x46,
    0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x56,0x55,0x5c,0x49,0x5d,0x4a,
    0x42,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x58,0x5b,0x59,0xff,0x52,
    0x4c,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x57,0x5e,0x5a,0x4f,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
    0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};
static const unsigned char hx_bcodeArray[48] = {
    0x14,0x77,0xf3,0xd4,0xbb,0x71,0x23,0xd0,0x03,0xff,0x47,0x93,0x55,0xaa,0x66,0x91,
    0xf2,0x88,0x6b,0x99,0xbf,0xcb,0x32,0x1a,0x19,0xd9,0xa7,0x82,0x22,0x49,0xa2,0x51,
    0xe2,0xb7,0x33,0x71,0x8b,0x9f,0x5d,0x01,0x44,0x70,0xae,0x11,0xef,0x28,0xf0,0x0d
};

/* ---- sap_bcode(pass, salt) — SAP BCODE 8-byte hash ----
 * Mirrors mdxfind.c:33128-33223 (the 8-byte path, pre-XOR-fold output).
 * For BCODE4 (e923), wrap the result as
 *   cut(upper(sap_bcode(pass, salt)), 0, 8) . "00000000"
 * since BCODE4 zero-fills the trailing 8 hex chars.
 */
static void fn_sap_bcode(hx_func_entry *self, hx_val *args, int nargs,
                         hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char tpass[8] = {0}, tsalt[12], digest[16], tbuf[64];
	unsigned char folded[8];
	int plen = args[0].len < 8 ? args[0].len : 8;
	int slen = args[1].len < 12 ? args[1].len : 12;
	int x, mlen;
	(void)self; (void)nargs;

	for (x = 0; x < 8; x++) {
		if (x < plen) {
			unsigned char c = (unsigned char)args[0].data[x];
			if (c >= 'a' && c <= 'z') c -= 32;
			tpass[x] = hx_sapb_trans_tbl[c];
		} else tpass[x] = 0;
	}
	for (x = 0; x < slen; x++) {
		unsigned char c = (unsigned char)args[1].data[x];
		if (c >= 'a' && c <= 'z') c -= 32;
		tsalt[x] = hx_sapb_trans_tbl[c];
	}

	{
		unsigned char buf[24];
		memcpy(buf, tpass, plen);
		memcpy(buf + plen, tsalt, slen);
		mlen = plen + slen;
		MD5(buf, mlen, digest);
	}

	{
		unsigned int sum20 = ((digest[0] >> 0) & 3)
		                   + ((digest[0] >> 2) & 3)
		                   + ((digest[1] >> 0) & 3)
		                   + ((digest[1] >> 2) & 3)
		                   + ((digest[2] >> 2) & 3);
		unsigned int i1 = 0, i2 = 0, i3 = 0;
		sum20 |= 0x20;
		memset(tbuf, 0, 64);
		while (i2 < sum20) {
			if (i1 < (unsigned int)plen) {
				if (digest[15 - i1] & 1) {
					tbuf[i2++] = hx_bcodeArray[48 - 1 - i1];
					if (i2 == sum20) break;
				}
				tbuf[i2++] = tpass[i1];
				if (i2 == sum20) break;
				i1++;
			}
			if (i3 < (unsigned int)slen) {
				tbuf[i2++] = tsalt[i3];
				if (i2 == sum20) break;
				i3++;
			}
			tbuf[i2] = hx_bcodeArray[i2 - i1 - i3];
			i2++;
			i2++;
		}
		MD5(tbuf, sum20, digest);
	}

	for (x = 0; x < 4; x++) {
		folded[x]     = digest[x]     ^ digest[x + 8];
		folded[x + 4] = digest[x + 4] ^ digest[x + 12];
	}
	emit_digest(folded, 8, result, arena, role);
}

/* ---- as400_des(pass, user) — IBM AS/400 DES password hash ----
 * The algorithm John the Ripper's as400-des format computes, which is the
 * one AS/400 password level 0/1 stores:
 *   user  → upper, EBCDIC, padded to 8 with 0x40.  A 9- or 10-character
 *           userid is folded into 8 bytes by spreading the bits of
 *           characters 9 and 10 over all eight (character 10 is 0x40 when
 *           there are only 9): byte k ^= the k-th pair of bits.
 *   pass  → characters 1-8 through hx_a2e_pc, padded with 0x2a, as DES key 1.
 *   hash  = DES_ECB(user, key 1).  A 9- or 10-character password also
 *           makes key 2 from characters 9-10, padded with 0x2a, and the
 *           hash is DES(user, key 1) XOR DES(user, key 2).
 * A userid or password over 10 characters cannot occur and gives a null
 * result.  Returns 8 bytes; default rendering is 16-char hex. */
static unsigned char as400_up_e(unsigned char c)
{
	if (c >= 'a' && c <= 'z') c -= 32;
	return hx_a2e[c];
}

static void fn_as400_des(hx_func_entry *self, hx_val *args, int nargs,
                         hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char deskey[8], plain[8], ctblk[8], ct2[8];
	DES_key_schedule ks;
	int plen = args[0].len, ulen = args[1].len;
	const unsigned char *pw = (const unsigned char *)args[0].data;
	const unsigned char *us = (const unsigned char *)args[1].data;
	int x;
	(void)self; (void)nargs;

	/* An AS/400 userid and password are each at most 10 characters:
	 * mdxfind skips longer ones, hashpipe refuses them, and John cannot
	 * represent them. */
	if (ulen > 10 || plen > 10) {
		result->data = hx_arena_alloc(arena, 1);
		result->data[0] = '\0';
		result->len = 0;
		return;
	}

	for (x = 0; x < 8; x++)
		plain[x] = (x < ulen) ? as400_up_e(us[x]) : 0x40;
	if (ulen > 8) {
		unsigned char e8 = as400_up_e(us[8]);
		unsigned char e9 = (ulen > 9) ? as400_up_e(us[9]) : 0x40;
		plain[0] ^= e8 & 0xC0;
		plain[1] ^= (unsigned char)((e8 & 0x30) << 2);
		plain[2] ^= (unsigned char)((e8 & 0x0C) << 4);
		plain[3] ^= (unsigned char)((e8 & 0x03) << 6);
		plain[4] ^= e9 & 0xC0;
		plain[5] ^= (unsigned char)((e9 & 0x30) << 2);
		plain[6] ^= (unsigned char)((e9 & 0x0C) << 4);
		plain[7] ^= (unsigned char)((e9 & 0x03) << 6);
	}

	for (x = 0; x < 8; x++)
		deskey[x] = (x < plen) ? hx_a2e_pc[pw[x]] : 0x2a;
	DES_set_key_unchecked((const_DES_cblock *)deskey, &ks);
	DES_ecb_encrypt((const_DES_cblock *)plain, (DES_cblock *)ctblk,
	                &ks, DES_ENCRYPT);

	if (plen > 8) {
		for (x = 0; x < 8; x++)
			deskey[x] = (8 + x < plen) ? hx_a2e_pc[pw[8 + x]] : 0x2a;
		DES_set_key_unchecked((const_DES_cblock *)deskey, &ks);
		DES_ecb_encrypt((const_DES_cblock *)plain, (DES_cblock *)ct2,
		                &ks, DES_ENCRYPT);
		for (x = 0; x < 8; x++) ctblk[x] ^= ct2[x];
	}

	emit_digest(ctblk, 8, result, arena, role);
}

/* ---- besder_encode(md5bytes) — Besder Auth 8-char encode ----
 * Algorithm per mdxfind.c:32992 (JOB_BESDER_AUTH). For each of 4
 * 4-byte groups in the 16-byte input, emits two alphanumeric chars:
 *   v0 = ((b0 + b1) & 0xff) % 62
 *   v1 = ((b2 + b3) & 0xff) % 62
 * indexed into "0-9A-Za-z". Inputs shorter than 16 bytes return
 * the empty string.
 */
static void fn_besder_encode(hx_func_entry *self, hx_val *args, int nargs,
                             hx_val *result, hx_arena *arena, uint8_t role)
{
	static const char besder_table[] =
	  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	const unsigned char *d = (const unsigned char *)args[0].data;
	char *out;
	int i;
	(void)self; (void)nargs; (void)role;

	if (args[0].len < 16) {
		result->data = hx_arena_alloc(arena, 1);
		result->data[0] = '\0';
		result->len = 0;
		return;
	}
	out = hx_arena_alloc(arena, 9);
	for (i = 0; i < 4; i++) {
		int v0 = ((d[i*4] + d[i*4+1]) & 0xff) % 62;
		int v1 = ((d[i*4+2] + d[i*4+3]) & 0xff) % 62;
		out[i*2]   = besder_table[v0];
		out[i*2+1] = besder_table[v1];
	}
	out[8] = '\0';
	result->data = out;
	result->len  = 8;
}

/* ---- dahua_encode(md5bytes) — Dahua Auth 8-char encode ----
 * Algorithm per mdxfind.c:32992 (JOB_DAHUA_AUTH; same case as
 * BESDER but without the & 0xff truncation):
 *   v0 = (b0 + b1) % 62
 *   v1 = (b2 + b3) % 62
 * indexed into "0-9A-Za-z". Inputs shorter than 16 bytes return
 * the empty string.
 */
static void fn_dahua_encode(hx_func_entry *self, hx_val *args, int nargs,
                            hx_val *result, hx_arena *arena, uint8_t role)
{
	static const char dahua_table[] =
	  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	const unsigned char *d = (const unsigned char *)args[0].data;
	char *out;
	int i;
	(void)self; (void)nargs; (void)role;

	if (args[0].len < 16) {
		result->data = hx_arena_alloc(arena, 1);
		result->data[0] = '\0';
		result->len = 0;
		return;
	}
	out = hx_arena_alloc(arena, 9);
	for (i = 0; i < 4; i++) {
		int v0 = (d[i*4] + d[i*4+1]) % 62;
		int v1 = (d[i*4+2] + d[i*4+3]) % 62;
		out[i*2]   = dahua_table[v0];
		out[i*2+1] = dahua_table[v1];
	}
	out[8] = '\0';
	result->data = out;
	result->len  = 8;
}

/* ---- aes_ecb_encrypt(key, plaintext) — single-block AES-ECB encrypt ----
 * Algorithm per mdxfind.c:33438 (JOB_AES{128,192,256}_NOKDF).
 * key:       16 / 24 / 32 bytes — selects AES-128/192/256.
 * plaintext: must be a positive multiple of 16 bytes.
 * Other lengths return the empty string.
 * Returns the ciphertext bytes, length == plaintext length.
 */
static void fn_aes_ecb_encrypt(hx_func_entry *self, hx_val *args, int nargs,
                               hx_val *result, hx_arena *arena, uint8_t role)
{
	int klen = args[0].len, ptlen = args[1].len;
	const unsigned char *key = (const unsigned char *)args[0].data;
	const unsigned char *pt  = (const unsigned char *)args[1].data;
	AES_KEY ak;
	unsigned char *out;
	int blocks, i;
	(void)self; (void)nargs;

	if ((klen != 16 && klen != 24 && klen != 32) ||
	    ptlen <= 0 || (ptlen & 15) != 0) {
		result->data = hx_arena_alloc(arena, 1);
		result->data[0] = '\0';
		result->len = 0;
		return;
	}

	AES_set_encrypt_key(key, klen * 8, &ak);
	blocks = ptlen / 16;
	out = (unsigned char *)hx_arena_alloc(arena, ptlen + 1);
	for (i = 0; i < blocks; i++)
		AES_ecb_encrypt(pt + i * 16, out + i * 16, &ak, AES_ENCRYPT);
	out[ptlen] = '\0';
	emit_digest((char *)out, ptlen, result, arena, role);
}

/* ---- aes_cbc_decrypt(key, iv, ct) — AES-CBC decrypt (no padding strip) ----
 * key: 16/24/32 bytes (AES-128/192/256).
 * iv:  16 bytes.
 * ct:  positive multiple of 16 bytes.
 * Returns the raw decrypted bytes (caller is responsible for any
 * padding handling). Bad lengths return the empty string.
 *
 * Algorithm per mdxfind.c:34340 (JOB_VEEAM_VBK) and elsewhere.
 */
static void fn_aes_cbc_decrypt(hx_func_entry *self, hx_val *args, int nargs,
                               hx_val *result, hx_arena *arena, uint8_t role)
{
	int klen = args[0].len, ivlen = args[1].len, ctlen = args[2].len;
	const unsigned char *key = (const unsigned char *)args[0].data;
	const unsigned char *ct  = (const unsigned char *)args[2].data;
	unsigned char ivcopy[16];
	AES_KEY ak;
	unsigned char *out;
	(void)self; (void)nargs;

	if ((klen != 16 && klen != 24 && klen != 32) ||
	    ivlen != 16 || ctlen <= 0 || (ctlen & 15) != 0) {
		result->data = hx_arena_alloc(arena, 1);
		result->data[0] = '\0';
		result->len = 0;
		return;
	}

	memcpy(ivcopy, args[1].data, 16);
	AES_set_decrypt_key(key, klen * 8, &ak);
	out = (unsigned char *)hx_arena_alloc(arena, ctlen + 1);
	AES_cbc_encrypt(ct, out, ctlen, &ak, ivcopy, AES_DECRYPT);
	out[ctlen] = '\0';
	emit_digest((char *)out, ctlen, result, arena, role);
}

/* ---- aes_cbc_encrypt(key, iv, pt) — AES-CBC encrypt (no padding) ----
 * Same length rules as aes_cbc_decrypt; caller pre-pads.
 */
static void fn_aes_cbc_encrypt(hx_func_entry *self, hx_val *args, int nargs,
                               hx_val *result, hx_arena *arena, uint8_t role)
{
	int klen = args[0].len, ivlen = args[1].len, ptlen = args[2].len;
	const unsigned char *key = (const unsigned char *)args[0].data;
	const unsigned char *pt  = (const unsigned char *)args[2].data;
	unsigned char ivcopy[16];
	AES_KEY ak;
	unsigned char *out;
	(void)self; (void)nargs;

	if ((klen != 16 && klen != 24 && klen != 32) ||
	    ivlen != 16 || ptlen <= 0 || (ptlen & 15) != 0) {
		result->data = hx_arena_alloc(arena, 1);
		result->data[0] = '\0';
		result->len = 0;
		return;
	}

	memcpy(ivcopy, args[1].data, 16);
	AES_set_encrypt_key(key, klen * 8, &ak);
	out = (unsigned char *)hx_arena_alloc(arena, ptlen + 1);
	AES_cbc_encrypt(pt, out, ptlen, &ak, ivcopy, AES_ENCRYPT);
	out[ptlen] = '\0';
	emit_digest((char *)out, ptlen, result, arena, role);
}

/* ---- aes_unwrap(kek, wrapped) — RFC 3394 AES Key Unwrap ----
 * kek:     16 bytes (AES-128) or 32 bytes (AES-256). Other lengths
 *          return empty.
 * wrapped: must be 8 + 8n bytes for n >= 1. Other lengths return empty.
 * Returns: 8n bytes of plaintext on success (when the unwrap-IV check
 *          matches 0xA6A6A6A6A6A6A6A6), or empty string on failure.
 */
static void fn_aes_unwrap(hx_func_entry *self, hx_val *args, int nargs,
                          hx_val *result, hx_arena *arena, uint8_t role)
{
	int klen = args[0].len, wlen = args[1].len;
	const unsigned char *kek = (const unsigned char *)args[0].data;
	const unsigned char *wrapped = (const unsigned char *)args[1].data;
	unsigned char A[8];
	unsigned char (*R)[8];
	unsigned char B[16];
	AES_KEY ak;
	int n, j, ii;
	(void)self; (void)nargs; (void)role;

	if ((klen != 16 && klen != 32) || wlen < 16 || (wlen & 7) != 0) {
		result->data = hx_arena_alloc(arena, 1);
		result->data[0] = '\0';
		result->len = 0;
		return;
	}
	n = wlen / 8 - 1;

	AES_set_decrypt_key(kek, klen * 8, &ak);
	memcpy(A, wrapped, 8);
	R = (unsigned char (*)[8])hx_arena_alloc(arena, n * 8);
	memcpy(R, wrapped + 8, n * 8);

	for (j = 5; j >= 0; j--) {
		for (ii = n - 1; ii >= 0; ii--) {
			unsigned int t = (unsigned int)(n * j + ii + 1);
			A[7] ^= t        & 0xff;
			A[6] ^= (t >> 8) & 0xff;
			A[5] ^= (t >> 16)& 0xff;
			A[4] ^= (t >> 24)& 0xff;
			memcpy(B,     A,    8);
			memcpy(B + 8, R[ii], 8);
			AES_ecb_encrypt(B, B, &ak, AES_DECRYPT);
			memcpy(A,     B,     8);
			memcpy(R[ii], B + 8, 8);
		}
	}

	{
		static const unsigned char iv[8] =
		    {0xa6,0xa6,0xa6,0xa6,0xa6,0xa6,0xa6,0xa6};
		if (memcmp(A, iv, 8) != 0) {
			result->data = hx_arena_alloc(arena, 1);
			result->data[0] = '\0';
			result->len = 0;
			return;
		}
	}

	{
		unsigned char *out = (unsigned char *)hx_arena_alloc(arena, n * 8 + 1);
		memcpy(out, R, n * 8);
		out[n * 8] = 0;
		result->data = (char *)out;
		result->len  = n * 8;
	}
}

/* ---- racf_kdfaes(pass, user, header, salt) — IBM RACF KDFAES ----
 * Algorithm per mdxfind.c:30390-30547. Five phases:
 *   1) DES key from EBCDIC-PC password (pad to 8 with 0x2a)
 *   2) DES-ECB encrypt EBCDIC username (pad to 8 with 0x40)
 *   3) Memory-filling PBKDF2-HMAC-SHA256 loop:
 *        mem_fac iterations producing 32-byte blocks in a memory buffer;
 *        salt updated each round to (prelast || out).
 *   4) Transposition pass: index-permuted PBKDF2-HMAC-SHA256(iter=1).
 *   5) Final PBKDF2-HMAC-SHA256 over (mem_fac-1)*32-byte buffer to derive
 *      a 32-byte AES-256 key; AES-256-ECB encrypt EBCDIC user (padded to
 *      16 with zeros) → 16-byte hash.
 *
 * Header (16 bytes):
 *   [8..9]   mem_fac_raw (BE u16, 1..15)  → mem_fac = (1<<raw)/32
 *   [10..11] rep_fac     (BE u16, >=1)    → pbkdf_iters = rep_fac * 100
 * Other header bytes are ignored by the KDF (carried in the format).
 *
 * Returns 16 bytes; default rendering is 32-char lowercase hex.
 */
static void fn_racf_kdfaes(hx_func_entry *self, hx_val *args, int nargs,
                           hx_val *result, hx_arena *arena, uint8_t role)
{
	const char *pdata = args[0].data;
	const char *udata = args[1].data;
	const char *hdata = args[2].data;
	const char *sdata = args[3].data;
	int plen = args[0].len, ulen = args[1].len;
	unsigned char deskey[8], euser[16], desout[8];
	unsigned char header[16], salt16[16];
	unsigned char key[32], outbuf[32], U[32], prelast[32];
	unsigned char pbsalt[64], stmp[128];
	unsigned char *membuf;
	unsigned char aeskey[32], aesout[16];
	DES_key_schedule ks;
	AES_KEY ak;
	int mem_fac, rep_fac, pbkdf_iters, mem_fac_raw;
	int i, j, k, slen;
	unsigned int hmlen = 32;
	(void)self; (void)nargs;

	if (plen > 8) plen = 8;
	if (args[2].len < 16 || args[3].len < 16) {
		memset(aesout, 0, 16);
		emit_digest(aesout, 16, result, arena, role);
		return;
	}
	memcpy(header, hdata, 16);
	memcpy(salt16, sdata, 16);

	/* Header parameters */
	mem_fac_raw = ((int)header[8] << 8) | header[9];
	rep_fac     = ((int)header[10] << 8) | header[11];
	if (mem_fac_raw < 1 || mem_fac_raw > 15 || rep_fac < 1) {
		memset(aesout, 0, 16);
		emit_digest(aesout, 16, result, arena, role);
		return;
	}
	mem_fac = (1 << mem_fac_raw) / 32;
	if (mem_fac < 1) {
		memset(aesout, 0, 16);
		emit_digest(aesout, 16, result, arena, role);
		return;
	}
	pbkdf_iters = rep_fac * 100;

	/* Phase 1: DES key from EBCDIC-PC password */
	for (i = 0; i < 8; i++)
		deskey[i] = (i < plen) ? hx_a2e_pc[(unsigned char)pdata[i]] : 0x2a;
	DES_set_key_unchecked((const_DES_cblock *)deskey, &ks);

	/* Username → standard EBCDIC, pad to 8 with 0x40 */
	for (i = 0; i < 8; i++) {
		unsigned char c = (i < ulen) ? (unsigned char)udata[i] : ' ';
		if (c >= 'a' && c <= 'z') c -= 32;
		euser[i] = hx_a2e[c];
	}

	/* Phase 2: DES encrypt username */
	DES_ecb_encrypt((const_DES_cblock *)euser, (DES_cblock *)desout,
	                &ks, DES_ENCRYPT);

	/* Phase 3: memory-filling PBKDF2-HMAC-SHA256 loop */
	membuf = (unsigned char *)hx_arena_alloc(arena, (size_t)mem_fac * 32);
	memset(key, 0, 32);
	memcpy(key, desout, 8);
	memcpy(pbsalt, salt16, 16);
	pbsalt[16] = (mem_fac >> 24) & 0xff;
	pbsalt[17] = (mem_fac >> 16) & 0xff;
	pbsalt[18] = (mem_fac >>  8) & 0xff;
	pbsalt[19] = (mem_fac      ) & 0xff;
	slen = 20;

	for (i = 0; i < mem_fac; i++) {
		memcpy(stmp, pbsalt, slen);
		stmp[slen]   = 0;
		stmp[slen+1] = 0;
		stmp[slen+2] = 0;
		stmp[slen+3] = 1;
		HMAC(EVP_sha256(), key, 8, stmp, slen + 4, U, &hmlen);
		memcpy(outbuf, U, 32);
		for (j = 1; j < pbkdf_iters; j++) {
			if (j == pbkdf_iters - 1) memcpy(prelast, U, 32);
			HMAC(EVP_sha256(), key, 8, U, 32, U, &hmlen);
			for (k = 0; k < 32; k++) outbuf[k] ^= U[k];
		}
		memcpy(membuf + (size_t)i * 32, outbuf, 32);
		memcpy(pbsalt, prelast, 16);
		memcpy(pbsalt + 16, outbuf, 32);
		slen = 48;
	}

	/* Phase 4: transposition pass */
	memcpy(key, outbuf, 32);
	for (i = 0; i < mem_fac; i++) {
		uint32_t n_val = ((uint32_t)key[28] << 24)
		               | ((uint32_t)key[29] << 16)
		               | ((uint32_t)key[30] << 8)
		               |  (uint32_t)key[31];
		int n_key = n_val & (mem_fac - 1);
		memcpy(stmp, membuf + (size_t)n_key * 32, 32);
		stmp[32] = 0; stmp[33] = 0; stmp[34] = 0; stmp[35] = 1;
		HMAC(EVP_sha256(), key, 32, stmp, 36, outbuf, &hmlen);
		memcpy(membuf + (size_t)i * 32, outbuf, 32);
		memcpy(key, outbuf, 32);
	}

	/* Phase 5: final PBKDF2 over (mem_fac-1)*32 bytes */
	{
		int final_slen = (mem_fac - 1) * 32;
		unsigned char *fs;
		memset(membuf + (size_t)(mem_fac - 1) * 32, 0, 32);
		fs = (unsigned char *)hx_arena_alloc(arena, final_slen + 8);
		memcpy(fs, membuf, final_slen);
		fs[final_slen]   = 0;
		fs[final_slen+1] = 0;
		fs[final_slen+2] = 0;
		fs[final_slen+3] = 1;
		HMAC(EVP_sha256(), key, 32, fs, final_slen + 4, U, &hmlen);
		memcpy(outbuf, U, 32);
		for (j = 1; j < pbkdf_iters; j++) {
			HMAC(EVP_sha256(), key, 32, U, 32, U, &hmlen);
			for (k = 0; k < 32; k++) outbuf[k] ^= U[k];
		}
		memcpy(aeskey, outbuf, 32);
	}

	/* Phase 6: AES-256-ECB encrypt EBCDIC user (pad to 16 with 0x00) */
	{
		unsigned char pt[16];
		memset(pt, 0, 16);
		memcpy(pt, euser, 8);
		AES_set_encrypt_key(aeskey, 256, &ak);
		AES_encrypt(pt, aesout, &ak);
	}

	emit_digest(aesout, 16, result, arena, role);
}

/* ---- axcrypt(pass, salt, iter) — AxCrypt AES Key Wrap KDF ----
 * Algorithm per mdxfind.c:19274-19345 (forward path):
 *   KEK = (sha1(pass)[0..15]) XOR salt[0..15]
 *   A   = 0xA6 * 8;  R1 = R2 = 0
 *   for j in 0..iter-1:
 *     A,R1 = AES_enc(A||R1, KEK);  A ^= LE32(2*j+1) at A[0..3]
 *     A,R2 = AES_enc(A||R2, KEK);  A ^= LE32(2*j+2) at A[0..3]
 *   output = A || R1 || R2  (24 bytes, default 48 lower-hex)
 */
static void fn_axcrypt(hx_func_entry *self, hx_val *args, int nargs,
                       hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char sha[20], salt16[16], kek[16];
	unsigned char A[8], R1[8], R2[8];
	unsigned char block[16], outblk[16];
	AES_KEY ks;
	int iter, j, i, slen;
	(void)self; (void)nargs;

	SHA1((const unsigned char *)args[0].data, args[0].len, sha);

	memset(salt16, 0, 16);
	slen = args[1].len < 16 ? args[1].len : 16;
	memcpy(salt16, args[1].data, slen);

	for (i = 0; i < 16; i++) kek[i] = sha[i] ^ salt16[i];

	iter = val_to_int(&args[2]);
	if (iter < 1) iter = 1;

	memset(A, 0xa6, 8);
	memset(R1, 0, 8);
	memset(R2, 0, 8);

	AES_set_encrypt_key(kek, 128, &ks);

	for (j = 0; j < iter; j++) {
		unsigned long tv;

		memcpy(block,     A, 8);
		memcpy(block + 8, R1, 8);
		AES_encrypt(block, outblk, &ks);
		memcpy(A,  outblk,     8);
		memcpy(R1, outblk + 8, 8);
		tv = (unsigned long)(2 * j + 1);
		A[0] ^= tv         & 0xff;
		A[1] ^= (tv >> 8)  & 0xff;
		A[2] ^= (tv >> 16) & 0xff;
		A[3] ^= (tv >> 24) & 0xff;

		memcpy(block,     A, 8);
		memcpy(block + 8, R2, 8);
		AES_encrypt(block, outblk, &ks);
		memcpy(A,  outblk,     8);
		memcpy(R2, outblk + 8, 8);
		tv = (unsigned long)(2 * j + 2);
		A[0] ^= tv         & 0xff;
		A[1] ^= (tv >> 8)  & 0xff;
		A[2] ^= (tv >> 16) & 0xff;
		A[3] ^= (tv >> 24) & 0xff;
	}

	{
		unsigned char wrapped[24];
		memcpy(wrapped,      A,  8);
		memcpy(wrapped + 8,  R1, 8);
		memcpy(wrapped + 16, R2, 8);
		emit_digest(wrapped, 24, result, arena, role);
	}
}

/* ---- oracle7(pass, user) — Oracle 7 H: Type DES-CBC password hash ----
 * Algorithm per mdxfind.c:17729-17793:
 *   wbuf = utf16be( upper(user) . upper(pass) ) zero-padded so that
 *          (user.len + pass.len) rounds up to a multiple of 4 characters.
 *   key1 = 0x0123456789ABCDEF (constant)
 *   pass1 = DES-CBC(wbuf, key=key1, iv=0)
 *   key2 = last 8 bytes (= IV state) from pass1
 *   pass2 = DES-CBC(wbuf, key=key2, iv=0)
 *   result = last 8 bytes from pass2
 * Returns 8 bytes; default rendering is 16-char hex. (mdxfind reports
 * the digest in uppercase hex; wrap with upper() if that's wanted.)
 */
static void fn_oracle7(hx_func_entry *self, hx_val *args, int nargs,
                       hx_val *result, hx_arena *arena, uint8_t role)
{
	static const unsigned char key1[8] =
	    {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
	const char *pdata = args[0].data;
	const char *udata = args[1].data;
	int plen = args[0].len, ulen = args[1].len;
	int catlen, padlen, widelen, max_w;
	unsigned char *wbuf;
	DES_key_schedule ks;
	DES_cblock iv, blk;
	int y, i;
	(void)self; (void)nargs;

	catlen = ulen + plen;
	padlen = (catlen + 3) & ~3;
	max_w  = padlen * 2;
	wbuf   = (unsigned char *)hx_arena_alloc(arena, max_w + 8);
	widelen = 0;

	for (i = 0; i < ulen; i++) {
		unsigned char c = (unsigned char)udata[i];
		if (c >= 'a' && c <= 'z') c -= 32;
		wbuf[widelen++] = 0;
		wbuf[widelen++] = c;
	}
	for (i = 0; i < plen; i++) {
		unsigned char c = (unsigned char)pdata[i];
		if (c >= 'a' && c <= 'z') c -= 32;
		wbuf[widelen++] = 0;
		wbuf[widelen++] = c;
	}
	while (widelen < max_w) {
		wbuf[widelen++] = 0;
		wbuf[widelen++] = 0;
	}

	/* Pass 1: DES-CBC with fixed key */
	DES_set_key_unchecked((const_DES_cblock *)key1, &ks);
	memset(iv, 0, 8);
	for (y = 0; y < widelen; y += 8) {
		blk[0] = wbuf[y+0] ^ iv[0]; blk[1] = wbuf[y+1] ^ iv[1];
		blk[2] = wbuf[y+2] ^ iv[2]; blk[3] = wbuf[y+3] ^ iv[3];
		blk[4] = wbuf[y+4] ^ iv[4]; blk[5] = wbuf[y+5] ^ iv[5];
		blk[6] = wbuf[y+6] ^ iv[6]; blk[7] = wbuf[y+7] ^ iv[7];
		DES_ecb_encrypt((const_DES_cblock *)blk, (DES_cblock *)iv,
		                &ks, DES_ENCRYPT);
	}

	/* Pass 2: DES-CBC with key derived from last block of pass 1 */
	DES_set_key_unchecked((const_DES_cblock *)iv, &ks);
	memset(iv, 0, 8);
	for (y = 0; y < widelen; y += 8) {
		blk[0] = wbuf[y+0] ^ iv[0]; blk[1] = wbuf[y+1] ^ iv[1];
		blk[2] = wbuf[y+2] ^ iv[2]; blk[3] = wbuf[y+3] ^ iv[3];
		blk[4] = wbuf[y+4] ^ iv[4]; blk[5] = wbuf[y+5] ^ iv[5];
		blk[6] = wbuf[y+6] ^ iv[6]; blk[7] = wbuf[y+7] ^ iv[7];
		DES_ecb_encrypt((const_DES_cblock *)blk, (DES_cblock *)iv,
		                &ks, DES_ENCRYPT);
	}

	emit_digest((unsigned char *)iv, 8, result, arena, role);
}

/* ---- ebcdic(s) — ASCII → EBCDIC byte-by-byte conversion ---- */
static void fn_ebcdic(hx_func_entry *self, hx_val *args, int nargs,
                     hx_val *result, hx_arena *arena, uint8_t role)
{
	int n = args[0].len;
	const unsigned char *in = (const unsigned char *)args[0].data;
	unsigned char *out;
	int i;
	(void)self; (void)nargs; (void)role;

	out = (unsigned char *)hx_arena_alloc(arena, n + 1);
	for (i = 0; i < n; i++) out[i] = hx_a2e[in[i]];
	out[n] = '\0';
	result->data = (char *)out;
	result->len  = n;
}

/* ---- racf_encrypt(pass, user) — IBM RACF DES hash ----
 * Algorithm per mdxfind.c:19619-19662:
 *   Pass → DES key: ebcdic(c) ^ 0x55, shift left 1 bit, set low bit for odd parity.
 *   User → plaintext: upper, pad-to-8 with ASCII space, then ebcdic.
 *   ciphertext = DES_ECB_encrypt(plaintext, key)
 * Returns the 8-byte ciphertext; default rendering is 16-char lowercase hex.
 * For the canonical $racf$*USER*HEX form, wrap with upper() and prepend.
 */
static void fn_racf_encrypt(hx_func_entry *self, hx_val *args, int nargs,
                            hx_val *result, hx_arena *arena, uint8_t role)
{
	unsigned char deskey[8], plain[8], ctblk[8];
	DES_key_schedule ks;
	int plen = args[0].len < 8 ? args[0].len : 8;
	int ulen = args[1].len < 8 ? args[1].len : 8;
	int x, bits;
	unsigned char val, t;
	(void)self; (void)nargs;

	for (x = 0; x < 8; x++) {
		unsigned char e = (x < plen)
		    ? hx_a2e[(unsigned char)args[0].data[x]]
		    : 0x40;             /* EBCDIC space */
		val = (e ^ 0x55);
		val = (val << 1) & 0xfe;
		bits = 0; t = val;
		while (t) { bits += t & 1; t >>= 1; }
		if ((bits & 1) == 0) val |= 1;
		deskey[x] = val;
	}
	for (x = 0; x < 8; x++) {
		unsigned char c = (x < ulen) ? (unsigned char)args[1].data[x] : ' ';
		if (c >= 'a' && c <= 'z') c -= 32;
		plain[x] = hx_a2e[c];
	}
	DES_set_key_unchecked((DES_cblock *)deskey, &ks);
	DES_ecb_encrypt((DES_cblock *)plain, (DES_cblock *)ctblk, &ks, DES_ENCRYPT);

	emit_digest(ctblk, 8, result, arena, role);
}

/* ---- cisco_pix_encode (Cisco PIX / ASA 16-char format) ----
 * Input:  16 raw bytes (typically an MD5 digest)
 * Output: 16-char ASCII string in the phpitoa64 alphabet
 *         (./0-9A-Za-z), encoding 4 chunks of 3 bytes each
 *         (every 4th byte of the digest is dropped).
 * Mirrors mdxfind.c:2176 (cisco_pix_encode); keep in sync if that diverges.
 */
static void fn_cisco_pix_encode(hx_func_entry *self, hx_val *args, int nargs,
                                hx_val *result, hx_arena *arena, uint8_t role)
{
	static const char phpitoa64[] =
	    "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	unsigned char buf[16];
	char *out;
	int copylen = args[0].len < 16 ? args[0].len : 16;
	int i, j = 0;
	(void)self; (void)nargs; (void)role;

	memset(buf, 0, 16);
	memcpy(buf, args[0].data, copylen);

	out = hx_arena_alloc(arena, 17);
	for (i = 0; i < 16; i += 4) {
		unsigned int v = buf[i] | (buf[i+1] << 8) | (buf[i+2] << 16);
		out[j++] = phpitoa64[v & 0x3f];
		out[j++] = phpitoa64[(v >> 6) & 0x3f];
		out[j++] = phpitoa64[(v >> 12) & 0x3f];
		out[j++] = phpitoa64[(v >> 18) & 0x3f];
	}
	out[16] = '\0';
	result->data = out;
	result->len  = 16;
}


/* ---- progress_encode (Progress OpenEdge ENCODE) ---- */

extern void myprogress(char *cur, int len, char *dest);

static void fn_progress_encode(hx_func_entry *self, hx_val *args, int nargs,
                               hx_val *result, hx_arena *arena, uint8_t role)
{
	int inlen = args[0].len;
	int padlen = ((inlen + 15) / 16) * 16;
	char *padded;
	char *out;
	(void)self; (void)nargs; (void)role;

	if (padlen < 16) padlen = 16;
	padded = hx_arena_alloc(arena, padlen);
	out = hx_arena_alloc(arena, 17);

	memcpy(padded, args[0].data, inlen);
	memset(padded + inlen, 0, padlen - inlen);
	myprogress(padded, inlen, out);
	out[16] = '\0';

	result->data = out;
	result->len = 16;
}

/* ---- sha512crypt_encode ---- */

/*
 * SHA-512 crypt uses a custom base64 with alphabet ./0-9A-Za-z
 * and a specific byte permutation of the 64-byte digest.
 * The encoding groups bytes in a specific order (not sequential)
 * and packs 3 bytes into 4 characters, similar to phpass but
 * with big-endian bit extraction.
 */
static const char crypt_b64[] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void crypt_b64_encode3(const unsigned char *in, int n,
                               char *out, int *opos)
{
	unsigned int v = 0;
	int i, o = *opos;

	/* big-endian packing: first byte is high bits */
	if (n > 0) v  = (unsigned int)in[0] << 16;
	if (n > 1) v |= (unsigned int)in[1] << 8;
	if (n > 2) v |= (unsigned int)in[2];

	for (i = 0; i < n + 1; i++) {
		out[o++] = crypt_b64[v & 0x3f];
		v >>= 6;
	}
	*opos = o;
}

static void fn_sha512crypt_encode(hx_func_entry *self, hx_val *args,
                                   int nargs, hx_val *result,
                                   hx_arena *arena, uint8_t role)
{
	/*
	 * SHA-512 crypt byte permutation: the 64-byte digest is
	 * rearranged into groups of 3 bytes before base64 encoding.
	 * Permutation order per crypt(3) specification.
	 */
	static const int perm[] = {
		42, 21,  0,  1, 43, 22, 23,  2, 44, 45, 24,  3,
		 4, 46, 25, 26,  5, 47, 48, 27,  6,  7, 49, 28,
		29,  8, 50, 51, 30,  9, 10, 52, 31, 32, 11, 53,
		54, 33, 12, 13, 55, 34, 35, 14, 56, 57, 36, 15,
		16, 58, 37, 38, 17, 59, 60, 39, 18, 19, 61, 40,
		41, 20, 62, 63
	};
	const unsigned char *in = (const unsigned char *)args[0].data;
	int inlen = args[0].len;
	char *out;
	int opos = 0, i;
	unsigned char permuted[64];
	(void)self; (void)nargs; (void)role;

	/* permute the input bytes (pad with 0 if short) */
	for (i = 0; i < 64; i++)
		permuted[i] = (perm[i] < inlen) ? in[perm[i]] : 0;

	/* encode: 21 groups of 3 bytes + 1 trailing byte = 86 chars */
	out = hx_arena_alloc(arena, 90);
	for (i = 0; i < 63; i += 3)
		crypt_b64_encode3(&permuted[i], 3, out, &opos);
	/* last byte: 1 byte → 2 chars */
	crypt_b64_encode3(&permuted[63], 1, out, &opos);

	out[opos] = '\0';
	result->data = out;
	result->len  = opos;
}

/* ---- bcrypt_encode ---- */

/*
 * bcrypt uses a custom base64 alphabet:
 *   ./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
 * Note: different order from standard base64 and crypt.
 * Encoding is big-endian, 4 chars per 3 bytes, no padding.
 */
static const char bcrypt_b64[] =
	"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static void fn_bcrypt_encode(hx_func_entry *self, hx_val *args,
                              int nargs, hx_val *result,
                              hx_arena *arena, uint8_t role)
{
	const unsigned char *in = (const unsigned char *)args[0].data;
	int inlen = args[0].len;
	int outmax = ((inlen + 2) / 3) * 4 + 1;
	char *out;
	int i, o;
	(void)self; (void)nargs; (void)role;

	out = hx_arena_alloc(arena, outmax);
	o = 0;
	for (i = 0; i < inlen; i += 3) {
		unsigned int a = in[i];
		unsigned int b = (i + 1 < inlen) ? in[i + 1] : 0;
		unsigned int c = (i + 2 < inlen) ? in[i + 2] : 0;
		unsigned int triple = (a << 16) | (b << 8) | c;

		out[o++] = bcrypt_b64[(triple >> 18) & 0x3f];
		out[o++] = bcrypt_b64[(triple >> 12) & 0x3f];
		if (i + 1 < inlen)
			out[o++] = bcrypt_b64[(triple >> 6) & 0x3f];
		if (i + 2 < inlen)
			out[o++] = bcrypt_b64[triple & 0x3f];
	}
	out[o] = '\0';
	result->data = out;
	result->len  = o;
}

/* ---- encoding functions ---- */

#include "ruleproc32.h"

/*
 * The conversion functions (utf16le, utf16be, utf7, zext16, from_cp1252,
 * from_cp1251, hex, base64, phpass_encode, cisco4_encode, fromhex,
 * frombase64, upper, lower, rev, rot13) are compiler aliases of OP_CONVERT
 * (hx-functions.md 18.6); their own implementations were retired (18.9)
 * once every bytecode consumer handled OP_CONVERT and the golden corpus
 * (hx-support/phase1/) gave identical output through the engine.  Each name
 * stays in the registry, bound to fn_conv_call below, so that it stays
 * reserved -- a bridge registers a name only when hx_func_lookup does not
 * know it -- and so that the call forms the aliases do not cover still work
 * the same way: hex_bin(x), the identity, and a call with extra arguments,
 * which these functions always ignored.  ruleproc32.c supplies
 * utf8_to_utf32 and utf8_to_utf7 to the engine.
 */

/* ================================================================
 * OP_CONVERT: the registry, convert() argument checking, the compiler
 * aliases, and the decode -> premap -> encode engine.  hx-functions.md
 * section 18.
 *
 * A name the registry knows but cannot yet decode or encode, and a premap
 * token not yet implemented, is a compile error naming it ("not yet
 * implemented"), never a silent fallback.
 *
 * UTF-8 is read by utf8_to_utf32 (the definition of well-formed UTF-8 for all
 * of mdxfind) and UTF-7 written by utf8_to_utf7.  Every cpNNN, KOI8 and case
 * table comes from hx_conv_tables.h, which hx-support/gen/gen_hx_tables.py
 * generates at build time from the Windows 11 dumps, the unicode.org KOI8
 * tables and Unicode 18.0.0 UnicodeData.txt (section 18.8).  The golden corpus
 * (hx-support/phase1/) shows every aliased function byte-identical to the
 * function it replaces; hx-support/phase2/ proves the tables against the
 * dumps exhaustively.
 * ================================================================ */

#include "hx_conv_tables.h"

enum { CV_NO = 0, CV_YES = 1, CV_LATER = 2 };   /* direction available? */

#define CS HXE_KIND_CHARSET
#define TX HXE_KIND_TRANSFER
#define CPE(n) [HXE_CP##n] = { "cp" #n, CS, CV_YES, CV_YES, n, 1, 0 }
#define SBE(id, nm) [HXE_SB_##id] = { nm, CS, CV_YES, CV_YES, 0, 1, 1 }
#define MBE(id, nm) [HXE_##id] = { nm, CS, CV_YES, CV_YES, 0, 1, 0, 1 }

/* unmap: the encoder has code points it cannot write (section 18.4) */
static const struct {
	const char *name;
	uint8_t     kind;
	uint8_t     dec, enc;
	uint16_t    cp;         /* a Windows code page (cpNNN): its number */
	uint8_t     unmap;
	uint8_t     sb;         /* a standard single-byte table (hxt_sb_*) */
	uint8_t     mb;         /* a multi-byte table (hxt_mb_*) or ISO-2022-JP */
} hxe_reg[HXE_COUNT] = {
	[HXE_UTF8]      = { "utf8",      CS, CV_YES, CV_YES, 0, 0 },
	[HXE_UTF16LE]   = { "utf16le",   CS, CV_YES, CV_YES, 0, 0 },
	[HXE_UTF16BE]   = { "utf16be",   CS, CV_YES, CV_YES, 0, 0 },
	[HXE_UTF7]      = { "utf7",      CS, CV_YES, CV_YES, 0, 0 },
	[HXE_LOWBYTE16] = { "lowbyte16", CS, CV_NO,  CV_YES, 0, 0 },
	[HXE_LATIN1]    = { "latin1",    CS, CV_YES, CV_YES, 0, 1 },
	[HXE_KOI8R]     = { "koi8r",     CS, CV_YES, CV_YES, 0, 1 },
	[HXE_KOI8U]     = { "koi8u",     CS, CV_YES, CV_YES, 0, 1 },
	CPE(1252), CPE(1251), CPE(37),
	CPE(874), CPE(932), CPE(936), CPE(949), CPE(950),
	CPE(1250), CPE(1253), CPE(1254), CPE(1255), CPE(1256),
	CPE(1257), CPE(1258), CPE(1361),
	CPE(437), CPE(737), CPE(775), CPE(850), CPE(852), CPE(855),
	CPE(857), CPE(858), CPE(860), CPE(861), CPE(862), CPE(863),
	CPE(864), CPE(865), CPE(866), CPE(869),
	CPE(20866), CPE(21866), CPE(28591),
	CPE(1047), CPE(1140), CPE(1148), CPE(10000),
	CPE(500), CPE(708), CPE(720), CPE(875), CPE(1026), CPE(1141), CPE(1142),
	CPE(1143), CPE(1144), CPE(1145), CPE(1146), CPE(1147), CPE(1149),
	CPE(10001), CPE(10002), CPE(10003), CPE(10004), CPE(10005), CPE(10006),
	CPE(10007), CPE(10008), CPE(10010), CPE(10017), CPE(10021), CPE(10029),
	CPE(10079), CPE(10081), CPE(10082), CPE(20127), CPE(28592), CPE(28593),
	CPE(28594), CPE(28595), CPE(28596), CPE(28597), CPE(28598), CPE(28599),
	CPE(28603), CPE(28605),
	SBE(ISO8859_2, "iso8859_2"),
	SBE(ISO8859_3, "iso8859_3"),
	SBE(ISO8859_4, "iso8859_4"),
	SBE(ISO8859_5, "iso8859_5"),
	SBE(ISO8859_6, "iso8859_6"),
	SBE(ISO8859_7, "iso8859_7"),
	SBE(ISO8859_8, "iso8859_8"),
	SBE(ISO8859_9, "iso8859_9"),
	SBE(ISO8859_10, "iso8859_10"),
	SBE(ISO8859_11, "iso8859_11"),
	SBE(ISO8859_13, "iso8859_13"),
	SBE(ISO8859_14, "iso8859_14"),
	SBE(ISO8859_15, "iso8859_15"),
	SBE(ISO8859_16, "iso8859_16"),
	SBE(MAC_ROMAN, "mac_roman"),
	SBE(MAC_CYRILLIC, "mac_cyrillic"),
	SBE(MAC_GREEK, "mac_greek"),
	SBE(MAC_TURKISH, "mac_turkish"),
	SBE(MAC_CENTEURO, "mac_centeuro"),
	SBE(MAC_ICELANDIC, "mac_icelandic"),
	SBE(MAC_CROATIAN, "mac_croatian"),
	SBE(MAC_ROMANIAN, "mac_romanian"),
	SBE(MAC_ARABIC, "mac_arabic"),
	SBE(MAC_HEBREW, "mac_hebrew"),
	SBE(MAC_THAI, "mac_thai"),
	SBE(ADOBE_SYMBOL, "adobe_symbol"),
	SBE(ADOBE_STANDARD, "adobe_standard"),
	SBE(JIS_X0201, "jis_x0201"),
	SBE(KZ1048, "kz1048"),
	SBE(VISCII, "viscii"),
	SBE(HP_ROMAN8, "hp_roman8"),
	SBE(DEC_MCS, "dec_mcs"),
	SBE(ATASCII, "atascii"),
	SBE(PETSCII, "petscii"),
	SBE(PETSCII_SHIFTED, "petscii_shifted"),
	SBE(ASCII, "ascii"),
	SBE(CP864_IBMGRAPH, "cp864_ibmgraph"),
	MBE(MB_SHIFT_JIS, "shift_jis"), MBE(MB_EUC_JP, "euc_jp"), MBE(MB_EUC_KR, "euc_kr"),
	MBE(MB_GB2312, "gb2312"), MBE(MB_GB18030, "gb18030"),
	MBE(MB_SHIFT_JIS_WEB, "shift_jis_web"), MBE(MB_EUC_JP_WEB, "euc_jp_web"),
	MBE(MB_EUC_KR_WEB, "euc_kr_web"), MBE(MB_BIG5_WEB, "big5_web"),
	MBE(MB_GB18030_WEB, "gb18030_web"), MBE(MB_GBK_WEB, "gbk_web"),
	MBE(MB_GSM0338, "gsm0338"), MBE(MB_T61, "t61"),
	MBE(MB_EUC_JP_C1, "euc_jp_c1"), MBE(MB_EUC_KR_C1, "euc_kr_c1"),
	MBE(ISO2022JP, "iso2022jp"), MBE(ISO2022JP_WEB, "iso2022jp_web"),
	[HXE_UTF32LE]   = { "utf32le",   CS, CV_YES, CV_YES, 0, 0 },
	[HXE_UTF32BE]   = { "utf32be",   CS, CV_YES, CV_YES, 0, 0 },
	[HXE_UTF32]     = { "utf32",     CS, CV_YES, CV_YES, 0, 0 },
	[HXE_UTF16]     = { "utf16",     CS, CV_YES, CV_YES, 0, 0 },
	[HXE_CESU8]     = { "cesu8",     CS, CV_YES, CV_YES, 0, 0 },
	[HXE_RAW]       = { "raw",       TX, CV_YES, CV_YES, 0, 0 },
	[HXE_HEX]       = { "hex",       TX, CV_YES, CV_YES, 0, 0 },
	[HXE_BASE64]    = { "base64",    TX, CV_YES, CV_YES, 0, 0 },
	[HXE_BASE64URL] = { "base64url", TX, CV_YES, CV_YES, 0, 0 },
	[HXE_BASE32]    = { "base32",    TX, CV_YES, CV_YES, 0, 0 },
	[HXE_CRYPT64]   = { "crypt64",   TX, CV_YES, CV_YES, 0, 0 },
	[HXE_CRYPT64BE] = { "crypt64be", TX, CV_YES, CV_YES, 0, 0 },
	[HXE_BCRYPT64]  = { "bcrypt64",  TX, CV_YES, CV_YES, 0, 0 },
};
#undef CPE
#undef SBE
#undef MBE

/* Encodings that never pad: the instruction always carries NOPAD for them, so
 * convert(x, "raw", "crypt64be") and the same with "nopad" are one program. */
#define CV_NEVER_PADS(id) ((id) == HXE_CRYPT64 || (id) == HXE_CRYPT64BE || \
                           (id) == HXE_BCRYPT64)
#define CV_IS_U16(id) ((id) == HXE_UTF16LE || (id) == HXE_UTF16BE || (id) == HXE_UTF16)
#define CV_IS_U32(id) ((id) == HXE_UTF32LE || (id) == HXE_UTF32BE || (id) == HXE_UTF32)
/* a target that cannot write a lone surrogate kept under "cesu" */
#define CV_SUR_UNMAP(id) ((id) == HXE_UTF7 || CV_IS_U32(id))
/* A source that can meet a byte it has no character for, and under "keep"
 * passes it on as itself (CV_RAWBYTE): UTF-8 and the standard single-byte
 * tables.  A cpNNN decodes every byte Windows does; its "null" is Windows'
 * strict decode (MB_ERR_INVALID_CHARS), decision D1. */
/* A source that defines every byte can never be ill-formed: latin1, the KOI8
 * tables, and a standard single-byte table with all 256 bytes assigned.  It
 * accepts the ill-formed-source tokens, which do nothing and are dropped, so
 * the instruction is the same with them as without. */
static int cv_never_ill(int id)
{
	int b;
	if (id == HXE_LATIN1 || id == HXE_KOI8R || id == HXE_KOI8U) return 1;
	if (!hxe_reg[id].sb) return 0;
	for (b = 0; b < 256; b++)
		if (!hxt_sb_dec[id - HXE_SB_FIRST][b]) return 0;
	return 1;
}
#define CV_RAWSRC(id) ((id) == HXE_UTF8 || (hxe_reg[id].sb && !cv_never_ill(id)) || \
                       hxe_reg[id].mb || CV_IS_U32(id) || (id) == HXE_CESU8 || (id) == HXE_UTF7)

int hx_conv_lookup(const char *name)
{
	int i;
	if (!name) return HXE_NONE;
	/* GBK and Big5 have no standard of their own: they are Windows' (D6) */
	if (strcmp(name, "gbk") == 0) return HXE_CP936;
	if (strcmp(name, "big5") == 0) return HXE_CP950;
	/* "ebcdic" is not a charset: ebcdic() is not CP37 (section 18.3) */
	for (i = 1; i < HXE_COUNT; i++)
		if (hxe_reg[i].name && strcmp(hxe_reg[i].name, name) == 0) return i;
	return HXE_NONE;
}

const char *hx_conv_name(int id)
{
	return (id > 0 && id < HXE_COUNT && hxe_reg[id].name) ? hxe_reg[id].name : "?";
}

int hx_conv_kind(int id)
{
	return (id > 0 && id < HXE_COUNT) ? hxe_reg[id].kind : 0;
}

/* The generated table of a cpNNN registry entry, or -1. */
static int cv_page(int id)
{
	int i;
	for (i = 0; i < HXT_NCP; i++)
		if (hxt_cpinfo[i].cp == hxe_reg[id].cp) return i;
	return -1;
}

/* The upper_oem table of an OEM code page, or -1. */
static int cv_oem(int cp)
{
	int i;
	for (i = 0; i < HXT_NOEM; i++)
		if (hxt_oem_cp[i] == cp) return i;
	return -1;
}

/* The glyph table of an OEM code page, or -1. */
static int cv_gly(int cp)
{
	int i;
	for (i = 0; i < HXT_NGLY; i++)
		if (hxt_gly_cp[i] == cp) return i;
	return -1;
}

/* ---- tokens ---- */

enum { TG_ILL = 1, TG_SUR, TG_ENC, TG_UNMAP, TG_UC, TG_PAD, TG_LENIENT, TG_GLYPH, TG_PREMAP };

static const char *const tg_name[] = {
	"", "ill-formed-source", "lone-surrogate", "encode", "unmappable",
	"hex-case", "padding", "decode", "glyph", "premap"
};


static const struct { const char *name; uint8_t group; uint16_t bits; } cv_tok[] = {
	{ "keep",   TG_ILL,   HXCV_ILL_KEEP },
	{ "null",   TG_ILL,   HXCV_ILL_NULL },
	{ "latin1", TG_ILL,   HXCV_ILL_LATIN1 },
	{ "fffd",   TG_ILL,   HXCV_ILL_FFFD },    /* TG_SUR for a utf16 source */
	{ "q",      TG_SUR,   HXCV_SUR_Q },
	{ "cesu",   TG_SUR,   HXCV_SUR_CESU },
	{ "strict", TG_ENC,   0 },
	{ "bestfit",TG_ENC,   HXCV_BESTFIT },
	{ "default",TG_UNMAP, 0 },
	{ "fail",   TG_UNMAP, HXCV_FAIL },
	{ "uc",     TG_UC,    HXCV_UC },
	{ "nopad",  TG_PAD,   HXCV_NOPAD },
	{ "lenient",TG_LENIENT, HXCV_LENIENT },
	{ "glyphs", TG_GLYPH, HXCV_GLYPHS },
	/* premaps: bits holds the HXPM_* id */
	{ "lower",     TG_PREMAP, HXPM_LOWER },
	{ "upper",     TG_PREMAP, HXPM_UPPER },
	{ "rev",       TG_PREMAP, HXPM_REV },
	{ "rot13",     TG_PREMAP, HXPM_ROT13 },
	{ "lower_win", TG_PREMAP, HXPM_LOWER_WIN },
	{ "upper_win", TG_PREMAP, HXPM_UPPER_WIN },
	{ "upper_oem", TG_PREMAP, HXPM_UPPER_OEM },
	{ "lower_full", TG_PREMAP, HXPM_LOWER_FULL },
	{ "upper_full", TG_PREMAP, HXPM_UPPER_FULL },
	{ "nfc",       TG_PREMAP, HXPM_NFC },
	{ "nfd",       TG_PREMAP, HXPM_NFD },
	{ "nfkc",      TG_PREMAP, HXPM_NFKC },
	{ "nfkd",      TG_PREMAP, HXPM_NFKD },
	{ "nfd_hfs",   TG_PREMAP, HXPM_NFD_HFS },
	{ NULL, 0, 0 }
};

static const char *const pm_name[] = {
	"none", "lower", "upper", "rev", "rot13", "lower_win", "upper_win", "upper_oem",
	"lower_full", "upper_full", "nfc", "nfd", "nfkc", "nfkd", "nfd_hfs"
};

int hx_convert_build(const char *from, const char *to,
                     const char *const *tokens, int ntokens,
                     hx_inst *ip, char *err, int errcap)
{
	int f = hx_conv_lookup(from), t = hx_conv_lookup(to), i, k;
	const char *seen[TG_PREMAP + 1] = { 0 };
	uint16_t policy = 0;
	uint8_t premap = HXPM_NONE;
	int unmap_possible;

	memset(ip, 0, sizeof *ip);
	if (!f) { snprintf(err, errcap, "convert(): unknown encoding '%s'", from); return -1; }
	if (!t) { snprintf(err, errcap, "convert(): unknown encoding '%s'", to); return -1; }
	if (hxe_reg[f].kind != hxe_reg[t].kind) {
		snprintf(err, errcap, "convert(): '%s' is a %s and '%s' a %s; nest two "
		         "convert() calls instead of mixing them", from,
		         hxe_reg[f].kind == HXE_KIND_CHARSET ? "charset" : "transfer encoding",
		         to, hxe_reg[t].kind == HXE_KIND_CHARSET ? "charset" : "transfer encoding");
		return -1;
	}
	if (hxe_reg[f].dec == CV_NO) {
		snprintf(err, errcap, "convert(): '%s' is encode-only and cannot be a source", from);
		return -1;
	}
	if (hxe_reg[f].dec == CV_LATER) {
		snprintf(err, errcap, "convert(): not yet implemented: decoding from '%s'", from);
		return -1;
	}
	if (hxe_reg[t].enc == CV_LATER) {
		snprintf(err, errcap, "convert(): not yet implemented: encoding to '%s'", to);
		return -1;
	}
	if ((hxe_reg[f].cp && cv_page(f) < 0) || (hxe_reg[t].cp && cv_page(t) < 0)) {
		snprintf(err, errcap, "convert(): no table for '%s'",
		         hxe_reg[f].cp && cv_page(f) < 0 ? from : to);
		return -1;
	}
	for (i = 0; i < ntokens; i++) {
		const char *tok = tokens[i];
		int g, ok;
		for (k = 0; cv_tok[k].name; k++)
			if (strcmp(cv_tok[k].name, tok) == 0) break;
		if (!cv_tok[k].name) {
			snprintf(err, errcap, "convert(): unknown token '%s'", tok);
			return -1;
		}
		g = cv_tok[k].group;
		if (g == TG_ILL && strcmp(tok, "fffd") == 0 && CV_IS_U16(f))
			g = TG_SUR;
		if (seen[g]) {
			snprintf(err, errcap, "convert(): '%s' and '%s' are both %s tokens",
			         seen[g], tok, tg_name[g]);
			return -1;
		}
		seen[g] = tok;
		switch (g) {
		case TG_ILL:     ok = CV_RAWSRC(f) || cv_never_ill(f) ||
		                      (hxe_reg[f].cp && (cv_tok[k].bits == HXCV_ILL_KEEP ||
		                                         cv_tok[k].bits == HXCV_ILL_NULL)); break;
		case TG_SUR:     ok = CV_IS_U16(f); break;
		case TG_ENC:     ok = hxe_reg[t].cp != 0; break;
		/* fail applies where the pair can meet something unmappable: a
		 * target with unmappable code points; a kept ill-formed unit
		 * (CV_RAWSRC) in any target but utf8, which writes it unchanged; a
		 * lone surrogate kept under "cesu" in utf7 or utf32, which cannot
		 * hold one.  Elsewhere it is an error.  A pair that can meet one,
		 * but not under the other tokens given ("null", or the default
		 * "fffd" for the surrogate), accepts it and drops it below. */
		case TG_UNMAP:   ok = hxe_reg[t].unmap || (CV_RAWSRC(f) && t != HXE_UTF8) ||
		                      (CV_IS_U16(f) && CV_SUR_UNMAP(t)); break;
		case TG_UC:      ok = t == HXE_HEX; break;
		case TG_PAD:     ok = t == HXE_BASE64 || t == HXE_BASE64URL ||
		                      t == HXE_BASE32 || CV_NEVER_PADS(t); break;
		case TG_LENIENT: ok = f == HXE_HEX || f == HXE_BASE64; break;
		case TG_GLYPH:   ok = hxe_reg[f].cp && cv_gly(hxe_reg[f].cp) >= 0; break;
		case TG_PREMAP:
			if (hxe_reg[f].kind == HXE_KIND_TRANSFER)
				ok = cv_tok[k].bits == HXPM_LOWER || cv_tok[k].bits == HXPM_UPPER ||
				     cv_tok[k].bits == HXPM_REV || cv_tok[k].bits == HXPM_ROT13;
			else if (cv_tok[k].bits == HXPM_UPPER_OEM)
				ok = hxe_reg[t].cp && cv_oem(hxe_reg[t].cp) >= 0;
			else
				ok = 1;
			break;
		default:         ok = 0; break;
		}
		if (!ok) {
			snprintf(err, errcap, "convert(): token '%s' does not apply to "
			         "%s -> %s", tok, from, to);
			return -1;
		}
		if (g == TG_PREMAP)
			premap = (uint8_t)cv_tok[k].bits;
		else if (g == TG_SUR) {
			if (strcmp(tok, "fffd") != 0) policy |= cv_tok[k].bits;
		} else
			policy |= cv_tok[k].bits;
	}
	if (premap == HXPM_UPPER_OEM && !(policy & HXCV_BESTFIT)) {
		snprintf(err, errcap, "convert(): premap 'upper_oem' is Windows' best-fit "
		         "OEM conversion; give \"bestfit\" with it");
		return -1;
	}
	if (CV_NEVER_PADS(t)) policy |= HXCV_NOPAD;
	if (cv_never_ill(f)) policy &= ~HXCV_ILL_MASK;   /* nothing for them to do */
	/* A code point is unmappable only in latin1, koi8 and cpNNN, an ill-formed
	 * byte kept under "keep" only outside UTF-8, and a lone surrogate kept
	 * under "cesu" only in UTF-7.  Where none can occur "fail" changes
	 * nothing, so it is dropped: then convert(x, "utf8", "utf16le", "null",
	 * "fail") is utf16le(x). */
	unmap_possible = hxe_reg[t].unmap ||
	    (CV_RAWSRC(f) && (policy & HXCV_ILL_MASK) == HXCV_ILL_KEEP && t != HXE_UTF8) ||
	    (CV_IS_U16(f) && (policy & HXCV_SUR_MASK) == HXCV_SUR_CESU && CV_SUR_UNMAP(t));
	if (!unmap_possible) policy &= ~HXCV_FAIL;
	ip->op = OP_CONVERT;
	ip->u.conv.from = (uint8_t)f;
	ip->u.conv.to = (uint8_t)t;
	ip->u.conv.premap = premap;
	ip->u.conv.policy = policy;
	return 0;
}

/* ---- aliases: sections 18.3a, 18.5a and 18.6 ----
 * legacy = 1: the instruction stands for an existing function, whose OP_CALL
 * identity the stable shared id keeps.  The first legacy row matching an
 * instruction names it, so cp1252_to_utf8 hashes as from_cp1252.
 * cpNNN_to_utf8, utf8_to_cpNNN and utf8_to_cpNNN_bestfit are recognised by
 * pattern in hx_convert_alias_inst, for every cpNNN in the registry.
 *
 * NOT aliased:
 *   ebcdic      its table is not CP37: 99 of 256 bytes differ from Windows
 *               CP37 (0x5B 0x5D 0x5E among them) and 0x7E and 0xE5 both give
 *               0xA1, so it is not a code page at all;
 *   hex_bin     the identity, not an encoding.
 * fromhex and frombase64 are the "lenient" decoders: exactly the decoding they
 * always did, which the strict hex and base64 decoders (null on anything an
 * encoder cannot produce) are not. */
static const struct {
	const char *name; uint8_t from, to; uint16_t policy; uint8_t premap, legacy;
} cv_alias[] = {
	{ "utf16le",        HXE_UTF8,   HXE_UTF16LE,   HXCV_ILL_NULL, 0, 1 },
	{ "utf16be",        HXE_UTF8,   HXE_UTF16BE,   HXCV_ILL_NULL, 0, 1 },
	{ "utf7",           HXE_UTF8,   HXE_UTF7,      HXCV_ILL_NULL, 0, 1 },
	{ "zext16",         HXE_LATIN1, HXE_UTF16LE,   0,             0, 1 },
	{ "from_cp1252",    HXE_CP1252, HXE_UTF8,      0,             0, 1 },
	{ "cp1252_to_utf8", HXE_CP1252, HXE_UTF8,      0,             0, 0 },
	{ "from_cp1251",    HXE_CP1251, HXE_UTF8,      0,             0, 1 },
	{ "cp1251_to_utf8", HXE_CP1251, HXE_UTF8,      0,             0, 0 },
	{ "latin1_to_utf8", HXE_LATIN1, HXE_UTF8,      0,             0, 0 },
	{ "utf8_to_latin1", HXE_UTF8,   HXE_LATIN1,    0,             0, 0 },
	{ "hex",            HXE_RAW,    HXE_HEX,       0,             0, 1 },
	{ "base64",         HXE_RAW,    HXE_BASE64,    0,             0, 1 },
	{ "phpass_encode",  HXE_RAW,    HXE_CRYPT64,   HXCV_NOPAD,    0, 1 },
	{ "cisco4_encode",  HXE_RAW,    HXE_CRYPT64BE, HXCV_NOPAD,    0, 1 },
	{ "fromhex",        HXE_HEX,    HXE_RAW,       HXCV_LENIENT,  0, 1 },
	{ "frombase64",     HXE_BASE64, HXE_RAW,       HXCV_LENIENT,  0, 1 },
	{ "upper",          HXE_RAW,    HXE_RAW,       0, HXPM_UPPER,    1 },
	{ "lower",          HXE_RAW,    HXE_RAW,       0, HXPM_LOWER,    1 },
	{ "rev",            HXE_RAW,    HXE_RAW,       0, HXPM_REV,      1 },
	{ "rot13",          HXE_RAW,    HXE_RAW,       0, HXPM_ROT13,    1 },
	{ "koi8r_to_utf8",  HXE_KOI8R,  HXE_UTF8,      0,             0, 0 },
	{ "utf8_to_koi8r",  HXE_UTF8,   HXE_KOI8R,     0,             0, 0 },
	{ "koi8u_to_utf8",  HXE_KOI8U,  HXE_UTF8,      0,             0, 0 },
	{ "utf8_to_koi8u",  HXE_UTF8,   HXE_KOI8U,     0,             0, 0 },
	{ "from_utf16le",      HXE_UTF16LE, HXE_UTF8,  0,             0, 0 },
	{ "from_utf16be",      HXE_UTF16BE, HXE_UTF8,  0,             0, 0 },
	{ "from_utf16le_q",    HXE_UTF16LE, HXE_UTF8,  HXCV_SUR_Q,    0, 0 },
	{ "from_utf16be_q",    HXE_UTF16BE, HXE_UTF8,  HXCV_SUR_Q,    0, 0 },
	{ "from_utf16le_cesu", HXE_UTF16LE, HXE_UTF8,  HXCV_SUR_CESU, 0, 0 },
	{ "from_utf16be_cesu", HXE_UTF16BE, HXE_UTF8,  HXCV_SUR_CESU, 0, 0 },
	{ "ulower",         HXE_UTF8,   HXE_UTF8,      0, HXPM_LOWER,     0 },
	{ "uupper",         HXE_UTF8,   HXE_UTF8,      0, HXPM_UPPER,     0 },
	{ "ulower_win",     HXE_UTF8,   HXE_UTF8,      0, HXPM_LOWER_WIN, 0 },
	{ "uupper_win",     HXE_UTF8,   HXE_UTF8,      0, HXPM_UPPER_WIN, 0 },
	{ "urev",           HXE_UTF8,   HXE_UTF8,      0, HXPM_REV,       0 },
	{ "ulower_full",    HXE_UTF8,   HXE_UTF8,      0, HXPM_LOWER_FULL, 0 },
	{ "uupper_full",    HXE_UTF8,   HXE_UTF8,      0, HXPM_UPPER_FULL, 0 },
	{ "nfc",            HXE_UTF8,   HXE_UTF8,      0, HXPM_NFC,       0 },
	{ "nfd",            HXE_UTF8,   HXE_UTF8,      0, HXPM_NFD,       0 },
	{ "nfkc",           HXE_UTF8,   HXE_UTF8,      0, HXPM_NFKC,      0 },
	{ "nfkd",           HXE_UTF8,   HXE_UTF8,      0, HXPM_NFKD,      0 },
	{ "nfd_hfs",        HXE_UTF8,   HXE_UTF8,      0, HXPM_NFD_HFS,   0 },
	{ "utf16_lowbyte",  HXE_UTF8,   HXE_LOWBYTE16, 0,             0, 0 },
	{ NULL, 0, 0, 0, 0, 0 }
};

static void cv_set(hx_inst *ip, int from, int to, uint16_t policy, int premap)
{
	memset(ip, 0, sizeof *ip);
	ip->op = OP_CONVERT;
	ip->u.conv.from = (uint8_t)from;
	ip->u.conv.to = (uint8_t)to;
	ip->u.conv.policy = policy;
	ip->u.conv.premap = (uint8_t)premap;
}

int hx_convert_alias_inst(const char *name, hx_inst *ip)
{
	char cs[16], back[48];
	unsigned n;
	int i, id;
	for (i = 0; cv_alias[i].name; i++)
		if (strcmp(cv_alias[i].name, name) == 0) {
			cv_set(ip, cv_alias[i].from, cv_alias[i].to, cv_alias[i].policy,
			       cv_alias[i].premap);
			return 1;
		}
	/* cpNNN_to_utf8, utf8_to_cpNNN, utf8_to_cpNNN_bestfit: the name must be
	 * exactly what the pattern prints back, so cp01252_to_utf8 is not one */
	if (sscanf(name, "cp%u_to_utf8", &n) == 1) {
		snprintf(back, sizeof back, "cp%u_to_utf8", n);
		snprintf(cs, sizeof cs, "cp%u", n);
		if (strcmp(back, name) == 0 && (id = hx_conv_lookup(cs)) && hxe_reg[id].cp) {
			cv_set(ip, id, HXE_UTF8, 0, HXPM_NONE);
			return 1;
		}
	}
	if (sscanf(name, "utf8_to_cp%u", &n) == 1) {
		snprintf(cs, sizeof cs, "cp%u", n);
		if (!(id = hx_conv_lookup(cs)) || !hxe_reg[id].cp) return 0;
		snprintf(back, sizeof back, "utf8_to_cp%u", n);
		if (strcmp(back, name) == 0) { cv_set(ip, HXE_UTF8, id, 0, HXPM_NONE); return 1; }
		snprintf(back, sizeof back, "utf8_to_cp%u_bestfit", n);
		if (strcmp(back, name) == 0) { cv_set(ip, HXE_UTF8, id, HXCV_BESTFIT, HXPM_NONE); return 1; }
	}
	return 0;
}

const char *hx_convert_legacy_name(const hx_inst *ip)
{
	int i;
	if (ip->op != OP_CONVERT) return NULL;
	for (i = 0; cv_alias[i].name; i++)
		if (cv_alias[i].legacy && cv_alias[i].from == ip->u.conv.from &&
		    cv_alias[i].to == ip->u.conv.to &&
		    cv_alias[i].policy == ip->u.conv.policy &&
		    cv_alias[i].premap == ip->u.conv.premap)
			return cv_alias[i].name;
	return NULL;
}

/* ---- fusion (section 18.7) ----
 * A -> B then B -> C is one A -> C exactly when the first instruction's
 * output is always the code-point sequence (or byte string) the second one
 * decodes, unchanged, and at most one of them has a premap:
 *   charsets: B is utf8, utf16le or utf16be, and the first cannot leave an
 *     ill-formed byte (a utf8 source under "keep") or a lone surrogate (a
 *     utf16 source under "cesu") in its output; it has no "fail" (nothing in
 *     it can be unmappable, so build dropped any); the second has no
 *     lone-surrogate token ("cesu" also changes how it writes NUL).  Then
 *     the second's ill-formed and surrogate policies never apply, and the
 *     fused instruction takes the first's source policy and the second's
 *     encode and unmappable policy.
 *   transfer encodings: B is raw (identity both ways), or hex (the strict
 *     and lenient hex decoders both read every hex encoder output exactly),
 *     and the result takes the first's decode policy and the second's
 *     encode policy; or the first ends in hex and the second is a byte
 *     upper/lower on raw, which is the "uc" form or the plain one (18.5a).
 * An encode followed by a decode (utf8 -> cpNNN -> utf8) never qualifies. */
static int cv_canon(hx_inst *ip)
{
	int f = ip->u.conv.from, t = ip->u.conv.to;
	uint16_t *p = &ip->u.conv.policy;
	if (CV_NEVER_PADS(t)) *p |= HXCV_NOPAD;
	if (t != HXE_BASE64 && t != HXE_BASE64URL && t != HXE_BASE32 && !CV_NEVER_PADS(t))
		*p &= ~HXCV_NOPAD;
	if (t != HXE_HEX) *p &= ~HXCV_UC;
	if (cv_never_ill(f)) *p &= ~HXCV_ILL_MASK;
	if (!(hxe_reg[t].unmap ||
	      (CV_RAWSRC(f) && (*p & HXCV_ILL_MASK) == HXCV_ILL_KEEP && t != HXE_UTF8) ||
	      (CV_IS_U16(f) && (*p & HXCV_SUR_MASK) == HXCV_SUR_CESU && CV_SUR_UNMAP(t))))
		*p &= ~HXCV_FAIL;
	return 1;
}

static int cv_fuse2(const hx_inst *a, const hx_inst *b, hx_inst *o)
{
	int af = a->u.conv.from, at = a->u.conv.to, bf = b->u.conv.from, bt = b->u.conv.to;
	int pa = a->u.conv.premap, pb = b->u.conv.premap;
	uint16_t qa = a->u.conv.policy, qb = b->u.conv.policy;

	if (hxe_reg[af].kind == HXE_KIND_TRANSFER) {
		if (hxe_reg[bf].kind != HXE_KIND_TRANSFER) return 0;
		if (at == HXE_HEX && bf == HXE_RAW && bt == HXE_RAW && qb == 0 &&
		    (pb == HXPM_UPPER || pb == HXPM_LOWER)) {
			*o = *a;
			o->u.conv.policy = pb == HXPM_UPPER ? qa | HXCV_UC : qa & ~HXCV_UC;
			return 1;
		}
		if (pa && pb) return 0;
		if (!((at == HXE_RAW && bf == HXE_RAW) || (at == HXE_HEX && bf == HXE_HEX)))
			return 0;
		cv_set(o, af, bt, (qa & HXCV_LENIENT) | (qb & (HXCV_UC | HXCV_NOPAD)), pa ? pa : pb);
		return cv_canon(o);
	}
	if (pa && pb) return 0;
	if (bf != at || !(at == HXE_UTF8 || CV_IS_U16(at))) return 0;
	if (CV_RAWSRC(af) && (qa & HXCV_ILL_MASK) == HXCV_ILL_KEEP) return 0;
	if (CV_IS_U16(af) && (qa & HXCV_SUR_MASK) == HXCV_SUR_CESU) return 0;
	if ((qa & HXCV_FAIL) || (qb & HXCV_SUR_MASK)) return 0;
	cv_set(o, af, bt, (qa & (HXCV_ILL_MASK | HXCV_SUR_MASK | HXCV_GLYPHS)) |
	       (qb & (HXCV_BESTFIT | HXCV_FAIL)),
	       pa ? pa : pb);
	return cv_canon(o);
}

static int cv_is_jump(int op)
{
	return op == OP_JUMP || op == OP_JUMP_LE || op == OP_JUMP_LT || op == OP_JUMP_GT ||
	       op == OP_JUMP_GE || op == OP_JUMP_EQ || op == OP_JUMP_NE;
}

int hx_convert_fuse(hx_inst *code, const char **names, int n)
{
	int i, k;
	for (i = 0; i + 1 < n; ) {
		hx_inst f;
		int target = 0;
		if (code[i].op != OP_CONVERT || code[i + 1].op != OP_CONVERT ||
		    !cv_fuse2(&code[i], &code[i + 1], &f)) { i++; continue; }
		for (k = 0; k < n; k++)
			if (cv_is_jump(code[k].op) && code[k].u.addr == i + 1) target = 1;
		if (target) { i++; continue; }
		code[i] = f;
		memmove(code + i + 1, code + i + 2, (n - i - 2) * sizeof *code);
		if (names) memmove(names + i + 1, names + i + 2, (n - i - 2) * sizeof *names);
		n--;
		for (k = 0; k < n; k++)
			if (cv_is_jump(code[k].op) && code[k].u.addr > i + 1) code[k].u.addr--;
		/* stay on i: the fused instruction may fuse with the next */
	}
	return n;
}

void hx_convert_describe(const hx_inst *ip, char *buf, int cap)
{
	static const char *ill[] = { NULL, "null", "latin1", "fffd" };
	static const char *sur[] = { NULL, "q", "cesu", NULL };
	const char *tok[8];
	int n = 0, i, o;
	uint16_t p = ip->u.conv.policy;
	uint8_t pm = ip->u.conv.premap;

	if (ill[p & HXCV_ILL_MASK]) tok[n++] = ill[p & HXCV_ILL_MASK];
	if (sur[(p & HXCV_SUR_MASK) >> 2]) tok[n++] = sur[(p & HXCV_SUR_MASK) >> 2];
	if (p & HXCV_BESTFIT) tok[n++] = "bestfit";
	if (p & HXCV_FAIL)    tok[n++] = "fail";
	if (p & HXCV_UC)      tok[n++] = "uc";
	if (p & HXCV_NOPAD)   tok[n++] = "nopad";
	if (p & HXCV_LENIENT) tok[n++] = "lenient";
	if (p & HXCV_GLYPHS)  tok[n++] = "glyphs";
	o = snprintf(buf, cap, "%s->%s [", hx_conv_name(ip->u.conv.from),
	             hx_conv_name(ip->u.conv.to));
	for (i = 0; i < n && o < cap; i++)
		o += snprintf(buf + o, cap - o, "%s%s", i ? "," : "", tok[i]);
	if (o < cap)
		snprintf(buf + o, cap - o, "] premap=%s",
		         pm < sizeof pm_name / sizeof pm_name[0] ? pm_name[pm] : "?");
}

/* ---- the engine ---- */

#define CV_RAWBYTE 0x80000000u   /* an ill-formed byte kept as itself */

static void cv_null(hx_val *out, hx_arena *arena)
{
	out->data = hx_arena_alloc(arena, 1);
	out->data[0] = '\0';
	out->len = 0;
}

/* Section 3: the length of the well-formed UTF-8 sequence at in[i], storing
 * its code point, or 0 when the byte there is a character on its own.
 * Whether a sequence is well-formed is utf8_to_utf32's decision. */
static int cv_utf8_at(const unsigned char *in, int i, int len, uint32_t *cp)
{
	unsigned char c = in[i];
	int sl = c < 0x80 ? 1 : (c >= 0xc2 && c <= 0xdf) ? 2 :
	         (c >= 0xe0 && c <= 0xef) ? 3 :
	         (c >= 0xf0 && c <= 0xf4) ? 4 : 0;
	if (sl == 1) { *cp = c; return 1; }
	if (sl && i + sl <= len && utf8_to_utf32(in + i, sl, cp, 1) == 1) return sl;
	return 0;
}

/* One code point as UTF-8, surrogates included (only "cesu" produces them). */
static int cv_put_utf8(uint32_t c, unsigned char *b)
{
	if (c < 0x80) { b[0] = (unsigned char)c; return 1; }
	if (c < 0x800) { b[0] = 0xc0 | (c >> 6); b[1] = 0x80 | (c & 0x3f); return 2; }
	if (c < 0x10000) { b[0] = 0xe0 | (c >> 12); b[1] = 0x80 | ((c >> 6) & 0x3f);
	                   b[2] = 0x80 | (c & 0x3f); return 3; }
	b[0] = 0xf0 | (c >> 18); b[1] = 0x80 | ((c >> 12) & 0x3f);
	b[2] = 0x80 | ((c >> 6) & 0x3f); b[3] = 0x80 | (c & 0x3f);
	return 4;
}

/* ---- multi-byte charsets (phase 4b step 3) ----
 * Tables from hx_conv_tables.h: a byte is a character (hxt_mb_d1), the lead
 * of a pair (hxt_mb_lead -> a row of hxt_mb_rows), or, for euc_jp's 0x8F, the
 * first of three (hxt_mb_lead3 on the second byte).  GB18030's four-byte
 * codes are the WHATWG algorithm (encoding.bs "index gb18030 ranges"), with
 * the 2022 edition's 18 four-byte PUA codes for "gb18030".
 *
 * An error follows the Encoding Standard: a lead whose next byte is not
 * ASCII and makes no character consumes both bytes; when the next byte is
 * ASCII, the lead alone is the error and the next byte is read again.  One
 * error is one ill-formed unit under the source tokens: under "keep" each of
 * its bytes is kept, under "latin1" each byte is its U+00xx, under "fffd" the
 * error is one U+FFFD. */
#define CV_MB_GB(m)  ((m) == HXE_MB_GB18030 - HXE_MB_FIRST ? 1 : \
                      ((m) == HXE_MB_GB18030_WEB - HXE_MB_FIRST || \
                       (m) == HXE_MB_GBK_WEB - HXE_MB_FIRST) ? 2 : 0)

static int64_t cv_gb4_cp(uint32_t p, int std)
{
	int lo = 0, hi = HXT_NGBR - 1, k;
	if ((p > 39419 && p < 189000) || p > 1237575) return -1;
	if (p >= 189000) return 0x10000 + p - 189000;
	if (p == 7457) return 0xe7c7;
	if (std)
		for (k = 0; k < 18; k++)
			if (hxt_gb4_std[k][0] == p) return hxt_gb4_std[k][1];
	while (lo < hi) {                 /* last range pointer <= p */
		int m = (lo + hi + 1) / 2;
		if (hxt_gb_ranges[m][0] <= p) lo = m; else hi = m - 1;
	}
	return hxt_gb_ranges[lo][1] + p - hxt_gb_ranges[lo][0];
}

static int64_t cv_gb4_ptr(uint32_t c, int std)
{
	int lo = 0, hi = HXT_NGBR - 1, k;
	if (c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) return -1;
	if (c >= 0x10000) return 189000 + c - 0x10000;
	if (c == 0xe7c7) return 7457;
	if (std)
		for (k = 0; k < 18; k++)
			if (hxt_gb4_std[k][1] == c) return hxt_gb4_std[k][0];
	while (lo < hi) {                 /* last range code point <= c */
		int m = (lo + hi + 1) / 2;
		if (hxt_gb_ranges[m][1] <= c) lo = m; else hi = m - 1;
	}
	return hxt_gb_ranges[lo][0] + c - hxt_gb_ranges[lo][1];
}

/* One error of k bytes at in[i]; returns the new n, or -1 for a null result. */
static int cv_mb_err(uint16_t policy, const unsigned char *in, int i, int k,
                     uint32_t *cp, int n)
{
	int j;
	switch (policy & HXCV_ILL_MASK) {
	case HXCV_ILL_NULL:   return -1;
	case HXCV_ILL_FFFD:   cp[n++] = 0xfffd; return n;
	case HXCV_ILL_LATIN1: for (j = 0; j < k; j++) cp[n++] = in[i + j]; return n;
	default:              for (j = 0; j < k; j++) cp[n++] = CV_RAWBYTE | in[i + j]; return n;
	}
}

static int cv_mb_put(uint32_t v, uint32_t *cp, int n)
{
	if ((v & 0xffff0000u) == 0xffff0000u) {
		cp[n++] = hxt_mb_pairs[v & 0xffff][0];
		cp[n++] = hxt_mb_pairs[v & 0xffff][1];
	} else
		cp[n++] = v;
	return n;
}

static int cv_mb_dec(int m, uint16_t policy, const unsigned char *in, int len, uint32_t *cp)
{
	int i = 0, n = 0, gb = CV_MB_GB(m), p3 = hxt_mb_p3[m], k;
	uint32_t v;
	/* a plain block, not do { } while (0): its continue is the loop's */
#define MBERR(nb) { k = (nb); if ((n = cv_mb_err(policy, in, i, k, cp, n)) < 0) return -1; \
                    i += k; continue; }
	while (i < len) {
		unsigned b = in[i];
		int row;
		if (gb && b >= 0x81 && b <= 0xfe && i + 1 < len && in[i + 1] >= 0x30 && in[i + 1] <= 0x39) {
			if (i + 3 < len && in[i + 2] >= 0x81 && in[i + 2] <= 0xfe &&
			    in[i + 3] >= 0x30 && in[i + 3] <= 0x39) {
				uint32_t p = (((b - 0x81) * 10 + in[i + 1] - 0x30) * 126 + in[i + 2] - 0x81) * 10 +
				             in[i + 3] - 0x30;
				int64_t c = cv_gb4_cp(p, gb == 1);
				if (c >= 0) { cp[n++] = (uint32_t)c; i += 4; continue; }
				MBERR(4);
			}
			/* the input ends inside the four-byte code: one error for the
			 * rest; otherwise the bytes after the lead are read again */
			if (i + 2 >= len || (i + 3 >= len && in[i + 2] >= 0x81 && in[i + 2] <= 0xfe))
				MBERR(len - i);
			MBERR(1);
		}
		if (p3 && b == (unsigned)p3) {
			row = i + 1 < len ? hxt_mb_lead3[m][in[i + 1]] : -1;
			if (row >= 0) {
				if (i + 2 < len && (v = hxt_mb_rows[row][in[i + 2]]) != HXT_MB_NONE) {
					n = cv_mb_put(v, cp, n);
					i += 3;
					continue;
				}
				MBERR(i + 2 < len && in[i + 2] >= 0x80 ? 3 : 2);
			}
			MBERR(i + 1 < len && in[i + 1] >= 0x80 ? 2 : 1);
		}
		if ((row = hxt_mb_lead[m][b]) >= 0) {
			if (i + 1 < len && (v = hxt_mb_rows[row][in[i + 1]]) != HXT_MB_NONE) {
				n = cv_mb_put(v, cp, n);
				i += 2;
				continue;
			}
			MBERR(i + 1 < len && in[i + 1] >= 0x80 ? 2 : 1);
		}
		if ((v = hxt_mb_d1[m][b]) != HXT_MB_NONE) { n = cv_mb_put(v, cp, n); i++; continue; }
		MBERR(1);
	}
#undef MBERR
	return n;
}

/* The bytes of one code point in multi-byte table m, or 0 when it has none. */
static int cv_mb_enc1(int m, uint32_t c, unsigned char *b)
{
	int lo = hxt_mb_start[m], hi = hxt_mb_start[m + 1] - 1, gb = CV_MB_GB(m), k;
	if (c & CV_RAWBYTE) return 0;
	while (lo <= hi) {
		int mid = (lo + hi) / 2;
		if (hxt_mb_enc[mid].c == c) {
			for (k = 0; k < hxt_mb_enc[mid].n; k++)
				b[k] = (unsigned char)(hxt_mb_enc[mid].code >> (8 * (hxt_mb_enc[mid].n - 1 - k)));
			return hxt_mb_enc[mid].n;
		}
		if (hxt_mb_enc[mid].c < c) lo = mid + 1; else hi = mid - 1;
	}
	/* four-byte GB 18030; gbk has none; WHATWG never encodes U+E5E5 */
	if (gb && m != HXE_MB_GBK_WEB - HXE_MB_FIRST && !(gb == 2 && c == 0xe5e5)) {
		int64_t p = cv_gb4_ptr(c, gb == 1);
		if (p < 0) return 0;
		b[3] = (unsigned char)(0x30 + p % 10); p /= 10;
		b[2] = (unsigned char)(0x81 + p % 126); p /= 126;
		b[1] = (unsigned char)(0x30 + p % 10); p /= 10;
		b[0] = (unsigned char)(0x81 + p);
		return 4;
	}
	return 0;
}

/* ISO-2022-JP.  web: the Encoding Standard decoder, state for state (the
 * katakana escape, and an escape directly after an escape is an error).
 * Not web: RFC 1468 -- ESC ( B, ESC ( J, ESC $ @ and ESC $ B only, and the
 * text must end in ASCII.  JIS X 0208 is the euc_jp table of the same
 * reading.  An error is one ill-formed unit of the bytes it consumed. */
static int cv_iso2022jp_dec(int web, uint16_t policy, const unsigned char *in, int len,
                            uint32_t *cp)
{
	enum { ASC, ROMAN, KATA, LEAD, TRAIL, ESC0, ESC1 };
	int m = (web ? HXE_MB_EUC_JP_WEB : HXE_MB_EUC_JP) - HXE_MB_FIRST;
	int st = ASC, ost = ASC, out = 0, n = 0, i = 0, k, e0 = 0;
	unsigned lead = 0;
#define JERR(at, nb) do { if ((n = cv_mb_err(policy, in, (at), (nb), cp, n)) < 0) return -1; } while (0)
	for (;;) {
		int eoq = i >= len;
		unsigned b = eoq ? 0 : in[i];
		switch (st) {
		case ASC: case ROMAN: case KATA: case LEAD:
			if (eoq) goto end;
			if (b == 0x1b) { e0 = i; st = ESC0; i++; continue; }
			out = 0;
			if (st == LEAD) {
				if (b >= 0x21 && b <= 0x7e) { lead = b; st = TRAIL; i++; continue; }
			} else if (st == KATA) {
				if (b >= 0x21 && b <= 0x5f) { cp[n++] = 0xff61 - 0x21 + b; i++; continue; }
			} else if (b <= 0x7f && b != 0x0e && b != 0x0f) {
				cp[n++] = st == ROMAN && b == 0x5c ? 0xa5 : st == ROMAN && b == 0x7e ? 0x203e : b;
				i++;
				continue;
			}
			JERR(i, 1); i++;
			continue;
		case TRAIL:
			if (eoq) { st = LEAD; JERR(i - 1, 1); goto end; }
			if (b == 0x1b) { JERR(i - 1, 1); e0 = i; st = ESC0; i++; continue; }
			st = LEAD;
			if (b >= 0x21 && b <= 0x7e) {
				int row = hxt_mb_lead[m][lead | 0x80];
				uint32_t v = row >= 0 ? hxt_mb_rows[row][b | 0x80] : HXT_MB_NONE;
				if (v != HXT_MB_NONE) { n = cv_mb_put(v, cp, n); i++; continue; }
			}
			JERR(i - 1, 2); i++;
			continue;
		case ESC0:
			if (!eoq && (b == 0x24 || b == 0x28)) { lead = b; st = ESC1; i++; continue; }
			out = 0; st = ost;
			JERR(e0, 1);       /* the ESC; the byte after it is read again */
			continue;
		case ESC1: {
			int ns = -1;
			if (!eoq) {
				if (lead == 0x28 && b == 0x42) ns = ASC;
				else if (lead == 0x28 && b == 0x4a) ns = ROMAN;
				else if (lead == 0x28 && b == 0x49 && web) ns = KATA;
				else if (lead == 0x24 && (b == 0x40 || b == 0x42)) ns = LEAD;
			}
			if (ns >= 0) {
				int was = out;
				st = ost = ns;
				i++;
				if (web) { out = 1; if (was) JERR(e0, 3); }
				continue;
			}
			out = 0; st = ost;
			JERR(e0, 1);       /* the ESC; the two bytes after it are read again */
			i = e0 + 1;
			continue;
		}
		}
	}
end:
	if (!web && st != ASC) {           /* RFC 1468: the text ends in ASCII */
		if ((policy & HXCV_ILL_MASK) == HXCV_ILL_NULL) return -1;
		if ((policy & HXCV_ILL_MASK) == HXCV_ILL_FFFD) cp[n++] = 0xfffd;
	}
	(void)k;
#undef JERR
	return n;
}

/* ---- the remaining Unicode forms (phase 4b step 4) ----
 * An ill-formed unit (cv_mb_err) is: a UTF-32 unit that is a surrogate or
 * past U+10FFFF, or a trailing partial unit; in CESU-8 a four-byte form, a
 * lone surrogate, or a byte utf8_to_utf32 rejects; in UTF-7 (RFC 2152) a
 * byte outside the direct and optional characters, or a base64 run with
 * non-zero pad bits, a part unit, or a lone surrogate -- the whole run. */
static int cv_utf32_dec(int f, uint16_t policy, const unsigned char *in, int len, uint32_t *cp)
{
	int be = f != HXE_UTF32LE, i = 0, n = 0;
	if (f == HXE_UTF32 && len >= 4) {
		if (in[0] == 0 && in[1] == 0 && in[2] == 0xfe && in[3] == 0xff) i = 4;
		else if (in[0] == 0xff && in[1] == 0xfe && in[2] == 0 && in[3] == 0) { be = 0; i = 4; }
	}
	for (; i + 4 <= len; i += 4) {
		uint32_t c = be ? (uint32_t)in[i] << 24 | in[i + 1] << 16 | in[i + 2] << 8 | in[i + 3]
		                : (uint32_t)in[i + 3] << 24 | in[i + 2] << 16 | in[i + 1] << 8 | in[i];
		if (c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) {
			if ((n = cv_mb_err(policy, in, i, 4, cp, n)) < 0) return -1;
		} else
			cp[n++] = c;
	}
	if (i < len && (n = cv_mb_err(policy, in, i, len - i, cp, n)) < 0) return -1;
	return n;
}

static int cv_cesu8_dec(uint16_t policy, const unsigned char *in, int len, uint32_t *cp)
{
	int i = 0, n = 0;
	while (i < len) {
		uint32_t c;
		int sl;
		if (i + 2 < len && in[i] == 0xed && in[i + 1] >= 0xa0 && in[i + 1] <= 0xbf &&
		    (in[i + 2] & 0xc0) == 0x80) {
			uint32_t h = 0xd000 | (in[i + 1] & 0x3f) << 6 | (in[i + 2] & 0x3f);
			if (h <= 0xdbff && i + 5 < len && in[i + 3] == 0xed && in[i + 4] >= 0xb0 &&
			    in[i + 4] <= 0xbf && (in[i + 5] & 0xc0) == 0x80) {
				uint32_t l = 0xd000 | (in[i + 4] & 0x3f) << 6 | (in[i + 5] & 0x3f);
				cp[n++] = 0x10000 + ((h - 0xd800) << 10) + (l - 0xdc00);
				i += 6;
				continue;
			}
			if ((n = cv_mb_err(policy, in, i, 3, cp, n)) < 0) return -1;
			i += 3;
			continue;
		}
		if (in[i] < 0xf0 && (sl = cv_utf8_at(in, i, len, &c)) > 0) { cp[n++] = c; i += sl; continue; }
		if ((n = cv_mb_err(policy, in, i, 1, cp, n)) < 0) return -1;
		i++;
	}
	return n;
}

static int cv_b64v(unsigned c)
{
	return c >= 'A' && c <= 'Z' ? (int)(c - 'A') : c >= 'a' && c <= 'z' ? (int)(c - 'a' + 26) :
	       c >= '0' && c <= '9' ? (int)(c - '0' + 52) : c == '+' ? 62 : c == '/' ? 63 : -1;
}

/* RFC 2152 Set D, Set O, and SP TAB CR LF: written as themselves */
static int cv_utf7_direct(unsigned c)
{
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
	       (c && strchr("'(),-./:?!\"#$%&*;<=>@[]^_`{|} \t\r\n", (int)c) != NULL);
}

static int cv_utf7_dec(uint16_t policy, const unsigned char *in, int len, uint32_t *cp)
{
	int i = 0, n = 0;
	while (i < len) {
		int s, j, bits = 0, nb = 0, bad = 0, m;
		uint32_t acc = 0, hi = 0;
		if (in[i] != '+') {
			if (cv_utf7_direct(in[i])) cp[n++] = in[i];
			else if ((n = cv_mb_err(policy, in, i, 1, cp, n)) < 0) return -1;
			i++;
			continue;
		}
		if (i + 1 < len && in[i + 1] == '-') { cp[n++] = '+'; i += 2; continue; }
		s = i++;
		m = n;
		for (j = i; j < len && cv_b64v(in[j]) >= 0; j++) {
			acc = acc << 6 | (uint32_t)cv_b64v(in[j]);
			bits += 6;
			if (bits >= 16) {
				uint32_t u = (acc >> (bits - 16)) & 0xffff;
				bits -= 16;
				nb++;
				if (hi) {
					if (u >= 0xdc00 && u <= 0xdfff) cp[n++] = 0x10000 + ((hi - 0xd800) << 10) + (u - 0xdc00);
					else bad = 1;
					hi = 0;
				} else if (u >= 0xd800 && u <= 0xdbff) hi = u;
				else if (u >= 0xdc00 && u <= 0xdfff) bad = 1;
				else cp[n++] = u;
			}
		}
		/* the run ends: at least one unit, under 6 bits left over, all zero,
		 * and no surrogate left open */
		if (!nb || bits >= 6 || (acc & ((1u << bits) - 1)) || hi) bad = 1;
		if (j < len && in[j] == '-') j++;     /* an explicit end is absorbed */
		if (bad) {
			n = m;
			if ((n = cv_mb_err(policy, in, s, j - s, cp, n)) < 0) return -1;
		}
		i = j;
	}
	return n;
}

/* At most this many code points come from one input byte (a standard
 * single-byte table's longest entry, hxt_sb_dec's count field). */
#define CV_MAXSEQ 4   /* gen_hx_tables.py sb_parse refuses a longer entry */

/* Decode a charset into code points.  Returns the count, or -1 for a null
 * result.  cp has room for CV_MAXSEQ * len + 1 entries. */
static int cv_decode(int f, uint16_t policy, const unsigned char *in, int len,
                     uint32_t *cp)
{
	int i, n = 0;
	switch (f) {
	case HXE_UTF8:
		if ((policy & HXCV_ILL_MASK) == HXCV_ILL_NULL) {
			n = utf8_to_utf32(in, len, cp, len + 1);
			return n < 0 ? -1 : n;
		}
		for (i = 0; i < len; ) {
			uint32_t one;
			int sl = cv_utf8_at(in, i, len, &one);
			if (sl) { cp[n++] = one; i += sl; continue; }
			switch (policy & HXCV_ILL_MASK) {
			case HXCV_ILL_LATIN1: cp[n++] = in[i]; break;
			case HXCV_ILL_FFFD:   cp[n++] = 0xfffd; break;
			default:              cp[n++] = CV_RAWBYTE | in[i]; break;
			}
			i++;
		}
		return n;
	case HXE_LATIN1:
		for (i = 0; i < len; i++) cp[i] = in[i];
		return len;
	case HXE_UTF32LE: case HXE_UTF32BE: case HXE_UTF32:
		return cv_utf32_dec(f, policy, in, len, cp);
	case HXE_CESU8:
		return cv_cesu8_dec(policy, in, len, cp);
	case HXE_UTF7:
		return cv_utf7_dec(policy, in, len, cp);
	case HXE_UTF16LE:
	case HXE_UTF16BE:
	case HXE_UTF16: {
		/* section 5: a pair is one code point; under "cesu" every unit is
		 * kept as itself, for the encoder to write; a lone surrogate and an
		 * odd trailing byte become U+FFFD, or "?" under "q".  utf16: a BOM
		 * gives the byte order and is not text; with none it is big-endian */
		int be = f != HXE_UTF16LE, sur = policy & HXCV_SUR_MASK;
		if (f == HXE_UTF16 && len >= 2 && ((in[0] == 0xfe && in[1] == 0xff) ||
		                                   (in[0] == 0xff && in[1] == 0xfe))) {
			be = in[0] == 0xfe;
			in += 2;
			len -= 2;
		}
		uint32_t bad = sur == HXCV_SUR_Q ? 0x3f : 0xfffd;
		int nu = len / 2;
#define U16AT(k) (be ? (uint32_t)in[2*(k)] << 8 | in[2*(k)+1] \
                     : (uint32_t)in[2*(k)+1] << 8 | in[2*(k)])
		for (i = 0; i < nu; i++) {
			uint32_t u = U16AT(i);
			if (sur == HXCV_SUR_CESU || u < 0xd800 || u > 0xdfff) { cp[n++] = u; continue; }
			if (u <= 0xdbff && i + 1 < nu) {
				uint32_t l = U16AT(i + 1);
				if (l >= 0xdc00 && l <= 0xdfff) {
					cp[n++] = 0x10000 + ((u - 0xd800) << 10) + (l - 0xdc00);
					i++;
					continue;
				}
			}
			cp[n++] = bad;
		}
#undef U16AT
		if (len & 1) cp[n++] = sur == HXCV_SUR_Q ? 0x3f : 0xfffd;
		return n;
	}
	case HXE_KOI8R:
	case HXE_KOI8U: {
		const uint16_t *t = f == HXE_KOI8R ? hxt_koi8r_dec : hxt_koi8u_dec;
		for (i = 0; i < len; i++) cp[i] = t[in[i]];
		return len;
	}
	default: {
		/* cpNNN, Windows rules (section 10.4): a DBCS lead byte and any
		 * non-NUL byte are one pair; a lead before NUL or at the end is the
		 * Unicode default character on its own.  Under "null", Windows'
		 * strict decode: any byte or pair it rejects is a null result. */
		int pg, gl, strict = (policy & HXCV_ILL_MASK) == HXCV_ILL_NULL;
		if (hxe_reg[f].sb) {
			/* a standard single-byte table: an undefined byte is ill-formed,
			 * under the same tokens as UTF-8 */
			int sb = f - HXE_SB_FIRST;
			for (i = 0; i < len; i++) {
				uint32_t e = hxt_sb_dec[sb][in[i]];
				int k;
				if (e) {
					for (k = 0; k < (int)(e & 7); k++) cp[n++] = hxt_sb_pool[(e >> 3) + k];
					continue;
				}
				switch (policy & HXCV_ILL_MASK) {
				case HXCV_ILL_NULL:   return -1;
				case HXCV_ILL_LATIN1: cp[n++] = in[i]; break;
				case HXCV_ILL_FFFD:   cp[n++] = 0xfffd; break;
				default:              cp[n++] = CV_RAWBYTE | in[i]; break;
				}
			}
			return n;
		}
		if (f == HXE_ISO2022JP || f == HXE_ISO2022JP_WEB)
			return cv_iso2022jp_dec(f == HXE_ISO2022JP_WEB, policy, in, len, cp);
		if (hxe_reg[f].mb)
			return cv_mb_dec(f - HXE_MB_FIRST, policy, in, len, cp);
		pg = cv_page(f);
		if (pg < 0) return -1;   /* not reachable: hx_convert_build refuses it */
		gl = (policy & HXCV_GLYPHS) ? cv_gly(hxe_reg[f].cp) : -1;
		for (i = 0; i < len; i++) {
			int row = hxt_lead[pg][in[i]];
			if (row < 0) {
				if (strict && !(hxt_dec1_sbit[pg][in[i] >> 3] & (1 << (in[i] & 7))))
					return -1;
				cp[n++] = gl >= 0 && (in[i] < 0x20 || in[i] == 0x7f)
				        ? hxt_gly[gl][in[i] == 0x7f ? 32 : in[i]] : hxt_dec1[pg][in[i]];
				continue;
			}
			if (i + 1 < len && in[i + 1] != 0) {
				if (strict && !(hxt_dec2_sbit[row][in[i + 1] >> 3] & (1 << (in[i + 1] & 7))))
					return -1;
				cp[n++] = hxt_dec2[row][in[i + 1]];
				i++;
			} else {
				if (strict) return -1;
				cp[n++] = hxt_cpinfo[pg].udef;
			}
		}
		return n;
	}
	}
}

/* Binary search of a sorted (from, to) table. */
static uint32_t cv_map32(const uint32_t (*t)[2], int n, uint32_t c)
{
	int lo = 0, hi = n - 1;
	while (lo <= hi) {
		int m = (lo + hi) / 2;
		if (t[m][0] == c) return t[m][1];
		if (t[m][0] < c) lo = m + 1; else hi = m - 1;
	}
	return c;
}

static uint32_t cv_map16(const uint16_t (*t)[2], int n, uint32_t c)
{
	int lo = 0, hi = n - 1;
	if (c > 0xffff) return c;
	while (lo <= hi) {
		int m = (lo + hi) / 2;
		if (t[m][0] == c) return t[m][1];
		if (t[m][0] < c) lo = m + 1; else hi = m - 1;
	}
	return c;
}

/* A character-domain premap, in place.  An ill-formed byte kept under "keep"
 * is not a character and no map changes it; rev moves it as one unit. */
static void cv_premap_chars(int pm, uint32_t *cp, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		uint32_t c = cp[i];
		if (c & CV_RAWBYTE) continue;
		switch (pm) {
		case HXPM_LOWER:     cp[i] = cv_map32(hxt_lower, HXT_NLOWER, c); break;
		case HXPM_UPPER:     cp[i] = cv_map32(hxt_upper, HXT_NUPPER, c); break;
		case HXPM_LOWER_WIN: cp[i] = cv_map16(hxt_lower_win, HXT_NLOWER_WIN, c); break;
		case HXPM_UPPER_WIN: cp[i] = cv_map16(hxt_upper_win, HXT_NUPPER_WIN, c); break;
		case HXPM_ROT13:
			if (c >= 'A' && c <= 'Z') cp[i] = 'A' + (c - 'A' + 13) % 26;
			else if (c >= 'a' && c <= 'z') cp[i] = 'a' + (c - 'a' + 13) % 26;
			break;
		default: break;
		}
	}
	if (pm == HXPM_REV)
		for (i = 0; i < n / 2; i++) {
			uint32_t c = cp[i];
			cp[i] = cp[n - 1 - i];
			cp[n - 1 - i] = c;
		}
}

/* ---- premaps that change the number of code points ----
 * Full case mapping (SpecialCasing.txt, its unconditional rows plus
 * Final_Sigma; never a language condition) and UAX #15 normalisation, all
 * from Unicode 18.0.0.  An ill-formed byte kept under "keep" (CV_RAWBYTE) is
 * not a character: it is never mapped, it is neither Cased nor
 * Case_Ignorable, so it ends a Final_Sigma context, and it has combining
 * class 0 and composes with nothing, so normalisation never crosses it
 * (section 14). */

static int cv_in_ranges(const uint32_t (*r)[2], int n, uint32_t c)
{
	int lo = 0, hi = n - 1;
	while (lo <= hi) {
		int m = (lo + hi) / 2;
		if (c < r[m][0]) hi = m - 1;
		else if (c > r[m][1]) lo = m + 1;
		else return 1;
	}
	return 0;
}

#define CV_CASED(c)   (!((c) & CV_RAWBYTE) && cv_in_ranges(hxt_cased, HXT_NCASED, c))
#define CV_CASEIGN(c) (!((c) & CV_RAWBYTE) && cv_in_ranges(hxt_case_ign, HXT_NCASE_IGN, c))

/* Unicode 3.13 Table 3-17, Final_Sigma: C is preceded by a Cased character
 * and then zero or more Case_Ignorable ones, and is not followed by zero or
 * more Case_Ignorable characters and then a Cased one.  Case_Ignorable
 * characters are skipped first, so one that is both Cased and Case_Ignorable
 * (U+02B0, U+0345, ...) counts as ignorable: that is what ICU (JavaScript)
 * and CPython do, measured with Node 16 / ICU 74 and Python 3.9
 * (hx-support/phase3/case/).  Java 11 decides by word boundaries instead. */
static int cv_final_sigma(const uint32_t *cp, int n, int i)
{
	int j;
	for (j = i - 1; j >= 0 && CV_CASEIGN(cp[j]); j--)
		;
	if (j < 0 || !CV_CASED(cp[j])) return 0;
	for (j = i + 1; j < n && CV_CASEIGN(cp[j]); j++)
		;
	return j >= n || !CV_CASED(cp[j]);
}

static const uint32_t *cv_full_row(const uint32_t (*t)[4], int n, uint32_t c)
{
	int lo = 0, hi = n - 1;
	while (lo <= hi) {
		int m = (lo + hi) / 2;
		if (t[m][0] == c) return t[m];
		if (t[m][0] < c) lo = m + 1; else hi = m - 1;
	}
	return NULL;
}

static uint32_t cv_ccc(uint32_t c, int hfs)
{
	const uint32_t (*t)[2] = hfs ? hxt_ccc_hfs : hxt_ccc;
	int lo = 0, hi = (hfs ? HXT_NCCC_HFS : HXT_NCCC) - 1;
	while (lo <= hi) {
		int m = (lo + hi) / 2;
		if (t[m][0] == c) return t[m][1];
		if (t[m][0] < c) lo = m + 1; else hi = m - 1;
	}
	return 0;
}

#define CV_SBASE 0xAC00
#define CV_LBASE 0x1100
#define CV_VBASE 0x1161
#define CV_TBASE 0x11A7
#define CV_SCOUNT 11172
#define CV_NCOUNT 588
#define CV_TCOUNT 28

/* The full decomposition of c for the premap: a pointer into hxt_dpool, or
 * into buf for a Hangul syllable.  Returns the length; 1 with *d = &c for a
 * character that does not decompose. */
static int cv_decomp(int pm, uint32_t c, const uint32_t **d, uint32_t *buf)
{
	int lo = 0, hi = HXT_NDECOMP - 1;
	if (c >= CV_SBASE && c < CV_SBASE + CV_SCOUNT) {
		uint32_t s = c - CV_SBASE;
		buf[0] = CV_LBASE + s / CV_NCOUNT;
		buf[1] = CV_VBASE + s % CV_NCOUNT / CV_TCOUNT;
		buf[2] = CV_TBASE + s % CV_TCOUNT;
		*d = buf;
		return s % CV_TCOUNT ? 3 : 2;
	}
	while (lo <= hi) {
		int m = (lo + hi) / 2, off, len;
		if (hxt_decomp[m].cp < c) { lo = m + 1; continue; }
		if (hxt_decomp[m].cp > c) { hi = m - 1; continue; }
		if (pm == HXPM_NFKC || pm == HXPM_NFKD) { off = hxt_decomp[m].ko; len = hxt_decomp[m].kl; }
		else if (pm == HXPM_NFD_HFS)            { off = hxt_decomp[m].ho; len = hxt_decomp[m].hl; }
		else                                    { off = hxt_decomp[m].co; len = hxt_decomp[m].cl; }
		if (!len) break;
		*d = hxt_dpool + off;
		return len;
	}
	buf[0] = c;
	*d = buf;
	return 1;
}

/* Primary composite of a + b, or 0. */
static uint32_t cv_compose2(uint32_t a, uint32_t b)
{
	int lo = 0, hi = HXT_NCOMP - 1;
	if (a >= CV_LBASE && a < CV_LBASE + 19 && b >= CV_VBASE && b < CV_VBASE + 21)
		return CV_SBASE + ((a - CV_LBASE) * 21 + (b - CV_VBASE)) * CV_TCOUNT;
	if (a >= CV_SBASE && a < CV_SBASE + CV_SCOUNT && (a - CV_SBASE) % CV_TCOUNT == 0 &&
	    b > CV_TBASE && b < CV_TBASE + CV_TCOUNT)
		return a + (b - CV_TBASE);
	while (lo <= hi) {
		int m = (lo + hi) / 2;
		if (hxt_comp[m][0] == a && hxt_comp[m][1] == b) return hxt_comp[m][2];
		if (hxt_comp[m][0] < a || (hxt_comp[m][0] == a && hxt_comp[m][1] < b)) lo = m + 1;
		else hi = m - 1;
	}
	return 0;
}

static int cv_cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
	return x < y ? -1 : x > y;
}

/* Canonical ordering: each run of non-starters, stably by combining class. */
static void cv_reorder(uint32_t *cp, int n, int hfs, hx_arena *arena)
{
	int i = 0, j, k;
	while (i < n) {
		if (!cv_ccc(cp[i], hfs)) { i++; continue; }
		for (j = i; j < n && cv_ccc(cp[j], hfs); j++)
			;
		if (j - i <= 32) {                      /* insertion sort, stable */
			for (k = i + 1; k < j; k++) {
				uint32_t c = cp[k], cc = cv_ccc(c, hfs);
				int m = k - 1;
				while (m >= i && cv_ccc(cp[m], hfs) > cc) { cp[m + 1] = cp[m]; m--; }
				cp[m + 1] = c;
			}
		} else {                                /* class, then position */
			uint64_t *key = (uint64_t *)hx_arena_alloc(arena, (j - i) * 8);
			for (k = i; k < j; k++)
				key[k - i] = (uint64_t)cv_ccc(cp[k], hfs) << 56 | (uint64_t)(k - i) << 24 | cp[k];
			qsort(key, j - i, 8, cv_cmp_u64);
			for (k = i; k < j; k++) cp[k] = (uint32_t)(key[k - i] & 0xffffff);
		}
		i = j;
	}
}

/* Canonical composition (UAX #15 section 9), in place; returns the new count. */
static int cv_compose(uint32_t *cp, int n)
{
	int spos = 0, o = 1, i;
	uint32_t last;
	if (n == 0) return 0;
	last = cv_ccc(cp[0], 0) ? 256 : 0;
	for (i = 1; i < n; i++) {
		uint32_t c = cp[i], cc = cv_ccc(c, 0), k;
		if ((last < cc || last == 0) && (k = cv_compose2(cp[spos], c)) != 0) {
			cp[spos] = k;
			continue;
		}
		if (cc == 0) spos = o;
		last = cc;
		cp[o++] = c;
	}
	return o;
}

/* Apply a length-changing premap; *cpp is replaced by a new array. */
static int cv_premap_var(int pm, uint32_t **cpp, int n, hx_arena *arena)
{
	const uint32_t *cp = *cpp, *d;
	uint32_t *o, buf[3];
	int i, k, m = 0, len;

	if (pm == HXPM_LOWER_FULL || pm == HXPM_UPPER_FULL) {
		o = (uint32_t *)hx_arena_alloc(arena, (3 * n + 1) * sizeof(uint32_t));
		for (i = 0; i < n; i++) {
			uint32_t c = cp[i];
			const uint32_t *r;
			if (c & CV_RAWBYTE) { o[m++] = c; continue; }
			if (pm == HXPM_LOWER_FULL) {
				if (c == 0x3a3 && cv_final_sigma(cp, n, i)) { o[m++] = HXT_FINAL_SIGMA; continue; }
				r = cv_full_row(hxt_lower_full, HXT_NLOWER_FULL, c);
			} else
				r = cv_full_row(hxt_upper_full, HXT_NUPPER_FULL, c);
			if (r) {
				for (k = 1; k < 4 && r[k]; k++) o[m++] = r[k];
				continue;
			}
			o[m++] = pm == HXPM_LOWER_FULL ? cv_map32(hxt_lower, HXT_NLOWER, c)
			                               : cv_map32(hxt_upper, HXT_NUPPER, c);
		}
		*cpp = o;
		return m;
	}
	/* normalisation: decompose (counted first), order, then compose.  An
	 * HFS+ volume stores U+FFFE and U+FFFF as the escaped text of their
	 * UTF-8 bytes, "%EF%BF%BE" and "%EF%BF%BF" (hx-support/phase3/hfs/) */
	for (i = 0, len = 0; i < n; i++)
		len += (cp[i] & CV_RAWBYTE) ? 1 :
		       (pm == HXPM_NFD_HFS && (cp[i] | 1) == 0xffff) ? 9 : cv_decomp(pm, cp[i], &d, buf);
	o = (uint32_t *)hx_arena_alloc(arena, (len + 1) * sizeof(uint32_t));
	for (i = 0; i < n; i++) {
		if (cp[i] & CV_RAWBYTE) { o[m++] = cp[i]; continue; }
		if (pm == HXPM_NFD_HFS && (cp[i] | 1) == 0xffff) {
			const char *e = cp[i] == 0xfffe ? "%EF%BF%BE" : "%EF%BF%BF";
			for (k = 0; k < 9; k++) o[m++] = (unsigned char)e[k];
			continue;
		}
		k = cv_decomp(pm, cp[i], &d, buf);
		memcpy(o + m, d, k * sizeof(uint32_t));
		m += k;
	}
	cv_reorder(o, m, pm == HXPM_NFD_HFS, arena);
	if (pm == HXPM_NFC || pm == HXPM_NFKC)
		m = cv_compose(o, m);
	*cpp = o;
	return m;
}

/* The same tokens on bytes (section 18.5a): ASCII only, never the C library. */
static void cv_premap_bytes(int pm, unsigned char *b, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		unsigned char c = b[i];
		switch (pm) {
		case HXPM_LOWER: if (c >= 'A' && c <= 'Z') b[i] = c + 32; break;
		case HXPM_UPPER: if (c >= 'a' && c <= 'z') b[i] = c - 32; break;
		case HXPM_ROT13:
			if (c >= 'A' && c <= 'Z') b[i] = 'A' + (c - 'A' + 13) % 26;
			else if (c >= 'a' && c <= 'z') b[i] = 'a' + (c - 'a' + 13) % 26;
			break;
		default: break;
		}
	}
	if (pm == HXPM_REV)
		for (i = 0; i < n / 2; i++) {
			unsigned char c = b[i];
			b[i] = b[n - 1 - i];
			b[n - 1 - i] = c;
		}
}

/* One UTF-16 unit (or kept ill-formed byte, as CV_RAWBYTE) into a cpNNN, per
 * section 10.5, or under upper_oem through Windows' upcase-to-OEM table.
 * Writes 1 or 2 bytes and returns the count, or -1 when the unit is
 * unmappable under "fail".  A unit is unmappable when its result is the
 * page's default character and the unit is not the character that byte
 * decodes to: that is what Windows reports as a used default character. */
static int cv_cp_unit(int pg, int oem, uint16_t policy, uint32_t u, unsigned char *b)
{
	int dflt = hxt_cpinfo[pg].dflt;
	unsigned v;
	if (u & CV_RAWBYTE) {
		v = dflt;
	} else if (oem >= 0) {
		v = hxt_oem_blk[hxt_oem_idx[oem][u >> 8]][u & 0xff];
	} else {
		int blk = hxt_enc_idx[pg][u >> 8];
		v = hxt_enc_blk[blk][u & 0xff];
		if (!(policy & HXCV_BESTFIT) &&
		    !(hxt_enc_sbit[blk][(u & 0xff) >> 3] & (1 << (u & 7))))
			v = dflt;
	}
	if (v == (unsigned)dflt && ((u & CV_RAWBYTE) || u != hxt_cpinfo[pg].qcp) &&
	    (policy & HXCV_FAIL))
		return -1;
	if (v > 0xff) { b[0] = (unsigned char)(v >> 8); b[1] = (unsigned char)v; return 2; }
	b[0] = (unsigned char)v;
	return 1;
}

/* Binary search of a KOI8 encode table, or -1. */
static int cv_koi8_enc(int t, uint32_t c)
{
	const uint16_t (*e)[2] = t == HXE_KOI8R ? hxt_koi8r_enc : hxt_koi8u_enc;
	int lo = 0, hi = (t == HXE_KOI8R ? (int)(sizeof hxt_koi8r_enc / sizeof hxt_koi8r_enc[0])
	                                 : (int)(sizeof hxt_koi8u_enc / sizeof hxt_koi8u_enc[0])) - 1;
	if (c & CV_RAWBYTE) return -1;
	while (lo <= hi) {
		int m = (lo + hi) / 2;
		if (e[m][0] == c) return e[m][1];
		if (e[m][0] < c) lo = m + 1; else hi = m - 1;
	}
	return -1;
}

/* ISO-2022-JP encode.  web: the Encoding Standard encoder (Roman for
 * U+00A5 and U+203E, halfwidth katakana as their fullwidth forms through
 * index ISO-2022-JP katakana, U+2212 as U+FF0D).  Not web: RFC 1468, with
 * U+00A5 and U+203E in JIS-Roman.  Both end in ASCII.  U+000E, U+000F and
 * U+001B are unmappable, as is anything else with no code; unmappable is
 * '?' in ASCII, or null under "fail".  Returns -1 for null. */
static int cv_iso2022jp_enc(int web, int fail, const uint32_t *cp, int n,
                            hx_val *out, hx_arena *arena)
{
	enum { ASC, ROMAN, JIS };
	int m = (web ? HXE_MB_EUC_JP_WEB : HXE_MB_EUC_JP) - HXE_MB_FIRST;
	unsigned char *b = (unsigned char *)hx_arena_alloc(arena, 5 * n + 4), eb[4];
	int st = ASC, o = 0, i;
#define TO(s, c1, c2) do { if (st != (s)) { b[o++] = 0x1b; b[o++] = (c1); b[o++] = (c2); st = (s); } } while (0)
	for (i = 0; i < n; i++) {
		uint32_t c = cp[i];
		int k;
		if (!(c & CV_RAWBYTE) && c < 0x80 && c != 0x0e && c != 0x0f && c != 0x1b) {
			if (!(st == ROMAN && c != 0x5c && c != 0x7e)) TO(ASC, 0x28, 0x42);
			b[o++] = (unsigned char)c;
			continue;
		}
		if (c == 0xa5 || c == 0x203e) {
			TO(ROMAN, 0x28, 0x4a);
			b[o++] = c == 0xa5 ? 0x5c : 0x7e;
			continue;
		}
		if (web && c >= 0xff61 && c <= 0xff9f) c = hxt_kata[c - 0xff61];
		k = (c & CV_RAWBYTE) || c < 0x80 ? 0 : cv_mb_enc1(m, c, eb);
		if (k == 2 && eb[0] >= 0xa1 && eb[1] >= 0xa1) {
			TO(JIS, 0x24, 0x42);
			b[o++] = eb[0] & 0x7f;
			b[o++] = eb[1] & 0x7f;
			continue;
		}
		if (fail) return -1;
		TO(ASC, 0x28, 0x42);
		b[o++] = '?';
	}
	TO(ASC, 0x28, 0x42);
#undef TO
	b[o] = '\0';
	out->data = (char *)b;
	out->len = o;
	return 0;
}

static void cv_encode(int t, uint16_t policy, int premap, const uint32_t *cp, int n,
                      hx_val *out, hx_arena *arena)
{
	int i, o = 0;
	unsigned char *b;
	int fail = (policy & HXCV_FAIL) != 0;
	int cesu = (policy & HXCV_SUR_MASK) == HXCV_SUR_CESU;
	switch (t) {
	case HXE_UTF8:
		b = (unsigned char *)hx_arena_alloc(arena, 4 * n + 1);
		for (i = 0; i < n; i++) {
			if (cp[i] & CV_RAWBYTE) { b[o++] = (unsigned char)cp[i]; continue; }
			if (cesu && cp[i] == 0) { b[o++] = 0xc0; b[o++] = 0x80; continue; }
			o += cv_put_utf8(cp[i], b + o);
		}
		break;
	case HXE_UTF32LE: case HXE_UTF32BE: case HXE_UTF32: {
		/* utf32: the BOM, then big-endian (D17) */
		int be = t != HXE_UTF32LE;
		b = (unsigned char *)hx_arena_alloc(arena, 4 * n + 5);
		if (t == HXE_UTF32) { b[o++] = 0; b[o++] = 0; b[o++] = 0xfe; b[o++] = 0xff; }
		for (i = 0; i < n; i++) {
			uint32_t c = cp[i];
			if ((c & CV_RAWBYTE) || (c >= 0xd800 && c <= 0xdfff)) {   /* unmappable */
				if (fail) { cv_null(out, arena); return; }
				c = 0xfffd;
			}
			b[o++] = (unsigned char)(be ? c >> 24 : c);
			b[o++] = (unsigned char)(be ? c >> 16 : c >> 8);
			b[o++] = (unsigned char)(be ? c >> 8 : c >> 16);
			b[o++] = (unsigned char)(be ? c : c >> 24);
		}
		break;
	}
	case HXE_CESU8:
		/* UTR #26: a supplementary character is its UTF-16 surrogate pair,
		 * each unit in the three-byte form; NUL is 0x00 */
		b = (unsigned char *)hx_arena_alloc(arena, 6 * n + 1);
		for (i = 0; i < n; i++) {
			uint32_t c = cp[i];
			if (c & CV_RAWBYTE) {
				if (fail) { cv_null(out, arena); return; }
				c = 0xfffd;
			}
			if (c >= 0x10000) {
				c -= 0x10000;
				o += cv_put_utf8(0xd800 | (c >> 10), b + o);
				c = 0xdc00 | (c & 0x3ff);
			}
			o += cv_put_utf8(c, b + o);
		}
		break;
	case HXE_UTF16LE:
	case HXE_UTF16BE:
	case HXE_UTF16: {
		/* utf16: the BOM, then big-endian (D17) */
		int be = t != HXE_UTF16LE;
		b = (unsigned char *)hx_arena_alloc(arena, 4 * n + 3);
		if (t == HXE_UTF16) { b[o++] = 0xfe; b[o++] = 0xff; }
		for (i = 0; i < n; i++) {
			uint32_t c = cp[i], u[2];
			int k, nu;
			if (c & CV_RAWBYTE) {   /* unmappable: U+FFFD, or fail */
				if (fail) { cv_null(out, arena); return; }
				c = 0xfffd;
			}
			if (c < 0x10000) { u[0] = c; nu = 1; }
			else { c -= 0x10000; u[0] = 0xd800 | (c >> 10); u[1] = 0xdc00 | (c & 0x3ff); nu = 2; }
			for (k = 0; k < nu; k++) {
				b[o++] = (unsigned char)(be ? u[k] >> 8 : u[k]);
				b[o++] = (unsigned char)(be ? u[k] : u[k] >> 8);
			}
		}
		break;
	}
	case HXE_UTF7: {
		unsigned char *u8 = (unsigned char *)hx_arena_alloc(arena, 4 * n + 1);
		uint32_t *scr;
		int n8 = 0, cap;
		for (i = 0; i < n; i++) {
			uint32_t c = cp[i];
			if ((c & CV_RAWBYTE) || (c >= 0xd800 && c <= 0xdfff)) {
				if (fail) { cv_null(out, arena); return; }
				c = 0xfffd;
			}
			n8 += cv_put_utf8(c, u8 + n8);
		}
		cap = n8 * 8 + 8;
		b = (unsigned char *)hx_arena_alloc(arena, cap + 1);
		scr = (uint32_t *)hx_arena_alloc(arena, (n8 + 2) * sizeof(uint32_t));
		o = utf8_to_utf7(u8, n8, (char *)b, cap, scr, n8 + 2);
		if (o < 0) { cv_null(out, arena); return; }
		break;
	}
	case HXE_LOWBYTE16:
		/* section 17 utf16_lowbyte: UTF-16 units, then the low byte of each
		 * (JavaScript charCodeAt(i) & 0xFF, Java (byte)c).  An ill-formed
		 * byte kept under "keep" is unmappable: U+FFFD, so 0xFD, as a
		 * runtime's UTF-8 decoder would have read it, or "fail" */
		b = (unsigned char *)hx_arena_alloc(arena, 2 * n + 1);
		for (i = 0; i < n; i++) {
			uint32_t c = cp[i];
			if (c & CV_RAWBYTE) {
				if (fail) { cv_null(out, arena); return; }
				c = 0xfffd;
			}
			if (c >= 0x10000) {
				c -= 0x10000;
				b[o++] = (unsigned char)(0xd800 | (c >> 10));
				c = 0xdc00 | (c & 0x3ff);
			}
			b[o++] = (unsigned char)c;
		}
		break;
	case HXE_LATIN1:
		b = (unsigned char *)hx_arena_alloc(arena, n + 1);
		for (i = 0; i < n; i++) {
			if (!(cp[i] & CV_RAWBYTE) && cp[i] <= 0xff) { b[o++] = (unsigned char)cp[i]; continue; }
			if (fail) { cv_null(out, arena); return; }
			b[o++] = '?';
		}
		break;
	case HXE_KOI8R:
	case HXE_KOI8U:
		/* per code point, as latin1: these are library tables, not Windows */
		b = (unsigned char *)hx_arena_alloc(arena, n + 1);
		for (i = 0; i < n; i++) {
			int v = cv_koi8_enc(t, cp[i]);
			if (v >= 0) { b[o++] = (unsigned char)v; continue; }
			if (fail) { cv_null(out, arena); return; }
			b[o++] = '?';
		}
		break;
	default: {
		/* cpNNN: per UTF-16 unit (section 10.5) */
		int pg;
		if (hxe_reg[t].sb) {
			/* a standard single-byte table: the longest sequence of code
			 * points the table has a byte for; anything else is unmappable,
			 * '?' or "fail", as latin1 */
			int sb = t - HXE_SB_FIRST, lo0 = hxt_sb_start[sb], hi0 = hxt_sb_start[sb + 1];
			b = (unsigned char *)hx_arena_alloc(arena, n + 1);
			for (i = 0; i < n; ) {
				int lo = lo0, hi = hi0 - 1, j = -1, k, m;
				uint32_t c = cp[i];
				while (lo <= hi) {        /* first entry whose first is c */
					m = (lo + hi) / 2;
					if (hxt_sb_enc[m].first < c) lo = m + 1;
					else { if (hxt_sb_enc[m].first == c) j = m; hi = m - 1; }
				}
				for (; j >= 0 && j < hi0 && hxt_sb_enc[j].first == c; j++) {
					int ln = hxt_sb_enc[j].n;
					if (i + ln > n) continue;
					for (k = 1; k < ln; k++)
						if (cp[i + k] != hxt_sb_pool[hxt_sb_enc[j].off + k]) break;
					if (k == ln) break;
				}
				if (j >= 0 && j < hi0 && hxt_sb_enc[j].first == c && !(c & CV_RAWBYTE)) {
					b[o++] = hxt_sb_enc[j].b;
					i += hxt_sb_enc[j].n;
					continue;
				}
				if (fail) { cv_null(out, arena); return; }
				b[o++] = '?';
				i++;
			}
			break;
		}
		if (t == HXE_ISO2022JP || t == HXE_ISO2022JP_WEB) {
			if (cv_iso2022jp_enc(t == HXE_ISO2022JP_WEB, fail, cp, n, out, arena) < 0)
				cv_null(out, arena);
			return;
		}
		if (hxe_reg[t].mb) {
			int m = t - HXE_MB_FIRST, k;
			b = (unsigned char *)hx_arena_alloc(arena, 4 * n + 1);
			for (i = 0; i < n; i++) {
				if ((k = cv_mb_enc1(m, cp[i], b + o)) > 0) { o += k; continue; }
				if (fail) { cv_null(out, arena); return; }
				b[o++] = '?';
			}
			break;
		}
		pg = cv_page(t);
		int oem = premap == HXPM_UPPER_OEM ? cv_oem(hxt_cpinfo[pg].cp) : -1;
		b = (unsigned char *)hx_arena_alloc(arena, 4 * n + 1);
		for (i = 0; i < n; i++) {
			uint32_t c = cp[i];
			int k;
			if (!(c & CV_RAWBYTE) && c >= 0x10000) {
				c -= 0x10000;
				if ((k = cv_cp_unit(pg, oem, policy, 0xd800 | (c >> 10), b + o)) < 0) break;
				o += k;
				c = 0xdc00 | (c & 0x3ff);
			}
			if ((k = cv_cp_unit(pg, oem, policy, c, b + o)) < 0) break;
			o += k;
		}
		if (i < n) { cv_null(out, arena); return; }
		break;
	}
	}
	b[o] = '\0';
	out->data = (char *)b;
	out->len = o;
}

/* ---- transfer encodings ---- */

static const char cv_a_b64[]  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char cv_a_b64u[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static const char cv_a_crypt[]= "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
static const char cv_a_bcr[]  = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
static const char cv_a_b32[]  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static void cv_alpha(int id, const char **alpha, int *bits, int *lsb, int *pad)
{
	*bits = 6; *lsb = 0; *pad = 4;
	switch (id) {
	case HXE_BASE64:    *alpha = cv_a_b64; break;
	case HXE_BASE64URL: *alpha = cv_a_b64u; break;
	case HXE_BASE32:    *alpha = cv_a_b32; *bits = 5; *pad = 8; break;
	case HXE_CRYPT64:   *alpha = cv_a_crypt; *lsb = 1; *pad = 0; break;
	case HXE_CRYPT64BE: *alpha = cv_a_crypt; *pad = 0; break;
	case HXE_BCRYPT64:  *alpha = cv_a_bcr; *pad = 0; break;
	default:            *alpha = NULL; break;
	}
}

/* bytes -> text.  Returns the length written into out (sized by the caller). */
static int cv_tx_encode(int t, uint16_t policy, const unsigned char *in, int len, char *out)
{
	const char *alpha;
	int bits, lsb, pad, i, o = 0, nb = 0;
	uint32_t acc = 0;
	if (t == HXE_RAW) { memcpy(out, in, len); return len; }
	if (t == HXE_HEX) {
		const char *hd = (policy & HXCV_UC) ? "0123456789ABCDEF" : "0123456789abcdef";
		for (i = 0; i < len; i++) { out[o++] = hd[in[i] >> 4]; out[o++] = hd[in[i] & 15]; }
		return o;
	}
	cv_alpha(t, &alpha, &bits, &lsb, &pad);
	for (i = 0; i < len; i++) {
		if (lsb) { acc |= (uint32_t)in[i] << nb; nb += 8;
		           while (nb >= bits) { out[o++] = alpha[acc & 63]; acc >>= 6; nb -= 6; } }
		else     { acc = (acc << 8) | in[i]; nb += 8;
		           while (nb >= bits) { nb -= bits; out[o++] = alpha[(acc >> nb) & ((1u << bits) - 1)]; } }
	}
	if (nb > 0) out[o++] = lsb ? alpha[acc & 63] : alpha[(acc << (bits - nb)) & ((1u << bits) - 1)];
	if (pad && !(policy & HXCV_NOPAD))
		while (o % pad) out[o++] = '=';
	return o;
}

static int cv_tx_cap(int t, int len)
{
	return t == HXE_RAW ? len : t == HXE_HEX ? 2 * len : (len * 8 + 4) / 5 + 8;
}

/* text -> bytes; -1 for a null result.  Accepts exactly what the encoder can
 * produce, with or without padding where the encoding pads. */
static int cv_tx_decode(int f, const unsigned char *in, int len, unsigned char *out,
                        hx_arena *arena)
{
	const char *alpha;
	int bits, lsb, pad, i, o = 0, nb = 0, dlen = len, k;
	uint32_t acc = 0;
	signed char map[256];
	if (f == HXE_RAW) { memcpy(out, in, len); return len; }
	if (f == HXE_HEX) {
		if (len & 1) return -1;
		for (i = 0; i < len; i += 2) {
			int v[2];
			for (k = 0; k < 2; k++) {
				unsigned char c = in[i + k];
				v[k] = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
				       (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
				if (v[k] < 0) return -1;
			}
			out[o++] = (unsigned char)(v[0] << 4 | v[1]);
		}
		return o;
	}
	cv_alpha(f, &alpha, &bits, &lsb, &pad);
	memset(map, -1, sizeof map);
	for (i = 0; alpha[i]; i++) map[(unsigned char)alpha[i]] = (signed char)i;
	if (pad) while (dlen > 0 && in[dlen - 1] == '=') dlen--;
	for (i = 0; i < dlen; i++) {
		int v = map[in[i]];
		if (v < 0) return -1;
		if (lsb) { acc |= (uint32_t)v << nb; nb += 6;
		           if (nb >= 8) { out[o++] = (unsigned char)acc; acc >>= 8; nb -= 8; } }
		else     { acc = (acc << bits) | (uint32_t)v; nb += bits;
		           if (nb >= 8) { nb -= 8; out[o++] = (unsigned char)(acc >> nb); } }
	}
	/* canonical only: re-encode, padded and not, and compare */
	{
		char *re = hx_arena_alloc(arena, cv_tx_cap(f, o) + 1);
		int rl = cv_tx_encode(f, 0, out, o, re);
		if (rl == len && memcmp(re, in, len) == 0) return o;
		rl = cv_tx_encode(f, HXCV_NOPAD, out, o, re);
		if (rl == len && memcmp(re, in, len) == 0) return o;
	}
	return -1;
}

void hx_convert_run(const hx_inst *ip, const hx_val *in, hx_val *out,
                    hx_arena *arena)
{
	int f = ip->u.conv.from, t = ip->u.conv.to, len = in->len;
	int pm = ip->u.conv.premap;
	uint16_t policy = ip->u.conv.policy;
	const unsigned char *src = (const unsigned char *)in->data;

	memset(out, 0, sizeof *out);
	if (hx_conv_kind(f) == HXE_KIND_TRANSFER) {
		unsigned char *bytes = (unsigned char *)hx_arena_alloc(arena, len + 4);
		int n;
		if (policy & HXCV_LENIENT)
			n = f == HXE_HEX ? hx_fromhex_lenient(src, len, bytes)
			                 : hx_frombase64_lenient(src, len, bytes);
		else
			n = cv_tx_decode(f, src, len, bytes, arena);
		if (n < 0) { cv_null(out, arena); return; }
		if (pm) cv_premap_bytes(pm, bytes, n);
		out->data = hx_arena_alloc(arena, cv_tx_cap(t, n) + 1);
		out->len = cv_tx_encode(t, policy, bytes, n, out->data);
		out->data[out->len] = '\0';
		return;
	}
	{
		uint32_t *cp = (uint32_t *)hx_arena_alloc(arena, ((hxe_reg[f].sb ? CV_MAXSEQ : 1) * len + 1) *
		                                            sizeof(uint32_t));
		int n = cv_decode(f, policy, src, len, cp);
		if (n < 0) { cv_null(out, arena); return; }
		if (pm >= HXPM_LOWER_FULL) n = cv_premap_var(pm, &cp, n, arena);
		else if (pm && pm != HXPM_UPPER_OEM) cv_premap_chars(pm, cp, n);
		cv_encode(t, policy, pm, cp, n, out, arena);
	}
}

/* Build facts for hx -V.  They state what this build is and stand alone:
 * no reference to any document or source path. */
const char *hx_build_facts(void)
{
	return "Unicode " HXT_UNICODE_VERSION ", frozen\n"
	       "cpNNN code pages, Windows case tables and LM preparation: Windows 11\n"
	       "KOI8-R and KOI8-U: RFC 1489 and RFC 2319\n"
	       "iso8859_N: ISO/IEC 8859; mac_* and adobe_symbol: Apple; "
	       "adobe_standard: Adobe\n"
	       "jis_x0201: JIS X 0201; kz1048: STRK1048-2002; viscii: RFC 1456; "
	       "hp_roman8, dec_mcs: RFC 1345\n"
	       "atascii, petscii, petscii_shifted: Unicode L2/19-025; ascii: ANSI X3.4; "
	       "cp864_ibmgraph: IBMGRAPH.TXT\n"
	       "shift_jis, euc_jp, iso2022jp: JIS X 0208, JIS X 0212, RFC 1468; "
	       "euc_kr: KS X 1001; euc_jp_c1, euc_kr_c1: with C1, as glibc\n"
	       "gb2312, gb18030: GB 18030-2022; *_web: WHATWG Encoding Standard\n"
	       "utf32*, utf16, cesu8, utf7: Unicode, UTR #26, RFC 2152; "
	       "gsm0338: 3GPP TS 23.038; t61: ITU-T T.61\n";
}

/* ---- the retired conversion functions' registry entries ----
 * Every call of one of these names that the compiler does not turn into
 * OP_CONVERT itself -- hex_bin(x), and a call with more than one argument --
 * runs the alias's instruction here, on the first argument, which is what
 * the old implementations did.  hex_bin is the identity (hx.1 2.4). */
static void fn_conv_call(hx_func_entry *self, hx_val *args, int nargs,
                         hx_val *result, hx_arena *arena, uint8_t role)
{
	hx_inst ci;
	(void)nargs;
	if (role == ROLE_BIN) { *result = args[0]; return; }   /* hex_bin */
	if (!hx_convert_alias_inst(self->name, &ci)) {
		fprintf(stderr, "hx: %s: %s:%d: no conversion for this name\n",
		        self->name, __FILE__, __LINE__);
		exit(1);
	}
	hx_convert_run(&ci, &args[0], result, arena);
}

/* ---- text programs: hx-functions.md 19 ----
 * valid(x, cs) and roundtrip(x, a, b) take their encoding names as string
 * constants; the compiler accepts only literals and loop variables there and
 * checks the names, so a lookup here cannot fail. */

static int cv_arg_id(const hx_val *a)
{
	char nm[32];
	int n = a->len < (int)sizeof nm - 1 ? a->len : (int)sizeof nm - 1;
	memcpy(nm, a->data, n);
	nm[n] = '\0';
	return hx_conv_lookup(nm);
}

/* x (not empty: fn_valid) is well-formed in f and decoding it substitutes
 * nothing:
 *   utf8        well-formed UTF-8 (no overlong form, surrogate or value past
 *               U+10FFFF), as utf16le() requires;
 *   utf16le/be  an even length and no lone surrogate;
 *   latin1, koi8r, koi8u: always, every byte is assigned;
 *   a standard single-byte table: every byte is assigned in it;
 *   a cpNNN: Windows' strict decode accepts it (MB_ERR_INVALID_CHARS,
 *               review/windows/cpdump3): no undefined byte, no invalid
 *               trail, and no lead byte at the end or before NUL;
 *   a transfer encoding: the strict decoder accepts it (section 18.3a). */
static int cv_valid(int f, const unsigned char *in, int len, hx_arena *arena)
{
	int i;
	switch (f) {
	case HXE_UTF8:
		for (i = 0; i < len; ) {
			uint32_t one;
			int sl = cv_utf8_at(in, i, len, &one);
			if (!sl) return 0;
			i += sl;
		}
		return 1;
	case HXE_UTF16LE:
	case HXE_UTF16BE:
	case HXE_UTF16: {
		int be = f != HXE_UTF16LE;
		if (f == HXE_UTF16 && len >= 2 && ((in[0] == 0xfe && in[1] == 0xff) ||
		                                   (in[0] == 0xff && in[1] == 0xfe))) {
			be = in[0] == 0xfe;
			in += 2;
			len -= 2;
		}
		if (len & 1) return 0;
		for (i = 0; i < len; i += 2) {
			uint32_t u = be ? (uint32_t)in[i] << 8 | in[i + 1]
			                : (uint32_t)in[i + 1] << 8 | in[i];
			uint32_t l;
			if (u < 0xd800 || u > 0xdfff) continue;
			if (u > 0xdbff || i + 3 >= len) return 0;
			l = be ? (uint32_t)in[i + 2] << 8 | in[i + 3]
			       : (uint32_t)in[i + 3] << 8 | in[i + 2];
			if (l < 0xdc00 || l > 0xdfff) return 0;
			i += 2;
		}
		return 1;
	}
	case HXE_LATIN1:
	case HXE_KOI8R:
	case HXE_KOI8U:
		return 1;
	default:
		if (hx_conv_kind(f) == HXE_KIND_TRANSFER) {
			unsigned char *b = (unsigned char *)hx_arena_alloc(arena, len + 4);
			return cv_tx_decode(f, in, len, b, arena) >= 0;
		}
		if (hxe_reg[f].sb) {
			for (i = 0; i < len; i++)
				if (!hxt_sb_dec[f - HXE_SB_FIRST][in[i]]) return 0;
			return 1;
		}
		if (hxe_reg[f].mb || CV_IS_U32(f) || f == HXE_CESU8 || f == HXE_UTF7) {
			uint32_t *scr = (uint32_t *)hx_arena_alloc(arena, (2 * len + 2) * sizeof(uint32_t));
			return cv_decode(f, HXCV_ILL_NULL, in, len, scr) >= 0;
		}
		{
			/* Windows' strict decode accepts it (MB_ERR_INVALID_CHARS) */
			uint32_t *scr = (uint32_t *)hx_arena_alloc(arena, (len + 1) * sizeof(uint32_t));   /* a cpNNN: one per byte */
			return cv_decode(f, HXCV_ILL_NULL, in, len, scr) >= 0;
		}
	}
}

static void fn_valid(hx_func_entry *self, hx_val *args, int nargs,
                     hx_val *result, hx_arena *arena, uint8_t role)
{
	(void)self; (void)nargs; (void)role;
	memset(result, 0, sizeof *result);
	/* The empty string is not valid: it is also the null result of a failed
	 * conversion (section 19.2), and a search must not keep that as a
	 * reading.  (A ruling may make it valid; it is well-formed.) */
	result->data = args[0].data && args[0].len > 0 &&
	               cv_valid(cv_arg_id(&args[1]),
	                        (const unsigned char *)args[0].data,
	                        args[0].len, arena) ? "1" : "";
	result->len = (int)strlen(result->data);
}

/* convert(convert(x, a, b), b, a) == x, both with the default policies.
 * ponytail: the two instructions are rebuilt from the names on every call; a
 * per-instruction cache is the upgrade if a search program spends its time
 * here. */
static void fn_roundtrip(hx_func_entry *self, hx_val *args, int nargs,
                         hx_val *result, hx_arena *arena, uint8_t role)
{
	char a[32], b[32], err[160];
	hx_inst ab, ba;
	hx_val mid, back;
	int la = args[1].len < 31 ? args[1].len : 31, lb = args[2].len < 31 ? args[2].len : 31;
	(void)self; (void)nargs; (void)role;
	memcpy(a, args[1].data, la); a[la] = '\0';
	memcpy(b, args[2].data, lb); b[lb] = '\0';
	if (hx_convert_build(a, b, NULL, 0, &ab, err, sizeof err) < 0 ||
	    hx_convert_build(b, a, NULL, 0, &ba, err, sizeof err) < 0) {
		fprintf(stderr, "hx: %s:%d: roundtrip(): %s\n", __FILE__, __LINE__, err);
		exit(1);
	}
	hx_convert_run(&ab, &args[0], &mid, arena);
	hx_convert_run(&ba, &mid, &back, arena);
	memset(result, 0, sizeof *result);
	/* the empty string is not a round trip, as it is not valid(): it is
	 * also the null result of a failed conversion (section 19.4a) */
	result->data = args[0].data && args[0].len > 0 &&
	               (back.len == (args[0].data ? args[0].len : 0) &&
	                (back.len == 0 || memcmp(back.data, args[0].data, back.len) == 0))
	               ? "1" : "";
	result->len = (int)strlen(result->data);
}

/* charsets(group), section 19.1.  ONE table: a row per encoding, in the
 * order every group lists its members; "all" is every row.  Adding an
 * encoding to a group is adding (or extending) its row here. */
enum { CSG_WINDOWS = 1, CSG_OEM = 2, CSG_ISO8859 = 4, CSG_MAC = 8,
       CSG_EBCDIC = 16, CSG_CJK = 32, CSG_UNICODE = 64 };

static const struct { const char *name; uint8_t groups; } hx_cs_rows[] = {
	{ "utf8",    CSG_UNICODE }, { "utf16le", CSG_UNICODE }, { "utf16be", CSG_UNICODE },
	{ "cp874",   CSG_WINDOWS },
	{ "cp932",   CSG_WINDOWS | CSG_CJK }, { "cp936", CSG_WINDOWS | CSG_CJK },
	{ "cp949",   CSG_WINDOWS | CSG_CJK }, { "cp950", CSG_WINDOWS | CSG_CJK },
	{ "cp1250",  CSG_WINDOWS }, { "cp1251", CSG_WINDOWS }, { "cp1252", CSG_WINDOWS },
	{ "cp1253",  CSG_WINDOWS }, { "cp1254", CSG_WINDOWS }, { "cp1255", CSG_WINDOWS },
	{ "cp1256",  CSG_WINDOWS }, { "cp1257", CSG_WINDOWS }, { "cp1258", CSG_WINDOWS },
	{ "cp1361",  CSG_CJK },
	{ "cp437",   CSG_OEM }, { "cp737", CSG_OEM }, { "cp775", CSG_OEM },
	{ "cp850",   CSG_OEM }, { "cp852", CSG_OEM }, { "cp855", CSG_OEM },
	{ "cp857",   CSG_OEM }, { "cp858", CSG_OEM }, { "cp860", CSG_OEM },
	{ "cp861",   CSG_OEM }, { "cp862", CSG_OEM }, { "cp863", CSG_OEM },
	{ "cp864",   CSG_OEM }, { "cp865", CSG_OEM }, { "cp866", CSG_OEM },
	{ "cp869",   CSG_OEM },
	{ "latin1",  CSG_ISO8859 },
	{ "cp10000", CSG_MAC },
	{ "cp37",    CSG_EBCDIC }, { "cp1047", CSG_EBCDIC }, { "cp1140", CSG_EBCDIC },
	{ "cp1148",  CSG_EBCDIC },
	/* in "all" only */
	{ "koi8r", 0 }, { "koi8u", 0 }, { "cp20866", 0 }, { "cp21866", 0 },
	{ "cp28591", 0 },
	/* phase 4b, step 1 */
	{ "iso8859_2", CSG_ISO8859 }, { "iso8859_3", CSG_ISO8859 }, { "iso8859_4", CSG_ISO8859 },
	{ "iso8859_5", CSG_ISO8859 }, { "iso8859_6", CSG_ISO8859 }, { "iso8859_7", CSG_ISO8859 },
	{ "iso8859_8", CSG_ISO8859 }, { "iso8859_9", CSG_ISO8859 }, { "iso8859_10", CSG_ISO8859 },
	{ "iso8859_11", CSG_ISO8859 }, { "iso8859_13", CSG_ISO8859 }, { "iso8859_14", CSG_ISO8859 },
	{ "iso8859_15", CSG_ISO8859 }, { "iso8859_16", CSG_ISO8859 },
	{ "mac_roman", CSG_MAC }, { "mac_cyrillic", CSG_MAC }, { "mac_greek", CSG_MAC },
	{ "mac_turkish", CSG_MAC }, { "mac_centeuro", CSG_MAC }, { "mac_icelandic", CSG_MAC },
	{ "mac_croatian", CSG_MAC }, { "mac_romanian", CSG_MAC }, { "mac_arabic", CSG_MAC },
	{ "mac_hebrew", CSG_MAC }, { "mac_thai", CSG_MAC },
	{ "cp500", CSG_EBCDIC }, { "cp875", CSG_EBCDIC }, { "cp1026", CSG_EBCDIC },
	{ "cp1141", CSG_EBCDIC }, { "cp1142", CSG_EBCDIC }, { "cp1143", CSG_EBCDIC },
	{ "cp1144", CSG_EBCDIC }, { "cp1145", CSG_EBCDIC }, { "cp1146", CSG_EBCDIC },
	{ "cp1147", CSG_EBCDIC }, { "cp1149", CSG_EBCDIC },
	{ "cp708", CSG_OEM }, { "cp720", CSG_OEM },
	{ "jis_x0201", CSG_CJK },
	{ "cp10001", CSG_CJK }, { "cp10002", CSG_CJK }, { "cp10003", CSG_CJK }, { "cp10008", CSG_CJK },
	/* Windows' readings of other standards, and the rest: "all" only */
	{ "cp28592", 0 }, { "cp28593", 0 }, { "cp28594", 0 }, { "cp28595", 0 }, { "cp28596", 0 },
	{ "cp28597", 0 }, { "cp28598", 0 }, { "cp28599", 0 }, { "cp28603", 0 }, { "cp28605", 0 },
	{ "cp10004", 0 }, { "cp10005", 0 }, { "cp10006", 0 }, { "cp10007", 0 }, { "cp10010", 0 },
	{ "cp10017", 0 }, { "cp10021", 0 }, { "cp10029", 0 }, { "cp10079", 0 }, { "cp10081", 0 },
	{ "cp10082", 0 }, { "cp20127", 0 },
	{ "ascii", 0 }, { "adobe_standard", 0 }, { "adobe_symbol", 0 }, { "kz1048", 0 },
	{ "viscii", 0 }, { "hp_roman8", 0 }, { "dec_mcs", 0 }, { "atascii", 0 }, { "petscii", 0 },
	{ "petscii_shifted", 0 }, { "cp864_ibmgraph", 0 },
	/* phase 4b, step 3 */
	{ "shift_jis", CSG_CJK }, { "euc_jp", CSG_CJK }, { "iso2022jp", CSG_CJK },
	{ "euc_kr", CSG_CJK }, { "gb2312", CSG_CJK }, { "gb18030", CSG_CJK },
	{ "shift_jis_web", CSG_CJK }, { "euc_jp_web", CSG_CJK }, { "iso2022jp_web", CSG_CJK },
	{ "euc_kr_web", CSG_CJK }, { "big5_web", CSG_CJK }, { "gb18030_web", CSG_CJK },
	{ "gbk_web", CSG_CJK },
	/* phase 4b, step 4 */
	{ "utf32le", CSG_UNICODE }, { "utf32be", CSG_UNICODE }, { "utf32", CSG_UNICODE },
	{ "utf16", CSG_UNICODE }, { "cesu8", CSG_UNICODE }, { "utf7", CSG_UNICODE },
	{ "gsm0338", 0 }, { "t61", 0 },
	{ "euc_jp_c1", CSG_CJK }, { "euc_kr_c1", CSG_CJK },
};
#define HX_CS_NROWS ((int)(sizeof hx_cs_rows / sizeof hx_cs_rows[0]))

const char *const *hx_charsets(const char *group)
{
	static const struct { const char *name; int bit; } g[] = {
		{ "all", 0 }, { "windows", CSG_WINDOWS }, { "oem", CSG_OEM },
		{ "iso8859", CSG_ISO8859 }, { "mac", CSG_MAC }, { "ebcdic", CSG_EBCDIC },
		{ "cjk", CSG_CJK }, { "unicode", CSG_UNICODE },
	};
	static const char *list[sizeof g / sizeof g[0]][HX_CS_NROWS + 1];
	int k, i, n = 0;
	for (k = 0; k < (int)(sizeof g / sizeof g[0]); k++)
		if (strcmp(g[k].name, group) == 0) break;
	if (k == (int)(sizeof g / sizeof g[0])) return NULL;
	for (i = 0; i < HX_CS_NROWS; i++)
		if (!g[k].bit || (hx_cs_rows[i].groups & g[k].bit))
			list[k][n++] = hx_cs_rows[i].name;
	list[k][n] = NULL;
	return list[k];
}

/* ---- lm_cpNNN: LM as Windows prepares it on a machine of that OEM page ----
 * hx-functions.md 12, 17, 18.6.  The password is put through
 * convert(x, "utf8", "cpNNN", "bestfit", "upper_oem", "fail") --
 * RtlUpcaseUnicodeStringToOemString, from the Windows 11 dumps -- truncated
 * or NUL-padded to 14 bytes, and each 7-byte half keys DES over "KGS!@#$%",
 * exactly the DES step of lm() (lm.a's auth_LMhash, hashpipe compute_lm).
 * For an ASCII password that is lm(): upper_oem maps a-z to A-Z and every
 * other ASCII character to itself.  A character with no OEM form fails the
 * conversion, and then there is no LM hash: the result is null (empty), as
 * Windows computes none.  The page comes from the function's name. */
static void fn_lm_oem(hx_func_entry *self, hx_val *args, int nargs,
                      hx_val *result, hx_arena *arena, uint8_t role)
{
	static const unsigned char magic[8] = { 'K','G','S','!','@','#','$','%' };
	unsigned char key[14], dg[16];
	char cs[16];
	hx_inst ci;
	hx_val ov;
	int n;
	(void)nargs;

	snprintf(cs, sizeof cs, "cp%s", self->name + 5);
	cv_set(&ci, HXE_UTF8, hx_conv_lookup(cs), HXCV_BESTFIT | HXCV_FAIL, HXPM_UPPER_OEM);
	hx_convert_run(&ci, &args[0], &ov, arena);
	if (ov.len == 0 && args[0].len > 0) {
		/* every character gives at least one byte, so an empty result from
		 * a non-empty password is the failed conversion */
		cv_null(result, arena);
		return;
	}
	n = ov.len < 14 ? ov.len : 14;
	memset(key, 0, sizeof key);
	memcpy(key, ov.data, n);
	hx_des7(key, magic, dg);
	hx_des7(key + 7, magic, dg + 8);
	emit_digest(dg, 16, result, arena, role);
}

/* ---- length ---- */

/*
 * length(x) — returns the byte length of x as an integer.
 * Useful in cut() arguments, loop bounds, and conditions.
 */
static void fn_length(hx_func_entry *self, hx_val *args, int nargs,
                      hx_val *result, hx_arena *arena, uint8_t role)
{
	char *buf;
	(void)self; (void)nargs; (void)role;

	result->is_int = 1;
	result->ival   = args[0].len;
	/* also produce string representation for use in string context */
	buf = hx_arena_alloc(arena, 20);
	result->len = sprintf(buf, "%d", args[0].len);
	result->data = buf;
}

/* ---- ulength, ucut, utrunc: counted in characters (section 3, 4.1) ---- */

/* The byte offset of every character boundary of x by the section 3 model:
 * a well-formed UTF-8 sequence is one character, any other byte is one on its
 * own.  Returns the character count; off has room for len + 1 entries. */
static int u_bounds(const unsigned char *s, int len, int *off)
{
	int i = 0, n = 0;
	while (i < len) {
		uint32_t cp;
		int sl = cv_utf8_at(s, i, len, &cp);
		off[n++] = i;
		i += sl ? sl : 1;
	}
	off[n] = len;
	return n;
}

/* ulength(x): the number of characters, as length() gives bytes. */
static void fn_ulength(hx_func_entry *self, hx_val *args, int nargs,
                       hx_val *result, hx_arena *arena, uint8_t role)
{
	int *off = (int *)hx_arena_alloc(arena, (args[0].len + 1) * (int)sizeof(int));
	int n = u_bounds((const unsigned char *)args[0].data, args[0].len, off);
	char *buf;
	(void)self; (void)nargs; (void)role;
	buf = hx_arena_alloc(arena, 20);
	result->is_int = 1;
	result->ival   = n;
	result->len = sprintf(buf, "%d", n);
	result->data = buf;
}

/* ucut(x[, start[, len]]): cut()'s rules, counted in characters, so the
 * result never splits a well-formed sequence (section 4.1). */
static void fn_ucut(hx_func_entry *self, hx_val *args, int nargs,
                    hx_val *result, hx_arena *arena, uint8_t role)
{
	int *off = (int *)hx_arena_alloc(arena, (args[0].len + 1) * (int)sizeof(int));
	int n = u_bounds((const unsigned char *)args[0].data, args[0].len, off);
	int start = 0, len, b0, b1;
	(void)self; (void)role;

	if (nargs >= 2) start = val_to_int(&args[1]);
	if (start < 0) { start = n + start; if (start < 0) start = 0; }
	if (start > n) start = n;
	if (nargs >= 3) { len = val_to_int(&args[2]); if (len < 0) len = 0; }
	else len = n - start;
	if (start + len > n) len = n - start;
	b0 = off[start];
	b1 = off[start + len];
	result->data = hx_arena_alloc(arena, b1 - b0 + 1);
	memcpy(result->data, args[0].data + b0, b1 - b0);
	result->data[b1 - b0] = '\0';
	result->len = b1 - b0;
}

/* utrunc(x, n): ucut(x, 0, n). */
static void fn_utrunc(hx_func_entry *self, hx_val *args, int nargs,
                      hx_val *result, hx_arena *arena, uint8_t role)
{
	hx_val a[3];
	(void)nargs;
	a[0] = args[0];
	memset(&a[1], 0, sizeof a[1]);
	a[1].is_int = 1; a[1].ival = 0;
	a[2] = args[1];
	fn_ucut(self, a, 3, result, arena, role);
}

/* ---- xor ---- */

/*
 * xor(a, b) — byte-wise exclusive OR.
 * If the arguments are of unequal length, the shorter is
 * cycled (repeated) to match the length of the longer.
 */
static void fn_xor(hx_func_entry *self, hx_val *args, int nargs,
                   hx_val *result, hx_arena *arena, uint8_t role)
{
	int alen = args[0].len, blen = args[1].len;
	int outlen = alen > blen ? alen : blen;
	char *out;
	int i;
	(void)self; (void)nargs; (void)role;

	if (outlen == 0 || alen == 0 || blen == 0) {
		result->data = hx_arena_alloc(arena, 1);
		result->data[0] = '\0';
		result->len = 0;
		return;
	}

	out = hx_arena_alloc(arena, outlen + 1);
	for (i = 0; i < outlen; i++)
		out[i] = args[0].data[i % alen] ^ args[1].data[i % blen];
	out[outlen] = '\0';
	result->data = out;
	result->len  = outlen;
}

/* ---- and / or (bitwise) ---- */

/*
 * and(a, b) — byte-wise AND.  Shorter argument is cycled.
 * or(a, b)  — byte-wise OR.   Shorter argument is cycled.
 */
static void fn_and(hx_func_entry *self, hx_val *args, int nargs,
                   hx_val *result, hx_arena *arena, uint8_t role)
{
	int alen = args[0].len, blen = args[1].len;
	int outlen = alen > blen ? alen : blen;
	char *out;
	int i;
	(void)self; (void)nargs; (void)role;

	if (outlen == 0 || alen == 0 || blen == 0) {
		result->data = hx_arena_alloc(arena, 1);
		result->data[0] = '\0';
		result->len = 0;
		return;
	}
	out = hx_arena_alloc(arena, outlen + 1);
	for (i = 0; i < outlen; i++)
		out[i] = args[0].data[i % alen] & args[1].data[i % blen];
	out[outlen] = '\0';
	result->data = out;
	result->len  = outlen;
}

static void fn_or(hx_func_entry *self, hx_val *args, int nargs,
                  hx_val *result, hx_arena *arena, uint8_t role)
{
	int alen = args[0].len, blen = args[1].len;
	int outlen = alen > blen ? alen : blen;
	char *out;
	int i;
	(void)self; (void)nargs; (void)role;

	if (outlen == 0 || alen == 0 || blen == 0) {
		result->data = hx_arena_alloc(arena, 1);
		result->data[0] = '\0';
		result->len = 0;
		return;
	}
	out = hx_arena_alloc(arena, outlen + 1);
	for (i = 0; i < outlen; i++)
		out[i] = args[0].data[i % alen] | args[1].data[i % blen];
	out[outlen] = '\0';
	result->data = out;
	result->len  = outlen;
}

/* ================================================================
 * Registry
 * ================================================================ */

/*
 * Role-capability presets:
 *   ROLES_DIGEST = BIN|HEX|B64       — digests, HMAC, KDF (raw-bytes output)
 *   ROLES_NONE   = 0                 — string transforms, encodings (no suffix
 *                                      applies; bare name only)
 *   ROLES_HEXBIN = BIN               — `hex` (special: identity for _bin)
 *   ROLES_CRYPT  = BIN|HEX|B64|MCF   — bcrypt, yescrypt (full MCF available)
 */
#define ROLES_DIGEST  (ROLE_CAP_BIN | ROLE_CAP_HEX | ROLE_CAP_B64 | ROLE_CAP_UC)
#define ROLES_NONE    (0)
#define ROLES_HEXBIN  (ROLE_CAP_BIN)
#define ROLES_CRYPT   (ROLE_CAP_BIN | ROLE_CAP_HEX | ROLE_CAP_B64 | ROLE_CAP_MCF)

hx_func_entry hx_func_table[HX_MAX_FUNCS] = {
#ifdef HX_STANDALONE
	{ "md5",           fn_md5,           16, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "md4",           fn_md4,           16, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "sha1",          fn_sha1,          20, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "sha256",        fn_sha256,        32, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "sha512",        fn_sha512,        64, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "hmac_sha1",     fn_hmac_sha1,     20, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "hmac_sha256",   fn_hmac_sha256,   32, NULL, 0, ROLES_DIGEST, ROLE_HEX },
#endif
	{ "hex",           fn_conv_call,            0, NULL, 0, ROLES_HEXBIN, ROLE_HEX },
	{ "upper",         fn_conv_call,          0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "lower",         fn_conv_call,          0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "cut",           fn_cut,            0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "pad",           fn_pad,            0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "trunc",         fn_trunc,          0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "rev",           fn_conv_call,            0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "bswap32",       fn_bswap32,        0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "rotate",        fn_rotate,         0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "cap",           fn_cap,            0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "rot13",         fn_conv_call,          0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "base64",        fn_conv_call,         0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "frombase64",    fn_conv_call,     0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "fromhex",       fn_conv_call,        0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "wperm",         fn_wperm,          0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "add",           fn_add,            0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "sub",           fn_sub,            0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "mul",           fn_mul,            0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "mod",           fn_mod,            0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "phpass_encode", fn_conv_call,  0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "progress_encode", fn_progress_encode, 0, NULL, 0, ROLES_NONE, ROLE_DEFAULT },
	{ "juniper_encode",  fn_juniper_encode,  0, NULL, 0, ROLES_NONE, ROLE_DEFAULT },
	{ "cisco_pix_encode", fn_cisco_pix_encode, 0, NULL, 0, ROLES_NONE, ROLE_DEFAULT },
	{ "cisco4_encode", fn_conv_call, 0, NULL, 0, ROLES_NONE, ROLE_DEFAULT },
	{ "ebcdic",        fn_ebcdic,         0, NULL, 0, ROLES_NONE, ROLE_DEFAULT },
	{ "racf_encrypt",  fn_racf_encrypt,   0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "domino5",       fn_domino5,        0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "lotus64_encode",fn_lotus64_encode, 0, NULL, 0, ROLES_NONE, ROLE_DEFAULT },
	{ "domino6",       fn_domino6,        0, NULL, 0, ROLES_NONE, ROLE_DEFAULT },
	{ "oracle7",       fn_oracle7,        0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "axcrypt",       fn_axcrypt,        0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "sap_bcode",     fn_sap_bcode,      0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "as400_des",     fn_as400_des,      0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "racf_kdfaes",   fn_racf_kdfaes,    0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "aes_unwrap",    fn_aes_unwrap,     0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "besder_encode", fn_besder_encode,  0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "dahua_encode",  fn_dahua_encode,   0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "aes_ecb_encrypt", fn_aes_ecb_encrypt, 0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "aes_cbc_encrypt", fn_aes_cbc_encrypt, 0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "aes_cbc_decrypt", fn_aes_cbc_decrypt, 0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "des",           fn_des,            0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "des_block",     fn_des_block,      0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "des3",          fn_des3,           0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "sha512crypt_encode", fn_sha512crypt_encode, 0, NULL, 0, ROLES_NONE, ROLE_DEFAULT },
	{ "bcrypt_encode", fn_bcrypt_encode,  0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "utf16le",       fn_conv_call,        0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "utf16be",       fn_conv_call,        0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "utf7",          fn_conv_call,           0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "zext16",        fn_conv_call,         0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "from_cp1252",   fn_conv_call,    0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "from_cp1251",   fn_conv_call,    0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "length",        fn_length,         0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "ulength",       fn_ulength,        0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "ucut",          fn_ucut,           0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "utrunc",        fn_utrunc,         0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "xor",           fn_xor,            0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "emit",          fn_emit,           0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "and",           fn_and,            0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "or",            fn_or,             0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	/* PBKDF2 (always available via OpenSSL) */
	{ "pbkdf2_sha1",   fn_pbkdf2_sha1,    0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "pbkdf2_sha256", fn_pbkdf2_sha256,  0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "pbkdf2_sha512", fn_pbkdf2_sha512,  0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "pbkdf2_md5",    fn_pbkdf2_md5,     0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
#if !defined(HX_STANDALONE) || defined(HX_HAS_KDF)
	/* KDF + crypt-family registry entries.  Available in hashpipe and in
	 * mdxfind (HX_STANDALONE + HX_HAS_KDF); skipped in the build-only
	 * tools/hx8_to_c standalone build.  Inner nested guard removes the
	 * subset whose backing symbols (pomelo_hash, hp_sm3_*, krb5 CTS, etc.)
	 * are not on mdxfind's link line. */
	{ "bcrypt",        fn_bcrypt,         0, NULL, 0, ROLES_CRYPT,  ROLE_MCF },
	{ "scrypt",        fn_scrypt,         0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "argon2id",      fn_argon2id,       0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "argon2i",       fn_argon2i,        0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "argon2d",       fn_argon2d,        0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "yescrypt",      fn_yescrypt,       0, NULL, 0, ROLES_CRYPT,  ROLE_MCF },
	{ "md5crypt",      fn_md5crypt,       0, NULL, 0, ROLES_CRYPT,  ROLE_MCF },
	{ "apr1",          fn_apr1,           0, NULL, 0, ROLES_CRYPT,  ROLE_MCF },
	{ "sha256crypt",   fn_sha256crypt,    0, NULL, 0, ROLES_CRYPT,  ROLE_MCF },
	{ "sha512crypt",   fn_sha512crypt,    0, NULL, 0, ROLES_CRYPT,  ROLE_MCF },
	{ "descrypt",      fn_descrypt,       0, NULL, 0, ROLES_CRYPT,  ROLE_MCF },
	{ "phpass",        fn_phpass,         0, NULL, 0, ROLES_CRYPT,  ROLE_MCF },
	{ "argon2",        fn_argon2,         0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
#ifndef HX_STANDALONE
	/* hashpipe-only subset: mdxfind doesn't link the backing libs */
	{ "pomelo",        fn_pomelo,         0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "rc4_hmac_md5",  fn_rc4_hmac_md5,   0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "aes128_cts_hmac_sha1", fn_aes128_cts_hmac_sha1, 0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "aes256_cts_hmac_sha1", fn_aes256_cts_hmac_sha1, 0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "sm3crypt",      fn_sm3crypt,       0, NULL, 0, ROLES_CRYPT,  ROLE_MCF },
	{ "gost12_512crypt", fn_gost12_512crypt, 0, NULL, 0, ROLES_CRYPT, ROLE_MCF },
#endif
#endif /* !HX_STANDALONE || HX_HAS_KDF */
	/* Always-available functions (no hashpipe dependency) */
	{ "siphash",       fn_siphash,        8, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "murmur3",       fn_murmur3,        4, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	{ "pbkdf1_sha1",   fn_pbkdf1_sha1,    0, NULL, 0, ROLES_DIGEST, ROLE_HEX },
	/* text programs (hx-functions.md 19.2): "1" or "" */
	{ "valid",         fn_valid,          0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	{ "roundtrip",     fn_roundtrip,      0, NULL, 0, ROLES_NONE,   ROLE_DEFAULT },
	/* lm_cpNNN, one per OEM page with an upper_oem table (hxt_oem_cp) */
#define LMOEM(n) { "lm_cp" #n, fn_lm_oem, 16, NULL, 0, ROLES_DIGEST, ROLE_HEX }
	LMOEM(437), LMOEM(737), LMOEM(775), LMOEM(850), LMOEM(852), LMOEM(855),
	LMOEM(857), LMOEM(858), LMOEM(860), LMOEM(861), LMOEM(862), LMOEM(863),
	LMOEM(864), LMOEM(865), LMOEM(866), LMOEM(869),
#undef LMOEM
};

/* Count initial static entries.  v1.527: KDF + crypt-family split into
 * an "mdxfind + hashpipe" set of 13 entries (bcrypt, phpass, scrypt,
 * argon2*, yescrypt, md5crypt, apr1, sha256crypt, sha512crypt, descrypt,
 * argon2-alias) and a hashpipe-only set of 6 entries (pomelo,
 * rc4_hmac_md5, aes128/256_cts_hmac_sha1, sm3crypt, gost12_512crypt).
 *
 *   tools/hx8_to_c (standalone, no HX_HAS_KDF): 7 + 42 + 21 + 5 + 16
 *   mdxfind        (standalone, HX_HAS_KDF):    7 + 42 + 21 + 13 + 5 + 16
 *   hashpipe       (non-standalone):            42 + 21 + 13 + 6 + 5 + 16
 * (5: siphash murmur3 pbkdf1_sha1 valid roundtrip; the last 16: lm_cp437 ...
 * lm_cp869)
 */
#if defined(HX_STANDALONE) && defined(HX_HAS_KDF)
int hx_func_count = 7 + 42 + 21 + 13 + 5 + 16;
#elif defined(HX_STANDALONE)
int hx_func_count = 7 + 42 + 21 + 5 + 16;
#else
int hx_func_count = 42 + 21 + 13 + 6 + 5 + 16;
#endif

hx_func_entry *hx_func_lookup(const char *name)
{
	int i;
	for (i = 0; i < hx_func_count; i++)
		if (hx_func_table[i].name &&
		    strcmp(hx_func_table[i].name, name) == 0)
			return &hx_func_table[i];
	return NULL;
}

void hx_func_register(const char *name, hx_hashfn fn, int max_out,
                       hx_bridge_fn bridge, int bridge_bytes,
                       uint8_t supported_roles, uint8_t default_role)
{
	if (hx_func_count >= HX_MAX_FUNCS) {
		fprintf(stderr, "hx: function registry full\n");
		return;
	}
	/* don't register duplicates */
	if (hx_func_lookup(name))
		return;
	/* nor a conversion alias (cp1252_to_utf8, nfc, ...): those names belong
	 * to OP_CONVERT (hx-functions.md 18.9), whether or not the registry has
	 * an entry for them */
	{
		hx_inst ci;
		if (hx_convert_alias_inst(name, &ci))
			return;
	}
	hx_func_table[hx_func_count].name            = strdup(name);
	hx_func_table[hx_func_count].fn              = fn;
	hx_func_table[hx_func_count].max_out         = max_out;
	hx_func_table[hx_func_count].bridge          = bridge;
	hx_func_table[hx_func_count].bridge_bytes    = bridge_bytes;
	hx_func_table[hx_func_count].supported_roles = supported_roles;
	hx_func_table[hx_func_count].default_role    = default_role;
	hx_func_count++;
}
