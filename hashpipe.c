/*
 * hashpipe - Multi-threaded hash verification tool
 *
 * Reads lines containing hash:password pairs (optionally with TYPE hints
 * and salts), verifies them by computing the hash from the password,
 * and outputs verified results in mdxfind stdout format.
 * Unresolved lines go to stderr.
 *
 * Uses yarn.c for threading and OpenSSL for hash computation.
 */
static char *Version = "$Header: /Users/dlr/src/mdfind/RCS/hashpipe.c,v 1.3 2026/02/28 23:28:00 dlr Exp dlr $";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include "yarn.h"

#ifdef MACOSX
#include <sys/sysctl.h>
int get_nprocs() {
    int numCPUs;
    size_t len = sizeof(numCPUs);
    int mib[2] = { CTL_HW, HW_NCPU };
    if (sysctl(mib, 2, &numCPUs, &len, NULL, 0))
      return 1;
    return numCPUs;
}
#elif defined(_SC_NPROCESSORS_ONLN)
int get_nprocs() {
    int numCPUs;
    numCPUs = sysconf(_SC_NPROCESSORS_ONLN);
    if (numCPUs <= 0)
      numCPUs = 1;
    return numCPUs;
}
#elif defined(_WIN32)
#include <windows.h>
int get_nprocs() {
    SYSTEM_INFO SysInfo;
    ZeroMemory(&SysInfo, sizeof(SYSTEM_INFO));
    GetSystemInfo(&SysInfo);
    return SysInfo.dwNumberOfProcessors;
}
#else
int get_nprocs() { return 1; }
#endif

/* ---- Constants ---- */

#define MAXLINE (40*1024)
#define BATCH_SIZE 4096
#define BATCH_BUFSIZE (1024 * 1024)
#define MAX_HASH_BYTES 64   /* SHA-512 */
#define MAX_SALT_BYTES 256
#define MAX_CANDIDATES 32

/* ---- Hash type flags ---- */

#define HTF_SALTED      0x01
#define HTF_SALT_AFTER  0x02  /* H(pass + salt) instead of H(salt + pass) */
#define HTF_UC          0x04  /* uppercase variant */
#define HTF_NTLM        0x08  /* UTF-16LE encode password */
#define HTF_COMPOSED    0x10  /* multi-step: MD5MD5PASS, SHA1MD5, MD5SHA1 */
#define HTF_ITER_X0     0x20  /* x=0 convention: no xNN suffix for first match */

/* ---- Hash type registry ---- */

struct hashtype {
    const char *name;
    int hashlen;        /* binary bytes */
    int flags;
    void (*compute)(const unsigned char *pass, int passlen,
                    const unsigned char *salt, int saltlen,
                    unsigned char *dest);
};

/* Forward declarations of compute functions */
static void compute_md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_md4(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_ntlm(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_sha1(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_sha224(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_sha256(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_sha384(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_sha512(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_md5salt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_md5passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_sha1saltpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_sha1passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_sha256saltpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_sha256passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_sha512saltpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_sha512passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_md5md5pass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_sha1md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_md5sha1(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);
static void compute_md5md5pass_colon(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);

static struct hashtype Hashtypes[] = {
    { "MD5",            16, 0,              compute_md5 },
    { "MD5UC",          16, HTF_UC,         compute_md5 },
    { "MD4",            16, 0,              compute_md4 },
    { "NTLM",          16, HTF_NTLM,       compute_ntlm },
    { "SHA1",           20, 0,              compute_sha1 },
    { "SHA1UC",         20, HTF_UC,         compute_sha1 },
    { "SHA224",         28, 0,              compute_sha224 },
    { "SHA256",         32, 0,              compute_sha256 },
    { "SHA384",         48, 0,              compute_sha384 },
    { "SHA512",         64, 0,              compute_sha512 },
    { "MD5SALT",        16, HTF_SALTED | HTF_ITER_X0,        compute_md5salt },
    { "MD5PASSSALT",    16, HTF_SALTED | HTF_SALT_AFTER,    compute_md5passsalt },
    { "SHA1SALTPASS",   20, HTF_SALTED,                     compute_sha1saltpass },
    { "SHA1PASSSALT",   20, HTF_SALTED | HTF_SALT_AFTER,    compute_sha1passsalt },
    { "SHA256SALTPASS", 32, HTF_SALTED,                     compute_sha256saltpass },
    { "SHA256PASSSALT", 32, HTF_SALTED | HTF_SALT_AFTER,    compute_sha256passsalt },
    { "SHA512SALTPASS", 64, HTF_SALTED,                     compute_sha512saltpass },
    { "SHA512PASSSALT", 64, HTF_SALTED | HTF_SALT_AFTER,    compute_sha512passsalt },
    { "MD5MD5PASS",     16, HTF_COMPOSED,   compute_md5md5pass },
    { "MD5MD5PASS",     16, HTF_COMPOSED,   compute_md5md5pass_colon },
    { "SHA1MD5",        20, HTF_COMPOSED,   compute_sha1md5 },
    { "MD5SHA1",        16, HTF_COMPOSED,   compute_md5sha1 },
    { NULL, 0, 0, NULL }
};

#define NUM_HASHTYPES (sizeof(Hashtypes) / sizeof(Hashtypes[0]) - 1)

/* ---- Hex tables (used by compute functions and utilities) ---- */

static const char hextab_lc[16] = "0123456789abcdef";
static const char hextab_uc[16] = "0123456789ABCDEF";

/* ---- Compute functions ---- */

static void compute_md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    MD5(pass, passlen, dest);
}

static void compute_md4(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    MD4(pass, passlen, dest);
}

static void compute_ntlm(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char utf16[MAXLINE * 2];
    int i, u16len = 0;
    const unsigned char *p = pass;
    const unsigned char *end = pass + passlen;

    (void)salt; (void)saltlen;

    /* UTF-8 to UTF-16LE */
    while (p < end) {
        unsigned int cp;
        if (*p < 0x80) {
            cp = *p++;
        } else if ((*p & 0xe0) == 0xc0 && p + 1 < end) {
            cp = (*p & 0x1f) << 6;
            cp |= (p[1] & 0x3f);
            p += 2;
        } else if ((*p & 0xf0) == 0xe0 && p + 2 < end) {
            cp = (*p & 0x0f) << 12;
            cp |= (p[1] & 0x3f) << 6;
            cp |= (p[2] & 0x3f);
            p += 3;
        } else if ((*p & 0xf8) == 0xf0 && p + 3 < end) {
            cp = (*p & 0x07) << 18;
            cp |= (p[1] & 0x3f) << 12;
            cp |= (p[2] & 0x3f) << 6;
            cp |= (p[3] & 0x3f);
            p += 4;
        } else {
            cp = *p++;
        }
        if (cp < 0x10000) {
            utf16[u16len++] = cp & 0xff;
            utf16[u16len++] = (cp >> 8) & 0xff;
        } else {
            /* surrogate pair */
            cp -= 0x10000;
            unsigned int hi = 0xD800 + (cp >> 10);
            unsigned int lo = 0xDC00 + (cp & 0x3ff);
            utf16[u16len++] = hi & 0xff;
            utf16[u16len++] = (hi >> 8) & 0xff;
            utf16[u16len++] = lo & 0xff;
            utf16[u16len++] = (lo >> 8) & 0xff;
        }
    }
    MD4(utf16, u16len, dest);
}

static void compute_sha1(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, dest);
}

static void compute_sha224(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    SHA224(pass, passlen, dest);
}

static void compute_sha256(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    SHA256(pass, passlen, dest);
}

static void compute_sha384(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    SHA384(pass, passlen, dest);
}

static void compute_sha512(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    SHA512(pass, passlen, dest);
}

/* MD5SALT: MD5(hex(MD5(pass)) + salt) — matches mdxfind JOB_MD5SALT */
static void compute_md5salt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    MD5_CTX ctx;

    MD5(pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    hexstr[32] = 0;

    MD5_Init(&ctx);
    MD5_Update(&ctx, hexstr, 32);
    MD5_Update(&ctx, salt, saltlen);
    MD5_Final(dest, &ctx);
}

/* Salted: H(pass + salt) */
static void compute_md5passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, pass, passlen);
    MD5_Update(&ctx, salt, saltlen);
    MD5_Final(dest, &ctx);
}

static void compute_sha1saltpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, salt, saltlen);
    SHA1_Update(&ctx, pass, passlen);
    SHA1_Final(dest, &ctx);
}

static void compute_sha1passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, pass, passlen);
    SHA1_Update(&ctx, salt, saltlen);
    SHA1_Final(dest, &ctx);
}

static void compute_sha256saltpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, salt, saltlen);
    SHA256_Update(&ctx, pass, passlen);
    SHA256_Final(dest, &ctx);
}

static void compute_sha256passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, pass, passlen);
    SHA256_Update(&ctx, salt, saltlen);
    SHA256_Final(dest, &ctx);
}

static void compute_sha512saltpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, salt, saltlen);
    SHA512_Update(&ctx, pass, passlen);
    SHA512_Final(dest, &ctx);
}

static void compute_sha512passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, pass, passlen);
    SHA512_Update(&ctx, salt, saltlen);
    SHA512_Final(dest, &ctx);
}

/* Composed: MD5(hex(MD5(pass)) + pass) — matches mdxfind JOB_MD5MD5PASS variant 1 */
static void compute_md5md5pass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    MD5_CTX ctx;

    (void)salt; (void)saltlen;
    MD5(pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    hexstr[32] = 0;

    MD5_Init(&ctx);
    MD5_Update(&ctx, hexstr, 32);
    MD5_Update(&ctx, pass, passlen);
    MD5_Final(dest, &ctx);
}

/* Composed: MD5(hex(MD5(pass)) + ":" + pass) — matches mdxfind JOB_MD5MD5PASS variant 2 */
static void compute_md5md5pass_colon(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    MD5_CTX ctx;

    (void)salt; (void)saltlen;
    MD5(pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    hexstr[32] = 0;

    MD5_Init(&ctx);
    MD5_Update(&ctx, hexstr, 32);
    MD5_Update(&ctx, ":", 1);
    MD5_Update(&ctx, pass, passlen);
    MD5_Final(dest, &ctx);
}

/* Composed: SHA1(hex(MD5(pass))) */
static void compute_sha1md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    static const char hextab[] = "0123456789abcdef";
    unsigned char md5bin[16];
    char hexstr[33];
    int i;

    (void)salt; (void)saltlen;
    MD5(pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab[md5bin[i] & 0xf];
    }
    hexstr[32] = 0;
    SHA1((unsigned char *)hexstr, 32, dest);
}

/* Composed: MD5(hex(SHA1(pass))) */
static void compute_md5sha1(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    static const char hextab[] = "0123456789abcdef";
    unsigned char sha1bin[20];
    char hexstr[41];
    int i;

    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1bin);
    for (i = 0; i < 20; i++) {
        hexstr[i * 2]     = hextab[(sha1bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab[sha1bin[i] & 0xf];
    }
    hexstr[40] = 0;
    MD5((unsigned char *)hexstr, 40, dest);
}

/* ---- Utility: hex conversion ---- */

/* Binary to lowercase hex */
static char *prmd5(const unsigned char *md5, char *out, int len)
{
    char *ob = out;
    int x;
    unsigned char v;
    for (x = 0; x < len / 2; x++) {
        v = *md5++;
        *ob++ = hextab_lc[(v >> 4) & 0xf];
        *ob++ = hextab_lc[v & 0xf];
    }
    *ob = 0;
    return out;
}

/* Binary to uppercase hex */
static char *prmd5UC(const unsigned char *md5, char *out, int len)
{
    char *ob = out;
    int x;
    unsigned char v;
    for (x = 0; x < len / 2; x++) {
        v = *md5++;
        *ob++ = hextab_uc[(v >> 4) & 0xf];
        *ob++ = hextab_uc[v & 0xf];
    }
    *ob = 0;
    return out;
}

/* Hex char to nibble, -1 on invalid */
static inline int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode hex string to binary. Returns byte count, or -1 on error. */
static int hex2bin(const char *hex, int hexlen, unsigned char *bin)
{
    int i;
    if (hexlen & 1) return -1;
    for (i = 0; i < hexlen; i += 2) {
        int hi = hexval(hex[i]);
        int lo = hexval(hex[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        bin[i / 2] = (hi << 4) | lo;
    }
    return hexlen / 2;
}

/* Check if a string is all hex digits */
static int is_hex(const char *s, int len)
{
    int i;
    for (i = 0; i < len; i++)
        if (hexval(s[i]) < 0) return 0;
    return 1;
}

/* Check if hex string has any uppercase letters */
static int has_uppercase_hex(const char *s, int len)
{
    int i;
    for (i = 0; i < len; i++)
        if (s[i] >= 'A' && s[i] <= 'F') return 1;
    return 0;
}

/* ---- Registry lookups ---- */

static struct hashtype *find_type_by_name(const char *name)
{
    int i;
    for (i = 0; Hashtypes[i].name; i++)
        if (strcasecmp(Hashtypes[i].name, name) == 0)
            return &Hashtypes[i];
    return NULL;
}

/* Find the UC variant of a type (e.g., MD5 → MD5UC) */
static struct hashtype *find_uc_variant(struct hashtype *base)
{
    char ucname[64];
    if (strlen(base->name) + 3 >= sizeof(ucname)) return NULL;
    sprintf(ucname, "%sUC", base->name);
    return find_type_by_name(ucname);
}

/* Get candidate types matching a given binary hash length.
 * Returns count; fills cands[] up to max entries.
 * If have_salt is set, only returns salted types.
 * If !have_salt, only returns unsalted types.
 * Types with hashlen >= hashbytes are returned (supports truncated hashes). */
static int get_candidates_by_hashlen(int hashbytes, int have_salt,
    struct hashtype **cands, int max)
{
    int i, n = 0;
    for (i = 0; Hashtypes[i].name && n < max; i++) {
        if (Hashtypes[i].hashlen < hashbytes) continue;
        if (have_salt) {
            if (!(Hashtypes[i].flags & HTF_SALTED)) continue;
        } else {
            if (Hashtypes[i].flags & HTF_SALTED) continue;
        }
        cands[n++] = &Hashtypes[i];
    }
    return n;
}

/* ---- $HEX[] decode ---- */

/* Decode $HEX[...] password. Returns decoded length, or -1 if not $HEX format. */
static int decode_hex_password(const char *pass, int passlen,
    unsigned char *out, int outmax)
{
    int hexlen;
    if (passlen < 6) return -1;
    if (strncmp(pass, "$HEX[", 5) != 0) return -1;
    if (pass[passlen - 1] != ']') return -1;
    hexlen = passlen - 6;  /* skip $HEX[ and ] */
    if (hexlen <= 0 || hexlen > outmax * 2) return -1;
    return hex2bin(pass + 5, hexlen, out);
}

/* ---- $HEX[] encode: check if password needs encoding ---- */

static int needs_hex(const char *pass, int passlen)
{
    int i;
    for (i = 0; i < passlen; i++) {
        if ((signed char)(pass[i] + 1) < '!')
            return 1;
        if (pass[i] == ':')
            return 1;
    }
    if (passlen >= 5 && strncmp(pass, "$HEX[", 5) == 0)
        return 1;
    return 0;
}

/* ---- Work item and batch ---- */

struct workitem {
    /* Input fields (set by parser) */
    char *line;             /* original line in batch buffer */
    int linelen;
    char *hashstr;          /* hex hash portion */
    int hashlen;            /* hex chars */
    char *salt;             /* salt string (between colons), or NULL */
    int saltlen;
    char *password;         /* password string (original, may be $HEX[]) */
    int passlen;
    char *alt_salt;         /* alternate colon split: salt (for 3+ colons) */
    int alt_saltlen;
    char *alt_password;     /* alternate colon split: password */
    int alt_passlen;
    struct hashtype *hint;  /* type hint, or NULL */
    int hint_iter;          /* iteration count from xNN suffix */
    int hash_is_uc;         /* original hex had uppercase */

    /* Output fields (set by worker) */
    int verified;           /* 1 if verified */
    struct hashtype *match_type;
    int match_iter;         /* iteration count that matched */
};

struct batch {
    struct workitem items[BATCH_SIZE];
    char buf[BATCH_BUFSIZE];
    int count;          /* items in this batch, -1 = poison pill */
    int bufused;
    int hot_type;       /* index into Hashtypes[], -1 = none */
    int hot_iter;
    int hot_saltlen;    /* known salt length, -1 = unknown */
    struct batch *next; /* free list / work queue */
};

/* ---- Globals ---- */

static int Numthreads = 1;
static int Maxiter = 128;
static FILE *Outfp;
static FILE *Errfp;
static int GlobalHotType = -1;
static int GlobalHotIter = 0;
static int GlobalHotSaltlen = -1;  /* known salt length, -1 = unknown */

/* Locks */
static lock *WorkLock;   /* work queue depth */
static lock *OutLock;    /* output serialization */
static lock *ErrLock;    /* error output serialization */
static lock *FreeLock;   /* free batch pool */

/* Queues (singly-linked, protected by respective locks) */
static struct batch *WorkHead, *WorkTail;
static struct batch *FreeHead;

/* Stats */
static long long Totallines;
static long long Verified;
static long long Unresolved;
static long long Nocolon;

/* ---- Batch pool management ---- */

static struct batch *alloc_batch(void)
{
    struct batch *b;

    possess(FreeLock);
    if (FreeHead) {
        b = FreeHead;
        FreeHead = b->next;
        release(FreeLock);
    } else {
        release(FreeLock);
        b = malloc(sizeof(struct batch));
        if (!b) {
            fprintf(stderr, "hashpipe: out of memory\n");
            exit(1);
        }
    }
    b->count = 0;
    b->bufused = 0;
    b->hot_type = GlobalHotType;
    b->hot_iter = GlobalHotIter;
    b->hot_saltlen = GlobalHotSaltlen;
    b->next = NULL;
    return b;
}

static void free_batch(struct batch *b)
{
    possess(FreeLock);
    b->next = FreeHead;
    FreeHead = b;
    twist(FreeLock, BY, 0);
}

/* Enqueue a batch for workers */
static void enqueue_batch(struct batch *b)
{
    possess(WorkLock);
    b->next = NULL;
    if (WorkTail)
        WorkTail->next = b;
    else
        WorkHead = b;
    WorkTail = b;
    twist(WorkLock, BY, 1);
}

/* Dequeue a batch (caller must possess WorkLock) */
static struct batch *dequeue_batch(void)
{
    struct batch *b = WorkHead;
    if (b) {
        WorkHead = b->next;
        if (!WorkHead) WorkTail = NULL;
        b->next = NULL;
    }
    return b;
}

/* ---- Verification engine ---- */

/* Hash binary data using the appropriate function for the given byte length */
static inline void hash_by_len(int hashbytes, const unsigned char *data,
    int datalen, unsigned char *dest)
{
    if (hashbytes == 16)
        MD5(data, datalen, dest);
    else if (hashbytes == 20)
        SHA1(data, datalen, dest);
    else if (hashbytes == 32)
        SHA256(data, datalen, dest);
    else if (hashbytes == 64)
        SHA512(data, datalen, dest);
}

/* Sliding-window match: check if hashbin (hashbytes) matches any
 * contiguous window within computed (fullbytes).
 * Returns 1 on match, 0 otherwise. */
static inline int hash_match(const unsigned char *hashbin, int hashbytes,
    const unsigned char *computed, int fullbytes)
{
    int off;
    for (off = 0; off <= fullbytes - hashbytes; off++) {
        if (memcmp(hashbin, computed + off, hashbytes) == 0)
            return 1;
    }
    return 0;
}

static void verify_item(struct workitem *item, int *hot_type, int *hot_iter)
{
    unsigned char hashbin[MAX_HASH_BYTES];
    unsigned char computed[MAX_HASH_BYTES];
    unsigned char passbuf[MAXLINE];
    unsigned char saltbin[MAX_SALT_BYTES];
    unsigned char iterbuf[MAX_HASH_BYTES];
    const unsigned char *pass;
    int passlen, hashbytes, saltbinlen;
    struct hashtype *cands[MAX_CANDIDATES];
    int ncands, c, iter;

    item->verified = 0;

    /* Decode hex hash to binary */
    hashbytes = hex2bin(item->hashstr, item->hashlen, hashbin);
    if (hashbytes < 0) return;

    /* Decode password: handle $HEX[] */
    passlen = decode_hex_password(item->password, item->passlen, passbuf, MAXLINE);
    if (passlen >= 0) {
        pass = passbuf;
    } else {
        pass = (const unsigned char *)item->password;
        passlen = item->passlen;
    }

    /* Decode salt if present (handle $HEX[] encoding) */
    saltbinlen = 0;
    if (item->salt && item->saltlen > 0) {
        int sdec = decode_hex_password(item->salt, item->saltlen,
                                       saltbin, MAX_SALT_BYTES);
        if (sdec >= 0) {
            saltbinlen = sdec;
        } else {
            saltbinlen = item->saltlen;
            if (saltbinlen > MAX_SALT_BYTES) saltbinlen = MAX_SALT_BYTES;
            memcpy(saltbin, item->salt, saltbinlen);
        }
    }

    /* --- Hot type check (try previously matched type first) --- */
    if (*hot_type >= 0) {
        struct hashtype *ht = &Hashtypes[*hot_type];
        if (ht->hashlen >= hashbytes) {
            if ((ht->flags & HTF_SALTED) && saltbinlen > 0) {
                ht->compute(pass, passlen, saltbin, saltbinlen, computed);
                if (hash_match(hashbin, hashbytes, computed, ht->hashlen)) {
                    item->verified = 1;
                    item->match_type = ht;
                    item->match_iter = (ht->flags & HTF_ITER_X0) ? 0 : 1;
                    return;
                }
            } else if (!(ht->flags & HTF_SALTED)) {
                ht->compute(pass, passlen, NULL, 0, computed);
                if (hash_match(hashbin, hashbytes, computed, ht->hashlen)) {
                    item->verified = 1;
                    item->match_type = ht;
                    item->match_iter = (ht->flags & HTF_ITER_X0) ? 0 : 1;
                    return;
                }
            }
        }
    }

    /* --- Easy pass: try hinted type --- */
    if (item->hint) {
        struct hashtype *ht = item->hint;
        if (ht->hashlen >= hashbytes) {
            if ((ht->flags & HTF_SALTED) && saltbinlen > 0) {
                ht->compute(pass, passlen, saltbin, saltbinlen, computed);
                if (hash_match(hashbin, hashbytes, computed, ht->hashlen)) {
                    item->verified = 1;
                    item->match_type = ht;
                    item->match_iter = (ht->flags & HTF_ITER_X0) ? 0 : 1;
                    *hot_type = ht - Hashtypes;
                    *hot_iter = item->match_iter;
                    return;
                }
            } else if (!(ht->flags & HTF_SALTED)) {
                ht->compute(pass, passlen, NULL, 0, computed);
                if (hash_match(hashbin, hashbytes, computed, ht->hashlen)) {
                    item->verified = 1;
                    item->match_type = ht;
                    item->match_iter = (ht->flags & HTF_ITER_X0) ? 0 : 1;
                    *hot_type = ht - Hashtypes;
                    *hot_iter = item->match_iter;
                    return;
                }
            }
        }
    }

    /* --- Easy pass: try all salted candidates --- */
    if (saltbinlen > 0) {
        ncands = get_candidates_by_hashlen(hashbytes, 1, cands, MAX_CANDIDATES);
        for (c = 0; c < ncands; c++) {
            cands[c]->compute(pass, passlen, saltbin, saltbinlen, computed);
            if (hash_match(hashbin, hashbytes, computed, cands[c]->hashlen)) {
                item->verified = 1;
                item->match_type = cands[c];
                item->match_iter = (cands[c]->flags & HTF_ITER_X0) ? 0 : 1;
                *hot_type = cands[c] - Hashtypes;
                *hot_iter = item->match_iter;
                return;
            }
        }
    }

    /* --- Easy pass: try all unsalted candidates --- */
    ncands = get_candidates_by_hashlen(hashbytes, 0, cands, MAX_CANDIDATES);
    for (c = 0; c < ncands; c++) {
        cands[c]->compute(pass, passlen, NULL, 0, computed);
        if (hash_match(hashbin, hashbytes, computed, cands[c]->hashlen)) {
            item->verified = 1;
            item->match_type = cands[c];
            item->match_iter = (cands[c]->flags & HTF_ITER_X0) ? 0 : 1;
            *hot_type = cands[c] - Hashtypes;
            *hot_iter = item->match_iter;
            return;
        }
    }

    /* --- Hard pass: iterate unsalted non-composed types 2..Maxiter --- */
    ncands = get_candidates_by_hashlen(hashbytes, 0, cands, MAX_CANDIDATES);
    for (c = 0; c < ncands; c++) {
        char hexiter[MAX_HASH_BYTES * 2 + 1];
        int uc, fullbytes;

        if (cands[c]->flags & (HTF_SALTED | HTF_COMPOSED | HTF_NTLM | HTF_UC))
            continue;

        fullbytes = cands[c]->hashlen;  /* full output length for iteration */

        for (uc = 0; uc <= 1; uc++) {
            cands[c]->compute(pass, passlen, NULL, 0, iterbuf);

            for (iter = 2; iter <= Maxiter; iter++) {
                if (uc)
                    prmd5UC(iterbuf, hexiter, fullbytes * 2);
                else
                    prmd5(iterbuf, hexiter, fullbytes * 2);
                cands[c]->compute((unsigned char *)hexiter, fullbytes * 2,
                                  NULL, 0, computed);
                if (hash_match(hashbin, hashbytes, computed, fullbytes)) {
                    item->verified = 1;
                    if (uc) {
                        struct hashtype *uct = find_uc_variant(cands[c]);
                        item->match_type = uct ? uct : cands[c];
                    } else {
                        item->match_type = cands[c];
                    }
                    item->match_iter = iter;
                    *hot_type = item->match_type - Hashtypes;
                    *hot_iter = iter;
                    return;
                }
                memcpy(iterbuf, computed, fullbytes);
            }
        }
    }

    /* --- Hard pass: iterate composed types --- */
    /* Compute x01 via compose function, then iterate outer hash */
    for (c = 0; Hashtypes[c].name; c++) {
        char hexiter[MAX_HASH_BYTES * 2 + 1];
        int fullbytes;

        if (!(Hashtypes[c].flags & HTF_COMPOSED)) continue;
        if (Hashtypes[c].hashlen < hashbytes) continue;

        fullbytes = Hashtypes[c].hashlen;

        /* x01: the composed computation */
        Hashtypes[c].compute(pass, passlen, NULL, 0, iterbuf);

        for (iter = 2; iter <= Maxiter; iter++) {
            prmd5(iterbuf, hexiter, fullbytes * 2);
            hash_by_len(fullbytes, (unsigned char *)hexiter,
                        fullbytes * 2, computed);
            if (hash_match(hashbin, hashbytes, computed, fullbytes)) {
                item->verified = 1;
                item->match_type = &Hashtypes[c];
                item->match_iter = iter;
                *hot_type = c;
                *hot_iter = iter;
                return;
            }
            memcpy(iterbuf, computed, fullbytes);
        }
    }

    /* --- Hard pass: iterate salted types --- */
    /* Salt used only in initial computation, iterations are H(hex(prev)) */
    if (saltbinlen > 0) {
        ncands = get_candidates_by_hashlen(hashbytes, 1, cands, MAX_CANDIDATES);
        for (c = 0; c < ncands; c++) {
            char hexiter[MAX_HASH_BYTES * 2 + 1];
            int fullbytes;

            if (cands[c]->flags & HTF_UC) continue;

            fullbytes = cands[c]->hashlen;

            /* Compute base with salt */
            cands[c]->compute(pass, passlen, saltbin, saltbinlen, iterbuf);

            for (iter = 2; iter <= Maxiter; iter++) {
                prmd5(iterbuf, hexiter, fullbytes * 2);
                hash_by_len(fullbytes, (unsigned char *)hexiter,
                            fullbytes * 2, computed);
                if (hash_match(hashbin, hashbytes, computed, fullbytes)) {
                    item->verified = 1;
                    item->match_type = cands[c];
                    item->match_iter = iter;
                    *hot_type = cands[c] - Hashtypes;
                    *hot_iter = iter;
                    return;
                }
                memcpy(iterbuf, computed, fullbytes);
            }
        }
    }
}

/* ---- Output formatting ---- */

static void format_output(struct workitem *item, char *outbuf, int *outlen)
{
    int pos = 0;
    unsigned char decoded[MAXLINE];
    const char *pass;
    int passlen;
    int dec_len;

    /* Decode $HEX[] on the fly if present */
    dec_len = decode_hex_password(item->password, item->passlen, decoded, MAXLINE);
    if (dec_len >= 0) {
        pass = (const char *)decoded;
        passlen = dec_len;
    } else {
        pass = item->password;
        passlen = item->passlen;
    }

    /* Type name + iteration suffix (only when iter > 0, matches mdxfind) */
    if (item->match_iter > 0)
        pos += sprintf(outbuf + pos, "%sx%02d", item->match_type->name, item->match_iter);
    else
        pos += sprintf(outbuf + pos, "%s", item->match_type->name);

    /* Space + hash (preserve original case) */
    pos += sprintf(outbuf + pos, " %.*s", item->hashlen, item->hashstr);

    /* Salt if present */
    if (item->salt && item->saltlen > 0)
        pos += sprintf(outbuf + pos, ":%.*s", item->saltlen, item->salt);

    /* Colon + password (with $HEX[] if needed) */
    outbuf[pos++] = ':';
    if (needs_hex(pass, passlen)) {
        int i;
        memcpy(outbuf + pos, "$HEX[", 5);
        pos += 5;
        for (i = 0; i < passlen; i++)
            pos += sprintf(outbuf + pos, "%02x", (unsigned char)pass[i]);
        outbuf[pos++] = ']';
    } else {
        memcpy(outbuf + pos, pass, passlen);
        pos += passlen;
    }
    outbuf[pos++] = '\n';
    outbuf[pos] = 0;
    *outlen = pos;
}

/* ---- Worker thread ---- */

static void worker(void *dummy)
{
    struct batch *b;
    char outbuf[MAXLINE * 2];
    char errbuf[MAXLINE * 2];
    int outpos, errpos, i, olen;
    char linebuf[MAXLINE * 2];
    int hot_type, hot_iter, hot_saltlen;
    int hard[BATCH_SIZE];
    int nhard;

    (void)dummy;

    for (;;) {
        possess(WorkLock);
        wait_for(WorkLock, NOT_TO_BE, 0);
        b = dequeue_batch();
        twist(WorkLock, BY, -1);

        if (!b) continue;
        if (b->count < 0) {
            /* Poison pill */
            free_batch(b);
            return;
        }

        outpos = 0;
        errpos = 0;
        hot_type = b->hot_type;
        hot_iter = b->hot_iter;
        hot_saltlen = b->hot_saltlen;
        nhard = 0;

        /* Fast pass: full verify with hot type tried first */
        for (i = 0; i < b->count; i++) {
            /* If we know the salt length and item has alternate split,
             * swap to the split that matches the known salt length */
            if (hot_saltlen >= 0 && b->items[i].alt_password) {
                if (b->items[i].alt_saltlen == hot_saltlen &&
                    b->items[i].saltlen != hot_saltlen) {
                    /* Only alternate matches — swap primary/alternate */
                    char *ts = b->items[i].salt;
                    int tsl = b->items[i].saltlen;
                    char *tp = b->items[i].password;
                    int tpl = b->items[i].passlen;
                    b->items[i].salt = b->items[i].alt_salt;
                    b->items[i].saltlen = b->items[i].alt_saltlen;
                    b->items[i].password = b->items[i].alt_password;
                    b->items[i].passlen = b->items[i].alt_passlen;
                    b->items[i].alt_salt = ts;
                    b->items[i].alt_saltlen = tsl;
                    b->items[i].alt_password = tp;
                    b->items[i].alt_passlen = tpl;
                }
            }

            verify_item(&b->items[i], &hot_type, &hot_iter);

            if (b->items[i].verified) {
                /* Track salt length from successful matches */
                if (b->items[i].salt && b->items[i].saltlen > 0)
                    hot_saltlen = b->items[i].saltlen;
                format_output(&b->items[i], linebuf, &olen);
                if (outpos + olen > (int)sizeof(outbuf) - 1) {
                    possess(OutLock);
                    fwrite(outbuf, 1, outpos, Outfp);
                    release(OutLock);
                    outpos = 0;
                }
                memcpy(outbuf + outpos, linebuf, olen);
                outpos += olen;
            } else if (b->items[i].alt_password) {
                /* Has alternate colon split — defer to hard queue */
                hard[nhard++] = i;
            } else {
                /* Unresolved → stderr */
                int elen = b->items[i].linelen;
                if (errpos + elen + 1 > (int)sizeof(errbuf) - 1) {
                    possess(ErrLock);
                    fwrite(errbuf, 1, errpos, Errfp);
                    release(ErrLock);
                    errpos = 0;
                }
                memcpy(errbuf + errpos, b->items[i].line, elen);
                errpos += elen;
                errbuf[errpos++] = '\n';
            }
        }

        /* Hard pass: retry deferred items with alternate colon split */
        for (i = 0; i < nhard; i++) {
            struct workitem *item = &b->items[hard[i]];

            /* Swap to alternate split */
            item->salt = item->alt_salt;
            item->saltlen = item->alt_saltlen;
            item->password = item->alt_password;
            item->passlen = item->alt_passlen;

            verify_item(item, &hot_type, &hot_iter);

            if (item->verified) {
                if (item->salt && item->saltlen > 0)
                    hot_saltlen = item->saltlen;
                format_output(item, linebuf, &olen);
                if (outpos + olen > (int)sizeof(outbuf) - 1) {
                    possess(OutLock);
                    fwrite(outbuf, 1, outpos, Outfp);
                    release(OutLock);
                    outpos = 0;
                }
                memcpy(outbuf + outpos, linebuf, olen);
                outpos += olen;
            } else {
                /* Unresolved → stderr (original line) */
                int elen = item->linelen;
                if (errpos + elen + 1 > (int)sizeof(errbuf) - 1) {
                    possess(ErrLock);
                    fwrite(errbuf, 1, errpos, Errfp);
                    release(ErrLock);
                    errpos = 0;
                }
                memcpy(errbuf + errpos, item->line, elen);
                errpos += elen;
                errbuf[errpos++] = '\n';
            }
        }

        /* Flush remaining */
        if (outpos > 0) {
            possess(OutLock);
            fwrite(outbuf, 1, outpos, Outfp);
            release(OutLock);
        }
        if (errpos > 0) {
            possess(ErrLock);
            fwrite(errbuf, 1, errpos, Errfp);
            release(ErrLock);
        }

        /* Propagate hot type and salt length to global */
        if (hot_type >= 0) {
            GlobalHotType = hot_type;
            GlobalHotIter = hot_iter;
        }
        if (hot_saltlen >= 0)
            GlobalHotSaltlen = hot_saltlen;

        free_batch(b);
    }
}

/* ---- Input parsing ---- */

/* Copy str into batch buffer, return pointer. Null-terminates. */
static char *batch_strdup(struct batch *b, const char *s, int len)
{
    char *p;
    if (b->bufused + len + 1 > BATCH_BUFSIZE) return NULL;
    p = b->buf + b->bufused;
    memcpy(p, s, len);
    p[len] = 0;
    b->bufused += len + 1;
    return p;
}

/* Parse a single line into a workitem.
 * Returns 1 if parsed OK (has colon and valid hex), 0 otherwise. */
static int parse_line(const char *line, int linelen, struct batch *b, int idx)
{
    struct workitem *item = &b->items[idx];
    const char *p, *end;
    const char *type_start, *type_end;
    const char *hashstart, *colon1, *colon_last;
    char typebuf[64];
    int typelen, iterval;
    int ncolons;

    memset(item, 0, sizeof(*item));

    /* Save full line */
    item->line = batch_strdup(b, line, linelen);
    if (!item->line) return 0;
    item->linelen = linelen;

    end = line + linelen;
    p = line;

    /* Check for TYPE hint: first space separates type from hash:pass */
    type_start = NULL;
    type_end = NULL;
    item->hint = NULL;
    item->hint_iter = 0;

    {
        const char *sp = memchr(p, ' ', linelen);
        if (sp) {
            /* Candidate type hint before the space */
            type_start = p;
            type_end = sp;
            p = sp + 1;

            /* Extract type name, stripping xNN iteration suffix */
            typelen = type_end - type_start;
            if (typelen > 0 && typelen < (int)sizeof(typebuf)) {
                memcpy(typebuf, type_start, typelen);
                typebuf[typelen] = 0;

                /* Check for xNN suffix */
                iterval = 0;
                {
                    char *xp = typebuf + typelen - 1;
                    while (xp > typebuf && isdigit((unsigned char)*xp)) xp--;
                    if (*xp == 'x' && xp > typebuf) {
                        iterval = atoi(xp + 1);
                        *xp = 0;
                    }
                }

                item->hint = find_type_by_name(typebuf);
                if (item->hint) {
                    item->hint_iter = iterval;
                } else {
                    /* Not a valid type name — treat entire line as hash:pass */
                    p = line;
                }
            } else {
                p = line;
            }
        }
    }

    /* Now p points to hash[:salt]:password portion */

    /* Find colons */
    colon1 = NULL;
    colon_last = NULL;
    ncolons = 0;
    {
        const char *c;
        for (c = p; c < end; c++) {
            if (*c == ':') {
                ncolons++;
                if (!colon1) colon1 = c;
                colon_last = c;
            }
        }
    }

    if (ncolons == 0) return 0;  /* No colon → not a hash:pass line */

    /* Hash is from p to first colon */
    hashstart = p;
    item->hashlen = colon1 - hashstart;

    /* Validate hash is hex and even length */
    if (item->hashlen < 2 || (item->hashlen & 1) ||
        !is_hex(hashstart, item->hashlen))
        return 0;

    item->hashstr = batch_strdup(b, hashstart, item->hashlen);
    if (!item->hashstr) return 0;

    /* Check for uppercase hex */
    item->hash_is_uc = has_uppercase_hex(hashstart, item->hashlen);

    item->alt_salt = NULL;
    item->alt_saltlen = 0;
    item->alt_password = NULL;
    item->alt_passlen = 0;

    if (ncolons == 1) {
        /* hash:password */
        item->salt = NULL;
        item->saltlen = 0;
        item->password = batch_strdup(b, colon1 + 1, end - (colon1 + 1));
        item->passlen = end - (colon1 + 1);
    } else if (ncolons == 2) {
        /* hash:salt:password — unambiguous */
        item->salt = batch_strdup(b, colon1 + 1, colon_last - (colon1 + 1));
        item->saltlen = colon_last - (colon1 + 1);
        item->password = batch_strdup(b, colon_last + 1, end - (colon_last + 1));
        item->passlen = end - (colon_last + 1);
    } else {
        /* 3+ colons: ambiguous — create primary + alternate splits */
        const char *colon2 = memchr(colon1 + 1, ':', end - (colon1 + 1));

        /* Primary: short salt (colon1..colon2), password may have colons */
        item->salt = batch_strdup(b, colon1 + 1, colon2 - (colon1 + 1));
        item->saltlen = colon2 - (colon1 + 1);
        item->password = batch_strdup(b, colon2 + 1, end - (colon2 + 1));
        item->passlen = end - (colon2 + 1);

        /* Alternate: long salt (colon1..colon_last), password after last colon */
        if (colon2 != colon_last) {
            item->alt_salt = batch_strdup(b, colon1 + 1, colon_last - (colon1 + 1));
            item->alt_saltlen = colon_last - (colon1 + 1);
            item->alt_password = batch_strdup(b, colon_last + 1, end - (colon_last + 1));
            item->alt_passlen = end - (colon_last + 1);
        }
    }
    if (!item->password) return 0;

    return 1;
}

/* ---- Process input ---- */

static void process_input(FILE *fp)
{
    char linebuf[MAXLINE];
    struct batch *b;
    int len;

    b = alloc_batch();

    while (fgets(linebuf, sizeof(linebuf), fp)) {
        /* Strip \r\n */
        len = strlen(linebuf);
        while (len > 0 && (linebuf[len - 1] == '\n' || linebuf[len - 1] == '\r'))
            len--;
        if (len == 0) continue;

        Totallines++;

        /* Try to parse */
        if (!parse_line(linebuf, len, b, b->count)) {
            /* No colon or invalid → stderr */
            Nocolon++;
            possess(ErrLock);
            fprintf(Errfp, "%.*s\n", len, linebuf);
            release(ErrLock);
            continue;
        }

        b->count++;

        /* Batch full or buffer nearly full → enqueue */
        if (b->count >= BATCH_SIZE ||
            b->bufused > BATCH_BUFSIZE - MAXLINE * 4) {
            enqueue_batch(b);
            b = alloc_batch();
        }
    }

    /* Flush remaining items */
    if (b->count > 0) {
        enqueue_batch(b);
    } else {
        free_batch(b);
    }
}

/* ---- Main ---- */

static void usage(void)
{
    fprintf(stderr,
        "Usage: hashpipe [-t N] [-i N] [-q N] [-o outfile] [-e errfile] [-V] [-h] [file ...]\n"
        "\n"
        "  -t N   Thread count (default: number of CPUs)\n"
        "  -i N   Max iteration count for hard pass (default: 128)\n"
        "  -q N   Quantization (reserved, default: 128)\n"
        "  -o F   Output verified results to file (default: stdout)\n"
        "  -e F   Output unresolved lines to file (default: stderr)\n"
        "  -V     Print version and exit\n"
        "  -h     Print this help\n"
        "\n"
        "Input: lines of [TYPE[xNN] ]hash[:salt]:password\n"
        "Output (stdout): TYPE[xNN] hash[:salt]:password  (verified)\n"
        "Output (stderr): original line  (unresolved)\n"
    );
}

int main(int argc, char **argv)
{
    int opt, i;
    char *outfile = NULL, *errfile = NULL;
    int quantize = 128;

    (void)quantize;
    (void)Version;

    Numthreads = get_nprocs();
    if (Numthreads < 1) Numthreads = 1;

    Outfp = stdout;
    Errfp = stderr;

    while ((opt = getopt(argc, argv, "t:i:q:o:e:Vh")) != -1) {
        switch (opt) {
        case 't':
            Numthreads = atoi(optarg);
            if (Numthreads < 1) Numthreads = 1;
            break;
        case 'i':
            Maxiter = atoi(optarg);
            if (Maxiter < 1) Maxiter = 1;
            break;
        case 'q':
            quantize = atoi(optarg);
            break;
        case 'o':
            outfile = optarg;
            break;
        case 'e':
            errfile = optarg;
            break;
        case 'V':
            fprintf(stderr, "%s\n", Version);
            exit(0);
        case 'h':
            usage();
            exit(0);
        default:
            usage();
            exit(1);
        }
    }

    if (outfile) {
        Outfp = fopen(outfile, "w");
        if (!Outfp) {
            perror(outfile);
            exit(1);
        }
    }
    if (errfile) {
        Errfp = fopen(errfile, "w");
        if (!Errfp) {
            perror(errfile);
            exit(1);
        }
    }

    /* Initialize locks and queues */
    yarn_prefix = "hashpipe";
    WorkLock = new_lock(0);
    OutLock = new_lock(0);
    ErrLock = new_lock(0);
    FreeLock = new_lock(0);
    WorkHead = WorkTail = NULL;
    FreeHead = NULL;

    /* Pre-allocate batch pool */
    {
        int poolsize = Numthreads * 2 + 4;
        for (i = 0; i < poolsize; i++) {
            struct batch *b = malloc(sizeof(struct batch));
            if (!b) {
                fprintf(stderr, "hashpipe: out of memory\n");
                exit(1);
            }
            b->next = FreeHead;
            FreeHead = b;
        }
    }

    /* Launch worker threads */
    for (i = 0; i < Numthreads; i++)
        launch(worker, NULL);

    /* Initialize stats */
    Totallines = 0;
    Verified = 0;
    Unresolved = 0;
    Nocolon = 0;

    /* Process input files or stdin */
    if (optind >= argc) {
        process_input(stdin);
    } else {
        for (i = optind; i < argc; i++) {
            FILE *fp = fopen(argv[i], "r");
            if (!fp) {
                perror(argv[i]);
                continue;
            }
            process_input(fp);
            fclose(fp);
        }
    }

    /* Send poison pills to all workers */
    for (i = 0; i < Numthreads; i++) {
        struct batch *b = alloc_batch();
        b->count = -1;
        enqueue_batch(b);
    }

    /* Wait for all workers to finish */
    join_all();

    /* Flush output */
    if (Outfp != stdout) fclose(Outfp);
    if (Errfp != stderr) fclose(Errfp);

    /* Clean up locks */
    free_lock(WorkLock);
    free_lock(OutLock);
    free_lock(ErrLock);
    free_lock(FreeLock);

    /* Free batch pool */
    while (FreeHead) {
        struct batch *b = FreeHead;
        FreeHead = b->next;
        free(b);
    }

    return 0;
}
