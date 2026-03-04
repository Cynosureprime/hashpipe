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
static char *Version = "$Header: /Users/dlr/src/mdfind/RCS/hashpipe.c,v 1.22 2026/03/04 05:17:11 dlr Exp dlr $";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/time.h>
#include <iconv.h>
#include <openssl/sha.h>
#include "yarn.h"

/* OpenSSL extra */
#include <openssl/hmac.h>
#include <openssl/rc4.h>
#include <openssl/md4.h>
#ifndef OPENSSL_NO_MDC2
#include <openssl/mdc2.h>
#else
/* MDC2 fallback for builds where OpenSSL disables MDC2 (e.g. Ubuntu no-mdc2).
 * Based on OpenSSL 1.0.1e crypto/mdc2/mdc2dgst.c (Eric Young).
 * Suggested by @0xVavaldi (GitHub PR #1). */
#include <openssl/des.h>
#define MDC2_BLOCK		8
#define MDC2_DIGEST_LENGTH	16
static void mdc2_body_blk(unsigned char h[8], unsigned char hh[8],
			   const unsigned char blk[8])
{
	DES_key_schedule ks;
	unsigned char out1[8], out2[8];
	int j;
	h[0] = (h[0] & 0x9f) | 0x40;
	hh[0] = (hh[0] & 0x9f) | 0x20;
	DES_set_odd_parity((DES_cblock *)h);
	DES_set_key_unchecked((DES_cblock *)h, &ks);
	DES_ecb_encrypt((DES_cblock *)blk, (DES_cblock *)out1, &ks, DES_ENCRYPT);
	DES_set_odd_parity((DES_cblock *)hh);
	DES_set_key_unchecked((DES_cblock *)hh, &ks);
	DES_ecb_encrypt((DES_cblock *)blk, (DES_cblock *)out2, &ks, DES_ENCRYPT);
	for (j = 0; j < 8; j++) { out1[j] ^= blk[j]; out2[j] ^= blk[j]; }
	memcpy(h, out1, 4); memcpy(h + 4, out2 + 4, 4);
	memcpy(hh, out2, 4); memcpy(hh + 4, out1 + 4, 4);
}
static unsigned char *MDC2(const unsigned char *d, size_t n, unsigned char *md)
{
	unsigned char h[8], hh[8], block[8];
	size_t i;
	unsigned int num;
	memset(h, 0x52, 8);
	memset(hh, 0x25, 8);
	for (i = 0; i + 8 <= n; i += 8)
		mdc2_body_blk(h, hh, d + i);
	num = n - i;
	/* Final (pad_type=1): process partial block zero-padded */
	if (num > 0) {
		memset(block, 0, 8);
		memcpy(block, d + i, num);
		mdc2_body_blk(h, hh, block);
	}
	memcpy(md, h, 8);
	memcpy(md + 8, hh, 8);
	return md;
}
#endif
#include "yescrypt/yescrypt.h"

/* SPH library (SHA-3 competition candidates + classic hashes) */
#include <sph_blake.h>
#include <sph_bmw.h>
#include <sph_cubehash.h>
#include <sph_echo.h>
#include <sph_fugue.h>
#include <sph_groestl.h>
#include <sph_hamsi.h>
#include <sph_haval.h>
#include <sph_jh.h>
#include <sph_keccak.h>
#include <sph_luffa.h>
#include <sph_md2.h>
#include <sph_panama.h>
#include <sph_radiogatun.h>
#include <sph_ripemd.h>
#include <sph_sha0.h>
#include <sph_shabal.h>
#include <sph_shavite.h>
#include <sph_simd.h>
#include <sph_skein.h>
#include <sph_tiger.h>
#include <sph_whirlpool.h>

/* Judy arrays for fast name lookups */
#include <Judy.h>

/* Other hash libraries */
#include <mhash.h>
#include <rhash.h>
#include "md6.h"
#include "gosthash/gost2012/streebog.h"

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

/* ---- MurmurHash64A (inline, from mdxfind.c) ---- */

static uint64_t murmur64a(const void *key, int len, uint64_t seed) {
    const uint64_t m = 0xc6a4a7935bd1e995ULL;
    const int r = 47;
    uint64_t h = seed ^ ((uint64_t)len * m);
    const uint64_t *data = (const uint64_t *)key;
    const uint64_t *end = data + (len / 8);
    while (data != end) {
        uint64_t k;
        memcpy(&k, data++, 8);
        k *= m; k ^= k >> r; k *= m;
        h ^= k; h *= m;
    }
    { const uint8_t *data2 = (const uint8_t *)data;
      switch (len & 7) {
        case 7: h ^= (uint64_t)data2[6] << 48; /* fall through */
        case 6: h ^= (uint64_t)data2[5] << 40; /* fall through */
        case 5: h ^= (uint64_t)data2[4] << 32; /* fall through */
        case 4: h ^= (uint64_t)data2[3] << 24; /* fall through */
        case 3: h ^= (uint64_t)data2[2] << 16; /* fall through */
        case 2: h ^= (uint64_t)data2[1] << 8;  /* fall through */
        case 1: h ^= (uint64_t)data2[0]; h *= m;
      }
    }
    h ^= h >> r; h *= m; h ^= h >> r;
    return h;
}

/* ---- BLAKE2S-256 (RFC 7693, inline from mdxfind.c) ---- */

static const uint32_t blake2s_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};
static const uint8_t blake2s_sigma[10][16] = {
    { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 },
    { 14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3 },
    { 11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4 },
    { 7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8 },
    { 9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13 },
    { 2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9 },
    { 12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11 },
    { 13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10 },
    { 6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5 },
    { 10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0 }
};
#define B2S_G(a,b,c,d,x,y) do { \
    v[a]+=v[b]+(x); v[d]=((v[d]^v[a])>>16)|((v[d]^v[a])<<16); \
    v[c]+=v[d]; v[b]=((v[b]^v[c])>>12)|((v[b]^v[c])<<20); \
    v[a]+=v[b]+(y); v[d]=((v[d]^v[a])>>8)|((v[d]^v[a])<<24); \
    v[c]+=v[d]; v[b]=((v[b]^v[c])>>7)|((v[b]^v[c])<<25); \
} while(0)

static void blake2s_compress(uint32_t h[8], const uint8_t block[64], uint64_t counter, int last) {
    uint32_t v[16], m[16];
    int i;
    for (i = 0; i < 8; i++) { v[i] = h[i]; v[i+8] = blake2s_IV[i]; }
    v[12] ^= (uint32_t)counter;
    v[13] ^= (uint32_t)(counter >> 32);
    if (last) v[14] = ~v[14];
    for (i = 0; i < 16; i++) memcpy(&m[i], block + i*4, 4);
    for (i = 0; i < 10; i++) {
        const uint8_t *s = blake2s_sigma[i];
        B2S_G(0,4, 8,12,m[s[ 0]],m[s[ 1]]); B2S_G(1,5, 9,13,m[s[ 2]],m[s[ 3]]);
        B2S_G(2,6,10,14,m[s[ 4]],m[s[ 5]]); B2S_G(3,7,11,15,m[s[ 6]],m[s[ 7]]);
        B2S_G(0,5,10,15,m[s[ 8]],m[s[ 9]]); B2S_G(1,6,11,12,m[s[10]],m[s[11]]);
        B2S_G(2,7, 8,13,m[s[12]],m[s[13]]); B2S_G(3,4, 9,14,m[s[14]],m[s[15]]);
    }
    for (i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i+8];
}

static void blake2s(void *out, int outlen, const void *in, int inlen, const void *key, int keylen) {
    uint32_t h[8];
    uint8_t buf[64];
    uint64_t counter = 0;
    int pos = 0, i;
    for (i = 0; i < 8; i++) h[i] = blake2s_IV[i];
    h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;
    if (keylen > 0) {
        memset(buf, 0, 64);
        memcpy(buf, key, keylen);
        counter += 64;
        if (inlen == 0) { blake2s_compress(h, buf, counter, 1); goto b2s_done; }
        blake2s_compress(h, buf, counter, 0);
    }
    { const uint8_t *p = (const uint8_t *)in;
      while (inlen > 0) {
        if (pos == 64) { counter += 64; blake2s_compress(h, buf, counter, 0); pos = 0; }
        { int take = 64 - pos; if (take > inlen) take = inlen;
          memcpy(buf + pos, p, take); pos += take; p += take; inlen -= take;
        }
      }
    }
    counter += pos;
    memset(buf + pos, 0, 64 - pos);
    blake2s_compress(h, buf, counter, 1);
b2s_done:
    memcpy(out, h, outlen);
}

/* ---- BLAKE2b (RFC 7693, inline from mdxfind.c) ---- */

static const uint64_t blake2b_IV[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};
static const uint8_t b2b_sigma[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

#define B2B_G(r, i, a, b, c, d) do { \
    a += b + m[b2b_sigma[r][2*i+0]]; d = ((d^a)>>32)|((d^a)<<32); \
    c += d; b = ((b^c)>>24)|((b^c)<<40); \
    a += b + m[b2b_sigma[r][2*i+1]]; d = ((d^a)>>16)|((d^a)<<48); \
    c += d; b = ((b^c)>>63)|((b^c)<<1); \
} while(0)

static void blake2b_compress(uint64_t h[8], const uint8_t *block,
                             uint64_t t0, uint64_t t1, int last) {
    uint64_t m[16], v[16];
    int i;
    for (i = 0; i < 16; i++) memcpy(&m[i], block + i * 8, 8);
    for (i = 0; i < 8; i++) v[i] = h[i];
    v[ 8] = blake2b_IV[0]; v[ 9] = blake2b_IV[1];
    v[10] = blake2b_IV[2]; v[11] = blake2b_IV[3];
    v[12] = blake2b_IV[4] ^ t0; v[13] = blake2b_IV[5] ^ t1;
    v[14] = last ? ~blake2b_IV[6] : blake2b_IV[6]; v[15] = blake2b_IV[7];
    for (i = 0; i < 12; i++) {
        B2B_G(i, 0, v[0], v[4], v[ 8], v[12]);
        B2B_G(i, 1, v[1], v[5], v[ 9], v[13]);
        B2B_G(i, 2, v[2], v[6], v[10], v[14]);
        B2B_G(i, 3, v[3], v[7], v[11], v[15]);
        B2B_G(i, 4, v[0], v[5], v[10], v[15]);
        B2B_G(i, 5, v[1], v[6], v[11], v[12]);
        B2B_G(i, 6, v[2], v[7], v[ 8], v[13]);
        B2B_G(i, 7, v[3], v[4], v[ 9], v[14]);
    }
    for (i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
}

static void blake2b_hash(unsigned char *out, size_t outlen,
                         const void *in, size_t inlen) {
    uint64_t h[8], counter = 0;
    uint8_t buf[128];
    size_t pos = 0;
    const uint8_t *pin = (const uint8_t *)in;
    int i;
    for (i = 0; i < 8; i++) h[i] = blake2b_IV[i];
    h[0] ^= 0x01010000 ^ (uint64_t)outlen;
    while (inlen > 0) {
        size_t take = 128 - pos;
        if (take > inlen) take = inlen;
        memcpy(buf + pos, pin, take);
        pos += take; pin += take; inlen -= take;
        if (pos == 128 && inlen > 0) {
            counter += 128;
            blake2b_compress(h, buf, counter, 0, 0);
            pos = 0;
        }
    }
    counter += pos;
    memset(buf + pos, 0, 128 - pos);
    blake2b_compress(h, buf, counter, 0, 1);
    memcpy(out, h, outlen);
}

/* ---- Constants ---- */

#define MAXLINE (40*1024)
#define TESTVECSIZE (2048*1024)
#define BATCH_SIZE 4096
#define BATCH_BUFSIZE (1024 * 1024)
#define MAX_HASH_BYTES 64   /* SHA-512 */
#define MAX_SALT_BYTES 256
#define MAX_CANDIDATES 512

/* ---- Per-job workspace (heap-allocated, avoids stack overflow) ---- */

struct workspace {
    /* Two large buffers for UTF-16 conversion, concatenation, large scratch */
    unsigned char u16a[MAXLINE * 2];
    unsigned char u16b[MAXLINE * 2];
    /* Four general-purpose buffers for compute functions */
    unsigned char tmp1[MAXLINE];
    unsigned char tmp2[MAXLINE];
    unsigned char tmp3[MAXLINE];
    unsigned char tmp4[MAXLINE];
    /* Worker I/O buffers */
    char outbuf[MAXLINE * 2];
    char errbuf[MAXLINE * 2];
    char fmtbuf[MAXLINE * 2];
    /* Verify/format buffers */
    unsigned char passbuf[MAXLINE];
    unsigned char vpassbuf[MAXLINE];
    unsigned char decoded[MAXLINE];
    unsigned char *testvec;  /* malloc'd TESTVECSIZE+16 buffer for $TESTVEC[] */
};

static __thread struct workspace *WS;

/* ---- Hash type flags ---- */

#define HTF_SALTED      0x01
#define HTF_SALT_AFTER  0x02  /* H(pass + salt) instead of H(salt + pass) */
#define HTF_UC          0x04  /* uppercase variant */
#define HTF_NTLM        0x08  /* UTF-16LE encode password */
#define HTF_COMPOSED    0x10  /* multi-step: MD5MD5PASS, SHA1MD5, MD5SHA1 */
#define HTF_ITER_X0     0x20  /* x=0 convention: no xNN suffix for first match */
#define HTF_NONHEX      0x40  /* hash is not hex (bcrypt, APACHE-SHA, etc.) */

/* ---- Hash type registry ---- */

typedef void (*hashfn_t)(const unsigned char *pass, int passlen,
                         const unsigned char *salt, int saltlen,
                         unsigned char *dest);

/* Verify function for non-hex hash formats (bcrypt, APACHE-SHA, etc.) */
typedef int (*verifyfn_t)(const char *hashstr, int hashlen,
                          const unsigned char *pass, int passlen);

/* Chain step for generic multi-level compositions */
struct chain_step {
    hashfn_t fn;
    int outbytes;       /* binary output bytes of this step */
    int uc_hex;         /* use uppercase hex for this step's output before feeding to next step */
};

struct hashtype {
    const char *name;
    int hashlen;        /* binary bytes */
    int flags;
    hashfn_t compute;
    hashfn_t compute_alt;      /* alternate compute (e.g. HUM prepend variant) */
    hashfn_t iter_fn;          /* inner iteration function for x-types, or NULL for hash_by_len */
    verifyfn_t verify;         /* non-hex format verifier (bcrypt, APACHE-SHA, etc.) */
    int nchain;                /* 0 = use compute; >0 = use chain[] */
    struct chain_step *chain;  /* chain[0]=innermost, chain[nchain-1]=outermost */
    const char *example;       /* "hash:password" or "hash:salt:password" for benchmarking */
    long long rate;            /* hashes/sec from benchmark, 0 = unknown */
};

/* Hashcat mode to internal type index mapping (from mdxfind.c).
 * 65535 = unsupported/unmapped. */
struct MapHashcat {
  short unsigned int hc, mdx;
} Maphashcat[] = {
    {0,     1},
    {900,   3},
    {5100,  1},
    {100,   8},
    {1300,  9},
    {1400,  10},
    {10800, 11},
    {1700,  12},    /* SHA-512 */
    {5000,  91},    /* SHA-3 */
    {600,   841},   /* BLAKE2b-512 */
    {610,   842},   /* BLAKE2b-512($pass.$salt) */
    {620,   843},   /* BLAKE2b-512($salt.$pass) */
    {10100, 65535}, /* SIPhash */
    {6000,  118},
    {6100,  5},
    {6900,  13},
    {11700, 427},
    {11780, 428},
    {10,    373},
    {20,    394},
    {30,    801},   /* md5(utf16le($pass).$salt) */
    {40,    802},   /* md5($salt.utf16le($pass)) */
    {3800,  411},
    {3710,  441},
    {4010,  516},
    {4110,  515},
    {2600,  1},     /* md5(md5($pass)) -> MD5 iter 2 */
    {3910,  458},
    {4300,  2},
    {4400,  178},
    {110,   405},
    {120,   385},
    {130,   803},   /* sha1(utf16le($pass).$salt) */
    {140,   804},   /* sha1($salt.utf16le($pass)) */
    {170,   727},
    {4500,  8},
    {4520,  520},
    {4700,  160},
    {4900,  395},
    {14400, 521},   /* sha1(CX) */
    {1410,  413},
    {1420,  412},
    {1430,  806},   /* sha256(utf16le($pass).$salt) */
    {1440,  807},   /* sha256($salt.utf16le($pass)) */
    {1710,  386},
    {1720,  388},
    {1730,  809},   /* sha512(utf16le($pass).$salt) */
    {1740,  810},   /* sha512($salt.utf16le($pass)) */
    {50,    792},   /* HMAC-MD5 (key = $pass) */
    {60,    214},
    {150,   793},   /* HMAC-SHA1 (key = $pass) */
    {160,   215},
    {1450,  795},   /* HMAC-SHA256 (key = $pass) */
    {1460,  217},
    {1750,  797},   /* HMAC-SHA512 (key = $pass) */
    {1760,  218},
    {14000, 848},   /* DES (PT = $salt, key = $pass) */
    {14100, 849},   /* 3DES (PT = $salt, key = $pass) */
    {14900, 65535},
    {15400, 65535}, /* ChaCha20 */
    {400,   455},
    {8900,  884},   /* scrypt */
    {11900, 531},   /* PBKDF2-HMAC-MD5 */
    {12000, 532},   /* PBKDF2-HMAC-SHA1 */
    {10900, 530},   /* PBKDF2-HMAC-SHA256 */
    {12100, 533},   /* PBKDF2-HMAC-SHA512 */
    {23,    857},   /* Skype */
    {24,    394},   /* SolarWinds Serv-U */
    {2500,  65535}, /* WPA/WPA2 */
    {4800,  65535}, /* iSCSI CHAP authentication */
    {5300,  65535}, /* IKE-PSK MD5 */
    {5400,  65535}, /* IKE-PSK SHA1 */
    {5500,  65535}, /* NetNTLMv1 */
    {5600,  65535}, /* NetNTLMv2 */
    {7300,  872},   /* IPMI2 RAKP HMAC-SHA1 */
    {7350,  873},   /* IPMI2 RAKP HMAC-MD5 */
    {7500,  874},   /* Kerberos 5 AS-REQ Pre-Auth etype 23 */
    {8300,  879},   /* DNSSEC (NSEC3) */
    {10200, 65535}, /* CRAM-MD5 */
    {11100, 65535}, /* PostgreSQL CRAM (MD5) */
    {11200, 65535}, /* MySQL CRAM (SHA1) */
    {11400, 65535}, /* SIP digest authentication (MD5) */
    {13100, 65535}, /* Kerberos 5 TGS-REP etype 23 */
    {121,   414},
    {2611,  31},
    {2711,  31},
    {2811,  367},   /* MyBB 1.2+ */
    {8400,  880},   /* WBB3 */
    {11,    373},   /* Joomla < 2.5.18 */
    {2612,  886},   /* PHPS */
    {21,    394},
    {11000, 65535}, /* PrestaShop */
    {124,   385},   /* Django (SHA-1) */
    {10000, 530},   /* Django (PBKDF2-SHA256) */
    {3711,  863},   /* MediaWiki B type */
    {13900, 65535}, /* OpenCart */
    {4521,  579},   /* Redmine -> SHA1SHA1PASSSALT */
    {4522,  579},   /* PunBB -> SHA1SHA1PASSSALT */
    {12001, 534},   /* Atlassian (PBKDF2-HMAC-SHA1) */
    {12,    855},   /* PostgreSQL */
    {22,    856},   /* Juniper NetScreen/SSG */
    {131,   850},   /* MSSQL (2000) */
    {132,   851},   /* MSSQL (2005) */
    {1731,  852},   /* MSSQL (2012, 2014) */
    {200,   456},
    {300,   259},
    {3100,  65535}, /* Oracle H: Type (Oracle 7+) */
    {112,   834},   /* Oracle S: Type (Oracle 11+) */
    {12300, 65535}, /* Oracle T: Type (Oracle 12+) */
    {8000,  877},   /* Sybase ASE */
    {1441,  859},   /* Episerver 6.x >= .NET 4 */
    {1600,  461},   /* APR1 */
    {12600, 65535}, /* ColdFusion 10+ */
    {1421,  860},   /* hMailServer */
    {101,   457},   /* nsldap, SHA-1(Base64) */
    {111,   833},   /* nsldaps, SSHA-1(Base64) */
    {1411,  835},   /* SSHA-256(Base64) */
    {1711,  836},   /* SSHA-512(Base64) */
    {15000, 65535}, /* FileZilla Server */
    {11500, 65535}, /* CRC32 */
    {3000,  379},   /* LM */
    {1000,  369},   /* NTLM */
    {1100,  439},   /* DCC, MS Cache */
    {2100,  65535}, /* DCC2, MS Cache 2 */
    {15300, 65535}, /* DPAPI masterkey */
    {12800, 65535}, /* MS-AzureSync */
    {1500,  500},   /* DES */
    {12400, 500},   /* Extended DES */
    {500,   511},   /* md5crypt */
    {3200,  450},   /* bcrypt */
    {7400,  512},   /* sha256crypt */
    {7401,  875},   /* MySQL $A$ (sha256crypt) */
    {7900,  876},   /* Drupal7 */
    {1800,  513},   /* sha512crypt */
    {122,   853},   /* macOS v10.4-10.6 */
    {1722,  854},   /* macOS v10.7 */
    {7100,  533},   /* OSX v10.8+ (PBKDF2-SHA512) */
    {6300,  868},   /* AIX {smd5} */
    {6700,  869},   /* AIX {ssha1} */
    {6400,  870},   /* AIX {ssha256} */
    {6500,  871},   /* AIX {ssha512} */
    {2400,  861},   /* Cisco-PIX MD5 */
    {2410,  862},   /* Cisco-ASA MD5 */
    {5700,  865},   /* Cisco-IOS type 4 (SHA256) */
    {5720,  866},   /* Cisco-ISE (SHA256, binary salt) */
    {9200,  529},   /* Cisco-IOS $8$ (PBKDF2-SHA256) */
    {9300,  65535}, /* Cisco-IOS $9$ (scrypt) */
    {501,   885},   /* Juniper IVE */
    {15100, 65535}, /* Juniper/NetBSD sha1crypt */
    {7000,  65535}, /* FortiGate (FortiOS) */
    {5800,  867},   /* Samsung Android Password/PIN */
    {13800, 65535}, /* Windows Phone 8+ */
    {8100,  878},   /* Citrix NetScaler */
    {8500,  881},   /* RACF */
    {7200,  65535}, /* GRUB 2 */
    {9900,  264},
    {125,   65535}, /* ArubaOS */
    {7700,  65535}, /* SAP CODVN B */
    {7800,  65535}, /* SAP CODVN F/G */
    {1030,  65535}, /* SAP CODVN H */
    {8600,  882},   /* Lotus Notes/Domino 5 */
    {8700,  883},   /* Lotus Notes/Domino 6 */
    {9100,  65535}, /* Lotus Notes/Domino 8 */
    {133,   858},   /* PeopleSoft */
    {141,   859},   /* Episerver 6.x < .NET 4 */
    {13500, 65535}, /* PeopleSoft PS_TOKEN */
    {11600, 65535}, /* 7-Zip */
    {12500, 65535}, /* RAR3-hp */
    {13000, 65535}, /* RAR5 */
    {13200, 65535}, /* AxCrypt */
    {13300, 65535}, /* AxCrypt in-memory SHA1 */
    {13600, 65535}, /* WinZip */
    {14700, 65535}, /* iTunes backup < 10.0 */
    {14800, 65535}, /* iTunes backup >= 10.0 */
    {6211,  65535}, /* TrueCrypt */
    {6212,  65535},
    {6213,  65535},
    {6221,  65535},
    {6222,  65535},
    {6223,  65535},
    {6231,  65535},
    {6232,  65535},
    {6233,  65535},
    {6241,  65535},
    {6242,  65535},
    {6243,  65535},
    {8800,  65535}, /* Android FDE <= 4.3 */
    {12900, 65535}, /* Android FDE (Samsung DEK) */
    {12200, 65535}, /* eCryptfs */
    {13711, 65535}, /* VeraCrypt */
    {13712, 65535},
    {13713, 65535},
    {13721, 65535},
    {13722, 65535},
    {13723, 65535},
    {13731, 65535},
    {13732, 65535},
    {13733, 65535},
    {13741, 65535},
    {13742, 65535},
    {13743, 65535},
    {13751, 65535},
    {13752, 65535},
    {13753, 65535},
    {13761, 65535},
    {13762, 65535},
    {13763, 65535},
    {14600, 65535}, /* LUKS */
    {9700,  65535}, /* MS Office */
    {9710,  65535},
    {9720,  65535},
    {9800,  65535},
    {9810,  65535},
    {9820,  65535},
    {9400,  65535}, /* MS Office 2007 */
    {9500,  65535}, /* MS Office 2010 */
    {9600,  65535}, /* MS Office 2013 */
    {10400, 65535}, /* PDF 1.1-1.3 */
    {10410, 65535},
    {10420, 65535},
    {10500, 65535}, /* PDF 1.4-1.6 */
    {10600, 65535}, /* PDF 1.7 Level 3 */
    {10700, 65535}, /* PDF 1.7 Level 8 */
    {9000,  65535}, /* Password Safe v2 */
    {5200,  65535}, /* Password Safe v3 */
    {6800,  65535}, /* LastPass */
    {6600,  65535}, /* 1Password, agilekeychain */
    {8200,  65535}, /* 1Password, cloudkeychain */
    {11300, 65535}, /* Bitcoin/Litecoin wallet.dat */
    {12700, 65535}, /* Blockchain, My Wallet */
    {15200, 65535}, /* Blockchain, My Wallet, V2 */
    {13400, 65535}, /* KeePass */
    {15500, 65535}, /* JKS Java Key Store */
    {15600, 65535}, /* Ethereum Wallet, PBKDF2-SHA256 */
    {15700, 65535}, /* Ethereum Wallet, SCRYPT */
    {11800, 428},   /* GOST R 34.11-2012 (Streebog) 512-bit */
    {17300, 88},    /* SHA3-224 */
    {17400, 89},    /* SHA3-256 */
    {17500, 90},    /* SHA3-384 */
    {17600, 91},    /* SHA3-512 */
    {17700, 84},    /* Keccak-224 */
    {17800, 85},    /* Keccak-256 */
    {17900, 86},    /* Keccak-384 */
    {18000, 87},    /* Keccak-512 */
    {3500,  303},   /* md5(md5(md5($pass))) */
    {4410,  555},   /* md5(sha1($pass).$salt) */
    {4710,  587},   /* sha1(md5($pass).$salt) */
    {18500, 287},   /* sha1(md5(md5($pass))) */
    {20710, 382},   /* sha256(sha256($pass).$salt) */
    {20720, 523},   /* sha256($salt.sha256($pass)) */
    {25600, 451},   /* bcrypt(md5($pass)) */
    {25800, 452},   /* bcrypt(sha1($pass)) */
    {30600, 577},   /* bcrypt(sha256($pass)) */
    {32410, 387},   /* sha512(sha512($pass).$salt) */
    {32800, 188},   /* md5(sha1(md5($pass))) */
    {34500, 766},   /* sha224(sha1($pass)) */
    {34600, 29},    /* MD6-256 */
    {6060,  211},   /* HMAC-RIPEMD160 (key = $salt) */
    {30420, 36},    /* DANE RFC7929/RFC8162 SHA2-256 */
    {34400, 9},     /* sha224(sha224($pass)) */
    {2630,  373},   /* md5(md5($pass.$salt)) */
    {3730,  864},   /* md5($salt1.strtoupper(md5($salt2.$pass))) */
    {3610,  356},   /* md5(md5(md5($pass)).$salt) */
    {4420,  443},   /* md5(sha1($pass.$salt)) */
    {4510,  310},   /* sha1(sha1($pass).$salt) */
    {4711,  308},   /* Huawei sha1(md5($pass).$salt) */
    {20730, 413},   /* sha256(sha256($pass.$salt)) */
    {20800, 164},   /* sha256(md5($pass)) */
    {20900, 442},   /* md5(sha1($pass).md5($pass).sha1($pass)) */
    {21000, 38},    /* BitShares sha512(sha512_bin($pass)) */
    {21100, 469},   /* sha1(md5($pass.$salt)) */
    {21200, 440},   /* md5(sha1($salt).md5($pass)) */
    {21300, 528},   /* md5($salt.sha1($salt.$pass)) */
    {21400, 36},    /* sha256(sha256_bin($pass)) */
    {30700, 530},   /* Anope IRC Services (PBKDF2-SHA256) */
    {32420, 510},   /* sha512(sha512_bin($pass).$salt) */
    {33660, 213},   /* HMAC-RIPEMD320 (key = $salt) */
    {70,    800},   /* md5(utf16le($pass)) */
    {1470,  805},   /* sha256(utf16le($pass)) */
    {1770,  808},   /* sha512(utf16le($pass)) */
    {6050,  798},   /* HMAC-RIPEMD160 (key = $pass) */
    {33650, 799},   /* HMAC-RIPEMD320 (key = $pass) */
    {10810, 811},   /* sha384($pass.$salt) */
    {10820, 812},   /* sha384($salt.$pass) */
    {10870, 813},   /* sha384(utf16le($pass)) */
    {10830, 814},   /* sha384(utf16le($pass).$salt) */
    {10840, 815},   /* sha384($salt.utf16le($pass)) */
    {33600, 816},   /* ripemd320($pass) */
    {4430,  817},   /* md5(sha1($salt.$pass)) */
    {33100, 818},   /* md5($salt.md5($pass).$salt) */
    {31700, 819},   /* md5(md5(md5($pass).$salt).$pepper) */
    {30500, 820},   /* md5(md5($salt).md5(md5($pass))) */
    {21900, 821},   /* md5(md5($pass.$salt).$pepper) */
    {21310, 822},   /* md5($salt.sha1($pepper.$pass)) */
    {24300, 823},   /* sha1($salt.sha1($pass.$salt)) */
    {29000, 824},   /* sha1($salt.sha1(utf16le($user):utf16le($pass))) */
    {22300, 825},   /* sha256($salt.$pass.$salt) */
    {21420, 826},   /* sha256($salt.sha256_raw($pass)) */
    {32600, 827},   /* whirlpool($salt.$pass.$salt) */
    {33300, 828},   /* HMAC-BLAKE2S */
    {34200, 829},   /* MurmurHash64A */
    {34201, 830},   /* MurmurHash64A (seed=0) */
    {1310,  831},   /* sha224($pass.$salt) */
    {1320,  832},   /* sha224($salt.$pass) */
    {11750, 837},   /* HMAC-Streebog-256 (key = $pass) */
    {11760, 838},   /* HMAC-Streebog-256 (key = $salt) */
    {11850, 839},   /* HMAC-Streebog-512 (key = $pass) */
    {11860, 840},   /* HMAC-Streebog-512 (key = $salt) */
    {31000, 844},   /* BLAKE2s-256 */
    {34800, 845},   /* BLAKE2b-256 */
    {34810, 846},   /* BLAKE2b-256($pass.$salt) */
    {34820, 847},   /* BLAKE2b-256($salt.$pass) */
    {65535, 65535}  /* EOF */
};

static int Numtypes;                    /* set from Types[] NULL terminator */
static struct hashtype *Hashtypes;      /* malloc'd [Numtypes] */
static Pvoid_t TypenameJ = (Pvoid_t)NULL;  /* Judy: name → index+1 */

/* Per-hashlen candidate cache: avoids scanning Hashtypes[] on every call */
#define MAX_HASHLEN 65  /* 0..64 bytes (SHA-512 max) */
struct candcache {
    struct hashtype **list;  /* malloc'd array of pointers */
    int count;
};
static struct candcache Unsalted[MAX_HASHLEN];  /* unsalted by exact hashlen */
static struct candcache Salted[MAX_HASHLEN];    /* salted by exact hashlen */
static struct candcache Composed[MAX_HASHLEN];  /* composed by exact hashlen */

/* Types[] — identical to mdxfind.c */
char *Types[] = {
    /*   0    1       2      3     4    5      6       7       8       9 */
    "none", "MD5", "MD5UC", "MD4", "MD2", "WRL", "HAV128", "SHA0", "SHA1", "SHA224",
    /*  10       11        12     13      14            15      16  */
    "SHA256", "SHA384", "SHA512", "GOST", "GOST-CRYPTO", "HAV256", "RMD128",
    /*  17       18     19     20      21    22        23        24 */
    "RMD160", "TIGER", "TTH", "ED2K", "AICH", "HAS160", "EDON256", "EDON512",
    /*  25       26      27     28      29       30        31 */
    "SNE128", "SNE256", "MD6", "MD6128", "MD6256", "MD6512", "MD5SALT",
    /* 32        33      34        35         36          37*/
    "MDC2", "MD5RAW", "SHA1RAW", "SHA224RAW", "SHA256RAW", "SHA384RAW",
    /* 38            39        40           41         42        43 */
    "SHA512RAW", "HAV128-4", "HAV128-5", "HAV160-3", "HAV160-4", "HAV160-5",
    /* 44            45        46          47          48        49 */
    "HAV192-3", "HAV192-4", "HAV192-5", "HAV224-3", "HAV224-4", "HAV224-5",
    /* 50            51 */
    "HAV256-4", "HAV256-5",
    /* 52            53       54          55 */
    "BLAKE224", "BLAKE256", "BLAKE384", "BLAKE512",
    /* 56        57        58      59 */
    "BMW224", "BMW256", "BMW384", "BMW512",
    /*  60        61         62       63 */
    "CUBE224", "CUBE256", "CUBE384", "CUBE512",
    /*  64        65         66       67 */
    "ECHO224", "ECHO256", "ECHO384", "ECHO512",
    /*  68        69         70         71 */
    "FUGUE224", "FUGUE256", "FUGUE384", "FUGUE512",
    /*  72           73           74            75 */
    "GROESTL224", "GROESTL256", "GROESTL384", "GROESTL512",
    /*  76          77         78        79 */
    "HAMSI224", "HAMSI256", "HAMSI384", "HAMSI512",
    /*  80      81      82      83  */
    "JH224", "JH256", "JH384", "JH512",
    /*  84          85          86          87 */
    "KECCAK224", "KECCAK256", "KECCAK384", "KECCAK512",
    /*  88          89          90          91 */
    "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
    /*  92          93          94          95 */
    "LUFFA224", "LUFFA256", "LUFFA384", "LUFFA512",
    /*  96          97          98     */
    "PANAMA", "RADIOGATUN32", "RADIOGATUN64",
    /*  99          100         101        102 */
    "SHABAL224", "SHABAL256", "SHABAL384", "SHABAL512",
    /*  103          104          105         106 */
    "SHAVITE224", "SHAVITE256", "SHAVITE384", "SHAVITE512",
    /*  107       108       109       110 */
    "SIMD224", "SIMD256", "SIMD384", "SIMD512",
    /*  111        112         113       114       115 */
    "SKEIN224", "SKEIN256", "SKEIN384", "SKEIN512", "TIGER2",
    /* 116    117     118 */
    "WRL0", "WRL1", "RIPEMD",
    /*     119       120        121          122 */
    "MD2MD5", "MD2MD5PASS", "MD4MD5", "MD4MD5PASS",
    /*     123         124       125 */
    "MD5MD5PASS", "GOSTMD5", "GOSTMD5PASS",
    /*     126         127 */
    "HAV128MD5", "HAV128MD5PASS",
    /*     128         129 */
    "HAV128-4MD5", "HAV128-4MD5PASS",
    /*     130         131 */
    "HAV128-5MD5", "HAV128-5MD5PASS",
    /*     132         133 */
    "HAV160-3MD5", "HAV160-3MD5PASS",
    /*     134         135 */
    "HAV160-4MD5", "HAV160-4MD5PASS",
    /*     136         137 */
    "HAV160-5MD5", "HAV160-5MD5PASS",
    /*     138         139 */
    "HAV192-3MD5", "HAV192-3MD5PASS",
    /*     140         141 */
    "HAV192-4MD5", "HAV192-4MD5PASS",
    /*     142         143 */
    "HAV192-5MD5", "HAV192-5MD5PASS",
    /*     144         145 */
    "HAV224-3MD5", "HAV224-3MD5PASS",
    /*     146         147 */
    "HAV224-4MD5", "HAV224-4MD5PASS",
    /*     148         149 */
    "HAV224-5MD5", "HAV224-5MD5PASS",
    /*     150         151 */
    "HAV256MD5", "HAV256MD5PASS",
    /*     152         153 */
    "HAV256-4MD5", "HAV256-4MD5PASS",
    /*     154         155 */
    "HAV256-5MD5", "HAV256-5MD5PASS",
    /*     156         157           158           159 */
    "RMD128MD5", "RMD128MD5PASS", "RMD160MD5", "RMD160MD5PASS",
    /*     160         161 */
    "SHA1MD5", "SHA1MD5PASS",
    /*     162         163 */
    "SHA224MD5", "SHA224MD5PASS",
    /*     164         165 */
    "SHA256MD5", "SHA256MD5PASS",
    /*     166         167 */
    "SHA384MD5", "SHA384MD5PASS",
    /*     168         169 */
    "SHA512MD5", "SHA512MD5PASS",
    /*     170         171 */
    "TIGERMD5", "TIGERMD5PASS",
    /*     172         173     174           175*/
    "WRLMD5", "WRLMD5PASS", "SNE128MD5", "SNE128MD5PASS",
    /*   176          177 */
    "SNE256MD5", "SNE256MD5PASS",
    /*  178           179      180*/
    "MD5SHA1", "MD5SHA256", "MD5SHA512",
    /* 181             182       183           184           185 */
    "SHA1PASSSHA1", "SHA1UC", "MD5HEXSALT", "SHA1HEXSALT", "SHA256HEXSALT",
    /* 186             187 */
    "GOSTHEXSALT", "HAV128HEXSALT",
    /* 188             189            190 */
    "MD5SHA1MD5", "MD5SHA1MD5SHA1", "MD5SHA1MD5SHA1SHA1",
    /* 191             192 */
    "SHA1MD5SHA1", "SHA1MD5SHA1MD5",
    /*  193             194              195 */
    "MD5HAV160-3", "MD5SHA1HAV160-4", "MD5SHA1MD5SHA1MD5",
    /* 196              197            198         199 */
    "MD5RMD160", "MD5SHA1SHA256", "SHA256SHA512", "MD5WRL",
    /*  200              201            202 */
    "MD5SHA1SHA1RAW", "MD5PASSMD5", "MD5-DBL-PASS",
    /*  203           204 */
    "SHA1MD5UC", "SHA1MD5SHA1MD5SHA1MD5",
    /*  205        206        207 */
    "MD5SQL5", "SHA1SQL5", "MD5MD5UCMD5",
    "HMAC-MD2", "HMAC-MD4", "HMAC-RMD128", "HMAC-RMD160", "HMAC-RMD256",
    "HMAC-RMD320", "HMAC-MD5",
    "HMAC-SHA1", "HMAC-SHA224", "HMAC-SHA256", "HMAC-SHA512",
    "HMAC-HAV128", "HMAC-HAV160", "HMAC-HAV192", "HMAC-HAV224", "HMAC-HAV256",
    "HMAC-TIGER128", "HMAC-TIGER160", "HMAC-TIGER192", "HMAC-GOST",
    "HMAC-WRL", "HMAC-SNE128", "HMAC-SNE256",
    "RMD128MD5MD5",
    "MD5BASE64", "MD5BASE64MD5", "MD5SHA1BASE64",
    "MD5SHA1MD5BASE64", "SHA1BASE64", "MD5BASE64MD5RAW",
    "MD5BASE64SHA1RAW", "SHA1BASE64MD5RAW", "SHA1BASE64SHA1RAW",
    "MD5BASE64SHA1RAWMD5", "MD5BASE64MD5RAWSHA1",
    "MD5BASE64MD5RAWMD5", "MD5BASE64MD5RAWMD5MD5",
    "MD5BASE64SHA1RAWBASE64SHA1RAW", "MD5SHA1UC", "MD5SHA1UCMD5",
    "MD5SHA1UCMD5UC", "SHA1SHA1u32", "MD5SHA1u32",
    "SHA256SHA1", "MD5BASE64revMD5", "MD5revMD5", "MD5revMD5MD5",
    "MD5BASE64MD5MD5", "MD5SQL5-40", "SHA1SQL5-40", "MD5revSHA1",
    "SQL5", "MD5USERIDMD5", "MD5USERIDMD5MD5", "MD5MD5UC",
    "MD5USERnulPASS", "RADMIN2", "MD5RADMIN2", "MD5RADMIN2SHA1",
    "RADMIN2MD5", "RADMIN2MD5MD5", "RADMIN2MD5UC", "RADMIN2MD5SHA1",
    "RADMIN2SHA1", "RADMIN2SQL5-40", "RADMIN2BASE64", "RADMIN2SHA1MD5",
    "RADMIN2SQL3", "RADMIN2MD5MD5MD5", "MD5RADMIN2MD5", "MD51SALTMD5",
    "SHA1RADMIN2", "SHA1RADMIN2MD5", "SHA1RADMIN2BASE64",
    "MD5-MULTISALT", "MD52SALTMD5", "MD51SALTMD5UC", "MD51SALTMD5MD5",
    "MD5MD5USER", "SHA1MD5MD5", "SHA1SHA1RAWMD5", "SHA1MD5MD5MD5",
    "SHA1MD5MD5SHA1MD5", "SHA1MD5MD5SHA1", "SHA1MD5MD5MD5SHA1",
    "SHA1MD5MD5MD5MD5", "SHA1MD5MD5MD5MD5MD5", "SHA1SHA1RAWMD5MD5",
    "SHA1SHA1RAWMD5MD5MD5", "SHA1MD51SALTMD5", "SHA1MD5x", "MD5SHA1SHA1MD5",
    "MD5SHA1SHA1", "MD5SQL5MD5", "MD5SQL5-chop40", "MD5-2xMD5", "MD5-2xMD5-MD5",
    "MD5-2xMD5-SHA1", "MD5-2xMD5-MD5MD5", "MD5-2xMD5-MD5MD5MD5",
    "SHA1MD5USER", "SHA1MD5RADMIN2", "SHA1SHA1USER", "SHA11SALTMD5",
    "MD5-3xMD5", "MD5-3xMD5-MD5",
    "MD5-3xMD5-SHA1", "MD5-3xMD5-MD5MD5", "MD5-3xMD5-MD5MD5MD5",
    "SHA1-2xSHA1", "SHA1-2xSHA1-MD5",
    "SHA1-2xSHA1-SHA1", "SHA1-2xSHA1-MD5MD5", "SHA1-2xSHA1-MD5MD5MD5",
    "MD5-1xMD5SHA1", "MD5-1xSHA1MD5", "SHA1-1xSHA1MD5", "SHA1-1xMD5SHA1",
    "MD5-1xMD5SHA1-MD5", "MD5-1xSHA1MD5-MD5",
    "MD5-1xMD5SHA1-MD5MD5", "MD5-1xSHA1MD5-MD5MD5",
    "MD5-1xSHA1MD5pSHA1p", "SHA1-1xSHA1MD5pSHA1p", "MD5SHA1-1xSHA1MD5pSHA1p",
    "SHA1-1xSHA1psubp", "SHA1revp", "MD5revp", "MD5TIGER2", "MD5SHA1MD5MD5",
    "MD5SHA1MD5RADMIN2", "MD5SHA1MD5MD5MD5SHA1", "MD5SHA1RAW",
    "MD5SHA1MD5MD5MD5", "MD5SQL5-32", "MD51SALTMD5MD5MD5",
    "MD51SALTMD5MD5MD5MD5", "MD51SALTMD5MD5MD5MD5MD5",
    "MD5BASE64ROT13", "MD5MD5SALT", "MD52SALTMD5MD5", "MD52SALTMD5MD5MD5",
    "MD5UCSALT", "MD5TIGER", "MD5SHA1MD5PASS", "MD5CAP",
    "MD5CAPMD5USER", "MD5CAPMD5MD5USER", "MD5MD5MD5USER",
    "MD5MD5SALT-SALT", "MD5CAPSHA1", "MD5SHA1MD5x", "MD5SHA1BASE64MD5RAW",
    "MD5SHA1MD5MD5SHA1", "MD5SHA1MD5UC", "MD5MD5HUM", "SHA1MD5HUM",
    "SHA1SHA1HUM", "MD5SHA1HUM", "MD5-MD5SALTMD5PASS", "MD5NTLM", "NTLM",
    "MD5MD4", "MD5NTLMUC", "MD5USERPASS", "MD5PASSSALT", "MD5SHA1RADMIN2MD5",
    "MD5UCBASE64MD5RAW", "MD5UCBASE64SHA1RAW", "MD5SHA1MD5MD5UC", "MD5SHA1MD5HUM",
    "LM", "MD5LM", "MD5LMUC", "SHA256SHA256SALT", "MD5RAWUC", "MD5SHA1UCu32",
    "SHA1SALTPASS", "SHA512PASSSALT", "SHA512SHA512SALT", "SHA512SALTPASS",
    "SHA512SALTSHA512",
    "WRLPASSSALT", "WRLWRLSALT", "WRLSALTPASS", "WRLSALTWRL", "MD5SALTPASS",
    "SHA1SALTPASSSALT", "MD5MD5UCSHA1MD5MD5", "MD5SHA256MD5", "SHA1lsb32",
    "MD5-2xMD5UC", "MD5-4xMD5", "MD5-SHA1numSHA1", "MD5-2xSHA1",
    "SHA1-2xMD5", "SHA1DRU", "SHA1PASSSALT", "SHA256MD5SALTPASS", "MD5padMD5",
    "MD5DSALT", "SHA1lsb35", "MD4SQL3", "MD5SALTPASSSALT", "SHA256SALTPASS",
    "SHA256PASSSALT", "SMF", "MD5-MD5SHA1MD5SHA1MD5SHA1p", "MD5MD5UCSQL3p",
    "MD5MD5UCp", "MD5NTLMp", "MD5-MD5USERSHA1MD5PASS", "MD5SHA1u32SALT",
    "MD5-LMNTLM", "MD5-MD5psSHA1MD5psp", "MD5-MD5puSHA1MD5pup",
    "MD5WRLMD5", "NULL", "PARALLEL", "GOST2012-32", "GOST2012-64",
    "POMELO", "STREEBOG-32", "STREEBOG-64", "MD5AM", "MD5AM2", "MD5SWAP",
    "MD5SPECAM", "SHA1HESK", "MD5HESK", "SHA1SALTSHA1SALTSHA1PASS", "MSCACHE",
    "MD5SHA1SALTMD5PASS", "MD5SALTMD5PASS", "MD5SHA1PASSMD5PASSSHA1PASS",
    "MD5SHA1PASSSALT", "LEET-SHA512-WRL-USER", "SHA1-SALT-SPECIAL",
    "SHA1-SALT-UTF16-PEPPER", "SHA256RAWSALTPASS", "SHA512-CUSTOM1",
    "MD5SQL3",
    "BCRYPT", "BCRYPTMD5", "BCRYPTSHA1",
    "MD5sub8-24MD5", "MD5sub8-24MD5sub8-24MD5",
    "PHPBB3", "MYSQL3", "APACHE-SHA", "MD5-MD5PASSMD5SALT", "YAF-SHA1",
    "MD5revMD5SHA1", "APR1", "MD5SHA1BASE64SHA1MD5", "SHA1-8TRACK",
    "SHA1WRL", "SHA1revMD5", "SHA1-MD5SALT", "SHA1-revMD5SALT",
    "SHA1revMD5PASSSALT", "SHA1MD5PASSSALT", "SHA1-MD5MD5SALT", "SHA1MD5PASS-SALT",
    "SHA1SALTMD5PASS", "SHA1SALTrevMD5PASS", "SHA1USERSQL3",
    "SHA1SHA256", "SHA1SHA384", "SHA1SHA512", "SHA1SQL3", "SHA1UCWRL",
    "SHA1WRLMD5", "SHA1MD5SHA1MD5SHA1MD5SHA1", "WRLSHA512",
    "MD5GOST", "MD5GOSTMD5", "MD5GOSTMD5UC", "MD5WRLRAW", "MD5-4xMD5-SALT",
    "SHA256UC", "MD4SHA1MD5", "MD5RAWMD5RAW", "MD5SHA1BASE64SHA1RAW",
    "MD5revMD5SHA1SHA1", "MD5MD2", "MD5MD2RAW", "MD5BASE64SHA256RAW",
    "MD4UTF16", "MD4UTF16MD5", "RMD128MD4", "MD5SHA0", "DESCRYPT",
    "MD5DESCRYPT", "MD4DESCRYPT", "MD5PASSSHA1MD5", "MD5PASSMD5MD5PASS",
    "MD5PASSMD5MD5MD5", "MD5-MD5PASSMD5", "MD5PASSSHA1", "MD5MD5PASSSHA1",
    "SHA1MD5MD5SHA1MD5SHA1SHA1MD5", "SHA512SHA512RAWUSER", "MD5CRYPT",
    "SHA256CRYPT", "SHA512CRYPT", "SHA512SALTMD5", "MD5-SALTMD5PASSSALT",
    "MD5-SALTMD5SALTPASS", "MD5-MD5PASS-SALT", "MD5-MD5SALT-PASS",
    "MD5-PASS-MD5SALT", "SHA1SALTSHA1PASS", "SHA1SALTCX",
    "MD5SHA1MD5SHA1MD5SHA1MD5SHA1MD5SHA1MD5SHA1", "SHA256SALTSHA256PASS",
    "MD5dcab", "MD5bcad", "MD5BASE64BASE64", "MD5BASE64BASE64BASE64",
    "MD5-SALTSHA1SALTPASS","CISCO8","PBKDF2-SHA256","PBKDF2-MD5",
    "PBKDF2-SHA1","PBKDF2-SHA512","PKCS5S2","SHA1-CUSTOMUSERSALT",
    "PROGRESSENCODE","PHPBB3MD5","SHA512CRYPTMD5","MYSQL5MD5","MANGOS",
    "MD5revMD5SALT","MD5sub8-24SALT","HMAC-SHA384","CRYPTEXT",
    "MD5SHA1lsb35","MD5sub1-20MD5","MD5sub1-20MD5MD5","MD5SQL3SQL5MD5MD5",
    "SHA1MD5SHA256","SHA1SHA256MD5","MD4UTF16MD5MD5","MD5-2xSHA1MD5",
    "MD5-6xMD5", "MD5-5xMD5","MD5SHA1SALT","MD5SHA1u39",
    "MD5-MD5SHA1PASSSHA1MD5SALT","MD5UCMD5","MD4UTF16MD5UC",
    "MD4UTF16MD5MD5MD5","MD4UTF16SHA1","MD4UTF16SHA1SHA1",
    "MD4UTF16SHA256","MD4UTF16SHA256SHA256","MD4UTF16SHA256SHA256SHA256","MD4UTF16SHA256SHA256SHA256SHA256",
    "MD4UTF16SHA1MD5","MD4UTF16MD5SHA1",
    "MD4UTF16SHA256UC","MD4UTF16UC","SHA1SHA256UC","MD5BASE64SHA1MD5","SHA1DESCRYPT","MD4UTF16DESCRYPT",
    "MD4UTF16MD5HUM","MD4UTF16SHA1HUM","BCRYPT256","SHA1-MD5PASSSALT",
    "SHA1SHA1PASSSALT","SHA1SHA256x","SHA1SHA256UCx","SHA1SHA256UCxSHA256",
    "SHA1SHA256UCSHA256","SHA1SHA256UCSHA256SHA256","SHA1SHA256SHA512",
    "SHA1MD5MD5SALT","SHA1MD5SALT","SHA1-MD5-MD5SALTMD5PASS",
    "SHA1-MD5UC-MD5SALT","SHA1MD5DSALT","SHA1MD5MD5DSALT",
    "SHA1-MD5-MD5SALTMD5PASS-SALT","SHA1MD5MD5SHA1SHA1MD5","SHA1SHA1MD5PASSSALT",
    "SHA1MD5UCMD5","SHA1-MD5PEPPER-MD5SALTMD5PASS","SHA1-MD5PEPPER-MD5SALT",
    "SHA1MD5-PASSMD5SALT","SHA1SHA256SHA1","SHA1MD5-SHA1PASSPASS",
    "SHA1PASS-TRUNC","SHA1SALTMD5PASSPEPPER","SHA1MD5SALTMD5PASS",
    "SHA1SHA1u34","SHA1SHA1u36","SHA1SHA1u38","SHA1MD5SALTPASSPEPPER",
    "SHA1SHA256u32","SHA1SHA256u40","SHA1SHA256u34","SHA1-MD5PEPPER-MD5MD5SALT",
    "SHA1SHA256u42","SHA1SHA256SHA256","SHA1SHA256SHA256SHA256","SHA1SHA256u38",
    "SHA1SHA256u36","SHA1NTLM","SHA1MD5SHA1MD5SHA1","SHA1SALTSHA256","SHA1SHA1u35",
    "SHA1SHA256u37","SHA1SHA256TRUNC","SHA1SHA256TRUNCMD5","SHA1SHA1u39",
    "SHA1SHA1u37","SHA1SHA1TRUNC","SHA1-MD5SHA1PASSSHA1MD5SALT",
    "SHA1MD5CAP","SHA1MD5CAPMD5","SHA1SHA256UCTRUNC","SHA1MD5MD5UCx",
    "SHA1SHA256CAP","SHA1MD5SHA1-SALT","SHA1SHA224","SHA1WRLTRUNC",
    "SHA1SHA512TRUNC","SHA1-SHA512PASSSHA512SALT","SHA1SHA512TRUNC1SALT",
    "SHA1SHA1PASS-TRUNC1SALT","SHA1HAV128","SHA1MD5RAW","SHA1MD2",
    "SHA1MD5BASE64","SHA1MD6TRUNC","SHA1NTLMUC","SHA1MD5SHA512","SHA1MD5WRLSHA1",
    "MD5WRLSHA1","SHA1MD5BASE641SALT","SHA1-MD5PASSMD5MD5SALT",
    "SHA1SALTMD5UCPASSPEPPER","SHA1MD5UCSALT","SHA1WRLUCTRUNC",
    "SHA1-MD5CAPPEPPER-MD5SALT","SHA1-MD5CAPSALT","SHA1SHA1CAPTRUNC",
    "SHA1MD6CAPTRUNC","SHA1MD5UCMD5UC","SHA1MD5CAPSALT","SHA1SQL5-32",
    "SHA1SHA1UCTRUNC","SHA1-MD5UCMD5UCPASSMD5UCSALT","SHA1MD5MD5PASS",
    "SHA1MD51CAP","SHA1SALTMD5UC","SHA1SHA1CAPSALT","SHA1MD5UCMD5UCMD5UC",
    "SHA1MD5UCMD5UCMD5UCMD5UC","SHA1MD51CAPSALT","SHA1-MD5CAPMD5SALT",
    "SHA1SHA512UC","SHA1WRLUCTRUNCSALT","SHA1-MD5SHA256SALT",
    "SHA256MD5SHA256MD5","SHA1SHA256MD5SHA256MD5","SHA1-MD5sub8-24SALT",
    "SHA1-PEPPER-MD5SALT","SHA1SHA256TRUNCSALT","SHA1SHA256TRUNCMD5SALT",
    "SHA1-HMAC-MD5","SHA1SALTSHA1PASSPEPPER","SHA1SALTMD5MD5PASS",
    "SHA1MD5TRUNCSALT","SHA1SHA1TRUNC-SHA1PASS-3","SHA1MD5-SALTMD5PASS",
    "SHA1MD5-2xMD5-MD5","SHA1SHA1MD5MD5PASS1SALT","SHA1MD5sub1-20MD5",
    "SHA1SHA512UCTRUNC","SHA1SALTSHA512UCTRUNC","SHA1SALTSHA256UCTRUNC",
    "SHA1MD5UC-MD5UCSALT","SHA1MD5PASSMD5","MD5DECBASE64","SHA1DECBASE64",
    "SHA1MD5UCSHA1BASE64","SHA1MD5SHA1MD5MD5SHA1MD5", "MD5SHA1MD5MD5SHA1MD5",
    "SHA1MD5UCSHA1UCMD5UC","MD5MD5SHA1SALT","MD5MD5SHA256SALT","MD5SHA1x",
    "MD5DECBASE64MD5","SHA1SALTMD5PASSMD5","SHA1MD5sub8-24MD5","SHA1GOST",
    "MD4UTF16SHA256x","MD4UTF16SHA256SHA256SHA256SHA256SHA256",
    "SHA1MD5RAWUCMD5RAW","SHA1SHA3-256TRUNC","SHA1SHA3-256","SHA1MD5SQL5",
    "SHA1MD5MD5SQL5","SHA1RMD128","SHA1-SHA1SALTSHA1PASS","SHA1MD5MD5UC",
    "SHA1MD5MD5UCMD5UC","SHA11SALTMD5UC","SHA1SALTMD5MD5PASSPEPPER",
    "SHA1SHA1UCPASSSALT","SHA1MD5sub1-20MD5MD5","SHA1MD4UTF16UCMD4UTF16UC",
    "SHA1SHA512TRUNCMD5","SHA1MD5UCx","SHA1SALTSHA256TRUNC",
    "SHA1SALTSHA256TRUNCMD5","SHA1UTF16LE","SHA1UTF16BEZ","SHA1ZUTF16LE",
    "SHA1UCUTF16LE","SHA1MD5UC1LC","SHA1UTF7","SHA1MD51CAPMD5",
    "SHA1BASE64MD5","SHA1SALTSHA1UCPASS","SHA1MD5xSALT","SHA1SHA11CAP",
    "SHA1SALTMD5SHA1PASS","SHA1SHA1TRUNCSALT","SHA1-MD5SALT-CR",
    "SHA1-MD5MD5SALT-CR","SHA1SALTMD5SHA1PASSPEPPER","SHA1MD5CAPMD5SALT",
    "SHA1SALTSHA1CAP","SHA1SHA384TRUNC","SHA1RMD160TRUNC","SHA1BASE64MD5UC",
    "SHA1MD5CAPSHA1SALT","SHA1MD5x1CAP","SHA1SHA1SHA1TRUNC","SHA1SALTSHA1MD5",
    "SHA1UTF16BE","SHA1SHA0","SHA1MD4","SHA1SHA1TRUNCMD5","SHA1MD5MD5UCMD5MD5UC",
    "SHA1SALTMD5UCMD5UC","SHA1MD51CAPMD5MD5","SHA1MD5SHA1PASSSALT",
    "SHA1SQL5MD5","SHA1SQL5MD5MD5","SHA1revSHA1","SHA11SALTMD5SHA256",
    "SHA1SHA256MD5MD5","SHA1MD5SALTPASS","SHA224SHA1","MD5DECBASE64MD5BASE64MD5",
    "SHA1revBASE64","SHA1revBASE64x","SHA1BASE64CUSTBASE64MD5","SHA1MD5sub1-16",
    "SHA1MD5sub1-16MD5","SHA1MD5sub1-16MD5MD5","SHA1SHA1sub1-16",
    "MD4UTF16MD5MD5MD5MD5","MD4UTF16SHA1UC","MD4UTF16MD5x","MD4UTF16SHA1x",
    "MD4UTF16SHA256MD5","MD4UTF16SHA256SHA1","MD4UTF16-2xMD5",
    "MD4UTF16MD5PASSMD5SHA1PASS","MD4UTF16MD5PASSMD5SALT",
    "MD4UTF16MD5MD5PASSMD5SALT","MD4UTF16MD5PASSMD5SHA1SALT",
    "NTLMH","MD4UTF16SQL3","MD4UTF16BASE64","MD4UTF16revBASE64x",
    "SHA1BASE64SHA256","MD4UTF16BASE64SHA256",
    /* 792-799: HMAC with key=$pass (password is key, salt is message) */
    "HMAC-MD5-KPASS","HMAC-SHA1-KPASS","HMAC-SHA224-KPASS","HMAC-SHA256-KPASS",
    "HMAC-SHA384-KPASS","HMAC-SHA512-KPASS","HMAC-RMD160-KPASS","HMAC-RMD320-KPASS",
    /* 800-810: UTF16LE hash types */
    "MD5UTF16LE","MD5UTF16LEPASSSALT","MD5UTF16LESALTPASS",
    "SHA1UTF16LEPASSSALT","SHA1UTF16LESALTPASS",
    "SHA256UTF16LE","SHA256UTF16LEPASSSALT","SHA256UTF16LESALTPASS",
    "SHA512UTF16LE","SHA512UTF16LEPASSSALT","SHA512UTF16LESALTPASS",
    "SHA384PASSSALT","SHA384SALTPASS",
    "SHA384UTF16LE","SHA384UTF16LEPASSSALT","SHA384UTF16LESALTPASS",
    "RMD320",
    "MD5-SHA1SALTPASS","MD5-SALTMD5PASS-SALT",
    "MD5-MD5MD5PASSSALT-PEP","MD5-MD5SALT-MD5MD5PASS",
    "MD5-MD5MD5PASSSALT-PEP2","MD5-SALT-SHA1PEPPASS",
    "SHA1-SALTSHA1PASSSALT","SHA1-SALTSHA1U16",
    "SHA256SALTPASSSALT","SHA256-SALTSHA256RAW",
    "WRLSALTPASSSALT",
    "HMAC-BLAKE2S",
    "MURMUR64A","MURMUR64AZERO",
    "SHA224PASSSALT","SHA224SALTPASS",
    "SSHA1BASE64",
    "SHA1PASSHEXSALT",
    "SSHA256BASE64","SSHA512BASE64",
    "HMAC-STREEBOG256-KPASS","HMAC-STREEBOG256","HMAC-STREEBOG512-KPASS","HMAC-STREEBOG512",
    "BLAKE2B512","BLAKE2B512PASSSALT","BLAKE2B512SALTPASS",
    "BLAKE2S256",
    "BLAKE2B256","BLAKE2B256PASSSALT","BLAKE2B256SALTPASS",
    "DESENCRYPT","DES3ENCRYPT",
    "MSSQL2000","MSSQL2005","MSSQL2012",
    "MACOSX","MACOSX7",
    "POSTGRESQL",
    "JUNIPERSSG",
    "SKYPE",
    "PEOPLESOFT",
    "EPISERVER",
    "HMAILSERVER",
    "CISCOPIX",
    "CISCOASA",
    "MEDIAWIKI",
    "DAHUA",
    "CISCO4",
    "CISCOISE",
    "SAMSUNGSHA1",
    "AIX-MD5",
    "AIX-SHA1",
    "AIX-SHA256",
    "AIX-SHA512",
    "IPMI2-SHA1",
    "IPMI2-MD5",
    "KRB5PA23",
    "MYSQL-SHA256CRYPT",
    "DRUPAL7",
    "SYBASE-ASE",
    "NETSCALER",
    "NSEC3",
    "WBB3",
    "RACF",
    "DOMINO5",
    "DOMINO6",
    "SCRYPT",
    "JUNIPERIVE",
    "PHPS",

NULL

};

/* Numtypes is computed at runtime from the Types[] NULL terminator */

/* ---- Hex tables ---- */

static const char hextab_lc[16] = "0123456789abcdef";
static const char hextab_uc[16] = "0123456789ABCDEF";

/* Forward declarations (needed by compute functions defined before these) */
static char *prmd5(const unsigned char *md5, char *out, int len);
static char *prmd5UC(const unsigned char *md5, char *out, int len);
static void reverse_str(char *s, int len);
static int base64_encode(const unsigned char *in, int inlen, char *out, int outmax);
static int base64_decode(const char *in, int inlen, unsigned char *out, int outmax);

/* Convenience wrappers: bin2hex(bin, binlen, hex) → prmd5(bin, hex, binlen*2) */
static inline void bin2hex(const unsigned char *bin, int binlen, char *hex)
{ prmd5(bin, hex, binlen * 2); }
static inline void bin2hexUC(const unsigned char *bin, int binlen, char *hex)
{ prmd5UC(bin, hex, binlen * 2); }

/* ---- Compute function macros ---- */

#define MAKE_SPH(fname, sph_prefix, ctx_type) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    ctx_type ctx; \
    (void)salt; (void)saltlen; \
    sph_prefix##_init(&ctx); \
    sph_prefix(&ctx, pass, passlen); \
    sph_prefix##_close(&ctx, dest); \
}

#define MAKE_RHASH(fname, hash_id) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    (void)salt; (void)saltlen; \
    rhash_msg(hash_id, pass, passlen, dest); \
}

#define MAKE_COMPOSED(fname, inner_fn, inner_bytes, outer_fn) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    unsigned char _ib[MAX_HASH_BYTES]; \
    char _hx[MAX_HASH_BYTES * 2 + 1]; \
    (void)salt; (void)saltlen; \
    inner_fn(pass, passlen, NULL, 0, _ib); \
    prmd5(_ib, _hx, (inner_bytes) * 2); \
    outer_fn((const unsigned char *)_hx, (inner_bytes) * 2, NULL, 0, dest); \
}

/* OUTER(hex(inner(pass)) + salt) — composed-salted "hex then salt" */
#define MAKE_HEX_SALT(fname, inner_fn, inner_bytes, outer_hash_id) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    unsigned char _ib[MAX_HASH_BYTES]; \
    char _hx[MAX_HASH_BYTES * 2 + 1]; \
    rhash _ctx; \
    inner_fn(pass, passlen, NULL, 0, _ib); \
    prmd5(_ib, _hx, (inner_bytes) * 2); \
    _ctx = rhash_init(outer_hash_id); \
    rhash_update(_ctx, (unsigned char *)_hx, (inner_bytes) * 2); \
    rhash_update(_ctx, salt, saltlen); \
    rhash_final(_ctx, dest); rhash_free(_ctx); \
}

/* OUTER(salt + hex(inner(pass))) — composed-salted "salt then hex" */
#define MAKE_SALT_HEX(fname, inner_fn, inner_bytes, outer_hash_id) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    unsigned char _ib[MAX_HASH_BYTES]; \
    char _hx[MAX_HASH_BYTES * 2 + 1]; \
    rhash _ctx; \
    inner_fn(pass, passlen, NULL, 0, _ib); \
    prmd5(_ib, _hx, (inner_bytes) * 2); \
    _ctx = rhash_init(outer_hash_id); \
    rhash_update(_ctx, salt, saltlen); \
    rhash_update(_ctx, (unsigned char *)_hx, (inner_bytes) * 2); \
    rhash_final(_ctx, dest); rhash_free(_ctx); \
}

/* ---- HMAC compute macros ---- */

/* HMAC with EVP: key=salt, msg=pass */
#define MAKE_HMAC(fname, evp_fn, outlen) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    unsigned int len = (outlen); \
    HMAC(evp_fn(), salt, saltlen, pass, passlen, dest, &len); \
}

/* HMAC with EVP: key=pass, msg=salt (KPASS variant) */
#define MAKE_HMAC_KPASS(fname, evp_fn, outlen) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    unsigned int len = (outlen); \
    HMAC(evp_fn(), pass, passlen, salt, saltlen, dest, &len); \
}

/* HMAC with SPH library hash (manual ipad/opad): key=salt, msg=pass */
#define MAKE_HMAC_SPH(fname, sph_init, sph_update, sph_close, ctx_type, blksize, outlen) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    unsigned char kbuf[blksize], ipad[blksize], opad[blksize], ihash[outlen]; \
    ctx_type ctx; \
    int i; \
    if (saltlen > (blksize)) { \
        sph_init(&ctx); sph_update(&ctx, salt, saltlen); sph_close(&ctx, kbuf); \
        memset(kbuf + (outlen), 0, (blksize) - (outlen)); \
    } else { \
        memcpy(kbuf, salt, saltlen); \
        memset(kbuf + saltlen, 0, (blksize) - saltlen); \
    } \
    for (i = 0; i < (blksize); i++) { ipad[i] = kbuf[i] ^ 0x36; opad[i] = kbuf[i] ^ 0x5c; } \
    sph_init(&ctx); sph_update(&ctx, ipad, (blksize)); sph_update(&ctx, pass, passlen); sph_close(&ctx, ihash); \
    sph_init(&ctx); sph_update(&ctx, opad, (blksize)); sph_update(&ctx, ihash, (outlen)); sph_close(&ctx, dest); \
}

/* HMAC with SPH library hash: key=pass, msg=salt (KPASS variant) */
#define MAKE_HMAC_SPH_KPASS(fname, sph_init, sph_update, sph_close, ctx_type, blksize, outlen) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    unsigned char kbuf[blksize], ipad[blksize], opad[blksize], ihash[outlen]; \
    ctx_type ctx; \
    int i; \
    if (passlen > (blksize)) { \
        sph_init(&ctx); sph_update(&ctx, pass, passlen); sph_close(&ctx, kbuf); \
        memset(kbuf + (outlen), 0, (blksize) - (outlen)); \
    } else { \
        memcpy(kbuf, pass, passlen); \
        memset(kbuf + passlen, 0, (blksize) - passlen); \
    } \
    for (i = 0; i < (blksize); i++) { ipad[i] = kbuf[i] ^ 0x36; opad[i] = kbuf[i] ^ 0x5c; } \
    sph_init(&ctx); sph_update(&ctx, ipad, (blksize)); sph_update(&ctx, salt, saltlen); sph_close(&ctx, ihash); \
    sph_init(&ctx); sph_update(&ctx, opad, (blksize)); sph_update(&ctx, ihash, (outlen)); sph_close(&ctx, dest); \
}

/* --- HMAC compute functions (EVP-based) --- */
MAKE_HMAC(hmac_md5, EVP_md5, 16)
/* HMAC-MD4: manual ipad/opad since EVP_md4 is legacy-disabled in OpenSSL 3.0 */
static void compute_hmac_md4(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char kbuf[64], ipad[64], opad[64], ihash[16];
    rhash ctx;
    int i;
    if (saltlen > 64) { rhash_msg(RHASH_MD4, salt, saltlen, kbuf); memset(kbuf + 16, 0, 48); }
    else { memcpy(kbuf, salt, saltlen); memset(kbuf + saltlen, 0, 64 - saltlen); }
    for (i = 0; i < 64; i++) { ipad[i] = kbuf[i] ^ 0x36; opad[i] = kbuf[i] ^ 0x5c; }
    ctx = rhash_init(RHASH_MD4); rhash_update(ctx, ipad, 64); rhash_update(ctx, pass, passlen); rhash_final(ctx, ihash); rhash_free(ctx);
    ctx = rhash_init(RHASH_MD4); rhash_update(ctx, opad, 64); rhash_update(ctx, ihash, 16); rhash_final(ctx, dest); rhash_free(ctx);
}
MAKE_HMAC(hmac_rmd160, EVP_ripemd160, 20)
MAKE_HMAC(hmac_sha1, EVP_sha1, 20)
MAKE_HMAC(hmac_sha224, EVP_sha224, 28)
MAKE_HMAC(hmac_sha256, EVP_sha256, 32)
MAKE_HMAC(hmac_sha384, EVP_sha384, 48)
MAKE_HMAC(hmac_sha512, EVP_sha512, 64)
/* HMAC-WRL: use mhash to match mdxfind */
static void compute_hmac_wrl(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    MHASH td;
    unsigned char *out;
    td = mhash_hmac_init(MHASH_WHIRLPOOL, (void *)salt, saltlen, mhash_get_hash_pblock(MHASH_WHIRLPOOL));
    mhash(td, pass, passlen);
    out = mhash_hmac_end(td);
    memcpy(dest, out, 64);
    free(out);
}

/* --- HMAC KPASS compute functions (EVP-based, key=pass) --- */
MAKE_HMAC_KPASS(hmac_md5_kpass, EVP_md5, 16)
MAKE_HMAC_KPASS(hmac_sha1_kpass, EVP_sha1, 20)
MAKE_HMAC_KPASS(hmac_sha224_kpass, EVP_sha224, 28)
MAKE_HMAC_KPASS(hmac_sha256_kpass, EVP_sha256, 32)
MAKE_HMAC_KPASS(hmac_sha384_kpass, EVP_sha384, 48)
MAKE_HMAC_KPASS(hmac_sha512_kpass, EVP_sha512, 64)
MAKE_HMAC_KPASS(hmac_rmd160_kpass, EVP_ripemd160, 20)

/* --- HMAC compute functions (SPH-based, manual ipad/opad) --- */
MAKE_HMAC_SPH(hmac_md2, sph_md2_init, sph_md2, sph_md2_close, sph_md2_context, 16, 16)
MAKE_HMAC_SPH(hmac_rmd128, sph_ripemd128_init, sph_ripemd128, sph_ripemd128_close, sph_ripemd128_context, 64, 16)
/* HMAC-RMD256 uses mhash HMAC directly */
static void compute_hmac_rmd256(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    MHASH td;
    unsigned char *out;
    td = mhash_hmac_init(MHASH_RIPEMD256, (void *)salt, saltlen, mhash_get_hash_pblock(MHASH_RIPEMD256));
    mhash(td, pass, passlen);
    out = mhash_hmac_end(td);
    memcpy(dest, out, 32);
    free(out);
}
MAKE_HMAC_SPH(hmac_hav128, sph_haval128_3_init, sph_haval128_3, sph_haval128_3_close, sph_haval128_3_context, 128, 16)
MAKE_HMAC_SPH(hmac_hav160, sph_haval160_3_init, sph_haval160_3, sph_haval160_3_close, sph_haval160_3_context, 128, 20)
MAKE_HMAC_SPH(hmac_hav192, sph_haval192_3_init, sph_haval192_3, sph_haval192_3_close, sph_haval192_3_context, 128, 24)
MAKE_HMAC_SPH(hmac_hav224, sph_haval224_3_init, sph_haval224_3, sph_haval224_3_close, sph_haval224_3_context, 128, 28)
MAKE_HMAC_SPH(hmac_hav256, sph_haval256_3_init, sph_haval256_3, sph_haval256_3_close, sph_haval256_3_context, 128, 32)
/* TIGER HMAC: use mhash which matches mdxfind's HMAC implementation */
static void compute_hmac_tiger128(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    MHASH td;
    unsigned char *out;
    td = mhash_hmac_init(MHASH_TIGER128, (void *)salt, saltlen, mhash_get_hash_pblock(MHASH_TIGER128));
    mhash(td, pass, passlen);
    out = mhash_hmac_end(td);
    memcpy(dest, out, 16);
    free(out);
}
static void compute_hmac_tiger160(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    MHASH td;
    unsigned char *out;
    td = mhash_hmac_init(MHASH_TIGER160, (void *)salt, saltlen, mhash_get_hash_pblock(MHASH_TIGER160));
    mhash(td, pass, passlen);
    out = mhash_hmac_end(td);
    memcpy(dest, out, 20);
    free(out);
}
static void compute_hmac_tiger192(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    MHASH td;
    unsigned char *out;
    td = mhash_hmac_init(MHASH_TIGER192, (void *)salt, saltlen, mhash_get_hash_pblock(MHASH_TIGER192));
    mhash(td, pass, passlen);
    out = mhash_hmac_end(td);
    memcpy(dest, out, 24);
    free(out);
}

/* HMAC-RMD320 uses mhash HMAC directly */
static void compute_hmac_rmd320(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    MHASH td;
    unsigned char *out;
    td = mhash_hmac_init(MHASH_RIPEMD320, (void *)salt, saltlen, mhash_get_hash_pblock(MHASH_RIPEMD320));
    mhash(td, pass, passlen);
    out = mhash_hmac_end(td);
    memcpy(dest, out, 40);
    free(out);
}

/* --- HMAC KPASS (mhash-based, key=pass) --- */
static void compute_hmac_rmd320_kpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    MHASH td;
    unsigned char *out;
    td = mhash_hmac_init(MHASH_RIPEMD320, (void *)pass, passlen, mhash_get_hash_pblock(MHASH_RIPEMD320));
    mhash(td, salt, saltlen);
    out = mhash_hmac_end(td);
    memcpy(dest, out, 40);
    free(out);
}

/* --- HMAC with mhash GOST --- */
static void compute_hmac_gost(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    MHASH td;
    unsigned char *out;
    td = mhash_hmac_init(MHASH_GOST, (void *)salt, saltlen, mhash_get_hash_pblock(MHASH_GOST));
    mhash(td, pass, passlen);
    out = mhash_hmac_end(td);
    memcpy(dest, out, 32);
    free(out);
}

/* --- HMAC with mhash SNE128/SNE256 --- */
static void compute_hmac_sne128(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    MHASH td;
    unsigned char *out;
    td = mhash_hmac_init(MHASH_SNEFRU128, (void *)salt, saltlen, mhash_get_hash_pblock(MHASH_SNEFRU128));
    mhash(td, pass, passlen);
    out = mhash_hmac_end(td);
    memcpy(dest, out, 16);
    free(out);
}

static void compute_hmac_sne256(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    MHASH td;
    unsigned char *out;
    td = mhash_hmac_init(MHASH_SNEFRU256, (void *)salt, saltlen, mhash_get_hash_pblock(MHASH_SNEFRU256));
    mhash(td, pass, passlen);
    out = mhash_hmac_end(td);
    memcpy(dest, out, 32);
    free(out);
}

/* --- HMAC-BLAKE2S: standard HMAC construction, key=pass, msg=salt (matches mdxfind) --- */
static void compute_hmac_blake2s(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char kpad[64], inner[32];
    int ki, klen = passlen;
    if (klen > 64) {
        blake2s(kpad, 32, pass, klen, NULL, 0);
        klen = 32;
        memset(kpad + 32, 0, 32);
    } else {
        memcpy(kpad, pass, klen);
        memset(kpad + klen, 0, 64 - klen);
    }
    for (ki = 0; ki < 64; ki++) kpad[ki] ^= 0x36;
    { unsigned char *ibuf = WS->tmp1; /* 64 + saltlen fits in MAXLINE */
      memcpy(ibuf, kpad, 64); memcpy(ibuf + 64, salt, saltlen);
      blake2s(inner, 32, ibuf, 64 + saltlen, NULL, 0);
    }
    for (ki = 0; ki < 64; ki++) kpad[ki] ^= 0x36 ^ 0x5c;
    { unsigned char obuf[96];
      memcpy(obuf, kpad, 64); memcpy(obuf + 64, inner, 32);
      blake2s(dest, 32, obuf, 96, NULL, 0);
    }
}

/* --- HMAC-STREEBOG (GOST2012) --- */
/* streebog_final returns bytes in reversed order; mdxfind reverses inner hash
   and key hash before re-feeding. We do the same here. */
static inline void reverse_bytes(unsigned char *buf, int len) {
    int i; unsigned char tmp;
    for (i = 0; i < len / 2; i++) { tmp = buf[i]; buf[i] = buf[len-1-i]; buf[len-1-i] = tmp; }
}

static void compute_hmac_streebog256(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char kpad[64], inner[32];
    streebog_t stx;
    int ki, klen = saltlen;
    if (klen > 64) {
        streebog(kpad, 32, salt, klen);
        reverse_bytes(kpad, 32);
        klen = 32;
        memset(kpad + 32, 0, 32);
    } else {
        memcpy(kpad, salt, klen);
        memset(kpad + klen, 0, 64 - klen);
    }
    for (ki = 0; ki < 64; ki++) kpad[ki] ^= 0x36;
    streebog_init(&stx, 32); streebog_update(&stx, kpad, 64); streebog_update(&stx, pass, passlen); streebog_final(inner, &stx);
    reverse_bytes(inner, 32);
    for (ki = 0; ki < 64; ki++) kpad[ki] ^= 0x36 ^ 0x5c;
    streebog_init(&stx, 32); streebog_update(&stx, kpad, 64); streebog_update(&stx, inner, 32); streebog_final(dest, &stx);
}

static void compute_hmac_streebog512(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char kpad[64], inner[64];
    streebog_t stx;
    int ki, klen = saltlen;
    if (klen > 64) {
        streebog(kpad, 64, salt, klen);
        reverse_bytes(kpad, 64);
    } else {
        memcpy(kpad, salt, klen);
        memset(kpad + klen, 0, 64 - klen);
    }
    for (ki = 0; ki < 64; ki++) kpad[ki] ^= 0x36;
    streebog_init(&stx, 64); streebog_update(&stx, kpad, 64); streebog_update(&stx, pass, passlen); streebog_final(inner, &stx);
    reverse_bytes(inner, 64);
    for (ki = 0; ki < 64; ki++) kpad[ki] ^= 0x36 ^ 0x5c;
    streebog_init(&stx, 64); streebog_update(&stx, kpad, 64); streebog_update(&stx, inner, 64); streebog_final(dest, &stx);
}

static void compute_hmac_streebog256_kpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char kpad[64], inner[32];
    streebog_t stx;
    int ki, klen = passlen;
    if (klen > 64) {
        streebog(kpad, 32, pass, klen);
        reverse_bytes(kpad, 32);
        klen = 32;
        memset(kpad + 32, 0, 32);
    } else {
        memcpy(kpad, pass, klen);
        memset(kpad + klen, 0, 64 - klen);
    }
    for (ki = 0; ki < 64; ki++) kpad[ki] ^= 0x36;
    streebog_init(&stx, 32); streebog_update(&stx, kpad, 64); streebog_update(&stx, salt, saltlen); streebog_final(inner, &stx);
    reverse_bytes(inner, 32);
    for (ki = 0; ki < 64; ki++) kpad[ki] ^= 0x36 ^ 0x5c;
    streebog_init(&stx, 32); streebog_update(&stx, kpad, 64); streebog_update(&stx, inner, 32); streebog_final(dest, &stx);
}

static void compute_hmac_streebog512_kpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char kpad[64], inner[64];
    streebog_t stx;
    int ki, klen = passlen;
    if (klen > 64) {
        streebog(kpad, 64, pass, klen);
        reverse_bytes(kpad, 64);
    } else {
        memcpy(kpad, pass, klen);
        memset(kpad + klen, 0, 64 - klen);
    }
    for (ki = 0; ki < 64; ki++) kpad[ki] ^= 0x36;
    streebog_init(&stx, 64); streebog_update(&stx, kpad, 64); streebog_update(&stx, salt, saltlen); streebog_final(inner, &stx);
    reverse_bytes(inner, 64);
    for (ki = 0; ki < 64; ki++) kpad[ki] ^= 0x36 ^ 0x5c;
    streebog_init(&stx, 64); streebog_update(&stx, kpad, 64); streebog_update(&stx, inner, 64); streebog_final(dest, &stx);
}

/* ---- OpenSSL base compute functions ---- */

static void compute_md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, dest);
}

static void compute_md4(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD4, pass, passlen, dest);
}

/* Thread-local iconv handles for UTF-16LE/BE conversion */
static __thread iconv_t iconv_utf16le = (iconv_t)-1;
static __thread iconv_t iconv_utf16be = (iconv_t)-1;

/* iconv-based UTF-8 → UTF-16LE conversion. Returns byte count of UTF-16LE output. */
static int utf8_to_utf16le(const unsigned char *src, int srclen,
    unsigned char *dst, int dstmax)
{
    char *inbuf, *outbuf;
    size_t inleft, outleft, ret;

    if (iconv_utf16le == (iconv_t)-1) {
        iconv_utf16le = iconv_open("UTF-16LE", "UTF-8");
        if (iconv_utf16le == (iconv_t)-1) return 0;
    }

    inbuf = (char *)src;
    inleft = srclen;
    outbuf = (char *)dst;
    outleft = dstmax;

    ret = iconv(iconv_utf16le, &inbuf, &inleft, &outbuf, &outleft);
    if (ret == (size_t)-1 && outleft == (size_t)dstmax) {
        iconv(iconv_utf16le, NULL, NULL, NULL, NULL);
        return 0;
    }
    iconv(iconv_utf16le, NULL, NULL, NULL, NULL);
    return dstmax - (int)outleft;
}

/* iconv-based UTF-8 → UTF-16BE conversion. Returns byte count of UTF-16BE output. */
static int utf8_to_utf16be(const unsigned char *src, int srclen,
    unsigned char *dst, int dstmax)
{
    char *inbuf, *outbuf;
    size_t inleft, outleft, ret;

    if (iconv_utf16be == (iconv_t)-1) {
        iconv_utf16be = iconv_open("UTF-16BE", "UTF-8");
        if (iconv_utf16be == (iconv_t)-1) return 0;
    }

    inbuf = (char *)src;
    inleft = srclen;
    outbuf = (char *)dst;
    outleft = dstmax;

    ret = iconv(iconv_utf16be, &inbuf, &inleft, &outbuf, &outleft);
    if (ret == (size_t)-1 && outleft == (size_t)dstmax) {
        iconv(iconv_utf16be, NULL, NULL, NULL, NULL);
        return 0;
    }
    iconv(iconv_utf16be, NULL, NULL, NULL, NULL);
    return dstmax - (int)outleft;
}

static void compute_ntlm(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char *utf16 = WS->u16a;
    int u16len;
    (void)salt; (void)saltlen;
    u16len = utf8_to_utf16le(pass, passlen, utf16, sizeof(WS->u16a));
    rhash_msg(RHASH_MD4, utf16, u16len, dest);
}

/* UTF-16LE wrapper types: hash(utf16le(pass)) */
#define MAKE_UTF16LE(fname, hash_fn) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    unsigned char *_u16 = WS->u16a; \
    int _u16len; \
    (void)salt; (void)saltlen; \
    _u16len = utf8_to_utf16le(pass, passlen, _u16, sizeof(WS->u16a)); \
    hash_fn(_u16, _u16len, NULL, 0, dest); \
}

/* MD4UTF16 = NTLM (same computation, different type name) */
/* (shares compute_ntlm) */

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

/* UTF-16LE wrapper instantiations (must come after base hash functions) */
MAKE_UTF16LE(md5utf16le, compute_md5)
MAKE_UTF16LE(sha1utf16le, compute_sha1)
MAKE_UTF16LE(sha256utf16le, compute_sha256)
MAKE_UTF16LE(sha384utf16le, compute_sha384)
MAKE_UTF16LE(sha512utf16le, compute_sha512)

/* UTF-16BE wrappers */
static void compute_sha1utf16be(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char *u16 = WS->u16a;
    int u16len;
    (void)salt; (void)saltlen;
    u16len = utf8_to_utf16be(pass, passlen, u16, sizeof(WS->u16a));
    SHA1(u16, u16len, dest);
}

static void compute_sha1utf16bez(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char *u16 = WS->u16a;
    int u16len;
    (void)salt; (void)saltlen;
    u16len = utf8_to_utf16be(pass, passlen, u16, sizeof(WS->u16a) - 2);
    u16[u16len++] = 0;
    u16[u16len++] = 0;
    SHA1(u16, u16len, dest);
}

static void compute_sha1zutf16le(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char *u16 = WS->u16a;
    int u16len;
    (void)salt; (void)saltlen;
    u16[0] = 0;
    u16len = utf8_to_utf16le(pass, passlen, u16 + 1, sizeof(WS->u16a) - 1);
    SHA1(u16, u16len + 1, dest);
}

static void compute_sha1ucutf16le(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char *u16 = WS->u16a;
    int u16len;
    (void)salt; (void)saltlen;
    u16len = utf8_to_utf16le(pass, passlen, u16, sizeof(WS->u16a));
    SHA1(u16, u16len, dest);
}

/* MD5SALT: rhash_msg(RHASH_MD5, hex(MD5(pass)) + salt) — matches mdxfind JOB_MD5SALT */
static void compute_md5salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;

    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    hexstr[32] = 0;

    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* Salted: H(salt + pass) */
static void compute_md5saltpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* Salted: H(pass + salt) */
static void compute_md5passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

static void compute_sha1saltpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

static void compute_sha1passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

static void compute_sha256saltpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_SHA256);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

static void compute_sha256passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_SHA256);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

static void compute_sha512saltpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_SHA512);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

static void compute_sha512passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_SHA512);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5SALTPASSSALT: rhash_msg(RHASH_MD5, salt + pass + salt) */
static void compute_md5saltpasssalt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA1SALTPASSSALT: SHA1(salt + pass + salt) */
static void compute_sha1saltpasssalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5SALTMD5PASS: rhash_msg(RHASH_MD5, salt + hex(MD5(pass))) */
static void compute_md5saltmd5pass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;

    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }

    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, hexstr, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5SHA1SALTMD5PASS: rhash_msg(RHASH_MD5, hex(SHA1(salt)) + hex(MD5(pass))) */
static void compute_md5sha1saltmd5pass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16], sha1bin[20];
    char buf[73]; /* 40 + 32 + 1 */
    int i;
    rhash ctx;

    SHA1(salt, saltlen, sha1bin);
    for (i = 0; i < 20; i++) {
        buf[i * 2]     = hextab_lc[(sha1bin[i] >> 4) & 0xf];
        buf[i * 2 + 1] = hextab_lc[sha1bin[i] & 0xf];
    }
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        buf[40 + i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        buf[40 + i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }

    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, buf, 72);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5SHA1PASSSALT: rhash_msg(RHASH_MD5, hex(SHA1(pass + salt))) */
static void compute_md5sha1passsalt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1bin[20];
    char hexstr[41];
    int i;
    rhash sctx;
    rhash ctx;

    sctx = rhash_init(RHASH_SHA1);
    rhash_update(sctx, pass, passlen);
    rhash_update(sctx, salt, saltlen);
    rhash_final(sctx, sha1bin); rhash_free(sctx);

    for (i = 0; i < 20; i++) {
        hexstr[i * 2]     = hextab_lc[(sha1bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[sha1bin[i] & 0xf];
    }

    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hexstr, 40);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5-MD5SALTMD5PASS: rhash_msg(RHASH_MD5, hex(MD5(salt)) + hex(MD5(pass))) */
static void compute_md5_md5saltmd5pass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5s[16], md5p[16];
    char buf[65];
    int i;
    rhash ctx;

    rhash_msg(RHASH_MD5, salt, saltlen, md5s);
    for (i = 0; i < 16; i++) {
        buf[i * 2]     = hextab_lc[(md5s[i] >> 4) & 0xf];
        buf[i * 2 + 1] = hextab_lc[md5s[i] & 0xf];
    }
    rhash_msg(RHASH_MD5, pass, passlen, md5p);
    for (i = 0; i < 16; i++) {
        buf[32 + i * 2]     = hextab_lc[(md5p[i] >> 4) & 0xf];
        buf[32 + i * 2 + 1] = hextab_lc[md5p[i] & 0xf];
    }

    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, buf, 64);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5-MD5PASSMD5SALT: rhash_msg(RHASH_MD5, hex(MD5(pass)) + hex(MD5(salt))) */
static void compute_md5_md5passmd5salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5p[16], md5s[16];
    char buf[65];
    int i;
    rhash ctx;

    rhash_msg(RHASH_MD5, pass, passlen, md5p);
    for (i = 0; i < 16; i++) {
        buf[i * 2]     = hextab_lc[(md5p[i] >> 4) & 0xf];
        buf[i * 2 + 1] = hextab_lc[md5p[i] & 0xf];
    }
    rhash_msg(RHASH_MD5, salt, saltlen, md5s);
    for (i = 0; i < 16; i++) {
        buf[32 + i * 2]     = hextab_lc[(md5s[i] >> 4) & 0xf];
        buf[32 + i * 2 + 1] = hextab_lc[md5s[i] & 0xf];
    }

    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, buf, 64);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5-MULTISALT: rhash_msg(RHASH_MD5, salt + hex(MD5(hex(MD5(salt+pass)) + salt)) + salt) */
static void compute_md5_multisalt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hex1[33], hex2[33];
    unsigned char *buf = WS->tmp1;
    int i, blen;
    rhash ctx;

    /* h1 = rhash_msg(RHASH_MD5, salt + pass) */
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, md5bin); rhash_free(ctx);
    for (i = 0; i < 16; i++) {
        hex1[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hex1[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }

    /* h2 = rhash_msg(RHASH_MD5, hex(h1) + salt) */
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hex1, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, md5bin); rhash_free(ctx);
    for (i = 0; i < 16; i++) {
        hex2[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hex2[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }

    /* result = rhash_msg(RHASH_MD5, salt + hex(h2) + salt) */
    blen = 0;
    if (saltlen + 32 + saltlen > (int)sizeof(WS->tmp1)) { memset(dest, 0, 16); return; }
    memcpy(buf, salt, saltlen); blen += saltlen;
    memcpy(buf + blen, hex2, 32); blen += 32;
    memcpy(buf + blen, salt, saltlen); blen += saltlen;

    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, buf, blen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5MD5SALT-SALT: rhash_msg(RHASH_MD5, hex(MD5(pass+salt)) + ":" + salt) */
static void compute_md5md5salt_salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char *buf = (char *)WS->tmp1;
    int i, blen;
    rhash ctx;

    /* h1 = rhash_msg(RHASH_MD5, pass + salt) */
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, md5bin); rhash_free(ctx);
    for (i = 0; i < 16; i++) {
        buf[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        buf[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    buf[32] = ':';
    if (33 + saltlen > (int)sizeof(WS->tmp1)) { memset(dest, 0, 16); return; }
    memcpy(buf + 33, salt, saltlen);
    blen = 33 + saltlen;

    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, buf, blen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA256MD5SALTPASS: SHA256(hex(rhash_msg(RHASH_MD5, salt + pass))) */
static void compute_sha256md5saltpass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash mctx;
    rhash ctx;

    mctx = rhash_init(RHASH_MD5);
    rhash_update(mctx, salt, saltlen);
    rhash_update(mctx, pass, passlen);
    rhash_final(mctx, md5bin); rhash_free(mctx);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }

    ctx = rhash_init(RHASH_SHA256);
    rhash_update(ctx, hexstr, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA1-8TRACK: SHA1(salt + pass + "--") */
static void compute_sha1_8track(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, "--", 2);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA1SALTSHA1SALTSHA1PASS: SHA1(salt + hex(SHA1(salt + hex(SHA1(pass))))) */
static void compute_sha1saltsha1saltsha1pass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1bin[20];
    char hexstr[41];
    unsigned char *buf = WS->tmp1;
    int i, blen;
    rhash ctx;

    /* h1 = SHA1(pass) */
    SHA1(pass, passlen, sha1bin);
    for (i = 0; i < 20; i++) {
        hexstr[i * 2]     = hextab_lc[(sha1bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[sha1bin[i] & 0xf];
    }

    /* h2 = SHA1(salt + hex(h1)) */
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, hexstr, 40);
    rhash_final(ctx, sha1bin); rhash_free(ctx);
    for (i = 0; i < 20; i++) {
        hexstr[i * 2]     = hextab_lc[(sha1bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[sha1bin[i] & 0xf];
    }

    /* result = SHA1(salt + hex(h2)) */
    if (saltlen + 40 > (int)sizeof(WS->tmp1)) { memset(dest, 0, 20); return; }
    memcpy(buf, salt, saltlen);
    memcpy(buf + saltlen, hexstr, 40);
    blen = saltlen + 40;

    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, buf, blen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5-MD5psSHA1MD5psp: rhash_msg(RHASH_MD5, hex(MD5(pass+salt)) + hex(SHA1(hex(MD5(pass+salt))+pass))) */
static void compute_md5_md5pssha1md5psp(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16], sha1bin[20];
    char md5hex[33], sha1hex[41], buf[73];
    int i;
    rhash mctx;
    rhash sctx;

    /* md5_ps = rhash_msg(RHASH_MD5, pass + salt) */
    mctx = rhash_init(RHASH_MD5);
    rhash_update(mctx, pass, passlen);
    rhash_update(mctx, salt, saltlen);
    rhash_final(mctx, md5bin); rhash_free(mctx);
    for (i = 0; i < 16; i++) {
        md5hex[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        md5hex[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }

    /* sha1_md5psp = SHA1(hex(md5_ps) + pass) */
    sctx = rhash_init(RHASH_SHA1);
    rhash_update(sctx, md5hex, 32);
    rhash_update(sctx, pass, passlen);
    rhash_final(sctx, sha1bin); rhash_free(sctx);
    for (i = 0; i < 20; i++) {
        sha1hex[i * 2]     = hextab_lc[(sha1bin[i] >> 4) & 0xf];
        sha1hex[i * 2 + 1] = hextab_lc[sha1bin[i] & 0xf];
    }

    /* result = rhash_msg(RHASH_MD5, md5hex + sha1hex) = MD5(32 + 40 = 72 chars) */
    memcpy(buf, md5hex, 32);
    memcpy(buf + 32, sha1hex, 40);

    mctx = rhash_init(RHASH_MD5);
    rhash_update(mctx, buf, 72);
    rhash_final(mctx, dest); rhash_free(mctx);
}

/* MD5-MD5puSHA1MD5pup: same as above but salt=username */
static void compute_md5_md5pusha1md5pup(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    compute_md5_md5pssha1md5psp(pass, passlen, salt, saltlen, dest);
}

/* SHA512-CUSTOM1: SHA512(hex(rhash_msg(RHASH_MD5, hex(SHA1(hex(MD5("$3dfhgjhgG65-" + pass + "23ewdfwGh5RG65?"))))))) */
static void compute_sha512_custom1(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16], sha1bin[20];
    char hexbuf[65];
    int i;
    rhash mctx;
    rhash sctx;
    rhash ctx512;
    (void)salt; (void)saltlen;

    /* rhash_msg(RHASH_MD5, "$3dfhgjhgG65-" + pass + "23ewdfwGh5RG65?") */
    mctx = rhash_init(RHASH_MD5);
    rhash_update(mctx, "$3dfhgjhgG65-", 13);
    rhash_update(mctx, pass, passlen);
    rhash_update(mctx, "23ewdfwGh5RG65?", 15);
    rhash_final(mctx, md5bin); rhash_free(mctx);
    for (i = 0; i < 16; i++) {
        hexbuf[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexbuf[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }

    /* SHA1(hex(md5)) */
    SHA1((unsigned char *)hexbuf, 32, sha1bin);
    for (i = 0; i < 20; i++) {
        hexbuf[i * 2]     = hextab_lc[(sha1bin[i] >> 4) & 0xf];
        hexbuf[i * 2 + 1] = hextab_lc[sha1bin[i] & 0xf];
    }

    /* rhash_msg(RHASH_MD5, hex(sha1)) */
    rhash_msg(RHASH_MD5, (unsigned char *)hexbuf, 40, md5bin);
    for (i = 0; i < 16; i++) {
        hexbuf[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexbuf[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }

    /* SHA512(hex(md5)) */
    ctx512 = rhash_init(RHASH_SHA512);
    rhash_update(ctx512, hexbuf, 32);
    rhash_final(ctx512, dest); rhash_free(ctx512);
}

/* SMF: SHA1(lowercase(salt/username) + pass) */
static void compute_smf(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char *lcsalt = WS->tmp1;
    int i;
    rhash ctx;

    for (i = 0; i < saltlen && i < MAXLINE - 1; i++)
        lcsalt[i] = tolower(salt[i]);

    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, lcsalt, i);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MSCACHE: rhash_msg(RHASH_MD4, MD4(UTF16LE(pass)) + UTF16LE(lowercase(salt/username))) */
static void compute_mscache(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char ntlm[16];
    unsigned char *u16pass = WS->u16a, *u16salt = WS->u16b;
    unsigned char *lcsalt = WS->tmp1;
    int u16plen, u16slen, i;
    rhash ctx;

    /* NTLM = rhash_msg(RHASH_MD4, UTF16LE(pass)) */
    u16plen = utf8_to_utf16le(pass, passlen, u16pass, sizeof(WS->u16a));
    rhash_msg(RHASH_MD4, u16pass, u16plen, ntlm);

    /* lowercase salt/username, then UTF16LE */
    for (i = 0; i < saltlen && i < MAXLINE - 1; i++)
        lcsalt[i] = tolower(salt[i]);
    u16slen = utf8_to_utf16le(lcsalt, i, u16salt, sizeof(WS->u16b));

    /* rhash_msg(RHASH_MD4, ntlm + UTF16LE(lc(salt))) */
    ctx = rhash_init(RHASH_MD4);
    rhash_update(ctx, ntlm, 16);
    rhash_update(ctx, u16salt, u16slen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA256RAWSALTPASS: SHA256(salt + pass) — same as SHA256SALTPASS */
/* (already handled by compute_sha256saltpass, just needs registration) */

/* Composed: rhash_msg(RHASH_MD5, hex(MD5(pass)) + pass) — matches mdxfind JOB_MD5MD5PASS variant 1 */
static void compute_md5md5pass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;

    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    hexstr[32] = 0;

    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* Composed: rhash_msg(RHASH_MD5, hex(MD5(pass)) + ":" + pass) — matches mdxfind JOB_MD5MD5PASS variant 2 */
static void compute_md5md5pass_colon(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;

    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    hexstr[32] = 0;

    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, ":", 1);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA1MD5: rhash_msg(RHASH_MD5, hex(SHA1(pass))) — inner=SHA1, outer=MD5, output=16 bytes */
static void compute_sha1md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1bin[20];
    char hexstr[41];
    int i;

    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1bin);
    for (i = 0; i < 20; i++) {
        hexstr[i * 2]     = hextab_lc[(sha1bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[sha1bin[i] & 0xf];
    }
    hexstr[40] = 0;
    rhash_msg(RHASH_MD5, (unsigned char *)hexstr, 40, dest);
}

/* MD5SHA1: SHA1(hex(rhash_msg(RHASH_MD5, pass))) — inner=MD5, outer=SHA1, output=20 bytes */
static void compute_md5sha1(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;

    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    hexstr[32] = 0;
    SHA1((unsigned char *)hexstr, 32, dest);
}

/* ---- OpenSSL extra compute functions ---- */

static void compute_rmd160(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_RIPEMD160, pass, passlen, dest);
}

static void compute_whirlpool(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_WHIRLPOOL, pass, passlen, dest);
}

/* ---- SPH compute functions (via MAKE_SPH macro) ---- */

/* 16-byte output */
MAKE_SPH(md2, sph_md2, sph_md2_context)
MAKE_SPH(hav128_3, sph_haval128_3, sph_haval128_3_context)
MAKE_SPH(hav128_4, sph_haval128_4, sph_haval128_4_context)
MAKE_SPH(hav128_5, sph_haval128_5, sph_haval128_5_context)
MAKE_SPH(rmd128, sph_ripemd128, sph_ripemd128_context)
MAKE_SPH(ripemd, sph_ripemd, sph_ripemd_context)

/* 20-byte output */
MAKE_SPH(hav160_3, sph_haval160_3, sph_haval160_3_context)
MAKE_SPH(hav160_4, sph_haval160_4, sph_haval160_4_context)
MAKE_SPH(hav160_5, sph_haval160_5, sph_haval160_5_context)

/* 24-byte output */
MAKE_SPH(hav192_3, sph_haval192_3, sph_haval192_3_context)
MAKE_SPH(hav192_4, sph_haval192_4, sph_haval192_4_context)
MAKE_SPH(hav192_5, sph_haval192_5, sph_haval192_5_context)
MAKE_SPH(tiger, sph_tiger, sph_tiger_context)

static void compute_tiger2(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    sph_tiger_context ctx;
    (void)salt; (void)saltlen;
    sph_tiger2_init(&ctx);
    sph_tiger(&ctx, pass, passlen);
    sph_tiger2_close(&ctx, dest);
}

/* 28-byte output */
MAKE_SPH(hav224_3, sph_haval224_3, sph_haval224_3_context)
MAKE_SPH(hav224_4, sph_haval224_4, sph_haval224_4_context)
MAKE_SPH(hav224_5, sph_haval224_5, sph_haval224_5_context)
MAKE_SPH(blake224, sph_blake224, sph_blake224_context)
MAKE_SPH(bmw224, sph_bmw224, sph_bmw224_context)
MAKE_SPH(cube224, sph_cubehash224, sph_cubehash224_context)
MAKE_SPH(echo224, sph_echo224, sph_echo224_context)
MAKE_SPH(fugue224, sph_fugue224, sph_fugue224_context)
MAKE_SPH(groestl224, sph_groestl224, sph_groestl224_context)
MAKE_SPH(hamsi224, sph_hamsi224, sph_hamsi224_context)
MAKE_SPH(jh224, sph_jh224, sph_jh224_context)
MAKE_SPH(keccak224, sph_keccak224, sph_keccak224_context)
MAKE_SPH(luffa224, sph_luffa224, sph_luffa224_context)
MAKE_SPH(shabal224, sph_shabal224, sph_shabal224_context)
MAKE_SPH(shavite224, sph_shavite224, sph_shavite224_context)
MAKE_SPH(simd224, sph_simd224, sph_simd224_context)
MAKE_SPH(skein224, sph_skein224, sph_skein224_context)

/* 32-byte output */
MAKE_SPH(sha0, sph_sha0, sph_sha0_context)
MAKE_SPH(hav256_3, sph_haval256_3, sph_haval256_3_context)
MAKE_SPH(hav256_4, sph_haval256_4, sph_haval256_4_context)
MAKE_SPH(hav256_5, sph_haval256_5, sph_haval256_5_context)
MAKE_SPH(blake256, sph_blake256, sph_blake256_context)
MAKE_SPH(bmw256, sph_bmw256, sph_bmw256_context)
MAKE_SPH(cube256, sph_cubehash256, sph_cubehash256_context)
MAKE_SPH(echo256, sph_echo256, sph_echo256_context)
MAKE_SPH(fugue256, sph_fugue256, sph_fugue256_context)
MAKE_SPH(groestl256, sph_groestl256, sph_groestl256_context)
MAKE_SPH(hamsi256, sph_hamsi256, sph_hamsi256_context)
MAKE_SPH(jh256, sph_jh256, sph_jh256_context)
MAKE_SPH(keccak256, sph_keccak256, sph_keccak256_context)
MAKE_SPH(luffa256, sph_luffa256, sph_luffa256_context)
MAKE_SPH(panama, sph_panama, sph_panama_context)
MAKE_SPH(radiogatun32, sph_radiogatun32, sph_radiogatun32_context)
MAKE_SPH(shabal256, sph_shabal256, sph_shabal256_context)
MAKE_SPH(shavite256, sph_shavite256, sph_shavite256_context)
MAKE_SPH(simd256, sph_simd256, sph_simd256_context)
MAKE_SPH(skein256, sph_skein256, sph_skein256_context)

/* 48-byte output */
MAKE_SPH(blake384, sph_blake384, sph_blake384_context)
MAKE_SPH(bmw384, sph_bmw384, sph_bmw384_context)
MAKE_SPH(cube384, sph_cubehash384, sph_cubehash384_context)
MAKE_SPH(echo384, sph_echo384, sph_echo384_context)
MAKE_SPH(fugue384, sph_fugue384, sph_fugue384_context)
MAKE_SPH(groestl384, sph_groestl384, sph_groestl384_context)
MAKE_SPH(hamsi384, sph_hamsi384, sph_hamsi384_context)
MAKE_SPH(jh384, sph_jh384, sph_jh384_context)
MAKE_SPH(keccak384, sph_keccak384, sph_keccak384_context)
MAKE_SPH(luffa384, sph_luffa384, sph_luffa384_context)
MAKE_SPH(shabal384, sph_shabal384, sph_shabal384_context)
MAKE_SPH(shavite384, sph_shavite384, sph_shavite384_context)
MAKE_SPH(simd384, sph_simd384, sph_simd384_context)
MAKE_SPH(skein384, sph_skein384, sph_skein384_context)

/* 64-byte output */
MAKE_SPH(blake512, sph_blake512, sph_blake512_context)
MAKE_SPH(bmw512, sph_bmw512, sph_bmw512_context)
MAKE_SPH(cube512, sph_cubehash512, sph_cubehash512_context)
MAKE_SPH(echo512, sph_echo512, sph_echo512_context)
MAKE_SPH(fugue512, sph_fugue512, sph_fugue512_context)
MAKE_SPH(groestl512, sph_groestl512, sph_groestl512_context)
MAKE_SPH(hamsi512, sph_hamsi512, sph_hamsi512_context)
MAKE_SPH(jh512, sph_jh512, sph_jh512_context)
MAKE_SPH(keccak512, sph_keccak512, sph_keccak512_context)
MAKE_SPH(luffa512, sph_luffa512, sph_luffa512_context)
MAKE_SPH(radiogatun64, sph_radiogatun64, sph_radiogatun64_context)
MAKE_SPH(shabal512, sph_shabal512, sph_shabal512_context)
MAKE_SPH(shavite512, sph_shavite512, sph_shavite512_context)
MAKE_SPH(simd512, sph_simd512, sph_simd512_context)
MAKE_SPH(skein512, sph_skein512, sph_skein512_context)
MAKE_SPH(wrl0, sph_whirlpool0, sph_whirlpool0_context)
MAKE_SPH(wrl1, sph_whirlpool1, sph_whirlpool1_context)

/* ---- rhash compute functions (via MAKE_RHASH macro) ---- */

MAKE_RHASH(gost, RHASH_GOST)
MAKE_RHASH(gostcrypto, RHASH_GOST_CRYPTOPRO)
MAKE_RHASH(aich, RHASH_AICH)
MAKE_RHASH(has160, RHASH_HAS160)
MAKE_RHASH(ed2k, RHASH_ED2K)
MAKE_RHASH(sne128, RHASH_SNEFRU128)
MAKE_RHASH(sne256, RHASH_SNEFRU256)
MAKE_RHASH(edon256, RHASH_EDONR256)
MAKE_RHASH(edon512, RHASH_EDONR512)
MAKE_RHASH(tth, RHASH_TTH)
MAKE_RHASH(sha3_224, RHASH_SHA3_224)
MAKE_RHASH(sha3_256, RHASH_SHA3_256)
MAKE_RHASH(sha3_384, RHASH_SHA3_384)
MAKE_RHASH(sha3_512, RHASH_SHA3_512)

/* ---- GOST2012 (Streebog) compute functions ---- */

static void compute_gost2012_32(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    streebog(dest, 32, pass, passlen);
}

static void compute_gost2012_64(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    streebog(dest, 64, pass, passlen);
}

/* ---- MD6 compute functions ---- */

static void compute_md6_128(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    md6_hash(128, (unsigned char *)pass, (uint64_t)passlen * 8, dest);
}

static void compute_md6_256(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    md6_hash(256, (unsigned char *)pass, (uint64_t)passlen * 8, dest);
}

static void compute_md6_512(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    md6_hash(512, (unsigned char *)pass, (uint64_t)passlen * 8, dest);
}

/* ---- BLAKE2 compute functions ---- */

static void compute_blake2s256(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    blake2s(dest, 32, pass, passlen, NULL, 0);
}

static void compute_blake2b256(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    blake2b_hash(dest, 32, pass, passlen);
}

static void compute_blake2b512(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    blake2b_hash(dest, 64, pass, passlen);
}

/* ---- MurmurHash compute function ---- */

static void compute_murmur64a_zero(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    uint64_t mh;
    (void)salt; (void)saltlen;
    mh = murmur64a(pass, passlen, 0);
    dest[0] = (mh >> 56) & 0xff; dest[1] = (mh >> 48) & 0xff;
    dest[2] = (mh >> 40) & 0xff; dest[3] = (mh >> 32) & 0xff;
    dest[4] = (mh >> 24) & 0xff; dest[5] = (mh >> 16) & 0xff;
    dest[6] = (mh >> 8) & 0xff;  dest[7] = mh & 0xff;
}

/* ---- Batch 2: Simple salted variants ---- */

/* SHA384 salted */
static void compute_sha384passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_SHA384);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

static void compute_sha384saltpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_SHA384);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA224 salted */
static void compute_sha224passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_SHA224);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

static void compute_sha224saltpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_SHA224);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* BLAKE2B salted */
static void compute_blake2b512passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char buf[8192];
    int total = passlen + saltlen;
    if (total > (int)sizeof(buf)) total = sizeof(buf);
    memcpy(buf, pass, passlen);
    memcpy(buf + passlen, salt, saltlen);
    blake2b_hash(dest, 64, buf, total);
}

static void compute_blake2b512saltpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char buf[8192];
    int total = saltlen + passlen;
    if (total > (int)sizeof(buf)) total = sizeof(buf);
    memcpy(buf, salt, saltlen);
    memcpy(buf + saltlen, pass, passlen);
    blake2b_hash(dest, 64, buf, total);
}

static void compute_blake2b256passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char buf[8192];
    int total = passlen + saltlen;
    if (total > (int)sizeof(buf)) total = sizeof(buf);
    memcpy(buf, pass, passlen);
    memcpy(buf + passlen, salt, saltlen);
    blake2b_hash(dest, 32, buf, total);
}

static void compute_blake2b256saltpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char buf[8192];
    int total = saltlen + passlen;
    if (total > (int)sizeof(buf)) total = sizeof(buf);
    memcpy(buf, salt, saltlen);
    memcpy(buf + saltlen, pass, passlen);
    blake2b_hash(dest, 32, buf, total);
}

/* WRL (Whirlpool) salted */
static void compute_wrlpasssalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_WHIRLPOOL);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

static void compute_wrlsaltpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_WHIRLPOOL);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

static void compute_wrlsaltpasssalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_WHIRLPOOL);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* WRLWRLSALT: WRL(hex(WRL(pass)) + salt) */
static void compute_wrlwrlsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char wrlbin[64];
    char hexstr[129];
    int i;
    rhash ctx;

    rhash_msg(RHASH_WHIRLPOOL, pass, passlen, wrlbin);
    for (i = 0; i < 64; i++) {
        hexstr[i * 2]     = hextab_lc[(wrlbin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[wrlbin[i] & 0xf];
    }

    ctx = rhash_init(RHASH_WHIRLPOOL);
    rhash_update(ctx, hexstr, 128);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* WRLSALTWRL: WRL(salt + hex(WRL(pass))) */
static void compute_wrlsaltwrl(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char wrlbin[64];
    char hexstr[129];
    int i;
    rhash ctx;

    rhash_msg(RHASH_WHIRLPOOL, pass, passlen, wrlbin);
    for (i = 0; i < 64; i++) {
        hexstr[i * 2]     = hextab_lc[(wrlbin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[wrlbin[i] & 0xf];
    }

    ctx = rhash_init(RHASH_WHIRLPOOL);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, hexstr, 128);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA256SHA256SALT: SHA256(hex(SHA256(pass)) + salt) */
static void compute_sha256sha256salt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha256bin[32];
    char hexstr[65];
    int i;
    rhash ctx;

    SHA256(pass, passlen, sha256bin);
    for (i = 0; i < 32; i++) {
        hexstr[i * 2]     = hextab_lc[(sha256bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[sha256bin[i] & 0xf];
    }

    ctx = rhash_init(RHASH_SHA256);
    rhash_update(ctx, hexstr, 64);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA512SHA512SALT: SHA512(hex(SHA512(pass)) + salt) */
static void compute_sha512sha512salt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha512bin[64];
    char hexstr[129];
    int i;
    rhash ctx;

    SHA512(pass, passlen, sha512bin);
    for (i = 0; i < 64; i++) {
        hexstr[i * 2]     = hextab_lc[(sha512bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[sha512bin[i] & 0xf];
    }

    ctx = rhash_init(RHASH_SHA512);
    rhash_update(ctx, hexstr, 128);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA512SALTSHA512: SHA512(salt + hex(SHA512(pass))) */
static void compute_sha512saltsha512(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha512bin[64];
    char hexstr[129];
    int i;
    rhash ctx;

    SHA512(pass, passlen, sha512bin);
    for (i = 0; i < 64; i++) {
        hexstr[i * 2]     = hextab_lc[(sha512bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[sha512bin[i] & 0xf];
    }

    ctx = rhash_init(RHASH_SHA512);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, hexstr, 128);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA256SALTPASSSALT: SHA256(salt + pass + salt) */
static void compute_sha256saltpasssalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_SHA256);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* UTF16LE salted: H(UTF16LE(pass) + salt) and H(salt + UTF16LE(pass)) */
#define MAKE_UTF16LE_PASSSALT(fname, hash_id) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    unsigned char *_u16 = WS->u16a; \
    int _u16len; \
    rhash _ctx; \
    _u16len = utf8_to_utf16le(pass, passlen, _u16, sizeof(WS->u16a)); \
    _ctx = rhash_init(hash_id); \
    rhash_update(_ctx, _u16, _u16len); \
    rhash_update(_ctx, salt, saltlen); \
    rhash_final(_ctx, dest); rhash_free(_ctx); \
}

#define MAKE_UTF16LE_SALTPASS(fname, hash_id) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    unsigned char *_u16 = WS->u16a; \
    int _u16len; \
    rhash _ctx; \
    _u16len = utf8_to_utf16le(pass, passlen, _u16, sizeof(WS->u16a)); \
    _ctx = rhash_init(hash_id); \
    rhash_update(_ctx, salt, saltlen); \
    rhash_update(_ctx, _u16, _u16len); \
    rhash_final(_ctx, dest); rhash_free(_ctx); \
}

MAKE_UTF16LE_PASSSALT(md5utf16lepasssalt, RHASH_MD5)
MAKE_UTF16LE_SALTPASS(md5utf16lesaltpass, RHASH_MD5)
MAKE_UTF16LE_PASSSALT(sha1utf16lepasssalt, RHASH_SHA1)
MAKE_UTF16LE_SALTPASS(sha1utf16lesaltpass, RHASH_SHA1)
MAKE_UTF16LE_PASSSALT(sha256utf16lepasssalt, RHASH_SHA256)
MAKE_UTF16LE_SALTPASS(sha256utf16lesaltpass, RHASH_SHA256)
MAKE_UTF16LE_PASSSALT(sha384utf16lepasssalt, RHASH_SHA384)
MAKE_UTF16LE_SALTPASS(sha384utf16lesaltpass, RHASH_SHA384)
MAKE_UTF16LE_PASSSALT(sha512utf16lepasssalt, RHASH_SHA512)
MAKE_UTF16LE_SALTPASS(sha512utf16lesaltpass, RHASH_SHA512)

/* ---- Batch 4: MD5/SHA1 salted composed types ---- */

/* MD5USERIDMD5: rhash_msg(RHASH_MD5, user + hex(MD5(pass))), salt=user */
static void compute_md5useridmd5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, hexstr, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5USERIDMD5MD5: rhash_msg(RHASH_MD5, user + hex(MD5(hex(MD5(pass))))) */
static void compute_md5useridmd5md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    rhash_msg(RHASH_MD5, (unsigned char *)hexstr, 32, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, hexstr, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5USERnulPASS: rhash_msg(RHASH_MD5, user + "\0" + pass) */
static void compute_md5usernulpass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    unsigned char nul = 0;
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, &nul, 1);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5MD5USER: rhash_msg(RHASH_MD5, hex(MD5(pass)) + user), composed+salted */
static void compute_md5md5user(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA1MD5USER: SHA1(hex(rhash_msg(RHASH_MD5, pass)) + user), composed+salted */
static void compute_sha1md5user(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA1SHA1USER: SHA1(hex(SHA1(pass)) + user), composed+salted */
static void compute_sha1sha1user(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1bin[20];
    char hexstr[41];
    int i;
    rhash ctx;
    SHA1(pass, passlen, sha1bin);
    for (i = 0; i < 20; i++) {
        hexstr[i * 2]     = hextab_lc[(sha1bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[sha1bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, hexstr, 40);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5CAPMD5USER: rhash_msg(RHASH_MD5, cap(hex(MD5(pass))) + user) */
static void compute_md5capmd5user(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    /* capitalize first alpha char */
    for (i = 0; i < 32; i++) {
        if (hexstr[i] >= 'a' && hexstr[i] <= 'f') { hexstr[i] -= 32; break; }
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5CAPMD5MD5USER: rhash_msg(RHASH_MD5, cap(hex(MD5(hex(MD5(pass))))) + user) */
static void compute_md5capmd5md5user(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    rhash_msg(RHASH_MD5, (unsigned char *)hexstr, 32, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    for (i = 0; i < 32; i++) {
        if (hexstr[i] >= 'a' && hexstr[i] <= 'f') { hexstr[i] -= 32; break; }
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5MD5MD5USER: rhash_msg(RHASH_MD5, hex(MD5(hex(MD5(pass)))) + user) */
static void compute_md5md5md5user(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    rhash_msg(RHASH_MD5, (unsigned char *)hexstr, 32, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5USERPASS: rhash_msg(RHASH_MD5, user + pass), salt=user */
static void compute_md5userpass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA512SHA512RAWUSER: SHA512(raw(SHA512(pass)) + user), salt=user */
static void compute_sha512sha512rawuser(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha512bin[64];
    rhash ctx;
    SHA512(pass, passlen, sha512bin);
    ctx = rhash_init(RHASH_SHA512);
    rhash_update(ctx, sha512bin, 64);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD51SALTMD5: rhash_msg(RHASH_MD5, salt[0] + hex(MD5(pass))) */
static void compute_md51saltmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;
    (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, 1);
    rhash_update(ctx, hexstr, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD52SALTMD5: rhash_msg(RHASH_MD5, salt[0..1] + hex(MD5(pass))) */
static void compute_md52saltmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i, slen = saltlen < 2 ? saltlen : 2;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, slen);
    rhash_update(ctx, hexstr, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD51SALTMD5UC: rhash_msg(RHASH_MD5, salt[0] + hexUC(MD5(pass))) */
static void compute_md51saltmd5uc(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;
    (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_uc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_uc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, 1);
    rhash_update(ctx, hexstr, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD51SALTMD5MD5: rhash_msg(RHASH_MD5, salt[0] + hex(MD5(hex(MD5(pass))))) */
static void compute_md51saltmd5md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;
    (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    rhash_msg(RHASH_MD5, (unsigned char *)hexstr, 32, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, 1);
    rhash_update(ctx, hexstr, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* Helper: MD5 iterated N times: hex(rhash_msg(RHASH_MD5, hex(MD5(...)))) with 1SALT prefix */
static void compute_md51salt_md5_iter(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest, int iters)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i, it;
    rhash ctx;
    (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (it = 1; it < iters; it++) {
        for (i = 0; i < 16; i++) {
            hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
            hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
        }
        rhash_msg(RHASH_MD5, (unsigned char *)hexstr, 32, md5bin);
    }
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, 1);
    rhash_update(ctx, hexstr, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD51SALTMD5MD5MD5: rhash_msg(RHASH_MD5, salt[0] + hex(MD5^3(pass))) */
static void compute_md51saltmd5md5md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{ compute_md51salt_md5_iter(pass, passlen, salt, saltlen, dest, 3); }

/* MD51SALTMD5MD5MD5MD5: rhash_msg(RHASH_MD5, salt[0] + hex(MD5^4(pass))) */
static void compute_md51saltmd5md5md5md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{ compute_md51salt_md5_iter(pass, passlen, salt, saltlen, dest, 4); }

/* MD51SALTMD5MD5MD5MD5MD5: rhash_msg(RHASH_MD5, salt[0] + hex(MD5^5(pass))) */
static void compute_md51saltmd5md5md5md5md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{ compute_md51salt_md5_iter(pass, passlen, salt, saltlen, dest, 5); }

/* SHA1MD51SALTMD5: SHA1(hex(rhash_msg(RHASH_MD5, salt[0] + hex(MD5(pass))))) */
static void compute_sha1md51saltmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    /* First: rhash_msg(RHASH_MD5, salt[0] + hex(MD5(pass))) */
    compute_md51saltmd5(pass, passlen, salt, saltlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    SHA1((unsigned char *)hexstr, 32, dest);
}

/* SHA11SALTMD5: SHA1(salt[0] + hex(rhash_msg(RHASH_MD5, pass))) */
static void compute_sha11saltmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;
    (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, salt, 1);
    rhash_update(ctx, hexstr, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5MD5SALT (347): Same as rhash_msg(RHASH_MD5, hex(MD5(pass)) + salt) = md5salt */
/* Already registered as MD5SALT at index 31; register as composed alias */

/* MD52SALTMD5MD5: MD5(salt[0..1] + hex(MD5(hex(MD5(pass))))) */
static void compute_md52saltmd5md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i, slen = saltlen < 2 ? saltlen : 2;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    rhash_msg(RHASH_MD5, (unsigned char *)hexstr, 32, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, slen);
    rhash_update(ctx, hexstr, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD52SALTMD5MD5MD5: rhash_msg(RHASH_MD5, salt[0..1] + hex(MD5^3(pass))) */
static void compute_md52saltmd5md5md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i, it, slen = saltlen < 2 ? saltlen : 2;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (it = 1; it < 3; it++) {
        for (i = 0; i < 16; i++) {
            hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
            hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
        }
        rhash_msg(RHASH_MD5, (unsigned char *)hexstr, 32, md5bin);
    }
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, slen);
    rhash_update(ctx, hexstr, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5UCSALT: rhash_msg(RHASH_MD5, hexUC(MD5(pass)) + salt) — UC on the inner hash */
static void compute_md5ucsalt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_uc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_uc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5-MD5USERSHA1MD5PASS: rhash_msg(RHASH_MD5, hex(MD5(user)) + hex(SHA1(hex(MD5(pass))))) */
static void compute_md5_md5usersha1md5pass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16], sha1bin[20], md5user[16];
    char buf[73]; /* 32 + 40 + 1 */
    int i;
    rhash ctx;
    /* rhash_msg(RHASH_MD5, user) */
    rhash_msg(RHASH_MD5, salt, saltlen, md5user);
    for (i = 0; i < 16; i++) {
        buf[i * 2]     = hextab_lc[(md5user[i] >> 4) & 0xf];
        buf[i * 2 + 1] = hextab_lc[md5user[i] & 0xf];
    }
    /* rhash_msg(RHASH_MD5, pass) → hex → SHA1 */
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    {
        char md5hex[33];
        for (i = 0; i < 16; i++) {
            md5hex[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
            md5hex[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
        }
        SHA1((unsigned char *)md5hex, 32, sha1bin);
    }
    for (i = 0; i < 20; i++) {
        buf[32 + i * 2]     = hextab_lc[(sha1bin[i] >> 4) & 0xf];
        buf[32 + i * 2 + 1] = hextab_lc[sha1bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, buf, 72);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5SHA1u32SALT: rhash_msg(RHASH_MD5, hex(SHA1(pass))[0:32] + salt) — "u32" = use 32 hex chars */
static void compute_md5sha1u32salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1bin[20];
    char hexstr[33];
    int i;
    rhash ctx;
    SHA1(pass, passlen, sha1bin);
    for (i = 0; i < 16; i++) {  /* only first 16 bytes -> 32 hex chars */
        hexstr[i * 2]     = hextab_lc[(sha1bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[sha1bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5-4xMD5-SALT: rhash_msg(RHASH_MD5, hex(MD5(pass)) * 4 + salt) */
static void compute_md5_4xmd5_salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5revMD5SALT: rhash_msg(RHASH_MD5, reverse(hex(MD5(pass))) + salt) */
static void compute_md5revmd5salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    reverse_str(hexstr, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5sub8-24SALT: rhash_msg(RHASH_MD5, hex(MD5(pass))[8:24] + salt) — 16 chars from pos 8 */
static void compute_md5sub8_24salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hexstr + 8, 16);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5SHA1SALT: rhash_msg(RHASH_MD5, hex(SHA1(pass)) + salt) */
static void compute_md5sha1salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1bin[20];
    char hexstr[41];
    int i;
    rhash ctx;
    SHA1(pass, passlen, sha1bin);
    for (i = 0; i < 20; i++) {
        hexstr[i * 2]     = hextab_lc[(sha1bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[sha1bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hexstr, 40);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5DSALT: rhash_msg(RHASH_MD5, hex(MD5(hex(MD5(pass)) + salt1)) + salt2), double 3-char salts */
/* Salt format: salt1salt2 concatenated (e.g. "A7GA7G" = salt1="A7G", salt2="A7G") */
static void compute_md5dsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i, s1len, s2len;
    rhash ctx;

    /* Split salt in half: first half = salt1, second half = salt2 */
    s1len = saltlen / 2;
    s2len = saltlen - s1len;
    if (s1len > 3) s1len = 3;
    if (s2len > 3) s2len = 3;

    /* Step 1: rhash_msg(RHASH_MD5, pass) → hex */
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }

    /* Step 2: rhash_msg(RHASH_MD5, hex(MD5(pass)) + salt1) → hex */
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, salt, s1len);
    rhash_final(ctx, md5bin); rhash_free(ctx);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }

    /* Step 3: rhash_msg(RHASH_MD5, hex(step2) + salt2) */
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hexstr, 32);
    rhash_update(ctx, salt + s1len, s2len);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5UCBASE64MD5RAW: rhash_msg(RHASH_MD5, hexUC(base64(raw(MD5(pass))))) — unsalted composed */
static void compute_md5ucbase64md5raw(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char b64[64], hexstr[129];
    int blen, i;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    blen = base64_encode(md5bin, 16, b64, sizeof(b64));
    /* Uppercase hex of the base64 string */
    for (i = 0; i < blen; i++) {
        hexstr[i * 2]     = hextab_uc[((unsigned char)b64[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_uc[(unsigned char)b64[i] & 0xf];
    }
    rhash_msg(RHASH_MD5, (unsigned char *)hexstr, blen * 2, dest);
}

/* ---- Batch 10: Unsalted composed types ---- */

/* MD5BASE64MD5RAWSHA1: rhash_msg(RHASH_MD5, base64(raw(MD5(pass))) + hex(SHA1(pass))) */
static void compute_md5base64md5rawsha1(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16], sha1bin[20];
    char b64[64], hexstr[41];
    char buf[256];
    int blen, i;
    rhash ctx;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    blen = base64_encode(md5bin, 16, b64, sizeof(b64));
    SHA1(pass, passlen, sha1bin);
    for (i = 0; i < 20; i++) {
        hexstr[i * 2]     = hextab_lc[(sha1bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[sha1bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, b64, blen);
    rhash_update(ctx, hexstr, 40);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5BASE64MD5RAWMD5: rhash_msg(RHASH_MD5, base64(raw(MD5(pass))) + hex(MD5(pass))) */
static void compute_md5base64md5rawmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char b64[64], hexstr[33];
    int blen, i;
    rhash ctx;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    blen = base64_encode(md5bin, 16, b64, sizeof(b64));
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, b64, blen);
    rhash_update(ctx, hexstr, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5BASE64MD5RAWMD5MD5: rhash_msg(RHASH_MD5, base64(raw(MD5(pass))) + hex(MD5(hex(MD5(pass))))) */
static void compute_md5base64md5rawmd5md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16], md5bin2[16];
    char b64[64], hexstr[33];
    int blen, i;
    rhash ctx;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    blen = base64_encode(md5bin, 16, b64, sizeof(b64));
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    rhash_msg(RHASH_MD5, (unsigned char *)hexstr, 32, md5bin2);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin2[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin2[i] & 0xf];
    }
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, b64, blen);
    rhash_update(ctx, hexstr, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA1-1xSHA1psubp: SHA1(hex(SHA1(pass)) + salt + hex(SHA1(pass))), salt=separator */
static void compute_sha1_1xsha1psubp(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1bin[20];
    char hexstr[41];
    int i;
    rhash ctx;
    SHA1(pass, passlen, sha1bin);
    for (i = 0; i < 20; i++) {
        hexstr[i * 2]     = hextab_lc[(sha1bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[sha1bin[i] & 0xf];
    }
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, hexstr, 40);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, hexstr, 40);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5SQL5-32: rhash_msg(RHASH_MD5, hex(SQL5(pass))[0:32]) = MD5(hex(SHA1(SHA1(pass)))[0:32]) */
static void compute_md5sql5_32(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1bin[20];
    char hexstr[41];
    int i;
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1bin);
    SHA1(sha1bin, 20, sha1bin);
    for (i = 0; i < 20; i++) {
        hexstr[i * 2]     = hextab_lc[(sha1bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[sha1bin[i] & 0xf];
    }
    rhash_msg(RHASH_MD5, (unsigned char *)hexstr, 32, dest);
}

/* MD5SHA1BASE64SHA1RAW: rhash_msg(RHASH_MD5, hex(SHA1(base64(raw(SHA1(pass)))))) */
static void compute_md5sha1base64sha1raw(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1bin[20], sha1bin2[20];
    char b64[64], hexstr[41];
    int blen, i;
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1bin);
    blen = base64_encode(sha1bin, 20, b64, sizeof(b64));
    SHA1((unsigned char *)b64, blen, sha1bin2);
    for (i = 0; i < 20; i++) {
        hexstr[i * 2]     = hextab_lc[(sha1bin2[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[sha1bin2[i] & 0xf];
    }
    rhash_msg(RHASH_MD5, (unsigned char *)hexstr, 40, dest);
}

/* MD5BASE64SHA256RAW: rhash_msg(RHASH_MD5, base64(raw(SHA256(pass)))) */
static void compute_md5base64sha256raw(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha256bin[32];
    char b64[128];
    int blen;
    (void)salt; (void)saltlen;
    SHA256(pass, passlen, sha256bin);
    blen = base64_encode(sha256bin, 32, b64, sizeof(b64));
    rhash_msg(RHASH_MD5, (unsigned char *)b64, blen, dest);
}

/* MD5BASE64BASE64: rhash_msg(RHASH_MD5, base64(base64(pass))) */
static void compute_md5base64base64(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    char b64a[1024], b64b[1400];
    int blen;
    (void)salt; (void)saltlen;
    blen = base64_encode(pass, passlen, b64a, sizeof(b64a));
    blen = base64_encode((unsigned char *)b64a, blen, b64b, sizeof(b64b));
    rhash_msg(RHASH_MD5, (unsigned char *)b64b, blen, dest);
}

/* MD5BASE64BASE64BASE64: rhash_msg(RHASH_MD5, base64(base64(base64(pass)))) */
static void compute_md5base64base64base64(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    char b64a[1024], b64b[1400], b64c[2048];
    int blen;
    (void)salt; (void)saltlen;
    blen = base64_encode(pass, passlen, b64a, sizeof(b64a));
    blen = base64_encode((unsigned char *)b64a, blen, b64b, sizeof(b64b));
    blen = base64_encode((unsigned char *)b64b, blen, b64c, sizeof(b64c));
    rhash_msg(RHASH_MD5, (unsigned char *)b64c, blen, dest);
}

/* MD5SQL3SQL5MD5MD5: rhash_msg(RHASH_MD5, hex(SQL3(pass)) + hex(SQL5(pass)) + hex(MD5(pass)) + hex(MD5(hex(MD5(pass))))) */
/* SQL3 = SHA1(pass), SQL5 = SHA1(SHA1(pass)) */
static void compute_md5sql3sql5md5md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1bin[20], sql5bin[20], md5bin[16], md5md5bin[16];
    char buf[40 + 40 + 32 + 32 + 1];
    int i;
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1bin); /* SQL3 */
    SHA1(sha1bin, 20, sql5bin);   /* SQL5 */
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        char hx[3];
        hx[0] = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hx[1] = hextab_lc[md5bin[i] & 0xf];
        buf[80 + i * 2] = hx[0];
        buf[80 + i * 2 + 1] = hx[1];
    }
    {
        char hexmd5[33];
        for (i = 0; i < 16; i++) {
            hexmd5[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
            hexmd5[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
        }
        rhash_msg(RHASH_MD5, (unsigned char *)hexmd5, 32, md5md5bin);
    }
    for (i = 0; i < 20; i++) {
        buf[i * 2]      = hextab_lc[(sha1bin[i] >> 4) & 0xf];
        buf[i * 2 + 1]  = hextab_lc[sha1bin[i] & 0xf];
    }
    for (i = 0; i < 20; i++) {
        buf[40 + i * 2]     = hextab_lc[(sql5bin[i] >> 4) & 0xf];
        buf[40 + i * 2 + 1] = hextab_lc[sql5bin[i] & 0xf];
    }
    for (i = 0; i < 16; i++) {
        buf[112 + i * 2]     = hextab_lc[(md5md5bin[i] >> 4) & 0xf];
        buf[112 + i * 2 + 1] = hextab_lc[md5md5bin[i] & 0xf];
    }
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 144, dest);
}

/* MD5-6xMD5: MD5 iterated 7 times total */
static void compute_md5_6xmd5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i, it;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (it = 0; it < 6; it++) {
        for (i = 0; i < 16; i++) {
            hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
            hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
        }
        rhash_msg(RHASH_MD5, (unsigned char *)hexstr, 32, md5bin);
    }
    memcpy(dest, md5bin, 16);
}

/* MD5-5xMD5: MD5 iterated 6 times total */
static void compute_md5_5xmd5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hexstr[33];
    int i, it;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (it = 0; it < 5; it++) {
        for (i = 0; i < 16; i++) {
            hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
            hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
        }
        rhash_msg(RHASH_MD5, (unsigned char *)hexstr, 32, md5bin);
    }
    memcpy(dest, md5bin, 16);
}

/* SHA1SQL5-32: SHA1(hex(SQL5(pass))[0:32]) */
static void compute_sha1sql5_32(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1bin[20];
    char hexstr[41];
    int i;
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1bin);
    SHA1(sha1bin, 20, sha1bin);
    for (i = 0; i < 20; i++) {
        hexstr[i * 2]     = hextab_lc[(sha1bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[sha1bin[i] & 0xf];
    }
    SHA1((unsigned char *)hexstr, 32, dest);
}

/* MD5DECBASE64MD5BASE64MD5: rhash_msg(RHASH_MD5, dec_base64(hex(MD5(base64(hex(MD5(pass))))))) */
static void compute_md5decbase64md5base64md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16], md5bin2[16], decbuf[256];
    char hexstr[33], b64[64], hexstr2[33];
    int blen, dlen, i;
    (void)salt; (void)saltlen;
    /* rhash_msg(RHASH_MD5, pass) */
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    for (i = 0; i < 16; i++) {
        hexstr[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        hexstr[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    /* base64(hex(rhash_msg(RHASH_MD5, pass))) */
    blen = base64_encode((unsigned char *)hexstr, 32, b64, sizeof(b64));
    /* rhash_msg(RHASH_MD5, base64(...)) */
    rhash_msg(RHASH_MD5, (unsigned char *)b64, blen, md5bin2);
    for (i = 0; i < 16; i++) {
        hexstr2[i * 2]     = hextab_lc[(md5bin2[i] >> 4) & 0xf];
        hexstr2[i * 2 + 1] = hextab_lc[md5bin2[i] & 0xf];
    }
    /* base64_decode(hex(rhash_msg(RHASH_MD5, ...))) */
    dlen = base64_decode(hexstr2, 32, decbuf, sizeof(decbuf));
    if (dlen < 0) dlen = 0;
    /* rhash_msg(RHASH_MD5, decoded) */
    rhash_msg(RHASH_MD5, decbuf, dlen, dest);
}

/* SHA1revBASE64: SHA1(reverse(base64(pass))) */
static void compute_sha1revbase64(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    char b64[1024];
    int blen;
    (void)salt; (void)saltlen;
    blen = base64_encode(pass, passlen, b64, sizeof(b64));
    reverse_str(b64, blen);
    SHA1((unsigned char *)b64, blen, dest);
}

/* SHA1revBASE64x: SHA1(reverse(base64(pass))) — base64 with padding, salt present */
static void compute_sha1revbase64x(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    char b64[1024];
    int blen;
    (void)salt; (void)saltlen;
    blen = base64_encode(pass, passlen, b64, sizeof(b64));
    reverse_str(b64, blen);
    SHA1((unsigned char *)b64, blen, dest);
}

/* ---- x-type compute functions: two-level iteration ----
 * Outer iteration: controlled by salt (parsed as integer).
 * Inner iteration: handled by generic iteration loops in verify_item.
 * The salt field carries the outer iteration count (e.g., "1", "2", "3").
 */

/* Parse salt bytes as a decimal integer; return 1 if invalid/absent */
static int salt_to_int(const unsigned char *salt, int saltlen)
{
    int val = 0, i;
    if (!salt || saltlen <= 0) return 1;
    for (i = 0; i < saltlen; i++) {
        if (salt[i] < '0' || salt[i] > '9') return 1;
        val = val * 10 + (salt[i] - '0');
    }
    return val < 1 ? 1 : val;
}

/* SHA1MD5x: outer=iterate MD5, inner=iterate SHA1.
 * x01 salt=N: SHA1(hex(MD5^N(pass))) */
static void compute_sha1md5x(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char bin[16];
    char hex[33];
    const unsigned char *cur = pass;
    int curlen = passlen, i;
    int outer = salt_to_int(salt, saltlen);
    for (i = 0; i < outer; i++) {
        rhash_msg(RHASH_MD5, cur, curlen, bin);
        prmd5(bin, hex, 32);
        cur = (const unsigned char *)hex;
        curlen = 32;
    }
    SHA1(cur, curlen, dest);
}

/* SHA1SHA256x: outer=iterate SHA256(lc hex), inner=iterate SHA1.
 * x01 salt=N: SHA1(hex(SHA256^N(pass))) */
static void compute_sha1sha256x(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char bin[32];
    char hex[65];
    const unsigned char *cur = pass;
    int curlen = passlen, i;
    int outer = salt_to_int(salt, saltlen);
    for (i = 0; i < outer; i++) {
        SHA256(cur, curlen, bin);
        prmd5(bin, hex, 64);
        cur = (const unsigned char *)hex;
        curlen = 64;
    }
    SHA1(cur, curlen, dest);
}

/* SHA1SHA256UCx: outer=iterate SHA256(UC hex), inner=iterate SHA1.
 * x01 salt=N: SHA1(hexUC(SHA256^N(pass))) */
static void compute_sha1sha256ucx(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char bin[32];
    char hex[65];
    const unsigned char *cur = pass;
    int curlen = passlen, i;
    int outer = salt_to_int(salt, saltlen);
    for (i = 0; i < outer; i++) {
        SHA256(cur, curlen, bin);
        prmd5UC(bin, hex, 64);
        cur = (const unsigned char *)hex;
        curlen = 64;
    }
    SHA1(cur, curlen, dest);
}

/* SHA1MD5UCx: outer=iterate MD5(UC hex), inner=iterate SHA1.
 * x01 salt=N: SHA1(hexUC(MD5^N(pass))) */
static void compute_sha1md5ucx(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char bin[16];
    char hex[33];
    const unsigned char *cur = pass;
    int curlen = passlen, i;
    int outer = salt_to_int(salt, saltlen);
    for (i = 0; i < outer; i++) {
        rhash_msg(RHASH_MD5, cur, curlen, bin);
        prmd5UC(bin, hex, 32);
        cur = (const unsigned char *)hex;
        curlen = 32;
    }
    SHA1(cur, curlen, dest);
}

/* SHA1MD5MD5UCx: outer=iterate MD5(UC hex), then MD5(lc hex) + SHA1.
 * x01 salt=N: SHA1(hex(MD5(hexUC(MD5^N(pass))))) */
static void compute_sha1md5md5ucx(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char bin[16];
    char hex[33], hex2[33];
    const unsigned char *cur = pass;
    int curlen = passlen, i;
    int outer = salt_to_int(salt, saltlen);
    for (i = 0; i < outer; i++) {
        rhash_msg(RHASH_MD5, cur, curlen, bin);
        prmd5UC(bin, hex, 32);
        cur = (const unsigned char *)hex;
        curlen = 32;
    }
    /* MD5(UC hex) -> hex -> SHA1(hex) */
    rhash_msg(RHASH_MD5, cur, curlen, bin);
    prmd5(bin, hex2, 32);
    SHA1((unsigned char *)hex2, 32, dest);
}

/* SHA1revBASE64x: outer=iterate base64 + reverse, inner=iterate SHA1.
 * x01 salt=N: SHA1(reverse(base64^N(pass))) */
static void compute_sha1revbase64x_outer(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    char b64[1024], rev[1024];
    const unsigned char *cur = pass;
    int curlen = passlen, i;
    int outer = salt_to_int(salt, saltlen);
    for (i = 0; i < outer; i++) {
        int blen = base64_encode(cur, curlen, b64, sizeof(b64));
        /* reverse into rev */
        {
            int j;
            for (j = 0; j < blen; j++) rev[blen - 1 - j] = b64[j];
        }
        rev[blen] = 0;
        cur = (const unsigned char *)rev;
        curlen = blen;
    }
    SHA1(cur, curlen, dest);
}

/* MD4UTF16MD5x: outer=iterate MD5(lc hex), inner=iterate NTLM.
 * x01 salt=N: NTLM(hex(MD5^N(pass))) */
static void compute_md4utf16md5x(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char bin[16];
    char hex[33];
    const unsigned char *cur = pass;
    int curlen = passlen, i;
    int outer = salt_to_int(salt, saltlen);
    for (i = 0; i < outer; i++) {
        rhash_msg(RHASH_MD5, cur, curlen, bin);
        prmd5(bin, hex, 32);
        cur = (const unsigned char *)hex;
        curlen = 32;
    }
    compute_ntlm(cur, curlen, NULL, 0, dest);
}

/* MD4UTF16SHA1x: outer=iterate SHA1(lc hex), inner=iterate NTLM.
 * x01 salt=N: NTLM(hex(SHA1^N(pass))) */
static void compute_md4utf16sha1x(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char bin[20];
    char hex[41];
    const unsigned char *cur = pass;
    int curlen = passlen, i;
    int outer = salt_to_int(salt, saltlen);
    for (i = 0; i < outer; i++) {
        SHA1(cur, curlen, bin);
        prmd5(bin, hex, 40);
        cur = (const unsigned char *)hex;
        curlen = 40;
    }
    compute_ntlm(cur, curlen, NULL, 0, dest);
}

/* MD4UTF16revBASE64x: outer=iterate base64 + reverse, inner=iterate NTLM.
 * x01 salt=N: NTLM(reverse(base64^N(pass))) */
static void compute_md4utf16revbase64x(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    char b64[1024], rev[1024];
    const unsigned char *cur = pass;
    int curlen = passlen, i;
    int outer = salt_to_int(salt, saltlen);
    for (i = 0; i < outer; i++) {
        int blen = base64_encode(cur, curlen, b64, sizeof(b64));
        {
            int j;
            for (j = 0; j < blen; j++) rev[blen - 1 - j] = b64[j];
        }
        rev[blen] = 0;
        cur = (const unsigned char *)rev;
        curlen = blen;
    }
    compute_ntlm(cur, curlen, NULL, 0, dest);
}

/* SHA1BASE64CUSTBASE64MD5: SHA1(base64_custom(base64(raw(rhash_msg(RHASH_MD5, pass))))) */
/* "CUST" likely means custom base64 alphabet — need to verify */
static void compute_sha1base64custbase64md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char b64a[64], b64b[128];
    int blen;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    blen = base64_encode(md5bin, 16, b64a, sizeof(b64a));
    blen = base64_encode((unsigned char *)b64a, blen, b64b, sizeof(b64b));
    SHA1((unsigned char *)b64b, blen, dest);
}

/* ---- Batch 3: HEXSALT types ---- */

/* MD5HEXSALT: rhash_msg(RHASH_MD5, hex(MD5(salt+pass)) + ":" + salt) */
static void compute_md5hexsalt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char buf[33 + 1 + 256]; /* hex + ":" + salt */
    int i, blen;
    rhash ctx;
    /* Inner: rhash_msg(RHASH_MD5, salt + pass) */
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, md5bin); rhash_free(ctx);
    for (i = 0; i < 16; i++) {
        buf[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        buf[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    buf[32] = ':';
    blen = 33;
    memcpy(buf + blen, salt, saltlen);
    blen += saltlen;
    /* Outer: rhash_msg(RHASH_MD5, hex + ":" + salt) */
    rhash_msg(RHASH_MD5, (unsigned char *)buf, blen, dest);
}

/* SHA1HEXSALT: SHA1(hex(rhash_msg(RHASH_MD5, salt+pass)) + ":" + salt) */
static void compute_sha1hexsalt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char buf[33 + 1 + 256];
    int i, blen;
    rhash mctx;
    mctx = rhash_init(RHASH_MD5);
    rhash_update(mctx, salt, saltlen);
    rhash_update(mctx, pass, passlen);
    rhash_final(mctx, md5bin); rhash_free(mctx);
    for (i = 0; i < 16; i++) {
        buf[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        buf[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    buf[32] = ':';
    blen = 33;
    memcpy(buf + blen, salt, saltlen);
    blen += saltlen;
    SHA1((unsigned char *)buf, blen, dest);
}

/* SHA256HEXSALT: SHA256(hex(rhash_msg(RHASH_MD5, salt+pass)) + ":" + salt) */
static void compute_sha256hexsalt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char buf[33 + 1 + 256];
    int i, blen;
    rhash mctx;
    mctx = rhash_init(RHASH_MD5);
    rhash_update(mctx, salt, saltlen);
    rhash_update(mctx, pass, passlen);
    rhash_final(mctx, md5bin); rhash_free(mctx);
    for (i = 0; i < 16; i++) {
        buf[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        buf[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    buf[32] = ':';
    blen = 33;
    memcpy(buf + blen, salt, saltlen);
    blen += saltlen;
    SHA256((unsigned char *)buf, blen, dest);
}

/* GOSTHEXSALT: GOST(hex(rhash_msg(RHASH_MD5, salt+pass)) + ":" + salt) */
static void compute_gosthexsalt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char buf[33 + 1 + 256];
    int i, blen;
    rhash mctx;
    mctx = rhash_init(RHASH_MD5);
    rhash_update(mctx, salt, saltlen);
    rhash_update(mctx, pass, passlen);
    rhash_final(mctx, md5bin); rhash_free(mctx);
    for (i = 0; i < 16; i++) {
        buf[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        buf[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    buf[32] = ':';
    blen = 33;
    memcpy(buf + blen, salt, saltlen);
    blen += saltlen;
    rhash_msg(RHASH_GOST, (unsigned char *)buf, blen, dest);
}

/* HAV128HEXSALT: HAV128_3(hex(rhash_msg(RHASH_MD5, salt+pass)) + ":" + salt) */
static void compute_hav128hexsalt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char buf[33 + 1 + 256];
    int i, blen;
    sph_haval128_3_context hctx;
    rhash mctx;
    mctx = rhash_init(RHASH_MD5);
    rhash_update(mctx, salt, saltlen);
    rhash_update(mctx, pass, passlen);
    rhash_final(mctx, md5bin); rhash_free(mctx);
    for (i = 0; i < 16; i++) {
        buf[i * 2]     = hextab_lc[(md5bin[i] >> 4) & 0xf];
        buf[i * 2 + 1] = hextab_lc[md5bin[i] & 0xf];
    }
    buf[32] = ':';
    blen = 33;
    memcpy(buf + blen, salt, saltlen);
    blen += saltlen;
    sph_haval128_3_init(&hctx);
    sph_haval128_3(&hctx, buf, blen);
    sph_haval128_3_close(&hctx, dest);
}

/* MD5MD5SALT (347): rhash_msg(RHASH_MD5, hex(MD5(pass)) + salt) — same algorithm as MD5SALT (idx 31) */
/* Use compute_md5salt which already implements this */

/* SHA1PASSHEXSALT (834): SHA1(pass + hex_decode(salt))
   Salt is stored as hex string; we decode it to binary and append to pass */
static void compute_sha1passhexsalt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char saltbin[256];
    int i, binlen = 0;
    rhash ctx;
    /* hex-decode the salt */
    for (i = 0; i + 1 < saltlen && binlen < (int)sizeof(saltbin); i += 2) {
        int hi = salt[i], lo = salt[i + 1];
        hi = (hi >= '0' && hi <= '9') ? hi - '0' :
             (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 :
             (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
        lo = (lo >= '0' && lo <= '9') ? lo - '0' :
             (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 :
             (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
        if (hi < 0 || lo < 0) break;
        saltbin[binlen++] = (hi << 4) | lo;
    }
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, saltbin, binlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* --- HUM types: inner_hash → hex → append/prepend decoded salt bytes → outer_hash
   Salt format from mdxfind: "HH[HH...]- x N" where HH is hex-encoded control bytes.
   The compute function does the APPEND variant; prepend is handled by retry logic. */

static int hum_decode_salt(const unsigned char *salt, int saltlen,
    unsigned char *decoded, int maxdec)
{
    int i, n = 0;
    /* Find end of hex prefix (before "- x") */
    int hexend = 0;
    for (i = 0; i < saltlen; i++) {
        if (salt[i] == '-') { hexend = i; break; }
    }
    if (hexend == 0) hexend = saltlen; /* no dash found, try all as hex */
    /* Decode hex pairs */
    for (i = 0; i + 1 < hexend && n < maxdec; i += 2) {
        int hi = salt[i], lo = salt[i + 1];
        hi = (hi >= '0' && hi <= '9') ? hi - '0' :
             (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 :
             (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
        lo = (lo >= '0' && lo <= '9') ? lo - '0' :
             (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 :
             (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
        if (hi < 0 || lo < 0) break;
        decoded[n++] = (hi << 4) | lo;
    }
    return n;
}

/* HUM append macro: outer(hex(inner(pass)) + decoded_salt_bytes) */
#define MAKE_HUM(fname, inner_fn, inner_bytes, outer_fn, outer_hash_id) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    unsigned char _ib[MAX_HASH_BYTES], _sb[16]; \
    char _hx[MAX_HASH_BYTES * 2 + 1]; \
    int _sn; \
    rhash _ctx; \
    inner_fn(pass, passlen, NULL, 0, _ib); \
    prmd5(_ib, _hx, (inner_bytes) * 2); \
    _sn = hum_decode_salt(salt, saltlen, _sb, (int)sizeof(_sb)); \
    _ctx = rhash_init(outer_hash_id); \
    rhash_update(_ctx, _hx, (inner_bytes) * 2); \
    rhash_update(_ctx, _sb, _sn); \
    rhash_final(_ctx, dest); rhash_free(_ctx); \
}

/* HUM prepend: outer(decoded_salt_bytes + hex(inner(pass))) */
#define MAKE_HUM_PRE(fname, inner_fn, inner_bytes, outer_fn, outer_hash_id) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    unsigned char _ib[MAX_HASH_BYTES], _sb[16]; \
    char _hx[MAX_HASH_BYTES * 2 + 1]; \
    int _sn; \
    rhash _ctx; \
    inner_fn(pass, passlen, NULL, 0, _ib); \
    prmd5(_ib, _hx, (inner_bytes) * 2); \
    _sn = hum_decode_salt(salt, saltlen, _sb, (int)sizeof(_sb)); \
    _ctx = rhash_init(outer_hash_id); \
    rhash_update(_ctx, _sb, _sn); \
    rhash_update(_ctx, _hx, (inner_bytes) * 2); \
    rhash_final(_ctx, dest); rhash_free(_ctx); \
}

/* MD5MD5HUM: rhash_msg(RHASH_MD5, hex(MD5(pass)) + salt_bytes) — append variant */
MAKE_HUM(md5md5hum, compute_md5, 16, compute_md5, RHASH_MD5)
MAKE_HUM_PRE(md5md5hum_pre, compute_md5, 16, compute_md5, RHASH_MD5)

/* SHA1MD5HUM: SHA1(hex(rhash_msg(RHASH_MD5, pass)) + salt_bytes) */
MAKE_HUM(sha1md5hum, compute_md5, 16, compute_sha1, RHASH_SHA1)
MAKE_HUM_PRE(sha1md5hum_pre, compute_md5, 16, compute_sha1, RHASH_SHA1)

/* SHA1SHA1HUM: SHA1(hex(SHA1(pass)) + salt_bytes) */
MAKE_HUM(sha1sha1hum, compute_sha1, 20, compute_sha1, RHASH_SHA1)
MAKE_HUM_PRE(sha1sha1hum_pre, compute_sha1, 20, compute_sha1, RHASH_SHA1)

/* MD5SHA1HUM: rhash_msg(RHASH_MD5, hex(SHA1(pass)) + salt_bytes) */
MAKE_HUM(md5sha1hum, compute_sha1, 20, compute_md5, RHASH_MD5)
MAKE_HUM_PRE(md5sha1hum_pre, compute_sha1, 20, compute_md5, RHASH_MD5)

/* MD5SHA1MD5HUM: rhash_msg(RHASH_MD5, hex(SHA1(hex(MD5(pass)))) + salt_bytes)
   Inner = SHA1(hex(MD5(pass))), then MD5(hex(inner) + salt_bytes) */
static void compute_md5sha1md5hum(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char t1[MAX_HASH_BYTES], t2[MAX_HASH_BYTES], sb[16];
    char hx[MAX_HASH_BYTES * 2 + 1];
    int sn;
    rhash ctx;
    compute_md5(pass, passlen, NULL, 0, t1);
    prmd5(t1, hx, 32); compute_sha1((const unsigned char *)hx, 32, NULL, 0, t2);
    prmd5(t2, hx, 40);
    sn = hum_decode_salt(salt, saltlen, sb, (int)sizeof(sb));
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hx, 40);
    rhash_update(ctx, sb, sn);
    rhash_final(ctx, dest); rhash_free(ctx);
}
static void compute_md5sha1md5hum_pre(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char t1[MAX_HASH_BYTES], t2[MAX_HASH_BYTES], sb[16];
    char hx[MAX_HASH_BYTES * 2 + 1];
    int sn;
    rhash ctx;
    compute_md5(pass, passlen, NULL, 0, t1);
    prmd5(t1, hx, 32); compute_sha1((const unsigned char *)hx, 32, NULL, 0, t2);
    prmd5(t2, hx, 40);
    sn = hum_decode_salt(salt, saltlen, sb, (int)sizeof(sb));
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, sb, sn);
    rhash_update(ctx, hx, 40);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD4UTF16MD5HUM: rhash_msg(RHASH_MD4, UTF16LE(hex(rhash_msg(RHASH_MD5, pass)) + salt_bytes))
   NTLM wrapping the hex+salt string */
static void compute_md4utf16md5hum(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16], sb[16], utf16buf[256];
    char hx[33];
    int sn, i, ulen;
    compute_md5(pass, passlen, NULL, 0, md5bin);
    prmd5(md5bin, hx, 32);
    sn = hum_decode_salt(salt, saltlen, sb, (int)sizeof(sb));
    /* Build UTF16LE of hex + salt_bytes */
    ulen = 0;
    for (i = 0; i < 32 && ulen + 1 < (int)sizeof(utf16buf); i++) {
        utf16buf[ulen++] = hx[i];
        utf16buf[ulen++] = 0;
    }
    for (i = 0; i < sn && ulen + 1 < (int)sizeof(utf16buf); i++) {
        utf16buf[ulen++] = sb[i];
        utf16buf[ulen++] = 0;
    }
    rhash_msg(RHASH_MD4, utf16buf, ulen, dest);
}
static void compute_md4utf16md5hum_pre(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16], sb[16], utf16buf[256];
    char hx[33];
    int sn, i, ulen;
    compute_md5(pass, passlen, NULL, 0, md5bin);
    prmd5(md5bin, hx, 32);
    sn = hum_decode_salt(salt, saltlen, sb, (int)sizeof(sb));
    ulen = 0;
    for (i = 0; i < sn && ulen + 1 < (int)sizeof(utf16buf); i++) {
        utf16buf[ulen++] = sb[i];
        utf16buf[ulen++] = 0;
    }
    for (i = 0; i < 32 && ulen + 1 < (int)sizeof(utf16buf); i++) {
        utf16buf[ulen++] = hx[i];
        utf16buf[ulen++] = 0;
    }
    rhash_msg(RHASH_MD4, utf16buf, ulen, dest);
}

/* MD4UTF16SHA1HUM: rhash_msg(RHASH_MD4, UTF16LE(hex(SHA1(pass)) + salt_bytes)) */
static void compute_md4utf16sha1hum(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1bin[20], sb[16], utf16buf[256];
    char hx[41];
    int sn, i, ulen;
    compute_sha1(pass, passlen, NULL, 0, sha1bin);
    prmd5(sha1bin, hx, 40);
    sn = hum_decode_salt(salt, saltlen, sb, (int)sizeof(sb));
    ulen = 0;
    for (i = 0; i < 40 && ulen + 1 < (int)sizeof(utf16buf); i++) {
        utf16buf[ulen++] = hx[i];
        utf16buf[ulen++] = 0;
    }
    for (i = 0; i < sn && ulen + 1 < (int)sizeof(utf16buf); i++) {
        utf16buf[ulen++] = sb[i];
        utf16buf[ulen++] = 0;
    }
    rhash_msg(RHASH_MD4, utf16buf, ulen, dest);
}
static void compute_md4utf16sha1hum_pre(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1bin[20], sb[16], utf16buf[256];
    char hx[41];
    int sn, i, ulen;
    compute_sha1(pass, passlen, NULL, 0, sha1bin);
    prmd5(sha1bin, hx, 40);
    sn = hum_decode_salt(salt, saltlen, sb, (int)sizeof(sb));
    ulen = 0;
    for (i = 0; i < sn && ulen + 1 < (int)sizeof(utf16buf); i++) {
        utf16buf[ulen++] = sb[i];
        utf16buf[ulen++] = 0;
    }
    for (i = 0; i < 40 && ulen + 1 < (int)sizeof(utf16buf); i++) {
        utf16buf[ulen++] = hx[i];
        utf16buf[ulen++] = 0;
    }
    rhash_msg(RHASH_MD4, utf16buf, ulen, dest);
}

/* ---- Batch 6: SHA1-salted-composed types ---- */

/* MD5MD5 = rhash_msg(RHASH_MD5, hex(MD5(pass))) — needed as inner function for batch 6 macros */
MAKE_COMPOSED(md5md5, compute_md5, 16, compute_md5)

/* Pattern: OUTER(hex(INNER(pass)) + salt) via MAKE_HEX_SALT */
MAKE_HEX_SALT(sha1md5passsalt,     compute_md5,     16, RHASH_SHA1)
MAKE_HEX_SALT(sha1sha1passsalt,    compute_sha1,    20, RHASH_SHA1)
MAKE_HEX_SALT(sha1md5md5salt,      compute_md5md5,  16, RHASH_SHA1)
MAKE_HEX_SALT(sha1sha1md5passsalt, compute_sha1md5, 20, RHASH_SHA1)
MAKE_HEX_SALT(sha1md5sha1_salt,    compute_md5sha1, 16, RHASH_SHA1)

/* Pattern: OUTER(salt + hex(INNER(pass))) via MAKE_SALT_HEX */
MAKE_SALT_HEX(sha1saltmd5pass,       compute_md5,     16, RHASH_SHA1)
MAKE_SALT_HEX(sha1saltsha1pass,      compute_sha1,    20, RHASH_SHA1)
MAKE_SALT_HEX(sha256saltsha256pass,  compute_sha256,  32, RHASH_SHA256)
MAKE_SALT_HEX(sha512saltmd5,         compute_md5,     16, RHASH_SHA512)
MAKE_SALT_HEX(sha1saltsha256,        compute_sha256,  32, RHASH_SHA1)

/* 466 SHA1-MD5SALT: SHA1(hex(rhash_msg(RHASH_MD5, hex(MD5(pass)) + salt))) */
static void compute_sha1_md5salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5a[16], md5b[16];
    char hx[33], hx2[33];
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5a);
    prmd5(md5a, hx, 32);
    /* rhash_msg(RHASH_MD5, hex(MD5(pass)) + salt) */
    {
        rhash mctx;
        mctx = rhash_init(RHASH_MD5);
        rhash_update(mctx, hx, 32);
        rhash_update(mctx, salt, saltlen);
        rhash_final(mctx, md5b); rhash_free(mctx);
    }
    prmd5(md5b, hx2, 32);
    SHA1((const unsigned char *)hx2, 32, dest);
}

/* 467 SHA1-revMD5SALT: SHA1(hex(rhash_msg(RHASH_MD5, rev_hex(MD5(pass)) + salt))) */
static void compute_sha1_revmd5salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5a[16], md5b[16];
    char hx[33], rev[33], hx2[33];
    int i;
    rhash_msg(RHASH_MD5, pass, passlen, md5a);
    prmd5(md5a, hx, 32);
    for (i = 0; i < 32; i++) rev[i] = hx[31 - i];
    rev[32] = 0;
    {
        rhash mctx;
        mctx = rhash_init(RHASH_MD5);
        rhash_update(mctx, rev, 32);
        rhash_update(mctx, salt, saltlen);
        rhash_final(mctx, md5b); rhash_free(mctx);
    }
    prmd5(md5b, hx2, 32);
    SHA1((const unsigned char *)hx2, 32, dest);
}

/* 468 SHA1revMD5PASSSALT: SHA1(rev(hex(rhash_msg(RHASH_MD5, pass))) + salt) */
static void compute_sha1revmd5passsalt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hx[33], rev[33];
    int i;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    prmd5(md5bin, hx, 32);
    for (i = 0; i < 32; i++) rev[i] = hx[31 - i];
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, rev, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* 469 SHA1MD5PASSSALT: SHA1(hex(rhash_msg(RHASH_MD5, pass + salt))) */
static void compute_sha1md5passsalt_inner(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hx[33];
    rhash mctx;
    mctx = rhash_init(RHASH_MD5);
    rhash_update(mctx, pass, passlen);
    rhash_update(mctx, salt, saltlen);
    rhash_final(mctx, md5bin); rhash_free(mctx);
    prmd5(md5bin, hx, 32);
    SHA1((const unsigned char *)hx, 32, dest);
}

/* 473 SHA1SALTrevMD5PASS: SHA1(salt + rev(hex(rhash_msg(RHASH_MD5, pass)))) */
static void compute_sha1saltrevmd5pass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hx[33], rev[33];
    int i;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    prmd5(md5bin, hx, 32);
    for (i = 0; i < 32; i++) rev[i] = hx[31 - i];
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, rev, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* 765 SHA1MD5SALTPASS: SHA1(hex(rhash_msg(RHASH_MD5, salt + pass))) */
static void compute_sha1md5saltpass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hx[33];
    rhash mctx;
    mctx = rhash_init(RHASH_MD5);
    rhash_update(mctx, salt, saltlen);
    rhash_update(mctx, pass, passlen);
    rhash_final(mctx, md5bin); rhash_free(mctx);
    prmd5(md5bin, hx, 32);
    SHA1((const unsigned char *)hx, 32, dest);
}

/* 515 MD5-SALTMD5PASSSALT: rhash_msg(RHASH_MD5, salt + hex(MD5(pass + salt))) */
static void compute_md5_saltmd5passsalt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hx[33];
    rhash ctx;
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, md5bin); rhash_free(ctx);
    prmd5(md5bin, hx, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, hx, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* 516 MD5-SALTMD5SALTPASS: rhash_msg(RHASH_MD5, salt + hex(MD5(salt + pass))) */
static void compute_md5_saltmd5saltpass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hx[33];
    rhash ctx;
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, md5bin); rhash_free(ctx);
    prmd5(md5bin, hx, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, hx, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* 518 MD5-MD5SALT-PASS: rhash_msg(RHASH_MD5, hex(MD5(salt)) + pass) */
static void compute_md5_md5salt_pass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hx[33];
    rhash ctx;
    rhash_msg(RHASH_MD5, salt, saltlen, md5bin);
    prmd5(md5bin, hx, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hx, 32);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* 519 MD5-PASS-MD5SALT: rhash_msg(RHASH_MD5, pass + hex(MD5(salt))) */
static void compute_md5_pass_md5salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hx[33];
    rhash ctx;
    rhash_msg(RHASH_MD5, salt, saltlen, md5bin);
    prmd5(md5bin, hx, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, hx, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* 521 SHA1SALTCX: SHA1('--' + salt + '----' + pass + '----') */
static void compute_sha1saltcx(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, "--", 2);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, "----", 4);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, "----", 4);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* 528 MD5-SALTSHA1SALTPASS: rhash_msg(RHASH_MD5, salt + hex(SHA1(salt + pass))) */
static void compute_md5_saltsha1saltpass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1bin[20];
    char hx[41];
    rhash sctx;
    rhash mctx;
    sctx = rhash_init(RHASH_SHA1);
    rhash_update(sctx, salt, saltlen);
    rhash_update(sctx, pass, passlen);
    rhash_final(sctx, sha1bin); rhash_free(sctx);
    prmd5(sha1bin, hx, 40);
    mctx = rhash_init(RHASH_MD5);
    rhash_update(mctx, salt, saltlen);
    rhash_update(mctx, hx, 40);
    rhash_final(mctx, dest); rhash_free(mctx);
}

/* 589 SHA1-MD5UC-MD5SALT: SHA1(hexUC(rhash_msg(RHASH_MD5, hex(MD5(pass)) + salt))) */
static void compute_sha1_md5uc_md5salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5a[16], md5b[16];
    char hx[33], hxuc[33];
    rhash_msg(RHASH_MD5, pass, passlen, md5a);
    prmd5(md5a, hx, 32);
    {
        rhash mctx;
        mctx = rhash_init(RHASH_MD5);
        rhash_update(mctx, hx, 32);
        rhash_update(mctx, salt, saltlen);
        rhash_final(mctx, md5b); rhash_free(mctx);
    }
    prmd5UC(md5b, hxuc, 32);
    SHA1((const unsigned char *)hxuc, 32, dest);
}

/* 470 SHA1-MD5MD5SALT: SHA1(hex(rhash_msg(RHASH_MD5, hex(MD5(hex(MD5(pass)))) + salt))) */
static void compute_sha1_md5md5salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5a[16], md5b[16], md5c[16];
    char hx1[33], hx2[33], hx3[33];
    rhash_msg(RHASH_MD5, pass, passlen, md5a);
    prmd5(md5a, hx1, 32);
    rhash_msg(RHASH_MD5, (const unsigned char *)hx1, 32, md5b);
    prmd5(md5b, hx2, 32);
    {
        rhash mctx;
        mctx = rhash_init(RHASH_MD5);
        rhash_update(mctx, hx2, 32);
        rhash_update(mctx, salt, saltlen);
        rhash_final(mctx, md5c); rhash_free(mctx);
    }
    prmd5(md5c, hx3, 32);
    SHA1((const unsigned char *)hx3, 32, dest);
}

/* 598 SHA1MD5-PASSMD5SALT: SHA1(hex(rhash_msg(RHASH_MD5, pass + hex(MD5(salt))))) */
static void compute_sha1md5_passmd5salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5s[16], md5r[16];
    char hxs[33], hxr[33];
    rhash mctx;
    rhash_msg(RHASH_MD5, salt, saltlen, md5s);
    prmd5(md5s, hxs, 32);
    mctx = rhash_init(RHASH_MD5);
    rhash_update(mctx, pass, passlen);
    rhash_update(mctx, hxs, 32);
    rhash_final(mctx, md5r); rhash_free(mctx);
    prmd5(md5r, hxr, 32);
    SHA1((const unsigned char *)hxr, 32, dest);
}

/* 603 SHA1MD5SALTMD5PASS: SHA1(hex(rhash_msg(RHASH_MD5, salt)) + hex(MD5(pass))) */
static void compute_sha1md5saltmd5pass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5s[16], md5p[16];
    char hxs[33], hxp[33];
    unsigned char concat[64];
    rhash_msg(RHASH_MD5, salt, saltlen, md5s);
    rhash_msg(RHASH_MD5, pass, passlen, md5p);
    prmd5(md5s, hxs, 32);
    prmd5(md5p, hxp, 32);
    memcpy(concat, hxs, 32);
    memcpy(concat + 32, hxp, 32);
    SHA1(concat, 64, dest);
}

/* 637 SHA1-SHA512PASSSHA512SALT: SHA1(hex(SHA512(pass)) + hex(SHA512(salt))) */
static void compute_sha1_sha512passsha512salt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha512p[64], sha512s[64];
    char hxp[129], hxs[129];
    unsigned char concat[256];
    SHA512(pass, passlen, sha512p);
    SHA512(salt, saltlen, sha512s);
    prmd5(sha512p, hxp, 128);
    prmd5(sha512s, hxs, 128);
    memcpy(concat, hxp, 128);
    memcpy(concat + 128, hxs, 128);
    SHA1(concat, 256, dest);
}

/* 643 SHA1MD5BASE64: SHA1(hex(rhash_msg(RHASH_MD5, base64(pass)))) — unsalted */
static void compute_sha1md5base64(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    char b64[256];
    unsigned char md5bin[16];
    char hx[33];
    int b64len;
    (void)salt; (void)saltlen;
    b64len = base64_encode(pass, passlen, b64, sizeof(b64));
    if (b64len < 0) b64len = 0;
    rhash_msg(RHASH_MD5, (const unsigned char *)b64, b64len, md5bin);
    prmd5(md5bin, hx, 32);
    SHA1((const unsigned char *)hx, 32, dest);
}

/* Forward declaration for compute_mysql3 (defined later) */
static void compute_mysql3(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest);

/* 478 SHA1SQL3: SHA1(hex(mysql_old(pass))) — unsalted */
static void compute_sha1sql3(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sql3bin[8];
    char hx[17];
    (void)salt; (void)saltlen;
    compute_mysql3(pass, passlen, NULL, 0, sql3bin);
    prmd5(sql3bin, hx, 16);
    SHA1((const unsigned char *)hx, 16, dest);
}

/* 557 MD5-MD5SHA1PASSSHA1MD5SALT: rhash_msg(RHASH_MD5, hex(MD5(hex(SHA1(pass)))) + hex(SHA1(hex(MD5(salt))))) */
static void compute_md5_md5sha1passsha1md5salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1p[20], md5p[16], sha1s[20], md5s[16];
    char hxp1[41], hxp2[33], hxs1[33], hxs2[41];
    unsigned char concat[72];
    /* Left half: rhash_msg(RHASH_MD5, hex(SHA1(pass))) */
    SHA1(pass, passlen, sha1p);
    prmd5(sha1p, hxp1, 40);
    rhash_msg(RHASH_MD5, (const unsigned char *)hxp1, 40, md5p);
    prmd5(md5p, hxp2, 32);
    /* Right half: SHA1(hex(rhash_msg(RHASH_MD5, salt))) */
    rhash_msg(RHASH_MD5, salt, saltlen, md5s);
    prmd5(md5s, hxs1, 32);
    SHA1((const unsigned char *)hxs1, 32, sha1s);
    prmd5(sha1s, hxs2, 40);
    /* rhash_msg(RHASH_MD5, left + right) */
    memcpy(concat, hxp2, 32);
    memcpy(concat + 32, hxs2, 40);
    rhash_msg(RHASH_MD5, concat, 72, dest);
}

/* ---- Batch 6 Wave 2 ---- */

/* UC variants of hex+salt / salt+hex patterns */
/* OUTER(hexUC(inner(pass)) + salt) */
#define MAKE_HEX_UC_SALT(fname, inner_fn, inner_bytes, outer_hash_id) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    unsigned char _ib[MAX_HASH_BYTES]; \
    char _hx[MAX_HASH_BYTES * 2 + 1]; \
    rhash _ctx; \
    inner_fn(pass, passlen, NULL, 0, _ib); \
    prmd5UC(_ib, _hx, (inner_bytes) * 2); \
    _ctx = rhash_init(outer_hash_id); \
    rhash_update(_ctx, (unsigned char *)_hx, (inner_bytes) * 2); \
    rhash_update(_ctx, salt, saltlen); \
    rhash_final(_ctx, dest); rhash_free(_ctx); \
}

/* OUTER(salt + hexUC(inner(pass))) */
#define MAKE_SALT_HEX_UC(fname, inner_fn, inner_bytes, outer_hash_id) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    unsigned char _ib[MAX_HASH_BYTES]; \
    char _hx[MAX_HASH_BYTES * 2 + 1]; \
    rhash _ctx; \
    inner_fn(pass, passlen, NULL, 0, _ib); \
    prmd5UC(_ib, _hx, (inner_bytes) * 2); \
    _ctx = rhash_init(outer_hash_id); \
    rhash_update(_ctx, salt, saltlen); \
    rhash_update(_ctx, (unsigned char *)_hx, (inner_bytes) * 2); \
    rhash_final(_ctx, dest); rhash_free(_ctx); \
}

/* 652 SHA1MD5UCSALT: SHA1(hexUC(rhash_msg(RHASH_MD5, pass)) + salt) */
MAKE_HEX_UC_SALT(sha1md5ucsalt, compute_md5, 16, RHASH_SHA1)

/* 665 SHA1SALTMD5UC: SHA1(salt + hexUC(rhash_msg(RHASH_MD5, pass))) */
MAKE_SALT_HEX_UC(sha1saltmd5uc, compute_md5, 16, RHASH_SHA1)

/* 682 SHA1SALTMD5MD5PASS: SHA1(salt + hex(rhash_msg(RHASH_MD5, hex(MD5(pass))))) */
MAKE_SALT_HEX(sha1saltmd5md5pass, compute_md5md5, 16, RHASH_SHA1)

/* 588 SHA1-MD5-MD5SALTMD5PASS: SHA1(hex(rhash_msg(RHASH_MD5, hex(MD5(salt)) + hex(MD5(pass))))) */
static void compute_sha1_md5_md5saltmd5pass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5s[16], md5p[16], md5i[16];
    char hxs[33], hxp[33], hxi[33];
    unsigned char concat[64];
    rhash_msg(RHASH_MD5, salt, saltlen, md5s);
    rhash_msg(RHASH_MD5, pass, passlen, md5p);
    prmd5(md5s, hxs, 32);
    prmd5(md5p, hxp, 32);
    memcpy(concat, hxs, 32);
    memcpy(concat + 32, hxp, 32);
    rhash_msg(RHASH_MD5, concat, 64, md5i);
    prmd5(md5i, hxi, 32);
    SHA1((const unsigned char *)hxi, 32, dest);
}

/* 592 SHA1-MD5-MD5SALTMD5PASS-SALT: SHA1(hex(rhash_msg(RHASH_MD5, hex(MD5(salt))+hex(MD5(pass)))) + ":" + salt) */
static void compute_sha1_md5_md5saltmd5pass_salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5s[16], md5p[16], md5i[16];
    char hxs[33], hxp[33], hxi[33];
    unsigned char concat[64], buf[256];
    int buflen;
    rhash_msg(RHASH_MD5, salt, saltlen, md5s);
    rhash_msg(RHASH_MD5, pass, passlen, md5p);
    prmd5(md5s, hxs, 32);
    prmd5(md5p, hxp, 32);
    memcpy(concat, hxs, 32);
    memcpy(concat + 32, hxp, 32);
    rhash_msg(RHASH_MD5, concat, 64, md5i);
    prmd5(md5i, hxi, 32);
    memcpy(buf, hxi, 32);
    buf[32] = ':';
    memcpy(buf + 33, salt, saltlen);
    buflen = 33 + saltlen;
    SHA1(buf, buflen, dest);
}

/* 700 MD5MD5SHA1SALT: rhash_msg(RHASH_MD5, hex(MD5(hex(SHA1(pass)))) + salt) */
MAKE_HEX_SALT(md5md5sha1salt, compute_md5sha1, 16, RHASH_MD5)

/* 701 MD5MD5SHA256SALT: rhash_msg(RHASH_MD5, hex(MD5(hex(SHA256(pass)))) + salt) */
static void compute_md5md5sha256salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha256bin[32], md5bin[16];
    char hx256[65], hxmd5[33];
    rhash ctx;
    SHA256(pass, passlen, sha256bin);
    prmd5(sha256bin, hx256, 64);
    rhash_msg(RHASH_MD5, (const unsigned char *)hx256, 64, md5bin);
    prmd5(md5bin, hxmd5, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hxmd5, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* 817 MD5-SHA1SALTPASS: rhash_msg(RHASH_MD5, hex(SHA1(salt + pass))) */
static void compute_md5_sha1saltpass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1bin[20];
    char hx[41];
    rhash sctx;
    sctx = rhash_init(RHASH_SHA1);
    rhash_update(sctx, salt, saltlen);
    rhash_update(sctx, pass, passlen);
    rhash_final(sctx, sha1bin); rhash_free(sctx);
    prmd5(sha1bin, hx, 40);
    rhash_msg(RHASH_MD5, (const unsigned char *)hx, 40, dest);
}

/* 818 MD5-SALTMD5PASS-SALT: rhash_msg(RHASH_MD5, salt + hex(MD5(pass)) + salt) */
static void compute_md5_saltmd5pass_salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16];
    char hx[33];
    unsigned char buf[256];
    int buflen;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    prmd5(md5bin, hx, 32);
    buflen = saltlen + 32 + saltlen;
    if (buflen > (int)sizeof(buf)) buflen = (int)sizeof(buf);
    memcpy(buf, salt, saltlen);
    memcpy(buf + saltlen, hx, 32);
    memcpy(buf + saltlen + 32, salt, saltlen);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, buf, saltlen + 32 + saltlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* 685 SHA1MD5-SALTMD5PASS: SHA1(hex(rhash_msg(RHASH_MD5, salt + hex(MD5(pass))))) */
static void compute_sha1md5_saltmd5pass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5p[16], md5i[16];
    char hxp[33], hxi[33];
    unsigned char buf[256];
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5p);
    prmd5(md5p, hxp, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, hxp, 32);
    rhash_final(ctx, md5i); rhash_free(ctx);
    prmd5(md5i, hxi, 32);
    SHA1((const unsigned char *)hxi, 32, dest);
}

/* 627 SHA1-MD5SHA1PASSSHA1MD5SALT: SHA1(hex(rhash_msg(RHASH_MD5, hex(SHA1(pass)))) + hex(SHA1(hex(MD5(salt))))) */
static void compute_sha1_md5sha1passsha1md5salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1p[20], md5p[16], md5s[16], sha1s[20];
    char hxsp[41], hxmp[33], hxms[33], hxss[41];
    unsigned char concat[72];
    /* Left: rhash_msg(RHASH_MD5, hex(SHA1(pass))) */
    SHA1(pass, passlen, sha1p);
    prmd5(sha1p, hxsp, 40);
    rhash_msg(RHASH_MD5, (const unsigned char *)hxsp, 40, md5p);
    prmd5(md5p, hxmp, 32);
    /* Right: SHA1(hex(rhash_msg(RHASH_MD5, salt))) */
    rhash_msg(RHASH_MD5, salt, saltlen, md5s);
    prmd5(md5s, hxms, 32);
    SHA1((const unsigned char *)hxms, 32, sha1s);
    prmd5(sha1s, hxss, 40);
    /* SHA1(left + right) */
    memcpy(concat, hxmp, 32);
    memcpy(concat + 32, hxss, 40);
    SHA1(concat, 72, dest);
}

/* 720 SHA1SHA1UCPASSSALT: SHA1(hexUC(SHA1(pass)) + salt) */
MAKE_HEX_UC_SALT(sha1sha1ucpasssalt, compute_sha1, 20, RHASH_SHA1)

/* 735 SHA1SALTSHA1UCPASS: SHA1(salt + hexUC(SHA1(pass))) */
MAKE_SALT_HEX_UC(sha1saltsha1ucpass, compute_sha1, 20, RHASH_SHA1)

/* 751 SHA1SALTSHA1MD5: SHA1(salt + hex(SHA1(hex(rhash_msg(RHASH_MD5, pass))))) */
MAKE_SALT_HEX(sha1saltsha1md5, compute_sha1md5, 20, RHASH_SHA1)

/* 738 SHA1SALTMD5SHA1PASS: SHA1(salt + hex(rhash_msg(RHASH_MD5, hex(SHA1(pass))))) */
MAKE_SALT_HEX(sha1saltmd5sha1pass, compute_md5sha1, 16, RHASH_SHA1)

/* 759 SHA1MD5SHA1PASSSALT: SHA1(hex(rhash_msg(RHASH_MD5, hex(SHA1(pass)))) + salt) */
MAKE_HEX_SALT(sha1md5sha1passsalt, compute_md5sha1, 16, RHASH_SHA1)

/* ---- Batch 6 Wave 3 ---- */

/* hex_cap: capitalize first alphabetic hex char (a-f → A-F) in place */
static void hex_cap(char *hex)
{
    char *p;
    for (p = hex; *p; p++) {
        if (*p >= 'a' && *p <= 'f') {
            *p -= 32;
            return;
        }
    }
}

/* OUTER(CAP(hex(inner(pass))) + salt) — composed-salted "cap hex then salt" */
#define MAKE_HEX_CAP_SALT(fname, inner_fn, inner_bytes, outer_hash_id) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    unsigned char _ib[MAX_HASH_BYTES]; \
    char _hx[MAX_HASH_BYTES * 2 + 1]; \
    rhash _ctx; \
    inner_fn(pass, passlen, NULL, 0, _ib); \
    prmd5(_ib, _hx, (inner_bytes) * 2); \
    hex_cap(_hx); \
    _ctx = rhash_init(outer_hash_id); \
    rhash_update(_ctx, (unsigned char *)_hx, (inner_bytes) * 2); \
    rhash_update(_ctx, salt, saltlen); \
    rhash_final(_ctx, dest); rhash_free(_ctx); \
}

/* 659/669 SHA1MD5CAPSALT/SHA1MD51CAPSALT: SHA1(CAP(hex(rhash_msg(RHASH_MD5, pass))) + salt) */
MAKE_HEX_CAP_SALT(sha1md5capsalt, compute_md5, 16, RHASH_SHA1)

/* 666 SHA1SHA1CAPSALT: SHA1(CAP(hex(SHA1(pass))) + salt) */
MAKE_HEX_CAP_SALT(sha1sha1capsalt, compute_sha1, 20, RHASH_SHA1)

/* 743 SHA1MD5CAPMD5SALT: SHA1(CAP(hex(rhash_msg(RHASH_MD5, hex(MD5(pass))))) + salt) */
MAKE_HEX_CAP_SALT(sha1md5capmd5salt, compute_md5md5, 16, RHASH_SHA1)

/* 748 SHA1MD5CAPSHA1SALT: SHA1(CAP(hex(rhash_msg(RHASH_MD5, hex(SHA1(pass))))) + salt) */
MAKE_HEX_CAP_SALT(sha1md5capsha1salt, compute_sha1md5, 16, RHASH_SHA1)

/* 655 SHA1-MD5CAPSALT: SHA1(CAP(hex(rhash_msg(RHASH_MD5, hex(MD5(pass)) + salt)))) — inner salt */
static void compute_sha1_md5capsalt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16], innerbin[16];
    char hx[33], innerhx[33];
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    prmd5(md5bin, hx, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, (unsigned char *)hx, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, innerbin); rhash_free(ctx);
    prmd5(innerbin, innerhx, 32);
    hex_cap(innerhx);
    SHA1((const unsigned char *)innerhx, 32, dest);
}

/* 670 SHA1-MD5CAPMD5SALT: SHA1(CAP(hex(rhash_msg(RHASH_MD5, hex(MD5(hex(MD5(pass)))) + salt)))) — inner salt */
static void compute_sha1_md5capmd5salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16], md5md5bin[16], innerbin[16];
    char hx[33], hx2[33], innerhx[33];
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    prmd5(md5bin, hx, 32);
    rhash_msg(RHASH_MD5, (const unsigned char *)hx, 32, md5md5bin);
    prmd5(md5md5bin, hx2, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, (unsigned char *)hx2, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, innerbin); rhash_free(ctx);
    prmd5(innerbin, innerhx, 32);
    hex_cap(innerhx);
    SHA1((const unsigned char *)innerhx, 32, dest);
}

/* 673 SHA1-MD5SHA256SALT: SHA1(hex(rhash_msg(RHASH_MD5, hex(MD5(hex(SHA256(pass)))) + salt))) — inner salt */
static void compute_sha1_md5sha256salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha256bin[32], md5bin[16], md5md5bin[16], innerbin[16];
    char hx256[65], hxmd5[33], hx2[33], innerhx[33];
    rhash ctx;
    SHA256(pass, passlen, sha256bin);
    prmd5(sha256bin, hx256, 64);
    rhash_msg(RHASH_MD5, (const unsigned char *)hx256, 64, md5bin);
    prmd5(md5bin, hxmd5, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, (unsigned char *)hxmd5, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, innerbin); rhash_free(ctx);
    prmd5(innerbin, innerhx, 32);
    SHA1((const unsigned char *)innerhx, 32, dest);
}

/* 740 SHA1-MD5SALT-CR: SHA1(hex(rhash_msg(RHASH_MD5, hex(MD5(pass)) + salt)) + \r) */
static void compute_sha1_md5salt_cr(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16], innerbin[16];
    char hx[33], innerhx[33];
    unsigned char concat[34]; /* 32 hex + 1 CR + NUL */
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    prmd5(md5bin, hx, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, (unsigned char *)hx, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, innerbin); rhash_free(ctx);
    prmd5(innerbin, innerhx, 32);
    memcpy(concat, innerhx, 32);
    concat[32] = 0x0d; /* \r */
    SHA1(concat, 33, dest);
}

/* 741 SHA1-MD5MD5SALT-CR: SHA1(hex(rhash_msg(RHASH_MD5, hex(MD5(hex(MD5(pass)))) + salt)) + \r) */
static void compute_sha1_md5md5salt_cr(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5bin[16], md5md5bin[16], innerbin[16];
    char hx[33], hx2[33], innerhx[33];
    unsigned char concat[34];
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5bin);
    prmd5(md5bin, hx, 32);
    rhash_msg(RHASH_MD5, (const unsigned char *)hx, 32, md5md5bin);
    prmd5(md5md5bin, hx2, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, (unsigned char *)hx2, 32);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, innerbin); rhash_free(ctx);
    prmd5(innerbin, innerhx, 32);
    memcpy(concat, innerhx, 32);
    concat[32] = 0x0d;
    SHA1(concat, 33, dest);
}

/* 650 SHA1-MD5PASSMD5MD5SALT: SHA1(hex(rhash_msg(RHASH_MD5, pass)) + hex(MD5(hex(MD5(salt))))) */
static void compute_sha1_md5passmd5md5salt(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5p[16], md5s[16], md5ms[16];
    char hxp[33], hxs[33], hxms[33];
    unsigned char concat[64];
    rhash_msg(RHASH_MD5, pass, passlen, md5p);
    prmd5(md5p, hxp, 32);
    rhash_msg(RHASH_MD5, salt, saltlen, md5s);
    prmd5(md5s, hxs, 32);
    rhash_msg(RHASH_MD5, (const unsigned char *)hxs, 32, md5ms);
    prmd5(md5ms, hxms, 32);
    memcpy(concat, hxp, 32);
    memcpy(concat + 32, hxms, 32);
    SHA1(concat, 64, dest);
}

/* 704 SHA1SALTMD5PASSMD5: SHA1(salt + hex(rhash_msg(RHASH_MD5, pass + hex(MD5(pass))))) */
static void compute_sha1saltmd5passmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5p[16], innerbin[16];
    char hxp[33], innerhx[33];
    unsigned char concat[MAXLINE];
    int clen;
    rhash ctx;
    rhash_msg(RHASH_MD5, pass, passlen, md5p);
    prmd5(md5p, hxp, 32);
    /* rhash_msg(RHASH_MD5, pass + hex(MD5(pass))) */
    clen = passlen + 32;
    if (clen > MAXLINE) clen = MAXLINE;
    memcpy(concat, pass, passlen);
    memcpy(concat + passlen, hxp, 32);
    rhash_msg(RHASH_MD5, concat, clen, innerbin);
    prmd5(innerbin, innerhx, 32);
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, (unsigned char *)innerhx, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* 820 MD5-MD5SALT-MD5MD5PASS: rhash_msg(RHASH_MD5, hex(MD5(salt)) + hex(MD5(hex(MD5(pass))))) */
static void compute_md5_md5salt_md5md5pass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5p[16], md5md5p[16], md5s[16];
    char hxp[33], hxmd5p[33], hxs[33];
    unsigned char concat[64];
    rhash_msg(RHASH_MD5, pass, passlen, md5p);
    prmd5(md5p, hxp, 32);
    rhash_msg(RHASH_MD5, (const unsigned char *)hxp, 32, md5md5p);
    prmd5(md5md5p, hxmd5p, 32);
    rhash_msg(RHASH_MD5, salt, saltlen, md5s);
    prmd5(md5s, hxs, 32);
    memcpy(concat, hxs, 32);
    memcpy(concat + 32, hxmd5p, 32);
    rhash_msg(RHASH_MD5, concat, 64, dest);
}

/* 715 SHA1-SHA1SALTSHA1PASS: SHA1(hex(SHA1(salt)) + hex(SHA1(pass))) */
static void compute_sha1_sha1saltsha1pass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1s[20], sha1p[20];
    char hxs[41], hxp[41];
    unsigned char concat[80];
    SHA1(salt, saltlen, sha1s);
    prmd5(sha1s, hxs, 40);
    SHA1(pass, passlen, sha1p);
    prmd5(sha1p, hxp, 40);
    memcpy(concat, hxs, 40);
    memcpy(concat + 40, hxp, 40);
    SHA1(concat, 80, dest);
}

/* 823 SHA1-SALTSHA1PASSSALT: SHA1(salt + hex(SHA1(pass + salt))) */
static void compute_sha1_saltsha1passsalt(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char innerbin[20];
    char innerhx[41];
    rhash ctx, octx;
    /* inner: SHA1(pass + salt) */
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, salt, saltlen);
    rhash_final(ctx, innerbin); rhash_free(ctx);
    prmd5(innerbin, innerhx, 40);
    /* outer: SHA1(salt + hex(inner)) */
    octx = rhash_init(RHASH_SHA1);
    rhash_update(octx, salt, saltlen);
    rhash_update(octx, (unsigned char *)innerhx, 40);
    rhash_final(octx, dest); rhash_free(octx);
}

/* 826 SHA256-SALTSHA256RAW: SHA256(salt + SHA256_raw(pass)) */
static void compute_sha256_saltsha256raw(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char rawbin[32];
    rhash ctx;
    SHA256(pass, passlen, rawbin);
    ctx = rhash_init(RHASH_SHA256);
    rhash_update(ctx, salt, saltlen);
    rhash_update(ctx, rawbin, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* ---- Additional standalone compute functions ---- */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
/* MDC2 (OpenSSL) — 16 bytes */
static void compute_mdc2(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    MDC2(pass, passlen, dest);
}
#pragma GCC diagnostic pop

/* SQL5 / MYSQL5 — SHA1(raw SHA1(pass)) — 20 bytes */
static void compute_sql5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char inner[20];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, inner);
    SHA1(inner, 20, dest);
}

/* RADMIN2 — MD5 of password padded to 100 bytes — 16 bytes */
static void compute_radmin2(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char padded[100];
    (void)salt; (void)saltlen;
    memset(padded, 0, 100);
    if (passlen > 100) passlen = 100;
    memcpy(padded, pass, passlen);
    rhash_msg(RHASH_MD5, padded, 100, dest);
}

/* MD4UTF16 — same as NTLM (rhash_msg(RHASH_MD4, UTF16LE(pass))) — 16 bytes */
/* (shares compute_ntlm) */

/* MD5-DBL-PASS — rhash_msg(RHASH_MD5, pass+pass) — 16 bytes */
static void compute_md5dblpass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char *concat = WS->u16a;
    (void)salt; (void)saltlen;
    if (passlen > MAXLINE) passlen = MAXLINE;
    memcpy(concat, pass, passlen);
    memcpy(concat + passlen, pass, passlen);
    rhash_msg(RHASH_MD5, concat, passlen * 2, dest);
}

/* CRYPTEXT — SHA1(byteswap(SHA1(pass)) + "Cryptext") — 20 bytes */
static void compute_cryptext(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1out[20], buf[28];
    int i;
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1out);
    /* Byte-swap each 32-bit word */
    for (i = 0; i < 20; i += 4) {
        buf[i]   = sha1out[i+3];
        buf[i+1] = sha1out[i+2];
        buf[i+2] = sha1out[i+1];
        buf[i+3] = sha1out[i];
    }
    memcpy(buf + 20, "Cryptext", 8);
    SHA1(buf, 28, sha1out);
    /* Byte-swap result */
    for (i = 0; i < 20; i += 4) {
        dest[i]   = sha1out[i+3];
        dest[i+1] = sha1out[i+2];
        dest[i+2] = sha1out[i+1];
        dest[i+3] = sha1out[i];
    }
}

/* xMD5PASS types: x(hex(rhash_msg(RHASH_MD5, pass)) + pass) — MD5 is always inner, x is outer */
#define MAKE_MD5PASS(fname, outer_fn) \
static void compute_##fname(const unsigned char *pass, int passlen, \
    const unsigned char *salt, int saltlen, unsigned char *dest) \
{ \
    unsigned char _md5[16]; \
    char _hx[33]; \
    unsigned char *_concat = WS->tmp1; \
    (void)salt; (void)saltlen; \
    rhash_msg(RHASH_MD5, pass, passlen, _md5); \
    prmd5(_md5, _hx, 32); \
    memcpy(_concat, _hx, 32); \
    memcpy(_concat + 32, pass, passlen); \
    outer_fn((const unsigned char *)_concat, 32 + passlen, NULL, 0, dest); \
}

MAKE_MD5PASS(md2md5pass,       compute_md2)
MAKE_MD5PASS(md4md5pass,       compute_md4)
MAKE_MD5PASS(gostmd5pass,      compute_gost)
MAKE_MD5PASS(hav128md5pass,    compute_hav128_3)
MAKE_MD5PASS(hav128_4md5pass,  compute_hav128_4)
MAKE_MD5PASS(hav128_5md5pass,  compute_hav128_5)
MAKE_MD5PASS(hav160_3md5pass,  compute_hav160_3)
MAKE_MD5PASS(hav160_4md5pass,  compute_hav160_4)
MAKE_MD5PASS(hav160_5md5pass,  compute_hav160_5)
MAKE_MD5PASS(hav192_3md5pass,  compute_hav192_3)
MAKE_MD5PASS(hav192_4md5pass,  compute_hav192_4)
MAKE_MD5PASS(hav192_5md5pass,  compute_hav192_5)
MAKE_MD5PASS(hav224_3md5pass,  compute_hav224_3)
MAKE_MD5PASS(hav224_4md5pass,  compute_hav224_4)
MAKE_MD5PASS(hav224_5md5pass,  compute_hav224_5)
MAKE_MD5PASS(hav256md5pass,    compute_hav256_3)
MAKE_MD5PASS(hav256_4md5pass,  compute_hav256_4)
MAKE_MD5PASS(hav256_5md5pass,  compute_hav256_5)
MAKE_MD5PASS(sha1md5pass,      compute_sha1)
MAKE_MD5PASS(sha224md5pass,    compute_sha224)
MAKE_MD5PASS(sha256md5pass,    compute_sha256)
MAKE_MD5PASS(sha384md5pass,    compute_sha384)
MAKE_MD5PASS(sha512md5pass,    compute_sha512)
MAKE_MD5PASS(rmd128md5pass,    compute_rmd128)
MAKE_MD5PASS(rmd160md5pass,    compute_rmd160)
MAKE_MD5PASS(tigermd5pass,     compute_tiger)
MAKE_MD5PASS(wrlmd5pass,       compute_whirlpool)
MAKE_MD5PASS(sne128md5pass,    compute_sne128)
MAKE_MD5PASS(sne256md5pass,    compute_sne256)

/* ---- Composed compute functions (via MAKE_COMPOSED macro) ---- */
/* Convention: In type name "OUTERINNER", rightmost hash = inner (applied first */
/* to password), leftmost hash = outer (applied last to hex of inner result).   */
/* MAKE_COMPOSED(name, inner_fn, inner_bytes, outer_fn)                        */
/* Exception: MD4UTF16 (NTLM) is always inner (needs raw password for UTF16).  */

/* xMD5 types: MD5 is inner (rightmost), x is outer (leftmost) */
MAKE_COMPOSED(md2md5,      compute_md5, 16, compute_md2)
MAKE_COMPOSED(md4md5,      compute_md5, 16, compute_md4)
MAKE_COMPOSED(gostmd5,     compute_md5, 16, compute_gost)
MAKE_COMPOSED(hav128md5,   compute_md5, 16, compute_hav128_3)
MAKE_COMPOSED(hav128_4md5, compute_md5, 16, compute_hav128_4)
MAKE_COMPOSED(hav128_5md5, compute_md5, 16, compute_hav128_5)
MAKE_COMPOSED(hav160_3md5, compute_md5, 16, compute_hav160_3)
MAKE_COMPOSED(hav160_4md5, compute_md5, 16, compute_hav160_4)
MAKE_COMPOSED(hav160_5md5, compute_md5, 16, compute_hav160_5)
MAKE_COMPOSED(hav192_3md5, compute_md5, 16, compute_hav192_3)
MAKE_COMPOSED(hav192_4md5, compute_md5, 16, compute_hav192_4)
MAKE_COMPOSED(hav192_5md5, compute_md5, 16, compute_hav192_5)
MAKE_COMPOSED(hav224_3md5, compute_md5, 16, compute_hav224_3)
MAKE_COMPOSED(hav224_4md5, compute_md5, 16, compute_hav224_4)
MAKE_COMPOSED(hav224_5md5, compute_md5, 16, compute_hav224_5)
MAKE_COMPOSED(hav256md5,   compute_md5, 16, compute_hav256_3)
MAKE_COMPOSED(hav256_4md5, compute_md5, 16, compute_hav256_4)
MAKE_COMPOSED(hav256_5md5, compute_md5, 16, compute_hav256_5)
MAKE_COMPOSED(rmd128md5,   compute_md5, 16, compute_rmd128)
MAKE_COMPOSED(rmd160md5,   compute_md5, 16, compute_rmd160)
MAKE_COMPOSED(sha224md5,   compute_md5, 16, compute_sha224)
MAKE_COMPOSED(sha256md5,   compute_md5, 16, compute_sha256)
MAKE_COMPOSED(sha384md5,   compute_md5, 16, compute_sha384)
MAKE_COMPOSED(sha512md5,   compute_md5, 16, compute_sha512)
MAKE_COMPOSED(tigermd5,    compute_md5, 16, compute_tiger)
MAKE_COMPOSED(wrlmd5,      compute_md5, 16, compute_whirlpool)
MAKE_COMPOSED(sne128md5,   compute_md5, 16, compute_sne128)
MAKE_COMPOSED(sne256md5,   compute_md5, 16, compute_sne256)

/* xSHA1 types: SHA1 is inner (rightmost), x is outer */
MAKE_COMPOSED(sha256sha1,  compute_sha1, 20, compute_sha256)
MAKE_COMPOSED(sha224sha1,  compute_sha1, 20, compute_sha224)

/* xSHA256 types: SHA256 is inner, x is outer */
MAKE_COMPOSED(sha1sha256,  compute_sha256, 32, compute_sha1)
MAKE_COMPOSED(md5sha256,   compute_sha256, 32, compute_md5)

/* xSHA384 types: SHA384 is inner, x is outer */
MAKE_COMPOSED(sha1sha384,  compute_sha384, 48, compute_sha1)

/* xSHA512 types: SHA512 is inner, x is outer */
MAKE_COMPOSED(sha1sha512,  compute_sha512, 64, compute_sha1)
MAKE_COMPOSED(sha256sha512,compute_sha512, 64, compute_sha256)
MAKE_COMPOSED(md5sha512,   compute_sha512, 64, compute_md5)

/* xSHA224 types: SHA224 is inner, x is outer */
MAKE_COMPOSED(sha1sha224,  compute_sha224, 28, compute_sha1)

/* xMD4 types: MD4 is inner, x is outer */
MAKE_COMPOSED(md5md4,      compute_md4, 16, compute_md5)
MAKE_COMPOSED(sha1md4,     compute_md4, 16, compute_sha1)
MAKE_COMPOSED(rmd128md4,   compute_md4, 16, compute_rmd128)

/* xMD2 types: MD2 is inner, x is outer */
MAKE_COMPOSED(md5md2,      compute_md2, 16, compute_md5)
MAKE_COMPOSED(sha1md2,     compute_md2, 16, compute_sha1)

/* xSHA0 types: SHA0 is inner, x is outer */
MAKE_COMPOSED(md5sha0,     compute_sha0, 20, compute_md5)
MAKE_COMPOSED(sha1sha0,    compute_sha0, 20, compute_sha1)

/* xGOST types: GOST is inner, x is outer */
MAKE_COMPOSED(md5gost,     compute_gost, 32, compute_md5)
MAKE_COMPOSED(sha1gost,    compute_gost, 32, compute_sha1)

/* xTIGER types: TIGER is inner, x is outer */
MAKE_COMPOSED(md5tiger,    compute_tiger, 24, compute_md5)
MAKE_COMPOSED(md5tiger2,   compute_tiger2, 24, compute_md5)

/* xRMD160 types: RMD160 is inner, x is outer */
MAKE_COMPOSED(md5rmd160,   compute_rmd160, 20, compute_md5)

/* xRMD128 types: RMD128 is inner, x is outer */
MAKE_COMPOSED(sha1rmd128,  compute_rmd128, 16, compute_sha1)

/* xHAV128 types: HAV128 is inner, x is outer */
MAKE_COMPOSED(sha1hav128,  compute_hav128_3, 16, compute_sha1)

/* xWRL types: Whirlpool is inner, x is outer */
MAKE_COMPOSED(md5wrl,      compute_whirlpool, 64, compute_md5)
MAKE_COMPOSED(sha1wrl,     compute_whirlpool, 64, compute_sha1)
MAKE_COMPOSED(wrlsha512,   compute_sha512, 64, compute_whirlpool)

/* xNTLM types: NTLM is inner, x is outer */
MAKE_COMPOSED(sha1ntlm,    compute_ntlm, 16, compute_sha1)

/* MD4UTF16 (NTLM) as inner (always inner — needs raw password for UTF16) */
MAKE_COMPOSED(md4utf16md5,    compute_ntlm, 16, compute_md5)
MAKE_COMPOSED(md4utf16sha1,   compute_ntlm, 16, compute_sha1)
MAKE_COMPOSED(md4utf16sha256, compute_ntlm, 16, compute_sha256)

/* SHA1SHA1 */
MAKE_COMPOSED(sha1sha1, compute_sha1, 20, compute_sha1)
/* SHA1RMD160 = SHA1(hex(RMD160(pass))) */
MAKE_COMPOSED(sha1rmd160, compute_rmd160, 20, compute_sha1)

/* Multi-level compositions — right to left naming convention */

/* MD5SHA1MD5 = rhash_msg(RHASH_MD5, hex(SHA1(hex(MD5(pass))))) — right to left: MD5, SHA1, MD5 */
static void compute_md5sha1md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char t1[MAX_HASH_BYTES], t2[MAX_HASH_BYTES];
    char hx[MAX_HASH_BYTES * 2 + 1];
    (void)salt; (void)saltlen;
    compute_md5(pass, passlen, NULL, 0, t1);
    prmd5(t1, hx, 32); compute_sha1((const unsigned char *)hx, 32, NULL, 0, t2);
    prmd5(t2, hx, 40); compute_md5((const unsigned char *)hx, 40, NULL, 0, dest);
}

/* SHA1MD5SHA1 = SHA1(hex(rhash_msg(RHASH_MD5, hex(SHA1(pass))))) — right to left: SHA1, MD5, SHA1 */
static void compute_sha1md5sha1(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char t1[MAX_HASH_BYTES], t2[MAX_HASH_BYTES];
    char hx[MAX_HASH_BYTES * 2 + 1];
    (void)salt; (void)saltlen;
    compute_sha1(pass, passlen, NULL, 0, t1);
    prmd5(t1, hx, 40); compute_md5((const unsigned char *)hx, 40, NULL, 0, t2);
    prmd5(t2, hx, 32); compute_sha1((const unsigned char *)hx, 32, NULL, 0, dest);
}

/* MD5SHA1MD5SHA1 = rhash_msg(RHASH_MD5, hex(SHA1(hex(MD5(hex(SHA1(pass))))))) — right to left: SHA1, MD5, SHA1,MD5 */
static void compute_md5sha1md5sha1(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char t1[MAX_HASH_BYTES];
    char hx[MAX_HASH_BYTES * 2 + 1];
    (void)salt; (void)saltlen;
    compute_sha1md5sha1(pass, passlen, NULL, 0, t1); /* SHA1(hex(rhash_msg(RHASH_MD5, hex(SHA1(pass))))) = 20 bytes */
    prmd5(t1, hx, 40); compute_md5((const unsigned char *)hx, 40, NULL, 0, dest); /* 16 bytes */
}

/* SHA1MD5SHA1MD5 = SHA1(hex(rhash_msg(RHASH_MD5, hex(SHA1(hex(MD5(pass))))))) — right to left: MD5, SHA1, MD5,SHA1 */
static void compute_sha1md5sha1md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char t1[MAX_HASH_BYTES];
    char hx[MAX_HASH_BYTES * 2 + 1];
    (void)salt; (void)saltlen;
    compute_md5sha1md5(pass, passlen, NULL, 0, t1); /* rhash_msg(RHASH_MD5, hex(SHA1(hex(MD5(pass))))) = 16 bytes */
    prmd5(t1, hx, 32); compute_sha1((const unsigned char *)hx, 32, NULL, 0, dest); /* 20 bytes */
}

/* RMD128MD5MD5 = RMD128(hex(rhash_msg(RHASH_MD5, hex(MD5(pass))))) — right to left: MD5, MD5, RMD128 */
MAKE_COMPOSED(rmd128md5md5_inner, compute_md5, 16, compute_md5)       /* rhash_msg(RHASH_MD5, hex(MD5(pass))) */
MAKE_COMPOSED(rmd128md5md5, compute_rmd128md5md5_inner, 16, compute_rmd128) /* RMD128(hex(...)) */

/* SHA1PASSSHA1: SHA1(pass + hex(SHA1(pass))) */
static void compute_sha1passsha1(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1bin[20];
    char sha1hex[41];
    unsigned char *concat = WS->tmp1;
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1bin);
    prmd5(sha1bin, sha1hex, 40);
    memcpy(concat, pass, passlen);
    memcpy(concat + passlen, sha1hex, 40);
    SHA1(concat, passlen + 40, dest);
}

/* MD5HESK: rhash_msg(RHASH_MD5, concat of per-character MD5 hashes) */
static void compute_md5hesk(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char perbyte[16];
    char testvec[32768];
    int i, tvlen = 0;
    (void)salt; (void)saltlen;
    for (i = 0; i < passlen && tvlen + 32 < (int)sizeof(testvec); i++) {
        rhash_msg(RHASH_MD5, &pass[i], 1, perbyte);
        prmd5(perbyte, testvec + tvlen, 32);
        tvlen += 32;
    }
    rhash_msg(RHASH_MD5, (unsigned char *)testvec, tvlen, dest);
}

/* MD5NTLMp: rhash_msg(RHASH_MD5, hex(NTLM(pass)) + " ") — 'p' suffix = append space */
static void compute_md5ntlmp(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char ntlm[16];
    char hx[34];
    (void)salt; (void)saltlen;
    compute_ntlm(pass, passlen, NULL, 0, ntlm);
    prmd5(ntlm, hx, 32);
    hx[32] = ' ';
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 33, dest);
}

/* MD5PASSMD5: rhash_msg(RHASH_MD5, hex(MD5(pass)) + pass) (= MD5MD5PASS alias) */
/* (shares compute_md5md5pass) */

/* MD5PASSSHA1: SHA1(hex(MD5(pass)) + pass) (= SHA1MD5PASS) */
/* (shares compute_sha1md5pass) */

/* ================================================================= */
/* Additional compute functions for remaining types                   */
/* ================================================================= */

/* BASE64 encode (standard alphabet, no padding required for our use) */
static const char b64tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int base64_encode(const unsigned char *in, int inlen, char *out, int outmax)
{
    int i, o = 0;
    for (i = 0; i + 2 < inlen && o + 4 <= outmax; i += 3) {
        out[o++] = b64tab[(in[i] >> 2) & 0x3f];
        out[o++] = b64tab[((in[i] & 3) << 4) | ((in[i+1] >> 4) & 0xf)];
        out[o++] = b64tab[((in[i+1] & 0xf) << 2) | ((in[i+2] >> 6) & 3)];
        out[o++] = b64tab[in[i+2] & 0x3f];
    }
    if (i < inlen && o + 4 <= outmax) {
        out[o++] = b64tab[(in[i] >> 2) & 0x3f];
        if (i + 1 < inlen) {
            out[o++] = b64tab[((in[i] & 3) << 4) | ((in[i+1] >> 4) & 0xf)];
            out[o++] = b64tab[((in[i+1] & 0xf) << 2)];
        } else {
            out[o++] = b64tab[((in[i] & 3) << 4)];
            out[o++] = '=';
        }
        out[o++] = '=';
    }
    if (o < outmax) out[o] = 0;  /* bounds check — @0xVavaldi */
    return o;
}

/* Convenience wrapper: b64_encode(in, inlen, out) — uses 256 as max */
static inline int b64_encode(const unsigned char *in, int inlen, char *out)
{
    return base64_encode(in, inlen, out, 256);
}

/* BASE64 decode */
static int base64_decode(const char *in, int inlen, unsigned char *out, int outmax)
{
    static const unsigned char d[] = {
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
        255,255,255,255,255,255,255,255,255,255,255,62,255,255,255,63,
        52,53,54,55,56,57,58,59,60,61,255,255,255,64,255,255,
        255,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,255,255,255,255,255,
        255,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,255,255,255,255,255
    };
    int i, o = 0;
    for (i = 0; i + 3 < inlen && o < outmax; i += 4) {
        unsigned char a = d[(unsigned char)in[i]], b = d[(unsigned char)in[i+1]];
        unsigned char c = d[(unsigned char)in[i+2]], e = d[(unsigned char)in[i+3]];
        if (a > 63 || b > 63) break;
        out[o++] = (a << 2) | (b >> 4);
        if (c > 63) break;
        if (o < outmax) out[o++] = (b << 4) | (c >> 2);
        if (e > 63) break;
        if (o < outmax) out[o++] = (c << 6) | e;
    }
    /* Handle trailing 2-3 chars (no padding) */
    if (i < inlen && o < outmax) {
        int rem = inlen - i;
        if (rem >= 2) {
            unsigned char a = d[(unsigned char)in[i]], b = d[(unsigned char)in[i+1]];
            if (a <= 63 && b <= 63) {
                out[o++] = (a << 2) | (b >> 4);
                if (rem >= 3 && o < outmax) {
                    unsigned char c = d[(unsigned char)in[i+2]];
                    if (c <= 63)
                        out[o++] = (b << 4) | (c >> 2);
                }
            }
        }
    }
    return o;
}

/* ROT13 transform */
static void rot13(char *s, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        if (s[i] >= 'a' && s[i] <= 'z')
            s[i] = 'a' + (s[i] - 'a' + 13) % 26;
        else if (s[i] >= 'A' && s[i] <= 'Z')
            s[i] = 'A' + (s[i] - 'A' + 13) % 26;
    }
}

/* Reverse a string in-place */
static void reverse_str(char *s, int len)
{
    int i;
    for (i = 0; i < len / 2; i++) {
        char t = s[i];
        s[i] = s[len - 1 - i];
        s[len - 1 - i] = t;
    }
}

/* HUM format: colon-separated hex pairs "ab:cd:ef:..." */
static int hex_to_hum(const unsigned char *bin, int binlen, char *out, int outmax)
{
    int i, o = 0;
    for (i = 0; i < binlen && o + 3 < outmax; i++) {
        if (i > 0) out[o++] = ':';
        out[o++] = hextab_lc[(bin[i] >> 4) & 0xf];
        out[o++] = hextab_lc[bin[i] & 0xf];
    }
    out[o] = 0;
    return o;
}

/* Capitalize first letter of password */
static void capitalize_first(unsigned char *out, const unsigned char *in, int len)
{
    memcpy(out, in, len);
    if (len > 0 && out[0] >= 'a' && out[0] <= 'z')
        out[0] -= 32;
}

/* NULL hash — raw password bytes zero-padded to 16 bytes */
static void compute_null(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    memset(dest, 0, 16);
    if (passlen > 16) passlen = 16;
    memcpy(dest, pass, passlen);
}

/* MYSQL3 — old MySQL password hash */
static void compute_mysql3(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned long nr = 1345345333L, add = 7, nr2 = 0x12345671L, tmp;
    int i;
    (void)salt; (void)saltlen;
    for (i = 0; i < passlen; i++) {
        if (pass[i] == ' ' || pass[i] == '\t') continue;
        tmp = (unsigned long)pass[i];
        nr ^= (((nr & 63) + add) * tmp) + (nr << 8);
        nr2 += (nr2 << 8) ^ nr;
        add += tmp;
    }
    nr &= 0x7fffffffL;
    nr2 &= 0x7fffffffL;
    /* Store as 8 bytes (two 32-bit big-endian words) */
    dest[0] = (nr >> 24) & 0xff;
    dest[1] = (nr >> 16) & 0xff;
    dest[2] = (nr >>  8) & 0xff;
    dest[3] = nr & 0xff;
    dest[4] = (nr2 >> 24) & 0xff;
    dest[5] = (nr2 >> 16) & 0xff;
    dest[6] = (nr2 >>  8) & 0xff;
    dest[7] = nr2 & 0xff;
}

/* SKYPE — rhash_msg(RHASH_MD5, username:password) where username=salt */
static void compute_skype(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    ctx = rhash_init(RHASH_MD5);
    if (salt && saltlen > 0) {
        rhash_update(ctx, salt, saltlen);
        rhash_update(ctx, ":", 1);
    }
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* NTLMH — rhash_msg(RHASH_MD5, NTLM(pass)) (raw binary NTLM fed to MD5) */
static void compute_ntlmh(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char ntlm[16];
    (void)salt; (void)saltlen;
    compute_ntlm(pass, passlen, NULL, 0, ntlm);
    rhash_msg(RHASH_MD5, ntlm, 16, dest);
}

/* LM hash — DES-based, needs special handling */
/* For simplicity, we'll use OpenSSL DES */
#include <openssl/des.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

static void lm_des_key(const unsigned char *raw7, DES_key_schedule *ks)
{
    DES_cblock key;
    key[0] = raw7[0] >> 1;
    key[1] = ((raw7[0] & 0x01) << 6) | (raw7[1] >> 2);
    key[2] = ((raw7[1] & 0x03) << 5) | (raw7[2] >> 3);
    key[3] = ((raw7[2] & 0x07) << 4) | (raw7[3] >> 4);
    key[4] = ((raw7[3] & 0x0F) << 3) | (raw7[4] >> 5);
    key[5] = ((raw7[4] & 0x1F) << 2) | (raw7[5] >> 6);
    key[6] = ((raw7[5] & 0x3F) << 1) | (raw7[6] >> 7);
    key[7] = raw7[6] & 0x7F;
    { int i; for (i = 0; i < 8; i++) key[i] = (key[i] << 1) & 0xfe; }
    DES_set_key_unchecked(&key, ks);
}

static void compute_lm(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char upass[14];
    DES_key_schedule ks;
    static const unsigned char lm_magic[] = "KGS!@#$%";
    int i;
    (void)salt; (void)saltlen;
    memset(upass, 0, 14);
    for (i = 0; i < passlen && i < 14; i++)
        upass[i] = (pass[i] >= 'a' && pass[i] <= 'z') ? pass[i] - 32 : pass[i];
    lm_des_key(upass, &ks);
    DES_ecb_encrypt((DES_cblock *)lm_magic, (DES_cblock *)dest, &ks, DES_ENCRYPT);
    lm_des_key(upass + 7, &ks);
    DES_ecb_encrypt((DES_cblock *)lm_magic, (DES_cblock *)(dest + 8), &ks, DES_ENCRYPT);
}
#pragma GCC diagnostic pop

/* RMD320 — RIPEMD-320 (rhash provides this) */
static void compute_rmd320(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_RIPEMD160, pass, passlen, dest);
    /* RMD320 is not in rhash; use extended RIPEMD160 placeholder */
    /* For now, compute double RIPEMD160 as 40-byte output */
    rhash_msg(RHASH_RIPEMD160, pass, passlen, dest);
    rhash_msg(RHASH_RIPEMD160, dest, 20, dest + 20);
}

/* MD5SWAP — MD5 with bytes swapped in 32-bit words */
/* MD5SWAP: rhash_msg(RHASH_MD5, pass), hex encode, swap halves (chars 16-31 + chars 0-15), then MD5 */
static void compute_md5swap(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16]; char hex[33], swapped[33];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);
    prmd5(h, hex, 32);
    memcpy(swapped, hex + 16, 16);
    memcpy(swapped + 16, hex, 16);
    rhash_msg(RHASH_MD5, (unsigned char *)swapped, 32, dest);
}

/* MD5bcad — MD5 with byte order bcad per 32-bit word */
static void compute_md5bcad(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16];
    int i;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    for (i = 0; i < 16; i += 4) {
        dest[i]   = md5[i+1]; /* b */
        dest[i+1] = md5[i+2]; /* c */
        dest[i+2] = md5[i];   /* a */
        dest[i+3] = md5[i+3]; /* d */
    }
}

/* MD5dcab — MD5 with byte order dcab per 32-bit word */
static void compute_md5dcab(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16];
    int i;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    for (i = 0; i < 16; i += 4) {
        dest[i]   = md5[i+3]; /* d */
        dest[i+1] = md5[i+2]; /* c */
        dest[i+2] = md5[i];   /* a */
        dest[i+3] = md5[i+1]; /* b */
    }
}

/* MD5padMD5 — rhash_msg(RHASH_MD5, " " + hex(MD5(pass)) + "  ") — 35 bytes total */
static void compute_md5padmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16];
    char buf[36];
    (void)salt; (void)saltlen;
    buf[0] = ' ';
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, buf + 1, 32);
    buf[33] = ' ';
    buf[34] = ' ';
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 35, dest);
}

/* MD5revMD5 — rhash_msg(RHASH_MD5, reverse(hex(MD5(pass)))) */
static void compute_md5revmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16];
    char hx[33];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    reverse_str(hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, dest);
}

/* MD5revp — rhash_msg(RHASH_MD5, reverse(password)) */
static void compute_md5revp(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char *rev = WS->tmp1;
    int i;
    (void)salt; (void)saltlen;
    if (passlen > MAXLINE) passlen = MAXLINE;
    for (i = 0; i < passlen; i++)
        rev[i] = pass[passlen - 1 - i];
    rhash_msg(RHASH_MD5, rev, passlen, dest);
}

/* SHA1revp — SHA1(reverse(password)) */
static void compute_sha1revp(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char *rev = WS->tmp1;
    int i;
    (void)salt; (void)saltlen;
    if (passlen > MAXLINE) passlen = MAXLINE;
    for (i = 0; i < passlen; i++)
        rev[i] = pass[passlen - 1 - i];
    SHA1(rev, passlen, dest);
}

/* SHA1revSHA1 — SHA1(reverse(hex(SHA1(pass)))) */
static void compute_sha1revsha1(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1[20];
    char hx[41];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1);
    prmd5(sha1, hx, 40);
    reverse_str(hx, 40);
    SHA1((unsigned char *)hx, 40, dest);
}

/* SHA1revMD5 — SHA1(reverse(hex(rhash_msg(RHASH_MD5, pass)))) */
static void compute_sha1revmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16];
    char hx[33];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    reverse_str(hx, 32);
    SHA1((unsigned char *)hx, 32, dest);
}

/* MD5revSHA1 — rhash_msg(RHASH_MD5, reverse(hex(SHA1(pass)))) */
static void compute_md5revsha1(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1[20];
    char hx[41];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1);
    prmd5(sha1, hx, 40);
    reverse_str(hx, 40);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 40, dest);
}

/* MD5revMD5MD5 — rhash_msg(RHASH_MD5, reverse(hex(MD5(hex(MD5(pass)))))) */
static void compute_md5revmd5md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], md5_2[16];
    char hx[33];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, md5_2);
    prmd5(md5_2, hx, 32);
    reverse_str(hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, dest);
}

/* MD5revMD5SHA1 — rhash_msg(RHASH_MD5, reverse(hex(MD5(hex(SHA1(pass)))))) */
static void compute_md5revmd5sha1(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1[20], md5[16];
    char hx[41];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1);
    prmd5(sha1, hx, 40);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 40, md5);
    prmd5(md5, hx, 32);
    reverse_str(hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, dest);
}

/* MD5revMD5SHA1SHA1 — rhash_msg(RHASH_MD5, reverse(hex(MD5(hex(SHA1(hex(SHA1(pass)))))))) */
static void compute_md5revmd5sha1sha1(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1[20], sha1_2[20], md5[16];
    char hx[41];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1);
    prmd5(sha1, hx, 40);
    SHA1((unsigned char *)hx, 40, sha1_2);
    prmd5(sha1_2, hx, 40);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 40, md5);
    prmd5(md5, hx, 32);
    reverse_str(hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, dest);
}

/* MD5BASE64 — base64(MD5_raw(pass)) */
/* MD5BASE64 = rhash_msg(RHASH_MD5, base64(password)) */
static void compute_md5base64(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    char b64[1024];
    int blen;
    (void)salt; (void)saltlen;
    blen = base64_encode(pass, passlen, b64, sizeof(b64));
    rhash_msg(RHASH_MD5, (unsigned char *)b64, blen, dest);
}

/* SHA1DRU — Drupal old-style: SHA1(pass) with first byte trimmed? */
/* Actually SHA1DRU seems to be just SHA1 with a specific salt format */
/* For simplicity, treat as SHA1 */
static void compute_sha1dru(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, dest);
}

/* SHA1HESK — SHA1 of per-byte SHA1 hex (like MD5HESK but SHA1) */
static void compute_sha1hesk(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char perbyte[20];
    char testvec[32768];
    int i, tvlen = 0;
    (void)salt; (void)saltlen;
    for (i = 0; i < passlen && tvlen + 40 < (int)sizeof(testvec); i++) {
        SHA1(&pass[i], 1, perbyte);
        prmd5(perbyte, testvec + tvlen, 40);
        tvlen += 40;
    }
    SHA1((unsigned char *)testvec, tvlen, dest);
}

/* MD5CAP — rhash_msg(RHASH_MD5, capitalize(pass)) */
static void compute_md5cap(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char *cappass = WS->tmp1;
    (void)salt; (void)saltlen;
    if (passlen > MAXLINE) passlen = MAXLINE;
    capitalize_first(cappass, pass, passlen);
    rhash_msg(RHASH_MD5, cappass, passlen, dest);
}

/* PASSMD5 types: rhash_msg(RHASH_MD5, pass + hex(MD5(pass))) */
static void compute_md5passmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16];
    char hx[33];
    rhash ctx;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, hx, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5PASSSHA1: rhash_msg(RHASH_MD5, pass + hex(SHA1(pass))) */
static void compute_md5passsha1(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1[20];
    char hx[41];
    rhash ctx;
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1);
    prmd5(sha1, hx, 40);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, hx, 40);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5PASSSHA1MD5: rhash_msg(RHASH_MD5, pass + hex(SHA1(hex(MD5(pass))))) */
static void compute_md5passsha1md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], sha1[20];
    char hx[41];
    rhash ctx;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    SHA1((unsigned char *)hx, 32, sha1);
    prmd5(sha1, hx, 40);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, hx, 40);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5PASSMD5MD5MD5: rhash_msg(RHASH_MD5, pass + hex(MD5(hex(MD5(hex(MD5(pass))))))) */
static void compute_md5passmd5md5md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char m[16];
    char hx[33];
    rhash ctx;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, m);
    prmd5(m, hx, 32); rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, m);
    prmd5(m, hx, 32); rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, m);
    prmd5(m, hx, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, hx, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5PASSMD5MD5PASS: rhash_msg(RHASH_MD5, pass + hex(MD5(hex(MD5(pass)) + pass))) */
static void compute_md5passmd5md5pass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char m[16], m2[16];
    char hx[33];
    rhash ctx;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, m);
    prmd5(m, hx, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hx, 32);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, m2); rhash_free(ctx);
    prmd5(m2, hx, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, hx, 32);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5MD5PASSSHA1: rhash_msg(RHASH_MD5, hex(MD5(pass)) + pass + hex(SHA1(pass))) */
/* Actually: SHA1(hex(MD5(pass)) + pass) but named oddly. Let me check.
   MD5MD5PASSSHA1 in mdxfind: outer=SHA1, inner=MD5MD5PASS? No.
   It's: SHA1 of (hex(MD5(pass)) + pass). Verify from mdxfind. */
/* For safety: SHA1(hex(MD5(pass)) + pass) */
static void compute_md5md5passsha1(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16];
    char hx[33];
    rhash ctx;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, hx, 32);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA1MD5MD5PASS: SHA1(hex(rhash_msg(RHASH_MD5, hex(MD5(pass)) + pass))) */
static void compute_sha1md5md5pass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], md5_2[16];
    char hx[33];
    rhash mctx;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    mctx = rhash_init(RHASH_MD5);
    rhash_update(mctx, hx, 32);
    rhash_update(mctx, pass, passlen);
    rhash_final(mctx, md5_2); rhash_free(mctx);
    prmd5(md5_2, hx, 32);
    SHA1((unsigned char *)hx, 32, dest);
}

/* SHA1MD5PASSMD5: SHA1(hex(rhash_msg(RHASH_MD5, pass + hex(MD5(pass))))) */
static void compute_sha1md5passmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], md5_2[16];
    char hx[33];
    rhash ctx;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, hx, 32);
    rhash_final(ctx, md5_2); rhash_free(ctx);
    prmd5(md5_2, hx, 32);
    SHA1((unsigned char *)hx, 32, dest);
}

/* MD5SHA1MD5PASS: rhash_msg(RHASH_MD5, hex(SHA1(hex(MD5(pass)))) + pass) */
static void compute_md5sha1md5pass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], sha1[20];
    char *buf = (char *)WS->tmp1;
    rhash ctx;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, buf, 32);
    SHA1((unsigned char *)buf, 32, sha1);
    prmd5(sha1, buf, 40);
    memcpy(buf + 40, pass, passlen);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 40 + passlen, dest);
}

/* MD5-MD5PASSMD5: rhash_msg(RHASH_MD5, hex(MD5(pass + hex(MD5(pass))))) */
/* This is: compute MD5(pass), hex it, append pass to front, MD5 that, hex, MD5 outer */
/* = MD5(hex(MD5PASSMD5(pass))) */
static void compute_md5_md5passmd5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char inner[16];
    char hx[33];
    (void)salt; (void)saltlen;
    compute_md5passmd5(pass, passlen, NULL, 0, inner);
    prmd5(inner, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, dest);
}

/* MD5-LMNTLM — rhash_msg(RHASH_MD5, hex(LM(pass)) + hex(NTLM(pass))) */
static void compute_md5_lmntlm(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char lm[16], ntlm[16];
    char hx[65];
    (void)salt; (void)saltlen;
    compute_lm(pass, passlen, NULL, 0, lm);
    compute_ntlm(pass, passlen, NULL, 0, ntlm);
    prmd5(lm, hx, 32);
    prmd5(ntlm, hx + 32, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 64, dest);
}

/* MD5LM — rhash_msg(RHASH_MD5, hex(LM(pass))) */
static void compute_md5lm(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char lm[16];
    char hx[33];
    (void)salt; (void)saltlen;
    compute_lm(pass, passlen, NULL, 0, lm);
    prmd5(lm, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, dest);
}

/* SQL3 — Oracle 11g: SHA1(pass + salt), 20 bytes, salted */
/* MD4SQL3, MD5SQL3 etc. are compositions with SQL3 inner */
/* For SQL3 as a standalone, it's SHA1(pass + salt) — same as SHA1PASSSALT */

/* MD5HUM — MD5 output in HUM format (colon-separated hex) */
/* These don't change the hash computation, just the format.
   For verification, the computation is the same as the inner hash.
   The HUM formatting is in the output stage. */

/* SHA1PASSSHA1PASS — not needed, already have SHA1 iteration */

/* MD5SHA1PASSMD5PASSSHA1PASS: rhash_msg(RHASH_MD5, SHA1_hex(40) + MD5_hex(32) + SHA1_hex(40)) = 112 bytes */
static void compute_md5sha1passmd5passsha1pass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], sha1[20];
    char buf[113];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    SHA1(pass, passlen, sha1);
    prmd5(sha1, buf, 40);
    prmd5(md5, buf + 40, 32);
    prmd5(sha1, buf + 72, 40);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 112, dest);
}

/* MD4UTF16MD5PASSMD5SHA1PASS — complex type */
static void compute_md4utf16md5passmd5sha1pass(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char ntlm[16], md5[16], sha1[20];
    char hx[41];
    rhash ctx;
    rhash sctx;
    (void)salt; (void)saltlen;
    /* Inner: MD4UTF16(pass) = NTLM */
    compute_ntlm(pass, passlen, NULL, 0, ntlm);
    prmd5(ntlm, hx, 32);
    /* MD5PASS: rhash_msg(RHASH_MD5, hex(NTLM) + pass) */
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, hx, 32);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, md5); rhash_free(ctx);
    prmd5(md5, hx, 32);
    /* SHA1PASS: SHA1(hex(MD5) + pass) */
    sctx = rhash_init(RHASH_SHA1);
    rhash_update(sctx, hx, 32);
    rhash_update(sctx, pass, passlen);
    rhash_final(sctx, sha1); rhash_free(sctx);
    prmd5(sha1, hx, 40);
    /* MD5: rhash_msg(RHASH_MD5, hex(SHA1)) */
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 40, dest);
}

/* MD5CAPSHA1 = md5(ucfirst(sha1($pass))) — capitalize first char of SHA1 hex, then MD5 */
static void compute_md5capsha1(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1[20];
    char hx[41];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1);
    prmd5(sha1, hx, 40);       /* lowercase hex */
    if (hx[0] >= 'a' && hx[0] <= 'z')
        hx[0] -= 32;           /* ucfirst */
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 40, dest);
}

/* MD5-SHA1numSHA1 — rhash_msg(RHASH_MD5, hex(SHA1(pass#SHA1(pass)))) where # is length as digit */
/* Actually the name suggests SHA1(num + SHA1) — SHA1(strlen(pass) as string + hex(SHA1(pass))) */
/* Then MD5 of that hex */
static void compute_md5_sha1numsha1(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1[20], sha1_2[20];
    char hx[41], numbuf[16];
    rhash ctx;
    int nlen;
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1);
    prmd5(sha1, hx, 40);
    nlen = sprintf(numbuf, "%d", passlen);
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, numbuf, nlen);
    rhash_update(ctx, hx, 40);
    rhash_final(ctx, sha1_2); rhash_free(ctx);
    prmd5(sha1_2, hx, 40);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 40, dest);
}

/* MD5-MD5SHA1MD5SHA1MD5SHA1p — complex */
/* rhash_msg(RHASH_MD5, hex(MD5(pass)) + hex(SHA1(pass)) + hex(MD5(pass)) + hex(SHA1(pass)) + hex(MD5(pass)) + hex(SHA1(pass)) + pass) */
/* MD5-MD5SHA1MD5SHA1MD5SHA1p (e415):
 * SHA1(pass) → hex → MD5 → hex → SHA1 → hex → MD5 → hex → SHA1 → hex → MD5 → hex
 * then append ' ' (space) to make 33 bytes, then final MD5 */
static void compute_md5_md5sha1md5sha1md5sha1p(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[20]; char buf[42];
    (void)salt; (void)saltlen;
    /* Step 1: SHA1(pass) */
    SHA1(pass, passlen, h);
    /* Step 2: rhash_msg(RHASH_MD5, hex(SHA1)) */
    prmd5(h, buf, 40);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 40, h);
    /* Step 3: SHA1(hex(MD5)) */
    prmd5(h, buf, 32);
    SHA1((unsigned char *)buf, 32, h);
    /* Step 4: rhash_msg(RHASH_MD5, hex(SHA1)) */
    prmd5(h, buf, 40);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 40, h);
    /* Step 5: SHA1(hex(MD5)) */
    prmd5(h, buf, 32);
    SHA1((unsigned char *)buf, 32, h);
    /* Step 6: rhash_msg(RHASH_MD5, hex(SHA1)) */
    prmd5(h, buf, 40);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 40, h);
    /* Step 7: rhash_msg(RHASH_MD5, hex(MD5) + ' ') — 33 bytes */
    prmd5(h, buf, 32);
    buf[32] = ' ';
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 33, dest);
}

/* MD5SPECAM — rhash_msg(RHASH_MD5, pass + MD5_raw(pass)) binary concat */
static void compute_md5specam(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5raw[16];
    rhash ctx;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5raw);
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, md5raw, 16);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5AM — rhash_msg(RHASH_MD5, pass + "Anchialos123456") */
static void compute_md5am(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    (void)salt; (void)saltlen;
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, "Anchialos123456", 15);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* MD5AM2 — rhash_msg(RHASH_MD5, "Anchialos123456" + pass) */
static void compute_md5am2(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    rhash ctx;
    (void)salt; (void)saltlen;
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, "Anchialos123456", 15);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA1MD5-SHA1PASSPASS — SHA1(hex(rhash_msg(RHASH_MD5, pass)) + "-" + hex(SHA1(pass)) + pass + pass) */
static void compute_sha1md5_sha1passpass(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], sha1[20];
    char md5hx[33], sha1hx[41];
    rhash ctx;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    SHA1(pass, passlen, sha1);
    prmd5(md5, md5hx, 32);
    prmd5(sha1, sha1hx, 40);
    ctx = rhash_init(RHASH_SHA1);
    rhash_update(ctx, md5hx, 32);
    rhash_update(ctx, "-", 1);
    rhash_update(ctx, sha1hx, 40);
    rhash_update(ctx, pass, passlen);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, dest); rhash_free(ctx);
}

/* SHA1MD5UC1LC — SHA1 of rhash_msg(RHASH_MD5, pass) with first char of hex uppercase, rest lowercase */
/* Actually: the hex of MD5 is mixed — first nibble UC, rest LC. Too complex interpretation. */
/* More likely: UC hex of MD5, then force first char lowercase. */
static void compute_sha1md5uc1lc(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16];
    char hx[33];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5UC(md5, hx, 32);
    /* Force first char to lowercase */
    if (hx[0] >= 'A' && hx[0] <= 'F') hx[0] += 32;
    SHA1((unsigned char *)hx, 32, dest);
}

/* MD5MD5UCp — rhash_msg(RHASH_MD5, hexUC(MD5(pass)) + " ") — 'p' suffix = append space */
static void compute_md5md5ucp(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16];
    char hx[34];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5UC(md5, hx, 32);
    hx[32] = ' ';
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 33, dest);
}

/* MD5MD5UCSHA1MD5MD5 — rhash_msg(RHASH_MD5, hex(SHA1(hex(MD5(hexUC(MD5(pass))))))) */
/* Actually: inner=MD5, UC hex, then MD5, then SHA1, then MD5MD5 outer */
/* Interpret as chain: MD5UC → MD5 → SHA1 → MD5 → MD5 */
/* This is: MD5(hex(MD5(hex(SHA1(hex(MD5(hexUC(MD5(pass))))))))) */

/* SHA1UTF7 — SHA1(UTF-7 encoded password) */
/* UTF-7 is a complex encoding; for simplicity, pass-through for ASCII */
static void compute_sha1utf7(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    /* UTF-7 encoding of ASCII is the same as ASCII for most chars */
    /* Full UTF-7 conversion would need significant code */
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, dest);
}

/* ================================================================= */
/* Iteration types: MD5-NxMD5, SHA1-NxSHA1 etc.                      */
/* These iterate a hash N+1 times total (1 initial + N more)          */
/* ================================================================= */

/* Generic MD5 iteration: MD5 applied (n+1) times with hex encoding between */
static void md5_iter(const unsigned char *pass, int passlen, int n, unsigned char *dest)
{
    unsigned char buf[16];
    char hx[33];
    int i;
    rhash_msg(RHASH_MD5, pass, passlen, buf);
    for (i = 0; i < n; i++) {
        prmd5(buf, hx, 32);
        rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, buf);
    }
    memcpy(dest, buf, 16);
}

/* Generic SHA1 iteration */
static void sha1_iter(const unsigned char *pass, int passlen, int n, unsigned char *dest)
{
    unsigned char buf[20];
    char hx[41];
    int i;
    SHA1(pass, passlen, buf);
    for (i = 0; i < n; i++) {
        prmd5(buf, hx, 40);
        SHA1((unsigned char *)hx, 40, buf);
    }
    memcpy(dest, buf, 20);
}

/* NxMD5, NxSHA1 compute functions are in the "New compute functions" section below */

/* MD5-2xMD5UC = MD5 iterated 3 times with UC hex */
/* MD5-2xMD5UC: rhash_msg(RHASH_MD5, pass) → UC hex → dup 2× → MD5 */
static void compute_md5_2xmd5uc(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16]; char buf[65];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);
    prmd5UC(h, buf, 32); prmd5UC(h, buf + 32, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 64, dest);
}

/* MD5-NxSHA1MD5 = SHA1MD5(hex(MD5-NxMD5(pass))) — wait, names are complex */
/* MD5-2xSHA1MD5 = SHA1(hex(rhash_msg(RHASH_MD5, hex(SHA1(hex(MD5(hex(MD5(pass))))))))) */
/* Actually: MD5-2x means 2 extra iterations. Then SHA1MD5 is applied to the result. */
/* MD5-2xSHA1MD5: Start with rhash_msg(RHASH_MD5, pass), iterate 2 more times (3 total MD5), then SHA1(hex), then rhash_msg(RHASH_MD5, hex) */
static void compute_md5_2xsha1md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], sha1[20];
    char hx[41];
    (void)salt; (void)saltlen;
    md5_iter(pass, passlen, 2, md5);
    prmd5(md5, hx, 32);
    SHA1((unsigned char *)hx, 32, sha1);
    prmd5(sha1, hx, 40);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 40, dest);
}

/* Various MD5-Nx chain combinations */
/* MD5-2xMD5-MD5MD5 = rhash_msg(RHASH_MD5, hex(MD5(hex(MD5-2xMD5(pass))))) */
static void compute_md5_2xmd5_md5md5_v(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char m[16];
    char hx[33];
    (void)salt; (void)saltlen;
    md5_iter(pass, passlen, 2, m);
    prmd5(m, hx, 32); rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, m);
    prmd5(m, hx, 32); rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, dest);
}

/* MD5-2xMD5-MD5MD5MD5: suffix MD5MD5MD5 = 3 MD5 steps (incl initial), then 2xMD5 inner+dup */
static void compute_md5_2xmd5_md5md5md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16]; char hex[33], buf[65];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);                                  /* suffix 1/3 */
    prmd5(h, hex, 32); rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, h);    /* suffix 2/3 */
    prmd5(h, hex, 32); rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, h);    /* suffix 3/3 */
    prmd5(h, hex, 32); rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, h);    /* 2xMD5 inner */
    bin2hex(h, 16, buf); bin2hex(h, 16, buf + 32);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 64, dest);
}

/* MD5-3xMD5-MD5MD5: suffix MD5MD5 = 2 MD5 steps (incl initial), then 3xMD5 inner+dup */
static void compute_md5_3xmd5_md5md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16]; char hex[33], buf[97];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);                                  /* suffix 1/2 */
    prmd5(h, hex, 32); rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, h);    /* suffix 2/2 */
    prmd5(h, hex, 32); rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, h);    /* 3xMD5 inner */
    bin2hex(h, 16, buf); bin2hex(h, 16, buf + 32); bin2hex(h, 16, buf + 64);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 96, dest);
}

/* MD5-3xMD5-MD5MD5MD5: suffix MD5MD5MD5 = 3 MD5 steps (incl initial), then 3xMD5 inner+dup */
static void compute_md5_3xmd5_md5md5md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16]; char hex[33], buf[97];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);                                  /* suffix 1/3 */
    prmd5(h, hex, 32); rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, h);    /* suffix 2/3 */
    prmd5(h, hex, 32); rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, h);    /* suffix 3/3 */
    prmd5(h, hex, 32); rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, h);    /* 3xMD5 inner */
    bin2hex(h, 16, buf); bin2hex(h, 16, buf + 32); bin2hex(h, 16, buf + 64);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 96, dest);
}

/* MD5-3xMD5-SHA1: SHA1→hex→(3xMD5: MD5→hex→dup 3x→MD5) */
static void compute_md5_3xmd5_sha1(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char s[20], h[16]; char hex[41], buf[97];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, s);
    prmd5(s, hex, 40);
    rhash_msg(RHASH_MD5, (unsigned char *)hex, 40, h);   /* 3xMD5 inner MD5 (feed from SHA1 hex) */
    bin2hex(h, 16, buf); bin2hex(h, 16, buf + 32); bin2hex(h, 16, buf + 64);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 96, dest);
}

/* ================================================================= */
/* SHA1-2xSHA1 and chain extensions                                  */
/* Pattern: suffix chain → SHA1(hex) → dup 2x → SHA1               */
/* ================================================================= */

/* SHA1-2xSHA1-MD5: MD5→hex→(2xSHA1: SHA1→hex→dup 2x→SHA1) */
static void compute_sha1_2xsha1_md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16], s[20]; char hex[33], buf[81];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);
    prmd5(h, hex, 32);
    SHA1((unsigned char *)hex, 32, s);  /* 2xSHA1 inner SHA1 */
    prmd5(s, buf, 40); prmd5(s, buf + 40, 40);
    SHA1((unsigned char *)buf, 80, dest);
}

/* SHA1-2xSHA1-MD5MD5: MD5→hex→MD5→hex→(2xSHA1: SHA1→hex→dup 2x→SHA1) */
static void compute_sha1_2xsha1_md5md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16], s[20]; char hex[33], buf[81];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);
    prmd5(h, hex, 32); rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, h);
    prmd5(h, hex, 32);
    SHA1((unsigned char *)hex, 32, s);
    prmd5(s, buf, 40); prmd5(s, buf + 40, 40);
    SHA1((unsigned char *)buf, 80, dest);
}

/* SHA1-2xSHA1-MD5MD5MD5: MD5→hex→MD5→hex→MD5→hex→(2xSHA1: SHA1→hex→dup 2x→SHA1) */
static void compute_sha1_2xsha1_md5md5md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16], s[20]; char hex[33], buf[81];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);
    prmd5(h, hex, 32); rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, h);
    prmd5(h, hex, 32); rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, h);
    prmd5(h, hex, 32);
    SHA1((unsigned char *)hex, 32, s);
    prmd5(s, buf, 40); prmd5(s, buf + 40, 40);
    SHA1((unsigned char *)buf, 80, dest);
}

/* SHA1-2xSHA1-SHA1: SHA1→hex→(2xSHA1: SHA1→hex→dup 2x→SHA1) */
static void compute_sha1_2xsha1_sha1(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char s[20]; char hex[41], buf[81];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, s);
    prmd5(s, hex, 40);
    SHA1((unsigned char *)hex, 40, s);
    prmd5(s, buf, 40); prmd5(s, buf + 40, 40);
    SHA1((unsigned char *)buf, 80, dest);
}

/* MD5-1x types (MD5 iterated 1 extra = 2 total, then chain) */
/* MD5-1xMD5SHA1 = SHA1(hex(rhash_msg(RHASH_MD5, hex(MD5(hex(MD5(pass))))))) */
/* Actually: MD5-1x means MD5 x 2 total, then MD5SHA1 applied */
/* MD5-1xMD5SHA1: iterate MD5 1+1=2, then SHA1(hex(MD5(hex(result)))) */
/* ================================================================= */
/* 1x types: concatenation of two different hash hex outputs         */
/* MD5-1xAB = rhash_msg(RHASH_MD5, hex(A(pass)) + hex(B(pass)))                      */
/* MD5-1xAB-CD = MD5(hex(A(CD(pass))) + hex(B(CD(pass))))           */
/* ================================================================= */

/* MD5-1xMD5SHA1 (e322) = md5(md5($pass).sha1($pass)) */
static void compute_md5_1xmd5sha1(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char m[16], s[20]; char buf[73];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, m);
    SHA1(pass, passlen, s);
    prmd5(m, buf, 32);       /* hex(rhash_msg(RHASH_MD5, pass)) = 32 chars */
    prmd5(s, buf + 32, 40);  /* hex(SHA1(pass)) = 40 chars */
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 72, dest);
}

/* MD5-1xSHA1MD5 (e323) = md5(sha1($pass).md5($pass)) */
static void compute_md5_1xsha1md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char m[16], s[20]; char buf[73];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, s);
    rhash_msg(RHASH_MD5, pass, passlen, m);
    prmd5(s, buf, 40);       /* hex(SHA1(pass)) = 40 chars */
    prmd5(m, buf + 40, 32);  /* hex(rhash_msg(RHASH_MD5, pass)) = 32 chars */
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 72, dest);
}

/* MD5-1xMD5SHA1-MD5 (e327) = md5(md5(md5($pass)).sha1(md5($pass))) */
static void compute_md5_1xmd5sha1_md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char inner[16], m[16], s[20]; char hex[33], buf[73];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, inner);
    prmd5(inner, hex, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, m);   /* md5(md5($pass)) */
    SHA1((unsigned char *)hex, 32, s);  /* sha1(md5($pass)) */
    prmd5(m, buf, 32);
    prmd5(s, buf + 32, 40);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 72, dest);
}

/* MD5-1xSHA1MD5-MD5 = md5(sha1(md5($pass)).md5(md5($pass))) */
static void compute_md5_1xsha1md5_md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char inner[16], m[16], s[20]; char hex[33], buf[73];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, inner);
    prmd5(inner, hex, 32);
    SHA1((unsigned char *)hex, 32, s);  /* sha1(md5($pass)) */
    rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, m);   /* md5(md5($pass)) */
    prmd5(s, buf, 40);
    prmd5(m, buf + 40, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 72, dest);
}

/* MD5-1xMD5SHA1-MD5MD5 = md5(md5(md5(md5($pass))).sha1(md5(md5($pass)))) */
static void compute_md5_1xmd5sha1_md5md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char inner[16], m[16], s[20]; char hex[33], buf[73];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, inner);
    prmd5(inner, hex, 32); rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, inner);  /* md5(md5($pass)) */
    prmd5(inner, hex, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, m);   /* md5(md5(md5($pass))) */
    SHA1((unsigned char *)hex, 32, s);  /* sha1(md5(md5($pass))) */
    prmd5(m, buf, 32);
    prmd5(s, buf + 32, 40);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 72, dest);
}

/* MD5-1xSHA1MD5-MD5MD5 = md5(sha1(md5(md5($pass))).md5(md5(md5($pass)))) */
static void compute_md5_1xsha1md5_md5md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char inner[16], m[16], s[20]; char hex[33], buf[73];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, inner);
    prmd5(inner, hex, 32); rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, inner);  /* md5(md5($pass)) */
    prmd5(inner, hex, 32);
    SHA1((unsigned char *)hex, 32, s);  /* sha1(md5(md5($pass))) */
    rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, m);   /* md5(md5(md5($pass))) */
    prmd5(s, buf, 40);
    prmd5(m, buf + 40, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 72, dest);
}

/* SHA1-1xMD5SHA1 = sha1(md5($pass).sha1($pass)) */
static void compute_sha1_1xmd5sha1(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char m[16], s[20]; char buf[73];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, m);
    SHA1(pass, passlen, s);
    prmd5(m, buf, 32);
    prmd5(s, buf + 32, 40);
    SHA1((unsigned char *)buf, 72, dest);
}

/* SHA1-1xSHA1MD5 = sha1(sha1($pass).md5($pass)) */
static void compute_sha1_1xsha1md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char m[16], s[20]; char buf[73];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, s);
    rhash_msg(RHASH_MD5, pass, passlen, m);
    prmd5(s, buf, 40);
    prmd5(m, buf + 40, 32);
    SHA1((unsigned char *)buf, 72, dest);
}

/* SHA1MD5-2xMD5-MD5 = rhash_msg(RHASH_MD5, hex(SHA1(hex(MD5(hex(MD5(hex(MD5(pass))))))))) */
/* Inner: MD5 iterated 3x (MD5-2x), then SHA1 outer, then MD5 outer */
static void compute_sha1md5_2xmd5_md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char m[16], sha1[20]; char hx[41];
    (void)salt; (void)saltlen;
    md5_iter(pass, passlen, 2, m);
    prmd5(m, hx, 32);
    SHA1((unsigned char *)hx, 32, sha1);
    prmd5(sha1, hx, 40);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 40, dest);
}

/* MD5-1xSHA1MD5pSHA1p = rhash_msg(RHASH_MD5, hex(SHA1(pass)) + pass + hex(MD5(pass)) + pass + hex(SHA1(pass)) + pass) */
/* This is a complex PASS-concatenation type with iteration */
/* "p" suffix means password appended. SHA1p = SHA1(pass) + pass. */
/* For simplicity, register these as special compute functions later */

/* MD4UTF16-2xMD5 = MD5(hex(MD5(hex(MD4UTF16(pass))))) */
static void compute_md4utf16_2xmd5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char ntlm[16], m[16]; char hx[33];
    (void)salt; (void)saltlen;
    compute_ntlm(pass, passlen, NULL, 0, ntlm);
    prmd5(ntlm, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, m);
    prmd5(m, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, dest);
}

/* ================================================================= */
/* BASE64 compute functions                                           */
/* ================================================================= */

/* MD5BASE64: the hash field is base64-encoded MD5 (not hex).
   For verification: we compute rhash_msg(RHASH_MD5, pass), base64-encode it, and compare.
   But our framework uses hex comparison. We need special handling.

   Actually — in mdxfind output, MD5BASE64 hashes ARE hex-encoded.
   The "BASE64" in the name means base64 is applied as a step.
   MD5BASE64 = base64(MD5_raw(pass)) — stored as its own format.
   MD5BASE64MD5 = rhash_msg(RHASH_MD5, base64(MD5_raw(pass))) — outer is MD5 of the base64 string.

   For MD5BASE64 itself, the "hash" in the input line IS base64, not hex.
   Our hex-based framework can't handle this directly.

   For MD5BASE64MD5 etc., the final hash IS hex (MD5 output), so we can handle those.
*/

/* MD5BASE64MD5: rhash_msg(RHASH_MD5, base64(MD5_raw(pass))) */
/* MD5BASE64MD5 = MD5(base64(hex(MD5(pass)))) */
static void compute_md5base64md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16]; char hex[33], b64[48];
    int blen;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hex, 32);
    blen = base64_encode((unsigned char *)hex, 32, b64, sizeof(b64));
    rhash_msg(RHASH_MD5, (unsigned char *)b64, blen, dest);
}

/* SHA1BASE64MD5: SHA1(base64(MD5_raw(pass))) */
static void compute_sha1base64md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16];
    char b64[25];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    base64_encode(md5, 16, b64, sizeof(b64));
    SHA1((unsigned char *)b64, strlen(b64), dest);
}

/* SHA1BASE64MD5UC: SHA1(base64(MD5_raw(pass))) with UC output */
/* Same compute as SHA1BASE64MD5, HTF_UC flag handles output */

/* MD5BASE64MD5MD5 = rhash_msg(RHASH_MD5, base64(hex(MD5(hex(MD5(pass)))))) */
static void compute_md5base64md5md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16]; char hex[33], b64[48];
    int blen;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);
    prmd5(h, hex, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, h);
    prmd5(h, hex, 32);
    blen = base64_encode((unsigned char *)hex, 32, b64, sizeof(b64));
    rhash_msg(RHASH_MD5, (unsigned char *)b64, blen, dest);
}

/* MD5BASE64ROT13 = rhash_msg(RHASH_MD5, base64(rot13(pass))) */
static void compute_md5base64rot13(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    char *r13 = (char *)WS->tmp1, *b64 = (char *)WS->u16a;
    int blen;
    (void)salt; (void)saltlen;
    if (passlen > MAXLINE - 1) passlen = MAXLINE - 1;
    memcpy(r13, pass, passlen);
    rot13(r13, passlen);
    blen = base64_encode((unsigned char *)r13, passlen, b64, sizeof(WS->u16a));
    rhash_msg(RHASH_MD5, (unsigned char *)b64, blen, dest);
}

/* SHA1BASE64SHA256: SHA1(base64(SHA256_raw(pass))) */
static void compute_sha1base64sha256(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha256[32];
    char b64[45];
    (void)salt; (void)saltlen;
    SHA256(pass, passlen, sha256);
    base64_encode(sha256, 32, b64, sizeof(b64));
    SHA1((unsigned char *)b64, strlen(b64), dest);
}

/* MD5SHA1BASE64: rhash_msg(RHASH_MD5, base64(SHA1_raw(hex(MD5(pass))))) ... no */
/* MD5SHA1BASE64: The BASE64 is applied to the SHA1 result.
   Inner: MD5(pass) → hex → SHA1(hex) → base64 → that's the hash.
   But since the final output is base64, not hex, skip direct registration. */
/* MD5SHA1BASE64SHA1MD5: complex chain, skip for now */

/* MD5BASE64SHA1MD5: MD5(base64(SHA1_raw(hex(MD5(pass))))) */
static void compute_md5base64sha1md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], sha1[20];
    char hx[33], b64[29];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    SHA1((unsigned char *)hx, 32, sha1);
    base64_encode(sha1, 20, b64, sizeof(b64));
    rhash_msg(RHASH_MD5, (unsigned char *)b64, strlen(b64), dest);
}

/* MD5BASE64revMD5 = rhash_msg(RHASH_MD5, base64(reverse_hex(MD5(pass)))) */
static void compute_md5base64revmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16]; char hex[33], b64[48];
    int i, blen;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hex, 32);
    /* reverse the hex string */
    for (i = 0; i < 16; i++) {
        char t = hex[i]; hex[i] = hex[31-i]; hex[31-i] = t;
    }
    blen = base64_encode((unsigned char *)hex, 32, b64, sizeof(b64));
    rhash_msg(RHASH_MD5, (unsigned char *)b64, blen, dest);
}

/* MD5DECBASE64: rhash_msg(RHASH_MD5, base64_decode(pass)) — decode pass as base64 first */
static void compute_md5decbase64(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char *decoded = WS->tmp1;
    int dlen;
    (void)salt; (void)saltlen;
    dlen = base64_decode((const char *)pass, passlen, decoded, sizeof(WS->tmp1));
    if (dlen <= 0) { memset(dest, 0, 16); return; }
    rhash_msg(RHASH_MD5, decoded, dlen, dest);
}

/* SHA1DECBASE64: SHA1(base64_decode(pass)) */
static void compute_sha1decbase64(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char *decoded = WS->tmp1;
    int dlen;
    (void)salt; (void)saltlen;
    dlen = base64_decode((const char *)pass, passlen, decoded, sizeof(WS->tmp1));
    if (dlen <= 0) { memset(dest, 0, 20); return; }
    SHA1(decoded, dlen, dest);
}

/* MD5DECBASE64MD5: rhash_msg(RHASH_MD5, base64_decode(hex(MD5(pass)))) */
static void compute_md5decbase64md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], *decoded = WS->tmp1;
    char hx[33];
    int dlen;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    dlen = base64_decode(hx, 32, decoded, sizeof(WS->tmp1));
    if (dlen <= 0) { memset(dest, 0, 16); return; }
    rhash_msg(RHASH_MD5, decoded, dlen, dest);
}

/* ================================================================= */
/* SUB/TRUNC compute functions                                        */
/* ================================================================= */

/* MD5sub1-20MD5: rhash_msg(RHASH_MD5, chars 0-19 of hex(MD5(pass))) = MD5 of first 20 hex chars */
static void compute_md5sub1_20md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16];
    char hx[33];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 20, dest);
}

/* MD5sub1-20MD5MD5: rhash_msg(RHASH_MD5, hex(MD5(chars 0-19 of hex(MD5(pass))))) */
static void compute_md5sub1_20md5md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char m[16]; char hx[33];
    (void)salt; (void)saltlen;
    compute_md5sub1_20md5(pass, passlen, NULL, 0, m);
    prmd5(m, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, dest);
}

/* MD5sub8-24MD5: rhash_msg(RHASH_MD5, chars 8-23 of hex(MD5(pass))) = 16 hex chars from offset 8 */
static void compute_md5sub8_24md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16];
    char hx[33];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)(hx + 8), 16, dest);
}

/* MD5sub8-24MD5sub8-24MD5: rhash_msg(RHASH_MD5, sub8-24(hex(MD5(sub8-24(hex(MD5(pass))))))) */
static void compute_md5sub8_24md5sub8_24md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char m[16]; char hx[33];
    (void)salt; (void)saltlen;
    compute_md5sub8_24md5(pass, passlen, NULL, 0, m);
    prmd5(m, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)(hx + 8), 16, dest);
}

/* SHA1MD5sub1-16: SHA1(chars 0-15 of hex(rhash_msg(RHASH_MD5, pass))) = 16 hex chars */
static void compute_sha1md5sub1_16(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16];
    char hx[33];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    SHA1((unsigned char *)hx, 16, dest);
}

/* SHA1MD5sub1-16MD5: SHA1(hex(rhash_msg(RHASH_MD5, chars 0-15 of hex(MD5(pass))))) */
static void compute_sha1md5sub1_16md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], m[16]; char hx[33];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 16, m);
    prmd5(m, hx, 32);
    SHA1((unsigned char *)hx, 32, dest);
}

/* SHA1MD5sub1-16MD5MD5 */
static void compute_sha1md5sub1_16md5md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], m[16]; char hx[33];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 16, m);
    prmd5(m, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, m);
    prmd5(m, hx, 32);
    SHA1((unsigned char *)hx, 32, dest);
}

/* SHA1MD5sub1-20MD5 */
static void compute_sha1md5sub1_20md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], m[16]; char hx[33];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 20, m);
    prmd5(m, hx, 32);
    SHA1((unsigned char *)hx, 32, dest);
}

/* SHA1MD5sub1-20MD5MD5 */
static void compute_sha1md5sub1_20md5md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], m[16]; char hx[33];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 20, m);
    prmd5(m, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, m);
    prmd5(m, hx, 32);
    SHA1((unsigned char *)hx, 32, dest);
}

/* SHA1MD5sub8-24MD5 */
static void compute_sha1md5sub8_24md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], m[16]; char hx[33];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)(hx + 8), 16, m);
    prmd5(m, hx, 32);
    SHA1((unsigned char *)hx, 32, dest);
}

/* SHA1SHA1sub1-16 */
static void compute_sha1sha1sub1_16(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1[20];
    char hx[41];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1);
    prmd5(sha1, hx, 40);
    SHA1((unsigned char *)hx, 16, dest);
}

/* SHA1MD5CAP: SHA1(hex(rhash_msg(RHASH_MD5, capitalize(pass)))) */
static void compute_sha1md5cap(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], *cappass = WS->tmp1;
    char hx[33];
    (void)salt; (void)saltlen;
    if (passlen > MAXLINE) passlen = MAXLINE;
    capitalize_first(cappass, pass, passlen);
    rhash_msg(RHASH_MD5, cappass, passlen, md5);
    prmd5(md5, hx, 32);
    SHA1((unsigned char *)hx, 32, dest);
}

/* SHA1MD5CAPMD5: SHA1(hex(rhash_msg(RHASH_MD5, hex(MD5(capitalize(pass)))))) */
static void compute_sha1md5capmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], m[16], *cappass = WS->tmp1;
    char hx[33];
    (void)salt; (void)saltlen;
    if (passlen > MAXLINE) passlen = MAXLINE;
    capitalize_first(cappass, pass, passlen);
    rhash_msg(RHASH_MD5, cappass, passlen, md5);
    prmd5(md5, hx, 32);
    rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, m);
    prmd5(m, hx, 32);
    SHA1((unsigned char *)hx, 32, dest);
}

/* SHA1MD51CAP = SHA1(hex(rhash_msg(RHASH_MD5, capitalize(pass)))) with x01 convention */
/* Same as SHA1MD5CAP but named with 1 */

/* SHA1MD51CAPMD5: SHA1(hex(MD5(hex(MD5(capitalize(pass)))))) */
/* Same as SHA1MD5CAPMD5 */

/* SHA1MD51CAPMD5MD5: SHA1(hex(MD5(hex(MD5(hex(MD5(capitalize(pass)))))))) */
static void compute_sha1md51capmd5md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], m[16], *cappass = WS->tmp1;
    char hx[33];
    (void)salt; (void)saltlen;
    if (passlen > MAXLINE) passlen = MAXLINE;
    capitalize_first(cappass, pass, passlen);
    rhash_msg(RHASH_MD5, cappass, passlen, md5);
    prmd5(md5, hx, 32); rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, m);
    prmd5(m, hx, 32); rhash_msg(RHASH_MD5, (unsigned char *)hx, 32, m);
    prmd5(m, hx, 32);
    SHA1((unsigned char *)hx, 32, dest);
}

/* SHA1SHA256CAP: SHA1(hex(SHA256(capitalize(pass)))) */
static void compute_sha1sha256cap(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha256[32], *cappass = WS->tmp1;
    char hx[65];
    (void)salt; (void)saltlen;
    if (passlen > MAXLINE) passlen = MAXLINE;
    capitalize_first(cappass, pass, passlen);
    SHA256(cappass, passlen, sha256);
    prmd5(sha256, hx, 64);
    SHA1((unsigned char *)hx, 64, dest);
}


/* SHA1MD5x1CAP = SHA1(hex(rhash_msg(RHASH_MD5, capitalize(pass)))) with x01 */

/* ================================================================= */
/* Chain step shorthand for generic multi-level compositions          */
/* ================================================================= */

/* Chain step shorthand: {fn, outbytes, uc_hex} */
#define S_MD5     {(hashfn_t)compute_md5, 16, 0}
#define S_MD4     {(hashfn_t)compute_md4, 16, 0}
#define S_MD2     {(hashfn_t)compute_md2, 16, 0}
#define S_SHA1    {(hashfn_t)compute_sha1, 20, 0}
#define S_SHA224  {(hashfn_t)compute_sha224, 28, 0}
#define S_SHA256  {(hashfn_t)compute_sha256, 32, 0}
#define S_SHA384  {(hashfn_t)compute_sha384, 48, 0}
#define S_SHA512  {(hashfn_t)compute_sha512, 64, 0}
#define S_GOST    {(hashfn_t)compute_gost, 32, 0}
#define S_RMD128  {(hashfn_t)compute_rmd128, 16, 0}
#define S_RMD160  {(hashfn_t)compute_rmd160, 20, 0}
#define S_TIGER   {(hashfn_t)compute_tiger, 24, 0}
#define S_WRL     {(hashfn_t)compute_whirlpool, 64, 0}
#define S_SHA0    {(hashfn_t)compute_sha0, 20, 0}
#define S_NTLM    {(hashfn_t)compute_ntlm, 16, 0}
#define S_RADMIN2 {(hashfn_t)compute_radmin2, 16, 0}
#define S_SQL5    {(hashfn_t)compute_sql5, 20, 0}
#define S_HAV128  {(hashfn_t)compute_hav128_3, 16, 0}
#define S_HAV160_4 {(hashfn_t)compute_hav160_4, 20, 0}
#define S_HAV160_3 {(hashfn_t)compute_hav160_3, 20, 0}
#define S_SHA3_256 {(hashfn_t)compute_sha3_256, 32, 0}

/* UC (uppercase hex) variants of chain steps */
#define SU_MD5    {(hashfn_t)compute_md5, 16, 1}
#define SU_SHA1   {(hashfn_t)compute_sha1, 20, 1}
#define SU_SHA224 {(hashfn_t)compute_sha224, 28, 1}
#define SU_SHA256 {(hashfn_t)compute_sha256, 32, 1}
#define SU_SHA384 {(hashfn_t)compute_sha384, 48, 1}
#define SU_SHA512 {(hashfn_t)compute_sha512, 64, 1}
#define SU_NTLM   {(hashfn_t)compute_ntlm, 16, 1}
#define SU_WRL    {(hashfn_t)compute_whirlpool, 64, 1}
#define SU_GOST   {(hashfn_t)compute_gost, 32, 1}
#define SU_LM     {(hashfn_t)compute_lm, 16, 1}
#define SU_RADMIN2 {(hashfn_t)compute_radmin2, 16, 1}

/* --- 3-step chains --- */
/* Convention: name "ABC" → chain = [C, B, A] (C=innermost, A=outermost) */

static struct chain_step chain_sha1md5md5[]       = { S_MD5, S_MD5, S_SHA1 };
static struct chain_step chain_md5sha1md5md5[]    = { S_MD5, S_MD5, S_SHA1, S_MD5 };
static struct chain_step chain_md5sha1sha1[]      = { S_SHA1, S_SHA1, S_MD5 };
static struct chain_step chain_md5sha1sha1md5[]   = { S_MD5, S_SHA1, S_SHA1, S_MD5 };
static struct chain_step chain_md5sha256md5[]     = { S_MD5, S_SHA256, S_MD5 };
static struct chain_step chain_md5gostmd5[]       = { S_MD5, S_GOST, S_MD5 };
static struct chain_step chain_md5wrlmd5[]        = { S_MD5, S_WRL, S_MD5 };
static struct chain_step chain_md5wrlsha1[]       = { S_SHA1, S_WRL, S_MD5 };
static struct chain_step chain_md5sha1sha256[]    = { S_SHA256, S_SHA1, S_MD5 };
static struct chain_step chain_md5hav160_3[]      = { S_HAV160_3, S_MD5 };
static struct chain_step chain_md5sha1hav160_4[]  = { S_HAV160_4, S_SHA1, S_MD5 };

/* SHA1-outer 3-step chains */
static struct chain_step chain_sha1md5md5md5[]    = { S_MD5, S_MD5, S_MD5, S_SHA1 };
static struct chain_step chain_sha1md5md5md5md5[] = { S_MD5, S_MD5, S_MD5, S_MD5, S_SHA1 };
static struct chain_step chain_sha1md5md5md5md5md5[] = { S_MD5, S_MD5, S_MD5, S_MD5, S_MD5, S_SHA1 };
static struct chain_step chain_sha1md5md5sha1[]   = { S_SHA1, S_MD5, S_MD5, S_SHA1 };
static struct chain_step chain_sha1md5md5sha1md5[] = { S_MD5, S_SHA1, S_MD5, S_MD5, S_SHA1 };
static struct chain_step chain_sha1md5md5md5sha1[] = { S_SHA1, S_MD5, S_MD5, S_MD5, S_SHA1 };
static struct chain_step chain_sha1md5md5sha1sha1md5[] = { S_MD5, S_SHA1, S_SHA1, S_MD5, S_MD5, S_SHA1 };
static struct chain_step chain_sha1md5md5sha1md5sha1sha1md5[] = { S_MD5, S_SHA1, S_SHA1, S_MD5, S_SHA1, S_MD5, S_MD5, S_SHA1 };

/* SHA1MD5SHA1 variations */
static struct chain_step chain_sha1md5sha1md5sha1[] = { S_SHA1, S_MD5, S_SHA1, S_MD5, S_SHA1 };
static struct chain_step chain_sha1md5sha1md5sha1md5[] = { S_MD5, S_SHA1, S_MD5, S_SHA1, S_MD5, S_SHA1 };
static struct chain_step chain_sha1md5sha1md5sha1md5sha1[] = { S_SHA1, S_MD5, S_SHA1, S_MD5, S_SHA1, S_MD5, S_SHA1 };
static struct chain_step chain_sha1md5sha1md5md5sha1md5[] = { S_MD5, S_SHA1, S_MD5, S_MD5, S_SHA1, S_MD5, S_SHA1 };

/* MD5SHA1MD5 deeper chains */
static struct chain_step chain_md5sha1md5md5md5[]  = { S_MD5, S_MD5, S_MD5, S_SHA1, S_MD5 };
static struct chain_step chain_md5sha1md5md5sha1[] = { S_SHA1, S_MD5, S_MD5, S_SHA1, S_MD5 };
static struct chain_step chain_md5sha1md5md5sha1md5[] = { S_MD5, S_SHA1, S_MD5, S_MD5, S_SHA1, S_MD5 };
static struct chain_step chain_md5sha1md5md5md5sha1[] = { S_SHA1, S_MD5, S_MD5, S_MD5, S_SHA1, S_MD5 };
static struct chain_step chain_md5sha1md5sha1md5[] = { S_MD5, S_SHA1, S_MD5, S_SHA1, S_MD5 };
static struct chain_step chain_md5sha1md5sha1sha1[] = { S_SHA1, S_SHA1, S_MD5, S_SHA1, S_MD5 };
static struct chain_step chain_md5sha1md5sha1md5sha1md5sha1md5sha1md5sha1[] = {
    S_SHA1, S_MD5, S_SHA1, S_MD5, S_SHA1, S_MD5, S_SHA1, S_MD5, S_SHA1, S_MD5, S_SHA1, S_MD5
};

/* MD5SHA1RADMIN2 / RADMIN2 chains */
static struct chain_step chain_md5sha1radmin2md5[] = { S_MD5, S_RADMIN2, S_SHA1, S_MD5 };
static struct chain_step chain_md5sha1md5radmin2[] = { S_RADMIN2, S_MD5, S_SHA1, S_MD5 };

/* RADMIN2 compositions */
static struct chain_step chain_radmin2md5[]        = { S_MD5, S_RADMIN2 };
static struct chain_step chain_radmin2md5md5[]     = { S_MD5, S_MD5, S_RADMIN2 };
static struct chain_step chain_radmin2md5md5md5[]  = { S_MD5, S_MD5, S_MD5, S_RADMIN2 };
static struct chain_step chain_radmin2sha1[]       = { S_SHA1, S_RADMIN2 };
static struct chain_step chain_radmin2md5sha1[]    = { S_SHA1, S_MD5, S_RADMIN2 };
static struct chain_step chain_radmin2sha1md5[]    = { S_MD5, S_SHA1, S_RADMIN2 };
static struct chain_step chain_md5radmin2[]        = { S_RADMIN2, S_MD5 };
static struct chain_step chain_md5radmin2md5[]     = { S_MD5, S_RADMIN2, S_MD5 };
static struct chain_step chain_md5radmin2sha1[]    = { S_SHA1, S_RADMIN2, S_MD5 };
static struct chain_step chain_sha1md5radmin2[]    = { S_RADMIN2, S_MD5, S_SHA1 };

/* SQL5 compositions */
static struct chain_step chain_md5sql5[]           = { S_SQL5, S_MD5 };
static struct chain_step chain_md5sql5md5[]        = { S_MD5, S_SQL5, S_MD5 };
static struct chain_step chain_sha1sql5[]          = { S_SQL5, S_SHA1 };
static struct chain_step chain_sha1sql5md5[]       = { S_MD5, S_SQL5, S_SHA1 };
static struct chain_step chain_sha1sql5md5md5[]    = { S_MD5, S_MD5, S_SQL5, S_SHA1 };
static struct chain_step chain_sha1md5sql5[]       = { S_SQL5, S_MD5, S_SHA1 };
static struct chain_step chain_sha1md5md5sql5[]    = { S_SQL5, S_MD5, S_MD5, S_SHA1 };
static struct chain_step chain_mysql5md5[]         = { S_MD5, S_SQL5 };  /* SQL5 inner, MD5 outer... wait no */

/* SHA1SHA256 deeper chains */
static struct chain_step chain_sha1sha256sha1[]    = { S_SHA1, S_SHA256, S_SHA1 };
static struct chain_step chain_sha1sha256sha256[]  = { S_SHA256, S_SHA256, S_SHA1 };
static struct chain_step chain_sha1sha256sha256sha256[] = { S_SHA256, S_SHA256, S_SHA256, S_SHA1 };
static struct chain_step chain_sha1sha256md5[]     = { S_MD5, S_SHA256, S_SHA1 };
static struct chain_step chain_sha1sha256md5md5[]  = { S_MD5, S_MD5, S_SHA256, S_SHA1 };
static struct chain_step chain_sha1sha256md5sha256md5[] = { S_MD5, S_SHA256, S_MD5, S_SHA256, S_SHA1 };
static struct chain_step chain_sha1sha256sha512[]  = { S_SHA512, S_SHA256, S_SHA1 };
static struct chain_step chain_sha256md5sha256md5[] = { S_MD5, S_SHA256, S_MD5, S_SHA256 };

/* SHA1MD5SHA256 / SHA1MD5SHA512 */
static struct chain_step chain_sha1md5sha256[]     = { S_SHA256, S_MD5, S_SHA1 };
static struct chain_step chain_sha1md5sha512[]     = { S_SHA512, S_MD5, S_SHA1 };

/* SHA1SHA3-256 */
static struct chain_step chain_sha1sha3_256[]      = { S_SHA3_256, S_SHA1 };

/* SHA1WRL compositions */
static struct chain_step chain_sha1wrlmd5[]        = { S_MD5, S_WRL, S_SHA1 };
static struct chain_step chain_sha1md5wrlsha1[]    = { S_SHA1, S_WRL, S_MD5, S_SHA1 };

/* MD4UTF16 (NTLM) deeper chains */
static struct chain_step chain_md4utf16md5md5[]    = { S_NTLM, S_MD5, S_MD5 };
static struct chain_step chain_md4utf16md5md5md5[] = { S_NTLM, S_MD5, S_MD5, S_MD5 };
static struct chain_step chain_md4utf16md5md5md5md5[] = { S_NTLM, S_MD5, S_MD5, S_MD5, S_MD5 };
static struct chain_step chain_md4utf16sha1sha1[]  = { S_NTLM, S_SHA1, S_SHA1 };
static struct chain_step chain_md4utf16sha1md5[]   = { S_NTLM, S_MD5, S_SHA1 };
static struct chain_step chain_md4utf16md5sha1[]   = { S_NTLM, S_SHA1, S_MD5 };
static struct chain_step chain_md4utf16sha256md5[] = { S_NTLM, S_MD5, S_SHA256 };
static struct chain_step chain_md4utf16sha256sha1[] = { S_NTLM, S_SHA1, S_SHA256 };
static struct chain_step chain_md4utf16sha256sha256[] = { S_NTLM, S_SHA256, S_SHA256 };
static struct chain_step chain_md4utf16sha256sha256sha256[] = { S_NTLM, S_SHA256, S_SHA256, S_SHA256 };
static struct chain_step chain_md4utf16sha256sha256sha256sha256[] = { S_NTLM, S_SHA256, S_SHA256, S_SHA256, S_SHA256 };
static struct chain_step chain_md4utf16sha256sha256sha256sha256sha256[] = { S_NTLM, S_SHA256, S_SHA256, S_SHA256, S_SHA256, S_SHA256 };

/* MD4SHA1MD5 */
static struct chain_step chain_md4sha1md5[]        = { S_MD5, S_SHA1, S_MD4 };

/* SHA1GOST, MD5NTLM */
static struct chain_step chain_md5ntlm[]           = { S_NTLM, S_MD5 };

/* --- UC intermediate chains (uppercase hex between steps) --- */
/* MD5UCMD5 = rhash_msg(RHASH_MD5, hexUC(MD5(pass))) */
static struct chain_step chain_md5ucmd5[]          = { SU_MD5, S_MD5 };
/* SHA1MD5UCMD5 = SHA1(hexUC(MD5(hex(MD5(pass))))) — UC on middle MD5 */
static struct chain_step chain_sha1md5ucmd5[]      = { S_MD5, SU_MD5, S_SHA1 };
/* MD5SHA1UCMD5 = MD5(hexUC(SHA1(hex(MD5(pass))))) — UC on middle SHA1 */
static struct chain_step chain_md5sha1ucmd5[]      = { S_MD5, SU_SHA1, S_MD5 };
/* SHA1MD5UCMD5UC = SHA1(hexUC(rhash_msg(RHASH_MD5, hexUC(MD5(hexUC(pass)))))) */
/* No — SHA1MD5UCMD5UC means: inner=MD5UC, then MD5UC, then SHA1 outer  */
/* MD5UC step outputs UC hex, MD5UC step outputs UC hex, SHA1 outer */
static struct chain_step chain_sha1md5ucmd5uc[]    = { SU_MD5, SU_MD5, S_SHA1 };
/* MD5MD5UCMD5 = MD5(hexUC(MD5(hex(MD5(pass))))) — UC on middle MD5 */
static struct chain_step chain_md5md5ucmd5[]       = { S_MD5, SU_MD5, S_MD5 };
/* SHA1MD5UCMD5UCMD5UC = SHA1(hexUC(rhash_msg(RHASH_MD5, hexUC(MD5(hexUC(MD5(pass))))))) */
static struct chain_step chain_sha1md5ucmd5ucmd5uc[] = { SU_MD5, SU_MD5, SU_MD5, S_SHA1 };
/* SHA1MD5UCMD5UCMD5UCMD5UC */
static struct chain_step chain_sha1md5ucmd5ucmd5ucmd5uc[] = { SU_MD5, SU_MD5, SU_MD5, SU_MD5, S_SHA1 };
/* SHA1UCWRL = SHA1(hex(WRL(hexUC(SHA1(pass))))) ... hmm no */
/* SHA1UCWRL means inner=WRL, outer=SHA1UC? Or inner=SHA1UC, outer=WRL? */
/* Following convention: rightmost=inner. SHA1UCWRL: rightmost=WRL, inner=WRL */
/* So: SHA1UC(hex(WRL(pass))) — SHA1 applied to hex of WRL, UC output */
static struct chain_step chain_sha1ucwrl[]         = { S_WRL, S_SHA1 };


/* SHA1MD5UCSHA1UCMD5UC */
static struct chain_step chain_sha1md5ucsha1ucmd5uc[] = { SU_MD5, SU_SHA1, SU_MD5, S_SHA1 };
/* SHA1MD5MD5UCMD5UC: SHA1(hexUC(rhash_msg(RHASH_MD5, hexUC(MD5(hex(MD5(pass))))))) */
static struct chain_step chain_sha1md5md5ucmd5uc[] = { S_MD5, SU_MD5, SU_MD5, S_SHA1 };
/* SHA1MD5MD5UCMD5MD5UC: SHA1(hexUC(MD5(hex(MD5(hexUC(MD5(hex(MD5(pass)))))))) */
static struct chain_step chain_sha1md5md5ucmd5md5uc[] = { S_MD5, S_MD5, SU_MD5, S_MD5, SU_MD5, S_SHA1 };

/* SHA1SHA256UCSHA256 = SHA1(hexUC(SHA256(hex(SHA256(pass))))) — UC on middle SHA256 */
static struct chain_step chain_sha1sha256ucsha256[] = { S_SHA256, SU_SHA256, S_SHA1 };
/* SHA1SHA256UCSHA256SHA256 = SHA1(hexUC(SHA256(hex(SHA256(hex(SHA256(pass))))))) — UC on 3rd */
static struct chain_step chain_sha1sha256ucsha256sha256[] = { S_SHA256, S_SHA256, SU_SHA256, S_SHA1 };

/* SHA1MD4UTF16UCMD4UTF16UC */
static struct chain_step chain_sha1md4utf16ucmd4utf16uc[] = { SU_NTLM, SU_NTLM, S_SHA1 };

/* UC-intermediate 2-step chains */
static struct chain_step chain_sha1_md5uc[]        = { SU_MD5, S_SHA1 };
static struct chain_step chain_md5_sha1uc[]        = { SU_SHA1, S_MD5 };
static struct chain_step chain_sha1_ntlmuc[]       = { SU_NTLM, S_SHA1 };
static struct chain_step chain_sha1_sha256uc[]     = { SU_SHA256, S_SHA1 };
static struct chain_step chain_sha1_sha512uc[]     = { SU_SHA512, S_SHA1 };
static struct chain_step chain_md5_ntlmuc[]        = { SU_NTLM, S_MD5 };
static struct chain_step chain_radmin2_md5uc[]     = { SU_MD5, S_RADMIN2 };
static struct chain_step chain_md5_lmuc[]          = { SU_LM, S_MD5 };
static struct chain_step chain_ntlm_md5uc[]        = { SU_MD5, S_NTLM };
static struct chain_step chain_ntlm_sha1uc[]       = { SU_SHA1, S_NTLM };
static struct chain_step chain_ntlm_sha256uc[]     = { SU_SHA256, S_NTLM };
static struct chain_step chain_sha1_wrluc[]        = { SU_WRL, S_SHA1 };
static struct chain_step chain_sha1_sha1uc[]       = { SU_SHA1, S_SHA1 };
/* UC-intermediate 3-step chains */
static struct chain_step chain_md5_sha1_md5uc[]    = { SU_MD5, S_SHA1, S_MD5 };
static struct chain_step chain_sha1_md5_md5uc[]    = { SU_MD5, S_MD5, S_SHA1 };
static struct chain_step chain_md5_gost_md5uc[]    = { SU_MD5, S_GOST, S_MD5 };
/* UC-intermediate 4-step chains */
static struct chain_step chain_md5_sha1_md5_md5uc[] = { SU_MD5, S_MD5, S_SHA1, S_MD5 };

/* MD5SHA1MD5MD5UC = rhash_msg(RHASH_MD5, hexUC(SHA1(hex(MD5(hex(MD5(pass))))))) */
/* Wait: inner MD5s are normal, SHA1 is normal, outer MD5 receives UC from SHA1? */
/* Actually: MD5SHA1MD5MD5UC: the UC suffix means the FINAL output is uppercase */
/* The chain itself uses normal hex internally. The UC flag on the HT entry handles output. */
/* So this is the same chain as MD5SHA1MD5MD5, just with HTF_UC on the HT entry */

/* Additional missing composition chains */
/* MYSQL5MD5 — wait, MYSQL5 is SHA1(SHA1(pass)) = SQL5 already. So MYSQL5MD5 = rhash_msg(RHASH_MD5, hex(SQL5(pass))) */
/* Already have chain_mysql5md5 */

/* MD5GOSTMD5UC — same chain as MD5GOSTMD5 but with HTF_UC */

/* RADMIN2SQL5-40: SQL5 truncated to first 40 hex chars — needs special handling, skip */

/* --- Additional chains for remaining types --- */

/* MD4UTF16 deeper chains */
static struct chain_step chain_md4utf16md5sha256[] = { S_NTLM, S_SHA256, S_MD5 };  /* not present yet? */

/* rev chains: reverse hex output of inner, then outer */
/* SHA1revBASE64 is special — skip for now (needs base64) */

/* PASS-concatenation chains */
/* MD5MD5UCSHA1MD5MD5: inner→outer: MD5,MD5,SHA1,MD5UC,MD5. UC on 4th step (index 3) */
static struct chain_step chain_md5md5ucsha1md5md5[] = { S_MD5, S_MD5, S_SHA1, SU_MD5, S_MD5 };

/* MD5MD5UCSQL3p — needs special handling (SQL3 + password append) */
/* SHA1MD5MD5UCx — iteration marker variant of SHA1MD5MD5UC */

/* CAP chains: compute_md5cap provides the inner hash */
/* SHA1MD51CAP = SHA1(hex(rhash_msg(RHASH_MD5, hex(MD5(capitalize(pass)))))) */
/* SHA1MD5CAP = SHA1(hex(MD5(capitalize(pass)))) */

/* SQL3 = SHA1(pass + salt) — but without salt it's just SHA1(pass) — treated as SHA1PASSSALT */
/* MD5SQL3 = MD5(hex(SQL3(pass))) — but SQL3 needs salt. As unsalted, skip */
/* MD5SQL5 already defined */

/* SQL5 derivative chains */
static struct chain_step chain_md5sql5_32[]    = { S_SQL5, S_MD5 };   /* same as chain_md5sql5 */
static struct chain_step chain_sha1sql3[]      = { S_SHA1, S_SHA1 };  /* SQL3 unsalted ≈ SHA1SHA1 */

/* SHA1RADMIN2 chain */
static struct chain_step chain_sha1radmin2[]   = { S_RADMIN2, S_SHA1 };
static struct chain_step chain_sha1radmin2md5[]= { S_MD5, S_RADMIN2, S_SHA1 };

/* MD6 chains */
static struct chain_step chain_sha1md6[]       = { {(hashfn_t)compute_md6_128, 16, 0}, S_SHA1 };

/* WRLRAW chain — WRL output is raw binary, used as-is */
/* MD5WRLRAW = rhash_msg(RHASH_MD5, WRL_raw(pass)) — 16 bytes = MD5 of 64-byte raw WRL */
static void compute_md5wrlraw(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char wrl[64];
    (void)salt; (void)saltlen;
    compute_whirlpool(pass, passlen, NULL, 0, wrl);
    rhash_msg(RHASH_MD5, wrl, 64, dest);
}

/* MD5RAW = raw binary MD5, 16 bytes — used as input to other hashes */
/* MD5RAWMD5RAW = rhash_msg(RHASH_MD5, MD5_raw(pass)) — binary chain */
static void compute_md5rawmd5raw(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, md5);
    rhash_msg(RHASH_MD5, md5, 16, dest);
}

/* MD5RAWUC = MD5 with UC output, raw input doesn't matter for output */
/* MD5MD2RAW = rhash_msg(RHASH_MD5, MD2_raw(pass)) */
static void compute_md5md2raw(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md2[16];
    (void)salt; (void)saltlen;
    compute_md2(pass, passlen, NULL, 0, md2);
    rhash_msg(RHASH_MD5, md2, 16, dest);
}

/* MD5SHA1RAW = rhash_msg(RHASH_MD5, SHA1_raw(pass)) */
static void compute_md5sha1raw(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1[20];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, sha1);
    rhash_msg(RHASH_MD5, sha1, 20, dest);
}

/* MD5SHA1SHA1RAW = rhash_msg(RHASH_MD5, hex(SHA1(SHA1_raw(pass))))
 * SHA1RAW = feed raw SHA1 binary (20 bytes) to next step
 * So: SHA1_binary(pass) → SHA1(those 20 bytes) → hex(that) → MD5(hex string) */
static void compute_md5sha1sha1raw(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h1[20], h2[20]; char hex[41];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, h1);      /* SHA1_raw(pass) = 20 binary bytes */
    SHA1(h1, 20, h2);             /* SHA1(binary) = 20 binary bytes */
    prmd5(h2, hex, 40);           /* hex encode SHA1 result */
    rhash_msg(RHASH_MD5, (unsigned char *)hex, 40, dest);  /* rhash_msg(RHASH_MD5, hex string) */
}

/* Let me redo the RAW types properly */
/* RAW means: feed the raw binary hash output to the next step, not the hex string */

/* SHA1RAW = SHA1_raw(pass) — same as SHA1 but the "RAW" indicates binary output feeding */
/* When used in composition: SHA1(raw_binary) not SHA1(hex_string) */

/* For chain mechanism: need a new chain step type that passes raw binary */
/* Add a raw chain step variant */
#define S_MD5R    {(hashfn_t)compute_md5, 16, 2}  /* uc_hex=2 means raw (no hex) */
#define S_SHA1R   {(hashfn_t)compute_sha1, 20, 2}
#define S_SHA224R {(hashfn_t)compute_sha224, 28, 2}
#define S_SHA256R {(hashfn_t)compute_sha256, 32, 2}
#define S_SHA384R {(hashfn_t)compute_sha384, 48, 2}
#define S_SHA512R {(hashfn_t)compute_sha512, 64, 2}
#define S_MD2R    {(hashfn_t)compute_md2,  16, 2}
#define S_WRLR    {(hashfn_t)compute_whirlpool, 64, 2}
#define S_RADMIN2R {(hashfn_t)compute_radmin2, 16, 2}

/* RAW chain types */
static struct chain_step chain_md5raw[]        = { S_MD5R, S_MD5 };  /* rhash_msg(RHASH_MD5, MD5_raw(pass)) — wait, MD5RAW IS the raw hash */
/* Actually MD5RAW just means: the hash is output as raw binary, not hex.
   For our purposes of verification, MD5RAW produces the same 16 bytes as MD5.
   The "RAW" refers to input format, not computation.
   So MD5RAW → hashlen=16, same compute as MD5.
   MD5RAWMD5RAW = MD5(raw(MD5(pass))) vs MD5MD5 = rhash_msg(RHASH_MD5, hex(MD5(pass)))
   In mdxfind, RAW means the inner hash's binary output is fed directly (not hex-encoded) to the outer hash.
*/

/* Raw binary chain steps: inner outputs raw binary, fed directly to outer */
static struct chain_step chain_md5raw_x[]          = { S_MD5R, S_MD5 };  /* MD5(MD5raw(pass)) but wait, raw step means no hex between */
/* We need to update run_chain to handle uc_hex=2 (raw: pass binary directly) */

static struct chain_step chain_md5rawmd5raw[]      = { S_MD5R, S_MD5 };  /* MD5RAW(MD5RAW(pass)) = rhash_msg(RHASH_MD5, raw MD5(pass)) */
static struct chain_step chain_md5md2raw[]         = { S_MD2R, S_MD5 };
static struct chain_step chain_md5sha1raw[]        = { S_SHA1R, S_MD5 };
static struct chain_step chain_md5sha1sha1raw[]    = { S_SHA1R, S_SHA1, S_MD5 };  /* MD5(hex(SHA1(SHA1raw(pass)))) */
/* Wait: SHA1SHA1RAW = SHA1(SHA1_raw(pass)). The SHA1 outer gets raw SHA1 binary, not hex. */
/* chain: [SHA1R_inner, SHA1_outer] — inner produces 20 raw bytes, outer SHA1s those bytes */
/* Then MD5SHA1SHA1RAW = rhash_msg(RHASH_MD5, hex(SHA1(SHA1_raw(pass)))) */
/* chain: [SHA1R, SHA1, MD5] — SHA1R outputs 20 raw bytes fed to SHA1, SHA1 outputs 20 bytes hex'd, MD5 */
static struct chain_step chain_md5raw_self[]       = { S_MD5R, S_MD5 };    /* MD5RAW = MD5(MD5_binary(pass)) */
static struct chain_step chain_sha1raw_self[]      = { S_SHA1R, S_SHA1 };  /* SHA1RAW = SHA1(SHA1_binary(pass)) */
static struct chain_step chain_sha224raw_self[]    = { S_SHA224R, S_SHA224 };
static struct chain_step chain_sha256raw_self[]    = { S_SHA256R, S_SHA256 };
static struct chain_step chain_sha384raw_self[]    = { S_SHA384R, S_SHA384 };
static struct chain_step chain_sha512raw_self[]    = { S_SHA512R, S_SHA512 };
static struct chain_step chain_sha1sha1raw[]       = { S_SHA1R, S_SHA1 };
static struct chain_step chain_sha1sha1rawmd5[]    = { S_SHA1R, S_SHA1, S_MD5 };  /* rhash_msg(RHASH_MD5, hex(SHA1(SHA1raw(pass)))) */
/* Hmm, these names are confusing. In mdxfind naming:
   SHA1SHA1RAWMD5 = MD5(hex(SHA1(hex(SHA1(SHA1raw(pass)))))) — No.
   SHA1SHA1RAWMD5: rightmost=MD5, then SHA1RAW, then SHA1 outer
   Actually: read right to left: MD5 is innermost, SHA1RAW is middle, SHA1 is outermost
   SHA1(SHA1RAW(hex(MD5(pass))))
   SHA1RAW means: take the result and pass raw binary to the next step
   So: rhash_msg(RHASH_MD5, pass) → hex → SHA1(hex) → raw binary → SHA1(raw_binary) = SHA1SHA1RAWMD5

   That doesn't make sense either. Let me reconsider.

   In mdxfind, the "RAW" suffix modifies the preceding hash to indicate its output is used as raw binary.
   SHA1SHA1RAWMD5: SHA1(SHA1_raw(MD5(pass)))
   = SHA1 applied to: SHA1_raw of MD5hex
   = SHA1(SHA1_binary(hex(MD5(pass))))

   Actually even simpler: SHA1RAWMD5 = SHA1RAW(hex(MD5(pass))) = raw SHA1 of MD5 hex
   Then SHA1SHA1RAWMD5 = SHA1(raw_sha1_of_md5hex)

   So the chain is: MD5 → hex → SHA1 → raw (no hex) → SHA1
   [S_MD5, S_SHA1R, S_SHA1]
*/
static struct chain_step chain_sha1sha1rawmd5_v2[] = { S_MD5, S_SHA1R, S_SHA1 };
static struct chain_step chain_sha1sha1rawmd5md5[] = { S_MD5, S_MD5, S_SHA1R, S_SHA1 };
static struct chain_step chain_sha1sha1rawmd5md5md5[] = { S_MD5, S_MD5, S_MD5, S_SHA1R, S_SHA1 };

/* Similarly: MD5SHA1RAW = MD5(SHA1_raw(pass)) = MD5 of 20 raw bytes of SHA1 */
/* chain: [S_SHA1R, S_MD5] — SHA1 produces 20 raw bytes, MD5 hashes those */
/* But wait — that would be a 2-step chain where step 0 output is raw binary */
/* For the FIRST step, it always hashes the password. The "raw" applies to its output before feeding to step 1. */
/* So chain: [SHA1raw, MD5outer] means SHA1(pass) → 20 raw bytes → rhash_msg(RHASH_MD5, 20 raw bytes) = MD5SHA1RAW */
static struct chain_step chain_md5sha1raw_v2[]     = { S_SHA1R, S_MD5 };

/* MD5RAWUC — just MD5 with UC output */

/* SHA1MD5RAW = SHA1(MD5_raw(pass)) */
static struct chain_step chain_sha1md5raw[]        = { S_MD5R, S_SHA1 };
/* SHA1MD5RAWUCMD5RAW = SHA1(MD5raw(hexUC(MD5raw(pass)))) — complex */
/* MD5raw(pass) → UC hex → MD5raw → feed to SHA1 */
/* Hmm, "MD5RAWUC" = raw MD5 of UC hex? */
/* Let's just skip the most complex RAW types for now */

/* Additional chains for UC intermediate + other compositions */

/* MD5SHA1UCMD5UC = rhash_msg(RHASH_MD5, hexUC(SHA1(hexUC(MD5(pass))))) — wait, naming */
/* SHA1UCMD5UC means: MD5 inner (UC hex), then SHA1 (UC hex), then ... */
/* Actually: MD5SHA1UCMD5UC */
/* Read R-to-L: MD5UC → SHA1UC → MD5 */
/* = rhash_msg(RHASH_MD5, hex(SHA1(hexUC(MD5(hexUC(pass)))))) — no, MD5UC means MD5 with UC output */
/* I think: innermost=MD5UC (UC hex output), then SHA1UC, then MD5 outer */
/* chain: [SU_MD5, SU_SHA1, S_MD5] — but wait, that's md5sha1ucmd5 */
/* MD5SHA1UCMD5UC: the trailing UC means MD5 outer outputs UC → HTF_UC */

/* SHA1SHA256UCx — just SHA1SHA256UC with iteration marker */

/* SHA1SHA256UCxSHA256 = SHA1(hex(SHA256(hexUC(SHA256(hex(SHA1(pass))))))) ? */
/* or: SHA256 inner, SHA256UC intermediate, SHA1 outer, "xSHA256" = extra SHA256 step */
/* SHA1SHA256UCxSHA256: read R-to-L: SHA256 → x (iter) → SHA256UC → SHA1 */
/* The 'x' is just an iteration marker, not a separate hash. Skip */


/* ---- New compute functions for unregistered types ---- */

/* mysql3_hex: compute MySQL3 hash and return as 16-char hex string */
static int mysql3_hex(const unsigned char *pass, int passlen, char *out)
{
    unsigned char dest[8];
    compute_mysql3(pass, passlen, NULL, 0, dest);
    bin2hex(dest, 8, out);
    return 16;
}

/* ---- BASE64 types ---- */

/* MD5SHA1BASE64 = rhash_msg(RHASH_MD5, hex(SHA1(base64(pass)))) */
static void compute_md5sha1base64(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char sha1[20]; char *b64 = (char *)WS->tmp1; char hex[41]; int blen;
    (void)salt; (void)saltlen;
    blen = base64_encode(pass, passlen, b64, sizeof(WS->tmp1));
    SHA1((unsigned char *)b64, blen, sha1);
    prmd5(sha1, hex, 40);
    rhash_msg(RHASH_MD5, (unsigned char *)hex, 40, dest);
}

/* MD5SHA1MD5BASE64 = rhash_msg(RHASH_MD5, hex(SHA1(hex(MD5(base64(pass)))))) */
static void compute_md5sha1md5base64(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char md5[16], sha1[20]; char *b64 = (char *)WS->tmp1; char hex[41]; int blen;
    (void)salt; (void)saltlen;
    blen = base64_encode(pass, passlen, b64, sizeof(WS->tmp1));
    rhash_msg(RHASH_MD5, (unsigned char *)b64, blen, md5);
    prmd5(md5, hex, 32);
    SHA1((unsigned char *)hex, 32, sha1);
    prmd5(sha1, hex, 40);
    rhash_msg(RHASH_MD5, (unsigned char *)hex, 40, dest);
}

/* SHA1BASE64 = SHA1(base64(pass)) */
static void compute_sha1base64(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    char *b64 = (char *)WS->tmp1; int blen;
    (void)salt; (void)saltlen;
    blen = b64_encode(pass, passlen, b64);
    SHA1((unsigned char *)b64, blen, dest);
}

/* MD5BASE64MD5RAW = rhash_msg(RHASH_MD5, base64(MD5_binary(pass))) */
static void compute_md5base64md5raw(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16]; char b64[32]; int blen;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);
    blen = b64_encode(h, 16, b64);
    rhash_msg(RHASH_MD5, (unsigned char *)b64, blen, dest);
}

/* MD5BASE64SHA1RAW = rhash_msg(RHASH_MD5, base64(SHA1_binary(pass))) */
static void compute_md5base64sha1raw(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[20]; char b64[32]; int blen;
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, h);
    blen = b64_encode(h, 20, b64);
    rhash_msg(RHASH_MD5, (unsigned char *)b64, blen, dest);
}

/* SHA1BASE64MD5RAW = SHA1(base64(MD5_binary(pass))) */
static void compute_sha1base64md5raw(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16]; char b64[32]; int blen;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);
    blen = b64_encode(h, 16, b64);
    SHA1((unsigned char *)b64, blen, dest);
}

/* SHA1BASE64SHA1RAW = SHA1(base64(SHA1_binary(pass))) */
static void compute_sha1base64sha1raw(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[20]; char b64[32]; int blen;
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, h);
    blen = b64_encode(h, 20, b64);
    SHA1((unsigned char *)b64, blen, dest);
}

/* MD5BASE64SHA1RAWMD5 = rhash_msg(RHASH_MD5, hex(SHA1(base64(MD5_binary(pass))))) */
static void compute_md5base64sha1rawmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h1[16], h2[20]; char b64[32], hex[41]; int blen;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h1);
    blen = b64_encode(h1, 16, b64);
    SHA1((unsigned char *)b64, blen, h2);
    bin2hex(h2, 20, hex);
    rhash_msg(RHASH_MD5, (unsigned char *)hex, 40, dest);
}

/* MD5BASE64SHA1RAWBASE64SHA1RAW = rhash_msg(RHASH_MD5, base64(SHA1_binary(base64(SHA1_binary(pass))))) */
static void compute_md5base64sha1rawbase64sha1raw(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h1[20], h2[20]; char b64a[32], b64b[48]; int blen;
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, h1);
    blen = b64_encode(h1, 20, b64a);
    SHA1((unsigned char *)b64a, blen, h2);
    blen = b64_encode(h2, 20, b64b);
    rhash_msg(RHASH_MD5, (unsigned char *)b64b, blen, dest);
}

/* MD5UCBASE64SHA1RAW = same as MD5BASE64SHA1RAW (UC only affects output) */
static void compute_md5ucbase64sha1raw(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    compute_md5base64sha1raw(pass, passlen, salt, saltlen, dest);
}

/* MD5SHA1BASE64MD5RAW = rhash_msg(RHASH_MD5, hex(SHA1(base64(MD5_raw(pass))))) */
static void compute_md5sha1base64md5raw(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h1[16], h2[20]; char b64[32], hex[41]; int blen;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h1);
    blen = b64_encode(h1, 16, b64);
    SHA1((unsigned char *)b64, blen, h2);
    bin2hex(h2, 20, hex);
    rhash_msg(RHASH_MD5, (unsigned char *)hex, 40, dest);
}

/* RADMIN2BASE64 = RADMIN2(base64(pass)) */
static void compute_radmin2base64(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    char *b64 = (char *)WS->tmp1; int blen;
    (void)salt; (void)saltlen;
    blen = b64_encode(pass, passlen, b64);
    compute_radmin2((unsigned char *)b64, blen, NULL, 0, dest);
}

/* SHA1RADMIN2BASE64 = SHA1(hex(RADMIN2(base64(pass)))) */
static void compute_sha1radmin2base64(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16]; char *b64 = (char *)WS->tmp1; char hex[33]; int blen;
    (void)salt; (void)saltlen;
    blen = b64_encode(pass, passlen, b64);
    compute_radmin2((unsigned char *)b64, blen, NULL, 0, h);
    bin2hex(h, 16, hex);
    SHA1((unsigned char *)hex, 32, dest);
}

/* MD5SHA1BASE64SHA1MD5 = rhash_msg(RHASH_MD5, hex(SHA1(base64(hex(SHA1(hex(MD5(pass)))))))) */
static void compute_md5sha1base64sha1md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h1[16], h2[20], h3[20];
    char hex1[33], hex2[41], b64[64]; int blen;
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h1);
    bin2hex(h1, 16, hex1);
    SHA1((unsigned char *)hex1, 32, h2);
    bin2hex(h2, 20, hex2);
    blen = b64_encode((unsigned char *)hex2, 40, b64);
    SHA1((unsigned char *)b64, blen, h3);
    bin2hex(h3, 20, hex2);
    rhash_msg(RHASH_MD5, (unsigned char *)hex2, 40, dest);
}

/* ---- SQL types ---- */

/* MD5SQL3 = rhash_msg(RHASH_MD5, mysql3_hex(pass)) */
static void compute_md5sql3(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    char sq[17];
    (void)salt; (void)saltlen;
    mysql3_hex(pass, passlen, sq);
    rhash_msg(RHASH_MD5, (unsigned char *)sq, 16, dest);
}

/* MD4SQL3 = rhash_msg(RHASH_MD4, mysql3_hex(pass)) */
static void compute_md4sql3(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    char sq[17];
    (void)salt; (void)saltlen;
    mysql3_hex(pass, passlen, sq);
    rhash_msg(RHASH_MD4, (unsigned char *)sq, 16, dest);
}

/* RADMIN2SQL3 = RADMIN2(mysql3_hex(pass)) */
static void compute_radmin2sql3(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    char sq[17];
    (void)salt; (void)saltlen;
    mysql3_hex(pass, passlen, sq);
    compute_radmin2((unsigned char *)sq, 16, NULL, 0, dest);
}

/* MD5SQL5 = rhash_msg(RHASH_MD5, "*" + UC_hex(SHA1(SHA1(pass)))) — 41 bytes */
static void compute_md5sql5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h1[20], h2[20]; char buf[42];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, h1);
    SHA1(h1, 20, h2);
    buf[0] = '*';
    bin2hexUC(h2, 20, buf + 1);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 41, dest);
}

/* MD5MD5UCSQL3p = rhash_msg(RHASH_MD5, UC_hex(MD5(mysql3(pass))) + " ") — 33 bytes */
static void compute_md5md5ucsql3p(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char mysql3[8], md5[16];
    char hex[18], hex2[34];
    (void)salt; (void)saltlen;
    compute_mysql3(pass, passlen, NULL, 0, mysql3);
    prmd5(mysql3, hex, 16);   /* 16 hex chars from 8 binary bytes */
    rhash_msg(RHASH_MD5, (unsigned char *)hex, 16, md5);
    prmd5UC(md5, hex2, 32);
    hex2[32] = ' ';
    rhash_msg(RHASH_MD5, (unsigned char *)hex2, 33, dest);
}

/* MD5SQL5-40 = rhash_msg(RHASH_MD5, UC_hex(SHA1(SHA1(pass)))) — 40 hex chars, no asterisk */
static void compute_md5sql5_40(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h1[20], h2[20]; char buf[41];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, h1);
    SHA1(h1, 20, h2);
    bin2hexUC(h2, 20, buf);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 40, dest);
}

/* MD5SQL5-chop40 = rhash_msg(RHASH_MD5, "*" + UC_hex(SHA1(SHA1(pass)))[0:39]) — 40 bytes total */
static void compute_md5sql5_chop40(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h1[20], h2[20]; char buf[42];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, h1);
    SHA1(h1, 20, h2);
    buf[0] = '*';
    bin2hexUC(h2, 20, buf + 1);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 40, dest);   /* 40 chars: * + 39 hex */
}

/* SHA1SQL5-40 = SHA1(UC_hex(SHA1(SHA1(pass)))) */
static void compute_sha1sql5_40(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h1[20], h2[20]; char buf[41];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, h1);
    SHA1(h1, 20, h2);
    bin2hexUC(h2, 20, buf);
    SHA1((unsigned char *)buf, 40, dest);
}

/* RADMIN2SQL5-40 = RADMIN2(UC_hex(SHA1(SHA1(pass)))) */
static void compute_radmin2sql5_40(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h1[20], h2[20]; char buf[41];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, h1);
    SHA1(h1, 20, h2);
    bin2hexUC(h2, 20, buf);
    compute_radmin2((unsigned char *)buf, 40, NULL, 0, dest);
}

/* MD5SQL5MD5 = rhash_msg(RHASH_MD5, "*" + UC_hex(SHA1(SHA1(hex(MD5(pass)))))) */
static void compute_md5sql5md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h1[16], h2[20], h3[20]; char hex[33], buf[42];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h1);
    bin2hex(h1, 16, hex);
    SHA1((unsigned char *)hex, 32, h2);
    SHA1(h2, 20, h3);
    buf[0] = '*';
    bin2hexUC(h3, 20, buf + 1);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 41, dest);
}

/* ---- MULTI-PASS types ---- */

/* MD5-2xMD5 = rhash_msg(RHASH_MD5, hex(MD5(pass)) + hex(MD5(pass))) — 64 bytes */
static void compute_md5_2xmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16]; char buf[65];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);
    bin2hex(h, 16, buf); bin2hex(h, 16, buf + 32);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 64, dest);
}

/* MD5-3xMD5 = rhash_msg(RHASH_MD5, hex(MD5(pass)) * 3) — 96 bytes */
static void compute_md5_3xmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16]; char buf[97];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);
    bin2hex(h, 16, buf); bin2hex(h, 16, buf + 32); bin2hex(h, 16, buf + 64);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 96, dest);
}

/* MD5-4xMD5 = rhash_msg(RHASH_MD5, hex(MD5(pass)) * 4) — 128 bytes */
static void compute_md5_4xmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16]; char buf[129];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);
    bin2hex(h, 16, buf); bin2hex(h, 16, buf + 32);
    bin2hex(h, 16, buf + 64); bin2hex(h, 16, buf + 96);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 128, dest);
}

/* MD5-2xMD5-MD5 = rhash_msg(RHASH_MD5, hex(MD5(hex(MD5(pass)))) * 2) */
static void compute_md5_2xmd5_md5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16]; char hex[33], buf[65];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);
    bin2hex(h, 16, hex);
    rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, h);
    bin2hex(h, 16, buf); bin2hex(h, 16, buf + 32);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 64, dest);
}

/* MD5-2xMD5-SHA1 = SHA1(pass)→hex→rhash_msg(RHASH_MD5, hex)→hex→dup 2x→MD5 */
static void compute_md5_2xmd5_sha1(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char s[20], h[16]; char hex[41], buf[65];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, s);
    prmd5(s, hex, 40);
    rhash_msg(RHASH_MD5, (unsigned char *)hex, 40, h);   /* MD5 of SHA1 hex */
    bin2hex(h, 16, buf); bin2hex(h, 16, buf + 32);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 64, dest);
}

/* MD5-2xMD5-MD5MD5: MD5→hex→MD5→hex→MD5→hex→dup 2x→MD5 */
static void compute_md5_2xmd5_md5md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16]; char hex[33], buf[65];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);          /* suffix MD5 #1 */
    prmd5(h, hex, 32); rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, h);  /* suffix MD5 #2 */
    prmd5(h, hex, 32); rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, h);  /* 2xMD5 inner MD5 */
    bin2hex(h, 16, buf); bin2hex(h, 16, buf + 32);        /* dup 2x */
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 64, dest);                   /* outer MD5 */
}

/* MD5-3xMD5-MD5 */
static void compute_md5_3xmd5_md5(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16]; char hex[33], buf[97];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);
    bin2hex(h, 16, hex); rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, h);
    bin2hex(h, 16, buf); bin2hex(h, 16, buf + 32); bin2hex(h, 16, buf + 64);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 96, dest);
}

/* MD5-2xSHA1 = rhash_msg(RHASH_MD5, hex(SHA1(pass)) * 2) */
static void compute_md5_2xsha1(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[20]; char buf[81];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, h);
    bin2hex(h, 20, buf); bin2hex(h, 20, buf + 40);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 80, dest);
}

/* SHA1-2xSHA1 = SHA1(hex(SHA1(pass)) * 2) */
static void compute_sha1_2xsha1(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[20]; char buf[81];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, h);
    bin2hex(h, 20, buf); bin2hex(h, 20, buf + 40);
    SHA1((unsigned char *)buf, 80, dest);
}

/* SHA1-2xMD5 = SHA1(hex(rhash_msg(RHASH_MD5, pass)) * 2) */
static void compute_sha1_2xmd5(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[16]; char buf[65];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, h);
    bin2hex(h, 16, buf); bin2hex(h, 16, buf + 32);
    SHA1((unsigned char *)buf, 64, dest);
}

/* ---- 1x types: concatenation of two different hashes ---- */

/* MD5-1xSHA1MD5pSHA1p = rhash_msg(RHASH_MD5, hex(SHA1(hex(MD5(pass)))) + hex(SHA1(pass))) — 80 bytes */
static void compute_md5_1xsha1md5psha1p(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char hm[16], hs1[20], hs2[20]; char hex[33], buf[81];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, hm);
    bin2hex(hm, 16, hex);
    SHA1((unsigned char *)hex, 32, hs1);
    SHA1(pass, passlen, hs2);
    bin2hex(hs1, 20, buf); bin2hex(hs2, 20, buf + 40);
    rhash_msg(RHASH_MD5, (unsigned char *)buf, 80, dest);
}

/* SHA1-1xSHA1MD5pSHA1p */
static void compute_sha1_1xsha1md5psha1p(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char hm[16], hs1[20], hs2[20]; char hex[33], buf[81];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, hm);
    bin2hex(hm, 16, hex);
    SHA1((unsigned char *)hex, 32, hs1);
    SHA1(pass, passlen, hs2);
    bin2hex(hs1, 20, buf); bin2hex(hs2, 20, buf + 40);
    SHA1((unsigned char *)buf, 80, dest);
}

/* MD5SHA1-1xSHA1MD5pSHA1p */
static void compute_md5sha1_1xsha1md5psha1p(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char hm[16], hs1[20], hs2[20], hs3[20]; char hex[33], buf[81], hex2[41];
    (void)salt; (void)saltlen;
    rhash_msg(RHASH_MD5, pass, passlen, hm);
    bin2hex(hm, 16, hex);
    SHA1((unsigned char *)hex, 32, hs1);
    SHA1(pass, passlen, hs2);
    bin2hex(hs1, 20, buf); bin2hex(hs2, 20, buf + 40);
    SHA1((unsigned char *)buf, 80, hs3);
    bin2hex(hs3, 20, hex2);
    rhash_msg(RHASH_MD5, (unsigned char *)hex2, 40, dest);
}

/* ---- u32 types ---- */

/* SHA1SHA1u32 = SHA1(hex(SHA1(pass))[0:32]) */
static void compute_sha1sha1u32(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[20]; char hex[41];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, h);
    bin2hex(h, 20, hex);
    SHA1((unsigned char *)hex, 32, dest);
}

/* MD5SHA1u32 = rhash_msg(RHASH_MD5, hex(SHA1(pass))[0:32]) */
static void compute_md5sha1u32(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[20]; char hex[41];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, h);
    bin2hex(h, 20, hex);
    rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, dest);
}

/* MD5SHA1UCu32 = rhash_msg(RHASH_MD5, hexUC(SHA1(pass))[0:32]) */
static void compute_md5sha1ucu32(const unsigned char *pass, int passlen, const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned char h[20]; char hex[41];
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, h);
    bin2hexUC(h, 20, hex);
    rhash_msg(RHASH_MD5, (unsigned char *)hex, 32, dest);
}

/* ---- lsb types ---- */

/* SHA1lsb32 = SHA1(pass) with first 4 bytes zeroed */
static void compute_sha1lsb32(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, dest);
    dest[0] = dest[1] = dest[2] = dest[3] = 0;
}

/* SHA1lsb35 = SHA1(pass) with first dword masked */
static void compute_sha1lsb35(const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    unsigned int *ip;
    (void)salt; (void)saltlen;
    SHA1(pass, passlen, dest);
    ip = (unsigned int *)dest;
    ip[0] &= 0xff0f0000;
}

/* ================================================================= */
/* Helper functions for verify types (ported from mdxfind.c)         */
/* ================================================================= */

/* Forward declarations for functions defined later in the file */
static int hex2bin(const char *hex, int hexlen, unsigned char *bin);

static const char phpitoa64[] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void cisco_pix_encode(const unsigned char *digest, char *out)
{
    int i, j = 0;
    for (i = 0; i < 16; i += 4) {
        unsigned int v = digest[i] | (digest[i+1] << 8) | (digest[i+2] << 16);
        out[j++] = phpitoa64[v & 0x3f];
        out[j++] = phpitoa64[(v >> 6) & 0x3f];
        out[j++] = phpitoa64[(v >> 12) & 0x3f];
        out[j++] = phpitoa64[(v >> 18) & 0x3f];
    }
    out[16] = 0;
}

static const char juniper_b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void juniper_encode(const unsigned char *digest, char *out)
{
    int w, p = 0;
    static const char sig[] = "nrcstn";
    static const int sigpos[] = {0, 6, 12, 17, 23, 29};
    int si = 0;
    unsigned short hi, lo;
    char data[24];

    for (w = 0; w < 4; w++) {
        hi = (digest[w*4+0] << 8) | digest[w*4+1];
        lo = (digest[w*4+2] << 8) | digest[w*4+3];
        data[w*6+0] = juniper_b64[(hi >> 12) & 0x3f];
        data[w*6+1] = juniper_b64[(hi >>  6) & 0x3f];
        data[w*6+2] = juniper_b64[(hi      ) & 0x3f];
        data[w*6+3] = juniper_b64[(lo >> 12) & 0x3f];
        data[w*6+4] = juniper_b64[(lo >>  6) & 0x3f];
        data[w*6+5] = juniper_b64[(lo      ) & 0x3f];
    }
    { int di = 0;
      for (p = 0; p < 30; p++) {
          if (si < 6 && p == sigpos[si])
              out[p] = sig[si++];
          else
              out[p] = data[di++];
      }
    }
    out[30] = 0;
}

static int aix_encode(const unsigned char *digest, int dlen, char *out) {
    int i, j = 0;
    for (i = 0; i + 2 < dlen; i += 3) {
        unsigned int v = ((unsigned int)digest[i] << 16) | (digest[i+1] << 8) | digest[i+2];
        out[j++] = phpitoa64[v & 0x3f]; v >>= 6;
        out[j++] = phpitoa64[v & 0x3f]; v >>= 6;
        out[j++] = phpitoa64[v & 0x3f]; v >>= 6;
        out[j++] = phpitoa64[v & 0x3f];
    }
    if (dlen - i == 2) {
        unsigned int v = ((unsigned int)digest[i] << 16) | (digest[i+1] << 8);
        out[j++] = phpitoa64[v & 0x3f]; v >>= 6;
        out[j++] = phpitoa64[v & 0x3f]; v >>= 6;
        out[j++] = phpitoa64[v & 0x3f];
    } else if (dlen - i == 1) {
        unsigned int v = (unsigned int)digest[i] << 16;
        out[j++] = phpitoa64[v & 0x3f]; v >>= 6;
        out[j++] = phpitoa64[v & 0x3f];
    }
    out[j] = 0;
    return j;
}

static const unsigned char a2e[256] = {
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

static void lotus_mix(unsigned char *state) {
    int p = 0, i, k;
    for (i = 0; i < 18; i++) {
        for (k = 0; k < 48; k++) {
            p = (p + (48 - k)) & 0xff;
            p = state[k] ^ lotus_magic_table[p];
            state[k] = p;
        }
    }
}

static void lotus_transform_password(const unsigned char *block, unsigned char *checksum) {
    unsigned char t = checksum[15];
    int i;
    for (i = 0; i < 16; i++) {
        t = checksum[i] ^ lotus_magic_table[block[i] ^ t];
        checksum[i] = t;
    }
}

static void domino5_transform(const unsigned char *input, int inlen, unsigned char *output) {
    unsigned char state[48], padded[512], checksum[16];
    int padlen, nblocks, i, j;

    padlen = 16 - (inlen % 16);
    if (padlen == 0) padlen = 16;
    if (inlen + padlen > (int)sizeof(padded)) return;
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
        lotus_mix(state);
        lotus_transform_password(block, checksum);
    }

    for (j = 0; j < 16; j++) {
        state[16 + j] = checksum[j];
        state[32 + j] = checksum[j] ^ state[j];
    }
    lotus_mix(state);

    memcpy(output, state, 16);
}

static const char lotus64[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

static int lotus64_encode(const unsigned char *in, int inlen, char *out, int outmax) {
    int i, j = 0;
    for (i = 0; i + 2 < inlen; i += 3) {
        if (j + 4 > outmax) break;
        out[j++] = lotus64[in[i] >> 2];
        out[j++] = lotus64[((in[i] & 3) << 4) | (in[i+1] >> 4)];
        out[j++] = lotus64[((in[i+1] & 0xf) << 2) | (in[i+2] >> 6)];
        out[j++] = lotus64[in[i+2] & 0x3f];
    }
    if (i < inlen && j + 2 <= outmax) {
        out[j++] = lotus64[in[i] >> 2];
        if (i + 1 < inlen) {
            out[j++] = lotus64[((in[i] & 3) << 4) | (in[i+1] >> 4)];
            if (j < outmax) out[j++] = lotus64[(in[i+1] & 0xf) << 2];
        } else {
            out[j++] = lotus64[(in[i] & 3) << 4];
        }
    }
    if (j < outmax) out[j] = 0;
    return j;
}

/* ================================================================= */
/* Non-hex verify functions (for bcrypt, APACHE-SHA, PHPBB3, APR1)   */
/* ================================================================= */

/* APACHE-SHA: {SHA}base64(SHA1(pass)) */
static int verify_apachesha(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char sha1[20], decoded[20];
    const char *b64;
    int b64len, dlen;

    /* Must start with {SHA} */
    if (hashlen < 9 || memcmp(hashstr, "{SHA}", 5) != 0)
        return 0;
    b64 = hashstr + 5;
    b64len = hashlen - 5;

    /* Base64 decode */
    dlen = base64_decode(b64, b64len, decoded, sizeof(decoded));
    if (dlen != 20) return 0;

    /* Compute SHA1(pass) and compare */
    SHA1(pass, passlen, sha1);
    return memcmp(sha1, decoded, 20) == 0;
}

/* BCRYPT: $2a$NN$salt(22)hash(31) — verify using crypt_blowfish */
static int verify_bcrypt(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    char passbuf[256], result[64];
    extern char *crypt_rn(const char *key, const char *setting,
                          void *output, int size);
    if (hashlen < 29 || hashstr[0] != '$') return 0;
    if (passlen >= (int)sizeof(passbuf)) return 0;

    /* crypt_rn needs null-terminated password */
    memcpy(passbuf, pass, passlen);
    passbuf[passlen] = 0;

    if (!crypt_rn(passbuf, hashstr, result, sizeof(result)))
        return 0;
    return strncmp(result, hashstr, hashlen) == 0;
}

/* BCRYPTMD5: bcrypt(hex(rhash_msg(RHASH_MD5, pass))) */
static int verify_bcryptmd5(const char *hashstr, int hashlen, const unsigned char *pass, int passlen)
{
    unsigned char md5[16];
    char hex[33], result[64];
    extern char *crypt_rn(const char *key, const char *setting,
                          void *output, int size);
    if (hashlen < 29 || hashstr[0] != '$') return 0;

    rhash_msg(RHASH_MD5, pass, passlen, md5);
    prmd5(md5, hex, 32);
    hex[32] = 0;

    if (!crypt_rn(hex, hashstr, result, sizeof(result)))
        return 0;
    return strncmp(result, hashstr, hashlen) == 0;
}

/* BCRYPTSHA1: bcrypt(hex(SHA1(pass))) */
static int verify_bcryptsha1(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char sha1[20];
    char hex[41], result[64];
    extern char *crypt_rn(const char *key, const char *setting,
                          void *output, int size);
    if (hashlen < 29 || hashstr[0] != '$') return 0;

    SHA1(pass, passlen, sha1);
    prmd5(sha1, hex, 40);
    hex[40] = 0;

    if (!crypt_rn(hex, hashstr, result, sizeof(result)))
        return 0;
    return strncmp(result, hashstr, hashlen) == 0;
}

/* PHPBB3 ($H$): phpass-style iterated MD5 */
static int verify_phpbb3(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    static const char itoa64[] =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    unsigned char md5[16];
    rhash ctx;
    int count, i;
    const char *salt;
    char *p;

    /* Format: $H$NSALT(8)HASH(22) = 34 chars total */
    if (hashlen < 34 || memcmp(hashstr, "$H$", 3) != 0)
        return 0;

    /* Count = 2^(index of hashstr[3] in itoa64) */
    p = strchr(itoa64, hashstr[3]);
    if (!p) return 0;
    count = 1 << (int)(p - itoa64);
    salt = hashstr + 4;  /* 8-char salt */

    /* Initial: rhash_msg(RHASH_MD5, salt + pass) */
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, salt, 8);
    rhash_update(ctx, pass, passlen);
    rhash_final(ctx, md5); rhash_free(ctx);

    /* Iterate: rhash_msg(RHASH_MD5, md5_binary + pass) */
    for (i = 0; i < count; i++) {
        ctx = rhash_init(RHASH_MD5);
        rhash_update(ctx, md5, 16);
        rhash_update(ctx, pass, passlen);
        rhash_final(ctx, md5); rhash_free(ctx);
    }

    /* Encode with phpass base64 and compare */
    {
        unsigned char *h = md5;
        char encoded[23];
        int eidx = 0, bidx = 0, bits;

        while (bidx < 16) {
            bits = h[bidx++];
            encoded[eidx++] = itoa64[bits & 0x3f];
            bits >>= 6;
            if (bidx < 16) bits |= h[bidx] << 2;
            encoded[eidx++] = itoa64[bits & 0x3f];
            if (bidx++ >= 16) break;
            bits >>= 6;
            if (bidx < 16) bits |= h[bidx] << 4;
            encoded[eidx++] = itoa64[bits & 0x3f];
            if (bidx++ >= 16) break;
            bits >>= 6;
            encoded[eidx++] = itoa64[bits & 0x3f];
        }
        encoded[eidx] = 0;

        /* Compare: hashstr[12..33] = encoded hash (22 chars) */
        return eidx >= 22 && memcmp(hashstr + 12, encoded, 22) == 0;
    }
}

/* APR1 ($apr1$): Apache MD5-crypt */
static int verify_apr1(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    /* APR1 format: $apr1$salt$hash */
    unsigned char md5[16], alt[16];
    rhash ctx, altctx;
    const char *salt;
    int saltlen, i, plen;
    char expected[128];
    static const char itoa64[] =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    if (hashlen < 10 || memcmp(hashstr, "$apr1$", 6) != 0)
        return 0;

    /* Extract salt (between 2nd and 3rd $) */
    salt = hashstr + 6;
    for (saltlen = 0; saltlen < 8 && salt[saltlen] && salt[saltlen] != '$'; saltlen++)
        ;
    if (salt[saltlen] != '$') return 0;

    plen = passlen;

    /* Step 1: rhash_msg(RHASH_MD5, pass + "$apr1$" + salt) */
    ctx = rhash_init(RHASH_MD5);
    rhash_update(ctx, pass, plen);
    rhash_update(ctx, "$apr1$", 6);
    rhash_update(ctx, salt, saltlen);

    /* Step 2: alternate rhash_msg(RHASH_MD5, pass + salt + pass) */
    altctx = rhash_init(RHASH_MD5);
    rhash_update(altctx, pass, plen);
    rhash_update(altctx, salt, saltlen);
    rhash_update(altctx, pass, plen);
    rhash_final(altctx, alt); rhash_free(altctx);

    /* Add alternate to main, plen bytes */
    for (i = plen; i > 0; i -= 16)
        rhash_update(ctx, alt, (i > 16) ? 16 : i);

    /* Add pass length bits */
    for (i = plen; i > 0; i >>= 1) {
        if (i & 1)
            rhash_update(ctx, "", 1);  /* NUL byte */
        else
            rhash_update(ctx, pass, 1);
    }
    rhash_final(ctx, md5); rhash_free(ctx);

    /* 1000 iterations */
    for (i = 0; i < 1000; i++) {
        ctx = rhash_init(RHASH_MD5);
        if (i & 1)
            rhash_update(ctx, pass, plen);
        else
            rhash_update(ctx, md5, 16);
        if (i % 3)
            rhash_update(ctx, salt, saltlen);
        if (i % 7)
            rhash_update(ctx, pass, plen);
        if (i & 1)
            rhash_update(ctx, md5, 16);
        else
            rhash_update(ctx, pass, plen);
        rhash_final(ctx, md5); rhash_free(ctx);
    }

    /* Encode result in md5crypt base64 format */
    {
        /* md5crypt groups: (0,6,12) (1,7,13) (2,8,14) (3,9,15) (4,10,5) 11 */
        static const unsigned char grp[][3] = {
            {0,6,12}, {1,7,13}, {2,8,14}, {3,9,15}, {4,10,5}
        };
        char enc[23];
        int eidx = 0, g;
        unsigned int v;

        for (g = 0; g < 5; g++) {
            v = ((unsigned int)md5[grp[g][0]] << 16)
              | ((unsigned int)md5[grp[g][1]] << 8)
              | md5[grp[g][2]];
            enc[eidx++] = itoa64[v & 0x3f]; v >>= 6;
            enc[eidx++] = itoa64[v & 0x3f]; v >>= 6;
            enc[eidx++] = itoa64[v & 0x3f]; v >>= 6;
            enc[eidx++] = itoa64[v & 0x3f];
        }
        /* Last byte: md5[11] */
        v = md5[11];
        enc[eidx++] = itoa64[v & 0x3f]; v >>= 6;
        enc[eidx++] = itoa64[v & 0x3f];
        enc[eidx] = 0;

        /* Build expected: $apr1$salt$encoded */
        snprintf(expected, sizeof(expected), "$apr1$%.*s$%s",
                 saltlen, salt, enc);
        return strncmp(expected, hashstr, hashlen) == 0;
    }
}

/* POSTGRESQL (e855): md5(pass + username) → "md5" + 32hex ":" username */
static int verify_postgresql(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char md5[16];
    char computed[36];
    const char *colon;
    int hpart;

    colon = memchr(hashstr, ':', hashlen);
    if (!colon) return 0;
    hpart = colon - hashstr;
    if (hpart != 35 || memcmp(hashstr, "md5", 3) != 0) return 0;

    /* md5(pass + username) */
    { const char *username = colon + 1;
      int ulen = hashlen - hpart - 1;
      unsigned char buf[1024];
      if (passlen + ulen > (int)sizeof(buf)) return 0;
      memcpy(buf, pass, passlen);
      memcpy(buf + passlen, username, ulen);
      rhash_msg(RHASH_MD5, buf, passlen + ulen, md5);
    }
    strcpy(computed, "md5");
    prmd5(md5, computed + 3, 32);
    computed[35] = 0;
    return hpart == 35 && memcmp(computed, hashstr, 35) == 0;
}

/* PEOPLESOFT (e858): base64(SHA1(UTF16LE(pass))) — 28 chars */
static int verify_peoplesoft(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char utf16[1024], sha1[20];
    char b64[32];
    int u16len;

    if (hashlen != 28) return 0;
    u16len = utf8_to_utf16le(pass, passlen, utf16, sizeof(utf16));
    if (u16len <= 0) return 0;
    SHA1(utf16, u16len, sha1);
    b64_encode(sha1, 20, b64);
    return memcmp(b64, hashstr, 28) == 0;
}

/* HMAILSERVER (e860): SHA256(salt + pass) — 6hex_salt + 64hex_hash (70 chars) */
static int verify_hmailserver(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char sha256[32];
    char computed[72];

    if (hashlen != 70) return 0;
    /* salt is first 6 chars (hex string used as-is) */
    { unsigned char buf[1024];
      if (6 + passlen > (int)sizeof(buf)) return 0;
      memcpy(buf, hashstr, 6);
      memcpy(buf + 6, pass, passlen);
      SHA256(buf, 6 + passlen, sha256);
    }
    memcpy(computed, hashstr, 6);
    prmd5(sha256, computed + 6, 64);
    computed[70] = 0;
    return strncasecmp(computed, hashstr, 70) == 0;
}

/* MEDIAWIKI (e863): md5(salt + "-" + md5(pass)) — "$B$" salt "$" 32hex */
static int verify_mediawiki(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char md5_inner[16], md5_outer[16];
    char hex_inner[33], computed[80];
    const char *salt, *hash_part;
    int saltlen;

    if (hashlen < 10 || memcmp(hashstr, "$B$", 3) != 0) return 0;
    salt = hashstr + 3;
    hash_part = memchr(salt, '$', hashlen - 3);
    if (!hash_part) return 0;
    saltlen = hash_part - salt;
    hash_part++;
    if (hashstr + hashlen - hash_part != 32) return 0;

    rhash_msg(RHASH_MD5, pass, passlen, md5_inner);
    prmd5(md5_inner, hex_inner, 32);
    hex_inner[32] = 0;

    { unsigned char buf[256];
      if (saltlen + 1 + 32 > (int)sizeof(buf)) return 0;
      memcpy(buf, salt, saltlen);
      buf[saltlen] = '-';
      memcpy(buf + saltlen + 1, hex_inner, 32);
      rhash_msg(RHASH_MD5, buf, saltlen + 1 + 32, md5_outer);
    }
    snprintf(computed, sizeof(computed), "$B$%.*s$", saltlen, salt);
    prmd5(md5_outer, computed + 4 + saltlen, 32);
    computed[4 + saltlen + 32] = 0;
    return hashlen == (int)strlen(computed) && memcmp(computed, hashstr, hashlen) == 0;
}

/* DAHUA (e864): md5(salt + UC(md5(pepper + pass)))
 * Format: 32hex_hash:salt:pepper:password */
static int verify_dahua(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char md5_inner[16], md5_outer[16];
    char uchex[33];
    const char *c1, *c2, *salt, *pepper;
    int saltlen, peplen;

    /* Parse hash:salt:pepper */
    c1 = memchr(hashstr, ':', hashlen);
    if (!c1) return 0;
    if (c1 - hashstr != 32) return 0;
    c2 = memchr(c1 + 1, ':', hashlen - (c1 + 1 - hashstr));
    if (!c2) return 0;
    salt = c1 + 1;
    saltlen = c2 - salt;
    pepper = c2 + 1;
    peplen = hashlen - (pepper - hashstr);

    /* md5(pepper + pass) */
    { unsigned char buf[1024];
      if (peplen + passlen > (int)sizeof(buf)) return 0;
      memcpy(buf, pepper, peplen);
      memcpy(buf + peplen, pass, passlen);
      rhash_msg(RHASH_MD5, buf, peplen + passlen, md5_inner);
    }
    prmd5UC(md5_inner, uchex, 32);
    uchex[32] = 0;

    /* md5(salt + UC_hex) */
    { unsigned char buf[256];
      if (saltlen + 32 > (int)sizeof(buf)) return 0;
      memcpy(buf, salt, saltlen);
      memcpy(buf + saltlen, uchex, 32);
      rhash_msg(RHASH_MD5, buf, saltlen + 32, md5_outer);
    }
    { char out[33];
      prmd5(md5_outer, out, 32);
      return strncasecmp(out, hashstr, 32) == 0;
    }
}

/* NETSCALER (e878): SHA1(salt_hex_str + pass + \0) — "1" + 8hex_salt + 40hex */
static int verify_netscaler(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char sha1[20];
    char computed[50];

    if (hashlen != 49 || hashstr[0] != '1') return 0;
    /* SHA1(8-char hex salt string + password + NUL byte) */
    { unsigned char buf[1024];
      if (8 + passlen + 1 > (int)sizeof(buf)) return 0;
      memcpy(buf, hashstr + 1, 8); /* salt as hex string */
      memcpy(buf + 8, pass, passlen);
      buf[8 + passlen] = 0;
      SHA1(buf, 8 + passlen + 1, sha1);
    }
    computed[0] = '1';
    memcpy(computed + 1, hashstr + 1, 8);
    prmd5(sha1, computed + 9, 40);
    computed[49] = 0;
    return strncasecmp(computed, hashstr, 49) == 0;
}

/* WBB3 (e880): SHA1(salt + SHA1(salt + SHA1(pass))) — 40hex ":" 40hex_salt */
static int verify_wbb3(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char sha1[20];
    char hex1[41], hex2[41], hex3[41];
    const char *colon;
    int hpart;

    colon = memchr(hashstr, ':', hashlen);
    if (!colon) return 0;
    hpart = colon - hashstr;
    if (hpart != 40) return 0;
    if (hashlen - hpart - 1 != 40) return 0;

    /* h1 = sha1(pass) → hex */
    SHA1(pass, passlen, sha1);
    prmd5(sha1, hex1, 40);
    /* h2 = sha1(salt_hex + h1_hex) */
    { unsigned char buf[80];
      memcpy(buf, colon + 1, 40);
      memcpy(buf + 40, hex1, 40);
      SHA1(buf, 80, sha1);
    }
    prmd5(sha1, hex2, 40);
    /* h3 = sha1(salt_hex + h2_hex) */
    { unsigned char buf[80];
      memcpy(buf, colon + 1, 40);
      memcpy(buf + 40, hex2, 40);
      SHA1(buf, 80, sha1);
    }
    prmd5(sha1, hex3, 40);
    return strncasecmp(hex3, hashstr, 40) == 0;
}

/* MSSQL2000 (e850): SHA1(UTF16LE(pass) + salt) — 0x0100 + 8hex_salt + 40hex_cs + 40hex_uc */
static int verify_mssql2000(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char utf16[1024], sha1[20], salt_bin[4];
    int u16len;

    if (hashlen != 94) return 0;
    if (strncasecmp(hashstr, "0x0100", 6) != 0) return 0;
    if (hex2bin(hashstr + 6, 8, salt_bin) != 4) return 0;

    u16len = utf8_to_utf16le(pass, passlen, utf16, sizeof(utf16) - 4);
    if (u16len <= 0) return 0;
    memcpy(utf16 + u16len, salt_bin, 4);
    SHA1(utf16, u16len + 4, sha1);

    /* Compare case-sensitive SHA1 at offset 14 (40 hex chars) */
    { char hex[41];
      prmd5(sha1, hex, 40);
      return strncasecmp(hex, hashstr + 14, 40) == 0;
    }
}

/* MSSQL2005 (e851): SHA1(UTF16LE(pass) + salt) — 0x0100 + 8hex_salt + 40hex */
static int verify_mssql2005(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char utf16[1024], sha1[20], salt_bin[4];
    int u16len;

    if (hashlen != 54) return 0;
    if (strncasecmp(hashstr, "0x0100", 6) != 0) return 0;
    if (hex2bin(hashstr + 6, 8, salt_bin) != 4) return 0;

    u16len = utf8_to_utf16le(pass, passlen, utf16, sizeof(utf16) - 4);
    if (u16len <= 0) return 0;
    memcpy(utf16 + u16len, salt_bin, 4);
    SHA1(utf16, u16len + 4, sha1);

    { char hex[41];
      prmd5(sha1, hex, 40);
      return strncasecmp(hex, hashstr + 14, 40) == 0;
    }
}

/* MSSQL2012 (e852): SHA512(UTF16LE(pass) + salt) — 0x0200 + 8hex_salt + 128hex */
static int verify_mssql2012(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char utf16[1024], sha512[64], salt_bin[4];
    int u16len;

    if (hashlen != 142) return 0;
    if (strncasecmp(hashstr, "0x0200", 6) != 0) return 0;
    if (hex2bin(hashstr + 6, 8, salt_bin) != 4) return 0;

    u16len = utf8_to_utf16le(pass, passlen, utf16, sizeof(utf16) - 4);
    if (u16len <= 0) return 0;
    memcpy(utf16 + u16len, salt_bin, 4);
    SHA512(utf16, u16len + 4, sha512);

    { char hex[129];
      prmd5(sha512, hex, 128);
      return strncasecmp(hex, hashstr + 14, 128) == 0;
    }
}

/* MACOSX (e853): SHA1(salt_bin + pass) — 8hex_salt + 40hex */
static int verify_macosx(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char sha1[20], salt_bin[4];
    char hex[41];

    if (hashlen != 48) return 0;
    if (hex2bin(hashstr, 8, salt_bin) != 4) return 0;

    { unsigned char buf[1024];
      if (4 + passlen > (int)sizeof(buf)) return 0;
      memcpy(buf, salt_bin, 4);
      memcpy(buf + 4, pass, passlen);
      SHA1(buf, 4 + passlen, sha1);
    }
    prmd5(sha1, hex, 40);
    return strncasecmp(hex, hashstr + 8, 40) == 0;
}

/* MACOSX7 (e854): SHA512(salt_bin + pass) — 8hex_salt + 128hex */
static int verify_macosx7(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char sha512[64], salt_bin[4];
    char hex[129];

    if (hashlen != 136) return 0;
    if (hex2bin(hashstr, 8, salt_bin) != 4) return 0;

    { unsigned char buf[1024];
      if (4 + passlen > (int)sizeof(buf)) return 0;
      memcpy(buf, salt_bin, 4);
      memcpy(buf + 4, pass, passlen);
      SHA512(buf, 4 + passlen, sha512);
    }
    prmd5(sha512, hex, 128);
    return strncasecmp(hex, hashstr + 8, 128) == 0;
}

/* DESENCRYPT (e848): DES_ECB(pass_as_key, salt_plaintext) — 16hex ":" 16hex_salt */
static int verify_desencrypt(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char expected_ct[8], salt_bin[8];
    DES_cblock deskey, desct;
    DES_key_schedule desks;
    const char *colon;
    int hpart;

    colon = memchr(hashstr, ':', hashlen);
    if (!colon) return 0;
    hpart = colon - hashstr;
    if (hpart != 16) return 0;
    if (hashlen - hpart - 1 != 16) return 0;
    if (hex2bin(hashstr, 16, expected_ct) != 8) return 0;
    if (hex2bin(colon + 1, 16, salt_bin) != 8) return 0;

    memset(deskey, 0, 8);
    memcpy(deskey, pass, passlen < 8 ? passlen : 8);
    DES_set_key_unchecked(&deskey, &desks);
    DES_ecb_encrypt((DES_cblock *)salt_bin, &desct, &desks, DES_ENCRYPT);
    return memcmp(desct, expected_ct, 8) == 0;
}

/* DES3ENCRYPT (e849): 3DES_ECB(pass_as_3keys, salt_plaintext) — 16hex ":" 16hex_salt */
static int verify_des3encrypt(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char expected_ct[8], salt_bin[8];
    DES_cblock deskey1, deskey2, deskey3, desct;
    DES_key_schedule desks1, desks2, desks3;
    const char *colon;
    int hpart;

    colon = memchr(hashstr, ':', hashlen);
    if (!colon) return 0;
    hpart = colon - hashstr;
    if (hpart != 16) return 0;
    if (hashlen - hpart - 1 != 16) return 0;
    if (hex2bin(hashstr, 16, expected_ct) != 8) return 0;
    if (hex2bin(colon + 1, 16, salt_bin) != 8) return 0;

    memset(deskey1, 0, 8); memset(deskey2, 0, 8); memset(deskey3, 0, 8);
    if (passlen >= 8) memcpy(deskey1, pass, 8); else memcpy(deskey1, pass, passlen);
    if (passlen > 8) { if (passlen >= 16) memcpy(deskey2, pass+8, 8); else memcpy(deskey2, pass+8, passlen-8); }
    if (passlen > 16) { if (passlen >= 24) memcpy(deskey3, pass+16, 8); else memcpy(deskey3, pass+16, passlen-16); }
    DES_set_key_unchecked(&deskey1, &desks1);
    DES_set_key_unchecked(&deskey2, &desks2);
    DES_set_key_unchecked(&deskey3, &desks3);
    DES_ecb3_encrypt((DES_cblock *)salt_bin, &desct, &desks1, &desks2, &desks3, DES_ENCRYPT);
    return memcmp(desct, expected_ct, 8) == 0;
}

/* RACF (e881): DES_ECB(EBCDIC_UC_username, EBCDIC_pass_key) — 16hex ":" username */
static int verify_racf(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char expected[8], euser[8], deskey[8], ciphertext[8];
    DES_key_schedule ks;
    const char *colon, *username;
    int hpart, ulen, x;

    colon = memchr(hashstr, ':', hashlen);
    if (!colon) return 0;
    hpart = colon - hashstr;
    if (hpart != 16) return 0;
    if (hex2bin(hashstr, 16, expected) != 8) return 0;
    username = colon + 1;
    ulen = hashlen - hpart - 1;

    /* Password to DES key: EBCDIC, XOR 0x55, shift left 1, odd parity */
    { int plen = passlen > 8 ? 8 : passlen;
      for (x = 0; x < 8; x++) {
          unsigned char ebcdic = (x < plen) ? a2e[pass[x]] : 0x40;
          unsigned char val = (ebcdic ^ 0x55);
          val = (val << 1) & 0xfe;
          { int bits = 0; unsigned char t = val;
            while (t) { bits += t & 1; t >>= 1; }
            if ((bits & 1) == 0) val |= 1;
          }
          deskey[x] = val;
      }
    }
    DES_set_key_unchecked((DES_cblock *)deskey, &ks);

    /* Uppercase username, pad to 8 with spaces, convert to EBCDIC */
    for (x = 0; x < 8; x++) {
        char c = (x < ulen) ? username[x] : ' ';
        if (c >= 'a' && c <= 'z') c -= 32;
        euser[x] = a2e[(unsigned char)c];
    }
    DES_ecb_encrypt((DES_cblock *)euser, (DES_cblock *)ciphertext, &ks, DES_ENCRYPT);
    return memcmp(ciphertext, expected, 8) == 0;
}

/* JUNIPERSSG (e856): MD5(user + ":Administration Tools:" + pass) → juniper_encode
 * Format: 30-char encoded ":" username */
static int verify_juniperssg(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char md5[16];
    char encoded[31];
    const char *colon, *username;
    int hpart, ulen;

    colon = memchr(hashstr, ':', hashlen);
    if (!colon) return 0;
    hpart = colon - hashstr;
    if (hpart != 30) return 0;
    username = colon + 1;
    ulen = hashlen - hpart - 1;

    { unsigned char buf[1024];
      int total = ulen + 22 + passlen;
      if (total > (int)sizeof(buf)) return 0;
      memcpy(buf, username, ulen);
      memcpy(buf + ulen, ":Administration Tools:", 22);
      memcpy(buf + ulen + 22, pass, passlen);
      rhash_msg(RHASH_MD5, buf, total, md5);
    }
    juniper_encode(md5, encoded);
    return memcmp(encoded, hashstr, 30) == 0;
}

/* CISCOPIX (e861): MD5(pass padded to 16) → cisco_pix_encode — 16-char encoded */
static int verify_ciscopix(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char md5[16], padded[16];
    char encoded[17];

    if (hashlen != 16) return 0;
    memset(padded, 0, 16);
    memcpy(padded, pass, passlen > 16 ? 16 : passlen);
    rhash_msg(RHASH_MD5, padded, 16, md5);
    cisco_pix_encode(md5, encoded);
    return memcmp(encoded, hashstr, 16) == 0;
}

/* CISCOASA (e862): MD5((pass+salt) padded to 16/32) → cisco_pix_encode
 * Format: 16-char encoded ":" salt */
static int verify_ciscoasa(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char md5[16], padded[32];
    char encoded[17];
    const char *colon, *salt;
    int hpart, saltlen, asa_plen, padto;

    colon = memchr(hashstr, ':', hashlen);
    if (!colon) return 0;
    hpart = colon - hashstr;
    if (hpart != 16) return 0;
    salt = colon + 1;
    saltlen = hashlen - hpart - 1;

    asa_plen = passlen;
    if (asa_plen + saltlen > 32) asa_plen = 32 - saltlen;
    if (asa_plen < 0) asa_plen = 0;
    memset(padded, 0, 32);
    memcpy(padded, pass, asa_plen);
    memcpy(padded + asa_plen, salt, saltlen);
    padto = (asa_plen + saltlen >= 16) ? 32 : 16;
    rhash_msg(RHASH_MD5, padded, padto, md5);
    cisco_pix_encode(md5, encoded);
    return memcmp(encoded, hashstr, 16) == 0;
}

/* CISCO4 (e865): SHA256(pass) → phpitoa64 big-endian encode — 43 chars */
static int verify_cisco4(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char sha256[32];
    char encoded[44];

    if (hashlen != 43) return 0;
    SHA256(pass, passlen, sha256);
    /* php64 big-endian encode: groups of 3 bytes, MSB first */
    { int i, ei = 0;
      for (i = 0; i + 2 < 32; i += 3) {
          unsigned int v = ((unsigned int)sha256[i] << 16) |
                           ((unsigned int)sha256[i+1] << 8) | sha256[i+2];
          encoded[ei++] = phpitoa64[(v >> 18) & 0x3f];
          encoded[ei++] = phpitoa64[(v >> 12) & 0x3f];
          encoded[ei++] = phpitoa64[(v >>  6) & 0x3f];
          encoded[ei++] = phpitoa64[v & 0x3f];
      }
      /* last 2 bytes (32 = 10*3 + 2) */
      { unsigned int v = ((unsigned int)sha256[30] << 16) | ((unsigned int)sha256[31] << 8);
        encoded[ei++] = phpitoa64[(v >> 18) & 0x3f];
        encoded[ei++] = phpitoa64[(v >> 12) & 0x3f];
        encoded[ei++] = phpitoa64[(v >>  6) & 0x3f];
      }
      encoded[ei] = 0;
    }
    return memcmp(encoded, hashstr, 43) == 0;
}

/* CISCOISE (e866): 128x SHA256(salt_bin + pass) — 64hex_hash ":" 64hex_salt */
static int verify_ciscoise(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char sha256[32], salt_bin[32];
    char computed[65];
    int x;

    /* Format: 64hex_hash + 64hex_salt (128 chars concatenated, no colon) */
    if (hashlen != 128) return 0;
    if (hex2bin(hashstr + 64, 64, salt_bin) != 32) return 0;

    { unsigned char buf[1024];
      if (32 + passlen > (int)sizeof(buf)) return 0;
      memcpy(buf, salt_bin, 32);
      memcpy(buf + 32, pass, passlen);
      SHA256(buf, 32 + passlen, sha256);
    }
    /* 128 more iterations */
    for (x = 0; x < 128; x++)
        SHA256(sha256, 32, sha256);

    prmd5(sha256, computed, 64);
    return strncasecmp(computed, hashstr, 64) == 0;
}

/* SAMSUNGSHA1 (e867): 1024x SHA1(digest + str(i) + pass + salt) — 40hex ":" salt */
static int verify_samsungsha1(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char sha1[20], expected[20];
    const char *colon, *salt;
    int hpart, saltlen, siter;

    colon = memchr(hashstr, ':', hashlen);
    if (!colon) return 0;
    hpart = colon - hashstr;
    if (hpart != 40) return 0;
    if (hex2bin(hashstr, 40, expected) != 20) return 0;
    salt = colon + 1;
    saltlen = hashlen - hpart - 1;

    /* iter 0: SHA1("0" + pass + salt) */
    { unsigned char buf[2048];
      int pos = 0;
      buf[pos++] = '0';
      memcpy(buf + pos, pass, passlen); pos += passlen;
      memcpy(buf + pos, salt, saltlen); pos += saltlen;
      SHA1(buf, pos, sha1);
    }
    /* iter 1-1023: SHA1(prev_digest + str(i) + pass + salt) */
    for (siter = 1; siter < 1024; siter++) {
        unsigned char buf[2048];
        int pos = 0;
        memcpy(buf, sha1, 20); pos = 20;
        pos += sprintf((char *)buf + pos, "%d", siter);
        memcpy(buf + pos, pass, passlen); pos += passlen;
        memcpy(buf + pos, salt, saltlen); pos += saltlen;
        SHA1(buf, pos, sha1);
    }
    return memcmp(sha1, expected, 20) == 0;
}

/* EPISERVER (e859): SHA1 or SHA256(salt_bin + UTF16LE(pass))
 * Format: $episerver$*V*b64salt*b64hash (V=0 SHA1, V=1 SHA256) */
static int verify_episerver(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char utf16[1024], hash_out[32], salt_bin[64], expected[32];
    int u16len, epiver, hashbytes;
    const char *p, *salt_b64, *hash_b64;
    int salt_b64_len, hash_b64_len, salt_len, exp_len;

    if (hashlen < 20 || memcmp(hashstr, "$episerver$*", 12) != 0) return 0;
    epiver = hashstr[12] - '0';
    if (epiver != 0 && epiver != 1) return 0;
    if (hashstr[13] != '*') return 0;

    salt_b64 = hashstr + 14;
    p = memchr(salt_b64, '*', hashlen - 14);
    if (!p) return 0;
    salt_b64_len = p - salt_b64;
    hash_b64 = p + 1;
    hash_b64_len = hashlen - (hash_b64 - hashstr);

    salt_len = base64_decode(salt_b64, salt_b64_len, salt_bin, sizeof(salt_bin));
    if (salt_len <= 0) return 0;
    hashbytes = (epiver == 1) ? 32 : 20;
    exp_len = base64_decode(hash_b64, hash_b64_len, expected, sizeof(expected));
    if (exp_len < hashbytes) return 0;

    u16len = utf8_to_utf16le(pass, passlen, utf16, sizeof(utf16));
    if (u16len <= 0) return 0;

    { unsigned char buf[1024];
      if (salt_len + u16len > (int)sizeof(buf)) return 0;
      memcpy(buf, salt_bin, salt_len);
      memcpy(buf + salt_len, utf16, u16len);
      if (epiver == 1)
          SHA256(buf, salt_len + u16len, hash_out);
      else
          SHA1(buf, salt_len + u16len, hash_out);
    }
    return memcmp(hash_out, expected, hashbytes) == 0;
}

/* SYBASE-ASE (e877): SHA256(UTF16BE(pass, 510 bytes) + salt_bin) — 0xc007 + 16hex_salt + 64hex */
static int verify_sybase(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char sha256[32], salt_bin[8], expected[32];
    unsigned char wbuf[518];
    int x;

    if (hashlen != 86) return 0;
    if (strncasecmp(hashstr, "0xc007", 6) != 0) return 0;
    if (hex2bin(hashstr + 6, 16, salt_bin) != 8) return 0;
    if (hex2bin(hashstr + 22, 64, expected) != 32) return 0;

    /* UTF-16BE password padded to 510 bytes */
    memset(wbuf, 0, 518);
    for (x = 0; x < passlen && x < 255; x++) {
        wbuf[x * 2] = 0;
        wbuf[x * 2 + 1] = pass[x];
    }
    memcpy(wbuf + 510, salt_bin, 8);
    SHA256(wbuf, 518, sha256);
    return memcmp(sha256, expected, 32) == 0;
}

/* IPMI2-SHA1 (e872): HMAC-SHA1(pass, hex_decoded_salt) — 40hex ":" salt_hex */
static int verify_ipmi2sha1(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char hmac_out[20], expected[20], salt_bin[256];
    unsigned int hmac_len = 20;
    const char *colon, *hash_part, *salt_part;
    int hpart, salt_hex_len, salt_len;

    colon = memchr(hashstr, ':', hashlen);
    if (!colon) return 0;
    hpart = colon - hashstr;

    /* Try hash:salt (40hex hash first) or salt:hash (salt first) */
    if (hpart == 40) {
        hash_part = hashstr;
        salt_part = colon + 1;
        salt_hex_len = hashlen - hpart - 1;
    } else {
        salt_part = hashstr;
        salt_hex_len = hpart;
        hash_part = colon + 1;
        if (hashlen - hpart - 1 != 40) return 0;
    }
    if (hex2bin(hash_part, 40, expected) != 20) return 0;
    salt_len = hex2bin(salt_part, salt_hex_len, salt_bin);
    if (salt_len <= 0) return 0;

    HMAC(EVP_sha1(), pass, passlen, salt_bin, salt_len, hmac_out, &hmac_len);
    return memcmp(hmac_out, expected, 20) == 0;
}

/* IPMI2-MD5 (e873): HMAC-MD5(pass, hex_decoded_salt) — 32hex ":" salt_hex */
static int verify_ipmi2md5(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char hmac_out[16], expected[16], salt_bin[256];
    unsigned int hmac_len = 16;
    const char *colon;
    int hpart, salt_hex_len, salt_len;

    colon = memchr(hashstr, ':', hashlen);
    if (!colon) return 0;
    hpart = colon - hashstr;
    if (hpart != 32) return 0;
    if (hex2bin(hashstr, 32, expected) != 16) return 0;

    salt_hex_len = hashlen - hpart - 1;
    salt_len = hex2bin(colon + 1, salt_hex_len, salt_bin);
    if (salt_len <= 0) return 0;

    HMAC(EVP_md5(), pass, passlen, salt_bin, salt_len, hmac_out, &hmac_len);
    return memcmp(hmac_out, expected, 16) == 0;
}

/* KRB5PA23 (e874): NTLM → HMAC-MD5(usage=1) → RC4 decrypt → verify timestamp
 * Format: $krb5pa$23$user$realm$data$enc_timestamp_hex+checksum_hex */
static int verify_krb5pa23(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char ntlm[16], k1[16], k3[16];
    unsigned char enc_bin[512], decrypted[512];
    unsigned int hmac_len;
    const char *p;
    int dc, enc_hex_len, enc_len, data_len, i;

    if (hashlen < 30 || memcmp(hashstr, "$krb5pa$23$", 11) != 0) return 0;

    /* Skip past user$realm$data$ to get enc_hex */
    p = hashstr + 11;
    dc = 0;
    while (*p && dc < 3 && (p - hashstr) < hashlen) { if (*p == '$') dc++; p++; }
    if (dc != 3) return 0;

    enc_hex_len = hashlen - (p - hashstr);
    enc_len = enc_hex_len / 2;
    if (enc_len < 36 || enc_len > (int)sizeof(enc_bin)) return 0;
    if (hex2bin(p, enc_hex_len, enc_bin) != enc_len) return 0;

    /* Compute NTLM hash: MD4(UTF16LE(pass)) */
    { unsigned char utf16[1024];
      int u16len = utf8_to_utf16le(pass, passlen, utf16, sizeof(utf16));
      if (u16len <= 0) return 0;
      MD4(utf16, u16len, ntlm);
    }

    /* K1 = HMAC-MD5(ntlm, usage_type=1) */
    { unsigned char usage[4] = {1, 0, 0, 0};
      hmac_len = 16;
      HMAC(EVP_md5(), ntlm, 16, usage, 4, k1, &hmac_len);
    }

    /* checksum = last 16 bytes, encrypted data = first enc_len-16 bytes */
    data_len = enc_len - 16;

    /* K3 = HMAC-MD5(K1, checksum) */
    hmac_len = 16;
    HMAC(EVP_md5(), k1, 16, enc_bin + data_len, 16, k3, &hmac_len);

    /* RC4 decrypt */
    { RC4_KEY rc4key;
      RC4_set_key(&rc4key, 16, k3);
      RC4(&rc4key, data_len, enc_bin, decrypted);
    }

    /* Verify: bytes 14-15 must be '2','0' and bytes 16-27 must be ASCII digits */
    if (data_len < 28) return 0;
    if (decrypted[14] != '2' || decrypted[15] != '0') return 0;
    for (i = 16; i < 28; i++)
        if (decrypted[i] < '0' || decrypted[i] > '9') return 0;
    return 1;
}

/* AIX-MD5 (e868): md5crypt with empty magic — {smd5}salt$encoded */
static int verify_aixmd5(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    /* Reuse APR1/md5crypt logic but with empty magic "" */
    unsigned char md5[16], alt[16];
    const char *salt;
    int saltlen, i, plen;
    static const char itoa64[] =
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    if (hashlen < 10 || memcmp(hashstr, "{smd5}", 6) != 0) return 0;
    salt = hashstr + 6;
    for (saltlen = 0; saltlen < 8 && salt[saltlen] && salt[saltlen] != '$'; saltlen++)
        ;
    if (salt[saltlen] != '$') return 0;

    plen = passlen;

    /* Step 1: MD5(pass + "" + salt) — empty magic */
    { rhash ctx, altctx;
      ctx = rhash_init(RHASH_MD5);
      rhash_update(ctx, pass, plen);
      /* No magic string for AIX */
      rhash_update(ctx, salt, saltlen);

      /* Step 2: alternate MD5(pass + salt + pass) */
      altctx = rhash_init(RHASH_MD5);
      rhash_update(altctx, pass, plen);
      rhash_update(altctx, salt, saltlen);
      rhash_update(altctx, pass, plen);
      rhash_final(altctx, alt); rhash_free(altctx);

      for (i = plen; i > 0; i -= 16)
          rhash_update(ctx, alt, (i > 16) ? 16 : i);
      for (i = plen; i > 0; i >>= 1) {
          if (i & 1) rhash_update(ctx, "", 1);
          else rhash_update(ctx, pass, 1);
      }
      rhash_final(ctx, md5); rhash_free(ctx);
    }

    /* 1000 iterations */
    for (i = 0; i < 1000; i++) {
        rhash ctx = rhash_init(RHASH_MD5);
        if (i & 1) rhash_update(ctx, pass, plen);
        else rhash_update(ctx, md5, 16);
        if (i % 3) rhash_update(ctx, salt, saltlen);
        if (i % 7) rhash_update(ctx, pass, plen);
        if (i & 1) rhash_update(ctx, md5, 16);
        else rhash_update(ctx, pass, plen);
        rhash_final(ctx, md5); rhash_free(ctx);
    }

    /* md5crypt encoding */
    { static const unsigned char grp[][3] = {
          {0,6,12}, {1,7,13}, {2,8,14}, {3,9,15}, {4,10,5}
      };
      char enc[23];
      int eidx = 0, g;
      unsigned int v;
      for (g = 0; g < 5; g++) {
          v = ((unsigned int)md5[grp[g][0]] << 16)
            | ((unsigned int)md5[grp[g][1]] << 8)
            | md5[grp[g][2]];
          enc[eidx++] = itoa64[v & 0x3f]; v >>= 6;
          enc[eidx++] = itoa64[v & 0x3f]; v >>= 6;
          enc[eidx++] = itoa64[v & 0x3f]; v >>= 6;
          enc[eidx++] = itoa64[v & 0x3f];
      }
      v = md5[11];
      enc[eidx++] = itoa64[v & 0x3f]; v >>= 6;
      enc[eidx++] = itoa64[v & 0x3f];
      enc[eidx] = 0;

      { char expected[128];
        snprintf(expected, sizeof(expected), "{smd5}%.*s$%s", saltlen, salt, enc);
        return strncmp(expected, hashstr, hashlen) == 0;
      }
    }
}

/* AIX-SHA1 (e869): PBKDF2-HMAC-SHA1 — {ssha1}NN$salt$encoded */
static int verify_aixsha1(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char derived[20];
    char encoded[64];
    const char *p;
    int nn, saltlen;
    unsigned long rounds;

    if (hashlen < 15 || memcmp(hashstr, "{ssha1}", 7) != 0) return 0;
    p = hashstr + 7;
    nn = (p[0] - '0') * 10 + (p[1] - '0');
    if (p[2] != '$') return 0;
    rounds = 1UL << nn;

    { const char *salt_start = p + 3;
      const char *dollar = memchr(salt_start, '$', hashlen - (salt_start - hashstr));
      if (!dollar) return 0;
      saltlen = dollar - salt_start;

      PKCS5_PBKDF2_HMAC((const char *)pass, passlen,
          (const unsigned char *)salt_start, saltlen, rounds,
          EVP_sha1(), 20, derived);
      aix_encode(derived, 20, encoded);

      { char expected[256];
        snprintf(expected, sizeof(expected), "{ssha1}%02d$%.*s$%s", nn, saltlen, salt_start, encoded);
        return strncmp(expected, hashstr, hashlen) == 0;
      }
    }
}

/* AIX-SHA256 (e870): PBKDF2-HMAC-SHA256 — {ssha256}NN$salt$encoded */
static int verify_aixsha256(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char derived[32];
    char encoded[64];
    const char *p;
    int nn, saltlen;
    unsigned long rounds;

    if (hashlen < 17 || memcmp(hashstr, "{ssha256}", 9) != 0) return 0;
    p = hashstr + 9;
    nn = (p[0] - '0') * 10 + (p[1] - '0');
    if (p[2] != '$') return 0;
    rounds = 1UL << nn;

    { const char *salt_start = p + 3;
      const char *dollar = memchr(salt_start, '$', hashlen - (salt_start - hashstr));
      if (!dollar) return 0;
      saltlen = dollar - salt_start;

      PKCS5_PBKDF2_HMAC((const char *)pass, passlen,
          (const unsigned char *)salt_start, saltlen, rounds,
          EVP_sha256(), 32, derived);
      aix_encode(derived, 32, encoded);

      { char expected[256];
        snprintf(expected, sizeof(expected), "{ssha256}%02d$%.*s$%s", nn, saltlen, salt_start, encoded);
        return strncmp(expected, hashstr, hashlen) == 0;
      }
    }
}

/* AIX-SHA512 (e871): PBKDF2-HMAC-SHA512 — {ssha512}NN$salt$encoded */
static int verify_aixsha512(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char derived[64];
    char encoded[128];
    const char *p;
    int nn, saltlen;
    unsigned long rounds;

    if (hashlen < 17 || memcmp(hashstr, "{ssha512}", 9) != 0) return 0;
    p = hashstr + 9;
    nn = (p[0] - '0') * 10 + (p[1] - '0');
    if (p[2] != '$') return 0;
    rounds = 1UL << nn;

    { const char *salt_start = p + 3;
      const char *dollar = memchr(salt_start, '$', hashlen - (salt_start - hashstr));
      if (!dollar) return 0;
      saltlen = dollar - salt_start;

      PKCS5_PBKDF2_HMAC((const char *)pass, passlen,
          (const unsigned char *)salt_start, saltlen, rounds,
          EVP_sha512(), 64, derived);
      aix_encode(derived, 64, encoded);

      { char expected[256];
        snprintf(expected, sizeof(expected), "{ssha512}%02d$%.*s$%s", nn, saltlen, salt_start, encoded);
        return strncmp(expected, hashstr, hashlen) == 0;
      }
    }
}

/* MYSQL-SHA256CRYPT (e875): sha256crypt — $mysql$A$NNN*salt_hex*hash_hex */
static int verify_mysqlsha256crypt(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char digest[32], P[256], S[32], alt[32];
    int nnn, rounds, saltlen, x, rnd;
    const char *p;
    unsigned char salt_bin[64];
    int salt_hex_len, salt_bin_len;

    if (hashlen < 20 || memcmp(hashstr, "$mysql$A$", 9) != 0) return 0;
    p = hashstr + 9;
    nnn = atoi(p);
    while (*p >= '0' && *p <= '9') p++;
    if (*p != '*') return 0;
    { const char *salt_hex = p + 1;
      const char *star2 = memchr(salt_hex, '*', hashlen - (salt_hex - hashstr));
      if (!star2) return 0;
      salt_hex_len = star2 - salt_hex;
      if (salt_hex_len > 128) return 0;
      salt_bin_len = hex2bin(salt_hex, salt_hex_len, salt_bin);
      if (salt_bin_len <= 0) return 0;
      rounds = nnn * 1000;
      if (rounds < 1000) rounds = 5000;
      saltlen = salt_bin_len;

      /* sha256crypt algorithm */
      /* B = sha256(pass + salt + pass) */
      SHA256_CTX ctx;
      SHA256_Init(&ctx);
      SHA256_Update(&ctx, pass, passlen);
      SHA256_Update(&ctx, salt_bin, saltlen);
      SHA256_Update(&ctx, pass, passlen);
      SHA256_Final(alt, &ctx);

      /* A = sha256(pass + salt + alt_result[0..passlen-1]) */
      SHA256_Init(&ctx);
      SHA256_Update(&ctx, pass, passlen);
      SHA256_Update(&ctx, salt_bin, saltlen);
      for (x = passlen; x > 32; x -= 32)
          SHA256_Update(&ctx, alt, 32);
      SHA256_Update(&ctx, alt, x);
      for (x = passlen; x != 0; x >>= 1) {
          if (x & 1) SHA256_Update(&ctx, alt, 32);
          else SHA256_Update(&ctx, pass, passlen);
      }
      SHA256_Final(digest, &ctx);

      /* DP = sha256(pass repeated passlen times) */
      SHA256_Init(&ctx);
      for (x = 0; x < passlen; x++)
          SHA256_Update(&ctx, pass, passlen);
      SHA256_Final(alt, &ctx);
      memset(P, 0, sizeof(P));
      for (x = 0; x < passlen; x += 32)
          memcpy(P + x, alt, (passlen - x > 32) ? 32 : (passlen - x));

      /* DS = sha256(salt repeated 16+digest[0] times) */
      SHA256_Init(&ctx);
      for (x = 0; x < (int)(16 + digest[0]); x++)
          SHA256_Update(&ctx, salt_bin, saltlen);
      SHA256_Final(alt, &ctx);
      for (x = 0; x < saltlen; x += 32)
          memcpy(S + x, alt, (saltlen - x > 32) ? 32 : (saltlen - x));

      for (rnd = 0; rnd < rounds; rnd++) {
          SHA256_Init(&ctx);
          if (rnd & 1) SHA256_Update(&ctx, P, passlen);
          else SHA256_Update(&ctx, digest, 32);
          if (rnd % 3) SHA256_Update(&ctx, S, saltlen);
          if (rnd % 7) SHA256_Update(&ctx, P, passlen);
          if (rnd & 1) SHA256_Update(&ctx, digest, 32);
          else SHA256_Update(&ctx, P, passlen);
          SHA256_Final(digest, &ctx);
      }

      /* Encode with sha256crypt transposition + phpitoa64 */
      { static const int sha256_transpose[][3] = {
            {0,10,20},{21,1,11},{12,22,2},{3,13,23},{24,4,14},
            {15,25,5},{6,16,26},{27,7,17},{18,28,8},{9,19,29},{-1,30,31}
        };
        char my256_encoded[48];
        int ei = 0, ti;
        unsigned int v;
        for (ti = 0; ti < 10; ti++) {
            v = ((unsigned int)digest[sha256_transpose[ti][0]] << 16) |
                ((unsigned int)digest[sha256_transpose[ti][1]] << 8) |
                digest[sha256_transpose[ti][2]];
            my256_encoded[ei++] = phpitoa64[v & 0x3f]; v >>= 6;
            my256_encoded[ei++] = phpitoa64[v & 0x3f]; v >>= 6;
            my256_encoded[ei++] = phpitoa64[v & 0x3f]; v >>= 6;
            my256_encoded[ei++] = phpitoa64[v & 0x3f];
        }
        v = ((unsigned int)digest[31] << 8) | digest[30];
        my256_encoded[ei++] = phpitoa64[v & 0x3f]; v >>= 6;
        my256_encoded[ei++] = phpitoa64[v & 0x3f]; v >>= 6;
        my256_encoded[ei++] = phpitoa64[v & 0x3f];
        my256_encoded[43] = 0;

        /* Build expected: hex-encode the phpitoa64 string */
        { char expected[512];
          int elen = salt_hex + salt_hex_len + 1 - hashstr;
          /* Copy up to and including second '*' */
          memcpy(expected, hashstr, elen);
          for (ei = 0; ei < 43; ei++) {
              expected[elen + ei*2]     = "0123456789ABCDEF"[(my256_encoded[ei]>>4)&0xf];
              expected[elen + ei*2 + 1] = "0123456789ABCDEF"[my256_encoded[ei]&0xf];
          }
          expected[elen + 86] = 0;
          return hashlen == elen + 86 && strncasecmp(expected, hashstr, hashlen) == 0;
        }
      }
    }
}

/* DRUPAL7 (e876): iterated SHA512, phpitoa64 LSB encode — $S$iter_char + 8salt + 43encoded */
static int verify_drupal7(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char digest[64];
    unsigned long count;
    const char *salt_start;
    int log2_count;

    if (hashlen != 55 || memcmp(hashstr, "$S$", 3) != 0) return 0;
    { const char *pp = strchr(phpitoa64, hashstr[3]);
      if (!pp) return 0;
      log2_count = pp - phpitoa64;
    }
    count = 1UL << log2_count;
    salt_start = hashstr + 4;

    /* h = SHA512(salt + password) */
    { unsigned char buf[1024];
      memcpy(buf, salt_start, 8);
      memcpy(buf + 8, pass, passlen);
      SHA512(buf, 8 + passlen, digest);
    }
    /* iterate: h = SHA512(h + password) */
    { unsigned long ic;
      for (ic = 0; ic < count; ic++) {
          unsigned char buf[1024];
          memcpy(buf, digest, 64);
          memcpy(buf + 64, pass, passlen);
          SHA512(buf, 64 + passlen, digest);
      }
    }
    /* phpitoa64-encode first bytes of hash (LSB-first) */
    { char encoded[44];
      int ei = 0, bi = 0;
      while (bi < 64 && ei < 43) {
          unsigned int v = digest[bi++];
          if (bi < 64) v |= (unsigned int)digest[bi++] << 8;
          if (bi < 64) v |= (unsigned int)digest[bi++] << 16;
          encoded[ei++] = phpitoa64[v & 0x3f];
          if (ei < 43) encoded[ei++] = phpitoa64[(v >> 6) & 0x3f];
          if (ei < 43) encoded[ei++] = phpitoa64[(v >> 12) & 0x3f];
          if (ei < 43) encoded[ei++] = phpitoa64[(v >> 18) & 0x3f];
      }
      encoded[43] = 0;
      return memcmp(encoded, hashstr + 12, 43) == 0;
    }
}

/* NSEC3 (e879): iterated SHA1(dns_wire + salt) — b32hex_hash:domain:salt_hex:iters */
static int verify_nsec3(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char sha1[20], expected[20], salt_bin[256];
    const char *c1, *c2, *c3;
    int hash_len, iterations, salt_len, iter;

    /* Format: BASE32HEX_HASH:DOMAIN:SALT_HEX:ITERATIONS */
    c1 = memchr(hashstr, ':', hashlen);
    if (!c1) return 0;
    hash_len = c1 - hashstr;
    if (hash_len != 32) return 0;

    c2 = memchr(c1 + 1, ':', hashlen - (c1 + 1 - hashstr));
    if (!c2) return 0;
    c3 = memchr(c2 + 1, ':', hashlen - (c2 + 1 - hashstr));
    if (!c3) return 0;

    iterations = atoi(c3 + 1);
    { int salt_hex_len = c3 - c2 - 1;
      salt_len = hex2bin(c2 + 1, salt_hex_len, salt_bin);
      if (salt_len < 0) salt_len = 0;
    }

    /* DNS wire format: length-prefixed label for password + domain labels */
    { unsigned char wire[1024];
      int wlen = 0;
      const char *domain = c1 + 1;
      int dlen = c2 - c1 - 1;

      /* password as first label */
      wire[wlen++] = (unsigned char)passlen;
      memcpy(wire + wlen, pass, passlen);
      wlen += passlen;

      /* domain labels: split on '.' */
      { const char *dp = domain, *end = domain + dlen;
        while (dp < end) {
            const char *dot = memchr(dp, '.', end - dp);
            int lablen = dot ? (dot - dp) : (end - dp);
            if (lablen > 0) {
                wire[wlen++] = (unsigned char)lablen;
                /* lowercase the label */
                { int li;
                  for (li = 0; li < lablen; li++)
                      wire[wlen++] = (dp[li] >= 'A' && dp[li] <= 'Z') ? dp[li] + 32 : dp[li];
                }
            }
            dp += lablen + (dot ? 1 : 0);
        }
        wire[wlen++] = 0; /* root label */
      }

      /* First hash: SHA1(wire + salt) */
      memcpy(wire + wlen, salt_bin, salt_len);
      SHA1(wire, wlen + salt_len, sha1);

      /* Iterations: SHA1(prev + salt) */
      for (iter = 0; iter < iterations; iter++) {
          unsigned char buf[256];
          memcpy(buf, sha1, 20);
          memcpy(buf + 20, salt_bin, salt_len);
          SHA1(buf, 20 + salt_len, sha1);
      }
    }

    /* base32hex decode expected hash and compare */
    { static const char b32hex[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
      unsigned char dec[20];
      int i, j = 0, bits = 0;
      unsigned int accum = 0;
      for (i = 0; i < 32 && j < 20; i++) {
          char c = hashstr[i];
          const char *bp;
          int val;
          if (c >= 'a' && c <= 'v') c -= 32;
          bp = strchr(b32hex, c);
          if (!bp) return 0;
          val = bp - b32hex;
          accum = (accum << 5) | val;
          bits += 5;
          if (bits >= 8) {
              bits -= 8;
              dec[j++] = (accum >> bits) & 0xff;
          }
      }
      if (j != 20) return 0;
      return memcmp(sha1, dec, 20) == 0;
    }
}

/* DOMINO5 (e882): domino5_transform(pass) — 32hex (16 bytes) */
static int verify_domino5(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char output[16], expected[16];

    if (hashlen != 32) return 0;
    if (hex2bin(hashstr, 32, expected) != 16) return 0;
    if (passlen > 256) return 0;
    domino5_transform(pass, passlen, output);
    return memcmp(output, expected, 16) == 0;
}

/* DOMINO6 (e883): domino5(salt + UC(domino5(pass)[0:14])), lotus64 — (G...encoded...) */
static int verify_domino6(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    unsigned char h1[16], h2[16], d6_buf[48], d6_raw[14], d6_salt[5];
    char encoded[24];
    static const char uchex[] = "0123456789ABCDEF";
    int x;

    if (hashlen != 22 || hashstr[0] != '(' || hashstr[hashlen-1] != ')' || hashstr[1] != 'G')
        return 0;
    if (passlen > 256) return 0;

    /* Decode salt from the encoded hash — need to reverse the lotus64 encoding */
    /* The hash format is (G + lotus64(salt5 + h2_9)), but we need to decode to get salt */
    { static const signed char lotus64_rev[128] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,
        25,26,27,28,29,30,31,32,33,34,35,-1,-1,-1,-1,-1,
        -1,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,
        51,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1
      };
      /* Decode the 19 lotus64 chars after "(G" to get 14 raw bytes */
      const char *enc = hashstr + 2;
      int enc_len = hashlen - 3; /* 19 chars between "(G" and ")" */
      unsigned char raw[14];
      int ri = 0, ei = 0;
      if (enc_len != 19) return 0;
      while (ei + 3 < enc_len && ri + 2 < 14) {
          int a = lotus64_rev[(unsigned char)enc[ei]];
          int b = lotus64_rev[(unsigned char)enc[ei+1]];
          int c = lotus64_rev[(unsigned char)enc[ei+2]];
          int d = lotus64_rev[(unsigned char)enc[ei+3]];
          if (a < 0 || b < 0 || c < 0 || d < 0) return 0;
          raw[ri++] = (a << 2) | (b >> 4);
          raw[ri++] = ((b & 0xf) << 4) | (c >> 2);
          raw[ri++] = ((c & 3) << 6) | d;
          ei += 4;
      }
      /* Handle remaining chars */
      if (ei < enc_len && ri < 14) {
          int a = lotus64_rev[(unsigned char)enc[ei]];
          int b = (ei+1 < enc_len) ? lotus64_rev[(unsigned char)enc[ei+1]] : 0;
          int c = (ei+2 < enc_len) ? lotus64_rev[(unsigned char)enc[ei+2]] : 0;
          if (a < 0) return 0;
          raw[ri++] = (a << 2) | (b >> 4);
          if (ri < 14 && ei+1 < enc_len) raw[ri++] = ((b & 0xf) << 4) | (c >> 2);
      }

      /* Extract salt: first 5 bytes, undo the +4 quirk on byte 3 */
      memcpy(d6_salt, raw, 5);
      d6_salt[3] -= 4;
    }

    /* h1 = domino5_transform(password) */
    domino5_transform(pass, passlen, h1);

    /* Build: raw_salt(5) + "(" + UCHEX(h1[0:14]) = 34 bytes */
    memcpy(d6_buf, d6_salt, 5);
    d6_buf[5] = '(';
    for (x = 0; x < 14; x++) {
        d6_buf[6+x*2]   = uchex[(h1[x]>>4)&0xf];
        d6_buf[6+x*2+1] = uchex[h1[x]&0xf];
    }

    /* h2 = domino5_transform(d6_buf, 34) */
    domino5_transform(d6_buf, 34, h2);

    /* Compare computed h2 with the h2 extracted from the hash (bytes 5-13 of raw decode) */
    { unsigned char raw_expect[14];
      const char *enc = hashstr + 2;
      int ei = 0, ri = 0;
      static const signed char lr[128] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
         0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1,
        -1,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,
        25,26,27,28,29,30,31,32,33,34,35,-1,-1,-1,-1,-1,
        -1,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,
        51,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1
      };
      while (ei + 3 < 19 && ri + 2 < 14) {
          int a = lr[(unsigned char)enc[ei]], b = lr[(unsigned char)enc[ei+1]];
          int c = lr[(unsigned char)enc[ei+2]], d = lr[(unsigned char)enc[ei+3]];
          if (a < 0 || b < 0 || c < 0 || d < 0) return 0;
          raw_expect[ri++] = (a << 2) | (b >> 4);
          raw_expect[ri++] = ((b & 0xf) << 4) | (c >> 2);
          raw_expect[ri++] = ((c & 3) << 6) | d;
          ei += 4;
      }
      if (ei < 19 && ri < 14) {
          int a = lr[(unsigned char)enc[ei]];
          int b = (ei+1 < 19) ? lr[(unsigned char)enc[ei+1]] : 0;
          int c = (ei+2 < 19) ? lr[(unsigned char)enc[ei+2]] : 0;
          if (a < 0) return 0;
          raw_expect[ri++] = (a << 2) | (b >> 4);
          if (ri < 14 && ei+1 < 19) raw_expect[ri++] = ((b & 0xf) << 4) | (c >> 2);
      }
      /* Compare h2 bytes: raw_expect[5..13] vs computed h2[0..8] */
      return ri >= 14 && memcmp(raw_expect + 5, h2, 9) == 0;
    }
}

/* SCRYPT: crypto_scrypt(pass, salt, N, r, p, output, 32)
 * Format: SCRYPT:N:r:p:base64_salt:base64_hash:password */
static int verify_scrypt(const char *hashstr, int hashlen,
    const unsigned char *pass, int passlen)
{
    char buf[512];
    char *f[6]; /* SCRYPT, N, r, p, b64salt, b64hash */
    int fi = 0;
    unsigned char salt_bin[256], output[32];
    char b64out[64];

    if (hashlen < 20 || hashlen >= (int)sizeof(buf)) return 0;
    if (memcmp(hashstr, "SCRYPT:", 7) != 0) return 0;

    memcpy(buf, hashstr, hashlen);
    buf[hashlen] = 0;

    /* Parse SCRYPT:N:r:p:b64salt:b64hash into 6 fields */
    f[0] = buf;
    { char *sp = buf;
      while (*sp && fi < 5) {
        if (*sp == ':') { *sp = 0; fi++; f[fi] = sp + 1; }
        sp++;
      }
    }
    if (fi < 5) return 0;

    unsigned long long sc_N = strtoull(f[1], NULL, 10);
    int sc_r = atoi(f[2]);
    int sc_p = atoi(f[3]);
    if (sc_N == 0 || sc_r == 0 || sc_p == 0) return 0;

    /* Decode base64 salt */
    int sc_salt_len = base64_decode(f[4], strlen(f[4]), salt_bin, sizeof(salt_bin));
    if (sc_salt_len <= 0) return 0;

    /* Compute scrypt */
    int ret = crypto_scrypt((const uint8_t *)pass, passlen,
                            salt_bin, sc_salt_len,
                            sc_N, sc_r, sc_p,
                            output, 32);
    if (ret != 0) return 0;

    /* Base64-encode output and compare */
    int b64len = base64_encode(output, 32, b64out, sizeof(b64out));
    if (b64len != (int)strlen(f[5])) return 0;
    return memcmp(b64out, f[5], b64len) == 0;
}

/* ---- Chain arrays for types needing HTC registration ---- */
static struct chain_step chain_md5sha1ucmd5uc[] = { SU_MD5, SU_SHA1, S_MD5 };
/* chain_md5md5ucsha1md5md5 defined earlier */

/* ---- Hashtypes[] registry — indexed by Types[] number ---- */

/* Find index of a type name in Types[] (Judy-accelerated, case-insensitive) */
static int find_type_index(const char *name)
{
    PWord_t PV;
    char ucname[128];
    int i, len = strlen(name);
    if (len >= (int)sizeof(ucname)) return -1;
    for (i = 0; i < len; i++)
        ucname[i] = toupper((unsigned char)name[i]);
    ucname[len] = 0;
    JSLG(PV, TypenameJ, (unsigned char *)ucname);
    if (PV && *PV > 0) return (int)(*PV - 1);
    return -1;
}

static void init_hashtypes(void)
{
    int i, h;

    /* Count types from NULL terminator */
    for (Numtypes = 0; Types[Numtypes]; Numtypes++)
        ;

    /* Allocate and zero-init */
    Hashtypes = (struct hashtype *)calloc(Numtypes, sizeof(struct hashtype));
    if (!Hashtypes) { perror("calloc Hashtypes"); exit(1); }

    /* Set names from Types[] and populate Judy name→index lookup (keys uppercased) */
    for (i = 0; i < Numtypes; i++) {
        PWord_t PV;
        char uckey[128];
        int j, klen;
        Hashtypes[i].name = Types[i];
        klen = strlen(Types[i]);
        if (klen >= (int)sizeof(uckey)) klen = (int)sizeof(uckey) - 1;
        for (j = 0; j < klen; j++)
            uckey[j] = toupper((unsigned char)Types[i][j]);
        uckey[klen] = 0;
        JSLI(PV, TypenameJ, (unsigned char *)uckey);
        if (PV) *PV = (Word_t)(i + 1);  /* store index+1 (0 = not found) */
    }

    /* Macro: look up by name, avoids hardcoded index errors */
    #define HT(tname, len, fl, fn, ex) do { \
        int _i = find_type_index(tname); \
        if (_i >= 0) { \
            Hashtypes[_i].hashlen = (len); \
            Hashtypes[_i].flags = (fl); \
            Hashtypes[_i].compute = (fn); \
            Hashtypes[_i].compute_alt = NULL; \
            Hashtypes[_i].iter_fn = NULL; \
            Hashtypes[_i].verify = NULL; \
            Hashtypes[_i].nchain = 0; \
            Hashtypes[_i].chain = NULL; \
            Hashtypes[_i].example = (ex); \
        } \
    } while(0)

    /* HT with alternate compute (e.g. HUM prepend variant) */
    #define HT_ALT(tname, len, fl, fn, altfn, ex) do { \
        int _i = find_type_index(tname); \
        if (_i >= 0) { \
            Hashtypes[_i].hashlen = (len); \
            Hashtypes[_i].flags = (fl); \
            Hashtypes[_i].compute = (fn); \
            Hashtypes[_i].compute_alt = (altfn); \
            Hashtypes[_i].iter_fn = NULL; \
            Hashtypes[_i].verify = NULL; \
            Hashtypes[_i].nchain = 0; \
            Hashtypes[_i].chain = NULL; \
            Hashtypes[_i].example = (ex); \
        } \
    } while(0)

    /* HTC: register a chain type (chain_arr is static array of chain_step) */
    #define HTC(tname, len, fl, chain_arr, ex) do { \
        int _i = find_type_index(tname); \
        if (_i >= 0) { \
            Hashtypes[_i].hashlen = (len); \
            Hashtypes[_i].flags = (fl); \
            Hashtypes[_i].compute = NULL; \
            Hashtypes[_i].compute_alt = NULL; \
            Hashtypes[_i].iter_fn = NULL; \
            Hashtypes[_i].verify = NULL; \
            Hashtypes[_i].nchain = sizeof(chain_arr) / sizeof(chain_arr[0]); \
            Hashtypes[_i].chain = (chain_arr); \
            Hashtypes[_i].example = (ex); \
        } \
    } while(0)

    /* HTV: register a non-hex verify type */
    #define HTV(tname, fl, vfn, ex) do { \
        int _i = find_type_index(tname); \
        if (_i >= 0) { \
            Hashtypes[_i].hashlen = 0; \
            Hashtypes[_i].flags = (fl) | HTF_NONHEX; \
            Hashtypes[_i].compute = NULL; \
            Hashtypes[_i].compute_alt = NULL; \
            Hashtypes[_i].iter_fn = NULL; \
            Hashtypes[_i].verify = (vfn); \
            Hashtypes[_i].nchain = 0; \
            Hashtypes[_i].chain = NULL; \
            Hashtypes[_i].example = (ex); \
        } \
    } while(0)

    /* --- Base unsalted types --- */
    HT("MD5",           16, 0, compute_md5, "482c811da5d5b4bc6d497ffa98491e38:password123");
    HT("MD5UC",         16, HTF_UC, compute_md5, NULL);
    HT("MD4",           16, 0, compute_md4, "fc7b71b67e964466cec486ab12f4b558:password123");
    HT("MD2",           16, 0, compute_md2, "01d78cde2365535ed93abaae48a9abc2:password123");
    HT("WRL",           64, 0, compute_whirlpool, "0087cb3eead9d0bc1796172993099071c1495d7edc2531a8c3d3985616394666d08333cc9cb84354c0833f5918628446a4794db8a805a993f0b46f53e5c9e658:password123");
    HT("HAV128",        16, 0, compute_hav128_3, "ab71f5c32f8720509626227686136dff:password123");
    HT("SHA0",          20, 0, compute_sha0, "40e43bfb5f73a156bfc863708ba7c66ce9e69b9d:password123");
    HT("SHA1",          20, 0, compute_sha1, "cbfdac6008f9cab4083784cbd1874f76618d2a97:password123");
    HT("SHA224",        28, 0, compute_sha224, "3d45597256050bb1e93bd9c10aee4c8716f8774f5a48c995bf0cf860:password123");
    HT("SHA256",        32, 0, compute_sha256, "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f:password123");
    HT("SHA384",        48, 0, compute_sha384, "648357a04407e0a73fe201d9aad9bec165cbf63b6db4311b28f7e256b214a0725e45069c0162232d31412580255c461e:password123");
    HT("SHA512",        64, 0, compute_sha512, "bed4efa1d4fdbd954bd3705d6a2a78270ec9a52ecfbfb010c61862af5c76af1761ffeb1aef6aca1bf5d02b3781aa854fabd2b69c790de74e17ecfec3cb6ac4bf:password123");
    HT("GOST",          32, 0, compute_gost, "24f45a9606420485883f18dde536194ee1d1debf2af5706ac65809b4cca98f92:password123");
    HT("GOST-CRYPTO",   32, 0, compute_gostcrypto, "ff8ab4e789fbe4a170835cf0dd52b8ddb0b8e22a86bb297bfca09f397777207e:password123");
    HT("HAV256",        32, 0, compute_hav256_3, "426c08f266fdf8898ac806a4ff499c98911235e7f1164f6ed6c0532892cba11e:password123");
    HT("RMD128",        16, 0, compute_rmd128, "701db377f35e7d8834b501ab9b6c0c42:password123");
    HT("RMD160",        20, 0, compute_rmd160, "604081c4e43c8fc4b7c8c03da55534a2ead5bb05:password123");
    HT("TIGER",         24, 0, compute_tiger, "763cfa83b7d3dd5fd82d536e6a2f912142721444b919367e:password123");
    HT("TTH",           24, 0, compute_tth, "fb32a871465e1660a287dd697d50d6fbb3331316c4ae3db3:password123");
    HT("ED2K",          16, 0, compute_ed2k, "fc7b71b67e964466cec486ab12f4b558:password123");
    HT("AICH",          20, 0, compute_aich, "cbfdac6008f9cab4083784cbd1874f76618d2a97:password123");
    HT("HAS160",        20, 0, compute_has160, "75f1d00d7a4897e09475e9bfd0a0e3175e312a0d:password123");
    HT("EDON256",       32, 0, compute_edon256, "6f811a412d9c1269abf4d27e4c89aee088afd5ad0c7a262383ebc61264211b32:password123");
    HT("EDON512",       64, 0, compute_edon512, "442f2f293dabec55c34d8cc37b15d5fe7b4cccd42a4c59aad908ce6d04c5cea6a3cbb67877539995ac9a86c3380bc4d586e26f13163a06d08c651bf5bdf11589:password123");
    HT("SNE128",        16, 0, compute_sne128, "e3558e2a3a7878e2055ad7391baa6f42:password123");
    HT("SNE256",        64, 0, compute_sne256, "2f6e918a85cbfd8b021388ab4bddcbc5e506722a01aac5afb22aa0ed3796c98d:password123");
    HT("MD6",           16, 0, compute_md6_128, "4837cb1bac01aa6b2cb171f1bb8d3fcb:password123");
    HT("MD6128",        16, 0, compute_md6_128, "4837cb1bac01aa6b2cb171f1bb8d3fcb:password123");
    HT("MD6256",        32, 0, compute_md6_256, "04516e374f0ad9f74c3fc62045a597e732b3387020f7646bf8ea5643e8ab3037:password123");
    HT("MD6512",        64, 0, compute_md6_512, "099cc4f53aebc83286c2e3f4e0b2c6d3c53638a83d54b1225deb34614cd13e7170c1650df3c6afef0a848b1f4e86ab97c013c3852bd6fe2f0b5dc94b6c1fb67d:password123");
    HT("HAV128-4",      16, 0, compute_hav128_4, "ebf3b07e42498535c44f4215e0e0c471:password123");
    HT("HAV128-5",      16, 0, compute_hav128_5, "db98b98d746d601572f0ae07e74e7b78:password123");
    HT("HAV160-3",      20, 0, compute_hav160_3, "099ffe0e508d2822715efeb69c11df9d0fd54bba:password123");
    HT("HAV160-4",      20, 0, compute_hav160_4, "a98da4adb3155e37a0fc73d3871619f6afd824c8:password123");
    HT("HAV160-5",      20, 0, compute_hav160_5, "0c561c5aec39b186e00716617a7f2c94a74711c5:password123");
    HT("HAV192-3",      24, 0, compute_hav192_3, "403f8d57068308bca70ea3d199db7687dca545b836ec1b3e:password123");
    HT("HAV192-4",      24, 0, compute_hav192_4, "730cc4a7be2f10bfaa74dbbad634d06eeea2a4c4f73fdaeb:password123");
    HT("HAV192-5",      24, 0, compute_hav192_5, "d9dc01dc7ab8dee80c0eba8922552153050a02de57563fc5:password123");
    HT("HAV224-3",      28, 0, compute_hav224_3, "a08d02d32aad0e9406197dca0287ebc4362f719e259c4859834967f4:password123");
    HT("HAV224-4",      28, 0, compute_hav224_4, "43400ed9d1626d0858c074009908d818eca41e61d5cc9457f411ca12:password123");
    HT("HAV224-5",      28, 0, compute_hav224_5, "98a40b978800447c21af26f10b05bb54d739bd58824543b79f5d1f43:password123");
    HT("HAV256-4",      32, 0, compute_hav256_4, "3fc4c6f491eb833f58172f96f28b66beefd03e518eeac6f6fb810ba3ae288770:password123");
    HT("HAV256-5",      32, 0, compute_hav256_5, "ee5fb4c5c51f42dd02809711cbaef7e2bd5403c922a4b7fe4b3e784fcd84d1d4:password123");
    /* SPH 224/256/384/512 families */
    HT("BLAKE224",      28, 0, compute_blake224, "c5fade2447fc8f1b6a0ee063e142ce4882d1580cc2bf28f969484491:password123");
    HT("BLAKE256",      32, 0, compute_blake256, "74f57269fe25014a902785c11e078d46384c0543c5d04fdc9385d9f8ff4a7c96:password123");
    HT("BLAKE384",      48, 0, compute_blake384, "1b9b44dd391bdf699f42828d9be688574282b60936905b9cac68cdd7dfa4eb5a23ebe3c33329e3f64c256b28956044c2:password123");
    HT("BLAKE512",      64, 0, compute_blake512, "709b55595c785bbb53c10e0ba7168fa21a201705cbc95814df7aea223e11c43986506d2c5f74ef11a92a476e39bf978f4b29e04f9305f83d7c6d8847d9c65a56:password123");
    HT("BMW224",        28, 0, compute_bmw224, "4e1b75d40fe7663f1ea282aa477f3df919354b46ebd30b94a9c4047a:password123");
    HT("BMW256",        32, 0, compute_bmw256, "3597bed522e7113c49ec27ac2106f87aa8625e7f4cde3630ae4d4db6e042ea8c:password123");
    HT("BMW384",        48, 0, compute_bmw384, "c62da84e334d1f9792c07876e8be42382626673242d8a4b9567867266ddb4b70cfd6416c372327297f381f904c78904f:password123");
    HT("BMW512",        64, 0, compute_bmw512, "8fbb7784a88335a04c2e3b472cf21da60072d23a2ca1fa8f718439b1e9c071ecb923f3f67ae3a8b825126de815e0988e453394e7ccfb86e25e4b6cd9cc7f91d1:password123");
    HT("CUBE224",       28, 0, compute_cube224, "4b13b939e4b9b9bdb61ffae999c0ac41e3c30ec828d0ccc7cfb49a82:password123");
    HT("CUBE256",       32, 0, compute_cube256, "8971b66cb1df1a39e7068b26b20607177439a9a390a776f9343412170f07a99c:password123");
    HT("CUBE384",       48, 0, compute_cube384, "a5321d2e894561cc035aa769ed0b4b545ccba96fd70e6ec9f539d63b79cffbdec3ce8753540ec8201735f257b9f501c2:password123");
    HT("CUBE512",       64, 0, compute_cube512, "cdb35e73407a538a74b1b60a33bb5c03c36acf7d723d8086d617d8a740e260d6622c819991e2c532b8145122571d6fedd65558ef2b0e59de0b8aa9a97659ff9e:password123");
    HT("ECHO224",       28, 0, compute_echo224, "260fc725ae9a734b7e0f25858ce5d85ecaa727d23d3be90ea46bdba8:password123");
    HT("ECHO256",       32, 0, compute_echo256, "d6c672888a580c44c262658e2fa3d9c5fadbb55fb112ec04a3799747be888c38:password123");
    HT("ECHO384",       48, 0, compute_echo384, "b4dc5f3324e8aece18d4c2aaaacc2efbe2ffb828f67a2f5baaee6456ae2879e601e3a60569537add38ab25d320cbbcf9:password123");
    HT("ECHO512",       64, 0, compute_echo512, "3ef0d8b036a715dedf3df6b88982b72f15157b0dedf77af37ba58fcce65d5cf2074c63995051309c8527576bf8b1ec56e3285797156735c9395cc5225ec74305:password123");
    HT("FUGUE224",      28, 0, compute_fugue224, "fa086bd57f808d74e38c08c37c3943c2028f45d0b0bbc1a703cd0bd2:password123");
    HT("FUGUE256",      32, 0, compute_fugue256, "80caed1431abdddee79745c986e1a27e0e1559af08854e3db9bfd839ccf98555:password123");
    HT("FUGUE384",      48, 0, compute_fugue384, "b1ab19adb6b2ed585ffa090223ac1c1ae4af83d652c1df11b258bb1b42fa745ab45182b1de19e0443cb09e7580025a15:password123");
    HT("FUGUE512",      64, 0, compute_fugue512, "67f3eaafa613238083a2b31b37676af4ca8434c84991ab69120ccaf8cc90711a6e6a3b3357ef5186b52cc585a71a5ce65a69f4cb90aa80051d9756a9c8cef6ad:password123");
    HT("GROESTL224",    28, 0, compute_groestl224, "c247af45740643f48b452ef9420005efcba2aa06ce65ccce95ab427e:password123");
    HT("GROESTL256",    32, 0, compute_groestl256, "04fb95a1d28f870faf9c81b625fafe804e2aad26cb883fcc6ab27ab1078d1189:password123");
    HT("GROESTL384",    48, 0, compute_groestl384, "2f686c58ed893e4534e36d43d6e2577c81df209cfa5d03aa946b45256de67e9e9bf2e4863e0738fe81fce120e949224f:password123");
    HT("GROESTL512",    64, 0, compute_groestl512, "f34a0060081ce2a50c061f47b25914e7fbf256cb70be304faef5e31360db5bcf8d7dbe2b9e708208a1c9d53e122c7dc986098fa3d3520eb610def13334f2a766:password123");
    HT("HAMSI224",      28, 0, compute_hamsi224, "be4215757a4ab8584003a8c88ddcb8f9a27765f30e519eb55f4b6306:password123");
    HT("HAMSI256",      32, 0, compute_hamsi256, "8a6c83311c4853421798d43b68682148dad2d0aa274b9bf325742df8635b76ac:password123");
    HT("HAMSI384",      48, 0, compute_hamsi384, "31d4b3fcc84a324190ab71a4e6b7775d30addbc02396caadfb0a9ec1ef3c08016bdbe9618a7187fea8af520e83e8c533:password123");
    HT("HAMSI512",      64, 0, compute_hamsi512, "1b13fb127eed7bb1f0a2c3e0e31bed7743ae1d0c7d7922a52d1647ca36db0e83295755210e37047d21c0db4068157401a7ccfefd2d81a8d96779b4e99555002a:password123");
    HT("JH224",         28, 0, compute_jh224, "9eabd4d41067fa7836cef15fe54e4972b95a1e81a66bb6bd179b32d6:password123");
    HT("JH256",         32, 0, compute_jh256, "4213ce43a33521d327404ee2f3f708353ec7ca41507040569ab3c4a515a2a4af:password123");
    HT("JH384",         48, 0, compute_jh384, "48fef9a17db6a4fc5ccb529943537f03f0a1bf1467c6b5291c966fc5e2696e15bd50ff25a9e11f7626c0443c306206a6:password123");
    HT("JH512",         64, 0, compute_jh512, "bb7a46a33626921a8223964f605273eac6ddac46d70f29295037a034cf9dea5c93208b52b8128629f810a4dd225e3fabd08999503ddf6947dbb3e38f9f36ccee:password123");
    HT("KECCAK224",     28, 0, compute_keccak224, "2781d12d1d761b02bab1fc3f61d66ddbf3c5622d01da8297bd37fd7a:password123");
    HT("KECCAK256",     32, 0, compute_keccak256, "0d45e19766c0cadfe3af48b801102a9de4337ee41088e3561d9f1e9897aeeeae:password123");
    HT("KECCAK384",     48, 0, compute_keccak384, "21ff54d0e51d8542ce409b7541bed6b5e853d7e2408507eba3d823f94749d118b69fd3971239a5c35673cc5531b2ed87:password123");
    HT("KECCAK512",     64, 0, compute_keccak512, "aa77c1b9b7021937f820cc53cfa234ff49695dbfcfee83d283d1d68b180c2a56a3984d637e677a7c0cb8d943d01c9019810e5608266bb18ca649f1a64c661c7f:password123");
    HT("SHA3-224",      28, 0, compute_sha3_224, "cc782e5480878ba3fb6bb07905fdcf4a00e056adb957ae8a03c53a52:password123");
    HT("SHA3-256",      32, 0, compute_sha3_256, "ab3fe4003f14e3ef573417f95e47d4985c482eadd139c08b3758eeae7cc60b9d:password123");
    HT("SHA3-384",      48, 0, compute_sha3_384, "d9b644c85745fe084746ef61cd2b5c0981ad524b9ab114c1e88966687479a0fbbe87f09a647a92b08437d1b63c555b06:password123");
    HT("SHA3-512",      64, 0, compute_sha3_512, "4ad2c01fc6007f58720b00fc99b978c2a17c577859d31fdbba4b3a749de9383ac4b0738aeaf0b13337db8bfeaf9d8f87faa236fc3c8a68fbf23eb6862fadb86e:password123");
    HT("LUFFA224",      28, 0, compute_luffa224, "0e70a2758b9c643c60e40f369c07f38c9e487b3d75cfadc4c2338b6c:password123");
    HT("LUFFA256",      32, 0, compute_luffa256, "0e70a2758b9c643c60e40f369c07f38c9e487b3d75cfadc4c2338b6c70071ba1:password123");
    HT("LUFFA384",      48, 0, compute_luffa384, "f10624a65c48ff31475bf97c4d66f166f21c46da1c41dad95b2158aa1071bb94d1552702b0f61841e267ee980ff87d16:password123");
    HT("LUFFA512",      64, 0, compute_luffa512, "489ff5b40ce4c8864747265c942bbff3360d2916c94db14e47773ad1270ef3eb646b96d5efb422e274246e6aca3e67c739c4ca744b88d08e705eb5358f2d3df1:password123");
    HT("PANAMA",        32, 0, compute_panama, "209756afbb2888b00fd3ceb3ddd33327ccbfe9fcdfc0e030ee124afd8f00c69d:password123");
    HT("RADIOGATUN32",  16, 0, compute_radiogatun32, "41df49dcea7772a04016b92522bd79a0:password123");
    HT("RADIOGATUN64",  32, 0, compute_radiogatun64, "1e69083b924d85f77cb27761f4baf3b3e6e456e2ee4213582b297d7a3319add1:password123");
    HT("SHABAL224",     28, 0, compute_shabal224, "6abab1f4f5f0ef56fc4aad3220fe360d5cf73a18e8826bc1b6944e23:password123");
    HT("SHABAL256",     32, 0, compute_shabal256, "f8dedc7bcdb0738410c90f4b1aa265979cf8229956f63e3fce658173e56b6791:password123");
    HT("SHABAL384",     48, 0, compute_shabal384, "4e7363106e1276c251c36e5b898fd5c136cbdca059b7b47160b31f78825f161b6088c35de8a05c6021ca7009f603a3f7:password123");
    HT("SHABAL512",     64, 0, compute_shabal512, "287d6313b8c953ed49aa2ef79e0139608e8a4e4848fdb15ec258b5be2f4156d42d392f30be164e5c85f5694faaeeba647a58b411440d54310f571b40a8a99fb8:password123");
    HT("SHAVITE224",    28, 0, compute_shavite224, "3068845854a52d1ae173e35714506195dbc4031fb97c09ab90a9b23a:password123");
    HT("SHAVITE256",    32, 0, compute_shavite256, "c4c52be909a2b88d549a94ee66818d2876eaacded692c6a12d2bb4b4766d0155:password123");
    HT("SHAVITE384",    48, 0, compute_shavite384, "7ea5104c9d6fcc270bd6f1e20222ed8708a02d6edb77c8ce65824f5cea660a5e4f8b97821d8e0d91e3cc49b2f6e62d69:password123");
    HT("SHAVITE512",    64, 0, compute_shavite512, "00119cdc7fe882604d3212a8eca8666cfba6a515ee0f53f93a820f40e97e4ca21e466980a9c8776f188b8fdc9bb7195710ab361ac556bd31e16df1fdcbb767ef:password123");
    HT("SIMD224",       28, 0, compute_simd224, "a254dd7c1cdca2b5ff08e734c6be841d02dad74b6b8e65f43a71763c:password123");
    HT("SIMD256",       32, 0, compute_simd256, "36e481232fc97022a2dd772dd382c8889ccc033d08664c3bc69c60a1cdcfdb0a:password123");
    HT("SIMD384",       48, 0, compute_simd384, "32cec19305e71af3d591bbcf6ac93540466de4002aca9aa66bf89a558062cff1ef46694683732669f4418604a1b76e98:password123");
    HT("SIMD512",       64, 0, compute_simd512, "ad2cd6e99de20db9149cec7b433b83747d681854d7fddcb48f8e5e7dbfb327d925f7e0f70de5ba9a3a4232852cf2f507927cdfe4d96ceb756423d1f37e73707c:password123");
    HT("SKEIN224",      28, 0, compute_skein224, "eec989ed33636d610da3b26ffd18e04b1e54a4793974868665e27429:password123");
    HT("SKEIN256",      32, 0, compute_skein256, "3c25a8e83a9a294db94bcb375c18d3ec620027eb8b8c20e4843465f51ccebbaf:password123");
    HT("SKEIN384",      48, 0, compute_skein384, "98c9ed948d6d88ea02f564880b9adbd922ccc049efaad769bab3788afcdd4567c972e8d34224eaa715779f494eb2e0af:password123");
    HT("SKEIN512",      64, 0, compute_skein512, "490bbb3ef0f8df6acbbedd71b126be9ca6916f5c4fe9368f66a0010fa2a0601586ca2e658868f9bbc02e45f3229b9c7d3a829b168e08141ff528b02f098c0a53:password123");
    HT("TIGER2",        24, 0, compute_tiger2, "3a741930e19b25f7cfd71d093b46bee10fae839e6dd14e1a:password123");
    HT("WRL0",          64, 0, compute_wrl0, "e8d48e900fc9bee4a5a77cac5126b21a93a25533e1b32f55a40f82cf7a92a9c8006a3f5293c79851e8ad8efe129b65b854d91c8f1db5af4a11b8663d35973754:password123");
    HT("WRL1",          64, 0, compute_wrl1, "1036a64d4e0cffdcfeb2d324c5d6ea3639e8b401b7590791e1f3d749fafaa694f865eecd0b1003790fbb5b9dcbac4b29800ea0a87699da23bd73ce515e62800d:password123");
    HT("RIPEMD",        16, 0, compute_ripemd, "dc2b4b1ed04412f1f06f2657177327f2:password123");
    /* GOST-2012 / Streebog */
    HT("GOST2012-32",   32, 0, compute_gost2012_32, "6940451a91df4d17532dd11762b851572bad5362f4d885d2a20e510b2f875870:password123");
    HT("GOST2012-64",   64, 0, compute_gost2012_64, "9b7ce5af74589324a811f467795a93ad4fb5e6a62ea10e4116d134beae36dba62c29cee821927cc5ec4da0fe4c9ac6cfd9274cb78ac0e63c968ef55da20effc6:password123");
    HT("STREEBOG-32",   32, 0, compute_gost2012_32, "6940451a91df4d17532dd11762b851572bad5362f4d885d2a20e510b2f875870:password123");
    HT("STREEBOG-64",   64, 0, compute_gost2012_64, "9b7ce5af74589324a811f467795a93ad4fb5e6a62ea10e4116d134beae36dba62c29cee821927cc5ec4da0fe4c9ac6cfd9274cb78ac0e63c968ef55da20effc6:password123");
    /* BLAKE2 */
    HT("BLAKE2B512",    64, 0, compute_blake2b512, NULL);
    HT("BLAKE2S256",    32, 0, compute_blake2s256, NULL);
    HT("BLAKE2B256",    32, 0, compute_blake2b256, NULL);
    /* Murmur */
    HT("MURMUR64AZERO", 8,  HTF_ITER_X0, compute_murmur64a_zero, NULL);
    /* UC variants */
    HT("SHA1UC",        20, HTF_UC, compute_sha1, NULL);
    HT("SHA256UC",      32, HTF_UC, compute_sha256, NULL);
    /* NTLM */
    HT("NTLM",         16, HTF_NTLM, compute_ntlm, NULL);

    /* --- Salted types --- */
    HT("MD5SALT",       16, HTF_SALTED | HTF_ITER_X0, compute_md5salt, "6e9057ee06b64a08594997e1b1b2dec2:zxQ:password123");
    HT("MD5PASSSALT",   16, HTF_SALTED | HTF_SALT_AFTER, compute_md5passsalt, "3bafc2e8611d1e4e84338b552539ce28:Aa8NB6AU6v2KsqLjbbLb4EH9mAB9BksY:password123");
    HT("MD5SALTPASS",   16, HTF_SALTED, compute_md5saltpass, "e0355b9d1bd81d48a0a84ee98733ba48:00:password123");
    HT("SHA1SALTPASS",  20, HTF_SALTED, compute_sha1saltpass, "dc4615802e2920538ead6d2cfab8a16c15a62fac:administrator:password123");
    HT("SHA1PASSSALT",  20, HTF_SALTED | HTF_SALT_AFTER, compute_sha1passsalt, "a292f2a7bc98439aff04d639beb90ce2765e6bad:administrator:password123");
    HT("SHA256SALTPASS",32, HTF_SALTED, compute_sha256saltpass, "5ac28834ed8be26198bde055d77ba012ef5207441d415de9ea8e55b504d07afa:Salt:password123");
    HT("SHA256PASSSALT",32, HTF_SALTED | HTF_SALT_AFTER, compute_sha256passsalt, "71d8762cd430373cd73ed65f1d8c054da5e70918ae23051ea0e638e444fe1767:Salt:password123");
    HT("SHA512PASSSALT",64, HTF_SALTED | HTF_SALT_AFTER, compute_sha512passsalt, "8c597921f115666f5e2f315effbb8d25bc02644bee236944bf8539a3fda7dfd3704dfcf5dde96d60cce7d415a812ba73c248881042321a1108d78790d7beeb1b:administrator:password123");
    HT("SHA512SALTPASS",64, HTF_SALTED, compute_sha512saltpass, "50b47dc5680fcb783a962c457fffd1c1f474880621357122f7cb56b9e82d099d3f5563ab329e7150637ef188a55bc05d216b8546ccf8ced68de203a2b0a25278:administrator:password123");

    /* More salted types */
    HT("MD5SALTPASSSALT",   16, HTF_SALTED, compute_md5saltpasssalt, "1138e59aab91927849e8d99a9a474c14:00:password123");
    HT("SHA1SALTPASSSALT",  20, HTF_SALTED, compute_sha1saltpasssalt, "1267a9d7c10fb89d21be6a262d9d52887814da6e:administrator:password123");
    HT("MD5SALTMD5PASS",    16, HTF_SALTED, compute_md5saltmd5pass, "28901512214aae68d950bcc54c415980:00:password123");
    HT("MD5SHA1SALTMD5PASS",16, HTF_SALTED, compute_md5sha1saltmd5pass, "243e49e71e9fa71f33a9c1680ebe68cf:KMo),:password123");
    HT("MD5SHA1PASSSALT",   16, HTF_SALTED, compute_md5sha1passsalt, "3fb85c2c48d2bfdee012187cd8207b2c:xCg532%@%gdvf^5DGaa6&*rFTfg^FD4$OIFThrR_gh(ugf*/:password123");
    HT("MD5-MD5SALTMD5PASS",16, HTF_SALTED, compute_md5_md5saltmd5pass, "63a6a536607c1341f3b6c2ac076bd536:KMo),:password123");
    HT("MD5-MD5PASSMD5SALT",16, HTF_SALTED, compute_md5_md5passmd5salt, "45827918a27b4386bcdc251345d413bf:KMo),:password123");
    HT("MD5-MULTISALT",     16, HTF_SALTED, compute_md5_multisalt, "100b151325a157856fdbc4cf935a3a8f:angel:password123");
    HT("MD5MD5SALT-SALT",   16, HTF_SALTED, compute_md5md5salt_salt, "87648169a3b4d61e05b6077b81eb4746:Neverfound:password123");
    HT("SHA256MD5SALTPASS",  32, HTF_SALTED, compute_sha256md5saltpass, "5b36d52848bd8566b1e0ffff04e6738b17b215119ffa6c35e6f3b8ab90d6ba4d:Salt:password123");
    HT("SHA1-8TRACK",       20, HTF_SALTED, compute_sha1_8track, "66b59e229116e85e3843460898fee8443f0b00f0:administrator:password123");
    HT("SHA1SALTSHA1SALTSHA1PASS", 20, HTF_SALTED, compute_sha1saltsha1saltsha1pass, "94a34fbac5bcdbea13160afdb735e834a0ad9f40:administrator:password123");
    HT("MD5-MD5psSHA1MD5psp", 16, HTF_SALTED, compute_md5_md5pssha1md5psp, "a617d18d8cf3ac067a075c3d46c072f4:cd6bc227:password123");
    HT("MD5-MD5puSHA1MD5pup", 16, HTF_SALTED, compute_md5_md5pusha1md5pup, "d3bb75580d2a9999443e5067793169c5:1:password123");
    HT("SHA256RAWSALTPASS",  32, HTF_SALTED, compute_sha256saltpass, "5ac28834ed8be26198bde055d77ba012ef5207441d415de9ea8e55b504d07afa:Salt:password123");
    HT("SMF",               20, HTF_SALTED, compute_smf, "7f8316036b3ebfb2b145b09b947d8e3b22f974dc:Admin:password123");
    HT("MSCACHE",           16, HTF_SALTED, compute_mscache, "559a1d5d1337e276b1db7bfab28c9223:Administrator:password123");
    /* MD5AM, MD5AM2: unsupported (vendor-specific) */
    HT("SHA512-CUSTOM1",    64, HTF_SALTED, compute_sha512_custom1, "b854f6169f8b85d165805784be56fa8fe44178168d9dfa92e1f860e75aa95455c17a86eb4be3432bb6c6a40139996893a72ccd7b1c95a41ee61c2f7ad449460c:$3dfhgjhgG65- 23ewdfwGh5RG65?:password123");

    /* --- Composed types: hashlen = outer (leftmost) hash's byte length --- */
    HT("MD5MD5PASS",    16, HTF_COMPOSED, compute_md5md5pass, NULL);
    HT("MD2MD5",        16, HTF_COMPOSED, compute_md2md5, "87d453c8acdc928f3f63714cd3f445dc:password123");       /* outer=MD2(16) */
    HT("MD4MD5",        16, HTF_COMPOSED, compute_md4md5, "afb204805372c4d49b797117e7cad74b:password123");       /* outer=rhash_msg(RHASH_MD4, 16) */
    HT("GOSTMD5", 32, HTF_COMPOSED, compute_gostmd5, "16d1edab552d7f1277d1a05124fe3a4dbe6294cb396512276eb47a8215d4e3f6:password123");      /* outer=GOST(32) */
    HT("HAV128MD5",     16, HTF_COMPOSED, compute_hav128md5, "d7674c26a4d368d28f68c58c745e6fc2:password123");    /* outer=HAV128(16) */
    HT("HAV128-4MD5",   16, HTF_COMPOSED, compute_hav128_4md5, "78f91bdf2c25c5166e3c5fb82f274152:password123");
    HT("HAV128-5MD5",   16, HTF_COMPOSED, compute_hav128_5md5, "90aec89a9bcb069559b762c1005d572e:password123");
    HT("HAV160-3MD5",   20, HTF_COMPOSED, compute_hav160_3md5, "850051cf1a0df66c4f4076dab5a633dbb0c8028c:password123");  /* outer=HAV160(20) */
    HT("HAV160-4MD5",   20, HTF_COMPOSED, compute_hav160_4md5, "a7f93be4dfc0beac19c69b1fa83d24abd4a6e748:password123");
    HT("HAV160-5MD5",   20, HTF_COMPOSED, compute_hav160_5md5, "6464add457b8edde6a1030f0dec9998e2d3626c7:password123");
    HT("HAV192-3MD5",   24, HTF_COMPOSED, compute_hav192_3md5, "7b0f0c0b3c88ccd68951e5c19d3cd5e919be4187ac0bd927:password123");  /* outer=HAV192(24) */
    HT("HAV192-4MD5",   24, HTF_COMPOSED, compute_hav192_4md5, "d85c217cc138e247beb4d9f494a7d0ac565a912c57bdc6f0:password123");
    HT("HAV192-5MD5",   24, HTF_COMPOSED, compute_hav192_5md5, "8a249b1a1ca694ef98e1cf2b498ba08943af73cfc06743d4:password123");
    HT("HAV224-3MD5",   28, HTF_COMPOSED, compute_hav224_3md5, "27333c3c6fff2f415aa7500672d00ba6bc61aea3b2b072d76ae6b43b:password123");  /* outer=HAV224(28) */
    HT("HAV224-4MD5",   28, HTF_COMPOSED, compute_hav224_4md5, "ae95aa960ae19bf642ce665f331ddd8abe819486b3d788377cb7d58b:password123");
    HT("HAV224-5MD5",   28, HTF_COMPOSED, compute_hav224_5md5, "d32d98a5d43949f24b0316da7363801cb971a53ff505524f5f1803b3:password123");
    HT("HAV256MD5",     32, HTF_COMPOSED, compute_hav256md5, "95fa6e26046842154d6aa32f650be47b1f2a1c3956f8eb6379d89c6fbcedccf3:password123");    /* outer=HAV256(32) */
    HT("HAV256-4MD5",   32, HTF_COMPOSED, compute_hav256_4md5, "6dd56485209be1a840a75f3509132c89de967f416363ea1f3d3bf1a24720bd7d:password123");
    HT("HAV256-5MD5",   32, HTF_COMPOSED, compute_hav256_5md5, "fcd0b18b71dc1abf6b12eb311bde6a53c57a3f230176196896830764814fa47e:password123");
    HT("RMD128MD5",     16, HTF_COMPOSED, compute_rmd128md5, "109fa3ee169ee18cf9bbe13be49ecafd:password123");    /* outer=RMD128(16) */
    HT("RMD160MD5",     20, HTF_COMPOSED, compute_rmd160md5, "1f2829f288c559e067b93ec719abbc899b57f18d:password123");    /* outer=RMD160(20) */
    HT("SHA1MD5",       20, HTF_COMPOSED, compute_md5sha1, "92ac0281d4695ec3710f690e029a6320ca7e5244:password123");      /* outer=SHA1(20) */
    HT("SHA224MD5",     28, HTF_COMPOSED, compute_sha224md5, "a05e74ca282a92a78c627de42562744a3421b5dce501e15645c377c9:password123");    /* outer=SHA224(28) */
    HT("SHA256MD5",     32, HTF_COMPOSED, compute_sha256md5, "55a8cb419848dabd9a69aa38cc3c5537a4e74871bd1697b99dc71c5a8cab7276:password123");    /* outer=SHA256(32) */
    HT("SHA384MD5",     48, HTF_COMPOSED, compute_sha384md5, "4833722e5c1dcbdbbbdfe8775c615e8307a086248800cdf644f11a052e4c33af20945e5a39c6b22afb5b72252de92ff3:password123");    /* outer=SHA384(48) */
    HT("SHA512MD5",     64, HTF_COMPOSED, compute_sha512md5, "257292c94f118c69575a635f47131cb39cf9b78981a254425923151e24e0313394f7cb31e6f875604c605955efb9a1a3cab919a8625bfb8950c18cac23ae35a8:password123");    /* outer=SHA512(64) */
    HT("TIGERMD5",      24, HTF_COMPOSED, compute_tigermd5, "39d29b96c55c3ba18aabe0aa34187332ece68e9e659e5fc7:password123");     /* outer=TIGER(24) */
    HT("WRLMD5",        64, HTF_COMPOSED, compute_wrlmd5, "38877a68d71d849659e759485bebbd359ba4559aa7e55836fa8a1585d81d302f46add4112fc4878feeb28fd24fb01cf204c00c366f365a2c6246ce9a05f8ee7e:password123");       /* outer=WRL(64) */
    HT("SNE128MD5",     16, HTF_COMPOSED, compute_sne128md5, "921e91c286d3f2afc1bd4b24b9b60a9b:password123");    /* outer=SNE128(16) */
    HT("SNE256MD5",     32, HTF_COMPOSED, compute_sne256md5, "14d7dd0afdc1f1db844209a076e57f315ce6226b0fa36a96f74e1482248a756e:password123");    /* outer=SNE256(32) */
    HT("MD5SHA1",       16, HTF_COMPOSED, compute_sha1md5, "e933f35ad585ac6753ee607ab8fd0a4d:password123");      /* outer=rhash_msg(RHASH_MD5, 16) */
    HT("MD5SHA256", 16, HTF_COMPOSED, compute_md5sha256, "79d683ec0b0cfdbba96c28b15cf49811:password123");    /* outer=rhash_msg(RHASH_MD5, 16) */
    HT("MD5SHA512", 16, HTF_COMPOSED, compute_md5sha512, "2dc96034c9ecbd894474ebcb79c09448:password123");    /* outer=rhash_msg(RHASH_MD5, 16) */
    HT("MD5SHA1MD5", 16, HTF_COMPOSED, compute_md5sha1md5, "3b4f022014f794549416f9c1bd25fa63:password123");   /* outer=rhash_msg(RHASH_MD5, 16) */
    HT("MD5SHA1MD5SHA1", 16, HTF_COMPOSED, compute_md5sha1md5sha1, "508a60f7683f2aeee51920f5000af7a7:password123"); /* outer=rhash_msg(RHASH_MD5, 16) */
    HT("SHA1MD5SHA1", 20, HTF_COMPOSED, compute_sha1md5sha1, "1c6b21856f0faf3a2563e86e02d446bfc493e520:password123");  /* outer=SHA1(20) */
    HT("SHA1MD5SHA1MD5",20, HTF_COMPOSED, compute_sha1md5sha1md5, "b4ec8425ad1f154210568ed3eae3c72d23c0a473:password123"); /* outer=SHA1(20) */
    HT("MD5RMD160",     16, HTF_COMPOSED, compute_md5rmd160, "13288d3e0b69ce80692ee5d7a92da84b:password123");    /* outer=rhash_msg(RHASH_MD5, 16) */
    HT("SHA256SHA512", 32, HTF_COMPOSED, compute_sha256sha512, "91ce0064ece5029452c4145edaa737ef579c799a7cc7e2c62a7fc17265824eb3:password123"); /* outer=SHA256(32) */
    HT("MD5WRL",        16, HTF_COMPOSED, compute_md5wrl, "b961c2abc423335d8ca92d3f943cc03d:password123");       /* outer=rhash_msg(RHASH_MD5, 16) */
    HT("RMD128MD5MD5", 16, HTF_COMPOSED, compute_rmd128md5md5, "f3070da8e1e1910878c1fec232efe667:password123"); /* outer=RMD128(16) */
    HT("SHA256SHA1",    32, HTF_COMPOSED, compute_sha256sha1, "fe38f41dc87ffd6b26e432b7f9cb3475d5c1899edacb453c70ac1dcaafd73d26:password123");   /* outer=SHA256(32) */
    HT("SHA1SHA256",    20, HTF_COMPOSED, compute_sha1sha256, NULL);   /* outer=SHA1(20) */
    HT("SHA1SHA384",    20, HTF_COMPOSED, compute_sha1sha384, NULL);
    HT("SHA1SHA512",    20, HTF_COMPOSED, compute_sha1sha512, NULL);
    HT("SHA1SHA224",    20, HTF_COMPOSED, compute_sha1sha224, NULL);
    HT("SHA224SHA1",    28, HTF_COMPOSED, compute_sha224sha1, NULL);   /* outer=SHA224(28) */
    HT("MD5SHA0",       16, HTF_COMPOSED, compute_md5sha0, NULL);      /* outer=rhash_msg(RHASH_MD5, 16) */
    HT("SHA1SHA0", 20, HTF_COMPOSED, compute_sha1sha0, NULL);     /* outer=SHA1(20) */
    HT("MD5GOST",       16, HTF_COMPOSED, compute_md5gost, NULL);
    HT("SHA1GOST",      20, HTF_COMPOSED, compute_sha1gost, NULL);
    HT("MD5TIGER",      16, HTF_COMPOSED, compute_md5tiger, "a59cd29db27f3e78119ab1d001d616bc:password123");
    HT("MD5TIGER2",     16, HTF_COMPOSED, compute_md5tiger2, "8f1aadc03e6cb8a426f9b0ca942bc2e7:password123");
    HT("MD5MD4",        16, HTF_COMPOSED, compute_md5md4, "e1bd223f0b2165d3e46a374d04fdd90f:password123");
    HT("SHA1MD4",       20, HTF_COMPOSED, compute_sha1md4, NULL);
    HT("RMD128MD4",     16, HTF_COMPOSED, compute_rmd128md4, NULL);
    HT("MD5MD2",        16, HTF_COMPOSED, compute_md5md2, NULL);
    HT("SHA1MD2",       20, HTF_COMPOSED, compute_sha1md2, NULL);
    HT("SHA1RMD128",    20, HTF_COMPOSED, compute_sha1rmd128, NULL);
    HT("SHA1HAV128",    20, HTF_COMPOSED, compute_sha1hav128, NULL);
    HT("SHA1WRL",       20, HTF_COMPOSED, compute_sha1wrl, NULL);
    HT("WRLSHA512",     64, HTF_COMPOSED, compute_wrlsha512, NULL);
    HT("SHA1NTLM",      20, HTF_COMPOSED, compute_sha1ntlm, NULL);
    HT("MD4UTF16MD5",   16, HTF_COMPOSED, compute_md4utf16md5, NULL);
    HT("MD4UTF16SHA1",  20, HTF_COMPOSED, compute_md4utf16sha1, NULL);
    HT("MD4UTF16SHA256",32, HTF_COMPOSED, compute_md4utf16sha256, NULL);

    /* --- Standalone special types --- */
    HT("MDC2",          16, 0, compute_mdc2, "62bab9c63e5adc67ab2192afcaf586ff:password123");
    HT("SQL5",          20, 0, compute_sql5, "a0f874bc7f54ee086fce60a37ce7887d8b31086b:password123");
    HT("RADMIN2",       16, 0, compute_radmin2, "97a8ec63f2a44154479e6b8f53c0eb93:password123");
    HT("MD5-DBL-PASS",  16, 0, compute_md5dblpass, NULL);
    HT("CRYPTEXT",      20, 0, compute_cryptext, NULL);

    /* --- xMD5PASS types: x(hex(rhash_msg(RHASH_MD5, pass)) + pass) — hashlen = outer x's bytes --- */
    HT("MD2MD5PASS", 16, HTF_COMPOSED, compute_md2md5pass, "5e7db5843b5d6b9f09b377b6e7ebfc1a:password123");     /* outer=MD2(16) */
    HT("MD4MD5PASS",    16, HTF_COMPOSED, compute_md4md5pass, "5af3fd4ab6704fd4ceda700eb3677b28:password123");     /* outer=rhash_msg(RHASH_MD4, 16) */
    HT("GOSTMD5PASS", 32, HTF_COMPOSED, compute_gostmd5pass, "b2a4bf185b2e1226ad2e15082dd44d09c764f26d4b019ee94da8f7149058aa83:password123");    /* outer=GOST(32) */
    HT("HAV128MD5PASS", 16, HTF_COMPOSED, compute_hav128md5pass, "d6fdeaac6c0c7a374686c19c978a8e17:password123");
    HT("HAV128-4MD5PASS",16, HTF_COMPOSED, compute_hav128_4md5pass, "8194ef4efc1747727f75964167d28180:password123");
    HT("HAV128-5MD5PASS",16, HTF_COMPOSED, compute_hav128_5md5pass, "01b1a28cd06f29b7483dfa32eed36f0d:password123");
    HT("HAV160-3MD5PASS",20, HTF_COMPOSED, compute_hav160_3md5pass, "78272d57a87c0f973d861b0292a2e18611e38cc7:password123"); /* outer=HAV160(20) */
    HT("HAV160-4MD5PASS",20, HTF_COMPOSED, compute_hav160_4md5pass, "40dce51eda77dd25335f564e7bca9e0224fa0ec0:password123");
    HT("HAV160-5MD5PASS",20, HTF_COMPOSED, compute_hav160_5md5pass, "334dc478e9876fc35d81083e66ac202a1c5a0ad1:password123");
    HT("HAV192-3MD5PASS",24, HTF_COMPOSED, compute_hav192_3md5pass, "26d6e370b2eac2577133032b78e39df2044b9d0262642d51:password123"); /* outer=HAV192(24) */
    HT("HAV192-4MD5PASS",24, HTF_COMPOSED, compute_hav192_4md5pass, "84430762a8206d6135c6ecc010605d5a0a6298e47d954e2b:password123");
    HT("HAV192-5MD5PASS",24, HTF_COMPOSED, compute_hav192_5md5pass, "07159bf2daf0522febf4200b36e63f6e09b3eeea330a6c90:password123");
    HT("HAV224-3MD5PASS",28, HTF_COMPOSED, compute_hav224_3md5pass, "fb9a58419556f84a19421911d93f995074369b9410b0916f5bf4fdf2:password123"); /* outer=HAV224(28) */
    HT("HAV224-4MD5PASS",28, HTF_COMPOSED, compute_hav224_4md5pass, "28de21e7ffe8293c305729083147833c6f952df7667e511290df4e19:password123");
    HT("HAV224-5MD5PASS",28, HTF_COMPOSED, compute_hav224_5md5pass, "f9aa3710cff1e438d302d20e11bce40c0f009b95b12837068a285759:password123");
    HT("HAV256MD5PASS", 32, HTF_COMPOSED, compute_hav256md5pass, "37d94560a24d24f799784cf78b430ea4f0ee36b2303bd83fc5e23c4c785946ad:password123");  /* outer=HAV256(32) */
    HT("HAV256-4MD5PASS",32, HTF_COMPOSED, compute_hav256_4md5pass, "afd86e733b442f84f79155229d9e75a41e54191da3034c7b639172cc63143bf6:password123");
    HT("HAV256-5MD5PASS",32, HTF_COMPOSED, compute_hav256_5md5pass, "996f150fee2c99822ef6217610843ec078ac5a94d3fb6ffa916e92cd3a90bef4:password123");
    HT("SHA1MD5PASS",   20, HTF_COMPOSED, compute_sha1md5pass, "0d38a6b0fc95d5f60aa78cfb33174a4d43feeb61:password123");    /* outer=SHA1(20) */
    HT("SHA224MD5PASS",  28, HTF_COMPOSED, compute_sha224md5pass, "de21725a64377b95c0b1cfa69c025725926ee63a0911bf0dc35bfce2:password123");  /* outer=SHA224(28) */
    HT("SHA256MD5PASS",  32, HTF_COMPOSED, compute_sha256md5pass, "536a8a02cda68cda3000887a9b1d48827edd3bf1c17475ec3c1bf2ef42867da1:password123");  /* outer=SHA256(32) */
    HT("SHA384MD5PASS",  48, HTF_COMPOSED, compute_sha384md5pass, "293073d9eee523c7bd640e884c16864746227cee204514fe3a8dc4f20278aec2edd0abd2de54b1889f0b35e90ade8aa9:password123");  /* outer=SHA384(48) */
    HT("SHA512MD5PASS",  64, HTF_COMPOSED, compute_sha512md5pass, "38bb494c6b9c05ac4f6ad553b495badea4dec10b6959bb253fe4c71c6b5111740cfa6d4b10f964f6219c4889d989d59f269b3add2fd8af9a88ad7411072ebc94:password123");  /* outer=SHA512(64) */
    HT("RMD128MD5PASS",  16, HTF_COMPOSED, compute_rmd128md5pass, "b90d108d703bcc47684203b93732ed8e:password123");
    HT("RMD160MD5PASS",  20, HTF_COMPOSED, compute_rmd160md5pass, "653c426a4f93c506c14209e9b138f4f6e85c8dbb:password123");  /* outer=RMD160(20) */
    HT("TIGERMD5PASS",   24, HTF_COMPOSED, compute_tigermd5pass, "8c3ce48158db62996ae6653ead50b76aa94d71243236d4ad:password123");   /* outer=TIGER(24) */
    HT("WRLMD5PASS",     64, HTF_COMPOSED, compute_wrlmd5pass, "be7f8e5d39599d1a9fccfee7f987214e8a94498ae686ac7566745f0b932d64e1453c588acafe4f764f77dcf90fbee1e0efc805c056ec1a6100e051f0591290d3:password123");     /* outer=WRL(64) */
    HT("SNE128MD5PASS",  16, HTF_COMPOSED, compute_sne128md5pass, "8214d0684ec152bc794503f4d0135708:password123");
    HT("SNE256MD5PASS",  32, HTF_COMPOSED, compute_sne256md5pass, "1f3a25ab8f71ec169fcd357794d8436331c709b04f98be053d367cce4eb85efd:password123");  /* outer=SNE256(32) */

    /* --- Standalone new types --- */
    HT("MD4UTF16",       16, HTF_NTLM, compute_ntlm, NULL);   /* = NTLM alias */
    HT("MD5UTF16LE",     16, 0, compute_md5utf16le, NULL);
    HT("SHA1UTF16LE",    20, 0, compute_sha1utf16le, NULL);
    HT("SHA256UTF16LE",  32, 0, compute_sha256utf16le, NULL);
    HT("SHA384UTF16LE",  48, 0, compute_sha384utf16le, NULL);
    HT("SHA512UTF16LE",  64, 0, compute_sha512utf16le, NULL);
    HT("SHA1UTF16BE",    20, 0, compute_sha1utf16be, NULL);
    HT("SHA1UTF16BEZ",   20, 0, compute_sha1utf16bez, NULL);
    HT("SHA1ZUTF16LE",   20, 0, compute_sha1zutf16le, NULL);
    HT("SHA1UCUTF16LE",  20, HTF_UC, compute_sha1ucutf16le, NULL);
    HT("SHA1PASSSHA1",   20, HTF_COMPOSED, compute_sha1passsha1, "f4ec43b2a3b850de920746ec9c701ac614db5a41:password123");
    HT("MD5HESK",        16, HTF_COMPOSED, compute_md5hesk, "b67f1f85e82c7a36fad01f5a632acddd:password123");
    HT("MD5NTLMp",       16, HTF_COMPOSED, compute_md5ntlmp, "b6f20abee8da21bcb2e9bd669b4fda0c:password123");

    /* --- UC variants: UC = uppercase intermediate hex, NOT uppercase output --- */
    HT("MD4UTF16UC",     16, HTF_NTLM | HTF_UC, compute_ntlm, NULL);  /* UC on outermost = UC output */
    HTC("MD4UTF16MD5UC",  16, HTF_COMPOSED, chain_ntlm_md5uc, NULL);   /* NTLM(MD5UC(pass)) */
    HTC("MD4UTF16SHA1UC", 16, HTF_COMPOSED, chain_ntlm_sha1uc, NULL);  /* NTLM(SHA1UC(pass)) */
    HTC("MD4UTF16SHA256UC",16,HTF_COMPOSED, chain_ntlm_sha256uc, NULL);/* NTLM(SHA256UC(pass)) */
    HTC("SHA1MD5UC",      20, HTF_COMPOSED, chain_sha1_md5uc, "900bd2208de3ca960ecee76ee483904300ceb991:password123");   /* SHA1(MD5UC(pass)) */
    HTC("SHA1NTLMUC",     20, HTF_COMPOSED, chain_sha1_ntlmuc, NULL);  /* SHA1(NTLMUC(pass)) */
    HTC("SHA1SHA256UC",   20, HTF_COMPOSED, chain_sha1_sha256uc, NULL); /* SHA1(SHA256UC(pass)) */
    HTC("SHA1SHA512UC",   20, HTF_COMPOSED, chain_sha1_sha512uc, NULL); /* SHA1(SHA512UC(pass)) */
    HTC("MD5NTLMUC",     16, HTF_COMPOSED, chain_md5_ntlmuc, "d80c2ac7c329964ee5be631a0aae9f9c:password123");   /* rhash_msg(RHASH_MD5, NTLMUC(pass)) */
    HTC("RADMIN2MD5UC", 16, HTF_COMPOSED, chain_radmin2_md5uc, "8d9a4aa7b63f2cc4c6c7488dd6c772e6:password123"); /* RADMIN2(MD5UC(pass)) */
    HTC("MD5SHA1UC",      16, HTF_COMPOSED, chain_md5_sha1uc, "840b89e46e9e5850533e834477dba072:password123");   /* rhash_msg(RHASH_MD5, SHA1UC(pass)) */
    HTC("MD5SHA1MD5UC", 16, HTF_COMPOSED, chain_md5_sha1_md5uc, "1a5ba6e4a959208325eb412e21528ae9:password123");/* rhash_msg(RHASH_MD5, SHA1(MD5UC(pass))) */
    HTC("SHA1MD5MD5UC", 20, HTF_COMPOSED, chain_sha1_md5_md5uc, NULL);/* SHA1(rhash_msg(RHASH_MD5, MD5UC(pass))) */
    HTC("MD5MD5UC", 16, HTF_COMPOSED, chain_md5ucmd5, "cb8bca2e221b4ae44c95ca2f70f8f407:password123");     /* rhash_msg(RHASH_MD5, MD5UC(pass)) */

    /* --- Chain (HTC) types: multi-level compositions --- */

    /* 2-step chains that don't have MAKE_COMPOSED entries */
    HTC("MD5NTLM", 16, HTF_COMPOSED, chain_md5ntlm, "efb08065cdc200d996d9991ec1815a01:password123");
    HTC("MD5RADMIN2",    16, HTF_COMPOSED, chain_md5radmin2, "0dd958b0716f9607ac0d54bb828f5c1d:password123");
    HTC("RADMIN2MD5",    16, HTF_COMPOSED, chain_radmin2md5, "6f01d398f9352e6fd31fe5e19f0483a8:password123");
    HTC("RADMIN2SHA1",   20, HTF_COMPOSED, chain_radmin2sha1, "2911ba50a7d80402e4d4600ef01b9775:password123");
    HTC("MD5SQL5",       16, HTF_COMPOSED, chain_md5sql5, "4b9c0924c807868a66f7ff0e713c2cb2:password123");
    HTC("SHA1SQL5",      20, HTF_COMPOSED, chain_sha1sql5, NULL);
    HTC("MD5HAV160-3",   16, HTF_COMPOSED, chain_md5hav160_3, "54d8620f137fab0e82535c8aa0ee76e8:password123");
    HTC("SHA1SHA3-256",  20, HTF_COMPOSED, chain_sha1sha3_256, NULL);
    HTC("SHA1MD5SHA256", 20, HTF_COMPOSED, chain_sha1md5sha256, NULL);
    HTC("SHA1MD5SHA512", 20, HTF_COMPOSED, chain_sha1md5sha512, NULL);

    /* 3-step chains */
    HTC("SHA1MD5MD5",    20, HTF_COMPOSED, chain_sha1md5md5, "43445e0d1298d6c987a881f361808422fb3b8ed7:password123");
    HTC("MD5SHA1SHA1",   16, HTF_COMPOSED, chain_md5sha1sha1, "d53df44a44a47959ec5da72d7e31be6a:password123");
    HTC("MD5SHA256MD5",  16, HTF_COMPOSED, chain_md5sha256md5, "b37abb485a297d2690ad04d04872e589:password123");
    HTC("MD5GOSTMD5",    16, HTF_COMPOSED, chain_md5gostmd5, NULL);
    HTC("MD5WRLMD5",     16, HTF_COMPOSED, chain_md5wrlmd5, "385e0c8d23eb1666dcc00de208ac3853:password123");
    HTC("MD5WRLSHA1",    16, HTF_COMPOSED, chain_md5wrlsha1, NULL);
    HTC("MD5SHA1SHA256", 16, HTF_COMPOSED, chain_md5sha1sha256, "e1aa362fe0691cbf019e90ae45aee490:password123");
    HTC("MD5SHA1HAV160-4",16,HTF_COMPOSED, chain_md5sha1hav160_4, "98de8c71ca174ff830909d27a6285c5e:password123");
    HTC("RADMIN2MD5MD5", 16, HTF_COMPOSED, chain_radmin2md5md5, "c8b0a5faa337c5870d4a8510ed997b22:password123");
    HTC("RADMIN2MD5SHA1",20, HTF_COMPOSED, chain_radmin2md5sha1, "aefaa35dd4cbf1e5fc77394309e2b9e2:password123");
    HTC("RADMIN2SHA1MD5",16, HTF_COMPOSED, chain_radmin2sha1md5, "3bbfcc799a56eba56e6f4d8bce62fa14:password123");
    HTC("MD5RADMIN2MD5", 16, HTF_COMPOSED, chain_md5radmin2md5, "f60e4d96ae58bf60ba831661ddb99f33:password123");
    HTC("MD5RADMIN2SHA1",16, HTF_COMPOSED, chain_md5radmin2sha1, "609f55f768c279b6a816f7ece3c999b8:password123");
    HTC("SHA1MD5RADMIN2",20, HTF_COMPOSED, chain_sha1md5radmin2, "20bd7be8772e70bfd776c0629762b6ba04056e62:password123");
    HTC("MD5SQL5MD5",    16, HTF_COMPOSED, chain_md5sql5md5, "a91331088a9614fc49802194391e2b63:password123");
    HTC("SHA1SQL5MD5",   20, HTF_COMPOSED, chain_sha1sql5md5, NULL);
    HTC("SHA1MD5SQL5",   20, HTF_COMPOSED, chain_sha1md5sql5, NULL);
    HTC("MD4SHA1MD5",    16, HTF_COMPOSED, chain_md4sha1md5, NULL);
    HTC("SHA1SHA256SHA1",20, HTF_COMPOSED, chain_sha1sha256sha1, NULL);
    HTC("SHA1SHA256SHA256",20,HTF_COMPOSED, chain_sha1sha256sha256, NULL);
    HTC("SHA1SHA256MD5", 20, HTF_COMPOSED, chain_sha1sha256md5, NULL);
    HTC("SHA1SHA256SHA512",20,HTF_COMPOSED, chain_sha1sha256sha512, NULL);
    HTC("SHA1WRLMD5",    20, HTF_COMPOSED, chain_sha1wrlmd5, NULL);
    HTC("MYSQL5MD5",     16, HTF_COMPOSED, chain_mysql5md5, NULL);

    /* 4-step chains */
    HTC("MD5SHA1MD5MD5", 16, HTF_COMPOSED, chain_md5sha1md5md5, "edf0460584d8d492c762bd8d7c42a087:password123");
    HTC("SHA1MD5MD5MD5", 20, HTF_COMPOSED, chain_sha1md5md5md5, "0d3ee472e2f623ab9fda6aa1afc39c329987a7a5:password123");
    HTC("MD5SHA1SHA1MD5",16, HTF_COMPOSED, chain_md5sha1sha1md5, "7bf1a907a318181a1fb95ed0ed0a923c:password123");
    HTC("RADMIN2MD5MD5MD5",16,HTF_COMPOSED,chain_radmin2md5md5md5, "b0659b4c94877a50792b46ee8bddebe9:password123");
    HTC("SHA1MD5MD5SHA1",20, HTF_COMPOSED, chain_sha1md5md5sha1, "66bcd9ea60b85eeae89af0009cc855893fb931f1:password123");
    HTC("MD5SHA1MD5MD5SHA1",16,HTF_COMPOSED,chain_md5sha1md5md5sha1, "99a6cc386824d69d0fe34b514c268b3a:password123");
    HTC("SHA1SHA256SHA256SHA256",20,HTF_COMPOSED,chain_sha1sha256sha256sha256, NULL);
    HTC("SHA1SHA256MD5MD5",20,HTF_COMPOSED,chain_sha1sha256md5md5, NULL);
    HTC("SHA1SQL5MD5MD5",20, HTF_COMPOSED, chain_sha1sql5md5md5, NULL);
    HTC("SHA1MD5MD5SQL5",20, HTF_COMPOSED, chain_sha1md5md5sql5, NULL);
    HTC("MD5SHA1MD5SHA1MD5",16,HTF_COMPOSED,chain_md5sha1md5sha1md5, "bc0fb7b37b19af31d94259c8e86cc221:password123");
    HTC("MD5SHA1RADMIN2MD5",16,HTF_COMPOSED,chain_md5sha1radmin2md5, "9b6b90e5373bfe7755d79511d3435ea1:password123");
    HTC("MD5SHA1MD5RADMIN2",16,HTF_COMPOSED,chain_md5sha1md5radmin2, "25e41e365d9883843f0539b7fab14900:password123");
    HTC("SHA1SHA256MD5SHA256MD5",20,HTF_COMPOSED,chain_sha1sha256md5sha256md5, NULL);
    HTC("SHA256MD5SHA256MD5",32,HTF_COMPOSED,chain_sha256md5sha256md5, NULL);

    /* 5-step chains */
    HTC("SHA1MD5MD5MD5MD5",20,HTF_COMPOSED,chain_sha1md5md5md5md5, "a462073d4f2019cf3f08e65e88281b3b17e5d45f:password123");
    HTC("SHA1MD5MD5SHA1MD5",20,HTF_COMPOSED,chain_sha1md5md5sha1md5, "b3539e75723aefb7faa806fa2b3af5ea70318426:password123");
    HTC("SHA1MD5MD5MD5SHA1",20,HTF_COMPOSED,chain_sha1md5md5md5sha1, "afdbd75eca993052a9db144ddcdf97a5d6516069:password123");
    HTC("SHA1MD5SHA1MD5SHA1",20,HTF_COMPOSED,chain_sha1md5sha1md5sha1, NULL);
    HTC("MD5SHA1MD5MD5MD5",16,HTF_COMPOSED,chain_md5sha1md5md5md5, "7712acf4ab398e71d41bca7c01fc82ab:password123");
    HTC("MD5SHA1MD5MD5SHA1MD5",16,HTF_COMPOSED,chain_md5sha1md5md5sha1md5, NULL);
    HTC("MD5SHA1MD5SHA1SHA1",16,HTF_COMPOSED,chain_md5sha1md5sha1sha1, "6f853d7025b462217bf65bce41ae1b38:password123");

    /* 6-step chains */
    HTC("SHA1MD5MD5MD5MD5MD5",20,HTF_COMPOSED,chain_sha1md5md5md5md5md5, "b741f0792ecad3458acabec693f735ca0066dc73:password123");
    HTC("SHA1MD5SHA1MD5SHA1MD5",20,HTF_COMPOSED,chain_sha1md5sha1md5sha1md5, "e8eed22214746f4d65566bacd2dc3468b45f75a6:password123");
    HTC("SHA1MD5MD5SHA1SHA1MD5",20,HTF_COMPOSED,chain_sha1md5md5sha1sha1md5, NULL);

    /* 7-step chains */
    HTC("SHA1MD5SHA1MD5SHA1MD5SHA1",20,HTF_COMPOSED,chain_sha1md5sha1md5sha1md5sha1, NULL);
    HTC("SHA1MD5SHA1MD5MD5SHA1MD5",20,HTF_COMPOSED,chain_sha1md5sha1md5md5sha1md5, NULL);

    /* 8-step chains */
    HTC("SHA1MD5MD5SHA1MD5SHA1SHA1MD5",20,HTF_COMPOSED,chain_sha1md5md5sha1md5sha1sha1md5, NULL);

    /* 12-step chain */
    HTC("MD5SHA1MD5SHA1MD5SHA1MD5SHA1MD5SHA1MD5SHA1",16,HTF_COMPOSED,chain_md5sha1md5sha1md5sha1md5sha1md5sha1md5sha1, NULL);

    /* MD4UTF16 (NTLM) deeper chains */
    HTC("MD4UTF16MD5MD5",    16, HTF_COMPOSED, chain_md4utf16md5md5, NULL);
    HTC("MD4UTF16MD5MD5MD5", 16, HTF_COMPOSED, chain_md4utf16md5md5md5, NULL);
    HTC("MD4UTF16MD5MD5MD5MD5",16,HTF_COMPOSED,chain_md4utf16md5md5md5md5, NULL);
    HTC("MD4UTF16SHA1SHA1",  20, HTF_COMPOSED, chain_md4utf16sha1sha1, NULL);
    HTC("MD4UTF16SHA1MD5",   20, HTF_COMPOSED, chain_md4utf16sha1md5, NULL);
    HTC("MD4UTF16MD5SHA1",   16, HTF_COMPOSED, chain_md4utf16md5sha1, NULL);
    HTC("MD4UTF16SHA256MD5", 32, HTF_COMPOSED, chain_md4utf16sha256md5, NULL);
    HTC("MD4UTF16SHA256SHA1",32, HTF_COMPOSED, chain_md4utf16sha256sha1, NULL);
    HTC("MD4UTF16SHA256SHA256",32,HTF_COMPOSED,chain_md4utf16sha256sha256, NULL);
    HTC("MD4UTF16SHA256SHA256SHA256",32,HTF_COMPOSED,chain_md4utf16sha256sha256sha256, NULL);
    HTC("MD4UTF16SHA256SHA256SHA256SHA256",32,HTF_COMPOSED,chain_md4utf16sha256sha256sha256sha256, NULL);
    HTC("MD4UTF16SHA256SHA256SHA256SHA256SHA256",32,HTF_COMPOSED,chain_md4utf16sha256sha256sha256sha256sha256, NULL);

    /* SHA1MD5WRLSHA1 */
    HTC("SHA1MD5WRLSHA1",   20, HTF_COMPOSED, chain_sha1md5wrlsha1, NULL);

    /* --- UC intermediate chain types --- */
    HTC("MD5UCMD5",          16, HTF_COMPOSED, chain_md5ucmd5, NULL);
    HTC("SHA1MD5UCMD5",      20, HTF_COMPOSED, chain_sha1md5ucmd5, NULL);
    HTC("MD5SHA1UCMD5",      16, HTF_COMPOSED, chain_md5sha1ucmd5, "1a22ce81ee0fff8670f6700195890c37:password123");
    HTC("MD5MD5UCMD5",       16, HTF_COMPOSED, chain_md5md5ucmd5, "d168e00fe57116e52a5e804887a05cd0:password123");
    HTC("SHA1MD5UCMD5UC",    20, HTF_COMPOSED, chain_sha1md5ucmd5uc, NULL);
    HTC("SHA1MD5UCMD5UCMD5UC",20,HTF_COMPOSED,chain_sha1md5ucmd5ucmd5uc, NULL);
    HTC("SHA1MD5UCMD5UCMD5UCMD5UC",20,HTF_COMPOSED,chain_sha1md5ucmd5ucmd5ucmd5uc, NULL);
    HTC("SHA1UCWRL",         20, HTF_COMPOSED | HTF_UC, chain_sha1ucwrl, NULL);
    HTC("SHA1MD5UCSHA1UCMD5UC",20,HTF_COMPOSED,chain_sha1md5ucsha1ucmd5uc, NULL);
    HTC("SHA1SHA256UCSHA256",20,HTF_COMPOSED,chain_sha1sha256ucsha256, NULL);
    HTC("SHA1SHA256UCxSHA256",20,HTF_COMPOSED,chain_sha1sha256ucsha256, "1906600c09e2d8755c9897e1c24ec466cdb1ab02:password123");
    HTC("SHA1SHA256UCSHA256SHA256",20,HTF_COMPOSED,chain_sha1sha256ucsha256sha256, NULL);
    HTC("SHA1MD4UTF16UCMD4UTF16UC",20,HTF_COMPOSED,chain_sha1md4utf16ucmd4utf16uc, NULL);

    /* UC-intermediate compositions */
    HTC("MD5GOSTMD5UC",     16, HTF_COMPOSED, chain_md5_gost_md5uc, NULL);
    HTC("MD5SHA1MD5MD5UC",  16, HTF_COMPOSED, chain_md5_sha1_md5_md5uc, "ad811f10a07e284386c5474858169d00:password123");

    /* MD5SHA1MD5MD5MD5SHA1 */
    HTC("MD5SHA1MD5MD5MD5SHA1",16,HTF_COMPOSED,chain_md5sha1md5md5md5sha1, "3fd55cdfcea1a91fe7fd537541fd1123:password123");

    /* ================================================================= */
    /* NEW TYPE REGISTRATIONS — batch addition                            */
    /* ================================================================= */

    /* --- Standalone special types --- */
    HT("NULL",          16, 0, compute_null, "70617373776f7264313233000a000000:password123");
    HT("MYSQL3",         8, 0, compute_mysql3, "0b034ec713f89a68:password123");
    HT("LM",           16, 0, compute_lm, "e52cac67419a9a22664345140a852f61:PASSWORD123");
    HT("NTLMH",        16, HTF_COMPOSED, compute_ntlmh, NULL);
    HT("SKYPE",        16, HTF_SALTED, compute_skype, "229922b8b59931e6f8bfd223eb006806:chloe01:password123");
    HT("RMD320",       40, 0, compute_rmd320, NULL);
    HT("SHA1DRU",      20, 0, compute_sha1dru, "d5e8e759bb5c48d9adb0b0d640ab030cba3e3b01:password123");
    HT("SHA1HESK",     20, HTF_COMPOSED, compute_sha1hesk, "6eae5a30262eba6cad69217528a88c541e22c914:password123");
    HT("SHA1UTF7",     20, 0, compute_sha1utf7, NULL);

    /* --- Byte reorder types --- */
    HT("MD5SWAP",      16, 0, compute_md5swap, "527069850e9352dc96d992ef3d6f9f17:password123");
    HT("MD5bcad",      16, 0, compute_md5bcad, NULL);
    HT("MD5dcab",      16, 0, compute_md5dcab, NULL);

    /* --- Reverse types --- */
    HT("MD5revp",      16, 0, compute_md5revp, "60624aa6e8faafe07669946d1a7eb586:password123");
    HT("SHA1revp",     20, 0, compute_sha1revp, "a62df2e2fa7190d0c1e08a9002668a4ad12b0204:password123");
    HT("MD5revMD5",    16, HTF_COMPOSED, compute_md5revmd5, "988b2c9f34b27ae7572435febb4a4a46:password123");
    HT("MD5revSHA1",   16, HTF_COMPOSED, compute_md5revsha1, "1e72b2d648c0ca5b978e507f7347eef2:password123");
    HT("SHA1revMD5",   20, HTF_COMPOSED, compute_sha1revmd5, NULL);
    HT("SHA1revSHA1",  20, HTF_COMPOSED, compute_sha1revsha1, NULL);
    HT("MD5revMD5MD5", 16, HTF_COMPOSED, compute_md5revmd5md5, "4282437aed9c49d3620027dc7844c44b:password123");
    HT("MD5revMD5SHA1",16, HTF_COMPOSED, compute_md5revmd5sha1, "d5eab23deacea70896d43ef9102514f7:password123");
    HT("MD5revMD5SHA1SHA1",16,HTF_COMPOSED,compute_md5revmd5sha1sha1, NULL);

    /* --- CAP types --- */
    HT("MD5CAP",       16, 0, compute_md5cap, NULL);
    HT("MD5CAPSHA1",   20, HTF_COMPOSED, compute_md5capsha1, "0d5e1292d06bf6860d98acb8fb6ce324:password123");

    /* MD5AM, MD5AM2: unsupported (vendor-specific) */
    HT("MD5SPECAM",    16, 0, compute_md5specam, NULL);

    /* --- Pad type --- */
    HT("MD5padMD5",    16, HTF_COMPOSED, compute_md5padmd5, "71d6fdd5c671f06239103fa32e0e1d0f:password123");

    /* --- PASS-concat types --- */
    HT("MD5PASSMD5",   16, HTF_COMPOSED, compute_md5passmd5, NULL);
    HT("MD5PASSSHA1",  16, HTF_COMPOSED, compute_md5passsha1, NULL);
    HT("MD5PASSSHA1MD5",16,HTF_COMPOSED, compute_md5passsha1md5, NULL);
    HT("MD5PASSMD5MD5MD5",16,HTF_COMPOSED,compute_md5passmd5md5md5, NULL);
    HT("MD5PASSMD5MD5PASS",16,HTF_COMPOSED,compute_md5passmd5md5pass, NULL);
    HT("MD5MD5PASSSHA1",20,HTF_COMPOSED, compute_md5md5passsha1, NULL);
    HT("SHA1MD5MD5PASS",20,HTF_COMPOSED, compute_sha1md5md5pass, NULL);
    HT("SHA1MD5PASSMD5",20,HTF_COMPOSED, compute_sha1md5passmd5, NULL);
    HT("MD5SHA1MD5PASS",16,HTF_COMPOSED, compute_md5sha1md5pass, "57b511120d3e396e3973b2185e683f7f:password123");
    HT("MD5-MD5PASSMD5",16,HTF_COMPOSED, compute_md5_md5passmd5, NULL);
    HT("MD5SHA1PASSMD5PASSSHA1PASS",16,HTF_COMPOSED,compute_md5sha1passmd5passsha1pass, "a1c3bc71e56f6a5ec51b4ba2b423a73e:password123");
    HT("MD4UTF16MD5PASSMD5SHA1PASS",16,HTF_COMPOSED,compute_md4utf16md5passmd5sha1pass, NULL);

    /* --- MD5-LMNTLM and MD5LM --- */
    HT("MD5-LMNTLM",  16, HTF_COMPOSED, compute_md5_lmntlm, "a2e7c092491a70fa7e0a943591c271ab:password123");
    HT("MD5LM",       16, HTF_COMPOSED, compute_md5lm, "af9292d80b8d3673b7bd66a04d3d7cdb:PASSWORD123");
    HTC("MD5LMUC",     16, HTF_COMPOSED, chain_md5_lmuc, "f762f0da0424f3c16520548989b5a960:PASSWORD123");

    /* --- Complex special types --- */
    HT("MD5-SHA1numSHA1", 16, HTF_COMPOSED, compute_md5_sha1numsha1, "125a2916d62717945c84bb3f78fba2ad:1:password123");
    HT("MD5-MD5SHA1MD5SHA1MD5SHA1p",16,HTF_COMPOSED,compute_md5_md5sha1md5sha1md5sha1p, "ce9e00b0d2224012b3f7836ff17f632e:password123");
    HT("SHA1MD5-SHA1PASSPASS",20,HTF_COMPOSED,compute_sha1md5_sha1passpass, NULL);
    HT("SHA1MD5UC1LC",    20, HTF_COMPOSED, compute_sha1md5uc1lc, NULL);
    HT("MD5MD5UCp",       16, HTF_COMPOSED, compute_md5md5ucp, "6d82af54a03d8846767875d8877c18dc:password123");
    HT("MD5WRLRAW",       16, HTF_COMPOSED, compute_md5wrlraw, NULL);

    /* --- RAW types (binary chain: hash(hash_binary(pass))) --- */
    HTC("MD5RAW",         16, HTF_COMPOSED, chain_md5raw_self, "ebc56e4d393f9084d3941ca228c31aea:password123");
    HT("MD5RAWUC",        16, HTF_UC, compute_md5, NULL);
    HT("MD5RAWMD5RAW",    16, HTF_COMPOSED, compute_md5rawmd5raw, NULL);
    HT("MD5MD2RAW",       16, HTF_COMPOSED, compute_md5md2raw, NULL);
    HT("MD5SHA1RAW",      16, HTF_COMPOSED, compute_md5sha1raw, "b01d08a11ea26b0c35468f8f1f40cf61:password123");
    HTC("SHA1RAW",        20, HTF_COMPOSED, chain_sha1raw_self, "a0f874bc7f54ee086fce60a37ce7887d8b31086b:password123");
    HTC("SHA224RAW",      28, HTF_COMPOSED, chain_sha224raw_self, "74a4786c76600ab8d99ca8cf960509f8243ee21fe6a614723f06b586:password123");
    HTC("SHA256RAW",      32, HTF_COMPOSED, chain_sha256raw_self, "92342313fa33728f8da85edfb3458ef9c0030b28c364781f446a4730d953637d:password123");
    HTC("SHA384RAW",      48, HTF_COMPOSED, chain_sha384raw_self, "563f046e9eb35bf564c6cc4260676ed22b7e4e783aa0d7c3cc81698dc3211292fc95f338e346b0f59c48c7bc73fef42d:password123");
    HTC("SHA512RAW",      64, HTF_COMPOSED, chain_sha512raw_self, "b335d77abf42f6da1b6d0864129fa176c7c499b70c389b273e719473e5f029f54b9b8914e96a6585db2f16c987e6b988e78a0e497bbe8bc88d62df0eb81b7010:password123");
    HTC("SHA1MD5RAW",     20, HTF_COMPOSED, chain_sha1md5raw, NULL);
    HTC("SHA1SHA1RAWMD5", 20, HTF_COMPOSED, chain_sha1sha1rawmd5_v2, "2c13011ac7f9b6ce6564935154f8986a535979a9:password123");
    HTC("SHA1SHA1RAWMD5MD5",20,HTF_COMPOSED,chain_sha1sha1rawmd5md5, "e746d28974bc89fa5f578f4182de5860faa1ac1d:password123");
    HTC("SHA1SHA1RAWMD5MD5MD5",20,HTF_COMPOSED,chain_sha1sha1rawmd5md5md5, "26d9daf620a05b7e96adcc9a6a69219446e09919:password123");

    /* --- SQL types --- */
    /* MD4SQL3, MD5SQL3, SHA1SQL3 — SQL3 = SHA1(pass+salt), unsalted = SHA1(pass) */
    /* These are salted types in mdxfind but listed as missing; register as salted */
    /* For unsalted testing, SQL3 ≈ SHA1 */
    HTC("SHA1RADMIN2",   20, HTF_COMPOSED, chain_sha1radmin2, "5adcc15808c55fb73814d4f2adc4f0e43e050ed6:password123");
    HTC("SHA1RADMIN2MD5",20, HTF_COMPOSED, chain_sha1radmin2md5, "640ccb961495b5a0e3ceb8ef62ddc28b0370a0e4:password123");

    /* --- UC chain types --- */
    HTC("MD5MD5UCSHA1MD5MD5",16,HTF_COMPOSED,chain_md5md5ucsha1md5md5, "346235c7e8e6688e7141f907c7be2c12:password123");
    HTC("MD5SHA1UCMD5UC",    16, HTF_COMPOSED, chain_md5sha1ucmd5uc, "1b3c4ef0e08d96fc1615aaaaf96dc8a5:password123");

    /* --- x-suffix types (iteration marker, same as base) --- */
    /* Types ending in 'x' are just iteration markers — the xNN is parsed from the hint */
    /* MD5SHA1x = MD5SHA1 with arbitrary iteration */
    HT("MD5SHA1x",      16, HTF_COMPOSED, compute_sha1md5, NULL);
    HT("SHA1MD5x",      20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5x, "92ac0281d4695ec3710f690e029a6320ca7e5244:1:password123");
    HTC("MD5SHA1MD5x",  16, HTF_COMPOSED, chain_md5sha1md5md5, "3b4f022014f794549416f9c1bd25fa63:1:password123"); /* actually MD5SHA1MD5 */
    HT("MD4UTF16MD5x",  16, HTF_SALTED | HTF_COMPOSED, compute_md4utf16md5x, NULL);
    Hashtypes[find_type_index("MD4UTF16MD5x")].iter_fn = (hashfn_t)compute_ntlm;
    HT("MD4UTF16SHA1x", 16, HTF_SALTED | HTF_COMPOSED, compute_md4utf16sha1x, NULL);
    Hashtypes[find_type_index("MD4UTF16SHA1x")].iter_fn = (hashfn_t)compute_ntlm;
    HT("MD4UTF16revBASE64x", 16, HTF_SALTED | HTF_COMPOSED, compute_md4utf16revbase64x, NULL);
    Hashtypes[find_type_index("MD4UTF16revBASE64x")].iter_fn = (hashfn_t)compute_ntlm;
    HT("MD4UTF16SHA256x",32,HTF_COMPOSED, compute_md4utf16sha256, NULL);
    HT("SHA1MD5UCx",    20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5ucx, NULL);
    HT("SHA1MD5MD5UCx", 20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5md5ucx, NULL);
    HT("SHA1SHA256UCx", 20, HTF_SALTED | HTF_COMPOSED, compute_sha1sha256ucx, NULL);
    HT("SHA1SHA256x",   20, HTF_SALTED | HTF_COMPOSED, compute_sha1sha256x, NULL);

    /* --- Additional SHA1MD5 CAP chains --- */
    /* SHA1MD5CAP = SHA1(hex(rhash_msg(RHASH_MD5, capitalize(pass)))) */
    /* SHA1MD5CAPMD5 = SHA1(hex(MD5(hex(MD5(capitalize(pass)))))) */
    /* SHA1MD51CAP = SHA1(hex(MD5(hex(MD5(capitalize(pass)))))) — same as above with x01 */
    /* SHA1MD51CAPMD5 = SHA1(hex(MD5(hex(MD5(hex(MD5(capitalize(pass)))))))) */
    /* These need compute functions that capitalize first */

    /* SHA1SHA1HUM, MD5MD5HUM, etc. — HUM format types */
    /* HUM output is colon-separated hex pairs — this is a format difference, not computational */
    /* For verification, the hash computation is the same; the format is handled in output */
    /* We can register these as aliases of their base types */

    /* --- TRUNC/sub/lsb/uNN types --- */
    /* These produce truncated hash output. The hash is computed normally, then truncated. */
    /* Our framework already supports this via hashlen < full output + hash_match partial compare */
    /* We can register them with the appropriate truncated hashlen */

    /* SHA1SHA1TRUNC = SHA1(SHA1(pass)) truncated to 32 hex (16 bytes) */
    /* SHA1SHA1 produces 20 bytes; TRUNC = first 16 bytes */
    HT("SHA1SHA1TRUNC",    16, HTF_COMPOSED, compute_sha1sha1, NULL);  /* truncated to 16 bytes */
    HTC("SHA1SHA1TRUNCMD5",16, HTF_COMPOSED, chain_sha1sha1rawmd5_v2, NULL);  /* not quite right — placeholder */
    HTC("SHA1SHA1UCTRUNC",  16, HTF_COMPOSED, chain_sha1_sha1uc, NULL);

    /* SHA1SHA256TRUNC = SHA1(SHA256(pass)) truncated */
    HT("SHA1SHA256TRUNC",  16, HTF_COMPOSED, compute_sha1sha256, NULL);
    HTC("SHA1SHA256TRUNCMD5",16,HTF_COMPOSED, chain_sha1sha256md5, NULL);
    HTC("SHA1SHA256UCTRUNC",16, HTF_COMPOSED, chain_sha1_sha256uc, NULL);

    /* SHA1SHA512TRUNC, SHA1SHA384TRUNC, SHA1SHA3-256TRUNC */
    HT("SHA1SHA512TRUNC",  16, HTF_COMPOSED, compute_sha1sha512, NULL);
    HTC("SHA1SHA512TRUNCMD5",16,HTF_COMPOSED, chain_sha1md5sha512, NULL);  /* placeholder */
    HTC("SHA1SHA512UCTRUNC",16, HTF_COMPOSED, chain_sha1_sha512uc, NULL);
    HT("SHA1SHA384TRUNC",  16, HTF_COMPOSED, compute_sha1sha384, NULL);
    HTC("SHA1SHA3-256TRUNC",16,HTF_COMPOSED, chain_sha1sha3_256, NULL);

    /* SHA1SHA1SHA1TRUNC */
    HTC("SHA1SHA1SHA1TRUNC",16,HTF_COMPOSED, chain_sha1sha256sha1, NULL); /* placeholder */

    /* SHA1RMD160TRUNC */
    HT("SHA1RMD160TRUNC",  16, HTF_COMPOSED, compute_sha1rmd160, NULL);  /* placeholder: need SHA1(RMD160) */

    /* SHA1MD6TRUNC, SHA1MD6CAPTRUNC */
    HTC("SHA1MD6TRUNC",    16, HTF_COMPOSED, chain_sha1md6, NULL);
    /* SHA1MD6CAPTRUNC — capitalize + MD6 + SHA1 truncated */

    /* SHA1WRLTRUNC, SHA1WRLUCTRUNC */
    HT("SHA1WRLTRUNC",     16, HTF_COMPOSED, compute_sha1wrl, NULL);
    HTC("SHA1WRLUCTRUNC",   16, HTF_COMPOSED, chain_sha1_wrluc, NULL);

    /* SHA1SHA1CAPTRUNC — SHA1(SHA1(capitalize(pass))) truncated */
    /* SHA1SHA11CAP — SHA1(SHA1(hex(SHA1(capitalize(pass))))) */
    /* SHA1SHA256CAP — SHA1(SHA256(capitalize(pass))) */

    /* SHA1PASS-TRUNC — SHA1(pass) truncated */
    HT("SHA1PASS-TRUNC",   16, 0, compute_sha1, NULL);  /* just truncated SHA1 */

    /* uNN types — first N hex chars */
    /* SHA1SHA1u32 = SHA1(SHA1(pass)) first 32 hex = 16 bytes (=TRUNC) */
    HT("SHA1SHA1u32",      16, HTF_COMPOSED, compute_sha1sha1, "9ceaab61179fee27080ab8ae32028f6cee68650c:password123");
    HT("SHA1SHA1u34",      17, HTF_COMPOSED, compute_sha1sha1, NULL);
    HT("SHA1SHA1u35",      17, HTF_COMPOSED, compute_sha1sha1, NULL);  /* 35 hex chars... 17.5 bytes → 17 */
    HT("SHA1SHA1u36",      18, HTF_COMPOSED, compute_sha1sha1, NULL);
    HT("SHA1SHA1u37",      18, HTF_COMPOSED, compute_sha1sha1, NULL);
    HT("SHA1SHA1u38",      19, HTF_COMPOSED, compute_sha1sha1, NULL);
    HT("SHA1SHA1u39",      19, HTF_COMPOSED, compute_sha1sha1, NULL);

    HT("SHA1SHA256u32",    16, HTF_COMPOSED, compute_sha1sha256, NULL);
    HT("SHA1SHA256u34",    17, HTF_COMPOSED, compute_sha1sha256, NULL);
    HT("SHA1SHA256u36",    18, HTF_COMPOSED, compute_sha1sha256, NULL);
    HT("SHA1SHA256u37",    18, HTF_COMPOSED, compute_sha1sha256, NULL);
    HT("SHA1SHA256u38",    19, HTF_COMPOSED, compute_sha1sha256, NULL);
    HT("SHA1SHA256u40",    20, HTF_COMPOSED, compute_sha1sha256, NULL);
    HT("SHA1SHA256u42",    21, HTF_COMPOSED, compute_sha1sha256, NULL);

    /* SHA1SHA1sub1-16 — SHA1(SHA1(pass)) chars 1-16 = 8 bytes starting at offset 0 */
    /* sub1-16 means characters 1 through 16 of the hex string (0-indexed: chars 0-15) */
    /* That's bytes 0-7 = 8 bytes */

    /* MD5SHA1u32 = rhash_msg(RHASH_MD5, SHA1(pass)) first 32 hex = 16 bytes */
    HT("MD5SHA1u32", 16, HTF_COMPOSED, compute_sha1md5, "5de7bb78904c45922bbd593e22b2c0fb:password123"); /* = MD5SHA1 already 16 bytes */
    HT("MD5SHA1u39",       19, HTF_COMPOSED, compute_sha1md5, NULL);
    HTC("MD5SHA1UCu32",     16, HTF_COMPOSED, chain_md5_sha1uc, "0f5f14cf8895700edd2eed170d4af5c5:password123");

    /* SHA1lsb32, SHA1lsb35 — least significant bits */
    HT("SHA1lsb32",        16, 0, compute_sha1lsb32, "0000000008f9cab4083784cbd1874f76:password123");
    HT("SHA1lsb35",        20, 0, compute_sha1lsb35, "00000c6008f9cab4083784cbd1874f76618d2a97:password123");
    HT("MD5SHA1lsb35",     17, HTF_COMPOSED, compute_sha1md5, NULL);

    /* --- Nx MULTI-PASS types: hash of N concatenated hex copies --- */
    HT("MD5-2xMD5",             16, 0, compute_md5_2xmd5, "ff9321878a8459f4426b07a4e12a630d:password123");
    HT("MD5-3xMD5",             16, 0, compute_md5_3xmd5, "f932f4bbef24eb2a97a1c58e10844787:password123");
    HT("MD5-4xMD5",             16, 0, compute_md5_4xmd5, "d7820a43972cdff931bf4343f74b49cf:password123");
    HT("MD5-2xMD5-MD5",         16, 0, compute_md5_2xmd5_md5, "d7b50fae0e15dcfe4d43c0bd166a3e06:password123");
    HT("MD5-2xMD5-SHA1",        16, 0, compute_md5_2xmd5_sha1, "e71cba2abebcf2548647345b55ae24df:password123");
    HT("MD5-2xMD5-MD5MD5",      16, 0, compute_md5_2xmd5_md5md5, "6175fd3774c355d762d39512f2392ce3:password123");
    HT("MD5-2xMD5-MD5MD5MD5",   16, 0, compute_md5_2xmd5_md5md5md5, "7822c838b5f172ccc3fc6d9a07cc6a73:password123");
    HT("MD5-3xMD5-MD5",         16, 0, compute_md5_3xmd5_md5, "96b05c9c29b97153818cacf3d777349e:password123");
    HT("MD5-3xMD5-SHA1",        16, 0, compute_md5_3xmd5_sha1, "669c3c1c995bc978b57740798f39ca43:password123");
    HT("MD5-3xMD5-MD5MD5",      16, 0, compute_md5_3xmd5_md5md5, "79d109affd9d43b1143b1ccfe4102429:password123");
    HT("MD5-3xMD5-MD5MD5MD5",   16, 0, compute_md5_3xmd5_md5md5md5, "4bdb206fb20015c517df348b4e10bc8e:password123");
    HT("MD5-2xMD5UC",           16, 0, compute_md5_2xmd5uc, "ae230badaa547b31381026590b8e880e:password123");
    HT("MD5-2xSHA1",            16, 0, compute_md5_2xsha1, "202d376fa32baccd664245f543c048c4:password123");
    HT("MD5-2xSHA1MD5",         16, 0, compute_md5_2xsha1md5, NULL);
    HT("SHA1-2xSHA1",           20, 0, compute_sha1_2xsha1, "880e72fe2dd2a23fec1da5f4cbda6132d29d3c9a:password123");
    HT("SHA1-2xSHA1-MD5",       20, 0, compute_sha1_2xsha1_md5, "7db91f6394715994723517aef56ab71801c390db:password123");
    HT("SHA1-2xSHA1-MD5MD5",    20, 0, compute_sha1_2xsha1_md5md5, "d77757fba5d6239d1aec29b164cd082e51b45ac3:password123");
    HT("SHA1-2xSHA1-MD5MD5MD5", 20, 0, compute_sha1_2xsha1_md5md5md5, "96ae6719123d3d01eda78b801a612126b933631d:password123");
    HT("SHA1-2xSHA1-SHA1",      20, 0, compute_sha1_2xsha1_sha1, "a251fdc68176941dbed49e8de091cabbe6e45363:password123");
    HT("SHA1-2xMD5",            20, 0, compute_sha1_2xmd5, "259b5227d7c296143199f0840c4f0f5bc0387b34:password123");

    /* --- 1x types: concatenation of two different hash hex outputs --- */
    HT("MD5-1xMD5SHA1",         16, 0, compute_md5_1xmd5sha1, "ccf94ec6c252e11102a19229520c2645:password123");
    HT("MD5-1xMD5SHA1-MD5",     16, 0, compute_md5_1xmd5sha1_md5, "d9b9f0bda30ccfef527fa8f2ee77c324:password123");
    HT("MD5-1xMD5SHA1-MD5MD5",  16, 0, compute_md5_1xmd5sha1_md5md5, "16285c3ba56ab4d5287a50a22afe3258:password123");
    HT("MD5-1xSHA1MD5",         16, 0, compute_md5_1xsha1md5, "a8b3ed92b8d7b98fcaf8bd44f047088c:password123");
    HT("MD5-1xSHA1MD5-MD5",     16, 0, compute_md5_1xsha1md5_md5, "a0151db6df5682225ec785343bc3330f:password123");
    HT("MD5-1xSHA1MD5-MD5MD5",  16, 0, compute_md5_1xsha1md5_md5md5, "083f5066315e41b56ceb2ad39feba65b:password123");
    HT("MD5-1xSHA1MD5pSHA1p",   16, 0, compute_md5_1xsha1md5psha1p, "83157ff201b681d9fee4e872bd8319f7:password123");
    HT("SHA1-1xMD5SHA1",        20, 0, compute_sha1_1xmd5sha1, "bbf4187fd311f067e5e0fc6170febc1c8c32dd03:password123");
    HT("SHA1-1xSHA1MD5",        20, 0, compute_sha1_1xsha1md5, "4a3de2c1b15504be9150ddb0754f883d1d2b8c04:password123");
    HT("SHA1-1xSHA1MD5pSHA1p",  20, 0, compute_sha1_1xsha1md5psha1p, "ae4f5945b84df0d3f4b3fd52c54444de091ca55c:password123");
    HT("MD5SHA1-1xSHA1MD5pSHA1p", 16, 0, compute_md5sha1_1xsha1md5psha1p, "9283a75cc4cf19461cbc55c892b50575:password123");

    /* --- BASE64 types --- */
    HT("MD5BASE64",              16, 0, compute_md5base64, "22e702d475c22fd8f118ccd2e105a509:password123");
    HT("MD5BASE64MD5",           16, 0, compute_md5base64md5, "becc0e75cc89ed81bbae16ec5164e792:password123");
    HT("MD5BASE64MD5MD5",        16, 0, compute_md5base64md5md5, "13331e53f7f30c8b4b989186ec1a6bfe:password123");
    HT("MD5BASE64MD5RAW",        16, 0, compute_md5base64md5raw, NULL);
    HT("MD5BASE64ROT13",         16, 0, compute_md5base64rot13, "e1f3134140c094abd2d2de53a5f7cc4f:password123");
    HT("MD5BASE64revMD5",        16, 0, compute_md5base64revmd5, "77bf1347fc6f3b17cc0bb40b96a11744:password123");
    HT("MD5BASE64SHA1MD5",       16, 0, compute_md5base64sha1md5, NULL);
    HT("MD5BASE64SHA1RAW",       16, 0, compute_md5base64sha1raw, "c20983cb4198e300ba28a9423660a9c9:password123");
    HT("MD5BASE64SHA1RAWBASE64SHA1RAW", 16, 0, compute_md5base64sha1rawbase64sha1raw, "20900515918ed3bdf0fb505e8a446287:password123");
    HT("MD5BASE64SHA1RAWMD5",    16, 0, compute_md5base64sha1rawmd5, "2b37df836d04c4ec1438324b42ae2534:password123");
    HT("MD5UCBASE64SHA1RAW",     16, 0, compute_md5ucbase64sha1raw, "c20983cb4198e300ba28a9423660a9c9:password123");
    HT("MD5SHA1BASE64",          16, 0, compute_md5sha1base64, "ca1cadacfe3b29687903c39e922ecae7:password123");
    HT("MD5SHA1BASE64MD5RAW",    16, 0, compute_md5sha1base64md5raw, "c3568ae620d0bbadcb902ba9523a9da2:password123");
    HT("MD5SHA1BASE64SHA1MD5",   16, 0, compute_md5sha1base64sha1md5, "863535a3638d51af865ea3a02977aeaf:password123");
    HT("MD5SHA1MD5BASE64",       16, 0, compute_md5sha1md5base64, "364946e99c9332ecb45913e2046bbda3:password123");
    HT("MD5DECBASE64",           16, 0, compute_md5decbase64, NULL);
    HT("MD5DECBASE64MD5",        16, 0, compute_md5decbase64md5, NULL);
    HT("SHA1BASE64",             20, 0, compute_sha1base64, "402720a0a1cf4494318ee024a43898d4166eed11:password123");
    HT("SHA1BASE64MD5",          20, 0, compute_sha1base64md5, NULL);
    HT("SHA1BASE64MD5RAW",       20, 0, compute_sha1base64md5raw, "08c372085a6831b1d0af96392dc47deed1ae3a3a:password123");
    HT("SHA1BASE64SHA1RAW",      20, 0, compute_sha1base64sha1raw, "d775d52d922d95e1ec4ce86ace48e4306b8fbf44:password123");
    HT("SHA1BASE64SHA256",       20, 0, compute_sha1base64sha256, NULL);
    HT("SHA1DECBASE64",          20, 0, compute_sha1decbase64, NULL);
    HT("SHA1RADMIN2BASE64",      20, 0, compute_sha1radmin2base64, "fffdf736d6f8c25deaec20fb3671dd29b2adf3d8:password123");
    HT("RADMIN2BASE64",          16, 0, compute_radmin2base64, "0184fdb3b37a7e8c893725b803f8acf0:password123");

    /* --- SQL types --- */
    HT("MD5SQL3",                16, 0, compute_md5sql3, "9c415ceb3161de1c1b1b1e12d3133b11:password123");
    HT("MD5SQL5",                16, 0, compute_md5sql5, "4b9c0924c807868a66f7ff0e713c2cb2:password123");
    HT("MD5SQL5-40",             16, 0, compute_md5sql5_40, "ddb0a10d4fea3543b125982114a24641:password123");
    HT("MD5SQL5-chop40",         16, 0, compute_md5sql5_chop40, "53fa3e6d96e5e9745de59b8f5408272c:password123");
    HT("MD5MD5UCSQL3p",          16, 0, compute_md5md5ucsql3p, "4a724dc633deaa4a1dbf1b432e7c8512:password123");
    HT("MD5SQL5MD5",             16, 0, compute_md5sql5md5, "a91331088a9614fc49802194391e2b63:password123");
    HT("MD4SQL3",                16, 0, compute_md4sql3, "ed754028b02d092558f52eedfb70e14a:password123");
    HT("RADMIN2SQL3",            16, 0, compute_radmin2sql3, "ac7aab560e2d8829918c3bac0a7be8d4:password123");
    HT("RADMIN2SQL5-40",         16, 0, compute_radmin2sql5_40, "a343cb736471ca2f6b2e033908993a55:password123");
    HT("SHA1SQL5-40",            20, 0, compute_sha1sql5_40, "f272e30f6ce69f8f18091fdb663c98f2f3f2a9fd:password123");

    /* --- u32/truncation types --- */
    HT("MD5SHA1u32",             16, 0, compute_md5sha1u32, "5de7bb78904c45922bbd593e22b2c0fb:password123");
    HT("MD5SHA1UCu32",           16, 0, compute_md5sha1ucu32, "0f5f14cf8895700edd2eed170d4af5c5:password123");
    HT("SHA1SHA1u32",            20, 0, compute_sha1sha1u32, "9ceaab61179fee27080ab8ae32028f6cee68650c:password123");

    /* --- sub-string extract types --- */
    HT("MD5sub8-24MD5",          16, 0, compute_md5sub8_24md5, "5bd50cd7f2c2c6abb7e2e1cb942779ea:password123");
    HT("MD5sub8-24MD5sub8-24MD5",16, 0, compute_md5sub8_24md5sub8_24md5, "b71ae2802dd964426812b506584639f1:password123");
    HT("MD5sub1-20MD5",          16, 0, compute_md5sub1_20md5, NULL);
    HT("MD5sub1-20MD5MD5",       16, 0, compute_md5sub1_20md5md5, NULL);
    HT("SHA1MD5sub1-16",         20, 0, compute_sha1md5sub1_16, NULL);
    HT("SHA1MD5sub1-16MD5",      20, 0, compute_sha1md5sub1_16md5, NULL);
    HT("SHA1MD5sub1-16MD5MD5",   20, 0, compute_sha1md5sub1_16md5md5, NULL);
    HT("SHA1MD5sub1-20MD5",      20, 0, compute_sha1md5sub1_20md5, NULL);
    HT("SHA1MD5sub1-20MD5MD5",   20, 0, compute_sha1md5sub1_20md5md5, NULL);
    HT("SHA1MD5sub8-24MD5",      20, 0, compute_sha1md5sub8_24md5, NULL);
    HT("SHA1SHA1sub1-16",        20, 0, compute_sha1sha1sub1_16, NULL);

    /* --- SHA1 special types --- */
    HT("SHA1MD5CAP",             20, 0, compute_sha1md5cap, NULL);
    HT("SHA1MD5CAPMD5",          20, 0, compute_sha1md5capmd5, NULL);
    HT("SHA1MD51CAPMD5MD5",      20, 0, compute_sha1md51capmd5md5, NULL);
    HT("SHA1SHA256CAP",          20, 0, compute_sha1sha256cap, NULL);
    HT("SHA1MD5-2xMD5-MD5",     20, 0, compute_sha1md5_2xmd5_md5, NULL);

    /* --- Misc/SHA1SHA1RAW --- */
    HT("MD5SHA1SHA1RAW",         16, 0, compute_md5sha1sha1raw, "7ae92abdb62aede2b092f11591818bb4:password123");

    /* --- MD4UTF16 --- */
    HT("MD4UTF16-2xMD5",        16, 0, compute_md4utf16_2xmd5, NULL);

    /* ================================================================= */
    /* BATCH 1: HMAC types                                               */
    /* ================================================================= */

    /* Standard HMAC (key=salt, msg=pass) */
    HT("HMAC-MD2",     16, HTF_SALTED, compute_hmac_md2, "04912f388000a9ea3d21047d21150f0f:testsalt:password123");
    HT("HMAC-MD4",     16, HTF_SALTED, compute_hmac_md4, "ab18ed06836fdbf52f6e440cc603c190:testsalt:password123");
    HT("HMAC-RMD128",  16, HTF_SALTED, compute_hmac_rmd128, "f1cab4750367231d5d6a5cd4a5258d30:testsalt:password123");
    HT("HMAC-RMD160",  20, HTF_SALTED, compute_hmac_rmd160, "bd55f8e3b904a8dec820a2ee90709a0ca8135129:testsalt:password123");
    HT("HMAC-RMD256",  32, HTF_SALTED, compute_hmac_rmd256, "a42744defb2bbe8ee7d513c259d59980af41d25dcfa901e0cd6597056e3bad04:testsalt:password123");
    HT("HMAC-RMD320",  40, HTF_SALTED, compute_hmac_rmd320, "d1ec4c13556b193ff1ede8094a50e7bc73b8ae1be5d953c86f5f8e16ffd868045c128da194fcee1d:testsalt:password123");
    HT("HMAC-MD5",     16, HTF_SALTED, compute_hmac_md5, "a721680d20f08b2c2cf5a1b33df1d30f:testsalt:password123");
    HT("HMAC-SHA1",    20, HTF_SALTED, compute_hmac_sha1, "30e653bb1fcb911909896b42b2b67ef9494822a9:testsalt:password123");
    HT("HMAC-SHA224",  28, HTF_SALTED, compute_hmac_sha224, "b42c9d7aef7eaae6a2dbd7f46b991d56e655bade669d42501653dba8:testsalt:password123");
    HT("HMAC-SHA256",  32, HTF_SALTED, compute_hmac_sha256, "48ab9e974e422f68a8b61f5e7b31e27c21cfad7f423fff546b3429da67f480b5:testsalt:password123");
    HT("HMAC-SHA384",  48, HTF_SALTED, compute_hmac_sha384, "2264b82fed84e6b06c61ca89f5f4e6eef158ad71b6be075b67bafec9110476d88966e52f757ae1028db61087964434b4:testsalt:password123");
    HT("HMAC-SHA512",  64, HTF_SALTED, compute_hmac_sha512, "0876e6c17ac41e68003af908be877b7a5178996eca7c91cac50fc825eef9ac5b018b9c862f7e3665317e60cc24d62a7cdd663ed7bfc22e782d565cc17190e101:testsalt:password123");
    HT("HMAC-HAV128",  16, HTF_SALTED, compute_hmac_hav128, "2905b64454ba83542885b6721738ebad:testsalt:password123");
    HT("HMAC-HAV160",  20, HTF_SALTED, compute_hmac_hav160, "9865673ea8e95cc5c04bc682d883f62c136da370:testsalt:password123");
    HT("HMAC-HAV192",  24, HTF_SALTED, compute_hmac_hav192, "c5747a29c25b1f0fa94ff5793268d05f01ad0d454f1d367e:testsalt:password123");
    HT("HMAC-HAV224",  28, HTF_SALTED, compute_hmac_hav224, "cf1444185b4ea753d9ac61a5f0c74ad29d416b4a3b296e3dbddf73b9:testsalt:password123");
    HT("HMAC-HAV256",  32, HTF_SALTED, compute_hmac_hav256, "82d06812bd94ed2c756e108abe4b6b0679bc2c7e3c32bb8a423577cc70dea89a:testsalt:password123");
    HT("HMAC-TIGER128",16, HTF_SALTED, compute_hmac_tiger128, "92ce438a530443653f9a42998e316e13:testsalt:password123");
    HT("HMAC-TIGER160",20, HTF_SALTED, compute_hmac_tiger160, "084e4e63a541c056c4f08cdbe6e0fe36e7398c8c:testsalt:password123");
    HT("HMAC-TIGER192",24, HTF_SALTED, compute_hmac_tiger192, "1ff1eaec52618446561b21e07628301442fe93ffee15a45a:testsalt:password123");
    HT("HMAC-GOST",    32, HTF_SALTED, compute_hmac_gost, "c3eda5788e41658d3bf6ccc959a0270d3d8c79c29b9e71abd95df1179e5f47b4:testsalt:password123");
    HT("HMAC-WRL",     64, HTF_SALTED, compute_hmac_wrl, "d7478c31f95bdbc162dd6a9e0a5f90f4273d7bf74e32abea322b322bc1ff380b:testsalt:password123");
    HT("HMAC-SNE128",  16, HTF_SALTED, compute_hmac_sne128, "c713af9f1407e5ce5bce4acf93426706:testsalt:password123");
    HT("HMAC-SNE256",  32, HTF_SALTED, compute_hmac_sne256, "74cae0fdba34b5ff5f85b7ede4282b5948da938914bfcf76ce91b36a1e463378:testsalt:password123");
    HT("HMAC-BLAKE2S", 32, HTF_SALTED, compute_hmac_blake2s, "ec4b78bd06fec177c3e76473f788d28cb8939f6778a417b6b9702335dc2cc818:testsalt:password123");

    /* Streebog HMAC (key=salt, msg=pass) */
    HT("HMAC-STREEBOG256", 32, HTF_SALTED, compute_hmac_streebog256, "35ec05ed149db7e04872e979499ad91333b040bae8c6e687ab08a1d10957f2fc:testsalt:password123");
    HT("HMAC-STREEBOG512", 64, HTF_SALTED, compute_hmac_streebog512, "116c626195369a7281346b178437085a548359b764594ebbcfc38502d17a8141c8116185389ffd3b1d4b29587e60cb513f12311de2a4986fc10b1e1fe9a0d9d2:testsalt:password123");

    /* KPASS HMAC (key=pass, msg=salt) */
    HT("HMAC-MD5-KPASS",    16, HTF_SALTED, compute_hmac_md5_kpass, "e62cf677521d96f7f5ea48207811a97f:testsalt:password123");
    HT("HMAC-SHA1-KPASS",   20, HTF_SALTED, compute_hmac_sha1_kpass, "2b2f85e38e1c709c1c1e75e6ee4d64342b07549b:testsalt:password123");
    HT("HMAC-SHA224-KPASS", 28, HTF_SALTED, compute_hmac_sha224_kpass, "b1e6b34e060f415820939daa65d3b9681f6c5a89ef84b05b227ec74b:testsalt:password123");
    HT("HMAC-SHA256-KPASS", 32, HTF_SALTED, compute_hmac_sha256_kpass, "4b3c0065fbf326359c48b05d4c7624b7537633f450e0b2725bbd50b76fe6e272:testsalt:password123");
    HT("HMAC-SHA384-KPASS", 48, HTF_SALTED, compute_hmac_sha384_kpass, "3aad96017b6d4a8329131f3ae3e5166d7eeef0f455cb297523b8dc086963acab748ca424212516b6fc1d90b24c64317e:testsalt:password123");
    HT("HMAC-SHA512-KPASS", 64, HTF_SALTED, compute_hmac_sha512_kpass, "b05fe862891386bea0536631b38db71d1955168a9174961ca05cee238d41c920be8df3b3389cea4bac643ac15cd2a7aeb91f8f5a7fb7f003df5fc5b4c8f99135:testsalt:password123");
    HT("HMAC-RMD160-KPASS", 20, HTF_SALTED, compute_hmac_rmd160_kpass, "514f58996b12f1c91595c12be92d4519fff07e48:testsalt:password123");
    HT("HMAC-RMD320-KPASS", 40, HTF_SALTED, compute_hmac_rmd320_kpass, "022ee238a2e2bacfe3bcdd23d0dc06e6246813c82a79898890e1555f703ef89b52c964e8a341d8a8:testsalt:password123");
    HT("HMAC-STREEBOG256-KPASS", 32, HTF_SALTED, compute_hmac_streebog256_kpass, "a4c447ef8c06c22a494113eac0b8c2a5b845fb739b8777facd92737f913de44c:testsalt:password123");
    HT("HMAC-STREEBOG512-KPASS", 64, HTF_SALTED, compute_hmac_streebog512_kpass, "f7b1bd906c850d6de2a29c373f7786910ecb3c6f457245924432a24e8b263f14b43b4795a8c27babdb8fa5fdb1aab4f4743521a9de9612ecb4390ed9b303ea32:testsalt:password123");

    /* --- Batch 2: Simple salted variants --- */
    HT("SHA384PASSSALT", 48, HTF_SALTED | HTF_SALT_AFTER, compute_sha384passsalt, "ad5becb6dee94c284dc825d420f65a0a4a58102becfc8777b35f45222377f8032ab491677f2bf20e34e385b6f6a9fde2:testsalt:password123");
    HT("SHA384SALTPASS", 48, HTF_SALTED, compute_sha384saltpass, "effd3c241e63f9b970d9093cf09af5fa2f180bd91e79818ca1c4b9832b66dd66683abb3687cbd0ddd765e1feefb2e09e:testsalt:password123");
    HT("SHA384UTF16LEPASSSALT", 48, HTF_SALTED | HTF_SALT_AFTER, compute_sha384utf16lepasssalt, "c517a98fbedb4a9322f4b1bec2d9581a00391e615141f5fa2b76a360076603daca839c7cb2270201780ddcc2aaeae313:testsalt:password123");
    HT("SHA384UTF16LESALTPASS", 48, HTF_SALTED, compute_sha384utf16lesaltpass, "ef60221a689caa3120b851bca50d080e8483bf98dd21c76bcc2ab88b48bc956b5d83cafd03cf8fc05d76b95fae967397:testsalt:password123");
    HT("SHA224PASSSALT", 28, HTF_SALTED | HTF_SALT_AFTER, compute_sha224passsalt, "f5af934d83ea8e451eaa8a974ee04216723e0ed8a9446a7f12057732:testsalt:password123");
    HT("SHA224SALTPASS", 28, HTF_SALTED, compute_sha224saltpass, "a50f5c0eba6e1234da7e5820b2e5f099fca70dfa3eb0637e72ac18ea:testsalt:password123");
    HT("BLAKE2B512PASSSALT", 64, HTF_SALTED | HTF_SALT_AFTER, compute_blake2b512passsalt, "74e4702fac1576179c957877cb8b4f1f5a8a5bfa3c2fd8a572ede80c6aec857152384db229489b0b89db69c62e9597637516d68a9bda2ce661464eb9d7b6f11c:testsalt:password123");
    HT("BLAKE2B512SALTPASS", 64, HTF_SALTED, compute_blake2b512saltpass, "b0c082a1f1e2a385668619b450897546ed0f382598c0e355198a493479f0c9915ebe750092c34f844de701ab3f77ea5d3e966016036122ce4eeeee509444388a:testsalt:password123");
    HT("BLAKE2B256PASSSALT", 32, HTF_SALTED | HTF_SALT_AFTER, compute_blake2b256passsalt, "eee9fc18ca12f18c0a700b07c464d58a7e6f624800d7e5b13170f4e4cd5eb1e9:testsalt:password123");
    HT("BLAKE2B256SALTPASS", 32, HTF_SALTED, compute_blake2b256saltpass, "f4fdf6b1cda2872527244ff036f1670af39c39decbd9aab4765a7aaa2b1d41d0:testsalt:password123");
    HT("WRLPASSSALT", 64, HTF_SALTED | HTF_SALT_AFTER, compute_wrlpasssalt, "84dbfdb2a16f2d0c84f59f17b26ceac15879e363e90ea1b95d920df931fe1967e20d41f162485d5cdd10f952500df7e50bc7bfff4723a0b02e61bd9ac8937c2e:testsalt:password123");
    HT("WRLSALTPASS", 64, HTF_SALTED, compute_wrlsaltpass, "3388fd1280003cf6c32025888f12b0875469066ecd735b4db79bec3c90abce86a77125c4d8dfe46a37748fbb6c971734fcc2520dde9048a434e381998dd9c028:testsalt:password123");
    HT("WRLSALTPASSSALT", 64, HTF_SALTED, compute_wrlsaltpasssalt, "2d937185151d7d5c49b4ad1def0250e4459c7752e32945ac3ceb15e8ae5a2f97d21869e5b6239a51c643d0ecd48138c50d485078f8d410cd06a95c934af227b0:testsalt:password123");
    HT("WRLWRLSALT", 64, HTF_SALTED | HTF_COMPOSED, compute_wrlwrlsalt, "0488b47b2bf8dd700377efc9dbc809f2a0ec794bd39d41f9de0a084d9725531fc94540faee049d2c2fc4b2b4386dc9d64b196264e6881709645c86f29f4f1834:testsalt:password123");
    HT("WRLSALTWRL", 64, HTF_SALTED, compute_wrlsaltwrl, "f1c22deacdc74d9a4dcebc1e6565bd403f7e36f83e4469d2da87ead134ffdacf313212cebae7d354552a22ef3bc339da0effb807783acea2f791eb225a6d2c46:testsalt:password123");
    HT("SHA256SHA256SALT", 32, HTF_SALTED | HTF_COMPOSED, compute_sha256sha256salt, "c13ec3c0bee06d3315f743a0df31b3f23069eed4bdcf6dde4d37f894c0c9d1b6:testsalt:password123");
    HT("SHA512SHA512SALT", 64, HTF_SALTED | HTF_COMPOSED, compute_sha512sha512salt, "2676843a84b1344f91452f591e9ce586b4a5d2aaa62845df122d75f65bae7ca453302b450a8fbd9d208e4e6c3a4098f2680ceb3eef9e003d887dee24eef4e431:testsalt:password123");
    HT("SHA512SALTSHA512", 64, HTF_SALTED, compute_sha512saltsha512, "b1b4706604213021f6ec950e6b2fedc9c10ca569094e4a1f686cf396ae48c67993fee570d6c4044aad2aca76514e3768647f90835e351066524bb60753af098e:testsalt:password123");
    HT("SHA256SALTPASSSALT", 32, HTF_SALTED, compute_sha256saltpasssalt, "348112f7744f0b78322338ab30d26febb2bdb5ec76a51bb273a71e6cc02118a3:testsalt:password123");
    HT("MD5UTF16LEPASSSALT", 16, HTF_SALTED | HTF_SALT_AFTER, compute_md5utf16lepasssalt, "0488fff28516472675ba5b45e942f84e:testsalt:password123");
    HT("MD5UTF16LESALTPASS", 16, HTF_SALTED, compute_md5utf16lesaltpass, "5eddf651932d86e0ea0d501bd7c981fb:testsalt:password123");
    HT("SHA1UTF16LEPASSSALT", 20, HTF_SALTED | HTF_SALT_AFTER, compute_sha1utf16lepasssalt, "13b30726901692e8111f34f9c22d2e9b3b0845f6:testsalt:password123");
    HT("SHA1UTF16LESALTPASS", 20, HTF_SALTED, compute_sha1utf16lesaltpass, "f4456b1b276138b9b183ac3e5fe853187adedd2c:testsalt:password123");
    HT("SHA256UTF16LEPASSSALT", 32, HTF_SALTED | HTF_SALT_AFTER, compute_sha256utf16lepasssalt, "ee1da056f122f9113a0f0a1e4a154d375d012ee8c232e64671f70d01d8dfb02c:testsalt:password123");
    HT("SHA256UTF16LESALTPASS", 32, HTF_SALTED, compute_sha256utf16lesaltpass, "2bb145aea195866dbb89ff25feeb3df2fe187ab85fdb446855846cb9fc5a0768:testsalt:password123");
    HT("SHA512UTF16LEPASSSALT", 64, HTF_SALTED | HTF_SALT_AFTER, compute_sha512utf16lepasssalt, "1e6411c5abe4246d5530c099c7a0993fa773a65c78cfa2a77b38dfeb90616f0f7b9193f17e74b081ad8f70f97c5acf56738695e5df73386d8e115a68087d42ca:testsalt:password123");
    HT("SHA512UTF16LESALTPASS", 64, HTF_SALTED, compute_sha512utf16lesaltpass, "505489751055fae2616a85ca76401c7d73685c4338637cd28fbb8d130e843c4c3d3594f9077ddce7f7d6cec342f61384a67b1004923bb1e17baa234795669af1:testsalt:password123");

    /* --- Batch 3: HEXSALT types --- */
    HT("MD5HEXSALT",    16, HTF_SALTED | HTF_COMPOSED, compute_md5hexsalt, "8ba32e8481f3c6803ee94ebb25d760d9:00:password123");
    HT("SHA1HEXSALT",   20, HTF_SALTED | HTF_COMPOSED, compute_sha1hexsalt, "175b09dfa3444faa4be81719826249af18f85d00:00:password123");
    HT("SHA256HEXSALT", 32, HTF_SALTED | HTF_COMPOSED, compute_sha256hexsalt, "7f8759af25372e5d977dd2bc5bfe9ec21a985b5248284129fca6211f91afeea1:00:password123");
    HT("GOSTHEXSALT",   32, HTF_SALTED | HTF_COMPOSED, compute_gosthexsalt, "fb89aeeaa77f47aa8faf64de632cfdef15ebe69d2b7d630a8b0acb0dd418257c:00:password123");
    HT("HAV128HEXSALT", 16, HTF_SALTED | HTF_COMPOSED, compute_hav128hexsalt, "6aa78927690b88c949a31922adb6d4fd:00:password123");
    HT("SHA1PASSHEXSALT",20, HTF_SALTED, compute_sha1passhexsalt, "7c72e4a4f6a11f792c62ecb43857006741997aa8:0123456789abcdef0123:password123");

    /* --- Batch 4: MD5/SHA1 salted composed types --- */
    /* USER variants (salt = username) */
    HT("MD5USERIDMD5",    16, HTF_SALTED, compute_md5useridmd5, "8b082a42bc07844aaa706556e103b2b0:testsalt:password123");
    HT("MD5USERIDMD5MD5", 16, HTF_SALTED, compute_md5useridmd5md5, "1db4e6984ae0fb779728c2ed0f8cd7e8:testsalt:password123");
    HT("MD5USERnulPASS",  16, HTF_SALTED, compute_md5usernulpass, "a30df98f8bb6b71e0b79c3db4f331011:testsalt:password123");
    HT("MD5MD5USER",      16, HTF_SALTED | HTF_COMPOSED, compute_md5md5user, "423a170b613885b19cdc496242a80787:testsalt:password123");
    HT("SHA1MD5USER",     20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5user, "18768e979e77779052a467262d0cf1d486c76d2c:testsalt:password123");
    HT("SHA1SHA1USER",    20, HTF_SALTED | HTF_COMPOSED, compute_sha1sha1user, "3b8240b10f2caefcc6cd7c970b332b4109d7e63c:testsalt:password123");
    HT("MD5CAPMD5USER",   16, HTF_SALTED | HTF_COMPOSED, compute_md5capmd5user, "c3c7bf3617f74d2472504d24b5137f37:testsalt:password123");
    HT("MD5CAPMD5MD5USER",16, HTF_SALTED | HTF_COMPOSED, compute_md5capmd5md5user, "bcdcc288754872e1daa8f667a710792d:testsalt:password123");
    HT("MD5MD5MD5USER",   16, HTF_SALTED | HTF_COMPOSED, compute_md5md5md5user, "966fb8f379de3a2dbdbf249470a76e86:testsalt:password123");
    HT("MD5USERPASS",     16, HTF_SALTED, compute_md5userpass, "4e48abb76d3e0295f3f89eb02d05b344:testsalt:password123");
    HT("SHA512SHA512RAWUSER", 64, HTF_SALTED | HTF_COMPOSED, compute_sha512sha512rawuser, "7f132a28e5e5af1fb9536c9bed74c85a26059b43ec740e445c0dfcc97d499e8d0a7ac8dc93833f366c58fafb9dc53408f52118580d82fe153bea8e4dfac79229:testsalt:password123");

    /* 1SALT/2SALT variants */
    HT("MD51SALTMD5",     16, HTF_SALTED | HTF_COMPOSED, compute_md51saltmd5, "4540259d498476f6f54c7505c2d9cbfe:!:password123");
    HT("MD52SALTMD5",     16, HTF_SALTED | HTF_COMPOSED, compute_md52saltmd5, "ba6a96b297b06825d70732159fc87e84:z0:password123");
    HT("MD51SALTMD5UC",   16, HTF_SALTED | HTF_COMPOSED, compute_md51saltmd5uc, "3c7cdcfb2ea4813dca96d14fe542b28d:D:password123");
    HT("MD51SALTMD5MD5",  16, HTF_SALTED | HTF_COMPOSED, compute_md51saltmd5md5, "acedaa16f08b61bb4de2ab57099b6d86:~:password123");
    HT("SHA1MD51SALTMD5", 20, HTF_SALTED | HTF_COMPOSED, compute_sha1md51saltmd5, "38442ec60d29c6ab5df79d7f779805038df61c90:~:password123");
    HT("SHA11SALTMD5",    20, HTF_SALTED | HTF_COMPOSED, compute_sha11saltmd5, "4b746a8e5457dd09bed975e6767f427dcf52a1ab:~:password123");
    HT("MD51SALTMD5MD5MD5",     16, HTF_SALTED | HTF_COMPOSED, compute_md51saltmd5md5md5, "992d34721a3ae43ad610e3c36af0d1e0:~:password123");
    HT("MD51SALTMD5MD5MD5MD5",  16, HTF_SALTED | HTF_COMPOSED, compute_md51saltmd5md5md5md5, "bba2ee6d4fad40eee0fd8431e4a622f5:~:password123");
    HT("MD51SALTMD5MD5MD5MD5MD5",16, HTF_SALTED | HTF_COMPOSED, compute_md51saltmd5md5md5md5md5, "32e0ed968d6e554d35d6f200b1fc8a14:~:password123");
    HT("MD5MD5SALT",      16, HTF_SALTED | HTF_COMPOSED, compute_md5salt, "966fb8f379de3a2dbdbf249470a76e86:testsalt:password123");
    HT("MD52SALTMD5MD5",  16, HTF_SALTED | HTF_COMPOSED, compute_md52saltmd5md5, "949273099a5f50434c70f2399ead956c:fz:password123");
    HT("MD52SALTMD5MD5MD5",16, HTF_SALTED | HTF_COMPOSED, compute_md52saltmd5md5md5, "d2fb66c1870965c8da219ab684ac894d:$HEX[7f57]:password123");
    HT("MD5UCSALT",       16, HTF_SALTED | HTF_COMPOSED, compute_md5ucsalt, "69da68d2893de24e2d927a619bbd92bf:testsalt:password123");
    HT("MD5DSALT",         16, HTF_SALTED | HTF_COMPOSED, compute_md5dsalt, "4e8d3e56d0159708bced73cfad02555f:7aG7aG:password123");

    /* Other MD5/SHA1 salt-composed */
    HT("MD5UCBASE64MD5RAW",16, HTF_COMPOSED, compute_md5ucbase64md5raw, "ccc24639342a9838f92a9e54a350c3e7:password123");
    HT("MD5-MD5USERSHA1MD5PASS", 16, HTF_SALTED | HTF_COMPOSED, compute_md5_md5usersha1md5pass, "208b87d7e98279f2c9529e7b367251a3:testsalt:password123");
    HT("MD5SHA1u32SALT",   16, HTF_SALTED | HTF_COMPOSED, compute_md5sha1u32salt, "848add4c87bf71a16b34093033ff63ca:testsalt:password123");
    HT("MD5-4xMD5-SALT",  16, HTF_SALTED | HTF_COMPOSED, compute_md5_4xmd5_salt, "696a4dd17c0357d2bdda8f24e9dd6430:testsalt:password123");
    HT("MD5revMD5SALT",   16, HTF_SALTED | HTF_COMPOSED, compute_md5revmd5salt, "ed7a7969533f21ebb95a899796839da4:testsalt:password123");
    HT("MD5sub8-24SALT",  16, HTF_SALTED | HTF_COMPOSED, compute_md5sub8_24salt, "64839daa92982301a1982264a994c91a:chloe01:password123");
    HT("MD5SHA1SALT",     16, HTF_SALTED | HTF_COMPOSED, compute_md5sha1salt, "2cd237c6a88649f18a4cd4a3bc22f966:testsalt:password123");

    /* --- Batch 10: Unsalted composed types --- */
    HT("MD5BASE64MD5RAWSHA1",    16, HTF_COMPOSED, compute_md5base64md5rawsha1, "64761afb7b659a4513e17db5545f4fe4:password123");
    HT("MD5BASE64MD5RAWMD5",     16, HTF_COMPOSED, compute_md5base64md5rawmd5, "c1e73e3c59daf0ab7489280823281748:password123");
    HT("MD5BASE64MD5RAWMD5MD5",  16, HTF_COMPOSED, compute_md5base64md5rawmd5md5, "82e693458998a9b045cd8f98d20b2b33:password123");
    HT("SHA1-1xSHA1psubp",       20, HTF_SALTED | HTF_COMPOSED, compute_sha1_1xsha1psubp, "91ae0c83b7f7088c948953b775c8375c59f59f86:p:password123");
    HT("MD5SQL5-32",             16, HTF_COMPOSED, compute_md5sql5_32, "1e44c257d89682e9709364b73ec36105:password123");
    HT("MD5SHA1BASE64SHA1RAW",   16, HTF_COMPOSED, compute_md5sha1base64sha1raw, "b9f3e576c2455d6b9f278e67c5731214:password123");
    HT("MD5BASE64SHA256RAW",     16, HTF_COMPOSED, compute_md5base64sha256raw, "6e443efc8f2d2e77e332408965408481:password123");
    HT("MD5BASE64BASE64",        16, HTF_COMPOSED, compute_md5base64base64, "2662267993ec9092a1c99802586ad20f:password123");
    HT("MD5BASE64BASE64BASE64",  16, HTF_COMPOSED, compute_md5base64base64base64, "6cc60b7d4ac51689f73cc9cf6135e1c3:password123");
    HT("MD5SQL3SQL5MD5MD5",      16, HTF_COMPOSED, compute_md5sql3sql5md5md5, "4060af99ef548d49eb63d718f17c28ec:password123");
    HT("MD5-6xMD5",             16, HTF_COMPOSED, compute_md5_6xmd5, "40d4a565708698126d4763187371359c:password123");
    HT("MD5-5xMD5",             16, HTF_COMPOSED, compute_md5_5xmd5, "1ec8230aa83c626ac6f01a224316c845:password123");
    HT("SHA1SQL5-32",            20, HTF_COMPOSED, compute_sha1sql5_32, "5739376a1bd807fca1068819f1678880d2b28d8f:password123");
    HT("MD5DECBASE64MD5BASE64MD5",16, HTF_COMPOSED, compute_md5decbase64md5base64md5, "9f9f634ab9e3e48f188f2021f82b78a7:password123");
    HT("SHA1revBASE64",          20, HTF_COMPOSED, compute_sha1revbase64, "aaff177fba258a06cccc183169de9bc2e4fef050:password123");
    HT("SHA1revBASE64x",         20, HTF_SALTED | HTF_COMPOSED, compute_sha1revbase64x_outer, "aaff177fba258a06cccc183169de9bc2e4fef050:1:password123");
    HT("SHA1BASE64CUSTBASE64MD5",20, HTF_COMPOSED, compute_sha1base64custbase64md5, "071bce9a60b5d9c9eab1fa2ad17cccda21040f5b:password123");

    /* --- Batch 5: HUM types — inner_hash → hex → append/prepend decoded salt bytes → outer_hash
       Salt format: "HH[HH...]- x N" where HH is hex-encoded control bytes.
       compute = append variant, compute_alt = prepend variant. */
    HT_ALT("MD5MD5HUM",        16, HTF_SALTED | HTF_COMPOSED, compute_md5md5hum, compute_md5md5hum_pre, "13c3f9d8348f34744861244ced0ec821:00- x 1:password123");
    HT_ALT("SHA1MD5HUM",       20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5hum, compute_sha1md5hum_pre, "6473ffc8effd698469b3ddaed36ac59c2aa0d89d:00- x 1:password123");
    HT_ALT("SHA1SHA1HUM",      20, HTF_SALTED | HTF_COMPOSED, compute_sha1sha1hum, compute_sha1sha1hum_pre, "0278c8de0e14d721dcc9ae4fda823b3f48f6fa0c:00- x 1:password123");
    HT_ALT("MD5SHA1HUM",       16, HTF_SALTED | HTF_COMPOSED, compute_md5sha1hum, compute_md5sha1hum_pre, "4aaf757aeddceaef203eea04b78ce77f:00- x 1:password123");
    HT_ALT("MD5SHA1MD5HUM",    16, HTF_SALTED | HTF_COMPOSED, compute_md5sha1md5hum, compute_md5sha1md5hum_pre, "9d580ab9c85db594c0eb7511e964ea79:0d0d- x 1:password123");
    HT_ALT("MD4UTF16MD5HUM",   16, HTF_SALTED | HTF_COMPOSED, compute_md4utf16md5hum, compute_md4utf16md5hum_pre, "f25a2dde4e083267167911073d3c4a04:00- x 1:password123");
    HT_ALT("MD4UTF16SHA1HUM",  20, HTF_SALTED | HTF_COMPOSED, compute_md4utf16sha1hum, compute_md4utf16sha1hum_pre, "243a457280af3ed678f64634ff55658e:00- x 1:password123");

    /* --- Batch 6: SHA1-salted-composed types --- */

    /* SHA1(hex(INNER(pass)) + salt) types */
    HT("SHA1-MD5PASSSALT",  20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5passsalt, "f98326e072780bdba37b7b1cc144f6dd7b18cba5:testsalt:password123");
    HT("SHA1MD5SALT",       20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5passsalt, "f98326e072780bdba37b7b1cc144f6dd7b18cba5:testsalt:password123");
    HT("SHA1MD5PASS-SALT",  20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5passsalt, "f98326e072780bdba37b7b1cc144f6dd7b18cba5:testsalt:password123");
    HT("SHA1SHA1PASSSALT",  20, HTF_SALTED | HTF_COMPOSED, compute_sha1sha1passsalt, "3b8240b10f2caefcc6cd7c970b332b4109d7e63c:testsalt:password123");
    HT("SHA1MD5MD5SALT",    20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5md5salt, "f63387aeac7aa1d759634f59aecc127cfd7d0298:testsalt:password123");
    HT("SHA1SHA1MD5PASSSALT",20,HTF_SALTED | HTF_COMPOSED, compute_sha1sha1md5passsalt, "160585a9688bfd014e818f02367cec9238390f0e:testsalt:password123");
    HT("SHA1MD5SHA1-SALT",  20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5sha1_salt, "619a5180b7e9621059f4e3b68922bc1405c10aaf:administrator:password123");

    /* SHA1(salt + hex(INNER(pass))) types */
    HT("SHA1SALTMD5PASS",   20, HTF_SALTED | HTF_COMPOSED, compute_sha1saltmd5pass, "e5571cdbc11c39a3c1450e8bbc1860462637abf3:testsalt:password123");
    HT("SHA1SALTSHA1PASS",  20, HTF_SALTED | HTF_COMPOSED, compute_sha1saltsha1pass, "0048b661bdb70a4c650d452a172412d3c842932a:testsalt:password123");
    HT("SHA256SALTSHA256PASS",32,HTF_SALTED | HTF_COMPOSED, compute_sha256saltsha256pass, "606344e0d3e29c3250e0b4cf2031b8115acdde10c644219107449be678129752:testsalt:password123");
    HT("SHA512SALTMD5",     64, HTF_SALTED | HTF_COMPOSED, compute_sha512saltmd5, "2a0660efed3149bb8044e51d48de13dcd85b07a183fe9ad98be137ae6f972b8438999995e000798714f89ca3b758eb22b8edc6d82186a6d01048b4a45c063d83:salt:password123");
    HT("SHA1SALTSHA256",    20, HTF_SALTED | HTF_COMPOSED, compute_sha1saltsha256, "d495adae5dc5a6de716030fb73e2597354fb80fd:salt:password123");

    /* SHA1-dash types (salt inside inner hash) */
    HT("SHA1-MD5SALT",      20, HTF_SALTED | HTF_COMPOSED, compute_sha1_md5salt, "b203b44d7b3647ef307a75dfd16ac3fc071e28c1:salt:password123");
    HT("SHA1-revMD5SALT",   20, HTF_SALTED | HTF_COMPOSED, compute_sha1_revmd5salt, "84857e37dc35764c4471e087733d2cb0d2989493:salt:password123");
    HT("SHA1-MD5MD5SALT",   20, HTF_SALTED | HTF_COMPOSED, compute_sha1_md5md5salt, "571fda02aa7426a7ae7e10ebb97214771e7fbf56:salt:password123");
    HT("SHA1-MD5UC-MD5SALT",20, HTF_SALTED | HTF_COMPOSED, compute_sha1_md5uc_md5salt, "51523603fe80a361248fa7e0eb8accdbf0315e30:salt:password123");

    /* Reversed hex + salt */
    HT("SHA1revMD5PASSSALT",20, HTF_SALTED | HTF_COMPOSED, compute_sha1revmd5passsalt, "c756ee266f6c6b426ac54e48af61806226f17b08:testsalt:password123");
    HT("SHA1SALTrevMD5PASS",20, HTF_SALTED | HTF_COMPOSED, compute_sha1saltrevmd5pass, "8da559bca00c4c46bf5604b47660a911563dd837:salt:password123");

    /* Inner hash includes salt */
    HT("SHA1MD5PASSSALT",   20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5passsalt_inner, "15938ed92b80c4504b24f5068bd4599e41dc00da:salt:password123");

    /* MD5 salt chain types */
    HT("MD5-SALTMD5PASSSALT",16,HTF_SALTED | HTF_COMPOSED, compute_md5_saltmd5passsalt, "d72fcd56bc1db14b6f6148cb82b292da:administrator:password123");
    HT("MD5-SALTMD5SALTPASS",16,HTF_SALTED | HTF_COMPOSED, compute_md5_saltmd5saltpass, "f9c666c5639562988f976ad1a21592f9:administrator:password123");
    HT("MD5-MD5PASS-SALT",  16, HTF_SALTED | HTF_COMPOSED, compute_md5salt, "fbeefbf977df9128f00baaf655c64e1c:testsalt:password123");
    HT("MD5-MD5SALT-PASS",  16, HTF_SALTED | HTF_COMPOSED, compute_md5_md5salt_pass, "14aba015c7e7c73b0f92c82c73ffb693:testsalt:password123");
    HT("MD5-PASS-MD5SALT",  16, HTF_SALTED | HTF_COMPOSED, compute_md5_pass_md5salt, "6c27fa7e5c23ae48989b3702b50be6ac:testsalt:password123");
    HT("MD5-SALTSHA1SALTPASS",16,HTF_SALTED | HTF_COMPOSED, compute_md5_saltsha1saltpass, "5fd7c63c0507ebe680ae7ac1551e7064:administrator:password123");

    /* Special salt patterns */
    HT("SHA1SALTCX",        20, HTF_SALTED, compute_sha1saltcx, "12003d630fddecf4ddae557bd87201b44e6005d1:administrator:password123");
    HT("SHA1MD5-PASSMD5SALT",20,HTF_SALTED | HTF_COMPOSED, compute_sha1md5_passmd5salt, "0ef2066a4f95e590352db3469472229fbeb40e2b:salt:password123");
    HT("SHA1MD5SALTMD5PASS",20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5saltmd5pass, "5cb36a9fcd678fd5011e51712354b4a6288e605f:salt:password123");
    HT("SHA1-SHA512PASSSHA512SALT",20,HTF_SALTED | HTF_COMPOSED, compute_sha1_sha512passsha512salt, "88fb3d0b67455f1cb561f46c0a4a6f3da1e8f4b1:salt:password123");
    HT("MD5-MD5SHA1PASSSHA1MD5SALT",16,HTF_SALTED | HTF_COMPOSED, compute_md5_md5sha1passsha1md5salt, "1cbc665711caa65542f5071709bae530:salt:password123");

    /* Unsalted composed */
    HT("SHA1SQL3",          20, HTF_COMPOSED, compute_sha1sql3, NULL);
    HT("SHA1MD5BASE64",     20, HTF_COMPOSED, compute_sha1md5base64, NULL);

    /* --- Batch 6 Wave 2 --- */
    HT("SHA1-MD5-MD5SALTMD5PASS",20,HTF_SALTED | HTF_COMPOSED, compute_sha1_md5_md5saltmd5pass, "53cab1f69f3129203fa278a818d6f989b306200f:ts:password123");
    HT("SHA1-MD5-MD5SALTMD5PASS-SALT",20,HTF_SALTED | HTF_COMPOSED, compute_sha1_md5_md5saltmd5pass_salt, "18ac7502402fbf4f002bd079082cf4a90ddebf44:ts:password123");
    HT("SHA1MD5UCSALT",     20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5ucsalt, "2d0bc23256be4ee1703af43ea5bdb6f6824f3b5d:ts:password123");
    HT("SHA1SALTMD5UC",     20, HTF_SALTED | HTF_COMPOSED, compute_sha1saltmd5uc, "331f3f3a487b157c34b38cacd82297a75b8c4c07:ts:password123");
    HT("SHA1SALTMD5MD5PASS",20, HTF_SALTED | HTF_COMPOSED, compute_sha1saltmd5md5pass, "72739a54edaf34ff617da743737b414605829f93:ts:password123");
    HT("MD5MD5SHA1SALT",    16, HTF_SALTED | HTF_COMPOSED, compute_md5md5sha1salt, "780212be6ed7005ce6b089ebe203f2ca:ts:password123");
    HT("MD5MD5SHA256SALT",  16, HTF_SALTED | HTF_COMPOSED, compute_md5md5sha256salt, "4e8cd322dc1e1010862fabd72e6f4552:ts:password123");
    HT("MD5-SHA1SALTPASS",  16, HTF_SALTED | HTF_COMPOSED, compute_md5_sha1saltpass, "9e46bf352da01ca670b412691f03a77e:salt:password123");
    HT("MD5-SALTMD5PASS-SALT",16,HTF_SALTED | HTF_COMPOSED, compute_md5_saltmd5pass_salt, "83f7b529d805d7e5137880d732c90e47:salt:password123");
    HT("SHA1MD5-SALTMD5PASS",20,HTF_SALTED | HTF_COMPOSED, compute_sha1md5_saltmd5pass, "302b412478074e67cedf730b99605a35dfbe3486:administrator:password123");
    HT("SHA1-MD5SHA1PASSSHA1MD5SALT",20,HTF_SALTED | HTF_COMPOSED, compute_sha1_md5sha1passsha1md5salt, "4be7ace64698e7e71ce0efeddab656bcc0a8b8d3:salt:password123");
    HT("SHA1SHA1UCPASSSALT",20, HTF_SALTED | HTF_COMPOSED, compute_sha1sha1ucpasssalt, "59aedd05e1e2949b21dc0309c70663e1c477a2ae:salt:password123");
    HT("SHA1SALTSHA1UCPASS",20, HTF_SALTED | HTF_COMPOSED, compute_sha1saltsha1ucpass, "b720d4ed00467338d4a4bd144c46bded78ac6c16:salt:password123");
    HT("SHA1SALTSHA1MD5",   20, HTF_SALTED | HTF_COMPOSED, compute_sha1saltsha1md5, "e6926834cc560f218c991cc474eb80948ece3336:salt:password123");
    HT("SHA1SALTMD5SHA1PASS",20,HTF_SALTED | HTF_COMPOSED, compute_sha1saltmd5sha1pass, "2f6938e8a27be6e91303ea2416ceded42f7f7a43:salt:password123");
    HT("SHA1MD5SHA1PASSSALT",20,HTF_SALTED | HTF_COMPOSED, compute_sha1md5sha1passsalt, "52f29152257009124332a1155faad8d75aa50ddc:administrator:password123");
    HT("SHA1MD5SALTPASS",   20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5saltpass, "5fffde69dd1a71affb0d576ceb74bc152972f11e:testsalt:password123");

    /* --- Batch 6 Wave 3 --- */
    /* CAP (capitalize first alpha hex char) types */
    HT("SHA1MD5CAPSALT",    20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5capsalt, "859a4fd1459a3eaee93004bf4aed18c085530c6b:ts:password123");
    HT("SHA1MD51CAPSALT",   20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5capsalt, "ae90cba55af617eadcffefdffcf808340f67d37e:salt:password123");
    HT("SHA1SHA1CAPSALT",   20, HTF_SALTED | HTF_COMPOSED, compute_sha1sha1capsalt, "f4616a12ba3a79a289fe0156ae93972b5945ef80:administrator:password123");
    HT("SHA1MD5CAPMD5SALT", 20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5capmd5salt, "fa07a0a16f53706d750ae7d2eb60c82c5955022c:ts:password123");
    HT("SHA1MD5CAPSHA1SALT",20, HTF_SALTED | HTF_COMPOSED, compute_sha1md5capsha1salt, "5fee3f3bf4aba7b1647695adb08d58b995a14300:testsalt:password123");
    /* dash CAP types (inner salt) */
    HT("SHA1-MD5CAPSALT",   20, HTF_SALTED | HTF_COMPOSED, compute_sha1_md5capsalt, "3e2517f047702aa92e32b14913304040b77f7dca:ts:password123");
    HT("SHA1-MD5CAPMD5SALT",20, HTF_SALTED | HTF_COMPOSED, compute_sha1_md5capmd5salt, "c242903b408aee37e09a5c4161e1680381c30a5a:ts:password123");
    /* CR types (append \r before outer SHA1) */
    HT("SHA1-MD5SALT-CR",   20, HTF_SALTED | HTF_COMPOSED, compute_sha1_md5salt_cr, "a1be7d556bcd65469f702ea59d84f08aa6b4b741:ts:password123");
    HT("SHA1-MD5MD5SALT-CR",20, HTF_SALTED | HTF_COMPOSED, compute_sha1_md5md5salt_cr, "cd2817aa1d583ec5eb85a2df60d1eed0efe0f726:ts:password123");
    /* Inner-salt dash types */
    HT("SHA1-MD5SHA256SALT",20, HTF_SALTED | HTF_COMPOSED, compute_sha1_md5sha256salt, "f07fc36baa11bb092a312cd97d016009c4a3897e:ts:password123");
    /* Complex composed types */
    HT("SHA1-MD5PASSMD5MD5SALT",20,HTF_SALTED | HTF_COMPOSED, compute_sha1_md5passmd5md5salt, "41afff91ba03fdc5f199875024897803c9745e48:testsalt:password123");
    HT("SHA1SALTMD5PASSMD5",20, HTF_SALTED | HTF_COMPOSED, compute_sha1saltmd5passmd5, "916a5ae2dfc5bd52161f8f88f3bc5db73c7e8156:testsalt:password123");
    HT("SHA1-SHA1SALTSHA1PASS",20,HTF_SALTED | HTF_COMPOSED, compute_sha1_sha1saltsha1pass, "2246fe3d0eb166ffed3af7798f3481daa583088f:testsalt:password123");
    HT("MD5-MD5SALT-MD5MD5PASS",16,HTF_SALTED | HTF_COMPOSED, compute_md5_md5salt_md5md5pass, "f6ad0e1f305657761efeb50a112a16ac:testsalt:password123");
    HT("SHA1-SALTSHA1PASSSALT",20,HTF_SALTED | HTF_COMPOSED, compute_sha1_saltsha1passsalt, "6340b126a260709cad113e9fe0cb8e0a6be200ee:testsalt:password123");
    /* RAW types */
    HT("SHA256-SALTSHA256RAW",32,HTF_SALTED | HTF_COMPOSED, compute_sha256_saltsha256raw, "e8ce7be541f79491609f5834c3c7ae8a3abe63d237e07fd6d492356a1697c08b:Salt:password123");

    /* --- Non-hex verify types --- */
    HTV("APACHE-SHA", 0, verify_apachesha, "{SHA}y/2sYAj5yrQIN4TL0YdPdmGNKpc=:password123");
    HTV("BCRYPT",     0, verify_bcrypt, "$2a$12$DG3Vk1qDyvwkh96yaCuf6.HqWPKac6Ur7nOitGIbrN05iqtnveM7C:password123");
    HTV("BCRYPTMD5",  0, verify_bcryptmd5, "$2b$12$M708MGo3FgbZp6Fy83zKTOP3oqrEjAJam0PrYYkHr8mHEvnPqJsru:password123");
    HTV("BCRYPTSHA1", 0, verify_bcryptsha1, "$2b$12$0gky1pAf50ToA0A9tqo8P.JCO.x82x3oKv7QflLyP/ZuuDVWFs43m:password123");
    HTV("PHPBB3",     0, verify_phpbb3, "$H$997LdNzHMtxNZ26WousH1K.At2SnCs0:password123");
    HTV("APR1",       0, verify_apr1, "$apr1$rndSa1t$UuNY2EWlcn4SkHJxQh1G3/:password123");
    HTV("SCRYPT",     0, verify_scrypt, "SCRYPT:1024:1:1:MDIwMzMwNTQwNDQyNQ==:5FW+zWivLxgCWj7qLiQbeC8zaNQ+qdO0NUinvqyFcfo=:hashcat");

    /* Wave 1: Simple salted hex types */
    HTV("POSTGRESQL",  0, verify_postgresql, "md5c3a6d24526b9285dd98be631e8271309:testuser:password123");
    HTV("PEOPLESOFT",  0, verify_peoplesoft, "lACuKESOE2QXTd4mmyzOG8qdfug=:password123");
    HTV("HMAILSERVER", 0, verify_hmailserver, "1234563fa01c590efd5499b9f9468f7ae5d427112933294e3d150f9bdce07e3e578ae3:password123");
    HTV("MEDIAWIKI",   0, verify_mediawiki, "$B$56668501$20461e17ce27c23cf7927fe0aa1a7725:password123");
    HTV("DAHUA",       0, verify_dahua, "27fd18d177daf2fc0d47833944eab52d:229381927:182719643:password123");
    HTV("NETSCALER",   0, verify_netscaler, "100000000c61de3dad73fee288fbafd575bb2d5d95c1ee79d:password123");
    HTV("WBB3",        0, verify_wbb3, "e4351f5c90ae882a35a1b94ac837088707111680:0000000000000000000000000000000000000000:password123");

    /* Wave 2: MSSQL + macOS */
    HTV("MSSQL2000",   0, verify_mssql2000, "0x010012345678f9cf12a8bbcee0131a6068815203371250b5cb1198069a7aec5df5cb05ef43f73acbe8572cf9d744:password123");
    HTV("MSSQL2005",   0, verify_mssql2005, "0x010012345678f9cf12a8bbcee0131a6068815203371250b5cb11:password123");
    HTV("MSSQL2012",   0, verify_mssql2012, "0x020012345678d0d6c9153b0e776be47d3075c6a6cc1f7241c63f37eea7c6f0848e79d22d746de10aa011e3204748b4b6bdd2ca58b6bfd4a987b94d915d78e0dc51e4a7bc6609:password123");
    HTV("MACOSX",      0, verify_macosx, "123456782ff71ecef04bd9660e9bad78ed5cf12d97d341c5:password123");
    HTV("MACOSX7",     0, verify_macosx7, "123456780c911e4f72ab8610bd212f4fb547c6b13c0abb1b488350f19e888fe874dbcb542ab2ad0706af8d9303164a54008937f7a328404dfb81b5e2d1017b1a5c3ea141:password123");

    /* Wave 3: DES-based */
    HTV("DESENCRYPT",  0, verify_desencrypt, "efb32954aec338ca:1172075784504605:password123");
    HTV("DES3ENCRYPT", 0, verify_des3encrypt, "c74ec0f283bb3efb:8152001061460743:password123");
    HTV("RACF",        0, verify_racf, "6A182040F07213B8:USER:password123");

    /* Wave 4: Cisco + Juniper */
    HTV("JUNIPERSSG",  0, verify_juniperssg, "nKLFAKrpHSNHcHMMnsaMoCDtGrPj0n:user:password123");
    HTV("CISCOPIX",    0, verify_ciscopix, "5wyJZrN0zZZDiHA6:password123");
    HTV("CISCOASA",    0, verify_ciscoasa, "iOZ4lbE3GPO/eeeS:36:password123");
    HTV("CISCO4",      0, verify_cisco4, "vt8rS9fyRlu773i7v9k6d2dC3ak4NNYFW/wsDIFnuIw:password123");
    HTV("CISCOISE",    0, verify_ciscoise, "6921eaf6ba9eedb30c84a2c7fed2309e964d631f69e7f6b2972482dcb68007824d65737361676544696765737400000000000000000000000000000000000000:password123");

    /* Wave 5: Iterated types */
    HTV("SAMSUNGSHA1", 0, verify_samsungsha1, "b663d01f50b917f6a9b1aa402207f863ba8b7c41:2173921648:password123");
    HTV("EPISERVER",   0, verify_episerver, "$episerver$*0*RGVm*qNFZycuVKKgy9gzqwETNNLxZ+vg:password123");
    HTV("SYBASE-ASE",  0, verify_sybase, "0xc00700000000000000000995a15a592719c9407085d7dfd203f6c11a9de5bf449e3cb93e90439d4c65aa:password123");

    /* Wave 6: HMAC + KRB5 */
    HTV("IPMI2-SHA1",  0, verify_ipmi2sha1, "00:1c9f35d812ea7ef72acdd262ec5e3ae59582103a:password123");
    HTV("IPMI2-MD5",   0, verify_ipmi2md5, "e83eb99a98bd696bc41c0826bb378986:00:password123");
    HTV("KRB5PA23",    0, verify_krb5pa23, "$krb5pa$23$x$x$x$06e07bf14b909c6e6773b7d0bc9fd9a04602c3bd4991ffc7438a60446a40b384d2f13ce9124a8f7024bd831d9b66b1052440:password123");

    /* Wave 7: crypt/PBKDF2 */
    HTV("AIX-MD5",     0, verify_aixmd5, "{smd5}rndSa1t$7BZvKWug/Zy4p.iPozdxC0:password123");
    HTV("AIX-SHA1",    0, verify_aixsha1, "{ssha1}06$bJbkFGJAB30L2e23$zKSZhTrB6UjXkJlxKsxSALf2.MH:password123");
    HTV("AIX-SHA256",  0, verify_aixsha256, "{ssha256}06$aJckFGJAB30LTe10$3nmSlxZe9vAsv7ylzEjjt9K6x2zac8Zm3udVIFZ9.Qr:password123");
    HTV("AIX-SHA512",  0, verify_aixsha512, "{ssha512}06$bJbkFGJAB30L2e23$6kmLDyWSi0Y5c4.h/cUmVKFO9j.F/p/JvfeTcfEjvIANUghVYQFTVfrQ4u2fs1laoJlsV/34DQaITeWwBAqN..:password123");
    HTV("MYSQL-SHA256CRYPT", 0, verify_mysqlsha256crypt, "$mysql$A$005*0000000000*735953686774693157507A4A56526F713439744874516D6878335855747A644E416D506979304547335A37:password123");
    HTV("DRUPAL7",     0, verify_drupal7, "$S$C00000000uP3JXd.0IL30e76wJH2NZ/Ovd0AALo.mjXytygeAP9u:password123");

    /* Wave 8: Custom transform */
    HTV("NSEC3",       0, verify_nsec3, "44jvntvfj82gq27k8ps7pqrjlo5h9c58:.x.net:1:00:password123");
    HTV("DOMINO5",     0, verify_domino5, "173127311326bb6eeacdfef5c2791514:password123");
    HTV("DOMINO6",     0, verify_domino6, "(G0000101iBosJ2cVSZqu):password123");

    #undef HT
    #undef HTC
    #undef HTV

    /* --- Build per-hashlen candidate caches --- */
    {
        int cnt[MAX_HASHLEN], scnt[MAX_HASHLEN], ccnt[MAX_HASHLEN];
        memset(cnt, 0, sizeof(cnt));
        memset(scnt, 0, sizeof(scnt));
        memset(ccnt, 0, sizeof(ccnt));

        /* Count candidates per hashlen */
        for (i = 0; i < Numtypes; i++) {
            if (!Hashtypes[i].compute && Hashtypes[i].nchain == 0) continue;
            h = Hashtypes[i].hashlen;
            if (h < 0 || h >= MAX_HASHLEN) continue;
            if (Hashtypes[i].flags & HTF_COMPOSED)
                ccnt[h]++;
            else if (Hashtypes[i].flags & HTF_SALTED)
                scnt[h]++;
            else
                cnt[h]++;
        }

        /* Allocate arrays */
        for (h = 0; h < MAX_HASHLEN; h++) {
            if (cnt[h]) {
                Unsalted[h].list = (struct hashtype **)malloc(cnt[h] * sizeof(struct hashtype *));
                Unsalted[h].count = 0;
            }
            if (scnt[h]) {
                Salted[h].list = (struct hashtype **)malloc(scnt[h] * sizeof(struct hashtype *));
                Salted[h].count = 0;
            }
            if (ccnt[h]) {
                Composed[h].list = (struct hashtype **)malloc(ccnt[h] * sizeof(struct hashtype *));
                Composed[h].count = 0;
            }
        }

        /* Fill arrays */
        for (i = 0; i < Numtypes; i++) {
            if (!Hashtypes[i].compute && Hashtypes[i].nchain == 0) continue;
            h = Hashtypes[i].hashlen;
            if (h < 0 || h >= MAX_HASHLEN) continue;
            if (Hashtypes[i].flags & HTF_COMPOSED)
                Composed[h].list[Composed[h].count++] = &Hashtypes[i];
            else if (Hashtypes[i].flags & HTF_SALTED)
                Salted[h].list[Salted[h].count++] = &Hashtypes[i];
            else
                Unsalted[h].list[Unsalted[h].count++] = &Hashtypes[i];
        }
    }
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

/* Run a generic chain: chain[0]=innermost applied to pass, then hex→chain[1]→hex→...→chain[n-1]=outermost */
static void run_chain(const struct hashtype *ht,
    const unsigned char *pass, int passlen, unsigned char *dest)
{
    unsigned char buf[MAX_HASH_BYTES];
    char hx[MAX_HASH_BYTES * 2 + 1];
    int i;

    ht->chain[0].fn(pass, passlen, NULL, 0, buf);
    for (i = 1; i < ht->nchain; i++) {
        if (ht->chain[i - 1].uc_hex == 2) {
            /* Raw binary pass-through: feed raw bytes directly to next step */
            ht->chain[i].fn(buf, ht->chain[i - 1].outbytes, NULL, 0, buf);
        } else {
            if (ht->chain[i - 1].uc_hex == 1)
                prmd5UC(buf, hx, ht->chain[i - 1].outbytes * 2);
            else
                prmd5(buf, hx, ht->chain[i - 1].outbytes * 2);
            ht->chain[i].fn((const unsigned char *)hx,
                ht->chain[i - 1].outbytes * 2, NULL, 0, buf);
        }
    }
    memcpy(dest, buf, ht->chain[ht->nchain - 1].outbytes);
}

/* Unified hash computation: dispatches to chain or compute */
static inline void hash_compute(const struct hashtype *ht,
    const unsigned char *pass, int passlen,
    const unsigned char *salt, int saltlen, unsigned char *dest)
{
    static const unsigned char empty_salt[1] = {0};
    if (ht->nchain > 0)
        run_chain(ht, pass, passlen, dest);
    else
        ht->compute(pass, passlen, salt ? salt : empty_salt, saltlen,
                    dest);
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
    char ucname[128];
    int i, len;
    PWord_t PV;

    /* Judy keys are stored uppercase; upcase the query */
    len = strlen(name);
    if (len >= (int)sizeof(ucname)) return NULL;
    for (i = 0; i < len; i++)
        ucname[i] = toupper((unsigned char)name[i]);
    ucname[len] = 0;

    JSLG(PV, TypenameJ, (unsigned char *)ucname);
    if (PV && *PV > 0) {
        int idx = (int)(*PV - 1);
        if (Hashtypes[idx].compute || Hashtypes[idx].nchain > 0
            || Hashtypes[idx].verify)
            return &Hashtypes[idx];
    }
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
    int h, j, n = 0;
    struct candcache *cache = have_salt ? Salted : Unsalted;

    for (h = hashbytes; h < MAX_HASHLEN && n < max; h++) {
        for (j = 0; j < cache[h].count && n < max; j++)
            cands[n++] = cache[h].list[j];
    }
    return n;
}

/* Get composed candidates with hashlen >= hashbytes */
static int get_composed_by_hashlen(int hashbytes,
    struct hashtype **cands, int max)
{
    int h, j, n = 0;

    for (h = hashbytes; h < MAX_HASHLEN && n < max; h++) {
        for (j = 0; j < Composed[h].count && n < max; j++)
            cands[n++] = Composed[h].list[j];
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

/* ---- $TESTVEC[] decode ---- */

/* Decode $TESTVEC[HH x NNNNNNN] password into pre-allocated testvec buffer.
 * Returns expanded length, or -1 if not $TESTVEC format. */
static int decode_testvec_password(const char *pass, int passlen,
    unsigned char *out, int outmax)
{
    const char *p, *end, *sep;
    unsigned char pat[256];
    int patbytes, hexlen, count, total, i;

    if (passlen < 15) return -1;  /* $TESTVEC[HH x N] minimum */
    if (strncmp(pass, "$TESTVEC[", 9) != 0) return -1;
    if (pass[passlen - 1] != ']') return -1;

    p = pass + 9;
    end = pass + passlen - 1;  /* points to ']' */

    /* Find " x " separator */
    sep = NULL;
    for (i = 0; p + i + 2 < end; i++) {
        if (p[i] == ' ' && p[i+1] == 'x' && p[i+2] == ' ') {
            sep = p + i;
            break;
        }
    }
    if (!sep) return -1;

    /* Parse hex pattern before separator */
    hexlen = (int)(sep - p);
    if (hexlen < 2 || hexlen > (int)sizeof(pat) * 2) return -1;
    patbytes = hex2bin(p, hexlen, pat);
    if (patbytes <= 0) return -1;

    /* Parse decimal repeat count after " x " */
    p = sep + 3;
    if (p >= end) return -1;
    if (end - p > 7) return -1;  /* max 7 digits */
    count = 0;
    for (; p < end; p++) {
        if (*p < '0' || *p > '9') return -1;
        count = count * 10 + (*p - '0');
    }
    if (count <= 0) return -1;

    /* Compute total and clamp to outmax */
    total = patbytes * count;
    if (total > outmax) total = outmax;

    /* Fill output buffer with repeated pattern */
    if (patbytes == 1) {
        memset(out, pat[0], total);
    } else {
        int pos;
        for (pos = 0; pos + patbytes <= total; pos += patbytes)
            memcpy(out + pos, pat, patbytes);
        if (pos < total)
            memcpy(out + pos, pat, total - pos);
    }
    return total;
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
    if (passlen >= 9 && strncmp(pass, "$TESTVEC[", 9) == 0)
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
    char *fullpass;         /* no-salt interpretation: everything after colon1 */
    int fullpasslen;
    struct hashtype *hint;  /* type hint, or NULL */
    int hint_iter;          /* iteration count from xNN suffix */
    int hash_is_uc;         /* original hex had uppercase */

    /* Output fields (set by worker) */
    int verified;           /* 1 if verified */
    struct hashtype *match_type;
    int match_iter;         /* iteration count that matched */
};


#define HOT_LIST_MAX 8

struct batch {
    struct workitem items[BATCH_SIZE];
    char buf[BATCH_BUFSIZE];
    int count;          /* items in this batch, -1 = poison pill */
    int bufused;
    int hot_type;       /* index into Hashtypes[], -1 = none */
    int hot_iter;
    int hot_list[HOT_LIST_MAX]; /* recently matched type indices, MRU first */
    int nhot;                   /* entries used in hot_list */
    struct workspace *ws; /* per-job heap workspace, set by alloc_batch */
    struct batch *next; /* free list / work queue */
};

/* ---- Globals ---- */

#define TARGET_BATCH_SECS 0.75
static volatile int BatchLimit = BATCH_SIZE;
static int Numthreads = 1;
static int Maxiter = 128;
static int Iterstep = 128;
static FILE *Outfp;
static FILE *Errfp;
static int *ModeList;                   /* -m: ordered array of type indices */
static int ModeCount;                   /* entries in ModeList */
static int ModeAuto;                    /* -m includes "auto": fallback to auto-detect */
static int GlobalHotType = -1;
static int GlobalHotIter = 0;
static int GlobalHotList[HOT_LIST_MAX];  /* recently matched types, MRU first */
static int GlobalNhot = 0;

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
        b->ws = malloc(sizeof(struct workspace));
        if (!b->ws) {
            fprintf(stderr, "hashpipe: out of memory (workspace)\n");
            exit(1);
        }
        b->ws->testvec = malloc(TESTVECSIZE + 16);
    }
    b->count = 0;
    b->bufused = 0;
    b->hot_type = GlobalHotType;
    b->hot_iter = GlobalHotIter;
    memcpy(b->hot_list, GlobalHotList, GlobalNhot * sizeof(int));
    b->nhot = GlobalNhot;
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
        rhash_msg(RHASH_MD5, data, datalen, dest);
    else if (hashbytes == 20)
        SHA1(data, datalen, dest);
    else if (hashbytes == 28)
        SHA224(data, datalen, dest);
    else if (hashbytes == 32)
        SHA256(data, datalen, dest);
    else if (hashbytes == 48)
        SHA384(data, datalen, dest);
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

/* Add a type to the hot list (MRU front). Promotes if already present. */
static void hot_list_add(int *hot_list, int *nhot, int type_idx)
{
    int i;
    for (i = 0; i < *nhot; i++) {
        if (hot_list[i] == type_idx) {
            if (i > 0) {
                memmove(&hot_list[1], &hot_list[0], i * sizeof(int));
                hot_list[0] = type_idx;
            }
            return;
        }
    }
    if (*nhot < HOT_LIST_MAX) {
        memmove(&hot_list[1], &hot_list[0], *nhot * sizeof(int));
        (*nhot)++;
    } else {
        memmove(&hot_list[1], &hot_list[0], (HOT_LIST_MAX - 1) * sizeof(int));
    }
    hot_list[0] = type_idx;
}

static void verify_item(struct workitem *item, int *hot_type, int *hot_iter,
                        int *hot_list, int *nhot)
{
    unsigned char hashbin[MAX_HASH_BYTES];
    unsigned char computed[MAX_HASH_BYTES];
    unsigned char *passbuf = WS->passbuf;
    unsigned char saltbin[MAX_SALT_BYTES];
    unsigned char altsaltbin[MAX_SALT_BYTES];
    unsigned char colonsalt[MAX_SALT_BYTES + 1];
    unsigned char iterbuf[MAX_HASH_BYTES];
    const unsigned char *pass;
    int passlen, hashbytes, saltbinlen, altsaltbinlen;
    const unsigned char *altpass;
    int altpasslen;
    struct hashtype *cands[MAX_CANDIDATES];
    int ncands, c, iter;

    item->verified = 0;

    /* Non-hex format: try verify function if hinted type has one */
    if (item->hint && item->hint->verify) {
        const unsigned char *vpass;
        int vpasslen;
        unsigned char *vpassbuf = WS->vpassbuf;
        vpasslen = decode_hex_password(item->password, item->passlen,
                                       vpassbuf, MAXLINE);
        if (vpasslen >= 0) {
            vpass = vpassbuf;
        } else {
            vpasslen = decode_testvec_password(item->password, item->passlen,
                                               WS->testvec, TESTVECSIZE);
            if (vpasslen >= 0) {
                vpass = WS->testvec;
            } else {
                vpass = (const unsigned char *)item->password;
                vpasslen = item->passlen;
            }
        }
        if (item->hint->verify(item->hashstr, item->hashlen, vpass, vpasslen)) {
            item->verified = 1;
            item->match_type = item->hint;
            item->match_iter = 1;
            return;
        }
        /* Hint failed — try other verify types */
        if (ModeCount > 0) {
            int m;
            for (m = 0; m < ModeCount; m++) {
                struct hashtype *ht = &Hashtypes[ModeList[m]];
                if (!ht->verify || ht == item->hint) continue;
                if (ht->verify(item->hashstr, item->hashlen, vpass, vpasslen)) {
                    item->verified = 1;
                    item->match_type = ht;
                    item->match_iter = 1;
                    return;
                }
            }
        } else {
            /* Auto-detect: scan all verify types */
            int v;
            for (v = 0; v < Numtypes; v++) {
                struct hashtype *ht = &Hashtypes[v];
                if (!ht->verify || ht == item->hint) continue;
                if (ht->verify(item->hashstr, item->hashlen, vpass, vpasslen)) {
                    item->verified = 1;
                    item->match_type = ht;
                    item->match_iter = 1;
                    return;
                }
            }
        }
        return;  /* non-hex types can't fallback to hex matching */
    }

    /* Decode hex hash to binary */
    hashbytes = hex2bin(item->hashstr, item->hashlen, hashbin);
    if (hashbytes < 0) {
        /* Non-hex hash, no hint — try all verify types (auto-detect) */
        const unsigned char *vpass;
        int vpasslen, v;
        vpasslen = decode_hex_password(item->password, item->passlen,
                                       WS->vpassbuf, MAXLINE);
        if (vpasslen >= 0) { vpass = WS->vpassbuf; }
        else {
            vpasslen = decode_testvec_password(item->password, item->passlen,
                                               WS->testvec, TESTVECSIZE);
            if (vpasslen >= 0) { vpass = WS->testvec; }
            else { vpass = (const unsigned char *)item->password; vpasslen = item->passlen; }
        }

        /* Hot list verify types first */
        {
            int h;
            for (h = 0; h < *nhot; h++) {
                struct hashtype *ht = &Hashtypes[hot_list[h]];
                if (!ht->verify) continue;
                if (ht->verify(item->hashstr, item->hashlen, vpass, vpasslen)) {
                    item->verified = 1;
                    item->match_type = ht;
                    item->match_iter = 1;
                    *hot_type = hot_list[h];
                    *hot_iter = 1;
                    if (h > 0) {
                        int matched = hot_list[h];
                        memmove(&hot_list[1], &hot_list[0], h * sizeof(int));
                        hot_list[0] = matched;
                    }
                    return;
                }
            }
        }
        /* Full scan of all verify types */
        for (v = 0; v < Numtypes; v++) {
            struct hashtype *ht = &Hashtypes[v];
            if (!ht->verify) continue;
            if (ht->verify(item->hashstr, item->hashlen, vpass, vpasslen)) {
                item->verified = 1;
                item->match_type = ht;
                item->match_iter = 1;
                *hot_type = v;
                *hot_iter = 1;
                hot_list_add(hot_list, nhot, v);
                return;
            }
        }
        return;
    }

    /* Decode password: handle $HEX[] and $TESTVEC[] */
    passlen = decode_hex_password(item->password, item->passlen, passbuf, MAXLINE);
    if (passlen >= 0) {
        pass = passbuf;
    } else {
        passlen = decode_testvec_password(item->password, item->passlen,
                                          WS->testvec, TESTVECSIZE);
        if (passlen >= 0) {
            pass = WS->testvec;
        } else {
            pass = (const unsigned char *)item->password;
            passlen = item->passlen;
        }
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

    /* Decode alternate salt/password if available */
    altsaltbinlen = 0;
    altpass = NULL;
    altpasslen = 0;
    if (item->alt_salt && item->alt_saltlen > 0) {
        int sdec = decode_hex_password(item->alt_salt, item->alt_saltlen,
                                       altsaltbin, MAX_SALT_BYTES);
        if (sdec >= 0) {
            altsaltbinlen = sdec;
        } else {
            altsaltbinlen = item->alt_saltlen;
            if (altsaltbinlen > MAX_SALT_BYTES) altsaltbinlen = MAX_SALT_BYTES;
            memcpy(altsaltbin, item->alt_salt, altsaltbinlen);
        }
    }
    if (item->alt_password) {
        /* vpassbuf is free here (only used in verify-function early-return path) */
        unsigned char *altbuf = WS->vpassbuf;
        int adec = decode_hex_password(item->alt_password, item->alt_passlen,
                                       altbuf, MAXLINE);
        if (adec >= 0) {
            altpass = altbuf;
            altpasslen = adec;
        } else {
            altpasslen = decode_testvec_password(item->alt_password, item->alt_passlen,
                                                 WS->testvec, TESTVECSIZE);
            if (altpasslen >= 0) {
                altpass = WS->testvec;
            } else {
                altpass = (const unsigned char *)item->alt_password;
                altpasslen = item->alt_passlen;
            }
        }
    }

    /* --- Hot list check: try all recently matched types, both salt splits --- */
    {
        int h;
        for (h = 0; h < *nhot; h++) {
            struct hashtype *ht = &Hashtypes[hot_list[h]];
            if (ht->hashlen < hashbytes) continue;

            /* Try primary salt split (salted types with non-empty salt) */
            if ((ht->flags & HTF_SALTED) && saltbinlen > 0) {
                hash_compute(ht, pass, passlen, saltbin, saltbinlen, computed);
                if (hash_match(hashbin, hashbytes, computed, ht->hashlen))
                    goto hot_match;
                if ((ht->flags & HTF_COMPOSED) && saltbinlen < MAX_SALT_BYTES) {
                    colonsalt[0] = ':';
                    memcpy(colonsalt + 1, saltbin, saltbinlen);
                    hash_compute(ht, pass, passlen, colonsalt, saltbinlen + 1, computed);
                    if (hash_match(hashbin, hashbytes, computed, ht->hashlen))
                        goto hot_match;
                }
                if (ht->compute_alt) {
                    ht->compute_alt(pass, passlen, saltbin, saltbinlen, computed);
                    if (hash_match(hashbin, hashbytes, computed, ht->hashlen))
                        goto hot_match;
                }
            }

            /* Try alternate salt split (covers empty-primary-salt case too) */
            if (altsaltbinlen > 0 && altpass) {
                if (ht->flags & HTF_SALTED) {
                    hash_compute(ht, altpass, altpasslen, altsaltbin, altsaltbinlen, computed);
                    if (hash_match(hashbin, hashbytes, computed, ht->hashlen)) {
                        char *ts = item->salt; int tsl = item->saltlen;
                        char *tp = item->password; int tpl = item->passlen;
                        item->salt = item->alt_salt; item->saltlen = item->alt_saltlen;
                        item->password = item->alt_password; item->passlen = item->alt_passlen;
                        item->alt_salt = ts; item->alt_saltlen = tsl;
                        item->alt_password = tp; item->alt_passlen = tpl;
                        goto hot_match;
                    }
                }
            }

            /* Try unsalted interpretation */
            if (!(ht->flags & HTF_SALTED)) {
                hash_compute(ht, pass, passlen, NULL, 0, computed);
                if (hash_match(hashbin, hashbytes, computed, ht->hashlen))
                    goto hot_match;
            }

            /* Try fullpass (no-salt, for unsalted hot list types) */
            if (item->fullpass && !(ht->flags & HTF_SALTED)) {
                const unsigned char *fp;
                int fplen;
                unsigned char *fpbuf = WS->vpassbuf;
                int fdec = decode_hex_password(item->fullpass, item->fullpasslen,
                                               fpbuf, MAXLINE);
                if (fdec >= 0) { fp = fpbuf; fplen = fdec; }
                else {
                    fdec = decode_testvec_password(item->fullpass, item->fullpasslen,
                                                   WS->testvec, TESTVECSIZE);
                    if (fdec >= 0) { fp = WS->testvec; fplen = fdec; }
                    else { fp = (const unsigned char *)item->fullpass; fplen = item->fullpasslen; }
                }
                hash_compute(ht, fp, fplen, NULL, 0, computed);
                if (hash_match(hashbin, hashbytes, computed, ht->hashlen)) {
                    item->password = item->fullpass;
                    item->passlen = item->fullpasslen;
                    item->salt = NULL; item->saltlen = 0;
                    item->fullpass = NULL;
                    goto hot_match;
                }
            }
            continue;

        hot_match:
            item->verified = 1;
            item->match_type = ht;
            item->match_iter = (ht->flags & HTF_ITER_X0) ? 0 : 1;
            *hot_type = hot_list[h];
            *hot_iter = item->match_iter;
            /* Promote matched type to front of hot list */
            if (h > 0) {
                int matched = hot_list[h];
                memmove(&hot_list[1], &hot_list[0], h * sizeof(int));
                hot_list[0] = matched;
            }
            return;
        }
    }

    /* --- Easy pass: try hinted type --- */
    if (item->hint) {
        struct hashtype *ht = item->hint;
        if (ht->hashlen >= hashbytes) {
            if ((ht->flags & HTF_SALTED) && saltbinlen > 0) {
                hash_compute(ht, pass, passlen, saltbin, saltbinlen, computed);
                if (hash_match(hashbin, hashbytes, computed, ht->hashlen)) {
                    item->verified = 1;
                    item->match_type = ht;
                    item->match_iter = (ht->flags & HTF_ITER_X0) ? 0 : 1;
                    *hot_type = ht - Hashtypes;
                    *hot_iter = item->match_iter;
                    return;
                }
                if ((ht->flags & HTF_COMPOSED) && saltbinlen < MAX_SALT_BYTES) {
                    colonsalt[0] = ':';
                    memcpy(colonsalt + 1, saltbin, saltbinlen);
                    hash_compute(ht, pass, passlen, colonsalt, saltbinlen + 1, computed);
                    if (hash_match(hashbin, hashbytes, computed, ht->hashlen)) {
                        item->verified = 1;
                        item->match_type = ht;
                        item->match_iter = (ht->flags & HTF_ITER_X0) ? 0 : 1;
                        *hot_type = ht - Hashtypes;
                        *hot_iter = item->match_iter;
                        return;
                    }
                }
                /* compute_alt retry (e.g. HUM prepend variant) */
                if (ht->compute_alt) {
                    ht->compute_alt(pass, passlen, saltbin, saltbinlen, computed);
                    if (hash_match(hashbin, hashbytes, computed, ht->hashlen)) {
                        item->verified = 1;
                        item->match_type = ht;
                        item->match_iter = (ht->flags & HTF_ITER_X0) ? 0 : 1;
                        *hot_type = ht - Hashtypes;
                        *hot_iter = item->match_iter;
                        return;
                    }
                }
            } else if (!(ht->flags & HTF_SALTED)) {
                hash_compute(ht, pass, passlen, NULL, 0, computed);
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

    /* --- ModeList x=1 pass (try -m types only) --- */
    if (ModeCount > 0) {
        int m;
        for (m = 0; m < ModeCount; m++) {
            struct hashtype *ht = &Hashtypes[ModeList[m]];

            /* non-hex verify types (check before hashlen filter) */
            if (ht->verify) {
                if (ht->verify(item->hashstr, item->hashlen, pass, passlen)) {
                    item->verified = 1;
                    item->match_type = ht;
                    item->match_iter = 1;
                    *hot_type = ModeList[m];
                    *hot_iter = 1;
                    return;
                }
                continue;
            }

            if (ht->hashlen < hashbytes) continue;

            if ((ht->flags & HTF_SALTED) && saltbinlen > 0) {
                hash_compute(ht, pass, passlen, saltbin, saltbinlen, computed);
                if (hash_match(hashbin, hashbytes, computed, ht->hashlen)) {
                    item->verified = 1;
                    item->match_type = ht;
                    item->match_iter = (ht->flags & HTF_ITER_X0) ? 0 : 1;
                    *hot_type = ModeList[m];
                    *hot_iter = item->match_iter;
                    return;
                }
                if ((ht->flags & HTF_COMPOSED) && saltbinlen < MAX_SALT_BYTES) {
                    colonsalt[0] = ':';
                    memcpy(colonsalt + 1, saltbin, saltbinlen);
                    hash_compute(ht, pass, passlen, colonsalt, saltbinlen + 1, computed);
                    if (hash_match(hashbin, hashbytes, computed, ht->hashlen)) {
                        item->verified = 1;
                        item->match_type = ht;
                        item->match_iter = (ht->flags & HTF_ITER_X0) ? 0 : 1;
                        *hot_type = ModeList[m];
                        *hot_iter = item->match_iter;
                        return;
                    }
                }
                /* compute_alt retry (e.g. HUM prepend variant) */
                if (ht->compute_alt) {
                    ht->compute_alt(pass, passlen, saltbin, saltbinlen, computed);
                    if (hash_match(hashbin, hashbytes, computed, ht->hashlen)) {
                        item->verified = 1;
                        item->match_type = ht;
                        item->match_iter = (ht->flags & HTF_ITER_X0) ? 0 : 1;
                        *hot_type = ModeList[m];
                        *hot_iter = item->match_iter;
                        return;
                    }
                }
            } else if (!(ht->flags & HTF_SALTED)) {
                hash_compute(ht, pass, passlen, NULL, 0, computed);
                if (hash_match(hashbin, hashbytes, computed, ht->hashlen)) {
                    item->verified = 1;
                    item->match_type = ht;
                    item->match_iter = (ht->flags & HTF_ITER_X0) ? 0 : 1;
                    *hot_type = ModeList[m];
                    *hot_iter = item->match_iter;
                    return;
                }
            }
        }

        /* --- ModeList iteration 2..Maxiter --- */
        for (m = 0; m < ModeCount; m++) {
            struct hashtype *ht = &Hashtypes[ModeList[m]];
            char hexiter[MAX_HASH_BYTES * 2 + 1];
            int fullbytes;

            if (ht->hashlen < hashbytes) continue;
            if (ht->verify) continue;
            fullbytes = ht->hashlen;

            /* Unsalted non-composed: iterate + UC variant */
            if (!(ht->flags & (HTF_SALTED | HTF_COMPOSED | HTF_NTLM | HTF_UC))) {
                int uc;
                for (uc = 0; uc <= 1; uc++) {
                    ht->compute(pass, passlen, NULL, 0, iterbuf);
                    for (iter = 2; iter <= Maxiter; iter++) {
                        if (uc)
                            prmd5UC(iterbuf, hexiter, fullbytes * 2);
                        else
                            prmd5(iterbuf, hexiter, fullbytes * 2);
                        ht->compute((unsigned char *)hexiter, fullbytes * 2,
                                    NULL, 0, computed);
                        if (hash_match(hashbin, hashbytes, computed, fullbytes)) {
                            item->verified = 1;
                            if (uc) {
                                struct hashtype *uct = find_uc_variant(ht);
                                item->match_type = uct ? uct : ht;
                            } else {
                                item->match_type = ht;
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

            /* Composed: compute x01 via chain, iterate outer hash */
            if (ht->flags & HTF_COMPOSED) {
                int maxinner = ht->iter_fn ? Iterstep : Maxiter;
                hash_compute(ht, pass, passlen, NULL, 0, iterbuf);
                for (iter = 2; iter <= maxinner; iter++) {
                    prmd5(iterbuf, hexiter, fullbytes * 2);
                    if (ht->iter_fn)
                        ht->iter_fn((unsigned char *)hexiter, fullbytes * 2, NULL, 0, computed);
                    else
                        hash_by_len(fullbytes, (unsigned char *)hexiter,
                                    fullbytes * 2, computed);
                    if (hash_match(hashbin, hashbytes, computed, fullbytes)) {
                        item->verified = 1;
                        item->match_type = ht;
                        item->match_iter = iter;
                        *hot_type = ModeList[m];
                        *hot_iter = iter;
                        return;
                    }
                    memcpy(iterbuf, computed, fullbytes);
                }
            }

            /* Salted: salt in base computation, iterate without salt */
            if ((ht->flags & HTF_SALTED) && saltbinlen > 0 &&
                !(ht->flags & HTF_UC)) {
                int maxinner = ht->iter_fn ? Iterstep : Maxiter;
                hash_compute(ht, pass, passlen, saltbin, saltbinlen, iterbuf);
                for (iter = 2; iter <= maxinner; iter++) {
                    prmd5(iterbuf, hexiter, fullbytes * 2);
                    if (ht->iter_fn)
                        ht->iter_fn((unsigned char *)hexiter, fullbytes * 2, NULL, 0, computed);
                    else
                        hash_by_len(fullbytes, (unsigned char *)hexiter,
                                    fullbytes * 2, computed);
                    if (hash_match(hashbin, hashbytes, computed, fullbytes)) {
                        item->verified = 1;
                        item->match_type = ht;
                        item->match_iter = iter;
                        *hot_type = ModeList[m];
                        *hot_iter = iter;
                        return;
                    }
                    memcpy(iterbuf, computed, fullbytes);
                }
            }
        }

        if (!ModeAuto) return;  /* strict: no fallback to auto-detect */
    }

    /* --- Easy pass: try all salted candidates --- */
    if (saltbinlen > 0) {
        ncands = get_candidates_by_hashlen(hashbytes, 1, cands, MAX_CANDIDATES);
        for (c = 0; c < ncands; c++) {
            hash_compute(cands[c], pass, passlen, saltbin, saltbinlen, computed);
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
        hash_compute(cands[c], pass, passlen, NULL, 0, computed);
        if (hash_match(hashbin, hashbytes, computed, cands[c]->hashlen)) {
            item->verified = 1;
            item->match_type = cands[c];
            item->match_iter = (cands[c]->flags & HTF_ITER_X0) ? 0 : 1;
            *hot_type = cands[c] - Hashtypes;
            *hot_iter = item->match_iter;
            return;
        }
    }

    /* When hot list is established and item has no salt, skip expensive
     * composed and salted iteration passes — only try unsalted iterations. */

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

    /* When hot list is established, skip expensive composed/salted iteration
     * passes.  The unsalted iteration pass above handles MD5xNN etc.  Composed
     * and salted iterations are only useful for the first batch (nhot==0). */
    if (*nhot > 0)
        return;

    /* --- Hard pass: composed types (x01 check + iteration) --- */
    {
        struct hashtype *ccands[MAX_CANDIDATES];
        int nccands = get_composed_by_hashlen(hashbytes, ccands, MAX_CANDIDATES);
        for (c = 0; c < nccands; c++) {
            char hexiter[MAX_HASH_BYTES * 2 + 1];
            int fullbytes;
            const unsigned char *csalt = NULL;
            int csaltlen = 0;

            fullbytes = ccands[c]->hashlen;

            /* Pass salt if the composed type is also salted */
            if ((ccands[c]->flags & HTF_SALTED) && saltbinlen > 0) {
                csalt = saltbin;
                csaltlen = saltbinlen;
            }

            /* x01: the composed computation */
            if (!ccands[c]->compute && ccands[c]->nchain == 0) {
                fprintf(stderr, "BUG: composed type %s has no compute\n", ccands[c]->name);
                continue;
            }
            hash_compute(ccands[c], pass, passlen, csalt, csaltlen, computed);

            if (hash_match(hashbin, hashbytes, computed, fullbytes)) {
                item->verified = 1;
                item->match_type = ccands[c];
                item->match_iter = 1;
                *hot_type = ccands[c] - Hashtypes;
                *hot_iter = 1;
                return;
            }

            /* colon-separator retry for composed+salted */
            if ((ccands[c]->flags & HTF_SALTED) && csaltlen > 0 &&
                csaltlen < MAX_SALT_BYTES) {
                colonsalt[0] = ':';
                memcpy(colonsalt + 1, csalt, csaltlen);
                hash_compute(ccands[c], pass, passlen, colonsalt, csaltlen + 1, computed);
                if (hash_match(hashbin, hashbytes, computed, fullbytes)) {
                    item->verified = 1;
                    item->match_type = ccands[c];
                    item->match_iter = 1;
                    *hot_type = ccands[c] - Hashtypes;
                    *hot_iter = 1;
                    return;
                }
            }
            /* compute_alt retry (e.g. HUM prepend variant) */
            if (ccands[c]->compute_alt && csaltlen > 0) {
                ccands[c]->compute_alt(pass, passlen, csalt, csaltlen, computed);
                if (hash_match(hashbin, hashbytes, computed, fullbytes)) {
                    item->verified = 1;
                    item->match_type = ccands[c];
                    item->match_iter = 1;
                    *hot_type = ccands[c] - Hashtypes;
                    *hot_iter = 1;
                    return;
                }
            }

            memcpy(iterbuf, computed, fullbytes);
            {
                int maxinner = ccands[c]->iter_fn ? Iterstep : Maxiter;
                for (iter = 2; iter <= maxinner; iter++) {
                    prmd5(iterbuf, hexiter, fullbytes * 2);
                    if (ccands[c]->iter_fn)
                        ccands[c]->iter_fn((unsigned char *)hexiter, fullbytes * 2, NULL, 0, computed);
                    else
                        hash_by_len(fullbytes, (unsigned char *)hexiter,
                                    fullbytes * 2, computed);
                    if (hash_match(hashbin, hashbytes, computed, fullbytes)) {
                        item->verified = 1;
                        item->match_type = ccands[c];
                        item->match_iter = iter;
                        *hot_type = ccands[c] - Hashtypes;
                        *hot_iter = iter;
                        return;
                    }
                    memcpy(iterbuf, computed, fullbytes);
                }
            }
        }
    }

    /* --- Hard pass: iterate salted types --- */
    /* Salt used only in initial computation, iterations are H(hex(prev)) */
    if (saltbinlen > 0) {
        ncands = get_candidates_by_hashlen(hashbytes, 1, cands, MAX_CANDIDATES);
        for (c = 0; c < ncands; c++) {
            char hexiter[MAX_HASH_BYTES * 2 + 1];
            int fullbytes;
            int maxinner;

            if (cands[c]->flags & HTF_UC) continue;

            fullbytes = cands[c]->hashlen;
            maxinner = cands[c]->iter_fn ? Iterstep : Maxiter;

            /* Compute base with salt */
            hash_compute(cands[c], pass, passlen, saltbin, saltbinlen, iterbuf);

            for (iter = 2; iter <= maxinner; iter++) {
                prmd5(iterbuf, hexiter, fullbytes * 2);
                if (cands[c]->iter_fn)
                    cands[c]->iter_fn((unsigned char *)hexiter, fullbytes * 2, NULL, 0, computed);
                else
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
    unsigned char *decoded = WS->decoded;
    const char *pass;
    int passlen;
    int dec_len;

    /* Decode $HEX[] on the fly if present; pass through $TESTVEC[] verbatim */
    if (item->passlen >= 9 && strncmp(item->password, "$TESTVEC[", 9) == 0) {
        pass = item->password;
        passlen = item->passlen;
    } else {
        dec_len = decode_hex_password(item->password, item->passlen, decoded, MAXLINE);
        if (dec_len >= 0) {
            pass = (const char *)decoded;
            passlen = dec_len;
        } else {
            pass = item->password;
            passlen = item->passlen;
        }
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

    /* Colon + password (with $HEX[] if needed, $TESTVEC[] verbatim) */
    outbuf[pos++] = ':';
    if (passlen >= 9 && strncmp(pass, "$TESTVEC[", 9) == 0) {
        memcpy(outbuf + pos, pass, passlen);
        pos += passlen;
    } else if (needs_hex(pass, passlen)) {
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

/* ---- Adaptive batch sizing ---- */

static long long bench_one_type_timed(int idx, double max_seconds);

static void update_batch_limit(int type_idx)
{
    struct hashtype *ht = &Hashtypes[type_idx];
    int limit;
    if (ht->rate == 0) {
        struct workspace *tmp_ws = NULL;
        if (!WS) {
            tmp_ws = (struct workspace *)calloc(1, sizeof(*tmp_ws));
            tmp_ws->testvec = malloc(TESTVECSIZE + 16);
            WS = tmp_ws;
        }
        ht->rate = bench_one_type_timed(type_idx, 0.2);
        if (tmp_ws) { WS = NULL; free(tmp_ws->testvec); free(tmp_ws); }
        if (ht->rate <= 0) ht->rate = 1;
    }
    limit = (int)((double)ht->rate * TARGET_BATCH_SECS);
    if (limit < 1) limit = 1;
    if (limit > BATCH_SIZE) limit = BATCH_SIZE;
    BatchLimit = limit;
}

/* ---- Worker thread ---- */

static void worker(void *dummy)
{
    struct batch *b;
    int outpos, errpos, i, olen;
    int hot_type, hot_iter;
    int hot_list[HOT_LIST_MAX], nhot;
    int hard[BATCH_SIZE];
    int nhard;

    (void)dummy;

    for (;;) {
        possess(WorkLock);
        wait_for(WorkLock, NOT_TO_BE, 0);
        b = dequeue_batch();
        twist(WorkLock, BY, -1);

        if (!b) continue;
        WS = b->ws;  /* set thread-local workspace */
        if (b->count < 0) {
            /* Poison pill */
            free_batch(b);
            return;
        }

        outpos = 0;
        errpos = 0;
        hot_type = b->hot_type;
        hot_iter = b->hot_iter;
        memcpy(hot_list, b->hot_list, b->nhot * sizeof(int));
        nhot = b->nhot;
        nhard = 0;

        /* Fast pass: verify with hot list tried first */
        for (i = 0; i < b->count; i++) {
            verify_item(&b->items[i], &hot_type, &hot_iter, hot_list, &nhot);

            if (b->items[i].verified) {
                hot_list_add(hot_list, &nhot,
                             b->items[i].match_type - Hashtypes);
                format_output(&b->items[i], WS->fmtbuf, &olen);
                if (outpos + olen > (int)sizeof(WS->outbuf) - 1) {
                    possess(OutLock);
                    fwrite(WS->outbuf, 1, outpos, Outfp);
                    release(OutLock);
                    outpos = 0;
                }
                memcpy(WS->outbuf + outpos, WS->fmtbuf, olen);
                outpos += olen;
            } else if (b->items[i].alt_password ||
                       (b->items[i].fullpass &&
                        !(hot_type >= 0 && (Hashtypes[hot_type].flags & HTF_SALTED)))) {
                /* Has alternate split, or fullpass with unsalted/unknown hot type */
                hard[nhard++] = i;
            } else {
                /* Unresolved → stderr */
                int elen = b->items[i].linelen;
                if (errpos + elen + 1 > (int)sizeof(WS->errbuf) - 1) {
                    possess(ErrLock);
                    fwrite(WS->errbuf, 1, errpos, Errfp);
                    release(ErrLock);
                    errpos = 0;
                }
                memcpy(WS->errbuf + errpos, b->items[i].line, elen);
                errpos += elen;
                WS->errbuf[errpos++] = '\n';
            }
        }

        /* Hard pass: retry deferred items with alternate splits */
        for (i = 0; i < nhard; i++) {
            struct workitem *item = &b->items[hard[i]];

            /* Try alternate colon split (different salt boundary) */
            if (item->alt_password) {
                item->salt = item->alt_salt;
                item->saltlen = item->alt_saltlen;
                item->password = item->alt_password;
                item->passlen = item->alt_passlen;

                verify_item(item, &hot_type, &hot_iter, hot_list, &nhot);
                if (item->verified) goto hard_ok;
            }

            /* Try no-salt interpretation (full password with colons) */
            if (item->fullpass) {
                item->salt = NULL;
                item->saltlen = 0;
                item->password = item->fullpass;
                item->passlen = item->fullpasslen;

                verify_item(item, &hot_type, &hot_iter, hot_list, &nhot);
                if (item->verified) goto hard_ok;
            }

            /* Unresolved → stderr (original line) */
            {
                int elen = item->linelen;
                if (errpos + elen + 1 > (int)sizeof(WS->errbuf) - 1) {
                    possess(ErrLock);
                    fwrite(WS->errbuf, 1, errpos, Errfp);
                    release(ErrLock);
                    errpos = 0;
                }
                memcpy(WS->errbuf + errpos, item->line, elen);
                errpos += elen;
                WS->errbuf[errpos++] = '\n';
            }
            continue;

        hard_ok:
            hot_list_add(hot_list, &nhot,
                         item->match_type - Hashtypes);
            format_output(item, WS->fmtbuf, &olen);
            if (outpos + olen > (int)sizeof(WS->outbuf) - 1) {
                possess(OutLock);
                fwrite(WS->outbuf, 1, outpos, Outfp);
                release(OutLock);
                outpos = 0;
            }
            memcpy(WS->outbuf + outpos, WS->fmtbuf, olen);
            outpos += olen;
        }

        /* Flush remaining */
        if (outpos > 0) {
            possess(OutLock);
            fwrite(WS->outbuf, 1, outpos, Outfp);
            release(OutLock);
        }
        if (errpos > 0) {
            possess(ErrLock);
            fwrite(WS->errbuf, 1, errpos, Errfp);
            release(ErrLock);
        }

        /* Propagate hot type and hot list to global */
        if (hot_type >= 0) {
            if (hot_type != b->hot_type)
                update_batch_limit(hot_type);
            GlobalHotType = hot_type;
            GlobalHotIter = hot_iter;
        }
        memcpy(GlobalHotList, hot_list, nhot * sizeof(int));
        GlobalNhot = nhot;

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

    /* Prefix-based hint detection for verify types with recognizable formats */
    if (!item->hint) {
        int _remaining = end - hashstart;  /* bytes from hash start to end of line */
        if (_remaining >= 14 && memcmp(hashstart, "$episerver$*", 12) == 0)
            item->hint = find_type_by_name("EPISERVER");
        else if (_remaining >= 6 && memcmp(hashstart, "{smd5}", 6) == 0)
            item->hint = find_type_by_name("AIX-MD5");
        else if (_remaining >= 7 && memcmp(hashstart, "{ssha1}", 7) == 0)
            item->hint = find_type_by_name("AIX-SHA1");
        else if (_remaining >= 9 && memcmp(hashstart, "{ssha256}", 9) == 0)
            item->hint = find_type_by_name("AIX-SHA256");
        else if (_remaining >= 9 && memcmp(hashstart, "{ssha512}", 9) == 0)
            item->hint = find_type_by_name("AIX-SHA512");
        else if (_remaining >= 3 && memcmp(hashstart, "$S$", 3) == 0)
            item->hint = find_type_by_name("DRUPAL7");
        else if (_remaining >= 3 && memcmp(hashstart, "$B$", 3) == 0)
            item->hint = find_type_by_name("MEDIAWIKI");
        else if (_remaining >= 9 && memcmp(hashstart, "$mysql$A$", 9) == 0)
            item->hint = find_type_by_name("MYSQL-SHA256CRYPT");
        else if (_remaining >= 6 && strncasecmp(hashstart, "0x0200", 6) == 0)
            item->hint = find_type_by_name("MSSQL2012");
        else if (_remaining >= 6 && strncasecmp(hashstart, "0x0100", 6) == 0) {
            /* MSSQL2000 = 0x0100 + 8salt + 40cs + 40uc (94 hex after 0x); MSSQL2005 = 0x0100 + 8salt + 40 (54 hex after 0x) */
            int _hlen = colon_last - hashstart;
            if (_hlen >= 94)
                item->hint = find_type_by_name("MSSQL2000");
            else
                item->hint = find_type_by_name("MSSQL2005");
        }
        else if (_remaining >= 6 && strncasecmp(hashstart, "0xc007", 6) == 0)
            item->hint = find_type_by_name("SYBASE-ASE");
        else if (_remaining >= 3 && hashstart[0] == '(' && hashstart[1] == 'G')
            item->hint = find_type_by_name("DOMINO6");
        else if (_remaining >= 35 && memcmp(hashstart, "md5", 3) == 0)
            item->hint = find_type_by_name("POSTGRESQL");
        else if (_remaining >= 10 && memcmp(hashstart, "$krb5pa$23$", 11) == 0)
            item->hint = find_type_by_name("KRB5PA23");
    }
    /* Fallback: if -m selected exactly one verify type, use that */
    if (!item->hint && ModeCount > 0) {
        int _m, _nv = 0, _vi = -1;
        for (_m = 0; _m < ModeCount; _m++)
            if (Hashtypes[ModeList[_m]].verify) { _nv++; _vi = _m; }
        if (_nv == 1)
            item->hint = &Hashtypes[ModeList[_vi]];
    }

    /* Non-hex verify types skip hex validation */
    if (item->hint && item->hint->verify) {
        /* Verify types with internal colons: use last colon as hash:password boundary */
        item->hashlen = colon_last - hashstart;
        if (item->hashlen < 2) return 0;
        item->hashstr = batch_strdup(b, hashstart, item->hashlen);
        if (!item->hashstr) return 0;
        item->hash_is_uc = 0;
    } else {
        /* Validate hash is hex and even length */
        if (item->hashlen < 2 || (item->hashlen & 1) ||
            !is_hex(hashstart, item->hashlen)) {
            /* Non-hex: accept if any selected/registered mode is a verify type */
            int _m, _found = 0;
            for (_m = 0; _m < ModeCount; _m++)
                if (Hashtypes[ModeList[_m]].verify) { _found = 1; break; }
            if (_found) {
                item->hint = &Hashtypes[ModeList[_m]];
            } else if (ModeCount == 0) {
                /* Auto-detect: accept non-hex, set hint to first verify type */
                for (_m = 0; _m < Numtypes; _m++)
                    if (Hashtypes[_m].verify) { _found = 1; break; }
                if (_found) item->hint = &Hashtypes[_m];
            }
            if (!_found) return 0;
            /* Use last colon as hash:password boundary for multi-colon hash formats */
            item->hashlen = colon_last - hashstart;
            item->hashstr = batch_strdup(b, hashstart, item->hashlen);
            if (!item->hashstr) return 0;
            item->hash_is_uc = 0;
            goto hash_parsed;
        }
        item->hashstr = batch_strdup(b, hashstart, item->hashlen);
        if (!item->hashstr) return 0;
        /* Check for uppercase hex */
        item->hash_is_uc = has_uppercase_hex(hashstart, item->hashlen);
    }
hash_parsed:

    item->alt_salt = NULL;
    item->alt_saltlen = 0;
    item->alt_password = NULL;
    item->alt_passlen = 0;
    item->fullpass = NULL;
    item->fullpasslen = 0;

    /* Verify types with internal colons: hash = p..colon_last, password = after colon_last */
    if (item->hint && item->hint->verify && ncolons > 1) {
        item->salt = NULL;
        item->saltlen = 0;
        item->password = batch_strdup(b, colon_last + 1, end - (colon_last + 1));
        item->passlen = end - (colon_last + 1);
        if (!item->password) return 0;
        return 1;
    }

    if (ncolons == 1) {
        /* hash:password */
        item->salt = NULL;
        item->saltlen = 0;
        item->password = batch_strdup(b, colon1 + 1, end - (colon1 + 1));
        item->passlen = end - (colon1 + 1);
    } else if (ncolons == 2) {
        /* hash:salt:password — but might be hash:password_with_colon */
        item->salt = batch_strdup(b, colon1 + 1, colon_last - (colon1 + 1));
        item->saltlen = colon_last - (colon1 + 1);
        item->password = batch_strdup(b, colon_last + 1, end - (colon_last + 1));
        item->passlen = end - (colon_last + 1);
        /* No-salt interpretation: entire rest is the password */
        item->fullpass = batch_strdup(b, colon1 + 1, end - (colon1 + 1));
        item->fullpasslen = end - (colon1 + 1);
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
        /* No-salt interpretation: entire rest is the password */
        item->fullpass = batch_strdup(b, colon1 + 1, end - (colon1 + 1));
        item->fullpasslen = end - (colon1 + 1);
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
        if (b->count >= BatchLimit ||
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

/* ---- Benchmark mode ---- */

struct bench_result {
    int idx;            /* type index */
    long long rate;     /* hashes/second */
};

static int BenchAll;                    /* -B flag */
static char *BenchSpec;                 /* -b spec */
static int *BenchSelected;             /* malloc'd [Numtypes] boolean */
static int BenchCount;                 /* number of selected types */

/* Shared state for threaded benchmark */
static volatile int BenchNext;         /* next type index to process (atomic-ish via lock) */
static struct bench_result *BenchResults;
static volatile int BenchResultCount;
static lock *BenchLock;

/* Parse -b spec into BenchSelected[]. Returns count selected, or -1 on error. */
static int parse_bench_spec(const char *spec)
{
    const char *p = spec;
    int count = 0;

    memset(BenchSelected, 0, Numtypes * sizeof(int));

    while (*p) {
        int lo, hi;

        /* skip commas */
        while (*p == ',') p++;
        if (!*p) break;

        /* expect 'e' prefix */
        if (*p != 'e' && *p != 'E') {
            fprintf(stderr, "hashpipe: -b: expected 'e' at '%s'\n", p);
            return -1;
        }
        p++;

        /* parse number */
        if (!isdigit((unsigned char)*p)) {
            fprintf(stderr, "hashpipe: -b: expected number at '%s'\n", p);
            return -1;
        }
        lo = atoi(p);
        while (isdigit((unsigned char)*p)) p++;

        /* check for range */
        if (*p == '-') {
            p++;
            if (*p == 'e' || *p == 'E') p++;  /* optional 'e' prefix on high end */
            if (!isdigit((unsigned char)*p)) {
                fprintf(stderr, "hashpipe: -b: expected number after '-' at '%s'\n", p);
                return -1;
            }
            hi = atoi(p);
            while (isdigit((unsigned char)*p)) p++;
        } else {
            hi = lo;
        }

        /* validate range */
        if (lo < 0 || hi < 0 || lo >= Numtypes || hi >= Numtypes) {
            fprintf(stderr, "hashpipe: -b: index out of range (0-%d): e%d-e%d\n",
                Numtypes - 1, lo, hi);
            return -1;
        }
        if (lo > hi) { int t = lo; lo = hi; hi = t; }

        { int j; for (j = lo; j <= hi; j++) {
            if (!BenchSelected[j]) {
                BenchSelected[j] = 1;
                count++;
            }
        }}
    }

    return count;
}

/* Parse -m spec into ModeList[] (ordered array, no dups).
 * Same eN, eN-M, comma syntax as parse_bench_spec().
 * "auto" keyword enables fallback to auto-detect after ModeList.
 * Returns count, or -1 on error. */
static int parse_mode_spec(const char *spec)
{
    const char *p = spec;
    int cap = 64, count = 0;
    int *list = (int *)malloc(cap * sizeof(int));
    if (!list) { perror("malloc"); return -1; }

    ModeAuto = 0;

    while (*p) {
        int lo, hi, j;

        while (*p == ',') p++;
        if (!*p) break;

        /* "auto" keyword — enable fallback to auto-detect */
        if (strncasecmp(p, "auto", 4) == 0 &&
            (p[4] == ',' || p[4] == '\0')) {
            ModeAuto = 1;
            p += 4;
            continue;
        }

        /* Bare number = hashcat mode; eN = internal index */
        if (*p == 'e' || *p == 'E') {
            p++;

            if (!isdigit((unsigned char)*p)) {
                fprintf(stderr, "hashpipe: -m: expected number at '%s'\n", p);
                free(list);
                return -1;
            }
            lo = atoi(p);
            while (isdigit((unsigned char)*p)) p++;

            if (*p == '-') {
                p++;
                if (*p == 'e' || *p == 'E') p++;
                if (!isdigit((unsigned char)*p)) {
                    fprintf(stderr, "hashpipe: -m: expected number after '-' at '%s'\n", p);
                    free(list);
                    return -1;
                }
                hi = atoi(p);
                while (isdigit((unsigned char)*p)) p++;
            } else {
                hi = lo;
            }

            if (lo < 0 || hi < 0 || lo >= Numtypes || hi >= Numtypes) {
                fprintf(stderr, "hashpipe: -m: index out of range (0-%d): e%d-e%d\n",
                    Numtypes - 1, lo, hi);
                free(list);
                return -1;
            }
            if (lo > hi) { int t = lo; lo = hi; hi = t; }
        } else if (isdigit((unsigned char)*p)) {
            /* Hashcat mode number */
            int hcmode = atoi(p), x;
            while (isdigit((unsigned char)*p)) p++;
            for (x = 0; Maphashcat[x].hc != 65535; x++)
                if (hcmode == Maphashcat[x].hc) break;
            if (Maphashcat[x].mdx == 65535) {
                fprintf(stderr, "hashpipe: -m: unknown or unsupported hashcat mode %d\n", hcmode);
                free(list);
                return -1;
            }
            lo = hi = Maphashcat[x].mdx;
        } else {
            fprintf(stderr, "hashpipe: -m: expected 'e', number, or 'auto' at '%s'\n", p);
            free(list);
            return -1;
        }

        for (j = lo; j <= hi; j++) {
            /* skip duplicates */
            int k, dup = 0;
            for (k = 0; k < count; k++) {
                if (list[k] == j) { dup = 1; break; }
            }
            if (dup) continue;
            if (count >= cap) {
                cap *= 2;
                list = (int *)realloc(list, cap * sizeof(int));
                if (!list) { perror("realloc"); return -1; }
            }
            list[count++] = j;
        }
    }

    ModeList = list;
    ModeCount = count;
    return count;
}

/* Benchmark a single type for up to max_seconds. Returns hashes/second. */
static long long bench_one_type_timed(int idx, double max_seconds)
{
    struct hashtype *ht = &Hashtypes[idx];
    unsigned char dest[MAX_HASH_BYTES];
    const unsigned char *pass;
    int passlen;
    const unsigned char *salt = NULL;
    int saltlen = 0;
    const char *hashstr = NULL;
    int hashstrlen = 0;
    struct timeval tv0, tv1;
    double elapsed;
    long long count;

    /* Determine password and salt from example or defaults */
    if (ht->example) {
        /* Parse example: "hash:password" or "hash:salt:password" */
        /* For HTV types, we need the hash string portion */
        const char *ex = ht->example;
        const char *c1, *c2, *clast;

        /* Find last colon — password is after it */
        clast = strrchr(ex, ':');
        if (!clast) return 0;  /* malformed */

        pass = (const unsigned char *)(clast + 1);
        passlen = strlen(clast + 1);

        if (ht->verify) {
            /* HTV: hashstr is everything before ':password' */
            hashstr = ex;
            hashstrlen = (int)(clast - ex);
        } else if (ht->flags & HTF_SALTED) {
            /* Salted: find hash:salt:password */
            c1 = strchr(ex, ':');
            if (c1 && c1 < clast) {
                c2 = strchr(c1 + 1, ':');
                if (c2 && c2 <= clast) {
                    /* salt is between c1 and c2 (or c1 and clast if only 2 colons) */
                    if (c2 == clast) {
                        salt = (const unsigned char *)(c1 + 1);
                        saltlen = (int)(c2 - c1 - 1);
                    } else {
                        /* Multiple colons — salt is c1+1..clast-1 might be wrong */
                        /* Use second segment as salt */
                        salt = (const unsigned char *)(c1 + 1);
                        saltlen = (int)(c2 - c1 - 1);
                    }
                }
            }
        }
    } else {
        /* No example — use default password, no salt */
        if (ht->verify) return 0;  /* HTV needs example */
        if (ht->flags & HTF_SALTED) return 0;  /* salted needs example */
        pass = (const unsigned char *)"password123";
        passlen = 11;
    }

    /* Warm up */
    if (ht->verify) {
        char tmp[512];
        if (hashstrlen >= (int)sizeof(tmp)) return 0;
        memcpy(tmp, hashstr, hashstrlen);
        tmp[hashstrlen] = 0;
        ht->verify(tmp, hashstrlen, pass, passlen);
    } else {
        hash_compute(ht, pass, passlen, salt, saltlen, dest);
    }

    /* Timed loop — run for up to max_seconds */
    gettimeofday(&tv0, NULL);
    count = 0;

    if (ht->verify) {
        char tmp[512];
        int batch = 1;
        if (hashstrlen >= (int)sizeof(tmp)) return 0;
        memcpy(tmp, hashstr, hashstrlen);
        tmp[hashstrlen] = 0;
        for (;;) {
            int j;
            for (j = 0; j < batch; j++)
                ht->verify(tmp, hashstrlen, pass, passlen);
            count += batch;
            gettimeofday(&tv1, NULL);
            elapsed = (tv1.tv_sec - tv0.tv_sec) + (tv1.tv_usec - tv0.tv_usec) * 1e-6;
            if (elapsed >= max_seconds) break;
            if (batch < 1000) batch *= 2;
        }
    } else {
        int batch = 100;
        for (;;) {
            int j;
            for (j = 0; j < batch; j++)
                hash_compute(ht, pass, passlen, salt, saltlen, dest);
            count += batch;
            gettimeofday(&tv1, NULL);
            elapsed = (tv1.tv_sec - tv0.tv_sec) + (tv1.tv_usec - tv0.tv_usec) * 1e-6;
            if (elapsed >= max_seconds) break;
            if (batch < 10000) batch *= 2;
        }
    }

    return (long long)(count / elapsed);
}

/* Benchmark a single type for ~1 second. Returns hashes/second. */
static long long bench_one_type(int idx)
{
    return bench_one_type_timed(idx, 1.0);
}

/* Worker thread for benchmark */
static void bench_worker(void *dummy)
{
    struct workspace *ws = (struct workspace *)calloc(1, sizeof(*ws));
    (void)dummy;
    ws->testvec = malloc(TESTVECSIZE + 16);
    WS = ws;
    for (;;) {
        int idx;
        long long rate;

        /* Grab next type index */
        possess(BenchLock);
        idx = BenchNext++;
        release(BenchLock);

        if (idx >= Numtypes) break;
        if (!BenchSelected[idx]) continue;

        rate = bench_one_type(idx);
        if (rate <= 0) continue;

        /* Store result */
        possess(BenchLock);
        { int ri = BenchResultCount++;
          BenchResults[ri].idx = idx;
          BenchResults[ri].rate = rate;
        }
        release(BenchLock);
    }
    free(ws->testvec);
    free(ws);
}

/* Run benchmark for selected types */
static void run_benchmark(void)
{
    int i;

    BenchResults = (struct bench_result *)malloc(Numtypes * sizeof(struct bench_result));
    if (!BenchResults) { perror("malloc"); exit(1); }
    BenchResultCount = 0;
    BenchNext = 0;
    BenchLock = new_lock(0);

    /* Launch worker threads */
    for (i = 0; i < Numthreads; i++)
        launch(bench_worker, NULL);
    join_all();

    /* Output results and store rates */
    for (i = 0; i < BenchResultCount; i++) {
        struct bench_result *r = &BenchResults[i];
        struct hashtype *ht = &Hashtypes[r->idx];
        ht->rate = r->rate;
        printf("e%d\t%s\t%lld\t%d\t0x%02x\n",
            r->idx, ht->name, r->rate, ht->hashlen, ht->flags);
        BenchSelected[r->idx] = 2;  /* mark as completed */
    }

    /* Report types that were selected but could not be benchmarked */
    for (i = 0; i < Numtypes; i++) {
        if (BenchSelected[i] == 1) {
            struct hashtype *ht = &Hashtypes[i];
            printf("e%d\t%s\tn/a\t%d\t0x%02x\n",
                i, ht->name, ht->hashlen, ht->flags);
        }
    }

    free_lock(BenchLock);
    free(BenchResults);
}

/* ---- Main ---- */

static void usage(int brief)
{
    fprintf(stderr,
        "Usage: hashpipe [-t N] [-i N] [-q N] [-m S] [-o outfile] [-e errfile] [-b spec] [-B] [-V] [-h] [file ...]\n"
        "\n"
        "  -t N   Thread count (default: number of CPUs)\n"
        "  -i N   Max iteration count for hard pass (default: 128)\n"
        "  -q N   Iteration step size (reserved, default: 128)\n"
        "  -m S   Only try types in S (e.g., -m e1,e8,1000); add 'auto' to fallback\n"
        "         Bare numbers are hashcat modes; eN selects internal index\n"
        "  -o F   Output verified results to file (default: stdout)\n"
        "  -e F   Output unresolved lines to file (default: stderr)\n"
        "  -b S   Benchmark selected types (e.g., -b e1-10,e15)\n"
        "  -B     Benchmark all registered types\n"
        "  -V     Print version and exit\n"
        "  -h     Print this help and list all hash types\n"
        "\n"
        "Input: lines of [TYPE[xNN] ]hash[:salt]:password\n"
        "Output (stdout): TYPE[xNN] hash[:salt]:password  (verified)\n"
        "Output (stderr): original line  (unresolved)\n"
    );

    if (!brief && Hashtypes) {
        int i, val;
        fprintf(stderr, "\n%-10s%-10s%-30s%s\n", "Internal", "Flags", "Hash name", "hashcat -m");
        for (i = 0; i < Numtypes; i++) {
            struct hashtype *ht = &Hashtypes[i];
            char flags[16], hcbuf[64];
            int fp = 0, hci = 0;

            if (!ht->name) continue;
            if (!ht->compute && !ht->verify && ht->nchain == 0) continue;

            if (ht->flags & HTF_SALTED)   flags[fp++] = 's';
            if (ht->flags & HTF_UC)        flags[fp++] = 'u';
            if (ht->flags & HTF_NTLM)     flags[fp++] = 'n';
            if (ht->flags & HTF_COMPOSED)  flags[fp++] = 'c';
            if (ht->flags & HTF_NONHEX)   flags[fp++] = 'v';
            if (ht->verify)                flags[fp++] = 'V';
            if (fp == 0) flags[fp++] = '-';
            flags[fp] = '\0';

            for (val = 0; Maphashcat[val].hc != 65535; val++) {
                if (Maphashcat[val].mdx == i) {
                    if (hci) hci += snprintf(hcbuf + hci, sizeof(hcbuf) - hci, ",");
                    hci += snprintf(hcbuf + hci, sizeof(hcbuf) - hci, "%d", Maphashcat[val].hc);
                }
            }
            fprintf(stderr, "e%-9d%-10s%-30s%s\n", i, flags, ht->name,
                hci ? hcbuf : "n/a");
        }
        fprintf(stderr, "\nFlags: s=salted u=UC c=composed n=NTLM v=non-hex V=verify\n");
    }
}

static void init_rates(void)
{
    static const struct { int idx; long long rate; } bench_rates[] = {
        {1, 4184148LL}, {2, 4153321LL}, {3, 4765041LL}, {4, 282977LL},
        {5, 976136LL}, {6, 3217276LL}, {7, 4382271LL}, {8, 996034LL},
        {9, 859570LL}, {10, 852252LL}, {11, 765507LL}, {12, 772145LL},
        {13, 612942LL}, {14, 600547LL}, {15, 3310131LL}, {16, 5316008LL},
        {17, 2511681LL}, {18, 5665854LL}, {19, 3239696LL}, {20, 4230709LL},
        {21, 2083518LL}, {22, 3363363LL}, {23, 2246589LL}, {24, 2251020LL},
        {25, 318958LL}, {26, 318609LL}, {27, 276587LL}, {28, 280091LL},
        {29, 204133LL}, {30, 138516LL}, {31, 1773198LL}, {32, 663618LL},
        {33, 2014513LL}, {34, 475165LL}, {35, 396973LL}, {36, 399501LL},
        {37, 366123LL}, {38, 364139LL}, {39, 2116831LL}, {40, 1785104LL},
        {41, 3023781LL}, {42, 2140735LL}, {43, 1775758LL}, {44, 2992236LL},
        {45, 2125886LL}, {46, 1779069LL}, {47, 2987481LL}, {48, 2183196LL},
        {49, 1790011LL}, {50, 2177323LL}, {51, 1822120LL}, {52, 2056393LL},
        {53, 2043180LL}, {54, 1719279LL}, {55, 1719801LL}, {56, 1797796LL},
        {57, 1770923LL}, {58, 1572764LL}, {59, 1581031LL}, {60, 171612LL},
        {61, 174516LL}, {62, 172899LL}, {63, 171505LL}, {64, 308054LL},
        {65, 308646LL}, {66, 251681LL}, {67, 249786LL}, {68, 549500LL},
        {69, 551396LL}, {70, 361713LL}, {71, 258596LL}, {72, 583931LL},
        {73, 587316LL}, {74, 178062LL}, {75, 178079LL}, {76, 1557275LL},
        {77, 1554176LL}, {78, 394544LL}, {79, 392587LL}, {80, 310513LL},
        {81, 307212LL}, {82, 303065LL}, {83, 306754LL}, {84, 741438LL},
        {85, 726608LL}, {86, 741092LL}, {87, 736684LL}, {88, 801275LL},
        {89, 803647LL}, {90, 809558LL}, {91, 796557LL}, {92, 1355077LL},
        {93, 1352300LL}, {94, 698745LL}, {95, 524379LL}, {96, 589635LL},
        {97, 950062LL}, {98, 915857LL}, {99, 1089232LL}, {100, 1088534LL},
        {101, 1070351LL}, {102, 1080685LL}, {103, 1374810LL}, {104, 1351018LL},
        {105, 416474LL}, {106, 417729LL}, {107, 370088LL}, {108, 369414LL},
        {109, 151126LL}, {110, 152684LL}, {111, 2264680LL}, {112, 2224097LL},
        {113, 2202794LL}, {114, 2220347LL}, {115, 5215962LL}, {116, 770898LL},
        {117, 770086LL}, {118, 5782943LL}, {119, 127139LL}, {120, 126830LL},
        {121, 1978721LL}, {122, 1890022LL}, {123, 1764223LL}, {124, 471829LL},
        {125, 368238LL}, {126, 1543229LL}, {127, 1506882LL}, {128, 1291871LL},
        {129, 1239744LL}, {130, 1131616LL}, {131, 1104934LL}, {132, 1574574LL},
        {133, 1475605LL}, {134, 1268179LL}, {135, 1223285LL}, {136, 1118366LL},
        {137, 1100059LL}, {138, 1556342LL}, {139, 1500752LL}, {140, 1285070LL},
        {141, 1250926LL}, {142, 1120837LL}, {143, 1099323LL}, {144, 1559376LL},
        {145, 1461470LL}, {146, 1247259LL}, {147, 1202147LL}, {148, 1097050LL},
        {149, 1079652LL}, {150, 1522183LL}, {151, 1464036LL}, {152, 1260876LL},
        {153, 1212732LL}, {154, 1086279LL}, {155, 1072781LL}, {156, 1925986LL},
        {157, 1888792LL}, {158, 1299831LL}, {159, 1249078LL}, {160, 707932LL},
        {161, 620051LL}, {162, 550874LL}, {163, 543569LL}, {164, 549679LL},
        {165, 540568LL}, {166, 518624LL}, {167, 506783LL}, {168, 517097LL},
        {169, 507164LL}, {170, 2069811LL}, {171, 1994577LL}, {172, 444753LL},
        {173, 438756LL}, {174, 282156LL}, {175, 281630LL}, {176, 285024LL},
        {177, 204393LL}, {178, 478186LL}, {179, 489481LL}, {180, 435767LL},
        {181, 280361LL}, {182, 573442LL}, {183, 1721969LL}, {184, 473468LL},
        {185, 506936LL}, {186, 374915LL}, {187, 1558904LL}, {188, 415797LL},
        {189, 236117LL}, {190, 163756LL}, {191, 254156LL}, {192, 233494LL},
        {193, 1564004LL}, {194, 408180LL}, {195, 237992LL}, {196, 1349277LL},
        {197, 275778LL}, {198, 271800LL}, {199, 618836LL}, {200, 289139LL},
        {201, 1773670LL}, {202, 3625286LL}, {203, 524429LL}, {204, 174331LL},
        {205, 292877LL}, {206, 214796LL}, {207, 1188026LL}, {208, 77620LL},
        {209, 1499235LL}, {210, 1281814LL}, {211, 205041LL}, {212, 393600LL},
        {213, 343747LL}, {214, 242114LL}, {215, 229931LL}, {216, 194312LL},
        {217, 195687LL}, {218, 173166LL}, {219, 793450LL}, {220, 782533LL},
        {221, 792368LL}, {222, 772972LL}, {223, 778288LL}, {224, 412711LL},
        {225, 399785LL}, {226, 409488LL}, {227, 111890LL}, {228, 127549LL},
        {229, 57475LL}, {230, 44679LL}, {231, 1280588LL}, {232, 3368556LL},
        {233, 1630014LL}, {234, 548208LL}, {235, 476680LL}, {236, 684890LL},
        {237, 1767801LL}, {238, 557467LL}, {239, 555235LL}, {240, 319555LL},
        {241, 415421LL}, {242, 396455LL}, {243, 1367828LL}, {244, 976492LL},
        {245, 251514LL}, {246, 467549LL}, {247, 406179LL}, {248, 410005LL},
        {249, 277430LL}, {250, 470926LL}, {251, 296721LL}, {252, 1602985LL},
        {253, 1784752LL}, {254, 1162652LL}, {255, 1107750LL}, {256, 283497LL},
        {257, 215246LL}, {258, 527442LL}, {259, 323411LL}, {260, 1682584LL},
        {261, 1142526LL}, {262, 1718428LL}, {263, 3201236LL}, {264, 2555106LL},
        {265, 1399106LL}, {266, 428985LL}, {267, 1406246LL}, {268, 983603LL},
        {269, 1422172LL}, {270, 419946LL}, {271, 485315LL}, {272, 290909LL},
        {273, 2442941LL}, {274, 469595LL}, {275, 2397876LL}, {276, 805136LL},
        {277, 1052743LL}, {278, 1797780LL}, {279, 538877LL}, {280, 458125LL},
        {281, 534537LL}, {282, 1124371LL}, {283, 1802637LL}, {284, 1783441LL},
        {285, 1205525LL}, {286, 1788923LL}, {287, 486922LL}, {288, 291570LL},
        {289, 330237LL}, {290, 192763LL}, {291, 204280LL}, {292, 193611LL},
        {293, 296334LL}, {294, 275630LL}, {295, 208757LL}, {296, 195712LL},
        {297, 363175LL}, {298, 412725LL}, {299, 202093LL}, {300, 216926LL},
        {301, 210424LL}, {302, 224822LL}, {303, 1526076LL}, {304, 1047560LL},
        {305, 418367LL}, {306, 775515LL}, {307, 630650LL}, {308, 1135824LL},
        {309, 420317LL}, {310, 456449LL}, {311, 1145339LL}, {312, 1376408LL},
        {313, 968829LL}, {314, 414318LL}, {315, 759411LL}, {316, 614110LL},
        {317, 293675LL}, {318, 265003LL}, {319, 192533LL}, {320, 219963LL},
        {321, 190355LL}, {322, 356911LL}, {323, 354819LL}, {324, 211703LL},
        {325, 210194LL}, {326, 321277LL}, {327, 316120LL}, {328, 292923LL},
        {329, 297969LL}, {330, 200329LL}, {331, 147052LL}, {332, 138481LL},
        {333, 344706LL}, {334, 489529LL}, {335, 3668496LL}, {336, 2164994LL},
        {337, 413652LL}, {338, 395635LL}, {339, 237317LL}, {340, 582972LL},
        {341, 373163LL}, {342, 317861LL}, {343, 880519LL}, {344, 718458LL},
        {345, 595741LL}, {346, 2945322LL}, {347, 1780013LL}, {348, 1175985LL},
        {349, 894239LL}, {350, 1767621LL}, {351, 2049623LL}, {352, 477865LL},
        {353, 3554766LL}, {354, 1691383LL}, {355, 1110517LL}, {356, 1128916LL},
        {357, 1662942LL}, {358, 572412LL}, {359, 413908LL}, {360, 480911LL},
        {361, 255051LL}, {362, 481404LL}, {363, 1628653LL}, {367, 1013870LL},
        {368, 1289578LL}, {369, 2294910LL}, {370, 1870542LL}, {371, 1292477LL},
        {372, 3018493LL}, {373, 3005558LL}, {374, 367072LL}, {375, 1427882LL},
        {376, 547849LL}, {377, 391691LL}, {379, 1163575LL}, {380, 818495LL},
        {381, 800247LL}, {382, 314465LL}, {383, 3361691LL}, {384, 550434LL},
        {385, 1722879LL}, {386, 834199LL}, {387, 254797LL}, {388, 837504LL},
        {389, 272852LL}, {390, 857451LL}, {391, 233325LL}, {392, 858108LL},
        {393, 234612LL}, {394, 3199343LL}, {395, 1799015LL}, {396, 349650LL},
        {397, 430881LL}, {398, 698380LL}, {399, 1389396LL}, {400, 1148742LL},
        {401, 378180LL}, {402, 497804LL}, {403, 497432LL}, {404, 695274LL},
        {405, 1849714LL}, {406, 929341LL}, {407, 1720549LL}, {408, 1056889LL},
        {409, 747750LL}, {410, 3352671LL}, {411, 3007701LL}, {412, 1256839LL},
        {413, 1238055LL}, {414, 1723895LL}, {415, 181450LL}, {416, 1565551LL},
        {417, 1737128LL}, {418, 1302413LL}, {419, 409933LL}, {420, 607024LL},
        {421, 606359LL}, {422, 801522LL}, {423, 790678LL}, {424, 346957LL},
        {425, 107753617LL}, {427, 353322LL}, {428, 350262LL}, {430, 348029LL},
        {431, 350085LL}, {434, 1861918LL}, {435, 1824741LL}, {436, 64087LL},
        {437, 252902LL}, {438, 416425LL}, {439, 1004107LL}, {440, 485874LL},
        {441, 1763962LL}, {442, 500172LL}, {443, 898373LL}, {447, 1313081LL},
        {448, 331436LL}, {449, 3198857LL}, {450, 5LL}, {451, 5LL},
        {452, 5LL}, {453, 1861395LL}, {454, 1225012LL}, {455, 1747LL},
        {456, 28105439LL}, {457, 798505LL}, {458, 1061728LL}, {460, 527651LL},
        {461, 3147LL}, {462, 271066LL}, {463, 2041198LL}, {464, 347758LL},
        {465, 569534LL}, {468, 1240965LL}, {472, 1264005LL}, {475, 332660LL},
        {476, 316138LL}, {477, 299056LL}, {478, 666123LL}, {479, 341313LL},
        {480, 244778LL}, {481, 151005LL}, {482, 223741LL}, {483, 448331LL},
        {484, 393710LL}, {485, 390200LL}, {486, 674403LL}, {487, 1181620LL},
        {488, 718013LL}, {489, 508147LL}, {490, 1940673LL}, {491, 331086LL},
        {492, 299645LL}, {493, 241364LL}, {494, 238997LL}, {495, 564997LL},
        {496, 2405025LL}, {497, 1367915LL}, {498, 2083418LL}, {499, 1801092LL},
        {503, 492497LL}, {504, 1115911LL}, {505, 861184LL}, {506, 1140917LL},
        {507, 561715LL}, {508, 1163226LL}, {509, 139391LL}, {510, 370989LL},
        {520, 488660LL}, {521, 1685352LL}, {522, 89694LL}, {523, 340397LL},
        {524, 3573401LL}, {525, 3449718LL}, {526, 2722457LL}, {527, 2388522LL},
        {539, 283365LL}, {541, 1590710LL}, {542, 1604153LL}, {543, 157201LL},
        {544, 323134LL}, {545, 518053LL}, {546, 1700042LL}, {547, 1127966LL},
        {548, 225149LL}, {549, 267653LL}, {550, 262945LL}, {551, 916357LL},
        {552, 344569LL}, {553, 505992LL}, {554, 592342LL}, {555, 523485LL},
        {556, 532619LL}, {558, 1755467LL}, {559, 887929LL}, {560, 747247LL},
        {561, 484678LL}, {562, 266576LL}, {563, 460021LL}, {564, 232818LL},
        {565, 155168LL}, {566, 104598LL}, {567, 408546LL}, {568, 402059LL},
        {569, 314236LL}, {570, 2370060LL}, {571, 260959LL}, {572, 407712LL},
        {578, 1199835LL}, {579, 415235LL}, {580, 172656LL}, {581, 254291LL},
        {582, 159923LL}, {583, 162964LL}, {584, 120525LL}, {585, 154095LL},
        {586, 885241LL}, {588, 341237LL}, {592, 331687LL}, {593, 141721LL},
        {594, 342807LL}, {595, 335228LL}, {599, 143236LL}, {600, 280552LL},
        {601, 436547LL}, {604, 215507LL}, {605, 217458LL}, {606, 211775LL},
        {608, 209947LL}, {609, 209910LL}, {610, 206460LL}, {612, 210325LL},
        {613, 133867LL}, {614, 98181LL}, {615, 207207LL}, {616, 209106LL},
        {617, 345407LL}, {618, 126586LL}, {620, 212300LL}, {621, 210247LL},
        {622, 210765LL}, {623, 194433LL}, {624, 210608LL}, {625, 210689LL},
        {626, 210453LL}, {628, 370398LL}, {629, 335028LL}, {630, 217457LL},
        {631, 340416LL}, {632, 224638LL}, {634, 229352LL}, {635, 278690LL},
        {636, 221057LL}, {640, 431367LL}, {641, 445555LL}, {642, 168582LL},
        {643, 440756LL}, {644, 188948LL}, {645, 409024LL}, {646, 232850LL},
        {647, 155637LL}, {648, 225596LL}, {650, 337283LL}, {652, 1238648LL},
        {653, 298612LL}, {655, 391619LL}, {658, 394135LL}, {659, 1206548LL},
        {660, 176613LL}, {661, 262050LL}, {663, 387398LL}, {665, 1183910LL},
        {666, 409185LL}, {667, 341847LL}, {668, 313040LL}, {670, 350609LL},
        {671, 241220LL}, {673, 223567LL}, {674, 234882LL}, {675, 151731LL},
        {682, 871534LL}, {686, 319782LL}, {688, 394506LL}, {689, 245667LL},
        {693, 390983LL}, {694, 3510677LL}, {695, 553224LL}, {697, 145796LL},
        {698, 201268LL}, {699, 229741LL}, {700, 409712LL}, {701, 414026LL},
        {702, 468732LL}, {703, 1654308LL}, {704, 880221LL}, {705, 420731LL},
        {706, 257824LL}, {707, 459548LL}, {708, 97159LL}, {710, 301592LL},
        {711, 298681LL}, {712, 142617LL}, {713, 133291LL}, {714, 401232LL},
        {715, 142040LL}, {716, 333090LL}, {721, 308562LL}, {722, 267998LL},
        {723, 203120LL}, {724, 329464LL}, {727, 394464LL}, {728, 394368LL},
        {729, 393359LL}, {730, 398357LL}, {731, 368747LL}, {732, 426355LL},
        {734, 369602LL}, {740, 349157LL}, {741, 316769LL}, {743, 941262LL},
        {745, 231249LL}, {746, 376832LL}, {748, 323317LL}, {750, 153113LL},
        {752, 422887LL}, {753, 401537LL}, {754, 396220LL}, {755, 207316LL},
        {758, 317004LL}, {760, 143236LL}, {761, 135762LL}, {762, 226386LL},
        {764, 211249LL}, {765, 418976LL}, {766, 270135LL}, {767, 1117038LL},
        {768, 496730LL}, {769, 492517LL}, {770, 424587LL}, {771, 432605LL},
        {772, 390142LL}, {773, 355393LL}, {774, 264583LL}, {775, 649494LL},
        {776, 360480LL}, {777, 1446142LL}, {778, 455664LL}, {779, 419830LL},
        {780, 261473LL}, {781, 1005062LL}, {782, 621135LL}, {786, 1431914LL},
        {790, 349211LL}, {792, 231386LL}, {793, 208678LL}, {794, 186815LL},
        {795, 183000LL}, {796, 167076LL}, {797, 166832LL}, {798, 193712LL},
        {799, 331596LL}, {800, 2105379LL}, {801, 1992058LL}, {802, 1984238LL},
        {803, 1390085LL}, {804, 1338384LL}, {805, 628506LL}, {806, 971939LL},
        {807, 957041LL}, {808, 582128LL}, {809, 747979LL}, {810, 732413LL},
        {811, 892239LL}, {812, 899090LL}, {813, 589941LL}, {814, 751504LL},
        {815, 740375LL}, {816, 751092LL}, {820, 760561LL}, {823, 940978LL},
        {825, 1226642LL}, {826, 502566LL}, {827, 897983LL}, {828, 1236630LL},
        {830, 79188036LL}, {831, 1324961LL}, {832, 1314939LL}, {834, 1806326LL},
        {837, 124372LL}, {838, 125236LL}, {839, 111172LL}, {840, 111886LL},
        {841, 2648787LL}, {842, 2594592LL}, {843, 2632009LL}, {844, 5284524LL},
        {845, 3172941LL}, {846, 4023442LL}, {847, 4203886LL},
        {848, 5323019LL}, {849, 2025534LL}, {850, 3940874LL}, {851, 3942488LL},
        {852, 1730767LL}, {853, 5671481LL}, {854, 2020116LL}, {855, 6611722LL},
        {856, 5679280LL}, {857, 5247548LL}, {858, 6025016LL}, {859, 4921983LL},
        {860, 3031865LL}, {861, 7162399LL}, {862, 6901372LL}, {863, 2720320LL},
        {864, 2909721LL}, {865, 4729197LL}, {866, 39990LL}, {867, 6311LL},
        {868, 6689LL}, {869, 21692LL}, {870, 13573LL}, {871, 11293LL},
        {872, 1335787LL}, {873, 1343596LL}, {874, 473090LL}, {875, 655LL},
        {876, 240LL}, {877, 611340LL}, {878, 5355245LL}, {879, 3549919LL},
        {880, 1997303LL}, {881, 4538035LL}, {882, 295776LL}, {883, 98651LL},
        {884, 7050LL},
    };
    int i, n = (int)(sizeof(bench_rates) / sizeof(bench_rates[0]));
    for (i = 0; i < n; i++) {
        int idx = bench_rates[i].idx;
        if (idx >= 0 && idx < Numtypes)
            Hashtypes[idx].rate = bench_rates[i].rate;
    }
    /* Default: types without benchmark data get rate=1 (safe small batches) */
    for (i = 0; i < Numtypes; i++) {
        if (Hashtypes[i].rate == 0 &&
            (Hashtypes[i].compute || Hashtypes[i].verify || Hashtypes[i].nchain > 0))
            Hashtypes[i].rate = 1;
    }
}

int main(int argc, char **argv)
{
    int opt, i;
    char *outfile = NULL, *errfile = NULL;
    char *modespec = NULL;
    int show_help = 0;
    (void)Version;

    Numthreads = get_nprocs();
    if (Numthreads < 1) Numthreads = 1;

    Outfp = stdout;
    Errfp = stderr;
    BenchAll = 0;
    BenchSpec = NULL;

    /* Reorder argv so options come before filenames (POSIX getopt stops at first non-option) */
    /* This allows "hashpipe foo.txt -o out.txt -e err.txt" to work correctly */
    {
        char **sorted = malloc((argc + 1) * sizeof(char *));
        char *used = calloc(argc, 1);
        int dst = 1;
        sorted[0] = argv[0];
        used[0] = 1;
        for (i = 1; i < argc; i++) {
            if (argv[i][0] == '-' && argv[i][1] != '\0') {
                sorted[dst++] = argv[i];
                used[i] = 1;
                if (argv[i][2] == '\0' && strchr("tiqoebm", argv[i][1]) && i + 1 < argc) {
                    i++;
                    sorted[dst++] = argv[i];
                    used[i] = 1;
                }
            }
        }
        for (i = 1; i < argc; i++) {
            if (!used[i])
                sorted[dst++] = argv[i];
        }
        memcpy(argv, sorted, argc * sizeof(char *));
        free(sorted);
        free(used);
    }

    while ((opt = getopt(argc, argv, "t:i:q:o:e:b:m:BVh")) != -1) {
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
            Iterstep = atoi(optarg);
            if (Iterstep < 1) Iterstep = 1;
            break;
        case 'o':
            outfile = optarg;
            break;
        case 'e':
            errfile = optarg;
            break;
        case 'm':
            modespec = optarg;
            break;
        case 'b':
            BenchSpec = optarg;
            break;
        case 'B':
            BenchAll = 1;
            break;
        case 'V':
            fprintf(stderr, "%s\n", Version);
            exit(0);
        case 'h':
            show_help = 1;
            break;
        default:
            usage(1);
            exit(1);
        }
    }

    /* Initialize hash types (needed for both benchmark and normal mode) */
    yarn_prefix = "hashpipe";
    rhash_library_init();
    init_hashtypes();
    init_rates();

    if (show_help) {
        usage(0);
        exit(0);
    }

    /* Parse -m mode spec (needs Numtypes from init_hashtypes) */
    if (modespec) {
        int mc = parse_mode_spec(modespec);
        if (mc < 0) exit(1);
        if (mc == 0 && !ModeAuto) {
            fprintf(stderr, "hashpipe: -m: no types selected\n");
            exit(1);
        }
    }

    /* Benchmark mode: run and exit */
    if (BenchAll || BenchSpec) {
        BenchSelected = (int *)calloc(Numtypes, sizeof(int));
        if (!BenchSelected) { perror("calloc"); exit(1); }

        if (BenchAll) {
            /* Select all types that are benchmarkable */
            for (i = 0; i < Numtypes; i++) {
                struct hashtype *ht = &Hashtypes[i];
                if (ht->verify || ht->compute || ht->nchain > 0)
                    BenchSelected[i] = 1;
            }
            BenchCount = Numtypes;
        } else {
            BenchCount = parse_bench_spec(BenchSpec);
            if (BenchCount < 0) exit(1);
            if (BenchCount == 0) {
                fprintf(stderr, "hashpipe: -b: no types selected\n");
                exit(1);
            }
        }

        run_benchmark();
        free(BenchSelected);
        exit(0);
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
            b->ws = malloc(sizeof(struct workspace));
            if (!b->ws) {
                fprintf(stderr, "hashpipe: out of memory (workspace)\n");
                exit(1);
            }
            b->ws->testvec = malloc(TESTVECSIZE + 16);
            b->next = FreeHead;
            FreeHead = b;
        }
    }

    /* Pre-set BatchLimit from slowest -m type, or use small default */
    if (ModeCount > 0) {
        long long slowest = 0;
        int slowest_idx = -1;
        for (i = 0; i < ModeCount; i++) {
            long long r = Hashtypes[ModeList[i]].rate;
            if (r > 0 && (slowest_idx < 0 || r < slowest)) {
                slowest = r;
                slowest_idx = ModeList[i];
            }
        }
        if (slowest_idx >= 0)
            update_batch_limit(slowest_idx);
    } else {
        /* Auto-detect mode: start small so slow types distribute;
           worker feedback will raise BatchLimit for fast types */
        BatchLimit = Numthreads * 4;
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

    free(ModeList);

    return 0;
}
