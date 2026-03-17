<p align="center">
  <img src="img/hashpipe.svg" width="128" alt="hashpipe logo">
</p>

# hashpipe

Multi-threaded hash verification tool. Reads lines containing `hash:password` pairs (optionally with TYPE hints and salts), verifies them by computing the hash from the password, and outputs verified results in mdxfind stdout format. Unresolved lines go to stderr.

Uses [yarn.c](https://github.com/madler/pigz) for threading and OpenSSL for hash computation.

## Usage

```
hashpipe [-t N] [-i N] [-q N] [-m S] [-L secs] [-o|-O outfile] [-e|-E errfile] [-s statfile] [-b spec] [-B] [-T] [-V] [-h] [file ...]
```

### Options

**`-t N`** — Thread count (default: number of CPUs)

**`-i N`** — Max iteration count for hard pass (default: 128)

**`-q N`** — Maximum internal hash iteration (default: 128)

**`-m S`** — Only try types in S; `eN` for internal index, bare number for hashcat mode (e.g., `-m e1,1000`); add `auto` to fallback to auto-detect

**`-o F`** — Append verified results to file (default: stdout)

**`-O F`** — Write verified results to file, truncating if it exists (default: stdout)

**`-e F`** — Append unresolved lines to file (default: stderr)

**`-E F`** — Write unresolved lines to file, truncating if it exists (default: stderr)

**`-s F`** — Append statistics to file.  Writes three tables at exit: hot list hits (per algorithm/salt-length pair), per-algorithm try counts, and per-algorithm solution counts.  Stats are collected unconditionally; this option controls whether they are written out.

**`-L secs`** — Maximum estimated time (in seconds) for a single iterated verify operation (default: 1000.0, effectively unlimited).  When an input hash specifies an iteration count that would exceed this limit (estimated from benchmark rates), the verify is skipped.  Useful for preventing misidentified hashes with extreme iteration counts from causing long stalls.

**`-b S`** — Benchmark selected types (e.g., `-b e1-e10,e15`)

**`-B`** — Benchmark all registered types

**`-T`** — Run self-tests on all registered types

**`-V`** — Print version and exit

**`-h`** — Print help and list all supported hash types

### Input Format

Each input line has the form:

```
[TYPE[xNN] ]hash[:salt]:password
```

- **TYPE** is an optional hash type hint (e.g., `MD5`, `SHA256`, `NTLM`).  When omitted, hashpipe tries all supported types.
- **xNN** is an optional iteration suffix on the type.
- **hash** is the hex-encoded hash value.
- **salt** is an optional salt, required for salted types.
- **password** is the plaintext candidate.

### Output

- **stdout**: verified lines in mdxfind format: `TYPE[xNN] hash[:salt]:password`
- **stderr**: unresolved lines (bad data, wrong password, corrupted entries)

### Examples

Verify a potfile from stdin:
```bash
cat potfile.txt | hashpipe
```

Verify with type hints, saving results and rejects to separate files:
```bash
hashpipe -o verified.txt -e unresolved.txt potfile.txt
```

Only try MD5 and SHA1 (no auto-detect):
```bash
hashpipe -m e1,e8 potfile.txt
```

Prefer MD5SALT and SHA1PASSSALT, then fall back to auto-detect:
```bash
hashpipe -m e31,e405,auto potfile.txt
```

Restrict to a range of types:
```bash
hashpipe -m e1-e12 potfile.txt
```

Use 8 threads:
```bash
hashpipe -t 8 potfile.txt
```

Pipe verified results directly into mdsplit:
```bash
hashpipe potfile.txt | mdsplit potfile.txt
```

Verify multiple files:
```bash
hashpipe file1.txt file2.txt file3.txt
```

Benchmark all types:
```bash
hashpipe -B
```

Benchmark specific types:
```bash
hashpipe -b e1,e8-e12
```

Limit expensive verify operations to 10 seconds estimated time:
```bash
hashpipe -L 10 potfile.txt
```

Write statistics to a file:
```bash
hashpipe -o verified.txt -E unresolved.txt -s stats.txt potfile.txt
cat stats.txt
```

```
--- Hot List ---
Type   Algorithm                       SaltL      HotHits
e31    MD5SALT                             3      8873141
e31    MD5SALT                             4        11305
e31    MD5SALT                             2         9577
e31    MD5SALT                             5        17027
e31    MD5SALT                             6       349991
e31    MD5SALT                            30       659261
e31    MD5SALT                             1           65
e31    MD5SALT                            12           12
e31    MD5SALT                             8         2240
e31    MD5SALT                            17          594
e31    MD5SALT                            10            8
e31    MD5SALT                            11            2
e31    MD5SALT                            18            1
e31    MD5SALT                            19            2
e31    MD5SALT                            13            2
e31    MD5SALT                            21            2
e31    MD5SALT                             9            2
e31    MD5SALT                             7            6
       TOTAL                                      9923255

--- Algorithm Tries ---
Type   Algorithm                             Tries
e1     MD5                                      15
e31    MD5SALT                             9923397
       TOTAL                               9928112

--- Solutions ---
Type   Algorithm                            Solved      HotHits
e1     MD5                                       2            0
e31    MD5SALT                             9923327      9923255
       TOTAL                               9923329      9923255
```

The **Hot List** section shows which `(algorithm, salt_length)` pairs were resolved via the hot list fast path.  **Algorithm Tries** shows total compute/verify calls per type.  **Solutions** shows how many hashes each type solved, and how many of those were hot list hits.

## Pot(files) considered harmful

For many years, I have taken the position that potfiles, the place where solved hashes go to die, are not only bad, but also dangerous.  They can confuse what hash types are involved, or what the algorithm is, and can introduce bad solutions into an otherwise perfect hash processing stream.  Hashpipe is intended to be an automated method to resolve, or verify, questionable hashes.  By trying many different hashing methods, in a fully automated fashion, hashpipe can figure out what types of hashes are involved, properly format the output, and can pipe directly into mdsplit for long term hash management.  Much more to the point, it also separates out the unsolved hashes, corrupted entries, or other bad data.

## Architecture

### Threading Model

hashpipe uses a producer-consumer architecture with [yarn.c](https://github.com/madler/pigz) (Mark Adler's thread pool abstraction over pthreads):

- **Main thread** reads input lines into fixed-size batches, then enqueues them for worker threads.
- **Worker threads** (one per CPU by default) dequeue batches and verify each item by computing the hash and comparing.
- Batches are recycled through a free-list pool to avoid allocation overhead.

### Adaptive Batch Sizing

Fixed batch sizes cause slow hash types (bcrypt at ~5 hashes/sec) to bottleneck on a single thread.  hashpipe uses adaptive batch sizing to distribute work evenly:

- Each hash type has a **benchmark rate** (hashes/sec), either from a built-in table of 988 pre-measured rates or from runtime `-B`/`-b` benchmarks.
- **BatchLimit** = `rate * 0.75` (target 0.75 seconds of work per batch), clamped to [1, 4096].
- When `-m` specifies types, BatchLimit is pre-set from the slowest selected type.
- In auto-detect mode, BatchLimit starts at `Numthreads * 4` and the worker feedback loop adjusts it as hash types are identified.

This achieves near-linear scaling for slow types: 1000 bcrypt cost-12 hashes run in ~13 seconds on 16 threads vs ~170 seconds single-threaded.

### Hot Type Optimization

hashpipe tracks the most recently matched hash type as a "hot type" and a hot list of recent `(type, salt_length)` matches.  When processing a batch, workers try the hot list first — using the known salt length to extract the salt directly without colon parsing — before falling back to the full candidate scan.  For homogeneous input (common in potfiles), this avoids testing hundreds of types per line and eliminates ambiguity when salts or passwords contain colons.

### Backward-Scanning Colon Resolution

When both the salt and password may contain colons (e.g., `hash:salt:with:colons:password:with:colons`), hashpipe scans backward through colon positions in the rest-of-line to try every possible salt/password boundary, right-to-left.  This ensures correct identification even when the password itself contains colons.

### $HEX[] Literal Password Retry

When a password field contains a valid `$HEX[...]` encoding (e.g., `$HEX[41]`), hashpipe first decodes it and tries all hash types with the decoded value (`A`).  If nothing matches, hashpipe retries with the literal string `$HEX[41]` as the password — because some potfiles contain passwords that are literally the text `$HEX[...]` rather than hex-encoded binary.

The literal password is output using double-encoding: `$HEX[244845585b34315d]` (hex encoding of the literal bytes `$HEX[41]`), which avoids ambiguity with actual hex-encoded passwords.

This retry only applies to passwords starting with `$HEX[` that contain valid hex content.  Invalid hex (e.g., `$HEX[ZZ]`) is always treated as a literal string on the first pass.

### Cost Limiting

Iterated verify functions (bcrypt, PBKDF2, scrypt, sha256crypt, etc.) estimate their execution time before running, using the formula `(parsed_cost / bench_cost) / bench_rate`.  If the estimate exceeds the `-L` limit, the verify is skipped.  This prevents misidentified hashes with extreme iteration counts (e.g., a hex string that happens to match bcrypt format with cost 31) from causing multi-minute stalls during auto-detection.

### Verification Strategies

Hash types use one of three verification strategies:

- **Direct compute**: compute the hash from the password and compare the binary result against the decoded hex input.  Used for simple types (MD5, SHA1, SHA256, etc.) and composed chains.
- **Chain compute**: a chain of hash steps defined declaratively (innermost to outermost), supporting UC (uppercase hex), NTLM (UTF-16LE), salt insertion, and raw binary passes.  Covers hundreds of composed types like `SHA1(MD5($pass))`.
- **Verify function**: a custom function that takes the hash string and password, returning match/no-match.  Used for non-hex formats where the hash encodes its own parameters: bcrypt (cost factor in hash), PHPBB3, APACHE-SHA, APR1.

### Per-hashlen Candidate Caches

Rather than scanning all 988 types for each input line, hashpipe maintains per-hashlen lookup tables: separate caches for unsalted, salted, and composed types indexed by binary hash length (0-64 bytes).  A 32-byte hex hash (16 binary bytes) only checks MD5, MD4, GOST, RIPEMD-128, and their composed variants.

## Supported Hash Types

hashpipe supports 988 hash types.  See [HASH_TYPES.md](HASH_TYPES.md) for the complete list with hashcat mode mappings and example hashes, or run `hashpipe -h` for a quick reference.

### Common types

| Index | Type | Algorithm |
|-------|------|-----------|
| e1 | MD5 | `md5($pass)` |
| e2 | MD5UC | `md5($pass)` (uppercase hex) |
| e3 | MD4 | `md4($pass)` |
| e4 | MD2 | `md2($pass)` |
| e8 | SHA1 | `sha1($pass)` |
| e9 | SHA224 | `sha224($pass)` |
| e10 | SHA256 | `sha256($pass)` |
| e11 | SHA384 | `sha384($pass)` |
| e12 | SHA512 | `sha512($pass)` |
| e369 | NTLM | `md4(utf16le($pass))` |

### Salted types

| Index | Type | Algorithm |
|-------|------|-----------|
| e31 | MD5SALT | `md5(hex(md5($pass)).$salt)` |
| e373 | MD5PASSSALT | `md5($pass.$salt)` |
| e394 | MD5SALTPASS | `md5($salt.$pass)` |
| e385 | SHA1SALTPASS | `sha1($salt.$pass)` |
| e405 | SHA1PASSSALT | `sha1($pass.$salt)` |
| e412 | SHA256SALTPASS | `sha256($salt.$pass)` |
| e413 | SHA256PASSSALT | `sha256($pass.$salt)` |
| e386 | SHA512PASSSALT | `sha512($pass.$salt)` |
| e388 | SHA512SALTPASS | `sha512($salt.$pass)` |
| e439 | MSCACHE | `md4(md4(utf16le($pass)).$salt)` |
| e857 | SKYPE | `md5($pass.\|$salt)` |

### Composed types (selected)

| Index | Type | Algorithm |
|-------|------|-----------|
| e160 | SHA1MD5 | `sha1(hex(md5($pass)))` |
| e178 | MD5SHA1 | `md5(hex(sha1($pass)))` |
| e123 | MD5MD5PASS | `md5(hex(md5($pass)).$pass)` |
| e188 | MD5SHA1MD5 | `md5(hex(sha1(hex(md5($pass)))))` |
| e497 | MD4UTF16MD5 | `md4(utf16le(hex(md5($pass))))` |
| e368 | MD5NTLM | `md5(hex(md4(utf16le($pass))))` |
| e251 | SHA256SHA1 | `sha256(hex(sha1($pass)))` |
| e786 | NTLMH | `md4(utf16le($pass))` (dual-mode, see note below) |

### Crypt types

| Index | Type | Algorithm |
|-------|------|-----------|
| e500 | DESCRYPT | `crypt($pass, $salt)` (DES) |
| e511 | MD5CRYPT | `$1$$` md5crypt |
| e512 | SHA256CRYPT | `$5$$` sha256crypt |
| e513 | SHA512CRYPT | `$6$$` sha512crypt |
| e577 | BCRYPT256 | `$2k$$` HMAC-SHA256 + bcrypt |
| e529 | CISCO8 | `$8$` PBKDF2-SHA256 20000 rounds |
| e917 | CISCO9 | `$9$` scrypt (hashcat 9300) |
| e884 | SCRYPT | `$7$$` scrypt |

### PBKDF2 / KDF types

| Index | Type | Algorithm |
|-------|------|-----------|
| e529 | CISCO8 | `$8$` PBKDF2-SHA256 20000 rounds |
| e530 | PBKDF2-SHA256 | PBKDF2-HMAC-SHA256 (incl. Python passlib `$pbkdf2-sha256$`) |
| e531 | PBKDF2-MD5 | PBKDF2-HMAC-MD5 |
| e532 | PBKDF2-SHA1 | PBKDF2-HMAC-SHA1 (incl. Python passlib `$pbkdf2$`) |
| e533 | PBKDF2-SHA512 | PBKDF2-HMAC-SHA512 (incl. Python passlib `$pbkdf2-sha512$`) |
| e534 | PKCS5S2 | `{PKCS5S2}` PBKDF2-SHA1 10000 rounds |
| e895 | NETSCALER-PBKDF2 | Citrix NetScaler PBKDF2-HMAC-SHA256 2500 rounds |
| e899 | LASTPASS | PBKDF2-SHA256 + AES-256-ECB (hashcat 6800) |
| e905 | REDHAT389DS | `{PBKDF2_SHA256}` PBKDF2-SHA256 256-byte output (hashcat 10901) |
| e918 | DCC2 | PBKDF2-HMAC-SHA1 over NTLM (hashcat 2100) |

### LDAP SSHA types

| Index | Type | Algorithm |
|-------|------|-----------|
| e833 | SSHA1BASE64 | `{SSHA}base64(sha1($pass.$salt).$salt)` |
| e835 | SSHA256BASE64 | `{SSHA256}base64(sha256($pass.$salt).$salt)` |
| e836 | SSHA512BASE64 | `{SSHA512}base64(sha512($pass.$salt).$salt)` |

### Non-hex / verify types

| Index | Type | Algorithm |
|-------|------|-----------|
| e450 | BCRYPT | `bcrypt($pass)` |
| e451 | BCRYPTMD5 | `bcrypt(hex(md5($pass)))` |
| e452 | BCRYPTSHA1 | `bcrypt(hex(sha1($pass)))` |
| e455 | PHPBB3 | `phpbb3($pass)` |
| e457 | APACHE-SHA | `{SHA}base64(sha1($pass))` |
| e461 | APR1 | `apr1($pass)` |
| e500 | DESCRYPT | DES crypt (including BSDi Extended DES) |
| e521 | SHA1SALTCX | `sha1($salt.sha1($pass))` iterated (hashcat 14400) |
| e819 | MD5-MD5MD5PASSSALT-PEP | `md5(md5(md5($pass).$salt1).$salt2)` (hashcat 31700) |
| e821 | MD5-MD5MD5PASSSALT-PEP2 | `md5(md5(md5($pass.$salt1)).$salt2)` (hashcat 21900) |
| e822 | MD5-SALT-SHA1PEPPASS | `md5($salt1.sha1($salt2.$pass))` (hashcat 21310) |
| e824 | SHA1-SALTSHA1U16 | `sha1($salt.sha1(utf16le($user):utf16le($pass)))` (hashcat 29000) |
| e861 | CISCOPIX | Cisco PIX `md5($pass)` phpitoa64 |
| e862 | CISCOASA | Cisco ASA `md5($pass.$salt)` phpitoa64 |
| e876 | DRUPAL7 | `$S$` SHA512 iterated |
| e884 | SCRYPT | `SCRYPT:N:r:p:salt:hash` (hashcat 8900) |
| e888 | ISCSI-CHAP | iSCSI CHAP authentication (hashcat 4800) |
| e899 | LASTPASS | PBKDF2-SHA256 + AES-256-ECB (hashcat 6800) |
| e901 | DOMINO8 | Lotus Notes/Domino 8+ PBKDF2-SHA1 (hashcat 9100) |
| e905 | REDHAT389DS | `{PBKDF2_SHA256}` Red Hat Directory Server (hashcat 10901) |
| e908 | SHIRO1 | Apache Shiro SHA-512 iterated (hashcat 12150) |
| e910 | ORACLE12 | Oracle 12C PBKDF2-SHA512 (hashcat 12300) |
| e918 | DCC2 | `$DCC2$` Domain Cached Credentials 2 (hashcat 2100) |
| e919 | PWSAFE3 | Password Safe v3 SHA-256 iterated (hashcat 5200) |
| e929 | RACF-KDFAES | RACF KDF/AES (hashcat 8500) |
| e930 | TACACS+ | TACACS+ authentication (hashcat 16100) |
| e931 | APPLE-SECURE-NOTES | Apple Secure Notes (hashcat 16200) |
| e932 | CRAMMD5-DOVECOT | CRAM-MD5 Dovecot (hashcat 16400) |
| e933 | JWT | JSON Web Token HMAC-SHA (hashcat 16500) |
| e934 | QNX-MD5 | QNX `/etc/shadow` MD5 (hashcat 19000) |
| e935 | QNX-SHA256 | QNX `/etc/shadow` SHA256 (hashcat 19100) |
| e936 | QNX-SHA512 | QNX `/etc/shadow` SHA512 (hashcat 19200) |
| e937 | QNX7-SHA512 | QNX 7 `/etc/shadow` SHA512 (hashcat 19210) |
| e938 | SHA1-S1PS2 | `sha1($salt1.$pass.$salt2)` (hashcat 19300) |
| e939 | RAILS-RESTFUL | Ruby on Rails Restful-Auth (hashcat 19500) |
| e940 | KRB5PA-17 | Kerberos 5 etype 17 Pre-Auth (hashcat 19800) |
| e941 | KRB5PA-18 | Kerberos 5 etype 18 Pre-Auth (hashcat 19900) |
| e942 | WPA-PMKID | WPA-PMKID PBKDF2 (hashcat 16800/22000) |
| e943 | WPA-EAPOL | WPA EAPOL MIC (hashcat 22000) |
| e944 | ANSIBLE-VAULT | Ansible Vault PBKDF2-SHA256 (hashcat 16900) |
| e945 | APFS | Apple File System (hashcat 18300) |
| e946 | OTM-SHA256 | Oracle Transportation Mgmt SHA256 (hashcat 20600) |
| e947 | TELEGRAM-SHA256 | Telegram Mobile Passcode SHA256 (hashcat 22301) |
| e948 | WEB2PY-SHA512 | Web2py PBKDF2-SHA512 (hashcat 21600) |
| e949 | SOLARWINDS | SolarWinds Orion (hashcat 21500) |
| e950 | SOLARWINDS2 | SolarWinds Orion v2 (hashcat 21501) |
| e951 | SIMPLACMS | Simpla CMS (hashcat 22800) |
| e952 | APPLE-KEYCHAIN | Apple Keychain PBKDF2+3DES (hashcat 23100) |
| e953 | APPLE-IWORK | Apple iWork PBKDF2+AES (hashcat 23300) |
| e954 | BITWARDEN | Bitwarden double PBKDF2 (hashcat 23400) |
| e955 | MONGODB-SHA1 | MongoDB SCRAM-SHA-1 (hashcat 24100) |
| e956 | MONGODB-SHA256 | MongoDB SCRAM-SHA-256 (hashcat 24200) |
| e957 | FORTIGATE256 | FortiGate SHA256 (hashcat 26300) |
| e958 | UMBRACO | Umbraco HMAC-SHA1 (hashcat 24800) |
| e959 | DAHUA-AUTH | Dahua Authentication MD5 (hashcat 24900) |
| e960 | BESDER-AUTH | Besder Authentication MD5 (hashcat 24901) |
| e961 | SQLCIPHER | SQLCipher PBKDF2+AES (hashcat 24600) |
| e962 | RORAILS-SHA1 | Ruby on Rails SHA1 (hashcat 27200) |
| e963 | AES128-NOKDF | AES-128-ECB no KDF (hashcat 26401) |
| e964 | AES192-NOKDF | AES-192-ECB no KDF (hashcat 26402) |
| e965 | AES256-NOKDF | AES-256-ECB no KDF (hashcat 26403) |
| e966 | VMWARE-VMX | VMware VMX (hashcat 27400) |
| e967 | BCRYPTSHA512 | bcrypt(sha512($pass)) (hashcat 28400) |
| e968 | POSTGRESSCRAM256 | PostgreSQL SCRAM-SHA-256 (hashcat 28600) |
| e969 | AWSSIGV4 | Amazon AWS Signature v4 (hashcat 28700) |
| e970 | KRB5DB17 | Kerberos 5 etype 17 DB (hashcat 28800) |
| e971 | KRB5DB18 | Kerberos 5 etype 18 DB (hashcat 28900) |
| e991 | MD5SALT1SALT2 | `md5($salt1.$pass.$salt2)` (hashcat 33000) |
| e992 | SYMFONY256 | Symfony Legacy SHA256 (hashcat 35800) |
| e993 | WPBCRYPT | WordPress bcrypt(hmac-sha384) (hashcat 35500) |
| e994 | GOST12512CRYPT | `$gost12512hash$` gost12512crypt (hashcat 35600) |

### Note on NTLMH (e786)

NTLM hashing requires converting the password to UTF-16LE before computing MD4.  For pure ASCII input, every tool agrees: each byte is zero-extended to a 16-bit value.  For non-ASCII input, however, hashcat's zero-extension mode does not perform proper UTF-8 → UTF-16LE conversion — it simply widens each raw byte to 16 bits.  The resulting hash is not a valid Microsoft NTLM hash and could never be used for Windows authentication, but it *is* what hashcat computes and stores in potfiles.

NTLMH (e786) accepts both interpretations:

1. **Proper UTF-8 → UTF-16LE** (via iconv with `//IGNORE`): invalid UTF-8 sequences are silently discarded, and only valid characters are converted.
2. **Blind zero-extension** (hashcat-compatible): every input byte is widened to 16 bits regardless of UTF-8 validity.

NTLM (e369) uses only the proper iconv path, since mdxfind always emits valid UTF-8 in its output for e369.

Example: the password `$HEX[c0ffeebabe]` (5 raw bytes, not valid UTF-8) produces two NTLMH hashes:

- `b3f4b4d05705228f87ed95e91e25bc70` — iconv discards `c0` and `ff`, converts remaining `ee ba be`
- `4b44f50004711067b1eab173dbef5ef8` — all 5 bytes blindly zero-extended (hashcat mode, not a valid NTLM hash)

### Additional algorithm families

hashpipe also supports GOST, GOST-CRYPTO, Streebog, gost12512crypt, RIPEMD-128/160/320, TIGER, HAVAL (all variants), BLAKE-224/256/384/512, BMW, CubeHash, ECHO, Fugue, Groestl, Hamsi, JH, Keccak, SHA-3, Luffa, Panama, RadioGatun, Shabal, SHAvite, SIMD, Skein, Whirlpool, MD6, MDC2, EDON, Snefru, HAS-160, BLAKE2B/2S, MurmurHash, RADMIN2, LM, SipHash, SAP BCODE/PASSCODE, AS/400 DES, PS-TOKEN, WINPHONE, QNX shadow, WPA-PMKID/EAPOL, Apple Keychain/iWork/APFS, Ansible Vault, Bitwarden, MongoDB SCRAM, SolarWinds, VMware VMX, SQLCipher, JWT, TACACS+, Kerberos 5 Pre-Auth/DB (etype 17/18), AWS Signature v4, PostgreSQL SCRAM-SHA-256, WordPress bcrypt, Symfony Legacy, Argon2, and hundreds of composed/chained variants.

## Benchmarking

`hashpipe -B` benchmarks all 988 registered types and reports hashes/second for each:

```
$ hashpipe -B | head -10
e1      MD5     7613341 16      0x00
e2      MD5UC   4153321 16      0x04
e3      MD4     4765041 16      0x00
e8      SHA1    2297819 20      0x00
e10     SHA256  1951415 32      0x00
e12     SHA512  772145  64      0x00
e369    NTLM    3005558 16      0x08
e450    BCRYPT  5       0       0x40
e455    PHPBB3  1747    0       0x40
e461    APR1    3147    0       0x40
```

Output format: `index  name  rate  hashlen  flags`

Types that cannot be benchmarked (missing dependencies) show `n/a` for rate.

Use `-b` to benchmark specific types: `-b e1,e8-e12,e450`.

Benchmark rates are used by the `-L` cost limit to estimate verify time for iterated types.  The built-in rates were measured on an Apple M1 (8-core).

## Building

```bash
make deps      # pull and build all dependencies from source
make hashpipe
```

`make deps` clones each dependency from its authoritative GitHub repository, pins it to a verified commit hash, and builds a static library.  This requires git, a C compiler, make, and autotools (for libmhash and libJudy).  Built artifacts are placed in the hashpipe source tree.

If you already have the required static libraries (from a previous `make deps` or a manual build), `make hashpipe` is sufficient.

To remove downloaded dependency sources:
```bash
make distclean
```

### Docker

Docker can be used to build and run hashpipe without installing dependencies locally:
```bash
docker build . -t csp/hashpipe
```

```bash
docker run -v ${PWD}:/data -it --rm csp/hashpipe -m auto potfile.txt
```

The `/data` directory inside the container is used as the working directory.

### Known Build Issues

**sphlib BMW strict aliasing bug (GCC 12+)**: sphlib's `bmw.c` contains strict aliasing violations that cause GCC to generate incorrect code for BMW-224 and BMW-256 at `-O2` and above.  BMW-384/512 (64-bit core) and all other sphlib algorithms are unaffected.  Apple clang is unaffected.  The `make deps` target already applies the workaround (`-fno-strict-aliasing`).  If you build sphlib separately, add `-fno-strict-aliasing` to its compile flags.  See [sphlib#3](https://github.com/pornin/sphlib/issues/3).

### Dependencies

hashpipe requires the following static libraries:

- OpenSSL 1.1.1w (`libssl.a`, `libcrypto.a`)
- sphlib (`libsph.a`)
- libmhash (`libmhash.a`)
- RHash (`librhash.a`)
- MD6 (`md6.a`)
- GOST/Streebog (`gosthash/gost2012/gost2012.a`)
- bcrypt / crypt_blowfish (`bcrypt-master/bcrypt.a`)
- Argon2 (`argon2/argon2.a`)
- libJudy (`libJudy.a`)
- yescrypt (`yescrypt/*.o`)

### Supported Platforms

The Makefile detects the build platform automatically.  Tested on:

- macOS x86\_64 and arm64 (requires libiconv from MacPorts)
- Linux x86\_64 (Ubuntu 18.04, 22.04)
- Linux i386 (32-bit)
- Linux ppc64le (PowerPC 8)
- FreeBSD 13.2 x86\_64 (uses gmake)
- Windows x86, x64, and ARM64 (cross-compiled via mingw-w64 / llvm-mingw)

## Type Indices and Hashcat Modes

hashpipe uses the same type index numbering as mdxfind. The `-m` option accepts both internal indices (with `e` prefix) and hashcat mode numbers (bare numbers):

```bash
# Internal indices
hashpipe -m e1,e8,e450 potfile.txt

# Hashcat mode numbers
hashpipe -m 0 potfile.txt          # MD5 (hashcat mode 0)
hashpipe -m 1000 potfile.txt       # NTLM (hashcat mode 1000)
hashpipe -m 3200 potfile.txt       # bcrypt (hashcat mode 3200)

# Mixed: hashcat modes and internal indices together
hashpipe -m 1000,e1,3200 potfile.txt

# Ranges (internal indices only) with hashcat modes
hashpipe -m e1-e12,1000,3200 potfile.txt

# With auto-detect fallback
hashpipe -m 0,1000,auto potfile.txt
```

Run `hashpipe -h` to see the full type list with hashcat mode mappings.

## Hashcat Mode Coverage

hashpipe maps hashcat mode numbers to internal type indices via the `-m` option.  Of hashcat's ~590 distinct modes, hashpipe currently resolves ~335.  The remaining ~255 modes are not supported for the following reasons:

| Reason | Modes | Description |
|--------|------:|-------------|
| Full-disk / volume encryption | ~80 | TrueCrypt, VeraCrypt, LUKS, BitLocker, DiskCryptor, BestCrypt, VirtualBox — require XTS block cipher decryption of 512+ byte sectors to verify a candidate password.  hashpipe verifies hashes, not disk images. |
| Document / archive encryption | ~25 | MS Office (2003–2016), PDF, 7-Zip, RAR3/5, WinZip, PKZIP, ODF, Stuffit, AxCrypt, AES Crypt — require decrypting a document/archive payload and checking structural integrity (CRC, HMAC, XML parse).  The "hash" is really an encrypted blob. |
| Wallet / blockchain encryption | ~25 | Bitcoin wallet.dat, Ethereum, Electrum, MultiBit, Exodus, MetaMask, Blockchain.com, MEGA, Terra Station, Bisq, Dogechain, Stargazer, 1Password — PBKDF2/scrypt key derivation followed by AES/3DES decryption of wallet data with structural verification. |
| Key file / credential store | ~20 | OpenSSH private keys, GnuPG/PGP, PEM, JKS Java Key Store, DPAPI master keys, KeePass, Mozilla NSS (key3.db/key4.db), SecureCRT, iTunes backup, Radmin3, Windows Hello — require decrypting a key structure and verifying internal consistency (ASN.1, PKCS padding, key check values). |
| Elliptic curve / cipher operations | ~17 | Bitcoin WIF/raw private keys (secp256k1 point multiplication), RC4 DropN (stream cipher key recovery), ChaCha20, Skip32, Kremlin NewDES — these are not hash functions; they require elliptic curve arithmetic or cipher-specific operations that have no place in a hash verification tool. |
| Network protocol / session tokens | ~15 | SIP digest auth, SNMPv3, Kerberos TGS/AS-REP (etype 17/18/23), XMPP SCRAM, WPA-EAPOL, KNX IP Secure, Flask/Mojolicious session cookies — require protocol-specific challenge-response state, ticket structures, or application-specific secret keys beyond what a password hash tool provides. |
| Non-cryptographic hashes | 6 | CRC32, CRC32C, CRC64Jones, Java Object hashCode(), MurmurHash (64-bit), STDOUT — trivially reversible checksums or debugging modes with no cryptographic purpose.  Infinite collisions make verification meaningless. |

The full list of unresolved modes with per-mode explanations is maintained in `regress/unresolved-hashcat.txt` and can be regenerated with `regress/build_unresolved_table.sh`.

## Acknowledgments

hashpipe depends on the following libraries:

- [OpenSSL](https://github.com/openssl/openssl) — OpenSSL Project
- [yarn.c](https://github.com/madler/pigz) — Mark Adler (from pigz)
- [libJudy](https://judy.sourceforge.net/) — Doug Baskins (Hewlett-Packard)
- [sphlib](https://github.com/pornin/sphlib) — Thomas Pornin (Projet RNRT SAPHIR)
- [RHash](https://github.com/rhash/RHash) — RHash Project
- [libmhash](https://mhash.sourceforge.net/) — Nikos Mavroyanopoulos, Sascha Schumann
- [bcrypt](https://www.openwall.com/crypt/) — Niels Provos, David Mazieres (via Openwall crypt_blowfish)
- [yescrypt](https://www.openwall.com/yescrypt/) — Alexander Peslyak (via Openwall)
- [Argon2](https://github.com/P-H-C/phc-winner-argon2) — Alex Biryukov, Daniel Dinu, Dmitry Khovratovich (University of Luxembourg; PHC winner, RFC 9106)
- [stribob](https://github.com/mjosaarinen/brutus) — Markku-Juhani O. Saarinen (Streebog/GOST R 34.11-2012 primitives; standalone wrapper from stricat bundled with permission)

Platform detection in the Makefile was inspired by [PR #1](https://github.com/Cynosureprime/hashpipe/pull/1) from [@0xVavaldi](https://github.com/0xVavaldi).

## License

MIT
