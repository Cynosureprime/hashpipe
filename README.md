<p align="center">
  <img src="img/hashpipe.svg" width="128" alt="hashpipe logo">
</p>

# hashpipe

Multi-threaded hash verification tool. Reads lines containing `hash:password` pairs (optionally with TYPE hints and salts), verifies them by computing the hash from the password, and outputs verified results in mdxfind stdout format. Unresolved lines go to stderr.

Uses [yarn.c](https://github.com/madler/pigz) for threading and OpenSSL for hash computation.

## Usage

```
hashpipe [-t N] [-i N] [-q N] [-m S] [-o outfile] [-e errfile] [-b spec] [-B] [-V] [-h] [file ...]
```

### Options

| Flag | Description |
|------|-------------|
| `-t N` | Thread count (default: number of CPUs) |
| `-i N` | Max iteration count for hard pass (default: 128) |
| `-q N` | Maximum internal hash iteration (default: 128) |
| `-m S` | Only try types in S (e.g., `-m e1,e8`); add `auto` to fallback to auto-detect |
| `-o F` | Output verified results to file (default: stdout) |
| `-e F` | Output unresolved lines to file (default: stderr) |
| `-b S` | Benchmark selected types (e.g., `-b e1-e10,e15`) |
| `-B` | Benchmark all registered types |
| `-V` | Print version and exit |
| `-h` | Print help and list all supported hash types |

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

- Each hash type has a **benchmark rate** (hashes/sec), either from a built-in table of 757 pre-measured rates or from runtime `-B`/`-b` benchmarks.
- **BatchLimit** = `rate * 0.75` (target 0.75 seconds of work per batch), clamped to [1, 4096].
- When `-m` specifies types, BatchLimit is pre-set from the slowest selected type.
- In auto-detect mode, BatchLimit starts at `Numthreads * 4` and the worker feedback loop adjusts it as hash types are identified.

This achieves near-linear scaling for slow types: 1000 bcrypt cost-12 hashes run in ~13 seconds on 16 threads vs ~170 seconds single-threaded.

### Hot Type Optimization

hashpipe tracks the most recently matched hash type as a "hot type" and a hot list of recent matches.  When processing a batch, workers try the hot type first before falling back to the full candidate scan.  For homogeneous input (common in potfiles), this avoids testing hundreds of types per line.

### Verification Strategies

Hash types use one of three verification strategies:

- **Direct compute**: compute the hash from the password and compare the binary result against the decoded hex input.  Used for simple types (MD5, SHA1, SHA256, etc.) and composed chains.
- **Chain compute**: a chain of hash steps defined declaratively (innermost to outermost), supporting UC (uppercase hex), NTLM (UTF-16LE), salt insertion, and raw binary passes.  Covers hundreds of composed types like `SHA1(MD5($pass))`.
- **Verify function**: a custom function that takes the hash string and password, returning match/no-match.  Used for non-hex formats where the hash encodes its own parameters: bcrypt (cost factor in hash), PHPBB3, APACHE-SHA, APR1.

### Per-hashlen Candidate Caches

Rather than scanning all 757 types for each input line, hashpipe maintains per-hashlen lookup tables: separate caches for unsalted, salted, and composed types indexed by binary hash length (0-64 bytes).  A 32-byte hex hash (16 binary bytes) only checks MD5, MD4, GOST, RIPEMD-128, and their composed variants.

## Supported Hash Types

hashpipe supports 757 hash types.  Run `hashpipe -h` for the full list.

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
| e786 | NTLMH | `md4(utf16le(hex(md4(utf16le($pass)))))` |

### Non-hex / verify types

| Index | Type | Algorithm |
|-------|------|-----------|
| e450 | BCRYPT | `bcrypt($pass)` |
| e451 | BCRYPTMD5 | `bcrypt(hex(md5($pass)))` |
| e452 | BCRYPTSHA1 | `bcrypt(hex(sha1($pass)))` |
| e455 | PHPBB3 | `phpbb3($pass)` |
| e457 | APACHE-SHA | `{SHA}base64(sha1($pass))` |
| e461 | APR1 | `apr1($pass)` |

### Additional algorithm families

hashpipe also supports GOST, GOST-CRYPTO, Streebog, RIPEMD-128/160/320, TIGER, HAVAL (all variants), BLAKE-224/256/384/512, BMW, CubeHash, ECHO, Fugue, Groestl, Hamsi, JH, Keccak, SHA-3, Luffa, Panama, RadioGatun, Shabal, SHAvite, SIMD, Skein, Whirlpool, MD6, MDC2, EDON, Snefru, HAS-160, BLAKE2B/2S, MurmurHash, RADMIN2, LM, and hundreds of composed/chained variants.

## Benchmarking

`hashpipe -B` benchmarks all 757 registered types and reports hashes/second for each:

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

### Dependencies

hashpipe requires the following static libraries:

- OpenSSL 1.1.1w (`libssl.a`, `libcrypto.a`)
- sphlib (`libsph.a`)
- libmhash (`libmhash.a`)
- RHash (`librhash.a`)
- MD6 (`md6.a`)
- GOST/Streebog (`gosthash/gost2012/gost2012.a`)
- bcrypt / crypt_blowfish (`bcrypt-master/bcrypt.a`)
- libJudy (`libJudy.a`)
- yescrypt (`yescrypt/*.o`)

### Supported Platforms

The Makefile detects the build platform automatically.  Tested on:

- macOS x86\_64 and arm64 (requires libiconv from MacPorts)
- Linux x86\_64 (Ubuntu 18.04, 22.04)
- Linux ppc64le (PowerPC 8)
- FreeBSD 13.2 x86\_64 (uses gmake)

## Type Indices

hashpipe uses the same type index numbering as mdxfind. The `e` prefix distinguishes internal indices from hashcat mode numbers. When using `-m`, always use the `e` prefix:

```bash
# Correct: internal index
hashpipe -m e1,e8,e450 potfile.txt

# Multiple ranges
hashpipe -m e1-e12,e369,e450-e461 potfile.txt
```

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
- [stribob](https://github.com/mjosaarinen/brutus) — Markku-Juhani O. Saarinen (Streebog/GOST R 34.11-2012 primitives; standalone wrapper from stricat bundled with permission)

Platform detection in the Makefile was inspired by [PR #1](https://github.com/Cynosureprime/hashpipe/pull/1) from [@0xVavaldi](https://github.com/0xVavaldi).

## License

MIT
