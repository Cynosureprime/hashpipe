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
| `-q N` | Quantization (reserved, default: 128) |
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

## Supported Hash Types

hashpipe supports 565 hash types.  Run `hashpipe -h` for the full list.

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

## Building

```bash
make hashpipe
```

Requires OpenSSL, libsph, librhash, libJudy, and GOST/Streebog libraries.

## License

MIT
