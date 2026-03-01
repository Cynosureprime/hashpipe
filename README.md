<p align="center">
  <img src="img/hashpipe.svg" width="128" alt="hashpipe logo">
</p>

# hashpipe

Multi-threaded hash verification tool. Reads lines containing `hash:password` pairs (optionally with TYPE hints and salts), verifies them by computing the hash from the password, and outputs verified results in mdxfind stdout format. Unresolved lines go to stderr.

Uses [yarn.c](https://github.com/madler/pigz) for threading and OpenSSL for hash computation.

## Usage

```
hashpipe [-t N] [-i N] [-q N] [-o outfile] [-e errfile] [-V] [-h] [file ...]
```

### Options

| Flag | Description |
|------|-------------|
| `-t N` | Thread count (default: number of CPUs) |
| `-i N` | Max iteration count for hard pass (default: 128) |
| `-q N` | Maximum internal hash iteration (default: 128) |
| `-o F` | Output verified results to file (default: stdout) |
| `-e F` | Output unresolved lines to file (default: stderr) |
| `-V` | Print version and exit |
| `-h` | Print help |

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
```
cat potfile.txt | hashpipe
```

Verify with type hints, saving results and rejects to separate files:
```
hashpipe -o verified.txt -e unresolved.txt potfile.txt
```

Use 8 threads:
```
hashpipe -t 8 potfile.txt
```

Pipe verified results directly into mdsplit:
```
hashpipe potfile.txt | mdsplit potfile.txt
```

Verify multiple files:
```
hashpipe file1.txt file2.txt file3.txt
```

## Pot(files) considered harmful

For many years, I have taken the position that potfiles, the place where solved hashes go to die, are not only bad, but also dangerous.  They can confuse what hash types are involved, or what the algorithm is, and can introduce bad solutions into an otherwise perfect hash processing stream.  Hashpipe is intended to be an automated method to resolve, or verify, questionable hashes.  By trying many different hashing methods, in a fully automated fashion, hashpipe can figure out what types of hashes are involved, properly format the output, and can pipe directly into mdsplit for long term hash management.  Much more to the point, it also separates out the unsolved hashes, corrupted entries, or other bad data.

## Supported Hash Types

| Type | Algorithm | MDXfind | hashcat |
|------|-----------|---------|---------|
| MD5 | `md5($pass)` | e1 | -m 0 |
| MD5UC | `md5($pass)` (uppercase hex) | e2 | -m 0 |
| MD4 | `md4($pass)` | e3 | -m 900 |
| NTLM | `md4(utf16le($pass))` | e369 | -m 1000 |
| SHA1 | `sha1($pass)` | e8 | -m 100 |
| SHA1UC | `sha1($pass)` (uppercase hex) | e182 | -m 100 |
| SHA224 | `sha224($pass)` | e9 | -m 1300 |
| SHA256 | `sha256($pass)` | e10 | -m 1400 |
| SHA384 | `sha384($pass)` | e11 | -m 10800 |
| SHA512 | `sha512($pass)` | e12 | -m 1700 |
| MD5PASSSALT | `md5($pass.$salt)` | e373 | -m 10 |
| MD5SALT | `md5(hex(md5($pass)).$salt)` | e31 | -m 2611 |
| SHA1SALTPASS | `sha1($salt.$pass)` | e385 | -m 120 |
| SHA1PASSSALT | `sha1($pass.$salt)` | e405 | -m 110 |
| SHA256SALTPASS | `sha256($salt.$pass)` | e412 | -m 1420 |
| SHA256PASSSALT | `sha256($pass.$salt)` | e413 | -m 1410 |
| SHA512SALTPASS | `sha512($salt.$pass)` | e388 | -m 1720 |
| SHA512PASSSALT | `sha512($pass.$salt)` | e386 | -m 1710 |
| MD5MD5PASS | `md5(hex(md5($pass)).$pass)` | e123 | — |
| MD5MD5PASS | `md5(hex(md5($pass)).":".$pass)` | e123 | — |
| SHA1MD5 | `sha1(hex(md5($pass)))` | e160 | -m 4700 |
| MD5SHA1 | `md5(hex(sha1($pass)))` | e178 | -m 4400 |

## Building

```
make
```

Requires OpenSSL development libraries.

## License

MIT
