<p align="center">
  <img src="img/hashpipe.svg" width="128" alt="hashpipe logo">
</p>

# hashpipe

Multi-threaded hash verification tool. Reads lines containing `hash:password` pairs (optionally with TYPE hints and salts), verifies them by computing the hash from the password, and outputs verified results in mdxfind stdout format. Unresolved lines go to stderr.

Uses [yarn.c](https://github.com/madler/pigz) for threading and OpenSSL for hash computation.

## Supported Hash Types

| Type | Description |
|------|-------------|
| MD4 | MD4 hash |
| MD5 | MD5 hash |
| NTLM | NT LAN Manager (MD4 of UTF-16LE) |
| SHA1 | SHA-1 hash |
| SHA224 | SHA-224 hash |
| SHA256 | SHA-256 hash |
| SHA384 | SHA-384 hash |
| SHA512 | SHA-512 hash |
| DCC | Domain Cached Credentials (MS-Cache v1) |
| DCC2 | Domain Cached Credentials v2 (PBKDF2) |
| NETLM | NetLM challenge-response |
| NETLMv2 | NetLMv2 challenge-response |
| NETNTLMv2 | NetNTLMv2 challenge-response |
| SHA1MD5 | SHA1(MD5(password)) |
| MD5SHA1 | MD5(SHA1(password)) |
| MD5MD5 | MD5(MD5(password)) |
| HMACMD5 | HMAC-MD5 with salt as key |
| HMACSHA1 | HMAC-SHA1 with salt as key |
| HMACSHA256 | HMAC-SHA256 with salt as key |
| SSHA1 | Salted SHA-1 (salt appended) |
| SSHA256 | Salted SHA-256 (salt appended) |
| SSHA512 | Salted SHA-512 (salt appended) |

## Building

```
make
```

Requires OpenSSL development libraries.

## License

MIT
