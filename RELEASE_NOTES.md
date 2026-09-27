# hashpipe v1.213: seventeen new hash types

Source: hashpipe.c 1.210 -> 1.213.

## New hash types (e1030 - e1046)

| index | name | construction |
|---|---|---|
| e1030 | `MD5BASE64MD5SHA1` | `md5(base64(md5(sha1(pass))))` |
| e1031 | `WRLSHA1` | `wrl(sha1(pass))` |
| e1032 | `MD5sub8-24MD5sub8-24MD5MD5MD5` | `md5(cut(md5(cut(md5(md5(md5(pass))), 8, 16)), 8, 16))` |
| e1033 | `MD5SHA1SHA1MD5SHA1MD5` | `md5(sha1(sha1(md5(sha1(md5(pass))))))` |
| e1034 | `MD5SHA1SHA1SHA1` | `md5(sha1(sha1(sha1(pass))))` |
| e1035 | `MD5SHA1MD5SHA1MD5SHA1` | `md5(sha1(md5(sha1(md5(sha1(pass))))))` |
| e1036 | `MD5SHA512MD5` | `md5(sha512(md5(pass)))` |
| e1037 | `MD5sub1-16MD5` | `md5(cut(md5(pass), 0, 16))` |
| e1038 | `MD5sub1-28MD5` | `md5(cut(md5(pass), 0, 28))` |
| e1039 | `MD5MD5sub1-30MD5` | `md5(md5(cut(md5(pass), 0, 30)))` |
| e1040 | `APACHE-SHA-TRUNC16` | `"{SHA}" . base64(trunc(sha1_bin(pass), 16))` |
| e1041 | `MD5SALTLAST16` | `cut(md5(md5(pass) . salt), -16)` |
| e1042 | `MD5SALTMD5PASS-PASS` | `md5(salt . md5(pass) . ":" . pass)` |
| e1043 | `MD5-1xMD5SHA1pSHA1p` | `md5(md5(sha1(pass)) . sha1(pass))` |
| e1044 | `MD5-1xMD5SHA256pSHA256p` | `md5(md5(sha256(pass)) . sha256(pass))` |
| e1045 | `MD5-1xMD5SHA512pSHA512p` | `md5(md5(sha512(pass)) . sha512(pass))` |
| e1046 | `MD5-1xMD5MD5pMD5p` | `md5(md5(md5(pass)) . md5(pass))` |

Self-test rises from 1028 to 1045 passed, 0 failed, 2 skipped. Each type was
verified against an independently supplied hash, and mdxfind's own compute was
checked against the `hx` expression evaluator rather than against itself.

`bench_rates.h` carries a measured rate for every one of the seventeen, so none
of them has a dead `-L` cost guard.

Three have a stored form. `APACHE-SHA-TRUNC16` is the RFC 2307 `{SHA}` scheme of
e457 with a 16-byte payload rather than 20, told apart from it by decoded
payload length. `MD5SALTLAST16` stores only the last 16 hex characters of its
digest, so it verifies at a single depth. `MD5SALTMD5PASS-PASS` carries its site
prefix as the salt rather than a hardcoded literal.

Four of the seventeen use the existing `-1x` naming convention, which marks the
outer hash as being over a concatenation rather than a chain; without it a name
such as `MD5MD5SHA1SHA1` would read as a four-deep chain, which is a different
digest.
