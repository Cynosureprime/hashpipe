# hashpipe v1.215: seven new hash types, and a HUM separator false-positive fix

Source: hashpipe.c 1.213 -> 1.215.

## New hash types (e1047 - e1053)

| index | name | construction |
|---|---|---|
| e1047 | `MD5-1xMD5pMD5SHA1p` | `md5(md5(pass) . md5(sha1(pass)))` |
| e1048 | `MD5-1xMD5pMD5SHA256p` | `md5(md5(pass) . md5(sha256(pass)))` |
| e1049 | `MD5-1xMD5pMD5SHA512p` | `md5(md5(pass) . md5(sha512(pass)))` |
| e1050 | `MD5SHA1revMD5` | `md5(sha1(rev(md5(pass))))` |
| e1051 | `MD5MD5RAWMD5PASS` | `md5(md5_bin(md5(pass) . pass))` |
| e1052 | `MD5MD5RAWMD5` | `md5(md5_bin(md5(pass)))` |
| e1053 | `MD5SHA1SHA1MD5MD5` | `md5(sha1(sha1(md5(md5(pass)))))` |

All seven are unsalted, catalogued in `hx.8`, and cleared the `hx_dedup_check`
gate before a number was assigned. Each vector was reproduced independently
rather than by the code under test. `e1051` and `e1052` consume the inner digest
as hex and feed the outer `md5` the raw sixteen bytes, which is what separates
them from the hex-chained forms already present.

Self-test rises to 1052 passed, 0 failed, 2 skipped.

## HUM types no longer claim hashes they cannot produce

The seven `HUM` types are unsalted. mdxfind does not take their separator from
the input: it sweeps a fixed eight-entry table and writes the hex of whichever
entry matched into the output line as a label, `<sephex>- x N`. hashpipe carries
that label in the salt slot as transport.

`hum_decode_salt` accepted any hex-looking field. It treated the whole field as
hex when the label marker was absent, returned a partial decode on a bad nibble,
and never checked the result against the separator alphabet. `MD5MD5HUM` was
therefore computing `md5(md5(pass) . <any bytes>)`, a strict superset of e31
`MD5SALT` -- so a genuine `MD5SALT` hash whose salt was written as bare hex was
attributed to `MD5MD5HUM`, a type that could never have produced it.

The marker is now required, hex parsing is strict, and the decoded separator must
be one of the eight values mdxfind can emit.

All 5405 real HUM lines in the regression corpus verify byte-identically before
and after, per type. 200 of 200 synthetic `MD5SALT` hashes with hex-spelled salts
stop being mis-attributed, and one genuine corpus line is corrected from an
impossible `SHA1SHA1HUM` to an iteration count confirmed by independent
computation. Corpus-wide, 1,228,884 lines that the old parse fed to the HUM
computes are now declined during parsing.
