# hashpipe v1.205: bertillon identifies $2b$, $2x$ and $2y$ bcrypt

Source: hashpipe.c 1.204 -> 1.205, bertillon.h 1.22 -> 1.24.

**bertillon rejected most bcrypt hashes.** A type's tag is whichever stored-form
prefix its own self-test vector carried, and it excluded candidates before any
computation. BCRYPT's tag is `$2a$`, so a bcrypt written `$2b$`, `$2x$` or `$2y$`
matched nothing and the tool answered `NOTHING to try -- no type can produce this
value`. `$2b$` is what most current libraries emit; `$2y$` is what PHP's
`password_hash()` writes. BCRYPTMD5 and BCRYPTSHA1, whose vectors are `$2b$`, were
never offered a real `$2a$` value. A verify type parses the stored form itself, so
the tag test now applies only to compute types. A cost-12 bcrypt takes 1.29s where
it took 0.95s; bare hex is unchanged.

**bertillon -p discarded a salt it had measured.** In FIELD BOUNDARY the direction
retry overwrote a measured suffix with a shorter prefix, so a list whose every
password ended in the same 7-byte site salt reported no shared run at all. It now
keeps the longer direction. The test for a run that IS the whole field is
arithmetic and no longer carries a threshold; a correct `hash:salt` list with a
3-byte site salt used to report the opposite of what was measured. Below the
threshold a run is named rather than judged, and every outcome now states that the
test sees only a salt every record shares and is blind to one that varies.

**docs/METHOD-bertillon-discovery.md** is now an operating reference written for an
AI agent rather than a human reader, covering bertillon, hashpipe and mdxfind
together. The guide and walkthrough are unchanged in substance.
