# hashpipe v1.209: $HEX[] and $TESTVEC[] work the same way everywhere

Source: hashpipe.c 1.206 -> 1.209, hx.c 1.4 -> 1.6, bertillon.h 1.24 -> 1.25.

**`-X` silently split a candidate longer than 4,094 characters.** The stdin
reader used a 4,096-byte stack buffer, so a longer line was cut into
`ceil(n/4094)` pieces and each piece hashed as a whole password — exit 0,
stderr empty, and a column of well-formed digests none of which is the answer.
A 10,240-byte NUL password presented through the hex channel, the only
line-safe way to write one, came back as five copies of `md5` of 2,047 NULs
plus a remainder; the correct digest appeared nowhere. Capacity now comes from
hashpipe's own TESTVEC size, doubled for hex plus a prefix, and an over-long
line is fatal rather than split. That is not new policy — `-c` already refuses
one loudly at MAXLINE — so this is the `-X` reader adopting what its sibling
already did.

**`$HEX[]` and `$TESTVEC[]` are now native on every channel.** They are ways to
write a password, not decoration on one: `$HEX[]` is how a password holding a
colon, a newline or a non-UTF-8 byte is presented at all, and `$TESTVEC[]` is
the only form in which a multi-megabyte repeated vector fits on a line. The
verify path decoded both already; `-X` treated both as literal text, hashing
the twenty-character spelling of a vector rather than the vector, and `-p`
decoded `$HEX[]` but not `$TESTVEC[]`. Both branches now share one binding
helper. A string that does not parse as either form is still taken literally,
which is what keeps a password that merely resembles a wrapper safe.

**The standalone `hx` never supported `$TESTVEC[]` at all.** It treated the
form as a hex container and decoded until the first non-hex character, so
`$TESTVEC[00 x 10240]` read `00`, stopped at the space, and hashed one NUL
byte. `$TESTVEC[HH x N]` is a repeat count. Both of its decode paths carried
their own copy of that loop and now share one expander.

**An oversized vector is refused rather than shortened.** A decoded vector is
bounded at 2 MB, and exceeding it used to clamp silently — the same
3,000,000-byte vector gave one answer from `hx`, a different one from
`hashpipe -X`, and no verify at all from `hashpipe -c`, with the true digest in
none of them. `hx` and `-X` now name the requested size and the limit and exit
non-zero. The verify path still clamps deliberately: aborting a bulk ledger run
on one oversized record is worse than skipping it.

**bertillon gains `--lookup COMMAND FILE`** — ask an external source, then
verify what it says. The source is named explicitly on the command line and is
the only thing that path knows about it: bare hashes in on stdin,
`hash[:salt]:plain` out on stdout. Whatever comes back goes to the gate, so the
type is derived here by computation and the source's own label is never read.
There is no network code, no credentials and no default source; a command that
is not named does not run.

`hx.1` now documents how a candidate is presented — both wrappers, the vector
grammar, the 2 MB bound, and that an unparseable form is taken literally.
