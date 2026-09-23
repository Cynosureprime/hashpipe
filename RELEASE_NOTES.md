# hashpipe v1.206: TESTVEC accepts the counts mdxfind writes

Source: hashpipe.c 1.205 -> 1.206.

**A zero-padded `$TESTVEC[]` count was rejected.** The repeat count was bounded by
the width of the field rather than by its value, at seven characters, and leading
zeros counted against that limit. So `$TESTVEC[00 x 00051200]` failed while
`$TESTVEC[00 x 0051200]` — the same 51200 — verified, and a larger value in a
narrower field was fine all along. mdxfind runs `atoi()` over the digit run and
imposes no width at all, so it matched candidates hashpipe then declined to
verify. The published form is written `$TESTVEC[HH x NNNNNNN]`, which is where
the seven came from; it is an illustration of the notation, not a limit. The
count is now bounded by value, with a guard that keeps the accumulation inside
an `int`.

**Two smaller divergences from mdxfind's parser are closed.** The trailing `]`
is optional, because mdxfind appends one when it is absent; and the separator
between pattern and count may be any run of non-digits, not the literal `" x "`,
which is also what mdxfind accepts. The pattern is now sized by scanning hex
digits rather than by locating a separator first. Strings that were rejected
before and should stay rejected still are: a zero count, an odd-length pattern,
a non-hex pattern, an absent count, and a bare digit run with no separator.

**An overflow is fixed in the same path.** `patbytes * count` was multiplied
before the size bound was tested, so a large count overflowed `int` before
anything noticed. The bound is now tested first.

A vector longer than the 2 MiB buffer is still silently truncated and hashed,
rather than reported as unsupported; mdxfind skips such a candidate instead.
That difference is unchanged here.
