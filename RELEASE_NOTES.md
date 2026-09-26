# hashpipe v1.210: `-m` restricts user-defined types

Source: hashpipe.c 1.209 -> 1.210, hashpipe.1 1.12 -> 1.13.

**`-m` did not restrict user-defined types.** `-m` is a filter: a type that is
not listed is never tried. That held for built-in types and not for
user-defined ones, which were tried on every line whatever `-m` said. A run
restricted to `-m e1` could therefore report a line as a user-defined type, and
because a user-type match suppresses the unresolved pass-through, the operator
saw a confident answer for a type they had excluded rather than the silent
negative `-m` promises. The cost was the other half: the loop walked every
loaded user type per line, so the speedup `-m` exists to deliver was never
available on that side.

`-m u`*id* exists and selects a user-defined type by the id its `userdef.txt`
stanza declares. It now restricts like everything else: `-m u47` tries that
type and nothing else. A spec naming no user type excludes user types
entirely, which is what makes `-m` usable for reading a file that must contain
one type only. A spec naming only user types excludes the built-ins the same
way. `auto` anywhere in the spec re-admits everything, unchanged.

**`-m u`*id* alone silently became full auto-detection.** The strict
"no fallback unless `auto`" gate sat inside the block that runs only when `-m`
selected at least one *built-in* type. A spec of `u47` leaves that count at
zero, so the gate was skipped and the line fell through to the full
auto-detect sweep over every built-in type as well as every user type --
exactly the opposite of what the spec asked for, and slower than issuing no
`-m` at all would have suggested.

Both follow from `-m` having begun life as a hint, where a user id only
reordered which user types were tried first. Selection is the contract now,
for built-in and user-defined types alike.

`-c` is unaffected: it takes the type from each line's label and already
restricted user types correctly. The built-in `-m` path is unchanged --
verified against the previous build over a corpus of all 1028 built-in test
vectors across seven different `-m` specs and under `-c`, byte-identical in
every case, with the self-test at 1028 passed, 0 failed, 2 skipped.

`hashpipe(1)` now documents `u`*id* in the `-m` grammar and states the
restriction rule for user-defined types.
