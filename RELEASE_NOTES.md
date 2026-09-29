# hashpipe v1.216: benchmark table completed

Source: hashpipe.c 1.215 -> 1.216.

## Every measurable type now has a benchmark rate

`bench_rates.h` gains measured throughputs for e1047 through e1053, the seven
types added in v1.213 and v1.215. The table goes from 1045 to 1052 entries.

Every registered type that can be benchmarked now has a rate. The only two
indices absent are e0 `none` and e426 `PARALLEL`, which are exactly the two the
self-test skips: neither has a test vector to measure against.

Measured on the canonical host named in the `bench_rates.h` header, using the
incremental path documented there.

## What the cost guard actually gates

Earlier notes said a missing rate left `-L` unable to decline the affected
types. That is not what happens, and the reasoning is now recorded in the
source.

`verify_cost_exceeds` needs both a rate and a bench cost, and treats either
being absent as no data. It is reached only from the verify functions of types
that parse an iteration count out of the hash -- the bcrypt, SAP and PBKDF2
families. A plain unsalted type never reaches it, so `-L` neither declines nor
could decline e1047 through e1053 whatever the table holds. e1053 verifies
identically at `-L 1000000` and at `-L 0.0000001`.

What a missing rate does cost is narrower and less visible: it silently disables
the cost guard of any type that *does* parse a cost, letting an expensive hash
verify at any `-L`, with nothing reporting the gap. That is the reason the table
is kept complete rather than filled in when a guard is added.

No functional change in this release. Self-test 1052 passed, 0 failed,
2 skipped.
