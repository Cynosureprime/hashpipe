# bertillon / hashpipe / mdxfind — operating facts, indexed for retrieval

**AUDIENCE: AI agent. NOT written for a human reader.**

A human wanting to learn these tools should read `GUIDE-bertillon.md` and
`WALKTHROUGH-2011-first-crack.md`, which explain and persuade. This document
does neither. It is ordered for lookup, not for reading: literal output
strings, exact option semantics, stated costs, and the failure modes that
return exit 0. Prose that would help a human orient has been removed on
purpose.

Every fact here was verified against the tools as they run, at the build named
in §9, or carried from a recorded measurement that §9 cites. Nothing is
inferred from a type name.

---

## TRIGGERS — literal strings that should bring you to this document

As they appear ON SCREEN, across all four tools: some are rendered format
strings, and `No password hashes loaded` is john's while `Token length
exception` is hashcat's.

    0 hashes, 0 salts, 0 users loaded
    None found, sorry!
    No password hashes loaded
    no registered type verified these formats
    bertillon: field 2 is not the plaintext
    bertillon: not solved
    bertillon: SOLVED as hash:plaintext
    bertillon gate: no parsed work factor
    looks like a path but no such
    Working on hash types: MD5
    Token length exception
    hash:salt
    take no salt, and one was supplied
    cannot produce a

---

## 0. Governing rules

**R0. A tool returning zero is not evidence of absence until it has returned
non-zero on a known positive.** Plant a canary — a known `hash:password` pair
of the type under test — as the FIRST line of every candidate file. COST of
skipping this: every entry in §7 presents as an honest negative. MAKE ONE with
mdxfind's generate mode, which hashes a password you choose under types you
name:

    echo password | mdxfind -f /dev/null -z -M e450,e451 stdin

All four parts are needed: `-M` before it, `-f /dev/null` to satisfy the
hash-file argument, and `stdin` as the wordlist. `-z` alone becomes an ordinary
MD5 run reading stdin as a hash list, which looks like a normal run. See `man
mdxfind`, EXAMPLES — the page carries the form, the flag and the caveat that
`-z` output resembles solves and is not.

**R1. Hash LENGTH DOES NOT IDENTIFY THE ALGORITHM.** mdxfind matches a short
hex hash against *any 32-char window* of the computed digest for any selected
type, by default, with no flag. All four 32-char quarters of
`SHA512("anotherpassword")` are reported as `SHA512x01`. A 32-char hex value is
therefore not necessarily MD5. CONSEQUENCE: single-mode attacks on short hashes
(hashcat `-m 5100` Half MD5) test one hypothesis out of many.

**R2. A RECORDED SAMPLE IS NOT A SPECIFICATION.** Two instances of one
failure:

- A type NAME does not state its construction. `MD5SALT` is
    `md5(md5($pass) . $salt)`. `md5($pass . $salt)` is `MD5PASSSALT` (e373).
    `md5($salt . $pass)` is `MD5USERPASS`. `hx.8` is the authority.
- A stored-form PREFIX is not a type discriminator. bcrypt's `$2a$`, `$2b$`,
    `$2x$` and `$2y$` are algorithm revisions, orthogonal to the construction.
    PHP's `password_hash()` writes `$2y$`; most current libraries write `$2b$`.

COST: a control test built on a guessed definition proves nothing, and a filter
keyed on a prefix taken from one example reports "no type can produce this
value" for the commonest form in the file.

**R3. e-numbers are POSITIONAL** and shift as built-in types are added. Key any
stored comparison on the type NAME, never on `eNNN`.

**R4. bertillon does not identify a hash.** It returns the set of types that
*could* have produced the value. For a bare 32-char hex value that set is 189
at the easy tier and no examination of the value narrows it.

---

## 1. Tool selection

| you have | you want | tool |
|---|---|---|
| unknown list, nothing solved | what forms are in it, which input channel | `bertillon -f` |
| unknown list, nothing solved | damage, salt reuse, is the split right | `bertillon -p` |
| unknown list, nothing solved | a type selection for a first cheap run | `bertillon -t e -e m` |
| `hash:password` pairs | which type(s) produce it | `bertillon --gate` |
| `TYPE hash:password` lines | does each verify under its OWN label | `hashpipe -c` |
| hashes + wordlist | search | `mdxfind` |
| solved plaintexts | structure, rules, shape | `pack2 cgrams`, `procrule -G`, `rling -q` |

`bertillon` IS `hashpipe` — the same binary reached through `argv[0]` via a
symlink, or as `hashpipe -Z ...`. Same types, same measured speeds.

**hashpipe is CPU-only by design and will not gain a GPU path.**

---

## 2. mdxfind input channels — the costliest thing to get wrong

| channel | for | selected by |
|---|---|---|
| `-f file` | plain hex digests ONLY. Vectorised fast path. | `-m` |
| `-F file` | anything not bare hex: `$id$salt$hash`, base64, `hash:salt`, `{ssha1}…` | `-m` or `-M` |
| `-J file` | as `-F`, no load-set restriction: every selected type is offered the file | `-m`/`-M` |

**`-f` DISCARDS EVERYTHING AFTER THE FIRST COLON.** A `hash:salt` line read
with `-f` loses its salt, the salted type then matches nothing, and the run
**exits 0**.

`bertillon -f` answers the channel question per distinct form, with counts:

    verdict          channel
    digest           -f
    delimited        -F      (a colon here is a field; -f would eat it)
    tagged           -F
    prefix           -F
    composite        -F
    not-hash         neither -- read the line before doing anything else

**ALWAYS READ THE LOAD RECEIPT.** Every hash file reports on stderr:

    hashes.txt: 4213 hashes, 4213 salts, 0 users loaded

`0 hashes` or `0 salts` IS the diagnosis. Before mdxfind 1.578 a file that
yielded nothing printed nothing.

**`$NT$` cannot be read by ANY channel.** mdxfind does not strip the header (it
is a John signature). Strip it, crack the bare 32-hex as NTLM, restore the
prefix before `mdsplit`.

### Option order is semantic — mdxfind acts during getopt, not after

- `-M` MUST PRECEDE `-F`, `-S`, `-U`, `-P`. Since 1.578 an `-m`/`-M`/`-h` after
a `-F`/`-J` is fatal and names the file; earlier versions ran to completion
printing a plausible `Working on hash types:` line and finding nothing.
- **Each `-M` resets the load selection.** One `-M` per group of `-S`/`-U`/`-P`.
`-M RESET` clears it.
- **Until the first `-m`/`-h`/`-M`, the selected set is MD5 ALONE.**
- **`-h` IS NOT HELP.** It is a case-insensitive PCRE over type names. Help is
`-?` or no arguments.

### Type selection width

    mdxfind -h .        22 types    (VERIFIED: a curated set, NOT everything)
    mdxfind -m e1-e999  everything

`-h .` and `-h ALL` both select that same curated 22. Anything that depends on
"we tried everything" must use `-m e1-e999`.

### The salted trap

With no `-s`, salted types consume the hash list itself as salt candidates. A
1,671-hash list once generated 903,952 salts and effectively stalled.
`bertillon -v` reports how many types in a selection want a salt the input does
not supply:

      not tried:
          251  take no salt, and one was supplied
           12  cost more than the easy tier allows

To build an unsalted-only selection by hand, filter the flag-letter column of
`hashpipe -N`: `awk 'NR>1 && $4 !~ /s/ && $4 !~ /u/'`. Measured 788 types at
the build in §9. The count is build-dependent — re-measure, do not carry it.

---

## 3. bertillon — exact semantics

    bertillon <hash>                 candidate types for one value
    bertillon <file>                 the same, for a list
    bertillon <hash>:<plaintext>     verify outright
    bertillon -f <file>              what forms are in this file
    bertillon -p <file>              what the list says collectively
    bertillon -g <file>              verify hash:plaintext pairs
    bertillon --emit-table [REF]     measure every type; compare to REF

    -t, --tier easy|medium|hard      cost budget
    -o, --only                       that tier alone, not the cheaper ones too
    -T, --truncation                 also types whose digest is longer
    -e, --emit enum|mdx|hashcat|john|cmd
    -b, --table REF.tsv              measured costs, for accurate tiering
    -v                               full breakdown

A value may be given by its first letter: `-t e -e h` is `--tier easy --emit
hashcat`.

**Selection to stdout, summary to stderr.** stdout carries nothing but the
selection, so it pipes.

**Field count decides how a value is read.** Two fields could be `hash:salt` or
`hash:plaintext` and nothing in the line says which, so BOTH are tried.

**A tier is a budget, not a verdict.** Types outside the selected tier are
untested, not ruled out. The count is printed on every run.

**Operand mismatch cuts BOTH ways.** A type needing a salt is excluded when the
input supplies none; a type taking no salt is excluded when one IS supplied.
`hash:salt` on a 32-char value yields 66 types at the easy tier and 78 across
all tiers, not the 254 an unsalted reading would give.

**`--emit-table` exit codes:**

    exit 0   compared, identical (row count to stderr)
    exit 1   compared, differs -- new table to stdout, diagnosis to stderr
    exit 2   could not compare -- reference absent, unreadable, malformed

`salt_ceiling`, `salt_rel`, `field2_is_salt`, `n_acceptors` and `collides_with`
are COPIED from the reference unchanged. This binary does not measure them;
`tools/bertillon-probe` does, and that run takes about 35 minutes.

**The reference path is always explicit.** No default location, no search path.
Userdef types are excluded unless `--include-userdef`, and then their measured
columns are blank.

### `-e hashcat` and `-e john` cannot express every type

hashcat and John name far fewer constructions than mdxfind. The count they drop
is reported. `-e hashcat` prints ONE MODE PER LINE because hashcat's `-m` takes
one mode per run where mdxfind's takes a set.

**The mode count is not the type count.** 25 modes came from 19 of 66 types; a
type can map to several modes. 47 of those 66 had no hashcat mode at all. COST
of reading the mode count as coverage: 47 constructions silently untried.

---

## 4. hashpipe — verification, not search

Input `[TYPE[xNN] ]hash[:salt]:password`. Verified lines to stdout, unresolved
to stderr. **The two streams are the result.**

| option | fact |
|---|---|
| `-c` | verify each line against its OWN leading TYPE label only. No detection, no fallback. ~240:1 faster than identification on an iterated salted type. |
| `-m spec` | strict FILTER, not a hint. Append `auto` whenever the type is uncertain, or an omitted type under-reports silently. |
| `-L N` | max estimated seconds per verify, **default 1000**. A SKIPPED verify is reported exactly like a FAILED one — line to stderr, no distinguishing diagnostic. Raise for scrypt, Argon2, high-cost bcrypt. |
| `-s file` | **DUAL USE, no diagnostic**: statistics filename in a normal run, the hx salt value in `-X`/`-F` expression mode. Not both. |
| `-T` / `-G` | self-tests over every registered type. Run FIRST after any build. |
| `-N` | type table as TSV: index, name, hashcat modes, flag letters, self-test vector. |

`bertillon --gate` wraps this: it computes `-L` from each line's own parsed
work factor BEFORE starting, because hashpipe reports a cost-skipped type and
an unhandled format with the same message.

---

## 5. Reading bertillon output — literal strings

| string | meaning | next action |
|---|---|---|
| `SOLVED as hash:plaintext -- N type(s) verified` | the line was `hash:plaintext` and N types reproduce it | if N>1, see §6 |
| `field 2 is not the plaintext -- N types tried, none matched` | two fields, and field 2 is a SALT not a password | read as `hash:salt`; the candidate set follows |
| `not solved -- N type(s) tried, none matched` | nothing verified | §7 row "gate line comes back bare" |
| `hash:salt` followed by e-numbers | the selection, for `mdxfind -M` | keys are POSITIONAL (R3) |
| `N types to try (…, easy tier)` | the APPLICABLE set | `widen:` line states what raising the tier adds |
| `no wider tier available` | no higher rung adds anything for this form | not an error |
| `M not tried` | partitioned in the `-v` breakdown | the four figures sum to M |
| `cannot produce a N-character <set> form` | arithmetic exclusion | says NOTHING about any algorithm |
| `take no salt, and one was supplied` | operand mismatch | these types apply to a DIFFERENT input |
| `cost more than the easy tier allows` | deferred, NOT decided | `--tier medium` to include |
| `looks like a path but no such` | a mistyped filename was about to be parsed as a hash | fix the path |
| `N e-number(s) shifted position; not a change` | built-ins were added since the reference | expected; compare on NAME |
| `derived digest lengths (bytes): [8, 16, 20, 24, 28, 32, 40, 48, 64]` | the length partition in use | 8/24/40 are REAL (TIGER at 24, RMD320 at 40) |

---

## 6. Several types verifying is the NORMAL case

SHA1, AICH and SHA1UTF7 all verify the same pair. AICH over one small block IS
SHA-1. `hashpipe` reports only the first match because a cracker needs one
answer; bertillon reports every one.

**NTLM / NTLMH / MD4UTF16 are ONE algorithm (MD4) fed three encodings**, each
a superset of the one above it:

| type | conversions offered |
|---|---|
| `MD4UTF16` | iconv UTF-8 -> UTF-16LE only |
| `NTLMH` | that, PLUS a UTF-16LE zero-extend (hashcat's method) |
| `NTLM` | that, PLUS CP1251 and CP1252 variants |

hashcat mode 1000 maps to NTLMH, not to NTLM.

**INFERENCE AVAILABLE:** all three coincide only on ASCII input — a UTF-8 `é`
(`0xC3 0xA9`) is one UTF-16LE unit under iconv and two under zero-extend. So
all three labels agreeing on a pair means **the plaintext is pure ASCII**.

Which label to record is a judgement about where the list came from. Nothing in
the line decides it.

---

## 7. Traps, indexed by symptom

| symptom | real cause | check |
|---|---|---|
| mdxfind finds nothing, exit 0, salted types selected | `-f` used on `hash:salt`; salt discarded at the first colon | the load receipt: `0 salts` |
| `Working on hash types: MD5` and nothing else | no `-m`/`-h`/`-M` reached before the file | reorder: selection BEFORE `-F`/`-J` |
| run completes, `None found, sorry!`, too few lines processed | one over-long line ended the dictionary read | `LC_ALL=C awk 'length($0)>0 && length($0)<=256'` |
| whole file matches nothing, presents as a wrong wordlist | CRLF list against LF candidates | `bertillon -p` reports it; `file list.txt` |
| a type "is not registered" | it was SKIPPED FOR COST — same message | raise `-L`; `bertillon --gate` sets it from the work factor |
| gate line comes back bare | three indistinguishable causes, in this order: password wrong; fields in wrong order; construction not registered | for the last, write it in `hx` + a `userdef` entry. A wider search will NOT find it. |
| a verified line, but candidates derived from it yield nothing | **salt folded into the password field.** Verifies perfectly, so verification cannot catch it. Every recorded plaintext carries the salt. | `bertillon -p`. It reports a run only where EVERY record shares it, so it sees a CONSTANT salt and is blind to one that VARIES — two hex characters over 256 values share no run. Silence there is not a negative. |
| `bertillon` answers `NOTHING to try` for a value `hashpipe` identifies | **version skew.** `bertillon` and `hashpipe` are ONE binary reached two ways. They cannot disagree unless they are different builds. | run both on the same line; `command -v hashpipe bertillon`; compare md5 |
| `$NT$`-prefixed hashes match nothing under any channel | mdxfind does not strip the John signature | strip, crack bare, restore before `mdsplit` |
| salted run stalls, enormous salt count | no `-s`: the hash list became the salt candidate list | 1,671 hashes -> 903,952 salts |
| 32-char hex assumed MD5, MD5 sweep finds nothing | R1: it may be a 32-char window of SHA1/SHA256/SHA512/NTLM | broad `-m` set, not one mode |
| `--emit-table` says "identical" while listing ADDED rows | userdef types were in the comparison domain | they are excluded by default; do not re-add them |
| two hosts produce overlapping work | corpora not partitioned before launch | `rling` subtract beforehand: 155,285 of 425,228 candidates were duplicated once |
| a monitor stays silent and you assume health | the watch fired only when ALL boxes went idle | alert on ANY unit idling |

---

## 8. What none of these tools do

**They do not rank by likelihood, and bertillon will not.** Measurements:
77 of the 78 salted 32-character types accept every salt length tried, so salt
length does not narrow the answer; the only labelled corpus available is one
file per type; and a corpus labelled by what solved it measures the SEARCH, not
the population. Counterexample on record: a list published across three modes,
every record verifying under its claimed one, all three a single algorithm
misfiled.

**They do not read the filename, the challenge text, or the organiser's
intent** — and those beat them routinely. An expensive KDF is evidence the
passphrase is meant to be DERIVED rather than searched. An 11-character token
in a filename is a video ID.

**They do not profile plaintexts.** Once anything cracks, the yield is in
reading what came back: `pack2 cgrams` for segmentation, `procrule -G` for the
rules, `rling -q` for shape.

**bertillon output is type identification, NOT a cracked-password record.**
Found-lines come from `hashpipe` and `mdxfind`, which own that format.

---

## 9. References

Read the MAN PAGES, not `-h`/usage output. Usage text was incomplete for years
(mdxfind documented 30 of 40 options, hashpipe 14 of 25); the man pages are the
authority. Installed under `/usr/local/share/man/man1`, so `man` and `apropos`
work.

    man bertillon        man hashpipe        man mdxfind
    man procrule         man rling           man 7 rules32
    hx.8                 authority on what each type computes

| for | read |
|---|---|
| cost-vs-yield of every technique | `contest/history/TIME-ALLOCATION.md` |
| cheap moves that beat compute | `contest/history/CHALLENGE-HEURISTICS.md` |
| every trap in §7, with its full case history | `contest/history/TOOLING-TRAPS.md` |
| the verify-instead-of-crack model | `contest/history/PAIRED-VERIFICATION.md` |
| what to do after the first hit | `contest/history/CORRELATION-DISCOVERY.md` |
| encoding forensics, `$HEX[]`, per-corpus splits | `contest/history/WORD-PATTERNS.md` |
| the example-file construction (`e31`, `saltfull.txt`) | `docs/BENCHMARK.md` in the mdxfind distribution |
| this tool's design decisions and their basis | `SPEC-hash-shape-filter.md` |
| a human-readable introduction | `GUIDE-bertillon.md`, `WALKTHROUGH-2011-first-crack.md` |

Counts in this document were measured on `mdxfind` 1.581 and `hashpipe` 1.204.

Type counts and selection sizes are build-dependent: re-measure them, do not
carry them forward. The version string names the `hashpipe.c` revision only, so
two builds that differ in behaviour can report the same number. Establish what
a binary does by running it, not by reading its version.
