# bertillon: a guide

## What it does

The purpose of bertillon is to assist with understanding hash lists. Given a
value, or a file of them, it identifies which registered types could have
produced it, grouped by how expensive each is to test. Sometimes the form of a
value names its algorithm outright, and sometimes that form is misleading.
Where a plaintext is available, bertillon confirms the type outright rather
than narrowing.

`bertillon` is `hashpipe` under another name: the same binary, the same hash
types, the same measured speeds.

    bertillon <hash>                 which types could produce this
    bertillon <file>                 the same, for a list
    bertillon <hash>:<plaintext>     verify it outright
    bertillon -f|--form <file>       what forms are in this file
    bertillon -p|--profile <file>    what the list as a whole says
    bertillon -g|--gate <file>       verify hash:plaintext pairs

Those are the modes. These modify the default one:

    -t, --tier easy|medium|hard      how expensive a type may be to test
    -o, --only                       that tier alone, not the cheaper ones too
    -T, --truncation                 also types whose digest is longer
    -e, --emit FORMAT                what to print (see "Feeding another tool")
    -b, --table REF.tsv              measured costs, for accurate tiering
    -v                               the full breakdown behind the summary

Options have short forms, and a value may be given by its first letter, so

    bertillon -t e -e h list.txt

is `--tier easy --emit hashcat`.

## What it will not tell you

**It does not identify all hashes.** For a bare 32-character hex value the honest
answer is 189 types, and no amount of examining the value can give more
information. MD5, MD5(SHA1(pass)) and MD5 iterated twice all produce 32 hex
characters. Only computing separates them.

**It does not rank by likelihood.** Types come back cheapest-first. Cost can be
measured; likelihood cannot. Any estimate of it would have to be learned from
lists of already-solved hashes, and those record what people went looking for,
not what is out there.  It is very tempting to say a certain hash form *must
be* an exact type, but `mdxfind`, using the output from bertillon, proves that
is not the case.

**A tier is a budget, not a verdict.** Types outside the selected tier are
untested, not ruled out, and the count is printed on every run.

**A verified pair is not a cracked password record.** Output is type
identification. Found-lines come from `hashpipe` and `mdxfind`, which own that
format.

---

## A list you know nothing about

The common case: a list arrived, nothing is solved, and you need to know what
to run.

    $ bertillon salted.txt
    bertillon: salted.txt -- 1000 lines, 1000 sampled, 1 different form

    bertillon: 66 types to try (32-char hex + salt, easy tier).
               widen: --tier medium +12, --truncation +531.  962 not tried, -v for why.
    hash:salt	e31,e183,e187,e209,e210,e224,e260,e261,e263,e282,e283,e286,e347,...

Standard output carries nothing but the selection, so it can be directly used
by other programs. The summary goes to standard error.

An unsalted list reduces differently:

    $ bertillon unsalted.txt
    bertillon: unsalted.txt -- 2000 lines, 2000 sampled, 1 different form

    bertillon: 189 types to try (32-char hex, easy tier).
               widen: --tier medium +61, --tier hard +1, --truncation +531.  839 not tried, -v for why.

Supplying a salt CUTS the set, from 189 to 66, because an algorithm that does
not use a salt cannot consume one.

In both cases, there are ways to have bertillon widen the search.  This should
be used when you *know* that the lower cost types will not (or have not)
produced results. Using the medium tier, for example, would result in 12
additional algorithms being made available for the salted.txt case, and 61 for
the unsalted.txt case. The hard tier brings in even more expensive algorithms;
only one is available in the unsalted.txt example, and none for the salted.txt
(because no more expensive algorithms matched the form of the input hash/salt
combination, as they were already present in the medium tier). Different hash
lists may produce more, or fewer options for the medium and hard tiers,
depending on which algorithms could produce the form of the hashes in those
lists.

Nothing can be assured, though; bertillon can only provide the algorithms that
may be in use for the supplied hash format, from the ones it knows.

## The same form, with nothing solvable

`noise.txt` has the same form as `salted.txt` -- the same length, the same
character set, the same two fields -- and no password behind it in any
wordlist. It is a smaller file with an identical form, and it reduces
identically:

    salted.txt (100% solvable) : 66 types
    noise.txt  (0%  solvable)  : 66 types    IDENTICAL

Reading the form of a value does not depend on solvability, and it does not
degrade as a list gets harder. Run both files yourself and compare.

## A value with its plaintext

When a plaintext is present, verification answers outright and no candidate set
is printed:

    $ bertillon < solved.txt
    614ddb184f43854169db7941decabc42:%!!((^
    VERIFIED	e1	MD5

    bertillon: SOLVED as hash:plaintext -- 1 type(s) verified of 824 tried.

## When several types verify

    $ bertillon < collision.txt
    459c5c282e5e6c017f20cbdcc488b507c100bbaa:0000009611
    VERIFIED	e8	SHA1
    VERIFIED	e21	AICH
    VERIFIED	e732	SHA1UTF7

    bertillon: SOLVED as hash:plaintext -- 3 type(s) verified of 824 tried.
      3 types produce identical hash results for this input.

All three are genuine -- `hashpipe -m AICH` verifies the same pair. AICH over a
single small block IS SHA-1. `hashpipe` reports only the first match, because a
cracker needs one answer; bertillon reports every one.

You need to **select** the best hash type, based on your knowledge of where the
list came from and anything else you know about it.

## Verifying a file of pairs

`--gate` verifies `hash:plaintext` and `hash:salt:plaintext` lines:

    $ bertillon --gate gate.txt
    bertillon gate: 5 line(s), 1 carrying a work factor
    bertillon gate: worst is bcrypt cost 12, est 0.17 s -> -L 10
    bertillon gate: if hashpipe now reports that no registered type
    bertillon gate: handled a format, the cost limit is not the reason.
    MD5SALT df9e335fc1cdd7c5c38824a15b1e0acd:ox5:000015
    MD5SALT b90b6311b4886c473f2c02d6b924bb08:ytp:00007584
    MD5SALT c72c0bbd2f813eabfc6971693c01fcc9:1d2:)(*&^
    MD5SALT 54a3aab52006ebd823b4917fd25927f9:a27:00001844
    BCRYPT $2a$12$3xrp7EKdP0ggzfNg32UA2.nZjaC84YvQbcNBvT6/lC04oOimp8rSm:!!!!!!!!!

**What it does.** Every line is tried against every registered type, and the
types that reproduce the hash are named.

**Why run it.** If you have even a handful of solved pairs, this identifies
the list outright, which makes narrowing candidates unnecessary.

**Reading the output.** A line with a type in front of it verified. A line
echoed back on its own did not:

    $ bertillon --gate g2.txt
    bertillon gate: 1 line(s), 0 carrying a work factor
    bertillon gate: no parsed work factor -> -L 10
    bertillon gate: if hashpipe now reports that no registered type
    bertillon gate: handled a format, the cost limit is not the reason.
    df9e335fc1cdd7c5c38824a15b1e0acd:ox5:wrongpassword

**When a line comes back bare**, there are three causes and the output does not indicate which it may be:

    the password is wrong for that hash
    the fields are in the wrong order
    the hash algorithm is not registered in this build

Work through them in that order. For the last, an `hx` expression and a
`userdef` entry can add a new hash algorithm; a wider search will not find it.

**A verified line does not prove your fields are right.** Swap the salt and the
password in a line that verified, and it verifies again -- as a different type:

    $ bertillon --gate g3.txt
    bertillon gate: 1 line(s), 0 carrying a work factor
    bertillon gate: no parsed work factor -> -L 10
    bertillon gate: if hashpipe now reports that no registered type
    bertillon gate: handled a format, the cost limit is not the reason.
    MD5-MD5SALT-PASSx01 df9e335fc1cdd7c5c38824a15b1e0acd:000015:ox5

Same hash, same two values, fields exchanged. Only you can say which one
describes the system the list came from, and this can be difficult with limited
information.

**About the `-L` line.** hashpipe will not verify an algorithm that would take too long, and
reports that the same way it reports a format it does not know -- so a slow
type can look like a missing one. Formats like bcrypt carry their cost in the
hash itself, so bertillon reads it and raises the limit before starting. That
is what the line reports, and it is why a "nothing handled this format" message
after `--gate` can be believed.  Certain hash types, like CMIYC (e1001), are
very, very slow by design. Bertillon understands this, and ensures that they
can be verified.

## Reading the full summary

`-v` gives the breakdown behind the two-line default:

    $ bertillon -v salted.txt
    bertillon: derived digest lengths (bytes): [8, 16, 20, 24, 28, 32, 40, 48, 64]
    bertillon: 1028 type(s), 22 with an uncertain parse
    bertillon: salted.txt -- 1000 lines, 1000 sampled, 1 different form

    bertillon: field 2 is not the plaintext -- 824 types tried, none matched.

    bertillon: 66 types to try (32-char hex + salt, easy tier).
               widen: --tier medium +12, --truncation +531.  962 not tried:

      a negative result covers these 66 types and no others.

      not tried:
          696  cannot produce a 32-character hex form
               of those, 531 have a LONGER digest and would apply if these
               values have been cut short (--truncation)
          251  take no salt, and one was supplied
           12  cost more than the easy tier allows
            3  emit the other letter case

      cost tiers are approximate: without --table, types that
      combine salts in pairs are costed as if they did not.
      --table hid-shape.tsv supplies that.

The four figures sum to 962, and each describes a different kind of exclusion.
"Cannot produce this form" is arithmetic and says nothing about any algorithm.
"Take no salt" is about THIS input, and the same types apply to a different
one. "Cost more than the tier allows" is deferred, not decided. Keeping them
apart is what lets a negative result be read: the 66 tried and the 962 untried
carry different weight when a run comes back empty.

## What is in a file

    $ bertillon -f mixed.txt 2>/dev/null
          220  digest|cipher? 16 bytes: digest length AND 16-byte block multiple -- arithmetic cannot separate them
          100  digest         20 bytes, a digest length
           50  delimited      2 field(s), first 32 chars, sep ':'
            5  not-hash       odd hex length 31 -- truncated or mis-copied

Each distinct answer once, commonest first. The rare lines are the interesting
ones -- here, five truncated values that would otherwise match nothing and look
like a wordlist problem.

`digest|cipher?` is not indecision. 16 bytes is a real digest length AND a
whole number of cipher blocks, and bertillon cannot choose. An 80-character hex
family that turned out to be DES-EDE2-CBC ciphertext cannot be told apart from
RMD320, a registered 80-character digest type, by looking at it; what separated
them was a solved hash, which bertillon cannot do on its own.

## Feeding another tool

    -e enum      type numbers, as mdxfind -M takes them (the default)
    -e mdx       a ready mdxfind -h selection
    -e hashcat   hashcat -m modes, one per line
    -e john      John format names, one per line
    -e cmd       an mdxfind command line, with HASHES and WORDLIST left
                 for you to fill in

`-e hashcat` prints one mode per line and not a comma list, because hashcat's
`-m` takes exactly one mode per run where mdxfind's takes a set. The same
answer is one argument for one tool and a sequence of runs for the other.

**Those two formats cannot say everything.** hashcat and John name far fewer
constructions than mdxfind does, and the count they cannot express is reported:

    $ bertillon -t e -e h salted.txt
    bertillon: 66 types to try (32-char hex + salt, easy tier).
               OF THOSE, 47 of 66 have no hashcat mode and are NOT in
               the list above. Covering what was printed does not cover
               the reduction.

That run prints **25 modes** -- which come from 19 of the 66 types, because a
type can map to several modes at once. The mode count therefore runs ahead of
the type count while covering less of the reduction, and the remaining 47
constructions need a tool that can name them.

## What the whole list says

Some things a single line cannot settle. `-p` reads the file and reports what
the records say collectively:

    $ bertillon -p sitewide.txt
      SALT REUSE
        records         : 100 (those whose salt is the usual 23 bytes)
        distinct salts  : 1
        most common     : 100 record(s), 100.0000%
          xKq7%$tR_2026_siteWide!
        -> ONE SALT FOR THE WHOLE SITE. Every record shares it, so the
           boundary between salt and password is known, and that single
           fact settles a reading the individual lines cannot.

Agreement across a whole file is the strongest evidence available. A hash taken
over one concatenated string does not record where the salt ended and the
password began, so a single line has as many readings as it has character
positions and nothing to choose between them. One salt on every record chooses.

`-p` also reports damage in the file, whether an odd field count is real
trouble or just salts that happen to contain a colon, and whether a salt has
been folded into the password field -- which verifies perfectly and is
therefore invisible to verification.

---

## Reproducing the examples

    tools/make-example-set.py <wordlist> <outdir>

The files are built to the same recipe as the published benchmark suite at
www.mdxfind.com (see `docs/BENCHMARK.md` in the mdxfind distribution): the
salted files are `MD5(` *hex of* `MD5($pass)` ` + salt)` with 3-character salts
-- the hex digest concatenated with the salt, not the raw 16 bytes -- which is
that suite's `saltfull.txt` construction and internal type **e31**. Any example
here scales to the published 14.3M-line files by changing the filename.

Every generated line is offered to hashpipe and kept only if hashpipe labels it
as intended, because **the type names are not a reliable guide to the
construction.** `MD5SALT` is `md5(md5($pass) . $salt)`. The construction most
people would guess from that name, `md5($pass . $salt)`, is `MD5PASSSALT`
(e373), and `md5($salt . $pass)` is `MD5USERPASS`.

---

## Do not judge a hash by its cover

Consider the two hashes:

    $2a$05$RndSa1tRndSa1tRndSa1tueCWqCRvcbXYTH4wS03p4Cy1gM8JZuW2:password
    $2a$05$RndSa1tRndSa1tRndSa1tubsI60Xla4qtTMYupKg5lJMMpc4qAUKm:password

Clearly, this must be wrong, since two bcrypt hashes, with the same salt and
the same cost, and the same password *must* give the same result -- right? But
this is the result of two different hash algorithms producing *similar* looking
hashes. bertillon knows the difference:

    VERIFIED	e450	BCRYPT
    VERIFIED	e451	BCRYPTMD5

`BCRYPTMD5` is bcrypt over the MD5 of the password rather than over the
password. Nothing in the stored form even hints at this, and both are `$2a$` at
cost 05 with the same salt.

**The cover misleads in the other direction too.** These four are the same
password, the same salt and the same algorithm, differing only in the version
byte:

    $2a$05$i/bXB/oO3QurEv2Tlx0WSuMF4fpAxSyOECrnh1fBUN2J3.QKXpRoO:password
    $2b$05$i/bXB/oO3QurEv2Tlx0WSuMF4fpAxSyOECrnh1fBUN2J3.QKXpRoO:password
    $2x$05$i/bXB/oO3QurEv2Tlx0WSuMF4fpAxSyOECrnh1fBUN2J3.QKXpRoO:password
    $2y$05$i/bXB/oO3QurEv2Tlx0WSuMF4fpAxSyOECrnh1fBUN2J3.QKXpRoO:password

    VERIFIED	e450	BCRYPT        (all four)

`$2a$`, `$2b$`, `$2x$` and `$2y$` are bcrypt revisions, not different
algorithms. PHP's `password_hash()` writes `$2y$` and most current libraries
write `$2b$`, so a prefix may tell you which implementation wrote the value but
nothing about what was hashed.

**And a form you are sure you recognise may be something else entirely.** A
32-character hex value is the one everybody reads on sight:

    $ echo '664fb595fdd4304eaec39789e22c8b96:1953' | bertillon
    VERIFIED	e369	NTLM
    VERIFIED	e496	MD4UTF16
    VERIFIED	e786	NTLMH

    bertillon: SOLVED as hash:plaintext -- 3 type(s) verified of 824 tried.

Not MD5 at all. The three names are one algorithm, MD4 over a UTF-16LE
expansion, offered three encodings: `MD4UTF16` converts, `NTLMH` also tries
hashcat's zero-extend, and `NTLM` adds CP1251 and CP1252. They agree here only
because `1953` is ASCII. Give them a non-ASCII password and the encodings part
company:

    $ printf 'caf\xc3\xa9\n' > pw.txt
    $ mdxfind -f /dev/null -z -M e369,e496,e786 pw.txt
    MD4UTF16x01 b1db12409c00d1fc586fc48ecadc36a1:$HEX[636166c3a9]
    NTLMHx01 b1db12409c00d1fc586fc48ecadc36a1:$HEX[636166c3a9]
    NTLMHx01 79ce465afc649cffc4dea9962775bbbc:$HEX[636166c3a9]
    NTLMx01 b1db12409c00d1fc586fc48ecadc36a1:$HEX[636166c3a9]
    NTLMx01 79ce465afc649cffc4dea9962775bbbc:$HEX[636166c383c2a9]
    NTLMx01 3cea4c283475f27ec56c2cf0d51ba10a:$HEX[636166d093c2a9]

One digest for ASCII, three for `café`. The `$HEX[]` forms show why: `c3a9`
stays as written under the iconv conversion, becomes `c383c2a9` when each byte
is treated as a character, and `d093c2a9` under CP1251. On a non-ASCII password
the three behave as three different algorithms.

`NTLM` emits three candidate plaintexts per word, so a run against a non-ASCII
list returns more result lines than it was given words.

---

## What this is for

Alphonse Bertillon, in 1879, introduced anthropometry. He built the first
systematic way to identify a person from a card of measurements. It worked by
narrowing a field of candidates, never by asserting an identity. It was correct
as far as it went, insufficient on its own, and superseded the moment a better
discriminator arrived. Fingerprinting replaced anthropometry because it
discriminated: it told two people apart where the measurements could not.

Bertillon sits at that step. It measures what can be measured, narrows the
field, and hands you a set of things to try. It does not know what your hash
is, and on a bare 32-character value it cannot: the 189 types it returns all
produce 32 hex characters and no examination of the value can further identify
it. What separates them is computing, or a plaintext, or knowing where the list
came from.

It is an **aid to the process of discovery**. Use it to see what your list is
made of before you commit a machine to it, to separate what is worth trying
from what cannot work, and to know afterwards what a negative result actually
covered. The judgement stays yours, but you have *informed* judgement.

Bertillon is pronounced in the French way: **Bear-tea-YAWN**, [bɛʁ.ti.jɔ̃]. The
`ll` is a Y and not an L, and the final n is not sounded -- it nasalises the
vowel, so stop just before your tongue touches the roof of your mouth.
