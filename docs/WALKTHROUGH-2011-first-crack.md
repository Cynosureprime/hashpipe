# From an unknown pile to a first crack: CMIYC 2011

You have `received.txt`: **121,614 hashes, one per line, no labels, no
documentation.** That is the whole of what you know.

---

## Why not just start cracking

Because a run that finds nothing and a run that *could never have found
anything* produce the same output: zero, exit 0, no diagnostic. Every expensive
mistake in this work has that shape. A salted hash read on the wrong input
channel loses its salt and matches nothing. A list of 60-character hashes fed to
a 32-character type finds nothing. A CRLF file read against LF candidates finds
nothing, for the entire file.

So the first job is not to crack anything. It is to find out what you are
holding, cheaply enough that it costs nothing if you are wrong.

# 6 seconds to Knowledge

## Step 1 — what is in here

    $ bertillon -f received.txt
        35438  digest|cipher? 16 bytes: digest length AND 16-byte block multiple
        17138  digest         20 bytes, a digest length
         9815  tagged         tag $PHPS$
         9803  tagged         tag {SSHA}
         8635  prefix         mssql (94 chars)
         7362  prefix         descrypt (13 chars)
         4905  delimited      2 field(s), first 32 chars, sep '$'
         4903  delimited      4 field(s), first 32 chars, sep '$'
         4900  digest|cipher? 64 bytes: digest length AND 16-byte block multiple
         4892  composite      30 bytes, no algorithm emits this;
                              layouts: d8+s22 d16+s14 d20+s10 d24+s6 d28+s2
         3470  delimited      2 field(s), first 22 chars, sep '$'
         3459  prefix         bsdicrypt (20 chars)
         3447  tagged         tag $1$
         2300  tagged         tag $P$
         1147  tagged         tag $2a$

Under a second to qualify 120,000 unknown hashes. Read what that bought.

**Six of the fifteen groups name their own format.** `$2a$` is bcrypt, `$1$` is
md5crypt, `$P$` is phpass, `{SSHA}` is salted SHA-1 in LDAP, `$PHPS$` is a PHP
forum format. That is 26,512 hashes -- 22% of the file -- where the
identification problem does not exist at all. Two more are named by shape alone:
a 13-character crypt string is descrypt, a 94-character `0x0100` value is MSSQL.

**The rest is grouped, not identified**, and the grouping is the useful part.
35,438 bare 32-character values are one job. 17,138 bare 40-character values are
another. They are not the same job and should not be in the same run.

**One line is doing more work than it looks.** The 4,892 hashes at 30 bytes: no
algorithm produces a 30-byte digest, so this is a digest with something
concatenated to it, and the tool enumerates the ways that could be true. One of
them is `d20+s10` -- a 20-byte digest with a 10-byte tail. A 20-byte digest is
SHA-1. That is Oracle 11g, which stores `sha1(password+salt) . salt`, and it has
been described correctly without the word "Oracle" appearing anywhere.

**What it does not tell you.** It has no idea what the 35,438 bare 32-character
values are. They could be MD5, NTLM, MD4, or any of a hundred constructions that
end in 32 hex characters. That is not a weakness to be worked around; it is the
truth about a 32-character hex string, and a tool that claimed otherwise would
be lying.

### The decision this actually makes

mdxfind has two input channels and choosing wrong is silent:

    -f   bare hex only -- DISCARDS EVERYTHING AFTER THE FIRST COLON
    -F   anything else

The census answers it per group. `digest` goes to `-f`. `tagged`, `delimited`
and `composite` go to `-F`, and a `delimited` group in particular would be
quietly mutilated by `-f`: 4,905 hashes whose salt is after a separator would
load as bare digests, match nothing, and exit 0.

## Step 2 — pick the cheapest door

Not the most interesting group: the cheapest. bcrypt at cost 5 is 1,147 hashes
that will take real time per candidate. The 35,438 bare 32-character values are
the fastest thing in the file and the largest group. Start there.

    $ bertillon -t easy bare32.txt
    bertillon: 189 types to try (32-char hex, easy tier).
               widen: --tier medium +61, --tier hard +1, --truncation +531.
               839 not tried, -v for why.

189 types, out of 1,028. That is a 5x cut and not a 100x one, and it is worth
being clear about why: every one of those 189 produces 32 lowercase hex
characters, and nothing about the value distinguishes them. The cut came from
excluding what *cannot* match -- wrong digest length, wrong letter case, types
that need a salt this input does not supply -- not from guessing what is likely.

The `839 not tried` is not a rounding error. 531 of them have longer digests and
would apply only if these values had been truncated; 251 need a salt. Those are
different reasons and the tool keeps them apart, because "we tried everything"
and "we tried everything affordable that could possibly match" are different
claims.

## Step 3 — the first run

    $ mdxfind -m "$(bertillon -t easy -e enum bare32.txt)" -i 2 \
              -f bare32.txt 10kpass.txt > run32.res

    bare32.txt: 35438 hashes, 0 salts, 0 users loaded
    real  0m2.073s

**Read the load receipt before the results.** `35438 hashes` is the confirmation
that the file was understood. `0 hashes` there is the whole diagnosis, and it is
the difference between a negative result and a broken pipeline.

Two seconds, 10,001 candidates, 51 result lines.

## Step 4 — the count is the least interesting number

    $ awk '{print $1}' run32.res | sort | uniq -c | sort -rn
      12 NTLMx01
      12 NTLMHx01
      12 MD4UTF16x01
       8 MD5x01
       4 MD5SHA1x01
       3 MD5CAPSHA1x01

**The first three lines are the same twelve hashes.** Verified: the sorted hash
lists under all three labels have identical checksums. NTLM *is*
`md4(utf16le(password))`, so a tool that implements both reports both, and
neither is wrong. This is the normal condition, not an error -- and it is why
"it verified" is not by itself an identification.

24 distinct hashes out of 35,438. As a yield that is nothing. As information it
is the most valuable thing you have, because of what the plaintexts are:

    NTLM:  1953 1971 1985 1987 1989 1999 2001 2004 2005  cheater fiesta money
    MD5:   1966 1990 1994  danger getit history loveme news

Nine of twelve, and three of eight, are four-digit years.

## Step 5 — treat the anomaly as a class

A year is not a find. It is a hypothesis about a population, and the population
is tiny: every year from 1900 to 2030 is **131 candidates**. Testing it costs a
second, so there is no reason to think about it rather than do it.

    $ seq 1900 2030 > years.txt
    $ mdxfind -m "$SEL" -i 2 -f bare32.txt years.txt > runyears.res
    real  0m1.047s

    10k wordlist      24 hashes from 10,001 candidates     2.4 per 1000
    years 1900-2030   16 hashes from    131 candidates   122.1 per 1000

**Fifty-one times the yield per candidate.** The hypothesis was right.

And it produced **two** hashes the wordlist had not already found. The 10k list
already contained most bare years, so the class was nearly exhausted before it
was tested. That is not a disappointing result -- it is the result, and it is
only visible because the test was run rather than assumed.

## Step 6 — push the class until it stops giving

If bare years are used, decorated years are the obvious next guess, and they are
exactly what a small wordlist would *not* contain. 131 years against 18 affixes,
2,358 candidates:

    $ mdxfind -m "$SEL" -i 2 -f bare32.txt years2.txt > runy2.res
    real  0m1.050s
      hashes: 16     new: 0

**Zero.** Not one hash in this file uses a year with anything attached to it.

Write that down. An elimination is worth what it costs to record, and this one
cost a second to establish and will otherwise be re-run by somebody next year:

> **2011 bare-32 set:** years appear bare. Year plus affix (18 variants, 2,358
> candidates) yields nothing new. Do not re-run.

## Step 7 — close the loop

Feed anything you cracked back through the gate. With a plaintext in hand,
identification is no longer a question:

    $ bertillon --gate founds.txt
    MD5x01  3683af9d6f6c06acee72992f2977f67e:1966
    NTLMx01 664fb595fdd4304eaec39789e22c8b96:1953

The 32-character group is not one type. It is at least two, mixed together in
one file, and that is now established by computation rather than assumed.

---

## Where you are

After about six seconds of compute:

- fifteen distinct forms identified, six of them named outright
- the input channel settled for every group, so no run will silently mutilate
  its own input
- the largest group narrowed to 189 candidate types with a stated basis
- 26 hashes recovered
- one real pattern found (bare years), confirmed at 51x yield, and its class
  exhausted
- one elimination recorded

And the honest part of the ledger:

- 121,588 hashes are still unsolved
- the 4,892-hash composite group has a *layout* hypothesis, not a type
- the two large bare groups are still one job each, not yet split by type
- nothing has been learned about bcrypt, descrypt, phpass or the LDAP hashes
  beyond what their tags announced

## Where this tool stops

Note what step 5 actually was: a person looked at twelve words and noticed they
were years. No part of that came from bertillon, and no part of it could have.
The tool narrowed 1,028 types to 189 and told you which channel to use; the
yield came from reading what came back.

That is the division of labour, and it does not change as the list gets harder.
Once you have plaintexts the work moves to `pack2 cgrams` for structure,
`procrule -G` for the rules that generate them, and `rling -q` for the shape of
what you already hold. Put bertillon down at that point. hashpipe still may be
useful as part of the process, to validate the finds. Bertillon itself has
nothing to add, and the interesting part of the contest is on the other side
of it.
