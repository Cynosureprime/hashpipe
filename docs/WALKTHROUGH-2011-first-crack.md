# From an unknown pile to a first crack: CMIYC 2011

You have `received.txt`: **121,614 hashes, one per line, no labels, no
documentation.**

---

## Why not just start cracking

A list of hashes with no information is difficult to deal with.  What kinds of
hashes they are, how best to attempt to crack them, which tools to use are all
basic questions that you need to know, before starting.  Bertillon is the tool
that helps with understanding each of these issues.  Traditionally, you would
need to be able to recognize and understand many different hash types, in order
to effectively do this; for many of you this is second nature.  You *know* that
a hex-32 hash is MD5.  And that a hex-40 hash is SHA1.  As it turns out,
though, that information you *know* can sometimes lead you down the wrong path.

It is true that `mdxfind` can solve many different hash types, with one pass
through a list, and that has fixed the problem for many people.  But not all
people have or can use `mdxfind`, and not all hashes read easily and simply
into `mdxfind`.  Knowing what *kind* of hashes are possible for a given hash
format is very helpful, and can remove wasted time and effort.

Bertillon finds this out, easily.  So the first job is to find out what kinds
of hashes are present, cheaply enough that being wrong costs nothing.

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

Under a second to qualify 120,000 unknown hashes.

**Five of the fifteen groups already identify their format.** `$2a$` is bcrypt,
`$1$` is md5crypt, `$P$` is phpass, `{SSHA}` is salted SHA-1 in LDAP, `$PHPS$`
is a PHP forum format. Three more are identified by their form: a 13-character
crypt string is descrypt, a 20-character one is bsdicrypt, a 94-character
`0x0100` value is MSSQL. The five tagged groups are 26,512 hashes, 22% of the
file; with the three identified by form it is 45,968, or 38%, and that still
leaves a gap for the rest of the list.

**The rest is grouped rather than identified.** 35,438 bare 32-character values
are one job, 17,138 bare 40-character values are a second, and they belong in
separate runs, depending on what tools are used.  `mdxfind` can have both kinds
in the same file, but hashcat objects to differing lengths, so you can choose
to separate them, or not.

**The 30-byte line is worth a second look.** No algorithm produces a 30-byte
digest, so each of those 4,892 values is a digest with something concatenated
to it, and the tool enumerates the ways that could be true. One is `d20+s10`, a
20-byte digest with a 10-byte tail. A 20-byte digest is SHA-1, and SHA-1
followed by a 10-byte salt is Oracle 11g, which stores `sha1(password+salt) .
salt`.

**What it does not tell you** is what the 35,438 bare 32-character values are.
They could be MD5, NTLM, MD4, or any of a hundred constructions that end in 32
hex characters, and no further examination of the bare hashes can help.

### The decision this actually makes

`mdxfind` has two ways to read hashes: just hex, ignoring everything else on
the line, and a more structured form:

    -f   bare hex only -- DISCARDS EVERYTHING AFTER THE FIRST COLON
    -F   anything else

The census settles the choice per group. `digest` goes to `-f`. `tagged`,
`prefix`, `delimited` and `composite` go to `-F`. Sent to `-f`, the 4,905
hashes in a `delimited` group would load as bare digests with their salts
stripped off, match nothing, and exit 0.

## Step 2 — pick the cheapest method to start

The bulk of the hash types positively identify as harder hashes, including
salted and bcrypt-style hashes.  These are known-expensive, even for relatively
small wordlists.  They are also identifiable *because* they are expensive: a
format that carries a salt and a cost has to have them in the stored value.
The largest groups, however, are the bare 32-character and 40-character hashes.
We do not know what actual hash type is present in these.

The 35,438 bare 32-character values are the largest group, and there are many
hash algorithms that result in 32-character hashes.  Starting with the easy
hash types makes sense, and bertillon makes this trivial.  In this context,
easy also means fast to compute.

    $ bertillon -t easy bare32.txt
    bertillon: 189 types to try (32-char hex, easy tier).
               widen: --tier medium +61, --tier hard +1, --truncation +531.
               839 not tried, -v for why.

189 types out of 1,028, which is a 5x cut rather than a 100x one. Every one of
those 189 produces 32 lowercase hex characters and nothing in the values tells
them apart. The cut came entirely from excluding what cannot match — wrong
digest length, wrong letter case, types needing a salt this input does not
supply.

The `839 not tried` breaks down: 531 have longer digests and apply only if
these values were truncated, and 251 need a salt. The tool keeps those reasons
apart, because "we tried everything" and "we tried everything affordable that
could match" are different claims.

## Step 3 — the first run

    $ mdxfind -m "$(bertillon -t easy -e enum bare32.txt)" -i 2 \
              -f bare32.txt 10kpass.txt > run32.res

    bare32.txt: 35438 hashes, 0 salts, 0 users loaded
    real  0m2.073s

**Read the load receipt before the results.** `35438 hashes` confirms the file
was understood; `0 hashes` there tells you the pipeline is broken, not that the
result is negative.

Two seconds, 10,001 candidates, 51 result lines.

## Step 4 — look at the results

    $ awk '{print $1}' run32.res | sort | uniq -c | sort -rn
      12 NTLMx01
      12 NTLMHx01
      12 MD4UTF16x01
       8 MD5x01
       4 MD5SHA1x01
       3 MD5CAPSHA1x01

**The first three lines are the same twelve hashes**, as there are different NTLM implementations in `mdxfind`, and each does different things depending on the input words.  For ASCII, they are the same — so we know that each of the found words is pure ASCII.  NTLMH implements the `hashcat` zero-extend-character method, and MD4UTF16 does not do the CP1252/CP1251 support that NTLM does.  Which one to use depends on the list, and human judgement is required. Expect this, and understand that different type labels can produce the same hash.

The yield is 24 distinct hashes out of 35,438. The plaintexts are the reason to
keep reading:

    NTLM:  1953 1971 1985 1987 1989 1999 2001 2004 2005  cheater fiesta money
    MD5:   1966 1990 1994  danger getit history loveme news

Nine of twelve, and three of eight, are four-digit years.

## Step 5 — treat the anomaly as a class

Every year from 1900 to 2030 is **131 candidates**, and testing them costs
about a second, so test them.

    $ seq 1900 2030 > years.txt
    $ mdxfind -m "$SEL" -i 2 -f bare32.txt years.txt > runyears.res
    real  0m1.047s

    10k wordlist      24 hashes from 10,001 candidates     2.4 per 1000
    years 1900-2030   16 hashes from    131 candidates   122.1 per 1000

**Fifty-one times the yield per candidate**, so the hypothesis holds.

It produced only **two** hashes the wordlist had not already found, because the
10k list already contained most bare years and the class was nearly exhausted
before it was tested. You know that now for the price of one second, and you
did not have to assume it.

## Step 6 — push the class until it stops producing hits

If bare years are in use, decorated years are the next guess, and they are
exactly what a small wordlist will not contain. 131 years against 18 affixes is
2,358 candidates:

    $ mdxfind -m "$SEL" -i 2 -f bare32.txt years2.txt > runy2.res
    real  0m1.050s
      hashes: 16     new: 0

**Zero.** Not one hash in this file uses a year with anything attached to it.

Write that down. It cost a second to establish and somebody will otherwise
re-run it next pass:

> **2011 bare-32 set:** years appear bare. Year plus affix (18 variants, 2,358
> candidates) yields nothing new. Do not re-run.

## Step 7 — close the loop

Feed anything you cracked back through the gate. With a plaintext in hand the
identification is settled:

    $ bertillon --gate founds.txt
    MD5x01  3683af9d6f6c06acee72992f2977f67e:1966
    NTLMx01 664fb595fdd4304eaec39789e22c8b96:1953

The 32-character group holds at least two types mixed together in one file, and
that is now a computed result rather than a guess.

---

## Where you are

After about six seconds of compute:

- fifteen distinct forms identified, eight of them named outright
- the input channel settled for every group, so no run will silently mutilate
its own input
- the largest group narrowed to 189 candidate types with a stated basis
- 26 hashes recovered
- one real pattern found (bare years), confirmed at 51x yield, and its class
exhausted
- one elimination recorded

And the list is now qualified, but certainly not all solved:

- 121,588 hashes are still unsolved
- the 4,892-hash composite group has a *layout* hypothesis, not a type
- the two large bare groups are still one job each, not yet split by type
- nothing has been learned about bcrypt, descrypt, phpass or the LDAP hashes
beyond what their tags announced

## Where this tool stops

Step 5 was a person looking at twelve words and noticing they were years. No
part of that came from bertillon, and no part of it could have. The tool
narrowed 1,028 types to 189 and told you which channel to use; the yield came
from reading what came back.

Once you have plaintexts the work moves to `pack2 cgrams` for structure,
`procrule -G` for the rules that generate them, and `rling -q` for the shape of
what you already hold. Put bertillon down at that point. hashpipe still may be
useful as part of the process, to validate the finds. Bertillon itself has
nothing more to add, and the interesting part of the contest is solving the
rest of the hashes.
