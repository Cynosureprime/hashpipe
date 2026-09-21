# Where bertillon fits in working an unknown list

**2026-09-21.** This is a narrow document. It covers the one job bertillon does
inside the discovery loop and, more importantly, the several jobs it does not.

**It does not restate the methodology of working a contest.** That is a larger
subject and a better-studied one, and this document assumes it rather than
competing with it. Two things from it are worth stating here because everything
below depends on them: the cheapest moves beat compute -- simply establishing
what a hash list actually *is* has recovered 637,082 hashes in twenty minutes --
and when a tool returns zero, the first question is whether it was capable of
returning anything else.

---

## The loop, and the one step this is for

    cheap run -> read the plaintexts, not the count -> recover the generator
              -> exhaust it -> repeat

bertillon sits **before** the first cheap run and **after** the first crack. It
does not generate candidates, does not crack anything, and has no opinion about
wordlists. Used at those two points it is worth minutes; used anywhere else it
is a distraction.

The reason it earns those minutes is narrow: a run that finds nothing and a run
that could never have found anything look identical. bertillon is a cheap check
on the second.

---

## Before the first run: what is this list made of

### The channel decision

The costliest thing to get wrong in mdxfind is the input channel, because
getting it wrong exits 0 and finds nothing:

    -f   bare hex digests only. DISCARDS EVERYTHING AFTER THE FIRST COLON.
    -F   anything else: $id$salt$hash, base64, hash:salt, {SSHA}...

`bertillon -f` answers that directly, per distinct form with a count:

    $ bertillon -f list.txt
      18668  delimited      2 field(s), first 32 chars, sep ':'
        657  delimited      3 field(s), first 32 chars, sep ':'
        643  delimited      3 field(s), first 32 chars, sep '$'

    verdict          channel
    digest           -f
    delimited        -F      (a colon here is a field, and -f would eat it)
    tagged           -F
    not-hash         neither -- look at the line before anything else

The counts matter as much as the classes. A list that is 96% one form and 4%
another is two jobs, and the 4% is usually the interesting one.

### Is it even one list

`bertillon -p` reads the whole file and reports what the records say
collectively -- intake damage, whether an odd field count is real trouble or
just salts containing a separator, and how far salts are reused.

Three of its findings change what you do next:

**Damage.** A CRLF list read against LF candidates matches nothing, for the
whole file, and presents as a wrong wordlist. This is the first thing to rule
out, not the last.

**One salt for the whole site.** If a single string is the salt on every record,
the field boundary is known and a whole class of ambiguity disappears. It also
means recovering one salt unlocks the installation.

**A salt folded into the password field.** Records whose "password" ends in the
same long run on every line are filed under the wrong split. They verify
perfectly -- which is exactly why verification cannot catch it -- and their
recorded plaintexts are useless as candidates because every one carries the
salt.

### Narrowing the type selection

`-h .` selects 22 types, not all of them. `-m e1-e999` is the real everything.
Between those, bertillon gives a selection derived from the form:

    $ bertillon -t e -e m list.txt
    hash:salt	-h '^(MD5SALT|MD5HEXSALT|HAV128HEXSALT|...)$'

Two cautions, both of which matter more than the reduction itself.

**The reduction is small on bare hex and that is honest.** A bare 32-character
value gives 189 types at the easy tier. They all produce 32 hex characters and
nothing about the value separates them. The large wins are on structured input,
where a tag cuts 1028 to a handful.

**Types are cheap, runs are expensive.** That is the standing economics and this
tool does not change it. Narrowing is worth doing when it removes types that
*cannot* match -- wrong digest length, wrong character case, an operand the
input does not supply -- and not worth doing to feel precise. One run over a
mixed pile still beats several runs over neat ones.

The place narrowing genuinely pays is the salted trap: with no `-s`, salted
types consume the hash list itself as salt candidates, and a 1,671-hash list
once generated 903,952 salts and effectively stalled. `bertillon -v` reports how
many types in a selection want a salt the input does not supply:

      not tried:
          251  take no salt, and one was supplied
           12  cost more than the easy tier allows

---

## After the first crack: identify, then re-narrow

The moment anything cracks, the cheapest move available is to stop guessing.

    $ bertillon --gate found.txt
    MD5SALT df9e335fc1cdd7c5c38824a15b1e0acd:ox5:000015

One verified pair identifies the list outright, and no candidate set is worth
anything next to it. The gate computes its own time limit from each line's work
factor first, because hashpipe reports a type skipped for cost and a format
nothing handles with the same message.

Three things to know about reading it:

**A bare line did not verify**, and the output does not say why. The causes, in
the order worth checking: the password is wrong, the fields are in the wrong
order, the construction is not registered. For the last, write it in `hx` and
add a `userdef` entry -- a wider search will not find it.

**A verified line does not prove your fields are right.** Swap the salt and the
password on a line that verified and it verifies again, as a different type.
Both readings are true statements about the bytes.

**Several types verifying is the normal case, not an error.** SHA1, AICH and
SHA1UTF7 all verify the same pair; AICH over one small block *is* SHA-1. Choose
using what you know about where the list came from. Nothing in the line chooses
for you.

---

## What this does not do

**It does not rank by likelihood, and will not.** The measurements: 77 of the
78 salted 32-character types
accept every salt length tried, so salt length does not narrow the answer; the
only labelled corpus available is one file per type; and a corpus labelled by
what solved it measures the search rather than the population. A list published
across three modes, every record verifying under its claimed one and all three a
single algorithm misfiled, is the counterexample.

**It does not know the construction from the name.** `MD5SALT` is
`md5(md5($pass) . $salt)`. The thing you would guess from that name,
`md5($pass . $salt)`, is `MD5PASSSALT`. `hx.8` is the authority on what each
type computes; a control test built on a guessed definition proves nothing.

**It does not read the filename, the challenge text, or the organiser's
intent** -- and those beat it routinely. An expensive KDF is evidence the
passphrase is meant to be derived rather than searched. An 11-character token in
a filename is a video ID.

**It does not profile plaintexts.** Once anything cracks, the yield is in
reading what came back -- `pack2 cgrams` for the segmentation, `procrule -G` for
the rules, `rling -q` for the shape. bertillon has nothing to add there and
should be put down.

---

## A sequence

    bertillon -f list.txt              what forms are in here; which channel
    bertillon -p list.txt              damage, salt reuse, is the split right
    bertillon -t e -e m list.txt       a selection for the first cheap run
    < run, with a canary planted FIRST in the candidate file >
    bertillon --gate first.founds      what it actually is
    < now stop using bertillon and go read the plaintexts >

The last line is the point. This is an aid to the part of the work that happens
before you know anything, and the part of the work that matters happens after.
