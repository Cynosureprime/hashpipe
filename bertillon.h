/*
 * bertillon.h -- hash shape measurement, reached through argv[0] from hashpipe.
 *
 * $Log: bertillon.h,v $
 * Revision 1.21  2026/09/21 21:31:29  dlr
 * the folded-salt test told a correctly laid out list it was damaged. A shared run that IS the whole last field is one value every record holds in its own column -- a site-wide salt, correctly placed -- while a shared run that is a PROPER part of a longer varying field is a salt folded into something else. Both are two-field lines, so field count cannot separate them: gating on it reported a clean hash:salt list as damaged and, once gated out, missed the real folded-salt case, which is also two fields. Now discriminated on whole-field versus proper-affix, verified against both: the synthetic site-wide list reads as correct and list 56's 52 misfiled records still report their 48-byte folded salt. Found by writing the documentation for the feature.
 *
 * Revision 1.20  2026/09/21 21:11:56  dlr
 * group lines by whether field 0 is hex, and widen the mistyped-filename guard. Both found by review. The grouping comment named three terms and the comparison used two: 50 hex and 50 non-hex values of equal length and field count reported as ONE form and reduced on whichever the sample held first, giving 189 types or 17 from the same file depending on line order. Now precomputed per line and compared on all three. The typo guard tested only for a path separator, so a bare 'saltd.txt' was reduced as a hash value with no warning and exit 0 -- the likelier typo of the two; it now also recognises common data-file extensions, and still warns rather than refuses because a stored form may contain a dot. Also stops the usage text implying --emit-table takes 35 minutes; that is the probe, and --emit-table is immediate.
 *
 * Revision 1.19  2026/09/21 17:41:17  dlr
 * short-form options. The argv[0] namespace exists so these could be chosen for this tool rather than inherited, and the commonest invocation was 26 characters of flags before the filename. -t tier, -e emit, -o only, -T truncation, -b table, -f form, -p profile, -g gate, -r reduce. Values may be given in full or by first letter, which is unambiguous because enum/mdx/hashcat/john/cmd and easy/medium/hard each have distinct initials: 'bertillon -t e -e h list.txt' is the whole of --tier easy --emit hashcat. Long forms unchanged and verified identical across all five formats and all three tiers.
 *
 * Revision 1.18  2026/09/21 16:46:03  dlr
 * --emit john, and name what each format cannot express. hashcat and John cover far less than mdxfind: for a bare 32-hex value the easy tier holds 189 types, of which 21 have a hashcat mode and 11 a portable John name. Emitting 23 numbers or 11 names with no further word invites a reader to believe the reduction was covered, so the shortfall is now reported with the count. John uses JohnMap only -- john_map.h's second table, JohnMapLocal, is config-defined dynamics whose numbering is per-machine and whose own header says they must never be used to stamp a name on a result; ten types here have an entry there and are deliberately reported as unnamed. Two defects fixed on the way: the label lookup predicted the x01 suffix instead of trying both forms, and the closing newline gave john a trailing blank line and every caller an off-by-one.
 *
 * Revision 1.17  2026/09/21 16:38:45  dlr
 * --profile: the list profiler, in the binary. What a list says that one line cannot -- intake damage, whether an odd field count is real or just salts containing a colon, whether a salt has been folded into the password field, and how far salts are reused. Salt cardinality uses JudySL, which hashpipe already links and uses. Agrees with tools/hid-profile on every figure across list 56 (one salt in 315,145), the 9.9M-line ledger (width 3, residual -0.06, 829,927 distinct, top 17,841 at 0.2055%), list165 and three known-answer synthetics, and runs 10.7x faster on the ledger: 4.8s against 51.3s. Salt statistics key on field-1 WIDTH, not field count, and the residual verdict has three branches; both were defects found in the Python and are carried over correct rather than reimplemented.
 *
 * Revision 1.16  2026/09/21 15:25:50  dlr
 * rename --shape to --form, and move the output formats in from tools/hid. --form matches the word the tool already prints ('3 different forms') and means something to a reader where 'shape' did not; it is unreleased, so the rename is free now and would not be later. --emit enum|mdx|hashcat|cmd: e-numbers as mdxfind -M takes them, a ready -h selection, hashcat modes ONE PER LINE because -m takes one mode per run where mdxfind takes a set, and a runnable command line. All four verified byte-identical to the Python implementation, which is now redundant for a user.
 *
 * Revision 1.15  2026/09/21 05:09:27  dlr
 * finish the plain-language sweep in --help. Cuts the user-defined-types paragraph from six lines to three; replaces stage-A, probe stages B and C, and census with what they mean; and removes a duplicated sentence in --shape that an earlier edit left behind by rewriting one line without deleting the one it replaced.
 *
 * Revision 1.14  2026/09/21 04:58:17  dlr
 * plain language throughout the user-facing text. 'the file's modal line shape is what gets reduced' becomes 'from which the hash type(s) are identified', and the same sweep removes modal/stored form/partition/e-number/discriminator/homogeneous and the Phase and Stage numbers, which name steps in a plan the reader has never seen. Settles on one word for the cost grouping -- tier, matching the flag the user types -- where band, group and tier had all been in use for the same thing. Comments keep the internal vocabulary; output does not.
 *
 * Revision 1.13  2026/09/21 04:49:38  dlr
 * do not announce the refutation of an unasked question, and say what a TARGET is. The gate still runs on a two-field value -- a file of hash:plaintext pairs should solve, and it costs microseconds -- but its FAILURE led the output with 'field 2 is not the plaintext' for every list of unsolved hashes, where nobody proposed that field 2 was a plaintext. Moved under -v, where the count still bounds what was eliminated. The usage line read 'bertillon [TARGET ...]' with TARGET undefined, which reads as a file reference and was taken as one; it now states that a TARGET is either a value or a file whose modal line shape gets reduced.
 *
 * Revision 1.12  2026/09/21 04:44:15  dlr
 * a FILE target names a list, not a hash. Without a file check, 'bertillon list165.orig' reduced the PATH -- a 17-character non-hex string -- and returned 17 types with full confidence, having never opened the file. It now reads the file and reduces on the MODAL line shape, sampled by floor over the whole file rather than by head, so the six damaged lines among 6.3 million cannot move the answer; list165.orig resolves to the salted 32-hex set led by e31 MD5SALT. Also warns when a target contains a path separator and names no readable file, which is how the original report arose: a mistyped .org for .orig produced a confident answer about the filename.
 *
 * Revision 1.11  2026/09/21 04:15:50  dlr
 * --shape reports distinct verdicts with counts instead of echoing one line per input line. A homogeneous list produced 900,000 copies of the same verdict, which is not a report -- it is the input measured and printed back, and it buries the rare lines that are the only interesting ones. Default is now each distinct verdict once with its count, commonest first, so the modal shape leads and the tail is where damage shows. Bounded by the number of distinct shapes, capped at 200 with the overflow announced rather than silently dropped. --per-line restores the old stream, --summary gives the census alone.
 *
 * Revision 1.10  2026/09/21 04:06:08  dlr
 * the reduce receipt answers what to run next. It described the state of the partition model -- a triple negation over four internal partition names, with --truncation mentioned only as a warning so every caveat read as a dead end rather than a door. Now two lines by default: the count with its basis, then a computed escalation ladder that offers only rungs which actually add types, plus the not-tried total. -v gives the breakdown in the reader's terms. Three arithmetic and wording fixes with it: the truncation-able types are a SUBSET of the shape cut and saying both totals made the column exceed the population; -v no longer advertises -v; and the refusal lines are one line each instead of three.
 *
 * Revision 1.9  2026/09/21 03:56:00  dlr
 * output speaks to the reader, not to the plan. The multiple-match note cited a design-document section the reader has never seen and described the result in the vocabulary of the process rather than of hashes; it now reads '%d types produce identical hash results for this input'. Same for the three-field path, and the gate's cap note no longer says FORMAT-DECLINED, which is internal shorthand. Internal reasoning stays in the comments.
 *
 * Revision 1.8  2026/09/21 03:35:04  dlr
 * on a positive identification, stop. 10a.1b says SOLVED means done and no reduction should be printed; the previous version printed the one-line answer and then dumped the alternative reading's entire partition census underneath it. That is redundant -- the pair verified, so the other reading is a hypothesis nobody needs -- and burying a one-line answer under twenty lines of arithmetic teaches people to stop reading the output. A solved single hash is now two lines total. The derivation diagnostics are gated behind -v and printed only where the table itself is the subject (--shape, --emit-table); they were noise in front of an identification. Also drops a duplicated digest-length banner in --shape. The receipt is unchanged where it earns its place: an unsolved or refuted target still carries its full partition census and bounds.
 *
 * Revision 1.7  2026/09/21 03:27:19  dlr
 * gate before reduce, per 10a.1b. A supplied plaintext is now VERIFIED first and the candidate set is suppressed when it solves: md5(XN7) is b4135cc539ebbdaa702d3444e7e1d21a, and the previous behaviour printed 267 candidates across two readings while never mentioning the answer was one compute away. Three defects fixed on the way in: a verify type was handed the whole 'stored:plaintext' line instead of the stored form, so every tagged family (bcrypt, phpBB3) failed silently while compute types worked; the comparison used strcasecmp over an always-lowercase rendering, making MD5UC verify a lowercase digest; and output is now an IDENTIFICATION (VERIFIED<TAB>enum<TAB>name), not a found line -- a verified pair is not a found (7g), reproducing hashpipe's xNN label got MD5SALT wrong on the first attempt, and a wrong label splits the mdsplit ledger. Multiple verifying types are reported and named as 7l ambiguity rather than collapsed: SHA1, AICH and SHA1UTF7 all verify one 40-hex pair and none is wrong.
 *
 * Revision 1.6  2026/09/21 03:16:07  dlr
 * operand mismatch cuts BOTH ways. Only one direction was implemented -- a salted type with no salt supplied -- so supplying a salt could only ADD candidates. The mirror was missing: a type taking NO salt cannot consume one that IS supplied, and under the hash:salt reading it leaves field 2 unexplained. fffffdc606682d3175ad054e658919ac:XN7 was returning MD5, MD4, HAV128, RMD128 and ED2K as candidates for a salted form none of them can express. Now returns salt-worthy types only: 78 for 32-hex+salt and 96 for 40-hex+salt, both exactly the figures in SPEC section 5, with the unsalted forms reconciling as 251+3 case = 254 and 212+3 case = 215.
 *
 * Revision 1.5  2026/09/21 03:08:02  dlr
 * Stage 5 in the binary: --reduce, and the no-flag easy mode. The reduction belongs where Hashtypes[] and its rates already live -- init_rates() has run by the dispatch point -- so a candidate set cannot be stale the way one derived from a generated TSV can. Field count selects the reading and the input selects it, never a flag: a two-field target runs BOTH readings, each labelled, because the discriminator is not in the line. Bands cumulative unless --only; UNAFFORDABLE counted every run; TRUNCATION-ABLE separate and opt-in; an empty APPLICABLE set is loud and names a case cut as recoverable. Agrees byte-for-byte with tools/hid across 3 tiers x 2 readings -- two independent implementations, one reading the live table and one the TSV. Fixes a regression the new argv parsing introduced in the same change: --shape FILE routed its filename into the target list and silently read stdin instead, reporting a zero census.
 *
 * Revision 1.4  2026/09/21 00:07:01  dlr
 * Stage 2: hid-gate. Parses each line's own work factor, raises -L before verifying, then hands the file to hashpipe's own verification path -- a wrapper, no reimplementation. Fixes the conflation where a cost-skipped type and a genuinely unhandled format produce the same 'no registered type verified' message: a cost-15 bcrypt now solves in 1.38s where -L 1 claimed nothing handled it. 69-line mixed fixture: 69/69 in 1.57s. Cost model anchored on measurement (cost 15 = 1.40s, doubling per step), verified against costs 10/12/15.
 *
 * Revision 1.3  2026/09/20 14:26:33  dlr
 * Stage 1: hid-shape, the arithmetic. Runtime Phase 0 and Phase 1 on input lines, with the digest-length whitelist DERIVED from this binary's type table rather than hand-written. Reproduces the SPEC 7k census exactly on all 897,512 contest hashes: tagged 557,856 / prefix 32,799 / delimited 20,187 / composite 10,040 / bare-at-digest-length 276,630 and every length bucket. Three corrections found by the corpus: specific prefixes must be tested before the generic tag (0x0100 MSSQL was being eaten by the 0x tag); a named prefix like scrypt$ is a Phase 1 identification, not a field model; and 0x is a tag only when its body is actually hex, or it fires on base64 values that begin 0x.
 *
 * Revision 1.2  2026/09/20 14:06:07  dlr
 * user types: blank the derived columns instead of emitting wrong ones. A user type's -N vector column is an hx expression, not a stored form, so stage A measured the recipe: USER_Cust1 (a 20-byte SHA-1) came out non-hex with d_bytes 0. Emission is never refused; the undecidable columns now report as undecidable, and userdef rows no longer feed the digest-length whitelist.
 *
 * Revision 1.1  2026/09/20 13:56:31  dlr
 * Stage 0: argv[0] dispatch, shared type walk, --emit-table self-check. Reproduces the 1028-row fixture exactly; -N byte-identical; self-test 1028/0/2 unchanged.
 *
 *
 * Alphonse Bertillon, 1879: identification from a card of MEASUREMENTS, which
 * narrowed to a candidate set and never asserted an identity. Correct,
 * insufficient, and superseded once a better discriminator arrived. That is
 * this tool, and the table below has the same form as his card.
 *
 * Stage 0 scope (PLAN section 3.2): the dispatch, and `--emit-table` -- stage A
 * generation in-process plus the comparison protocol. Salt sweeps (stage B) and
 * the collision matrix (stage C) stay in tools/bertillon-probe; their columns
 * are carried through from the reference untouched, never fabricated here.
 *
 * WHY THIS LIVES INSIDE HASHPIPE. The verifier is the specification: nothing
 * upstream publishes salt widths, parity or collision behaviour, but hashpipe
 * enforces all of it. Sharing the binary means the table cannot drift from
 * Hashtypes[]. That property is the entire reason for integration, so the row
 * walk below is the SAME code -N uses -- not a copy of it. A copy would drift,
 * which is the defect this design exists to prevent.
 */
#ifndef BERTILLON_H
#define BERTILLON_H

#include <errno.h>
#include <unistd.h>

/* ------------------------------------------------------------------ rows */

struct bert_row {
    char *id, *name, *hashcat, *flags, *stored;
    int   stored_len, fields, d_bytes, salt_len;
    char  tag[64];
    const char *d_charset;
    const char *phase0;
    int   parse_uncertain;
    int   udef;             /* userdef registry, not Hashtypes[] */
    /* Carried through from the reference, never derived here. Empty when no
     * reference supplied -- an empty cell says "not measured", and a fabricated
     * one would say "measured, and it is blank". Those are different claims. */
    const char *salt_ceiling, *salt_rel, *field2_is_salt;
    const char *n_acceptors, *collides_with;
};

static struct bert_row *Bert_rows = NULL;
static int Bert_nrows = 0, Bert_cap = 0;

/* Set when argv[0] (or -Z) selects bertillon; read in main() after the type
 * table is built. Dispatch cannot happen earlier: Hashtypes[] is malloc'd by
 * init_hashtypes() and the userdef registry is loaded after that, so an
 * "argv[0] first thing in main" dispatch would measure an empty table. */
/*
 * User-defined types come from $MDXFIND_CACHE/userdef.txt, so whether they
 * exist is a property of the OPERATOR'S ENVIRONMENT, not of the build. They are
 * therefore outside the comparison domain and outside the emitted table: a
 * reference that contained them would report drift for everyone whose
 * MDXFIND_CACHE differs, and a fixture whose contents depend on an environment
 * variable is not a fixture. Counted and named, never compared.
 */
static int    Bert_include_udef = 0;
/* The derivation diagnostics are meaningful when the subject IS the table --
 * --shape and --emit-table -- and are noise in front of a one-line
 * identification. */
static int    Bert_verbose = 0;
static int    Bert_mode = 0;
static int    Bert_argc = 0;
static char **Bert_argv = NULL;

/* ------------------------------------------------- character-class tests */
/* Mirrors tools/bertillon-probe exactly, including the ORDER of the tests:
 * an all-digit string matches hex-lower first, and that is deliberate. */

static int bert_hexl(const char *s)
{ for (; *s; s++) if (!((*s>='0'&&*s<='9')||(*s>='a'&&*s<='f'))) return 0; return 1; }
static int bert_hexu(const char *s)
{ for (; *s; s++) if (!((*s>='0'&&*s<='9')||(*s>='A'&&*s<='F'))) return 0; return 1; }
static int bert_hexm(const char *s)
{ for (; *s; s++) if (!isxdigit((unsigned char)*s)) return 0; return 1; }
static int bert_b64(const char *s)
{
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (!(isalnum(c) || c=='+' || c=='/' || c=='.' || c=='_' || c=='=' || c=='-'))
            return 0;
    }
    return 1;
}

static const char *bert_charset(const char *s)
{
    if (!*s)          return "empty";
    if (bert_hexl(s)) return "hex-lower";
    if (bert_hexu(s)) return "hex-upper";
    if (bert_hexm(s)) return "hex-mixed";
    if (bert_b64(s))  return "b64ish";
    return "other";
}

/* ------------------------------------------------------------ the anchor */
/*
 * The self-test vector is "<stored form>:<plaintext>". Split on the KNOWN
 * plaintext rather than on the last colon: stored forms contain colons of
 * their own (Oracle, the PBKDF2 families), and a rightmost-colon split cuts
 * them in the wrong place. Longest candidate first, so "password123" is not
 * shortened to "password".
 */
static const char *Bert_plains[] = { "password123", "password", "hashcat", "test", NULL };

static char *bert_split_vector(const char *v, int *uncertain)
{
    size_t vl = strlen(v);
    int i;
    for (i = 0; Bert_plains[i]; i++) {
        size_t pl = strlen(Bert_plains[i]) + 1;         /* ":" + plain */
        if (vl > pl) {
            const char *tail = v + vl - pl;
            if (*tail == ':' && !strcmp(tail + 1, Bert_plains[i])) {
                char *s = (char *)malloc(vl - pl + 1);
                memcpy(s, v, vl - pl); s[vl - pl] = '\0';
                *uncertain = 0;
                return s;
            }
        }
    }
    *uncertain = 1;                                     /* flagged, not dropped */
    return strdup(v);
}

/* ---------------------------------------------------------------- the tag */
/*
 * A leading tag, NOT any interior separator. 23,698 contest hashes carry an
 * interior '$' that is a field split; treating those as tagged is wrong in
 * exactly the same way that a '^\$' test is wrong for the ones that are.
 *   $...$   {word}   0x
 */
static void bert_tag(const char *s, char *out, size_t outsz)
{
    size_t j;
    out[0] = '\0';
    if (s[0] == '$') {
        for (j = 1; s[j] && (isalnum((unsigned char)s[j]) || s[j]=='_' || s[j]=='.' || s[j]=='-'); j++)
            ;
        if (s[j] == '$' && j + 2 <= outsz) { memcpy(out, s, j + 1); out[j + 1] = '\0'; }
    } else if (s[0] == '{') {
        for (j = 1; s[j] && (isalnum((unsigned char)s[j]) || s[j]=='_' || s[j]=='-'); j++)
            ;
        if (j > 1 && s[j] == '}' && j + 2 <= outsz) { memcpy(out, s, j + 1); out[j + 1] = '\0'; }
    } else if (s[0] == '0' && s[1] == 'x') {
        /*
         * `0x` announces a HEX LITERAL, so it is a tag only when what follows
         * actually is hex up to the first separator. Without that test it fires
         * on any base64 value that happens to begin "0x" -- five corpus records
         * of the base64(22)$8 inline-salt form (SPEC 7k.1) read as tagged,
         * where they are delimited. The tag must be earned by the body.
         */
        size_t k;
        for (k = 2; s[k] && s[k] != '$' && s[k] != ':'; k++)
            if (!isxdigit((unsigned char)s[k])) return;
        if (k > 2) strcpy(out, "0x");
    }
}

/* ------------------------------------------------------- the row callback */
/*
 * One row per type, in -N's own order and with -N's own field values. This is
 * called BY the -N walk, so the two listings cannot disagree about what the
 * type table contains.
 */
static void bert_collect(const char *id, const char *name, const char *hashcat,
                         const char *flags, const char *vector, void *ctx)
{
    struct bert_row *r;
    char *stored, *colon;
    int uncertain = 0;
    (void)ctx;

    if (Bert_nrows == Bert_cap) {
        Bert_cap = Bert_cap ? Bert_cap * 2 : 1024;
        Bert_rows = (struct bert_row *)realloc(Bert_rows, Bert_cap * sizeof(*Bert_rows));
        if (!Bert_rows) { perror("bertillon: realloc"); exit(2); }
    }
    r = &Bert_rows[Bert_nrows++];
    memset(r, 0, sizeof(*r));

    r->id = strdup(id); r->name = strdup(name);
    r->udef = (id[0] == 'u');
    r->hashcat = strdup(hashcat); r->flags = strdup(flags);

    stored = bert_split_vector(vector, &uncertain);
    r->stored = stored;
    r->parse_uncertain = uncertain;
    r->stored_len = (int)strlen(stored);

    bert_tag(stored, r->tag, sizeof(r->tag));

    /* fields = colon-separated count of the STORED form (plaintext already off) */
    r->fields = 1;
    for (colon = stored; *colon; colon++) if (*colon == ':') r->fields++;

    {
        /* digest = field 0; salt = everything after the first colon, joined */
        char *first = strchr(stored, ':');
        size_t dlen = first ? (size_t)(first - stored) : strlen(stored);
        char *digest = (char *)malloc(dlen + 1);
        memcpy(digest, stored, dlen); digest[dlen] = '\0';

        if (r->tag[0]) {
            r->d_charset = "tagged";
            r->d_bytes   = 0;
        } else {
            r->d_charset = bert_charset(digest);
            r->d_bytes   = (dlen && bert_hexm(digest)) ? (int)(dlen / 2) : 0;
        }
        r->salt_len = first ? (int)strlen(first + 1) : 0;
        free(digest);
    }

    r->salt_ceiling = r->salt_rel = r->field2_is_salt = "";
    r->n_acceptors  = r->collides_with = "";

    /*
     * A user type's -N "vector" column is its hx EXPRESSION, not a stored form:
     * "sha1(md5(pass) . \"register\")". Everything above therefore measured the
     * recipe instead of the dish -- stored_len became the length of the
     * expression string, d_charset described its punctuation, and USER_Cust1
     * (a 20-byte SHA-1) came out as non-hex with d_bytes 0. Those are not
     * incomplete values, they are wrong ones, and hid-reduce reading that row
     * would never offer the type for a 40-hex line.
     *
     * Blank them. An empty cell says "not measured"; a plausible wrong number
     * says "measured, and this is the answer". Computing is never refused --
     * the row is still emitted, with the expression intact and the registry
     * facts (id, name, flags) which ARE correct -- but an undecidable result is
     * reported as undecidable.
     *
     * The real derivation does not parse anything: struct userdef_type already
     * holds diglen_hex (probed against the hx VM at load), slot_mask (which
     * operands the program references) and form (the declared stored layout).
     * See PLAN section 4, Stage 0b.
     */
    if (r->udef) {
        r->tag[0]    = '\0';
        r->d_charset = "";
        r->phase0    = "";
        r->stored_len = r->fields = r->d_bytes = r->salt_len = -1;
    }
}

/* -------------------------------------------------- phase 0, second pass */
/*
 * The digest-length whitelist is DERIVED, never written down. A hand-written
 * set demoted TIGER at 24 bytes and RMD320 at 40 -- both real digest lengths
 * with exactly one type each. Popularity is not the criterion: a length counts
 * if SOME type emits it as a bare, unsalted, unstructured digest.
 */
static unsigned char Bert_diglen[256];   /* byte lengths that ARE digest lengths */

static void bert_phase0(void)
{
    unsigned char *isdig = Bert_diglen;
    int i;
    memset(isdig, 0, sizeof(Bert_diglen));

    for (i = 0; i < Bert_nrows; i++) {
        struct bert_row *r = &Bert_rows[i];
        if (!r->udef && r->tag[0] == '\0' && r->fields == 1 && r->d_bytes > 0 && r->d_bytes < 256
            && !strchr(r->flags, 'v') && !strchr(r->flags, 'V') && !strchr(r->flags, 's'))
            isdig[r->d_bytes] = 1;
    }
    for (i = 0; i < Bert_nrows; i++) {
        struct bert_row *r = &Bert_rows[i];
        int n = r->d_bytes;
        if      (r->udef)                        r->phase0 = "";
        else if (r->tag[0])                      r->phase0 = "tagged";
        else if (n == 0)                         r->phase0 = "non-hex";
        else if (n < 256 && isdig[n])            r->phase0 = "digest";
        else if (n % 16 == 0)                    r->phase0 = "cipher-aes?";
        else if (n % 8  == 0)                    r->phase0 = "cipher-des?";
        else                                     r->phase0 = "layout?";
    }
    if (Bert_verbose) {
        int first = 1;
        fprintf(stderr, "bertillon: derived digest lengths (bytes): [");
        for (i = 0; i < 256; i++)
            if (isdig[i]) { fprintf(stderr, "%s%d", first ? "" : ", ", i); first = 0; }
        fprintf(stderr, "]\n");
    }
}

/* ------------------------------------------------------- the shared walk */
/*
 * The ONE place the type table is turned into rows. -N calls it and so does
 * --emit-table, so the two cannot disagree about what types exist, what flags
 * they carry or what vector they hold. Duplicating this loop would have been
 * less invasive and would have reintroduced exactly the drift that putting
 * bertillon inside hashpipe is meant to rule out.
 *
 * Row order, e-numbering and field formatting are -N's, unchanged.
 */
typedef void (*bert_rowcb)(const char *id, const char *name, const char *hashcat,
                           const char *flags, const char *vector, void *ctx);

static void bert_walk_types(bert_rowcb cb, void *ctx)
{
    int ti, mv;
    char idbuf[32];

    for (ti = 0; ti < Numtypes; ti++) {
        struct hashtype *ht = &Hashtypes[ti];
        char flags[16], hcbuf[64];
        int fp = 0, hci = 0;

        if (!ht->name) continue;
        if (!ht->compute && !ht->verify && ht->nchain == 0) continue;

        if (ht->flags & HTF_SALTED)   flags[fp++] = 's';
        if (ht->flags & HTF_UC)       flags[fp++] = 'u';
        if (ht->flags & HTF_NTLM)     flags[fp++] = 'n';
        if (ht->flags & HTF_COMPOSED) flags[fp++] = 'c';
        if (ht->flags & HTF_NONHEX)   flags[fp++] = 'v';
        if (ht->verify)               flags[fp++] = 'V';
        if (fp == 0) flags[fp++] = '-';
        flags[fp] = '\0';

        for (mv = 0; Maphashcat[mv].hc != 65535; mv++) {
            if (Maphashcat[mv].mdx == ti) {
                if (hci) hci += snprintf(hcbuf + hci, sizeof(hcbuf) - hci, ",");
                hci += snprintf(hcbuf + hci, sizeof(hcbuf) - hci, "%d", Maphashcat[mv].hc);
            }
        }
        snprintf(idbuf, sizeof(idbuf), "e%d", ti);
        cb(idbuf, ht->name, hci ? hcbuf : "n/a", flags,
           ht->example ? ht->example : "", ctx);
    }
    /* User-defined types are a SEPARATE address space and are not in
     * Hashtypes[]; they live in the userdef registry. Keyed on the declared
     * id as u<idstr>, never on the internal op -- the op is derived from the
     * built-in count at startup and moves as built-ins are added. */
    {
        int un = userdef_count(), ui;
        for (ui = 0; ui < un; ui++) {
            struct userdef_type *ut = userdef_get_by_index(ui);
            char uf[8]; int uo = 0;
            if (!ut) continue;
            if (ut->slot_mask & USERDEF_SLOT_SALT) uf[uo++] = 's';
            if (uo == 0) uf[uo++] = '-';
            uf[uo] = '\0';
            snprintf(idbuf, sizeof(idbuf), "u%s", ut->idstr);
            cb(idbuf, ut->dispname, "n/a", uf, ut->hx, ctx);
        }
    }
}

/* The -N row, printed exactly as it was printed inline before the walk was
 * shared. Byte-for-byte identity with the previous output is the gate. */
static void bert_print_N(const char *id, const char *name, const char *hashcat,
                         const char *flags, const char *vector, void *ctx)
{
    (void)ctx;
    printf("%s\t%s\t%s\t%s\t%s\n", id, name, hashcat, flags, vector);
}

/* ------------------------------------------------------ the 17-column form */
/*
 * The schema the committed fixture carries. Stage A owns the first eleven and
 * the last; salt_ceiling and salt_rel come from stage B, n_acceptors and
 * collides_with from stage C, field2_is_salt from the join. Those five are
 * carried, never invented.
 *
 * `id` is in the table but is NOT compared. e-numbers are positional -- the op
 * "is derived from the built-in count at start-up and shifts as built-ins are
 * added" (hashpipe.c:56) -- so comparing them turns one inserted type into a
 * thousand CHANGED rows. An alarm that loud is an alarm that gets ignored.
 * Shifts are counted and reported as information, which is what they are.
 */
static const char *Bert_hdr[] = {
    "id","name","hashcat","flags","phase0","stored_len","fields","tag",
    "d_bytes","d_charset","salt_len","salt_ceiling","salt_rel","field2_is_salt",
    "n_acceptors","collides_with","stored", NULL
};
#define BERT_NCOL 17

/* The stage-A-owned columns that a comparison may speak about. Everything
 * else is either the key, positional, or carried. */
static const char *Bert_cmp[] = {
    "hashcat","flags","phase0","stored_len","fields","tag",
    "d_bytes","d_charset","salt_len","stored", NULL
};

static void bert_fmt(const struct bert_row *r, const char *out[BERT_NCOL])
{
    static char nb[5][32];
    /* -1 is the not-measured sentinel and prints as an empty cell, never as a
     * number a consumer could mistake for a measurement. */
    #define BERT_N(slot, v) do { if ((v) < 0) nb[slot][0] = '\0'; \
                                 else snprintf(nb[slot], sizeof(nb[slot]), "%d", (v)); } while (0)
    BERT_N(0, r->stored_len);
    BERT_N(1, r->fields);
    BERT_N(2, r->d_bytes);
    BERT_N(3, r->salt_len);
    #undef BERT_N
    out[0]=r->id;      out[1]=r->name;     out[2]=r->hashcat;  out[3]=r->flags;
    out[4]=r->phase0;  out[5]=nb[0];       out[6]=nb[1];       out[7]=r->tag;
    out[8]=nb[2];      out[9]=r->d_charset; out[10]=nb[3];
    out[11]=r->salt_ceiling; out[12]=r->salt_rel; out[13]=r->field2_is_salt;
    out[14]=r->n_acceptors;  out[15]=r->collides_with; out[16]=r->stored;
}

/* ------------------------------------------------------ reference loading */

struct bert_ref { char *col[BERT_NCOL]; int seen; };
static struct bert_ref *Bert_ref = NULL;
static int Bert_nref = 0, Bert_refcol = 0;
static char *Bert_refhdr[BERT_NCOL];

/* -> 0 loaded, 2 unusable. Unusable is never silently treated as "no changes":
 * a reference that could not be read is a DIFFERENT outcome from one that
 * matched, and the exit code has to say which. */
static int bert_load_ref(const char *path)
{
    FILE *f = fopen(path, "r");
    char *line = NULL; size_t cap = 0; ssize_t n;
    int row = 0, capn = 0;

    if (!f) { fprintf(stderr, "bertillon: %s: %s\n", path, strerror(errno)); return 2; }

    while ((n = getline(&line, &cap, f)) > 0) {
        char *p = line, *tab; int c = 0;
        if (n && line[n-1] == '\n') line[--n] = '\0';
        if (n && line[n-1] == '\r') line[--n] = '\0';   /* a CRLF reference is a
                                                         * repair, not a diff */
        if (row == 0) {
            while (c < BERT_NCOL) {
                tab = strchr(p, '\t');
                if (tab) *tab = '\0';
                Bert_refhdr[c++] = strdup(p);
                if (!tab) break;
                p = tab + 1;
            }
            Bert_refcol = c;
            if (c != BERT_NCOL) {
                fprintf(stderr, "bertillon: %s: header has %d columns, expected %d\n",
                        path, c, BERT_NCOL);
                fclose(f); free(line); return 2;
            }
            { int i; for (i = 0; i < BERT_NCOL; i++)
                if (strcmp(Bert_refhdr[i], Bert_hdr[i])) {
                    fprintf(stderr, "bertillon: %s: column %d is \"%s\", expected \"%s\"\n",
                            path, i + 1, Bert_refhdr[i], Bert_hdr[i]);
                    fclose(f); free(line); return 2;
                }
            }
            row++; continue;
        }
        if (Bert_nref == capn) {
            capn = capn ? capn * 2 : 1024;
            Bert_ref = (struct bert_ref *)realloc(Bert_ref, capn * sizeof(*Bert_ref));
            if (!Bert_ref) { perror("bertillon: realloc"); exit(2); }
        }
        memset(&Bert_ref[Bert_nref], 0, sizeof(Bert_ref[0]));
        while (c < BERT_NCOL) {
            tab = strchr(p, '\t');
            if (tab) *tab = '\0';
            Bert_ref[Bert_nref].col[c++] = strdup(p);
            if (!tab) break;
            p = tab + 1;
        }
        while (c < BERT_NCOL) Bert_ref[Bert_nref].col[c++] = strdup("");
        Bert_nref++; row++;
    }
    fclose(f); free(line);
    if (Bert_nref == 0) {
        fprintf(stderr, "bertillon: %s: no data rows\n", path);
        return 2;
    }
    return 0;
}

static struct bert_ref *bert_find(const char *name)
{
    int i;                                  /* linear: 1k rows, once, at build */
    for (i = 0; i < Bert_nref; i++)
        if (!strcmp(Bert_ref[i].col[1], name)) return &Bert_ref[i];
    return NULL;
}

/* -------------------------------------------------------------- emitting */

static void bert_emit(FILE *fp)
{
    int i, c;
    const char *col[BERT_NCOL];
    for (c = 0; c < BERT_NCOL; c++) fprintf(fp, "%s%s", c ? "\t" : "", Bert_hdr[c]);
    fputc('\n', fp);
    for (i = 0; i < Bert_nrows; i++) {
        if (Bert_rows[i].udef && !Bert_include_udef) continue;
        bert_fmt(&Bert_rows[i], col);
        for (c = 0; c < BERT_NCOL; c++) fprintf(fp, "%s%s", c ? "\t" : "", col[c]);
        fputc('\n', fp);
    }
}

/* ------------------------------------------------------------- comparing */

static int bert_colidx(const char *name)
{ int i; for (i = 0; i < BERT_NCOL; i++) if (!strcmp(Bert_hdr[i], name)) return i; return -1; }

/* -> 0 identical, 1 differs. Diagnosis to stderr, so a caller can redirect the
 * new table over the old one and still read what moved. */
static int bert_compare(void)
{
    int i, k, changed = 0, added = 0, added_udef = 0, removed = 0, shifted = 0;
    const char *col[BERT_NCOL];

    for (i = 0; i < Bert_nrows; i++) {
        struct bert_row *r = &Bert_rows[i];
        struct bert_ref *ref;
        if (r->udef && !Bert_include_udef) { added_udef++; continue; }
        ref = bert_find(r->name);
        if (!ref) {
            fprintf(stderr, "ADDED    %-6s %s\n", r->id, r->name);
            added++;
            continue;
        }
        ref->seen = 1;
        bert_fmt(r, col);
        if (strcmp(ref->col[0], r->id)) shifted++;
        for (k = 0; Bert_cmp[k]; k++) {
            int ci = bert_colidx(Bert_cmp[k]);
            if (ci < 0) continue;
            if (strcmp(ref->col[ci], col[ci])) {
                fprintf(stderr, "CHANGED  %-6s %-28s %-12s %s -> %s\n",
                        r->id, r->name, Bert_cmp[k], ref->col[ci], col[ci]);
                changed++;
            }
        }
    }
    for (i = 0; i < Bert_nref; i++)
        if (!Bert_ref[i].seen) {
            fprintf(stderr, "REMOVED  %-6s %s\n", Bert_ref[i].col[0], Bert_ref[i].col[1]);
            removed++;
        }

    if (shifted)
        fprintf(stderr, "bertillon: %d e-number(s) shifted position; not a change "
                        "(ids are positional, comparison is keyed on name)\n", shifted);
    if (added_udef)
        fprintf(stderr, "bertillon: %d user-defined type(s) excluded (environment, not build); "
                        "--include-userdef emits them with derived columns empty\n", added_udef);

    return (changed || added || removed) ? 1 : 0;
}


/* ============================================================== STAGE 1 ===
 * hid-shape: the arithmetic on an INPUT LINE. Runtime Phase 0 ("is it a hash
 * at all?") and Phase 1 ("does it identify itself?"). No candidate sets, no
 * verification, no I/O beyond the line.
 *
 * The digest-length whitelist is Bert_diglen[], DERIVED from this binary's own
 * type table. That is the point of living inside hashpipe: METHOD's condensed
 * Phase 0 table lists byte lengths 16,20,28,32,48,64 and drops 8, 24 and 40,
 * which is exactly the "wrongly demoted TIGER at 24 and RMD320 at 40" error the
 * probe warns about. A derived set cannot go stale that way.
 */

/* Repair before measuring. A CRLF list against an LF ledger yields
 * md5(salt . "\r" . pass) and matches nothing, for the entire file. */
static int bert_repair(char *s)
{
    int n = (int)strlen(s), repaired = 0;
    while (n && (s[n-1] == '\n' || s[n-1] == '\r')) { s[--n] = '\0'; repaired = 1; }
    return repaired;
}

/* $HEX[...] is an ENCODING, unwrapped before field counting, never after. */
static int bert_unhex(char *s)
{
    int n = (int)strlen(s), i, j;
    if (n < 6 || strncmp(s, "$HEX[", 5) || s[n-1] != ']') return 0;
    for (i = 5, j = 0; i < n - 1; i += 2) {
        int hi, lo;
        if (!isxdigit((unsigned char)s[i]) || !isxdigit((unsigned char)s[i+1])) return 0;
        hi = isdigit((unsigned char)s[i])   ? s[i]-'0'   : (tolower(s[i])  -'a'+10);
        lo = isdigit((unsigned char)s[i+1]) ? s[i+1]-'0' : (tolower(s[i+1])-'a'+10);
        s[j++] = (char)((hi << 4) | lo);
    }
    s[j] = '\0';
    return 1;
}

static int bert_is_crypt64(const char *s, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!(isalnum(c) || c == '.' || c == '/')) return 0;
    }
    return 1;
}

/*
 * Phase 1 shapes that name a format without carrying a `$...$` tag (SPEC 7k).
 * These run BEFORE the generic tag test, because specific beats generic: `0x`
 * is a tag by the letter of the rule, but MSSQL's `0x0100` says far more, and
 * letting the two-character tag match first discards the difference.
 */
static const char *bert_prefix_shape(const char *s, int n, char *buf, size_t bufsz)
{
    int i;
    if (n == 13 && bert_is_crypt64(s, n))                       return "descrypt";
    if (n == 20 && s[0] == '_' && bert_is_crypt64(s + 1, 12))   return "bsdicrypt";
    if (n == 94 && !strncmp(s, "0x0100", 6))                    return "mssql";
    if (n == 54 && !strncmp(s, "0x0100", 6))                    return "mssql2012";

    /*
     * A NAMED prefix: a leading word followed by '$', as in
     * "scrypt$JR6BbBlUH8v.$15$8$1$64$...". That names its format exactly as
     * `$2a$` does and belongs in Phase 1, not in the delimited bucket.
     *
     * The leading token must NOT be all-hex, or every "32hex$salt" record --
     * de472cdfd62cd07106cf33bff732900d$mMXH10Wp -- would read as a format
     * called "de472cdf...". An all-hex head is a digest with a separator,
     * which is a field model, not an identification.
     */
    for (i = 0; i < n && ((s[i] >= 'a' && s[i] <= 'z') || isdigit((unsigned char)s[i])); i++)
        ;
    if (i >= 2 && i <= 12 && i < n && s[i] == '$') {
        char head[16];
        memcpy(head, s, i); head[i] = '\0';
        /* Not all-hex: an all-hex head is a digest with a separator, so
         * "de472cdfd62cd07106cf33bff732900d$mMXH10Wp" is a field model and not
         * a format called "de472cdf...". */
        if (!bert_hexm(head)) {
            snprintf(buf, bufsz, "named:%s", head);
            return buf;
        }
    }
    /*
     * Deliberately NOT matched: a mixed-case or long leading token, such as the
     * base64(22)$8 form "ysgDqOQ2yjuyl4HkW39Fx0$EGMMEG1S" that SPEC 7k.1 files
     * as inline-salt DELIMITED. Accepting it would invent a format named after
     * a salt. A per-line heuristic may REJECT but must never ACCEPT, so the
     * rule is narrow on purpose and anything it declines falls through to the
     * field model, which is the honest answer.
     */
    return NULL;
}

struct bert_shape_stat {
    long tagged, prefix, delimited, digest, cipher_des, cipher_aes;
    long composite, nothash, repaired, hexwrap, ambiguous;
    long bylen[256];
};

/*
 * Classify one line. `out` receives the verdict; the return is the class name.
 * Where a length is BOTH a digest length and a block multiple the verdict names
 * both readings -- a single label there would be wrong by construction. 40
 * bytes is RMD320's digest length AND five DES blocks, and the dynu family that
 * turned out to be DES-EDE2-CBC is indistinguishable from RMD320 by arithmetic.
 * Only verification or a key separated them, and it was a supplied key that
 * did it.
 */
static const char *bert_shape_line(char *line, char *out, size_t outsz,
                                   struct bert_shape_stat *st)
{
    int n, hex, i, ndollar = 0, ncolon = 0;
    const char *pfx;

    if (bert_repair(line)) st->repaired++;
    if (bert_unhex(line))  st->hexwrap++;
    n = (int)strlen(line);

    if (n == 0) { snprintf(out, outsz, "empty line"); st->nothash++; return "not-hash"; }

    /* Phase 1. Specific shapes first, then the generic tag; a tag
     * short-circuits ~62% of real input at no cost. */
    {
        char pbuf[80];
        if ((pfx = bert_prefix_shape(line, n, pbuf, sizeof(pbuf))) != NULL) {
            snprintf(out, outsz, "%s (%d chars)", pfx, n);
            st->prefix++;
            return "prefix";
        }
    }
    {
        char tag[64];
        bert_tag(line, tag, sizeof(tag));
        if (tag[0]) {
            snprintf(out, outsz, "tag %s", tag);
            st->tagged++;
            return "tagged";
        }
    }

    /* An interior '$' is a SEPARATOR, not a tag, and delimits exactly as ':'
     * does. A '^\$' test files these as untagged and a '$'-anywhere test files
     * them as tagged; both are wrong, and 23,698 of the corpus are affected. */
    for (i = 0; i < n; i++) {
        if (line[i] == '$') ndollar++;
        else if (line[i] == ':') ncolon++;
    }
    if (ndollar || ncolon) {
        int flen = 0; char *p;
        for (p = line, flen = 0; *p && *p != '$' && *p != ':'; p++) flen++;
        snprintf(out, outsz, "%d field(s), first %d chars, sep '%c'",
                 ndollar + ncolon + 1, flen, ndollar ? '$' : ':');
        st->delimited++;
        return "delimited";
    }

    hex = bert_hexm(line);
    if (!hex) {
        snprintf(out, outsz, "not hex, %d chars, charset %s", n, bert_charset(line));
        st->nothash++;
        return "not-hash";
    }
    if (n & 1) {
        snprintf(out, outsz, "odd hex length %d -- truncated or mis-copied", n);
        st->nothash++;
        return "not-hash";
    }

    /* Phase 0: the arithmetic, on the stored value's length in BYTES. */
    {
        int L = n / 2, isdig = (L < 256 && Bert_diglen[L]);
        int des = (L % 8 == 0), aes = (L % 16 == 0);
        if (L < 256) st->bylen[L]++;

        if (isdig && (des || aes)) {
            snprintf(out, outsz, "%d bytes: digest length AND %s multiple -- "
                                 "arithmetic cannot separate them", L,
                     aes ? "16-byte block" : "8-byte block");
            st->digest++; st->ambiguous++;
            return "digest|cipher?";
        }
        if (isdig) { snprintf(out, outsz, "%d bytes, a digest length", L);
                     st->digest++; return "digest"; }
        if (aes)   { snprintf(out, outsz, "%d bytes = %d AES blocks, no digest is this long",
                              L, L / 16); st->cipher_aes++; return "cipher-aes?"; }
        if (des)   { snprintf(out, outsz, "%d bytes = %d DES blocks, no digest is this long",
                              L, L / 8); st->cipher_des++; return "cipher-des?"; }

        /* Off-list: DECOMPOSE, do not search. Report layout hypotheses, which
         * are an instruction to re-read the file with a different field model,
         * not a type selection. */
        {
            int k, w = 0;
            w = snprintf(out, outsz, "%d bytes, no algorithm emits this; layouts:", L);
            for (k = 1; k < 256 && w < (int)outsz - 24; k++)
                if (Bert_diglen[k] && k < L)
                    w += snprintf(out + w, outsz - w, " d%d+s%d", k, L - k);
            st->composite++;
            return "composite";
        }
    }
}

/*
 * Distinct verdicts, with counts. A homogeneous list produced one identical
 * line per input line -- 900,000 copies of "delimited 2 field(s), first 32
 * chars, sep ':'" -- which is not a report, it is the input measured and then
 * printed back. What a reader wants from a list is the distinct shapes and how
 * many of each, and the rare ones are the interesting ones.
 *
 * Bounded: the verdict text is derived from the shape, so the distinct count is
 * the number of distinct shapes, which is small. Capped anyway, and the cap is
 * announced rather than silently truncating.
 */
#define BERT_VERD_MAX 200
struct bert_verdict { char text[560]; long n; };

static int bert_verd_add(struct bert_verdict *v, int *nv, const char *cls,
                         const char *detail)
{
    char key[560];
    int i;
    snprintf(key, sizeof(key), "%-14s %s", cls, detail);
    for (i = 0; i < *nv; i++)
        if (!strcmp(v[i].text, key)) { v[i].n++; return 1; }
    if (*nv >= BERT_VERD_MAX) return 0;
    snprintf(v[*nv].text, sizeof(v[*nv].text), "%s", key);
    v[*nv].n = 1;
    (*nv)++;
    return 1;
}

static int bert_cmd_shape(const char *path, int per_line)
{
    FILE *fp = path ? fopen(path, "r") : stdin;
    char *line = NULL, out[512];
    size_t cap = 0;
    ssize_t n;
    struct bert_shape_stat st;
    long total = 0, overflow = 0;
    int i, nv = 0;
    struct bert_verdict *verd;

    if (!fp) { fprintf(stderr, "bertillon: %s: %s\n", path, strerror(errno)); return 2; }
    memset(&st, 0, sizeof(st));
    verd = (struct bert_verdict *)calloc(BERT_VERD_MAX, sizeof(*verd));
    if (!verd) { perror("bertillon: calloc"); return 2; }

    while ((n = getline(&line, &cap, fp)) > 0) {
        const char *cls = bert_shape_line(line, out, sizeof(out), &st);
        total++;
        if (per_line > 0) printf("%-14s %s\n", cls, out);
        else if (per_line == 0 && !bert_verd_add(verd, &nv, cls, out)) overflow++;
    }
    if (path) fclose(fp);
    free(line);

    if (per_line == 0 && nv) {
        /* Commonest first: the modal shape is what the file IS, and the tail is
         * where the damage lives. */
        for (i = 0; i < nv; i++) {
            int j, best = i;
            for (j = i + 1; j < nv; j++) if (verd[j].n > verd[best].n) best = j;
            if (best != i) { struct bert_verdict t = verd[i]; verd[i] = verd[best]; verd[best] = t; }
            printf("%9ld  %s\n", verd[i].n, verd[i].text);
        }
        if (overflow)
            fprintf(stderr, "bertillon: %ld line(s) past %d distinct verdicts were "
                            "counted in the\n           census below but not listed "
                            "above.\n", overflow, BERT_VERD_MAX);
    }
    free(verd);

    fprintf(stderr, "\n  %-26s %9ld  %6.2f%%\n", "TAGGED (names a format)", st.tagged,
            total ? 100.0 * st.tagged / total : 0.0);
    fprintf(stderr, "  %-26s %9ld  %6.2f%%\n", "PREFIX/SHAPE", st.prefix,
            total ? 100.0 * st.prefix / total : 0.0);
    fprintf(stderr, "  %-26s %9ld  %6.2f%%\n", "DELIMITED (interior sep)", st.delimited,
            total ? 100.0 * st.delimited / total : 0.0);
    fprintf(stderr, "  %-26s %9ld  %6.2f%%\n", "BARE at a digest length", st.digest,
            total ? 100.0 * st.digest / total : 0.0);
    fprintf(stderr, "  %-26s %9ld  %6.2f%%\n", "  of those, also a block mult", st.ambiguous,
            total ? 100.0 * st.ambiguous / total : 0.0);
    fprintf(stderr, "  %-26s %9ld  %6.2f%%\n", "CIPHER? aes-block multiple", st.cipher_aes,
            total ? 100.0 * st.cipher_aes / total : 0.0);
    fprintf(stderr, "  %-26s %9ld  %6.2f%%\n", "CIPHER? des-block multiple", st.cipher_des,
            total ? 100.0 * st.cipher_des / total : 0.0);
    fprintf(stderr, "  %-26s %9ld  %6.2f%%\n", "COMPOSITE (off-list length)", st.composite,
            total ? 100.0 * st.composite / total : 0.0);
    fprintf(stderr, "  %-26s %9ld  %6.2f%%\n", "NOT A HASH", st.nothash,
            total ? 100.0 * st.nothash / total : 0.0);
    fprintf(stderr, "  %-26s %9ld\n", "-- total", total);
    if (st.repaired) fprintf(stderr, "  intake: %ld line(s) had a line terminator stripped\n", st.repaired);
    if (st.hexwrap)  fprintf(stderr, "  intake: %ld line(s) unwrapped from $HEX[]\n", st.hexwrap);

    fprintf(stderr, "\n  bare-hex byte lengths seen:\n");
    for (i = 0; i < 256; i++)
        if (st.bylen[i])
            fprintf(stderr, "    %3d bytes (%3d hex)  %9ld%s\n", i, i * 2, st.bylen[i],
                    Bert_diglen[i] ? "  [a digest length]" : "");
    return 0;
}


/* ============================================================== STAGE 2 ===
 * hid-gate: runtime Phase 2. With a plaintext in hand, VERIFY against every
 * registered type first and do not reduce -- verification is cheaper than the
 * reasoning it would replace (0.009 s for a salted 32-hex pair).
 *
 * THE DEFECT THIS EXISTS TO FIX. hashpipe emits
 *
 *     "no registered type verified these formats"
 *
 * both when a format is genuinely unhandled AND when its only supporting type
 * was skipped for exceeding -L, and it cannot tell them apart. Measured: the
 * same cost-15 bcrypt pair verifies in 1.40 s with -L raised and produces the
 * unhandled-format message under -L 1. An operator reading that message
 * concludes nothing handles bcrypt and goes off to write an hx expression for
 * a type that already works.
 *
 * Modular-crypt formats carry their work factor in the string, so the cap can
 * be COMPUTED rather than guessed, and must be -- otherwise the gate reports an
 * unhandled format where there is only an unaffordable one.
 *
 * This is a wrapper and not a reimplementation: it parses work factors, sets
 * MaxVerifyLimit, and hands the input to hashpipe's own verification path.
 */

#define BERT_CONTINUE (-1)        /* bertillon_main -> "let hashpipe proceed" */

static const char *Bert_gate_file = NULL;

/* itoa64, as phpass/md5crypt count their rounds in. */
/* 2^k without math.h: the only exponential here is a doubling ladder. */
static double bert_pow2(int k)
{
    double v = 1.0;
    while (k > 0) { v *= 2.0; k--; }
    while (k < 0) { v /= 2.0; k++; }
    return v;
}

static int bert_itoa64(int c)
{
    static const char *A = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const char *q = strchr(A, c);
    return q ? (int)(q - A) : -1;
}

/*
 * Estimated worst-case verify seconds for ONE line, from its own stored form.
 * Anchored on a measurement, not a guess: bcrypt cost 15 takes 1.40 s on this
 * machine, and each cost step doubles. Returns 0 for a form that carries no
 * work factor, which is the overwhelming majority.
 */
static double bert_workfactor(const char *line, char *why, size_t whysz)
{
    if (!strncmp(line, "$2", 2) && line[3] == '$' && isdigit((unsigned char)line[4])) {
        int cost = atoi(line + 4);
        if (cost >= 4 && cost <= 31) {
            snprintf(why, whysz, "bcrypt cost %d", cost);
            return 1.40 * bert_pow2(cost - 15);
        }
    }
    if ((!strncmp(line, "$H$", 3) || !strncmp(line, "$P$", 3)) && line[3]) {
        int idx = bert_itoa64((unsigned char)line[3]);
        if (idx >= 7 && idx <= 30) {
            snprintf(why, whysz, "phpass 2^%d rounds", idx);
            /* ~1e7 md5/s single-threaded; 2^19 rounds is still milliseconds. */
            return bert_pow2(idx) / 1.0e7;
        }
    }
    if (!strncmp(line, "$5$rounds=", 10) || !strncmp(line, "$6$rounds=", 10)) {
        long r = atol(line + 10);
        if (r > 0) {
            snprintf(why, whysz, "sha%scrypt %ld rounds", line[1] == '6' ? "512" : "256", r);
            return (double)r / 2.0e6;
        }
    }
    if (!strncmp(line, "$5$", 3) || !strncmp(line, "$6$", 3)) {
        snprintf(why, whysz, "sha%scrypt default 5000 rounds", line[1] == '6' ? "512" : "256");
        return 5000.0 / 2.0e6;
    }
    return 0.0;
}

/*
 * Scan the input once for the worst work factor, then set the cap from it.
 * The cap is ANNOUNCED: a silently chosen limit that turns out too low is
 * indistinguishable, in the output, from a format nothing handles.
 */
static int bert_cmd_gate(const char *path)
{
    FILE *fp;
    char *line = NULL, why[64], worst_why[64] = "";
    size_t cap = 0;
    ssize_t n;
    double worst = 0.0, limit;
    long total = 0, costed = 0;

    if (!path) {
        fprintf(stderr, "bertillon: --gate needs a FILE: the input is scanned for work\n"
                        "factors before it is verified, which a stream cannot be.\n");
        return 2;
    }
    if ((fp = fopen(path, "r")) == NULL) {
        fprintf(stderr, "bertillon: %s: %s\n", path, strerror(errno));
        return 2;
    }
    while ((n = getline(&line, &cap, fp)) > 0) {
        double w;
        bert_repair(line);
        if (!*line) continue;
        total++;
        why[0] = '\0';
        w = bert_workfactor(line, why, sizeof(why));
        if (w > 0.0) costed++;
        if (w > worst) { worst = w; snprintf(worst_why, sizeof(worst_why), "%s", why); }
    }
    fclose(fp); free(line);

    /*
     * Four times the worst single line, floor 10 s. The margin is for machine
     * variation, not for arithmetic: being wrong LOW here silently converts a
     * solvable line into "nothing handles this format", which is the one
     * outcome the gate exists to prevent. Being wrong high costs only patience.
     */
    limit = worst * 4.0;
    if (limit < 10.0) limit = 10.0;
    MaxVerifyLimit = limit;

    fprintf(stderr, "bertillon gate: %ld line(s), %ld carrying a work factor\n", total, costed);
    if (worst > 0.0)
        fprintf(stderr, "bertillon gate: worst is %s, est %.2f s -> -L %.0f\n",
                worst_why, worst, limit);
    else
        fprintf(stderr, "bertillon gate: no parsed work factor -> -L %.0f\n", limit);
    fprintf(stderr, "bertillon gate: if hashpipe now reports that no registered type\n"
                    "bertillon gate: handled a format, the cost limit is not the reason.\n");

    Bert_gate_file = path;
    return BERT_CONTINUE;
}


/* ============================================================== STAGE 5 ===
 * Reduction, in the binary that owns the type table.
 *
 * This belongs here and not in a script reading a generated TSV. bertillon has
 * Hashtypes[] and its rates in memory -- init_rates() has already run by the
 * time the dispatch fires -- so the reduction cannot be stale. A candidate set
 * derived from a file that was generated an unknown number of builds ago can.
 *
 * A TIER IS A BUDGET, NOT A VERDICT. Types outside the band are UNAFFORDABLE:
 * deferred, never eliminated, and always counted on stderr.
 */

enum { BP_APPLICABLE = 0, BP_UNAFFORDABLE, BP_UNSATISFIABLE, BP_INAPPLICABLE, BP_N };
static const char *Bert_part_name[BP_N] =
    { "APPLICABLE", "UNAFFORDABLE", "UNSATISFIABLE", "INAPPLICABLE" };

/*
 * Output format. e-numbers are what mdxfind's -M takes and are the default.
 * The others exist because the same selection is ONE argument for mdxfind and a
 * SEQUENCE OF RUNS for hashcat -- `-m` there accepts exactly one mode -- and a
 * tool that printed only e-numbers would leave the reader to do that
 * translation by hand, with a 1028-row table to do it from.
 */
enum { BE_ENUM = 0, BE_MDX, BE_HASHCAT, BE_CMD, BE_JOHN };
static int   Bert_emit   = BE_ENUM;
static int   Bert_tier   = 0;        /* 0 easy, 1 medium, 2 hard */
static int   Bert_only   = 0;
static int   Bert_trunc  = 0;
static const char *Bert_tier_name[3] = { "easy", "medium", "hard" };

/* The rate the binary itself measured, by internal index. r->id is "e<ti>". */
static long long bert_rate(const struct bert_row *r)
{
    int ti;
    if (r->udef || r->id[0] != 'e') return 0;
    ti = atoi(r->id + 1);
    if (ti < 0 || ti >= Numtypes) return 0;
    return Hashtypes[ti].rate;
}

/*
 * easy    linear, rate >= 1M/s
 * medium  linear, rate >= 10K/s
 * hard    everything else applicable
 *
 * Derived, never curated. MD5DSALT benchmarks at 1.5M/s -- "easy" by rate --
 * and is HARD because it composes its salt from a PAIR, so an n-entry salt file
 * costs n squared. A curated list would have to remember that; a derived band
 * cannot forget it. The salt-combining signal comes from the reference table's
 * salt_rel column ("stored=2x input"), so WITHOUT a --table the expansion class
 * is unknown and every type is assumed linear -- stated, not assumed silently.
 */
static int bert_tier_of(const struct bert_row *r, const char **why)
{
    long long rate = bert_rate(r);
    if (r->salt_rel && strstr(r->salt_rel, "2x")) { *why = "quadratic salt expansion"; return 2; }
    if (rate <= 1)      { *why = "no benchmark rate";  return 2; }
    if (rate >= 1000000){ *why = "linear, >=1M/s";     return 0; }
    if (rate >= 10000)  { *why = "linear, >=10K/s";    return 1; }
    *why = "under 10K/s";
    return 2;
}

static int bert_hex_str(const char *s, int n)
{
    int i;
    if (!n) return 0;
    for (i = 0; i < n; i++) if (!isxdigit((unsigned char)s[i])) return 0;
    return 1;
}

struct bert_red {
    int n[BP_N];
    int trunc, casecut;
    /*
     * Types the chosen output format cannot name. This is not a detail: for a
     * bare 32-hex value the easy tier holds 189 types and only 21 of them have
     * a hashcat mode, so `--emit hashcat` prints 23 numbers and drops 168
     * types. Handed 23 modes with no further word, a reader would reasonably
     * believe the reduction had been covered. Untranslatable is not tested.
     */
    int untranslatable;
    /* Counts per cost band for the rows that pass shape AND operand tests,
     * so the escalation ladder can show a real delta for each rung instead of
     * a boilerplate list of flags. A rung that adds nothing is not offered. */
    int band[3];
    /* Why a row was not tried, in the reader's terms rather than the
     * partition's. */
    int cut_shape, cut_nosalt, cut_wantsalt;
};

/*
 * One target, one reading. `have_salt` says whether the caller is offering a
 * salt operand; it is what separates the two readings of a two-field line.
 */
static void bert_reduce_one(const char *hash, int have_salt, const char *label,
                            const char *prefix, int emit)
{
    int i, hl = (int)strlen(hash), hb = -1, hexish;
    struct bert_red R;
    int first = 1;
    char casenames[256]; int cn = 0;

    memset(&R, 0, sizeof(R));
    casenames[0] = '\0';
    hexish = bert_hex_str(hash, hl);
    if (hexish && (hl % 2) == 0) hb = hl / 2;

    if (emit && prefix) fputs(prefix, stdout);
    if (emit && label)  { fputs(label, stdout); fputc('\t', stdout); }

    for (i = 0; i < Bert_nrows; i++) {
        struct bert_row *r = &Bert_rows[i];
        int part = BP_APPLICABLE;
        const char *why = "";
        int t;

        if (r->udef && !Bert_include_udef) continue;

        if (r->tag[0] && strncmp(hash, r->tag, strlen(r->tag))) { part = BP_INAPPLICABLE; R.cut_shape++; }
        else if (!r->tag[0] && r->d_bytes > 0 && hexish && hb > 0 && r->d_bytes != hb) {
            /* TRUNCATION-ABLE is its own axis: a LONGER digest is reachable if
             * the list carries chopped hashes. Counted, named, never default. */
            if (r->d_bytes > hb) { R.trunc++; if (Bert_trunc) goto keep; }
            part = BP_INAPPLICABLE; R.cut_shape++;
        }
        else if (hexish && !r->tag[0] && r->d_charset
                 && !strcmp(r->d_charset, "hex-lower") && strpbrk(hash, "ABCDEF")) {
            /* Hex CASE is presentation, not algorithm. Tracked apart so an
             * empty result can say "re-run lower-cased" instead of nothing. */
            R.casecut++;
            if (cn < 200) cn += snprintf(casenames + cn, sizeof(casenames) - cn,
                                         "%s%s", cn ? ", " : "", r->name);
            part = BP_INAPPLICABLE;
        }
        else if (hexish && !r->tag[0] && r->d_charset
                 && !strcmp(r->d_charset, "hex-upper") && strpbrk(hash, "abcdef")) {
            R.casecut++;
            if (cn < 200) cn += snprintf(casenames + cn, sizeof(casenames) - cn,
                                         "%s%s", cn ? ", " : "", r->name);
            part = BP_INAPPLICABLE;
        }
        else if (hexish && !r->tag[0] && r->d_charset
                 && strncmp(r->d_charset, "hex", 3)) { part = BP_INAPPLICABLE; R.cut_shape++; }
        else if (!hexish && !r->tag[0] && r->d_charset
                 && !strncmp(r->d_charset, "hex", 3)) { part = BP_INAPPLICABLE; R.cut_shape++; }
        /*
         * OPERAND MISMATCH, and it cuts BOTH WAYS. The first direction is
         * obvious: a salted type with no salt supplied cannot run. The second
         * was missing and is what made this wrong -- when a salt IS supplied,
         * a type that takes NO salt cannot consume it, and under the hash:salt
         * reading the second field would be left unexplained. MD5, MD4, HAV128,
         * RMD128 and ED2K were being returned as candidates for a salted form
         * they cannot express, so supplying a salt only ever ADDED candidates
         * where it should have cut them from 254 to the 78 salt-worthy ones.
         *
         * Both directions exclude the INPUT, not the type: the same type
         * against a differently shaped input applies again.
         */
        else if (strchr(r->flags, 's') && !have_salt) { part = BP_UNSATISFIABLE; R.cut_nosalt++; }
        else if (!strchr(r->flags, 's') && have_salt) { part = BP_UNSATISFIABLE; R.cut_wantsalt++; }
        else {
keep:
            t = bert_tier_of(r, &why);
            if (Bert_only ? (t != Bert_tier) : (t > Bert_tier)) part = BP_UNAFFORDABLE;
            else part = BP_APPLICABLE;
        }

        R.n[part]++;
        if (part == BP_APPLICABLE || part == BP_UNAFFORDABLE) {
            const char *tw;
            int tb = bert_tier_of(r, &tw);
            if (tb >= 0 && tb < 3) R.band[tb]++;
        }
        if (part == BP_APPLICABLE && emit) {
            switch (Bert_emit) {
            case BE_ENUM:
                fputs(first ? "" : ",", stdout); fputs(r->id, stdout); break;
            case BE_MDX: case BE_CMD:
                if (first) fputs(Bert_emit == BE_CMD
                                 ? "mdxfind -h '^(" : "-h '^(", stdout);
                else fputc('|', stdout);
                fputs(r->name, stdout);
                break;
            case BE_HASHCAT: {
                /* A LIST, not a value: hashcat -m takes one mode per run. */
                char hc[64], *tok, *sv = NULL;
                snprintf(hc, sizeof(hc), "%s", r->hashcat);
                if (strcmp(hc, "n/a")) {
                    for (tok = strtok_r(hc, ",", &sv); tok; tok = strtok_r(NULL, ",", &sv))
                        printf("%s\n", tok);
                } else R.untranslatable++;
                break;
            }
            case BE_JOHN: {
                /*
                 * The John table keys on the emitted LABEL, and the iteration
                 * suffix is part of the identity there -- MD5x02 is dynamic_2.
                 * But whether a given type's label CARRIES that suffix is not
                 * predictable from anything visible here: dynamic_0 is MD5x01
                 * and dynamic_6 is MD5SALT, bare. An earlier version derived
                 * the suffix from whether the type has a verify function and
                 * found 11 of the 21 real mappings, silently reporting the
                 * other 10 as having no John name. Try both forms rather than
                 * predict which one applies.
                 */
                /*
                 * JohnMap only. john_map.h carries a SECOND table,
                 * JohnMapLocal[], of config-defined dynamics whose numbering is
                 * local to the machine whose dynamic.conf was read -- its own
                 * header says those rows are for input only and must never be
                 * used to stamp a name on a result. Ten of the types here have
                 * an entry there and are deliberately reported as having no
                 * John name: dynamic_1300 means MD5RAW on one machine and
                 * possibly something else on the reader's.
                 */
                int j, hit = 0;
                char bare[128], iter[128];
                snprintf(bare, sizeof(bare), "%s", r->name);
                snprintf(iter, sizeof(iter), "%sx01", r->name);
                for (j = 0; j < JOHN_MAP_COUNT && !hit; j++)
                    if (!strcmp(JohnMap[j].hptype, bare)
                        || !strcmp(JohnMap[j].hptype, iter)) {
                        printf("%s\n", JohnMap[j].john); hit = 1;
                    }
                if (!hit) R.untranslatable++;
                break;
            }
            }
            first = 0;
        }
    }
    if (emit) {
        if (!first && (Bert_emit == BE_MDX || Bert_emit == BE_CMD))
            fputs(Bert_emit == BE_CMD ? ")$' -f HASHES WORDLIST" : ")$'", stdout);
        /* hashcat and john print one item per line already; a closing
         * newline there adds a blank line and an off-by-one to any
         * caller counting lines. */
        if (Bert_emit != BE_HASHCAT && Bert_emit != BE_JOHN) fputc('\n', stdout);
    }

    /*
     * The receipt answers "what do I run, and what do I do when it fails" --
     * not "what is the state of my partition model". The earlier version led
     * with a triple negation over four internal partition names and mentioned
     * --truncation only as a warning, so every caveat read as a dead end
     * rather than a door. Two lines by default; -v for the full breakdown.
     */
    {
        int ap    = R.n[BP_APPLICABLE];
        int total = R.n[BP_APPLICABLE] + R.n[BP_UNAFFORDABLE]
                  + R.n[BP_UNSATISFIABLE] + R.n[BP_INAPPLICABLE];
        int nottried = total - ap;
        /* Only rungs that actually ADD types are offered. On many targets the
         * hard band contains nothing the medium band did not, and printing it
         * anyway trains people to ignore the list. */
        int dmed  = (Bert_tier < 1) ? R.band[1] : 0;
        int dhard = (Bert_tier < 2) ? R.band[2] : 0;
        char widen[256];
        int w = 0;
        widen[0] = '\0';
        if (dmed)     w += snprintf(widen + w, sizeof(widen) - w,
                                    "%s--tier medium +%d", w ? ", " : "", dmed);
        if (dhard)    w += snprintf(widen + w, sizeof(widen) - w,
                                    "%s--tier hard +%d", w ? ", " : "", dhard);
        if (R.trunc && !Bert_trunc)
                      w += snprintf(widen + w, sizeof(widen) - w,
                                    "%s--truncation +%d", w ? ", " : "", R.trunc);

        fprintf(stderr, "\nbertillon: %d type%s to try (%s%d-char %s%s, %s tier).\n",
                ap, ap == 1 ? "" : "s", label ? "" : "",
                hl, hexish ? "hex" : "non-hex",
                have_salt ? " + salt" : "", Bert_tier_name[Bert_tier]);

        if (ap == 0) {
            fprintf(stderr, "           NOTHING to try -- no type can produce this "
                            "value%s.\n",
                    R.casecut ? " in this letter case" : "");
            if (R.casecut)
                fprintf(stderr, "           %d type%s excluded on hex case alone (%s%s). "
                                "Hex case is\n           presentation, not algorithm: "
                                "lower-case the value and re-run.\n",
                        R.casecut, R.casecut == 1 ? " was" : "s were",
                        casenames, R.casecut > 3 ? ", ..." : "");
        }
        if (R.untranslatable && ap) {
            const char *what = (Bert_emit == BE_HASHCAT) ? "hashcat mode"
                             : (Bert_emit == BE_JOHN)    ? "John format name"
                             : "name in this format";
            fprintf(stderr, "           OF THOSE, %d of %d have no %s and are NOT in\n"
                            "           the list above. Covering what was printed does "
                            "not cover\n           the reduction.\n",
                    R.untranslatable, ap, what);
            if (Bert_emit == BE_JOHN)
                fprintf(stderr, "           Only portable John names are emitted; "
                                "config-defined dynamics\n           are numbered per "
                                "machine and are not safe to name here.\n");
        }
        if (ap == 0) {
            /* handled above */
        } else if (widen[0]) {
            fprintf(stderr, "           widen: %s.  %d not tried%s\n",
                    widen, nottried, Bert_verbose ? ":" : ", -v for why.");
        } else {
            fprintf(stderr, "           no wider tier available.  %d not tried%s\n",
                    nottried, Bert_verbose ? ":" : ", -v for why.");
        }

        if (Bert_verbose) {
            fprintf(stderr, "\n  a negative result covers these %d type%s and no others.\n",
                    ap, ap == 1 ? "" : "s");
            fprintf(stderr, "\n  not tried:\n");
            if (R.cut_shape) {
                fprintf(stderr, "    %5d  cannot produce a %d-character %s form\n",
                        R.cut_shape, hl, hexish ? "hex" : "non-hex");
                /* The truncation-able types are a SUBSET of that shape cut, not
                 * a separate group. Listing both totals without saying so makes
                 * the column add up to more than the population. */
                if (R.trunc && !Bert_trunc)
                    fprintf(stderr, "           of those, %d have a LONGER digest and "
                                    "would apply if these\n           values have been "
                                    "cut short (--truncation)\n", R.trunc);
            }
            if (R.cut_nosalt)
                fprintf(stderr, "    %5d  need a salt, and none was supplied\n", R.cut_nosalt);
            if (R.cut_wantsalt)
                fprintf(stderr, "    %5d  take no salt, and one was supplied\n", R.cut_wantsalt);
            if (R.n[BP_UNAFFORDABLE])
                fprintf(stderr, "    %5d  cost more than the %s tier allows\n",
                        R.n[BP_UNAFFORDABLE], Bert_tier_name[Bert_tier]);
            if (R.casecut)
                fprintf(stderr, "    %5d  emit the other letter case\n", R.casecut);
            if (!Bert_nref)
                fprintf(stderr, "\n  cost tiers are approximate: without --table, types that\n"
                                "  combine salts in pairs are costed as if they did not.\n"
                                "  --table hid-shape.tsv supplies that.\n");
        }
    }
}

/*
 * PHASE 2 INSIDE THE REDUCTION. When a plaintext is present, VERIFY before
 * reducing -- verification is cheaper than the reasoning it would replace, and
 * a verified positive ENDS the question that a candidate set only frames.
 *
 * md5("XN7") is b4135cc539ebbdaa702d3444e7e1d21a. Offered that pair, an earlier
 * version printed 267 candidates across two readings and never mentioned that
 * the answer was one compute away. "SOLVED -- a line on stdout with its type.
 * Done. No reduction was needed and none should be printed." (10a.1b)
 */
static int bert_verify_one(const struct bert_row *r,
                           const char *stored, int storedlen,
                           const char *digest,
                           const unsigned char *pass, int passlen,
                           const unsigned char *salt, int saltlen)
{
    int ti;
    struct hashtype *ht;
    if (r->udef || r->id[0] != 'e') return 0;
    ti = atoi(r->id + 1);
    if (ti < 0 || ti >= Numtypes) return 0;
    ht = &Hashtypes[ti];
    if (ht->verify) {
        /*
         * A verify type parses the STORED FORM itself -- "$2a$10$<salt+digest>"
         * -- and must never be handed the plaintext along with it. Passing the
         * whole "stored:plaintext" line made every verify type fail silently,
         * so bcrypt, phpBB3 and the rest of the tagged families could not be
         * solved at all while the compute types worked.
         */
        char tmp[512];
        if (storedlen >= (int)sizeof(tmp)) return 0;
        memcpy(tmp, stored, storedlen); tmp[storedlen] = '\0';
        return ht->verify(tmp, storedlen, pass, passlen) ? 1 : 0;
    }
    if (((ht->compute && ht->hashlen > 0) || ht->nchain > 0)
        && ht->hashlen <= MAX_HASH_BYTES) {
        unsigned char dest[MAX_HASH_BYTES];
        char hexout[MAX_HASH_BYTES * 2 + 1];
        memset(dest, 0, sizeof(dest));
        hash_compute(ht, pass, passlen, salt, saltlen, dest);
        /*
         * Render in the type's OWN case and compare exactly. The self-test
         * compares case-insensitively, which is right there because every type
         * checks its own vector -- but a gate that ignores case makes MD5UC
         * verify a lower-case digest, and hashpipe's real path reports only
         * MD5. MD5 and MD5UC are separate registered types precisely because
         * the case is part of the stored form.
         */
        if (ht->flags & HTF_UC) prmd5UC(dest, hexout, ht->hashlen * 2);
        else                    prmd5(dest, hexout, ht->hashlen * 2);
        hexout[ht->hashlen * 2] = '\0';
        return strcmp(hexout, digest) == 0;
    }
    return 0;
}

/*
 * Verify the candidates for one reading. Returns the count that verified and
 * prints each as hashpipe itself would. The set tried is the shape-APPLICABLE
 * set, so the negative it licenses is bounded by that and the caller says so.
 */
static int bert_gate_reading(const char *whole, const char *stored,
                             const char *digest,
                             const unsigned char *pass, int passlen,
                             const unsigned char *salt, int saltlen,
                             int have_salt, int *ntried)
{
    int i, hits = 0, tried = 0, sl = (int)strlen(stored);
    struct workspace *ws = (struct workspace *)calloc(1, sizeof(*ws));
    if (!ws) return 0;
    ws->testvec = malloc(TESTVECSIZE + 16);
    ws_init_rhash(ws);
    WS = ws;
    for (i = 0; i < Bert_nrows; i++) {
        struct bert_row *r = &Bert_rows[i];
        if (r->udef) continue;
        /* Only the shape-compatible, operand-compatible candidates. */
        if (r->tag[0] && strncmp(stored, r->tag, strlen(r->tag))) continue;
        /* The operand test applies only where the salt is a SEPARATE FIELD. A
         * tagged or verify type carries its salt inside the stored form and
         * takes no salt operand, so testing it against have_salt excluded every
         * one of them. */
        if (!r->tag[0] && !Hashtypes[atoi(r->id + 1)].verify
            && !!strchr(r->flags, 's') != !!have_salt) continue;
        tried++;
        if (bert_verify_one(r, stored, sl, digest, pass, passlen, salt, saltlen)) {
            /*
             * An IDENTIFICATION, deliberately NOT a found line.
             *
             * A verified pair is not a found (7g), and this tool is explicitly
             * not a founds harvester. Emitting hashpipe's "MD5x01 hash:pass"
             * shape would invite mdsplit to ingest it, and getting the suffix
             * wrong splits the ledger: the same recovered hash filed under
             * MD5SALT by one tool and MD5SALTx01 by another. An attempt at
             * reproducing that suffix here got MD5SALT wrong on the first try,
             * which is reason enough not to reproduce it at all. Founds come
             * from hashpipe and mdxfind, which own the format.
             *
             * TSV, because the separator this whole exercise distrusts is the
             * colon, and a stored form is full of them.
             */
            printf("VERIFIED\t%s\t%s\n", r->id, r->name);
            fflush(stdout);          /* keep the answer ahead of the receipt */
            hits++;
        }
    }
    WS = NULL;
    ws_free_rhash(ws);
    free(ws->testvec);
    free(ws);
    if (ntried) *ntried = tried;
    return hits;
}


/*
 * A FILE names a list, not a hash. Without this check "bertillon list165.orig"
 * reduced the PATH -- a 17-character non-hex string -- and returned 17 types
 * with perfect confidence, having never opened the file.
 *
 * The answer for a list is the MODAL line shape. Sampled by floor (n >= 4.6/p,
 * independent of list size) and never with head: large lists are ordered by
 * source, so the first n lines are the least representative n in the file. A
 * handful of damaged lines -- list165 has six, at lengths 0, 5, 8, 19, 24 and
 * 33 among 6.3 million at 32 -- must not move the answer, and a modal choice
 * over a uniform sample cannot be moved by them.
 */
#define BERT_SAMPLE 4601

static int bert_looks_like_path(const char *t)
{
    static const char *const ext[] = { ".txt",".lst",".hash",".hashes",".orig",
                                       ".found",".pot",".csv",".dat",".list", NULL };
    size_t n = strlen(t);
    int i;
    if (strchr(t, '/')) return 1;
    for (i = 0; ext[i]; i++) {
        size_t e = strlen(ext[i]);
        if (n > e && !strcasecmp(t + n - e, ext[i])) return 1;
    }
    return 0;
}

static int bert_modal_line(const char *path, char *out, size_t outsz,
                           long *nsampled, int *nshapes, long *nlines)
{
    FILE *fp = fopen(path, "r");
    char *ln = NULL, **keep;
    size_t cap = 0;
    ssize_t n;
    long seen = 0;
    int i, k = 0, best = -1, bestn = 0, distinct = 0;
    unsigned seed = 20260920u;

    if (!fp) return 0;
    keep = (char **)calloc(BERT_SAMPLE, sizeof(*keep));
    if (!keep) { fclose(fp); return 0; }

    while ((n = getline(&ln, &cap, fp)) > 0) {
        bert_repair(ln);
        if (!*ln) continue;
        seen++;
        if (k < BERT_SAMPLE) keep[k++] = strdup(ln);
        else {
            /* Reservoir: uniform over the whole file in one pass, no seek and
             * no prior knowledge of the line count. */
            seed = seed * 1103515245u + 12345u;
            { long j = (long)((seed >> 16) % (unsigned long)seen);
              if (j < BERT_SAMPLE) { free(keep[j]); keep[j] = strdup(ln); } }
        }
    }
    fclose(fp); free(ln);
    if (!k) { free(keep); return 0; }

    /*
     * Group by (field count, field-0 length, field-0 is hex). The hex term was
     * described here but never implemented, and it is not cosmetic: 50 hex and
     * 50 non-hex values of the same length and field count reported as ONE form
     * and reduced on whichever the sample happened to hold first -- 189 types
     * or 17, from the same file, decided by line order. Precomputed per line so
     * the comparison is a struct match rather than a re-parse.
     */
    {
        int *fc = (int *)calloc(k, sizeof(int));
        int *f0 = (int *)calloc(k, sizeof(int));
        int *hx = (int *)calloc(k, sizeof(int));
        if (!fc || !f0 || !hx) { free(fc); free(f0); free(hx);
                                 for (i = 0; i < k; i++) free(keep[i]);
                                 free(keep); return 0; }
        for (i = 0; i < k; i++) {
            char *c = strchr(keep[i], ':');
            int nf = 1;
            for (c = keep[i]; *c; c++) if (*c == ':') nf++;
            c = strchr(keep[i], ':');
            fc[i] = nf;
            f0[i] = c ? (int)(c - keep[i]) : (int)strlen(keep[i]);
            hx[i] = bert_hex_str(keep[i], f0[i]);
        }
        for (i = 0; i < k; i++) {
            int j, cnt = 0;
            for (j = 0; j < k; j++)
                if (fc[j] == fc[i] && f0[j] == f0[i] && hx[j] == hx[i]) cnt++;
            if (cnt > bestn) { bestn = cnt; best = i; }
        }
        for (i = 0; i < k; i++) {
            int j, dup = 0;
            for (j = 0; j < i; j++)
                if (fc[j] == fc[i] && f0[j] == f0[i] && hx[j] == hx[i]) { dup = 1; break; }
            if (!dup) distinct++;
        }
        free(fc); free(f0); free(hx);
    }
    snprintf(out, outsz, "%s", keep[best]);
    for (i = 0; i < k; i++) free(keep[i]);
    free(keep);
    *nsampled = k; *nshapes = distinct; *nlines = seen;
    return 1;
}

/* Field count selects the reading, and the input selects it -- never a flag. */
static void bert_reduce_target(const char *line, const char *prefix, int emit)
{
    const char *c1 = strchr(line, ':');
    char hash[512];
    size_t hl;

    hl = c1 ? (size_t)(c1 - line) : strlen(line);
    if (hl >= sizeof(hash)) hl = sizeof(hash) - 1;
    memcpy(hash, line, hl); hash[hl] = '\0';

    if (!c1) {                                   /* one field: REDUCE */
        bert_reduce_one(hash, 0, NULL, prefix, emit);
        return;
    }
    if (!strchr(c1 + 1, ':')) {
        /*
         * Two fields are AMBIGUOUS between hash:plaintext and hash:salt and the
         * tool must not guess -- the discriminator is not in the line. But one
         * of the two readings CAN be settled outright: if field 2 is the
         * plaintext, verification answers yes or no in microseconds. Gate that
         * reading first and reduce only on failure.
         */
        int tried = 0;
        int hits = bert_gate_reading(line, hash, hash,
                                     (const unsigned char *)(c1 + 1),
                                     (int)strlen(c1 + 1), NULL, 0, 0, &tried);
        if (hits) {
            fprintf(stderr, "\nbertillon: SOLVED as hash:plaintext -- %d type(s) "
                            "verified of %d tried.\n", hits, tried);
            if (hits > 1)
                /*
                 * Say what happened, in words that stand on their own. The
                 * earlier wording ("that is 7l, not an error") cited a section
                 * of a design document the reader has never seen, and described
                 * the result in the vocabulary of the process that produced it
                 * rather than the vocabulary of hashes. Internal reasoning
                 * belongs in comments like this one; output belongs to whoever
                 * is reading it.
                 */
                fprintf(stderr, "  %d types produce identical hash results for "
                                "this input.\n", hits);
            /*
             * DONE. "SOLVED -- a line on stdout with its type. Done. No
             * reduction was needed and none should be printed." (10a.1b)
             *
             * An earlier version printed the answer and then dumped the
             * hash:salt reading's full partition census underneath it, on the
             * theory that the reading might be rejected. It is redundant: the
             * pair verified, so the alternative reading is a hypothesis nobody
             * needs, and burying a one-line answer under twenty lines of
             * partition arithmetic is how a tool teaches people to stop reading
             * its output.
             */
            return;
        }
        /*
         * The gate still runs -- a file of hash:plaintext pairs should solve,
         * and it costs microseconds -- but its FAILURE is not news. Nobody
         * proposed that field 2 was a plaintext; for a list of unsolved hashes
         * it plainly is not, and announcing the refutation of an unasked
         * question is noise ahead of the answer. The count is kept under -v,
         * where it still bounds what was eliminated.
         */
        if (Bert_verbose)
            fprintf(stderr, "\nbertillon: field 2 is not the plaintext -- %d type%s "
                            "tried, none matched.\n", tried, tried == 1 ? "" : "s");
        bert_reduce_one(hash, 1, "hash:salt", prefix, emit);
        return;
    }
    {
        /* Three fields: salt AND plaintext are both in hand. Gate outright. */
        const char *c2 = strchr(c1 + 1, ':');
        char salt[256];
        size_t sl = (size_t)(c2 - c1 - 1);
        int tried = 0, hits;
        if (sl >= sizeof(salt)) sl = sizeof(salt) - 1;
        memcpy(salt, c1 + 1, sl); salt[sl] = '\0';
        {   /* A verify type wants "digest:salt" as its stored form; a compute
             * type wants the digest with the salt as a separate operand. */
            char sf[600];
            size_t n2 = (size_t)(c2 - line);
            if (n2 >= sizeof(sf)) n2 = sizeof(sf) - 1;
            memcpy(sf, line, n2); sf[n2] = '\0';
            hits = bert_gate_reading(line, sf, hash,
                                     (const unsigned char *)(c2 + 1), (int)strlen(c2 + 1),
                                     (const unsigned char *)salt, (int)sl, 1, &tried);
        }
        if (hits) {
            fprintf(stderr, "\nbertillon: SOLVED -- %d type(s) verified of %d tried. "
                            "No candidate set.\n", hits, tried);
            if (hits > 1)
                fprintf(stderr, "  %d types produce identical hash results for "
                                "this record.\n", hits);
            return;
        }
        fprintf(stderr, "\nbertillon: not solved -- %d type%s tried, none matched. "
                        "Either the fields\n           are assigned wrongly, or the "
                        "construction is not registered.\n", tried, tried == 1 ? "" : "s");
        bert_reduce_one(hash, 1, "hash:salt:plaintext", prefix, emit);
    }
}


/* ============================================================== PROFILE ===
 * What a LIST says that a single line cannot.
 *
 * A hash taken over one concatenated byte string does not record where the
 * salt ended and the password began, so for n bytes of concatenated material
 * there are n+1 readings in each direction and the line cannot choose between
 * them. One real 57-byte record admitted 116 labellings and every one of them
 * verified. What chooses is the LIST: if a single string is the salt in 315,145
 * of 315,146 records, it is the installation's salt and the boundary is known.
 *
 * Salt cardinality is why this lives in the binary rather than a script: at
 * 9.9M records with 830k distinct salts it wants a real string-keyed map, and
 * hashpipe already links and uses JudySL.
 */

#define BERT_AFFIX_SAMPLE 4601   /* floor for p=0.001; see the sampling note */

/* (94/95)^L -- the fraction of random printable salts of length L that contain
 * no colon. Field count is NOT an invariant of a salted list: at L=30 more than
 * a quarter of a perfectly intact file carries an "extra" field by
 * construction, and calling that corruption misreads most of it. */
static double bert_conform_pred(int L)
{
    double v = 1.0;
    int i;
    for (i = 0; i < L && i < 4096; i++) v *= (94.0 / 95.0);
    return v;
}

static char *bert_field(const char *line, int n, char *out, size_t outsz)
{
    const char *p = line, *q;
    int i;
    for (i = 0; i < n; i++) {
        q = strchr(p, ':');
        if (!q) { out[0] = '\0'; return out; }
        p = q + 1;
    }
    q = strchr(p, ':');
    { size_t len = q ? (size_t)(q - p) : strlen(p);
      if (len >= outsz) len = outsz - 1;
      memcpy(out, p, len); out[len] = '\0'; }
    return out;
}

/* Longest string shared by every sampled value, from the right or the left. */
static int bert_common_affix(char **v, int n, int suffix, char *out, size_t outsz)
{
    int k, i;
    if (n < 3) return 0;
    k = (int)strlen(v[0]);
    for (i = 1; i < n; i++) {
        int m = (int)strlen(v[i]);
        if (m < k) k = m;
        while (k > 0) {
            const char *a = suffix ? v[0] + strlen(v[0]) - k : v[0];
            const char *b = suffix ? v[i] + strlen(v[i]) - k : v[i];
            if (!memcmp(a, b, (size_t)k)) break;
            k--;
        }
        if (!k) return 0;
    }
    if ((size_t)k >= outsz) k = (int)outsz - 1;
    memcpy(out, suffix ? v[0] + strlen(v[0]) - k : v[0], (size_t)k);
    out[k] = '\0';
    return k;
}

static int bert_cmd_profile(const char *path)
{
    FILE *fp;
    char *ln = NULL;
    size_t cap = 0;
    ssize_t n;
    long total = 0, crlf = 0, cr = 0, hexwrap = 0, trail = 0, bslash = 0, blank = 0;
    long nfields[64], w_n[512];
    long shape_n = 0;
    int i, modal_nf = 0, modal_w = -1;
    long withsalt = 0, distinct = 0, topn = 0;
    char topsalt[512];
    char **samp = NULL;
    int nsamp = 0;
    unsigned seed = 20260921u;
    Pvoid_t salts = (Pvoid_t)NULL;
    Word_t *PV;

    memset(nfields, 0, sizeof(nfields));
    memset(w_n, 0, sizeof(w_n));
    topsalt[0] = '\0';

    if (!path) {
        fprintf(stderr, "bertillon: --profile needs a FILE: a list is the subject.\n");
        return 2;
    }
    if ((fp = fopen(path, "r")) == NULL) {
        fprintf(stderr, "bertillon: %s: %s\n", path, strerror(errno));
        return 2;
    }
    samp = (char **)calloc(BERT_AFFIX_SAMPLE, sizeof(*samp));
    if (!samp) { fclose(fp); perror("bertillon: calloc"); return 2; }

    /* Pass 1: damage, field counts, field-1 widths, and a uniform sample of
     * last fields for the boundary test. */
    while ((n = getline(&ln, &cap, fp)) > 0) {
        int nf = 1, w;
        char *c;
        size_t L;
        if (n >= 2 && ln[n-2] == '\r' && ln[n-1] == '\n') crlf++;
        else if (n >= 2 && ln[n-2] != '\r' && ln[n-1] == '\n') { }
        bert_repair(ln);
        L = strlen(ln);
        if (!L) { blank++; continue; }
        if (strchr(ln, '\r')) cr++;
        total++;
        if (!strncmp(ln, "$HEX[", 5) && ln[L-1] == ']') hexwrap++;
        if (ln[L-1] == ' ' || strstr(ln, " :")) trail++;
        if (strstr(ln, "\\\\") || strstr(ln, "\\'")) bslash++;
        for (c = ln; *c; c++) if (*c == ':') nf++;
        if (nf < 64) nfields[nf]++;
        if (nf > 1) {
            char f1[512];
            bert_field(ln, 1, f1, sizeof(f1));
            w = (int)strlen(f1);
            if (w < 512) w_n[w]++;
            {   /* reservoir over the LAST field, $HEX[] unwrapped first */
                char lastf[1024];
                char *lastc = strrchr(ln, ':');
                snprintf(lastf, sizeof(lastf), "%s", lastc ? lastc + 1 : ln);
                bert_unhex(lastf);
                if (nsamp < BERT_AFFIX_SAMPLE) samp[nsamp++] = strdup(lastf);
                else {
                    seed = seed * 1103515245u + 12345u;
                    { long j = (long)((seed >> 16) % (unsigned long)total);
                      if (j < BERT_AFFIX_SAMPLE) { free(samp[j]); samp[j] = strdup(lastf); } }
                }
            }
        }
    }
    fclose(fp);

    for (i = 0; i < 64; i++) if (nfields[i] > shape_n) { shape_n = nfields[i]; modal_nf = i; }
    { long best = 0;
      for (i = 0; i < 512; i++) if (w_n[i] > best) { best = w_n[i]; modal_w = i; } }

    /* Pass 2: salt cardinality, over lines whose field 1 is the MODAL WIDTH.
     * Keying on width and not on field count is the whole trick: an extra field
     * can come from a separator in the salt OR in the password, and only the
     * first makes field 1 a fragment. List 56 settles it -- 282 of its records
     * carry colons in the PASSWORD while their 48-byte salt is intact, and
     * excluding those for field count undercounts the site salt by exactly 282. */
    if (modal_w > 0) {
        fp = fopen(path, "r");
        if (fp) {
            while ((n = getline(&ln, &cap, fp)) > 0) {
                char f1[512];
                bert_repair(ln);
                if (!*ln || !strchr(ln, ':')) continue;
                bert_field(ln, 1, f1, sizeof(f1));
                if ((int)strlen(f1) != modal_w) continue;
                withsalt++;
                JSLI(PV, salts, (unsigned char *)f1);
                if (PV) {
                    if (*PV == 0) distinct++;   /* a fresh key comes back zero */
                    (*PV)++;
                    if ((long)*PV > topn) {
                        topn = (long)*PV;
                        snprintf(topsalt, sizeof(topsalt), "%s", f1);
                    }
                }
            }
            fclose(fp);
        }
    }
    free(ln);

    /* ------------------------------------------------------------ report */
    printf("%s -- %ld lines\n", path, total);

    printf("\n  INTAKE\n");
    if (crlf || cr || hexwrap || trail || bslash || blank) {
        if (crlf)    printf("    %8ld  CRLF line endings\n", crlf);
        if (cr)      printf("    %8ld  stray carriage return\n", cr);
        if (hexwrap) printf("    %8ld  wrapped in $HEX[]\n", hexwrap);
        if (trail)   printf("    %8ld  trailing space (a padded database column?)\n", trail);
        if (bslash)  printf("    %8ld  doubled backslashes (SQL escaping?)\n", bslash);
        if (blank)   printf("    %8ld  blank\n", blank);
        printf("    Fix these before anything else. A list with CRLF endings read\n");
        printf("    against an LF wordlist matches NOTHING, for the whole file, and\n");
        printf("    looks exactly like the wrong wordlist.\n");
    } else {
        printf("    no line-ending, padding or escaping damage found\n");
    }

    printf("\n  FIELD COUNT\n");
    printf("    most common     : %d field(s) in %ld of %ld lines (%.2f%%)\n",
           modal_nf, shape_n, total, total ? 100.0 * shape_n / total : 0.0);
    if (modal_w > 0) {
        double conf = total ? 100.0 * shape_n / total : 0.0;
        double pred = 100.0 * bert_conform_pred(modal_w);
        double resid = conf - pred;
        printf("    salt width      : %d\n", modal_w);
        printf("    expected        : %.2f%% of lines would have %d fields if the\n",
               pred, modal_nf);
        printf("                      salts were random printable text of that length\n");
        printf("    difference      : %+.2f points\n", resid);
        if (resid <= 1.0 && resid >= -1.0)
            printf("    -> As expected. The odd lines are salts that happen to contain a\n"
                   "       colon, not damage. A reader that demands a fixed field count\n"
                   "       would silently discard %.1f%% of this file.\n", 100.0 - conf);
        else if (resid < -1.0)
            printf("    -> FEWER conforming lines than colons in salts can explain.\n"
                   "       Something else is in this file; it is worth looking at.\n");
        else
            printf("    -> MORE conforming lines than that would predict, so the salts\n"
                   "       are not random printable text: a fixed salt, or one drawn\n"
                   "       from a restricted set such as hex, never contains a colon.\n"
                   "       The prediction does not apply here; nothing is wrong.\n");
    }

    printf("\n  FIELD BOUNDARY\n");
    if (nsamp < 3) {
        printf("    %d record(s): too few to say. A single line cannot settle where\n", nsamp);
        printf("    the salt ends and the password begins.\n");
    } else {
        char aff[600];
        int k = bert_common_affix(samp, nsamp, 1, aff, sizeof(aff));
        int shortest = (int)strlen(samp[0]), q;
        if (k < 8) k = bert_common_affix(samp, nsamp, 0, aff, sizeof(aff));
        for (q = 1; q < nsamp; q++)
            if ((int)strlen(samp[q]) < shortest) shortest = (int)strlen(samp[q]);
        /*
         * A shared run that IS the whole field is a field every record holds in
         * common -- a site-wide salt sitting correctly in its own column. A
         * shared run that is a PROPER part of a longer, varying field is a salt
         * folded into something else. Field count cannot tell these apart:
         * both are two-field lines. An earlier version gated on field count and
         * reported a correctly laid out hash:salt list as damaged, then, when
         * that was gated out, missed the real folded-salt case, which is also
         * two fields.
         */
        if (k >= 8 && k >= shortest) {
            printf("    every last field is the same %d bytes:\n", k);
            printf("      %.64s\n", aff);
            printf("    -> One value shared by every record, in a field of its own.\n");
            printf("       That is a salt where it belongs, not a misplaced split.\n");
            printf("       See SALT REUSE below.\n");
        } else if (k >= 8) {
            printf("    every last field ends or begins with the same %d bytes:\n", k);
            printf("      %.64s\n", aff);
            printf("    -> That string is on EVERY record, so it is not part of anyone's\n");
            printf("       password: it is a salt that has been folded into the password\n");
            printf("       field. These records are filed under the wrong split. They\n");
            printf("       will still verify, which is why verifying cannot catch it.\n");
        } else {
            printf("    no common run of 8+ bytes across %d last fields: no sign the\n", nsamp);
            printf("    boundary is misplaced. That is not proof it is right.\n");
        }
    }

    printf("\n  SALT REUSE\n");
    if (!withsalt) {
        printf("    no second field: nothing to say about salts\n");
    } else {
        double ratio = (double)topn / (double)withsalt;
        printf("    records         : %ld (those whose salt is the usual %d bytes)\n",
               withsalt, modal_w);
        printf("    distinct salts  : %ld\n", distinct);
        printf("    most common     : %ld record(s), %.4f%%\n", topn, 100.0 * ratio);
        if (ratio > 0.5) {
            printf("      %.48s\n", topsalt);
            printf("    -> ONE SALT FOR THE WHOLE SITE. Every record shares it, so the\n");
            printf("       boundary between salt and password is known, and that single\n");
            printf("       fact settles a reading the individual lines cannot. Say that\n");
            printf("       this is what decided it: \"it verifies\" does not decide\n");
            printf("       anything, because the reading you are replacing verified too.\n");
        } else if (distinct >= withsalt * 9 / 10) {
            printf("    -> A SALT PER USER, near enough all different. Reuse cannot fix\n");
            printf("       the boundary here, but a constant width can, and the width is\n");
            printf("       %d bytes on %ld of %ld records.\n", modal_w, w_n[modal_w], withsalt);
        } else {
            printf("    -> Neither one salt nor one per user. Look before assuming a\n");
            printf("       single field model covers the file.\n");
        }
    }
    { Word_t fr; JSLFA(fr, salts); (void)fr; }
    for (i = 0; i < nsamp; i++) free(samp[i]);
    free(samp);
    return 0;
}

/* ------------------------------------------------------------- the driver */

static void bert_usage(FILE *fp)
{
    fprintf(fp,
"bertillon -- identify which hash types could have produced a value.\n"
"\n"
"  bertillon [TARGET ...]              (simplest form: type numbers, no flags)\n"
"  bertillon [-r] [TARGET ...] [-t easy|medium|hard] [-o] [-T] [-b REF.tsv]\n"
"        Identify which hash types could have produced these values, sorted\n"
"        into easy, medium and hard tiers by how expensive each is to test.\n"
"\n"
"        A TARGET is either\n"
"          a VALUE   hash, hash:salt, or hash:salt:plaintext, or\n"
"          a FILE    containing such values one per line, from which the\n"
"                    hash type(s) are identified.\n"
"\n"
"        How many colon-separated fields a value has decides how it is read.\n"
"        Two fields could be hash:salt or hash:plaintext and nothing in the\n"
"        line says which, so both are tried. Reads stdin when no TARGET is\n"
"        given.\n"
"        -e, --emit FORMAT   what to print. A value may be given in full or by\n"
"                            its first letter, so -e h is -e hashcat.\n"
"             enum  (e)  type numbers, as mdxfind -M takes them (default)\n"
"             mdx   (m)  a ready mdxfind -h selection argument\n"
"             hashcat (h) hashcat -m modes, ONE PER LINE, because -m takes one\n"
"                        mode per run where mdxfind takes a set\n"
"             john  (j)  John format names, one per line\n"
"             cmd   (c)  a runnable mdxfind command line\n"
"\n"
"        hashcat and John name far fewer constructions than mdxfind does, so\n"
"        those two formats cannot express every type in a selection. The count\n"
"        they drop is reported: covering what is printed does not cover the\n"
"        reduction.\n"
"\n"
"        Selection to stdout, the summary to stderr. Each tier includes\n"
"        the cheaper ones unless --only. A tier is a budget, not a verdict:\n"
"        types outside it are untested, not ruled out.\n"
"\n"
"        Short forms: -t tier, -e emit, -o only, -T truncation, -b table,\n"
"        -f form, -p profile, -g gate, -r reduce, -v verbose. So\n"
"        `bertillon -t e -e h list.txt` is the whole of --tier easy\n"
"        --emit hashcat.\n"
"\n"
"  bertillon -g, --gate FILE\n"
"        Verify hash:plaintext pairs against every registered type.\n"
"        Computes -L from each line's own parsed work factor first, because\n"
"        hashpipe reports a cost-skipped type and an unhandled format with the\n"
"        same message, and the two need different next actions.\n"
"\n"
"  bertillon -p, --profile FILE\n"
"        What the LIST says that one line cannot: damage in the file, whether\n"
"        an odd field count is real or just salts containing a colon, whether\n"
"        a salt has been folded into the password field, and how far the salts\n"
"        are reused. One salt shared by every record settles a reading that no\n"
"        single line can.\n"
"\n"
"  bertillon -f, --form [FILE] [--summary]\n"
"        For each input line: is it a hash at all, and does it name its own\n"
"        format. Each distinct answer once with its count, commonest first,\n"
"        to stdout; the totals to stderr. Reads stdin when no FILE is given.\n"
"        --per-line gives one line out per line in, --summary the totals\n"
"        alone. No type lists, no verification.\n"
"\n"
"  bertillon --emit-table [REFERENCE.tsv]\n"
"        Measure every type this binary knows and write the table. With a\n"
"        REFERENCE, compare against it and stay silent when nothing moved.\n"
"        Without one, write it unconditionally.\n"
"\n"
"        exit 0   compared, identical (row count to stderr)\n"
"        exit 1   compared, differs -- new table to stdout, diagnosis to stderr\n"
"        exit 2   could not compare -- reference absent, unreadable, malformed\n"
"\n"
"  The salt_ceiling, salt_rel, field2_is_salt, n_acceptors and collides_with\n"
"  columns are copied from the reference unchanged; this binary does not\n"
"  measure them -- tools/bertillon-probe does, and that run takes about 35\n"
"  minutes. --emit-table itself is immediate.\n"
"\n"
"  The reference path is always explicit: there is no default location and no\n"
"  search path. A tool that silently reads an unexpected file changes behaviour\n"
"  invisibly.\n"
"\n"
"  Types from your own userdef.txt are not listed: they depend on your setup,\n"
"  not on this build. --include-userdef adds them, with their measured\n"
"  columns left blank.\n"
"\n"
"  Reached as `bertillon` (a symlink to hashpipe) or as `hashpipe -Z ...`.\n");
}

/*
 * Short forms. The argv[0] namespace exists so these can be chosen for this
 * tool rather than inherited from hashpipe, and the commonest invocation is a
 * tier and a format, which spelled out is 34 characters of flags before the
 * filename. Every value in both enumerations has a distinct first letter --
 * enum/mdx/hashcat/john/cmd and easy/medium/hard -- so a single letter names
 * any of them without ambiguity.
 */
static int bert_opt(const char *a, const char *shrt, const char *lng)
{
    return (shrt && !strcmp(a, shrt)) || (lng && !strcmp(a, lng));
}

/* Accept a full value or its first letter. Returns -1 if it matches neither. */
static int bert_val(const char *a, const char *const *names, int n)
{
    int i;
    for (i = 0; i < n; i++)
        if (!strcmp(a, names[i]) || (a[0] == names[i][0] && !a[1])) return i;
    return -1;
}

static int bertillon_main(int argc, char **argv)
{
    const char *ref = NULL;
    int i, emit = 0, shape = 0, gate = 0, per_line = 0, summary_only = 0, rc;
    int reduce = 0, profile = 0, ntargets = 0;
    char *targets[256];

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--emit-table")) emit = 1;
        else if (bert_opt(argv[i], "-f", "--form")) shape = 1;
        else if (bert_opt(argv[i], "-p", "--profile")) profile = 1;
        else if (bert_opt(argv[i], "-g", "--gate")) gate = 1;
        else if (bert_opt(argv[i], "-r", "--reduce")) reduce = 1;
        else if (bert_opt(argv[i], "-o", "--only")) Bert_only = 1;
        else if (bert_opt(argv[i], "-T", "--truncation")) Bert_trunc = 1;
        else if (bert_opt(argv[i], "-e", "--emit") && i + 1 < argc) {
            static const char *const fmts[] = { "enum","mdx","hashcat","cmd","john" };
            int k = bert_val(argv[++i], fmts, 5);
            if (k < 0) {
                fprintf(stderr, "bertillon: -e enum|mdx|hashcat|john|cmd "
                                "(or e|m|h|j|c)\n"); return 2;
            }
            Bert_emit = (k == 0) ? BE_ENUM : (k == 1) ? BE_MDX
                      : (k == 2) ? BE_HASHCAT : (k == 3) ? BE_CMD : BE_JOHN;
        }
        else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) Bert_verbose = 1;
        else if (bert_opt(argv[i], "-b", "--table") && i + 1 < argc) ref = argv[++i];
        else if (bert_opt(argv[i], "-t", "--tier") && i + 1 < argc) {
            static const char *const tiers[] = { "easy","medium","hard" };
            int k = bert_val(argv[++i], tiers, 3);
            if (k < 0) {
                fprintf(stderr, "bertillon: -t easy|medium|hard (or e|m|h)\n"); return 2;
            }
            Bert_tier = k;
        }
        else if (!strcmp(argv[i], "--summary")) summary_only = 1;
        else if (!strcmp(argv[i], "--per-line")) per_line = 1;
        else if (!strcmp(argv[i], "--include-userdef")) Bert_include_udef = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { bert_usage(stdout); return 0; }
        else if (argv[i][0] == '-') {
            fprintf(stderr, "bertillon: unknown option \"%s\"\n", argv[i]);
            bert_usage(stderr); return 2;
        }
        else if (ntargets < 256) targets[ntargets++] = argv[i];
        else { fprintf(stderr, "bertillon: too many targets\n"); return 2; }
    }
    /* A lone non-option argument is the reference table for --emit-table, and a
     * target everywhere else. */
    if ((emit || gate || shape || profile) && !ref && ntargets) { ref = targets[0]; ntargets = 0; }
    if (!emit && !shape && !gate && !reduce && !profile) reduce = 1;
    if (emit || shape) Bert_verbose = 1;
    if (profile) return bert_cmd_profile(ref);
    if (gate) return bert_cmd_gate(ref);

    /* Both modes need the derived digest-length set, and both derive it the
     * same way from the same table. */
    bert_walk_types(bert_collect, NULL);
    bert_phase0();

    if (shape) {
        /* bert_phase0() already printed the derived set; saying it twice is
         * just noise in front of the census. */
        return bert_cmd_shape(ref, summary_only ? -1 : per_line);
    }

    {
        int unc = 0, n = 0;
        for (i = 0; i < Bert_nrows; i++) {
            if (Bert_rows[i].udef && !Bert_include_udef) continue;
            n++; unc += Bert_rows[i].parse_uncertain;
        }
        if (Bert_verbose)
            fprintf(stderr, "bertillon: %d type(s), %d with an uncertain parse\n", n, unc);
    }

    if (Bert_include_udef) {
        int nu = 0;
        for (i = 0; i < Bert_nrows; i++) nu += Bert_rows[i].udef;
        if (nu)
            fprintf(stderr, "bertillon: WARNING: %d user-defined type(s) included with "
                            "EMPTY derived columns -- stage A cannot measure an hx "
                            "expression. Do not commit this table.\n", nu);
    }
    if (reduce) {
        /* Optional reference: supplies the stage B/C columns, which is where
         * the expansion class lives. Without it the reduction still runs and
         * says what it does not know. */
        if (ref && bert_load_ref(ref) == 0) {
            for (i = 0; i < Bert_nrows; i++) {
                struct bert_ref *rr = bert_find(Bert_rows[i].name);
                if (!rr) continue;
                Bert_rows[i].salt_ceiling = rr->col[11];
                Bert_rows[i].salt_rel     = rr->col[12];
                Bert_rows[i].n_acceptors  = rr->col[14];
                Bert_rows[i].collides_with= rr->col[15];
            }
        }
        if (ntargets) {
            for (i = 0; i < ntargets; i++) {
                char pre[600], modal[1024];
                const char *use = targets[i];
                long ns = 0, nl = 0; int nsh = 0;
                pre[0] = '\0';
                /*
                 * A target with a path separator that names no file is almost
                 * always a mistyped path, and the old behaviour was to reduce
                 * the path STRING and answer with confidence. Say so instead.
                 * A base64 stored form can contain '/', so this warns and
                 * proceeds rather than refusing.
                 */
                /*
                 * A target that names no readable file but looks like a
                 * filename is a typo, and reducing the NAME answers with
                 * confidence about nothing. The first version tested only for a
                 * path separator, so "saltd.txt" in the right directory still
                 * got through silently -- which is the likelier typo of the
                 * two. Extensions are checked as well. A warning, not a
                 * refusal: a stored form can legitimately contain a dot.
                 */
                if (access(targets[i], R_OK) != 0 && bert_looks_like_path(targets[i]))
                    fprintf(stderr, "bertillon: \"%s\" looks like a path but no such "
                                    "file is readable;\n           treating it as a hash "
                                    "value. Check the name.\n", targets[i]);
                if (bert_modal_line(targets[i], modal, sizeof(modal), &ns, &nsh, &nl)) {
                    use = modal;
                    fprintf(stderr, "bertillon: %s -- %ld lines, %ld sampled, "
                                    "%d different form%s\n", targets[i], nl, ns, nsh,
                                    nsh == 1 ? "" : "s");
                    if (nsh > 1)
                        fprintf(stderr, "           identifying the most common form; "
                                        "the other %d %s not covered here.\n",
                                        nsh - 1, nsh == 2 ? "is" : "are");
                }
                /* Follow grep: one target bare, many prefixed, separator TAB. */
                if (ntargets > 1) snprintf(pre, sizeof(pre), "%s\t", targets[i]);
                bert_reduce_target(use, ntargets > 1 ? pre : NULL, 1);
            }
        } else {
            char *ln = NULL; size_t cap = 0; ssize_t n; long seen = 0;
            while ((n = getline(&ln, &cap, stdin)) > 0) {
                bert_repair(ln);
                if (!*ln) continue;
                seen++;
                bert_reduce_target(ln, NULL, 1);
            }
            free(ln);
            if (!seen) { bert_usage(stderr); return 2; }
        }
        return 0;
    }

    if (!ref) { bert_emit(stdout); return 0; }

    rc = bert_load_ref(ref);
    if (rc == 2) {
        fprintf(stderr, "bertillon: no comparison performed\n");
        return 2;                       /* never conflated with "nothing moved" */
    }
    /* Carry the stage B/C/join columns forward, so the emitted table is a
     * complete replacement rather than one with five columns silently blanked. */
    for (i = 0; i < Bert_nrows; i++) {
        struct bert_ref *r = bert_find(Bert_rows[i].name);
        if (!r) continue;
        Bert_rows[i].salt_ceiling  = r->col[11];
        Bert_rows[i].salt_rel      = r->col[12];
        Bert_rows[i].field2_is_salt= r->col[13];
        Bert_rows[i].n_acceptors   = r->col[14];
        Bert_rows[i].collides_with = r->col[15];
    }
    rc = bert_compare();
    {   int n = 0;
        for (i = 0; i < Bert_nrows; i++)
            if (!Bert_rows[i].udef || Bert_include_udef) n++;
        if (rc == 0) {
            /* Silence, but a PROVABLE silence: the count is what makes "clean"
             * distinguishable from "never ran". */
            fprintf(stderr, "bertillon: %d rows compared against %s, identical\n", n, ref);
            return 0;
        }
        bert_emit(stdout);
        fprintf(stderr, "bertillon: %d rows compared against %s, differences above\n", n, ref);
    }
    return 1;
}

/*
 * Selection. argv[0] so that the option namespace is bertillon's own and can
 * be redefined while the interface is still being discovered; -Z so that a host
 * missing the symlink is never stuck. Detection runs before hashpipe's getopt
 * (which would reject --emit-table); the CALL runs after the type table is
 * built, because that is what bertillon measures.
 */
static int bertillon_detect(int argc, char **argv)
{
    const char *b = argv[0], *p;
    int i;
    for (p = argv[0]; *p; p++) if (*p == '/') b = p + 1;
    if (!strcmp(b, "bertillon") || !strcmp(b, "berti")) {
        Bert_mode = 1; Bert_argc = argc; Bert_argv = argv; return 1;
    }
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-Z")) {            /* hand off the remainder */
            Bert_mode = 1; Bert_argc = argc - i; Bert_argv = argv + i;
            Bert_argv[0] = (char *)"bertillon";
            return 1;
        }
        if (!strcmp(argv[i], "--")) break;
    }
    return 0;
}

#endif /* BERTILLON_H */
