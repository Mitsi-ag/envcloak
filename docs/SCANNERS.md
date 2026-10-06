# Bounded local scanners

M2-12 supplies read-only scanner APIs for doctor, import, migrate-mcp and
scrub. Command integration remains with those tasks. The caller hardens its
process before reading, installs the wiping allocator, builds approved sources
from `envcloak_agents::locations`, and sends distinct candidates only through
the daemon's purpose-constrained comparison API. No scanner compares vault
values, executes profile contents, rewrites files, or grants cleanup authority.

`scan_profiles` and `scan_config_sources` return a `ScanReport`, rather than the
plan's sketch `Vec<Found>`, so partial findings and refusals cannot disappear.
`complete()` is derived from its issues each time. `notes` lists existing
credential and database stores deliberately outside scanner coverage; notes
alone do not make a report incomplete. Absent optional stores produce neither
notes nor issues. Unsafe or unreadable paths still produce issues. Display paths and names must
pass the CLI's existing masking renderer; internal ranges, stamps, values and
object identifiers are not report fields. Input-holding types have value-free
Debug implementations. A consumer must treat an error or an incomplete report
as incomplete, even if another file produced findings.

Below each approved root, reads use held directory descriptors and no-follow,
nonblocking opens; traversal never crosses mount points. Only regular files
owned by the current user are read. Symlinks, non-regular files and unreadable
paths are reported. Hard links are reported even when their contents can be
read, and do not grant modification permission. Profile and config files have
a 1 MiB cap. Catalog roots accept only the root-owned macOS `/tmp`, `/var`
and `/etc` aliases with their fixed `/private` targets. User-controlled links
remain refused. Device checks apply both during discovery and at the actual
read, including plain metadata files.

Catalog entries retain distinct selectors and reader formats when their paths
overlap. Failed filesystem reads are cached separately from parser outcomes.
Database and credential omissions apply before readable sources in either
catalog order, including indirect `envFile` reads; sibling logs remain eligible.
Directory attempts consume the file budget even when empty.

Profiles cover the seven conventional shell files, literal `source`/`.` paths
within the supplied home root, at most four source edges and 64 attempted paths,
including missing conventional profiles and failed includes. Attempts and their
failures are reused within one run, and recomputed on the next run. Once a
budget is exhausted, remaining includes do not create unbounded diagnostics.
Only `$HOME` and `~` path prefixes expand. Assignments never execute. Dollar or
backtick values contribute names only after syntax validation; comments do
not affect value classification. POSIX quoting preserves Bash's ordinary
double-quoted backslashes and CRLF bytes. Unquoted parentheses, including
arrays, are manual; quoted and escaped parentheses remain literal. Fish's
supported subset is a single literal word in `set -x`, `-gx`, `-Ux`, `-xg` or
`-xU`. Lists, command and arithmetic substitutions, context-dependent expansion
and unsupported commands are manual. Multiline assignments may supply values but
cannot supply whole-line removal permission. Any unsupported syntax in a file
removes automatic line-removal eligibility from its findings. M2-16 still has
to satisfy every delete-plaintext gate before editing anything.

JSON and TOML configs inspect MCP `env`/`environment`, `headers`/`http_headers`,
`auth` and `envFile` beneath `mcpServers`, `mcp_servers`, `mcp` or `servers`,
plus top-level `env` settings. Both formats retain `args` literals with a manual
disposition. The common config contract treats `${NAME}`, `${NAME:-default}`
and `envcloak://` as names-only references. Other dollar bytes remain literal;
unsupported braced syntax is manual with an issue. This conservative contract
does not imply that every host interpolates these references.

YAML produces an unsupported-format issue. Existing credential and database
stores are noted without parsing contents. `envFile` directives stay distinct
from bindings with that name. Included paths stay within the descriptor's
approved root, use the dotenv reader, and consume the same byte and finding
budgets. Template filenames such as `.env.example` contribute names only;
unresolved include references produce `unread_env_file`. Candidate and
occurrence limits bound config findings during accumulation, conservatively
counting bindings before value de-duplication. CodexBar's documented
provider key fields are inspected through provider-config descriptors, never
registered as MCP servers. Host paths live only in the catalog.

JSONL is streamed with an 8 MiB line cap. An oversized line is counted and
skipped, and later lines are still scanned. Invalid JSON, invalid text and
oversized tokens produce fixed reasons. Strings are decoded with raw offsets
for their escape sequences. Tokens of at least 16 characters yield raw,
base64, hex and percent-decoded candidates, with a 4 KiB candidate cap. Raw
stores use the same token rules without JSON decoding. Each bounded token
retains its whole spelling, plus ASCII punctuation-trimmed and
punctuation-separated readings, assignment right-hand sides and query values. Short JSON strings
also retain whole-string and whitespace-word readings. URL user information,
Go DSN passwords and `password`/`passwd`/`pwd` connection fields carry their
specific password forms to the daemon, including on decoded readings.
Alternatives are capped at 256 per reading; exhausting this or an emission
budget makes the report incomplete. Binary boundaries record `invalid_text`
while still scanning adjacent UTF-8 text.

Whole JSON sources, including host backups, decode as documents within the
1 MiB config cap. Malformed documents get a raw fallback and an `invalid_json`
issue, so fallback never reports complete. JSONL falls back to raw readings on
a damaged line with the same visible issue. Structured transcript descriptors
take precedence over overlapping raw coverage, so each physical leaf is read
once. Conflicting JSON and JSONL descriptors report partial coverage. JSON
readers scan strings; this does not promise raw readings of numeric JSON scalars.
Assignment and query readings are bounded by words and URL fragments while
retaining internal punctuation. Equals-run lookahead is linear; overlapping
password lookahead has a linear work allowance and reports `reading_budget`
when exhausted.

This is a bounded tokenizer, not a complete shell or connection-string parser.
Raw values spanning whitespace, dialect-specific backslash or doubled-quote
escapes, nested encodings and every interpretation of ambiguous punctuation
are not reconstructed. Readings may overlap. Scrub must use confirmed,
non-overlapping ranges or a structured rewrite, never replace every alternative. Decoded runs are marked
not directly rewritable: a base64 run may contain more than the matched value.
A read file's stamp travels with occurrences; a change during the read makes
the scan incomplete. Scrub must re-check that stamp at use.

`Candidates` uses a new random BLAKE3 key for each run. Each distinct value and
form has one id. `Candidates::new` retains every accepted range for scrub.
`Candidates::counted` instead retains a count per candidate and source (file or
Git object), without ranges or rewrite authority. Doctor callers should use
`Budget::for_counts()` for both the stream and collector. Repeated readings then
consume no additional retained path or range record.

Default limits are 1 GiB read, two million distinct candidates, four million
emissions and retained records, 10,000 source entries and 100,000 Git objects.
Count mode raises the emission allowance to 128 million, keeping the other
limits. The retained-record cap applies to candidate/source pairs in count mode.
At the denser host's measured 12,700 tokens/MiB and two readings per token
(docs/AGENTS.md), four million emissions reach about 157 MiB; 128 million reach
about 5,039 MiB, beyond the 1 GiB byte limit. Actual reach depends on token shape,
unique candidates and source count; hitting any cap remains incomplete.
A synthetic 32 MiB stream at that density with two distinct readings retained
two count records versus 812,800 range records; peak RSS on arm64 macOS was
about 3 MiB versus 121 MiB. This is a repeated-value measurement, not a bound for
unique values. Limits are injectable in tests.
A failed config read reserves its allowance against the byte budget; the report's
byte count includes that conservative charge. No entry is evicted. A refused
callback stops scanning with a reason. Callers
share one collector and divide the byte budget across sources. JSON duplicate
keys are refused and nesting and node counts are bounded.

Git history is opt-in. An absolute `/usr/bin/git` runs `cat-file
--batch-all-objects --batch` with a cleared environment, global/system config
disabled, replacement objects disabled and fsmonitor disabled. An explicit
Git directory and work tree relative to the held root prevent discovery of a
parent repository, including after a rename. Working trees and bare
repositories are covered. The held root supplies the child's working directory.
Bytes and objects are bounded, stderr is discarded, and an owned-child deadline caps the whole Git subprocess at
30 seconds, including time spent making progress. Larger histories may therefore
be incomplete. Blobs, commits and annotated tags are scanned; recoverable token
issues are retained while later objects are still read. Object ranges
are distinct from file ranges and never authorize rewriting history. Git owns
the interpretation of the repository's object database, including its linked
object stores; this reader makes no working-tree filesystem-safety claim about
git's internal traversal.

Possible restore leftovers match both `.<name>.envcloak-new-<hex>.tmp` and
`.<name>.envcloak-swap-<hex>.tmp`, including non-env configs and transcripts.
Discovery checks metadata only, reports unreadable/oversized/unsafe candidates,
and never reads contents to infer ownership. Foreign files with the same shape
are reported too. M2-20 and M2-22 consume this result after both successful and
refused undo; cleanup and those command-level reports belong to those tasks.

The tests use the independent cycle200 Bash corpus, Python JSON/encoding output,
real git objects, and the pinned Claude Code and Codex CLIs and transcript
stores. CodexBar is a documentation-derived fixture. Bounded proptest targets
cover profile, config and transcript parsers, including planted values in
errors, Debug, reports and captured process channels. The independent cycle432
JSON/encoding oracle checks 37 cases and 100,080 ranges with ordinary reads and
seven-byte chunks, including matching occurrence counts before normalization.
It does not qualify scrub rewrites. The milestone hardening task owns
longer fuzz campaigns. Gate 11 checks profile, JSON and JSONL buffers without allocator-assisted
wiping as well as under the production wiping allocator. TOML's library parser
is covered under the production allocator, including its failure paths.
