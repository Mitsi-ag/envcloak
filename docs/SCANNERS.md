# Bounded local scanners

M2-12 supplies read-only scanner APIs for doctor, import, migrate-mcp and
scrub. Command integration remains with those tasks. The caller hardens its
process before reading, installs the wiping allocator, builds approved sources
from `envcloak_agents::locations`, and sends distinct candidates only through
the daemon's purpose-constrained comparison API. No scanner compares vault
values, executes profile contents, rewrites files, or grants cleanup authority.

`scan_profiles` and `scan_config_sources` return a `ScanReport`, rather than the
plan's sketch `Vec<Found>`, so partial findings and refusals cannot disappear.
`complete()` is derived from its issues each time. Display paths and names must
pass the CLI's existing masking renderer; internal ranges, stamps, values and
object identifiers are not report fields. Input-holding types have value-free
Debug implementations. A consumer must treat an error or an incomplete report
as incomplete, even if another file produced findings.

Below each approved root, reads use held directory descriptors and no-follow,
nonblocking opens; traversal never crosses mount points. Only regular files
owned by the current user are read. Symlinks, non-regular files and unreadable
paths are reported. Hard links are reported even when their contents can be
read, and do not grant modification permission. Profile and config files have
a 1 MiB cap.

Profiles cover the seven conventional shell files, literal `source`/`.` paths
within the supplied home root, at most four source edges and 64 readable files.
Only `$HOME` and `~` path prefixes expand. Assignments never execute. Dollar or
backtick values contribute names only. POSIX quoting preserves Bash's ordinary
double-quoted backslashes and CRLF bytes. Fish's supported subset is a single
literal word in `set -x NAME value`. Lists, context-dependent expansion and
unsupported commands are manual. Multiline assignments may supply values but
cannot supply whole-line removal permission. Any unsupported syntax in a file
removes automatic line-removal eligibility from its findings. M2-16 still has
to satisfy every delete-plaintext gate before editing anything.

JSON and TOML configs inspect MCP `env`/`environment`, `headers`/`http_headers`,
`auth` and `envFile`. References contribute names only. JSON `args` literals
carry a manual disposition. YAML and credential databases are reported without
being parsed. `envFile` paths stay within the descriptor's approved root, use
the dotenv reader, and consume the same byte budget. CodexBar's documented
provider key fields are inspected through provider-config descriptors, never
registered as MCP servers. Host paths live only in the catalog.

JSONL is streamed with an 8 MiB line cap. An oversized line is counted and
skipped, and later lines are still scanned. Invalid JSON, invalid text and
oversized tokens produce fixed reasons. Strings are decoded with raw offsets
for their escape sequences. Tokens of at least 16 characters yield raw,
base64, hex and percent-decoded candidates, with a 4 KiB candidate cap. Raw
stores use the same token rules without JSON decoding. Each bounded token
retains its whole spelling, plus punctuation-trimmed and punctuation-separated
readings, assignment right-hand sides and query values. Short JSON strings
also retain whole-string and whitespace-word readings. URL user information,
Go DSN passwords and `password`/`passwd`/`pwd` connection fields carry their
specific password forms to the daemon, including on decoded readings.
Alternatives are capped at 256 per reading; exhausting this or an emission
budget makes the report incomplete. Binary boundaries record `invalid_text`
while still scanning adjacent UTF-8 text.

This is a bounded tokenizer, not a complete shell or connection-string parser.
Raw values spanning whitespace, dialect-specific backslash or doubled-quote
escapes, nested encodings and every interpretation of ambiguous punctuation
are not reconstructed. Readings may overlap. Scrub must use confirmed,
non-overlapping ranges or a structured rewrite, never replace every alternative. Decoded runs are marked
not directly rewritable: a base64 run may contain more than the matched value.
A read file's stamp travels with occurrences; a change during the read makes
the scan incomplete. Scrub must re-check that stamp at use.

`Candidates` uses a new random BLAKE3 key for each run. Each distinct value and
form has one id and every occurrence remains recorded. Default limits are
1 GiB read, two million distinct candidates, four million occurrence records,
10,000 source entries and 100,000 git objects. Limits are injectable in tests.
A failed config read reserves its allowance against the byte budget; the report's
byte count includes that conservative charge. No entry is evicted. A refused
callback stops scanning with a reason. Callers
share one collector and divide the byte budget across sources. JSON duplicate
keys are refused and nesting and node counts are bounded.

Git history is opt-in. An absolute `/usr/bin/git` runs `cat-file
--batch-all-objects --batch` with a cleared environment, global/system config
disabled, replacement objects disabled and fsmonitor disabled. The held root
supplies the child's working directory. Bytes and objects are bounded, stderr
is discarded, and an owned-child deadline caps the whole Git subprocess at
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
cover profile, config and transcript parsers; the milestone hardening task owns
longer fuzz campaigns. Gate 11 uses the production wiping allocator, including
library TOML parsing and its failure paths.
