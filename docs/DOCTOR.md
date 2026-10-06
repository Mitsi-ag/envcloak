# Doctor

`envcloak doctor [--json] [--path <path>]... [--git-history]` finds plaintext
copies of secrets. Unlock the vault first. Rotation is the first remedy;
`envcloak scrub` is offered second, with an encrypted backup before rewriting.
Doctor does not rewrite a source file and is never an MCP tool.

The CLI reads dotenv files under HOME and the current directory, shell profiles
and their supported sourced files, and the agent catalog's configuration,
backup, history and transcript stores. This includes CodexBar's provider config.
`--path` adds a file or directory, including a transcript store outside the
catalog. Relative paths are relative to the current directory. Git history is
read only with `--git-history`. Gemini may automatically load a project's dotenv
file; a clean local scan does not establish what a running host already loaded.

Before any store is inspected, doctor refuses a tracer. CLI startup disables
core dumps and, on Linux, makes the process non-dumpable. The scanners use held
directory handles, no-follow opens and regular-file ownership checks. They do
not wait on FIFOs or read devices. Symlinks, unreadable paths, hard links and
unsupported formats are reported. A skipped endpoint is not evidence that a
particular credential provider owns it. Host credential stores and databases
remain explicitly not scanned. No external broker, network or cloud API is
contacted to diagnose a store.

Candidates stay in wiping storage. A per-run random keyed index removes
repeated candidates; count mode retains accepted readings per file or Git
object, without offsets. The CLI sends bounded batches to the verified daemon
with `purpose: doctor`. Only the daemon compares them with the vault. It counts
characters as the destination server reads them: fewer than 16 characters,
without a registry key pattern, cannot match, even for a terminal prover.
This includes short multibyte text and short passwords inside connection
strings. Unknown keys are identified by the embedded provider registry.

The report contains item slugs, sanitized display paths, counts and registry
rotation links. It contains no values, snippets, line numbers, offsets, object
identifiers or comparison hashes. Counts describe accepted candidate readings,
not unique secret fields. The JSON fields are `items` (slug, places, rotate_url),
`unknown` (provider, places), `not_scanned` (display_path, reason) and
`incomplete` (null or a fixed reason). Each place has display_path and count.
A provider without an embedded key-page link has a null rotate_url.

Findings are marked exposed in the vault, including transcripts, prompt history,
configuration backups, Git objects and explicitly scanned synced paths. The
mark is bound to the values held by the item when the daemon marks it; rotation
clears it only when no covered value remains. A failed exposure write or an item
removed before marking makes the run incomplete. Each invocation rebuilds its
matches and metadata; no previous report is reused.

Doctor allows at most 2 GiB of source bytes per run, two million distinct
candidate/form identities, 128 million candidate emissions, four million
retained candidate/source pairs and 10,000 discovered entries per scanner pass.
Profiles also have their scanner's include and byte bounds. Individual dotenv
and configuration files are capped at 1 MiB; JSONL lines at 8 MiB. These are
ceilings, not a promise that every input shape fits. No bounded collection
evicts entries to claim completion. The daemon separately limits each subject
root to two million non-guessable comparisons per awake hour. Duplicates consume
one comparison per scan, but another invocation compares them again.

A bound, malformed input, unreadable selected store, comparison refusal or
failed exposure write produces `incomplete` and exit 1. Deliberately uncovered
stores remain in `not_scanned`; they do not by themselves make a successful
scan incomplete. `doctor: complete` means the selected supported inputs were
processed within the bounds, not that no secret exists elsewhere. Copies sent
to providers, backups outside the selected roots, snapshots, terminal scrollback,
indexes and a running agent's memory remain outside this report.

The 1 GiB regression uses synthetic JSONL at 12,787 tokens/MiB, slightly above
M2-04's denser pinned-host measurement of 12,700 tokens/MiB in docs/AGENTS.md.
It repeats 1,996,800 distinct candidates, 1,950 per MiB against the measured
approximate 2,000 per MiB. That stays just below the two-million comparison
ceiling: one run fits the daemon's hour budget;
two runs from one fixture-agent root exceed it. This is a measured-density
synthetic workload, not a universal performance claim or a new host measurement.
The independent cycle432 JSON oracle supplies 37 cases and 100,080 expected
occurrences for count-mode verification.
