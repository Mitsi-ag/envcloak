# M2-14 validation

Qualification date: 2026-10-07. Worktree branch: `m2/m2-14`.
Platform: macOS, Darwin 25.4.0, arm64; Rust 1.98.1.

## Scope and requirements

| ID | Implementation and evidence |
| --- | --- |
| Gate 36, R-M2-83 | Metadata-only human/JSON grammar, no guessable matches, no MCP doctor tool, clean output with a positive leak control; CLI gates and serializer-authored story. |
| R-M2-36 | CLI builds the catalog descriptors; dotenv, profiles and includes, provider configs including CodexBar, backups, transcripts, explicit paths and opt-in Git history. Source-kind integration tests and inherited scanner suites. |
| R-M2-37 | Count-only keyed de-duplication, typed `scan.match`, value-free paths, slugs, counts and provider-pattern unknowns. Exact report fields, hostile-name masking and independent count oracle. |
| R-M2-38 | `purpose: doctor` on every batch; daemon's character and server-password floor applies to terminal and agent callers. Short ASCII, multibyte and F-65 raw connection-string and extracted-field fixtures. The 1 GiB test checks one terminal run and two runs under one agent root. |
| R-M2-39 | Embedded registry key-page links precede scrub and its encrypted-backup instruction. Mutable item links are never used. |
| R-M2-40 | Matched items are marked exposed, including transcripts, historical Git blobs, config backups and explicitly selected synced paths. Lock-before-mark returns incomplete. A new scan after rotation recomputes matches. |
| R-M2-41 | CLI-owned scanner reads, inherited descriptor/no-follow checks, bounded streaming, template omissions, explicit network/synced opt-in and reported skips. Overlapping paths count once. |
| R-M2-79, T-11 | Tracer refusal precedes catalog inspection or plaintext reads; startup hardening is inherited. Wiping candidates move into typed IPC without a new expose site. Linux first-read test has an atime positive control; native Linux execution remains for CI. |

The JSON contract is unchanged from the plan. Scans reconnect after reading large
stores, batch both candidate count and byte size, and refresh display metadata
after matching and exposure writes. Failure paths cannot claim completion.
No dependency, IPC schema, daemon comparison budget or expose allowlist changed.

## Mutation receipts

Every mutation was restored. Exit 101 below means an assertion failed, not a
compile failure. Ignored local logs are under `.collab/m2-14/`.

| Mutation | Test and observed failure |
| --- | --- |
| Leave key-shaped path components unmasked | Client `report_masks_hostile_metadata_and_keeps_only_the_schema`: the canary sweep detects the path value. |
| Increment count-mode occurrences twice | Scanner `doctor_counts_match_the_independent_json_oracle`: 200160 against the independent 100080 expectation. |
| Lower the daemon's character floor from 16 to 8 | CLI `gate36_report_grammar_floor_exposure_and_output_sweep`: a guessable item is reported. |
| Print `line 1` in human reports | The same CLI grammar gate rejects the extra line. |
| Exit zero for an incomplete report | CLI `bounded_transcripts_report_incomplete`: status 0 instead of 1. |
| Advertise doctor in MCP tools/list | CLI `doctor_is_absent_from_mcp`: the actual tool response contains doctor. |
| Send import purpose from doctor | The report gate fails when the terminal comparison admits a guessable value. |
| Map connection-password form to raw | The strengthened report gate finds an extra item for a field that libpq decodes to 15 characters. |
| Disable the keyed de-duplication lookup | The corrected 1 GiB gate fails after 177.00 seconds: the terminal run returns `incomplete: limited`. Source restored byte-for-byte to the successful baseline. |
| Discard every scan.match result | Story `doctor::gate36_doctor_story`: expected slug is absent (`null`). The restored story passes. |

The non-UTF-8 regression first failed because the old doctor-stub routing
ignored arguments (exit 1 instead of 2). Removing that routing made it pass.

## Independent checks and limits

The adopted cycle432 Python oracle supplies 37 independently serialized cases
and 100080 expected occurrences. Count-only adoption retains no ranges, checks
counts by source and preserves the oracle's fixed, non-echoing failure codes.
This is scanner/report evidence, not scrub-preview or filesystem-write evidence.
The two existing libpq-oracle tests also passed, using the counts captured from
libpq itself for full strings and isolated password fields.

The 1 GiB JSONL workload uses the denser M2-04 pinned-host measurement recorded
in `docs/AGENTS.md`: 12787 tokens/MiB versus approximately 12700 measured, with
1996800 distinct candidates (1950/MiB versus approximately 2000 measured).
A cardinality control proves that one synthetic word emits one identity.
The candidate/comparison ceilings stay at two million. No real host transcript
or credential is used by the corrected fixture.

Cycle470/471 provider-endpoint and broker diagnostic proposals remain unexecuted
research. This task preserves explicit `not_scanned` results and does not add
provider inference, broker contact, network diagnostics or stronger claims.

## Local checks

- Full client and scanner suites: 243 passed, zero failed or ignored.
- Full CLI suite except the separately run 1 GiB case: 231 passed and one stale
  help snapshot failed. After updating the snapshot, all five snapshot tests
  passed. The strengthened report grammar also passed separately.
- Final strict workspace/all-target Clippy passed with `RUSTFLAGS="-D warnings"`.
- Format, unsafe boundary, exposure lint (6/6 canaries), compiler source audit,
  crate graph (50 edges, 21 crates) and reservations (262 rows, 17 tables) passed.
- Corrected 1 GiB gate: passed in 2290.65 seconds for all three scans. The
  terminal and first agent runs completed; the second run under the same agent
  root returned exit 1 and `incomplete: limited`. Disabling de-duplication on
  that corrected fixture failed the gate after 177.00 seconds. Its restored
  source hashes match the successful baseline; the long workload was not
  repeated after the mutation.
- After the final mutations and restoration: all 11 smaller doctor tests and
  the end-to-end doctor story passed, followed by strict Clippy and every
  check script above. The source hashes were checked after each mutation.
- Aggregate CLI coverage is 233 tests, including the separately run large
  workload and the corrected help snapshot. The E2E run covers the doctor
  story only; unrelated host and story modules belong to CI.

Builds use lane E, incremental compilation off and three build jobs. Tests use
three test threads and `--no-fail-fast`, in a double-forked session with a cleared
environment. Test processes use isolated short `/tmp` HOME/XDG roots. The lint
canary's hardcoded target path is routed by an ignored worktree symlink into E.
The full workspace test suite was not run on this shared laptop. No new
dependencies were added; the plan section 6 full platform suite and `cargo deny`
remain CI checks.

Native Linux tracer execution and its remove-refusal mutation remain for the
plan section 6 platform CI matrix. The test is present, but this Mac provides no
Linux runtime evidence. No local result claims qualification on Linux, real
host activation, service-manager installation, or scrub rewriting.

## Failed setup attempts

The first large fixture used an invalid whitespace-only final JSONL record.
A later punctuation-bearing token also emitted an extra candidate reading and
correctly exhausted the budget. Those runs are not evidence for the corrected
workload or its required de-duplication mutation. The final fixture has a valid
null record and an explicit single-identity control. Candidate batches were
also enlarged within the existing IPC count and frame bounds.

One early missing-path test omitted `CLAUDE_CODE_TMPDIR` and may have read host
temporary output before its 60-second timeout. No file contents were printed.
The test now overrides that variable into its isolated root; every doctor
invocation was audited for the override, and the smaller suite was rerun.
That failed attempt is retained here rather than described as isolated.
