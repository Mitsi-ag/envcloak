# M2-22 validation

The task follows SPEC 6.4 and 6.5, plan D-02/D-07/D-16/D-32, review rows
12 and 32, F-75 and the scan-purpose refinement. Requirements in scope are
R-M2-39, R-M2-40, R-M2-44 through R-M2-47, R-M2-79 and R-M2-84 (gate 37).

Implementation uses range-mode scanner candidates and daemon `scan.match`
with purpose `scrub`. Plans coalesce exact duplicate observations, retain
repeated physical occurrences and refuse an affected file on conflicting
spans, unsupported encoded readings, missing stamps or incomplete scanning.
Whole decoded tokens can be replaced; a matched substring inside a longer
encoded run cannot. JSON and JSONL are parsed again before publication.

Scrub streams an encrypted backup before writing, marks confirmed items for
rotation before rename, and records the resulting SHA-256 before reporting
success. New temporary files contain only the scrubbed output. Unlike the
shared restore transaction, scrub does not move the original into a swap
name. It implements SPEC's final stamp check followed by rename and directory
fsync. A competing rename inside that syscall interval is not excluded.

Undo displays the sealed creator before reading a proof and opens one restore
lease. It uses `restore_over_left`; an edit since scrub refuses the restore.
Explicit `--unrecorded` recovery takes the current digest as the expected
replacement target and still uses the same guarded restore. Unknown and agent
creators require `--created-by-agent`. The existing `files.show` metadata
handler required a narrow extension from first-run backups to single-file
scrub backups; its proof-origin and creator-origin checks are unchanged.

The independent Cycle570 fragment emitter and checker is copied, without its
reference planner, to `crates/envcloak-scan/tests/oracles/scrub_plan.py`.
`tests/scrub_oracle.rs` adapts public synthetic observations to the actual
planner and preview. Python retains the independently emitted expectations
and parses the accepted JSONL. All 15 groups, 22 files, and both enumeration
orders are exercised. Synthetic completeness and source-binding facts at the
adapter boundary do not qualify filesystem or scanner provenance; the native
and CLI gates test those separately. The older Cycle432 range oracle remains
in the scanner suite. Its blanket assertion that every decoded token was
non-rewritable is replaced by paired whole-token/embedded-run controls.

Tests run detached with cleared environments and isolated short temporary
homes. Build target is `/Volumes/KeenShiftDev/tmp/envcloak-target/E`,
incremental compilation is off, build jobs and test threads are limited to 3.
No host credentials or agent stores are read by the tests.
The local run is dated 2026-10-08 on macOS 26.4.1 (25E253), arm64, with
rustc 1.98.1 (48a229cea, 2026-09-01).

## Receipts

Gate tests were added before the corresponding implementation. The initial
planner failed to compile without `scrub`. The first CLI run stopped at the
harness's stale-daemon guard and is not property evidence. Each row below was
then exercised with a compiling product mutation, observed failing, and
restored. A compiler error or timeout is not counted as mutation evidence.
Test names below omit the common `gate37_` prefix.

| Tests | Named mutation caught |
| --- | --- |
| `plan_preserves_occurrences_coalesces_duplicates_and_accepts_adjacency` | Drop repeated occurrences after deduplication |
| `plan_refuses_overlap_stale_and_nonrewritable_provenance` | Accept overlaps; ignore stale stamps; promote unsupported readings |
| `json_preview_preserves_escape_boundaries_and_refuses_invalid_json` | Skip JSON boundary and parse validation |
| `recent_linked_and_stale_sources_refused` | Skip the two-minute rule |
| `atomic::tests::gate37_scrub_exclusive_staging_and_ctime_recheck` | Remove `O_EXCL`; ignore ctime differences |
| `apply_streams_only_scrubbed_temporary_bytes_and_keeps_mode` | Copy raw matched bytes to output |
| `whole_encoded_tokens_rewrite_but_embedded_runs_remain_manual` | Deny whole encoded-token rewrite |
| `open_elsewhere_refuses_aged_source_with_a_closed_control` | Skip open-file detection |
| `independent_fragment_oracle_forward_and_reverse` | Drop repeated occurrences |
| `cli_rewrites_marks_and_undoes_with_one_proof` | Skip rotation marking; skip backup commit |
| `short_values_untouched_output_swept_and_later_edits_refuse_undo` | Send `purpose: import`; ignore post-scrub digest |
| `agent_backup_requires_explicit_creator_tick` | Automatically tick agent restore consent |
| `kill_at_every_pause_leaves_whole_files_and_no_temporary_exposure` | Stage original JSON bytes instead of markers |
| `recent_live_writer_symlink_and_failed_backup_never_succeed` | Skip the two-minute rule in the real CLI |
| `scrub_backup_retention_is_seven_days_by_an_independent_clock` | Extend retention to fourteen days |
| `256_mib_undo_uses_one_argon2id_run_and_restores_exact_digest` | Open two restore proofs; measured two Argon2id runs |
| `failed_result_record_never_reports_success_and_unrecorded_needs_ack` | Ignore result-recording failure |
| `confirmation_rechecks_matches_and_never_uses_stale_items` | Omit publication-time match revalidation |
| `leftovers_reported_on_undo_success_and_refusal_without_deleting_foreign_files` | Hide discovered leftovers; restore the old inconsistent completion flag |
| `python_encoded_jsonl_is_scrubbed_and_remains_valid` | Disable encoded-token redaction |
| `scrub::gate37_scrub_story` | Retain original JSON bytes; the unfiltered exposure sweep fails |

The kill gate covers all six barriers, including committed backup, staged
output, final stamp check, rename and result recording. It checks every
temporary sibling for the generated canary. The backup directory is swept
separately. The real CLI story also has a raw-count exposure positive control
before scrub and after undo. No detector removes its own hits.

The short-value gate uses a generated ten-character value both directly and
inside a connection URI. It checks the untouched bytes and the sealed audit:
three `ScanMatch` entries use `scrub`, with zero guessable comparisons. The
independent Python JSONL gate emits ordinary strings, Unicode escapes and
base64, then reparses the rewritten documents and checks their markers.

The 256 MiB file uses independently calculated SHA-256 values and daemon
Argon2id trace events. Its restored baseline passed in 126.81 seconds on this
Mac; this is a local observation, not a performance guarantee. Cycle548's host
density measurement does not establish scrub throughput.

| Requirement | Closure |
| --- | --- |
| R-M2-39, R-M2-40 | Sanitized locations, registry rotation destinations before confirmation, exposed marking before publication |
| R-M2-44 | Same-directory exclusive stage, original mode, file and directory fsync, device/inode/size/mtime/ctime checks |
| R-M2-45 | Recent live writer, separately held file, symlink and hard-link refusals |
| R-M2-46 | Printed local-only limitations, short-value policy and named database omissions |
| R-M2-47 | Encrypted v2 backup before write, guarded byte-exact undo, independent seven-day clock |
| R-M2-79 | Existing startup hardening plus tracer refusal before source discovery; Linux runtime qualification remains CI-only |
| R-M2-84 / gate 37 | Crash barriers, plaintext sweeps, undo digest, retention and rotation gates above |

All 21 macOS gate tests in the table have a failing product control and a
restored pass. The 27 named negative runs include the old leftover-completion
regression; none relies on a compile failure or timeout. The hostile-preview
property test additionally covers arbitrary bytes and invalid ranges.

The Linux-only `gate37_traced_scrub_refuses_before_reading_plaintext` is wired
into the CLI gate target. Its native execution and the mutation removing the
initial tracer refusal remain for Linux CI under the plan's section 6 OS
matrix. This Mac does not qualify that kernel behavior. Gate 41's complete
pinned-host story belongs to M2-26; M2-22's story drives the real CLI and daemon
with synthetic transcripts. SQLite rewriting remains out of M2 scope, and a
match inside a longer encoded run is deliberately reported as unsupported.

Implementation and mutation receipts are split across `ff962584` (planner,
streaming and atomic writes), `8902dc5c` (CLI, backups and guarded undo),
`770c347f` (story, open-file/live-writer checks and consistent undo reporting)
and `45bac804` (the atomic library gate in CI). The final check results below
refer to the restored tree after these commits.

## Final checks

The commands below ran with `CARGO_TARGET_DIR=/Volumes/KeenShiftDev/tmp/envcloak-target/E`,
`CARGO_INCREMENTAL=0` and `CARGO_BUILD_JOBS=3`. Test processes were detached
from the agent tree, with cleared environments and isolated fixture homes.
No workspace-wide test command was run.

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets` | Passed |
| Full `envcloak` CLI suite | 286 passed, zero failures or ignored tests |
| Full `envcloak-scan` suite | 235 passed, zero failures or ignored tests |
| Full `envcloakd` suite | 260 passed, zero failures or ignored tests |
| Full `envcloak-e2e` suite | 137 unique tests passed after the fresh-host target rerun, zero final failures or ignored tests |
| `scripts/check-unsafe.sh` | Passed |
| `scripts/check-expose-lint.sh` | Passed, all 6 expected exposure sites detected |
| `python3 scripts/check-crate-graph.py` | Passed, 50 edges among 21 crates |
| `scripts/check-sources.sh` | Passed |
| `cargo deny check` | Passed: advisories, bans, licenses and sources; nonfatal unused-license-allowance warnings |
| `git diff --check` | Passed |

The full CLI command was `cargo test -p envcloak --no-fail-fast -- --test-threads 3`.
The other touched crates ran together using `cargo test -p envcloak-scan -p
envcloakd -p envcloak-e2e --no-fail-fast -- --test-threads 3`. The existing
1 GiB doctor target passed all three scans in 2556.92 seconds. All 33 M2 story
tests passed, including the new scrub story and the pinned Claude Code and
Codex scanner stories. The four crates total 918 distinct passing macOS tests.

The first broad end-to-end run had 134 passes and three failures, all at the
freshness guard for the pre-existing `envcloak-probe-model` executable.
Rebuilding with `cargo build -p envcloak-agents --bins` fixed that setup error.
The complete affected target was rerun with `cargo test -p envcloak-e2e --test
agent_hosts --no-fail-fast -- --test-threads 3`: all 60 tests passed in 272.81
seconds, including the Codex, Copilot and Kimi PTY cases. The end-to-end total
counts each test once, using the fresh run for that target. Future runs should
build all helper binaries first:

```sh
cargo build -p envcloak -p envcloakd -p envcloak-agents -p envcloak-testkit -p envcloak-e2e --bins
```

`cargo-deny` was initially absent. The official 0.20.2 macOS arm64 archive
was installed under target E's `m2-22-tools` directory after verifying its
published SHA-256, `fe67d82a10d8597a3549364cb733a3f9cc1bfff9031b7ae46384a9f2a72090c3`.
The successful check used that directory on `PATH`. The exposure-lint script
now honors `CARGO_TARGET_DIR` for its isolated canary build.

## PR 46 CI follow-up

The Linux CI failures reported on 2026-10-08 exposed two separate issues.
`check-reservations.py` could not read the dynamic `reason` forwarded to
`Failure::new`. Commit `05046fee` makes that conversion a fixed vocabulary,
keeps an unknown reason a failure with token `incomplete`, and records the
previously implicit scrub tokens in `docs/IPC.md`. CI now runs the new CLI
unit gate as well as the existing integration target.

The scanner's closed controls failed because scrub retained its source
file while `check_modifiable` opened the same inode a second time. Linux's
`F_SETLEASE` write lease counts this process's other open descriptions too,
so the second open produces `open_elsewhere` even without an external
holder. Commit `52ed1b5a` checks the retained source descriptor and drops the
temporary pathname-check descriptor before asking the kernel. Both checks
in streamed replacement use it. Full pathname and source-stamp checks,
including ctime, still precede publication.

This uses the existing inode-specific lease detector, not a walk of
`/proc/*/fd`: unrelated runner processes and inaccessible descriptor
directories do not affect its answer. A real holder of the source still
refuses the change. The existing best-effort behavior on a filesystem
without leases is unchanged. Linux execution remains for CI; this Mac's
process-list detector cannot reproduce the Linux duplicate-open failure.

The native holder gate now retains a source before starting the independent
Python holder. It verifies that `check`, `validate` and `apply` refuse while
the holder is alive, drops its own source before checking a fresh open
refusal, and checks the unchanged bytes and closed controls after the holder
exits. The three filesystem gates share a test mutex because a sibling
test's fork can briefly inherit descriptors before exec. The holder
assertions require the exact `open_elsewhere` refusal.

| Gate, with `gate37_` prefix omitted | Repeated named mutation | Observed failure |
| --- | --- | --- |
| `failure_tokens_are_fixed_and_unknown_reasons_stay_failures` | `forward_unchecked_scrub_reason` | Unknown text escaped as a token instead of `incomplete`; the original reservation check also failed |
| `open_elsewhere_refuses_aged_source_with_a_closed_control` | `skip_open_elsewhere` | A separately held source was accepted |
| `apply_streams_only_scrubbed_temporary_bytes_and_keeps_mode` | `copy_raw_matches_to_output` | The resulting bytes retained the matched text |
| `recent_linked_and_stale_sources_refused` | `skip_two_minute_rule` | A recent file was accepted |
| `scrub_exclusive_staging_and_ctime_recheck` | `ignore_ctime` | A same-size edit with restored mtime was lost |
| `scrub_exclusive_staging_and_ctime_recheck` | `remove_exclusive_stage` | A planted temporary file was overwritten |

Each negative test compiled and exited 101 at an assertion, with one failed
test. No timeout or compiler error counts as evidence. The mutations are
named in the two fix commits and all were restored before the final checks.
These extend gate 37's existing R-M2-44, R-M2-45 and R-M2-84 evidence; the
scope and OS qualifications listed above remain the same.

The first final pipeline rebuilt only the normal CLI and daemon binaries.
Its 47 CLI unit tests passed, but the 256 MiB integration test saw zero
Argon2id trace events and correctly failed; the other ten scrub tests passed.
The daemon was missing the syscall crate's `testing` instrumentation.
Before the successful rerun, `cargo test -p envcloakd --no-run` rebuilt it
with the test features, as the CI gates job already does. The count assertion
was unchanged. Standalone CLI gate runs need this preparation after a normal
CLI/daemon build. The complete target then passed all eleven tests in 128.59
seconds, including the one-proof, one-Argon2id and exact-digest checks.

The final follow-up pipeline passed on the same macOS and Rust versions
listed above, using target E, incremental compilation off, three build jobs,
and detached tests with cleared environments and three test threads.

| Follow-up check | Result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets` | Passed |
| Full `envcloak-scan` suite | 235 passed, zero failures or ignored tests, including the independent oracle |
| CLI `envcloak` binary unit tests | 47 passed, zero failures or ignored tests |
| CLI `scrub` integration target | 11 passed, zero failures or ignored tests |
| `python3 scripts/check-reservations.py` | Passed, 276 rows in 17 tables |
| `python3 scripts/check-spec-decisions.py` | Passed, 54 decisions and 51 sentences |
| `scripts/check-unsafe.sh` | Passed |
| `scripts/check-expose-lint.sh` | Passed, all 6 expected sites reported |
| `scripts/check-sources.sh` | Passed |
| `python3 scripts/check-crate-graph.py` | Passed, 50 edges among 21 crates |
| `git diff --check` | Passed |

The test preparation and final test commands were:

```sh
cargo build -p envcloak -p envcloakd --bins
cargo test -p envcloakd --no-run
cargo test -p envcloak-scan --no-fail-fast -- --test-threads 3
cargo test -p envcloak --bin envcloak --test scrub --no-fail-fast -- --test-threads 3
```

These are 293 distinct passing tests for this follow-up, not a rerun of the
historical 918-test receipt above. No workspace-wide test command was run.
