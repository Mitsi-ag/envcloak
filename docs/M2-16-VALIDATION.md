# M2-16 validation

Implementation: machine-wide first-run import, `first_run.v1`, opt-in profile/AWS cleanup and undo. Local platform: macOS 26.4.1 (25E253), arm64. Oracle tools: AWS CLI 2.34.20 (Python 3.14.6), Bash 3.2.57. Fixtures use isolated short `/tmp` HOME/XDG directories, synthetic canaries and an environment cleared before launching the CLI, daemon, Bash and AWS CLI. Approval/undo tests run detached from the coding agent's process tree. No real credential/config files are used.

## Requirement coverage

| ID | Implementation and evidence |
|---|---|
| R-M2-69 (local portion), T-10 | Dotenv, profiles/includes, catalog MCP JSON/TOML, AWS shared files. `first_run.v1` exposes providers, source counts, duplicate counts, MCP handoff names and current doctor exposure metadata. Accounts stay unknown until M4, vendor export parsing belongs to M2-23 and MCP config replacement to M2-20. |
| R-M2-70 | One digest-bound daemon plan/commit across named roots and HOME. Gate 10 CLI and story deduplicate dotenv/profile/MCP into the existing item and prove dry-run writes no manifest. |
| R-M2-71 | Scanning in CLI; scan-owned input types; catalog supplied by `Locations`; `scan.match` purpose Import and the existing verified `import.plan`/commit path. No crate edges added. |
| R-M2-73 | Explicit cleanup, fresh stored-value/reference/kit verification before and after durable v2 backup, checked atomic rewrite, recent/open/hard-link refusal, nine kill barriers per profile and AWS file, checked v2 undo. Dotenv retains the existing init gate and v1 backups. |
| R-M2-74 (M2-16 integration) | Existing project import/adoption flow is reused; first-run does not grant run authority. Private cleanup manifests contain references only and are passed explicitly to the existing `run --manifest` interface. Full approval UI/managed-project work remains with the plan's M2-03/M2-27 owners. |
| R-M2-75 | Existing daemon provider/classification rules apply to every candidate. Agent-marked runs keep guessable values; configuration, ambiguous assignments and templates remain in their files and are named. |

## Gate tests and mutations

Across 19 named mutations, 22 targeted test runs failed by assertion. Each listed mutation was applied to production code, the named test was run to an assertion failure, and the original was restored. Mutation receipts and logs are under the ignored worktree-local `.collab/m2-16/` directory; the commit messages preserve the mutation names.

| Test (crate/test target) | Deliberately broken version |
|---|---|
| `aws_cli_is_the_file_oracle` (scan/first_run) | `aws-drop-keys`: remove all AWS findings |
| `aws_hostile_grammar_is_explicit_and_value_free` (scan/first_run) | `aws-ignore-grammar`: clear grammar issues |
| `gate15_aws_and_profiles_never_follow_special_files` (scan/first_run) | `aws-hide-read-errors`: suppress special-file/read refusals |
| `gate16_only_complete_single_lines_are_commented` (scan/first_run) | `profile-allow-multiline`: remove complete-line requirement |
| `gate16_profile_edits_preserve_bash_oracle_bindings` (scan/first_run) | `drop-preserved-tail`: discard bytes after rewritten assignments |
| `gate10_machine_dedupe_dry_run_and_clean_report` (CLI/first_run), `gate10_first_run_story` (e2e/m2_story) | `commit-without-yes`: commit the dry run |
| `gate15_hard_links_are_importable_but_never_rewritten`, `failures_and_hostile_metadata_never_report_success_or_values` (CLI/first_run) | `hide-incomplete-exit`: report success after a refusal |
| `gate16_profile_requires_kit_and_old_complete_assignment` (CLI/first_run) | `skip-recovery-kit`; `rewrite-recent-profile` (zero-second minimum age) |
| `gate16_lock_after_backup_refuses_stale_verification`, `gate16_each_cleanup_condition_is_checked_again` (CLI/first_run) | `skip-backup-reverification`: use pre-backup verification after a lock or rotation |
| `gate16_kill_at_each_profile_and_aws_boundary_preserves_value` (CLI/first_run) | `profile-keep-plaintext`: the rewrite preserves the secret instead of commenting its line |
| `gate16_a_rewrite_must_fit_the_undo_read_limit` (CLI/first_run) | `permit-oversized-rewrite`: disable the result-size guard, allowing a comment to grow the source beyond the undo read cap |
| `gate16_profile_undo_is_byte_exact_and_checks_the_result` (CLI/first_run) | `restore-over-edits`: use the current file's digest instead of the recorded post-cleanup digest |
| `first_run_backup_paths_are_exact_and_init_only` (daemon unit tests) | `cross-purpose-profile-backup`: allow the additional paths for non-init purposes |
| `bounded_ten_thousand_file_tree_and_machine_skips` (CLI/first_run) | `cloud-profile-include`: read cloud includes without explicit opt-in |
| `agent_scan_leaves_guessable_and_ambiguous_assignments` (CLI/first_run) | `compare-guessable-agent`: disable the import guessability refusal |
| `gate15_sourced_names_never_become_plaintext_ignore_entries` (CLI/first_run) | `omit-source-name-guard`: permit a key-shaped basename in ignore metadata |
| `retained_config_temporaries_are_reported_as_incomplete` (CLI/first_run) | `ignore-config-leftovers`: suppress the incomplete flag for retained plaintext temporaries |
| `doctor_exposure_is_reported_without_copying_values` (CLI/first_run) | `hide-doctor-exposure`: suppress existing exposure metadata |

The scan oracle invokes the installed AWS CLI's `aws configure set` with isolated credential/config paths. It verifies the emitted file independently of EnvCloak's parser. The Bash oracle uses the checked-in Python-generated grammar cases, applies the actual comment transform, and asks Bash whether the selected binding disappeared while an unrelated binding survived. These are host-generated/host-executed fixtures. No network/provider calls are involved.

The CLI output sweep first feeds the same detector a raw generated canary and requires nonzero hits, then checks stdout and stderr without filtering hits. The 10,000-file fixture additionally plants values under dependency, cache, trash and cloud paths and proves an explicitly named cloud root is scanned. Kill tests require every requested barrier to be reached and signal only the test's unreaped child handle. Stale helper/build failures are setup failures, never counted as mutation evidence.

## Bounds and handoff

The narrow daemon change supplies the v2 backup prerequisite for conventional HOME profiles and AWS paths, for purpose Init only, and allows their existing `files.show` undo statement to read sealed v2 metadata. It adds no IPC fields or methods. An arbitrary sourced script outside the backup allowlist remains unchanged with an incomplete backup-refusal report: a client-supplied source relationship is not new restore authority. This preserves the plan's encrypted-backup deletion condition.

Linux filesystem/process behavior and the real-host CI matrix require the existing CI runners; this macOS worktree makes no Linux or whole-milestone qualification claim. M3 owns the scan screen, M4 owns accounts, M2-20 owns MCP rewrites, and M2-23 owns vendor exports.

## Local checks

All checks use `CARGO_TARGET_DIR=/Volumes/KeenShiftDev/tmp/envcloak-target/E`, `CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=3`; tests use `--no-fail-fast` and `--test-threads 3`. Cargo is launched in a detached, minimal environment. No workspace-wide test command was used.

- `cargo fmt --all --check`: passed.
- `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets`: passed.
- `scripts/check-unsafe.sh`, `scripts/check-expose-lint.sh`, `scripts/check-crate-graph.py`, `scripts/check-reservations.py`, `scripts/check-spec-decisions.py`, `scripts/check-sources.sh`: passed.
- Full `envcloak-scan` suite: 213 passed.
- Full `envcloakd` suite: 241 passed.
- Full `envcloak` suite plus the grammar rerun, separate large regression and new size-bound case: all 248 tests passed in aggregate. The 1 GiB, three-scan budget regression passed in 2,408.18 seconds.
- Full `envcloak-e2e` suite plus the rebuilt `agent_hosts` rerun: all 133 tests passed in aggregate, including the 31-test M2 story target. The first run's only failed target was the freshness-refused host target; its rerun passed all 60 tests.
- Final focused CLI run: all 15 first-run tests passed after the result-size guard. The five snapshots passed after the cleanup error refactor; that guard changes no snapshot output.
- The new `m2_story::first_run` step passed before and after the mutations.

The first broad CLI run refused stale testkit executables. They were rebuilt, and the suite rerun. The second broad run had one existing doctor grammar test observe an extra `unknown openai` provider line; the unchanged targeted rerun passed. The separate long 1 GiB regression passed (2,408.18 seconds). End-to-end agent-host tests that overlapped the final source edit refused an older CLI binary before doing their work and passed when rerun with the rebuilt binary; those setup refusals are not gate evidence.

The reservation check exposed a global alias-reader collision from the new associated `Refusal = Failure` type and rejected a dynamic Failure token. Cleanup now uses its own local refusal enum, with reasons confined to the report. Config-scan failure uses the existing `io` exit token and exits non-zero. The `incomplete` exit-token row remains reserved to M2-14 under D-23; M2-16 does not take that row. The checker and its reservation fixtures were not modified. Its final pass covers all 262 rows in 17 tables.

Raw local evidence: `.collab/m2-16/scanner-mutations.json`, `oracle-mutation.json`, `mutations-final.json`, the two `*-confirmed.json` hostile-input receipts, `permit-oversized-rewrite.json`, `final-check-results.json`, and per-suite logs/exit receipts. These temporary files are ignored; this document and the commit messages retain the reviewable results.

## CI reservation regression

The broken version `land-incomplete-outside-owner` marked M2-14's `incomplete` row as landed for the M2-16 config-scan fallback. Before restoring the reservation, all four selected `check_reservations` tests failed (0 passed, 4 failed):

- `a_failure_token_returned_by_another_crates_token_method_counts`
- `a_failure_token_through_a_helper_function_counts`
- `a_failure_token_written_as_a_constant_in_another_crate_counts`
- `a_token_printed_directly_as_envcloak_token_counts`

The fix restores the row and uses `io` for that fallback. It preserves exit code 1 and the fixed message, while leaving the reservation checker and fixtures unchanged. The full detached `check_reservations` target passed afterward (91 passed, 0 failed, including those four; 881.94 seconds). First-run CLI tests passed again (15 tests), as did formatting, workspace clippy with `-D warnings`, and the six check scripts listed above. Evidence is in `.collab/m2-16/ci-four-before.log`, `ci-reservations-after.log`, `ci-first-run.log`, `ci-clippy.log`, `ci-checks.log` and their exit receipts.

## Commits

- `5ad1b5b2`: AWS parser and complete-line guard; `aws-drop-keys`, `aws-ignore-grammar`, `aws-hide-read-errors`, `profile-allow-multiline`.
- `76d02df2`: narrow Init backup paths and sealed undo metadata; `cross-purpose-profile-backup`.
- `d7008639`: profile source filter and Bash oracle; `drop-preserved-tail`, `cloud-profile-include`.
- `7a2de05f`: first-run CLI, cleanup, undo and story; the gate 10/15/16 and report mutations in the table above.
- `b652750b`: separate local cleanup reasons from registered exit tokens; the unchanged cleanup guards retain their mutation evidence; 14 first-run tests and five snapshots passed.
- `09510afd`: ensure rewritten sources remain readable by undo; `permit-oversized-rewrite`; final 15-test first-run run and story passed.

All changes are local to the M2-16 worktree. No push, pull request or GitHub comment was made.
