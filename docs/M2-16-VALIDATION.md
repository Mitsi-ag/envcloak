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

## Original implementation checks

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

## Review repair after 965c2970

All nine supplied findings are resolved. No finding was rejected. The private-manifest rerun uses the review's permitted manual-step solution: JSON and text name the directory to move, retain the earlier manifest and explain updating previous run commands before retrying. Automatic merging is not claimed.

The class sweep searched all 28 files added or changed since `4f3059ba`, including the CLI, scanner, daemon backup/show integration, story, fuzz input, snapshots, documentation and expose allowance. The searches covered filesystem writes and preconditions, grammar and normalization, outcome/receipt state, approval statements, selection/discovery, leftover names and every scan limit. Matching production paths were read. Local search receipts are `sweep-*.txt` in `.collab/m2-16/`.

| Bug class | Instances swept and disposition | Regression evidence |
|---|---|---|
| Filesystem effects before eligibility | Profile and AWS cleanup shared the project ignore writer and created private manifests before recent/open/link checks. Machine cleanup now leaves HOME and AWS ignore files alone and checks eligibility and output size first. Atomic checks still run again at the write. Project dotenv import/init retains its specified ignore edits. | `review_cleanup_preserves_ignore_files_and_refuses_before_metadata`: profile/AWS, successful/recent/open/hard-linked cases; existing size and stale-verification gates. |
| Grammar ambiguity and option normalization | AWS continuations with `=` were masked by the old unsupported-syntax fixture. The sweep also addressed indexed F147: mixed-case fields and differently cased duplicates. Static case-insensitive field matching allocates no arbitrary option text. Continuations after ignored options, indented section-like lines, Unicode indentation and repeated sections were also found and made manual. Profile complete-line and MCP manual/references-only cleanup guards were checked. | `aws_hostile_grammar_is_explicit_and_value_free`, `aws_option_casing_matches_python_ini_oracle`, `aws_continuation_context_matches_python_ini_oracle`; existing AWS CLI and Bash oracles. |
| Stale private metadata blocks a retry | A second profile/AWS cleanup cannot silently replace an earlier manifest's bindings. The existing mismatch refusal now gives an actionable manual step in both report formats and IMPORT.md. Dotenv manifests retain their existing verification path. | `review_repeated_cleanup_names_the_manual_manifest_step` exercises adding a second key after cleanup. |
| Selection rules applied at the wrong boundary | Extra cache/trash rules leaked into ordinary named scans; omitted cloud directories were unnamed. JSON and TOML MCP includes bypassed cloud opt-in. Caller selection now covers top-level descriptors and every resolved include before reads or sibling inspection. The sweep also found alternate casing bypassing cloud selection or directory exclusions, and case aliases failing explicit opt-in. All readers now share case-aware selection and canonical parent scope. | `review_named_scan_keeps_cache_projects`, `review_mcp_includes_require_cloud_opt_in`, `review_config_selection_covers_json_toml_and_each_include`, `review_cloud_selection_covers_case_aliases_in_every_reader`; existing profile cloud test. |
| Approval disclosure mismatches writes | Both v2 recorded and unrecorded undo used v1 project/missing-only text. The missing-flag refusal repeated that error (indexed F149). V2 now names sealed absolute targets and actual overwrite conditions before proof; leased target, result and creator must still match the shown metadata. V1 keeps its original behavior. | Recorded gate restores from outside the project and refuses later edits; unrecorded test discloses overwriting later edits, restores exact bytes, and verifies missing flags write nothing. |
| Crash artifacts omitted from discovery | Profiles, sourced includes and both AWS files missed siblings, including absent originals; the shared classifier also omitted delete temporaries. New/swap/del names are now reported without granting deletion or import authority. Config/include and dotenv discovery were swept too. | `review_profile_include_and_aws_leftovers_survive_missing_originals` covers four source paths, three temporary kinds and present/missing originals. The kill gate now covers 36 boundaries across profiles, includes and both AWS files, requiring post-crash incomplete scans. Existing config-leftover test remains. |
| Discovery depends on unrelated files or path spelling | Nested MCP-only projects depended on finding dotenv files. Catalog paths beneath an explicitly selected root alias also failed the canonical-root comparison. Config locations now come from every bounded, held directory; only explicitly opened root aliases are rebased, leaving child no-follow checks intact. | `review_nested_projects_need_no_dotenv_to_discover_mcp` covers root and host-specific config names. `review_catalog_discovery_through_an_explicit_root_alias` covers machine and explicit-root modes. |
| Truncated scans reported complete | The dotenv file cap stopped without an error; pending entries in one directory could bypass it. Directory discovery and omitted-directory bookkeeping also need a bound. Exhaustion with work remaining now emits `limited`; byte, depth, config and retained-value limits were checked for explicit failures. | `review_walk_reports_file_limits_in_one_directory_and_across_directories`, `review_project_directory_discovery_has_an_explicit_limit`, `review_dotenv_file_limit_is_incomplete` with 10,000 empty dotenv files before a credential. |
| Stale outcome after a completed write | Indexed F148: a failed result-record RPC falsely called rewritten entries kept. The sweep also found retained temporary paths reported as the original source. Reports now preserve actual rewrite state, backup/replacement data and unconfirmed receipt state, and name a retained sibling separately. Existing init/delete reducers already distinguish rewritten and kept paths. | `review_receipt_failure_preserves_the_completed_rewrite_report` locks after rewrite in JSON and text. `review_retained_swap_is_named_separately_from_the_rewritten_source` changes the swapped-out file and asserts both resulting paths and dispositions. |

### Repair mutation evidence

The following 27 named mutations each produced an assertion failure, then were restored. The `aws-case-sensitive` mutation was repeated after switching to allocation-free matching. `allow-unselected-config-source` initially survived because the include refusal hid the top-level read; the test was strengthened to require zero bytes/files and the correct originating path, then the same mutation failed. Initial stale-build and fixture-setup failures were not counted.

| Named mutation | Test that failed |
|---|---|
| `aws-no-multiline` | `aws_hostile_grammar_is_explicit_and_value_free` |
| `aws-case-sensitive` | `aws_option_casing_matches_python_ini_oracle` |
| `aws-forget-unknown-option`, `aws-section-before-continuation` | `aws_continuation_context_matches_python_ini_oracle` |
| `aws-ignore-duplicate-sections`, `aws-ascii-indentation` | `aws_hostile_grammar_is_explicit_and_value_free` |
| `omit-profile-leftovers`, `omit-aws-leftovers` | `review_profile_include_and_aws_leftovers_survive_missing_originals` |
| `silent-file-limit` | `review_walk_reports_file_limits_in_one_directory_and_across_directories` |
| `ignore-directory-limit` | `review_project_directory_discovery_has_an_explicit_limit` |
| `allow-config-includes`, `allow-unselected-config-source` | `review_config_selection_covers_json_toml_and_each_include` |
| `ignore-post-crash-siblings` | `gate16_kill_at_each_profile_and_aws_boundary_preserves_value` |
| `omit-config-only-projects` | `review_nested_projects_need_no_dotenv_to_discover_mcp` |
| `omit-catalog-root-alias` | `review_catalog_discovery_through_an_explicit_root_alias` |
| `machine-skips-every-scan`, `hide-excluded-directories` | `review_named_scan_keeps_cache_projects` |
| `case-sensitive-cloud-selection`, `lexical-opt-in-scope`, `case-sensitive-directory-skips` | `review_cloud_selection_covers_case_aliases_in_every_reader` |
| `edit-machine-gitignore`, `metadata-before-file-checks` | `review_cleanup_preserves_ignore_files_and_refuses_before_metadata` |
| `omit-manifest-retry-guidance` | `review_repeated_cleanup_names_the_manual_manifest_step` |
| `forget-rewrite-after-receipt-failure` | `review_receipt_failure_preserves_the_completed_rewrite_report` |
| `misreport-kept-swap-as-source` | `review_retained_swap_is_named_separately_from_the_rewritten_source` |
| `reuse-project-undo-statement` | Both recorded and unrecorded undo tests |
| `reuse-v1-missing-form` | Unrecorded undo test |

Independent checks include the isolated AWS CLI and Bash oracles from the original gate work, plus Python's `RawConfigParser` for AWS option normalization. The latter checks exact canonical names and values across sections, never machine credentials. Research index entries cycle535, cycle540 and cycle541 supplied the F147/F148/F149 cases above. The root-alias, cloud-case and retained-swap-path regressions came from this sweep. Cloud-case tests cover all four cloud-folder names across dotenv discovery, profile includes and MCP includes, before and after explicit opt-in. On a case-insensitive filesystem they also use a differently cased include spelling; that host measurement caught `lexical-opt-in-scope` locally.

R-M2-69 (local portion), R-M2-70, R-M2-71, R-M2-73, R-M2-74 (M2-16 integration), R-M2-75 and gates T-10/15/16 retain the scope mapping above, with the repaired omission, cleanup and recovery cases now included. The plan's ownership boundaries remain: M2-20 MCP rewrites, M2-23 vendor exports, M3 scan UI and M4 account attribution. No new review defect is deferred to those tasks.

Repair commits:

- `6ae04a48`: AWS grammar/casing and profile/include/AWS leftovers; `aws-no-multiline`, `aws-case-sensitive`, `omit-profile-leftovers`, `omit-aws-leftovers`.
- `7e0fc924`: allocation-free option matching; repeated `aws-case-sensitive`.
- `e60d5545`: discovery, source selection and budgets; file/directory-limit, config-selection, config-only-project, root-alias and skip-rule mutations above.
- `755b8aff`: cleanup effects, retry guidance and truthful outcomes; ignore/preflight, retry, receipt, retained-swap and post-crash mutations above.
- `7b7fc31e`: v2 disclosure and missing-form text; `reuse-project-undo-statement`, `reuse-v1-missing-form`.
- `bf1737c4`: AWS continuation context and section grammar; `aws-forget-unknown-option`, `aws-section-before-continuation`, `aws-ignore-duplicate-sections`, `aws-ascii-indentation`, repeated `aws-no-multiline`.
- `6d78329f`: behavior documentation for the repaired discovery, cleanup and undo flows.
- `d2333635`: cloud selection across case aliases; `case-sensitive-cloud-selection`, `lexical-opt-in-scope`, `case-sensitive-directory-skips`.


### Repair local checks

All runs used target E, incremental compilation off, three build jobs, detached cleared environments and isolated HOME/XDG fixtures. Tests used `--no-fail-fast` and `--test-threads 3`. No workspace-wide test command was run.

| Check | Result |
|---|---|
| `cargo fmt --all --check` | Passed |
| `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets` | Passed |
| `check-unsafe.sh`, `check-expose-lint.sh`, `check-crate-graph.py`, `check-reservations.py`, `check-spec-decisions.py`, `check-sources.sh` | All passed; reservations remain 262 rows in 17 tables |
| Full `envcloak` tests | 259 passed, zero failed; first-run target 26/26, including 36 crash boundaries |
| Final-code CLI regression repeat | 258 passed, zero failed; only the already-passed 1 GiB density gate excluded from this repeat |
| Full `envcloak-scan` tests | 219 passed, zero failed; first-run target 11/11 |
| Full `envcloakd` tests | 241 passed, zero failed |
| Full `envcloak-e2e` tests plus two setup-refused cases rerun | 133 passed in aggregate; M2 story target 31/31 |

The unchanged 1 GiB, three-scan doctor regression passed in 2,278.04 seconds. The final AWS/context and cloud/case refinements were made while that unrelated regression ran; binaries were rebuilt, the CLI unit target passed again (44/44), and the final-code CLI regression repeat above validated all other CLI tests. The full scanner, daemon and end-to-end runs followed those changes.

The first end-to-end run passed 131 cases and refused two before they exercised their host: Kimi Code and Copilot CLI's own-terminal catalog cases detected an `envcloak-probe-model` older than its scanner dependency. `cargo build -p envcloak-agents --bins` rebuilt that helper; both exact cases then passed, one test per rerun. These setup failures are not mutation evidence. The initial unsafe-source check also rejected a fixture variable named `include`; it was renamed to `referenced_dir`, with the checker unchanged, and the fixture, strict clippy and all scripts passed again.

Current evidence is in `.collab/m2-16/r2-full-results.json`, `r2-full-{cli,scan,daemon,e2e}.log`, `r2-head-cli-regressions.{json,log}`, `r2-host-rerun-results.json`, `r2-case-fixture-{checks,clippy}.json`, `r2-check-results.json` and the named `*-result.json` mutation receipts. The earlier CI reservation regression remains fixed by `965c2970`; neither its checker nor its fixtures changed in this repair.

These are local macOS results. Linux and complete milestone qualification remain with the plan's CI/driver flow. All nine review findings are resolved, no review finding is deferred, and no push, pull request or GitHub comment was made.

## Third review repair and base integration

Rebased the 17 M2-16 commits onto `origin/main` `6489768be87a4c362ce7212075a6feb243ba8ee2` without conflicts. A fresh fetch confirmed that main ref. The former `a78739b8` task head became `bde99f5c`; the fixes below are tested on the updated base. Remote PR CI remains the driver's step because this lane must not push or operate the PR.

All seven review rows are accepted. The two AWS delimiter rows describe the same parser defect. The class sweep covered every Rust file in the task's diff against main, its tests, and the import/IPC documentation:

| Bug class | Instances swept and repair or existing evidence |
|---|---|
| Grammar mismatch silently changes or omits a candidate | AWS's single parser now selects the first equals or colon delimiter, including mixed-case keys, embedded equals, base64 padding and cross-delimiter duplicates. Both AWS files have CLI import/cleanup checks. Python `RawConfigParser` supplies independent field/value expectations; the real AWS CLI writer remains a separate positive control. Profile assignment and source-path decoding share `word`: unquoted leading equals and equals after colon are manual, including conventional zsh profiles and recursively sourced files. Quoted, escaped and ordinary embedded equals are literal controls under real zsh. JSON/TOML MCP readers use their format parsers; shell assignment-name splitting does not use INI delimiter rules. No additional hand-split INI path exists in the task. |
| An earlier refusal masks a missing later safety check | The ambiguity fixture now imports both a long quoted multiline value and a physically continued assignment that decodes to the full registry canary. It requires two imports, per-name `manual_assignment`, and byte-identical source contents. Both CLI selection and scan transformation guards were removed together for the mutation. MCP findings always lack line-removal eligibility and are handed off, not commented by first-run. |
| A later refusal masks an unauthorized earlier comparison | First-run's shared comparison/report path now has an end-to-end assertion for exactly two comparisons and one skipped guessable candidate, plus the sealed audit's purpose, outcome, total, candidate and per-class counts. Only `scan.match` eligibility was mutated; `import.plan` and its separate refusal stayed intact. The task's daemon import path and existing purpose-aware daemon tests retain their independent guards. |
| Defense-in-depth tests observe only the final writer | Gate 15 now covers a profile, a sourced profile, AWS credentials and AWS config. Scanner tests check both `single_complete_line` and `hard_link`, with ordinary single-link controls. CLI tests check `hard_link` and both hard-link names' unchanged bytes. The sweep also checked the existing direct hard-link assertions in dotenv walking, config/config-reference scanning, atomic writes and guarded restores (`scan_safety`, `configs`, `config_refs`, `scanner_safety`, `atomic`, `restore_left`, and CLI `import`). |
| Validation against a stale integration base | Rebased onto the fetched main ref before testing. No conflicts or speculative changes to another task's ownership/reservations were needed. Linux and PR checks must run on the new pushed head before merge. |

New oracle qualification: macOS zsh 5.9 and `/usr/bin/python3` 3.9.6. The zsh fixture executes only generated source with `-f`, a cleared environment and a private HOME/PATH. Production never executes profile contents. Existing Bash and AWS CLI oracles remain in the scanner suite. This is local macOS evidence, not a new Linux runtime claim.

### Third review mutations

Tests were strengthened before production repair. The original AWS parser failed both the delimiter oracle and the added hostile duplicate case; the original profile parser failed the zsh oracle. After repair their baselines passed. Each named mutation below was then applied, rebuilt, observed failing by assertion and restored. No compile error, stale helper, or setup refusal is counted as mutation evidence.

| Mutation | Failing test and observation |
|---|---|
| `r3-aws-equals-only` | `aws_delimiters_match_python_ini_oracle`, `aws_hostile_grammar_is_explicit_and_value_free`, and CLI `aws_colon_credentials_are_imported_before_cleanup`: missing/unsupported colon fields and missed normalized duplicates. |
| `r3-zsh-equals-literal` | `zsh_equals_expansion_matches_the_shell_oracle` and CLI `gate16_zsh_expansions_are_manual_in_profiles_and_includes`: the parser claims a complete literal and terminal cleanup changes the profile. |
| `r3-aws-nlink-guards` | Scanner `gate15_machine_hard_links_remove_line_eligibility` and CLI `gate15_hard_links_are_importable_but_never_rewritten`: wrong eligibility and missing `hard_link` for AWS credentials. The baseline matrix also checks AWS config. |
| `r3-profile-nlink-guards` | The same two gates fail for profiles. Their baseline matrix also checks recursive includes. |
| `r3-comment-multiline-both` | CLI `agent_scan_leaves_guessable_and_ambiguous_assignments`: removing both complete-line guards changes the source bytes. Both long multiline candidates had been imported, so guessability cannot mask this failure. |
| `r3-scan-match-guessable` | The same CLI test: the reported comparison count becomes 3 instead of 2 while the separate import refusal stays enabled. The restored baseline also verifies the encrypted audit counts. |

Repair commits: `3c908fcc` contains the parser fixes, scanner regressions and import documentation; `a65e5d61` contains the CLI regressions and audit assertions. Both commit messages name their tested mutations. All six mutation receipts report test exit 101; the supervising mutation run exits 0 after restoration. Raw receipts and logs use the worktree-local ignored `.collab/m2-16/r3-` prefix.

Requirement closure remains R-M2-69 (local portion), R-M2-70, R-M2-71, R-M2-73, R-M2-74 (integration), R-M2-75 and T-10, with gates 10, 15 and 16 and D-32's comparison boundary. The plan's existing ownership deferrals remain unchanged: M3 scan UI, M4 owning accounts, M2-20 MCP rewriting and M2-23 vendor exports. No review defect is deferred.

### Third review local checks

All Cargo commands use target E, incremental compilation disabled and three build jobs. Tests run detached in a cleared environment with isolated HOME/XDG paths, `--no-fail-fast` and `--test-threads 3`. No workspace-wide test command was run.

- `cargo fmt --all --check`: passed.
- `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets`: passed.
- Reservation, unsafe-boundary, exposure-lint, crate-graph, SPEC-decision and source checks: all passed (262 reservation rows in 17 tables; 6/6 exposure canaries; 50 dependency edges among 21 crates; 54 decisions and 51 sentences).
- Full `envcloak-e2e` suite: 135 passed, including `gate10_first_run_story` on the updated base.
- Full `envcloak-scan` suite: 222 passed, including both shell oracles, both AWS reader/writer oracles, the hostile parser cases and direct hard-link gates.
- Full `envcloakd` suite on the rebased implementation: 259 passed.
- `envcloak-testkit --test check_reservations`: 91 passed, including all four token tests from the earlier CI failure. The M2-14 `incomplete` reservation and checker fixtures remain unchanged.

A further real-zsh sweep found that quote removal also exposes equals expansion in `''=command`, `'prefix:'=command` and related forms. Both expanded scanner and terminal CLI regressions failed against the initial raw-position guard before the follow-up repair. Literal controls include a quoted equals sign followed by unquoted text, an escaped equals sign after a quoted colon, and a quoted non-colon prefix. The decoder must track an empty decoded prefix or a trailing decoded colon, preserving that state across empty quotes and escaped newlines.

The long, transcript-only `gate36_gib_dedup_and_per_root_awake_hour_budget` passed before that follow-up; its full doctor target passed 12/12 in 3,620.07 seconds. Production code stayed unchanged throughout that run. The new quoted-prefix CLI case was deliberately introduced as a failing regression during the broad run; it is not counted as a passing baseline. The final CLI rerun omits only the already-passed 1 GiB case: the follow-up changes profile word decoding, which the generated JSONL density fixture does not exercise.

The follow-up is committed as `b6e71138`. Its real-zsh baseline passes 34 assignment cases plus source-path controls; the terminal CLI matrix covers 20 profile/include cases. Mutation `r3-zsh-raw-equals-position` restores the raw-position restriction while retaining the decoded state: both `zsh_equals_expansion_matches_the_shell_oracle` and `gate16_zsh_expansions_are_manual_in_profiles_and_includes` fail by assertion (test exit 101). The mutation was restored and all helpers rebuilt. This closes the quoted-prefix instance of the grammar-mismatch class, including recursive source paths.

After the follow-up, the full scanner suite passed again (222 tests), `gate10_first_run_story` passed again, strict workspace clippy passed, and all seven formatting/check-script commands passed again. These final receipts use `r3-scan-final`, `r3-story-final`, `r3-clippy-final` and `r3-checks-final`; the seven named mutation receipts use the `r3-*-result.json` suffix.

Final CLI rerun: 265 passed, zero failed, with only the previously passed 1 GiB case filtered out. All 28 first-run cases passed, including the expanded zsh matrix, comparison/audit assertions, AWS colon cleanup, hard-link defenses and crash/undo gates. Together with the unchanged transcript-only budget regression, all 266 CLI cases passed in aggregate. The earlier broad CLI run had 265 passes and the one deliberately added quoted-prefix failure; no other failure was suppressed or counted as a pass. Final raw receipt: `r3-cli-final.json`.

The final tree has no pending production changes or review defects. These are macOS local results; the driver must push the rebased commits and rerun PR/Linux CI before merging. This lane did not push, open a PR or comment on GitHub.
