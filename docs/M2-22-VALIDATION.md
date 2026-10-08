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

Tests run detached with cleared environments and isolated temporary homes.
Incremental compilation is off; build jobs and test threads are limited to
three. No host credentials or agent stores are read by the tests. A compiling
mutation must fail at its property assertion; build failures and timeouts do
not count as mutation evidence.

## Gate mutations

These gate mutations were restored after their failing controls. Test
names omit the common `gate37_` prefix.

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
| `traced_scrub_refuses_before_reading_plaintext` (Linux) | `skip_initial_scrub_tracer_refusal`; runtime failure and restored passes recorded below |

The crash gate now uses independent Python output for three eligible vault
canaries: raw, both hex cases, padded and unpadded standard and URL base64,
both percent-escape cases and JSON Unicode escapes. Every pause receives the
encoded transcript. The same detector checks all canaries and supported
encodings in every temporary sibling before and after killing the child.
Each encoding has a planted-file positive control; backups are swept before
and after the kill too. Four pauses retain the original and two retain the
complete scrubbed JSONL, with every item flagged.

The short-value gate retains the generated ten-character value directly and
inside a connection URI, and checks three sealed `ScanMatch` entries with
purpose `scrub` and zero guessable comparisons. The 256 MiB undo gate checks
one proof, one Argon2id event and an independently computed original digest.
The Cycle570 adapter covers all 15 groups and 22 files in both enumeration
orders; the Cycle432 scanner oracle remains a separate provenance check.

| Requirement | Closure |
| --- | --- |
| R-M2-39, R-M2-40 | Sanitized locations, registry rotation destinations before confirmation, exposed marking before publication |
| R-M2-44 | Same-directory exclusive stage, original mode, file and directory fsync, device/inode/size/mtime/ctime checks |
| R-M2-45 | Recent live writer, separately held file, symlink and hard-link refusals |
| R-M2-46 | Printed local-only limitations, short-value policy and named database omissions |
| R-M2-47 | Encrypted v2 backup before write, guarded byte-exact undo, independent seven-day clock |
| R-M2-79 | Existing startup hardening plus tracer refusal before source discovery; Linux refusal mutation qualified under L-01 by a runtime assertion failure and two restored passing receipts below |
| R-M2-84 / gate 37 | Crash barriers, plaintext sweeps, undo digest, retention and rotation gates above |

## Review repair audit

Every path in the M2-22 diff from `36ada484` was searched for these classes.
The sweep also follows the shared scanner and backup admission dependencies.

| Bug class | Instances and disposition |
| --- | --- |
| Lost source provenance | CLI path selection and post-scan rewrite format inference; retain named direct-child filters, select the most specific enclosing source, normalize fixed system aliases and pass the actual scanner format to rewriting. Raw stores, misleading extensions, Mixed tool results and JSONL directory selections have CLI controls. Undo's descriptor is only used for leftover discovery and does not choose a rewrite grammar. |
| Admission drift | Daemon backup roots versus catalog-selected scrub stores: default and relocated Claude/Codex roots, named legacy backups, per-user temporary trees, direct-child cwd files, hook outputs and configured Codex logs now have admission and undo controls. Daemon-owned roots normalize redundant separators and current-directory components, while client path grammar and parent-component refusals remain strict. Existing creator, upload owner, proof, lease and post-change digest checks remain the authorization boundaries. |
| Unsupported coverage claim | CLI `LIMITS` and DOCTOR's scrub paragraph claimed a short registry exception; both now state the actual short-value exclusion. IPC's comparison eligibility describes the daemon, not scanner discovery, and is unchanged. |
| Incomplete exposure detector | CLI crash temporary siblings, the post-kill file and the basic rewrite gate used raw-only checks. Use the encoding-aware detector, independent encoded input, unfiltered positive controls and pre/post-kill sweeps. Native preview tests assert exact byte output; the story and Python JSONL gates already use encoding-aware sweeps. |
| Unqualified platform evidence | Closed by the driver-reported Linux tracer-removal mutation failure and two restored passes on `69acef57`, recorded below. |
| Producer/reader status race | The required unsafe check exposed an early-exit allowlist pipeline. A large valid-list control reproduced it. CI's Xcode version pipeline had the same pattern and a forced producer reproduced a broken pipe. Both readers now consume all input; unlisted-file and wrong-version controls still fail. Other task-file `grep -q` uses read files directly. |
| Raw metadata in diagnostics | The new `ScanReport.transcript_formats` map bypassed `Source`'s value-free debug output. `ScanReport` now prints counts only, and a generated filename canary qualifies the fix. Scrub `Match`, `Edit`, `FilePlan` and `OpenFile` already have opaque debug implementations; the new daemon scope has none. Existing atomic path errors are converted to fixed CLI reason tokens and sanitized locations. |
| Public receipt hygiene | Removed local absolute paths, host build details, tool install locations and superseded aggregate test counts from this document. No other task-added documentation or comments contained those receipt details. The local receipt check rejects the old document (`restore_host_receipts`) for all three categories and accepts the repaired task docs. |

## Review mutation receipts

| Gate or check | Mutations observed failing | Repair commits |
| --- | --- | --- |
| `catalog_formats_survive_file_and_directory_selection` | `old_format_for` | `aec40697` |
| `canonical_selections_keep_catalog_jsonl_without_extensions` | `skip_catalog_alias_normalization` | `47fad3a9` |
| `short_values_untouched_output_swept_and_later_edits_refuse_undo` | `short_registry_exception`, repeated as `short_registry_exception_recheck`; `document_short_registry_exception` | `f3fe82fa`, `48c77fb0` |
| `kill_at_every_pause_leaves_whole_files_and_no_temporary_exposure` | `retain_github_base64`, `retain_stripe_hex`, `retain_github_json_escape` | `b00f249f` |
| `cli_rewrites_marks_and_undoes_with_one_proof` | `copy_all_json_matches` | `b00f249f` |
| `scrub_catalog_backup_scope_and_restore` | `fixed_backup_allowlist` | `813ee50e` |
| `scrub_refuses_client_only_catalog_roots` | `admit_all_scrub_paths`, repeated after strengthening the input and exact refusal assertions | `813ee50e` |
| Daemon `catalog_scope_preserves_name_root_and_purpose_boundaries` | `ignore_named_filter`, `allow_nested_named_source`, `widen_scrub_purpose`, `skip_catalog_path_grammar`, `canonicalize_user_symlink_root`, `wrong_default_claude_temp` | `813ee50e`, `93e09cf4` |
| Daemon `catalog_log_setting_is_bounded_typed_and_recomputed` | `drop_configured_log_root`, `accept_untyped_log_root`, `double_config_read_limit`, `retain_previous_log_root`, `follow_linked_log_setting` | `813ee50e` |
| Both daemon catalog gates and `scrub_catalog_backup_scope_and_restore` | `reject_equivalent_catalog_roots` | `3389f570` |
| `format_provenance_debug_never_discloses_paths` | `debug_raw_format_paths` | `16cc8f2b` |
| `allowlist_membership_does_not_depend_on_pipe_capacity` | `early_exit_allowlist_reader` | `669a9c69` |
| `ci_version_probe_consumes_the_producers_output` | `early_exit_ci_version_reader` | `669a9c69` |

Every row reached a runtime assertion under its mutation and passed after
restoration. The format matrix covers catalog, directory and individual-file
selections. The backup matrix exercises every writable transcript descriptor
and host backup, in default and relocated layouts, with byte-exact undo and
an agent-created legacy backup requiring consent. Default temporary paths are
also tested by pure admission checks; tests never enumerate real host stores.

The daemon adds normal uses of the already pinned `toml_edit` and `zeroize`
packages. Cargo's normal/build dependency tree was recorded locally. No new
package, version, proc macro or workspace crate edge was introduced. The
catalog parity test avoids a new daemon-to-agents dependency forbidden by
D-02; every additional path comes from the daemon's own settings.

Original implementation receipts are in `ff962584`, `8902dc5c`, `770c347f`
and `45bac804`; the first table retains their per-gate mutations.

## Earlier CI repairs

`05046fee` replaced dynamic failure-token forwarding with a fixed vocabulary;
unknown reasons remain `incomplete`. Mutation `forward_unchecked_scrub_reason`
fails the CLI unit gate. `52ed1b5a` reuses the held source descriptor for the
Linux write-lease check: a second open by this process had made a closed file
look externally held. `aa38155f` qualifies the retained and fresh-open holder
controls with `skip_open_elsewhere`, `copy_raw_matches_to_output`,
`skip_two_minute_rule`, `ignore_ctime` and `remove_exclusive_stage`.

`ab26e52f` makes reservation-reader fixtures own their reserved tokens instead
of depending on live IPC rows remaining reserved. Exact token and source
assertions and landed-row positive controls remain. Its mutation receipts:

| Test | Named checker mutation observed failing |
| --- | --- |
| `a_failure_token_returned_by_another_crates_token_method_counts` | `skip_nonfailure_token_methods`: ignore methods outside `Failure` itself |
| `a_failure_token_through_a_helper_function_counts` | `skip_token_helper_calls`: omit token arguments passed to helpers |
| `a_failure_token_written_as_a_constant_in_another_crate_counts` | `discard_constant_values`: discard resolved constant-reference values |
| `a_failure_token_in_a_field_or_a_token_method_counts` | `skip_nonfailure_token_methods` loses the method's literal token; `discard_method_constant_values` loses its constant token while the field and literal diagnostics still pass |
| `a_token_printed_directly_as_envcloak_token_counts` | `disable_printed_token_detection`: disable the printed-token pattern |

## Platform qualification and remaining scope

R-M2-79's Linux tracer mutation is qualified under L-01. The driver supplied
the following failing mutation and restored-source receipts, completing the
Linux handoff.

Mutation `skip_initial_scrub_tracer_refusal` was the only change on disposable
branch `m2/m2-22-mut-tracer`, commit
`23e73e03072663fb2f6d17d6edb2255288bd7c86`, whose parent is `69acef57`.
It bypassed the initial `refuse_if_traced()` result in the scrub entry point
with `if false { refuse_if_traced() } else { Ok(()) }`. The unreachable call
kept the import used, and the mutation was rustfmt clean.

In [mutation run 37795007127](https://github.com/Mitsi-ag/envcloak/actions/runs/37795007127)
(`workflow_dispatch`), the `test (ubuntu-latest)` job compiled and ran
`cargo test --workspace`. Exactly one target failed: `envcloak --test scrub`,
with 15 tests passed and one failed. The failing test was
`gate37_traced_scrub_refuses_before_reading_plaintext`, at
`crates/envcloak-cli/tests/scrub.rs:953:5`, with this assertion:

```text
assertion failed: stderr(&out).starts_with("envcloak: traced:")
```

This was a runtime assertion failure, not a compilation error or timeout.
The mutation run's macOS test job was cancelled before any step ran; the
tracer gate is Linux-only.

Both restored-source receipts use commit
`69acef57274b191b33d8bb9ed71edb8edda95825`:

- [PR run 37794925651](https://github.com/Mitsi-ag/envcloak/actions/runs/37794925651)
  passed, including the gates job's full CLI scrub target on Linux.
- [Manual run 37795051722](https://github.com/Mitsi-ag/envcloak/actions/runs/37795051722)
  passed its full `test (ubuntu-latest)` job.

The driver also reports detached local checks passing on `69acef57`: fmt,
strict Clippy, unsafe and exposure checks, scanner 236, daemon 262, CLI 291,
testkit `check_unsafe` 29 and the scrub story one, with no failures.

Gate 41's complete pinned-host story belongs to M2-26. M2-22's story drives
the real CLI and daemon with synthetic transcripts. SQLite rewriting remains
out of M2 scope; a match inside a longer encoded run remains manual.

## Current local checks

Review repair checks ran on macOS with incremental compilation disabled,
three build jobs and three test threads. Tests ran detached with cleared
environments and `--no-fail-fast`. No workspace-wide test command was used.

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets` | Passed |
| Full `envcloak-scan` suite | 236 passed, no failures or ignored tests |
| Full `envcloakd` suite | 262 passed, no failures or ignored tests |
| Full `envcloak` CLI suite | 291 passed, including the separate large doctor case; no failures or ignored tests |
| Separate 1 GiB doctor gate | Passed, including both scans from one persistent agent |
| Full `envcloak-testkit` suite | 286 passed across the full run and the seven-test `ec_model` rerun; no unresolved failures or ignored tests |
| Full `envcloak-e2e` suite, with required pinned hosts | 137 reported passes: 134 exercised tests and three release-only early returns; no failures |
| Final CLI `scrub` target | 15 passed, no failures or ignored tests |
| `bash scripts/check-unsafe.sh` | Passed |
| `bash scripts/check-expose-lint.sh` | Passed, all 6 expected sites |
| `python3 scripts/check-reservations.py` | Passed, 276 rows in 17 tables |
| `python3 scripts/check-spec-decisions.py` | Passed, 54 decisions and 51 sentences |
| `python3 scripts/check-crate-graph.py` | Passed, 50 edges among 21 crates |
| `bash scripts/check-sources.sh` | Passed |
| `cargo deny check` | Advisories, bans, licenses and sources passed; nonfatal unused-license-allowance warnings |
| Public receipt hygiene and `git diff --check` | Passed |

Final receipts use the source after the catalog-root spelling and counts-only
debug repairs. The large gate 36 doctor case runs separately from the other
CLI tests, serially; the combined CLI count includes it once. The test-enabled
daemon is prepared with `cargo test -p envcloakd --no-run` for the Argon2id
trace assertions.

The end-to-end run requires the pinned agent hosts. The fixture story's
optional PHP subcase is unavailable in the detached environment; its other
available runtime cases run normally. This is separate from M2-22's scrub
story and the required pinned-host checks. Three release-artifact probes
return early without `ENVCLOAK_TEST_RELEASE_DIR`; they are not qualified by
the local pass count. CI's release job supplies that directory, sets
`ENVCLOAK_TEST_REQUIRE_RELEASE` and requires the PHP emitter too.

Interrupted checks and stale-binary refusals are not passing receipts. After
the host restart, cached helper, CLI and daemon binaries predated the local
Cargo settings even though the initial build completed successfully. The
freshness guard refused them. Helpers were relinked and the affected product
packages were cleaned and rebuilt before repeating the affected suites. No
freshness checks or test deadlines were relaxed.

A pre-restart attempt timed out in three daemon `answers` cases. All five
cases passed unchanged in the final full daemon run. The timed-out attempt
does not qualify any mutation or passing receipt.

An earlier unsafe-check invocation used `sh` instead of Bash; that exit 2 is
superseded by the successful Bash run. The corrected invocation exposed the
reader race repaired in `669a9c69`. The initial root-spelling mutation control
also stopped at the stale-daemon guard; only its subsequent rebuilt run,
which reached the expected `invalid_params` assertion, qualifies as evidence.
