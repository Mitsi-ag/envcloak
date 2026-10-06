# M2-27 follow-up validation

Scope: the unmerged managed-launch implementation at dff40dd1, repaired in this worktree. SPEC section 6.6 remains the source of truth. This receipt distinguishes the 2026-10-07 macOS run from Linux CI and the existing branch's earlier mutation claims.

## Findings and class sweep

The sweep inventories 94 files: every path in `git diff --name-only origin/main...HEAD`, plus this follow-up's new files. The relevant predicates occur in policy/managed, daemon/launch_check and managed, client/managed, CLI/run, exec/launch, IPC/control, sys/launch and owned, the managed tests and their documentation. No duplicate private classifier was found.

| Bug class | Instances swept and disposition | Regression |
| --- | --- | --- |
| Attached option values selecting unexamined code | PHP `-f` and clusters; sibling PHP `-F`, `-B`, `-R`, `-S`, `-a`; Python `-X` presite and future options; Python `-W` dotted category imports and their `PYTHON_PRESITE`/`PYTHONWARNINGS` environment equivalents. Registration, changes and shebang construction share the classifier. Other attached-value families were checked: Ruby separator/encoding/safe-level, shell options, PHP document root and Julia numeric/thread settings. | Pure refusal/positive matrix and real PHP/debug CPython oracle tests |
| Native classification of interpreter aliases | Version and ABI names, four architecture suffixes, pythonw, GraalPy, MicroPython, TruffleRuby, PHP CGI/FPM with versions on either side. Unknown suffixes after a numeric version stay interpreters. Canonical-name disguise checks use the same family matcher. Negative controls include pythond, python-server, nodemon and pythonwrench. | Alias matrix including refusal, positional entry and disguised-name checks |
| Environment-name canonicalization | Every npm_config_ spelling is compared case insensitively; Python startup variables are refused by exact name. Node options, script shell, user/global config, prefix and unknown future config are refused; only registry/cache/fund/audit/update_notifier pass. Registration, updates, inherited environment, recorded variables and injected bindings use the shared predicate. | Boundary matrix with permitted-name controls |
| Losing the cleanup owner after release | Confirmation receive timeout, failed response send and partial Release write now close control and allow the runner to clean up without killing it. A bounded exit observation transfers a slow runner to the existing reaper, retaining its cleanup owner without holding the request open. The runner still owns and reaps its server. Pre-release anchor and abandon failures may kill their child safely because no server exists. exec::confirm_or_kill signals its own server handle; sys::spawn failure owns its child. | Recording model forbids runner signals; native timeout and channel-loss tests witness a server before the fault, both processes absent from a successful kernel process listing afterwards and a healthy launch after restart |
| Stale proof-origin state | managed.register, update and unregister all commit under the guard returned by the shared prove recheck. update_plan only returns metadata after the initial refusal check. No second mutation path bypasses prove. | Barrier inserts a live same-terminal request after initial registration check, asserts proof_refused/requester_terminal, revision 1 and audit; unrelated-terminal control commits revision 2 |
| Stale stored policy after an upgrade | The pre-release check now revalidates the original declaration and the prepared argv/environment against current policy, including cached class, entry and strength. It preserves the recorded executable rather than searching PATH or rereading a shebang. A record that no longer satisfies policy refuses `managed_launch_changed` before pending/grant lookup; updating it needs the existing proof and revision change. | Stored-record regression matrix with real matching file identities, healthy native/script/package controls and a changed-PATH control |
| Unrecorded recovery residual | The pre-resumption stopped-runner window is separate from confirmation failure after server spawn. Driver-owned residual registry is outside the permitted worktree. | Local M2-25 handoff below; not claimed fixed |

## Independent checks

The cycle499 interpreter review calls for real argument-consumption controls and warns that policy-generated tables are not an independent grammar oracle. `managed_interpreter_oracle.rs` runs fixed benign scripts using PHP 8.4.5 CLI and debug CPython 3.14.0 in private short `/tmp` HOME/XDG directories, with a 20-second process-group deadline and 8 KiB output cap. The PHP control executes the positional entry; attached `-f` and clustered `-nf` select the other file. Python's control runs the entry; presite and a dotted warning category print a prelude first. Both paths and the matching Python startup environment variables must be refused by EnvCloak. A third runtime, npm 11.19.0, confirms lower-case, upper-case and mixed-case script-shell configuration names against empty private user/global config files, with a no-override control. Missing runtimes fail `scripts/check-managed-oracles.sh`; ordinary crate tests explicitly mark these runtime-dependent tests ignored.

Sources: [PHP CLI options](https://www.php.net/manual/en/features.commandline.options.php), [Python command line](https://docs.python.org/3.14/using/cmdline.html), [npm configuration loader](https://github.com/npm/cli/blob/latest/workspaces/config/lib/index.js). PHP archive SHA-256 from the official release metadata: `0d3270bbce4d9ec617befce52458b763fd461d475f1fe2ed878bb8573faed327`. Runtime binary hashes are emitted by the check, since compilation changes their identities. The macOS binaries used here were PHP `2b48081ee0ad424ef78c269c0616b9c3ad6460cbda601f5c8eb6e1f53f9e4ca5` and debug CPython `2cc68752140074e76695ac9d84511a53afe675a8c07cf92aa27221d1a1d2dbf7`.

The cycle518 transition acceptance is implemented at the existing managed.register_resolved barrier. Kernel process-table observations in the cleanup tests are observations only; no signal authority is taken from them. The immediate-kill mutation runs against RecordingProcesses, so testing it cannot orphan a real suspended process.

## Mutation receipts

Every new gate below was observed failing an assertion against the named broken behavior and passing after restoration. Compilation errors do not count. The policy matrix was first run against the unmodified dff40dd1 implementation and all three new tests failed. The runtime and native gates then received separate mutations.

| Commit | Gate tests | Deliberate broken behavior |
| --- | --- | --- |
| `ecc3a6a1` | `attached_values_cannot_select_unchecked_code`, `php_attached_file_selects_the_actual_entry`, `python_attached_options_can_import_before_the_entry` | Accept PHP `-f` as an unchecked attached value; accept every Python `-X`/`-W` attached value |
| `ecc3a6a1` | `native_interpreter_aliases_keep_interpreter_policy` | Restore the old interpreter-name matcher, omitting the new alias families |
| `ecc3a6a1` | `npm_configuration_is_case_insensitive_at_every_boundary`, `npm_configuration_names_match_without_case` | Restore case-sensitive npm prefix matching |
| `6164eb9c` | `failed_release_waits_for_runner_cleanup_without_signalling` | Immediately kill the runner after failed release, losing its server's cleanup owner |
| `6164eb9c` | `confirmation_timeout_after_spawn_cleans_the_server`, `confirmation_channel_loss_after_spawn_cleans_the_server` | Return success after failed confirmation, retaining real cleanup so the mutation cannot orphan the native fixture |
| `3f1cdad5` | `a_pending_request_arriving_during_registration_is_rechecked` | Remove only `requester_terminal_in` in `prove`, leaving the initial check intact; revision 2 was wrongly committed |
| `7e3187f9` | `python_startup_environment_cannot_select_unchecked_code` | Omit `PYTHON_PRESITE` and `PYTHONWARNINGS` from the environment refusal predicate |
| `c3fb4db8` | `failed_release_keeps_a_slow_cleanup_owner` and the completed-cleanup control | Reap without first observing exit; then separately kill the cleanup owner. Both mutations failed; restored checks observe exit, retain slow ownership and never signal |
| `86fb08fc` | Extended `attached_values_cannot_select_unchecked_code`; repeated Python environment oracle | Separately omit PHP `-S` and `-a` refusals, then separately omit `PYTHON_PRESITE` and `PYTHONWARNINGS`. Each mutation failed and restoration passed |
| `bf0746c1` | `stored_declarations_obey_current_policy`, `stored_native_classes_cannot_outlive_interpreter_policy`, `stored_effective_arguments_and_entries_obey_current_policy` | Bypass the current-policy check on stored records: all three gates fail. Checking only the original declaration separately fails the effective-argument/environment gate |

The slow-cleanup follow-up also tightens native observations: failure to read or parse the kernel process table fails the test, rather than counting as an absent process. Confirmation failures must never report `started`. The release counter describes completed handshakes, so its zero value is not a claim that a suspended server never held the injected environment.

## Gate and requirement mapping

- Gates 39 and 40: interpreter and environment refusals preserve the exact-launch and standing-capability boundaries. Existing managed-launch and runner suites cover the surrounding identity/revision/descriptor paths. Gate 40's actual standing-policy issuance remains M2-15.
- Gate 23: the controlled pending-state transition verifies the post-proof check separately from the initial check.
- Gate 33: the transition asserts the proof-refusal audit event; existing suites retain managed register/launch audit tests.
- R-M2-03, R-M2-24, R-M2-49, R-M2-50, R-M2-52, R-M2-74, R-M2-86 and T-16: this task implements the managed record, binding, private recipient, receipt, adoption and revision portions. Actual HTTP relay behavior is M2-18; config rewriting and backup/host round trips are M2-20, as the plan specifies. No claim here closes those tasks or Linux CI.

## M2-25 residual handoff

The driver must copy this entry into its canonical `.collab/m2-residuals.json` before merge. This lane cannot edit that file under the explicit worktree boundary.

- Origin: M2-27 verifier round 4, low, macOS stopped runner before anchor resumption.
- Owner: M2-25, hardening pass; state: open, not fixed here.
- Window: daemon SIGKILL/crash after its verified runner starts suspended and before resume. The runner has pipe ends but no binding value, leads its own session and cannot execute its own timeout.
- Required fix: durable accounting for unresumed starts, with cleanup only through newly obtained owned authority. A persisted pid/start stamp alone never grants signal authority. Qualify any proposed fresh-handle mechanism against D-34; otherwise narrow availability honestly.
- Required gate: kill the owned test daemon at launch.anchor_resume, restart, and observe cleanup or an explicit unresolved state without signalling by a recorded numeric pid. Include a resumed-runner survival control.

## Local results

Final validation runs detached through a double fork and `setsid`, with an empty inherited environment and private HOME/XDG directories. Every Cargo invocation uses `CARGO_TARGET_DIR=/Volumes/KeenShiftDev/tmp/envcloak-target/A`, `CARGO_INCREMENTAL=0` and `CARGO_BUILD_JOBS=3`; test invocations use `--no-fail-fast` and `--test-threads 3`. No `cargo test --workspace` is run.

The selected packages cover every crate changed by the task: `envcloak-policy`, `envcloakd`, `envcloak-e2e`, `envcloak-agents`, `envcloak`, `envcloak-client`, `envcloak-core`, `envcloak-exec`, `envcloak-ipc`, `envcloak-mcp`, `envcloak-sys` and `envcloak-testkit`. The final checks also include formatting, strict workspace/all-target Clippy, the four pinned runtime oracles, an explicit isolated service-manager restart, unsafe/expose lint, source, crate-graph and reservation checks.

All required checks passed on the final product code:

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | Pass |
| `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets` | Pass |
| Policy, daemon and e2e crate suites after the stored-record repair | Pass; managed launch 29/29 and managed runner 19/19 |
| The other nine changed crate suites | Pass in the preceding full run; their sources were unchanged by the last repair |
| `scripts/check-managed-oracles.sh` | Pass, all four runtime oracles explicitly enabled |
| Isolated launchd restart | Pass on the focused retry with `ENVCLOAK_TEST_SERVICE_MANAGER=1`; fixture and runner survive the test daemon restart |
| `scripts/check-unsafe.sh`, `scripts/check-expose-lint.sh` | Pass |
| `scripts/check-sources.sh`, `scripts/check-crate-graph.py`, `scripts/check-reservations.py` | Pass |

The broader crate run includes 92 reservation-checker mutation tests and its 23 M3 extension cases. Two pre-existing ignored sys documentation examples remain ignored; the four runtime oracle tests ignored by the ordinary policy invocation were run explicitly by the check script. The default runner suite's optional service-manager case was also run explicitly, rather than claiming its default skip as qualification.

The first full e2e pass had one unrelated failure at `probe_local.rs:427`: the test compares every shared `/tmp/ecp*` directory before and after its own run and observed two additional concurrent directories. Both subsequent full e2e runs passed, including that test. No probe code or foreign temporary directory was changed to obtain a pass.

The final aggregate run's separate launchd check failed at initial service installation: the loaded daemon did not answer before the install command's deadline. No managed launch or restart had been reached. An isolated retry on the same final binaries passed (12.43 seconds), as had the preceding aggregate run. This startup failure is retained in the raw result; no cause beyond that failed startup observation is claimed.

This lane adds fresh macOS development-build and isolated launchd evidence. Linux-specific gates remain for the plan's required CI, and packaged-release/TCC observations were not rerun here. The existing branch's earlier platform evidence is not represented as a new measurement. Standing-policy issuance (M2-15), actual HTTP relay behavior (M2-18), host config rewriting/backup round trips (M2-20), and the stopped-runner recovery residual (M2-25) keep their plan owners.

Raw check and mutation logs are local under `/Volumes/KeenShiftDev/tmp/envcloak-target/A/m27-*.log`; aggregate check results are `m27-final2-results.json` and `m27-final3-results.json`. The first covers all twelve changed crates; the last rechecks the three crates affected by the final repair. `m27-service-retry.log` and its `.done` file record the successful retry of the service-startup failure retained in the last aggregate result. No push, PR or GitHub comment was performed.

Final confirmation at `b43364b5`: the requested detached rerun passed formatting, strict workspace/all-target Clippy, the binary freshness build, all three follow-up crate suites (210 policy, 258 daemon and 179 e2e tests), all four runtime oracles, and unsafe, expose, source, crate-graph and reservation checks. Every command exited 0; no implementation change or retry was needed in this rerun. Results are in `m27-resume-final-results.json` and `m27-resume-final-*.log` in the same local target directory. The earlier successful nine unchanged-crate suites and explicit launchd qualification remain the evidence for those checks.
