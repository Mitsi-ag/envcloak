# M2-27 follow-up validation

Scope: the unmerged managed-launch implementation at dff40dd1, repaired in this worktree. SPEC section 6.6 remains the source of truth. The dated receipts below preserve earlier failures and platform limits. Later receipts record the checks and supplied CI for each named head, superseding older pending-CI requests without turning unsuccessful local checks into passes.

## Findings and class sweep

The initial sweep inventoried 94 files: every path in `git diff --name-only origin/main...HEAD`, plus this follow-up's new files. The relevant predicates occur in policy/managed, daemon/launch_check and managed, client/managed, CLI/run, exec/launch, IPC/control, sys/launch and owned, the managed tests and their documentation. No duplicate private classifier was found.

| Bug class | Instances swept and disposition | Regression |
| --- | --- | --- |
| Attached option values selecting unexamined code | PHP `-f` and clusters; sibling PHP `-F`, `-B`, `-R`, `-S`, `-a`; Python `-X` presite and future options; Python `-W` dotted category imports and their `PYTHON_PRESITE`/`PYTHONWARNINGS` environment equivalents. Registration, changes and shebang construction share the classifier. Other attached-value families were checked: Ruby separator/encoding/safe-level, shell options, PHP document root and Julia numeric/thread settings. | Pure refusal/positive matrix and real PHP/debug CPython oracle tests |
| Native classification of interpreter aliases | Version and ABI names, four architecture suffixes, pythonw, GraalPy, MicroPython, TruffleRuby, PHP CGI/FPM with versions on either side. Unknown suffixes after a numeric version stay interpreters. Canonical-name disguise checks use the same family matcher. Negative controls include pythond, python-server, nodemon and pythonwrench. | Alias matrix including refusal, positional entry and disguised-name checks |
| Environment-name canonicalization | Every npm_config_ spelling is compared case insensitively; Python startup variables are refused by exact name. Node options, script shell, user/global config, prefix and unknown future config are refused; only registry/cache/fund/audit/update_notifier pass. Registration, updates, inherited environment, recorded variables and injected bindings use the shared predicate. | Boundary matrix with permitted-name controls |
| Losing the cleanup owner after release | Confirmation receive timeout, failed response send and partial Release write now close control and allow the runner to clean up without killing it. A bounded exit observation transfers a slow runner to the existing reaper, retaining its cleanup owner without holding the request open. The runner still owns and reaps its server. Pre-release anchor and abandon failures may kill their child safely because no server exists. exec::confirm_or_kill signals its own server handle; sys::spawn failure owns its child. | Recording model forbids runner signals; native timeout and channel-loss tests witness a server before the fault, both processes absent from a successful kernel process listing afterwards and a healthy launch after restart |
| Stale proof-origin state | managed.register, update and unregister all commit under the guard returned by the shared prove recheck. update_plan now checks again under the state lock after resolution before returning declaration metadata; the initial-only check was incomplete and is repaired in the M2-19 integration receipt below. No second mutation path bypasses prove. | Barrier inserts a live same-terminal request after initial registration check, asserts proof_refused/requester_terminal, revision 1 and audit; unrelated-terminal control commits revision 2 |
| Stale stored policy after an upgrade | The pre-release check now revalidates the original declaration and the prepared argv/environment against current policy, including cached class, entry and strength. It preserves the recorded executable rather than searching PATH or rereading a shebang. A record that no longer satisfies policy refuses `managed_launch_changed` before pending/grant lookup; updating it needs the existing proof and revision change. | Stored-record regression matrix with real matching file identities, healthy native/script/package controls and a changed-PATH control |
| Recovery residual registration | The pre-resumption stopped-runner window is separate from confirmation failure after server spawn. | Registered as M2R-87, open, M2-25; not claimed fixed |

## Independent checks

The cycle499 interpreter review calls for real argument-consumption controls and warns that policy-generated tables are not an independent grammar oracle. `managed_interpreter_oracle.rs` runs fixed benign scripts using PHP 8.4.5 CLI and debug CPython 3.14.0 in private short `/tmp` HOME/XDG directories, with a 20-second process-group deadline and 8 KiB output cap. The PHP control executes the positional entry; attached `-f` and clustered `-nf` select the other file. Python's control runs the entry; presite and a dotted warning category print a prelude first. Both paths and the matching Python startup environment variables must be refused by EnvCloak. A third runtime, npm 11.19.0, confirms lower-case, upper-case and mixed-case script-shell configuration names against empty private user/global config files, with a no-override control. Missing runtimes fail `scripts/check-managed-oracles.sh`. Ordinary crate tests explicitly mark four runtime-dependent tests ignored; CI now provisions their pinned source builds and requires all four plus the non-ignored Bash startup-file oracle, with an exact execution receipt. An ignored, missing or filtered case fails the runner even when Cargo exits zero.

Sources: [PHP CLI options](https://www.php.net/manual/en/features.commandline.options.php), [Python command line](https://docs.python.org/3.14/using/cmdline.html), [npm configuration loader](https://github.com/npm/cli/blob/v11.19.0/workspaces/config/lib/index.js). PHP archive SHA-256 from the official release metadata: `0d3270bbce4d9ec617befce52458b763fd461d475f1fe2ed878bb8573faed327`. Runtime binary hashes are emitted by the check, since compilation changes their identities. The macOS binaries used here were PHP `2b48081ee0ad424ef78c269c0616b9c3ad6460cbda601f5c8eb6e1f53f9e4ca5` and debug CPython `2cc68752140074e76695ac9d84511a53afe675a8c07cf92aa27221d1a1d2dbf7`.

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

- Gates 39 and 40: interpreter and environment refusals preserve the exact-launch and standing-capability boundaries. Existing managed-launch and runner suites cover the surrounding identity/revision/descriptor paths. Gate 40's actual standing-policy issuance remains M2-15. The missing foreign-client case under a standing record, plus the standing negative-case matrix audit, is handed to M2-15 as registered M2R-89 below; that coverage is not claimed closed here.
- Gate 23: the controlled pending-state transition verifies the post-proof check separately from the initial check.
- Gate 33: the transition asserts the proof-refusal audit event; existing suites retain managed register/launch audit tests.
- R-M2-03, R-M2-24, R-M2-49, R-M2-50, R-M2-52, R-M2-74, R-M2-86 and T-16: this task implements the managed record, binding, private recipient, receipt, adoption and revision portions. Actual HTTP relay behavior is M2-18; config rewriting and backup/host round trips are M2-20, as the plan specifies. No claim here closes those tasks or Linux CI.

## M2-25 residual handoff

The canonical `.collab/m2-residuals.json` now records this as **M2R-87**, open and owned by M2-25. Its entry was checked read-only in this review; this lane did not edit the driver-owned registry.

- Origin: M2-27 verifier round 4, low, macOS stopped runner before anchor resumption.
- Owner: M2-25, hardening pass; state: open, not fixed here.
- Window: daemon SIGKILL/crash after its verified runner starts suspended and before resume. The runner has pipe ends but no binding value, leads its own session and cannot execute its own timeout.
- Required fix: durable accounting for unresumed starts, with cleanup only through newly obtained owned authority. A persisted pid/start stamp alone never grants signal authority. Qualify any proposed fresh-handle mechanism against D-34; otherwise narrow availability honestly.
- Required gate: kill the owned test daemon at launch.anchor_resume, restart, and observe cleanup or an explicit unresolved state without signalling by a recorded numeric pid. Include a resumed-runner survival control.

## Local results

Final validation runs detached through a double fork and `setsid`, with an empty inherited environment and private HOME/XDG directories. Every Cargo invocation uses the driver-assigned `CARGO_TARGET_DIR`, `CARGO_INCREMENTAL=0` and `CARGO_BUILD_JOBS=3`; test invocations use `--no-fail-fast` and `--test-threads 3`. No `cargo test --workspace` is run.

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

The final aggregate run's separate launchd check failed at initial service installation: the loaded daemon did not answer before the install command's deadline. No managed launch or restart had been reached. An isolated retry on the same final binaries passed (12.43 seconds), as had the preceding aggregate run. This startup failure and successful retry are retained as historical results. Later external-SSD controls and the host limitation are recorded in the final review handoff; they do not change either result.

This lane adds fresh macOS development-build and isolated launchd evidence. Linux-specific gates remain for the plan's required CI, and packaged-release/TCC observations were not rerun here. The existing branch's earlier platform evidence is not represented as a new measurement. Standing-policy issuance (M2-15), actual HTTP relay behavior (M2-18), host config rewriting/backup round trips (M2-20), and the stopped-runner recovery residual (M2-25) keep their plan owners.

Raw check and mutation logs are local under the lane's private target directory; aggregate check results are `m27-final2-results.json` and `m27-final3-results.json`. The first covers all twelve changed crates; the last rechecks the three crates affected by the final repair. `m27-service-retry.log` and its `.done` file record the successful retry of the service-startup failure retained in the last aggregate result. No push, PR or GitHub comment was performed.

Final confirmation at `b43364b5`: the requested detached rerun passed formatting, strict workspace/all-target Clippy, the binary freshness build, all three follow-up crate suites (210 policy, 258 daemon and 179 e2e tests), all four runtime oracles, and unsafe, expose, source, crate-graph and reservation checks. Every command exited 0; no implementation change or retry was needed in this rerun. Results are in `m27-resume-final-results.json` and `m27-resume-final-*.log` in the same local target directory. The earlier successful nine unchanged-crate suites and explicit launchd qualification remain the evidence for those checks.

## M3-03 integration receipt

Main merged without conflicts in `25a15619`. Commit `b7b4b049` adds the four managed-launch error kinds and codes (-32039 through -32042) and the seven missing reason tokens to EnvCloakKit. The Swift enums now match all 50 Rust kinds and 76 reasons. `requester_terminal` was already present; the sweep of Swift client and app sources found no separate words or strings table to update. The repository's `swift_cross_language_vectors` generator and Python escape oracle generated fresh private vectors for each run; no checked-in vector was hand-edited.

The merged baseline failed the reason-set, kind-count and non-nil-kind assertions. The restored oracle passed before and after three mutations: `drop-runner-unavailable` removed its enum case and code arm, `drop-header-bindings` removed its reason, and `wrong-managed-launch-code` substituted -32039 for -32040. Each mutation compiled and failed its expected assertion.

The detached `scripts/macos/test-kit.sh` run passed all 36 Swift tests, including the real daemon and generated Rust vectors, plus both optimized buffer tests. Xcode tests for EnvCloakKit and EnvCloakDesign passed, as did `check-sources.sh --swift` on both derived-data trees. Every cheap macos-app script test passed: CI coverage, Swift rules and literal oracle, project settings, signature fixtures and policy, build-swap cleanup, compiled-source fixtures, and owned-cleanup/record models. Built-app-only cases report their normal skips when no app bundle is supplied.

Formatting, strict workspace/all-target Clippy, IPC (64), policy (210), daemon (258), both managed suites, runtime oracles, unsafe/expose lint, Rust source, graph, reservation and SPEC-decision checks passed. The first daemon run overlapped the Swift script's plain daemon build in the same target directory and lost its test hooks; its backup pause/trace assertions failed. After all Swift work ended, the test-enabled binaries were rebuilt and the complete daemon and both managed suites passed sequentially. The failed run remains in the logs. Results are in `m27-m3-*-results.json`, `m27-m3-swift-full.log` and `m27-m3-retry-*.log` under the local target directory.

## Package-runner lifecycle follow-up

The driver subsequently reproduced a real sweep race on Node v26.7.0: the request helper closed its input and lifeline, wrote its result, and returned while the runner was still stopping the Node group. Node's compile-cache temporary file could disappear between the sweep's directory listing and read. Commit `ba2dbedb` records the live server's group, waits for every group member to exit after closing the lifeline, and independently requires the group absent before the sweep. The fixture stays alive through TERM to exercise cleanup. Kernel listings are observations only, never signal targets; failed, empty or malformed listings fail the test. The sweep and its refusal of unreadable files are unchanged.

The three isolated zero-release failures have a different cause. The driver's `ec-checks-m2-27-r7.log` ends with `test-kit.sh` rebuilding `envcloakd` without `envcloak-sys/testing` in the shared target. That disables `test_event` entirely. The unchanged success trace in `Ready::send` predates both cleanup commits (`git blame` attributes it to `87a6394c2`); the merge did not remove it. Building the plain daemon reproduced a missing trace; rebuilding with `--features envcloak-sys/testing` restored the passing test. Reusing a target after the Swift script therefore requires rebuilding the test-enabled Rust fixture binaries before the managed suites.

The class sweep covers both users of `managed_common`: `managed_launch` and `managed_runner`. Their shared World setup now requires an actual test trace, so a wrong fixture cannot silently pass zero-release assertions. Their shared release assertion waits boundedly for positive counts to reach the reader and still requires exact counts. The local npm-registry test is the suites' only Node package/cache writer; its group wait covers both npm's cache and Node's temporary compile cache. Other lifecycle tests deliberately retain a client or server to measure its behavior and keep their existing exit controls.

Mutations witnessed against the package-runner gate, with restoration passing each time:

- `plain-daemon-refused`: build without the testing feature; the fixture's trace-presence assertion fails before release counts are trusted.
- `omit-group-exit-wait`: remove the helper's exit wait; the independent assertion sees the package server group still running before the sweep.
- `omit-runner-release-trace`: suppress only the successful release event; the exact count fails as (0, 0) instead of (0, 1) after its deadline.

The final run at `ba2dbedb` used Node v26.7.0, the detached empty-environment launcher, private HOME/XDG/TMPDIR beneath `/tmp`, the required target directory, incremental compilation disabled, three build jobs, and `--no-fail-fast` with three test threads. All requested checks exited 0:

| Check | Result |
| --- | --- |
| Package-runner test, five consecutive runs | 5/5 pass |
| Complete `managed_launch` suite | 29/29 pass |
| Complete `managed_runner` suite | 19/19 pass |
| `cargo fmt --all --check` | Pass |
| `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets` | Pass |
| `scripts/check-unsafe.sh` | Pass |
| `scripts/check-expose-lint.sh` | Pass, all 8 exposure call sites reported |

The final run rebuilt the test-enabled binaries before testing and did not overlap a plain daemon build. Raw results are `m27-npx-final-results.json`, `m27-npx-final-*.log` and `m27-npx-mutation-results.json` in the lane's private target directory. The older M2-25 residual and other tasks' plan ownership above are unchanged. No push was performed by this lane.


## M2-14 integration and doctor grammar receipt

Main merged without conflicts in `5bfb82b5`. The extra `unknown openai` is a seed-dependent M2-14 test defect. The runtime-generated OpenAI canary can end in `-` or `_`; the scanner deliberately emits both the full token and a punctuation-trimmed reading. The full token matches the stored item twice, while the trimmed candidate matches OpenAI's registry pattern but is absent from the vault, so it is correctly reported as unknown twice. Those scanner, provider, canary and daemon matching sources are unchanged from main. No timing, order or M2-27 behavior change is needed to explain the failure.

Commit `92bff9e2` makes the fixture endings explicit: alphanumeric as the control, then hyphen and underscore. The hyphen fixture reproduced the original CI assertion before the repair. The corrected gate requires exact JSON findings and exact ordered human lines, including multiplicity. It no longer assumes only one unknown provider or collapses repeated path/count and rotation-URL lines across distinct finding sections. Production doctor output and matching behavior are unchanged.

Class sweep: the CLI doctor grammar gate was the only flat unique-line oracle among the merged CLI, client report and doctor story tests. The client report test checks schema, masking and canaries; the story checks typed JSON findings and exposure counts. The 1 GiB fixture already has its independent candidate-cardinality control and is unchanged. The full scanner suite, including `deleted_history_is_found_and_limits_are_partial`, passed locally; no change was made for the separate Ubuntu Git-history report.

Three named mutations of the human renderer were compiled and observed failing the corrected gate: `add-line-number`, `omit-unknown-openai-heading`, and `duplicate-item-heading`. Each was restored, and the full suffix matrix passed before and after the mutations. Thus legitimate repeated lines are accepted only in their expected sections, while missing, extra and duplicated grammar entries still fail.

Final validation used the required target directory, no incremental compilation, three Cargo build jobs and three test threads with `--no-fail-fast`. Everything ran detached from agent ancestry, with private short `/tmp` HOME/XDG/TMPDIR roots. Test-enabled daemon and CLI fixture binaries were built first. Three complete doctor-suite runs used separate private roots, each including the unmodified 1 GiB gate with its terminal and two same-agent-root scans. No full workspace test command was run.

| Check | Result |
| --- | --- |
| Complete doctor suite, including every local gate 36 case | 12/12 pass in each of three runs |
| Remaining CLI coverage, with the large case qualified above | 233 pass |
| Client and scanner suites | 37 and 208 pass |
| Policy and daemon suites | 210 and 258 pass |
| Managed launch and runner suites | 29 and 19 pass |
| Doctor story | 1 pass |
| Formatting and strict workspace/all-target Clippy | Pass |
| Unsafe, expose lint and compiler-source checks | Pass |
| Crate graph, reservations and SPEC decisions | Pass |

Raw results are `m27-doctor-final-results.json`, `m27-doctor-final-*.log`, `m27-doctor-repro.log` and `m27-doctor-mutation-results.json` in the lane's private target directory. These are macOS measurements; no Linux execution is claimed. No push was performed by this lane.


## M2-19 integration and review repairs

Main at `2361c758` was merged, without rebasing, in `1b2365be`. The four conflicts retained both the PTY monitor and managed runner modules, the `--pty` parser and private `--launch` entry, the terminal-refresh test and the owned signal helper, and the landed IPC tokens. The compiler additionally caught the managed pipe runner's missing argument to the PTY-aware coverage printer, repaired in `39b9241e`. Strict Clippy caught the incoming self-job suspension's direct numeric signal call; its resolution retains one raw kill boundary in `owned.rs` with a fixed self-group operation, not a caller-supplied target.

The review sweep covered every changed or added task file (101 paths, including the signal integration fixes). Searches covered interpreter family dispatch, startup options, proof eligibility, stored declarations and host config access, ignored runtime tests, signal authority, and machine-specific paths. The original sweep's alias and update-plan conclusions were incomplete; the following repairs supersede them.

| Finding or bug class | Instances swept and disposition | Gate evidence |
| --- | --- | --- |
| Merge interface and signal-boundary composition | CLI `run` parsing and coverage, exec module exports, sys PTY refresh and job suspension, IPC token status. PTY monitor and managed OwnedChild behavior retained. | Managed launch/runner, exec, sys PTY and real CLI job-control suites; `skip-self-group-stop` fails the outer-shell gate and restoration passes |
| Interpreter names misclassified as native | The shared family predicate now compares ASCII case insensitively and accepts a hyphen before a numeric version, including LuaJIT. Python, Python3, LuaJIT, Node, Pythonw and PHP SAPI aliases cover declarations, changes, shebangs, resolved disguises and stored native classes. Negative controls retain python-server, nodemon and pythonwrench. No duplicate managed-family predicate exists in the changed files. | `old-case-sensitive-family`, `old-case-sensitive-stored`, `omit-hyphen-version` each fail; restoration passes |
| Startup code treated as a harmless option | `--login` moved from the harmless table to code loading. The sibling forms `-l` and `-lx`, rc/init-file options and Python startup environment/options were swept. One classifier serves registration, updates and shebangs, and stored declarations/effective argv are rechecked. | Real Bash reads a private startup file before the entry; policy and daemon boundary tests reject all three forms. `allow-login-policy`, `allow-login-e2e`, `allow-login-stored` fail |
| Stale authorization while resolving a statement | `update_plan` rechecks pending-terminal eligibility under the state lock before constructing its reply. Register/update/unregister retain the shared post-proof guard; no second statement path exposes the declaration. | A barrier queues a live request after the initial check. Same-terminal disclosure is denied; a different terminal remains eligible. `omit-update-plan-recheck` and `omit-proof-recheck` fail |
| Update oracle missing the migrated config | The CR-2 test writes a wrapper-only Claude-shaped config, checks exact old/new stored argv and checks byte preservation after planning and committing. Real host CLI round trips remain M2-20's integration responsibility. | `host-config-update` compiles, reads that config instead of the stored declaration and fails the gate; restored update succeeds |
| Tests passing because another refusal masks the intended one | Stored-record fixtures used noncanonical temporary paths; an effective-entry name also resembled an interpreter. Both independent refusal causes were removed. Each option case now first proves a healthy record with matching identities and canonical paths is accepted. | The login mutation initially passed the old test, then failed both repaired stored-record gates |
| Test fixtures coupled to product release state | M2-19 borrowed `not_started_by_daemon` as an unlanded token, while M2-27 already lands it. Generic field, method, constant, constructor, printed-token and ignored-source cases now own three synthetic reservations. The ignored module also uses a reserved token so its inclusion cannot be masked by a landed one. Product registry rows are unchanged. | The borrowed-token failure was reproduced; `omit-method-token-reader`, `omit-field-token-reader` and `include-cfg-test-token` each fail. Restored controls and the complete 92-test target pass |
| Runtime oracles skipped by successful CI | All four ignored PHP/CPython/npm tests are explicitly enabled in the new CI job, together with the ordinary Bash case. Source archives are version- and SHA-256-pinned; Node is 26.7.0. The runner requires exactly five executed successes, zero skipped/filtered cases and a successful Cargo exit. | `omit-include-ignored`, `accept-zero-exit-as-complete` and `omit-archive-digest` fail; all five restored runtime cases pass locally |
| Unmeasured privacy behavior | Protected-folder and local-network prompt attribution is open, owned by M2-27 and due before the M2 release. Registered M2R-88 below tracks the measurement. CI cannot measure the prompts. | No measurement claimed; canonical entry confirmed |
| Private receipt paths and unregistered recovery residual | Machine-specific absolute receipt paths removed throughout this document; the only user-directory strings elsewhere in the task diff are synthetic plist-escaping fixtures. The canonical residual registry was checked read-only: M2R-87 already records the stopped-runner issue, open and owned by M2-25. | Static path sweep; registry evidence, no out-of-worktree edits |

Repair commits: `e14a38e4` (interpreter/startup and stored-record tests), `098380c3` (statement eligibility, host-config and managed-boundary tests), `a4aa9ca8` (pinned CI oracles), `3d79ad4e` (fixed self-job suspension through the owned signal boundary), and `de7d34e8` (merged fixture signals use the test-only helper). Each commit names its mutations. Compile failures while preparing a mutation were retained as diagnostics and never counted as gate failures.

The task-owned portions of gates 23, 33, 39 and 40 and requirements R-M2-03, R-M2-24, R-M2-49, R-M2-50, R-M2-52, R-M2-74, R-M2-86 and T-16 retain the mapping above. This integration needs fresh PR and manual full CI on the merged head before landing; the older green runs at `5ef8b9d3` do not qualify it. The driver owns pushing and triggering those runs. No Linux or fresh remote CI result is inferred from the local checks.


### Final merged-head local receipt

The detached macOS run completed all 30 validation stages on the merged production code. One reservation-checker fixture failed; `9cad00f0` repairs its coupling to a newly landed product token. The complete 92-test checker target and six formatting, strict-Clippy and boundary checks then passed. The initial managed-runner stage also failed at service installation; its full 19-test rerun, including an actual launchd restart, passed after a fresh test-instrumented build. All remaining initial stages passed. Together these runs qualify every changed crate on the final head. The run used an empty inherited environment, private short temporary HOME/XDG/TMPDIR directories, the assigned target directory, no incremental compilation, three build jobs, `--no-fail-fast` and three test threads. Test-instrumented binaries were rebuilt before the end-to-end gates. No workspace-wide test command was run.

| Checks | Result |
| --- | --- |
| `cargo fmt --all --check`; workspace/all-target Clippy with `RUSTFLAGS="-D warnings"` | Pass |
| Full core, IPC, client, policy, daemon, exec, sys, MCP, agents and testkit crate tests | Pass |
| CLI crate tests, including one unabridged doctor suite with its long budget case | Pass; doctor 12/12 |
| E2E library/binary tests; full managed_launch and managed_runner suites | Pass; managed_launch 31/31, managed_runner 19/19 |
| Real service-manager restart (`ENVCLOAK_TEST_SERVICE_MANAGER=1`) | Pass within managed_runner |
| Full sys PTY and exec suites; real CLI PTY job-control suite | Pass; CLI job control 2/2 |
| Pinned-runtime provisioning, execution-receipt controls and all five runtime oracles | Pass |
| Unsafe, exposure lint, compiler-source, crate-graph, reservation and SPEC checks | Pass |
| CI path self-test and macOS CI-job controls | Pass |

The initial strict-Clippy attempts exposed incoming M2-19 numeric signal calls: production self-group suspension, the PTY relay fixture and the late pipe-signal fixture. The production path now uses the one owned signal boundary; both fixtures use the existing testing-only helper. `restore-production-numeric-signals-in-tests` was observed rejected at both fixture calls. Strict Clippy and the exec/PTY suites passed after these repairs. The separate testkit fixture failure and its complete-target repair run are recorded above, rather than describing the first aggregate as green.

The initial launchd installation did not produce an answering daemon within the existing install deadline. No managed registration or restart had been reached. The full detached managed-runner rerun passed with the same source and unchanged timeout after rebuilding the instrumented binaries. The initial failure remains in the receipt; the retry does not establish why that startup failed.

The fixture repair commit is `9cad00f0`; its named mutation results are `m27-r8-reservation-mutations.json`. Receipts are local `m27-r8-runner-recheck-results.json`, `m27-r8-checker-final-results.json`, `m27-r8-final-results.json` and `m27-r8-final-*.log`; named mutation receipts include `m27-r8-mutation4-results.json`, `m27-r8-provision-mutations.json` and `m27-r8-pty-mutation-results.json`. Fresh merged-head PR and manual full CI on macOS and Ubuntu remain driver-owned before landing. The signed-build privacy-prompt measurement and M2R-87 remain explicit residuals with the owners above. No remote result is claimed and no push was performed.


## M3-04 integration and current local receipt

Merge `99b83863` joins `479568fe` with main at `6489768b`. The three conflicts
retain both daemon modules (`managed` and `projects`), all 44 client methods,
and both families of wire views. The auto-merges in requests, server dispatch,
state, typed client helpers, IPC documentation and vault limits were reviewed.
Both ordinary and managed delivery keep M3-04's provisional project adoption,
rollback, audit correction and final authority check. The sealed managed record
still governs launch identity and private value delivery; it does not replace
SPEC 6.4/6.6's project-index adoption. Methods and descriptor/control-pipe paths
remain present.

The compile sweep found five incoming `RunRequestParams` constructors missing
the managed fields. Commit `0fc986cb` supplies no bridge or launch and an empty
descriptor list for each ordinary manifest request. The instances are the
metadata-screening case, near-limit manifest case, initial and refreshed
adoption requests, and adoption during pagination. No assertion changed.
The first repair attempt also used an optional value for the descriptor vector;
the compiler rejected all five sites, and the final repair uses empty vectors.
Neither compile failure is counted as a gate mutation.

A final SPEC cross-check found a second composition class: the managed route
returned before M3-04's new project-record construction. The initial merge
supplied no adoption row there. Commit `62a74cac` corrects this by constructing
the effective manifest metadata once before routing and passing it into both
production delivery calls, including the shared runner/relay path. No second
binding filter or index writer was introduced. The new end-to-end gate proves
that registration, pending requests and approval alone adopt nothing; admitted
delivery records the exact directory, hash and bindings; a subsequent covered
run refreshes the hash; and a changed executable is refused without changing
the index. It also requires zero releases to clients, two to runners, and a
clean value sweep. The HTTP transport itself remains M2-18's scope.

Mutation `omit-managed-project-adoption` replaces `Some(c.project)` with
`None`. It compiled and failed the new gate with zero indexed rows instead of
one, then passed after byte-for-byte restoration. The unfixed merge also failed
that gate before the repair. The named mutation
`drop-ordinary-project-adoption` removes the project row from ordinary delivery while leaving delivery itself successful. The compiled
`projects_adopted_by_run_are_listed_with_current_bindings_and_hashes` gate
failed at runtime with zero rows instead of two. Restoring the production
source byte for byte made all six project integration tests pass. The final
instrumented daemon and fixture build passed after the Swift script and the
mutation run, so neither a plain daemon nor a mutated binary is left as the
end-to-end fixture.

These are macOS 26.4.1 arm64 measurements. Cargo used the assigned lane A
cache, incremental compilation disabled and three build jobs. Tests ran
detached from agent ancestry with cleared inherited environments, isolated
short temporary HOME/XDG directories, `--no-fail-fast` and three test threads.
The main validation supervisors also set private TMPDIR/state/runtime roots.
No workspace-wide test command was run.

| Check | Current result |
| --- | --- |
| Formatting; strict workspace/all-target Clippy | Pass after the constructor repair |
| Full IPC, core and client crate suites | 65, 344 and 40 pass |
| Full daemon crate suite | 276 pass, including all six M3-04 project integration cases and delivery rollback/authority tests |
| Full policy crate suite, with service-manager testing enabled | 211 pass, one service-start timeout; all three full runs have the same result |
| Full managed_launch suite | 32/32 pass |
| Full managed_runner suite, with service-manager testing enabled | 18 pass, one initial service-start failure before the restart assertion |
| CLI run, ref_unset, ref_edit and snapshots targets | 4, 3, 3 and 5 pass; includes real CLI project adoption and the independent TOML/byte oracle |
| All five pinned-runtime interpreter oracles; execution/archive controls | Pass; the four ignored cases in the ordinary policy run execute here |
| `scripts/macos/test-kit.sh` | Pass: fresh Rust vectors, 36 Swift tests and two optimized wiping probes |
| Unsafe, exposure lint and Rust compiler-source checks | Pass; all eight forbidden exposure/signal sites reported |
| Crate graph, reservations and SPEC decisions | Pass: 50 edges, 270 rows, 54 decisions and 51 sentences |
| Swift rules, compiled-source check, CI job controls and CI path self-test | Pass; compiled-source check uses the existing Kit build records, with unchanged Swift sources |

Two local checks remain unsuccessful, and this receipt does not describe the
aggregate as green:

- Policy's `gate26_launchctl_submit_escapes_the_grant` times out waiting for its
  service-started probe. It fails in all three full policy runs. The probe and
  that test are unchanged from `479568fe`.
- Managed runner's `the_runner_outlives_a_service_manager_restart` fails while
  installing the fixture service because the daemon never answers. It has not
  reached registration or the restart assertion. The daemon-install code and
  system boundary are also unchanged by this merge. The separate
  `the_runner_outlives_the_daemon` case passes.

A detached, value-free diagnostic reproduced the host startup problem outside
the test harness: launchd's system `true` control exits successfully, while its
`ec-probe` process never connects. Sampling that owned fixture shows it still
in dyld's `getOnDiskBinarySliceOffset` / `__open` path before program startup.
The corresponding TCC log records a denied `SystemPolicyAllFiles` preflight.
A diagnostic with output files in the lane cache also records launchd
`posix_spawn` refusal with `Operation not permitted`. Together with the
verifier's independent exit-126 control below, this is a local host limitation: launchd cannot run the fixture binaries/scripts from the
external SSD here. No timeout, assertion or host policy was changed. The final
local managed-runner repeat still fails at initial installation; successful CI
on both supported platforms, recorded below, is the authority for these gates.

The final production-code repeat is `m27-m304-adoption-results.json`, with
`m27-m304-managed-mutation.json` for the new gate. Earlier receipts are
`m27-m304-results.json`, `m27-m304-followup-results.json`,
`m27-m304-policy-recheck.log` and `m27-m304-mutation-result.json`. Core, client,
reference editing, snapshots and Swift source/CI controls are unchanged since
their earlier passing runs; the final repeat covers the daemon, IPC, policy,
both managed suites, CLI run, runtime oracles, boundary scripts and Swift kit.
The first supervisor also recorded three invocation errors (an old CLI target name, an incorrect script path and a
missing Swift build-record argument); the correctly invoked checks all passed
in the follow-up receipt. The final Swift repeat initially reused the vector
directory populated by the full IPC suite and correctly failed `AlreadyExists`.
A separate fresh vector directory made the full kit script pass again, 36 plus
two optimized Swift tests; `m27-m304-swift-final-results.json` records that run
and the successful instrumented rebuild afterwards. Diagnostic receipts are
`m27-m304-service-controls.log`, `m27-m304-probe-sample.txt` and
`m27-m304-service-tcc.log`. They stay in the private lane cache. Machine-specific
absolute paths are omitted here and removed from the incoming M3-04 receipt.

The prior scope, requirement and mutation mapping remains above. The final
review handoff records the subsequently supplied PR and manual full CI results.
The signed-build privacy-prompt measurement, standing-test handoff and M2R-87
remain open with their owners. No push was performed.

## Final review handoff, 2026-10-08

This follow-up changes documentation and residual tracking only. Production code
and runtime tests remain byte-identical to `53406f4c`. The driver-supplied verifier
reports PR run `37609446417` green and manual full run `37610408716` green on
macOS and Ubuntu, including test, release, managed runtime oracles and
agents-e2e. Its macOS receipt has managed_launch 32/32 and managed_runner 19/19,
with zero ignored; the service-manager restart asserts in CI instead of skipping.
Linux also ran the hardened-process CR-1 precondition and the OwnedChild
compile-fail doctest. These are attributed CI results, not new local executions.

The two unsuccessful local service checks are a host limitation: launchd cannot
run fixture binaries/scripts from the external SSD on this Mac. In addition to
the dyld, TCC and `posix_spawn` observations above, the independent verifier's
`launchctl submit` of an SSD script exited **126**. The system `true` control
exited 0. This supports external-volume execution denial here, not a product
failure or a general claim about every external volume. CI is the authority for
`gate26_launchctl_submit_escapes_the_grant` and
`the_runner_outlives_a_service_manager_restart`. Host policy is unchanged.

### Residual registration and scope

The driver registered **M2R-88** and **M2R-89** in the canonical
`.collab/m2-residuals.json` with the exact handoff contents. This lane confirmed
both entries read-only, including owner, open state, deadline and closure
evidence. The duplicate handoff JSON has been removed. M2R-87 remains registered
and open as before.

| ID | Owner and deadline | Open work and closure evidence |
| --- | --- | --- |
| M2R-88 (registered, open) | M2-27, before the M2 release | Signed build on a real Mac: a daemon-started server performs a protected-folder read and a local-network request. Record each prompt's named process, macOS version/build and EnvCloak version/signing identity; update MIGRATE-MCP's Consequences privacy bullet and this receipt. Existing consent or no prompt is not attribution evidence. |
| M2R-89 (registered, open) | M2-15, before its gate 39/40 closure and the M2 release | A foreign client under a real covering standing record gets `started` and fixture protocol, no value, zero client releases and a runner release. No session/once grant may mask standing coverage. Sweep every client-visible output and readable-memory capture with generated fixtures and a positive detector control. Include the genuine hardened-client control and fail the `return-values-to-foreign-client` mutation. Audit the remaining standing matrix, including upward search and changed launch inputs. |
| M2R-87 (registered, open) | M2-25 hardening pass | Durable recovery for a stopped runner before anchor resumption, under D-34 owned authority; the earlier handoff is unchanged. |

The implemented portions of gates **23, 33, 39 and 40** and requirements
**R-M2-03, R-M2-24, R-M2-49, R-M2-50, R-M2-52, R-M2-74, R-M2-86 and T-16** retain
the earlier test and mutation mapping. They do not close the physical spike-(c)
measurement or M2-15's standing-policy tests. HTTP relay behavior (M2-18) and
host rewrite/backup round trips (M2-20) remain with the plan's named owners.

### Finding classes and sweep

The sweep inspected all 103 paths changed from `origin/main`, plus this
follow-up's residual handoff. No production fix was needed for these findings.

| Class | Instances and disposition | Check |
| --- | --- | --- |
| Untracked acceptance work | Privacy prose in MIGRATE-MCP and the validation class table/final receipt; standing issuance and negative-case coverage in the gate mapping, managed_launch and managed_runner suites, policy grants documentation, and M2-15/M2-27 tests-first lists. The two new handoff entries name owners, deadlines, closure evidence and target docs. M2R-87 was checked already registered. | Read-only canonical-registry comparison; handoff JSON validation and cross-reference checks. Physical privacy and standing runtime evidence remain open. |
| Stale or overstated qualification | Historical launchd results, final M3-04 diagnostic conclusion, repeated fresh-CI requirements, and the current summary. Historical failures stay failures; the final receipt supersedes pending-CI language and names the external-SSD limitation with the independent exit-126 control. | Compare the supplied verifier receipt with both named service gates and local diagnostic receipts; no host policy change or timeout relaxation. |
| Missing independent review evidence | Two prior empty review outputs supplied no verdict. Neither counts as a clean review. | A new independent read-only review at `53406f4c` returned an explicit clean verdict for the inspected production paths, with no new actionable findings. It did not rerun runtime checks or close the residuals. |

The verifier separately witnessed six runtime mutations at `53406f4c`: remove
launch identity comparison, resume the macOS child before confirmation, omit
origin and binding-digest checks, ignore launch revision, inherit all environment
and omit its code-selecting filter, and omit the registered cwd. Each failed its
assertion; all five affected e2e tests passed after restoration. Linux-only
mutations retain the earlier receipts and Linux CI evidence. No new runtime gate
or implementation mutation is introduced by this documentation-only follow-up.

At `98e468ea`, the supplied verifier reports PR run `37630033288` and manual
full run `37630066105` green on macOS and Ubuntu. The manual macOS job needed
one rerun for the existing `proc.rs` process-memory flake, in a file M2-27 does
not change. These newer results qualify the documentation follow-up; they do
not qualify later production changes in this receipt. M2R-88, M2R-89 and M2R-87
remain open with their named owners. The physical privacy measurement is
scheduled as a driver-coordinated signed-build release prerequisite owned by
M2-27, before the M2 release; no calendar date or completed measurement is
claimed. It must exercise both operations on a real Mac and record prompt
attribution plus macOS and signed-build versions before M2R-88 closes.


The independent review covered record/identity/origin/revision checks before
pending and grant evaluation, lock-held record and proof rechecks, descriptor
handoff, private runner release, Linux sealed images and retained anchor,
macOS suspended confirmation, interpreter/environment policy, runner cleanup
ownership, and ordinary/managed project adoption through `State::deliver`.
Its verdict is scoped static evidence, not a second runtime pass.

The final detached documentation-follow-up checks passed: `cargo fmt --all
--check`; `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets`;
unsafe, expose and compiler-source scripts; crate graph, reservations and SPEC
decisions; managed-oracle control tests; and all five real-runtime managed
oracles (5 passed, 0 failed, 0 ignored). The first unsafe invocation incorrectly
used `sh` for a Bash script and exited 2 on syntax; the corrected Bash invocation
passed. Raw receipts are `m27-review-final-results.json` and
`m27-review-final-unsafe-correct.log` in the private lane target directory.
The residual JSON parsed, its owner/state/deadline fields and proposed-ID
availability matched the read-only canonical registry, and doc references,
private-path/style checks and `git diff --check` passed. No crate changed in this
follow-up, so the existing full-crate receipts and the supplied green CI at the
identical production tree remain its crate-suite evidence. No workspace-wide
test command, host-policy change, push or GitHub comment was performed.


## Descriptor and policy coverage follow-up

The review at `98e468ea` found one production defect and two coverage gaps.
`ClientEnds` accepted any socket for stdin and the lifeline. A Unix datagram
peer's exit need not produce EOF, so the runner's reader threads could wait
indefinitely after that client exited. Commit `0bfb2b81` checks socket `SO_TYPE`
through the sys boundary, admits only byte-stream sockets for standard streams,
and requires the lifeline to be a read-only pipe. Unsupported types and failed
socket queries refuse before pending or release. The same validator serves
stdio runners and HTTP relays.

Commit `07c6ea1e` adds direct coverage of the existing policy behavior. The
launch-field matrix changes revision, class, strength, argv bytes/order/count,
each cwd component, environment path/names/values/counts, binding names/counts,
entry presence and all declaration fields. Executable and entry identities each
exercise path/device/inode, SHA-256, digest kind, cdhash, Team ID and signing
identifier, including absent versus empty optional identities. Each variant
must change `launch_digest` and `update_digest` on both the old and new side.
The common launch id is checked in its outer statement field. The loader matrix
separately feeds recorded variables and released bindings, testing `LD_*`,
`DYLD_*`, future prefix names and every exact code-selecting variable, with
allowed-name controls. No policy encoding or environment implementation changed.

| Bug class | Instances swept across all 103 changed paths | Test and mutation |
| --- | --- | --- |
| Descriptor type mistaken for stream/EOF semantics | sys `descriptor_kind`; daemon `ClientEnds` and request routing; CLI control handoff. No second caller-provided descriptor validator exists. Every stdin/stdout/stderr/lifeline role is covered for runner and relay, with valid pipe/stream controls and a write-end lifeline refusal. Internal control sockets are created as streams. | `descriptor_kind_distinguishes_streams_from_datagrams` and `managed_descriptors_require_streams_and_a_read_only_pipe_lifeline` fail on the original implementation. `accept-datagram-streams` fails both gates; `accept-socket-lifeline` fails daemon admission. Both tests run on Linux and macOS. |
| Digest fields left without omission coverage | Shared policy launch encoder, update statement and audit digest; nested executable/entry/cwd/environment/declaration encoders; core record schema and daemon update/audit consumers. | `every_launch_field_changes_both_digests` fails `omit-resolved-cwd-digest` on the cwd path assertion. No digest implementation defect was present. |
| Another filter masks a missing boundary test | Policy environment builder, declaration/stored-record checks, exec builder call, CLI and control-message handoff. Inherited allowlisting must not stand in for recorded-variable or binding filtering. | `loader_names_are_filtered_from_recorded_vars_and_bindings` fails `allow-loader-recorded-vars` and independently `allow-loader-bindings`. Allowed names pass both paths. |
| Stale tracking and unsupported prompt-attribution claims | MIGRATE-MCP privacy bullet; validation gate mapping, class table, residual status and CI receipt; duplicate handoff JSON. | Canonical M2R-88/89 entries checked read-only against the exact committed handoff. Proposed-ID wording and the duplicate JSON removed; newer supplied `98e468ea` CI recorded above. No physical prompt result claimed. |

All five named mutations above compiled and failed their intended assertions;
`accept-datagram-streams` was checked against two gates. All focused controls
passed before mutation and after restoration. The first daemon baseline build
was interrupted by the shared compiler cache retaining a deleted temporary
directory from an earlier isolated job. That compile failure is not a mutation
receipt. Disabling the compiler wrapper for this lane's detached jobs let the
unchanged baseline run and fail its actual `datagram Stdin` assertion; no shared
cache process or host policy was changed. Receipts are `m27-r10-mutations.json`
and the correspondingly named local logs.

M2R-88's physical measurement remains a pre-release prerequisite owned by M2-27,
coordinated by the driver. The independent Cycle575 P01-P04 controls require
synthetic operations, separate permission contexts, a prompt-producing positive
control and a no-operation baseline for each surface. A loopback-only request,
existing consent, process ancestry or green CI cannot establish attribution.
M2R-89's S01-S07 controls remain with M2-15, including real standing minting
beneath an eligible agent root with no cached grant masking it. Both residuals
are registered and open; this corrects the review's stale registration premise,
not the missing measurement. M2R-87 remains open with M2-25. No outside-worktree
registry, privacy setting, signing keychain or protected user file was modified.


### Final local receipt for the descriptor repair

All 15 detached stages passed on the production changes in `0bfb2b81`, with the
policy tests in `07c6ea1e`. The run used an empty inherited environment, private
short temporary HOME/XDG/TMPDIR directories, the assigned target directory,
`CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=3`, `--no-fail-fast` and three test
threads. The instrumented binaries were rebuilt before the integration tests;
no plain daemon build overlapped them. No workspace-wide test command was run.

| Check | macOS result |
| --- | --- |
| Formatting and strict workspace/all-target Clippy | Pass |
| Full envcloak-policy suite | 214 reported passed, four runtime cases ignored here and explicitly executed below; local service-manager case not exercised |
| Full envcloakd suite | 277 passed, including descriptor admission, frame refusal and delivery/adoption checks |
| Full envcloak-sys suite | 213 passed, two existing ignored documentation examples; OwnedChild compile-fail test passed |
| managed_launch | 32/32 reported passed |
| managed_runner | 19/19 reported passed; includes 18 exercised cases and the local service-manager case's documented skip path |
| Client-death cleanup controls | `the_client_killed_stops_the_server` and `the_lifeline_ending_stops_the_server` passed |
| Unsafe, exposure and compiler-source checks | Pass |
| Crate graph, reservations and SPEC decisions | Pass |
| Managed runtime oracle controls and check script | Pass; all five real-runtime cases executed, none ignored |

The local service-manager opt-in was not enabled because the external-SSD
launchd limitation above is unchanged. Its two skipped paths are not fresh
service qualification. The supplied `98e468ea` CI runs retain that historical
evidence; the driver must obtain fresh macOS and Linux CI for the descriptor
repair before landing. No Linux execution or physical privacy observation is
inferred from this Mac's checks.

The final receipt is `m27-r10-final-results.json`; its stage logs and the named
mutation logs remain in the private lane target directory. Canonical residual
entries were compared byte-for-field with the former handoff; doc references,
private-path/style checks and `git diff --check` passed. The task-owned mapping
for gates 23, 33, 39 and the launch portion of 40, and R-M2-03, R-M2-24, R-M2-49,
R-M2-50, R-M2-52, R-M2-74, R-M2-86 and T-16 remains unchanged. M2R-88, M2R-89 and
M2R-87 retain their stated owners, deadlines and open work; HTTP transport and
host rewrite round trips remain M2-18/M2-20 as the plan assigns. No push or
GitHub comment was performed.


## M2-21 merge integration

Merge `56964998` joins M2-27 at `ac90aed5` with main at `6750d841`.
The three conflict resolutions preserve the exact union of both parents:

- `AuditKind` has 30 entries in numeric order. Reveal remains 22;
  managed registration and launch remain 29 and 43. Tokens and decoding
  retain both families with no renumbering.
- The typed client protocol has 45 methods, including `items.reveal`, all
  four managed methods and `projects.list`. Reveal parameters/output and
  the managed declaration, update and runner fields are retained.
- Reservation tests keep M2-21's synthetic audit/exit rows and M2-27's
  independent generic token fixtures. Tests no longer borrow the now-landed
  reveal audit kind as an unimplemented reservation.

The auto-merges were checked through CLI, client, daemon routing, proof
boundaries, audit conversion, exposure allowlisting and IPC/VAULT docs.
Linux reveal still checks the requester before proof and again before release,
and durably records the reveal before sending its framed value. Its shared
pending-request boundary includes managed requests; managed update-plan and
proof checks remain intact. macOS keeps its no-value method refusal.
The terminal-only exposure allowlist entry coexists with the runner's entries.

| Merge check | Mutation receipt |
| --- | --- |
| `managed_and_reveal_methods_are_known_client_methods` independently pins both families, requiring one registry entry, client role and the known log label | `drop-reveal-client-method` and `drop-managed-client-method` each compiled and failed the missing-entry assertion; original and restored controls passed |
| The existing reservation checker validates the audit decoder's complete ordered registry | `drop-reveal-audit-all` failed on the omitted `AuditKind::Reveal`; the restored checker passed |

The reservation checker alone accepted a client-method-list omission, since
it checks typed method definitions rather than that list. That surviving
probe led to the focused IPC test above; it is not counted as a failing
mutation. The audit probe was a static checker failure, not a runtime test.
Raw mutation receipts are `m27-m221-ipc-mutations.json` and the named audit
checker log in the private lane target directory.


### Detached validation after M2-21

The run uses the same private short HOME/XDG/TMPDIR isolation, empty inherited
environment, assigned target directory, incremental compilation disabled,
three build workers and three test threads. Cargo tests use `--no-fail-fast`;
no workspace-wide test command is used. Strict Clippy covers the workspace and
all targets. Instrumented binaries are built before integration tests.

The first build reused testkit binaries whose timestamps preceded the merged
`Cargo.lock`: Cargo had no changed dependency to compile for those binaries,
while the testkit's conservative freshness guard requires a newer link.
Policy's `evidence_gates` and daemon `backups_v2`/`live_guard` therefore refused
those fixtures before testing their behavior. These are failed checks, not
behavioral passes. The guard remains unchanged; the repair is a package-scoped
clean of testkit build output and a fresh instrumented binary build, followed
by retries of every affected target. Initial and retry logs are retained
separately in the private lane target directory.


All requested checks are closed on the merged code. Policy was rerun in full;
daemon `live_guard` passed 9/9 and `backups_v2` passed 38/38 after the rebuild.
The first retry helper excluded digits in a target name and missed
`backups_v2`; receipt inspection caught that omission, the helper was fixed,
and the target was run explicitly. A separate receipt comparison matches
all 12 initially failing policy cases and all 24 initially failing daemon
cases to named passing retries. The initial failures are not erased or counted
as passes.

| Check | macOS result after retries |
| --- | --- |
| `cargo fmt --all --check` | Pass |
| `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets` | Pass |
| Full envcloak-core | 344 passed |
| Full envcloak-ipc | 67 passed, including the new registry omission gate |
| Full envcloak-client | 42 passed, including terminal-write refusal controls |
| Full envcloak-policy | 214 reported passed; four ignored runtime cases exercised by the oracle script below; local service-manager path not exercised |
| Full envcloakd, with affected targets rerun | All 278 covered; 254 initially passed, with both affected targets fully passing after fixture rebuild |
| envcloak-sys library | 109 passed |
| testkit `check_reservations` and `check_reservations_m3` | 92/92 and 23/23 passed |
| Reveal CLI/stub tests and gate-34 story | 8/8 and 1/1 passed |
| managed_launch | 32/32 passed |
| managed_runner | 19/19 reported passed; 18 exercised cases plus the documented local service-manager skip |
| Unsafe and exposure check scripts | Pass |
| Source, crate graph, reservation and SPEC-decision check scripts | Pass |
| Managed oracle controls and runtime check script | Pass; all five runtime tests executed, none ignored |

The existing external-SSD launchd limitation remains: the policy launchctl
escape and runner service-manager restart paths are not locally qualified.
No host policy was changed. Linux reveal's runtime behavior and both real
service-manager paths still require fresh CI on this merge; earlier green
runs are not claimed as evidence for this head. M2R-87/88/89 and the plan's
other task-owned follow-ups retain their existing owners and deadlines.

Receipts are `m27-m221-final-results.json`, `m27-m221-recheck-results.json`,
`m27-m221-backups-v2.log` and `m27-m221-validation.json`, with their stage logs
in the private lane target directory. The combined receipt checks that every
initial failure has a passing named retry. The merge and omission-test
receipts above are unchanged. No push or GitHub comment was performed.

## Review round r2 repairs, 2026-10-08

Seven findings from the last verifier and review were resolved. Each is
listed with its bug class and the instances swept across every file this
task adds or changes.

| Finding | Class | Instances swept and disposition | Regression and mutation |
| --- | --- | --- | --- |
| `luajit -jv` loads `jit.v` through `./?.lua` before the entry (medium) | Short interpreter options checked against a denylist that cannot be complete | Every family's short options. They are now refused unless listed harmless for the family (`harmless_short`), an attached-only value (`attached_short`: `ruby -W`, `luajit -O`) or a checked value (`value_short`). This is the stance already taken for long options with `=value`. Measured with the pinned LuaJIT: `-jv` runs `./jit/v.lua` first, `-b` runs `./jit/bcsave.lua` and not the entry, `-v`, `-O3` and `-jon` run only the entry. Registration, updates, `#!` lines and stored records all go through `classify_named`. | `short_options_register_only_when_known_harmless` (declaration, update and shebang), `luajit_module_options_load_code_before_the_entry` (real LuaJIT oracle, benign-entry, `-v` and `-O3` controls), stored-record cases in `launch_check`. Mutation: the `harmless_short` check removed. Both new tests fail on `luajit -jv` |
| `Ready::send` failure leaves only a `covered` entry (low) | A failure after the delivery is committed that the audit does not correct | `Ready::send` (every error kind, not only `managed_launch_changed`). Also the two `grants().consume` failures after a delivery entry (managed and unmanaged), which now audit `internal`. Registration, update and unregister audit right after their commit and cannot fail after it. | `a_release_that_fails_after_delivery_is_audited`, using the new `launch.release_write` fail point. Mutation: the new audit removed. The log ends at `covered` and the test fails |
| macOS replacement controls never reach the cdhash comparison (low) | A control refused by a coarser predicate than the one it claims to test | `other_build` (used by eight managed_launch tests) now re-signs with the original identifier, so only the cdhash differs. The anchor test gains a same-identifier real `envcloak` replacement before its script one. No other macOS replacement control claims the cdhash check. | Mutation "cdhash value ignored" in `ExpectedCode::matches`: `the_anchor_is_the_image_taken_at_start` and `the_approved_image_runs_whatever_happens_at_the_barrier` fail |
| Stale mutation claim on the barrier test (low) | A test claiming a mutation it cannot fail | The "child resumed before the answer" claim is removed from `the_approved_image_runs_whatever_happens_at_the_barrier`. That mutation stays on `a_suspended_server_runs_nothing_until_the_daemon_confirms`, the test that catches it. | As above |
| Standing-record foreign-client leg, M2R-89 (medium) | Coverage that names a grant kind it does not exercise | The foreign-client test now runs under each grant this build issues: the default session grant and a `once` grant (`a_foreign_client_under_a_once_grant_gets_started_and_no_value`). Each case checks that the approval covers the request and adds no pending request. A standing record cannot be made in this build: `envcloak standing` is M2-15's `not_in_this_build` stub, and the daemon has no standing minting. The standing leg therefore stays M2R-89, owned by M2-15. Gates 39 and 40 are not claimed closed for standing records. | Mutation: a managed route answered as an unmanaged one, which returns the values to the client. Both foreign-client tests fail on the sweep |
| SPEC §6.6 states the unmeasured prompt attribution (medium), and validation line 351 (low) | An unmeasured claim stated as fact | SPEC §6.6 now says the attribution is unmeasured and tracked as M2R-88, matching MIGRATE-MCP. No other document states it. | `check-spec-decisions` passes. M2R-88 stays open for a signed build on a real Mac, by founder direction |

## Review round r3 repairs, 2026-10-08

Seven findings from the r2 verifier and Codex review. Five are fixed. One
is fixed defensively, though a measurement contradicts its premise. Two
remain registered residuals with their owners (evidence below).

| Finding | Class | Instances swept and disposition | Regression and mutation |
| --- | --- | --- | --- |
| Ruby `-W`, `-K` and `-T` read a short value and then the rest of the cluster as options: `ruby -We'code' /s.rb` runs `code` (medium) | A value option modelled as ending its cluster where the real parser goes on reading options | Every `value_short` and `attached_short` entry, checked against each interpreter's parser. Ruby 3.4.7 `ruby.c`: `-W` reads one octal digit or a whole `:category`, `-K` reads one letter, and both then `reswitch`; `-F` takes the rest. Now `W` and `K` take their value as ruby does, and the letters after it are checked. `-W:` accepts only a known category, and `-T` is refused. Bash and dash `-o`/`-O` take the next argument whatever follows in the cluster (measured: `bash -oposix /s.sh` reads `/s.sh` as the option name, and `bash -Oc extglob 'code'` runs `code`); zsh and ksh take the rest. So `-o`/`-O` now leave the entry unknown (`no_entry_file`), attached or not. CPython `-W`/`-X`, PHP `-t`, Julia `-t -p -O -g` (getopt) and LuaJIT `-O` (whole argument to `jit.opt`) consume the rest and are unchanged. No `harmless_short` letter takes a value. | `ruby_short_values_do_not_end_the_cluster` (declaration, update, `#!` line), `shell_option_names_leave_the_entry_unknown`, stored-record cases in `launch_check`, and the new pinned Ruby 3.4.7 oracle `ruby_short_values_read_the_rest_of_the_cluster_as_options`. The oracle puts payloads behind `-W`, `-W1`, `-KU`, `-Wr` and `-WI.`, with `-W2`, `-w`, `-W0`, `-W:no-deprecated` and `-KU` as controls. Mutations: ruby `W`/`K` returning `Ok` at their letter (the unit test and the oracle fail on `-We...`); `o`/`O` back in `value_short` for the shells (`bash -oposix` registers) |
| Grant-use failure audits untested (low) | A failure-path audit no test can reach | Every audit this task added on a failure path: `Ready::send` (tested in r2), both `grants().consume` failures (new `run.grant_consume` fail point), and the runner start failure in `prepare_runner`, whose audit was untested too. `prepare_runner`'s consume audit now names its grant explicitly. | `a_managed_grant_that_cannot_be_used_is_audited`, `an_unmanaged_grant_that_cannot_be_used_is_audited`, and `a_runner_that_cannot_start_releases_nothing`, which now reads the sealed log. Mutations: each audit removed in turn; each test fails on the log |
| A Linux sparse descriptor mapping leaves inherited descriptors below the highest target open (medium) | A descriptor number that a later step reuses or skips | Linux `child_main` now closes every number below the report pipe that is not a target (stdio included, as macOS's `POSIX_SPAWN_CLOEXEC_DEFAULT` does), then everything above. The macOS start also moves the directory's descriptor above the targets. Both callers (the daemon's runner start and the runner's server start) map 0, 1 and 2 themselves. | `only_handed_descriptors_reach_the_child_and_the_directory_survives_a_collision`: a helper run with an inherited descriptor 5 hands over a pipe at 7 only, then a directory descriptor numbered as a target. Mutations, Linux in a container: closing only from above (the child has 0, 1, 2 and 5 open), and `fchdir` through the unmoved number (the start fails). Both fail |
| macOS cwd descriptor overwritten by a target (low) | As above | Fixed defensively, but a measurement contradicts the premise. On macOS 26.4, with the move removed, the child still starts in the directory the parent named, so the test cannot fail there. The move stays because the order of file actions is not documented. | The same test. Its Linux leg is the one that fails under the mutation |
| The injected-library oracle captured only readable and writable memory (medium) | A sweep narrower than the requirement it serves | The dumper now captures every readable region. It reads each region through the system (`process_vm_readv` on Linux, since a hardened client's `/proc/self/mem` belongs to root; `mach_vm_read_overwrite` on macOS), so an unreadable part is skipped and counted rather than faulting. The only regions excluded are read-only ones the process never wrote: file contents as on disk, and untouched reservations. A read-only control page is planted at load. The mutation was run on macOS only: the local Docker engine stopped responding before the standalone Linux check ran, so on Linux the control is shown only by the green CI run. | `an_injected_library_finds_no_value_in_the_client` (a 164 MB dump on macOS, 0 bytes unreadable). Mutation: dump read-write regions only. The read-only control is then missing and the test fails |
| Standing-approval leg (medium) | Coverage naming a grant kind it does not exercise | The evidence is unchanged. This build cannot mint a standing record: `envcloak standing` is M2-15's `not_in_this_build` stub, and M2-15 is not on main at 3d64c9a1. M2R-89 stays with M2-15. | n/a |
| Unresumed macOS runner after a daemon crash (low) | A crash window that leaves a process no owner can end | M2R-87, owned by M2-25 under D-34 owned authority; M2-25 is not on main. No handle survives a daemon crash, and D-34 forbids signalling a process found by name. | n/a |

Local receipts are `r3-mut-results.json` and the `r3-*.log` files in the
lane's target directory. The e2e and daemon runs were detached from any
agent's process tree, with a cleared environment.

## Review round r4 repairs, 2026-10-09

Six findings from the r3 verifier and Codex review. One is fixed, one is
a CI gate handled on GitHub, one is left as the optional note it was, and
the two residuals stay with their registered owners.

| Finding | Class | Instances swept and disposition | Regression and mutation |
| --- | --- | --- | --- |
| `node --allow-fs-read <file> --permission -e <code>` registers with `<file>` as its entry and runs `<code>`; registration and stored-record revalidation share the parser (high) | An option's arity taken from a rule shared across interpreters instead of measured on the interpreter that parses it | Every long-option rule in `interpreter_option`. The shared `BOOLEAN_LONG` list and its prefixes (`--no-`, `--allow-`, `--deny-`, `--enable-`, `--disable-`) are now `boolean_long`, one measured list per family: Node 26.7.0's own option table (its non-boolean `--allow-fs-read`, `--allow-fs-write`, `--disable-warning`, `--disable-proto` are refused bare; `--no-` stays because Node refuses it on any option that is not boolean), deno's `--allow-`, `--deny-` and `--no-` (values only after `=`), Bun 1.3.13 (`--smol`, `--no-`), Ruby (`--enable-`, `--disable-`, `--verbose`, `--jit`, `--yjit`), bash and zsh. Any other family has none, so a bare long option leaves the entry unknown. Swept and unchanged: `value_short`, `attached_short`, `shell_named_option` (already per family and measured), long options with `=value` (an attached value never moves the entry), the daemon's `names_a_file` (looks at every argument), and the package runners' option scan (it only labels a launch that is never bound) | `long_options_take_values_as_their_own_interpreter_does` (policy: classification, declaration, update, `#!` line, and the measured booleans as controls); `a_stored_value_taking_long_option_cannot_keep_its_entry` (daemon launch check on a stored record, with a boolean-option control); the real-Node oracle `node_long_options_take_values_as_node_does` runs the injected forms on Node 26.7.0, then every Node option and its `--no-` form that the policy accepts bare, between two files, and requires Node never to run the second. Mutation: one shared prefix list for every family, as before; all three fail. A second mutation lists `--title` as a Node boolean, and the oracle's sweep fails |
| Merge gate not met; macOS `tty.rs` typeahead test failed once (medium) | CI | The full macOS and Ubuntu runs are repeated on the new head. If the typeahead test fails again, the job is rerun once, and a second failure goes to a separate task rather than being merged over | GitHub runs |
| Barrier test cannot see a child resumed early (low, optional) | A test claiming a mutation it cannot fail | The claim was already removed in r2. `a_suspended_server_runs_nothing_until_the_daemon_confirms` catches that mutation. No change | n/a |
| Standing-record legs, M2R-89 (low and medium) | Coverage naming a grant kind it does not exercise | Unchanged: `envcloak standing` is still the `not_in_this_build` stub on main, and M2-15 depends on M2-27. M2R-89 is open in the canonical registry, owned by M2-15 | n/a |
| Unresumed macOS runner after a daemon crash, M2R-87 (low) | A crash window that leaves a process no owner can end | Unchanged: registered for M2-25 under D-34; M2-25 is not on main | n/a |

The Node oracle joins the managed runtime oracles job:
`scripts/provision-managed-oracles.py` exports `ENVCLOAK_NODE_ORACLE`, the
Node 26.7.0 that job selects, and `scripts/check-managed-oracles.py`
requires it to run.

## Review round r5 repairs, 2026-10-09

Four findings from the r4 verifier and Codex review, all fixed. One
corrects an r4 claim: r4 kept Node's `--no-` prefix because "Node refuses
it on any option that is not boolean". The measurement says otherwise for
a boolean that is a mode: `node --no-print <file>` still turns on eval
mode and evaluates the file's name (Node 26.7.0, `[eval]:1`).

| Finding | Class | Instances swept and disposition | Regression and mutation |
| --- | --- | --- | --- |
| Node accepts any bare `--no-*` by prefix; `node --no-print <file>` evaluates `<file>`'s name instead of running it (high) | An option prefix accepted for a family without every option it matches being measured on that interpreter | Every prefix in `boolean_long`. Node: the prefix is gone; 37 negations are listed one by one, each taken from Node's option table, each turning off a feature and none naming a mode, each measured to run the first of two files. Bun 1.3.13: every `--no-` form tried, `--no-print`, `--no-eval` and `--no-preload` included, runs the first file (kept). zsh: every option's `--no-` and `--no-no` form run between two files; each runs the first, fails as an unknown option, or (`--no-exec`) runs nothing (kept). Deno 2.9.7: every long option `deno run --help` names is now swept by a pinned Deno oracle (kept). TruffleRuby took Ruby's long options unmeasured: it now has none. The shared `=value` table (`VALUE_LONG`) was swept too: Node refuses each name it does not know before running anything, Bun ignores unknown options and runs the first file, and an attached value never moves the entry; unchanged | `long_options_take_values_as_their_own_interpreter_does` (`node --no-print /abs/x.js`, `--no-eval`, `truffleruby --disable-gems`: declaration, update, `#!` line); `a_stored_value_taking_long_option_cannot_keep_its_entry` (a stored `--no-print` record, with a `--no-warnings` control); `node_long_options_take_values_as_node_does` (now passes a failed run only for Node's own option refusals, never an `[eval]` error, with `--no-print` as the positive control); new `deno_prefixed_options_take_values_only_with_equals`. Mutations: Node's `--no-` prefix restored (unit, daemon and oracle tests fail); TruffleRuby given Ruby's long options (unit test fails); deno's prefixes widened to every long option (`--cert` takes the next argument; the Deno oracle fails) |
| The runner scan treated an option's value as the package and stopped: `npx --package foo --call 'echo CONTROL'` and `npx --cache /c --node-options=... pkg` passed (medium) | An option's value taken for a positional argument | The Node package runners now scan to the end of their own options: for npx, to its package, modelled on npm 11.19.0's `npx-cli.js` (an option it does not know as a switch takes the next argument unless that starts with `-`); for npm, every argument up to `--`, since npm reads options on both sides of its words; pnpm, pnpx, yarn and bunx are scanned as npm is (not measured to stop sooner). Every argument in that range is checked, values included. The scan also refuses `--script-shell`, npx's `--shell`, `--userconfig` and `--globalconfig`, the command-line forms of the `npm_config_*` variables already refused. The runner label had the same fault (`npm --cache /c exec` was labelled `npm /c`): for a Node runner, a word after an option without `=` is no longer read as the subcommand | `code_selecting_declarations_are_refused` and the new `runner_options_after_an_option_value_are_still_the_runners` (declaration and update, with the package's own arguments as controls); stored runner records in `stored_effective_arguments_and_entries_obey_current_policy`; new oracle `npx_reads_its_options_after_an_option_value` on the pinned npm 11.19.0, where both injected forms print `CONTROL` and the control (`--call` after the package) runs the package. Mutation: the scan stopped at the first word that is not an option (the r4 rule); the unit, daemon and npx oracle tests fail |
| The suspended-runner cleanup test ignored `ps`'s exit status and dropped malformed rows (low) | A process observation whose failure reads as an empty table, so the test cannot fail | Every process-table reading in the files this task changes: `managed_runner.rs` (fixed), and `process_groups` (`managed_common`) and `process_parents` (`managed_launch.rs`), which were already strict and now share one parser. `/proc/<pid>/exe` in `envcloak-sys/tests/launch.rs` asserts its errno and its control, so it was already strict | `a_process_table_that_cannot_be_read_is_never_empty`: a failed `ps`, an empty listing and five malformed listings are errors, and the live table holds this process. Mutation: the previous reading (status ignored, bad rows dropped); the test fails |
| Deno's prefixes and TruffleRuby's mapping onto Ruby were unmeasured (low) | As the first row | Deno 2.9.7's release binary joins the managed runtime oracles job (pinned per platform by SHA-256, verified before extraction); TruffleRuby's long options are dropped until measured. An unknown family still has none | `deno_prefixed_options_take_values_only_with_equals`; `test_changed_deno_archive_is_never_extracted` in `scripts/test-managed-oracles.py` |

The Deno and npx oracles join `scripts/check-managed-oracles.py`, which
requires all ten to run. Local receipts are `ec-checks-m2-27-r6.*` in the
lane's scratch directory; the e2e and daemon runs were detached from any
agent's process tree, with a cleared environment.
