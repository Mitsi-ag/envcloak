# M2-19 validation receipt

The original receipt below covers the six open findings from the second review and verifier,
on branch `m2/m2-19`. All six are fixed; none is rejected or deferred. The
task's existing PTY implementation and acceptance tests are retained.
Later review findings and fresh platform checks are recorded below. The newest
review log and validation supersede the earlier platform-verification status.

## Scope and requirements

`run --pty` uses one redacted merged stream, a 40 ms idle deadline, bounded
input that is wiped after each write, and current window dimensions. Typed
control characters go through the slave's line discipline. External signals
use the owned monitor/session routes. Suspension restores the outer terminal
before stopping, waits for foreground ownership before refreshing settings,
and resumes the command only after raw mode and size are restored.

The relay preserves reported command status, drains output, applies the
descendant cutoff, and retains `pty_monitor_lost` when a signal interrupts a
lost monitor's drain. CLI help, `pty_unavailable`, coverage limits, and the
PTY contract are in place. Pipe mode retains its separate redactors and has
the same strengthened prompt measurement.

| Requirement | Implementation and local evidence |
| --- | --- |
| R-M2-03, R-M2-07, R-M2-09 | Merged redactor, CR LF variants, real serializer matrix over a real PTY, `/dev/tty` writes, burst input, and kernel controls for inherited output translations. Cursor reconstruction remains explicitly outside coverage. |
| R-M2-08 | Existing pipe runner suite, including all five prompt samples timed before emission. |
| R-M2-10 | Existing short-value policy and warning tests, child-environment-only gate, and argv checks. |
| R-M2-11, T-12 | Typed interrupt, per-signal direct/nested receipt counts, resize, stop/resume ordering, remapped/disabled suspend characters, raw/nested commands, and foreground-only refresh. |
| R-M2-12 | EOF, descendant cutoff, slow output reader, late signals, and monitor death before/after the command's exit report. |
| R-M2-13 | Stable failure tokens and exit codes; unavailable PTY refuses before a daemon request; lost monitor remains an error at both result-selection sites. |
| R-M2-14 | End-to-end gate 23: typing `y` into the requester's PTY grants nothing. |
| R-M2-79 | Existing hardening and PTY spawn tests; Linux-specific tracer/non-dumpable execution remains a CI check. |
| R-M2-89 | Gates 8 (PTY), 9, 13, 14, and 23 are implemented and exercised locally; CI retains both operating systems. Fresh Linux execution of this revision remains with the driver. |

## Bug classes and swept instances

The sweep searched every file changed by M2-19, from the parent of `4521a37`
through this revision, including product code, fixtures, CLI, and documentation.

| Class | Instances and fix | Regression evidence |
| --- | --- | --- |
| Capturing another foreground job's terminal state | Both `PtyAct::Continued` and `job_control::command_stopped` reach `TerminalGuard::refresh`. The guard waits until its own group owns the foreground before reading saved settings. Refresh updates both ordinary restore and panic-hook state. | Native background-continue fixture covers external SIGSTOP and relay SIGTSTP, a shell-like line editor, foreground transfer, round trip, and final settings. The sys abort fixture now uses an owned terminal foreground group and still checks refreshed settings and raw-settings refusal. |
| Retaining consumed sensitive input after partial writes | The only pending-input cursor, `Relay::write_keys`, now wipes each successful range before a possible `WouldBlock`. Read, discard, end, and drop paths were also swept. | Partial write followed by backpressure asserts immediate zeroing, preservation of the unsent suffix, exact later delivery, and final zeroing. Input includes non-UTF-8, NUL, ESC, and an incomplete multibyte sequence. |
| Timing gates that omit latency or accept only the best sample | Both pipe and PTY prompt fixtures use an acknowledgement before emission; the clock starts before sending it. Every one of five samples must be within 100 ms. PTY read, idle, and end deadline paths were swept. | An injected clock checks the 40 ms boundary, one-shot flush, and reset after another read, independently of scheduler timing. |
| Treating one nondeterministic host outcome as another run's oracle | Four sites: end-to-end `cat_after_fg` comparison, sys `monitor_cycle`, sys `outer_shell_cycle`, and sys shell/monitor comparison. BSD cat independently accepts read-on or EINTR; GNU and retrying cats still require a resumed round trip. RUN.md's matching-baseline claims were corrected. | Real outer-shell gate, all topology gates, delayed-reader coverage, and mutation failures at restoration/continuation assertions rather than a BSD scheduling mismatch. |
| Output rewritten before redaction by inherited terminal flags | The relay's PTY creation now retains only `OPOST` and `ONLCR` in the slave's output flags. Saved outer settings and all other settings remain intact. Later refresh copies changed control characters only. | Termios mask unit plus native kernel controls for macOS OXTABS, ONOEOT, OCRNL, ONOCR, and ONLRET. Linux TAB3/OLCUC/CR/column cases are in the same test for CI. |
| Late events replacing an established failure with an ordinary exit | Both result paths, in-loop `signal_end` and final-boundary `late_result`, preserve monitor loss while allowing the signal to end the drain. CLI token mapping and pipe-mode result handling were swept. | Each path tests INT, QUIT, TERM, and HUP with a reported-exit positive control; final-boundary coverage also preserves another error. Native monitor-death gates remain green. |

The foreground fixture also marks its child reaped before asserting on its
status, so failing cleanup cannot signal a reaped process.

## Mutation receipts

All mutations below were restored. A nonzero command status alone was not
accepted as evidence: the named assertion had to fail.

| Commit | Mutation observed failing |
| --- | --- |
| `9a60b70` | Remove the foreground wait from refresh: both STOP and TSTP routes save line-editor settings and fail final restoration. |
| `5b956c9` | Advance the input cursor without wiping; replace monitor loss with a signal during the drain; replace monitor loss with a late signal at the result boundary. Each focused regression fails. |
| `8616fc9` | Retain inherited output flags: native kernel gate and mask unit fail. Keep only the first prompt fast and delay the other four: both pipe and PTY gates fail. Flush strictly after the deadline: the exact 40 ms gate fails. |
| `587bca4` | Omit the panic-hook registration update: abort restores old echo/suspend settings. The foreground-wait mutation also fails both native continuation routes. |
| `9f22870` | Stop the CLI before restoration: dash cannot process `jobs`. Omit Resume's SIGCONT: monitor/comparison gates see no Continued and the outer-shell gate cannot round-trip the next line. The panic-registration mutation remains covered. |

Two interrupted sys mutation attempts initially returned Cargo status 101
because their processes received external termination signals. Those attempts
are not counted. Their reruns reached the intended assertions and failed:
`an_outer_job_control_shell_regains_its_terminal_and_fg_resumes` and
`a_stopped_cat_has_a_valid_read_outcome_under_the_monitor_and_shell`.

Existing scope-wide mutation receipts remain in commits `81ae503`, `86773ed`,
`d55306a`, and `b21dab0`: old orphaned-session topology, suspend-byte-to-SIGSTOP,
stop before restore, Resume before raw mode, restore before stopping the
command, raw passthrough, missing CR LF variants, duplicate typed interrupt,
direct-group-only forwarded signals, Linux TIOCSIG misuse, output after the
cutoff, absent idle flush, ignored resize, absent panic restore, monitor loss
reported as success, and silent pipe fallback. Those historical receipts are
not represented as new mutation executions in this review-fix run.

## Independent checks and local validation

Host: macOS 26.4.1 (25E253), arm64, Rust 1.98.1. Native controls use private
terminals and generated values. The kernel output controls extend the
cycle356 CRLF oracle approach; the explicit idle clock and partial-write
checks use cycle410's delivery/trace distinctions. Cycle416's fixture I/O
and reap-receipt guidance informed the fixture ownership check. None of those
research records is treated as runtime evidence for this revision.

The serializer gate used Python, Node, and Go, alongside labelled fixtures;
PHP was not exercised locally. The final exec suite passed 31 PTY relay cases,
5 PTY spawn cases, 30 pipe runner cases, 32 unit tests, and the allocator test.
All five PTY prompt samples were 40.66 to 42.24 ms; all five pipe samples were
40.75 to 44.92 ms. Both started timing before the acknowledgement was sent.

All Cargo builds used target directory
`/Volumes/KeenShiftDev/tmp/envcloak-target/C`, incremental compilation off,
and three build jobs. Tests used `--no-fail-fast -- --test-threads 3`, a
detached double-fork/setsid runner with a minimal environment, and isolated
short `/tmp` HOME/XDG directories. No workspace-wide test command was used.

Passed checks:

- `cargo fmt --all --check`.
- `RUSTFLAGS="-D warnings" cargo clippy --offline --workspace --all-targets`.
- `scripts/check-unsafe.sh`, `scripts/check-expose-lint.sh`, and
  `scripts/check-unsafe-lint.sh`.
- `scripts/check-reservations.py`, `scripts/check-spec-decisions.py`,
  `scripts/check-crate-graph.py`, and `scripts/check-sources.sh`.
- Full restored `envcloak-sys` crate suite, including PTY topology and refresh
  fixtures; its two existing documentation examples remain ignored.
- Full `envcloak` (CLI), `envcloak-e2e`, and `envcloak-testkit` crate suites:
  550 tests passed, including both `pty_job_control` cases and all 91 reservation
  checker cases.
- Full final `envcloak-exec` crate suite: 99 tests passed, including every native
  PTY case and the pipe-mode regression suite.

All final check commands exited 0. Local logs and mutation runners remain in
the ignored `.collab/m2-19/` directory, including `final-results.json`,
`final-crate-tests.log`, `final-exec-tests.log`, and `sys-restored.log`.

## Remaining platform verification

No implementation or review finding is deferred. Fresh Linux execution and
the driver's PR/CI work remain outside this local macOS run, as assigned by
plan section 6 and the user's no-push instruction. In particular, Linux-only
output flags, cutoff behavior, and signal routing need that run. The existing
D-35 narrowing of SIGTERM/SIGHUP on kernels before 6.9 remains documented and
tested conditionally; it is an intentional platform contract, not a newly
waived gate. Cross-platform acceptance of R-M2-89 remains conditional on CI.

## Subsequent review: post-loss output, discard wiping, and CLI receipts

The verifier reported the full macOS and Ubuntu CI run at `bfb0cab` green,
including the native relay and real-shell tests. Its three remaining findings
are all addressed, including the optional real-CLI receipt check. None was
rejected. The existing scope and requirement mapping above is retained:
gates 8 (PTY), 9, 13, 14 and 23; R-M2-03, R-M2-07 through R-M2-14,
R-M2-79, R-M2-89 and T-12. CR-4 now also has real-CLI signal receipts.

The class sweep searched all 33 files changed by the task from review base
`8a4df098`, including the new e2e manifest change, product code, tests,
fixtures, CLI and documentation. Search receipts remain in the ignored
`.collab/m2-19/review3/*-sweep.txt` files.

| Bug class | Instances swept and coverage |
| --- | --- |
| A post-transition redaction assertion satisfied only by earlier output | Swept `read_master`, idle flush, `master_ended`, `cut`, final flush, monitor loss before and after an exit report, descendant drains and pipe-mode drains. Existing exit/EOF/cutoff gates retain their values and redaction assertions. The new Linux loss gate pauses only after `lost` is set, then lets a HUP-ignoring writer emit three numbered values with hostile bytes. Its write receipt precedes draining, and the test requires all three redacted lines, exit 125, one `pty_monitor_lost`, restored terminal settings and the clean-canary sweep. macOS revokes the slave on hangup, so its existing native hangup gate remains the applicable check. |
| Sensitive input or stale cursors retained when pending input is discarded | Swept every `drop_keys` caller: exit report, monitor loss, absent master, completed or failed write, and `end_input`; also the read and partial-write paths and final `Zeroizing` cleanup. All discard callers use the same tested helper. Unsent, partially sent, empty, exhausted and short buffers are checked before RAII cleanup, then the allocation is reused and checked again. NUL, ESC, invalid UTF-8 and incomplete multibyte bytes are included. Both cursors must reset. Other prepared exec strings and CLI receive buffers retain their existing wiping paths and tests. |
| Acceptance receipts that substitute a library runner for the product entrypoint | Swept the direct/nested four-signal relay cases, Linux forced narrowing, sys forwarding routes, CLI `RunSpec::pty` construction and real-shell e2e paths. An owning parent now sends all four external signals to the actual `envcloak run --pty`, both directly and under a nested shell. Exact job and shell counters are required; the kernel support probe selects D-35's documented Linux narrowing. Existing lower-level receipts still cover forced narrowing. |

| Commit | Mutation and observed result |
| --- | --- |
| `09040c02` | `E-passthrough-after-loss`: pass raw bytes through once `lost` is set. The new native Linux numbered-line gate fails. `H-omit-discard-wipe`: remove the wipe; the discard test fails on retained bytes. `H-omit-discard-cursors`: retain both cursors; the same test fails on stale state. Restored gates pass. |
| `a399c8c0` | `direct-group-only`: replace foreground-job forwarding with a signal to the monitor's direct command group, then rebuild the real CLI. Direct receipts pass; the nested SIGINT receipt fails because the job got none. Rebuilding the restored CLI makes both receipt cases pass. |

These failures reached their intended assertions, with Cargo exit 101, rather
than failing to compile or start. The runners restored every mutation in a
`finally` path and rebuilt the CLI before restored checks. Cycle410's
delivery/trace oracle informed the causal post-loss barrier and numbered
receipts; cycle416's bounded I/O and owned-child guidance informed the
fixtures. Those research records are independent design checks, not claimed
as runtime results for this revision.

Fresh local checks passed on macOS 26.4.1 arm64, Rust 1.98.1:

- `cargo fmt --all --check` and
  `RUSTFLAGS="-D warnings" cargo clippy --offline --workspace --all-targets`.
- Full detached `envcloak-exec` suite: 100 tests, including 33 unit tests,
  31 native PTY relay cases, 5 PTY spawn cases, 30 pipe cases and the
  allocator test.
- Full detached `envcloak-e2e` suite: 130 tests, including both real-shell
  PTY cases. Direct and nested CLI signal receipts both give job
  `[1, 1, 1, 1]` and shell `[0, 0, 0, 0]`.
- `check-unsafe.sh`, `check-expose-lint.sh` (6/6 canary reports),
  `check-unsafe-lint.sh` (9/9), `check-reservations.py`,
  `check-spec-decisions.py`, `check-crate-graph.py` and `check-sources.sh`.

Linux checks ran offline in a local container on kernel
`6.12.72-linuxkit`, Rust 1.99.0 and Python 3.12.3. The image was built from
the cached `ec-m2-17-build` and `rust:1-slim` images; its id is
`sha256:6f988e26cb5eeccd75a61236f858dbedbf3d2c7ea4fd455fb479bc542c4e5c52`.
The new post-loss gate passes, fails under raw passthrough, and passes again
after restoration. Both real-CLI PTY tests also pass there, with direct and
nested job `[1, 1, 1, 1]` and shell `[0, 0, 0, 0]` receipts.
An additional host-control run enables the existing group-signal refusal
seam by default and makes the test's support probe report that refusal.
The real CLI then gives nested job `[1, 1, 0, 0]` and shell
`[0, 0, 1, 1]`, while direct delivery remains `[1, 1, 1, 1]`.
This exercises the new assertion's older-kernel branch on the current
kernel without adding any permanent test flag to the CLI. The temporary
control was restored, the binaries rebuilt and both CLI tests passed again
with all four signals reaching the nested job.

The detached macOS runner and Linux container use isolated short `/tmp`
HOME/XDG directories and cleared environments. Every Cargo build uses three
jobs and incremental compilation off. The host target is
`/Volumes/KeenShiftDev/tmp/envcloak-target/C`; Linux artifacts are isolated
under its `linux19` subdirectory, mounted at that same target path inside
the container. Tests use `--no-fail-fast -- --test-threads 3`. No workspace
test command was run. Logs and results are under `.collab/m2-19/review3/`:
`exec-mutations.json`, `cli-mutation.json`, `positive.json`, `final.json`
and `linux-narrowing.json`, with their per-check logs.

No scope or review fix is deferred. The D-35 narrowing on Linux before 6.9
remains the intentional platform contract. Fresh GitHub CI for these commits
belongs to the driver under plan section 6 and the no-push instruction;
the verifier's green `bfb0cab` CI is prior evidence, not a run of these commits.

## Final review log

- **Plan deviation, M2-19 interface:** `RunSpec::pty(argv, injected, redactor, OuterTerminal)` replaces the planned `winsize` argument; the owned outer terminal supplies current dimensions at startup, SIGWINCH and resume instead of retaining a size snapshot.
- **M2-28 follow-up, shared temporary-directory observations:** `probe_local.rs::probe_homes` scans machine-wide `/tmp/ecp*` state. Give each test a private root and count only its descendants. Sweep all three callers: `the_probe_runs_beside_the_persons_daemon_and_touches_nothing_of_theirs`, `a_version_outside_the_table_is_not_qualified`, and `the_probe_home_is_cleaned_after_kill_9`. Add a concurrent unrelated-root control that cannot affect the count, and retain a positive control proving that a probe created under the owned root is found. This is tracked here, with no M2-28 code change, as the verifier requested; the plan's task ownership and section 6 disjoint-lane rule keep that implementation with M2-28.
- **Main integration:** merge `36f2c89f` incorporates main through `689c55aa`. Remote main is now `4f3059ba` (M2-14), confirmed again with `git ls-remote origin refs/heads/main` on 2026-10-07 at 03:15 UTC. The verifier reports green PR run `37552905954` tested merge ref `75587455`, whose parents are `8539acb0` and `4f3059ba`; manual full run `37552910397` also passed on both systems, including release. Those runs cover the newer integration baseline for the prior head. No redundant main merge is needed; fresh CI on this correction remains the driver's pre-merge check under section 6 and the no-push instruction.

The stop-order finding was a temporal-oracle gap: the stopped state at the
outer shell's prompt did not prove that the command was stopped when the
terminal was restored. The outside-SIGTSTP case now pauses inside
`TerminalGuard::restore`, immediately after the successful `tcsetattr`,
and reads the command's kernel state there. It first observes the ticker
running, then requires stopped state and the restored terminal settings at
the barrier, releases the CLI, and retains the prompt, `jobs`, `stty -g`,
`fg`, resumed ticker and final-exit checks. The pid is read only; the owning
parent still supplies every signal.

The sweep searched all 33 task files against the merged main baseline. Its
stop-order checks cover both relay restore call sites, outside-SIGTSTP
dispatch, the monitor's stop report, `command_stopped`, raw-mode reentry,
resume, monitor-loss restoration and final/panic restoration. A barrier in
the terminal primitive observes an early direct guard restore as well as
one through `Suspension::restore_terminal`. Final and panic restoration
have different requirements and retain their existing gates.

The documentation sweep corrects claims that turn a scheduling-dependent
observation into a promise: RUN.md's suspension paragraph and the e2e
`cat_after_fg` comment now explicitly allow either ordinary BSD-cat
outcome; its nearby comment says "read on", not "retry", because BSD cat
does not retry EINTR. The sys topology cases and foundation paragraph
already accept both outcomes independently. The strict Python retrying
fixture still requires a fresh round trip. RUN.md's pipe prompt table also
had stale "fastest of five" wording; it now describes the existing gate's
pre-emission acknowledgement and all-five-samples requirement. Cycle512's
independent outcome-policy review supports that distinction; the runtime
checks remain the native tests, not that source-only review.

The other swept classes are unrecorded interface deviations (the sole PTY
constructor and all its call sites, with startup/resize/resume measurements),
shared host state in tests (no machine-wide temporary-directory count in
M2-19's files; the three M2-28 callers are tracked above), and stale
integration evidence (the branch now contains the fetched main baseline).
Search receipts are in `.collab/m2-19/review4/*-sweep.txt`.

The actual-restore gate and wording corrections are committed in `d9ea98cc`.
Mutation `restore-before-stop` inserts a direct guard restore into the relay's
SIGTSTP dispatch, before asking the monitor to stop: the real-CLI gate fails
at the restore point with kernel state `S+`, even though the later normal
stop would still satisfy the old prompt-time assertion. Mutation
`barrier-before-tcsetattr` moves the witness before the settings change and
fails the independent settings comparison. Both tests reached the named
assertion with Cargo exit 101. Both sources were restored, the CLI rebuilt,
and the gate passed with state `T` and restored settings on macOS. The
unchanged native sys topology and retrying-cat cases supply the documented
ordinary-cat and mandatory-round-trip evidence.

The Linux real-CLI gate also passes on the merged tree, observing stopped
state `Tl` and restored settings at the barrier. Both PTY e2e cases pass
there, with direct and nested signal receipts unchanged. The ancestry
check `git merge-base --is-ancestor 689c55aa HEAD` passes; the same check
against the pre-merge `0f8d7d89` control fails, showing it detects the
reviewed integration gap.

Commit `f5e9afde` also bounds the restore observation to 30 seconds from the
stop request, before the barrier's 60-second automatic release. An expired
barrier cannot let a later stop turn an early restore into a passing
observation. Control `expired-restore-witness` makes that deadline already
expired and fails the intended assertion with Cargo exit 101. Restoring the
deadline passes the full detached e2e suite and strict Clippy.

Final local validation on the merged tree:

- `cargo fmt --all --check` and
  `RUSTFLAGS="-D warnings" cargo clippy --offline --workspace --all-targets`.
- Full detached `envcloak-sys` suite, including 14 PTY, 5 signal and 9
  topology cases; its two existing documentation examples remain ignored.
- Full detached `envcloak-exec` suite: 100 tests.
- Full detached `envcloak-e2e` suite: 133 tests, rerun after the expiry guard.
- Linux real-CLI PTY tests: both pass again with the expiry guard, observing
  stopped state `Tl` at the restore barrier.
- `scripts/check-unsafe.sh`, `scripts/check-expose-lint.sh`,
  `scripts/check-unsafe-lint.sh`, `scripts/check-reservations.py`,
  `scripts/check-spec-decisions.py`, `scripts/check-crate-graph.py` and
  `scripts/check-sources.sh`.

The host and offline Linux container are the same as the preceding review
round. Builds retain target directory C, incremental compilation off and
three jobs; all test commands use `--no-fail-fast -- --test-threads 3`,
detached and with private short HOME/XDG directories. No workspace test
command was run. Logs, mutation receipts and final statuses are in
`.collab/m2-19/review4/`, especially `mutations.json`, `main-ancestry.json`,
`final.json`, `linux-focused.json` and `expiry.json`.

M2-19's scope, requirement ids and gates listed above remain covered. The
only follow-up implementation belongs to M2-28, explicitly tracked above;
fresh merged-head GitHub CI remains with the driver. No finding is rejected.

## Release-binary restore gate correction

Manual run `37547853061` on `1c48bad8` exposed a test capability mismatch:
the real-CLI gate unconditionally awaited `termios.restored`, although
production release binaries deliberately contain no testing hooks. The
earlier local PTY receipts used testing binaries and did not cover this
release-binary invocation.

The gate now uses the harness's existing binary mode, `Harness::test_build`.
With the target's testing binaries, the actual-restore barrier is mandatory:
its absence fails within the 30-second observation window with the captured
terminal in the diagnostic. It still requires stopped kernel state and
restored settings before releasing the barrier. With external release
artifacts selected by `ENVCLOAK_E2E_BIN_DIR`, the test prints why that
internal observation is unavailable. Both modes still require the outer
prompt, stopped command, `jobs` status, restored `stty -g`, `fg`, resumed
ticks, input and successful exit. All the other job-control, redaction and
direct/nested signal receipt assertions still run. No timeout or missing
marker can select release mode.

The class sweep covered all 33 task files against the current merge base,
including every changed test and CI's external-binary invocations. The
instances are the e2e restore barrier (fixed), the same gate's injected
panic (already conditional on `test_build`), exec's PTY pause/failure/panic
hooks and pipe-runner pause (their runner is `current_exe`, always the
testing executable), and sys's terminal/topology helpers (also their own
testing executable). CLI snapshot/stub tests, the allocation probe,
emitter and reservation tests have no external-release seam dependency.
There is no second affected test. The production hook definitions retain
their feature guards; release artifacts acquire no testing capability.
The sweep receipt is `.collab/m2-19/review5/seam-sweep.txt`.

All three mutations failed the intended assertion with Cargo exit 101,
and all sources were restored:

- `missing-testing-restore-barrier`: remove the `termios.restored` pause
  from the testing binary. The real-CLI gate fails with "testing binary
  missed the actual outer-terminal restore barrier".
- `restore-before-stop`: restore the guard in SIGTSTP dispatch before
  asking the monitor to stop the command. The gate fails at the actual
  restore with the command still in kernel state `S+`.
- `require-restore-hook-in-release`: force the testing-only branches on
  when using external release binaries. This reproduces the missing
  barrier failure, so the release run guards the reported regression too.

The restored macOS testing build passes both PTY cases, with stopped state
`T` and restored settings observed at the barrier. A fresh
`cargo build --release --offline --locked` using the workspace's default
members, without testing features, also passes both PTY cases with
`ENVCLOAK_E2E_BIN_DIR=/Volumes/KeenShiftDev/tmp/envcloak-target/C/release`.
`release_artifacts_carry_no_test_hook` passes on those same release
artifacts. Direct and nested signal receipts in both modes remain job
`[1,1,1,1]`, shell `[0,0,0,0]`. The release gate completes in 18 seconds;
its explicit no-barrier message accompanies the user-visible assertions.
The mutation and release receipts are `review5/mutations.json` and
`review5/release.json` under `.collab/m2-19/`.

Final checks pass: all 133 `envcloak-e2e` tests, `cargo fmt --all --check`,
strict workspace/all-target Clippy, unsafe, expose-lint, unsafe-lint,
reservations, spec-decisions, crate-graph and sources. The final receipt
is `.collab/m2-19/review5/final.json`. All builds retained target C,
incremental compilation off and three jobs. Tests ran detached with
private short HOME/XDG directories and `--no-fail-fast -- --test-threads 3`.
The scope and requirement ids above remain covered; this correction
defers no implementation. Both-platform CI on this commit remains the
driver's check under the no-push instruction.

## Startup status and final contract review

Commit `83e0e50c` fixes the startup completion contract. A command can
execute before its monitor reports `Started`; loss of that report cannot
prove that nothing ran. `SessionError::Unconfirmed` distinguishes an EOF,
unreadable frame or unexpected first report from explicit `SetupFailed`
and `ExecFailed` reports. Exec maps it to `Followed`, whose CLI completion
record is `unknown`, exit 125 and `run_failed`. An ambiguous report drops
the owned monitor through its kill-and-reap path instead of assuming it
has already exited. Prelaunch refusals retain their existing codes and
`not_started` records.

The native real-CLI regression witnesses a file the command creates,
while a testing-only seam withholds `Started`. Only after that independent
side effect and the CLI's pause are observed does it release the CLI to
kill its own unreaped monitor. It requires the exact `unknown` wire
record, exit 125 and restored terminal settings. Successful execution,
missing-command and non-executable controls check the other records.
The release gate explicitly omits the injected loss, whose seam does not
ship, but retains those controls. The sys test drives the actual channel
reader with bytes written without the encoder: all partial-frame EOFs,
bad padding, invalid pid, non-text garbage, unexpected stop/continue/exit
reports and read errors remain uncertain. Only explicit refusal frames
mean no launch. The wire vectors are protocol fixtures; the native side
effect is the independent lifecycle evidence, following cycle287 and
cycle289's distinction between constructed errors and observed execution.

The second contract correction limits descriptor pass-through to pipe
mode without `--status-fd`. PTY mode always replaces 0..2 with the slave
and closes inherited descriptors above them. The CLI comment and RUN.md
now agree with the existing foundation contract. A real command uses
`fstat` identity to test inherited fixture files on descriptors 3 and 8,
and `isatty` to independently establish pipe versus PTY mode. All four
mode/status-option combinations are checked; only pipe mode without the
status option inherits those files. These controls run on release builds
as well as testing builds.

The class sweep covers all 35 changed task files, with the foundation's
`pty_spawn` callers also inspected:

| Bug class | Instances swept and regression evidence |
| --- | --- |
| Treating missing lifecycle evidence as proof of no execution | Both startup error arms (unexpected report and channel error), the sys-to-exec conversion, `start_pty`, relay setup before and after launch, `ExecError::may_have_started`, CLI `Ended::exec`/status encoding, and the MCP diagnostic assertion. Explicit monitor refusals still occur before exec. Raw channel cases and the real-CLI side-effect gate protect the ambiguous paths; existing spawn and status controls protect known refusals. |
| Applying a mode-specific descriptor promise to every mode | RUN.md's status paragraph and the CLI module comment were wrong; both are corrected. Monitor descriptor 3, closure above it, command-side control/exec-pipe closure, the foundation paragraph and existing topology/above-limit gates were checked. The four real-CLI descriptor cases cover the corrected promise. |
| Assigning a temporal property to a test that observes only a later result | The e2e doc comment, RUN.md gate rows, validation receipt, unit order model and relay resume barrier were swept. Resume-before-raw is detected by `a_stop_restores_before_the_cli_stops_and_resumes_only_once_raw_again` and `the_command_is_resumed_only_once_the_outer_terminal_is_raw_again`; the real-CLI post-fg round trip alone is not a deterministic ordering oracle. This records the verifier's offered clarification instead of adding a redundant e2e seam. |
| Stale integration evidence | The Main integration row now distinguishes the branch's `689c55aa` merge from PR CI's tested merge with main `4f3059ba`. A fresh remote-ref query confirms `4f3059ba`; the green CI claims are the verifier's supplied receipts, not new runs by this engineer. |

New seam dependencies were included in the sweep: startup loss is testing
only and explicit, like the restore witness and injected panic. All
ordinary status and descriptor controls run in both binary modes. The
existing native exec/sys seams still use their own testing executables.
The sweep files and main-ref receipt are under `.collab/m2-19/review6/`.

Mutation receipts, each Cargo exit 101 at the intended assertion:

- `startup-channel-loss-is-not-started`: the original classification
  writes `not_started/run_failed` after the side effect was observed.
- `unexpected-startup-report-as-setup`: an unexpected first report is
  wrongly a setup refusal; the sys wire gate fails.
- `startup-channel-error-as-setup`: a channel error is wrongly a setup
  refusal; the sys gate fails at the empty EOF case.
- `unconfirmed-startup-as-setup`: the exec conversion loses uncertainty;
  the real-CLI completion-record assertion fails.
- `retain-inherited-fd-8`: the monitor preserves an inherited non-cloexec
  descriptor 8; the PTY/no-status case sees it and fails, while the pipe
  inheritance control passes.
- `resume-before-raw`: move the Resume barrier and send ahead of raw-mode
  reentry; both the unit order model and native relay barrier fail, the
  latter with "the outer terminal is not raw before Resume".
- `certain-start-diagnostic` (commit `b9585353`): restore the old "the
  command was started" diagnostic. The MCP gate rejects that wording at
  its stderr assertion.

Every mutation was restored. All focused controls pass again. The first
baseline attempt used `/bin/true`, absent on macOS, and failed its ordinary
control; it is not mutation evidence. The corrected `/usr/bin/true`
control passed before the original startup-status bug failed as intended.
The first full CLI suite also exposed a stale MCP diagnostic assertion.
It now expects "may have started"; its existing observed-side-effect and
`execution_unknown` checks are unchanged. A repository-wide diagnostic
search found this one stale assertion. The diagnostic mutation above
checks the corrected expectation independently of the status assertions.

Fresh macOS checks for this correction:

- Full `envcloak-sys`, `envcloak-exec` and `envcloak-e2e` suites passed.
  Sys ran 224 cases (two existing documentation examples ignored); exec
  ran 33 unit tests, the allocator gate, 31 PTY relay cases, five PTY
  spawn cases and 30 pipe runner cases. E2e reported 133 passed, including
  both real-CLI PTY cases and the fixture story.
- A fresh `cargo build --release` passed. Both `pty_job_control` cases
  passed with `ENVCLOAK_E2E_BIN_DIR` pointing to target C's release
  directory; `release_artifacts_carry_no_test_hook` also passed. The release
  receipt explicitly excludes injected startup loss and the restore
  barrier, while retaining ordinary status, all four descriptor cases,
  job control and signal receipt checks. Direct and nested jobs received
  each signal once; their shells received none.
- `check-unsafe.sh`, `check-expose-lint.sh`, `check-unsafe-lint.sh`,
  `check-reservations.py`, `check-spec-decisions.py`,
  `check-crate-graph.py` and `check-sources.sh` passed.
- The corrected full CLI suite passed all 222 cases, including all 27
  MCP cases. Final `cargo fmt --all --check` and
  `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets` passed
  again after the diagnostic mutation was restored.

The focused Linux run also passed in the cached, offline container:
startup wire classification, both real-CLI PTY cases, and the native
relay's raw-before-Resume barrier. The startup receipt observed the
command's side effect, then `unknown` and terminal restoration. All four
descriptor combinations passed. At the restore barrier the command was
already stopped (`Tl`); direct and nested signal receipts were job
`[1, 1, 1, 1]`, shell `[0, 0, 0, 0]`. This was a scoped Linux run, not a
full Linux suite or a fresh Linux release build.

All test runs were detached with a minimal environment, private short
HOME/XDG paths, three build jobs, incremental compilation disabled, and
`--no-fail-fast -- --test-threads 3`. Native artifacts use target C; the
Linux container maps target C's `linux19` subdirectory to its target C.
Final logs and status files are under `.collab/m2-19/review6/`: `final.json`
retains the initial CLI failure, `post.json` records its corrected full
suite and final fmt/Clippy results, and `linux.json` records Linux's four
successful steps. Expected mutation failures remain in `mutations.json`
and `post.json`; none is counted as a passing control.

The latest four findings are resolved, with none rejected. The optional
real-CLI resume barrier is handled by the verifier's offered documentation
clarification; the lower-level ordering gates were mutation-checked again.
Gates 8 (PTY), 9, 13, 14 and 23 and requirements R-M2-03, R-M2-07 through
R-M2-14, R-M2-79, R-M2-89 and T-12 retain the evidence mapped above. No
M2-19 implementation is deferred. The previously recorded M2-28 private
probe-root follow-up remains with its owner under section 6's disjoint-lane
rule. Fresh CI on these corrections remains the driver's pre-merge check;
this work was neither pushed nor submitted to GitHub.
