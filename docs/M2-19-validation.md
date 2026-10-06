# M2-19 validation receipt

The original receipt below covers the six open findings from the second review and verifier,
on branch `m2/m2-19`. All six are fixed; none is rejected or deferred. The
task's existing PTY implementation and acceptance tests are retained.
The subsequent review's three findings and fresh platform checks are recorded
in the final section, which supersedes the original platform-verification status.

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
