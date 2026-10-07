# M2-21: terminal reveal

Scope: SPEC §6.7, §4.4, §10b and gates 34, 23, 33 and 19. Implemented
`items.reveal` on Linux, strict typed IPC, the terminal CLI, proof-origin
preflight and final checks, the shared proof limiter, secret-only targets,
and a durable `reveal` audit entry before release. macOS requests no value
and exits 125 with `app_required` until M3 (D-20).

| Requirement | Evidence |
|---|---|
| R-M2-04, R-M2-25, R-M2-26, R-M2-81 | CLI `gate34_reveal_only_on_tty_after_proof_and_until_enter`, the independent Python PTY observer, `gate34_reveal_story`, terminal-free refusal, the warning and Enter checks |
| R-M2-27 | `gate34_mcp_neither_lists_nor_dispatches_reveal`: actual stdio initialization, list with a known tool control, and a refused direct reveal call |
| R-M2-28 | Builtin, asserted and extension refusal tests; T9-3/F-70 sibling-terminal tests; a pipe barrier creates a pending agent request after the prompt and the final request refuses it; direct terminal-less and claimed-agent RPC tests |
| R-M2-29 | The existing verified client connection, fresh proof and shared-limiter tests; framed response withheld on audit failure; durable audit decoded from the stopped daemon's vault; a rotation changes the next reveal |
| R-M2-30 | Class-specific refusals for cards, logins and issuer credentials with explicit valid fields, plus an ambiguous-secret refusal and explicit-field control; macOS CLI and raw RPC refusal |
| R-M2-79 | CLI tracer refusal with an untraced control; existing process hardening at binary startup; inherited terminal input guards and interruption restoration checks |

The new method uses the existing slug and field grammar, the existing
WireSecret decoder and frame cap, and no new parser. Hostile tests include
empty, oversized, non-UTF-8 CLI arguments, controls, Unicode, extra CLI
options, unknown wire fields, missing proofs, invalid targets and fields,
and value-free Debug for input-bearing reveal parameters. A failed terminal
write is an error. No unsafe code or production testing switch was added.

Independent checks: the PTY observer is Python code using the kernel's
`openpty`, termios and non-reaping `waitid`, separate from the Rust terminal
implementation. It captures stdout and stderr in different files, reports
unfiltered fixture counts, checks a known-exposure control, and types only
after observing prompts. The cycle338 whole-chain revalidation and cycle356
kernel PTY notes in the supplied oracle index informed the evidence and
terminal checks. The already adopted policy revalidation/argument oracles
are additional checks; historical host measurements are not claimed as new
runs. No agent host, credential file or real secret is needed for these gates.

Fixtures use short isolated HOME/XDG paths; macOS tests run in a
double-forked, environment-cleared process, and Linux tests run in a disposable
Linux arm64 container. Container runtime tests also run as uid 501 with no
SYS_PTRACE capability. Build output stays in the assigned C target directory,
with incremental compilation off and three build/test workers.

M3's macOS app reveal remains deferred by D-20. Scrollback intentionally
retains the value; the warning states this. The full real-agent M2 acceptance
story is composed by M2-26, and this task adds its own gate-34 story module.

## Mutation receipts

Every injected mutation below reached a failing runtime assertion (cargo exit 101),
then was restored. Compilation failures did not qualify. The original
stub also failed the first CLI gate before implementation. The observer's
no-contact assertions use command/reply snapshots that drain completed
socket connections before replying, with `status` as a positive control.
Both platform mutations were rerun after that observer change.

| Test or assertion | Named mutation observed failing |
|---|---|
| Original CLI reveal contract | `stub_reveal` |
| No terminal, no daemon contact | `tty_failure_falls_back_to_stderr` |
| macOS no daemon contact | `macos_contacts_daemon` |
| macOS no raw value RPC | `register_linux_reveal_on_macos` |
| CLI hostile argument output | `echo_hostile_reveal_arguments` |
| Gate 34 terminal-only output, Enter and warning | `write_reveal_to_stdout`, `omit_enter_wait`, `omit_scrollback_warning` |
| Gate 23 builtin, asserted and extension callers | `accept_agent_proof` |
| Gate 23 requester terminal, including the extension ancestor across sessions | `accept_requester_terminal` |
| Gate 23 requester appears after preflight | `trust_preflight_origin` |
| Direct terminal-less RPC with correct proof | `accept_terminal_less_proof` |
| Gate 33 CLI and daemon audit failure | `release_before_audit` |
| Persisted audit and current-value test | `release_without_persisted_record` |
| Fresh proof and the shared attempt limit | `skip_passphrase_verification`, `skip_shared_limiter` |
| Secret-only target classes | `allow_nonsecret_target` |
| Claimed agents and hostile target resolution | `ignore_requested_slug` |
| Strict wire schema and value-free Debug | `accept_unknown_reveal_fields`, `echo_reveal_debug` |
| Failed terminal write | `failed_terminal_write_succeeds` |
| Proof and acknowledgement interruption restoration | `forget_terminal_restore` |
| Gate 19 traced CLI | `omit_reveal_tracer_check` |
| Gate 34 MCP list and direct call | `list_reveal_over_mcp`, `dispatch_unlisted_reveal` |
| Gate 34 story | `story_value_on_stdout` |

The first class-refusal fixture let `allow_nonsecret_target` survive:
multifield ambiguity masked the missing class check. The test was strengthened
with explicit valid fields and class-specific refusal reasons, then the same
mutation failed. That initial pass is not counted as mutation qualification.

Commit `75ffd777` adds the initial tests; `239097c2` implements the typed
RPC and audited daemon flow. Their commit messages name the checked mutations.
Commit `4c142b03` adds the terminal implementation, independent observer and
story, and names their mutations. The validation commit records the final
restored-code checks.

## Local checks

Measured platforms: macOS 26.4.1 (25E253), arm64, Rust 1.98.1 and Python
3.14.6; Linux 6.12.72-linuxkit, aarch64, Rust 1.99.0 and Python 3.12.3.
Linux uses the preexisting `ec-m2-19-review3:local` image, image id prefix
`6f988e26cb5e`, network disabled, uid 501, without SYS_PTRACE capability.
The container permits the tracer test's ordinary same-user tracing through
its seccomp configuration. This is kernel/CLI evidence, not real-agent-host
or signed-release evidence.

- `cargo fmt --all --check`: passed.
- `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets`: passed
  on both macOS and Linux (Linux adds `--target aarch64-unknown-linux-gnu`).
- Linux: 710 passed, 0 failed, 0 ignored (including doctests), covering
  full core/client/IPC/daemon suites, all 10 reveal CLI tests, the reveal
  story, and both policy oracle targets. All tests used `--no-fail-fast`
  and `--test-threads 3`.

The earlier broad macOS run was interrupted by the driver's time limit.
Its GiB-scale doctor test had passed, but the incomplete suite is not counted
as a complete successful run. The resumed validation excludes that test and
other unrelated integration suites. The resumed commands use offline locked
builds, isolated homes and three test threads:

- Core and terminal-client library tests only.
- CLI and daemon binary unit tests plus their `reveal` integration targets.
- IPC library and integration targets, including `proto`, framing and client
  transport tests.
- macOS: 346 passed, 0 failed, 0 ignored.
- Linux: 364 distinct tests passed, 0 outstanding failures, 0 ignored.
  Two existing CLI import unit tests initially failed because the cached
  image lacked `git`. Git 2.43.0 was packaged into the assigned target
  directory; that five-test module then passed, including both failed tests.
  The remaining IPC targets passed. Runtime containers retained uid 501 and
  network isolation. No product change was needed for the environment fix.

The final macOS run also passed formatting, strict workspace/all-target
Clippy, `check-unsafe.sh`, `check-expose-lint.sh` (6 of 6 deliberate call sites
reported), `check-sources.sh`, `check-crate-graph.py` (50 edges, 21 crates),
`check-reservations.py` (262 rows, 17 tables), and `check-spec-decisions.py`
(54 decisions, 51 sentences). The normal/build dependency tree for
`envcloak-client` was recorded. No production or test source changed during
the resumed run.

This receipt follows the committed `M2-14-VALIDATION.md`,
`M2-19-validation.md` and `M2B-03A-VALIDATION.md` convention. The protocol
contract remains in `docs/IPC.md`.

`cargo-deny` is absent from both local toolchains, so the CI dependency-policy
check remains with the plan's §6 CI checks. The new direct dependency is the
already-pinned `secrecy 0.10.3`; no package version was added or changed.
The full workspace and real-agent acceptance jobs also remain with CI and
M2-26, as required by the task's local-test restriction. No claim is made for
production-signed artifacts or an opt-in privileged core-dump control.
