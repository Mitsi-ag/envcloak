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
| R-M2-28 | Builtin, asserted and extension refusal tests; T9-3/F-70 sibling-terminal tests; a wrong-proof request proves requester refusal precedes verification; a proof barrier changes a real ancestor into a builtin or extension agent before final revalidation; direct terminal-less and claimed-agent RPC tests |
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

The commits titled `M2 M2-21: add reveal boundary gates` and
`M2 M2-21: prove and audit terminal reveals` add the initial tests and
typed RPC with audited daemon flow. Their messages name the mutations.
`M2 M2-21: reveal only on the person's terminal` adds the terminal
implementation, independent observer and story with its named mutations. The validation commit records the final
restored-code checks.

## Original local checks

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

## CI follow-up after the M3-04 rebase

The driver commit titled `M2 M2-21: count reveal in the client methods after rebasing on M3-04` keeps `CLIENT_METHODS` at 41. The real `reveal`
audit kind 22 and `app_required` exit token remain landed. Reservation tests
now add synthetic `fixture_audit` (200) and `tst_required` rows to their
isolated document copies. The exit token keeps the original token's length
for the formatting cases. Numeric-literal cases use 200 in each radix and
201 for an unregistered entry. The production checker is unchanged.

Mutation `ignore_synthetic_reservation_entries` removed these entries from
both the rows and the code checked by a temporary copy of the checker. All
five selected gates failed because the checker incorrectly returned success:
`a_reserved_entry_the_code_already_has_fails`,
`a_landed_row_the_code_lacks_fails`,
`a_landed_row_with_another_number_than_the_code_fails`,
`a_line_whose_pieces_the_source_holds_is_read_whole`, and
`a_compiled_corpus_of_constructors_and_layouts_is_read_or_refused` (the
compiled `relative` case). No mutation remains in the tracked tree.

The doctor gate has a pre-existing fixture-dependent failure. Temporarily
replacing only its `fresh_seed()` with `51` reproduces exactly the extra
`unknown openai` line. That generated fixture ends in `-`; the scanner's
punctuation trimming emits another valid provider-shaped candidate that is
not the full value held in the vault. The human grammar allows only
`unknown github`, although its JSON assertions permit other unknown
providers. No timing or ordering change is needed to reproduce it.
The doctor test and command, scanner, provider registry, daemon scan matcher,
and canary generator are identical to the pre-M2-21 commit titled
`M2 M3-04: record final boundary validation`.
The seed change was restored; the unmodified doctor gate passed. Doctor is
left unchanged as requested for an unrelated existing flake.

Detached macOS checks after the fixture repair passed: `cargo fmt --all
--check`, `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets`,
`check-unsafe.sh`, `check-expose-lint.sh` (6 of 6 call sites), and
`check-reservations.py` on the real tree (262 rows, 17 tables). Builds used
target C, incremental disabled and three jobs; tests used `--no-fail-fast`
and `--test-threads 3`. No full workspace or GiB-scale scanner test was run.

The detached `check_reservations` target passed all 91 tests, including the
26 failures reported by CI (0 failed, 0 ignored). The unmodified doctor
gate passed its one selected test; the GiB test stayed filtered out.

## Reviewer follow-up: class sweep and new evidence

All 26 paths changed by M2-21 were searched for each class below, including
the shared item proof flow, typed IPC, audit code, metadata output, fixture
helpers and the story. The review findings are resolved; none is rejected.

| Bug class | Instances swept and resolution |
|---|---|
| Indistinguishable selection fixtures | Daemon class/ambiguity fixtures used the same bytes in both fields for secrets, cards and issuer credentials. All now use distinct generated values; both explicit secret selections are checked. Existing rotation and slug tests already distinguish their values. |
| Non-independent authorization-phase coverage | Swept CLI preflight, `target_view`, `prove`, `refuse_item_prover`, final `reveal` evidence, and the requester/agent tests. The after-prompt requester test supplies a wrong proof, so only a pre-verification refusal passes. A new native PTY test pauses after admission with the vault out, immediately before Argon2id, then execs the same ancestor process with a builtin or extension agent identity. Fresh evidence and the post-proof refusal are independently required; no value or acknowledgement prompt reaches the terminal. A fresh human terminal still succeeds. |
| Missing observable ordering | The CLI gate and the M2 story only checked warning presence. Both now assert PTY byte offsets in the order warning, proof prompt, value, acknowledgement prompt. The shared Python observer reports offsets without fixture bytes. |
| Terminal interpretation of hostile stored bytes | Swept `Terminal::write_secret`, its sole production caller in CLI reveal, the IPC value transfer, terminal input and metadata-output paths. The value writer checks the entire input before any write. Unit cases cover every C0/DEL/C1 scalar and byte, invalid UTF-8, partial-output refusal and printable Unicode. The PTY gate covers OSC 52, screen clearing, terminal queries and C0/C1 corpora, with an independent control detector and a printable Unicode control. Other raw writes carry framed IPC or user input, not stored bytes to a terminal. |
| Rebase-dependent validation references | Swept commit citations in the receipt and other changed docs. All five receipt citations now use unique ancestor commit subjects, including the driver and pre-M2-21 baseline. A reference check resolves each subject in branch history; injecting an obsolete reference fails it. |

The proof race uses the existing `envcloak-sys` test-only pause mechanism,
which is inert without its `testing` feature. It changes a real process's
argv identity through `execve`, preserving its PID, start identity, session
and child. A pipe acknowledgement after exec precedes proof release. No
sleep chooses the race window. Both builtin and extension cases run. The
whole-chain oracle (cycle338) informed this check; the observer uses actual
kernel PTY bytes and flags, as in the cycle356 measurement approach.

A new pending run cannot be created during Argon2id: `State::begin_proof`
removes the vault, and `run_request` requires `State::unlocked`, which returns
`busy` until it is returned. The native ancestor change tests the actual
mutable authority in that interval. The existing pending-request path is
separately tested after the prompt and before verification, including the
F-70 separate-session extension case. Neither daemon check remains covered
only by the other check's refusal.

| Gate or check | Named mutation observed failing at runtime |
|---|---|
| Daemon explicit first/second selection | `reveal_wrong_field` |
| Gate 23 requester refusal before verification | `drop_pre_proof_check` |
| Gate 23 ancestry change during proof | `drop_post_proof_recheck`, `drop_final_evidence_refresh` |
| Gate 34 CLI and story ordering | `warning_after_value` (both gates fail) |
| Terminal control unit corpus and hostile-value PTY gate | `raw_reveal_bytes` (original writer fails both) |
| Receipt reference check | `stale_validation_refs` (obsolete citation injected in memory) |

Each code mutation produced an assertion failure after successful compilation;
all were restored. No compilation failure or harness timeout counts as proof.
The pre-existing doctor flake is unchanged. The original requirement table
and gates 19, 23, 33 and 34 remain the task's closure map.

Final restored-code checks for this follow-up, detached with isolated HOME/XDG,
target C, incremental disabled, three build jobs and three test threads:

| Platform | Scoped tests passed | Scope |
|---|---|---|
| macOS | 186, no failures or ignored tests | CLI units 45 and reveal 3; daemon units 94 and reveal 1; client library 35; e2e library 4 and reveal story 1; release-feature checks 3 |
| Linux | 206, no failures or ignored tests | CLI units 45 and reveal 12; daemon units 100 and reveal 6; client library 35; e2e library 4 and reveal story 1; release-feature checks 3 |

`cargo fmt --all --check` passed. Strict workspace/all-target Clippy passed
on both platforms (Linux uses its explicit target). `check-unsafe.sh`,
`check-expose-lint.sh` (6/6), `check-sources.sh`, `check-crate-graph.py`
(50 edges, 21 crates), `check-reservations.py` (262 rows, 17 tables), and
`check-spec-decisions.py` (54 decisions, 51 sentences) passed on macOS.
The reference check passed with its stale-reference negative control.
No full workspace test suite or GiB scanner integration test was rerun.

Requirements R-M2-04, R-M2-25, R-M2-26, R-M2-27, R-M2-28, R-M2-29,
R-M2-30, R-M2-79 and R-M2-81 are covered by the original closure table
and the strengthened gates above. No review finding is deferred. The
plan's existing M3 app reveal (D-20) and composed real-agent acceptance
(M2-26) deferrals remain; this follow-up makes no new CI or release claim.
