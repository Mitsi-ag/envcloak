# M2b-03a validation

Revalidated 2026-10-06 on branch `m2/m2b-03a`, macOS 26.4.1 arm64,
Rust 1.98.1, Python 3.14.6 and Node 26.7.0. This is library evidence, not a claim about
main, Linux execution, native sign-in, a browser or a real account.

## Scope and requirements

| Requirement or gate | Closed here | Remaining owner |
| --- | --- | --- |
| R-M2b-05 | Enrollment seed, algorithm, width and period; bounded URI parsing; display-only labels | M2b-03b: login items and commands |
| R-M2b-06, engine part | Typed `TotpSpec` and `Code`; seed and result remain `SecretBytes`; only two explicit exposure boundaries in the pure library | M2b-03b: the worker's credential reader and resolver integration |
| R-M2b-40, library part; b3 diagnostic slice | Fixed errors, value-free Debug/Display, bounded digit sweeps with positive controls, heap wiping on success and failure | M2b-03b/M2b-09: tool, audit, stderr and other real output paths; M2b-11: full containment story |
| R-M2b-24 timing support, R-M2b-52; b15 primitive slice | RFC vectors, independent counter/width/offset cases, timing boundaries and the after-start pair | M2b-03b: leases, concurrent account serialization, submitted-step reuse and restart behavior in the daemon |
| M2b-03a SHA-1 rule | Clippy rejects direct, HMAC-generic and block-core SHA-1 types outside `totp.rs`; CI runs the canary | No deferral |
| M2b-03a parser fuzzing | Three bounded proptest properties in the ordinary test suite, including arbitrary bytes and damaged valid enrollments | No `fuzz/` workspace exists at this revision; M2-25 owns libFuzzer infrastructure and its unsafe entry-point accommodation |

The task's pure scope is complete. Full b3/b15, R-M2b-05/06/40/52 and the
remaining M2b-03 gates are not declared complete by this split task.
See [SIGNIN.md](SIGNIN.md) for the accepted grammar and daemon handoff.

## Review input and class sweep

The supplied `m2b-03a-open-findings.json` has `rounds: {}` and explicitly
says there are no review findings yet. No finding was rejected. This round
read the task split, its D-24 architecture, common rules, founder decisions,
parent-task review rows 16, 17 and 31, SPEC, lessons L-01 to L-15 and the
Cycle206/469/474/480 oracle and allocator handoffs.

All 21 files added or changed by this task since `71e6fd0` were swept for
both classes below, including production code, tests, scripts and docs.

| Bug class | Instances swept and repaired | Regression evidence |
| --- | --- | --- |
| ASCII-only blank checks on Unicode text components | Both the issuer prefix and account portion of a label used ASCII spaces. Both now use `display_text`. Whole labels and separate issuer parameters already used Unicode trimming and remain covered. No other instance in the task files. | `every_label_component_requires_nonblank_unicode_text` failed before repair; both component mutations fail independently. Nonblank Unicode controls preserve their original display bytes. |
| Unbounded validation subprocess waits and raw spawn-failure diagnostics | Both Node calls in `totp_oracle.py` now share a 30-second runner; the Cargo call in `check-totp-lint.sh` has a 600-second deadline. All three calls refuse timeout or spawn failure with fixed diagnostics. No other child launcher in the task files. | Three new Python runner controls failed before implementation. Four independent deadline/diagnostic mutations fail. CI runs the controls; real oracle and canary executions pass. |

The runner failure tests inject `TimeoutExpired` and `OSError` and verify
fixed diagnostics and configured deadlines. They do not simulate an entire
hung Cargo process tree. The independent calculation functions and all
reference/corpus bytes remain unchanged.

## Execution and independent evidence

All builds use
`CARGO_TARGET_DIR=/Volumes/KeenShiftDev/tmp/envcloak-target/F`,
`CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=3`. The ignored worktree `target`
link points there for the exposure checker's explicit target directory.
Tests use `--no-fail-fast -- --test-threads 3`, a double-fork/setsid runner,
a cleared environment, disabled core dumps and isolated HOME/XDG/TMPDIR
under `/tmp/ec-m2b03a-F`, an alias into the same target directory. No real
account, credential file, browser or daemon is used by the new gates.

The full `envcloak-signin` suite passed: 81 integration tests (including
all ten exhaustive models) and 13 doctests. After mutation restoration,
all 14 TOTP/parser/heap gates passed again, plus all three Python runner
controls. The initial Unicode regression failed against the original
parser; the new runner controls failed before their implementations.

Cycle206's independently composed Python and Node oracles passed 36
reference checks, 1,142 comparisons, 17 faulty-oracle controls, 20 invalid
parameter controls and the wrong-expected-code positive control. The
checked-in bytes regenerate exactly. The corpus retains all 16 dynamic
offsets per algorithm and 115 leading-zero cases. This is actual execution
of the adopted oracle, extending Cycle469's source-only evidence.

For the Cycle474/480 allocator handoff, three existing `alloc_probe` controls
passed: `wiping_mode_wipes_a_freed_block_that_held_the_needle`,
`unwiped_mode_catches_a_growing_buffer` and
`unwiped_mode_accepts_code_that_wipes_its_own_buffers`. The TOTP probe checks
its actual decoded seed/code semantics, includes unwiped release controls
for the seed, base32 and short code, and observes no protected bytes freed
by the restored success or error paths. Removing the parser buffer wipe
makes that gate fail. This is heap-release evidence, not a stack, live
allocation or process-hardening claim.

## Mutation receipts from this round

All 19 deliberate mutations below caused the named tests/checker to fail.
Each mutation was restored before the passing checks or any commit. Raw
failure logs stay private in the target directory; this table contains no
fixture values. This round rechecked every task gate, rather than treating
the original commit's receipts as current execution.

| Gate or test | Mutation detected |
| --- | --- |
| `rfc_and_independent_oracle_bytes` | `fixed-dynamic-offset` |
| `step_boundaries_and_last_three_seconds` | `allow-at-three-seconds` |
| `after_start_refuses_current_and_previous_without_underflow` | `forget-previous-start-step` |
| `invalid_parameters_cannot_reach_arithmetic` | `accept-seven-digits` |
| `accepted_forms_match_python_base32_bytes` | `wrong-base32-value` |
| `hostile_grammar_is_refused_without_echo` | `error-echoes-synthetic-seed` |
| `input_and_decoded_caps_refuse_instead_of_truncating` | `remove-decoded-seed-cap` |
| `uri_cap_has_valid_boundary_controls` | `remove-uri-cap` |
| `public_debug_and_display_are_value_free` | `debug-prints-code` |
| `every_public_debug_type_hides_seed_and_code` | `debug-prints-code` |
| `parser_fuzz_and_public_debug` | `step-rounded-up` |
| `damaged_valid_enrollment_fuzz` | `error-debug-prints-code` |
| `seed_decoding_and_code_buffers_wipe_on_every_exit` | `base32-buffer-not-wiped` |
| `every_label_component_requires_nonblank_unicode_text` | `ascii-only-label-prefix`, `ascii-only-label-account` |
| `test_every_node_call_has_a_deadline` | `omit-node-deadline` |
| `test_runner_failures_have_fixed_diagnostics` | `echo-node-runner-error` |
| `test_compiler_call_has_a_deadline_and_fixed_failures` | `omit-compiler-deadline`, `echo-compiler-runner-error` |
| `scripts/check-totp-lint.sh` | Direct, HMAC-generic and block-core uses are refused; `remove-sha1-ban` makes the checker fail |

## Commits

Original implementation, retained:

- `94dbad7`: pure TOTP, arithmetic, independent oracles and SHA-1 lint.
  Its message records the original offset, counter, padding, clock,
  startup-pair, invalid-width and removed-ban mutations.
- `dd6b8fe`: parser, hostile-input/fuzz/output/wipe gates and accepted forms.
  Its message records the original base32, duplicate, tail-bit, error-echo,
  caps, Debug, clock and buffer-wipe mutations.
- `a933dc5`: original validation receipt, superseded by this revalidation.

This audit and repair:

- `bff0b6f`: Unicode component repair; the two component mutations above.
- `9e2239c`: bounded Node/compiler waits and fixed diagnostics; the four
  deadline/diagnostic mutations above.
- The commit updating this document records all 19 current mutations and
  their gate mapping, plus the final check results.

## Final local checks

Every check below exited zero on the restored implementation. Only this
value-free validation document changed after these checks.

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | Pass |
| `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets --locked` | Pass |
| `cargo test -p envcloak-signin --locked --no-fail-fast -- --test-threads 3` | 81 integration tests and 13 doctests passed |
| Restored TOTP/parser/heap targets | All 14 tests passed |
| Python runner controls | All 3 tests passed |
| Selected allocator controls | All 3 tests passed |
| `scripts/check-unsafe.sh` | Pass |
| `scripts/check-expose-lint.sh` | All 6 prohibited exposure sites detected |
| `scripts/check-totp-lint.sh` | All 3 prohibited SHA-1 type sites detected |
| `scripts/check-sources.sh` | Dev/all-target and release/shipped-source checks passed |
| `totp_oracle.py` | Exact fixture regeneration and independent controls passed |
| `scripts/check-reservations.py` | Pass |
| `scripts/check-spec-decisions.py` | Pass |
| `scripts/check-crate-graph.py` | Pass |
| `cargo tree --locked -p envcloak-signin -e normal,build` | Reviewed; HMAC/SHA-1 retain the existing digest/zeroize line, no new build script or proc macro |
| `cargo deny check` | Advisories, bans, licenses and sources passed; existing unused-license allowances warn |

Cargo-deny was unavailable on this host. Version 0.20.2 was fetched from
its official release into the task target and verified against the release
asset SHA-256 before use. No system tool installation was changed.

Private machine receipts are under
`/Volumes/KeenShiftDev/tmp/envcloak-target/F/evidence`, including
`mutation-results.json`, `check-results.json`, `signin-restored.json` and
`deny-final.json`. No push, PR, GitHub comment or shared-memory update was
made. No full workspace test suite was run.

## Deliberate deferrals from the plan

No M2b-03a scope item remains open. There is no `fuzz/` workspace in this
checkout, so the task's conditional libFuzzer target does not apply;
bounded arbitrary-byte and damaged-enrollment proptests run normally.
M2-25 owns libFuzzer infrastructure. M2b-03b retains CLI enrollment,
credential readers, daemon leases/account serialization/submitted-step
tracking, restart enforcement, login rotation and typed resolver checks
(b18). M2b-09/M2b-11 retain native output/browser stories and full b3/b15.
The pure task closes only the requirement and gate slices in the first
table, as the M2b-03a split explicitly requires.
