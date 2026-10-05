# M2b-03a validation

Local implementation on branch `m2/m2b-03a`, Darwin arm64, Rust 1.98.1,
Python 3.14.6 and Node 26.7.0. This is library evidence, not a claim about
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

## Tests first and independent evidence

The initial empty-code, zero-clock and always-refusing-parser stubs failed
the new tests before implementation. Restored product code passes all 13
new tests. The tests use isolated HOME/XDG/TMPDIR below `/tmp/ec-target-F`
and run after double-fork/setsid with a cleared child environment. Builds
use `CARGO_TARGET_DIR=/tmp/ec-target-F`, `CARGO_INCREMENTAL=0` and
`CARGO_BUILD_JOBS=4`; Rust test runners use `--test-threads 4` and
`cargo test --no-fail-fast`.

Cycle206's independent oracle was adopted from the plan's research index:
36 reference checks (18 published eight-digit vectors and 18 independently
computed six-digit reductions), 1,142 Python/Node comparisons, all 16
dynamic offsets for every algorithm, leading-zero witnesses, 17 faulty
oracle variants, 20 invalid-parameter controls and a wrong-expected-code
Node control. Rust consumes the checked-in bytes without printing values.
The dependency graph for HMAC 0.13 and SHA-1 0.11 was recorded and reviewed:
only the existing digest/zeroize line and cfg-if/cpufeatures/libc, no new
build script or proc macro. `cargo deny` passes advisories, bans, licenses
and sources; its existing unused-license allowances produce warnings.

## Product mutation receipts

Each product-test row failed at runtime against the named mutation.
The lint row checks an intentional compiler refusal. Mutations were restored before the passing runs and commits.
There are 16 product mutations and 18 failing test executions, plus the
SHA-1 lint controls. Fixed diagnostics and numeric comparisons keep seeds
and codes out of normal failure messages.

| Test | Mutation detected |
| --- | --- |
| `rfc_and_independent_oracle_bytes` | `fixed-dynamic-offset`, `counter-truncated-u32`, `drop-leading-zero` |
| `step_boundaries_and_last_three_seconds` | `step-rounded-up`, `allow-at-three-seconds` |
| `after_start_refuses_current_and_previous_without_underflow` | `forget-previous-start-step` |
| `invalid_parameters_cannot_reach_arithmetic` | `accept-seven-digits` |
| `accepted_forms_match_python_base32_bytes` | `wrong-base32-value` |
| `hostile_grammar_is_refused_without_echo` | `accept-duplicate-parameters`, `ignore-base32-tail-bits`, `echo-synthetic-seed-in-error` |
| `input_and_decoded_caps_refuse_instead_of_truncating` | `remove-decoded-seed-cap` |
| `uri_cap_has_valid_boundary_controls` | `remove-uri-cap` |
| `public_debug_and_display_are_value_free` | `debug-prints-code` |
| `every_public_debug_type_hides_seed_and_code` | `debug-prints-code` |
| `parser_fuzz_and_public_debug` | `step-rounded-up` |
| `damaged_valid_enrollment_fuzz` | `debug-echoes-input-marker` |
| `seed_decoding_and_code_buffers_wipe_on_every_exit` | `base32-buffer-not-wiped` |
| `scripts/check-totp-lint.sh` | Three real SHA-1 uses outside `totp.rs` rejected; `remove-sha1-ban` makes the checker fail; restored ban passes |

The error-echo mutation deliberately formats a generated fixture seed in
an error. The code-Debug mutation opens the generated code. The allocator
probe disables the global allocator's wipe, detects at least 180 unwiped
positive-control releases, and observes no seed/base32/code needles freed
by the actual path. It tests decoding, late failure and all algorithms and
widths over seeds around the HMAC block sizes. It is not a stack-memory
scan and does not establish native process hardening.

## Commits

- `94dbad7`: pure TOTP, injected time, independent oracles and SHA-1 lint.
- `dd6b8fe`: enrollment parser, hostile-input/fuzz/output/wipe gates and
  accepted forms. Both commit messages name their tested mutations.

Local receipts are in `/tmp/ec-target-F/evidence`; they contain synthetic
fixtures only. This document is the durable, value-free handoff.

## Final local checks

All checks below exited zero on the restored, committed implementation.
The only later change is this validation document.

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | Pass |
| `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets` | Pass |
| `cargo test -p envcloak-signin --no-fail-fast -- --test-threads 4` | 80 integration tests and 13 doctests passed; all 10 exhaustive models passed |
| `scripts/check-unsafe.sh` | Pass |
| `scripts/check-expose-lint.sh` | All 6 prohibited exposure sites detected |
| `scripts/check-totp-lint.sh` | All 3 prohibited SHA-1 type sites detected |
| `scripts/check-sources.sh` | Dev/all-target and release/shipped-source checks passed |
| `totp_oracle.py` | Checked-in bytes regenerated exactly; 1,142 Python/Node comparisons passed |
| `scripts/check-reservations.py` | 237 rows in 17 tables passed |
| `scripts/check-spec-decisions.py` | 54 decisions and 51 sentences passed |
| `scripts/check-crate-graph.py` | 50 edges among 21 crates passed |
| `cargo deny check` | Advisories, bans, licenses and sources passed; advisory cache kept under the task target |

No push, PR or GitHub comment was made. No shared-memory files were
updated. Native account-state and browser/output gates remain with the
owners above because M2b-03a deliberately ships no daemon behavior.
