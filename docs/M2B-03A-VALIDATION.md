# M2b-03a validation

Revalidated 2026-10-06 on branch `m2/m2b-03a`, macOS 26.4.1 arm64,
Rust 1.98.1, Python 3.14.6 and Node 26.7.0. This is library evidence, not a
claim about main, Linux execution, native sign-in, a browser or a real account.

## Scope and requirements

| Requirement or gate | Closed here | Remaining owner |
| --- | --- | --- |
| R-M2b-05 | Enrollment seed, algorithm, width and 4-300-second period; bounded URI parsing; display-only labels | M2b-03b: login items and commands |
| R-M2b-06, engine part | Typed `TotpSpec` and `Code`; seed and result remain `SecretBytes`; only two explicit exposure boundaries in the pure library | M2b-03b: the worker's credential reader and resolver integration |
| R-M2b-40, library part; b3 diagnostic slice | Exact fixed Debug/Display, empty library stdout/stderr, encoded disclosure controls, heap wiping on success and failure | M2b-03b/M2b-09: tool, audit, native-process stderr and other integrated output paths; M2b-11: full containment story |
| R-M2b-24 timing support, R-M2b-52; b15 primitive slice | RFC vectors, independent counter/width/offset cases, timing boundaries and the after-start pair | M2b-03b: leases, concurrent account serialization, submitted-step reuse and restart behavior in the daemon |
| M2b-03a SHA-1 rule | Clippy rejects SHA-1 types and compression function uses outside `totp.rs`; CI requires all six canaries | No deferral |
| M2b-03a parser fuzzing | Three bounded proptest properties in the ordinary test suite, including arbitrary bytes and damaged valid enrollments | No `fuzz/` workspace exists at this revision; M2-25 owns libFuzzer infrastructure and its unsafe entry-point accommodation |

The task's pure scope is complete. Full b3/b15, R-M2b-05/06/40/52 and the
remaining M2b-03 gates are not declared complete by this split task.
See [SIGNIN.md](SIGNIN.md) for the accepted grammar and daemon handoff.

## Review dispositions and class sweep

All six supplied findings are accepted and resolved. The verifier's CI
results describe the prior rebased head, not this repair's current head.
This receipt claims local macOS execution only. References use commit
subjects rather than hashes so a later rebase does not stale the handoff.

All 24 files added or changed by M2b-03a were swept, including source,
tests, oracle fixtures, manifests, scripts, CI and documentation.

| Finding and bug class | Instances swept and repaired | Test and mutation evidence |
| --- | --- | --- |
| Verifier formatting and reviewer encoded output: incomplete disclosure oracles | All four formatting/property tests; Debug of all seven public TOTP/parser types and every implemented Display; success/error Result wrappers; both process output streams. Exact markers supplement the old raw/digit controls. | The previously surviving `spec-debug-seed` and `code-debug-bytes` fail both formatting gates, as does `code-debug-base64`. The new output gate rejects five byte-list/base64/hex/percent/JSON disclosures. |
| Reviewer SHA-1: primitive functions bypass a type-only ban | Pinned SHA-1 public exports: Sha1, Sha1Core and compress. Task source has no other SHA-1 use. Direct, aliased and function-pointer compression calls now join direct/core/generic type canaries. | Both `remove-sha1-type-ban` and `remove-sha1-compression-ban` leave only three of six refusals and fail the checker. |
| Verifier periods: accepted configuration cannot make bounded progress | TotpParams constructor, URI parser, accepted-form and property inputs, raw-cap controls, arithmetic boundary tests and SIGNIN documentation. Enrollment accepts 4 through 300 seconds. The arithmetic-only Period still models every positive input. | Both new eligibility tests failed before repair. `accept-ineligible-short-period` and `accept-unbounded-period` each fail the constructor and parser gates. |
| Verifier CI: independent oracle omitted from execution | Existing runner-only CI step, Node availability, full Python/Node comparison and checked-in corpus freshness. A new isolated shell entry point runs the full oracle on each CI test job. | `omit-full-oracle-ci`, `omit-oracle-isolation` and `hand-edited-corpus` fail. The restored real wrapper passes. |
| Verifier receipt: derived references stale after rebase | All commit references in this document, its obsolete source-base reference, old counts and CI runtime commentary. Subjects replace hashes; historical measurements are not current passes. | Receipt-reference control failed before repair and rejects `stale-receipt-hash`. |

No finding was rejected or deferred. The Unicode component and bounded
runner fixes from the preceding round remain intact and mutation-tested.

The accepted-period range is a local enrollment policy, not an RFC limit.
At least one second in every accepted step is eligible, and a fresh step
is at most 300 seconds away. Daemon authorization, account serialization,
lease expiry and submission-time rechecks still belong to M2b-03b.
The input cap is now 4000 bytes: with a bounded period, the previous
4096-byte cap exceeded the largest otherwise valid escaped enrollment.
The new cap retains independently valid inputs on each side of its bound,
so removing it still fails its own test instead of another field's limit.

## Execution and independent evidence

Builds use `CARGO_TARGET_DIR=/Volumes/KeenShiftDev/tmp/envcloak-target/F`,
`CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=3`. The ignored worktree target
link points there for checkers with an explicit target directory. Tests
use `--no-fail-fast -- --test-threads 3`, a double-fork/setsid runner, a
cleared environment and disabled core dumps. HOME/XDG/TMPDIR live below
`/tmp/ec-m2b03a-F`, an alias into the task target. No real credentials,
account, browser or daemon are used by the task's new gates.

The full sign-in suite passes with 83 integration tests, 13 doctests and
one harness-free output gate. All ten exhaustive state models pass.
Five Python controls and three selected existing allocator controls pass.

Cycle206's independent Python/Node compositions pass 36 RFC-derived
checks, 1,142 comparisons, 17 faulty-oracle controls, 20 invalid-parameter
controls and the wrong-expected-code control. Fixture bytes regenerate
exactly. The corpus retains all dynamic offsets and 115 leading-zero
cases. The calculation functions and reference/corpus bytes are unchanged.
`scripts/check-totp-oracle.sh` runs this actual oracle with isolated
HOME/XDG/TMPDIR; CI installs Node on pull requests as well as full runs.

The harness-free output fixture calls the parser, code generator and all
public formatters on all algorithms and widths, including refusals.
Python standard-library serializers independently construct 13 forms for
seed, base32 and code bytes: raw, Rust decimal byte-list, lower/upper hex,
base64/base64url padded and unpadded, percent variants, JSON and Unicode
escapes. All 39 disclosure controls fire. Real stdout and stderr are both
empty and both hit counts are zero. The empty-stream rule also rejects
transforms beyond this finite sweep's vocabulary. The gate never prints
fixture content. Its deadline/spawn failure is a fixed refusal.

The allocator controls from the Cycle474/480 handoff and the TOTP probe
pass. Dropping the parser's own buffer wipe fails the probe. This measures
heap releases of synthetic values, not stack/live-memory erasure or
native process hardening. Runner timeout tests inject failures rather than
simulating a hung Cargo process tree.

## Mutation receipts from this round

All 35 mutations caused the named gate to fail. Each was restored before
passing checks and commits. Diagnostic logs remain private in the task
target; this table contains no fixture values.

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
| `public_debug_and_display_are_value_free` and `every_public_debug_type_hides_seed_and_code` | `debug-prints-code`, `spec-debug-seed`, `code-debug-bytes`, `code-debug-base64` |
| `parser_fuzz_and_public_debug` | `step-rounded-up` |
| `damaged_valid_enrollment_fuzz` | `error-debug-prints-code` |
| `seed_decoding_and_code_buffers_wipe_on_every_exit` | `base32-buffer-not-wiped` |
| `every_label_component_requires_nonblank_unicode_text` | `ascii-only-label-prefix`, `ascii-only-label-account` |
| `test_every_node_call_has_a_deadline` | `omit-node-deadline` |
| `test_runner_failures_have_fixed_diagnostics` | `echo-node-runner-error` |
| `test_compiler_call_has_a_deadline_and_fixed_failures` | `omit-compiler-deadline`, `echo-compiler-runner-error` |
| `scripts/check-totp-lint.sh` | `remove-sha1-type-ban`, `remove-sha1-compression-ban` |
| `totp_output` | `stdout-code-byte-list`, `stderr-code-hex`, `stdout-code-base64`, `stderr-code-percent`, `stdout-code-json-escapes`, `omit-base64-disclosure-needles` |
| `accepted_periods_have_an_eligible_instant_and_bounded_wait` and `enrollment_refuses_periods_without_bounded_eligibility` | `accept-ineligible-short-period`, `accept-unbounded-period` |
| `test_ci_runs_independent_oracle_with_isolation` | `omit-full-oracle-ci`, `omit-oracle-isolation` |
| `test_receipt_commit_references_survive_rebase` | `stale-receipt-hash` |
| `scripts/check-totp-oracle.sh` | `hand-edited-corpus` |

## Commits

References use unique subject lines so rebasing does not invalidate them:

- `M2 M2b-03a: add pure TOTP and RFC oracles`: engine and arithmetic.
- `M2 M2b-03a: parse and protect TOTP enrollments`: parser and containment.
- `M2 M2b-03a: record gate and mutation receipts`: original evidence.
- `M2 M2b-03a: reject blank Unicode label parts`: Unicode component checks.
- `M2 M2b-03a: bound validation subprocess waits`: runner deadlines.
- `M2 M2b-03a: record repaired gate evidence`: prior class sweep receipts.
- `M2 M2b-03a: bound enrollment periods`: period and cap controls.
- `M2 M2b-03a: confine SHA-1 compression calls`: all public SHA-1 primitives.
- `M2 M2b-03a: enforce exact and silent diagnostics`: formatting and streams.
- `M2 M2b-03a: run independent gates in CI`: CI, receipt and final checks.

The receipt-reference gate rejects hash-based references in this section.
Each implementation commit names its corresponding mutation controls.

## Final local checks

Every final check below exited zero. The initial strict Clippy run caught
`err_expect` in the new output fixture. Its refusal branch now uses a
pattern match, avoiding value-bearing Debug even on an unexpected success.
Strict workspace/all-target Clippy, the output gate and formatting were
rerun and passed. Initial failures and final rechecks remain in the receipts.

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | Pass |
| `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets --locked` | Pass |
| `cargo test -p envcloak-signin --locked --no-fail-fast -- --test-threads 3` | 83 integration tests, 13 doctests and 1 output gate passed |
| Restored TOTP/parser/heap targets | 16 named TOTP/parser/heap tests plus the output gate passed |
| Python runner controls | All 5 tests passed |
| Selected allocator controls | All 3 tests passed |
| `scripts/check-unsafe.sh` | Pass |
| `scripts/check-expose-lint.sh` | All 6 prohibited exposure sites detected |
| `scripts/check-totp-lint.sh` | All 6 prohibited SHA-1 type/function sites detected |
| `scripts/check-sources.sh` | Dev/all-target and release/shipped-source checks passed |
| `scripts/check-totp-oracle.sh` | Exact fixture regeneration and independent controls passed |
| `scripts/check-reservations.py` | Pass |
| `scripts/check-spec-decisions.py` | Pass |
| `scripts/check-crate-graph.py` | Pass |
| `cargo tree --locked -p envcloak-signin -e normal,build` | Reviewed; HMAC/SHA-1 retain the existing digest/zeroize line, no new build script or proc macro |
| `cargo deny check` | Advisories, bans, licenses and sources passed; existing unused-license allowances warn |

Cargo-deny 0.20.2 is retained in the task target from the preceding round,
which verified its official release asset SHA-256 before use. No system
tool installation was changed.

Private machine receipts are under
`/Volumes/KeenShiftDev/tmp/envcloak-target/F/evidence/r3`, including
`mutation-results.json`, `check-results.json`, `final-rechecks.json` and
the per-check logs. The initial Clippy failure remains recorded separately
from its successful recheck. No push, PR, GitHub comment or shared-memory
update was made. No full workspace test suite was run.

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
