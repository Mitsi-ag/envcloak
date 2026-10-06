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
| M2b-03a SHA-1 rule | Source guard rejects SHA-1 references independently of exposure exceptions; Clippy requires all six canaries | No deferral |
| M2b-03a parser fuzzing | Three bounded proptest properties in the ordinary test suite, including arbitrary bytes and damaged valid enrollments | No `fuzz/` workspace exists at this revision; M2-25/M2b owns the explicitly named `otpauth::parse` libFuzzer target and its unsafe entry-point accommodation |

The task's pure scope is complete. Full b3/b15, R-M2b-05/06/40/52 and the
remaining M2b-03 gates are not declared complete by this split task.
See [SIGNIN.md](SIGNIN.md) for the accepted grammar and daemon handoff.

## Review dispositions and class sweep

The latest two medium findings are resolved. The verifier's duplicate SHA-1
finding is resolved by the same change. Its optional parser check remains
layered, with the evidence below; its conditional fuzz handoff is explicit.
No finding is rejected. The supplied green CI results apply to the prior
head. This receipt claims local macOS execution only.

All 28 files added or changed by this task were swept: source, tests,
fixtures, manifests, scripts, CI, the exposure list and documentation.

| Latest finding and bug class | Instances swept and disposition | Test and mutation evidence |
| --- | --- | --- |
| SHA-1 exemption gap: overlapping lint exceptions | Both parser/TOTP exposure boundaries, every public SHA-1 primitive, all six canaries, all Rust source locations and Cargo aliases. A separate source check reserves the crate identifier outside the implementation and guarded canary. It covers imports, raw identifiers, comments between tokens, inactive cfgs and future fuzz targets. The only string exceptions are exact test algorithm markers. | `sha1-in-exposure-scope`: a call inside the actual allowed parser function passes Clippy, then fails the source guard. `remove-sha1-source-guard`, `allow-sha1-dependency-alias`, `allow-unguarded-sha1-canary`, `allow-sha1-type-exception` and `omit-source-walk` fail their controls. |
| Partial wipe coverage: detector window exceeds retained prefix | Base32 success, every symbol failure position, tail-bit refusal, late parameter refusal; percent decoding's truncated, bad-high, bad-low, raw-symbol and post-decode refusals in labels and all five parameters. Seeds of lengths 1-32 use exact-length needles with separate positive controls. The existing long-seed/HMAC/code probe remains. | All selective missing-wipe mutations below fail. The test-only allocator's two-byte lower bound was another instance of the detector class; its new one-byte test failed before repair and catches `one-byte-observer-disabled`. No production allocator changes. |
| Fuzz handoff: conditional work lacks a concrete target | SIGNIN and this receipt now name `otpauth::parse` for M2-25/M2b, arbitrary-byte input and regression checks. No fuzz workspace exists in this checkout. | `omit-parser-fuzz-handoff` fails the owner/target documentation control. Bounded proptests still run; no libFuzzer execution is claimed. |
| Layered digits validation: redundant checks obscure mutation attribution | Parser grammar, TotpParams constructor, hostile-input tests, arithmetic parameter tests and receipt claims were checked. Retain both checks; behavior is correct. | `parser-only-seven-layering` survives as expected because the constructor refuses seven; the full parser target passes with that mutation. `accept-seven-digits` in the constructor fails `invalid_parameters_cannot_reach_arithmetic`. This is a documented layered control, not a claimed independent parser-branch detection. |

Previous-round repairs remain intact and were rechecked:

| Finding and bug class | Instances swept and repaired | Test and mutation evidence |
| --- | --- | --- |
| Verifier formatting and reviewer encoded output: incomplete disclosure oracles | All four formatting/property tests; Debug of all seven public TOTP/parser types and every implemented Display; success/error Result wrappers; both process output streams. Exact markers supplement the old raw/digit controls. | The previously surviving `spec-debug-seed` and `code-debug-bytes` fail both formatting gates, as does `code-debug-base64`. The new output gate rejects five byte-list/base64/hex/percent/JSON disclosures. |
| Reviewer SHA-1: primitive functions bypass a type-only ban | Pinned SHA-1 public exports: Sha1, Sha1Core and compress. Task source has no other SHA-1 use. Direct, aliased and function-pointer compression calls now join direct/core/generic type canaries. | Both `remove-sha1-type-ban` and `remove-sha1-compression-ban` leave only three of six refusals and fail the checker. |
| Verifier periods: accepted configuration cannot make bounded progress | TotpParams constructor, URI parser, accepted-form and property inputs, raw-cap controls, arithmetic boundary tests and SIGNIN documentation. Enrollment accepts 4 through 300 seconds. The arithmetic-only Period still models every positive input. | Both new eligibility tests failed before repair. `accept-ineligible-short-period` and `accept-unbounded-period` each fail the constructor and parser gates. |
| Verifier CI: independent oracle omitted from execution | Existing runner-only CI step, Node availability, full Python/Node comparison and checked-in corpus freshness. A new isolated shell entry point runs the full oracle on each CI test job. | `omit-full-oracle-ci`, `omit-oracle-isolation` and `hand-edited-corpus` fail. The restored real wrapper passes. |
| Verifier receipt: derived references stale after rebase | All commit references in this document, its obsolete source-base reference, old counts and CI runtime commentary. Subjects replace hashes; historical measurements are not current passes. | Receipt-reference control failed before repair and rejects `stale-receipt-hash`. |

The previous-round findings were resolved without deferral. Unicode
component and bounded-runner fixes remain intact and mutation-tested.

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
Seven Python controls and the selected existing allocator controls pass.
The full sys suite is also required because its test-only probe now accepts
one-byte needles. Its separate shortest-release gate has one positive
release and one correctly wiped control.

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
pass. Dropping the parser's own buffer wipe fails the probe. The new short corpus
adds 2,068 separately controlled heap observations: 64 accepted forms,
32 late refusals, 794 nonempty base32 prefixes, 26 tail-bit refusals and
1,152 percent-decoding/refusal cases. The original 60 long-seed failure samples now also use exact decoded
prefixes, including their six 15-byte prefixes, each with its own control.
Another 64 base32 positions refuse
before producing a byte, so no decoded-seed wipe is claimed for them.
Python standard-library base32 encoding generates this new corpus; the
full oracle checks its exact freshness alongside the unchanged RFC corpus. This measures
heap releases of synthetic values, not stack/live-memory erasure or
native process hardening. Runner timeout tests inject failures rather than
simulating a hung Cargo process tree.

## Mutation receipts from this round

All 60 fault mutations (25 new and 35 replayed) caused the named gate to
fail. The parser-only layering control above is excluded from that total.
Each mutation was restored before
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

| Source confinement and its Python controls | `sha1-in-exposure-scope`, `remove-sha1-source-guard`, `allow-sha1-dependency-alias`, `allow-unguarded-sha1-canary`, `allow-sha1-type-exception`, `omit-source-walk` |
| Short and partial heap observations | `base32-short-success-not-wiped`, `base32-prefix-1-not-wiped`, `base32-prefix-2-not-wiped`, `base32-prefix-15-not-wiped`, `base32-tail-not-wiped`, `long-base32-prefix-not-wiped`, `percent-truncated-prefix-1-not-wiped`, `percent-truncated-prefix-15-not-wiped`, `percent-high-prefix-1-not-wiped`, `percent-high-prefix-15-not-wiped`, `percent-low-prefix-1-not-wiped`, `percent-low-prefix-15-not-wiped`, `percent-raw-symbol-not-wiped`, `percent-complete-buffer-not-wiped`, `short-late-seed-not-wiped`, `disable-prefix-positive-control` |
| `one_byte_needle_observes_the_shortest_release` | `one-byte-observer-disabled` |
| Short independent corpus freshness | `hand-edited-decoding-corpus` |
| `test_fuzz_handoff_names_parser_and_owner` | `omit-parser-fuzz-handoff` |

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

- `M2 M2b-03a: probe one-byte heap releases`: test-only allocator boundary.
- `M2 M2b-03a: cover partial decoding wipes`: exact-prefix heap gates and fixtures.
- `M2 M2b-03a: close SHA-1 exemption gap`: source confinement and explicit handoffs.
- `M2 M2b-03a: record final review repairs`: class sweep and local receipts.

The receipt-reference gate rejects hash-based references in this section.
Each implementation commit names its corresponding mutation controls.

## Final local checks

Every final check below exited zero on the restored tree. Both complete
crate suites ran, never the workspace suite. The first sys run failed its
existing PTY stop/resume stress case after 15,788 stops: the monitor's
next-event wait returned None. The complete sys rerun passed, including
all nine topology cases, without changing PTY code. That intermittent
observation remains recorded; this task does not claim to repair it.

An earlier lint invocation overlapped a deliberately broken source mutation
and is excluded from validation. Final checks run after mutations end.
The final sign-in suite, formatting, strict Clippy and source/compiler
canaries were rerun after adding the retained long-prefix cases.

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | Pass |
| `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets --locked` | Pass |
| `cargo test -p envcloak-signin --locked --no-fail-fast -- --test-threads 3` | 83 integration tests, 13 doctests and 1 output gate passed |
| `cargo test -p envcloak-sys --locked --no-fail-fast -- --test-threads 3` | 184 ordinary tests and all custom harnesses passed; 2 existing doctests ignored; initial topology timeout recorded above |
| Restored TOTP/parser/heap targets | 16 named TOTP/parser/heap tests plus the output gate passed |
| Python runner controls | All 7 tests passed |
| Selected allocator controls | All 3 tests passed |
| `scripts/check-unsafe.sh` | Pass |
| `scripts/check-expose-lint.sh` | All 6 prohibited exposure sites detected |
| `scripts/check-totp-lint.sh` | Source confinement and all 6 prohibited SHA-1 type/function sites detected |
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
`/Volumes/KeenShiftDev/tmp/envcloak-target/F/evidence/r4`, `r4-extra`,
`r4-wipe-extra`, `r4-replay` and `r4-final`, including mutation and check result JSON
and private per-check logs. Prior-round evidence remains under `r3`.
No push, PR, GitHub comment, shared-memory update or workspace test run
was made.

## Deliberate deferrals from the plan

No M2b-03a scope item remains open. There is no `fuzz/` workspace in this
checkout, so the task's conditional libFuzzer target does not apply;
bounded arbitrary-byte and damaged-enrollment proptests run normally.
M2-25/M2b owns the explicit `otpauth::parse` libFuzzer target. M2b-03b
retains CLI enrollment, credential readers, daemon leases/account serialization/submitted-step
tracking, restart enforcement, login rotation and typed resolver checks
(b18). M2b-09/M2b-11 retain native output/browser stories and full b3/b15.
The pure task closes only the requirement and gate slices in the first
table, as the M2b-03a split explicitly requires.
