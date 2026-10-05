# M2-12 handoff

Worktree `/tmp/ec-m2-m2-12`, branch `m2/m2-12`; build target `/tmp/ec-target-E`.
No push, pull request, GitHub comment, or shared-memory update was made.
SPEC and the task's build decisions, common rules, founder decisions, review
refinements, lessons and relevant independent-oracle notes governed the work.

## Scope and gate mapping

| Requirement or gate | M2-12 implementation and evidence |
| --- | --- |
| R-M2-36 | Seven profile roots and bounded literal sources; descriptor-driven JSON/TOML configs and envFile; CodexBar catalog entries; JSONL/raw transcript stores; opt-in git objects, including deleted history. |
| R-M2-41; gate 15, new roots | Descriptor-relative no-follow reads, owned regular files, FIFO/symlink/hard-link/unreadable refusals, 1 MiB config/profile caps, bounded 2 GiB sparse transcript test, file-stamp recheck and held Git root. The leaf-device test is a recording model, not a privileged mount experiment. |
| R-M2-42; gate 11, three parsers | Fixed value-free errors, wiping candidates, bounded hostile-byte fuzz target, and production-allocator probe with an unwiped positive control. Includes upstream TOML parser failure allocations. |
| R-M2-83 contribution; D-32 | Per-run random keyed deduplication, all 100,000 repeated-token ranges retained under one candidate, explicit byte/distinct/occurrence/file/object limits and incomplete reports. Overall doctor gate 36 belongs to M2-14. |
| T-10 and T-11, scanner portion | Conservative single-line eligibility, names-only templates, retained stamps, read-only APIs, bounded work and no local vault comparison. Caller process hardening and purpose-constrained daemon comparison remain the command tasks' responsibility. |
| F-75; D-02 | Catalog-owned host paths feed scan-owned descriptors. The catalog tests assert actual findings, including the provider-config path; the allowed crate graph stays one-way. |
| Cycle277/284/287 reporting refinement | Metadata-only discovery of both new and swap temporary-name shapes beside env and non-env files. Actual interrupted/refused restores and a displaced foreign save remain visible. Names never establish ownership or permit deletion. |

The complete API and consumer contract is in [SCANNERS.md](SCANNERS.md).
`ScanReport` deliberately replaces the plan's sketch `Vec<Found>` return type,
so partial findings retain their refusal reasons and completeness is derived.

## Independent checks

- The adapted cycle200 Python corpus has 74 generated profile cases. An isolated
  Bash evaluates only these synthetic fixtures; comparisons use SHA-256 digests.
  Unsupported syntax is manual and never grants automatic line removal.
- Pinned native Claude Code 2.1.280 and Codex 0.159.2 author configs and actual
  transcripts in the M2-04 isolated homes. Both scanners find the fixture values;
  both host stories fail when either extraction path is removed.
- Python writes escaped JSON and encoded forms. The existing gate-8
  `ec-emit-serde` binary separately verifies JSON escape decoding and raw spans.
- Real Git storage supplies the deleted-history and replaced-root checks.
- Actual restore operations, owned interrupted children, a retained foreign
  save and the independent testkit sweep qualify leftover reporting.
- CodexBar is a documentation-derived fixture, not a measured CodexBar runtime.
  Fish's conservative literal subset is fixture-qualified; no fish runtime was
  available. Linux filesystem and host behavior remains for the driver's CI.

## Commits and sensitivity

| Commit | Scope | Mutations watched failing |
| --- | --- | --- |
| `132caa5` | Profile parser and Bash oracle | follow-symlinked-profile; silence-unreadable-profile; unescape-all-double-quoted-backslashes; skip-source-depth-limit |
| `3d3128d` | Configs, catalog and initial leftover discovery | omit-json-bindings; omit-restore-leftovers; silence-database-omission; disconnect-catalog-scanner; omit-provider-key-reader |
| `7edcb38` | Streaming, ranges, deduplication, safety and memory | drop-json-unescaping; send-duplicate-candidates; silence-byte-budget; skip-stream-stamp-recheck; silence-line-overflow; silence-hardlink-report; skip-encoded-forms; skip-inner-decoded-tokens; recurse-assignment-readings; silence-stream-read-error; remove-production-allocator-wipe; panic-on-malformed-json |
| `c640ee2` | Bounded Git process and held working directory | inherit-git-environment; silence-git-limits; reopen-git-root-by-path |
| `ca11e14` | Conservative profile eligibility and 64-file limit | skip-profile-file-cap |
| `b462ded` | Included-file accounting and actual recovery evidence | remove-leaf-device-guard; remove-leftover-file-budget; hide-retained-restores; drop-envfile-template-name; omit-envfile-hardlink-report; ignore-shared-config-file-cap |
| `5bc7a7c` | Host stories and gate-8 serializer | omit-host-config-values; omit-host-transcript-tokens; drop-json-backslash-unescaping |
| `2364d2e` | Strict-lint cleanup and fuzz-scope wording | No new runtime behavior or gate; affected controls rerun |

All 34 named mutations caused test assertion failures and were restored.
[M2-12-MUTATIONS.json](M2-12-MUTATIONS.json) lists every failing test, result,
local receipt path and receipt SHA-256. Process-entry helper tests are exercised
by their parent gates, rather than being independent acceptance tests.

Early wrong-path/stale-helper runs, one malformed allocator mutation that failed
compilation, and an incorrect test-fixture length do not count as mutation
receipts. Each was corrected and rerun. The original macOS `/dev/fd` working
path experiment was replaced by the owned-descriptor `fchdir` wrapper.

## Local verification

Local macOS verification passed. Logs are under `/tmp/ec-target-E/m2-12`.

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | Pass |
| `RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets` | Pass (`clippy3.log`), after lint-only helper placement and fixture syntax fixes |
| Full tests of all four touched crates | 557 passed, zero failed: agents 172, e2e 97, scan 105, sys 183; two sys documentation examples ignored |
| Required pinned hosts and official MCP client | All 60 host integration tests and all 26 M2 story tests passed, including the three new scanner stories |
| `scripts/check-unsafe.sh`, `scripts/check-expose-lint.sh`, `scripts/check-sources.sh` | Pass |
| `scripts/check-crate-graph.py` | Pass, 50 allowed edges among 21 crates |
| `scripts/check-reservations.py`, `scripts/check-spec-decisions.py` | Pass, 237 rows and 54 decisions/51 sentences respectively |
| Combined agents/scan/mcp/CLI graph, default/all/no-default features | Pass, all targets; default also covered by the source audit's full workspace check |
| `cargo deny check` | Advisories, bans, licenses and sources pass; existing warning-level duplicate/license allowances remain |
| `cargo tree -p envcloak-scan -e normal,build` | Recorded in `static-checks2.log`; no forbidden EnvCloak edge |

Cargo-deny 0.20.2 is installed only at `/tmp/ec-target-E/tools/cargo-deny`.
The official release archive was checked against published SHA-256
`fe67d82a10d8597a3549364cb733a3f9cc1bfff9031b7ae46384a9f2a72090c3`.
Its receipt is `deny.log`; no dependency policy exception was added.

The full suite's result is in `touched-tests.log`. The final strict lint result
is in `clippy3.log`; the initial lint findings and their corrections are kept in
the earlier logs. After lint-only cleanup, focused scanner controls and all 87
sys unit tests passed again. Formatting, unsafe/exposure/source checks and a
fresh workspace binary build also passed again (`final-controls.log`).

Release-artifact/core-dump-only cases retain their normal local skip behavior
without the CI release/core environment. They do not qualify a release gate here.
The two ignored sys doctests are illustrative allocator/testing examples.

The detached runner double-forks, calls setsid, clears its environment and uses
isolated HOME/XDG/TMPDIR. Builds use `CARGO_TARGET_DIR=/tmp/ec-target-E`,
`CARGO_INCREMENTAL=0`, `CARGO_BUILD_JOBS=4`; tests use `--no-fail-fast` and
`--test-threads 4`. Fresh workspace binaries precede the full crate suites;
agent hosts are required, so missing pins cannot silently skip those checks.

## Work owned by later tasks

These are plan boundaries, not M2-12 acceptance claims: M2-14 owns doctor CLI,
full gate 36, presentation, comparison orchestration and the 1 GiB density story;
M2-16 owns opt-in profile rewriting; M2-20 and M2-22 consume leftover reports on
successful and refused undo, and own migration/scrub edits and cleanup proofs;
M2-25 owns longer fuzz/hardening campaigns. This task never deletes a discovered
leftover. No whole-milestone, Linux, release-core-dump, or unmeasured host gate is
claimed by the local scanner results.
