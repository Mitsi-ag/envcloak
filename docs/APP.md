# EnvCloak: the macOS app

Status: M3, written by task M3-01 as the contract the M3 tasks build to. Nothing in this file is built yet: each part names the task that builds it, and changes from "planned" to a description of what exists only in the commit that lands it, with its test (claims match evidence). The decisions are the M3 plan's (`D3-nn`); SPEC §12 is the source of truth for what the app is, and SPEC §4.3 and §4.4 for what it may ask of the daemon.

## Toolchain and floor

- SwiftUI, Swift 6 with strict concurrency and warnings as errors, macOS 26 or later (SPEC §12, D3-04). Every Liquid Glass API is macOS 26 or later.
- Built with Xcode 26.6 (17F113), on the founder's Mac (macOS 26.4.1) and on GitHub's `macos-26` arm64 runner, which has it as its default and no Xcode 27. CI selects `/Applications/Xcode_26.6.app` by path and fails when it is missing.
- The few macOS 27 SDK APIs the design names sit behind `#if compiler(>=6.4)` (Swift 6.4 ships with Xcode 27) with their macOS 26 fallbacks; the lane moves to Xcode 27 when both the build Mac and the runner image have it.

## Bundle layout (M3-02; the login item M3-18)

```
EnvCloak.app/                                   ai.envcloak.app
  Contents/MacOS/EnvCloak                       the app
  Contents/MacOS/envcloak                       the CLI (ai.envcloak.cli)
  Contents/Helpers/EnvCloakAgent.app/           ai.envcloak.agent, background-only
    Contents/MacOS/envcloakd                    the daemon
    Contents/embedded.provisionprofile          the helper's own profile (from M3-10)
  Contents/Library/LaunchAgents/ai.envcloak.agent.plist
                                                BundleProgram, registered with
                                                SMAppService.agent (M3-18)
  Contents/embedded.provisionprofile            the app's profile (from M3-10)
```

The bundle holds exactly these three executables; `scripts/macos/sign-check.sh` refuses any other. The data protection keychain exists only in a GUI login session, so the helper runs as a LaunchAgent, never a system daemon (SPEC §12).

Source layout: `apps/macos/EnvCloak.xcodeproj` with the targets `EnvCloak`, `EnvCloakAgent` (the helper wrapper), `EnvCloakTests`, `EnvCloakUITests` and `EnvCloakHardwareTests` (in no CI scheme); the local packages `apps/macos/Packages/EnvCloakKit` (the Swift client, D3-03) and `apps/macos/Packages/EnvCloakDesign` (the brand tokens); `apps/macos/Config/{Base,Signing-Adhoc,Signing-Development,Signing-CI}.xcconfig`; scripts under `scripts/macos/`. `apps/macos/` and `scripts/macos/` are code-owned (.github/CODEOWNERS).

## The Swift client (M3-03)

`EnvCloakKit` speaks the protocol of docs/IPC.md itself: 4-byte big-endian frames of at most 1 MiB, JSON-RPC 2.0 with `u64` ids and unknown fields refused, padded base64 values decoded straight into a `SecretBuffer`, fixed error tokens, and the client's peer checks before the first byte is sent (gates 20 and 21). No Rust is linked into the app: an FFI crate would need `unsafe` outside `envcloak-sys` (SPEC §5 "Process hardening"). Both sides stay equal through vectors written at test time: framing, base64 and escaping (Rust and a Python oracle), the canonical statement (`crates/envcloak-policy/tests/oracles/statement.py`, the Rust encoder and the Swift one), and HPKE (CryptoKit and the Rust `hpke` crate, SPEC §11).

The app never waits on an open connection: it polls `status` once a second, each call on its own connection, at most two open at once (D3-09).

## Signing tiers (D3-05)

| Tier | Where | Identity | Keychain | `envcloak status` |
|---|---|---|---|---|
| 1. Ad hoc | EU-0 and EU-1 builds, any Mac | `codesign -s - -o runtime` | none | "daemon identity unverified" (SPEC §4.2) |
| 2. Apple Development | the founder's Mac, from EU-2 (M3-10) | the team's Apple Development certificate, with two macOS development profiles carrying Keychain Sharing for `ai.envcloak.app` and `ai.envcloak.agent` | the data protection keychain group `<TEAMID>.ai.envcloak`, authorised by the profiles | verified |
| 3. CI | the `macos-app` job and the Rust macOS tests | a throwaway self-signed code-signing identity in a temporary keychain (`scripts/macos/ci-identity.sh`, M3-07), used only by tests | none | verified against the `testing` pins |
| 4. Developer ID | M7, not M3 | the Developer ID Application certificate, which only the Account Holder can create; notarised, stapled, Sparkle, Homebrew cask | as tier 2, with Developer ID profiles | verified |

Every tier signs with the hardened runtime and none with `com.apple.security.get-task-allow`. Release builds set `CODE_SIGN_INJECT_BASE_ENTITLEMENTS = NO`, and `scripts/macos/sign-check.sh` refuses any artifact that carries `get-task-allow` or a hardened-runtime exception entitlement. The signing order is the helper, then the CLI, then the app (SPEC §12).

## Pins (D3-06; M3-07 and M3-10)

The daemon gives the `app` role, and the CLI and the app trust the daemon, only on a code signature read from the peer's audit token that satisfies its pinned requirement:

| Signed code | Requirement |
|---|---|
| The app | `identifier "ai.envcloak.app" and anchor apple generic and certificate leaf[subject.OU] = "<TEAMID>"` |
| The daemon (helper) | the same with `ai.envcloak.agent` |
| The CLI | the same with `ai.envcloak.cli` |

Beyond the requirement the peer must run with the hardened runtime flag and carry none of `com.apple.security.get-task-allow`, `com.apple.security.cs.allow-jit`, `com.apple.security.cs.allow-unsigned-executable-memory`, `com.apple.security.cs.allow-dyld-environment-variables`, `com.apple.security.cs.disable-library-validation`, `com.apple.security.cs.disable-executable-page-protection` and `com.apple.security.cs.debugger` (SPEC §4.3). The verdict is per connection.

- The Rust pins live in one file, `crates/envcloak-sys/src/peer_code/pins.rs` (M3-07), with the Team ID of the founder's team (Q3-01); the Team ID and signing identifiers are build-time configuration, so a fork edits that file and signs its own builds (SPEC §12). The Swift copy, `EnvCloakKit/Peer/Pins.swift` (M3-10), is checked byte for byte against it by a test that reads `pins.rs`.
- The `testing` feature substitutes requirements on the CI identity's certificate leaf hash; a release-feature test refuses a release build that holds them.
- `security-framework` 3.x covers the audit-token guest lookup (`SecCodeCopyGuestWithAttributes`), the requirement check (`SecCodeCheckValidity`) and the data protection keychain items; it does not wrap `SecCodeCopySigningInformation`, which the runtime-flag and entitlement conditions need, so M3-07 calls that from `envcloak-sys` (the dependency trial, below).
- A build that pins no signing identity (Linux, source and unsigned builds) has no `app` role, and its CLI reports "daemon identity unverified", as in M1.

## The app run by an agent (M3-07 to M3-16)

The `app` role says which code sent a request, not who started it. The daemon still reads the peer's evidence at each `app.` request: from an app whose evidence names an agent (an agent ran the app's executable itself, so the agent is in its ancestry or its markers are in the app's claims) or whose chain is cut at the walk's depth limit, every `app.` request but `app.lock` is refused (`proof_refused`) and audited before anything is answered, so no envelope, pending request or Touch ID prompt reaches it; `app.lock` is answered, since locking only tightens (SPEC §10b). An agent that starts the app through LaunchServices (`open -a`), or whose app outlives it and is reparented to launchd, is not seen this way; there the guard is user presence on the Secure Enclave key for the statement the app renders (SPEC §10b, "Honest limits").

## Screen lock and session switch (M3-17)

The app reports a screen lock and a switch away from the login session with `app.lock` (`screen_lock`, `session_resign`; SPEC §5 "Lock"), which no client can call. M3-17 picks the signal on macOS 26 and 27 (plan K3-04) among `NSWorkspace.screensDidSleepNotification`, `NSWorkspace.sessionDidResignActiveNotification` and the undocumented `com.apple.screenIsLocked` distributed notification, and records here which one, with the evidence, and whether another program running as the user can post it. Any such program can post a distributed notification, so if the app listens for one, a program can make it lock the vault early with that reason. Locking only tightens: what such a program changes is the recorded reason, never what a grant reaches. Not chosen yet.

## Build commands

| Command | Task | What it does |
|---|---|---|
| `scripts/macos/build-app.sh [--sign adhoc\|development\|ci] [--install]` | M3-02, M3-06 | `cargo build --release` of `envcloak` and `envcloakd`; `xcodebuild` (Release); copies the binaries into the bundle; signs the helper, then the CLI, then the app, with the hardened runtime; runs `sign-check.sh`; with `--install`, the founder build below |
| `scripts/macos/sign-check.sh` | M3-02 | every executable has the runtime flag and no `get-task-allow` or exception entitlement (`codesign -dv`, `codesign -d --entitlements -`), and the bundle holds exactly the three executables; from M3-18 also no quarantine attribute on the bundled plist |
| `scripts/macos/check-swift.sh` | M3-02 | the lane-C Swift rules: values only in `SecretBuffer`, no side doors (`CFBundleURLTypes`, `NSAppleScriptEnabled`, `OSAScriptingDefinition`, `NSServices`, `import AppIntents`), `os_log`/`Logger` only with private by default, every daemon string escaped, brand tokens only |
| `scripts/macos/ci-identity.sh` | M3-07 | the CI identity in a temporary keychain, and test fixtures signed with it |
| `scripts/macos/profiles.sh` | M3-10 | the bundle ids, this Mac's registration and the two development profiles, from the team's App Store Connect API key; prints no key material (Q3-02) |
| `scripts/macos/hardware-tests.sh` | M3-10 | `EnvCloakHardwareTests` on the founder's Mac (Secure Enclave, keychain group, `SMAppService`), each skip reported as a skip with the macOS build |

## The founder build (D3-18, D3-07)

One command, `scripts/macos/build-app.sh --install`, builds both Rust binaries and the app, signs inside out, checks the entitlements, installs to `/Applications`, and restarts the daemon through the bundled CLI only when its version changed. Until the login item lands (M3-18), the app's "Start background process" runs the bundled `envcloak daemon install --daemon /Applications/EnvCloak.app/Contents/Helpers/EnvCloakAgent.app/Contents/MacOS/envcloakd`, the CLI's LaunchAgent with an absolute path, which SPEC §4.1 allows. M3-18 moves to `SMAppService.agent(plistName:)` and never runs both. Vault creation stays in Terminal (`envcloak vault create`, D3-14), and the first-run scan runs in the CLI, never in the app (D3-13).

## Dependencies (D3-15, the trial of task M3-01)

The trial ran each candidate alone in a scratch crate, then the three together, through `cargo tree -e normal,build` (every target, and `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`), `cargo metadata` per platform, `cargo deny` 0.20.2, `scripts/check-sources.sh` and a build and test of a file using each API on `aarch64-apple-darwin`. A second run (after review) compiled the same five for `x86_64-apple-darwin`: `scripts/check-sources.sh` with `CARGO_BUILD_TARGET=x86_64-apple-darwin`, so its `cargo check` runs, every workspace unit's dep-info and the proc-macros compiled for the workspace are those of that target, and the same build and test, run under Rosetta 2 on this arm64 Mac (macOS 26.4.1, rustc 1.98.1). The scripts and outputs are on the scratch branch `m2/m3-01-deptrial` (commits c6153a2 and e2d1bfd, `results/` and `results/x86_64-apple-darwin/`), never merged.

| Candidate | Features | cargo deny | check-sources.sh: arm64 Mac / x86_64 Mac | Proc-macros: arm64 Mac / x86_64 Mac / x86_64 Linux |
|---|---|---|---|---|
| `hpke` 0.14.1 | default off; `alloc`, `getrandom`, `x25519`, `nistp`, `aes`, `chacha` | ok | refused: `zeroize_derive` / refused: `curve25519-dalek-derive`, `zeroize_derive` | `zeroize_derive` / `zeroize_derive`, `curve25519-dalek-derive` / the same |
| `hpke` 0.14.1, the D3-15 fallback | default off; `alloc`, `getrandom`, `nistp`, `aes` | ok | refused: `zeroize_derive` / the same | `zeroize_derive` on all three |
| `p256` 0.14.0 | default off; `ecdsa` (`VerifyingKey` is behind it, so the signing code compiles too, unused) | ok | ok / ok | none |
| `security-framework` 3.7.0, `core-foundation` 0.10.1, macOS only | default off; `OSX_10_15` (the data protection keychain) | ok | ok / ok | none |
| all three | as above | ok | refused: `zeroize_derive` / refused: `curve25519-dalek-derive`, `zeroize_derive` | as `hpke` |

`hpke` 0.14.1 depends on `zeroize` with `zeroize_derive` on every target, so the fallback to DHKEM(P-256) for the reseal does not avoid the proc-macro allowlist review; it avoids only `curve25519-dalek-derive`, which `x25519-dalek` 3 (`curve25519-dalek` 5) compiles on x86_64. The default of D3-15 therefore stands: M3-08, the task that adds `hpke`, asks for the allowlist review of `zeroize_derive` (a derive of a well-known trait, whose output the item fixes) and of `curve25519-dalek-derive` (an attribute that copies functions with target features), and takes the SPEC fallback only if the review refuses the second. Every candidate builds and its tests pass on this Mac for both targets (arm64 natively, x86_64 under Rosetta 2; all three together, 3 passed on each): the two HPKE suites round-trip and a wrong AAD does not open, a malformed P-256 key is refused, and a malformed requirement or audit token is refused. On x86_64 the source check refuses exactly the proc-macros the resolved graph named, and the compiler reads no file that `scripts/check-unsafe.sh` does not scan; the x86_64 Linux column is still the resolved graph (`cargo metadata --filter-platform`), and Linux CI is where the task that adds `hpke` runs it.

## Founder requests (M3 plan §11)

Sent on 2026-10-05 with task M3-01; each has the default the plan assumes, and nothing in M3-01 waits for them.

- Q3-01: which Apple Developer team signs EnvCloak; its Team ID becomes the pin. Default: the team behind this Mac's "Apple Development" identity. Needed by M3-07's pins and M3-10.
- Q3-02: whether the lane may create the bundle ids, register this Mac and make the two development profiles with the team's App Store Connect API key, or the founder does it in Xcode (about 10 minutes). Default: the lane does it and prints nothing secret. Needed by M3-10.
- Q3-03: a fourth concurrent session for two lane-C sub-lanes. Default: yes when the load guard allows; otherwise one session and the plan's slower marks.

## Manual QA script (skeleton; M3-21 fills it)

Run with `scripts/macos/qa-run.sh` on a clean macOS user account the founder creates, with a fingerprint enrolled (or the password path), the Apple Development build with both profiles in `/Applications`, and the fixtures `scripts/macos/qa-fixture.sh` makes (M1's `acme-web` and a second repository, `billing`). Steps that need no finger are scripted; the script stops and asks for each Touch ID step. Every step records its result, the macOS build and the commit; a step not run is reported as not run, never as passed.

| Step | Gates | Result |
|---|---|---|
| A1 first launch, background item | R-M3-08 | not run |
| A2 vault, projects, unlock in Terminal | M1 S1 | not run |
| A3 add Touch ID, approved once in Terminal | R-M3-21 | not run |
| A4 unlock with Touch ID, twice | g2, g3 | not run |
| A5 paste sheet, bindings, undo | R-M3-05, R-M3-F1 | not run |
| A6 an agent's request, the notification | | not run |
| A7 approve with Touch ID, twice | g3, gate 8 | not run |
| A8 cancel, deny, auto-deny | gate 32 | not run |
| A9 replace and remove with Touch ID | SPEC §10b | not run |
| A10 reveal and copy, the 30-second clear | g6 | not run |
| A11 Activity, verify log | gate 33 | not run |
| A12 screen lock | g7 | not run |
| A13 rollback | g5 | not run |
| A14 forged app peers, and the genuine app run by the fixture agent (every request but `app.lock` refused) | g4, gates 22 and 23 | not run |
| A15 a forged daemon | g1, gate 21 | not run |
| A16 `envcloak reveal` from a person and an agent | R-M3-30 | not run |
| A17 `envcloak add --ask` from an agent | R-M3-26 | not run |
| A18 first-run scan screen | R-M3-38 | not run |
| A19 menu bar search, revoke, lock | | not run |
| A20 the canary sweep | gate 12 | not run |

The founder's Touch ID subset (A3, A4, A7, A8's cancel, A9 and A10's Touch ID parts, about 15 minutes) runs first at EU-2 on the founder's own account, then again in full at M3-21 on the clean account.
