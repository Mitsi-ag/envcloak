# EnvCloak: the macOS app

Status: M3, written by task M3-01 as the contract the M3 tasks build to. Each part names the task that builds it, and changes from "planned" to a description of what exists only in the commit that lands it, with its test (claims match evidence). Task M3-02 built the toolchain settings, the bundle layout, the design tokens, the logging rule, the build, signing and check scripts and the CI job below; the rest is still planned. The decisions are the M3 plan's (`D3-nn`); SPEC §12 is the source of truth for what the app is, and SPEC §4.3 and §4.4 for what it may ask of the daemon.

## Toolchain and floor

- SwiftUI, Swift 6 with strict concurrency and warnings as errors, macOS 26 or later (SPEC §12, D3-04). Every Liquid Glass API is macOS 26 or later. `apps/macos/Config/Base.xcconfig` sets these for every target of the project (`SWIFT_VERSION = 6.0`, `SWIFT_STRICT_CONCURRENCY = complete`, `SWIFT_TREAT_WARNINGS_AS_ERRORS = YES`, `MACOSX_DEPLOYMENT_TARGET = 26.0`, the hardened runtime, and no base entitlements in Release), and the packages declare `.macOS(.v26)` with tools version 6.2, so Swift 6 mode.
- Xcode builds a local package as a dependency with its warnings suppressed (`-suppress-warnings`), and a package that asks for warnings as errors itself then fails to build in the app ("conflicting options", measured with Xcode 26.6). So the package manifests set no warning flags; every scripted build (`build-app.sh`, the CI job) passes `SWIFT_SUPPRESS_WARNINGS=NO SWIFT_TREAT_WARNINGS_AS_ERRORS=YES` to xcodebuild, which holds the packages to the same bar as the app.
- Built with Xcode 26.6 (17F113), on the founder's Mac (macOS 26.4.1) and on GitHub's `macos-26` arm64 runner, which has it as its default and no Xcode 27. CI selects `/Applications/Xcode_26.6.app` by path and fails when it is missing.
- The few macOS 27 SDK APIs the design names sit behind `#if compiler(>=6.4)` (Swift 6.4 ships with Xcode 27) with their macOS 26 fallbacks; the lane moves to Xcode 27 when both the build Mac and the runner image have it.

## Bundle layout (M3-02; the login item M3-18)

```
EnvCloak.app/                                   ai.envcloak.app
  Contents/MacOS/EnvCloakApp                    the app
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

The app's executable is `EnvCloakApp`, not `EnvCloak` (the target sets `EXECUTABLE_NAME`; the bundle, its name and its identifier are unchanged). On the default APFS volume, which is case-insensitive, `Contents/MacOS/EnvCloak` and `Contents/MacOS/envcloak` are one file: the first build of this layout copied the CLI over the app, and sign-check refused the bundle (measured on macOS 26.4.1; the GitHub runner's volume is case-insensitive too). sign-check also refuses two names in one directory that differ only in case, so a bundle built on a case-sensitive volume cannot carry the clash to a Mac.

The bundled `ai.envcloak.agent.plist` starts the helper's `envcloakd --foreground` with the same launchd settings as the CLI's LaunchAgent (`packaging/launchd/`): restart only after a crash, umask 077, no core files, and `AssociatedBundleIdentifiers` naming the app for Login Items. It has no log path, because launchd expands no `~` (M3-18 decides where the helper's log goes when it registers the plist).

Source layout: `apps/macos/EnvCloak.xcodeproj` with the targets `EnvCloak`, `EnvCloakAgent` (the helper wrapper), `EnvCloakTests`, `EnvCloakUITests` and `EnvCloakHardwareTests` (in no CI scheme); the local packages `apps/macos/Packages/EnvCloakKit` (the Swift client, D3-03) and `apps/macos/Packages/EnvCloakDesign` (the brand tokens); `apps/macos/Config/{Base,Signing-Adhoc,Signing-Development,Signing-CI}.xcconfig`; scripts under `scripts/macos/`. `apps/macos/` and `scripts/macos/` are code-owned (.github/CODEOWNERS), which binds once main's branch protection requires code-owner review (a repository admin's setting; not set when M3-01 landed).

As built by M3-02:

- The targets' sources are folders Xcode keeps in step with the disk (`EnvCloak/`, `EnvCloakTests/`, `EnvCloakUITests/`, `EnvCloakHardwareTests/`), so a later task adds a Swift file without editing the project. Info.plists, entitlements and the LaunchAgent plist live in `apps/macos/Support/`, outside them. The shared schemes are `EnvCloak` (builds the app, tests `EnvCloakTests`), `EnvCloakUITests` and `EnvCloakHardwareTests`.
- `EnvCloakAgent` is a bundle target with no code: Xcode makes `EnvCloakAgent.app` with its Info.plist (`CFBundleExecutable` `envcloakd`, `LSBackgroundOnly`), unsigned, and `build-app.sh` puts it in `Contents/Helpers/` with the Rust daemon inside. An Xcode build of the app alone (for its tests) has no helper and no CLI; only `build-app.sh` makes the bundle above.
- `EnvCloakTests` runs inside the launched app (its test host): the bundle identifier and floor, the main window on screen, no side-door key in the running app's Info.plist (with a positive control per key), and the brand resources bundled. `EnvCloakUITests` launches the app, finds the main window and opens About from the app menu. `EnvCloakHardwareTests` holds one test that reports itself skipped until M3-10.
- The placeholder main window shows the mark and says that projects and keys arrive in a later build; About shows the version, "Daemon identity: not checked in this build", the bundled font's licence and that the guarantees table arrives later (M3-17 builds the real one, SPEC §1.1).

## The Swift client (M3-03)

`EnvCloakKit` speaks the protocol of docs/IPC.md itself: 4-byte big-endian frames of at most 1 MiB, JSON-RPC 2.0 with `u64` ids and unknown fields refused, padded base64 values decoded straight into a `SecretBuffer`, fixed error tokens, and the client's peer checks before the first byte is sent (gates 20 and 21). No Rust is linked into the app: an FFI crate would need `unsafe` outside `envcloak-sys` (SPEC §5 "Process hardening"). Both sides stay equal through vectors written at test time: framing, base64 and escaping (Rust and a Python oracle), the canonical statement (`crates/envcloak-policy/tests/oracles/statement.py`, the Rust encoder and the Swift one), and HPKE (CryptoKit and the Rust `hpke` crate, SPEC §11).

The P-256 signatures the app makes with its Secure Enclave key, and the daemon verifies with `p256` (SPEC §10b's signed proofs), get an independent signature-format gate when M3-09 lands the daemon's verifier and M3-11 the app's `ApprovalSigner`: an independently compiled consumer on the other side of each, so that a test in which both sides share a fault cannot pass. Three single changes must each fail it while a paired control on the same keys and bytes still passes: the statement's SHA-256 signed as `Data(digest)`, which CryptoKit hashes again, instead of as the typed `Digest`; the daemon's own digest checked with the plain verifier, which hashes again, instead of the prehash verifier; and a DER signature where the protocol carries the raw 64-byte `r || s`. Each of these faults makes every valid proof fail between CryptoKit and the Rust verifier.

The app never waits on an open connection: it polls `status` once a second, each call on its own connection, at most two open at once (D3-09).

Every string the daemon sends reaches a view escaped (M3 plan §5 rule 4). The rule M3-02's `check-swift.sh` enforces for this (`daemon-text`) expects the client to hold such text as a `DaemonText`, whose escaped form (`Escape.display`) is what views show and whose raw form, `.unescaped`, only the files listed for `daemon-text` in `apps/macos/security/check-swift-allowlist.txt` read. M3-03 defines the type to that contract; until it does, nothing in the tree reads `.unescaped`.

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

That guard holds only if the way the app was started gives it no input. `open` sets the started app's arguments, environment and standard streams (`--args`, `--env`, `--stdin`, `--stdout`, `--stderr`; `man open` on macOS 26.4.1), and `launchctl submit` sets a job's arguments and environment. So a release build of the app reads no launch argument, environment variable or standard stream to choose a socket, a daemon, a vault or an action: it finds the user's home directory from the user database (`getpwuid_r` for its own uid), never from `$HOME` or an `XDG_*` variable, and builds the socket path of SPEC §4.2 from it. A test-only override, if M3-03 needs one, exists only in the `Signing-CI` configuration, and `scripts/macos/sign-check.sh` refuses a release artifact that holds it, as the release-feature test does for the `testing` pins.

As built by M3-02, `scripts/macos/check-swift.sh` (rule `launch-input`) refuses in the app's product sources, outside the entries of `apps/macos/security/check-swift-allowlist.txt` (each with its reason): `CommandLine`, any `.arguments`, any `.environment` that is not SwiftUI's `.environment(...)` modifier, `getenv`, `environ`, `_NSGetArgv`, `_NSGetArgc`, `_NSGetEnviron`, the standard input (`standardInput`, `readLine`, `stdin`), and `UserDefaults` and `@AppStorage`: a launch argument `-key value` lands in the defaults' argument domain, so `open --args -socket /elsewhere` would set what `UserDefaults.standard.string(forKey: "socket")` returns (measured with a probe program on macOS 26.4.1). Two measurements on the same Mac bound what the rule needs to cover: Foundation's home and temporary directories ignore the environment (`NSHomeDirectory()`, `homeDirectoryForCurrentUser`, `URL.homeDirectory`, `~` expansion, the Application Support lookup and `NSTemporaryDirectory()` all gave the user database's answers under `HOME=/tmp/fakehome TMPDIR=/tmp/faketmp/`), so they are not launch inputs; and the resource accessor SwiftPM generates for a package with resources reads `PACKAGE_RESOURCE_BUNDLE_PATH` from the environment in a Debug build only, which `sign-check.sh` refuses in any artifact (a Debug build's `EnvCloakApp.debug.dylib` holds it; the Release executable does not).

## Screen lock and session switch (M3-17)

The app reports a screen lock and a switch away from the login session with `app.lock` (`screen_lock`, `session_resign`; SPEC §5 "Lock"), which no client can call. M3-17 picks the signal on macOS 26 and 27 (plan K3-04) among `NSWorkspace.screensDidSleepNotification`, `NSWorkspace.sessionDidResignActiveNotification` and the undocumented `com.apple.screenIsLocked` distributed notification, and records here which one, with the evidence, and whether another program running as the user can post it. Any such program can post a distributed notification, so if the app listens for one, a program can make it lock the vault early with that reason. Locking only tightens: what such a program changes is the recorded reason, never what a grant reaches. Not chosen yet.

## Logging (M3-02)

The app logs only through `Logger` under the subsystem `ai.envcloak.app` (`ECLog` in EnvCloakKit), and a log message interpolates nothing but a `LogToken`: a word from an `enum`'s raw values, written in the source. `Logger` keeps interpolated values private by default (SPEC §5 "Logging"), but that is not a boundary against whoever starts the app: measured on macOS 26.4.1, a program that logs a value with the default privacy shows `<private>` in `log show` when run plainly, and the value itself when its environment holds `OS_ACTIVITY_DT_MODE=YES`, which `open --env`, `launchctl submit` and `xcodebuild test` can all set (xcodebuild's test runs showed the value even in the process's own `OSLogStore`). So `check-swift.sh` (rule `log`) refuses any other interpolation in a log call, `privacy: .public` on anything but `x.logToken`, `%{public}` in any string, a `LogToken` conformance on anything but an `enum`, a `logToken` declared outside `EnvCloakKit/Log/LogToken.swift`, and `print`, `debugPrint`, `dump`, `NSLog` and the C stdio writers. For the same reason the log sweeps of M3-06 and M3-21 (A20) run the app as a person starts it, and once more with `OS_ACTIVITY_DT_MODE=YES`, never under xcodebuild.

## Design tokens (M3-02)

`EnvCloakDesign` holds the colours below as named colours in `Resources/Colors.xcassets`, each with a light, a dark and an Increase Contrast value in both appearances, and views take them as `ECToken.<name>.color` (`check-swift.sh`, rule `color`, refuses any other colour in the app). The values are docs/BRAND.md §3's; EnvCloakDesign's tests read this table, check every value against BRAND.md, resolve each token in light and dark as the app does, and read all four renditions of each (Increase Contrast included) from the compiled asset catalog with `assetutil` (an `NSAppearance` named for Increase Contrast resolves as plain Aqua while the system setting is off, measured on macOS 26.4.1, so a test cannot ask for those values the way the app gets them). Controls keep the system accent colour (BRAND §3).

| Token | Light | Dark | Increase Contrast | Use |
|---|---|---|---|---|
| `background` | `#F3F0E8` | `#111110` | the same | Window and sheet content, welcome and About |
| `raised` | `#FBFAF7` | `#1C1C1A` | the same | Code blocks, the value row, footers, the reveal field |
| `text` | `#111110` | `#F3F0E8` | the same | Body text and marks |
| `secondary` | `#5E5B54` | `#A9A59C` | `text` | Captions and metadata |
| `rule` | `#D9D4C7` | `#2E2D2A` | `secondary` | Decorative dividers only, never a control's only edge |
| `success` | `#1E6B3A` | `#4FC27E` | the same | With `checkmark.circle` and a word |
| `warning` | `#9A4A00` | `#FF8C42` | the same | With `exclamationmark.triangle` and a word |
| `danger` | `#B42318` | `#FF6B61` | the same | With `xmark.octagon` and a word; real failures only |
| `info` | `#1D5A9E` | `#6EA8FE` | the same | With `info.circle` and a word |
| `amber` | `#FFB000` | `#FFB000` | the same | The held value, only on Ink (`plate`, or the dark appearance) |
| `plate` | `#111110` | `#0B0B0A` | the same | The approval mark's plate |

Type: Martian Mono, the variable font `MartianMono[wdth,wght].ttf` from google/fonts (commit `c8bba5c4a69195e4fabc69d75136814c65fe0cf5`, SHA-256 `c3467843ec1c2574b05fbcfd7147c7bfbcf63ddca8fc2bcb9d117f1bfb1b22e7`), bundled as `Resources/Fonts/MartianMono.ttf` with its licence beside it and registered for the process at launch (`ECFonts`); `ECFont.martianMono(size:weight:width:)` comes from the motion file. Motion: `assets/brand/motion/swiftui/EnvCloakMotion.swift`, which `Sources/EnvCloakDesign/EnvCloakMotion.swift` links to rather than copies (§5 rule 5 of the M3 plan). The icon is `assets/brand/icon/EnvCloak.icon`, referenced from the project, never copied, and the menu bar template is the `EnvCloakMenuTemplate` image, whose asset links to `assets/brand/icon/menubar/EnvCloakMenuTemplate.svg`. The font's licence is a copy (a link would ship as a dangling link in the bundle), and a test keeps it byte for byte equal to `assets/brand/fonts/MartianMono-OFL.txt`.

## Build commands

| Command | Task | What it does |
|---|---|---|
| `scripts/macos/build-app.sh [--sign adhoc\|development\|ci] [--install]` | M3-02, M3-06 | Built (M3-02): `cargo build --release --locked` of `envcloak` and `envcloakd`, located from cargo's own report; `xcodebuild` (Release, the Rust host's architecture, Xcode's signing off, the tier's `Signing-*.xcconfig`, the CLI's version as the bundle's); the helper wrapper and both binaries copied in; the helper, then the CLI, then the app signed with the hardened runtime, each with its own identifier and entitlements file from `apps/macos/Support/`; `sign-check.sh`, and the bundle's and the helper's versions equal to the CLI's; only then the previous build at the output path is replaced. `--install` copies to `/Applications` (or `--install-dir`), checks the copy, then swaps it in, and says that a running background process was not restarted: restarting it when its version changed is M3-06's. `--sign ci` needs `ENVCLOAK_CI_IDENTITY` (M3-07) and refuses to run without it |
| `scripts/macos/sign-check.sh [--facts] EnvCloak.app` | M3-02 | Built: exactly the three executables, found by content or execute bit whatever their names; each signed with its own identifier, the runtime bit read from the code directory's flags as a number, and none of `get-task-allow`, any `com.apple.security.cs.` key or any `temporary-exception` key in its parsed entitlements, whatever the key's value; `codesign --verify --strict --deep` for the whole bundle (an outer signature made before an inner change fails it); no symbolic link and no two names that differ only in case; the app's and helper's Info.plists, the helper background-only, no side-door key in any Info.plist; the LaunchAgent plist's label and `BundleProgram`; one set of architectures; no Debug resource override. From M3-18 also no quarantine attribute on the bundled plist |
| `scripts/macos/check-swift.sh [--root DIR] [--list-swift]` | M3-02 | Built: the lane-C Swift rules, read with a Swift lexer (comments and string contents never count as code; interpolations do): `unsafe-bytes`, `storage`, `launch-input`, `side-door`, `a11y-action`, `gated-key`, `log`, `daemon-text` (a `DaemonText`'s raw `.unescaped` text, M3-03, read only where allowed), `color`, `remote-package`, `entitlement`, `key-literal` (provider key patterns, in every text file), `symlink`, `stray-swift`, `lex`, `allowlist`. The rules and their limits are documented in `scripts/macos/check_swift.py` |
| `scripts/check-sources.sh --swift <derived data>` | M3-02 | Built: every Swift file an xcodebuild of the app compiled is one `check-swift.sh` reads, or SwiftPM's or Xcode's generated package accessor in the build's own `DerivedSources/` |
| `scripts/macos/ci-identity.sh` | M3-07 | the CI identity in a temporary keychain, and test fixtures signed with it |
| `scripts/macos/profiles.sh` | M3-10 | the bundle ids, this Mac's registration and the two development profiles, from the team's App Store Connect API key; prints no key material (Q3-02) |
| `scripts/macos/hardware-tests.sh` | M3-10 | `EnvCloakHardwareTests` on the founder's Mac (Secure Enclave, keychain group, `SMAppService`), each skip reported as a skip with the macOS build |

The scripts' own tests (M3-02): `scripts/macos/tests/test_check_swift.py` writes a clean tree and one fixture per refusal at run time (the key-literal fixture needs a key-shaped string, which is never committed), with negative controls that must pass; `scripts/macos/tests/test_sign_check.py` builds bundles from tiny programs signed with the real `codesign`, one property changed per refusal, and confirms each fixture's property with an independent reader, `oracles/codesign_facts.swift` (the Security framework's `SecStaticCode`), before the refusal counts; with `--app` it checks a built app with both readers and with a third, the bundled CLI's own report of its kernel code-signing flags (`envcloak internal hardening`). `scripts/macos/tests/test_project_settings.py` reads every target's settings as xcodebuild resolves them, in Debug and Release: Swift 6, complete strict concurrency, warnings as errors, macOS 26, the hardened runtime and no base entitlements in Release on what ships, ad hoc by default, and the layout's identifiers and executable names.

## CI: the `macos-app` job (M3-02)

One job on `macos-26` with `/Applications/Xcode_26.6.app` selected by path (it fails when the runner lacks it). On a pull request it runs when `apps/macos/`, `scripts/macos/`, `crates/envcloak-{ipc,daemon,sys,core}/`, `crates/envcloak-cli/src/cmd/{ref_,add,approve*,status}.rs`, `assets/brand/` (the app links the brand's motion file, icon and menu template), `scripts/check-sources.sh`, `scripts/ci-paths.py` or the workflow change (`scripts/ci-paths.py` answers `app`); on main, nightly and manual runs it always runs. It runs `check-swift.sh` and its tests, the project-settings test, the sign-check fixture tests, the two packages' tests, `build-app.sh` (ad hoc), the built-app checks, an install into a temporary directory, the hosted `EnvCloakTests`, `check-sources.sh --swift` over every build it made, and, on main, nightly and manual runs only, `EnvCloakUITests` (M3 plan K3-07). The runner enables UI automation without a password; this Mac asks for one, so a local run of the UI tests is reported as not run.

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
