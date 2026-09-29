# Contributing to EnvCloak

Thanks for helping. EnvCloak guards other people's credentials, so we hold every change to a high bar, and we try hard to make that bar easy to meet.

## The fastest way to contribute: add a provider

Every provider EnvCloak knows about is one TOML file in [`providers/`](providers/). A provider file teaches EnvCloak how to recognise a key by its prefix, where its docs, billing and key pages are, which hosts the key may be sent to in proxy mode, and (optionally) how to read balance, spend and expiry. The format and the rules the loader enforces are in [docs/PROVIDERS.md](docs/PROVIDERS.md); after editing `providers/`, run `python3 scripts/gen-providers.py`, which compiles the files into the release. Most providers take ten minutes.

## Development setup

```sh
git clone https://github.com/Mitsi-ag/envcloak
cd envcloak
cargo test --workspace
```

The macOS app lives in `apps/macos/` and needs Xcode 16 or later.

## Before you open a pull request

- `cargo fmt --all`
- `cargo clippy --workspace --all-targets` with no warnings
- `cargo test --workspace`
- `cargo clippy --release` with no warnings (the shipped configuration)
- `scripts/check-unsafe.sh`, `scripts/check-sources.sh`, `scripts/check-unsafe-lint.sh` and `scripts/check-expose-lint.sh` (all but the last need `python3`, and the first needs 3.11 or later)
- New behaviour has tests. Anything that touches secret handling has a test proving the value does not leak (to output, logs, errors or panics).
- User-facing changes update the docs.

## Rules for code that handles secrets

1. Secret values live in `SecretBytes` or `SecretBuf` (`envcloak-core`) and are never `Debug`- or `Display`-printed. Only files listed in [`security/expose-allowlist.txt`](security/expose-allowlist.txt) may call `expose_secret`, and adding a file needs review. Clippy enforces it in the configurations CI compiles; `scripts/check-unsafe.sh` refuses the names `expose_secret`, `expose_secret_mut`, `ExposeSecret` and `ExposeSecretMut` anywhere outside those files, whatever `cfg` the code sits under (only `security/lint-canary`, which opens secrets on purpose to prove the lint works, is exempt). Listed files may not define macros, which could carry a call into another file.
2. Errors never include secret values.
3. No new cryptography. Use the crates listed in the spec.
4. `unsafe` is forbidden workspace-wide, so the compiler rejects it and any `allow` of it. Only `crates/envcloak-sys` has its own lint tables, identical apart from `unsafe_code = "deny"`, and every `unsafe` block there needs a `// SAFETY:` comment (clippy `undocumented_unsafe_blocks`). `scripts/check-unsafe.sh` keeps the manifests that way, and `scripts/check-unsafe-lint.sh` proves the compiler enforces it.
5. Never allow `warnings`, `clippy::all` or `clippy::style`, in source or in the workspace lint tables: each of these can silence the `expose_secret` lint. Allow the specific lint you need instead. The tree also holds no cargo config, build scripts, proc-macro crates, `include!`, `#[path]` or `clippy` cfg (`cfg(not(clippy))` hides code from the lint), each of which can change lint levels or compile code the checks never read. `scripts/check-unsafe.sh` enforces this from the source text. Because a macro can assemble `#[path]` or `include!` from pieces no text check sees, `scripts/check-sources.sh` also asks the compiler: in the configurations CI lints (every workspace target in the dev profile, and the shipped binaries in the release profile), every file rustc reads for a workspace crate must be a `.rs` file `check-unsafe.sh` scans, so `include_str!` and `include_bytes!` are refused as well, and every proc-macro crate compiled for the workspace must be listed in [`security/proc-macro-allowlist.txt`](security/proc-macro-allowlist.txt), which needs review like the expose allowlist. Code that only another target or feature compiles is not linted by clippy or read by `check-sources.sh`; there the text checks stand alone. They refuse the `expose_secret` names outside the allowlist and every lint attribute, `#[path]`, `include!` and `clippy` cfg they can see, but not what a macro assembles from pieces.
6. Tests never contain real or key-shaped secrets. Generate fixture values at test time with `envcloak-testkit` (`canaries`), and check outputs with its canary sweep. Start processes from tests through `TestHome::apply`, which clears the environment, so nothing exported in your shell reaches a child or a core file it leaves.

## Reporting security issues

Never in a public issue. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are dual-licensed under MIT OR Apache-2.0, like the rest of the project.
