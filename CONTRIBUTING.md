# Contributing to EnvCloak

Thanks for helping. EnvCloak guards other people's credentials, so we hold every change to a high bar, and we try hard to make that bar easy to meet.

## The fastest way to contribute: add a provider

Every provider EnvCloak knows about is one TOML file in [`providers/`](providers/). A provider file teaches EnvCloak how to recognise a key by its prefix, where its docs, billing and key pages are, which hosts the key may be sent to in proxy mode, and (optionally) how to read balance, spend and expiry. See the format in [docs/SPEC.md](docs/SPEC.md#8-dashboard-balance-spend-expiry). Most providers take ten minutes.

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
- `scripts/check-unsafe.sh` and `scripts/check-expose-lint.sh`
- New behaviour has tests. Anything that touches secret handling has a test proving the value does not leak (to output, logs, errors or panics).
- User-facing changes update the docs.

## Rules for code that handles secrets

1. Secret values live in `SecretBytes` or `SecretBuf` (`envcloak-core`) and are never `Debug`- or `Display`-printed. Only files listed in [`security/expose-allowlist.txt`](security/expose-allowlist.txt) may call `expose_secret`; clippy enforces it, and adding a file needs review.
2. Errors never include secret values.
3. No new cryptography. Use the crates listed in the spec.
4. `unsafe` is denied workspace-wide. It is allowed only in `crates/envcloak-sys` (`scripts/check-unsafe.sh` enforces this), and every `unsafe` block there needs a `// SAFETY:` comment (clippy `undocumented_unsafe_blocks`).
5. Never allow `warnings`, `clippy::all` or `clippy::style`, in source or in the workspace lint tables, and never set rustflags in a cargo config: each of these also silences the `expose_secret` lint. Allow the specific lint you need instead. `scripts/check-unsafe.sh` enforces this.
6. Tests never contain real or key-shaped secrets. Generate fixture values at test time with `envcloak-testkit` (`canaries`), and check outputs with its canary sweep. Start processes from tests through `TestHome::apply`, which clears the environment, so nothing exported in your shell reaches a child or a core file it leaves.

## Reporting security issues

Never in a public issue. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are dual-licensed under MIT OR Apache-2.0, like the rest of the project.
