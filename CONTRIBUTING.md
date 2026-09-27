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
- New behaviour has tests. Anything that touches secret handling has a test proving the value does not leak (to output, logs, errors or panics).
- User-facing changes update the docs.

## Rules for code that handles secrets

1. Secret values live in `secrecy`/`zeroize` types and are never `Debug`- or `Display`-printed.
2. Errors never include secret values.
3. No new cryptography. Use the crates listed in the spec.
4. `unsafe` is denied workspace-wide; exceptions need a written justification and a maintainer's review.

## Reporting security issues

Never in a public issue. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are dual-licensed under MIT OR Apache-2.0, like the rest of the project.
