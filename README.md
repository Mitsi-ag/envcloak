# EnvCloak

**Your AI agents use your API keys. They never see them.**

EnvCloak is a local-first, open-source secrets vault built for developers who work with AI coding agents: Claude Code, Codex, Cursor, Gemini CLI, OpenCode, and anything that reads `AGENTS.md`. It is a native macOS app plus a cross-platform CLI.

> Status: pre-alpha, under active development. Not ready for real secrets yet. Watch the repo for the first release.

## Why

- Agents read `.env` files, echo variables while debugging, and store every turn in local transcripts. Keys leak without anyone doing anything wrong.
- Keys end up scattered across dozens of repos, dotfiles, MCP configs and dashboards, bought under different accounts, with no idea which is which.
- Balance, spend and expiry live in fifty different provider dashboards.

## What it does

- **Run with secrets, never show them.** `envcloak run -- npm test` injects the project's keys into the process and redacts them (and their base64, hex and URL-encoded forms) from everything the command prints.
- **Proxy mode.** The agent's process gets worthless placeholders; a local proxy swaps in the real key only for the provider's own hosts.
- **Touch ID approvals.** "Claude Code wants to run `npm test` in acme-web with OPENAI_API_KEY." One tap, scoped to that project and session.
- **Agent-native.** `envcloak agents install` teaches Claude Code, Codex, Cursor and friends how to use it: instructions, hooks that stop `.env` reads and pasted keys, rules, and an MCP server that never returns values.
- **One place for every key.** Group by project, provider or account email. Docs, billing and key pages one click away.
- **Balance, spend and expiry.** A dashboard that polls providers and warns before a key runs dry or expires.
- **Leak doctor.** Finds keys sitting in `.env` files, shell profiles, MCP configs and past agent transcripts, and tells you which ones to rotate.
- **Move machines in one step.** Pair a new laptop with a short code; the vault travels end-to-end encrypted, peer to peer.
- **No account, no cloud.** Everything stays on your machines.

## Quick look

```sh
envcloak init                          # turn this repo's .env into references
envcloak add openai --ask              # paste a key into the app, not into chat
envcloak run -- npm run dev            # keys injected, output redacted
envcloak agents install --global       # teach every installed agent the rules
envcloak doctor                        # find keys that already leaked
```

`envcloak.toml` lives in your repo and contains references only:

```toml
[env]
OPENAI_API_KEY = "openai/work"
STRIPE_SECRET_KEY = "stripe/acme-live"
```

## Design

The full product and architecture spec, including the threat model, is in [docs/SPEC.md](docs/SPEC.md).
The vault's byte formats and key derivations are in [docs/CRYPTO.md](docs/CRYPTO.md), and its storage format in [docs/VAULT.md](docs/VAULT.md).
Project manifests and env files are in [docs/MANIFEST.md](docs/MANIFEST.md), and the provider registry in [docs/PROVIDERS.md](docs/PROVIDERS.md).
The daemon protocol, socket checks and lock rules are in [docs/IPC.md](docs/IPC.md), the caller evidence in [docs/AGENTS.md](docs/AGENTS.md), and grants and approvals in [docs/GRANTS.md](docs/GRANTS.md).
How `envcloak run` releases, injects and redacts values, and handles signals and exit codes, is in [docs/RUN.md](docs/RUN.md).
How `envcloak init` and `envcloak import` move `.env` files into the vault, and when they delete them, is in [docs/IMPORT.md](docs/IMPORT.md).
What `envcloak agents install` writes for Claude Code and Codex, what its hooks stop and what they do not see, is in [docs/INSTALLERS.md](docs/INSTALLERS.md). On Linux neither host's sandboxed shell can reach EnvCloak in this build, so no sandbox exception is written there: commands that need keys run through EnvCloak's MCP server or with the host's sandbox off. `envcloak agents status --probe` checks, on your machine and in a throwaway probe home, that the hooks act for the host version you have; it probes only the host versions EnvCloak's release was qualified against, and a host that updated since reads `not_qualified` until the next release qualifies it.
The brand (logo, app icon, colour, type, motion and voice) is in [docs/BRAND.md](docs/BRAND.md), and its files are in [assets/brand/](assets/brand/).

## Contributing

Provider adapters are the easiest place to start. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.
