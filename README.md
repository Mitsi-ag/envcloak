# EnvCloak

**Your AI agents use your API keys. They never see them.**

EnvCloak is a local-first, open-source secrets vault built for developers who work with AI coding agents: Claude Code, Codex, Cursor, Gemini CLI, OpenCode, and anything that reads `AGENTS.md`. It is a native macOS app plus a cross-platform CLI.

> Status: pre-alpha, under active development. Not ready for real secrets yet. Watch the repo for the first release.

## What each mode guarantees

The line above is fully true in proxy mode, for HTTPS APIs. In inject mode, EnvCloak keeps keys out of files, configs and what reaches the model, but the command you approve holds the key while it runs, and a key pasted into some agents can persist in their local history until `envcloak scrub` (§7.1). A feature that has not shipped is shown as unavailable, never implied.

| Guarantee | Proxy mode (M6+, HTTPS APIs; unavailable in this build) | Inject mode (`envcloak run`, M1+; available) | Sign-in mode (`request_sign_in`, M2b+; unavailable in this build) |
|---|---|---|---|
| Secret out of `.env` files, git, shell history, agent configs | Yes (unavailable until M6) | Yes | Yes (unavailable until M2b) |
| Secret out of agent context & transcripts | Yes (unavailable until M6) | Yes (with output redaction + hooks; if a key is pasted into a prompt before a hook runs or into an agent that persists blocked prompts, `envcloak scrub` removes it; §7.1) | Yes (unavailable until M2b: username, password and TOTP stay in the sign-in worker; delivered browser state stays in the hosted browser context) |
| Secret out of command output shown to the agent | Yes (unavailable until M6) | Best-effort (streaming redaction; §4.5) | Yes (unavailable until M2b: tool responses and screenshots are scrubbed and origin-restricted; §6.8) |
| Secret out of the child process's memory & `/proc/<pid>/environ` | **Yes** (unavailable until M6: child gets a short-lived capability token) | **No** (child receives the real secret in `environ` for the duration of the command) | **Yes for credentials** (unavailable until M2b: never enter the agent or its child processes; the browser worker holds the delivered session only while the grant is live) |
| Bound to allowed HTTP hosts & methods | **Yes** (unavailable until M6) | **No** (once injected, the child can send it anywhere) | **Yes** (unavailable until M2b: bound to the target's allowed login and app origins; §6.8) |
| Per-request audit & instant revocation mid-run | **Yes** (unavailable until M6) | **No** (revocation kills the child process) | **Yes** (unavailable until M2b: each browser tool call is checked against the grant; revoking closes the browser context) |
| Works with any tool or SDK | HTTPS clients that honour `HTTPS_PROXY` / base-URL overrides, or wrap with `envcloak run --proxy` (unavailable until M6) | **Every** CLI, SDK, database driver and binary | Web apps driven through EnvCloak's hosted browser tools (Playwright-backed; §6.8; unavailable until M2b) |

## Why

- Agents read `.env` files, echo variables while debugging, and store every turn in local transcripts. Keys leak without anyone doing anything wrong.
- Keys end up scattered across dozens of repos, dotfiles, MCP configs and dashboards, bought under different accounts, with no idea which is which.
- Balance, spend and expiry live in fifty different provider dashboards.

## What it does

- **Run with secrets, never show them.** `envcloak run -- npm test` injects the project's keys into the process and redacts them (and their base64, hex and URL-encoded forms) from everything the command prints.
- **Proxy mode (unavailable in this build; M6).** The agent's process gets worthless placeholders; a local proxy swaps in the real key only for the provider's own hosts.
- **Touch ID approvals.** "Claude Code wants to run `npm test` in acme-web with OPENAI_API_KEY." One tap, scoped to that project and session.
- **Agent-native.** `envcloak agents install` teaches Claude Code, Codex, Cursor and friends how to use it: instructions, hooks that stop `.env` reads and pasted keys, rules, and an MCP server that never returns values. `run_with_secrets` starts a child `envcloak run`; commands it starts run outside the agent host's sandbox, as every MCP server does.
- **One place for every key.** Group by project, provider or account email. Docs, billing and key pages one click away.
- **Balance, spend and expiry (unavailable in this build; M4).** A dashboard that polls providers and warns before a key runs dry or expires.
- **Leak doctor.** Finds keys sitting in `.env` files, shell profiles, MCP configs and past agent transcripts, and tells you which ones to rotate; `envcloak scrub` removes them from local transcripts and history.
- **Move machines in one step (unavailable in this build; M5).** Pair a new laptop with a short code; the vault travels end-to-end encrypted, peer to peer.
- **No account, no cloud.** Everything stays on your machines.

## Agent coverage (`integrations/compat/matrix.toml`)

Every surface state reported by `envcloak agents status` is backed by the probes in [`integrations/compat/matrix.toml`](integrations/compat/matrix.toml) and [docs/COMPAT.md](docs/COMPAT.md):

| Host | Version | OS | `prompt_to_model` | `transcript` | `file_read` | `shell` | `mcp` | `output` | `envcloak_server` |
|---|---|---|---|---|---|---|---|---|---|
| `claude-code` | `2.1.280` | `macos`, `linux` | `degraded` (`fails_open_on_timeout`, `workspace_untrusted`) | `unsupported` (`persists_blocked_prompt`) | `degraded` (`fails_open_on_timeout`, `workspace_untrusted`) | `degraded` (`fails_open_on_timeout`, `workspace_untrusted`) | `degraded` (`fails_open_on_timeout`, `workspace_untrusted`) | `active` | `needs_host_approval`; `outside_host_sandbox` |
| `codex` | `0.159.2` | `macos` | `degraded` (`fails_open_on_timeout`, `hooks_untrusted`) | `degraded` (`fails_open_on_timeout`, `hooks_untrusted`) | `degraded` (`fails_open_on_timeout`, `hooks_untrusted`) | `degraded` (`fails_open_on_timeout`, `hooks_untrusted`) | `degraded` (`fails_open_on_timeout`, `hooks_untrusted`) | `active` | `needs_host_approval`; `outside_host_sandbox` |
| `codex` | `0.159.2` | `linux` | `degraded` (`fails_open_on_timeout`, `hooks_untrusted`) | `degraded` (`fails_open_on_timeout`, `hooks_untrusted`) | `degraded` (`fails_open_on_timeout`, `hooks_untrusted`) | `unsupported` (`sandbox_blocks_socket`) | `degraded` (`fails_open_on_timeout`, `hooks_untrusted`) | `active` | `needs_host_approval`; `outside_host_sandbox` |
| Tier 2 & Tier 3 (`cursor`, `gemini-cli`, `copilot-cli`, `kimi`, `opencode`, `qwen-code`, `goose`, `aider`) | unprobed in CI | `macos`, `linux` | `unverified` (`not_probed`) | `unverified` (`not_probed`) | `unverified` (`not_probed`) | `unverified` (`not_probed`) | `unverified` (`not_probed`) | `unverified` (`not_probed`) | `listed` or `not_installed` |

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
How `envcloak mcp`, `envcloak mcp-bridge` and `envcloak agents migrate-mcp` serve and wrap MCP tools (and why commands that `run_with_secrets` starts run outside the agent host's sandbox) is in [docs/MCP.md](docs/MCP.md).
How `envcloak init` and `envcloak import` move `.env` files into the vault, and when they delete them, is in [docs/IMPORT.md](docs/IMPORT.md).
How `envcloak doctor` and `envcloak scrub` find and remove leaked keys across files, transcripts, shell history and Git history is in [docs/DOCTOR.md](docs/DOCTOR.md).
What `envcloak agents install` writes for Claude Code and Codex, what its hooks stop and what they do not see, is in [docs/INSTALLERS.md](docs/INSTALLERS.md) and [docs/COMPAT.md](docs/COMPAT.md). On Linux neither host's sandboxed shell can reach EnvCloak in this build, so no sandbox exception is written there: commands that need keys run through EnvCloak's MCP server or with the host's sandbox off. `envcloak agents status --probe` checks, on your machine and in a throwaway probe home, that the hooks act for the host version you have; it probes only the host versions EnvCloak's release was qualified against, and a host that updated since reads `not_qualified` until the next release qualifies it. It needs `envcloak-probe-model` and `envcloak-probe-mcp` beside `envcloak` (a source build has them; the macOS app does not ship them yet, so from the app it answers `probe_unavailable`), and it does not probe a host that has a system or managed configuration on the machine.
The brand (logo, app icon, colour, type, motion and voice) is in [docs/BRAND.md](docs/BRAND.md), and its files are in [assets/brand/](assets/brand/).

## Contributing

Provider adapters are the easiest place to start. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.

