# EnvCloak: product and architecture spec

Status: draft v0.1 (2026-09-27). This document is the source of truth for what EnvCloak is and how it is built. Changes go through a PR that edits this file.

## 1. One line

Your AI agents use your API keys. They never see them.

EnvCloak is a local-first, open-source secrets vault for developers who work with AI coding agents (Claude Code, Codex, Cursor, Gemini CLI, OpenCode, and anything that reads AGENTS.md). It ships as a native macOS app plus a cross-platform CLI and daemon.

## 2. The problem

1. **Agents leak keys.** Plaintext `.env` files, shell profiles that export keys, and MCP configs with literal tokens all end up inside agent context. Agents `cat .env`, echo variables while debugging, or paste keys into commands. Every one of those turns is stored in local transcripts (for example `~/.claude/projects/**/*.jsonl` and `~/.codex/sessions/**`), and often in provider logs too. A scan of one working developer machine found key-shaped strings in well over a hundred transcript files, including live payment, cloud and source-control credentials.
2. **Keys are scattered.** A solo developer with dozens of projects has keys spread across per-repo `.env` files, a shared dotfile, MCP configs, hosting dashboards and cloud parameter stores. The same provider is often bought under several accounts (different emails), and nobody knows which key belongs to which account.
3. **There is no single view of cost and health.** Balance, spend, plan, expiry and docs for each key live in fifty different dashboards.
4. **Moving machines is painful.** A new laptop means copying `.env` files over chat or USB.

Existing tools solve slices: 1Password (GUI, `op run`, masking) is paid and not agent-native; Infisical and Doppler are cloud-first web dashboards without output masking; Varlock adds redaction but no store or GUI; Infisical Agent Vault proxies HTTP credentials but has no vault UI or spend view. Nobody combines a local vault, a native GUI, agent-native guardrails, a spend and expiry dashboard, and peer-to-peer device transfer in one open-source tool.

## 3. Principles

1. **Local-first, no account.** The vault lives on your machine, encrypted. No EnvCloak cloud, no sign-up. Sync is device to device.
2. **Capability, not secrets.** Agents get the ability to run a command with a key, not the key. Injection at exec time, streaming redaction of output, and a proxy mode where the agent's process never holds the real value at all.
3. **Human in the loop, cheaply.** One Touch ID tap approves an agent for a project for a session. Scopes are per project, per agent, per time window.
4. **Everything is audited.** Every secret access is recorded in a tamper-evident log: which key, which project, which command, which agent, which decision.
5. **Agent-native by default.** One command teaches every installed agent how to use EnvCloak (instructions, hooks, rules, MCP). New projects inherit it automatically.
6. **Open and extensible.** Provider adapters (balance, spend, expiry, key patterns, allowed hosts) are declarative files the community can add in minutes.
7. **Boring, audited crypto.** No custom cryptography. Well-reviewed Rust crates only.

## 4. Components

| Component | Language | Role |
|---|---|---|
| `envcloak` | Rust | CLI used by humans and agents |
| `envcloakd` | Rust | Vault broker daemon; holds unlocked keys in memory; policy, approvals, audit, provider polling, sync |
| `EnvCloak.app` | Swift 6 / SwiftUI | macOS app: menu bar, main window, Touch ID and Secure Enclave, approvals, dashboard; bundles and supervises `envcloakd` |
| `envcloak mcp` | Rust | stdio MCP server; never returns secret values |
| Provider registry | TOML | `providers/*.toml`: key patterns, docs and billing links, allowed hosts, balance and usage endpoints |
| Agent integrations | files + Rust installers | Claude Code plugin (skill, hooks, MCP), Codex (AGENTS.md block, execpolicy rules, MCP), Cursor, Gemini CLI, OpenCode, generic AGENTS.md |

Linux gets the CLI and daemon (passphrase or Secret Service unlock, TTY approvals). A GUI for Linux and Windows is out of scope for v1.

### Rust workspace layout

```
crates/
  envcloak-core       vault format, crypto, data model, storage
  envcloak-policy     grants, approvals model, agent detection
  envcloak-redact     streaming multi-pattern redactor (values + encodings)
  envcloak-proxy      placeholder tokens + local TLS proxy (proxy mode)
  envcloak-providers  registry loader, key-pattern detection, balance/usage/expiry adapters
  envcloak-sync       pairing (PAKE), transport (iroh), replication
  envcloak-mcp        MCP server
  envcloak-agents     installers for Claude Code, Codex, Cursor, Gemini CLI, OpenCode, AGENTS.md
  envcloak-ipc        daemon protocol (JSON-RPC over Unix socket), shared types
  envcloak-cli        bin: envcloak
  envcloak-daemon     bin: envcloakd
apps/macos/           SwiftUI app (Xcode project), talks to envcloakd over the socket
providers/            *.toml provider definitions
integrations/         static files shipped to agents (skill, hooks, rules, snippets)
docs/                 this spec, security model, user docs (site source)
```

## 5. Data model

### Vault

A single vault per user at the platform data dir (`~/Library/Application Support/EnvCloak/` on macOS, `$XDG_DATA_HOME/envcloak/` on Linux).

- Storage: SQLite (rusqlite). Every row's payload is sealed with XChaCha20-Poly1305 under a vault key; the plaintext columns are only opaque ids, timestamps needed for sync ordering, and a keyed hash index. Associated data binds each ciphertext to its row id, table and field so ciphertexts cannot be swapped.
- Key hierarchy:
  - **Vault Master Key (VMK)**: random 256-bit. Never stored in plaintext.
  - **Wrapping**: the VMK is stored wrapped by one or more unlockers:
    - macOS app: a P-256 key in the Secure Enclave with a user-presence or biometry access control; the VMK is wrapped with ECIES to that key. Unwrapping requires Touch ID or the login password.
    - Recovery passphrase: Argon2id (memory-hard, parameters stored with the envelope) derives a key-encryption key. Shown once as a Recovery Kit.
    - Linux / headless: passphrase, or the OS keyring via Secret Service.
    - Paired devices: each device has its own X25519 identity; the VMK is shared to a new device inside the pairing channel and re-wrapped locally with that device's own unlockers.
  - Subkeys derived from the VMK with HKDF: `data` (row sealing), `index` (keyed BLAKE3 for value lookup and leak scanning), `audit` (log MAC chain), `sync` (replication envelopes).
- Memory hygiene: secrets live in `zeroize`-on-drop buffers, `mlock`ed where the OS allows; the daemon disables core dumps and denies debugger attach on macOS.

### Items

```
Secret {
  id: ULID
  slug: "openai/work"                 # human reference, unique
  title: "OpenAI (work account)"
  provider: "openai"                  # registry id, optional
  account: { email, label, org_id }   # who owns / pays for it
  fields: [{ name: "api_key", value: <sealed>, sensitive: true }]
  env_hint: "OPENAI_API_KEY"
  tags: [..]
  links: { docs, billing, keys_page, dashboard }   # defaulted from registry
  expires_at, rotated_at, created_at, last_used_at
  budget_monthly: Money?
  notes
}
```

Projects are not stored as owners of secrets. A project references secrets; many projects can reference one secret, so rotating a shared key is one edit. The vault keeps a project index (path, manifest hash, last seen) for the dashboard.

### Project manifest: `envcloak.toml` (committed to the repo)

```toml
[project]
name = "acme-web"

[env]                                  # default profile
OPENAI_API_KEY = "openai/work"         # <slug>[#field]
STRIPE_SECRET_KEY = "stripe/acme-live#secret_key"
DATABASE_URL = { ref = "neon/acme", field = "url" }

[env.production]                       # optional profiles, inherit [env]
STRIPE_SECRET_KEY = "stripe/acme-live"

[policy]
agents = "approve"                     # approve | allow | deny
redact = true
mode = "inject"                        # inject | proxy
```

The manifest contains no secret values and is safe for agents to read. Dotenv interop: any `.env`-style file may contain `envcloak://<slug>[#field]` references and be used with `envcloak run --env-file`.

## 6. Core flows

### 6.1 Run with secrets

`envcloak run [--profile p] [--env-file f] -- <cmd...>`

1. Locate the nearest `envcloak.toml` upward from the working directory.
2. Ask the daemon for the referenced secrets, sending context: project path and manifest hash, command line, parent process chain, detected agent.
3. Agent detection: environment markers (`CLAUDECODE=1`, `CODEX_THREAD_ID`, `CURSOR_AGENT`, `GEMINI_CLI`, `OPENCODE`, generic `AGENT`) plus the process ancestry obtained from the socket peer PID.
4. Policy check. If no grant covers (agent, project, keys), the daemon requests approval: the macOS app shows a native sheet (Touch ID) "Claude Code wants to run `npm test` in acme-web with OPENAI_API_KEY and STRIPE_SECRET_KEY" with Allow once, Allow for this session (default 8 hours), Deny. Without the app, a TTY prompt on the user's terminal; in non-interactive contexts, a clear error that names the fix.
5. Spawn the child with the variables injected. Signals and exit codes pass through; TTY is preserved for interactive use.
6. Stdout and stderr stream through the redactor, which replaces any secret value, and its base64, base64url, hex, URL-encoded and JSON-escaped forms, with `[envcloak:openai/work]`. The redactor is chunk-boundary safe.
7. The access is appended to the audit log.

Redaction is a guard against accidents, not a security boundary: a process that holds a key can always transform and exfiltrate it. Proxy mode is the answer to that.

### 6.2 Proxy mode

With `mode = "proxy"` (per project or per key), the child process receives placeholder values (`ecph_...`, random, session-scoped) and `HTTPS_PROXY` pointing at a local EnvCloak proxy. Language runtimes are pointed at a per-session CA (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`). The proxy substitutes the real value only in requests to the provider's allowed hosts from the registry (for example `api.openai.com` for OpenAI keys). A placeholder leaked in a transcript is worthless, and a prompt-injected agent cannot send the real key to an attacker's host. Proxy mode is HTTP(S) only; database URLs and non-HTTP protocols stay in inject mode.

### 6.3 Adding a key without the agent seeing it

- `envcloak add openai --account you@work.com --ask`: the macOS app opens a "Paste key" sheet. The value travels from the user straight into the vault; the agent that ran the command only learns the new slug.
- `--from-clipboard` reads and then clears the clipboard; `--stdin` for scripts. Values never appear on argv.
- The provider is auto-detected from the key's prefix (registry patterns: `sk-proj-`, `sk-ant-`, `AIza`, `ghp_`, `github_pat_`, `sk_live_`, `rk_live_`, `xoxb-`, `AKIA`, and so on), which pre-fills docs, billing and allowed hosts.

### 6.4 Onboarding a project

`envcloak init` in a repo:

1. Scans `.env*` files, matches values against the vault by keyed hash, and creates any missing items with provider detection.
2. Writes `envcloak.toml`, adds `.env*` (except references-only files) to `.gitignore`.
3. Verifies with a dry run that every reference resolves, then offers to delete the plaintext files.
4. Adds a short project-level agent note (AGENTS.md / CLAUDE.md managed block) if the user opts in.

`envcloak import --scan ~/Dev` does the same across many repos with a dry-run report first, deduplicating identical values into one item referenced by many projects.

### 6.5 Doctor and scrub

`envcloak doctor` finds plaintext secrets and leaks:

- `.env` files, shell profiles (`~/.zshrc`, `~/.zprofile`, `~/.bashrc`, sourced files), agent configs (`~/.claude.json`, `~/.codex/config.toml`, Cursor and Gemini configs), agent transcripts, and optionally git history.
- Matching is by keyed hash of candidate tokens against vault values, plus registry key patterns for unknown keys. Output never prints values: it prints item slugs, file paths and counts.
- For each leaked item: where it leaked, a direct link to the provider's key page to rotate it, and `envcloak scrub` to rewrite transcripts replacing the value with a redaction marker (with a backup).

### 6.6 MCP servers that need keys

`envcloak agents migrate-mcp` rewrites agent MCP configs that contain literal secrets:

- stdio servers: `command: envcloak`, `args: ["run", "--ref", "ALPACA_API_KEY=alpaca/paper", "--", <original command>]`.
- HTTP servers with literal headers: Claude Code `headersHelper: "envcloak headers <slug>"`; Codex `bearer_token_env_var` or `env_http_headers` fed by an EnvCloak-launched environment.

### 6.7 Reveal

`envcloak reveal <slug>` shows a value to a human. It always requires Touch ID or the passphrase, refuses when an agent is detected, and is not exposed over MCP. The macOS app can reveal and copy with Touch ID, clearing the clipboard after 30 seconds.

## 7. Agent integrations

`envcloak agents install [--global] [--project]` detects installed agents and writes idempotent managed blocks (`<!-- envcloak:begin -->` / `<!-- envcloak:end -->`) that `envcloak agents uninstall` removes cleanly.

Global instructions (all agents) say, in short:

1. Never read `.env*` files, never print environment variables, never ask the user to paste a key into chat.
2. If the project has `envcloak.toml`, run anything that needs secrets as `envcloak run -- <cmd>`.
3. If a key is missing, run `envcloak ls` (metadata only) to find it and add a reference with `envcloak ref`; if it does not exist, run `envcloak add <provider> --ask` so the user pastes it into the app.
4. If a project has plaintext `.env` files and no manifest, suggest `envcloak init`.

Per agent:

- **Claude Code**: a plugin (`integrations/claude-code/`) with a skill, the MCP server, and hooks:
  - `UserPromptSubmit`: if the user pastes something that looks like a key, block the prompt before it reaches the model and offer to store it with `envcloak add --ask`.
  - `PreToolUse` (Bash, Read, Grep, Edit): block reading `.env*`, dumping the environment (`env`, `printenv`, `export -p`, `set`), `envcloak reveal`, and other secret-printing commands, with a message that says what to do instead.
  - `SessionStart`: inject the names (never values) of the project's available secrets and the one-line usage rule.
- **Codex**: a managed block in `~/.codex/AGENTS.md`, `~/.codex/rules/envcloak.rules` with `forbidden` prefix rules for secret-printing commands, the MCP server in `config.toml` (with `env_vars` rather than literal values), and a note on `shell_environment_policy`.
- **Cursor**: `.cursor/rules/envcloak.mdc`, MCP config, and hooks where supported.
- **Gemini CLI, OpenCode, others**: `GEMINI.md` / `AGENTS.md` blocks and MCP config.

MCP tools (never return values): `list_secrets`, `project_status`, `add_reference`, `request_new_secret` (opens the app's paste sheet), `run_with_secrets` (runs a command through the same policy and redaction path as `envcloak run`), `usage_summary`.

## 8. Dashboard: balance, spend, expiry

The daemon polls provider adapters on a schedule (default hourly, jittered, backoff on errors) using the stored keys internally. Only non-secret metrics are stored (sealed like everything else).

For each key: provider, account email, projects referencing it, balance or credits, spend (month to date, last 30 days), plan or tier, expiry, last used, status (ok, low balance, expiring, invalid, leaked, unused 90 days), and direct links to docs, billing and the keys page.

Views: by project, by provider, by account email. Alerts via native notifications: low balance, expiring within N days, spend spike, invalid key, leak found.

Adapters are declarative where possible:

```toml
id = "deepseek"
name = "DeepSeek"
key_patterns = ["^sk-[a-f0-9]{32}$"]
env_hints = ["DEEPSEEK_API_KEY"]
allowed_hosts = ["api.deepseek.com"]
links = { docs = "https://api-docs.deepseek.com", billing = "https://platform.deepseek.com/usage", keys = "https://platform.deepseek.com/api_keys" }

[balance]
request = { method = "GET", url = "https://api.deepseek.com/user/balance", auth = "bearer" }
value = "$.balance_infos[0].total_balance"
currency = "$.balance_infos[0].currency"
```

Providers without an API get manual fields (balance, renewal date) and a billing link. Providers whose usage APIs need an admin key reference a second vault item.

## 9. Device transfer and sync

- **Pairing**: `envcloak pair` on device A prints a short code (`7-crystal-orbit`) and a QR. On device B, `envcloak pair 7-crystal-orbit`. The code seeds a PAKE (SPAKE2) handshake, so a short code resists man-in-the-middle attacks. Both devices show a confirmation with Touch ID. Device identities (Ed25519/X25519) are exchanged and pinned.
- **Transport**: iroh (QUIC with hole punching, relay fallback). All payloads are end-to-end encrypted; relays see ciphertext only. Users can run their own relay, or connect directly over a LAN or Tailscale address.
- **Transfer vs sync**: `envcloak transfer` sends the whole vault once. `envcloak sync` replicates continuously between paired devices: an append-only change log, per-field last-writer-wins ordered by hybrid logical clocks, with tombstones for deletes.
- **Revocation**: removing a device rotates the sync key and stops replication to it. (A removed device keeps what it already had; the UI says so and links to rotation.)

## 10. Threat model

| Threat | Defense |
|---|---|
| Well-meaning agent prints or logs a key | No plaintext `.env`; inject at exec time; streaming redaction; agent hooks and rules; paste guard |
| Key pasted into chat by the user | `UserPromptSubmit` hook blocks it before it reaches the model; paste sheet in the app |
| Prompt-injected agent tries to exfiltrate | Per-project, per-agent, time-boxed grants; proxy mode with host allowlist; audit log; reveal blocked for agents |
| Laptop stolen or disk imaged | Vault sealed at rest; VMK wrapped by Secure Enclave key or Argon2id passphrase |
| Other process of the same user | Socket permissions and peer checks, approvals, audit. Same-user malware with debugger access is out of scope and documented as such |
| Network attacker during pairing or sync | PAKE pairing, pinned device keys, end-to-end encryption, untrusted relays |
| Malicious update or dependency | Signed and notarized releases, reproducible builds, SBOM, `cargo-deny` and `cargo-audit` in CI, minimal dependencies |

Non-goals: protecting secrets from a process that the user has approved to hold them in inject mode; protecting against a fully compromised user account.

## 11. Crypto and core dependencies

XChaCha20-Poly1305 (`chacha20poly1305`), Argon2id (`argon2`), HKDF-SHA256 (`hkdf`), BLAKE3 keyed hashing (`blake3`), X25519 and Ed25519 (`x25519-dalek`, `ed25519-dalek`), SPAKE2 (`spake2`), iroh for transport, `zeroize` and `secrecy` for memory, `rusqlite` for storage, `aho-corasick` for redaction, `rustls` and `rcgen` for proxy mode, `rmcp` for MCP. Secure Enclave and LocalAuthentication are used from Swift in the app.

## 12. macOS app

- SwiftUI, macOS 14 or later, Swift 6.
- Menu bar extra: lock state, pending approvals, alerts, quick search, "Add key".
- Main window: Keys (group by project, provider, account email), Projects, Dashboard, Activity (audit log), Devices, Leaks (doctor results), Settings (agents installed, policies, unlock methods, recovery kit).
- Approval sheet with Touch ID. Paste sheet for new keys.
- Bundles `envcloakd` and the `envcloak` CLI; "Install command-line tool" links the CLI into the user's PATH; runs the daemon as a login item (SMAppService).
- Developer ID signed and notarized; updates via Sparkle; also a Homebrew cask.

## 13. Open-source plan

- License: MIT OR Apache-2.0 (dual).
- Repository: `github.com/Mitsi-ag/envcloak`. Homebrew tap for the cask and CLI; `cargo install envcloak`; prebuilt binaries for macOS and Linux.
- Community: README with a 30-second demo, CONTRIBUTING, Code of Conduct, SECURITY.md (private disclosure via GitHub security advisories), issue and PR templates, Discussions. Provider adapters are the designated good first issues.
- Quality bar: CI on macOS and Linux (fmt, clippy with warnings as errors, unit, integration and end-to-end tests with scripted fake agents), `cargo-deny`, `cargo-audit`, coverage on core crates, fuzzing of the redactor and parsers.
- Docs site from `docs/` with install, quick start, agent guides, security model, provider guide.

## 14. Milestones

| # | Milestone | Done when |
|---|---|---|
| M0 | Repo, CI, spec, license, community files | CI green on an empty workspace |
| M1 | Core vault, crypto, passphrase unlock, CLI (`init`, `add`, `ls`, `show`, `ref`, `run`, `check`, `import`), redactor | End-to-end test: import a fixture repo, run a command, value redacted in output |
| M2 | Daemon, grants and approvals (TTY), audit log, agent detection, MCP server, agent installers, `doctor`, `scrub`, `migrate-mcp` | Claude Code and Codex run a fixture project via EnvCloak with no value in any transcript |
| M3 | macOS app: unlock with Secure Enclave and Touch ID, approvals, paste sheet, keys, projects, activity, install CLI, login item | Manual QA script passes on a clean user account |
| M4 | Provider registry and dashboard (balance, spend, expiry, alerts) | Registry covers the top providers; dashboard shows live data |
| M5 | Pairing, transfer, sync over iroh | Two machines pair with a code and converge after concurrent edits |
| M6 | Proxy mode | Placeholder-only child process reaches a provider API successfully; non-allowlisted host gets the placeholder |
| M7 | Packaging and release: signed and notarized app, Homebrew, cargo-dist binaries, docs site | `brew install --cask envcloak` works on a clean Mac |
| M8 | Launch | Public repo, launch posts, directory listings |
