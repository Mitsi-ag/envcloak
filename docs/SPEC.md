# EnvCloak: product and architecture spec

Status: draft v0.2 (2026-09-27). Revised after an adversarial security review, a platform feasibility check on macOS 26 and Linux, and reviewer findings F-1 to F-10. This document is the source of truth for what EnvCloak is and how it is built. Changes go through a PR that edits this file.

## 1. One line

Your AI agents use your API keys. They never see them.

EnvCloak is a local-first, open-source secrets vault for developers who work with AI coding agents (Claude Code, Codex, Cursor, Gemini CLI, OpenCode, and anything that reads AGENTS.md). It ships as a native macOS app plus a cross-platform CLI and daemon.

### 1.1 What EnvCloak guarantees

The line above is fully true in proxy mode, for HTTPS APIs. In inject mode, EnvCloak keeps keys out of files, prompts, configs and transcripts, but the command you approve holds the key while it runs. This table is published next to the headline on the README, the site and the app's About screen. A feature that has not shipped is shown as unavailable, never implied.

| Mode | What the approved process holds | EnvCloak guarantees | EnvCloak does not guarantee |
|---|---|---|---|
| Proxy (HTTPS APIs; M6) | A session placeholder, never the key | The key is inserted only into the provider's declared auth slot, only for that item's exact hosts, only over verified TLS, and only while the grant lasts. Key-management and key-minting paths are refused. The placeholder is useless outside the session. | That the agent will not use the key's permissions with that provider during the grant (spend, delete, create). Non-HTTP protocols. Programs that ignore proxy settings fail instead of connecting directly. A program that can read the child's environment can use the session until it ends. |
| Inject + redact (the default until M6) | The real key, in its environment and memory | Every delivery is approved and audited. There is no plaintext in the repo or agent configs. The exact value and the encodings listed in §6.1 are masked in that command's own stdout and stderr. | Anything a careless, deliberate or prompt-injected process does with a key it holds: transformed output, files, network, child processes. Other programs running as you can read a running process's environment on macOS and Linux. |
| Native credential helpers (AWS, git, Docker, kube; M9) | A short-lived or scoped credential, in plaintext | The long-lived source credential never leaves EnvCloak. Every delivery is approved, audited and time-bounded. | The delivered credential until it expires. Stopping delivery does not revoke credentials already issued. |
| Reveal and cards | Nothing: human only | Values appear only in the EnvCloak app after Touch ID, or (secrets only, never cards) on Linux on the terminal after the passphrase; never in CLI stdout or stderr, MCP or agent paths. | Screen capture, an agent that drives the terminal where a value is shown, or someone reading your screen. |
| Every mode | | The vault is encrypted at rest and unlocks only with the Secure Enclave, your passphrase or your Recovery Kit. Grants are limited to a project, a key list, one process tree and a time window, and need an approval proof that a program cannot produce by itself. | Protection from root, kernel malware or a fully compromised account. Removal of anything already sent to a model provider. On Linux and in builds without EnvCloak's signature: protection from a program running as you that impersonates the daemon or the `envcloak` command to capture your passphrase, or that watches a terminal where you type it. On macOS, your login password is also an approval factor, because Touch ID falls back to it. |

## 2. The problem

1. **Agents leak keys.** Plaintext `.env` files, shell profiles that export keys, and MCP configs with literal tokens all end up inside agent context. Agents `cat .env`, echo variables while debugging, or paste keys into commands. Every one of those turns is stored in local transcripts (for example `~/.claude/projects/**/*.jsonl` and `~/.codex/sessions/**`), and often in provider logs too. A scan of one working developer machine found key-shaped strings in well over a hundred transcript files, including live payment, cloud and source-control credentials.
2. **Keys are scattered.** A solo developer with dozens of projects has keys spread across per-repo `.env` files, a shared dotfile, MCP configs, hosting dashboards and cloud parameter stores. The same provider is often bought under several accounts (different emails), and nobody knows which key belongs to which account.
3. **Cost and health are not tied to keys.** Usage meters exist (CodexBar shows usage and spend for about 87 AI providers), but nothing ties balance, spend, expiry and leak status to the specific key, account, card and project they belong to.
4. **Moving machines is painful.** A new laptop means copying `.env` files over chat or USB.

Existing tools solve slices:

- 1Password `op run` and Environments inject references at run time and mask output; paid and not agent-native.
- Infisical Agent Vault is an open-source local credential proxy (session-authenticated CONNECT, fixed upstream hosts) without a vault UI or spend view. Doppler is cloud-first, with encrypted offline fallbacks.
- Varlock validates schemas, redacts piped output and has a credential proxy; interactive terminal output passes through unredacted.
- fnox is open-source Rust with encrypted local config and many backends; its MCP exec redacts literal values and disclaims isolation.
- Claude Code's sandbox can mask credentials: sandboxed commands see a sentinel, and its proxy substitutes the real value for listed hosts, including in request bodies. It is Claude-only, the real value stays in Claude Code's own environment, and TLS termination is experimental.
- CodexBar (MIT) shows usage windows, credits and spend for about 87 AI providers in the menu bar and a CLI.

EnvCloak's position: a local vault whose values never enter the agent host process; approvals a program cannot forge; the same guardrails across every agent, with honest per-agent coverage; cost attributed to keys, accounts, cards and projects; and device-to-device transfer, in one open-source tool. Every one of these claims is bounded by §1.1.

## 2a. Scope: one control plane for everything agents use

Secrets are the wedge, not the whole product. Every coding agent a developer runs (Claude Code, Codex, Cursor, Gemini CLI, OpenCode, Copilot, Kimi CLI, Qwen Code, and the next one) keeps its own copy of the same things in its own format: API keys, MCP servers, skills, instructions files, hooks, permission rules. A heavy user can have a thousand skills and two dozen MCP servers configured separately per agent, with literal keys inside those configs, and no way to carry the setup to a second machine.

EnvCloak is built as modules on one core (vault, policy, audit, sync):

| Module | What it does | Release |
|---|---|---|
| Keys | The vault, run and redact, proxy mode, leak doctor, approvals (Touch ID on macOS, passphrase on Linux) | v0.1 |
| Spend | Balance, spend and expiry attributed to each key, account, card and project; budgets with separately labeled controls (§2a-bis); alerts. Reads CodexBar output as an optional source instead of rebuilding its meters | v0.1 |
| MCP servers | One list of MCP servers, installed into every agent's config in its native format (JSON, TOML, YAML), with secrets injected by EnvCloak instead of written into configs | v0.2 |
| Skills and instructions | See every skill, instructions file, hook and rule across agents; enable per agent and per project; show the context cost of each; sync across devices; translate to agents that use a different format | v0.3 |

Principles for the wider scope:

- **Interoperate, don't fork standards.** Read and write the open Agent Skills format (`SKILL.md`), `AGENTS.md`, and each agent's native config. Work alongside existing installers such as the `skills` CLI rather than replacing them.
- **Translation is compilation.** A canonical definition compiles into each agent's native format. Most of it is mechanical (skills, instructions, MCP config). Hooks and permission rules map partially; the translator reports anything that cannot map instead of guessing. Optional model-assisted rewriting uses the user's own key from the vault, with the cost shown.
- **Configs never hold secrets.** Any MCP server, skill or hook that needs a key gets it through EnvCloak at run time.

## 2a-bis. Money: cards, subscriptions and budgets

The developer's real question is not only "where is my key" but "what is this costing me, on which account, on which card, and when does it break". EnvCloak treats money as a first-class part of the agent environment.

- **Card items.** A separate item class (`card`) with its own tables, sealed under the `card` subkey. Brand, last four digits, expiry, issuer, cardholder, billing address, and which accounts and providers bill it. Storing the full number is off by default; storing the CVV needs a second, separate opt-in. Card sensitive fields sync device to device only when enabled for each card. Each reveal needs its own approval proof and happens only in the app. The resolver used by run, proxy, helpers, MCP, redaction lists and generic doctor matching cannot open `card`-sealed values; this is enforced by types. A manifest or `--ref` that names a card fails to parse. Doctor finds card numbers by Luhn check, BIN pattern and a `card`-keyed hash, and reports only the last four digits.
- **Card health.** "Your Visa ending 4242 expires next month; 14 providers bill it: OpenAI, Vercel, AWS ..." with a checklist and direct links to each billing page. Failed-payment signals from provider billing APIs where available.
- **Subscriptions.** Recurring plans (hosting, AI subscriptions, SaaS) with price, renewal date, account and card, alongside usage-billed API keys. One number: monthly burn across everything. A subscription and the card payment that settles it are one cost, never counted twice.
- **Budgets.** Budgets per key, provider, project or account, with alerts and forecasts ("at this burn rate your Anthropic credit runs out Thursday"). A budget is enforced only by the controls below, and the UI shows which ones apply to it.
- **Spend controls are separate things.** EnvCloak models and shows each one separately. It says "hard cap" only for a provider-enforced cap, or for a proxy gate whose provider adapter supplies a conservative per-request cost bound, and only for the traffic that control sees.

| Control | Enforced by | Stops | Does not stop |
|---|---|---|---|
| Provider-enforced usage cap | The provider (a spend or key limit set in its API or dashboard) | Usage the provider refuses after the cap, under its own rules | Usage accrued before the provider applies the cap; provider-specific lag |
| Proxy spend gate (M6) | EnvCloak's proxy, synchronously, per request. By default an estimated-spend gate. It is a hard cap only when the provider adapter supplies a conservative per-request cost bound: the proxy then atomically reserves that bound before dispatch (counting concurrent and retried requests), reconciles actual charges afterwards, and refuses request classes that have no safe bound | Requests through an EnvCloak proxy session once reserved or estimated spend reaches the budget | Traffic outside the proxy (inject mode, other machines, the provider's console); for the estimated gate, estimation error and requests already in flight |
| Automatic key disable | EnvCloak or Cloud, after polling usage, where the provider's API can disable a key | New usage after the key is disabled | Usage between polls and during the provider's billing lag |
| Card authorization limit | The card issuer | Payments the provider tries to collect on that card | Usage already delivered: the provider can bill another method, suspend the account or pursue the debt |
| Alert only | Notifications | Nothing | Everything |

- **Virtual cards (optional).** A dedicated card per provider through an issuer API, so provider payments are isolated and limited at authorization. "Dedicated card" and "merchant-restricted card" are shown as different things. The first candidate issuers for Australian users are Airwallex and Revolut Business. An issuer adapter ships only after account eligibility, production API access, fees and merchant matching are confirmed for it. An empty merchant allowlist means unrestricted (Airwallex documents this), so card creation fails closed when merchant lookup returns no ID. The budget view shows the reset timezone, FX conversion, and refunds, which restore the limit. Issuer failures and provider billing failures are shown separately.
- **Issuer credentials.** Issuer API credentials are class `issuer_credential`. They are never resolvable for any subject and are used only by the daemon's card module. Creating, freezing or changing the limit of a card needs an approval proof. Issuer tokens and hosted reveal are preferred over storing card numbers.
- **Cost per project.** Attribute spend to projects from provider per-key usage and EnvCloak's own run audit.
- **Receipts.** Collect invoices from provider billing APIs (and optionally a mail connector) and export them for bookkeeping.
- **Later: agent payments with a human on the trigger.** An agent can request a top-up; the human approves with Touch ID; payment uses a single-use token or virtual card. Built on emerging agent-payment standards once they settle.

## 2a-quater. Auth: every credential on the machine

API keys in `.env` files are only half of what agents can use. The other half is the logins already sitting on the machine: `~/.aws/credentials` and SSO caches, `gh`, `gcloud`, `vercel`, `supabase`, `stripe`, `fly`, `wrangler`, npm and Docker registry tokens, kubeconfigs, SSH keys, `~/.netrc` and git credentials, and the agents' own auth files. An agent that never sees a single API key can still run `aws iam create-access-key` with whatever profile is lying around.

- **Inventory.** `envcloak auth scan` lists every CLI credential on the machine with its tool, account or identity, scope where knowable, age, expiry and last use, without printing values. The app shows it as an Auth tab next to Keys.
- **Native credential helpers, so static credentials leave the disk.** EnvCloak plugs into each tool's own extension point and serves credentials on demand, through the same approval, grant and audit path as `envcloak run`:
  - AWS: `credential_process` in `~/.aws/config`. EnvCloak holds the long-lived key (or better, an IAM Identity Center session) and hands out short-lived STS credentials per approved session.
  - git: a git credential helper. Docker: a `docker-credential-envcloak` helper. Kubernetes: an exec credential plugin. GitHub CLI, npm and others: injected tokens via `envcloak run`.
- **Plaintext boundary.** Helpers deliver plaintext to whoever invokes them, by design: `credential_process` prints JSON on stdout, `git credential fill` prints the password, and `aws configure export-credentials` re-exports it. Helper-delivered credentials are therefore outside the "never see" guarantee (§1.1).
  - Every invocation is an ordinary daemon request with its own grant (`mode = helper(kind)`), subject root and audit entry.
  - AWS for agent subjects: STS credentials default to 15 minutes (the STS minimum of 900 s), and a session policy is required. Long-lived source keys never leave the daemon. STS results are cached in daemon memory only, keyed by identity, role, session policy and grant, and concurrent refreshes are deduplicated. `Expiration` is always the real AWS expiration.
  - git and Docker for agent subjects: only tokens scoped to the repo or registry.
  - Stopping delivery does not revoke issued credentials. The app offers "revoke active sessions" (an `aws:TokenIssueTime` deny policy) for role sessions.
  - Helper stdout carries only the protocol; stderr never carries values. The helper's path in `~/.aws/config` is absolute and quoted.
  - Earlier credential providers (environment variables, static profiles) take precedence over `credential_process`, so `envcloak auth scan` reports them as defeating the helper.
- **AWS accounts and IAM.** For linked accounts (AWS Organizations or multiple profiles), a read-only view of identities per account: IAM users and their access keys (age, last used), roles, Identity Center access, root MFA status. Findings with fixes: rotate or delete keys older than 90 days or unused, move humans to Identity Center, never give agents admin profiles. Changes are proposed as commands for the human to approve, never applied silently.
- **Agent identity separation.** Agents get their own scoped identities (an `agent` AWS role with a permission boundary, a fine-grained GitHub token limited to the repo) instead of the human's full-power sessions, with the grant and expiry shown in the app.

## 2a-ter. What makes EnvCloak the best tool in its category

Ranked by value to developers; each is scheduled in the milestones.

1. **A 60-second first run that proves its worth.** Scan the machine, import every key (dotenv files, shell profiles, MCP configs, exports from 1Password, Bitwarden, Doppler, Infisical, Vercel and AWS), deduplicate, detect providers and owning accounts, and show what already leaked. The result screen is the product's best marketing.
2. **Agents never hold keys where the protocol allows it.** Proxy mode for HTTPS APIs; inject with redaction elsewhere; approvals, hooks and rules for every agent, with per-agent coverage reporting (§7.1); reveal blocked for agents. Bounded by §1.1.
3. **Live-key guard.** Agents get test-mode keys by default (`sk_test_` over `sk_live_`, sandbox over production); live keys need an explicit, time-boxed grant.
4. **One wallet view.** Keys, accounts, cards, subscriptions, spend, expiry and docs in one place, searchable from the menu bar.
5. **Capture at creation.** A browser extension notices when you create a key on a provider's site and saves it straight into EnvCloak with the account email from the page, so "which email bought this" is never a question again.
6. **Rotation assistant.** Guided rotation for every provider and one-click rotation where the provider's API can mint keys; every project referencing the key picks up the new one.
7. **Spend protection you can reason about.** Budgets, forecasts, provider caps, a proxy budget gate, virtual cards and 24/7 watching in Cloud, each labeled with what it actually stops (§2a-bis).
8. **New machine in one step.** Pair, and keys, MCP servers, skills, instructions and agent configs arrive together.
9. **Every agent, every format.** MCP, skills, instructions, hooks and rules managed once and compiled to each agent.
10. **Everywhere developers work.** CLI, menu bar, Raycast, VS Code and Cursor extension (status and "insert reference"), shell integration for human shells only, git pre-commit leak guard, and sync targets for Vercel, AWS, GitHub Actions and other hosts.
11. **Trust you can check.** Open source, reproducible signed builds, published threat model, external audit before 1.0, bug bounty.

## 2b. Free and paid

EnvCloak itself is free and open source forever, with everything a single developer needs locally, including device-to-device sync between their own machines.

EnvCloak Cloud is an optional paid service on AWS for things a laptop cannot do. The client and protocols stay open; the hosted service is closed source. The service is zero-knowledge wherever possible.

- **Always-on backup and sync**: end-to-end encrypted; devices no longer need to be online at the same time. The server stores ciphertext only.
- **24/7 spend watch**: polls providers while the laptop is closed; alerts by email, Slack or push on low balance, spend spikes, expiring or leaked keys; disables a key at a budget where the provider's API allows it (this stops new usage after detection; it is not a cap on cost already incurred, see §2a-bis).
- **Secrets for cloud agents and CI**: cloud coding agents (Codex cloud, Claude Code on the web, background agents) and CI jobs get placeholders; a hosted credential proxy swaps in the real key only for allowed hosts. The proxy runs in AWS Nitro Enclaves with published attestation, so the operator cannot read keys.
- **Teams**: share keys, MCP sets and skill packs; per-member policies; onboarding and offboarding with rotation prompts; central audit; SSO.

Indicative pricing: Pro for individuals around US$5 a month; Team around US$12 per user per month. Final pricing follows the waitlist and early usage.

## 3. Principles

1. **Local-first, no account.** The vault lives on your machine, encrypted. No EnvCloak cloud, no sign-up. Sync is device to device.
2. **Capability, not secrets, where the protocol allows.** In proxy mode, agents get the ability to call an API with a key, not the key. In inject mode, the approved command holds the key, and redaction only guards against accidents.
3. **Human in the loop, cheaply and unforgeably.** One approval (Touch ID on macOS, the vault passphrase on Linux) grants one process tree access to named keys in one project for a time window. An approval is a proof the daemon verifies, never a message a program could send or a key a program could type.
4. **Everything is audited.** Every delivery is recorded before the value is released, in a tamper-evident (not tamper-proof) log: which key, which project, which command, which process tree, which decision.
5. **Agent-native by default.** One command teaches every installed agent how to use EnvCloak (instructions, hooks, rules, MCP). New projects inherit it automatically.
6. **Open and extensible.** Provider adapters (balance, spend, expiry, key patterns, allowed hosts) are declarative files the community can add in minutes.
7. **Boring, audited crypto.** No custom cryptography. Well-reviewed Rust crates only. EnvCloak composes reviewed primitives exactly as specified in §5 and adds no constructions of its own.

## 4. Components

| Component | Language | Role |
|---|---|---|
| `envcloak` | Rust | CLI used by humans and agents. Scans files, runs commands with injected values and redacts their output. Never holds the vault key. |
| `envcloakd` | Rust | Vault broker daemon, one per user: the only process that holds the unlocked vault key. Grants, approvals, audit; later provider polling and sync. |
| `EnvCloak.app` | Swift 6 / SwiftUI | macOS app (M3): menu bar, main window, Secure Enclave unlock and signed approvals, paste sheet, dashboard. Bundles `envcloakd` as a helper app (§12). |
| `envcloak mcp` | Rust | stdio MCP server; never returns secret values |
| Provider registry | TOML | `providers/*.toml`: key patterns, docs and billing links, allowed hosts, balance and usage endpoints |
| Agent integrations | files + Rust installers | Claude Code plugin (skill, hooks, MCP), Codex (AGENTS.md block, execpolicy rules, MCP), Cursor, Gemini CLI, OpenCode, generic AGENTS.md |

Linux gets the CLI and daemon (passphrase unlock, passphrase-proven approvals). A GUI for Linux and Windows is out of scope for v1.

### Rust workspace layout

```
crates/
  envcloak-sys        the only crate allowed `unsafe`: peer credentials, audit tokens, process info, prctl, setrlimit, mlock, the wiping allocator
  envcloak-core       secret types, crypto, vault format and storage, unlockers, backups, audit log
  envcloak-policy     manifest, project identity, caller evidence, grants, approvals
  envcloak-redact     streaming multi-pattern redactor (values + encodings)
  envcloak-exec       run pipeline: child spawn, signals, redacted output (used by the CLI and MCP)
  envcloak-scan       filesystem-safe scanning, dotenv parsing, atomic file replacement (import, doctor, scrub)
  envcloak-proxy      placeholder tokens + local TLS proxy (proxy mode)
  envcloak-providers  registry loader and safety checks, key-pattern detection, balance/usage/expiry adapters
  envcloak-sync       pairing (PAKE), transport (iroh), replication
  envcloak-mcp        MCP server
  envcloak-agents     installers and activation probes for each agent
  envcloak-ipc        daemon protocol (length-prefixed JSON-RPC over a Unix socket), shared types, verified client
  envcloak-testkit    test only, never published: runtime-generated canaries, encodings, canary sweep
  envcloak-cli        bin: envcloak
  envcloak-daemon     bin: envcloakd
apps/macos/           SwiftUI app (Xcode project), talks to envcloakd over the socket
providers/            *.toml provider definitions
integrations/         static files shipped to agents (skill, hooks, rules, snippets)
docs/                 this spec, security model, user docs (site source)
```

### 4.1 Starting the daemon

The daemon is started only by:
- launchd, through `SMAppService` from the app bundle (macOS with the app, M3);
- a user LaunchAgent (macOS) or systemd user unit (Linux) written by `envcloak daemon install`, with an absolute path to `envcloakd`, for CLI-only installs;
- the user, running `envcloakd --foreground` by absolute path.

Clients never start a daemon found on PATH. When no daemon answers, the CLI prints how to start one and does nothing else.

### 4.2 Socket

- Location: `~/Library/Application Support/EnvCloak/run/envcloakd.sock` on macOS; `$XDG_RUNTIME_DIR/envcloak/envcloakd.sock` on Linux. When `XDG_RUNTIME_DIR` is unset, the daemon uses `$XDG_STATE_HOME/envcloak/run/` (default `~/.local/state/envcloak/run/`) and prints a warning. Socket paths longer than `sun_path` (104 bytes on macOS, 108 on Linux) are refused with a clear error.
- The directory is mode 0700 and the socket 0600. The daemon binds with umask 077. It refuses to start if the directory is a symlink, is owned by another uid, or is writable by group or others. It holds an exclusive `flock` on `run/envcloakd.lock`, so a second instance refuses to start, and it removes a stale socket only while holding that lock.
- Before sending anything, a client verifies that the server's uid equals its own (`LOCAL_PEERCRED` or `SO_PEERCRED`). On signed macOS builds it also checks the server's code identity from its audit token. Client sockets are opened with `CLOEXEC`.
- No environment variable or flag disables these checks. Builds that cannot pass the code-identity check (Linux, source and unsigned builds) report "daemon identity unverified" in `envcloak status`. On those builds, a program running as you can impersonate the daemon (§1.1).

### 4.3 Peer identity and roles

At accept, the daemon records:
- the uid, rejected if it differs from the daemon's;
- on macOS, the audit token (pid and pidversion);
- on Linux, `SO_PEERPIDFD` where available (Linux 6.5+), otherwise the `SO_PEERCRED` pid confirmed against its `/proc/<pid>/stat` start time.

Roles:
- The `app` role requires the peer's code signature to satisfy the app's pinned designated requirement. Its methods are: unlock with the Secure Enclave, approve with a signature, policy.set, reveal, paste-sheet ingest, device.add, device.remove and registry.override.
- Every other same-uid peer gets the `client` role. Its methods are: request (run, helper, proxy session), list and show (metadata), check, status, lock, grants.list, grants.revoke, `add`, `import`, `request_new_secret`, and the passphrase-proven methods (unlock, approve, rotate, remove, recover, and terminal reveal on Linux from M2, §6.7).
- Before M3 there is no `app` role; its methods are rejected and audited.
- On Linux, and on macOS without the app, `policy.set`, `registry.override`, `device.add` and `device.remove` are client methods that need a passphrase proof (§10b), like `approve`. Secure Enclave unlock, signed approvals, paste-sheet ingest and in-app reveal exist only with the app.

### 4.4 What crosses the socket

This list is complete.
- App to daemon: one HPKE-sealed VMK per unlock; signed approval, policy, device and reveal statements; values typed into the paste sheet, sealed to a daemon ephemeral key.
- Daemon to app: envelopes (ciphertext); approval request descriptors (metadata only); reveal values sealed to an app ephemeral key after a signed reveal statement.
- Client to daemon: request context and metadata; new values from `add`, `import` and `rotate`; the passphrase or Recovery Kit for passphrase-proven methods. Values and proofs are sent only after the client has verified the daemon (§4.2).
- Daemon to client: metadata, and plaintext values only in the response to a granted inject-mode or native-helper request, or to a passphrase-proven terminal reveal on Linux (§6.7).
- Never to a client: the VMK, subkeys, unlocker material or any grant token.

## 5. Data model

### Vault

A single vault per user under the platform data directory: `~/Library/Application Support/EnvCloak/` on macOS, `$XDG_DATA_HOME/envcloak/` on Linux. The layout is `vault/vault.db`, `audit/`, `backups/` and, on macOS, `run/`. Every directory is 0700 and every file 0600.

- **Storage.** SQLite (rusqlite, bundled) in WAL mode with `synchronous=FULL`, `secure_delete=ON`, `temp_store=MEMORY`, and `fullfsync=ON` on macOS.
  - Plaintext columns hold only opaque ids, row versions, timestamps needed for sync ordering, and keyed hashes.
  - Every sensitive field is sealed with XChaCha20-Poly1305 before it is bound to a statement, so plaintext never enters SQLite pages, WAL or journal.
  - The associated data for every sealed value is the canonical encoding of (vault_id, schema_version, key_epoch, table, row_id, field, item_class, row_version).
  - Nonces are 192-bit values from the OS CSPRNG, one per seal; counters are never used.
  - Size caps: 64 KiB per sensitive field, 1 MiB per row.
- **Key hierarchy.**
  - Vault Master Key (VMK): random 256-bit, one per epoch (§9: revocation starts a new epoch). Never stored in plaintext.
  - Subkeys: HKDF-SHA256(ikm = VMK_e, salt = vault_id, info = `envcloak/v1/<purpose>/e<epoch>`) for the purposes `data`, `index` (keyed BLAKE3), `audit`, `sync`, `card`, `backup`, `header` and `anchor`.
  - Unlockers. Each is an envelope that wraps the VMK:
    - **Passphrase** (Linux, headless, and macOS before or without the app). User-chosen, at least 12 characters, and not in a bundled list of common passwords. `vault create` offers a generated six-word passphrase. On macOS the app offers to remove this unlocker once the Secure Enclave unlocker exists: every program you run can read the vault file, so the passphrase envelope is the only target for offline guessing.
    - **Recovery Kit.** A generated 128-bit secret, shown once and never user-chosen. KEK = Argon2id(secret, salt). It is shown only on the terminal (`/dev/tty`), or written to an explicitly named file descriptor, never to stdout.
    - **macOS Secure Enclave (M3).** Two Secure Enclave P-256 keys created by the app in the keychain access group `<TEAMID>.ai.envcloak`, both `ThisDeviceOnly`, with access control `privateKeyUsage` + `userPresence`: `unlock` (key agreement) and `approve` (signing).
      - The keys, and any CryptoKit `dataRepresentation` of them, are stored only as data protection keychain items in that group, never in the vault or any file. A file-stored blob is usable by any process running as you.
      - The VMK envelope is HPKE (RFC 9180, base mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM) to the `unlock` public key, with info `envcloak/v1/unlocker/se || vault_id || unlocker_id || epoch`. The daemon creates and re-creates this envelope without user presence.
    - **Paired devices.** Each device has its own identity (§9). The VMK arrives over the pairing channel and is re-wrapped locally with that device's unlockers.
    - **No Secret Service unlocker.** It would let any process running as you unwrap the vault, so it is not offered.
  - Envelope parameters:
    - Argon2id defaults: m = 256 MiB, t = 3, p = 4, 16-byte salt, 32-byte output.
    - Parameters are stored with the envelope and bounded when read: 64 MiB ≤ m ≤ 4 GiB, 2 ≤ t ≤ 16, 1 ≤ p ≤ 16. Anything outside the bounds is rejected before any KDF work. Every re-wrap uses the current defaults, never the stored parameters.
    - Every envelope carries a key-commitment tag: keyed BLAKE3 of the envelope header, under a commitment key derived from the KEK. The tag is verified before decryption.

#### Unlock flow

1. On connect, each side checks the other as described in §4.2 and §4.3. Clients never trust a peer by socket path alone.
2. Secure Enclave unlock (M3). The daemon sends `{request_id, challenge (32 random bytes), envelope, daemon_eph_pub}`, where `daemon_eph_pub` is a fresh X25519 key for this unlock only.
3. The app opens the envelope with the `unlock` key through CryptoKit HPKE, using a fresh `LAContext` with `touchIDAuthenticationAllowableReuseDuration = 0`. It then seals the VMK with HPKE (X25519, HKDF-SHA256, ChaCha20-Poly1305, AAD = request_id || challenge) to `daemon_eph_pub`, sends only that ciphertext, and overwrites its own copies. Swift cannot guarantee that framework-internal copies are erased; that exposure is limited to a hardened-runtime process for the duration of the call.
4. The daemon opens the ciphertext, erases the ephemeral secret, verifies the VMK against the sealed header, derives subkeys and reports `unlocked`.
5. Passphrase unlock (Linux, and macOS without the app, from M1). `envcloak unlock` reads the passphrase from `/dev/tty` with echo off, never from argv or the environment. It reads stdin only with an explicit `--passphrase-fd`. It sends the passphrase once, to a daemon it has verified. The daemon runs Argon2id and erases the passphrase.

#### Integrity

- The header is sealed under `header` and holds:
  - `epoch`;
  - a monotonic `write_counter`;
  - the audit head;
  - `state_digest` = keyed BLAKE3 over the sorted list (table, row_id, row_version, SHA-256(ciphertext)) of all rows.
- At unlock the daemon recomputes the digest. On a mismatch the vault opens read-only and reports tampering.
- On macOS (M3), an anchor (vault_id, epoch, write_counter, state_digest, audit head) is stored in the data protection keychain. It is updated on every security-critical write (unlockers, devices, policy, registry overrides, deletions) and at lock. An anchor newer than the file means the file was rolled back.
- Without an anchor (Linux, and macOS before M3), restoring the whole file together with its header is not detected locally. Paired devices compare epochs and counters when they sync.

#### Lock

- The daemon locks on:
  - a request from any client (locking only tightens, so it needs no proof);
  - sleep;
  - screen lock (reported by the app);
  - 8 hours idle (configurable, at most 24);
  - logout;
  - daemon stop.
- Without the app, the daemon detects sleep by comparing two clocks on a one-second tick and before every request: on macOS `CLOCK_MONOTONIC_RAW` (`mach_continuous_time`, counts sleep) against `CLOCK_UPTIME_RAW` (`mach_absolute_time`, does not), which share a timebase; on Linux `CLOCK_BOOTTIME` (counts suspend) against `CLOCK_MONOTONIC` (does not). A divergence of more than 5 seconds means the machine slept.
- Lock erases the VMK and subkeys, drops every grant and pending request, stops proxy substitution and stops helper deliveries.
- Processes that already received values keep them.

#### Memory hygiene

- Sensitive values live in `SecretBytes` (a fixed-size boxed slice wrapped by `secrecy` and `zeroize`). It has no `Clone`, no `Serialize` and no `Display`, and its `Debug` is redacted. `expose_secret` is allowed only in modules on a reviewed allowlist, enforced by clippy `disallowed-methods`.
- Buffers holding plaintext are pre-sized. Growth allocates a new zeroizing buffer, copies, and wipes the old one; a populated secret buffer never grows in place.
- `envcloakd` and `envcloak` install a global allocator that wipes every block on free and implements realloc as allocate, copy, wipe, free.
- The key arena is `mlock`ed where the OS allows, and marked `MADV_DONTDUMP` on Linux (macOS has no equivalent). Both are best effort.
- Not covered, and documented: stack and register copies, kernel pipe and socket buffers, non-Rust allocators (Security.framework and the Swift app), and the child process in inject mode.

#### Process hardening

- `envcloakd`, and `envcloak` on the run and helper paths, set `RLIMIT_CORE = 0` at start.
- On Linux they also set `prctl(PR_SET_DUMPABLE, 0)`, which blocks new same-uid `ptrace` attaches and reading their `/proc/<pid>` files. They then check that `TracerPid` is 0 and refuse to handle values if a tracer is already attached.
- On macOS, protection against debugger attach comes from the hardened runtime without `get-task-allow`, checked in CI. `PT_DENY_ATTACH` is not relied on.
- Builds without these protections (source, Homebrew from source) report "unhardened" in `envcloak status`. Source installs sign ad hoc with the hardened runtime (`codesign -s - -o runtime`).
- Release builds use `panic = "abort"`, and there is no third-party crash reporter.
- The workspace sets `unsafe_code = "forbid"` for every crate except `envcloak-sys`, so the compiler rejects unsafe code, and any `allow` of it, everywhere else. CI checks the manifests and proves the level with a compile canary.

#### Logging

- `tracing` records method names, request ids and decisions only; there is no payload logging at any level.
- Every parser of secret-bearing input (dotenv, TOML, JSON, IPC frames, provider responses, hook payloads) returns value-free error types. Upstream and library error text is never forwarded.
- Hook commands scan prompts in memory and never echo matched text.
- The Swift app uses `os_log` with private redaction by default and has no analytics SDK.

### Items

```
Item {
  id: ULID
  class: secret | card | issuer_credential      # cards and issuer credentials: §2a-bis
  slug: "openai/work"                           # human reference, unique
  title: "OpenAI (work account)"
  provider: "openai"                            # registry id, optional
  account: { email, label, org_id }             # who owns / pays for it
  fields: [{ id, name: "api_key", value: <sealed>, sensitive: true, prior: [<sealed>, up to 3] }]
  env_hint: "OPENAI_API_KEY"
  classification: test | live | unknown         # from registry patterns; editable
  allowed_hosts: ["api.openai.com"]             # snapshot from the registry at creation (§8)
  allow_short: false                            # values of 8 to 15 bytes need this for injection (§6.1)
  tags: [..]
  links: { docs, billing, keys_page, dashboard }
  expires_at, rotated_at, created_at, last_used_at
  budget_monthly: Money?
  notes
}
```

Projects are not stored as owners of secrets. A project references secrets; many projects can reference one secret, so rotating a shared key is one edit. The vault keeps a project index (path, directory identity, manifest hash, adopted bindings, last seen; §6.4) for adoption and the dashboard.

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

[policy]                     # can only tighten your vault policy for this project
agents = "approve"           # approve | deny
redact = true                # false is ignored for agent subjects
mode = "proxy"               # proxy | inject; the stricter of manifest and vault wins
```

The manifest contains no secret values and is safe for agents to read. The manifest is untrusted input: it lives in the repo and agents can edit it. Its `[policy]` can make handling stricter than the vault's policy for the project, never looser. `agents = "allow"` fails to parse; `redact = false` is ignored for agent subjects; `mode = "inject"` is ignored for any binding whose vault policy is proxy. Loosening settings live only in the vault and change only with an approval proof (§10b). Unknown keys fail to parse. A symlinked `envcloak.toml` is refused. A reference to a card or issuer credential fails to parse. Dotenv interop: any `.env`-style file may contain `envcloak://<slug>[#field]` references and be used with `envcloak run --env-file`.

## 6. Core flows

### 6.1 Run with secrets

`envcloak run [--profile p] [--ref NAME=slug[#field]]... [--env-file f] [--wait duration] -- <cmd...>`

1. The CLI finds the nearest `envcloak.toml` upward from the working directory.
2. The CLI sends the manifest path, profile, requested bindings (`--ref`, `--env-file`) and argv. The daemon opens and canonicalizes the manifest itself (realpath, then `fstat` of the opened directory for device and inode) and resolves bindings from the file it read. It treats the client-supplied argv only as display text, and never uses manifest content supplied by the client.
3. **Caller evidence.**
   - The daemon walks the caller's ancestry from the kernel, recording each ancestor's pid, start time, executable path and code identity (macOS: Team ID, signing ID and cdhash; Linux: device, inode and SHA-256 of the executable).
   - It classifies known agents by executable identity and interpreter arguments, using `integrations/agents.toml` plus any user extension files, which can only add entries.
   - Environment markers (`CLAUDECODE`, `CODEX_THREAD_ID` and so on) are recorded as the caller's own claims.
   - Evidence can only make handling stricter. A marker can turn a request into an agent request, but the absence of markers, or of an agent ancestor, never removes a restriction (§10a).
4. **Grant check (§10b).**
   - If no grant covers the request, the daemon opens a pending request and needs an approval proof.
   - Non-interactive requests, and interactive requests without `--wait`, exit with code 125 and `envcloak: approval_required request=<id>: run "envcloak approve <id>" in a terminal you control`.
   - With `--wait`, the CLI waits that long for the approval.
   - Approval input is never read from the requesting process's terminal.
5. The daemon appends the audit entry and fsyncs it. Only then does it send the values to the CLI, which has already verified the daemon (§4.2).
6. **Values and redaction.**
   - The CLI refuses values shorter than 8 bytes, and values of 8 to 15 bytes unless the item has `allow_short`.
   - It builds the redactor and prints coverage gaps by slug on stderr.
   - It spawns the child with the values in the child's environment only. Values never appear in argv, temporary files or the CLI's own environment.
7. **Output.**
   - In pipe mode (the default, and the only mode in M1), stdout and stderr are separate pipes, each through its own streaming redactor, with an idle flush every 40 ms. Relative ordering between the two streams is not preserved.
   - Stdin is inherited, and the child sees non-terminal stdout and stderr.
   - PTY mode (`--pty`, M2) is an explicit option with merged output. EnvCloak never switches to unredacted passthrough because a terminal is present.
8. **Signals and exit.**
   - With a controlling terminal, the child stays in the CLI's process group, terminal-generated signals reach it directly, and the CLI forwards only SIGTERM and SIGHUP. Without one, the child gets its own process group and the CLI forwards SIGINT, SIGTERM, SIGHUP and SIGQUIT to it.
   - The CLI exits with the child's code, or 128 + signal number.
   - It never execs the child in its own place, because that would end redaction.
   - After the child exits, output is drained until EOF. If a descendant keeps the pipes open, the CLI closes them after 2 seconds; further output is lost, never passed through unredacted.
9. **Failures.** EnvCloak's own failures exit 125, with one stable token on stderr: `approval_required`, `vault_locked`, `daemon_unavailable`, `daemon_unverified`, `manifest_invalid`, `binding_unresolved`, `value_too_short` or `traced`. Exit codes 126 and 127 keep their `env(1)` meanings.

**Redaction coverage.** The redactor matches:
- the raw value;
- base64 and base64url, padded and unpadded, including the value embedded in a longer base64 stream;
- lower and upper hex;
- percent-encodings from common encoders, with upper or lower hex digits;
- JSON string escapes from common serializers.

It does not cover mixed-case percent-encoding, compression, encryption, partial values, or output rebuilt on a terminal by cursor movement. The crate documentation of `envcloak-redact` is the authoritative list, and the security gates (§15) test it against independent serializers. Redaction guards against accidents; it is not a boundary against a process that holds the key. Proxy mode is that boundary.

`--env-file` accepts `envcloak://<slug>[#field]` references. Other lines are passed through as ordinary variables, and `check` warns when one matches a registry key pattern.

### 6.2 Proxy mode

With `mode = "proxy"` (per project or per key), the child process receives placeholder values (`ecph_...`, random, session-scoped) and `HTTPS_PROXY` pointing at a local EnvCloak proxy. Language runtimes are pointed at a per-session trust bundle (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`). Node children also get `NODE_USE_ENV_PROXY=1`. Proxy mode is HTTPS only; database URLs and non-HTTP protocols stay in inject mode.

**Substitution rules.** The proxy substitutes only when all of these hold. Otherwise it forwards the request unchanged, with the placeholder.
1. The CONNECT host, the TLS SNI and the HTTP Host or `:authority` are equal and exactly match one of the item's allowed hosts (the snapshot in the item, §8).
2. The upstream is TLS with normal certificate verification. Plain HTTP is never substituted, and the proxy never follows redirects.
3. The placeholder is the entire value of an auth slot the registry declares for that provider: a named header with an optional scheme (`Authorization: Bearer`, `x-api-key`), the user-name or the password part of `Authorization: Basic` (whichever part the registry declares; Stripe, for one, takes its key as the user name), or a named query parameter. In a Basic slot the placeholder must be the whole declared part, and the other part is never substituted. Placeholders in bodies, paths, other headers or cookies are never substituted, so an API that echoes its input cannot reflect the key.
4. The request path is not in the provider's `denied_paths` (key-management, admin and credential-minting endpoints). Those requests get a 403 and an audit entry.
5. The placeholder belongs to the session that owns the connection, and the connecting process, resolved from the local TCP endpoint, belongs to that session's process tree. If it cannot be resolved, there is no substitution.

Requests with duplicate auth headers or ambiguous framing are rejected. Responses to substituted requests stream through the redactor for the session's real values; registry key patterns in responses are masked and audited. HMAC-signing schemes such as AWS SigV4 are not supported in proxy mode; use the native helper instead.

**Session CA.**
- Per session, the daemon generates an ECDSA P-256 root in memory. It uses the root to sign one intermediate, with `basicConstraints CA:true, pathLen:0`, `keyUsage keyCertSign`, and a critical `nameConstraints` permitting exactly the session's allowed hosts. It then discards the root key.
- The name constraints are on the intermediate because clients may ignore constraints on a trust anchor (RFC 5280 §6.1).
- Validity is the session lifetime (at most 24 h), backdated by 5 minutes. Leaf certificates are issued per host from the intermediate, with an exact SAN and no wildcards.
- No key is ever written to disk, and the CA is never installed in a keychain or system trust store.
- The child gets a 0600 bundle file (system roots plus the session root) in a 0700 per-session directory, removed at session end. The bundle includes the system roots because `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and `CURL_CA_BUNDLE` replace the default trust store rather than adding to it.
- `rustls-webpki` must be at least 0.103.12 (RUSTSEC-2026-0099).

**Listener.** The proxy listens on 127.0.0.1 on an ephemeral port and requires `Proxy-Authorization` with a 256-bit session token carried in the `HTTPS_PROXY` URL. Clients that ignore proxy settings send the placeholder directly and fail authentication; that is the intended failure. Any process that can read the child's environment can use the session until it ends (§1.1).

**Compared with Claude Code's credential masking.** The pattern is the same, but EnvCloak:
- keeps the real value out of the agent host process;
- substitutes only in declared auth slots, never in bodies;
- blocks key-minting paths;
- works for every agent;
- requires an approval, and audits, every grant.

### 6.3 Adding a key without the agent seeing it

- `envcloak add openai --account you@work.com` reads the value from `/dev/tty` with echo off, or from `--stdin` for scripts. Values never appear on argv. With the macOS app (M3), `--ask` opens a "Paste key" sheet: the value travels from the user straight into the vault, and the agent that ran the command learns only the new slug. A key added through an agent-initiated `--ask` gets no implicit grant, and the sheet shows the requesting process evidence.
- `--from-clipboard` (M3) reads the clipboard, then clears it, and warns that clipboard history tools may already hold the value.
- **Clipboard.** Copies are marked `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType`. After 30 seconds the clipboard is cleared, but only if its change count still matches EnvCloak's own copy.
- The provider is auto-detected from the key's prefix (registry patterns: `sk-proj-`, `sk-ant-`, `AIza`, `ghp_`, `github_pat_`, `sk_live_`, `rk_live_`, `xoxb-`, `AKIA`, and so on), which pre-fills docs, billing and allowed hosts.

### 6.4 Onboarding a project

`envcloak init` in a repo:

1. Scans `.env*` files, matches values against the vault by keyed hash, and creates any missing items with provider detection.
2. Writes `envcloak.toml`, adds `.env*` (except references-only files) to `.gitignore`.
3. Verifies with a dry run that every reference resolves, then offers to delete the plaintext files, under the rules in "Deleting plaintext after import" below.
4. Adds a short project-level agent note (AGENTS.md / CLAUDE.md managed block) if the user opts in.

`envcloak import --scan ~/Dev` does the same across many repos with a dry-run report first, deduplicating identical values into one item referenced by many projects.

Scanning and parsing run in the CLI. The CLI sends values to a verified daemon, which deduplicates them by keyed hash and seals them. Machine scans never run in the daemon or the app, so macOS privacy prompts are never attributed to them.

**Adoption.**
- The first time the daemon sees a manifest, the approval shows: "new project", the canonical path, the git remote, whether the manifest was written by `envcloak init` on this device, and every binding. Bindings to items that no adopted project uses are flagged "first use".
- Adoption is recorded as (path, directory identity, adopted bindings) in the vault's project index.

**Filesystem safety.**
- Scans use `openat` from a directory handle with `O_NOFOLLOW` and `O_NONBLOCK`. After open, `fstat` must show a regular file owned by the user; FIFOs, sockets and devices are skipped.
- Size cap: 1 MiB for dotenv and profile files. Transcripts are streamed.
- Directory symlinks are not followed out of the scan root, mount points are not crossed, and network or cloud-provider volumes are skipped unless named explicitly.
- Symlinked or hard-linked (`nlink > 1`) targets are reported, never modified.
- Template files (`.env.example`, `.env.sample`, `.env.template`) contribute names only.

**Backups.**
- Backups of modified or deleted files are encrypted with a per-backup key wrapped under `backup`, stored in `EnvCloak/backups/` (0700), and removed after 7 days.
- `envcloak scrub --undo <id>` and `envcloak init --undo <id>` restore the original byte for byte.
- No plaintext `.bak` or temporary copy is ever written.

**Deleting plaintext after import.** Allowed only after all four of these hold:
- the vault write is committed and fsynced;
- a dry run resolves every reference;
- an encrypted backup exists;
- the Recovery Kit is confirmed (`envcloak recovery confirm`).

Deletion removes the working copy only. Values that were in git history, synced folders, backups or transcripts are marked "exposed: rotate".

### 6.5 Doctor and scrub

`envcloak doctor` finds plaintext secrets and leaks:

- `.env` files, shell profiles (`~/.zshrc`, `~/.zprofile`, `~/.bashrc`, sourced files), agent configs (`~/.claude.json`, `~/.codex/config.toml`, Cursor and Gemini configs), agent transcripts, and optionally git history.
- Matching is by keyed hash of candidate tokens against vault values, plus registry key patterns for unknown keys. Output never prints values. CLI and hook output shows item slugs, file paths and counts, never line numbers, offsets or snippets. Line-level detail appears only in the app. Doctor is not exposed over MCP. Keyed-hash matching reports only values of at least 16 characters, or values that match a registry pattern, so doctor is not a guess-confirmation oracle for low-entropy values. Doctor runs are rate-limited per subject root.
- For each leaked item: where it leaked, a direct link to the provider's key page to rotate it, and `envcloak scrub` to rewrite transcripts replacing the value with a redaction marker (with an encrypted backup, §6.4).

**Modifying a file.**
1. Write a temporary file in the same directory (`O_EXCL`, mode 0600, then restore the original mode) and fsync it.
2. Re-check that the original's device, inode, size and mtime are unchanged, then `renameat` and fsync the directory.
3. Refuse any file that is open in another process or was modified within the last 2 minutes, and ask the user to quit the agent first. This covers transcripts that are being appended to.

**Scrub is hygiene; rotation is the fix.**
- Scrub rewrites local files.
- It cannot remove copies already sent to model providers, cloud-synced transcripts, Time Machine backups or APFS snapshots, other machines, terminal scrollback, Spotlight's index, crash reports, or a running agent's context.
- Every doctor finding in a transcript is treated as "exposed". Rotation is offered first and scrub second.

### 6.6 MCP servers that need keys

`envcloak agents migrate-mcp` rewrites agent MCP configs that contain literal secrets:

- stdio servers: `command: envcloak`, `args: ["run", "--ref", "ALPACA_API_KEY=alpaca/paper", "--", <original command>]`.
- HTTP servers with literal headers: by default, rewrite to a stdio server `envcloak mcp-bridge --url <url> --header Authorization=<slug>`. The bridge adds the header inside EnvCloak, so the agent host never holds it. `headersHelper` (Claude Code) and `bearer_token_env_var` (Codex) are opt-in, labeled "delivers plaintext to the agent's own process", and require a helper grant.

### 6.7 Reveal

`envcloak reveal <slug>` never writes a value to stdout or stderr.
- On macOS (M3) it opens the app. The app shows the value after a signed reveal statement (Secure Enclave, reuse 0) and can copy it under the clipboard rules in §6.3.
- On Linux (M2) it writes to `/dev/tty` only, after the passphrase, with a warning that a terminal driven by an agent can read it.
- Reveal is never available over MCP.
- Agent detection does not gate reveal; the proof does. A reveal from a caller with a known agent in its ancestry is refused anyway (§10b).

## 7. Agent integrations

`envcloak agents install [--global] [--project]` detects installed agents and writes idempotent managed blocks (`<!-- envcloak:begin -->` / `<!-- envcloak:end -->`) that `envcloak agents uninstall` removes cleanly.

Global instructions (all agents) say, in short:

1. Never read `.env*` files, never print environment variables, never ask the user to paste a key into chat.
2. If the project has `envcloak.toml`, run anything that needs secrets as `envcloak run -- <cmd>`.
3. If a key is missing, run `envcloak ls` (metadata only) to find it and add a reference with `envcloak ref`; if it does not exist, run `envcloak add <provider> --ask` so the user pastes it into the app.
4. If a project has plaintext `.env` files and no manifest, suggest `envcloak init`.

Per agent:

- **Claude Code**: a plugin (`integrations/claude-code/`: `.claude-plugin/plugin.json`, `skills/`, `hooks/hooks.json`, `.mcp.json`) distributed through a git marketplace, with hooks:
  - `UserPromptSubmit`: if the prompt contains something that looks like a key, return `decision: "block"` with `suppressOriginalPrompt`, never echo the match, and offer `envcloak add --ask`.
  - `PreToolUse` (Bash, Read, Grep, Glob, Edit, `mcp__*`): deny reading `.env*`, dumping the environment (`env`, `printenv`, `export -p`, `set`), `envcloak reveal`, and other secret-printing commands, with a message that says what to do instead.
  - `SessionStart`: inject the names (never values) of the project's available secrets and the one-line usage rule.
  - Sandbox settings in the user's `~/.claude/settings.json`:
    - On macOS, add EnvCloak's socket path to `sandbox.network.allowUnixSockets`; otherwise sandboxed Bash cannot reach the daemon.
    - On Linux the sandbox can only allow every Unix socket (`allowAllUnixSockets`), so the installer asks first. It never adds `envcloak` to `excludedCommands`, because that would run every wrapped command outside the sandbox.
    - `sandbox.credentials` deny entries for `EnvCloak/vault` and `EnvCloak/backups` stop sandboxed commands from copying the vault file.
  - Reported as degraded:
    - a project `.claude/settings.json` that sets `disableAllHooks`;
    - `--safe-mode`, which leaves only managed hooks;
    - hook timeouts, after which the prompt still reaches the model.
    An optional, admin-installed `managed-settings.d/envcloak.json` keeps the hooks on.
- **Codex**:
  - Hooks in `~/.codex/hooks.json`: `PreToolUse` deny and `UserPromptSubmit` block.
  - A managed block in `~/.codex/AGENTS.md`.
  - `~/.codex/rules/envcloak.rules`, with `forbidden` prefix rules for secret-printing commands.
  - The MCP server in `config.toml`, with `env_vars` rather than literal values.
  - A note on `shell_environment_policy`.
  - Non-managed hooks run only after the user trusts them; until then coverage is reported as degraded.
  - `write_stdin` into a running session does not rerun `PreToolUse`, and hosted tools are not covered.
- **Cursor**: `.cursor/rules/envcloak.mdc`, MCP config, and hooks where supported.
- **Gemini CLI, OpenCode, others**: `GEMINI.md` / `AGENTS.md` blocks and MCP config.

MCP tools (never return values): `list_secrets`, `project_status`, `add_reference`, `request_new_secret` (opens the app's paste sheet), `run_with_secrets` (runs a command through the same policy and redaction path as `envcloak run`), `usage_summary`.

### 7.1 Coverage reporting

Installing an integration is not the same as being protected. For each agent and version, `envcloak agents status` reports six surfaces separately: prompt-to-model, transcript, file read, shell, MCP and output. Each surface is `active` (a synthetic probe passed on this machine), `degraded` (installed, but it needs trust, can be switched off, or fails open), `unsupported`, or `unverified`. Output filtering comes only from `envcloak run` redaction, never from hooks. Transcript prevention is claimed only when a probe shows that a blocked prompt was not persisted.

Documented capabilities as of 2026-09-27 (probes decide per machine):

| Agent | Prompt guard | File read / shell / MCP guard | Known gaps |
|---|---|---|---|
| Claude Code | `UserPromptSubmit` block | `PreToolUse` deny | `disableAllHooks` in project settings, `--safe-mode`, fail-open timeouts; whether a blocked prompt reaches `history.jsonl` is unverified |
| Codex CLI | `UserPromptSubmit` block, after trust | `PreToolUse` deny, `forbidden` rules | Untrusted hooks skipped; `write_stdin` bypasses `PreToolUse`; hosted tools not covered |
| Cursor | `beforeSubmitPrompt` `continue:false` | `beforeReadFile`, `beforeShellExecution`, `beforeMCPExecution` | Most hook failures fail open; user hooks absent in cloud VMs |
| Gemini CLI | `BeforeAgent` deny | `BeforeTool` deny | `AfterTool` hiding cannot undo side effects |
| Copilot CLI | Unsupported: command-hook `userPromptSubmitted` output is ignored | `preToolUse` deny | Paste guard never claimed |
| OpenCode | Unsupported: no prompt-rejection contract | Plugin `tool.execute.before` (v1) or `execute.before` (v2) | Adapter pinned to the plugin API version |
| Kimi CLI / Kimi Code | `UserPromptSubmit` exit 2 | `PreToolUse` | Two products with different config paths; timeouts and crashes fail open |
| Qwen Code | `UserPromptSubmit` block for supported sends | `PreToolUse` deny | Steer, Cron, Notification, Teammate and Retry sends not covered; safe and bare modes disable hooks |

### 7.2 Installer rules

1. Adapters are per product and versioned. The installer detects the installed product and version (for example Kimi CLI versus Kimi Code, or OpenCode v1 versus v2) and writes only that format.
2. Before reporting protection as active, the installer runs synthetic activation and denial probes in an isolated HOME.
3. Hook payloads are scanned locally and deterministically, never sent to a model. Block reasons and diagnostics never echo matched text. Hook input and output are bounded and time-limited.
4. An agent with the user's shell can bypass advisory integrations; §1.1 and §10 say so.

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

**Registry safety.**
- Registry files ship inside the signed release and are never fetched from arbitrary URLs at runtime.
- The loader rejects:
  - any request URL whose host is not in the provider's `allowed_hosts`;
  - non-HTTPS URLs;
  - wildcards under a multi-tenant suffix, from a list kept in-repo (`supabase.co`, `workers.dev`, `vercel.app`, `herokuapp.com`, `netlify.app`, `amazonaws.com` and others).
- Tenant hosts are stored per item (for example `acme.supabase.co`).
- Each item snapshots its allowed hosts at creation. A registry update that widens them requires approval.
- Local registry overrides require an approval proof and show the hosts.
- Adapters never follow redirects.
- CODEOWNERS requires two maintainer reviews for any change to `allowed_hosts`, `auth` slots or `denied_paths`.

**Scope and CodexBar.**
- Spend in EnvCloak is about attribution and control: which key, account, card and project a cost belongs to; budgets, alerts and forecasts; expiry, leak status, subscriptions and card health.
- EnvCloak does not rebuild the usage meters that CodexBar (MIT) already provides for about 87 providers. CodexBar output is an optional input: `envcloak run --ref DEEPSEEK_API_KEY=deepseek/work -- codexbar usage --provider deepseek --format json` feeds the per-key view, and the key reaches only that process.
- Doctor flags plaintext keys in CodexBar's `config.json`.
- Adapter endpoint knowledge may be reused with CodexBar's MIT notice in `THIRD_PARTY_NOTICES`. Browser-cookie scraping is never adopted.

Providers without an API get manual fields (balance, renewal date) and a billing link. Providers whose usage APIs need an admin key reference a second vault item.

## 9. Device transfer and sync

- **Pairing.** `envcloak pair` on device A prints a code (`7-crystal-orbit-lamp`: a nameplate plus three words from a 256-word list, 24 bits) and a QR. The code seeds SPAKE2 (symmetric mode, identity `envcloak-pair-v1`). Both sides confirm the key with MACs over the transcript hash, which includes both iroh EndpointIds. Codes are single use: one failed confirmation burns the nameplate, and unused codes expire after 10 minutes.
- **Approval and device identity.**
  - Both screens show a device fingerprint (6 words derived from both identity keys). The existing device must approve with a signed statement naming the new device and its fingerprint. That approval, not the code, authorizes sending the VMK.
  - Each device generates its own identity: Ed25519 for signing and the iroh EndpointId, X25519 for sealing. It is stored in the data protection keychain as `ThisDeviceOnly` (macOS), or sealed under the local unlocker (Linux).
  - Device identity is never synced or restored from a backup. A vault restored through the Recovery Kit gets a new identity and must be re-registered.
- **Transport.**
  - iroh QUIC. Peers are pinned by EndpointId and dialed by EndpointId plus relay URL, both exchanged during pairing.
  - n0 DNS/pkarr address publishing is off by default.
  - Relays see ciphertext only, but they do see metadata: EndpointIds, IP addresses, timing and volume.
  - A self-hosted relay, LAN or Tailscale is one setting away.
- **Transfer vs sync**: `envcloak transfer` sends the whole vault once. `envcloak sync` replicates continuously between paired devices.
- **Replication.** An append-only change log with per-field last-writer-wins, ordered by hybrid logical clocks (HLC), and tombstones for deletes.
  - Each change entry is signed with the origin device's Ed25519 key and sealed under `sync`, with AAD (vault_id, epoch, origin_device, seq). Per-device sequence numbers expose replays and gaps.
  - A remote HLC whose physical component is more than 5 minutes ahead of the local clock is quarantined, not applied.
  - Security-critical records (device list, unlockers, policy, registry overrides, revocations) are accepted only with a valid approval signature from the origin device's pinned `approve` key (§10b defines the key on each platform).
  - Grants never replicate. Audit logs replicate for viewing only, with one chain per device.
  - Secret fields never lose a value to last-writer-wins: the losing concurrent value is kept as a sealed prior version (up to 3) and shown as a conflict.
  - Tombstones are kept for 180 days; a device offline for longer must do a full transfer.
- **Revocation.**
  - Removing a device starts a new VMK epoch: a new random VMK, every row re-sealed, new subkeys. The new VMK is sent to each remaining device by HPKE to its X25519 key, signed by the revoking device.
  - The revocation record is signed with the revoking device's `approve` key and names, for the removed device, the last per-device sequence number accepted (the cutoff) and the new epoch. It replicates like any security-critical record.
  - After revocation, an entry originated by the removed device is accepted only if its sequence number is at or below the cutoff, whoever relays it and whatever HLC it carries. Timestamps chosen by the removed device never decide acceptance.
  - Entries sealed under the old epoch are accepted only from devices still in the membership and only up to each device's cutoff recorded at the epoch change; anything else is quarantined and needs a human-approved recovery.
  - The removed device's EndpointId is blocked.
  - The removed device keeps every value it already had. The app lists each secret that device held and opens rotation for each.

The `spake2` crate states that it has had no independent audit. It is pinned, wrapped behind an internal interface, and included in the pre-1.0 audit.

## 10. Threat model

| Threat | Defense |
|---|---|
| Well-meaning agent prints or logs a key | No plaintext `.env`; inject at exec time; streaming redaction; agent hooks and rules; paste guard |
| Key pasted into chat by the user | `UserPromptSubmit` hook blocks it before it reaches the model; paste sheet in the app |
| Prompt-injected agent tries to exfiltrate | Proxy mode: the key never enters the agent's process; header-only substitution to exact hosts. Inject mode: approval scope and audit only; no protection for values already delivered. |
| Laptop stolen or disk imaged | Vault sealed at rest; VMK wrapped by Secure Enclave key or Argon2id passphrase |
| Other process of the same user | Needs a grant covering its process tree, and grants need an approval proof. Cannot open the vault file without an unlocker. Can read the environment of injected children, and can use a proxy session whose environment it reads. Debugger attach to the daemon and CLI is blocked by the hardened runtime (macOS, signed builds) and `PR_SET_DUMPABLE=0` plus a tracer check (Linux). |
| Agent edits `envcloak.toml` to loosen policy | Manifest policy only tightens (§5). |
| Agent replaces a stored key with one it controls | Replacing or deleting a value needs an approval proof; three prior versions are kept. |
| Agent runs a native credential helper | Plaintext by design; agent subjects get only short-lived, scoped credentials; every delivery audited (§2a-quater). |
| Program running as you impersonates the daemon or `envcloak` | Code-identity checks on signed macOS builds. Not prevented on Linux or unsigned builds; stated in §1.1. |
| Agent ignores or disables its hooks, rules or instructions | Nothing in the agent integrations: they are advisory, and an agent with your shell can bypass them. Enforcement comes from grants, approval proofs, the manifest's tighten-only rule and proxy mode (§10b, §6.2). |
| Online passphrase guessing through the daemon | Attempt limiter (§10b). |
| Offline guessing against a copied vault file | Argon2id with bounded parameters, passphrase rules, generated 128-bit Recovery Kit, Secure Enclave unlocker on macOS. |
| Rollback of the vault file | Sealed state digest; keychain anchor on macOS (M3); epoch and counter comparison when syncing. |
| Network attacker during pairing or sync | PAKE pairing, pinned device keys, end-to-end encryption, untrusted relays |
| Malicious update or dependency | Signed and notarized releases, reproducible builds, SBOM, `cargo-deny` and `cargo-audit` in CI, minimal dependencies; registry files embedded in the signed release; `unsafe` confined to `envcloak-sys` |

Non-goals: protecting a value from the process approved to hold it in inject mode, or from a native helper's caller; protecting against root, kernel malware or a fully compromised account; removing copies already sent to a model provider.

## 10a. Caller identity

The daemon records evidence about every caller and uses it only as this table allows. Unauthenticated evidence may only make handling stricter.

| Claim | Strength | Used for |
|---|---|---|
| Caller runs as your uid | Kernel-verified | Connection admission |
| Caller is the signed EnvCloak app, helper or CLI | Strong (code signature via audit token; signed macOS builds only) | `app` role; client verification of the daemon |
| Caller descends from process instance P (pid and start time) | Strong for membership: the kernel keeps the parent chain, and joining another tree needs control of a process in it. On Linux with Yama `ptrace_scope = 0`, any process running as you can attach to an agent and act inside its tree; with `ptrace_scope` ≥ 1, and on macOS (the debugger entitlement plus admin authorization), it cannot. Files the tree will execute (package scripts, git hooks) are another way in (§10b). | Scoping grants |
| Caller does not descend from P | Worthless: double-fork, `setsid`, launchd, tmux, cron and osascript all leave the tree | Never grants anything |
| An ancestor is Claude Code, Codex, Cursor and so on | Evidence (executable identity) | Labels, grant root selection, agent barrier, refusing proofs from agent sessions, live-key guard |
| Environment markers and argv | Caller-asserted | Labels and tightening only |
| "No agent is involved" or "a human typed this" | Cannot be claimed | Nothing |
| Project path | Caller-asserted; the daemon reads the manifest itself | Grant scoping together with the subject root |

The ancestry walk records pid and start time for each ancestor, then re-validates the chain: each parent started no later than its child, and each ancestor still has the recorded start time. An orphan reparented to launchd or init has lost its ancestry, which fails closed. Agents are recognized by executable path, `argv[0]`, interpreter script and, on macOS, code signature, from a builtin catalog plus add-only user extensions (docs/AGENTS.md).

**Bounds and display.**
- Frames are limited to 1 MiB.
- At most 3 pending approvals per subject root, and 20 per daemon.
- A request identical to one denied in the last 10 minutes is denied without a prompt.
- 3 denials for one root within 10 minutes auto-deny that root for 30 minutes and send a notification.
- Approval surfaces render argv as a list, with control characters, bidirectional overrides and zero-width characters shown as visible escapes. Text beyond 2 KB is truncated with a "(N more bytes)" marker. The approved statement always covers the full argv.

## 10b. Grants and approvals

```
Grant {
  id: ULID
  subject: {
    root: ProcessInstance { pid, start_time, exe_path, code_identity }   # macOS: + pidversion when the root is the direct peer
    kind: agent(label) | terminal | unknown                               # label is display only
  }
  project: { canonical_dir, dir_dev_ino, manifest_path, manifest_sha256_at_approval, git_remote (display only) }
  bindings: [{ env_name, item_id, field, live: bool }]                    # item ids, never slugs
  mode: proxy | inject | helper(kind)
  uses: once | session
  not_after: min(wall-clock UTC deadline, monotonic deadline)
  approval: ApprovalProof
  vault_epoch, policy_epoch
}
```

**Root selection.** If a known agent is in the caller's ancestry, the root is the agent process nearest the caller. Otherwise the root is the caller's session leader (`getsid`). If the session leader is no longer alive, the root is the topmost live ancestor in that session. pid 1 is never a root, nor a session leader for this rule. An agent that only a user extension recognizes is the root only at or below the process the session rules would pick.

**Subject kind.** `agent` when a known agent is in the ancestry; `unknown` when the ancestry no longer reaches the caller's session leader (an orphan), whatever the caller claims; `agent` when the caller claims agent markers; `unknown` in a session without a controlling terminal; otherwise `terminal`. docs/AGENTS.md has the details.

**Match.** Request R is covered by grant G only if all of these hold:
1. G is not expired, revoked or used up.
2. The vault is unlocked at G's epoch.
3. R's kernel-verified ancestry contains G's root instance, with both pid and start time matching. A recycled pid never matches.
4. Agent barrier: no known agent sits strictly between G's root and the caller, unless the root is that agent. A grant approved for a terminal subject covers only terminal subjects.
5. R's canonical project directory, and its device and inode, equal G's.
6. R's bindings are a subset of G's bindings, compared by (env_name, item_id, field).
7. R's effective mode is at least as strict as G's.

A manifest change that leaves the bindings a subset does not prompt; the new hash is recorded in the audit log. Any added or changed binding, env-name remapping, profile switch, `--ref` or `--env-file` reference prompts for the difference only.

**Lifetimes.**
- Agent grants: default 8 h, maximum 24 h.
- Terminal grants: maximum 12 h.
- A grant never outlives its root process.
- Grants live only in daemon memory and are never persisted or synced.

**What a grant means.** A grant authorizes a process tree, not a person or a model. Everything inside that tree during the window gets the bound values in the bound mode: prompt-injected turns, package install scripts, test code, and files in the project that another program changed. What narrows it is the root instance, the key list, the mode and the time window.

**Approval proofs.**
- The daemon records every request that no grant covers as a pending request `{request_id, daemon_nonce, subject evidence, project, bindings, mode, uses, ttl, live flags, new project, first use, argv}`.
- Request ids are 8 Crockford base32 characters, unique among pending requests. Pending requests expire after 10 minutes.
- macOS with the app (M3): the app renders every field, computes SHA-256 over the canonical encoding of exactly what it rendered, and signs it with the Secure Enclave `approve` key, using a fresh `LAContext` with reuse duration 0. The daemon verifies the signature with the pinned public key and checks that the statement equals its pending request.
- Linux, and macOS without the app: the human runs `envcloak approve <request_id> [--once | --for <duration>] [--live <ENV_NAME>]...` in a terminal they control, reads the same statement, and enters the vault passphrase on `/dev/tty` (or `--passphrase-fd`). The daemon verifies the passphrase against the envelope.
- **Approval signing key without a Secure Enclave.** On Linux, and on macOS without the app, each device has an Ed25519 `approve` key generated at vault creation or pairing. Its private key is stored only inside its own Argon2id envelope under the passphrase (not under the VMK), so it is usable only when the passphrase is presented. For each approval that must be recorded or replicated (policy, registry overrides, device add or remove, revocation), the daemon unwraps it with the presented passphrase, signs the canonical statement, and wipes it. The public key is pinned in the device record at pairing. This is weaker than a Secure Enclave key: the envelope can be guessed offline from a copy of the vault, and the key is briefly in daemon memory, so peers display which kind of key signed a record. Gates: Linux-to-macOS and Linux-to-Linux pairing, policy replication and revocation succeed with passphrase-signed records, and a record signed by any other key is rejected.
- A y/n answer is never an approval. Approval input is never read from the requesting process's terminal.
- The daemon refuses any proof (approve, unlock, rotate, remove, reveal, recover) submitted by a caller with a known agent in its ancestry or agent markers in its claims. This only tightens.
- Honest limits:
  - A passphrase typed into a terminal that an agent controls can be captured by that agent.
  - On Linux and unsigned builds, a program running as you can impersonate the daemon.
  - On macOS, `userPresence` accepts the login password.

**Passphrase attempts.** Failed proofs share one limiter. After 5 failures, each further attempt waits 30 seconds, doubling up to 1 hour, and `envcloak status` reports the failures. Offline guessing against a copied vault file is limited only by Argon2id and the passphrase itself.

**Writes that need a proof.** These need an approval proof:
- replacing a secret's value (`rotate`);
- deleting an item or field;
- loosening vault policy for a project;
- registry overrides;
- adding or removing unlockers;
- standing approvals.

Adding a new item needs none, because nothing is bound to it yet. Replaced values are kept as up to 3 sealed prior versions.

**Standing approvals (M2).** A standing approval creates session grants automatically for one agent's code identity in one project, for up to 30 days. It covers test-classified keys only; live keys are never standing. The app labels it: "any <agent> session in this project, including one started by another program, gets these keys without asking."

**Live-key guard (M2).** Agent subjects receive live-classified bindings only when each live binding is individually ticked on the approval. When both a test and a live item exist for a provider, the test item is proposed.

**A grant ends on:**
- expiry;
- its first use, if `once`;
- exit of the root process;
- `envcloak grants revoke <id>|--all` (any client may revoke; tightening needs no proof);
- lock or daemon restart;
- sleep or screen lock;
- a change to the project's canonical directory or its device and inode;
- deletion of a bound item, or its reclassification (for example from test to live);
- the user tightening vault policy for the project (policy epoch bump);
- device revocation or a VMK epoch change.

Rotating a bound item's value does not end a grant.

## 11. Crypto and core dependencies

XChaCha20-Poly1305 (`chacha20poly1305` 0.11), Argon2id (`argon2` 0.6), HKDF-SHA256 (`hkdf` 0.13), BLAKE3 keyed hashing (`blake3`), HPKE RFC 9180 (`hpke` 0.14, with cross-implementation vectors against CryptoKit), P-256 ECDSA verification of Secure Enclave signatures (`p256`, `ecdsa`), X25519 and Ed25519 (`x25519-dalek`, `ed25519-dalek` 3.x), SPAKE2 (`spake2`, pinned and wrapped; no independent audit, so it is in the pre-1.0 audit), iroh 1.x for transport, `zeroize` and `secrecy` plus a zero-on-free global allocator for memory, `rusqlite` with bundled SQLite for storage, `aho-corasick` for redaction, `rustls` 0.23 with `rustls-webpki` 0.103.12 or later and `rcgen` for proxy mode, `rmcp` 3.x (pinned) for MCP, `nix` and `libc` for Unix interfaces, and `security-framework` 3.x on macOS for code-signing checks and keychain items. The RustCrypto major versions released in 2026 are adopted together across the workspace. There is no `keyring` crate in v0.1. Secure Enclave and LocalAuthentication are used from Swift in the app.

## 12. macOS app

- SwiftUI, macOS 14 or later, Swift 6.
- Menu bar extra: lock state, pending approvals, alerts, quick search, "Add key".
- Main window: Keys (group by project, provider, account email), Projects, Dashboard, Activity (audit log), Devices, Leaks (doctor results), Settings (agents installed, policies, unlock methods, recovery kit).
- Approval sheet with Touch ID. Paste sheet for new keys.
- **Layout.**
  - `EnvCloak.app/Contents/Helpers/EnvCloakAgent.app` contains `envcloakd`, with its own `embedded.provisionprofile`.
  - `Contents/Library/LaunchAgents/ai.envcloak.agent.plist` uses `BundleProgram`.
  - `Contents/MacOS/envcloak` is the CLI.
  - "Install command-line tool" links the CLI into the user's PATH.
  - The helper is registered with `SMAppService.agent(plistName:)`. The app checks its status at every launch and shows `.requiresApproval` as "Background item disabled in Login Items", with a button that opens that settings pane. The app registers from `/Applications` and re-registers after it moves.
- **Keychain.**
  - The app and the helper each hold `keychain-access-groups = [<TEAMID>.ai.envcloak]`, authorized by their own Developer ID provisioning profiles with Keychain Sharing. That authorization is what binds keychain items to EnvCloak's code.
  - The data protection keychain exists only in a GUI login session, so the helper runs as a LaunchAgent, never as a system daemon.
- **Certificates and profiles.**
  - The Developer ID Application certificate (G2) is created once by the Apple Developer Account Holder, in the developer portal or in Xcode, and exported as a `.p12` for CI. App Store Connect API keys cannot create it.
  - Everything else is automated with a Team API key: bundle IDs for the app (`ai.envcloak.app`) and the helper (`ai.envcloak.agent`); Keychain Sharing on both; `MAC_APP_DIRECT` profiles; `notarytool submit --wait`; and stapling of the app and DMG.
- **Signing and release.**
  - Sign the helper app, then the CLI, then the outer app, all with the hardened runtime and none with `com.apple.security.get-task-allow`; CI checks every artifact with `codesign -d --entitlements -`.
  - Notarize the outer container. Updates ship through Sparkle and a Homebrew cask.
  - Standalone CLI binaries (Homebrew formula, cargo-dist tarballs) are notarized but cannot be stapled, so their first launch needs an online Gatekeeper check. The cask with the stapled app avoids this.
- **Builds without EnvCloak's profile.** CLI-only installs, source builds and forks have no profile. They use the passphrase unlocker and passphrase approvals, and `envcloak daemon install` writes a user LaunchAgent with an absolute `ProgramArguments`. `envcloak status` reports "daemon identity unverified", and "unhardened" without the hardened runtime. The pinned Team ID and signing identifiers are build-time configuration, so forks can sign their own builds.
- **The passphrase path stays after M3** for Macs without a Secure Enclave, SSH-only sessions, and sessions without a GUI login. LocalAuthentication cannot prompt over SSH, so requests fail closed and name `envcloak approve`.
- **Approval factors.** Both Secure Enclave keys use `privateKeyUsage` + `userPresence`: Touch ID when available, and the login password otherwise (Macs without a Touch ID keyboard, clamshell mode, Screen Sharing). This makes the login password an approval factor. An optional "Touch ID only" setting uses `biometryCurrentSet` on Macs with Touch ID.
- **No side doors.** The app exposes no approve, reveal or policy path through URL schemes, AppleScript, App Intents or Accessibility actions that skips the Secure Enclave-gated sheet.

## 13. Open-source plan

- License: MIT OR Apache-2.0 (dual).
- Repository: `github.com/Mitsi-ag/envcloak`. Homebrew tap for the cask and CLI; `cargo install envcloak`; prebuilt binaries for macOS and Linux.
- Community: README with a 30-second demo, CONTRIBUTING, Code of Conduct, SECURITY.md (private disclosure via GitHub security advisories), issue and PR templates, Discussions. Provider adapters are the designated good first issues.
- Quality bar: CI on macOS and Linux (fmt, clippy with warnings as errors, unit, integration and end-to-end tests with scripted fake agents), `cargo-deny`, `cargo-audit`, coverage on core crates, fuzzing of the redactor and parsers. Security acceptance gates (§15) run in CI on macOS and Linux. Redaction is tested against independent serializers: real runtimes, with fixtures produced by those runtimes and loaded as bytes, never the redactor's own encoder. Fixture secrets are generated at test time and never committed. A canary sweep checks every output, log and temporary file. `unsafe` appears only in `envcloak-sys`, enforced by a CI check.
- Docs site from `docs/` with install, quick start, agent guides, security model, provider guide.

## 14. Milestones

| # | Milestone | Done when |
|---|---|---|
| M0 | Repo, CI, spec, license, community files | CI green on an empty workspace |
| M1 | Core vault and crypto (sealed rows, integrity digest, passphrase and Recovery Kit unlockers, encrypted backups); minimal daemon (socket hygiene, peer checks, lock and unlock, caller evidence, grants, passphrase approvals, audit); CLI (`vault create`, `unlock`, `lock`, `status`, `init`, `import`, `add`, `ls`, `show`, `ref`, `check`, `run`, `rotate`, `rm`, `approve`, `grants`, `backup`, `recover`, `recovery confirm`, `audit verify`, `daemon install`); redactor integration in pipe mode; provider detection | The fixture acceptance story (§15.1) and every M1 gate pass on macOS and Linux CI |
| M2 | PTY run mode, full agent catalog, live-key guard, standing approvals, reveal on the terminal, MCP server, agent installers with activation probes and coverage reporting (§7.1), `doctor`, `scrub`, `migrate-mcp` with `mcp-bridge`, machine-wide first-run scan and import | Claude Code and Codex run the fixture project via EnvCloak with no value in any transcript; every M2 gate passes |
| M3 | macOS app: signed helper, Secure Enclave unlock and signed approvals, paste sheet, clipboard, first-run scan screen, keys, projects, activity, install CLI, login item, keychain rollback anchor | Manual QA script passes on a clean user account; every M3 gate passes |
| M4 | Spend and money: key-attributed balance, spend and expiry adapters (CodexBar output as optional input), cards, subscriptions, budgets with separately labeled controls, alerts, forecasts | Adapters show live data for the fixture providers; every spend control is labeled with what it stops |
| M5 | Pairing, transfer, sync over iroh; VMK epochs and revocation; new-machine bootstrap | Two machines pair with a code and converge after concurrent edits; every M5 gate passes |
| M6 | Proxy mode | A placeholder-only child reaches a provider API; a non-allowlisted host gets the placeholder; every M6 gate passes |
| M7 | Packaging and release: Developer ID certificate created by the Account Holder, app and helper profiles, signed and notarized app, Homebrew, cargo-dist binaries, docs site, landing page with Cloud waitlist | `brew install --cask envcloak` works on a clean Mac |
| M8 | Launch (v0.1: Keys + Spend) | Public repo, launch posts, directory listings |
| M9 | v0.2: MCP servers module, Auth module (inventory, AWS credential_process, git and Docker helpers, AWS multi-account IAM view), browser capture extension, rotation assistant | MCP set installed into four agents from one list; no static AWS keys left on disk |
| M10 | v0.3: Skills and instructions module with translation; Raycast and editor extensions | A skill compiles to five agents' formats with a loss report |
| M11 | EnvCloak Cloud MVP on AWS: encrypted backup and sync mailbox, 24/7 spend watch and alerts, then the Nitro Enclave credential proxy and Teams | Paying users |

## 15. Security acceptance gates

Each gate blocks its milestone. Fixture values are generated at test time. "No value" means no raw value and none of its listed encodings.

### 15.1 M1 fixture acceptance story

On macOS and Linux, in an isolated HOME, with no app:
1. Import a fixture repo.
2. Check it, with metadata-only output.
3. A non-interactive run is denied without a grant.
4. The human approves from a terminal with the passphrase.
5. The run injects the values.
6. Independently serialized outputs are redacted.
7. Rotate a value.
8. Rerun: the run picks up the new value.
9. Lock: runs are refused and grants are gone.
10. Unlock with the passphrase.
11. Recover from an encrypted backup with the Recovery Kit.

After every step, no fixture value appears in any output, log or temporary file.

### 15.2 Gates

M1:
1. Seal tamper. Any bit flip in nonce, ciphertext or tag fails with a value-free error. Swapping ciphertexts between rows, fields, tables or item classes, or changing `row_version` or `key_epoch`, fails on the associated data.
2. Nonces and AAD. 10^6 seals give no duplicate nonce. The AAD equals the canonical tuple. No fixture appears in the SQLite main, WAL or journal bytes.
3. KDF bounds. Out-of-bounds parameters are rejected before any Argon2 work. A re-wrap uses the current defaults. A wrong passphrase gives one generic error. The commitment tag rejects a wrong KEK before decryption.
4. Recovery. After the primary unlocker is destroyed, restoring from the Recovery Kit gives identical items. A wrong kit fails.
5. Crash consistency. After `kill -9` at 1,000 random points during writes, the vault reopens at the last committed state with a valid digest.
6. Integrity digest. Deleting a row, or restoring one row from an older copy, makes unlock report tampering and open read-only.
7. Migration failure. A failure mid-migration leaves the old vault intact and openable.
8. Redaction against independent serializers. The serializers:
   - Python `json.dumps` with `ensure_ascii` true and false;
   - Node `JSON.stringify`;
   - Go `encoding/json`;
   - .NET `System.Text.Json`;
   - serde_json;
   - PHP `json_encode`;
   - `quote` and `quote_plus` in lower and upper hex;
   - form encoding;
   - standard and URL-safe base64, padded and unpadded, at offsets 0, 1 and 2 of a larger payload;
   - lower and upper hex.

   Each output is split at every chunk boundary with idle flush, interleaved on stdout and stderr, and followed by malformed UTF-8, EOF or SIGTERM. Expected: no value in the output.
9. Short secrets. Values under 8 bytes are refused for injection. Values of 8 to 15 bytes need `allow_short` and produce coverage warnings. Whole-value encodings are always covered.
10. Duplicate owners. A value shared by two items is reported for both.
11. Allocator probe. With the wiping allocator and a zero-initializing inspection allocator, no freed block holds a fixture during: stream growth; dotenv, TOML and JSON parsing; IPC frames; seal and open; building the child's environment; and building and dropping the redactor.
12. Canary sweep. The full suite runs at `RUST_LOG=trace` with injected panics and malformed inputs that contain fixtures. No fixture appears in any stdout, stderr, log or panic output.
13. Argv. Values are never accepted on argv, and `ps` during `run` shows no value in the CLI's argv or environment.
14. Child environment scope. Values exist only in the child's environment, with no temporary files. A sibling reading the child's environment matches §1.1, and the result is recorded per OS.
15. Import filesystem safety. Test with a symlinked `.env` outside the root, a FIFO, a 2 GB file, a directory symlink loop, a hard link and an unreadable file. Expected: no hang, nothing followed or modified, and no value in the report.
16. Delete-after-import. Deletion is refused until all four conditions hold. `kill -9` at every step leaves either the plaintext file or the committed item.
17. Manifest tighten-only. `agents = "allow"` fails to parse. `redact = false` and `mode = "inject"` do not loosen. References to a card or an unknown item class are rejected.
18. Registry loader. A request host outside `allowed_hosts`, an `http://` URL, or a wildcard under a multi-tenant suffix each fail to load.
19. Process hardening.
    - `RLIMIT_CORE = 0`, and a forced abort leaves no core file.
    - Linux: a same-uid ptrace attach and reads of `/proc/<pid>/mem` and `environ` are denied, and a traced CLI refuses to request values.
    - macOS: signed artifacts have the hardened runtime and no `get-task-allow`.
20. Socket hygiene. The directory is 0700 and the socket 0600. A symlinked, foreign-owned, or group- or world-writable directory is refused. A second instance is refused. Another uid is rejected at accept.
21. Squatting. A server bound by another uid is refused. Values and proofs are never sent to an unverified peer. The CLI never starts `envcloakd` from PATH.
22. Role separation. Every `app`-role method called by a client peer is rejected and audited.
23. Forged approvals.
    - `y` typed into the requester's PTY approves nothing.
    - A missing or wrong passphrase fails.
    - A statement that differs from the pending request is rejected.
    - Approval input is never read from the requester's terminal.
    - Proofs from an agent-descended caller are refused.
24. Manifest self-authorization. A fixture repo with loosening policy plus a scripted agent still needs approval, and redaction stays on.
25. Evidence forgery.
    - A known-agent fixture under `env -i` is still classified by ancestry.
    - A terminal grant does not cover it.
    - `CLAUDECODE=1` in a human shell only tightens.
26. Ancestry escape. A process escapes by double-fork, `setsid`, `nohup` with `disown`, `launchctl submit` or `systemd-run --user`. The escaped process is not covered and gets a new request labeled "unknown".
27. PID reuse. After the root exits and its pid is reused, the new process is not covered.
28. Binding changes after approval.
    - An added reference, a retargeted env name, a renamed env var, a profile switch, or `--ref` or `--env-file` naming an ungranted item each prompt for the difference only.
    - A comment-only change does not prompt, and its new hash is audited.
    - Copying or moving the repo creates a new identity; a symlinked path to the same directory keeps it.
29. Expiry and revocation. Wall-clock and monotonic expiry are tested separately. `grants revoke` needs no proof. Lock, daemon restart, sleep and root exit end the affected grants.
30. Once grants. Of concurrent requests on a `once` grant, exactly one succeeds.
31. Approval display injection. ANSI escapes, `\r`, U+202E, zero-width characters and 100 KB of argv render escaped and truncated. The statement covers the full argv.
32. Flood control. Pending caps hold, and 3 denials auto-deny the root. Frames over 1 MiB are rejected, and memory stays bounded. The passphrase attempt limiter holds.
33. Audit.
    - Every delivery has an entry that is fsynced before release, and an audit write failure denies the request.
    - Entries contain no values, and command lines are redacted.
    - A modified, deleted or reordered entry is flagged at its sequence number.
    - An unanchored tail is reported.

M2:
34. Reveal. The value never reaches stdout or stderr. Linux writes to `/dev/tty` only, after the passphrase. There is no MCP path.
35. MCP. No response contains a fixture, `run_with_secrets` output is redacted, and there is no doctor or reveal tool.
36. Doctor. Output has slugs, paths and counts only. Low-entropy fixtures are not reported. Doctor is absent from MCP.
37. Scrub.
    - A live-appended or symlinked transcript is refused.
    - `kill -9` leaves either the original or the fully scrubbed file.
    - No plaintext appears in `backups/` or temporary directories.
    - `--undo` restores the file byte for byte, and backups are purged after 7 days.
    - Every scrubbed item is flagged for rotation.
38. Agent installers.
    - Activation and denial probes run for each agent in an isolated HOME, and coverage is reported per surface.
    - Untrusted Codex hooks are reported as degraded, and Copilot's prompt guard as unsupported.
    - A probe checks whether a blocked prompt reaches Claude Code's history or transcripts.
39. migrate-mcp. No literal secret remains in any agent config. HTTP servers use `mcp-bridge`. Writes are atomic, with encrypted backups.
40. Live-key guard. A live binding without a per-binding tick is refused. The test item is proposed first. A standing approval cannot include a live key.
41. End-to-end story with Claude Code and Codex, on macOS and Linux. Afterwards, no fixture appears in `~/.claude/projects/**` or `~/.codex/sessions/**` in the isolated HOME.

M3:
- Code-signature checks work in both directions.
- The VMK crosses the socket only HPKE-sealed, once per unlock.
- Approvals are signed by the Secure Enclave with reuse 0.
- A forged app peer is rejected.
- Keychain-anchor rollback detection works.
- Clipboard concealed and transient types are set.
- Screen lock drops all grants.

M5:
- A wrong code aborts and burns the nameplate.
- A race winner is caught by the fingerprint comparison.
- A revoked device cannot open entries from the new epoch.
- Future HLC timestamps are quarantined.
- Replays are rejected.
- Unsigned policy or device records are rejected.
- No pkarr publishing happens.
- A last-writer-wins conflict keeps both values.

M6:
- Echo-endpoint reflection returns the placeholder.
- A non-allowlisted host gets the placeholder.
- A multi-tenant wildcard is rejected.
- A denied path gets a 403.
- A mismatch between SNI, Host and CONNECT is refused.
- A redirect, or plain HTTP, gets no substitution.
- Another session's placeholder, or a process outside the tree, gets no substitution.
- The intermediate is name-constrained with at most 24 h validity, is in no trust store, and no key is on disk.
- The bundle includes the system roots.
