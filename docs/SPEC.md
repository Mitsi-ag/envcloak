# EnvCloak: product and architecture spec

Status: draft v0.4 (2026-10-01). v0.2 (2026-09-27) was revised after an adversarial security review, a platform feasibility check on macOS 26 and Linux, and reviewer findings F-1 to F-10. v0.3 adds dev sign-in (§6.8, milestone M2b) after two independent designs and a harness-acceptance probe; v0.3.1 adds its guarantees row, the sign-in scope and approval contract, and the gates from the review of v0.3 (F-67, F-68). v0.4 records the build decisions of the M2 and M2b plan and its reviews (F-72 to F-76): a hand-written MCP server, the `envcloak-client` and sign-in crates, managed MCP servers bound to a registered launch (run on Linux from a sealed copy of what was checked) whose values go only into processes the daemon starts, standing approvals by kernel identity with signing from M5, the PTY monitor, honest M2 forms of features that need the app, the hosted browser's tool allowlist and supervisor, the agent coverage table refreshed on 2026-10-01, and gates 38, 39, 41 and two M2b gates worded to what their tests establish. This document is the source of truth for what EnvCloak is and how it is built. Changes go through a PR that edits this file.

## 1. One line

Your AI agents use your API keys. They never see them.

EnvCloak is a local-first, open-source secrets vault for developers who work with AI coding agents (Claude Code, Codex, Cursor, Gemini CLI, OpenCode, and anything that reads AGENTS.md). It ships as a native macOS app plus a cross-platform CLI and daemon.

### 1.1 What EnvCloak guarantees

The line above is fully true in proxy mode, for HTTPS APIs. In inject mode, EnvCloak keeps keys out of files, configs and what reaches the model, but the command you approve holds the key while it runs, and a key pasted into some agents can persist in their local history until `envcloak scrub` (§7.1). This table is published next to the headline on the README, the site and the app's About screen. A feature that has not shipped is shown as unavailable, never implied.

| Mode | What the approved process holds | EnvCloak guarantees | EnvCloak does not guarantee |
|---|---|---|---|
| Proxy (HTTPS APIs; M6) | A session placeholder, never the key | The key is inserted only into the provider's declared auth slot, only for that item's exact hosts, only over verified TLS, and only while the grant lasts. Key-management and key-minting paths are refused. The placeholder is useless outside the session. | That the agent will not use the key's permissions with that provider during the grant (spend, delete, create). Non-HTTP protocols. Programs that ignore proxy settings fail instead of connecting directly. A program that can read the child's environment can use the session until it ends. |
| Inject + redact (the default until M6) | The real key, in its environment and memory | Every delivery is approved and audited. There is no plaintext in the repo or agent configs. The exact value and the encodings listed in §6.1 are masked in that command's own stdout and stderr. | Anything a careless, deliberate or prompt-injected process does with a key it holds: transformed output, files, network, child processes. Other programs running as you can read a running process's environment on macOS and Linux. |
| Native credential helpers (AWS, git, Docker, kube; M9) | A short-lived or scoped credential, in plaintext | The long-lived source credential never leaves EnvCloak. Every delivery is approved, audited and time-bounded. | The delivered credential until it expires. Stopping delivery does not revoke credentials already issued. |
| Dev sign-in (own apps and test accounts; M2b) | A usable session for a dedicated test account, in a fresh browser context EnvCloak creates and publishes for that grant | The password and TOTP seed are used only by EnvCloak's sign-in worker, only on the target's exact credential-entry origins, and are never returned in a tool result, error, log or audit entry; the agent's browser tools never receive a filled credential form. A one-time code is generated only for an approved attempt. Only the target's declared session state is delivered, and only after the account, tenant and role are verified in the receiving context. | What the agent does with the session: it can use and export it for as long as the app honours it. Browser cookies are not port-scoped, so other services on the same hostname can receive them. Ending access stops EnvCloak and clears its browser context; server-side revocation is reported separately, and only when verified. A page that captures or reflects the password it receives. A process running as you with debugger, memory or file access to the worker (§10). TOTP is not phishing-resistant, and a password stored with its TOTP seed in one unlocked vault is one factor, not two. |
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

- **Card items.** A separate item class (`card`) with its own tables, sealed under the `card` subkey. Brand, last four digits, expiry, issuer, cardholder, billing address, and which accounts and providers bill it. Storing the full number is off by default; storing the CVV needs a second, separate opt-in. Card sensitive fields sync device to device only when enabled for each card. Each reveal needs its own approval proof and happens only in the app. The resolver used by run, proxy, helpers, MCP, redaction lists and generic doctor matching cannot open `card`-sealed values; this is enforced by types. A manifest or `--ref` that names a card is rejected (`manifest_invalid`) when its references are bound to the vault's items, since a slug does not say its item's class, and the item ids a run releases come only from that binding. Doctor finds card numbers by Luhn check, BIN pattern and a `card`-keyed hash, and reports only the last four digits.
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

1. **A 60-second first run that proves its worth.** Scan the machine, import every key (dotenv files, shell profiles, MCP configs, exports from 1Password, Bitwarden, Doppler, Infisical, Vercel and AWS), deduplicate, detect providers and owning accounts, and show what already leaked. The result screen is the product's best marketing. M2 ships the command-line side: dotenv files, shell profiles and the files they `source`, the MCP configs of every catalog agent, AWS shared credentials and config files, and Bitwarden JSON, 1Password CSV, Doppler JSON and Infisical JSON exports (Vercel's `env pull`, Infisical's default export and Doppler's `--format env` already write dotenv files). 1Password's 1PUX format comes later; the screen comes with the app (M3).
2. **Agents never hold keys where the protocol allows it.** Proxy mode for HTTPS APIs; inject with redaction elsewhere; approvals, hooks and rules for every agent, with per-agent coverage reporting (§7.1); reveal blocked for agents. Bounded by §1.1.
3. **Agents sign in to your own app without seeing the password.** Agent harnesses refuse to type passwords, and 2FA stops unattended runs. EnvCloak signs in for them in its own worker, including the TOTP step, verifies the account, and hands the agent's browser only the session for a dedicated test account (§6.8).
4. **Live-key guard.** Agents get test-mode keys by default (`sk_test_` over `sk_live_`, sandbox over production); live keys need an explicit, time-boxed grant.
5. **One wallet view.** Keys, accounts, cards, subscriptions, spend, expiry and docs in one place, searchable from the menu bar.
6. **Capture at creation.** A browser extension notices when you create a key on a provider's site and saves it straight into EnvCloak with the account email from the page, so "which email bought this" is never a question again.
7. **Rotation assistant.** Guided rotation for every provider and one-click rotation where the provider's API can mint keys; every project referencing the key picks up the new one.
8. **Spend protection you can reason about.** Budgets, forecasts, provider caps, a proxy budget gate, virtual cards and 24/7 watching in Cloud, each labeled with what it actually stops (§2a-bis).
9. **New machine in one step.** Pair, and keys, MCP servers, skills, instructions and agent configs arrive together.
10. **Every agent, every format.** MCP, skills, instructions, hooks and rules managed once and compiled to each agent.
11. **Everywhere developers work.** CLI, menu bar, Raycast, VS Code and Cursor extension (status and "insert reference"), shell integration for human shells only, git pre-commit leak guard, and sync targets for Vercel, AWS, GitHub Actions and other hosts.
12. **Trust you can check.** Open source, reproducible signed builds, published threat model, external audit before 1.0, bug bounty.

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
| `envcloakd` | Rust | Vault broker daemon, one per user: the only process that holds the unlocked vault key. Grants, approvals, audit; from M2 it starts the processes in the row below it, and from M2b the sign-in driver and reaper of each attempt (§6.8); later provider polling and sync. |
| Daemon-started modes of `envcloak` | Rust | Processes that only `envcloakd` starts, from the `envcloak` installed beside it, through the checked spawn of §6.6: the managed runner (`envcloak run --launch <id>`) and HTTP relay (`envcloak mcp-bridge --relay`) for managed MCP servers (§6.6, M2), and the browser supervisor (`envcloak mcp --browser-supervisor`) for one sign-in operation generation (§6.8, M2b). Apart from the client responses §4.4 lists (a granted inject-mode `envcloak run` or, from M9, native helper; the person's own passphrase-proven terminal reveal or backup restore) and the login steps the daemon sends its own sign-in driver, they are the only processes that receive a value or captured session state (§4.4). Started any other way, each receives nothing and exits 125 with `not_started_by_daemon`. |
| `EnvCloak.app` | Swift 6 / SwiftUI | macOS app (M3): menu bar, main window, Secure Enclave unlock and signed approvals, paste sheet, dashboard. Bundles `envcloakd` as a helper app (§12). |
| `envcloak mcp` | Rust | stdio MCP server, hand-written on `serde_json` (§11); never returns secret values. `run_with_secrets` starts a child `envcloak run` (its own absolute path, stdin `/dev/null`, output on pipes), never the runner in-process, so it takes `envcloak run`'s policy and redaction path. Commands it starts run outside the agent host's sandbox, as every MCP server does; the tool description, `envcloak agents status` and the README say so. From M2b it relays the agent's browser tools to the browser supervisor the daemon starts for each sign-in operation (§6.8) and never holds session state. |
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
  envcloak-client     the CLI's reusable client modules: verified connect, failure tokens, rendering, terminal input, .gitignore and manifest edits
  envcloak-mcp        MCP server, mcp-bridge and its relay, the browser supervisor (M2b)
  envcloak-agents     host, version and path catalog, installers, hook handler, activation probes, migrate-mcp
  envcloak-signin     pure sign-in contract (M2b): scope and its encoding, statement, operation store, authorizations and credits, publication decision, TOTP; no I/O, injected clock
  envcloak-browser    sign-in driver (M2b): CDP over a pipe, origin guard, login state machine, identity check, state extraction, test-session adapter client
  envcloak-ipc        daemon protocol (length-prefixed JSON-RPC over a Unix socket), shared types, verified client
  envcloak-testkit    test only, never published: runtime-generated canaries, encodings, canary sweep
  envcloak-cli        bin: envcloak
  envcloak-daemon     bin: envcloakd
apps/macos/           SwiftUI app (Xcode project), talks to envcloakd over the socket
providers/            *.toml provider definitions
integrations/         static files shipped to agents (skill, hooks, rules, snippets)
docs/                 this spec, security model, user docs (site source)
```

The crate graph is one-way, and CI checks it against a table of allowed edges (`scripts/check-crate-graph.py`): `envcloak-scan` depends on no workspace crate other than `envcloak-core`, `envcloak-policy`, `envcloak-redact` and `envcloak-sys`, and owns the neutral input types its scanners read; the host, version and path catalog lives in `envcloak-agents`, which builds those inputs and calls the scanners; `envcloak-mcp` uses `envcloak-agents` and `envcloak-client`, and nothing points back at the CLI. Neither sign-in crate allows `unsafe`; descriptor handling for their processes is in `envcloak-sys`. A library target inside `envcloak-cli` cannot replace `envcloak-client`: `envcloak` depends on `envcloak-mcp`, so it would be a package cycle.

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
- Every other same-uid peer gets the `client` role. Its methods are: request (run, helper, proxy session), list and show (metadata), check, status, lock, grants.list, grants.revoke, `add`, `import`, `request_new_secret`, and the passphrase-proven methods (unlock, approve, rotate, remove, recover, the file restore of `init --undo` and, from M2, of `scrub --undo` and `migrate-mcp --undo`, terminal reveal on Linux from M2 (§6.7), registering and updating a managed MCP server (§6.6), confirming standing approvals (§10b), and reclassifying an item towards `test` or `unknown` (§10b)), and the Recovery Kit confirmation, proven with the kit.
- Before M3 there is no `app` role; its methods are rejected and audited.
- On Linux, and on macOS without the app, `policy.set`, `registry.override`, `device.add` and `device.remove` are client methods that need a passphrase proof (§10b), like `approve`. Secure Enclave unlock, signed approvals, paste-sheet ingest and in-app reveal exist only with the app.

### 4.4 What crosses the socket

This list is complete.
- App to daemon: one HPKE-sealed VMK per unlock; signed approval, policy, device and reveal statements; values typed into the paste sheet, sealed to a daemon ephemeral key.
- Daemon to app: envelopes (ciphertext); approval request descriptors (metadata only); reveal values sealed to an app ephemeral key after a signed reveal statement.
- Client to daemon: request context and metadata; new values from `add`, `import` and `rotate`; the bytes of any file under an allowed root (env files, the agent config and transcript roots, EnvCloak's managed MCP directories) that is about to be modified or deleted, for its encrypted backup (§6.4); candidate tokens from `doctor`, `scrub`, `migrate-mcp` and machine scans, which the daemon compares by keyed hash and wipes, never stores (the client never holds the `index` key, which would be an offline oracle); the passphrase or Recovery Kit for passphrase-proven methods; and, as descriptors and never as data, the pipe ends a daemon-started process will use (§6.6, §6.8). Values and proofs are sent only after the client has verified the daemon (§4.2).
- Daemon to client: metadata, and plaintext values only in the response to a granted inject-mode or native-helper request, to a passphrase-proven terminal reveal on Linux (§6.7), or to a passphrase-proven restore of a file backup (`envcloak init --undo`, and from M2 `scrub --undo` and `migrate-mcp --undo`), which gets back the files the change deleted or rewrote (§6.4). A covered request for a managed MCP server is answered `started`, never with a value.
- Daemon to a process it started itself, over that process's inherited control pipe and never over the socket: a managed runner receives its registered launch's binding values, an HTTP relay its header value and the origin it is bound to (§6.6), and a browser supervisor the declared session state of its operation generation, after capture and before publication (§6.8). From M2b each attempt's sign-in driver (`envcloakd --signin-driver`) receives a login's username and password from the daemon, one step at a time, to type on the target's credential-entry origins alone (§6.8). Apart from the client responses of the bullet above, which go to the process a grant was made for or to the person's own passphrase-proven request, and from the driver's login steps, which no agent tool reaches, values and session state leave the daemon by one rule. The daemon sends a value or captured session state to a process other than an `envcloak run` in inject mode only when it started that process itself: EnvCloak's runner for a managed server, its HTTP relay for a bridged server, and its browser supervisor for a sign-in operation, each over an inherited pipe. No client process, `mcp-bridge` and `envcloak mcp` included, receives any of them, and no release depends on identifying the requesting process's code: the daemon cannot read a hardened client's executable on Linux.
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

- Sensitive values live in `SecretBytes` (a fixed-size boxed slice wrapped by `secrecy` and `zeroize`). It has no `Clone`, no `Serialize` and no `Display`, and its `Debug` is redacted. `expose_secret` is allowed only in modules on a reviewed allowlist, enforced by clippy `disallowed-methods` in the configurations CI compiles and, in every other configuration, by `scripts/check-unsafe.sh`, which refuses the method and trait names in any file not on the list.
- Buffers holding plaintext are pre-sized. Growth allocates a new zeroizing buffer, copies, and wipes the old one; a populated secret buffer never grows in place.
- `envcloakd` and `envcloak` install a global allocator that wipes every block on free and implements realloc as allocate, copy, wipe, free.
- The key arena is `mlock`ed where the OS allows, and marked `MADV_DONTDUMP` on Linux (macOS has no equivalent). Both are best effort.
- Not covered, and documented: stack and register copies, kernel pipe and socket buffers, non-Rust allocators (Security.framework and the Swift app), and the child process in inject mode.

#### Process hardening

- `envcloakd`, and `envcloak` on the run and helper paths and on every other path that handles a value or a candidate token (reveal, doctor, scrub, `mcp-bridge` and the daemon-started modes of §4), set `RLIMIT_CORE = 0` at start.
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
  classification: test | live | unknown         # from registry patterns; editable, towards test or unknown with a proof (§10b)
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

The manifest contains no secret values and is safe for agents to read. The manifest is untrusted input: it lives in the repo and agents can edit it. Its `[policy]` can make handling stricter than the vault's policy for the project, never looser. `agents = "allow"` fails to parse; `redact = false` is ignored for agent subjects; `mode = "inject"` is ignored for any binding whose vault policy is proxy. Loosening settings live only in the vault and change only with an approval proof (§10b). Unknown keys fail to parse. A symlinked `envcloak.toml` is refused. A reference to a card or an issuer credential parses, since a slug does not say its item's class, and is rejected (`manifest_invalid`) when the references are bound to the vault's items; the item ids a request releases come only from that binding. Dotenv interop: any `.env`-style file may contain `envcloak://<slug>[#field]` references and be used with `envcloak run --env-file`.

## 6. Core flows

### 6.1 Run with secrets

`envcloak run [--profile p] [--ref NAME=slug[#field]]... [--env-file f] [--manifest <absolute path>] [--wait duration] [--pty] -- <cmd...>`

`envcloak pending [--json]`

`envcloak run --launch <id>` (started by the daemon only; §6.6)

1. The CLI finds the nearest `envcloak.toml` upward from the working directory, or takes the absolute path `--manifest` names; either way the daemon opens it itself (step 2).
2. The CLI sends the manifest path, profile, requested bindings (`--ref`, `--env-file`) and argv. The daemon opens and canonicalizes the manifest itself (realpath, then `fstat` of the opened directory for device and inode) and resolves bindings from the file it read. It treats the client-supplied argv only as display text, and never uses manifest content supplied by the client.
3. **Caller evidence.**
   - The daemon walks the caller's ancestry from the kernel, recording each ancestor's pid, start time, executable path and code identity (macOS: Team ID, signing ID and cdhash; Linux: device, inode and, from M2, SHA-256 of the executable). M1 records the Linux executable's device and inode only: hashing a large binary on every request needs a cache keyed by device, inode and change time, which M2 adds with the full agent catalog.
   - It classifies known agents by executable identity and interpreter arguments, using `integrations/agents.toml` plus any user extension files, which can only add entries.
   - Environment markers (`CLAUDECODE`, `CODEX_THREAD_ID` and so on) are recorded as the caller's own claims.
   - Evidence can only make handling stricter. A marker can turn a request into an agent request, but the absence of markers, or of an agent ancestor, never removes a restriction (§10a).
4. **Grant check (§10b).**
   - If no grant covers the request, the daemon opens a pending request and needs an approval proof.
   - Non-interactive requests, and interactive requests without `--wait`, exit with code 125 and `envcloak: approval_required request=<id>: run "envcloak approve <id>" in a terminal you control`.
   - With `--wait` (at most the pending request's 10-minute lifetime), the CLI waits that long for the approval. It never holds a connection open while it waits: it asks for the request's state on fresh connections, backing off from 250 ms to 1 s, and backs off further when the daemon answers that polls must slow down. The daemon answers that state only to the request's own process tree.
   - `envcloak pending` lists the pending requests, with id, age, agent label, project and the bindings' slugs, only to a caller whose proof the daemon would accept (§10b), so the person can find a request id that went to an agent host's log; anyone else gets an empty list.
   - Approval input is never read from the requesting process's terminal.
5. The daemon appends the audit entry and fsyncs it. Only then does it send the values to the CLI, which has already verified the daemon (§4.2).
6. **Values and redaction.**
   - The CLI refuses values shorter than 8 bytes, and values of 8 to 15 bytes unless the item has `allow_short`.
   - It builds the redactor and prints coverage gaps by slug on stderr.
   - It spawns the child with the values in the child's environment only. Values never appear in argv, temporary files or the CLI's own environment.
7. **Output.**
   - In pipe mode (the default, and the only mode in M1), stdout and stderr are separate pipes, each through its own streaming redactor, with an idle flush every 40 ms. Relative ordering between the two streams is not preserved.
   - Stdin is inherited, and the child sees non-terminal stdout and stderr.
   - PTY mode (`--pty`, M2) is an explicit option with merged output. EnvCloak never switches to unredacted passthrough because a terminal is present. Without a terminal on stdin and stdout, `--pty` exits 125 with `pty_unavailable`; it never falls back to pipe mode. Because the terminal maps NL to CR NL on output, the PTY redactor also matches the CR LF form of every value that contains LF.
8. **Signals and exit.**
   - In pipe mode, with a controlling terminal, the child stays in the CLI's process group, terminal-generated signals reach it directly, and the CLI forwards SIGTERM and SIGHUP, and SIGINT and SIGQUIT sent by another process rather than by the terminal (Linux reads the sender from `si_code`; macOS, which reports both alike, counts a sender in the CLI's session or already gone; docs/RUN.md). Without one, the child gets its own process group and the CLI forwards SIGINT, SIGTERM, SIGHUP and SIGQUIT to it.
   - The CLI exits with the child's code, or 128 + signal number.
   - It never execs the child in its own place, because that would end redaction.
   - After the child exits, output is drained until EOF. If a descendant keeps the pipes open, the CLI closes them after 2 seconds, giving up any write its own reader has not taken by then; further output is lost, never passed through unredacted. A pipe no process holds any more is delivered at the reader's pace.
   - A SIGINT, SIGTERM, SIGHUP or SIGQUIT the CLI catches after it has seen the child exit stops the run at once, and the CLI exits with 128 + that signal's number.
   - **PTY signals.** In PTY mode the command runs as the foreground process group of a new session whose leader is EnvCloak's PTY monitor. Typing the terminal's suspend character stops the command, restores your terminal and suspends `envcloak run` in your shell; `fg` resumes both. A nested shell keeps its own job control, and a raw-mode program that reads the suspend character itself keeps doing so. SIGINT, SIGQUIT, SIGTERM and SIGHUP sent to `envcloak run` by another process reach the terminal's foreground job, the job a nested shell is running included, as the terminal's own keys would; where a system cannot deliver one of them that way, `envcloak run --pty` documents it and sends that signal to the command's own process group.
   - In PTY mode EnvCloak signals only processes it owns: the monitor, the command's process group while the monitor has not reaped the command, and on Linux the members of the monitor's own session it verifies through a pidfd. It never signals a process group number read from the terminal. If the monitor dies, the kernel hangs up the session; the CLI restores your terminal, drains output until EOF or the 2-second cutoff, and exits with the command's status if the monitor reported one, otherwise 125 with `pty_monitor_lost`.
9. **Failures.** EnvCloak's own failures exit 125, with one stable token on stderr: `approval_required`, `vault_locked`, `daemon_unavailable`, `daemon_unverified`, `manifest_invalid`, `binding_unresolved`, `value_too_short` or `traced`; from M2 also `managed_command_mismatch` and `managed_launch_changed` (a request against a managed MCP server's project that is not its registered launch, or whose launch changed, §6.6), `pty_unavailable` and `pty_monitor_lost`, `not_started_by_daemon` (`envcloak run --launch` started by anything but the daemon, §4), and `not_in_this_build` for a command whose milestone has not shipped; from M2b `login_reference` (a reference to a login field, §6.8). Exit codes 126 and 127 keep their `env(1)` meanings.

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

- `envcloak add openai --account you@work.com` reads the value from `/dev/tty` with echo off, or from `--stdin` for scripts (a pipe, read to its end, less one final line ending). Values never appear on argv, and a name given there that is shaped like a key (a slug, account or variable) is refused rather than kept. Without `--slug`, the item is named after its provider (`openai`, then `openai-2`, ...). With the macOS app (M3), `--ask` opens a "Paste key" sheet: the value travels from the user straight into the vault, and the agent that ran the command learns only the new slug. A key added through an agent-initiated `--ask` gets no implicit grant, and the sheet shows the requesting process evidence.
- `--from-clipboard` (M3) reads the clipboard, then clears it, and warns that clipboard history tools may already hold the value.
- **Clipboard.** Copies are marked `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType`. After 30 seconds the clipboard is cleared, but only if its change count still matches EnvCloak's own copy.
- The provider is auto-detected from the key's prefix (registry patterns: `sk-proj-`, `sk-ant-`, `AIza`, `ghp_`, `github_pat_`, `sk_live_`, `rk_live_`, `xoxb-`, `AKIA`, and so on), which pre-fills docs, billing and allowed hosts.

### 6.4 Onboarding a project

`envcloak init` in a repo:

1. Scans `.env*` files, matches values against the vault by keyed hash, and creates any missing items with provider detection. Values that are not secrets stay in the file: under 8 bytes (never injected, §6.1), or configuration (no provider's key pattern matches, no word of the name says secret, and the value is neither a URL with a password nor shaped like a generated key); docs/IMPORT.md has the rules.
2. Writes `envcloak.toml`, adds each `.env*` file it read (except templates and references-only files) to `.gitignore`.
3. Verifies with a dry run that every reference resolves, then offers to take the imported values out of the plaintext files, under the rules in "Deleting plaintext after import" below.
4. Adds a short project-level agent note (AGENTS.md / CLAUDE.md managed block) if the user opts in.

`envcloak import --scan ~/Dev` does the same across many repos with a dry-run report first, deduplicating identical values into one item referenced by many projects.

Scanning and parsing run in the CLI. The CLI sends values to a verified daemon, which deduplicates them by keyed hash and seals them. Machine scans never run in the daemon or the app, so macOS privacy prompts are never attributed to them. Matching a value against the vault is not a guess-confirmation oracle, by the rules of §6.5: a value under 16 characters that matches no registry pattern, or a value holding a password that is under 16 characters in any reading of where it ends, is imported and matched only for a caller that may give a proof (a terminal subject with no agent), so an agent's import and delete gate leave it in its file; values matched are rate-limited per subject root and audited by count. The password forms read are a URL's (`scheme://user:password@`, in every URL a value lists), Go's MySQL DSN (`user:password@tcp(...)`, `@(...)` for the default protocol, or `@tcp/` for the default address, which is not read when the password starts with `//`) and a `password=`, `passwd=` or `pwd=` field of a libpq, ADO.NET, ODBC or JDBC connection string, counted with JDBC's `%XX` and libpq's backslash escapes decoded (the fewer characters counting). A password inside a value of any other form (Oracle's `user/password@host`, a scheme-less `user:password@host`, a Go DSN `app://password@tcp/db`, a JSON or YAML document) is measured with the whole value, so a value of 16 characters or more holding a short password that way is matched for any caller; docs/IMPORT.md has the rules.

**Adoption.**
- The first time the daemon sees a manifest, the approval shows: "new project", the canonical path, the git remote, whether the manifest was written by `envcloak init` on this device (for a managed MCP server's directory, §6.6, whether it was "written by migrate-mcp on this device", or else "registered by an agent or unknown process"), and every binding. Bindings to items that no adopted project uses are flagged "first use".
- Adoption is recorded as (path, directory identity, adopted bindings) in the vault's project index.

**Filesystem safety.**
- Scans use `openat` from a directory handle with `O_NOFOLLOW` and `O_NONBLOCK`. After open, `fstat` must show a regular file owned by the user; FIFOs, sockets and devices are skipped.
- Size cap: 1 MiB for dotenv and profile files. Transcripts are streamed.
- Directory symlinks are not followed out of the scan root, mount points are not crossed, and network or cloud-provider volumes are skipped unless named explicitly.
- Symlinked or hard-linked (`nlink > 1`) targets are reported, never modified.
- Template files (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`) contribute names only.

**Backups.**
- Backups of modified or deleted files are encrypted with a per-backup key wrapped under `backup`, stored in `EnvCloak/backups/` (0700), and removed after 7 days.
- `envcloak scrub --undo <id>` and `envcloak init --undo <id>` restore the original byte for byte.
- From M2 the daemon, not the client, seals into each backup who created it (the subject kind and evidence digest, and the agent's label), its purpose and, after the change, the SHA-256 of what the change left. Only the process instance that began a backup may add to it or record its result. A restore takes one passphrase proof from a terminal subject and restores only while the file is what the change left. A backup whose creator exited before recording what the change left says so in its statement, since EnvCloak does not know what the change left, and restores only through the separate recovery form `--unrecorded`, with the same proof. The restore statement names the creator, and a backup an agent or unknown process created restores only with an explicit tick, because restoring it writes that process's bytes outside its sandbox.
- No plaintext `.bak` or temporary copy is ever written.

**Deleting plaintext after import.** Allowed only after all four of these hold:
- the vault write is committed and fsynced;
- a dry run resolves every reference;
- an encrypted backup exists;
- the Recovery Kit is confirmed (`envcloak recovery confirm`).

A file modified in the last 2 minutes, open in another process as far as the system can tell, or with another hard link is kept. Only the entries the vault holds (committed, where the manifest binds their variables) leave a file, so nothing that was never committed is deleted: a file whose every entry the vault holds is deleted; one that also holds entries that are not imported (configuration, an interpolated value, a reference) is rewritten to hold those, as they were; the report names every entry that stays. `envcloak init --undo <id>` puts back a rewritten file only while it is what the deletion left.

Deletion removes the working copy only. Values that were in git history, synced folders, backups or transcripts are marked "exposed: rotate" (in M1 the deletion report says to rotate them; marking items comes with `doctor`, §6.5).

### 6.5 Doctor and scrub

`envcloak doctor` finds plaintext secrets and leaks:

- `.env` files, shell profiles (`~/.zshrc`, `~/.zprofile`, `~/.bashrc`, sourced files), agent configs (`~/.claude.json`, `~/.codex/config.toml`, Cursor and Gemini configs), agent transcripts, and, with `--git-history`, git history.
- Matching is by keyed hash of candidate tokens against vault values, plus registry key patterns for unknown keys. Output never prints values. CLI and hook output shows item slugs, file paths and counts, never line numbers, offsets or snippets. Line-level detail appears only in the app. Doctor is not exposed over MCP. Keyed-hash matching reports only values of at least 16 characters, or values that match a registry pattern, so doctor is not a guess-confirmation oracle for low-entropy values. Doctor runs are rate-limited per subject root.
- For each leaked item: where it leaked, a direct link to the provider's key page to rotate it, and `envcloak scrub` to rewrite transcripts replacing the value with a redaction marker (with an encrypted backup, §6.4).

**Modifying a file.**
1. Write a temporary file in the same directory (`O_EXCL`, mode 0600, then restore the original mode) and fsync it.
2. Re-check that the original's device, inode, size and mtime are unchanged, then `renameat` and fsync the directory.
3. Refuse any file that is open in another process or was modified within the last 2 minutes, and ask the user to quit the agent first. This covers transcripts that are being appended to.

**Scrub is hygiene; rotation is the fix.**
- Scrub rewrites local files.
- It compares and rewrites only values of at least 16 characters, or values that match a registry pattern, for every caller: a short value is neither found nor removed, and its report says so.
- It cannot remove copies already sent to model providers, cloud-synced transcripts, Time Machine backups or APFS snapshots, other machines, terminal scrollback, Spotlight's index, crash reports, or a running agent's context.
- Every doctor finding in a transcript is treated as "exposed". Rotation is offered first and scrub second.

### 6.6 MCP servers that need keys

`envcloak agents migrate-mcp` rewrites agent MCP configs that contain literal secrets. Each literal is imported into the vault (machine scope, §6.4), and each migrated server gets a managed project directory, `<data>/mcp/<agent>-<server>/` (0700), whose `envcloak.toml` (0600) binds the server's variables or headers to their items. The directory is adopted through the normal "new project" approval, so grants and standing approvals apply to it as to any project. `migrate-mcp` changes a host's config only while the host is stopped, and only after an encrypted backup (§6.4).

**Managed servers.** A binding alone would let any command in the agent's process tree receive the server's key, since no match rule compares argv (§10b). So each managed directory is also registered in the vault as a sealed managed-server record, created only with a passphrase proof from a terminal subject and marked "written by migrate-mcp on this device".

- **stdio servers** are rewritten to `command: envcloak`, `args: ["mcp-bridge", "--stdio", "--launch", "<id>"]`, and the host config keeps no part of the original command. Its declaration (argv, the config's working directory, non-secret environment and the `PATH` the host would use) goes to the daemon, which resolves it once into a sealed **registered launch**: the absolute executable and its identity (Linux: SHA-256 read through a descriptor, plus device and inode; macOS: the code directory hash, with Team ID and signing identifier when Developer ID signed, plus device and inode), the full argv, the working directory's identity, and the launch environment (cleared, then `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_*`, `TZ` and `TMPDIR`, the recorded `PATH` and non-secret variables, and the injected bindings; nothing else from the caller). Variables that select code (`LD_*`, `DYLD_*`, `NODE_OPTIONS`, `NODE_PATH`, `BUN_OPTIONS`, `BUN_BE_BUN`, `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, `PERL5LIB`, `PERL5OPT`, `RUBYLIB`, `RUBYOPT`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `BASH_ENV`, `ENV`, `GCONV_PATH`) and interpreter options that load other code (`-e`, `-c`, `-m`, `-r`, `--require`, `--import`, `--loader`) are refused (`code_selecting_env`), and that server is reported as manual. The person sees a launch receipt: the server, launch class, executable path and identity, working directory, environment names (never values), bindings and binding strength.
- **Launch classes.** `native` (a Mach-O or ELF executable) is checked before release and bound through spawn: binding strength `bound`. `script` (a `#!` file, or `node`, `python3`, `bun`, `deno`, `ruby`, `perl`, `sh` or `bash` with an absolute entry file as its first non-option argument): the interpreter is checked like a `native` executable and the entry file's identity before release, but nothing the script imports is bound, so its strength is `checked_at_rest`, and the receipt says "EnvCloak checks the interpreter and the entry script before launch, not the modules it loads or a change made during launch". `package_runner` (`npx`, `pnpm dlx`, `yarn dlx`, `bunx`, `uvx`, `pipx run`): only the runner is checked, and the code it fetches or selects is not, so its strength is `checked_at_rest`, the receipt says "the code that runs is chosen by <runner> at launch", and the report says how to pin it. A macOS executable without a code directory is `checked_at_rest`. Only `bound` launches can have standing approvals (§10b).
- **The stdio bridge** answers the host's `initialize` at once, and until the person approves answers each tool call with an error that names the pending request and `envcloak pending`; it waits by polling (§6.1). On approval its request hands the server-side pipe ends and a lifeline to the daemon, which checks the launch (below) and starts EnvCloak's runner, `envcloak run --launch <id>`. The runner starts the registered launch, never one rebuilt from the caller's argv, `PATH`, working directory or environment, and redacts its output. The bridge then replays `initialize`, sends `notifications/tools/list_changed` and relays both directions. It never holds a value.
- **HTTP servers with literal headers** are rewritten to a stdio server, `envcloak mcp-bridge --manifest <managed manifest> --url <url> --header Authorization=<slug>`. The URL's exact origin is part of the binding's identity: the record holds the origin and the header names, the binding is named for the origin's digest, and the daemon, not the bridge, compares the origin the bridge sends with them. An edited `--url` is refused, and so is an edited URL together with an edited manifest, until `migrate-mcp` registers the server again with a proof. On approval the daemon starts EnvCloak's HTTP relay, `envcloak mcp-bridge --relay`, on pipes the bridge handed over, and gives it the header value and its origin. The relay inserts the header only into requests to that origin, over verified TLS (§11) or plain `http` to a loopback literal, never follows a redirect with it, sends it, when the provider is known, only to a host within that provider's `allowed_hosts`, and redacts everything it sends back. The bridge never holds the value, so the agent host never does.

**The daemon's check.** A request against a managed project is covered only when it names the registered launch (or, for a bridged HTTP server, its registered origin and header names) and the daemon's own launch check passes, both before any pending request exists or any grant is consulted (§10b, match rule 6). The check opens the recorded executable and compares its device, inode and identity with the record, does the same for a script's entry file, and compares the working directory's device and inode. A command that is not the registered launch is refused with `managed_command_mismatch`. A launch whose executable, entry file or working directory changed is refused with `managed_launch_changed`: "This server changed since you approved it. Run `envcloak agents migrate-mcp --update <agent>/<server>` in your own terminal to review and approve its new version". What runs is the executable that was checked. A file can be rewritten in place after any check of it, so on Linux a `bound` launch never runs from its file: the daemon copies the executable, through the descriptor it checked, into a sealed in-memory file (a memfd sealed against writing, growing and shrinking), computes the identity over that sealed copy and compares it with the record, and the runner executes the copy (`execveat`), so the bytes that run are the bytes that were hashed, whatever happens to the file afterwards. On macOS the runner starts the checked path suspended, the daemon compares the suspended child's code directory hash with the record, and the child runs only if they match. A launch that cannot run this way is not `bound`. On Linux the server sees the copy as its own executable, so a program that finds its libraries or other files through its own path does not find them there. The daemon reads an executable's run path when it registers the launch, and one that names `$ORIGIN` is `checked_at_rest`: it runs from the checked descriptor after its stamp is read again, and a change made between that last read and the start is not caught. A program that reads its own path only while it runs (through `/proc/self/exe`) cannot be recognised before it starts: from the copy it may fail to start, and it is then never started from its file instead. On a system whose kernel or security policy refuses to execute a sealed memfd (for example `vm.memfd_noexec=2`), the daemon cannot start its own runner or relay either (below), so managed servers are unavailable there: a request for one is refused with `runner_unavailable`, and the server is reported as manual. Where a system can run neither form, its launches are unsupported there and reported as manual, never assumed bound.

**Where the values go.** A covered request is answered `started`, never with a value. The values go only into the runner or relay the daemon starts itself (§4.4), from the `envcloak` installed beside `envcloakd`. On Linux the daemon starts them from a sealed in-memory copy of that `envcloak`, made and hashed once when the daemon starts, so a change to the file after the daemon started never reaches a process that receives a value, and an upgraded `envcloak` takes effect when the daemon restarts; on macOS from a suspended start whose code directory hash must equal the one the daemon read when it started. A managed server therefore runs as a descendant of the daemon, outside the agent's process tree, and stops when the bridge's lifeline closes, so a value lives no longer than a process in the tree its grant was made for. On macOS, privacy prompts for such a server name `envcloakd`, and a command the server starts is an `unknown` subject.

**Updates.** `envcloak agents migrate-mcp --update <agent>/<server> [--cwd <dir>] [--env NAME=VALUE]... [--unset-env NAME]... [--path-env <PATH>] [-- <argv>...]` takes the declaration stored in the record (the host config holds only the bridge), applies the changes given, resolves it again in the daemon, shows the old and new identity, and registers it with a passphrase proof as the launch's next revision. A grant or standing approval covers only the revision it was made for.

**What it does not stop.** A program the agent runs can have the registered launch started on pipes of its own and talk to that server, and receives no value from EnvCloak in doing so; a program running as you can start the exact server command itself and read the key from that server's environment (§1.1). A `bound` launch binds the server's main executable only, not the dynamic loader, the shared libraries it loads or anything they load, so a program running as you that can write those files (as in a Homebrew or Linuxbrew prefix) can change what the server runs; the launch receipt says so. The migrate report, the adoption statement and the standing approval label say so: "only this server's exact command can receive its key, but any program <agent> runs can start that command and read the key from its environment".

**Reported, not migrated.** YAML configs, key-shaped literals in a server's `args` (moving them into an argv would show them to `ps`) and the stores that hold an agent's own credentials (Copilot's `mcp-secrets/`, OpenCode's `auth.json`) are reported as manual, and the command exits non-zero. `headersHelper` (Claude Code) and `bearer_token_env_var`, `http_headers_helper` and `env_http_headers` (Codex) would deliver plaintext to the agent's own process and require a helper grant, which has no delivery path before M9; until then they are shown as unavailable.

### 6.7 Reveal

`envcloak reveal <slug>` never writes a value to stdout or stderr.
- On macOS (M3) it opens the app. The app shows the value after a signed reveal statement (Secure Enclave, reuse 0) and can copy it under the clipboard rules in §6.3. Before the app, on macOS it exits 125 with `app_required` and requests no value.
- On Linux (M2) it writes to `/dev/tty` only, after the passphrase, with a warning that a terminal driven by an agent can read it.
- Reveal is never available over MCP.
- Agent detection does not gate reveal; the proof does. A reveal from a caller with a known agent in its ancestry is refused anyway (§10b).

### 6.8 Dev sign-in

Agents that test a developer's app keep reaching its login page. Agent harnesses refuse to type passwords, and 2FA stops unattended runs. EnvCloak signs in for them: the agent asks for an outcome ("signed in to the fixture app as the editor"), never for a value.

Scope in M2b: the developer's own apps on loopback or registered HTTPS staging origins, with dedicated test identities. Real third-party websites, native CLI logins, email or SMS codes and TOTP for live personal accounts come later (§14 M9 and after); until then they stay human sign-ins.

- **Login items.** A `login` item holds a username, a password, an optional TOTP enrollment (from an `otpauth://` URI: seed, algorithm, digits, period) and metadata: test or live; the target's app origins, credential-entry origins, identity-provider and callback origins; the identity check; the tier; the session lifetime. Login fields are typed: `run`, `ref`, the helpers, the proxy and every MCP resolver refuse them. Only the sign-in worker opens them.
- **Tools** (on the M2 MCP server): `request_sign_in(target, role?, operation_key)`, `sign_in_status(request)`, `cancel_sign_in(request)` and `end_sign_in_session(session)`. Arguments name a registered target and role, never a URL to fill, a script, a callback or a CDP address. Results are allowlisted status and metadata with a monotonically increasing status revision. The description says plainly that the tool signs in with stored credentials after the person approves in EnvCloak, that the resulting session acts as that account, and that cancelling a tool call only stops waiting while `cancel_sign_in` ends the operation. `request_sign_in` waits for approval for a bounded time, shorter than the host's tool timeout, then returns `waiting_for_approval`.
- **Sign-in scope.** The daemon resolves every request, before any pending state exists, into one immutable scope: the subject (verified root process instance and evidence); the project (canonical directory, device and inode, and the digest of the effective sign-in configuration); the account (login item id and its authorization revision; expected account, tenant and exact role; test or live); the target and adapter (ids, authorization revisions, parsed credential-entry origins, identity check and transfer scope); the delivery (`browser_session_delivery`, the requesting process instance that is to receive the browser tools, and the recipient browser instance's generation); the limits (attempt kind and count, approval duration, per-attempt timeout, maximum session lifetime); and the daemon, vault and policy epochs. It is encoded from typed, length-prefixed fields with sorted, duplicate-free sets; never from display labels or raw JSON, and never with a credential hashed into it. The authorization revision changes when the password or TOTP enrollment is replaced, or when origins, identity check, account, tenant or role mapping, transfer scope or adapter behaviour change.
- **Retries.** `operation_key` is chosen by the caller, kept across retries of one intent and changed for a deliberate new attempt; it is looked up only within the owner root and daemon instance, and never logged. Same owner, key and scope: the same request and its current status, with no new prompt, worker or attempt. Same key with any scope field changed: `request_conflict`, and the existing request is untouched. A finished, failed or cancelled operation returns its result, never a new authentication. A new key with the same scope is a new intent under the attempt budget; a new role, project or browser is a new scope and a new approval, with no subset or "lower role" inference. Status and cancel from another subject are refused before any metadata is returned. Value-free receipts are kept for a published retry window in a bounded store that refuses new work when full rather than evicting; a daemon restart ends grants and retry state, and no operation is claimed exactly-once across a restart.
- **Approval.** A sign-in grant (§10b, mode `sign_in`) holds the scope. The approval statement encodes the scope, the request id, a fresh daemon nonce, creation and expiry, the chosen options and one reserved recipient-context id (reserved only for a new operation, after the retry lookup). The approval screen shows the account, tenant and role, project, browser, what session delivery allows, the attempt budget and both lifetimes, as an access receipt; a digest alone is not an explanation. Tiers:
  - `dev`: loopback and registered dev origins with a test identity. One proof opens an authorization of up to 24 hours (a rolling window, clamped by §10b's subject limits, root lifetime, lock and epochs) for one exact scope and one managed browser instance, with a bounded attempt budget; each operation gets its own context and attempt lease, and nothing resets the budget or extends the deadline.
  - `each`: one proof per sign-in. The default for everything else.
  - `never-agent`: banks, primary email, identity and recovery accounts, password managers. Refused.
  A once grant authorises one authentication attempt (one password submission and at most two one-time codes). Polls, joined retries and identity checks use no attempt; a credit is reserved atomically with the grant and epoch check and the intent audit entry, and is not refunded once credentials may be used. A change of the login's authorization revision ends pending statements and authorizations for it, stops its attempts and tears down its delivered contexts, unlike a key rotation under §10b. The session's own lifetime is shown separately.
- **Sign-in worker.** Chrome for Testing with `--remote-debugging-pipe` (no port), a fresh context per attempt, no extensions and no traces, HAR, video or screenshots, started by the daemon for each attempt through two processes of its own, so input a page influences is never parsed in the process that holds the vault key. A reaper (`envcloakd --signin-reaper`) launches Chrome as its own child in a new session and owns it: on a stop, on the daemon's exit or on Chrome's exit it ends Chrome, removes its profile and writes a teardown confirmation record. A driver (`envcloakd --signin-driver`), started with a cleared environment and only its pipes, parses all DevTools traffic and runs the login state machine; the daemon sends it the username and password one step at a time and generates each one-time code itself. The daemon starts the reaper and the driver from its own executable as it was when the daemon started, never from a path it reads again: on Linux from a sealed in-memory copy of `envcloakd` made then, as it starts its own modes of `envcloak` (§6.6); on macOS from a suspended start whose code directory hash must equal its own. Where that sealed copy cannot be made or executed (for example under `vm.memfd_noexec=2`, as for managed servers in §6.6), dev sign-in is unavailable: a sign-in request is refused with `runner_unavailable`, and `envcloak agents status` and the sign-in tool's result say so. Cleanup that no reaper confirmed is reported as `cleanup_unconfirmed`, never assumed. The worker is separated from the agent's browser tools, not from every process: EnvCloak creates no endpoint to it, and a process running as you with debugger, memory or file access is out of scope (§10); an OS-isolated worker is later work. In M2b, after an attempt EnvCloak retains no reusable worker-owned trust, refresh or session state: the worker process, its profile and its control channel end with the attempt. Deliberately delivered application state follows the delivery and stop-outcomes contract below. A pinned login state machine finds username, password, one-time-code, handoff and error states from autocomplete tokens, input types and per-target hints, and submits every step itself; the agent never clicks Login on a filled form.
  - Origins are registered in ASCII only: `http` for `127.0.0.1`, `::1` and `*.localhost`, `https` otherwise; a punycode A-label written as it is; an explicit or default port; no userinfo, path, query or fragment. Every request, navigation, frame and form action is checked against the target's origins as the browser itself serializes them (each intercepted request's URL and each frame's security origin): exact scheme, host and port, compared byte for byte; no suffix or substring matching; no userinfo. An internationalized lookalike reaches EnvCloak as a different punycode host. Anything else stops the attempt.
  - At most one password submission and two one-time-code submissions per attempt. A failure stops and tells the person.
  - CAPTCHAs, risk challenges, push or number matching, passkeys and unknown states are never bypassed. In M2b they end the attempt with `handoff_required`: a terminal cannot show a live browser view, and a worker window on the desktop would be a surface an agent's screen capture could reach. With the app (M3) they pause for the person, with a live view of the worker shown only on EnvCloak's human surface. No view or capture of the worker reaches the agent's browser tools, captures or recordings.
- **TOTP.** RFC 6238 in the daemon, only inside a bound attempt. Attempts on one account are serialised, a code already submitted for that account is not reused, and no code is generated in the last 3 s of a step. No tool returns a code or a seed.
- **Identity check.** After login the worker runs the target's declared check: an app endpoint or page element that names the account, tenant and role. The check runs again in the recipient context after transfer and before the operation reports active. A mismatch or an unknown identity delivers nothing (`identity_unverified`), and the recipient context is removed.
- **Delivery.** The agent's browser tools are EnvCloak's. For each operation generation the daemon starts a browser supervisor (`envcloak mcp --browser-supervisor`, §4), which starts that generation's pinned Playwright MCP helper, one helper per generation, through its public API with a context getter. `envcloak mcp` relays the agent's browser calls to the supervisor over pipes it handed over with the sign-in request, and never receives the session state. The supervisor serves a fixed tool allowlist, the same for listing and calling: the page-interaction tools, with every `filename` or output-path argument removed from their schemas and refused if sent; no tool that runs code in the helper process, uploads a local file, installs a browser or belongs to an optional capability group; and navigation to any scheme other than `http` and `https` refused. These are guardrails, not a boundary: the helper is not one. The supervisor checks the grant with the daemon on every tool call, not only when a context is first handed over. Each operation gets its own fresh recipient context, private to EnvCloak while it is filled and verified: the daemon sends the declared state to the supervisor on its control pipe (§4.4), reads the bounded identity response from the recipient context before the helper serves any agent call, and matches account, tenant and role itself. Only the target's declared cookies and storage keys move into it; identity-provider cookies, other origins and whole profiles never move, cookies are never rewritten to fit, and state broader than declared or in a format the adapter does not support (such as device-bound sessions) fails the operation. Publication, the moment the agent's tools can reach the context, happens after the grant, cancellation, root, epochs, revisions, deadlines and recipient instance are checked again under one serialised decision:
  - cancel, lock or root exit before publication wins: nothing is published and late worker results are discarded;
  - after publication the session is delivered: ending stops EnvCloak's further actions and closes the context, and a copy already taken cannot be recalled;
  - a failed cleanup stays visible as `cleanup_failed`.
  Status reports the broker stop, local cleanup and server revocation as three separate results; revocation reads verified only when the target declares a revocation call and a copied session is then rejected by the app, otherwise "server session expiry unknown".
- **Cookie scope.** Credential submission is checked against exact origins, but delivered state follows browser rules: cookies are scoped by host and path, not by port, while local storage is origin-scoped. A cookie delivered for a loopback target can reach another service on the same hostname at another port, including through background requests. The receipt says so for shared loopback hostnames; a per-project hostname such as `project-a.localhost` reduces overlap between projects when the app supports it, and is not an isolation boundary.
- **Test-session adapter** (optional; preferred for the developer's own apps). The app exposes a test-only, loopback, authenticated control endpoint that mints a short-lived session for a disposable identity and role. EnvCloak calls it instead of filling a form and delivers the session the same way. EnvCloak ships the protocol and a reference middleware. Projects keep a separate real-login test so login regressions stay covered.
- **Audit.** An intent entry before any credential use and an outcome entry after it: item, target, subject evidence, adapter version and result class. Never values, page titles, URLs with queries or agent-supplied reasons.
- **Hosts.** Installers (§7.2) add one instruction line naming `request_sign_in` as the person's approved credential tool, set the host's per-server tool timeout (Claude Code's default was 10 s when measured), and, only with the person's consent, pre-approve exactly the four sign-in tools, tool by tool (Codex's per-tool `approval_mode`, Claude Code's allow rules by tool name). `run_with_secrets`, `add_reference`, the metadata tools and every browser tool keep the host's own prompt, and a host that offers only server-wide approval gets no setting. The instruction line is a transparent integration note, never a way around a restriction the person or project set. Whether each host calls the tool is measured per host version, model and configuration before release and kept as a compatibility matrix, never assumed.

## 7. Agent integrations

`envcloak agents install [--global] [--project]` detects installed agents and writes idempotent managed blocks (`<!-- envcloak:begin -->` / `<!-- envcloak:end -->`) that `envcloak agents uninstall` removes cleanly.

Global instructions (all agents) say, in short:

1. Never read `.env*` files, never print environment variables, never ask the user to paste a key into chat.
2. If the project has `envcloak.toml`, run anything that needs secrets as `envcloak run -- <cmd>`.
3. If a key is missing, run `envcloak ls` (metadata only) to find it and add a reference with `envcloak ref`; if it does not exist, ask the person to run `envcloak add <provider>` in their own terminal. (From M3, with the app, `envcloak add <provider> --ask` lets the person paste it into the app; the M2 block names only shipped commands.)
4. If a project has plaintext `.env` files and no manifest, suggest `envcloak init`.

Per agent:

- **Claude Code**: a plugin (`integrations/claude-code/`: `.claude-plugin/plugin.json`, `skills/`, `hooks/hooks.json`, `.mcp.json`) distributed through a git marketplace, with hooks:
  - `UserPromptSubmit`: if the prompt contains something that looks like a key, return `decision: "block"` with `suppressOriginalPrompt`, never echo the match, and say that the person can add the key with `envcloak add <provider>` in their own terminal (`--ask` from M3). Claude Code documents that a blocked prompt can still reach the session transcript and prompt history, so this keeps the key from the model, not off disk (§7.1).
  - `PreToolUse` (Bash, Read, Grep, Glob, Edit, `mcp__*`): deny reading `.env*`, dumping the environment (`env`, `printenv`, `export -p`, `set`), `envcloak reveal`, and other secret-printing commands, with a message that says what to do instead.
  - `SessionStart`: inject the names (never values) of the project's available secrets and the one-line usage rule.
  - `permissions.deny` entries `Read(**/.env*)`, which Claude Code also applies, best effort, to `@file` mentions that `PreToolUse` never sees.
  - Sandbox settings in the user's `~/.claude/settings.json`:
    - On macOS, add EnvCloak's socket path to `sandbox.network.allowUnixSockets`; otherwise sandboxed Bash cannot reach the daemon.
    - On Linux the sandbox can only allow every Unix socket (`allowAllUnixSockets`), so the installer asks first. It never adds `envcloak` to `excludedCommands`, because that would run every wrapped command outside the sandbox.
    - `sandbox.credentials` deny entries for `EnvCloak/vault` and `EnvCloak/backups` stop sandboxed commands from copying the vault file.
  - Reported as degraded:
    - `disableAllHooks` in user, project, local or managed settings, managed `allowManagedHooksOnly`, and `CLAUDE_CONFIG_DIR` pointing elsewhere;
    - an interactive session in a folder whose workspace trust dialog has not been accepted: Claude Code holds back every settings-file hook until then (`-p` sessions treat the folder as trusted);
    - `--safe-mode`, which leaves only managed hooks, and `--bare`, which skips hooks;
    - hook timeouts, after which the prompt still reaches the model.
    An optional, admin-installed `managed-settings.d/envcloak.json` keeps the hooks on.
- **Codex**:
  - Hooks in `~/.codex/hooks.json`: `PreToolUse` deny and `UserPromptSubmit` block.
  - A managed block in `~/.codex/AGENTS.md`, unless `~/.codex/AGENTS.override.md` exists, which shadows it: then nothing is written and the surface reads `degraded (override_file)`.
  - `~/.codex/rules/envcloak.rules`, with `forbidden` prefix rules for secret-printing commands.
  - The MCP server in `config.toml`, with `env_vars` rather than literal values. The installer writes no approval setting for EnvCloak's tools: Codex documents that destructive MCP tool calls always ask, and a server-wide pre-approval would switch off the host's one check on `run_with_secrets`. Under `codex exec` with approval policy "never", EnvCloak's MCP surface therefore reads `degraded (needs_host_approval)`. From M2b, and only with consent, exactly the four sign-in tools are pre-approved, each with its own `[mcp_servers.envcloak.tools.<tool>] approval_mode` (§7.2 rule 5).
  - A note on `shell_environment_policy`.
  - Non-managed hooks run only after the user trusts them; until then coverage is reported as degraded (`hooks_untrusted`), and so is `[features] hooks = false` or `allow_managed_hooks_only`.
  - `write_stdin` into a running session does not rerun `PreToolUse`, and hosted tools are not covered.
- **Cursor**: `.cursor/rules/envcloak.mdc`, MCP config, and hooks where supported.
- **Gemini CLI, OpenCode, others**: `GEMINI.md` / `AGENTS.md` blocks and MCP config.

MCP tools (never return values): `list_secrets`, `project_status`, `add_reference`, `request_new_secret` (in M2 it takes no value and returns the instruction "the person runs `envcloak add <provider>` in their own terminal"; from M3 it opens the app's paste sheet), `run_with_secrets` (runs a command through a child `envcloak run`, so through the same policy and redaction path; the command runs outside the host's sandbox and holds the injected keys while it runs), `usage_summary` (listed from M4; until then `project_status` says it is unavailable). From M2b: `request_sign_in`, `sign_in_status`, `cancel_sign_in`, `end_sign_in_session` and the allowlisted browser tools (§6.8). Reveal and doctor are never tools. `list_secrets`, `project_status` and `request_new_secret` carry `readOnlyHint`; `run_with_secrets` carries `destructiveHint` and `openWorldHint` and never `readOnlyHint`; no tool carries both. Annotations are hints a host may ignore: whether each host prompts is tested against the real hosts. The MCP server refuses, before contacting the daemon, `run_with_secrets` argv that the `PreToolUse` hook would deny, with the same message.

### 7.1 Coverage reporting

Installing an integration is not the same as being protected. For each agent and version, `envcloak agents status` reports six surfaces separately: prompt-to-model, transcript, file read, shell, MCP and output. Each surface is one of:

- `active`: a synthetic activation and denial probe passed on this machine for this host version and configuration, and nothing degrades it;
- `degraded`: installed, but it needs trust, can be switched off, or fails open, always with value-free reason tokens: `hooks_untrusted`, `workspace_untrusted`, `switched_off_user`, `switched_off_project`, `switched_off_local`, `managed_only`, `fails_open_on_timeout`, `override_file`, `needs_host_approval`, `outside_host_sandbox`;
- `unsupported`, with its reason where one applies (for example `persists_blocked_prompt`);
- `unverified`, with its reason (for example `not_drivable` for a host the scripted model cannot drive, `probe_needs_terminal` for a probe that needs an approval no terminal can give).

Every surface also reports its probe outcome, separately from its state: `passed`, `failed`, `skipped`, or `not_qualified` (the probe is not qualified for this host version, which is not a failure). For example `degraded (fails_open_on_timeout, workspace_untrusted; probe=passed)`; a failed probe reads `probe=failed` and is listed first, so a reason never hides a broken probe. A hook that times out is taken to let the action through: Claude Code documents that it does, Codex does not say for command hooks, and a host's fail-closed option (such as Cursor's `failClosed`) counts only where a probe on this machine shows a timed-out hook blocking the action. Until such a probe passes, a hook-based surface carries `fails_open_on_timeout` and is never `active`. Output filtering comes only from `envcloak run` redaction, never from hooks. Transcript prevention is claimed only when a probe shows that a blocked prompt was not persisted. Degraders are read from the person's real configuration, every switch the host documents included. Results are kept per host binary, version and configuration digest, and recomputed when any of them changes; a stale result reads `unverified`. An integration whose MCP surface can run commands says that they run outside the host's sandbox (`outside_host_sandbox`), as a qualification result, not an assumption.

Agents come in tiers:
- **Tier 1, Claude Code and Codex:** installer, activation and denial probes in CI and on the person's machine, and both acceptance stories.
- **Tier 2, Gemini CLI, Copilot CLI, OpenCode, Kimi Code and Cursor CLI:** installer, and probes only where a documented setting points the host's model traffic at EnvCloak's scripted model in a protocol it serves; every other surface reads `unverified (not_drivable)`. Hook contracts are tested on payloads captured from pinned versions.
- **Tier 3, Cursor IDE, Kimi CLI, Qwen Code, Goose and Aider:** the instruction block and MCP entry where a documented file exists; surfaces read `unverified` or `unsupported`.

Documented capabilities as of 2026-10-01, read from each agent's own documentation (probes decide per machine):

| Agent | Prompt guard | File read / shell / MCP guard | Blocked prompt kept out of local history | Known gaps |
|---|---|---|---|---|
| Claude Code | `UserPromptSubmit` block; in an interactive session only after the folder's workspace trust is accepted | `PreToolUse` deny; `Read()` deny rules, which also cover `@` file mentions, best effort | Unsupported: its docs say a blocked prompt can still reach the session transcript and prompt history | `disableAllHooks` at any settings level, `allowManagedHooksOnly`, `CLAUDE_CONFIG_DIR`, `--safe-mode`, `--bare`; fail-open timeouts; `@` mentions never reach `PreToolUse` |
| Codex CLI | `UserPromptSubmit` block, after the person trusts the hooks | `PreToolUse` deny, `forbidden` rules | Unverified | Untrusted hooks skipped; `[features] hooks = false`, `allow_managed_hooks_only`; `AGENTS.override.md` shadows the instructions; `write_stdin` bypasses `PreToolUse`; hosted tools not covered; MCP tool calls need the host's approval |
| Cursor (IDE and CLI) | `beforeSubmitPrompt` `continue:false` | `beforeReadFile` (which receives the file's contents), `beforeShellExecution`, `beforeMCPExecution`; `failClosed` optional | Unverified | Crashes and timeouts fail open unless `failClosed` is set; user hooks absent in cloud agents; Claude Code's settings-file hooks also run inside Cursor |
| Gemini CLI | `BeforeAgent` deny | `BeforeTool` deny | Documented: a denied prompt is discarded from history; unverified until a probe on this machine confirms it | `AfterTool` hiding cannot undo side effects; shell commands run on a pseudo-terminal; Gemini loads the nearest `.env` into its own process |
| Copilot CLI | Unsupported: `userPromptTransformed` can rewrite a prompt but not block it, and command-hook `userPromptSubmitted` output is ignored | `preToolUse` deny (fails closed on a crash, open on a timeout) | Unsupported | Paste guard never claimed; input typed into a running shell goes through separate tools (`write_bash`) |
| OpenCode | Unsupported: no prompt-rejection contract (v2 can only rewrite) | Plugin `tool.execute.before` (v1) or `execute.before` (v2); `*.env` reads denied by default | Unsupported | Adapter pinned to the plugin API version; whether plugins see MCP calls is unverified |
| Kimi Code / Kimi CLI | `UserPromptSubmit` exit 2 | `PreToolUse` | Unverified | Two products with different data roots (`~/.kimi-code`, `~/.kimi`); timeouts and crashes fail open |
| Qwen Code | `UserPromptSubmit` block for supported sends | `PreToolUse` deny | Unverified | Steer, Cron, Notification, Teammate and Retry sends not covered; safe and bare modes disable hooks |
| Goose | Unsupported: `UserPromptSubmit` only observes | `PreToolUse` | Unsupported (sessions in a database) | Hooks new in the Open Plugins format; unverified |
| Aider | Unsupported: no hooks | Unsupported | Unsupported | Instructions only, through a `read:` entry |

### 7.2 Installer rules

1. Adapters are per product and versioned. The installer detects the installed product and version (for example Kimi CLI versus Kimi Code, or OpenCode v1 versus v2) and writes only that format.
2. Before reporting protection as active, the installer runs synthetic activation and denial probes in an isolated HOME.
3. Hook payloads are scanned locally and deterministically, never sent to a model. Block reasons and diagnostics never echo matched text. Hook input and output are bounded and time-limited.
4. An agent with the user's shell can bypass advisory integrations; §1.1 and §10 say so.
5. Host approval is set per tool, never per server. Where the product has sign-in tools (§6.8), the installer writes one instruction line naming them as the person's approved credential tool, raises the host's per-server tool timeout for EnvCloak, and only with the person's consent pre-approves exactly the four sign-in tools, each by name, where the host offers per-tool approval. It never pre-approves `run_with_secrets`, `add_reference`, the metadata tools, a browser tool or any tool of another server, writes no approval setting at all in M2, and gives a host that offers only server-wide approval (Gemini's `trust`) none; a person may set host approval for a tool by hand, and `envcloak agents status` then reports it.

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
  - wildcards under a multi-tenant suffix, from a list kept in-repo (`supabase.co`, `workers.dev`, `vercel.app`, `herokuapp.com`, `netlify.app`, `amazonaws.com` and others);
  - in M1, every other wildcard host: without a pinned Public Suffix List the loader cannot tell a provider's domain from wildcard DNS, tunnel or free-subdomain services (`*.nip.io`, `*.lhr.life`, `*.eu.org`), so each host is listed until a snapshot is embedded.
- Tenant hosts are stored per item (for example `acme.supabase.co`).
- Each item snapshots its allowed hosts at creation. A registry update that widens them requires approval.
- Local registry overrides require an approval proof and show the hosts.
- Adapters never follow redirects.
- Any change to `allowed_hosts`, `auth` slots or `denied_paths` needs two maintainer reviews: CODEOWNERS names the owners of the registry, its loader, detection and their tests, and `main`'s branch protection requires code-owner review and 2 approvals (an M1 release blocker, §14).

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
| Environment markers, argv and the command name | Caller-asserted | Labels and tightening only |
| "No agent is involved" or "a human typed this" | Cannot be claimed | Nothing |
| Project path | Caller-asserted; the daemon reads the manifest itself | Grant scoping together with the subject root |

The ancestry walk records pid and start time for each ancestor, then re-validates the chain: each parent started no later than its child, and each ancestor still has the recorded start time. An orphan reparented to launchd, init or a subreaper has lost its ancestry, which fails closed: it is not a terminal subject and its proofs are refused. So does a chain cut at the walk's depth limit (64 processes): an agent may be above the cut, so the caller is not a terminal subject and its proofs are refused. Agents are recognized by executable path, `argv[0]`, interpreter script, command name and, on macOS, code signature, from a builtin catalog plus add-only user extensions (docs/AGENTS.md). A match on `argv[0]`, the script, the command name or a name other programs share (the catalog's `names`) is caller-asserted: it makes the caller an agent subject, but only a builtin match on the executable path or code signature selects a grant root above the caller's session (§10b). An interpreter's path or signature is never an agent's identity.

**Bounds and display.**
- Frames are limited to 1 MiB.
- At most 3 pending approvals per subject root, and 20 per daemon.
- A request identical to one denied in the last 10 minutes is denied without a prompt.
- 3 denials for one root within 10 minutes auto-deny that root for 30 minutes, whatever it asks (requests a grant it holds would cover included), and send a notification.
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
  mode: proxy | inject | helper(kind) | sign_in(scope)                  # sign_in: §6.8
  uses: once | session
  not_after: min(wall-clock UTC deadline, monotonic deadline)
  approval: ApprovalProof
  vault_epoch, policy_epoch
}
```

**Root selection.** If a known agent is in the caller's ancestry, the root is the agent process nearest the caller. Otherwise the root is the caller's session leader (`getsid`). If the session leader is no longer alive, the root is the topmost live ancestor in that session. pid 1 is never a root, nor a session leader for this rule; a known agent that is pid 1 (in a container) still makes the caller an agent subject. An agent that only a user extension recognizes, or that is recognized only by its `argv[0]`, script or command name, is the root only at or below the process the session rules would pick.

**Subject kind.** `agent` when a known agent is in the ancestry; `unknown` when the ancestry no longer reaches the caller's session leader (an orphan), or the walk was cut at its depth limit (§10a) with no known agent below the cut, whatever the caller claims; `agent` when the caller claims agent markers; `unknown` in a session without a controlling terminal; otherwise `terminal`. docs/AGENTS.md has the details.

**Match.** Request R is covered by grant G only if all of these hold:
1. G is not expired, revoked or used up.
2. The vault is unlocked at G's epoch.
3. R's kernel-verified ancestry contains G's root instance, with both pid and start time matching. A recycled pid never matches.
4. Agent barrier: no known agent sits strictly between G's root and the caller, unless the root is that agent. A grant approved for a terminal subject covers only terminal subjects. A root above the caller's session is an agent the builtin catalog recognizes by its executable path or code signature; any other root covers only callers in its own session, on every system: a grant rooted at a GUI app, a desktop shell, a `launchd` job or a `tmux` server never covers the sessions it starts.
5. R's canonical project directory, and its device and inode, equal G's.
6. R's bindings are a subset of G's bindings, compared by (env_name, item_id, field); for a managed project, the paragraph below applies too.
7. R's effective mode is at least as strict as G's.

For a managed project (§6.6), a request is covered only when it names the project's registered launch (or, for a bridged HTTP server, its registered origin and header names), and the daemon's check of that launch passes before any pending request or grant lookup: the executable, its identity, the working directory and, for a script, the entry file must equal what was registered with a proof. A covered request's values are never returned to the requesting process: the daemon starts EnvCloak's own runner (or HTTP relay), which receives them and starts the checked executable with the registered argv, working directory and environment, never the caller's. A grant or standing approval covers only the launch revision it was made for. A changed launch is refused and must be re-registered by the person. A launch whose code EnvCloak can check only at rest (interpreter scripts, package runners) gets once and session approvals, never standing approvals.

A sign-in request (§6.8) is matched differently: only by a `sign_in` grant whose scope is exactly equal to the request's, field for field, after rules 1 to 4; roles have no ordering, and no inject, proxy or helper grant covers it, nor a sign-in grant any of those.

A manifest change that leaves the bindings a subset does not prompt; the new hash is recorded in the audit log. Any added or changed binding, env-name remapping, profile switch, `--ref` or `--env-file` reference prompts for the difference: the statement asks for the bindings no grant in force for the caller and project covers, and lists the ones a grant already covers apart, since the new grant holds the whole request.

**Lifetimes.**
- Agent grants: default 8 h, maximum 24 h when the root is a known agent process in the caller's ancestry.
- Terminal grants: maximum 12 h. Unknown grants take the same maximum: missing evidence gets the tighter bound. So do agent grants whose root is not a known agent (an agent subject by its claims alone, such as `CLAUDECODE=1` set in a person's shell): claims only label and tighten.
- A grant never outlives its root process.
- Grants live only in daemon memory and are never persisted or synced.

**What a grant means.** A grant authorizes a process tree, not a person or a model. Everything inside that tree during the window gets the bound values in the bound mode: prompt-injected turns, package install scripts, test code, and files in the project that another program changed. What narrows it is the root instance, the key list, the mode and the time window.

**Approval proofs.**
- The daemon records every request that no grant covers as a pending request `{request_id, daemon_nonce, subject evidence, project, bindings, mode, uses, ttl, live flags, new project, first use, argv}`.
- Request ids are 8 Crockford base32 characters, unique among pending requests. Pending requests expire after 10 minutes.
- macOS with the app (M3): the app renders every field, computes SHA-256 over the canonical encoding of exactly what it rendered, and signs it with the Secure Enclave `approve` key, using a fresh `LAContext` with reuse duration 0. The daemon verifies the signature with the pinned public key and checks that the statement equals its pending request.
- Linux, and macOS without the app: the human runs `envcloak approve <request_id> [--once | --for <duration>] [--live <ENV_NAME>]...` in a terminal they control, reads the same statement, and enters the vault passphrase on `/dev/tty` (or `--passphrase-fd`). The daemon verifies the passphrase against the envelope.
- **Approval signing key without a Secure Enclave (M5).** From M5, on Linux, and on macOS without the app, each device has an Ed25519 `approve` key generated at vault creation or pairing. Before M5 nothing replicates, so no record is signed: the standing approvals of M2 are sealed, integrity-covered and local, and keep a slot for the signature M5 adds before any record replicates. Its private key is stored only inside its own Argon2id envelope under the passphrase (not under the VMK), so it is usable only when the passphrase is presented. For each approval that must be recorded or replicated (policy, registry overrides, device add or remove, revocation), the daemon unwraps it with the presented passphrase, signs the canonical statement, and wipes it. The public key is pinned in the device record at pairing. This is weaker than a Secure Enclave key: the envelope can be guessed offline from a copy of the vault, and the key is briefly in daemon memory, so peers display which kind of key signed a record. Gates: Linux-to-macOS and Linux-to-Linux pairing, policy replication and revocation succeed with passphrase-signed records, and a record signed by any other key is rejected.
- A y/n answer is never an approval. Approval input is never read from the requesting process's terminal.
- The daemon takes a proof (approve, unlock, rotate, remove, reveal, recover) only from a terminal subject (Subject kind, above), and refuses it from every other caller: one with a known agent in its ancestry, agent markers in its claims, an ancestry that no longer reaches its session leader (an orphan; docs/AGENTS.md), a chain cut at the walk's depth limit (§10a), or no controlling terminal (a job a service manager starts, such as `launchctl submit` or `systemd-run --user`, and a process that forked out and called `setsid`: neither an agent's nor an orphan, yet started from anywhere, an agent's tree included). An approval surface does not show a pending request to a caller whose proof it would refuse, so no prompt appears where none is taken. This only tightens.
- Honest limits:
  - A passphrase typed into a terminal that an agent controls can be captured by that agent.
  - A captured passphrase is not made useless by the refusal. A program running as you can start a session with a pseudo-terminal of its own outside the agent's tree (`script` or `tmux` run through `launchd`, `systemd --user` or a double fork), where it is a terminal subject; and the passphrase opens a copy of the vault file anywhere. The refusal keeps an agent from getting an approval, or showing a prompt, in its own tree.
  - On Linux and unsigned builds, a program running as you can impersonate the daemon.
  - On macOS, `userPresence` accepts the login password.

**Passphrase attempts.** Failed proofs share one limiter. After 5 failures, each further attempt waits 30 seconds, doubling up to 1 hour, and `envcloak status` reports the failures. Offline guessing against a copied vault file is limited only by Argon2id and the passphrase itself.

**Writes that need a proof.** These need an approval proof:
- replacing a secret's value (`rotate`);
- deleting an item or field;
- loosening vault policy for a project;
- registry overrides;
- adding or removing unlockers;
- creating standing approvals, and confirming them (below);
- registering or updating a managed MCP server (§6.6);
- restoring a file backup (§6.4);
- reclassifying an item towards `test` or `unknown` (M2), which loosens the live-key guard and, towards `test`, what a standing approval can cover.

Adding a new item needs none, because nothing is bound to it yet. Replaced values are kept as up to 3 sealed prior versions. Removing an item (`envcloak rm`) first writes an encrypted backup of the vault, which keeps its values for `envcloak recover`; when the backup cannot be written, nothing is removed.

**Standing approvals (M2).** A standing approval creates session grants automatically for one agent's code identity in one project, for up to 30 days. It covers test-classified keys only; live keys, and keys classified `unknown`, are never standing. It is created only from a real pending request of an agent subject, with `envcloak approve <id> --standing <duration up to 30d>` and a passphrase proof from a terminal subject under the rules above. The identity is the kernel's view of that request's nearest agent, never a path or name a program can copy: on macOS its code signature (Team ID and signing identifier), on Linux the SHA-256 of its executable. Only a builtin catalog match on the executable path or code signature qualifies; an agent launched by an interpreter, recognized only by a user extension, or asserted by its name or markers is refused (`identity_not_standing_capable`). So is an agent whose own executable runs other code when a variable is set in its environment, while that agent process's environment sets one: the catalog lists those variables per agent as measured on its pinned builds (`BUN_OPTIONS` for Claude Code's native build, `BUN_BE_BUN` for OpenCode). A program already running inside the agent can clear such a variable from its own environment; docs/AGENTS.md lists this among the limits. On Linux a builtin match is still a path match, so the statement shows the executable's path, its SHA-256 and whether EnvCloak recognizes the digest as a release of that agent (from the digests CI observed for pinned releases) or calls it an "unrecognized build", as a warning line above the passphrase prompt; creation is refused (`identity_outside_install_tree`) when the path is outside that agent's documented install trees. For a managed project the record names the launch revision it was made for, and only a `bound` launch can have one (`launch_not_standing_capable`, §6.6). A standing approval never covers a terminal or unknown subject. The terminal statement, and from M3 the app, labels it: "any <agent> session in this project, including one started by another program, gets these keys without asking."

Standing records are sealed in the vault. The set of them carries a generation, which a sidecar file outside the vault (`<data>/policy-epoch`) also holds; a create or revoke is acknowledged only after both are durable. When the vault is behind the sidecar (an older vault file put back), or the sidecar is missing or damaged after a record was ever written, every standing record is refused (`policy_epoch_unverified`) until the person runs `envcloak standing confirm`, with a passphrase proof, over a statement listing every record. Restoring older copies of both the vault and that file brings a revoked record back for the rest of its 30 days: a program running as you can do so, and without an anchor (Linux, and macOS before M3; §5 "Integrity") nothing detects it. `envcloak standing rm` says so, and revoking a standing approval bumps the policy epoch, which ends the grants it created.

**Live-key guard (M2).** Agent and unknown subjects receive live-classified bindings only when each live binding is individually ticked on the approval; an approval whose statement holds an unticked live binding creates no grant and is refused with `live_not_ticked`. When both a test and a live item exist for a provider, the test item is proposed: the statement and the `approval_required` text name the same provider's test item and the `envcloak ref` line that binds it, and the daemon never substitutes an item. A key classified `unknown` is not live-guarded and is not a test key. The statement that carries classifications, ticks and proposals is `envcloak-statement/2`.

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

XChaCha20-Poly1305 (`chacha20poly1305` 0.11), Argon2id (`argon2` 0.6), HKDF-SHA256 (`hkdf` 0.13), BLAKE3 keyed hashing (`blake3`), HPKE RFC 9180 (`hpke` 0.14, with cross-implementation vectors against CryptoKit), P-256 ECDSA verification of Secure Enclave signatures (`p256`, `ecdsa`), X25519 (`x25519-dalek`) and, from M5, Ed25519 (`ed25519-dalek` 3.x, whose `curve25519-dalek` 5 dependency compiles a proc-macro crate on x86_64 that the proc-macro allowlist must first admit by review), SPAKE2 (`spake2`, pinned and wrapped; no independent audit, so it is in the pre-1.0 audit), iroh 1.x for transport, `zeroize` and `secrecy` plus a zero-on-free global allocator for memory, `rusqlite` with bundled SQLite for storage, `aho-corasick` for redaction, `rustls` 0.23 with `rustls-webpki` 0.103.12 or later and `rcgen` for proxy mode, `ureq` 3 with default features off, over `rustls` 0.23 (the `ring` provider) and `rustls-platform-verifier`, as the HTTPS client of `mcp-bridge`'s relay (linked into `envcloak`, never into `envcloakd`), a hand-written MCP server (newline-delimited JSON-RPC on `serde_json`: `rmcp`'s server feature brings token-pasting and code-generating proc-macros and an async runtime the workspace does not use), `sha1` 0.11 and `hmac` 0.13 for TOTP (M2b), `nix` and `libc` for Unix interfaces, and `security-framework` 3.x on macOS for code-signing checks and keychain items. The RustCrypto major versions released in 2026 are adopted together across the workspace. There is no `keyring` crate in v0.1, and no `url` or `idna` crate: `idna` brings ICU4X, whose proc-macros the allowlist refuses, so origins are parsed as ASCII (§6.8). A new dependency passes `cargo deny`, `scripts/check-sources.sh` and its `cargo tree -e normal,build` review before it lands. Secure Enclave and LocalAuthentication are used from Swift in the app.

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
| M1 | Core vault and crypto (sealed rows, integrity digest, passphrase and Recovery Kit unlockers, encrypted backups); minimal daemon (socket hygiene, peer checks, lock and unlock, caller evidence, grants, passphrase approvals, audit); CLI (`vault create`, `unlock`, `lock`, `status`, `init`, `import`, `add`, `ls`, `show`, `ref`, `check`, `run`, `rotate`, `rm`, `approve`, `grants`, `backup`, `recover`, `recovery confirm`, `audit verify`, `daemon install`); redactor integration in pipe mode; provider detection | The fixture acceptance story (§15.1) and every M1 gate pass on macOS and Linux CI; release blocker: `main`'s branch protection requires a pull request, review from code owners and 2 approving reviews (§8 "Registry safety"), which a repository admin sets |
| M2 | PTY run mode, full agent catalog, live-key guard, standing approvals, reveal on the terminal, MCP server, agent installers with activation probes and coverage reporting (§7.1), `doctor`, `scrub`, `migrate-mcp` with `mcp-bridge`, machine-wide first-run scan and import | Claude Code and Codex run the fixture project via EnvCloak with no value in any transcript; every M2 gate passes |
| M2b | Dev sign-in (§6.8): login items and TOTP engine, sign-in worker and login state machine, identity check, sign-in scope and approval contract, session delivery through EnvCloak's hosted browser tools, test-session adapter protocol and reference middleware, sign-in tools and grants, installer wiring | Claude Code and Codex, each with the installer's instruction line, sign in to the fixture app (password and TOTP) and through the test-session adapter, with no value in any transcript; every M2b gate passes |
| M3 | macOS app: signed helper, Secure Enclave unlock and signed approvals, paste sheet, clipboard, first-run scan screen, keys, projects, activity, install CLI, login item, keychain rollback anchor | Manual QA script passes on a clean user account; every M3 gate passes |
| M4 | Spend and money: key-attributed balance, spend and expiry adapters (CodexBar output as optional input), cards, subscriptions, budgets with separately labeled controls, alerts, forecasts | Adapters show live data for the fixture providers; every spend control is labeled with what it stops |
| M5 | Pairing, transfer, sync over iroh; VMK epochs and revocation; new-machine bootstrap | Two machines pair with a code and converge after concurrent edits; every M5 gate passes |
| M6 | Proxy mode | A placeholder-only child reaches a provider API; a non-allowlisted host gets the placeholder; every M6 gate passes |
| M7 | Packaging and release: Developer ID certificate created by the Account Holder, app and helper profiles, signed and notarized app, Homebrew, cargo-dist binaries, docs site, landing page with Cloud waitlist | `brew install --cask envcloak` works on a clean Mac |
| M8 | Launch (v0.1: Keys + Spend + Dev sign-in) | Public repo, launch posts, directory listings |
| M9 | v0.2: MCP servers module, Auth module (inventory, AWS credential_process, git and Docker helpers, AWS multi-account IAM view), browser capture extension, rotation assistant, sign-in beyond dev (real websites, native CLI login coordination starting with gh and Docker, email one-time codes) | MCP set installed into four agents from one list; no static AWS keys left on disk |
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
    - Proofs from an agent-descended caller are refused, and so are proofs from a caller without a terminal session (a service manager's job, `setsid`).
24. Manifest self-authorization. A fixture repo with loosening policy plus a scripted agent still needs approval, and redaction stays on.
25. Evidence forgery.
    - A known-agent fixture under `env -i` is still classified by ancestry.
    - A terminal grant does not cover it.
    - `CLAUDECODE=1` in a human shell only tightens.
26. Ancestry escape. A process escapes by double-fork, `setsid`, `nohup` with `disown`, `launchctl submit` or `systemd-run --user`. The escaped process is not covered and gets a new request labeled "unknown".
27. PID reuse. After the root exits and its pid is reused, the new process is not covered.
28. Binding changes after approval.
    - An added reference, a retargeted env name, a renamed env var, a profile switch, or `--ref` or `--env-file` naming an ungranted item each prompt for the difference: the statement asks for exactly the bindings no grant in force covers.
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
    - Activation and denial probes run in an isolated HOME for each agent whose host the scripted model can drive in CI (Claude Code and Codex, and any tier-2 host the drivability check of §7.1 qualifies); every other agent reports each surface `unverified` with a reason token and never `active`.
    - Untrusted Codex hooks are reported as degraded, and Copilot's prompt guard as unsupported.
    - A probe checks whether a blocked prompt reaches Claude Code's history or transcripts.
39. migrate-mcp. No literal secret remains in the MCP server entries of the covered agents' JSON and TOML configs (Claude Code, Codex, Cursor, Gemini CLI, Copilot CLI, Kimi, OpenCode); YAML configs, key-shaped `args` literals and stores that hold an agent's own credentials are reported as manual and the command exits non-zero. HTTP servers use `mcp-bridge`. Writes are atomic, with encrypted backups. Only a managed server's registered launch receives its key: a launch whose executable was replaced is refused, and a `bound` launch whose executable is rewritten in place after the daemon's last check runs the checked image, never the rewritten one.
40. Live-key guard. A live binding without a per-binding tick is refused. The test item is proposed first. A standing approval cannot include a live key.
41. End-to-end story with Claude Code and Codex, on macOS and Linux. Afterwards, no fixture appears, raw or in any §6.1 encoding, in any store the hosts document that can hold a pasted or printed value, in the isolated HOME: `~/.claude/projects/**` (with `tool-results/`, `subagents/`, and orphaned and superseded files), `~/.claude/history.jsonl`, `paste-cache/`, `file-history/` and `~/.claude/backups/`; `~/.codex/sessions/**`, `archived_sessions/**`, `history.jsonl` and `log/`. The sweep reports raw counts and finds a planted positive control. In CI the real, pinned Claude Code and Codex binaries run against a local scripted model, which records every request it receives; real models are measured separately (nightly and before a release). Before a milestone is released, each tier-1 host makes at least 20 real-model runs, with the same sweep after each. A fixture found in any of those runs holds the release, and so do fewer than 20 runs for a host. A low use rate does not: a host that used EnvCloak instead of reading `.env` or typing a password in fewer than 80% of its runs is published as "not reliably used" in the compatibility matrix.

M2b:
- Wrong target. An unregistered origin, an IDN lookalike, a userinfo URL, a changed port, a cross-origin iframe, a mid-login redirect and an off-origin form action each receive zero credential submissions, counted by the fixture server.
- Worker separation. The worker has no debugging port and EnvCloak creates no endpoint to it; a CDP client the agent starts cannot reach it through any endpoint EnvCloak created. The agent's browser tools never receive a filled credential form. Same-user debugger, memory and file access are out of scope (§10) and are not claimed by this gate.
- Output containment. No password, seed or code in tool results, errors, stdout, stderr, logs, audit or permitted artifacts, raw or in any §6.1 encoding.
- Boundary honesty. A session delivered to the agent browser can be exported and reused (expected, and documented), and after `end_sign_in_session` it is gone from that context.
- State allowlist. With extra identity-provider cookies, other origins and seeded storage in the worker, only the declared state reaches the agent context; an unsupported format fails.
- Wrong identity. A login that lands in another test account or tenant delivers nothing. A transfer the browser accepts but the app rejects, and a wrong or expired recipient context, never report active; the recipient context is removed.
- Scope and retries. Concurrent calls with one key and scope give one statement, at most one password submission and one published context. A retry after a lost response, with a fresh MCP request id, recovers the same operation with no new submission. The same key with any one scope field changed gets `request_conflict` and leaves the old statement and reserved context unchanged. A new key with another role, project or recipient never uses an earlier proof or standing authorization. A target edit or browser replacement while a proof is checked refuses the stale proof, and nothing reaches the changed target.
- Standing budget. Polls, retries, new keys and parallel calls never add attempts to a `dev` authorization or extend its deadline.
- Publication race. Cancel, lock or root exit at a barrier before publication leaves no context reachable through EnvCloak's browser tools, and the late result is discarded. Publication followed by cancel with a forced close failure reports delivered and `cleanup_failed`, and does not claim revocation.
- Stop outcomes. Broker stop, local cleanup and server revocation are tested and reported separately; revocation reads verified only after a copied fixture session is rejected by the fixture app.
- Cookie scope honesty. A delivered host-only fixture cookie reaches another port on the same hostname, including by background fetch (the documented limit); a different hostname and a fresh context receive nothing; local storage stays per origin; the receipt for a shared loopback hostname states the limit.
- No retained authority. After an attempt, and across lock, expiry and daemon restart, EnvCloak retains no reusable worker-owned trust, refresh or session state: no worker process, profile directory or control channel remains, and no captured state is held outside a published recipient context. Deliberately delivered application state follows the delivery and stop-outcomes contract (§6.8) and is tested by the boundary-honesty and stop-outcome gates; this gate does not require the app to reject a delivered session.
- Handoff channel. A CAPTCHA or other handoff state stops the attempt with `handoff_required` and is never bypassed, and no view or capture of the worker reaches the agent's browser tools, screenshots or recordings. (With the app, M3, the live view of the worker appears only on EnvCloak's human surface.)
- Approval and concurrency. A changed target, adapter, role, subject or recipient cannot reuse a proof; concurrent once requests yield at most one attempt.
- TOTP. RFC 6238 vectors (SHA-1, SHA-256, SHA-512; 6 and 8 digits), step boundaries, serialised concurrent attempts, and no reuse of a submitted code.
- Attempt budget. A wrong password stops after one submission and wrong codes after two; nothing is resent in a loop.
- Cancellation and lock. Lock, sleep, root exit, timeout, daemon restart and cancel during approval or handoff tear the attempt down and prevent any late delivery.
- Typed fields. `run`, `ref`, the helpers, the proxy and the MCP resolvers refuse login fields.
- Test-session adapter. The reference middleware is off outside test configuration and refuses unauthenticated and cross-origin requests; minted sessions expire on the server.

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
