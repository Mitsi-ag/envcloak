# Spend, subscriptions, budgets, alerts and cards (`envcloak-spend`, `envcloak-poll`)

Status: M4 architecture, decision index and gate skeleton, opened by task M4-01 (SPEC §2a-bis, §4.3, §4.4, §5, §6.3, §6.7, §7, §8, §10b, §11, §14, §15.2 gates `s1` to `s11`; M4 plan decisions `D4-01` to `D4-29`, kill criteria `K4-01` to `K4-17`). Nothing below is built yet; later M4 tasks replace each section with its implementation and test references as it lands.

## 1. Boundary and crates (`D4-01`, `D4-02`, `D4-03`, `D4-27`)

- `envcloak-spend` depends only on `envcloak-core`. It holds the pure money representation (`Money`: minor units plus an explicit ISO 4217 currency code, `D4-08`), spend records (`SubscriptionRecord`, `BudgetRecord`, `AlertRuleRecord`, `ManualFactRecord`, `ControlFactRecord`, `SpendSnapshot`, `AccountLinkRecord`, `D4-09`), roll-up, provenance (`D4-10`), five-control table (`D4-07`, `D4-28`), budgets (`D4-17`), alerts (`D4-16`), attribution (`D4-19`) and payment-card health (`D4-11`) rules, with no network, no IPC and no process execution.
- `envcloak-poll` depends on `envcloak-core`, `envcloak-ipc`, `envcloak-providers` and `envcloak-sys`. It is linked into the `envcloak` binary (which hosts the `envcloak spend-poller` helper, `D4-03`, `D4-27`) and never into `envcloakd`.
- `envcloakd` never opens a network socket (`SPEC §4.4`, `D4-03`, gate `s4`). For every scheduled or on-demand poll, `envcloakd` writes a durable `spend_poll` (`60`) audit entry first (`SPEC §3` principle 4, `D4-13`), spawns a one-shot `envcloak spend-poller` child (`Role::Poller`) over an inherited socketpair (`poller` channel: `PollJobFrame`, `PollResultFrame`, `PollAbort`), verifies its executable identity via `checked_spawn` before writing the key (`D4-03`, `R-M4-06`), receives a bounded `PollResult` (never raw response bytes, `D4-03`, `D4-04`), writes `spend_poll_result` (`61`), and reaps the helper.

## 2. Vault storage and item classes (`D4-06`, `D4-09`, `D4-11`, `K4-16`)

- Vault schema version stays `2` (`D4-09`, `K4-04` verdict `held` in §5, `K4-16`).
- Spend state is stored in the `policies` table (`TableTag::Policies` = 3, `FieldTag::Policy` = 7) as seven `PolicyKind` variants (`5` to `11`, `M4-02`, `crates/envcloak-core/src/vault/policy/`):
  - `5` `subscription` (`SubscriptionRecord`)
  - `6` `budget` (`BudgetRecord`)
  - `7` `alert_rule` (`AlertRuleRecord`)
  - `8` `manual_fact` (`ManualFactRecord`)
  - `9` `control_fact` (`ControlFactRecord`)
  - `10` `spend_snapshot` (`SpendSnapshot`, 35 daily buckets, capped at `48 KiB`)
  - `11` `account_link` (`AccountLinkRecord`)
- **Downgrade behaviour (`D4-09`, `D4-11`):** an M4 vault containing any policy record of kinds `5` to `11` opens read-only (`Integrity::Tampered(TamperKind::RowInconsistent)`) in an older M2 or M3 build because unknown policy kinds are refused like tampering (`VAULT.md` "Policy records"), while still serving secret items and values for owner recovery; an M4 vault holding a `card` item (item record version 4, `D4-11`) does not unlock in an older build at all. Both are stated in the release notes.
- Usage credentials (`ItemClass::UsageCredential` = 5, `M4-19`, `D4-06`) hold organization or admin read keys. Only the poller job builder opens a `usage_credential` through its typed reader; `run`, `mcp`, `mcp-bridge`, `signin` and `reveal` refuse it at the type boundary (`usage_credential_refused`, gate `s6`).
- Payment cards use M1's baseline `ItemClass::Card` = 2 with item record version 4 (`FieldTag` 17 `card_meta`, 18 `card_number`, 19 `card_cvv`, and keyed-hash domain `envcloak/v2/card-number` under the `card` subkey when the card number opt-in is on; `M4-15`, `M4-16`, `D4-11`, `K4-16`). By default only metadata is stored; full PAN and CVV require explicit opt-in (`card.optin`), cannot be opened outside the card reveal path (gate `s1`), and are revealed only in the signed macOS app through `app.reveal` (`envcloak-reveal-statement/1`, or `envcloak-reveal-statement/2` if `M4-23` requires it; `D4-12`, gate `s2`).

## 3. Poller transport, provider scope and method-aware denial (`D4-02`, `D4-04`, `D4-21`, `D4-24`, `D4-29`)

- `envcloak-poll` uses a bounded synchronous HTTPS client (`ureq` 3 + `rustls` 0.23 with `ring` and `rustls-platform-verifier`, `SPEC §8`, `§11`, `D4-04`, `M4-06a`, `M4-06b`): TLS 1.2 or higher with system roots only, `GET` only, no redirects, `10 s` connect timeout, `30 s` total timeout, `256 KiB` response body cap, `Accept-Encoding: identity`, proxy environment variables cleared and ignored, and every request host required to appear in both the compiled-in provider registry and the item's `allowed_hosts` snapshot (`s3`).
- Provider scope in M4 (`SPEC §8`, `§14`, `D4-02`, `D4-24`):
  - Per-key live adapters (`M4-07`, `M4-10`): DeepSeek (`/user/balance`), OpenRouter (`/api/v1/auth/key`, `/api/v1/credits`), Moonshot (`/v1/users/me/balance`), and GitHub key expiry (`GET /rate_limit` reading the `GitHub-Authentication-Token-Expiration` response header).
  - Usage-credential live adapter (`M4-08`, `M4-20`, conditional on `M4-08`'s spike and `K4-02`): OpenAI (`providers/openai-admin.toml`, `class = "usage_credential"`, `GET /v1/organization/costs` and `GET /v1/organization/usage/completions`).
  - Manual fields and billing links only in M4 (`D4-02`, `D4-24`): Anthropic, Google / Gemini, AWS, Stripe, Groq, Mistral, Cloudflare, xAI and Fireworks.
- Method-aware denial (`D4-06`, `D4-29`, gate `s6`):
  - Usage-credential provider files declare `methods = ["POST", "PUT", "PATCH", "DELETE"]` on denied entries alongside `denied_paths`, and allow `{id}` path templates checked against `^[A-Za-z0-9_-]{1,64}$` before substitution.
  - An in-code never list of `(method, path)` pairs (`POST /v1/organization/admin_api_keys`, `DELETE /v1/organization/admin_api_keys/{id}`, `POST /v1/organization/projects/{id}/api_keys`, `DELETE /v1/organization/projects/{id}/api_keys/{id}`, `POST /v1/organization/invites`, `POST /v1/organization/users/{id}`) refuses to load any adapter whose allowed paths intersect it (`s6`).
- `envcloak spend codexbar` (`M4-18`, `D4-21`) runs a pinned CodexBar binary verified by code identity (`cdhash` and Team ID on macOS, SHA-256 on Linux) with an empty environment plus `PATH` and `HOME` set to a fresh empty temporary directory (`0700`), caps output at `1 MiB`, ingests only `source: "api"` rows, and records them as `client_reported`.

## 4. Five-control table, hard-cap rules and honest limits (`D4-07`, `D4-13`, `D4-14`, `D4-22`, `D4-28`)

- Every budget and spend surface renders the five-control table from one shared table in `envcloak-spend` (`SPEC §2a-bis`, `§8`, `D4-07`, `D4-28`, gate `s7`), with columns `Control`, `Enforced by`, `Stops`, `Does not stop` and `Availability`:
  1. `Provider hard cap` (`Available` when a fresh enforcing cap is recorded; `Unverified` or `Manual` otherwise)
  2. `Prepaid balance` (`Available` when polled or manually recorded)
  3. `EnvCloak soft budget & alert` (`Available` in M4; alerts only, never blocks `envcloak run`)
  4. `EnvCloak grant / lease cap` (`Not in this release` in M4; `M5`+)
  5. `EnvCloak proxy rate / spend breaker` (`Not in this release` in M4; `M6`+)
- A control qualifies as a `hard cap` (`SPEC §2a-bis`, `D4-07`, gate `s7`) only when all four conditions hold: (1) the provider enforces it by rejecting requests or ending prepaid credit, (2) its amount is in the budget's currency (`currency_mismatch` otherwise), (3) its amount is less than or equal to the budget and covers every key the budget counts, and (4) the figure was read within the last `26 hours` (`stale_figure` otherwise).
- Honest limits (`SPEC §10b`, `D4-13`, `D4-22`):
  - `D4-13`: `spend.poll.enable` refuses callers whose peer evidence names an agent (`human_only`), while a detached process started outside the agent's process tree has `terminal` subject evidence and can enable polling.
  - `D4-22`: callers with agent evidence receive project-scoped, email-free spend views and card `slug`, `brand` and `last4` only (`s9`), while an agent caller that can read another project directory on disk can pass that directory's path to request its project-scoped summary.

## 5. Risk verdicts and kill-criterion placeholders (`m4-plan.md` §5 rule 1, §8 `R-M4-01` to `R-M4-51`)

| Task | Kill criterion / risk | Status |
|---|---|---|
| `M4-02` | `K4-04`, `D4-09`, `R-M4-03`..`R-M4-05`: 500-item + 1/10/50-account snapshot write-cost measurement | **held** (`crates/envcloak-core/tests/spend_write_cost.rs::d4_09_write_cost_measurement_retires_k4_04`, `snapshot_size_stays_under_48_kib_and_oversized_records_are_refused`, `unknown_policy_kind_or_version_opens_vault_read_only`, `sigkill_during_snapshot_overwrite_reopens_at_last_commit`): `1` transaction and `2` rows re-sealed (`1` `policies` row + `1` `header` row) per account update across 1, 10 and 50 accounts; state-digest input hashed per commit with 500 items (`1,001` baseline stamped rows at `58` bytes/row) is `58,116` bytes at 1 account, `58,638` bytes at 10 accounts and `60,958` bytes at 50 accounts (`<= 64 KiB` limit); encoded `SpendSnapshot` is `944` bytes for a 4-key 35-bucket account and `10,164` bytes at the maximum 256 keys and 35 buckets (`<= 48 KiB` limit); schema version stays `2` |
| `M4-05` | `K4-03`, `R-M4-14`..`R-M4-19`: five-control table, 26 h stale-cap rule and single-currency budget math | placeholder (recorded by `M4-05`) |
| `M4-06b` | `K4-01`, `K4-05`, `R-M4-01`..`R-M4-05`, `R-M4-09`..`R-M4-11`: `ureq` + `rustls` egress, 256 KiB cap, no redirects, no proxy env | placeholder (recorded by `M4-06b`) |
| `M4-08` | `K4-02`, `R-M4-12`, `R-M4-13`: OpenAI usage-credential spike and `D4-29` never-list enforcement | placeholder (recorded by `M4-08`) |
| `M4-09a` | `K4-01`, `R-M4-06`..`R-M4-08`: `envcloakd` zero-network-symbol invariant and `checked_spawn` poller pipe lifecycle | placeholder (recorded by `M4-09a`) |
| `M4-18` | `K4-08`, `R-M4-34`..`R-M4-36`: CodexBar code-identity verification, isolated `HOME` (`0700`) and `source: "api"` filter | placeholder (recorded by `M4-18`) |

## 6. Gates (`SPEC §15.2` `s1` to `s11`)

| Gate | Requirement (`SPEC §15.2`) | Tasks |
|---|---|---|
| `s1` | Card values cannot be opened by run, ref, proxy, helpers, MCP, redaction lists or generic comparisons, enforced by types (compile-fail and runtime) | `M4-15`, `M4-16`, `M4-25` |
| `s2` | Card reveal only in the app, one signed proof per reveal; terminal, CLI and MCP refuse | `M4-16`, `M4-23`, `M4-25` |
| `s3` | A poll sends one key only to a host in both the registry and the item's snapshot, over HTTPS, with GET, in a declared header slot; redirects, plain HTTP, query slots, denied paths, proxy variables and foreign certificates send zero key bytes | `M4-06a`, `M4-06b`, `M4-07`, `M4-09a`, `M4-25` |
| `s4` | Poll isolation: audit durable before the key leaves; audit failure sends nothing; lock, sleep and a killed daemon end pollers before they send and nothing polls while locked; no key in any output, log, audit entry, record or error | `M4-09a`, `M4-09b`, `M4-25` |
| `s5` | Hostile provider responses end as result classes with nothing stored but typed, bounded values | `M4-06a`, `M4-06b`, `M4-07`, `M4-24`, `M4-25` |
| `s6` | Usage credentials are never resolvable and admin-shaped values are not stored as secrets silently; when usage-credential adapters ship, they reach only listed GET paths and templates, and never-list (method, path) pairs cannot load | `M4-08`, `M4-19`, `M4-20`, `M4-25` |
| `s7` | Every control on every surface shows enforced by, stops, does not stop and availability from one table; "hard cap" only for a fresh, enforcing cap in the budget's currency, no larger than the budget, covering every key it counts; unshipped controls "Not in this release" | `M4-05`, `M4-11`, `M4-13`, `M4-21`, `M4-22`, `M4-25` |
| `s8` | Manual and client-reported figures and account re-links can only tighten; writes that can silence an alert or hide spend need an approval proof, and are refused to callers with agent evidence before the proof is asked | `M4-03`, `M4-11`, `M4-12`, `M4-16`, `M4-18`, `M4-19`, `M4-20`, `M4-22`, `M4-25` |
| `s9` | Spend records, CLI output, `usage_summary` and errors hold no value, card number or provider text; callers with agent evidence get the project-scoped, email-free view and card slug, brand and last four only, over MCP and the client socket alike | `M4-02`, `M4-03`, `M4-04`, `M4-14`, `M4-16`, `M4-25` |
| `s10` | Doctor and the audit report cards by last four only; Luhn-invalid strings and low-entropy partials are not reported | `M4-16`, `M4-17`, `M4-25` |
| `s11` | Adapters show live data for the fixture providers (§14 done-when) | `M4-07`, `M4-10`, `M4-20`, `M4-25` |
