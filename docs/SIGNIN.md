# Sign-in operations (`docs/SIGNIN.md`)

Status: M2b-05 (`crates/envcloak-signin`, `crates/envcloak-daemon/src/signin/`, `crates/envcloak-cli/src/cmd/signin.rs`).

EnvCloak executes app sign-in operations inside a separate worker profile, verifies the resulting session identity against a declared target policy, and injects only the declared cookies or origin storage into the agent's browser supervisor over a bound control pipe. No username, password, TOTP seed, TOTP code, or adapter key crosses the client IPC socket or enters an agent prompt.

## Sign-in targets

A sign-in target (`PolicyRecord::SignInTarget` in the vault's policy block) binds a project directory (`project_key`), a target name (`<provider>/<env>`), and a role (`identity_check.role`) to:
- a `login`-class vault item (`login_item_id`);
- allowed `app_origins`, `credential_origins`, `identity_provider_origins`, and `callback_origins`;
- an `identity_check` (`endpoint` or `selector`, `locator`, `account`, optional `tenant`, and `role`);
- declared `cookies` (`domain`, `host_only`, `path`, `name`, optional `partition_top_site`, `cross_site_ancestor`) and `storage` (`origin`, `key`);
- `session_format` (`cookies`, `storage_state`, or `adapter`), `tier` (`dev` or `each`), optional `adapter` (`id`, `version`), `approval_lifetime_secs`, `session_lifetime_secs`, and optional `revocation` endpoint.

### Origin rules (D-26)

Every origin in a target (`app_origins`, `credential_origins`, `identity_provider_origins`, `callback_origins`, and `storage[].origin`) is parsed and normalized as `scheme://host[:port]`:
- `https` is accepted for any valid registered host or IP literal;
- `http` is accepted only for loopback hosts (`127.0.0.1`, `[::1]`, or `localhost`), never for a non-loopback hostname or IP;
- userinfo, non-empty paths (other than `/`), query strings, and fragments are rejected with `invalid_params` (`reason: "invalid_origin"`).

When any `app_origins` entry uses a loopback host (`127.0.0.1`, `[::1]`, or `localhost`) or any declared cookie targets a loopback domain, the target view sets `shared_loopback_cookie_jar: true`. Both `envcloak signin target add|edit|ls` and `envcloak approve` print a receipt warning that cookies on a loopback host are shared across every port on that host (RFC 6265 §8.5).

### Target management (`signin.target.*`)

| Method | Role | Proof | Description |
|---|---|---|---|
| `signin.target.add` | `client` | Passphrase from a terminal subject | Adds a sign-in target policy record (`policy_revision = 1`) and increments the vault's `policy_epoch` |
| `signin.target.edit` | `client` | Passphrase from a terminal subject | Replaces a sign-in target policy record, increments its `policy_revision` and the vault's `policy_epoch` |
| `signin.target.remove` | `client` | Passphrase from a terminal subject | Removes the sign-in target policy record and increments the vault's `policy_epoch` |
| `signin.target.list` | `client` | None | Lists sign-in targets for a project (or all projects when `manifest` is omitted), metadata only |

Every target mutation checks all parameters before verifying the passphrase; calling `signin.target.add`, `signin.target.edit`, or `signin.target.remove` with `passphrase: None` runs the pre-proof validation check and returns `invalid_params` without counting a passphrase attempt.

## Operation lifecycle and live `World` verification

`signin.request` opens or joins an idempotent sign-in operation keyed by `(caller_root, operation_key)` in `OperationStore`.

On every store transition (`request`, `statement`, `approve`, `deny`, `worker_captured`, `verify_imported_cookies`, `inject_state`, `record_identity`, `decide_publish`, `check_session`, `status`, `cancel`, `end`, `revoke`, `revoke_all`, `reconcile`), the daemon constructs a `LiveDaemonWorld` that reads live state from:
- the vault slot (`slot_unlocked`): whether the vault is unlocked, the current `vault_epoch` and `policy_epoch`, whether the login item still exists as a `Login` item with matching `authorization_revision`, `tier`, `classification`, and `session_lifetime`, and whether the `SignInTarget` policy record still exists with matching `policy_revision` and `target_hash`;
- the kernel process table (`envcloak_sys::process_exists` and `evidence`): whether the requester root process is still alive, whether the requester's subject chain, agent identity, or terminal attachment changed, and whether the project's `envcloak.toml` digest on disk still matches the operation's `SignInScope`;
- the browser runtime generation counter (`SigninState::browser_generation`).

Any drift in epochs, item revision, target revision, manifest digest, subject chain, or browser generation invalidates active operations and `dev` authorizations immediately, emitting `Effect::TearDown` and sending `ToSupervisor::Close` over the bound control pipe before returning.

## Pipe-origin-bound supervisor messaging

Captured cookie and storage values are held inside the daemon in `SecretBytes` buffers (`CapturedBrowserState`) and are never serialized into any `signin.*` IPC reply (`SigninStatusView` carries metadata only).

1. When `OperationStore` emits `Effect::StartSupervisor`, the daemon creates a `UnixStream::pair()` (`SupervisorPipe`) bound to `(request_id, supervisor_id)`.
2. After the worker captures browser state (`signin_worker_captured`) and the supervisor reports imported cookies (`signin_verify_imported_cookies`, verified in order-independent set equality against the target's declared `CookieScope`s), `signin_inject_over_bound_pipe` calls `OperationStore::inject_state` with `Channel::Supervisor(pipe.supervisor)` and writes `ToSupervisor::InjectState` only over `pipe.daemon_stream`.
3. The supervisor replies over the same pipe with `FromSupervisor::IdentityResponse`, which the daemon feeds into `OperationStore::record_identity` and `OperationStore::decide_publish`, sending `ToSupervisor::Publish` over `pipe.daemon_stream`.
4. Only after the supervisor confirms `FromSupervisor::Check` over `pipe.daemon_stream` does `OperationStore::check_session` mark the operation delivered.

## Approval statements and `dev` authorizations

When a sign-in request requires approval (`Phase::PendingApproval`), it appears in `envcloak pending` with its 32-hex `RequestId` and binding `signin:<target>#<role>=<login_slug>`.

`pending.get` returns `PendingGetOutput::SignIn(SignInPendingDescriptor)` to a terminal prover that does not share the requester's session or terminal. `envcloak approve <id>` renders the canonical `envcloak-signin-statement/1` statement and verifies its SHA-256 digest before checking the passphrase:
- `envcloak approve <id> --once`: grants a single-use `once` authorization (`AuthorizationKind::Once`) for one attempt;
- `envcloak approve <id> --dev <window> [--attempts <1..=5>]`: grants a bounded `dev` authorization (`AuthorizationKind::Dev`, up to 8 hours and 5 attempts) when both the login item and target allow `tier = dev` and `classification = test`.

Active `dev` authorizations are listed in `envcloak grants list` (`mode: sign_in`, `uses: session`) and can be revoked individually (`envcloak grants revoke <AUTH_ID>`) or together (`envcloak grants revoke --all`), which tears down any active sign-in operation covered by a revoked authorization.

## Gates

| Gate | Where |
|---|---|
| `b5`, `b6`, `b7`, `b8`, `b9`, `b10`, `b11`, `b12`, `b14`, `b15`: pure retry/state machine and statement digest invariants | `crates/envcloak-signin/src/` and `crates/envcloak-signin/tests/` |
| Daemon sign-in targets, live `World` invalidation (including negative control against a pinned snapshot), pipe-origin-bound `InjectState`, imported cookie verification, `once` vs `dev` approvals, and audit events | `crates/envcloak-daemon/src/signin/ops.rs` (unit tests) and `crates/envcloak-daemon/tests/signin.rs` |
| CLI `envcloak signin target add|edit|ls|rm`, loopback cookie-jar receipt note, `envcloak pending`, `envcloak approve --once|--dev`, `envcloak deny`, and `envcloak grants list|revoke` | `crates/envcloak-cli/tests/signin.rs` |
