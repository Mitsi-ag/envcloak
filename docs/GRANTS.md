# EnvCloak: grants and approvals

Status: M1. This file fixes how SPEC §10a "Bounds and display" and §10b are carried out: what the daemon keeps for a request, how a grant is matched, how a person approves one with the passphrase, what the approval statement is, and the bounds on prompts and passphrase attempts. The code is in `crates/envcloak-policy/src/{grants,pending,statement,flood,limiter}.rs`, the daemon handlers in `crates/envcloak-daemon/src/requests.rs`, and the commands in `crates/envcloak-cli/src/cmd/{run,approve,grants}.rs`. The wire form of each method is in docs/IPC.md; the caller evidence a grant is scoped to is in docs/AGENTS.md.

## A request

`envcloak run [--profile NAME] [--ref NAME=slug[#field]]... [--env-file FILE] -- <cmd...>` sends `run.request` with the manifest's path, the profile, the `--ref` bindings, the `--env-file`'s references and the names of its ordinary variables (never their values: those stay with the CLI, whose runner sets them for the command; docs/MANIFEST.md "Env files"), the command line as display text, and the names of the agent markers in its environment. The daemon then, in order:

1. reads the caller's evidence from the kernel (docs/AGENTS.md): the chain, the root instance, the kind;
2. opens the manifest itself from the path sent (a symlinked manifest is refused, SPEC §5) and resolves the bindings from the file it read, the profile, the `--ref` bindings and the env file's references and names (docs/MANIFEST.md "Resolving a run's bindings"); the caller's argv is never used for anything but display;
3. binds each reference to a field of a secret item in the vault, and looks up whether the vault has a record of the project ("new project") and whether any adopted project's bindings name each item ("first use", SPEC §6.4 "Adoption");
4. applies the effective policy: the vault's policy for the project (approve, redact, inject in M1), tightened by the manifest's `[policy]`, for the subject's kind. `agents = "deny"` refuses an agent or unknown subject (`policy_denied`); a required proxy mode is refused in M1 (`mode_unsupported`), never injected;
5. asks the grant store for the decision: `covered` (with the grant id, whether output is redacted, the mode, and whether the manifest's hash differs from the one at approval), `pending` (with the request id) or `denied` (with the reason).

A covered request is a delivery: its answer carries the bindings' values, and `envcloak run` starts the command with them (docs/RUN.md). A pending run exits 125 with `approval_required request=<id>: run "envcloak approve <id>" in a terminal you control`, and reads nothing from its own terminal: that terminal may be an agent's, and a `y` typed there approves nothing.

No decision is made, and no proof taken, from a vault that failed its integrity check (`vault_tampered`): its project index and policy cannot be trusted.

## The grant store

The store lives in the daemon's memory under its state lock, is cleared at every lock, and is never written to disk or synced. It holds at most 256 grants and 20 pending requests.

A grant records what SPEC §10b lists: the root process instance (pid and start time, plus the executable for display), the subject's kind and the agent's name, the project identity (canonical directory, device, inode), the manifest's hash at approval, the bindings as (variable, item id, field id) with the display slug and the `live` tick, the mode, `once` or `session`, both deadlines, and the vault and policy epochs.

**Match.** Request R is covered by grant G when all of these hold:

1. G has not passed either deadline (below), been revoked or been used up;
2. G was made under the vault's current epoch and the current policy epoch;
3. G's root is in R's kernel-verified chain, pid and start time alike, and no known agent sits between the root and the caller unless the root is that agent; a grant approved for a terminal subject covers only a terminal subject (docs/AGENTS.md "Coverage");
4. R's project identity equals G's: a symlinked path to the same directory keeps it, a copy (another inode) or a move (another canonical path) is another project;
5. R's bindings are a subset of G's, compared by (variable, item id, field id): a renamed or retargeted variable, an added reference, another field or a profile switch each prompt again, for the difference (below);
6. R's mode is at least as strict as G's.

A manifest change that leaves the bindings a subset does not prompt; the daemon audits `manifest changed grant=<id> approved_sha256=<hex> sha256=<hex>`, the SHA-256 of the manifest's bytes at approval and now, and the decision says `manifest_changed`. A request that is not covered only because of some of its bindings prompts for the difference (SPEC §10b): each binding a session grant in force for the same caller, project and mode already holds is marked `granted` in the pending request, and the statement asks for the others first and lists these apart, under a line saying the new grant holds them too. The new grant holds the whole request, for its own uses and length, so its statement still shows every binding. A `once` grant marks nothing, since it ends at its next use; and the marks are taken when the request opens, so the line says the bindings were covered when the request was made. When a session grant and a once grant both cover a request, the session grant is used and the once grant kept.

**Once.** A `once` grant is used up by the first request it covers. The decision and the consumption happen under one lock, so of concurrent requests exactly one is covered; the others are pending, and identical ones share one pending request.

**Audit before release.** A covered request's audit entry is flushed to disk before the answer, and the values go into the answer only after that (docs/RUN.md "Release"); a `once` grant is consumed only after that too. When the entry cannot be written, the request is denied with `audit_failed`, nothing is released, and the grant is left as it was (VAULT.md "Audit log").

**Deadlines.** An approval sets two: the wall clock plus the grant's length, and time awake plus the same length. Either passing ends the grant, so a clock stepped either way cannot lengthen one. Lengths: 8 hours by default (`--for` sets it, from 30 seconds), at most 24 hours for an agent subject whose root is a known agent process (the agent nearest the caller, SPEC §10b "Root selection"), and 12 hours for every other subject: a terminal or unknown subject, whose evidence is missing, and an agent subject by its claims alone (markers such as `CLAUDECODE=1` set in a person's shell), or by an agent matched only on what it says about itself above the caller's session, whose root is a session's process like a terminal's. Claims only label and tighten.

**A grant ends on** expiry; its first use, if `once`; the root process exiting (a tick every second drops grants whose root's pid is gone or has another start time); `envcloak grants revoke <id> | --all`, which any client may run (tightening needs no proof); lock, for any reason (a request, idle time, sleep, a signal, a restore), which also drops every pending request; a daemon restart, which starts empty; a policy epoch bump; a vault epoch change; the removal of an item it binds (`envcloak rm`), which also drops every pending request that asks for the item. Rotating a bound item's value does not end a grant.

## Pending requests and approval

A request no grant covers becomes a pending request: an id of 8 Crockford base32 characters (unique among the pending requests; `I`, `L` and `O` read as `1` and `0`), a 32-byte daemon nonce, the request as the daemon built it, and the descriptor an approval surface shows (`pending.get`). A pending request expires after 10 minutes of awake time. An identical request (the same root, project, bindings, mode and argv) while one is pending gets the same id.

`envcloak approve <REQUEST> [--once | --for DURATION] [--live NAME]... [--passphrase-fd N]`, run by a person in a terminal they control:

1. refuses under a tracer (gate 19), before anything is read, and refuses (`proof_refused`) when its environment holds an agent's markers;
2. fetches the descriptor, which the daemon serves only to a caller that may give a proof (below), so where none is taken it stops here, before anything is shown or read; and renders the statement (below);
3. reads the vault passphrase from `/dev/tty` with echo off, or from the descriptor named, never from argv or the environment;
4. sends `approve` with the request id, the options, the SHA-256 of the canonical statement it rendered with those options, the passphrase, and the names of the agent markers in its environment.

The daemon, before any key derivation: reads the approver's evidence and refuses every caller but a terminal subject: one with a known agent in its ancestry or agent markers in its claims, a chain cut at the walk's limit, a lost ancestry (an orphan), or no controlling terminal (a service manager's job, a process that forked out and called `setsid`) (`proof_refused`, audited as `proof refused method=<name> reason=<agent|chain_cut|orphaned|no_terminal>`; docs/AGENTS.md "Proofs"); checks that the request exists (`no_such_request`), that the options are within bounds (`invalid_options`), that the digest equals the digest of its own descriptor with the same options (`statement_mismatch`), and that the attempt limiter admits the attempt (`too_many_attempts`). Only then does it run Argon2id, with the vault taken out of its slot as an unlock takes it: other requests see `busy` for that moment, and a lock that arrives meanwhile wins. A wrong passphrase gives `wrong_passphrase` and counts. The right one creates the grant and removes the request.

The statement shown by the CLI is advisory: the daemon approves what its own pending request says, and refuses when the digest differs. The passphrase is the proof; a `y` typed anywhere is nothing. `envcloak deny <REQUEST>` refuses a request and needs no proof.

`unlock` is a proof too: it is refused from the same callers as `approve`, and counted by the same limiter. The CLI sends its marker names with it, and refuses before it reads the passphrase when it has any.

A passphrase an agent captured is not made useless by this: a program running as the user can open a pseudo-terminal of its own outside the agent's tree, where it is a terminal subject, and the passphrase opens a copy of the vault file anyway (SPEC §10b "Honest limits"). What the rule gives is that an agent gets no approval, and shows no prompt, from its own tree or from a process without a terminal.

## The statement

The descriptor (`envcloak_policy::PendingDescriptor`) holds: the request id, the nonce (hex), when the request was opened and its expiry, the subject (kind, the agent's name, the caller's pid, the root's pid, start time and executable path), the project (canonical directory, manifest path, manifest SHA-256, whether it is new), each binding (variable, slug, item id, field id, field name, `test`, `live` or `unknown`, whether it is a first use, whether a grant in force already holds it), the mode, and argv.

**Canonical encoding** (`canonical_statement`): the bytes `envcloak-statement/1\n`, then every field of the descriptor and of the options (`once` or `session`, the length in seconds, the `live` names), each as a 4-byte big-endian length followed by the bytes, lists preceded by their count, numbers as decimal strings, booleans as `1` or `0`. Nothing is ambiguous whatever the strings hold, and the full argv is in it. `statement_digest` is its SHA-256. The nonce binds the digest to one request of one daemon.

**Rendering** (`render_statement`): the text a person reads. Every string from the daemon goes through `escape_for_display`: backslash, `\n`, `\r` and `\t` as those escapes, and every other control character, bidirectional control, zero-width or other invisible character as `\u{...}`. The bindings no grant covers come first, under a line saying the request asks for them, and those a session grant already held follow under a line saying this grant holds them too. Argv is a list, one argument per line with its index; rendered argv beyond 2048 bytes is cut on a character boundary with `(N more bytes)` and a line saying that the passphrase approves the full command line. The rendering ends with "The passphrase you enter approves exactly this, and nothing else."

`envcloak grants list` escapes what it prints the same way; its `--json` form prints the daemon's answer as JSON, whose own encoding escapes control characters.

## Bounds

- At most 3 pending requests per root and 20 per daemon; a request beyond either is denied (`pending_per_root`, `pending_total`).
- A request identical to one denied in the last 10 minutes is denied without a prompt (`repeated`).
- Three denials for one root within 10 minutes deny that root for 30 minutes (`root_denied`), whatever it asks: the store checks this before it looks for a grant, so a grant the root already holds covers none of its requests meanwhile. The grant is kept (revoke it with `envcloak grants revoke` to end it) and covers again when the 30 minutes end. The daemon logs a notice, until there is a surface for a notification (M3).
- Denials are remembered for their whole 10 minutes, and this state outlives a lock, since it only tightens. None is forgotten early to make room: while 64 are remembered, no new pending request is opened (`denials_full`) until the oldest is 10 minutes old, so a denied request never prompts again inside its window and a root's count toward the auto-deny is never reset. Only a pending request can be denied, so at most 64 plus the 20 pending requests are held.
- The passphrase attempt limiter is one for every proof: after 5 failures, each further attempt must wait, 30 seconds after the fifth failure and twice as long after each failure beyond it, up to an hour; an attempt that comes early is refused without a passphrase being checked. A success clears it. `envcloak status` shows the failures and the wait.
- Windows count time awake: a machine asleep serves none of them.

## Gates

| Gate | Where |
|---|---|
| 23: a `y` on the requester's terminal approves nothing; a missing or wrong passphrase fails; a statement that differs is rejected; approval input is never read from the requester's terminal; proofs from an agent-descended caller are refused, and so are proofs from a caller without a terminal (a `launchctl submit` or `systemd-run --user` job, `setsid`), before anything is shown or read | `crates/envcloak-cli/tests/approve.rs`, `crates/envcloak-daemon/tests/grants.rs` and `proofs.rs`, `crates/envcloak-policy/tests/grants.rs` and `evidence.rs` |
| 24: a loosening manifest with a scripted agent still needs approval, and redaction stays on | `crates/envcloak-cli/tests/approve.rs` |
| 25, the grant half: a terminal grant does not cover the agent under it | `crates/envcloak-cli/tests/approve.rs`, `crates/envcloak-policy/tests/grants.rs` |
| 27: a recycled root pid is not covered, and the grant is swept though a process has its root's pid | `crates/envcloak-cli/tests/approve.rs` (Linux: a real pid handed out again in a user and pid namespace), `crates/envcloak-policy/tests/grants.rs` (synthetic instances, both systems), `crates/envcloak-daemon/src/requests.rs` (the sweep compares start times) |
| 28: binding changes prompt for the difference (the statement asks for exactly the bindings no grant holds): an added reference, a retargeted or renamed variable, a profile switch, a `--ref` and an `--env-file` reference; a comment-only change is covered and its new hash audited; a copy or move is a new identity, a symlink keeps it | `crates/envcloak-daemon/tests/grants.rs`, `crates/envcloak-cli/tests/approve.rs` (a real `run --env-file`), `crates/envcloak-policy/tests/grants.rs` and `statement.rs` |
| 29: wall-clock and awake-time expiry apart; revoke without a proof; lock, restart, sleep and root exit end grants | `crates/envcloak-policy/tests/grants.rs`, `crates/envcloak-daemon/tests/grants.rs`, `crates/envcloak-daemon/src/state.rs` (a lock for each reason: a request, idle time, sleep, a signal), `crates/envcloak-cli/tests/approve.rs` |
| 30: concurrent requests on a `once` grant, exactly one covered | `crates/envcloak-daemon/tests/grants.rs`, `crates/envcloak-policy/tests/grants.rs` |
| 31: escapes, `\r`, U+202E, zero-width characters and 100 KB of argv render escaped and truncated; the statement covers the full argv | `crates/envcloak-policy/tests/statement.rs`, `crates/envcloak-cli/tests/approve.rs` |
| 32: the pending caps, three denials, denials kept for their whole window, the attempt limiter | `crates/envcloak-policy/tests/grants.rs`, `crates/envcloak-daemon/tests/grants.rs` |

The daemon and CLI tests unlock and approve as a terminal subject: the CLI tests run those commands leading a session on a pseudo-terminal of their own (`run_on_terminal`), and the daemon tests make the test process itself a terminal session (`envcloak_sys::testing::enter_terminal_session`). They need no agent in the ancestry, as CI has. Under a developer's Claude Code those proofs are refused, as SPEC §10b requires; run the tests outside the agent's tree then (on macOS, `launchctl submit` runs a command under `launchd`, and `script` gives it a terminal). The service-manager cases run where `ENVCLOAK_TEST_SERVICE_MANAGER=1`, as in CI.
