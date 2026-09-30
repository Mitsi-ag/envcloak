# EnvCloak: daemon protocol

Status: M1. This file fixes how SPEC §4.1 to §4.4 and §5 "Lock" are carried out between `envcloak` and `envcloakd`: where the socket lives and what is checked on each side, the framing, the messages, the methods M1 serves, the error tokens, and when the daemon locks by itself. The code is in `crates/envcloak-ipc/`, `crates/envcloak-daemon/` and `crates/envcloak-sys/src/peer.rs`.

A change to the framing, a method's name or shape, or an error token here is a protocol change: old clients must keep working, or both sides change together.

## Socket location

| | macOS | Linux |
|---|---|---|
| Runtime directory | `~/Library/Application Support/EnvCloak/run/` | `$XDG_RUNTIME_DIR/envcloak/`; without `XDG_RUNTIME_DIR`, `$XDG_STATE_HOME/envcloak/run/` (default `~/.local/state/envcloak/run/`) and a warning |
| Socket | `<run>/envcloakd.sock`, mode 0600 | same |
| Lock file | `<run>/envcloakd.lock`, mode 0600 | same |

- A socket path longer than `sun_path` allows (104 bytes on macOS, 108 on Linux, counting the terminating NUL) is refused with a clear error, never shortened.
- Relative `XDG_*` values are ignored, as the XDG specification says.

## Daemon start-up

`envcloakd --foreground [--idle-lock <duration>]`, started by launchd or systemd from `envcloak daemon install`, or by the user by absolute path. Nothing else starts it: no client ever starts a daemon, and no client looks for `envcloakd` on `PATH`. In order, and refusing to start when a step fails:

1. Core dumps off and, on Linux, `PR_SET_DUMPABLE` 0. Umask 077. SIGTERM, SIGINT and SIGHUP are blocked before any thread exists; one thread collects them with `sigwait`.
2. A tracer already attached stops it (`traced`).
3. The runtime directory is created 0700 if missing, then checked: a real directory (not a symlink), owned by the effective uid, not writable by group or others (`runtime_dir`). One that others can only read is tightened to 0700. Its parent must belong to this uid or root and must not be writable by others unless it is sticky.
4. An exclusive `flock` on the lock file (`O_NOFOLLOW`, a regular file of this uid). A second instance stops here (`already_running`), before it touches the socket.
5. Holding the lock, a socket of this uid left at the socket path by a daemon that died is removed. Anything else there is refused (`socket_taken`). The socket is bound under umask 077, made 0600, and checked on disk.
6. The vault, if there is one, is opened locked.

Start-up errors print `envcloakd: <token>: <message>` and exit 1; usage errors exit 2.

## Peer checks

**Daemon, at accept.** Every connection's peer is identified from kernel handles tied to the process that connected, before any byte is read:

| | uid, pid | start time |
|---|---|---|
| macOS | the audit token (`LOCAL_PEERTOKEN`), which also carries the pid version | `proc_pidinfo(PROC_PIDTBSDINFO)`; a process that started after the accept is refused |
| Linux 6.5+ | `SO_PEERCRED` | `/proc/<pid>/stat`, read while `SO_PEERPIDFD` pins the process: it must still be alive after the read. Whether the kernel has `SO_PEERPIDFD` is found once; on one that has it, a peer it gives no pidfd for (one reaped before the accept gets `EINVAL`) is refused, never checked the way older kernels are |
| Linux before 6.5 | `SO_PEERCRED` | `/proc/<pid>/stat`; a process that started after the accept is refused. A narrow race remains: the peer exits and its pid is reused between its `connect` and the `accept` |

A peer running as another uid is closed at once, answered nothing, and audited. At most 32 connections are served at a time, and at most 8 for any one process (by pid), so one process that keeps connections open cannot lock the user's own `envcloak lock` and `status` out; more are closed at once. Many processes together can still fill the 32; the pending-request caps and the denial rules (docs/GRANTS.md "Bounds") limit what an agent can ask for.

**Client, before it sends anything.** `Client::connect` checks the runtime directory as the daemon does (without changing it), checks that the socket is a socket of this uid, connects (the descriptor is close-on-exec), and checks with `getpeereid` (macOS) or `SO_PEERCRED` (Linux) that the process at the other end runs as this uid. A missing directory, socket or listener is `daemon_unavailable`; any failed check is `daemon_unverified`, and nothing is sent. A passphrase is read only after the daemon is verified, and sent on a connection verified again.

Signed macOS builds will also check the daemon's code signature from its audit token (M3). Builds that pin no signing identity, which is every M1 build, cannot: `envcloak status` says "daemon identity unverified", and on them a program running as the same user can impersonate the daemon (SPEC §1.1).

## Framing

A frame is a 4-byte big-endian length `N`, then `N` bytes of UTF-8 JSON holding one JSON-RPC 2.0 message.

- `1 ≤ N ≤ 1 MiB`. A header announcing 0 or more than 1 MiB is answered with an error (`invalid_request` or `frame_too_large`, `id` null) and the connection is closed; nothing after the header is read.
- A frame's body may hold a value, so both sides keep it in a buffer wiped on drop. An incoming body starts in a 16 KiB buffer that doubles as bytes arrive, up to the announced length; each growth copies into a new buffer and wipes the old one.
- The daemon waits up to 10 minutes for a frame to start, then up to 10 seconds from its first byte for the rest of it. A connection that misses either is closed.
- One request gets exactly one response, in order. A connection may carry any number of requests.

## Messages

Request:

```json
{"jsonrpc": "2.0", "id": 7, "method": "unlock", "params": {"passphrase": "..."}}
```

- `id` is an unsigned 64-bit integer. Notifications (no `id`) and batches are not used.
- `params` is an object, and may be left out for a method that takes none. Unknown fields, at the top level or in `params`, are refused.

Response, one of:

```json
{"jsonrpc": "2.0", "id": 7, "result": {"integrity": "ok", "read_only": false, "already": false}}
{"jsonrpc": "2.0", "id": 7, "error": {"code": -32005, "message": "...", "data": {"kind": "wrong_passphrase"}}}
```

- `data.kind` is a stable token (below); some kinds add `data.reason`. `message` is fixed text for the kind; a client prints its own text for the kind and never what it received.
- An error to a request the daemon could not read has `id` null.

**Values.** A secret inside a message (a passphrase, the Recovery Kit's text, and the values a covered run receives) is a JSON string of standard padded base64. It is decoded where it lies in the frame straight into a wiped buffer; a string with JSON escapes cannot be read in place and is refused (`invalid_params`). Encoding writes the base64 into a wiped buffer from which the serializer copies it into the frame.

**No text crosses back.** Errors on both sides are built from fixed tokens. A decode error never carries serde's message, which can quote the input. `status` carries two strings, the daemon's version and the reason the vault is unavailable; the client replaces a version that is not 1 to 32 characters of `[0-9A-Za-z.+-]` with `unrecognized`, and a reason that is not one of the tokens below with `unknown`, before anything prints them, because a program running as the user could answer in the daemon's place. A method name is logged only when it is one of the names below; any other is logged as `(unknown)` or `app.(unknown)`, because a name a client sent can hold anything.

## Methods (M1, client role)

| Method | Params | Result |
|---|---|---|
| `status` | none | `daemon` (version, pid, hardening, whether the runtime directory fell back), `vault` (state `absent`, `locked`, `unlocked` or `unavailable`; integrity; read-only; the reason it is unavailable; whether an unlock is in progress; failed unlocks), `lock` (last reason, idle limit, idle time left), `approvals` (grants in force, pending requests, failed proofs since the last success, seconds before the next proof is admitted), `audit` (whether the log is open for writing, its last sequence number, entries not yet anchored in the vault's header, whether the last save of the head failed (the daemon tries again, at most every 15 minutes), events waiting to be written and events dropped) |
| `vault.create` | `passphrase`, `recovery_kit` (the kit's text as the user wrote it down), `kdf_memory_kib` (optional, 65536 to 4194304) | `locked` (true when a lock arrived while Argon2id ran: the vault was created, then locked), `integrity`, `read_only` |
| `unlock` | `passphrase`, `claims` (optional: the names of the agent markers in the caller's environment) | `integrity`, `read_only`, `already` (true when it was unlocked already; nothing was checked) |
| `lock` | none | `was_unlocked` |
| `run.request` | `manifest` (the absolute path of `envcloak.toml`), `profile` (optional), `refs` (`NAME=<slug>[#field]` strings), `env_file` (optional: `refs`, each `{line, text}` with `text` as `NAME=<slug>[#field]`, and `plain`, each `{line, text}` with `text` the name of an ordinary variable; never a value), `argv` (display text), `claims` | `decision`: `covered` with `grant`, `redact`, `mode` and `manifest_changed`; `pending` with `request`; or `denied` with `reason` (`repeated`, `root_denied`, `pending_per_root`, `pending_total`, `denials_full`, or `audit_failed` when a grant covers the request but its audit entry could not be written). With `covered` only, `values`: for each binding, `env_name`, `slug`, `allow_short` and `value` |
| `pending.get` | `request`, `claims` | the pending request's descriptor (`envcloak_policy::PendingDescriptor`; docs/GRANTS.md "The statement"), for a caller that may give a proof |
| `approve` | `request`, `options` (`uses`: `once` or `session`; `ttl_secs`; `live`: variable names), `digest` (SHA-256 of the canonical statement, 64 hex characters), `passphrase`, `claims` | `grant`, `expires_in_secs` |
| `deny` | `request` | `root_auto_denied` |
| `grants.list` | none | `grants`: each with `id`, `kind`, `label`, `root_pid`, `root_exe`, `project_dir`, `bindings` (`env_name`, `slug`, `live`), `mode`, `uses`, `created_secs`, `remaining_secs` |
| `grants.revoke` | `grant`, or `all: true` | `revoked` (a count) |
| `audit.verify` | none | `segments`, `entries`, `last_seq`, `first_problem` (`seq` and `kind`: `altered`, `chain_broken`, `missing`, `reordered`, `segment_damaged`, `unreadable` or `anchor_mismatch`), `problems`, `anchor` (`state`: `none`, `matched`, `mismatch` or `missing`; `seq`), `unanchored_tail` (`first`, `last`), `torn_tail` and `torn_bytes` (the log ends in what a crash in the middle of a write leaves, and its size), `live_head_matches` (the log still ends where the daemon last wrote it), `queued`, `dropped` |
| `items.list` | `long` (optional: each item's account too) | `items`: each an item view, sorted by slug: `id`, `slug`, `class`, `title`, `provider`, `classification` (`test`, `live` or `unknown`), `env_hint`, `allow_short`, `fields` (`name`, `prior_count`, `created_secs`, `updated_secs`), `created_secs`, `updated_secs`, `rotated_secs`, `expires_secs`, and `account` (`email`, `label`, `org_id`) only with `long` |
| `items.show` | `slug` | one item view with `account` and `detail` (`allowed_hosts`, `tags`, `links`: `docs`, `billing`, `keys_page`, `dashboard`; `last_used_secs`, `notes`) |
| `items.check` | `manifest` (optional: the absolute path of `envcloak.toml`, which the daemon opens itself), `refs` (`NAME=<slug>[#field]` strings) | `project_dir`, `project_name`, `bindings` (each of `[env]`, then each profile's own: `profile`, `env_name`, `reference`, `status`), `refs` (a status for each reference sent, in order). A status is `ok`, a binding kind (`unknown_item`, `unknown_field`, `ambiguous_field`, `no_field`, `card_reference`, `issuer_credential_reference`, `unknown_item_class`), `invalid_reference`, or `looks_like_value`, when the name or reference is shaped like a key; its text is then left out |
| `items.add` | `slug`, `provider`, `field`, `account`, `env_hint` (each optional), `allow_short`, `value`, `claims` | `item` (an item view with its account), `field`, `detected` (the provider the value's shape says, when the item does not carry it), `ambiguous` (several providers' patterns match), `length` (`ok`, `short` for 8 to 15 bytes, `too_short` under 8) |
| `items.target` | `slug`, `field` (optional), `claims` | `item` (with its account), `field` (the one named, or the item's only field; null when it has several), `grants` (grants in force that bind the item). For a caller that may give a proof |
| `items.rotate` | `slug`, `field`, `item` (the id `items.target` gave), `value`, `passphrase`, `claims` | `slug`, `field`, `prior_count`, `length` |
| `items.remove` | `slug`, `item`, `passphrase`, `claims` | `slug`, `grants_ended`, `backup` (the encrypted backup's file name in `<data>/backups/`) |
| `import.plan` | `projects` (each `dir`, an absolute path, and `name`, one slug part), `entries` (each `project` (an index), `file`, `line`, `profile` (optional), `name` and `value`), `claims` | `digest` (SHA-256 of the plan, 64 hex characters), `entries` (one per entry sent: `item`, an index into `items`, or `skipped`: `empty`, `too_short`, `not_secret`, `looks_like_value`, `too_large`, `nul_byte` or `guessable`), `items` (each `slug`, `field`, `reference`, `existing`, `provider`, `classification`, `length`, `holders` (every item that holds the value already, by slug), `entries`, `projects`). Writes nothing |
| `import.commit` | `import` (as `import.plan`), `digest` (the plan shown) | the plan, as `import.plan` answers it, once its new items are committed |
| `import.verify` | `manifest` (the absolute path of `envcloak.toml`, which the daemon opens itself), `files` (each `file`, `profile` (optional) and `entries`: `line`, `name`, `value`), `claims` | `recovery_confirmed`, `resolves` (every binding of every profile resolves), `files` (each `file`, `covered`, and `entries`: `line`, `name`, `status` (`stored`, `left_out` or `not_stored`) and `skipped`, which is `guessable` for a value only a person is told about) |
| `files.backup` | `files` (each `path`, absolute, to an env file (`.env`, `.env.<suffix>`), `mode` and `content`), `claims` | `id` (26 Crockford base32 characters), `files`, `file_name` (in `<data>/backups/`) |
| `files.restore` | `backup` (an id), `passphrase`, `claims` | `files`: each `path`, `mode` and `content`. For a caller that may give a proof |
| `recovery.confirm` | `recovery_kit` (the kit's text), `claims` | `already` (it was confirmed before) |
| `backup.create` | none | `path` (the backup's absolute path, in `<data>/backups/`), `file_name`, `items`, `bytes`, `created_secs` |
| `vault.recover` | `backup` (the backup file's absolute path), `recovery_kit` (the kit's text), `new_passphrase`, `claims` | `items`, `backup_created_secs`, `replaced` (files moved out of the new vault's way), `locked` (true when a lock arrived while it ran: the vault is the restored one, locked) |

- `vault.create` checks the Argon2id bounds, the passphrase rules and the kit's check symbols before any key derivation. The CLI generates the Recovery Kit and shows it (on the terminal, or the descriptor `--kit-fd` names, never stdout or stderr), so the kit crosses the socket only from the client to the daemon (SPEC §4.4: unlocker material is never sent to a client). Both envelopes use Argon2id with the given memory, 3 passes and 4 lanes.
- A `vault.create` result means the vault exists under the passphrase and the kit sent, so the kit the CLI showed is valid, whether `locked` is true or not. The CLI calls a kit void only when no vault was created: the daemon refused before creating anything (`vault_exists`, `busy`, `passphrase_rejected`, `kdf_params`, `invalid_params`, `traced`), or the connection failed or the answer was unreadable and a new `status` then shows no vault and nothing in progress. Otherwise it says to keep the kit.
- `unlock`, `vault.create` and `approve` run Argon2id on the connection's thread, outside the state lock, one at a time. All refuse (`traced`) while a tracer is attached to the daemon. A wrong passphrase and a damaged envelope give the one error `wrong_passphrase`, which is counted and audited.
- `unlock` and `approve` are proofs (SPEC §10b): the daemon reads the caller's evidence first and takes a proof only from a terminal subject, refusing a caller with a known agent in its ancestry or agent markers in its claims, a chain cut at the walk's limit, a lost ancestry, or no controlling terminal (`proof_refused`, audited as `proof refused method=<name> reason=<token>`). `pending.get` is refused to the same callers, before the id is looked up. Both count against one attempt limiter: after 5 failures each further attempt waits, 30 seconds doubling to an hour, and an early attempt is refused (`too_many_attempts`) without a passphrase being checked. `status` reports the failures and the wait.
- `run.request` decides, and a covered answer releases the bindings' values, the only values the daemon ever sends a client in M1 (SPEC §4.4). They go out after the delivery's audit entry is on disk, and never under a tracer or from a vault that failed its check or turns out changed on disk while open (`vault_tampered`); docs/RUN.md has the release and what the CLI does with them. The client refuses an answer whose values are not well formed (values beside another decision, a variable or slug of the wrong shape, a variable twice, an empty value or one with a NUL byte) as `protocol_error`. `pending.get`, `deny`, `grants.list` and `grants.revoke` carry metadata only and need no proof (`pending.get` still needs a caller that may give one): denying and revoking only tighten. Ids are Crockford base32 (26 characters for a grant, 8 for a request); a malformed one is `invalid_params`, an unknown or expired one `no_such_request`. docs/GRANTS.md has the rules.
- `lock` needs no proof: locking only tightens. It drops every grant and pending request.
- The item methods carry metadata only; the only values that cross are the new ones `items.add` and `items.rotate` send to the daemon (SPEC §4.4). Names are checked before they are used, and none is repeated in an error: a slug, provider, field, account or variable shaped like a key or token (a provider's key pattern, or a run of 24 or more letters and digits mixing two of lowercase, uppercase and digits) is refused as `invalid_item` with `looks_like_value`, so a pasted value is never kept as a name. `items.add` needs no proof, since nothing is bound to a new item: it detects the provider and classification from the value, fills the item's links and allowed hosts from the registry, and without a slug takes the provider's id (`openai`, then `openai-2` up to `openai-99`), or `secret`. `items.target`, `items.rotate` and `items.remove` are served only to a caller that may give a proof, like `pending.get` and `approve`, and the two writes check the passphrase as `approve` does, counted by the same limiter. Both refuse (`no_such_item` with `item_changed`) when the slug no longer names the item `items.target` showed. A rotation keeps the old value as the newest of three prior values and leaves grants in force; a removal first writes an encrypted backup of the vault (VAULT.md "Backups"), and removes nothing when it cannot (`backup_failed`), then ends every grant and pending request that binds the item. Every write is refused on a vault that failed its integrity check (`vault_tampered`), and recorded in the audit log (kinds `add`, `rotate` and `remove`, with the item's id and slug).
- The import methods (IMPORT.md): the values of `envcloak init --import` and `envcloak import` cross from the client to the daemon, as `items.add`'s do (SPEC §4.4), in `import.plan`, `import.commit` and `import.verify`; the answers carry metadata only. The daemon sorts each value into a secret or configuration, compares values by keyed hash under the `index` subkey, and names new items; the plan's digest covers every entry's fate, every item and each value's keyed hash, and `import.commit` works the plan out again under the lock it writes under and refuses one that is not the plan shown (`plan_changed`). Importing needs no proof, as `items.add` needs none; it is audited (kind `import`, with the items made and a count of the ones reused). `import.verify` answers the delete gate from the manifest it opens itself. Comparing a value with the vault tells the caller whether the vault holds it, so `import.plan`, `import.commit` and `import.verify` import and compare a value short enough to guess (under 16 characters with no provider's key pattern, or a URL whose password is under 16 characters) only for a caller that may give a proof (a terminal subject with no agent): for any other, the plan leaves it out and `import.verify` answers `left_out`, both with `guessable`, whether the vault holds it or not (SPEC §6.5's rule for doctor). Each subject root may have 100,000 values compared per hour of awake time; beyond that the call is refused (`too_many_checks`). A call comparing no value is not counted, and a new root beyond the 4,096 counted at once takes the place of the one whose hour started first. Each call is audited with the count of values compared (kind `import`, outcome `checked`, or `refused`). `files.backup` carries the bytes of env files about to be deleted (a path to any other file is `invalid_params`, since `envcloak init --undo` writes a backup's files back), writes them encrypted (VAULT.md "File backups", kind `files_backup` in the audit log) and purges file backups over 7 days old; a failure is `files_backup_failed`. `files.restore` is the one method besides a covered `run.request` that answers with plaintext: the files of a backup, for `envcloak init --undo`, only with the passphrase from a terminal subject, checked as `items.rotate` checks it and counted by the same limiter (kind `files_restore`); an unknown or malformed id is `no_such_backup`. Like a covered request's delivery, its audit entry is written durably before the files are released; when it cannot be, nothing is released (`audit_failed`). `recovery.confirm` is a proof too, with the Recovery Kit in place of the passphrase (kind `recovery_confirm`); a wrong or malformed kit is `wrong_passphrase`.
- The backup methods (VAULT.md "Backups"): `backup.create` writes an encrypted backup of the unlocked, verified vault (a vault that failed its check is `vault_tampered`, and any other failure `backup_failed`) and needs no proof: no value crosses, and the file opens only with the Recovery Kit (kind `backup`, with the backup's id). `vault.recover` is a proof, like `unlock`, with the kit in place of the passphrase: taken only from a terminal subject and counted by the same attempt limiter. The kit's shape, the new passphrase's rules (`passphrase_rejected`) and the path (absolute, else `invalid_params`; a regular file whose last component is not a symlink, else `backup_unusable`) are checked before the vault is touched. Then the daemon locks an unlocked vault (every grant and pending request ends, the audit log's head is saved), closes the vault file, and restores the backup outside the state lock and under the proof gate, since Argon2id runs twice (for the kit, and for the new passphrase, with the current default parameters). A backup that is altered or cut short is `backup_unusable`, and so is a valid backup of another vault than the one in place, refused before anything is moved: the id of a vault that opens, or for one that opens as damaged the vault ids its rows still hold, none of them the backup's (a file that names no vault is moved aside, and restoring where no vault exists, story S11, is unchanged); a wrong kit is `wrong_passphrase`, counted and audited (kind `recover`, outcome `failed`). Either way the vault on disk is the old one, now locked. A restore leaves the old vault or the restored one in place, never neither, keeps the replaced file as `vault/replaced-<time>.db`, and unlocks the restored vault, whose passphrase is the new one and whose kit is confirmed (kind `recover`, with the backup's id and the item count).
- Every decision, proof, refusal, lock and unlock is recorded in the sealed audit log (VAULT.md "Audit log") and as a value-free line on the daemon's standard error. A covered `run.request` is a delivery: its entry is flushed to disk before the answer, and when it cannot be written the answer is `denied` with `audit_failed`. The command line an entry keeps is masked first. `audit.verify` needs an unlocked vault (the log's keys come from the vault key) and carries counts, sequence numbers and fixed tokens only.

## App-role methods

Every method whose name starts with `app.` belongs to the `app` role (SPEC §4.3): `app.unlock`, `app.approve`, `app.policy.set`, `app.reveal`, `app.paste`, `app.device.add`, `app.device.remove`, `app.registry.override`, and any other `app.` name. Before the macOS app (M3) no peer has that role: each call is answered `role_denied` (code -32001), changes nothing, and is audited as `audit: denied method=<name> reason=role_denied role=client pid=<pid> uid=<uid>`.

## Error tokens

| Token | Code | Meaning |
|---|---|---|
| `parse_error` | -32700 | The frame is not JSON |
| `invalid_request` | -32600 | Not a JSON-RPC 2.0 request, or an empty frame |
| `method_not_found` | -32601 | No such method |
| `invalid_params` | -32602 | Parameters missing, malformed, or a value that is not plain base64 |
| `role_denied` | -32001 | An `app`-role method |
| `vault_locked` | -32002 | The vault is locked, or was locked while an unlock ran |
| `no_vault` | -32003 | There is no vault yet |
| `vault_exists` | -32004 | `vault.create` found a vault |
| `wrong_passphrase` | -32005 | Wrong passphrase or Recovery Kit, or a damaged envelope |
| `passphrase_rejected` | -32006 | A new passphrase breaks the rules; `reason` is `not_text`, `control_character`, `too_short` or `common` |
| `kdf_params` | -32007 | Argon2id memory outside 64 MiB to 4 GiB |
| `busy` | -32008 | An unlock or vault creation is in progress |
| `traced` | -32009 | A tracer is attached to the daemon |
| `vault_unavailable` | -32010 | The vault file could not be opened; `reason` is `busy`, `damaged`, `unsupported_version`, `permissions`, `disk_full`, `storage`, `io` or `migration` |
| `frame_too_large` | -32011 | A frame over 1 MiB |
| `evidence` | -32012 | The caller's ancestry could not be read; `reason` is `caller_gone`, `ancestry_changed`, `ancestry_hidden` or `ancestry_unreadable` |
| `manifest_invalid` | -32013 | The manifest, or the path it was opened from; `reason` is a `ManifestErrorKind` token (`not_found`, `syntax`, `loose_policy`, `symlinked_manifest`, ...) or a binding kind that makes the manifest invalid (`card_reference`, ...) |
| `binding_unresolved` | -32014 | A `--profile` or `--ref` the run asked for; `reason` is `unknown_profile`, `unknown_item`, `unknown_field`, `ambiguous_field`, `no_field`, `invalid_reference` or `duplicate_env_name` |
| `policy_denied` | -32015 | The effective policy refuses agent requests for the project |
| `mode_unsupported` | -32016 | The effective mode is proxy, which M1 does not have |
| `no_such_request` | -32017 | No pending request has the id, or it expired |
| `statement_mismatch` | -32018 | The digest is not the pending request's with the options sent |
| `proof_refused` | -32019 | A proof (or `pending.get`) from a caller that is not a terminal subject: an agent by any evidence, or no terminal session |
| `too_many_attempts` | -32020 | The attempt limiter refused the attempt |
| `vault_tampered` | -32021 | The vault failed its integrity check; no decision, no proof |
| `too_many_grants` | -32022 | 256 grants are in force |
| `invalid_options` | -32023 | `reason` is `ttl_zero`, `ttl_too_long` or `live_not_bound` |
| `audit_unavailable` | -32024 | The audit log's directory could not be read (`audit.verify`) |
| `no_such_item` | -32025 | No item has the slug, or it has no such field; `reason` is `unknown_item`, `unknown_field`, `ambiguous_field`, `no_field`, `unknown_item_class` or `item_changed` |
| `item_exists` | -32026 | `items.add` with a slug an item has |
| `invalid_item` | -32027 | A new item's names or a new value; `reason` is `invalid_slug`, `invalid_field`, `unknown_provider`, `invalid_account`, `invalid_env_name`, `looks_like_value`, `empty_value`, `nul_byte`, `value_too_large` or `no_free_slug` |
| `backup_failed` | -32028 | An encrypted backup of the vault could not be written (`backup.create`, or `items.remove` first, which then removed nothing) |
| `plan_changed` | -32029 | `import.commit` found another plan than the one shown: the vault or the files changed meanwhile |
| `no_such_backup` | -32030 | No file backup has the id, or it was purged after 7 days |
| `files_backup_failed` | -32031 | A file backup could not be written, or could not be read back; nothing was deleted or restored |
| `too_many_checks` | -32032 | The caller's subject root had 100,000 values compared with the vault in the last hour (`import.plan`, `import.commit`, `import.verify`) |
| `audit_failed` | -32033 | A delivery's audit entry could not be written (`files.restore`): nothing was released |
| `backup_unusable` | -32034 | The file named for `vault.recover` is not a vault backup this build can read (missing, not a regular file, a symlink as its last component, altered or cut short), or is a backup of another vault than the one in place; nothing was restored |
| `internal` | -32099 | The daemon failed |

The CLI prints `envcloak: <token>: <message>` for its own failures, adding `daemon_unavailable`, `daemon_unverified` and `protocol_error` for the connection, `approval_required request=<id>` and `approval_denied` for a run's decision, `audit_problem` when `envcloak audit verify` finds the log changed or damaged, `not_imported`, `unresolved_reference`, `recovery_kit_unconfirmed`, `not_deleted` and `import_too_large` for `envcloak init` and `envcloak import` (IMPORT.md), and `traced` when a tracer is attached to it. `envcloak run` exits 125 on them (SPEC §6.1); the other commands exit 1, and 2 on a usage error.

## Lock

The daemon locks on a `lock` request, on SIGTERM, SIGINT or SIGHUP (it then removes the socket and exits 0, also when its standard error is gone: a log line that cannot be written is dropped, never fatal), after the machine slept, and after the idle limit (8 hours by default, 1 minute to 24 hours with `--idle-lock`). Locking drops the unlocked vault, whose VMK, subkeys and decrypted metadata are wiped as they are freed, and keeps the file open and its lock held.

- **Sleep.** On a one-second tick and before every request, the daemon compares how far two clocks moved since its last reading: time awake (macOS `CLOCK_UPTIME_RAW`, Linux `CLOCK_MONOTONIC`) and time including sleep (macOS `CLOCK_MONOTONIC_RAW`, Linux `CLOCK_BOOTTIME`). Each pair counts the same timebase from boot, so the difference is only the time asleep. When the second ran more than 5 seconds ahead, the machine slept. Deltas since the last reading, never totals, so drift does not add up.
- **Idle.** Awake time since the last activity: a successful `unlock`, `vault.create` or `approve`, and a covered `run.request`, which releases values. `status`, `lock`, `grants.list` and `pending.get` are not activity, so polling never keeps the vault open.
- **During an unlock.** Every lock bumps a generation number. An unlock that started under an older one (a lock request, sleep or a signal arrived while Argon2id ran) finishes locked and answers `vault_locked`. A `vault.create` in that case still creates the vault, whose kit the client has already shown, leaves it locked and answers `locked: true`. Idle time does not cut either short. A signal that stops the daemon during `vault.create` may leave the vault created or not; the client gets no answer and says to keep the kit.

## Service definitions

`envcloak daemon install` writes `packaging/launchd/ai.envcloak.envcloakd.plist` (a LaunchAgent, loaded with `launchctl bootstrap gui/<uid>`, or `user/<uid>` without a GUI session) or `packaging/systemd/envcloakd.service` (a systemd user unit, written where the user manager reads units, under the manager's own `XDG_CONFIG_HOME` or `HOME/.config`, and enabled and started with `systemctl --user` run with that environment), filled in with the absolute path of the `envcloakd` beside `envcloak` (or `--daemon`'s absolute path) and the `HOME` and, on Linux, `XDG_*` directories of the installing shell. `launchctl` and `systemctl` are run by absolute path. `envcloak daemon uninstall` stops and removes it; the vault is untouched. See `packaging/README.md`.

## Gates

| Gate | Where |
|---|---|
| 19, for the daemon: core dumps off and no core after a forced abort; on Linux same-uid ptrace and `/proc/<pid>/mem` and `environ` denied, and a traced daemon refuses to start; on macOS the hardened runtime reported | `crates/envcloak-daemon/tests/hardening.rs` |
| 20: directory 0700 and socket 0600; symlinked, foreign-owned, group- or world-writable directories refused; a second instance refused; another uid rejected at accept | `crates/envcloak-daemon/tests/socket.rs` |
| 21: a server of another uid refused and sent nothing; the CLI never starts `envcloakd` from `PATH` | `crates/envcloak-cli/tests/squat.rs`, `crates/envcloak-ipc/tests/client.rs`, `crates/envcloak-cli/tests/daemon_commands.rs` |
| 22: every `app`-role method rejected and audited | `crates/envcloak-daemon/tests/roles.rs` |
| 32, frames: over 1 MiB rejected, memory bounded under a flood from many processes, one process held to 8 connections, a stalled frame dropped | `crates/envcloak-daemon/tests/frames.rs`, `crates/envcloak-ipc/tests/frame.rs` |
| 23 and 27 to 32, the grant methods | docs/GRANTS.md "Gates" |
| 8, 9, 13 and 14 during a run, and 33's release order | docs/RUN.md "Gates" |
| 33: every decision audited; a covered request's entry flushed before the answer, and a failure to write it denies the request and keeps a `once` grant; command lines masked before sealing (the request's values and key patterns); no canary in an entry, the log or the daemon's output; the head saved every 100 entries, every 15 minutes, at lock and at stop, and a save that failed tried again by ticks until it succeeds; `audit verify` reports the anchor, the tail and a changed entry | `crates/envcloak-daemon/tests/audit.rs`, `crates/envcloak-daemon/src/state.rs` (tests), `crates/envcloak-cli/tests/audit.rs`, `crates/envcloak-core/tests/audit.rs` |
| 11, for IPC frames: no freed block holds a value or its base64 | `crates/envcloak-ipc/tests/frame_probe.rs` |
| 13: no command takes a value as an argument, and a name shaped like a key is refused, unechoed and unkept, in every command; `ps` shows no value in the CLI's argv or environment while it holds one (`rotate --stdin` waiting for the passphrase; Linux: the environment cannot be read at all) | `crates/envcloak-cli/tests/argv.rs`, `crates/envcloak-daemon/tests/items.rs` (the daemon refuses such names too) |
| T11: the item methods answer with metadata only; `rotate` and `rm` need the passphrase from a terminal subject, keep a prior value (a rotation) or an encrypted backup (a removal, which removes nothing when the backup cannot be written), and a removal ends the grants that bind the item; every command's output matches its value-free snapshot, and names shaped like a key are hidden in text and JSON alike; `ref` changes one binding and nothing else | `crates/envcloak-daemon/tests/items.rs` and `proofs.rs`, `crates/envcloak-cli/tests/snapshots.rs` and `tests/snapshots/`, `crates/envcloak-cli/tests/ref_edit.rs`, `crates/envcloak-cli/src/render.rs` and `src/cmd/ref_.rs` (tests) |
| 10, 15 and 16, the import methods, file backups and the delete gate | IMPORT.md "Gates" |
| 4 through the daemon (story S11): `backup create` writes a backup of ciphertext only; `recover` takes the kit only from a terminal subject, refuses a wrong kit (counted and audited) and a file that is not a backup, leaving the vault it had, and after the vault directory is lost restores it unlocked under the new passphrase, which alone opens it then | `crates/envcloak-cli/tests/backup.rs`, `crates/envcloak-daemon/src/state.rs` and `src/backup.rs` (tests), `crates/envcloak-cli/tests/snapshots.rs` |

The other-uid checks need a second user and `sudo`; CI creates one on Linux (`ENVCLOAK_TEST_OTHER_USER`). The service-manager check runs where `ENVCLOAK_TEST_SERVICE_MANAGER=1`, which CI sets on both systems.
