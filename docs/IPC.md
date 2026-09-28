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

A peer running as another uid is closed at once, answered nothing, and audited. At most 32 connections are served at a time; more are closed at once.

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

**Values.** A secret inside a message (a passphrase, the Recovery Kit's text, and from T12 the values a run receives) is a JSON string of standard padded base64. It is decoded where it lies in the frame straight into a wiped buffer; a string with JSON escapes cannot be read in place and is refused (`invalid_params`). Encoding writes the base64 into a wiped buffer from which the serializer copies it into the frame.

**No text crosses back.** Errors on both sides are built from fixed tokens. A decode error never carries serde's message, which can quote the input. `status` carries two strings, the daemon's version and the reason the vault is unavailable; the client replaces a version that is not 1 to 32 characters of `[0-9A-Za-z.+-]` with `unrecognized`, and a reason that is not one of the tokens below with `unknown`, before anything prints them, because a program running as the user could answer in the daemon's place. A method name is logged only when it is one of the names below; any other is logged as `(unknown)` or `app.(unknown)`, because a name a client sent can hold anything.

## Methods (M1, client role)

| Method | Params | Result |
|---|---|---|
| `status` | none | `daemon` (version, pid, hardening, whether the runtime directory fell back), `vault` (state `absent`, `locked`, `unlocked` or `unavailable`; integrity; read-only; the reason it is unavailable; whether an unlock is in progress; failed unlocks), `lock` (last reason, idle limit, idle time left) |
| `vault.create` | `passphrase`, `recovery_kit` (the kit's text as the user wrote it down), `kdf_memory_kib` (optional, 65536 to 4194304) | `locked` (true when a lock arrived while Argon2id ran: the vault was created, then locked), `integrity`, `read_only` |
| `unlock` | `passphrase` | `integrity`, `read_only`, `already` (true when it was unlocked already; nothing was checked) |
| `lock` | none | `was_unlocked` |

- `vault.create` checks the Argon2id bounds, the passphrase rules and the kit's check symbols before any key derivation. The CLI generates the Recovery Kit and shows it (on the terminal, or the descriptor `--kit-fd` names, never stdout or stderr), so the kit crosses the socket only from the client to the daemon (SPEC §4.4: unlocker material is never sent to a client). Both envelopes use Argon2id with the given memory, 3 passes and 4 lanes.
- A `vault.create` result means the vault exists under the passphrase and the kit sent, so the kit the CLI showed is valid, whether `locked` is true or not. The CLI calls a kit void only when no vault was created: the daemon refused before creating anything (`vault_exists`, `busy`, `passphrase_rejected`, `kdf_params`, `invalid_params`, `traced`), or the connection failed or the answer was unreadable and a new `status` then shows no vault and nothing in progress. Otherwise it says to keep the kit.
- `unlock` and `vault.create` run Argon2id on the connection's thread, outside the state lock, one at a time. Both refuse (`traced`) while a tracer is attached to the daemon. A wrong passphrase and a damaged envelope give the one error `wrong_passphrase`, which is counted and audited.
- `lock` needs no proof: locking only tightens.

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
| `internal` | -32099 | The daemon failed |

The CLI prints `envcloak: <token>: <message>` for its own failures, adding `daemon_unavailable`, `daemon_unverified` and `protocol_error` for the connection. `envcloak run` exits 125 on them (SPEC §6.1); the other commands exit 1, and 2 on a usage error.

## Lock

The daemon locks on a `lock` request, on SIGTERM, SIGINT or SIGHUP (it then removes the socket and exits 0), after the machine slept, and after the idle limit (8 hours by default, 1 minute to 24 hours with `--idle-lock`). Locking drops the unlocked vault, whose VMK, subkeys and decrypted metadata are wiped as they are freed, and keeps the file open and its lock held.

- **Sleep.** On a one-second tick and before every request, the daemon compares how far two clocks moved since its last reading: time awake (macOS `CLOCK_UPTIME_RAW`, Linux `CLOCK_MONOTONIC`) and time including sleep (macOS `CLOCK_MONOTONIC_RAW`, Linux `CLOCK_BOOTTIME`). Each pair counts the same timebase from boot, so the difference is only the time asleep. When the second ran more than 5 seconds ahead, the machine slept. Deltas since the last reading, never totals, so drift does not add up.
- **Idle.** Awake time since the last activity: a successful `unlock` or `vault.create` in M1, and every value release from T12. `status` and `lock` are not activity, so polling never keeps the vault open.
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
| 32, frames: over 1 MiB rejected, memory bounded under a flood, a stalled frame dropped | `crates/envcloak-daemon/tests/frames.rs`, `crates/envcloak-ipc/tests/frame.rs` |
| 11, for IPC frames: no freed block holds a value or its base64 | `crates/envcloak-ipc/tests/frame_probe.rs` |

The other-uid checks need a second user and `sudo`; CI creates one on Linux (`ENVCLOAK_TEST_OTHER_USER`). The service-manager check runs where `ENVCLOAK_TEST_SERVICE_MANAGER=1`, which CI sets on both systems.
