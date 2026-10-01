# EnvCloak: the agent catalog and caller evidence

Status: M1. This file fixes the format of the agent catalog (`integrations/agents.toml` and the user's extensions), how the daemon reads a caller's process ancestry, and how that evidence picks a grant's root, the subject's kind and whether a grant covers a caller (SPEC §10a, §10b "Root selection" and "Match" rules 3 and 4; gates 25 and 26). The code is in `crates/envcloak-sys/src/proc/` (the kernel's view) and `crates/envcloak-policy/src/{agents,evidence}.rs`.

Evidence here tightens, with one exception. Matching a process as an agent makes handling stricter (an agent subject, the agent barrier, proofs refused); the absence of a match never removes a restriction, and evidence the daemon cannot read in full (an orphan's lost ancestry, a chain cut at the depth limit) is handled as if an agent may be there. The exception is the root: an agent runs each command in a session of its own, so its grants are rooted at the agent process, above the caller's session, and cover every command it runs. Only a builtin match on the executable's path or its macOS code signature roots a grant there; a match on what a process says about itself (`argv[0]`, its script, its command name) or on a user extension's entry roots it no higher than the caller's session leader (Root, below). The one thing a missed agent costs is the agent barrier: an unrecognized agent started in a terminal that holds a terminal grant would be covered by it. The catalog exists to make that rare, and the daemon's other defenses (approval proofs, the manifest's tighten-only rule, proxy mode) do not depend on it.

## Where the catalog comes from

The builtin catalog ships inside the release: `integrations/agents.toml` is compiled in byte for byte as Rust source, `crates/envcloak-policy/src/agents_builtin.rs`, which `scripts/gen-agents.py` writes (no `include_str!` and no build script, for the reasons in docs/PROVIDERS.md). After editing the file, run:

```sh
python3 scripts/gen-agents.py            # rewrites agents_builtin.rs
python3 scripts/gen-agents.py --check    # exits 1 if it is stale
```

The policy crate's `agents` test fails when the compiled copy and the file differ. `.github/CODEOWNERS` names an owner for the catalog, its compiled copy, the generator and the matching and rooting code, and the same test fails if it stops doing so.

The M1 catalog knows Claude Code, Codex and the test fixture agent (`crates/envcloak-testkit/src/bin/fixture-agent.rs`). The fixture entry ships too, since CI runs the release build's `fixture-agent` in the acceptance story. It matches only a program named `fixture-agent`, but a match on that name is a builtin match on the executable, so it roots grants above the caller's session like any other (Root, below): a program named `fixture-agent` is in the same class as a program named `claude` (Limits). The tests pin that it roots its grants there (`evidence_gates.rs`).

## Catalog format

UTF-8 TOML, at most 64 KiB. Unknown keys fail, as does a value of the wrong type.

```toml
interpreters = ["node", "nodejs", "bun", "deno"]

[[agent]]
id = "claude-code"
name = "Claude Code"
executables = ["claude", "claude.exe", "claude/versions/*"]
scripts = ["claude", "@anthropic-ai/claude-code/cli.js"]
signatures = [{ team = "Q6L2SF6YDW", identifier = "com.anthropic.claude-code" }]
markers = ["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"]
```

| Key | Rule |
|---|---|
| `interpreters` | File names of programs that run scripts. For these, the script arguments are matched against `scripts`. One path component each, without `/` or `*`, at most 64 bytes |
| `id` | Required. 1 to 32 lowercase ASCII letters, digits and `-`, not starting or ending with `-`. Unique within a file |
| `name` | Display text: 1 to 64 bytes, without control or invisible characters. Required for a new agent |
| `executables` | Patterns matched against the executable's path, `argv[0]` and the kernel's command name |
| `scripts` | Patterns matched against an interpreter's script arguments: the first 3 arguments that do not start with `-`, among the first 16 after `argv[0]` |
| `signatures` | macOS only: `identifier` (the signing identifier, printable ASCII) and optionally `team` (a 10-character Team ID). Matched against the signature the kernel validated when the process started its executable (`csops`, `CS_VALID`) |
| `markers` | Environment variables the agent sets in the commands it runs. Variable names. They are the caller's claims, not ancestry evidence (below) |

A match records what it rests on (`MatchBasis`): the executable's path or its code signature (`Executable`), or `argv[0]`, a script or the command name (`Asserted`), each of which the process sets itself (`exec -a`, node's `process.title`, and on Linux `prctl(PR_SET_NAME)` or the name of a link it was run through). The executable's path and signature are tried first, for every agent, so a process whose path names one agent and whose command name names another is the first. What differs is where it may root a grant (Root, below).

A pattern is a path suffix of 1 to 8 components separated by `/`, at most 256 bytes. Each component is a name or `*`, which stands for any one component, and at least one is a name. `.`, `..`, empty components, a `*` inside a name and control characters are refused. `claude/versions/*` matches `/home/u/.local/share/claude/versions/2.1.112`; `claude` matches `/usr/local/bin/claude`, `./claude` and the command name `claude`, and not `claude2` or `Claude`. Matching is byte for byte and case-sensitive.

An agent must list at least one of `executables`, `scripts`, `signatures` or `markers`. A file holds at most 64 agents, and each list at most 32 entries.

## Extensions

Users add agents in `<data>/agents.d/*.toml`, where `<data>` is `~/Library/Application Support/EnvCloak/` on macOS and `$XDG_DATA_HOME/envcloak/` on Linux. Extensions only add:

- a new `id` adds an agent, which needs a `name`;
- an existing `id`, builtin included, gets the extension's patterns, signatures and markers added to its own; its `name` stays;
- `interpreters` are added to the list.

Nothing in an extension removes or narrows a builtin entry. A match that needed an extension's entry is labeled as such (`CatalogSource::Extension`), which limits where it can root a grant (below). That includes a match on arguments the daemon read only because an extension names an interpreter: builtin patterns are tried against a process's arguments only where the builtin catalog alone would read them (a hidden executable, or a builtin interpreter by executable or command name), so such a match, on `argv[0]` or on a script, is an extension match too.

`agents.d` must be a real directory (not a symlink) owned by the user and not writable by group or others, or no extension is read. Each file is opened through that directory's handle with `O_NOFOLLOW` and must be a regular file owned by the user, not writable by group or others, and at most 64 KiB. Files are read in name order, at most 16; names starting with `.` and names not ending in `.toml` are ignored. A file that fails any check or rule is skipped as a whole and reported by kind and line (`AgentCatalog::problems`), never with its contents.

## Reading the ancestry

The daemon identifies a caller at accept (docs/IPC.md): uid, pid and start time. It then reads the caller's ancestry from the kernel:

| | macOS | Linux |
|---|---|---|
| Parent, start time, uid, controlling terminal, command name | `sysctl(KERN_PROC_PID)` (`kinfo_proc`), which answers for processes of other users (`login`, `launchd`) where `proc_pidinfo` refuses | `/proc/<pid>/stat` and `status` |
| Session | `getsid` | `stat` field 6 |
| Executable | `proc_pidpath`, and the code signature (`csops`: signing identifier, Team ID, cdhash) | `/proc/<pid>/exe`, with its device and inode |
| Arguments | `KERN_PROCARGS2` | `/proc/<pid>/cmdline` |

Neither kernel offers a race-free parent chain, so the walk is checked:

1. The first entry must be the caller the socket reported, with its start time.
2. Every parent must have started no later than its child. A pid reused after the real parent exited belongs to a newer process.
3. After the walk, every entry is read again and must still have its start time, parent, session and terminal. A process keeps its pid until it exits, so an entry that passes was the same process throughout, and every link held when it was checked.

A change means the tree moved under the walk (a parent exited, a process was reparented): the daemon walks again, up to 3 times, and then refuses with `ancestry_changed`. A caller that exited is `caller_gone`. A parent the kernel will not show while its child still names it (a process that exits has its children reparented before its entry goes) is hidden, not changed: the request is refused at once with `ancestry_hidden` (see Limits). The walk stops at the top of the tree or after 64 processes. A cut chain hides what is above the cut, and an agent could put itself there by running its command under enough nested shells with `env -i`, so a cut chain fails closed: unless a known agent is found below the cut, the caller's kind is `unknown` (no terminal grant covers it) and its proofs are refused, as for an agent. Real chains are about 10 processes deep.

Only processes of the caller's uid are classified. pid 1 is one only in a container (the host's runs as root), where it may be the agent the entrypoint started.

Arguments are read only for a process whose executable is hidden from the daemon (so `argv[0]` stands in for it) or that runs an interpreter (so its script decides): at most 17 (`argv[0]` and the 16 after it, all the catalog looks at) and 16 KiB. They can hold other programs' secrets, so they are held in storage allocated once and wiped on drop (`envcloak_sys::Argv`), which the catalog borrows to compare; nothing copies them out, `Debug` shows only their count, and errors are fixed text. They are dropped after classification; the evidence holds pids, start times, executables and labels.

Neither kernel keeps a boundary between a process's arguments and its environment that the process cannot move, and both put the environment right after the arguments:

- macOS `KERN_PROCARGS2` returns the process's string area as it is now, with the argument count `exec` saved: the executable's path, the arguments, then the environment. The arguments start where `exec` put them (after the path and its NUL, padded to a multiple of 8 bytes), never at the first byte that is not a NUL, so an empty `argv[0]` is never taken for padding. The count ends them, and the rest of the buffer is wiped unparsed. But a process that removed the NULs between its arguments makes the count run on into its environment: those strings are read as arguments. node does this whenever `process.title` is longer than its command line (libuv writes the title over the argument area, cut to fit). They stay in the wiped storage and are never shown (see Limits).
- Linux `/proc/<pid>/cmdline` runs on into the environment, up to its first NUL, when the process overwrote the NUL that ends its argument area (the kernel takes that for `setproctitle`). The daemon reads no more than the area's length, from the kernel's own record of where it starts and ends (`/proc/<pid>/stat` fields 48 and 49, which only a privileged `prctl(PR_SET_MM)` moves), so it never reads the environment there. The kernel shows that record only to a reader that may trace the process; for a non-dumpable process (the EnvCloak CLI) the 16 KiB cap alone bounds the read.

The Linux CLI makes itself non-dumpable, so its own `/proc/<pid>/exe` is hidden from the daemon. Its `stat` and `cmdline` stay readable, and the walk starts there. The CLI's claims are the names (never the values) of the catalog's markers set in its environment (`Claims::from_env`); requests that need a decision carry them, and the daemon checks them (`Claims::from_markers`: variable names, at most 16).

## Root, kind and coverage

**Root.** The process instance a grant for the caller is scoped to:

1. the known agent nearest the caller;
2. otherwise the caller's session leader, when it is in the verified chain (so alive, with its start time checked);
3. otherwise the topmost ancestor still in the caller's session: the session leader died, or the caller left its tree.

pid 1 (`launchd`, `init`) is never a root and never counts as a session leader: every process descends from it, and GUI apps on macOS run in its session. A known agent that is pid 1 (a container whose entrypoint ends in `exec claude`, with the daemon started in it) is still an agent for the kind, the agent barrier and proofs; rules 2 and 3 pick the root. A caller that is pid 1 itself (a container whose pid 1 is the shell or the CLI, with the daemon in the same pid namespace) has no process to root a grant at, so its requests are refused (`evidence`, reason `caller_is_init`) instead of opening requests no grant could ever cover; run it under a shell or an init such as `tini`.

Rule 1 may pick an agent above the caller's session, and must: Claude Code and Codex run each command in a session of its own, without a terminal, so the command leads its own session. Only a builtin match on the agent's executable path or signature does that. An agent matched only on `argv[0]`, a script or its command name, or only through an extension, is the root only at or below the point rule 2 or 3 would pick; above it, rules 2 and 3 apply. So a process that calls itself `claude`, and an extension that matches a terminal emulator or an IDE, cannot widen a grant beyond the caller's session; they still make the caller an agent subject, stand as a barrier and refuse its proofs.

**Kind**, in this order:

1. a known agent in the ancestry: `agent`;
2. no session leader in the chain, so the ancestry is lost, or a chain cut at 64 processes: `unknown`, whatever the claims say;
3. agent markers in the claims: `agent`;
4. a session without a controlling terminal: `unknown`;
5. otherwise `terminal`. This never proves that a person is there.

**Coverage.** A grant rooted at instance R, approved for a subject of kind K, may cover the caller only if:

- R is in the caller's chain with its pid and start time (a recycled pid never matches, and pid 1 never does);
- no known agent sits between R and the caller, the caller included, unless R is that agent (the agent barrier);
- K is `terminal` only if the caller is a terminal subject;
- R, when it is above the caller's session (past the leading run of the caller's chain in its own session), is an agent a builtin entry matched by its executable path or signature. Any other root covers only callers in its own session run, on every system alike. On macOS a caller in pid 1's session without a terminal (an IDE's extension host, an MCP server it runs, a `launchd` job) is rooted by rule 3 at the topmost process below pid 1: the whole app. On Linux, where only pid 1 is in session 1, the same caller is rooted by rule 2 at its session's leader, often the desktop shell (`gnome-shell`); a job a `tmux` server runs itself is rooted at the server, which leads a session of its own on both systems. Each such grant covers the callers in that session, never the sessions the app, the shell or the server starts: its integrated terminals, its panes, and the commands an agent the catalog does not know runs in sessions of their own.

The remaining match rules (expiry, epochs, project, bindings, mode) are the grant store's (SPEC §10b; docs/GRANTS.md).

**Proofs** (approve, unlock, rotate, remove, recover) are taken only from a terminal subject (`SubjectEvidence::proof_refusal`, SPEC §10b). They are refused, with the first reason that applies, from a caller with a known agent in its ancestry or agent markers in its claims (`agent`), a chain cut at 64 processes (`chain_cut`), an orphan's lost ancestry (`orphaned`), or no terminal session (`no_terminal`). An orphan's chain no longer reaches its session's leader: a double fork or `nohup` out of a terminal keeps that terminal, and could prompt on it for a proof the same command may not give from inside its agent's tree. pid 1's session without a controlling terminal, where macOS runs GUI apps and `launchd` jobs, is not an orphan's (pid 1 leads it and is in every chain); with one (a container whose init is a shell), it is. A job a service manager starts, and a process that forked out and called `setsid`, is neither an orphan nor seen as an agent's, but it has no terminal: no person could have typed its proof there, and a passphrase an agent captured and passed on a descriptor would otherwise work. `pending.get` is refused to the same callers, so `envcloak approve` run there fails before it shows the statement or asks for the passphrase, and `pending.list` (`envcloak pending`) lists nothing to them. An approval is also refused when the approver shares a session or a controlling terminal with the chain of an agent's or unknown process's request, from its caller up to its root or up to its nearest known agent, whichever is further (`requester_terminal`, `SubjectEvidence::approval_refusal`): the kernel reports each process's terminal device, and the daemon keeps the requester's chain with the pending request; `pending.list` leaves such a request out for that approver. The nearest agent counts even where it may not be the root: an agent known only by what it says about itself, or through an extension, roots its grants at its command's session (Root, above), yet the terminal it runs on is still the agent's, and a shell on it is not where a person approves (review F-70).

**Claims** can turn a terminal subject into an agent subject and make its proofs refused (SPEC §10b); they never change the chain, the root or a lower kind. `CLAUDECODE=1` set in a person's shell therefore only tightens.

## Escapes

A process that leaves the tree loses every grant rooted in it (gate 26):

| Escape | What the daemon sees | Kind |
|---|---|---|
| Double fork | Reparented to `launchd`, `init` or a subreaper; its session leader, though alive, is no longer an ancestor | unknown |
| `setsid` after a fork whose parent exits | Leads a new session without a terminal | unknown |
| `nohup` with `disown`, and the shell exits | Reparented; its session's leader is gone or elsewhere | unknown |
| `launchctl submit` | Started by `launchd` | unknown |
| `systemd-run --user` | Started by the user's service manager, leading its own session without a terminal | unknown |

In each case the process's new request gets a root of its own, and a person approves it or not. Its proofs are refused in every case: after a double fork or `nohup` it is an orphan, and after the others it has no controlling terminal, which a proof needs (`no_terminal`), even when it reads the passphrase from a descriptor. `setsid` alone, without the parent exiting, leaves the process a child of its parent: it is still in the tree, and an agent's grant still covers it.

## Limits

- A renamed agent binary on Linux, or a renamed unsigned one on macOS, is not recognized, and a grant for the terminal it runs in covers its commands. When it sets its markers, its commands are still agent subjects, which a terminal grant does not cover.
- An agent known only by what it says about itself (the older npm build of Claude Code, `node .../cli.js`; an agent whose executable is hidden, as a non-dumpable process's is on Linux) roots its grants no higher than the caller's session. As it runs each command in a session of its own, each command asks. The native builds are known by their executables.
- An executable's path is the name of whatever file the process runs: a program copied to a file named `claude` matches Claude Code by path, and roots grants above the caller's session, over every session it holds. The same holds for `codex` and for the test fixture's `fixture-agent`, which ships in the release catalog. The root's executable is part of a grant's subject (SPEC §10b). On macOS the signature is the identity a copy cannot take.
- An agent that starts a pseudo-terminal of its own (`script`, `tmux`) and escapes into it creates a terminal session. SPEC §10a says a terminal subject never proves a person is there. Its proofs are taken there, so a passphrase the agent captured works from it, as it works against a copy of the vault file (SPEC §10b "Honest limits").
- macOS records start times on the wall clock. A clock stepped backwards between a parent's start and its child's makes the walk fail its order check; the request is refused (`ancestry_changed`) until the processes restart.
- On Linux, `/proc` mounted with `hidepid=1` or `hidepid=2` (some hardened distributions and shared hosts) hides other users' processes from the daemon, and nearly every chain has one (`sshd`, `login`, `init`). Every request is then refused with `ancestry_hidden`: closed, but EnvCloak does not work there. The mount's `gid=` option names a group whose members see every process; an administrator can add the user to it.
- SPEC §6.1 names the executable's SHA-256 on Linux. M1 records its device and inode only (`ExeIdentity::file`); the hash, with a cache keyed by device, inode and change time so a large binary is not hashed on every request, comes in M2. On macOS the cdhash the kernel validated is recorded. Neither decides a match: matching uses pid and start time, and the catalog.
- A grant rooted at a GUI app (above) covers every process of that app in pid 1's session: its helpers and extension hosts, and an agent the catalog does not know running among them. On Linux the root is the session's leader, often the desktop shell, so the grant covers every process in the desktop session below it that has not started a session of its own. The root's executable is part of the grant's subject (SPEC §10b), so the approval names the app or the shell.
- On macOS a process that removed the NULs between its arguments (node with a `process.title` longer than its command line) has up to 16 of its environment strings read as arguments: the kernel keeps nothing that marks where its arguments end. They can include values `envcloak run` injected. They are held in wiped storage, compared against the catalog's patterns and dropped; nothing prints, logs or sends them. On Linux the kernel's record of the argument area bounds the read, except for a process the daemon may not trace (a non-dumpable one): when it also overwrote the NUL that ends its arguments, its environment up to the next NUL is read, into the same wiped storage.
- Any program running as the user can write `agents.d`. An extension that matches the user's shell makes every request from it an agent request and refuses its proofs: a denial of service, never a way to widen a grant.

## Host behaviour

What the pinned hosts were measured to do, against the scripted model in an isolated home (M2 plan task M2-04; docs/ACCEPTANCE.md, "M2"). `crates/envcloak-e2e/tests/agent_hosts.rs` and `m2_story` re-measure every row in CI's `agents-e2e` job and print it as a `measurement:` line; a host version outside this table is not qualified (`probe::model::QUALIFIED`). Measured 2026-10-01 on macOS 26.4 (arm64); rows marked (macOS) hold for macOS only, and Linux's values come from CI's `agents-e2e` job (x64, loopback only).

**Claude Code 2.1.280** (`-p`, `--permission-mode default`, tools allowed by `--allowedTools`):

| What | Measured | For |
|---|---|---|
| MCP tool call of 15 s, server added with `claude mcp add-json` and no `timeout` | Answered after 15.0 s: no 10 s cutoff under `-p` (SI-17's 10 s was not seen) | M2-06 `--wait-ms`, K-08 |
| The same with `"timeout": 60000` in the entry | Answered after 15.0 s | M2-06, M2-08 |
| MCP server's ancestry; marker variables it gets | Its parent is `claude`; `AI_AGENT`, `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `CLAUDE_CODE_SESSION_ID`, `CLAUDE_PROJECT_DIR`, `CLAUDE_CODE_MESSAGING_SOCKET`, `CLAUDE_CODE_MESSAGING_TOKEN`, and `ANTHROPIC_API_KEY` and `ANTHROPIC_BASE_URL` | M2-06, M2-10 |
| Bash tool: terminal | Standard input, output and error are not terminals; no controlling terminal | M2-17, M2-19 |
| Bash tool: marker variables | `AI_AGENT`, `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `CLAUDE_CODE_SESSION_ID`, `CLAUDE_CODE_CHILD_SESSION`, `CLAUDE_CODE_EXECPATH`, `CLAUDE_CODE_MESSAGING_SOCKET`, `CLAUDE_CODE_MESSAGING_TOKEN`, `CLAUDE_CODE_SESSION_ATTENDED`, `CLAUDE_EFFORT`, `CLAUDE_PID`. The model credential (`ANTHROPIC_API_KEY`) reaches commands | M2-10 markers; the inject-mode limit |
| A prompt a `UserPromptSubmit` hook blocks (exit 2) | Exit 0; never sent to the model; not in `history.jsonl`; **kept in the transcript** (`~/.claude/projects/`) | K-14: transcript surface `unsupported (persists_blocked_prompt)` |
| `@README.md` in a `-p` prompt | Expanded: the file's content reaches the model | M2-09's `@.env` probe runs under `-p` |
| Interactive: a prompt typed and entered at the workspace trust dialog | Never reaches the model; Enter answers the dialog's default, "No, exit" (exit 1) | M2-26's interactive variant |
| Interactive: a one-line and a 40-line bracketed paste | Each kept in `history.jsonl` and the transcript; neither in `paste-cache/` | Gate 41's sweep; scrub (M2-22) |
| `envcloak status` from the Bash tool, sandbox off | Reaches the daemon | K-01 |
| The same, `sandbox.enabled` (`failIfUnavailable`, `allowUnsandboxedCommands: false`), no socket allowance | Does not: `daemon_unverified` (macOS) | K-01 |
| The same with `network.allowUnixSockets` naming the socket as the daemon names it (`/tmp/...`) | Does not (macOS): the sandbox compares the resolved path | M2-08 writes the resolved path |
| The same with the socket's resolved path (`/private/tmp/...`) | Reaches the daemon (macOS) | M2-08 |
| The subject the daemon records for `envcloak run` from the Bash tool | `agent Claude Code` (S0's statement) | Gate 41 |
| Blocked prompt and tool payloads | `crates/envcloak-e2e/tests/fixtures/hook-payloads/claude-code-2.1.280/` | M2-08's parsers |
| Candidates of 16 or more characters in what S0 wrote | About 12,400 per MiB, 2,000 distinct per MiB | D-32's budget, K-21 |

**Codex 0.159.2** (`exec`, `--sandbox` and `approval_policy` pinned per run):

| What | Measured | For |
|---|---|---|
| How an MCP server's tools are offered | As a Responses `namespace` tool, `mcp__<server>` | The scripted model; M2-06 |
| An MCP call under approval policy `never`, by the server's `default_tools_approval_mode` | Refused when unset, `auto` or `prompt`; runs only with `approve` | D-22: Codex's MCP surface reads `degraded (needs_host_approval)` under `exec` |
| MCP tool call of 15 s with `tool_timeout_sec = 5` | Cut off after 5.0 s: the setting is the cutoff | M2-06 `--wait-ms`, M2-08 |
| MCP server's ancestry | Its parent is `codex` | M2-10 |
| Shell tool (`exec_command`): terminal | Standard input, output and error are not terminals; no controlling terminal | M2-17, M2-19 |
| Shell tool: marker variables | `CODEX_CI`, `CODEX_HOME`, `CODEX_SANDBOX`, `CODEX_SANDBOX_NETWORK_DISABLED`, `CODEX_SESSION_ID`, `CODEX_THREAD_ID`, `CODEX_VERSION`. The provider's key variable (`env_key`) reaches commands | M2-10 markers |
| Hooks in `config.toml`, not trusted | Do not run | `degraded (hooks_untrusted)` |
| A prompt a trusted `UserPromptSubmit` hook blocks (exit 2) | Exit 0; never sent to the model; in no store (`sessions/`, `history.jsonl`, SQLite) | Codex's transcript surface |
| A hook that outlives its `timeout` on a prompt it would block | The prompt goes on: hooks fail open | `fails_open_on_timeout` |
| `permission_mode` hooks get under `exec`, approval policy `never` | `bypassPermissions` | M2-08's parsers |
| `envcloak status` from the shell tool, `read-only` (the `exec` default) or `workspace-write` | Does not: `daemon_unverified` | K-01 |
| The same, `sandbox_workspace_write.network_access = true` | Reaches the daemon, **and** a loopback TCP listener and another Unix socket | Never written alone |
| The same plus `[features.network_proxy] enabled = true`, no `domains`, and one `[features.network_proxy.unix_sockets]` rule for EnvCloak's socket | Reaches the daemon; a loopback TCP listener and another Unix socket are refused (asserted) | M2-08's bounded allowance; K-01 kill criterion not met |
| The subject the daemon records for `envcloak run` under that setting | `agent Codex` (S0's statement) | Gate 41 |
| Blocked prompt and tool payloads | `crates/envcloak-e2e/tests/fixtures/hook-payloads/codex-0.159.2/` (the shell tool is `Bash` there, with `tool_input.command`) | M2-08's parsers |
| Candidates of 16 or more characters in what S0 wrote | About 4,400 per MiB, 500 distinct per MiB | D-32, K-21 |

## Tests

- `crates/envcloak-e2e/tests/agent_hosts.rs` and `tests/m2_story/`: the pinned hosts against the scripted model, and the host behaviour above (docs/ACCEPTANCE.md, "M2").
- `crates/envcloak-sys/tests/proc.rs`: this process, pid 1 and real children (a new session, a pseudo-terminal) as the kernel reports them; the walk and its re-validation against a table whose answers change; the `KERN_PROCARGS2`, `cmdline` and `stat` parsers against arbitrary bytes.
- `crates/envcloak-sys/tests/argv_wiped.rs`: a `python3` child that removes the NULs in its own argument area, and `node` with a long `process.title`, each with an environment marker. macOS reads the marker as an argument, Linux does not; neither `Debug` nor an error shows it, and no block freed after the read holds it (the allocator probe, with the global allocator's wipe turned off).
- `crates/envcloak-policy/tests/agents.rs`: the builtin catalog, installs of Claude Code and Codex, ordinary programs, what each match rests on, extensions and their checks, claims.
- `crates/envcloak-policy/tests/evidence.rs`: root, kind, claims and coverage on synthetic chains; what `gather` reads and classifies; walking again.
- `crates/envcloak-policy/tests/evidence_gates.rs`: gates 25 and 26 with real processes (every escape also gives no proof), the test fixture agent (also 70 nested shells below it, past the cut), processes that only call themselves agents (by `argv[0]` or a script under `node`, or by a link's name on Linux), a pseudo-terminal, and `launchctl submit` or `systemd-run --user` where `ENVCLOAK_TEST_SERVICE_MANAGER=1`.
