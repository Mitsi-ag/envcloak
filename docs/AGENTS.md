# EnvCloak: the agent catalog and caller evidence

Status: M1. This file fixes the format of the agent catalog (`integrations/agents.toml` and the user's extensions), how the daemon reads a caller's process ancestry, and how that evidence picks a grant's root, the subject's kind and whether a grant covers a caller (SPEC §10a, §10b "Root selection" and "Match" rules 3 and 4; gates 25 and 26). The code is in `crates/envcloak-sys/src/proc/` (the kernel's view) and `crates/envcloak-policy/src/{agents,evidence}.rs`.

Everything here is evidence, and evidence only tightens. Matching a process as an agent makes handling stricter; the absence of a match never removes a restriction, and evidence the daemon cannot read in full (an orphan's lost ancestry, a chain cut at the depth limit) is handled as if an agent may be there. The one thing a missed agent costs is the agent barrier: an unrecognized agent started in a terminal that holds a terminal grant would be covered by it. The catalog exists to make that rare, and the daemon's other defenses (approval proofs, the manifest's tighten-only rule, proxy mode) do not depend on it.

## Where the catalog comes from

The builtin catalog ships inside the release: `integrations/agents.toml` is compiled in byte for byte as Rust source, `crates/envcloak-policy/src/agents_builtin.rs`, which `scripts/gen-agents.py` writes (no `include_str!` and no build script, for the reasons in docs/PROVIDERS.md). After editing the file, run:

```sh
python3 scripts/gen-agents.py            # rewrites agents_builtin.rs
python3 scripts/gen-agents.py --check    # exits 1 if it is stale
```

The policy crate's `agents` test fails when the compiled copy and the file differ. `.github/CODEOWNERS` names an owner for the catalog, its compiled copy, the generator and the matching and rooting code, and the same test fails if it stops doing so.

The M1 catalog knows Claude Code, Codex and the test fixture agent (`crates/envcloak-testkit/src/bin/fixture-agent.rs`). The fixture entry ships too: it matches only a program named `fixture-agent`, and a match only tightens.

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
| Executable | `proc_pidpath`, and the code signature (`csops`) | `/proc/<pid>/exe`, with its device and inode |
| Arguments | `KERN_PROCARGS2` | `/proc/<pid>/cmdline` |

Neither kernel offers a race-free parent chain, so the walk is checked:

1. The first entry must be the caller the socket reported, with its start time.
2. Every parent must have started no later than its child. A pid reused after the real parent exited belongs to a newer process.
3. After the walk, every entry is read again and must still have its start time, parent, session and terminal. A process keeps its pid until it exits, so an entry that passes was the same process throughout, and every link held when it was checked.

A change means the tree moved under the walk (a parent exited, a process was reparented): the daemon walks again, up to 3 times, and then refuses with `ancestry_changed`. A caller that exited is `caller_gone`. The walk stops at the top of the tree or after 64 processes. A cut chain hides what is above the cut, and an agent could put itself there by running its command under enough nested shells with `env -i`, so a cut chain fails closed: unless a known agent is found below the cut, the caller's kind is `unknown` (no terminal grant covers it) and its proofs are refused, as for an agent. Real chains are about 10 processes deep.

Only processes of the caller's uid, other than pid 1, are classified. Arguments are read only for a process whose executable is hidden from the daemon (so `argv[0]` stands in for it) or that runs an interpreter (so its script decides), at most 64 arguments and 16 KiB. On macOS `KERN_PROCARGS2` returns the environment after the arguments: parsing stops at the last argument, and the buffer is wiped. The arguments start where `exec` put them (after the executable's path and its NUL, padded to a multiple of 8 bytes), never at the first byte that is not a NUL, so an empty `argv[0]` is never taken for padding and the count never runs into the environment. A process can rewrite its own argument area; then what it wrote is what is read. Arguments are dropped after classification; the evidence holds pids, start times, executables and labels.

The Linux CLI makes itself non-dumpable, so its own `/proc/<pid>/exe` is hidden from the daemon. Its `stat` and `cmdline` stay readable, and the walk starts there. The CLI's claims are the names (never the values) of the catalog's markers set in its environment (`Claims::from_env`); requests that need a decision carry them, and the daemon checks them (`Claims::from_markers`: variable names, at most 16).

## Root, kind and coverage

**Root.** The process instance a grant for the caller is scoped to:

1. the known agent nearest the caller;
2. otherwise the caller's session leader, when it is in the verified chain (so alive, with its start time checked);
3. otherwise the topmost ancestor still in the caller's session: the session leader died, or the caller left its tree.

pid 1 (`launchd`, `init`) is never a root and never counts as a session leader: every process descends from it, and GUI apps on macOS run in its session. An agent matched only through an extension is the root only at or below the point rule 2 or 3 would pick; above it, rules 2 and 3 apply. So an extension that matches a terminal emulator or an IDE cannot widen a grant beyond the caller's session.

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
- R, when it is above the caller's session, is not an agent that only an extension matched.

The remaining match rules (expiry, epochs, project, bindings, mode) are the grant store's (SPEC §10b).

**Proofs** (approve, unlock, rotate, remove, recover) are refused from a caller with a known agent in its ancestry, agent markers in its claims, or a chain cut at 64 processes (SPEC §10b).

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

In each case the process's new request gets a root of its own, and a person approves it or not. `setsid` alone, without the parent exiting, leaves the process a child of its parent: it is still in the tree, and an agent's grant still covers it.

## Limits

- A renamed agent binary on Linux, or a renamed unsigned one on macOS, is not recognized, and a grant for the terminal it runs in covers its commands. When it sets its markers, its commands are still agent subjects, which a terminal grant does not cover.
- An agent that starts a pseudo-terminal of its own (`script`, `tmux`) and escapes into it creates a terminal session. SPEC §10a says a terminal subject never proves a person is there.
- macOS records start times on the wall clock. A clock stepped backwards between a parent's start and its child's makes the walk fail its order check; the request is refused (`ancestry_changed`) until the processes restart.
- Any program running as the user can write `agents.d`. An extension that matches the user's shell makes every request from it an agent request and refuses its proofs: a denial of service, never a way to widen a grant.

## Tests

- `crates/envcloak-sys/tests/proc.rs`: this process, pid 1 and real children (a new session, a pseudo-terminal) as the kernel reports them; the walk and its re-validation against a table whose answers change; the `KERN_PROCARGS2`, `cmdline` and `stat` parsers against arbitrary bytes.
- `crates/envcloak-policy/tests/agents.rs`: the builtin catalog, installs of Claude Code and Codex, ordinary programs, extensions and their checks, claims.
- `crates/envcloak-policy/tests/evidence.rs`: root, kind, claims and coverage on synthetic chains; what `gather` reads and classifies; walking again.
- `crates/envcloak-policy/tests/evidence_gates.rs`: gates 25 and 26 with real processes, the test fixture agent (also 70 nested shells below it, past the cut), a pseudo-terminal, and `launchctl submit` or `systemd-run --user` where `ENVCLOAK_TEST_SERVICE_MANAGER=1`.
