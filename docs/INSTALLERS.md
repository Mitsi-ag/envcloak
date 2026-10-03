# Agent installers and the hook handler

Status: M2 (task M2-08). This file fixes what `envcloak agents install` writes for Claude Code and Codex, how it changes an agent's files, how `envcloak agents uninstall` takes it out, and what `envcloak hook`, the handler the hosts' hooks run, decides. The code is in `crates/envcloak-agents` (`install.rs`, `hosts/`, `writer.rs`, `jsonedit.rs`, `blocks.rs`, `detect.rs`, `locations.rs`, `hook/`), `crates/envcloak-cli/src/cmd/{agents,hook,init}.rs` and `integrations/`. Coverage reporting (`envcloak agents status`) is M2-09 and M2-28; the other hosts' installers are M2-24; `migrate-mcp` is M2-20.

Installed is not protected (SPEC §7.1). Everything here prevents accidents: an agent with the person's shell can switch hooks off, edit these files or run a program the hook does not read. Enforcement is the approval proof, the grants and the manifest (SPEC §7.2 rule 4, §10).

## Commands

- `envcloak agents install [--global] [--project] [--agent claude-code|codex]... [--consent-sandbox-sockets] [--yes] [--json]`. Without `--yes` it lists every file and every change, and writes nothing. With it, the daemon must be running and unlocked, since every file is backed up before it changes. Each tier-1 host found on `PATH` is taught (or only those named with `--agent`, whose absence is then a failure). `--global` is the default; `--project` writes the instruction block into the project's own instruction file instead (below), and with both, both.
- `envcloak agents uninstall [--global] [--project] [--agent ID]... [--yes] [--json]` takes out what `install` added (below). Without `--yes` it lists it.
- `envcloak init --agents-note` writes the project's instruction block as `agents install --project --yes` does (SPEC §6.4 step 4); not in a dry run of `--import`.
- `envcloak hook --host claude-code|codex --event UserPromptSubmit|PreToolUse|SessionStart`, which the hosts run.

Exit 0 when every change was made or was there already; otherwise 1 with `agents_incomplete`, after the report's line for each file left as it was says why. A host that is not installed is reported, and fails the run only when named with `--agent`.

## Hosts are detected, never assumed

A host is the executable of its name on `PATH` (`claude`, `codex`) asked for its `--version` with a cleared environment (`HOME`, `PATH` and the host's own location variable) and a 5-second limit. The answer is read strictly: Claude Code's `<version> (Claude Code)`, Codex's `codex-cli <version>`, the version three runs of digits with an optional pre-release. Any other answer is `not_recognized`, and nothing is written for that host (SPEC §7.2 rule 1).

## What install writes

### Claude Code

| File | What | Rule |
|---|---|---|
| `~/.claude/CLAUDE.md` | the instruction block | |
| `~/.claude/settings.json` | hooks: `UserPromptSubmit`; `PreToolUse` with matcher `Bash\|Read\|Grep\|Glob\|Edit` and with matcher `mcp__.*`; `SessionStart`, each `<envcloak> hook --host claude-code --event <name>` with EnvCloak's absolute path and a 10-second host timeout | Claude Code may rewrite it: D-16 (below) |
| | `permissions.deny` `Read(**/.env*)`, which Claude Code also applies, best effort, to `@` file mentions no hook sees | |
| | `sandbox.credentials.files` deny entries for `<data>/vault` and `<data>/backups` | |
| | macOS: `sandbox.network.allowUnixSockets` naming EnvCloak's socket by its resolved path (M2-04 measured that the sandbox compares resolved paths) | |
| MCP server `envcloak` (user scope) | registered with `claude mcp add-json --scope user envcloak '{"command": <envcloak>, "args": ["mcp", "--host", "claude-code"], "timeout": 60000}'`, then checked with `claude mcp get envcloak` and by reading `~/.claude.json` | `~/.claude.json` is never edited by EnvCloak (Claude Code rewrites it on every start, D-16); it is backed up before the command changes it |

`CLAUDE_CONFIG_DIR` moves the directory and its `.claude.json`. `excludedCommands` is never written. No approval setting is written for any EnvCloak tool (D-22): Claude Code asks before each call of `run_with_secrets`, which runs commands outside its sandbox (D-03).

When the EnvCloak plugin (`integrations/claude-code/`, below) is enabled in the person's settings, only the instruction block is written: the plugin carries the hooks and the MCP server, and installing them again would run each hook twice.

### Codex

| File | What | Rule |
|---|---|---|
| `~/.codex/AGENTS.md` | the instruction block, unless `~/.codex/AGENTS.override.md` exists: Codex then reads the override instead, so nothing is written, the report asks the person to add the block to the override or remove it, and the instruction surface reads `degraded (override_file)` | |
| `~/.codex/hooks.json` | hooks: `UserPromptSubmit`; `PreToolUse` with matcher `Bash` (Codex's shell tools reach hooks as `Bash`) and with matcher `mcp__.*`; `SessionStart`, 10-second timeout | |
| `~/.codex/rules/envcloak.rules` | `forbidden` prefix rules for `printenv`, `export -p`, `envcloak reveal`, `envcloak approve`, and `cat`, `head`, `tail`, `less`, `more`, `bat`, `source` and `.` of the usual env file names, each with examples Codex checks when it loads the file | EnvCloak's whole: removed by uninstall |
| `~/.codex/config.toml` | `[mcp_servers.envcloak]`: `command` (EnvCloak's absolute path), `args = ["mcp", "--host", "codex"]`, `tool_timeout_sec = 60`, and on Linux `env_vars` naming `XDG_RUNTIME_DIR`, `XDG_DATA_HOME` and `XDG_STATE_HOME`, which place EnvCloak's socket and data | Codex rewrites it: D-16 |
| | macOS, only with `--consent-sandbox-sockets`: `sandbox_workspace_write.network_access = true`, `[features.network_proxy] enabled = true` with no domain rule, and one `[features.network_proxy.unix_sockets]` rule allowing EnvCloak's socket (the bounded setting M2-04 qualified: from `workspace-write` a command reaches EnvCloak's socket and nothing else) | |

`CODEX_HOME` moves the directory. No approval setting is written for any EnvCloak tool (D-22): Codex documents that a destructive tool always asks, and under `codex exec` with approval policy "never" a call of `run_with_secrets` is refused, so EnvCloak's MCP surface there reads `degraded (needs_host_approval)`. Codex runs non-managed hooks only once the person trusts them in `/hooks`; until then they read `degraded (hooks_untrusted)`, and the report says so. The report also notes that Codex passes its own environment to the commands it runs, names holding `KEY`, `SECRET` or `TOKEN` included, unless `shell_environment_policy` says otherwise.

### The sandboxed shell, by system (K-01)

macOS: Claude Code's allowance needs no consent (one socket, SPEC §7); Codex's turns on command networking limited to EnvCloak's socket, so it needs `--consent-sandbox-sockets`, and without it the report says the sandboxed shell cannot reach EnvCloak. Linux: no socket allowance and no broader network setting is written for either host, with or without consent: M2-04 measured that no documented setting lets the pinned Linux sandboxes reach and verify the daemon (Claude Code's `allowAllUnixSockets` reaches the socket, but the sandbox's pid namespace hides the daemon's pid, which EnvCloak's client requires; Codex's proxy honours `unix_sockets` on macOS only), so the sandboxed shell is `unsupported (sandbox_blocks_socket)` there and the report says so. SPEC §7 still says the Linux installer "asks first" before `allowAllUnixSockets`; this build follows the measurement (plan cycle249, K-01), and the SPEC follow-up is requested.

### The project scope

`--project` (and `init --agents-note`) writes the instruction block into the project's own file, following Map C §6: `CLAUDE.md` when it exists, `AGENTS.md` when it exists, and a new `AGENTS.md` when neither does (Codex reads it, and Claude Code reads it when there is no `CLAUDE.md`). It never creates `CLAUDE.md` or `CLAUDE.local.md` beside a lone `AGENTS.md`. The project is the directory of the nearest `envcloak.toml`, else the working directory.

## The instruction block

The same bytes in every file (so hosts that read several can tell the copies are one), between the lines `<!-- envcloak:begin -->` and `<!-- envcloak:end -->`, which Claude Code strips from context; the instructions are never inside an HTML comment. Its text (`envcloak_agents::blocks::INSTRUCTIONS`) names only commands this build ships (`run`, `ls`, `ref`, `add`, `init`) and never `--ask`, which comes with the app (M3; D-20). It is worded for any agent: it never says a hook will stop anything, since some hosts that read these files run no hook.

A file is refused, and reported, when it is not UTF-8, when its markers are repeated, unpaired, out of order or not lines of their own, and when it ends inside an open HTML comment or code fence (the block would be hidden there). An older block is replaced in place.

## How a file is changed

`envcloak_agents::writer` (lesson L-11):

1. The file is read beneath its directory, never through a symlink. A symlink, a file with another hard link, one that is not a regular file of this user, and one over 1 MiB are refused and reported, never changed.
2. JSON is read strictly (RFC 8259): comments and trailing commas (JSONC) are refused and named, as are a key given twice in one object, a byte-order mark, invalid UTF-8, a lone surrogate, control characters in strings and nesting past 64. Edits change only the spans they add to: every other byte stays, in a file laid out on lines the new entry goes on a line of its own at its siblings' indentation, in a one-line file on that line. TOML is edited key by key with `toml_edit`, which keeps the rest of the file as it was; a key given twice is refused. An MCP server named `envcloak` that EnvCloak did not write is a conflict, refused.
3. **D-16.** A file the host rewrites itself (Claude Code's `settings.json`, Codex's `config.toml`) is changed only while no other process has it open and when it was not modified in the last 2 minutes: quit the agent and run again. A file whose stamp (device, inode, size, modification and change times, mode, links, owner) is still the one EnvCloak recorded right after its own last write is not held to the 2 minutes, so `agents install` and an EnvCloak edit of the same file right after it (`agents install` again, `uninstall`, `migrate-mcp`) work without waiting or backdating. A change by the host or the person in between makes the stamp another, and the 2 minutes apply again.
4. An existing file is backed up first, as a backup v2 the daemon seals with purpose `agents` (docs/IPC.md "Backups v2"); without the backup nothing changes. After the change its result, the SHA-256 of what the change left, is recorded.
5. The file is replaced in one step only if it is still the file read (`envcloak_scan::replace_atomically`, the stamp checked again, change time included); a new file is created only if its name is still free (mode 0600).
6. The new stamp, the exact splice made (where, what was there, what went in) and the edits it stands for (a block, an array element, a TOML key and what it held before) are kept in `<data>/agents/state.json` (0600, its directory 0700), locked while an install or uninstall runs.

## How uninstall takes it out

For each file the state names for the hosts and scopes given:

- still byte for byte what EnvCloak last left (its SHA-256): the splices are undone in reverse, which gives back the file as it was before the first install, byte for byte, its SHA-256 checked; a file EnvCloak created is removed;
- changed since (the host rewrote it, the person edited it): only EnvCloak's edits are taken out, by structure (the block; the array elements equal to the ones added, and the objects and arrays the install created once they are empty; the TOML keys still holding what EnvCloak wrote, set back to what they held before or removed); a file EnvCloak created that holds nothing else is removed.

The same D-16 rule, backup and atomic replacement apply. The MCP server is removed with `claude mcp remove --scope user envcloak` only while `~/.claude.json` holds exactly the entry EnvCloak registered.

## The hook handler

`envcloak hook` reads the payload from standard input into wiped storage, at most 2 MiB, within 2 seconds of its start. Decisions are pure functions of the payload (`envcloak_agents::hook::decide`, D-12): the same payload always gets the same answer, so a hook a host fires twice (natively and through another host's import) agrees with itself. Nothing is compared with the vault and nothing is sent anywhere.

| Event | Decision |
|---|---|
| `UserPromptSubmit` | stop the prompt when, as written or with the `<pasted_content id="…">` lines around pastes taken out (so a key pasted in two parts is read whole), it holds a word a provider's key pattern matches, a URL with a password, or a run of 24 or more ASCII letters and digits that holds both, other than one of exactly 40 or 64 hexadecimal digits in one case (a commit or a digest) |
| `PreToolUse` | stop a shell command (`Bash`) that reads an env file, prints the environment, or runs `envcloak reveal` or `envcloak approve`, and one whose commands cannot be told (below); Claude Code's `Read` and `Edit` of an env file, and its `Grep` of one (by path, or by a `glob` that matches one); an MCP tool call any of whose string arguments names an env file; and `mcp__envcloak__run_with_secrets` with an argv in those classes. `Glob` lists names only and is let through |
| `SessionStart` | add, as context, the names (never the values) of the variables the session directory's `envcloak.toml` binds, from the daemon, and the one-line usage rule; nothing when there is no manifest or the daemon does not answer in time |

An env file is one `envcloak_scan::dotenv_kind` names (`.env`, `.env.<profile>`, and a `.env.` suffix it cannot read); templates (`.env.example` and the like) hold names only and are not. Reading the shell command: see `crates/envcloak-agents/src/hook/shell.rs` for the grammar read. A command whose structure cannot be told is stopped too (`ambiguous`): an unfinished quote or substitution, a command named by a variable (`$CMD`, `c${IFS}at`), `eval` or `sh -c` of text only known when it runs, or nesting past 24.

**Answers.** Allowed: no output, exit 0. Stopped: the host's JSON on standard output (Claude Code: `decision: "block"` with `hookSpecificOutput.suppressOriginalPrompt` for a prompt, `permissionDecision: "deny"` for a tool call; Codex: `decision: "block"` for a prompt, `permissionDecision: "deny"` for a tool call), the message on standard error, and exit 2, which stops the action on both hosts even where the JSON is not read. Every message starts with EnvCloak's marker `[envcloak:<reason>]` (`key_in_prompt`, `env_file`, `env_dump`, `reveal`, `approve`, `ambiguous`, `unchecked`), which the probes look for (M2-09), says what to do instead and that the hook prevents accidents; none echoes what it matched. A payload over 2 MiB or not all there within the 2 seconds stops the prompt or the tool call (`unchecked`). A payload that is not the one `--host` and `--event` name (another event, another host's shape, a field of the wrong type, not JSON) gets no decision: `envcloak: hook_payload: ...` on standard error and exit 1, which both hosts take as a hook error that stops nothing. A usage error exits 1 too, never 2.

**The same check in the MCP server.** `run_with_secrets` refuses an argv in the classes above before it asks the daemon anything, with the hook's message and the token `command_refused` (D-22), so a host without hooks gets the same accident prevention.

**Fails open.** A hook that does not answer within the host's timeout lets the action through on both hosts (Claude Code documents it; Codex was measured, docs/AGENTS.md). Hook-based surfaces therefore read `fails_open_on_timeout` and are never `active` (SPEC §7.1).

### What the hook does not see

Each row is a way past the hook, with the commands of the bypass corpus (`crates/envcloak-agents/tests/hook_bypass.rs`) the hook lets through. The test keeps this table equal to what the code misses: a command the code starts catching, or a new one it misses, fails it until this table says so (lesson L-15).

<!-- hook-misses:begin -->
| What | Example |
|---|---|
| A value only known when the command runs: a file name or a variable held in a variable, a loop or a substitution | `f=.env; cat "$f"`, `for f in .env*; do cat "$f"; done`, `cat $(echo .env)`, `echo $OPENAI_API_KEY` |
| File names piped to `xargs` | `ls -a \| grep '^.env' \| xargs cat` |
| A script a shell or an interpreter reads: its own code, a file, a pipe | `python3 -c 'print(open(".env").read())'`, `node -e 'console.log(process.env)'`, `bash script.sh`, `printf 'cat .env' \| sh` |
| A copy, or the file under another name | `cp .env notes.txt && cat notes.txt`, `ln -s .env x && cat x` |
| A program not on the reader list | `git show HEAD:.env`, `iconv -f utf-8 -t utf-8 .env` |
| A recursive search of a directory holding an env file | `grep -r KEY .` |
| Shell options that change globbing | `shopt -s dotglob; cat *` |
| An alias or a function defined in an earlier command or the shell's startup files | `e` |
| A relative path into `/proc` | `cd /proc/self && cat environ` |
<!-- /hook-misses -->

The prompt check misses: a key made of words and separators that no provider pattern names (an AWS secret access key on its own), a key of exactly 40 or 64 hexadecimal digits, and a key encoded or broken up by other text. Hooks see only what the host passes them: Codex's `write_stdin` into a running session does not rerun `PreToolUse`, hosted tools are not covered, and `@` mentions never reach Claude Code's `PreToolUse` (the `Read(**/.env*)` deny rule covers them, best effort).

## Claude Code plugin

`integrations/claude-code/` is the same integration as a plugin for people who install through a marketplace: `.claude-plugin/plugin.json`, `skills/envcloak/SKILL.md` (the instruction block's text), `hooks/hooks.json` (the same hooks, with `envcloak` found on `PATH`) and `.mcp.json` (the same server). `integrations/codex/` holds the Codex hook and rules files as written. With the plugin enabled, `agents install` writes only the instruction block (above).

## Tests

| Requirement | Tests |
|---|---|
| R-M2-53, R-M2-60: managed blocks, idempotent, removed cleanly | `crates/envcloak-agents/src/blocks.rs`, `crates/envcloak-cli/tests/agents.rs`, `crates/envcloak-e2e/tests/m2_story/install.rs` (configs the real hosts' own CLIs wrote: install then uninstall byte-identical, twice equals once, each host still lists its MCP servers) |
| R-M2-54, D-20: the block names shipped commands only, never `--ask` | `blocks.rs` (`the_block_names_shipped_commands_only`), `crates/envcloak-cli/tests/agents.rs` (`every_command_the_block_names_is_shipped`) |
| R-M2-55, R-M2-58, R-M2-67, R-M2-42: hooks, payload parsers, value-free and bounded | `crates/envcloak-agents/src/hook/`, `crates/envcloak-agents/tests/hook_bypass.rs` (the captured payloads of the pinned hosts, the bypass corpus and this table, hostile and fuzzed input), `crates/envcloak-cli/tests/hook.rs` (2 MiB and the 2-second limit, a 100 MiB payload, nothing echoed), `m2_story/install.rs` (the real hosts stop a pasted key and `printenv` with EnvCloak's marker, with controls) |
| R-M2-82, D-22: `run_with_secrets` argv refusal | `crates/envcloak-cli/tests/mcp.rs` (`hook_classes_are_refused_before_the_daemon_is_asked`) |
| R-M2-56, R-M2-35, K-01: sandbox and MCP settings | `crates/envcloak-agents/src/hosts/`, `crates/envcloak-cli/tests/agents.rs`, `m2_story/install.rs` (macOS: Codex's `workspace-write` sandbox reaches EnvCloak's socket and nothing else after install) |
| D-16, L-11: the writer | `crates/envcloak-agents/src/writer.rs`, `crates/envcloak-cli/tests/agents.rs` (symlinks, hard links, 4 MiB, non-UTF-8, the 2 minutes and EnvCloak's own stamp) |
| D-02, F-75: the scanner's descriptors and the one-way graph | `crates/envcloak-agents/tests/catalog_graph.rs`, `scripts/check-crate-graph.py` |
