# EnvCloak: M1 acceptance

Status: M1, and the start of M2. This file says how the M1 acceptance story (SPEC §15.1) and every M1 gate (SPEC §15.2, gates 1 to 33) are tested, and where; the last section is M2's harness: the pinned agent hosts, the scripted model they are driven with, the store sweep and story step S0 (M2 plan task M2-04). M1 is done when the story and every gate pass on `macos-latest` and `ubuntu-latest` in CI (`.github/workflows/ci.yml`). The story's code is in `crates/envcloak-e2e/`.

## The story

`crates/envcloak-e2e/tests/fixture_story.rs` runs the story as one ordered test, on the built `envcloak` and `envcloakd`, in one isolated user: `HOME` and every `XDG_*` directory under a short `/tmp/ecXXXXXX` (so the socket path stays under macOS's 104-byte `sun_path`), a cleared environment for every process, and `envcloakd --foreground` started by absolute path.

- **The person** runs each command leading a session on a pseudo-terminal of its own, as in a terminal window, with no agent in its ancestry. What a command asks for on the terminal is typed when its prompt shows, waiting for the prompt's text, never for a time. Secrets on descriptors (`--passphrase-fd`, `--kit-fd`) come from files outside the home.
- **The agent** is `fixture-agent` (crates/envcloak-testkit), which the builtin catalog knows, running one shell for the whole story, with no terminal. A grant is scoped to that process instance, so it covers the agent's later commands.
- **The fixture repo** `acme-web` is generated at run time from `envcloak-testkit`'s canaries: `OPENAI_API_KEY` (an `sk-proj-` prefix, 64 bytes), `STRIPE_SECRET_KEY`, `GITHUB_TOKEN`, `DATABASE_URL` (a password with `/`, `"`, `+`, a space and a non-ASCII character), `SHORT_TOKEN` (10 bytes, in `.env.short`, so in the `short` profile only), `PORT=8080`, and a `.env.example`. No key-shaped literal is in the source.
- **Its command** `./emit` (`crates/envcloak-e2e/tests/fixtures/emitters/emit.py`) puts each value through every serializer gate 8 names: Python's `json.dumps` (`ensure_ascii` true and false), `quote` and `quote_plus` in upper and lower hex, form encoding, standard and URL-safe base64, padded and unpadded, at offsets 0, 1 and 2 of a larger payload, and lower and upper hex; Node's `JSON.stringify` (`emit.js`), Go's `encoding/json` (`emit.go`), .NET's `System.Text.Json` (`Emit.cs`), PHP's `json_encode` (`emit.php`) and serde_json (`ec-emit-serde`). Each result is written whole and in pieces, on standard output and standard error at once: every byte boundary of `DATABASE_URL`'s results, three boundaries of the others', with a 45 ms pause after each piece (the runner flushes after 40 ms idle), then bytes that are not UTF-8 around halves of a value. Last, each serializer prints the SHA-256 of each value it was given.
- **The sweep** runs after every step: everything any process printed, every daemon's log (the one S11 stops too), and the whole home with the fixture repo in it, for every canary (the values, the passphrases, a wrong passphrase typed once, the Recovery Kit) in every encoding `envcloak-testkit` knows, and for what each serializer made of each value, run outside EnvCloak before the story starts and loaded as bytes. Only the fixture repo's `.env` files are skipped, until S2 takes their secrets out.

| Step | What the test checks |
|---|---|
| S1 | `vault create --passphrase-fd 3 --kit-fd 4 --kdf-memory 64MiB`: created and unlocked; the kit went only to descriptor 4 |
| S2 | `init --import` (dry run, nothing written), then `init --import --yes`: every entry mapped to its item, providers detected, `envcloak.toml` and `.gitignore` created, every reference resolves. `init --delete-plaintext` is refused with `recovery_kit_unconfirmed` and changes nothing; after `recovery confirm --kit-fd 4` it deletes `.env.short`, rewrites `.env` to what was not imported (`PORT=8080` and a comment), and the encrypted file backup exists |
| S3 | `ls`, `show openai/acme-web` and `check` by the agent: metadata only. `status` says "daemon identity: unverified", and "hardened" or "unhardened" as `codesign` (macOS) or `/proc` (Linux) says |
| S4 | The agent's `run -- ./emit`: exit 125, `approval_required request=<ID>`, no output from the command, and the daemon's audit line `decision=pending id=<ID>` |
| S5 | `approve <ID> --for 1h` on the person's terminal: the statement shows the escaped command line, every binding, the agent and "new project"; a wrong passphrase is refused and counted (`status`: one failed proof); the right one makes the grant |
| S6 | The agent's run: exit 0; every serializer ran, every result's frames went through, markers stand where the values were, and every serializer's digest of every value matches. `run --profile short` needs its own approval, then exits 125 with `value_too_short`, naming the item, and starts nothing |
| S7 | `rotate openai/acme-web --stdin`, the new value on standard input and the passphrase typed on the terminal: one prior value kept; both grants stay |
| S8 | The agent's rerun: the digests of `OPENAI_API_KEY` are the new value's; neither value, nor any serializer's form of either, appears |
| S9 | The agent's `lock`, then its run: exit 125, `vault_locked`; `grants list` is empty |
| S10 | `unlock` on the person's terminal; the agent's run is `approval_required` again |
| S11 | `backup create`; the daemon stops (SIGTERM); `vault/` is deleted; a new daemon starts; `recover --backup <file> --kit-fd 4 --new-passphrase-fd 3`: restored and unlocked with 5 items; `ls` equals the listing before the backup (and S3's, apart from the rotation's date); after an approval with the new passphrase, the run's digests are the rotated value's |
| S12 | `audit verify`: no problem, the anchor matched, and the unanchored tail reported when there is one |
| S13 | The last sweep: nothing anywhere; `vault/`, `audit/` and `backups/` hold ciphertext only |

## Gate 12

`crates/envcloak-e2e/tests/gate12.rs`, with `RUST_LOG=trace` and `RUST_BACKTRACE=full` in every process:

- **Injected panics.** Both binaries print a panic's place in the source and never its message (`envcloak_sys::install_panic_hook`), and no backtrace. `envcloak internal panic` and `envcloakd internal panic` panic with what standard input holds, in every build. The test build also panics on request at places on a value path (`envcloak_sys::panic_point`, feature `testing`, which no release build has): the CLI holding a run's released values (`cli.run.released`), the CLI holding an env file's parsed values (`cli.import.parsed`), and the daemon about to send a run's values (`daemon.release`). Each message holds a fixture; none shows anywhere.
- **Malformed inputs holding fixtures.** Values on the command line wherever a name or an id goes, and in an argument that is not UTF-8; a manifest with a value where a reference goes, one that is not TOML, and one with a value as a variable name; env files whose broken lines hold values, for `init`, `import --scan`, `check` and `run --env-file`; a value where the Recovery Kit or a passphrase goes, and a value with a NUL byte on standard input; frames sent straight to the daemon's socket with a value as the method, as an unknown field, JSON-escaped where base64 goes, as a slug, in a request's paths and names, as the whole body, and after an oversized header.

CI also runs the whole workspace's suite at `RUST_LOG=trace` and `RUST_BACKTRACE=full`, and `TestHome` passes both settings on to every process the tests start (they choose what a program logs and hold no secret). No EnvCloak program reads `RUST_LOG` yet: M1 has no logger, and the daemon's log is the fixed lines it writes to standard error. The setting is kept so that logging added later runs at its most verbose under the same sweeps. Gate 12 rests on `gate12.rs`, the fixture story (swept after every step), and the sweeps of the tests that start processes with fixtures, each of which sweeps the streams and logs it captures, among them the service-managed daemon's log in `crates/envcloak-cli/tests/service.rs`.

## The release artifacts

CI's `release` job builds the binaries as shipped (`cargo build --release`: `panic = "abort"`, LTO, stripped) and runs `crates/envcloak-e2e` against them (`ENVCLOAK_E2E_BIN_DIR`, `ENVCLOAK_TEST_RELEASE_DIR`):

- `tests/release.rs`: a panic aborts (SIGABRT, where the test build, the control, exits 101), with the handler's one line and no message; started with the core limit raised, and on macOS signed with `get-task-allow`, an aborting release binary leaves no core file, while the positive control does dump core into `ENVCLOAK_TEST_CORE_DIR`; the names of the test-only hooks are in the test build and in neither release binary; `internal hardening` and `status` say what `codesign` or `/proc` says, and "daemon identity: unverified";
- the fixture story and gate 12, on the release binaries (the panic points exist only in the test build, and are skipped there).

## Every M1 gate

| Gate | Where |
|---|---|
| 1, 2 (crypto), 3 | `crates/envcloak-core/tests/seal_tamper.rs`, `crypto_kat.rs`; CRYPTO.md |
| 2 (storage), 5, 6, 7 | VAULT.md "Gates" |
| 3 (re-wrap), 4 | VAULT.md "Gates"; 4 through the daemon and the CLI (S11): IPC.md "Gates", and the story |
| 8, 9, 13, 14, 33 (release order) | RUN.md "Gates"; 8 through the whole of `run`, and 9's `--profile short`: the story (S6, S8) |
| 10, 15, 16 | IMPORT.md "Gates"; the story (S2) |
| 11 | `crates/envcloak-sys/tests/alloc_probe.rs` and the probes each doc's "Gates" names (IPC frames, dotenv, TOML and JSON parsing, seal and open, the child's environment, the redactor) |
| 12 | `crates/envcloak-e2e/tests/gate12.rs`, `release.rs`, the fixture story, and every test's sweep of what it captures (the suite runs at `RUST_LOG=trace` for logging to come) |
| 17 | MANIFEST.md "Gates" |
| 18 | PROVIDERS.md "Gates" |
| 19 | `crates/envcloak-cli/tests/hardening.rs`, `crates/envcloak-daemon/tests/hardening.rs`, `crates/envcloak-sys/tests/{harden,tracer,codesign}.rs`; for the release artifacts, `crates/envcloak-e2e/tests/release.rs` |
| 20, 21, 22, 32 (frames) | IPC.md "Gates" |
| 23, 24, 27 to 32 | GRANTS.md "Gates"; 23's wrong passphrase and 29's lock: the story (S5, S9, S10) |
| 25, 26 | AGENTS.md; GRANTS.md "Gates" |
| 33 | IPC.md and VAULT.md "Gates"; the story (S4, S12) |

## Running it

`cargo test --workspace` runs everything. The story needs `python3` (it drives the terminals), and uses whichever of `node`, `go`, `dotnet` and `php` are on `PATH`, building the Go and .NET emitters under the target directory; set `ENVCLOAK_TEST_REQUIRE_EMITTERS` (a comma list of `python`, `node`, `go`, `dotnet`, `php` and `serde`) to make a missing one a failure, as CI does. The daemon takes a proof only from a terminal session with no agent in its ancestry (SPEC §10b), so run the tests outside an AI coding agent's process tree: under one, every approval is refused, as it must be. Tests that start daemons run one at a time within each test binary, since Argon2id's memory times parallel vaults can exhaust a runner.

## M2: agent hosts, the scripted model and step S0

M2's gates are end to end with real agent hosts (M2 plan D-13): the pinned Claude Code and Codex binaries, pointed at a local scripted model in an isolated home, run EnvCloak in CI. M2 plan task M2-04 lands the harness, retires the risks it was planned to measure first (K-01, K-02, K-08, K-14, K-21), and runs story step S0. What the hosts were measured to do is in docs/AGENTS.md, "Host behaviour".

### The spike (2026-10-01)

Each tier-1 host was run with its model URL pointed at a recording server and `HTTPS_PROXY` pointed at the same server, which refuses every tunnel and records its target, so nothing else was reachable and every attempt was seen (on Linux CI the hosts also run with loopback only).

| Host | Model traffic | Tunnels it tried, refused | Runs headless with no further setup |
|---|---|---|---|
| Claude Code 2.1.280 (native and npm builds) | `POST /v1/messages?beta=true`: Anthropic Messages, streaming. Without a proxy it also sends `HEAD /api/hello` to the base URL, with no credential | `api.anthropic.com:443`; interactively also `raw.githubusercontent.com:443` and `downloads.claude.ai:443` | Yes: `-p` with `ANTHROPIC_BASE_URL` and the run's token as `ANTHROPIC_API_KEY`, in a fresh `HOME`. Interactive use needs onboarding done, the key approved and the workspace trust dialog answered |
| Codex 0.159.2 | `POST /v1/responses`: OpenAI Responses, streaming | `chatgpt.com:443`, `ab.chatgpt.com:443`, `github.com:443`, `api.github.com:443` | Yes: `exec` with a `model_providers.ec` entry in `$CODEX_HOME/config.toml` (it warns that it has no metadata for the model's name) |

Neither run depends on what it could not reach. What the scripted model therefore serves is these two endpoints, plus Claude Code's credential-less `HEAD /api/hello`; every other path is answered 404 and fails the run. Other findings:

- The npm build of Claude Code 2.x is the native binary: its install script copies the platform package's binary over `bin/claude.exe` (the same SHA-256 as the native download). Only with install scripts off is it started by `node cli-wrapper.cjs`, a launcher that runs the same binary as its child. The interpreter-launched npm build the agent catalog's `scripts` entry describes is the older one (M2-10 decides what the catalog keeps).
- The shell tools the scripted model calls: Claude Code's `Bash {command, description}`; Codex's `exec_command {cmd, ...}`, which returns what a command printed so far after `yield_time_ms` (10 s by default, at most 30 s) and expects the model to poll. Codex offers an MCP server's tools as a Responses `namespace` tool, `mcp__<server>`, and a call names the namespace.
- The Responses events the scripted model sends are the ones Codex 0.159.2's `process_responses_event` handles or ignores by name (`codex-rs/codex-api/src/sse/responses.rs` at `rust-v0.159.2`); `response.completed` carries the `id` and `usage` its `ResponseCompleted` requires.

**Tier 2: which hosts the scripted model can drive.** A host is drivable only if a documented setting points its model traffic at a base URL and it then speaks one of the scripted model's two protocols. No third protocol is added in M2. These hosts are installed at pinned versions (below) so M2-10 can observe their layouts; M2-24 drives the drivable ones.

| Host | Pinned | Documented base-URL setting | Protocol it then speaks | Drivable |
|---|---|---|---|---|
| Gemini CLI | 0.62.0 | `GOOGLE_GEMINI_BASE_URL` (Gemini API key auth) | Gemini API (`generateContent`) | No: `unverified (not_drivable)` |
| Copilot CLI | 1.0.90 | `COPILOT_PROVIDER_BASE_URL` with `COPILOT_PROVIDER_TYPE=anthropic`, or `openai` with `COPILOT_PROVIDER_WIRE_API=responses`; `COPILOT_OFFLINE=true` keeps it off GitHub's servers | Anthropic Messages, or OpenAI Responses | Yes |
| OpenCode | 1.18.34 | A provider's `options.baseURL`, with `@ai-sdk/openai` (Responses) or `@ai-sdk/anthropic` | OpenAI Responses or Anthropic Messages | Yes |
| Kimi Code | 2.1.1 | `[providers.<id>] type = "anthropic"` or `"openai_responses"` with `base_url` | Anthropic Messages or OpenAI Responses | Yes |
| Cursor CLI | 2026.09.28-64d2043 | None: its configuration names only `HTTP(S)_PROXY` and CA settings | | No: `unverified (not_drivable)` |
| Qwen Code | 0.24.7 | `modelProviders.anthropic` with `baseUrl`, or `openai` with `wireApi: "responses"` | Anthropic Messages or OpenAI Responses | Yes |

Sources: https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/reference/configuration.md, https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-byok-models and https://github.com/github/copilot-sdk/blob/main/docs/auth/byok.md, https://opencode.ai/docs/providers/, https://github.com/MoonshotAI/kimi-code/blob/main/docs/en/configuration/providers.md, https://cursor.com/docs/cli/reference/configuration, https://qwenlm.github.io/qwen-code-docs/en/users/configuration/model-providers/ (read 2026-10-01). Drivability here is what the documentation says; a host's probes report `not_qualified` until its pinned version has been run against the scripted model.

### The scripted model

`envcloak-probe-model`, a program of `crates/envcloak-agents` (`probe::model`), never linked into `envcloak` or `envcloakd` (`agent_hosts.rs` checks both binaries for its sentinel). It listens on `127.0.0.1` only, on a port the system picks, refuses a connection from any other address, and answers only requests that present the run's token (`x-api-key` or `Authorization: Bearer`; Claude Code's `HEAD /api/hello` is the one exception). Its HTTP/1.1 parser is hand-written on the standard library: `Content-Length` bodies only, at most 4 MiB a body and 16 MiB recorded in a run, after which the run is `incomplete`; everything outside the grammar is refused with a fixed error that echoes nothing. It replays a script of turns and tool calls (the step a request gets is the number of tool calls its conversation already holds, so retries get the same step), can hold a step's reply until the test releases it (a barrier, so a person can approve between two turns without timing), records every request body in wiping buffers until the run ends, and has a time limit. It is driven over its standard input and output (`ModelStub`; the testkit's `agents::Model`), never over the network. `qualified()` names the host versions it was run against (M2-28 reads it); a test keeps that table equal to the pinned tier-1 hosts.

Tests: `crates/envcloak-agents/tests/probe_model.rs` (both APIs, the 404, the token, a non-loopback peer, the body and run caps, malformed requests, the barrier, the time limit), `tests/probe_http_fuzz.rs` (random bytes and damaged real requests through the connection code: whole responses of known statuses or nothing, no panic, no echo, no recording past the caps). The libFuzzer target over the same entry point (`serve_bytes`) is M2-25's, with the rest of `fuzz/`.

### Pinned hosts

`crates/envcloak-e2e/agents/versions.toml` pins each host: version, install method and the SHA-256 of its entry file on `darwin-arm64` and `linux-x64`. `scripts/install-agent-hosts.py` installs them into a cache outside every HOME (`ENVCLOAK_AGENT_HOSTS`, else `<target>/agent-hosts`), keeping a host only when its download (where pinned) and its entry file hash as pinned. Tests find a host only when its entry file still hashes as pinned, and after every run check the hash again and that `--version` names the pinned version, so a host that updated itself fails the test. Updates are switched off by each host's own setting (`DISABLE_AUTOUPDATER=1`; `check_for_update_on_startup = false`), and Codex runs with `--strict-config`, so a setting it does not know fails the run. npm-installed tier-2 hosts are pinned by version and entry file; their dependencies resolve at install time.

### The agent home and the sweep

`envcloak-testkit::agents::AgentHome` is a `TestHome` set up for one host: a cleared environment, `ANTHROPIC_BASE_URL` and the run's token for Claude Code, `model_providers.ec` in `$CODEX_HOME/config.toml` with the token in `EC_MODEL_TOKEN` for Codex, `HTTPS_PROXY` at the model, and no developer or CI credential. Settings a test says the person made are written into the home and labelled so. Host flags are pinned per run and never a bypass mode (D-13): Claude Code `-p --permission-mode default` with an explicit `--allowedTools`; Codex `exec --sandbox <mode>` with `approval_policy` set, and `--dangerously-bypass-hook-trust` only in a probe home, where a test says so.

`envcloak-testkit::transcripts` lists every store D-15 names and the ones the pinned versions were seen to write:

| Host | D-15 | Also written by the pinned version |
|---|---|---|
| Claude Code | `~/.claude/projects/**`, `history.jsonl`, `paste-cache/`, `file-history/`, `backups/` | `~/.claude/{sessions,session-env,shell-snapshots,telemetry,todos,debug}/`, `~/.claude.json` and its backups beside it |
| Codex | `~/.codex/sessions/**`, `archived_sessions/**`, `history.jsonl`, `log/` | its SQLite stores in `$CODEX_HOME` (a command's output reaches `thread_history_1.sqlite`), `shell_snapshots/`, `memories/` |

A sweep reads each host's directory once, for every canary in every encoding `envcloak-testkit` knows, files each hit under its store and keeps a hit in none of them under `other`: raw counts, nothing filtered, the harness's own canaries included. The scripted model's request bodies are swept too. Every test that runs a host also sweeps the whole home. Positive control: a canary a scripted turn prints with plain `echo` is found in the host's transcript store and in its model requests; negative control: a run that never saw a canary leaves none anywhere. `crates/envcloak-testkit/tests/transcripts.rs` plants a canary in every store in five encodings made independently of the sweep's encoders.

### Step S0

`crates/envcloak-e2e/tests/m2_story/skeleton.rs` (the `m2_story` target, one module per task; M2-26 composes the story): the M1 fixture repo `acme-web` is imported by the person; each host, driven by the scripted model with its flags pinned, runs `envcloak run -- ./emit --quick` through its shell tool. Codex runs in `workspace-write` with the person's settings of §4 (command networking on, the network proxy on with no domain rule, one `unix_sockets` rule for EnvCloak's socket). The daemon answers `approval_required`, which the host sends its model; the person approves from a terminal of their own, the statement naming the host; the model's next turn, held by a barrier until then, reruns the command, which exits 0 with redaction markers where the values were. Every capture, every daemon log, the whole home, every host store and every model request are swept, with a positive control the same session printed found in the host's transcript.

On Linux, Codex 0.159.2 does not honour `unix_sockets` rules (its proxy's Unix socket support is macOS only, and its sandbox's seccomp filter refuses every Unix socket under the network proxy), so the CLI cannot reach the daemon from Codex's sandbox there (K-01, measured in `agent_hosts`). S0 then checks the other half of K-01 for Codex on Linux: both runs fail closed with `daemon_unverified` before a byte is sent, the daemon's audit log gains no request, and the same sweep is clean with the positive control found. Any other host or system that is refused fails the step.

### CI

`.github/workflows/ci.yml` carries the M2 trigger table (M2 plan §6). A `changes` job reads a pull request's paths. `gates` (pull requests, Linux) runs the `m2_story` target with the pinned tier-1 hosts restored from a cache keyed by `versions.toml` and the installer; `agents-e2e` runs `agent_hosts` on Linux for pull requests touching `envcloak-agents`, `envcloak-mcp`, the harness or `integrations/`, and `agent_hosts` with `m2_story` on both systems for main, nightly and manual runs. On Linux both run under `unshare --user --map-root-user --net` with loopback only. Only pull-request runs cancel their predecessors, so a main run always finishes. `release-check-models` (nightly and manual) is defined with its low-limit keys from Actions secrets; until the M2 instruction block exists (M2-08, V1) and the keys are configured, it states that it ran nothing, as a warning and in the job summary.

### Running it locally

`python3 scripts/install-agent-hosts.py --tier 1` (or `--tier all`), then `cargo test -p envcloak-e2e --test agent_hosts --test m2_story`, outside an AI coding agent's process tree (S0's approval is refused inside one, as it must be). A host that is not installed skips its test with a line on standard error; `ENVCLOAK_TEST_REQUIRE_AGENT_HOSTS=1` makes that a failure, as in CI. `ENVCLOAK_TEST_WRITE_FIXTURES=1` rewrites the hook payload fixtures, for a maintainer pinning a new version. `ec-model --script FILE [--record FILE] -- COMMAND` runs any command against a scripted model, for a measurement by hand. A machine with Claude Code managed settings (`/Library/Application Support/ClaudeCode/` on macOS) applies them to the pinned host too; CI has none.
