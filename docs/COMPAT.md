# Agent Host Compatibility (`docs/COMPAT.md`)

Status: M2 (SPEC v0.4.1, §7.1, §14, §15.2 gates 38 and 41).

This document summarizes the probed compatibility matrix in [`integrations/compat/matrix.toml`](../integrations/compat/matrix.toml), how `envcloak agents status` and `envcloak agents status --probe` report per-surface coverage, the sandbox behavior on macOS and Linux, and the real-model nightly and release-check protocol.

---

## 1. Pinned host matrix (`integrations/compat/matrix.toml`)

Every state reported for a tier-1 host rests on an activation-and-denial probe with a positive control (`crates/envcloak-e2e/tests/probes.rs` and `envcloak agents status --probe`). When a probe passes, the surface still reports `degraded` whenever a structural limitation applies (`fails_open_on_timeout`, `workspace_untrusted`, `hooks_untrusted`).

### Claude Code (`2.1.280`)

| OS | Surface | State | Reasons | Probe outcome & skipped cases |
|---|---|---|---|---|
| `macos`, `linux` | `prompt_to_model` | `degraded` | `fails_open_on_timeout`, `workspace_untrusted` | `passed` |
| `macos`, `linux` | `transcript` | `unsupported` | `persists_blocked_prompt` | `failed` (`interactive_history` skipped under `-p`; covered by the PTY interactive variant) |
| `macos`, `linux` | `file_read` | `degraded` | `fails_open_on_timeout`, `workspace_untrusted` | `passed` |
| `macos`, `linux` | `shell` | `degraded` | `fails_open_on_timeout`, `workspace_untrusted` | `passed` (unsandboxed `-p`; see §2 for sandboxed shells) |
| `macos`, `linux` | `mcp` | `degraded` | `fails_open_on_timeout`, `workspace_untrusted` | `passed` |
| `macos`, `linux` | `output` | `active` | none | `passed` |
| `macos`, `linux` | `envcloak_server` | `listed` | `needs_host_approval`, `outside_host_sandbox` | `passed`, `sentinel = appeared` |

Why `transcript` is `unsupported (persists_blocked_prompt)`: Claude Code writes the submitted prompt to its session `.jsonl` transcript (and, in interactive sessions, `~/.claude/history.jsonl`) before running `UserPromptSubmit` hooks. Blocking the prompt keeps the secret from reaching the model (`prompt_to_model`), but the local copy remains on disk until `envcloak scrub` removes it.

### Codex (`0.159.2`)

| OS | Surface | State | Reasons | Probe outcome & skipped cases |
|---|---|---|---|---|
| `macos`, `linux` | `prompt_to_model` | `degraded` | `fails_open_on_timeout`, `hooks_untrusted` | `passed` |
| `macos`, `linux` | `transcript` | `degraded` | `fails_open_on_timeout`, `hooks_untrusted` | `passed` (`interactive_history` skipped under `codex exec`) |
| `macos`, `linux` | `file_read` | `degraded` | `fails_open_on_timeout`, `hooks_untrusted` | `passed` |
| `macos` | `shell` | `degraded` | `fails_open_on_timeout`, `hooks_untrusted` | `passed` |
| `linux` | `shell` | `unsupported` | `sandbox_blocks_socket` | `passed` |
| `macos`, `linux` | `mcp` | `degraded` | `fails_open_on_timeout`, `hooks_untrusted` | `passed` |
| `macos`, `linux` | `output` | `active` | none | `passed` |
| `macos`, `linux` | `envcloak_server` | `listed` | `needs_host_approval`, `outside_host_sandbox` | `passed`, `sentinel = appeared` |

### Tier 2 and Tier 3 hosts (gate 38)

Hosts that are not driven by the scripted model in CI (`cursor`, `gemini-cli`, `copilot-cli`, `kimi`, `opencode`, `qwen-code`, `goose`, `aider`) report every hook surface as `unverified (not_probed)` and never `active`.

---

## 2. Host sandboxes and `run_with_secrets`

- **MCP servers run outside the host's sandbox (`outside_host_sandbox`):** Both Claude Code and Codex start MCP servers outside their command sandboxes. `run_with_secrets` starts a child `envcloak run`, so commands it runs execute outside the agent host's sandbox as well. The sentinel probe verifies this by writing a file where the host's own sandboxed shell is denied (`sentinel = appeared`).
- **Claude Code sandbox (`sandbox.enabled: true`, `allowUnsandboxedCommands: false`):**
  - On **macOS**, `envcloak agents install` writes `sandbox.network.allowUnixSockets` with the daemon socket path (with user consent), allowing `envcloak` inside the Seatbelt sandbox to reach `envcloakd` while outbound network connections remain blocked.
  - On **Linux**, `bubblewrap` places sandboxed shell commands in a fresh PID namespace where `SO_PEERCRED` reports the host daemon's PID as `0` (`daemon_unverified (pid_unavailable)`), and when the optional `@anthropic-ai/sandbox-runtime` seccomp filter is active, `AF_UNIX` stream sockets are blocked with `EPERM`. `envcloak agents install` writes no Linux sandbox exception; commands that need secrets under a sandboxed Linux session use `run_with_secrets` (which runs outside the host's sandbox) or run with the host's sandbox off.
- **Codex sandbox (`--sandbox workspace-write`):**
  - On **macOS**, Seatbelt allows `AF_UNIX` connections to the daemon socket.
  - On **Linux**, Landlock and bubblewrap block the daemon socket (`sandbox_blocks_socket`), so `shell` is reported `unsupported (sandbox_blocks_socket)`. `run_with_secrets` via EnvCloak's MCP server remains available.

---

## 3. Scripted-model CI gates and real-model release checks

1. **Deterministic CI gates (`gates`, `agents-e2e`, `probes`):**
   - Run on every qualifying pull request and push to `main` using the pinned Claude Code (`2.1.280`) and Codex (`0.159.2`) binaries driven by the local loopback scripted model (`envcloak-testkit::agents::Model`).
   - Verify the §4 M2 acceptance story (`S1` to `S18`, including `S12b` and `S12c`) and its three variants (`Interactive Claude Code`, `Sandboxed Claude Code`, `Five migrated servers`), with a full post-run sweep across all §6.1 encodings and a pre-scrub positive control.
2. **Nightly and manual real-model release-check runs (`release-check-models`):**
   - Triggered in `.github/workflows/ci.yml` on the nightly schedule (`17 16 * * *`) and via `workflow_dispatch` when `vars.ENVCLOAK_RELEASE_CHECK_MODELS == 'on'` and `ENVCLOAK_RELEASE_CHECK_ANTHROPIC_KEY` and `ENVCLOAK_RELEASE_CHECK_OPENAI_KEY` are configured in repository secrets.
   - Runs 5 iterations per (`host`, `os`) cell (`claude-code` and `codex` on `ubuntu-latest` and `macos-latest`) against live Anthropic and OpenAI models, checking every encoding (raw, JSON-escaped, URL-encoded, base64, base64url, hex, and CR LF variants) and verifying the positive control.
   - **Release rule (SPEC §15.2 gate 41, M2 plan Q-01):** A milestone release requires at least 20 real-model runs per tier-1 host across the `release-check-models` series in which the host chooses EnvCloak (`envcloak run` or `run_with_secrets`) instead of reading `.env` directly in at least 80% of runs, with 0 fixture hits in every run. Any host below 80% is recorded here as `not reliably used`; a single fixture hit in any run holds the release.

| Host | Pinned version | OS | Scripted-model story (`S1..S18`) | Real-model status (`release-check-models`) |
|---|---|---|---|---|
| `claude-code` | `2.1.280` | `macos`, `linux` | `passed` (0 fixture leaks, positive control > 0) | Tracked by `release-check-models` (threshold: >= 80% over >= 20 runs, 0 leaks; otherwise `not reliably used`) |
| `codex` | `0.159.2` | `macos`, `linux` | `passed` (0 fixture leaks, positive control > 0) | Tracked by `release-check-models` (threshold: >= 80% over >= 20 runs, 0 leaks; otherwise `not reliably used`) |
