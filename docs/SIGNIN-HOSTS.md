# Sign-In Host Compatibility Matrix

This document records the measured compatibility of coding agent hosts with EnvCloak's web sign-in flow (`request_sign_in`, `sign_in_status`, `cancel_sign_in`, `end_sign_in_session`, and the companion `browser_*` tools).

Every row is populated from real release-check and harness probe runs, never assumed. Hosts other than the two tier-1 hosts start `unverified`.

## Summary by Host Tier

| Host | ID | Tier | Status | Per-Server Timeout Setting | Per-Tool Sign-In Approval (`--signin --consent-approval-mode`) |
| --- | --- | --- | --- | --- | --- |
| Claude Code | `claude-code` | Tier 1 | `verified` | `mcpServers.envcloak.timeout = 60000` (`~/.claude.json`) | `permissions.allow` entries for the 4 sign-in tools (`~/.claude/settings.json`) |
| Codex | `codex` | Tier 1 | `verified` | `mcp_servers.envcloak.tool_timeout_sec = 60` (`~/.codex/config.toml`) | `[mcp_servers.envcloak.tools.<tool>] approval_mode = "approve"` for the 4 sign-in tools (`~/.codex/config.toml`) |
| Cursor | `cursor` | Tier 2 | `unverified` | none documented (`~/.cursor/mcp.json`) | none (no per-tool config setting) |
| Gemini CLI | `gemini` | Tier 2 | `unverified` | `mcpServers.envcloak.timeout = 60000` (`~/.gemini/settings.json`) | none (`trust` is server-wide only; never set) |
| Copilot CLI | `copilot` | Tier 2 | `unverified` | `mcpServers.envcloak.timeout = 60000` (`~/.copilot/mcp-config.json`) | none (no per-tool approval mode setting) |
| OpenCode | `opencode` | Tier 2 | `unverified` | `mcp.envcloak.timeout = 60000` (`~/.config/opencode/opencode.json`) | none (no per-tool approval mode setting) |
| Kimi Code | `kimi` | Tier 2 | `unverified` | `mcpServers.envcloak.toolTimeoutMs = 60000` (`~/.kimi-code/mcp.json`) | none (no per-tool approval mode setting) |
| Qwen Code | `qwen` | Tier 2 | `unverified` | `mcpServers.envcloak.timeout = 60000` (`~/.qwen/settings.json`) | none (`trust` is server-wide only; never set) |
| Goose | `goose` | Tier 3 | `unverified` | manual YAML (`timeout: 60`) | none |
| Aider | `aider` | Tier 3 | `unverified` | no MCP client | none |

## Release-Check and Harness Probe Runs

Columns:
- **Host**: Agent host binary and pinned version.
- **OS**: Operating system and architecture where the run executed.
- **Model**: Model or scripted harness endpoint used for the run.
- **Configuration**: Installer flags and host invocation flags (`envcloak agents install --signin [--consent-approval-mode]`).
- **Used the tool**: Fraction of runs that invoked `request_sign_in` rather than improvising or bypassing the tool.
- **Finished**: Fraction of runs that completed the full sign-in flow and verified the resulting session without any credential or session value reaching stdout, stderr, or the transcript.
- **n**: Number of trials in the cell.

| Host | Version | OS | Model | Configuration | Used the tool | Finished | n | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Claude Code | `2.1.104` | macOS 15 arm64 | `claude-sonnet-4-6` | `install --signin --consent-approval-mode` (`claude -p`, `permissions.allow` for 4 sign-in tools, `timeout: 60000`) | 20/20 (100%) | 20/20 (100%) | 20 | `verified` |
| Claude Code | `2.1.280` | macOS 15 arm64 / Linux x86_64 | `scripted-anthropic-sse` | `install --signin --consent-approval-mode` (`claude -p`, no `--allowedTools`, `permissions.allow` for 4 sign-in tools, `timeout: 60000`) | 1/1 (100%) | 1/1 (100%) | 1 | `verified` |
| Codex | `0.114.0` | macOS 15 arm64 | `gpt-5.4` | `install --signin --consent-approval-mode` (`codex exec`, `approval_mode = "approve"` on 4 sign-in tools, `tool_timeout_sec = 60`) | 20/20 (100%) | 20/20 (100%) | 20 | `verified` |
| Codex | `0.159.2` | macOS 15 arm64 / Linux x86_64 | `scripted-openai-responses` | `install --signin --consent-approval-mode` (`codex exec -c 'approval_policy="never"'`, `approval_mode = "approve"` on 4 sign-in tools, `tool_timeout_sec = 60`) | 1/1 (100%) | 1/1 (100%) | 1 | `verified` |
| Cursor | `2026.02.27` | macOS 15 arm64 / Linux x86_64 | `-` | `install --signin --agent cursor` | `-` | `-` | 0 | `unverified` |
| Gemini CLI | `0.36.0` | macOS 15 arm64 / Linux x86_64 | `-` | `install --signin --agent gemini` | `-` | `-` | 0 | `unverified` |
| Copilot CLI | `1.0.90` | macOS 15 arm64 / Linux x86_64 | `-` | `install --signin --agent copilot` | `-` | `-` | 0 | `unverified` |
| OpenCode | `1.18.34` | macOS 15 arm64 / Linux x86_64 | `-` | `install --signin --agent opencode` | `-` | `-` | 0 | `unverified` |
| Kimi Code | `2.1.1` | macOS 15 arm64 / Linux x86_64 | `-` | `install --signin --agent kimi` | `-` | `-` | 0 | `unverified` |
| Qwen Code | `0.10.2` | macOS 15 arm64 / Linux x86_64 | `-` | `install --signin --agent qwen` | `-` | `-` | 0 | `unverified` |
| Goose | `1.53.0` | macOS 15 arm64 / Linux x86_64 | `-` | `install --signin --agent goose` | `-` | `-` | 0 | `unverified` |
| Aider | `0.86.0` | macOS 15 arm64 / Linux x86_64 | `-` | `install --signin --agent aider` | `-` | `-` | 0 | `unverified` |

## Approval Boundary Invariants

1. **No approval change without `--consent-approval-mode`**: Running `envcloak agents install --signin` without `--consent-approval-mode` writes the sign-in instruction line and the 60-second per-server tool timeout, and writes no host approval rule.
2. **Per-tool approval only for the four sign-in tools**: With `--signin --consent-approval-mode`, only `request_sign_in`, `sign_in_status`, `cancel_sign_in`, and `end_sign_in_session` are pre-approved at the host layer (because EnvCloak's daemon enforces its own TTY approval prompt for `request_sign_in`).
3. **Other tools still prompt**: `run_with_secrets`, `add_reference`, `list_secrets`, `project_status`, `request_new_secret`, and every `browser_*` tool are never pre-approved by the installer. Server-wide settings (`default_tools_approval_mode`, `mcp__envcloak__*`, `trust = true`) are never written.
4. **Other MCP servers untouched**: Existing MCP servers and their approval settings in `~/.claude.json`, `~/.claude/settings.json`, and `~/.codex/config.toml` remain byte-identical across `install` and `uninstall`.
