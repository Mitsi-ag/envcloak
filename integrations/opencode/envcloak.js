// envcloak-managed: opencode-plugin-v1
// Written by `envcloak agents install` (detected OpenCode plugin API: v1).
// Serves both OpenCode v1 (exported async function) and v2 (`{ id, server }`).
import { spawnSync } from "node:child_process";

const ENVCLOAK_BIN = "envcloak";

const createHooks = async ({ directory } = {}) => ({
  "tool.execute.before": async (input, output) => {
    const payload = JSON.stringify({
      hook_event_name: "PreToolUse",
      session_id: String((input && input.sessionID) || ""),
      cwd: String(directory || process.cwd()),
      tool_name: String((input && input.tool) || ""),
      tool_input: (output && output.args) || {},
    });
    const proc = spawnSync(
      ENVCLOAK_BIN,
      ["hook", "--host", "opencode", "--event", "PreToolUse"],
      {
        input: payload,
        encoding: "utf8",
        timeout: 5000,
      },
    );
    if (proc.status === 2) {
      let reason = (proc.stderr || "").trim();
      if (!reason && proc.stdout) {
        try {
          const parsed = JSON.parse(proc.stdout);
          reason = parsed.reason || "";
        } catch {
          reason = proc.stdout.trim();
        }
      }
      throw new Error(reason || "[envcloak] Blocked by EnvCloak policy");
    }
  },
});

const EnvCloakPlugin = async (ctx) => createHooks(ctx);
EnvCloakPlugin.id = "envcloak";
EnvCloakPlugin.server = createHooks;

export { EnvCloakPlugin };
export default EnvCloakPlugin;
