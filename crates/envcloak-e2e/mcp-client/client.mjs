// The independent MCP client of M2 plan task M2-06 (lesson L-02): the
// official MCP TypeScript SDK, pinned by package-lock.json in this
// directory and installed by scripts/install-agent-hosts.py into the agent
// host cache, drives `envcloak mcp` over stdio as a host would.
//
// usage: node client.mjs <sdk-node_modules> <plan.json>
//
// The plan: {"command": "...", "args": [...], "env": {...}, "cwd": "...",
// "steps": [...]}, each step one of
//   {"list": true}                          tools/list
//   {"call": "<tool>", "arguments": {...}}  tools/call, the SDK validating
//                                           structured output against the
//                                           tool's outputSchema
//   {"barrier": "<name>"}                   prints {"barrier": name} and
//                                           waits for a line on stdin
// Every result is printed as one JSON line on standard output: {"step": i,
// "result": ...}, or {"step": i, "error": {"code": ..., "message": ...}}
// when the SDK throws (a protocol error, or structured output that does
// not match its schema). The first line is {"initialized": ...}: the
// version the session agreed, the server's info, capabilities and
// instructions. The server's standard error is passed on to this
// program's.

import { readFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { join } from "node:path";

const [sdkModules, planPath] = process.argv.slice(2);
const sdk = join(sdkModules, "@modelcontextprotocol", "sdk", "dist", "esm");
const { Client } = await import(pathToFileURL(join(sdk, "client", "index.js")).href);
const { StdioClientTransport } = await import(pathToFileURL(join(sdk, "client", "stdio.js")).href);

const plan = JSON.parse(readFileSync(planPath, "utf8"));
const lines = createInterface({ input: process.stdin });
const waiting = [];
const queued = [];
lines.on("line", (l) => {
  const w = waiting.shift();
  if (w) w(l);
  else queued.push(l);
});
const nextLine = () =>
  new Promise((resolve) => {
    const l = queued.shift();
    if (l !== undefined) resolve(l);
    else waiting.push(resolve);
  });
const print = (v) => process.stdout.write(JSON.stringify(v) + "\n");

const transport = new StdioClientTransport({
  command: plan.command,
  args: plan.args,
  env: plan.env,
  cwd: plan.cwd,
  stderr: "pipe",
});
const client = new Client({ name: "envcloak-e2e-sdk-client", version: "1.0.0" });
// The server's diagnostics go on, to be swept with everything else.
transport.stderr?.on("data", (d) => process.stderr.write(d));
await client.connect(transport);
print({
  initialized: {
    protocolVersion: transport._protocolVersion ?? null,
    serverVersion: client.getServerVersion(),
    capabilities: client.getServerCapabilities(),
    instructions: client.getInstructions(),
  },
});

// Long enough for a command split byte by byte; a host's own cutoff is
// what the server's wait is set against, not this.
const options = { timeout: 600000 };
for (const [i, step] of plan.steps.entries()) {
  try {
    if (step.list) {
      print({ step: i, result: await client.listTools({}, options) });
    } else if (step.call) {
      const result = await client.callTool(
        { name: step.call, arguments: step.arguments ?? {} },
        undefined,
        options,
      );
      print({ step: i, result });
    } else if (step.barrier) {
      print({ barrier: step.barrier });
      await nextLine();
    }
  } catch (e) {
    print({ step: i, error: { code: e?.code ?? null, message: String(e?.message ?? e) } });
  }
}
await client.close();
lines.close();
