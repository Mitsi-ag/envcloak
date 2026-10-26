#!/usr/bin/env node
"use strict";

// D-34 / R-M2b-49 process measurements for the pinned headless Chrome for
// Testing, by observation only (no signal is sent to any process):
// 1. Starts headless Chrome in its own session (`detached: true`, which calls
//    setsid()) with `--remote-debugging-pipe` on descriptors 3 and 4.
// 2. Exchanges `Browser.getVersion` and `Target.createTarget` over the pipe
//    so the browser and its helper processes (GPU, network, renderer) are up.
// 3. Observes the process table and session IDs (`os.getsid(pid)` via python3
//    without signalling anything) to verify that no process created by Chrome
//    lives outside the session it was started in.
// 4. Closes the parent's ends of the debugging pipe (`fd 3` write end and
//    `fd 4` read end) without sending any signal, and measures whether
//    headless Chrome and every member of its session exit on their own.

const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

async function main() {
  const chromeExe = process.argv[2];
  if (!chromeExe || !fs.existsSync(chromeExe)) {
    throw new Error(`chrome_executable_missing:${chromeExe}`);
  }
  const udir = fs.mkdtempSync(path.join(os.tmpdir(), "ec-cft-pipe-"));
  const tStart = Date.now();
  try {
    const child = spawn(
      chromeExe,
      [
        "--headless",
        "--remote-debugging-pipe",
        `--user-data-dir=${udir}`,
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        "about:blank",
      ],
      {
        detached: true,
        stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"],
      }
    );

    const pipeWrite = child.stdio[3];
    const pipeRead = child.stdio[4];
    const pending = new Map();
    let buf = Buffer.alloc(0);

    pipeRead.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      while (true) {
        const nul = buf.indexOf(0);
        if (nul === -1) break;
        const raw = buf.subarray(0, nul).toString("utf8");
        buf = buf.subarray(nul + 1);
        if (!raw) continue;
        try {
          const msg = JSON.parse(raw);
          if (msg.id && pending.has(msg.id)) {
            const resolve = pending.get(msg.id);
            pending.delete(msg.id);
            resolve(msg);
          }
        } catch {}
      }
    });

    const cdpCall = (id, method, params = {}) =>
      new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`cdp_timeout:${method}`));
        }, 8000);
        pending.set(id, (msg) => {
          clearTimeout(timer);
          resolve(msg);
        });
        pipeWrite.write(JSON.stringify({ id, method, params }) + "\0");
      });

    const ver = await cdpCall(1, "Browser.getVersion");
    await cdpCall(2, "Target.createTarget", { url: "about:blank" });
    const startupMs = Date.now() - tStart;

    const pyScript = `
import json, os, subprocess, sys
leader = int(sys.argv[1])
ps = subprocess.check_output(["ps", "-axo", "pid=,ppid=,pgid=,command="], text=True)
children = {}
commands = {}
for line in ps.splitlines():
    parts = line.split(None, 3)
    if len(parts) < 4:
        continue
    pid, ppid = int(parts[0]), int(parts[1])
    children.setdefault(ppid, []).append(pid)
    commands[pid] = parts[3]
tree = []
stack = [leader]
while stack:
    cur = stack.pop()
    if cur not in tree:
        tree.append(cur)
        stack.extend(children.get(cur, []))
leader_sid = os.getsid(leader)
outside = []
for p in tree:
    try:
        sid = os.getsid(p)
        if sid != leader_sid:
            outside.append({"pid": p, "sid": sid, "cmd": commands.get(p, "")})
    except OSError:
        pass
print(json.dumps({
    "leader_pid": leader,
    "leader_sid": leader_sid,
    "tree_pids": tree,
    "outside_session": outside,
}))
`;
    const obsRaw = execFileSync("python3", ["-c", pyScript, String(child.pid)], {
      encoding: "utf8",
    });
    const obs = JSON.parse(obsRaw.trim());

    const tClose = Date.now();
    const exitPromise = new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("chrome_did_not_exit_on_pipe_close")), 8000);
      child.on("exit", (code, signal) => {
        clearTimeout(timer);
        resolve({ code, signal });
      });
    });

    pipeWrite.destroy();
    pipeRead.destroy();
    const exitRes = await exitPromise;
    const pipeExitMs = Date.now() - tClose;

    const pyAfterScript = `
import json, subprocess, sys
pids = [int(x) for x in sys.argv[1].split(",") if x]
ps = subprocess.check_output(["ps", "-axo", "pid="], text=True)
alive_set = {int(line.strip()) for line in ps.splitlines() if line.strip().isdigit()}
remaining = [p for p in pids if p in alive_set]
print(json.dumps({"remaining_pids": remaining}))
`;
    const afterRaw = execFileSync(
      "python3",
      ["-c", pyAfterScript, obs.tree_pids.join(",")],
      { encoding: "utf8" }
    );
    const after = JSON.parse(afterRaw.trim());

    process.stdout.write(
      JSON.stringify({
        ok: true,
        product: ver.result?.product || "",
        startup_ms: startupMs,
        pipe_close_exit_ms: pipeExitMs,
        exit_code: exitRes.code,
        exit_signal: exitRes.signal,
        leader_pid: obs.leader_pid,
        leader_sid: obs.leader_sid,
        session_member_count: obs.tree_pids.length,
        outside_session: obs.outside_session,
        remaining_after_exit: after.remaining_pids,
        exited_on_pipe_close: exitRes.code === 0 && after.remaining_pids.length === 0,
      }) + "\n"
    );
  } finally {
    fs.rmSync(udir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  process.stderr.write(`chrome-pipe-probe fatal: ${err && err.stack ? err.stack : err}\n`);
  process.exit(1);
});
