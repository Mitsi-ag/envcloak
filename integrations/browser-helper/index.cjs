#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const dns = require("node:dns");
const net = require("node:net");
const path = require("node:path");
const readline = require("node:readline");
const { EventEmitter } = require("node:events");

function installHostResolverRules(hostRulesStr) {
  const origLookup = dns.lookup.bind(dns);
  const hostMap = new Map();
  for (const part of String(hostRulesStr || "").split(",")) {
    const tokens = part.trim().split(/\s+/);
    if (tokens.length >= 3 && tokens[0].toUpperCase() === "MAP") {
      hostMap.set(tokens[1].toLowerCase(), tokens[2]);
    }
  }
  dns.lookup = function patchedLookup(hostname, options, callback) {
    let cb = callback;
    let opts = options;
    if (typeof options === "function") {
      cb = options;
      opts = {};
    } else if (typeof options === "number") {
      opts = { family: options };
    } else {
      opts = options || {};
    }
    const lower = String(hostname || "").toLowerCase();
    const mapped =
      hostMap.get(lower) ||
      (lower === "localhost" || lower.endsWith(".localhost") ? "127.0.0.1" : null);
    if (mapped) {
      process.nextTick(() => {
        if (opts && opts.all) {
          cb(null, [{ address: mapped, family: 4 }]);
        } else {
          cb(null, mapped, 4);
        }
      });
      return;
    }
    return origLookup(hostname, options, callback);
  };
}

function parseArgs(argv) {
  const out = {
    modulesDir: process.env.ENVCLOAK_BROWSER_HELPER_MODULES || path.join(__dirname, "node_modules"),
    chromeExe: process.env.ENVCLOAK_CHROME_FOR_TESTING || "",
    outputDir: process.env.ENVCLOAK_BROWSER_OUTPUT_DIR || "/tmp",
    hostRules: process.env.ENVCLOAK_BROWSER_HOST_RULES || "",
    controlFd: Number(process.env.ENVCLOAK_BROWSER_CONTROL_FD || "3"),
    isolatedControl: false,
  };
  for (let i = 2; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--modules" && i + 1 < argv.length) {
      out.modulesDir = argv[++i];
    } else if (a === "--chrome" && i + 1 < argv.length) {
      out.chromeExe = argv[++i];
    } else if (a === "--output-dir" && i + 1 < argv.length) {
      out.outputDir = argv[++i];
    } else if (a === "--host-rules" && i + 1 < argv.length) {
      out.hostRules = argv[++i];
    } else if (a === "--control-fd" && i + 1 < argv.length) {
      out.controlFd = Number(argv[++i]);
    } else if (a === "--isolated-control") {
      out.isolatedControl = true;
    }
  }
  return out;
}

class StdioMcpTransport extends EventEmitter {
  constructor(onToolCall) {
    super();
    this.onclose = undefined;
    this.onerror = undefined;
    this.onmessage = undefined;
    this._onToolCall = onToolCall;
    this._rl = null;
  }

  async start() {
    this._rl = readline.createInterface({
      input: process.stdin,
      crlfDelay: Infinity,
    });
    this._rl.on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      try {
        const msg = JSON.parse(trimmed);
        if (msg && msg.method === "tools/call" && this._onToolCall) {
          this._onToolCall({
            id: msg.id ?? null,
            name: msg.params?.name ?? "",
            arguments: msg.params?.arguments ?? {},
          });
        }
        if (this.onmessage) {
          this.onmessage(msg);
        }
      } catch (err) {
        if (this.onerror) {
          this.onerror(err);
        }
      }
    });
    this._rl.on("close", () => {
      if (this.onclose) {
        this.onclose();
      }
    });
  }

  async send(message) {
    process.stdout.write(JSON.stringify(message) + "\n");
  }

  async close() {
    if (this._rl) {
      this._rl.close();
      this._rl = null;
    }
    if (this.onclose) {
      this.onclose();
    }
  }
}

async function main() {
  const opts = parseArgs(process.argv);
  installHostResolverRules(opts.hostRules);
  const mcpPath = path.join(opts.modulesDir, "@playwright", "mcp");
  const pwPath = path.join(opts.modulesDir, "playwright");
  const { createConnection } = require(mcpPath);
  const { chromium } = require(pwPath);
  const mcpPkg = JSON.parse(fs.readFileSync(path.join(mcpPath, "package.json"), "utf8"));
  const pwPkg = JSON.parse(fs.readFileSync(path.join(pwPath, "package.json"), "utf8"));

  let boundGeneration = null;
  let browser = null;
  let recipientContext = null;
  let published = false;
  let closed = false;
  let getterCalls = 0;
  let getterRefusals = 0;
  const forwardedCalls = [];

  const contextGetter = async () => {
    getterCalls += 1;
    if (!recipientContext || !published || closed) {
      getterRefusals += 1;
      throw new Error("sign_in_context_not_published");
    }
    return recipientContext;
  };

  const config = {
    browser: {
      browserName: "chromium",
      isolated: opts.isolatedControl,
    },
    saveSession: false,
    webmcp: false,
    imageResponses: "omit",
    snapshot: { mode: "none" },
    console: { level: "error" },
    codegen: "none",
    outputDir: opts.outputDir,
    timeouts: {
      action: 5000,
      navigation: 8000,
      settle: 0,
    },
  };

  const mcpServer = await createConnection(config, contextGetter);
  const transport = new StdioMcpTransport((call) => {
    forwardedCalls.push(call);
  });
  await mcpServer.connect(transport);

  async function ensureBrowser() {
    if (browser) {
      return browser;
    }
    if (!opts.chromeExe || !fs.existsSync(opts.chromeExe)) {
      throw new Error("chrome_executable_missing");
    }
    const args = [
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-background-networking",
      "--disable-sync",
    ];
    if (opts.hostRules) {
      args.push(`--host-resolver-rules=${opts.hostRules}`);
    }
    browser = await chromium.launch({
      headless: true,
      executablePath: opts.chromeExe,
      args,
    });
    return browser;
  }

  async function handleControl(msg) {
    const cmd = msg.cmd;
    if (cmd === "get_stats") {
      return {
        package_surface: {
          has_create_connection: typeof createConnection === "function",
          mcp_version: mcpPkg.version,
          playwright_version: pwPkg.version,
        },
        bound_generation: boundGeneration,
        published,
        closed,
        getter_calls: getterCalls,
        getter_refusals: getterRefusals,
        forwarded_calls: forwardedCalls,
      };
    }

    if (cmd === "create_context") {
      if (opts.isolatedControl) {
        throw new Error("isolated mode cannot be used with contextGetter");
      }
      const gen = String(msg.generation ?? "");
      if (!gen) {
        throw new Error("missing_generation");
      }
      if (boundGeneration !== null) {
        throw new Error("generation_already_bound");
      }
      boundGeneration = gen;
      await ensureBrowser();
      recipientContext = await browser.newContext({
        ignoreHTTPSErrors: Boolean(msg.ignore_https_errors),
      });
      await recipientContext.addInitScript(() => {
        window.__agentSeen = "recipient-only";
      });
      published = false;
      closed = false;
      return {
        generation: boundGeneration,
        created: true,
      };
    }

    if (cmd === "inject_state") {
      const gen = String(msg.generation ?? "");
      if (boundGeneration === null || gen !== boundGeneration) {
        throw new Error("generation_mismatch");
      }
      if (!recipientContext || closed) {
        throw new Error("context_not_available");
      }
      if (published) {
        throw new Error("already_published");
      }
      const state = msg.declared_state || {};
      const cookies = Array.isArray(state.cookies) ? state.cookies : [];
      const origins = Array.isArray(state.origins) ? state.origins : [];
      const allowedCookieDomains = Array.isArray(state.allowed_cookie_domains)
        ? state.allowed_cookie_domains
        : null;
      const allowedOrigins = Array.isArray(state.allowed_origins)
        ? state.allowed_origins
        : null;

      for (const c of cookies) {
        if (c.format && c.format !== "standard") {
          throw new Error("unsupported_session_scope");
        }
        if (c.device_bound || c.unsupported) {
          throw new Error("unsupported_session_scope");
        }
        if (allowedCookieDomains) {
          const dom = String(c.domain || "").replace(/^\./, "");
          let host = dom;
          if (!host && c.url) {
            try {
              host = new URL(c.url).hostname;
            } catch {
              throw new Error("unsupported_session_scope");
            }
          }
          if (!allowedCookieDomains.includes(host)) {
            throw new Error("unsupported_session_scope");
          }
        }
      }

      for (const o of origins) {
        if (!o || typeof o.origin !== "string") {
          throw new Error("unsupported_session_scope");
        }
        if (allowedOrigins && !allowedOrigins.includes(o.origin)) {
          throw new Error("unsupported_session_scope");
        }
      }

      if (cookies.length > 0) {
        const pwCookies = cookies.map((c) => {
          const out = {
            name: String(c.name),
            value: String(c.value),
          };
          if (c.url) {
            out.url = String(c.url);
          } else {
            out.domain = String(c.domain);
            out.path = String(c.path || "/");
          }
          if (typeof c.httpOnly === "boolean") out.httpOnly = c.httpOnly;
          if (typeof c.secure === "boolean") out.secure = c.secure;
          if (c.sameSite) out.sameSite = c.sameSite;
          if (typeof c.expires === "number") out.expires = c.expires;
          return out;
        });
        await recipientContext.addCookies(pwCookies);
      }

      for (const entry of origins) {
        const targetOrigin = entry.origin;
        const ls = Array.isArray(entry.localStorage) ? entry.localStorage : [];
        if (ls.length > 0) {
          await recipientContext.addInitScript(
            ({ expectedOrigin, pairs }) => {
              if (window.location.origin === expectedOrigin) {
                for (const item of pairs) {
                  window.localStorage.setItem(item.name, item.value);
                }
              }
            },
            { expectedOrigin: targetOrigin, pairs: ls }
          );
        }
      }

      return {
        injected: true,
        cookies: cookies.length,
        origins: origins.length,
      };
    }

    if (cmd === "read_identity") {
      const gen = String(msg.generation ?? "");
      if (boundGeneration === null || gen !== boundGeneration) {
        throw new Error("generation_mismatch");
      }
      if (!recipientContext || closed) {
        throw new Error("context_not_available");
      }
      const check = msg.check || {};
      const url = String(check.url || "");
      if (!url) {
        throw new Error("missing_identity_url");
      }
      const maxBytes = typeof check.max_bytes === "number" && check.max_bytes > 0
        ? Math.min(check.max_bytes, 65536)
        : 16384;
      const resp = await recipientContext.request.fetch(url, {
        method: String(check.method || "GET"),
        headers: check.headers || {},
        failOnStatusCode: false,
        timeout: 5000,
      });
      const buf = await resp.body();
      const truncated = buf.length > maxBytes;
      const bodySlice = truncated ? buf.subarray(0, maxBytes) : buf;
      return {
        status: resp.status(),
        headers: resp.headers(),
        body: bodySlice.toString("utf8"),
        truncated,
      };
    }

    if (cmd === "publish") {
      const gen = String(msg.generation ?? "");
      if (boundGeneration === null || gen !== boundGeneration) {
        throw new Error("generation_mismatch");
      }
      if (!recipientContext || closed) {
        throw new Error("context_not_available");
      }
      published = true;
      return {
        published: true,
        generation: boundGeneration,
      };
    }

    if (cmd === "unpublish_getter_only") {
      const gen = String(msg.generation ?? "");
      if (boundGeneration === null || gen !== boundGeneration) {
        throw new Error("generation_mismatch");
      }
      published = false;
      return {
        published: false,
        generation: boundGeneration,
      };
    }

    if (cmd === "worker_login_and_capture") {
      if (closed) {
        throw new Error("browser_not_available");
      }
      await ensureBrowser();
      const loginUrl = String(msg.login_url || "");
      const appOrigin = new URL(loginUrl).origin;
      const workerContext = await browser.newContext({
        ignoreHTTPSErrors: Boolean(msg.ignore_https_errors),
      });
      try {
        const workerPage = await workerContext.newPage();
        await workerPage.goto(loginUrl, { waitUntil: "domcontentloaded" });
        await workerPage.evaluate(() => {
          window.__workerOnly = "worker-secret";
          window.localStorage.setItem("worker_secret_note", "worker-only-secret-value");
        });
        await workerPage.fill("#username", String(msg.username || ""));
        await workerPage.fill("#password", String(msg.password || ""));
        if (msg.totp !== undefined && msg.totp !== null) {
          await workerPage.fill("#totp", String(msg.totp));
        }
        await Promise.all([
          workerPage.waitForNavigation({ waitUntil: "domcontentloaded" }),
          workerPage.click("#submit"),
        ]);
        const cookies = await workerContext.cookies([appOrigin]);
        const storageSnapshot = await workerPage.evaluate(() => ({
          tenant: window.localStorage.getItem("acme_tenant"),
          token: window.localStorage.getItem("acme_token"),
        }));
        const lsItems = [];
        if (storageSnapshot.tenant) {
          lsItems.push({ name: "acme_tenant", value: storageSnapshot.tenant });
        }
        if (storageSnapshot.token) {
          lsItems.push({ name: "acme_token", value: storageSnapshot.token });
        }
        return {
          worker_context_closed: true,
          getter_calls: getterCalls,
          token: storageSnapshot.token,
          captured_state: {
            allowed_cookie_domains: [new URL(appOrigin).hostname],
            allowed_origins: [appOrigin],
            cookies: cookies.map((c) => ({
              name: c.name,
              value: c.value,
              domain: c.domain,
              path: c.path || "/",
              httpOnly: c.httpOnly,
              secure: c.secure,
              sameSite: c.sameSite,
            })),
            origins: [
              {
                origin: appOrigin,
                localStorage: lsItems,
              },
            ],
          },
        };
      } finally {
        await workerContext.close();
      }
    }

    if (cmd === "verify_shared_browser_isolation") {
      await ensureBrowser();
      const url = String(msg.url || "");
      const otherCtx = await browser.newContext({
        ignoreHTTPSErrors: Boolean(msg.ignore_https_errors),
      });
      try {
        const page = await otherCtx.newPage();
        const resp = await page.goto(url, { waitUntil: "domcontentloaded" });
        const statusBeforeClose = resp ? resp.status() : 0;
        if (recipientContext) {
          try {
            await recipientContext.close();
          } catch {}
          recipientContext = null;
        }
        published = false;
        const respAfter = await page.goto(url, { waitUntil: "domcontentloaded" });
        const statusAfterRecipientClose = respAfter ? respAfter.status() : 0;
        return {
          ok:
            statusBeforeClose === 200 &&
            statusAfterRecipientClose === 200 &&
            recipientContext === null,
          other_context_status_before_close: statusBeforeClose,
          other_context_status_after_recipient_close: statusAfterRecipientClose,
          recipient_closed: recipientContext === null,
        };
      } finally {
        await otherCtx.close();
      }
    }

    if (cmd === "close") {
      const gen = String(msg.generation ?? "");
      if (boundGeneration !== null && gen && gen !== boundGeneration) {
        throw new Error("generation_mismatch");
      }
      published = false;
      closed = true;
      if (recipientContext) {
        try {
          await recipientContext.close();
        } catch {
          // ignore close errors during teardown
        }
        recipientContext = null;
      }
      if (browser) {
        try {
          await browser.close();
        } catch {
          // ignore close errors during teardown
        }
        browser = null;
      }
      return {
        closed: true,
        generation: boundGeneration,
      };
    }

    throw new Error(`unknown_control_command:${cmd}`);
  }

  const controlSock = new net.Socket({ fd: opts.controlFd, readable: true, writable: true });
  const controlRl = readline.createInterface({
    input: controlSock,
    crlfDelay: Infinity,
  });

  let chain = Promise.resolve();
  controlRl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    chain = chain.then(async () => {
      let req;
      try {
        req = JSON.parse(trimmed);
      } catch {
        controlSock.write(JSON.stringify({ id: null, ok: false, error: "invalid_json" }) + "\n");
        return;
      }
      const id = req.id ?? null;
      try {
        const result = await handleControl(req);
        controlSock.write(JSON.stringify({ id, ok: true, result }) + "\n");
      } catch (err) {
        controlSock.write(
          JSON.stringify({
            id,
            ok: false,
            error: String(err && err.message ? err.message : err),
          }) + "\n"
        );
      }
    });
  });

  controlRl.on("close", async () => {
    published = false;
    closed = true;
    if (recipientContext) {
      try {
        await recipientContext.close();
      } catch {}
    }
    if (browser) {
      try {
        await browser.close();
      } catch {}
    }
    process.exit(0);
  });
}

main().catch((err) => {
  process.stderr.write(`browser-helper fatal: ${err && err.stack ? err.stack : err}\n`);
  process.exit(1);
});
