#!/usr/bin/env node
"use strict";

// SI-16 cookie-scope evidence probe run against the pinned Chrome for Testing
// and pinned Playwright build. Verifies:
// 1. A host-only `HttpOnly; SameSite=Strict` cookie set on
//    `http://project-a.localhost:<p1>` IS sent to
//    `http://project-a.localhost:<p2>` (both top-level navigation and
//    background `fetch(..., { mode: "no-cors", credentials: "include" })`),
//    while `localStorage` stays isolated per `(scheme, host, port)` origin.
// 2. Neither cookies nor `localStorage` cross to
//    `http://project-b.localhost:<p2>`.
// 3. A second browser context (`browser.newContext()`) in the same browser
//    process receives neither the cookie nor `localStorage` on
//    `http://project-a.localhost:<p1>`.

const http = require("node:http");
const path = require("node:path");
const { URL } = require("node:url");

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(";")) {
    const idx = part.indexOf("=");
    if (idx > 0) {
      out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
    }
  }
  return out;
}

async function main() {
  const modulesDir = process.argv[2];
  const chromeExe = process.argv[3];
  const { chromium } = require(path.join(modulesDir, "playwright"));

  const cookieSecret = "COOKIE_CANARY_A1_9f8e7d6c5b4a";
  const storageSecret = "LS_CANARY_A1_1a2b3c4d5e6f";
  const serverLog = [];

  function makeServer(portLabel) {
    return http.createServer((req, res) => {
      const u = new URL(req.url, "http://localhost");
      const cookies = parseCookies(req.headers.cookie);
      const hasCookie = cookies.ec_session === cookieSecret;
      serverLog.push({
        port_label: portLabel,
        host: req.headers.host || "",
        path: u.pathname,
        tag: u.searchParams.get("tag") || "",
        cookie_present: hasCookie,
      });

      if (u.pathname === "/login") {
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "set-cookie": `ec_session=${cookieSecret}; Path=/; HttpOnly; SameSite=Strict`,
        });
        res.end(`<!doctype html><html><body>
          <script>localStorage.setItem("ec_token", ${JSON.stringify(storageSecret)});</script>
          <div id="status">logged-in</div>
        </body></html>`);
        return;
      }

      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(`<!doctype html><html><body>
        <div id="cookie">${hasCookie ? "COOKIE_PRESENT" : "NO_COOKIE"}</div>
      </body></html>`);
    });
  }

  const srv1 = makeServer("p1");
  const srv2 = makeServer("p2");
  const listen = (s) =>
    new Promise((resolve) => s.listen(0, "127.0.0.1", () => resolve(s.address().port)));
  const [p1, p2] = await Promise.all([listen(srv1), listen(srv2)]);

  const browser = await chromium.launch({
    headless: true,
    executablePath: chromeExe,
    args: [
      "--no-first-run",
      "--no-default-browser-check",
      "--host-resolver-rules=MAP project-a.localhost 127.0.0.1, MAP project-b.localhost 127.0.0.1",
    ],
  });

  try {
    const ctxA = await browser.newContext();
    const pageA = await ctxA.newPage();

    await pageA.goto(`http://project-a.localhost:${p1}/login`, {
      waitUntil: "domcontentloaded",
    });
    const lsOrigin1 = await pageA.evaluate(() => localStorage.getItem("ec_token"));

    // 1. Same hostname (`project-a.localhost`), different port (`p2`).
    const pageA2 = await ctxA.newPage();
    await pageA2.goto(`http://project-a.localhost:${p2}/probe?tag=same_host_other_port`, {
      waitUntil: "domcontentloaded",
    });
    const sameHostCookieDom = await pageA2.textContent("#cookie");
    const sameHostLs = await pageA2.evaluate(() => localStorage.getItem("ec_token"));

    // 2. Different `.localhost` subdomain (`project-b.localhost`), port `p2`.
    const pageB = await ctxA.newPage();
    await pageB.goto(`http://project-b.localhost:${p2}/probe?tag=other_subdomain`, {
      waitUntil: "domcontentloaded",
    });
    const otherSubdomainCookieDom = await pageB.textContent("#cookie");
    const otherSubdomainLs = await pageB.evaluate(() => localStorage.getItem("ec_token"));

    // 3. Background no-cors fetch from `project-a.localhost:p1` to `project-a.localhost:p2` and `project-b.localhost:p2`.
    await pageA.evaluate(
      async ({ port2 }) => {
        await fetch(`http://project-a.localhost:${port2}/probe?tag=bg_same_host`, {
          mode: "no-cors",
          credentials: "include",
        });
        await fetch(`http://project-b.localhost:${port2}/probe?tag=bg_other_subdomain`, {
          mode: "no-cors",
          credentials: "include",
        });
      },
      { port2: p2 }
    );

    // 4. Separate browser context in the same browser process on `project-a.localhost:p1`.
    const ctxB = await browser.newContext();
    const pageOtherCtx = await ctxB.newPage();
    await pageOtherCtx.goto(`http://project-a.localhost:${p1}/probe?tag=other_context`, {
      waitUntil: "domcontentloaded",
    });
    const otherCtxCookieDom = await pageOtherCtx.textContent("#cookie");
    const otherCtxLs = await pageOtherCtx.evaluate(() => localStorage.getItem("ec_token"));

    await ctxB.close();
    await ctxA.close();

    const byTag = (t) => serverLog.find((e) => e.tag === t);
    const out = {
      ok: true,
      origin_1_local_storage_set: lsOrigin1 === storageSecret,
      same_host_other_port_cookie_present:
        sameHostCookieDom === "COOKIE_PRESENT" &&
        Boolean(byTag("same_host_other_port")?.cookie_present),
      same_host_other_port_local_storage_isolated: sameHostLs === null,
      other_subdomain_cookie_present:
        otherSubdomainCookieDom === "COOKIE_PRESENT" ||
        Boolean(byTag("other_subdomain")?.cookie_present),
      other_subdomain_local_storage_isolated: otherSubdomainLs === null,
      bg_fetch_same_host_other_port_cookie_present: Boolean(
        byTag("bg_same_host")?.cookie_present
      ),
      bg_fetch_other_subdomain_cookie_present: Boolean(
        byTag("bg_other_subdomain")?.cookie_present
      ),
      separate_context_same_origin_cookie_present:
        otherCtxCookieDom === "COOKIE_PRESENT" ||
        Boolean(byTag("other_context")?.cookie_present),
      separate_context_same_origin_local_storage_isolated: otherCtxLs === null,
    };

    process.stdout.write(JSON.stringify(out) + "\n");
  } finally {
    await browser.close();
    srv1.close();
    srv2.close();
  }
}

main().catch((err) => {
  process.stderr.write(`cookie-scope-probe fatal: ${err && err.stack ? err.stack : err}\n`);
  process.exit(1);
});
