#!/usr/bin/env node
"use strict";

const http = require("node:http");
const crypto = require("node:crypto");
const {
  createTestSessionHandler,
  signTestSessionRequest,
} = require("./index.cjs");

async function runExample() {
  process.env.ENVCLOAK_TEST_SESSION = "1";
  const adapterKey = `synthetic-example-key-${crypto.randomBytes(8).toString("hex")}`;

  const testSession = createTestSessionHandler({
    enabled: process.env.ENVCLOAK_TEST_SESSION === "1",
    key: adapterKey,
  });

  const server = http.createServer(async (req, res) => {
    if (await testSession(req, res)) {
      return;
    }
    if (req.method === "GET" && req.url === "/api/me") {
      const session = testSession.verifyRequestSession(req);
      if (!session) {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ authenticated: false }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          authenticated: true,
          identity: session.identity,
          tenant: session.tenant,
          role: session.role,
        })
      );
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();

  const body = JSON.stringify({
    identity: "dev@acme.test",
    tenant: "t1",
    role: "editor",
    ttl: 300,
  });
  const signed = signTestSessionRequest({
    key: adapterKey,
    method: "POST",
    path: "/__envcloak/test-session",
    body,
  });

  const mintRes = await fetch(
    `http://127.0.0.1:${port}/__envcloak/test-session`,
    {
      method: "POST",
      headers: signed.headers,
      body,
    }
  );
  const minted = await mintRes.json();
  process.stdout.write(`minted status=${mintRes.status} ok=${minted.ok}\n`);

  server.close();
}

if (require.main === module) {
  runExample().catch((err) => {
    process.stderr.write(`${err.stack || err}\n`);
    process.exit(1);
  });
}

module.exports = { runExample };
