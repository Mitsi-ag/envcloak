"use strict";

const crypto = require("node:crypto");
const { URL } = require("node:url");

const ENDPOINT_PATH = "/__envcloak/test-session";
const DEFAULT_REPLAY_WINDOW_MS = 300_000;
const DEFAULT_TTL_SECS = 900;
const DEFAULT_MAX_TTL_SECS = 3_600;
const MAX_BODY_BYTES = 16_384;
const MAX_NONCE_CACHE = 4_096;

function assertNotProduction() {
  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "envcloak test-session middleware refuses to load when NODE_ENV=production"
    );
  }
}

// Refuse to load synchronously when required in production (D-28, R-M2b-56).
assertNotProduction();

function isTestConfigActive(env = process.env) {
  if (env.NODE_ENV === "production") {
    return false;
  }
  return env.NODE_ENV === "test" || env.ENVCLOAK_TEST_SESSION === "1";
}

function isLoopbackAddress(addr) {
  if (typeof addr !== "string") return false;
  return (
    addr === "127.0.0.1" ||
    addr === "::1" ||
    addr === "::ffff:127.0.0.1"
  );
}

function canonicalSigningPayload({ method, path, timestamp, nonce, body }) {
  return `${String(method).toUpperCase()}\n${path}\n${timestamp}\n${nonce}\n${body}`;
}

function signTestSessionRequest({
  key,
  method = "POST",
  path = ENDPOINT_PATH,
  timestamp,
  nonce,
  body = "",
}) {
  if (typeof key !== "string" && !Buffer.isBuffer(key)) {
    throw new TypeError("adapter key must be a non-empty string or Buffer");
  }
  const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key, "utf8");
  if (keyBuf.length === 0) {
    throw new Error("adapter key must not be empty");
  }
  const ts =
    timestamp !== undefined
      ? String(timestamp)
      : String(Math.floor(Date.now() / 1000));
  const nc =
    nonce !== undefined ? String(nonce) : crypto.randomBytes(16).toString("hex");
  const rawBody = typeof body === "string" ? body : JSON.stringify(body);
  const payload = canonicalSigningPayload({
    method,
    path,
    timestamp: ts,
    nonce: nc,
    body: rawBody,
  });
  const signature = crypto
    .createHmac("sha256", keyBuf)
    .update(payload, "utf8")
    .digest("hex");
  return {
    timestamp: ts,
    nonce: nc,
    signature,
    headers: {
      "content-type": "application/json",
      "x-envcloak-timestamp": ts,
      "x-envcloak-nonce": nc,
      "x-envcloak-signature": signature,
    },
  };
}

function readBoundedBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
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

function sendJson(res, status, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...extraHeaders,
  });
  res.end(body);
}

function normalizeKeys(options) {
  const raw = [];
  if (options.key) raw.push(options.key);
  if (options.adapterKey) raw.push(options.adapterKey);
  if (Array.isArray(options.keys)) {
    raw.push(...options.keys);
  } else if (typeof options.keys === "function") {
    return options.keys;
  }
  const bufs = raw
    .filter((k) => (typeof k === "string" && k.length > 0) || Buffer.isBuffer(k))
    .map((k) => (Buffer.isBuffer(k) ? Buffer.from(k) : Buffer.from(k, "utf8")))
    .filter((b) => b.length > 0);
  return () => bufs;
}

function verifyHmacConstantTime(keyBuffers, payload, signatureHex) {
  const cleanHex = signatureHex.startsWith("sha256=")
    ? signatureHex.slice(7)
    : signatureHex;
  if (!/^[0-9a-fA-F]{64}$/.test(cleanHex)) {
    return false;
  }
  const given = Buffer.from(cleanHex, "hex");
  if (given.length !== 32) {
    return false;
  }
  let matched = false;
  for (const keyBuf of keyBuffers) {
    const expected = crypto
      .createHmac("sha256", keyBuf)
      .update(payload, "utf8")
      .digest();
    if (
      expected.length === given.length &&
      crypto.timingSafeEqual(expected, given)
    ) {
      matched = true;
    }
  }
  return matched;
}

function parseCookieHeader(header) {
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

function createTestSessionHandler(options = {}) {
  assertNotProduction();

  const path = options.path || ENDPOINT_PATH;
  const replayWindowMs =
    typeof options.replayWindowMs === "number" && options.replayWindowMs > 0
      ? options.replayWindowMs
      : DEFAULT_REPLAY_WINDOW_MS;
  const defaultTtlSecs =
    typeof options.defaultTtlSecs === "number" && options.defaultTtlSecs > 0
      ? Math.floor(options.defaultTtlSecs)
      : DEFAULT_TTL_SECS;
  const maxTtlSecs =
    typeof options.maxTtlSecs === "number" && options.maxTtlSecs > 0
      ? Math.floor(options.maxTtlSecs)
      : DEFAULT_MAX_TTL_SECS;
  const clock =
    typeof options.clock === "function" ? options.clock : () => Date.now();
  const resolveKeys = normalizeKeys(options);

  const seenNonces = new Map();
  const mintedSessions = new Map();

  function pruneNonces(nowMs) {
    for (const [nonce, expiresAt] of seenNonces.entries()) {
      if (expiresAt <= nowMs) {
        seenNonces.delete(nonce);
      }
    }
    while (seenNonces.size >= MAX_NONCE_CACHE) {
      const oldestKey = seenNonces.keys().next().value;
      if (oldestKey === undefined) break;
      seenNonces.delete(oldestKey);
    }
  }

  function verifySessionToken(token) {
    if (typeof token !== "string" || token.length === 0) {
      return null;
    }
    const record = mintedSessions.get(token);
    if (!record || record.revoked) {
      return null;
    }
    const nowMs = Number(clock());
    if (nowMs >= record.expiresAtMs) {
      return null;
    }
    return { ...record };
  }

  function verifyRequestSession(req, cookieName = "session") {
    const cookies = parseCookieHeader(req && req.headers ? req.headers.cookie : "");
    return verifySessionToken(cookies[cookieName]);
  }

  async function handle(req, res, next) {
    let pathname = "";
    try {
      const u = new URL(req.url || "/", "http://127.0.0.1");
      pathname = u.pathname;
    } catch {
      pathname = "";
    }

    if (pathname !== path) {
      if (typeof next === "function") {
        next();
      }
      return false;
    }

    // Off unless explicitly enabled AND running in test configuration (D-28, R-M2b-56).
    const isEnabled =
      options.enabled === true && isTestConfigActive(process.env);
    if (!isEnabled) {
      sendJson(res, 404, { ok: false, error: "test_session_disabled" });
      return true;
    }

    // Loopback listener restriction.
    const remoteAddr =
      req.socket && req.socket.remoteAddress
        ? req.socket.remoteAddress
        : req.connection && req.connection.remoteAddress
          ? req.connection.remoteAddress
          : "";
    if (!isLoopbackAddress(remoteAddr)) {
      sendJson(res, 403, { ok: false, error: "loopback_required" });
      return true;
    }

    // Refuse any request carrying an Origin header or cross-site fetch metadata with 401 (D-28).
    const hasOrigin =
      req.headers &&
      Object.prototype.hasOwnProperty.call(req.headers, "origin") &&
      req.headers.origin !== undefined;
    const secFetchSite = String(
      (req.headers && req.headers["sec-fetch-site"]) || ""
    ).toLowerCase();
    if (hasOrigin || secFetchSite === "cross-site") {
      sendJson(res, 401, { ok: false, error: "origin_forbidden" });
      return true;
    }

    if (req.method !== "POST") {
      sendJson(res, 405, { ok: false, error: "method_not_allowed" });
      return true;
    }

    const tsHeader =
      req.headers && typeof req.headers["x-envcloak-timestamp"] === "string"
        ? req.headers["x-envcloak-timestamp"].trim()
        : "";
    const nonceHeader =
      req.headers && typeof req.headers["x-envcloak-nonce"] === "string"
        ? req.headers["x-envcloak-nonce"].trim()
        : "";
    const sigHeader =
      req.headers && typeof req.headers["x-envcloak-signature"] === "string"
        ? req.headers["x-envcloak-signature"].trim()
        : "";

    if (
      !/^[0-9]{1,20}$/.test(tsHeader) ||
      !/^[A-Za-z0-9._-]{16,128}$/.test(nonceHeader) ||
      sigHeader.length === 0
    ) {
      sendJson(res, 401, {
        ok: false,
        error: "missing_or_invalid_auth_headers",
      });
      return true;
    }

    const nowMs = Number(clock());
    const tsSec = Number(tsHeader);
    if (
      !Number.isFinite(tsSec) ||
      Math.abs(nowMs - tsSec * 1000) > replayWindowMs
    ) {
      sendJson(res, 401, { ok: false, error: "timestamp_skew" });
      return true;
    }

    let rawBody = "";
    try {
      rawBody = await readBoundedBody(req, MAX_BODY_BYTES);
    } catch {
      sendJson(res, 413, { ok: false, error: "body_too_large" });
      return true;
    }

    const keyList = resolveKeys().map((k) =>
      Buffer.isBuffer(k) ? k : Buffer.from(String(k), "utf8")
    );
    if (keyList.length === 0) {
      sendJson(res, 401, { ok: false, error: "invalid_signature" });
      return true;
    }

    const signingString = canonicalSigningPayload({
      method: "POST",
      path,
      timestamp: tsHeader,
      nonce: nonceHeader,
      body: rawBody,
    });

    if (!verifyHmacConstantTime(keyList, signingString, sigHeader)) {
      sendJson(res, 401, { ok: false, error: "invalid_signature" });
      return true;
    }

    pruneNonces(nowMs);
    if (seenNonces.has(nonceHeader)) {
      sendJson(res, 401, { ok: false, error: "nonce_replayed" });
      return true;
    }
    seenNonces.set(nonceHeader, nowMs + replayWindowMs);

    let parsed = {};
    if (rawBody.trim().length > 0) {
      try {
        parsed = JSON.parse(rawBody);
      } catch {
        sendJson(res, 400, { ok: false, error: "invalid_json" });
        return true;
      }
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      sendJson(res, 400, { ok: false, error: "invalid_body" });
      return true;
    }

    const rawIdentity =
      typeof parsed.identity === "string" && parsed.identity.trim().length > 0
        ? parsed.identity.trim()
        : typeof parsed.account === "string" && parsed.account.trim().length > 0
          ? parsed.account.trim()
          : "";
    if (rawIdentity.length === 0 || rawIdentity.length > 256) {
      sendJson(res, 400, { ok: false, error: "invalid_identity" });
      return true;
    }

    const tenant =
      parsed.tenant === undefined || parsed.tenant === null
        ? null
        : String(parsed.tenant);
    if (tenant !== null && tenant.length > 256) {
      sendJson(res, 400, { ok: false, error: "invalid_tenant" });
      return true;
    }

    const role =
      typeof parsed.role === "string" && parsed.role.trim().length > 0
        ? parsed.role.trim()
        : "";
    if (role.length === 0 || role.length > 128) {
      sendJson(res, 400, { ok: false, error: "invalid_role" });
      return true;
    }

    let requestedTtl = defaultTtlSecs;
    if (parsed.ttl !== undefined && parsed.ttl !== null) {
      const ttlNum = Number(parsed.ttl);
      if (!Number.isInteger(ttlNum) || ttlNum <= 0 || ttlNum > 86_400) {
        sendJson(res, 400, { ok: false, error: "invalid_ttl" });
        return true;
      }
      requestedTtl = ttlNum;
    }
    const effectiveTtl = Math.min(requestedTtl, maxTtlSecs);
    const expiresAtMs = nowMs + effectiveTtl * 1000;

    let minted = null;
    if (typeof options.mint === "function") {
      minted = await options.mint({
        identity: rawIdentity,
        account: rawIdentity,
        tenant,
        role,
        ttl: effectiveTtl,
        nowMs,
        expiresAtMs,
        req,
      });
    } else {
      const token = `sess_${crypto.randomBytes(16).toString("hex")}`;
      minted = {
        session_token: token,
        cookies: [
          {
            name: "session",
            value: token,
            domain: "127.0.0.1",
            path: "/",
            httpOnly: true,
            sameSite: "Strict",
          },
        ],
        storage: [],
      };
    }

    const sessionToken =
      (minted && minted.session_token) ||
      (minted &&
        Array.isArray(minted.cookies) &&
        minted.cookies[0] &&
        minted.cookies[0].value) ||
      `sess_${crypto.randomBytes(16).toString("hex")}`;

    mintedSessions.set(sessionToken, {
      token: sessionToken,
      identity: rawIdentity,
      account: rawIdentity,
      tenant,
      role,
      ttl: effectiveTtl,
      mintedAtMs: nowMs,
      expiresAtMs,
      revoked: false,
    });

    const cookies =
      minted && Array.isArray(minted.cookies) ? minted.cookies : [];
    const storage =
      minted && Array.isArray(minted.storage) ? minted.storage : [];
    const setCookieHeader =
      minted && typeof minted.setCookie === "string"
        ? minted.setCookie
        : cookies.length > 0
          ? `${cookies[0].name}=${cookies[0].value}; Path=${cookies[0].path || "/"}; HttpOnly; SameSite=${cookies[0].sameSite || "Strict"}`
          : undefined;

    const extraHeaders = setCookieHeader
      ? { "set-cookie": setCookieHeader }
      : {};

    const responseBody = {
      ok: true,
      identity: rawIdentity,
      account: rawIdentity,
      tenant,
      role,
      ttl: effectiveTtl,
      expires_at_ms: expiresAtMs,
      session_token: sessionToken,
      cookies,
      storage,
      ...(minted && minted.declared_state
        ? { declared_state: minted.declared_state }
        : {}),
    };

    sendJson(res, 200, responseBody, extraHeaders);
    return true;
  }

  handle.verifySessionToken = verifySessionToken;
  handle.verifyRequestSession = verifyRequestSession;
  handle.mintedSessions = mintedSessions;
  return handle;
}

module.exports = {
  ENDPOINT_PATH,
  DEFAULT_REPLAY_WINDOW_MS,
  assertNotProduction,
  isTestConfigActive,
  canonicalSigningPayload,
  signTestSessionRequest,
  createTestSessionHandler,
};
