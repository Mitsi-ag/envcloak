# EnvCloak Test-Session Adapter Protocol (D-28)

Status: Normative for Milestone M2b (`SPEC.md` §6.8, D-28, R-M2b-56, gate b19).

This document specifies the loopback test-session adapter protocol (`POST /__envcloak/test-session`) and the Node reference middleware in `integrations/test-session/node/`.

## 1. Purpose and Scope

When a development application runs locally on a loopback origin and opts into EnvCloak's test-session adapter, EnvCloak's sign-in driver (`envcloakd --signin-driver`) can mint an authenticated test session directly on the application's loopback listener instead of driving a human login form in headless Chromium.

The adapter is strictly a local development and test mechanism:
- It is off by default unless the application runs in a test configuration and passes an explicit `enabled: true` flag to the middleware constructor.
- The Node reference middleware refuses to load when `NODE_ENV` is `"production"`, throwing synchronously both when `require`d and when `createTestSessionHandler` is called.
- It accepts requests only on a loopback socket (`127.0.0.1`, `::1`, or `::ffff:127.0.0.1`) with a loopback `Host` header.
- It refuses any request carrying an `Origin` header (or `Sec-Fetch-Site: cross-site`) with HTTP `401` and never mints a session, so no browser page can invoke the endpoint across origins.
- It authenticates every request with HMAC-SHA-256 using the login item's `adapter_key` field over the HTTP method, path, timestamp, nonce, and raw body, enforcing a bounded timestamp skew and rejecting replayed nonces within the replay window.
- Every minted session carries a server-side expiry (`ttl`) enforced on the server against the server's clock.
- The `adapter_key` never appears in any HTTP response, error message, or log line.

## 2. Endpoint and Transport Rules

- **Method**: `POST`
- **Path**: `/__envcloak/test-session`
- **Socket peer**: `req.socket.remoteAddress` must be `127.0.0.1`, `::1`, or `::ffff:127.0.0.1`. Any other remote address is refused with `403` (`{"ok":false,"error":"loopback_required"}`) before body parsing or authentication.
- **Origin guard**: If `req.headers.origin !== undefined` (including an empty string or a loopback origin) or `req.headers["sec-fetch-site"] === "cross-site"`, the middleware immediately responds with `401` (`{"ok":false,"error":"origin_forbidden"}`) and does not mint a session. Browser-initiated `POST` requests always attach `Origin` or `Sec-Fetch-Site`; the non-browser sign-in driver never sends `Origin`.
- **Content-Type**: `application/json` (UTF-8), bounded to 16,384 bytes.

## 3. Activation and Production Guards

1. **Production load refusal**:
   - If `process.env.NODE_ENV === "production"`, requiring `integrations/test-session/node` throws `Error("envcloak test-session middleware refuses to load when NODE_ENV=production")`.
   - Calling `createTestSessionHandler(...)` when `process.env.NODE_ENV === "production"` throws the same error.
2. **Off by default**:
   - The handler mints sessions only when all three conditions hold at request time:
     1. `process.env.NODE_ENV !== "production"`
     2. `options.enabled === true`
     3. `process.env.NODE_ENV === "test"` or `process.env.ENVCLOAK_TEST_SESSION === "1"`
   - When disabled, requests to `/__envcloak/test-session` receive `404` (`{"ok":false,"error":"test_session_disabled"}`) and never mint a session.

## 4. HMAC-SHA-256 Request Authentication and Replay Window

Every `POST /__envcloak/test-session` request must carry three headers:

| Header | Format | Description |
| :--- | :--- | :--- |
| `X-EnvCloak-Timestamp` | ASCII decimal integer (`^[0-9]{1,20}$`) | Unix epoch timestamp in whole seconds. |
| `X-EnvCloak-Nonce` | `^[A-Za-z0-9._-]{16,128}$` | Unique per-request nonce (for example, 32 lowercase hex characters). |
| `X-EnvCloak-Signature` | 64 hex chars (or `sha256=<64 hex chars>`) | Hex-encoded HMAC-SHA-256 digest computed with the login item's `adapter_key`. |

### Canonical Signing Payload

The HMAC-SHA-256 key is the raw UTF-8 byte sequence of the login item's `adapter_key` field. The message signed is the five-line UTF-8 string joined by `\n` (`0x0A`):

```text
POST
/__envcloak/test-session
<X-EnvCloak-Timestamp>
<X-EnvCloak-Nonce>
<raw-request-body-utf8>
```

### Verification Order

1. Verify `X-EnvCloak-Timestamp`, `X-EnvCloak-Nonce`, and `X-EnvCloak-Signature` are present and syntactically valid; otherwise respond `401` (`{"ok":false,"error":"missing_or_invalid_auth_headers"}`).
2. Compare `Math.abs(clockMs() - Number(timestamp) * 1000)` against `replayWindowMs` (default `300000` ms, i.e., 300 seconds). If outside the window, respond `401` (`{"ok":false,"error":"timestamp_skew"}`).
3. Compute the expected 32-byte HMAC-SHA-256 digest over the canonical signing payload for each configured adapter key and compare against the decoded signature using `crypto.timingSafeEqual`. If no key matches, respond `401` (`{"ok":false,"error":"invalid_signature"}`).
4. Prune expired nonces older than `replayWindowMs` from the replay cache and check whether `X-EnvCloak-Nonce` is already present. If present, respond `401` (`{"ok":false,"error":"nonce_replayed"}`). Otherwise record the nonce with its expiry timestamp.

## 5. Request and Response Payload

### Request Body

The JSON request body is an object with the following fields:

```json
{
  "identity": "editor@acme.test",
  "tenant": "t1",
  "role": "editor",
  "ttl": 900
}
```

- `identity` (string, required; `account` is accepted as a compatibility alias when `identity` is omitted): non-empty account identifier (`1..=256` characters).
- `tenant` (string or `null`, optional): tenant identifier (`0..=256` characters).
- `role` (string, required): target role (`1..=128` characters).
- `ttl` (integer, optional, default `900`): requested session lifetime in whole seconds (`1..=86400`), clamped to the server's configured `maxTtlSecs` (default `3600`).

### Response Body and Server-Side Expiry

On success (`200 OK`, `Content-Type: application/json; charset=utf-8`, `Cache-Control: no-store`), the middleware invokes its `mint` handler (or built-in session store), records a server-side expiration timestamp `expires_at_ms = clockMs() + effectiveTtl * 1000`, and returns the declared cookies and storage:

```json
{
  "ok": true,
  "identity": "editor@acme.test",
  "account": "editor@acme.test",
  "tenant": "t1",
  "role": "editor",
  "ttl": 900,
  "expires_at_ms": 1700000900000,
  "cookies": [
    {
      "name": "session",
      "value": "sess_...",
      "domain": "acme.localhost",
      "path": "/",
      "httpOnly": true,
      "sameSite": "Strict"
    }
  ],
  "storage": [
    {
      "origin": "http://acme.localhost:12345",
      "localStorage": [
        { "name": "acme_tenant", "value": "t1" }
      ]
    }
  ]
}
```

Once `clockMs() >= expires_at_ms`, the server treats the minted session as expired and rejects subsequent requests carrying that session token with `401`.

## 6. Node Reference Middleware (`integrations/test-session/node/`)

The reference package in `integrations/test-session/node/index.cjs` uses only Node's built-in standard library (`node:crypto`, `node:http`, `node:url`) and works with `http.createServer`, Express, and Connect:

```js
const {
  createTestSessionHandler,
  signTestSessionRequest,
} = require("./integrations/test-session/node");

const testSession = createTestSessionHandler({
  enabled: process.env.ENVCLOAK_TEST_SESSION === "1",
  keys: [process.env.ACME_ADAPTER_KEY],
  clock: () => Date.now(),
  replayWindowMs: 300_000,
  maxTtlSecs: 3_600,
  mint: ({ identity, tenant, role, ttl, expiresAtMs }) => ({
    cookies: [
      {
        name: "session",
        value: `sess_${identity}_${expiresAtMs}`,
        domain: "127.0.0.1",
        path: "/",
        httpOnly: true,
        sameSite: "Strict",
      },
    ],
    storage: [],
  }),
});
```

When used as Express/Connect middleware `app.use(testSession)`, non-matching paths pass through to `next()`. When used directly inside `http.createServer((req, res) => { ... })`, `await testSession(req, res)` returns `true` when the request targeted `/__envcloak/test-session` and was handled, or `false` when the caller should continue routing.
