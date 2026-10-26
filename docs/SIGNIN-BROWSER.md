# Hosted Browser Helper, Tool Allowlist, and Process Measurements

This document records the pinned versions, runtime and process measurements (`Q-06`, `D-34`, `R-M2b-49`), tool allowlist (`D-30`), control protocol (`D-03`, `D-31`), and cookie-scope reproduction (`SI-16`) for the hosted browser sign-in helper (`M2b-02`).

## 1. Pinned Runtime and Browser Versions (`D-29`, `Q-06`)

All version and SHA-256 pins for the hosted browser helper live in `integrations/browser/versions.toml` and `integrations/browser-helper/package-lock.json`:

| Component | Version / Revision | Entry / Binary | SHA-256 (`darwin-arm64`) | SHA-256 (`linux-x64`) |
| --- | --- | --- | --- | --- |
| Node.js runtime | `22.23.3` | `bin/node` | `68f4d07ca49e0500cc135c7e0a445093e228e42e126ac22306d045f0a8c2636b` | `fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48` |
| `@playwright/mcp` | `0.0.83` | `node_modules/@playwright/mcp/index.js` | `28c639173fb79f5cae1ed44519995cea0dd2aee2f4a48a2511f06f153802b946` | `28c639173fb79f5cae1ed44519995cea0dd2aee2f4a48a2511f06f153802b946` |
| `playwright` / `playwright-core` | `1.64.0-alpha-1790635538000` | `node_modules/playwright-core/lib/coreBundle.js` | `cd6730be1bbcff00771a0fc1390f200306d28428ce68e305420ca623cb39cdeb` | `cd6730be1bbcff00771a0fc1390f200306d28428ce68e305420ca623cb39cdeb` |
| Chrome for Testing | `151.0.7922.34` (`chromium-1234`) | `chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing` / `chrome-linux64/chrome` | `a596b1cfc6353e987fcec8d71a23a28cd6a9e7a6b4e20b908e4c4fcffe51158e` | `0b20b130e7edd9dd51873be867761295fe0cfad490c2b9a64f95bd3cfc08fa71` |

### Q-06 Node Runtime Decision and Measurements

1. **Resolution**: `BrowserSupervisor` launches the helper using the pinned Node `22.23.3` binary from the verified local cache (`node-22.23.3-<platform>/bin/node`), verifying its SHA-256 against `integrations/browser/versions.toml` before `spawn`. It never searches the ambient `PATH` for `node` or `npx`.
2. **Environment hygiene**: The helper is spawned after `Command::env_clear()` with only an isolated temporary `HOME`, `TMPDIR`, fixed minimal `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, and optional diagnostic coverage variables.
3. **Startup and memory measurements (`darwin-arm64`)**:
   - Pinned Node `22.23.3` cold `createConnection` + MCP `initialize` handshake (before launching Chrome): **58 ms**, helper RSS **49 MB**.
   - First `create_context(generation)` (launching headless Chrome for Testing `151.0.7922.34` and creating the isolated recipient `BrowserContext`): **720 ms** to **1700 ms**.
   - Subsequent control operations (`inject_state`, `read_identity`, `publish`, `close`) on the warm browser: **8 ms** to **35 ms** per command.

## 2. Chrome for Testing Process and Session Measurements (`D-34`, `R-M2b-49`)

`integrations/browser-helper/chrome_pipe_probe.cjs` (exercised by `envcloak_testkit::signin::measure_chrome_pipe_and_session` and `browser_helper_smoke::chrome_pipe_exit_and_session_containment_measurement`) launches the pinned Chrome for Testing `151.0.7922.34` binary in a fresh `setsid()` session with `--headless --remote-debugging-pipe` on file descriptors 3 and 4 and measures process lifetime and session containment by observation only (zero signals sent):

| Measurement | Observed Value (`darwin-arm64`) | Requirement (`D-34` / `R-M2b-49`) |
| --- | --- | --- |
| Browser product | `Chrome/151.0.7922.34` | Pinned Chrome for Testing build |
| Cold CDP `Browser.getVersion` + `Target.createTarget` | `1704 ms` | Responds over `--remote-debugging-pipe` (`fd 3`/`fd 4`) |
| Processes in `setsid` session while active | `9` (`Google Chrome for Testing` main + GPU, network, storage, and renderer helpers) | All helper processes stay in the session |
| Descendant processes outside the `setsid` session | `0` | Zero processes outside the session |
| Exit latency after closing pipe fds (`fd 3`/`fd 4`) with zero signals | `576 ms` (exit code `0`) | Exits automatically on pipe close (`< 5000 ms`) |
| Remaining processes in session after main process exit | `0` | Zero surviving helper processes |

Before launching Chrome for Testing, `verify_chrome_executable` verifies the binary's SHA-256 against `integrations/browser/versions.toml` and (on macOS) checks via `/usr/bin/xattr -l` that `com.apple.quarantine` is absent. A mismatched SHA-256 is refused with `chrome_for_testing_hash_mismatch` before any process is spawned.

## 3. One Helper per Generation and Control Protocol (`D-03`, `D-31`)

Per `D-03`, each operation generation gets its own `integrations/browser-helper` process. Attempting `create_context` for a second generation on an already-bound helper is rejected with `generation_already_bound`.

- **MCP channel (`fd 0` / `fd 1`)**: Standard newline-delimited JSON-RPC 2.0 MCP transport, bounded at `1 MiB` per line by `BrowserSupervisor`.
- **Control channel (`fd 3` / `--control-fd`)**: Inherited Unix stream socket pair (`envcloak_sys::inherit_on_spawn`), bounded at `1 MiB` per line, supporting:
  1. `create_context(generation)`: Launches headless Chrome for Testing (if not already running) and creates the private recipient `BrowserContext` without publishing it to `contextGetter`.
  2. `inject_state(generation, declared_state)`: Clears existing cookies/origins and injects only the declared cookies, `localStorage`, and `sessionStorage` into the unpublished recipient context.
  3. `read_identity(generation, check) -> { status, body, truncated }`: Fetches the configured identity check URL inside the unpublished recipient context and returns the HTTP status, body bounded to `64 KiB`, and a `truncated` boolean. Per `D-31`, the helper never computes or reports a match verdict; `BrowserSupervisor::verify_and_publish` (representing the daemon) parses and matches `account`, `tenant`, and `role`.
  4. `publish(generation)`: Flips `published = true` so `contextGetter` returns the recipient `BrowserContext` to allowed MCP tool calls.
  5. `close(generation)`: Flips `published = false`, closes the recipient `BrowserContext`, and resets `@playwright/mcp`'s cached tab state so any subsequent getter invocation throws `sign_in_context_not_published`.

Because `@playwright/mcp` caches the `BrowserContext` returned by `contextGetter` after the first tool call in a connection (Observation 13), `BrowserSupervisor::tools_call` checks the operation lease before forwarding every tool call (Observation 14) and pairs revocation with `close(generation)` (Observation 15).

## 4. Hosted Browser Tool Allowlist (`D-30`)

`ToolAllowlist` (`crates/envcloak-testkit/src/signin.rs`) enforces the `D-30` (`SPEC.md` section 6.8) allowlist on both `tools/list` and `tools/call`:

- **19 Allowed Tools (`ALLOWED_BROWSER_TOOLS`)**:
  `browser_close`, `browser_resize`, `browser_console_messages`, `browser_handle_dialog`, `browser_evaluate`, `browser_fill_form`, `browser_press_key`, `browser_type`, `browser_navigate`, `browser_navigate_back`, `browser_network_requests`, `browser_take_screenshot`, `browser_snapshot`, `browser_click`, `browser_drag`, `browser_hover`, `browser_select_option`, `browser_tabs`, `browser_wait_for`.
- **Excluded Tools Refused (`tool_not_allowed`)**:
  `browser_run_code_unsafe`, `browser_run_code`, `browser_file_upload`, `browser_drop`, `browser_emulate_media`, `browser_find`, `browser_network_request`, and all optional `--caps` tools (`browser_pdf_save`, `browser_start_tracing`, `browser_stop_tracing`, etc.).
- **Schema and Argument Filtering (`FORBIDDEN_PATH_ARGS`)**:
  `filename`, `outputPath`, `output_path`, `path`, `paths`, `savePath`, and `save_path` are stripped from every tool's `inputSchema` in `tools/list` and refused with `tool_not_allowed` in `tools/call`.
- **Navigation Scheme Filter**:
  `browser_navigate` and `browser_tabs` (when `url` is supplied) admit only `http://` and `https://` URLs and refuse `file:`, `javascript:`, `data:`, `chrome:`, `about:`, and all other schemes.

## 5. Cookie-Scope Evidence (`SI-16`)

`integrations/browser-helper/cookie_scope_probe.cjs` (`run_cookie_scope_probe`) and Observation 18 of `browser_helper_smoke` confirm under Chrome for Testing `151.0.7922.34`:

- Host-only cookies (without a `Domain` attribute) set on `http://acme.localhost:<p1>` ARE sent to `http://acme.localhost:<p3>` (different port, same hostname), because RFC 6265 section 8.5 cookies are port-agnostic.
- Host-only cookies set on `http://acme.localhost:<p1>` are NOT sent to `http://idp-acme.localhost:<p2>` (different `.localhost` subdomain).
- `localStorage` and `sessionStorage` are isolated by full `(scheme, host, port)` origin across both `acme.localhost:<p3>` and `idp-acme.localhost:<p2>`.
- Separate Playwright `BrowserContext` instances within the same Chrome process do not share cookies or `localStorage` even for the exact same `(scheme, host, port)` origin.
