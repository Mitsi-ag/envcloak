//! M2b-02 integration tests: hosted browser supervisor prototype, D-30 tool
//! allowlist, all 19 observations of `signin-mcp-context-evidence.md`, SI-16
//! cookie-scope probe, D-34 Chrome `--remote-debugging-pipe` process and
//! session measurements, and the sign-in fixture app (RFC 6238 TOTP vectors,
//! `b1` wrong-target and exfiltration counters, deterministic barriers, and
//! wrong Chrome for Testing hash refusal).

use std::thread;

use envcloak_testkit::signin::{
    ALLOWED_BROWSER_TOOLS, BrowserSupervisor, CONTEXT_NOT_PUBLISHED, CookieScopeReport,
    ExpectedIdentity, FORBIDDEN_PATH_ARGS, SigninFixture, SupervisorOptions, ToolAllowlist,
    browser_versions_path, http_request, measure_chrome_pipe_and_session, parse_counters,
    read_browser_pins, require_browser_runtime, resolve_node_binary, run_cookie_scope_probe,
    test_session_mint, verify_chrome_executable,
};
use serde_json::{Value, json};

fn extract_text(result: &Value) -> String {
    result
        .get("content")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

#[test]
fn tool_allowlist_snapshot_and_refusals() {
    // Pure ToolAllowlist::admit and ToolAllowlist::list checks run unconditionally.
    assert_eq!(
        ToolAllowlist::admit(
            "browser_navigate",
            &json!({ "url": "http://acme.localhost:8080/login" })
        ),
        Ok(())
    );
    assert_eq!(
        ToolAllowlist::admit(
            "browser_navigate",
            &json!({ "url": "https://127.0.0.1:8443/login" })
        ),
        Ok(())
    );
    assert_eq!(
        ToolAllowlist::admit("browser_run_code_unsafe", &json!({})),
        Err("tool_not_allowed")
    );
    assert_eq!(
        ToolAllowlist::admit(
            "browser_take_screenshot",
            &json!({ "filename": "/tmp/out.png" })
        ),
        Err("tool_not_allowed")
    );
    assert_eq!(
        ToolAllowlist::admit("browser_navigate", &json!({ "url": "file:///etc/passwd" })),
        Err("tool_not_allowed")
    );

    let Some(_runtime) = require_browser_runtime() else {
        return;
    };

    let mut sup = BrowserSupervisor::start(SupervisorOptions::default())
        .expect("start BrowserSupervisor with pinned runtime");
    sup.mcp_initialize().expect("mcp initialize");

    // Raw tools from @playwright/mcp include excluded tools and filename properties.
    let raw_tools = sup.raw_tools_list().expect("raw_tools_list");
    let raw_names: Vec<&str> = raw_tools
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .collect();
    assert!(
        raw_names.contains(&"browser_run_code_unsafe"),
        "expected raw @playwright/mcp tools to include browser_run_code_unsafe, got {raw_names:?}"
    );
    assert!(
        raw_names.contains(&"browser_file_upload"),
        "expected raw @playwright/mcp tools to include browser_file_upload, got {raw_names:?}"
    );
    let raw_has_filename = raw_tools.iter().any(|t| {
        t.get("inputSchema")
            .and_then(|s| s.get("properties"))
            .and_then(Value::as_object)
            .is_some_and(|p| p.contains_key("filename"))
    });
    assert!(
        raw_has_filename,
        "expected raw @playwright/mcp tool schemas to expose filename property before filtering"
    );

    // Filtered tools from ToolAllowlist::list contain only ALLOWED_BROWSER_TOOLS
    // and strip all FORBIDDEN_PATH_ARGS from every inputSchema.
    let allowed_tools = sup.tools_list().expect("filtered tools_list");
    let mut got_names: Vec<&str> = allowed_tools
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .collect();
    got_names.sort_unstable();
    let mut expected_names = ALLOWED_BROWSER_TOOLS.to_vec();
    expected_names.sort_unstable();
    assert_eq!(
        got_names, expected_names,
        "filtered tool allowlist must match ALLOWED_BROWSER_TOOLS exactly"
    );

    for tool in &allowed_tools {
        let tname = tool.get("name").and_then(Value::as_str).unwrap_or("");
        if let Some(props) = tool
            .get("inputSchema")
            .and_then(|s| s.get("properties"))
            .and_then(Value::as_object)
        {
            for forbidden in FORBIDDEN_PATH_ARGS {
                assert!(
                    !props.contains_key(*forbidden),
                    "tool {tname} schema still exposes forbidden path property {forbidden}"
                );
            }
        }
        if let Some(req) = tool
            .get("inputSchema")
            .and_then(|s| s.get("required"))
            .and_then(Value::as_array)
        {
            for forbidden in FORBIDDEN_PATH_ARGS {
                assert!(
                    !req.iter().any(|v| v.as_str() == Some(*forbidden)),
                    "tool {tname} required array still contains {forbidden}"
                );
            }
        }
    }

    // Excluded tools are refused by the supervisor before reaching the helper.
    for excluded in [
        "browser_run_code_unsafe",
        "browser_run_code",
        "browser_file_upload",
        "browser_drop",
        "browser_emulate_media",
        "browser_find",
        "browser_network_request",
        "browser_pdf_save",
        "browser_start_tracing",
        "browser_stop_tracing",
    ] {
        let res = sup
            .tools_call(excluded, json!({}))
            .expect("tools_call excluded");
        assert_eq!(res.get("isError"), Some(&json!(true)));
        assert_eq!(res.get("refusedBySupervisor"), Some(&json!(true)));
        assert_eq!(res.get("reason"), Some(&json!("tool_not_allowed")));
    }

    // Forbidden path arguments on allowed tools are refused.
    for (tool, arg_key) in [
        ("browser_take_screenshot", "filename"),
        ("browser_snapshot", "filename"),
        ("browser_console_messages", "filename"),
        ("browser_network_requests", "filename"),
        ("browser_take_screenshot", "outputPath"),
        ("browser_snapshot", "path"),
        ("browser_take_screenshot", "savePath"),
    ] {
        let mut args = serde_json::Map::new();
        args.insert(arg_key.to_owned(), json!("/tmp/evil.out"));
        let res = sup
            .tools_call(tool, Value::Object(args))
            .expect("tools_call with forbidden path arg");
        assert_eq!(res.get("isError"), Some(&json!(true)));
        assert_eq!(res.get("refusedBySupervisor"), Some(&json!(true)));
        assert_eq!(res.get("reason"), Some(&json!("tool_not_allowed")));
    }

    // Non-http(s) navigation schemes are refused.
    for bad_url in [
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html,<h1>pwn</h1>",
        "chrome://version",
        "about:blank",
        "ftp://example.com/file",
    ] {
        let res = sup
            .tools_call("browser_navigate", json!({ "url": bad_url }))
            .expect("tools_call bad scheme");
        assert_eq!(res.get("isError"), Some(&json!(true)));
        assert_eq!(res.get("refusedBySupervisor"), Some(&json!(true)));
        assert_eq!(res.get("reason"), Some(&json!("tool_not_allowed")));

        let tab_res = sup
            .tools_call("browser_tabs", json!({ "action": "new", "url": bad_url }))
            .expect("browser_tabs bad scheme");
        assert_eq!(tab_res.get("isError"), Some(&json!(true)));
        assert_eq!(tab_res.get("refusedBySupervisor"), Some(&json!(true)));
    }

    // Also verify ToolAllowlist::admit directly for allowed HTTP/HTTPS URLs vs refused calls.
    assert_eq!(
        ToolAllowlist::admit(
            "browser_navigate",
            &json!({ "url": "http://acme.localhost:8080/login" })
        ),
        Ok(())
    );
    assert_eq!(
        ToolAllowlist::admit(
            "browser_navigate",
            &json!({ "url": "https://127.0.0.1:8443/login" })
        ),
        Ok(())
    );
    assert_eq!(
        ToolAllowlist::admit("browser_run_code_unsafe", &json!({})),
        Err("tool_not_allowed")
    );

    // Verify that none of the refused calls reached the helper process.
    let stats = sup.helper_stats().expect("helper_stats");
    assert!(
        stats.forwarded_calls.is_empty(),
        "expected zero forwarded calls when supervisor refuses, got {:?}",
        stats.forwarded_calls
    );
}

#[test]
fn all_nineteen_mcp_context_observations_and_generation_isolation() {
    let Some(_runtime) = require_browser_runtime() else {
        return;
    };
    let (origins, control) = SigninFixture::start();

    let mut sup_a = BrowserSupervisor::start(SupervisorOptions {
        host_resolver_rules: Some(origins.host_resolver_rules.clone()),
        isolated_control: false,
    })
    .expect("start supervisor A");

    // Observation 1: package_surface
    let stats_0 = sup_a.helper_stats().expect("initial helper_stats");
    assert!(
        stats_0.has_create_connection,
        "Observation 1: createConnection present"
    );
    assert_eq!(
        stats_0.mcp_version, "0.0.83",
        "Observation 1: @playwright/mcp version"
    );
    assert_eq!(
        stats_0.playwright_version, "1.64.0-alpha-1790635538000",
        "Observation 1: playwright version"
    );

    // Observation 2: initialize
    let init_res = sup_a.mcp_initialize().expect("Observation 2: initialize");
    assert!(
        init_res
            .get("result")
            .and_then(|r| r.get("serverInfo"))
            .is_some(),
        "Observation 2: serverInfo returned on initialize"
    );

    // Observation 3: list_before_publish
    let tools = sup_a.tools_list().expect("Observation 3: tools_list");
    assert_eq!(
        tools.len(),
        ALLOWED_BROWSER_TOOLS.len(),
        "Observation 3: tools/list returns allowlisted tools before publish"
    );

    // Observation 4: pre_publish_navigate_refused
    let nav_pre = sup_a
        .tools_call(
            "browser_navigate",
            json!({ "url": format!("{}/dashboard", origins.app) }),
        )
        .expect("Observation 4: navigate before publish");
    assert_eq!(nav_pre.get("isError"), Some(&json!(true)));
    assert!(
        extract_text(&nav_pre).contains(CONTEXT_NOT_PUBLISHED),
        "Observation 4: expected {CONTEXT_NOT_PUBLISHED}, got {nav_pre}"
    );

    // Observation 5: pre_publish_snapshot_refused
    let snap_pre = sup_a
        .tools_call("browser_snapshot", json!({}))
        .expect("Observation 5: snapshot before publish");
    assert_eq!(snap_pre.get("isError"), Some(&json!(true)));
    assert!(
        extract_text(&snap_pre).contains(CONTEXT_NOT_PUBLISHED),
        "Observation 5: expected {CONTEXT_NOT_PUBLISHED}, got {snap_pre}"
    );

    // Observation 6: worker_login_isolated
    let totp_editor = control
        .verify_totp(
            &origins.editor_totp_secret_hex,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            8,
            "SHA1",
            "00000000",
        )
        .expect("compute current TOTP for editor")
        .expected
        .expect("expected TOTP code");

    let login_url = format!("{}/login", origins.app);
    let captured_a = sup_a
        .worker_login_and_capture(
            &login_url,
            "editor@acme.test",
            &origins.editor_password,
            Some(&totp_editor),
        )
        .expect("Observation 6: worker_login_and_capture for editor");
    assert_eq!(
        captured_a.get("worker_context_closed"),
        Some(&json!(true)),
        "Observation 6: worker context closed after capture"
    );
    let token_a = captured_a
        .get("token")
        .and_then(Value::as_str)
        .expect("captured acme_token for editor")
        .to_owned();
    let state_a = captured_a
        .get("captured_state")
        .cloned()
        .expect("captured_state for editor");

    // Create private recipient context for generation A and inject declared state
    // (only session cookie, acme_tenant, and acme_token; worker_secret_note is excluded).
    sup_a
        .create_context("gen-A")
        .expect("create_context(gen-A)");
    sup_a
        .inject_state("gen-A", state_a)
        .expect("inject_state(gen-A)");

    // Observation 7: pre_publish_evaluate_refused (even after create_context + inject_state)
    let eval_pre = sup_a
        .tools_call(
            "browser_evaluate",
            json!({ "function": "() => document.title" }),
        )
        .expect("Observation 7: evaluate before publish");
    assert_eq!(eval_pre.get("isError"), Some(&json!(true)));
    assert!(
        extract_text(&eval_pre).contains(CONTEXT_NOT_PUBLISHED),
        "Observation 7: expected {CONTEXT_NOT_PUBLISHED} before publish, got {eval_pre}"
    );

    // Observation 8: publish_navigate_dashboard (D-31: read_identity returns bounded
    // status/body/truncated without a match boolean; supervisor matches and calls publish).
    let id_resp_a = sup_a
        .verify_and_publish(
            "gen-A",
            json!({ "url": format!("{}/api/whoami", origins.app) }),
            &ExpectedIdentity {
                account: "editor@acme.test".to_owned(),
                tenant: "t1".to_owned(),
                role: "editor".to_owned(),
            },
        )
        .expect("Observation 8: verify_and_publish(gen-A)");
    assert_eq!(id_resp_a.status, 200);
    assert!(!id_resp_a.truncated);

    let nav_dash = sup_a
        .tools_call(
            "browser_navigate",
            json!({ "url": format!("{}/dashboard", origins.app) }),
        )
        .expect("Observation 8: navigate to dashboard after publish");
    assert_ne!(nav_dash.get("isError"), Some(&json!(true)));
    let dash_text = extract_text(&nav_dash);
    assert!(
        dash_text.contains("Acme Dashboard") || dash_text.contains("Signed in as editor@acme.test"),
        "Observation 8: dashboard text should show signed-in page, got {dash_text}"
    );

    // Observation 9: publish_evaluate_state
    let eval_state = sup_a
        .tools_call(
            "browser_evaluate",
            json!({
                "function": "() => ({ tenant: localStorage.getItem('acme_tenant'), token: localStorage.getItem('acme_token'), agentSeen: window.__agentSeen, workerLeak: localStorage.getItem('worker_secret_note'), workerGlobal: window.__workerOnly || null })"
            }),
        )
        .expect("Observation 9: evaluate state");
    assert_ne!(eval_state.get("isError"), Some(&json!(true)));
    let state_text = extract_text(&eval_state);
    assert!(
        state_text.contains(&token_a),
        "Observation 9: expected acme_token {token_a} in recipient state, got {state_text}"
    );
    assert!(
        state_text.contains("recipient-only"),
        "Observation 9: expected window.__agentSeen == recipient-only, got {state_text}"
    );
    assert!(
        state_text.contains("\"workerLeak\": null") || state_text.contains("\"workerLeak\":null"),
        "Observation 9: worker_secret_note must be null in recipient context, got {state_text}"
    );

    // Observation 10: publish_evaluate_whoami
    let eval_whoami = sup_a
        .tools_call(
            "browser_evaluate",
            json!({
                "function": "async () => { const r = await fetch('/api/whoami', { credentials: 'include' }); return await r.json(); }"
            }),
        )
        .expect("Observation 10: evaluate /api/whoami");
    assert_ne!(eval_whoami.get("isError"), Some(&json!(true)));
    let whoami_text = extract_text(&eval_whoami);
    assert!(whoami_text.contains("editor@acme.test"));
    assert!(
        whoami_text.contains("\"role\": \"editor\"") || whoami_text.contains("\"role\":\"editor\"")
    );

    // Observation 11: worker_secret_absent_from_recipient
    for combined in [&dash_text, &state_text, &whoami_text] {
        assert!(
            !combined.contains(&origins.editor_password),
            "Observation 11: editor password leaked into recipient output"
        );
        assert!(
            !combined.contains(&origins.editor_totp_secret_hex),
            "Observation 11: editor TOTP secret leaked into recipient output"
        );
        assert!(
            !combined.contains("worker-only-secret-value"),
            "Observation 11: worker_secret_note value leaked into recipient output"
        );
    }

    // D-03 check: attempting to bind a second generation in the same helper is rejected.
    let second_gen_err = sup_a
        .create_context("gen-B-on-same-helper")
        .expect_err("D-03: helper bound to gen-A must reject a second generation");
    assert!(
        second_gen_err.contains("generation_already_bound"),
        "expected generation_already_bound, got {second_gen_err}"
    );

    // Observation 12: operation_b_isolated (separate helper for generation B)
    let mut sup_b = BrowserSupervisor::start(SupervisorOptions {
        host_resolver_rules: Some(origins.host_resolver_rules.clone()),
        isolated_control: false,
    })
    .expect("start supervisor B");
    sup_b.mcp_initialize().expect("mcp_initialize B");

    let totp_admin = control
        .verify_totp(
            &origins.admin_totp_secret_hex,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            8,
            "SHA1",
            "00000000",
        )
        .expect("compute current TOTP for admin")
        .expected
        .expect("expected TOTP code for admin");

    let captured_b = sup_b
        .worker_login_and_capture(
            &login_url,
            "admin@acme.test",
            &origins.admin_password,
            Some(&totp_admin),
        )
        .expect("worker_login_and_capture for admin");
    let token_b = captured_b
        .get("token")
        .and_then(Value::as_str)
        .expect("token B")
        .to_owned();
    assert_ne!(
        token_a, token_b,
        "Operation A and B must have distinct session tokens"
    );
    let state_b = captured_b
        .get("captured_state")
        .cloned()
        .expect("captured_state B");

    sup_b
        .create_context("gen-B")
        .expect("create_context(gen-B)");
    sup_b
        .inject_state("gen-B", state_b)
        .expect("inject_state(gen-B)");
    sup_b
        .verify_and_publish(
            "gen-B",
            json!({ "url": format!("{}/api/whoami", origins.app) }),
            &ExpectedIdentity {
                account: "admin@acme.test".to_owned(),
                tenant: "t1".to_owned(),
                role: "admin".to_owned(),
            },
        )
        .expect("verify_and_publish(gen-B)");

    sup_b
        .tools_call(
            "browser_navigate",
            json!({ "url": format!("{}/dashboard", origins.app) }),
        )
        .expect("navigate B to dashboard");
    let whoami_b = extract_text(
        &sup_b
            .tools_call(
                "browser_evaluate",
                json!({
                    "function": "async () => ({ whoami: await (await fetch('/api/whoami', { credentials: 'include' })).json(), token: localStorage.getItem('acme_token') })"
                }),
            )
            .expect("evaluate whoami B"),
    );
    assert!(
        whoami_b.contains("admin@acme.test"),
        "Observation 12: helper B must see admin@acme.test, got {whoami_b}"
    );
    assert!(
        whoami_b.contains(&token_b) && !whoami_b.contains(&token_a),
        "Observation 12: helper B must see token_b and not token_a, got {whoami_b}"
    );

    // Meanwhile helper A still sees editor@acme.test.
    let whoami_a_again = extract_text(
        &sup_a
            .tools_call(
                "browser_evaluate",
                json!({
                    "function": "async () => (await (await fetch('/api/whoami', { credentials: 'include' })).json())"
                }),
            )
            .expect("evaluate whoami A again"),
    );
    assert!(
        whoami_a_again.contains("editor@acme.test"),
        "Observation 12: helper A must still see editor@acme.test while B is active, got {whoami_a_again}"
    );

    // Observation 13: getter_not_rechecked_after_open
    sup_a
        .unpublish_getter_only("gen-A")
        .expect("unpublish_getter_only(gen-A)");
    let after_unpublish_only = sup_a
        .tools_call("browser_evaluate", json!({ "function": "() => 21 + 21" }))
        .expect("Observation 13: evaluate after unpublish_getter_only");
    assert_ne!(
        after_unpublish_only.get("isError"),
        Some(&json!(true)),
        "Observation 13: @playwright/mcp caches the context once opened"
    );
    let stats_13 = sup_a.helper_stats().expect("stats after obs 13");
    assert_eq!(
        stats_13.getter_refusals, 3,
        "Observation 13: 3 pre-publish getter refusals (Observations 4, 5, 7)"
    );
    assert_eq!(
        stats_13.getter_calls, 4,
        "Observation 13: contextGetter called 3 times before publish + 1 time on initial open, and 0 times on subsequent tool calls"
    );

    // Observation 14: supervisor_gate_revokes_immediately
    let forwarded_before_14 = stats_13.forwarded_calls.len();
    sup_a.set_lease_active(false);
    let revoked_call = sup_a
        .tools_call("browser_evaluate", json!({ "function": "() => 1 + 1" }))
        .expect("Observation 14: evaluate when lease is revoked");
    assert_eq!(revoked_call.get("isError"), Some(&json!(true)));
    assert_eq!(revoked_call.get("refusedBySupervisor"), Some(&json!(true)));
    assert_eq!(revoked_call.get("reason"), Some(&json!("grant_revoked")));
    let stats_14 = sup_a.helper_stats().expect("stats after obs 14");
    assert_eq!(
        stats_14.forwarded_calls.len(),
        forwarded_before_14,
        "Observation 14: revoked call must not be forwarded to the helper"
    );

    // Re-enable supervisor lease to test Observation 15 (context.close() + getter refusal).
    sup_a.set_lease_active(true);

    // Observation 15: context_close_revokes_and_refuses
    sup_a.close("gen-A").expect("Observation 15: close(gen-A)");
    let after_close = sup_a
        .tools_call(
            "browser_evaluate",
            json!({ "function": "() => document.title" }),
        )
        .expect("Observation 15: evaluate after close(gen-A)");
    assert_eq!(
        after_close.get("isError"),
        Some(&json!(true)),
        "Observation 15: tool call after close(gen-A) must return isError=true, got {after_close}"
    );

    // Observation 16: isolated_true_control_rejected
    let mut sup_iso = BrowserSupervisor::start(SupervisorOptions {
        host_resolver_rules: None,
        isolated_control: true,
    })
    .expect("start supervisor with isolated_control=true");
    let iso_err = sup_iso
        .create_context("gen-iso")
        .expect_err("Observation 16: isolated=true must reject contextGetter");
    assert!(
        iso_err.contains("isolated mode cannot be used with contextGetter"),
        "Observation 16: unexpected error {iso_err}"
    );

    // Observation 18: cookie_port_scope_verified (SI-16 on the fixture's observer port)
    let nav_obs = sup_b
        .tools_call(
            "browser_navigate",
            json!({ "url": format!("{}/probe", origins.observer) }),
        )
        .expect("Observation 18: navigate to observer port on same hostname");
    assert_ne!(nav_obs.get("isError"), Some(&json!(true)));
    let obs_eval = extract_text(
        &sup_b
            .tools_call(
                "browser_evaluate",
                json!({
                    "function": "() => ({ body: document.body.innerText, ls: localStorage.getItem('acme_token') })"
                }),
            )
            .expect("Observation 18: evaluate on observer port"),
    );
    assert!(
        obs_eval.contains("cookie_present") && obs_eval.contains("true"),
        "Observation 18 (SI-16): host-only cookie is shared across ports on acme.localhost, got {obs_eval}"
    );
    assert!(
        obs_eval.contains("\"ls\": null") || obs_eval.contains("\"ls\":null"),
        "Observation 18: localStorage is isolated across ports, got {obs_eval}"
    );
    let c_after_obs = control.counters().expect("counters after observer hit");
    assert!(
        c_after_obs.observer_cookie_hits >= 1,
        "Observation 18: observer_cookie_hits must be incremented"
    );

    // Observation 17: shared_browser_context_isolation
    let shared_res = sup_b
        .verify_shared_browser_isolation(&format!("{}/login", origins.app))
        .expect("Observation 17: verify_shared_browser_isolation");
    assert_eq!(shared_res.get("ok"), Some(&json!(true)));

    // Observation 19: wrong_tenant_blocked_before_publish
    let (wt_status, wt_body) = test_session_mint(
        &origins.app,
        &origins.adapter_key,
        &json!({
            "identity": "editor@acme.test",
            "account": "editor@acme.test",
            "tenant": "t2",
            "role": "editor",
            "ttl": 900,
        })
        .to_string(),
    )
    .expect("mint wrong-tenant session");
    assert_eq!(wt_status, 200);
    let wt_json: Value = serde_json::from_str(&wt_body).expect("parse wrong-tenant session");
    let wt_declared_state = wt_json
        .get("declared_state")
        .cloned()
        .expect("wrong-tenant declared_state");

    let mut sup_wt = BrowserSupervisor::start(SupervisorOptions {
        host_resolver_rules: Some(origins.host_resolver_rules.clone()),
        isolated_control: false,
    })
    .expect("start supervisor for wrong-tenant test");
    sup_wt.mcp_initialize().expect("mcp_initialize wt");
    sup_wt
        .create_context("gen-wt")
        .expect("create_context(gen-wt)");
    sup_wt
        .inject_state("gen-wt", wt_declared_state)
        .expect("inject wrong-tenant state");
    let wt_err = sup_wt
        .verify_and_publish(
            "gen-wt",
            json!({ "url": format!("{}/api/whoami", origins.app) }),
            &ExpectedIdentity {
                account: "editor@acme.test".to_owned(),
                tenant: "t1".to_owned(),
                role: "editor".to_owned(),
            },
        )
        .expect_err("Observation 19: wrong tenant must fail verify_and_publish");
    assert_eq!(wt_err, "identity_unverified");

    let wt_stats = sup_wt.helper_stats().expect("wt helper_stats");
    assert!(
        !wt_stats.published,
        "Observation 19: context must remain unpublished when identity mismatches"
    );
    let wt_eval = sup_wt
        .tools_call(
            "browser_evaluate",
            json!({ "function": "() => document.cookie" }),
        )
        .expect("Observation 19: evaluate after failed identity check");
    assert_eq!(wt_eval.get("isError"), Some(&json!(true)));
    assert!(extract_text(&wt_eval).contains(CONTEXT_NOT_PUBLISHED));
}

#[test]
fn si_16_cookie_scope_probe_matches_rfc_6265() {
    let Some(_runtime) = require_browser_runtime() else {
        return;
    };
    let report = run_cookie_scope_probe().expect("run_cookie_scope_probe");
    assert_eq!(
        report,
        CookieScopeReport {
            origin_1_local_storage_set: true,
            same_host_other_port_cookie_present: true,
            same_host_other_port_local_storage_isolated: true,
            other_subdomain_cookie_present: false,
            other_subdomain_local_storage_isolated: true,
            bg_fetch_same_host_other_port_cookie_present: true,
            bg_fetch_other_subdomain_cookie_present: false,
            separate_context_same_origin_cookie_present: false,
            separate_context_same_origin_local_storage_isolated: true,
        }
    );
}

#[test]
fn fixture_totp_rfc_6238_vectors_and_controls() {
    // Pure counter parser self-test runs unconditionally (catches off-by-one mutations).
    let sample = json!({
        "password_submissions": 3,
        "code_submissions": 2,
        "wrong_target_submissions": 5,
        "mints": 1,
        "revocations": 4,
        "observer_cookie_hits": 2,
        "exfiltration_by_channel": { "fetch": 1, "beacon": 2 },
        "by_origin": {
            "idp": {
                "requests": 7,
                "password_submissions": 3,
                "code_submissions": 2,
                "mints": 1,
                "revocations": 0,
                "exfiltrations": 0
            }
        }
    });
    let parsed = parse_counters(&sample).expect("parse_counters sample");
    assert_eq!(parsed.password_submissions, 3);
    assert_eq!(parsed.code_submissions, 2);
    assert_eq!(parsed.wrong_target_submissions, 5);
    assert_eq!(parsed.mints, 1);
    assert_eq!(parsed.revocations, 4);
    assert_eq!(parsed.observer_cookie_hits, 2);
    assert_eq!(parsed.exfiltration_by_channel.get("fetch"), Some(&1));
    assert_eq!(parsed.exfiltration_by_channel.get("beacon"), Some(&2));
    assert_eq!(parsed.by_origin.get("idp").unwrap().requests, 7);

    let Some(_runtime) = require_browser_runtime() else {
        return;
    };
    let (origins, control) = SigninFixture::start();

    // RFC 6238 Appendix B canonical test secrets (ASCII):
    // SHA1:   "12345678901234567890" (20 bytes)
    // SHA256: "12345678901234567890123456789012" (32 bytes)
    // SHA512: "1234567890123456789012345678901234567890123456789012345678901234" (64 bytes)
    let sha1_hex = "3132333435363738393031323334353637383930";
    let sha256_hex = "3132333435363738393031323334353637383930313233343536373839303132";
    let sha512_hex = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334";

    let vectors: &[(u64, &str, &str, &str)] = &[
        (59, "SHA1", sha1_hex, "94287082"),
        (59, "SHA256", sha256_hex, "46119246"),
        (59, "SHA512", sha512_hex, "90693936"),
        (1_111_111_109, "SHA1", sha1_hex, "07081804"),
        (1_111_111_109, "SHA256", sha256_hex, "68084774"),
        (1_111_111_109, "SHA512", sha512_hex, "25091201"),
        (1_111_111_111, "SHA1", sha1_hex, "14050471"),
        (1_111_111_111, "SHA256", sha256_hex, "67062674"),
        (1_111_111_111, "SHA512", sha512_hex, "99943326"),
        (1_234_567_890, "SHA1", sha1_hex, "89005924"),
        (1_234_567_890, "SHA256", sha256_hex, "91819424"),
        (1_234_567_890, "SHA512", sha512_hex, "93441116"),
        (2_000_000_000, "SHA1", sha1_hex, "69279037"),
        (2_000_000_000, "SHA256", sha256_hex, "90698825"),
        (2_000_000_000, "SHA512", sha512_hex, "38618901"),
        (20_000_000_000, "SHA1", sha1_hex, "65353130"),
        (20_000_000_000, "SHA256", sha256_hex, "77737706"),
        (20_000_000_000, "SHA512", sha512_hex, "47863826"),
    ];

    for (ts, alg, secret, expected_8) in vectors {
        let v8 = control
            .verify_totp(secret, *ts, 8, alg, expected_8)
            .expect("verify_totp 8-digit");
        assert!(
            v8.valid,
            "RFC 6238 vector failed at ts={ts} alg={alg}: expected {expected_8}, got {v8:?}"
        );
        assert_eq!(v8.expected.as_deref(), Some(*expected_8));

        // 6-digit truncation is the last 6 digits of the 8-digit code.
        let expected_6 = &expected_8[2..];
        let v6 = control
            .verify_totp(secret, *ts, 6, alg, expected_6)
            .expect("verify_totp 6-digit");
        assert!(
            v6.valid,
            "6-digit TOTP failed at ts={ts} alg={alg}: expected {expected_6}, got {v6:?}"
        );
    }

    // Concurrent submissions & wrong-target / exfiltration channel counters.
    control.reset_counters().expect("reset_counters");
    let mut handles = Vec::new();
    for bad_origin in [
        origins.unregistered.clone(),
        origins.idn_lookalike.clone(),
        origins.changed_port.clone(),
    ] {
        handles.push(thread::spawn(move || {
            let (status, body) = http_request(
                "POST",
                &format!("{bad_origin}/login"),
                &[("content-type", "application/x-www-form-urlencoded")],
                "username=editor%40acme.test&password=synthetic&totp=12345678",
            )
            .expect("post to wrong target");
            assert_eq!(status, 200);
            assert!(body.contains("wrong_target_recorded"));
        }));
    }
    {
        let unreg = origins.unregistered.clone();
        handles.push(thread::spawn(move || {
            let (status, body) = http_request(
                "POST",
                &format!("{unreg}/login?userinfo=1"),
                &[("content-type", "application/x-www-form-urlencoded")],
                "username=editor%40acme.test&password=synthetic&totp=12345678",
            )
            .expect("post to userinfo wrong target");
            assert_eq!(status, 200);
            assert!(body.contains("wrong_target_recorded"));
        }));
    }
    for ch in ["fetch", "worker", "service_worker", "websocket", "beacon"] {
        let unreg = origins.unregistered.clone();
        let ch_name = ch.to_owned();
        handles.push(thread::spawn(move || {
            let (status, _) = http_request(
                "POST",
                &format!("{unreg}/exfil/{ch_name}"),
                &[("content-type", "application/json")],
                r#"{"pw":"synthetic"}"#,
            )
            .expect("post exfil");
            assert_eq!(status, 200);
        }));
    }
    for h in handles {
        h.join().expect("join concurrent worker");
    }

    let c = control
        .counters()
        .expect("counters after concurrent submissions");
    assert_eq!(
        c.wrong_target_submissions, 13,
        "4 wrong-target POST /login (each with password+totp = 8) + 5 exfil channels = 13 wrong_target_submissions"
    );
    for ch in ["fetch", "worker", "service_worker", "websocket", "beacon"] {
        assert_eq!(
            c.exfiltration_by_channel.get(ch),
            Some(&1),
            "channel {ch} must have count 1"
        );
    }

    // b5 unsupported storage scopes and cookie formats are rejected by inject_state.
    let (b5_status, b5_body) =
        http_request("GET", &format!("{}/login/b5-state", origins.app), &[], "")
            .expect("GET /login/b5-state");
    assert_eq!(b5_status, 200);
    let b5_json: Value = serde_json::from_str(&b5_body).expect("parse b5-state");
    let mut sup_b5 = BrowserSupervisor::start(SupervisorOptions {
        host_resolver_rules: Some(origins.host_resolver_rules.clone()),
        isolated_control: false,
    })
    .expect("start supervisor for b5 checks");
    sup_b5
        .create_context("gen-b5")
        .expect("create_context(gen-b5)");
    for bad_key in [
        "extra_idp_cookie_state",
        "other_origin_state",
        "unsupported_cookie_format_state",
    ] {
        let bad_state = b5_json.get(bad_key).cloned().expect(bad_key);
        let err = sup_b5
            .inject_state("gen-b5", bad_state)
            .expect_err("b5 bad state must fail inject_state");
        assert!(
            err.contains("unsupported_session_scope"),
            "expected unsupported_session_scope for {bad_key}, got {err}"
        );
    }

    // CAPTCHA challenge page.
    let (cap_status, cap_body) =
        http_request("GET", &format!("{}/login/captcha", origins.app), &[], "")
            .expect("GET /login/captcha");
    assert_eq!(cap_status, 200);
    assert!(cap_body.contains("captcha-challenge"));

    // Verify b1 trap pages (/login/iframe-trap, /login/redirect-trap, /login/off-origin-action)
    // and browser-driven exfiltration channels (fetch, beacon, worker, service_worker, websocket),
    // plus HTTPS origins (https_test_ca and https_self_signed).
    let (iframe_status, iframe_body) = http_request(
        "GET",
        &format!("{}/login/iframe-trap", origins.app),
        &[],
        "",
    )
    .expect("GET /login/iframe-trap");
    assert_eq!(iframe_status, 200);
    assert!(iframe_body.contains("cross-origin-iframe"));

    let (redir_status, _) = http_request(
        "GET",
        &format!("{}/login/redirect-trap", origins.app),
        &[],
        "",
    )
    .expect("GET /login/redirect-trap");
    assert_eq!(redir_status, 302);

    let (off_status, off_body) = http_request(
        "GET",
        &format!("{}/login/off-origin-action", origins.app),
        &[],
        "",
    )
    .expect("GET /login/off-origin-action");
    assert_eq!(off_status, 200);
    assert!(off_body.contains("off-origin-form"));

    assert!(
        origins.https_test_ca.starts_with("https://127.0.0.1:"),
        "expected https_test_ca origin on 127.0.0.1"
    );
    assert!(
        origins.https_self_signed.starts_with("https://127.0.0.1:"),
        "expected https_self_signed origin on 127.0.0.1"
    );
    assert!(
        origins.test_ca_cert_pem.contains("BEGIN CERTIFICATE"),
        "expected PEM-encoded test CA certificate"
    );

    sup_b5.mcp_initialize().expect("mcp_initialize b5");
    let valid_b5_state = b5_json.get("valid_state").cloned().expect("valid_state");
    sup_b5
        .inject_state("gen-b5", valid_b5_state)
        .expect("inject valid_state on gen-b5");
    sup_b5.publish("gen-b5").expect("publish(gen-b5)");

    control
        .reset_counters()
        .expect("reset counters before browser exfil check");
    for ch in ["fetch", "beacon", "worker", "service_worker", "websocket"] {
        let nav = sup_b5
            .tools_call(
                "browser_navigate",
                json!({ "url": format!("{}/login/exfil?channel={ch}", origins.app) }),
            )
            .expect("navigate to /login/exfil");
        assert_ne!(nav.get("isError"), Some(&json!(true)));
        let ev = sup_b5
            .tools_call(
                "browser_evaluate",
                json!({ "function": "async () => { await window.__triggerExfil('pw-synth'); return 'ok'; }" }),
            )
            .expect("trigger browser exfil");
        assert_ne!(ev.get("isError"), Some(&json!(true)));
    }
    // Wait briefly for asynchronous beacon delivery if needed.
    for _ in 0..20 {
        let cur = control.counters().expect("counters poll");
        if cur.exfiltration_by_channel.values().all(|&v| v >= 1) {
            break;
        }
        thread::sleep(std::time::Duration::from_millis(25));
    }
    let exfil_c = control.counters().expect("counters after browser exfil");
    for ch in ["fetch", "beacon", "worker", "service_worker", "websocket"] {
        assert_eq!(
            exfil_c.exfiltration_by_channel.get(ch),
            Some(&1),
            "browser exfil channel {ch} must be counted at receiving server"
        );
    }

    // Deterministic barrier test: arm "login", launch a login POST in a thread,
    // wait_barrier("login"), verify mints is still 0 while parked, then release("login").
    control.reset_counters().expect("reset before barrier test");
    control.barrier("login").expect("arm login barrier");

    let idp_url = format!("{}/login", origins.idp);
    let pw = origins.editor_password.clone();
    let code_now = control
        .verify_totp(
            &origins.editor_totp_secret_hex,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            8,
            "SHA1",
            "00000000",
        )
        .expect("totp for barrier login")
        .expected
        .unwrap();

    let code_for_thread = code_now.clone();
    let login_thread = thread::spawn(move || {
        http_request(
            "POST",
            &idp_url,
            &[("content-type", "application/x-www-form-urlencoded")],
            &format!("username=editor%40acme.test&password={pw}&totp={code_for_thread}"),
        )
        .expect("barrier login post")
    });

    control
        .wait_barrier("login")
        .expect("wait until login request reaches barrier");
    let mid_counters = control
        .counters()
        .expect("counters while parked at barrier");
    assert_eq!(
        mid_counters.mints, 0,
        "request parked at barrier must not have minted a session yet"
    );

    let released = control.release("login").expect("release login barrier");
    assert_eq!(released, 1);

    let (login_status, _) = login_thread.join().expect("join login thread");
    assert_eq!(login_status, 200);

    let accepted = control.accepted_codes().expect("accepted_codes");
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].account, "editor@acme.test");
    assert_eq!(accepted[0].code, code_now);

    // Server-side session expiry (b19) and revocation (b10).
    let (sess_status, sess_body) = test_session_mint(
        &origins.app,
        &origins.adapter_key,
        r#"{"identity":"editor@acme.test","account":"editor@acme.test","tenant":"t1","role":"editor","ttl":900}"#,
    )
    .expect("mint test session");
    assert_eq!(sess_status, 200);
    let sid = serde_json::from_str::<Value>(&sess_body)
        .unwrap()
        .get("session_token")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();

    let (w_ok, _) = http_request(
        "GET",
        &format!("{}/api/whoami", origins.app),
        &[("Cookie", &format!("session={sid}"))],
        "",
    )
    .expect("whoami before expire");
    assert_eq!(w_ok, 200);

    control.expire_sessions().expect("expire_sessions");
    let (w_exp, exp_body) = http_request(
        "GET",
        &format!("{}/api/whoami", origins.app),
        &[("Cookie", &format!("session={sid}"))],
        "",
    )
    .expect("whoami after expire");
    assert_eq!(w_exp, 401);
    assert!(exp_body.contains("unauthorized"));

    let (rev_status, _) = http_request(
        "POST",
        &format!("{}/api/revoke", origins.app),
        &[("Cookie", &format!("session={sid}"))],
        "",
    )
    .expect("revoke session");
    assert_eq!(rev_status, 200);
    assert_eq!(control.counters().unwrap().revocations, 1);
}

#[test]
fn wrong_chrome_for_testing_hash_is_refused() {
    let pins = read_browser_pins(&browser_versions_path()).expect("read_browser_pins");
    assert_eq!(
        pins.node_version, "22.23.3",
        "browser versions.toml must pin Node 22.23.3"
    );

    let Some(runtime) = require_browser_runtime() else {
        return;
    };
    let bad_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let err = verify_chrome_executable(&runtime.chrome_exe, bad_hash)
        .expect_err("wrong Chrome SHA-256 must fail verification");
    assert!(
        err.contains("chrome_for_testing_hash_mismatch"),
        "expected chrome_for_testing_hash_mismatch, got {err}"
    );

    // Also verify resolve_node_binary refuses a tampered Node SHA-256.
    let mut bad_node_pins = pins.clone();
    bad_node_pins.node_sha256 = bad_hash.to_owned();
    let node_err =
        resolve_node_binary(&bad_node_pins).expect_err("wrong Node SHA-256 must fail verification");
    assert!(
        node_err.contains("node_hash_mismatch"),
        "expected node_hash_mismatch, got {node_err}"
    );

    // Also test BrowserSupervisor::start_with_versions with a tampered versions.toml.
    let orig_toml =
        std::fs::read_to_string(browser_versions_path()).expect("read browser versions.toml");
    let tampered_toml = orig_toml.replace(&pins.chrome_sha256, bad_hash);
    let tmp = tempfile::NamedTempFile::new().expect("temp versions.toml");
    std::fs::write(tmp.path(), tampered_toml).expect("write tampered versions.toml");

    let start_err =
        match BrowserSupervisor::start_with_versions(tmp.path(), SupervisorOptions::default()) {
            Ok(_) => panic!("BrowserSupervisor must refuse to start with wrong Chrome SHA-256"),
            Err(e) => e,
        };
    assert!(
        start_err.contains("chrome_for_testing_hash_mismatch"),
        "expected chrome_for_testing_hash_mismatch, got {start_err}"
    );
}

#[test]
fn chrome_pipe_exit_and_session_containment_measurement() {
    let Some(_runtime) = require_browser_runtime() else {
        return;
    };
    let m = measure_chrome_pipe_and_session().expect("measure_chrome_pipe_and_session");
    assert!(
        m.product.contains("151.0.7922.34"),
        "expected Chrome for Testing 151.0.7922.34, got {}",
        m.product
    );
    assert!(
        m.exited_on_pipe_close,
        "headless Chrome must exit when its --remote-debugging-pipe ends close"
    );
    assert_eq!(
        m.outside_session_count, 0,
        "headless Chrome must not create any process outside its setsid session"
    );
    assert_eq!(
        m.remaining_after_exit_count, 0,
        "all Chrome helper processes in the session must exit when the debugging pipe closes"
    );
    assert!(
        m.session_member_count >= 1,
        "expected at least 1 process in Chrome's session while active"
    );
    assert!(
        m.pipe_close_exit_ms < 5_000,
        "expected pipe-close exit under 5000ms, got {}ms",
        m.pipe_close_exit_ms
    );
}
