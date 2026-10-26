//! M2b-08 integration tests: hosted browser supervisor, D-30 tool allowlist,
//! `not_started_by_daemon` direct-entry refusal, `traced` refusal on
//! `inject_state`, host-facing `BrowserRelay` and `Router` dispatch, `cycle342`
//! post-`addCookies` cookie metadata verification across all 5 acceptance cases,
//! and Gates `b2`, `b3`, `b4`, `b5`, `b6`, `b9`, `b10`, `b11`, `b13`.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::thread;

use envcloak_mcp::browser::{
    ALLOWED_BROWSER_TOOLS, BrokerStopOutcome, BrowserRelay, BrowserSupervisor,
    CONTEXT_NOT_PUBLISHED, CleanupOutcome, DeclaredSecretCookie, DeclaredSecretLocalStorageItem,
    DeclaredSecretOrigin, DeclaredSecretState, EXCLUDED_BROWSER_TOOLS, ExpectedIdentity,
    FORBIDDEN_PATH_ARGS, GRANT_REVOKED, IDENTITY_UNVERIFIED, NOT_STARTED_BY_DAEMON,
    RevocationOutcome, SessionDeliveryPlan, SupervisorError, SupervisorOptions, TOOL_NOT_ALLOWED,
    TRACED_REFUSAL, ToolAllowlist, UNSUPPORTED_SESSION_SCOPE, browser_versions_path,
    deliver_secret_session, deliver_session, end_session, register_browser_tools,
    resolve_browser_runtime, run_browser_supervisor, verify_started_by_daemon,
    verify_started_by_daemon_fd,
};
use envcloak_mcp::{Router, Server};
use envcloak_testkit::signin::{SigninFixture, http_request, require_browser_runtime};
use secrecy::SecretString;
use serde_json::{Map, Value, json};

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
fn direct_browser_supervisor_entry_refused_and_positive_control_accepted() {
    // Without ENVCLOAK_BROWSER_SUPERVISOR_FD or daemon parent socket, direct
    // entry is refused with not_started_by_daemon before any helper starts.
    let err = run_browser_supervisor().expect_err("direct entry must be refused");
    assert_eq!(err.token(), NOT_STARTED_BY_DAEMON);
    assert_eq!(
        verify_started_by_daemon().expect_err("missing env var must fail"),
        SupervisorError::NotStartedByDaemon
    );
    assert_eq!(
        verify_started_by_daemon_fd(2).expect_err("fd < 3 must fail"),
        SupervisorError::NotStartedByDaemon
    );

    // Positive control: a genuine same-UID connected UnixStream is accepted by
    // verify_started_by_daemon_fd().
    let (parent_sock, child_sock) = UnixStream::pair().expect("UnixStream::pair");
    let raw_fd = child_sock.as_raw_fd();
    // Keep child_sock open while verify_started_by_daemon_fd claims it.
    std::mem::forget(child_sock);
    let claimed = verify_started_by_daemon_fd(raw_fd).expect("same-UID socketpair must pass");
    drop(claimed);
    drop(parent_sock);

    // Runtime pin verification positive & negative controls (`signin setup` engine):
    if require_browser_runtime().is_some() {
        let vpath = browser_versions_path();
        let rt = resolve_browser_runtime(&vpath).expect("pinned runtime must verify");
        assert!(!rt.pins.node_version.is_empty());
        assert!(!rt.pins.helper_version.is_empty());
        assert!(!rt.pins.chrome_version.is_empty());

        let tmp = tempfile::tempdir().expect("tempdir");
        let bad_versions = tmp.path().join("versions.toml");
        let orig_toml = std::fs::read_to_string(&vpath).expect("read versions.toml");
        let mutated = orig_toml.replace(
            &rt.pins.helper_entry_sha256,
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        std::fs::write(&bad_versions, mutated).expect("write mutated versions.toml");
        let bad_err =
            resolve_browser_runtime(&bad_versions).expect_err("mutated SHA-256 must fail");
        assert!(
            bad_err.contains("SHA-256"),
            "unexpected error on mutated pin: {bad_err}"
        );
    }
}

#[test]
fn d30_allowlist_and_router_registration_enforce_tool_and_arg_filters() {
    // Verify static schemas and Router registration work even without a browser runtime.
    let static_tools = ToolAllowlist::static_schemas();
    assert_eq!(static_tools.len(), ALLOWED_BROWSER_TOOLS.len());

    let mut router = Router::new();
    let relay = BrowserRelay::new();
    register_browser_tools(&mut router, relay.clone()).expect("register_browser_tools");

    let srv = Server::with_browser_relay(relay.clone());
    assert!(
        srv.tools().iter().any(|t| t.name == "browser_find"),
        "Server::with_browser_relay must list browser_find and the D-30 browser tools"
    );

    let listed: Vec<Value> = router.list().into_iter().map(|s| s.to_json()).collect();
    for &tool_name in ALLOWED_BROWSER_TOOLS {
        let entry = listed
            .iter()
            .find(|t| t.get("name").and_then(Value::as_str) == Some(tool_name))
            .unwrap_or_else(|| panic!("router missing allowlisted browser tool {tool_name}"));
        let props = entry
            .get("inputSchema")
            .and_then(|s| s.get("properties"))
            .and_then(Value::as_object)
            .expect("inputSchema.properties");
        for forbidden in FORBIDDEN_PATH_ARGS {
            assert!(
                !props.contains_key(*forbidden),
                "tool {tool_name} exposed forbidden path arg {forbidden}"
            );
        }
    }
    for &excluded in EXCLUDED_BROWSER_TOOLS {
        assert!(
            !listed
                .iter()
                .any(|t| t.get("name").and_then(Value::as_str) == Some(excluded)),
            "router must never list excluded tool {excluded}"
        );
    }

    // Calling BrowserRelay with an excluded tool or forbidden path arg returns
    // tool_not_allowed before touching any supervisor.
    let bad_tool = relay.call_json("browser_run_code_unsafe", json!({}));
    assert_eq!(bad_tool.get("isError"), Some(&json!(true)));
    assert_eq!(bad_tool.get("reason"), Some(&json!(TOOL_NOT_ALLOWED)));

    let bad_arg = relay.call_json(
        "browser_take_screenshot",
        json!({ "filename": "/tmp/evil.png" }),
    );
    assert_eq!(bad_arg.get("isError"), Some(&json!(true)));
    assert_eq!(bad_arg.get("reason"), Some(&json!(TOOL_NOT_ALLOWED)));

    // Calling BrowserRelay with an allowed tool when no session is published
    // returns sign_in_context_not_published.
    let unpub = relay.call_json(
        "browser_navigate",
        json!({ "url": "https://acme.localhost/dashboard" }),
    );
    assert_eq!(unpub.get("isError"), Some(&json!(true)));
    assert_eq!(unpub.get("reason"), Some(&json!(CONTEXT_NOT_PUBLISHED)));
}

#[test]
fn traced_supervisor_refuses_inject_state_and_keeps_context_unpublished() {
    let Some(_rt) = require_browser_runtime() else {
        return;
    };

    let mut sup = BrowserSupervisor::start(SupervisorOptions {
        host_resolver_rules: None,
        isolated_control: false,
        simulate_traced: true,
        simulate_close_failure: false,
    })
    .expect("start BrowserSupervisor");
    sup.mcp_initialize().expect("mcp_initialize");
    sup.create_context("gen-traced")
        .expect("create_context(gen-traced)");

    // Both JSON inject_state and SecretString inject_secret_state must refuse with Traced.
    let err1 = sup
        .inject_state(
            "gen-traced",
            json!({
                "allowed_cookie_domains": ["acme.localhost"],
                "cookies": [{
                    "name": "sid",
                    "value": "secret-val",
                    "domain": "acme.localhost",
                    "path": "/"
                }]
            }),
        )
        .expect_err("traced supervisor must refuse inject_state");
    assert_eq!(err1, SupervisorError::Traced);
    assert_eq!(err1.as_str(), TRACED_REFUSAL);

    let secret_state = DeclaredSecretState {
        allowed_cookie_domains: vec!["acme.localhost".to_owned()],
        allowed_origins: vec!["http://acme.localhost".to_owned()],
        cookies: vec![DeclaredSecretCookie {
            name: "sid".to_owned(),
            value: SecretString::from("secret-cookie-val".to_owned()),
            domain: "acme.localhost".to_owned(),
            path: "/".to_owned(),
            http_only: true,
            secure: false,
            same_site: Some("Lax".to_owned()),
            format: None,
            device_bound: false,
        }],
        origins: Vec::new(),
    };
    let err2 = sup
        .inject_secret_state("gen-traced", &secret_state)
        .expect_err("traced supervisor must refuse inject_secret_state");
    assert_eq!(err2, SupervisorError::Traced);

    let stats = sup.helper_stats().expect("helper_stats");
    assert!(
        !stats.published,
        "context must remain unpublished after traced refusal"
    );
}

#[test]
fn cycle342_all_five_cookie_path_cases_verified_against_live_browser_helper() {
    let Some(_rt) = require_browser_runtime() else {
        return;
    };

    // Start a tiny local HTTP server on 127.0.0.1 that serves the 5 Set-Cookie
    // headers from `.collab/research/cycle342-native-acceptance.json`.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let port = listener.local_addr().expect("local_addr").port();
    let server_handle = thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap_or(0);
            if n == 0 {
                continue;
            }
            let req = String::from_utf8_lossy(&buf[..n]);
            let first_line = req.lines().next().unwrap_or("");
            let path = first_line.split_whitespace().nth(1).unwrap_or("/");
            if path == "/quit" {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                break;
            }
            let set_cookie = match path {
                "/set/plain" => "s=v; Path=/part-one; HttpOnly; SameSite=Lax",
                "/set/encoded-space" => "s=v; Path=/part%20one; HttpOnly; SameSite=Lax",
                "/set/interior-space" => "s=v; Path=/part one; HttpOnly; SameSite=Lax",
                "/set/header-trailing-space" => "s=v; Path=/part-one ; HttpOnly; SameSite=Lax",
                "/set/header-leading-space" => "s=v; Path= /part-one; HttpOnly; SameSite=Lax",
                _ => "s=v; Path=/; HttpOnly; SameSite=Lax",
            };
            let body = "<!doctype html><title>cookie</title>ok";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: {set_cookie}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });

    let rules = "MAP acme.localhost 127.0.0.1".to_string();
    let cases = [
        ("plain", "/set/plain", true),
        ("encoded-space", "/set/encoded-space", true),
        ("interior-space", "/set/interior-space", false),
        ("header-trailing-space", "/set/header-trailing-space", true),
        ("header-leading-space", "/set/header-leading-space", true),
    ];

    for (name, endpoint, expect_accepted) in cases {
        let mut sup = BrowserSupervisor::start(SupervisorOptions {
            host_resolver_rules: Some(rules.clone()),
            isolated_control: false,
            simulate_traced: false,
            simulate_close_failure: false,
        })
        .expect("start BrowserSupervisor for cycle342 case");

        let url = format!("http://acme.localhost:{port}{endpoint}");
        let captured = sup
            .capture_cookies_from_url(&url)
            .expect("capture_cookies_from_url");
        assert_eq!(
            captured.len(),
            1,
            "case {name}: expected 1 captured cookie from {url}"
        );

        // Also verify direct cookie import with the exact declared path (without
        // trimming or normalizing interior spaces) so `/part one` is refused by
        // `inject_state`'s post-`addCookies` re-read (`cycle342`).
        let direct_path = match name {
            "plain" | "header-trailing-space" | "header-leading-space" => "/part-one",
            "encoded-space" => "/part%20one",
            "interior-space" => "/part one",
            _ => "/",
        };
        let mut direct_cookie = captured[0].clone();
        if let Some(obj) = direct_cookie.as_object_mut() {
            obj.insert("path".to_owned(), json!(direct_path));
        }

        let generation = format!("gen-{name}");
        sup.create_context(&generation).expect("create_context");
        let inject_res = sup.inject_state(
            &generation,
            json!({
                "allowed_cookie_domains": ["acme.localhost"],
                "cookies": [direct_cookie],
            }),
        );

        if expect_accepted {
            assert!(
                inject_res.is_ok(),
                "case {name}: expected cookie import to succeed, got {inject_res:?}"
            );
        } else {
            let err = inject_res.expect_err("case interior-space must be refused on import");
            assert_eq!(
                err.as_str(),
                UNSUPPORTED_SESSION_SCOPE,
                "case {name}: expected {UNSUPPORTED_SESSION_SCOPE}, got {err:?}"
            );
            let stats = sup.helper_stats().expect("helper_stats");
            assert!(
                !stats.published,
                "case {name}: refused cookie scope must leave context unpublished"
            );
        }
    }

    let _ = http_request("GET", &format!("http://127.0.0.1:{port}/quit"), &[], "");
    let _ = server_handle.join();
}

#[test]
fn delivery_pipeline_stop_outcomes_and_relay_isolation_end_to_end() {
    let Some(_rt) = require_browser_runtime() else {
        return;
    };
    let (origins, control) = SigninFixture::start();

    let mut sup = BrowserSupervisor::start(SupervisorOptions {
        host_resolver_rules: Some(origins.host_resolver_rules.clone()),
        isolated_control: false,
        simulate_traced: false,
        simulate_close_failure: false,
    })
    .expect("start BrowserSupervisor");
    sup.mcp_initialize().expect("mcp_initialize");

    // Capture a live editor session using worker_login_and_capture.
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let totp_code = control
        .verify_totp(
            &origins.editor_totp_secret_hex,
            now_secs,
            8,
            "SHA1",
            "00000000",
        )
        .expect("compute editor TOTP")
        .expected
        .expect("expected TOTP");

    let login_url = format!("{}/login", origins.app);
    let captured = sup
        .worker_login_and_capture(
            &login_url,
            "editor@acme.test",
            &origins.editor_password,
            Some(&totp_code),
        )
        .expect("worker_login_and_capture");
    let token = captured
        .get("token")
        .and_then(Value::as_str)
        .expect("captured token")
        .to_owned();
    let first_cookie = captured
        .get("captured_state")
        .and_then(|s| s.get("cookies"))
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .cloned()
        .expect("captured session cookie");
    let cookie_name = first_cookie
        .get("name")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    let cookie_val = first_cookie
        .get("value")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    let cookie_domain = first_cookie
        .get("domain")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned();
    let cookie_path = first_cookie
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("/")
        .to_owned();

    // Deliver the session using DeclaredSecretState (`deliver_secret_session`).
    let secret_state = DeclaredSecretState {
        allowed_cookie_domains: vec![cookie_domain.trim_start_matches('.').to_owned()],
        allowed_origins: vec![origins.app.clone()],
        cookies: vec![DeclaredSecretCookie {
            name: cookie_name.clone(),
            value: SecretString::from(cookie_val.clone()),
            domain: cookie_domain,
            path: cookie_path,
            http_only: true,
            secure: false,
            same_site: Some("Lax".to_owned()),
            format: None,
            device_bound: false,
        }],
        origins: vec![DeclaredSecretOrigin {
            origin: origins.app.clone(),
            local_storage: vec![
                DeclaredSecretLocalStorageItem {
                    name: "acme_tenant".to_owned(),
                    value: SecretString::from("t1".to_owned()),
                },
                DeclaredSecretLocalStorageItem {
                    name: "acme_token".to_owned(),
                    value: SecretString::from(token.clone()),
                },
            ],
        }],
    };
    let expected_id = ExpectedIdentity {
        account: "editor@acme.test".to_owned(),
        tenant: "t1".to_owned(),
        role: "editor".to_owned(),
    };
    let whoami_url = format!("{}/api/whoami", origins.app);
    let receipt = deliver_secret_session(
        &mut sup,
        "gen-e2e",
        &secret_state,
        Some((&whoami_url, &expected_id)),
    )
    .expect("deliver_secret_session");
    assert!(receipt.published);
    assert_eq!(receipt.generation, "gen-e2e");

    // Attach to host-facing BrowserRelay and exercise browser_navigate + browser_evaluate.
    let relay = BrowserRelay::with_supervisor(sup);
    let nav_res = relay.call_json(
        "browser_navigate",
        json!({ "url": format!("{}/dashboard", origins.app) }),
    );
    assert_ne!(nav_res.get("isError"), Some(&json!(true)));
    let dash_text = extract_text(&nav_res);
    assert!(
        dash_text.contains("Acme Dashboard") || dash_text.contains("editor@acme.test"),
        "unexpected dashboard text: {dash_text}"
    );
    let whoami_eval = relay.call_json(
        "browser_evaluate",
        json!({
            "function": "async () => (await (await fetch('/api/whoami', { credentials: 'include' })).json())"
        }),
    );
    assert_ne!(whoami_eval.get("isError"), Some(&json!(true)));
    let whoami_text = extract_text(&whoami_eval);
    assert!(
        whoami_text.contains("editor@acme.test"),
        "expected editor@acme.test in /api/whoami response, got {whoami_text}"
    );
    for text in [&dash_text, &whoami_text] {
        assert!(!text.contains(&origins.editor_password));
        assert!(!text.contains(&origins.editor_totp_secret_hex));
        assert!(!text.contains(&totp_code));
    }

    // Gate b10: simulate close failure (`cleanup_failed`) and verify StopOutcomes
    // reports delivered=true, broker=Stopped, cleanup=CleanupFailed, revocation=Unknown.
    let outcomes_fail = relay
        .with_supervisor_mut(|s| {
            s.set_simulate_close_failure(true);
            end_session(s, "gen-e2e", true, false)
        })
        .expect("with_supervisor_mut");
    assert_eq!(
        outcomes_fail,
        envcloak_mcp::browser::StopOutcomes {
            delivered: true,
            broker: BrokerStopOutcome::Stopped,
            cleanup: CleanupOutcome::CleanupFailed,
            revocation: RevocationOutcome::Unknown,
        }
    );
    assert_eq!(outcomes_fail.cleanup.as_str(), "cleanup_failed");
    assert_eq!(
        outcomes_fail.revocation.description(),
        "server session expiry unknown"
    );

    // Subsequent tool calls through the relay are immediately refused with grant_revoked.
    let after_end = relay.call_json(
        "browser_evaluate",
        json!({ "function": "() => document.title" }),
    );
    assert_eq!(after_end.get("isError"), Some(&json!(true)));
    assert_eq!(after_end.get("reason"), Some(&json!(GRANT_REVOKED)));

    // Clear simulated close failure and perform real local context close (Gate b4:
    // copied cookie still works on server until server revocation is called).
    let outcomes_clean = relay
        .with_supervisor_mut(|s| {
            s.set_simulate_close_failure(false);
            end_session(s, "gen-e2e", true, false)
        })
        .expect("clean end_session");
    assert_eq!(outcomes_clean.cleanup, CleanupOutcome::Cleaned);
    assert_eq!(outcomes_clean.revocation, RevocationOutcome::Unknown);

    // Gate b4: a cookie value copied before end_session still works against /api/whoami
    // when no server revocation endpoint was invoked.
    let cookie_hdr = format!("{cookie_name}={cookie_val}");
    let (status_before_revoke, body_before_revoke) =
        http_request("GET", &whoami_url, &[("Cookie", &cookie_hdr)], "")
            .expect("GET /api/whoami with copied cookie");
    assert_eq!(
        status_before_revoke, 200,
        "Gate b4: copied cookie still works after local context close when server session is unrevoked: {body_before_revoke}"
    );

    // Verify wrong-identity refusal in SessionDeliveryPlan (`deliver_session`).
    let mut sup_wrong = BrowserSupervisor::start(SupervisorOptions {
        host_resolver_rules: Some(origins.host_resolver_rules.clone()),
        isolated_control: false,
        simulate_traced: false,
        simulate_close_failure: false,
    })
    .expect("start sup_wrong");
    let bad_plan = SessionDeliveryPlan {
        generation: "gen-wrong-role".to_owned(),
        declared_state: captured.get("captured_state").cloned().unwrap(),
        identity_check: Some((
            json!({ "url": whoami_url }),
            ExpectedIdentity {
                account: "editor@acme.test".to_owned(),
                tenant: "t1".to_owned(),
                role: "admin".to_owned(),
            },
        )),
    };
    let wrong_err =
        deliver_session(&mut sup_wrong, &bad_plan).expect_err("wrong role must be refused");
    assert_eq!(wrong_err.as_str(), IDENTITY_UNVERIFIED);
    assert!(!sup_wrong.is_published());
    let _ = Map::new();
}
