//! Gate 22, role separation (SPEC §4.3): peers failing the app pins stay
//! clients. Every `app`-role method such a peer calls is rejected and
//! audited, and changes nothing. app_peer covers the native signed tier. The audit record names a
//! known method, or a placeholder for an unknown one, and never repeats
//! what the client sent.
#![allow(clippy::unwrap_used)]

mod common;

use base64::Engine as _;
use common::{client, create_vault, error_kind, raw, read_json, send_json, start};
use envcloak_ipc::proto::APP_METHODS;
use envcloak_ipc::view::VaultState;
use envcloak_testkit::{TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels};
use serde_json::json;

#[test]
fn every_app_method_is_rejected_and_audited() {
    let cs = canaries(fresh_seed());
    let secret = by_label(&cs, labels::OPENAI_API_KEY).as_str();
    let pass = by_label(&cs, labels::VAULT_PASSPHRASE).value();
    let b64 = base64::engine::general_purpose::STANDARD.encode(pass);
    let home = TestHome::new();
    let d = start(&home);
    let kit = create_vault(&home, &cs);
    client(&home).lock().unwrap();

    let unknown = format!("app.{secret}");
    let mut methods: Vec<&str> = APP_METHODS.to_vec();
    methods.push("app.something.else");
    methods.push(&unknown);
    let mut s = raw(&home);
    for (id, m) in methods.iter().enumerate() {
        // Parameters an app would send, including the real passphrase: a
        // client-role peer gets nothing for them.
        send_json(
            &mut s,
            &json!({"jsonrpc": "2.0", "id": id, "method": m, "params": {"passphrase": b64, "value": secret}}),
        );
        let r = read_json(&mut s).unwrap();
        assert_eq!(error_kind(&r), "role_denied", "{m}");
        assert_eq!(r["id"], id, "{m}");
        assert_eq!(r["error"]["code"], -32001);
    }
    drop(s);

    // Nothing changed: in particular, app.unlock did not unlock.
    assert_eq!(
        client(&home).status().unwrap().vault.state,
        VaultState::Locked
    );

    let log = d.log();
    let audited: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("audit: denied"))
        .collect();
    assert_eq!(audited.len(), methods.len(), "{log}");
    for m in APP_METHODS {
        let line = format!("audit: denied method={m} reason=role_denied role=client pid=");
        assert_eq!(log.matches(&line).count(), 1, "{m} is audited once: {log}");
    }
    assert_eq!(log.matches("method=app.(unknown)").count(), 2, "{log}");
    let mut all = cs.clone();
    all.push(kit);
    assert_no_canary(&d.log_bytes(), &all);
}

#[test]
fn unknown_client_methods_are_not_found_and_not_echoed() {
    let cs = canaries(fresh_seed());
    let secret = by_label(&cs, labels::GITHUB_TOKEN).as_str();
    let home = TestHome::new();
    let d = start(&home);
    let mut s = raw(&home);
    for m in ["unlockx", "status.more", secret] {
        send_json(&mut s, &json!({"jsonrpc": "2.0", "id": 5, "method": m}));
        let r = read_json(&mut s).unwrap();
        assert_eq!(error_kind(&r), "method_not_found", "{m}");
        assert_no_canary(r.to_string().as_bytes(), &cs);
    }
    // A malformed request gets a fixed error and the connection stays up.
    send_json(
        &mut s,
        &json!({"jsonrpc": "2.0", "id": secret, "method": "status"}),
    );
    let r = read_json(&mut s).unwrap();
    assert_eq!(error_kind(&r), "invalid_request");
    assert!(r["id"].is_null());
    send_json(
        &mut s,
        &json!({"jsonrpc": "2.0", "id": 6, "method": "status"}),
    );
    assert_eq!(read_json(&mut s).unwrap()["id"], 6);
    drop(s);
    assert_no_canary(&d.log_bytes(), &cs);
}
