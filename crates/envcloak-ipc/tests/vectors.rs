//! Cross-language M3-03 fixtures. The values are runtime canaries and the
//! encoders are the real Rust frame, WireSecret and display implementations.
#![allow(clippy::unwrap_used)]

use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{fs, io::Write, path::Path};

use envcloak_core::SecretBytes;
use envcloak_ipc::{ErrorKind, Frame, WireSecret, proto::REASONS};
use envcloak_testkit::{canaries, fresh_seed};
use serde_json::json;

#[test]
fn swift_cross_language_vectors() {
    let temporary = tempfile::tempdir().unwrap();
    let explicit = std::env::var_os("ENVCLOAK_SWIFT_VECTORS");
    let directory = explicit
        .as_deref()
        .map(Path::new)
        .unwrap_or(temporary.path());
    let metadata = fs::symlink_metadata(directory).unwrap();
    assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.permissions().mode() & 0o077, 0);
    let mut values = Vec::new();
    for canary in canaries(fresh_seed()) {
        let value = WireSecret::new(SecretBytes::copy_from(canary.value()));
        let frame = Frame::encode(&value).unwrap();
        let mut encoded = Vec::new();
        frame.write_to(&mut encoded).unwrap();
        let decoded: WireSecret = Frame::read_from(&mut encoded.as_slice())
            .unwrap()
            .decode()
            .unwrap();
        assert!(decoded.as_secret().ct_eq(canary.value()));
        values.push(json!({"bytes": canary.value(), "frame": encoded}));
    }
    // Padding and the 16 KiB growth boundary, generated without literals.
    for length in [0, 1, 2, 3, 16_383, 16_384, 16_385] {
        let bytes: Vec<u8> = (0..length).map(|n| (n % 256) as u8).collect();
        let value = WireSecret::new(SecretBytes::copy_from(&bytes));
        let mut encoded = Vec::new();
        Frame::encode(&value)
            .unwrap()
            .write_to(&mut encoded)
            .unwrap();
        values.push(json!({"bytes": bytes, "frame": encoded}));
    }
    let escapes: Vec<_> = (0..=0x10ffff)
        .filter_map(char::from_u32)
        .filter(|c| envcloak_policy::display_escaped(*c) || *c == '\\')
        .map(|c| {
            let text = format!("a{c}z");
            json!({"input": text, "display": envcloak_policy::escape_for_display(&text)})
        })
        .collect();
    let errors: Vec<_> = ErrorKind::ALL
        .iter()
        .map(|kind| json!({"kind": kind.token(), "code": kind.code()}))
        .collect();
    let output = json!({"base64": values, "escapes": escapes, "reasons": REASONS, "errors": errors, "responses": response_vectors()});
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("rust.json"))
        .unwrap();
    file.write_all(&serde_json::to_vec(&output).unwrap())
        .unwrap();
    file.sync_all().unwrap();
}

// Contract-derived metadata, serialized by the production Rust response
// encoder. These exercise nonempty success shapes beside the real-daemon
// absent-vault checks; they are not a vault authorization oracle.
fn response_vectors() -> serde_json::Value {
    use envcloak_ipc::{proto::result_frame, view::*};
    fn response<T: View>(value: serde_json::Value) -> Vec<u8> {
        let typed: T = serde_json::from_value(value).unwrap();
        let mut wire = Vec::new();
        result_frame(u64::MAX, &typed)
            .unwrap()
            .write_to(&mut wire)
            .unwrap();
        wire
    }
    let item = json!({
        "id": "fixture", "slug": "fixture", "class": "secret", "title": "Fixture",
        "provider": "fixture", "classification": "test", "env_hint": "FIXTURE",
        "allow_short": false, "fields": [{"name": "value", "prior_count": 2, "created_secs": 1, "updated_secs": 2}],
        "created_secs": 1, "updated_secs": 2, "rotated_secs": 2, "expires_secs": null,
        "account": {"email": "fixture@example.invalid", "label": null, "org_id": null},
        "detail": {"allowed_hosts": ["example.invalid"], "tags": ["test"],
          "links": {"docs": "https://example.invalid/", "billing": null, "keys_page": null, "dashboard": null},
          "last_used_secs": 2, "notes": "metadata"},
        "exposed": {"since_secs": 1, "sources": ["agent_config"], "count": 2}
    });
    json!({
        "status": response::<StatusView>(json!({
            "daemon": {"version": "0.1.0", "pid": 7, "hardening": {"core_dumps_off": true, "non_dumpable": false, "hardened_runtime": false}, "runtime_dir_fallback": false},
            "vault": {"state": "unlocked", "integrity": "ok", "read_only": false, "unavailable": null, "busy": false, "failed_unlocks": 0},
            "lock": {"last_reason": "request", "idle_limit_secs": 600, "idle_remaining_secs": 599},
            "approvals": {"grants": 1, "pending": 2, "proof_failures": 0, "proof_wait_secs": 0},
            "audit": {"open": true, "head_seq": 8, "unanchored": 1, "anchor_failed": false, "queued": 0, "dropped": 0}
        })),
        "lock": response::<LockedView>(json!({"was_unlocked": true})),
        "items.list": response::<ItemsView>(json!({"items": [item.clone()]})),
        "items.show": response::<ItemView>(item.clone()),
        "items.add": response::<AddedView>(json!({"item": item, "field": "value", "detected": null, "ambiguous": false, "length": "ok"})),
        "items.check": response::<CheckView>(json!({"project_dir": "/fixture", "project_name": "Fixture", "bindings": [{"profile": null, "env_name": "FIXTURE", "reference": "fixture", "status": "ok"}], "refs": ["unknown_item"]})),
        "grants.list": response::<GrantsView>(json!({"grants": [{"id": "fixture", "kind": "agent", "label": "Fixture", "root_pid": 7, "root_exe": "/fixture", "project_dir": "/project", "bindings": [{"env_name": "FIXTURE", "slug": "fixture", "live": false}], "mode": "inject", "uses": "session", "created_secs": 1, "remaining_secs": 30}]})),
        "grants.revoke": response::<RevokedView>(json!({"revoked": 1})),
        "deny": response::<DeniedView>(json!({"root_auto_denied": true})),
        "audit.verify": response::<AuditVerifyView>(json!({"segments": 1, "entries": 8, "last_seq": 8, "first_problem": {"seq": 8, "kind": "altered"}, "problems": 1, "anchor": {"state": "matched", "seq": 7}, "unanchored_tail": {"first": 8, "last": 8}, "torn_tail": false, "torn_bytes": 0, "live_head_matches": true, "queued": 0, "dropped": 0})),
        "backup.create": response::<BackupView>(json!({"path": "/fixture/backup", "file_name": "backup", "items": 1, "bytes": 1024, "created_secs": 3}))
    })
}
