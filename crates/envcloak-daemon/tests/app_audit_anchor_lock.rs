//! Paged audit reading (`app.audit.list`), the keychain rollback anchor
//! (`ai.envcloak.anchor` / `ENVCLOAK_TEST_ANCHOR_FILE`), and app-role locking
//! (`app.lock`) over the daemon's socket (SPEC §4.3, §4.4, §5, §10b; M3 plan
//! task M3-16):
//!
//! - `app.audit.list`: reverse sequence order, `before_seq` pagination with
//!   `next_before_seq`, filtering by `project`, `item`, `agent` and `kinds`,
//!   `invalid_params` on out-of-range `limit` or unknown `kinds`, works on
//!   read-only tampered vaults, refused to `client`-role peers (`role_denied`,
//!   audited) and to `app` peers carrying agent evidence (`proof_refused`,
//!   audited), and canary-clean across all fields and `argv_masked`.
//! - Keychain rollback anchor: 68-byte `Anchor` written at `vault.create`,
//!   `unlock`, `app.unlock`, security-critical writes (`items.add`,
//!   `items.rotate`, `items.remove`, `app.items.rotate`, `app.items.remove`,
//!   `app.unlocker.enroll`), and `lock` / `app.lock`; checked at `unlock` and
//!   `app.unlock`. Rollback after `items.remove` or `app.items.remove` opens
//!   the vault read-only (`integrity = Tampered`, `read_only = true`,
//!   `status.vault.keychain_anchor = "ahead"`), writes a
//!   `keychain_anchor_mismatch` (`outcome = "tampered"`,
//!   `reason = "rolled_back"`) audit entry, and refuses grants, proofs and
//!   writes with `vault_tampered` (`reason = "rolled_back"`). A missing anchor
//!   on an anchored vault reports `status.vault.keychain_anchor = "missing"`,
//!   re-creates the anchor, and writes `keychain_anchor_mismatch`
//!   (`outcome = "recreated"`, `reason = "keychain_anchor_missing"`).
//! - `app.lock`: refused to `client`-role peers (`role_denied`, audited),
//!   accepted from an `app` peer even under agent evidence, updates the
//!   rollback anchor before dropping the unlocked `Vault`, drops the VMK, ends
//!   all grants and pending requests, records `last_reason` (`screen_lock`,
//!   `session_resign`, `request`), and writes the `lock` audit entry with the
//!   reason.
//!
//! Named mutation checks (M3 plan M3-16):
//! 1. Skip the anchor comparison at unlock:
//!    `rollback_after_items_remove_and_app_items_remove_marks_vault_tampered`
//!    fails.
//! 2. Skip updating the anchor at `items.remove` or `app.items.remove`:
//!    `rollback_after_items_remove_and_app_items_remove_marks_vault_tampered`
//!    fails.
//! 3. Allow `client`-role peers to call `app.lock` or `app.audit.list`:
//!    `role_and_agent_evidence_guards_on_app_audit_list_and_app_lock` fails.
//! 4. Apply the agent-evidence refusal to `app.lock`:
//!    `role_and_agent_evidence_guards_on_app_audit_list_and_app_lock` fails.
#![allow(clippy::unwrap_used)]

mod common;

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use common::{MANIFEST, SLUGS, client, data_dir, passphrase, project};
use envcloak_core::crypto::{
    ItemClass, KdfParams, P256_PUBLIC_KEY_LEN, SE_CHALLENGE_LEN, SE_HPKE_CIPHERTEXT_LEN,
    SE_HPKE_ENC_LEN, SeHpkeEnvelope, UnlockerId, UnlockerKind, VaultId, derive_p256_keypair,
    open_se_envelope, se_reseal_aad, seal_secret_to_x25519, seal_vmk_to_daemon, secret_sha256,
    sign_p256_prehash,
};
use envcloak_core::vault::{ANCHOR_LEN, Anchor, FieldName, ItemDetails, NewItem, Slug, VaultPaths};
use envcloak_core::{RecoveryKit, SecretBytes, create_vault_with_kit};
use envcloak_ipc::app::{
    AppAuditListParams, AppItemsRemoveParams, AppItemsRotateParams, AppLockReason,
    AppUnlockBeginOutput, AppUnlockerEnrollOutput,
};
use envcloak_ipc::proto::{AddParams, ErrorKind, PendingGetOutput, RunRequestParams};
use envcloak_ipc::view::{DecisionView, Integrity, KeychainAnchorState, LockReason, VaultState};
use envcloak_ipc::{ClientError, WireSecret};
use envcloak_policy::{
    ApprovalOptions, DEFAULT_TTL, Uses, WriteAction, WriteStatement, statement_digest,
    unlocker_statement_digest, write_statement_digest,
};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, encodings, fresh_seed, labels,
};

const TEST_TEAM_ID: &str = "AB12CD34EF";
const TEST_SIGNING_ID: &str = "ai.envcloak.app";

fn rpc_kind(e: ClientError) -> (ErrorKind, Option<&'static str>) {
    match e {
        ClientError::Rpc(r) => (r.kind, r.reason),
        other => panic!("expected an RPC error, got {other:?}"),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), 2 * N, "unexpected hex length: {}", s.len());
    let mut out = [u8::default(); N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

fn this_process_app_id() -> String {
    format!("{}:{TEST_TEAM_ID}:{TEST_SIGNING_ID}", std::process::id())
}

fn sample_se_keypairs(
    seed_byte: u8,
) -> (
    [u8; 32],
    [u8; P256_PUBLIC_KEY_LEN],
    [u8; 32],
    [u8; P256_PUBLIC_KEY_LEN],
) {
    let (unlock_sk, unlock_pub) = derive_p256_keypair(&[seed_byte; 32]);
    let (approve_sk, approve_pub) = derive_p256_keypair(&[seed_byte.wrapping_add(1); 32]);
    (unlock_sk, unlock_pub, approve_sk, approve_pub)
}

fn start_daemon(home: &TestHome, app_id: Option<&str>, anchor_file: Option<&Path>) -> Daemon {
    let mut cmd = Command::new(common::exe());
    home.apply(&mut cmd).env(envcloak_sys::testing::TRACE, "1");
    if let Some(id) = app_id {
        cmd.env(envcloak_sys::testing::APP_IDENTITY, id);
    }
    if let Some(af) = anchor_file {
        cmd.env(envcloak_sys::testing::ANCHOR_FILE, af);
    }
    Daemon::start_command(cmd, &[])
}

fn read_anchor_file(path: &Path) -> Anchor {
    let text = std::fs::read_to_string(path).unwrap();
    let line = text.lines().next().unwrap().trim();
    let (_account, hex_bytes) = line.split_once(':').unwrap();
    let arr = decode_hex::<ANCHOR_LEN>(hex_bytes);
    Anchor::decode(&arr).unwrap()
}

fn snapshot_vault_db(vault_dir: &Path, snap_dir: &Path) {
    let _ = std::fs::remove_dir_all(snap_dir);
    std::fs::create_dir_all(snap_dir).unwrap();
    for name in ["vault.db", "vault.db-wal", "vault.db-shm"] {
        let src = vault_dir.join(name);
        if src.exists() {
            std::fs::copy(&src, snap_dir.join(name)).unwrap();
        }
    }
}

fn restore_vault_db(snap_dir: &Path, vault_dir: &Path) {
    for name in ["vault.db", "vault.db-wal", "vault.db-shm"] {
        let dst = vault_dir.join(name);
        let src = snap_dir.join(name);
        if src.exists() {
            std::fs::copy(&src, &dst).unwrap();
        } else {
            let _ = std::fs::remove_file(&dst);
        }
    }
}

fn seed_vault_with_kit(home: &TestHome, cs: &[Canary]) -> (VaultId, UnlockerId, Vec<Canary>) {
    let kit = RecoveryKit::generate();
    let kit_text = kit.to_display();
    let paths = VaultPaths::under(data_dir(home));
    let mut v = create_vault_with_kit(&paths, &passphrase(cs), &kit, KdfParams::minimum()).unwrap();
    let vault_id = v.vault_id();

    let values = [
        labels::OPENAI_API_KEY,
        labels::STRIPE_SECRET_KEY,
        labels::GITHUB_TOKEN,
        labels::SHORT_TOKEN,
    ];
    let registry = envcloak_providers::load_embedded().unwrap();
    v.transact(|t| {
        for (slug, label) in SLUGS.iter().zip(values) {
            let value = SecretBytes::copy_from(by_label(cs, label).value());
            let det = registry.detect(&value, None);
            let mut details = ItemDetails {
                title: (*slug).to_owned(),
                classification: det.classification,
                ..ItemDetails::default()
            };
            registry.prefill(&det, &mut details);
            let id = t.create_item(NewItem {
                class: ItemClass::Secret,
                slug: Slug::new(slug).unwrap(),
                details,
            })?;
            t.add_field(id, FieldName::new("value").unwrap(), value)?;
        }
        Ok(())
    })
    .unwrap();
    let kit_id = v
        .unlockers()
        .find(|e| e.kind() == UnlockerKind::RecoveryKit)
        .unwrap()
        .unlocker_id();
    drop(v);
    let mut all_cs = cs.to_vec();
    all_cs.push(Canary::new("RECOVERY_KIT", kit_text.to_string()));
    (vault_id, kit_id, all_cs)
}

fn enroll_se_over_socket(
    c: &mut envcloak_ipc::Client,
    cs: &[Canary],
    unlock_pub: &[u8; P256_PUBLIC_KEY_LEN],
    approve_pub: &[u8; P256_PUBLIC_KEY_LEN],
    label: &str,
) -> String {
    let begin = c
        .app_unlocker_enroll_begin(
            &hex_encode(unlock_pub),
            &hex_encode(approve_pub),
            label,
            &[],
        )
        .unwrap();
    let PendingGetOutput::UnlockerAdd(desc) = c.pending_get_any(&begin.request, &[]).unwrap()
    else {
        panic!("expected unlocker_add descriptor");
    };
    let digest = unlocker_statement_digest(&desc);
    c.approve(
        &begin.request,
        ApprovalOptions {
            uses: Uses::Once,
            ttl_secs: DEFAULT_TTL.as_secs(),
            live: Vec::new(),
            standing: None,
        },
        &digest,
        passphrase(cs),
        &[],
    )
    .unwrap();
    let AppUnlockerEnrollOutput::Enrolled { unlocker_id } =
        c.app_unlocker_enroll(&begin.request, &[]).unwrap()
    else {
        panic!("expected Enrolled");
    };
    unlocker_id
}

fn perform_app_hpke_reseal(unlock_sk: &[u8; 32], begin: &AppUnlockBeginOutput) -> [u8; 80] {
    let vault_id = VaultId(decode_hex::<16>(&begin.vault_id));
    let unlocker_id = UnlockerId(decode_hex::<16>(&begin.unlocker_id));
    let challenge = decode_hex::<SE_CHALLENGE_LEN>(&begin.challenge);
    let daemon_eph_pub = decode_hex::<32>(&begin.daemon_eph_pub);
    let enc = decode_hex::<SE_HPKE_ENC_LEN>(&begin.envelope.enc);
    let ciphertext = decode_hex::<SE_HPKE_CIPHERTEXT_LEN>(&begin.envelope.ciphertext);
    let vmk = open_se_envelope(
        unlock_sk,
        vault_id,
        unlocker_id,
        begin.epoch,
        &SeHpkeEnvelope { enc, ciphertext },
    )
    .unwrap();
    seal_vmk_to_daemon(&daemon_eph_pub, &begin.request_id, &challenge, &vmk).unwrap()
}

fn app_unlock_se_over_socket(
    c: &mut envcloak_ipc::Client,
    unlocker_id_str: &str,
    unlock_sk: &[u8; 32],
) -> envcloak_ipc::view::UnlockedView {
    let begin = c.app_unlock_begin(Some(unlocker_id_str), &[]).unwrap();
    let sealed = perform_app_hpke_reseal(unlock_sk, &begin);
    c.app_unlock(&begin.request_id, &hex_encode(&sealed), &[])
        .unwrap()
}

fn sign_write(approve_sk: &[u8; 32], stmt: &WriteStatement) -> (String, String) {
    let digest = write_statement_digest(stmt);
    let sig = sign_p256_prehash(approve_sk, &digest).unwrap();
    (hex_encode(&digest), hex_encode(&sig))
}

#[test]
fn role_and_agent_evidence_guards_on_app_audit_list_and_app_lock() {
    common::terminal_session();
    let home = TestHome::new();
    let cs = canaries(fresh_seed());
    let (_vault_id, _kit_id, _all_cs) = seed_vault_with_kit(&home, &cs);

    // 1. A client-role peer (forged/mismatched APP_IDENTITY pid) is refused
    //    both `app.audit.list` and `app.lock` with `role_denied`, and both
    //    refusals are audited.
    let forged_pid = std::process::id().saturating_add(99_999);
    let forged_id = format!("{forged_pid}:{TEST_TEAM_ID}:{TEST_SIGNING_ID}");
    let d_forged = start_daemon(&home, Some(&forged_id), None);
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();

    let (kind, _) = rpc_kind(
        c.app_audit_list(&AppAuditListParams::default())
            .unwrap_err(),
    );
    assert_eq!(kind, ErrorKind::RoleDenied);

    let (kind, _) = rpc_kind(c.app_lock(AppLockReason::User, &[]).unwrap_err());
    assert_eq!(kind, ErrorKind::RoleDenied);
    assert_eq!(c.status().unwrap().vault.state, VaultState::Unlocked);
    let log = d_forged.log();
    for m in ["app.audit.list", "app.lock"] {
        assert!(
            log.contains(&format!(
                "audit: denied method={m} reason=role_denied role=client pid="
            )),
            "missing role_denied audit for {m}: {log}"
        );
    }
    drop(c);
    drop(d_forged);

    // 2. Restart with this process admitted as the `app` peer.
    let app_id = this_process_app_id();
    let d_app = start_daemon(&home, Some(&app_id), None);
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();

    // 3. An `app` peer carrying agent evidence (`claims: ["CURSOR_AGENT"]`) is
    //    refused `app.audit.list` with `proof_refused` (audited), but is
    //    allowed to call `app.lock` (`D3-11`: locking is always safe).
    let (kind, _) = rpc_kind(
        c.app_audit_list(&AppAuditListParams {
            claims: vec!["CURSOR_AGENT".into()],
            ..AppAuditListParams::default()
        })
        .unwrap_err(),
    );
    assert_eq!(kind, ErrorKind::ProofRefused);

    let app_log = d_app.log();
    assert!(
        app_log.contains("audit: proof refused method=app.audit.list reason=agent pid="),
        "missing proof_refused audit for app.audit.list: {app_log}"
    );

    let agent_claims = vec!["CURSOR_AGENT".to_owned()];
    let locked = c
        .app_lock(AppLockReason::ScreenLock, &agent_claims)
        .unwrap();
    assert!(locked.was_unlocked);

    let st = c.status().unwrap();
    assert_eq!(st.vault.state, VaultState::Locked);
    assert_eq!(st.lock.last_reason, Some(LockReason::ScreenLock));

    drop(c);
    drop(d_app);
}

#[test]
fn app_audit_list_pagination_filters_validation_and_canary_sweep() {
    common::terminal_session();
    let home = TestHome::new();
    let cs = canaries(fresh_seed());
    let (_vault_id, _kit_id, all_cs) = seed_vault_with_kit(&home, &cs);
    let manifest = project(&home, "acme-web", MANIFEST);
    let manifest_str = manifest.to_str().unwrap().to_owned();
    let app_id = this_process_app_id();

    let d = start_daemon(&home, Some(&app_id), None);
    let mut c = client(&home);

    // Locked vault refuses `app.audit.list` with `vault_locked`.
    let (kind, _) = rpc_kind(
        c.app_audit_list(&AppAuditListParams::default())
            .unwrap_err(),
    );
    assert_eq!(kind, ErrorKind::VaultLocked);

    c.unlock(passphrase(&cs), &[]).unwrap();

    // Parameter validation: limit 0, limit > 200, and unknown kind return `invalid_params`.
    for bad in [
        AppAuditListParams {
            limit: Some(0),
            ..AppAuditListParams::default()
        },
        AppAuditListParams {
            limit: Some(201),
            ..AppAuditListParams::default()
        },
        AppAuditListParams {
            kinds: vec!["not_a_real_audit_kind".into()],
            ..AppAuditListParams::default()
        },
    ] {
        let (kind, _) = rpc_kind(c.app_audit_list(&bad).unwrap_err());
        assert_eq!(kind, ErrorKind::InvalidParams);
    }

    // Generate a variety of audit entries: human run request + approval, agent
    // run request with inline canary in argv, and item rotation.
    let inline_canary = String::from_utf8_lossy(by_label(&cs, labels::OPENAI_API_KEY).value());
    let req = c
        .run_request(&RunRequestParams {
            manifest: manifest_str.clone(),
            profile: None,
            refs: Vec::new(),
            env_file: None,
            argv: vec!["./emit".into(), format!("INLINE={inline_canary}")],
            claims: Vec::new(),
            launch: None,
            bridge: None,
            fds: Vec::new(),
        })
        .unwrap();
    let request_id = match req.decision {
        DecisionView::Pending { request } => request,
        other => panic!("expected Pending, got {other:?}"),
    };
    let desc = c.pending_get(&request_id, &[]).unwrap();
    let opts = ApprovalOptions::once(DEFAULT_TTL);
    let digest = statement_digest(&desc, &opts);
    c.approve(&request_id, opts, &digest, passphrase(&cs), &[])
        .unwrap();

    let rotating = c.items_target(SLUGS[0], None, &[]).unwrap();
    c.items_rotate(
        &rotating,
        SecretBytes::copy_from(by_label(&cs, labels::OPENAI_API_KEY_ROTATED).value()),
        passphrase(&cs),
        &[],
    )
    .unwrap();

    // Agent run request so the audit log also carries an entry with `subject.agent`.
    let _agent_req = c
        .run_request(&RunRequestParams {
            manifest: manifest_str,
            profile: None,
            refs: Vec::new(),
            env_file: None,
            argv: vec!["./agent-emit".into(), format!("INLINE={inline_canary}")],
            claims: vec!["CURSOR_AGENT".into()],
            launch: None,
            bridge: None,
            fds: Vec::new(),
        })
        .unwrap();

    // Fetch all entries in one page and check reverse sequence order.
    let all = c.app_audit_list(&AppAuditListParams::default()).unwrap();
    assert!(
        all.entries.len() >= 4,
        "expected >= 4 entries, got {:?}",
        all.entries
    );
    assert_eq!(all.next_before_seq, None);
    for pair in all.entries.windows(2) {
        assert!(
            pair[0].seq > pair[1].seq,
            "entries must be in strictly descending seq order: {:?}",
            all.entries
        );
    }

    // Walk all entries 2 at a time using `before_seq` / `next_before_seq`.
    let mut paged = Vec::new();
    let mut cursor = None;
    loop {
        let page = c
            .app_audit_list(&AppAuditListParams {
                before_seq: cursor,
                limit: Some(2),
                ..AppAuditListParams::default()
            })
            .unwrap();
        assert!(page.entries.len() <= 2);
        paged.extend(page.entries);
        match page.next_before_seq {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(
        paged.iter().map(|e| e.seq).collect::<Vec<_>>(),
        all.entries.iter().map(|e| e.seq).collect::<Vec<_>>()
    );

    // Filter by `project`.
    let canonical_proj = std::fs::canonicalize(manifest.parent().unwrap())
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let by_proj = c
        .app_audit_list(&AppAuditListParams {
            project: Some(canonical_proj.clone()),
            ..AppAuditListParams::default()
        })
        .unwrap();
    assert!(!by_proj.entries.is_empty());
    assert!(
        by_proj
            .entries
            .iter()
            .all(|e| e.project_dir.as_deref() == Some(canonical_proj.as_str()))
    );

    // Filter by `item`.
    let by_item = c
        .app_audit_list(&AppAuditListParams {
            item: Some(SLUGS[0].into()),
            ..AppAuditListParams::default()
        })
        .unwrap();
    assert!(!by_item.entries.is_empty());
    assert!(
        by_item
            .entries
            .iter()
            .all(|e| e.slugs.iter().any(|s| s == SLUGS[0]))
    );

    // Filter by `agent`.
    let agent_name = all
        .entries
        .iter()
        .find_map(|e| e.subject.as_ref().and_then(|s| s.agent.clone()))
        .expect("expected an entry with an agent label");
    let by_agent = c
        .app_audit_list(&AppAuditListParams {
            agent: Some(agent_name.clone()),
            ..AppAuditListParams::default()
        })
        .unwrap();
    assert!(!by_agent.entries.is_empty());
    assert!(by_agent.entries.iter().all(|e| {
        e.subject.as_ref().and_then(|s| s.agent.as_deref()) == Some(agent_name.as_str())
    }));

    // Filter by `kinds`.
    let by_kinds = c
        .app_audit_list(&AppAuditListParams {
            kinds: vec!["rotate".into(), "approve".into()],
            ..AppAuditListParams::default()
        })
        .unwrap();
    assert_eq!(by_kinds.entries.len(), 2);
    assert!(
        by_kinds
            .entries
            .iter()
            .all(|e| e.kind == "rotate" || e.kind == "approve")
    );

    // Canary sweep across the entire serialized response (including `argv_masked`).
    let json_bytes = serde_json::to_vec(&all).unwrap();
    assert_no_canary(&json_bytes, &all_cs);
    for c_item in &all_cs {
        for (enc_name, enc_bytes) in encodings(c_item) {
            assert!(
                !json_bytes
                    .windows(enc_bytes.len())
                    .any(|w| w == enc_bytes.as_slice()),
                "canary {} ({enc_name:?}) leaked in app.audit.list JSON",
                c_item.label
            );
        }
    }

    drop(c);
    drop(d);
}

#[test]
fn app_lock_reasons_anchor_sync_and_grant_pending_wipe() {
    common::terminal_session();
    let home = TestHome::new();
    let cs = canaries(fresh_seed());
    let (_vault_id, _kit_id, _all_cs) = seed_vault_with_kit(&home, &cs);
    let manifest = project(&home, "acme-web", MANIFEST);
    let manifest_str = manifest.to_str().unwrap().to_owned();
    let app_id = this_process_app_id();
    let anchor_file = home.root().join("anchor.bin");

    let d = start_daemon(&home, Some(&app_id), Some(&anchor_file));
    let mut c = client(&home);

    c.unlock(passphrase(&cs), &[]).unwrap();
    let anchor_after_unlock = read_anchor_file(&anchor_file);

    // Create a pending request and approve a session grant so we can verify
    // `app.lock` clears grants and pending requests and updates the anchor's
    // `audit_seq` at lock.
    let req = c
        .run_request(&RunRequestParams {
            manifest: manifest_str.clone(),
            profile: None,
            refs: Vec::new(),
            env_file: None,
            argv: vec!["./emit".into()],
            claims: Vec::new(),
            launch: None,
            bridge: None,
            fds: Vec::new(),
        })
        .unwrap();
    let request_id = match req.decision {
        DecisionView::Pending { request } => request,
        other => panic!("expected Pending, got {other:?}"),
    };
    let desc = c.pending_get(&request_id, &[]).unwrap();
    let opts = ApprovalOptions::session(Duration::from_secs(600));
    let digest = statement_digest(&desc, &opts);
    c.approve(&request_id, opts, &digest, passphrase(&cs), &[])
        .unwrap();
    assert_eq!(c.grants_list().unwrap().grants.len(), 1);

    // Also leave a second pending request open before locking.
    let req2 = c
        .run_request(&RunRequestParams {
            manifest: manifest_str,
            profile: None,
            refs: vec!["GITHUB_TOKEN=github/acme-web".into()],
            env_file: None,
            argv: vec!["./other".into()],
            claims: Vec::new(),
            launch: None,
            bridge: None,
            fds: Vec::new(),
        })
        .unwrap();
    assert!(matches!(req2.decision, DecisionView::Pending { .. }));
    assert_eq!(c.pending_list(&[]).unwrap().requests.len(), 1);

    // 1. `app.lock` with `screen_lock`.
    let locked = c.app_lock(AppLockReason::ScreenLock, &[]).unwrap();
    assert!(locked.was_unlocked);
    let locked_again = c.app_lock(AppLockReason::ScreenLock, &[]).unwrap();
    assert!(!locked_again.was_unlocked);

    let st = c.status().unwrap();
    assert_eq!(st.vault.state, VaultState::Locked);
    assert_eq!(st.lock.last_reason, Some(LockReason::ScreenLock));
    assert_eq!(st.approvals.grants, 0);
    assert_eq!(st.approvals.pending, 0);

    let anchor_after_screen_lock = read_anchor_file(&anchor_file);
    assert!(
        anchor_after_screen_lock.audit_seq > anchor_after_unlock.audit_seq,
        "app.lock must update the rollback anchor's audit_seq before dropping the vault"
    );

    // 2. Unlock and `app.lock` with `session_resign`.
    c.unlock(passphrase(&cs), &[]).unwrap();
    assert!(c.grants_list().unwrap().grants.is_empty());
    assert!(c.pending_list(&[]).unwrap().requests.is_empty());
    let locked = c.app_lock(AppLockReason::SessionResign, &[]).unwrap();
    assert!(locked.was_unlocked);
    assert_eq!(
        c.status().unwrap().lock.last_reason,
        Some(LockReason::SessionResign)
    );

    // 3. Unlock and `app.lock` with `user` (`LockReason::Request`).
    c.unlock(passphrase(&cs), &[]).unwrap();
    let locked = c.app_lock(AppLockReason::User, &[]).unwrap();
    assert!(locked.was_unlocked);
    assert_eq!(
        c.status().unwrap().lock.last_reason,
        Some(LockReason::Request)
    );

    // 4. Unlock and verify the three `lock` audit entries carry the expected reasons.
    c.unlock(passphrase(&cs), &[]).unwrap();
    let locks = c
        .app_audit_list(&AppAuditListParams {
            kinds: vec!["lock".into()],
            ..AppAuditListParams::default()
        })
        .unwrap();
    let reasons: Vec<Option<&str>> = locks
        .entries
        .iter()
        .take(3)
        .map(|e| e.reason.as_deref())
        .collect();
    assert_eq!(
        reasons,
        vec![Some("request"), Some("session_resign"), Some("screen_lock")]
    );

    drop(c);
    drop(d);
}

#[test]
fn rollback_after_items_remove_and_app_items_remove_marks_vault_tampered() {
    common::terminal_session();
    let home = TestHome::new();
    let cs = canaries(fresh_seed());
    let (vault_id, _kit_id, _all_cs) = seed_vault_with_kit(&home, &cs);
    let manifest = project(&home, "acme-web", MANIFEST);
    let manifest_str = manifest.to_str().unwrap().to_owned();
    let app_id = this_process_app_id();
    let anchor_file = home.root().join("anchor.bin");
    let vault_dir = VaultPaths::under(data_dir(&home)).vault_dir;
    let snapshot_dir = home.root().join("vault-snapshot");

    // First verify that without `ENVCLOAK_TEST_ANCHOR_FILE` on an unsigned
    // build, `status.vault.keychain_anchor` reports `Unavailable`.
    let d_no_anchor = start_daemon(&home, Some(&app_id), None);
    let mut c = client(&home);
    assert_eq!(
        c.status().unwrap().vault.keychain_anchor,
        KeychainAnchorState::Unavailable
    );
    c.unlock(passphrase(&cs), &[]).unwrap();
    assert_eq!(
        c.status().unwrap().vault.keychain_anchor,
        KeychainAnchorState::Unavailable
    );
    drop(c);
    drop(d_no_anchor);

    // Start the daemon with `ENVCLOAK_TEST_ANCHOR_FILE`. Because `seed_vault_with_kit`
    // wrote items offline (`write_counter > 1`) with no keychain anchor yet,
    // the first unlock detects `KeychainAnchorState::Missing` (`F-M3-16-01`),
    // re-creates the anchor file, and after lock+unlock reports `Matched`.
    let d = start_daemon(&home, Some(&app_id), Some(&anchor_file));
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();
    assert_eq!(
        c.status().unwrap().vault.keychain_anchor,
        KeychainAnchorState::Missing
    );
    let a0 = read_anchor_file(&anchor_file);
    assert_eq!(a0.vault_id, vault_id);
    c.lock().unwrap();
    c.unlock(passphrase(&cs), &[]).unwrap();
    assert_eq!(
        c.status().unwrap().vault.keychain_anchor,
        KeychainAnchorState::Matched
    );
    let a0 = read_anchor_file(&anchor_file);

    // Enroll a Secure Enclave unlocker so we can test both `app.items.remove`
    // and `app.unlock` rollback detection.
    let (unlock_sk, unlock_pub, approve_sk, approve_pub) = sample_se_keypairs(0x41);
    let se_unlocker_id = enroll_se_over_socket(&mut c, &cs, &unlock_pub, &approve_pub, "Touch ID");
    let a_after_enroll = read_anchor_file(&anchor_file);
    assert!(a_after_enroll.write_counter > a0.write_counter);
    assert!(a_after_enroll.audit_seq > a0.audit_seq);

    // Verify `grants.revoke` immediately advances the keychain anchor's `audit_seq` (`F-M3-16-03`).
    c.grants_revoke(None).unwrap();
    let a_after_revoke = read_anchor_file(&anchor_file);
    assert!(
        a_after_revoke.audit_seq > a_after_enroll.audit_seq,
        "grants.revoke must immediately advance the keychain anchor audit_seq"
    );

    // Add a temporary item and verify the anchor advances.
    c.items_add(&AddParams {
        slug: Some("temp/cli-item".into()),
        provider: None,
        field: None,
        account: None,
        env_hint: None,
        allow_short: false,
        value: WireSecret::new(SecretBytes::copy_from(
            by_label(&cs, labels::OPENAI_API_KEY_ROTATED).value(),
        )),
        claims: Vec::new(),
    })
    .unwrap();
    let a_after_add = read_anchor_file(&anchor_file);
    assert!(a_after_add.write_counter > a_after_revoke.write_counter);

    // Snapshot `vault.db` (and its WAL files) before `items.remove`, then
    // remove `temp/cli-item`. Drop the daemon without calling `lock` so that
    // the only anchor update after the snapshot is `items.remove` itself
    // (exercising Mutation 2).
    snapshot_vault_db(&vault_dir, &snapshot_dir);
    let rm_target_cli = c.items_target("temp/cli-item", None, &[]).unwrap();
    c.items_remove(&rm_target_cli, passphrase(&cs), &[])
        .unwrap();
    let a_after_cli_remove = read_anchor_file(&anchor_file);
    assert!(
        a_after_cli_remove.write_counter > a_after_add.write_counter,
        "items.remove must update the keychain rollback anchor immediately"
    );
    assert!(
        a_after_cli_remove.audit_seq > a_after_add.audit_seq,
        "items.remove must immediately anchor its Removed audit_seq"
    );
    drop(c);
    drop(d);

    // Restore the pre-remove `vault.db` snapshot while keeping the anchor from
    // `items.remove`, then restart and unlock with the passphrase.
    restore_vault_db(&snapshot_dir, &vault_dir);
    let d = start_daemon(&home, Some(&app_id), Some(&anchor_file));
    let mut c = client(&home);
    let unlocked = c.unlock(passphrase(&cs), &[]).unwrap();
    assert_eq!(unlocked.integrity, Integrity::Tampered);
    assert!(unlocked.read_only);

    let st = c.status().unwrap();
    assert_eq!(st.vault.keychain_anchor, KeychainAnchorState::Ahead);
    assert_eq!(st.vault.integrity, Some(Integrity::Tampered));

    // Verify `keychain_anchor_mismatch` (`outcome = "tampered"`,
    // `reason = "rolled_back"`) was recorded and `app.audit.list` still works
    // on the read-only tampered vault.
    let mismatch_page = c
        .app_audit_list(&AppAuditListParams {
            kinds: vec!["keychain_anchor_mismatch".into()],
            ..AppAuditListParams::default()
        })
        .unwrap();
    assert!(
        mismatch_page
            .entries
            .iter()
            .any(|e| e.outcome == "tampered" && e.reason.as_deref() == Some("rolled_back")),
        "expected tampered/rolled_back entry, got {:?}",
        mismatch_page.entries
    );

    // Grants (`run.request`) and writes (`items.add`) are refused with
    // `vault_tampered` and `reason = Some("rolled_back")`.
    let (kind, reason) = rpc_kind(
        c.run_request(&RunRequestParams {
            manifest: manifest_str,
            profile: None,
            refs: Vec::new(),
            env_file: None,
            argv: vec!["./emit".into()],
            claims: Vec::new(),
            launch: None,
            bridge: None,
            fds: Vec::new(),
        })
        .unwrap_err(),
    );
    assert_eq!(kind, ErrorKind::VaultTampered);
    assert_eq!(reason, Some("rolled_back"));

    let (kind, reason) = rpc_kind(
        c.items_add(&AddParams {
            slug: Some("another/item".into()),
            provider: None,
            field: None,
            account: None,
            env_hint: None,
            allow_short: false,
            value: WireSecret::new(SecretBytes::copy_from(
                by_label(&cs, labels::OPENAI_API_KEY_ROTATED).value(),
            )),
            claims: Vec::new(),
        })
        .unwrap_err(),
    );
    assert_eq!(kind, ErrorKind::VaultTampered);
    assert_eq!(reason, Some("rolled_back"));

    drop(c);
    drop(d);

    // Now test `app.items.remove` anchor update + `app.unlock` rollback
    // detection AND missing-anchor recreation:
    // Delete the anchor file on this already-anchored vault (`se_unlockers` is
    // non-empty), so the next unlock reports `KeychainAnchorState::Missing`,
    // re-creates the anchor file, and writes `keychain_anchor_mismatch`
    // (`outcome = "recreated"`, `reason = "keychain_anchor_missing"`).
    std::fs::remove_file(&anchor_file).unwrap();
    let d = start_daemon(&home, Some(&app_id), Some(&anchor_file));
    let mut c = client(&home);
    let unlocked = app_unlock_se_over_socket(&mut c, &se_unlocker_id, &unlock_sk);
    assert_eq!(unlocked.integrity, Integrity::Ok);
    assert!(!unlocked.read_only);
    assert_eq!(
        c.status().unwrap().vault.keychain_anchor,
        KeychainAnchorState::Missing
    );
    assert!(
        anchor_file.exists(),
        "missing anchor must be re-created in the keychain at unlock"
    );
    let recreated_page = c
        .app_audit_list(&AppAuditListParams {
            kinds: vec!["keychain_anchor_mismatch".into()],
            ..AppAuditListParams::default()
        })
        .unwrap();
    assert!(
        recreated_page.entries.iter().any(|e| {
            e.outcome == "recreated" && e.reason.as_deref() == Some("keychain_anchor_missing")
        }),
        "expected recreated keychain_anchor_mismatch entry, got {:?}",
        recreated_page.entries
    );

    // Also verify `app.items.rotate` updates the anchor, while preserving
    // `KeychainAnchorState::Missing` until the next lock/unlock cycle (`F-M3-16-01`).
    let a_before_rotate = read_anchor_file(&anchor_file);
    let t_rot = c.app_items_target(SLUGS[0], None, &[]).unwrap();
    let rot_secret = SecretBytes::copy_from(by_label(&cs, labels::OPENAI_API_KEY_ROTATED).value());
    let rot_sha = hex_encode(&secret_sha256(&rot_secret));
    let daemon_pub: [u8; 32] = decode_hex(&t_rot.daemon_eph_pub);
    let nonce: [u8; 32] = decode_hex(&t_rot.nonce);
    let aad = se_reseal_aad(&t_rot.target, &nonce);
    let sealed_rot = hex_encode(&seal_secret_to_x25519(&daemon_pub, &aad, &rot_secret).unwrap());
    let rot_stmt = WriteStatement {
        target: t_rot.target.clone(),
        nonce: t_rot.nonce.clone(),
        vault_id: t_rot.vault_id.clone(),
        action: WriteAction::Rotate {
            item: t_rot.item.clone(),
            slug: t_rot.slug.clone(),
            field: t_rot.field.clone().unwrap(),
            field_name: t_rot.field_name.clone().unwrap(),
            classification: t_rot.classification.as_str().to_owned(),
            prior_count: t_rot.prior_count,
            grants: t_rot.grants,
            new_value_sha256: rot_sha,
        },
    };
    let (rot_digest, rot_sig) = sign_write(&approve_sk, &rot_stmt);
    c.app_items_rotate(&AppItemsRotateParams {
        target: t_rot.target,
        sealed_value: sealed_rot,
        digest: rot_digest,
        signature: rot_sig,
        claims: Vec::new(),
    })
    .unwrap();
    let a_after_rotate = read_anchor_file(&anchor_file);
    assert!(a_after_rotate.write_counter > a_before_rotate.write_counter);
    assert_eq!(
        c.status().unwrap().vault.keychain_anchor,
        KeychainAnchorState::Missing,
        "KeychainAnchorState::Missing must persist until the next lock/unlock cycle"
    );

    // Snapshot `vault.db` before `app.items.remove`, then remove `temp/cli-item`
    // via `app.items.remove` without calling `lock` before dropping the daemon.
    snapshot_vault_db(&vault_dir, &snapshot_dir);
    let r_rm = c.app_items_target("temp/cli-item", None, &[]).unwrap();
    let rm_stmt = WriteStatement {
        target: r_rm.target.clone(),
        nonce: r_rm.nonce.clone(),
        vault_id: r_rm.vault_id.clone(),
        action: WriteAction::Remove {
            item: r_rm.item.clone(),
            slug: r_rm.slug.clone(),
            grants: r_rm.grants,
        },
    };
    let (rm_digest, rm_sig) = sign_write(&approve_sk, &rm_stmt);
    c.app_items_remove(&AppItemsRemoveParams {
        target: r_rm.target,
        digest: rm_digest,
        signature: rm_sig,
        claims: Vec::new(),
    })
    .unwrap();
    let a_after_app_remove = read_anchor_file(&anchor_file);
    assert!(
        a_after_app_remove.write_counter > a_after_rotate.write_counter,
        "app.items.remove must update the keychain rollback anchor immediately"
    );
    assert!(
        a_after_app_remove.audit_seq > a_after_rotate.audit_seq,
        "app.items.remove must immediately anchor its Removed audit_seq"
    );
    drop(c);
    drop(d);

    // Restore the pre-`app.items.remove` snapshot and unlock via `app.unlock`:
    // the vault must open read-only with `Integrity::Tampered` and
    // `KeychainAnchorState::Ahead`.
    restore_vault_db(&snapshot_dir, &vault_dir);
    let d = start_daemon(&home, Some(&app_id), Some(&anchor_file));
    let mut c = client(&home);
    let unlocked = app_unlock_se_over_socket(&mut c, &se_unlocker_id, &unlock_sk);
    assert_eq!(unlocked.integrity, Integrity::Tampered);
    assert!(unlocked.read_only);
    assert_eq!(
        c.status().unwrap().vault.keychain_anchor,
        KeychainAnchorState::Ahead
    );

    let (kind, reason) = rpc_kind(c.app_items_target(SLUGS[0], None, &[]).unwrap_err());
    assert_eq!(kind, ErrorKind::VaultTampered);
    assert_eq!(reason, Some("rolled_back"));

    drop(c);
    drop(d);

    // Also verify `vault.create` transitions `status.vault.keychain_anchor`
    // from `None` to `Matched`, and that equal `write_counter` with altered
    // `state_digest`, higher `epoch`, higher `audit_seq`, a different
    // `vault_id`, or a corrupt/wrong-length record in the anchor file each
    // trigger `Tampered` / `Ahead` / `rolled_back` (`F-M3-16-02`).
    let fresh_home = TestHome::new();
    let fresh_anchor_file = fresh_home.root().join("fresh-anchor.bin");
    let d_fresh = start_daemon(&fresh_home, Some(&app_id), Some(&fresh_anchor_file));
    let mut c_fresh = client(&fresh_home);
    assert_eq!(
        c_fresh.status().unwrap().vault.keychain_anchor,
        KeychainAnchorState::None
    );
    let fresh_kit = RecoveryKit::generate();
    let created = c_fresh
        .vault_create(
            passphrase(&cs),
            SecretBytes::copy_from(fresh_kit.to_display().as_bytes()),
            Some(KdfParams::minimum().m_kib()),
        )
        .unwrap();
    let _ = created;
    assert_eq!(
        c_fresh.status().unwrap().vault.keychain_anchor,
        KeychainAnchorState::Matched
    );
    c_fresh.lock().unwrap();
    let base_anchor = read_anchor_file(&fresh_anchor_file);

    for mutated in [
        Anchor {
            state_digest: [0xEE; 32],
            ..base_anchor
        },
        Anchor {
            epoch: base_anchor.epoch + 1,
            ..base_anchor
        },
        Anchor {
            audit_seq: base_anchor.audit_seq + 1,
            ..base_anchor
        },
        Anchor {
            vault_id: VaultId([0x99; 16]),
            ..base_anchor
        },
    ] {
        let line = format!(
            "{}:{}\n",
            hex_encode(&base_anchor.vault_id.0),
            hex_encode(&mutated.encode()),
        );
        std::fs::write(&fresh_anchor_file, line).unwrap();
        let unlocked = c_fresh.unlock(passphrase(&cs), &[]).unwrap();
        assert_eq!(unlocked.integrity, Integrity::Tampered);
        assert!(unlocked.read_only);
        assert_eq!(
            c_fresh.status().unwrap().vault.keychain_anchor,
            KeychainAnchorState::Ahead
        );
        c_fresh.lock().unwrap();
    }

    // Corrupt (wrong-length) keychain anchor record must also fail closed into
    // `Integrity::Tampered` / `KeychainAnchorState::Ahead` without overwriting
    // the corrupt anchor (`F-M3-16-02`).
    let corrupt_line = format!("{}:deadbeef\n", hex_encode(&base_anchor.vault_id.0));
    std::fs::write(&fresh_anchor_file, &corrupt_line).unwrap();
    let unlocked = c_fresh.unlock(passphrase(&cs), &[]).unwrap();
    assert_eq!(unlocked.integrity, Integrity::Tampered);
    assert!(unlocked.read_only);
    assert_eq!(
        c_fresh.status().unwrap().vault.keychain_anchor,
        KeychainAnchorState::Ahead
    );
    assert_eq!(
        std::fs::read_to_string(&fresh_anchor_file).unwrap(),
        corrupt_line,
        "corrupt keychain anchor must not be overwritten by unlock"
    );

    drop(c_fresh);
    drop(d_fresh);
}
