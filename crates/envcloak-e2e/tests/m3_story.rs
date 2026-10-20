//! The M3 macOS app & Secure Enclave acceptance story (SPEC §15.2, §4.3,
//! §4.4, §5, §6.3, §6.7, §10b, §10c; M3 plan task M3-21, steps A1..A20),
//! end to end through the built `envcloak` and `envcloakd` binaries.
//!
//! After every step, everything any process printed, every daemon's log,
//! every recorded wire frame, and the whole test home are swept for every
//! canary across all §6.1 encodings and every serializer's output.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use envcloak_core::SecretBytes;
use envcloak_core::crypto::{
    P256_PUBLIC_KEY_LEN, SE_CHALLENGE_LEN, SE_HPKE_CIPHERTEXT_LEN, SE_HPKE_ENC_LEN, SeEphemeralKey,
    SeHpkeEnvelope, UnlockerId, VaultId, derive_p256_keypair, open_se_envelope, se_reseal_aad,
    se_reveal_aad, seal_secret_to_x25519, seal_vmk_to_daemon, secret_sha256, sign_p256_prehash,
};
use envcloak_e2e::{Harness, RECOVERY_KIT, age, sha256_hex, text, token, write_script};
use envcloak_ipc::app::{
    AppAuditListParams, AppItemsRemoveParams, AppItemsRotateParams, AppLockReason, AppPasteParams,
    AppRevealBeginParams, AppRevealParams, AppUnlockerEnrollOutput,
};
use envcloak_ipc::proto::{AskParams, ErrorKind, PendingGetOutput};
use envcloak_ipc::view::{
    AddedView, ClassificationView, KeychainAnchorState, LengthClass, LockReason, VaultState,
};
use envcloak_ipc::{Client, ClientError, RunPaths};
use envcloak_policy::{
    ApprovalOptions, AskStateOutcome, DEFAULT_TTL, EnvName, Uses, WriteAction, WriteStatement,
    reveal_statement_digest, statement_digest, unlocker_statement_digest, write_statement_digest,
};
use envcloak_testkit::{Canary, daemon_run_dir, fresh_seed, labels};
use serde_json::json;

const TEST_TEAM_ID: &str = "AB12CD34EF";
const TEST_SIGNING_ID: &str = "ai.envcloak.app";
const CHILD_ROLE_DENIED_ENV: &str = "ENVCLOAK_TEST_M321_CHILD_ROLE_DENIED";

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

fn decode_hex_vec(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn rpc_kind(e: ClientError) -> (ErrorKind, Option<&'static str>) {
    match e {
        ClientError::Rpc(r) => (r.kind, r.reason),
        other => panic!("expected an RPC error, got {other:?}"),
    }
}

fn stripe_key(kind: &str) -> String {
    let seed = fresh_seed();
    let tail: String = (0..32u32)
        .map(|i| {
            let n = u8::try_from((seed.rotate_left(7 * i) ^ (u64::from(i) * 0x9e37)) % 36).unwrap();
            char::from(if n < 10 { b'0' + n } else { b'a' + n - 10 })
        })
        .collect();
    format!("{}_{kind}_{tail}", concat!("s", "k"))
}

#[track_caller]
fn request_id(o: &std::process::Output) -> String {
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(token(&o.stderr), "approval_required", "{}", text(o));
    err.split("request=")
        .nth(1)
        .and_then(|r| r.get(..8))
        .unwrap_or_else(|| panic!("no request id: {err}"))
        .to_owned()
}

fn app_client(h: &Harness) -> Client {
    let paths = RunPaths::under(daemon_run_dir(&h.home)).unwrap();
    Client::connect(&paths).unwrap()
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

fn paste_secret(
    c: &mut Client,
    secret: &SecretBytes,
    slug: &str,
    provider: Option<&str>,
    env_hint: Option<&str>,
    ask: Option<&str>,
) -> AddedView {
    let stage = c.app_paste_begin(&[]).unwrap();
    let sealed = seal_secret_to_x25519(
        &decode_hex(&stage.daemon_eph_pub),
        stage.stage.as_bytes(),
        secret,
    )
    .unwrap();
    let inspected = c
        .app_paste_inspect(&stage.stage, &hex_encode(&sealed), &[])
        .unwrap();
    assert_eq!(inspected.length, LengthClass::Ok);
    c.app_paste(&AppPasteParams {
        stage: stage.stage,
        slug: Some(slug.to_owned()),
        provider: provider.map(str::to_owned),
        field: None,
        account: None,
        env_hint: env_hint.map(str::to_owned),
        allow_short: false,
        ask: ask.map(str::to_owned),
        claims: Vec::new(),
    })
    .unwrap()
}

fn unlock_with_se(c: &mut Client, vault_id: VaultId, unlocker_id: &str, unlock_sk: &[u8; 32]) {
    let begin = c.app_unlock_begin(Some(unlocker_id), &[]).unwrap();
    let vmk = open_se_envelope(
        unlock_sk,
        vault_id,
        UnlockerId(decode_hex(unlocker_id)),
        begin.epoch,
        &SeHpkeEnvelope {
            enc: decode_hex::<SE_HPKE_ENC_LEN>(&begin.envelope.enc),
            ciphertext: decode_hex::<SE_HPKE_CIPHERTEXT_LEN>(&begin.envelope.ciphertext),
        },
    )
    .unwrap();
    let challenge = decode_hex::<SE_CHALLENGE_LEN>(&begin.challenge);
    let daemon_pub: [u8; 32] = decode_hex(&begin.daemon_eph_pub);
    let sealed_vmk = seal_vmk_to_daemon(&daemon_pub, &begin.request_id, &challenge, &vmk).unwrap();
    let unlocked = c
        .app_unlock(&begin.request_id, &hex_encode(&sealed_vmk), &[])
        .unwrap();
    assert!(!unlocked.already);
}

#[test]
fn child_client_role_denied_probe() {
    let Some(sock_path) = std::env::var_os(CHILD_ROLE_DENIED_ENV) else {
        return;
    };
    let mut stream = UnixStream::connect(sock_path).unwrap();
    let req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "app.paste.begin",
        "params": {"claims": []}
    });
    let payload = serde_json::to_vec(&req).unwrap();
    let len = u32::try_from(payload.len()).unwrap().to_be_bytes();
    stream.write_all(&len).unwrap();
    stream.write_all(&payload).unwrap();
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).unwrap();
    let rlen = u32::from_be_bytes(hdr) as usize;
    let mut body = vec![0u8; rlen];
    stream.read_exact(&mut body).unwrap();
    let resp: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp["error"]["data"]["kind"].as_str(), Some("role_denied"));
    println!("@@ client_role_denied_ok");
}

#[test]
fn m3_acceptance_story_a1_to_a20() {
    envcloak_sys::testing::enter_terminal_session().unwrap();
    let app_id = format!("{}:{TEST_TEAM_ID}:{TEST_SIGNING_ID}", std::process::id());
    let anchor_dir = tempfile::Builder::new()
        .prefix("eca")
        .tempdir_in("/tmp")
        .unwrap();
    let anchor_file = anchor_dir.path().join("anchor.txt");
    let mut h = Harness::start_with(&[
        (envcloak_sys::testing::APP_IDENTITY, &app_id),
        (
            envcloak_sys::testing::ANCHOR_FILE,
            anchor_file.to_str().unwrap(),
        ),
    ]);

    let live_stripe_1 = stripe_key("live");
    h.add_canary(Canary::new("LIVE_STRIPE_1", live_stripe_1.clone()));
    let live_stripe_2 = stripe_key("live");
    h.add_canary(Canary::new("LIVE_STRIPE_2", live_stripe_2.clone()));
    let asked_stripe = stripe_key("test");
    h.add_canary(Canary::new("ASKED_STRIPE", asked_stripe.clone()));
    let scanned_stripe = stripe_key("test");
    h.add_canary(Canary::new("SCANNED_STRIPE", scanned_stripe.clone()));

    // -------------------------------------------------------------------------
    // A1 / A2: Connection states (`Absent` -> `vault create` -> `Unlocked`).
    // -------------------------------------------------------------------------
    let mut c = app_client(&h);
    assert_eq!(c.status().unwrap().vault.state, VaultState::Absent);

    let pass = h.secret_file(labels::VAULT_PASSPHRASE, true);
    let kit_path = h.files().join("recovery.kit");
    let home_dir = h.home.home();
    let created = h.human(
        &home_dir,
        &[
            "vault",
            "create",
            "--passphrase-fd",
            "3",
            "--kit-fd",
            "4",
            "--kdf-memory",
            "64MiB",
        ],
        &[(3, &pass, true), (4, &kit_path, false)],
        &[],
    );
    assert_eq!(created.code, 0, "{}", created.all());
    let kit_text = std::fs::read_to_string(&kit_path).unwrap();
    h.add_canary(Canary::new(RECOVERY_KIT, kit_text.trim_end().to_owned()));
    assert_eq!(c.status().unwrap().vault.state, VaultState::Unlocked);
    h.assert_swept("A2 vault created");

    // -------------------------------------------------------------------------
    // A3 / A4 / A5: Touch ID enrollment (`app.unlocker.enroll.begin` ->
    // `approve` -> `app.unlocker.enroll`), lock, and unlock with Touch ID.
    // -------------------------------------------------------------------------
    let (unlock_sk, unlock_pub): ([u8; 32], [u8; P256_PUBLIC_KEY_LEN]) =
        derive_p256_keypair(&[0x42; 32]);
    let (approve_sk, approve_pub): ([u8; 32], [u8; P256_PUBLIC_KEY_LEN]) =
        derive_p256_keypair(&[0x43; 32]);

    let begin_enroll = c
        .app_unlocker_enroll_begin(
            &hex_encode(&unlock_pub),
            &hex_encode(&approve_pub),
            "Touch ID",
            &[],
        )
        .unwrap();
    let PendingGetOutput::UnlockerAdd(enroll_desc) =
        c.pending_get_any(&begin_enroll.request, &[]).unwrap()
    else {
        panic!("expected unlocker_add descriptor");
    };
    let vault_id = VaultId(decode_hex(&enroll_desc.vault_id));
    let enroll_digest = unlocker_statement_digest(&enroll_desc);
    let pass_bytes = SecretBytes::copy_from(h.value(labels::VAULT_PASSPHRASE));
    c.approve(
        &begin_enroll.request,
        ApprovalOptions {
            uses: Uses::Once,
            ttl_secs: DEFAULT_TTL.as_secs(),
            live: Vec::new(),
            standing: None,
        },
        &enroll_digest,
        pass_bytes,
        &[],
    )
    .unwrap();
    let AppUnlockerEnrollOutput::Enrolled { unlocker_id } =
        c.app_unlocker_enroll(&begin_enroll.request, &[]).unwrap()
    else {
        panic!("expected Enrolled");
    };

    c.lock().unwrap();
    assert_eq!(c.status().unwrap().vault.state, VaultState::Locked);
    unlock_with_se(&mut c, vault_id, &unlocker_id, &unlock_sk);
    assert_eq!(c.status().unwrap().vault.state, VaultState::Unlocked);
    h.assert_swept("A5 unlocked with Touch ID");

    // -------------------------------------------------------------------------
    // A6 / A7: Sealed paste (`app.paste.begin` -> `app.paste.inspect` ->
    // `app.paste`) and project binding (`acme-web/envcloak.toml`).
    // -------------------------------------------------------------------------
    let openai_sec = SecretBytes::copy_from(h.value(labels::OPENAI_API_KEY));
    let github_sec = SecretBytes::copy_from(h.value(labels::GITHUB_TOKEN));
    let live_sec_1 = SecretBytes::copy_from(live_stripe_1.as_bytes());

    let p_openai = paste_secret(
        &mut c,
        &openai_sec,
        "openai/acme-web",
        Some("openai"),
        Some("OPENAI_API_KEY"),
        None,
    );
    assert_eq!(p_openai.item.slug, "openai/acme-web");

    let p_stripe = paste_secret(
        &mut c,
        &live_sec_1,
        "stripe/acme-live",
        Some("stripe"),
        Some("STRIPE_SECRET_KEY"),
        None,
    );
    assert_eq!(p_stripe.item.slug, "stripe/acme-live");
    assert_eq!(p_stripe.item.classification, ClassificationView::Live);

    let p_github = paste_secret(
        &mut c,
        &github_sec,
        "github/acme-web",
        Some("github"),
        Some("GITHUB_TOKEN"),
        None,
    );
    assert_eq!(p_github.item.slug, "github/acme-web");

    let repo = h.home.root().join("acme-web");
    std::fs::create_dir_all(&repo).unwrap();
    let manifest_body = "[project]\nname = \"acme-web\"\n\n[env]\nOPENAI_API_KEY = \"openai/acme-web\"\nSTRIPE_SECRET_KEY = \"stripe/acme-live\"\nGITHUB_TOKEN = \"github/acme-web\"\n\n[env.denytest]\nEXTRA_GITHUB_TOKEN = \"github/acme-web\"\n";
    std::fs::write(repo.join("envcloak.toml"), manifest_body).unwrap();
    write_script(
        &repo.join("emit"),
        "#!/bin/sh\nset -eu\npython3 -c 'import hashlib, os\nfor k in (\"OPENAI_API_KEY\", \"STRIPE_SECRET_KEY\", \"GITHUB_TOKEN\"):\n    v = os.environ.get(k, \"\").encode()\n    print(\"raw\", k, v.decode())\n    print(\"sha256\", k, hashlib.sha256(v).hexdigest())\n'\n",
    );
    h.assert_swept("A7 pasted and bound");

    // -------------------------------------------------------------------------
    // A8 / A9: Approval window, live-key confirmation tick, session grant
    // reuse, and 3-denial auto-deny cooldown.
    // -------------------------------------------------------------------------
    let run_pending = h.agent(&repo, &["run", "--", "./emit"]);
    let req_run = request_id(&run_pending);
    assert_eq!(c.status().unwrap().approvals.pending, 1);

    let desc_run = c.app_pending_get(&req_run, &[]).unwrap();
    assert_eq!(desc_run.request, req_run);

    // Omitting `live: ["STRIPE_SECRET_KEY"]` is rejected (`live_not_ticked`).
    let opts_missing_live = ApprovalOptions::session(Duration::from_secs(3600));
    let digest_missing_live = statement_digest(&desc_run, &opts_missing_live);
    let sig_missing_live =
        hex_encode(&sign_p256_prehash(&approve_sk, &digest_missing_live).unwrap());
    assert_eq!(
        rpc_kind(
            c.app_approve(
                &req_run,
                &opts_missing_live,
                &digest_missing_live,
                &sig_missing_live,
                &[]
            )
            .unwrap_err()
        )
        .0,
        ErrorKind::LiveNotTicked
    );

    // Confirming BOTH live keys (`OPENAI_API_KEY` and `STRIPE_SECRET_KEY`)
    // succeeds and creates a 1-hour session grant.
    let mut opts_live = ApprovalOptions::session(Duration::from_secs(3600));
    opts_live.live = vec![
        EnvName::new("GITHUB_TOKEN").unwrap(),
        EnvName::new("OPENAI_API_KEY").unwrap(),
        EnvName::new("STRIPE_SECRET_KEY").unwrap(),
    ];
    let digest_live = statement_digest(&desc_run, &opts_live);
    let sig_live = hex_encode(&sign_p256_prehash(&approve_sk, &digest_live).unwrap());
    let approved = c
        .app_approve(&req_run, &opts_live, &digest_live, &sig_live, &[])
        .unwrap();
    assert!(!approved.grant.is_empty());

    // Re-running in the same agent session succeeds immediately under the grant;
    // raw secret output is redacted while SHA-256 digests match the values.
    let run_ok = h.agent(&repo, &["run", "--", "./emit"]);
    assert_eq!(run_ok.status.code(), Some(0), "{}", text(&run_ok));
    let stdout_ok = String::from_utf8_lossy(&run_ok.stdout);
    assert!(
        stdout_ok.contains("[envcloak:stripe/acme-live]"),
        "{stdout_ok}"
    );
    assert!(stdout_ok.contains(&format!(
        "sha256 OPENAI_API_KEY {}",
        sha256_hex(h.value(labels::OPENAI_API_KEY))
    )));
    assert!(stdout_ok.contains(&format!(
        "sha256 STRIPE_SECRET_KEY {}",
        sha256_hex(live_stripe_1.as_bytes())
    )));

    // 3 consecutive denials on `(root, project)` trigger auto-deny on the 4th
    // even when argv differs.
    for i in 0..3 {
        let arg = i.to_string();
        let d_out = h.agent(
            &repo,
            &["run", "--profile", "denytest", "--", "./emit", &arg],
        );
        let d_req = request_id(&d_out);
        c.deny(&d_req).unwrap();
    }
    let fourth_out = h.agent(
        &repo,
        &["run", "--profile", "denytest", "--", "./emit", "3"],
    );
    assert_eq!(
        token(&fourth_out.stderr),
        "approval_denied",
        "{}",
        text(&fourth_out)
    );
    h.assert_swept("A9 approval and 3-denial auto-deny");

    // -------------------------------------------------------------------------
    // A10: Forged peer (`role_denied` from a client-role process) & agent
    // refusal (`proof_refused` when agent claims are sent).
    // -------------------------------------------------------------------------
    let child_out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_client_role_denied_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(
            CHILD_ROLE_DENIED_ENV,
            RunPaths::under(daemon_run_dir(&h.home)).unwrap().socket,
        )
        .output()
        .unwrap();
    assert!(
        child_out.status.success()
            && String::from_utf8_lossy(&child_out.stdout).contains("@@ client_role_denied_ok"),
        "child_client_role_denied_probe failed: {}",
        String::from_utf8_lossy(&child_out.stderr)
    );
    assert_eq!(
        rpc_kind(c.app_paste_begin(&["CURSOR_AGENT".to_owned()]).unwrap_err()).0,
        ErrorKind::ProofRefused
    );
    h.assert_swept("A10 forged peer and agent refusal");

    // -------------------------------------------------------------------------
    // A11: Replace (`app.items.target` -> `app.items.rotate`) & remove
    // (`app.items.target` -> `app.items.remove` with encrypted backup first).
    // -------------------------------------------------------------------------
    let target_rot = c.app_items_target("stripe/acme-live", None, &[]).unwrap();
    assert_eq!(target_rot.grants, 1);
    let live_sec_2 = SecretBytes::copy_from(live_stripe_2.as_bytes());
    let new_sha = hex_encode(&secret_sha256(&live_sec_2));
    let rot_stmt = WriteStatement {
        target: target_rot.target.clone(),
        nonce: target_rot.nonce.clone(),
        vault_id: target_rot.vault_id.clone(),
        action: WriteAction::Rotate {
            item: target_rot.item.clone(),
            slug: target_rot.slug.clone(),
            field: target_rot.field.clone().unwrap(),
            field_name: target_rot.field_name.clone().unwrap(),
            classification: target_rot.classification.as_str().to_owned(),
            prior_count: target_rot.prior_count,
            grants: target_rot.grants,
            new_value_sha256: new_sha,
        },
    };
    let rot_digest = write_statement_digest(&rot_stmt);
    let rot_sig = sign_p256_prehash(&approve_sk, &rot_digest).unwrap();
    let rot_aad = se_reseal_aad(&target_rot.target, &decode_hex(&target_rot.nonce));
    let rot_sealed = seal_secret_to_x25519(
        &decode_hex(&target_rot.daemon_eph_pub),
        &rot_aad,
        &live_sec_2,
    )
    .unwrap();
    let rotated = c
        .app_items_rotate(&AppItemsRotateParams {
            target: target_rot.target,
            sealed_value: hex_encode(&rot_sealed),
            digest: hex_encode(&rot_digest),
            signature: hex_encode(&rot_sig),
            claims: Vec::new(),
        })
        .unwrap();
    assert_eq!(rotated.prior_count, 1);

    let target_rm = c.app_items_target("github/acme-web", None, &[]).unwrap();
    let rm_stmt = WriteStatement {
        target: target_rm.target.clone(),
        nonce: target_rm.nonce.clone(),
        vault_id: target_rm.vault_id.clone(),
        action: WriteAction::Remove {
            item: target_rm.item.clone(),
            slug: target_rm.slug.clone(),
            grants: target_rm.grants,
        },
    };
    let rm_digest = write_statement_digest(&rm_stmt);
    let rm_sig = sign_p256_prehash(&approve_sk, &rm_digest).unwrap();
    let removed = c
        .app_items_remove(&AppItemsRemoveParams {
            target: target_rm.target,
            digest: hex_encode(&rm_digest),
            signature: hex_encode(&rm_sig),
            claims: Vec::new(),
        })
        .unwrap();
    assert!(
        h.data_dir().join("backups").join(&removed.backup).is_file(),
        "encrypted backup must exist before item removal"
    );
    h.assert_swept("A11 rotated and removed");

    // -------------------------------------------------------------------------
    // A12: App-initiated reveal (`app.reveal.begin` -> `app.reveal`).
    // -------------------------------------------------------------------------
    let rev_desc = c
        .app_reveal_begin(&AppRevealBeginParams {
            request: None,
            slug: Some("stripe/acme-live".to_owned()),
            field: None,
            claims: Vec::new(),
        })
        .unwrap();
    let app_eph = SeEphemeralKey::generate().unwrap();
    let app_eph_pub_hex = hex_encode(app_eph.public_key());
    let mut signed_rev_desc = rev_desc.clone();
    signed_rev_desc.app_eph_pub.clone_from(&app_eph_pub_hex);
    let rev_digest = reveal_statement_digest(&signed_rev_desc);
    let rev_sig = sign_p256_prehash(&approve_sk, &rev_digest).unwrap();
    let rev_out = c
        .app_reveal(&AppRevealParams {
            request: rev_desc.request.clone(),
            digest: hex_encode(&rev_digest),
            signature: hex_encode(&rev_sig),
            app_eph_pub: app_eph_pub_hex,
            claims: Vec::new(),
        })
        .unwrap();
    h.record(
        "A12 app.reveal sealed_value hex",
        rev_out.sealed_value.as_bytes(),
    );
    let rev_aad = se_reveal_aad(
        &rev_desc.request,
        &decode_hex(&rev_desc.nonce),
        app_eph.public_key(),
    );
    let opened_rev = app_eph
        .open_secret(&rev_aad, &decode_hex_vec(&rev_out.sealed_value))
        .unwrap();
    assert_eq!(secret_sha256(&opened_rev), secret_sha256(&live_sec_2));
    drop(opened_rev);
    h.assert_swept("A12 revealed in app");

    // -------------------------------------------------------------------------
    // A13: Activity (`app.audit.list`) & audit verification (`audit verify --json`).
    // -------------------------------------------------------------------------
    let app_audit = c
        .app_audit_list(&AppAuditListParams {
            before_seq: None,
            limit: Some(50),
            project: None,
            item: None,
            agent: None,
            kinds: Vec::new(),
            claims: Vec::new(),
        })
        .unwrap();
    let kinds: Vec<&str> = app_audit.entries.iter().map(|e| e.kind.as_str()).collect();
    for expected_kind in ["unlock", "approve", "rotate", "remove", "reveal_app"] {
        assert!(
            kinds.contains(&expected_kind),
            "expected audit entry kind {expected_kind} in {kinds:?}"
        );
    }
    let audit_out = h.program(&h.cli(), &["audit", "verify", "--json"], None);
    assert_eq!(audit_out.status.code(), Some(0), "{}", text(&audit_out));
    let audit_json: serde_json::Value = serde_json::from_slice(&audit_out.stdout).unwrap();
    assert_eq!(audit_json["problems"].as_u64(), Some(0));
    h.assert_swept("A13 audit verified");

    // -------------------------------------------------------------------------
    // A14 / A15: Screen lock (`app.lock` with `screen_lock`) & keychain
    // rollback anchor read-only mode (`KeychainAnchorState::Ahead`).
    // -------------------------------------------------------------------------
    c.app_lock(AppLockReason::ScreenLock, &[]).unwrap();
    let st_locked = c.status().unwrap();
    assert_eq!(st_locked.vault.state, VaultState::Locked);
    assert_eq!(st_locked.lock.last_reason, Some(LockReason::ScreenLock));
    assert!(c.grants_list().unwrap().grants.is_empty());

    // Snapshot the vault db, advance the anchor with a remove, then restore
    // the older vault db while keeping the newer anchor to trigger rollback
    // read-only (A15).
    drop(c);
    h.stop_daemon();
    let vault_dir = h.data_dir().join("vault");
    let snap_before = h.files().join("db-before");
    let snap_after = h.files().join("db-after");
    snapshot_vault_db(&vault_dir, &snap_before);

    h.start_daemon(&[]);
    let mut c = app_client(&h);
    unlock_with_se(&mut c, vault_id, &unlocker_id, &unlock_sk);
    let temp_sec = SecretBytes::copy_from(asked_stripe.as_bytes());
    paste_secret(
        &mut c,
        &temp_sec,
        "stripe/temp-epoch",
        Some("stripe"),
        None,
        None,
    );
    let t_rm_temp = c.app_items_target("stripe/temp-epoch", None, &[]).unwrap();
    let rm_temp_stmt = WriteStatement {
        target: t_rm_temp.target.clone(),
        nonce: t_rm_temp.nonce.clone(),
        vault_id: t_rm_temp.vault_id.clone(),
        action: WriteAction::Remove {
            item: t_rm_temp.item.clone(),
            slug: t_rm_temp.slug.clone(),
            grants: t_rm_temp.grants,
        },
    };
    let rm_temp_dig = write_statement_digest(&rm_temp_stmt);
    let rm_temp_sig = sign_p256_prehash(&approve_sk, &rm_temp_dig).unwrap();
    c.app_items_remove(&AppItemsRemoveParams {
        target: t_rm_temp.target,
        digest: hex_encode(&rm_temp_dig),
        signature: hex_encode(&rm_temp_sig),
        claims: Vec::new(),
    })
    .unwrap();
    drop(c);
    h.stop_daemon();

    snapshot_vault_db(&vault_dir, &snap_after);
    restore_vault_db(&snap_before, &vault_dir);

    h.start_daemon(&[]);
    let mut c = app_client(&h);
    unlock_with_se(&mut c, vault_id, &unlocker_id, &unlock_sk);
    let st_ro = c.status().unwrap();
    assert_eq!(st_ro.vault.state, VaultState::Unlocked);
    assert!(st_ro.vault.read_only);
    assert_eq!(st_ro.vault.keychain_anchor, KeychainAnchorState::Ahead);
    let ro_audit = c
        .app_audit_list(&AppAuditListParams {
            kinds: vec!["keychain_anchor_mismatch".into()],
            ..AppAuditListParams::default()
        })
        .unwrap();
    assert!(
        ro_audit
            .entries
            .iter()
            .any(|e| e.outcome == "tampered" && e.reason.as_deref() == Some("rolled_back"))
    );
    assert_eq!(
        rpc_kind(c.app_paste_begin(&[]).unwrap_err()),
        (ErrorKind::VaultTampered, Some("rolled_back"))
    );
    assert_eq!(
        rpc_kind(
            c.app_reveal_begin(&AppRevealBeginParams {
                request: None,
                slug: Some("stripe/acme-live".to_owned()),
                field: None,
                claims: Vec::new(),
            })
            .unwrap_err()
        ),
        (ErrorKind::VaultTampered, Some("rolled_back"))
    );

    // Restore the newer vault files so the story continues in healthy `Unlocked` state.
    drop(c);
    h.stop_daemon();
    restore_vault_db(&snap_after, &vault_dir);
    h.start_daemon(&[]);
    let mut c = app_client(&h);
    unlock_with_se(&mut c, vault_id, &unlocker_id, &unlock_sk);
    let st_restored = c.status().unwrap();
    assert_eq!(st_restored.vault.state, VaultState::Unlocked);
    assert!(!st_restored.vault.read_only);
    assert_eq!(
        st_restored.vault.keychain_anchor,
        KeychainAnchorState::Matched
    );
    h.assert_swept("A15 rollback read-only verified and restored");

    // -------------------------------------------------------------------------
    // A16: Client-initiated reveal (`reveal.request` from terminal fulfilled in
    // app; `envcloak reveal` from `fixture-agent` refused with `proof_refused`).
    // -------------------------------------------------------------------------
    let agent_rev = h.agent(&repo, &["reveal", "openai/acme-web"]);
    assert_eq!(
        token(&agent_rev.stderr),
        "proof_refused",
        "{}",
        text(&agent_rev)
    );

    let cli_rev_req = c.reveal_request("openai/acme-web", None, &[]).unwrap();
    assert_eq!(c.status().unwrap().app_requests, 1);
    let cli_rev_desc = c
        .app_reveal_begin(&AppRevealBeginParams {
            request: Some(cli_rev_req.request.clone()),
            slug: None,
            field: None,
            claims: Vec::new(),
        })
        .unwrap();
    let app_eph_cli = SeEphemeralKey::generate().unwrap();
    let app_eph_cli_pub_hex = hex_encode(app_eph_cli.public_key());
    let mut signed_cli_rev = cli_rev_desc.clone();
    signed_cli_rev.app_eph_pub.clone_from(&app_eph_cli_pub_hex);
    let cli_rev_digest = reveal_statement_digest(&signed_cli_rev);
    let cli_rev_sig = sign_p256_prehash(&approve_sk, &cli_rev_digest).unwrap();
    let cli_rev_out = c
        .app_reveal(&AppRevealParams {
            request: cli_rev_req.request,
            digest: hex_encode(&cli_rev_digest),
            signature: hex_encode(&cli_rev_sig),
            app_eph_pub: app_eph_cli_pub_hex,
            claims: Vec::new(),
        })
        .unwrap();
    h.record(
        "A16 client reveal sealed_value hex",
        cli_rev_out.sealed_value.as_bytes(),
    );
    assert_eq!(c.status().unwrap().app_requests, 0);
    h.assert_swept("A16 client-initiated reveal");

    // -------------------------------------------------------------------------
    // A17 / A18: `items.ask` / `add --ask`, answered via `app.paste`, creates
    // no grant (`grants_list` stays empty).
    // -------------------------------------------------------------------------
    let ask_opened = c
        .items_ask(&AskParams {
            provider: Some("stripe".to_owned()),
            project_dir: Some(repo.to_str().unwrap().to_owned()),
            account: Some("billing".to_owned()),
            env_hint: Some("STRIPE_BILLING_KEY".to_owned()),
            note: Some("Need billing key".to_owned()),
            claims: Vec::new(),
        })
        .unwrap();
    assert_eq!(c.app_asks_list(&[]).unwrap().asks.len(), 1);
    let asked_sec = SecretBytes::copy_from(asked_stripe.as_bytes());
    let pasted_ask = paste_secret(
        &mut c,
        &asked_sec,
        "stripe/billing-asked",
        Some("stripe"),
        Some("STRIPE_BILLING_KEY"),
        Some(&ask_opened.ask),
    );
    assert_eq!(pasted_ask.item.slug, "stripe/billing-asked");
    assert_eq!(
        c.items_ask_state(&ask_opened.ask).unwrap(),
        AskStateOutcome::Added {
            slug: "stripe/billing-asked".to_owned()
        }
    );
    assert!(
        c.grants_list().unwrap().grants.is_empty(),
        "answering an ask must never create a grant"
    );
    h.assert_swept("A18 ask answered without grant");

    // -------------------------------------------------------------------------
    // A19: First-run scan (`envcloak import --scan ... --report` + `init --import`).
    // -------------------------------------------------------------------------
    let billing = h.home.home().join("billing");
    std::fs::create_dir_all(&billing).unwrap();
    let billing_env = billing.join(".env");
    std::fs::write(
        &billing_env,
        format!("STRIPE_SECRET_KEY={scanned_stripe}\n"),
    )
    .unwrap();
    age(&billing_env, Duration::from_secs(600));
    h.allow_plaintext(billing_env.clone());

    let scan_out = h.program(
        &h.cli(),
        &[
            "import",
            "--scan",
            billing.to_str().unwrap(),
            "--machine",
            "--report",
        ],
        None,
    );
    assert_eq!(scan_out.status.code(), Some(0), "{}", text(&scan_out));
    let report_path = h.data_dir().join("reports/first-run.json");
    assert!(report_path.is_file(), "expected first-run.json report");
    let report_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report_json["version"], 1);
    assert!(report_json["keys_found"].as_u64().unwrap() >= 1);

    let init_out = h.human(&billing, &["init", "--import", "--yes"], &[], &[]);
    assert_eq!(init_out.code, 0, "{}", init_out.all());
    let confirmed = h.human(
        &billing,
        &["recovery", "confirm", "--kit-fd", "4"],
        &[(4, &kit_path, true)],
        &[],
    );
    assert_eq!(confirmed.code, 0, "{}", confirmed.all());
    let deleted = h.human(
        &billing,
        &["init", "--delete-plaintext", "--json"],
        &[],
        &[],
    );
    assert_eq!(deleted.code, 0, "{}", deleted.all());
    assert!(
        !billing_env.exists(),
        "envcloak init --delete-plaintext must remove billing/.env"
    );
    h.allow_no_plaintext();
    h.assert_swept("A19 scan and init");

    // -------------------------------------------------------------------------
    // A20: Menu bar / grant revoke (`grants.revoke`) and lock (`lock`).
    // -------------------------------------------------------------------------
    let p2_manifest = "[project]\nname = \"acme-web\"\n\n[env]\nOPENAI_API_KEY = \"openai/acme-web\"\nSTRIPE_SECRET_KEY = \"stripe/acme-live\"\n";
    std::fs::write(repo.join("envcloak.toml"), p2_manifest).unwrap();
    let p2 = h.agent(&repo, &["run", "--", "./emit"]);
    let req_p2 = request_id(&p2);
    let desc_p2 = c.app_pending_get(&req_p2, &[]).unwrap();
    let mut opts_p2 = ApprovalOptions::session(Duration::from_secs(3600));
    opts_p2.live = vec![
        EnvName::new("OPENAI_API_KEY").unwrap(),
        EnvName::new("STRIPE_SECRET_KEY").unwrap(),
    ];
    let dig_p2 = statement_digest(&desc_p2, &opts_p2);
    let sig_p2 = hex_encode(&sign_p256_prehash(&approve_sk, &dig_p2).unwrap());
    let app_p2 = c
        .app_approve(&req_p2, &opts_p2, &dig_p2, &sig_p2, &[])
        .unwrap();
    let grant_id = app_p2.grant;
    assert_eq!(c.grants_list().unwrap().grants.len(), 1);
    c.grants_revoke(Some(&grant_id)).unwrap();
    assert!(c.grants_list().unwrap().grants.is_empty());

    c.lock().unwrap();
    assert_eq!(c.status().unwrap().vault.state, VaultState::Locked);
    drop(c);
    h.stop_daemon();
    let _ = BTreeMap::<String, String>::new();
    h.assert_swept("A20 final");
}
