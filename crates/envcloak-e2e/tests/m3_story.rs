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
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

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
use envcloak_ipc::proto::{ErrorKind, PendingGetOutput};
use envcloak_ipc::view::{
    AddedView, ClassificationView, KeychainAnchorState, LengthClass, LockReason, VaultState,
};
use envcloak_ipc::{Client, ClientError, RunPathErrorKind, RunPaths, Unverified};
use envcloak_policy::{
    ApprovalOptions, DEFAULT_TTL, EnvName, SubjectKind, Uses, WriteAction, WriteStatement,
    reveal_statement_digest, statement_digest, unlocker_statement_digest, write_statement_digest,
};
use envcloak_testkit::{Canary, Detector, daemon_run_dir, fresh_seed, labels};
use serde_json::json;

const TEST_TEAM_ID: &str = "AB12CD34EF";
const TEST_SIGNING_ID: &str = "ai.envcloak.app";
const CHILD_ROLE_DENIED_ENV: &str = "ENVCLOAK_TEST_M321_CHILD_ROLE_DENIED";

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_encode_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
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

fn unlock_with_se(
    h: &mut Harness,
    c: &mut Client,
    vault_id: VaultId,
    unlocker_id: &str,
    unlock_sk: &[u8; 32],
    step_label: &str,
) -> (String, String, String, String) {
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

    // Register the opened 32-byte VMK (raw bytes, lowercase hex, uppercase hex,
    // standard base64, and URL-safe base64) before recording the IPC wire frames
    // so `h.record` and `h.assert_swept` verify the VMK never crosses the socket
    // in any unsealed encoding (g2).
    let vmk_bytes = vmk.export_for_testing();
    let vmk_hex = hex_encode(&vmk_bytes);
    let vmk_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &vmk_bytes);
    let vmk_b64_url =
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE, &vmk_bytes);
    let vmk_b64_no_pad = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &vmk_bytes,
    );
    if !h.canaries.iter().any(|c| c.label == "VMK_HEX") {
        h.add_canary(Canary::new("VMK_HEX", vmk_hex));
        h.add_canary(Canary::new("VMK_B64", vmk_b64));
    }
    h.add_needle("VMK_RAW".to_owned(), vmk_bytes.clone());
    h.add_needle(
        "VMK_HEX_UPPER".to_owned(),
        hex_encode_upper(&vmk_bytes).into_bytes(),
    );
    h.add_needle("VMK_B64_URL".to_owned(), vmk_b64_url.into_bytes());
    h.add_needle("VMK_B64_NO_PAD".to_owned(), vmk_b64_no_pad.into_bytes());

    let begin_wire = serde_json::to_vec(&json!({
        "request_id": &begin.request_id,
        "vault_id": &begin.vault_id,
        "unlocker_id": &begin.unlocker_id,
        "epoch": begin.epoch,
        "envelope": {
            "enc": &begin.envelope.enc,
            "ciphertext": &begin.envelope.ciphertext,
        },
        "daemon_eph_pub": &begin.daemon_eph_pub,
        "challenge": &begin.challenge,
    }))
    .unwrap();
    h.record(
        &format!("{step_label} app.unlock.begin response"),
        &begin_wire,
    );

    let challenge = decode_hex::<SE_CHALLENGE_LEN>(&begin.challenge);
    let daemon_pub: [u8; 32] = decode_hex(&begin.daemon_eph_pub);
    let sealed_vmk = seal_vmk_to_daemon(&daemon_pub, &begin.request_id, &challenge, &vmk).unwrap();
    let sealed_vmk_hex = hex_encode(&sealed_vmk);
    let unlock_wire = serde_json::to_vec(&json!({
        "request_id": &begin.request_id,
        "sealed_vmk": &sealed_vmk_hex,
    }))
    .unwrap();
    h.record(&format!("{step_label} app.unlock request"), &unlock_wire);

    let unlocked = c
        .app_unlock(&begin.request_id, &sealed_vmk_hex, &[])
        .unwrap();
    assert!(!unlocked.already);
    (
        begin.request_id,
        begin.daemon_eph_pub,
        begin.challenge,
        sealed_vmk_hex,
    )
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
#[allow(clippy::too_many_lines)]
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

    let (unlock_sk, unlock_pub): ([u8; 32], [u8; P256_PUBLIC_KEY_LEN]) =
        derive_p256_keypair(&[0x42; 32]);
    let (approve_sk, approve_pub): ([u8; 32], [u8; P256_PUBLIC_KEY_LEN]) =
        derive_p256_keypair(&[0x43; 32]);

    // When `ENVCLOAK_E2E_BIN_DIR` points at the release binaries (built without
    // `envcloak-sys/testing`), verify that `ENVCLOAK_TEST_APP_IDENTITY` is
    // ignored (`RoleDenied`) and skip the steps that require the test-only
    // Secure Enclave software stand-in hooks.
    if !h.test_build() {
        assert_eq!(
            rpc_kind(
                c.app_unlocker_enroll_begin(
                    &hex_encode(&unlock_pub),
                    &hex_encode(&approve_pub),
                    "Touch ID",
                    &[],
                )
                .unwrap_err()
            )
            .0,
            ErrorKind::RoleDenied,
            "release binary must ignore ENVCLOAK_TEST_APP_IDENTITY"
        );
        eprintln!(
            "m3_story: Secure Enclave software stand-in hooks exist in the test build only; skipped here"
        );
        h.assert_swept("m3_story release build check");
        return;
    }

    // -------------------------------------------------------------------------
    // A3 / A4: Touch ID enrollment (`app.unlocker.enroll.begin` -> `approve` ->
    // `app.unlocker.enroll`), then lock and unlock with Touch ID twice in a row
    // (g2: VMK crosses the socket only HPKE-sealed, once per unlock, with fresh
    // challenge/ephemeral key each time and no VMK bytes in any encoding).
    // -------------------------------------------------------------------------
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
    let u1 = unlock_with_se(&mut h, &mut c, vault_id, &unlocker_id, &unlock_sk, "A4-1");
    assert_eq!(c.status().unwrap().vault.state, VaultState::Unlocked);

    c.lock().unwrap();
    assert_eq!(c.status().unwrap().vault.state, VaultState::Locked);
    let u2 = unlock_with_se(&mut h, &mut c, vault_id, &unlocker_id, &unlock_sk, "A4-2");
    assert_eq!(c.status().unwrap().vault.state, VaultState::Unlocked);
    assert_ne!(u1.0, u2.0, "each unlock must issue a fresh request_id");
    assert_ne!(
        u1.1, u2.1,
        "each unlock must generate a fresh daemon_eph_pub"
    );
    assert_ne!(u1.2, u2.2, "each unlock must generate a fresh challenge");
    assert_ne!(u1.3, u2.3, "each unlock must produce a distinct sealed_vmk");
    h.assert_swept("A4 unlocked twice with Touch ID");

    // -------------------------------------------------------------------------
    // A5: Sealed paste (`app.paste.begin` -> `app.paste.inspect` -> `app.paste`),
    // project bindings (`envcloak ref`, `envcloak ref --unset`), `envcloak check --json`
    // across `acme-web` and `billing`, and byte-for-byte undo (`--undo-fd` /
    // `--restore-fd`).
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
    std::fs::write(
        repo.join("envcloak.toml"),
        "[project]\nname = \"acme-web\"\n\n[env]\n",
    )
    .unwrap();
    for args in [
        &["ref", "OPENAI_API_KEY=openai/acme-web", "--json"][..],
        &["ref", "STRIPE_SECRET_KEY=stripe/acme-live", "--json"][..],
        &["ref", "GITHUB_TOKEN=github/acme-web", "--json"][..],
        &[
            "ref",
            "EXTRA_GITHUB_TOKEN=github/acme-web",
            "--profile",
            "denytest",
            "--json",
        ][..],
    ] {
        let out = h.human(&repo, args, &[], &[]);
        assert_eq!(out.code, 0, "{}", out.all());
    }
    let check_acme = h.human(&repo, &["check", "--json"], &[], &[]);
    assert_eq!(check_acme.code, 0, "{}", check_acme.all());

    let billing_a5 = h.home.root().join("billing-a5");
    std::fs::create_dir_all(&billing_a5).unwrap();
    let billing_manifest = billing_a5.join("envcloak.toml");
    std::fs::write(
        &billing_manifest,
        "# Billing manifest\n[project]\nname = \"billing\"\n\n[env]\n",
    )
    .unwrap();
    let ref_b1 = h.human(
        &billing_a5,
        &["ref", "OPENAI_API_KEY=openai/acme-web", "--json"],
        &[],
        &[],
    );
    assert_eq!(ref_b1.code, 0, "{}", ref_b1.all());
    let check_b1 = h.human(&billing_a5, &["check", "--json"], &[], &[]);
    assert_eq!(check_b1.code, 0, "{}", check_b1.all());
    let billing_snapshot = std::fs::read(&billing_manifest).unwrap();

    // Change binding in `billing` with `--undo-fd` and restore byte-for-byte.
    let undo_change = h.files().join("billing-change.undo");
    let ref_b2 = h.human(
        &billing_a5,
        &[
            "ref",
            "OPENAI_API_KEY=github/acme-web",
            "--undo-fd",
            "3",
            "--json",
        ],
        &[(3, &undo_change, false)],
        &[],
    );
    assert_eq!(ref_b2.code, 0, "{}", ref_b2.all());
    assert_ne!(std::fs::read(&billing_manifest).unwrap(), billing_snapshot);
    let check_b2 = h.human(&billing_a5, &["check", "--json"], &[], &[]);
    assert_eq!(check_b2.code, 0, "{}", check_b2.all());

    let restore_b2 = h.human(
        &billing_a5,
        &["ref", "--restore-fd", "3", "--json"],
        &[(3, &undo_change, true)],
        &[],
    );
    assert_eq!(restore_b2.code, 0, "{}", restore_b2.all());
    assert_eq!(
        std::fs::read(&billing_manifest).unwrap(),
        billing_snapshot,
        "undo of binding change must restore envcloak.toml byte-for-byte"
    );

    // Unset binding in `billing` with `--undo-fd` and restore byte-for-byte.
    let undo_unset = h.files().join("billing-unset.undo");
    let unset_b = h.human(
        &billing_a5,
        &[
            "ref",
            "--unset",
            "OPENAI_API_KEY",
            "--undo-fd",
            "3",
            "--json",
        ],
        &[(3, &undo_unset, false)],
        &[],
    );
    assert_eq!(unset_b.code, 0, "{}", unset_b.all());
    assert!(
        !String::from_utf8_lossy(&std::fs::read(&billing_manifest).unwrap())
            .contains("OPENAI_API_KEY")
    );
    let restore_unset = h.human(
        &billing_a5,
        &["ref", "--restore-fd", "3", "--json"],
        &[(3, &undo_unset, true)],
        &[],
    );
    assert_eq!(restore_unset.code, 0, "{}", restore_unset.all());
    assert_eq!(
        std::fs::read(&billing_manifest).unwrap(),
        billing_snapshot,
        "undo of --unset must restore envcloak.toml byte-for-byte"
    );

    write_script(
        &repo.join("emit"),
        "#!/bin/sh\nset -eu\npython3 -c 'import hashlib, os\nfor k in (\"OPENAI_API_KEY\", \"STRIPE_SECRET_KEY\", \"GITHUB_TOKEN\"):\n    v = os.environ.get(k, \"\").encode()\n    print(\"raw\", k, v.decode())\n    print(\"sha256\", k, hashlib.sha256(v).hexdigest())\n'\n",
    );
    h.assert_swept("A5 pasted, bound, checked and undone byte-for-byte");

    // -------------------------------------------------------------------------
    // A6 / A7 / A8: Approval window, live-key confirmation tick, two approvals
    // within 10 s each requiring its own signature (g3), session grant reuse,
    // and 3-denial auto-deny cooldown (gate 32).
    // -------------------------------------------------------------------------
    let run_pending_1 = h.agent(&repo, &["run", "--", "./emit"]);
    let req_run_1 = request_id(&run_pending_1);
    assert_eq!(c.status().unwrap().approvals.pending, 1);

    let desc_run_1 = c.app_pending_get(&req_run_1, &[]).unwrap();
    assert_eq!(desc_run_1.request, req_run_1);

    // Omitting `live: ["STRIPE_SECRET_KEY"]` is rejected (`live_not_ticked`).
    let opts_missing_live = ApprovalOptions::once(DEFAULT_TTL);
    let digest_missing_live = statement_digest(&desc_run_1, &opts_missing_live);
    let sig_missing_live =
        hex_encode(&sign_p256_prehash(&approve_sk, &digest_missing_live).unwrap());
    assert_eq!(
        rpc_kind(
            c.app_approve(
                &req_run_1,
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

    // First approval (`Uses::Once`) with live keys confirmed.
    let mut opts_once = ApprovalOptions::once(DEFAULT_TTL);
    opts_once.live = vec![
        EnvName::new("GITHUB_TOKEN").unwrap(),
        EnvName::new("OPENAI_API_KEY").unwrap(),
        EnvName::new("STRIPE_SECRET_KEY").unwrap(),
    ];
    let digest_1 = statement_digest(&desc_run_1, &opts_once);
    let sig_1 = hex_encode(&sign_p256_prehash(&approve_sk, &digest_1).unwrap());
    let approved_1 = c
        .app_approve(&req_run_1, &opts_once, &digest_1, &sig_1, &[])
        .unwrap();
    assert!(!approved_1.grant.is_empty());

    // Running consumes the `Uses::Once` grant; output is redacted and SHA-256 matches.
    let run_once_ok = h.agent(&repo, &["run", "--", "./emit"]);
    assert_eq!(run_once_ok.status.code(), Some(0), "{}", text(&run_once_ok));
    let stdout_ok = String::from_utf8_lossy(&run_once_ok.stdout);
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

    // Second request within 10 seconds (A7, g3): requires a fresh statement
    // digest and signature; replaying `sig_1` is rejected with `signature_invalid`.
    let run_pending_2 = h.agent(&repo, &["run", "--", "./emit"]);
    let req_run_2 = request_id(&run_pending_2);
    assert_ne!(req_run_1, req_run_2);
    let desc_run_2 = c.app_pending_get(&req_run_2, &[]).unwrap();
    let mut opts_session = ApprovalOptions::session(Duration::from_secs(3600));
    opts_session.live.clone_from(&opts_once.live);
    let digest_2 = statement_digest(&desc_run_2, &opts_session);
    assert_ne!(digest_1, digest_2);
    assert_eq!(
        rpc_kind(
            c.app_approve(&req_run_2, &opts_session, &digest_2, &sig_1, &[])
                .unwrap_err()
        )
        .0,
        ErrorKind::SignatureInvalid,
        "replaying the first approval's signature within 10 s must be rejected (g3)"
    );
    let sig_2 = hex_encode(&sign_p256_prehash(&approve_sk, &digest_2).unwrap());
    let approved_2 = c
        .app_approve(&req_run_2, &opts_session, &digest_2, &sig_2, &[])
        .unwrap();
    assert!(!approved_2.grant.is_empty());

    // Subsequent run in the same session succeeds immediately under the session grant.
    let run_session_ok = h.agent(&repo, &["run", "--", "./emit"]);
    assert_eq!(
        run_session_ok.status.code(),
        Some(0),
        "{}",
        text(&run_session_ok)
    );

    // 3 consecutive denials on `(root, project)` trigger auto-deny on the 4th
    // even when argv differs (A8, gate 32).
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
    h.assert_swept("A8 approvals and 3-denial auto-deny");

    // -------------------------------------------------------------------------
    // A9: Replace (`app.items.target` -> `app.items.rotate`) & remove
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
    h.assert_swept("A9 rotated and removed");

    // -------------------------------------------------------------------------
    // A10: App-initiated reveal (`app.reveal.begin` -> `app.reveal`).
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
        "A10 app.reveal sealed_value hex",
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
    h.assert_swept("A10 revealed in app");

    // -------------------------------------------------------------------------
    // A11: Activity (`app.audit.list`) & audit verification (`audit verify --json`).
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
    h.assert_swept("A11 audit verified");

    // -------------------------------------------------------------------------
    // A12: Screen lock (`app.lock` with `screen_lock`, g7: drops all grants).
    // -------------------------------------------------------------------------
    c.app_lock(AppLockReason::ScreenLock, &[]).unwrap();
    let st_locked = c.status().unwrap();
    assert_eq!(st_locked.vault.state, VaultState::Locked);
    assert_eq!(st_locked.lock.last_reason, Some(LockReason::ScreenLock));
    assert!(c.grants_list().unwrap().grants.is_empty());

    // -------------------------------------------------------------------------
    // A13: Keychain rollback anchor read-only mode (`KeychainAnchorState::Ahead`, g5).
    // -------------------------------------------------------------------------
    drop(c);
    h.stop_daemon();
    let vault_dir = h.data_dir().join("vault");
    let snap_before = h.files().join("db-before");
    let snap_after = h.files().join("db-after");
    snapshot_vault_db(&vault_dir, &snap_before);

    h.start_daemon(&[]);
    let mut c = app_client(&h);
    unlock_with_se(&mut h, &mut c, vault_id, &unlocker_id, &unlock_sk, "A13-1");
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
    unlock_with_se(&mut h, &mut c, vault_id, &unlocker_id, &unlock_sk, "A13-2");
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
    unlock_with_se(&mut h, &mut c, vault_id, &unlocker_id, &unlock_sk, "A13-3");
    let st_restored = c.status().unwrap();
    assert_eq!(st_restored.vault.state, VaultState::Unlocked);
    assert!(!st_restored.vault.read_only);
    assert_eq!(
        st_restored.vault.keychain_anchor,
        KeychainAnchorState::Matched
    );
    h.assert_swept("A13 rollback read-only verified and restored");

    // -------------------------------------------------------------------------
    // A14 / A15: Forged peer (`role_denied` from a client-role process, g4 /
    // gate 22), agent claims on app methods (every `app.*` method refused with
    // `proof_refused` except `app.lock`, gate 23), and `daemon_unverified` (g1 /
    // gate 21).
    // -------------------------------------------------------------------------
    let run_paths = RunPaths::under(daemon_run_dir(&h.home)).unwrap();
    let child_out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_client_role_denied_probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ROLE_DENIED_ENV, &run_paths.socket)
        .output()
        .unwrap();
    assert!(
        child_out.status.success()
            && String::from_utf8_lossy(&child_out.stdout).contains("@@ client_role_denied_ok"),
        "child_client_role_denied_probe failed: {}",
        String::from_utf8_lossy(&child_out.stderr)
    );

    let agent_claims = vec!["CURSOR_AGENT".to_owned()];
    assert_eq!(
        rpc_kind(c.app_paste_begin(&agent_claims).unwrap_err()).0,
        ErrorKind::ProofRefused
    );
    assert_eq!(
        rpc_kind(c.app_pending_list(&agent_claims).unwrap_err()).0,
        ErrorKind::ProofRefused
    );
    assert_eq!(
        rpc_kind(c.app_asks_list(&agent_claims).unwrap_err()).0,
        ErrorKind::ProofRefused
    );
    assert_eq!(
        rpc_kind(
            c.app_audit_list(&AppAuditListParams {
                claims: agent_claims.clone(),
                ..AppAuditListParams::default()
            })
            .unwrap_err()
        )
        .0,
        ErrorKind::ProofRefused
    );
    assert_eq!(
        rpc_kind(c.app_unlock_begin(None, &agent_claims).unwrap_err()).0,
        ErrorKind::ProofRefused
    );
    // `app.lock` is permitted even under agent claims so screen-lock protection
    // is never blocked.
    c.app_lock(AppLockReason::ScreenLock, &agent_claims)
        .unwrap();
    assert_eq!(c.status().unwrap().vault.state, VaultState::Locked);
    unlock_with_se(&mut h, &mut c, vault_id, &unlocker_id, &unlock_sk, "A14");

    // A15 (`g1` / gate 21): `daemon_unverified` when peer verification fails.
    assert_eq!(
        ClientError::Unverified(Unverified::CodeIdentity).token(),
        "daemon_unverified"
    );
    std::fs::set_permissions(&run_paths.dir, std::fs::Permissions::from_mode(0o770)).unwrap();
    let unverified_client_err = Client::connect(&run_paths).unwrap_err();
    let unverified_cli = h.program(&h.cli(), &["ls"], None);
    std::fs::set_permissions(&run_paths.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        unverified_client_err,
        ClientError::Unverified(Unverified::Directory(RunPathErrorKind::OpenPermissions))
    );
    assert_eq!(unverified_client_err.token(), "daemon_unverified");
    assert_eq!(unverified_cli.status.code(), Some(1));
    assert_eq!(
        token(&unverified_cli.stderr),
        "daemon_unverified",
        "{}",
        text(&unverified_cli)
    );
    h.assert_swept("A14/A15 forged peer, agent refusal, and daemon_unverified");

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
    // A17: `fixture-agent` runs `envcloak add stripe --ask --wait 30s`; app
    // answers via `app.paste`; agent prints only the new slug and holds no grant.
    // -------------------------------------------------------------------------
    let asked_sec = SecretBytes::copy_from(asked_stripe.as_bytes());
    let ask_run_paths = run_paths.clone();
    let ask_out = std::thread::scope(|scope| {
        scope.spawn(|| {
            let deadline = Instant::now() + Duration::from_secs(15);
            let ask = loop {
                let mut c_ask = Client::connect(&ask_run_paths).unwrap();
                let listed = c_ask.app_asks_list(&[]).unwrap();
                if let Some(a) = listed.asks.into_iter().next() {
                    break a;
                }
                assert!(Instant::now() < deadline, "timed out waiting for items.ask");
                std::thread::sleep(Duration::from_millis(40));
            };
            assert_eq!(ask.requester.kind, SubjectKind::Agent);
            assert_eq!(
                ask.requester.label.as_deref(),
                Some("EnvCloak test fixture agent")
            );
            let mut c_paste = Client::connect(&ask_run_paths).unwrap();
            let pasted = paste_secret(
                &mut c_paste,
                &asked_sec,
                "stripe/billing-asked",
                Some("stripe"),
                Some("STRIPE_BILLING_KEY"),
                Some(&ask.ask),
            );
            assert_eq!(pasted.item.slug, "stripe/billing-asked");
        });
        h.agent(
            &repo,
            &[
                "add",
                "stripe",
                "--account",
                "billing",
                "--env",
                "STRIPE_BILLING_KEY",
                "--note",
                "Need billing key",
                "--ask",
                "--wait",
                "30s",
            ],
        )
    });
    assert_eq!(ask_out.status.code(), Some(0), "{}", text(&ask_out));
    assert_eq!(
        String::from_utf8_lossy(&ask_out.stdout),
        "stripe/billing-asked\n",
        "add --ask must print only the new slug"
    );
    assert!(ask_out.stderr.is_empty(), "{}", text(&ask_out));
    assert!(
        c.grants_list().unwrap().grants.is_empty(),
        "answering an ask must never create a grant"
    );
    h.assert_swept("A17 ask answered without grant");

    // -------------------------------------------------------------------------
    // A18: First-run scan (`envcloak import --scan ... --report` + `init --import`
    // + `init --delete-plaintext`).
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
    h.assert_swept("A18 scan and init");

    // -------------------------------------------------------------------------
    // A19 / A20: Menu bar / grant revoke (`grants.revoke`), lock (`lock`), and
    // final canary sweep with a planted positive control (gate 12).
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

    // Planted positive control (gate 12): verify both `Detector` and `h.sweep()`
    // catch a planted canary and a planted VMK hex string, then clean up and
    // re-assert `h.assert_swept`.
    let detector = Detector::new(&h.canaries);
    assert!(
        !detector.find(live_stripe_1.as_bytes()).is_empty(),
        "Detector positive control must catch LIVE_STRIPE_1"
    );
    let vmk_hex_val = h.canary("VMK_HEX").value().to_vec();
    assert!(
        !detector.find(&vmk_hex_val).is_empty(),
        "Detector positive control must catch VMK_HEX"
    );
    let planted_path = h.home.root().join("planted-positive-control.txt");
    std::fs::write(&planted_path, live_stripe_2.as_bytes()).unwrap();
    assert!(
        !h.sweep().is_empty(),
        "h.sweep() positive control must catch a planted canary file in HOME"
    );
    std::fs::remove_file(&planted_path).unwrap();
    h.assert_swept("A20 final after positive control");
}
