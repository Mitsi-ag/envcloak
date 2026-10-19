//! Signed writes (`envcloak-write-statement/1`), signed reveal
//! (`envcloak-reveal-statement/1`), sealed paste (`app.paste.*`) and
//! secret-addition asks (`items.ask`, `items.ask_state`, `app.asks.*`) over the
//! daemon's socket (SPEC §4.3, §4.4, §5, §6.3, §6.7, §10b, §15.2 gates `22`,
//! `23`, `32`, `33`; M3 plan task M3-14):
//!
//! - `app.items.target`, `app.items.rotate`, `app.items.remove` (encrypted
//!   backup first; `backup_failed` removes nothing), `app.unlocker.add`,
//!   `app.unlocker.remove` (never the Recovery Kit's, `no_unlocker`; never the
//!   last daily unlocker or last Secure Enclave unlocker, `last_unlocker`).
//! - `reveal.request` (client role; `proof_refused` to an agent, unknown or
//!   terminal-less subject before anything is filed), `app.reveal.begin`,
//!   `app.reveal` (HPKE-sealed to `app_eph_pub`, `reveal_app` audit entry
//!   durable before release).
//! - `app.paste.begin`, `app.paste.inspect` (`SecretBytes` staged in daemon
//!   memory for 2 minutes on the awake clock, wiped on lock/expiry), `app.paste`.
//! - `items.ask`, `items.ask_state` (`pending`, `added { slug }`, `declined`,
//!   `expired` only to the requester's process tree; `unknown` to any other
//!   tree; never creates a grant), `app.asks.list`, `app.asks.decline`, and
//!   `status.app_requests`.
//!
//! Named mutation checks (M3 plan M3-14):
//! 1. Skip the backup before `app.items.remove`:
//!    `failed_backup_before_app_items_remove_removes_nothing` fails.
//! 2. Release `app.reveal` before the audit entry is durable:
//!    `signed_reveal_and_failed_audit_write_before_app_reveal_releases_nothing`
//!    fails.
//! 3. Allow removing the last unlocker:
//!    `unlocker_add_and_remove_passphrase_se_and_last_unlocker_guards` fails.
//! 4. Answer `items.ask_state` to another process tree:
//!    `asks_answered_declined_expired_other_tree_unknown_and_no_grant` fails.
//! 5. Create a grant when an ask is answered:
//!    `asks_answered_declined_expired_other_tree_unknown_and_no_grant` fails.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    MANIFEST, SLUGS, client, data_dir, error_kind, passphrase, project, raw, read_json, send_json,
};
use envcloak_core::audit::AuditKind;
use envcloak_core::crypto::{
    ItemClass, KdfParams, P256_PUBLIC_KEY_LEN, SE_CHALLENGE_LEN, SE_HPKE_CIPHERTEXT_LEN,
    SE_HPKE_ENC_LEN, SeEphemeralKey, SeHpkeEnvelope, UnlockerId, UnlockerKind, VaultId,
    derive_p256_keypair, open_se_envelope, p256_fingerprint, se_reseal_aad, seal_secret_to_x25519,
    seal_vmk_to_daemon, secret_sha256, sign_p256_prehash,
};
use envcloak_core::vault::{FieldName, ItemDetails, LockedVault, NewItem, Slug, VaultPaths};
use envcloak_core::{RecoveryKit, SecretBytes, create_vault_with_kit};
use envcloak_ipc::app::{
    AppItemsRemoveParams, AppItemsRotateParams, AppPasteParams, AppRevealBeginParams,
    AppRevealParams, AppUnlockerAddParams, AppUnlockerEnrollOutput, AppUnlockerRemoveParams,
};
use envcloak_ipc::proto::{AskParams, ErrorKind, PendingGetOutput, RunRequestParams};
use envcloak_ipc::view::{ClassificationView, DecisionView, LengthClass};
use envcloak_ipc::{Client, ClientError, RunPaths};
use envcloak_policy::{
    ApprovalOptions, AskStateOutcome, DEFAULT_TTL, UnlockerTarget, Uses, WriteAction,
    WriteStatement, reveal_statement_digest, statement_digest, unlocker_statement_digest,
    write_statement_digest,
};
use envcloak_testkit::{
    Canary, Daemon, Detector, TestHome, assert_no_canary, by_label, canaries, daemon_run_dir,
    encodings, fresh_seed, labels,
};
use serde_json::json;

const TEST_TEAM_ID: &str = "AB12CD34EF";
const TEST_SIGNING_ID: &str = "ai.envcloak.app";
const OTHER_TREE_POLL_ENV: &str = "ENVCLOAK_TEST_M314_OTHER_TREE_POLL";
const AGENT_REVEAL_ENV: &str = "ENVCLOAK_TEST_M314_AGENT_REVEAL";

struct RecordingProxy {
    run_dir: PathBuf,
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl RecordingProxy {
    fn start(home: &TestHome) -> Self {
        let run_dir = home.root().join("proxy-run");
        std::fs::create_dir(&run_dir).unwrap();
        std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let proxy_paths = RunPaths::under(run_dir.clone()).unwrap();
        let listener = UnixListener::bind(&proxy_paths.socket).unwrap();
        let daemon_sock = common::run_paths(home).socket;
        let frames = Arc::new(Mutex::new(Vec::new()));
        let frames_bg = Arc::clone(&frames);
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut client_stream) = incoming else {
                    break;
                };
                let Ok(mut daemon_stream) = UnixStream::connect(&daemon_sock) else {
                    break;
                };
                let mut c_read = client_stream.try_clone().unwrap();
                let mut d_write = daemon_stream.try_clone().unwrap();
                let frames_c2d = Arc::clone(&frames_bg);
                let c2d = std::thread::spawn(move || {
                    while let Some(raw) = read_raw_frame(&mut c_read) {
                        frames_c2d.lock().unwrap().push(raw.clone());
                        if d_write.write_all(&raw).is_err() {
                            break;
                        }
                    }
                });
                let frames_d2c = Arc::clone(&frames_bg);
                while let Some(raw) = read_raw_frame(&mut daemon_stream) {
                    frames_d2c.lock().unwrap().push(raw.clone());
                    if client_stream.write_all(&raw).is_err() {
                        break;
                    }
                }
                let _ = c2d.join();
            }
        });
        RecordingProxy { run_dir, frames }
    }

    fn connect(&self) -> Client {
        let paths = RunPaths::under(self.run_dir.clone()).unwrap();
        Client::connect(&paths).unwrap()
    }

    fn recorded(&self) -> Vec<Vec<u8>> {
        self.frames.lock().unwrap().clone()
    }
}

fn read_raw_frame(s: &mut UnixStream) -> Option<Vec<u8>> {
    let mut header = [0u8; 4];
    if s.read_exact(&mut header).is_err() {
        return None;
    }
    let len = u32::from_be_bytes(header) as usize;
    let mut raw = Vec::with_capacity(4 + len);
    raw.extend_from_slice(&header);
    raw.resize(4 + len, 0);
    s.read_exact(&mut raw[4..]).ok()?;
    Some(raw)
}

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

fn decode_hex_vec(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn assert_secret_eq(actual: &SecretBytes, expected: &[u8]) {
    assert_eq!(actual.len(), expected.len());
    let expected_sec = SecretBytes::copy_from(expected);
    assert_eq!(secret_sha256(actual), secret_sha256(&expected_sec));
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

fn start_with_app_id(home: &TestHome, app_id: Option<&str>, clock_file: Option<&Path>) -> Daemon {
    let mut cmd = Command::new(common::exe());
    home.apply(&mut cmd).env(envcloak_sys::testing::TRACE, "1");
    if let Some(id) = app_id {
        cmd.env(envcloak_sys::testing::APP_IDENTITY, id);
    }
    if let Some(cf) = clock_file {
        cmd.env(envcloak_sys::testing::CLOCK_FILE, cf);
    }
    Daemon::start_command(cmd, &[])
}

/// Seeds a vault with both a Passphrase envelope and a RecoveryKit envelope so
/// `Vault::create_backup` (used by `app.items.remove`) has a Recovery Kit
/// envelope to seal the backup under.
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
    c: &mut Client,
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

fn sign_write(approve_sk: &[u8; 32], stmt: &WriteStatement) -> (String, String) {
    let digest = write_statement_digest(stmt);
    let sig = sign_p256_prehash(approve_sk, &digest).unwrap();
    (hex_encode(&digest), hex_encode(&sig))
}

/// Child entrypoint when spawned as `fixture-agent` so its `SubjectEvidence`
/// root is this `fixture-agent` process instance (distinct from both the
/// parent test process and any sibling `fixture-agent`).
#[test]
fn other_tree_poll_ask_child() {
    let Some(run_dir) = std::env::var_os(OTHER_TREE_POLL_ENV) else {
        return;
    };
    let run_paths = RunPaths::under(PathBuf::from(run_dir)).unwrap();
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut line = String::new();
    while stdin.read_line(&mut line).unwrap() > 0 {
        let trimmed = line.trim();
        if trimmed == "quit" {
            break;
        } else if let Some(rest) = trimmed.strip_prefix("ask ") {
            let params: AskParams = serde_json::from_str(rest).unwrap();
            let mut c = Client::connect(&run_paths).unwrap();
            let opened = c.items_ask(&params).unwrap();
            writeln!(stdout, "\n@@ {}", opened.ask).unwrap();
            stdout.flush().unwrap();
        } else if let Some(ask_id) = trimmed.strip_prefix("state ") {
            let mut c = Client::connect(&run_paths).unwrap();
            let state = c.items_ask_state(ask_id).unwrap();
            writeln!(stdout, "\n@@ {}", serde_json::to_string(&state).unwrap()).unwrap();
            stdout.flush().unwrap();
        } else if let Some(manifest) = trimmed.strip_prefix("run ") {
            let mut c = Client::connect(&run_paths).unwrap();
            let out = c
                .run_request(&RunRequestParams {
                    manifest: manifest.to_owned(),
                    profile: None,
                    refs: Vec::new(),
                    env_file: None,
                    argv: vec!["./emit".to_owned()],
                    claims: Vec::new(),
                    launch: None,
                    bridge: None,
                    fds: Vec::new(),
                })
                .unwrap();
            let tag = match out.decision {
                DecisionView::Pending { .. } => "pending",
                DecisionView::Covered { .. } => "covered",
                DecisionView::Denied { .. } => "denied",
                DecisionView::Started {} => "started",
            };
            writeln!(stdout, "\n@@ {tag}").unwrap();
            stdout.flush().unwrap();
        }
        line.clear();
    }
}

/// Child entrypoint when spawned as `fixture-agent` to verify `reveal.request`
/// is refused (`proof_refused`) due to agent ancestry even with empty claims.
#[test]
fn fixture_agent_reveal_request_child() {
    let Some(run_dir) = std::env::var_os(AGENT_REVEAL_ENV) else {
        return;
    };
    envcloak_sys::testing::enter_terminal_session().unwrap();
    let run_paths = RunPaths::under(PathBuf::from(run_dir)).unwrap();
    let mut c = Client::connect(&run_paths).unwrap();
    let err = c.reveal_request("openai/acme-web", None, &[]).unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::ProofRefused);
    println!("@@ agent_reveal_refused_ok");
}

/// Signed item writes (`app.items.target`, `app.items.rotate`, `app.items.remove`):
/// - Real P-256 signature rotates a field, increments `prior_count`, updates
///   classification when rotating a test key to a live key (ending bound
///   grants, F-47), and writes a `rotate` audit record.
/// - Wrong key, mutated statement (`slug`, `prior_count`, `grants`,
///   `new_value_sha256`), and replayed target/nonce are rejected
///   (`signature_invalid`, `statement_mismatch`, `no_such_request`).
/// - `app.items.remove` writes an encrypted backup first, deletes the item,
///   ends bound grants, and writes a `remove` audit record.
#[test]
fn signed_item_rotate_and_remove_with_signature_and_statement_guards() {
    common::terminal_session();
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let (_, _, mut all_cs) = seed_vault_with_kit(&home, &cs);
    let manifest = project(&home, "acme-web", MANIFEST);

    let app_id = this_process_app_id();
    let mut d = start_with_app_id(&home, Some(&app_id), None);
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();

    let (_, unlock_pub, approve_sk, approve_pub) = sample_se_keypairs(0x11);
    let (_, _, wrong_sk, _) = sample_se_keypairs(0x22);
    enroll_se_over_socket(&mut c, &cs, &unlock_pub, &approve_pub, "Touch ID");

    // Create a session grant covering `stripe/acme-web` (currently
    // `test`-classified) and `openai/acme-web` so we can verify grant count in
    // `app.items.target` and grant termination on reclassification (F-47).
    let DecisionView::Pending { request: run_req } = c
        .run_request(&RunRequestParams {
            manifest: manifest.to_str().unwrap().to_owned(),
            profile: None,
            refs: Vec::new(),
            env_file: None,
            argv: vec!["./emit".to_owned()],
            claims: Vec::new(),
            launch: None,
            bridge: None,
            fds: Vec::new(),
        })
        .unwrap()
        .decision
    else {
        panic!("expected pending");
    };
    let run_desc = c.app_pending_get(&run_req, &[]).unwrap();
    let run_opts = ApprovalOptions::session(Duration::from_secs(600));
    let run_digest = statement_digest(&run_desc, &run_opts);
    let run_sig = hex_encode(&sign_p256_prehash(&approve_sk, &run_digest).unwrap());
    c.app_approve(&run_req, &run_opts, &run_digest, &run_sig, &[])
        .unwrap();
    assert_eq!(c.grants_list().unwrap().grants.len(), 1);

    // 1. `app.items.target` for `stripe/acme-web`: reports `grants == 1` and
    //    `prior_count == 0`.
    let t1 = c.app_items_target("stripe/acme-web", None, &[]).unwrap();
    assert_eq!(t1.slug, "stripe/acme-web");
    assert_eq!(t1.field_name.as_deref(), Some("value"));
    assert_eq!(t1.classification, ClassificationView::Test);
    assert_eq!(t1.prior_count, 0);
    assert_eq!(t1.grants, 1);

    let test_stripe_2 = stripe_key("test");
    all_cs.push(Canary::new("ROTATED_TEST_STRIPE", test_stripe_2.clone()));
    let test_secret_2 = SecretBytes::copy_from(test_stripe_2.as_bytes());
    let test_sha_2 = hex_encode(&secret_sha256(&test_secret_2));

    let live_stripe = stripe_key("live");
    all_cs.push(Canary::new("ROTATED_LIVE_STRIPE", live_stripe.clone()));
    let live_secret = SecretBytes::copy_from(live_stripe.as_bytes());
    let new_sha = hex_encode(&secret_sha256(&live_secret));

    let seal_for_target = |t: &envcloak_ipc::app::AppItemsTargetOutput, sec: &SecretBytes| {
        let daemon_pub: [u8; 32] = decode_hex(&t.daemon_eph_pub);
        let nonce: [u8; 32] = decode_hex(&t.nonce);
        let aad = se_reseal_aad(&t.target, &nonce);
        hex_encode(&seal_secret_to_x25519(&daemon_pub, &aad, sec).unwrap())
    };
    let build_rotate_stmt =
        |t: &envcloak_ipc::app::AppItemsTargetOutput, sha: &str| WriteStatement {
            target: t.target.clone(),
            nonce: t.nonce.clone(),
            vault_id: t.vault_id.clone(),
            action: WriteAction::Rotate {
                item: t.item.clone(),
                slug: t.slug.clone(),
                field: t.field.clone().unwrap(),
                field_name: t.field_name.clone().unwrap(),
                classification: t.classification.as_str().to_owned(),
                prior_count: t.prior_count,
                grants: t.grants,
                new_value_sha256: sha.to_owned(),
            },
        };

    // Mutated statement (wrong `grants` count) -> `statement_mismatch`.
    let mut bad_stmt = build_rotate_stmt(&t1, &new_sha);
    if let WriteAction::Rotate { grants, .. } = &mut bad_stmt.action {
        *grants = 99;
    }
    let (bad_digest, bad_sig) = sign_write(&approve_sk, &bad_stmt);
    let err = c
        .app_items_rotate(&AppItemsRotateParams {
            target: t1.target.clone(),
            sealed_value: seal_for_target(&t1, &live_secret),
            digest: bad_digest,
            signature: bad_sig,
            claims: Vec::new(),
        })
        .unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::StatementMismatch);

    // Replaying the consumed `t1.target` -> `no_such_request`.
    let (d1, s1) = sign_write(&approve_sk, &build_rotate_stmt(&t1, &new_sha));
    let err = c
        .app_items_rotate(&AppItemsRotateParams {
            target: t1.target.clone(),
            sealed_value: seal_for_target(&t1, &live_secret),
            digest: d1,
            signature: s1,
            claims: Vec::new(),
        })
        .unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::NoSuchRequest);

    // Sealed value with wrong AAD -> `invalid_params`.
    let t_bad_aad = c.app_items_target("stripe/acme-web", None, &[]).unwrap();
    let bad_aad_ct = hex_encode(
        &seal_secret_to_x25519(
            &decode_hex(&t_bad_aad.daemon_eph_pub),
            b"wrong-aad",
            &live_secret,
        )
        .unwrap(),
    );
    let (d_aad, s_aad) = sign_write(&approve_sk, &build_rotate_stmt(&t_bad_aad, &new_sha));
    assert_eq!(
        rpc_kind(
            c.app_items_rotate(&AppItemsRotateParams {
                target: t_bad_aad.target,
                sealed_value: bad_aad_ct,
                digest: d_aad,
                signature: s_aad,
                claims: Vec::new(),
            })
            .unwrap_err()
        )
        .0,
        ErrorKind::InvalidParams
    );

    // Signature over another nonce -> `statement_mismatch`.
    let t_nonce = c.app_items_target("stripe/acme-web", None, &[]).unwrap();
    let mut wrong_nonce_stmt = build_rotate_stmt(&t_nonce, &new_sha);
    wrong_nonce_stmt.nonce = "ff".repeat(32);
    let (d_wn, s_wn) = sign_write(&approve_sk, &wrong_nonce_stmt);
    assert_eq!(
        rpc_kind(
            c.app_items_rotate(&AppItemsRotateParams {
                target: t_nonce.target.clone(),
                sealed_value: seal_for_target(&t_nonce, &live_secret),
                digest: d_wn,
                signature: s_wn,
                claims: Vec::new(),
            })
            .unwrap_err()
        )
        .0,
        ErrorKind::StatementMismatch
    );

    // Wrong P-256 key (`wrong_sk`) -> `signature_invalid`.
    let t2 = c.app_items_target("stripe/acme-web", None, &[]).unwrap();
    let (d2_wrong, s2_wrong) = sign_write(&wrong_sk, &build_rotate_stmt(&t2, &new_sha));
    let err = c
        .app_items_rotate(&AppItemsRotateParams {
            target: t2.target.clone(),
            sealed_value: seal_for_target(&t2, &live_secret),
            digest: d2_wrong,
            signature: s2_wrong,
            claims: Vec::new(),
        })
        .unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::SignatureInvalid);

    // Same-class rotation (test -> test) keeps a prior value (`prior_count == 1`)
    // and leaves the bound grant in force (`grants_ended == 0`).
    let t_test = c.app_items_target("stripe/acme-web", None, &[]).unwrap();
    let (d_test, s_test) = sign_write(&approve_sk, &build_rotate_stmt(&t_test, &test_sha_2));
    let rotated_test = c
        .app_items_rotate(&AppItemsRotateParams {
            target: t_test.target.clone(),
            sealed_value: seal_for_target(&t_test, &test_secret_2),
            digest: d_test,
            signature: s_test,
            claims: Vec::new(),
        })
        .unwrap();
    assert_eq!(rotated_test.slug, "stripe/acme-web");
    assert_eq!(rotated_test.prior_count, 1);
    assert_eq!(rotated_test.classification, ClassificationView::Test);
    assert_eq!(rotated_test.reclassified_from, None);
    assert_eq!(rotated_test.grants_ended, 0);
    assert_eq!(c.grants_list().unwrap().grants.len(), 1);

    // Reclassifying rotation (test -> live) increments `prior_count` to 2 and
    // ends the bound grant (F-47).
    let t3 = c.app_items_target("stripe/acme-web", None, &[]).unwrap();
    assert_eq!(t3.prior_count, 1);
    assert_eq!(t3.grants, 1);
    let (d3, s3) = sign_write(&approve_sk, &build_rotate_stmt(&t3, &new_sha));
    let rotated = c
        .app_items_rotate(&AppItemsRotateParams {
            target: t3.target.clone(),
            sealed_value: seal_for_target(&t3, &live_secret),
            digest: d3,
            signature: s3,
            claims: Vec::new(),
        })
        .unwrap();
    assert_eq!(rotated.slug, "stripe/acme-web");
    assert_eq!(rotated.prior_count, 2);
    assert_eq!(rotated.classification, ClassificationView::Live);
    assert_eq!(rotated.reclassified_from, Some(ClassificationView::Test));
    assert_eq!(rotated.grants_ended, 1);
    assert!(c.grants_list().unwrap().grants.is_empty());

    // 2. `app.items.remove`: mutated statement, wrong key, then valid removal
    //    which creates an encrypted backup in `<data>/backups/` and deletes
    //    `github/acme-web`.
    let r_bad = c.app_items_target("github/acme-web", None, &[]).unwrap();
    let mut bad_rem_stmt = WriteStatement {
        target: r_bad.target.clone(),
        nonce: r_bad.nonce.clone(),
        vault_id: r_bad.vault_id.clone(),
        action: WriteAction::Remove {
            item: r_bad.item.clone(),
            slug: "openai/acme-web".to_owned(),
            grants: r_bad.grants,
        },
    };
    let (bd, bs) = sign_write(&approve_sk, &bad_rem_stmt);
    assert_eq!(
        rpc_kind(
            c.app_items_remove(&AppItemsRemoveParams {
                target: r_bad.target,
                digest: bd,
                signature: bs,
                claims: Vec::new(),
            })
            .unwrap_err()
        )
        .0,
        ErrorKind::StatementMismatch
    );

    let r_wrong = c.app_items_target("github/acme-web", None, &[]).unwrap();
    bad_rem_stmt.target.clone_from(&r_wrong.target);
    bad_rem_stmt.nonce.clone_from(&r_wrong.nonce);
    if let WriteAction::Remove { slug, .. } = &mut bad_rem_stmt.action {
        "github/acme-web".clone_into(slug);
    }
    let (wd, ws) = sign_write(&wrong_sk, &bad_rem_stmt);
    assert_eq!(
        rpc_kind(
            c.app_items_remove(&AppItemsRemoveParams {
                target: r_wrong.target,
                digest: wd,
                signature: ws,
                claims: Vec::new(),
            })
            .unwrap_err()
        )
        .0,
        ErrorKind::SignatureInvalid
    );

    let r_ok = c.app_items_target("github/acme-web", None, &[]).unwrap();
    let ok_rem_stmt = WriteStatement {
        target: r_ok.target.clone(),
        nonce: r_ok.nonce.clone(),
        vault_id: r_ok.vault_id.clone(),
        action: WriteAction::Remove {
            item: r_ok.item.clone(),
            slug: r_ok.slug.clone(),
            grants: r_ok.grants,
        },
    };
    let (ok_d, ok_s) = sign_write(&approve_sk, &ok_rem_stmt);
    let removed = c
        .app_items_remove(&AppItemsRemoveParams {
            target: r_ok.target,
            digest: ok_d,
            signature: ok_s,
            claims: Vec::new(),
        })
        .unwrap();
    assert_eq!(removed.slug, "github/acme-web");
    assert!(
        data_dir(&home)
            .join("backups")
            .join(&removed.backup)
            .is_file(),
        "expected encrypted vault backup file {} on disk",
        removed.backup
    );
    assert!(
        !c.items_list(false)
            .unwrap()
            .items
            .iter()
            .any(|i| i.slug == "github/acme-web"),
        "github/acme-web must be removed after app.items.remove"
    );

    drop(c);
    d.signal("-TERM");
    assert!(d.wait_exit(Duration::from_secs(30)).is_some());
    assert_no_canary(&d.log_bytes(), &all_cs);
    home.assert_clean(&all_cs);
}

/// Mutation Check 1: `app.items.remove` writes the encrypted vault backup
/// BEFORE deleting the item. When the backup cannot be written, `app.items.remove`
/// returns `backup_failed` and removes nothing.
#[test]
fn failed_backup_before_app_items_remove_removes_nothing() {
    common::terminal_session();
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let (_, _, all_cs) = seed_vault_with_kit(&home, &cs);

    let app_id = this_process_app_id();
    let mut d = start_with_app_id(&home, Some(&app_id), None);
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();

    let (_, unlock_pub, approve_sk, approve_pub) = sample_se_keypairs(0x31);
    enroll_se_over_socket(&mut c, &cs, &unlock_pub, &approve_pub, "Touch ID");

    let target = c.app_items_target("github/acme-web", None, &[]).unwrap();
    let stmt = WriteStatement {
        target: target.target.clone(),
        nonce: target.nonce.clone(),
        vault_id: target.vault_id.clone(),
        action: WriteAction::Remove {
            item: target.item.clone(),
            slug: target.slug.clone(),
            grants: target.grants,
        },
    };
    let (digest, sig) = sign_write(&approve_sk, &stmt);

    // Replace `<data>/backups` with a regular file so `create_backup` fails.
    let backups_dir = data_dir(&home).join("backups");
    let _ = std::fs::remove_dir_all(&backups_dir);
    std::fs::write(&backups_dir, b"blocked").unwrap();

    let err = c
        .app_items_remove(&AppItemsRemoveParams {
            target: target.target,
            digest,
            signature: sig,
            claims: Vec::new(),
        })
        .unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::BackupFailed);

    // Item `github/acme-web` must still exist in the vault (nothing removed).
    assert!(
        c.items_list(false)
            .unwrap()
            .items
            .iter()
            .any(|i| i.slug == "github/acme-web"),
        "github/acme-web must not be removed when backup before app.items.remove fails"
    );

    std::fs::remove_file(&backups_dir).unwrap();
    std::fs::create_dir(&backups_dir).unwrap();
    std::fs::set_permissions(&backups_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    drop(c);
    d.signal("-TERM");
    assert!(d.wait_exit(Duration::from_secs(30)).is_some());
    assert_no_canary(&d.log_bytes(), &all_cs);
    home.assert_clean(&all_cs);
}

/// `app.unlocker.add` and `app.unlocker.remove` (Mutation Check 3):
/// - `app.unlocker.add` enrolls a second Secure Enclave unlocker signed by the
///   first, rejects a replayed nonce (`statement_mismatch`), wrong key
///   (`signature_invalid`), and mutated statement (`statement_mismatch`).
/// - `app.unlocker.remove` removes the passphrase unlocker when a Secure
///   Enclave unlocker exists, removes one of two Secure Enclave unlockers
///   (whose `unlock` and `approve` keys are then rejected), refuses to remove
///   the Recovery Kit (`no_unlocker`), and refuses to remove the last daily /
///   Secure Enclave unlocker (`last_unlocker`, removing nothing).
#[test]
fn unlocker_add_and_remove_passphrase_se_and_last_unlocker_guards() {
    common::terminal_session();
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let (vault_id, kit_id, all_cs) = seed_vault_with_kit(&home, &cs);

    let app_id = this_process_app_id();
    let mut d = start_with_app_id(&home, Some(&app_id), None);
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();

    let (unlock_sk_1, unlock_pub_1, approve_sk_1, approve_pub_1) = sample_se_keypairs(0x41);
    let (unlock_sk_2, unlock_pub_2, approve_sk_2, approve_pub_2) = sample_se_keypairs(0x51);
    let (_, _, wrong_sk, _) = sample_se_keypairs(0x61);

    let uid_1 = enroll_se_over_socket(&mut c, &cs, &unlock_pub_1, &approve_pub_1, "Touch ID 1");

    // Before adding a second SE unlocker: removing `uid_1` would leave the
    // vault with zero Secure Enclave unlockers -> refused with `last_unlocker`!
    let nonce_last_se = hex_encode(&[0xaa; 32]);
    let stmt_last_se = WriteStatement {
        target: "unlocker_remove".to_owned(),
        nonce: nonce_last_se.clone(),
        vault_id: hex_encode(&vault_id.0),
        action: WriteAction::UnlockerRemove {
            unlocker: UnlockerTarget::SecureEnclave {
                unlocker_id: uid_1.clone(),
                label: "Touch ID 1".to_owned(),
                unlock_pub_sha256: hex_encode(&p256_fingerprint(&unlock_pub_1)),
                approve_pub_sha256: hex_encode(&p256_fingerprint(&approve_pub_1)),
            },
        },
    };
    let (d_last_se, s_last_se) = sign_write(&approve_sk_1, &stmt_last_se);
    let err = c
        .app_unlocker_remove(&AppUnlockerRemoveParams {
            unlocker: uid_1.clone(),
            nonce: nonce_last_se,
            digest: d_last_se,
            signature: s_last_se,
            created_secs: 1_800_000_000,
            claims: Vec::new(),
        })
        .unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::LastUnlocker);

    // Removing the Recovery Kit (by keyword `"recovery_kit"` or by its hex id)
    // is refused with `no_unlocker`.
    for rk in ["recovery_kit".to_owned(), hex_encode(&kit_id.0)] {
        let err = c
            .app_unlocker_remove(&AppUnlockerRemoveParams {
                unlocker: rk,
                nonce: hex_encode(&[0xab; 32]),
                digest: "00".repeat(32),
                signature: "00".repeat(64),
                created_secs: 1_800_000_000,
                claims: Vec::new(),
            })
            .unwrap_err();
        assert_eq!(rpc_kind(err).0, ErrorKind::NoUnlocker);
    }

    // `app.unlocker.add`: enroll a second SE unlocker ("Touch ID 2") signed by
    // `approve_sk_1`.
    let nonce_add = hex_encode(&[0xac; 32]);
    let add_stmt = WriteStatement {
        target: "unlocker_add".to_owned(),
        nonce: nonce_add.clone(),
        vault_id: hex_encode(&vault_id.0),
        action: WriteAction::UnlockerAdd {
            label: "Touch ID 2".to_owned(),
            unlock_pub_sha256: hex_encode(&p256_fingerprint(&unlock_pub_2)),
            approve_pub_sha256: hex_encode(&p256_fingerprint(&approve_pub_2)),
            team_id: TEST_TEAM_ID.to_owned(),
            signing_id: TEST_SIGNING_ID.to_owned(),
        },
    };
    // Wrong key -> `signature_invalid`.
    let (d_add_wrong, s_add_wrong) = sign_write(&wrong_sk, &add_stmt);
    assert_eq!(
        rpc_kind(
            c.app_unlocker_add(&AppUnlockerAddParams {
                label: "Touch ID 2".to_owned(),
                unlock_pub: hex_encode(&unlock_pub_2),
                approve_pub: hex_encode(&approve_pub_2),
                nonce: nonce_add.clone(),
                digest: d_add_wrong,
                signature: s_add_wrong,
                created_secs: 1_800_000_000,
                claims: Vec::new(),
            })
            .unwrap_err()
        )
        .0,
        ErrorKind::SignatureInvalid
    );

    // Valid signature -> enrolls `uid_2`.
    let (d_add, s_add) = sign_write(&approve_sk_1, &add_stmt);
    let added = c
        .app_unlocker_add(&AppUnlockerAddParams {
            label: "Touch ID 2".to_owned(),
            unlock_pub: hex_encode(&unlock_pub_2),
            approve_pub: hex_encode(&approve_pub_2),
            nonce: nonce_add.clone(),
            digest: d_add.clone(),
            signature: s_add.clone(),
            created_secs: 1_800_000_000,
            claims: Vec::new(),
        })
        .unwrap();
    let uid_2 = added.unlocker_id;

    // Replaying the same nonce in `app.unlocker.add` -> `statement_mismatch`.
    assert_eq!(
        rpc_kind(
            c.app_unlocker_add(&AppUnlockerAddParams {
                label: "Touch ID 2".to_owned(),
                unlock_pub: hex_encode(&unlock_pub_2),
                approve_pub: hex_encode(&approve_pub_2),
                nonce: nonce_add,
                digest: d_add,
                signature: s_add,
                created_secs: 1_800_000_000,
                claims: Vec::new(),
            })
            .unwrap_err()
        )
        .0,
        ErrorKind::StatementMismatch
    );

    // Remove the passphrase unlocker (`"passphrase"`), signed by `approve_sk_2`!
    let nonce_rm_pass = hex_encode(&[0xad; 32]);
    let rm_pass_stmt = WriteStatement {
        target: "unlocker_remove".to_owned(),
        nonce: nonce_rm_pass.clone(),
        vault_id: hex_encode(&vault_id.0),
        action: WriteAction::UnlockerRemove {
            unlocker: UnlockerTarget::Passphrase,
        },
    };
    let (d_rm_pass, s_rm_pass) = sign_write(&approve_sk_2, &rm_pass_stmt);
    let removed_pass = c
        .app_unlocker_remove(&AppUnlockerRemoveParams {
            unlocker: "passphrase".to_owned(),
            nonce: nonce_rm_pass,
            digest: d_rm_pass,
            signature: s_rm_pass,
            created_secs: 1_800_000_000,
            claims: Vec::new(),
        })
        .unwrap();
    assert_eq!(removed_pass.removed.len(), 32);

    // Remove `uid_1` (now allowed since `uid_2` remains).
    let nonce_rm_se1 = hex_encode(&[0xae; 32]);
    let rm_se1_stmt = WriteStatement {
        target: "unlocker_remove".to_owned(),
        nonce: nonce_rm_se1.clone(),
        vault_id: hex_encode(&vault_id.0),
        action: WriteAction::UnlockerRemove {
            unlocker: UnlockerTarget::SecureEnclave {
                unlocker_id: uid_1.clone(),
                label: "Touch ID 1".to_owned(),
                unlock_pub_sha256: hex_encode(&p256_fingerprint(&unlock_pub_1)),
                approve_pub_sha256: hex_encode(&p256_fingerprint(&approve_pub_1)),
            },
        },
    };
    let (d_rm_se1, s_rm_se1) = sign_write(&approve_sk_2, &rm_se1_stmt);
    let removed_se1 = c
        .app_unlocker_remove(&AppUnlockerRemoveParams {
            unlocker: uid_1.clone(),
            nonce: nonce_rm_se1,
            digest: d_rm_se1,
            signature: s_rm_se1,
            created_secs: 1_800_000_000,
            claims: Vec::new(),
        })
        .unwrap();
    assert_eq!(removed_se1.removed, uid_1);

    // Removed unlocker `uid_1`'s `approve_sk_1` is now rejected with
    // `signature_invalid`!
    let nonce_rm_se2 = hex_encode(&[0xaf; 32]);
    let rm_se2_stmt = WriteStatement {
        target: "unlocker_remove".to_owned(),
        nonce: nonce_rm_se2.clone(),
        vault_id: hex_encode(&vault_id.0),
        action: WriteAction::UnlockerRemove {
            unlocker: UnlockerTarget::SecureEnclave {
                unlocker_id: uid_2.clone(),
                label: "Touch ID 2".to_owned(),
                unlock_pub_sha256: hex_encode(&p256_fingerprint(&unlock_pub_2)),
                approve_pub_sha256: hex_encode(&p256_fingerprint(&approve_pub_2)),
            },
        },
    };
    let (d_by_removed, s_by_removed) = sign_write(&approve_sk_1, &rm_se2_stmt);
    assert_eq!(
        rpc_kind(
            c.app_unlocker_remove(&AppUnlockerRemoveParams {
                unlocker: uid_2.clone(),
                nonce: nonce_rm_se2.clone(),
                digest: d_by_removed,
                signature: s_by_removed,
                created_secs: 1_800_000_000,
                claims: Vec::new(),
            })
            .unwrap_err()
        )
        .0,
        ErrorKind::SignatureInvalid
    );

    // Removing `uid_2` (now the LAST daily unlocker) with `approve_sk_2` is
    // refused with `last_unlocker` (Mutation Check 3)!
    let (d_last, s_last) = sign_write(&approve_sk_2, &rm_se2_stmt);
    assert_eq!(
        rpc_kind(
            c.app_unlocker_remove(&AppUnlockerRemoveParams {
                unlocker: uid_2.clone(),
                nonce: nonce_rm_se2,
                digest: d_last,
                signature: s_last,
                created_secs: 1_800_000_000,
                claims: Vec::new(),
            })
            .unwrap_err()
        )
        .0,
        ErrorKind::LastUnlocker
    );

    // Trying to remove `"passphrase"` a second time returns `no_unlocker`.
    assert_eq!(
        rpc_kind(
            c.app_unlocker_remove(&AppUnlockerRemoveParams {
                unlocker: "passphrase".to_owned(),
                nonce: hex_encode(&[0xb0; 32]),
                digest: "00".repeat(32),
                signature: "00".repeat(64),
                created_secs: 1_800_000_000,
                claims: Vec::new(),
            })
            .unwrap_err()
        )
        .0,
        ErrorKind::NoUnlocker
    );

    // Lock the vault: passphrase unlock now returns `wrong_passphrase` (gate 3),
    // `uid_1` returns `no_unlocker`, and `uid_2` unlocks the vault!
    c.lock().unwrap();
    assert_eq!(
        rpc_kind(c.unlock(passphrase(&cs), &[]).unwrap_err()).0,
        ErrorKind::WrongPassphrase
    );
    assert_eq!(
        rpc_kind(c.app_unlock_begin(Some(&uid_1), &[]).unwrap_err()).0,
        ErrorKind::NoUnlocker
    );
    let _ = unlock_sk_1;
    let begin_u2 = c.app_unlock_begin(Some(&uid_2), &[]).unwrap();
    let vmk = open_se_envelope(
        &unlock_sk_2,
        vault_id,
        UnlockerId(decode_hex(&uid_2)),
        begin_u2.epoch,
        &SeHpkeEnvelope {
            enc: decode_hex::<SE_HPKE_ENC_LEN>(&begin_u2.envelope.enc),
            ciphertext: decode_hex::<SE_HPKE_CIPHERTEXT_LEN>(&begin_u2.envelope.ciphertext),
        },
    )
    .unwrap();
    let challenge = decode_hex::<SE_CHALLENGE_LEN>(&begin_u2.challenge);
    let daemon_pub: [u8; 32] = decode_hex(&begin_u2.daemon_eph_pub);
    let sealed_vmk =
        seal_vmk_to_daemon(&daemon_pub, &begin_u2.request_id, &challenge, &vmk).unwrap();
    let unlocked = c
        .app_unlock(&begin_u2.request_id, &hex_encode(&sealed_vmk), &[])
        .unwrap();
    assert!(!unlocked.already);

    drop(c);
    d.signal("-TERM");
    assert!(d.wait_exit(Duration::from_secs(30)).is_some());

    // Verify durable `unlocker_remove` (kind 47) entries in the audit log.
    let paths = VaultPaths::under(data_dir(&home));
    let lv = LockedVault::open(&paths).unwrap();
    let v = lv.unlock(vmk).unwrap();
    let (entries, report) = v.read_audit().unwrap();
    assert_eq!(report.problems, 0);
    let remove_entries: Vec<_> = entries
        .iter()
        .filter(|e| e.record.kind == AuditKind::UnlockerRemove)
        .collect();
    assert_eq!(
        remove_entries.len(),
        2,
        "expected 2 UnlockerRemove audit records (passphrase and uid_1)"
    );
    drop(v);

    assert_no_canary(&d.log_bytes(), &all_cs);
    home.assert_clean(&all_cs);
}

/// Signed reveal (`reveal.request`, `app.reveal.begin`, `app.reveal`) and
/// Mutation Check 2 (durable `reveal_app` audit entry flushed BEFORE release):
/// - `reveal.request` from an agent (claims or `fixture-agent` ancestry) is
///   refused with `proof_refused` before anything is filed.
/// - `reveal.request` from a terminal opens a pending reveal request and
///   increments `status().app_requests`.
/// - `app.reveal.begin` (by `request` or by `slug`) + `app.reveal` verifies
///   `envcloak-reveal-statement/1`, rejects wrong key, removed key, mutated
///   statement, and replayed request, and when `<data>/audit` is blocked
///   returns `audit_failed` releasing nothing (Mutation Check 2).
/// - All recorded wire frames carry the secret value ONLY inside the HPKE
///   ciphertext (swept across all §6.1 encodings with a positive control).
#[test]
fn signed_reveal_and_failed_audit_write_before_app_reveal_releases_nothing() {
    common::terminal_session();
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let (_, _, all_cs) = seed_vault_with_kit(&home, &cs);

    let app_id = this_process_app_id();
    let mut d = start_with_app_id(&home, Some(&app_id), None);
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();

    let (_, unlock_pub, approve_sk, approve_pub) = sample_se_keypairs(0x71);
    let (_, _, wrong_sk, _) = sample_se_keypairs(0x73);
    enroll_se_over_socket(&mut c, &cs, &unlock_pub, &approve_pub, "Touch ID");

    // 1. `reveal.request` from an agent (by claims and by `fixture-agent`
    //    ancestry) is refused with `proof_refused` before anything is filed.
    let agent_claims = vec!["CURSOR_AGENT".to_owned()];
    assert_eq!(
        rpc_kind(
            c.reveal_request("openai/acme-web", None, &agent_claims)
                .unwrap_err()
        )
        .0,
        ErrorKind::ProofRefused
    );
    let agent_exe = home.root().join("fixture-agent");
    std::fs::copy(std::env::current_exe().unwrap(), &agent_exe).unwrap();
    std::fs::set_permissions(&agent_exe, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut agent_cmd = Command::new(&agent_exe);
    home.apply(&mut agent_cmd)
        .args([
            "--exact",
            "fixture_agent_reveal_request_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(AGENT_REVEAL_ENV, daemon_run_dir(&home))
        .stdin(Stdio::null());
    let agent_out = agent_cmd.output().unwrap();
    assert!(
        agent_out.status.success()
            && String::from_utf8_lossy(&agent_out.stdout).contains("@@ agent_reveal_refused_ok"),
        "fixture_agent_reveal_request_child failed: {:?}",
        String::from_utf8_lossy(&agent_out.stderr)
    );
    assert_eq!(c.status().unwrap().app_requests, 0);

    // 2. `reveal.request` from a terminal opens a pending request and bumps
    //    `status().app_requests` to 1.
    let req = c.reveal_request("openai/acme-web", None, &[]).unwrap();
    assert_eq!(c.status().unwrap().app_requests, 1);

    let proxy = RecordingProxy::start(&home);
    let mut proxy_c = proxy.connect();

    let desc = proxy_c
        .app_reveal_begin(&AppRevealBeginParams {
            request: Some(req.request.clone()),
            slug: None,
            field: None,
            claims: Vec::new(),
        })
        .unwrap();
    assert_eq!(desc.request, req.request);
    assert_eq!(desc.slug, "openai/acme-web");
    assert!(desc.requester.is_some());

    let app_eph = SeEphemeralKey::generate().unwrap();
    let app_eph_pub_hex = hex_encode(app_eph.public_key());

    // Mutated statement -> `statement_mismatch`.
    let mut bad_desc = desc.clone();
    "stripe/acme-web".clone_into(&mut bad_desc.slug);
    let bad_digest = reveal_statement_digest(&bad_desc);
    let bad_sig = sign_p256_prehash(&approve_sk, &bad_digest).unwrap();
    assert_eq!(
        rpc_kind(
            proxy_c
                .app_reveal(&AppRevealParams {
                    request: req.request.clone(),
                    digest: hex_encode(&bad_digest),
                    signature: hex_encode(&bad_sig),
                    app_eph_pub: app_eph_pub_hex.clone(),
                    claims: Vec::new(),
                })
                .unwrap_err()
        )
        .0,
        ErrorKind::StatementMismatch
    );

    // Wrong key -> `signature_invalid`.
    let digest = reveal_statement_digest(&desc);
    let wrong_sig = sign_p256_prehash(&wrong_sk, &digest).unwrap();
    assert_eq!(
        rpc_kind(
            proxy_c
                .app_reveal(&AppRevealParams {
                    request: req.request.clone(),
                    digest: hex_encode(&digest),
                    signature: hex_encode(&wrong_sig),
                    app_eph_pub: app_eph_pub_hex.clone(),
                    claims: Vec::new(),
                })
                .unwrap_err()
        )
        .0,
        ErrorKind::SignatureInvalid
    );

    // 3. Mutation Check 2: block `<data>/audit` so the durable `reveal_app`
    //    audit write fails -> `app.reveal` returns `audit_failed`, releases
    //    nothing, and keeps the pending reveal open.
    let sig = sign_p256_prehash(&approve_sk, &digest).unwrap();
    let audit_dir = data_dir(&home).join("audit");
    std::fs::remove_dir_all(&audit_dir).unwrap();
    std::fs::write(&audit_dir, b"blocked").unwrap();

    let err = proxy_c
        .app_reveal(&AppRevealParams {
            request: req.request.clone(),
            digest: hex_encode(&digest),
            signature: hex_encode(&sig),
            app_eph_pub: app_eph_pub_hex.clone(),
            claims: Vec::new(),
        })
        .unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::AuditFailed);
    assert_eq!(
        c.status().unwrap().app_requests,
        1,
        "pending reveal must remain open when durable audit write fails"
    );

    // Restore `<data>/audit` and retry: `app.reveal` now succeeds and seals
    // the secret to `app_eph_pub` with AAD `request || nonce`.
    std::fs::remove_file(&audit_dir).unwrap();
    std::fs::create_dir(&audit_dir).unwrap();
    std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    let revealed = proxy_c
        .app_reveal(&AppRevealParams {
            request: req.request.clone(),
            digest: hex_encode(&digest),
            signature: hex_encode(&sig),
            app_eph_pub: app_eph_pub_hex.clone(),
            claims: Vec::new(),
        })
        .unwrap();
    assert_eq!(c.status().unwrap().app_requests, 0);
    // Replaying the same `app.reveal` request -> `no_such_request`.
    assert_eq!(
        rpc_kind(
            proxy_c
                .app_reveal(&AppRevealParams {
                    request: req.request,
                    digest: hex_encode(&digest),
                    signature: hex_encode(&sig),
                    app_eph_pub: app_eph_pub_hex,
                    claims: Vec::new(),
                })
                .unwrap_err()
        )
        .0,
        ErrorKind::NoSuchRequest
    );

    // 4. App-initiated reveal (`app.reveal.begin` with `slug: Some("stripe/acme-web")`).
    let direct_desc = proxy_c
        .app_reveal_begin(&AppRevealBeginParams {
            request: None,
            slug: Some("stripe/acme-web".to_owned()),
            field: None,
            claims: Vec::new(),
        })
        .unwrap();
    assert!(direct_desc.requester.is_none());
    let direct_digest = reveal_statement_digest(&direct_desc);
    let direct_sig = sign_p256_prehash(&approve_sk, &direct_digest).unwrap();
    let app_eph_2 = SeEphemeralKey::generate().unwrap();
    let direct_out = proxy_c
        .app_reveal(&AppRevealParams {
            request: direct_desc.request.clone(),
            digest: hex_encode(&direct_digest),
            signature: hex_encode(&direct_sig),
            app_eph_pub: hex_encode(app_eph_2.public_key()),
            claims: Vec::new(),
        })
        .unwrap();
    drop(proxy_c);

    // Sweep every recorded wire frame for every canary across all §6.1
    // encodings BEFORE opening the sealed ciphertexts, with a positive control!
    let frames = proxy.recorded();
    assert!(!frames.is_empty());
    let all_detector = Detector::new(&all_cs);
    for (idx, frame) in frames.iter().enumerate() {
        let hits = all_detector.find(frame);
        assert!(
            hits.is_empty(),
            "secret leak in recorded app.reveal frame {idx}: {hits:?}"
        );
    }
    let openai_canary = by_label(&cs, labels::OPENAI_API_KEY);
    for (enc_name, enc_bytes) in encodings(openai_canary).iter().take(6) {
        let mut planted = frames[0].clone();
        planted.extend_from_slice(enc_bytes);
        assert!(
            !all_detector.find(&planted).is_empty(),
            "positive control failed for encoding {enc_name}"
        );
    }

    let nonce_bytes: [u8; 32] = decode_hex(&desc.nonce);
    let aad = se_reseal_aad(&desc.request, &nonce_bytes);
    let opened = app_eph
        .open_secret(&aad, &decode_hex_vec(&revealed.sealed_value))
        .unwrap();
    assert_secret_eq(&opened, by_label(&cs, labels::OPENAI_API_KEY).value());
    drop(opened);

    let direct_nonce: [u8; 32] = decode_hex(&direct_desc.nonce);
    let direct_aad = se_reseal_aad(&direct_desc.request, &direct_nonce);
    let direct_opened = app_eph_2
        .open_secret(&direct_aad, &decode_hex_vec(&direct_out.sealed_value))
        .unwrap();
    assert_secret_eq(
        &direct_opened,
        by_label(&cs, labels::STRIPE_SECRET_KEY).value(),
    );
    drop(direct_opened);

    drop(c);
    d.signal("-TERM");
    assert!(d.wait_exit(Duration::from_secs(30)).is_some());
    assert_no_canary(&d.log_bytes(), &all_cs);
    home.assert_clean(&all_cs);
}

/// Sealed paste (`app.paste.begin`, `app.paste.inspect`, `app.paste`) round-trip
/// and 2-minute awake-clock expiry, plus asks (`items.ask`, `items.ask_state`,
/// `app.asks.list`, `app.asks.decline`) answered, declined, expired, polled
/// from another process tree (`unknown`, Mutation Check 4), and creating no
/// grant when answered (Mutation Check 5).
#[test]
fn asks_answered_declined_expired_other_tree_unknown_and_no_grant() {
    common::terminal_session();
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let (_, _, mut all_cs) = seed_vault_with_kit(&home, &cs);
    let clock_file = home.root().join("clock-offset");
    std::fs::write(&clock_file, "0").unwrap();

    let app_id = this_process_app_id();
    let mut d = start_with_app_id(&home, Some(&app_id), Some(&clock_file));
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();

    // 1. Sealed paste 2-minute expiry: `app.paste.begin` + `app.paste.inspect`,
    //    then advance clock by 125s -> `app.paste` returns `no_such_request`.
    let stage_exp = c.app_paste_begin(&[]).unwrap();
    assert_eq!(stage_exp.expires_in_secs, 120);
    let pasted_test = stripe_key("test");
    all_cs.push(Canary::new("PASTED_STRIPE_TEST", pasted_test.clone()));
    let pasted_secret = SecretBytes::copy_from(pasted_test.as_bytes());
    let sealed_exp = seal_secret_to_x25519(
        &decode_hex(&stage_exp.daemon_eph_pub),
        stage_exp.stage.as_bytes(),
        &pasted_secret,
    )
    .unwrap();
    let inspected = c
        .app_paste_inspect(&stage_exp.stage, &hex_encode(&sealed_exp), &[])
        .unwrap();
    assert_eq!(inspected.provider.as_deref(), Some("stripe"));
    assert_eq!(inspected.classification, ClassificationView::Test);
    assert_eq!(inspected.length, LengthClass::Ok);
    assert_eq!(inspected.suggested_slug.as_deref(), Some("stripe"));
    assert_eq!(inspected.env_hint.as_deref(), Some("STRIPE_SECRET_KEY"));

    std::fs::write(&clock_file, "125").unwrap();
    let err = c
        .app_paste(&AppPasteParams {
            stage: stage_exp.stage,
            slug: None,
            provider: None,
            field: None,
            account: None,
            env_hint: None,
            allow_short: false,
            ask: None,
            claims: Vec::new(),
        })
        .unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::NoSuchRequest);

    // 2. `items.ask` rejects any field shaped like a secret (`looks_like_value`).
    assert_eq!(
        rpc_kind(
            c.items_ask(&AskParams {
                provider: None,
                project_dir: None,
                account: None,
                env_hint: None,
                note: Some(pasted_test.clone()),
                claims: Vec::new(),
            })
            .unwrap_err()
        ),
        (ErrorKind::InvalidItem, Some("looks_like_value"))
    );

    // 3. Spawn two `fixture-agent` children (`agent_1` and `agent_2`). Each
    //    has its own `ProcessInstance` as its `SubjectEvidence::root()`,
    //    distinct from each other and from this parent test process.
    let agent_exe = home.root().join("fixture-agent");
    std::fs::copy(std::env::current_exe().unwrap(), &agent_exe).unwrap();
    std::fs::set_permissions(&agent_exe, std::fs::Permissions::from_mode(0o700)).unwrap();

    let spawn_agent = || {
        let mut cmd = Command::new(&agent_exe);
        home.apply(&mut cmd)
            .args([
                "--exact",
                "other_tree_poll_ask_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(OTHER_TREE_POLL_ENV, daemon_run_dir(&home))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        (child, stdin, stdout)
    };
    let send_agent = |stdin: &mut std::process::ChildStdin,
                      stdout: &mut std::io::BufReader<std::process::ChildStdout>,
                      cmd_line: &str|
     -> String {
        use std::io::BufRead as _;
        writeln!(stdin, "{cmd_line}").unwrap();
        stdin.flush().unwrap();
        let mut buf = String::new();
        while stdout.read_line(&mut buf).unwrap() > 0 {
            if let Some((_, rest)) = buf.trim().split_once("@@ ") {
                return rest.to_owned();
            }
            buf.clear();
        }
        panic!("agent child exited without @@ response for {cmd_line}");
    };

    let (mut agent_1, mut in_1, mut out_1) = spawn_agent();
    let (mut agent_2, mut in_2, mut out_2) = spawn_agent();

    let ask_via_agent = |stdin: &mut std::process::ChildStdin,
                         stdout: &mut std::io::BufReader<std::process::ChildStdout>,
                         params: &AskParams|
     -> String {
        let line = format!("ask {}", serde_json::to_string(params).unwrap());
        send_agent(stdin, stdout, &line)
    };
    let state_via_agent = |stdin: &mut std::process::ChildStdin,
                           stdout: &mut std::io::BufReader<std::process::ChildStdout>,
                           ask_id: &str|
     -> AskStateOutcome {
        let raw = send_agent(stdin, stdout, &format!("state {ask_id}"));
        serde_json::from_str(&raw).unwrap()
    };
    let mut poll_other_trees = |c: &mut Client, ask_id: &str| {
        assert_eq!(
            c.items_ask_state(ask_id).unwrap(),
            AskStateOutcome::Unknown,
            "parent terminal tree must receive Unknown for {ask_id}"
        );
        let raw = send_agent(&mut in_2, &mut out_2, &format!("state {ask_id}"));
        let state: AskStateOutcome = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            state,
            AskStateOutcome::Unknown,
            "sibling agent tree must receive Unknown for {ask_id}"
        );
    };

    let proj_dir = home.home().join("proj-ask");
    std::fs::create_dir_all(&proj_dir).unwrap();
    let ask_add = ask_via_agent(
        &mut in_1,
        &mut out_1,
        &AskParams {
            provider: Some("stripe".to_owned()),
            project_dir: Some(proj_dir.to_str().unwrap().to_owned()),
            account: Some("billing".to_owned()),
            env_hint: Some("STRIPE_SECRET_KEY".to_owned()),
            note: Some("Need Stripe test key".to_owned()),
            claims: Vec::new(),
        },
    );
    let ask_dec = ask_via_agent(
        &mut in_1,
        &mut out_1,
        &AskParams {
            provider: Some("openai".to_owned()),
            project_dir: None,
            account: None,
            env_hint: Some("OPENAI_API_KEY".to_owned()),
            note: Some("Need OpenAI key".to_owned()),
            claims: Vec::new(),
        },
    );
    let ask_exp = ask_via_agent(
        &mut in_1,
        &mut out_1,
        &AskParams {
            provider: None,
            project_dir: None,
            account: None,
            env_hint: Some("CUSTOM_TOKEN".to_owned()),
            note: Some("Will expire".to_owned()),
            claims: Vec::new(),
        },
    );
    assert_eq!(c.status().unwrap().app_requests, 3);
    let listed = c.app_asks_list(&[]).unwrap();
    assert_eq!(listed.asks.len(), 3);
    assert_eq!(listed.asks[0].ask, ask_add);
    assert_eq!(listed.asks[1].ask, ask_dec);
    assert_eq!(listed.asks[2].ask, ask_exp);

    assert_eq!(
        state_via_agent(&mut in_1, &mut out_1, &ask_add),
        AskStateOutcome::Pending
    );

    // Mutation Check 4: polling `items.ask_state` from another process tree
    // returns `AskStateOutcome::Unknown`!
    poll_other_trees(&mut c, &ask_add);

    // 4. Answer `ask_add` via `app.paste.begin` -> `app.paste.inspect` -> `app.paste`.
    let stage_ok = c.app_paste_begin(&[]).unwrap();
    let sealed_ok = seal_secret_to_x25519(
        &decode_hex(&stage_ok.daemon_eph_pub),
        stage_ok.stage.as_bytes(),
        &pasted_secret,
    )
    .unwrap();
    c.app_paste_inspect(&stage_ok.stage, &hex_encode(&sealed_ok), &[])
        .unwrap();
    let added = c
        .app_paste(&AppPasteParams {
            stage: stage_ok.stage.clone(),
            slug: Some("stripe-asked".to_owned()),
            provider: Some("stripe".to_owned()),
            field: None,
            account: Some("billing".to_owned()),
            env_hint: Some("STRIPE_SECRET_KEY".to_owned()),
            allow_short: false,
            ask: Some(ask_add.clone()),
            claims: Vec::new(),
        })
        .unwrap();
    assert_eq!(added.item.slug, "stripe-asked");
    assert_eq!(c.status().unwrap().app_requests, 2);
    assert_eq!(
        state_via_agent(&mut in_1, &mut out_1, &ask_add),
        AskStateOutcome::Added {
            slug: "stripe-asked".to_owned()
        }
    );
    poll_other_trees(&mut c, &ask_add);

    // Mutation Check 5: answering an ask creates NO grant for the asking
    // agent's root (or any other root)!
    assert!(
        c.grants_list().unwrap().grants.is_empty(),
        "answering an ask via app.paste must never create a grant"
    );
    let ask_manifest = project(
        &home,
        "proj-ask",
        "[project]\nname = \"proj-ask\"\n\n[env]\nSTRIPE_SECRET_KEY = \"stripe-asked\"\n",
    );
    let agent_run_decision = send_agent(
        &mut in_1,
        &mut out_1,
        &format!("run {}", ask_manifest.display()),
    );
    assert_eq!(
        agent_run_decision, "pending",
        "answering an ask must not cover the asking agent's run request without approval"
    );

    // Declining an already-answered ask returns `ask_closed`.
    assert_eq!(
        rpc_kind(c.app_asks_decline(&ask_add, &[]).unwrap_err()).0,
        ErrorKind::AskClosed
    );

    // 5. Decline `ask_dec` via `app.asks.decline`.
    let dec_out = c.app_asks_decline(&ask_dec, &[]).unwrap();
    assert_eq!(dec_out.declined, ask_dec);
    assert_eq!(c.status().unwrap().app_requests, 1);
    assert_eq!(
        state_via_agent(&mut in_1, &mut out_1, &ask_dec),
        AskStateOutcome::Declined
    );
    poll_other_trees(&mut c, &ask_dec);
    assert_eq!(
        rpc_kind(c.app_asks_decline(&ask_dec, &[]).unwrap_err()).0,
        ErrorKind::AskClosed
    );

    // 6. Advance clock past 600s (`PENDING_TTL`) so `ask_exp` expires.
    std::fs::write(&clock_file, "750").unwrap();
    assert_eq!(c.status().unwrap().app_requests, 0);
    assert_eq!(
        state_via_agent(&mut in_1, &mut out_1, &ask_exp),
        AskStateOutcome::Expired
    );
    poll_other_trees(&mut c, &ask_exp);
    assert_eq!(
        rpc_kind(c.app_asks_decline(&ask_exp, &[]).unwrap_err()).0,
        ErrorKind::AskClosed
    );

    writeln!(in_1, "quit").unwrap();
    writeln!(in_2, "quit").unwrap();
    drop(in_1);
    drop(in_2);
    let _ = agent_1.wait();
    let _ = agent_2.wait();

    drop(c);
    d.signal("-TERM");
    assert!(d.wait_exit(Duration::from_secs(30)).is_some());
    assert_no_canary(&d.log_bytes(), &all_cs);
    home.assert_clean(&all_cs);
}

/// Role separation (`role_denied`, gate 22) and agent refusal (`proof_refused`,
/// SPEC §10b) across all 12 new `app.*` methods added in M3-14.
#[test]
fn role_denied_and_agent_proof_refused_on_all_m3_14_app_methods() {
    common::terminal_session();
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let (_, _, all_cs) = seed_vault_with_kit(&home, &cs);

    let methods_and_params = |claims: serde_json::Value| {
        vec![
            (
                "app.unlocker.add",
                json!({
                    "label": "Touch ID",
                    "unlock_pub": "00".repeat(65),
                    "approve_pub": "00".repeat(65),
                    "nonce": "00".repeat(32),
                    "digest": "00".repeat(32),
                    "signature": "00".repeat(64),
                    "created_secs": 1,
                    "claims": claims,
                }),
            ),
            (
                "app.unlocker.remove",
                json!({
                    "unlocker": "passphrase",
                    "nonce": "00".repeat(32),
                    "digest": "00".repeat(32),
                    "signature": "00".repeat(64),
                    "created_secs": 1,
                    "claims": claims,
                }),
            ),
            (
                "app.items.target",
                json!({"slug": "openai/acme-web", "claims": claims}),
            ),
            (
                "app.items.rotate",
                json!({
                    "target": "4KQ7M2XD",
                    "sealed_value": "00",
                    "digest": "00".repeat(32),
                    "signature": "00".repeat(64),
                    "claims": claims,
                }),
            ),
            (
                "app.items.remove",
                json!({
                    "target": "4KQ7M2XD",
                    "digest": "00".repeat(32),
                    "signature": "00".repeat(64),
                    "claims": claims,
                }),
            ),
            (
                "app.reveal.begin",
                json!({"slug": "openai/acme-web", "claims": claims}),
            ),
            (
                "app.reveal",
                json!({
                    "request": "4KQ7M2XD",
                    "digest": "00".repeat(32),
                    "signature": "00".repeat(64),
                    "app_eph_pub": "00".repeat(32),
                    "claims": claims,
                }),
            ),
            ("app.paste.begin", json!({"claims": claims})),
            (
                "app.paste.inspect",
                json!({
                    "stage": "4KQ7M2XD",
                    "sealed": "00",
                    "claims": claims,
                }),
            ),
            (
                "app.paste",
                json!({
                    "stage": "4KQ7M2XD",
                    "claims": claims,
                }),
            ),
            ("app.asks.list", json!({"claims": claims})),
            (
                "app.asks.decline",
                json!({"ask": "4KQ7M2XD", "claims": claims}),
            ),
        ]
    };

    // 1. Client peer (no `APP_IDENTITY`) -> `role_denied` on all 12 methods.
    let d_client = start_with_app_id(&home, None, None);
    for (method, params) in methods_and_params(json!([])) {
        let mut s = raw(&home);
        send_json(
            &mut s,
            &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
        );
        let r = read_json(&mut s).unwrap();
        assert_eq!(error_kind(&r), "role_denied", "{method}: {r}");
    }
    let client_log = d_client.log();
    for (method, _) in methods_and_params(json!([])) {
        assert!(
            client_log.contains(&format!(
                "audit: denied method={method} reason=role_denied role=client pid="
            )),
            "missing role_denied audit for {method}:\n{client_log}"
        );
    }
    drop(d_client);

    // 2. Admitted `app` peer with agent claims (`CURSOR_AGENT`) ->
    //    `proof_refused` on all 12 methods.
    let app_id = this_process_app_id();
    let d_app = start_with_app_id(&home, Some(&app_id), None);
    for (method, params) in methods_and_params(json!(["CURSOR_AGENT"])) {
        let mut s = raw(&home);
        send_json(
            &mut s,
            &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
        );
        let r = read_json(&mut s).unwrap();
        assert_eq!(error_kind(&r), "proof_refused", "{method}: {r}");
    }
    let app_log = d_app.log();
    for (method, _) in methods_and_params(json!(["CURSOR_AGENT"])) {
        assert!(
            app_log.contains(&format!(
                "audit: proof refused method={method} reason=agent pid="
            )),
            "missing proof_refused audit for {method}:\n{app_log}"
        );
    }
    assert_no_canary(&d_app.log_bytes(), &all_cs);
    drop(d_app);
    home.assert_clean(&all_cs);
}
