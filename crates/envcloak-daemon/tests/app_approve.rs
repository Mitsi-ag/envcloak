//! Pending run list, descriptor fetch, and Secure Enclave signed run approvals
//! from the native macOS app over the daemon's socket (SPEC §10a, §10b, §12,
//! §15.2 gates `g3`, `23`, `30`, `32`, `33`; M3 plan task M3-09):
//!
//! - `app.pending.list`: returns pending run requests (at most 20, oldest
//!   first) with `statement_domain: "envcloak-statement/2"`.
//! - `app.pending.get`: returns the full `PendingDescriptor` with
//!   classifications and proposals rebuilt from the current vault (L-09) and
//!   raw `argv` strings (including ANSI and `U+202E` bytes) unchanged.
//! - `app.approve`: rebuilds the canonical `envcloak-statement/2` statement
//!   from the daemon's own pending request, current vault items, and `options`,
//!   verifies the digest (`statement_mismatch`), enforces the live-key guard
//!   (`live_not_ticked`, audited), verifies the 64-byte raw P-256 ECDSA
//!   signature (`r || s`) against an enrolled Secure Enclave unlocker whose
//!   `enrolled_under` matches the caller's verified `(team_id, signing_id)`
//!   (`signature_invalid`, audited), flushes the durable `approved` audit
//!   entry before committing the grant (`audit_failed` leaves no grant and
//!   keeps the request pending), and creates the grant.
//!
//! Named mutation checks (M3 plan M3-09):
//! 1. Verify the signature over the app's digest without rebuilding the
//!    statement: `statement_mismatch_on_other_request_changed_options_or_new_proposal`
//!    fails.
//! 2. Accept a removed unlocker's key:
//!    `unenrolled_removed_and_foreign_identity_keys_are_rejected_with_signature_invalid`
//!    fails.
//! 3. Grant before the audit entry is durable:
//!    `audit_write_failure_refuses_app_approve_before_creating_grant` fails.
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::{
    MANIFEST, SLUGS, client, data_dir, error_kind, passphrase, project, raw, read_json, send_json,
};
use envcloak_core::SecretBytes;
use envcloak_core::audit::AuditKind;
use envcloak_core::crypto::{
    Argon2id, EnvelopeCtx, ItemClass, KdfParams, P256_PUBLIC_KEY_LEN, P256_SIGNATURE_LEN,
    SeEnrolledUnder, SeUnlockerRecord, UnlockerId, UnlockerKind, VaultId, Vmk, derive_p256_keypair,
    p256_fingerprint, sign_p256_prehash, wrap_vmk_with,
};
use envcloak_core::vault::{
    FieldName, INITIAL_EPOCH, ItemDetails, LockedVault, NewItem, Slug, Vault, VaultPaths,
};
use envcloak_ipc::app::{AppUnlockerEnrollOutput, RUN_STATEMENT_DOMAIN};
use envcloak_ipc::proto::{AddParams, ErrorKind, PendingGetOutput, RunRequestParams};
use envcloak_ipc::view::{DecisionView, VaultState};
use envcloak_ipc::wait::{Fresh, MAX_WAIT, SystemClock, Waited, wait_for_run};
use envcloak_ipc::{Client, ClientError, WireSecret};
use envcloak_policy::{
    ApprovalOptions, DEFAULT_TTL, EnvName, GrantId, SubjectKind, Uses, statement_digest,
    unlocker_statement_digest,
};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, daemon_run_dir, fresh_seed,
    labels,
};
use serde_json::json;

const TEST_TEAM_ID: &str = "AB12CD34EF";
const TEST_SIGNING_ID: &str = "ai.envcloak.app";
const AGENT_WAIT_ENV: &str = "ENVCLOAK_TEST_M309_AGENT_WAIT";
const AGENT_PEER_ENV: &str = "ENVCLOAK_TEST_M309_AGENT_PEER";

fn rpc_kind(e: ClientError) -> (ErrorKind, Option<&'static str>) {
    match e {
        ClientError::Rpc(r) => (r.kind, r.reason),
        other => panic!("expected an RPC error, got {other:?}"),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

/// A Stripe key of `kind` (`test` or `live`) constructed at runtime so
/// `items.add` detects provider `stripe` and its classification.
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

fn start_with_app_id(home: &TestHome, app_id: Option<&str>) -> Daemon {
    let mut cmd = Command::new(common::exe());
    home.apply(&mut cmd).env(envcloak_sys::testing::TRACE, "1");
    if let Some(id) = app_id {
        cmd.env(envcloak_sys::testing::APP_IDENTITY, id);
    }
    Daemon::start_command(cmd, &[])
}

/// Seeds the vault in `home`, optionally running `customize` on the open vault
/// before closing it.
fn seed_vault_with(
    home: &TestHome,
    cs: &[Canary],
    customize: impl FnOnce(&mut Vault),
) -> (VaultId, Vec<Canary>) {
    let pass = passphrase(cs);
    let paths = VaultPaths::under(data_dir(home));
    let vault_id = VaultId::generate();
    let vmk = Vmk::generate();
    let kdf = KdfParams::minimum();
    let env = wrap_vmk_with(
        &vmk,
        &pass,
        UnlockerKind::Passphrase,
        &EnvelopeCtx {
            vault_id,
            unlocker_id: UnlockerId::generate(),
            epoch: INITIAL_EPOCH,
        },
        &kdf,
        &Argon2id,
    )
    .unwrap();
    let mut v = Vault::create(&paths, vault_id, vmk, vec![env]).unwrap();

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
            let id = t.create_item(NewItem {
                class: ItemClass::Secret,
                slug: Slug::new(slug).unwrap(),
                details: ItemDetails {
                    title: (*slug).to_owned(),
                    classification: registry.detect(&value, None).classification,
                    ..ItemDetails::default()
                },
            })?;
            t.add_field(id, FieldName::new("value").unwrap(), value)?;
        }
        Ok(())
    })
    .unwrap();
    customize(&mut v);
    drop(v);
    (vault_id, cs.to_vec())
}

/// Enrolls a Secure Enclave unlocker over the socket via
/// `app.unlocker.enroll.begin` + `approve` and returns its `unlocker_id` hex.
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
    assert_eq!(
        desc.approve_pub_sha256,
        hex_encode(&p256_fingerprint(approve_pub))
    );
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

/// Copies the current test binary to `<home>/fixture-agent` so the kernel
/// process-ancestry walk identifies the child process as the builtin catalog's
/// `fixture-agent` (`EnvCloak test fixture agent`).
fn make_fixture_agent_exe(home: &TestHome) -> PathBuf {
    let dest = home.root().join("fixture-agent");
    if !dest.exists() {
        std::fs::copy(std::env::current_exe().unwrap(), &dest).unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dest
}

/// Entrypoint when this binary is spawned as `fixture-agent` to run
/// `wait_for_run` (`envcloak run --wait` engine) in its own session.
#[test]
fn fixture_agent_wait_child() {
    let Some(spec) = std::env::var_os(AGENT_WAIT_ENV) else {
        return;
    };
    let spec = spec.into_string().unwrap();
    let mut lines = spec.lines();
    let run_dir = PathBuf::from(lines.next().unwrap());
    let manifest = lines.next().unwrap().to_owned();
    let arg = lines.next().unwrap().to_owned();
    let seed: u64 = lines.next().unwrap().parse().unwrap();

    envcloak_sys::testing::enter_terminal_session().unwrap();
    let cs = canaries(seed);
    let paths = envcloak_ipc::RunPaths::under(run_dir).unwrap();
    let params = RunRequestParams {
        manifest,
        profile: None,
        refs: Vec::new(),
        env_file: None,
        argv: vec!["./emit".to_owned(), arg],
        claims: Vec::new(),
        launch: None,
        bridge: None,
        fds: Vec::new(),
    };
    let mut t = Fresh {
        paths: &paths,
        params: &params,
    };
    let mut notices = 0usize;
    let got = wait_for_run(&mut t, &mut SystemClock::new(), MAX_WAIT, &mut |_| {
        notices += 1;
    })
    .unwrap();
    match got {
        Waited::Answer(ans) => match ans.decision {
            DecisionView::Covered { grant, .. } => {
                assert_eq!(ans.values.len(), 2);
                let openai = ans
                    .values
                    .iter()
                    .find(|v| v.env_name == "OPENAI_API_KEY")
                    .unwrap();
                let stripe = ans
                    .values
                    .iter()
                    .find(|v| v.env_name == "STRIPE_SECRET_KEY")
                    .unwrap();
                assert_eq!(openai.slug, SLUGS[0]);
                assert_eq!(stripe.slug, SLUGS[1]);
                let _ = cs;
                println!("@@ covered grant={grant} notices={notices} values_matched=true");
            }
            other => panic!("unexpected decision: {other:?}"),
        },
        other => panic!("unexpected wait outcome: {other:?}"),
    }
}

/// Entrypoint when this binary is spawned as `fixture-agent` to test that an
/// app peer with `fixture-agent` in its ancestry is refused with
/// `proof_refused`.
#[test]
fn fixture_agent_app_peer_child() {
    let Some(run_dir) = std::env::var_os(AGENT_PEER_ENV) else {
        return;
    };
    let run_dir = PathBuf::from(run_dir);
    let sock = run_dir.join("envcloakd.sock");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut c = loop {
        if sock.exists()
            && let Ok(paths) = envcloak_ipc::RunPaths::under(run_dir.clone())
            && let Ok(client) = Client::connect(&paths)
        {
            break client;
        }
        assert!(Instant::now() < deadline, "daemon socket never appeared");
        std::thread::sleep(Duration::from_millis(20));
    };
    let e_list = c.app_pending_list(&[]).unwrap_err();
    assert_eq!(rpc_kind(e_list).0, ErrorKind::ProofRefused);
    let e_get = c.app_pending_get("4KQ7M2XD", &[]).unwrap_err();
    assert_eq!(rpc_kind(e_get).0, ErrorKind::ProofRefused);
    let e_approve = c
        .app_approve(
            "4KQ7M2XD",
            &ApprovalOptions::once(Duration::from_secs(60)),
            &[0u8; 32],
            &"00".repeat(P256_SIGNATURE_LEN),
            &[],
        )
        .unwrap_err();
    assert_eq!(rpc_kind(e_approve).0, ErrorKind::ProofRefused);
    println!("@@ agent_ancestry_refused_ok");
}

fn sign_statement(
    approve_sk: &[u8; 32],
    desc: &envcloak_policy::PendingDescriptor,
    opts: &ApprovalOptions,
) -> ([u8; 32], String) {
    let digest = statement_digest(desc, opts);
    let sig = sign_p256_prehash(approve_sk, &digest).unwrap();
    (digest, hex_encode(&sig))
}

fn live_names(desc: &envcloak_policy::PendingDescriptor) -> Vec<EnvName> {
    desc.bindings
        .iter()
        .filter(|b| b.classification == "live")
        .map(|b| EnvName::new(&b.env_name).unwrap())
        .collect()
}

/// A fixture agent's `run --wait` (`wait_for_run`) is covered after
/// `app.approve` with an enrolled software P-256 `approve` key:
/// - `app.pending.list` lists the agent's pending run request with
///   `statement_domain == "envcloak-statement/2"`.
/// - `app.pending.get` returns the full `PendingDescriptor`.
/// - Unticked live binding on an agent request is refused (`live_not_ticked`,
///   audited as `live_refused`) before signature verification creates any
///   grant.
/// - `once` approval covers the waiting agent run, delivers the expected
///   canary values, consumes the `once` grant on first use, and refuses a
///   replayed `app.approve` with `no_such_request`.
/// - `session` approval covers a second waiting agent run and stays active in
///   `grants.list`.
#[test]
fn fixture_agent_run_wait_is_covered_after_app_approve_once_and_session() {
    common::terminal_session();
    let seed = fresh_seed();
    let cs = canaries(seed);
    let home = TestHome::new();
    let (_, all_cs) = seed_vault_with(&home, &cs, |_| {});
    let manifest = project(&home, "acme-web", MANIFEST);

    let app_id = this_process_app_id();
    let mut d = start_with_app_id(&home, Some(&app_id));
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();

    let (_, unlock_pub, approve_sk, approve_pub) = sample_se_keypairs(0x11);
    let unlocker_id =
        enroll_se_over_socket(&mut c, &cs, &unlock_pub, &approve_pub, "Mac Studio SE");
    assert_eq!(unlocker_id.len(), 32);

    // Spawn `fixture-agent` running the `wait_for_run` loop.
    let agent_exe = make_fixture_agent_exe(&home);
    let run_dir = daemon_run_dir(&home);
    let mut waiter_cmd = Command::new(&agent_exe);
    home.apply(&mut waiter_cmd)
        .args([
            "--exact",
            "fixture_agent_wait_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(
            AGENT_WAIT_ENV,
            format!(
                "{}\n{}\n--once-run\n{seed}",
                run_dir.display(),
                manifest.display()
            ),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let waiter = waiter_cmd.spawn().unwrap();

    // Wait until `app.pending.list` shows the fixture agent's pending request.
    let deadline = Instant::now() + Duration::from_secs(30);
    let listed = loop {
        let list = c.app_pending_list(&[]).unwrap();
        if !list.requests.is_empty() {
            break list;
        }
        assert!(Instant::now() < deadline, "waiter never opened a request");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(listed.requests.len(), 1);
    let row = &listed.requests[0];
    assert_eq!(row.statement_domain, RUN_STATEMENT_DOMAIN);
    assert_eq!(row.kind, SubjectKind::Agent);
    assert_eq!(row.agent.as_deref(), Some("EnvCloak test fixture agent"));
    let req_id = row.request.clone();

    let desc = c.app_pending_get(&req_id, &[]).unwrap();
    assert_eq!(desc.request, req_id);
    assert_eq!(desc.subject.kind, SubjectKind::Agent);
    assert_eq!(
        desc.subject.label.as_deref(),
        Some("EnvCloak test fixture agent")
    );
    assert_eq!(desc.argv, vec!["./emit", "--once-run"]);

    // Live-key guard on `app.approve`: leaving live bindings unticked for an
    // agent subject is refused `live_not_ticked` and audited as `live_refused`,
    // with no grant created.
    let unticked_opts = ApprovalOptions::once(Duration::from_secs(300));
    let (unticked_digest, unticked_sig) = sign_statement(&approve_sk, &desc, &unticked_opts);
    let err = c
        .app_approve(
            &req_id,
            &unticked_opts,
            &unticked_digest,
            &unticked_sig,
            &[],
        )
        .unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::LiveNotTicked);
    assert!(c.grants_list().unwrap().grants.is_empty());
    assert!(
        d.log().contains(&format!(
            "approve refused reason=live_not_ticked request={req_id}"
        )),
        "missing live_not_ticked audit line in log:\n{}",
        d.log()
    );

    // Tick all live bindings and approve with `Uses::Once`.
    let mut once_opts = ApprovalOptions::once(Duration::from_secs(300));
    once_opts.live = live_names(&desc);
    let (once_digest, once_sig) = sign_statement(&approve_sk, &desc, &once_opts);
    let approved_once = c
        .app_approve(&req_id, &once_opts, &once_digest, &once_sig, &[])
        .unwrap();
    GrantId::parse(&approved_once.grant).unwrap();

    // Replaying the used approval returns `no_such_request`.
    let replay_err = c
        .app_approve(&req_id, &once_opts, &once_digest, &once_sig, &[])
        .unwrap_err();
    assert_eq!(rpc_kind(replay_err).0, ErrorKind::NoSuchRequest);

    // The waiting fixture-agent child receives the covered answer and exits 0.
    let out = waiter.wait_with_output().unwrap();
    let stdout_text = String::from_utf8_lossy(&out.stdout);
    let stderr_text = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "fixture_agent_wait_child failed:\nstdout: {stdout_text}\nstderr: {stderr_text}"
    );
    assert!(
        stdout_text.contains(&format!(
            "@@ covered grant={} notices=1 values_matched=true",
            approved_once.grant
        )),
        "unexpected waiter output: {stdout_text}"
    );
    assert_no_canary(&out.stdout, &all_cs);
    assert_no_canary(&out.stderr, &all_cs);

    // The `once` grant was consumed on that single covered run.
    assert!(c.grants_list().unwrap().grants.is_empty());
    assert!(c.app_pending_list(&[]).unwrap().requests.is_empty());

    // Now test a `session` grant with a second fixture-agent wait.
    let mut waiter2_cmd = Command::new(&agent_exe);
    home.apply(&mut waiter2_cmd)
        .args([
            "--exact",
            "fixture_agent_wait_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(
            AGENT_WAIT_ENV,
            format!(
                "{}\n{}\n--session-run\n{seed}",
                run_dir.display(),
                manifest.display()
            ),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let waiter2 = waiter2_cmd.spawn().unwrap();

    let deadline = Instant::now() + Duration::from_secs(30);
    let req2_id = loop {
        let list = c.app_pending_list(&[]).unwrap();
        if let Some(first) = list.requests.first() {
            break first.request.clone();
        }
        assert!(Instant::now() < deadline, "waiter2 never opened a request");
        std::thread::sleep(Duration::from_millis(20));
    };
    let desc2 = c.app_pending_get(&req2_id, &[]).unwrap();
    let mut session_opts = ApprovalOptions::session(Duration::from_secs(600));
    session_opts.live = live_names(&desc2);
    let (session_digest, session_sig) = sign_statement(&approve_sk, &desc2, &session_opts);
    let approved_session = c
        .app_approve(&req2_id, &session_opts, &session_digest, &session_sig, &[])
        .unwrap();
    let out2 = waiter2.wait_with_output().unwrap();
    assert!(out2.status.success());
    assert!(String::from_utf8_lossy(&out2.stdout).contains(&format!(
        "@@ covered grant={} notices=1 values_matched=true",
        approved_session.grant
    )));
    assert_no_canary(&out2.stdout, &all_cs);
    assert_no_canary(&out2.stderr, &all_cs);

    // Inspect the durable audit log entries after stopping the daemon.
    drop(c);
    d.signal("-TERM");
    assert!(d.wait_exit(Duration::from_secs(30)).is_some());
    assert_no_canary(&d.log_bytes(), &all_cs);

    let v = LockedVault::open(&VaultPaths::under(data_dir(&home)))
        .unwrap()
        .unlock_with_passphrase(&passphrase(&cs))
        .unwrap_or_else(|(_, e)| panic!("unlock failed: {e:?}"));
    let (entries, report) = v.read_audit().unwrap();
    assert!(report.ok(), "{report:?}");
    assert!(
        entries.iter().any(|e| {
            e.record.kind == AuditKind::Approve
                && e.record.request_id.as_deref() == Some(req_id.as_str())
                && e.record.grant_id.as_deref() == Some(approved_once.grant.as_str())
                && e.record.decision.outcome == "approved"
                && e.record.decision.reason.as_deref() == Some("once")
        }),
        "missing once Approve audit entry in {entries:?}"
    );
    assert!(
        entries.iter().any(|e| {
            e.record.kind == AuditKind::Approve
                && e.record.request_id.as_deref() == Some(req2_id.as_str())
                && e.record.grant_id.as_deref() == Some(approved_session.grant.as_str())
                && e.record.decision.outcome == "approved"
                && e.record.decision.reason.as_deref() == Some("session")
        }),
        "missing session Approve audit entry in {entries:?}"
    );
    drop(v);
    home.assert_clean(&all_cs);
}

/// Signatures by an unenrolled key, by a removed unlocker's key (Mutation
/// Check 2), by an unlocker enrolled under a different `(team_id, signing_id)`,
/// or with corrupted `r || s` bytes are all rejected with `signature_invalid`,
/// audited (`approve_failed` with reason `signature_invalid`), and create no
/// grant.
#[test]
fn unenrolled_removed_and_foreign_identity_keys_are_rejected_with_signature_invalid() {
    common::terminal_session();
    let cs = canaries(fresh_seed());
    let home = TestHome::new();

    let (_, unlock_pub_active, approve_sk_active, approve_pub_active) = sample_se_keypairs(0x21);
    let (_, unlock_pub_removed, approve_sk_removed, approve_pub_removed) = sample_se_keypairs(0x31);
    let (_, unlock_pub_foreign, approve_sk_foreign, approve_pub_foreign) = sample_se_keypairs(0x41);
    let (_, _, approve_sk_unenrolled, _) = sample_se_keypairs(0x51);

    let (_, all_cs) = seed_vault_with(&home, &cs, |v| {
        // 1. Active unlocker enrolled under (TEST_TEAM_ID, TEST_SIGNING_ID).
        let id_active = UnlockerId::generate();
        v.enroll_se_unlocker(SeUnlockerRecord {
            unlocker_id: id_active,
            unlock_pub: unlock_pub_active,
            approve_pub: approve_pub_active,
            label: "Active Touch ID".to_owned(),
            created_secs: 1_700_000_000,
            enrolled_under: SeEnrolledUnder {
                team_id: TEST_TEAM_ID.to_owned(),
                signing_id: TEST_SIGNING_ID.to_owned(),
            },
        })
        .unwrap();

        // 2. Unlocker that is enrolled and then removed before the approval
        //    attempt (Mutation Check 2).
        let id_removed = UnlockerId::generate();
        v.enroll_se_unlocker(SeUnlockerRecord {
            unlocker_id: id_removed,
            unlock_pub: unlock_pub_removed,
            approve_pub: approve_pub_removed,
            label: "Removed Touch ID".to_owned(),
            created_secs: 1_700_000_000,
            enrolled_under: SeEnrolledUnder {
                team_id: TEST_TEAM_ID.to_owned(),
                signing_id: TEST_SIGNING_ID.to_owned(),
            },
        })
        .unwrap();
        v.transact(|t| t.remove_unlocker(id_removed)).unwrap();

        // 3. Unlocker enrolled under a different app identity.
        let id_foreign = UnlockerId::generate();
        v.enroll_se_unlocker(SeUnlockerRecord {
            unlocker_id: id_foreign,
            unlock_pub: unlock_pub_foreign,
            approve_pub: approve_pub_foreign,
            label: "Foreign App Touch ID".to_owned(),
            created_secs: 1_700_000_000,
            enrolled_under: SeEnrolledUnder {
                team_id: "9999999999".to_owned(),
                signing_id: "ai.envcloak.other".to_owned(),
            },
        })
        .unwrap();
    });

    let manifest = project(&home, "acme-web", MANIFEST);
    let app_id = this_process_app_id();
    let mut d = start_with_app_id(&home, Some(&app_id));
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();

    let DecisionView::Pending { request: req_id } = c
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

    let desc = c.app_pending_get(&req_id, &[]).unwrap();
    let opts = ApprovalOptions::session(Duration::from_secs(600));
    let digest = statement_digest(&desc, &opts);

    // 1. Unenrolled key -> `signature_invalid`.
    let sig_unenrolled = hex_encode(&sign_p256_prehash(&approve_sk_unenrolled, &digest).unwrap());
    let err = c
        .app_approve(&req_id, &opts, &digest, &sig_unenrolled, &[])
        .unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::SignatureInvalid);
    assert!(c.grants_list().unwrap().grants.is_empty());

    // 2. Removed unlocker's key -> `signature_invalid` (Mutation Check 2).
    let sig_removed = hex_encode(&sign_p256_prehash(&approve_sk_removed, &digest).unwrap());
    let err = c
        .app_approve(&req_id, &opts, &digest, &sig_removed, &[])
        .unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::SignatureInvalid);
    assert!(c.grants_list().unwrap().grants.is_empty());

    // 3. Key enrolled under another `(team_id, signing_id)` -> `signature_invalid`.
    let sig_foreign = hex_encode(&sign_p256_prehash(&approve_sk_foreign, &digest).unwrap());
    let err = c
        .app_approve(&req_id, &opts, &digest, &sig_foreign, &[])
        .unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::SignatureInvalid);
    assert!(c.grants_list().unwrap().grants.is_empty());

    // 4. Tampered signature from the active key -> `signature_invalid`.
    let mut sig_bad = sign_p256_prehash(&approve_sk_active, &digest).unwrap();
    sig_bad[31] ^= 0x01;
    let err = c
        .app_approve(&req_id, &opts, &digest, &hex_encode(&sig_bad), &[])
        .unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::SignatureInvalid);
    assert!(c.grants_list().unwrap().grants.is_empty());

    // All 4 failed signature checks were audited and left the request pending;
    // the passphrase attempt limiter (`proof_failures`) did not move.
    assert_eq!(c.status().unwrap().approvals.proof_failures, 0);
    assert_eq!(c.app_pending_list(&[]).unwrap().requests.len(), 1);
    assert_eq!(
        d.log()
            .matches("audit: approve failed reason=signature_invalid ")
            .count(),
        4,
        "expected 4 signature_invalid audit lines:\n{}",
        d.log()
    );

    // 5. Valid signature by the active enrolled key succeeds.
    let sig_ok = hex_encode(&sign_p256_prehash(&approve_sk_active, &digest).unwrap());
    let approved = c
        .app_approve(&req_id, &opts, &digest, &sig_ok, &[])
        .unwrap();
    assert_eq!(c.grants_list().unwrap().grants.len(), 1);
    assert_eq!(c.grants_list().unwrap().grants[0].id, approved.grant);

    drop(c);
    d.signal("-TERM");
    assert!(d.wait_exit(Duration::from_secs(30)).is_some());
    assert_no_canary(&d.log_bytes(), &all_cs);

    let v = LockedVault::open(&VaultPaths::under(data_dir(&home)))
        .unwrap()
        .unlock_with_passphrase(&passphrase(&cs))
        .unwrap_or_else(|(_, e)| panic!("unlock failed: {e:?}"));
    let (entries, report) = v.read_audit().unwrap();
    assert!(report.ok(), "{report:?}");
    let sig_invalid_entries = entries
        .iter()
        .filter(|e| {
            e.record.kind == AuditKind::Approve
                && e.record.decision.outcome == "failed"
                && e.record.decision.reason.as_deref() == Some("signature_invalid")
        })
        .count();
    assert_eq!(sig_invalid_entries, 4, "{entries:?}");
    drop(v);
    home.assert_clean(&all_cs);
}

/// Gate 23 & L-09 (Mutation Check 1):
/// - A valid signature by the enrolled `approve` key over another pending
///   request's statement is refused with `statement_mismatch` and creates no
///   grant.
/// - Changing options after signing (`once` vs `session`, `ttl_secs`, or
///   `live` ticks) is refused with `statement_mismatch` and creates no grant.
/// - Out-of-bounds options (`ttl_zero`, `ttl_too_long`, `live_not_bound`) are
///   refused with `invalid_options`.
/// - Adding a proposed test item after `app.pending.get` changes the rebuilt
///   statement's `proposals` (L-09), so the old statement digest is refused
///   with `statement_mismatch` until `app.pending.get` is fetched again.
#[test]
fn statement_mismatch_on_other_request_changed_options_or_new_proposal() {
    common::terminal_session();
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let (_, all_cs) = seed_vault_with(&home, &cs, |_| {});
    let manifest = project(&home, "acme-web", MANIFEST);

    let app_id = this_process_app_id();
    let d = start_with_app_id(&home, Some(&app_id));
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();

    let (_, unlock_pub, approve_sk, approve_pub) = sample_se_keypairs(0x61);
    enroll_se_over_socket(&mut c, &cs, &unlock_pub, &approve_pub, "Touch ID");

    let live_key_str = stripe_key("live");
    let mut all_cs = all_cs;
    all_cs.push(Canary::new("STRIPE_LIVE", live_key_str.clone()));
    c.items_add(&AddParams {
        slug: Some("stripe/acme-live".to_owned()),
        provider: None,
        field: None,
        account: None,
        env_hint: None,
        allow_short: false,
        value: WireSecret::new(SecretBytes::copy_from(live_key_str.as_bytes())),
        claims: Vec::new(),
    })
    .unwrap();

    // Open two distinct pending run requests (`req_a` and `req_b`).
    let open_req = |c: &mut Client, arg: &str| -> String {
        let DecisionView::Pending { request } = c
            .run_request(&RunRequestParams {
                manifest: manifest.to_str().unwrap().to_owned(),
                profile: None,
                refs: vec!["STRIPE_LIVE=stripe/acme-live".to_owned()],
                env_file: None,
                argv: vec!["./emit".to_owned(), arg.to_owned()],
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
        request
    };
    let req_a = open_req(&mut c, "--first");
    let req_b = open_req(&mut c, "--second");
    assert_ne!(req_a, req_b);

    // `app.pending.list` returns both requests oldest first with
    // `statement_domain == "envcloak-statement/2"`.
    let listed = c.app_pending_list(&[]).unwrap().requests;
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].request, req_a);
    assert_eq!(listed[1].request, req_b);
    assert!(
        listed
            .iter()
            .all(|r| r.statement_domain == RUN_STATEMENT_DOMAIN)
    );

    let desc_a = c.app_pending_get(&req_a, &[]).unwrap();
    let desc_b = c.app_pending_get(&req_b, &[]).unwrap();
    let opts = ApprovalOptions::session(Duration::from_secs(600));

    // 1. Valid signature over `req_b`'s statement presented for `req_a` ->
    //    `statement_mismatch` (Mutation Check 1).
    let (digest_b, sig_b) = sign_statement(&approve_sk, &desc_b, &opts);
    let err = c
        .app_approve(&req_a, &opts, &digest_b, &sig_b, &[])
        .unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::StatementMismatch);
    assert!(c.grants_list().unwrap().grants.is_empty());

    // 2. Options changed after signing (`once` vs `session`, `ttl_secs`, or
    //    `live` ticks) -> `statement_mismatch`.
    let (digest_a, sig_a) = sign_statement(&approve_sk, &desc_a, &opts);
    for mutated_opts in [
        ApprovalOptions::once(Duration::from_secs(600)),
        ApprovalOptions::session(Duration::from_secs(599)),
        {
            let mut o = ApprovalOptions::session(Duration::from_secs(600));
            o.live = vec![EnvName::new("OPENAI_API_KEY").unwrap()];
            o
        },
    ] {
        let err = c
            .app_approve(&req_a, &mutated_opts, &digest_a, &sig_a, &[])
            .unwrap_err();
        assert_eq!(rpc_kind(err).0, ErrorKind::StatementMismatch);
        assert!(c.grants_list().unwrap().grants.is_empty());
    }

    // 3. Out-of-bounds options -> `invalid_options`.
    for (bad_opts, reason) in [
        (ApprovalOptions::session(Duration::ZERO), "ttl_zero"),
        (
            ApprovalOptions::session(Duration::from_secs(25 * 3600)),
            "ttl_too_long",
        ),
        (
            {
                let mut o = ApprovalOptions::session(Duration::from_secs(600));
                o.live = vec![EnvName::new("NOT_BOUND_VAR").unwrap()];
                o
            },
            "live_not_bound",
        ),
    ] {
        let (bad_digest, bad_sig) = sign_statement(&approve_sk, &desc_a, &bad_opts);
        let err = c
            .app_approve(&req_a, &bad_opts, &bad_digest, &bad_sig, &[])
            .unwrap_err();
        assert_eq!(rpc_kind(err), (ErrorKind::InvalidOptions, Some(reason)));
        assert!(c.grants_list().unwrap().grants.is_empty());
    }

    // 4. L-09: adding a test-classified secret item for `stripe` changes the
    //    rebuilt proposals on `req_a`, so `digest_a` (computed before the test
    //    item existed) is now refused with `statement_mismatch`.
    assert!(desc_a.proposals.is_empty());
    let test_key_str = stripe_key("test");
    all_cs.push(Canary::new("STRIPE_TEST", test_key_str.clone()));
    c.items_add(&AddParams {
        slug: Some("stripe/acme-test".to_owned()),
        provider: None,
        field: None,
        account: None,
        env_hint: None,
        allow_short: false,
        value: WireSecret::new(SecretBytes::copy_from(test_key_str.as_bytes())),
        claims: Vec::new(),
    })
    .unwrap();

    let err = c
        .app_approve(&req_a, &opts, &digest_a, &sig_a, &[])
        .unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::StatementMismatch);
    assert!(c.grants_list().unwrap().grants.is_empty());

    // Fetching `app.pending.get` again reflects the new proposal, and signing
    // the rebuilt statement succeeds.
    let desc_a_updated = c.app_pending_get(&req_a, &[]).unwrap();
    assert_eq!(desc_a_updated.proposals.len(), 1);
    assert_eq!(desc_a_updated.proposals[0].test_slug, "stripe/acme-test");
    let (digest_a_new, sig_a_new) = sign_statement(&approve_sk, &desc_a_updated, &opts);
    let approved_a = c
        .app_approve(&req_a, &opts, &digest_a_new, &sig_a_new, &[])
        .unwrap();
    assert_eq!(c.grants_list().unwrap().grants.len(), 1);
    assert_eq!(c.grants_list().unwrap().grants[0].id, approved_a.grant);

    assert_no_canary(&d.log_bytes(), &all_cs);
    home.assert_clean(&all_cs);
}

/// Gate 22, §10b & Gate 31:
/// - `app.pending.list`, `app.pending.get`, and `app.approve` from a client
///   peer or forged app peer -> `role_denied`, audited.
/// - From an admitted app peer with agent claims (`CURSOR_AGENT`) or with
///   `fixture-agent` in its process ancestry -> `proof_refused`, audited.
/// - On a tampered vault -> `vault_tampered`.
/// - `app.pending.get` preserves raw `argv` strings with ANSI escapes and
///   `U+202E` bidirectional control characters unchanged (escaping is the
///   renderer's job).
#[test]
fn role_denied_proof_refused_tampered_vault_and_raw_argv_round_trip() {
    common::terminal_session();
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let (_, all_cs) = seed_vault_with(&home, &cs, |_| {});
    let manifest = project(&home, "acme-web", MANIFEST);

    // 1. Forged app peer (wrong pid in `ENVCLOAK_TEST_APP_IDENTITY`):
    //    `role_denied` and audited.
    let forged_pid = std::process::id().saturating_add(99_999);
    let forged_id = format!("{forged_pid}:{TEST_TEAM_ID}:{TEST_SIGNING_ID}");
    let d_forged = start_with_app_id(&home, Some(&forged_id));
    for (method, params) in [
        ("app.pending.list", json!({})),
        ("app.pending.get", json!({"request": "4KQ7M2XD"})),
        (
            "app.approve",
            json!({
                "request": "4KQ7M2XD",
                "options": {"uses": "once", "ttl_secs": 60, "live": []},
                "digest": "00".repeat(32),
                "signature": "00".repeat(64),
            }),
        ),
    ] {
        let mut s = raw(&home);
        send_json(
            &mut s,
            &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
        );
        let r = read_json(&mut s).unwrap();
        assert_eq!(error_kind(&r), "role_denied", "{method}: {r}");
    }
    let forged_log = d_forged.log();
    for m in ["app.pending.list", "app.pending.get", "app.approve"] {
        assert!(
            forged_log.contains(&format!(
                "audit: denied method={m} reason=role_denied role=client pid="
            )),
            "missing role_denied audit for {m}:\n{forged_log}"
        );
    }
    drop(d_forged);

    // 2. Admitted app peer: test agent claims (`CURSOR_AGENT`), and raw `argv`
    //    round-trip with ANSI and `U+202E`.
    let app_id = this_process_app_id();
    let d = start_with_app_id(&home, Some(&app_id));
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();

    let (_, unlock_pub, approve_sk, approve_pub) = sample_se_keypairs(0x71);
    enroll_se_over_socket(&mut c, &cs, &unlock_pub, &approve_pub, "Touch ID");

    let raw_argv = vec![
        "./emit".to_owned(),
        "\x1b[31m--ansi-red\x1b[0m".to_owned(),
        "rtl-\u{202e}txt.exe".to_owned(),
        "line1\rline2\nline3".to_owned(),
    ];
    let DecisionView::Pending { request: req_id } = c
        .run_request(&RunRequestParams {
            manifest: manifest.to_str().unwrap().to_owned(),
            profile: None,
            refs: Vec::new(),
            env_file: None,
            argv: raw_argv.clone(),
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

    // Agent claims on `app.pending.list`, `app.pending.get`, and `app.approve`
    // -> `proof_refused`, audited.
    let agent_claims = vec!["CURSOR_AGENT".to_owned()];
    assert_eq!(
        rpc_kind(c.app_pending_list(&agent_claims).unwrap_err()).0,
        ErrorKind::ProofRefused
    );
    assert_eq!(
        rpc_kind(c.app_pending_get(&req_id, &agent_claims).unwrap_err()).0,
        ErrorKind::ProofRefused
    );
    assert_eq!(
        rpc_kind(
            c.app_approve(
                &req_id,
                &ApprovalOptions::once(Duration::from_secs(60)),
                &[0u8; 32],
                &"00".repeat(P256_SIGNATURE_LEN),
                &agent_claims,
            )
            .unwrap_err()
        )
        .0,
        ErrorKind::ProofRefused
    );
    let log = d.log();
    for m in ["app.pending.list", "app.pending.get", "app.approve"] {
        assert!(
            log.contains(&format!(
                "audit: proof refused method={m} reason=agent pid="
            )),
            "missing proof_refused audit for {m}:\n{log}"
        );
    }

    // Raw `argv` with ANSI and `U+202E` bytes round-trips unchanged in
    // `app.pending.get`, and `app.approve` over that descriptor succeeds.
    let desc = c.app_pending_get(&req_id, &[]).unwrap();
    assert_eq!(desc.argv, raw_argv);
    let opts = ApprovalOptions::once(Duration::from_secs(300));
    let (digest, sig) = sign_statement(&approve_sk, &desc, &opts);
    c.app_approve(&req_id, &opts, &digest, &sig, &[]).unwrap();
    drop(c);
    drop(d);

    // 3. Admitted app peer whose process is `fixture-agent` (agent ancestry
    //    without any claims): `proof_refused` on all three methods.
    let agent_exe = make_fixture_agent_exe(&home);
    let run_dir = daemon_run_dir(&home);
    let mut agent_cmd = Command::new(&agent_exe);
    home.apply(&mut agent_cmd)
        .args([
            "--exact",
            "fixture_agent_app_peer_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(AGENT_PEER_ENV, &run_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let agent_child = agent_cmd.spawn().unwrap();
    let agent_app_id = format!("{}:{TEST_TEAM_ID}:{TEST_SIGNING_ID}", agent_child.id());
    let d_ancestry = start_with_app_id(&home, Some(&agent_app_id));
    let agent_out = agent_child.wait_with_output().unwrap();
    assert!(
        agent_out.status.success()
            && String::from_utf8_lossy(&agent_out.stdout).contains("@@ agent_ancestry_refused_ok"),
        "fixture_agent_app_peer_child failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&agent_out.stdout),
        String::from_utf8_lossy(&agent_out.stderr)
    );
    let ancestry_log = d_ancestry.log();
    for m in ["app.pending.list", "app.pending.get", "app.approve"] {
        assert!(
            ancestry_log.contains(&format!(
                "audit: proof refused method={m} reason=agent pid="
            )),
            "missing agent-ancestry proof_refused audit for {m}:\n{ancestry_log}"
        );
    }
    drop(d_ancestry);

    // 4. Tampered vault refuses `app.pending.list`, `app.pending.get`, and
    //    `app.approve` with `vault_tampered`.
    let db = VaultPaths::under(data_dir(&home)).db;
    let raw_db = rusqlite::Connection::open(&db).unwrap();
    raw_db
        .execute_batch("DELETE FROM fields WHERE rowid = (SELECT min(rowid) FROM fields);")
        .unwrap();
    drop(raw_db);

    let d_tampered = start_with_app_id(&home, Some(&app_id));
    let mut c_tampered = client(&home);
    let u = c_tampered.unlock(passphrase(&cs), &[]).unwrap();
    assert_eq!(u.integrity, envcloak_ipc::view::Integrity::Tampered);
    assert_eq!(
        rpc_kind(c_tampered.app_pending_list(&[]).unwrap_err()).0,
        ErrorKind::VaultTampered
    );
    assert_eq!(
        rpc_kind(c_tampered.app_pending_get("4KQ7M2XD", &[]).unwrap_err()).0,
        ErrorKind::VaultTampered
    );
    assert_eq!(
        rpc_kind(
            c_tampered
                .app_approve(
                    "4KQ7M2XD",
                    &ApprovalOptions::once(Duration::from_secs(60)),
                    &[0u8; 32],
                    &"00".repeat(P256_SIGNATURE_LEN),
                    &[],
                )
                .unwrap_err()
        )
        .0,
        ErrorKind::VaultTampered
    );
    assert_no_canary(&d_tampered.log_bytes(), &all_cs);
    drop(c_tampered);
    drop(d_tampered);
    home.assert_clean(&all_cs);
}

/// Gate 33 (Mutation Check 3): the `approved` audit entry is flushed durably
/// (`audit_delivery`) before the grant is committed to `GrantStore`. When the
/// audit log cannot write the entry, `app.approve` returns `audit_failed`,
/// creates no grant, and leaves the pending request waiting so it can be
/// approved once the audit directory is restored.
#[test]
fn audit_write_failure_refuses_app_approve_before_creating_grant() {
    common::terminal_session();
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let (_, all_cs) = seed_vault_with(&home, &cs, |_| {});
    let manifest = project(&home, "acme-web", MANIFEST);

    let app_id = this_process_app_id();
    let mut d = start_with_app_id(&home, Some(&app_id));
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();
    assert_eq!(c.status().unwrap().vault.state, VaultState::Unlocked);

    let (_, unlock_pub, approve_sk, approve_pub) = sample_se_keypairs(0x81);
    enroll_se_over_socket(&mut c, &cs, &unlock_pub, &approve_pub, "Touch ID");

    let DecisionView::Pending { request: req_id } = c
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
    let desc = c.app_pending_get(&req_id, &[]).unwrap();
    let opts = ApprovalOptions::session(Duration::from_secs(600));
    let (digest, sig) = sign_statement(&approve_sk, &desc, &opts);

    // Replace `<data>/audit` with a regular file so `audit_delivery` fails.
    let audit_dir = data_dir(&home).join("audit");
    std::fs::remove_dir_all(&audit_dir).unwrap();
    std::fs::write(&audit_dir, b"blocked").unwrap();

    let err = c
        .app_approve(&req_id, &opts, &digest, &sig, &[])
        .unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::AuditFailed);

    // Because the durable audit write precedes grant creation (Mutation Check
    // 3), no grant was created and the request is still pending.
    assert!(
        c.grants_list().unwrap().grants.is_empty(),
        "grant must not be created when durable audit write fails"
    );
    assert_eq!(
        c.app_pending_list(&[]).unwrap().requests.len(),
        1,
        "pending request must remain pending when durable audit write fails"
    );

    // Restore `<data>/audit` and retry with the exact same digest and
    // signature: the approval now succeeds and creates the grant.
    std::fs::remove_file(&audit_dir).unwrap();
    std::fs::create_dir(&audit_dir).unwrap();
    std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    let approved = c.app_approve(&req_id, &opts, &digest, &sig, &[]).unwrap();
    let grants = c.grants_list().unwrap().grants;
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].id, approved.grant);
    assert!(c.app_pending_list(&[]).unwrap().requests.is_empty());

    drop(c);
    d.signal("-TERM");
    assert!(d.wait_exit(Duration::from_secs(30)).is_some());
    assert_no_canary(&d.log_bytes(), &all_cs);
    home.assert_clean(&all_cs);
}
