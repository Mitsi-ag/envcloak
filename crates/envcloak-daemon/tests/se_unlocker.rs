//! Secure Enclave unlocker enrolment and HPKE unlock over the daemon's
//! socket (SPEC §5, §10b, §11; M3 plan task M3-08):
//!
//! - Enrolment (`app.unlocker.enroll.begin`, `envcloak approve <id>` in a
//!   `human()` PTY with the passphrase, `app.unlocker.enroll`), and the
//!   `unlocker_add` audit record (gate 33).
//! - Denied, expired, statement-mismatch (gate 23) and wrong-passphrase
//!   enrolment paths.
//! - Role separation (gate 22): enrolment and unlock from a client peer and
//!   from a forged app peer (`role_denied`, audited), and from an app peer
//!   claiming an agent marker (`proof_refused`, audited; `app.unlock.begin`
//!   sends no envelope).
//! - Unlock (`app.unlock.begin`, `app.unlock`) behind a frame-recording
//!   proxy (gate g2, daemon half):
//!   - Every raw frame in both directions is recorded and counted.
//!   - Exactly one frame carries the 80-byte HPKE-sealed VMK (`sealed`).
//!   - The test vault's VMK (read through `Vault::vmk` and
//!     `Vmk::export_for_testing`) appears in no frame, raw or in any §6.1
//!     encoding (`envcloak_testkit::Detector` and `encodings`), with raw
//!     byte counts per frame and a positive control.
//!   - Two `app.unlock.begin` calls return two different `daemon_eph_pub`
//!     and two different `challenge` values.
//!   - Replaying `sealed` after a new `app.unlock.begin`, or replaying the
//!     same `(request_id, sealed)` a second time, is refused
//!     (`unlock_failed`, audited).
//!   - `sealed` built with another request's AAD (or without the challenge)
//!     is refused (`unlock_failed`, audited).
//!
//! Named mutation checks (M3 plan M3-08):
//! 1. AAD without the challenge (`se_reseal_aad` omitting `challenge`):
//!    `unlock_behind_recording_proxy_and_replay_guards` fails.
//! 2. One daemon ephemeral key for every unlock (`begin_se_unlock` reusing a
//!    fixed `SeEphemeralKey`): the distinct-key assertion fails.
//! 3. A debug field carrying the VMK in base64 on `AppUnlockBeginOutput` or
//!    `UnlockedView`: the frame-recording proxy's `Detector` sweep finds it.
//! 4. Enrol without the passphrase proof (`approve_unlocker` skipping
//!    `verify_passphrase`): the wrong-passphrase enrolment test fails.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{
    MANIFEST, SLUGS, client, data_dir, error_kind, passphrase, project, raw, read_json, send_json,
};
use envcloak_core::SecretBytes;
use envcloak_core::audit::AuditKind;
use envcloak_core::crypto::{
    Argon2id, EnvelopeCtx, ItemClass, KdfParams, P256_PUBLIC_KEY_LEN, SE_CHALLENGE_LEN,
    SE_HPKE_CIPHERTEXT_LEN, SE_HPKE_ENC_LEN, SeHpkeEnvelope, UnlockerId, UnlockerKind, VaultId,
    Vmk, derive_p256_keypair, open_se_envelope, p256_fingerprint, seal_vmk_to_daemon,
    wrap_vmk_with,
};
use envcloak_core::vault::{
    FieldName, INITIAL_EPOCH, ItemDetails, LockedVault, NewItem, Slug, Vault, VaultPaths,
};
use envcloak_ipc::app::{AppUnlockBeginOutput, AppUnlockerEnrollOutput};
use envcloak_ipc::proto::{ErrorKind, PendingGetOutput, RunRequestParams};
use envcloak_ipc::view::{DecisionView, VaultState};
use envcloak_ipc::{Client, ClientError, RunPaths};
use envcloak_policy::{
    ApprovalOptions, DEFAULT_TTL, Uses, render_unlocker_statement, unlocker_statement_digest,
};
use envcloak_testkit::{
    Canary, Daemon, Detector, TestHome, assert_no_canary, by_label, canaries, encodings,
    fresh_seed, labels,
};
use serde_json::json;

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
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// Finds `envcloak` built beside `envcloakd` and checks that it is fresh.
fn cli_exe() -> PathBuf {
    let p = common::exe().with_file_name("envcloak");
    assert!(
        p.is_file(),
        "{} is missing: run cargo build -p envcloak --bin envcloak first",
        p.display()
    );
    envcloak_testkit::assert_fresh(&p, "envcloak");
    p
}

/// Finds `python3` on `PATH` for the PTY wrapper.
fn python3() -> PathBuf {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|d| d.join("python3"))
        .find(|p| p.is_file())
        .expect("python3 is needed on PATH")
}

/// Runs `argv[2..]` as the leader of a new session whose controlling
/// terminal is a new pseudo-terminal (a `human()` PTY), with the descriptors
/// in `argv[1]` opened (`3<path`).
const ON_TERMINAL: &str = "import os, pty, select, sys
out, err = os.dup(1), os.dup(2)
pid, fd = pty.fork()
if pid == 0:
    os.dup2(out, 1)
    os.dup2(err, 2)
    for item in [i for i in sys.argv[1].split(',') if i]:
        n, p = item.split('<', 1)
        f = os.open(p, os.O_RDONLY)
        if f != int(n):
            os.dup2(f, int(n))
            os.close(f)
        os.set_inheritable(int(n), True)
    os.execv(sys.argv[2], sys.argv[2:])
os.close(out)
os.close(err)
reading = True
while True:
    if reading:
        r, _, _ = select.select([fd], [], [], 0.05)
        if r:
            try:
                reading = bool(os.read(fd, 4096))
            except OSError:
                reading = False
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            break
    else:
        _, status = os.waitpid(pid, 0)
        break
code = os.waitstatus_to_exitcode(status)
sys.exit(code if code >= 0 else 128 - code)
";

/// Runs `envcloak <args>` in a `human()` PTY with `pass_file` on descriptor 3.
fn run_cli_in_pty(home: &TestHome, args: &[&str], pass_file: &Path) -> Output {
    let spec = format!("3<{}", pass_file.display());
    let mut cmd = Command::new(python3());
    home.apply(&mut cmd)
        .args(["-c", ON_TERMINAL])
        .arg(spec)
        .arg(cli_exe())
        .args(args)
        .current_dir(home.home())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let mut out = child.stdout.take().unwrap();
    let mut err = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut o = Vec::new();
        let mut e = Vec::new();
        let _ = out.read_to_end(&mut o);
        let _ = err.read_to_end(&mut e);
        (o, e)
    });
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < deadline, "envcloak did not exit in time");
        std::thread::sleep(Duration::from_millis(20));
    };
    let (stdout, stderr) = reader.join().unwrap();
    Output {
        status,
        stdout,
        stderr,
    }
}

/// Seeds the vault in `home` and returns `vmk_canary`, reading the 32-byte VMK
/// back through `Vault::vmk().export_for_testing()`.
///
/// The 32-byte VMK is generated as printable ASCII (including `/`, `+`, `"`
/// and alphanumeric bytes) so `Canary` and `Detector` can sweep for every
/// §6.1 encoding (raw, hex, base64, base64url, embedded base64 at all 3
/// alignments, percent/form encodings, and all 108 JSON escaping styles).
fn seed_vault_with_vmk_canary(home: &TestHome, cs: &[Canary]) -> Canary {
    let seed = fresh_seed();
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+";
    let mut state = seed ^ 0x5345_5f56_4d4b_3038;
    let mut vmk_str = String::from("vmk/\"+ \u{e9}");
    while vmk_str.len() < 32 {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        vmk_str.push(char::from(alphabet[(z as usize) % alphabet.len()]));
    }
    assert_eq!(vmk_str.len(), 32);

    let pass = passphrase(cs);
    let paths = VaultPaths::under(data_dir(home));
    let vault_id = VaultId::generate();
    let vmk = Vmk::import_for_testing(vmk_str.as_bytes()).unwrap();
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
    let exported = v.vmk().export_for_testing();
    assert_eq!(exported, vmk_str.as_bytes());

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
    drop(v);
    Canary::new("VAULT_VMK", String::from_utf8(exported).unwrap())
}

/// Starts `envcloakd` with `ENVCLOAK_TEST_APP_IDENTITY` set to `app_id` and
/// optional `ENVCLOAK_TEST_CLOCK_FILE`.
fn start_with_app_id(home: &TestHome, app_id: Option<&str>, clock_file: Option<&Path>) -> Daemon {
    let mut cmd = Command::new(common::exe());
    home.apply(&mut cmd);
    if let Some(id) = app_id {
        cmd.env(envcloak_sys::testing::APP_IDENTITY, id);
    }
    if let Some(cf) = clock_file {
        cmd.env(envcloak_sys::testing::CLOCK_FILE, cf);
    }
    Daemon::start_command(cmd, &[])
}

fn this_process_app_id() -> String {
    format!("{}:{TEST_TEAM_ID}:{TEST_SIGNING_ID}", std::process::id())
}

fn sample_se_keys(
    seed_byte: u8,
) -> (
    [u8; 32],
    [u8; P256_PUBLIC_KEY_LEN],
    [u8; P256_PUBLIC_KEY_LEN],
) {
    let (unlock_sk, unlock_pub) = derive_p256_keypair(&[seed_byte; 32]);
    let (_, approve_pub) = derive_p256_keypair(&[seed_byte.wrapping_add(1); 32]);
    (unlock_sk, unlock_pub, approve_pub)
}

/// Direction of a frame captured by [`RecordingProxy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    ClientToDaemon,
    DaemonToClient,
}

/// One raw length-prefixed frame (`4-byte BE length || JSON body`) captured
/// on the wire.
#[derive(Debug, Clone)]
struct RecordedFrame {
    direction: Direction,
    raw: Vec<u8>,
}

impl RecordedFrame {
    fn body(&self) -> &[u8] {
        &self.raw[4..]
    }
}

/// A Unix domain socket proxy that forwards every frame between an app client
/// and `envcloakd.sock` while recording the exact wire bytes in both
/// directions.
struct RecordingProxy {
    run_dir: PathBuf,
    frames: Arc<Mutex<Vec<RecordedFrame>>>,
}

impl RecordingProxy {
    fn start(home: &TestHome) -> Self {
        let daemon_sock = common::run_paths(home).socket;
        let run_dir = home.root().join("proxy-run");
        std::fs::create_dir_all(&run_dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let proxy_sock = run_dir.join("envcloakd.sock");
        let listener = UnixListener::bind(&proxy_sock).unwrap();
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
                        frames_c2d.lock().unwrap().push(RecordedFrame {
                            direction: Direction::ClientToDaemon,
                            raw: raw.clone(),
                        });
                        if d_write.write_all(&raw).is_err() {
                            break;
                        }
                    }
                });
                let frames_d2c = Arc::clone(&frames_bg);
                while let Some(raw) = read_raw_frame(&mut daemon_stream) {
                    frames_d2c.lock().unwrap().push(RecordedFrame {
                        direction: Direction::DaemonToClient,
                        raw: raw.clone(),
                    });
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

    fn recorded(&self) -> Vec<RecordedFrame> {
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

/// Software stand-in for the Secure Enclave + CryptoKit unlock step: opens
/// the P-256 HPKE envelope from `app.unlock.begin` and reseals the 32-byte
/// VMK to `daemon_eph_pub` with AAD `request_id || challenge`.
fn perform_app_hpke_reseal(unlock_sk: &[u8; 32], begin: &AppUnlockBeginOutput) -> (Vmk, [u8; 80]) {
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
    let sealed = seal_vmk_to_daemon(&daemon_eph_pub, &begin.request_id, &challenge, &vmk).unwrap();
    (vmk, sealed)
}

/// Enrols a Secure Enclave unlocker through `envcloak approve <id>` in a
/// `human()` PTY with the passphrase, checks the rendered statement and the
/// durable `unlocker_add` audit entry (gate 33), and tests the denied,
/// expired, statement-mismatch (gate 23) and wrong-passphrase paths.
#[test]
fn enrolment_via_cli_pty_and_denied_expired_and_mismatch_paths() {
    common::terminal_session();
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let vmk_canary = seed_vault_with_vmk_canary(&home, &cs);
    let mut all_cs = cs.clone();
    all_cs.push(vmk_canary);

    let clock_file = home.root().join("clock-offset");
    std::fs::write(&clock_file, "0").unwrap();
    let app_id = this_process_app_id();
    let mut d = start_with_app_id(&home, Some(&app_id), Some(&clock_file));
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();

    // 1. Denied path: begin -> pending -> deny -> denied.
    let (_, unlock_pub_1, approve_pub_1) = sample_se_keys(0x10);
    let begin_denied = c
        .app_unlocker_enroll_begin(
            &hex_encode(&unlock_pub_1),
            &hex_encode(&approve_pub_1),
            "Denied Touch ID",
            &[],
        )
        .unwrap();
    assert_eq!(
        c.app_unlocker_enroll(&begin_denied.request, &[]).unwrap(),
        AppUnlockerEnrollOutput::Pending
    );
    assert!(!c.deny(&begin_denied.request).unwrap().root_auto_denied);
    assert_eq!(
        c.app_unlocker_enroll(&begin_denied.request, &[]).unwrap(),
        AppUnlockerEnrollOutput::Denied
    );

    // 2. Expired path: begin -> pending -> advance clock past PENDING_TTL -> expired.
    let (_, unlock_pub_2, approve_pub_2) = sample_se_keys(0x20);
    let begin_expired = c
        .app_unlocker_enroll_begin(
            &hex_encode(&unlock_pub_2),
            &hex_encode(&approve_pub_2),
            "Expired Touch ID",
            &[],
        )
        .unwrap();
    assert_eq!(
        c.app_unlocker_enroll(&begin_expired.request, &[]).unwrap(),
        AppUnlockerEnrollOutput::Pending
    );
    std::fs::write(&clock_file, "605").unwrap();
    assert_eq!(
        c.app_unlocker_enroll(&begin_expired.request, &[]).unwrap(),
        AppUnlockerEnrollOutput::Expired
    );

    // 3. Statement mismatch (gate 23), wrong passphrase, and successful
    // approval via `envcloak approve <id> --passphrase-fd 3` in a PTY.
    let (_, unlock_pub_3, approve_pub_3) = sample_se_keys(0x30);
    let label = "MacBook Pro Touch ID";
    let begin_ok = c
        .app_unlocker_enroll_begin(
            &hex_encode(&unlock_pub_3),
            &hex_encode(&approve_pub_3),
            label,
            &[],
        )
        .unwrap();
    let PendingGetOutput::UnlockerAdd(desc) = c.pending_get_any(&begin_ok.request, &[]).unwrap()
    else {
        panic!("expected an unlocker_add descriptor");
    };
    assert_eq!(desc.label, label);
    assert_eq!(desc.team_id, TEST_TEAM_ID);
    assert_eq!(desc.signing_id, TEST_SIGNING_ID);
    assert_eq!(
        desc.unlock_pub_sha256,
        hex_encode(&p256_fingerprint(&unlock_pub_3))
    );
    assert_eq!(
        desc.approve_pub_sha256,
        hex_encode(&p256_fingerprint(&approve_pub_3))
    );

    // Gate 23: altering any field of the unlocker statement produces another
    // digest that `approve` refuses (`statement_mismatch`) before touching
    // the passphrase (`proof_failures` stays 0).
    let opts = ApprovalOptions {
        uses: Uses::Once,
        ttl_secs: DEFAULT_TTL.as_secs(),
        live: Vec::new(),
    };
    for field in [
        "label",
        "unlock_pub_sha256",
        "approve_pub_sha256",
        "team_id",
        "signing_id",
        "nonce",
    ] {
        let mut altered = desc.clone();
        match field {
            "label" => altered.label = "Other Label".to_owned(),
            "unlock_pub_sha256" => altered.unlock_pub_sha256 = "00".repeat(32),
            "approve_pub_sha256" => altered.approve_pub_sha256 = "ff".repeat(32),
            "team_id" => altered.team_id = "ZZZZZZZZZZ".to_owned(),
            "signing_id" => altered.signing_id = "ai.envcloak.other".to_owned(),
            "nonce" => altered.nonce = "11".repeat(16),
            _ => unreachable!(),
        }
        let bad_digest = unlocker_statement_digest(&altered);
        let err = c
            .approve(
                &begin_ok.request,
                opts.clone(),
                &bad_digest,
                passphrase(&cs),
                &[],
            )
            .unwrap_err();
        assert_eq!(rpc_kind(err).0, ErrorKind::StatementMismatch, "{field}");
        assert_eq!(c.status().unwrap().approvals.proof_failures, 0, "{field}");
    }

    // Wrong passphrase on `approve` is refused (`wrong_passphrase`), counted,
    // and leaves the request pending and unenrolled.
    let good_digest = unlocker_statement_digest(&desc);
    let err = c
        .approve(
            &begin_ok.request,
            opts,
            &good_digest,
            SecretBytes::copy_from(b"wrong passphrase for unlocker enrolment"),
            &[],
        )
        .unwrap_err();
    assert_eq!(rpc_kind(err).0, ErrorKind::WrongPassphrase);
    assert_eq!(c.status().unwrap().approvals.proof_failures, 1);
    assert_eq!(
        c.app_unlocker_enroll(&begin_ok.request, &[]).unwrap(),
        AppUnlockerEnrollOutput::Pending
    );

    // Approve in a `human()` PTY using the real `envcloak approve` CLI binary.
    let pass_dir = tempfile::tempdir().unwrap();
    let pass_file = pass_dir.path().join("pass");
    std::fs::write(&pass_file, by_label(&cs, labels::VAULT_PASSPHRASE).value()).unwrap();
    let out = run_cli_in_pty(
        &home,
        &["approve", &begin_ok.request, "--passphrase-fd", "3"],
        &pass_file,
    );
    let stdout_text = String::from_utf8_lossy(&out.stdout);
    let stderr_text = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "envcloak approve failed:\nstdout: {stdout_text}\nstderr: {stderr_text}\nlog: {}",
        d.log()
    );
    let expected_statement = render_unlocker_statement(&desc);
    assert!(
        stdout_text.contains(&expected_statement),
        "stdout missing rendered unlocker statement:\n{stdout_text}"
    );
    let enrolled = c.app_unlocker_enroll(&begin_ok.request, &[]).unwrap();
    let AppUnlockerEnrollOutput::Enrolled { unlocker_id } = enrolled else {
        panic!("expected Enrolled, got {enrolled:?}");
    };
    assert_eq!(unlocker_id.len(), 32);
    assert!(
        stdout_text.contains(&format!(
            "Approved request {}: enrolled Secure Enclave unlocker {unlocker_id}.",
            begin_ok.request
        )),
        "stdout missing approval confirmation:\n{stdout_text}"
    );

    // Gate 33: `audit.verify` passes and the `unlocker_add` entry is durable
    // in the vault's audit log.
    let verified = c.audit_verify().unwrap();
    assert_eq!(verified.problems, 0, "{verified:?}");
    assert!(verified.entries >= 2, "{verified:?}");

    drop(c);
    d.signal("-TERM");
    assert!(d.wait_exit(Duration::from_secs(30)).is_some());
    assert_no_canary(&d.log_bytes(), &all_cs);
    drop(d);

    let paths = VaultPaths::under(data_dir(&home));
    let v = LockedVault::open(&paths)
        .unwrap()
        .unlock_with_passphrase(&passphrase(&cs))
        .unwrap_or_else(|(_, e)| panic!("unlock failed: {e:?}"));
    let (entries, report) = v.read_audit().unwrap();
    assert_eq!(report.problems, 0, "{report:?}");
    assert!(
        entries.iter().any(|e| {
            e.record.kind == AuditKind::UnlockerAdd
                && e.record.request_id.as_deref() == Some(begin_ok.request.as_str())
                && e.record.grant_id.as_deref() == Some(unlocker_id.as_str())
                && e.record.decision.outcome == "enrolled"
                && e.record.argv_redacted
                    == vec![
                        label.to_owned(),
                        desc.unlock_pub_sha256.clone(),
                        desc.approve_pub_sha256.clone(),
                    ]
        }),
        "missing UnlockerAdd audit entry in {entries:?}"
    );
    drop(v);
    assert_no_canary(&out.stdout, &all_cs);
    assert_no_canary(&out.stderr, &all_cs);
    home.assert_clean(&all_cs);
}

/// Gate 22 & §10b:
/// - Client peer (no app identity) calling any `app.*` method: `role_denied`,
///   audited.
/// - Forged app peer (wrong pid in `ENVCLOAK_TEST_APP_IDENTITY`):
///   `role_denied`, audited.
/// - Admitted app peer whose claims include an agent marker (`CURSOR_AGENT`):
///   `proof_refused`, audited, and `app.unlock.begin` sends no envelope.
#[test]
fn role_denied_for_client_and_forged_app_and_proof_refused_for_agent_claims() {
    common::terminal_session();
    let cs = canaries(fresh_seed());
    let (_, unlock_pub, approve_pub) = sample_se_keys(0x40);

    // 1. Forged app peer: `ENVCLOAK_TEST_APP_IDENTITY` names another pid.
    let home = TestHome::new();
    let vmk_canary = seed_vault_with_vmk_canary(&home, &cs);
    let mut all_cs = cs.clone();
    all_cs.push(vmk_canary);

    let forged_pid = std::process::id().saturating_add(99_999);
    let forged_id = format!("{forged_pid}:{TEST_TEAM_ID}:{TEST_SIGNING_ID}");
    let d_forged = start_with_app_id(&home, Some(&forged_id), None);
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();

    for (method, params) in [
        (
            "app.unlocker.enroll.begin",
            json!({
                "unlock_pub": hex_encode(&unlock_pub),
                "approve_pub": hex_encode(&approve_pub),
                "label": "Forged Peer",
            }),
        ),
        ("app.unlocker.enroll", json!({"request": "4KQ7M2XD"})),
        ("app.unlock.begin", json!({})),
        (
            "app.unlock",
            json!({"request_id": "4KQ7M2XD", "sealed": "00".repeat(80)}),
        ),
    ] {
        let mut s = raw(&home);
        send_json(
            &mut s,
            &json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}),
        );
        let r = read_json(&mut s).unwrap();
        assert_eq!(
            error_kind(&r),
            "role_denied",
            "forged app peer on {method}: {r}"
        );
    }
    let log = d_forged.log();
    for m in [
        "app.unlocker.enroll.begin",
        "app.unlocker.enroll",
        "app.unlock.begin",
        "app.unlock",
    ] {
        assert!(
            log.contains(&format!(
                "audit: denied method={m} reason=role_denied role=client pid="
            )),
            "missing role_denied audit for {m}: {log}"
        );
    }
    assert_no_canary(&d_forged.log_bytes(), &all_cs);
    drop(c);
    drop(d_forged);

    // 2. Admitted app peer claiming `CURSOR_AGENT`: refused with `proof_refused`
    // and audited (`app.unlock.begin` sends no envelope).
    let app_id = this_process_app_id();
    let d_app = start_with_app_id(&home, Some(&app_id), None);
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();

    // Enrol a real unlocker first so `app.unlock.begin` would succeed without
    // agent claims.
    let begin = c
        .app_unlocker_enroll_begin(
            &hex_encode(&unlock_pub),
            &hex_encode(&approve_pub),
            "Touch ID",
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
        passphrase(&cs),
        &[],
    )
    .unwrap();
    c.lock().unwrap();

    let agent_claims = vec!["CURSOR_AGENT".to_owned()];
    let mut s = raw(&home);
    send_json(
        &mut s,
        &json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "app.unlock.begin",
            "params": {"claims": ["CURSOR_AGENT"]},
        }),
    );
    let r_begin = read_json(&mut s).unwrap();
    assert_eq!(error_kind(&r_begin), "proof_refused", "{r_begin}");
    assert!(
        r_begin.get("result").is_none() && !r_begin.to_string().contains("envelope"),
        "app.unlock.begin sent an envelope on proof_refused: {r_begin}"
    );

    let err_unlock = c
        .app_unlock("4KQ7M2XD", &"00".repeat(80), &agent_claims)
        .unwrap_err();
    assert_eq!(rpc_kind(err_unlock).0, ErrorKind::ProofRefused);

    let err_enroll_begin = c
        .app_unlocker_enroll_begin(
            &hex_encode(&unlock_pub),
            &hex_encode(&approve_pub),
            "Agent Touch ID",
            &agent_claims,
        )
        .unwrap_err();
    assert_eq!(rpc_kind(err_enroll_begin).0, ErrorKind::ProofRefused);

    let err_enroll = c
        .app_unlocker_enroll(&begin.request, &agent_claims)
        .unwrap_err();
    assert_eq!(rpc_kind(err_enroll).0, ErrorKind::ProofRefused);

    let app_log = d_app.log();
    for m in [
        "app.unlock.begin",
        "app.unlock",
        "app.unlocker.enroll.begin",
        "app.unlocker.enroll",
    ] {
        assert!(
            app_log.contains(&format!(
                "audit: proof refused method={m} reason=agent pid="
            )),
            "missing proof_refused audit for {m}: {app_log}"
        );
    }
    assert_no_canary(&d_app.log_bytes(), &all_cs);
    home.assert_clean(&all_cs);
}

/// Gate g2 (daemon half): unlock behind a recording proxy that keeps every
/// frame:
/// - Exactly one frame carries the 80-byte HPKE-sealed VMK (`sealed`).
/// - The test vault's VMK (read through `Vmk::export_for_testing`) appears in
///   no recorded frame, raw or in any §6.1 encoding (`Detector` and
///   `encodings`), with raw byte counts per frame and a positive control.
/// - Two `app.unlock.begin` calls return two different `daemon_eph_pub` and
///   two different `challenge` values.
/// - Replaying `sealed` after a new `app.unlock.begin`, or replaying the same
///   `(request_id, sealed)` twice, is refused (`unlock_failed`, audited).
/// - `sealed` built with another request's AAD or wrong challenge is refused
///   (`unlock_failed`, audited).
/// - `app.unlock.begin` for an unknown unlocker id returns `no_unlocker`.
#[test]
fn unlock_behind_recording_proxy_and_replay_guards() {
    common::terminal_session();
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let vmk_canary = seed_vault_with_vmk_canary(&home, &cs);
    let mut all_cs = cs.clone();
    all_cs.push(vmk_canary.clone());

    let app_id = this_process_app_id();
    let d = start_with_app_id(&home, Some(&app_id), None);
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();
    let manifest = project(&home, "acme-web", MANIFEST);

    // Enrol a Secure Enclave unlocker while unlocked.
    let (unlock_sk, unlock_pub, approve_pub) = sample_se_keys(0x55);
    let enroll_begin = c
        .app_unlocker_enroll_begin(
            &hex_encode(&unlock_pub),
            &hex_encode(&approve_pub),
            "Studio Touch ID",
            &[],
        )
        .unwrap();
    let PendingGetOutput::UnlockerAdd(desc) =
        c.pending_get_any(&enroll_begin.request, &[]).unwrap()
    else {
        panic!("expected unlocker_add descriptor");
    };
    let digest = unlocker_statement_digest(&desc);
    c.approve(
        &enroll_begin.request,
        ApprovalOptions {
            uses: Uses::Once,
            ttl_secs: DEFAULT_TTL.as_secs(),
            live: Vec::new(),
        },
        &digest,
        passphrase(&cs),
        &[],
    )
    .unwrap();
    let AppUnlockerEnrollOutput::Enrolled { unlocker_id } =
        c.app_unlocker_enroll(&enroll_begin.request, &[]).unwrap()
    else {
        panic!("expected enrolled");
    };

    // Lock the vault and perform the HPKE unlock through the recording proxy.
    assert!(c.lock().unwrap().was_unlocked);
    assert_eq!(c.status().unwrap().vault.state, VaultState::Locked);

    let proxy = RecordingProxy::start(&home);
    let mut proxy_client = proxy.connect();
    let begin = proxy_client
        .app_unlock_begin(Some(&unlocker_id), &[])
        .unwrap();
    assert_eq!(begin.unlocker_id, unlocker_id);
    assert_eq!(begin.epoch, INITIAL_EPOCH);

    let (opened_vmk, sealed) = perform_app_hpke_reseal(&unlock_sk, &begin);
    assert_eq!(opened_vmk.export_for_testing(), vmk_canary.value());
    let sealed_hex = hex_encode(&sealed);
    assert_eq!(sealed_hex.len(), 160);

    let unlocked = proxy_client
        .app_unlock(&begin.request_id, &sealed_hex, &[])
        .unwrap();
    assert!(!unlocked.already);
    assert!(!unlocked.read_only);
    drop(proxy_client);

    // Verify the vault is unlocked and items are usable.
    assert_eq!(c.status().unwrap().vault.state, VaultState::Unlocked);
    assert_eq!(c.items_list(false).unwrap().items.len(), SLUGS.len());

    // Inspect the recorded frames from `app.unlock.begin` and `app.unlock`.
    let frames = proxy.recorded();
    assert_eq!(
        frames.len(),
        4,
        "expected 2 request + 2 response frames, got {}",
        frames.len()
    );
    let counts: Vec<(Direction, usize)> =
        frames.iter().map(|f| (f.direction, f.raw.len())).collect();
    for (idx, (dir, byte_len)) in counts.iter().enumerate() {
        assert!(*byte_len > 4, "frame {idx} ({dir:?}) is empty: {byte_len}");
    }

    // Exactly one frame carries the 80-byte sealed VMK (`sealed_hex`).
    let carrying_sealed: Vec<usize> = frames
        .iter()
        .enumerate()
        .filter(|(_, f)| {
            f.raw
                .windows(sealed_hex.len())
                .any(|w| w == sealed_hex.as_bytes())
                || f.raw.windows(sealed.len()).any(|w| w == sealed)
        })
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        carrying_sealed,
        vec![2],
        "expected only frame 2 (the app.unlock request) to carry sealed VMK; counts={counts:?}"
    );
    assert_eq!(frames[2].direction, Direction::ClientToDaemon);

    // Sweep every recorded frame for the VMK (and all other canaries) across
    // raw and every §6.1 encoding.
    let vmk_detector = Detector::new(std::slice::from_ref(&vmk_canary));
    let all_detector = Detector::new(&all_cs);
    let vmk_encodings = encodings(&vmk_canary);
    assert!(
        vmk_encodings.len() >= 15,
        "expected full §6.1 encoding suite, got {}",
        vmk_encodings.len()
    );
    for (idx, frame) in frames.iter().enumerate() {
        let hits = all_detector.find(&frame.raw);
        assert!(
            hits.is_empty(),
            "canary leak in recorded frame {idx} ({:?}, {} bytes): {hits:?}",
            frame.direction,
            frame.raw.len()
        );
        let body_hits = vmk_detector.find(frame.body());
        assert!(
            body_hits.is_empty(),
            "VMK leak in recorded frame {idx} body: {body_hits:?}"
        );
    }

    // Positive control: planting the VMK in raw, hex-lower or base64 inside a
    // copy of a recorded frame is caught by `vmk_detector`.
    for (enc_name, enc_bytes) in vmk_encodings.iter().take(6) {
        let mut planted = frames[1].raw.clone();
        planted.extend_from_slice(b"\"debug_vmk\":\"");
        planted.extend_from_slice(enc_bytes);
        planted.extend_from_slice(b"\"");
        let found = vmk_detector.find(&planted);
        assert!(
            !found.is_empty(),
            "positive control failed to detect VMK encoding {enc_name}"
        );
    }

    // Lock again to test distinct ephemeral keys, replay, AAD binding, and
    // unknown unlocker ids.
    assert!(c.lock().unwrap().was_unlocked);

    // Unknown unlocker id -> `no_unlocker`.
    let err_no_unlocker = c.app_unlock_begin(Some(&"ff".repeat(16)), &[]).unwrap_err();
    assert_eq!(rpc_kind(err_no_unlocker).0, ErrorKind::NoUnlocker);

    // Two `app.unlock.begin` calls give two different `daemon_eph_pub`,
    // `challenge` and `request_id` values.
    let b1 = c.app_unlock_begin(None, &[]).unwrap();
    let b2 = c.app_unlock_begin(None, &[]).unwrap();
    assert_ne!(b1.daemon_eph_pub, b2.daemon_eph_pub);
    assert_ne!(b1.challenge, b2.challenge);
    assert_ne!(b1.request_id, b2.request_id);

    // Replaying the earlier `sealed` under `b1.request_id` fails
    // (`unlock_failed`, audited), and consumes `b1.request_id`.
    let err_replay_new = c.app_unlock(&b1.request_id, &sealed_hex, &[]).unwrap_err();
    assert_eq!(rpc_kind(err_replay_new).0, ErrorKind::UnlockFailed);
    assert_eq!(c.status().unwrap().vault.state, VaultState::Locked);

    // Replaying the old `(begin.request_id, sealed)` a second time also fails.
    let err_replay_old = c
        .app_unlock(&begin.request_id, &sealed_hex, &[])
        .unwrap_err();
    assert_eq!(rpc_kind(err_replay_old).0, ErrorKind::UnlockFailed);

    // Sealing to `b2.daemon_eph_pub` with `b1`'s AAD (`b1.challenge`) is
    // refused (`unlock_failed`), consuming `b2`.
    let b2_eph_pub = decode_hex::<32>(&b2.daemon_eph_pub);
    let b1_challenge = decode_hex::<SE_CHALLENGE_LEN>(&b1.challenge);
    let sealed_wrong_challenge =
        seal_vmk_to_daemon(&b2_eph_pub, &b2.request_id, &b1_challenge, &opened_vmk).unwrap();
    let err_wrong_aad = c
        .app_unlock(&b2.request_id, &hex_encode(&sealed_wrong_challenge), &[])
        .unwrap_err();
    assert_eq!(rpc_kind(err_wrong_aad).0, ErrorKind::UnlockFailed);
    assert_eq!(c.status().unwrap().vault.state, VaultState::Locked);

    // Sealing a wrong VMK to a fresh `b3.daemon_eph_pub` with the right AAD
    // passes HPKE open but fails step 4's header check (`unlock_failed`).
    let b3 = c.app_unlock_begin(None, &[]).unwrap();
    let b3_eph_pub = decode_hex::<32>(&b3.daemon_eph_pub);
    let b3_challenge = decode_hex::<SE_CHALLENGE_LEN>(&b3.challenge);
    let wrong_vmk = Vmk::generate();
    let sealed_wrong_vmk =
        seal_vmk_to_daemon(&b3_eph_pub, &b3.request_id, &b3_challenge, &wrong_vmk).unwrap();
    let err_wrong_vmk = c
        .app_unlock(&b3.request_id, &hex_encode(&sealed_wrong_vmk), &[])
        .unwrap_err();
    assert_eq!(rpc_kind(err_wrong_vmk).0, ErrorKind::UnlockFailed);
    assert_eq!(c.status().unwrap().vault.state, VaultState::Locked);
    assert_eq!(c.status().unwrap().vault.failed_unlocks, 4);

    // A fresh valid `app.unlock.begin` + `app.unlock` still unlocks cleanly
    // and allows a `run.request` to proceed.
    let b4 = c.app_unlock_begin(None, &[]).unwrap();
    let (_, sealed_b4) = perform_app_hpke_reseal(&unlock_sk, &b4);
    c.app_unlock(&b4.request_id, &hex_encode(&sealed_b4), &[])
        .unwrap();
    assert_eq!(c.status().unwrap().vault.state, VaultState::Unlocked);
    let run_decision = c
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
        .decision;
    assert!(matches!(run_decision, DecisionView::Pending { .. }));

    let log = d.log();
    assert_eq!(
        log.matches("audit: unlock failed reason=unlock_failed pid=")
            .count(),
        4,
        "{log}"
    );
    assert_no_canary(&d.log_bytes(), &all_cs);
    home.assert_clean(&all_cs);
}

/// Regression tests for Round 1 review findings:
/// - `F-01`: An empty vault (no items, fields, projects or policies) whose
///   `header` row was deleted (`DELETE FROM header`) refuses `app.unlock` with
///   `unlock_failed` even when given the valid resealed VMK, rather than
///   opening read-only without verifying the VMK against the sealed header.
/// - `F-02`: An `unlocker_add` approval whose durable `unlocker_add` audit
///   write fails (`audit` directory blocked) fails with `audit_failed`, rolls
///   back the staged unlocker row (`app.unlock.begin` returns `no_unlocker`),
///   and leaves the enrolment request pending until the audit directory is
///   restored.
/// - `F-03`: Denying three `unlocker_add` requests from the same root never
///   sets `root_auto_denied` or blocks `run.request` for that root.
/// - `F-04`: Passing `--once`, `--for` or `--live` to `envcloak approve` on an
///   `unlocker_add` request is refused before reading the passphrase, and raw
///   IPC `approve` with non-default options is refused with `invalid_options`.
#[test]
fn enrolment_audit_failure_rolls_back_and_empty_vault_deleted_header_refuses_se_unlock() {
    use std::os::unix::fs::PermissionsExt;

    common::terminal_session();
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let paths = VaultPaths::under(data_dir(&home));
    let vmk = Vmk::generate();
    let vault_id = VaultId::generate();
    let pass_env = wrap_vmk_with(
        &vmk,
        &passphrase(&cs),
        UnlockerKind::Passphrase,
        &EnvelopeCtx {
            vault_id,
            unlocker_id: UnlockerId::generate(),
            epoch: INITIAL_EPOCH,
        },
        &KdfParams::minimum(),
        &Argon2id,
    )
    .unwrap();
    // Create an empty vault (0 items, 0 fields, 0 projects, 0 policies).
    let v = Vault::create(&paths, vault_id, vmk, vec![pass_env]).unwrap();
    drop(v.lock());

    let app_id = this_process_app_id();
    let mut d = start_with_app_id(&home, Some(&app_id), None);
    let mut c = client(&home);
    c.unlock(passphrase(&cs), &[]).unwrap();

    // F-03: Denying three distinct `unlocker_add` requests never auto-denies
    // the app root (`root_auto_denied == false`).
    for seed in [0x61u8, 0x62, 0x63] {
        let (_, upub, apub) = sample_se_keys(seed);
        let b = c
            .app_unlocker_enroll_begin(
                &hex_encode(&upub),
                &hex_encode(&apub),
                &format!("Denied {seed}"),
                &[],
            )
            .unwrap();
        let denied = c.deny(&b.request).unwrap();
        assert!(!denied.root_auto_denied, "seed {seed}");
        assert_eq!(
            c.app_unlocker_enroll(&b.request, &[]).unwrap(),
            AppUnlockerEnrollOutput::Denied
        );
    }

    // Open a fresh enrolment request.
    let (unlock_sk, unlock_pub, approve_pub) = sample_se_keys(0x70);
    let enroll_begin = c
        .app_unlocker_enroll_begin(
            &hex_encode(&unlock_pub),
            &hex_encode(&approve_pub),
            "Audit Gate Unlocker",
            &[],
        )
        .unwrap();
    let PendingGetOutput::UnlockerAdd(desc) =
        c.pending_get_any(&enroll_begin.request, &[]).unwrap()
    else {
        panic!("expected unlocker_add descriptor");
    };
    let digest = unlocker_statement_digest(&desc);

    // F-04: CLI `envcloak approve <id> --once` and `--for 1h` and `--live X`
    // are refused with `invalid_options` before reading the passphrase.
    let pass_dir = tempfile::tempdir().unwrap();
    let pass_file = pass_dir.path().join("pass");
    std::fs::write(&pass_file, by_label(&cs, labels::VAULT_PASSPHRASE).value()).unwrap();
    for bad_args in [
        &["approve", enroll_begin.request.as_str(), "--once"][..],
        &["approve", enroll_begin.request.as_str(), "--for", "1h"][..],
        &["approve", enroll_begin.request.as_str(), "--live", "A"][..],
    ] {
        let out = run_cli_in_pty(&home, bad_args, &pass_file);
        assert!(!out.status.success(), "{bad_args:?}");
        let stderr_text = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr_text.contains("invalid_options"),
            "expected invalid_options in stderr for {bad_args:?}: {stderr_text}"
        );
    }
    // Raw IPC `approve` with non-default options is also refused with
    // `invalid_options` without counting a proof failure.
    let err_opts = c
        .approve(
            &enroll_begin.request,
            ApprovalOptions {
                uses: Uses::Session,
                ttl_secs: 3600,
                live: Vec::new(),
            },
            &digest,
            passphrase(&cs),
            &[],
        )
        .unwrap_err();
    assert_eq!(rpc_kind(err_opts).0, ErrorKind::InvalidOptions);
    assert_eq!(c.status().unwrap().approvals.proof_failures, 0);

    // F-02: Block the audit directory so durable `unlocker_add` audit write
    // fails. `approve` must fail with `audit_failed`, roll back the staged
    // unlocker row in `vault.db`, and leave the request pending.
    let audit_dir = data_dir(&home).join("audit");
    std::fs::remove_dir_all(&audit_dir).unwrap();
    std::fs::write(&audit_dir, b"blocked").unwrap();
    let err_audit = c
        .approve(
            &enroll_begin.request,
            ApprovalOptions {
                uses: Uses::Once,
                ttl_secs: DEFAULT_TTL.as_secs(),
                live: Vec::new(),
            },
            &digest,
            passphrase(&cs),
            &[],
        )
        .unwrap_err();
    assert_eq!(rpc_kind(err_audit).0, ErrorKind::AuditFailed);
    assert_eq!(
        c.app_unlocker_enroll(&enroll_begin.request, &[]).unwrap(),
        AppUnlockerEnrollOutput::Pending
    );
    assert_eq!(
        rpc_kind(c.app_unlock_begin(None, &[]).unwrap_err()).0,
        ErrorKind::NoUnlocker
    );

    // Restore the audit directory and complete the enrolment.
    std::fs::remove_file(&audit_dir).unwrap();
    std::fs::create_dir(&audit_dir).unwrap();
    std::fs::set_permissions(&audit_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    c.approve(
        &enroll_begin.request,
        ApprovalOptions {
            uses: Uses::Once,
            ttl_secs: DEFAULT_TTL.as_secs(),
            live: Vec::new(),
        },
        &digest,
        passphrase(&cs),
        &[],
    )
    .unwrap();
    let AppUnlockerEnrollOutput::Enrolled { unlocker_id } =
        c.app_unlocker_enroll(&enroll_begin.request, &[]).unwrap()
    else {
        panic!("expected enrolled after audit recovery");
    };

    // Stop the daemon, delete the `header` row from the empty vault on disk,
    // and restart.
    drop(c);
    d.signal("-TERM");
    assert!(d.wait_exit(Duration::from_secs(30)).is_some());
    assert_no_canary(&d.log_bytes(), &cs);
    drop(d);

    {
        let conn = rusqlite::Connection::open(&paths.db).unwrap();
        conn.execute("DELETE FROM header", []).unwrap();
    }

    // F-01: With the `header` row deleted on an empty vault, `app.unlock`
    // cannot verify the caller-supplied VMK against a sealed header and must
    // refuse with `unlock_failed` (even with the valid resealed VMK).
    let d2 = start_with_app_id(&home, Some(&app_id), None);
    let mut c2 = client(&home);
    let begin = c2.app_unlock_begin(Some(&unlocker_id), &[]).unwrap();
    let (_, sealed) = perform_app_hpke_reseal(&unlock_sk, &begin);
    let err_deleted_header = c2
        .app_unlock(&begin.request_id, &hex_encode(&sealed), &[])
        .unwrap_err();
    assert_eq!(rpc_kind(err_deleted_header).0, ErrorKind::UnlockFailed);
    assert_eq!(c2.status().unwrap().vault.state, VaultState::Locked);
    assert_eq!(c2.status().unwrap().vault.failed_unlocks, 1);
    assert_no_canary(&d2.log_bytes(), &cs);
    home.assert_clean(&cs);
}
