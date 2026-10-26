//! Integration tests for the sign-in worker driver, origin guard, state machine,
//! identity check, declared-state extraction, D-28 test-session adapter client,
//! entry-image binding, and worker reaper (`SPEC.md` §6.8, M2 plan gates `b1`,
//! `b2`, `b5`, `b6`, `b12`, `b13`, `b16`, `b19`, task `M2b-07`).

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tempfile::TempDir;
use zeroize::Zeroizing;

use envcloak_browser::launch::EntryImageError;
use envcloak_browser::{
    AttemptFlow, AttemptOutcome, AttemptSpec, CdpClient, CleanupOutcome, DaemonToDriver, Driver,
    DriverMessage, DriverPipe, EntryImageAnchor, ExpectedIdentity, FORBIDDEN_CHROME_FLAGS,
    LaunchError, LaunchSpec, LoginFieldHints, LoopbackOriginProxy, REAPER_REPLY_BYTES, Reaper,
    ReaperCommand, ReaperReply, TEARDOWN_CONFIRMATION_FILE, TargetScope, TeardownRecord,
    TeardownStep, WORKER_DIAGNOSTIC_FILE, WorkerSessionFormat, WorkerStopReason,
    execute_teardown_sequence, extract_from_cdp,
};
use envcloak_signin::origin::parse_registered;
use envcloak_signin::{
    CheckKind, CookieDomain, CookiePartition, CookiePath, DeclaredCookie, DeclaredStorage,
    IdentityCheck, Label, Origin, SortedSet, TransferScope,
};
use envcloak_sys::owned::{Recorded, RecordingProcesses};
use envcloak_sys::{
    OwnedChild, create_dir_beneath, pipe_cloexec, proc_info, process_running, take_inherited_fd,
};
use envcloak_testkit::signin::{
    Control, INSTALL_BROWSER_RUNTIME, REQUIRE_BROWSER_RUNTIME_VAR, SigninFixture,
    VerifiedBrowserRuntime, browser_versions_path, resolve_browser_runtime,
};

fn browser_runtime_or_skip() -> Option<VerifiedBrowserRuntime> {
    match resolve_browser_runtime(&browser_versions_path()) {
        Ok(rt) => Some(rt),
        Err(reason) => {
            if std::env::var_os(REQUIRE_BROWSER_RUNTIME_VAR).is_some() {
                panic!(
                    "browser runtime missing or unverified ({REQUIRE_BROWSER_RUNTIME_VAR} is set): {reason}; run `{INSTALL_BROWSER_RUNTIME}`"
                );
            }
            eprintln!("skipping browser test (run `{INSTALL_BROWSER_RUNTIME}`): {reason}");
            None
        }
    }
}

fn fixture_totp_code(control: &Control, secret_hex: &str, step_offset: i64) -> String {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let ts = if step_offset >= 0 {
        now_secs.saturating_add((step_offset as u64) * 30)
    } else {
        now_secs.saturating_sub(((-step_offset) as u64) * 30)
    };
    control
        .verify_totp(secret_hex, ts, 8, "SHA1", "00000000")
        .expect("verify_totp")
        .expected
        .expect("expected totp code")
}

fn default_transfer_scope(app_origin: &Origin) -> TransferScope {
    let session_cookie = DeclaredCookie {
        name: Label::new("session").expect("valid cookie name"),
        domain: CookieDomain::HostOnly(app_origin.host().clone()),
        path: CookiePath::new("/").expect("valid cookie path"),
        partition: CookiePartition::Unpartitioned,
    };
    let tenant_storage = DeclaredStorage {
        origin: app_origin.clone(),
        key: Label::new("acme_tenant").expect("valid storage key"),
    };
    TransferScope {
        cookies: SortedSet::new(vec![session_cookie]).expect("valid cookies"),
        storage: SortedSet::new(vec![tenant_storage]).expect("valid storage"),
    }
}

fn cookie_only_transfer_scope(origin: &Origin) -> TransferScope {
    let session_cookie = DeclaredCookie {
        name: Label::new("session").expect("valid cookie name"),
        domain: CookieDomain::HostOnly(origin.host().clone()),
        path: CookiePath::new("/").expect("valid cookie path"),
        partition: CookiePartition::Unpartitioned,
    };
    TransferScope {
        cookies: SortedSet::new(vec![session_cookie]).expect("valid cookies"),
        storage: SortedSet::new(vec![]).expect("valid storage"),
    }
}

fn whoami_identity_check() -> IdentityCheck {
    IdentityCheck {
        kind: CheckKind::Endpoint,
        locator: Label::new("/api/whoami").expect("valid locator"),
    }
}

fn build_target_scope(app_origin: &Origin, extra_entry: Option<&Origin>) -> TargetScope {
    let mut entry = vec![app_origin.clone()];
    if let Some(ex) = extra_entry {
        entry.push(ex.clone());
    }
    TargetScope {
        app: SortedSet::new(vec![app_origin.clone()]).expect("valid app scope"),
        credential_entry: SortedSet::new(entry).expect("valid entry scope"),
        identity_provider: SortedSet::new(vec![]).expect("valid idp scope"),
        callback: SortedSet::new(vec![]).expect("valid callback scope"),
    }
}

#[derive(Serialize, Deserialize)]
struct SubprocReaperSpec {
    chrome_exe: PathBuf,
    expected_sha256_hex: String,
    attempt_dir_path: PathBuf,
    host_resolver_rules: Option<String>,
    proxy_server: Option<String>,
    test_ca_spki_sha256: Option<String>,
    attempt_id: String,
}

/// Subprocess entry point invoked when `EntryImageAnchor::spawn_bound` runs this
/// test binary with `--exact subprocess_dispatcher --nocapture`.
#[test]
fn subprocess_dispatcher() {
    let Ok(mode) = std::env::var("ENVCLOAK_SUBPROC_MODE") else {
        // Normal `cargo test` run: no-op unless invoked as a bound child.
        return;
    };

    match mode.as_str() {
        "probe" => {
            let marker = std::env::var("ENVCLOAK_PROBE_PAYLOAD")
                .unwrap_or_else(|_| "ANCHOR_PROBE_V1".to_owned());
            if let Ok(fd) = take_inherited_fd(3) {
                let mut f = File::from(fd);
                let _ = f.write_all(marker.as_bytes());
                let _ = f.flush();
            }
            std::process::exit(0);
        }
        "reaper" => {
            let cdp_in = take_inherited_fd(3).expect("reaper fd 3 cdp_in");
            let cdp_out = take_inherited_fd(4).expect("reaper fd 4 cdp_out");
            let spec_fd = take_inherited_fd(5).expect("reaper fd 5 spec");
            let ctrl_r = take_inherited_fd(6).expect("reaper fd 6 ctrl_r");
            let ctrl_w = take_inherited_fd(7).expect("reaper fd 7 ctrl_w");
            let lifeline = take_inherited_fd(8).expect("reaper fd 8 lifeline");
            let attempt_dir = take_inherited_fd(9).expect("reaper fd 9 attempt_dir");

            let mut spec_bytes = Vec::new();
            File::from(spec_fd)
                .read_to_end(&mut spec_bytes)
                .expect("read reaper spec");
            let sub: SubprocReaperSpec =
                serde_json::from_slice(&spec_bytes).expect("parse reaper spec");
            let mut launch = LaunchSpec::new(
                &sub.attempt_id,
                sub.chrome_exe,
                sub.expected_sha256_hex,
                sub.attempt_dir_path,
            );
            launch.host_resolver_rules = sub.host_resolver_rules;
            launch.proxy_server = sub.proxy_server;
            launch.test_ca_spki_sha256 = sub.test_ca_spki_sha256;

            let outcome = Reaper::run(
                File::from(ctrl_r),
                File::from(ctrl_w),
                lifeline,
                launch,
                (cdp_in, cdp_out),
                attempt_dir,
                &sub.attempt_id,
            );
            std::process::exit(outcome.exit_code());
        }
        "driver_hang" => {
            // Holds the driver side of the CDP pipes open until killed by the harness
            // (`kill -9` of the driver test).
            let _cdp_r = take_inherited_fd(3).expect("driver fd 3");
            let _cdp_w = take_inherited_fd(4).expect("driver fd 4");
            if let Ok(ready_fd) = take_inherited_fd(5) {
                let mut f = File::from(ready_fd);
                let _ = f.write_all(b"DRIVER_READY\n");
                let _ = f.flush();
            }
            loop {
                std::thread::sleep(Duration::from_secs(60));
            }
        }
        _ => std::process::exit(2),
    }
}

struct SpawnedReaper {
    child: OwnedChild,
    ctrl_r: File,
    ctrl_w: File,
    lifeline_w: File,
}

fn spawn_reaper_via_anchor(
    anchor: &EntryImageAnchor,
    sub_spec: &SubprocReaperSpec,
    cdp_browser_in: OwnedFd,
    cdp_browser_out: OwnedFd,
    attempt_dir_file: &File,
) -> SpawnedReaper {
    let (spec_r, spec_w) = pipe_cloexec().expect("spec pipe");
    let (ctrl_to_reaper_r, ctrl_to_reaper_w) = pipe_cloexec().expect("ctrl_to_reaper pipe");
    let (ctrl_from_reaper_r, ctrl_from_reaper_w) = pipe_cloexec().expect("ctrl_from_reaper pipe");
    let (lifeline_r, lifeline_w) = pipe_cloexec().expect("lifeline pipe");

    let payload = serde_json::to_vec(sub_spec).expect("serialize SubprocReaperSpec");
    {
        let mut sw = File::from(spec_w);
        sw.write_all(&payload).expect("write SubprocReaperSpec");
    }

    let argv: &[&[u8]] = &[
        b"envcloakd",
        b"--exact",
        b"subprocess_dispatcher",
        b"--nocapture",
    ];
    let env: &[&[u8]] = &[b"ENVCLOAK_SUBPROC_MODE=reaper", b"PATH=/usr/bin:/bin"];
    let fds = [
        (cdp_browser_in.as_fd(), 3),
        (cdp_browser_out.as_fd(), 4),
        (spec_r.as_fd(), 5),
        (ctrl_to_reaper_r.as_fd(), 6),
        (ctrl_from_reaper_w.as_fd(), 7),
        (lifeline_r.as_fd(), 8),
        (attempt_dir_file.as_fd(), 9),
    ];

    let child = anchor
        .spawn_bound(argv, env, &fds)
        .expect("spawn_bound reaper");

    drop(cdp_browser_in);
    drop(cdp_browser_out);
    drop(spec_r);
    drop(ctrl_to_reaper_r);
    drop(ctrl_from_reaper_w);
    drop(lifeline_r);

    SpawnedReaper {
        child,
        ctrl_r: File::from(ctrl_from_reaper_r),
        ctrl_w: File::from(ctrl_to_reaper_w),
        lifeline_w: File::from(lifeline_w),
    }
}

fn wait_for_worker_diagnostic(attempt_dir: &Path, timeout: Duration) -> (u32, u32) {
    let meta_path = attempt_dir.join(WORKER_DIAGNOSTIC_FILE);
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(bytes) = std::fs::read(&meta_path)
            && let Ok(val) = serde_json::from_slice::<Value>(&bytes)
            && let (Some(pid), Some(sid)) = (
                val.get("pid").and_then(Value::as_u64),
                val.get("sid").and_then(Value::as_u64),
            )
            && pid > 0
        {
            return (pid as u32, sid as u32);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!(
        "timed out waiting for {} in {}",
        WORKER_DIAGNOSTIC_FILE,
        attempt_dir.display()
    );
}

fn is_pid_alive(pid: u32) -> bool {
    let Ok(pid_i32) = i32::try_from(pid) else {
        return false;
    };
    let Ok(info) = proc_info(pid_i32) else {
        return false;
    };
    process_running(pid_i32, info.start_time)
}

#[allow(clippy::too_many_arguments)]
fn run_browser_login_attempt(
    runtime: &VerifiedBrowserRuntime,
    login_url: &str,
    scope: TargetScope,
    identity_check: IdentityCheck,
    expected_identity: ExpectedIdentity,
    transfer: TransferScope,
    format: WorkerSessionFormat,
    username: &str,
    password: &str,
    codes: &[String],
    host_resolver_rules: Option<String>,
    test_ca_spki_sha256: Option<String>,
) -> (AttemptOutcome, ReaperReply, TempDir) {
    let temp = tempfile::Builder::new()
        .prefix("ec-m2b07-attempt-")
        .tempdir()
        .expect("tempdir");
    let attempt_dir_file = File::open(temp.path()).expect("open attempt_dir");
    create_dir_beneath(&attempt_dir_file, OsStr::new("profile"), 0o700)
        .expect("create profile 0700");

    let proxy = LoopbackOriginProxy::start(scope.clone()).expect("start LoopbackOriginProxy");
    let proxy_blocked = proxy.blocked_handle();

    let (driver_to_chrome_r, driver_to_chrome_w) = pipe_cloexec().expect("pipe 1");
    let (chrome_to_driver_r, chrome_to_driver_w) = pipe_cloexec().expect("pipe 2");
    let (ctrl_to_reaper_r, ctrl_to_reaper_w) = pipe_cloexec().expect("ctrl pipe 1");
    let (ctrl_from_reaper_r, ctrl_from_reaper_w) = pipe_cloexec().expect("ctrl pipe 2");
    let (lifeline_r, lifeline_w) = pipe_cloexec().expect("lifeline pipe");

    let mut launch = LaunchSpec::new(
        "attempt-1",
        &runtime.chrome_exe,
        &runtime.pins.chrome_sha256,
        temp.path(),
    );
    launch.host_resolver_rules = host_resolver_rules;
    launch.proxy_server = Some(proxy.addr().to_owned());
    launch.test_ca_spki_sha256 = test_ca_spki_sha256;

    let reaper_handle = std::thread::spawn(move || {
        Reaper::run(
            File::from(ctrl_to_reaper_r),
            File::from(ctrl_from_reaper_w),
            lifeline_r,
            launch,
            (driver_to_chrome_r, chrome_to_driver_w),
            OwnedFd::from(attempt_dir_file),
            "attempt-1",
        )
    });

    let (drv_to_daemon_r, drv_to_daemon_w) = pipe_cloexec().expect("drv_to_daemon");
    let (daemon_to_drv_r, daemon_to_drv_w) = pipe_cloexec().expect("daemon_to_drv");

    let spec = AttemptSpec {
        scope,
        identity_check,
        expected_identity,
        transfer,
        session_format: format,
        flow: AttemptFlow::BrowserLogin {
            login_url: login_url.to_owned(),
            hints: LoginFieldHints::default(),
        },
    };

    let driver_handle = std::thread::spawn(move || {
        let mut pipe = DriverPipe::new(File::from(daemon_to_drv_r), File::from(drv_to_daemon_w));
        Driver::run(
            &mut pipe,
            spec,
            Some((chrome_to_driver_r, driver_to_chrome_w)),
            Some(proxy_blocked),
        )
    });

    let mut daemon_r = File::from(drv_to_daemon_r);
    let mut daemon_w = File::from(daemon_to_drv_w);
    let mut code_idx = 0usize;

    loop {
        let Ok(msg) = envcloak_browser::recv_from_driver(&mut daemon_r) else {
            break;
        };
        match msg {
            DriverMessage::NeedUsername => {
                let _ = envcloak_browser::send_to_driver(
                    &mut daemon_w,
                    &DaemonToDriver::Username(Zeroizing::new(username.to_owned())),
                );
            }
            DriverMessage::NeedPassword => {
                let _ = envcloak_browser::send_to_driver(
                    &mut daemon_w,
                    &DaemonToDriver::Password(Zeroizing::new(password.to_owned())),
                );
            }
            DriverMessage::NeedCode { .. } => {
                let code = codes
                    .get(code_idx)
                    .cloned()
                    .unwrap_or_else(|| "00000000".to_owned());
                code_idx += 1;
                let _ = envcloak_browser::send_to_driver(
                    &mut daemon_w,
                    &DaemonToDriver::Code(Zeroizing::new(code)),
                );
            }
            DriverMessage::Captured(_) | DriverMessage::Stopped(_) => {
                break;
            }
        }
    }

    let attempt_outcome = driver_handle.join().expect("join driver");

    // Daemon sends `ReaperCommand::Stop` as soon as the driver exits.
    let mut ctrl_w_file = File::from(ctrl_to_reaper_w);
    let _ = ctrl_w_file.write_all(&ReaperCommand::Stop.encode());
    let _ = ctrl_w_file.flush();
    drop(lifeline_w);

    let mut reply_buf = [0u8; REAPER_REPLY_BYTES];
    File::from(ctrl_from_reaper_r)
        .read_exact(&mut reply_buf)
        .expect("read reaper reply");
    let reply = ReaperReply::decode(&reply_buf).expect("decode reaper reply");
    let reaper_outcome = reaper_handle.join().expect("join reaper");
    assert_eq!(reaper_outcome.exit_code(), 0);

    (attempt_outcome, reply, temp)
}

#[test]
fn entry_image_binding_and_negative_controls() {
    let current_exe = std::env::current_exe().expect("current_exe");
    let canon_exe = std::fs::canonicalize(&current_exe).expect("canonicalize current_exe");

    let anchor = EntryImageAnchor::capture_from_path(&canon_exe).expect("capture current_exe");

    // 1. Positive control: bound child starts from the anchor and writes its probe payload.
    {
        let (r, w) = pipe_cloexec().expect("pipe");
        let argv: &[&[u8]] = &[
            b"envcloakd",
            b"--exact",
            b"subprocess_dispatcher",
            b"--nocapture",
        ];
        let env: &[&[u8]] = &[
            b"ENVCLOAK_SUBPROC_MODE=probe",
            b"ENVCLOAK_PROBE_PAYLOAD=ANCHOR_OK_1",
            b"PATH=/usr/bin:/bin",
        ];
        let fds = [(w.as_fd(), 3)];
        let child = anchor.spawn_bound(argv, env, &fds).expect("spawn_bound");
        drop(w);
        let mut out = String::new();
        File::from(r).read_to_string(&mut out).expect("read probe");
        let status = child.reap().expect("reap probe child");
        assert!(status.success());
        assert_eq!(out, "ANCHOR_OK_1");
    }

    // 2. macOS negative control: a suspended child whose `cdhash` differs from the
    // startup identity is refused and killed before resumption, executing zero user-space
    // instructions and writing nothing to its probe pipe.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let mismatched = EntryImageAnchor::capture_from_path(&canon_exe)
            .expect("capture")
            .with_expected_cdhash_for_test([0xAA; envcloak_sys::CDHASH_LEN]);
        let (r, w) = pipe_cloexec().expect("pipe");
        let argv: &[&[u8]] = &[
            b"envcloakd",
            b"--exact",
            b"subprocess_dispatcher",
            b"--nocapture",
        ];
        let env: &[&[u8]] = &[
            b"ENVCLOAK_SUBPROC_MODE=probe",
            b"ENVCLOAK_PROBE_PAYLOAD=MUST_NEVER_RUN",
            b"PATH=/usr/bin:/bin",
        ];
        let fds = [(w.as_fd(), 3)];
        let res = mismatched.spawn_bound(argv, env, &fds);
        drop(w);
        assert_eq!(res.unwrap_err(), EntryImageError::IdentityMismatch);
        let mut out = String::new();
        File::from(r).read_to_string(&mut out).expect("read pipe");
        assert!(
            out.is_empty(),
            "suspended child with mismatched cdhash must be killed before running any instruction"
        );
    }

    // 3. Linux test: rewriting or replacing the installed daemon file after startup
    // does not change the image launched by the existing anchor (`memfd`), while a
    // newly captured anchor adopts the new file.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let temp = tempfile::tempdir().expect("tempdir");
        let installed_bin = temp.path().join("envcloakd");
        std::fs::copy(&canon_exe, &installed_bin).expect("copy exe");
        let anchor_before =
            EntryImageAnchor::capture_from_path(&installed_bin).expect("capture installed");

        // Replace `installed_bin` on disk with a corrupt non-ELF file; `anchor_before`
        // must still execute the sealed memfd copy, while a new capture fails on spawn.
        std::fs::remove_file(&installed_bin).expect("remove installed");
        std::fs::write(&installed_bin, b"not-an-elf-binary").expect("overwrite installed");

        let (r, w) = pipe_cloexec().expect("pipe");
        let argv: &[&[u8]] = &[
            b"envcloakd",
            b"--exact",
            b"subprocess_dispatcher",
            b"--nocapture",
        ];
        let env: &[&[u8]] = &[
            b"ENVCLOAK_SUBPROC_MODE=probe",
            b"ENVCLOAK_PROBE_PAYLOAD=SEALED_MEMFD_STILL_WORKS",
            b"PATH=/usr/bin:/bin",
        ];
        let child = anchor_before
            .spawn_bound(argv, env, &[(w.as_fd(), 3)])
            .expect("sealed memfd still spawns after disk file overwrite");
        drop(w);
        let mut out = String::new();
        File::from(r).read_to_string(&mut out).expect("read");
        assert!(child.reap().unwrap().success());
        assert_eq!(out, "SEALED_MEMFD_STILL_WORKS");
    }

    // 4. Inability to capture or verify an entry image starts no credential step
    // and never falls back to a mutable file path or symlink.
    let temp = tempfile::tempdir().expect("tempdir");
    let missing = temp.path().join("nonexistent-envcloakd");
    assert_eq!(
        EntryImageAnchor::capture_from_path(&missing).unwrap_err(),
        EntryImageError::NotFound
    );

    let symlink_path = temp.path().join("symlink-envcloakd");
    std::os::unix::fs::symlink(&canon_exe, &symlink_path).expect("symlink");
    assert_eq!(
        EntryImageAnchor::capture_from_path(&symlink_path).unwrap_err(),
        EntryImageError::NotFound,
        "symlink must be refused by O_NOFOLLOW"
    );
}

#[test]
fn gate_b1_wrong_target_matrix_and_https_ca_vs_self_signed() {
    let Some(runtime) = browser_runtime_or_skip() else {
        return;
    };
    let (origins, control) = SigninFixture::start();

    let app_origin = parse_registered(&origins.app).expect("parse app origin");
    let idp_origin = parse_registered(&origins.idp).expect("parse idp origin");
    let app_scope = build_target_scope(&app_origin, Some(&idp_origin));
    let expected_editor = ExpectedIdentity {
        account: Label::new("editor@acme.test").unwrap(),
        tenant: Some(Label::new("t1").unwrap()),
        role: Label::new("editor").unwrap(),
    };

    // 1. Matrix of wrong origins and mid-flow traps: zero credential submissions at every
    // wrong origin and zero exfiltrations across all 5 channels.
    let wrong_urls = [
        ("unregistered", format!("{}/login", origins.unregistered)),
        ("idn_lookalike", format!("{}/login", origins.idn_lookalike)),
        ("userinfo", origins.userinfo.clone()),
        ("changed_port", format!("{}/login", origins.changed_port)),
        (
            "cross_origin_iframe",
            format!("{}/login/iframe-trap", origins.app),
        ),
        (
            "mid_login_redirect",
            format!("{}/login/redirect-trap", origins.app),
        ),
        (
            "off_origin_form_action",
            format!("{}/login/off-origin-action", origins.app),
        ),
        (
            "exfil_fetch",
            format!("{}/login/exfil?channel=fetch", origins.app),
        ),
        (
            "exfil_worker",
            format!("{}/login/exfil?channel=worker", origins.app),
        ),
        (
            "exfil_service_worker",
            format!("{}/login/exfil?channel=service_worker", origins.app),
        ),
        (
            "exfil_websocket",
            format!("{}/login/exfil?channel=websocket", origins.app),
        ),
        (
            "exfil_beacon",
            format!("{}/login/exfil?channel=beacon", origins.app),
        ),
    ];

    for (case_name, url) in &wrong_urls {
        let code = fixture_totp_code(&control, &origins.editor_totp_secret_hex, 0);
        let (outcome, reply, _dir) = run_browser_login_attempt(
            &runtime,
            url,
            app_scope.clone(),
            whoami_identity_check(),
            expected_editor.clone(),
            default_transfer_scope(&app_origin),
            WorkerSessionFormat::CookiesAndStorage,
            "editor@acme.test",
            &origins.editor_password,
            &[code],
            Some(origins.host_resolver_rules.clone()),
            None,
        );
        assert_eq!(
            outcome,
            AttemptOutcome::Stopped(WorkerStopReason::OffOrigin),
            "case {case_name} ({url}) must stop with OffOrigin"
        );
        assert_eq!(reply, ReaperReply::Confirmed);
    }

    let snap = control.counters().expect("counters");
    assert_eq!(
        snap.wrong_target_submissions, 0,
        "zero credentials may ever be submitted to a wrong target"
    );
    assert_eq!(
        snap.exfiltration_by_channel
            .get("fetch")
            .copied()
            .unwrap_or(0),
        0,
        "fetch exfil must be 0"
    );
    assert_eq!(
        snap.exfiltration_by_channel
            .get("worker")
            .copied()
            .unwrap_or(0),
        0,
        "worker exfil must be 0"
    );
    assert_eq!(
        snap.exfiltration_by_channel
            .get("service_worker")
            .copied()
            .unwrap_or(0),
        0,
        "service_worker exfil must be 0"
    );
    assert_eq!(
        snap.exfiltration_by_channel
            .get("websocket")
            .copied()
            .unwrap_or(0),
        0,
        "websocket exfil must be 0"
    );
    assert_eq!(
        snap.exfiltration_by_channel
            .get("beacon")
            .copied()
            .unwrap_or(0),
        0,
        "beacon exfil must be 0"
    );
    assert_eq!(snap.by_origin["unregistered"].password_submissions, 0);
    assert_eq!(snap.by_origin["idn_lookalike"].password_submissions, 0);
    assert_eq!(snap.by_origin["userinfo"].password_submissions, 0);
    assert_eq!(snap.by_origin["changed_port"].password_submissions, 0);

    // 2. Registered HTTPS origin with a self-signed certificate (not trusted by platform
    // roots or test CA SPKI): fails TLS check with zero credential submissions.
    let https_self_origin =
        parse_registered(&origins.https_self_signed).expect("parse https_self_signed");
    let https_self_scope = build_target_scope(&https_self_origin, None);
    {
        let code = fixture_totp_code(&control, &origins.editor_totp_secret_hex, 0);
        let (outcome, reply, _dir) = run_browser_login_attempt(
            &runtime,
            &format!("{}/login", origins.https_self_signed),
            https_self_scope,
            whoami_identity_check(),
            expected_editor.clone(),
            cookie_only_transfer_scope(&https_self_origin),
            WorkerSessionFormat::Cookies,
            "editor@acme.test",
            &origins.editor_password,
            &[code],
            Some(origins.host_resolver_rules.clone()),
            None, // No SPKI override -> self-signed cert rejected!
        );
        assert_eq!(
            outcome,
            AttemptOutcome::Stopped(WorkerStopReason::OffOrigin),
            "self-signed HTTPS origin must be refused"
        );
        assert_eq!(reply, ReaperReply::Confirmed);
    }
    let snap_after_self = control.counters().expect("counters");
    assert_eq!(
        snap_after_self.by_origin["https_self_signed"].password_submissions, 0,
        "zero credentials submitted to self-signed HTTPS origin"
    );

    // 3. Registered HTTPS origin with the fixture test CA (`test_ca_spki_sha256` under
    // `testing`): succeeds and captures the declared `session` cookie.
    let https_ca_origin = parse_registered(&origins.https_test_ca).expect("parse https_test_ca");
    let https_ca_scope = build_target_scope(&https_ca_origin, None);
    {
        let code = fixture_totp_code(&control, &origins.editor_totp_secret_hex, 0);
        let (outcome, reply, _dir) = run_browser_login_attempt(
            &runtime,
            &format!("{}/login", origins.https_test_ca),
            https_ca_scope,
            whoami_identity_check(),
            expected_editor,
            cookie_only_transfer_scope(&https_ca_origin),
            WorkerSessionFormat::Cookies,
            "editor@acme.test",
            &origins.editor_password,
            &[code],
            Some(origins.host_resolver_rules.clone()),
            Some(origins.test_ca_spki_sha256.clone()),
        );
        match outcome {
            AttemptOutcome::Captured(state) => {
                assert_eq!(state.cookies.len(), 1);
                assert_eq!(state.cookies[0].declaration.name.as_str(), "session");
                assert!(state.cookies[0].value.starts_with("sess_"));
            }
            other => panic!("expected Captured on https_test_ca, got {other:?}"),
        }
        assert_eq!(reply, ReaperReply::Confirmed);
    }
    let snap_after_ca = control.counters().expect("counters");
    assert_eq!(
        snap_after_ca.by_origin["https_test_ca"].password_submissions, 1,
        "https_test_ca must record 1 valid password submission"
    );
}

#[test]
fn gate_b2_no_listening_socket_or_devtools_active_port_and_clean_env() {
    let Some(runtime) = browser_runtime_or_skip() else {
        return;
    };

    // 1. Forbidden flag check: `--remote-debugging-port` or any screenshot/HAR/trace flag
    // is rejected before launch.
    let temp = tempfile::tempdir().expect("tempdir");
    for forbidden in FORBIDDEN_CHROME_FLAGS {
        let mut bad_spec = LaunchSpec::new(
            "forbidden-flag-test",
            &runtime.chrome_exe,
            &runtime.pins.chrome_sha256,
            temp.path(),
        );
        bad_spec.extra_args.push(format!("{forbidden}=9222"));
        assert!(matches!(
            bad_spec.build_args(),
            Err(LaunchError::ForbiddenFlag(_))
        ));
    }

    // 2. Wrong SHA-256 is refused before Chrome is ever launched.
    {
        let attempt_dir_file = File::open(temp.path()).expect("open temp");
        create_dir_beneath(&attempt_dir_file, OsStr::new("profile"), 0o700).expect("profile");
        let (cdp_in, _cdp_in_w) = pipe_cloexec().expect("pipe");
        let (_cdp_out_r, cdp_out) = pipe_cloexec().expect("pipe");
        let (ctrl_r, _ctrl_w) = pipe_cloexec().expect("pipe");
        let (reply_r, reply_w) = pipe_cloexec().expect("pipe");
        let (lifeline_r, _lifeline_w) = pipe_cloexec().expect("pipe");

        let bad_hash_spec = LaunchSpec::new(
            "bad-hash-attempt",
            &runtime.chrome_exe,
            "0000000000000000000000000000000000000000000000000000000000000000",
            temp.path(),
        );
        let outcome = Reaper::run(
            File::from(ctrl_r),
            File::from(reply_w),
            lifeline_r,
            bad_hash_spec,
            (cdp_in, cdp_out),
            OwnedFd::from(attempt_dir_file),
            "bad-hash-attempt",
        );
        assert_eq!(
            outcome.cleanup,
            CleanupOutcome::Failed(TeardownStep::Launch)
        );
        assert_eq!(outcome.exit_code(), 1);
        let mut buf = [0u8; REAPER_REPLY_BYTES];
        File::from(reply_r).read_exact(&mut buf).expect("reply");
        assert_eq!(
            ReaperReply::decode(&buf),
            Ok(ReaperReply::Failed(TeardownStep::Launch))
        );
        assert!(!temp.path().join(WORKER_DIAGNOSTIC_FILE).exists());
        assert!(!temp.path().join(TEARDOWN_CONFIRMATION_FILE).exists());
    }

    // 3. Live worker check: no `DevToolsActivePort` file, `getsid(pid) == pid`, and
    // on Linux `/proc/<pid>/environ` holds none of the caller's environment markers.
    let live_temp = tempfile::tempdir().expect("live_temp");
    let attempt_dir_file = File::open(live_temp.path()).expect("open live_temp");
    create_dir_beneath(&attempt_dir_file, OsStr::new("profile"), 0o700).expect("profile");

    let (driver_to_chrome_r, driver_to_chrome_w) = pipe_cloexec().expect("pipe");
    let (chrome_to_driver_r, chrome_to_driver_w) = pipe_cloexec().expect("pipe");
    let (ctrl_to_reaper_r, ctrl_to_reaper_w) = pipe_cloexec().expect("ctrl");
    let (ctrl_from_reaper_r, ctrl_from_reaper_w) = pipe_cloexec().expect("ctrl");
    let (lifeline_r, lifeline_w) = pipe_cloexec().expect("lifeline");

    let spec = LaunchSpec::new(
        "live-b2-attempt",
        &runtime.chrome_exe,
        &runtime.pins.chrome_sha256,
        live_temp.path(),
    );
    let reaper_thread = std::thread::spawn(move || {
        Reaper::run(
            File::from(ctrl_to_reaper_r),
            File::from(ctrl_from_reaper_w),
            lifeline_r,
            spec,
            (driver_to_chrome_r, chrome_to_driver_w),
            OwnedFd::from(attempt_dir_file),
            "live-b2-attempt",
        )
    });

    let mut cdp = CdpClient::new(
        File::from(chrome_to_driver_r),
        File::from(driver_to_chrome_w),
    );
    let targets = cdp
        .call(None, "Target.getTargets", json!({}))
        .expect("Target.getTargets over pipe");
    assert!(targets.get("targetInfos").is_some());

    let (worker_pid, worker_sid) =
        wait_for_worker_diagnostic(live_temp.path(), Duration::from_secs(5));
    assert_eq!(
        worker_pid, worker_sid,
        "worker Chrome must lead its own session (getsid == pid)"
    );

    // Verify no `DevToolsActivePort` exists in `attempt_dir` or `profile`.
    assert!(
        !live_temp.path().join("DevToolsActivePort").exists(),
        "DevToolsActivePort must not exist in attempt_dir"
    );
    assert!(
        !live_temp.path().join("profile/DevToolsActivePort").exists(),
        "DevToolsActivePort must not exist in profile"
    );

    #[cfg(target_os = "linux")]
    {
        if let Ok(env_bytes) = std::fs::read(format!("/proc/{worker_pid}/environ")) {
            let env_str = String::from_utf8_lossy(&env_bytes);
            assert!(
                !env_str.contains("CARGO_PKG_NAME"),
                "worker Chrome environment must be cleared of parent Cargo variables"
            );
        }
    }

    drop(cdp);
    let _ = File::from(ctrl_to_reaper_w).write_all(&ReaperCommand::Stop.encode());
    drop(lifeline_w);

    let mut reply_buf = [0u8; REAPER_REPLY_BYTES];
    File::from(ctrl_from_reaper_r)
        .read_exact(&mut reply_buf)
        .expect("read reply");
    assert_eq!(ReaperReply::decode(&reply_buf), Ok(ReaperReply::Confirmed));
    let out = reaper_thread.join().expect("join reaper");
    assert_eq!(out.exit_code(), 0);
}

#[test]
fn gate_b16_attempt_budget_and_gate_b13_handoff_and_gate_b6_wrong_identity() {
    let Some(runtime) = browser_runtime_or_skip() else {
        return;
    };
    let (origins, control) = SigninFixture::start();

    let app_origin = parse_registered(&origins.app).expect("app origin");
    let app_scope = build_target_scope(&app_origin, None);
    let expected_editor = ExpectedIdentity {
        account: Label::new("editor@acme.test").unwrap(),
        tenant: Some(Label::new("t1").unwrap()),
        role: Label::new("editor").unwrap(),
    };

    // 1. Gate b16: Wrong password stops after exactly 1 password submission (`CredentialsRejected`).
    control.reset_counters().expect("reset");
    {
        let code = fixture_totp_code(&control, &origins.editor_totp_secret_hex, 0);
        let (outcome, _reply, _dir) = run_browser_login_attempt(
            &runtime,
            &format!("{}/login", origins.app),
            app_scope.clone(),
            whoami_identity_check(),
            expected_editor.clone(),
            default_transfer_scope(&app_origin),
            WorkerSessionFormat::CookiesAndStorage,
            "editor@acme.test",
            "wrong-password-attempt",
            &[code],
            Some(origins.host_resolver_rules.clone()),
            None,
        );
        assert_eq!(
            outcome,
            AttemptOutcome::Stopped(WorkerStopReason::CredentialsRejected)
        );
    }
    let snap_pw = control.counters().expect("counters");
    assert_eq!(
        snap_pw.password_submissions, 1,
        "wrong password must stop after 1 password submission"
    );

    // 2. Gate b16: Wrong TOTP codes stop after 1 password submission and 2 code submissions (`CodeRejected`).
    control.reset_counters().expect("reset");
    {
        let (outcome, _reply, _dir) = run_browser_login_attempt(
            &runtime,
            &format!("{}/login", origins.app),
            app_scope.clone(),
            whoami_identity_check(),
            expected_editor.clone(),
            default_transfer_scope(&app_origin),
            WorkerSessionFormat::CookiesAndStorage,
            "editor@acme.test",
            &origins.editor_password,
            &[
                "00000000".to_owned(),
                "11111111".to_owned(),
                "22222222".to_owned(),
            ],
            Some(origins.host_resolver_rules.clone()),
            None,
        );
        assert_eq!(
            outcome,
            AttemptOutcome::Stopped(WorkerStopReason::CodeRejected)
        );
    }
    let snap_code = control.counters().expect("counters");
    assert_eq!(
        snap_code.password_submissions, 1,
        "password must not be re-submitted during MFA code retry"
    );
    assert_eq!(
        snap_code.code_submissions, 2,
        "wrong TOTP codes must stop after exactly 2 code submissions"
    );

    // 3. Gate b16 positive retry control: 1st TOTP code wrong, 2nd TOTP code valid -> succeeds!
    control.reset_counters().expect("reset");
    {
        let valid_code = fixture_totp_code(&control, &origins.editor_totp_secret_hex, 0);
        let (outcome, _reply, _dir) = run_browser_login_attempt(
            &runtime,
            &format!("{}/login", origins.app),
            app_scope.clone(),
            whoami_identity_check(),
            expected_editor.clone(),
            default_transfer_scope(&app_origin),
            WorkerSessionFormat::CookiesAndStorage,
            "editor@acme.test",
            &origins.editor_password,
            &["00000000".to_owned(), valid_code],
            Some(origins.host_resolver_rules.clone()),
            None,
        );
        assert!(
            matches!(outcome, AttemptOutcome::Captured(_)),
            "second TOTP code should succeed when valid, got {outcome:?}"
        );
    }
    let snap_retry_ok = control.counters().expect("counters");
    assert_eq!(snap_retry_ok.password_submissions, 1);
    assert_eq!(snap_retry_ok.code_submissions, 2);

    // 4. Gate b13: CAPTCHA page stops with `HandoffRequired` and submits nothing.
    control.reset_counters().expect("reset");
    {
        let code = fixture_totp_code(&control, &origins.editor_totp_secret_hex, 0);
        let (outcome, _reply, _dir) = run_browser_login_attempt(
            &runtime,
            &format!("{}/login/captcha", origins.app),
            app_scope.clone(),
            whoami_identity_check(),
            expected_editor.clone(),
            default_transfer_scope(&app_origin),
            WorkerSessionFormat::CookiesAndStorage,
            "editor@acme.test",
            &origins.editor_password,
            &[code],
            Some(origins.host_resolver_rules.clone()),
            None,
        );
        assert_eq!(
            outcome,
            AttemptOutcome::Stopped(WorkerStopReason::HandoffRequired)
        );
    }
    let snap_captcha = control.counters().expect("counters");
    assert_eq!(snap_captcha.password_submissions, 0);
    assert_eq!(snap_captcha.code_submissions, 0);

    // 5. Gate b6: Login landing in wrong tenant (`t2` instead of `t1`) stops with
    // `IdentityUnverified` and captures nothing.
    control.reset_counters().expect("reset");
    {
        let code = fixture_totp_code(&control, &origins.editor_totp_secret_hex, 0);
        let (outcome, _reply, _dir) = run_browser_login_attempt(
            &runtime,
            &format!("{}/login/wrong-tenant-form", origins.app),
            app_scope.clone(),
            whoami_identity_check(),
            expected_editor.clone(),
            default_transfer_scope(&app_origin),
            WorkerSessionFormat::CookiesAndStorage,
            "editor@acme.test",
            &origins.editor_password,
            &[code],
            Some(origins.host_resolver_rules.clone()),
            None,
        );
        assert_eq!(
            outcome,
            AttemptOutcome::Stopped(WorkerStopReason::IdentityUnverified)
        );
    }

    // 6. Gate b19 (client side): D-28 test-session adapter client mints session,
    // verifies `/api/whoami`, and extracts declared state without launching a browser.
    control.reset_counters().expect("reset");
    {
        let (drv_to_daemon_r, drv_to_daemon_w) = pipe_cloexec().expect("pipe");
        let (daemon_to_drv_r, daemon_to_drv_w) = pipe_cloexec().expect("pipe");

        let spec = AttemptSpec {
            scope: app_scope,
            identity_check: whoami_identity_check(),
            expected_identity: expected_editor,
            transfer: default_transfer_scope(&app_origin),
            session_format: WorkerSessionFormat::CookiesAndStorage,
            flow: AttemptFlow::TestSession {
                endpoint_origin: origins.app.clone(),
                ttl_secs: 600,
            },
        };

        let key = origins.adapter_key.clone();
        let responder = std::thread::spawn(move || {
            let mut r = File::from(drv_to_daemon_r);
            let mut w = File::from(daemon_to_drv_w);
            let msg = envcloak_browser::recv_from_driver(&mut r).expect("recv NeedPassword");
            assert_eq!(msg, DriverMessage::NeedPassword);
            envcloak_browser::send_to_driver(
                &mut w,
                &DaemonToDriver::Password(Zeroizing::new(key)),
            )
            .expect("send adapter key");
            envcloak_browser::recv_from_driver(&mut r).expect("recv Captured")
        });

        let mut pipe = DriverPipe::new(File::from(daemon_to_drv_r), File::from(drv_to_daemon_w));
        let outcome = Driver::run(&mut pipe, spec, None, None);
        let final_msg = responder.join().expect("join responder");
        match (&outcome, &final_msg) {
            (AttemptOutcome::Captured(s1), DriverMessage::Captured(s2)) => {
                assert_eq!(s1, s2);
                assert_eq!(s1.cookies.len(), 1);
                assert_eq!(s1.cookies[0].declaration.name.as_str(), "session");
                assert_eq!(s1.storage.len(), 1);
                assert_eq!(s1.storage[0].declaration.key.as_str(), "acme_tenant");
                assert_eq!(s1.storage[0].value.as_str(), "t1");
            }
            _ => panic!("expected Captured from TestSession adapter, got {outcome:?}"),
        }
    }
    assert_eq!(control.counters().expect("counters").mints, 1);
}

#[test]
fn gate_b5_declared_state_allowlist_and_unsupported_format() {
    let Some(runtime) = browser_runtime_or_skip() else {
        return;
    };
    let (origins, _control) = SigninFixture::start();
    let app_origin = parse_registered(&origins.app).expect("app origin");

    // Seed a real worker browser with:
    // - declared cookie `session` on `acme.localhost`
    // - undeclared IdP cookie `idp_sid` on `idp-acme.localhost`
    // - undeclared app cookie `extra_pref` on `acme.localhost`
    // - declared localStorage `acme_tenant` on `app_origin`
    // - undeclared localStorage `secret_draft` on `app_origin`
    // and verify `extract_from_cdp` captures ONLY the declared items.
    let temp = tempfile::tempdir().expect("tempdir");
    let attempt_dir_file = File::open(temp.path()).expect("open temp");
    create_dir_beneath(&attempt_dir_file, OsStr::new("profile"), 0o700).expect("profile");

    let (driver_to_chrome_r, driver_to_chrome_w) = pipe_cloexec().expect("pipe");
    let (chrome_to_driver_r, chrome_to_driver_w) = pipe_cloexec().expect("pipe");
    let (ctrl_to_reaper_r, ctrl_to_reaper_w) = pipe_cloexec().expect("ctrl");
    let (ctrl_from_reaper_r, ctrl_from_reaper_w) = pipe_cloexec().expect("ctrl");
    let (lifeline_r, lifeline_w) = pipe_cloexec().expect("lifeline");

    let mut launch = LaunchSpec::new(
        "b5-attempt",
        &runtime.chrome_exe,
        &runtime.pins.chrome_sha256,
        temp.path(),
    );
    launch.host_resolver_rules = Some(origins.host_resolver_rules.clone());

    let reaper_thread = std::thread::spawn(move || {
        Reaper::run(
            File::from(ctrl_to_reaper_r),
            File::from(ctrl_from_reaper_w),
            lifeline_r,
            launch,
            (driver_to_chrome_r, chrome_to_driver_w),
            OwnedFd::from(attempt_dir_file),
            "b5-attempt",
        )
    });

    let mut cdp = CdpClient::new(
        File::from(chrome_to_driver_r),
        File::from(driver_to_chrome_w),
    );
    let created = cdp
        .call(
            None,
            "Target.createTarget",
            json!({ "url": format!("{}/login", origins.app) }),
        )
        .expect("createTarget");
    let target_id = created["targetId"].as_str().unwrap().to_owned();
    let attached = cdp
        .call(
            None,
            "Target.attachToTarget",
            json!({ "targetId": target_id, "flatten": true }),
        )
        .expect("attachToTarget");
    let session_id = attached["sessionId"].as_str().unwrap().to_owned();
    let _ = cdp.call(Some(&session_id), "Network.enable", json!({}));
    let _ = cdp.call(Some(&session_id), "DOMStorage.enable", json!({}));
    std::thread::sleep(Duration::from_millis(150));

    // Seed declared + undeclared cookies and storage.
    let _ = cdp.call(
        Some(&session_id),
        "Network.setCookie",
        json!({
            "name": "session",
            "value": "sess_declared_val",
            "url": origins.app,
            "path": "/",
            "httpOnly": true,
            "sameSite": "Strict"
        }),
    );
    let _ = cdp.call(
        Some(&session_id),
        "Network.setCookie",
        json!({
            "name": "idp_sid",
            "value": "idp_secret_never_capture",
            "url": origins.idp,
            "path": "/",
            "httpOnly": true
        }),
    );
    let _ = cdp.call(
        Some(&session_id),
        "Network.setCookie",
        json!({
            "name": "extra_pref",
            "value": "undeclared_val",
            "url": origins.app,
            "path": "/"
        }),
    );
    let _ = cdp.call(
        Some(&session_id),
        "Runtime.evaluate",
        json!({
            "expression": "localStorage.setItem('acme_tenant', 't1'); localStorage.setItem('secret_draft', 'do_not_capture');"
        }),
    );

    let transfer = default_transfer_scope(&app_origin);
    let extracted = extract_from_cdp(
        &mut cdp,
        &session_id,
        &transfer,
        WorkerSessionFormat::CookiesAndStorage,
    )
    .expect("extract declared state");

    assert_eq!(extracted.cookies.len(), 1);
    assert_eq!(extracted.cookies[0].declaration.name.as_str(), "session");
    assert_eq!(extracted.cookies[0].value.as_str(), "sess_declared_val");
    assert!(extracted.cookies[0].http_only);
    assert_eq!(extracted.storage.len(), 1);
    assert_eq!(extracted.storage[0].declaration.key.as_str(), "acme_tenant");
    assert_eq!(extracted.storage[0].value.as_str(), "t1");

    // Unsupported format (`device_bound`) is refused with `UnsupportedSessionScope`.
    assert_eq!(
        extract_from_cdp(
            &mut cdp,
            &session_id,
            &transfer,
            WorkerSessionFormat::Unsupported
        ),
        Err(WorkerStopReason::UnsupportedSessionScope)
    );

    drop(cdp);
    let _ = File::from(ctrl_to_reaper_w).write_all(&ReaperCommand::Stop.encode());
    drop(lifeline_w);
    let mut reply_buf = [0u8; REAPER_REPLY_BYTES];
    File::from(ctrl_from_reaper_r)
        .read_exact(&mut reply_buf)
        .expect("reply");
    assert_eq!(ReaperReply::decode(&reply_buf), Ok(ReaperReply::Confirmed));
    let _ = reaper_thread.join().expect("join reaper");
}

#[test]
fn gate_b12_reaper_teardown_symlink_fault_and_crash_lifecycle() {
    let Some(runtime) = browser_runtime_or_skip() else {
        return;
    };
    let current_exe = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    let anchor = EntryImageAnchor::capture_from_path(&current_exe).expect("capture anchor");

    // 1. Symlink planted inside `profile` pointing to an outside sentinel directory:
    // the link is removed without following it, `profile` is gone, `sentinel` is untouched,
    // and `teardown.confirmed` is written.
    {
        let outer = tempfile::tempdir().expect("outer");
        let sentinel_dir = outer.path().join("sentinel");
        std::fs::create_dir_all(&sentinel_dir).expect("mkdir sentinel");
        let sentinel_file = sentinel_dir.join("keep.txt");
        std::fs::write(&sentinel_file, b"untouched-sentinel").expect("write sentinel");

        let attempt_dir = outer.path().join("attempt-symlink");
        std::fs::create_dir_all(&attempt_dir).expect("mkdir attempt");
        let attempt_dir_file = File::open(&attempt_dir).expect("open attempt_dir");
        create_dir_beneath(&attempt_dir_file, OsStr::new("profile"), 0o700).expect("profile");
        std::os::unix::fs::symlink(&sentinel_dir, attempt_dir.join("profile/planted_link"))
            .expect("plant symlink");

        let model = RecordingProcesses::new();
        model.exit(4242);
        let child = model.child(4242);
        let outcome = execute_teardown_sequence(child, &attempt_dir_file, "symlink-attempt", false);
        assert!(matches!(outcome, CleanupOutcome::Confirmed(_)));
        assert!(
            !attempt_dir.join("profile").exists(),
            "profile directory must be removed"
        );
        assert!(
            sentinel_file.is_file(),
            "sentinel target outside profile must be untouched"
        );
        assert!(
            attempt_dir.join(TEARDOWN_CONFIRMATION_FILE).is_file(),
            "teardown.confirmed must exist"
        );
    }

    // 2. Fault injection (`signin.reaper.remove_profile`): reaper exits `cleanup_failed`
    // (`CleanupOutcome::Failed(TeardownStep::RemoveProfile)`) and writes NO confirmation record.
    {
        let attempt_temp = tempfile::tempdir().expect("attempt_temp");
        let attempt_dir_file = File::open(attempt_temp.path()).expect("open");
        create_dir_beneath(&attempt_dir_file, OsStr::new("profile"), 0o700).expect("profile");

        let (cdp_in, cdp_in_w) = pipe_cloexec().expect("pipe");
        let (cdp_out_r, cdp_out) = pipe_cloexec().expect("pipe");
        let (spec_r, spec_w) = pipe_cloexec().expect("spec");
        let (ctrl_r, ctrl_w) = pipe_cloexec().expect("ctrl");
        let (reply_r, reply_w) = pipe_cloexec().expect("reply");
        let (lifeline_r, lifeline_w) = pipe_cloexec().expect("lifeline");

        let sub = SubprocReaperSpec {
            chrome_exe: runtime.chrome_exe.clone(),
            expected_sha256_hex: runtime.pins.chrome_sha256.clone(),
            attempt_dir_path: attempt_temp.path().to_path_buf(),
            host_resolver_rules: None,
            proxy_server: None,
            test_ca_spki_sha256: None,
            attempt_id: "failpoint-attempt".to_owned(),
        };
        File::from(spec_w)
            .write_all(&serde_json::to_vec(&sub).unwrap())
            .unwrap();

        let argv: &[&[u8]] = &[
            b"envcloakd",
            b"--exact",
            b"subprocess_dispatcher",
            b"--nocapture",
        ];
        let env: &[&[u8]] = &[
            b"ENVCLOAK_SUBPROC_MODE=reaper",
            b"ENVCLOAK_TEST_FAIL=signin.reaper.remove_profile",
            b"PATH=/usr/bin:/bin",
        ];
        let fds = [
            (cdp_in.as_fd(), 3),
            (cdp_out.as_fd(), 4),
            (spec_r.as_fd(), 5),
            (ctrl_r.as_fd(), 6),
            (reply_w.as_fd(), 7),
            (lifeline_r.as_fd(), 8),
            (attempt_dir_file.as_fd(), 9),
        ];
        let reaper_child = anchor.spawn_bound(argv, env, &fds).expect("spawn reaper");
        drop(cdp_in);
        drop(cdp_out);
        drop(spec_r);
        drop(ctrl_r);
        drop(reply_w);
        drop(lifeline_r);

        let _ = wait_for_worker_diagnostic(attempt_temp.path(), Duration::from_secs(5));
        drop(cdp_in_w);
        drop(cdp_out_r);
        let _ = File::from(ctrl_w).write_all(&ReaperCommand::Stop.encode());
        drop(lifeline_w);

        let mut reply_buf = [0u8; REAPER_REPLY_BYTES];
        File::from(reply_r)
            .read_exact(&mut reply_buf)
            .expect("reply");
        assert_eq!(
            ReaperReply::decode(&reply_buf),
            Ok(ReaperReply::Failed(TeardownStep::RemoveProfile))
        );
        let status = reaper_child.reap().expect("reap reaper");
        assert!(
            !status.success(),
            "reaper must exit non-zero on cleanup_failed"
        );
        assert!(
            !attempt_temp
                .path()
                .join(TEARDOWN_CONFIRMATION_FILE)
                .exists(),
            "no confirmation record when remove_profile failpoint triggers"
        );
        // Clean up the remaining profile directory in temp.
        let _ = std::fs::remove_dir_all(attempt_temp.path().join("profile"));
    }

    // 3. `kill -9` of the driver `OwnedChild`: the harness (in the daemon's role) sends
    // `ReaperCommand::Stop` to the reaper `OwnedChild`, and within 5s no worker process or
    // `profile` directory remains and `teardown.confirmed` is on disk, without the harness
    // ever signalling Chrome.
    {
        let attempt_temp = tempfile::tempdir().expect("attempt_temp");
        let attempt_dir_file = File::open(attempt_temp.path()).expect("open");
        create_dir_beneath(&attempt_dir_file, OsStr::new("profile"), 0o700).expect("profile");

        let (driver_to_chrome_r, driver_to_chrome_w) = pipe_cloexec().expect("pipe");
        let (chrome_to_driver_r, chrome_to_driver_w) = pipe_cloexec().expect("pipe");

        let sub = SubprocReaperSpec {
            chrome_exe: runtime.chrome_exe.clone(),
            expected_sha256_hex: runtime.pins.chrome_sha256.clone(),
            attempt_dir_path: attempt_temp.path().to_path_buf(),
            host_resolver_rules: None,
            proxy_server: None,
            test_ca_spki_sha256: None,
            attempt_id: "driver-kill9-attempt".to_owned(),
        };
        let mut spawned_reaper = spawn_reaper_via_anchor(
            &anchor,
            &sub,
            driver_to_chrome_r,
            chrome_to_driver_w,
            &attempt_dir_file,
        );

        // Spawn the driver as a second `OwnedChild` via `EntryImageAnchor`.
        let (ready_r, ready_w) = pipe_cloexec().expect("ready pipe");
        let drv_argv: &[&[u8]] = &[
            b"envcloakd",
            b"--exact",
            b"subprocess_dispatcher",
            b"--nocapture",
        ];
        let drv_env: &[&[u8]] = &[b"ENVCLOAK_SUBPROC_MODE=driver_hang", b"PATH=/usr/bin:/bin"];
        let drv_fds = [
            (chrome_to_driver_r.as_fd(), 3),
            (driver_to_chrome_w.as_fd(), 4),
            (ready_w.as_fd(), 5),
        ];
        let driver_child = anchor
            .spawn_bound(drv_argv, drv_env, &drv_fds)
            .expect("spawn driver");
        drop(chrome_to_driver_r);
        drop(driver_to_chrome_w);
        drop(ready_w);

        let mut ready_line = [0u8; 13];
        File::from(ready_r)
            .read_exact(&mut ready_line)
            .expect("driver ready");
        let (worker_pid, worker_sid) =
            wait_for_worker_diagnostic(attempt_temp.path(), Duration::from_secs(5));
        assert_eq!(worker_pid, worker_sid);
        assert!(is_pid_alive(worker_pid));

        // Kill -9 the driver through its `OwnedChild` handle, then send `Stop` to the reaper.
        driver_child.signal(9).expect("SIGKILL driver");
        let _ = driver_child.reap().expect("reap driver");

        let kill_start = Instant::now();
        spawned_reaper
            .ctrl_w
            .write_all(&ReaperCommand::Stop.encode())
            .expect("send Stop to reaper");
        spawned_reaper.ctrl_w.flush().expect("flush Stop");

        let mut reply_buf = [0u8; REAPER_REPLY_BYTES];
        spawned_reaper
            .ctrl_r
            .read_exact(&mut reply_buf)
            .expect("read reaper reply");
        assert_eq!(ReaperReply::decode(&reply_buf), Ok(ReaperReply::Confirmed));
        let reaper_status = spawned_reaper.child.reap().expect("reap reaper");
        assert!(reaper_status.success());
        assert!(
            kill_start.elapsed() < Duration::from_secs(5),
            "teardown after driver kill -9 must complete within 5s"
        );
        assert!(
            !is_pid_alive(worker_pid),
            "worker Chrome process must be gone after reaper teardown"
        );
        assert!(
            !attempt_temp.path().join("profile").exists(),
            "profile directory must be gone"
        );
        let confirm_bytes =
            std::fs::read(attempt_temp.path().join(TEARDOWN_CONFIRMATION_FILE)).expect("confirm");
        let record: TeardownRecord = serde_json::from_slice(&confirm_bytes).expect("parse confirm");
        assert_eq!(record.attempt_id, "driver-kill9-attempt");
        assert_eq!(
            record.steps,
            vec![
                TeardownStep::ObserveExit,
                TeardownStep::SignalGroup,
                TeardownStep::ReapLeader,
                TeardownStep::RemoveProfile,
                TeardownStep::WriteConfirmation,
            ]
        );
    }

    // 4. Closing the reaper's `lifeline` write end (simulating daemon `kill -9`):
    // reaper detects EOF, kills and reaps Chrome, removes `profile`, writes
    // `teardown.confirmed`, and exits 0 within 5s.
    {
        let attempt_temp = tempfile::tempdir().expect("attempt_temp");
        let attempt_dir_file = File::open(attempt_temp.path()).expect("open");
        create_dir_beneath(&attempt_dir_file, OsStr::new("profile"), 0o700).expect("profile");

        let (driver_to_chrome_r, _driver_to_chrome_w) = pipe_cloexec().expect("pipe");
        let (_chrome_to_driver_r, chrome_to_driver_w) = pipe_cloexec().expect("pipe");

        let sub = SubprocReaperSpec {
            chrome_exe: runtime.chrome_exe.clone(),
            expected_sha256_hex: runtime.pins.chrome_sha256.clone(),
            attempt_dir_path: attempt_temp.path().to_path_buf(),
            host_resolver_rules: None,
            proxy_server: None,
            test_ca_spki_sha256: None,
            attempt_id: "lifeline-eof-attempt".to_owned(),
        };
        let mut spawned_reaper = spawn_reaper_via_anchor(
            &anchor,
            &sub,
            driver_to_chrome_r,
            chrome_to_driver_w,
            &attempt_dir_file,
        );

        let (worker_pid, _) =
            wait_for_worker_diagnostic(attempt_temp.path(), Duration::from_secs(5));
        assert!(is_pid_alive(worker_pid));

        let eof_start = Instant::now();
        drop(spawned_reaper.lifeline_w);

        let mut reply_buf = [0u8; REAPER_REPLY_BYTES];
        spawned_reaper
            .ctrl_r
            .read_exact(&mut reply_buf)
            .expect("read reply on lifeline EOF");
        assert_eq!(ReaperReply::decode(&reply_buf), Ok(ReaperReply::Confirmed));
        let status = spawned_reaper.child.reap().expect("reap reaper");
        assert!(status.success());
        assert!(eof_start.elapsed() < Duration::from_secs(5));
        assert!(!is_pid_alive(worker_pid));
        assert!(!attempt_temp.path().join("profile").exists());
        assert!(
            attempt_temp
                .path()
                .join(TEARDOWN_CONFIRMATION_FILE)
                .is_file()
        );
    }

    // 5. `kill -9` of the reaper in the harness: on Linux Chrome dies by `PR_SET_PDEATHSIG`;
    // on macOS the harness closes the driver's CDP pipe ends and Chrome exits within 5s,
    // and no `teardown.confirmed` record exists.
    {
        let attempt_temp = tempfile::tempdir().expect("attempt_temp");
        let attempt_dir_file = File::open(attempt_temp.path()).expect("open");
        create_dir_beneath(&attempt_dir_file, OsStr::new("profile"), 0o700).expect("profile");

        let (driver_to_chrome_r, driver_to_chrome_w) = pipe_cloexec().expect("pipe");
        let (chrome_to_driver_r, chrome_to_driver_w) = pipe_cloexec().expect("pipe");

        let sub = SubprocReaperSpec {
            chrome_exe: runtime.chrome_exe.clone(),
            expected_sha256_hex: runtime.pins.chrome_sha256.clone(),
            attempt_dir_path: attempt_temp.path().to_path_buf(),
            host_resolver_rules: None,
            proxy_server: None,
            test_ca_spki_sha256: None,
            attempt_id: "reaper-kill9-attempt".to_owned(),
        };
        let spawned_reaper = spawn_reaper_via_anchor(
            &anchor,
            &sub,
            driver_to_chrome_r,
            chrome_to_driver_w,
            &attempt_dir_file,
        );

        let (worker_pid, _) =
            wait_for_worker_diagnostic(attempt_temp.path(), Duration::from_secs(5));
        assert!(is_pid_alive(worker_pid));

        // Kill -9 the reaper through its `OwnedChild` handle.
        spawned_reaper.child.signal(9).expect("SIGKILL reaper");
        let _ = spawned_reaper.child.reap().expect("reap killed reaper");

        // Close the driver's CDP pipe ends as the daemon/driver does when the reaper dies.
        drop(driver_to_chrome_w);
        drop(chrome_to_driver_r);

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && is_pid_alive(worker_pid) {
            std::thread::sleep(Duration::from_millis(25));
        }
        assert!(
            !is_pid_alive(worker_pid),
            "worker Chrome must exit within 5s after reaper kill -9 and CDP pipe close"
        );
        assert!(
            !attempt_temp
                .path()
                .join(TEARDOWN_CONFIRMATION_FILE)
                .exists(),
            "killed reaper must leave no teardown.confirmed file (unconfirmed cleanup)"
        );
    }
}

#[test]
fn recording_only_pid_reuse_and_teardown_order_invariants() {
    // 1. Normal teardown records `[HasExited(pid), SignalGroup(pid, 9), Reap(pid)]`
    // in exact order, and writes `teardown.confirmed` only after reaping and profile removal.
    {
        let temp = tempfile::tempdir().expect("tempdir");
        let attempt_dir_file = File::open(temp.path()).expect("open");
        create_dir_beneath(&attempt_dir_file, OsStr::new("profile"), 0o700).expect("profile");

        let model = RecordingProcesses::new();
        let pid = 7001;
        model.exit(pid);
        let child = model.child(pid);

        let outcome = execute_teardown_sequence(child, &attempt_dir_file, "rec-normal", false);
        assert_eq!(
            outcome,
            CleanupOutcome::Confirmed(TeardownRecord {
                attempt_id: "rec-normal".to_owned(),
                steps: vec![
                    TeardownStep::ObserveExit,
                    TeardownStep::SignalGroup,
                    TeardownStep::ReapLeader,
                    TeardownStep::RemoveProfile,
                    TeardownStep::WriteConfirmation,
                ],
            })
        );
        assert_eq!(
            model.calls(),
            vec![
                Recorded::HasExited(pid),
                Recorded::SignalGroup(pid, 9),
                Recorded::Reap(pid),
            ],
            "signal_group_before_reap must precede reap"
        );
        assert!(!temp.path().join("profile").exists());
        assert!(temp.path().join(TEARDOWN_CONFIRMATION_FILE).is_file());
    }

    // 2. Recording-only PID reuse test: if the leader was reaped elsewhere (so its PID
    // could be reused by an unrelated process), `execute_teardown_sequence` refuses at
    // `ObserveExit`, emits ZERO signals to the reused PID, and writes no confirmation record.
    {
        let temp = tempfile::tempdir().expect("tempdir");
        let attempt_dir_file = File::open(temp.path()).expect("open");
        create_dir_beneath(&attempt_dir_file, OsStr::new("profile"), 0o700).expect("profile");

        let model = RecordingProcesses::new();
        let reused_pid = 8002;
        model.reap_elsewhere(reused_pid);
        let child = model.child(reused_pid);

        let outcome = execute_teardown_sequence(child, &attempt_dir_file, "rec-reused", false);
        assert_eq!(outcome, CleanupOutcome::Failed(TeardownStep::ObserveExit));
        assert!(
            !model
                .calls()
                .iter()
                .any(|c| matches!(c, Recorded::Signal(_, _, _) | Recorded::SignalGroup(_, _))),
            "reaped-elsewhere / reused PID must never receive a signal: {:?}",
            model.calls()
        );
        assert!(!temp.path().join(TEARDOWN_CONFIRMATION_FILE).exists());
    }

    // 3. Direct handle check: if `reap_elsewhere` occurs after `has_exited()` but before
    // `signal_group_before_reap(9)`, `signal_group_before_reap` fails with `ECHILD` and
    // records no `SignalGroup` call.
    {
        let model = RecordingProcesses::new();
        let pid = 9003;
        model.exit(pid);
        let child = model.child(pid);

        assert!(child.has_exited().unwrap());
        // Simulate the leader being reaped and its number handed to an unrelated model process
        // between observation and group signal.
        model.reap_elsewhere(pid);
        let err = child.signal_group_before_reap(9).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(10 /* ECHILD */));
        assert_eq!(
            model.calls(),
            vec![Recorded::HasExited(pid)],
            "no SignalGroup may be recorded after reap_elsewhere"
        );
    }
}
