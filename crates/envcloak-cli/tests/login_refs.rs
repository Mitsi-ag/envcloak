//! Gate b18's `run` and `ref` part through the built CLI (plan task M2-07,
//! SPEC §6.8 "Login fields are typed"): with a login in the vault, planted
//! through the core API as `login.add` (M2b-03) will plant it, a person's
//! `envcloak run` naming any of its fields, by `--ref` or in a manifest,
//! exits 125 with `login_reference` and starts nothing, and `envcloak ref`
//! refuses it with `login_reference` and leaves `envcloak.toml` as it was.
//! A reference to a secret still binds (the control). No login value is in
//! any output, the daemon's log or the home.
//!
//! `ref` never writes a binding the daemon did not check: with no daemon
//! running, and with the daemon's vault locked, a login's field and a
//! secret alike are refused (`daemon_unavailable`, `vault_locked`) and
//! `envcloak.toml` is left as it was. Mutation checked: the class check's
//! failure taken as "not a login" (the `.ok()` fallback ref had), which
//! writes the login's binding here and fails. Nor does it write on an
//! answer that is not one status for the one reference, an unverified
//! daemon or a daemon's error, which a stand-in daemon gives.
//!
//! The person's commands run on a terminal of their own, as tests/run.rs's
//! approver's do; under a developer's Claude Code the unlock is refused,
//! so run them outside the agent's tree then.
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::Output;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::{
    Fd, MANIFEST, cli_command, data_dir, finish_within, on_terminal_command, outside_dir, project,
    run_on_terminal, secret_file, seed_vault, start_daemon, stderr, stdout,
};
use envcloak_core::SecretBytes;
use envcloak_core::vault::{
    ItemDetails, LockedVault, LoginMeta, LoginTier, NewLogin, Slug, TotpAlgorithm, TotpEnrollment,
    TotpParams, VaultPaths,
};
use envcloak_ipc::proto::{self, ErrorKind, IncomingRequest, RpcError};
use envcloak_ipc::view::{CheckView, RefStatus};
use envcloak_ipc::{Frame, RunPaths};
use envcloak_testkit::{
    Canary, TestHome, assert_no_canary, by_label, canaries, daemon_run_dir, fresh_seed, labels,
};

/// Plants `fixture/editor`, a login whose every field is a fixture of its
/// own, before the daemon starts; returns the fixtures.
fn plant_login(home: &TestHome, cs: &[Canary]) -> Vec<Canary> {
    let login: Vec<Canary> = ["USERNAME", "PASSWORD", "TOTP_SEED", "ADAPTER_KEY"]
        .into_iter()
        .map(|label| {
            Canary::new(
                format!("LOGIN_{label}"),
                format!("login-{}-{:016x}", label.to_ascii_lowercase(), fresh_seed()),
            )
        })
        .collect();
    let value = |n: usize| SecretBytes::copy_from(login[n].value());
    let pass = SecretBytes::copy_from(by_label(cs, labels::VAULT_PASSPHRASE).value());
    let mut v = LockedVault::open(&VaultPaths::under(data_dir(home)))
        .unwrap()
        .unlock_with_passphrase(&pass)
        .map_err(|(_, e)| e)
        .unwrap();
    v.transact(|t| {
        t.create_login(NewLogin {
            slug: Slug::new("fixture/editor").unwrap(),
            details: ItemDetails {
                title: "fixture editor".into(),
                ..ItemDetails::default()
            },
            meta: LoginMeta {
                tier: LoginTier::Dev,
                session_lifetime: 900,
            },
            username: value(0),
            password: value(1),
            totp: Some(TotpEnrollment {
                params: TotpParams::new(TotpAlgorithm::Sha1, 6, 30).unwrap(),
                seed: value(2),
            }),
            adapter_key: Some(value(3)),
        })
    })
    .unwrap();
    login
}

/// `envcloak <args>` by the person on a terminal of their own, in `dir`.
fn in_dir(home: &TestHome, dir: &Path, args: &[&str], fds: &[Fd<'_>]) -> Output {
    let mut cmd = on_terminal_command(home, args, fds);
    cmd.current_dir(dir);
    finish_within(cmd, Duration::from_secs(60))
}

#[test]
fn b18_run_and_ref_refuse_a_login_field() {
    let mut cs = canaries(fresh_seed());
    let home = TestHome::new();
    let kit = seed_vault(&home, &cs);
    cs.push(kit);
    let login = plant_login(&home, &cs);
    cs.extend(login);
    let story = project(&home, "acme-web", MANIFEST);
    let manifest = std::fs::read(story.join("envcloak.toml")).unwrap();
    let swept = |o: &Output| {
        assert_no_canary(&o.stdout, &cs);
        assert_no_canary(&o.stderr, &cs);
    };
    // `ref` that the daemon could not check writes nothing, for a login's
    // field and a secret's reference alike.
    let unchecked = |token: &str| {
        for binding in [
            "PASSWORD=fixture/editor#password",
            "PASSWORD=fixture/editor",
            "GITHUB_TOKEN=github/acme-web",
        ] {
            let o = in_dir(&home, &story, &["ref", binding], &[]);
            swept(&o);
            assert_eq!(o.status.code(), Some(1), "ref {binding}: {}", stderr(&o));
            let err = stderr(&o);
            assert!(
                err.starts_with(&format!("envcloak: {token}: ")),
                "ref {binding}: {err}"
            );
            assert!(err.contains("nothing was written"), "ref {binding}: {err}");
            assert!(stdout(&o).is_empty(), "ref {binding}: {}", stdout(&o));
            assert_eq!(
                std::fs::read(story.join("envcloak.toml")).unwrap(),
                manifest,
                "ref {binding} changed envcloak.toml with {token}"
            );
        }
    };
    // No daemon running.
    unchecked("daemon_unavailable");
    let d = start_daemon(&home);
    // The daemon's vault locked.
    unchecked("vault_locked");
    let files = outside_dir();
    let pass = secret_file(
        files.path(),
        "pass",
        by_label(&cs, labels::VAULT_PASSPHRASE).value(),
    );
    let out = run_on_terminal(
        &home,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &pass, true)],
    );
    assert!(out.status.success(), "{}{}", stderr(&out), d.log());
    let refused = |o: &Output, code: i32, what: &str| {
        swept(o);
        assert_eq!(o.status.code(), Some(code), "{what}: {}", stderr(o));
        assert!(
            stderr(o).starts_with("envcloak: login_reference: "),
            "{what}: {}",
            stderr(o)
        );
        assert!(stdout(o).is_empty(), "{what}: {}", stdout(o));
    };
    let marker = story.join("started");
    let command = format!("touch {}", marker.display());
    for reference in [
        "fixture/editor",
        "fixture/editor#username",
        "fixture/editor#password",
        "fixture/editor#totp",
        "fixture/editor#adapter_key",
    ] {
        let binding = format!("PASSWORD={reference}");
        let o = in_dir(
            &home,
            &story,
            &["run", "--ref", &binding, "--", "/bin/sh", "-c", &command],
            &[],
        );
        refused(&o, 125, &format!("run --ref {binding}"));
        assert!(!marker.exists(), "the command started");
        let o = in_dir(&home, &story, &["ref", &binding], &[]);
        refused(&o, 1, &format!("ref {binding}"));
        assert_eq!(
            std::fs::read(story.join("envcloak.toml")).unwrap(),
            manifest,
            "ref {binding} changed envcloak.toml"
        );
    }
    // A manifest that binds one.
    let bound = project(
        &home,
        "login-bound",
        "[env]\nOPENAI_API_KEY = \"openai/acme-web\"\nPASSWORD = \"fixture/editor#password\"\n",
    );
    let o = in_dir(
        &home,
        &bound,
        &["run", "--", "/bin/sh", "-c", &command],
        &[],
    );
    refused(&o, 125, "a manifest binding a login's password");
    assert!(!marker.exists(), "the command started");

    // The control: a secret's reference is still written.
    let o = in_dir(&home, &story, &["ref", "GITHUB_TOKEN=github/acme-web"], &[]);
    swept(&o);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_ne!(
        std::fs::read(story.join("envcloak.toml")).unwrap(),
        manifest
    );

    assert_no_canary(&d.log_bytes(), &cs);
    home.assert_clean(&cs);
    drop(files);
}

/// What a stand-in daemon answers `items.check` with.
enum Answer {
    Refs(serde_json::Value),
    Error(ErrorKind),
}

/// A request the stand-in took: its method, and the references it sent.
type Asked = (String, Vec<String>);

/// A stand-in for the daemon, on the daemon's socket under `home`: it
/// answers each request with `answer` and records its method and the
/// references it sent. The socket is bound before it returns (ready), and
/// the thread takes connections only until it is stopped or 60 seconds
/// pass, so it never outlives the test.
struct StandIn {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Vec<Asked>>>,
}

impl StandIn {
    fn start(home: &TestHome, answer: Answer) -> StandIn {
        let paths = RunPaths::under(daemon_run_dir(home)).unwrap();
        paths.prepare_dir().unwrap();
        let _ = std::fs::remove_file(&paths.socket);
        let listener = UnixListener::bind(&paths.socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let mut seen = Vec::new();
            let until = Instant::now() + Duration::from_secs(60);
            while !stopping.load(Ordering::SeqCst) && Instant::now() < until {
                let mut s = match listener.accept() {
                    Ok((s, _)) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(e) => panic!("accept: {e}"),
                };
                s.set_nonblocking(false).unwrap();
                s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
                let Ok(f) = Frame::read_from(&mut s) else {
                    continue;
                };
                let req = IncomingRequest::parse(&f).unwrap();
                let refs = req
                    .params::<serde_json::Value>()
                    .ok()
                    .and_then(|p| serde_json::from_value(p["refs"].clone()).ok())
                    .unwrap_or_default();
                seen.push((req.method.to_owned(), refs));
                let frame = match &answer {
                    Answer::Refs(refs) => proto::result_frame(
                        req.id,
                        &serde_json::json!({
                            "project_dir": null,
                            "project_name": null,
                            "bindings": [],
                            "refs": refs,
                        }),
                    ),
                    Answer::Error(kind) => proto::error_frame(Some(req.id), &RpcError::new(*kind)),
                };
                let _ = frame.unwrap().write_to(&mut s);
            }
            seen
        });
        StandIn {
            stop,
            thread: Some(thread),
        }
    }

    /// Stops it, and what it was asked.
    fn asked(mut self) -> Vec<Asked> {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for StandIn {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// `envcloak ref` writes only on an answer of one status for the one
/// reference it sent. Against a stand-in daemon, an answer with no
/// status, with two, with a status this build does not know, and a
/// daemon's error each leave `envcloak.toml` byte for byte as it was, and
/// say so with the failure's token; so does a daemon whose directory its
/// group can write (`daemon_unverified`), which is asked nothing. The positive
/// control: the same stand-in answering one `ok` gets the binding written.
/// Each run asks `items.check` once, with the one reference.
///
/// Mutation checked (the verifier's survivor): the first status of any
/// number taken, and none taken as `ok` (`[status, ..] => Ok(*status), _
/// => Ok(RefStatus::Ok)` in `ref_.rs`): the empty and the two-status
/// answers write the binding, and this fails.
#[test]
fn ref_writes_nothing_unless_the_daemon_answers_one_status() {
    let home = TestHome::new();
    let story = project(&home, "acme-web", MANIFEST);
    let manifest = std::fs::read(story.join("envcloak.toml")).unwrap();
    let binding = "GITHUB_TOKEN=github/acme-web";
    let ref_ = || {
        let mut cmd = cli_command(&home, &["ref", binding], &[]);
        cmd.current_dir(&story);
        finish_within(cmd, Duration::from_secs(60))
    };
    let one_check = |asked: &[Asked], what: &str| {
        assert_eq!(
            asked,
            [("items.check".to_owned(), vec![binding.to_owned()])],
            "{what}"
        );
    };
    let ok = serde_json::to_value(RefStatus::Ok).unwrap();
    for (answer, token, what) in [
        (
            Answer::Refs(serde_json::json!([])),
            "protocol_error",
            "no status",
        ),
        (
            Answer::Refs(serde_json::json!([ok, ok])),
            "protocol_error",
            "two statuses",
        ),
        (
            Answer::Refs(serde_json::json!([ok, "login_reference"])),
            "protocol_error",
            "a status for a reference never sent",
        ),
        (
            Answer::Refs(serde_json::json!(["not_a_status"])),
            "protocol_error",
            "a status this build does not know",
        ),
        (Answer::Error(ErrorKind::Internal), "internal", "an error"),
    ] {
        let daemon = StandIn::start(&home, answer);
        let o = ref_();
        let asked = daemon.asked();
        let err = stderr(&o);
        assert_eq!(o.status.code(), Some(1), "{what}: {err}");
        assert!(
            err.starts_with(&format!("envcloak: {token}: ")),
            "{what}: {err}"
        );
        assert!(err.contains("nothing was written"), "{what}: {err}");
        assert!(stdout(&o).is_empty(), "{what}: {}", stdout(&o));
        assert_eq!(
            std::fs::read(story.join("envcloak.toml")).unwrap(),
            manifest,
            "{what} changed envcloak.toml"
        );
        one_check(&asked, what);
    }

    // A daemon directory its group can write: the daemon is not verified,
    // and nothing is sent to it or written.
    let daemon = StandIn::start(&home, Answer::Refs(serde_json::json!([ok])));
    let dir = daemon_run_dir(&home);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770)).unwrap();
    let o = ref_();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let asked = daemon.asked();
    let err = stderr(&o);
    assert_eq!(o.status.code(), Some(1), "{err}");
    assert!(err.starts_with("envcloak: daemon_unverified: "), "{err}");
    assert!(err.contains("nothing was written"), "{err}");
    assert!(asked.is_empty(), "{asked:?}");
    assert_eq!(
        std::fs::read(story.join("envcloak.toml")).unwrap(),
        manifest
    );

    // The control: one `ok` for the one reference, and it is written.
    let daemon = StandIn::start(&home, Answer::Refs(serde_json::json!([ok])));
    let o = ref_();
    one_check(&daemon.asked(), "one ok");
    assert!(o.status.success(), "{}", stderr(&o));
    let written = String::from_utf8(std::fs::read(story.join("envcloak.toml")).unwrap()).unwrap();
    assert!(
        written.contains("GITHUB_TOKEN = \"github/acme-web\""),
        "{written}"
    );
    // `CheckView` is what the stand-in's answers are shaped as.
    let _: CheckView = serde_json::from_value(serde_json::json!({
        "project_dir": null, "project_name": null, "bindings": [], "refs": [ok],
    }))
    .unwrap();
}
