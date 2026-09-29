//! Gate 12 (SPEC §15.2), the canary sweep: with `RUST_LOG=trace` and
//! `RUST_BACKTRACE=full` in every process, panics whose messages hold a
//! fixture, and malformed inputs that hold one, no fixture appears in any
//! standard output or error, log, panic output or file.
//!
//! - Injected panics: `envcloak internal panic` and `envcloakd internal
//!   panic`, whose messages hold what standard input held (a fixture), in
//!   every build; and, in the test build, panics at places on a value path
//!   (`envcloak_sys::panic_point`): the CLI holding a run's released values
//!   (`cli.run.released`), the CLI holding an env file's parsed values
//!   (`cli.import.parsed`), and the daemon about to send a run's values
//!   (`daemon.release`), each with a fixture in its message. The panic
//!   handler of both binaries prints where the panic happened and never the
//!   message, and no backtrace.
//! - Malformed inputs holding fixtures: values on the command line in
//!   every place a name goes, and in an argument that is not UTF-8; a
//!   manifest with a value where a reference goes, and one that is not
//!   TOML; env files whose broken lines hold values, for `init`, `import`,
//!   `check` and `run --env-file`; secrets on descriptors that are not
//!   what was asked for; and frames sent straight to the daemon's socket
//!   with a value as the method, as an unknown field, JSON-escaped where
//!   base64 goes, as a name, as the whole body, and after an oversized
//!   header.
//!
//! The whole workspace's suite runs at `RUST_LOG=trace` and
//! `RUST_BACKTRACE=full` in CI too (.github/workflows/ci.yml), and
//! `TestHome` passes both settings on to the processes the tests start.
//! No EnvCloak program reads `RUST_LOG` yet (M1 has no logger); the setting
//! is kept so that logging added later is swept at its most verbose. Gate
//! 12 is enforced by this file, the fixture story (swept after every step)
//! and the sweeps of each test that starts processes with fixtures.
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use envcloak_e2e::{Harness, RECOVERY_KIT, age, quoted, text, token};
use envcloak_testkit::{Canary, daemon_socket, labels};

const TRACE: [(&str, &str); 2] = [("RUST_LOG", "trace"), ("RUST_BACKTRACE", "full")];

/// Whether `o` is a panic: exit 101 in a test build (unwinding), or
/// SIGABRT in a release build (`panic = "abort"`).
fn panicked(o: &Output) -> bool {
    o.status.code() == Some(101) || o.status.signal() == Some(libc::SIGABRT)
}

/// Standard error of a panic: one line from the handler, naming the
/// program and a place in the source, and nothing else.
fn assert_panic_line(program: &str, stderr: &[u8], place: &str) {
    let err = String::from_utf8_lossy(stderr);
    let lines: Vec<&str> = err.lines().collect();
    let line = lines
        .iter()
        .find(|l| l.starts_with(&format!("{program}: internal error: a panic at ")))
        .unwrap_or_else(|| panic!("no panic line: {err}"));
    assert!(line.contains(place), "{line}");
    assert!(
        line.ends_with("; its message is not shown, since it could hold a secret"),
        "{line}"
    );
    assert!(
        !err.contains("stack backtrace") && !err.contains("panicked at"),
        "{err}"
    );
}

/// A vault made through the CLI, unlocked, with the story's repo imported
/// (`.env` and `.env.short` taken out after an encrypted backup), and the
/// passphrase on a file.
fn vault_with_repo(h: &mut Harness) -> (PathBuf, PathBuf) {
    let pass = h.secret_file(labels::VAULT_PASSPHRASE, true);
    let kit = h.files().join("kit");
    let home = h.home.home();
    let made = h.human(
        &home,
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
        &[(3, &pass, true), (4, &kit, false)],
        &[],
    );
    assert_eq!(made.code, 0, "{}", made.all());
    let text_kit = std::fs::read_to_string(&kit).unwrap();
    h.add_canary(Canary::new(RECOVERY_KIT, text_kit.trim_end().to_owned()));
    let repo = h.home.root().join("acme-web");
    std::fs::create_dir_all(&repo).unwrap();
    let env = format!(
        "OPENAI_API_KEY={}\nDATABASE_URL='{}'\n",
        h.canary(labels::OPENAI_API_KEY).as_str(),
        h.canary(labels::DATABASE_URL).as_str().replace('\'', "")
    );
    std::fs::write(repo.join(".env"), env).unwrap();
    age(&repo.join(".env"), Duration::from_secs(600));
    h.allow_plaintext(repo.join(".env"));
    let imported = h.human(&repo, &["init", "--import", "--yes"], &[], &[]);
    assert_eq!(imported.code, 0, "{}", imported.all());
    let confirmed = h.human(
        &repo,
        &["recovery", "confirm", "--kit-fd", "4"],
        &[(4, &kit, true)],
        &[],
    );
    assert_eq!(confirmed.code, 0, "{}", confirmed.all());
    let deleted = h.human(&repo, &["init", "--delete-plaintext"], &[], &[]);
    assert_eq!(deleted.code, 0, "{}", deleted.all());
    assert!(!repo.join(".env").exists());
    h.allow_no_plaintext();
    std::fs::write(repo.join("emit"), "#!/bin/sh\necho started\n").unwrap();
    std::fs::set_permissions(
        repo.join("emit"),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .unwrap();
    (repo, pass)
}

/// The agent's run, approved by the person with the passphrase from
/// `pass`: returns once a grant covers the agent's runs.
fn grant_the_agent(h: &mut Harness, repo: &Path, pass: &Path) {
    let asked = h.agent(repo, &["run", "--", "./emit"]);
    assert_eq!(
        token(&asked.stderr),
        "approval_required",
        "{}",
        text(&asked)
    );
    let err = String::from_utf8_lossy(&asked.stderr).into_owned();
    let id = err
        .split("request=")
        .nth(1)
        .and_then(|r| r.get(..8))
        .unwrap()
        .to_owned();
    let approved = h.human(
        repo,
        &["approve", &id, "--for", "1h", "--passphrase-fd", "3"],
        &[(3, pass, true)],
        &[],
    );
    assert_eq!(approved.code, 0, "{}", approved.all());
    let covered = h.agent(repo, &["run", "--", "./emit"]);
    assert_eq!(covered.status.code(), Some(0), "{}", text(&covered));
}

#[test]
fn panics_show_where_and_never_what() {
    let mut h = Harness::start_with(&TRACE);

    // Both binaries, any build: the message holds what standard input
    // held, each fixture in turn.
    for label in [
        labels::OPENAI_API_KEY,
        labels::DATABASE_URL,
        labels::VAULT_PASSPHRASE,
    ] {
        let payload = h.secret_file(label, false);
        for (program, exe) in [("envcloak", h.cli()), ("envcloakd", h.daemon_exe())] {
            let o = h.program(&exe, &["internal", "panic"], Some(&payload));
            assert!(panicked(&o), "{program}: {}", text(&o));
            assert!(o.stdout.is_empty(), "{program}: {}", text(&o));
            assert_panic_line(program, &o.stderr, "crates/envcloak-sys/src/panic.rs:");
        }
    }
    if !h.test_build() {
        eprintln!("gate 12: the panic points exist in the test build only; skipped here");
        h.assert_swept("internal panics");
        return;
    }

    let (repo, pass) = vault_with_repo(&mut h);
    let payload = h.secret_file(labels::STRIPE_SECRET_KEY, false);
    let inject = |site: &str| {
        format!(
            "ENVCLOAK_TEST_PANIC={site} ENVCLOAK_TEST_PANIC_FILE={}",
            quoted(payload.to_str().unwrap())
        )
    };

    // The CLI, holding a run's released values.
    grant_the_agent(&mut h, &repo, &pass);
    let line = format!(
        "{} {} run -- ./emit",
        inject("cli.run.released"),
        quoted(h.cli().to_str().unwrap())
    );
    let o = h.agent_line(&repo, &line);
    assert!(panicked(&o), "{}", text(&o));
    assert!(o.stdout.is_empty(), "the command started: {}", text(&o));
    assert_panic_line("envcloak", &o.stderr, "crates/envcloak-cli/src/cmd/run.rs:");

    // The CLI, holding an env file's parsed values.
    let other = h.home.root().join("other-repo");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(
        other.join(".env"),
        format!("GITHUB_TOKEN={}\n", h.canary(labels::GITHUB_TOKEN).as_str()),
    )
    .unwrap();
    h.allow_plaintext(other.join(".env"));
    let cli = h.cli();
    let site = "ENVCLOAK_TEST_PANIC=cli.import.parsed".to_owned();
    let file = format!("ENVCLOAK_TEST_PANIC_FILE={}", payload.display());
    let o = h.human_argv(
        &other,
        &[
            "/usr/bin/env",
            &site,
            &file,
            cli.to_str().unwrap(),
            "init",
            "--import",
        ],
        &[],
        &[],
    );
    assert_eq!(o.code, 101, "{}", o.all());
    assert_panic_line(
        "envcloak",
        &o.stderr,
        "crates/envcloak-cli/src/cmd/import.rs:",
    );
    assert!(!other.join("envcloak.toml").exists());
    std::fs::remove_file(other.join(".env")).unwrap();
    h.allow_no_plaintext();

    // The daemon, about to send a run's values: its connection's thread
    // panics, the run gets nothing, and the daemon's log shows the place.
    h.stop_daemon();
    let file = payload.to_str().unwrap().to_owned();
    h.start_daemon(&[
        ("ENVCLOAK_TEST_PANIC", "daemon.release"),
        ("ENVCLOAK_TEST_PANIC_FILE", &file),
    ]);
    let unlocked = h.human(
        &repo,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(unlocked.code, 0, "{}", unlocked.all());
    let asked = h.agent(&repo, &["run", "--", "./emit"]);
    let err = String::from_utf8_lossy(&asked.stderr).into_owned();
    let id = err
        .split("request=")
        .nth(1)
        .and_then(|r| r.get(..8))
        .unwrap_or_else(|| panic!("{}", text(&asked)))
        .to_owned();
    let approved = h.human(
        &repo,
        &["approve", &id, "--for", "1h", "--passphrase-fd", "3"],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(approved.code, 0, "{}", approved.all());
    let o = h.agent(&repo, &["run", "--", "./emit"]);
    assert_eq!(o.status.code(), Some(125), "{}", text(&o));
    assert!(o.stdout.is_empty(), "the command started: {}", text(&o));
    h.expect_log(
        "envcloakd: internal error: a panic at crates/envcloak-daemon/src/requests.rs:",
        Duration::from_secs(10),
    );
    // What else the panic printed can come after that line, so the check
    // that the default hook's message never came reads the whole log,
    // once the daemon has stopped and its log is complete.
    let log = h.stop_daemon();
    assert!(
        !log.contains("panicked at") && !log.contains("stack backtrace"),
        "{log}"
    );
    h.assert_swept("after the injected panics");
}

/// Standard padded base64, as the protocol carries a secret.
fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(T[(n >> (18 - 6 * i)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// One frame to the daemon's socket, and its answer (or none).
fn frame(socket: &Path, body: &[u8], announce: Option<u32>) -> Vec<u8> {
    let mut s = UnixStream::connect(socket).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let len = announce.unwrap_or(u32::try_from(body.len()).unwrap());
    s.write_all(&len.to_be_bytes()).unwrap();
    let _ = s.write_all(body);
    let mut answer = Vec::new();
    let mut head = [0u8; 4];
    if s.read_exact(&mut head).is_ok() {
        let n = u32::from_be_bytes(head) as usize;
        answer.resize(n.min(1 << 20), 0);
        let _ = s.read_exact(&mut answer);
    }
    answer
}

#[test]
fn malformed_inputs_holding_values_are_never_echoed() {
    let mut h = Harness::start_with(&TRACE);
    let (repo, pass) = vault_with_repo(&mut h);
    let v = h.canary(labels::GITHUB_TOKEN).as_str().to_owned();
    let url = h.canary(labels::DATABASE_URL).as_str().to_owned();

    // Values on the command line, wherever a name or an id goes: refused,
    // never echoed.
    let bad: Vec<Vec<String>> = vec![
        vec!["add".into(), v.clone()],
        vec!["add".into(), "--slug".into(), v.clone(), "--stdin".into()],
        vec!["show".into(), v.clone()],
        vec!["rotate".into(), v.clone()],
        vec!["rm".into(), v.clone()],
        vec!["approve".into(), v.clone()],
        vec!["deny".into(), v.clone()],
        vec!["grants".into(), "revoke".into(), v.clone()],
        vec!["ref".into(), format!("OPENAI_API_KEY={v}")],
        vec![
            "run".into(),
            "--ref".into(),
            format!("OPENAI_API_KEY={v}"),
            "--".into(),
            "true".into(),
        ],
        vec![
            "run".into(),
            "--profile".into(),
            v.clone(),
            "--".into(),
            "true".into(),
        ],
        vec!["init".into(), "--undo".into(), v.clone()],
        vec!["vault".into(), "create".into(), v.clone()],
        vec!["unlock".into(), v.clone()],
        vec![v.clone()],
        vec![format!("--{v}")],
        vec!["status".into(), url.clone()],
    ];
    for args in &bad {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let o = h.agent(&repo, &args);
        assert_ne!(o.status.code(), Some(0), "{}", text(&o));
    }
    // An argument that is not UTF-8, with a value after the bad byte.
    let line = format!(
        "{} show \"$(printf '\\377')\"{}",
        quoted(h.cli().to_str().unwrap()),
        quoted(&v)
    );
    let o = h.agent_line(&repo, &line);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));

    // A manifest with a value where a reference goes, and one that is not
    // TOML, each holding a value.
    for (name, body) in [
        ("value-ref", format!("[env]\nOPENAI_API_KEY = \"{v}\"\n")),
        ("not-toml", format!("[env\nOPENAI_API_KEY = \"{v}\n")),
        ("bad-key", format!("[env]\n\"{v}\" = \"openai/acme-web\"\n")),
    ] {
        let dir = h.home.root().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("envcloak.toml"), body).unwrap();
        h.allow_plaintext(dir.join("envcloak.toml"));
        for args in [&["run", "--", "true"][..], &["check"], &["check", "--json"]] {
            let o = h.agent(&dir, args);
            assert_ne!(o.status.code(), Some(0), "{name} {args:?}: {}", text(&o));
        }
        // A variable named like a key is a variable all the same: `ref`
        // may add a binding beside it, and never shows its name.
        h.agent(&dir, &["ref", "X=openai/acme-web"]);
        std::fs::remove_file(dir.join("envcloak.toml")).unwrap();
    }
    h.allow_no_plaintext();

    // Env files whose broken lines hold values: the report names lines,
    // never text from them.
    let broken = h.home.root().join("broken");
    std::fs::create_dir_all(&broken).unwrap();
    let body = format!(
        "OPENAI_API_KEY=\"{v}\nexport {v}\n{v}\nGOOD=1\nQUOTED='{url}\nBACKTICK=`{v}\n\
         MULTI=\"{url}\\\n"
    );
    std::fs::write(broken.join(".env"), &body).unwrap();
    std::fs::write(broken.join(".env.nul"), format!("NUL=a\u{0}{v}\n")).unwrap();
    for name in [".env", ".env.nul"] {
        age(&broken.join(name), Duration::from_secs(600));
        h.allow_plaintext(broken.join(name));
    }
    h.human(&broken, &["init", "--import"], &[], &[]);
    h.human(&broken, &["init", "--import", "--yes", "--json"], &[], &[]);
    let root = h.home.root().to_str().unwrap().to_owned();
    h.agent(&repo, &["import", "--scan", &root]);
    h.agent(&repo, &["import", "--scan", &root, "--json"]);
    h.agent(&repo, &["check"]);
    let env_file = broken.join(".env").to_str().unwrap().to_owned();
    let o = h.agent(&repo, &["run", "--env-file", &env_file, "--", "true"]);
    assert_ne!(o.status.code(), Some(0), "{}", text(&o));
    for name in [".env", ".env.nul"] {
        std::fs::remove_file(broken.join(name)).unwrap();
    }
    h.allow_no_plaintext();

    // Secrets on descriptors that are not what was asked for.
    let kit_shaped = h.secret_file(labels::STRIPE_SECRET_KEY, true);
    let o = h.human(
        &repo,
        &["recovery", "confirm", "--kit-fd", "4"],
        &[(4, &kit_shaped, true)],
        &[],
    );
    assert_eq!(o.code, 1, "{}", o.all());
    let o = h.human(
        &repo,
        &["approve", "ABCDEFGH", "--passphrase-fd", "3"],
        &[(3, &kit_shaped, true)],
        &[],
    );
    assert_eq!(o.code, 1, "{}", o.all());
    let nul = h.files().join("nul-value");
    std::fs::write(&nul, format!("{v}\u{0}{v}")).unwrap();
    let o = h.agent_line(
        &repo,
        &format!(
            "{} add --slug misc/nul --stdin < {}",
            quoted(h.cli().to_str().unwrap()),
            quoted(nul.to_str().unwrap())
        ),
    );
    assert_ne!(o.status.code(), Some(0), "{}", text(&o));
    let _ = &pass;

    // Frames straight to the daemon's socket.
    let socket = daemon_socket(&h.home);
    let b64 = base64(v.as_bytes());
    let escaped: String = v.chars().map(|c| format!("\\u{:04x}", c as u32)).collect();
    let bodies: Vec<Vec<u8>> = vec![
        format!("{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{v}\"}}").into_bytes(),
        format!("{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"app.{v}\"}}").into_bytes(),
        v.clone().into_bytes(),
        format!("{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"status\",\"params\":{{\"{v}\":1}}}}")
            .into_bytes(),
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"unlock\",\"params\":{{\"passphrase\":\"{escaped}\"}}}}"
        )
        .into_bytes(),
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"items.add\",\"params\":{{\"slug\":\"{v}\",\
             \"allow_short\":false,\"value\":\"{b64}\"}}}}"
        )
        .into_bytes(),
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"run.request\",\"params\":{{\"manifest\":\
             \"/{v}/envcloak.toml\",\"refs\":[\"X={v}\"],\"argv\":[\"{v}\"],\"claims\":[\"{v}\"]}}}}"
        )
        .into_bytes(),
        format!("{{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"unlock\",\"params\":{{\"passphrase\":\"{b64}\"}}}}")
            .into_bytes(),
    ];
    for (i, body) in bodies.iter().enumerate() {
        let answer = frame(&socket, body, None);
        h.record(&format!("the daemon's answer to frame {i}"), &answer);
    }
    let answer = frame(&socket, v.as_bytes(), Some(2 << 20));
    h.record("the daemon's answer to an oversized frame", &answer);
    let status = h.agent(&repo, &["status"]);
    assert_eq!(status.status.code(), Some(0), "{}", text(&status));

    h.assert_swept("after the malformed inputs");
}
