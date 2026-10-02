//! `ec-model` (M2 plan task M2-04): the command it wraps runs in an
//! isolated home with a cleared environment, so no credential or
//! configuration of whoever runs it reaches the command (Codex review,
//! high); its diagnostics name no request target a host controls (Codex
//! review, medium: a request to `/<value>` put the value on standard
//! error, then a destination of letters only did); its record is a new
//! file of mode 0600 (Codex review and verifier: an existing file kept its
//! mode, a link was followed); and the command is bounded, its group
//! stopped before its home goes (Codex review, medium).
#![allow(clippy::unwrap_used)]

use std::io::Read;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use envcloak_testkit::{
    Canary, TestHome, by_label, canaries, find, fresh_seed, labels, testkit_bin,
};

/// `ec-model` with `script` and `--record <record>`, running `command`
/// under `/bin/sh -c`, with `parent` as the variables of its own
/// environment (nothing else of this process's).
fn ec_model(record: &Path, parent: &[(&str, &str)], command: &str) -> Output {
    run_ec_model(record, &[], parent, command, Duration::from_secs(120))
}

/// The same with `extra` options, given `outer` to end. `ec-model` runs
/// as a plain child here, not as the leader of a group this test kills
/// when it exits (`finish_within`): that kill would also stop whatever
/// `ec-model` left running and hide it. Past `outer` it is killed itself
/// and the test fails.
fn run_ec_model(
    record: &Path,
    extra: &[&str],
    parent: &[(&str, &str)],
    command: &str,
    outer: Duration,
) -> Output {
    let script = PathBuf::from(format!("{}.script.json", record.display()));
    std::fs::write(&script, r#"{"steps": [{"say": "done"}]}"#).unwrap();
    let mut cmd = Command::new(testkit_bin("ec-model"));
    cmd.env_clear()
        .envs(parent.iter().copied())
        .arg("--script")
        .arg(&script)
        .arg("--record")
        .arg(record)
        .args(extra)
        .args(["--", "/bin/sh", "-c", command])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let read = |r: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut r) = r {
                let _ = r.read_to_end(&mut bytes);
            }
            bytes
        })
    };
    let stdout = read(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let stderr = read(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let end = Instant::now() + outer;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > end {
            let _ = child.kill();
            let _ = child.wait();
            panic!("ec-model did not end within {outer:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Output {
        status,
        stdout: stdout.join().unwrap(),
        stderr: stderr.join().unwrap(),
    }
}

/// A command that prints `c` on a line of its own, named in two pieces,
/// so whole it can only be what the command printed.
fn print_split(c: &Canary) -> String {
    let (a, b) = c.as_str().split_at(c.as_str().len() / 2);
    format!("printf '%s%s\\n' '{a}' '{b}'")
}

/// The variables the command may see: the test home's, the two
/// `ec-model` adds for hosts, the model's, the diagnostic ones, and what a
/// shell sets itself.
const ALLOWED: [&str; 21] = [
    "PATH",
    "LANG",
    "TERM",
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "XDG_CACHE_HOME",
    "XDG_RUNTIME_DIR",
    "TMPDIR",
    "CODEX_HOME",
    "CLAUDE_CODE_TMPDIR",
    "EC_MODEL_BASE_URL",
    "EC_MODEL_TOKEN",
    "RUST_LOG",
    "RUST_BACKTRACE",
    "PWD",
    "OLDPWD",
    "SHLVL",
    "_",
    "__CF_USER_TEXT_ENCODING",
];

/// Credentials and configurations planted in the environment `ec-model`
/// runs with (variables, and a home whose host configs hold keys) never
/// reach the command: it sees a home of its own under `/tmp/ec`, only the
/// variables [`ALLOWED`] names, starts in that home, and reads none of
/// the planted files. A control the command prints is found in its
/// output, so the clean result is the detector's and not a blind one.
#[test]
fn the_command_runs_in_a_home_of_its_own_with_nothing_of_the_callers_environment() {
    let cs = canaries(fresh_seed());
    let key = |l: &str| by_label(&cs, l).as_str().to_owned();
    // The caller's home, with the hosts' credential and config files.
    let parent = TestHome::new();
    let home = parent.home();
    for (file, body) in [
        (
            ".codex/auth.json",
            format!(
                "{{\"OPENAI_API_KEY\": \"{}\"}}",
                key(labels::OPENAI_API_KEY)
            ),
        ),
        (
            ".claude/.credentials.json",
            format!(
                "{{\"claudeAiOauth\": {{\"accessToken\": \"{}\"}}}}",
                key(labels::STRIPE_SECRET_KEY)
            ),
        ),
        (
            ".config/gh/hosts.yml",
            format!(
                "github.com:\n  oauth_token: {}\n",
                key(labels::GITHUB_TOKEN)
            ),
        ),
    ] {
        let path = home.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, body).unwrap();
    }
    let (home_s, codex, claude, config) = (
        home.to_str().unwrap().to_owned(),
        home.join(".codex").to_str().unwrap().to_owned(),
        home.join(".claude").to_str().unwrap().to_owned(),
        home.join(".config").to_str().unwrap().to_owned(),
    );
    let (openai, github, db) = (
        key(labels::OPENAI_API_KEY),
        key(labels::GITHUB_TOKEN),
        key(labels::DATABASE_URL),
    );
    let planted = [
        ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
        ("HOME", home_s.as_str()),
        ("CODEX_HOME", codex.as_str()),
        ("CLAUDE_CONFIG_DIR", claude.as_str()),
        ("XDG_CONFIG_HOME", config.as_str()),
        ("ANTHROPIC_API_KEY", openai.as_str()),
        ("OPENAI_API_KEY", openai.as_str()),
        ("GITHUB_TOKEN", github.as_str()),
        ("DATABASE_URL", db.as_str()),
        ("ANTHROPIC_BASE_URL", "https://elsewhere.invalid"),
    ];
    let control = Canary::new(
        "POSITIVE_CONTROL",
        format!("ecctl-{:016x}{:016x}", fresh_seed(), fresh_seed()),
    );
    let command = format!(
        "env; echo \"CWD=$(pwd -P)\"; for f in \"$HOME/.codex/auth.json\" \
         \"$HOME/.claude/.credentials.json\" \"$HOME/.config/gh/hosts.yml\" \
         \"$CODEX_HOME/auth.json\" \"${{CLAUDE_CONFIG_DIR:-$HOME/.claude}}/.credentials.json\"; \
         do cat \"$f\" 2>/dev/null; done; {}",
        print_split(&control)
    );
    let files = TestHome::new();
    let record = files.root().join("record.json");
    let out = ec_model(&record, &planted, &command);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The control: found, so the detector looks where it should.
    let all: Vec<Canary> = cs.iter().cloned().chain([control.clone()]).collect();
    let hits = find(&out.stdout, &all);
    assert!(
        hits.iter().any(|f| f.label == "POSITIVE_CONTROL"),
        "the control the command printed was not found"
    );
    let leaked: Vec<String> = hits
        .iter()
        .filter(|f| f.label != "POSITIVE_CONTROL")
        .map(|f| format!("{} as {}", f.label, f.encoding))
        .collect();
    assert!(
        leaked.is_empty(),
        "the caller's credentials reached the command: {leaked:?}"
    );
    assert!(
        find(&out.stderr, &all).is_empty(),
        "ec-model's diagnostics hold a value"
    );
    // Only the allowed variables, and a home of its own.
    let vars: Vec<(&str, &str)> = stdout
        .lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        .collect();
    for (name, _) in &vars {
        assert!(
            ALLOWED.contains(name) || *name == "CWD",
            "the command got {name} from the caller"
        );
    }
    let var = |n: &str| {
        vars.iter()
            .find(|(k, _)| *k == n)
            .map(|(_, v)| PathBuf::from(v))
            .unwrap_or_else(|| panic!("no {n} in {stdout}"))
    };
    let its_home = var("HOME");
    assert!(
        its_home.starts_with("/tmp") && its_home != home,
        "the command's HOME is {}",
        its_home.display()
    );
    assert!(
        its_home
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|n| n.to_string_lossy().starts_with("ec")),
        "the command's HOME is not a test home: {}",
        its_home.display()
    );
    assert_eq!(var("CODEX_HOME"), its_home.join(".codex"));
    assert!(
        var("CLAUDE_CODE_TMPDIR").starts_with(its_home.parent().unwrap()),
        "CLAUDE_CODE_TMPDIR is outside the command's home"
    );
    let real = std::fs::canonicalize(home.parent().unwrap()).unwrap();
    let cwd = var("CWD");
    assert!(
        cwd.ends_with("home") && !cwd.starts_with(&real),
        "the command started in {}",
        cwd.display()
    );
    // Removed after the run, without --keep-home.
    assert!(
        std::fs::symlink_metadata(&its_home).is_err(),
        "the command's home was left behind"
    );
}

/// A request a host sends can put anything in its request line: a path,
/// a method, a tunnel's destination. `ec-model`'s diagnostics show an
/// endpoint the model serves and a destination the pinned hosts were
/// measured reaching for by name, and anything else only by its length,
/// so values placed in every part of a request line (here by `curl`),
/// a destination of letters only that reads as any host name included,
/// never reach its standard error. Its record, mode 0600, keeps them
/// whole: the positive control that the requests carried them.
#[test]
fn diagnostics_name_no_request_target_a_host_controls() {
    let curl = ["/usr/bin/curl", "/bin/curl"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .unwrap_or_else(|| panic!("curl is needed"));
    let hex = || format!("{:016x}{:016x}", fresh_seed(), fresh_seed());
    let path = Canary::new("PATH_VALUE", format!("ecpath{}", hex()));
    let host = Canary::new("HOST_VALUE", format!("echost{}", hex()));
    let letters = |n: usize| -> String {
        hex()
            .bytes()
            .chain(hex().bytes())
            .take(n)
            .map(|b| char::from(b'a' + (b % 26)))
            .collect()
    };
    // A method is 16 upper-case letters at most.
    let method = Canary::new(
        "METHOD_VALUE",
        format!("EC{}", letters(14).to_ascii_uppercase()),
    );
    // A secret that is a valid DNS label: letters only.
    let word = Canary::new("WORD_VALUE", format!("ec{}", letters(30)));
    let command = format!(
        "c={curl}; t=\"x-api-key: $EC_MODEL_TOKEN\"; \
         $c -s -o /dev/null --path-as-is -H \"$t\" \"$EC_MODEL_BASE_URL/{p}?{p}\"; \
         $c -s -o /dev/null -X {m} -H \"$t\" \"$EC_MODEL_BASE_URL/v1/messages\"; \
         $c -s -o /dev/null -p -x \"$EC_MODEL_BASE_URL\" \"https://{h}.example/\"; \
         $c -s -o /dev/null -x \"$EC_MODEL_BASE_URL\" \"http://{h}.example/{p}\"; \
         $c -s -o /dev/null -p -x \"$EC_MODEL_BASE_URL\" \"https://{w}.com/\"; \
         $c -s -o /dev/null -p -x \"$EC_MODEL_BASE_URL\" \"https://api.anthropic.com/\"; true",
        p = path.as_str(),
        m = method.as_str(),
        h = host.as_str(),
        w = word.as_str(),
    );
    let files = TestHome::new();
    let record = files.root().join("record.json");
    let out = ec_model(&record, &[("PATH", "/usr/bin:/bin")], &command);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let cs = [path.clone(), host.clone(), method.clone(), word.clone()];
    // The requests carried every value: the record has each.
    let kept = std::fs::read(&record).unwrap();
    for c in &cs {
        assert!(
            find(&kept, &cs).iter().any(|f| f.label == c.label),
            "no request carried {}",
            c.label
        );
    }
    assert_eq!(
        std::fs::metadata(&record).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // The diagnostics hold none, and still say what was asked.
    let hits: Vec<String> = find(&out.stderr, &cs)
        .iter()
        .map(|f| format!("{} as {}", f.label, f.encoding))
        .collect();
    assert!(hits.is_empty(), "ec-model printed {hits:?}");
    assert!(
        stderr.contains("GET <") && stderr.contains("<method of "),
        "{stderr}"
    );
    assert!(
        stderr.contains("api.anthropic.com:443"),
        "a listed destination is not named: {stderr}"
    );
    // Not clean: the paths are not served. The run says so.
    assert_eq!(out.status.code(), Some(3), "{stderr}");
}

/// The record is a new file, made with mode 0600 before the command
/// starts. A path that is already there is refused before anything runs
/// and left as it was: a file of another mode (whose mode `open` would
/// have kept), a link to another file (which it would have followed and
/// truncated), and a link to nothing (which it would have made).
#[test]
fn the_record_is_a_new_file_of_mode_0600_and_never_one_already_there() {
    let files = TestHome::new();
    let dir = files.root();
    let ran = dir.join("ran");
    let command = format!("touch '{}'", ran.display());
    let parent = [("PATH", "/usr/bin:/bin")];
    // An existing file, 0644.
    let existing = dir.join("existing.json");
    std::fs::write(&existing, "before").unwrap();
    std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o644)).unwrap();
    // A link to another file, and a link to nothing.
    let target = dir.join("target");
    std::fs::write(&target, "target").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    let link = dir.join("link.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let dangling = dir.join("dangling.json");
    let nowhere = dir.join("nowhere");
    std::os::unix::fs::symlink(&nowhere, &dangling).unwrap();
    for path in [&existing, &link, &dangling] {
        let out = ec_model(path, &parent, &command);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{}: {stderr}", path.display());
        assert!(stderr.contains("must be a new file"), "{stderr}");
        assert!(
            std::fs::symlink_metadata(&ran).is_err(),
            "the command ran with the record refused"
        );
    }
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(std::fs::read_to_string(&existing).unwrap(), "before");
    assert_eq!(mode(&existing), 0o644);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "target");
    assert_eq!(mode(&target), 0o644);
    assert!(std::fs::symlink_metadata(&link).unwrap().is_symlink());
    assert!(std::fs::symlink_metadata(&nowhere).is_err());
    // The control: a new path gets the record, 0600, and the command ran.
    let fresh = dir.join("fresh.json");
    let out = ec_model(&fresh, &parent, &command);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(std::fs::symlink_metadata(&ran).is_ok());
    assert_eq!(mode(&fresh), 0o600);
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&fresh).unwrap()).unwrap();
    assert!(doc["outcome"].is_object(), "{doc}");
}

/// The record keeps a body as the bytes came (Codex review, low: it was
/// decoded as lossy UTF-8, so bytes that are not UTF-8 were replaced for
/// good): a body of bytes that are not UTF-8 (a NUL among them) around a
/// canary comes back from the record byte for byte, and so does the
/// request's header value.
#[test]
fn the_record_keeps_a_body_byte_for_byte() {
    use base64::Engine as _;
    let curl = ["/usr/bin/curl", "/bin/curl"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .unwrap_or_else(|| panic!("curl is needed"));
    let canary = format!("ecbody{:016x}", fresh_seed());
    let command = format!(
        "printf '\\377\\376%s\\303(\\000\\200' '{canary}' >body && \
         {curl} -s -o /dev/null -H 'x-ec-probe: hello' -H \"x-api-key: $EC_MODEL_TOKEN\" \
         --data-binary @body \"$EC_MODEL_BASE_URL/ec-binary\"; true"
    );
    let files = TestHome::new();
    let record = files.root().join("record.json");
    let out = ec_model(&record, &[("PATH", "/usr/bin:/bin")], &command);
    // Not clean: the path is not served, which the run says.
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
    let request = doc["requests"]
        .as_array()
        .and_then(|rs| rs.iter().find(|r| r["path"] == "/ec-binary"))
        .unwrap_or_else(|| panic!("the request is not in the record: {doc}"));
    let bytes = |v: &serde_json::Value| {
        base64::engine::general_purpose::STANDARD
            .decode(v.as_str().unwrap_or_else(|| panic!("not base64 text: {v}")))
            .unwrap_or_else(|e| panic!("not base64: {e}"))
    };
    let want = [&b"\xff\xfe"[..], canary.as_bytes(), b"\xc3(\x00\x80"].concat();
    assert_eq!(bytes(&request["body"]), want);
    let names = request["headers"].as_array().unwrap();
    let at = names
        .iter()
        .position(|n| n == "x-ec-probe")
        .unwrap_or_else(|| panic!("no x-ec-probe header: {request}"));
    assert_eq!(bytes(&request["values"][at]), b"hello");
}

/// A command in the background that writes a beat to `beat` every 0.2 s
/// for 30 s and then ends on its own (so a failing test leaves nothing
/// running for long), its output away from the command's.
fn heartbeat(beat: &Path) -> String {
    format!(
        "(i=0; while [ $i -lt 150 ]; do echo $i >'{b}'; i=$((i+1)); sleep 0.2; done) \
         >/dev/null 2>&1 </dev/null &",
        b = beat.display()
    )
}

/// Whether the beat stopped: unchanged over a second, once it began.
fn stopped(beat: &Path) -> bool {
    let read = || std::fs::read_to_string(beat).unwrap_or_default();
    let before = read();
    std::thread::sleep(Duration::from_secs(1));
    !before.is_empty() && read() == before
}

/// A command past `--limit` is stopped with its whole group (its
/// background beat included), and `ec-model` says so and exits 3, well
/// before the command would have ended (Codex review, medium: the
/// command was waited for without a limit).
#[test]
fn a_command_past_its_limit_is_stopped_with_its_group() {
    let files = TestHome::new();
    let beat = files.root().join("beat");
    let command = format!(
        "{} while [ ! -s '{b}' ]; do sleep 0.1; done; sleep 30",
        heartbeat(&beat),
        b = beat.display()
    );
    let start = Instant::now();
    let out = run_ec_model(
        &files.root().join("record.json"),
        &["--limit", "2"],
        &[("PATH", "/usr/bin:/bin")],
        &command,
        Duration::from_secs(90),
    );
    let took = start.elapsed();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{stderr}");
    assert!(
        stderr.contains("the command did not end within 2 s"),
        "{stderr}"
    );
    assert!(took < Duration::from_secs(20), "it took {took:?}");
    assert!(stopped(&beat), "the command's background beat goes on");
}

/// When the command ends, what is left of its group (here a beat it
/// started in the background) is stopped before its home is removed,
/// and the run is what the command made of it (Codex review, medium: a
/// background descendant outlived the wrapper and its home).
#[test]
fn what_is_left_of_the_command_s_group_is_stopped_when_it_ends() {
    let files = TestHome::new();
    let beat = files.root().join("beat");
    let command = format!(
        "{} while [ ! -s '{b}' ]; do sleep 0.1; done; exit 0",
        heartbeat(&beat),
        b = beat.display()
    );
    let out = ec_model(
        &files.root().join("record.json"),
        &[("PATH", "/usr/bin:/bin")],
        &command,
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stopped(&beat), "the command's background beat outlived it");
}

/// A descendant that left the command's group and still holds its output
/// cannot be stopped with the group: `ec-model` waits 10 s for the output
/// to close, then says so and exits 3, never reporting the run as one
/// that ended. (The descendant ends on its own 20 s after it started.)
#[test]
fn a_descendant_outside_the_group_holding_the_output_fails_the_run() {
    let python = [
        "/usr/bin/python3",
        "/usr/local/bin/python3",
        "/opt/homebrew/bin/python3",
    ]
    .into_iter()
    .find(|p| Path::new(p).is_file())
    .unwrap_or_else(|| panic!("python3 is needed"));
    let files = TestHome::new();
    let started = files.root().join("left");
    let command = format!(
        "{python} -c 'import os, time; os.setsid(); open(\"{s}\", \"w\").close(); \
         time.sleep(20)' & while [ ! -e '{s}' ]; do sleep 0.1; done; echo done",
        s = started.display()
    );
    let out = ec_model(
        &files.root().join("record.json"),
        &[("PATH", "/usr/bin:/bin")],
        &command,
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{stderr}");
    assert!(
        stderr.contains("a process outside the command's group still held its output"),
        "{stderr}"
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("done"));
}
