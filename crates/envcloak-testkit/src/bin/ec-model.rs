//! `ec-model`: runs one command against a scripted model in an isolated
//! home, for measurements made by hand or from a CI step (M2 plan task
//! M2-04).
//!
//! usage: ec-model --script FILE [--record FILE] [--limit SECONDS] [--keep-home] -- COMMAND [ARG...]
//!
//! Starts `envcloak-probe-model` (beside this program in the target
//! directory, refused when older than its sources) with the script in
//! FILE, then runs COMMAND in a test home of its own (`/tmp/ecXXXXXX`,
//! testkit's `TestHome`), started in its `HOME`. COMMAND's environment is
//! cleared first: it gets the home's variables (`PATH` of system
//! directories only, `LANG`, `TERM`, and `HOME`, every `XDG_*` base
//! directory and `TMPDIR` inside the home), `CODEX_HOME` and
//! `CLAUDE_CODE_TMPDIR` inside the home, `EC_MODEL_BASE_URL`
//! (`http://127.0.0.1:<port>`) and `EC_MODEL_TOKEN`, and nothing else from
//! this process: no credential or configuration of whoever runs it
//! (`ANTHROPIC_API_KEY`, `~/.codex`, `~/.claude`) reaches the command
//! (L-03). Name COMMAND by absolute path, and point a host at the model in
//! a wrapper (`/bin/sh -c 'ANTHROPIC_BASE_URL=$EC_MODEL_BASE_URL exec ...'`).
//!
//! COMMAND leads a process group of its own, with an empty standard input;
//! what it writes to its standard output and error is passed on once it
//! has ended. It has `--limit` seconds (300 at most, the default): past
//! them its group gets `SIGTERM`, then `SIGKILL` 2 s later. When COMMAND
//! exits, whatever is left of its group (a command it started in the
//! background) is killed too, before the home is removed. A descendant
//! that left the group and still holds the output open 10 s later is
//! reported, as is a read of the output that fails (the output is then
//! incomplete); one that left it and closed its output cannot be seen. The
//! home is removed when COMMAND has ended, unless `--keep-home` keeps it
//! for a look at what the host wrote (its path is printed).
//!
//! When COMMAND has ended, the run is stopped and its report (every
//! request with its header values, a forwarded request's whole target and
//! its body, each of these three as the bytes came, in standard base64,
//! and the outcome) is written to the `--record`
//! file as JSON: a new file, made with mode 0600 before COMMAND starts; a
//! path that already exists, a symbolic link included, is refused (L-12:
//! the record holds every body whole). Give it a path outside any home a
//! test sweeps. On standard error it prints, without any body, the
//! endpoints the command called and where else it tried to reach, each as
//! a diagnostic may show it (a request line is whatever a client sent: an
//! endpoint the model serves, an HTTP method and a destination the pinned
//! hosts were measured reaching for are named, anything else only by its
//! length; the record has them whole), and the outcome.
//!
//! Exits with COMMAND's code when it ended within its limit, its output
//! was read whole, nothing outside its group held it, and the run was
//! complete with every request one the script served; else 3 (and 2 on a
//! usage error).

use std::fs::File;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use envcloak_testkit::TestHome;
use envcloak_testkit::agents::{Model, RUN_LIMIT, run_within};

const USAGE: &str = "usage: ec-model --script FILE [--record FILE] [--limit SECONDS] \
                     [--keep-home] -- COMMAND [ARG...]";

/// What the options say.
struct Options {
    script: String,
    record: Option<String>,
    limit: Duration,
    keep: bool,
}

fn options(opts: &[String]) -> Option<Options> {
    let (mut script, mut record, mut limit, mut keep) = (None, None, RUN_LIMIT, false);
    let mut i = 0;
    while i < opts.len() {
        match (opts[i].as_str(), opts.get(i + 1)) {
            ("--keep-home", _) => {
                keep = true;
                i += 1;
                continue;
            }
            ("--script", Some(v)) => script = Some(v.clone()),
            ("--record", Some(v)) => record = Some(v.clone()),
            ("--limit", Some(v)) => {
                let secs: u64 = v.parse().ok().filter(|s| *s >= 1)?;
                limit = Duration::from_secs(secs);
                if limit > RUN_LIMIT {
                    return None;
                }
            }
            _ => return None,
        }
        i += 2;
    }
    Some(Options {
        script: script?,
        record,
        limit,
        keep,
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(split) = args.iter().position(|a| a == "--") else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let (opts, command) = (&args[..split], &args[split + 1..]);
    let (Some(opts), Some(program)) = (options(opts), command.first()) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let text = match std::fs::read(&opts.script) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("ec-model: cannot read the script: {}", e.kind());
            return ExitCode::from(2);
        }
    };
    let Ok(script) = serde_json::from_slice::<serde_json::Value>(&text) else {
        eprintln!("ec-model: the script is not JSON");
        return ExitCode::from(2);
    };
    // The record is made before the command runs: new, 0600 from the
    // start, never through a link (Codex review and verifier, low: an
    // existing file kept its mode, and a link was followed).
    let mut record: Option<File> = None;
    if let Some(path) = &opts.record {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
        {
            Ok(f) => record = Some(f),
            Err(e) => {
                eprintln!(
                    "ec-model: cannot make the record, which must be a new file: {}",
                    e.kind()
                );
                return ExitCode::from(2);
            }
        }
    }
    let home = TestHome::new();
    let codex_home = home.home().join(".codex");
    if let Err(e) = std::fs::create_dir(&codex_home) {
        eprintln!("ec-model: cannot make CODEX_HOME in the home: {}", e.kind());
        return ExitCode::from(3);
    }
    let model = Model::start(&script);
    let mut cmd = Command::new(program);
    home.apply(&mut cmd)
        .args(&command[1..])
        .env("CODEX_HOME", &codex_home)
        .env("CLAUDE_CODE_TMPDIR", home.root().join("tmp"))
        .env("EC_MODEL_BASE_URL", model.base_url())
        .env("EC_MODEL_TOKEN", model.api_key())
        .current_dir(home.home())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Bounded, in a group of its own, and what is left of the group killed
    // before the home goes (Codex review, medium: `status()` could wait
    // forever, and a background descendant outlived the home).
    let ended = run_within(cmd, opts.limit);
    let report = model.finish();
    let mut ok = true;
    let code = match &ended {
        Ok(b) => {
            let _ = std::io::stdout().write_all(&b.output.stdout);
            let _ = std::io::stderr().write_all(&b.output.stderr);
            if !b.in_time {
                eprintln!(
                    "ec-model: the command did not end within {} s; its process group was stopped",
                    opts.limit.as_secs()
                );
                ok = false;
            }
            if b.read_failed {
                eprintln!("ec-model: a read of the command's output failed; it is incomplete");
                ok = false;
            } else if !b.complete {
                eprintln!(
                    "ec-model: a process outside the command's group still held its output \
                     open after it ended; it may still be running"
                );
                ok = false;
            }
            b.output.status.code().unwrap_or(128)
        }
        Err(e) => {
            eprintln!("ec-model: cannot run the command: {}", e.kind());
            ok = false;
            128
        }
    };
    eprintln!(
        "ec-model: endpoints: {}",
        report.shown_model_endpoints().join(", ")
    );
    eprintln!(
        "ec-model: tunnels refused: {}",
        report.shown_connects().join(", ")
    );
    eprintln!("ec-model: outcome: {}", report.outcome);
    if opts.keep {
        eprintln!("ec-model: home kept: {}", home.keep().display());
    } else {
        drop(home);
    }
    if let Some(mut file) = record {
        let requests: Vec<serde_json::Value> = report
            .requests
            .iter()
            .map(|r| {
                // Bytes as they came, in base64, as the scripted model
                // reports them (Codex review, low: decoded as lossy UTF-8,
                // a body's other bytes were replaced for good).
                let b64 = |b: &[u8]| STANDARD.encode(b);
                let values: Vec<String> = r.header_values.iter().map(|v| b64(v)).collect();
                serde_json::json!({
                    "seq": r.seq, "at_ms": r.at_ms, "method": r.method, "path": r.path,
                    "query": r.query, "headers": r.headers, "values": values,
                    "forward": b64(&r.forward), "status": r.status,
                    "answered": r.answered, "api": r.api, "pick": r.pick,
                    "body": b64(&r.body),
                })
            })
            .collect();
        let doc = serde_json::json!({"requests": requests, "outcome": report.outcome});
        if let Err(e) = file
            .write_all(doc.to_string().as_bytes())
            .and_then(|()| file.sync_all())
        {
            eprintln!("ec-model: cannot write the record: {}", e.kind());
            return ExitCode::from(3);
        }
    }
    if !ok {
        return ExitCode::from(3);
    }
    if !report.clean() {
        eprintln!("ec-model: the model's run was incomplete or served something unscripted");
        return ExitCode::from(3);
    }
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
