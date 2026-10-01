//! `ec-model`: runs one command against a scripted model, for tests and
//! for measurements made by hand or from a CI step (M2 plan task M2-04).
//!
//! usage: ec-model --script FILE [--record FILE] -- COMMAND [ARG...]
//!
//! Starts `envcloak-probe-model` (beside this program in the target
//! directory, refused when older than its sources) with the script in
//! FILE, then runs COMMAND with `EC_MODEL_BASE_URL` (`http://127.0.0.1:<port>`)
//! and `EC_MODEL_TOKEN` added to this process's environment, so the
//! command can point a host at it (`ANTHROPIC_BASE_URL`,
//! `model_providers.<id>.base_url`). When COMMAND ends, the run is stopped
//! and its report (every request with its body, and the outcome) is
//! written to the `--record` file as JSON, mode 0600: give it a path
//! outside any home a test sweeps. On standard error it prints, without
//! any body, the endpoints the command called, where else it tried to
//! reach, and the outcome.
//!
//! Exits with COMMAND's code when the run was complete and every request
//! one the script served; else 3 (and 2 on a usage error).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, ExitCode};

use envcloak_testkit::agents::Model;

const USAGE: &str = "usage: ec-model --script FILE [--record FILE] -- COMMAND [ARG...]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(split) = args.iter().position(|a| a == "--") else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let (opts, command) = (&args[..split], &args[split + 1..]);
    let (mut script, mut record) = (None, None);
    let mut i = 0;
    while i < opts.len() {
        match (opts[i].as_str(), opts.get(i + 1)) {
            ("--script", Some(v)) => script = Some(v.clone()),
            ("--record", Some(v)) => record = Some(v.clone()),
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
        i += 2;
    }
    let (Some(script), Some(program)) = (script, command.first()) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let text = match std::fs::read(&script) {
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
    let model = Model::start(&script);
    let status = Command::new(program)
        .args(&command[1..])
        .env("EC_MODEL_BASE_URL", model.base_url())
        .env("EC_MODEL_TOKEN", model.token())
        .status();
    let report = model.finish();
    eprintln!("ec-model: endpoints: {}", report.endpoints().join(", "));
    eprintln!(
        "ec-model: tunnels refused: {}",
        report.connects().join(", ")
    );
    eprintln!("ec-model: outcome: {}", report.outcome);
    if let Some(path) = record {
        let requests: Vec<serde_json::Value> = report
            .requests
            .iter()
            .map(|r| {
                serde_json::json!({
                    "seq": r.seq, "at_ms": r.at_ms, "method": r.method, "path": r.path,
                    "status": r.status, "api": r.api, "pick": r.pick,
                    "body": String::from_utf8_lossy(&r.body),
                })
            })
            .collect();
        let doc = serde_json::json!({"requests": requests, "outcome": report.outcome});
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| f.write_all(doc.to_string().as_bytes()));
        if let Err(e) = written {
            eprintln!("ec-model: cannot write the record: {}", e.kind());
            return ExitCode::from(3);
        }
    }
    let code = match status {
        Ok(s) => s.code().unwrap_or(128),
        Err(e) => {
            eprintln!("ec-model: cannot run the command: {}", e.kind());
            return ExitCode::from(3);
        }
    };
    if !report.clean() {
        eprintln!("ec-model: the model's run was incomplete or served something unscripted");
        return ExitCode::from(3);
    }
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
