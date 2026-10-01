//! `envcloak-probe-model`: the scripted model the agent hosts are pointed
//! at during a coverage probe or a test (M2 plan task M2-04). See
//! `envcloak_agents::probe::model` for what it serves and the lines it
//! reads and writes.
//!
//! usage: envcloak-probe-model [--time-limit SECONDS]
//!
//! The script is the first line of standard input. The process hardens
//! itself first (no core file; on Linux, not dumpable), installs the
//! wiping allocator, and prints no request content anywhere but its
//! reports on standard output.

use std::io::{self, BufRead, Read, Write};
use std::process::ExitCode;
use std::time::Duration;

use envcloak_agents::probe::model::{Limits, Script, Server, script::MAX_SCRIPT};
use zeroize::Zeroizing;

#[global_allocator]
static ALLOCATOR: envcloak_sys::WipingAllocator = envcloak_sys::WipingAllocator;

const NAME: &str = "envcloak-probe-model";
const USAGE: &str = "usage: envcloak-probe-model [--time-limit SECONDS]
The script is the first line of standard input (JSON); see the crate
documentation of envcloak-agents for the lines that follow.";
/// The longest run anyone may ask for: one hour.
const MAX_TIME: u64 = 3600;

fn main() -> ExitCode {
    envcloak_sys::harden_process();
    envcloak_sys::install_panic_hook(NAME);

    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let args: Option<Vec<&str>> = args.iter().map(|a| a.to_str()).collect();
    let mut limits = Limits::default();
    match args.as_deref() {
        Some([]) => {}
        Some(["--time-limit", secs]) => match secs.parse::<u64>() {
            Ok(s) if (1..=MAX_TIME).contains(&s) => limits.time = Duration::from_secs(s),
            _ => return usage(),
        },
        Some(["--version"]) => {
            println!("{NAME} {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some(["--help"]) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        _ => return usage(),
    }

    let mut input = io::stdin().lock();
    let mut line: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let read = (&mut input)
        .take(MAX_SCRIPT as u64 + 1)
        .read_until(b'\n', &mut line);
    if read.is_err() || line.last() != Some(&b'\n') {
        eprintln!("{NAME}: the script must be one line of at most 1 MiB on standard input");
        return ExitCode::from(2);
    }
    line.pop();
    // What stdin buffered past the script stays in its buffer for the
    // control thread.
    drop(input);
    let script = match Script::parse(&line) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{NAME}: {e}");
            return ExitCode::from(2);
        }
    };
    drop(line);

    let server = match Server::bind(script, limits) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{NAME}: cannot listen on 127.0.0.1: {}", e.kind());
            return ExitCode::from(2);
        }
    };
    let ready = serde_json::json!({
        "addr": server.addr().to_string(),
        "token": server.token().as_str(),
    });
    let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(ready.to_string().into_bytes());
    drop(ready);
    out.push(b'\n');
    {
        let mut stdout = io::stdout().lock();
        if stdout
            .write_all(&out)
            .and_then(|()| stdout.flush())
            .is_err()
        {
            return ExitCode::from(2);
        }
    }
    drop(out);

    let handle = server.handle();
    let control = handle.clone();
    std::thread::spawn(move || {
        let mut input = io::stdin().lock();
        let mut cmd = String::new();
        loop {
            cmd.clear();
            match input.read_line(&mut cmd) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            match cmd.trim_end_matches(['\n', '\r']) {
                "requests" => {
                    let mut stdout = io::stdout().lock();
                    if control.write_report(&mut stdout, false).is_err() {
                        break;
                    }
                }
                "stop" => break,
                _ => eprintln!("{NAME}: an unknown control line was ignored"),
            }
        }
        control.stop();
    });

    server.serve();
    let complete = handle.outcome().complete();
    {
        let mut stdout = io::stdout().lock();
        let _ = handle.write_report(&mut stdout, true);
    }
    handle.wipe();
    if complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(3)
    }
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}
