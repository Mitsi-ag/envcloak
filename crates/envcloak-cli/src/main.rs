//! `envcloak`: the EnvCloak command-line client.
//!
//! Every run starts with process hardening (SPEC §5): core dumps off and, on
//! Linux, non-dumpable, before any argument or input is read. The CLI never
//! holds the vault key; it talks to `envcloakd` over a socket it verifies
//! first, and never starts a daemon itself (SPEC §4.1, §4.2).
//!
//! Commands in this build:
//! - `envcloak vault create`, `unlock`, `lock`, `status` and `daemon
//!   install` / `daemon uninstall` (see [`cmd`]);
//! - `envcloak run -- <cmd...>` (SPEC §6.1), whose first step refuses to go
//!   on under a tracer, with exit 125 and `traced` (gate 19), before any
//!   contact with the daemon. It then connects to a verified daemon; the
//!   runner itself arrives in T12.
//!
//! `envcloak internal hardening [--hold]` is a hidden, value-free diagnostic
//! used by the gate 19 tests: it prints `key=value` hardening lines and, with
//! `--hold`, prints `ready` and waits for stdin to close, so a test can
//! inspect the live process from outside.
//!
//! No argument is ever echoed: one could be a pasted secret.

mod cmd;
mod connect;
mod fail;
mod tty;

use std::io::{Read, Write};
use std::process::ExitCode;

use fail::{Failure, RUN_FAILURE, USAGE};

#[global_allocator]
static ALLOCATOR: envcloak_sys::WipingAllocator = envcloak_sys::WipingAllocator;

const HELP: &str = "usage:
  envcloak vault create [--passphrase-fd N] [--kit-fd N] [--kdf-memory SIZE]
  envcloak unlock [--passphrase-fd N]
  envcloak lock
  envcloak status [--json]
  envcloak daemon install [--daemon /absolute/path/to/envcloakd] [--no-start]
  envcloak daemon uninstall
  envcloak run -- <cmd...>";

fn main() -> ExitCode {
    envcloak_sys::harden_process();

    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let args: Vec<&str> = args.iter().map(|a| a.to_str().unwrap_or("")).collect();
    match args.as_slice() {
        ["--version"] | ["-V"] => {
            println!("envcloak {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["--help"] | ["-h"] | ["help"] => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        ["internal", "hardening"] => internal_hardening(false),
        ["internal", "hardening", "--hold"] => internal_hardening(true),
        ["run", rest @ ..] => run(rest),
        ["vault", rest @ ..] => cmd::vault::run(rest),
        ["unlock", rest @ ..] => cmd::unlock::run(rest),
        ["lock", rest @ ..] => cmd::lock::run(rest),
        ["status", rest @ ..] => cmd::status::run(rest),
        ["daemon", rest @ ..] => cmd::daemon::run(rest),
        // Never echo arguments: one of them could be a pasted secret.
        _ => {
            eprintln!("envcloak: unknown command\n{HELP}");
            ExitCode::from(USAGE)
        }
    }
}

fn internal_hardening(hold: bool) -> ExitCode {
    let mut out = std::io::stdout().lock();
    let mut ok = out
        .write_all(envcloak_sys::hardening_report().as_bytes())
        .is_ok();
    if hold {
        ok &= writeln!(out, "ready").is_ok() && out.flush().is_ok();
        drop(out);
        let mut sink = [0u8; 64];
        let mut stdin = std::io::stdin().lock();
        while matches!(stdin.read(&mut sink), Ok(n) if n > 0) {}
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// What must hold before this process asks the daemon for any value (SPEC
/// §5 "Process hardening"): no tracer is attached. Non-dumpable keeps new
/// same-uid attaches out, but not a tracer that started the process
/// (`strace`, `gdb`), so the CLI refuses instead. When the check cannot
/// tell, it refuses too.
fn ready_to_request_values() -> Result<(), Failure> {
    match envcloak_sys::tracer_present() {
        Ok(false) => Ok(()),
        Ok(true) | Err(_) => Err(Failure::new(
            "traced",
            "a debugger or tracer is attached to this process, so it will not request values",
        )),
    }
}

/// `envcloak run -- <cmd...>`. Never echoes its arguments: the command line
/// could hold a pasted secret.
fn run(args: &[&str]) -> ExitCode {
    match args {
        ["--", _, ..] => {}
        [] | ["--"] => {
            eprintln!("envcloak: run needs a command: envcloak run -- <cmd...>");
            return ExitCode::from(USAGE);
        }
        _ => {
            eprintln!("envcloak: run takes no options in this build yet: envcloak run -- <cmd...>");
            return ExitCode::from(USAGE);
        }
    }
    if let Err(failure) = ready_to_request_values() {
        return failure.report(RUN_FAILURE);
    }
    // Only a verified daemon is ever asked; with none, run says how to
    // start one and starts nothing.
    if let Err(failure) = connect::connect() {
        return failure.report(RUN_FAILURE);
    }
    // The runner (T12) goes here.
    eprintln!("envcloak: run cannot start commands in this build yet");
    ExitCode::from(USAGE)
}
