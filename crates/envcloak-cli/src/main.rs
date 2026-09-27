//! `envcloak`: the EnvCloak command-line client.
//!
//! Every run starts with process hardening (SPEC §5): core dumps off and, on
//! Linux, non-dumpable, before any argument or input is read. Commands arrive
//! in later M1 tasks.
//!
//! `envcloak run -- <cmd...>` (SPEC §6.1) has its first step only: before it
//! asks the daemon for any value, it refuses to go on under a tracer, with
//! exit 125 and `traced` (SPEC §5 "Process hardening", gate 19). Past that
//! check this build has no daemon client yet (T7) and reports
//! `daemon_unavailable`; the runner arrives in T12 behind the same check.
//!
//! `envcloak internal hardening [--hold]` is a hidden, value-free diagnostic
//! used by the gate 19 tests: it prints `key=value` hardening lines and, with
//! `--hold`, prints `ready` and waits for stdin to close, so a test can
//! inspect the live process from outside.

use std::io::{Read, Write};
use std::process::ExitCode;

#[global_allocator]
static ALLOCATOR: envcloak_sys::WipingAllocator = envcloak_sys::WipingAllocator;

fn main() -> ExitCode {
    envcloak_sys::harden_process();

    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let args: Vec<&str> = args.iter().map(|a| a.to_str().unwrap_or("")).collect();
    match args.as_slice() {
        ["--version"] | ["-V"] => {
            println!("envcloak {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["internal", "hardening"] => internal_hardening(false),
        ["internal", "hardening", "--hold"] => internal_hardening(true),
        ["run", rest @ ..] => run(rest),
        // Never echo arguments: one of them could be a pasted secret.
        _ => {
            eprintln!("envcloak: unknown command; this build has only `envcloak run -- <cmd...>`");
            ExitCode::from(2)
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

/// EnvCloak's own failures (SPEC §6.1, "Failures"): exit 125 with one
/// stable token on stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// A tracer is attached, or the check could not tell.
    Traced,
    /// No daemon to ask. In this build, always: the client arrives in T7.
    DaemonUnavailable,
}

impl Failure {
    fn report(self) -> ExitCode {
        let (token, detail) = match self {
            Failure::Traced => (
                "traced",
                "a debugger or tracer is attached to this process, so it will not request values",
            ),
            Failure::DaemonUnavailable => {
                ("daemon_unavailable", "this build has no daemon client yet")
            }
        };
        eprintln!("envcloak: {token}: {detail}");
        ExitCode::from(125)
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
        Ok(true) | Err(_) => Err(Failure::Traced),
    }
}

/// `envcloak run -- <cmd...>`. Never echoes its arguments: the command line
/// could hold a pasted secret.
fn run(args: &[&str]) -> ExitCode {
    match args {
        ["--", _, ..] => {}
        [] | ["--"] => {
            eprintln!("envcloak: run needs a command: envcloak run -- <cmd...>");
            return ExitCode::from(2);
        }
        _ => {
            eprintln!("envcloak: run takes no options in this build yet: envcloak run -- <cmd...>");
            return ExitCode::from(2);
        }
    }
    if let Err(failure) = ready_to_request_values() {
        return failure.report();
    }
    // The daemon client (T7) and the runner (T12) go here.
    Failure::DaemonUnavailable.report()
}
