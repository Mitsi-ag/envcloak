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
//! - `envcloak run [--profile p] [--ref NAME=slug[#field]]... -- <cmd...>`
//!   (SPEC §6.1 steps 1 to 4), whose first step refuses to go on under a
//!   tracer, with exit 125 and `traced` (gate 19), before any contact with
//!   the daemon. It asks a verified daemon for the decision; the runner
//!   itself arrives in T12;
//! - `envcloak approve`, `deny` and `grants list` / `grants revoke` (SPEC
//!   §10b).
//!
//! Every command that reads, shows or sends a secret or a proof (`vault
//! create`, `unlock`, `approve`, `run`) refuses under a tracer first.
//!
//! `envcloak internal hardening [--hold]` is a hidden, value-free diagnostic
//! used by the gate 19 tests: it prints `key=value` hardening lines and, with
//! `--hold`, prints `ready` and waits for stdin to close, so a test can
//! inspect the live process from outside.
//!
//! No argument is ever echoed: one could be a pasted secret. An argument
//! that is not valid UTF-8 is refused as a usage error, before anything
//! else, rather than changed: the command line `run` sends for approval
//! must be the one it was given.

mod cmd;
mod connect;
mod fail;
mod tty;

use std::io::{Read, Write};
use std::process::ExitCode;

use fail::USAGE;

#[global_allocator]
static ALLOCATOR: envcloak_sys::WipingAllocator = envcloak_sys::WipingAllocator;

const HELP: &str = "usage:
  envcloak vault create [--passphrase-fd N] [--kit-fd N] [--kdf-memory SIZE]
  envcloak unlock [--passphrase-fd N]
  envcloak lock
  envcloak status [--json]
  envcloak daemon install [--daemon /absolute/path/to/envcloakd] [--no-start]
  envcloak daemon uninstall
  envcloak run [--profile NAME] [--ref NAME=slug[#field]]... -- <cmd...>
  envcloak approve <REQUEST> [--once | --for DURATION] [--live NAME]... [--passphrase-fd N]
  envcloak deny <REQUEST>
  envcloak grants list [--json]
  envcloak grants revoke <GRANT> | --all";

fn main() -> ExitCode {
    envcloak_sys::harden_process();

    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    // An argument that is not UTF-8 is refused, never replaced: `run` sends
    // its command line for the approval statement, which must show every
    // argument as it is (SPEC §10a), and this build carries text only. The
    // argument is not echoed.
    let Some(args) = args
        .iter()
        .map(|a| a.to_str())
        .collect::<Option<Vec<&str>>>()
    else {
        eprintln!("envcloak: an argument is not valid UTF-8, which this build does not take");
        return ExitCode::from(USAGE);
    };
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
        ["run", rest @ ..] => cmd::run::run(rest),
        ["vault", rest @ ..] => cmd::vault::run(rest),
        ["unlock", rest @ ..] => cmd::unlock::run(rest),
        ["lock", rest @ ..] => cmd::lock::run(rest),
        ["status", rest @ ..] => cmd::status::run(rest),
        ["daemon", rest @ ..] => cmd::daemon::run(rest),
        ["approve", rest @ ..] => cmd::approve::approve(rest),
        ["deny", rest @ ..] => cmd::approve::deny(rest),
        ["grants", rest @ ..] => cmd::grants::run(rest),
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
