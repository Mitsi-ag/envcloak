//! `envcloak`: the EnvCloak command-line client.
//!
//! Every run starts with process hardening (SPEC §5): core dumps off and, on
//! Linux, non-dumpable, before any argument or input is read. Commands arrive
//! in later M1 tasks.
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
        // Never echo arguments: one of them could be a pasted secret.
        _ => {
            eprintln!("envcloak: no commands are available in this build yet");
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
