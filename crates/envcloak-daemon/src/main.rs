//! `envcloakd`: the EnvCloak vault broker daemon.
//!
//! Every run starts with process hardening (SPEC §5): core dumps off and, on
//! Linux, non-dumpable. The daemon itself arrives in task T7.
//!
//! `envcloakd internal hardening` is a hidden, value-free diagnostic that
//! prints `key=value` hardening lines.

use std::io::Write;
use std::process::ExitCode;

#[global_allocator]
static ALLOCATOR: envcloak_sys::WipingAllocator = envcloak_sys::WipingAllocator;

fn main() -> ExitCode {
    envcloak_sys::harden_process();

    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let args: Vec<&str> = args.iter().map(|a| a.to_str().unwrap_or("")).collect();
    match args.as_slice() {
        ["--version"] | ["-V"] => {
            println!("envcloakd {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["internal", "hardening"] => {
            let report = envcloak_sys::hardening_report();
            match std::io::stdout().lock().write_all(report.as_bytes()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            }
        }
        // Never echo arguments.
        _ => {
            eprintln!("envcloakd: the daemon is not available in this build yet");
            ExitCode::from(2)
        }
    }
}
