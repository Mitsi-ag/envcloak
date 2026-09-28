//! A caller for the caller-evidence tests (SPEC §10a; gates 25 and 26). It
//! connects to a Unix socket as the EnvCloak CLI does, and stays connected
//! until the other end closes, so the test can read its ancestry.
//!
//! Usage:
//! - `ec-probe [--setsid] [--orphan-of <pid>] <socket>`
//!   - `--setsid`: first become the leader of a new session, with no
//!     controlling terminal.
//!   - `--orphan-of <pid>`: first wait (up to 30 seconds) until this
//!     process's parent is no longer `<pid>`: the parent exited and the
//!     kernel reparented this process, as after a double fork, `setsid`
//!     from a shell, or `nohup` and `disown`.
//! - `ec-probe --session -- <program> [args...]`: become the leader of a
//!   new session, run the program as a child, and exit with its status. The
//!   tests start each scenario this way, so its session leader is known.
//!
//! On Linux it makes itself non-dumpable first, as the CLI does, so the
//! other end cannot read its `/proc/<pid>/exe`.

use std::io::Read;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

fn usage() -> ExitCode {
    eprintln!(
        "usage: ec-probe [--setsid] [--orphan-of <pid>] <socket>\n       ec-probe --session -- <program> [args...]"
    );
    ExitCode::from(2)
}

fn session(args: Vec<std::ffi::OsString>) -> ExitCode {
    let mut it = args.into_iter();
    if it.next().is_none_or(|a| a != "--") {
        return usage();
    }
    let Some(program) = it.next() else {
        return usage();
    };
    if let Err(e) = envcloak_sys::testing::setsid() {
        eprintln!("ec-probe: setsid failed: {e}");
        return ExitCode::from(3);
    }
    match Command::new(program).args(it).status() {
        Ok(status) => {
            let code = status
                .code()
                .or_else(|| status.signal().map(|s| 128 + s))
                .unwrap_or(1);
            ExitCode::from(u8::try_from(code).unwrap_or(1))
        }
        Err(e) => {
            eprintln!("ec-probe: cannot run the program: {}", e.kind());
            ExitCode::from(127)
        }
    }
}

fn main() -> ExitCode {
    let mut args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|a| a == "--session") {
        args.remove(0);
        return session(args);
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Err(e) = envcloak_sys::set_non_dumpable() {
        eprintln!("ec-probe: cannot become non-dumpable: {e}");
        return ExitCode::from(3);
    }
    let mut new_session = false;
    let mut orphan_of: Option<u32> = None;
    let mut socket = None;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        if a == "--setsid" {
            new_session = true;
        } else if a == "--orphan-of" {
            let Some(pid) = it.next().and_then(|p| p.to_str()?.parse().ok()) else {
                return usage();
            };
            orphan_of = Some(pid);
        } else if socket.is_none() {
            socket = Some(a);
        } else {
            return usage();
        }
    }
    let Some(socket) = socket else {
        return usage();
    };
    if new_session {
        if let Err(e) = envcloak_sys::testing::setsid() {
            eprintln!("ec-probe: setsid failed: {e}");
            return ExitCode::from(3);
        }
    }
    if let Some(parent) = orphan_of {
        let end = Instant::now() + Duration::from_secs(30);
        while std::os::unix::process::parent_id() == parent {
            if Instant::now() > end {
                eprintln!("ec-probe: the parent did not exit");
                return ExitCode::from(4);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let mut stream = match UnixStream::connect(&socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ec-probe: cannot connect: {}", e.kind());
            return ExitCode::from(5);
        }
    };
    // Wait for the other end to close.
    let mut buf = [0u8; 64];
    while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
    ExitCode::SUCCESS
}
