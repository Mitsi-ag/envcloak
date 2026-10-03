//! `envcloakd`: the EnvCloak vault broker daemon, the only process that
//! holds the unlocked vault key (SPEC §4).
//!
//! It is started only by launchd or systemd from `envcloak daemon
//! install`, or by the user as `envcloakd --foreground` by absolute path
//! (SPEC §4.1). It never daemonizes itself, and the CLI never starts it.
//!
//! Every run starts with process hardening (SPEC §5): core dumps off and,
//! on Linux, non-dumpable, before any argument is read.
//!
//! - `envcloakd --foreground [--idle-lock <duration>]` serves the socket
//!   until SIGTERM, SIGINT or SIGHUP, which lock the vault first. The idle
//!   limit is 8 hours by default, at most 24 (`90m`, `8h`, `3600s`).
//! - `envcloakd internal hardening` is a hidden, value-free diagnostic that
//!   prints `key=value` hardening lines.
//! - `envcloakd internal panic` is a hidden command that panics with its
//!   standard input in the message. A panic prints where it happened and
//!   never its message, which could hold a value
//!   (`envcloak_sys::install_panic_hook`, gate 12); release builds then
//!   abort.

/// Writes a line to standard error, and goes on when the write fails: the
/// terminal the daemon was started in may be closed, or the process
/// reading its log gone. `eprintln!` panics then, and a panic in the
/// signal thread left the daemon running after SIGTERM, holding its lock
/// file.
macro_rules! log_line {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

mod audit;
mod backup;
mod backups;
mod clock;
mod crowded;
mod exe_hash;
mod import;
mod items;
mod lock;
mod redact;
mod requests;
mod server;
mod state;

use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use server::{DaemonConfig, run_daemon};

#[global_allocator]
static ALLOCATOR: envcloak_sys::WipingAllocator = envcloak_sys::WipingAllocator;

const USAGE: &str = "usage: envcloakd --foreground [--idle-lock <duration>]\n\
    envcloakd is started by launchd or systemd (run `envcloak daemon install`), \
    or by you with `envcloakd --foreground`, by absolute path";

fn main() -> ExitCode {
    envcloak_sys::harden_process();
    envcloak_sys::install_panic_hook("envcloakd");

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
        ["internal", "panic"] => envcloak_sys::panic_with_input(),
        ["--foreground", rest @ ..] => match parse_options(rest) {
            Some(cfg) => serve(cfg),
            None => usage(),
        },
        // Never echo arguments.
        _ => usage(),
    }
}

fn usage() -> ExitCode {
    log_line!("{USAGE}");
    ExitCode::from(2)
}

fn serve(cfg: DaemonConfig) -> ExitCode {
    match run_daemon(cfg) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log_line!("envcloakd: {}: {}", e.token(), e.message());
            ExitCode::FAILURE
        }
    }
}

fn parse_options(args: &[&str]) -> Option<DaemonConfig> {
    let mut cfg = DaemonConfig {
        idle_limit: lock::DEFAULT_IDLE,
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match *arg {
            "--idle-lock" => cfg.idle_limit = parse_idle(rest.next()?)?,
            _ => return None,
        }
    }
    Some(cfg)
}

/// `<n>s`, `<n>m` or `<n>h`, from 1 minute to 24 hours.
fn parse_idle(s: &str) -> Option<Duration> {
    // Match the unit as a suffix rather than splitting at a byte offset: a
    // value ending in a multi-byte character must fail like any other bad
    // input, not panic inside that character.
    let (digits, per_unit) = if let Some(d) = s.strip_suffix('s') {
        (d, 1)
    } else if let Some(d) = s.strip_suffix('m') {
        (d, 60)
    } else {
        (s.strip_suffix('h')?, 3600)
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secs = digits.parse::<u64>().ok()?.checked_mul(per_unit)?;
    let d = Duration::from_secs(secs);
    (lock::MIN_IDLE..=lock::MAX_IDLE).contains(&d).then_some(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_limits_parse_within_bounds() {
        assert_eq!(parse_idle("8h"), Some(Duration::from_secs(8 * 3600)));
        assert_eq!(parse_idle("90m"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_idle("60s"), Some(Duration::from_secs(60)));
        assert_eq!(parse_idle("24h"), Some(Duration::from_secs(86_400)));
        for bad in [
            "",
            "h",
            "8",
            "25h",
            "59s",
            "-1h",
            "1.5h",
            "8H",
            "8 h",
            "99999999999999999999h",
            // A multi-byte last character is refused, never split inside.
            "8\u{e9}",
            "8\u{20ac}",
            "8\u{1F600}",
            "8\u{ff48}",
            "\u{e9}h",
            "8\u{e9}h",
        ] {
            assert_eq!(parse_idle(bad), None, "{bad}");
        }
        assert!(parse_options(&["--idle-lock", "8\u{ff48}"]).is_none());
        assert!(parse_options(&["--idle-lock", "2h"]).is_some());
        assert!(parse_options(&["--idle-lock"]).is_none());
        assert!(parse_options(&["--other"]).is_none());
    }
}
