//! `envcloak status [--json]` (SPEC §4.2, §5 "Process hardening"): the
//! daemon, how far it can be trusted, the vault and its lock. Metadata
//! only.
//!
//! It says truthfully what this build cannot guarantee:
//! - "daemon identity unverified" on every build that pins no code
//!   signature (every M1 build): only the daemon's uid was checked, so a
//!   program running as you could impersonate it;
//! - "unhardened" for the daemon and for this CLI when they run without
//!   the hardened runtime (macOS) or could not be made non-dumpable
//!   (Linux).
//!
//! With no daemon it says so, and how to start one, and exits 1.

use std::process::ExitCode;

use envcloak_ipc::view::{HardeningView, Integrity, StatusView, VaultState};
use envcloak_ipc::{ClientError, DaemonIdentity};

use crate::connect::{connect, run_paths};
use crate::fail::{FAILURE, Failure, START_DAEMON, usage};

pub fn run(args: &[&str]) -> ExitCode {
    let json = match args {
        [] => false,
        ["--json"] => true,
        _ => return usage("envcloak status [--json]"),
    };
    let cli = HardeningView::from(envcloak_sys::hardening_status());
    let answer = connect().and_then(|mut c| {
        let identity = c.identity();
        c.status().map(|s| (s, identity)).map_err(Failure::from)
    });
    let (status, identity) = match answer {
        Ok(a) => a,
        Err(f) => {
            let running = if f.token == ClientError::Unavailable.token() {
                "not running"
            } else {
                "not verified"
            };
            if json {
                println!(
                    "{}",
                    serde_json::json!({"daemon": {"state": running}, "cli": {"hardening": cli}})
                );
            } else {
                println!("daemon: {running}");
                if running == "not running" {
                    println!("  {START_DAEMON}");
                }
                println!("cli hardening: {}", hardening_text(&cli));
            }
            return f.report(FAILURE);
        }
    };
    if json {
        print_json(&status, identity, &cli);
    } else {
        print_human(&status, identity, &cli);
    }
    ExitCode::SUCCESS
}

fn identity_word(i: DaemonIdentity) -> &'static str {
    match i {
        DaemonIdentity::Verified => "verified",
        DaemonIdentity::Unverified => "unverified",
    }
}

fn hardening_text(h: &HardeningView) -> String {
    if h.hardened() {
        return "hardened".to_owned();
    }
    let mut missing = Vec::new();
    if !h.core_dumps_off {
        missing.push("core dumps are on");
    }
    match h.hardened_runtime {
        Some(false) => missing.push("not signed with the hardened runtime"),
        Some(true) => {}
        None if !h.non_dumpable => missing.push("the process is dumpable"),
        None => {}
    }
    format!("unhardened ({})", missing.join("; "))
}

fn duration(secs: u64) -> String {
    let (h, m) = (secs / 3600, secs % 3600 / 60);
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m")
    } else {
        format!("{secs}s")
    }
}

fn print_human(s: &StatusView, identity: DaemonIdentity, cli: &HardeningView) {
    println!(
        "daemon: running (pid {}, version {})",
        s.daemon.pid, s.daemon.version
    );
    match identity {
        DaemonIdentity::Verified => println!("daemon identity: verified"),
        DaemonIdentity::Unverified => println!(
            "daemon identity: unverified (this build pins no code signature, so only the \
             daemon's user was checked; a program running as you could impersonate it)"
        ),
    }
    println!("daemon hardening: {}", hardening_text(&s.daemon.hardening));
    println!("cli hardening: {}", hardening_text(cli));
    let vault = match s.vault.state {
        VaultState::Absent => "none yet (run `envcloak vault create`)".to_owned(),
        VaultState::Locked if s.vault.busy => "locked (an unlock is in progress)".to_owned(),
        VaultState::Locked => "locked".to_owned(),
        VaultState::Unlocked => {
            let integrity = match s.vault.integrity {
                Some(Integrity::Ok) => "integrity ok",
                _ => "modified outside EnvCloak",
            };
            if s.vault.read_only {
                format!("unlocked, read-only ({integrity})")
            } else {
                format!("unlocked ({integrity})")
            }
        }
        VaultState::Unavailable => format!(
            "unavailable ({})",
            s.vault.unavailable.as_deref().unwrap_or("unknown")
        ),
    };
    println!("vault: {vault}");
    match s.lock.idle_remaining_secs {
        Some(left) => println!(
            "idle lock: after {} idle; locks in {}",
            duration(s.lock.idle_limit_secs),
            duration(left)
        ),
        None => println!("idle lock: after {} idle", duration(s.lock.idle_limit_secs)),
    }
    if let Some(r) = s.lock.last_reason {
        println!("last locked by: {}", r.as_str());
    }
    if s.vault.failed_unlocks > 0 {
        println!("failed unlocks: {}", s.vault.failed_unlocks);
    }
    if s.daemon.runtime_dir_fallback {
        if let Ok(p) = run_paths() {
            println!(
                "warning: XDG_RUNTIME_DIR is not set, so the daemon socket is in {}",
                p.dir.display()
            );
        }
    }
}

fn print_json(s: &StatusView, identity: DaemonIdentity, cli: &HardeningView) {
    let mut v = serde_json::to_value(s).unwrap_or_default();
    v["daemon"]["state"] = "running".into();
    v["daemon"]["identity"] = identity_word(identity).into();
    v["daemon"]["hardened"] = s.daemon.hardening.hardened().into();
    v["cli"] = serde_json::json!({"hardening": cli, "hardened": cli.hardened()});
    println!("{v}");
}
