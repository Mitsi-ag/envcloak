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

use envcloak_client::connect::{connect, run_paths};
use envcloak_client::fail::{FAILURE, Failure, START_DAEMON, usage};
use envcloak_client::render;
use envcloak_ipc::view::{HardeningView, Integrity, StatusView, VaultState};
use envcloak_ipc::{ClientError, DaemonIdentity};

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
            let running = if f.token() == ClientError::Unavailable.token() {
                "not running"
            } else {
                "not verified"
            };
            if json {
                print!("{}", not_running_json(running, &cli));
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
        print!("{}", status_json(&status, identity, &cli));
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
    println!(
        "grants: {} in force, {} waiting for approval",
        s.approvals.grants, s.approvals.pending
    );
    let audit = &s.audit;
    match (audit.open, audit.head_seq, s.vault.state) {
        (true, Some(seq), _) => println!(
            "audit log: open, last entry {seq} ({} not yet anchored in the vault)",
            audit.unanchored
        ),
        (false, _, VaultState::Unlocked) => println!(
            "audit log: UNAVAILABLE: requests that would release values are denied until it can \
             be written"
        ),
        _ => println!("audit log: closed while the vault is locked"),
    }
    if audit.anchor_failed {
        println!(
            "audit log: its head could not be saved in the vault; the daemon tries again, and \
             until then the entries after the last saved head are not anchored"
        );
    }
    if audit.queued > 0 || audit.dropped > 0 {
        println!(
            "audit events waiting to be written: {}; lost because the queue was full: {}",
            audit.queued, audit.dropped
        );
    }
    if s.approvals.proof_failures > 0 {
        println!(
            "failed passphrase attempts: {} (next attempt admitted in {})",
            s.approvals.proof_failures,
            duration(s.approvals.proof_wait_secs)
        );
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

/// What `status --json` prints without a verified daemon: JSON through
/// the CLI's one writer ([`render::json_text`]), and a newline.
fn not_running_json(running: &str, cli: &HardeningView) -> String {
    let v = serde_json::json!({"daemon": {"state": running}, "cli": {"hardening": cli}});
    format!("{}\n", render::json_text(&v))
}

/// What `status --json` prints for the daemon's answer: JSON through the
/// CLI's one writer ([`render::json_text`]), and a newline.
fn status_json(s: &StatusView, identity: DaemonIdentity, cli: &HardeningView) -> String {
    let mut v = serde_json::to_value(s).unwrap_or_default();
    v["daemon"]["state"] = "running".into();
    v["daemon"]["identity"] = identity_word(identity).into();
    v["daemon"]["hardened"] = s.daemon.hardening.hardened().into();
    v["cli"] = serde_json::json!({"hardening": cli, "hardened": cli.hardened()});
    format!("{}\n", render::json_text(&v))
}

#[cfg(test)]
mod tests {
    use super::*;
    use envcloak_ipc::view::{
        ApprovalsView, AuditStatusView, DaemonView, LockView, VaultState, VaultView,
    };
    use envcloak_policy::display_escaped;

    fn hardening() -> HardeningView {
        HardeningView {
            core_dumps_off: true,
            non_dumpable: false,
            hardened_runtime: Some(false),
        }
    }

    /// Review T11 open 2 (verification): `status --json` goes through the
    /// CLI's one JSON writer. A program answering in the daemon's place
    /// can put a C1 control (U+009B, CSI) or a bidirectional override
    /// (U+202E) in a string that JSON's own encoding leaves as it is; the
    /// text printed escapes them as `\uXXXX` and reads back unchanged.
    #[test]
    fn status_json_escapes_what_a_terminal_would_act_on() {
        let version = "0.1.0\u{202e}\u{9b}31m";
        let s = StatusView {
            daemon: DaemonView {
                version: version.to_owned(),
                pid: 4242,
                hardening: hardening(),
                runtime_dir_fallback: false,
            },
            vault: VaultView {
                state: VaultState::Unavailable,
                integrity: None,
                read_only: false,
                unavailable: Some("damaged\u{9b}2J".to_owned()),
                busy: false,
                failed_unlocks: 0,
            },
            lock: LockView {
                last_reason: None,
                idle_limit_secs: 900,
                idle_remaining_secs: None,
            },
            approvals: ApprovalsView {
                grants: 0,
                pending: 0,
                proof_failures: 0,
                proof_wait_secs: 0,
            },
            audit: AuditStatusView {
                open: false,
                head_seq: None,
                unanchored: 0,
                anchor_failed: false,
                queued: 0,
                dropped: 0,
            },
        };
        let text = status_json(&s, DaemonIdentity::Unverified, &hardening());
        assert!(text.ends_with('\n'), "{text:?}");
        assert!(!text.trim_end().chars().any(display_escaped), "{text:?}");
        assert!(
            text.contains(r#""version":"0.1.0\u202e\u009b31m""#),
            "{text}"
        );
        assert!(
            text.contains(r#""unavailable":"damaged\u009b2J""#),
            "{text}"
        );
        let back: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(back["daemon"]["version"], version);
        assert_eq!(back["daemon"]["state"], "running");
        assert_eq!(back["daemon"]["identity"], "unverified");

        let text = not_running_json("not running", &hardening());
        assert!(text.ends_with('\n'), "{text:?}");
        let back: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(back["daemon"]["state"], "not running");
        assert_eq!(back["cli"]["hardening"]["core_dumps_off"], true);
    }
}
