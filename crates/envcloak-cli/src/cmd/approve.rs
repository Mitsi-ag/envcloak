//! `envcloak approve <REQUEST> [--once | --for DURATION] [--live NAME]...
//! [--passphrase-fd N]` and `envcloak deny <REQUEST>` (SPEC §10b
//! "Approval proofs"; gates 23 and 31).
//!
//! `approve` is run by a person, in a terminal they control, after
//! `envcloak run` printed `approval_required request=<id>`:
//! 1. under a tracer it refuses at once (gate 19);
//! 2. it fetches the pending request from a verified daemon and renders
//!    the statement ([`render_statement`]): the caller, the project, every
//!    binding, the full command line as an escaped list (cut past 2 KB
//!    with a marker), and the grant the options ask for;
//! 3. it reads the vault passphrase from `/dev/tty` with echo off, or from
//!    the descriptor `--passphrase-fd` names, never from argv or the
//!    environment;
//! 4. it sends the passphrase once, with the SHA-256 of the canonical
//!    statement it rendered ([`statement_digest`]) and the names of the
//!    agent markers in its environment. The daemon verifies the passphrase
//!    against the envelope and checks that the digest is its own pending
//!    request's with the same options.
//!
//! The statement shown here is advisory: the daemon approves what its
//! pending request says, and refuses when the digest differs. The
//! passphrase is the proof. A `y` typed anywhere approves nothing.
//!
//! `deny` refuses a pending request. Tightening needs no proof.

use std::process::ExitCode;
use std::time::Duration;

use envcloak_policy::{
    ApprovalOptions, DEFAULT_TTL, EnvName, GrantId, MAX_AGENT_TTL, PendingId, Uses,
    escape_for_display, render_statement, statement_digest,
};

use super::{claims, fd_number};
use crate::connect::connect;
use crate::fail::{FAILURE, Failure, refuse_if_traced, usage};
use crate::tty::{Terminal, read_secret_fd};

const APPROVE_USAGE: &str = "envcloak approve <REQUEST> [--once | --for DURATION (30s to 24h)] [--live NAME]... \
     [--passphrase-fd N]";
const DENY_USAGE: &str = "envcloak deny <REQUEST>";

/// The parsed options of `approve`.
#[derive(Debug, PartialEq, Eq)]
struct ApproveArgs {
    request: PendingId,
    options: ApprovalOptions,
    passphrase_fd: Option<i32>,
}

/// `<n>s`, `<n>m` or `<n>h`, from 30 seconds to 24 hours.
fn parse_duration(s: &str) -> Option<Duration> {
    let (digits, unit) = s.split_at(s.len().checked_sub(1)?);
    if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    let secs = match unit {
        "s" => n,
        "m" => n.checked_mul(60)?,
        "h" => n.checked_mul(3600)?,
        _ => return None,
    };
    let d = Duration::from_secs(secs);
    (Duration::from_secs(30)..=MAX_AGENT_TTL)
        .contains(&d)
        .then_some(d)
}

fn parse(args: &[&str]) -> Option<ApproveArgs> {
    let (first, rest) = args.split_first()?;
    let request = PendingId::parse(first)?;
    let mut uses = None;
    let mut ttl = None;
    let mut live = Vec::new();
    let mut passphrase_fd = None;
    let mut it = rest.iter();
    while let Some(flag) = it.next() {
        match *flag {
            "--once" if uses.is_none() => uses = Some(Uses::Once),
            "--for" if uses.is_none() => {
                uses = Some(Uses::Session);
                ttl = Some(parse_duration(it.next()?)?);
            }
            "--live" => live.push(EnvName::new(it.next()?).ok()?),
            "--passphrase-fd" if passphrase_fd.is_none() => {
                passphrase_fd = Some(fd_number(it.next()?)?);
            }
            _ => return None,
        }
    }
    live.sort();
    live.dedup();
    Some(ApproveArgs {
        request,
        options: ApprovalOptions {
            uses: uses.unwrap_or(Uses::Session),
            ttl_secs: ttl.unwrap_or(DEFAULT_TTL).as_secs(),
            live,
        },
        passphrase_fd,
    })
}

pub fn approve(args: &[&str]) -> ExitCode {
    match parse(args) {
        Some(a) => run_approve(a).unwrap_or_else(|f| f.report(FAILURE)),
        None => usage(APPROVE_USAGE),
    }
}

fn run_approve(a: ApproveArgs) -> Result<ExitCode, Failure> {
    refuse_if_traced()?;
    let id = a.request.to_string();
    let descriptor = connect()?.pending_get(&id)?;
    // The statement is rendered from what the daemon sent, escaped, and
    // its digest is computed over exactly that (gate 23: a statement that
    // differs from the pending request is rejected by the daemon).
    let statement = render_statement(&descriptor, &a.options);
    let digest = statement_digest(&descriptor, &a.options);
    let passphrase = match a.passphrase_fd {
        Some(fd) => {
            print!("{statement}");
            read_secret_fd(fd)?
        }
        None => {
            let mut t = Terminal::open()?;
            t.say(&statement)?;
            t.read_secret("Vault passphrase to approve this: ")?
        }
    };
    let approved = connect()?.approve(&id, a.options.clone(), &digest, passphrase, &claims())?;
    let grant = GrantId::parse(&approved.grant)
        .ok_or_else(|| Failure::new("protocol_error", "the daemon's answer was malformed"))?;
    match a.options.uses {
        Uses::Once => println!("Approved request {id}: grant {grant}, for one request."),
        Uses::Session => println!(
            "Approved request {id}: grant {grant}, for {}.",
            words(approved.expires_in_secs)
        ),
    }
    Ok(ExitCode::SUCCESS)
}

/// A duration in words.
fn words(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, secs % 3600 / 60, secs % 60);
    let mut parts = Vec::new();
    if h > 0 {
        parts.push(format!("{h}h"));
    }
    if m > 0 {
        parts.push(format!("{m}m"));
    }
    if s > 0 || parts.is_empty() {
        parts.push(format!("{s}s"));
    }
    parts.join(" ")
}

pub fn deny(args: &[&str]) -> ExitCode {
    let id = match args {
        [id] => match PendingId::parse(id) {
            Some(id) => id,
            None => return usage(DENY_USAGE),
        },
        _ => return usage(DENY_USAGE),
    };
    run_deny(id).unwrap_or_else(|f| f.report(FAILURE))
}

fn run_deny(id: PendingId) -> Result<ExitCode, Failure> {
    let denied = connect()?.deny(&id.to_string())?;
    println!("Denied request {}.", escape_for_display(&id.to_string()));
    if denied.root_auto_denied {
        println!(
            "That process tree was denied three times in 10 minutes; it is denied for 30 minutes."
        );
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_and_options_parse_within_bounds() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("90m"), Some(Duration::from_secs(5400)));
        assert_eq!(parse_duration("24h"), Some(MAX_AGENT_TTL));
        for bad in ["", "h", "1", "29s", "25h", "1.5h", "8H", "-1h", "9999999h"] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
        let a = parse(&["ABCDEFGH"]).unwrap();
        assert_eq!(a.request, PendingId::parse("ABCDEFGH").unwrap());
        assert_eq!(a.options.uses, Uses::Session);
        assert_eq!(a.options.ttl_secs, DEFAULT_TTL.as_secs());
        assert!(a.options.live.is_empty());
        assert_eq!(a.passphrase_fd, None);
        let a = parse(&[
            "abcdefgh",
            "--for",
            "1h",
            "--live",
            "B",
            "--live",
            "A",
            "--live",
            "B",
            "--passphrase-fd",
            "3",
        ])
        .unwrap();
        assert_eq!(a.options.ttl_secs, 3600);
        assert_eq!(
            a.options.live,
            vec![EnvName::new("A").unwrap(), EnvName::new("B").unwrap()]
        );
        assert_eq!(a.passphrase_fd, Some(3));
        let a = parse(&["ABCDEFGH", "--once"]).unwrap();
        assert_eq!(a.options.uses, Uses::Once);
        for bad in [
            &[][..],
            &["ABCDEFG"],
            &["ABCDEFGH!"],
            &["ABCDEFGH", "--once", "--for", "1h"],
            &["ABCDEFGH", "--for"],
            &["ABCDEFGH", "--for", "1d"],
            &["ABCDEFGH", "--live", "not a name"],
            &["ABCDEFGH", "--passphrase-fd", "x"],
            &["ABCDEFGH", "--passphrase-fd", "3", "--passphrase-fd", "4"],
            &["ABCDEFGH", "extra"],
        ] {
            assert!(parse(bad).is_none(), "{bad:?}");
        }
        assert_eq!(words(3600), "1h");
        assert_eq!(words(90), "1m 30s");
    }
}
