//! `envcloak approve <REQUEST> [--once | --for DURATION] [--live NAME]...
//! [--passphrase-fd N]` and `envcloak deny <REQUEST>` (SPEC §10b
//! "Approval proofs"; gates 23 and 31).
//!
//! `approve` is run by a person, in a terminal they control, after
//! `envcloak run` printed `approval_required request=<id>`:
//! 1. under a tracer it refuses at once (gate 19), and so it does when
//!    its environment holds an agent's markers (the daemon would refuse
//!    the proof);
//! 2. it fetches the pending request from a verified daemon, which serves
//!    it only to a caller that may give a proof (a terminal session with
//!    no agent in it, SPEC §10b), and renders
//!    the statement ([`render_statement_with`]): the caller, the project,
//!    the same provider's test items the daemon proposes in place of live
//!    ones with how to bind each (a name of one shaped like a key or token
//!    hidden), every binding with its classification and live tick, the
//!    full command line as an escaped list (cut past 2 KB with a marker),
//!    and the grant the options ask for;
//! 3. the live-key guard (SPEC §10b): when the request is an agent's or an
//!    unknown process's and the options leave a live binding unticked
//!    ([`unticked_live`]), it shows the statement, which names the
//!    `--live` flags it lacks and says that nothing is approved, and reads
//!    no passphrase (L-10). It sends the approval without one, as a check
//!    the daemon answers before any proof: the daemon refuses it
//!    `live_not_ticked` and audits the refusal (kind `live_refused`), as it
//!    does an approval with the passphrase, and the command exits with
//!    the daemon's refusal, naming the test keys the statement proposes
//!    for those bindings. Any other answer is the daemon's refusal, or, an
//!    answer that is not one, `protocol_error`: a check never approves;
//! 4. it reads the vault passphrase from `/dev/tty` with echo off, or from
//!    the descriptor `--passphrase-fd` names, never from argv or the
//!    environment;
//! 5. it sends the passphrase once, with the SHA-256 of the canonical
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

use envcloak_client::claims::refuse_if_claimed;
use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, refuse_if_traced, usage};
use envcloak_client::render::looks_like_value;
use envcloak_client::tty::{Terminal, read_secret_fd};
use envcloak_ipc::ClientError;
use envcloak_ipc::proto::{ErrorKind, PendingGetOutput};
use envcloak_policy::{
    ApprovalOptions, DEFAULT_TTL, EnvName, GrantId, MAX_AGENT_TTL, MAX_STANDING_TTL, PendingId,
    StandingId, Uses, escape_for_display, proposed_for, render_statement_with, statement_digest,
    unticked_live,
};
use envcloak_signin::{
    AuthorizationId, DEFAULT_DEV_ATTEMPTS, MAX_APPROVAL, MAX_DEV_ATTEMPTS, Options, RequestId,
    SignInDevOptions, SignInPendingDescriptor, render_signin_statement,
};

use super::fd_number;

const APPROVE_USAGE: &str = "envcloak approve <REQUEST> [--once | --for DURATION (30s to 24h) | \
     --standing [DURATION (30s to 30d)] | --dev DURATION [--attempts N]] [--live NAME]... \
     [--passphrase-fd N]";
const DENY_USAGE: &str = "envcloak deny <REQUEST>";
const DEFAULT_STANDING_TTL: Duration = Duration::from_secs(7 * 86_400);

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestSelector {
    Pending(PendingId),
    SignIn(RequestId),
}

impl RequestSelector {
    fn parse(s: &str) -> Option<Self> {
        if let Some(p) = PendingId::parse(s) {
            return Some(Self::Pending(p));
        }
        RequestId::parse(s).map(Self::SignIn)
    }

    fn id_string(&self) -> String {
        match self {
            Self::Pending(p) => p.to_string(),
            Self::SignIn(r) => r.to_string(),
        }
    }
}

/// The parsed options of `approve`.
#[derive(Debug, PartialEq, Eq)]
struct ApproveArgs {
    request: RequestSelector,
    options: ApprovalOptions,
    signin_dev: Option<(Duration, Option<u8>)>,
    has_run_options: bool,
    passphrase_fd: Option<i32>,
}

/// `<n>s`, `<n>m` or `<n>h`, from 30 seconds to 24 hours.
fn parse_duration(s: &str) -> Option<Duration> {
    // The unit is matched as a suffix, never split off at a byte offset: a
    // value ending in a multi-byte character fails like any other bad
    // input instead of panicking inside that character.
    let (digits, per_unit) = if let Some(d) = s.strip_suffix('s') {
        (d, 1)
    } else if let Some(d) = s.strip_suffix('m') {
        (d, 60)
    } else {
        (s.strip_suffix('h')?, 3600)
    };
    if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secs = digits.parse::<u64>().ok()?.checked_mul(per_unit)?;
    let d = Duration::from_secs(secs);
    (Duration::from_secs(30)..=MAX_AGENT_TTL)
        .contains(&d)
        .then_some(d)
}

/// `<n>s`, `<n>m` or `<n>h`, from 1 second to 24 hours (`MAX_APPROVAL`).
fn parse_signin_dev_duration(s: &str) -> Option<Duration> {
    let (digits, per_unit) = if let Some(d) = s.strip_suffix('s') {
        (d, 1)
    } else if let Some(d) = s.strip_suffix('m') {
        (d, 60)
    } else {
        (s.strip_suffix('h')?, 3600)
    };
    if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secs = digits.parse::<u64>().ok()?.checked_mul(per_unit)?;
    let d = Duration::from_secs(secs);
    (Duration::from_secs(1)..=MAX_APPROVAL)
        .contains(&d)
        .then_some(d)
}

/// `<n>s`, `<n>m`, `<n>h` or `<n>d`, from 30 seconds to 30 days.
fn parse_standing_duration(s: &str) -> Option<Duration> {
    let (digits, per_unit) = if let Some(d) = s.strip_suffix('s') {
        (d, 1)
    } else if let Some(d) = s.strip_suffix('m') {
        (d, 60)
    } else if let Some(d) = s.strip_suffix('h') {
        (d, 3600)
    } else {
        (s.strip_suffix('d')?, 86_400)
    };
    if digits.is_empty() || digits.len() > 7 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secs = digits.parse::<u64>().ok()?.checked_mul(per_unit)?;
    let d = Duration::from_secs(secs);
    (Duration::from_secs(30)..=MAX_STANDING_TTL)
        .contains(&d)
        .then_some(d)
}

fn parse_attempts(s: &str) -> Option<u8> {
    if s.is_empty() || s.len() > 3 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = s.parse::<u8>().ok()?;
    if n == 0 || n > MAX_DEV_ATTEMPTS {
        return None;
    }
    Some(n)
}

fn parse(args: &[&str]) -> Option<ApproveArgs> {
    let (first, rest) = args.split_first()?;
    let request = RequestSelector::parse(first)?;
    let mut uses = None;
    let mut ttl = None;
    let mut standing = None;
    let mut dev_window = None;
    let mut dev_attempts = None;
    let mut live = Vec::new();
    let mut passphrase_fd = None;
    let mut it = rest.iter().peekable();
    while let Some(flag) = it.next() {
        match *flag {
            "--once" if uses.is_none() && dev_window.is_none() => uses = Some(Uses::Once),
            "--for" if uses.is_none() && dev_window.is_none() => {
                uses = Some(Uses::Session);
                ttl = Some(parse_duration(it.next()?)?);
            }
            "--standing" if uses.is_none() && standing.is_none() && dev_window.is_none() => {
                uses = Some(Uses::Session);
                let d = match it.peek() {
                    Some(next) if !next.starts_with('-') => parse_standing_duration(it.next()?)?,
                    _ => DEFAULT_STANDING_TTL,
                };
                standing = Some(d);
            }
            "--dev" if uses.is_none() && standing.is_none() && dev_window.is_none() => {
                dev_window = Some(parse_signin_dev_duration(it.next()?)?);
            }
            "--attempts" if dev_attempts.is_none() => {
                dev_attempts = Some(parse_attempts(it.next()?)?);
            }
            "--live" => live.push(EnvName::new(it.next()?).ok()?),
            "--passphrase-fd" if passphrase_fd.is_none() => {
                passphrase_fd = Some(fd_number(it.next()?)?);
            }
            _ => return None,
        }
    }
    if dev_attempts.is_some() && dev_window.is_none() {
        return None;
    }
    if (standing.is_some() || dev_window.is_some()) && !live.is_empty() {
        return None;
    }
    live.sort();
    live.dedup();
    let signin_dev = dev_window.map(|w| (w, dev_attempts));
    let has_run_options = uses.is_some() || ttl.is_some() || standing.is_some() || !live.is_empty();
    Some(ApproveArgs {
        request,
        options: ApprovalOptions {
            uses: uses.unwrap_or(Uses::Session),
            ttl_secs: ttl.unwrap_or(DEFAULT_TTL).as_secs(),
            live,
            standing,
        },
        signin_dev,
        has_run_options,
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
    let claims = refuse_if_claimed()?;
    let id = a.request.id_string();
    // The daemon serves the request only to a caller that may give a
    // proof, so where none is taken this stops before the statement is
    // shown or the passphrase read.
    let descriptor = match connect()?.pending_get_any(&id, &claims)? {
        PendingGetOutput::Run(d) => {
            if a.signin_dev.is_some() {
                return Err(Failure::new(
                    ErrorKind::InvalidOptions.token(),
                    "--dev and --attempts apply only to a sign-in request",
                ));
            }
            d
        }
        PendingGetOutput::UnlockerAdd(u) => {
            if a.has_run_options || a.signin_dev.is_some() {
                return Err(Failure::new(
                    ErrorKind::InvalidOptions.token(),
                    "--once, --for, --dev and --live do not apply to an unlocker enrolment request",
                ));
            }
            return super::approve_unlocker::run(&id, u, a.passphrase_fd, &claims);
        }
        PendingGetOutput::SignIn(s) => {
            return run_approve_signin(&id, *s, &a, &claims);
        }
    };
    // The statement is rendered from what the daemon sent, escaped (a
    // proposed name shaped like a key hidden), and its digest is computed
    // over exactly that (gate 23: a statement that differs from the
    // pending request is rejected by the daemon).
    let statement = render_statement_with(&descriptor, &a.options, &looks_like_value);
    let digest = statement_digest(&descriptor, &a.options);
    // The live-key guard: the daemon would refuse this approval, so no
    // passphrase is read for it. The statement says which ticks it lacks
    // and which test items could be bound instead; the daemon is asked
    // without a passphrase, so that the refusal is its own, and audited.
    let unticked = unticked_live(&descriptor, &a.options);
    if !unticked.is_empty() {
        print!("{statement}");
        let refused = match connect()?.approve_check(&id, a.options.clone(), &digest, &claims) {
            Err(e) => Failure::from(e),
            // A check never grants: an answer that says otherwise is not
            // the daemon's to give.
            Ok(_) => Failure::new("protocol_error", "the daemon's answer was malformed"),
        };
        return Err(match proposed_for(&descriptor, &unticked) {
            Some(names) if refused.token() == ErrorKind::LiveNotTicked.token() => refused
                .with_tail(&format!(
                    "or bind the test key the statement proposes for {names}"
                )),
            _ => refused,
        });
    }
    if a.options.standing.is_some() {
        match connect()?.approve_check(&id, a.options.clone(), &digest, &claims) {
            Err(ClientError::Rpc(r)) if r.kind == ErrorKind::InvalidParams => {}
            Err(e) => {
                print!("{statement}");
                return Err(Failure::from(e));
            }
            Ok(_) => {
                print!("{statement}");
                return Err(Failure::new(
                    "protocol_error",
                    "the daemon's answer was malformed",
                ));
            }
        }
    }
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
    let approved = connect()?.approve(&id, a.options.clone(), &digest, passphrase, &claims)?;
    let grant = GrantId::parse(&approved.grant)
        .ok_or_else(|| Failure::new("protocol_error", "the daemon's answer was malformed"))?;
    if let Some(standing) = &approved.standing {
        let standing = StandingId::parse(standing)
            .ok_or_else(|| Failure::new("protocol_error", "the daemon's answer was malformed"))?;
        let standing_secs = approved
            .standing_expires_in_secs
            .unwrap_or_else(|| a.options.standing.unwrap_or_default().as_secs());
        println!(
            "Approved request {id}: standing approval {standing} (for {}), and grant {grant} \
             (for {}).",
            words(standing_secs),
            words(approved.expires_in_secs)
        );
        return Ok(ExitCode::SUCCESS);
    }
    match a.options.uses {
        Uses::Once => println!("Approved request {id}: grant {grant}, for one request."),
        Uses::Session => println!(
            "Approved request {id}: grant {grant}, for {}.",
            words(approved.expires_in_secs)
        ),
    }
    Ok(ExitCode::SUCCESS)
}

fn run_approve_signin(
    id: &str,
    descriptor: SignInPendingDescriptor,
    a: &ApproveArgs,
    claims: &[String],
) -> Result<ExitCode, Failure> {
    if (a.signin_dev.is_some() || (a.has_run_options && a.options.uses != Uses::Once))
        && descriptor.tier == "each"
    {
        return Err(Failure::new(
            "step_up_once_only",
            "step-up sign-in targets allow --once only; --for and --dev are not permitted",
        ));
    }
    if a.options.standing.is_some()
        || !a.options.live.is_empty()
        || (a.has_run_options && a.options.uses != Uses::Once)
    {
        return Err(Failure::new(
            ErrorKind::InvalidOptions.token(),
            "--for, --standing and --live do not apply to a sign-in request; use --once or --dev",
        ));
    }
    let opt_override = match a.signin_dev {
        Some((window, attempts_opt)) => {
            let attempts =
                attempts_opt.unwrap_or_else(|| DEFAULT_DEV_ATTEMPTS.min(descriptor.max_attempts));
            Some(Options::Dev { window, attempts })
        }
        None if a.has_run_options => Some(Options::Once),
        None => None,
    };
    let (statement, chosen_options, digest) = render_signin_statement(&descriptor, opt_override)
        .ok_or_else(|| Failure::new("protocol_error", "the daemon's answer was malformed"))?;
    let dev_params = match chosen_options {
        Options::Once => None,
        Options::Dev { window, attempts } => Some(SignInDevOptions {
            window_secs: window.as_secs(),
            attempts,
        }),
    };
    let wire_options = ApprovalOptions {
        uses: Uses::Once,
        ttl_secs: DEFAULT_TTL.as_secs(),
        live: Vec::new(),
        standing: None,
    };
    match connect()?.approve_check_with_dev(id, wire_options.clone(), dev_params, &digest, claims) {
        Err(ClientError::Rpc(r)) if r.kind == ErrorKind::InvalidParams => {}
        Err(e) => {
            print!("{statement}");
            return Err(Failure::from(e));
        }
        Ok(_) => {
            print!("{statement}");
            return Err(Failure::new(
                "protocol_error",
                "the daemon's answer was malformed",
            ));
        }
    }
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
    let approved =
        connect()?.approve_with_dev(id, wire_options, dev_params, &digest, passphrase, claims)?;
    let auth = AuthorizationId::parse(&approved.grant)
        .ok_or_else(|| Failure::new("protocol_error", "the daemon's answer was malformed"))?;
    match chosen_options {
        Options::Once => println!(
            "Approved sign-in request {id}: authorization {auth}, for one attempt (up to {}).",
            words(approved.expires_in_secs)
        ),
        Options::Dev { attempts, .. } => println!(
            "Approved sign-in request {id}: dev authorization {auth}, for {} ({attempts} attempts).",
            words(approved.expires_in_secs),
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
        [id] => match RequestSelector::parse(id) {
            Some(sel) => sel.id_string(),
            None => return usage(DENY_USAGE),
        },
        _ => return usage(DENY_USAGE),
    };
    run_deny(&id).unwrap_or_else(|f| f.report(FAILURE))
}

fn run_deny(id: &str) -> Result<ExitCode, Failure> {
    let denied = connect()?.deny(id)?;
    println!("Denied request {}.", escape_for_display(id));
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
        assert_eq!(
            parse_standing_duration("7d"),
            Some(Duration::from_secs(7 * 86_400))
        );
        assert_eq!(parse_standing_duration("30d"), Some(MAX_STANDING_TTL));
        assert_eq!(parse_standing_duration("31d"), None);
        for bad in [
            "",
            "h",
            "1",
            "29s",
            "25h",
            "1.5h",
            "8H",
            "-1h",
            "9999999h",
            // A multi-byte last character is refused, never split inside.
            "1\u{e9}",
            "1\u{20ac}",
            "1\u{1F600}",
            "1\u{ff48}",
            "\u{e9}",
        ] {
            assert_eq!(parse_duration(bad), None, "{bad}");
        }
        let a = parse(&["ABCDEFGH"]).unwrap();
        assert_eq!(
            a.request,
            RequestSelector::Pending(PendingId::parse("ABCDEFGH").unwrap())
        );
        assert_eq!(a.options.uses, Uses::Session);
        assert_eq!(a.options.ttl_secs, DEFAULT_TTL.as_secs());
        assert!(a.options.live.is_empty());
        assert_eq!(a.options.standing, None);
        assert_eq!(a.signin_dev, None);
        assert_eq!(a.passphrase_fd, None);
        let req32 = "0123456789abcdef0123456789abcdef";
        let a = parse(&[
            req32,
            "--dev",
            "4h",
            "--attempts",
            "5",
            "--passphrase-fd",
            "3",
        ])
        .unwrap();
        assert_eq!(
            a.request,
            RequestSelector::SignIn(RequestId::parse(req32).unwrap())
        );
        assert_eq!(a.signin_dev, Some((Duration::from_secs(4 * 3600), Some(5))));
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
        let a = parse(&["ABCDEFGH", "--standing"]).unwrap();
        assert_eq!(a.options.standing, Some(DEFAULT_STANDING_TTL));
        let a = parse(&["ABCDEFGH", "--standing", "14d", "--passphrase-fd", "3"]).unwrap();
        assert_eq!(a.options.standing, Some(Duration::from_secs(14 * 86_400)));
        assert_eq!(a.passphrase_fd, Some(3));
        for bad in [
            &[][..],
            &["ABCDEFG"],
            &["ABCDEFGH!"],
            &["ABCDEFGH", "--once", "--for", "1h"],
            &["ABCDEFGH", "--once", "--standing", "7d"],
            &["ABCDEFGH", "--for", "1h", "--standing", "7d"],
            &["ABCDEFGH", "--standing", "31d"],
            &["ABCDEFGH", "--standing", "7d", "--live", "A"],
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
