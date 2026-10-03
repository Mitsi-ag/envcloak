//! `envcloak hook --host <claude-code|codex> --event
//! <UserPromptSubmit|PreToolUse|SessionStart>`: the handler the agent
//! hosts' prompt and tool-call hooks run (SPEC §7, §7.2 rule 3; M2 plan
//! M2-08, D-12). The installer writes it into each host's hook settings
//! with EnvCloak's absolute path.
//!
//! The host's payload is read from standard input into wiped storage, at
//! most 2 MiB, and answered within 2 seconds of the start: the deadline
//! covers the reading, the decision and `SessionStart`'s lookup alike
//! (the work runs on a thread of its own, and an answer not ready by the
//! deadline is `unchecked`, Codex review). What to answer is
//! `envcloak_agents::hook::decide`, a pure function of the payload:
//! registry key patterns and key shape for a prompt, what a command reads
//! or runs and file names for a tool call. Nothing is compared with the
//! vault, nothing is sent anywhere, and nothing it matched is echoed.
//!
//! - Allowed: no output, exit 0.
//! - Stopped: the host's JSON on standard output, the message (with
//!   EnvCloak's marker, `[envcloak:<reason>]`) on standard error, exit 2,
//!   which stops the prompt or the tool call on both hosts.
//! - A payload larger than 2 MiB, one that does not arrive in time, or one
//!   not decided in time: the prompt or the tool call is stopped
//!   (`unchecked`).
//! - A payload that is not the one `--host` and `--event` name: no
//!   decision, a value-free diagnostic and exit 1, which both hosts take
//!   as a hook error that stops nothing.
//! - A debugger or tracer attached to the handler: standard input is not
//!   read at all (a prompt can hold a key; SPEC §5, the Codex review), and
//!   the prompt or the tool call is stopped (`traced`); `SessionStart`
//!   adds nothing.
//! - `SessionStart`: when the session's directory has an `envcloak.toml`
//!   and the daemon answers within the 2 seconds, the names (never the
//!   values) of the variables it binds and the one-line usage rule, as
//!   added context; otherwise nothing.
//!
//! A usage error exits 1, never 2: a host reads 2 as "stop".

use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::path::Path;
use std::process::ExitCode;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use envcloak_agents::hook::{
    self, Decision, Event, Host, MAX_PAYLOAD, NO_DECISION, Reason, answer, payload_cwd,
    session_context,
};
use envcloak_client::fail::{Failure, refuse_if_traced};
use envcloak_core::SecretBuf;
use envcloak_policy::find_manifest;
use zeroize::Zeroizing;

const USAGE_TEXT: &str =
    "envcloak hook --host claude-code|codex --event UserPromptSubmit|PreToolUse|SessionStart";

/// The handler's own time limit, from its start.
const LIMIT: Duration = Duration::from_secs(2);

fn parse(args: &[&str]) -> Option<(Host, Event)> {
    match args {
        ["--host", h, "--event", e] | ["--event", e, "--host", h] => {
            Some((Host::from_id(h)?, Event::from_name(e)?))
        }
        _ => None,
    }
}

/// Why the payload was not read whole.
enum Unread {
    /// Over [`MAX_PAYLOAD`], or not all there by the deadline.
    Unchecked,
    /// Standard input could not be read.
    Failed,
}

/// Reads standard input, at most [`MAX_PAYLOAD`] bytes, until `deadline`.
fn read_payload(deadline: Instant) -> Result<SecretBuf, Unread> {
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    let mut buf = SecretBuf::with_capacity(64 * 1024);
    let mut chunk = Zeroizing::new(vec![0u8; 64 * 1024]);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Unread::Unchecked);
        }
        match envcloak_sys::wait_readable(lock.as_fd(), left) {
            Ok(true) => {}
            Ok(false) => return Err(Unread::Unchecked),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Unread::Failed),
        }
        let n = match lock.read(&mut chunk) {
            Ok(0) => return Ok(buf),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(Unread::Failed),
        };
        if buf.len() + n > MAX_PAYLOAD {
            return Err(Unread::Unchecked);
        }
        if buf.len() + n > buf.capacity() {
            buf.grow((buf.capacity() * 2).max(buf.len() + n).min(MAX_PAYLOAD));
        }
        if buf.extend(&chunk[..n]).is_err() {
            return Err(Unread::Failed);
        }
    }
}

fn emit(a: &hook::Answer) -> ExitCode {
    let _ = std::io::stdout().write_all(&a.stdout);
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().write_all(&a.stderr);
    ExitCode::from(a.code)
}

fn no_decision() -> ExitCode {
    Failure::new(
        "hook_payload",
        "the hook's input is not a payload this hook was set up for (another host or event, or \
         not JSON); no decision was made",
    )
    .report(NO_DECISION)
}

/// What the work on the payload came to.
enum Reply {
    /// The payload is not one this hook was set up for.
    NoDecision,
    /// Bytes for standard output and standard error, and the exit status.
    Answer(hook::Answer),
}

/// `work`, run on a thread of its own, if it is done by `deadline`. A
/// thread still running then is left to the process's exit, which follows
/// at once.
fn within<T: Send + 'static>(
    deadline: Instant,
    work: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(work());
    });
    rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .ok()
}

pub fn run(args: &[&str]) -> ExitCode {
    let start = Instant::now();
    let Some((host, event)) = parse(args) else {
        eprintln!("envcloak: usage: {USAGE_TEXT}");
        return ExitCode::from(NO_DECISION);
    };
    // Nothing is read under a tracer, the payload included: a prompt can
    // hold a pasted key (SPEC §5; the Codex review: the hook read it
    // first).
    if refuse_if_traced().is_err() {
        if event == Event::SessionStart {
            return ExitCode::SUCCESS;
        }
        return emit(&answer(host, event, Decision::Deny(Reason::Traced)));
    }
    let deadline = start + LIMIT;
    let payload = match read_payload(deadline) {
        Ok(p) => p,
        Err(Unread::Unchecked) if event != Event::SessionStart => {
            return emit(&answer(host, event, Decision::Deny(Reason::Unchecked)));
        }
        Err(Unread::Unchecked) => return ExitCode::SUCCESS,
        Err(Unread::Failed) => return no_decision(),
    };
    let work = move || {
        let decision = hook::decide(host, event, &payload);
        if decision == Decision::NoDecision {
            return Reply::NoDecision;
        }
        if event == Event::SessionStart {
            return Reply::Answer(session_start(host, &payload, deadline));
        }
        Reply::Answer(answer(host, event, decision))
    };
    match within(deadline, work) {
        Some(Reply::NoDecision) => no_decision(),
        Some(Reply::Answer(a)) => emit(&a),
        None if event == Event::SessionStart => ExitCode::SUCCESS,
        None => emit(&answer(host, event, Decision::Deny(Reason::Unchecked))),
    }
}

/// `SessionStart`: the project's bound names, when the daemon answers in
/// time; nothing otherwise.
fn session_start(host: Host, payload: &SecretBuf, deadline: Instant) -> hook::Answer {
    let nothing = hook::Answer {
        stdout: Vec::new(),
        stderr: Vec::new(),
        code: 0,
    };
    let Some(cwd) = payload_cwd(host, Event::SessionStart, payload) else {
        return nothing;
    };
    let Ok(Some(manifest)) = find_manifest(Path::new(&cwd)) else {
        return nothing;
    };
    let Some(text) = manifest.to_str().map(str::to_owned) else {
        return nothing;
    };
    let names = within(deadline, move || {
        let mut c = envcloak_client::connect::connect().ok()?;
        let check = c.items_check(Some(&text), &[]).ok()?;
        let mut names: Vec<String> = check
            .bindings
            .iter()
            .filter_map(|b| b.env_name.clone())
            .filter(|n| !envcloak_client::render::looks_like_value(n))
            .collect();
        names.sort();
        names.dedup();
        names.truncate(64);
        Some(names)
    });
    match names {
        Some(Some(names)) if !names.is_empty() => hook::Answer {
            stdout: session_context(host, &names),
            stderr: Vec::new(),
            code: 0,
        },
        _ => nothing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Codex review's finding: the 2 seconds cover the decision too,
    /// not only the reading. Work not done by the deadline gives no
    /// answer, at the deadline; work done in time gives its own.
    ///
    /// Mutation checked: `within` running the work on the calling thread
    /// and returning its result (the previous synchronous `decide`): the
    /// slow work's answer comes after 3 s and this fails.
    #[test]
    fn work_past_the_deadline_gives_no_answer_at_the_deadline() {
        let t = Instant::now();
        let deadline = t + Duration::from_millis(300);
        let slow = within(deadline, || {
            std::thread::sleep(Duration::from_secs(3));
            1
        });
        assert_eq!(slow, None);
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        let quick = within(Instant::now() + Duration::from_secs(5), || 2);
        assert_eq!(quick, Some(2));
    }

    #[test]
    fn arguments_are_read_exactly() {
        assert_eq!(
            parse(&["--host", "codex", "--event", "PreToolUse"]),
            Some((Host::Codex, Event::PreToolUse))
        );
        assert_eq!(
            parse(&["--event", "SessionStart", "--host", "claude-code"]),
            Some((Host::ClaudeCode, Event::SessionStart))
        );
        for bad in [
            &["--host", "cursor", "--event", "PreToolUse"][..],
            &["--host", "codex", "--event", "Stop"],
            &["--host", "codex"],
            &["--host", "codex", "--event", "PreToolUse", "x"],
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }
}
