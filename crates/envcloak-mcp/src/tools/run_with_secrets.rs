//! `run_with_secrets { project_dir, argv, profile? }`: runs a command with
//! the project's keys through a child `envcloak run` (SPEC §7, D-03), so
//! through the same approval, policy and redaction path as `envcloak run`
//! typed in a shell. This server never receives a value: the child asks
//! the daemon, receives the values, starts the command with them and
//! redacts its output before this server reads it.
//!
//! 1. The arguments are checked against the schema, and every string is
//!    refused, unechoed, when it is shaped like a key or token (gate 13),
//!    before anything is started or asked of the daemon.
//! 2. The child is `<this envcloak> run --wait <n>s --wait-grace <g>s
//!    [--profile p] -- <argv>`, in `project_dir`, with standard input from
//!    `/dev/null`, its output on pipes, leading a process group of its own
//!    ([`crate::child`]). The server's wait (`--wait-ms`, from the host's
//!    tool cutoff) holds both: `<n>` for the person's approval, polling
//!    without holding a connection, and `<g>` after it for the daemon's
//!    last answer (`envcloak_agents::tool_timeouts::person_wait` and
//!    `LAST_ANSWER_GRACE`), so the child gives up before the host does even
//!    when the daemon is slow to answer at the deadline.
//! 3. When the child stops at EnvCloak's own failure (exit 125 with
//!    nothing but `envcloak: <token>: ...` lines), the result is that
//!    outcome: `approval_required` names the request and says how the
//!    person approves it, from a terminal of their own (T-15); the child's
//!    own line, which names `envcloak approve`, is not passed on.
//!    Otherwise the command ran: the result is its exit code and its
//!    output, at most [`child::OUTPUT_HEAD`] bytes from the start and
//!    [`child::OUTPUT_TAIL`] from the end of each stream, with a marker
//!    naming how much was left out between them, and with every word a
//!    provider's key pattern matches masked here too
//!    (`Registry::mask_keys`), for keys the run does not bind. A word cut
//!    by the head's end, the tail's start or a stream left unread is
//!    dropped whole ([`shown_output`]): what is left of a key past a cut
//!    has no prefix for a pattern to match.
//! 4. A host's cancellation stops the child's group; the call then answers
//!    nothing (see [`crate::child`]).

use std::process::Command;

use envcloak_agents::tool_timeouts;
use envcloak_client::fail::Failure;
use envcloak_policy::{PendingId, ProfileName};
use serde_json::{Map, Value, json};

use super::{Ctx, check_keys, invalid, object, opt_str, project_dir, refuse_value_like, req_str};
use crate::child::{self, Call, Captured, HeadTail, NotRun};
use crate::router::{Annotations, Tool, ToolResult, ToolSchema};

/// The tool's name.
pub const TOOL: &str = "run_with_secrets";
/// The most arguments a command may have.
pub const MAX_ARGS: usize = 256;
/// The most bytes its arguments may hold in all.
pub const MAX_ARGV_BYTES: usize = 128 * 1024;
/// The longest message passed on from `envcloak run`'s own failure line.
const MAX_MESSAGE: usize = 1024;

#[derive(Debug)]
pub struct RunWithSecrets;

impl Tool for RunWithSecrets {
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: TOOL,
            title: "Run a command with the project's keys",
            description: "Runs a command with the keys the project's envcloak.toml names in its \
                 environment, through `envcloak run`: the same approval, policy and redaction as \
                 running `envcloak run -- <argv>` in a shell. In the command's output each key, \
                 and its common encodings, are masked; output the command transforms (part of a \
                 key, a re-encoding, compression or encryption) is not. A command needs the \
                 person's approval in EnvCloak, given from a terminal of their own; until then \
                 the result names the pending request, and the call can be made again once it is \
                 approved. The command runs outside this host's sandbox, and holds the injected \
                 keys in its environment and memory while it runs: what it does with them (files, \
                 network, its own child processes) is up to the command. argv runs without a \
                 shell; output is cut to its first and last 64 KiB per stream.",
            input: object(
                json!({
                    "project_dir": {
                        "type": "string",
                        "description": "Absolute path of the project directory: the command \
                             runs there, and its envcloak.toml (there or above) names the keys.",
                    },
                    "argv": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 1,
                        "maxItems": MAX_ARGS,
                        "description": "The command and its arguments, run without a shell. \
                             Never put a key here.",
                    },
                    "profile": {
                        "type": "string",
                        "description": "A profile of envcloak.toml ([env.<profile>]).",
                    },
                }),
                &["project_dir", "argv"],
            ),
            output: object(
                json!({
                    "status": {
                        "type": "string",
                        "enum": ["completed", "approval_required", "denied", "refused"],
                    },
                    "exit_code": {"type": ["integer", "null"]},
                    "signal": {"type": ["integer", "null"]},
                    "token": {"type": ["string", "null"]},
                    "request": {"type": ["string", "null"]},
                    "message": {"type": "string"},
                    "stdout": {"type": "string"},
                    "stderr": {"type": "string"},
                    "stdout_left_out": {"type": "integer"},
                    "stderr_left_out": {"type": "integer"},
                    "output_cut": {"type": "boolean"},
                }),
                &["status", "exit_code", "message"],
            ),
            annotations: Annotations {
                destructive: Some(true),
                open_world: Some(true),
                ..Annotations::default()
            },
        }
    }

    fn call(&self, args: &Map<String, Value>, ctx: &Ctx, call: &Call) -> ToolResult {
        match run(args, ctx, call) {
            Ok(v) => ToolResult::Ok(v),
            Err(f) => ToolResult::Err(f),
        }
    }
}

/// The arguments, checked.
struct Args<'a> {
    dir: std::path::PathBuf,
    argv: Vec<&'a str>,
    profile: Option<ProfileName>,
}

fn args(args: &Map<String, Value>) -> Result<Args<'_>, Failure> {
    check_keys(
        args,
        &["project_dir", "argv", "profile"],
        &["project_dir", "argv"],
    )?;
    let dir = req_str(args, "project_dir")?;
    let argv: Vec<&str> = match args.get("argv") {
        Some(Value::Array(a)) if (1..=MAX_ARGS).contains(&a.len()) => a
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<&str>>>()
            .ok_or_else(invalid)?,
        _ => return Err(invalid()),
    };
    if argv.iter().map(|a| a.len()).sum::<usize>() > MAX_ARGV_BYTES
        || argv.iter().any(|a| a.contains('\0'))
        || argv[0].is_empty()
    {
        return Err(invalid());
    }
    let profile = opt_str(args, "profile")?;
    // Values never on argv (gate 13): refused before anything is started
    // or asked of the daemon, and never echoed.
    let mut names = vec![dir];
    names.extend(argv.iter().copied());
    names.extend(profile);
    refuse_value_like(&names)?;
    let profile = profile
        .map(ProfileName::new)
        .transpose()
        .map_err(|_| Failure::new("invalid_profile_name", "the profile name is invalid"))?;
    Ok(Args {
        dir: project_dir(dir)?,
        argv,
        profile,
    })
}

fn run(a: &Map<String, Value>, ctx: &Ctx, call: &Call) -> Result<Value, Failure> {
    let a = args(a)?;
    let wait_secs = tool_timeouts::person_wait(ctx.wait).as_secs();
    let mut cmd = Command::new(&ctx.exe);
    cmd.arg("run")
        .arg("--wait")
        .arg(format!("{wait_secs}s"))
        .arg("--wait-grace")
        .arg(format!("{}s", tool_timeouts::LAST_ANSWER_GRACE.as_secs()));
    if let Some(p) = &a.profile {
        cmd.arg("--profile").arg(p.as_str());
    }
    cmd.arg("--").args(&a.argv).current_dir(&a.dir);
    let done = match child::run(cmd, call, None) {
        Ok(done) => done,
        Err(NotRun::Cancelled) => return Err(Failure::new("cancelled", "the call was cancelled")),
        Err(NotRun::Spawn) => {
            return Err(Failure::new(
                "run_failed",
                "`envcloak run` could not be started; nothing was run",
            ));
        }
    };
    Ok(outcome(&done, ctx, wait_secs))
}

/// `envcloak run`'s own failure, when that is how it stopped: its token
/// and message, from the last `envcloak: <token>: <message>` line.
fn own_failure(done: &Captured) -> Option<(String, String)> {
    if done.code != Some(125)
        || !done.stdout.head().is_empty()
        || done.stderr.left_out() > 0
        || done.cut
    {
        return None;
    }
    let mut text = done.stderr.head().to_vec();
    text.extend(done.stderr.tail());
    let text = std::str::from_utf8(&text).ok()?;
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    if lines.is_empty() || !lines.iter().all(|l| l.starts_with("envcloak: ")) {
        return None;
    }
    let last = lines.last()?.strip_prefix("envcloak: ")?;
    let (token, message) = last.split_once(": ")?;
    let token_shaped = !token.is_empty()
        && token
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    (token_shaped && token != "coverage").then(|| (token.to_owned(), message.to_owned()))
}

/// The request id in `approval_required`'s message: `request=<id>`.
fn request_of(message: &str) -> Option<PendingId> {
    let rest = message.split_once("request=")?.1;
    PendingId::parse(rest.get(..8)?)
}

/// What the call answers for `done`.
fn outcome(done: &Captured, ctx: &Ctx, wait_secs: u64) -> Value {
    if let Some((token, message)) = own_failure(done) {
        let mut v = json!({
            "status": "refused",
            "exit_code": done.code,
            "signal": Value::Null,
            "token": envcloak_client::render::shown(&token),
            "request": Value::Null,
        });
        match (token.as_str(), request_of(&message)) {
            ("approval_required", Some(id)) => {
                ctx.remember_pending(id);
                v["status"] = json!("approval_required");
                v["request"] = json!(id.to_string());
                v["message"] = json!(format!(
                    "Request {id} needs the person's approval in EnvCloak. Ask them to run \
                     `envcloak pending` and approve it from a terminal of their own; approvals \
                     from this session are refused. This call waited {wait_secs} s for it. Once \
                     it is approved, call run_with_secrets again with the same arguments. The \
                     command then runs outside this host's sandbox and holds the injected keys \
                     while it runs."
                ));
            }
            ("approval_denied", _) => {
                v["status"] = json!("denied");
                v["message"] = json!(passed_on(&message));
            }
            _ => v["message"] = json!(passed_on(&message)),
        }
        return v;
    }
    let (stdout, out_left) = shown_output(&done.stdout, done.cut);
    let (stderr, err_left) = shown_output(&done.stderr, done.cut);
    let message = match (done.code, done.signal) {
        (Some(c), _) => format!("The command ran through EnvCloak and exited with code {c}."),
        (None, Some(s)) => format!("The command ran through EnvCloak and was ended by signal {s}."),
        (None, None) => "The command ran through EnvCloak; its exit status is unknown.".to_owned(),
    };
    json!({
        "status": "completed",
        "exit_code": done.code,
        "signal": done.signal,
        "token": Value::Null,
        "request": Value::Null,
        "message": message,
        "stdout": stdout,
        "stderr": stderr,
        "stdout_left_out": out_left,
        "stderr_left_out": err_left,
        "output_cut": done.cut,
    })
}

/// `envcloak run`'s own message, as it may be passed on: bounded, and with
/// any key-shaped word masked.
fn passed_on(message: &str) -> String {
    let mut end = message.len().min(MAX_MESSAGE);
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    masked(&message[..end])
}

/// `text` with every word a provider's key pattern matches replaced.
fn masked(text: &str) -> String {
    match envcloak_client::render::registry() {
        Some(r) => r.mask_keys(text),
        None => text.to_owned(),
    }
}

/// Whether `b` can be part of a key: what `Registry::mask_keys` takes for
/// a word's byte at its widest.
fn key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+' | b'/' | b'=' | b'~')
}

/// A stream as the result shows it: whole when it was kept whole;
/// otherwise its head and its tail with a marker between them naming how
/// many bytes were left out. A word cut by the head's end or the tail's
/// start is dropped whole, however long (a run of bytes that could be part
/// of a key, [`key_byte`]), and so is the stream's last word when it was
/// left unread past there (`unread`, the output still open after the
/// command exited): what is left of a key past a cut has no prefix for a
/// pattern to match, so it is never shown. The masking then runs over the
/// whole text. Returns the text and the bytes left out, those dropped with
/// a cut word included.
pub fn shown_output(s: &HeadTail, unread: bool) -> (String, u64) {
    let head = s.head();
    let tail = s.tail();
    let (mut body, mut rest): (Vec<u8>, Vec<u8>) = if s.left_out() == 0 {
        let mut all = head.to_vec();
        all.extend_from_slice(&tail);
        (all, Vec::new())
    } else {
        (head.to_vec(), tail)
    };
    let mut left_out = s.left_out();
    if s.left_out() > 0 {
        let head_end = body.len() - trailing_word(&body);
        left_out += (body.len() - head_end) as u64;
        body.truncate(head_end);
        let tail_start = rest.iter().take_while(|b| key_byte(**b)).count();
        left_out += tail_start as u64;
        rest.drain(..tail_start);
    }
    if unread {
        let last = if s.left_out() > 0 {
            &mut rest
        } else {
            &mut body
        };
        let end = last.len() - trailing_word(last);
        left_out += (last.len() - end) as u64;
        last.truncate(end);
    }
    let mut text = if s.left_out() > 0 {
        format!(
            "{}\n[envcloak: {left_out} bytes of output left out here]\n{}",
            String::from_utf8_lossy(&body),
            String::from_utf8_lossy(&rest),
        )
    } else {
        String::from_utf8_lossy(&body).into_owned()
    };
    if unread {
        text.push_str("\n[envcloak: the output was not read past here]\n");
    }
    (masked(&text), left_out)
}

/// How many bytes at the end of `b` could be part of a key: its last word.
fn trailing_word(b: &[u8]) -> usize {
    b.iter().rev().take_while(|b| key_byte(**b)).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::child::{OUTPUT_HEAD, OUTPUT_TAIL};

    fn captured(code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> Captured {
        let mut out = HeadTail::default();
        out.push(stdout);
        let mut err = HeadTail::default();
        err.push(stderr);
        Captured {
            code,
            signal: None,
            stdout: out,
            stderr: err,
            timed_out: false,
            cut: false,
        }
    }

    fn ctx() -> Ctx {
        Ctx::new("/x".into(), None, std::time::Duration::from_secs(8))
    }

    #[test]
    fn envcloaks_own_outcomes_are_told_from_the_commands() {
        let id = PendingId::generate();
        let pending = format!(
            "envcloak: approval_required: request={id}: run \"envcloak approve {id}\" in a \
             terminal you control; waiting up to 8s for it\n"
        );
        let c = ctx();
        let v = outcome(&captured(Some(125), b"", pending.as_bytes()), &c, 8);
        assert_eq!(v["status"], "approval_required");
        assert_eq!(v["request"], id.to_string());
        let m = v["message"].as_str().unwrap();
        assert!(m.contains("envcloak pending") && m.contains("terminal of their own"));
        assert!(m.contains("outside this host's sandbox"));
        // The child's own line, which names `envcloak approve`, is not
        // passed on: nothing invites the agent to approve.
        assert!(!v.to_string().contains("envcloak approve"));
        assert_eq!(c.pending_seen().0, vec![id]);

        let denied =
            b"envcloak: approval_denied: request=ABCD1234 was denied; nothing was started\n";
        let v = outcome(&captured(Some(125), b"", denied), &c, 8);
        assert_eq!(v["status"], "denied");

        let locked = b"envcloak: vault_locked: the vault is locked\n";
        let v = outcome(&captured(Some(125), b"", locked), &c, 8);
        assert_eq!(v["status"], "refused");
        assert_eq!(v["token"], "vault_locked");

        // The command's own exit 125, with output of its own: completed.
        for (out, err) in [
            (&b"x\n"[..], &locked[..]),
            (b"", b"oops\nenvcloak: vault_locked: no\n"),
            (b"", b"envcloak: coverage: a/b is 8 to 15 bytes\n"),
        ] {
            let v = outcome(&captured(Some(125), out, err), &c, 8);
            assert_eq!(v["status"], "completed", "{err:?}");
            assert_eq!(v["exit_code"], 125);
        }
        let v = outcome(&captured(Some(0), b"hello\n", b""), &c, 8);
        assert_eq!(v["status"], "completed");
        assert_eq!(v["stdout"], "hello\n");
        assert_eq!(v["stdout_left_out"], 0);
    }

    /// Output past the caps keeps its ends, names what was left out, and
    /// never shows part of a key-shaped word at a cut: the cut moves to a
    /// byte that cannot be in one, and the masking sees whole words.
    #[test]
    fn long_output_keeps_its_ends_and_masks_whole_words() {
        let cs = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
        let key = envcloak_testkit::by_label(&cs, envcloak_testkit::labels::GITHUB_TOKEN).as_str();
        // A key straddling the head's end, and another the tail's start:
        // 10 of its bytes before the tail, the rest in it.
        let mut stream = vec![b' '; OUTPUT_HEAD - 10];
        stream.extend_from_slice(key.as_bytes());
        stream.extend(vec![b' '; 200_000]);
        let second = stream.len();
        stream.extend_from_slice(key.as_bytes());
        stream.extend(vec![b' '; OUTPUT_TAIL + 10 - key.len() - 1]);
        stream.push(b'\n');
        assert_eq!(stream.len() - OUTPUT_TAIL, second + 10);
        let mut h = HeadTail::default();
        h.push(&stream);
        let (text, left) = shown_output(&h, false);
        envcloak_testkit::assert_no_canary(text.as_bytes(), &cs);
        assert!(text.contains(&format!("[envcloak: {left} bytes of output left out here]")));
        assert!(left > h.left_out());
        // Nothing of either key's run is left beside the cuts.
        for piece in [&key[..10], &key[key.len() - 10..]] {
            assert!(!text.contains(piece), "a piece of a cut key shows");
        }
        // A key whole inside the output is masked by its pattern.
        let mut h = HeadTail::default();
        h.push(format!("token {key} end\n").as_bytes());
        let (text, left) = shown_output(&h, false);
        assert_eq!(left, 0);
        assert!(text.contains("[envcloak:key:github]"), "{text}");
        envcloak_testkit::assert_no_canary(text.as_bytes(), &cs);
    }

    /// `n` letters and digits from `seed`, none repeating a window.
    fn alnum(seed: u64, n: usize) -> String {
        const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x = x
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                char::from(ALNUM[usize::try_from((x >> 33) % 62).unwrap()])
            })
            .collect()
    }

    /// Whether any 16-byte piece of `token` shows in `text`.
    fn any_piece(text: &str, token: &str) -> bool {
        let shown: std::collections::HashSet<&[u8]> = text.as_bytes().windows(16).collect();
        token.as_bytes().windows(16).any(|w| shown.contains(w))
    }

    /// A key-shaped word of any length cut by the head's end, by the
    /// tail's start, or by the end of output left unread, is dropped whole:
    /// no piece of it shows, however far it runs past the cut (Codex's
    /// reproduction: a 1,068-byte remnant of a long provider token beside
    /// the head's cut).
    ///
    /// Mutation checked: each cut moved at most 1,024 bytes (the old
    /// bound): what is left of each 4,000-byte token past it shows, and
    /// this fails.
    #[test]
    fn a_long_word_at_a_cut_is_dropped_whole() {
        let cs = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
        let seed = envcloak_testkit::fresh_seed();
        let prefix = envcloak_testkit::by_label(&cs, envcloak_testkit::labels::OPENAI_API_KEY);
        let token = |i: u64| format!("{}{}", prefix.as_str(), alnum(seed ^ i, 4000));
        let (first, second, third) = (token(1), token(2), token(3));
        // The first crosses the head's end 1,000 bytes in; the second the
        // tail's start the same way.
        let mut stream = vec![b' '; OUTPUT_HEAD - 1000];
        stream.extend_from_slice(first.as_bytes());
        stream.extend(vec![b' '; 300_000]);
        let tail_start = stream.len() + 1000;
        stream.extend_from_slice(second.as_bytes());
        stream.extend(vec![b' '; tail_start + OUTPUT_TAIL - stream.len() - 1]);
        stream.push(b'\n');
        let mut h = HeadTail::default();
        h.push(&stream);
        assert_eq!(h.tail().len(), OUTPUT_TAIL);
        let (text, left) = shown_output(&h, false);
        assert!(
            !any_piece(&text, &first),
            "a piece of the first token shows"
        );
        assert!(
            !any_piece(&text, &second),
            "a piece of the second token shows"
        );
        assert!(text.contains(&format!("[envcloak: {left} bytes of output left out here]")));
        // The 1,000 bytes of the first in the head, and the rest of the
        // second in the tail, are left out with the middle.
        assert_eq!(left, h.left_out() + 1000 + (second.len() as u64 - 1000));
        envcloak_testkit::assert_no_canary(text.as_bytes(), &cs);

        // Output left unread after the command exited: its last word may
        // be cut, and is dropped whole; earlier words are kept.
        let mut h = HeadTail::default();
        h.push(format!("kept {third}").as_bytes());
        let (text, left) = shown_output(&h, true);
        assert!(!any_piece(&text, &third), "a piece of the last token shows");
        assert!(text.starts_with("kept "), "{text}");
        assert!(text.contains("[envcloak: the output was not read past here]"));
        assert_eq!(left, third.len() as u64);
        // Read to its end, the same output is whole.
        let (text, left) = shown_output(&h, false);
        assert_eq!(left, 0);
        assert!(!text.contains("not read past here"));
    }

    #[test]
    fn arguments_are_refused_before_anything_runs() {
        let cs = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
        let key = envcloak_testkit::by_label(&cs, envcloak_testkit::labels::OPENAI_API_KEY);
        let call = |v: Value| {
            let m = v.as_object().cloned().unwrap();
            args(&m).map(|_| ()).unwrap_err()
        };
        assert_eq!(
            call(json!({"project_dir": "/", "argv": []})).token,
            "invalid_params"
        );
        assert_eq!(
            call(json!({"project_dir": "/", "argv": [""]})).token,
            "invalid_params"
        );
        assert_eq!(
            call(json!({"project_dir": "/", "argv": [1]})).token,
            "invalid_params"
        );
        assert_eq!(
            call(json!({"project_dir": "/", "argv": "ls"})).token,
            "invalid_params"
        );
        assert_eq!(
            call(json!({"project_dir": "/", "argv": ["ls"], "extra": key.as_str()})).token,
            "invalid_params"
        );
        assert_eq!(call(json!({"argv": ["ls"]})).token, "invalid_params");
        assert_eq!(
            call(json!({"project_dir": "/", "argv": ["a\u{0}b"]})).token,
            "invalid_params"
        );
        let e = call(json!({"project_dir": "/", "argv": ["curl", "-H", key.as_str()]}));
        assert_eq!(e.token, "value_on_argv");
        envcloak_testkit::assert_no_canary(e.message.as_bytes(), &cs);
        let e = call(json!({"project_dir": "rel", "argv": ["ls"]}));
        assert_eq!(e.token, "invalid_path");
        let many: Vec<&str> = vec!["x"; MAX_ARGS + 1];
        assert_eq!(
            call(json!({"project_dir": "/", "argv": many})).token,
            "invalid_params"
        );
    }
}
