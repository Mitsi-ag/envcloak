//! `ec-fake-host`: a stand-in for Claude Code's `-p` mode, for the coverage
//! probes' own tests (M2 plan M2-09: "fake host binaries that fail each
//! probe or each control give the right state, reasons and outcome").
//!
//! It answers `--version` as the pinned Claude Code does, and with `-p
//! <prompt>` talks Anthropic Messages to `ANTHROPIC_BASE_URL` with
//! `ANTHROPIC_API_KEY`, as Claude Code does, offering `Bash`, `Read` and
//! the probe fixture's MCP tools, running each tool call the model asks
//! for and sending its result back, until the model ends its turn. What
//! it does where a real host's guard would act is set by
//! `$HOME/.ec-fake-host.json` (every field optional):
//!
//! - `url`: `"dead"` sends to a port nothing listens on (and then ends
//!   with `exit`, as a host that swallows the error would);
//! - `prompt`: `"block"` (the default) never sends a prompt holding a
//!   key-shaped token, and prints what Claude Code prints when EnvCloak's
//!   prompt hook blocks one (`UserPromptSubmit operation blocked by
//!   hook:` and the hook's reason, its marker first); `"leak"` sends it;
//!   `"drop"` sends nothing and prints nothing, as a run that ended for
//!   another reason; `"other"` prints another hook's block, without
//!   EnvCloak's marker;
//! - sessions as Claude Code keeps them: `--session-id <id>` starts the
//!   session `~/.claude/projects/fake/<id>.jsonl`, `--resume <id>` goes on
//!   with it, the prompts it sent before going to the model again with
//!   the new one (without either, `session.jsonl`); `session`: `"lost"`
//!   keeps every prompt in `session.jsonl` whatever the id; `resume`:
//!   `"fresh"` goes on with no earlier turn;
//! - `persist`: `"allowed"` (the default) keeps each prompt it sent in
//!   the session's file; `"all"` keeps a blocked one too; `"none"` keeps
//!   nothing; `"linked"` keeps a blocked one in a file outside the stores
//!   that a link in them leads to; `"moved"` keeps a blocked one where
//!   `CLAUDE_CODE_TMPDIR` places Claude Code's working-directory files (a
//!   store its environment moves);
//! - `unread`: `true` leaves a file in its store that a sweep cannot read
//!   whole: one past the sweep's cap per file (a sparse file, so nothing is
//!   written; a file of mode 0000 would not do, since a test run as root, as
//!   in CI's user namespace, reads it);
//! - `stray`: `true` also sends the model a request for a route it does
//!   not serve;
//! - `mention`: `"guarded"` (the default) expands `@<file>` mentions but
//!   `@.env`; `"all"` expands that too; `"none"` expands nothing;
//! - `tools`: what a call that reads `.env` or prints the environment
//!   gets: `"marker"` (the default) EnvCloak's denial marker; `"plain"` a
//!   denial without it; `"run"` the call is run;
//! - `control`: `"run"` (the default) runs a benign call; `"fail"` answers
//!   it with an error;
//! - `rule`: `"on"` (the default) refuses a `Read` of an env file within
//!   the working directory as Claude Code's `Read(**/.env*)` deny rule
//!   does, before any hook, with the host's own words; `"off"` leaves it
//!   to the hook;
//! - `sandbox`: what a `Bash` call does when `--settings` turns the
//!   sandbox on: `"deny"` (the default) lets a `touch` write within the
//!   working directory only; `"open"` lets it write anywhere; `"closed"`
//!   nowhere; `"dead"` runs nothing and answers as a sandbox that cannot
//!   start does (Claude Code's inside a user namespace);
//! - `server`: what EnvCloak's `run_with_secrets` does: `"outside"` (the
//!   default) runs its argv, outside any sandbox; `"inside"` refuses it;
//! - `exit`: the exit code once done (0 by default).
//!
//! Test support only: it holds nothing of value, and runs a command only
//! as the scripted model asks.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

/// The most bytes of one file a sweep reads
/// (`envcloak_agents::probe::controls::SWEEP_FILE_CAP`, whose test keeps
/// the two equal).
const SWEEP_FILE_CAP: u64 = 64 * 1024 * 1024;

struct Mode {
    dead: bool,
    prompt: String,
    session_lost: bool,
    resume_fresh: bool,
    unread: bool,
    stray: bool,
    persist: String,
    mention: String,
    tools: String,
    control_fails: bool,
    rule: bool,
    sandbox: String,
    server_outside: bool,
    exit: i32,
}

fn mode(home: &Path) -> Mode {
    let v: Value = std::fs::read(home.join(".ec-fake-host.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null);
    let s = |k: &str, d: &str| v.get(k).and_then(Value::as_str).unwrap_or(d).to_owned();
    Mode {
        dead: s("url", "ok") == "dead",
        prompt: s("prompt", "block"),
        session_lost: s("session", "kept") == "lost",
        resume_fresh: s("resume", "history") == "fresh",
        unread: v.get("unread").and_then(Value::as_bool) == Some(true),
        stray: v.get("stray").and_then(Value::as_bool) == Some(true),
        persist: s("persist", "allowed"),
        mention: s("mention", "guarded"),
        tools: s("tools", "marker"),
        control_fails: s("control", "run") == "fail",
        rule: s("rule", "on") == "on",
        sandbox: s("sandbox", "deny"),
        server_outside: s("server", "outside") == "outside",
        exit: v
            .get("exit")
            .and_then(Value::as_i64)
            .and_then(|e| i32::try_from(e).ok())
            .unwrap_or(0),
    }
}

/// A run of 24 or more letters and digits holding both: what the prompt
/// hook takes for a key.
fn key_shaped(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric()).any(|w| {
        w.len() >= 24
            && w.bytes().any(|b| b.is_ascii_digit())
            && w.bytes().any(|b| b.is_ascii_alphabetic())
    })
}

fn env_file(path: &str) -> bool {
    Path::new(path)
        .file_name()
        .is_some_and(|n| n.to_string_lossy().starts_with(".env"))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--version"] {
        println!("2.1.280 (Claude Code)");
        return;
    }
    let Some(i) = args.iter().position(|a| a == "-p") else {
        std::process::exit(2);
    };
    let Some(prompt) = args.get(i + 1).cloned() else {
        std::process::exit(2);
    };
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    let m = mode(&home);
    // The Bash sandbox, as `--settings` turns it on.
    let sandboxed = args
        .iter()
        .position(|a| a == "--settings")
        .and_then(|i| args.get(i + 1))
        .and_then(|t| serde_json::from_str::<Value>(t).ok())
        .is_some_and(|v| v["sandbox"]["enabled"] == json!(true));
    let flag = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let resumed = flag("--resume");
    let id = resumed.clone().or_else(|| flag("--session-id"));
    let store = home.join(".claude/projects/fake");
    let transcript = match id.filter(|_| !m.session_lost) {
        Some(id) => store.join(format!("{id}.jsonl")),
        None => store.join("session.jsonl"),
    };
    let _ = std::fs::create_dir_all(&store);
    if m.unread {
        if let Ok(f) = std::fs::File::create(store.join("large.jsonl")) {
            let _ = f.set_len(SWEEP_FILE_CAP + 1);
        }
    }
    let keep = |file: &Path, text: &str, blocked: bool| {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(file)
        {
            let _ = writeln!(f, "{}", json!({"prompt": text, "blocked": blocked}));
        }
    };
    // The prompts the session sent before, which go to the model again.
    let earlier: Vec<String> = if resumed.is_some() && !m.resume_fresh {
        std::fs::read_to_string(&transcript)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["blocked"] != json!(true))
            .filter_map(|v| v["prompt"].as_str().map(str::to_owned))
            .collect()
    } else {
        Vec::new()
    };
    if key_shaped(&prompt) && m.prompt != "leak" {
        match m.persist.as_str() {
            "all" => keep(&transcript, &prompt, true),
            "moved" => {
                // Where the environment moves a store: a working-directory
                // file in `CLAUDE_CODE_TMPDIR`, as Claude Code's Bash tool
                // leaves them.
                if let Some(tmp) = std::env::var_os("CLAUDE_CODE_TMPDIR") {
                    let dir = PathBuf::from(tmp);
                    let _ = std::fs::create_dir_all(&dir);
                    keep(&dir.join("claude-fake-cwd"), &prompt, true);
                }
            }
            "linked" => {
                // Kept outside the stores, behind a link in them.
                let outside = home.join("elsewhere");
                let _ = std::fs::create_dir_all(&outside);
                keep(&outside.join("kept.jsonl"), &prompt, true);
                let _ = std::os::unix::fs::symlink(
                    outside.join("kept.jsonl"),
                    store.join("linked.jsonl"),
                );
            }
            _ => {}
        }
        match m.prompt.as_str() {
            "drop" => {}
            "other" => println!("UserPromptSubmit operation blocked by hook:\nNot today."),
            _ => println!(
                "UserPromptSubmit operation blocked by hook:\n[envcloak:key_in_prompt] EnvCloak \
                 stopped this prompt before it reached the model."
            ),
        }
        std::process::exit(m.exit);
    }
    if m.persist != "none" {
        keep(&transcript, &prompt, false);
    }
    let mut first = prompt.clone();
    if m.mention != "none" {
        for word in prompt.split_whitespace() {
            if let Some(file) = word.strip_prefix('@') {
                if env_file(file) && m.mention != "all" {
                    continue;
                }
                if let Ok(t) = std::fs::read_to_string(file) {
                    first.push_str(&format!("\n<file {file}>\n{t}\n</file>"));
                }
            }
        }
    }
    let base = if m.dead {
        "http://127.0.0.1:1".to_owned()
    } else {
        std::env::var("ANTHROPIC_BASE_URL").unwrap_or_default()
    };
    let key = std::env::var("ANTHROPIC_API_KEY").unwrap_or_default();
    let tools: Vec<Value> = [
        "Bash",
        "Read",
        "mcp__ecprobe__echo",
        "mcp__ecprobe__read_file",
        "mcp__envcloak__run_with_secrets",
    ]
    .iter()
    .map(|n| json!({"name": n, "input_schema": {"type": "object"}}))
    .collect();
    let mut messages: Vec<Value> = Vec::new();
    for text in earlier {
        messages.push(json!({"role": "user", "content": text}));
        messages.push(json!({"role": "assistant", "content": [{"type": "text", "text": "done"}]}));
    }
    messages.push(json!({"role": "user", "content": first}));
    if m.stray {
        stray(&base, &key);
    }
    for _ in 0..16 {
        let body = json!({
            "model": "fake", "max_tokens": 64, "stream": false,
            "messages": messages, "tools": tools,
        });
        // A host that cannot reach its model ends as `exit` says (0 by
        // default, as a host that swallows the error would): only the
        // probe's control can tell.
        let Some(reply) = post(&base, &key, &body) else {
            std::process::exit(m.exit);
        };
        let content = reply
            .get("content")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        messages.push(json!({"role": "assistant", "content": content}));
        let calls: Vec<&Value> = content
            .iter()
            .filter(|c| c.get("type").and_then(Value::as_str) == Some("tool_use"))
            .collect();
        if calls.is_empty() {
            std::process::exit(m.exit);
        }
        let mut results = Vec::new();
        for c in calls {
            let name = c.get("name").and_then(Value::as_str).unwrap_or("");
            let input = c.get("input").cloned().unwrap_or(Value::Null);
            let out = call(&m, sandboxed, name, &input);
            results.push(json!({
                "type": "tool_result",
                "tool_use_id": c.get("id").cloned().unwrap_or(Value::Null),
                "content": out,
            }));
        }
        messages.push(json!({"role": "user", "content": results}));
    }
    std::process::exit(m.exit);
}

/// Whether `path` is within the working directory, both resolved.
fn within_cwd(path: &str) -> bool {
    let (Ok(p), Ok(cwd)) = (
        std::fs::canonicalize(path),
        std::env::current_dir().and_then(std::fs::canonicalize),
    ) else {
        return false;
    };
    p.starts_with(cwd)
}

/// A `Bash` call in the sandbox `m.sandbox` says: each `;`-separated
/// command run in turn, a `touch` written only where the sandbox lets it.
fn sandboxed_shell(m: &Mode, cmd: &str) -> String {
    if m.sandbox == "dead" {
        return "apply-seccomp: write /proc/self/uid_map: Operation not permitted".to_owned();
    }
    let mut out = String::new();
    for part in cmd.split(';') {
        let words: Vec<String> = part
            .split_whitespace()
            .map(|w| w.trim_matches('\'').to_owned())
            .collect();
        if words.first().map(String::as_str) == Some("touch") {
            for target in &words[1..] {
                let parent = Path::new(target)
                    .parent()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let lets = match m.sandbox.as_str() {
                    "open" => true,
                    "closed" => false,
                    _ => within_cwd(&parent),
                };
                if lets {
                    let _ = std::fs::write(target, b"");
                } else {
                    out.push_str(&format!("touch: {target}: Operation not permitted\n"));
                }
            }
            continue;
        }
        if let Ok(o) = Command::new("/bin/sh").args(["-c", part]).output() {
            out.push_str(&String::from_utf8_lossy(&o.stdout));
        }
    }
    out
}

/// What a tool call returns.
fn call(m: &Mode, sandboxed: bool, name: &str, input: &Value) -> String {
    let s = |k: &str| {
        input
            .get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    let guarded = |reason: &str, run: &dyn Fn() -> String| match m.tools.as_str() {
        "plain" => "Permission denied".to_owned(),
        "run" => run(),
        _ => format!("[envcloak:{reason}] EnvCloak's hook stopped this"),
    };
    let control = |run: &dyn Fn() -> String| {
        if m.control_fails {
            "Error: the tool failed".to_owned()
        } else {
            run()
        }
    };
    let shell = |cmd: &str| {
        Command::new("/bin/sh")
            .args(["-c", cmd])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    };
    let read = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    match name {
        "Bash" => {
            let cmd = s("command");
            if matches!(cmd.trim(), "printenv" | "env") {
                guarded("env_dump", &|| shell(&cmd))
            } else if sandboxed {
                control(&|| sandboxed_shell(m, &cmd))
            } else {
                control(&|| shell(&cmd))
            }
        }
        "Read" if m.rule && env_file(&s("file_path")) && within_cwd(&s("file_path")) => {
            format!(
                "Permission to read {} has been denied by your permission settings.",
                s("file_path")
            )
        }
        "Read" | "mcp__ecprobe__read_file" => {
            let p = if name == "Read" {
                s("file_path")
            } else {
                s("path")
            };
            if env_file(&p) {
                guarded("env_file", &|| read(&p))
            } else {
                control(&|| read(&p))
            }
        }
        "mcp__envcloak__run_with_secrets" => {
            if !m.server_outside {
                return "Error: the server refused the call".to_owned();
            }
            let argv: Vec<String> = input
                .get("argv")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|w| w.as_str().map(str::to_owned))
                .collect();
            match argv.split_first() {
                Some((exe, rest)) => Command::new(exe)
                    .args(rest)
                    .status()
                    .map(|st| format!("exit {}", st.code().unwrap_or(-1)))
                    .unwrap_or_else(|_| "Error: it did not start".to_owned()),
                None => "Error: no argv".to_owned(),
            }
        }
        "mcp__ecprobe__echo" => control(&|| format!("{}{}", s("text"), s("more"))),
        _ => "Error: no such tool".to_owned(),
    }
}

/// A request for a route the model does not serve.
fn stray(base: &str, key: &str) {
    let Some(addr) = base
        .strip_prefix("http://")
        .map(|a| a.trim_end_matches('/'))
    else {
        return;
    };
    let Ok(mut s) = TcpStream::connect(addr) else {
        return;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = s.write_all(
        format!(
            "GET /v1/elsewhere HTTP/1.1\r\nHost: {addr}\r\nx-api-key: {key}\r\nconnection: \
             close\r\n\r\n"
        )
        .as_bytes(),
    );
    let mut sink = Vec::new();
    let _ = s.read_to_end(&mut sink);
}

/// One Messages request; the reply's JSON, or `None` when nothing
/// answered 200.
fn post(base: &str, key: &str, body: &Value) -> Option<Value> {
    let addr = base.strip_prefix("http://")?.trim_end_matches('/');
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(60))).ok()?;
    let bytes = body.to_string();
    let head = format!(
        "POST /v1/messages HTTP/1.1\r\nHost: {addr}\r\nx-api-key: {key}\r\n\
         anthropic-version: 2023-06-01\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n",
        bytes.len()
    );
    s.write_all(head.as_bytes()).ok()?;
    s.write_all(bytes.as_bytes()).ok()?;
    // The head, then exactly the body its `content-length` names: the
    // server may keep the connection open.
    let mut reply = Vec::new();
    let mut buf = [0u8; 8192];
    let split = loop {
        if let Some(i) = reply.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        let n = s.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        reply.extend_from_slice(&buf[..n]);
    };
    let head = std::str::from_utf8(&reply[..split]).ok()?.to_owned();
    if head.split_whitespace().nth(1) != Some("200") {
        return None;
    }
    let len: usize = head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case("content-length")
            .then(|| v.trim().parse().ok())
            .flatten()
    })?;
    let mut body = reply[split + 4..].to_vec();
    while body.len() < len {
        let n = s.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&buf[..n]);
    }
    body.truncate(len);
    serde_json::from_slice(&body).ok()
}
