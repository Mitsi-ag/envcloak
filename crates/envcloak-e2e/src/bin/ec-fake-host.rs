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
//!   key-shaped token; `"leak"` sends it;
//! - `persist`: `"allowed"` (the default) keeps each prompt it sent in
//!   `~/.claude/projects/fake/session.jsonl`; `"all"` keeps a blocked one
//!   too; `"none"` keeps nothing;
//! - `mention`: `"guarded"` (the default) expands `@<file>` mentions but
//!   `@.env`; `"all"` expands that too; `"none"` expands nothing;
//! - `tools`: what a call that reads `.env` or prints the environment
//!   gets: `"marker"` (the default) EnvCloak's denial marker; `"plain"` a
//!   denial without it; `"run"` the call is run;
//! - `control`: `"run"` (the default) runs a benign call; `"fail"` answers
//!   it with an error;
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

struct Mode {
    dead: bool,
    leak_prompt: bool,
    persist: String,
    mention: String,
    tools: String,
    control_fails: bool,
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
        leak_prompt: s("prompt", "block") == "leak",
        persist: s("persist", "allowed"),
        mention: s("mention", "guarded"),
        tools: s("tools", "marker"),
        control_fails: s("control", "run") == "fail",
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
    let transcript = home.join(".claude/projects/fake/session.jsonl");
    let keep = |text: &str| {
        let _ = std::fs::create_dir_all(transcript.parent().unwrap_or(&home));
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&transcript)
        {
            let _ = writeln!(f, "{}", json!({"prompt": text}));
        }
    };
    if key_shaped(&prompt) && !m.leak_prompt {
        if m.persist == "all" {
            keep(&prompt);
        }
        std::process::exit(m.exit);
    }
    if m.persist != "none" {
        keep(&prompt);
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
    ]
    .iter()
    .map(|n| json!({"name": n, "input_schema": {"type": "object"}}))
    .collect();
    let mut messages = vec![json!({"role": "user", "content": first})];
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
            let out = call(&m, name, &input);
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

/// What a tool call returns.
fn call(m: &Mode, name: &str, input: &Value) -> String {
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
            } else {
                control(&|| shell(&cmd))
            }
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
        "mcp__ecprobe__echo" => control(&|| format!("{}{}", s("text"), s("more"))),
        _ => "Error: no such tool".to_owned(),
    }
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
