//! `ec-mcp-fixture`: a minimal stdio MCP server for measuring the agent
//! hosts (M2 plan task M2-04): how long a host waits for a tool call, and
//! what a server it starts sees of its environment and ancestry.
//!
//! One JSON-RPC message per line on standard input and output
//! (`initialize`, `notifications/initialized`, `ping`, `tools/list`,
//! `tools/call`); other requests are answered `-32601`. Two tools:
//!
//! - `wait {ms}`: answers after `ms` milliseconds (at most 600,000), with
//!   the text `waited <ms>`;
//! - `whoami {}`: the names of its environment variables (never their
//!   values) and the command names of its ancestors, from `ps`;
//! - `echo {text, more}`: the two joined (the coverage probe's control,
//!   M2-09: a marker sent in two pieces comes back whole only from a call
//!   that ran);
//! - `read_file {path}`: the file's first 64 KiB (the coverage probe's
//!   call that EnvCloak's hook must deny for `.env`).
//!
//! Test support only. It holds no value: the hosts start it with whatever
//! environment they give their servers, and it reports names.

use std::io::{BufRead, Write};
use std::process::Command;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use serde_json::{Value, json};

const VERSIONS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

fn main() {
    let out = Arc::new(Mutex::new(std::io::stdout()));
    let send = |out: &Arc<Mutex<std::io::Stdout>>, v: &Value| {
        let mut o = out.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = writeln!(o, "{v}");
        let _ = o.flush();
    };
    let stdin = std::io::stdin();
    let mut calls = Vec::new();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let id = msg.get("id").cloned();
        let method = msg["method"].as_str().unwrap_or("").to_owned();
        let Some(id) = id else {
            continue; // a notification
        };
        let reply = |result: Value| json!({"jsonrpc": "2.0", "id": id, "result": result});
        match method.as_str() {
            "initialize" => {
                let asked = msg["params"]["protocolVersion"].as_str().unwrap_or("");
                let version = if VERSIONS.contains(&asked) {
                    asked
                } else {
                    VERSIONS[0]
                };
                send(
                    &out,
                    &reply(json!({
                        "protocolVersion": version,
                        "capabilities": {"tools": {"listChanged": false}},
                        "serverInfo": {"name": "ec-mcp-fixture", "version": "1"},
                    })),
                );
            }
            "ping" => send(&out, &reply(json!({}))),
            "tools/list" => send(
                &out,
                &reply(json!({"tools": [
                    {"name": "wait", "description": "Waits, then answers.",
                     "inputSchema": {"type": "object",
                                     "properties": {"ms": {"type": "integer"}},
                                     "required": ["ms"], "additionalProperties": false}},
                    {"name": "whoami", "description": "Its environment's names and its ancestry.",
                     "inputSchema": {"type": "object", "properties": {},
                                     "additionalProperties": false}},
                    {"name": "echo", "description": "Answers its two texts joined.",
                     "inputSchema": {"type": "object",
                                     "properties": {"text": {"type": "string"},
                                                    "more": {"type": "string"}},
                                     "required": ["text"], "additionalProperties": false}},
                    {"name": "read_file", "description": "Answers a file's contents.",
                     "inputSchema": {"type": "object",
                                     "properties": {"path": {"type": "string"}},
                                     "required": ["path"], "additionalProperties": false}},
                ]})),
            ),
            "tools/call" => {
                let name = msg["params"]["name"].as_str().unwrap_or("").to_owned();
                let args = msg["params"]["arguments"].clone();
                let ms = args["ms"].as_u64().unwrap_or(0).min(600_000);
                let out = Arc::clone(&out);
                let id = id.clone();
                calls.push(std::thread::spawn(move || {
                    let text = match name.as_str() {
                        "wait" => {
                            std::thread::sleep(Duration::from_millis(ms));
                            format!("waited {ms}")
                        }
                        "whoami" => whoami(),
                        "echo" => format!(
                            "{}{}",
                            args["text"].as_str().unwrap_or(""),
                            args["more"].as_str().unwrap_or("")
                        ),
                        "read_file" => read_file(args["path"].as_str().unwrap_or("")),
                        _ => "no such tool".to_owned(),
                    };
                    let error = !matches!(name.as_str(), "wait" | "whoami" | "echo" | "read_file");
                    send(
                        &out,
                        &json!({"jsonrpc": "2.0", "id": id, "result": {
                            "content": [{"type": "text", "text": text}],
                            "isError": error,
                        }}),
                    );
                }));
            }
            _ => send(
                &out,
                &json!({"jsonrpc": "2.0", "id": id,
                        "error": {"code": -32601, "message": "method not found"}}),
            ),
        }
    }
    // Input ended: answer the calls still running, then exit.
    for call in calls {
        let _ = call.join();
    }
}

/// The first 64 KiB of the file at `path` (relative to the working
/// directory), as text, or a fixed line when it cannot be read.
fn read_file(path: &str) -> String {
    use std::io::Read as _;
    let mut out = Vec::new();
    match std::fs::File::open(path) {
        Ok(f) => {
            let _ = f.take(64 * 1024).read_to_end(&mut out);
            String::from_utf8_lossy(&out).into_owned()
        }
        Err(_) => "the file could not be read".to_owned(),
    }
}

/// `env=<names> ancestry=<comm> <- <comm> ...`, names only.
fn whoami() -> String {
    let mut names: Vec<String> = std::env::vars_os()
        .map(|(k, _)| k.to_string_lossy().into_owned())
        .collect();
    names.sort();
    let mut chain = Vec::new();
    let mut pid = std::process::id();
    for _ in 0..16 {
        let Ok(out) = Command::new("ps")
            .args(["-o", "ppid=,comm=", "-p", &pid.to_string()])
            .output()
        else {
            break;
        };
        let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        let mut parts = text.splitn(2, char::is_whitespace);
        let (Some(ppid), Some(comm)) = (parts.next(), parts.next()) else {
            break;
        };
        let comm = comm.trim();
        let base = comm.rsplit('/').next().unwrap_or(comm);
        chain.push(base.to_owned());
        match ppid.trim().parse::<u32>() {
            Ok(p) if p > 1 => pid = p,
            _ => break,
        }
    }
    format!("env={} ancestry={}", names.join(","), chain.join(" <- "))
}
