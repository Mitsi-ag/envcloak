//! `envcloak mcp-bridge --stdio --launch <launch-id>`: the stdio client
//! bridge for a managed local MCP server (SPEC §6.4, §6.6; M2 plan D-04,
//! D-33, D-36; task M2-18).
//!
//! Creates `stdin`, `stdout`, `stderr` and `lifeline` pipes, hands the
//! server-side ends to `envcloakd` in `run.request` (`SCM_RIGHTS`), waits
//! for `DecisionView::Started` (never receiving any secret value), and
//! pumps its own standard input and output to and from the daemon-started
//! runner (`envcloak run --launch <id>`) while holding the lifeline open.

use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use envcloak_client::claims::claims;
use envcloak_client::fail::Failure;
use envcloak_ipc::proto::RunRequestParams;
use serde_json::Value;

use super::handoff::{BridgeSession, WaitBudget, connect_bridge};
use crate::rpc::{self, Id, PARSE_ERROR, PARSE_MESSAGE};
use crate::stdio::{Line, LineReader};

/// Configuration for `envcloak mcp-bridge --stdio --launch <id>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StdioBridgeConfig {
    /// The 26-character Crockford base32 launch id.
    pub launch_id: String,
    /// Optional explicit wait budget (`--wait`).
    pub wait: Option<WaitBudget>,
}

/// Runs the stdio bridge for `config`.
///
/// # Errors
/// Returns a [`Failure`] when the daemon refuses the launch, the request is
/// pending or denied, or the runner reports a pre-start failure.
pub fn run_stdio(config: &StdioBridgeConfig) -> Result<(), Failure> {
    let params = RunRequestParams {
        manifest: String::new(),
        profile: None,
        refs: Vec::new(),
        env_file: None,
        argv: vec![
            "mcp-bridge".to_owned(),
            "--stdio".to_owned(),
            "--launch".to_owned(),
            config.launch_id.clone(),
        ],
        claims: claims(),
        launch: Some(config.launch_id.clone()),
        bridge: None,
        fds: Vec::new(),
    };
    let session = connect_bridge(&params, true, config.wait)?;
    pump_stdio(session)
}

fn pump_stdio(session: BridgeSession) -> Result<(), Failure> {
    let BridgeSession {
        pipes,
        stdin_rx,
        queued_stdin,
        replayed_initialize,
        saw_initialized_notification: _,
    } = session;
    let mut to_child = pipes.to_child;
    let from_child = pipes.from_child;
    let from_errors = pipes.from_errors;
    let lifeline = pipes.lifeline;

    let mut child_reader = LineReader::new(from_child);

    // If `initialize` was answered locally while pending, replay it to the
    // started child server, absorb the child's `initialize` response, send
    // `notifications/initialized`, and notify the host with
    // `notifications/tools/list_changed`.
    if let Some(mut init_line) = replayed_initialize {
        init_line.push(b'\n');
        let _ = to_child.write_all(&init_line);
        let _ = to_child.flush();
        let _ = child_reader.next_line();
        let _ =
            to_child.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n");
        let _ = to_child.flush();
        let mut out = std::io::stdout().lock();
        let _ = out
            .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n");
        let _ = out.flush();
    }

    for mut queued in queued_stdin {
        queued.push(b'\n');
        let _ = to_child.write_all(&queued);
        let _ = to_child.flush();
    }

    // Forward stdin -> runner line by line (`MAX_LINE = 1 MiB`) in a background
    // thread; when stdin reaches EOF, dropping `to_child` closes the runner's
    // stdin.
    std::thread::spawn(move || {
        match stdin_rx {
            Some(rx) => {
                while let Ok(item) = rx.recv() {
                    match item {
                        Ok(Line::Message(mut bytes)) => {
                            bytes.push(b'\n');
                            if to_child.write_all(&bytes).is_err() || to_child.flush().is_err() {
                                break;
                            }
                        }
                        Ok(Line::Oversized) => {
                            let mut out = std::io::stdout().lock();
                            let _ = out.write_all(&rpc::error(None, PARSE_ERROR, PARSE_MESSAGE));
                            let _ = out.flush();
                        }
                        Ok(Line::End) | Err(_) => break,
                    }
                }
            }
            None => {
                let mut reader = LineReader::new(std::io::stdin());
                loop {
                    match reader.next_line() {
                        Ok(Line::Message(mut bytes)) => {
                            bytes.push(b'\n');
                            if to_child.write_all(&bytes).is_err() || to_child.flush().is_err() {
                                break;
                            }
                        }
                        Ok(Line::Oversized) => {
                            let mut out = std::io::stdout().lock();
                            let _ = out.write_all(&rpc::error(None, PARSE_ERROR, PARSE_MESSAGE));
                            let _ = out.flush();
                        }
                        Ok(Line::End) | Err(_) => break,
                    }
                }
            }
        }
        drop(to_child);
    });

    // Forward runner stderr -> our stderr, watching for a runner refusal line.
    let runner_failed = Arc::new(AtomicBool::new(false));
    let err_handle = from_errors.map(|err_file| {
        let flag = Arc::clone(&runner_failed);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(err_file);
            let mut line = Vec::new();
            let mut stderr = std::io::stderr();
            while let Ok(n) = reader.read_until(b'\n', &mut line) {
                if n == 0 {
                    break;
                }
                if is_runner_failure_line(&line) {
                    flag.store(true, Ordering::SeqCst);
                }
                let _ = stderr.write_all(&line);
                let _ = stderr.flush();
                line.clear();
            }
        })
    });

    // Forward runner stdout -> our stdout line by line on the main thread,
    // validating that each line is a single JSON-RPC 2.0 object within 1 MiB.
    let mut wrote_stdout = false;
    loop {
        match child_reader.next_line() {
            Ok(Line::Message(bytes)) => {
                wrote_stdout = true;
                let out_line = sanitize_stdio_child_line(&bytes);
                let mut out = std::io::stdout().lock();
                if out.write_all(&out_line).is_err() || out.flush().is_err() {
                    break;
                }
            }
            Ok(Line::Oversized) => {
                wrote_stdout = true;
                let mut out = std::io::stdout().lock();
                if out
                    .write_all(&rpc::error(None, PARSE_ERROR, PARSE_MESSAGE))
                    .is_err()
                    || out.flush().is_err()
                {
                    break;
                }
            }
            Ok(Line::End) | Err(_) => break,
        }
    }
    drop(child_reader);
    drop(lifeline);

    if let Some(h) = err_handle {
        let _ = h.join();
    }

    if !wrote_stdout && runner_failed.load(Ordering::SeqCst) {
        return Err(Failure::new("run_failed", ""));
    }
    Ok(())
}

/// Validates that `bytes` from a stdio child server is a valid UTF-8 JSON-RPC
/// 2.0 object, sanitizing any unsafe `"id"`, or returns a fixed protocol
/// parse error line if the child wrote garbage or a half-line.
fn sanitize_stdio_child_line(bytes: &[u8]) -> Vec<u8> {
    let Ok(mut v) = serde_json::from_slice::<Value>(bytes) else {
        return rpc::error(None, PARSE_ERROR, PARSE_MESSAGE);
    };
    let Some(obj) = v.as_object_mut() else {
        return rpc::error(None, PARSE_ERROR, PARSE_MESSAGE);
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || (!obj.contains_key("result")
            && !obj.contains_key("error")
            && !obj.contains_key("method"))
    {
        return rpc::error(None, PARSE_ERROR, PARSE_MESSAGE);
    }
    if let Some(id_val) = obj.get("id") {
        if !id_val.is_null() && Id::from_value(id_val).is_none() {
            obj.insert("id".to_owned(), Value::Null);
        }
    }
    let Ok(mut out) = serde_json::to_vec(&v) else {
        return rpc::error(None, PARSE_ERROR, PARSE_MESSAGE);
    };
    out.push(b'\n');
    out
}

fn is_runner_failure_line(line: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(line) else {
        return false;
    };
    let Some(rest) = s.strip_prefix("envcloak: ") else {
        return false;
    };
    !rest.starts_with("coverage:") && !rest.starts_with("warning:")
}
