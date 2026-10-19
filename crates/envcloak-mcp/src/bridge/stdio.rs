//! `envcloak mcp-bridge --stdio --launch <launch-id>`: the stdio client
//! bridge for a managed local MCP server (SPEC §6.4, §6.6; M2 plan D-04,
//! D-33, D-36; task M2-18).
//!
//! Creates `stdin`, `stdout`, `stderr` and `lifeline` pipes, hands the
//! server-side ends to `envcloakd` in `run.request` (`SCM_RIGHTS`), waits
//! for `DecisionView::Started` (never receiving any secret value), and
//! pumps its own standard input and output to and from the daemon-started
//! runner (`envcloak run --launch <id>`) while holding the lifeline open.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use envcloak_client::claims::claims;
use envcloak_client::fail::Failure;
use envcloak_ipc::proto::RunRequestParams;

use super::handoff::{StartedPipes, WaitBudget, request_pipes};

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
    let pipes = request_pipes(&params, true, config.wait)?;
    pump_stdio(pipes)
}

fn pump_stdio(pipes: StartedPipes) -> Result<(), Failure> {
    let StartedPipes {
        mut to_child,
        mut from_child,
        from_errors,
        lifeline,
    } = pipes;

    // Forward stdin -> runner in a background thread; when stdin reaches EOF,
    // dropping `to_child` closes the runner's stdin.
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 16 * 1024];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to_child.write_all(&buf[..n]).is_err() || to_child.flush().is_err() {
                        break;
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

    // Forward runner stdout -> our stdout on the main thread.
    let mut stdout = std::io::stdout().lock();
    let mut buf = [0u8; 16 * 1024];
    let mut wrote_stdout = false;
    loop {
        match from_child.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                wrote_stdout = true;
                if stdout.write_all(&buf[..n]).is_err() || stdout.flush().is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    drop(stdout);
    drop(from_child);
    drop(lifeline);

    if let Some(h) = err_handle {
        let _ = h.join();
    }

    if !wrote_stdout && runner_failed.load(Ordering::SeqCst) {
        return Err(Failure::new("run_failed", ""));
    }
    Ok(())
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
