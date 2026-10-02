//! `envcloak mcp [--host ID] [--wait-ms N]`: EnvCloak's MCP server, which
//! an agent host starts and talks to over standard input and output (SPEC
//! §7; M2 plan task M2-06). The server is `envcloak_mcp`'s; this module
//! reads its options and runs it.
//!
//! - `--host` names the host that starts it (`claude-code`, `codex`, as the
//!   installer writes it). It sets how long a tool waits for the person's
//!   approval before it answers with the pending request: the host's tool
//!   cutoff as the installer sets it, less 2 seconds, from 1 to 20 seconds
//!   (`envcloak_agents::tool_timeouts`); 8 seconds for any other host or
//!   none, below the 10-second cutoff a host without a per-server timeout
//!   may have.
//! - `--wait-ms` sets that wait itself, from 1,000 to 20,000 milliseconds;
//!   `envcloak run`'s wait is whole seconds, so it is rounded down.
//!
//! The process is hardened and its panics show their place only, as every
//! command's are (`main`). `SIGTERM`, `SIGINT` and `SIGHUP` are taken by one
//! thread, blocked in every other before any starts: the calls in hand are
//! stopped first (each child's process group, while the child is
//! unreaped), then the process ends as the signal asks. No option is ever
//! echoed: a usage error names the rule, never the argument.

use std::process::ExitCode;
use std::time::Duration;

use envcloak_agents::tool_timeouts::{self, MAX_WAIT, MIN_WAIT};
use envcloak_client::fail::{FAILURE, Failure, usage};

const USAGE_TEXT: &str = "envcloak mcp [--host ID] [--wait-ms 1000..20000]
       started by an agent host, which talks to it on standard input and output";

/// The parsed command line.
#[derive(Debug, PartialEq, Eq)]
struct McpArgs {
    host: Option<String>,
    wait: Duration,
}

/// Whether `id` can name a host: 1 to 32 lowercase letters, digits and
/// `-`, starting with a letter.
fn host_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// `--wait-ms`: digits only, within [`MIN_WAIT`] and [`MAX_WAIT`].
fn wait_ms(v: &str) -> Option<Duration> {
    if v.is_empty() || v.len() > 6 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let d = Duration::from_millis(v.parse().ok()?);
    (MIN_WAIT..=MAX_WAIT).contains(&d).then_some(d)
}

fn parse(args: &[&str]) -> Result<McpArgs, &'static str> {
    let mut host = None;
    let mut wait = None;
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--host" if host.is_none() => {
                let id = *it.next().ok_or("--host needs a host id")?;
                if !host_id(id) {
                    return Err("--host needs a host id: lowercase letters, digits and -");
                }
                host = Some(id.to_owned());
            }
            "--wait-ms" if wait.is_none() => {
                let v = *it
                    .next()
                    .ok_or("--wait-ms needs a number of milliseconds")?;
                wait = Some(wait_ms(v).ok_or("--wait-ms takes 1000 to 20000 milliseconds")?);
            }
            _ => return Err("unknown or repeated option"),
        }
    }
    let wait = wait.unwrap_or_else(|| tool_timeouts::default_wait(host.as_deref()));
    Ok(McpArgs { host, wait })
}

pub fn run(args: &[&str]) -> ExitCode {
    if args == ["--help"] || args == ["-h"] {
        println!("usage: {USAGE_TEXT}");
        return ExitCode::SUCCESS;
    }
    let a = match parse(args) {
        Ok(a) => a,
        Err(why) => {
            eprintln!("envcloak: {why}");
            return usage(USAGE_TEXT);
        }
    };
    serve(a).unwrap_or_else(|f| f.report(FAILURE))
}

fn serve(a: McpArgs) -> Result<ExitCode, Failure> {
    // Before any thread starts, so every thread inherits the mask and the
    // signals wait for the one that takes them.
    let signals = envcloak_sys::TerminationSignals::block().map_err(|_| {
        Failure::new(
            "signals",
            "the termination signals could not be set up; the server did not start",
        )
    })?;
    // The children run this same executable, by its absolute path (D-03).
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok())
        .filter(|p| p.is_absolute())
        .ok_or_else(|| {
            Failure::new(
                "run_failed",
                "this program's own path could not be found; the server did not start",
            )
        })?;
    let server = envcloak_mcp::Server::new();
    let shutdown = server.shutdown();
    std::thread::spawn(move || {
        if let Ok(sig) = signals.wait() {
            shutdown.stop();
            envcloak_sys::exit_by_signal(sig);
        }
    });
    let ctx = envcloak_mcp::Ctx::new(exe, a.host, a.wait);
    match server.run(std::io::stdin().lock(), std::io::stdout(), ctx) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(_) => Err(Failure::new(
            "io",
            "standard input could not be read; the calls in hand were stopped",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_are_a_host_and_a_wait() {
        let secs = Duration::from_secs;
        assert_eq!(
            parse(&[]).unwrap(),
            McpArgs {
                host: None,
                wait: secs(8)
            }
        );
        assert_eq!(parse(&["--host", "claude-code"]).unwrap().wait, secs(20));
        assert_eq!(parse(&["--host", "codex"]).unwrap().wait, secs(20));
        assert_eq!(parse(&["--host", "gemini-cli"]).unwrap().wait, secs(8));
        assert_eq!(
            parse(&["--host", "codex", "--wait-ms", "1500"]).unwrap(),
            McpArgs {
                host: Some("codex".into()),
                wait: Duration::from_millis(1500)
            }
        );
        assert_eq!(parse(&["--wait-ms", "1000"]).unwrap().wait, secs(1));
        assert_eq!(parse(&["--wait-ms", "20000"]).unwrap().wait, secs(20));
        for bad in [
            &["--host"][..],
            &["--host", ""],
            &["--host", "Claude"],
            &["--host", "-x"],
            &["--host", "a b"],
            &["--host", "codex", "--host", "codex"],
            &["--wait-ms"],
            &["--wait-ms", "999"],
            &["--wait-ms", "20001"],
            &["--wait-ms", "8s"],
            &["--wait-ms", "-1"],
            &["--wait-ms", "1000", "--wait-ms", "1000"],
            &["--bogus"],
            &["serve"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
