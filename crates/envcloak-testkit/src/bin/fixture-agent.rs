//! A stand-in AI coding agent for tests: the acceptance story's agent
//! (SPEC §15.1) and the evidence gates 25 and 26. The builtin agent catalog
//! (integrations/agents.toml) knows it by its file name, `fixture-agent`,
//! as it knows Claude Code and Codex by theirs.
//!
//! Usage: `fixture-agent [--marker] [--] <program> [args...]`
//!
//! It runs the program as its child, the way an agent runs a tool command:
//! the same standard streams, the environment it was given (plus
//! `ENVCLOAK_FIXTURE_AGENT=1` with `--marker`, as real agents mark their
//! commands), and it exits with the child's status (128 plus the signal
//! when the child was killed). It never `exec`s, so it stays in its
//! child's ancestry, and it neither starts a session nor reads a terminal.

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1).peekable();
    let mut marker = false;
    while let Some(a) = args.peek() {
        if a == "--marker" {
            marker = true;
            args.next();
        } else if a == "--" {
            args.next();
            break;
        } else {
            break;
        }
    }
    let Some(program) = args.next() else {
        eprintln!("usage: fixture-agent [--marker] [--] <program> [args...]");
        return ExitCode::from(2);
    };
    let mut cmd = Command::new(program);
    cmd.args(args);
    if marker {
        cmd.env("ENVCLOAK_FIXTURE_AGENT", "1");
    }
    match cmd.status() {
        Ok(status) => {
            let code = status
                .code()
                .or_else(|| status.signal().map(|s| 128 + s))
                .unwrap_or(1);
            ExitCode::from(u8::try_from(code).unwrap_or(1))
        }
        Err(e) => {
            eprintln!("fixture-agent: cannot run the program: {}", e.kind());
            ExitCode::from(127)
        }
    }
}
