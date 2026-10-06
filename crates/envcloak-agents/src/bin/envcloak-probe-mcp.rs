//! `envcloak-probe-mcp`: the MCP server `envcloak agents status --probe`
//! registers with an agent host in its probe home, for the MCP surface's
//! probe (M2 plan M2-28). See `envcloak_agents::probe::mcp` for what it
//! serves.
//!
//! usage: envcloak-probe-mcp
//!
//! It reads JSON-RPC lines on standard input and answers on standard
//! output until its input ends; `read_file` reads only regular files in
//! its working directory.

use std::process::ExitCode;

const NAME: &str = "envcloak-probe-mcp";

fn main() -> ExitCode {
    envcloak_sys::harden_process();
    envcloak_sys::install_panic_hook(NAME);
    if std::env::args_os().len() > 1 {
        eprintln!("usage: {NAME}");
        return ExitCode::from(2);
    }
    let Ok(dir) = std::fs::File::open(".") else {
        eprintln!("{NAME}: the working directory could not be opened");
        return ExitCode::from(1);
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    match envcloak_agents::probe::mcp::serve(&mut stdin.lock(), &mut stdout.lock(), &dir) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}
