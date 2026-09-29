//! `envcloak`: the EnvCloak command-line client.
//!
//! Every run starts with process hardening (SPEC §5): core dumps off and, on
//! Linux, non-dumpable, before any argument or input is read. The CLI never
//! holds the vault key; it talks to `envcloakd` over a socket it verifies
//! first, and never starts a daemon itself (SPEC §4.1, §4.2).
//!
//! Commands in this build:
//! - `envcloak vault create`, `unlock`, `lock`, `status` and `daemon
//!   install` / `daemon uninstall` (see [`cmd`]);
//! - `envcloak run [--profile p] [--ref NAME=slug[#field]]... [--env-file
//!   f] -- <cmd...>` (SPEC §6.1), whose first step refuses to go on under
//!   a tracer, with exit 125 and `traced` (gate 19), before any contact
//!   with the daemon. It asks a verified daemon for the decision and, when
//!   a grant covers it, starts the command with the released values in its
//!   environment and its output redacted (`envcloak_exec`; docs/RUN.md);
//! - `envcloak approve`, `deny` and `grants list` / `grants revoke` (SPEC
//!   §10b);
//! - `envcloak audit verify`: the audit log's check (SPEC §15.2 gate 33);
//! - `envcloak add`, `ls`, `show`, `ref`, `check`, `rotate` and `rm`: the
//!   vault's items and the project's references, metadata only (SPEC §6.3,
//!   §7, §10b). Their output is `envcloak_ipc::view` types rendered by
//!   [`render`], as text or with `--json`; `rotate` and `rm` need the
//!   passphrase as a proof;
//! - `envcloak init`, `import --scan` and `recovery confirm`: env files
//!   imported into the vault with filesystem-safe scanning, and deleted
//!   only after the four conditions of SPEC §6.4 (see [`cmd::init`]).
//!
//! Every command that reads, shows or sends a secret or a proof (`vault
//! create`, `unlock`, `approve`, `run`, `add`, `rotate`, `rm`, `init`,
//! `import`, `recovery confirm`) refuses under a tracer first, before it
//! reads a file, a descriptor or the terminal.
//!
//! `envcloak internal hardening [--hold]` is a hidden, value-free diagnostic
//! used by the gate 19 tests: it prints `key=value` hardening lines and, with
//! `--hold`, prints `ready` and waits for stdin to close, so a test can
//! inspect the live process from outside.
//!
//! No argument is ever echoed: one could be a pasted secret. No command
//! takes a value as an argument (gate 13): values come from a hidden
//! prompt on `/dev/tty` or from standard input, and a name shaped like a
//! key or token is refused. An argument that is not valid UTF-8 is
//! refused as a usage error, before anything else, rather than changed:
//! the command line `run` sends for approval must be the one it was given.

mod cmd;
mod connect;
mod fail;
mod gitignore;
mod render;
mod tty;

use std::io::{Read, Write};
use std::process::ExitCode;

use fail::USAGE;

#[global_allocator]
static ALLOCATOR: envcloak_sys::WipingAllocator = envcloak_sys::WipingAllocator;

const HELP: &str = "usage:
  envcloak vault create [--passphrase-fd N] [--kit-fd N] [--kdf-memory SIZE]
  envcloak unlock [--passphrase-fd N]
  envcloak lock
  envcloak status [--json]
  envcloak daemon install [--daemon /absolute/path/to/envcloakd] [--no-start]
  envcloak daemon uninstall
  envcloak run [--profile NAME] [--ref NAME=slug[#field]]... [--env-file FILE] -- <cmd...>
  envcloak approve <REQUEST> [--once | --for DURATION] [--live NAME]... [--passphrase-fd N]
  envcloak deny <REQUEST>
  envcloak grants list [--json]
  envcloak grants revoke <GRANT> | --all
  envcloak audit verify [--json]
  envcloak add [PROVIDER] [--slug SLUG] [--field NAME] [--account ACCOUNT] [--env NAME] [--allow-short] [--stdin] [--json]
  envcloak ls [--long] [--json]
  envcloak show <slug> [--json]
  envcloak ref NAME=<slug>[#field] [--profile NAME] [--json]
  envcloak check [--json]
  envcloak rotate <slug>[#field] [--stdin] [--passphrase-fd N] [--json]
  envcloak rm <slug> [--passphrase-fd N] [--json]
  envcloak init [--import] [--yes] [--delete-plaintext] [--json]
  envcloak init --undo <ID> [--passphrase-fd N] [--json]
  envcloak import --scan <dir> [--yes] [--json]
  envcloak recovery confirm [--kit-fd N] [--json]
Values are never arguments: type them at the hidden prompt, or pipe them in with --stdin.";

fn main() -> ExitCode {
    envcloak_sys::harden_process();

    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    // An argument that is not UTF-8 is refused, never replaced: `run` sends
    // its command line for the approval statement, which must show every
    // argument as it is (SPEC §10a), and this build carries text only. The
    // argument is not echoed.
    let Some(args) = args
        .iter()
        .map(|a| a.to_str())
        .collect::<Option<Vec<&str>>>()
    else {
        eprintln!("envcloak: an argument is not valid UTF-8, which this build does not take");
        return ExitCode::from(USAGE);
    };
    match args.as_slice() {
        ["--version"] | ["-V"] => {
            println!("envcloak {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["--help"] | ["-h"] | ["help"] => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        ["internal", "hardening"] => internal_hardening(false),
        ["internal", "hardening", "--hold"] => internal_hardening(true),
        ["run", rest @ ..] => cmd::run::run(rest),
        ["vault", rest @ ..] => cmd::vault::run(rest),
        ["unlock", rest @ ..] => cmd::unlock::run(rest),
        ["lock", rest @ ..] => cmd::lock::run(rest),
        ["status", rest @ ..] => cmd::status::run(rest),
        ["daemon", rest @ ..] => cmd::daemon::run(rest),
        ["approve", rest @ ..] => cmd::approve::approve(rest),
        ["deny", rest @ ..] => cmd::approve::deny(rest),
        ["grants", rest @ ..] => cmd::grants::run(rest),
        ["audit", rest @ ..] => cmd::audit::run(rest),
        ["add", rest @ ..] => cmd::add::run(rest),
        ["ls", rest @ ..] => cmd::ls::run(rest),
        ["show", rest @ ..] => cmd::show::run(rest),
        ["ref", rest @ ..] => cmd::ref_::run(rest),
        ["check", rest @ ..] => cmd::check::run(rest),
        ["rotate", rest @ ..] => cmd::rotate::run(rest),
        ["rm", rest @ ..] => cmd::rm::run(rest),
        ["init", rest @ ..] => cmd::init::run(rest),
        ["import", rest @ ..] => cmd::import::run(rest),
        ["recovery", rest @ ..] => cmd::recovery::run(rest),
        // Never echo arguments: one of them could be a pasted secret.
        _ => {
            eprintln!("envcloak: unknown command\n{HELP}");
            ExitCode::from(USAGE)
        }
    }
}

fn internal_hardening(hold: bool) -> ExitCode {
    let mut out = std::io::stdout().lock();
    let mut ok = out
        .write_all(envcloak_sys::hardening_report().as_bytes())
        .is_ok();
    if hold {
        ok &= writeln!(out, "ready").is_ok() && out.flush().is_ok();
        drop(out);
        let mut sink = [0u8; 64];
        let mut stdin = std::io::stdin().lock();
        while matches!(stdin.read(&mut sink), Ok(n) if n > 0) {}
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
