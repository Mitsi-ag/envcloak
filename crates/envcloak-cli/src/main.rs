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
//!   f] [--manifest PATH] [--wait DURATION] -- <cmd...>` (SPEC §6.1), whose
//!   first step refuses to go on under a tracer, with exit 125 and `traced`
//!   (gate 19), before any contact with the daemon. It asks a verified
//!   daemon for the decision (waiting for an approval with `--wait`,
//!   without holding a connection) and, when a grant covers it, starts the
//!   command with the released values in its environment and its output
//!   redacted (`envcloak_exec`; docs/RUN.md);
//! - `envcloak pending`, `approve`, `deny` and `grants list` / `grants
//!   revoke` (SPEC §6.1 step 4, §10b);
//! - `envcloak audit verify`: the audit log's check (SPEC §15.2 gate 33);
//! - `envcloak add`, `ls`, `show`, `ref`, `check`, `rotate` and `rm`: the
//!   vault's items and the project's references, metadata only (SPEC §6.3,
//!   §7, §10b). Their output is `envcloak_ipc::view` types rendered by
//!   [`envcloak_client::render`], as text or with `--json`; `rotate` and
//!   `rm` need the passphrase as a proof;
//! - `envcloak init`, `import --scan` and `recovery confirm`: env files
//!   imported into the vault with filesystem-safe scanning, and deleted
//!   only after the four conditions of SPEC §6.4 (see [`cmd::init`]);
//! - `envcloak backup create` and `recover`: an encrypted backup of the
//!   vault, and the vault restored from one with the Recovery Kit under a
//!   new passphrase (see [`cmd::recover`]);
//! - `envcloak mcp [--host ID] [--wait-ms N]`: EnvCloak's MCP server, which
//!   an agent host starts and talks to over standard input and output
//!   (SPEC §7; `envcloak_mcp`, docs/MCP.md). It never receives a value:
//!   `run_with_secrets` runs a child `envcloak run`.
//! - `envcloak agents install` and `uninstall`, which teach Claude Code
//!   and Codex EnvCloak and take it out again, and `envcloak hook`, the
//!   handler their prompt and tool-call hooks run (SPEC §7;
//!   `envcloak_agents`, docs/INSTALLERS.md).
//!
//! Every command that reads, shows or sends a secret or a proof (`vault
//! create`, `unlock`, `approve`, `run`, `add`, `rotate`, `rm`, `init`,
//! `import`, `recovery confirm`, `recover`), or input that can hold one
//! (`hook`, whose prompt can hold a pasted key; `agents install` and
//! `uninstall`, which read agents' configs), refuses under a tracer first,
//! before it reads a file, a descriptor or the terminal.
//!
//! The commands of M2 and M2b are registered ahead of their tasks and
//! listed in the help as not in this build: each exits 125 with
//! `not_in_this_build` and reads no argument (see [`cmd`]).
//!
//! `envcloak internal hardening [--hold]` is a hidden, value-free diagnostic
//! used by the gate 19 tests: it prints `key=value` hardening lines and, with
//! `--hold`, prints `ready` and waits for stdin to close, so a test can
//! inspect the live process from outside.
//!
//! A panic prints where it happened and never its message, which could
//! hold a value (`envcloak_sys::install_panic_hook`, gate 12); release
//! builds then abort. `envcloak internal panic` is a hidden command that
//! panics with its standard input in the message, so a test can show
//! that on any build, the release artifact included.
//!
//! No argument is ever echoed: one could be a pasted secret. No command
//! takes a value as an argument (gate 13): values come from a hidden
//! prompt on `/dev/tty` or from standard input, and a name shaped like a
//! key or token is refused. An argument that is not valid UTF-8 is
//! refused as a usage error, before anything else, rather than changed:
//! the command line `run` sends for approval must be the one it was given.

mod cmd;

use std::io::{Read, Write};
use std::process::ExitCode;

use envcloak_client::fail::USAGE;

#[global_allocator]
static ALLOCATOR: envcloak_sys::WipingAllocator = envcloak_sys::WipingAllocator;

const HELP: &str = "usage:
  envcloak vault create [--passphrase-fd N] [--kit-fd N] [--kdf-memory SIZE]
  envcloak unlock [--passphrase-fd N]
  envcloak lock
  envcloak status [--json]
  envcloak daemon install [--daemon /absolute/path/to/envcloakd] [--no-start]
  envcloak daemon uninstall
  envcloak run [--profile NAME] [--ref NAME=slug[#field]]... [--env-file FILE] [--manifest PATH] [--wait DURATION] -- <cmd...>
  envcloak pending [--json]
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
  envcloak items reclassify <slug> test|live|unknown [--passphrase-fd N] [--json]
  envcloak init [--import] [--yes] [--delete-plaintext] [--agents-note] [--json]
  envcloak init --undo <ID> [--created-by-agent] [--unrecorded] [--passphrase-fd N] [--json]
  envcloak import --scan <dir> [--yes] [--json]
  envcloak recovery confirm [--kit-fd N] [--json]
  envcloak backup create [--json]
  envcloak recover --backup <file> [--kit-fd N] [--new-passphrase-fd N] [--json]
  envcloak mcp [--host ID] [--wait-ms N]
  envcloak agents install [--global] [--project] [--agent ID]... [--consent-sandbox-sockets] [--yes] [--json]
  envcloak agents uninstall [--global] [--project] [--agent ID]... [--yes] [--json]
  envcloak hook --host ID --event NAME
Not in this build (each exits 125 with not_in_this_build):
  envcloak run --pty
  envcloak reveal
  envcloak doctor
  envcloak scrub
  envcloak agents status | migrate-mcp
  envcloak mcp-bridge
  envcloak standing
  envcloak login
  envcloak signin
Values are never arguments: type them at the hidden prompt, or pipe them in with --stdin.";

fn main() -> ExitCode {
    envcloak_sys::harden_process();
    envcloak_sys::install_panic_hook("envcloak");

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
        // A command this build registers but does not have refuses
        // whatever its arguments, one that is not UTF-8 included (M2-02's
        // rule; review M2R-9): its words are read as text, nothing else.
        if let Some(code) = not_in_this_build_whatever_the_arguments(&args) {
            return code;
        }
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
        ["internal", "panic"] => envcloak_sys::panic_with_input(),
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
        ["backup", rest @ ..] => cmd::backup::run(rest),
        ["recover", rest @ ..] => cmd::recover::run(rest),
        // M2 and M2b, registered ahead of their tasks.
        ["pending", rest @ ..] => cmd::pending::run(rest),
        ["reveal", rest @ ..] => cmd::reveal::run(rest),
        ["doctor", rest @ ..] => cmd::doctor::run(rest),
        ["scrub", rest @ ..] => cmd::scrub::run(rest),
        ["agents", rest @ ..] => cmd::agents::run(rest),
        ["hook", rest @ ..] => cmd::hook::run(rest),
        ["mcp", rest @ ..] => cmd::mcp::run(rest),
        ["mcp-bridge", rest @ ..] => cmd::mcp_bridge::run(rest),
        ["standing", rest @ ..] => cmd::standing::run(rest),
        ["items", rest @ ..] => cmd::items::run(rest),
        ["login", rest @ ..] => cmd::login::run(rest),
        ["signin", rest @ ..] => cmd::signin::run(rest),
        // Never echo arguments: one of them could be a pasted secret.
        _ => {
            eprintln!("envcloak: unknown command\n{HELP}");
            ExitCode::from(USAGE)
        }
    }
}

/// The refusal of an M2 or M2b command this build does not have, or of
/// `run --pty`, chosen by the words that select it (the first, and for
/// `agents` the second; for `run`, `--pty` anywhere before
/// `--`); `None` for any other command line. No other argument is read.
fn not_in_this_build_whatever_the_arguments(args: &[std::ffi::OsString]) -> Option<ExitCode> {
    let word = |i: usize| args.get(i).and_then(|a| a.to_str());
    Some(match word(0)? {
        "reveal" => cmd::reveal::run(&[]),
        "doctor" => cmd::doctor::run(&[]),
        "scrub" => cmd::scrub::run(&[]),
        "mcp-bridge" => cmd::mcp_bridge::run(&[]),
        "standing" => cmd::standing::run(&[]),
        "login" => cmd::login::run(&[]),
        "signin" => cmd::signin::run(&[]),
        "agents" if matches!(word(1)?, "status" | "migrate-mcp") => cmd::agents::run(&[word(1)?]),
        "run"
            if args[1..]
                .iter()
                .take_while(|a| a.as_os_str() != "--")
                .any(|a| a.as_os_str() == "--pty") =>
        {
            cmd::not_in_this_build("`envcloak run --pty`")
        }
        _ => return None,
    })
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
