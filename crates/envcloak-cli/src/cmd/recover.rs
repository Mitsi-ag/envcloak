//! `envcloak recover --backup <file> [--kit-fd N] [--new-passphrase-fd N]
//! [--json]` (SPEC §15.1 step 11, story S11): replaces the vault with the
//! one an encrypted backup holds, opened with the Recovery Kit, under a new
//! passphrase, and leaves it unlocked. It is how a vault comes back after
//! its file is lost or damaged, or its passphrase forgotten.
//!
//! The kit is the proof, as for `envcloak recovery confirm`:
//! 1. under a tracer nothing is read (gate 19), and a caller with agent
//!    markers is refused before anything is asked; the daemon takes the
//!    kit only from a terminal session with no agent in it, counted by the
//!    attempt limiter;
//! 2. the daemon is verified before anything is read;
//! 3. the kit is read from `/dev/tty` with echo off, or from the
//!    descriptor `--kit-fd` names (one line, as `envcloak vault create
//!    --kit-fd` wrote it), never from argv, the environment or standard
//!    input, and its shape is checked here first, so a typo costs no
//!    attempt;
//! 4. the new passphrase is typed twice on `/dev/tty` (or a generated one
//!    shown once and typed back), or read from the descriptor
//!    `--new-passphrase-fd` names, and checked against the rules here;
//! 5. the daemon opens the backup itself, from its absolute path (a
//!    relative one is taken from the working directory), and restores it.
//!    A vault that was unlocked is locked first, so every grant ends; the
//!    replaced vault file is kept beside the new one.

use std::path::Path;
use std::process::ExitCode;

use envcloak_core::{RecoveryKit, SecretBytes, check_passphrase};

use super::{fd_number, refuse_if_claimed};
use crate::connect::connect;
use crate::fail::{FAILURE, Failure, refuse_if_traced, usage};
use crate::render::print;
use crate::tty::{InputError, Terminal, read_secret_fd};

const USAGE_TEXT: &str =
    "envcloak recover --backup <file> [--kit-fd N] [--new-passphrase-fd N] [--json]";

#[derive(Debug, Default, PartialEq, Eq)]
struct RecoverArgs {
    backup: String,
    kit_fd: Option<i32>,
    passphrase_fd: Option<i32>,
    json: bool,
}

fn parse(args: &[&str]) -> Option<RecoverArgs> {
    let mut a = RecoverArgs::default();
    let mut backup = None;
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--json" if !a.json => a.json = true,
            "--backup" if backup.is_none() => backup = Some(*it.next()?),
            "--kit-fd" if a.kit_fd.is_none() => a.kit_fd = Some(fd_number(it.next()?)?),
            "--new-passphrase-fd" if a.passphrase_fd.is_none() => {
                a.passphrase_fd = Some(fd_number(it.next()?)?);
            }
            _ => return None,
        }
    }
    a.backup = backup.filter(|b| !b.is_empty())?.to_owned();
    if a.kit_fd.is_some() && a.kit_fd == a.passphrase_fd {
        return None;
    }
    Some(a)
}

pub fn run(args: &[&str]) -> ExitCode {
    if args == ["--help"] || args == ["-h"] {
        println!("usage: {USAGE_TEXT}");
        return ExitCode::SUCCESS;
    }
    let Some(a) = parse(args) else {
        return usage(USAGE_TEXT);
    };
    recover(&a).unwrap_or_else(|f| f.report(FAILURE))
}

fn recover(a: &RecoverArgs) -> Result<ExitCode, Failure> {
    refuse_if_traced()?;
    let claims = refuse_if_claimed()?;
    for fd in [a.kit_fd, a.passphrase_fd].into_iter().flatten() {
        if fd <= 2 {
            return Err(Failure::new(
                "secret_fd",
                "the Recovery Kit and the passphrase are never read from standard input, \
                 output or error; name other descriptors",
            ));
        }
    }
    let backup = absolute(&a.backup)?;
    // A verified daemon, before anything is read.
    connect()?.status()?;
    let mut terminal = if a.kit_fd.is_none() || a.passphrase_fd.is_none() {
        Some(Terminal::open().map_err(|_| no_terminal(a))?)
    } else {
        None
    };
    let kit = match (a.kit_fd, terminal.as_mut()) {
        (Some(fd), _) => read_secret_fd(fd)?,
        (None, Some(t)) => {
            t.read_secret("Recovery Kit (typing is hidden): ")
                .map_err(|e| match e {
                    InputError::Empty => Failure::new("no_input", "no Recovery Kit was entered"),
                    e => e.into(),
                })?
        }
        (None, None) => return Err(no_terminal(a)),
    };
    if RecoveryKit::parse(&kit).is_err() {
        return Err(Failure::new(
            "invalid_kit",
            "that is not a Recovery Kit: it is seven groups of four characters, as `envcloak \
             vault create` showed it, and its check characters caught a typo",
        ));
    }
    let passphrase: SecretBytes = match (a.passphrase_fd, terminal.as_mut()) {
        (Some(fd), _) => read_secret_fd(fd)?,
        (None, Some(t)) => super::vault::new_passphrase(t)?,
        (None, None) => return Err(no_terminal(a)),
    };
    check_passphrase(&passphrase).map_err(|r| Failure::new("passphrase_rejected", r.message()))?;
    drop(terminal);
    let view = connect()?.vault_recover(&backup, kit, passphrase, &claims)?;
    print(&view, a.json);
    Ok(ExitCode::SUCCESS)
}

/// The backup's path made absolute against the working directory. It is
/// never echoed: a path can hold anything.
fn absolute(p: &str) -> Result<String, Failure> {
    let path = Path::new(p);
    let full = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| {
                Failure::new(
                    "invalid_path",
                    "the working directory cannot be read; give the backup's absolute path",
                )
            })?
            .join(path)
    };
    full.into_os_string().into_string().map_err(|_| {
        Failure::new(
            "invalid_path",
            "the working directory's path is not UTF-8; give the backup's absolute path",
        )
    })
}

fn no_terminal(a: &RecoverArgs) -> Failure {
    let what = match (a.kit_fd, a.passphrase_fd) {
        (None, _) => "type the Recovery Kit on; pass it on a descriptor with --kit-fd",
        (Some(_), None) => {
            "type the new passphrase on; pass it on a descriptor with --new-passphrase-fd"
        }
        (Some(_), Some(_)) => "use",
    };
    Failure::new("no_terminal", format!("there is no terminal to {what}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backup_is_named_and_descriptors_differ() {
        assert_eq!(
            parse(&["--backup", "b.ecbackup"]).unwrap(),
            RecoverArgs {
                backup: "b.ecbackup".into(),
                ..RecoverArgs::default()
            }
        );
        assert_eq!(
            parse(&[
                "--kit-fd",
                "4",
                "--backup",
                "/x/b",
                "--new-passphrase-fd",
                "3",
                "--json"
            ])
            .unwrap(),
            RecoverArgs {
                backup: "/x/b".into(),
                kit_fd: Some(4),
                passphrase_fd: Some(3),
                json: true,
            }
        );
        for bad in [
            &[][..],
            &["--backup"],
            &["--backup", ""],
            &["b.ecbackup"],
            &["--backup", "a", "--backup", "b"],
            &["--backup", "a", "--kit-fd", "3", "--new-passphrase-fd", "3"],
            &["--backup", "a", "--kit-fd", "x"],
            &["--backup", "a", "--passphrase-fd", "3"],
        ] {
            assert!(parse(bad).is_none(), "{bad:?}");
        }
        assert!(absolute("/abs/b").unwrap() == "/abs/b");
        assert!(Path::new(&absolute("rel/b").unwrap()).is_absolute());
    }
}
