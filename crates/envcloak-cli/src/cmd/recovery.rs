//! `envcloak recovery confirm [--kit-fd N] [--json]` (SPEC §6.4, story
//! S2): records that you hold the Recovery Kit, after checking the kit you
//! type opens the vault. Plaintext env files are deleted only once the kit
//! is confirmed, so a forgotten passphrase cannot lose what they held.
//!
//! The kit is a proof, like the passphrase: under a tracer nothing is read
//! (gate 19), a caller with agent markers is refused before anything is
//! asked, and the daemon takes it only from a terminal session with no
//! agent in it, counted by the attempt limiter. It is read from `/dev/tty`
//! with echo off, or from the descriptor `--kit-fd` names (one line, as
//! `envcloak vault create --kit-fd` wrote it), never from argv, the
//! environment or standard input. It is checked here for its shape first,
//! so a typo costs no attempt.

use std::process::ExitCode;

use envcloak_client::claims::refuse_if_claimed;
use envcloak_client::connect::connect;
use envcloak_client::fail::{FAILURE, Failure, refuse_if_traced, usage};
use envcloak_client::render::print;
use envcloak_client::tty::{InputError, Terminal, read_secret_fd};
use envcloak_core::RecoveryKit;

use super::{fd_number, require_unlocked};

const USAGE_TEXT: &str = "envcloak recovery confirm [--kit-fd N] [--json]";

#[derive(Debug, Default, PartialEq, Eq)]
struct ConfirmArgs {
    kit_fd: Option<i32>,
    json: bool,
}

fn parse(args: &[&str]) -> Option<ConfirmArgs> {
    let ["confirm", rest @ ..] = args else {
        return None;
    };
    let mut a = ConfirmArgs::default();
    let mut it = rest.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--json" if !a.json => a.json = true,
            "--kit-fd" if a.kit_fd.is_none() => a.kit_fd = Some(fd_number(it.next()?)?),
            _ => return None,
        }
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
    confirm(&a).unwrap_or_else(|f| f.report(FAILURE))
}

fn confirm(a: &ConfirmArgs) -> Result<ExitCode, Failure> {
    refuse_if_traced()?;
    let claims = refuse_if_claimed()?;
    require_unlocked(&mut connect()?)?;
    let kit = match a.kit_fd {
        Some(fd) if fd <= 2 => {
            return Err(Failure::new(
                "kit_fd",
                "the Recovery Kit is never read from standard input, output or error; name \
                 another descriptor with --kit-fd",
            ));
        }
        Some(fd) => read_secret_fd(fd)?,
        None => Terminal::open()
            .map_err(|_| {
                Failure::new(
                    "no_terminal",
                    "there is no terminal to type the Recovery Kit on; pass it on a descriptor \
                     with --kit-fd",
                )
            })?
            .read_secret("Recovery Kit (typing is hidden): ")
            .map_err(|e| match e {
                InputError::Empty => Failure::new("no_input", "no Recovery Kit was entered"),
                e => e.into(),
            })?,
    };
    if RecoveryKit::parse(&kit).is_err() {
        return Err(Failure::new(
            "invalid_kit",
            "that is not a Recovery Kit: it is seven groups of four characters, as `envcloak \
             vault create` showed it, and its check characters caught a typo",
        ));
    }
    let view = connect()?.recovery_confirm(kit, &claims)?;
    print(&view, a.json);
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_takes_a_descriptor_and_nothing_else() {
        assert_eq!(parse(&["confirm"]).unwrap(), ConfirmArgs::default());
        assert_eq!(
            parse(&["confirm", "--kit-fd", "4", "--json"]).unwrap(),
            ConfirmArgs {
                kit_fd: Some(4),
                json: true
            }
        );
        for bad in [
            &[][..],
            &["confirm", "--kit-fd"],
            &["confirm", "--kit-fd", "x"],
            &["confirm", "KIT-TEXT"],
            &["show"],
        ] {
            assert!(parse(bad).is_none(), "{bad:?}");
        }
    }
}
