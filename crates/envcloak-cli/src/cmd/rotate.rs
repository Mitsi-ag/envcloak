//! `envcloak rotate <slug>[#field] [--stdin] [--passphrase-fd N] [--json]`
//! (SPEC §10b "Writes that need a proof"; story S7): replaces a secret's
//! value. The old one is kept as the newest of three prior values, and
//! grants that bind the item stay (a rotated key keeps working for the
//! runs already approved).
//!
//! Replacing a value is a proof, so an agent cannot swap a key for one it
//! controls (SPEC §10):
//! 1. under a tracer it refuses at once (gate 19), and so it does when its
//!    environment holds an agent's markers;
//! 2. a verified daemon names the item and field, and serves them only to
//!    a caller that may give a proof (a terminal session with no agent in
//!    it), so where none is taken nothing is asked for;
//! 3. the new value is read from `/dev/tty` with echo off, or from
//!    standard input with `--stdin` (a pipe);
//! 4. the statement is shown, and the vault passphrase read from
//!    `/dev/tty` (or the descriptor `--passphrase-fd` names), never from
//!    argv or the environment;
//! 5. the daemon checks the proof, and that the slug still names the item
//!    shown, then replaces the value.

use std::process::ExitCode;

use super::{claims, fd_number, refuse_if_claimed, refuse_value_like};
use crate::connect::connect;
use crate::fail::{FAILURE, Failure, USAGE, refuse_if_traced, usage};
use crate::render::{print, rotate_statement};
use crate::tty::{InputError, Terminal, read_secret_fd, read_stdin_value};

const USAGE_TEXT: &str = "envcloak rotate <slug>[#field] [--stdin] [--passphrase-fd N] [--json]
       the new value is typed at a hidden prompt, or piped in with --stdin; never an argument";

/// The parsed command line.
#[derive(Debug, Default, PartialEq, Eq)]
struct RotateArgs {
    slug: String,
    field: Option<String>,
    stdin: bool,
    passphrase_fd: Option<i32>,
    json: bool,
}

fn parse(args: &[&str]) -> Option<RotateArgs> {
    let mut a = RotateArgs::default();
    let mut target = None;
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--stdin" if !a.stdin => a.stdin = true,
            "--json" if !a.json => a.json = true,
            "--passphrase-fd" if a.passphrase_fd.is_none() => {
                a.passphrase_fd = Some(fd_number(it.next()?)?);
            }
            _ if arg.starts_with('-') || target.is_some() => return None,
            _ => target = Some(arg),
        }
    }
    let (slug, field) = match target?.split_once('#') {
        Some((slug, field)) => (slug, Some(field.to_owned())),
        None => (target?, None),
    };
    a.slug = slug.to_owned();
    a.field = field;
    Some(a)
}

pub fn run(args: &[&str]) -> ExitCode {
    let Some(a) = parse(args) else {
        return usage(USAGE_TEXT);
    };
    let mut names = vec![a.slug.as_str()];
    names.extend(a.field.as_deref());
    if let Err(f) = refuse_value_like(&names) {
        return f.report(USAGE);
    }
    rotate(a).unwrap_or_else(|f| f.report(FAILURE))
}

fn rotate(a: RotateArgs) -> Result<ExitCode, Failure> {
    refuse_if_traced()?;
    let claims_now = refuse_if_claimed()?;
    // Served only where a proof is taken: nothing is asked for elsewhere.
    let target = connect()?.items_target(&a.slug, a.field.as_deref(), &claims_now)?;
    if target.field.is_none() {
        return Err(Failure::new(
            "ambiguous_field",
            "the item has several fields: name one with <slug>#<field>",
        ));
    }
    let statement = rotate_statement(&target);
    let no_terminal = |what: &'static str| {
        move |_| {
            Failure::new(
                "no_terminal",
                format!("there is no terminal to type {what} on"),
            )
        }
    };
    let mut terminal = None;
    let value = if a.stdin {
        read_stdin_value()?
    } else {
        let t = terminal
            .insert(Terminal::open().map_err(no_terminal("the value; pipe it in with --stdin"))?);
        t.read_secret("New value (typing is hidden): ")
            .map_err(|e| match e {
                InputError::Empty => Failure::new("no_input", "no value was entered"),
                e => e.into(),
            })?
    };
    let passphrase = match a.passphrase_fd {
        Some(fd) => {
            eprint!("{statement}");
            read_secret_fd(fd)?
        }
        None => {
            let t = match terminal.as_mut() {
                Some(t) => t,
                None => terminal.insert(Terminal::open().map_err(no_terminal(
                    "the passphrase; pass it on a descriptor with --passphrase-fd",
                ))?),
            };
            t.say(&statement)?;
            t.read_secret("Vault passphrase to rotate this: ")?
        }
    };
    let rotated = connect()?.items_rotate(&target, value, passphrase, &claims())?;
    print(&rotated, a.json);
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_target_is_a_slug_and_an_optional_field() {
        let a = parse(&["openai/acme-web"]).unwrap();
        assert_eq!(
            (a.slug.as_str(), a.field.as_deref()),
            ("openai/acme-web", None)
        );
        let a = parse(&["--stdin", "openai/acme-web#api_key", "--passphrase-fd", "3"]).unwrap();
        assert_eq!(
            a,
            RotateArgs {
                slug: "openai/acme-web".into(),
                field: Some("api_key".into()),
                stdin: true,
                passphrase_fd: Some(3),
                json: false,
            }
        );
        for bad in [
            &[][..],
            &["a", "b"],
            &["a", "--value", "x"],
            &["a", "--stdin", "--stdin"],
            &["a", "--passphrase-fd"],
            &["a", "--passphrase-fd", "x"],
            &["--stdin"],
        ] {
            assert!(parse(bad).is_none(), "{bad:?}");
        }
    }
}
