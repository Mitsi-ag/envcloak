//! `envcloak rm <slug> [--passphrase-fd N] [--json]` (SPEC §10b "Writes
//! that need a proof"): removes an item and its values.
//!
//! Deleting a value is a proof, as replacing one is (`rotate`): otherwise
//! an agent could remove a key and add one it controls under the same
//! slug. The steps are `rotate`'s, without a new value: the daemon names
//! the item to a caller that may give a proof, the statement is shown, and
//! the passphrase read from `/dev/tty` or `--passphrase-fd`. The daemon
//! then writes an encrypted backup of the vault, which keeps the removed
//! values (`envcloak recover --backup <file>` restores it), removes the
//! item, and ends the grants and pending requests that bind it. When the
//! backup cannot be written, nothing is removed.

use std::process::ExitCode;

use super::{claims, fd_number, refuse_if_claimed, refuse_value_like};
use crate::connect::connect;
use crate::fail::{FAILURE, Failure, USAGE, refuse_if_traced, usage};
use crate::render::{print, remove_statement};
use crate::tty::{Terminal, read_secret_fd};

const USAGE_TEXT: &str = "envcloak rm <slug> [--passphrase-fd N] [--json]";

#[derive(Debug, Default, PartialEq, Eq)]
struct RmArgs {
    slug: String,
    passphrase_fd: Option<i32>,
    json: bool,
}

fn parse(args: &[&str]) -> Option<RmArgs> {
    let mut a = RmArgs::default();
    let mut slug = None;
    let mut it = args.iter();
    while let Some(&arg) = it.next() {
        match arg {
            "--json" if !a.json => a.json = true,
            "--passphrase-fd" if a.passphrase_fd.is_none() => {
                a.passphrase_fd = Some(fd_number(it.next()?)?);
            }
            // A field is not removed on its own in M1: no M1 command makes
            // an item with more than one.
            _ if arg.starts_with('-') || arg.contains('#') || slug.is_some() => return None,
            _ => slug = Some(arg),
        }
    }
    a.slug = slug?.to_owned();
    Some(a)
}

pub fn run(args: &[&str]) -> ExitCode {
    let Some(a) = parse(args) else {
        return usage(USAGE_TEXT);
    };
    if let Err(f) = refuse_value_like(&[&a.slug]) {
        return f.report(USAGE);
    }
    rm(a).unwrap_or_else(|f| f.report(FAILURE))
}

fn rm(a: RmArgs) -> Result<ExitCode, Failure> {
    refuse_if_traced()?;
    let claims_now = refuse_if_claimed()?;
    let target = connect()?.items_target(&a.slug, None, &claims_now)?;
    let statement = remove_statement(&target);
    let passphrase = match a.passphrase_fd {
        Some(fd) => {
            eprint!("{statement}");
            read_secret_fd(fd)?
        }
        None => {
            let mut t = Terminal::open().map_err(|_| {
                Failure::new(
                    "no_terminal",
                    "there is no terminal to type the passphrase on; pass it on a descriptor \
                     with --passphrase-fd",
                )
            })?;
            t.say(&statement)?;
            t.read_secret("Vault passphrase to remove this: ")?
        }
    };
    let removed = connect()?.items_remove(&target, passphrase, &claims())?;
    print(&removed, a.json);
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rm_takes_one_slug() {
        assert_eq!(
            parse(&["openai/acme-web", "--json"]).unwrap(),
            RmArgs {
                slug: "openai/acme-web".into(),
                passphrase_fd: None,
                json: true,
            }
        );
        assert_eq!(
            parse(&["--passphrase-fd", "3", "a"]).unwrap().passphrase_fd,
            Some(3)
        );
        for bad in [
            &[][..],
            &["a", "b"],
            &["a#value"],
            &["--force", "a"],
            &["a", "--json", "--json"],
        ] {
            assert!(parse(bad).is_none(), "{bad:?}");
        }
    }
}
