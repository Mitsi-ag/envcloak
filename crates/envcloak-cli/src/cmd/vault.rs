//! `envcloak vault create [--passphrase-fd N] [--kit-fd N] [--kdf-memory
//! SIZE]` (SPEC §5 "Unlockers", story S1).
//!
//! 1. The daemon is verified, and must have no vault yet.
//! 2. The passphrase comes from the terminal (typed twice, or a generated
//!    six-word passphrase shown once and typed back), or from the
//!    descriptor `--passphrase-fd` names. It is checked against the rules
//!    here first, so a weak one is refused before any key derivation.
//! 3. The Recovery Kit is generated here, and shown on the terminal or
//!    written to the descriptor `--kit-fd` names, never to stdout or
//!    stderr. It is written before the vault exists, so a vault never
//!    exists whose kit was lost; if creation then fails, the kit is void
//!    and the message says so.
//! 4. The daemon creates the vault with both, and leaves it unlocked. The
//!    kit crosses the socket only from here to the daemon (SPEC §4.4).

use std::fs::File;
use std::io::Write;
use std::process::ExitCode;

use envcloak_core::{RecoveryKit, SecretBytes, check_passphrase, suggest_passphrase};
use envcloak_ipc::proto::ErrorKind;
use envcloak_ipc::view::VaultState;
use envcloak_ipc::{ClientError, RpcError};

use super::fd_number;
use crate::connect::connect;
use crate::fail::{FAILURE, Failure, usage};
use crate::tty::{InputError, Terminal, read_secret_fd};

const USAGE: &str =
    "envcloak vault create [--passphrase-fd N] [--kit-fd N] [--kdf-memory SIZE (64MiB to 4GiB)]";

/// The parsed options of `vault create`.
#[derive(Debug, Default, PartialEq, Eq)]
struct CreateArgs {
    passphrase_fd: Option<i32>,
    kit_fd: Option<i32>,
    kdf_memory_kib: Option<u32>,
}

pub fn run(args: &[&str]) -> ExitCode {
    match args {
        ["create", rest @ ..] => match parse(rest) {
            Some(a) => create(&a).unwrap_or_else(|f| f.report(FAILURE)),
            None => usage(USAGE),
        },
        _ => usage(USAGE),
    }
}

fn parse(args: &[&str]) -> Option<CreateArgs> {
    let mut a = CreateArgs::default();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it.next()?;
        match *flag {
            "--passphrase-fd" if a.passphrase_fd.is_none() => {
                a.passphrase_fd = Some(fd_number(value)?);
            }
            "--kit-fd" if a.kit_fd.is_none() => a.kit_fd = Some(fd_number(value)?),
            "--kdf-memory" if a.kdf_memory_kib.is_none() => {
                a.kdf_memory_kib = Some(parse_size_kib(value)?);
            }
            _ => return None,
        }
    }
    if a.kit_fd.is_some() && a.kit_fd == a.passphrase_fd {
        return None;
    }
    Some(a)
}

/// `64MiB`, `256MiB`, `1GiB`: Argon2id memory in KiB, within the bounds
/// (64 MiB to 4 GiB).
fn parse_size_kib(v: &str) -> Option<u32> {
    let (digits, factor) = if let Some(d) = v.strip_suffix("MiB") {
        (d, 1024u64)
    } else if let Some(d) = v.strip_suffix("GiB") {
        (d, 1024 * 1024)
    } else {
        return None;
    };
    if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let kib = digits.parse::<u64>().ok()?.checked_mul(factor)?;
    (64 * 1024..=4 * 1024 * 1024)
        .contains(&kib)
        .then(|| u32::try_from(kib).ok())
        .flatten()
}

fn create(a: &CreateArgs) -> Result<ExitCode, Failure> {
    if a.kit_fd.is_some_and(|fd| fd <= 2) {
        return Err(Failure::new(
            "kit_fd",
            "the Recovery Kit is never written to stdin, stdout or stderr; name another \
             descriptor with --kit-fd",
        ));
    }
    // The daemon, verified, with no vault yet: checked before anything is
    // asked or shown.
    let mut client = connect()?;
    if client.status()?.vault.state != VaultState::Absent {
        return Err(ClientError::Rpc(RpcError::new(ErrorKind::VaultExists)).into());
    }
    drop(client);

    let mut kit_out = match a.kit_fd {
        Some(fd) => Some(File::from(
            envcloak_sys::inherited_fd(fd).map_err(|_| InputError::BadFd)?,
        )),
        None => None,
    };
    let mut terminal = if kit_out.is_none() || a.passphrase_fd.is_none() {
        Some(Terminal::open().map_err(|_| no_terminal(a))?)
    } else {
        None
    };

    let passphrase = match (a.passphrase_fd, terminal.as_mut()) {
        (Some(fd), _) => read_secret_fd(fd)?,
        (None, Some(t)) => new_passphrase(t)?,
        (None, None) => return Err(no_terminal(a)),
    };
    check_passphrase(&passphrase).map_err(|r| Failure::new("passphrase_rejected", r.message()))?;

    let kit = RecoveryKit::generate();
    let text = kit.to_display();
    drop(kit);
    match (kit_out.as_mut(), terminal.as_mut()) {
        (Some(f), _) => f
            .write_all(text.as_bytes())
            .and_then(|()| f.write_all(b"\n"))
            .and_then(|()| f.flush())
            .map_err(|_| {
                Failure::new(
                    "kit_not_written",
                    "the Recovery Kit could not be written to the --kit-fd descriptor; no vault \
                     was created",
                )
            })?,
        (None, Some(t)) => {
            t.say(
                "\nYour Recovery Kit. It is shown once: write it down and keep it offline. It \
                 unlocks the vault if you forget the passphrase.\n\n    ",
            )?;
            t.say(&text)?;
            t.say("\n\n")?;
        }
        (None, None) => return Err(no_terminal(a)),
    }
    drop(kit_out);

    let mut client = connect()?;
    let created = client.vault_create(
        passphrase,
        SecretBytes::copy_from(text.as_bytes()),
        a.kdf_memory_kib,
    );
    drop(text);
    if let Err(e) = created {
        let mut f = Failure::from(e);
        f.message = format!(
            "{}; no vault was created, so the Recovery Kit just shown or written is void",
            f.message
        )
        .into();
        return Err(f);
    }
    println!("Vault created and unlocked.");
    if a.kit_fd.is_some() {
        println!("The Recovery Kit went only to the descriptor you named.");
    }
    Ok(ExitCode::SUCCESS)
}

fn no_terminal(a: &CreateArgs) -> Failure {
    let what = match (a.passphrase_fd, a.kit_fd) {
        (None, _) => "type the passphrase on; pass it on a descriptor with --passphrase-fd",
        (Some(_), None) => "show the Recovery Kit on; name a descriptor for it with --kit-fd",
        (Some(_), Some(_)) => "use",
    };
    Failure::new("no_terminal", format!("there is no terminal to {what}"))
}

/// Asks for a new passphrase twice, or offers a generated one.
fn new_passphrase(t: &mut Terminal) -> Result<SecretBytes, Failure> {
    let first = t.read_secret(
        "New vault passphrase (at least 12 characters; press Enter for a generated one): ",
    )?;
    if first.is_empty() {
        let suggested = suggest_passphrase();
        t.say("\nYour new passphrase, six random words. Write it down:\n\n    ")?;
        t.say(&suggested)?;
        t.say("\n\n")?;
        let again = t.read_secret("Type it once to confirm: ")?;
        if !again.ct_eq(suggested.as_bytes()) {
            return Err(mismatch());
        }
        return Ok(SecretBytes::copy_from(suggested.as_bytes()));
    }
    check_passphrase(&first).map_err(|r| Failure::new("passphrase_rejected", r.message()))?;
    let again = t.read_secret("Repeat the passphrase: ")?;
    if !first.ct_eq_secret(&again) {
        return Err(mismatch());
    }
    Ok(first)
}

fn mismatch() -> Failure {
    Failure::new("passphrase_mismatch", "the passphrases do not match")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_parse_and_repeat_or_clash_is_refused() {
        assert_eq!(parse(&[]), Some(CreateArgs::default()));
        assert_eq!(
            parse(&[
                "--passphrase-fd",
                "3",
                "--kit-fd",
                "4",
                "--kdf-memory",
                "64MiB"
            ]),
            Some(CreateArgs {
                passphrase_fd: Some(3),
                kit_fd: Some(4),
                kdf_memory_kib: Some(65536),
            })
        );
        for bad in [
            &["--passphrase-fd"][..],
            &["--passphrase-fd", "x"],
            &["--kit-fd", "3", "--passphrase-fd", "3"],
            &["--kit-fd", "3", "--kit-fd", "4"],
            &["--bogus", "1"],
            &["positional"],
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn kdf_memory_is_bounded() {
        assert_eq!(parse_size_kib("64MiB"), Some(64 * 1024));
        assert_eq!(parse_size_kib("256MiB"), Some(256 * 1024));
        assert_eq!(parse_size_kib("4GiB"), Some(4 * 1024 * 1024));
        for bad in [
            "63MiB",
            "5GiB",
            "64",
            "64MB",
            "MiB",
            "-64MiB",
            "0GiB",
            "99999999GiB",
        ] {
            assert_eq!(parse_size_kib(bad), None, "{bad}");
        }
    }
}
