//! `envcloak approve <REQUEST>` when `<REQUEST>` is a pending Secure Enclave
//! unlocker enrolment (`unlocker_add`, SPEC §10b, D3-08).
//!
//! Renders the `envcloak-unlocker-statement/1` statement (request id, label,
//! vault id, SHA-256 fingerprints of both public keys, and the app's verified
//! Team ID and signing identifier), reads the vault passphrase from `/dev/tty`
//! or `--passphrase-fd`, and sends the passphrase with the statement digest to
//! the daemon.

use std::process::ExitCode;

use envcloak_client::connect::connect;
use envcloak_client::fail::Failure;
use envcloak_client::tty::{Terminal, read_secret_fd};
use envcloak_policy::{
    ApprovalOptions, DEFAULT_TTL, UnlockerAddDescriptor, Uses, escape_for_display,
    render_unlocker_statement, unlocker_statement_digest,
};

pub fn run(
    id: &str,
    descriptor: UnlockerAddDescriptor,
    passphrase_fd: Option<i32>,
    claims: &[String],
) -> Result<ExitCode, Failure> {
    let statement = render_unlocker_statement(&descriptor);
    let digest = unlocker_statement_digest(&descriptor);
    let passphrase = match passphrase_fd {
        Some(fd) => {
            print!("{statement}");
            read_secret_fd(fd)?
        }
        None => {
            let mut t = Terminal::open()?;
            t.say(&statement)?;
            t.read_secret("Vault passphrase to approve this: ")?
        }
    };
    let options = ApprovalOptions {
        uses: Uses::Once,
        ttl_secs: DEFAULT_TTL.as_secs(),
        live: Vec::new(),
    };
    let approved = connect()?.approve(id, options, &digest, passphrase, claims)?;
    let unlocker = &approved.grant;
    if unlocker.len() != 32
        || !unlocker
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(Failure::new(
            "protocol_error",
            "the daemon's answer was malformed",
        ));
    }
    println!(
        "Approved request {}: enrolled Secure Enclave unlocker {unlocker}.",
        escape_for_display(id)
    );
    Ok(ExitCode::SUCCESS)
}
