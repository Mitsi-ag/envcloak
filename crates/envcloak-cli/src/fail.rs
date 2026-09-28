//! How the CLI reports its own failures: one line on stderr, `envcloak:
//! <token>: <message>`, with a stable token (SPEC §6.1 "Failures") and a
//! message built from fixed text. Neither ever holds an argument, a value
//! or text the daemon sent.

use std::borrow::Cow;
use std::process::ExitCode;

use envcloak_ipc::ClientError;

/// Exit code of a usage error.
pub const USAGE: u8 = 2;
/// Exit code of `run`'s own failures, apart from the child's codes.
pub const RUN_FAILURE: u8 = 125;
/// Exit code of every other command's failures.
pub const FAILURE: u8 = 1;

/// A failure to report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub token: &'static str,
    pub message: Cow<'static, str>,
}

impl Failure {
    pub fn new(token: &'static str, message: impl Into<Cow<'static, str>>) -> Self {
        Failure {
            token,
            message: message.into(),
        }
    }

    /// Prints the failure and returns `code`.
    pub fn report(&self, code: u8) -> ExitCode {
        eprintln!("envcloak: {}: {}", self.token, self.message);
        ExitCode::from(code)
    }
}

/// How to start a daemon, for every message that says none is running.
pub const START_DAEMON: &str = "start it with `envcloak daemon install`, or run \
     `envcloakd --foreground` by its absolute path; envcloak never starts it for you";

impl From<ClientError> for Failure {
    fn from(e: ClientError) -> Self {
        let message: Cow<'static, str> = match e {
            ClientError::Unavailable => {
                format!("the EnvCloak daemon is not running; {START_DAEMON}").into()
            }
            ClientError::Unverified(u) => format!("{}; nothing was sent to it", u.message()).into(),
            ClientError::Rpc(r) => match r.reason {
                Some(reason) => format!("{} ({})", r.kind.message(), reason_text(reason)).into(),
                None => r.kind.message().into(),
            },
            other => other.to_string().into(),
        };
        Failure {
            token: e.token(),
            message,
        }
    }
}

/// Words for an error's reason token.
fn reason_text(reason: &str) -> &'static str {
    match reason {
        "not_text" => "the passphrase must be UTF-8 text",
        "control_character" => "the passphrase must not contain control characters",
        "too_short" => "the passphrase must be at least 12 characters long",
        "common" => "the passphrase is a commonly used password",
        "busy" => "the vault file is in use by another process",
        "damaged" => "the vault file is damaged",
        "unsupported_version" => "the vault was written by a newer EnvCloak",
        "permissions" => "a vault directory or file has unsafe permissions or ownership",
        "disk_full" => "the disk is full",
        "storage" => "the vault storage failed",
        "io" => "the vault file could not be accessed",
        "migration" => "the vault format could not be upgraded",
        _ => "no detail",
    }
}

/// A usage error: never echoes the arguments, one of which could be a
/// pasted secret.
pub fn usage(text: &'static str) -> ExitCode {
    eprintln!("envcloak: usage: {text}");
    ExitCode::from(USAGE)
}
