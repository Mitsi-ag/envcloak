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
        "io" => "the vault file or the manifest could not be accessed",
        "migration" => "the vault format could not be upgraded",
        // Caller evidence.
        "caller_gone" => "this process exited before its ancestry could be read",
        "ancestry_changed" => "this process's ancestry kept changing while it was read",
        "ancestry_hidden" => {
            "a process in this process's ancestry is hidden from the daemon (Linux: /proc \
             mounted with hidepid; see docs/AGENTS.md)"
        }
        "ancestry_unreadable" => "this process's ancestry could not be read",
        "caller_is_init" => {
            "this process is pid 1, which no grant is rooted at; run it under a shell or an init"
        }
        // The manifest.
        "too_large" => "the manifest is larger than 64 KiB",
        "not_utf8" => "the manifest is not UTF-8",
        "syntax" => "the manifest is not valid TOML",
        "duplicate_key" => "the manifest defines a key twice",
        "unknown_key" => "the manifest has an unknown key",
        "wrong_type" => "a manifest value has the wrong type",
        "invalid_env_name" => "a variable name in the manifest or a --ref is invalid",
        "invalid_profile_name" => "the profile name is invalid",
        "nested_profile" => "profiles do not nest",
        "invalid_reference" => "a reference in the manifest or a --ref is invalid",
        "invalid_project_name" => "the project name is invalid",
        "loose_policy" => "the manifest's [policy] tries to loosen policy, which is refused",
        "invalid_policy" => "the manifest's [policy] has an invalid value",
        "unknown_profile" => "the manifest has no such profile",
        "duplicate_env_name" => "a variable is bound twice",
        "invalid_path" => "the manifest path is not absolute, or not named envcloak.toml",
        "not_found" => "no envcloak.toml there",
        "symlinked_manifest" => "envcloak.toml is a symlink, which is refused",
        "not_regular_file" => "envcloak.toml is not a regular file",
        "not_owned" => "envcloak.toml is owned by another user",
        "directory_changed" => "the project directory changed while it was opened",
        // Bindings.
        "unknown_item" => "no item has that slug",
        "unknown_field" => "the item has no field of that name",
        "ambiguous_field" => "the item has several fields: name one with <slug>#<field>",
        "no_field" => "the item has no fields",
        "card_reference" => "a reference names a card, which is never bound to a variable",
        "issuer_credential_reference" => {
            "a reference names an issuer credential, which is never bound to a variable"
        }
        "unknown_item_class" => "a reference names an item of a class that cannot be bound",
        // Approval options.
        "ttl_zero" => "the grant length must be more than zero",
        "ttl_too_long" => "the grant length is over the limit (24h for an agent, 12h otherwise)",
        "live_not_bound" => "a --live name is not one of the request's variables",
        // Items.
        "item_changed" => "the slug names another item than the one shown; run it again",
        "invalid_slug" => {
            "a slug is lowercase letters and digits, then those, `.`, `_` or `-`, in parts \
             separated by `/` (at most 128 bytes)"
        }
        "invalid_field" => {
            "a field name is lowercase letters, digits, `_`, `.` or `-` (at most 64 bytes)"
        }
        "unknown_provider" => "no provider has that name",
        "invalid_account" => {
            "an account is 1 to 254 bytes without blanks, control or invisible characters"
        }
        "looks_like_value" => {
            "a name is shaped like a key or token; values are never taken as names"
        }
        "empty_value" => "the value is empty",
        "nul_byte" => "the value holds a NUL byte, which no environment variable can carry",
        "value_too_large" => "the value is larger than 64 KiB",
        "no_free_slug" => "every numbered slug for it is taken; give one with --slug",
        "requester_terminal" => {
            "this terminal or its session is where the request came from; approve it from another \
             terminal window"
        }
        _ => "no detail",
    }
}

/// What must hold before this process reads, shows or sends a secret or a
/// proof (SPEC §5 "Process hardening"): no tracer is attached.
/// Non-dumpable keeps new same-uid attaches out, but not a tracer that
/// started the process (`strace`, `gdb`), so the CLI refuses instead.
/// When the check cannot tell, it refuses too.
pub fn refuse_if_traced() -> Result<(), Failure> {
    match envcloak_sys::tracer_present() {
        Ok(false) => Ok(()),
        Ok(true) | Err(_) => Err(Failure::new(
            "traced",
            "a debugger or tracer is attached to this process, so it will not handle secrets",
        )),
    }
}

/// A usage error: never echoes the arguments, one of which could be a
/// pasted secret.
pub fn usage(text: &'static str) -> ExitCode {
    eprintln!("envcloak: usage: {text}");
    ExitCode::from(USAGE)
}
