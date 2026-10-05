//! How the CLI reports its own failures: one line on stderr, `envcloak:
//! <token>: <message>`, with a stable token (SPEC §6.1 "Failures") and a
//! message built from fixed text. Neither ever holds an argument, a value
//! or text the daemon sent.

use std::borrow::Cow;
use std::process::ExitCode;

use envcloak_ipc::ClientError;
use envcloak_ipc::proto::ErrorKind;

/// Exit code of a usage error.
pub const USAGE: u8 = 2;
/// Exit code of `run`'s own failures, apart from the child's codes.
pub const RUN_FAILURE: u8 = 125;
/// Exit code of every other command's failures.
pub const FAILURE: u8 = 1;

/// A failure's stable token (SPEC §6.1 "Failures"): fixed text, never an
/// argument or a value.
pub type ExitToken = &'static str;

/// A failure to report.
///
/// Its fields are private: a failure gets its token only where it is made
/// ([`Failure::new`], or a conversion in this file), never after, so
/// `scripts/check-reservations.py` reads every token a failure can carry
/// where it is made (review of M2-RES1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    token: ExitToken,
    message: Cow<'static, str>,
}

impl Failure {
    pub fn new(token: ExitToken, message: impl Into<Cow<'static, str>>) -> Self {
        Failure {
            token,
            message: message.into(),
        }
    }

    /// The failure's stable token.
    pub fn token(&self) -> ExitToken {
        self.token
    }

    /// The failure's message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The same failure with `tail` after its message (`<message>;
    /// <tail>`).
    #[must_use]
    pub fn with_tail(self, tail: &str) -> Self {
        Failure {
            token: self.token,
            message: format!("{}; {tail}", self.message).into(),
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
                Some(reason) => {
                    format!("{} ({})", r.kind.message(), reason_text_for(r.kind, reason)).into()
                }
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

/// Words for each error reason token of `REASONS` that an error carries
/// (the reasons a `run` is denied for have theirs in `DenyReason`).
const REASON_TEXTS: &[(&str, &str)] = &[
    ("not_text", "the passphrase must be UTF-8 text"),
    (
        "control_character",
        "the passphrase must not contain control characters",
    ),
    (
        "too_short",
        "the passphrase must be at least 12 characters long",
    ),
    ("common", "the passphrase is a commonly used password"),
    ("busy", "the vault file is in use by another process"),
    ("damaged", "the vault file is damaged"),
    (
        "unsupported_version",
        "the vault was written by a newer EnvCloak",
    ),
    (
        "permissions",
        "a vault directory or file has unsafe permissions or ownership",
    ),
    ("disk_full", "the disk is full"),
    ("storage", "the vault storage failed"),
    ("io", "the vault file or the manifest could not be accessed"),
    ("migration", "the vault format could not be upgraded"),
    // Caller evidence.
    (
        "caller_gone",
        "this process exited before its ancestry could be read",
    ),
    (
        "ancestry_changed",
        "this process's ancestry kept changing while it was read",
    ),
    (
        "ancestry_hidden",
        "a process in this process's ancestry is hidden from the daemon (Linux: /proc \
         mounted with hidepid; see docs/AGENTS.md)",
    ),
    (
        "ancestry_unreadable",
        "this process's ancestry could not be read",
    ),
    (
        "caller_is_init",
        "this process is pid 1, which no grant is rooted at; run it under a shell or an init",
    ),
    // The manifest.
    ("too_large", "the manifest is larger than 64 KiB"),
    ("not_utf8", "the manifest is not UTF-8"),
    ("syntax", "the manifest is not valid TOML"),
    ("duplicate_key", "the manifest defines a key twice"),
    ("unknown_key", "the manifest has an unknown key"),
    ("wrong_type", "a manifest value has the wrong type"),
    (
        "invalid_env_name",
        "a variable name in the manifest or a --ref is invalid",
    ),
    ("invalid_profile_name", "the profile name is invalid"),
    ("nested_profile", "profiles do not nest"),
    (
        "invalid_reference",
        "a reference in the manifest or a --ref is invalid",
    ),
    ("invalid_project_name", "the project name is invalid"),
    (
        "loose_policy",
        "the manifest's [policy] tries to loosen policy, which is refused",
    ),
    (
        "invalid_policy",
        "the manifest's [policy] has an invalid value",
    ),
    ("unknown_profile", "the manifest has no such profile"),
    ("duplicate_env_name", "a variable is bound twice"),
    (
        "invalid_path",
        "the manifest path is not absolute, or not named envcloak.toml",
    ),
    ("not_found", "no envcloak.toml there"),
    (
        "symlinked_manifest",
        "envcloak.toml is a symlink, which is refused",
    ),
    ("not_regular_file", "envcloak.toml is not a regular file"),
    ("not_owned", "envcloak.toml is owned by another user"),
    (
        "directory_changed",
        "the project directory changed while it was opened",
    ),
    // Bindings.
    ("unknown_item", "no item has that slug"),
    ("unknown_field", "the item has no field of that name"),
    (
        "ambiguous_field",
        "the item has several fields: name one with <slug>#<field>",
    ),
    ("no_field", "the item has no fields"),
    (
        "card_reference",
        "a reference names a card, which is never bound to a variable",
    ),
    (
        "issuer_credential_reference",
        "a reference names an issuer credential, which is never bound to a variable",
    ),
    (
        "unknown_item_class",
        "a reference names an item of a class that cannot be bound",
    ),
    // Approval options.
    ("ttl_zero", "the grant length must be more than zero"),
    (
        "ttl_too_long",
        "the grant length is over the limit (24h for an agent, 12h otherwise)",
    ),
    (
        "live_not_bound",
        "a --live name is not one of the request's variables",
    ),
    // The pending cap a request met (`too_many_pending`).
    (
        "pending_per_root",
        "this process tree already has 3 requests waiting for approval",
    ),
    (
        "pending_total",
        "20 requests are already waiting for approval",
    ),
    // Items.
    (
        "item_changed",
        "the slug names another item than the one shown; run it again",
    ),
    (
        "invalid_slug",
        "a slug is lowercase letters and digits, then those, `.`, `_` or `-`, in parts \
         separated by `/` (at most 128 bytes)",
    ),
    (
        "invalid_field",
        "a field name is lowercase letters, digits, `_`, `.` or `-` (at most 64 bytes)",
    ),
    ("unknown_provider", "no provider has that name"),
    (
        "invalid_account",
        "an account is 1 to 254 bytes without blanks, control or invisible characters",
    ),
    (
        "looks_like_value",
        "a name is shaped like a key or token; values are never taken as names",
    ),
    ("empty_value", "the value is empty"),
    (
        "nul_byte",
        "the value holds a NUL byte, which no environment variable can carry",
    ),
    ("value_too_large", "the value is larger than 64 KiB"),
    (
        "no_free_slug",
        "every numbered slug for it is taken; give one with --slug",
    ),
    (
        "requester_terminal",
        "this terminal or its session is where the request came from; approve it from another \
         terminal window",
    ),
    // A backup v2 restore refused before the proof (`restore_refused`).
    (
        "result_unrecorded",
        "the backup does not record what the change left (the process that made it never \
         recorded it, or an earlier EnvCloak made it), so EnvCloak cannot check the file \
         against it; only the recovery form `--unrecorded` restores it",
    ),
    (
        "created_by_agent",
        "the backup was made by an agent or an unknown process, or does not record who made \
         it; restoring it writes bytes that process stored, so it needs `--created-by-agent`",
    ),
    // A backup replaced under its name, or cut or written into, before it
    // was checked in place (`files_backup_failed`).
    (
        "substituted",
        "something replaced or changed the backup inside the vault's directory before it was \
         checked in place, so it was not taken as written; nothing was deleted",
    ),
    // A comparison budget stopped a scan (`too_many_checks` from
    // `scan.match`): the run is incomplete.
    // A managed launch declaration refused (`code_selecting_env`, M2-27):
    // the server is reported manual.
    (
        "code_selecting_variable",
        "the launch sets a variable that selects code (a loader, interpreter or runtime \
         variable such as NODE_OPTIONS or LD_PRELOAD), so EnvCloak cannot check what runs",
    ),
    (
        "interpreter_option",
        "the launch gives its interpreter an option that loads other code (such as node -r), \
         so EnvCloak cannot check what runs",
    ),
    (
        "limited",
        "this process tree has used an hour's comparisons with the vault (100,000 short values \
         for a person's import, 2,000,000 others), so nothing more was compared and the run is \
         incomplete; run it again later",
    ),
];

/// Words for `reason` on an error of `kind`: [`reason_text`], except for
/// a backup v2 over its caps (`files_backup_failed` with `too_large`).
fn reason_text_for(kind: ErrorKind, reason: &str) -> &'static str {
    if kind == ErrorKind::FilesBackupFailed && reason == "too_large" {
        "a file is over 256 MiB, the files are over 1 GiB in all, or there are more than 4,096 \
         of them"
    } else {
        reason_text(reason)
    }
}

/// Words for an error's reason token.
fn reason_text(reason: &str) -> &'static str {
    REASON_TEXTS
        .iter()
        .find(|(name, _)| *name == reason)
        .map_or("no detail", |(_, text)| text)
}

/// What must hold before this process reads, shows or sends a secret or a
/// proof (SPEC §5 "Process hardening"): no tracer is attached.
/// Non-dumpable keeps new same-uid attaches out, but not a tracer that
/// started the process (`strace`, `gdb`), so the CLI refuses instead.
/// When the check cannot tell, it refuses too.
pub fn refuse_if_traced() -> Result<(), Failure> {
    match envcloak_sys::tracer_present() {
        Ok(false) => Ok(()),
        Ok(true) | Err(_) => Err(traced()),
    }
}

/// The `traced` failure: a tracer is attached to this process (or whether
/// one is could not be read).
pub fn traced() -> Failure {
    Failure::new(
        "traced",
        "a debugger or tracer is attached to this process, so it will not handle secrets",
    )
}

/// A usage error: never echoes the arguments, one of which could be a
/// pasted secret.
pub fn usage(text: &'static str) -> ExitCode {
    eprintln!("envcloak: usage: {text}");
    ExitCode::from(USAGE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use envcloak_ipc::proto::REASONS;
    use envcloak_policy::DenyReason;

    /// A backup v2 over its caps says which caps; `too_large` elsewhere
    /// keeps the manifest's words.
    #[test]
    fn a_backup_over_its_caps_has_words_of_its_own() {
        assert!(reason_text_for(ErrorKind::FilesBackupFailed, "too_large").contains("256 MiB"));
        assert_eq!(
            reason_text_for(ErrorKind::ManifestInvalid, "too_large"),
            reason_text("too_large")
        );
    }

    /// Review R-7: two lanes adding reason tokens could leave one without
    /// words, printed as "no detail". Every token of `REASONS` has words
    /// here, once, unless it is a reason a `run` is denied for, which
    /// `DenyReason` words; and every token here is one of `REASONS`.
    #[test]
    fn every_reason_token_has_words() {
        for token in REASONS {
            let here = REASON_TEXTS.iter().filter(|(t, _)| t == token).count();
            if DenyReason::from_token(token).is_some() {
                assert_eq!(here, 0, "{token}");
            } else {
                assert_eq!(here, 1, "{token}");
                assert_ne!(reason_text(token), "no detail", "{token}");
            }
        }
        for (token, text) in REASON_TEXTS {
            assert!(REASONS.contains(token), "{token}");
            assert!(!text.is_empty(), "{token}");
        }
        assert_eq!(reason_text("not_a_reason"), "no detail");
    }
}
