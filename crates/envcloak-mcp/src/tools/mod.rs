//! The M2 tools (SPEC §7): [`list_secrets`], [`project_status`],
//! [`add_reference`], [`run_with_secrets`] and [`request_new_secret`].
//! None ever returns a value, and none takes one: a string argument shaped
//! like a key or token is refused unechoed ([`refuse_value_like`]).
//! Reveal and doctor are never tools, and `usage_summary` is not listed
//! before M4.
//!
//! Every argument is checked against the tool's input schema here, not
//! trusted to the host: an unknown property, a missing one or one of the
//! wrong type is refused with the same fixed text ([`invalid`]), which
//! names nothing from the input.

pub mod add_reference;
pub mod list_secrets;
pub mod project_status;
pub mod request_new_secret;
pub mod run_with_secrets;

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use envcloak_client::fail::Failure;
use envcloak_ipc::Client;
use envcloak_policy::PendingId;
use serde_json::{Map, Value, json};

use crate::router::Tool;

/// The most request ids [`Ctx`] remembers for `project_status`.
pub const MAX_TRACKED: usize = 32;
/// The longest path argument taken.
pub const MAX_PATH: usize = 4096;

/// What the tools share.
#[derive(Debug)]
pub struct Ctx {
    /// The absolute path of this `envcloak`, which a tool's children run.
    pub exe: PathBuf,
    /// The host `--host` named, when it named one.
    pub host: Option<String>,
    /// How long a tool waits for a person's approval, and at most for the
    /// daemon.
    pub wait: Duration,
    /// The requests this server's `run_with_secrets` calls opened, which
    /// `project_status` reports (an agent is never shown the person's list
    /// of pending requests, SPEC §10b).
    pending: Mutex<Tracked>,
}

/// The requests remembered, and whether one was not for want of room.
#[derive(Debug, Default)]
struct Tracked {
    ids: Vec<PendingId>,
    overflowed: bool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Ctx {
    pub fn new(exe: PathBuf, host: Option<String>, wait: Duration) -> Ctx {
        Ctx {
            exe,
            host,
            wait,
            pending: Mutex::new(Tracked::default()),
        }
    }

    /// Remembers `id`. False when [`MAX_TRACKED`] are remembered already:
    /// the id is then not, and `project_status` says that one was missed
    /// (a bounded store refuses rather than evicts, L-08).
    pub(crate) fn remember_pending(&self, id: PendingId) -> bool {
        let mut p = lock(&self.pending);
        if p.ids.contains(&id) {
            return true;
        }
        if p.ids.len() >= MAX_TRACKED {
            p.overflowed = true;
            return false;
        }
        p.ids.push(id);
        true
    }

    /// The requests remembered, and whether one was missed for want of
    /// room.
    pub(crate) fn pending_seen(&self) -> (Vec<PendingId>, bool) {
        let p = lock(&self.pending);
        (p.ids.clone(), p.overflowed)
    }

    /// Forgets `ids`, whose requests have ended.
    pub(crate) fn forget_pending(&self, ids: &[PendingId]) {
        lock(&self.pending).ids.retain(|id| !ids.contains(id));
    }

    /// A verified connection to the daemon whose every call is answered
    /// within the wait counted from `call`'s arrival (the time it waited
    /// for a worker included), or fails then.
    pub(crate) fn connect(&self, call: &crate::child::Call) -> Result<Client, Failure> {
        self.connect_by(call.deadline(self.wait))
    }

    /// A verified connection to the daemon whose every call is answered
    /// by `deadline`, or fails then.
    pub(crate) fn connect_by(&self, deadline: Instant) -> Result<Client, Failure> {
        let paths = envcloak_client::connect::run_paths()?;
        Client::connect_by(&paths, deadline).map_err(Failure::from)
    }
}

/// Every M2 tool, in the order `tools/list` shows them.
pub fn m2_tools() -> Vec<Box<dyn Tool>> {
    vec![
        Box::new(list_secrets::ListSecrets),
        Box::new(project_status::ProjectStatus),
        Box::new(add_reference::AddReference),
        Box::new(run_with_secrets::RunWithSecrets),
        Box::new(request_new_secret::RequestNewSecret),
    ]
}

/// The failure for arguments that do not match the input schema.
pub(crate) fn invalid() -> Failure {
    Failure::new(
        "invalid_params",
        "the arguments do not match this tool's input schema (tools/list shows it); nothing was \
         done",
    )
}

/// Checks that `args` has only properties of `allowed` and every one of
/// `required`.
pub(crate) fn check_keys(
    args: &Map<String, Value>,
    allowed: &[&str],
    required: &[&str],
) -> Result<(), Failure> {
    if args.keys().any(|k| !allowed.contains(&k.as_str()))
        || required.iter().any(|k| !args.contains_key(*k))
    {
        return Err(invalid());
    }
    Ok(())
}

/// The string property `key`, when present.
pub(crate) fn opt_str<'a>(
    args: &'a Map<String, Value>,
    key: &str,
) -> Result<Option<&'a str>, Failure> {
    match args.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(invalid()),
    }
}

/// The string property `key`, which must be present.
pub(crate) fn req_str<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, Failure> {
    opt_str(args, key)?.ok_or_else(invalid)
}

/// Refuses, unechoed, any of `names` shaped like a key or token (gate 13):
/// a tool never takes a value, so one there was most likely pasted.
pub(crate) fn refuse_value_like(names: &[&str]) -> Result<(), Failure> {
    if names
        .iter()
        .any(|n| envcloak_client::render::looks_like_value(n))
    {
        return Err(Failure::new(
            "value_on_argv",
            "an argument is shaped like a key or token, and EnvCloak's tools never take a value: \
             name keys by reference (list_secrets, add_reference); if it was a key, ask the \
             person to rotate it, since this conversation holds it now; nothing was done",
        ));
    }
    Ok(())
}

/// A `project_dir` argument: an absolute path to a directory.
pub(crate) fn project_dir(s: &str) -> Result<PathBuf, Failure> {
    if s.len() > MAX_PATH || s.contains('\0') || !Path::new(s).is_absolute() {
        return Err(Failure::new(
            "invalid_path",
            "project_dir must be the absolute path of the project's directory; nothing was done",
        ));
    }
    let p = PathBuf::from(s);
    if !p.is_dir() {
        return Err(Failure::new(
            "invalid_path",
            "project_dir is not a directory this process can open; nothing was done",
        ));
    }
    Ok(p)
}

/// The project's `envcloak.toml`: in `dir` or above it.
pub(crate) fn manifest_of(dir: &Path) -> Result<Option<PathBuf>, Failure> {
    envcloak_policy::find_manifest(dir).map_err(|_| {
        Failure::new(
            "manifest_invalid",
            "project_dir could not be read while looking for envcloak.toml",
        )
    })
}

/// A path as text, or the failure for one that is not UTF-8.
pub(crate) fn path_text(p: &Path) -> Result<String, Failure> {
    p.to_str().map(str::to_owned).ok_or_else(|| {
        Failure::new(
            "manifest_invalid",
            "the manifest's path is not valid UTF-8, which this build cannot send",
        )
    })
}

/// A name the daemon sent, as it may be shown: escaped, or a placeholder
/// when it looks like a value (`envcloak_client::render::shown`).
pub(crate) fn shown(s: &str) -> String {
    envcloak_client::render::shown(s)
}

/// A path the daemon sent, escaped.
pub(crate) fn shown_path(s: &str) -> String {
    envcloak_policy::escape_for_display(s)
}

/// A JSON Schema object with `properties`, `required` ones and no others.
pub(crate) fn object(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_checked_without_echo() {
        let args = json!({"a": "x", "b": 1}).as_object().cloned().unwrap();
        assert!(check_keys(&args, &["a", "b"], &["a"]).is_ok());
        assert!(check_keys(&args, &["a"], &[]).is_err());
        assert!(check_keys(&args, &["a", "b", "c"], &["c"]).is_err());
        assert_eq!(req_str(&args, "a").unwrap(), "x");
        assert!(req_str(&args, "b").is_err());
        assert!(req_str(&args, "c").is_err());
        assert_eq!(opt_str(&args, "c").unwrap(), None);
        let e = invalid();
        assert_eq!(e.token, "invalid_params");

        let cs = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
        for label in [
            envcloak_testkit::labels::OPENAI_API_KEY,
            envcloak_testkit::labels::STRIPE_SECRET_KEY,
            envcloak_testkit::labels::GITHUB_TOKEN,
        ] {
            let key = envcloak_testkit::by_label(&cs, label).as_str();
            let e = refuse_value_like(&["fine", key]).unwrap_err();
            assert_eq!(e.token, "value_on_argv");
            envcloak_testkit::assert_no_canary(e.message.as_bytes(), &cs);
        }
        assert!(refuse_value_like(&["openai/acme-web", "OPENAI_API_KEY"]).is_ok());

        for bad in ["", "relative/dir", "./x", "/no/such/dir/here", "/a\0b"] {
            assert_eq!(
                project_dir(bad).unwrap_err().token,
                "invalid_path",
                "{bad:?}"
            );
        }
        assert!(project_dir("/").is_ok());
    }

    #[test]
    fn requests_are_remembered_up_to_the_bound() {
        let ctx = Ctx::new(PathBuf::from("/x"), None, Duration::from_secs(1));
        let ids: Vec<PendingId> = (0..=MAX_TRACKED).map(|_| PendingId::generate()).collect();
        for id in &ids[..MAX_TRACKED] {
            assert!(ctx.remember_pending(*id));
        }
        assert!(ctx.remember_pending(ids[0]));
        assert!(!ctx.pending_seen().1);
        assert!(!ctx.remember_pending(ids[MAX_TRACKED]));
        assert!(ctx.pending_seen().1);
        ctx.forget_pending(&ids[..2]);
        assert_eq!(ctx.pending_seen().0.len(), MAX_TRACKED - 2);
        assert!(ctx.remember_pending(ids[MAX_TRACKED]));
    }
}
