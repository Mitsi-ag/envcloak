//! The one place the hook handler reads a payload's bytes (listed in
//! security/expose-allowlist.txt): parsed in place into the JSON object
//! the host sent, which [`super::decide`] reads and drops. A prompt or a
//! tool's input may hold a key; only a decision leaves.

use envcloak_core::SecretBuf;
use secrecy::ExposeSecret;
use serde_json::{Map, Value};

use super::{Event, Host, MAX_PAYLOAD, claude, codex};

/// A payload as read.
pub(super) enum Parsed {
    /// Over [`MAX_PAYLOAD`]: not read.
    TooLarge,
    /// Not JSON, not an object, or not the shape `--host` and `--event`
    /// name.
    Unfit,
    /// The object the host sent for this event.
    Fits(Map<String, Value>),
}

/// `payload`, read as `host`'s `event`.
pub(super) fn parse(host: Host, event: Event, payload: &SecretBuf) -> Parsed {
    #[allow(clippy::disallowed_methods)]
    let bytes: &[u8] = payload.expose_secret();
    if bytes.len() > MAX_PAYLOAD {
        return Parsed::TooLarge;
    }
    let Ok(Value::Object(p)) = serde_json::from_slice::<Value>(bytes) else {
        return Parsed::Unfit;
    };
    let fits = match host {
        Host::ClaudeCode => claude::fits(event, &p),
        Host::Codex => codex::fits(event, &p),
    };
    if fits { Parsed::Fits(p) } else { Parsed::Unfit }
}
