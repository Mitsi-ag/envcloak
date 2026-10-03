//! The one place the hook handler reads a payload's bytes (listed in
//! security/expose-allowlist.txt): parsed in place into the JSON object
//! the host sent, which [`super::decide`] reads and drops. A prompt or a
//! tool's input may hold a key; only a decision leaves, and every string
//! the object holds is wiped when it is dropped ([`Wiped`]).

use std::ops::Deref;

use envcloak_core::SecretBuf;
use secrecy::ExposeSecret;
use serde_json::{Map, Value};
use zeroize::Zeroize;

use super::{Event, Host, MAX_PAYLOAD, claude, codex};

/// A payload's JSON object, its strings and keys wiped on drop (lesson
/// L-12: a pasted key read out of the wiped input buffer is wiped again
/// here, not left in freed memory).
pub(super) struct Wiped(Map<String, Value>);

impl Deref for Wiped {
    type Target = Map<String, Value>;

    fn deref(&self) -> &Map<String, Value> {
        &self.0
    }
}

/// Wipes every string `v` holds, at any depth.
pub(super) fn wipe(v: Value) {
    let mut stack = vec![v];
    while let Some(v) = stack.pop() {
        match v {
            Value::String(mut s) => s.zeroize(),
            Value::Array(a) => stack.extend(a),
            Value::Object(o) => {
                for (mut k, v) in o {
                    k.zeroize();
                    stack.push(v);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
}

impl Drop for Wiped {
    fn drop(&mut self) {
        wipe(Value::Object(std::mem::take(&mut self.0)));
    }
}

/// A payload as read.
pub(super) enum Parsed {
    /// Over [`MAX_PAYLOAD`]: not read.
    TooLarge,
    /// Not JSON, not an object, or not the shape `--host` and `--event`
    /// name.
    Unfit,
    /// The object the host sent for this event.
    Fits(Wiped),
}

/// `payload`, read as `host`'s `event`.
pub(super) fn parse(host: Host, event: Event, payload: &SecretBuf) -> Parsed {
    #[allow(clippy::disallowed_methods)]
    let bytes: &[u8] = payload.expose_secret();
    if bytes.len() > MAX_PAYLOAD {
        return Parsed::TooLarge;
    }
    let p = match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(p)) => Wiped(p),
        Ok(other) => {
            wipe(other);
            return Parsed::Unfit;
        }
        Err(_) => return Parsed::Unfit,
    };
    let fits = match host {
        Host::ClaudeCode => claude::fits(event, &p),
        Host::Codex => codex::fits(event, &p),
    };
    if fits { Parsed::Fits(p) } else { Parsed::Unfit }
}
