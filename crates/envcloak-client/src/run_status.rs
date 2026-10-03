//! The status record of `envcloak run --status-fd N`: how a run ended,
//! written for the program that started it on a descriptor the command
//! cannot reach (Codex F-113; M2 plan M2-RES1).
//!
//! A command's exit code and its output are the command's own: one that
//! exits 125 after printing `envcloak: approval_required: ...` looks, by
//! those alone, exactly like `envcloak run` refusing before it started
//! anything. `envcloak mcp` therefore never reads the outcome from them.
//! It hands `envcloak run` the write end of a pipe of its own as
//! descriptor `N`; `envcloak run` sets the close-on-exec flag on it (and
//! on every other descriptor it inherited above the standard streams)
//! before it starts anything, so the command never holds it, and writes
//! one record there as it ends:
//!
//! - [`RunStatus::NotStarted`]: EnvCloak's own failure before the command
//!   was started; nothing ran. Its token, and the request id when the
//!   failure is `approval_required`.
//! - [`RunStatus::Ran`]: the command was started and followed to its end:
//!   its exit code, or the signal that ended it or stopped the run.
//! - [`RunStatus::Unknown`]: the command may have been started, and how it
//!   ended is not known (the runner failed after the spawn).
//!
//! The record is one line of JSON, at most [`MAX_RECORD`] bytes, written
//! with one `write`: a pipe takes a write of up to 512 bytes whole
//! (POSIX's `PIPE_BUF` minimum), so the reader never sees part of one. It
//! carries no value, no output and no free text: a token, an id, a number.
//! A reader takes a missing record, a second one, one cut short, one too
//! long, one of an unknown version or any other malformed one as
//! [`RunStatus::Unknown`] ([`RunStatus::decode`]): never as "not run".

use std::io::{self, Write};

use envcloak_policy::PendingId;
use serde::{Deserialize, Serialize};

/// The longest record, its newline included: one write a pipe takes
/// whole.
pub const MAX_RECORD: usize = 512;
/// The record's version.
pub const VERSION: u32 = 1;
/// The longest token a record carries.
const MAX_TOKEN: usize = 64;

/// How the command ended, as [`RunStatus::Ran`] reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// It exited with this code.
    Code(u8),
    /// This signal ended it.
    Signal(i32),
    /// It exited, and this signal, caught after its exit, stopped the run
    /// before its output was all read.
    Stopped(i32),
}

/// How a run ended: see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunStatus {
    /// Refused before the command was started: nothing ran.
    NotStarted {
        /// The failure's token (SPEC §6.1 "Failures").
        token: String,
        /// The pending request, for `approval_required`.
        request: Option<PendingId>,
    },
    /// The command was started and followed to its end.
    Ran(Exit),
    /// The command may have been started; how it ended is not known.
    Unknown,
}

/// The record as it is written.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    v: u32,
    state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signal: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stopped: Option<i32>,
}

/// Whether `t` is shaped like a failure token.
fn token_shaped(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= MAX_TOKEN
        && t.as_bytes()[0].is_ascii_lowercase()
        && t.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Whether `s` is a signal number a process can be ended by.
fn signal_number(s: i32) -> bool {
    (1..=127).contains(&s)
}

impl RunStatus {
    /// The record: one line of JSON.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Wire {
            v: VERSION,
            state: String::new(),
            token: None,
            request: None,
            code: None,
            signal: None,
            stopped: None,
        };
        match self {
            RunStatus::NotStarted { token, request } => {
                "not_started".clone_into(&mut w.state);
                w.token = Some(token.clone());
                w.request = request.map(|id| id.to_string());
            }
            RunStatus::Ran(exit) => {
                "ran".clone_into(&mut w.state);
                match *exit {
                    Exit::Code(c) => w.code = Some(c),
                    Exit::Signal(s) => w.signal = Some(s),
                    Exit::Stopped(s) => w.stopped = Some(s),
                }
            }
            RunStatus::Unknown => "unknown".clone_into(&mut w.state),
        }
        let mut line = serde_json::to_vec(&w).unwrap_or_default();
        line.push(b'\n');
        line
    }

    /// Writes the record to `out` with one write.
    ///
    /// # Errors
    /// When the record would be longer than [`MAX_RECORD`] (a token over
    /// 64 bytes, which no record carries), or the write fails or is
    /// short.
    pub fn write_to(&self, out: &mut impl Write) -> io::Result<()> {
        let line = self.encode();
        if line.len() > MAX_RECORD || self.decoded_again(&line).is_none() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let n = out.write(&line)?;
        if n != line.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        out.flush()
    }

    /// `line` decoded, when it is this record.
    fn decoded_again(&self, line: &[u8]) -> Option<RunStatus> {
        RunStatus::decode(line).filter(|d| d == self)
    }

    /// The record in `bytes`, all a reader received: exactly one line of
    /// at most [`MAX_RECORD`] bytes, this version, each field as its state
    /// requires. Anything else is `None`, which a reader takes as
    /// [`RunStatus::Unknown`].
    pub fn decode(bytes: &[u8]) -> Option<RunStatus> {
        if bytes.len() > MAX_RECORD {
            return None;
        }
        let line = bytes.strip_suffix(b"\n")?;
        if line.contains(&b'\n') {
            return None;
        }
        let w: Wire = serde_json::from_slice(line).ok()?;
        if w.v != VERSION {
            return None;
        }
        let exits = [w.code.is_some(), w.signal.is_some(), w.stopped.is_some()];
        let exit_given = exits.iter().filter(|x| **x).count();
        match w.state.as_str() {
            "not_started" if exit_given == 0 => {
                let token = w.token.filter(|t| token_shaped(t))?;
                let request = match w.request {
                    None => None,
                    Some(r) => Some(PendingId::parse(&r)?),
                };
                if request.is_some() && token != "approval_required" {
                    return None;
                }
                Some(RunStatus::NotStarted { token, request })
            }
            "ran" if exit_given == 1 && w.token.is_none() && w.request.is_none() => {
                let exit = match (w.code, w.signal, w.stopped) {
                    (Some(c), None, None) => Exit::Code(c),
                    (None, Some(s), None) if signal_number(s) => Exit::Signal(s),
                    (None, None, Some(s)) if signal_number(s) => Exit::Stopped(s),
                    _ => return None,
                };
                Some(RunStatus::Ran(exit))
            }
            "unknown" if exit_given == 0 && w.token.is_none() && w.request.is_none() => {
                Some(RunStatus::Unknown)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_record_reads_back_as_written() {
        let id = PendingId::generate();
        for s in [
            RunStatus::NotStarted {
                token: "approval_required".into(),
                request: Some(id),
            },
            RunStatus::NotStarted {
                token: "vault_locked".into(),
                request: None,
            },
            RunStatus::Ran(Exit::Code(0)),
            RunStatus::Ran(Exit::Code(125)),
            RunStatus::Ran(Exit::Signal(15)),
            RunStatus::Ran(Exit::Stopped(2)),
            RunStatus::Unknown,
        ] {
            let mut out = Vec::new();
            s.write_to(&mut out).unwrap();
            assert!(out.len() <= MAX_RECORD);
            assert_eq!(out.iter().filter(|b| **b == b'\n').count(), 1);
            assert_eq!(RunStatus::decode(&out), Some(s.clone()), "{s:?}");
        }
        // The id in either case is the same request, shown canonically.
        let lower = format!(
            "{{\"v\":1,\"state\":\"not_started\",\"token\":\"approval_required\",\"request\":\"{}\"}}\n",
            id.to_string().to_ascii_lowercase()
        );
        assert_eq!(
            RunStatus::decode(lower.as_bytes()),
            Some(RunStatus::NotStarted {
                token: "approval_required".into(),
                request: Some(id)
            })
        );
    }

    /// Anything but one well-formed record of this version is no record:
    /// missing, two, cut short, too long, another version, an unknown or
    /// doubled field, fields its state does not take, a malformed token
    /// or id, an out-of-range signal.
    #[test]
    fn anything_else_is_no_record() {
        let good = RunStatus::Ran(Exit::Code(3)).encode();
        let mut two = good.clone();
        two.extend_from_slice(&good);
        let mut long = br#"{"v":1,"state":"unknown"}"#.to_vec();
        long.extend(std::iter::repeat_n(b' ', MAX_RECORD));
        long.push(b'\n');
        for bad in [
            &b""[..],
            &two,
            &good[..good.len() - 1],
            &good[..5],
            &long,
            br#"{"v":2,"state":"unknown"}
"#,
            br#"{"v":1,"state":"unknown","extra":1}
"#,
            br#"{"v":1,"v":1,"state":"unknown"}
"#,
            br#"{"v":1,"state":"started"}
"#,
            br#"{"v":1,"state":"ran"}
"#,
            br#"{"v":1,"state":"ran","code":1,"signal":9}
"#,
            br#"{"v":1,"state":"ran","signal":0}
"#,
            br#"{"v":1,"state":"ran","signal":200}
"#,
            br#"{"v":1,"state":"ran","code":256}
"#,
            br#"{"v":1,"state":"ran","code":1,"token":"x"}
"#,
            br#"{"v":1,"state":"unknown","code":1}
"#,
            br#"{"v":1,"state":"not_started"}
"#,
            br#"{"v":1,"state":"not_started","token":"Vault_locked"}
"#,
            br#"{"v":1,"state":"not_started","token":"vault locked"}
"#,
            br#"{"v":1,"state":"not_started","token":"approval_required","request":"nope"}
"#,
            br#"{"v":1,"state":"not_started","token":"vault_locked","request":"ABCDEFGH"}
"#,
            br#"{"v":1,"state":"not_started","token":"vault_locked","code":125}
"#,
            b"not json\n",
            b"\xff\xfe\n",
        ] {
            assert_eq!(
                RunStatus::decode(bad),
                None,
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        let token = "a".repeat(MAX_TOKEN + 1);
        let s = RunStatus::NotStarted {
            token,
            request: None,
        };
        assert!(s.write_to(&mut Vec::new()).is_err());
    }
}
