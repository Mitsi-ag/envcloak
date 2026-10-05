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
//!   was started; nothing ran. Its token, and with `approval_required`
//!   the request id and the test items the daemon proposed in place of
//!   live ones (SPEC §10b "Live-key guard": the `approval_required` text
//!   names them), at most [`MAX_PROPOSALS`] with a count of the rest.
//! - [`RunStatus::Ran`]: the command was started and followed to its end:
//!   its exit code, or the signal that ended it or stopped the run.
//! - [`RunStatus::Unknown`]: the command may have been started, and how it
//!   ended is not known (the runner failed after the spawn).
//!
//! The record is one line of JSON, at most [`MAX_RECORD`] bytes. One
//! without proposals is at most [`ONE_WRITE`] bytes, written with one
//! `write`: a pipe takes a write of up to 512 bytes whole (POSIX's
//! `PIPE_BUF` minimum), so the reader never sees part of one. One that
//! names proposals can be longer and take several writes; the command
//! never holds the descriptor, so no other writer comes between them, and
//! a record cut short (the run killed while writing it) is no record. It
//! carries no value, no output and no free text: a token, an id, a number,
//! and the proposals' names, each of the shape the daemon gives it
//! ([`Proposal::well_formed`]). A reader takes only the exact bytes
//! [`RunStatus::encode`] writes for a well-formed record; a missing record,
//! a second one, one cut short, one too long, one of an unknown version,
//! one written any other way (other spacing, field order or case) or any
//! other malformed one is [`RunStatus::Unknown`] ([`RunStatus::decode`]):
//! never "not run".

use std::io::{self, Write};

use envcloak_policy::{PendingId, Proposal};
use serde::{Deserialize, Serialize};

/// The longest record without proposals, its newline included: one write
/// a pipe takes whole.
pub const ONE_WRITE: usize = 512;
/// The most proposals a record names; it counts the rest.
pub const MAX_PROPOSALS: usize = 8;
/// The longest record, its newline included: [`MAX_PROPOSALS`] proposals
/// of the longest names fit.
pub const MAX_RECORD: usize = 8 * 1024;
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
        /// For `approval_required`: the test items the daemon proposed in
        /// place of live ones, at most [`MAX_PROPOSALS`].
        proposals: Vec<Proposal>,
        /// How many more it proposed than `proposals` names.
        proposals_left_out: u32,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    proposals: Vec<Proposal>,
    #[serde(default, skip_serializing_if = "is_zero")]
    proposals_left_out: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signal: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stopped: Option<i32>,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde passes a reference
fn is_zero(n: &u32) -> bool {
    *n == 0
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
    /// Refused before the command was started with `token`, nothing else
    /// to say.
    pub fn not_started(token: &str) -> RunStatus {
        RunStatus::NotStarted {
            token: token.to_owned(),
            request: None,
            proposals: Vec::new(),
            proposals_left_out: 0,
        }
    }

    /// `approval_required` for request `id`, naming the first
    /// [`MAX_PROPOSALS`] of `proposals` and counting the rest.
    pub fn approval_required(id: PendingId, proposals: &[Proposal]) -> RunStatus {
        let named = proposals.len().min(MAX_PROPOSALS);
        RunStatus::NotStarted {
            token: "approval_required".to_owned(),
            request: Some(id),
            proposals: proposals[..named].to_vec(),
            proposals_left_out: u32::try_from(proposals.len() - named).unwrap_or(u32::MAX),
        }
    }

    /// The record: one line of JSON.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Wire {
            v: VERSION,
            state: String::new(),
            token: None,
            request: None,
            proposals: Vec::new(),
            proposals_left_out: 0,
            code: None,
            signal: None,
            stopped: None,
        };
        match self {
            RunStatus::NotStarted {
                token,
                request,
                proposals,
                proposals_left_out,
            } => {
                "not_started".clone_into(&mut w.state);
                w.token = Some(token.clone());
                w.request = request.map(|id| id.to_string());
                w.proposals.clone_from(proposals);
                w.proposals_left_out = *proposals_left_out;
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

    /// Writes the record to `out`: with one write when it is at most
    /// [`ONE_WRITE`] bytes, as every record without proposals is.
    ///
    /// # Errors
    /// When the record is not one [`RunStatus::decode`] reads back (a
    /// token over 64 bytes, a malformed proposal, or more than
    /// [`MAX_PROPOSALS`], which no record carries), or the write fails or,
    /// for a record of one write, is short.
    pub fn write_to(&self, out: &mut impl Write) -> io::Result<()> {
        let line = self.encode();
        if line.len() > MAX_RECORD || self.decoded_again(&line).is_none() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if line.len() > ONE_WRITE {
            out.write_all(&line)?;
            return out.flush();
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

    /// The record in `bytes`, all a reader received: exactly the line
    /// [`RunStatus::encode`] writes for a record of this version whose
    /// every field is as its state requires, at most [`MAX_RECORD`] bytes.
    /// Anything else, a well-formed record written another way included,
    /// is `None`, which a reader takes as [`RunStatus::Unknown`]: one
    /// writer, one encoding, so no second reading of a record exists.
    pub fn decode(bytes: &[u8]) -> Option<RunStatus> {
        RunStatus::parse_fields(bytes).filter(|s| s.encode() == bytes)
    }

    /// The record `bytes` describes, read field by field (see
    /// [`RunStatus::decode`], which also requires the exact encoding).
    fn parse_fields(bytes: &[u8]) -> Option<RunStatus> {
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
        let no_proposals = w.proposals.is_empty() && w.proposals_left_out == 0;
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
                // Proposals only with a request; at most MAX_PROPOSALS,
                // counted beyond only when that many are named; each of
                // the daemon's shapes, no variable twice.
                if !no_proposals
                    && (request.is_none()
                        || w.proposals.len() > MAX_PROPOSALS
                        || (w.proposals_left_out > 0 && w.proposals.len() < MAX_PROPOSALS)
                        || !w.proposals.iter().all(Proposal::well_formed)
                        || w.proposals.iter().enumerate().any(|(i, x)| {
                            w.proposals[..i].iter().any(|y| y.env_name == x.env_name)
                        }))
                {
                    return None;
                }
                Some(RunStatus::NotStarted {
                    token,
                    request,
                    proposals: w.proposals,
                    proposals_left_out: w.proposals_left_out,
                })
            }
            "ran"
                if exit_given == 1 && w.token.is_none() && w.request.is_none() && no_proposals =>
            {
                let exit = match (w.code, w.signal, w.stopped) {
                    (Some(c), None, None) => Exit::Code(c),
                    (None, Some(s), None) if signal_number(s) => Exit::Signal(s),
                    (None, None, Some(s)) if signal_number(s) => Exit::Stopped(s),
                    _ => return None,
                };
                Some(RunStatus::Ran(exit))
            }
            "unknown"
                if exit_given == 0 && w.token.is_none() && w.request.is_none() && no_proposals =>
            {
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
        let many: Vec<Proposal> = (0..MAX_PROPOSALS + 3).map(longest).collect();
        for s in [
            RunStatus::approval_required(id, &[]),
            RunStatus::approval_required(id, &many[..1]),
            RunStatus::approval_required(id, &many[..MAX_PROPOSALS]),
            RunStatus::not_started("vault_locked"),
            RunStatus::Ran(Exit::Code(0)),
            RunStatus::Ran(Exit::Code(125)),
            RunStatus::Ran(Exit::Signal(15)),
            RunStatus::Ran(Exit::Stopped(2)),
            RunStatus::Unknown,
        ] {
            let mut out = Vec::new();
            s.write_to(&mut out).unwrap();
            assert!(out.len() <= MAX_RECORD);
            // One write a pipe takes whole, for every record that names no
            // proposal.
            if !matches!(&s, RunStatus::NotStarted { proposals, .. } if !proposals.is_empty()) {
                assert!(out.len() <= ONE_WRITE, "{s:?}");
            }
            assert_eq!(out.iter().filter(|b| **b == b'\n').count(), 1);
            assert_eq!(RunStatus::decode(&out), Some(s.clone()), "{s:?}");
        }
        // Only the encoding written: the same record with the id in
        // lower case, or with a space, is not it.
        let lower = format!(
            "{{\"v\":1,\"state\":\"not_started\",\"token\":\"approval_required\",\"request\":\"{}\"}}\n",
            id.to_string().to_ascii_lowercase()
        );
        assert_eq!(RunStatus::decode(lower.as_bytes()), None);
        assert_eq!(
            RunStatus::decode(b"{\"v\":1, \"state\":\"unknown\"}\n"),
            None
        );
        assert_eq!(
            RunStatus::decode(b"{\"state\":\"unknown\",\"v\":1}\n"),
            None
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
        let s = RunStatus::not_started(&token);
        assert!(s.write_to(&mut Vec::new()).is_err());
    }

    /// The `n`th proposal, every name as long as its grammar allows, from
    /// a profile of the longest name: the longest a record carries.
    fn longest(n: usize) -> Proposal {
        let name = format!("{}{n:03}", "A".repeat(125));
        let slug = |kind: &str| format!("{kind}/{}", "s".repeat(127 - kind.len()));
        Proposal {
            env_name: name,
            live_slug: slug("live"),
            test_slug: slug("test"),
            test_field: Some("f".repeat(64)),
            source: envcloak_policy::BindingSource::Profile {
                profile: "p".repeat(64),
            },
        }
    }

    /// Proposals in a record (SPEC §10b "Live-key guard"): at most
    /// `MAX_PROPOSALS` named, of the longest names, fit `MAX_RECORD`, the
    /// rest counted; more are counted, never dropped unsaid. Only with
    /// `approval_required` and its request, each of the daemon's shapes,
    /// no variable twice, and a count only past a full list: anything else
    /// is no record.
    #[test]
    fn proposals_are_named_with_a_request_and_counted_past_the_cap() {
        let id = PendingId::generate();
        let many: Vec<Proposal> = (0..MAX_PROPOSALS + 3).map(longest).collect();
        assert!(many.iter().all(Proposal::well_formed));
        let s = RunStatus::approval_required(id, &many);
        let RunStatus::NotStarted {
            proposals,
            proposals_left_out,
            ..
        } = &s
        else {
            unreachable!()
        };
        assert_eq!(proposals.as_slice(), &many[..MAX_PROPOSALS]);
        assert_eq!(*proposals_left_out, 3);
        let mut out = Vec::new();
        s.write_to(&mut out).unwrap();
        assert!(
            out.len() > ONE_WRITE && out.len() <= MAX_RECORD,
            "{}",
            out.len()
        );
        assert_eq!(RunStatus::decode(&out), Some(s.clone()));

        // Each malformed variant of a good record's own encoding is no
        // record.
        let good = RunStatus::approval_required(id, &many[..2]);
        let text = String::from_utf8(good.encode()).unwrap();
        assert_eq!(RunStatus::decode(text.as_bytes()), Some(good.clone()));
        let (first, second) = (&many[0], &many[1]);
        let at_end = |s: &str| text.replacen("}\n", &format!("{s}}}\n"), 1);
        let bad = [
            // Another token, or no request.
            text.replacen("\"approval_required\"", "\"vault_locked\"", 1),
            text.replacen(&format!(",\"request\":\"{id}\""), "", 1),
            // A variable twice.
            text.replacen(&second.env_name, &first.env_name, 1),
            // Names not of the daemon's shapes.
            text.replacen(&first.test_slug, "Not A Slug", 1),
            text.replacen(&first.env_name, "1BAD", 1),
            text.replacen(
                &format!("\"profile\":\"{}\"", "p".repeat(64)),
                "\"profile\":\"no such/name\"",
                1,
            ),
            // A count past a list that is not full.
            at_end(",\"proposals_left_out\":1"),
            // An unknown field in a proposal.
            text.replacen("\"source\":", "\"value\":\"x\",\"source\":", 1),
        ];
        for (i, b) in bad.iter().enumerate() {
            assert_ne!(*b, text, "variant {i} changed nothing");
            assert_eq!(RunStatus::decode(b.as_bytes()), None, "variant {i}");
        }
        // More than MAX_PROPOSALS named is no record, and is never written.
        let over = RunStatus::NotStarted {
            token: "approval_required".into(),
            request: Some(id),
            proposals: many.clone(),
            proposals_left_out: 0,
        };
        assert_eq!(RunStatus::decode(&over.encode()), None);
        assert!(over.write_to(&mut Vec::new()).is_err());
        // Nor are proposals with another outcome.
        let ran = String::from_utf8(RunStatus::Ran(Exit::Code(0)).encode()).unwrap();
        let with = ran.replacen(
            "}",
            &format!(
                ",\"proposals\":{}}}",
                serde_json::to_string(&many[..1]).unwrap()
            ),
            1,
        );
        assert_eq!(RunStatus::decode(with.as_bytes()), None);
    }
}
