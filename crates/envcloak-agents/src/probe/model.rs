//! The scripted model (M2 plan task M2-04, decision D-13): what the agent
//! hosts talk to instead of a real model when EnvCloak drives them, in CI
//! and in `envcloak agents status --probe` (M2-28).
//!
//! It is shipped as its own program, `envcloak-probe-model`, and is never
//! linked into `envcloak` or `envcloakd`. A run:
//!
//! - listens on `127.0.0.1` only, on a port the system picks, and refuses
//!   a connection from any other address;
//! - makes a per-run [`Token`] that every request must present as its API
//!   key (`x-api-key: <token>` or `Authorization: Bearer <token>`), and
//!   answers any other request `401`;
//! - stops at its time limit;
//! - reads requests with a hand-written HTTP/1.1 parser ([`http`]):
//!   `Content-Length` bodies only, at most 4 MiB a body and 16 MiB recorded
//!   in all, after which the run is *incomplete* and says why ([`Outcome`]);
//! - records at most 1,024 requests and 1 MiB of what describes them
//!   (method, target, header names), whatever path a request takes (a
//!   refused token, a tunnel, Claude Code's connectivity check), then
//!   refuses the rest and is incomplete;
//! - answers `POST /v1/messages` (Anthropic Messages) and `POST
//!   /v1/responses` (OpenAI Responses) from a [`Script`] ([`wire`]), and any
//!   other path `404`, recording it, so a host that calls something new
//!   fails the run loudly instead of being half served;
//! - refuses a request meant for a proxy, a tunnel (`CONNECT host:port`)
//!   or a request to forward (an absolute `http://` or `https://` target),
//!   in HTTP/1.1 or 1.0, and records the `host:port` it names, so with a
//!   host's proxy variables pointed at it a run shows every other place
//!   the host tried to reach;
//! - records every request it accepts with its whole body, held in wiping
//!   buffers and wiped when the run ends.
//!
//! The program is driven over its standard input and output, never over
//! the network: the first line in is the script as JSON; the first line
//! out is `{"addr": "127.0.0.1:<port>", "token": "<token>"}`. Then each
//! input line `requests` is answered with one line `{"final": false,
//! "requests": [...], "outcome": {...}}`, the line `release <name>`
//! releases a barrier (a step's `after`), and the line `stop`, or the end
//! of input, ends the run with a last line whose `final` is true. The
//! program exits 0 when the run was complete, 3 when it was not or its
//! last line was not read within 10 s (the records are wiped either way),
//! and 2 on a usage error. A request's body is base64 in `body`; its headers are
//! listed by name, never by value. [`ModelStub`] is the client side.
//!
//! The pinned hosts the wire protocols are qualified against are in
//! [`QUALIFIED`]: a host version outside it is `not_qualified`, which
//! `agents status --probe` reports instead of a probe result.

pub mod http;
pub mod script;
pub mod server;
pub mod wire;

mod stub;

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub use script::{Script, ScriptError, Step};
pub use server::{Handle, SERVER, Server};
pub use stub::ModelStub;

/// Test hooks, with the `testing` feature only: a connection handed to the
/// server as if from any peer ([`admit_as`]), and one connection's bytes
/// served from memory ([`serve_bytes`], the hostile-input tests). No build
/// of `envcloak-probe-model` has them
/// (crates/envcloak-agents/tests/release_features.rs).
#[cfg(feature = "testing")]
pub use server::{admit_as, serve_bytes};

/// A host version the scripted model was qualified against: its requests
/// were recorded and served end to end in CI (M2-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qualified {
    /// The host's catalog id (`integrations/agents.toml`).
    pub host: &'static str,
    /// The version `<host> --version` reports.
    pub version: &'static str,
    /// The protocol it speaks to the stub.
    pub api: wire::Api,
}

/// The qualified host versions (crates/envcloak-e2e/agents/versions.toml
/// pins the same ones; a test keeps the two equal).
pub const QUALIFIED: &[Qualified] = &[
    Qualified {
        host: "claude-code",
        version: "2.1.280",
        api: wire::Api::Messages,
    },
    Qualified {
        host: "codex",
        version: "0.159.2",
        api: wire::Api::Responses,
    },
];

/// Whether `host` at `version` is in [`QUALIFIED`].
pub fn qualified(host: &str, version: &str) -> bool {
    QUALIFIED
        .iter()
        .any(|q| q.host == host && q.version == version)
}

/// A run's limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most bytes one request body may have (4 MiB).
    pub body: usize,
    /// The most body bytes the run records in all (16 MiB).
    pub total: usize,
    /// How long the run may last.
    pub time: Duration,
    /// How long a connection may sit idle.
    pub idle: Duration,
    /// The most connections open at once.
    pub connections: usize,
    /// The most requests the run records, whatever their path (1,024).
    pub records: usize,
    /// The most bytes of request metadata the run records in all (1 MiB):
    /// each record's method, path, query and header names, and
    /// [`RECORD_OVERHEAD`] for the record itself.
    pub meta: usize,
}

/// What each recorded request counts against [`Limits::meta`] besides its
/// own text, so that requests with nothing in them are bounded too.
pub const RECORD_OVERHEAD: usize = 64;

impl Default for Limits {
    fn default() -> Self {
        Limits {
            body: 4 * 1024 * 1024,
            total: 16 * 1024 * 1024,
            time: Duration::from_secs(600),
            idle: Duration::from_secs(30),
            connections: 32,
            records: 1024,
            meta: 1024 * 1024,
        }
    }
}

/// A run's token: `ecp_` and 40 random hexadecimal digits. Not a secret
/// beyond the run, but never printed by `Debug`.
#[derive(Clone)]
pub struct Token(Zeroizing<String>);

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(..)")
    }
}

impl Token {
    /// A fresh token.
    ///
    /// # Errors
    /// When the system has no random bytes to give.
    pub fn generate() -> std::io::Result<Token> {
        let mut raw = Zeroizing::new([0u8; 20]);
        getrandom::fill(&mut *raw).map_err(std::io::Error::other)?;
        let mut s = Zeroizing::new(String::with_capacity(44));
        s.push_str("ecp_");
        for b in raw.iter() {
            s.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
            s.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
        }
        Ok(Token(s))
    }

    /// A token received from a running model.
    pub fn from_text(text: Zeroizing<String>) -> Token {
        Token(text)
    }

    /// The token, to hand to a host as its API key.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn equals(&self, presented: &[u8]) -> bool {
        let mine = self.0.as_bytes();
        mine.len() == presented.len() && bool::from(mine.ct_eq(presented))
    }

    /// Whether `head` presents this token, in every credential header it
    /// has and in at least one: `x-api-key: <token>` or `Authorization:
    /// Bearer <token>`.
    pub fn admits(&self, head: &http::Head) -> bool {
        let key = head.api_key.as_ref().map(|k| self.equals(k));
        let bearer = head
            .authorization
            .as_ref()
            .map(|a| a.strip_prefix(b"Bearer ").is_some_and(|t| self.equals(t)));
        match (key, bearer) {
            (None, None) => false,
            (k, b) => k.unwrap_or(true) && b.unwrap_or(true),
        }
    }
}

/// Why a run is incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Incomplete {
    /// A request body was larger than the per-body cap.
    BodyCap,
    /// The run reached the cap on recorded bytes.
    TotalCap,
    /// The run reached its time limit.
    TimeLimit,
    /// The run reached the cap on recorded requests or on their metadata.
    RecordCap,
    /// The run ended while a reply was held on a barrier: it was never
    /// sent.
    HeldReply,
}

impl Incomplete {
    /// The name the report gives it.
    pub fn name(self) -> &'static str {
        match self {
            Incomplete::BodyCap => "body_cap",
            Incomplete::TotalCap => "total_cap",
            Incomplete::TimeLimit => "time_limit",
            Incomplete::RecordCap => "record_cap",
            Incomplete::HeldReply => "held_reply",
        }
    }
}

/// What happened in a run, besides the requests it recorded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    /// Why the run is incomplete; empty when it is complete.
    pub incomplete: Vec<String>,
    /// Requests for a path the stub does not serve (answered 404).
    pub unknown: u64,
    /// Requests without the run's token (answered 401).
    pub bad_token: u64,
    /// Connections from an address that is not loopback (closed).
    pub bad_peer: u64,
    /// Requests outside the HTTP grammar, cut short, or with a body that
    /// is not its API's JSON (answered 400 or closed).
    pub malformed: u64,
    /// Steps that call the shell when the request offered no shell tool.
    pub mismatch: u64,
    /// Requests past the script's last step.
    pub exhausted: u64,
    /// Connections refused because the cap on open ones was reached.
    pub busy: u64,
    /// Requests meant for a proxy (a `CONNECT host:port` tunnel, or an
    /// absolute target to forward), refused: what a host tried to reach
    /// besides the model. Not a failure of the run.
    pub connect: u64,
    /// Recorded requests whose reply was never sent whole: held on a
    /// barrier when the run ended, or the connection failed first.
    pub unanswered: u64,
    /// Body bytes recorded.
    pub recorded_bytes: u64,
    /// Metadata bytes recorded ([`Limits::meta`]).
    pub recorded_meta: u64,
}

impl Outcome {
    /// Adds `why` once.
    pub fn mark(&mut self, why: Incomplete) {
        let name = why.name().to_owned();
        if !self.incomplete.contains(&name) {
            self.incomplete.push(name);
        }
    }

    /// Whether the run is complete: no cap or limit was reached.
    pub fn complete(&self) -> bool {
        self.incomplete.is_empty()
    }

    /// Whether the run is complete and every request was one the script
    /// served: nothing unknown, refused, malformed or unscripted.
    pub fn clean(&self) -> bool {
        self.complete()
            && self.unknown == 0
            && self.bad_token == 0
            && self.bad_peer == 0
            && self.malformed == 0
            && self.mismatch == 0
            && self.exhausted == 0
            && self.busy == 0
            && self.unanswered == 0
    }
}

/// One request the stub accepted. `Debug` leaves the body out, and shows
/// the target only as the endpoint it names or by its length.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recorded {
    /// Its number in the run, from 1.
    pub seq: u64,
    /// When it came, in milliseconds since the run started.
    pub at_ms: u64,
    /// The method.
    pub method: String,
    /// The target's path.
    pub path: String,
    /// The target's query.
    pub query: Option<String>,
    /// Its header names, lower-cased, in order; never their values.
    pub headers: Vec<String>,
    /// The status it is answered with.
    pub status: u16,
    /// Whether that answer was sent whole. A reply held on a barrier is
    /// recorded before it is sent, unanswered, so a run that ends while it
    /// is held says so.
    pub answered: bool,
    /// `messages` or `responses`, for a request to one of the two APIs;
    /// `hello` for Claude Code's connectivity check; `connect` for a
    /// tunnel and `proxy` for a request to forward, whose `path` is the
    /// `host:port` it names.
    pub api: Option<String>,
    /// What the script gave it: `step <n>`, `side`, `exhausted` or
    /// `mismatch`.
    pub pick: Option<String>,
    /// The whole body (empty for a refused request, whose body is never
    /// read), base64 on the wire.
    #[serde(with = "b64")]
    pub body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Recorded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recorded")
            .field("seq", &self.seq)
            .field("at_ms", &self.at_ms)
            .field("method", &self.method)
            .field(
                "target",
                &http::shown_target(&self.path, self.query.as_deref()),
            )
            .field("status", &self.status)
            .field("answered", &self.answered)
            .field("api", &self.api)
            .field("pick", &self.pick)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

impl Recorded {
    fn without_body(seq: u64, at: Duration, head: &http::Head, status: u16) -> Recorded {
        Recorded {
            seq,
            at_ms: u64::try_from(at.as_millis()).unwrap_or(u64::MAX),
            method: head.method.clone(),
            path: head.path.clone(),
            query: head.query.clone(),
            headers: head.header_names.clone(),
            status,
            answered: false,
            api: None,
            pick: None,
            body: Zeroizing::new(Vec::new()),
        }
    }

    /// What this record counts against [`Limits::meta`].
    pub fn meta_len(&self) -> usize {
        meta_len(
            &self.method,
            &self.path,
            self.query.as_deref(),
            &self.headers,
        )
    }

    /// The body parsed as JSON, when it is JSON.
    pub fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

/// What a request with this method, path, query and header names counts
/// against [`Limits::meta`].
fn meta_len(method: &str, path: &str, query: Option<&str>, headers: &[String]) -> usize {
    RECORD_OVERHEAD
        + method.len()
        + path.len()
        + query.map_or(0, str::len)
        + headers.iter().map(String::len).sum::<usize>()
}

/// A run's report, as the program writes it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// Whether the run has ended.
    #[serde(rename = "final")]
    pub last: bool,
    /// Every request recorded, in order.
    pub requests: Vec<Recorded>,
    /// What happened.
    pub outcome: Outcome,
}

#[derive(Serialize)]
struct ReportRef<'a> {
    #[serde(rename = "final")]
    last: bool,
    requests: &'a [Recorded],
    outcome: &'a Outcome,
}

mod b64 {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};
    use zeroize::Zeroizing;

    pub(super) fn serialize<S: Serializer>(
        v: &Zeroizing<Vec<u8>>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let text = Zeroizing::new(STANDARD.encode(v.as_slice()));
        s.serialize_str(&text)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Zeroizing<Vec<u8>>, D::Error> {
        let text = Zeroizing::new(String::deserialize(d)?);
        STANDARD
            .decode(text.as_bytes())
            .map(Zeroizing::new)
            .map_err(|_| D::Error::custom("a body that is not base64"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(extra: &str) -> http::Head {
        let text = format!("POST /v1/messages HTTP/1.1\r\nHost: x\r\n{extra}\r\n");
        http::parse_head(text.as_bytes(), 10).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn tokens_are_fresh_and_compared_whole() {
        let t = Token::generate().unwrap_or_else(|e| panic!("{e}"));
        let u = Token::generate().unwrap_or_else(|e| panic!("{e}"));
        assert_ne!(t.as_str(), u.as_str());
        assert_eq!(t.as_str().len(), 44);
        assert!(t.as_str().starts_with("ecp_"));
        assert_eq!(format!("{t:?}"), "Token(..)");
        let tok = t.as_str();
        assert!(t.admits(&head(&format!("x-api-key: {tok}\r\n"))));
        assert!(t.admits(&head(&format!("Authorization: Bearer {tok}\r\n"))));
        assert!(t.admits(&head(&format!(
            "x-api-key: {tok}\r\nAuthorization: Bearer {tok}\r\n"
        ))));
        assert!(!t.admits(&head("")));
        assert!(!t.admits(&head(&format!("x-api-key: {}\r\n", u.as_str()))));
        assert!(!t.admits(&head(&format!("x-api-key: {}\r\n", &tok[..43]))));
        assert!(!t.admits(&head(&format!("x-api-key: {tok}x\r\n"))));
        assert!(!t.admits(&head(&format!("Authorization: {tok}\r\n"))));
        assert!(!t.admits(&head(&format!(
            "x-api-key: {tok}\r\nAuthorization: Bearer {}\r\n",
            u.as_str()
        ))));
    }

    #[test]
    fn outcomes_say_why_a_run_is_incomplete() {
        let mut o = Outcome::default();
        assert!(o.complete() && o.clean());
        o.unknown = 1;
        assert!(o.complete() && !o.clean());
        o.mark(Incomplete::BodyCap);
        o.mark(Incomplete::BodyCap);
        assert_eq!(o.incomplete, ["body_cap"]);
        assert!(!o.complete());
    }

    #[test]
    fn the_qualified_table_names_each_pinned_host_once() {
        assert!(qualified("claude-code", "2.1.280"));
        assert!(qualified("codex", "0.159.2"));
        assert!(!qualified("codex", "0.159.3"));
        let mut hosts: Vec<&str> = QUALIFIED.iter().map(|q| q.host).collect();
        hosts.sort_unstable();
        hosts.dedup();
        assert_eq!(hosts.len(), QUALIFIED.len());
    }
}
