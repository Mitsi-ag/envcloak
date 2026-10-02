//! JSON-RPC 2.0 messages as MCP's stdio transport carries them: one per
//! line, never a batch (MCP 2025-06-18 removed batching).
//!
//! [`parse`] reads one line, already bounded by [`crate::stdio`], and
//! tells a request, a notification and a message to answer with an error
//! apart. Nothing from the input is ever put in an error: each error is a
//! code and fixed text ([`error`]). The one thing echoed is a request's
//! id, which JSON-RPC requires in its answer, and only an id of the shape
//! [`Id`] takes, which a key, a URL, a passphrase or a Recovery Kit does
//! not have; any other is answered as an invalid request with a `null`
//! id. (The host chose the id, and a short plain string, such as a token
//! of under [`MAX_ID_SYMBOLS`] letters and digits, cannot be told from
//! one.)

use serde_json::{Map, Value, json};

/// The input was not one JSON value of valid UTF-8 within the line cap.
pub const PARSE_ERROR: i64 = -32700;
/// Valid JSON that is not a request or notification: a batch, a missing
/// or wrong `jsonrpc`, an id of a shape this server does not take, or a
/// request out of the session's order.
pub const INVALID_REQUEST: i64 = -32600;
/// No such method. (A `tools/call` naming a tool that is not listed is
/// [`INVALID_PARAMS`], with [`UNKNOWN_TOOL`], as MCP has it.)
pub const METHOD_NOT_FOUND: i64 = -32601;
/// Parameters of the wrong shape, or a `tools/call` naming a tool that is
/// not listed ([`UNKNOWN_TOOL`]).
pub const INVALID_PARAMS: i64 = -32602;
/// The message for a `tools/call` naming a tool that is not listed:
/// nothing has that name, or a tool that has it is registered but not
/// listed. The two are answered alike.
pub const UNKNOWN_TOOL: &str = "unknown tool: tools/list shows the tools";
/// The call queue is full: the error kind `busy` of EnvCloak's own
/// protocol (docs/IPC.md), reused for the MCP server's queue.
pub const BUSY: i64 = -32008;

/// The longest string id taken.
pub const MAX_ID: usize = 64;
/// The most letters and digits a string id may hold, in all: one short
/// of the shortest run a key is taken to be
/// ([`envcloak_policy::VALUE_RUN`]), so that a key, or a Recovery Kit
/// (28 symbols in groups joined by `-`), is refused whatever separates
/// its parts.
pub const MAX_ID_SYMBOLS: usize = envcloak_policy::VALUE_RUN - 1;
/// The longest method name looked at; a longer one is not one this server
/// has.
pub const MAX_METHOD: usize = 64;

/// A request id: an integer, or a string of at most [`MAX_ID`] ASCII
/// letters, digits, `_`, `-`, `.` and `:`, holding at most
/// [`MAX_ID_SYMBOLS`] letters and digits in all, that is not shaped like
/// a key (`envcloak_client::render::looks_like_value`). Anything else
/// could carry a value that the answer would echo, so it is refused: a
/// Recovery Kit, and a key split by separators, are too long in letters
/// and digits; so is a UUID, a common shape for API keys. MCP clients
/// number their requests, which this takes whole.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum Id {
    Signed(i64),
    Unsigned(u64),
    Text(String),
}

impl std::fmt::Debug for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Id::Signed(n) => write!(f, "Id({n})"),
            Id::Unsigned(n) => write!(f, "Id({n})"),
            Id::Text(s) => write!(f, "Id(<{} bytes>)", s.len()),
        }
    }
}

impl Id {
    /// The id in `v`, when it is one this server takes.
    pub fn from_value(v: &Value) -> Option<Id> {
        match v {
            Value::Number(n) => n
                .as_i64()
                .map(Id::Signed)
                .or_else(|| n.as_u64().map(Id::Unsigned)),
            Value::String(s) => {
                let shaped = !s.is_empty()
                    && s.len() <= MAX_ID
                    && s.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':')
                    })
                    && s.bytes().filter(u8::is_ascii_alphanumeric).count() <= MAX_ID_SYMBOLS;
                (shaped && !envcloak_client::render::looks_like_value(s))
                    .then(|| Id::Text(s.clone()))
            }
            _ => None,
        }
    }

    /// The id as JSON, as it came.
    pub fn to_value(&self) -> Value {
        match self {
            Id::Signed(n) => json!(n),
            Id::Unsigned(n) => json!(n),
            Id::Text(s) => json!(s),
        }
    }
}

/// One line, read. Its `Debug` shows kinds and lengths, never the method
/// or the parameters, which could hold a pasted key (L-12).
pub enum Incoming {
    /// A request: answered with a result or an error for its id.
    Request {
        id: Id,
        method: String,
        params: Option<Map<String, Value>>,
    },
    /// A notification: never answered.
    Notification {
        method: String,
        params: Option<Map<String, Value>>,
    },
    /// A response or error from the client: this server sends no requests,
    /// so it is dropped.
    Response,
    /// To be answered with this error code, and the id when it was one
    /// this server takes (`null` otherwise).
    Invalid {
        id: Option<Id>,
        code: i64,
        message: &'static str,
    },
}

impl std::fmt::Debug for Incoming {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let params = |p: &Option<Map<String, Value>>| p.as_ref().map(Map::len);
        match self {
            Incoming::Request {
                id,
                method,
                params: p,
            } => f
                .debug_struct("Request")
                .field("id", id)
                .field("method_bytes", &method.len())
                .field("params", &params(p))
                .finish(),
            Incoming::Notification { method, params: p } => f
                .debug_struct("Notification")
                .field("method_bytes", &method.len())
                .field("params", &params(p))
                .finish(),
            Incoming::Response => f.write_str("Response"),
            Incoming::Invalid { id, code, message } => f
                .debug_struct("Invalid")
                .field("id", id)
                .field("code", code)
                .field("message", message)
                .finish(),
        }
    }
}

/// Reads one line (without its newline).
pub fn parse(line: &[u8]) -> Incoming {
    let invalid = |id: Option<Id>, code, message| Incoming::Invalid { id, code, message };
    let Ok(text) = std::str::from_utf8(line) else {
        return invalid(None, PARSE_ERROR, PARSE_MESSAGE);
    };
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        return invalid(None, PARSE_ERROR, PARSE_MESSAGE);
    };
    let mut obj = match value {
        Value::Object(o) => o,
        Value::Array(_) => {
            return invalid(
                None,
                INVALID_REQUEST,
                "batches are not accepted: send one message per line",
            );
        }
        _ => return invalid(None, INVALID_REQUEST, "a message must be a JSON object"),
    };
    let id = match obj.get("id") {
        None => None,
        Some(v) => match Id::from_value(v) {
            Some(id) => Some(id),
            None => {
                return invalid(
                    None,
                    INVALID_REQUEST,
                    "an id must be an integer, or a short string of letters, digits, `_`, `-`, \
                     `.` and `:` that is not shaped like a key or token",
                );
            }
        },
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return invalid(id, INVALID_REQUEST, "`jsonrpc` must be \"2.0\"");
    }
    let method = match obj.remove("method") {
        Some(Value::String(m)) => m,
        Some(_) => return invalid(id, INVALID_REQUEST, "`method` must be a string"),
        None if obj.contains_key("result") || obj.contains_key("error") => {
            return Incoming::Response;
        }
        None => return invalid(id, INVALID_REQUEST, "a request needs a `method`"),
    };
    let params = match obj.remove("params") {
        None => None,
        Some(Value::Object(p)) => Some(p),
        Some(_) => match id {
            Some(id) => {
                return invalid(Some(id), INVALID_PARAMS, "`params` must be an object");
            }
            // A notification is never answered; one with params of the
            // wrong shape is dropped.
            None => return Incoming::Response,
        },
    };
    match id {
        Some(id) => Incoming::Request { id, method, params },
        None => Incoming::Notification { method, params },
    }
}

/// The message for [`PARSE_ERROR`].
pub const PARSE_MESSAGE: &str = "parse error: each line must be one JSON-RPC message in valid UTF-8, \
     of at most 1 MiB, with no newline inside it";

/// A result for `id`, as one line.
pub fn result(id: &Id, result: Value) -> Vec<u8> {
    line(&json!({"jsonrpc": "2.0", "id": id.to_value(), "result": result}))
}

/// An error for `id` (`null` when there is none), as one line: a code and
/// fixed text, never anything from the input.
pub fn error(id: Option<&Id>, code: i64, message: &'static str) -> Vec<u8> {
    let id = id.map_or(Value::Null, Id::to_value);
    line(&json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}))
}

/// `v` as one line of compact JSON: a newline inside a string is written
/// escaped, so the only newline is the one that ends it.
fn line(v: &Value) -> Vec<u8> {
    let mut out = serde_json::to_vec(v).unwrap_or_else(|_| b"null".to_vec());
    out.push(b'\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code_of(i: &Incoming) -> Option<i64> {
        match i {
            Incoming::Invalid { code, .. } => Some(*code),
            _ => None,
        }
    }

    #[test]
    fn requests_notifications_and_errors_are_told_apart() {
        match parse(br#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#) {
            Incoming::Request { id, method, params } => {
                assert_eq!(id, Id::Signed(7));
                assert_eq!(method, "ping");
                assert!(params.is_none());
            }
            other => panic!("{other:?}"),
        }
        match parse(br#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#) {
            Incoming::Notification { method, params } => {
                assert_eq!(method, "notifications/initialized");
                assert!(params.is_some());
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
            Incoming::Response
        ));
        for (line, code) in [
            (&b"{"[..], PARSE_ERROR),
            (b"", PARSE_ERROR),
            (b"\xff\xfe", PARSE_ERROR),
            (b"[]", INVALID_REQUEST),
            (
                br#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#,
                INVALID_REQUEST,
            ),
            (b"7", INVALID_REQUEST),
            (br#"{"id":1,"method":"ping"}"#, INVALID_REQUEST),
            (
                br#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#,
                INVALID_REQUEST,
            ),
            (br#"{"jsonrpc":"2.0","id":1}"#, INVALID_REQUEST),
            (br#"{"jsonrpc":"2.0","id":1,"method":7}"#, INVALID_REQUEST),
            (
                br#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
                INVALID_REQUEST,
            ),
            (
                br#"{"jsonrpc":"2.0","id":1.5,"method":"ping"}"#,
                INVALID_REQUEST,
            ),
            (
                br#"{"jsonrpc":"2.0","id":{},"method":"ping"}"#,
                INVALID_REQUEST,
            ),
            (
                br#"{"jsonrpc":"2.0","id":"a b","method":"ping"}"#,
                INVALID_REQUEST,
            ),
            (
                br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[1]}"#,
                INVALID_PARAMS,
            ),
        ] {
            assert_eq!(code_of(&parse(line)), Some(code), "{line:?}");
        }
        // An id that could carry a value is refused, and answered `null`.
        let keyish = format!(
            r#"{{"jsonrpc":"2.0","id":"{}","method":"ping"}}"#,
            "aB3".repeat(9)
        );
        match parse(keyish.as_bytes()) {
            Incoming::Invalid { id, code, .. } => {
                assert_eq!(id, None);
                assert_eq!(code, INVALID_REQUEST);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            Id::from_value(&json!("req-1.a:b_c")),
            Some(Id::Text("req-1.a:b_c".into()))
        );
        assert_eq!(Id::from_value(&json!("x".repeat(MAX_ID + 1))), None);
        assert_eq!(
            Id::from_value(&json!(u64::MAX)),
            Some(Id::Unsigned(u64::MAX))
        );
        assert_eq!(Id::from_value(&json!(-3)), Some(Id::Signed(-3)));
        assert_eq!(format!("{:?}", Id::Text("abc".into())), "Id(<3 bytes>)");
    }

    /// What was read is never in its `Debug`: a key pasted as a method, a
    /// parameter's name or a value shows as lengths only (L-12).
    ///
    /// Mutation checked: `Incoming` deriving `Debug`: the key shows and
    /// this fails.
    #[test]
    fn what_was_read_is_never_in_its_debug() {
        let cs = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
        for c in &cs {
            let k = c.as_str();
            for line in [
                json!({"jsonrpc": "2.0", "id": 1, "method": k, "params": {k: k}}),
                json!({"jsonrpc": "2.0", "method": k, "params": {"x": k}}),
            ] {
                let shown = format!("{:?}", parse(line.to_string().as_bytes()));
                envcloak_testkit::assert_no_canary(shown.as_bytes(), &cs);
            }
        }
    }

    /// A string id is echoed only when it cannot hold a key: real Recovery
    /// Kits (seven groups of four symbols joined by `-`), the fixture keys
    /// split at every place by each separator the grammar takes, and a
    /// UUID are refused, and answered with a `null` id; the ids clients
    /// send are taken.
    ///
    /// Mutations checked: no count of letters and digits (the shape and
    /// `looks_like_value` alone): every kit, and every split key, is taken
    /// as an id and this fails. No `looks_like_value` (the shape and the
    /// count alone): an AWS access key id, 20 letters and digits, is taken
    /// as an id and this fails (verifier, M2-06 round 2).
    #[test]
    fn ids_that_could_hold_a_kit_or_a_key_are_refused() {
        let refused = |s: &str| {
            let line = json!({"jsonrpc": "2.0", "id": s, "method": "ping"}).to_string();
            match parse(line.as_bytes()) {
                Incoming::Invalid { id: None, code, .. } => code == INVALID_REQUEST,
                _ => false,
            }
        };
        for _ in 0..64 {
            let kit = envcloak_core::recovery::RecoveryKit::generate().to_display();
            assert!(refused(&kit), "a Recovery Kit was taken as an id");
            assert!(refused(&kit.to_lowercase()));
            assert!(refused(&kit.replace('-', "")));
            assert!(refused(&kit.replace('-', ".")));
        }
        let cs = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
        for c in &cs {
            let alnum: String = c
                .as_str()
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .collect();
            if alnum.len() < envcloak_policy::VALUE_RUN {
                continue;
            }
            for sep in ["-", "_", ".", ":"] {
                for at in 1..alnum.len().min(MAX_ID) {
                    let split = format!("{}{sep}{}", &alnum[..at], &alnum[at..]);
                    if split.len() <= MAX_ID {
                        assert!(refused(&split), "{} split at {at}", c.label);
                    }
                }
            }
        }
        assert!(refused("123e4567-e89b-12d3-a456-426614174000"));
        // The registry's key patterns with fewer letters and digits than
        // the count refuses, built here at run time: AWS access key ids
        // (`AKIA` or `ASIA` and 16 of `A-Z2-7`: 20) and Stripe keys with a
        // body of 10 to 17 (16 to 23). Only their pattern refuses them.
        let seed = envcloak_testkit::fresh_seed();
        let pick = |alphabet: &[u8], n: usize, salt: u64| -> String {
            let mut x = (seed ^ salt) | 1;
            (0..n)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    let at = usize::try_from(x % alphabet.len() as u64).unwrap();
                    char::from(alphabet[at])
                })
                .collect()
        };
        let base32 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let alnum = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let mut short_keys = Vec::new();
        for (i, start) in ["AK", "AS"].into_iter().enumerate() {
            for salt in 0..16u64 {
                short_keys.push(format!(
                    "{start}IA{}",
                    pick(base32, 16, salt * 2 + i as u64)
                ));
            }
        }
        for kind in ["s", "r", "p"] {
            for mode in ["live", "test"] {
                for body in 10..=17 {
                    let salt = body as u64 * 7 + u64::from(kind.as_bytes()[0]);
                    short_keys.push(format!("{kind}k_{mode}_{}", pick(alnum, body, salt)));
                }
            }
        }
        for key in &short_keys {
            let symbols = key.bytes().filter(u8::is_ascii_alphanumeric).count();
            assert!(symbols <= MAX_ID_SYMBOLS, "{symbols}");
            assert!(
                refused(key),
                "a key of a registry pattern was taken as an id"
            );
        }
        for ok in [
            "1",
            "req-1",
            "1a2b3c4d-5",
            "call_42",
            "a.b:c-d_e",
            &"x".repeat(MAX_ID_SYMBOLS),
        ] {
            assert!(!refused(ok), "{ok}");
            assert_eq!(Id::from_value(&json!(ok)), Some(Id::Text(ok.to_owned())));
        }
        assert!(refused(&"x".repeat(MAX_ID_SYMBOLS + 1)));
        assert!(refused(&"x-".repeat(MAX_ID_SYMBOLS + 1)));
    }

    #[test]
    fn answers_are_one_line_with_fixed_errors() {
        let r = result(&Id::Text("a\nb".into()), json!({"text": "x\ny"}));
        assert_eq!(r.iter().filter(|b| **b == b'\n').count(), 1);
        assert!(r.ends_with(b"\n"));
        let e = error(None, PARSE_ERROR, PARSE_MESSAGE);
        let v: Value = serde_json::from_slice(&e).unwrap();
        assert_eq!(v["id"], Value::Null);
        assert_eq!(v["error"]["code"], PARSE_ERROR);
    }
}
