//! Hostile input for the status record's reader (L-06; verifier review of
//! M2-RES1: `RunStatus::decode` had only a fixed table of bad records):
//! random bytes, valid records with random damage, and records whose
//! every field is drawn from good and bad values, in any order and
//! spacing. Whatever comes in, `decode` never panics, and it accepts
//! exactly the encodings of valid records: the oracle below writes the
//! one encoding by hand from docs/RUN.md's record and checks each field
//! by its own rules, apart from the reader's code. Everything else is
//! `None`, which a reader takes as unknown.
#![allow(clippy::unwrap_used)]

use envcloak_client::run_status::{Exit, MAX_RECORD, RunStatus};
use envcloak_policy::PendingId;
use proptest::prelude::*;

/// Crockford base32, as a request id is shown (8 characters).
const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The one encoding of `s`: its fields in the record's order, no white
/// space, one newline.
fn canonical(s: &RunStatus) -> String {
    match s {
        RunStatus::NotStarted {
            token,
            request: None,
        } => format!("{{\"v\":1,\"state\":\"not_started\",\"token\":\"{token}\"}}\n"),
        RunStatus::NotStarted {
            token,
            request: Some(id),
        } => format!(
            "{{\"v\":1,\"state\":\"not_started\",\"token\":\"{token}\",\"request\":\"{id}\"}}\n"
        ),
        RunStatus::Ran(Exit::Code(c)) => format!("{{\"v\":1,\"state\":\"ran\",\"code\":{c}}}\n"),
        RunStatus::Ran(Exit::Signal(n)) => {
            format!("{{\"v\":1,\"state\":\"ran\",\"signal\":{n}}}\n")
        }
        RunStatus::Ran(Exit::Stopped(n)) => {
            format!("{{\"v\":1,\"state\":\"ran\",\"stopped\":{n}}}\n")
        }
        RunStatus::Unknown => "{\"v\":1,\"state\":\"unknown\"}\n".to_owned(),
    }
}

/// A failure token: lower-case ASCII letters, digits and `_`, starting
/// with a letter, at most 64 bytes.
fn token_ok(t: &str) -> bool {
    let b = t.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// Whether `s` is a record a run can write.
fn valid(s: &RunStatus) -> bool {
    match s {
        RunStatus::NotStarted { token, request } => {
            token_ok(token) && (request.is_none() || token == "approval_required")
        }
        RunStatus::Ran(Exit::Code(_)) | RunStatus::Unknown => true,
        RunStatus::Ran(Exit::Signal(n) | Exit::Stopped(n)) => (1..=127).contains(n),
    }
}

/// Whether `id` is a request id as it is shown: 8 Crockford characters,
/// upper case.
fn id_shown(id: &str) -> bool {
    id.len() == 8 && id.bytes().all(|c| CROCKFORD.contains(&c))
}

/// One field of a record as drawn: its JSON value, or absent.
type Field = Option<String>;

/// A record's fields as drawn, and how it is written.
#[derive(Debug, Clone)]
struct Drawn {
    v: Field,
    state: Field,
    token: Field,
    request: Field,
    code: Field,
    signal: Field,
    stopped: Field,
    extra: bool,
    order: Vec<usize>,
    spaced: bool,
}

impl Drawn {
    /// The record's text, its fields in the drawn order.
    fn text(&self) -> String {
        let named = [
            ("v", &self.v),
            ("state", &self.state),
            ("token", &self.token),
            ("request", &self.request),
            ("code", &self.code),
            ("signal", &self.signal),
            ("stopped", &self.stopped),
        ];
        let mut parts: Vec<String> = Vec::new();
        for &i in &self.order {
            if let (name, Some(value)) = named[i] {
                parts.push(if self.spaced {
                    format!("\"{name}\": {value}")
                } else {
                    format!("\"{name}\":{value}")
                });
            }
        }
        if self.extra {
            parts.push("\"extra\":1".to_owned());
        }
        format!("{{{}}}\n", parts.join(if self.spaced { ", " } else { "," }))
    }

    /// What the reader must make of the text: the record, when every
    /// field is as its state requires and the text is its one encoding;
    /// else nothing.
    fn expected(&self) -> Option<RunStatus> {
        let string = |f: &Field| -> Option<String> {
            let v = f.as_ref()?;
            let inner = v.strip_prefix('"')?.strip_suffix('"')?;
            (!inner.contains(['"', '\\'])).then(|| inner.to_owned())
        };
        let number = |f: &Field| -> Option<i64> { f.as_ref()?.parse().ok() };
        if self.extra || self.v.as_deref() != Some("1") {
            return None;
        }
        let exits = [&self.code, &self.signal, &self.stopped]
            .iter()
            .filter(|f| f.is_some())
            .count();
        let record = match string(&self.state)?.as_str() {
            "not_started" => {
                if exits != 0 {
                    return None;
                }
                let token = string(&self.token)?;
                let request = match &self.request {
                    None => None,
                    Some(_) => {
                        let id = string(&self.request)?;
                        if !id_shown(&id) {
                            return None;
                        }
                        Some(PendingId::parse(&id)?)
                    }
                };
                RunStatus::NotStarted { token, request }
            }
            "ran" => {
                if exits != 1 || self.token.is_some() || self.request.is_some() {
                    return None;
                }
                if self.code.is_some() {
                    RunStatus::Ran(Exit::Code(u8::try_from(number(&self.code)?).ok()?))
                } else if self.signal.is_some() {
                    RunStatus::Ran(Exit::Signal(i32::try_from(number(&self.signal)?).ok()?))
                } else {
                    RunStatus::Ran(Exit::Stopped(i32::try_from(number(&self.stopped)?).ok()?))
                }
            }
            "unknown" => {
                if exits != 0 || self.token.is_some() || self.request.is_some() {
                    return None;
                }
                RunStatus::Unknown
            }
            _ => return None,
        };
        (valid(&record) && canonical(&record) == self.text()).then_some(record)
    }
}

fn quoted(s: impl Into<String>) -> String {
    format!("\"{}\"", s.into())
}

fn shown_id() -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::sample::select(CROCKFORD.to_vec()), 8)
        .prop_map(|b| String::from_utf8(b).unwrap())
}

/// Good and bad values for each field, in the record's order (`v`,
/// `state`, `token`, `request`, `code`, `signal`, `stopped`); `None` is
/// the field left out.
fn pools() -> [Vec<Field>; 7] {
    let some = |v: &[&str]| -> Vec<Field> {
        std::iter::once(None)
            .chain(v.iter().map(|s| Some((*s).to_owned())))
            .collect()
    };
    let long = |n: usize| quoted("a".repeat(n));
    let mut tokens = some(&[
        "\"approval_required\"",
        "\"vault_locked\"",
        "\"Vault_locked\"",
        "\"vault locked\"",
        "\"\"",
        "\"1abc\"",
        "null",
        "7",
    ]);
    tokens.extend([Some(long(64)), Some(long(65))]);
    let exit = some(&["0", "1", "15", "127", "128", "-5", "\"1\"", "1.0"]);
    [
        some(&["1", "0", "2", "\"1\"", "1.0"]),
        some(&[
            "\"not_started\"",
            "\"ran\"",
            "\"unknown\"",
            "\"started\"",
            "3",
        ]),
        tokens,
        some(&[
            "\"ABCDEFGH\"",
            "\"abcdefgh\"",
            "\"ABCDEFGI\"",
            "\"nope\"",
            "7",
        ]),
        some(&["0", "125", "255", "256", "-1", "\"1\""]),
        exit.clone(),
        exit,
    ]
}

/// The fields of `s` as its encoding writes them.
fn fields_of(s: &RunStatus) -> [Field; 7] {
    let mut f: [Field; 7] = Default::default();
    f[0] = Some("1".to_owned());
    match s {
        RunStatus::NotStarted { token, request } => {
            f[1] = Some(quoted("not_started"));
            f[2] = Some(quoted(token.clone()));
            f[3] = request.map(|id| quoted(id.to_string()));
        }
        RunStatus::Ran(exit) => {
            f[1] = Some(quoted("ran"));
            match exit {
                Exit::Code(c) => f[4] = Some(c.to_string()),
                Exit::Signal(n) => f[5] = Some(n.to_string()),
                Exit::Stopped(n) => f[6] = Some(n.to_string()),
            }
        }
        RunStatus::Unknown => f[1] = Some(quoted("unknown")),
    }
    f
}

/// A record a run can write, with up to three of its fields replaced by
/// good or bad values (or left out), sometimes an unknown field added,
/// its fields sometimes in another order, sometimes spaced.
fn drawn() -> impl Strategy<Value = Drawn> {
    (
        valid_record(),
        proptest::collection::vec((0usize..7, any::<proptest::sample::Index>()), 0..4),
        proptest::bool::weighted(0.1),
        Just((0..7).collect::<Vec<usize>>()).prop_shuffle(),
        proptest::bool::weighted(0.6),
        proptest::bool::weighted(0.15),
    )
        .prop_map(|(s, changes, extra, order, keep, spaced)| {
            let mut f = fields_of(&s);
            let pools = pools();
            for (i, pick) in changes {
                f[i] = pick.get(&pools[i]).clone();
            }
            let [v, state, token, request, code, signal, stopped] = f;
            Drawn {
                v,
                state,
                token,
                request,
                code,
                signal,
                stopped,
                extra,
                order: if keep { (0..7).collect() } else { order },
                spaced,
            }
        })
}

/// Records a run can write.
fn valid_record() -> impl Strategy<Value = RunStatus> {
    let token = "[a-z][a-z0-9_]{0,63}";
    prop_oneof![
        token.prop_map(|token| RunStatus::NotStarted {
            token,
            request: None
        }),
        shown_id().prop_map(|id| RunStatus::NotStarted {
            token: "approval_required".to_owned(),
            request: PendingId::parse(&id),
        }),
        any::<u8>().prop_map(|c| RunStatus::Ran(Exit::Code(c))),
        (1i32..=127).prop_map(|n| RunStatus::Ran(Exit::Signal(n))),
        (1i32..=127).prop_map(|n| RunStatus::Ran(Exit::Stopped(n))),
        Just(RunStatus::Unknown),
    ]
}

/// Checks what the reader made of `bytes`: nothing, or a valid record
/// whose one encoding is exactly `bytes`.
fn check(bytes: &[u8]) -> Result<(), TestCaseError> {
    if let Some(s) = RunStatus::decode(bytes) {
        prop_assert!(valid(&s), "an invalid record was read: {s:?}");
        let encoding = canonical(&s);
        prop_assert_eq!(
            encoding.as_bytes(),
            bytes,
            "a record was read from bytes other than its encoding"
        );
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    /// Random bytes: never a panic, and nothing read but an encoding.
    #[test]
    fn random_bytes_are_never_a_record_but_an_encoding(
        bytes in proptest::collection::vec(any::<u8>(), 0..=MAX_RECORD + 64)
    ) {
        check(&bytes)?;
    }

    /// Every record a run can write is written in its one encoding, in
    /// one line of at most 512 bytes, and read back as itself.
    #[test]
    fn every_valid_record_reads_back_as_itself(s in valid_record()) {
        let mut out = Vec::new();
        s.write_to(&mut out).unwrap();
        let encoding = canonical(&s);
        prop_assert_eq!(out.as_slice(), encoding.as_bytes());
        prop_assert!(out.len() <= MAX_RECORD);
        prop_assert_eq!(RunStatus::decode(&out), Some(s));
    }

    /// A valid record with random damage (bytes flipped, put in, taken
    /// out, the end cut off) is nothing, or another valid record whose
    /// encoding the damage happened to make.
    #[test]
    fn a_damaged_record_is_nothing_or_another_encoding(
        s in valid_record(),
        edits in proptest::collection::vec((0usize..600, any::<u8>(), 0u8..4), 1..4),
    ) {
        let mut bytes = canonical(&s).into_bytes();
        for (at, byte, kind) in edits {
            let at = at % (bytes.len() + 1);
            match kind {
                0 if at < bytes.len() => bytes[at] ^= byte | 1,
                1 => bytes.insert(at, byte),
                2 if at < bytes.len() => {
                    bytes.remove(at);
                }
                _ => bytes.truncate(at),
            }
        }
        check(&bytes)?;
    }

    /// Records whose every field is drawn from good and bad values, in any
    /// order and spacing: the reader makes of each exactly what the
    /// oracle says, a record only when every field is as its state
    /// requires and the text is its one encoding.
    #[test]
    fn each_drawn_record_is_read_as_the_oracle_says(d in drawn()) {
        let text = d.text();
        prop_assert_eq!(RunStatus::decode(text.as_bytes()), d.expected(), "{}", text);
    }
}

/// The drawn records reach both outcomes: a record, and nothing, for each
/// state, so the oracle test is not passing on one side only.
#[test]
fn the_drawn_records_reach_each_outcome() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    let strategy = drawn();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..20_000 {
        let d = strategy.new_tree(&mut runner).unwrap().current();
        let outcome = match d.expected() {
            Some(RunStatus::NotStarted { request: None, .. }) => "not_started",
            Some(RunStatus::NotStarted {
                request: Some(_), ..
            }) => "approval_required",
            Some(RunStatus::Ran(Exit::Code(_))) => "code",
            Some(RunStatus::Ran(Exit::Signal(_))) => "signal",
            Some(RunStatus::Ran(Exit::Stopped(_))) => "stopped",
            Some(RunStatus::Unknown) => "unknown",
            None => "none",
        };
        seen.insert(outcome);
    }
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        [
            "approval_required",
            "code",
            "none",
            "not_started",
            "signal",
            "stopped",
            "unknown"
        ]
    );
}
