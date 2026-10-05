//! Hostile input for the status record's reader (L-06; verifier review of
//! M2-RES1: `RunStatus::decode` had only a fixed table of bad records):
//! random bytes, valid records with random damage, and records whose
//! every field is drawn from good and bad values, in any order and
//! spacing. Whatever comes in, `decode` never panics, and it accepts
//! exactly the encodings of valid records: the oracle below writes the
//! one encoding by hand from docs/RUN.md's record and checks each field
//! by its own rules, apart from the reader's code. Everything else is
//! `None`, which a reader takes as unknown. The test items an
//! `approval_required` record proposes (M2-13) are drawn too: lists of
//! well-formed and malformed proposals, and counts of the ones left out.
#![allow(clippy::unwrap_used)]

use envcloak_client::run_status::{Exit, MAX_PROPOSALS, MAX_RECORD, RunStatus};
use envcloak_policy::{BindingSource, PendingId, Proposal};
use proptest::prelude::*;

/// Crockford base32, as a request id is shown (8 characters).
const CROCKFORD: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// One proposal's JSON, written by hand: its fields in their order, the
/// field `null` when absent, the layer tagged.
fn proposal_json(x: &Proposal) -> String {
    let field = x
        .test_field
        .as_ref()
        .map_or_else(|| "null".to_owned(), |f| format!("\"{f}\""));
    let source = match &x.source {
        BindingSource::Env => "{\"layer\":\"env\"}".to_owned(),
        BindingSource::Profile { profile } => {
            format!("{{\"layer\":\"profile\",\"profile\":\"{profile}\"}}")
        }
        BindingSource::EnvFile { line } => format!("{{\"layer\":\"env_file\",\"line\":{line}}}"),
        BindingSource::Ref => "{\"layer\":\"ref\"}".to_owned(),
    };
    format!(
        "{{\"env_name\":\"{}\",\"live_slug\":\"{}\",\"test_slug\":\"{}\",\"test_field\":{field},\"source\":{source}}}",
        x.env_name, x.live_slug, x.test_slug
    )
}

/// The `,"proposals":[...]` and `,"proposals_left_out":n` an
/// `approval_required` record carries, empty when it has none.
fn proposals_json(proposals: &[Proposal], left_out: u32) -> String {
    let mut out = String::new();
    if !proposals.is_empty() {
        let list: Vec<String> = proposals.iter().map(proposal_json).collect();
        out.push_str(&format!(",\"proposals\":[{}]", list.join(",")));
    }
    if left_out > 0 {
        out.push_str(&format!(",\"proposals_left_out\":{left_out}"));
    }
    out
}

/// The one encoding of `s`: its fields in the record's order, no white
/// space, one newline.
fn canonical(s: &RunStatus) -> String {
    match s {
        RunStatus::NotStarted {
            token,
            request: None,
            proposals,
            proposals_left_out,
        } => format!(
            "{{\"v\":1,\"state\":\"not_started\",\"token\":\"{token}\"{}}}\n",
            proposals_json(proposals, *proposals_left_out)
        ),
        RunStatus::NotStarted {
            token,
            request: Some(id),
            proposals,
            proposals_left_out,
        } => format!(
            "{{\"v\":1,\"state\":\"not_started\",\"token\":\"{token}\",\"request\":\"{id}\"{}}}\n",
            proposals_json(proposals, *proposals_left_out)
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

/// A variable name: an ASCII letter or `_`, then letters, digits or `_`,
/// at most 128 bytes.
fn env_name_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 128
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

/// A slug: parts separated by `/`, each a lower-case letter or digit then
/// those, `.`, `_` or `-`; at most 128 bytes.
fn slug_ok(s: &str) -> bool {
    let part = |p: &str| {
        let b = p.as_bytes();
        !b.is_empty()
            && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(c))
    };
    !s.is_empty() && s.len() <= 128 && s.split('/').all(part)
}

/// A field name: a lower-case letter, digit or `_`, then those, `.` or
/// `-`; at most 64 bytes.
fn field_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(c))
}

/// A profile name: a lower-case letter or digit, then those, `_` or `-`;
/// at most 64 bytes.
fn profile_ok(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(c))
}

/// Whether `x` has the shapes the daemon gives a proposal.
fn proposal_ok(x: &Proposal) -> bool {
    env_name_ok(&x.env_name)
        && slug_ok(&x.live_slug)
        && slug_ok(&x.test_slug)
        && x.test_field.as_deref().is_none_or(field_ok)
        && match &x.source {
            BindingSource::Env | BindingSource::Ref => true,
            BindingSource::Profile { profile } => profile_ok(profile),
            BindingSource::EnvFile { line } => *line >= 1,
        }
}

/// Whether `s` is a record a run can write.
fn valid(s: &RunStatus) -> bool {
    match s {
        RunStatus::NotStarted {
            token,
            request,
            proposals,
            proposals_left_out,
        } => {
            let named: Vec<&str> = proposals.iter().map(|x| x.env_name.as_str()).collect();
            let unique = named
                .iter()
                .enumerate()
                .all(|(i, n)| !named[..i].contains(n));
            token_ok(token)
                && (request.is_none() || token == "approval_required")
                && ((proposals.is_empty() && *proposals_left_out == 0)
                    || (request.is_some()
                        && proposals.len() <= MAX_PROPOSALS
                        && (*proposals_left_out == 0 || proposals.len() == MAX_PROPOSALS)
                        && unique
                        && proposals.iter().all(proposal_ok)))
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
    proposals: Field,
    left_out: Field,
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
            ("proposals", &self.proposals),
            ("proposals_left_out", &self.left_out),
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
        let proposed = self.proposals.is_some() || self.left_out.is_some();
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
                // Proposals only as the pool's well-formed lists write
                // them; the reader's code is not asked.
                let proposals = match &self.proposals {
                    None => Vec::new(),
                    Some(text) => known_list(text)?,
                };
                let proposals_left_out = match &self.left_out {
                    None => 0,
                    Some(n) => u32::try_from(number(&Some(n.clone()))?).ok()?,
                };
                RunStatus::NotStarted {
                    token,
                    request,
                    proposals,
                    proposals_left_out,
                }
            }
            "ran" => {
                if exits != 1 || self.token.is_some() || self.request.is_some() || proposed {
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
                if exits != 0 || self.token.is_some() || self.request.is_some() || proposed {
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

/// A well-formed proposal for variable `n`: the layers in turn.
fn good_proposal(n: usize) -> Proposal {
    Proposal {
        env_name: format!("KEY_{n}"),
        live_slug: format!("stripe/live-{n}"),
        test_slug: format!("stripe/test-{n}"),
        test_field: (n % 2 == 1).then(|| "secret".to_owned()),
        source: match n % 4 {
            0 => BindingSource::Env,
            1 => BindingSource::Profile {
                profile: "dev".to_owned(),
            },
            2 => BindingSource::EnvFile {
                line: u32::try_from(n + 1).unwrap(),
            },
            _ => BindingSource::Ref,
        },
    }
}

/// The well-formed lists of proposals the pool draws from: one, two, and
/// a full list.
fn good_lists() -> Vec<Vec<Proposal>> {
    vec![
        vec![good_proposal(0)],
        vec![good_proposal(1), good_proposal(2)],
        (0..MAX_PROPOSALS).map(good_proposal).collect(),
    ]
}

/// The list `text` writes, when it is one of [`good_lists`] as written.
fn known_list(text: &str) -> Option<Vec<Proposal>> {
    good_lists().into_iter().find(|l| {
        let items: Vec<String> = l.iter().map(proposal_json).collect();
        text == format!("[{}]", items.join(","))
    })
}

/// Malformed lists: empty (never written), a variable twice, a name of
/// the wrong shape, an unknown layer, a profile of the wrong shape, line
/// 0, an unknown field, more than the cap, and not a list.
fn bad_lists() -> Vec<String> {
    let json = |l: &[Proposal]| {
        let items: Vec<String> = l.iter().map(proposal_json).collect();
        format!("[{}]", items.join(","))
    };
    let mut twice = vec![good_proposal(0), good_proposal(1)];
    twice[1].env_name = twice[0].env_name.clone();
    let mut slug = vec![good_proposal(0)];
    slug[0].test_slug = "Stripe/Test".to_owned();
    let mut name = vec![good_proposal(0)];
    name[0].env_name = "1KEY".to_owned();
    let mut profile = vec![good_proposal(1)];
    profile[0].source = BindingSource::Profile {
        profile: "Dev".to_owned(),
    };
    let mut line = vec![good_proposal(2)];
    line[0].source = BindingSource::EnvFile { line: 0 };
    let over: Vec<Proposal> = (0..=MAX_PROPOSALS).map(good_proposal).collect();
    let one = json(&[good_proposal(0)]);
    vec![
        "[]".to_owned(),
        json(&twice),
        json(&slug),
        json(&name),
        json(&profile),
        json(&line),
        json(&over),
        one.replace("\"layer\":\"env\"", "\"layer\":\"shell\""),
        one.replace("\"source\"", "\"value\":\"x\",\"source\""),
        "null".to_owned(),
        "7".to_owned(),
    ]
}

fn shown_id() -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::sample::select(CROCKFORD.to_vec()), 8)
        .prop_map(|b| String::from_utf8(b).unwrap())
}

/// Good and bad values for each field, in the record's order (`v`,
/// `state`, `token`, `request`, `proposals`, `proposals_left_out`, `code`,
/// `signal`, `stopped`); `None` is the field left out.
fn pools() -> [Vec<Field>; 9] {
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
        std::iter::once(None)
            .chain(good_lists().iter().map(|l| {
                let items: Vec<String> = l.iter().map(proposal_json).collect();
                Some(format!("[{}]", items.join(",")))
            }))
            .chain(bad_lists().into_iter().map(Some))
            .collect(),
        some(&["0", "1", "3", "-1", "\"1\"", "4294967296"]),
        some(&["0", "125", "255", "256", "-1", "\"1\""]),
        exit.clone(),
        exit,
    ]
}

/// The fields of `s` as its encoding writes them.
fn fields_of(s: &RunStatus) -> [Field; 9] {
    let mut f: [Field; 9] = Default::default();
    f[0] = Some("1".to_owned());
    match s {
        RunStatus::NotStarted {
            token,
            request,
            proposals,
            proposals_left_out,
        } => {
            f[1] = Some(quoted("not_started"));
            f[2] = Some(quoted(token.clone()));
            f[3] = request.map(|id| quoted(id.to_string()));
            if !proposals.is_empty() {
                let items: Vec<String> = proposals.iter().map(proposal_json).collect();
                f[4] = Some(format!("[{}]", items.join(",")));
            }
            if *proposals_left_out > 0 {
                f[5] = Some(proposals_left_out.to_string());
            }
        }
        RunStatus::Ran(exit) => {
            f[1] = Some(quoted("ran"));
            match exit {
                Exit::Code(c) => f[6] = Some(c.to_string()),
                Exit::Signal(n) => f[7] = Some(n.to_string()),
                Exit::Stopped(n) => f[8] = Some(n.to_string()),
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
        proptest::collection::vec((0usize..9, any::<proptest::sample::Index>()), 0..4),
        proptest::bool::weighted(0.1),
        Just((0..9).collect::<Vec<usize>>()).prop_shuffle(),
        proptest::bool::weighted(0.6),
        proptest::bool::weighted(0.15),
    )
        .prop_map(|(s, changes, extra, order, keep, spaced)| {
            let mut f = fields_of(&s);
            let pools = pools();
            for (i, pick) in changes {
                f[i] = pick.get(&pools[i]).clone();
            }
            let [
                v,
                state,
                token,
                request,
                proposals,
                left_out,
                code,
                signal,
                stopped,
            ] = f;
            Drawn {
                v,
                state,
                token,
                request,
                code,
                signal,
                stopped,
                proposals,
                left_out,
                extra,
                order: if keep { (0..9).collect() } else { order },
                spaced,
            }
        })
}

/// Records a run can write.
fn valid_record() -> impl Strategy<Value = RunStatus> {
    let token = "[a-z][a-z0-9_]{0,63}";
    prop_oneof![
        token.prop_map(|token| RunStatus::not_started(&token)),
        shown_id().prop_map(|id| RunStatus::approval_required(PendingId::parse(&id).unwrap(), &[])),
        (shown_id(), 0usize..3, 0u32..3).prop_map(|(id, which, more)| {
            let list = &good_lists()[which];
            // A count only past a full list.
            let mut all = list.clone();
            if list.len() == MAX_PROPOSALS {
                all.extend((0..more as usize).map(|i| good_proposal(MAX_PROPOSALS + i)));
            }
            RunStatus::approval_required(PendingId::parse(&id).unwrap(), &all)
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
    /// one line of at most `MAX_RECORD` bytes, and read back as itself.
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
                request: Some(_),
                proposals,
                ..
            }) if !proposals.is_empty() => "proposing",
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
            "proposing",
            "signal",
            "stopped",
            "unknown"
        ]
    );
}
