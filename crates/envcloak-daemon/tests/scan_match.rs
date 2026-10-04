//! `scan.match` and `items.mark_exposed` over the daemon's socket (M2 plan
//! M2-11, D-32; SPEC §6.4, §6.5; gate 36's low-entropy part, gate 33):
//! - a candidate short enough to guess, counted as a server reads it (in
//!   characters, F-58; libpq's escapes decoded, F-65; a Go DSN whose
//!   password starts with `//`, R-11; every URL a value lists, R-4; a
//!   password read out of its value), is compared only for a person's
//!   `import`: an agent's import, any doctor and any scrub get the same
//!   answer for a right guess and a wrong one; a person's import is told;
//!   16 characters are compared for anyone;
//! - the purpose is required, and decides for every caller;
//! - each budget stops at its limit (`limited`, then `too_many_checks`),
//!   one spent leaves the other usable, and a guessable candidate is never
//!   charged to `ScanChecks`;
//! - only `secret` items match: never a card's value or a login's;
//! - a request that breaks the bounds is refused whole, and a frame over
//!   1 MiB is refused before it is read;
//! - every call is audited with counts and never a candidate;
//! - an answer too large for a frame is audited as `frame_too_large`, and
//!   a refused well-formed call is audited too;
//! - `items.mark_exposed` marks, repeats change nothing, and a rotation
//!   clears the mark.
//!
//! The caller is this test process, made a terminal session so the daemon
//! takes its proofs (a person); the fixture agent's marker makes it an
//! agent. The daemon writes its test trace. Every response, the daemon's
//! log, the decrypted audit entries and the home are swept for every
//! value the tests send, with a positive control for the detector.
#![allow(clippy::unwrap_used)]

mod common;

use std::io::Write as _;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use base64::Engine as _;
use common::{
    client, closed, data_dir, error_kind, exe, passphrase, raw, read_json, seed_vault, send_json,
};
use envcloak_core::SecretBytes;
use envcloak_core::audit::{AuditEntry, AuditKind};
use envcloak_core::crypto::ItemClass;
use envcloak_core::vault::{
    FieldName, ItemDetails, LockedVault, LoginMeta, LoginTier, NewItem, NewLogin, Slug, Vault,
    VaultPaths,
};
use envcloak_ipc::proto::{
    AddParams, CandidateForm, ErrorKind, ExposedItem, ImportEntry, ImportParams, ImportProject,
    ImportScope, MAX_CANDIDATE, MAX_SCAN_CANDIDATES, MarkExposedParams, ScanCandidate,
    ScanMatchParams, ScanPurpose, ScanSource,
};
use envcloak_ipc::view::{ExposureSourceView, ScanMatchView, ScanMatchedView};
use envcloak_ipc::{Client, ClientError, WireSecret};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, find, fresh_seed, labels,
};

/// The marker the fixture catalog knows as an agent's.
const AGENT: &str = "ENVCLOAK_FIXTURE_AGENT";

fn rpc(e: ClientError) -> (ErrorKind, Option<&'static str>) {
    match e {
        ClientError::Rpc(r) => (r.kind, r.reason),
        other => panic!("expected an error response, got {other:?}"),
    }
}

/// `n` random lowercase letters and digits.
fn word(n: usize) -> String {
    let mut out = String::new();
    while out.len() < n {
        let seed = fresh_seed();
        for i in 0..10 {
            let k = usize::try_from((seed >> (i * 6)) % 36).unwrap();
            out.push(char::from(b"abcdefghijklmnopqrstuvwxyz0123456789"[k]));
        }
    }
    out.truncate(n);
    out
}

/// `n` random two-byte letters.
fn two_byte(n: usize) -> String {
    let alphabet = ['\u{e9}', '\u{fc}', '\u{f1}', '\u{f8}', '\u{e5}', '\u{e7}'];
    let mut out = String::new();
    while out.chars().count() < n {
        let seed = fresh_seed();
        for i in 0..8 {
            let k = usize::try_from((seed >> (i * 8)) % alphabet.len() as u64).unwrap();
            out.push(alphabet[k]);
        }
    }
    out.chars().take(n).collect()
}

/// `l` and `r` random letters and digits either side of one backslash,
/// written as libpq's keyword form escapes it: `l + r + 1` characters to
/// libpq, one byte more as written.
fn backslashed(l: usize, r: usize) -> String {
    format!("{}\\\\{}", word(l), word(r))
}

/// A seeded, unlocked vault behind a running daemon that writes its test
/// trace, and every value the test sends, as canaries.
struct Fixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
}

impl Fixture {
    /// The story's seeded vault; `more` adds items before the daemon
    /// starts.
    fn new(more: impl FnOnce(&mut Vault, &mut Vec<Canary>)) -> Self {
        common::terminal_session();
        let mut cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        {
            let mut v = LockedVault::open(&VaultPaths::under(data_dir(&home)))
                .unwrap()
                .unlock_with_passphrase(&passphrase(&cs))
                .map_err(|(_, e)| e)
                .unwrap();
            more(&mut v, &mut cs);
        }
        cs.push(kit);
        // The trace: a line for every connection, which must hold no
        // candidate either.
        let mut cmd = Command::new(exe());
        home.apply(&mut cmd);
        cmd.env("ENVCLOAK_TEST_TRACE", "1");
        let d = Daemon::start_command(cmd, &[]);
        client(&home).unlock(passphrase(&cs), &[]).unwrap();
        Fixture { cs, home, d }
    }

    fn value(&self, label: &str) -> Vec<u8> {
        by_label(&self.cs, label).value().to_vec()
    }

    /// Adds `value` as item `slug`, as a person would, and keeps it as a
    /// canary.
    fn add(&mut self, c: &mut Client, slug: &str, value: &str) -> String {
        self.cs
            .push(Canary::new(format!("ITEM_{slug}"), value.to_owned()));
        c.items_add(&AddParams {
            slug: Some(slug.to_owned()),
            provider: None,
            field: None,
            account: None,
            env_hint: None,
            allow_short: false,
            value: WireSecret::new(SecretBytes::copy_from(value.as_bytes())),
            claims: Vec::new(),
        })
        .unwrap()
        .item
        .id
    }

    /// Keeps `value`, which the test sends, as a canary.
    fn keep(&mut self, label: &str, value: &str) {
        self.cs
            .push(Canary::new(label.to_owned(), value.to_owned()));
    }

    fn stop_and_open(&mut self) -> Vault {
        self.d.signal("-TERM");
        assert!(self.d.wait_exit(Duration::from_secs(30)).is_some());
        LockedVault::open(&VaultPaths::under(data_dir(&self.home)))
            .unwrap()
            .unlock_with_passphrase(&passphrase(&self.cs))
            .map_err(|(_, e)| e)
            .unwrap()
    }

    /// The daemon's log (its trace included) and the home hold no value
    /// the test sent; and the decrypted audit entries hold none either,
    /// in any encoding, the detector finding a planted one (the positive
    /// control).
    fn sweep_with(&self, entries: &[AuditEntry]) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
        let records: String = entries
            .iter()
            .map(|e| format!("{:?}\n", e.record))
            .collect();
        assert_no_canary(records.as_bytes(), &self.cs);
        let planted = format!("{records}{}", self.cs[0].as_str());
        assert!(!find(planted.as_bytes(), &self.cs).is_empty());
    }
}

/// A candidate.
fn cand(id: u32, v: &[u8], form: CandidateForm) -> ScanCandidate {
    ScanCandidate {
        id,
        value: WireSecret::new(SecretBytes::copy_from(v)),
        form,
    }
}

/// `scan.match` for `candidates`, for `purpose`, asked as `claims` says.
fn scan(
    c: &mut Client,
    purpose: ScanPurpose,
    claims: &[&str],
    candidates: Vec<ScanCandidate>,
) -> Result<ScanMatchView, ClientError> {
    c.scan_match(&ScanMatchParams {
        candidates,
        source_kind: ScanSource::Transcript,
        purpose,
        claims: claims.iter().map(|c| (*c).to_owned()).collect(),
    })
}

/// What a call that compared nothing of one guessable candidate answers.
fn skipped_one() -> ScanMatchView {
    ScanMatchView {
        matches: Vec::new(),
        patterns: Vec::new(),
        compared: 0,
        skipped_guessable: 1,
        limited: false,
    }
}

/// A `scan.match` audit entry: outcome, reason (the purpose), count and
/// named counts.
type ScanEntry = (String, String, u64, Vec<(String, u64)>);

/// The `scan.match` entries of the audit log.
fn scan_entries(entries: &[AuditEntry]) -> Vec<ScanEntry> {
    entries
        .iter()
        .filter(|e| e.record.kind == AuditKind::ScanMatch)
        .map(|e| {
            let d = &e.record.decision;
            assert_eq!(d.method.as_deref(), Some("scan.match"));
            (
                d.outcome.clone(),
                d.reason.clone().unwrap(),
                d.count.unwrap(),
                d.counts.clone(),
            )
        })
        .collect()
}

/// The named count `name` of an entry's counts.
fn named(counts: &[(String, u64)], name: &str) -> u64 {
    counts
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("no count {name}"))
        .1
}

/// A value around a password: the password in, the value out.
type ValueOf = fn(&str) -> String;

/// One case of the oracle matrix: a name for its slug, the form the
/// candidate is sent in, the value around a password, a right and a wrong
/// password a server reads as under 16 characters, and a control one reads
/// as 16.
struct Shape {
    name: &'static str,
    form: CandidateForm,
    value: ValueOf,
    right: String,
    wrong: String,
    control: String,
}

/// The oracle matrix (plan M2-11 "Tests first"; L-07): for each shape, with
/// the vault holding the value around the right password, a right and a
/// wrong guess get the same answer, nothing compared and one guessable
/// candidate skipped, from an agent's import, a person's doctor, an
/// agent's doctor and a person's scrub; a person's import is told which
/// is right; and the control, read as 16 characters, is compared and
/// found for an agent's doctor. The shapes: 8 two-byte characters (F-58),
/// raw and as a URL's password; libpq's keyword form with an escaped
/// backslash, 15 characters to libpq in 16 bytes (F-65), raw and as a
/// field's password; Go's MySQL DSN whose password starts with `//`
/// (R-11); a password in the second of two URLs (R-4).
///
/// Mutations: guessable candidates compared for anyone (an agent's hit is
/// told from its miss); bytes counted instead of characters (the
/// two-byte cases are compared for an agent); the import rules for doctor
/// and scrub too (one shared filter: a person's doctor is told).
#[test]
fn a_guessable_value_is_compared_only_for_a_persons_import() {
    let mut f = Fixture::new(|_, _| {});
    let mut c = client(&f.home);
    let shapes = [
        Shape {
            name: "multibyte",
            form: CandidateForm::Raw,
            value: |pw| pw.to_owned(),
            right: two_byte(8),
            wrong: two_byte(8),
            control: two_byte(16),
        },
        Shape {
            name: "multibyte-url-password",
            form: CandidateForm::UrlPassword,
            value: |pw| pw.to_owned(),
            right: two_byte(8),
            wrong: two_byte(8),
            control: two_byte(16),
        },
        Shape {
            name: "libpq-escaped",
            form: CandidateForm::Raw,
            value: |pw| format!("host=db.internal port=5432 dbname=app user=app password={pw}"),
            right: backslashed(7, 7),
            wrong: backslashed(7, 7),
            control: backslashed(7, 8),
        },
        Shape {
            name: "libpq-conn-password",
            form: CandidateForm::ConnPassword,
            value: |pw| pw.to_owned(),
            right: backslashed(7, 7),
            wrong: backslashed(7, 7),
            control: backslashed(7, 8),
        },
        Shape {
            name: "go-dsn-slashes",
            form: CandidateForm::Raw,
            value: |pw| format!("app://{pw}@tcp(db.internal:3306)/app"),
            right: word(8),
            wrong: word(8),
            // `//` and 14 more: 16 characters.
            control: word(14),
        },
        Shape {
            name: "two-urls",
            form: CandidateForm::Raw,
            value: |pw| format!("redis://s1.internal:26379,redis://:{pw}@s2.internal:26379"),
            right: word(8),
            wrong: word(8),
            control: word(16),
        },
    ];
    let person_import = (ScanPurpose::Import, &[][..]);
    let hidden = [
        (ScanPurpose::Import, &[AGENT][..]),
        (ScanPurpose::Doctor, &[][..]),
        (ScanPurpose::Doctor, &[AGENT][..]),
        (ScanPurpose::Scrub, &[][..]),
    ];
    for s in &shapes {
        let (right, wrong, control) = (
            (s.value)(&s.right),
            (s.value)(&s.wrong),
            (s.value)(&s.control),
        );
        assert!(right != wrong, "{}", s.name);
        f.keep(&format!("WRONG_{}", s.name), &wrong);
        f.keep(&format!("RIGHT_PASSWORD_{}", s.name), &s.right);
        let slug = format!("pw-{}/acme", s.name);
        let id = f.add(&mut c, &slug, &right);
        let long_slug = format!("long-{}/acme", s.name);
        let long_id = f.add(&mut c, &long_slug, &control);
        let one = |c: &mut Client, purpose, claims: &[&str], v: &str| {
            scan(c, purpose, claims, vec![cand(7, v.as_bytes(), s.form)]).unwrap()
        };
        for (purpose, claims) in hidden {
            let hit = one(&mut c, purpose, claims, &right);
            let miss = one(&mut c, purpose, claims, &wrong);
            assert_eq!(hit, miss, "{} {purpose:?} {claims:?}", s.name);
            assert_eq!(hit, skipped_one(), "{} {purpose:?} {claims:?}", s.name);
            // The control is compared and found for anyone.
            let found = one(&mut c, purpose, claims, &control);
            assert_eq!(found.compared, 1, "{} {purpose:?}", s.name);
            assert_eq!(
                found.matches,
                [ScanMatchedView {
                    id: 7,
                    item: long_id.clone(),
                    slug: long_slug.clone()
                }],
                "{} {purpose:?}",
                s.name
            );
        }
        // A person's import is told.
        let (purpose, claims) = person_import;
        let hit = one(&mut c, purpose, claims, &right);
        assert_eq!(
            hit.matches,
            [ScanMatchedView {
                id: 7,
                item: id.clone(),
                slug: slug.clone()
            }],
            "{}",
            s.name
        );
        assert_eq!((hit.compared, hit.skipped_guessable), (1, 0), "{}", s.name);
        let miss = one(&mut c, purpose, claims, &wrong);
        assert!(miss.matches.is_empty(), "{}", s.name);
        assert_eq!(
            (miss.compared, miss.skipped_guessable),
            (1, 0),
            "{}",
            s.name
        );
    }
    drop(c);
    let v = f.stop_and_open();
    let (entries, _) = v.read_audit().unwrap();
    f.sweep_with(&entries);
}

/// The purpose decides for every caller (Codex cycle173 proposal 3): the
/// same short value (the vault's 10-character `short/acme-web`, which no
/// provider's pattern matches) sent as a person's `import` may be found;
/// sent as a person's `doctor`, an agent's `doctor` and a person's `scrub`
/// it is compared with nothing, matches nothing and counts no guessable
/// comparison, in the answer and in the audit entry, which records the
/// purpose. A request without a purpose, or with one the protocol does not
/// name, is `invalid_params`, and so is one without a source.
///
/// Mutations: a missing purpose taken as `import` (the request is
/// answered); the import rules for every purpose (a person's doctor is
/// told).
#[test]
fn the_purpose_decides_what_is_compared_for_every_caller() {
    let mut f = Fixture::new(|_, _| {});
    let short = f.value(labels::SHORT_TOKEN);
    assert_eq!(short.len(), 10);
    let mut c = client(&f.home);
    let one = |c: &mut Client, purpose, claims: &[&str]| {
        scan(
            c,
            purpose,
            claims,
            vec![cand(1, &short, CandidateForm::Raw)],
        )
        .unwrap()
    };
    let found = one(&mut c, ScanPurpose::Import, &[]);
    assert_eq!(found.matches.len(), 1);
    assert_eq!(found.matches[0].slug, "short/acme-web");
    for (purpose, claims) in [
        (ScanPurpose::Doctor, &[][..]),
        (ScanPurpose::Doctor, &[AGENT][..]),
        (ScanPurpose::Scrub, &[][..]),
    ] {
        assert_eq!(one(&mut c, purpose, claims), skipped_one(), "{purpose:?}");
    }
    drop(c);
    // Without a purpose, with an unknown one, without a source: refused,
    // never taken as an import.
    let b64 = base64::engine::general_purpose::STANDARD.encode(&short);
    for params in [
        serde_json::json!({"candidates": [{"id": 1, "value": b64, "form": "raw"}],
            "source_kind": "transcript"}),
        serde_json::json!({"candidates": [{"id": 1, "value": b64, "form": "raw"}],
            "source_kind": "transcript", "purpose": "audit"}),
        serde_json::json!({"candidates": [{"id": 1, "value": b64, "form": "raw"}],
            "purpose": "import"}),
    ] {
        let mut s = raw(&f.home);
        send_json(
            &mut s,
            &serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "scan.match",
                "params": params}),
        );
        let answer = read_json(&mut s).unwrap();
        assert_eq!(error_kind(&answer), "invalid_params", "{params}");
    }
    let v = f.stop_and_open();
    let (entries, _) = v.read_audit().unwrap();
    // Counts only: no candidate in any entry, the log or the home.
    f.sweep_with(&entries);
    let scans = scan_entries(&entries);
    assert_eq!(scans.len(), 4);
    let purposes: Vec<&str> = scans.iter().map(|s| s.1.as_str()).collect();
    assert_eq!(purposes, ["import", "doctor", "doctor", "scrub"]);
    assert_eq!(scans[0].0, "checked");
    assert_eq!(scans[0].2, 1);
    assert_eq!(named(&scans[0].3, "compared_guessable"), 1);
    for s in &scans[1..] {
        assert_eq!((s.0.as_str(), s.2), ("checked", 0));
        assert_eq!(named(&s.3, "compared_guessable"), 0);
        assert_eq!(named(&s.3, "skipped_guessable"), 1);
        assert_eq!(named(&s.3, "candidates_transcript"), 1);
    }
}

/// Each line of the libpq fixture, as libpq's own parser counted its
/// password (crates/envcloak-providers/tests/fixtures/libpq, generated with
/// `PQconninfoParse`): its count, whether EnvCloak's is exactly that, and
/// the connection string.
fn libpq_cases() -> Vec<(usize, bool, Vec<u8>)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../envcloak-providers/tests/fixtures/libpq/passwords.txt");
    let text = std::fs::read_to_string(path).unwrap();
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let mut parts = line.split(' ');
        let (chars, kind, written) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        let w = written.as_bytes();
        let mut bytes = Vec::with_capacity(w.len());
        let mut i = 0;
        while i < w.len() {
            if w[i] == b'%' {
                let hex = std::str::from_utf8(&w[i + 1..i + 3]).unwrap();
                bytes.push(u8::from_str_radix(hex, 16).unwrap());
                i += 3;
            } else {
                bytes.push(w[i]);
                i += 1;
            }
        }
        out.push((chars.parse().unwrap(), kind == "exact", bytes));
    }
    out
}

/// libpq's own counts as the oracle at the daemon (F-65, the independent
/// oracle of crates/envcloak-providers/tests/libpq.rs): every connection
/// string whose password libpq reads as under 16 characters, sent whole by
/// an agent for doctor, is left out as guessable, and every one libpq
/// reads as 16 or more, that EnvCloak reads exactly as libpq does, is
/// compared.
///
/// Mutation: bytes counted instead of characters in the password readings
/// (an escaped password under 16 is compared).
#[test]
fn libpq_passwords_are_guessable_as_libpq_reads_them() {
    let f = Fixture::new(|_, _| {});
    let mut c = client(&f.home);
    let cases = libpq_cases();
    let short: Vec<&Vec<u8>> = cases
        .iter()
        .filter(|(n, ..)| *n < 16)
        .map(|(.., b)| b)
        .collect();
    let long: Vec<&Vec<u8>> = cases
        .iter()
        .filter(|(n, exact, _)| *n >= 16 && *exact)
        .map(|(.., b)| b)
        .collect();
    assert!(
        short.len() >= 300 && long.len() >= 50,
        "{} {}",
        short.len(),
        long.len()
    );
    let send = |c: &mut Client, values: &[&Vec<u8>]| {
        let candidates = values
            .iter()
            .enumerate()
            .map(|(i, v)| cand(u32::try_from(i).unwrap(), v, CandidateForm::Raw))
            .collect();
        scan(c, ScanPurpose::Doctor, &[AGENT], candidates).unwrap()
    };
    let a = send(&mut c, &short);
    assert_eq!(
        (a.compared, a.skipped_guessable),
        (0, u32::try_from(short.len()).unwrap())
    );
    let b = send(&mut c, &long);
    assert_eq!(
        (b.compared, b.skipped_guessable),
        (u32::try_from(long.len()).unwrap(), 0)
    );
    assert!(a.matches.is_empty() && b.matches.is_empty());
}

/// `n` copies of `v` as candidates with ids from `from`.
fn copies(v: &[u8], n: usize, from: u32) -> Vec<ScanCandidate> {
    (0..n)
        .map(|i| cand(from + u32::try_from(i).unwrap(), v, CandidateForm::Raw))
        .collect()
}

/// Sends `total` copies of `v` for a person's import in calls of
/// [`MAX_SCAN_CANDIDATES`], all compared, and returns the last answer.
fn spend(c: &mut Client, v: &[u8], total: usize) -> ScanMatchView {
    let mut left = total;
    let mut last = None;
    while left > 0 {
        let n = left.min(MAX_SCAN_CANDIDATES);
        let a = scan(c, ScanPurpose::Import, &[], copies(v, n, 0)).unwrap();
        assert_eq!((a.compared, a.limited), (u32::try_from(n).unwrap(), false));
        left -= n;
        last = Some(a);
    }
    last.unwrap()
}

/// The budgets at the daemon, with their real limits: `ScanChecks` takes
/// 2,000,000 candidates that are not guessable from one subject root in
/// an hour of awake time, and the call that reaches it compares what fits
/// and says `limited`; the next is `too_many_checks` (`limited`), and
/// nothing is compared. With `ScanChecks` spent, a person's guessable
/// candidates are still compared, charged to `ValueChecks`, up to its
/// 100,000, where the same happens; `import.plan`, which counts against
/// the same `ValueChecks`, is then refused too. Every comparison is
/// counted in the audit entries, by budget, and each refusal
/// (`too_many_checks`) and each call cut short (`limited`) is audited as
/// such. (That a guessable candidate never
/// draws on `ScanChecks` while `ValueChecks` is spent and `ScanChecks` has
/// room is the unit test `each_budget_stops_at_its_limit_and_the_other_
/// goes_on` in src/scan_match.rs, with an injected clock.)
///
/// Mutations: the limiter skipped (the call past the limit is answered
/// in full); a guessable candidate charged to `ScanChecks` (with
/// `ScanChecks` spent, the guessable candidates are refused).
#[test]
fn each_budget_stops_at_its_limit_and_one_spent_leaves_the_other() {
    const SCAN: usize = 2_000_000;
    const VALUE: usize = 100_000;
    let mut f = Fixture::new(|_, _| {});
    let long = f.value(labels::GITHUB_TOKEN);
    let short = f.value(labels::SHORT_TOKEN);
    // A value no item holds and no key pattern matches, to spend the
    // budgets with small answers.
    let filler = format!("{}-{}", word(20), word(20));
    f.keep("FILLER", &filler);
    let mut c = client(&f.home);
    // `ScanChecks` to 10 short of its limit.
    let last = spend(&mut c, filler.as_bytes(), SCAN - 10);
    assert!(last.matches.is_empty() && last.patterns.is_empty());
    // The call that reaches it: 10 compared, the rest not.
    let a = scan(&mut c, ScanPurpose::Doctor, &[], copies(&long, 30, 0)).unwrap();
    assert_eq!((a.compared, a.skipped_guessable, a.limited), (10, 0, true));
    assert_eq!(a.matches.len(), 10);
    assert!(
        a.matches
            .iter()
            .all(|m| m.id < 10 && m.slug == "github/acme-web")
    );
    let e = scan(&mut c, ScanPurpose::Doctor, &[], copies(&long, 1, 0)).unwrap_err();
    assert_eq!(rpc(e), (ErrorKind::TooManyChecks, Some("limited")));
    // `ScanChecks` spent: a person's guessable candidates go on, charged to
    // `ValueChecks`; the long one beside them is not compared.
    let mut mixed = copies(&short, 2, 0);
    mixed.push(cand(2, &long, CandidateForm::Raw));
    let a = scan(&mut c, ScanPurpose::Import, &[], mixed).unwrap();
    assert_eq!((a.compared, a.limited), (2, true));
    assert_eq!(a.matches.len(), 2);
    assert!(a.matches.iter().all(|m| m.slug == "short/acme-web"));
    // `ValueChecks` to its limit, the same way.
    spend(&mut c, &short, VALUE - 2 - 5);
    let a = scan(&mut c, ScanPurpose::Import, &[], copies(&short, 8, 0)).unwrap();
    assert_eq!((a.compared, a.limited), (5, true));
    let e = scan(&mut c, ScanPurpose::Import, &[], copies(&short, 1, 0)).unwrap_err();
    assert_eq!(rpc(e), (ErrorKind::TooManyChecks, Some("limited")));
    // `import.plan` counts against the same `ValueChecks`.
    let e = c
        .import_plan(&ImportParams {
            projects: vec![ImportProject {
                dir: f.home.root().join("acme").to_str().unwrap().to_owned(),
                name: "acme".into(),
            }],
            entries: vec![ImportEntry {
                scope: ImportScope::Project(0),
                file: ".env".into(),
                line: 1,
                profile: None,
                name: "GITHUB_TOKEN".into(),
                value: WireSecret::new(SecretBytes::copy_from(&long)),
            }],
            claims: Vec::new(),
        })
        .unwrap_err();
    assert_eq!(rpc(e), (ErrorKind::TooManyChecks, None));
    drop(c);
    let v = f.stop_and_open();
    let (entries, _) = v.read_audit().unwrap();
    let scans = scan_entries(&entries);
    let outcomes: Vec<&str> = scans.iter().map(|s| s.0.as_str()).collect();
    let refused: Vec<usize> = outcomes
        .iter()
        .enumerate()
        .filter(|(_, o)| **o == "too_many_checks")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(refused.len(), 2);
    let limited: Vec<&ScanEntry> = scans.iter().filter(|s| s.0 == "limited").collect();
    assert_eq!(limited.len(), 3);
    assert_eq!(named(&limited[0].3, "not_compared"), 20);
    assert_eq!(named(&limited[1].3, "compared_guessable"), 2);
    assert_eq!(named(&limited[1].3, "not_compared"), 1);
    assert_eq!(named(&limited[2].3, "not_compared"), 3);
    let total_other: u64 = scans.iter().map(|s| named(&s.3, "compared_other")).sum();
    let total_guessable: u64 = scans
        .iter()
        .map(|s| named(&s.3, "compared_guessable"))
        .sum();
    assert_eq!(
        (total_other, total_guessable),
        (u64::try_from(SCAN).unwrap(), u64::try_from(VALUE).unwrap())
    );
    f.sweep_with(&entries);
}

/// Only `secret` items match (R-M2-34; card detection is M4): a value held
/// by a card and by a secret matches the secret alone, one held by a card
/// alone or by a login (its password, its username) matches nothing, for a
/// person's import that compares each of them.
///
/// Mutation: every item class compared (the card matches).
#[test]
fn cards_and_logins_never_match() {
    let (card_only, shared_value, password, username) = (word(24), word(24), word(24), word(24));
    let (a, b, p, u) = (
        card_only.clone(),
        shared_value.clone(),
        password.clone(),
        username.clone(),
    );
    let mut f = Fixture::new(move |v, cs| {
        for (label, value) in [
            ("CARD_ONLY", &a),
            ("SHARED", &b),
            ("LOGIN_PASSWORD", &p),
            ("LOGIN_USERNAME", &u),
        ] {
            cs.push(Canary::new(label, value.clone()));
        }
        v.transact(|t| {
            for (slug, class, value) in [
                ("card/one", ItemClass::Card, &a),
                ("card/two", ItemClass::Card, &b),
                ("secret/two", ItemClass::Secret, &b),
            ] {
                let id = t.create_item(NewItem {
                    class,
                    slug: Slug::new(slug).unwrap(),
                    details: ItemDetails {
                        title: slug.to_owned(),
                        ..ItemDetails::default()
                    },
                })?;
                t.add_field(
                    id,
                    FieldName::new("value").unwrap(),
                    SecretBytes::copy_from(value.as_bytes()),
                )?;
            }
            t.create_login(NewLogin {
                slug: Slug::new("login/editor").unwrap(),
                details: ItemDetails::default(),
                meta: LoginMeta {
                    tier: LoginTier::Dev,
                    session_lifetime: 3600,
                },
                username: SecretBytes::copy_from(u.as_bytes()),
                password: SecretBytes::copy_from(p.as_bytes()),
                totp: None,
                adapter_key: None,
            })?;
            Ok(())
        })
        .unwrap();
    });
    let mut c = client(&f.home);
    let a = scan(
        &mut c,
        ScanPurpose::Import,
        &[],
        vec![
            cand(1, card_only.as_bytes(), CandidateForm::Raw),
            cand(2, shared_value.as_bytes(), CandidateForm::Raw),
            cand(3, password.as_bytes(), CandidateForm::Raw),
            cand(4, username.as_bytes(), CandidateForm::Raw),
        ],
    )
    .unwrap();
    assert_eq!(a.compared, 4);
    let found: Vec<(u32, &str)> = a.matches.iter().map(|m| (m.id, m.slug.as_str())).collect();
    assert_eq!(found, [(2, "secret/two")]);
    drop(c);
    let v = f.stop_and_open();
    let (entries, _) = v.read_audit().unwrap();
    f.sweep_with(&entries);
}

/// A candidate no item holds that a provider's key pattern matches is
/// reported with the provider, for any caller; one an item holds is a
/// match and no pattern. A key-shaped candidate under 16 characters would
/// be compared for anyone by the pattern exception, but the generated keys
/// here are long.
#[test]
fn unknown_keys_are_reported_by_their_provider_pattern() {
    let f = Fixture::new(|_, _| {});
    let mut c = client(&f.home);
    let (known, unknown) = (
        f.value(labels::OPENAI_API_KEY),
        f.value(labels::OPENAI_API_KEY_ROTATED),
    );
    let a = scan(
        &mut c,
        ScanPurpose::Doctor,
        &[AGENT],
        vec![
            cand(1, &known, CandidateForm::Raw),
            cand(2, &unknown, CandidateForm::Raw),
        ],
    )
    .unwrap();
    assert_eq!(a.compared, 2);
    let found: Vec<(u32, &str)> = a.matches.iter().map(|m| (m.id, m.slug.as_str())).collect();
    assert_eq!(found, [(1, "openai/acme-web")]);
    let patterns: Vec<(u32, &str)> = a
        .patterns
        .iter()
        .map(|p| (p.id, p.provider.as_str()))
        .collect();
    assert_eq!(patterns, [(2, "openai")]);
}

/// A request that breaks the bounds is refused whole (`invalid_params`):
/// more than [`MAX_SCAN_CANDIDATES`] candidates, an empty value, one over
/// [`MAX_CANDIDATE`] bytes, an id twice, a claim that names no marker.
/// Nothing is compared or audited for it. A frame over 1 MiB (a batch the
/// CLI would split) is refused before its body is read (`frame_too_large`)
/// and the connection closed. A well-formed call on a locked vault answers
/// `vault_locked` and is audited as such, with the caller's subject and
/// nothing compared (Codex review: every well-formed call writes one
/// entry, a refused one too).
///
/// Mutations: no bound on the candidates of a call (the 4,097 are
/// compared); a refused call left unaudited (the locked call has no
/// entry).
#[test]
fn requests_over_the_bounds_are_refused_whole() {
    let mut f = Fixture::new(|_, _| {});
    let long = f.value(labels::GITHUB_TOKEN);
    let mut c = client(&f.home);
    let over = copies(&long, MAX_SCAN_CANDIDATES + 1, 0);
    let empty = vec![cand(1, b"", CandidateForm::Raw)];
    let huge = vec![cand(1, &vec![b'a'; MAX_CANDIDATE + 1], CandidateForm::Raw)];
    let twice = vec![
        cand(1, &long, CandidateForm::Raw),
        cand(1, &long, CandidateForm::Raw),
    ];
    for (n, candidates) in [over, empty, huge, twice].into_iter().enumerate() {
        let e = scan(&mut c, ScanPurpose::Import, &[], candidates).unwrap_err();
        assert_eq!(rpc(e), (ErrorKind::InvalidParams, None), "{n}");
    }
    // A claim that is not a marker's name is malformed too.
    let e = scan(
        &mut c,
        ScanPurpose::Import,
        &["not a marker"],
        copies(&long, 1, 0),
    )
    .unwrap_err();
    assert_eq!(rpc(e), (ErrorKind::InvalidParams, None));
    // The largest value is taken.
    let most = vec![cand(1, &vec![b'a'; MAX_CANDIDATE], CandidateForm::Raw)];
    assert_eq!(
        scan(&mut c, ScanPurpose::Import, &[], most)
            .unwrap()
            .compared,
        1
    );
    // Over a frame: 1 MiB and a little of candidates, refused unread.
    let b64 = base64::engine::general_purpose::STANDARD.encode(&long);
    let many: Vec<serde_json::Value> = (0..20_000)
        .map(|i| serde_json::json!({"id": i, "value": b64, "form": "raw"}))
        .collect();
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 9, "method": "scan.match",
        "params": {"candidates": many, "source_kind": "mixed", "purpose": "doctor"}});
    let body = serde_json::to_vec(&body).unwrap();
    assert!(body.len() > 1024 * 1024);
    let mut s = raw(&f.home);
    s.write_all(&u32::try_from(body.len()).unwrap().to_be_bytes())
        .unwrap();
    // The daemon answers from the header and closes; the body's write
    // then fails, which is the point.
    let _ = s.write_all(&body);
    let answer = read_json(&mut s).unwrap();
    assert_eq!(error_kind(&answer), "frame_too_large");
    assert!(answer["id"].is_null());
    assert!(closed(&mut s));
    // A well-formed call on a locked vault is refused and audited, its
    // entry queued until the vault is unlocked: nothing compared.
    c.lock().unwrap();
    let e = scan(&mut c, ScanPurpose::Doctor, &[AGENT], copies(&long, 3, 0)).unwrap_err();
    assert_eq!(rpc(e).0, ErrorKind::VaultLocked);
    c.unlock(passphrase(&f.cs), &[]).unwrap();
    drop(c);
    let v = f.stop_and_open();
    let (entries, _) = v.read_audit().unwrap();
    // The call answered and the call refused on the locked vault are
    // audited, and nothing malformed is.
    let scans = scan_entries(&entries);
    let outcomes: Vec<(&str, &str, u64)> = scans
        .iter()
        .map(|s| (s.0.as_str(), s.1.as_str(), s.2))
        .collect();
    assert_eq!(
        outcomes,
        [("checked", "import", 1), ("vault_locked", "doctor", 0)]
    );
    assert_eq!(named(&scans[0].3, "candidates_transcript"), 1);
    let locked = &scans[1].3;
    assert_eq!(named(locked, "candidates_transcript"), 3);
    for n in [
        "compared_guessable",
        "compared_other",
        "matches",
        "patterns",
    ] {
        assert_eq!(named(locked, n), 0, "{n}");
    }
    // Its subject is the caller's, read before the vault's lock was.
    let refused = entries
        .iter()
        .filter(|e| e.record.kind == AuditKind::ScanMatch)
        .nth(1)
        .unwrap();
    assert_eq!(refused.record.subject.kind.as_deref(), Some("agent"));
    f.sweep_with(&entries);
}

/// `items.mark_exposed` (R-M2-40): an item is marked "exposed: rotate" with
/// the kinds of place and the count; a repeat of the same kinds changes
/// nothing (the view and the audit say `already`); a new kind is added; an
/// id of no item is counted missing, never an error for the rest; any
/// caller may mark (tightening), an agent included; a malformed request is
/// refused whole; and a rotation clears the mark. Each call is audited
/// with the items it marked.
///
/// Mutations: a repeat written again (the count doubles and `already` is
/// 0); rotation leaving the mark (the rotated item still shows it).
#[test]
fn marking_exposed_items_is_idempotent_and_rotation_clears_it() {
    let mut f = Fixture::new(|_, _| {});
    let mut c = client(&f.home);
    let items = c.items_list(false).unwrap().items;
    let id_of = |slug: &str| items.iter().find(|i| i.slug == slug).unwrap().id.clone();
    let (openai, github) = (id_of("openai/acme-web"), id_of("github/acme-web"));
    let mark = |item: &str, sources: &[ExposureSourceView], count| ExposedItem {
        item: item.to_owned(),
        sources: sources.to_vec(),
        count,
    };
    let params = |items: Vec<ExposedItem>, claims: &[&str]| MarkExposedParams {
        items,
        claims: claims.iter().map(|c| (*c).to_owned()).collect(),
    };
    let first = c
        .items_mark_exposed(&params(
            vec![mark(&openai, &[ExposureSourceView::Transcript], 2)],
            &[AGENT],
        ))
        .unwrap();
    assert_eq!((first.marked, first.already, first.missing), (1, 0, 0));
    let shown = c.items_show("openai/acme-web").unwrap();
    let exposed = shown.exposed.clone().unwrap();
    assert_eq!(exposed.sources, [ExposureSourceView::Transcript]);
    assert_eq!(exposed.count, 2);
    // The same again: nothing changes.
    let again = c
        .items_mark_exposed(&params(
            vec![mark(&openai, &[ExposureSourceView::Transcript], 2)],
            &[],
        ))
        .unwrap();
    assert_eq!((again.marked, again.already, again.missing), (0, 1, 0));
    assert_eq!(c.items_show("openai/acme-web").unwrap(), shown);
    // A new kind is added, and an item of no id is counted.
    let gone = "01K00000000000000000000000";
    let more = c
        .items_mark_exposed(&params(
            vec![
                mark(&openai, &[ExposureSourceView::GitHistory], 1),
                mark(&github, &[ExposureSourceView::ConfigBackup], 1),
                mark(gone, &[ExposureSourceView::Transcript], 1),
            ],
            &[],
        ))
        .unwrap();
    assert_eq!((more.marked, more.already, more.missing), (2, 0, 1));
    let exposed = c.items_show("openai/acme-web").unwrap().exposed.unwrap();
    assert_eq!(
        exposed.sources,
        [
            ExposureSourceView::Transcript,
            ExposureSourceView::GitHistory
        ]
    );
    assert_eq!(exposed.count, 3);
    assert!(c.items_list(false).unwrap().items.iter().all(
        |i| i.exposed.is_some() == (i.slug == "openai/acme-web" || i.slug == "github/acme-web")
    ));
    // Refused whole: no items, an id twice, a malformed id, no kind, a
    // count of 0, too many items.
    for bad in [
        params(Vec::new(), &[]),
        params(
            vec![
                mark(&github, &[ExposureSourceView::Transcript], 1),
                mark(&github, &[ExposureSourceView::Transcript], 1),
            ],
            &[],
        ),
        params(
            vec![mark(
                "openai/acme-web",
                &[ExposureSourceView::Transcript],
                1,
            )],
            &[],
        ),
        params(vec![mark(&github, &[], 1)], &[]),
        params(
            vec![mark(&github, &[ExposureSourceView::Transcript], 0)],
            &[],
        ),
        params(
            (0..257)
                .map(|i| mark(&format!("01K{i:023}"), &[ExposureSourceView::EnvFile], 1))
                .collect(),
            &[],
        ),
    ] {
        let e = c.items_mark_exposed(&bad).unwrap_err();
        assert_eq!(rpc(e), (ErrorKind::InvalidParams, None));
    }
    // A rotation clears the mark: the value found elsewhere is not the
    // item's any more.
    let target = c.items_target("openai/acme-web", None, &[]).unwrap();
    let rotated = word(40);
    f.keep("ROTATED", &rotated);
    c.items_rotate(
        &target,
        SecretBytes::copy_from(rotated.as_bytes()),
        passphrase(&f.cs),
        &[],
    )
    .unwrap();
    assert_eq!(c.items_show("openai/acme-web").unwrap().exposed, None);
    assert!(c.items_show("github/acme-web").unwrap().exposed.is_some());
    drop(c);
    let v = f.stop_and_open();
    assert!(
        v.find(&Slug::new("openai/acme-web").unwrap())
            .unwrap()
            .exposure
            .is_none()
    );
    assert!(
        !v.find(&Slug::new("openai/acme-web").unwrap())
            .unwrap()
            .rotate_recommended
    );
    let (entries, _) = v.read_audit().unwrap();
    let marks: Vec<(u64, Vec<String>, u64, u64)> = entries
        .iter()
        .filter(|e| e.record.kind == AuditKind::MarkExposed)
        .map(|e| {
            let d = &e.record.decision;
            (
                d.count.unwrap(),
                e.record.items.iter().map(|(_, s)| s.to_string()).collect(),
                named(&d.counts, "already"),
                named(&d.counts, "missing"),
            )
        })
        .collect();
    assert_eq!(
        marks,
        [
            (1, vec!["openai/acme-web".to_owned()], 0, 0),
            (0, Vec::new(), 1, 0),
            (
                2,
                vec!["openai/acme-web".to_owned(), "github/acme-web".to_owned()],
                0,
                1
            ),
        ]
    );
    f.sweep_with(&entries);
}

/// An answer too large for one frame (a value many items hold, sent under
/// many ids) is refused `frame_too_large`, and its audit entry says so,
/// with the comparisons it counted, never that the matches were answered
/// (L-08; F-77's order: the answer is framed before the entry is
/// written). A smaller batch of the same value is answered and audited
/// `checked`.
///
/// Mutation: an answer too large for its frame recorded as answered (the
/// entry says `checked`).
#[test]
fn an_answer_too_large_for_a_frame_is_audited_as_such() {
    const HOLDERS: usize = 6;
    let same = word(32);
    let held = same.clone();
    let mut f = Fixture::new(move |v, cs| {
        cs.push(Canary::new("HELD_BY_MANY", held.clone()));
        v.transact(|t| {
            for i in 0..HOLDERS {
                let id = t.create_item(NewItem {
                    class: ItemClass::Secret,
                    slug: Slug::new(&format!(
                        "same-value/holder-{i}-of-many-items-that-hold-one-value"
                    ))
                    .unwrap(),
                    details: ItemDetails::default(),
                })?;
                t.add_field(
                    id,
                    FieldName::new("value").unwrap(),
                    SecretBytes::copy_from(held.as_bytes()),
                )?;
            }
            Ok(())
        })
        .unwrap();
    });
    f.keep("SAME", &same);
    let mut c = client(&f.home);
    let e = scan(
        &mut c,
        ScanPurpose::Doctor,
        &[],
        copies(same.as_bytes(), MAX_SCAN_CANDIDATES, 0),
    )
    .unwrap_err();
    assert_eq!(rpc(e).0, ErrorKind::FrameTooLarge);
    let a = scan(
        &mut c,
        ScanPurpose::Doctor,
        &[],
        copies(same.as_bytes(), 100, 0),
    )
    .unwrap();
    assert_eq!((a.compared, a.matches.len()), (100, 100 * HOLDERS));
    drop(c);
    let v = f.stop_and_open();
    let (entries, _) = v.read_audit().unwrap();
    let scans = scan_entries(&entries);
    let outcomes: Vec<(&str, u64)> = scans.iter().map(|s| (s.0.as_str(), s.2)).collect();
    assert_eq!(
        outcomes,
        [
            (
                "frame_too_large",
                u64::try_from(MAX_SCAN_CANDIDATES).unwrap()
            ),
            ("checked", 100)
        ]
    );
    assert_eq!(
        named(&scans[0].3, "matches"),
        u64::try_from(MAX_SCAN_CANDIDATES * HOLDERS).unwrap()
    );
    f.sweep_with(&entries);
}
