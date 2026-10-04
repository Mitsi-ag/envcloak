//! `scan.match` (SPEC §6.4, §6.5; M2 plan D-32, task M2-11): the one place
//! candidate tokens a scan found (doctor, scrub, the first-run import,
//! `migrate-mcp`) are compared with the vault, by keyed hash, in this
//! daemon, which alone holds the key. The CLI scans, removes duplicates
//! and sends each distinct candidate once a run; nothing it says about a
//! candidate widens what is compared.
//!
//! A comparison tells the caller whether the vault holds a value, so it is
//! guarded as the import rules guard `import.plan` (L-07):
//! - Each candidate is classed before anything is compared. A token
//!   (`raw`) is guessable as an imported value is
//!   ([`crate::import::guessable`]): under 16 characters as a server reads
//!   it, in every password reading of a URL, a Go DSN or a connection
//!   string, unless a provider's key pattern matches it whole. A password
//!   read out of its value (`url_password`, `dsn_password`,
//!   `conn_password`) is guessable under 16 characters as its form's
//!   server decodes it ([`password_form_chars`]), with no pattern
//!   exception: a password is chosen, not issued.
//! - The purpose decides what is compared, never more than the caller's
//!   subject allows. `import` compares a guessable candidate only for a
//!   caller that may give a proof (a terminal subject with no agent by any
//!   evidence); `doctor` and `scrub` never compare one, for any caller,
//!   terminal provers included, so doctor never reports a short value and
//!   scrub never rewrites one. A guessable candidate left out is counted
//!   in `skipped_guessable` and nowhere else, whether the vault holds it
//!   or not: the answer is the same either way.
//! - Comparisons count against the subject root's budgets, per window of
//!   awake time: a guessable one against the `ValueChecks` the import
//!   methods count against ([`crate::import::MAX_VALUE_CHECKS`]), any
//!   other against `ScanChecks` ([`MAX_SCAN_CHECKS`]). A guessable
//!   candidate is never charged to `ScanChecks`, so a spent `ValueChecks`
//!   stops it whatever is left there, and either budget spent leaves the
//!   other as it was. A budget that runs out during a call compares the
//!   candidates it has room for, in the order sent, and answers `limited`;
//!   one with no room for any is `too_many_checks` with the reason
//!   `limited`, and nothing is compared.
//! - Only `secret` items' current values are compared: never a card's or
//!   a login's (R-M2-34; card detection is M4), nor a prior value. A
//!   candidate is looked up among the secret items' value keys alone
//!   ([`SecretValues`]), so no other class's value is compared at all.
//! - One state lock is held from the vault's check to the answer's frame,
//!   so the vault cannot lock between the budgets' count and the
//!   comparisons it counts. Under it the answer is built only while it can
//!   still fit one frame ([`Answer`]): once its records' least sizes pass
//!   [`MAX_FRAME`] none is built or kept, the matches are only counted,
//!   and the call is `frame_too_large`, so many candidates of a value many
//!   items hold cost a frame's worth of work, not one record a pair.
//! - Each call whose request is well formed writes exactly one audit entry
//!   (kind `scan_match`) with its purpose, source and counts, never a
//!   candidate, after the answer is framed (F-77's order): its outcome is
//!   `checked` or `limited` for an answer sent, and the error's token for
//!   any refusal after the request's checks (`evidence`, `traced`,
//!   `vault_locked`, `too_many_checks`, or `frame_too_large` for an answer
//!   that did not fit a frame, its comparisons counted). A malformed
//!   request (`invalid_params`) is refused before anything is read,
//!   counted or audited.
//! - Candidates live in wiped buffers and are dropped when the call ends.
//!   No error repeats anything the client sent, and nothing is logged.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use envcloak_core::SecretBytes;
use envcloak_core::audit::SubjectSummary;
use envcloak_core::vault::{ValueKey, Vault};
use envcloak_ipc::proto::{
    CandidateForm, ErrorKind, MAX_CANDIDATE, MAX_SCAN_CANDIDATES, ScanMatch, ScanMatchParams,
    ScanPurpose,
};
use envcloak_ipc::view::{ScanMatchView, ScanMatchedView, ScanPatternView};
use envcloak_ipc::{Frame, MAX_FRAME, RpcError};
use envcloak_policy::{Claims, ProcessInstance};
use envcloak_providers::{PasswordForm, password_form_chars};
use envcloak_sys::PeerIdentity;

use crate::audit::{AuditEvent, ScanCounts};
use crate::clock::now_of;
use crate::import::{GUESSABLE_BELOW, SecretValues, ValueChecks, guessable};
use crate::requests::{evidence, subject_summary};
use crate::server::{Shared, locked, refuse_if_traced, result_framed};

/// Candidates that are not guessable one subject root may have compared
/// within [`crate::import::CHECK_WINDOW`] of awake time (`ScanChecks`):
/// D-32's initial size. M2-04 measured about 2,000 distinct raw tokens of
/// 16 or more characters per MiB of what the pinned hosts wrote
/// (docs/AGENTS.md); the scanners also send each token's decoded forms
/// (base64, hex, percent, D-32), so how much of a transcript tree one
/// window covers is M2-14's 1 GiB run to measure, not a figure stated
/// here.
pub const MAX_SCAN_CHECKS: usize = 2_000_000;

/// A candidate's class: whether its value is short enough to guess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Guessable,
    Other,
}

/// The class of `value`, read as `form` says (see the module
/// documentation).
fn class_of(shared: &Shared, value: &SecretBytes, form: CandidateForm) -> Class {
    let short = match form {
        CandidateForm::Raw => guessable(shared, value),
        CandidateForm::UrlPassword => {
            password_form_chars(value, PasswordForm::Url) < GUESSABLE_BELOW
        }
        CandidateForm::DsnPassword => {
            password_form_chars(value, PasswordForm::Dsn) < GUESSABLE_BELOW
        }
        CandidateForm::ConnPassword => {
            password_form_chars(value, PasswordForm::Field) < GUESSABLE_BELOW
        }
    };
    if short {
        Class::Guessable
    } else {
        Class::Other
    }
}

/// Whether `purpose` compares a candidate of `class` for a caller that is
/// a person (`person`: it may give a proof) or not. A candidate that is
/// not guessable is compared for every purpose and every caller; a
/// guessable one only for a person's import.
fn eligible(purpose: ScanPurpose, class: Class, person: bool) -> bool {
    match class {
        Class::Other => true,
        Class::Guessable => purpose == ScanPurpose::Import && person,
    }
}

/// Which of a call's candidates are compared, and the counts its answer
/// and its audit entry give.
#[derive(Debug, Default, PartialEq, Eq)]
struct Admitted {
    /// One per candidate, in order: compared or not.
    compare: Vec<bool>,
    /// Guessable candidates compared, charged to `ValueChecks`.
    guessable: usize,
    /// Other candidates compared, charged to `ScanChecks`.
    other: usize,
    /// Guessable candidates this purpose or caller may not compare.
    skipped_guessable: usize,
    /// Candidates that would have been compared but for a spent budget.
    not_compared: usize,
}

impl Admitted {
    fn compared(&self) -> usize {
        self.guessable + self.other
    }
}

/// Decides which candidates of `classes` are compared for `purpose` and a
/// caller that is a person or not, charging the guessable ones to `value`
/// (`ValueChecks`) and the others to `scan` (`ScanChecks`) for `root` at
/// `awake`. Each budget admits what it has room for, in the order sent.
fn admit(
    classes: &[Class],
    purpose: ScanPurpose,
    person: bool,
    value: &mut ValueChecks,
    scan: &mut ValueChecks,
    root: &ProcessInstance,
    awake: Duration,
) -> Admitted {
    let mut a = Admitted::default();
    let (mut want_guessable, mut want_other) = (0usize, 0usize);
    for &c in classes {
        if !eligible(purpose, c, person) {
            a.skipped_guessable += 1;
        } else if c == Class::Guessable {
            want_guessable += 1;
        } else {
            want_other += 1;
        }
    }
    a.guessable = value.admit_up_to(root, want_guessable, awake);
    a.other = scan.admit_up_to(root, want_other, awake);
    a.not_compared = (want_guessable - a.guessable) + (want_other - a.other);
    let (mut room_guessable, mut room_other) = (a.guessable, a.other);
    a.compare = classes
        .iter()
        .map(|&c| {
            if !eligible(purpose, c, person) {
                return false;
            }
            let room = if c == Class::Guessable {
                &mut room_guessable
            } else {
                &mut room_other
            };
            let take = *room > 0;
            *room = room.saturating_sub(1);
            take
        })
        .collect();
    a
}

/// One candidate, checked: its id, its value and how it was read.
struct Candidate {
    id: u32,
    value: SecretBytes,
    form: CandidateForm,
}

fn invalid() -> RpcError {
    RpcError::new(ErrorKind::InvalidParams)
}

/// The candidates of `p` and its claims, checked before anything is read:
/// at most [`MAX_SCAN_CANDIDATES`], each id once, each value 1 to
/// [`MAX_CANDIDATE`] bytes, and claims that are markers. A request that
/// breaks any of these is malformed: refused whole (`invalid_params`), and
/// nothing is compared, counted or audited.
fn check(p: ScanMatchParams) -> Result<(Vec<Candidate>, Vec<String>), RpcError> {
    if p.candidates.len() > MAX_SCAN_CANDIDATES {
        return Err(invalid());
    }
    Claims::from_markers(&p.claims).map_err(|_| invalid())?;
    let mut ids = HashSet::with_capacity(p.candidates.len());
    let mut out = Vec::with_capacity(p.candidates.len());
    for c in p.candidates {
        let value = c.value.into_inner();
        if !ids.insert(c.id) || value.is_empty() || value.len() > MAX_CANDIDATE {
            return Err(invalid());
        }
        out.push(Candidate {
            id: c.id,
            value,
            form: c.form,
        });
    }
    Ok((out, p.claims))
}

/// What the vault holds for one distinct candidate value: its `secret`
/// items, by id and slug, sorted by slug; or, when none holds it, the
/// providers whose key patterns match it.
struct Found {
    holders: Vec<(String, String)>,
    providers: Vec<String>,
}

/// The items holding the value of `key` now (its current value, never a
/// prior one): looked up among the `secret` items' value keys alone
/// (`secrets`), so a card's or a login's value is never compared.
fn find(shared: &Shared, secrets: &SecretValues, key: &ValueKey, value: &SecretBytes) -> Found {
    let mut holders: Vec<(String, String)> = secrets
        .fields(key)
        .iter()
        .map(|h| (h.item.id.to_string(), h.item.slug.as_str().to_owned()))
        .collect();
    holders.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    holders.dedup();
    let providers = if holders.is_empty() {
        shared.registry.as_ref().map_or_else(Vec::new, |r| {
            r.detect(value, None)
                .candidates
                .iter()
                .map(|p| p.as_str().to_owned())
                .collect()
        })
    } else {
        Vec::new()
    };
    Found { holders, providers }
}

/// `scan.match`, answering request `id` with its result frame. See the
/// module documentation: after the request's checks, every way the call
/// ends writes its one audit entry, with the counts as far as it got and
/// the caller's subject once its evidence was read.
pub fn scan_match(
    shared: &Shared,
    peer: &PeerIdentity,
    id: u64,
    p: ScanMatchParams,
) -> Result<Frame, RpcError> {
    let purpose = p.purpose;
    let source = p.source_kind;
    let (candidates, claims) = check(p)?;
    let mut call = Call {
        subject: None,
        counts: ScanCounts::new(purpose.as_str(), source.as_str(), candidates.len()),
    };
    let answered = answer(shared, peer, id, &claims, purpose, &candidates, &mut call);
    drop(candidates);
    let outcome = match &answered {
        Ok(_) if call.counts.not_compared > 0 => "limited",
        Ok(_) => "checked",
        Err(e) => e.kind.token(),
    };
    shared.audit(AuditEvent::ScanMatched {
        pid: peer.pid,
        subject: call.subject.unwrap_or_else(|| SubjectSummary {
            pid: peer.pid,
            ..SubjectSummary::default()
        }),
        counts: call.counts,
        outcome,
    });
    answered
}

/// What a call's audit entry records: who made it, once its evidence was
/// read, and what it did, by count.
struct Call {
    subject: Option<SubjectSummary>,
    counts: ScanCounts,
}

/// The call after its request's checks: the caller's evidence, the
/// tracer, the vault's lock, the budgets, the comparisons and the answer's
/// frame, filling in `call` as it goes. One state lock is held from the
/// vault's check to the frame.
fn answer(
    shared: &Shared,
    peer: &PeerIdentity,
    id: u64,
    claims: &[String],
    purpose: ScanPurpose,
    candidates: &[Candidate],
    call: &mut Call,
) -> Result<Frame, RpcError> {
    let caller = evidence(shared, peer, claims)?;
    call.subject = Some(subject_summary(peer, &caller));
    refuse_if_traced()?;
    let person = caller.proof_refusal().is_none();
    let root = caller.root();
    let classes: Vec<Class> = candidates
        .iter()
        .map(|c| class_of(shared, &c.value, c.form))
        .collect();
    let now = now_of(&shared.clocks);
    let s = locked(&shared.state);
    let v: &Vault = s.unlocked()?;
    let admitted = {
        // The state lock, then `ValueChecks`, then `ScanChecks`: the order
        // the import methods take the first two in.
        let mut value = locked(&shared.value_checks);
        let mut scan = locked(&shared.scan_checks);
        admit(
            &classes, purpose, person, &mut value, &mut scan, &root, now.awake,
        )
    };
    let c = &mut call.counts;
    c.guessable = admitted.guessable;
    c.other = admitted.other;
    c.skipped_guessable = admitted.skipped_guessable;
    c.not_compared = admitted.not_compared;
    if admitted.compared() == 0 && admitted.not_compared > 0 {
        return Err(RpcError::with_reason(ErrorKind::TooManyChecks, "limited"));
    }
    let secrets = SecretValues::of(v);
    // Each distinct value is looked up once, by its keyed hash.
    let mut seen: BTreeMap<ValueKey, Found> = BTreeMap::new();
    let mut built = Answer::default();
    for (cand, _) in candidates
        .iter()
        .zip(&admitted.compare)
        .filter(|(_, compare)| **compare)
    {
        let key = v.value_key(&cand.value);
        let found = seen
            .entry(key)
            .or_insert_with(|| find(shared, &secrets, &key, &cand.value));
        built.add(cand.id, found);
    }
    c.matches = built.matched;
    c.patterns = built.patterned;
    if built.over {
        if envcloak_sys::test_trace() {
            envcloak_sys::test_event(&format!(
                "scan.match answer over a frame after {} records",
                built.built
            ));
        }
        return Err(RpcError::new(ErrorKind::FrameTooLarge));
    }
    let view = ScanMatchView {
        matches: built.matches,
        patterns: built.patterns,
        compared: u32::try_from(admitted.compared()).unwrap_or(u32::MAX),
        skipped_guessable: u32::try_from(admitted.skipped_guessable).unwrap_or(u32::MAX),
        limited: admitted.not_compared > 0,
    };
    // Framed before the entry is written, so an answer too large for a
    // frame is recorded as such (`frame_too_large`), never as answered.
    result_framed::<ScanMatch>(id, &view)
}

/// The fewest bytes a match takes in the answer's frame, besides its item
/// id and slug: `{"id":0,"item":"","slug":""}`, the shortest id, and no
/// comma before it. Escaping only lengthens a string.
const MATCH_FLOOR: usize = 28;
/// The fewest bytes a pattern takes, besides its provider:
/// `{"id":0,"provider":""}`.
const PATTERN_FLOOR: usize = 22;

/// A `scan.match` answer's matches and patterns, built only while they
/// can still fit one frame (Codex review: many candidates of one value
/// that many items hold would otherwise build millions of records under
/// the state lock before the frame refused them). Each record adds at
/// least its floor to the frame; once those floors pass [`MAX_FRAME`] the
/// answer cannot fit, the records are dropped and no more are built
/// (`over`), and only the counts go on, for the audit entry. Below that
/// the frame itself is the exact check.
#[derive(Debug, Default)]
struct Answer {
    matches: Vec<ScanMatchedView>,
    patterns: Vec<ScanPatternView>,
    /// The least the records built would take in a frame.
    floor: usize,
    /// The answer cannot fit a frame: no record is kept.
    over: bool,
    /// Records built, kept or dropped since.
    built: usize,
    /// Every match and pattern the answer holds, built or not.
    matched: usize,
    patterned: usize,
}

impl Answer {
    /// Adds what the vault holds for candidate `id`.
    fn add(&mut self, id: u32, found: &Found) {
        self.matched += found.holders.len();
        self.patterned += found.providers.len();
        for (item, slug) in &found.holders {
            if !self.room(MATCH_FLOOR + item.len() + slug.len()) {
                return;
            }
            self.built += 1;
            self.matches.push(ScanMatchedView {
                id,
                item: item.clone(),
                slug: slug.clone(),
            });
        }
        for provider in &found.providers {
            if !self.room(PATTERN_FLOOR + provider.len()) {
                return;
            }
            self.built += 1;
            self.patterns.push(ScanPatternView {
                id,
                provider: provider.clone(),
            });
        }
    }

    /// Whether a record of at least `bytes` can still be added; once one
    /// cannot, the answer is over a frame and keeps nothing.
    fn room(&mut self, bytes: usize) -> bool {
        if self.over {
            return false;
        }
        self.floor = self.floor.saturating_add(bytes);
        if self.floor > MAX_FRAME {
            self.over = true;
            self.matches = Vec::new();
            self.patterns = Vec::new();
        }
        !self.over
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::{CHECK_WINDOW, MAX_VALUE_CHECKS};

    fn root(pid: i32) -> ProcessInstance {
        ProcessInstance {
            pid,
            start_time: envcloak_sys::StartTime::from_raw(7),
            pidversion: None,
            exe: None,
        }
    }

    /// The budgets a daemon starts with.
    fn budgets() -> (ValueChecks, ValueChecks) {
        (
            ValueChecks::default(),
            ValueChecks::with_limit(MAX_SCAN_CHECKS),
        )
    }

    use Class::{Guessable as G, Other as O};
    use ScanPurpose::{Doctor, Import, Scrub};

    /// The purposes' rules: a candidate that is not guessable is compared
    /// for every purpose and caller; a guessable one only for a person's
    /// import, and is otherwise counted as skipped and charged nowhere.
    ///
    /// Mutations: the import rules for every purpose (one shared filter:
    /// a person's doctor and scrub compare the guessable candidate);
    /// guessable candidates compared for anyone (an agent's import
    /// compares it).
    #[test]
    fn each_purpose_compares_what_its_rules_allow() {
        let r = root(10);
        let t0 = Duration::from_secs(1000);
        for (purpose, person, compare) in [
            (Import, true, vec![true, true]),
            (Import, false, vec![true, false]),
            (Doctor, true, vec![true, false]),
            (Doctor, false, vec![true, false]),
            (Scrub, true, vec![true, false]),
            (Scrub, false, vec![true, false]),
        ] {
            let (mut value, mut scan) = budgets();
            let a = admit(&[O, G], purpose, person, &mut value, &mut scan, &r, t0);
            assert_eq!(a.compare, compare, "{purpose:?} person={person}");
            let skipped = usize::from(!compare[1]);
            assert_eq!(a.skipped_guessable, skipped, "{purpose:?} {person}");
            assert_eq!(a.guessable, 1 - skipped, "{purpose:?} {person}");
            assert_eq!((a.other, a.not_compared), (1, 0));
            // A guessable candidate left out took nothing from either budget.
            assert_eq!(
                value.admit_up_to(&r, MAX_VALUE_CHECKS, t0),
                MAX_VALUE_CHECKS - a.guessable
            );
            assert_eq!(
                scan.admit_up_to(&r, MAX_SCAN_CHECKS, t0),
                MAX_SCAN_CHECKS - 1
            );
        }
    }

    /// Each budget stops at its own limit, in the root's window of awake
    /// time (an injected clock): the call that reaches it compares what
    /// fits, in the order sent, and says the rest was not compared; the
    /// next compares nothing. Exhausting one leaves the other usable, and
    /// a guessable candidate is never charged to `ScanChecks`: with
    /// `ValueChecks` spent and `ScanChecks` empty, a person's guessable
    /// candidate is still not compared. A new window starts an hour of
    /// awake time after the first count; another root has its own.
    ///
    /// Mutations: a guessable candidate charged to `ScanChecks` (it is
    /// compared with `ValueChecks` spent); the limiter skipped (every
    /// candidate compared past the limits).
    #[test]
    fn each_budget_stops_at_its_limit_and_the_other_goes_on() {
        let r = root(10);
        let t0 = Duration::from_secs(1000);
        let (mut value, mut scan) = budgets();
        // `ScanChecks` up to one short of its limit.
        assert_eq!(
            scan.admit_up_to(&r, MAX_SCAN_CHECKS - 1, t0),
            MAX_SCAN_CHECKS - 1
        );
        let a = admit(&[O, O, G, O], Import, true, &mut value, &mut scan, &r, t0);
        assert_eq!(a.compare, [true, false, true, false]);
        assert_eq!((a.guessable, a.other, a.not_compared), (1, 1, 2));
        let a = admit(&[O], Doctor, true, &mut value, &mut scan, &r, t0);
        assert_eq!(
            (a.compare.as_slice(), a.compared(), a.not_compared),
            (&[false][..], 0, 1)
        );
        // `ScanChecks` spent: guessable candidates still go to
        // `ValueChecks`, up to its limit.
        let many = vec![G; MAX_VALUE_CHECKS];
        let a = admit(&many, Import, true, &mut value, &mut scan, &r, t0);
        assert_eq!((a.guessable, a.not_compared), (MAX_VALUE_CHECKS - 1, 1));
        let a = admit(&[G], Import, true, &mut value, &mut scan, &r, t0);
        assert_eq!((a.compared(), a.not_compared), (0, 1));
        // Another root has both budgets to itself.
        let other = root(20);
        let a = admit(&[G, O], Import, true, &mut value, &mut scan, &other, t0);
        assert_eq!(a.compare, [true, true]);
        // A window ends an hour of awake time after its first count.
        let later = t0 + CHECK_WINDOW;
        let a = admit(&[G, O], Import, true, &mut value, &mut scan, &r, later);
        assert_eq!(a.compare, [true, true]);
        // `ValueChecks` spent, `ScanChecks` with room: a guessable
        // candidate is not compared, and charges nothing there.
        let (mut value, mut scan) = budgets();
        assert!(value.admit(&r, MAX_VALUE_CHECKS, t0));
        let a = admit(&[G, O], Import, true, &mut value, &mut scan, &r, t0);
        assert_eq!(a.compare, [false, true]);
        assert_eq!((a.guessable, a.other, a.not_compared), (0, 1, 1));
        assert_eq!(
            scan.admit_up_to(&r, MAX_SCAN_CHECKS, t0),
            MAX_SCAN_CHECKS - 1
        );
    }

    /// What the vault holds for one value: `n` items, ids and slugs of
    /// real lengths, and no pattern.
    fn held_by(n: usize) -> Found {
        Found {
            holders: (0..n)
                .map(|i| (format!("{i:026}"), format!("same-value/holder-{i}")))
                .collect(),
            providers: Vec::new(),
        }
    }

    /// Each floor is the fewest bytes its record takes in a frame: the
    /// shortest record serializes to exactly it, and a real answer to at
    /// least the floors of its records, so an answer the floors put over a
    /// frame could never have fit.
    #[test]
    fn the_floors_are_the_least_a_record_takes() {
        let m = ScanMatchedView {
            id: 0,
            item: String::new(),
            slug: String::new(),
        };
        let p = ScanPatternView {
            id: 0,
            provider: String::new(),
        };
        assert_eq!(serde_json::to_vec(&m).unwrap().len(), MATCH_FLOOR);
        assert_eq!(serde_json::to_vec(&p).unwrap().len(), PATTERN_FLOOR);
        let mut a = Answer::default();
        for id in [7, 4_000_000_000] {
            a.add(id, &held_by(5));
            a.add(
                id,
                &Found {
                    holders: Vec::new(),
                    providers: vec!["openai".to_owned(), "stripe".to_owned()],
                },
            );
        }
        assert!(!a.over);
        assert_eq!((a.matches.len(), a.patterns.len()), (10, 4));
        let records = serde_json::to_vec(&a.matches).unwrap().len()
            + serde_json::to_vec(&a.patterns).unwrap().len();
        assert!(records >= a.floor, "{records} {}", a.floor);
    }

    /// An answer that cannot fit a frame stops being built once its
    /// records' floors pass one (Codex review): many candidates of one
    /// value a thousand items hold (a million matches) build at most a
    /// frame's worth of records, keep none, and still count every match
    /// for the audit entry. A smaller answer is built whole, in order.
    ///
    /// Mutation: the bound only at the frame (`room` always true): the
    /// million records are built, and this fails.
    #[test]
    fn an_answer_too_large_for_a_frame_stops_being_built() {
        let found = held_by(1000);
        let mut a = Answer::default();
        for id in 0..1000 {
            a.add(id, &found);
        }
        assert!(a.over);
        assert!(a.built <= MAX_FRAME / MATCH_FLOOR + 1, "{}", a.built);
        assert!(a.matches.is_empty() && a.patterns.is_empty());
        assert_eq!((a.matched, a.patterned), (1_000_000, 0));
        let mut a = Answer::default();
        for id in 0..3 {
            a.add(id, &held_by(2));
        }
        assert!(!a.over);
        let got: Vec<(u32, &str)> = a.matches.iter().map(|m| (m.id, m.slug.as_str())).collect();
        assert_eq!(
            got,
            [
                (0, "same-value/holder-0"),
                (0, "same-value/holder-1"),
                (1, "same-value/holder-0"),
                (1, "same-value/holder-1"),
                (2, "same-value/holder-0"),
                (2, "same-value/holder-1"),
            ]
        );
    }
}
