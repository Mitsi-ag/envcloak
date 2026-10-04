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
//!   a login's (R-M2-34; card detection is M4), nor a prior value.
//! - Each call writes one audit entry (kind `scan_match`) with its purpose,
//!   source and counts, and never a candidate; a refused one too.
//! - Candidates live in wiped buffers and are dropped when the call ends.
//!   No error repeats anything the client sent, and nothing is logged.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use envcloak_core::SecretBytes;
use envcloak_core::crypto::ItemClass;
use envcloak_core::vault::{FieldId, ItemMeta, ValueKey, Vault};
use envcloak_ipc::RpcError;
use envcloak_ipc::proto::{
    CandidateForm, ErrorKind, MAX_CANDIDATE, MAX_SCAN_CANDIDATES, ScanMatchParams, ScanPurpose,
};
use envcloak_ipc::view::{ScanMatchView, ScanMatchedView, ScanPatternView};
use envcloak_policy::ProcessInstance;
use envcloak_providers::{PasswordForm, password_form_chars};
use envcloak_sys::PeerIdentity;

use crate::audit::{AuditEvent, ScanCounts};
use crate::clock::now_of;
use crate::import::{GUESSABLE_BELOW, ValueChecks, guessable};
use crate::requests::{evidence, subject_summary};
use crate::server::{Shared, locked, refuse_if_traced};

/// Candidates that are not guessable one subject root may have compared
/// within [`crate::import::CHECK_WINDOW`] of awake time (`ScanChecks`, M2
/// plan D-32). Sized from M2-04's measurement of what the pinned hosts
/// write (docs/AGENTS.md: at most about 2,000 distinct candidates of 16 or
/// more characters per MiB): about a GiB of transcripts an hour, after the
/// CLI's de-duplication.
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

/// The candidates of `p`, checked before anything is read: at most
/// [`MAX_SCAN_CANDIDATES`], each id once, each value 1 to
/// [`MAX_CANDIDATE`] bytes. A request that breaks any of these is refused
/// whole (`invalid_params`), and nothing is compared or counted.
fn check(p: ScanMatchParams) -> Result<Vec<Candidate>, RpcError> {
    if p.candidates.len() > MAX_SCAN_CANDIDATES {
        return Err(invalid());
    }
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
    Ok(out)
}

/// What the vault holds for one distinct candidate value: its `secret`
/// items, by id and slug, sorted by slug; or, when none holds it, the
/// providers whose key patterns match it.
struct Found {
    holders: Vec<(String, String)>,
    providers: Vec<String>,
}

/// The items holding `value` now (its current value, never a prior one),
/// from `owners`, the `secret` items' fields: a card's or a login's field
/// is not in it, so neither ever matches.
fn find(
    shared: &Shared,
    v: &Vault,
    owners: &HashMap<FieldId, &ItemMeta>,
    value: &SecretBytes,
) -> Found {
    let mut holders: Vec<(String, String)> = v
        .find_by_value(value)
        .iter()
        .filter_map(|f| owners.get(f))
        .map(|m| (m.id.to_string(), m.slug.as_str().to_owned()))
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

/// `scan.match`. See the module documentation.
pub fn scan_match(
    shared: &Shared,
    peer: &PeerIdentity,
    p: ScanMatchParams,
) -> Result<ScanMatchView, RpcError> {
    let purpose = p.purpose;
    let source = p.source_kind;
    let claims = p.claims.clone();
    let candidates = check(p)?;
    refuse_if_traced()?;
    locked(&shared.state).unlocked()?;
    let caller = evidence(shared, peer, &claims)?;
    let person = caller.proof_refusal().is_none();
    let classes: Vec<Class> = candidates
        .iter()
        .map(|c| class_of(shared, &c.value, c.form))
        .collect();
    let now = now_of(&shared.clocks);
    let admitted = {
        // Always `ValueChecks` first, as the import methods take it alone.
        let mut value = locked(&shared.value_checks);
        let mut scan = locked(&shared.scan_checks);
        admit(
            &classes,
            purpose,
            person,
            &mut value,
            &mut scan,
            &caller.root(),
            now.awake,
        )
    };
    let mut counts = ScanCounts {
        purpose: purpose.as_str(),
        source: source.as_str(),
        candidates: candidates.len(),
        guessable: admitted.guessable,
        other: admitted.other,
        skipped_guessable: admitted.skipped_guessable,
        not_compared: admitted.not_compared,
        matches: 0,
        patterns: 0,
    };
    if admitted.compared() == 0 && admitted.not_compared > 0 {
        shared.audit(AuditEvent::ScanMatched {
            pid: peer.pid,
            subject: subject_summary(peer, &caller),
            counts,
            refused: true,
        });
        return Err(RpcError::with_reason(ErrorKind::TooManyChecks, "limited"));
    }
    let mut s = locked(&shared.state);
    let (matches, patterns) = {
        let v = s.unlocked()?;
        let owners: HashMap<FieldId, &ItemMeta> = v
            .items()
            .iter()
            .filter(|m| m.class == ItemClass::Secret)
            .flat_map(|m| m.fields.iter().map(move |f| (f.id, m)))
            .collect();
        // Each distinct value is looked up once, by its keyed hash.
        let mut seen: BTreeMap<ValueKey, Found> = BTreeMap::new();
        let (mut matches, mut patterns) = (Vec::new(), Vec::new());
        for (c, _) in candidates
            .iter()
            .zip(&admitted.compare)
            .filter(|(_, compare)| **compare)
        {
            let found = seen
                .entry(v.value_key(&c.value))
                .or_insert_with(|| find(shared, v, &owners, &c.value));
            for (item, slug) in &found.holders {
                matches.push(ScanMatchedView {
                    id: c.id,
                    item: item.clone(),
                    slug: slug.clone(),
                });
            }
            for provider in &found.providers {
                patterns.push(ScanPatternView {
                    id: c.id,
                    provider: provider.clone(),
                });
            }
        }
        (matches, patterns)
    };
    drop(candidates);
    counts.matches = matches.len();
    counts.patterns = patterns.len();
    s.audit(AuditEvent::ScanMatched {
        pid: peer.pid,
        subject: subject_summary(peer, &caller),
        counts,
        refused: false,
    });
    Ok(ScanMatchView {
        matches,
        patterns,
        compared: u32::try_from(admitted.compared()).unwrap_or(u32::MAX),
        skipped_guessable: u32::try_from(admitted.skipped_guessable).unwrap_or(u32::MAX),
        limited: admitted.not_compared > 0,
    })
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
}
