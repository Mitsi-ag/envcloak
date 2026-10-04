//! An independent oracle for `scan.match`'s admission (M2-11; L-02): which
//! candidates a call compares and what each budget counts, checked against
//! a model written from the contract (docs/IPC.md "Comparisons with the
//! vault", M2 plan D-32), never from this daemon's functions. The model
//! knows the rules only as they are stated:
//! - a guessable candidate is compared only for a person's `import`; any
//!   other candidate for every purpose and every caller;
//! - guessable candidates count against one budget and the others against
//!   another, each with its own limit a root may use in an hour of awake
//!   time: a root's window starts at its first count (a call that wants a
//!   comparison starts it even when none fits; one that wants none takes
//!   no place) and ends an hour later;
//! - a budget short of room compares the first candidates of its class,
//!   in the order sent;
//! - a root is a process, its pid and its start time, whatever else is
//!   known of it (a pid version, an executable).
//!
//! It works by ranks and tables of its own: a candidate is compared when
//! its rank among the eligible candidates of its class is under its
//! budget's room, the limit less the root's count in that budget's table.
//!
//! The matrix: every purpose, both callers; inputs empty, of one class and
//! mixed in several orders; budgets with no room, small ones and the real
//! sizes; tables fresh, full and one short of full; steps from four roots
//! (the first; another pid; another start time; the first process with
//! its pid version and executable known) and a step just before, at and
//! just after a window's end. 3,186 cases of six steps; after each step
//! the mask of what was compared, the counts and both budgets' tables
//! must be the model's. 18 cases are positive controls, inputs no fault
//! below touches (one root, candidates that are never guessable, room for
//! all), which agree under each fault while the other cases catch it.
//!
//! Faults this catches, each applied to the daemon's code and seen to
//! fail here with all 18 controls agreeing: the caller ignored (an agent's
//! import compares a guessable candidate); the purpose ignored (a person's
//! doctor and scrub do); a guessable candidate charged to the other
//! budget; the input's order reversed; a window that ends late (kept at
//! its hour); a root keyed by its pid alone.

use std::collections::BTreeMap;
use std::time::Duration;

use envcloak_ipc::proto::ScanPurpose;
use envcloak_policy::ProcessInstance;
use envcloak_sys::{ExeIdentity, StartTime};

use super::{Class, MAX_SCAN_CHECKS, admit};
use crate::import::{CHECK_WINDOW, MAX_CHECKING_ROOTS, MAX_VALUE_CHECKS, ValueChecks};

/// An hour, in nanoseconds of awake time: the contract's window.
const HOUR: u64 = 3_600_000_000_000;
/// The awake time a case starts at.
const T0: u64 = 1_000_000_000;
/// The budgets' real sizes, as the contract states them: guessable
/// candidates (`ValueChecks`, shared with the import methods), others
/// (`ScanChecks`).
const REAL: (usize, usize) = (100_000, 2_000_000);

/// The roots the steps come from, as (pid, start time): the first, another
/// pid, another start time, and the first again.
const ROOTS: [(i32, u64); 4] = [(11, 101), (12, 101), (11, 102), (11, 101)];

/// The roots as the daemon knows them: the fourth is the first process
/// with its pid version and executable known.
fn root(n: usize) -> ProcessInstance {
    let (pid, start) = ROOTS[n];
    ProcessInstance {
        pid,
        start_time: StartTime::from_raw(start),
        pidversion: (n == 3).then_some(17),
        exe: (n == 3).then(|| ExeIdentity {
            path: "/oracle/root".into(),
            file: None,
            sha256: None,
            signature: None,
        }),
    }
}

/// A budget's table: each root's window start (awake nanoseconds) and
/// count.
type Table = BTreeMap<(i32, u64), (u64, usize)>;

/// One case: the limits and the tables' first counts (of the first root,
/// at `T0`), as (guessable, other); the purpose and caller; and its steps
/// as (root, awake nanoseconds, candidates: `g` guessable, `o` other).
struct Case {
    id: usize,
    control: bool,
    limits: (usize, usize),
    warm: (usize, usize),
    purpose: ScanPurpose,
    person: bool,
    steps: Vec<(usize, u64, &'static str)>,
}

/// What one step must give.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    compare: Vec<bool>,
    guessable: usize,
    other: usize,
    skipped: usize,
    not_compared: usize,
    value: Table,
    scan: Table,
}

const PATTERNS: [&str; 8] = ["", "o", "g", "og", "go", "ogog", "gogo", "ooggogo"];
const PURPOSES: [ScanPurpose; 3] = [ScanPurpose::Import, ScanPurpose::Doctor, ScanPurpose::Scrub];
/// A case's first step comes this long after `T0`: at once, just before
/// the warm window's end, at it, just after.
const DELAYS: [u64; 4] = [0, HOUR - 1, HOUR, HOUR + 1];

/// Case `id`, of `who` (the purpose, and whether the caller is a person).
fn case(
    id: usize,
    control: bool,
    limits: (usize, usize),
    warm: (usize, usize),
    delay: u64,
    who: (ScanPurpose, bool),
    bits: &'static str,
) -> Case {
    let (purpose, person) = who;
    let at = T0 + delay;
    let (others, last) = if control { (0, "oo") } else { (1, "og") };
    let steps = vec![
        (0, at, bits),
        (0, at + 1, bits),
        (others, at + 2, bits),
        (2 * others, at + 3, bits),
        (3 * others, at + 4, bits),
        (0, at + HOUR + 1, last),
    ];
    Case {
        id,
        control,
        limits,
        warm,
        purpose,
        person,
        steps,
    }
}

/// The matrix (see the module documentation).
fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    let full_less_one = |l: (usize, usize)| (l.0.saturating_sub(1), l.1.saturating_sub(1));
    for limits in [(0, 0), (1, 1), (2, 3), (5, 2), (32, 32)] {
        for warm in [(0, 0), limits, full_less_one(limits)] {
            for delay in DELAYS {
                for purpose in PURPOSES {
                    for person in [false, true] {
                        for bits in PATTERNS {
                            let c = case(
                                out.len(),
                                false,
                                limits,
                                warm,
                                delay,
                                (purpose, person),
                                bits,
                            );
                            out.push(c);
                        }
                    }
                }
            }
        }
    }
    for warm in [(0, 0), REAL, full_less_one(REAL)] {
        for delay in DELAYS {
            for purpose in PURPOSES {
                for person in [false, true] {
                    for bits in ["og", "go", "gogo", "ooggogo"] {
                        let c = case(out.len(), false, REAL, warm, delay, (purpose, person), bits);
                        out.push(c);
                    }
                }
            }
        }
    }
    for purpose in PURPOSES {
        for person in [false, true] {
            for bits in ["o", "oo", "ooooooo"] {
                let c = case(
                    out.len(),
                    true,
                    (64, 64),
                    (0, 0),
                    0,
                    (purpose, person),
                    bits,
                );
                out.push(c);
            }
        }
    }
    out
}

/// The positions of `class` in `bits`, in order.
fn positions(bits: &str, class: char) -> Vec<usize> {
    bits.char_indices()
        .filter(|(_, c)| *c == class)
        .map(|(i, _)| i)
        .collect()
}

/// The model's step: what a call of `bits` from root `r` at `awake`
/// compares and counts, given and updating the two tables.
fn model(
    c: &Case,
    value: &mut Table,
    scan: &mut Table,
    r: usize,
    awake: u64,
    bits: &str,
) -> Outcome {
    for t in [&mut *value, &mut *scan] {
        t.retain(|_, (start, _)| awake - *start < HOUR);
    }
    let key = ROOTS[r];
    let guess = positions(bits, 'g');
    let other = positions(bits, 'o');
    let eligible: Vec<usize> = if c.purpose == ScanPurpose::Import && c.person {
        guess.clone()
    } else {
        Vec::new()
    };
    let room = |t: &Table, limit: usize| limit - t.get(&key).map_or(0, |e| e.1);
    let g: Vec<usize> = eligible
        .iter()
        .copied()
        .take(room(value, c.limits.0))
        .collect();
    let o: Vec<usize> = other.iter().copied().take(room(scan, c.limits.1)).collect();
    for (t, want, took) in [
        (&mut *value, eligible.len(), g.len()),
        (&mut *scan, other.len(), o.len()),
    ] {
        if want > 0 {
            t.entry(key).or_insert((awake, 0)).1 += took;
        }
    }
    Outcome {
        compare: (0..bits.len())
            .map(|i| g.contains(&i) || o.contains(&i))
            .collect(),
        guessable: g.len(),
        other: o.len(),
        skipped: guess.len() - eligible.len(),
        not_compared: eligible.len() + other.len() - g.len() - o.len(),
        value: value.clone(),
        scan: scan.clone(),
    }
}

/// A budget of the daemon's, as a table of the model's form.
fn table(b: &ValueChecks) -> Table {
    b.windows()
        .1
        .into_iter()
        .map(|(r, start, n)| {
            let at = u64::try_from(start.as_nanos()).unwrap();
            ((r.pid, r.start_time.raw()), (at, n))
        })
        .collect()
}

/// Runs case `c` through the daemon's admission, step by step, against the
/// model: the first step that differs, or none.
fn run(c: &Case) -> Result<(), String> {
    let mut value = ValueChecks::with_limit(c.limits.0);
    let mut scan = ValueChecks::with_limit(c.limits.1);
    let (mut model_value, mut model_scan) = (Table::new(), Table::new());
    let t0 = Duration::from_nanos(T0);
    for (b, t, warm) in [
        (&mut value, &mut model_value, c.warm.0),
        (&mut scan, &mut model_scan, c.warm.1),
    ] {
        assert!(b.admit(&root(0), warm, t0));
        if warm > 0 {
            t.insert(ROOTS[0], (T0, warm));
        }
    }
    for (n, &(r, awake, bits)) in c.steps.iter().enumerate() {
        let want = model(c, &mut model_value, &mut model_scan, r, awake, bits);
        let classes: Vec<Class> = bits
            .chars()
            .map(|b| {
                if b == 'g' {
                    Class::Guessable
                } else {
                    Class::Other
                }
            })
            .collect();
        let a = admit(
            &classes,
            c.purpose,
            c.person,
            &mut value,
            &mut scan,
            &root(r),
            Duration::from_nanos(awake),
        );
        let got = Outcome {
            compare: a.compare,
            guessable: a.guessable,
            other: a.other,
            skipped: a.skipped_guessable,
            not_compared: a.not_compared,
            value: table(&value),
            scan: table(&scan),
        };
        if got != want {
            return Err(format!("step {n}: got {got:?}, want {want:?}"));
        }
    }
    Ok(())
}

/// Every case of the matrix agrees with the model (see the module
/// documentation), the controls included, and the daemon's budgets are the
/// contract's sizes.
#[test]
fn admission_agrees_with_an_independent_model() {
    assert_eq!(
        (MAX_VALUE_CHECKS, MAX_SCAN_CHECKS),
        REAL,
        "the budgets' sizes"
    );
    assert_eq!(ValueChecks::default().windows().0, REAL.0);
    assert_eq!(CHECK_WINDOW, Duration::from_nanos(HOUR));
    assert_eq!(MAX_CHECKING_ROOTS, 4096);
    let cases = cases();
    let steps: usize = cases.iter().map(|c| c.steps.len()).sum();
    let controls = cases.iter().filter(|c| c.control).count();
    assert_eq!((cases.len(), steps, controls), (3186, 19_116, 18));
    let mut failed = Vec::new();
    let mut agreed_controls = 0;
    for c in &cases {
        match run(c) {
            Ok(()) => agreed_controls += usize::from(c.control),
            Err(e) => failed.push((c.id, e)),
        }
    }
    assert!(
        failed.is_empty(),
        "{} of {} cases differ from the model ({agreed_controls} of {controls} controls agree); \
         first: {:?}",
        failed.len(),
        cases.len(),
        &failed[..failed.len().min(2)]
    );
    assert_eq!(agreed_controls, controls);
}
