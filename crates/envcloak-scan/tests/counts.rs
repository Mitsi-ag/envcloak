//! Doctor counts occurrences without retaining a range and path per reading.
#![allow(clippy::unwrap_used)]
use envcloak_core::SecretBytes;
use envcloak_scan::{
    candidates::{Budget, Candidate, Candidates, Encoding, Form, Occurrence, Source},
    source::ConfigFormat,
    transcript::scan_reader,
};

fn reading(file: &str, value: &[u8], offset: u64) -> Candidate {
    Candidate {
        id: offset,
        value: SecretBytes::copy_from(value),
        form: Form::Raw,
        occurrence: Occurrence {
            source: Source {
                path: file.into(),
                object: None,
            },
            range: offset..offset + value.len() as u64,
            encoding: Encoding::Raw,
            stamp: None,
            rewritable: true,
        },
    }
}

#[test]
fn count_only_repetitions_keep_one_record_per_candidate_and_source() {
    let value = b"fixtureZcountedOccurrence";
    let budget = Budget {
        retained: 2,
        ..Budget::for_counts()
    };
    let mut set = Candidates::counted(budget).unwrap();
    for i in 0..100_000 {
        assert!(set.insert(reading("first", value, i)));
    }
    assert!(set.insert(reading("second", value, 10)));
    assert!(!set.limited());
    assert_eq!(set.entries().len(), 1);
    let entry = &set.entries()[0];
    assert!(entry.occurrences.is_empty());
    assert_eq!(entry.counts.len(), 2);
    assert_eq!(
        entry.counts[&Source {
            path: "first".into(),
            object: None
        }],
        100_000
    );
    assert_eq!(
        entry.counts[&Source {
            path: "second".into(),
            object: None
        }],
        1
    );
    assert!(!set.insert(reading("third", value, 0)));
    assert!(set.limited());
    assert!(!set.insert(reading("first", value, 100_001)));
    assert_eq!(set.entries()[0].counts.values().sum::<u64>(), 100_001);
}

#[test]
fn retained_ranges_and_count_budgets_preserve_accepted_data() {
    let value = b"fixtureZcountedOccurrence";
    let mut ranges = Candidates::new(Budget {
        retained: 2,
        ..Budget::default()
    })
    .unwrap();
    assert!(ranges.insert(reading("first", value, 1)));
    assert!(ranges.insert(reading("first", value, 2)));
    assert!(!ranges.insert(reading("first", value, 3)));
    assert!(ranges.limited());
    assert_eq!(ranges.entries()[0].occurrences.len(), 2);
    assert_eq!(ranges.entries()[0].occurrences[1].range.start, 2);
    assert!(ranges.entries()[0].counts.is_empty());
    for budget in [
        Budget {
            candidates: 0,
            ..Budget::for_counts()
        },
        Budget {
            occurrences: 0,
            ..Budget::for_counts()
        },
        Budget {
            retained: 0,
            ..Budget::for_counts()
        },
    ] {
        let mut set = Candidates::counted(budget).unwrap();
        let report = scan_reader(
            &mut std::io::Cursor::new(value),
            ConfigFormat::Raw,
            Source::default(),
            budget,
            &mut |c| set.insert(c),
        )
        .unwrap();
        assert!(!report.complete());
        assert!(set.entries().is_empty());
    }
    let budget = Budget {
        occurrences: 2,
        ..Budget::for_counts()
    };
    let mut set = Candidates::counted(budget).unwrap();
    assert!(set.insert(reading("first", value, 1)));
    assert!(set.insert(reading("first", value, 2)));
    assert!(!set.insert(reading("first", value, 3)));
    assert!(set.limited());
    assert_eq!(set.entries()[0].counts.values().sum::<u64>(), 2);
}

#[test]
fn count_budget_covers_one_gib_at_measured_host_density() {
    // docs/AGENTS.md: the denser host measured about 12,700 tokens/MiB.
    // Allow two readings per token and keep the distinct-value cap independent.
    let budget = Budget::for_counts();
    assert_eq!(budget.bytes, 1 << 30);
    assert!(budget.occurrences >= 12_700 * 2 * 1024);
    assert_eq!(budget.candidates, Budget::default().candidates);
    let value = b"fixtureZcountedOccurrence";
    let mut set = Candidates::counted(budget).unwrap();
    let mut object = reading("repo", value, 0);
    object.occurrence.source.object = Some("object-one".into());
    assert!(set.insert(object));
    let mut other = reading("repo", value, 0);
    other.occurrence.source.object = Some("object-two".into());
    assert!(set.insert(other));
    assert_eq!(set.entries()[0].counts.len(), 2);
}
