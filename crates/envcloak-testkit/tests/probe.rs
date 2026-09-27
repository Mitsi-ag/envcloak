//! `probe_canaries` arms the allocator probe with what is random in each
//! canary, so a freed buffer holding only a fixture's fixed parts is not a
//! leak, and one holding the random part is.
#![allow(clippy::unwrap_used)]

use envcloak_testkit::{
    ProbeAllocator, ProbeMode, by_label, canaries, fresh_seed, labels, probe_canaries,
};

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

#[test]
fn only_the_random_part_of_a_database_url_is_watched() {
    let cs = canaries(fresh_seed());
    let url = by_label(&cs, labels::DATABASE_URL);
    let password = url.probe_needle();
    let fixed = [
        b"postgres://acme:".to_vec(),
        b"@db.acme.internal:5432/acme".to_vec(),
    ]
    .concat();

    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    drop(std::hint::black_box(fixed));
    let report = session.finish();
    assert_eq!(report.released_with_needle, 0, "{report:?}");

    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    drop(std::hint::black_box(password.to_vec()));
    let report = session.finish();
    assert_eq!(report.released_with_needle, 1, "{report:?}");

    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    drop(std::hint::black_box(url.value().to_vec()));
    let report = session.finish();
    assert_eq!(report.released_with_needle, 1, "{report:?}");
}
