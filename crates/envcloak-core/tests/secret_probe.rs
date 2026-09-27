//! Gate 11 for the secret types: building, growing, freezing and dropping
//! `SecretBytes` and `SecretBuf` never frees a block that still holds the
//! value. The probe runs with the allocator's own wipe turned off
//! (`ProbeMode::Unwiped`), so these types must wipe by themselves.
#![allow(clippy::unwrap_used)]

use envcloak_core::{SecretBuf, SecretBytes};
use envcloak_testkit::{
    Canary, ProbeAllocator, ProbeMode, by_label, canaries, fresh_seed, labels, probe_canaries,
};

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

fn fixtures() -> Vec<Canary> {
    canaries(fresh_seed())
}

#[test]
fn probe_sees_an_unwiped_copy_of_a_canary() {
    // Negative control: a plain Vec holding the canary is caught.
    let cs = fixtures();
    let c = by_label(&cs, labels::OPENAI_API_KEY);
    let session = probe_canaries(&cs, ProbeMode::Unwiped);
    drop(std::hint::black_box(c.value().to_vec()));
    let report = session.finish();
    assert!(report.released_with_needle >= 1, "{report:?}");
}

#[test]
fn secret_bytes_free_no_unwiped_copies() {
    let cs = fixtures();
    let v = by_label(&cs, labels::DATABASE_URL).value();
    let session = probe_canaries(&cs, ProbeMode::Unwiped);

    // Spare capacity: moved to an exact allocation, original wiped.
    let mut spare = Vec::with_capacity(4 * v.len());
    spare.extend_from_slice(v);
    drop(SecretBytes::from_vec(spare));

    // Exact capacity: kept in place.
    let mut exact = vec![0u8; v.len()];
    exact.copy_from_slice(v);
    drop(SecretBytes::from_vec(exact));

    drop(SecretBytes::copy_from(v));

    let report = session.finish();
    assert_eq!(report.released_with_needle, 0, "{report:?}");
}

#[test]
fn secret_buf_free_no_unwiped_copies() {
    let cs = fixtures();
    let v = by_label(&cs, labels::OPENAI_API_KEY).value();
    let session = probe_canaries(&cs, ProbeMode::Unwiped);

    // Fill, refuse overflow, grow, finish, freeze with spare capacity.
    let mut b = SecretBuf::with_capacity(16);
    b.extend(&v[..16]).unwrap();
    assert!(b.extend(&v[16..]).is_err());
    b.grow(v.len() + 32);
    b.extend(&v[16..]).unwrap();
    drop(b.freeze());

    // Freeze without moving.
    let mut full = SecretBuf::with_capacity(v.len());
    let cap = full.capacity();
    full.extend(&v[..cap.min(v.len())]).unwrap();
    drop(full.freeze());

    // Truncate and clear wipe the removed bytes; drop wipes the rest.
    let mut t = SecretBuf::with_capacity(v.len());
    t.extend(v).unwrap();
    t.truncate(20);
    t.clear();
    t.extend(v).unwrap();
    drop(t);

    let report = session.finish();
    assert_eq!(report.released_with_needle, 0, "{report:?}");
}
