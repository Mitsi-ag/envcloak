//! One test binary keeps one-byte observations free of other probe tests.
use envcloak_sys::testing::{ProbeAllocator, ProbeMode, ProbeSession};
use zeroize::Zeroizing;

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

#[test]
fn one_byte_needle_observes_the_shortest_release() {
    let n = [239u8];
    let session = ProbeSession::start(&[&n], 1, ProbeMode::Unwiped);
    drop(std::hint::black_box(n.to_vec()));
    let control = session.finish();
    assert_eq!(control.released_with_needle, 1, "{control:?}");
    let session = ProbeSession::start(&[&n], 1, ProbeMode::Unwiped);
    drop(std::hint::black_box(Zeroizing::new(n.to_vec())));
    let wiped = session.finish();
    assert_eq!(wiped.released_with_needle, 0, "{wiped:?}");
}
