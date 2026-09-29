//! What a panic shows (SPEC §15.2 gate 12): its place in the source, never
//! its message.
//!
//! A panic's message is built from whatever the failing code had at hand:
//! an `unwrap` on a result whose error quotes its input, an index shown
//! with the slice it was out of, a format string with a value in it. Rust's
//! default hook prints that message, so a panic anywhere near a value could
//! put the value on standard error, which an agent reads. [`install`]
//! replaces the hook with one that prints the program's name and where the
//! panic happened, and nothing the panic carried. Both binaries install it
//! first thing in `main`; release builds then abort (`panic = "abort"`),
//! with core dumps off.
//!
//! [`panic_point`] and [`panic_with_input`] let tests cause a panic whose
//! message holds a fixture: the first at named places on a value path, in
//! test builds only; the second from `internal panic`, a hidden command of
//! both binaries, in every build, so a release artifact can be shown to
//! abort without a core file and without the message.

use std::io::{Read, Write};

/// The most `internal panic` reads from standard input.
const MAX_INPUT: u64 = 64 * 1024;

/// Replaces the panic hook with one that writes one line to standard
/// error, naming `program` and the panic's place in the source (a file
/// path of this repository or of the standard library, and a line), and
/// never the message. A write that fails is ignored: the process is going
/// down, and standard error may be gone.
pub fn install(program: &'static str) {
    std::panic::set_hook(Box::new(move |info| {
        let line = match info.location() {
            Some(l) => format!(
                "{program}: internal error: a panic at {}:{}; its message is not shown, since it \
                 could hold a secret\n",
                l.file(),
                l.line()
            ),
            None => format!(
                "{program}: internal error: a panic; its message is not shown, since it could \
                 hold a secret\n"
            ),
        };
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
    }));
}

/// A place on a value path where a test build can be made to panic (gate
/// 12's injected panics). Nothing in a build without the `testing`
/// feature, which only tests enable (release builds never have it:
/// `crates/envcloak-cli/tests/release_features.rs`). With it, when
/// `ENVCLOAK_TEST_PANIC` names `site`, the process panics here, with the
/// contents of the file `ENVCLOAK_TEST_PANIC_FILE` names in the message,
/// and the caller's place as the panic's.
#[track_caller]
pub fn panic_point(site: &str) {
    #[cfg(feature = "testing")]
    crate::testing::panic_point(site);
    #[cfg(not(feature = "testing"))]
    let _ = site;
}

/// Panics with what standard input holds (at most 64 KiB) in the message:
/// `envcloak internal panic` and `envcloakd internal panic`. With the hook
/// [`install`] sets, the message is never shown; a release build then
/// aborts, and leaves no core file.
pub fn panic_with_input() -> ! {
    let mut input = Vec::new();
    let _ = std::io::stdin()
        .lock()
        .take(MAX_INPUT)
        .read_to_end(&mut input);
    panic!(
        "internal panic requested, with this input: {}",
        String::from_utf8_lossy(&input)
    );
}
