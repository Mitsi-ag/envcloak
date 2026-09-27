//! A deliberate violation: every way this file opens a secret must be
//! reported by clippy's disallowed-methods lint, configured in the root
//! clippy.toml. scripts/check-expose-lint.sh counts the reports against the
//! EXPECT-DISALLOWED markers. Never add this file to the expose allowlist.

use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};

pub fn method_call(s: &SecretBox<[u8; 4]>) -> u8 {
    s.expose_secret()[0] // EXPECT-DISALLOWED
}

pub fn path_call(s: &SecretBox<[u8; 4]>) -> u8 {
    ExposeSecret::expose_secret(s)[0] // EXPECT-DISALLOWED
}

pub fn mutable(s: &mut SecretBox<[u8; 4]>) {
    s.expose_secret_mut()[0] = 1; // EXPECT-DISALLOWED
}

/// A wrapper like `envcloak_core::SecretBytes`: calls on it resolve to the
/// same trait method.
pub struct Wrapper(SecretBox<[u8; 4]>);

impl ExposeSecret<[u8; 4]> for Wrapper {
    fn expose_secret(&self) -> &[u8; 4] {
        self.0.expose_secret() // EXPECT-DISALLOWED
    }
}

pub fn through_wrapper(w: &Wrapper) -> u8 {
    w.expose_secret()[0] // EXPECT-DISALLOWED
}

pub fn by_reference(v: &[SecretBox<[u8; 4]>]) -> usize {
    v.iter().map(ExposeSecret::expose_secret).count() // EXPECT-DISALLOWED
}
