//! Secret value types (SPEC §5 "Memory hygiene").
//!
//! - [`SecretBytes`]: an immutable, exact-size boxed slice wrapped by
//!   `secrecy`, wiped on drop. It has no `Clone`, `Display` or `Serialize`,
//!   and its `Debug` prints `SecretBytes(..)`.
//! - [`SecretBuf`]: a fixed-capacity buffer for building a secret (a
//!   passphrase read from a terminal, a value decoded from a frame). It never
//!   reallocates in place: [`SecretBuf::extend`] refuses to exceed the
//!   capacity, and [`SecretBuf::grow`] copies into a new buffer and wipes
//!   the old one.
//!
//! Reading a value goes through [`secrecy::ExposeSecret::expose_secret`],
//! which clippy's `disallowed-methods` forbids outside the files listed in
//! `security/expose-allowlist.txt`.

use secrecy::{ExposeSecret, SecretBox};
use zeroize::{Zeroize, Zeroizing};

/// An immutable secret value.
pub struct SecretBytes(SecretBox<[u8]>);

impl SecretBytes {
    /// Takes ownership of `v`. When `v` has spare capacity, the bytes move to
    /// an exact-size allocation and `v`'s whole buffer is wiped, so no
    /// reallocation ever frees an unwiped copy.
    pub fn from_vec(mut v: Vec<u8>) -> Self {
        if v.len() == v.capacity() {
            // No spare capacity: `into_boxed_slice` keeps the allocation.
            return SecretBytes(SecretBox::new(v.into_boxed_slice()));
        }
        let exact = Self::copy_from(&v);
        v.zeroize();
        exact
    }

    /// Copies `b` into a new exact-size allocation.
    pub fn copy_from(b: &[u8]) -> Self {
        // `vec![0; n]` allocates exactly `n` bytes, so `into_boxed_slice`
        // does not reallocate.
        let mut boxed = vec![0u8; b.len()].into_boxed_slice();
        boxed.copy_from_slice(b);
        SecretBytes(SecretBox::new(boxed))
    }

    /// Length in bytes. Not secret.
    #[allow(clippy::disallowed_methods)] // Reads the length only.
    pub fn len(&self) -> usize {
        self.0.expose_secret().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the value equals `other`, compared in constant time for
    /// equal lengths. Lengths are not secret.
    #[allow(clippy::disallowed_methods)] // Compares without revealing.
    pub fn ct_eq(&self, other: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        bool::from(self.0.expose_secret().ct_eq(other))
    }
}

#[allow(clippy::disallowed_methods)] // The one place SecretBytes is opened.
impl ExposeSecret<[u8]> for SecretBytes {
    fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretBytes(..)")
    }
}

/// [`SecretBuf::extend`] would exceed the buffer's capacity. Carries sizes
/// only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityExceeded {
    pub capacity: usize,
    pub needed: usize,
}

impl core::fmt::Display for CapacityExceeded {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "secret buffer capacity exceeded ({} bytes needed, {} available)",
            self.needed, self.capacity
        )
    }
}

impl std::error::Error for CapacityExceeded {}

/// A fixed-capacity buffer for building a secret. Wiped on drop, including
/// its spare capacity.
pub struct SecretBuf {
    buf: Zeroizing<Vec<u8>>,
}

impl SecretBuf {
    /// A buffer that holds at least `cap` bytes without reallocating.
    pub fn with_capacity(cap: usize) -> Self {
        SecretBuf {
            buf: Zeroizing::new(Vec::with_capacity(cap)),
        }
    }

    /// Appends `b`, or leaves the buffer untouched and fails when it does not
    /// fit. Never reallocates.
    pub fn extend(&mut self, b: &[u8]) -> Result<(), CapacityExceeded> {
        let needed = self.buf.len().saturating_add(b.len());
        if needed > self.buf.capacity() {
            return Err(CapacityExceeded {
                capacity: self.buf.capacity(),
                needed,
            });
        }
        self.buf.extend_from_slice(b);
        Ok(())
    }

    /// Raises the capacity to at least `new_cap`: allocates a new buffer,
    /// copies, and wipes the old one. Does nothing when the capacity is
    /// already large enough.
    pub fn grow(&mut self, new_cap: usize) {
        if new_cap <= self.buf.capacity() {
            return;
        }
        let mut next = Zeroizing::new(Vec::with_capacity(new_cap));
        next.extend_from_slice(&self.buf);
        // The old buffer is wiped, spare capacity included, when it drops.
        self.buf = next;
    }

    /// Wipes the bytes beyond `len` and shortens the buffer. Does nothing
    /// when `len` is not shorter.
    pub fn truncate(&mut self, len: usize) {
        if len < self.buf.len() {
            self.buf[len..].zeroize();
            self.buf.truncate(len);
        }
    }

    /// Wipes the contents and empties the buffer. The capacity stays.
    pub fn clear(&mut self) {
        self.truncate(0);
    }

    /// Length in bytes. Not secret.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// Converts into an exact-size [`SecretBytes`], wiping this buffer when
    /// its bytes have to move.
    pub fn freeze(mut self) -> SecretBytes {
        // Leaves an empty Vec (no allocation) behind for `Zeroizing` to drop.
        SecretBytes::from_vec(core::mem::take(&mut *self.buf))
    }
}

#[allow(clippy::disallowed_methods)] // Read access to a buffer being built.
impl ExposeSecret<[u8]> for SecretBuf {
    fn expose_secret(&self) -> &[u8] {
        &self.buf
    }
}

impl core::fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretBuf(..)")
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // Tests read values back.
mod tests {
    use super::*;

    static_assertions::assert_not_impl_any!(
        SecretBytes: Clone,
        Copy,
        core::fmt::Display,
        serde::Serialize
    );
    static_assertions::assert_not_impl_any!(
        SecretBuf: Clone,
        Copy,
        core::fmt::Display,
        serde::Serialize
    );

    fn sample() -> Vec<u8> {
        (0..40u8).map(|i| b'a' + i % 26).collect()
    }

    #[test]
    fn debug_output_is_redacted() {
        let s = SecretBytes::copy_from(&sample());
        assert_eq!(format!("{s:?}"), "SecretBytes(..)");
        assert_eq!(format!("{s:#?}"), "SecretBytes(..)");
        let mut b = SecretBuf::with_capacity(64);
        b.extend(&sample()).unwrap();
        assert_eq!(format!("{b:?}"), "SecretBuf(..)");
        let e = b.extend(&[0; 64]).unwrap_err();
        assert!(!format!("{e} {e:?}").contains("abc"));
    }

    #[test]
    fn from_vec_and_copy_from_keep_the_bytes() {
        let v = sample();
        assert_eq!(SecretBytes::copy_from(&v).expose_secret(), &v[..]);
        let mut spare = Vec::with_capacity(100);
        spare.extend_from_slice(&v);
        let s = SecretBytes::from_vec(spare);
        assert_eq!(s.expose_secret(), &v[..]);
        assert_eq!(s.len(), v.len());
        assert!(!s.is_empty());
        assert!(SecretBytes::from_vec(Vec::new()).is_empty());
    }

    #[test]
    fn ct_eq_compares_whole_values() {
        let s = SecretBytes::copy_from(b"value");
        assert!(s.ct_eq(b"value"));
        assert!(!s.ct_eq(b"valuf"));
        assert!(!s.ct_eq(b"valu"));
        assert!(!s.ct_eq(b"values"));
        assert!(SecretBytes::copy_from(b"").ct_eq(b""));
    }

    #[test]
    fn extend_never_reallocates() {
        let mut b = SecretBuf::with_capacity(8);
        let cap = b.capacity();
        let before = b.expose_secret().as_ptr();
        b.extend(b"12345").unwrap();
        let err = b.extend(&vec![b'x'; cap]).unwrap_err();
        assert_eq!(err.capacity, cap);
        assert_eq!(err.needed, 5 + cap);
        // A failed extend leaves the contents alone.
        assert_eq!(b.expose_secret(), b"12345");
        b.extend(&vec![b'y'; cap - 5]).unwrap();
        assert_eq!(b.len(), cap);
        assert_eq!(b.capacity(), cap);
        assert_eq!(b.expose_secret().as_ptr(), before);
    }

    #[test]
    fn grow_copies_into_a_larger_buffer() {
        let mut b = SecretBuf::with_capacity(4);
        b.extend(b"abcd").unwrap();
        b.grow(2);
        assert!(b.capacity() >= 4);
        b.grow(32);
        assert!(b.capacity() >= 32);
        b.extend(b"efgh").unwrap();
        assert_eq!(b.expose_secret(), b"abcdefgh");
    }

    #[test]
    fn truncate_and_clear() {
        let mut b = SecretBuf::with_capacity(16);
        b.extend(b"passphrase\n").unwrap();
        b.truncate(10);
        assert_eq!(b.expose_secret(), b"passphrase");
        b.truncate(50);
        assert_eq!(b.len(), 10);
        b.clear();
        assert!(b.is_empty());
        assert!(b.capacity() >= 16);
    }

    #[test]
    fn freeze_gives_exact_bytes() {
        let mut b = SecretBuf::with_capacity(64);
        b.extend(&sample()).unwrap();
        let s = b.freeze();
        assert_eq!(s.expose_secret(), &sample()[..]);
        let mut full = SecretBuf::with_capacity(3);
        let cap = full.capacity();
        full.extend(&vec![7; cap]).unwrap();
        assert_eq!(full.freeze().expose_secret(), &vec![7; cap][..]);
    }
}
