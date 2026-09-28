//! A secret value inside a protocol message (SPEC §4.4).
//!
//! On the wire it is a JSON string of standard, padded base64. Encoding
//! writes the base64 into a buffer wiped on drop, from which the frame's
//! serializer copies it into the frame body. Decoding reads the base64
//! where it lies in the frame body and decodes it, a chunk at a time
//! through a wiped stack buffer, straight into a [`SecretBuf`] of the
//! decoded size. A string with JSON escapes cannot be read in place, so it
//! is refused: base64 never needs one.
//!
//! This file is on security/expose-allowlist.txt: it reads a value to
//! encode it.

use envcloak_core::{SecretBuf, SecretBytes};
use secrecy::ExposeSecret;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// Base64 symbols decoded per step: 1024 symbols, 768 bytes.
const CHUNK: usize = 1024;

/// A secret value in a request or response. It has no `Clone` or
/// `Display`, and its `Debug` prints `WireSecret(..)`.
pub struct WireSecret(SecretBytes);

impl WireSecret {
    pub fn new(value: SecretBytes) -> Self {
        WireSecret(value)
    }

    /// The value, for the code that receives it.
    pub fn into_inner(self) -> SecretBytes {
        self.0
    }

    pub fn as_secret(&self) -> &SecretBytes {
        &self.0
    }
}

impl From<SecretBytes> for WireSecret {
    fn from(value: SecretBytes) -> Self {
        WireSecret(value)
    }
}

impl core::fmt::Debug for WireSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WireSecret(..)")
    }
}

impl Serialize for WireSecret {
    #[allow(clippy::disallowed_methods)] // Encodes the value for a verified peer.
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let raw = self.0.expose_secret();
        let len = base64::encoded_len(raw.len(), true)
            .ok_or_else(|| serde::ser::Error::custom("a value too large to encode"))?;
        let mut text = Zeroizing::new(vec![0u8; len]);
        let written = STANDARD
            .encode_slice(raw, &mut text[..])
            .map_err(|_| serde::ser::Error::custom("a value could not be encoded"))?;
        let text = text
            .get(..written)
            .and_then(|t| core::str::from_utf8(t).ok())
            .ok_or_else(|| serde::ser::Error::custom("a value could not be encoded"))?;
        s.serialize_str(text)
    }
}

impl<'de> Deserialize<'de> for WireSecret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(SecretVisitor)
    }
}

struct SecretVisitor;

impl<'de> Visitor<'de> for SecretVisitor {
    type Value = WireSecret;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a base64 string without escapes")
    }

    fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<WireSecret, E> {
        decode(v.as_bytes()).map(WireSecret).ok_or_else(|| {
            // A fixed message; serde would otherwise quote the input.
            E::custom("a secret is not valid base64")
        })
    }

    /// A string the deserializer had to unescape into its own scratch
    /// buffer, or that it does not borrow from the input. Refused, so no
    /// copy of a value is made outside a wiped buffer.
    fn visit_str<E: de::Error>(self, _v: &str) -> Result<WireSecret, E> {
        Err(E::custom("a secret must be plain base64 without escapes"))
    }
}

/// Decodes standard padded base64 into an exact-size secret, or `None`.
fn decode(text: &[u8]) -> Option<SecretBytes> {
    if text.len() % 4 != 0 {
        return None;
    }
    let mut out = SecretBuf::with_capacity(base64::decoded_len_estimate(text.len()));
    let mut step = Zeroizing::new([0u8; CHUNK / 4 * 3]);
    for chunk in text.chunks(CHUNK) {
        let n = STANDARD.decode_slice(chunk, &mut step[..]).ok()?;
        out.extend(step.get(..n)?).ok()?;
    }
    Some(out.freeze())
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // Tests read values back.
mod tests {
    use super::*;

    static_assertions::assert_not_impl_any!(WireSecret: Clone, Copy, core::fmt::Display);

    fn round_trip(v: &[u8]) -> Vec<u8> {
        let json = serde_json::to_string(&WireSecret::new(SecretBytes::copy_from(v))).unwrap();
        let back: WireSecret = serde_json::from_str(&json).unwrap();
        back.into_inner().expose_secret().to_vec()
    }

    #[test]
    fn values_round_trip_through_base64() {
        let long: Vec<u8> = (0..5000u32).map(|i| (i * 7 % 256) as u8).collect();
        for v in [
            &b"a"[..],
            b"ab",
            b"abc",
            b"abcd",
            b"\x00\xff\x10",
            &long[..],
        ] {
            assert_eq!(round_trip(v), v);
        }
        let json = serde_json::to_string(&WireSecret::new(SecretBytes::copy_from(b"hi?"))).unwrap();
        assert_eq!(json, "\"aGk/\"");
    }

    #[test]
    fn malformed_or_escaped_base64_is_refused() {
        for bad in [
            "\"aGk\"",
            "\"aGk=x\"",
            "\"a!!=\"",
            "\"aGk\\/\"",
            "3",
            "null",
        ] {
            assert!(serde_json::from_str::<WireSecret>(bad).is_err(), "{bad}");
        }
        // Non-canonical trailing bits.
        assert!(serde_json::from_str::<WireSecret>("\"aGl=\"").is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let w = WireSecret::new(SecretBytes::copy_from(b"sensitive words"));
        assert_eq!(format!("{w:?}"), "WireSecret(..)");
    }
}
