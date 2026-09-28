//! Crockford base32 for grant and request identifiers (SPEC §10b: a
//! grant's id is a ULID; a request id is 8 Crockford characters).
//!
//! Decoding accepts either case and Crockford's aliases (`I` and `L` read
//! as `1`, `O` as `0`), so an id read back from a screen or typed by hand
//! still parses. Encoding writes the canonical upper-case alphabet.

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The value of one Crockford symbol, or `None`.
fn symbol(b: u8) -> Option<u8> {
    let b = b.to_ascii_uppercase();
    match b {
        b'0' | b'O' => Some(0),
        b'1' | b'I' | b'L' => Some(1),
        _ => ALPHABET.iter().position(|a| *a == b).map(|p| p as u8),
    }
}

/// Encodes `bytes` as big-endian base32, `symbols` symbols long, the
/// leading bits zero-padded. Used for 16 bytes in 26 symbols (a ULID)
/// and 5 bytes in 8 symbols.
pub(crate) fn encode(bytes: &[u8], symbols: usize) -> String {
    let mut v: u128 = 0;
    for b in bytes {
        v = (v << 8) | u128::from(*b);
    }
    (0..symbols)
        .map(|i| {
            let shift = 5 * (symbols - 1 - i);
            char::from(ALPHABET[((v >> shift) & 0x1f) as usize])
        })
        .collect()
}

/// Decodes `text`, which must be exactly `symbols` symbols, into `out`
/// (big-endian). Bits above `out`'s size must be zero: a ULID's first
/// symbol is 0 to 7.
pub(crate) fn decode(text: &str, symbols: usize, out: &mut [u8]) -> Option<()> {
    let b = text.as_bytes();
    if b.len() != symbols || out.len() > 16 {
        return None;
    }
    let mut v: u128 = 0;
    for c in b {
        // A symbol that would shift bits off the top (a ULID's first
        // symbol above 7) is out of range.
        if v >> 123 != 0 {
            return None;
        }
        v = (v << 5) | u128::from(symbol(*c)?);
    }
    let bits = out.len() * 8;
    if bits < 128 && (v >> bits) != 0 {
        return None;
    }
    for (i, o) in out.iter_mut().rev().enumerate() {
        *o = ((v >> (8 * i)) & 0xff) as u8;
    }
    Some(())
}

/// `n` random bytes from the OS CSPRNG.
///
/// # Panics
/// When the OS random number generator fails. Nothing safe can be done
/// without it, and release builds abort on panic.
pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    if getrandom::fill(&mut b).is_err() {
        panic!("the OS random number generator failed");
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_aliases() {
        let bytes: [u8; 16] = [
            0x01, 0x8f, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
            0xab, 0xcd,
        ];
        let text = encode(&bytes, 26);
        assert_eq!(text.len(), 26);
        let mut back = [0u8; 16];
        decode(&text, 26, &mut back).unwrap();
        assert_eq!(back, bytes);
        decode(&text.to_lowercase(), 26, &mut back).unwrap();
        assert_eq!(back, bytes);
        // The top three bits of a 26-symbol ULID must be zero.
        assert!(decode(&format!("8{}", &text[1..]), 26, &mut back).is_none());
        assert!(decode(&text[..25], 26, &mut back).is_none());
        assert!(decode("U".repeat(26).as_str(), 26, &mut back).is_none());

        let five = [0xde, 0xad, 0xbe, 0xef, 0x42];
        let text = encode(&five, 8);
        let mut back = [0u8; 5];
        decode(&text, 8, &mut back).unwrap();
        assert_eq!(back, five);
        let mut a = [0u8; 5];
        let mut b = [0u8; 5];
        decode("0O1IL2ab", 8, &mut a).unwrap();
        decode("001112AB", 8, &mut b).unwrap();
        assert_eq!(a, b);
        assert_eq!(encode(&[0u8; 5], 8), "00000000");
    }
}
