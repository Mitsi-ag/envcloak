//! Payment card primary account number (PAN) detection: Luhn check and issuer
//! BIN ranges (`m4-plan.md` §5 rule 9, D4-11, M4-02).
//!
//! Shared by free-text value rejection (`looks_like_value`), the audit log
//! card masker, and `envcloak doctor`. [`Pan`] retains only the card brand,
//! digit count, and last four digits; full card numbers are never stored in
//! [`Pan`] or printed by its [`core::fmt::Debug`] implementation.

/// Recognised payment card network brands by IIN/BIN prefix and length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CardBrand {
    Visa,
    Mastercard,
    Amex,
    Discover,
    DinersClub,
    Jcb,
    UnionPay,
}

impl CardBrand {
    pub const fn as_str(self) -> &'static str {
        match self {
            CardBrand::Visa => "visa",
            CardBrand::Mastercard => "mastercard",
            CardBrand::Amex => "amex",
            CardBrand::Discover => "discover",
            CardBrand::DinersClub => "diners",
            CardBrand::Jcb => "jcb",
            CardBrand::UnionPay => "unionpay",
        }
    }
}

/// Summary of a detected PAN: brand, total digit length, and last four ASCII
/// digits. Never holds the full PAN.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pan {
    brand: CardBrand,
    last4: [u8; 4],
    len: u8,
}

impl Pan {
    pub const fn brand(&self) -> CardBrand {
        self.brand
    }

    pub const fn last4(&self) -> &[u8; 4] {
        &self.last4
    }

    pub fn last4_str(&self) -> &str {
        core::str::from_utf8(&self.last4).unwrap_or("????")
    }

    pub const fn len(&self) -> u8 {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::fmt::Debug for Pan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pan")
            .field("brand", &self.brand)
            .field("len", &self.len)
            .field("last4", &self.last4_str())
            .finish()
    }
}

/// Returns whether `digits` (each an ASCII digit `b'0'..=b'9'`) has a valid
/// Luhn check digit.
pub fn luhn_valid(digits: &[u8]) -> bool {
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    if !digits.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if digits.iter().all(|&b| b == b'0') {
        return false;
    }
    let mut sum: u32 = 0;
    let mut double = false;
    for &b in digits.iter().rev() {
        let mut d = u32::from(b - b'0');
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }
    sum.is_multiple_of(10)
}

fn prefix_u32(digits: &[u8], n: usize) -> Option<u32> {
    if digits.len() < n {
        return None;
    }
    let mut v = 0u32;
    for &b in &digits[..n] {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v * 10 + u32::from(b - b'0');
    }
    Some(v)
}

/// Matches `digits` (contiguous ASCII digits) against standard payment card
/// BIN ranges and lengths.
pub fn brand_for_digits(digits: &[u8]) -> Option<CardBrand> {
    let len = digits.len();
    if !(13..=19).contains(&len) {
        return None;
    }
    let p1 = prefix_u32(digits, 1)?;
    let p2 = prefix_u32(digits, 2)?;
    let p3 = prefix_u32(digits, 3)?;
    let p4 = prefix_u32(digits, 4)?;
    let p6 = prefix_u32(digits, 6)?;

    // Visa: prefix 4, length 13, 16, or 19.
    if p1 == 4 && matches!(len, 13 | 16 | 19) {
        return Some(CardBrand::Visa);
    }
    // Mastercard: 51..=55 or 2221..=2720, length 16.
    if len == 16 && ((51..=55).contains(&p2) || (2221..=2720).contains(&p4)) {
        return Some(CardBrand::Mastercard);
    }
    // American Express: 34 or 37, length 15.
    if len == 15 && (p2 == 34 || p2 == 37) {
        return Some(CardBrand::Amex);
    }
    // Discover: 6011, 644..=649, 65, or 622126..=622925, length 16..=19.
    if (16..=19).contains(&len)
        && (p4 == 6011
            || (644..=649).contains(&p3)
            || p2 == 65
            || (622_126..=622_925).contains(&p6))
    {
        return Some(CardBrand::Discover);
    }
    // JCB: 3528..=3589, length 16..=19.
    if (16..=19).contains(&len) && (3528..=3589).contains(&p4) {
        return Some(CardBrand::Jcb);
    }
    // Diners Club: 300..=305, 36, 38, 39, length 14..=19.
    if (14..=19).contains(&len) && ((300..=305).contains(&p3) || matches!(p2, 36 | 38 | 39)) {
        return Some(CardBrand::DinersClub);
    }
    // UnionPay: 62, length 16..=19.
    if (16..=19).contains(&len) && p2 == 62 {
        return Some(CardBrand::UnionPay);
    }
    None
}

/// Checks whether `input` (digits, optionally separated by single ASCII spaces
/// or hyphens between groups) is a Luhn-valid card number in a known BIN range.
pub fn luhn_bin(input: &[u8]) -> Option<Pan> {
    let trimmed = trim_ascii(input);
    if trimmed.is_empty() {
        return None;
    }
    let mut digits = [0u8; 19];
    let mut len = 0usize;
    let mut prev_sep = true; // forbid leading separator
    let mut sep_char: Option<u8> = None;

    for &b in trimmed {
        if b.is_ascii_digit() {
            if len >= digits.len() {
                return None;
            }
            digits[len] = b;
            len += 1;
            prev_sep = false;
        } else if b == b' ' || b == b'-' {
            if prev_sep {
                return None;
            }
            match sep_char {
                None => sep_char = Some(b),
                Some(c) if c == b => {}
                Some(_) => return None,
            }
            prev_sep = true;
        } else {
            return None;
        }
    }
    if prev_sep {
        return None;
    }
    let slice = &digits[..len];
    let brand = brand_for_digits(slice)?;
    if !luhn_valid(slice) {
        return None;
    }
    let last4 = [
        slice[len - 4],
        slice[len - 3],
        slice[len - 2],
        slice[len - 1],
    ];
    let result = Pan {
        brand,
        last4,
        len: len as u8,
    };
    digits.fill(0);
    Some(result)
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    &b[start..end]
}

/// Scans `text` for any token sequence that forms a Luhn-valid, BIN-matched
/// PAN, bounded by non-alphanumeric characters (so longer digit strings or
/// identifiers containing digits are not split into false matches).
pub fn find_pan_in_text(text: &str) -> Option<Pan> {
    let bytes = text.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    while i < n {
        if bytes[i].is_ascii_digit() {
            let preceded_by_alnum = i > 0
                && (bytes[i - 1].is_ascii_alphanumeric()
                    || bytes[i - 1] == b'_'
                    || bytes[i - 1] == b'/');
            if !preceded_by_alnum {
                if let Some((pan, end)) = scan_candidate(bytes, i) {
                    let followed_by_alnum = end < n
                        && (bytes[end].is_ascii_alphanumeric()
                            || bytes[end] == b'_'
                            || bytes[end] == b'/');
                    if !followed_by_alnum {
                        return Some(pan);
                    }
                }
            }
            while i < n && bytes[i].is_ascii_digit() {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    None
}

fn scan_candidate(bytes: &[u8], start: usize) -> Option<(Pan, usize)> {
    let n = bytes.len();
    let mut i = start;
    let mut digits = 0usize;
    let mut last_digit_end = start;
    let mut sep_char: Option<u8> = None;

    while i < n {
        let b = bytes[i];
        if b.is_ascii_digit() {
            digits += 1;
            i += 1;
            last_digit_end = i;
            if digits > 19 {
                return None;
            }
        } else if (b == b' ' || b == b'-')
            && i > start
            && i + 1 < n
            && bytes[i + 1].is_ascii_digit()
        {
            match sep_char {
                None => sep_char = Some(b),
                Some(c) if c == b => {}
                Some(_) => break,
            }
            i += 1;
        } else {
            break;
        }
    }

    if (13..=19).contains(&digits) {
        if let Some(pan) = luhn_bin(&bytes[start..last_digit_end]) {
            return Some((pan, last_digit_end));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_standard_luhn_valid_test_cards() {
        // Visa 16-digit test number (4111 1111 1111 1111)
        let visa = luhn_bin(b"4111111111111111").expect("valid Visa test PAN");
        assert_eq!(visa.brand(), CardBrand::Visa);
        assert_eq!(visa.len(), 16);
        assert_eq!(visa.last4_str(), "1111");

        // Spaced and hyphenated Visa
        let spaced = luhn_bin(b"4111 1111 1111 1111").expect("spaced Visa");
        assert_eq!(spaced, visa);
        let dashed = luhn_bin(b"4111-1111-1111-1111").expect("dashed Visa");
        assert_eq!(dashed, visa);

        // Mastercard (5555 5555 5555 4444)
        let mc = luhn_bin(b"5555555555554444").expect("valid Mastercard test PAN");
        assert_eq!(mc.brand(), CardBrand::Mastercard);
        assert_eq!(mc.len(), 16);
        assert_eq!(mc.last4_str(), "4444");

        // Amex 15-digit (3782 822463 10005)
        let amex = luhn_bin(b"378282246310005").expect("valid Amex test PAN");
        assert_eq!(amex.brand(), CardBrand::Amex);
        assert_eq!(amex.len(), 15);
        assert_eq!(amex.last4_str(), "0005");
    }

    #[test]
    fn rejects_order_ids_and_luhn_invalid_numbers() {
        // 16-digit order id outside BIN ranges (starts with 1)
        assert_eq!(luhn_bin(b"1000000000000008"), None);
        // 16-digit order id starting with 9
        assert_eq!(luhn_bin(b"9123456789012345"), None);
        // Luhn-invalid Visa prefix
        assert_eq!(luhn_bin(b"4111111111111112"), None);
        // Wrong length for Mastercard (15 digits)
        assert_eq!(luhn_bin(b"555555555555444"), None);
        // Mixed separators rejected
        assert_eq!(luhn_bin(b"4111-1111 1111-1111"), None);
        // Double separator rejected
        assert_eq!(luhn_bin(b"4111--1111-1111-1111"), None);
    }

    #[test]
    fn find_pan_in_free_text_and_debug_hides_prefix() {
        let pan =
            find_pan_in_text("backup card 4111 1111 1111 1111 for api").expect("PAN in free text");
        assert_eq!(pan.brand(), CardBrand::Visa);
        assert_eq!(pan.last4_str(), "1111");
        let dbg = format!("{pan:?}");
        assert!(!dbg.contains("41111111"));
        assert!(dbg.contains("1111"));

        // Order IDs and long hex/numeric strings do not trigger false positives
        assert_eq!(find_pan_in_text("order #1234567890123452"), None);
        assert_eq!(find_pan_in_text("id=41111111111111110000"), None);
    }
}
