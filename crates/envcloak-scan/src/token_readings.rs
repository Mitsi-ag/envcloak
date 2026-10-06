//! Bounded alternative ranges, not a comparison or eligibility oracle.
//! The daemon applies the password-form rules before any vault comparison.
use crate::candidates::Form;
use std::collections::HashSet;
use std::ops::Range;

const MAX_READINGS: usize = 256;
#[derive(Default)]
struct Padding {
    end: usize,
    #[cfg(test)]
    inspected: usize,
}
impl Padding {
    fn at(&mut self, bytes: &[u8], at: usize) -> bool {
        if at >= self.end {
            self.end = at;
            while self.end < bytes.len() && bytes[self.end] == b'=' {
                #[cfg(test)]
                {
                    self.inspected += 1;
                }
                self.end += 1;
            }
        }
        bytes.get(self.end).is_none_or(|b| {
            b.is_ascii_whitespace()
                || matches!(
                    b,
                    b'.' | b'`' | b')' | b']' | b'}' | b'"' | b'\'' | b',' | b';'
                )
        })
    }
}

struct Readings {
    ranges: Vec<(Range<usize>, Form)>,
    seen: HashSet<(usize, usize, Form)>,
    limited: bool,
}
impl Readings {
    fn push(&mut self, start: usize, end: usize, form: Form) {
        if end.saturating_sub(start) < 16 || self.seen.contains(&(start, end, form)) {
            return;
        }
        if self.ranges.len() == MAX_READINGS {
            self.limited = true;
            return;
        }
        self.seen.insert((start, end, form));
        self.ranges.push((start..end, form));
    }
    fn raw(&mut self, bytes: &[u8], start: usize, end: usize) {
        self.push(start, end, Form::Raw);
        let mut a = start;
        let mut b = end;
        while a < b && bytes[a].is_ascii_punctuation() {
            a += 1;
        }
        while b > a && bytes[b - 1].is_ascii_punctuation() && bytes[b - 1] != b'=' {
            b -= 1;
        }
        self.push(a, b, Form::Raw);
    }
}
pub(crate) fn ranges(bytes: &[u8]) -> (Vec<(Range<usize>, Form)>, bool) {
    let mut out = Readings {
        ranges: Vec::new(),
        seen: HashSet::new(),
        limited: false,
    };
    out.raw(bytes, 0, bytes.len());
    let mut word = 0;
    for end in 0..=bytes.len() {
        if end == bytes.len() || bytes[end].is_ascii_whitespace() || bytes[end] < 32 {
            out.raw(bytes, word, end);
            // A JSON string or decoded run may contain several shell words.
            // Keep each assignment RHS intact before punctuation alternatives.
            if let Some(eq) = bytes[word..end].iter().position(|b| *b == b'=') {
                out.raw(bytes, word + eq + 1, end);
            }
            word = end + 1;
        }
    }
    // Keep the full RHS, including internal punctuation and base64 padding.
    // Never recursively emit every suffix of a chain of assignments.
    if let Some(eq) = bytes.iter().position(|b| *b == b'=') {
        out.raw(bytes, eq + 1, bytes.len());
    }
    let mut start = 0;
    let mut padding = Padding::default();
    for end in 0..=bytes.len() {
        if end == bytes.len()
            || bytes[end].is_ascii_whitespace()
            || (bytes[end].is_ascii_punctuation()
                && !(bytes[end] == b'=' && padding.at(bytes, end)))
        {
            out.push(start, end, Form::Raw);
            start = end + 1;
        }
    }
    // Query and connection fields retain punctuation inside each value.
    let mut start = 0;
    for end in 0..=bytes.len() {
        if end == bytes.len()
            || bytes[end].is_ascii_whitespace()
            || bytes[end] < 32
            || matches!(bytes[end], b'?' | b'&' | b';' | b'#')
        {
            if let Some(eq) = bytes[start..end].iter().position(|b| *b == b'=') {
                out.raw(bytes, start + eq + 1, end);
            }
            start = end + 1;
        }
    }
    // URL user information. The authority ends before path, query or fragment.
    for scheme in 0..bytes.len().saturating_sub(2) {
        if &bytes[scheme..scheme + 3] != b"://" {
            continue;
        }
        let a = scheme + 3;
        let end = bytes[a..]
            .iter()
            .position(|b| matches!(b, b'/' | b'?' | b'#') || b.is_ascii_whitespace())
            .map_or(bytes.len(), |n| a + n);
        if let Some(at) = bytes[a..end].iter().rposition(|b| *b == b'@') {
            let at = a + at;
            if let Some(colon) = bytes[a..at].iter().position(|b| *b == b':') {
                out.push(a + colon + 1, at, Form::UrlPassword);
            }
        }
        if out.limited {
            break;
        }
    }
    // Go MySQL DSN: protocol/address parentheses, or its default-address slash.
    if let Some(colon) = bytes.iter().position(|b| *b == b':') {
        let url = bytes[colon..].starts_with(b"://");
        for at in colon + 1..bytes.len() {
            if bytes[at] != b'@' {
                continue;
            }
            let rest = &bytes[at + 1..];
            let n = rest
                .iter()
                .position(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'_' | b'-'))
                .unwrap_or(rest.len());
            if rest.get(n) == Some(&b'(') || (!url && rest.get(n) == Some(&b'/')) {
                out.push(colon + 1, at, Form::DsnPassword);
            }
            if out.limited {
                break;
            }
        }
    }
    // Ambiguous, unclosed fields can overlap. Bound total lookahead work as
    // well as retained readings; reaching either limit is visibly incomplete.
    let mut password_work = 0;
    'passwords: for at in 0..bytes.len() {
        if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_') {
            continue;
        }
        for key in [b"password".as_slice(), b"passwd", b"pwd"] {
            if !bytes
                .get(at..at + key.len())
                .is_some_and(|b| b.eq_ignore_ascii_case(key))
            {
                continue;
            }
            let mut a = at + key.len();
            while bytes.get(a).is_some_and(u8::is_ascii_whitespace) {
                a += 1;
            }
            if bytes.get(a) != Some(&b'=') {
                continue;
            }
            a += 1;
            while bytes.get(a).is_some_and(u8::is_ascii_whitespace) {
                a += 1;
            }
            let closing = match bytes.get(a) {
                Some(b'\'') => Some(b'\''),
                Some(b'"') => Some(b'"'),
                Some(b'{') => Some(b'}'),
                _ => None,
            };
            if closing.is_some() {
                a += 1;
            }
            let mut end = a;
            while end < bytes.len() {
                password_work += 1;
                if password_work > bytes.len().saturating_mul(8) {
                    out.limited = true;
                    break 'passwords;
                }
                if bytes[end] == b'\\' && end + 1 < bytes.len() {
                    end += 2;
                    continue;
                }
                if closing == Some(bytes[end]) {
                    break;
                }
                if closing.is_none()
                    && (bytes[end].is_ascii_whitespace() || matches!(bytes[end], b';' | b'&'))
                {
                    break;
                }
                end += 1;
            }
            out.push(a, end, Form::ConnPassword);
        }
        if out.limited {
            break;
        }
    }
    // A password substring must not also reach the daemon as a less specific
    // raw reading. Keep the full contextual token and the typed substrings.
    let passwords: Vec<_> = out
        .ranges
        .iter()
        .filter(|(_, f)| *f != Form::Raw)
        .cloned()
        .collect();
    let mut seen = HashSet::new();
    out.ranges.retain_mut(|(range, form)| {
        if *form == Form::Raw && (range.start != 0 || range.end != bytes.len()) {
            for (password, kind) in &passwords {
                if range.start >= password.start && range.end <= password.end {
                    *form = *kind;
                    break;
                }
                if range.start <= password.start && range.end >= password.end {
                    return false;
                }
            }
        }
        seen.insert((range.start, range.end, *form))
    });
    (out.ranges, out.limited)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_lookahead_visits_each_byte_once() {
        for suffix in [b"".as_slice(), b" ", b"x", b";"] {
            let mut input = vec![b'='; crate::transcript::MAX_CANDIDATE - 1];
            input.extend_from_slice(suffix);
            let mut padding = Padding::default();
            for at in 0..crate::transcript::MAX_CANDIDATE - 1 {
                assert_eq!(padding.at(&input, at), suffix != b"x");
            }
            assert!(
                padding.inspected <= input.len(),
                "repeated suffix inspections"
            );
        }
    }
}
