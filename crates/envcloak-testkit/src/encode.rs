//! Encoders for canary detection, written independently of
//! `envcloak-redact` (tests cross-check them against real libraries).

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// RFC 4648 base64 (`url` picks the URL-safe alphabet).
pub(crate) fn base64(data: &[u8], url: bool, pad: bool) -> Vec<u8> {
    let table = if url { B64_URL } else { B64_STD };
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        let chars = [
            table[(n >> 18) as usize & 63],
            table[(n >> 12) as usize & 63],
            table[(n >> 6) as usize & 63],
            table[n as usize & 63],
        ];
        let keep = chunk.len() + 1;
        out.extend_from_slice(&chars[..keep]);
        if pad {
            out.extend(std::iter::repeat_n(b'=', 4 - keep));
        }
    }
    out
}

/// The base64 characters that encode `data` when it sits at byte offset
/// `offset` (mod 3) of a longer stream: only the 3-byte groups wholly inside
/// `data`. `None` when fewer than two whole groups remain.
pub(crate) fn base64_embedded(data: &[u8], offset: usize, url: bool) -> Option<Vec<u8>> {
    let skip = (3 - offset % 3) % 3;
    let body = data.get(skip..)?;
    let whole = body.len() / 3 * 3;
    (whole >= 6).then(|| base64(&body[..whole], url, false))
}

pub(crate) fn hex(data: &[u8], upper: bool) -> Vec<u8> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    data.iter()
        .flat_map(|b| [digits[usize::from(b >> 4)], digits[usize::from(b & 15)]])
        .collect()
}

/// One percent-encoding convention: which ASCII bytes stay literal besides
/// letters and digits, and whether a space becomes `+`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PercentStyle {
    pub name_upper: &'static str,
    pub name_lower: &'static str,
    pub keep: &'static [u8],
    pub space_plus: bool,
}

pub(crate) const PERCENT_STYLES: [PercentStyle; 5] = [
    // RFC 3986 unreserved; Python `quote(safe="")`.
    PercentStyle {
        name_upper: "percent-rfc3986-upper",
        name_lower: "percent-rfc3986-lower",
        keep: b"-._~",
        space_plus: false,
    },
    // Python `urllib.parse.quote` with its default `safe="/"`.
    PercentStyle {
        name_upper: "percent-quote-upper",
        name_lower: "percent-quote-lower",
        keep: b"-._~/",
        space_plus: false,
    },
    // Python `urllib.parse.quote_plus`.
    PercentStyle {
        name_upper: "percent-quote-plus-upper",
        name_lower: "percent-quote-plus-lower",
        keep: b"-._~",
        space_plus: true,
    },
    // WHATWG application/x-www-form-urlencoded.
    PercentStyle {
        name_upper: "form-urlencoded-upper",
        name_lower: "form-urlencoded-lower",
        keep: b"*-._",
        space_plus: true,
    },
    // JavaScript `encodeURIComponent`.
    PercentStyle {
        name_upper: "percent-uri-component-upper",
        name_lower: "percent-uri-component-lower",
        keep: b"-_.!~*'()",
        space_plus: false,
    },
];

pub(crate) fn percent(data: &[u8], style: &PercentStyle, upper: bool) -> Vec<u8> {
    let digits: &[u8; 16] = if upper {
        b"0123456789ABCDEF"
    } else {
        b"0123456789abcdef"
    };
    let mut out = Vec::with_capacity(data.len() * 3);
    for &b in data {
        if b.is_ascii_alphanumeric() || style.keep.contains(&b) {
            out.push(b);
        } else if b == b' ' && style.space_plus {
            out.push(b'+');
        } else {
            out.extend_from_slice(&[
                b'%',
                digits[usize::from(b >> 4)],
                digits[usize::from(b & 15)],
            ]);
        }
    }
    out
}

/// How a `\u` escape spells its hex digits, or no escape at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Esc {
    Raw,
    Lower,
    Upper,
}

/// One JSON string-escaping convention.
///
/// - Python `json.dumps` (`ensure_ascii` true): non-ASCII lower.
/// - Python (`ensure_ascii` false), Node, serde_json: all raw.
/// - Go `encoding/json`: `<>&` escaped with lower hex.
/// - .NET `System.Text.Json`: quote as `\u0022`, non-ASCII upper, and
///   `<>&'+` and the backtick escaped with upper hex.
/// - PHP `json_encode`: `\/`, non-ASCII lower.
#[derive(Debug, Clone, Copy)]
pub(crate) struct JsonStyle {
    /// `"` as `\u0022` instead of `\"`.
    pub quote_u: bool,
    /// `/` as `\/`.
    pub slash: bool,
    pub non_ascii: Esc,
    /// `<`, `>` and `&` (Go's HTML-safe set).
    pub html: Esc,
    /// `'`, `+` and the backtick (the rest of .NET's default set).
    pub extra: Esc,
}

/// Every combination of the options above, each with a stable name.
pub(crate) fn json_styles() -> &'static [(JsonStyle, &'static str)] {
    static STYLES: std::sync::OnceLock<Vec<(JsonStyle, &'static str)>> = std::sync::OnceLock::new();
    STYLES.get_or_init(|| {
        let escs = [Esc::Raw, Esc::Lower, Esc::Upper];
        let mut v = Vec::new();
        for quote_u in [false, true] {
            for slash in [false, true] {
                for non_ascii in escs {
                    for html in escs {
                        for extra in escs {
                            let style = JsonStyle {
                                quote_u,
                                slash,
                                non_ascii,
                                html,
                                extra,
                            };
                            let name = format!(
                                "json/quote-{}/slash-{}/non-ascii-{}/html-{}/extra-{}",
                                if quote_u { "u" } else { "esc" },
                                if slash { "esc" } else { "raw" },
                                esc_name(non_ascii),
                                esc_name(html),
                                esc_name(extra),
                            );
                            v.push((style, &*Box::leak(name.into_boxed_str())));
                        }
                    }
                }
            }
        }
        v
    })
}

fn esc_name(e: Esc) -> &'static str {
    match e {
        Esc::Raw => "raw",
        Esc::Lower => "lower",
        Esc::Upper => "upper",
    }
}

fn push_u(out: &mut String, unit: u16, case: Esc) {
    if case == Esc::Upper {
        out.push_str(&format!("\\u{unit:04X}"));
    } else {
        out.push_str(&format!("\\u{unit:04x}"));
    }
}

/// The body of a JSON string literal for `text` (no surrounding quotes).
pub(crate) fn json(text: &str, style: &JsonStyle) -> String {
    let mut out = String::with_capacity(text.len() * 2);
    for ch in text.chars() {
        match ch {
            '"' if style.quote_u => out.push_str("\\u0022"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '/' if style.slash => out.push_str("\\/"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if u32::from(c) < 0x20 => push_u(&mut out, c as u16, Esc::Lower),
            '<' | '>' | '&' if style.html != Esc::Raw => push_u(&mut out, c_u16(ch), style.html),
            '\'' | '+' | '`' if style.extra != Esc::Raw => push_u(&mut out, c_u16(ch), style.extra),
            c if !c.is_ascii() && style.non_ascii != Esc::Raw => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    push_u(&mut out, *unit, style.non_ascii);
                }
            }
            c => out.push(c),
        }
    }
    out
}

fn c_u16(c: char) -> u16 {
    // Only called for ASCII characters.
    c as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        let vectors: [(&str, &str); 7] = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, enc) in vectors {
            assert_eq!(base64(plain.as_bytes(), false, true), enc.as_bytes());
            assert_eq!(
                base64(plain.as_bytes(), false, false),
                enc.trim_end_matches('=').as_bytes()
            );
        }
        assert_eq!(base64(&[0xfb, 0xff], false, true), b"+/8=");
        assert_eq!(base64(&[0xfb, 0xff], true, true), b"-_8=");
    }

    #[test]
    fn hex_and_percent_cases() {
        assert_eq!(hex(&[0xab, 0x01], false), b"ab01");
        assert_eq!(hex(&[0xab, 0x01], true), b"AB01");
        let quote_plus = &PERCENT_STYLES[2];
        assert_eq!(percent(b"a b/\xc3\xa9", quote_plus, true), b"a+b%2F%C3%A9");
        assert_eq!(percent(b"a b/\xc3\xa9", quote_plus, false), b"a+b%2f%c3%a9");
        let quote = &PERCENT_STYLES[1];
        assert_eq!(percent(b"a b/~", quote, true), b"a%20b/~");
    }

    #[test]
    fn json_escapes_by_style() {
        let text = "a\"b/c\u{e9}<+\u{1f511}";
        let find = |q, s, n, h, x| {
            json_styles()
                .iter()
                .find(|(st, _)| {
                    st.quote_u == q
                        && st.slash == s
                        && st.non_ascii == n
                        && st.html == h
                        && st.extra == x
                })
                .map(|(st, _)| json(text, st))
                .unwrap_or_default()
        };
        assert_eq!(
            find(false, false, Esc::Raw, Esc::Raw, Esc::Raw),
            "a\\\"b/c\u{e9}<+\u{1f511}"
        );
        assert_eq!(
            find(false, true, Esc::Lower, Esc::Raw, Esc::Raw),
            "a\\\"b\\/c\\u00e9<+\\ud83d\\udd11"
        );
        assert_eq!(
            find(true, false, Esc::Upper, Esc::Upper, Esc::Upper),
            "a\\u0022b/c\\u00E9\\u003C\\u002B\\uD83D\\uDD11"
        );
        assert_eq!(json_styles().len(), 108);
    }
}
