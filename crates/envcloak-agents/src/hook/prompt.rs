//! Whether a prompt holds something shaped like a key or token (M2 plan
//! M2-08, D-12; SPEC §7 `UserPromptSubmit`): read in place, locally and
//! deterministically, never compared with the vault (that would confirm
//! guesses, lesson L-07) and never sent anywhere. Only a yes or no leaves.
//!
//! A prompt holds a key when, as written or with the pasted-text markers
//! some hosts put around each paste taken out (so a key pasted in two
//! parts is read whole), it has:
//! - a word a provider's key pattern in the registry matches
//!   (`envcloak_providers::Registry::mask_keys`, through the client);
//! - a URL with a password (`scheme://user:password@host`); or
//! - a run of at least [`RUN`] ASCII letters and digits that holds both
//!   letters and digits, as generated keys and tokens do, except one of
//!   exactly 40 or 64 hexadecimal digits in one case, the shape of a git
//!   object id or a SHA-256 digest, which prompts name all the time.
//!
//! What this does not catch is in docs/INSTALLERS.md ("What the hook does
//! not see"): a key made of words and separators that no provider
//! pattern names (an AWS secret access key on its own), a key of 40 or 64
//! hexadecimal digits, and a key encoded or split by other text.

/// The shortest run of letters and digits taken for a generated key.
pub const RUN: usize = 24;

/// Whether `prompt` holds something shaped like a key or token.
pub fn holds_key(prompt: &str) -> bool {
    shaped(prompt) || {
        let joined = without_paste_markers(prompt);
        joined != prompt && shaped(&joined)
    }
}

fn shaped(text: &str) -> bool {
    has_key_run(text.as_bytes())
        || has_url_password(text.as_bytes())
        || envcloak_client::render::registry().is_some_and(|r| r.mask_keys(text) != text)
}

/// `text` with the lines that open and close a paste
/// (`<pasted_content id="...">`, `</pasted_content id="...">`) taken out,
/// and what was on either side of one joined without a line break.
pub fn without_paste_markers(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut join = true;
    let mut first = true;
    for line in text.split('\n') {
        if is_paste_marker(line.trim_end_matches('\r')) {
            join = true;
            continue;
        }
        if !first && !join {
            out.push('\n');
        }
        out.push_str(line);
        first = false;
        join = false;
    }
    out
}

fn is_paste_marker(line: &str) -> bool {
    let rest = line
        .strip_prefix("</pasted_content")
        .or_else(|| line.strip_prefix("<pasted_content"));
    rest.is_some_and(|r| {
        r.strip_prefix(" id=\"")
            .and_then(|r| r.strip_suffix("\">"))
            .is_some_and(|id| !id.contains('"'))
    })
}

/// A run of [`RUN`] or more letters and digits holding both, that is not
/// a git object id or a digest.
fn has_key_run(b: &[u8]) -> bool {
    let mut i = 0;
    while i < b.len() {
        if !b[i].is_ascii_alphanumeric() {
            i += 1;
            continue;
        }
        let start = i;
        while i < b.len() && b[i].is_ascii_alphanumeric() {
            i += 1;
        }
        let run = &b[start..i];
        if run.len() < RUN {
            continue;
        }
        let digits = run.iter().any(u8::is_ascii_digit);
        let letters = run.iter().any(u8::is_ascii_alphabetic);
        if !(digits && letters) {
            continue;
        }
        let hex_id = matches!(run.len(), 40 | 64)
            && (run
                .iter()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
                || run
                    .iter()
                    .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(c)));
        if !hex_id {
            return true;
        }
    }
    false
}

/// A URL with a non-empty password in its user information.
fn has_url_password(b: &[u8]) -> bool {
    let mut from = 0;
    while let Some(p) = b[from..].windows(3).position(|w| w == b"://") {
        let at = from + p + 3;
        from = at;
        let end = b[at..]
            .iter()
            .position(|c| {
                c.is_ascii_whitespace()
                    || matches!(c, b'/' | b'?' | b'#' | b'"' | b'\'' | b'<' | b'>')
            })
            .map_or(b.len(), |e| at + e);
        let authority = &b[at..end];
        let Some(last_at) = authority.iter().rposition(|&c| c == b'@') else {
            continue;
        };
        let userinfo = &authority[..last_at];
        if let Some(colon) = userinfo.iter().position(|&c| c == b':') {
            if colon + 1 < userinfo.len() {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key-shaped token made at run time, never a literal (gate 13's
    /// rule on key-shaped literals in the tree).
    fn generated(len: usize, seed: u64) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                char::from(ALPHABET[usize::try_from(x % 57).unwrap_or(0)])
            })
            .collect()
    }

    #[test]
    fn generated_tokens_are_keys_and_prose_is_not() {
        let token = generated(32, 7);
        assert!(holds_key(&format!("use this one: {token} thanks")));
        // A commit id and a digest, made at run time.
        let commit: String = (0..40)
            .map(|i| char::from(b"0123456789abcdef"[i * 7 % 16]))
            .collect();
        let digest: String = (0..64)
            .map(|i| char::from(b"0123456789abcdef"[i * 5 % 16]))
            .collect();
        let mixed = format!("{}A", &commit[..39]);
        assert!(holds_key(&format!("revert {mixed}")), "not one case: no id");
        for ok in [
            "Refactor AbstractSingletonProxyFactoryBean please",
            &format!("revert {commit}"),
            &format!("revert {}", commit.to_ascii_uppercase()),
            &format!("the digest is {digest}"),
            "call https://example.com/v1/users/12345/profile",
            "a uuid 123e4567-e89b-12d3-a456-426614174000",
            "",
        ] {
            assert!(!holds_key(ok), "{ok}");
        }
        assert!(holds_key("connect to postgres://app:hunter2@db.local/app"));
        assert!(!holds_key("connect to postgres://app@db.local/app"));
    }

    #[test]
    fn a_key_pasted_in_two_parts_is_read_whole() {
        let token = generated(32, 11);
        let (a, b) = token.split_at(16);
        let prompt = format!(
            "<pasted_content id=\"1\">\n{a}\n</pasted_content id=\"1\">\n\
             <pasted_content id=\"2\">\n{b}\n</pasted_content id=\"2\">\nuse it"
        );
        assert!(!shaped(&prompt), "each part alone is no key");
        assert!(holds_key(&prompt));
        assert_eq!(without_paste_markers("a\nb"), "a\nb");
    }
}
