//! Passphrase rules and suggested passphrases (SPEC §5 "Unlockers").
//!
//! - [`check_passphrase`]: a passphrase must be UTF-8 text without control
//!   characters, at least [`MIN_PASSPHRASE_CHARS`] characters long, and not
//!   on the bundled list of common passwords (compared ignoring ASCII
//!   case). Every new passphrase envelope is checked: at `vault create`,
//!   when the passphrase changes, and when a backup is restored.
//! - [`suggest_passphrase`]: six words drawn uniformly from the EFF Large
//!   Wordlist (about 77.5 bits), joined by spaces, which `vault create`
//!   offers.
//!
//! Rejections ([`PassphraseRejected`]) carry no part of the passphrase.
//! Suggested passphrases are built in a [`Zeroizing`] string of exact
//! capacity. This file is on security/expose-allowlist.txt: it reads a
//! passphrase to check it.

use secrecy::ExposeSecret;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::fill_random_or_panic;
use crate::secret::SecretBytes;
use crate::wordlists::{COMMON_PASSWORDS, EFF_WORDS, eff_word};

/// The minimum length of a passphrase, in characters (Unicode scalar
/// values).
pub const MIN_PASSPHRASE_CHARS: usize = 12;

/// Words in a suggested passphrase.
pub const SUGGESTED_WORDS: usize = 6;

/// Why a passphrase was refused. Carries no part of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PassphraseRejected {
    /// Not valid UTF-8.
    NotText,
    /// Holds a control character, such as a newline or a tab.
    ControlCharacter,
    /// Shorter than [`MIN_PASSPHRASE_CHARS`] characters.
    TooShort,
    /// On the bundled list of common passwords.
    Common,
}

impl PassphraseRejected {
    /// Every kind, in declaration order.
    pub const ALL: [PassphraseRejected; 4] = [
        PassphraseRejected::NotText,
        PassphraseRejected::ControlCharacter,
        PassphraseRejected::TooShort,
        PassphraseRejected::Common,
    ];

    /// The fixed message for this rejection.
    pub const fn message(self) -> &'static str {
        match self {
            PassphraseRejected::NotText => "the passphrase must be UTF-8 text",
            PassphraseRejected::ControlCharacter => {
                "the passphrase must not contain control characters such as newlines or tabs"
            }
            PassphraseRejected::TooShort => "the passphrase must be at least 12 characters long",
            PassphraseRejected::Common => {
                "the passphrase is a commonly used password; choose another, or use the \
                 suggested one"
            }
        }
    }
}

impl core::fmt::Display for PassphraseRejected {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for PassphraseRejected {}

/// Checks a new passphrase against the rules. Allocates nothing.
#[allow(clippy::disallowed_methods)] // Reads the passphrase to check it.
pub fn check_passphrase(p: &SecretBytes) -> Result<(), PassphraseRejected> {
    let text = core::str::from_utf8(p.expose_secret()).map_err(|_| PassphraseRejected::NotText)?;
    if text.chars().any(char::is_control) {
        return Err(PassphraseRejected::ControlCharacter);
    }
    if text.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(PassphraseRejected::TooShort);
    }
    // The list is lowercase ASCII; a passphrase with other characters can
    // match only where they are equal byte for byte.
    if COMMON_PASSWORDS
        .lines()
        .any(|c| c.eq_ignore_ascii_case(text))
    {
        return Err(PassphraseRejected::Common);
    }
    Ok(())
}

/// Six words drawn uniformly and independently from the EFF Large Wordlist,
/// joined by single spaces. Always passes [`check_passphrase`].
///
/// # Panics
/// When the OS random number generator fails.
pub fn suggest_passphrase() -> Zeroizing<String> {
    loop {
        let mut picks = [0usize; SUGGESTED_WORDS];
        for p in &mut picks {
            *p = uniform_below(EFF_WORDS);
        }
        let words = picks.map(|i| eff_word(i).unwrap_or_default());
        picks.zeroize();
        let len = words.iter().map(|w| w.len()).sum::<usize>() + SUGGESTED_WORDS - 1;
        let mut out = Zeroizing::new(String::with_capacity(len));
        for (i, w) in words.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            out.push_str(w);
        }
        debug_assert_eq!(out.len(), out.capacity());
        if check_passphrase(&SecretBytes::copy_from(out.as_bytes())).is_ok() {
            return out;
        }
    }
}

/// A uniform value below `n` (at most 2^16), by rejection sampling.
fn uniform_below(n: usize) -> usize {
    debug_assert!(n > 0 && n <= 1 << 16);
    // The largest multiple of `n` that fits in 16 bits.
    let limit = (1usize << 16) / n * n;
    loop {
        let mut b = [0u8; 2];
        fill_random_or_panic(&mut b);
        let v = usize::from(u16::from_be_bytes(b));
        b.zeroize();
        if v < limit {
            return v % n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_below_stays_in_range_and_reaches_the_ends() {
        let mut seen = [false; 6];
        for _ in 0..2000 {
            let v = uniform_below(6);
            seen[v] = true;
        }
        assert!(seen.iter().all(|s| *s));
        for _ in 0..2000 {
            assert!(uniform_below(EFF_WORDS) < EFF_WORDS);
        }
    }
}
