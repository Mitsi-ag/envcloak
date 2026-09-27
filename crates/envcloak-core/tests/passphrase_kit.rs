//! Passphrase rules, suggested passphrases and the Recovery Kit's text
//! (SPEC §5 "Unlockers"; the formats are in docs/CRYPTO.md "Passphrases"
//! and "Recovery Kit").
//!
//! - A new passphrase must be UTF-8 text without control characters, at
//!   least 12 characters long, and not on the bundled common-password list
//!   in any ASCII case. Rejections carry no part of the passphrase.
//! - A suggested passphrase is six EFF words that pass the rules.
//! - A kit shows as seven groups of four Crockford symbols, parses back
//!   leniently, and its check symbols catch every one- or two-symbol
//!   mistake before any key derivation.
#![allow(clippy::unwrap_used)]

use envcloak_core::passphrase::{MIN_PASSPHRASE_CHARS, SUGGESTED_WORDS};
use envcloak_core::vault::VaultErrorKind;
use envcloak_core::{
    KitError, PassphraseRejected, RecoveryKit, SecretBytes, check_passphrase, suggest_passphrase,
};
use envcloak_testkit::{Detector, by_label, canaries, fresh_seed, labels};

static_assertions::assert_not_impl_any!(RecoveryKit: Clone, Copy, core::fmt::Display);

fn secret(s: &str) -> SecretBytes {
    SecretBytes::copy_from(s.as_bytes())
}

// ------------------------------------------------------ passphrase rules

#[test]
fn passphrase_rules() {
    let cs = canaries(fresh_seed());
    check_passphrase(&secret(by_label(&cs, labels::VAULT_PASSPHRASE).as_str())).unwrap();

    // Length counts characters, not bytes.
    let twelve = "q7 kx vb3 tw";
    assert_eq!(twelve.chars().count(), MIN_PASSPHRASE_CHARS);
    check_passphrase(&secret(twelve)).unwrap();
    for short in [
        "",
        "a",
        "correct hor",
        "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}",
    ] {
        assert_eq!(
            check_passphrase(&secret(short)).unwrap_err(),
            PassphraseRejected::TooShort,
            "{} chars",
            short.chars().count()
        );
    }
    check_passphrase(&secret(&"\u{e9}".repeat(12))).unwrap();

    for control in [
        "correct horse\nbattery staple",
        "correct horse\tbattery staple",
        "correct horse battery staple\r",
        "correct horse\u{7f}battery staple",
        "correct horse\u{85}battery staple",
    ] {
        assert_eq!(
            check_passphrase(&secret(control)).unwrap_err(),
            PassphraseRejected::ControlCharacter
        );
    }
    let not_text = SecretBytes::copy_from(b"correct horse \xff battery staple");
    assert_eq!(
        check_passphrase(&not_text).unwrap_err(),
        PassphraseRejected::NotText
    );

    // On the bundled list, in any ASCII case.
    for common in [
        "passwordpassword",
        "PasswordPassword",
        "QWERTYUIOPASDFGH",
        "iloveyouiloveyou",
        "1234567890qwerty",
        "qwertyuiop[]\\",
    ] {
        assert_eq!(
            check_passphrase(&secret(common)).unwrap_err(),
            PassphraseRejected::Common,
            "{common}"
        );
    }
    // Close to a listed one is not on the list.
    check_passphrase(&secret("passwordpassword7x")).unwrap();

    // Messages are fixed and value-free.
    let det = Detector::new(&cs);
    let mut seen = std::collections::HashSet::new();
    for r in PassphraseRejected::ALL {
        let shown = format!("{r} {r:?} {}", VaultErrorKind::Passphrase(r).message());
        assert!(det.find(shown.as_bytes()).is_empty());
        assert!(seen.insert(r.message()));
        assert_eq!(r.to_string(), r.message());
    }
}

#[test]
fn suggested_passphrases_are_six_listed_words_and_pass_the_rules() {
    let mut seen = std::collections::HashSet::new();
    for _ in 0..200 {
        let s = suggest_passphrase();
        assert_eq!(s.len(), s.capacity(), "exact capacity: no reallocation");
        let words: Vec<&str> = s.split(' ').collect();
        assert_eq!(words.len(), SUGGESTED_WORDS);
        for w in &words {
            assert!(
                (3..=9).contains(&w.len())
                    && w.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "an EFF word"
            );
        }
        check_passphrase(&secret(&s)).unwrap();
        assert!(seen.insert(s.to_string()), "a repeated suggestion");
    }
    // 200 suggestions draw 1,200 words from 7,776: many distinct ones.
    let words: std::collections::HashSet<String> = seen
        .iter()
        .flat_map(|s| s.split(' ').map(str::to_owned).collect::<Vec<_>>())
        .collect();
    assert!(words.len() > 900, "{} distinct words", words.len());
}

// ------------------------------------------------------ Recovery Kit text

const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn symbols(text: &str) -> Vec<u8> {
    text.bytes().filter(|b| *b != b'-').collect()
}

fn with_symbols(s: &[u8]) -> SecretBytes {
    SecretBytes::copy_from(s)
}

#[test]
fn the_kit_is_seven_groups_of_four_and_parses_back() {
    for _ in 0..200 {
        let kit = RecoveryKit::generate();
        let text = kit.to_display();
        assert_eq!(text.len(), text.capacity(), "exact capacity");
        let groups: Vec<&str> = text.split('-').collect();
        assert_eq!(groups.len(), 7);
        for g in &groups {
            assert_eq!(g.len(), 4);
            assert!(g.bytes().all(|b| ALPHABET.contains(&b)));
        }
        let back = RecoveryKit::parse(&secret(&text)).unwrap();
        assert_eq!(*back.to_display(), *text);
        assert_eq!(format!("{kit:?}"), "RecoveryKit(..)");

        // Lowercase, spaced, or run together, with the confusable letters.
        let loose: String = text
            .chars()
            .map(|c| match c {
                '-' => ' ',
                '0' => 'o',
                '1' => 'l',
                c => c.to_ascii_lowercase(),
            })
            .collect();
        let parsed = RecoveryKit::parse(&secret(&format!("  {loose}\n"))).unwrap();
        assert_eq!(*parsed.to_display(), *text);
        let packed: String = text.chars().filter(|c| *c != '-').collect();
        let parsed = RecoveryKit::parse(&secret(&packed.replace('1', "I"))).unwrap();
        assert_eq!(*parsed.to_display(), *text);
    }
}

/// The check symbols catch every single-symbol typo and every swap of two
/// different symbols, before any key derivation.
#[test]
fn every_one_or_two_symbol_mistake_is_caught() {
    for _ in 0..8 {
        let text = RecoveryKit::generate().to_display();
        let good = symbols(&text);
        assert_eq!(good.len(), RecoveryKit::SYMBOLS);
        for i in 0..good.len() {
            for &c in ALPHABET {
                if c == good[i] {
                    continue;
                }
                let mut bad = good.clone();
                bad[i] = c;
                assert_eq!(
                    RecoveryKit::parse(&with_symbols(&bad)).unwrap_err(),
                    KitError::Checksum,
                    "symbol {i} changed"
                );
            }
            for j in i + 1..good.len() {
                if good[i] == good[j] {
                    continue;
                }
                let mut bad = good.clone();
                bad.swap(i, j);
                assert_eq!(
                    RecoveryKit::parse(&with_symbols(&bad)).unwrap_err(),
                    KitError::Checksum,
                    "symbols {i} and {j} swapped"
                );
            }
        }
        // Two changed symbols anywhere.
        let mut n = 0u32;
        for i in 0..good.len() {
            for j in i + 1..good.len() {
                n += 1;
                let mut bad = good.clone();
                bad[i] = ALPHABET[(ALPHABET.iter().position(|a| *a == good[i]).unwrap()
                    + 1
                    + (n as usize % 30))
                    % 32];
                bad[j] = ALPHABET[(ALPHABET.iter().position(|a| *a == good[j]).unwrap()
                    + 1
                    + (n as usize * 7 % 31))
                    % 32];
                assert_eq!(
                    RecoveryKit::parse(&with_symbols(&bad)).unwrap_err(),
                    KitError::Checksum,
                    "symbols {i} and {j} changed"
                );
            }
        }
    }
}

#[test]
fn malformed_kits_are_refused_without_their_text() {
    let text = RecoveryKit::generate().to_display();
    let good = symbols(&text);
    let cases: Vec<(Vec<u8>, KitError)> = vec![
        (Vec::new(), KitError::Length),
        (good[..27].to_vec(), KitError::Length),
        ([&good[..], b"0"].concat(), KitError::Length),
        ([&good[..], &good[..]].concat(), KitError::Length),
        ([&good[..27], b"U"].concat(), KitError::Character),
        ([&good[..27], b"*"].concat(), KitError::Character),
        ([&good[..27], b"_"].concat(), KitError::Character),
        (
            [&good[..27], "\u{e9}".as_bytes()].concat(),
            KitError::Character,
        ),
        ([&good[..27], b"\0"].concat(), KitError::Character),
    ];
    for (input, want) in cases {
        let e = RecoveryKit::parse(&with_symbols(&input)).unwrap_err();
        assert_eq!(e, want);
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains(&text[..9]) && !shown.contains(&text[10..14]));
    }
    let messages: std::collections::HashSet<&str> =
        KitError::ALL.iter().map(|e| e.message()).collect();
    assert_eq!(messages.len(), KitError::ALL.len());
    // A passphrase is not a kit.
    let cs = canaries(fresh_seed());
    let pass = by_label(&cs, labels::VAULT_PASSPHRASE);
    assert!(RecoveryKit::parse(&secret(pass.as_str())).is_err());
}
