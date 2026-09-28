//! The short-value policy and the redactor for one run (SPEC §6.1 step 6,
//! §15.2 gate 9).
//!
//! - A value under [`MIN_VALUE_LEN`] (8) bytes is never injected: it would
//!   be too common a string to redact without destroying ordinary output.
//! - A value of 8 to 15 bytes is injected only when its item has
//!   `allow_short` ([`ShortPolicy::Allow`]), and is then reported
//!   ([`CoverageReport::warned_short`]): its whole-value encodings are
//!   redacted, but pieces of it inside a longer base64 stream may not be.
//! - Every value is added to one [`Redactor`] labeled with its item's
//!   slug. Two bindings of one item add it once.
//!
//! This file is on security/expose-allowlist.txt: it hands the values to
//! the redactor's builder.

use envcloak_core::SecretBytes;
use envcloak_core::vault::Slug;
use envcloak_redact::{Redactor, RedactorBuilder};
use secrecy::ExposeSecret;

use crate::ExecError;

/// Values shorter than this are never injected.
pub const MIN_VALUE_LEN: usize = 8;

/// Values shorter than this need `allow_short` on their item.
pub const COMFORT_LEN: usize = 16;

/// Whether an item takes values of 8 to 15 bytes (its `allow_short`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShortPolicy {
    /// The default: such a value is refused.
    Refuse,
    /// The item has `allow_short`: such a value is injected, with a
    /// warning.
    Allow,
}

impl From<bool> for ShortPolicy {
    fn from(allow_short: bool) -> Self {
        if allow_short {
            ShortPolicy::Allow
        } else {
            ShortPolicy::Refuse
        }
    }
}

/// One value to redact: the slug that labels it, the value, and its
/// item's short-value policy.
#[derive(Debug, Clone, Copy)]
pub struct Label<'a> {
    pub slug: &'a Slug,
    pub value: &'a SecretBytes,
    pub short: ShortPolicy,
}

/// What the redactor covers less than fully, by slug, in the order the
/// values came. Never a value.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CoverageReport {
    /// Values that may not be injected: under 8 bytes, or 8 to 15 bytes
    /// without `allow_short`.
    pub refused_short: Vec<Slug>,
    /// Values of 8 to 15 bytes injected under `allow_short`.
    pub warned_short: Vec<Slug>,
    /// Values whose pieces inside a longer base64 or base64url stream are
    /// not redacted at every byte alignment (too few whole groups). The
    /// value and its whole-value encodings still are.
    pub partial: Vec<Slug>,
    /// Values with so many kinds of JSON escapes that not every
    /// combination of serializer options is redacted; the default output
    /// of common serializers still is.
    pub truncated: Vec<Slug>,
}

impl CoverageReport {
    /// Whether anything is less than fully covered.
    pub fn is_clean(&self) -> bool {
        self.refused_short.is_empty()
            && self.warned_short.is_empty()
            && self.partial.is_empty()
            && self.truncated.is_empty()
    }
}

fn push_once(list: &mut Vec<Slug>, slug: &Slug) {
    if !list.contains(slug) {
        list.push(slug.clone());
    }
}

/// Builds the run's redactor from `labels` and reports what it does not
/// fully cover.
///
/// # Errors
/// [`ExecError::ValueTooShort`], carrying the whole report, when any value
/// is under 8 bytes, or 8 to 15 bytes with [`ShortPolicy::Refuse`]. No
/// redactor is built then.
pub fn build_redactor(labels: &[Label<'_>]) -> Result<(Redactor, CoverageReport), ExecError> {
    let mut report = CoverageReport::default();
    for l in labels {
        let len = l.value.len();
        if len < MIN_VALUE_LEN || (len < COMFORT_LEN && l.short == ShortPolicy::Refuse) {
            push_once(&mut report.refused_short, l.slug);
        } else if len < COMFORT_LEN {
            push_once(&mut report.warned_short, l.slug);
        }
    }
    if !report.refused_short.is_empty() {
        return Err(ExecError::ValueTooShort(report));
    }
    let mut builder = RedactorBuilder::new().min_secret_len(MIN_VALUE_LEN);
    let mut added: Vec<(&Slug, &SecretBytes)> = Vec::with_capacity(labels.len());
    for l in labels {
        // A value bound twice (two variables, one item) is added once.
        if added
            .iter()
            .any(|(s, v)| *s == l.slug && v.ct_eq_secret(l.value))
        {
            continue;
        }
        added.push((l.slug, l.value));
        builder = add(builder, l.slug, l.value);
    }
    let (redactor, built) = builder.build();
    // The policy above refused everything the builder would skip.
    if !built.skipped.is_empty() {
        return Err(ExecError::Setup(std::io::ErrorKind::InvalidData));
    }
    let find = |label: &String| added.iter().find(|(s, _)| s.as_str() == label);
    for label in &built.partial {
        if let Some((slug, _)) = find(label) {
            push_once(&mut report.partial, slug);
        }
    }
    for label in &built.truncated {
        if let Some((slug, _)) = find(label) {
            push_once(&mut report.truncated, slug);
        }
    }
    Ok((redactor, report))
}

#[allow(clippy::disallowed_methods)] // Hands the value to the redactor's builder.
fn add(builder: RedactorBuilder, slug: &Slug, value: &SecretBytes) -> RedactorBuilder {
    builder.secret(slug.as_str(), value.expose_secret())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slug(s: &str) -> Slug {
        Slug::new(s).unwrap()
    }

    /// `n` letters and digits, generated: no literal value in the source.
    fn value(n: usize) -> SecretBytes {
        const ALNUM: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut x = 0x9e37_79b9_7f4a_7c15_u64 ^ u64::try_from(n).unwrap();
        let v: Vec<u8> = (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                ALNUM[usize::try_from(x % 62).unwrap()]
            })
            .collect();
        SecretBytes::from_vec(v)
    }

    /// Gate 9's policy: under 8 bytes refused whatever the item says, 8 to
    /// 15 refused without `allow_short` and reported with it, 16 and over
    /// taken as they are.
    #[test]
    fn short_values_are_refused_or_reported() {
        let (a, b, c) = (slug("a/x"), slug("b/x"), slug("c/x"));
        for (len, short, refused, warned) in [
            (7, ShortPolicy::Allow, true, false),
            (1, ShortPolicy::Allow, true, false),
            (8, ShortPolicy::Refuse, true, false),
            (15, ShortPolicy::Refuse, true, false),
            (8, ShortPolicy::Allow, false, true),
            (15, ShortPolicy::Allow, false, true),
            (16, ShortPolicy::Refuse, false, false),
            (64, ShortPolicy::Refuse, false, false),
        ] {
            let v = value(len);
            let long = value(40);
            let labels = [
                Label {
                    slug: &a,
                    value: &v,
                    short,
                },
                Label {
                    slug: &b,
                    value: &long,
                    short: ShortPolicy::Refuse,
                },
            ];
            match build_redactor(&labels) {
                Err(ExecError::ValueTooShort(r)) => {
                    assert!(refused, "{len} {short:?} was refused");
                    assert_eq!(r.refused_short, vec![a.clone()]);
                }
                Ok((red, r)) => {
                    assert!(!refused, "{len} {short:?} was taken");
                    assert_eq!(r.refused_short, Vec::<Slug>::new());
                    assert_eq!(r.warned_short.contains(&a), warned, "{len} {short:?}");
                    assert!(!r.warned_short.contains(&b));
                    // Whole values are redacted, short ones included.
                    #[allow(clippy::disallowed_methods)] // Test: reads the fixture back.
                    let raw = v.expose_secret().to_vec();
                    assert_eq!(red.redact(&raw), b"[envcloak:a/x]");
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        // Every refused value is named, once.
        let (s1, s2) = (value(3), value(12));
        let labels = [
            Label {
                slug: &a,
                value: &s1,
                short: ShortPolicy::Allow,
            },
            Label {
                slug: &c,
                value: &s2,
                short: ShortPolicy::Refuse,
            },
            Label {
                slug: &a,
                value: &s1,
                short: ShortPolicy::Allow,
            },
        ];
        let Err(ExecError::ValueTooShort(r)) = build_redactor(&labels) else {
            panic!("short values were taken");
        };
        assert_eq!(r.refused_short, vec![a, c]);
    }

    /// A 10-byte value has too few whole base64 groups at one alignment,
    /// and is reported partial; a 40-byte one is not.
    #[test]
    fn partial_coverage_is_reported_by_slug() {
        let (short, long) = (slug("short/x"), slug("long/x"));
        let (s, l) = (value(10), value(40));
        let (_, r) = build_redactor(&[
            Label {
                slug: &short,
                value: &s,
                short: ShortPolicy::Allow,
            },
            Label {
                slug: &long,
                value: &l,
                short: ShortPolicy::Refuse,
            },
            Label {
                slug: &long,
                value: &l,
                short: ShortPolicy::Refuse,
            },
        ])
        .unwrap();
        assert_eq!(r.warned_short, vec![short.clone()]);
        assert_eq!(r.partial, vec![short]);
        assert!(r.truncated.is_empty());
        assert!(!r.is_clean());
        let (_, r) = build_redactor(&[Label {
            slug: &long,
            value: &l,
            short: ShortPolicy::Refuse,
        }])
        .unwrap();
        assert!(r.is_clean(), "{r:?}");
    }
}
