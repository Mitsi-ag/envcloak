//! Names and references shared by manifests, `--ref` arguments and env
//! files: [`EnvName`], [`ProfileName`], [`Reference`] and [`Binding`].
//!
//! Each name checks its grammar before it allocates, so a rejected name is
//! never copied.

use envcloak_core::vault::{FieldName, Slug};

use crate::manifest::{ManifestError, ManifestErrorKind};

/// An environment variable a manifest, `--ref` or env file binds: an ASCII
/// letter or `_`, then ASCII letters, digits or `_`. At most
/// [`EnvName::MAX_LEN`] bytes. Case is kept and matters, as it does to the
/// kernel.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnvName(String);

impl EnvName {
    pub const MAX_LEN: usize = 128;

    pub fn new(s: &str) -> Result<Self, ManifestError> {
        Self::from_bytes(s.as_bytes())
    }

    /// As [`EnvName::new`], from bytes.
    pub fn from_bytes(b: &[u8]) -> Result<Self, ManifestError> {
        if !Self::valid(b) {
            return Err(ManifestErrorKind::InvalidEnvName.into());
        }
        // Valid names are ASCII.
        Ok(EnvName(b.iter().map(|&c| char::from(c)).collect()))
    }

    pub(crate) fn valid(b: &[u8]) -> bool {
        b.len() <= Self::MAX_LEN
            && b.first()
                .is_some_and(|&c| c.is_ascii_alphabetic() || c == b'_')
            && b.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_')
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for EnvName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl serde::Serialize for EnvName {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

/// A name from the wire is checked as one from a manifest is; the error
/// names the rule, never the text.
impl<'de> serde::Deserialize<'de> for EnvName {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        EnvName::new(&s).map_err(|_| serde::de::Error::custom("not an environment variable name"))
    }
}

/// A profile's name: the `<name>` of `[env.<name>]`, and the argument of
/// `--profile`. A lowercase ASCII letter or digit, then those, `_` or `-`.
/// At most [`ProfileName::MAX_LEN`] bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfileName(String);

impl ProfileName {
    pub const MAX_LEN: usize = 64;

    pub fn new(s: &str) -> Result<Self, ManifestError> {
        let b = s.as_bytes();
        let ok = b.len() <= Self::MAX_LEN
            && b.first()
                .is_some_and(|&c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && b.iter()
                .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-');
        if !ok {
            return Err(ManifestErrorKind::InvalidProfileName.into());
        }
        Ok(ProfileName(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for ProfileName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a binding names: an item by its slug, and optionally one of its
/// fields. Written `<slug>[#field]`; see [`Reference::parse`].
///
/// A reference says nothing about the item's class. Binding it to the
/// vault's items ([`crate::bind_items`]) rejects anything but a secret.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reference {
    pub slug: Slug,
    /// `None`: the item's only field.
    pub field: Option<FieldName>,
}

impl Reference {
    /// Parses `<slug>` or `<slug>#<field>`, with the grammars of
    /// [`Slug::new`] and [`FieldName::new`]. Anything else, including a
    /// scheme such as `envcloak://`, fails with
    /// [`ManifestErrorKind::InvalidReference`].
    pub fn parse(s: &str) -> Result<Self, ManifestError> {
        let (slug, field) = match s.split_once('#') {
            Some((slug, field)) => (slug, Some(field)),
            None => (s, None),
        };
        let invalid = |_| ManifestError::from(ManifestErrorKind::InvalidReference);
        Ok(Reference {
            slug: Slug::new(slug).map_err(invalid)?,
            field: field.map(FieldName::new).transpose().map_err(invalid)?,
        })
    }
}

impl core::fmt::Display for Reference {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.slug.as_str())?;
        if let Some(field) = &self.field {
            write!(f, "#{field}")?;
        }
        Ok(())
    }
}

impl core::str::FromStr for Reference {
    type Err = ManifestError;

    fn from_str(s: &str) -> Result<Self, ManifestError> {
        Reference::parse(s)
    }
}

/// The shortest run of ASCII letters and digits [`value_shaped`] takes for
/// a generated key or token.
pub const VALUE_RUN: usize = 24;

/// Whether `s` looks like a value rather than a name a person chose: it
/// holds a run of at least [`VALUE_RUN`] ASCII letters and digits that
/// mixes two of lowercase, uppercase and digits, as generated keys and
/// tokens do (a hex secret, the body of a `ghp_` or `sk_test_` key) and
/// names rarely do. Names separate their words (`stripe/acme-live`,
/// `OPENAI_API_KEY`, `a.person@example.com`).
///
/// Values are never taken on the command line (gate 13), so a name that
/// looks like one was most likely pasted by mistake: commands refuse it
/// without echoing it, and output shows a placeholder in its place. The
/// check does not catch a value made of words; a provider's key pattern
/// (`envcloak_providers::Registry::mask_keys`) catches more.
pub fn value_shaped(s: &str) -> bool {
    let (mut run, mut classes) = (0usize, 0u8);
    for b in s.bytes() {
        let class = if b.is_ascii_lowercase() {
            1
        } else if b.is_ascii_uppercase() {
            2
        } else if b.is_ascii_digit() {
            4
        } else {
            (run, classes) = (0, 0);
            continue;
        };
        run += 1;
        classes |= class;
        if run >= VALUE_RUN && classes.count_ones() >= 2 {
            return true;
        }
    }
    false
}

/// One environment variable bound to one reference.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Binding {
    pub env_name: EnvName,
    pub reference: Reference,
}

impl Binding {
    /// Parses a `--ref` argument, `NAME=<slug>[#field]`. The error has no
    /// origin; the caller adds [`crate::Origin::Ref`] with the argument's
    /// index.
    pub fn parse_arg(s: &str) -> Result<Self, ManifestError> {
        let Some((name, reference)) = s.split_once('=') else {
            return Err(ManifestErrorKind::InvalidReference.into());
        };
        let env_name = EnvName::new(name)?;
        Ok(Binding {
            env_name,
            reference: Reference::parse(reference)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generated keys and tokens are value-shaped, whatever their prefix;
    /// the names people give items, variables and accounts are not.
    #[test]
    fn values_are_told_from_names() {
        let seed = envcloak_testkit::fresh_seed();
        for c in envcloak_testkit::canaries(seed) {
            let shaped = value_shaped(c.as_str());
            match c.label.as_str() {
                // Words, and a short token: not shaped like a key.
                envcloak_testkit::labels::VAULT_PASSPHRASE
                | envcloak_testkit::labels::SHORT_TOKEN
                | envcloak_testkit::labels::DATABASE_URL => {}
                // The body of every generated key is one long run of mixed
                // letters and digits, unless its random `-` and `_` cut
                // every run short (the OpenAI shape), which a key pattern
                // catches instead.
                envcloak_testkit::labels::OPENAI_API_KEY
                | envcloak_testkit::labels::OPENAI_API_KEY_ROTATED => {}
                label => assert!(shaped, "{label} (seed {seed})"),
            }
        }
        let hex: String = (0..40)
            .map(|i| char::from(b"0123456789abcdef"[i * 7 % 16]))
            .collect();
        // An access key id's shape, built here so that no key-shaped
        // literal is in the source.
        let akia: String = "AKIA"
            .chars()
            .chain(
                (0..20).map(|i| char::from(b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[i * 11 % 36])),
            )
            .collect();
        for v in [
            hex.as_str(),
            akia.as_str(),
            "x=ab12cd34ef56ab12cd34ef56",
            "ab12cd34ef56ab12cd34ef56",
            "QmFzZTY0IGlzIG5vdCBhIG5hbWU",
            "aBcDeFgHiJkLmNoPqRsTuVwX",
        ] {
            assert!(value_shaped(v), "{v}");
        }
        for name in [
            "openai/acme-web",
            "stripe/acme-live-2024",
            "OPENAI_API_KEY",
            "a.person2024@example.com",
            "acme-web",
            "value",
            "0123456789012345678901234567890123",
            "abcdefghijklmnopqrstuvwxyzabcdefghij",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJ",
            "ab12cd34ef56ab12cd34ef5",
            "123e4567-e89b-12d3-a456-426614174000",
            "",
        ] {
            assert!(!value_shaped(name), "{name}");
        }
    }
}
