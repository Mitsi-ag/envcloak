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
