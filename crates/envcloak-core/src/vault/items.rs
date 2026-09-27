//! Items, fields, projects and policies: the metadata the vault keeps, and
//! the records sealed into its rows (SPEC §5 "Items"; layouts in
//! docs/VAULT.md).
//!
//! Metadata is decrypted into memory at unlock. Values are not: they stay
//! sealed in `fields.sealed_value` and `fields.sealed_prior` until a caller
//! asks for one (see `values.rs`).

use crate::crypto::ItemClass;

use super::codec::{Dec, Enc};
use super::error::{VaultError, VaultErrorKind};

/// The largest sealed plaintext of one column: a secret value, an item's
/// metadata, a project or a policy (SPEC §5: 64 KiB per sensitive field).
/// The prior list is the exception: it packs up to [`MAX_PRIOR`] values of
/// at most this size each into one column, bounded by [`MAX_ROW`].
pub const MAX_FIELD: usize = 64 * 1024;
/// The largest row, all columns together (SPEC §5: 1 MiB per row).
pub const MAX_ROW: usize = 1024 * 1024;
/// Prior values kept per field when a value is replaced.
pub const MAX_PRIOR: usize = 3;

macro_rules! row_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        ///
        /// A ULID: 48 bits of creation time in milliseconds, then 80 random
        /// bits. Not secret. `Display` and `Debug` show the 26-character
        /// Crockford base32 form.
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            /// A new identifier.
            ///
            /// # Panics
            /// When the OS random number generator fails.
            pub fn generate() -> Self {
                $name(new_ulid())
            }

            pub fn from_bytes(b: [u8; 16]) -> Self {
                $name(b)
            }

            pub fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&ulid_text(&self.0))
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}({})", stringify!($name), ulid_text(&self.0))
            }
        }
    };
}

row_id!(
    /// An item's identifier.
    ItemId
);
row_id!(
    /// A field's identifier.
    FieldId
);
row_id!(
    /// A project record's identifier.
    ProjectId
);
row_id!(
    /// A policy record's identifier.
    PolicyId
);

fn new_ulid() -> [u8; 16] {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let ms = u64::try_from(ms).unwrap_or(u64::MAX);
    let mut id = [0u8; 16];
    id[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
    crate::crypto::fill_random_or_panic(&mut id[6..]);
    id
}

fn ulid_text(id: &[u8; 16]) -> String {
    const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let v = u128::from_be_bytes(*id);
    (0..26)
        .map(|i| {
            let shift = 5 * (25 - i);
            char::from(CROCKFORD[((v >> shift) & 0x1f) as usize])
        })
        .collect()
}

/// An item's human reference, such as `openai/work`. Unique in the vault.
///
/// One or more parts separated by `/`. Each part starts with a lowercase
/// ASCII letter or digit and continues with those, `.`, `_` or `-`. At most
/// 128 bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Slug(String);

impl Slug {
    pub const MAX_LEN: usize = 128;

    pub fn new(s: &str) -> Result<Self, VaultError> {
        let ok = !s.is_empty() && s.len() <= Self::MAX_LEN && s.split('/').all(valid_part);
        if ok {
            Ok(Slug(s.to_owned()))
        } else {
            Err(VaultErrorKind::InvalidSlug.into())
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for Slug {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A field's name within its item, such as `api_key`. Unique per item.
///
/// Starts with a lowercase ASCII letter, digit or `_` and continues with
/// those, `.` or `-`. At most 64 bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FieldName(String);

impl FieldName {
    pub const MAX_LEN: usize = 64;

    pub fn new(s: &str) -> Result<Self, VaultError> {
        let first_ok = s
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if first_ok && s.len() <= Self::MAX_LEN && s.bytes().all(part_byte) {
            Ok(FieldName(s.to_owned()))
        } else {
            Err(VaultErrorKind::InvalidFieldName.into())
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for FieldName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

fn part_byte(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
}

fn valid_part(p: &str) -> bool {
    p.bytes()
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && p.bytes().all(part_byte)
}

/// Whether an item is a test key, a live key, or not known (SPEC §5
/// "Items"). Part of the item record: never renumber.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Classification {
    #[default]
    Unknown = 0,
    Test = 1,
    Live = 2,
}

impl Classification {
    fn from_byte(b: u8) -> Result<Self, VaultError> {
        match b {
            0 => Ok(Classification::Unknown),
            1 => Ok(Classification::Test),
            2 => Ok(Classification::Live),
            _ => Err(VaultErrorKind::Corrupt.into()),
        }
    }
}

/// Who owns or pays for an item. Personal metadata: shown only where the
/// spec allows (T11).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Account {
    pub email: Option<String>,
    pub label: Option<String>,
    pub org_id: Option<String>,
}

/// Provider pages for an item.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Links {
    pub docs: Option<String>,
    pub billing: Option<String>,
    pub keys_page: Option<String>,
    pub dashboard: Option<String>,
}

/// An item's editable metadata. Times are Unix seconds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ItemDetails {
    pub title: String,
    /// A provider registry id, such as `openai`.
    pub provider: Option<String>,
    pub account: Account,
    /// The environment variable the value usually goes in.
    pub env_hint: Option<String>,
    pub classification: Classification,
    /// Snapshot of the provider's allowed hosts at creation.
    pub allowed_hosts: Vec<String>,
    /// Values of 8 to 15 bytes may be injected only with this set (§6.1).
    pub allow_short: bool,
    pub tags: Vec<String>,
    pub links: Links,
    pub expires_at: Option<u64>,
    pub rotated_at: Option<u64>,
    pub last_used_at: Option<u64>,
    pub notes: String,
}

/// A new item for [`Txn::create_item`](super::Txn::create_item).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewItem {
    /// Any class but [`ItemClass::None`].
    pub class: ItemClass,
    pub slug: Slug,
    pub details: ItemDetails,
}

/// A field as the vault lists it: never its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldMeta {
    pub id: FieldId,
    pub name: FieldName,
    /// Prior values kept, newest first, up to [`MAX_PRIOR`].
    pub prior_count: u8,
    pub created_at: u64,
    pub updated_at: u64,
}

/// An item's metadata, with its fields sorted by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemMeta {
    pub id: ItemId,
    pub class: ItemClass,
    pub slug: Slug,
    pub details: ItemDetails,
    pub created_at: u64,
    pub updated_at: u64,
    pub fields: Vec<FieldMeta>,
}

/// What identifies a project directory to the vault: bytes chosen by the
/// caller, such as the device and inode of the opened directory (T5). Kept
/// sealed; the row stores only its keyed hash.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProjectKey(Vec<u8>);

impl ProjectKey {
    pub const MAX_LEN: usize = 1024;

    pub fn new(b: &[u8]) -> Result<Self, VaultError> {
        if b.is_empty() || b.len() > Self::MAX_LEN {
            return Err(VaultErrorKind::InvalidRecord.into());
        }
        Ok(ProjectKey(b.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One `ENV_NAME = "<reference>"` binding a project adopted (§6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectBinding {
    pub env_name: String,
    pub reference: String,
}

/// The vault's index entry for a project (SPEC §5: path, directory
/// identity, manifest hash, adopted bindings, last seen).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectRecord {
    pub key: ProjectKey,
    /// For display only; the key is the identity.
    pub display_path: String,
    pub manifest_sha256: [u8; 32],
    pub bindings: Vec<ProjectBinding>,
    pub last_seen: u64,
}

// Record format versions: the first byte of each sealed record.
const ITEM_RECORD: u8 = 1;
const FIELD_RECORD: u8 = 1;
const PROJECT_RECORD: u8 = 1;

/// The sealed plaintext of `items.sealed_meta`.
pub(crate) fn encode_item(slug: &Slug, created_at: u64, d: &ItemDetails) -> Vec<u8> {
    let mut e = Enc::new();
    e.u8(ITEM_RECORD)
        .str(slug.as_str())
        .str(&d.title)
        .opt_str(d.provider.as_deref())
        .opt_str(d.account.email.as_deref())
        .opt_str(d.account.label.as_deref())
        .opt_str(d.account.org_id.as_deref())
        .opt_str(d.env_hint.as_deref())
        .u8(d.classification as u8)
        .strs(&d.allowed_hosts)
        .u8(u8::from(d.allow_short))
        .strs(&d.tags)
        .opt_str(d.links.docs.as_deref())
        .opt_str(d.links.billing.as_deref())
        .opt_str(d.links.keys_page.as_deref())
        .opt_str(d.links.dashboard.as_deref())
        .u64(created_at)
        .opt_u64(d.expires_at)
        .opt_u64(d.rotated_at)
        .opt_u64(d.last_used_at)
        .str(&d.notes);
    e.finish()
}

/// Decodes [`encode_item`]'s output: `(slug, created_at, details)`.
pub(crate) fn decode_item(b: &[u8]) -> Result<(Slug, u64, ItemDetails), VaultError> {
    let mut d = Dec::new(b);
    if d.u8()? != ITEM_RECORD {
        return Err(VaultErrorKind::Corrupt.into());
    }
    let slug = Slug::new(&d.string()?).map_err(|_| VaultError::from(VaultErrorKind::Corrupt))?;
    let title = d.string()?;
    let provider = d.opt_string()?;
    let account = Account {
        email: d.opt_string()?,
        label: d.opt_string()?,
        org_id: d.opt_string()?,
    };
    let env_hint = d.opt_string()?;
    let classification = Classification::from_byte(d.u8()?)?;
    let allowed_hosts = d.strings()?;
    let allow_short = d.bool()?;
    let tags = d.strings()?;
    let links = Links {
        docs: d.opt_string()?,
        billing: d.opt_string()?,
        keys_page: d.opt_string()?,
        dashboard: d.opt_string()?,
    };
    let created_at = d.u64()?;
    let details = ItemDetails {
        title,
        provider,
        account,
        env_hint,
        classification,
        allowed_hosts,
        allow_short,
        tags,
        links,
        expires_at: d.opt_u64()?,
        rotated_at: d.opt_u64()?,
        last_used_at: d.opt_u64()?,
        notes: d.string()?,
    };
    d.end()?;
    Ok((slug, created_at, details))
}

/// The field's metadata record, sealed into `fields.sealed_name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldRecord {
    pub name: FieldName,
    pub prior_count: u8,
    pub created_at: u64,
    pub updated_at: u64,
}

pub(crate) fn encode_field(r: &FieldRecord) -> Vec<u8> {
    let mut e = Enc::new();
    e.u8(FIELD_RECORD)
        .str(r.name.as_str())
        .u8(r.prior_count)
        .u64(r.created_at)
        .u64(r.updated_at);
    e.finish()
}

pub(crate) fn decode_field(b: &[u8]) -> Result<FieldRecord, VaultError> {
    let mut d = Dec::new(b);
    if d.u8()? != FIELD_RECORD {
        return Err(VaultErrorKind::Corrupt.into());
    }
    let name =
        FieldName::new(&d.string()?).map_err(|_| VaultError::from(VaultErrorKind::Corrupt))?;
    let r = FieldRecord {
        name,
        prior_count: d.u8()?,
        created_at: d.u64()?,
        updated_at: d.u64()?,
    };
    d.end()?;
    if usize::from(r.prior_count) > MAX_PRIOR {
        return Err(VaultErrorKind::Corrupt.into());
    }
    Ok(r)
}

pub(crate) fn encode_project(p: &ProjectRecord) -> Vec<u8> {
    let mut e = Enc::new();
    e.u8(PROJECT_RECORD)
        .bytes(p.key.as_bytes())
        .str(&p.display_path)
        .raw(&p.manifest_sha256);
    let n = u32::try_from(p.bindings.len()).unwrap_or(u32::MAX);
    e.raw(&n.to_be_bytes());
    for b in &p.bindings {
        e.str(&b.env_name).str(&b.reference);
    }
    e.u64(p.last_seen);
    e.finish()
}

pub(crate) fn decode_project(b: &[u8]) -> Result<ProjectRecord, VaultError> {
    let mut d = Dec::new(b);
    if d.u8()? != PROJECT_RECORD {
        return Err(VaultErrorKind::Corrupt.into());
    }
    let key = ProjectKey::new(d.bytes()?).map_err(|_| VaultError::from(VaultErrorKind::Corrupt))?;
    let display_path = d.string()?;
    let manifest_sha256 = d.array()?;
    let n = d.u32()?;
    let mut bindings = Vec::new();
    for _ in 0..n {
        bindings.push(ProjectBinding {
            env_name: d.string()?,
            reference: d.string()?,
        });
    }
    let last_seen = d.u64()?;
    d.end()?;
    Ok(ProjectRecord {
        key,
        display_path,
        manifest_sha256,
        bindings,
        last_seen,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs_and_field_names_follow_their_grammar() {
        for ok in [
            "openai/work",
            "a",
            "stripe/acme-live",
            "neon/acme.v2",
            "x_y/0",
        ] {
            assert_eq!(Slug::new(ok).unwrap().as_str(), ok);
        }
        let long = "a".repeat(Slug::MAX_LEN + 1);
        for bad in [
            "",
            "/a",
            "a/",
            "a//b",
            "A/b",
            "a b",
            "a#f",
            ".a",
            "-a",
            "a/_b",
            "\u{e9}",
            long.as_str(),
        ] {
            assert_eq!(
                Slug::new(bad).unwrap_err().kind(),
                VaultErrorKind::InvalidSlug,
                "{bad:?}"
            );
        }
        for ok in ["api_key", "_x", "url", "a.b-c", "0"] {
            assert_eq!(FieldName::new(ok).unwrap().as_str(), ok);
        }
        let long = "a".repeat(FieldName::MAX_LEN + 1);
        for bad in ["", "API_KEY", "a/b", ".a", "-a", "a b", long.as_str()] {
            assert_eq!(
                FieldName::new(bad).unwrap_err().kind(),
                VaultErrorKind::InvalidFieldName,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn ids_are_ulids() {
        let a = ItemId::generate();
        let b = ItemId::generate();
        assert_ne!(a, b);
        let text = a.to_string();
        assert_eq!(text.len(), 26);
        assert!(text.bytes().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(format!("{a:?}"), format!("ItemId({text})"));
        // Known answer: all zero bits, and one bit at each end.
        assert_eq!(ulid_text(&[0; 16]), "0".repeat(26));
        let mut one = [0u8; 16];
        one[15] = 1;
        assert_eq!(ulid_text(&one), format!("{}1", "0".repeat(25)));
        let mut top = [0u8; 16];
        top[0] = 0x80;
        assert_eq!(ulid_text(&top), format!("4{}", "0".repeat(25)));
        // The time prefix orders ids by creation.
        let later = {
            std::thread::sleep(std::time::Duration::from_millis(2));
            FieldId::generate()
        };
        assert!(later.as_bytes()[..6] > a.as_bytes()[..6]);
    }

    #[test]
    fn records_round_trip() {
        let details = ItemDetails {
            title: "OpenAI (work)".into(),
            provider: Some("openai".into()),
            account: Account {
                email: Some("dev@example.com".into()),
                label: None,
                org_id: Some("org-1".into()),
            },
            env_hint: Some("OPENAI_API_KEY".into()),
            classification: Classification::Live,
            allowed_hosts: vec!["api.openai.com".into()],
            allow_short: true,
            tags: vec!["work".into(), "ai".into()],
            links: Links {
                docs: Some("https://example.com/docs".into()),
                ..Links::default()
            },
            expires_at: Some(5),
            rotated_at: None,
            last_used_at: Some(7),
            notes: "note".into(),
        };
        let slug = Slug::new("openai/work").unwrap();
        let bytes = encode_item(&slug, 42, &details);
        assert_eq!(decode_item(&bytes).unwrap(), (slug, 42, details));
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(
            decode_item(&extra).unwrap_err().kind(),
            VaultErrorKind::Corrupt
        );

        let f = FieldRecord {
            name: FieldName::new("api_key").unwrap(),
            prior_count: 2,
            created_at: 1,
            updated_at: 2,
        };
        assert_eq!(decode_field(&encode_field(&f)).unwrap(), f);

        let p = ProjectRecord {
            key: ProjectKey::new(&[1, 2, 3]).unwrap(),
            display_path: "/src/acme-web".into(),
            manifest_sha256: [9; 32],
            bindings: vec![ProjectBinding {
                env_name: "OPENAI_API_KEY".into(),
                reference: "openai/work".into(),
            }],
            last_seen: 3,
        };
        assert_eq!(decode_project(&encode_project(&p)).unwrap(), p);
        assert_eq!(
            ProjectKey::new(&[]).unwrap_err().kind(),
            VaultErrorKind::InvalidRecord
        );
    }
}
