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
/// at most this size each into one column, bounded by [`MAX_ROW`]. An
/// item's record holds this much of what its writer gives, and after it the
/// few bytes the vault keeps itself ([`MAX_ITEM_KEPT`]).
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

/// Where an item's value was found outside the vault, which makes it
/// "exposed: rotate" (SPEC §6.4, §6.5). Part of the item record (schema
/// version 2): never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ExposureSource {
    /// An agent's transcript or one of its stores.
    Transcript = 1,
    /// A git repository's history.
    GitHistory = 2,
    /// A backup of a config file, an agent's included.
    ConfigBackup = 3,
    /// A folder a sync service copies off the machine.
    SyncedFolder = 4,
    /// A shell profile or a file one sources.
    ShellProfile = 5,
    /// An agent's or an MCP server's config.
    AgentConfig = 6,
    /// A dotenv file.
    EnvFile = 7,
}

impl ExposureSource {
    /// Every source, in number order.
    pub const ALL: [ExposureSource; 7] = [
        ExposureSource::Transcript,
        ExposureSource::GitHistory,
        ExposureSource::ConfigBackup,
        ExposureSource::SyncedFolder,
        ExposureSource::ShellProfile,
        ExposureSource::AgentConfig,
        ExposureSource::EnvFile,
    ];

    fn from_byte(b: u8) -> Result<Self, VaultError> {
        ExposureSource::ALL
            .into_iter()
            .find(|s| *s as u8 == b)
            .ok_or_else(|| VaultErrorKind::Corrupt.into())
    }
}

/// That an item's value was found outside the vault (R-M2-40): since when,
/// where, and how many times it was marked. Set by
/// [`Txn::mark_exposed`](super::Txn::mark_exposed), which only adds to it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Exposure {
    /// Unix seconds of the first mark.
    pub since: u64,
    /// Every kind of place it was found, sorted, each once; never empty.
    pub sources: Vec<ExposureSource>,
    /// Places found, summed over every mark.
    pub count: u64,
}

/// A login's sign-in tier (SPEC §6.8 "Approval"). Part of the item
/// record: never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LoginTier {
    /// Loopback and registered dev origins with a test identity.
    Dev = 1,
    /// One proof per sign-in.
    Each = 2,
    /// Never for an agent.
    NeverAgent = 3,
}

impl LoginTier {
    fn from_byte(b: u8) -> Result<Self, VaultError> {
        match b {
            1 => Ok(LoginTier::Dev),
            2 => Ok(LoginTier::Each),
            3 => Ok(LoginTier::NeverAgent),
            _ => Err(VaultErrorKind::Corrupt.into()),
        }
    }
}

/// A login item's own metadata (SPEC §6.8 "Login items"). Whether it is a
/// test or a live login is its [`ItemDetails::classification`]; anything
/// but `Test` counts as live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoginMeta {
    pub tier: LoginTier,
    /// The longest a session it signs in may be kept, in seconds.
    pub session_lifetime: u64,
}

/// What kind of value a field holds. Every field of a `secret`, `card` or
/// `issuer_credential` item is a [`FieldKind::Value`]; a `login` item's
/// fields are typed, one of each, named for their kind (SPEC §6.8: "Login
/// fields are typed"). Part of the field record (schema version 2): never
/// renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FieldKind {
    Value = 0,
    Username = 1,
    Password = 2,
    /// The TOTP enrollment: seed, algorithm, digits and period, sealed
    /// together as one value.
    TotpSeed = 3,
    /// The key of the test-session adapter (SPEC §6.8).
    AdapterKey = 4,
}

impl FieldKind {
    /// The kinds a login's fields have.
    pub const LOGIN: [FieldKind; 4] = [
        FieldKind::Username,
        FieldKind::Password,
        FieldKind::TotpSeed,
        FieldKind::AdapterKey,
    ];

    /// The name a login field of this kind has; `None` for a value field,
    /// whose name its item chooses.
    pub fn login_name(self) -> Option<&'static str> {
        match self {
            FieldKind::Value => None,
            FieldKind::Username => Some("username"),
            FieldKind::Password => Some("password"),
            FieldKind::TotpSeed => Some("totp"),
            FieldKind::AdapterKey => Some("adapter_key"),
        }
    }

    pub fn is_login(self) -> bool {
        self != FieldKind::Value
    }

    fn from_byte(b: u8) -> Result<Self, VaultError> {
        match b {
            0 => Ok(FieldKind::Value),
            1 => Ok(FieldKind::Username),
            2 => Ok(FieldKind::Password),
            3 => Ok(FieldKind::TotpSeed),
            4 => Ok(FieldKind::AdapterKey),
            _ => Err(VaultErrorKind::Corrupt.into()),
        }
    }
}

/// The parts of an item's record that schema version 2 added, and that no
/// [`ItemDetails`] edit sets: the vault keeps them itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ItemExtra {
    /// Unix seconds of the last change of the classification; `None` for
    /// an item a vault of schema version 1 held, which did not record it.
    pub classification_changed_at: Option<u64>,
    pub exposure: Option<Exposure>,
    pub rotate_recommended: bool,
    /// Present exactly on a login item.
    pub login: Option<LoginMeta>,
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
    /// [`FieldKind::Value`] but on a login item.
    pub kind: FieldKind,
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
    /// Unix seconds of the last change of `details.classification`,
    /// recorded by the vault on every change; `None` for an item a vault of
    /// schema version 1 held, which did not record it.
    pub classification_changed_at: Option<u64>,
    /// Set when the item's value was found outside the vault.
    pub exposure: Option<Exposure>,
    /// The value should be rotated (set with an exposure).
    pub rotate_recommended: bool,
    /// A login item's own metadata; `None` for every other class.
    pub login: Option<LoginMeta>,
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

// Record format versions: the first byte of each sealed record. A vault of
// schema version 1 holds version 1 of the item and field records, and one
// of schema version 2 or later holds version 2; the project record is
// version 1 in both. A later change to a record is a new version of that
// record, read beside the old one, not a schema migration (plan D-08).
const ITEM_RECORD_V1: u8 = 1;
const ITEM_RECORD_V2: u8 = 2;
const FIELD_RECORD_V1: u8 = 1;
const FIELD_RECORD_V2: u8 = 2;
const PROJECT_RECORD: u8 = 1;

/// The schema version from which item and field records are version 2.
pub(crate) const RECORDS_V2_FROM: u16 = 2;

/// The longest list of exposure sources a record holds: each source once.
const MAX_SOURCES: usize = ExposureSource::ALL.len();

/// The most bytes an item record holds after `notes`: the parts schema
/// version 2 added, which the vault keeps itself ([`ItemExtra`]): the
/// classification's last change (9), the exposure (1, then 8 + 8 + 4 and a
/// byte per source), the rotation flag (1) and a login's block (1, then 1 +
/// 8). They are bounded by their types and counted apart from
/// [`MAX_FIELD`], which bounds the rest, what the item's writer gives: so
/// neither the migration, which adds them to every record version 1 held,
/// nor a mark the vault makes later (a classification change, an exposure)
/// takes a record that was within the limit over it.
pub(crate) const MAX_ITEM_KEPT: usize = 9 + (1 + 8 + 8 + 4 + MAX_SOURCES) + 1 + (1 + 1 + 8);

/// The sealed plaintext of `items.sealed_meta`, version 2, and the one
/// check of its size, for every writer of one (a transaction and the
/// migration alike): the record up to `notes`, what version 1 held and what
/// the item's writer gives, is at most [`MAX_FIELD`] bytes, as version 1
/// counted it ([`VaultErrorKind::TooLarge`] beyond); the parts the vault
/// keeps add at most [`MAX_ITEM_KEPT`] after it.
pub(crate) fn encode_item(
    slug: &Slug,
    created_at: u64,
    d: &ItemDetails,
    extra: &ItemExtra,
) -> Result<Vec<u8>, VaultError> {
    let mut e = Enc::new();
    e.u8(ITEM_RECORD_V2);
    encode_item_body(&mut e, slug, created_at, d);
    let given = e.len();
    if given > MAX_FIELD {
        return Err(VaultErrorKind::TooLarge.into());
    }
    e.opt_u64(extra.classification_changed_at);
    match &extra.exposure {
        None => {
            e.u8(0);
        }
        Some(x) => {
            e.u8(1).u64(x.since).u64(x.count).count(x.sources.len());
            for src in &x.sources {
                e.u8(*src as u8);
            }
        }
    }
    e.bool(extra.rotate_recommended);
    match &extra.login {
        None => {
            e.u8(0);
        }
        Some(l) => {
            e.u8(1).u8(l.tier as u8).u64(l.session_lifetime);
        }
    }
    debug_assert!(e.len() - given <= MAX_ITEM_KEPT);
    Ok(e.finish())
}

/// A version 1 item record (schema version 1) of an item of `class` as
/// version 2: everything it holds kept, and what version 1 did not record
/// left empty (in particular the classification's last change, which is
/// not known). The migration's one way to rewrite one: through
/// [`encode_item`]'s check, so it writes no record a later write would
/// refuse. Every record version 1 held passes it, version 1's limit being
/// the same bytes.
pub(crate) fn upgrade_item_v1(b: &[u8], class: ItemClass) -> Result<Vec<u8>, VaultError> {
    let (slug, created_at, details, _) = decode_item(b, RECORDS_V2_FROM - 1, class)?;
    encode_item(&slug, created_at, &details, &ItemExtra::default())
}

/// The fields version 1 has, which version 2 keeps in the same order.
fn encode_item_body(e: &mut Enc, slug: &Slug, created_at: u64, d: &ItemDetails) {
    e.str(slug.as_str())
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
}

/// The sealed plaintext of `items.sealed_meta` as schema version 1 holds
/// it: what [`decode_item`] reads there. Unit tests only; the migration
/// tests read vaults the M1 build wrote (`tests/fixtures/m1-vault`).
#[cfg(test)]
pub(crate) fn encode_item_v1(slug: &Slug, created_at: u64, d: &ItemDetails) -> Vec<u8> {
    let mut e = Enc::new();
    e.u8(ITEM_RECORD_V1);
    encode_item_body(&mut e, slug, created_at, d);
    e.finish()
}

/// A decoded item record.
pub(crate) type ItemRecord = (Slug, u64, ItemDetails, ItemExtra);

/// Decodes an item record of an item of `class` in a vault of `schema`:
/// version 1 at schema version 1, version 2 from then on. Anything else is
/// [`VaultErrorKind::Corrupt`], and so is a login block on an item that is
/// not a login, or none on one that is.
pub(crate) fn decode_item(
    b: &[u8],
    schema: u16,
    class: ItemClass,
) -> Result<ItemRecord, VaultError> {
    let corrupt = || VaultError::from(VaultErrorKind::Corrupt);
    let mut d = Dec::new(b);
    let want = if schema >= RECORDS_V2_FROM {
        ITEM_RECORD_V2
    } else {
        ITEM_RECORD_V1
    };
    if d.u8()? != want {
        return Err(corrupt());
    }
    let slug = Slug::new(&d.string()?).map_err(|_| corrupt())?;
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
    let mut extra = ItemExtra::default();
    if want == ITEM_RECORD_V2 {
        extra.classification_changed_at = d.opt_u64()?;
        if d.bool()? {
            let since = d.u64()?;
            let count = d.u64()?;
            let n = d.count(1, MAX_SOURCES)?;
            let mut sources = Vec::with_capacity(n);
            for _ in 0..n {
                sources.push(ExposureSource::from_byte(d.u8()?)?);
            }
            // Sorted, each once, never empty: one form per set.
            if sources.is_empty() || sources.windows(2).any(|w| w[0] >= w[1]) {
                return Err(corrupt());
            }
            extra.exposure = Some(Exposure {
                since,
                sources,
                count,
            });
        }
        extra.rotate_recommended = d.bool()?;
        if d.bool()? {
            extra.login = Some(LoginMeta {
                tier: LoginTier::from_byte(d.u8()?)?,
                session_lifetime: d.u64()?,
            });
        }
    }
    d.end()?;
    if extra.login.is_some() != (class == ItemClass::Login) {
        return Err(corrupt());
    }
    Ok((slug, created_at, details, extra))
}

/// The field's metadata record, sealed into `fields.sealed_name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldRecord {
    pub name: FieldName,
    pub prior_count: u8,
    pub created_at: u64,
    pub updated_at: u64,
    pub kind: FieldKind,
}

/// The field record, version 2.
pub(crate) fn encode_field(r: &FieldRecord) -> Vec<u8> {
    let mut e = Enc::new();
    e.u8(FIELD_RECORD_V2)
        .str(r.name.as_str())
        .u8(r.prior_count)
        .u64(r.created_at)
        .u64(r.updated_at)
        .u8(r.kind as u8);
    e.finish()
}

/// A version 1 field record as version 2: every field of version 1 holds
/// a value. Its name is at most [`FieldName::MAX_LEN`] bytes, so the record
/// stays far under [`MAX_FIELD`], and its row under [`MAX_ROW`], with the
/// byte version 2 adds (`field_rows_stay_under_their_limits`).
pub(crate) fn upgrade_field_v1(b: &[u8]) -> Result<Vec<u8>, VaultError> {
    Ok(encode_field(&decode_field(b, RECORDS_V2_FROM - 1)?))
}

/// The field record as schema version 1 holds it (no kind). Unit tests
/// only, as [`encode_item_v1`].
#[cfg(test)]
pub(crate) fn encode_field_v1(r: &FieldRecord) -> Vec<u8> {
    let mut e = Enc::new();
    e.u8(FIELD_RECORD_V1)
        .str(r.name.as_str())
        .u8(r.prior_count)
        .u64(r.created_at)
        .u64(r.updated_at);
    e.finish()
}

/// Decodes a field record of a vault of `schema`: version 1 (every field a
/// [`FieldKind::Value`]) at schema version 1, version 2 from then on.
pub(crate) fn decode_field(b: &[u8], schema: u16) -> Result<FieldRecord, VaultError> {
    let mut d = Dec::new(b);
    let v2 = schema >= RECORDS_V2_FROM;
    let want = if v2 { FIELD_RECORD_V2 } else { FIELD_RECORD_V1 };
    if d.u8()? != want {
        return Err(VaultErrorKind::Corrupt.into());
    }
    let name =
        FieldName::new(&d.string()?).map_err(|_| VaultError::from(VaultErrorKind::Corrupt))?;
    let prior_count = d.u8()?;
    let created_at = d.u64()?;
    let updated_at = d.u64()?;
    let kind = if v2 {
        FieldKind::from_byte(d.u8()?)?
    } else {
        FieldKind::Value
    };
    d.end()?;
    if usize::from(prior_count) > MAX_PRIOR {
        return Err(VaultErrorKind::Corrupt.into());
    }
    // A login field is named for its kind.
    if kind.login_name().is_some_and(|n| n != name.as_str()) {
        return Err(VaultErrorKind::Corrupt.into());
    }
    Ok(FieldRecord {
        name,
        prior_count,
        created_at,
        updated_at,
        kind,
    })
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

    fn details() -> ItemDetails {
        ItemDetails {
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
        }
    }

    fn exposed() -> ItemExtra {
        ItemExtra {
            classification_changed_at: Some(11),
            exposure: Some(Exposure {
                since: 12,
                sources: vec![ExposureSource::Transcript, ExposureSource::EnvFile],
                count: 3,
            }),
            rotate_recommended: true,
            login: None,
        }
    }

    fn login_extra() -> ItemExtra {
        ItemExtra {
            login: Some(LoginMeta {
                tier: LoginTier::Dev,
                session_lifetime: 3600,
            }),
            ..ItemExtra::default()
        }
    }

    #[test]
    fn records_round_trip() {
        let details = details();
        let slug = Slug::new("openai/work").unwrap();
        for extra in [ItemExtra::default(), exposed()] {
            let bytes = encode_item(&slug, 42, &details, &extra).unwrap();
            for schema in [2, 3] {
                assert_eq!(
                    decode_item(&bytes, schema, ItemClass::Secret).unwrap(),
                    (slug.clone(), 42, details.clone(), extra.clone())
                );
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert_eq!(
                decode_item(&trailing, 2, ItemClass::Secret)
                    .unwrap_err()
                    .kind(),
                VaultErrorKind::Corrupt
            );
        }
        let bytes = encode_item(&slug, 42, &details, &login_extra()).unwrap();
        assert_eq!(
            decode_item(&bytes, 2, ItemClass::Login).unwrap().3,
            login_extra()
        );

        for kind in [FieldKind::Value, FieldKind::Password] {
            let f = FieldRecord {
                name: FieldName::new(kind.login_name().unwrap_or("api_key")).unwrap(),
                prior_count: if kind.is_login() { 0 } else { 2 },
                created_at: 1,
                updated_at: 2,
                kind,
            };
            assert_eq!(decode_field(&encode_field(&f), 2).unwrap(), f);
        }

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

    /// Schema version 1 holds version 1 of the item and field records, and
    /// a version 1 record reads with nothing version 2 added: no exposure,
    /// no flag, no recorded classification change. Each version is read
    /// only at its own schema versions. (The M1 build's own files are read
    /// in `tests/m1_format.rs`; these bytes come from this file's copy of
    /// the version 1 layout.)
    #[test]
    fn version_1_records_read_at_schema_1_only() {
        let details = details();
        let slug = Slug::new("openai/work").unwrap();
        let v1 = encode_item_v1(&slug, 42, &details);
        assert_eq!(
            decode_item(&v1, 1, ItemClass::Secret).unwrap(),
            (slug.clone(), 42, details.clone(), ItemExtra::default())
        );
        let v2 = encode_item(&slug, 42, &details, &ItemExtra::default()).unwrap();
        for (bytes, schema) in [(&v1, 2), (&v2, 1)] {
            assert_eq!(
                decode_item(bytes, schema, ItemClass::Secret)
                    .unwrap_err()
                    .kind(),
                VaultErrorKind::Corrupt
            );
        }
        let f = FieldRecord {
            name: FieldName::new("api_key").unwrap(),
            prior_count: 1,
            created_at: 1,
            updated_at: 2,
            kind: FieldKind::Value,
        };
        assert_eq!(decode_field(&encode_field_v1(&f), 1).unwrap(), f);
        assert!(decode_field(&encode_field_v1(&f), 2).is_err());
        assert!(decode_field(&encode_field(&f), 1).is_err());
    }

    /// The login block is there exactly on a login item; exposure sources
    /// are sorted, each once and never none; kinds and tiers are known;
    /// a login field is named for its kind. Anything else does not decode.
    #[test]
    fn version_2_records_keep_their_forms() {
        let slug = Slug::new("a/b").unwrap();
        let d = ItemDetails::default();
        let corrupt = |r: Result<ItemRecord, VaultError>| {
            assert_eq!(r.unwrap_err().kind(), VaultErrorKind::Corrupt);
        };
        corrupt(decode_item(
            &encode_item(&slug, 1, &d, &login_extra()).unwrap(),
            2,
            ItemClass::Secret,
        ));
        corrupt(decode_item(
            &encode_item(&slug, 1, &d, &ItemExtra::default()).unwrap(),
            2,
            ItemClass::Login,
        ));
        let with_sources = |sources: Vec<ExposureSource>| {
            encode_item(
                &slug,
                1,
                &d,
                &ItemExtra {
                    exposure: Some(Exposure {
                        since: 1,
                        sources,
                        count: 1,
                    }),
                    ..ItemExtra::default()
                },
            )
            .unwrap()
        };
        for bad in [
            vec![],
            vec![ExposureSource::EnvFile, ExposureSource::Transcript],
            vec![ExposureSource::GitHistory, ExposureSource::GitHistory],
        ] {
            corrupt(decode_item(&with_sources(bad), 2, ItemClass::Secret));
        }
        // An unknown source, tier or field kind: the byte that holds it
        // changed to one this build does not know.
        let mut b = with_sources(vec![ExposureSource::GitHistory]);
        let at = b
            .iter()
            .rposition(|x| *x == ExposureSource::GitHistory as u8)
            .unwrap();
        b[at] = 8;
        corrupt(decode_item(&b, 2, ItemClass::Secret));
        let mut b = encode_item(&slug, 1, &d, &login_extra()).unwrap();
        let at = b.len() - 9;
        assert_eq!(b[at], LoginTier::Dev as u8);
        b[at] = 4;
        corrupt(decode_item(&b, 2, ItemClass::Login));
        let f = FieldRecord {
            name: FieldName::new("password").unwrap(),
            prior_count: 0,
            created_at: 1,
            updated_at: 2,
            kind: FieldKind::Password,
        };
        let mut b = encode_field(&f);
        *b.last_mut().unwrap() = 5;
        assert!(decode_field(&b, 2).is_err());
        // A login field under another name.
        let renamed = FieldRecord {
            name: FieldName::new("username").unwrap(),
            ..f.clone()
        };
        assert!(decode_field(&encode_field(&renamed), 2).is_err());
        // Every cut short record fails, and none panics.
        for full in [
            encode_item(&slug, 1, &d, &exposed()).unwrap(),
            encode_item(&slug, 1, &d, &login_extra()).unwrap(),
        ] {
            for n in 0..full.len() {
                assert!(decode_item(&full[..n], 2, ItemClass::Secret).is_err());
                assert!(decode_item(&full[..n], 2, ItemClass::Login).is_err());
            }
        }
        let full = encode_field(&f);
        for n in 0..full.len() {
            assert!(decode_field(&full[..n], 2).is_err());
        }
    }

    /// Details whose record, as version 1 lays it out, is `size` bytes:
    /// the notes fill it.
    fn details_of_size(slug: &Slug, size: usize) -> ItemDetails {
        let d = details();
        let besides = encode_item_v1(slug, 42, &d).len() - d.notes.len();
        ItemDetails {
            notes: "n".repeat(size - besides),
            ..d
        }
    }

    /// The most the vault keeps after `notes`: every part present, every
    /// exposure source.
    fn most_kept() -> ItemExtra {
        ItemExtra {
            classification_changed_at: Some(11),
            exposure: Some(Exposure {
                since: 12,
                sources: ExposureSource::ALL.to_vec(),
                count: u64::MAX,
            }),
            rotate_recommended: true,
            login: Some(LoginMeta {
                tier: LoginTier::NeverAgent,
                session_lifetime: u64::MAX,
            }),
        }
    }

    /// What an item's writer gives is held to `MAX_FIELD` bytes as version
    /// 1 counted it, and what the vault keeps comes after it, at most
    /// `MAX_ITEM_KEPT` bytes: a record at the limit takes every part the
    /// vault adds (a migration's, a classification change's, an
    /// exposure's), and one byte more is refused whatever it carries.
    /// Mutations checked: the whole record held to `MAX_FIELD` (as
    /// `write_item` held it): the record at the limit is refused with any
    /// part kept, and this fails (and `m1_format`'s boundary test, whose
    /// migration then fails); no check in `encode_item`: the byte more is
    /// taken, and this fails.
    #[test]
    fn an_item_record_holds_max_field_of_what_it_is_given_and_what_the_vault_keeps() {
        let slug = Slug::new("openai/work").unwrap();
        let full = details_of_size(&slug, MAX_FIELD);
        assert_eq!(encode_item_v1(&slug, 42, &full).len(), MAX_FIELD);
        for (extra, class) in [
            (ItemExtra::default(), ItemClass::Secret),
            (exposed(), ItemClass::Card),
            (most_kept(), ItemClass::Login),
        ] {
            let b = encode_item(&slug, 42, &full, &extra).unwrap();
            assert!(b.len() > MAX_FIELD && b.len() - MAX_FIELD <= MAX_ITEM_KEPT);
            assert_eq!(
                decode_item(&b, 2, class).unwrap(),
                (slug.clone(), 42, full.clone(), extra)
            );
        }
        // The bound is the most the vault keeps.
        assert_eq!(
            encode_item(&slug, 42, &full, &most_kept()).unwrap().len(),
            MAX_FIELD + MAX_ITEM_KEPT
        );
        let over = details_of_size(&slug, MAX_FIELD + 1);
        for extra in [ItemExtra::default(), most_kept()] {
            assert_eq!(
                encode_item(&slug, 42, &over, &extra).unwrap_err().kind(),
                VaultErrorKind::TooLarge
            );
        }
    }

    /// The migration's rewrite of a version 1 item record keeps the record
    /// whole up to the largest version 1 stored, and the record it writes
    /// takes every later write of the same item; a record over that limit
    /// (which version 1 never stored) is refused, not written for later
    /// writes to refuse. Mutation checked: the rewrite encoding without
    /// `encode_item`'s check (as the migration did): the record over the
    /// limit is rewritten, and this fails.
    #[test]
    fn a_version_1_item_record_upgrades_whole_up_to_its_limit() {
        let slug = Slug::new("openai/work").unwrap();
        for size in [MAX_FIELD - 1, MAX_FIELD] {
            let full = details_of_size(&slug, size);
            let v1 = encode_item_v1(&slug, 42, &full);
            assert_eq!(v1.len(), size);
            for class in [ItemClass::Secret, ItemClass::Card] {
                let v2 = upgrade_item_v1(&v1, class).unwrap();
                assert_eq!(
                    decode_item(&v2, 2, class).unwrap(),
                    (slug.clone(), 42, full.clone(), ItemExtra::default())
                );
                // A later write of it, with what the vault adds.
                encode_item(&slug, 42, &full, &exposed()).unwrap();
            }
        }
        let over = encode_item_v1(&slug, 42, &details_of_size(&slug, MAX_FIELD + 1));
        assert_eq!(
            upgrade_item_v1(&over, ItemClass::Secret)
                .unwrap_err()
                .kind(),
            VaultErrorKind::TooLarge
        );
    }

    /// The byte a field record gains in the migration cannot take it, or
    /// its row, over a limit: the longest name makes a record of a few
    /// dozen bytes, and the largest row (that record, a value of
    /// `MAX_FIELD` bytes and `MAX_PRIOR` prior values of that size, each
    /// sealed) stays under `MAX_ROW`. `m1_format`'s boundary test writes
    /// such a row after the migration.
    #[test]
    fn field_rows_stay_under_their_limits() {
        let longest = FieldRecord {
            name: FieldName::new(&"a".repeat(FieldName::MAX_LEN)).unwrap(),
            prior_count: 3,
            created_at: u64::MAX,
            updated_at: u64::MAX,
            kind: FieldKind::Value,
        };
        let v1 = encode_field_v1(&longest);
        let v2 = upgrade_field_v1(&v1).unwrap();
        assert_eq!(v2.len(), v1.len() + 1);
        assert_eq!(decode_field(&v2, 2).unwrap(), longest);
        let sealed = |n: usize| n + crate::crypto::Sealed::OVERHEAD;
        let row = sealed(v2.len()) + sealed(MAX_FIELD) + sealed(2 + MAX_PRIOR * (4 + MAX_FIELD));
        assert!(v2.len() < 128 && row < MAX_ROW, "{row}");
    }
}
