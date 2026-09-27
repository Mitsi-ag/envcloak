//! The vault's in-memory state, and loading and verifying it at unlock.
//!
//! [`load`] reads every row, decrypts the metadata (item records, field
//! records, projects, policies) and never a value, checks each row's
//! plaintext columns against its sealed contents (`meta` and the header's
//! against the vault id, schema version and epoch it opened under), and
//! recomputes the state digest from the rows' stamps. Anything wrong is
//! recorded as a [`TamperKind`] and the vault opens read-only; rows that do
//! not open are left out.

use std::collections::BTreeMap;

use rusqlite::Connection;

use crate::crypto::{
    Aad, Envelope, FieldTag, ItemClass, Keyring, Purpose, SubKey, TableTag, UnlockerId, VaultId,
    keyed_hash,
};

use super::error::{VaultError, VaultErrorKind};
use super::integrity::{
    HeaderState, Integrity, RowKey, Stamp, TamperKind, digest_eq, field_body, item_body,
    policy_body, project_body, row_key, state_digest, unlocker_body,
};
use super::items::{
    FieldId, FieldMeta, FieldRecord, ItemDetails, ItemId, ItemMeta, PolicyId, ProjectId,
    ProjectRecord, Slug, decode_field, decode_item, decode_project,
};
use super::values::{CryptoOrRecord, open_record};

/// The keyed-hash domain of `items.slug_hash`.
pub(crate) const SLUG_DOMAIN: &str = "envcloak/v1/slug";
/// The keyed-hash domain of `projects.dir_hash`.
pub(crate) const PROJECT_DOMAIN: &str = "envcloak/v1/project";

/// What the associated data of every sealed value in one vault shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VaultCtx {
    pub vault_id: VaultId,
    pub schema_version: u16,
    pub epoch: u32,
}

impl VaultCtx {
    pub(crate) fn aad(
        &self,
        table: TableTag,
        row_id: &[u8; 16],
        field: FieldTag,
        item_class: ItemClass,
        row_version: u64,
    ) -> Aad {
        Aad {
            vault_id: self.vault_id,
            schema_version: self.schema_version,
            key_epoch: self.epoch,
            table,
            row_id: *row_id,
            field,
            item_class,
            row_version,
        }
    }

    /// The header's associated data: row id all zeros, row version 0.
    pub(crate) fn header_aad(&self) -> Aad {
        self.aad(
            TableTag::Header,
            &[0; 16],
            FieldTag::Header,
            ItemClass::None,
            0,
        )
    }
}

/// The class stored in `items.class`: 1 to 3.
pub(crate) fn item_class_from(v: i64) -> Option<ItemClass> {
    match v {
        1 => Some(ItemClass::Secret),
        2 => Some(ItemClass::Card),
        3 => Some(ItemClass::IssuerCredential),
        _ => None,
    }
}

/// The subkey an item's rows are sealed under: `card` for cards, `data`
/// for everything else.
pub(crate) fn item_key(keys: &Keyring, class: ItemClass) -> &SubKey {
    match class {
        ItemClass::Card => keys.key(Purpose::Card),
        _ => keys.key(Purpose::Data),
    }
}

pub(crate) fn slug_hash(keys: &Keyring, slug: &Slug) -> [u8; 32] {
    keyed_hash(
        keys.key(Purpose::Index),
        SLUG_DOMAIN,
        slug.as_str().as_bytes(),
    )
}

pub(crate) fn dir_hash(keys: &Keyring, key: &[u8]) -> [u8; 32] {
    keyed_hash(keys.key(Purpose::Index), PROJECT_DOMAIN, key)
}

#[derive(Debug, Clone)]
pub(crate) struct ItemRow {
    pub class: ItemClass,
    pub slug: Slug,
    pub details: ItemDetails,
    pub created_at: u64,
    pub updated_at: u64,
    pub row_version: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct FieldRow {
    pub item: ItemId,
    pub record: FieldRecord,
    pub row_version: u64,
    pub value_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub(crate) struct ProjectRow {
    pub record: ProjectRecord,
    pub row_version: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct PolicyRow {
    pub body: Vec<u8>,
    pub row_version: u64,
}

/// Everything the vault knows once unlocked, and the stamps its digest is
/// computed from.
#[derive(Debug, Clone, Default)]
pub(crate) struct State {
    pub header: HeaderState,
    pub items: BTreeMap<ItemId, ItemRow>,
    pub slugs: BTreeMap<Slug, ItemId>,
    pub fields: BTreeMap<FieldId, FieldRow>,
    pub projects: BTreeMap<ProjectId, ProjectRow>,
    pub project_keys: BTreeMap<[u8; 32], ProjectId>,
    pub policies: BTreeMap<PolicyId, PolicyRow>,
    pub unlockers: BTreeMap<UnlockerId, Envelope>,
    pub stamps: BTreeMap<RowKey, Stamp>,
}

impl State {
    /// The items, sorted by slug, each with its fields sorted by name.
    pub(crate) fn item_list(&self) -> Vec<ItemMeta> {
        let mut fields: BTreeMap<ItemId, Vec<FieldMeta>> = BTreeMap::new();
        for (id, f) in &self.fields {
            fields.entry(f.item).or_default().push(FieldMeta {
                id: *id,
                name: f.record.name.clone(),
                prior_count: f.record.prior_count,
                created_at: f.record.created_at,
                updated_at: f.record.updated_at,
            });
        }
        self.slugs
            .values()
            .filter_map(|id| {
                let row = self.items.get(id)?;
                let mut fs = fields.remove(id).unwrap_or_default();
                fs.sort_by(|a, b| a.name.cmp(&b.name));
                Some(ItemMeta {
                    id: *id,
                    class: row.class,
                    slug: row.slug.clone(),
                    details: row.details.clone(),
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                    fields: fs,
                })
            })
            .collect()
    }
}

/// The rows of each table as stored, before any check.
struct RawUnlocker {
    id: Vec<u8>,
    vault_id: Vec<u8>,
    kind: i64,
    envelope: Vec<u8>,
    created_at: i64,
}

struct RawItem {
    id: Vec<u8>,
    row_version: i64,
    class: i64,
    slug_hash: Vec<u8>,
    sealed_meta: Vec<u8>,
    updated_at: i64,
}

struct RawField {
    id: Vec<u8>,
    item_id: Vec<u8>,
    row_version: i64,
    sealed_name: Vec<u8>,
    sealed_value: Vec<u8>,
    value_hash: Vec<u8>,
    sealed_prior: Option<Vec<u8>>,
}

struct RawSealed {
    id: Vec<u8>,
    row_version: i64,
    /// `projects.dir_hash`; empty for policies.
    dir_hash: Vec<u8>,
    sealed: Vec<u8>,
}

struct Raw {
    unlockers: Vec<RawUnlocker>,
    items: Vec<RawItem>,
    fields: Vec<RawField>,
    projects: Vec<RawSealed>,
    policies: Vec<RawSealed>,
}

pub(crate) fn query<T>(
    conn: &Connection,
    sql: &str,
    f: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
) -> Result<Vec<T>, VaultError> {
    let mut st = conn.prepare(sql)?;
    let rows = st.query_map([], f)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

fn read_raw(conn: &Connection) -> Result<Raw, VaultError> {
    Ok(Raw {
        unlockers: query(
            conn,
            "SELECT id, vault_id, kind, envelope, created_at FROM unlockers",
            |r| {
                Ok(RawUnlocker {
                    id: r.get(0)?,
                    vault_id: r.get(1)?,
                    kind: r.get(2)?,
                    envelope: r.get(3)?,
                    created_at: r.get(4)?,
                })
            },
        )?,
        items: query(
            conn,
            "SELECT id, row_version, class, slug_hash, sealed_meta, updated_at FROM items",
            |r| {
                Ok(RawItem {
                    id: r.get(0)?,
                    row_version: r.get(1)?,
                    class: r.get(2)?,
                    slug_hash: r.get(3)?,
                    sealed_meta: r.get(4)?,
                    updated_at: r.get(5)?,
                })
            },
        )?,
        fields: query(
            conn,
            "SELECT id, item_id, row_version, sealed_name, sealed_value, value_hash, sealed_prior \
             FROM fields",
            |r| {
                Ok(RawField {
                    id: r.get(0)?,
                    item_id: r.get(1)?,
                    row_version: r.get(2)?,
                    sealed_name: r.get(3)?,
                    sealed_value: r.get(4)?,
                    value_hash: r.get(5)?,
                    sealed_prior: r.get(6)?,
                })
            },
        )?,
        projects: query(
            conn,
            "SELECT id, row_version, dir_hash, sealed FROM projects",
            |r| {
                Ok(RawSealed {
                    id: r.get(0)?,
                    row_version: r.get(1)?,
                    dir_hash: r.get(2)?,
                    sealed: r.get(3)?,
                })
            },
        )?,
        policies: query(conn, "SELECT id, row_version, sealed FROM policies", |r| {
            Ok(RawSealed {
                id: r.get(0)?,
                row_version: r.get(1)?,
                dir_hash: Vec::new(),
                sealed: r.get(2)?,
            })
        })?,
    })
}

fn id16(b: &[u8]) -> Option<[u8; 16]> {
    b.try_into().ok()
}

fn stamp(table: TableTag, id: &[u8], row_version: i64, body: [u8; 32]) -> Option<(RowKey, Stamp)> {
    let id = id16(id)?;
    let row_version = u64::try_from(row_version).ok()?;
    Some((row_key(table, &id), Stamp { row_version, body }))
}

impl RawUnlocker {
    fn stamp(&self) -> Option<(RowKey, Stamp)> {
        // Unlockers carry no row version; a changed envelope changes the
        // body.
        let body = unlocker_body(&self.vault_id, self.kind, self.created_at, &self.envelope);
        stamp(TableTag::Unlockers, &self.id, 0, body)
    }
}

impl RawItem {
    fn stamp(&self) -> Option<(RowKey, Stamp)> {
        let body = item_body(
            self.class,
            &self.slug_hash,
            self.updated_at,
            &self.sealed_meta,
        );
        stamp(TableTag::Items, &self.id, self.row_version, body)
    }
}

impl RawField {
    fn stamp(&self) -> Option<(RowKey, Stamp)> {
        let body = field_body(
            &self.item_id,
            &self.value_hash,
            &self.sealed_name,
            &self.sealed_value,
            self.sealed_prior.as_deref(),
        );
        stamp(TableTag::Fields, &self.id, self.row_version, body)
    }
}

impl RawSealed {
    fn stamp(&self, table: TableTag) -> Option<(RowKey, Stamp)> {
        let body = match table {
            TableTag::Projects => project_body(&self.dir_hash, &self.sealed),
            _ => policy_body(&self.sealed),
        };
        stamp(table, &self.id, self.row_version, body)
    }
}

/// Every row's stamp, read from the file without decrypting anything. For
/// a migration, which runs on a vault that has just passed [`load`].
pub(crate) fn scan_stamps(conn: &Connection) -> Result<BTreeMap<RowKey, Stamp>, VaultError> {
    let raw = read_raw(conn)?;
    let mut out = BTreeMap::new();
    let all = raw
        .unlockers
        .iter()
        .map(RawUnlocker::stamp)
        .chain(raw.items.iter().map(RawItem::stamp))
        .chain(raw.fields.iter().map(RawField::stamp))
        .chain(raw.projects.iter().map(|p| p.stamp(TableTag::Projects)))
        .chain(raw.policies.iter().map(|p| p.stamp(TableTag::Policies)));
    for s in all {
        let (k, v) = s.ok_or(VaultErrorKind::Damaged)?;
        out.insert(k, v);
    }
    Ok(out)
}

/// The result of [`load`].
#[derive(Debug)]
pub(crate) struct Loaded {
    pub state: State,
    pub integrity: Integrity,
}

/// The first tamper finding.
#[derive(Default)]
struct Findings(Option<TamperKind>);

impl Findings {
    fn note(&mut self, k: TamperKind) {
        self.0.get_or_insert(k);
    }
}

/// Records a row's stamp, or a finding when its id or version is malformed
/// (such a row cannot be in the digest, which then fails too).
fn note_stamp(st: &mut State, found: &mut Findings, s: Option<(RowKey, Stamp)>) {
    match s {
        Some((k, v)) => {
            st.stamps.insert(k, v);
        }
        None => found.note(TamperKind::RowInconsistent),
    }
}

/// Reads and verifies the vault. `schema_ok` is [`verify_schema`]'s
/// answer.
///
/// Fails with [`VaultErrorKind::KeyMismatch`] when the file holds something
/// sealed (a header row or a sealed row) and nothing of it opens under
/// `keys`. A file with nothing sealed at all, which is an empty vault whose
/// header was deleted, has nothing to check the key against: it opens
/// read-only and empty, reporting the header.
///
/// [`verify_schema`]: super::schema::verify_schema
pub(crate) fn load(
    conn: &Connection,
    keys: &Keyring,
    ctx: &VaultCtx,
    schema_ok: bool,
) -> Result<Loaded, VaultError> {
    let mut found = Findings::default();
    if !schema_ok {
        found.note(TamperKind::SchemaAltered);
    }

    // `meta` is one row naming the vault id and schema version everything
    // opened under.
    let metas = query(conn, "SELECT vault_id, schema_version FROM meta", |r| {
        Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?))
    })?;
    match metas.as_slice() {
        [(id, version)]
            if id[..] == ctx.vault_id.0[..] && *version == i64::from(ctx.schema_version) => {}
        _ => found.note(TamperKind::MetaAltered),
    }

    // Every header row is tried, whatever its plaintext columns say, so a
    // doubled header or an altered epoch still proves the key.
    let headers = query(
        conn,
        "SELECT epoch, vault_id, schema_version, sealed FROM header",
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        },
    )?;
    let mut opened_headers = Vec::new();
    for (epoch, vault_id, version, sealed) in &headers {
        let opened = open_record(
            keys.key(Purpose::Header),
            &ctx.header_aad(),
            sealed,
            HeaderState::decode,
        );
        if let Ok(h) = opened {
            let consistent = *epoch == i64::from(ctx.epoch)
                && vault_id[..] == ctx.vault_id.0[..]
                && *version == i64::from(ctx.schema_version);
            opened_headers.push((h, consistent));
        }
    }
    let mut opened_any = !opened_headers.is_empty();
    let header = match (headers.len(), opened_headers.as_slice()) {
        (1, [(h, consistent)]) => {
            if !consistent {
                found.note(TamperKind::RowInconsistent);
            }
            Some(*h)
        }
        _ => None,
    };

    let raw = read_raw(conn)?;
    let sealed_present = !headers.is_empty()
        || !raw.items.is_empty()
        || !raw.fields.is_empty()
        || !raw.projects.is_empty()
        || !raw.policies.is_empty();
    let mut st = State {
        header: header.unwrap_or_default(),
        ..State::default()
    };
    let mut names = std::collections::BTreeSet::new();

    for u in &raw.unlockers {
        note_stamp(&mut st, &mut found, u.stamp());
        let env = Envelope::from_bytes(&u.envelope).ok().filter(|e| {
            Some(e.unlocker_id().0) == id16(&u.id)
                && u.vault_id[..] == ctx.vault_id.0[..]
                && i64::from(e.kind() as u8) == u.kind
                && e.epoch() == ctx.epoch
        });
        match env {
            Some(envelope) => {
                st.unlockers.insert(envelope.unlocker_id(), envelope);
            }
            None => found.note(TamperKind::RowInconsistent),
        }
    }

    for it in &raw.items {
        note_stamp(&mut st, &mut found, it.stamp());
        let (Some(id), Some(class), Ok(rv), Ok(updated_at)) = (
            id16(&it.id),
            item_class_from(it.class),
            u64::try_from(it.row_version),
            u64::try_from(it.updated_at),
        ) else {
            found.note(TamperKind::RowInconsistent);
            continue;
        };
        let aad = ctx.aad(TableTag::Items, &id, FieldTag::ItemMeta, class, rv);
        let (slug, created_at, details) =
            match open_record(item_key(keys, class), &aad, &it.sealed_meta, decode_item) {
                Ok(v) => v,
                Err(e) => {
                    found.note(unreadable(&e));
                    continue;
                }
            };
        opened_any = true;
        if slug_hash(keys, &slug)[..] != it.slug_hash[..] || st.slugs.contains_key(&slug) {
            found.note(TamperKind::RowInconsistent);
            continue;
        }
        let id = ItemId::from_bytes(id);
        st.slugs.insert(slug.clone(), id);
        st.items.insert(
            id,
            ItemRow {
                class,
                slug,
                details,
                created_at,
                updated_at,
                row_version: rv,
            },
        );
    }

    for f in &raw.fields {
        note_stamp(&mut st, &mut found, f.stamp());
        let item = id16(&f.item_id).map(ItemId::from_bytes);
        let class = item.and_then(|i| st.items.get(&i)).map(|r| r.class);
        let (Some(id), Some(item), Some(class), Ok(rv), Ok(value_hash)) = (
            id16(&f.id),
            item,
            class,
            u64::try_from(f.row_version),
            <[u8; 32]>::try_from(f.value_hash.as_slice()),
        ) else {
            found.note(TamperKind::RowInconsistent);
            continue;
        };
        let aad = ctx.aad(TableTag::Fields, &id, FieldTag::FieldName, class, rv);
        let record = match open_record(item_key(keys, class), &aad, &f.sealed_name, decode_field) {
            Ok(r) => r,
            Err(e) => {
                found.note(unreadable(&e));
                continue;
            }
        };
        opened_any = true;
        let clash = !names.insert((item, record.name.clone()));
        if clash || (record.prior_count == 0) != f.sealed_prior.is_none() {
            found.note(TamperKind::RowInconsistent);
            continue;
        }
        st.fields.insert(
            FieldId::from_bytes(id),
            FieldRow {
                item,
                record,
                row_version: rv,
                value_hash,
            },
        );
    }

    let data = keys.key(Purpose::Data);
    for p in &raw.projects {
        note_stamp(&mut st, &mut found, p.stamp(TableTag::Projects));
        let (Some(id), Ok(rv)) = (id16(&p.id), u64::try_from(p.row_version)) else {
            found.note(TamperKind::RowInconsistent);
            continue;
        };
        let aad = ctx.aad(
            TableTag::Projects,
            &id,
            FieldTag::Project,
            ItemClass::None,
            rv,
        );
        let record = match open_record(data, &aad, &p.sealed, decode_project) {
            Ok(r) => r,
            Err(e) => {
                found.note(unreadable(&e));
                continue;
            }
        };
        opened_any = true;
        let h = dir_hash(keys, record.key.as_bytes());
        if h[..] != p.dir_hash[..] || st.project_keys.contains_key(&h) {
            found.note(TamperKind::RowInconsistent);
            continue;
        }
        let id = ProjectId::from_bytes(id);
        st.project_keys.insert(h, id);
        st.projects.insert(
            id,
            ProjectRow {
                record,
                row_version: rv,
            },
        );
    }

    for p in &raw.policies {
        note_stamp(&mut st, &mut found, p.stamp(TableTag::Policies));
        let (Some(id), Ok(rv)) = (id16(&p.id), u64::try_from(p.row_version)) else {
            found.note(TamperKind::RowInconsistent);
            continue;
        };
        let aad = ctx.aad(
            TableTag::Policies,
            &id,
            FieldTag::Policy,
            ItemClass::None,
            rv,
        );
        match open_record(data, &aad, &p.sealed, |b| Ok(b.to_vec())) {
            Ok(body) => {
                opened_any = true;
                st.policies.insert(
                    PolicyId::from_bytes(id),
                    PolicyRow {
                        body,
                        row_version: rv,
                    },
                );
            }
            Err(e) => found.note(unreadable(&e)),
        }
    }

    let integrity = if header.is_none() {
        if sealed_present && !opened_any {
            return Err(VaultErrorKind::KeyMismatch.into());
        }
        Integrity::Tampered(TamperKind::HeaderUnreadable)
    } else {
        if !digest_eq(&state_digest(keys, &st.stamps), &st.header.state_digest) {
            found.note(TamperKind::DigestMismatch);
        }
        match found.0 {
            None => Integrity::Ok,
            Some(k) => Integrity::Tampered(k),
        }
    };
    Ok(Loaded {
        state: st,
        integrity,
    })
}

fn unreadable(e: &CryptoOrRecord) -> TamperKind {
    match e {
        CryptoOrRecord::Crypto => TamperKind::RowUnreadable,
        CryptoOrRecord::Record => TamperKind::RowInconsistent,
    }
}
