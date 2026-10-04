//! Write transactions (SPEC §5 "Vault" and "Integrity").
//!
//! [`Vault::transact`](super::Vault::transact) runs a closure against a
//! [`Txn`] inside one `BEGIN IMMEDIATE` SQLite transaction. Every write
//! seals its columns before they are bound, bumps the row version the
//! associated data carries, and records the row's new stamp. At commit the
//! state digest is recomputed from the stamps, the write counter goes up,
//! and the sealed header is rewritten in the same transaction, so the rows
//! and the header that vouches for them are committed together or not at
//! all. The closure works on a copy of the vault's state, which replaces
//! the vault's own only after the commit succeeds; an error or a panic
//! rolls both back.

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::crypto::{Envelope, FieldTag, ItemClass, Keyring, Purpose, TableTag, UnlockerId};
use crate::secret::SecretBytes;

use super::error::{VaultError, VaultErrorKind};
use super::integrity::{
    AuditHead, Stamp, field_body, item_body, policy_body, project_body, row_key, state_digest,
    unlocker_body,
};
use super::items::{
    Exposure, ExposureSource, FieldId, FieldKind, FieldName, FieldRecord, ItemDetails, ItemExtra,
    ItemId, MAX_FIELD, MAX_PRIOR, MAX_ROW, NewItem, PolicyId, ProjectId, ProjectKey, ProjectRecord,
    Slug, encode_field, encode_item, encode_project,
};
use super::login::{LoginFieldValue, NewLogin};
use super::policies::{PolicyRecord, StandingSetHeader};
use super::schema::drop_page_cache;
use super::state::{
    FieldRow, ItemRow, PolicyRow, ProjectRow, State, VaultCtx, dir_hash, item_key, slug_hash,
};
use super::values::{
    check_value, login_value_hash, open_priors, open_value, pack_totp, seal_priors, seal_record,
    seal_value, tampered, value_hash,
};

/// A write transaction on an unlocked vault. See [`Vault::transact`].
///
/// [`Vault::transact`]: super::Vault::transact
pub struct Txn<'v> {
    tx: Transaction<'v>,
    keys: &'v Keyring,
    ctx: VaultCtx,
    state: State,
    dirty: bool,
    /// A standing approval was added, changed or removed: the commit moves
    /// the standing set's generation and recomputes its digest.
    standing_changed: bool,
    now: u64,
}

impl core::fmt::Debug for Txn<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Txn")
            .field("dirty", &self.dirty)
            .finish_non_exhaustive()
    }
}

pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn to_i64(v: u64) -> Result<i64, VaultError> {
    i64::try_from(v).map_err(|_| VaultErrorKind::InvalidRecord.into())
}

/// The row a write expected is not there: the file changed behind this
/// process's back.
fn changed_on_disk() -> VaultError {
    VaultErrorKind::Tampered.into()
}

fn one_row(n: usize) -> Result<(), VaultError> {
    if n == 1 {
        Ok(())
    } else {
        Err(changed_on_disk())
    }
}

impl<'v> Txn<'v> {
    /// Starts the transaction on the file as it is now: a page cached
    /// before another program changed the file must not be written back
    /// over the change (see [`drop_page_cache`]). Every time it records is
    /// `now` (Unix seconds).
    pub(crate) fn begin(
        conn: &'v mut Connection,
        keys: &'v Keyring,
        ctx: VaultCtx,
        state: State,
        now: u64,
    ) -> Result<Self, VaultError> {
        drop_page_cache(conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Ok(Txn {
            tx,
            keys,
            ctx,
            state,
            dirty: false,
            standing_changed: false,
            now,
        })
    }

    /// Writes the header and commits. Returns the state to install.
    pub(crate) fn commit(self) -> Result<State, VaultError> {
        let Txn {
            tx,
            keys,
            ctx,
            mut state,
            dirty,
            standing_changed,
            ..
        } = self;
        if dirty {
            let mut header = state.header;
            if standing_changed {
                header.standing_set = StandingSetHeader {
                    generation: header
                        .standing_set
                        .generation
                        .checked_add(1)
                        .ok_or(VaultErrorKind::Corrupt)?,
                    set_digest: state.standing_set_digest(keys),
                };
            }
            header.write_counter = header
                .write_counter
                .checked_add(1)
                .ok_or(VaultErrorKind::Corrupt)?;
            header.state_digest = state_digest(keys, &state.stamps);
            let sealed = seal_record(
                keys.key(Purpose::Header),
                &ctx.header_aad(),
                &header.encode(),
            )?;
            let n = tx.execute(
                "UPDATE header SET sealed = ?1 WHERE epoch = ?2",
                params![sealed, ctx.epoch],
            )?;
            one_row(n)?;
            state.header = header;
        }
        tx.commit()?;
        Ok(state)
    }

    /// The id of the item named `slug`, including items created in this
    /// transaction.
    pub fn item_id(&self, slug: &Slug) -> Option<ItemId> {
        self.state.slugs.get(slug).copied()
    }

    /// The id of `item`'s field named `name`.
    pub fn field_id(&self, item: ItemId, name: &FieldName) -> Option<FieldId> {
        self.state
            .fields
            .iter()
            .find(|(_, f)| f.item == item && &f.record.name == name)
            .map(|(id, _)| *id)
    }

    /// Creates an item with no fields. A login is made with
    /// [`Txn::create_login`] instead ([`VaultErrorKind::LoginField`]).
    pub fn create_item(&mut self, n: NewItem) -> Result<ItemId, VaultError> {
        match n.class {
            ItemClass::None => return Err(VaultErrorKind::InvalidRecord.into()),
            ItemClass::Login => return Err(VaultErrorKind::LoginField.into()),
            ItemClass::Secret | ItemClass::Card | ItemClass::IssuerCredential => {}
        }
        self.new_item(n.class, n.slug, n.details, None)
    }

    fn new_item(
        &mut self,
        class: ItemClass,
        slug: Slug,
        details: ItemDetails,
        login: Option<super::items::LoginMeta>,
    ) -> Result<ItemId, VaultError> {
        if self.state.slugs.contains_key(&slug) {
            return Err(VaultErrorKind::DuplicateSlug.into());
        }
        let id = loop {
            let id = ItemId::generate();
            if !self.state.items.contains_key(&id) {
                break id;
            }
        };
        let row = ItemRow {
            class,
            slug,
            details,
            extra: ItemExtra {
                // Set at creation: its first value.
                classification_changed_at: Some(self.now),
                login,
                ..ItemExtra::default()
            },
            created_at: self.now,
            updated_at: self.now,
            row_version: 1,
        };
        self.write_item(id, row, None)?;
        Ok(id)
    }

    /// Replaces an item's details. A change of the classification records
    /// when it happened ([`ItemMeta::classification_changed_at`]).
    ///
    /// [`ItemMeta::classification_changed_at`]: super::ItemMeta::classification_changed_at
    pub fn update_item(&mut self, id: ItemId, details: ItemDetails) -> Result<(), VaultError> {
        let old = self.item_row(id)?;
        let mut extra = old.extra.clone();
        if details.classification != old.details.classification {
            extra.classification_changed_at = Some(self.now);
        }
        let row = ItemRow {
            details,
            extra,
            updated_at: self.now,
            row_version: old.row_version + 1,
            ..old.clone()
        };
        self.write_item(id, row, Some(&old))
    }

    /// Marks an item "exposed: rotate" (R-M2-40): its value was found in
    /// `count` places of the kinds in `sources` (at least one). Only adds:
    /// the kinds are joined and the counts summed; rotation is then
    /// recommended. The mark's time ([`Exposure::since`]) stands for the
    /// values it covers, those set at or before it: it is the first
    /// mark's, and it stays while the item holds no value set after it. A
    /// mark made when the item holds one (a field replaced since, whose new
    /// value may be the one found now) restarts it now, so the mark covers
    /// every value the item holds again ([`ItemMeta::exposure_covers`]).
    ///
    /// [`ItemMeta::exposure_covers`]: super::ItemMeta::exposure_covers
    pub fn mark_exposed(
        &mut self,
        item: ItemId,
        sources: &[ExposureSource],
        count: u64,
    ) -> Result<(), VaultError> {
        if sources.is_empty() {
            return Err(VaultErrorKind::InvalidRecord.into());
        }
        let old = self.item_row(item)?;
        let fresh = Exposure {
            since: self.now,
            sources: Vec::new(),
            count: 0,
        };
        let mut exposure = match old.extra.exposure.clone() {
            None => fresh,
            Some(x) => {
                let newer = self
                    .state
                    .fields
                    .values()
                    .any(|f| f.item == item && f.record.updated_at > x.since);
                if newer {
                    Exposure {
                        since: self.now,
                        ..x
                    }
                } else {
                    x
                }
            }
        };
        exposure.sources.extend_from_slice(sources);
        exposure.sources.sort_unstable();
        exposure.sources.dedup();
        exposure.count = exposure.count.saturating_add(count);
        let row = ItemRow {
            extra: ItemExtra {
                exposure: Some(exposure),
                rotate_recommended: true,
                ..old.extra.clone()
            },
            updated_at: self.now,
            row_version: old.row_version + 1,
            ..old.clone()
        };
        self.write_item(item, row, Some(&old))
    }

    /// Clears an item's exposure and its rotation flag: its exposed value
    /// was replaced (M2-11: a rotation that leaves no value the mark covers,
    /// [`ItemMeta::exposure_replaced_but`]).
    ///
    /// [`ItemMeta::exposure_replaced_but`]: super::ItemMeta::exposure_replaced_but
    pub fn clear_exposure(&mut self, item: ItemId) -> Result<(), VaultError> {
        let old = self.item_row(item)?;
        if old.extra.exposure.is_none() && !old.extra.rotate_recommended {
            return Ok(());
        }
        let row = ItemRow {
            extra: ItemExtra {
                exposure: None,
                rotate_recommended: false,
                ..old.extra.clone()
            },
            updated_at: self.now,
            row_version: old.row_version + 1,
            ..old.clone()
        };
        self.write_item(item, row, Some(&old))
    }

    /// Gives an item a new slug.
    pub fn rename_item(&mut self, id: ItemId, slug: Slug) -> Result<(), VaultError> {
        let old = self.item_row(id)?;
        if old.slug == slug {
            return Ok(());
        }
        if self.state.slugs.contains_key(&slug) {
            return Err(VaultErrorKind::DuplicateSlug.into());
        }
        let row = ItemRow {
            slug,
            updated_at: self.now,
            row_version: old.row_version + 1,
            ..old.clone()
        };
        self.write_item(id, row, Some(&old))
    }

    fn item_row(&self, id: ItemId) -> Result<ItemRow, VaultError> {
        self.state
            .items
            .get(&id)
            .cloned()
            .ok_or_else(|| VaultErrorKind::UnknownItem.into())
    }

    fn write_item(
        &mut self,
        id: ItemId,
        row: ItemRow,
        old: Option<&ItemRow>,
    ) -> Result<(), VaultError> {
        // Its size checked there (what the writer gives at most MAX_FIELD,
        // what the vault keeps after it), as the migration's records are.
        let record = encode_item(&row.slug, row.created_at, &row.details, &row.extra)?;
        let aad = self.ctx.aad(
            TableTag::Items,
            id.as_bytes(),
            FieldTag::ItemMeta,
            row.class,
            row.row_version,
        );
        let sealed = seal_record(item_key(self.keys, row.class), &aad, &record)?;
        let hash = slug_hash(self.keys, &row.slug);
        let class = i64::from(row.class as u16);
        let updated_at = to_i64(row.updated_at)?;
        let rv = to_i64(row.row_version)?;
        let n = match old {
            None => self.tx.execute(
                "INSERT INTO items (id, row_version, class, slug_hash, sealed_meta, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![&id.as_bytes()[..], rv, class, &hash[..], sealed, updated_at],
            )?,
            Some(old) => self.tx.execute(
                "UPDATE items SET row_version = ?1, slug_hash = ?2, sealed_meta = ?3, \
                 updated_at = ?4 WHERE id = ?5 AND row_version = ?6",
                params![
                    rv,
                    &hash[..],
                    sealed,
                    updated_at,
                    &id.as_bytes()[..],
                    to_i64(old.row_version)?
                ],
            )?,
        };
        one_row(n)?;
        let body = item_body(class, &hash, updated_at, &sealed);
        self.stamp(TableTag::Items, id.as_bytes(), row.row_version, body);
        if let Some(old) = old {
            self.state.slugs.remove(&old.slug);
        }
        self.state.slugs.insert(row.slug.clone(), id);
        self.state.items.insert(id, row);
        Ok(())
    }

    /// Adds a field holding `value` to an item. A login's fields are
    /// typed: refused here ([`VaultErrorKind::LoginField`]).
    pub fn add_field(
        &mut self,
        item: ItemId,
        name: FieldName,
        value: SecretBytes,
    ) -> Result<FieldId, VaultError> {
        check_value(&value)?;
        let class = self.item_row(item)?.class;
        if class == ItemClass::Login {
            return Err(VaultErrorKind::LoginField.into());
        }
        if self.field_id(item, &name).is_some() {
            return Err(VaultErrorKind::DuplicateField.into());
        }
        let id = self.new_field_id();
        let row = FieldRow {
            item,
            record: FieldRecord {
                name,
                prior_count: 0,
                created_at: self.now,
                updated_at: self.now,
                kind: FieldKind::Value,
            },
            row_version: 1,
            value_hash: value_hash(self.keys.key(Purpose::Index), &value),
        };
        self.write_field(id, row, class, &value, &[], None)?;
        Ok(id)
    }

    fn new_field_id(&self) -> FieldId {
        loop {
            let id = FieldId::generate();
            if !self.state.fields.contains_key(&id) {
                break id;
            }
        }
    }

    /// Creates a login item with its typed fields (SPEC §6.8): a username
    /// and a password, and a TOTP enrollment and an adapter key when given,
    /// each named for its kind and sealed with the `login` class.
    pub fn create_login(&mut self, n: NewLogin) -> Result<ItemId, VaultError> {
        let NewLogin {
            slug,
            details,
            meta,
            username,
            password,
            totp,
            adapter_key,
        } = n;
        let mut values = vec![
            LoginFieldValue::Username(username),
            LoginFieldValue::Password(password),
        ];
        values.extend(totp.map(LoginFieldValue::Totp));
        values.extend(adapter_key.map(LoginFieldValue::AdapterKey));
        // Every value is checked before anything is written.
        let packed = values
            .into_iter()
            .map(|v| Ok((v.kind(), login_value(v)?)))
            .collect::<Result<Vec<_>, VaultError>>()?;
        let item = self.new_item(ItemClass::Login, slug, details, Some(meta))?;
        for (kind, value) in packed {
            self.write_login_field(item, kind, &value)?;
        }
        Ok(item)
    }

    /// Replaces one field of login `item`, or adds its TOTP enrollment or
    /// adapter key when it has none. The old value is not kept: a login
    /// keeps no prior values. The login's row moves too, so a sign-in
    /// attempt's lease issued before it opens nothing (`LeaseStale`).
    pub fn replace_login_field(
        &mut self,
        item: ItemId,
        value: LoginFieldValue,
    ) -> Result<FieldId, VaultError> {
        let old = self.item_row(item)?;
        if old.class != ItemClass::Login {
            return Err(VaultErrorKind::LoginField.into());
        }
        let kind = value.kind();
        let value = login_value(value)?;
        let field = self.write_login_field(item, kind, &value)?;
        let row = ItemRow {
            updated_at: self.now,
            row_version: old.row_version + 1,
            ..old.clone()
        };
        self.write_item(item, row, Some(&old))?;
        Ok(field)
    }

    /// Writes the `kind` field of login `item`: a new row, or the next
    /// version of the one it has.
    fn write_login_field(
        &mut self,
        item: ItemId,
        kind: FieldKind,
        value: &SecretBytes,
    ) -> Result<FieldId, VaultError> {
        let name = FieldName::new(kind.login_name().ok_or(VaultErrorKind::LoginField)?)?;
        let hash = login_value_hash(self.keys.key(Purpose::Index), value);
        let existing = self
            .state
            .fields
            .iter()
            .find(|(_, f)| f.item == item && f.record.kind == kind)
            .map(|(id, f)| (*id, f.clone()));
        let (id, row, old_version) = match existing {
            None => (
                self.new_field_id(),
                FieldRow {
                    item,
                    record: FieldRecord {
                        name,
                        prior_count: 0,
                        created_at: self.now,
                        updated_at: self.now,
                        kind,
                    },
                    row_version: 1,
                    value_hash: hash,
                },
                None,
            ),
            Some((id, old)) => (
                id,
                FieldRow {
                    record: FieldRecord {
                        updated_at: self.now,
                        ..old.record.clone()
                    },
                    row_version: old.row_version + 1,
                    value_hash: hash,
                    ..old.clone()
                },
                Some(old.row_version),
            ),
        };
        self.write_field(id, row, ItemClass::Login, value, &[], old_version)?;
        Ok(id)
    }

    /// Replaces a field's value. The old value becomes the newest prior
    /// value; at most [`MAX_PRIOR`] are kept. A login's field is replaced
    /// with [`Txn::replace_login_field`] instead
    /// ([`VaultErrorKind::LoginField`]).
    pub fn set_value(&mut self, field: FieldId, value: SecretBytes) -> Result<(), VaultError> {
        check_value(&value)?;
        let old = self
            .state
            .fields
            .get(&field)
            .cloned()
            .ok_or(VaultErrorKind::UnknownField)?;
        let class = self.item_row(old.item)?.class;
        if class == ItemClass::Login {
            return Err(VaultErrorKind::LoginField.into());
        }
        let k = item_key(self.keys, class);
        let a = |f| {
            self.ctx.aad(
                TableTag::Fields,
                field.as_bytes(),
                f,
                class,
                old.row_version,
            )
        };
        let stored: Option<(Vec<u8>, Option<Vec<u8>>)> = self
            .tx
            .query_row(
                "SELECT sealed_value, sealed_prior FROM fields WHERE id = ?1 AND row_version = ?2",
                params![&field.as_bytes()[..], to_i64(old.row_version)?],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (sealed_value, sealed_prior) = stored.ok_or_else(changed_on_disk)?;
        let previous = open_value(k, &a(FieldTag::FieldValue), &sealed_value).map_err(tampered)?;
        // The history carried forward must be the one the record counts: a
        // list removed on disk is refused, not sealed into the new row.
        let older = open_priors(
            k,
            &a(FieldTag::FieldPrior),
            sealed_prior.as_deref(),
            old.record.prior_count,
        )
        .map_err(|_| changed_on_disk())?;
        let mut priors = Vec::with_capacity(MAX_PRIOR + 1);
        priors.push(previous);
        priors.extend(older);
        priors.truncate(MAX_PRIOR);
        let row = FieldRow {
            item: old.item,
            record: FieldRecord {
                prior_count: u8::try_from(priors.len()).map_err(|_| VaultErrorKind::Corrupt)?,
                updated_at: self.now,
                ..old.record.clone()
            },
            row_version: old.row_version + 1,
            value_hash: value_hash(self.keys.key(Purpose::Index), &value),
        };
        self.write_field(field, row, class, &value, &priors, Some(old.row_version))
    }

    fn write_field(
        &mut self,
        id: FieldId,
        row: FieldRow,
        class: ItemClass,
        value: &SecretBytes,
        priors: &[SecretBytes],
        old_version: Option<u64>,
    ) -> Result<(), VaultError> {
        let k = item_key(self.keys, class);
        let a = |f| {
            self.ctx
                .aad(TableTag::Fields, id.as_bytes(), f, class, row.row_version)
        };
        let name = seal_record(k, &a(FieldTag::FieldName), &encode_field(&row.record))?;
        let sealed_value = seal_value(k, &a(FieldTag::FieldValue), value)?;
        let sealed_prior = seal_priors(k, &a(FieldTag::FieldPrior), priors)?;
        let size = name.len() + sealed_value.len() + sealed_prior.as_ref().map_or(0, Vec::len);
        if size > MAX_ROW {
            return Err(VaultErrorKind::TooLarge.into());
        }
        let rv = to_i64(row.row_version)?;
        let item_id = &row.item.as_bytes()[..];
        let n = match old_version {
            None => self.tx.execute(
                "INSERT INTO fields (id, item_id, row_version, sealed_name, sealed_value, \
                 value_hash, sealed_prior) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    &id.as_bytes()[..],
                    item_id,
                    rv,
                    name,
                    sealed_value,
                    &row.value_hash[..],
                    sealed_prior
                ],
            )?,
            Some(old) => self.tx.execute(
                "UPDATE fields SET row_version = ?1, sealed_name = ?2, sealed_value = ?3, \
                 value_hash = ?4, sealed_prior = ?5 WHERE id = ?6 AND row_version = ?7",
                params![
                    rv,
                    name,
                    sealed_value,
                    &row.value_hash[..],
                    sealed_prior,
                    &id.as_bytes()[..],
                    to_i64(old)?
                ],
            )?,
        };
        one_row(n)?;
        let body = field_body(
            item_id,
            &row.value_hash,
            &name,
            &sealed_value,
            sealed_prior.as_deref(),
        );
        self.stamp(TableTag::Fields, id.as_bytes(), row.row_version, body);
        self.state.fields.insert(id, row);
        Ok(())
    }

    /// Deletes an item and every field it has, values and prior values
    /// included. `secure_delete` overwrites the freed pages.
    pub fn delete_item(&mut self, item: ItemId) -> Result<(), VaultError> {
        let row = self.item_row(item)?;
        let fields: Vec<(FieldId, u64)> = self
            .state
            .fields
            .iter()
            .filter(|(_, f)| f.item == item)
            .map(|(id, f)| (*id, f.row_version))
            .collect();
        for (id, rv) in fields {
            let n = self.tx.execute(
                "DELETE FROM fields WHERE id = ?1 AND row_version = ?2",
                params![&id.as_bytes()[..], to_i64(rv)?],
            )?;
            one_row(n)?;
            self.state.fields.remove(&id);
            self.unstamp(TableTag::Fields, id.as_bytes());
        }
        let n = self.tx.execute(
            "DELETE FROM items WHERE id = ?1 AND row_version = ?2",
            params![&item.as_bytes()[..], to_i64(row.row_version)?],
        )?;
        one_row(n)?;
        self.state.items.remove(&item);
        self.state.slugs.remove(&row.slug);
        self.unstamp(TableTag::Items, item.as_bytes());
        Ok(())
    }

    /// Adds or replaces the record for `p.key`'s project.
    pub fn upsert_project(&mut self, p: ProjectRecord) -> Result<ProjectId, VaultError> {
        let record = encode_project(&p);
        if record.len() > MAX_FIELD {
            return Err(VaultErrorKind::TooLarge.into());
        }
        let hash = dir_hash(self.keys, p.key.as_bytes());
        let existing = self
            .state
            .project_keys
            .get(&hash)
            .and_then(|id| self.state.projects.get(id).map(|r| (*id, r.row_version)));
        let (id, rv) = match existing {
            Some((id, rv)) => (id, rv + 1),
            None => (ProjectId::generate(), 1),
        };
        let aad = self.ctx.aad(
            TableTag::Projects,
            id.as_bytes(),
            FieldTag::Project,
            ItemClass::None,
            rv,
        );
        let sealed = seal_record(self.keys.key(Purpose::Data), &aad, &record)?;
        let n = match existing {
            None => self.tx.execute(
                "INSERT INTO projects (id, row_version, dir_hash, sealed) VALUES (?1, ?2, ?3, ?4)",
                params![&id.as_bytes()[..], to_i64(rv)?, &hash[..], sealed],
            )?,
            Some((_, old)) => self.tx.execute(
                "UPDATE projects SET row_version = ?1, sealed = ?2 WHERE id = ?3 AND row_version = ?4",
                params![to_i64(rv)?, sealed, &id.as_bytes()[..], to_i64(old)?],
            )?,
        };
        one_row(n)?;
        self.stamp(
            TableTag::Projects,
            id.as_bytes(),
            rv,
            project_body(&hash, &sealed),
        );
        self.state.project_keys.insert(hash, id);
        self.state.projects.insert(
            id,
            ProjectRow {
                record: p,
                row_version: rv,
            },
        );
        Ok(id)
    }

    /// Deletes the record for `key`'s project. Returns whether one existed.
    pub fn delete_project(&mut self, key: &ProjectKey) -> Result<bool, VaultError> {
        let hash = dir_hash(self.keys, key.as_bytes());
        let Some(id) = self.state.project_keys.get(&hash).copied() else {
            return Ok(false);
        };
        let rv = self.state.projects.get(&id).map_or(0, |r| r.row_version);
        let n = self.tx.execute(
            "DELETE FROM projects WHERE id = ?1 AND row_version = ?2",
            params![&id.as_bytes()[..], to_i64(rv)?],
        )?;
        one_row(n)?;
        self.state.project_keys.remove(&hash);
        self.state.projects.remove(&id);
        self.unstamp(TableTag::Projects, id.as_bytes());
        Ok(true)
    }

    /// Stores a policy record under `id`, replacing the one it had.
    /// Refused with [`VaultErrorKind::InvalidRecord`] when the record breaks
    /// its kind's bounds and [`VaultErrorKind::TooLarge`] over
    /// [`MAX_FIELD`]. A standing approval added or replaced, or replaced by
    /// another kind, moves the standing set (see [`StandingSetHeader`]) at
    /// the commit.
    pub fn put_policy(&mut self, id: PolicyId, record: &PolicyRecord) -> Result<(), VaultError> {
        record.check()?;
        let body = record.encode();
        let standing =
            |p: Option<&PolicyRecord>| matches!(p, Some(PolicyRecord::StandingApproval(_)));
        let was = standing(self.state.policies.get(&id).and_then(|p| p.record.as_ref()));
        self.put_policy_body(id, &body, Some(record.clone()))?;
        if was || standing(Some(record)) {
            self.standing_changed = true;
        }
        Ok(())
    }

    /// Test support only: stores `body` sealed as a policy row, whatever it
    /// holds, as only a program holding the vault's key could (an unknown
    /// kind, say).
    #[cfg(feature = "testing")]
    pub fn put_raw_policy_for_testing(
        &mut self,
        id: PolicyId,
        body: &[u8],
    ) -> Result<(), VaultError> {
        let record = PolicyRecord::decode(body).ok();
        let standing =
            |p: Option<&PolicyRecord>| matches!(p, Some(PolicyRecord::StandingApproval(_)));
        let was = standing(self.state.policies.get(&id).and_then(|p| p.record.as_ref()));
        if was || standing(record.as_ref()) {
            self.standing_changed = true;
        }
        self.put_policy_body(id, body, record)
    }

    fn put_policy_body(
        &mut self,
        id: PolicyId,
        body: &[u8],
        record: Option<PolicyRecord>,
    ) -> Result<(), VaultError> {
        if body.len() > MAX_FIELD {
            return Err(VaultErrorKind::TooLarge.into());
        }
        let old = self.state.policies.get(&id).map(|p| p.row_version);
        let rv = old.map_or(1, |v| v + 1);
        let aad = self.ctx.aad(
            TableTag::Policies,
            id.as_bytes(),
            FieldTag::Policy,
            ItemClass::None,
            rv,
        );
        let sealed = seal_record(self.keys.key(Purpose::Data), &aad, body)?;
        let n = match old {
            None => self.tx.execute(
                "INSERT INTO policies (id, row_version, sealed) VALUES (?1, ?2, ?3)",
                params![&id.as_bytes()[..], to_i64(rv)?, sealed],
            )?,
            Some(old) => self.tx.execute(
                "UPDATE policies SET row_version = ?1, sealed = ?2 WHERE id = ?3 AND row_version = ?4",
                params![to_i64(rv)?, sealed, &id.as_bytes()[..], to_i64(old)?],
            )?,
        };
        one_row(n)?;
        self.stamp(TableTag::Policies, id.as_bytes(), rv, policy_body(&sealed));
        self.state.policies.insert(
            id,
            PolicyRow {
                record,
                row_version: rv,
            },
        );
        Ok(())
    }

    /// Deletes a policy record. Returns whether it existed. Removing a
    /// standing approval moves the standing set at the commit.
    pub fn delete_policy(&mut self, id: PolicyId) -> Result<bool, VaultError> {
        let Some((rv, standing)) = self.state.policies.get(&id).map(|p| {
            (
                p.row_version,
                matches!(p.record, Some(PolicyRecord::StandingApproval(_))),
            )
        }) else {
            return Ok(false);
        };
        if standing {
            self.standing_changed = true;
        }
        let n = self.tx.execute(
            "DELETE FROM policies WHERE id = ?1 AND row_version = ?2",
            params![&id.as_bytes()[..], to_i64(rv)?],
        )?;
        one_row(n)?;
        self.state.policies.remove(&id);
        self.unstamp(TableTag::Policies, id.as_bytes());
        Ok(true)
    }

    /// Adds an unlocker envelope for this vault's epoch.
    pub fn add_unlocker(&mut self, env: Envelope) -> Result<(), VaultError> {
        if self.state.unlockers.contains_key(&env.unlocker_id()) {
            return Err(VaultErrorKind::DuplicateUnlocker.into());
        }
        self.write_unlocker(env, false)
    }

    /// Replaces the envelope of an existing unlocker (a new passphrase, or
    /// a re-wrap under the current parameters).
    pub fn replace_unlocker(&mut self, env: Envelope) -> Result<(), VaultError> {
        if !self.state.unlockers.contains_key(&env.unlocker_id()) {
            return Err(VaultErrorKind::UnknownUnlocker.into());
        }
        self.write_unlocker(env, true)
    }

    fn write_unlocker(&mut self, env: Envelope, replace: bool) -> Result<(), VaultError> {
        if env.epoch() != self.ctx.epoch {
            return Err(VaultErrorKind::InvalidRecord.into());
        }
        let id = env.unlocker_id();
        let vault_id = &self.ctx.vault_id.0[..];
        let kind = i64::from(env.kind() as u8);
        let created_at = to_i64(self.now)?;
        let bytes = env.to_bytes();
        let n = if replace {
            self.tx.execute(
                "UPDATE unlockers SET vault_id = ?1, kind = ?2, envelope = ?3, created_at = ?4 \
                 WHERE id = ?5",
                params![vault_id, kind, &bytes[..], created_at, &id.0[..]],
            )?
        } else {
            self.tx.execute(
                "INSERT INTO unlockers (id, vault_id, kind, envelope, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![&id.0[..], vault_id, kind, &bytes[..], created_at],
            )?
        };
        one_row(n)?;
        let body = unlocker_body(vault_id, kind, created_at, &bytes);
        self.stamp(TableTag::Unlockers, &id.0, 0, body);
        self.state.unlockers.insert(id, env);
        Ok(())
    }

    /// Removes an unlocker. The last one cannot be removed.
    pub fn remove_unlocker(&mut self, id: UnlockerId) -> Result<(), VaultError> {
        if !self.state.unlockers.contains_key(&id) {
            return Err(VaultErrorKind::UnknownUnlocker.into());
        }
        if self.state.unlockers.len() == 1 {
            return Err(VaultErrorKind::LastUnlocker.into());
        }
        let n = self
            .tx
            .execute("DELETE FROM unlockers WHERE id = ?1", params![&id.0[..]])?;
        one_row(n)?;
        self.state.unlockers.remove(&id);
        self.unstamp(TableTag::Unlockers, &id.0);
        Ok(())
    }

    /// Saves the audit log's head in the header (T10).
    pub fn set_audit_head(&mut self, head: AuditHead) {
        self.state.header.audit_head = Some(head);
        self.dirty = true;
    }

    /// Records whether the Recovery Kit was confirmed (T4).
    pub fn set_recovery_confirmed(&mut self, confirmed: bool) {
        self.state.header.recovery_confirmed = confirmed;
        self.dirty = true;
    }

    /// Bumps the policy epoch and returns the new value (T9).
    pub fn bump_policy_epoch(&mut self) -> u64 {
        self.state.header.policy_epoch = self.state.header.policy_epoch.saturating_add(1);
        self.dirty = true;
        self.state.header.policy_epoch
    }

    /// The fields whose current value equals `v`, including writes made in
    /// this transaction. Compared by keyed hash; prior values are not
    /// searched.
    pub fn find_by_value(&self, v: &SecretBytes) -> Vec<FieldId> {
        find_by_value(self.keys, &self.state, v)
    }

    fn stamp(&mut self, table: TableTag, id: &[u8; 16], row_version: u64, body: [u8; 32]) {
        self.state
            .stamps
            .insert(row_key(table, id), Stamp { row_version, body });
        self.dirty = true;
    }

    fn unstamp(&mut self, table: TableTag, id: &[u8; 16]) {
        self.state.stamps.remove(&row_key(table, id));
        self.dirty = true;
    }
}

/// A login field's value as its row seals it: the text, or the packed TOTP
/// enrollment. Checked for size and emptiness as any value is.
fn login_value(v: LoginFieldValue) -> Result<SecretBytes, VaultError> {
    let packed = match v {
        LoginFieldValue::Username(s)
        | LoginFieldValue::Password(s)
        | LoginFieldValue::AdapterKey(s) => s,
        LoginFieldValue::Totp(t) => pack_totp(&t.params, &t.seed)?,
    };
    check_value(&packed)?;
    Ok(packed)
}

pub(crate) fn find_by_value(keys: &Keyring, state: &State, v: &SecretBytes) -> Vec<FieldId> {
    let h = value_hash(keys.key(Purpose::Index), v);
    state
        .fields
        .iter()
        .filter(|(_, f)| f.value_hash == h)
        .map(|(id, _)| *id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        Argon2id, EnvelopeCtx, KdfParams, UnlockerId, UnlockerKind, VaultId, Vmk, wrap_vmk_with,
    };
    use crate::vault::{
        INITIAL_EPOCH, Integrity, LockedVault, LoginMeta, LoginTier, TamperKind, Vault, VaultPaths,
    };

    fn vault() -> (tempfile::TempDir, VaultPaths, Vec<u8>, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::under(dir.path().join("data"));
        let vault_id = VaultId::generate();
        let vmk = Vmk::generate();
        let raw = vmk.export_for_testing();
        let env = wrap_vmk_with(
            &vmk,
            &SecretBytes::copy_from(b"unit test passphrase"),
            UnlockerKind::Passphrase,
            &EnvelopeCtx {
                vault_id,
                unlocker_id: UnlockerId::generate(),
                epoch: INITIAL_EPOCH,
            },
            &KdfParams::minimum(),
            &Argon2id,
        )
        .unwrap();
        let v = Vault::create(&paths, vault_id, vmk, vec![env]).unwrap();
        (dir, paths, raw, v)
    }

    fn reopened(paths: &VaultPaths, raw: &[u8]) -> Vault {
        LockedVault::open(paths)
            .unwrap()
            .unlock(Vmk::import_for_testing(raw).unwrap())
            .map_err(|(_, e)| e)
            .unwrap()
    }

    /// A field whose kind does not fit its item's class (a typed field on
    /// a secret, a value field on a login), written here with the key as
    /// only a holder of the key could, is inconsistent at the next unlock:
    /// the type rule holds for what is on disk, not only for what the
    /// public writes allow.
    #[test]
    fn a_field_whose_kind_does_not_fit_its_class_is_refused() {
        for (class, kind, name) in [
            (ItemClass::Secret, FieldKind::Password, "password"),
            (ItemClass::Login, FieldKind::Value, "value"),
        ] {
            let (_d, paths, raw, mut v) = vault();
            v.transact(|t| {
                let login = (class == ItemClass::Login).then_some(LoginMeta {
                    tier: LoginTier::Dev,
                    session_lifetime: 60,
                });
                let item = t.new_item(
                    class,
                    Slug::new("a/b").unwrap(),
                    ItemDetails::default(),
                    login,
                )?;
                let id = t.new_field_id();
                let value = SecretBytes::copy_from(b"a value");
                let row = FieldRow {
                    item,
                    record: FieldRecord {
                        name: FieldName::new(name).unwrap(),
                        prior_count: 0,
                        created_at: 1,
                        updated_at: 1,
                        kind,
                    },
                    row_version: 1,
                    value_hash: value_hash(t.keys.key(Purpose::Index), &value),
                };
                t.write_field(id, row, class, &value, &[], None)
            })
            .unwrap();
            drop(v);
            let v = reopened(&paths, &raw);
            assert_eq!(
                v.integrity(),
                Integrity::Tampered(TamperKind::RowInconsistent),
                "{class:?} with a {kind:?} field"
            );
            assert!(v.items()[0].fields.is_empty(), "the field is not served");
        }
    }
}
