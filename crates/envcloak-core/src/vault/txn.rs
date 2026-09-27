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
    FieldId, FieldName, FieldRecord, ItemDetails, ItemId, MAX_FIELD, MAX_PRIOR, MAX_ROW, NewItem,
    PolicyId, ProjectId, ProjectKey, ProjectRecord, Slug, encode_field, encode_item,
    encode_project,
};
use super::schema::drop_page_cache;
use super::state::{
    FieldRow, ItemRow, PolicyRow, ProjectRow, State, VaultCtx, dir_hash, item_key, slug_hash,
};
use super::values::{
    check_value, open_priors, open_value, seal_priors, seal_record, seal_value, tampered,
    value_hash,
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
    /// over the change (see [`drop_page_cache`]).
    pub(crate) fn begin(
        conn: &'v mut Connection,
        keys: &'v Keyring,
        ctx: VaultCtx,
        state: State,
    ) -> Result<Self, VaultError> {
        drop_page_cache(conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        Ok(Txn {
            tx,
            keys,
            ctx,
            state,
            dirty: false,
            now: now_secs(),
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
            ..
        } = self;
        if dirty {
            let mut header = state.header;
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

    /// Creates an item with no fields.
    pub fn create_item(&mut self, n: NewItem) -> Result<ItemId, VaultError> {
        if n.class == ItemClass::None {
            return Err(VaultErrorKind::InvalidRecord.into());
        }
        if self.state.slugs.contains_key(&n.slug) {
            return Err(VaultErrorKind::DuplicateSlug.into());
        }
        let id = loop {
            let id = ItemId::generate();
            if !self.state.items.contains_key(&id) {
                break id;
            }
        };
        let row = ItemRow {
            class: n.class,
            slug: n.slug,
            details: n.details,
            created_at: self.now,
            updated_at: self.now,
            row_version: 1,
        };
        self.write_item(id, row, None)?;
        Ok(id)
    }

    /// Replaces an item's details.
    pub fn update_item(&mut self, id: ItemId, details: ItemDetails) -> Result<(), VaultError> {
        let old = self.item_row(id)?;
        let row = ItemRow {
            details,
            updated_at: self.now,
            row_version: old.row_version + 1,
            ..old.clone()
        };
        self.write_item(id, row, Some(&old))
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
        let record = encode_item(&row.slug, row.created_at, &row.details);
        if record.len() > MAX_FIELD {
            return Err(VaultErrorKind::TooLarge.into());
        }
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

    /// Adds a field holding `value` to an item.
    pub fn add_field(
        &mut self,
        item: ItemId,
        name: FieldName,
        value: SecretBytes,
    ) -> Result<FieldId, VaultError> {
        check_value(&value)?;
        let class = self.item_row(item)?.class;
        if self.field_id(item, &name).is_some() {
            return Err(VaultErrorKind::DuplicateField.into());
        }
        let id = loop {
            let id = FieldId::generate();
            if !self.state.fields.contains_key(&id) {
                break id;
            }
        };
        let row = FieldRow {
            item,
            record: FieldRecord {
                name,
                prior_count: 0,
                created_at: self.now,
                updated_at: self.now,
            },
            row_version: 1,
            value_hash: value_hash(self.keys.key(Purpose::Index), &value),
        };
        self.write_field(id, row, class, &value, &[], None)?;
        Ok(id)
    }

    /// Replaces a field's value. The old value becomes the newest prior
    /// value; at most [`MAX_PRIOR`] are kept.
    pub fn set_value(&mut self, field: FieldId, value: SecretBytes) -> Result<(), VaultError> {
        check_value(&value)?;
        let old = self
            .state
            .fields
            .get(&field)
            .cloned()
            .ok_or(VaultErrorKind::UnknownField)?;
        let class = self.item_row(old.item)?.class;
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

    /// Stores a policy record (its format belongs to the policy layer).
    pub fn put_policy(&mut self, id: PolicyId, body: &[u8]) -> Result<(), VaultError> {
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
                body: body.to_vec(),
                row_version: rv,
            },
        );
        Ok(())
    }

    /// Deletes a policy record. Returns whether it existed.
    pub fn delete_policy(&mut self, id: PolicyId) -> Result<bool, VaultError> {
        let Some(rv) = self.state.policies.get(&id).map(|p| p.row_version) else {
            return Ok(false);
        };
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

pub(crate) fn find_by_value(keys: &Keyring, state: &State, v: &SecretBytes) -> Vec<FieldId> {
    let h = value_hash(keys.key(Purpose::Index), v);
    state
        .fields
        .iter()
        .filter(|(_, f)| f.value_hash == h)
        .map(|(id, _)| *id)
        .collect()
}
