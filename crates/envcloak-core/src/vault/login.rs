//! Login items (SPEC §6.8 "Login items", plan task M2-07): typed fields
//! that only a sign-in attempt opens.
//!
//! A `login` item ([`ItemClass::Login`]) holds a username, a password, an
//! optional TOTP enrollment (seed, algorithm, digits and period, sealed
//! together as one value) and an optional test-session adapter key, each a
//! field of its own [`FieldKind`] named for it, plus [`LoginMeta`] in its
//! record. Every one of its sealed columns carries the `login` class in its
//! associated data, so a login ciphertext moved into another item's row
//! does not open there.
//!
//! The type rule: a login field opens only through
//! [`LoginFieldReader::open`], which takes an [`AttemptLease`]. Nothing
//! else opens one: [`Vault::read_value`] and [`Vault::read_prior`] refuse
//! it ([`VaultErrorKind::LoginField`]), [`Txn::add_field`] and
//! [`Txn::set_value`] refuse to write one, and a login's values are hashed
//! in a domain of their own, so [`Vault::find_by_value`] never matches one.
//! A lease names one login item at its revision (the item row's version,
//! which every change to the login moves), so a lease made before the
//! password or TOTP enrollment was replaced opens nothing
//! ([`VaultErrorKind::LeaseStale`]).
//!
//! Only this module can make an [`AttemptLease`]: its fields are private
//! and it has no `Clone`, no `Default` and no public constructor, so no
//! code outside it can hold one, and no login field opens anywhere. The
//! daemon's sign-in module, which plan tasks M2b-05 and M2b-09 add, is to
//! be the one place that makes leases; it adds the constructor it calls
//! with it, as a method clippy.toml forbids outside the reviewed files of
//! security/expose-allowlist.txt, as `expose_secret` is (M2b-03: the
//! sign-in module is the one `LoginFieldReader` user).
//!
//! [`ItemClass::Login`]: crate::crypto::ItemClass::Login
//! [`Vault::read_value`]: super::Vault::read_value
//! [`Vault::read_prior`]: super::Vault::read_prior
//! [`Vault::find_by_value`]: super::Vault::find_by_value
//! [`Txn::add_field`]: super::Txn::add_field
//! [`Txn::set_value`]: super::Txn::set_value

use rusqlite::{OptionalExtension, params};

use crate::crypto::{FieldTag, ItemClass, TableTag};
use crate::secret::SecretBytes;

use super::Vault;
use super::error::{VaultError, VaultErrorKind};
use super::integrity::Integrity;
use super::items::{FieldId, FieldKind, ItemDetails, ItemId, LoginMeta, Slug};
use super::state::item_key;
use super::values::{open_value, unpack_totp};

/// The HMAC of a TOTP enrollment (RFC 6238). Part of the sealed enrollment:
/// never renumber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TotpAlgorithm {
    Sha1 = 1,
    Sha256 = 2,
    Sha512 = 3,
}

impl TotpAlgorithm {
    pub(crate) fn from_byte(b: u8) -> Result<Self, VaultError> {
        match b {
            1 => Ok(TotpAlgorithm::Sha1),
            2 => Ok(TotpAlgorithm::Sha256),
            3 => Ok(TotpAlgorithm::Sha512),
            _ => Err(VaultErrorKind::Corrupt.into()),
        }
    }
}

/// A TOTP enrollment's parameters (an `otpauth://` URI's, M2b-03): 6 or
/// 8 digits, a period of 1 to 3,600 seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TotpParams {
    algorithm: TotpAlgorithm,
    digits: u8,
    period: u32,
}

impl TotpParams {
    /// The longest period accepted, in seconds.
    pub const MAX_PERIOD: u32 = 3600;

    /// Fails with [`VaultErrorKind::InvalidRecord`] unless `digits` is 6
    /// or 8 and `period` is 1 to [`TotpParams::MAX_PERIOD`].
    pub fn new(algorithm: TotpAlgorithm, digits: u8, period: u32) -> Result<Self, VaultError> {
        if !matches!(digits, 6 | 8) || period == 0 || period > Self::MAX_PERIOD {
            return Err(VaultErrorKind::InvalidRecord.into());
        }
        Ok(TotpParams {
            algorithm,
            digits,
            period,
        })
    }

    pub fn algorithm(&self) -> TotpAlgorithm {
        self.algorithm
    }

    pub fn digits(&self) -> u8 {
        self.digits
    }

    pub fn period(&self) -> u32 {
        self.period
    }
}

/// A TOTP enrollment: the seed and its parameters, sealed together as the
/// value of a login's [`FieldKind::TotpSeed`] field. Its `Debug` shows the
/// parameters only.
pub struct TotpEnrollment {
    pub params: TotpParams,
    /// The shared secret: 1 to [`TotpEnrollment::MAX_SEED`] bytes.
    pub seed: SecretBytes,
}

impl TotpEnrollment {
    /// The longest seed accepted, in bytes.
    pub const MAX_SEED: usize = 256;
}

impl core::fmt::Debug for TotpEnrollment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TotpEnrollment")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

/// A new login item for [`Txn::create_login`](super::Txn::create_login).
/// Its `Debug` shows no value.
pub struct NewLogin {
    pub slug: Slug,
    pub details: ItemDetails,
    pub meta: LoginMeta,
    pub username: SecretBytes,
    pub password: SecretBytes,
    pub totp: Option<TotpEnrollment>,
    pub adapter_key: Option<SecretBytes>,
}

impl core::fmt::Debug for NewLogin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NewLogin")
            .field("slug", &self.slug)
            .field("meta", &self.meta)
            .field("totp", &self.totp)
            .field("adapter_key", &self.adapter_key.is_some())
            .finish_non_exhaustive()
    }
}

/// One login field's new value, for
/// [`Txn::replace_login_field`](super::Txn::replace_login_field). Its
/// `Debug` shows the kind only.
pub enum LoginFieldValue {
    Username(SecretBytes),
    Password(SecretBytes),
    Totp(TotpEnrollment),
    AdapterKey(SecretBytes),
}

impl LoginFieldValue {
    pub fn kind(&self) -> FieldKind {
        match self {
            LoginFieldValue::Username(_) => FieldKind::Username,
            LoginFieldValue::Password(_) => FieldKind::Password,
            LoginFieldValue::Totp(_) => FieldKind::TotpSeed,
            LoginFieldValue::AdapterKey(_) => FieldKind::AdapterKey,
        }
    }
}

impl core::fmt::Debug for LoginFieldValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LoginFieldValue({:?})", self.kind())
    }
}

/// A login field [`LoginFieldReader::open`] opened. Its `Debug` shows no
/// value.
pub enum LoginValue {
    /// A username, a password or an adapter key.
    Text(SecretBytes),
    Totp(TotpEnrollment),
}

impl core::fmt::Debug for LoginValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LoginValue::Text(_) => f.write_str("LoginValue::Text(..)"),
            LoginValue::Totp(t) => write!(f, "LoginValue::Totp({:?})", t.params),
        }
    }
}

/// The right to open one login item's fields for one sign-in attempt, at
/// the login's revision when it was made. Only this module makes one (see
/// the module documentation); it cannot be copied, cloned, defaulted or
/// built from its parts outside it:
///
/// ```
/// // The type itself is public: code can name it, and take one.
/// use envcloak_core::vault::{AttemptLease, FieldKind, LoginFieldReader, LoginValue};
/// fn sign_in(r: &LoginFieldReader<'_>, lease: &AttemptLease) -> Option<LoginValue> {
///     r.open(lease, FieldKind::Password).ok()
/// }
/// ```
///
/// ```compile_fail
/// use envcloak_core::vault::{AttemptLease, ItemId};
/// let lease = AttemptLease { item: ItemId::generate(), revision: 1 };
/// ```
///
/// ```compile_fail
/// use envcloak_core::vault::AttemptLease;
/// let lease = AttemptLease::default();
/// ```
///
/// ```compile_fail
/// use envcloak_core::vault::AttemptLease;
/// fn copy(l: &AttemptLease) -> AttemptLease {
///     l.clone()
/// }
/// ```
pub struct AttemptLease {
    item: ItemId,
    revision: u64,
}

impl core::fmt::Debug for AttemptLease {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AttemptLease")
            .field("item", &self.item)
            .field("revision", &self.revision)
            .finish()
    }
}

impl AttemptLease {
    /// The login item it opens.
    pub fn item(&self) -> ItemId {
        self.item
    }
}

/// The one way to open a login field (see the module documentation): it
/// takes an [`AttemptLease`].
#[derive(Debug, Clone, Copy)]
pub struct LoginFieldReader<'v> {
    vault: &'v Vault,
}

impl Vault {
    /// The reader of this vault's login fields.
    pub fn login_fields(&self) -> LoginFieldReader<'_> {
        LoginFieldReader { vault: self }
    }
}

impl LoginFieldReader<'_> {
    /// Opens the `kind` field of the login `lease` names. Fails with
    /// [`VaultErrorKind::Tampered`] unless the vault verified (and when the
    /// row no longer opens, which turns it read-only, as a read of a value
    /// does), [`VaultErrorKind::LeaseStale`] when the login changed since
    /// the lease was issued, or it was removed, [`VaultErrorKind::LoginField`]
    /// for [`FieldKind::Value`], and [`VaultErrorKind::UnknownField`] when
    /// the login has no field of that kind.
    pub fn open(&self, lease: &AttemptLease, kind: FieldKind) -> Result<LoginValue, VaultError> {
        let v = self.vault;
        if v.integrity() != Integrity::Ok {
            return Err(VaultErrorKind::Tampered.into());
        }
        if !kind.is_login() {
            return Err(VaultErrorKind::LoginField.into());
        }
        let row = v
            .state
            .items
            .get(&lease.item)
            .filter(|r| r.class == ItemClass::Login && r.row_version == lease.revision)
            .ok_or(VaultErrorKind::LeaseStale)?;
        let (field, f) = login_field(v, lease.item, kind).ok_or(VaultErrorKind::UnknownField)?;
        let stored: Option<Vec<u8>> = v
            .file
            .conn
            .query_row(
                "SELECT sealed_value FROM fields WHERE id = ?1",
                params![&field.as_bytes()[..]],
                |r| r.get(0),
            )
            .optional()?;
        let aad = v.ctx.aad(
            TableTag::Fields,
            field.as_bytes(),
            FieldTag::FieldValue,
            row.class,
            f,
        );
        let opened = stored
            .ok_or(VaultErrorKind::Tampered)
            .and_then(|s| {
                open_value(item_key(&v.keys, row.class), &aad, &s)
                    .map_err(|_| VaultErrorKind::Tampered)
            })
            .map_err(|k| v.changed_while_open(k))?;
        match kind {
            FieldKind::TotpSeed => {
                let (params, seed) = unpack_totp(&opened)
                    .map_err(|_| v.changed_while_open(VaultErrorKind::Tampered))?;
                Ok(LoginValue::Totp(TotpEnrollment { params, seed }))
            }
            _ => Ok(LoginValue::Text(opened)),
        }
    }
}

/// The id and row version of `item`'s field of `kind`.
fn login_field(v: &Vault, item: ItemId, kind: FieldKind) -> Option<(FieldId, u64)> {
    v.state
        .fields
        .iter()
        .find(|(_, f)| f.item == item && f.record.kind == kind)
        .map(|(id, f)| (*id, f.row_version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        Argon2id, EnvelopeCtx, KdfParams, UnlockerId, UnlockerKind, VaultId, Vmk, wrap_vmk_with,
    };
    use crate::vault::{
        ExposureSource, FieldName, INITIAL_EPOCH, LoginTier, NewItem, TamperKind, VaultPaths,
    };

    fn vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::under(dir.path().join("data"));
        let vault_id = VaultId::generate();
        let vmk = Vmk::generate();
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
        (dir, v)
    }

    /// The lease the sign-in module will make: the login at its revision
    /// now.
    fn lease(v: &Vault, item: ItemId) -> AttemptLease {
        AttemptLease {
            item,
            revision: v.state.items[&item].row_version,
        }
    }

    fn text(v: LoginValue) -> SecretBytes {
        match v {
            LoginValue::Text(t) => t,
            LoginValue::Totp(_) => panic!("a text field opened as a TOTP enrollment"),
        }
    }

    fn new_login(totp: bool) -> NewLogin {
        NewLogin {
            slug: Slug::new("fixture/editor").unwrap(),
            details: ItemDetails::default(),
            meta: LoginMeta {
                tier: LoginTier::Dev,
                session_lifetime: 3600,
            },
            username: SecretBytes::copy_from(b"editor@example.test"),
            password: SecretBytes::copy_from(b"unit test password"),
            totp: totp.then(|| TotpEnrollment {
                params: TotpParams::new(TotpAlgorithm::Sha256, 8, 60).unwrap(),
                seed: SecretBytes::copy_from(b"unit test totp seed bytes"),
            }),
            adapter_key: totp.then(|| SecretBytes::copy_from(b"unit test adapter key")),
        }
    }

    /// The type rule: a lease opens each typed field of its login, and
    /// nothing generic opens or writes any of them.
    #[test]
    fn a_lease_opens_each_typed_field_and_nothing_else_does() {
        let (_d, mut v) = vault();
        let item = v.transact(|t| t.create_login(new_login(true))).unwrap();
        let r = v.login_fields();
        let l = lease(&v, item);
        assert!(text(r.open(&l, FieldKind::Username).unwrap()).ct_eq(b"editor@example.test"));
        assert!(text(r.open(&l, FieldKind::Password).unwrap()).ct_eq(b"unit test password"));
        assert!(text(r.open(&l, FieldKind::AdapterKey).unwrap()).ct_eq(b"unit test adapter key"));
        match r.open(&l, FieldKind::TotpSeed).unwrap() {
            LoginValue::Totp(t) => {
                assert_eq!(
                    t.params,
                    TotpParams::new(TotpAlgorithm::Sha256, 8, 60).unwrap()
                );
                assert!(t.seed.ct_eq(b"unit test totp seed bytes"));
            }
            LoginValue::Text(_) => panic!("the TOTP enrollment opened as text"),
        }
        assert_eq!(
            r.open(&l, FieldKind::Value).unwrap_err().kind(),
            VaultErrorKind::LoginField
        );
        let meta = v.item(item).unwrap().clone();
        assert_eq!(meta.class, ItemClass::Login);
        assert_eq!(meta.fields.len(), 4);
        for f in &meta.fields {
            assert_eq!(Some(f.name.as_str()), f.kind.login_name());
            for e in [
                v.read_value(f.id).unwrap_err(),
                v.read_prior(f.id, 0).unwrap_err(),
            ] {
                assert_eq!(e.kind(), VaultErrorKind::LoginField, "{:?}", f.kind);
            }
        }
        // Nothing generic writes one either.
        let e = v
            .transact(|t| {
                t.add_field(
                    item,
                    FieldName::new("value").unwrap(),
                    SecretBytes::copy_from(b"x"),
                )
            })
            .unwrap_err();
        assert_eq!(e.kind(), VaultErrorKind::LoginField);
        let e = v
            .transact(|t| t.set_value(meta.fields[0].id, SecretBytes::copy_from(b"x")))
            .unwrap_err();
        assert_eq!(e.kind(), VaultErrorKind::LoginField);
        let e = v
            .transact(|t| {
                t.create_item(NewItem {
                    class: ItemClass::Login,
                    slug: Slug::new("other/login").unwrap(),
                    details: ItemDetails::default(),
                })
            })
            .unwrap_err();
        assert_eq!(e.kind(), VaultErrorKind::LoginField);
        assert_eq!(v.integrity(), Integrity::Ok);
    }

    /// A lease names the login at its revision: once the password is
    /// replaced (or the login otherwise changed, or removed), it opens
    /// nothing, and a new lease opens the new password.
    #[test]
    fn a_lease_made_before_a_change_opens_nothing() {
        let (_d, mut v) = vault();
        let item = v.transact(|t| t.create_login(new_login(false))).unwrap();
        let old = lease(&v, item);
        v.transact(|t| {
            t.replace_login_field(
                item,
                LoginFieldValue::Password(SecretBytes::copy_from(b"the new password")),
            )
        })
        .unwrap();
        let r = v.login_fields();
        for kind in [FieldKind::Username, FieldKind::Password] {
            assert_eq!(
                r.open(&old, kind).unwrap_err().kind(),
                VaultErrorKind::LeaseStale
            );
        }
        let new = lease(&v, item);
        assert!(text(r.open(&new, FieldKind::Password).unwrap()).ct_eq(b"the new password"));
        // Any other change to the login moves it too.
        v.transact(|t| t.mark_exposed(item, &[ExposureSource::Transcript], 1))
            .unwrap();
        let r = v.login_fields();
        assert_eq!(
            r.open(&new, FieldKind::Password).unwrap_err().kind(),
            VaultErrorKind::LeaseStale
        );
        // A TOTP enrollment is added the same way, and the lease made
        // before it opens nothing.
        let fresh = lease(&v, item);
        v.transact(|t| {
            t.replace_login_field(
                item,
                LoginFieldValue::Totp(TotpEnrollment {
                    params: TotpParams::new(TotpAlgorithm::Sha1, 6, 30).unwrap(),
                    seed: SecretBytes::copy_from(b"another seed"),
                }),
            )
        })
        .unwrap();
        let r = v.login_fields();
        assert_eq!(
            r.open(&fresh, FieldKind::TotpSeed).unwrap_err().kind(),
            VaultErrorKind::LeaseStale
        );
        assert!(matches!(
            r.open(&lease(&v, item), FieldKind::TotpSeed).unwrap(),
            LoginValue::Totp(_)
        ));
        let last = lease(&v, item);
        v.transact(|t| t.delete_item(item)).unwrap();
        assert_eq!(
            v.login_fields()
                .open(&last, FieldKind::Password)
                .unwrap_err()
                .kind(),
            VaultErrorKind::LeaseStale
        );
    }

    /// A lease names a login: one that names any other item (here a secret
    /// with a field named `password`) opens nothing; and a login without a
    /// TOTP enrollment has none to open.
    #[test]
    fn a_lease_opens_only_its_own_login() {
        let (_d, mut v) = vault();
        let (login, secret) = v
            .transact(|t| {
                let login = t.create_login(new_login(false))?;
                let secret = t.create_item(NewItem {
                    class: ItemClass::Secret,
                    slug: Slug::new("openai/work").unwrap(),
                    details: ItemDetails::default(),
                })?;
                t.add_field(
                    secret,
                    FieldName::new("password").unwrap(),
                    SecretBytes::copy_from(b"a secret value"),
                )?;
                Ok((login, secret))
            })
            .unwrap();
        let r = v.login_fields();
        assert_eq!(
            r.open(&lease(&v, secret), FieldKind::Password)
                .unwrap_err()
                .kind(),
            VaultErrorKind::LeaseStale
        );
        assert_eq!(
            r.open(&lease(&v, login), FieldKind::TotpSeed)
                .unwrap_err()
                .kind(),
            VaultErrorKind::UnknownField
        );
    }

    /// A vault that failed its check opens no login field, whatever lease.
    #[test]
    fn a_tampered_vault_opens_no_login_field() {
        let (_d, mut v) = vault();
        let item = v.transact(|t| t.create_login(new_login(false))).unwrap();
        let l = lease(&v, item);
        v.integrity
            .set(Integrity::Tampered(TamperKind::ChangedWhileOpen));
        assert_eq!(
            v.login_fields()
                .open(&l, FieldKind::Password)
                .unwrap_err()
                .kind(),
            VaultErrorKind::Tampered
        );
    }

    #[test]
    fn values_and_enrollments_are_checked_and_never_debug_printed() {
        assert!(TotpParams::new(TotpAlgorithm::Sha1, 7, 30).is_err());
        assert!(TotpParams::new(TotpAlgorithm::Sha1, 6, 0).is_err());
        assert!(TotpParams::new(TotpAlgorithm::Sha1, 6, TotpParams::MAX_PERIOD + 1).is_err());
        assert!(TotpParams::new(TotpAlgorithm::Sha512, 8, TotpParams::MAX_PERIOD).is_ok());
        let (_d, mut v) = vault();
        for (seed, want) in [
            (Vec::new(), VaultErrorKind::InvalidValue),
            (
                vec![1u8; TotpEnrollment::MAX_SEED + 1],
                VaultErrorKind::TooLarge,
            ),
        ] {
            let mut n = new_login(true);
            if let Some(t) = n.totp.as_mut() {
                t.seed = SecretBytes::copy_from(&seed);
            }
            assert_eq!(v.transact(|t| t.create_login(n)).unwrap_err().kind(), want);
        }
        let mut n = new_login(false);
        n.password = SecretBytes::copy_from(b"");
        assert_eq!(
            v.transact(|t| t.create_login(n)).unwrap_err().kind(),
            VaultErrorKind::InvalidValue
        );
        // Nothing was written by the refused ones.
        assert!(v.items().is_empty());
        let shown = format!(
            "{:?} {:?} {:?}",
            new_login(true),
            LoginFieldValue::Password(SecretBytes::copy_from(b"unit test password")),
            LoginValue::Text(SecretBytes::copy_from(b"unit test password")),
        );
        for secret in [
            "unit test password",
            "editor@example.test",
            "unit test totp seed bytes",
            "unit test adapter key",
        ] {
            assert!(!shown.contains(secret), "{shown}");
        }
    }
}
