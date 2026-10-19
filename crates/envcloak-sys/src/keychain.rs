//! The macOS data-protection keychain rollback anchor (`D3-12`, SPEC §5
//! "Keychain rollback anchor", `docs/VAULT.md`).
//!
//! Stores a 68-byte record (`vault_id(16) || epoch(4) || write_counter(8) ||
//! state_digest(32) || audit_seq(8)`) in the macOS data-protection keychain
//! under `service = "ai.envcloak.anchor"`, `account = <vault_id hex>`,
//! `access_group = "<TEAMID>.ai.envcloak"`,
//! `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`,
//! `kSecAttrSynchronizable = kCFBooleanFalse`.
//!
//! On Linux and on macOS builds without an embedded Team ID pin or keychain
//! access-group entitlement (`errSecMissingEntitlement`), these calls report
//! [`KeychainAnchorError::Unavailable`] and never touch the user's login
//! keychain.

/// The byte length of a serialized keychain rollback anchor.
pub const KEYCHAIN_ANCHOR_LEN: usize = 68;

/// The keychain service name for rollback anchors (`docs/VAULT.md`).
pub const KEYCHAIN_ANCHOR_SERVICE: &str = "ai.envcloak.anchor";

/// The keychain access-group suffix (`<TEAMID>.ai.envcloak`).
pub const KEYCHAIN_ANCHOR_ACCESS_GROUP_SUFFIX: &str = "ai.envcloak";

/// Fixed errors from reading or writing the keychain rollback anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainAnchorError {
    /// The data-protection keychain anchor is unavailable on this platform or
    /// build (Linux, unsigned dev builds without `TEAM_ID`, or
    /// `errSecMissingEntitlement`).
    Unavailable,
    /// A stored anchor record did not have [`KEYCHAIN_ANCHOR_LEN`] bytes.
    InvalidRecord,
    /// The keychain store rejected or failed the operation.
    Storage,
}

/// Whether the keychain rollback anchor store is available in this process.
#[must_use]
pub fn is_keychain_anchor_available() -> bool {
    #[cfg(feature = "testing")]
    if let Some(avail) = test_override::is_available() {
        return avail;
    }
    #[cfg(target_os = "macos")]
    {
        crate::peer_code::pins::TEAM_ID.is_some()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Reads the 68-byte rollback anchor for `vault_id_hex`, or `Ok(None)` if no
/// anchor is stored for that vault.
///
/// # Errors
/// Returns [`KeychainAnchorError::Unavailable`] when the data-protection
/// keychain is unavailable, [`KeychainAnchorError::InvalidRecord`] when the
/// stored item is not [`KEYCHAIN_ANCHOR_LEN`] bytes, or
/// [`KeychainAnchorError::Storage`] on a keychain failure.
pub fn read_keychain_anchor(
    vault_id_hex: &str,
) -> Result<Option<[u8; KEYCHAIN_ANCHOR_LEN]>, KeychainAnchorError> {
    if !valid_vault_id_hex(vault_id_hex) {
        return Err(KeychainAnchorError::InvalidRecord);
    }
    #[cfg(feature = "testing")]
    if let Some(res) = test_override::read(vault_id_hex) {
        return res;
    }
    #[cfg(target_os = "macos")]
    {
        macos::read(vault_id_hex)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(KeychainAnchorError::Unavailable)
    }
}

/// Writes or updates the 68-byte rollback anchor for `vault_id_hex`.
///
/// # Errors
/// Returns [`KeychainAnchorError::Unavailable`] when the data-protection
/// keychain is unavailable, [`KeychainAnchorError::InvalidRecord`] when
/// `vault_id_hex` is malformed, or [`KeychainAnchorError::Storage`] on a
/// keychain failure.
pub fn write_keychain_anchor(
    vault_id_hex: &str,
    record: &[u8; KEYCHAIN_ANCHOR_LEN],
) -> Result<(), KeychainAnchorError> {
    if !valid_vault_id_hex(vault_id_hex) {
        return Err(KeychainAnchorError::InvalidRecord);
    }
    #[cfg(feature = "testing")]
    if let Some(res) = test_override::write(vault_id_hex, record) {
        return res;
    }
    #[cfg(target_os = "macos")]
    {
        macos::write(vault_id_hex, record)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = record;
        Err(KeychainAnchorError::Unavailable)
    }
}

fn valid_vault_id_hex(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(feature = "testing")]
mod test_override {
    use super::{KEYCHAIN_ANCHOR_LEN, KeychainAnchorError};
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::path::PathBuf;

    const ENV_VAR: &str = "ENVCLOAK_TEST_ANCHOR_FILE";

    enum Mode {
        Unavailable,
        File(PathBuf),
    }

    fn mode() -> Option<Mode> {
        let raw = std::env::var_os(ENV_VAR)?;
        if raw == "unavailable" {
            Some(Mode::Unavailable)
        } else {
            Some(Mode::File(PathBuf::from(raw)))
        }
    }

    pub(super) fn is_available() -> Option<bool> {
        match mode()? {
            Mode::Unavailable => Some(false),
            Mode::File(_) => Some(true),
        }
    }

    pub(super) fn read(
        vault_id_hex: &str,
    ) -> Option<Result<Option<[u8; KEYCHAIN_ANCHOR_LEN]>, KeychainAnchorError>> {
        let path = match mode()? {
            Mode::Unavailable => return Some(Err(KeychainAnchorError::Unavailable)),
            Mode::File(p) => p,
        };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(Ok(None)),
            Err(_) => return Some(Err(KeychainAnchorError::Storage)),
        };
        let needle = vault_id_hex.to_ascii_lowercase();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let Some((k, v)) = line.split_once(':') else {
                return Some(Err(KeychainAnchorError::InvalidRecord));
            };
            if k.eq_ignore_ascii_case(&needle) {
                return Some(decode_hex_anchor(v).map(Some));
            }
        }
        Some(Ok(None))
    }

    pub(super) fn write(
        vault_id_hex: &str,
        record: &[u8; KEYCHAIN_ANCHOR_LEN],
    ) -> Option<Result<(), KeychainAnchorError>> {
        let path = match mode()? {
            Mode::Unavailable => return Some(Err(KeychainAnchorError::Unavailable)),
            Mode::File(p) => p,
        };
        let existing = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(_) => return Some(Err(KeychainAnchorError::Storage)),
        };
        let needle = vault_id_hex.to_ascii_lowercase();
        let mut entries: Vec<(String, String)> = Vec::new();
        let mut replaced = false;
        for line in existing.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                if k.eq_ignore_ascii_case(&needle) {
                    entries.push((needle.clone(), encode_hex(record)));
                    replaced = true;
                } else {
                    entries.push((k.to_ascii_lowercase(), v.to_owned()));
                }
            }
        }
        if !replaced {
            entries.push((needle, encode_hex(record)));
        }
        let mut out = String::new();
        for (k, v) in entries {
            out.push_str(&k);
            out.push(':');
            out.push_str(&v);
            out.push('\n');
        }
        let write_res = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| {
                f.write_all(out.as_bytes())?;
                f.sync_all()
            });
        Some(write_res.map_err(|_| KeychainAnchorError::Storage))
    }

    fn encode_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes
            .iter()
            .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            })
    }

    fn decode_hex_anchor(hex: &str) -> Result<[u8; KEYCHAIN_ANCHOR_LEN], KeychainAnchorError> {
        if hex.len() != KEYCHAIN_ANCHOR_LEN * 2 {
            return Err(KeychainAnchorError::InvalidRecord);
        }
        let mut out = [0u8; KEYCHAIN_ANCHOR_LEN];
        for (i, slot) in out.iter_mut().enumerate() {
            let byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| KeychainAnchorError::InvalidRecord)?;
            *slot = byte;
        }
        Ok(out)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{
        KEYCHAIN_ANCHOR_ACCESS_GROUP_SUFFIX, KEYCHAIN_ANCHOR_LEN, KEYCHAIN_ANCHOR_SERVICE,
        KeychainAnchorError,
    };
    use core_foundation::{
        base::{CFType, CFTypeRef, TCFType},
        boolean::CFBoolean,
        data::{CFData, CFDataRef},
        dictionary::{CFDictionary, CFDictionaryRef},
        string::{CFString, CFStringRef},
    };

    const ERR_SEC_SUCCESS: i32 = 0;
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecItemCopyMatching(query: CFDictionaryRef, result: *mut CFTypeRef) -> i32;
        fn SecItemAdd(attributes: CFDictionaryRef, result: *mut CFTypeRef) -> i32;
        fn SecItemUpdate(query: CFDictionaryRef, attributesToUpdate: CFDictionaryRef) -> i32;

        static kSecClass: CFStringRef;
        static kSecClassGenericPassword: CFStringRef;
        static kSecAttrService: CFStringRef;
        static kSecAttrAccount: CFStringRef;
        static kSecAttrAccessGroup: CFStringRef;
        static kSecAttrAccessible: CFStringRef;
        static kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly: CFStringRef;
        static kSecAttrSynchronizable: CFStringRef;
        static kSecUseDataProtectionKeychain: CFStringRef;
        static kSecReturnData: CFStringRef;
        static kSecMatchLimit: CFStringRef;
        static kSecMatchLimitOne: CFStringRef;
        static kSecValueData: CFStringRef;
    }

    fn access_group() -> Result<String, KeychainAnchorError> {
        let team = crate::peer_code::pins::TEAM_ID.ok_or(KeychainAnchorError::Unavailable)?;
        Ok(format!("{team}.{KEYCHAIN_ANCHOR_ACCESS_GROUP_SUFFIX}"))
    }

    pub(super) fn read(
        vault_id_hex: &str,
    ) -> Result<Option<[u8; KEYCHAIN_ANCHOR_LEN]>, KeychainAnchorError> {
        let group = access_group()?;
        let service = CFString::new(KEYCHAIN_ANCHOR_SERVICE);
        let account = CFString::new(&vault_id_hex.to_ascii_lowercase());
        let group = CFString::new(&group);
        // SAFETY: Security.framework string constants are process-lifetime
        // CFStrings; wrap_under_get_rule retains them safely.
        let (
            k_class,
            v_generic,
            k_service,
            k_account,
            k_group,
            k_sync,
            k_dp,
            k_ret_data,
            k_limit,
            v_limit_one,
        ) = unsafe {
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassGenericPassword),
                CFString::wrap_under_get_rule(kSecAttrService),
                CFString::wrap_under_get_rule(kSecAttrAccount),
                CFString::wrap_under_get_rule(kSecAttrAccessGroup),
                CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain),
                CFString::wrap_under_get_rule(kSecReturnData),
                CFString::wrap_under_get_rule(kSecMatchLimit),
                CFString::wrap_under_get_rule(kSecMatchLimitOne),
            )
        };
        let query = CFDictionary::<CFString, CFType>::from_CFType_pairs(&[
            (k_class, v_generic.as_CFType()),
            (k_service, service.as_CFType()),
            (k_account, account.as_CFType()),
            (k_group, group.as_CFType()),
            (k_sync, CFBoolean::false_value().as_CFType()),
            (k_dp, CFBoolean::true_value().as_CFType()),
            (k_ret_data, CFBoolean::true_value().as_CFType()),
            (k_limit, v_limit_one.as_CFType()),
        ]);
        let mut raw: CFTypeRef = core::ptr::null();
        // SAFETY: query is a live CFDictionary; raw is a writable out-pointer
        // that receives an owned CFDataRef on ERR_SEC_SUCCESS.
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut raw) };
        match status {
            ERR_SEC_SUCCESS => {
                if raw.is_null() {
                    return Err(KeychainAnchorError::Storage);
                }
                // SAFETY: SecItemCopyMatching with kSecReturnData = true
                // returns an owned CFDataRef on ERR_SEC_SUCCESS.
                let data = unsafe { CFData::wrap_under_create_rule(raw.cast::<_>() as CFDataRef) };
                let bytes = data.bytes();
                let buf: [u8; KEYCHAIN_ANCHOR_LEN] = bytes
                    .try_into()
                    .map_err(|_| KeychainAnchorError::InvalidRecord)?;
                Ok(Some(buf))
            }
            ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            ERR_SEC_MISSING_ENTITLEMENT => Err(KeychainAnchorError::Unavailable),
            _ => Err(KeychainAnchorError::Storage),
        }
    }

    pub(super) fn write(
        vault_id_hex: &str,
        record: &[u8; KEYCHAIN_ANCHOR_LEN],
    ) -> Result<(), KeychainAnchorError> {
        let group = access_group()?;
        let service = CFString::new(KEYCHAIN_ANCHOR_SERVICE);
        let account = CFString::new(&vault_id_hex.to_ascii_lowercase());
        let group = CFString::new(&group);
        let value_data = CFData::from_buffer(record);
        // SAFETY: Security.framework string constants are process-lifetime
        // CFStrings; wrap_under_get_rule retains them safely.
        let (
            k_class,
            v_generic,
            k_service,
            k_account,
            k_group,
            k_accessible,
            v_accessible,
            k_sync,
            k_dp,
            k_value,
        ) = unsafe {
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassGenericPassword),
                CFString::wrap_under_get_rule(kSecAttrService),
                CFString::wrap_under_get_rule(kSecAttrAccount),
                CFString::wrap_under_get_rule(kSecAttrAccessGroup),
                CFString::wrap_under_get_rule(kSecAttrAccessible),
                CFString::wrap_under_get_rule(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
                CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain),
                CFString::wrap_under_get_rule(kSecValueData),
            )
        };
        let query = CFDictionary::<CFString, CFType>::from_CFType_pairs(&[
            (k_class.clone(), v_generic.as_CFType()),
            (k_service.clone(), service.as_CFType()),
            (k_account.clone(), account.as_CFType()),
            (k_group.clone(), group.as_CFType()),
            (k_sync.clone(), CFBoolean::false_value().as_CFType()),
            (k_dp.clone(), CFBoolean::true_value().as_CFType()),
        ]);
        let updates = CFDictionary::<CFString, CFType>::from_CFType_pairs(&[
            (k_value.clone(), value_data.as_CFType()),
            (k_accessible.clone(), v_accessible.as_CFType()),
        ]);
        // SAFETY: query and updates are live CFDictionaries.
        let status =
            unsafe { SecItemUpdate(query.as_concrete_TypeRef(), updates.as_concrete_TypeRef()) };
        match status {
            ERR_SEC_SUCCESS => Ok(()),
            ERR_SEC_ITEM_NOT_FOUND => {
                let add = CFDictionary::<CFString, CFType>::from_CFType_pairs(&[
                    (k_class, v_generic.as_CFType()),
                    (k_service, service.as_CFType()),
                    (k_account, account.as_CFType()),
                    (k_group, group.as_CFType()),
                    (k_accessible, v_accessible.as_CFType()),
                    (k_sync, CFBoolean::false_value().as_CFType()),
                    (k_dp, CFBoolean::true_value().as_CFType()),
                    (k_value, value_data.as_CFType()),
                ]);
                // SAFETY: add is a live CFDictionary; result is null because no
                // return reference is requested.
                let add_status =
                    unsafe { SecItemAdd(add.as_concrete_TypeRef(), core::ptr::null_mut()) };
                match add_status {
                    ERR_SEC_SUCCESS => Ok(()),
                    ERR_SEC_MISSING_ENTITLEMENT => Err(KeychainAnchorError::Unavailable),
                    _ => Err(KeychainAnchorError::Storage),
                }
            }
            ERR_SEC_MISSING_ENTITLEMENT => Err(KeychainAnchorError::Unavailable),
            _ => Err(KeychainAnchorError::Storage),
        }
    }
}
