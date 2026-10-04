//! M3-01 dependency trial (scratch, never merged): what `security-framework`
//! 3.x covers of D3-06 and D3-12 without `unsafe`: a peer's code from its
//! audit token checked against a requirement, and a data protection
//! keychain item. SecCodeCopySigningInformation (the runtime flag and the
//! entitlements D3-06 also checks) is not wrapped; M3-07 calls it from
//! envcloak-sys.
#[cfg(target_os = "macos")]
mod mac {
    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use security_framework::os::macos::code_signing::{
        Flags, GuestAttributes, SecCode, SecRequirement,
    };
    use security_framework::passwords::{
        delete_generic_password_options, generic_password, set_generic_password_options,
    };
    use security_framework::passwords_options::PasswordOptions;

    /// The guest named by an audit token satisfies `requirement`.
    pub fn satisfies(audit_token: &[u8], requirement: &str) -> bool {
        let Ok(req) = requirement.parse::<SecRequirement>() else {
            return false;
        };
        let data = CFData::from_buffer(audit_token);
        let mut attrs = GuestAttributes::new();
        attrs.set_audit_token(data.as_concrete_TypeRef());
        let Ok(code) = SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE) else {
            return false;
        };
        code.check_validity(Flags::NONE, &req).is_ok()
    }

    /// An anchor item in the data protection keychain (D3-12).
    pub fn anchor_round_trip(service: &str, account: &str, group: &str, bytes: &[u8]) -> bool {
        let opts = || {
            let mut o = PasswordOptions::new_generic_password(service, account);
            o.set_access_group(group);
            o.use_protected_keychain();
            o
        };
        set_generic_password_options(bytes, opts()).is_ok()
            && generic_password(opts()).is_ok_and(|b| b == bytes)
            && delete_generic_password_options(opts()).is_ok()
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn a_malformed_requirement_or_token_is_refused() {
            assert!(!super::satisfies(&[0u8; 32], "identifier \"ai.envcloak.app\""));
            assert!(!super::satisfies(&[0u8; 32], "not a requirement ("));
        }
    }
}

#[cfg(target_os = "macos")]
pub use mac::*;
