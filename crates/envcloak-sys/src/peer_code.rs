//! Dynamic code identity from the kernel's audit token (SPEC §4.2, §4.3).
//! No path lookup, pid cache, runtime override or static-only verification.
pub mod pins;

use std::os::fd::BorrowedFd;

/// Opaque kernel token. Only the socket reader can construct one.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuditToken(pub(crate) [u32; 8]);

impl core::fmt::Debug for AuditToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AuditToken")
    }
}

impl AuditToken {
    /// Bind this exact signature token to the previously recorded socket user.
    /// Separate identity reads cannot detect an A -> B -> A descriptor race.
    fn matches_peer(&self, peer: &crate::PeerIdentity) -> bool {
        peer.source == crate::PeerSource::AuditToken
            && peer.pid > 0
            && self.0[1] == peer.uid
            && self.0[5] == peer.pid as u32
            && Some(self.0[7] as i32) == peer.pidversion
    }
}

/// A requirement produced only by this build's pins.
#[derive(Debug)]
pub struct PinnedRequirement(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeVerdict {
    Satisfies,
    Fails(Why),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    Unsigned,
    Requirement,
    RuntimeFlagMissing,
    ExceptionEntitlement,
    Debuggable,
}

/// Fixed errors; Security.framework diagnostics never reach an IPC response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerCodeError {
    Configuration,
    PeerUnknown,
    Security,
    Metadata,
    Unsupported,
}

pub const EXCEPTION_ENTITLEMENTS: &[&str] = &[
    "com.apple.security.cs.allow-jit",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.disable-executable-page-protection",
    "com.apple.security.cs.debugger",
];

/// Entitlement presence refuses, even when its embedded value is false.
pub fn runtime_verdict(runtime: bool, debuggable: bool, entitlements: &[&str]) -> CodeVerdict {
    if !runtime {
        return CodeVerdict::Fails(Why::RuntimeFlagMissing);
    }
    if debuggable {
        return CodeVerdict::Fails(Why::Debuggable);
    }
    if entitlements
        .iter()
        .any(|e| EXCEPTION_ENTITLEMENTS.contains(e))
    {
        return CodeVerdict::Fails(Why::ExceptionEntitlement);
    }
    CodeVerdict::Satisfies
}

/// Reads LOCAL_PEERTOKEN, never a caller-supplied pid or token.
pub fn audit_token(fd: BorrowedFd<'_>) -> Result<AuditToken, PeerCodeError> {
    #[cfg(target_os = "macos")]
    {
        #[cfg(feature = "testing")]
        token_barrier("before-token")?;
        let token = crate::peer::macos::raw_audit_token(fd).map_err(|_| PeerCodeError::PeerUnknown);
        #[cfg(feature = "testing")]
        token_barrier("after-token")?;
        token
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = fd;
        Err(PeerCodeError::Unsupported)
    }
}

// A bounded rendezvous for the native alternating-user test, absent from all
// non-testing builds. build.rs refuses testing in every release configuration.
#[cfg(all(target_os = "macos", feature = "testing"))]
fn token_barrier(stage: &str) -> Result<(), PeerCodeError> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let Some(path) = std::env::var_os("ENVCLOAK_TEST_PEER_BARRIER") else {
        return Ok(());
    };
    let rendezvous = || -> std::io::Result<()> {
        let mut stream = UnixStream::connect(path)?;
        let timeout = Some(std::time::Duration::from_secs(30));
        stream.set_read_timeout(timeout)?;
        stream.set_write_timeout(timeout)?;
        stream.write_all(stage.as_bytes())?;
        let mut ack = [0];
        stream.read_exact(&mut ack)?;
        if ack != [1] {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        Ok(())
    };
    rendezvous().map_err(|_| PeerCodeError::PeerUnknown)
}

/// Checks the running image and then its runtime flags and entitlements.
pub fn peer_satisfies(
    token: &AuditToken,
    peer: &crate::PeerIdentity,
    pin: &PinnedRequirement,
) -> Result<CodeVerdict, PeerCodeError> {
    if !token.matches_peer(peer) {
        return Err(PeerCodeError::PeerUnknown);
    }
    #[cfg(target_os = "macos")]
    {
        macos::check(token, pin)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (token, &pin.0);
        Err(PeerCodeError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_token_must_name_the_recorded_peer() {
        let token = AuditToken([0, 501, 20, 501, 20, 42, 0, 7]);
        let peer = crate::PeerIdentity {
            uid: 501,
            pid: 42,
            pidversion: Some(7),
            start_time: crate::StartTime::from_raw(1),
            source: crate::PeerSource::AuditToken,
        };
        assert!(token.matches_peer(&peer));
        for changed in [
            crate::PeerIdentity { uid: 502, ..peer },
            crate::PeerIdentity { pid: 43, ..peer },
            crate::PeerIdentity {
                pidversion: Some(8),
                ..peer
            },
            crate::PeerIdentity {
                pidversion: None,
                ..peer
            },
            crate::PeerIdentity {
                source: crate::PeerSource::PeerCred,
                ..peer
            },
        ] {
            assert!(!token.matches_peer(&changed));
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use core_foundation::{
        base::{CFType, TCFType},
        data::CFData,
        dictionary::{CFDictionary, CFDictionaryRef},
        number::CFNumber,
        string::{CFString, CFStringRef},
    };
    use security_framework::os::macos::code_signing::{
        Flags, GuestAttributes, SecCode, SecRequirement,
    };

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecCodeCopySigningInformation(
            code: *const core::ffi::c_void,
            flags: u32,
            info: *mut CFDictionaryRef,
        ) -> i32;
        static kSecCodeInfoFlags: CFStringRef;
        static kSecCodeInfoStatus: CFStringRef;
        static kSecCodeInfoEntitlementsDict: CFStringRef;
    }

    pub(super) fn check(
        token: &AuditToken,
        pin: &PinnedRequirement,
    ) -> Result<CodeVerdict, PeerCodeError> {
        // Native-endian audit_token_t: eight initialized u32 words, no padding.
        let bytes: Vec<u8> = token.0.iter().flat_map(|w| w.to_ne_bytes()).collect();
        let data = CFData::from_buffer(&bytes);
        let mut attrs = GuestAttributes::new();
        attrs.set_audit_token(data.as_concrete_TypeRef());
        let code = SecCode::copy_guest_with_attribues(None, &attrs, Flags::NONE)
            .map_err(|_| PeerCodeError::Security)?;
        let requirement: SecRequirement =
            pin.0.parse().map_err(|_| PeerCodeError::Configuration)?;
        if let Err(error) = code.check_validity(Flags::NONE, &requirement) {
            return Ok(CodeVerdict::Fails(if error.code() == -67062 {
                Why::Unsigned
            } else {
                Why::Requirement
            }));
        }
        let mut raw = core::ptr::null();
        // SAFETY: code is live; raw is a writable out-pointer. On success,
        // Copy returns an owned CFDictionary, released by its Rust wrapper.
        let status = unsafe {
            SecCodeCopySigningInformation(code.as_CFTypeRef(), (1 << 1) | (1 << 3), &mut raw)
        };
        if status != 0 || raw.is_null() {
            return Err(PeerCodeError::Security);
        }
        // SAFETY: the successful Copy call returned this owned dictionary.
        let info = unsafe { CFDictionary::<CFString, CFType>::wrap_under_create_rule(raw) };
        // SAFETY: framework constants are process-lifetime CFStrings, retained
        // by wrap_under_get_rule; they are never modified.
        let (flags_key, status_key, entitlements_key) = unsafe {
            (
                CFString::wrap_under_get_rule(kSecCodeInfoFlags),
                CFString::wrap_under_get_rule(kSecCodeInfoStatus),
                CFString::wrap_under_get_rule(kSecCodeInfoEntitlementsDict),
            )
        };
        let number = |key: &CFString| -> Result<i64, PeerCodeError> {
            info.find(key)
                .and_then(|v| v.downcast::<CFNumber>())
                .and_then(|v| v.to_i64())
                .ok_or(PeerCodeError::Metadata)
        };
        let flags = number(&flags_key)?;
        let status = number(&status_key)?;
        let mut names = Vec::new();
        if let Some(value) = info.find(&entitlements_key) {
            let dictionary = value
                .downcast::<CFDictionary>()
                .ok_or(PeerCodeError::Metadata)?;
            for name in EXCEPTION_ENTITLEMENTS
                .iter()
                .copied()
                .chain(["com.apple.security.get-task-allow"])
            {
                if dictionary.contains_key(&CFString::new(name).as_CFTypeRef()) {
                    names.push(name);
                }
            }
        }

        let verdict = runtime_verdict(
            flags & 0x10000 != 0 && status & 0x10000 != 0,
            names.contains(&"com.apple.security.get-task-allow"),
            &names,
        );
        // A process that execs while metadata is read must not keep the verdict.
        code.check_validity(Flags::NONE, &requirement)
            .map_err(|_| PeerCodeError::Security)?;
        Ok(verdict)
    }
}
