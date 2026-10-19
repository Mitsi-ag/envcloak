//! App-role admission and handlers (`app.unlock.*`, `app.unlocker.enroll.*`).
//! A code-identity verdict belongs only to the accepted connection.

pub(crate) mod enroll;
pub(crate) mod unlock;

use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;

use envcloak_core::crypto::SeEnrolledUnder;
use envcloak_sys::{
    PeerIdentity,
    peer_code::{self, CodeVerdict, pins},
};

/// Checks whether the peer on `stream` satisfies the app-role requirement and
/// returns the verified `(team_id, signing_id)` when it does.
pub(crate) fn verified(stream: &UnixStream, peer: &PeerIdentity) -> Option<SeEnrolledUnder> {
    match pins::app() {
        Ok(Some(pin)) => {
            let token = peer_code::audit_token(stream.as_fd()).ok()?;
            if matches!(
                peer_code::peer_satisfies(&token, peer, &pin),
                Ok(CodeVerdict::Satisfies)
            ) && envcloak_sys::peer_unchanged(stream.as_fd(), peer).unwrap_or(false)
            {
                Some(SeEnrolledUnder {
                    team_id: pin.team_id().to_owned(),
                    signing_id: pin.signing_id().to_owned(),
                })
            } else {
                None
            }
        }
        Ok(None) => {
            let (team_id, signing_id) = envcloak_sys::test_app_identity(peer.pid)?;
            if envcloak_sys::peer_unchanged(stream.as_fd(), peer).unwrap_or(false) {
                Some(SeEnrolledUnder {
                    team_id,
                    signing_id,
                })
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

/// Lowercase hex encoding.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decodes `2 * N` hex characters into `[u8; N]`.
pub(crate) fn decode_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Decodes `N` bytes from `2 * N` hex characters or standard padded base64.
pub(crate) fn decode_fixed_bytes<const N: usize>(s: &str) -> Option<[u8; N]> {
    if let Some(hex) = decode_hex::<N>(s) {
        return Some(hex);
    }
    decode_base64::<N>(s)
}

fn decode_base64<const N: usize>(s: &str) -> Option<[u8; N]> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    for chunk in bytes.chunks_exact(4) {
        let a = b64_val(chunk[0])?;
        let b = b64_val(chunk[1])?;
        let c = if chunk[2] == b'=' {
            if chunk[3] != b'=' {
                return None;
            }
            None
        } else {
            Some(b64_val(chunk[2])?)
        };
        let d = if chunk[3] == b'=' {
            None
        } else {
            Some(b64_val(chunk[3])?)
        };
        out.push((a << 2) | (b >> 4));
        if let Some(c) = c {
            out.push(((b & 0x0f) << 4) | (c >> 2));
            if let Some(d) = d {
                out.push(((c & 0x03) << 6) | d);
            } else if (c & 0x03) != 0 {
                return None;
            }
        } else if (b & 0x0f) != 0 {
            return None;
        }
    }
    out.as_slice().try_into().ok()
}

fn b64_val(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
