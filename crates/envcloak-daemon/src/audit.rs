//! Security events the daemon records (SPEC §3 principle 4, §4.3, gate
//! 22).
//!
//! Until the sealed audit log arrives (T10), each event is one value-free
//! line on the daemon's standard error, which launchd and systemd keep;
//! T10 routes the same events into the sealed, MAC-chained log. Every
//! field is a fixed token or a number: a method name is recorded only
//! through [`envcloak_ipc::proto::loggable_method`], because a name a
//! client sent can hold anything.

/// An event worth recording. The ids in it are the daemon's own
/// (Crockford base32) and the tokens fixed; nothing a client sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    /// A client-role peer called an `app`-role method.
    RoleDenied {
        method: &'static str,
        pid: i32,
        uid: u32,
    },
    /// A peer running as another uid connected; it was closed at accept.
    ForeignPeer { uid: u32 },
    /// A wrong passphrase was offered to `unlock`.
    UnlockFailed { pid: i32 },
    /// A `run.request` was decided: `covered` with the grant id, `pending`
    /// with the request id, `denied` with the reason, or `policy_denied`.
    Request {
        pid: i32,
        decision: &'static str,
        id: String,
    },
    /// A pending request was approved into a grant.
    Approved {
        pid: i32,
        request: String,
        grant: String,
    },
    /// An `approve` failed its proof.
    ApproveFailed { pid: i32, reason: &'static str },
    /// A proof was refused because of the caller's evidence, for the
    /// reason's token (`envcloak_policy::ProofRefusal::token`).
    ProofRefused {
        pid: i32,
        method: &'static str,
        reason: &'static str,
    },
    /// A pending request was denied.
    Denied {
        pid: i32,
        request: String,
        root_auto_denied: bool,
    },
    /// Grants were revoked.
    Revoked { pid: i32, count: usize },
    /// A covered request came with a manifest whose hash differs from the
    /// one at approval; the bindings were still a subset (SPEC §10b). The
    /// hashes are SHA-256 digests of the manifest's bytes, at approval and
    /// now.
    ManifestChanged {
        pid: i32,
        grant: String,
        approved_sha256: [u8; 32],
        sha256: [u8; 32],
    },
}

/// Where events go.
#[derive(Debug)]
pub struct Audit;

impl Audit {
    pub fn record(&self, e: AuditEvent) {
        match e {
            AuditEvent::RoleDenied { method, pid, uid } => eprintln!(
                "envcloakd: audit: denied method={method} reason=role_denied role=client pid={pid} uid={uid}"
            ),
            AuditEvent::ForeignPeer { uid } => {
                eprintln!("envcloakd: audit: rejected connection reason=foreign_uid uid={uid}")
            }
            AuditEvent::UnlockFailed { pid } => {
                eprintln!("envcloakd: audit: unlock failed reason=wrong_passphrase pid={pid}")
            }
            AuditEvent::Request { pid, decision, id } => {
                eprintln!("envcloakd: audit: request decision={decision} id={id} pid={pid}")
            }
            AuditEvent::Approved {
                pid,
                request,
                grant,
            } => eprintln!("envcloakd: audit: approved request={request} grant={grant} pid={pid}"),
            AuditEvent::ApproveFailed { pid, reason } => {
                eprintln!("envcloakd: audit: approve failed reason={reason} pid={pid}")
            }
            AuditEvent::ProofRefused {
                pid,
                method,
                reason,
            } => {
                eprintln!(
                    "envcloakd: audit: proof refused method={method} reason={reason} pid={pid}"
                )
            }
            AuditEvent::Denied {
                pid,
                request,
                root_auto_denied,
            } => {
                eprintln!("envcloakd: audit: denied request={request} pid={pid}");
                if root_auto_denied {
                    // The notification of SPEC §10a, until there is a
                    // surface for one (M3).
                    eprintln!(
                        "envcloakd: notice: a process tree was denied three times in 10 minutes \
                         and is denied for 30"
                    );
                }
            }
            AuditEvent::Revoked { pid, count } => {
                eprintln!("envcloakd: audit: revoked grants={count} pid={pid}")
            }
            AuditEvent::ManifestChanged {
                pid,
                grant,
                approved_sha256,
                sha256,
            } => eprintln!(
                "envcloakd: audit: manifest changed grant={grant} approved_sha256={} sha256={} \
                 pid={pid}",
                hex(&approved_sha256),
                hex(&sha256)
            ),
        }
    }
}

/// Lower-case hex, as the approval statement shows a manifest's hash.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(2 * bytes.len()), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::hex;

    #[test]
    fn hashes_are_lower_case_hex() {
        assert_eq!(hex(&[0x00, 0xab, 0x7f, 0xff]), "00ab7fff");
        assert_eq!(hex(&[0u8; 32]).len(), 64);
    }
}
