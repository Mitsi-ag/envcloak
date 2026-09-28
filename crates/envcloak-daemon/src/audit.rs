//! Security events the daemon records (SPEC §3 principle 4, §4.3, gate
//! 22).
//!
//! Until the sealed audit log arrives (T10), each event is one value-free
//! line on the daemon's standard error, which launchd and systemd keep;
//! T10 routes the same events into the sealed, MAC-chained log. Every
//! field is a fixed token or a number: a method name is recorded only
//! through [`envcloak_ipc::proto::loggable_method`], because a name a
//! client sent can hold anything.

/// An event worth recording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        }
    }
}
