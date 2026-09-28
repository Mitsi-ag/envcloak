//! The verified client (SPEC §4.1, §4.2).
//!
//! [`Client::connect`] checks, in order, before it sends a byte:
//! 1. the runtime directory is a real directory of this uid, not writable
//!    by others, in a parent no other user controls;
//! 2. the socket file is a socket of this uid;
//! 3. after connecting, the kernel reports that the process holding the
//!    other end runs as this uid (`getpeereid` on macOS, `SO_PEERCRED` on
//!    Linux).
//!
//! A missing directory, socket or listener means no daemon is running:
//! [`ClientError::Unavailable`]. The client never starts one, and never
//! looks for `envcloakd` on `PATH`; the CLI says how to start it. Anything
//! else that fails a check is [`ClientError::Unverified`], and nothing is
//! sent. The socket is opened close-on-exec, so a child the CLI starts
//! does not inherit the connection.
//!
//! On signed macOS builds the client will also check the daemon's code
//! signature from its audit token (M3). Builds that pin no signing
//! identity, which is every M1 build, cannot, and say so:
//! [`DaemonIdentity::Unverified`]. On them a program running as the same
//! user can impersonate the daemon (SPEC §1.1).

use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use envcloak_core::SecretBytes;

use crate::frame::{Frame, FrameError};
use crate::paths::{RunPathError, RunPathErrorKind, RunPaths};
use crate::proto::{
    self, Lock, Method, NoParams, ResponseError, RpcError, Status, Unlock, UnlockParams,
    VaultCreate, VaultCreateParams,
};
use crate::view::{CreatedView, LockedView, StatusView, UnlockedView};
use crate::wire_secret::WireSecret;

/// How long a call may wait for its response. `vault create` runs
/// Argon2id twice, at up to 4 GiB each.
const CALL_TIMEOUT: Duration = Duration::from_secs(300);

/// Whether the client verified the daemon's code identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DaemonIdentity {
    /// The daemon's code signature matched the pinned identity.
    Verified,
    /// This build pins no signing identity, so only the daemon's uid was
    /// checked: `daemon identity unverified` in `envcloak status`.
    Unverified,
}

/// Why the socket could not be trusted. Nothing was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unverified {
    /// The runtime directory failed a check.
    Directory(RunPathErrorKind),
    /// The socket file failed a check.
    Socket(RunPathErrorKind),
    /// The process at the other end runs as another user.
    ForeignServer,
    /// The kernel did not report who is at the other end.
    PeerUnknown,
}

impl Unverified {
    /// The fixed message.
    pub fn message(self) -> &'static str {
        match self {
            Unverified::Directory(k) | Unverified::Socket(k) => k.message(),
            Unverified::ForeignServer => {
                "the process listening on the daemon socket runs as another user"
            }
            Unverified::PeerUnknown => "the kernel did not report who is listening on the socket",
        }
    }
}

/// A failed connection or call. Carries kinds and fixed tokens only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientError {
    /// No daemon is running: no runtime directory, no socket, or nothing
    /// listening.
    Unavailable,
    /// The socket or the process behind it could not be verified; nothing
    /// was sent.
    Unverified(Unverified),
    /// The runtime location cannot be used at all.
    Paths(RunPathErrorKind),
    /// The connection failed during a call.
    Frame(FrameError),
    /// The daemon answered with an error.
    Rpc(RpcError),
    /// The daemon's answer was malformed or answered another request.
    Protocol,
}

impl ClientError {
    /// The stable token the CLI prints.
    pub fn token(self) -> &'static str {
        match self {
            ClientError::Unavailable | ClientError::Paths(_) | ClientError::Frame(_) => {
                "daemon_unavailable"
            }
            ClientError::Unverified(_) => "daemon_unverified",
            ClientError::Rpc(e) => e.kind.token(),
            ClientError::Protocol => "protocol_error",
        }
    }
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClientError::Unavailable => f.write_str("the EnvCloak daemon is not running"),
            ClientError::Unverified(u) => f.write_str(u.message()),
            ClientError::Paths(k) => f.write_str(k.message()),
            ClientError::Frame(e) => e.fmt(f),
            ClientError::Rpc(e) => e.fmt(f),
            ClientError::Protocol => f.write_str("the daemon's answer was malformed"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<FrameError> for ClientError {
    fn from(e: FrameError) -> Self {
        ClientError::Frame(e)
    }
}

impl From<RunPathError> for ClientError {
    fn from(e: RunPathError) -> Self {
        ClientError::Paths(e.kind())
    }
}

/// A connection to a verified daemon.
#[derive(Debug)]
pub struct Client {
    stream: UnixStream,
    next_id: u64,
}

impl Client {
    /// Connects to the daemon at `p` and verifies it (see the module
    /// documentation) before anything is sent.
    ///
    /// # Errors
    /// [`ClientError::Unavailable`] when no daemon is running,
    /// [`ClientError::Unverified`] when a check fails.
    pub fn connect(p: &RunPaths) -> Result<Client, ClientError> {
        Self::connect_as(p, envcloak_sys::effective_uid())
    }

    /// Test support only (feature `testing`): connects as
    /// [`Client::connect`] does, but requires the daemon to run as `uid`,
    /// so a test can present a same-uid server as a foreign one.
    #[cfg(feature = "testing")]
    pub fn connect_expecting_uid(p: &RunPaths, uid: u32) -> Result<Client, ClientError> {
        Self::connect_as(p, uid)
    }

    fn connect_as(p: &RunPaths, uid: u32) -> Result<Client, ClientError> {
        match p.check_dir() {
            Ok(()) => {}
            Err(e) if e.kind() == RunPathErrorKind::Missing => {
                return Err(ClientError::Unavailable);
            }
            Err(e) => return Err(ClientError::Unverified(Unverified::Directory(e.kind()))),
        }
        match p.check_socket() {
            Ok(()) => {}
            Err(e) if e.kind() == RunPathErrorKind::Missing => {
                return Err(ClientError::Unavailable);
            }
            Err(e) => return Err(ClientError::Unverified(Unverified::Socket(e.kind()))),
        }
        // std opens Unix sockets close-on-exec.
        let stream = match UnixStream::connect(&p.socket) {
            Ok(s) => s,
            Err(e) => {
                return Err(match e.kind() {
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound => {
                        ClientError::Unavailable
                    }
                    k => ClientError::Unverified(Unverified::Socket(RunPathErrorKind::Io(k))),
                });
            }
        };
        // Before a byte is sent: who is at the other end.
        let server = envcloak_sys::peer_uid(stream.as_fd())
            .map_err(|_| ClientError::Unverified(Unverified::PeerUnknown))?;
        if server != uid {
            return Err(ClientError::Unverified(Unverified::ForeignServer));
        }
        let timeouts = stream
            .set_read_timeout(Some(CALL_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(CALL_TIMEOUT)));
        timeouts.map_err(|e| ClientError::Frame(FrameError::Io(e.kind())))?;
        Ok(Client { stream, next_id: 1 })
    }

    /// Whether the daemon's code identity was verified. Always
    /// [`DaemonIdentity::Unverified`] in M1 builds, which pin none.
    pub fn identity(&self) -> DaemonIdentity {
        DaemonIdentity::Unverified
    }

    /// Calls method `M`. The request frame, which may hold a value, is
    /// wiped as soon as it is sent.
    ///
    /// # Errors
    /// [`ClientError::Rpc`] for an error response, [`ClientError::Frame`]
    /// when the connection fails, [`ClientError::Protocol`] for a
    /// malformed response.
    pub fn call<M: Method>(&mut self, params: &M::Params) -> Result<M::Output, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        let request = proto::request_frame::<M>(id, params)?;
        request.write_to(&mut self.stream)?;
        drop(request);
        let response = Frame::read_from(&mut self.stream)?;
        proto::parse_response::<M::Output>(&response, id).map_err(|e| match e {
            ResponseError::Rpc(e) => ClientError::Rpc(e),
            ResponseError::Protocol => ClientError::Protocol,
        })
    }

    /// `status`, with the daemon's strings checked
    /// ([`StatusView::sanitize`]).
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn status(&mut self) -> Result<StatusView, ClientError> {
        let mut s = self.call::<Status>(&NoParams {})?;
        s.sanitize();
        Ok(s)
    }

    /// `vault.create` with the passphrase and the kit's text.
    ///
    /// # Errors
    /// As [`Client::call`]. An error does not always mean that no vault was
    /// created: after a [`ClientError::Frame`] or [`ClientError::Protocol`]
    /// the daemon may have created it before the answer was lost.
    pub fn vault_create(
        &mut self,
        passphrase: SecretBytes,
        recovery_kit: SecretBytes,
        kdf_memory_kib: Option<u32>,
    ) -> Result<CreatedView, ClientError> {
        let params = VaultCreateParams {
            passphrase: WireSecret::new(passphrase),
            recovery_kit: WireSecret::new(recovery_kit),
            kdf_memory_kib,
        };
        self.call::<VaultCreate>(&params)
    }

    /// `unlock` with the passphrase.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn unlock(&mut self, passphrase: SecretBytes) -> Result<UnlockedView, ClientError> {
        self.call::<Unlock>(&UnlockParams {
            passphrase: WireSecret::new(passphrase),
        })
    }

    /// `lock`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn lock(&mut self) -> Result<LockedView, ClientError> {
        self.call::<Lock>(&NoParams {})
    }
}

impl AsFd for Client {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }
}
