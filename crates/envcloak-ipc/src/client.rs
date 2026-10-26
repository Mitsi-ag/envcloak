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
//! looks for `envcloakd` on `PATH`; the CLI says how to start it. Other
//! failures in these connection checks are [`ClientError::Unverified`];
//! no request has been sent. The socket is opened close-on-exec, so a child
//! the CLI starts does not inherit the connection.
//!
//! Every connection is bounded in time from before it connects
//! ([`envcloak_sys::connect_unix`]). An ordinary call waits at most 300
//! seconds for each read and each write (`vault create` runs Argon2id
//! twice). A waiter's connection ([`Client::connect_by`]) is bounded by
//! one instant instead, for the whole call: the connect is given the time
//! left to it, and then, before each read and each write, the socket is
//! waited on (`poll`) for at most the time left, and only what it holds
//! or takes then is read or written, without blocking. So a daemon that
//! stalls, sends its answer a byte at a time, or reads the request slowly
//! cannot hold `envcloak run --wait` past that instant.
//!
//! On signed macOS builds the client also checks the daemon's code
//! signature and runtime policy from its audit token. Builds that pin no
//! signing identity cannot, and say so:
//! [`DaemonIdentity::Unverified`]. On them a program running as the same
//! user can impersonate the daemon (SPEC §1.1).
//!
//! Calls recheck a verified peer before sending and after I/O. Identity loss
//! after sending begins returns [`ClientError::UnverifiedAfterSend`]: delivery
//! is uncertain. Once a verified connection loses its identity, it remains
//! unverified and refuses later calls.

use std::cell::Cell;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use envcloak_core::SecretBytes;
use envcloak_policy::{ApprovalOptions, PendingDescriptor, PendingId, PendingState};

use crate::frame::{Frame, FrameError};
use crate::paths::{RunPathError, RunPathErrorKind, RunPaths};
use crate::proto::{
    self, AddParams, Approve, ApproveParams, AuditVerify, CheckParams, Deny, GrantsList,
    GrantsRevoke, ItemsAdd, ItemsCheck, ItemsList, ItemsRemove, ItemsRotate, ItemsShow,
    ItemsTarget, ListParams, Lock, LoginAdd, LoginAddParams, Method, NoParams, PendingGet,
    PendingGetOutput, PendingGetParams, RemoveParams, RequestParams, ResponseError, RevokeParams,
    RotateParams, RpcError, RunAnswer, RunRequest, RunRequestParams, SlugParams, Status,
    TargetParams, Unlock, UnlockParams, VaultCreate, VaultCreateParams,
};
use crate::proto::{
    BackupBegin, BackupBeginParams, BackupChunk, BackupCommit, BackupIdParams, BackupList,
    BackupOpenRestore, BackupPut, BackupPutParams, BackupRead, BackupReadParams,
    BackupRecordResult, BackupResultParams, OpenRestoreParams,
};
use crate::proto::{
    BackupCreate, FilesBackup, FilesBackupParams, FilesRestore, FilesRestoreParams, FilesShow,
    FilesShowParams, FilesShown, ImportCommit, ImportCommitParams, ImportParams, ImportPlan,
    ImportVerify, PendingList, PendingListParams, PendingPoll, PendingStateParams, RecoverParams,
    RecoveryConfirm, RecoveryConfirmParams, RestoredFiles, VaultRecover, VerifyParams,
};
use crate::proto::{
    FdRole, ManagedRegister, ManagedRegisterParams, ManagedUnregister, ManagedUnregisterParams,
    ManagedUpdate, ManagedUpdateParams, ManagedUpdatePlan, ManagedUpdatePlanParams,
};
use crate::proto::{ItemsMarkExposed, MarkExposedParams, ScanMatch, ScanMatchParams};
use crate::proto::{ItemsReclassify, ReclassifyParams};
use crate::view::{
    AddedView, ApprovedView, AuditVerifyView, CheckView, CreatedView, DeniedView, GrantsView,
    ItemView, ItemsView, LockedView, LoginAddedView, RemovedView, RevokedView, RotatedView,
    StatusView, TargetView, UnlockedView,
};
use crate::view::{
    BackupBegunView, BackupCommittedView, BackupListView, BackupPutView, BackupResultView,
    RestoreLeaseView,
};
use crate::view::{
    BackupView, FileBackupView, ImportPlanView, PendingListView, RecoveredView,
    RecoveryConfirmedView, VerifyView,
};
use crate::view::{ClassificationView, ReclassifiedView};
use crate::view::{
    ManagedRegisteredView, ManagedUnregisteredView, ManagedUpdatePlanView, ManagedUpdatedView,
};
use crate::view::{MarkedView, ScanMatchView};
use crate::wire_secret::WireSecret;

/// How long a call may wait for its response. `vault create` runs
/// Argon2id twice, at up to 4 GiB each.
const CALL_TIMEOUT: Duration = Duration::from_secs(300);

#[cfg(all(test, target_os = "macos"))]
mod identity_tests {
    use super::*;

    #[test]
    fn an_observed_identity_loss_permanently_invalidates_the_connection() {
        let (stream, _peer_stream) = UnixStream::pair().expect("socket pair");
        let peer = envcloak_sys::peer_identity(stream.as_fd()).expect("kernel identity");
        let mut client = Client {
            stream,
            verified_peer: Some(peer),
            identity_lost: Cell::new(false),
            next_id: 1,
            by: None,
        };
        assert_eq!(client.identity(), DaemonIdentity::Verified);
        client.verified_peer.as_mut().expect("peer").pidversion = None;
        assert_eq!(client.identity(), DaemonIdentity::Unverified);
        client.verified_peer = Some(peer);
        assert_eq!(client.identity(), DaemonIdentity::Unverified);
        assert_eq!(
            client.check_peer(true),
            Err(ClientError::UnverifiedAfterSend)
        );
        assert_eq!(
            client.check_peer(false),
            Err(ClientError::Unverified(Unverified::CodeIdentity))
        );
    }
}

fn verify_code_identity(
    stream: &UnixStream,
) -> Result<Option<envcloak_sys::PeerIdentity>, ClientError> {
    use envcloak_sys::peer_code::{self, CodeVerdict, pins};
    let denied = || ClientError::Unverified(Unverified::CodeIdentity);
    let Some(pin) = pins::agent().map_err(|_| denied())? else {
        return Ok(None);
    };
    let peer = envcloak_sys::peer_identity(stream.as_fd()).map_err(|_| denied())?;
    let token = peer_code::audit_token(stream.as_fd()).map_err(|_| denied())?;
    if peer_code::peer_satisfies(&token, &peer, &pin).map_err(|_| denied())?
        != CodeVerdict::Satisfies
        || !envcloak_sys::peer_unchanged(stream.as_fd(), &peer).unwrap_or(false)
    {
        return Err(denied());
    }
    Ok(Some(peer))
}

/// Whether the client verified the daemon's code identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DaemonIdentity {
    /// The daemon's code signature matched the pinned identity.
    Verified,
    /// This build pins no signing identity, or this connection observed an
    /// identity loss: `daemon identity unverified` in `envcloak status`.
    Unverified,
}

/// Why the socket could not be trusted before sending this request.
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
    /// The daemon failed the embedded code requirement or runtime policy.
    CodeIdentity,
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
            Unverified::CodeIdentity => {
                "code_identity: the daemon's code identity could not be verified"
            }
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
    /// was sent for this request.
    Unverified(Unverified),
    /// Identity changed after writing began. Delivery and the result are unknown.
    UnverifiedAfterSend,
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
            ClientError::Unverified(_) | ClientError::UnverifiedAfterSend => "daemon_unverified",
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
            ClientError::UnverifiedAfterSend => f.write_str(
                "code_identity: the daemon's identity changed after sending began; delivery is uncertain",
            ),
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

/// Outcome of [`Client::wait_for_ask`] (`envcloak add --ask`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AskWaitOutcome {
    /// The person pasted and saved the new item under `slug`.
    Added { slug: String },
    /// The person declined the ask.
    Declined,
    /// The ask expired or the wait deadline passed while it was still pending.
    Expired,
}

/// Outcome of [`Client::wait_for_reveal`] (`envcloak reveal` on macOS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevealWaitOutcome {
    /// The person completed the signed reveal in the app.
    Shown,
    /// The person declined the reveal request.
    Declined,
    /// The reveal request expired or the wait deadline passed while it was still pending.
    Expired,
}

/// A connection to a verified daemon.
#[derive(Debug)]
pub struct Client {
    stream: UnixStream,
    verified_peer: Option<envcloak_sys::PeerIdentity>,
    identity_lost: Cell<bool>,
    next_id: u64,
    /// For a waiter's connection ([`Client::connect_by`]): the instant by
    /// which every call on it must be answered.
    by: Option<Instant>,
}

/// How long a connection may take.
#[derive(Debug, Clone, Copy)]
enum Limit {
    /// Each read and each write, and the connect, at most this long.
    Each(Duration),
    /// Everything done on it, connect included, by this instant.
    By(Instant),
}

/// The time left to `by`, or a timeout when less than a millisecond is.
fn left(by: Instant) -> io::Result<Duration> {
    by.checked_duration_since(Instant::now())
        .filter(|d| *d >= Duration::from_millis(1))
        .ok_or_else(|| io::ErrorKind::TimedOut.into())
}

/// A non-blocking stream read and written only until `by`: before each
/// read or write the socket is waited on for at most the time left, and
/// past `by` the read or write fails with [`io::ErrorKind::TimedOut`].
/// However the peer paces its bytes, nothing here waits beyond `by`.
struct Bounded<'a> {
    stream: &'a UnixStream,
    by: Instant,
}

impl Bounded<'_> {
    /// Runs `op` once the socket is ready, as `ready` says, retrying while
    /// it would block, until `by`.
    fn when_ready<T>(
        &mut self,
        ready: fn(BorrowedFd<'_>, Duration) -> io::Result<bool>,
        mut op: impl FnMut(&UnixStream) -> io::Result<T>,
    ) -> io::Result<T> {
        loop {
            match ready(self.stream.as_fd(), left(self.by)?) {
                // Not ready in the time left: looked at again, and past
                // `by` that is the timeout.
                Ok(false) => continue,
                Ok(true) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
            match op(self.stream) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                r => return r,
            }
        }
    }
}

impl Read for Bounded<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.when_ready(envcloak_sys::wait_readable, |mut s| s.read(buf))
    }
}

impl Write for Bounded<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.when_ready(envcloak_sys::wait_writable, |mut s| s.write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Client {
    /// Connects to the daemon at `p` and verifies it (see the module
    /// documentation) before anything is sent.
    ///
    /// # Errors
    /// [`ClientError::Unavailable`] when no daemon is running,
    /// [`ClientError::Unverified`] when a check fails.
    pub fn connect(p: &RunPaths) -> Result<Client, ClientError> {
        Self::connect_as(p, envcloak_sys::effective_uid(), Limit::Each(CALL_TIMEOUT))
    }

    /// Connects as [`Client::connect`] does, for calls that must all be
    /// answered by `by` (taken as 300 seconds away when it is further, as
    /// an ordinary call's timeout): the connect is given
    /// the time left to it, and every call after waits for the socket,
    /// before each write and each read, only for the time then left (see
    /// the module documentation). A waiter passes the limit of its wait
    /// ([`crate::wait`]).
    ///
    /// # Errors
    /// As [`Client::connect`]; [`ClientError::Frame`] with
    /// [`std::io::ErrorKind::TimedOut`] or
    /// [`std::io::ErrorKind::WouldBlock`] when the daemon did not take the
    /// connection by `by`. A call on it fails the same way, with
    /// [`FrameError::Truncated`] inside an answer, when `by` passes.
    pub fn connect_by(p: &RunPaths, by: Instant) -> Result<Client, ClientError> {
        Self::connect_as(p, envcloak_sys::effective_uid(), Limit::By(by))
    }

    /// Test support only (feature `testing`): connects as
    /// [`Client::connect`] does, but requires the daemon to run as `uid`,
    /// so a test can present a same-uid server as a foreign one.
    #[cfg(feature = "testing")]
    pub fn connect_expecting_uid(p: &RunPaths, uid: u32) -> Result<Client, ClientError> {
        Self::connect_as(p, uid, Limit::Each(CALL_TIMEOUT))
    }

    fn connect_as(p: &RunPaths, uid: u32, limit: Limit) -> Result<Client, ClientError> {
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
        let (within, by) = match limit {
            Limit::Each(d) => (d, None),
            Limit::By(by) => {
                // Never further away than an ordinary call's timeout.
                let by = Instant::now()
                    .checked_add(CALL_TIMEOUT)
                    .map_or(by, |most| by.min(most));
                let d = left(by).map_err(|e| ClientError::Frame(FrameError::Io(e.kind())))?;
                (d, Some(by))
            }
        };
        // Close-on-exec, with its timeouts set before it connects.
        let stream = match envcloak_sys::connect_unix(&p.socket, within) {
            Ok(s) => s,
            Err(e) => {
                return Err(match e.kind() {
                    std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound => {
                        ClientError::Unavailable
                    }
                    // A listener there that did not take the connection in
                    // time: a daemon too busy or stalled.
                    k @ (std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                        ClientError::Frame(FrameError::Io(k))
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
        let verified_peer = verify_code_identity(&stream)?;
        // A waiter's calls never block on the socket: each read and write
        // waits for it only for the time left (`Bounded`).
        if by.is_some() {
            stream
                .set_nonblocking(true)
                .map_err(|e| ClientError::Frame(FrameError::Io(e.kind())))?;
        }
        Ok(Client {
            stream,
            verified_peer,
            identity_lost: Cell::new(false),
            next_id: 1,
            by,
        })
    }

    /// Whether this connection verified the daemon and still names that peer.
    pub fn identity(&self) -> DaemonIdentity {
        if self.identity_lost.get() {
            return DaemonIdentity::Unverified;
        }
        match &self.verified_peer {
            Some(peer)
                if envcloak_sys::peer_unchanged(self.stream.as_fd(), peer).unwrap_or(false) =>
            {
                DaemonIdentity::Verified
            }
            Some(_) => {
                self.identity_lost.set(true);
                DaemonIdentity::Unverified
            }
            None => DaemonIdentity::Unverified,
        }
    }

    /// Calls method `M`. The request frame, which may hold a value, is
    /// wiped as soon as it is sent.
    ///
    /// # Errors
    /// [`ClientError::Unverified`] when the recorded peer changed before sending,
    /// [`ClientError::Rpc`] for an error response, [`ClientError::Frame`]
    /// when the connection fails, [`ClientError::Protocol`] for a
    /// malformed response, [`ClientError::UnverifiedAfterSend`] when identity
    /// is lost after sending began. Such a call may already have taken effect.
    pub fn call<M: Method>(&mut self, params: &M::Params) -> Result<M::Output, ClientError> {
        self.check_peer(false)?;
        let id = self.next_id;
        self.next_id += 1;
        let request = proto::request_frame::<M>(id, params)?;
        let response = (|| -> Result<Frame, FrameError> {
            match self.by {
                None => {
                    request.write_to(&mut self.stream)?;
                    drop(request);
                    Frame::read_from(&mut self.stream)
                }
                Some(by) => {
                    let mut s = Bounded {
                        stream: &self.stream,
                        by,
                    };
                    request.write_to(&mut s)?;
                    drop(request);
                    Frame::read_from(&mut s)
                }
            }
        })();
        // Check even after a partial write or failed read. Neither proves that
        // the request was undelivered; a changed peer permanently poisons it.
        self.check_peer(true)?;
        proto::parse_response::<M::Output>(&response?, id).map_err(|e| match e {
            ResponseError::Rpc(e) => ClientError::Rpc(e),
            ResponseError::Protocol => ClientError::Protocol,
        })
    }

    fn check_peer(&self, sent: bool) -> Result<(), ClientError> {
        if self.verified_peer.is_some() && self.identity() != DaemonIdentity::Verified {
            return Err(if sent {
                ClientError::UnverifiedAfterSend
            } else {
                ClientError::Unverified(Unverified::CodeIdentity)
            });
        }
        Ok(())
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
    /// created: after a [`ClientError::Frame`], [`ClientError::Protocol`] or
    /// [`ClientError::UnverifiedAfterSend`]
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

    /// `unlock` with the passphrase, claiming the agent marker names
    /// `claims` (`envcloak_policy::Claims::from_env`).
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn unlock(
        &mut self,
        passphrase: SecretBytes,
        claims: &[String],
    ) -> Result<UnlockedView, ClientError> {
        self.call::<Unlock>(&UnlockParams {
            passphrase: WireSecret::new(passphrase),
            claims: claims.to_vec(),
        })
    }

    /// `lock`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn lock(&mut self) -> Result<LockedView, ClientError> {
        self.call::<Lock>(&NoParams {})
    }

    /// `run.request`: the decision for a run, and the values a covered
    /// one releases.
    ///
    /// # Errors
    /// As [`Client::call`], and [`ClientError::Protocol`] for an answer
    /// that is not [`RunAnswer::well_formed`]; its values are dropped, and
    /// wiped, unused.
    pub fn run_request(&mut self, p: &RunRequestParams) -> Result<RunAnswer, ClientError> {
        let answer = self.call::<RunRequest>(p)?;
        if answer.well_formed() {
            Ok(answer)
        } else {
            Err(ClientError::Protocol)
        }
    }

    /// `pending.get` for a run request `id`, with the caller's claims (the
    /// daemon serves it only to a caller that may give a proof).
    ///
    /// # Errors
    /// As [`Client::call`], and [`ClientError::Protocol`] when `id` is an
    /// `unlocker_add` request rather than a run request.
    pub fn pending_get(
        &mut self,
        id: &str,
        claims: &[String],
    ) -> Result<PendingDescriptor, ClientError> {
        match self.pending_get_any(id, claims)? {
            PendingGetOutput::Run(d) => Ok(d),
            PendingGetOutput::UnlockerAdd(_) | PendingGetOutput::SignIn(_) => {
                Err(ClientError::Protocol)
            }
        }
    }

    /// `pending.get` for request `id`, returning either a run request's
    /// [`PendingDescriptor`], an `unlocker_add` request's descriptor, or a
    /// sign-in request's [`envcloak_policy::SignInPendingDescriptor`].
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn pending_get_any(
        &mut self,
        id: &str,
        claims: &[String],
    ) -> Result<PendingGetOutput, ClientError> {
        self.call::<PendingGet>(&PendingGetParams {
            request: id.to_owned(),
            claims: claims.to_vec(),
        })
    }

    /// `pending.state` for request `id`: how it stands, told only to the
    /// request's own process tree (`unknown` to anyone else). One call on
    /// this connection; a waiter connects afresh for each.
    ///
    /// # Errors
    /// As [`Client::call`]; [`crate::ErrorKind::Busy`] when the caller's
    /// root asks too often.
    pub fn pending_state(&mut self, id: &PendingId) -> Result<PendingState, ClientError> {
        self.pending_state_str(&id.to_string())
    }

    /// `pending.state` for request `id` (either a `PendingId` or a sign-in
    /// `RequestId`): how it stands, told only to the request's own process
    /// tree (`unknown` to anyone else).
    ///
    /// # Errors
    /// As [`Client::call`]; [`crate::ErrorKind::Busy`] when the caller's
    /// root asks too often.
    pub fn pending_state_str(&mut self, id: &str) -> Result<PendingState, ClientError> {
        self.call::<PendingPoll>(&PendingStateParams {
            request: id.to_owned(),
        })
        .map(|v| v.state)
    }

    /// `pending.list`, with the caller's claims: the requests waiting for
    /// approval that this caller may approve.
    ///
    /// # Errors
    /// As [`Client::call`], and [`ClientError::Protocol`] for an answer
    /// that is not [`PendingListView::well_formed`].
    pub fn pending_list(&mut self, claims: &[String]) -> Result<PendingListView, ClientError> {
        let list = self.call::<PendingList>(&PendingListParams {
            claims: claims.to_vec(),
        })?;
        if list.well_formed() {
            Ok(list)
        } else {
            Err(ClientError::Protocol)
        }
    }

    /// `approve` request `id` with `options`, the `digest` of the
    /// statement read, the passphrase, and the approver's claims.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn approve(
        &mut self,
        id: &str,
        options: ApprovalOptions,
        digest: &[u8; 32],
        passphrase: SecretBytes,
        claims: &[String],
    ) -> Result<ApprovedView, ClientError> {
        self.approve_with_dev(id, options, None, digest, passphrase, claims)
    }

    /// `approve` request `id` with `options`, optional sign-in `dev` window
    /// options, the `digest` of the statement read, the passphrase, and the
    /// approver's claims.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn approve_with_dev(
        &mut self,
        id: &str,
        options: ApprovalOptions,
        dev: Option<envcloak_policy::SignInDevOptions>,
        digest: &[u8; 32],
        passphrase: SecretBytes,
        claims: &[String],
    ) -> Result<ApprovedView, ClientError> {
        self.call::<Approve>(&ApproveParams {
            request: id.to_owned(),
            options,
            dev,
            digest: digest.iter().map(|b| format!("{b:02x}")).collect(),
            passphrase: Some(WireSecret::new(passphrase)),
            claims: claims.to_vec(),
        })
    }

    /// `approve` of request `id` without the passphrase: a check that never
    /// grants (see [`Approve`]). The daemon refuses with the first check
    /// before the proof that fails (`live_not_ticked`, audited, where the
    /// live-key guard does), or `invalid_params` when none does.
    ///
    /// # Errors
    /// As [`Client::call`]; an answer that is not an error is the daemon's
    /// to explain, and the caller treats it as malformed.
    pub fn approve_check(
        &mut self,
        id: &str,
        options: ApprovalOptions,
        digest: &[u8; 32],
        claims: &[String],
    ) -> Result<ApprovedView, ClientError> {
        self.approve_check_with_dev(id, options, None, digest, claims)
    }

    /// `approve` of request `id` without the passphrase, carrying optional
    /// sign-in `dev` window options.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn approve_check_with_dev(
        &mut self,
        id: &str,
        options: ApprovalOptions,
        dev: Option<envcloak_policy::SignInDevOptions>,
        digest: &[u8; 32],
        claims: &[String],
    ) -> Result<ApprovedView, ClientError> {
        self.call::<Approve>(&ApproveParams {
            request: id.to_owned(),
            options,
            dev,
            digest: digest.iter().map(|b| format!("{b:02x}")).collect(),
            passphrase: None,
            claims: claims.to_vec(),
        })
    }

    /// `deny` request `id`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn deny(&mut self, id: &str) -> Result<DeniedView, ClientError> {
        self.call::<Deny>(&RequestParams {
            request: id.to_owned(),
        })
    }

    /// `grants.list`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn grants_list(&mut self) -> Result<GrantsView, ClientError> {
        self.call::<GrantsList>(&NoParams {})
    }

    /// `grants.revoke` for grant `id`, or every grant.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn grants_revoke(&mut self, id: Option<&str>) -> Result<RevokedView, ClientError> {
        self.call::<GrantsRevoke>(&RevokeParams {
            grant: id.map(str::to_owned),
            all: id.is_none(),
        })
    }

    /// `standing.list`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn standing_list(&mut self) -> Result<crate::view::StandingListView, ClientError> {
        self.call::<crate::proto::StandingList>(&NoParams {})
    }

    /// `standing.revoke`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn standing_revoke(
        &mut self,
        p: &crate::proto::StandingRevokeParams,
    ) -> Result<crate::view::StandingRevokedView, ClientError> {
        self.call::<crate::proto::StandingRevoke>(p)
    }

    /// `standing.confirm` with the passphrase proof.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn standing_confirm(
        &mut self,
        digest: &[u8; 32],
        passphrase: SecretBytes,
        claims: &[String],
    ) -> Result<crate::view::StandingConfirmedView, ClientError> {
        self.call::<crate::proto::StandingConfirm>(&crate::proto::StandingConfirmParams {
            digest: digest.iter().map(|b| format!("{b:02x}")).collect(),
            passphrase: Some(WireSecret::new(passphrase)),
            claims: claims.to_vec(),
        })
    }

    /// `standing.confirm` without the passphrase: a pre-prompt check that
    /// verifies the caller may give a proof and that `digest` matches the
    /// current standing set.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn standing_confirm_check(
        &mut self,
        digest: &[u8; 32],
        claims: &[String],
    ) -> Result<crate::view::StandingConfirmedView, ClientError> {
        self.call::<crate::proto::StandingConfirm>(&crate::proto::StandingConfirmParams {
            digest: digest.iter().map(|b| format!("{b:02x}")).collect(),
            passphrase: None,
            claims: claims.to_vec(),
        })
    }

    /// `audit.verify`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn audit_verify(&mut self) -> Result<AuditVerifyView, ClientError> {
        self.call::<AuditVerify>(&NoParams {})
    }

    /// `items.list`, with each item's account when `long`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn items_list(&mut self, long: bool) -> Result<ItemsView, ClientError> {
        self.call::<ItemsList>(&ListParams { long })
    }

    /// `items.show` for `slug`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn items_show(&mut self, slug: &str) -> Result<ItemView, ClientError> {
        self.call::<ItemsShow>(&SlugParams {
            slug: slug.to_owned(),
        })
    }

    /// `items.check` for the manifest at `manifest`, and `refs`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn items_check(
        &mut self,
        manifest: Option<&str>,
        refs: &[String],
    ) -> Result<CheckView, ClientError> {
        self.call::<ItemsCheck>(&CheckParams {
            manifest: manifest.map(str::to_owned),
            refs: refs.to_vec(),
        })
    }

    /// `items.add`. The value in `p` is wiped with the request frame.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn items_add(&mut self, p: &AddParams) -> Result<AddedView, ClientError> {
        self.call::<ItemsAdd>(p)
    }

    /// `login.add`. The login fields in `p` are wiped with the request frame.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn login_add(&mut self, p: &LoginAddParams) -> Result<LoginAddedView, ClientError> {
        self.call::<LoginAdd>(p)
    }

    /// `items.target` for `slug` (and `field`), with the caller's claims
    /// (the daemon serves it only to a caller that may give a proof).
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn items_target(
        &mut self,
        slug: &str,
        field: Option<&str>,
        claims: &[String],
    ) -> Result<TargetView, ClientError> {
        self.call::<ItemsTarget>(&TargetParams {
            slug: slug.to_owned(),
            field: field.map(str::to_owned),
            claims: claims.to_vec(),
        })
    }

    /// Reveals one secret to a Linux terminal after a fresh proof.
    ///
    /// # Errors
    /// As [`Client::call`]. No value is returned after a refused proof or
    /// a failed durable audit append. Unavailable on macOS before M3.
    pub fn items_reveal(
        &mut self,
        slug: &str,
        field: Option<&str>,
        passphrase: SecretBytes,
        claims: &[String],
    ) -> Result<SecretBytes, ClientError> {
        self.call::<crate::proto::ItemsReveal>(&crate::proto::RevealParams {
            slug: slug.to_owned(),
            field: field.map(str::to_owned),
            passphrase: WireSecret::new(passphrase),
            claims: claims.to_vec(),
        })
        .map(|r| r.value.into_inner())
    }

    /// `items.rotate`: `value` in place of the value of `slug`'s field,
    /// with the passphrase as the proof.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn items_rotate(
        &mut self,
        target: &TargetView,
        value: SecretBytes,
        passphrase: SecretBytes,
        claims: &[String],
    ) -> Result<RotatedView, ClientError> {
        self.call::<ItemsRotate>(&RotateParams {
            slug: target.item.slug.clone(),
            field: target.field.clone(),
            item: target.item.id.clone(),
            value: WireSecret::new(value),
            passphrase: WireSecret::new(passphrase),
            claims: claims.to_vec(),
        })
    }

    /// `items.remove`: deletes `target`'s item, with the passphrase as the
    /// proof.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn items_remove(
        &mut self,
        target: &TargetView,
        passphrase: SecretBytes,
        claims: &[String],
    ) -> Result<RemovedView, ClientError> {
        self.call::<ItemsRemove>(&RemoveParams {
            slug: target.item.slug.clone(),
            item: target.item.id.clone(),
            passphrase: WireSecret::new(passphrase),
            claims: claims.to_vec(),
        })
    }

    /// `items.reclassify` of `slug` to live: tightening, with no proof.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn items_reclassify_live(
        &mut self,
        slug: &str,
        claims: &[String],
    ) -> Result<ReclassifiedView, ClientError> {
        self.call::<ItemsReclassify>(&ReclassifyParams {
            slug: slug.to_owned(),
            to: ClassificationView::Live,
            item: None,
            passphrase: None,
            claims: claims.to_vec(),
        })
    }

    /// `items.reclassify` of `target`'s item to `to` (`test` or
    /// `unknown`), with the passphrase as the proof.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn items_reclassify(
        &mut self,
        target: &TargetView,
        to: ClassificationView,
        passphrase: SecretBytes,
        claims: &[String],
    ) -> Result<ReclassifiedView, ClientError> {
        self.call::<ItemsReclassify>(&ReclassifyParams {
            slug: target.item.slug.clone(),
            to,
            item: Some(target.item.id.clone()),
            passphrase: Some(WireSecret::new(passphrase)),
            claims: claims.to_vec(),
        })
    }
}

impl Client {
    /// `import.plan`: what importing `p`'s entries would do.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn import_plan(&mut self, p: &ImportParams) -> Result<ImportPlanView, ClientError> {
        self.call::<ImportPlan>(p)
    }

    /// `import.commit`: the import `p` describes, if its plan is still the
    /// one with `p.digest`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn import_commit(&mut self, p: &ImportCommitParams) -> Result<ImportPlanView, ClientError> {
        self.call::<ImportCommit>(p)
    }

    /// `import.verify`: whether `p`'s files may be deleted.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn import_verify(&mut self, p: &VerifyParams) -> Result<VerifyView, ClientError> {
        self.call::<ImportVerify>(p)
    }

    /// `scan.match`: which of `p`'s candidates the vault holds, under the
    /// rules of `p.purpose` (M2 plan D-32). The values in `p` are wiped
    /// with the request frame. A caller sends its candidates in batches of
    /// at most [`crate::proto::MAX_SCAN_CANDIDATES`] whose request fits in
    /// a frame, and stops with its run `incomplete (limited)` when an
    /// answer is `limited` or the call is refused `too_many_checks`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn scan_match(&mut self, p: &ScanMatchParams) -> Result<ScanMatchView, ClientError> {
        self.call::<ScanMatch>(p)
    }

    /// `items.mark_exposed`: marks `p`'s items "exposed: rotate".
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn items_mark_exposed(&mut self, p: &MarkExposedParams) -> Result<MarkedView, ClientError> {
        self.call::<ItemsMarkExposed>(p)
    }

    /// `files.backup`: an encrypted backup of `p`'s files.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn files_backup(&mut self, p: &FilesBackupParams) -> Result<FileBackupView, ClientError> {
        self.call::<FilesBackup>(p)
    }

    /// `files.show`: who made backup `id` and what its files are, without
    /// their bytes, for the statement before the proof.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn files_show(&mut self, id: &str, claims: &[String]) -> Result<FilesShown, ClientError> {
        self.call::<FilesShow>(&FilesShowParams {
            backup: id.to_owned(),
            claims: claims.to_vec(),
        })
    }

    /// `files.restore`: the files of backup `id`, with the passphrase as
    /// the proof; `created_by_agent_ticked` when the person ticked
    /// `--created-by-agent`, `unrecorded` for the recovery form
    /// `--unrecorded`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn files_restore(
        &mut self,
        id: &str,
        passphrase: SecretBytes,
        created_by_agent_ticked: bool,
        unrecorded: bool,
        claims: &[String],
    ) -> Result<RestoredFiles, ClientError> {
        self.call::<FilesRestore>(&FilesRestoreParams {
            backup: id.to_owned(),
            passphrase: WireSecret::new(passphrase),
            created_by_agent_ticked,
            unrecorded,
            claims: claims.to_vec(),
        })
    }

    /// `recovery.confirm` with the kit as typed.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn recovery_confirm(
        &mut self,
        kit: SecretBytes,
        claims: &[String],
    ) -> Result<RecoveryConfirmedView, ClientError> {
        self.call::<RecoveryConfirm>(&RecoveryConfirmParams {
            recovery_kit: WireSecret::new(kit),
            claims: claims.to_vec(),
        })
    }

    /// `backup.create`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn backup_create(&mut self) -> Result<BackupView, ClientError> {
        self.call::<BackupCreate>(&NoParams {})
    }

    /// `vault.recover` from the backup at `backup` (an absolute path), with
    /// the kit as typed as the proof and `new_passphrase` as the vault's
    /// passphrase from now on.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn vault_recover(
        &mut self,
        backup: &str,
        kit: SecretBytes,
        new_passphrase: SecretBytes,
        claims: &[String],
    ) -> Result<RecoveredView, ClientError> {
        self.call::<VaultRecover>(&RecoverParams {
            backup: backup.to_owned(),
            recovery_kit: WireSecret::new(kit),
            new_passphrase: WireSecret::new(new_passphrase),
            claims: claims.to_vec(),
        })
    }
}

impl Client {
    /// `backup.v2.begin`: starts a backup v2 of `p`'s files; this process
    /// is its creator.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn backup_v2_begin(
        &mut self,
        p: &BackupBeginParams,
    ) -> Result<BackupBegunView, ClientError> {
        self.call::<BackupBegin>(p)
    }

    /// `backup.v2.put`: chunk `chunk` of file `file` of backup `id`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn backup_v2_put(
        &mut self,
        id: &str,
        file: u32,
        chunk: u32,
        data: SecretBytes,
    ) -> Result<BackupPutView, ClientError> {
        self.call::<BackupPut>(&BackupPutParams {
            id: id.to_owned(),
            file,
            chunk,
            data: WireSecret::new(data),
        })
    }

    /// `backup.v2.commit`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn backup_v2_commit(&mut self, id: &str) -> Result<BackupCommittedView, ClientError> {
        self.call::<BackupCommit>(&BackupIdParams { id: id.to_owned() })
    }

    /// `backup.v2.record_result`: what the change left in file `file`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn backup_v2_record_result(
        &mut self,
        id: &str,
        file: u32,
        sha256_after: &[u8; 32],
    ) -> Result<BackupResultView, ClientError> {
        use core::fmt::Write as _;
        let hex = sha256_after
            .iter()
            .fold(String::with_capacity(64), |mut s, b| {
                let _ = write!(s, "{b:02x}");
                s
            });
        self.call::<BackupRecordResult>(&BackupResultParams {
            id: id.to_owned(),
            file,
            sha256_after: hex,
        })
    }

    /// `backup.v2.open_restore`, with the passphrase as the proof.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn backup_v2_open_restore(
        &mut self,
        id: &str,
        passphrase: SecretBytes,
        created_by_agent_ticked: bool,
        unrecorded: bool,
        claims: &[String],
    ) -> Result<RestoreLeaseView, ClientError> {
        self.call::<BackupOpenRestore>(&OpenRestoreParams {
            id: id.to_owned(),
            passphrase: WireSecret::new(passphrase),
            created_by_agent_ticked,
            unrecorded,
            claims: claims.to_vec(),
        })
    }

    /// `backup.v2.read`: one chunk under lease `lease`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn backup_v2_read(
        &mut self,
        lease: &str,
        file: u32,
        chunk: u32,
    ) -> Result<BackupChunk, ClientError> {
        self.call::<BackupRead>(&BackupReadParams {
            lease: lease.to_owned(),
            file,
            chunk,
        })
    }

    /// `backup.v2.list`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn backup_v2_list(&mut self) -> Result<BackupListView, ClientError> {
        self.call::<BackupList>(&NoParams {})
    }

    /// Calls method `M` with `fds` attached to the request's first byte
    /// (`SCM_RIGHTS`), as [`Client::call`] calls it otherwise. Only on a
    /// connection made with [`Client::connect`]: a waiter's connection
    /// ([`Client::connect_by`]) is non-blocking, and a descriptor is handed
    /// over on a call of its own.
    ///
    /// # Errors
    /// As [`Client::call`]; [`ClientError::Protocol`] on a waiter's
    /// connection.
    pub fn call_with_fds<M: Method>(
        &mut self,
        params: &M::Params,
        fds: &[BorrowedFd<'_>],
    ) -> Result<M::Output, ClientError> {
        if self.by.is_some() {
            return Err(ClientError::Protocol);
        }
        let id = self.next_id;
        self.next_id += 1;
        let request = proto::request_frame::<M>(id, params)?;
        request.write_with_fds(&self.stream, fds)?;
        drop(request);
        let response = Frame::read_from(&mut self.stream)?;
        proto::parse_response::<M::Output>(&response, id).map_err(|e| match e {
            ResponseError::Rpc(e) => ClientError::Rpc(e),
            ResponseError::Protocol => ClientError::Protocol,
        })
    }

    /// `run.request` for a managed server's launch or bridge (SPEC §6.6, M2
    /// task M2-27), handing over `fds`, whose roles the request names
    /// (`p.fds` is set from them). A covered answer is `started`, never a
    /// value: the client receives none, and an answer that carries one is
    /// [`ClientError::Protocol`].
    ///
    /// # Errors
    /// As [`Client::call_with_fds`].
    pub fn run_request_with_fds(
        &mut self,
        p: &RunRequestParams,
        fds: &ClientFds,
    ) -> Result<RunAnswer, ClientError> {
        let mut p = p.clone();
        p.fds = fds.roles();
        let answer = self.call_with_fds::<RunRequest>(&p, &fds.borrowed())?;
        if !answer.values.is_empty() || !answer.well_formed() {
            return Err(ClientError::Protocol);
        }
        Ok(answer)
    }

    /// `managed.register`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn register_managed(
        &mut self,
        p: &ManagedRegisterParams,
    ) -> Result<ManagedRegisteredView, ClientError> {
        self.call::<ManagedRegister>(p)
    }

    /// `managed.unregister`: by the record's id or its `<agent>/<server>`
    /// name.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn unregister_managed(
        &mut self,
        id: &str,
        passphrase: SecretBytes,
        claims: &[String],
    ) -> Result<ManagedUnregisteredView, ClientError> {
        self.call::<ManagedUnregister>(&ManagedUnregisterParams {
            id: id.to_owned(),
            passphrase: WireSecret::new(passphrase),
            claims: claims.to_vec(),
        })
    }

    /// `managed.update_plan`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn plan_managed_update(
        &mut self,
        launch: &str,
        changes: &envcloak_policy::managed::LaunchChanges,
        claims: &[String],
    ) -> Result<ManagedUpdatePlanView, ClientError> {
        self.call::<ManagedUpdatePlan>(&ManagedUpdatePlanParams {
            launch: launch.to_owned(),
            changes: changes.clone(),
            claims: claims.to_vec(),
        })
    }

    /// `managed.update`.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn update_managed(
        &mut self,
        launch: &str,
        changes: &envcloak_policy::managed::LaunchChanges,
        digest: &str,
        passphrase: SecretBytes,
        claims: &[String],
    ) -> Result<ManagedUpdatedView, ClientError> {
        self.call::<ManagedUpdate>(&ManagedUpdateParams {
            launch: launch.to_owned(),
            changes: changes.clone(),
            digest: digest.to_owned(),
            passphrase: WireSecret::new(passphrase),
            claims: claims.to_vec(),
        })
    }
}

/// The pipe ends a managed request hands over (SPEC §6.6, M2 plan D-36):
/// what the server (or relay) reads, what it writes, optionally its
/// standard error, and the lifeline, the read end of a pipe whose write
/// end the client keeps and never writes, so that its end of file says
/// the client is gone. The daemon passes them to the runner it starts;
/// the client keeps the other ends.
#[derive(Debug)]
pub struct ClientFds {
    pub stdin: std::os::fd::OwnedFd,
    pub stdout: std::os::fd::OwnedFd,
    pub stderr: Option<std::os::fd::OwnedFd>,
    pub lifeline: std::os::fd::OwnedFd,
}

impl ClientFds {
    /// The roles, in the order [`ClientFds::borrowed`] attaches them.
    pub fn roles(&self) -> Vec<FdRole> {
        let mut r = vec![FdRole::Stdin, FdRole::Stdout];
        if self.stderr.is_some() {
            r.push(FdRole::Stderr);
        }
        r.push(FdRole::Lifeline);
        r
    }

    /// The descriptors, in the order of [`ClientFds::roles`].
    pub fn borrowed(&self) -> Vec<BorrowedFd<'_>> {
        let mut v = vec![self.stdin.as_fd(), self.stdout.as_fd()];
        if let Some(e) = &self.stderr {
            v.push(e.as_fd());
        }
        v.push(self.lifeline.as_fd());
        v
    }
}

impl AsFd for Client {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }
}

impl Client {
    /// One page of the vault's adopted project metadata, never values.
    pub fn projects_list(
        &mut self,
        after: Option<crate::view::ProjectCursor>,
    ) -> Result<crate::view::ProjectsView, ClientError> {
        self.call::<crate::proto::ProjectsList>(&crate::proto::ProjectsListParams { after })
    }

    /// `app.unlock.begin`: starts a Secure Enclave unlock.
    pub fn app_unlock_begin(
        &mut self,
        unlocker_id: Option<&str>,
        claims: &[String],
    ) -> Result<crate::app::AppUnlockBeginOutput, ClientError> {
        self.call::<crate::app::AppUnlockBegin>(&crate::app::AppUnlockBeginParams {
            unlocker_id: unlocker_id.map(str::to_owned),
            claims: claims.to_vec(),
        })
    }

    /// `app.unlock`: completes a Secure Enclave unlock with the HPKE-sealed VMK.
    pub fn app_unlock(
        &mut self,
        request_id: &str,
        sealed: &str,
        claims: &[String],
    ) -> Result<UnlockedView, ClientError> {
        self.call::<crate::app::AppUnlock>(&crate::app::AppUnlockParams {
            request_id: request_id.to_owned(),
            sealed: sealed.to_owned(),
            claims: claims.to_vec(),
        })
    }

    /// `app.unlocker.enroll.begin`: opens a pending `unlocker_add` request.
    pub fn app_unlocker_enroll_begin(
        &mut self,
        unlock_pub: &str,
        approve_pub: &str,
        label: &str,
        claims: &[String],
    ) -> Result<crate::app::AppUnlockerEnrollBeginOutput, ClientError> {
        self.call::<crate::app::AppUnlockerEnrollBegin>(&crate::app::AppUnlockerEnrollBeginParams {
            unlock_pub: unlock_pub.to_owned(),
            approve_pub: approve_pub.to_owned(),
            label: label.to_owned(),
            claims: claims.to_vec(),
        })
    }

    /// `app.unlocker.enroll`: polls the outcome of a pending `unlocker_add` request.
    pub fn app_unlocker_enroll(
        &mut self,
        request: &str,
        claims: &[String],
    ) -> Result<crate::app::AppUnlockerEnrollOutput, ClientError> {
        self.call::<crate::app::AppUnlockerEnroll>(&crate::app::AppUnlockerEnrollParams {
            request: request.to_owned(),
            claims: claims.to_vec(),
        })
    }

    /// `app.pending.list`: the pending run requests waiting for approval,
    /// oldest first (at most 20).
    pub fn app_pending_list(
        &mut self,
        claims: &[String],
    ) -> Result<crate::app::AppPendingListView, ClientError> {
        let list = self.call::<crate::app::AppPendingList>(&crate::app::AppPendingListParams {
            claims: claims.to_vec(),
        })?;
        if list.well_formed() {
            Ok(list)
        } else {
            Err(ClientError::Protocol)
        }
    }

    /// `app.pending.get`: the full [`PendingDescriptor`] for pending run
    /// request `request`.
    pub fn app_pending_get(
        &mut self,
        request: &str,
        claims: &[String],
    ) -> Result<PendingDescriptor, ClientError> {
        self.call::<crate::app::AppPendingGet>(&crate::app::AppPendingGetParams {
            request: request.to_owned(),
            claims: claims.to_vec(),
        })
    }

    /// `app.approve`: approves pending run request `request` with a 64-byte
    /// P-256 ECDSA signature over `digest`.
    pub fn app_approve(
        &mut self,
        request: &str,
        options: &ApprovalOptions,
        digest: &[u8; 32],
        signature: &str,
        claims: &[String],
    ) -> Result<ApprovedView, ClientError> {
        use core::fmt::Write as _;
        let hex = digest.iter().fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        });
        self.call::<crate::app::AppApprove>(&crate::app::AppApproveParams {
            request: request.to_owned(),
            options: options.clone(),
            digest: hex,
            signature: signature.to_owned(),
            claims: claims.to_vec(),
        })
    }

    /// `items.ask`: files an ask for the app's paste sheet.
    pub fn items_ask(
        &mut self,
        p: &crate::proto::AskParams,
    ) -> Result<crate::view::AskOpenedView, ClientError> {
        self.call::<crate::proto::ItemsAsk>(p)
    }

    /// `items.ask_state`: polls the state of ask `ask`.
    pub fn items_ask_state(
        &mut self,
        ask: &str,
    ) -> Result<envcloak_policy::AskStateOutcome, ClientError> {
        self.call::<crate::proto::ItemsAskState>(&crate::proto::AskStateParams {
            ask: ask.to_owned(),
        })
    }

    /// Files `items.ask` and polls `items.ask_state` on fresh connections
    /// using [`crate::wait::Backoff`] up to `wait` (`envcloak add --ask`,
    /// SPEC §6.3, M3 plan M3-19). Holds no connection between polls.
    pub fn wait_for_ask(
        paths: &RunPaths,
        p: &crate::proto::AskParams,
        wait: Duration,
    ) -> Result<AskWaitOutcome, ClientError> {
        let start = Instant::now();
        let deadline = start
            .checked_add(wait)
            .ok_or(ClientError::Frame(FrameError::Io(
                io::ErrorKind::InvalidInput,
            )))?;
        let limit = deadline
            .checked_add(crate::wait::CALL_GRACE)
            .unwrap_or(deadline);
        let mut backoff = crate::wait::Backoff::new();
        let mut answered = false;
        'ask: loop {
            let id = loop {
                if Instant::now() >= deadline {
                    return Ok(AskWaitOutcome::Expired);
                }
                match Self::connect_by(paths, limit).and_then(|mut c| c.items_ask(p)) {
                    Ok(opened) => {
                        answered = true;
                        break PendingId::parse(&opened.ask).ok_or(ClientError::Protocol)?;
                    }
                    Err(ClientError::Rpc(RpcError {
                        kind: crate::ErrorKind::TooManyPending | crate::ErrorKind::Busy,
                        ..
                    })) => {
                        answered = true;
                        let now = Instant::now();
                        if now >= deadline {
                            return Ok(AskWaitOutcome::Expired);
                        }
                        backoff.after_busy();
                        std::thread::sleep(
                            backoff
                                .interval()
                                .min(deadline.saturating_duration_since(now)),
                        );
                    }
                    Err(e) if crate::wait::not_taken(&e, answered) => {
                        let now = Instant::now();
                        if now >= deadline {
                            return Err(e);
                        }
                        backoff.after_busy();
                        std::thread::sleep(
                            backoff
                                .interval()
                                .min(deadline.saturating_duration_since(now)),
                        );
                    }
                    Err(e) => return Err(e),
                }
            };
            let id_str = id.to_string();
            loop {
                let now = Instant::now();
                if now >= deadline {
                    return Ok(AskWaitOutcome::Expired);
                }
                let sleep_for = backoff
                    .interval()
                    .min(deadline.saturating_duration_since(now));
                if !sleep_for.is_zero() {
                    std::thread::sleep(sleep_for);
                }
                match Self::connect_by(paths, limit).and_then(|mut c| c.items_ask_state(&id_str)) {
                    Ok(envcloak_policy::AskStateOutcome::Added { slug }) => {
                        envcloak_core::vault::Slug::new(&slug)
                            .map_err(|_| ClientError::Protocol)?;
                        return Ok(AskWaitOutcome::Added { slug });
                    }
                    Ok(envcloak_policy::AskStateOutcome::Declined) => {
                        return Ok(AskWaitOutcome::Declined);
                    }
                    Ok(envcloak_policy::AskStateOutcome::Expired) => {
                        return Ok(AskWaitOutcome::Expired);
                    }
                    Ok(envcloak_policy::AskStateOutcome::Unknown) => {
                        if Instant::now() >= deadline {
                            return Ok(AskWaitOutcome::Expired);
                        }
                        continue 'ask;
                    }
                    Ok(envcloak_policy::AskStateOutcome::Pending) => {
                        if Instant::now() >= deadline {
                            return Ok(AskWaitOutcome::Expired);
                        }
                        backoff.after_pending();
                    }
                    Err(ClientError::Rpc(RpcError {
                        kind: crate::ErrorKind::Busy,
                        ..
                    })) => {
                        if Instant::now() >= deadline {
                            return Ok(AskWaitOutcome::Expired);
                        }
                        backoff.after_busy();
                    }
                    Err(e) if crate::wait::not_taken(&e, answered) => {
                        if Instant::now() >= deadline {
                            return Err(e);
                        }
                        backoff.after_busy();
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    /// `reveal.request`: files a reveal request for the app from a terminal
    /// subject.
    pub fn reveal_request(
        &mut self,
        slug: &str,
        field: Option<&str>,
        claims: &[String],
    ) -> Result<crate::view::RevealRequestedView, ClientError> {
        self.call::<crate::proto::RevealRequest>(&crate::proto::RevealRequestParams {
            slug: slug.to_owned(),
            field: field.map(str::to_owned),
            claims: claims.to_vec(),
        })
    }

    /// Files `reveal.request` and polls `pending.state` on fresh connections
    /// using [`crate::wait::Backoff`] up to `wait` (`envcloak reveal` on
    /// macOS, SPEC §6.7, M3 plan M3-J5). Holds no connection between polls.
    pub fn wait_for_reveal(
        paths: &RunPaths,
        slug: &str,
        field: Option<&str>,
        claims: &[String],
        wait: Duration,
    ) -> Result<RevealWaitOutcome, ClientError> {
        let start = Instant::now();
        let deadline = start
            .checked_add(wait)
            .ok_or(ClientError::Frame(FrameError::Io(
                io::ErrorKind::InvalidInput,
            )))?;
        let limit = deadline
            .checked_add(crate::wait::CALL_GRACE)
            .unwrap_or(deadline);
        let mut backoff = crate::wait::Backoff::new();
        let mut answered = false;
        'reveal: loop {
            let id = loop {
                if Instant::now() >= deadline {
                    return Ok(RevealWaitOutcome::Expired);
                }
                match Self::connect_by(paths, limit)
                    .and_then(|mut c| c.reveal_request(slug, field, claims))
                {
                    Ok(opened) => {
                        answered = true;
                        break PendingId::parse(&opened.request).ok_or(ClientError::Protocol)?;
                    }
                    Err(ClientError::Rpc(RpcError {
                        kind: crate::ErrorKind::TooManyPending | crate::ErrorKind::Busy,
                        ..
                    })) => {
                        answered = true;
                        let now = Instant::now();
                        if now >= deadline {
                            return Ok(RevealWaitOutcome::Expired);
                        }
                        backoff.after_busy();
                        std::thread::sleep(
                            backoff
                                .interval()
                                .min(deadline.saturating_duration_since(now)),
                        );
                    }
                    Err(e) if crate::wait::not_taken(&e, answered) => {
                        let now = Instant::now();
                        if now >= deadline {
                            return Err(e);
                        }
                        backoff.after_busy();
                        std::thread::sleep(
                            backoff
                                .interval()
                                .min(deadline.saturating_duration_since(now)),
                        );
                    }
                    Err(e) => return Err(e),
                }
            };
            loop {
                let now = Instant::now();
                if now >= deadline {
                    return Ok(RevealWaitOutcome::Expired);
                }
                let sleep_for = backoff
                    .interval()
                    .min(deadline.saturating_duration_since(now));
                if !sleep_for.is_zero() {
                    std::thread::sleep(sleep_for);
                }
                match Self::connect_by(paths, limit).and_then(|mut c| c.pending_state(&id)) {
                    Ok(PendingState::Approved) => return Ok(RevealWaitOutcome::Shown),
                    Ok(PendingState::Denied) => return Ok(RevealWaitOutcome::Declined),
                    Ok(PendingState::Expired) => return Ok(RevealWaitOutcome::Expired),
                    Ok(PendingState::Unknown) => {
                        if Instant::now() >= deadline {
                            return Ok(RevealWaitOutcome::Expired);
                        }
                        continue 'reveal;
                    }
                    Ok(PendingState::Pending) => {
                        if Instant::now() >= deadline {
                            return Ok(RevealWaitOutcome::Expired);
                        }
                        backoff.after_pending();
                    }
                    Err(ClientError::Rpc(RpcError {
                        kind: crate::ErrorKind::Busy,
                        ..
                    })) => {
                        if Instant::now() >= deadline {
                            return Ok(RevealWaitOutcome::Expired);
                        }
                        backoff.after_busy();
                    }
                    Err(e) if crate::wait::not_taken(&e, answered) => {
                        if Instant::now() >= deadline {
                            return Err(e);
                        }
                        backoff.after_busy();
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    /// `app.unlocker.add`: enrols another Secure Enclave unlocker under a
    /// signed `envcloak-write-statement/1`.
    pub fn app_unlocker_add(
        &mut self,
        p: &crate::app::AppUnlockerAddParams,
    ) -> Result<crate::app::AppUnlockerAddedView, ClientError> {
        self.call::<crate::app::AppUnlockerAdd>(p)
    }

    /// `app.unlocker.remove`: removes the passphrase unlocker or a Secure
    /// Enclave unlocker under a signed `envcloak-write-statement/1`.
    pub fn app_unlocker_remove(
        &mut self,
        p: &crate::app::AppUnlockerRemoveParams,
    ) -> Result<crate::app::AppUnlockerRemovedView, ClientError> {
        self.call::<crate::app::AppUnlockerRemove>(p)
    }

    /// `app.items.target`: opens a 60-second signed-write target for `slug`
    /// (and `field`).
    pub fn app_items_target(
        &mut self,
        slug: &str,
        field: Option<&str>,
        claims: &[String],
    ) -> Result<crate::app::AppItemsTargetOutput, ClientError> {
        self.call::<crate::app::AppItemsTarget>(&crate::app::AppItemsTargetParams {
            slug: slug.to_owned(),
            field: field.map(str::to_owned),
            claims: claims.to_vec(),
        })
    }

    /// `app.items.rotate`: replaces an item field's value under a signed
    /// `envcloak-write-statement/1`.
    pub fn app_items_rotate(
        &mut self,
        p: &crate::app::AppItemsRotateParams,
    ) -> Result<RotatedView, ClientError> {
        self.call::<crate::app::AppItemsRotate>(p)
    }

    /// `app.items.remove`: removes an item under a signed
    /// `envcloak-write-statement/1` after writing an encrypted vault backup.
    pub fn app_items_remove(
        &mut self,
        p: &crate::app::AppItemsRemoveParams,
    ) -> Result<RemovedView, ClientError> {
        self.call::<crate::app::AppItemsRemove>(p)
    }

    /// `app.reveal.begin`: starts a reveal in the app.
    pub fn app_reveal_begin(
        &mut self,
        p: &crate::app::AppRevealBeginParams,
    ) -> Result<envcloak_policy::RevealDescriptor, ClientError> {
        self.call::<crate::app::AppRevealBegin>(p)
    }

    /// `app.reveal`: releases a secret value HPKE-sealed to `app_eph_pub`
    /// after verifying a signed `envcloak-reveal-statement/1`.
    pub fn app_reveal(
        &mut self,
        p: &crate::app::AppRevealParams,
    ) -> Result<crate::app::AppRevealOutput, ClientError> {
        self.call::<crate::app::AppReveal>(p)
    }

    /// `app.paste.begin`: opens a 2-minute paste stage with a daemon X25519
    /// ephemeral public key.
    pub fn app_paste_begin(
        &mut self,
        claims: &[String],
    ) -> Result<crate::app::AppPasteBeginOutput, ClientError> {
        self.call::<crate::app::AppPasteBegin>(&crate::app::AppPasteBeginParams {
            claims: claims.to_vec(),
        })
    }

    /// `app.paste.inspect`: opens the HPKE-sealed pasted value into daemon
    /// memory and returns provider, classification and length metadata.
    pub fn app_paste_inspect(
        &mut self,
        stage: &str,
        sealed: &str,
        claims: &[String],
    ) -> Result<crate::app::AppPasteInspectOutput, ClientError> {
        self.call::<crate::app::AppPasteInspect>(&crate::app::AppPasteInspectParams {
            stage: stage.to_owned(),
            sealed: sealed.to_owned(),
            claims: claims.to_vec(),
        })
    }

    /// `app.paste`: saves the staged value from `app.paste.inspect` as a new
    /// item (and optionally resolves an open ask).
    pub fn app_paste(&mut self, p: &crate::app::AppPasteParams) -> Result<AddedView, ClientError> {
        self.call::<crate::app::AppPaste>(p)
    }

    /// `app.asks.list`: lists open asks filed by `items.ask`.
    pub fn app_asks_list(
        &mut self,
        claims: &[String],
    ) -> Result<crate::app::AppAsksListView, ClientError> {
        self.call::<crate::app::AppAsksList>(&crate::app::AppAsksListParams {
            claims: claims.to_vec(),
        })
    }

    /// `app.asks.decline`: declines an open ask.
    pub fn app_asks_decline(
        &mut self,
        ask: &str,
        claims: &[String],
    ) -> Result<crate::app::AppAskDeclinedView, ClientError> {
        self.call::<crate::app::AppAsksDecline>(&crate::app::AppAsksDeclineParams {
            ask: ask.to_owned(),
            claims: claims.to_vec(),
        })
    }

    /// `app.lock`: locks the vault with `reason` (`screen_lock`,
    /// `session_resign` or `user`).
    pub fn app_lock(
        &mut self,
        reason: crate::app::AppLockReason,
        claims: &[String],
    ) -> Result<LockedView, ClientError> {
        self.call::<crate::app::AppLock>(&crate::app::AppLockParams {
            reason,
            claims: claims.to_vec(),
        })
    }

    /// `app.audit.list`: lists decrypted audit entries for the Activity window.
    pub fn app_audit_list(
        &mut self,
        p: &crate::app::AppAuditListParams,
    ) -> Result<crate::app::AppAuditListView, ClientError> {
        self.call::<crate::app::AppAuditList>(p)
    }

    /// `signin.target.add`: registers a sign-in target with a passphrase
    /// proof (or runs a pre-prompt check when `p.passphrase` is `None`).
    pub fn signin_target_add(
        &mut self,
        p: &crate::proto::SigninTargetAddParams,
    ) -> Result<crate::view::SigninTargetView, ClientError> {
        self.call::<crate::proto::SigninTargetAdd>(p)
    }

    /// `signin.target.edit`: updates a sign-in target with a passphrase
    /// proof (or runs a pre-prompt check when `p.passphrase` is `None`).
    pub fn signin_target_edit(
        &mut self,
        p: &crate::proto::SigninTargetEditParams,
    ) -> Result<crate::view::SigninTargetView, ClientError> {
        self.call::<crate::proto::SigninTargetEdit>(p)
    }

    /// `signin.target.remove`: deletes a sign-in target and ends its active
    /// authorizations.
    pub fn signin_target_remove(
        &mut self,
        p: &crate::proto::SigninTargetRemoveParams,
    ) -> Result<crate::view::SigninTargetRemovedView, ClientError> {
        self.call::<crate::proto::SigninTargetRemove>(p)
    }

    /// `signin.target.list`: lists registered sign-in targets in stable
    /// `(name, role)` order.
    pub fn signin_target_list(
        &mut self,
        manifest: Option<&str>,
    ) -> Result<crate::view::SigninTargetListView, ClientError> {
        self.call::<crate::proto::SigninTargetList>(&crate::proto::SigninTargetListParams {
            manifest: manifest.map(str::to_owned),
        })
    }

    /// `signin.request`: opens or retries a sign-in operation.
    pub fn signin_request(
        &mut self,
        p: &crate::proto::SigninRequestParams,
    ) -> Result<crate::view::SigninStatusView, ClientError> {
        self.call::<crate::proto::SigninRequest>(p)
    }

    /// `signin.request` carrying passed file descriptors (`SCM_RIGHTS`).
    pub fn signin_request_with_fds(
        &mut self,
        p: &crate::proto::SigninRequestParams,
        fds: &[BorrowedFd<'_>],
    ) -> Result<crate::view::SigninStatusView, ClientError> {
        self.call_with_fds::<crate::proto::SigninRequest>(p, fds)
    }

    /// `signin.status`: returns the status of a sign-in operation.
    pub fn signin_status(
        &mut self,
        request: &str,
    ) -> Result<crate::view::SigninStatusView, ClientError> {
        self.call::<crate::proto::SigninStatus>(&crate::proto::SigninOperationParams {
            request: request.to_owned(),
        })
    }

    /// `signin.cancel`: cancels an active or pending sign-in operation.
    pub fn signin_cancel(
        &mut self,
        request: &str,
    ) -> Result<crate::view::SigninStatusView, ClientError> {
        self.call::<crate::proto::SigninCancel>(&crate::proto::SigninOperationParams {
            request: request.to_owned(),
        })
    }

    /// `signin.end`: ends a delivered sign-in session by request id or
    /// context id.
    pub fn signin_end(
        &mut self,
        session: &str,
    ) -> Result<crate::view::SigninStatusView, ClientError> {
        self.call::<crate::proto::SigninEnd>(&crate::proto::SigninEndParams {
            session: session.to_owned(),
        })
    }
}
