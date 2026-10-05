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
//! On signed macOS builds the client will also check the daemon's code
//! signature from its audit token (M3). Builds that pin no signing
//! identity, which is every M1 build, cannot, and say so:
//! [`DaemonIdentity::Unverified`]. On them a program running as the same
//! user can impersonate the daemon (SPEC §1.1).

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
    ItemsTarget, ListParams, Lock, Method, NoParams, PendingGet, PendingGetParams, RemoveParams,
    RequestParams, ResponseError, RevokeParams, RotateParams, RpcError, RunAnswer, RunRequest,
    RunRequestParams, SlugParams, Status, TargetParams, Unlock, UnlockParams, VaultCreate,
    VaultCreateParams,
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
    ItemView, ItemsView, LockedView, RemovedView, RevokedView, RotatedView, StatusView, TargetView,
    UnlockedView,
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
        // A waiter's calls never block on the socket: each read and write
        // waits for it only for the time left (`Bounded`).
        if by.is_some() {
            stream
                .set_nonblocking(true)
                .map_err(|e| ClientError::Frame(FrameError::Io(e.kind())))?;
        }
        Ok(Client {
            stream,
            next_id: 1,
            by,
        })
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
        let response = match self.by {
            None => {
                request.write_to(&mut self.stream)?;
                drop(request);
                Frame::read_from(&mut self.stream)?
            }
            Some(by) => {
                let mut s = Bounded {
                    stream: &self.stream,
                    by,
                };
                request.write_to(&mut s)?;
                drop(request);
                Frame::read_from(&mut s)?
            }
        };
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

    /// `pending.get` for request `id`, with the caller's claims (the
    /// daemon serves it only to a caller that may give a proof).
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn pending_get(
        &mut self,
        id: &str,
        claims: &[String],
    ) -> Result<PendingDescriptor, ClientError> {
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
        self.call::<PendingPoll>(&PendingStateParams {
            request: id.to_string(),
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
        self.call::<Approve>(&ApproveParams {
            request: id.to_owned(),
            options,
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
        self.call::<Approve>(&ApproveParams {
            request: id.to_owned(),
            options,
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
}
