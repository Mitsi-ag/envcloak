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
    BackupCreate, FilesBackup, FilesBackupParams, FilesRestore, FilesRestoreParams, ImportCommit,
    ImportCommitParams, ImportParams, ImportPlan, ImportVerify, PendingList, PendingListParams,
    PendingPoll, PendingStateParams, RecoverParams, RecoveryConfirm, RecoveryConfirmParams,
    RestoredFiles, VaultRecover, VerifyParams,
};
use crate::view::{
    AddedView, ApprovedView, AuditVerifyView, CheckView, CreatedView, DeniedView, GrantsView,
    ItemView, ItemsView, LockedView, RemovedView, RevokedView, RotatedView, StatusView, TargetView,
    UnlockedView,
};
use crate::view::{
    BackupView, FileBackupView, ImportPlanView, PendingListView, RecoveredView,
    RecoveryConfirmedView, VerifyView,
};
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
            passphrase: WireSecret::new(passphrase),
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

    /// `files.backup`: an encrypted backup of `p`'s files.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn files_backup(&mut self, p: &FilesBackupParams) -> Result<FileBackupView, ClientError> {
        self.call::<FilesBackup>(p)
    }

    /// `files.restore`: the files of backup `id`, with the passphrase as
    /// the proof.
    ///
    /// # Errors
    /// As [`Client::call`].
    pub fn files_restore(
        &mut self,
        id: &str,
        passphrase: SecretBytes,
        claims: &[String],
    ) -> Result<RestoredFiles, ClientError> {
        self.call::<FilesRestore>(&FilesRestoreParams {
            backup: id.to_owned(),
            passphrase: WireSecret::new(passphrase),
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

impl AsFd for Client {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.stream.as_fd()
    }
}
