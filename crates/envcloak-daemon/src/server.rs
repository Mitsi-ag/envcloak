//! The socket server (SPEC §4.1 to §4.4, §5 "Lock").
//!
//! [`run_daemon`] starts in this order, and refuses to start when a step
//! fails:
//! 1. the umask becomes 077, and SIGTERM, SIGINT and SIGHUP are blocked
//!    before any thread exists, so only the signal thread takes them;
//! 2. a tracer already attached stops it (SPEC §5 "Process hardening");
//! 3. the runtime directory is created 0700 and checked: not a symlink,
//!    owned by this uid, not writable by group or others;
//! 4. an exclusive `flock` on `envcloakd.lock`: a second instance stops
//!    here, before touching the socket;
//! 5. a stale socket is removed, only while holding that lock; the socket
//!    is bound under umask 077 and made 0600;
//! 6. the vault, if there is one, is opened locked.
//!
//! Then three kinds of thread run:
//! - the accept loop: each peer is identified at accept (uid, pid, start
//!   time); another uid is closed at once and audited; at most
//!   [`MAX_CONNECTIONS`] are served at a time, and at most
//!   [`MAX_PER_PROCESS`] for any one process;
//! - one thread per connection: frames of at most 1 MiB, a body that must
//!   arrive within [`FRAME_DEADLINE`] of its first byte, and an idle limit
//!   between frames. Before each request the peer is read again
//!   ([`envcloak_sys::peer_unchanged`]): on macOS the kernel names the
//!   last process to use the client's socket, so another process sending
//!   on a descriptor passed to it would otherwise act as the one
//!   identified at accept (its evidence, grants and proofs); such a
//!   connection is closed, unanswered;
//! - a tick every second for the sleep and idle checks, which also run
//!   before every request; and the signal thread, which locks, removes the
//!   socket and exits.
//!
//! Argon2id runs on the connection's thread, outside the state lock, and
//! one run at a time (the proof gate), so parallel unlock attempts cannot
//! multiply its memory.
//!
//! Security events go to the audit log through the state
//! ([`State::audit`]); the signal thread's lock saves the log's head in
//! the vault's header before the daemon exits.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use envcloak_core::crypto::KdfParams;
use envcloak_core::vault::VaultPaths;
use envcloak_core::{RecoveryKit, check_passphrase, create_vault_with_kit};
use envcloak_ipc::proto::{
    self, Approve, AuditVerify, BackupBegin, BackupCommit, BackupCreate, BackupList,
    BackupOpenRestore, BackupPut, BackupRead, BackupRecordResult, Deny, ErrorKind, FilesBackup,
    FilesRestore, GrantsList, GrantsRevoke, ImportCommit, ImportPlan, ImportVerify,
    IncomingRequest, ItemsAdd, ItemsCheck, ItemsList, ItemsRemove, ItemsRotate, ItemsShow,
    ItemsTarget, Lock, Method, PendingGet, PendingList, PendingPoll, RecoveryConfirm, Role,
    RunRequest, Status, Unlock, UnlockParams, VaultCreate, VaultCreateParams, VaultRecover,
    loggable_method, required_role,
};
use envcloak_ipc::view::{
    CreatedView, DaemonView, LockReason, LockedView, StatusView, UnlockedView,
};
use envcloak_ipc::{Frame, FrameError, RpcError, RunPathErrorKind, RunPaths};
use envcloak_policy::{AgentCatalog, Claims, gather};
use envcloak_providers::Registry;
use envcloak_sys::{PeerIdentity, TerminationSignals};

use crate::audit::AuditEvent;
use crate::backup;
use crate::backups;
use crate::clock::{SystemClocks, now_of};
use crate::import;
use crate::items;
use crate::lock::Reading;
use crate::requests;
use crate::state::{BeginUnlock, State, passphrase_error};

/// Connections served at once. Each holds at most one frame (1 MiB) and a
/// thread, so this bounds the daemon's memory.
pub const MAX_CONNECTIONS: usize = 32;
/// Connections one process may hold at once, so a process that keeps its
/// connections open (an agent leaking them, say) cannot take every place
/// and lock out the user's `envcloak lock` and `status`. Many processes
/// together still can; per-agent limits come with the grant flood control
/// (T9).
pub const MAX_PER_PROCESS: usize = 8;
/// A frame's body must arrive within this long of its first byte.
pub const FRAME_DEADLINE: Duration = Duration::from_secs(10);
/// A connection with no frame for this long is closed. No client waits
/// for a person on an open connection: every CLI prompt is answered
/// before the CLI connects, and each step of a flow that does local work
/// between requests (`init --delete-plaintext`'s scans and file changes,
/// `import`'s plan and commit) opens a connection of its own. Only a
/// process that holds connections idle gains from a longer wait, and four
/// of them holding [`MAX_PER_PROCESS`] each could keep every place taken,
/// and `envcloak lock` and `status` out, for that long (review T7 open 2).
pub const IDLE_CONNECTION: Duration = Duration::from_secs(30);
/// A response must be written within this long.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// How the daemon runs.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Awake time without activity before the vault locks.
    pub idle_limit: Duration,
}

/// Why the daemon did not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonError {
    /// A tracer is attached.
    Traced,
    /// Another instance holds the lock.
    AlreadyRunning,
    /// The runtime directory is unsafe or unusable.
    RunDir(RunPathErrorKind),
    /// The data directory cannot be found (`HOME` unset).
    DataDir,
    /// The termination signals could not be blocked.
    Signals,
    /// The lock file cannot be opened, or is not this uid's regular file.
    LockFile,
    /// Something other than this uid's socket is where the socket goes.
    SocketTaken,
    /// Binding or securing the socket failed.
    Bind(io::ErrorKind),
}

impl DaemonError {
    /// The stable token the daemon prints.
    pub fn token(self) -> &'static str {
        match self {
            DaemonError::Traced => "traced",
            DaemonError::AlreadyRunning => "already_running",
            DaemonError::RunDir(_) => "runtime_dir",
            DaemonError::DataDir => "data_dir",
            DaemonError::Signals => "signals",
            DaemonError::LockFile => "lock_file",
            DaemonError::SocketTaken => "socket_taken",
            DaemonError::Bind(_) => "bind",
        }
    }

    /// The fixed message.
    pub fn message(self) -> &'static str {
        match self {
            DaemonError::Traced => "a debugger or tracer is attached, so the daemon will not start",
            DaemonError::AlreadyRunning => "another envcloakd is already running for this user",
            DaemonError::RunDir(k) => k.message(),
            DaemonError::DataDir => "HOME is not set to an absolute path",
            DaemonError::Signals => "the termination signals could not be blocked",
            DaemonError::LockFile => {
                "the daemon lock file cannot be opened, or is not a regular file of this user"
            }
            DaemonError::SocketTaken => {
                "something other than this user's socket is where the daemon socket goes"
            }
            DaemonError::Bind(_) => "the daemon socket could not be created",
        }
    }
}

impl core::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for DaemonError {}

/// What every thread shares.
pub(crate) struct Shared {
    pub(crate) state: Mutex<State>,
    /// Held while Argon2id runs, so only one runs at a time.
    pub(crate) proof_gate: Mutex<()>,
    pub(crate) clocks: SystemClocks,
    places: Mutex<Places>,
    runtime_dir_fallback: bool,
    /// The known agents: builtin plus the user's extensions, read once at
    /// start.
    pub(crate) catalog: AgentCatalog,
    /// The provider registry compiled into this build, whose key patterns
    /// mask keys in the command lines the audit log keeps.
    pub(crate) registry: Option<Registry>,
    /// Values compared with the vault, per subject root.
    pub(crate) value_checks: Mutex<crate::import::ValueChecks>,
}

impl Shared {
    /// Records an event in the audit log. Takes the state lock: callers
    /// that hold it use [`State::audit`].
    pub(crate) fn audit(&self, e: AuditEvent) {
        locked(&self.state).audit(e);
    }
}

/// Why a connection was not served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Full {
    /// [`MAX_CONNECTIONS`] are being served.
    All,
    /// Its process holds [`MAX_PER_PROCESS`].
    Process,
}

/// The connections being served: in all, and for each process by pid.
#[derive(Debug, Default)]
struct Places {
    total: usize,
    by_pid: HashMap<i32, usize>,
}

impl Places {
    /// Takes a place for a connection from process `pid`.
    fn take(&mut self, pid: i32) -> Result<(), Full> {
        if self.total >= MAX_CONNECTIONS {
            return Err(Full::All);
        }
        let held = self.by_pid.entry(pid).or_insert(0);
        if *held >= MAX_PER_PROCESS {
            return Err(Full::Process);
        }
        *held += 1;
        self.total += 1;
        Ok(())
    }

    /// Gives back a place [`Places::take`] gave `pid`.
    fn give_back(&mut self, pid: i32) {
        self.total = self.total.saturating_sub(1);
        if let Some(held) = self.by_pid.get_mut(&pid) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                self.by_pid.remove(&pid);
            }
        }
    }
}

pub(crate) fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Runs the daemon until a termination signal. See the module
/// documentation for the start-up order.
///
/// # Errors
/// A [`DaemonError`] when a start-up step fails. Once serving, it never
/// returns: the signal thread exits the process.
pub fn run_daemon(cfg: DaemonConfig) -> Result<(), DaemonError> {
    envcloak_sys::restrict_umask();
    let signals = TerminationSignals::block().map_err(|_| DaemonError::Signals)?;
    if !matches!(envcloak_sys::tracer_present(), Ok(false)) {
        return Err(DaemonError::Traced);
    }
    let run = RunPaths::for_user().map_err(|e| DaemonError::RunDir(e.kind()))?;
    if run.fallback {
        log_line!(
            "envcloakd: warning: XDG_RUNTIME_DIR is not set, so the socket is in {} instead; \
             it is not cleared at logout",
            run.dir.display()
        );
    }
    let vault_paths = VaultPaths::for_user().map_err(|_| DaemonError::DataDir)?;
    run.prepare_dir()
        .map_err(|e| DaemonError::RunDir(e.kind()))?;
    let lock_file = open_lock_file(&run.lock)?;
    match envcloak_sys::try_lock_exclusive(&lock_file) {
        Ok(true) => {}
        Ok(false) => return Err(DaemonError::AlreadyRunning),
        Err(_) => return Err(DaemonError::LockFile),
    }
    // Holding the lock: no other daemon uses this socket.
    remove_stale_socket(&run.socket)?;
    let listener = bind(&run.socket)?;

    let clocks = SystemClocks;
    let catalog = AgentCatalog::load(&vault_paths.data_dir);
    if !catalog.problems().is_empty() {
        // File names are not repeated: any program running as the user
        // can write agents.d (docs/AGENTS.md "Extensions").
        log_line!(
            "envcloakd: warning: {} agent extension file(s) in agents.d were skipped",
            catalog.problems().len()
        );
    }
    let registry = match envcloak_providers::load_embedded() {
        Ok(r) => Some(r),
        Err(_) => {
            log_line!(
                "envcloakd: warning: the provider registry did not load; key-shaped words in \
                 command lines are not masked in the audit log"
            );
            None
        }
    };
    let state = State::open(vault_paths, cfg.idle_limit, Reading::now(&clocks));
    log_line!(
        "envcloakd: listening on {} (pid {}, version {})",
        run.socket.display(),
        std::process::id(),
        env!("CARGO_PKG_VERSION")
    );
    let shared = Arc::new(Shared {
        state: Mutex::new(state),
        proof_gate: Mutex::new(()),
        clocks,
        places: Mutex::new(Places::default()),
        runtime_dir_fallback: run.fallback,
        catalog,
        registry,
        value_checks: Mutex::new(crate::import::ValueChecks::default()),
    });

    {
        let shared = Arc::clone(&shared);
        let socket = run.socket.clone();
        thread::Builder::new()
            .name("signals".into())
            .spawn(move || stop_on_signal(&signals, &shared, &socket, lock_file))
            .map_err(|_| DaemonError::Signals)?;
    }
    {
        let shared = Arc::clone(&shared);
        thread::Builder::new()
            .name("tick".into())
            .spawn(move || {
                loop {
                    thread::sleep(Duration::from_secs(1));
                    tick(&shared);
                }
            })
            .map_err(|_| DaemonError::Signals)?;
    }
    accept_loop(&listener, &shared);
    Ok(())
}

fn open_lock_file(path: &Path) -> Result<File, DaemonError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| DaemonError::LockFile)?;
    let m = file.metadata().map_err(|_| DaemonError::LockFile)?;
    if !m.is_file() || m.uid() != envcloak_sys::effective_uid() || m.mode() & 0o022 != 0 {
        return Err(DaemonError::LockFile);
    }
    Ok(file)
}

fn remove_stale_socket(socket: &Path) -> Result<(), DaemonError> {
    match std::fs::symlink_metadata(socket) {
        Ok(m) if m.file_type().is_socket() && m.uid() == envcloak_sys::effective_uid() => {
            std::fs::remove_file(socket).map_err(|e| DaemonError::Bind(e.kind()))
        }
        Ok(_) => Err(DaemonError::SocketTaken),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(DaemonError::Bind(e.kind())),
    }
}

/// Binds the socket (the umask is 077) and makes it 0600, then checks what
/// is on disk.
fn bind(socket: &Path) -> Result<UnixListener, DaemonError> {
    let listener = UnixListener::bind(socket).map_err(|e| DaemonError::Bind(e.kind()))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| DaemonError::Bind(e.kind()))?;
    let m = std::fs::symlink_metadata(socket).map_err(|e| DaemonError::Bind(e.kind()))?;
    if !m.file_type().is_socket()
        || m.uid() != envcloak_sys::effective_uid()
        || m.mode() & 0o777 != 0o600
    {
        return Err(DaemonError::SocketTaken);
    }
    Ok(listener)
}

/// Waits for SIGTERM, SIGINT or SIGHUP, then locks, removes the socket
/// while still holding the lock file, and exits.
fn stop_on_signal(signals: &TerminationSignals, shared: &Shared, socket: &Path, lock_file: File) {
    let sig = signals.wait().unwrap_or(0);
    let was_unlocked = locked(&shared.state).lock(LockReason::Signal);
    let _ = std::fs::remove_file(socket);
    log_line!(
        "envcloakd: stopping on signal {sig}; vault {}",
        if was_unlocked {
            "locked"
        } else {
            "was not unlocked"
        }
    );
    drop(lock_file);
    std::process::exit(0);
}

/// The sleep and idle checks.
fn observe(shared: &Shared) {
    let now = Reading::now(&shared.clocks);
    if let Some(reason) = locked(&shared.state).observe(now) {
        log_line!("envcloakd: vault locked (reason: {})", reason.as_str());
    }
}

/// The tick: the sleep and idle checks, then the grant sweep, which
/// drops expired grants and pending requests and every grant whose root
/// process exited (SPEC §10b: a grant never outlives its root), and the
/// backups v2 sweep, which ends restore leases whose process exited or
/// that sat idle, and drops backups in progress whose creator exited.
fn tick(shared: &Shared) {
    observe(shared);
    let now = now_of(&shared.clocks);
    let mut s = locked(&shared.state);
    s.grants().sweep(&now, &requests::alive);
    s.backups().sweep(now.awake);
    s.audit_tick(Reading::now(&shared.clocks));
}

/// Frees a connection's place when its thread ends, or when the thread
/// could not be started.
struct ConnectionSlot {
    shared: Arc<Shared>,
    pid: i32,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        let mut places = locked(&self.shared.places);
        places.give_back(self.pid);
        if envcloak_sys::test_trace() {
            log_line!(
                "envcloakd: test: connection closed pid={} open={}",
                self.pid,
                places.total
            );
        }
    }
}

fn accept_loop(listener: &UnixListener, shared: &Arc<Shared>) {
    let own_uid = envcloak_sys::effective_uid();
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                // Out of descriptors, say: back off instead of spinning.
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        let peer = match envcloak_sys::peer_identity(stream.as_fd()) {
            Ok(p) => p,
            Err(_) => {
                log_line!("envcloakd: closed a connection whose peer could not be identified");
                continue;
            }
        };
        if peer.uid != own_uid {
            shared.audit(AuditEvent::ForeignPeer {
                pid: peer.pid,
                uid: peer.uid,
            });
            continue;
        }
        let taken = locked(&shared.places).take(peer.pid);
        match taken {
            Ok(()) => {}
            Err(Full::All) => {
                log_line!("envcloakd: connection limit reached; closed a connection");
                continue;
            }
            Err(Full::Process) => {
                log_line!(
                    "envcloakd: connection limit reached for pid {}; closed a connection",
                    peer.pid
                );
                continue;
            }
        }
        if envcloak_sys::test_trace() {
            let open = locked(&shared.places).total;
            log_line!(
                "envcloakd: test: connection opened pid={} open={open}",
                peer.pid
            );
        }
        let slot = ConnectionSlot {
            shared: Arc::clone(shared),
            pid: peer.pid,
        };
        let started = thread::Builder::new()
            .name("connection".into())
            .spawn(move || {
                serve(&stream, &peer, &slot.shared);
                drop(slot);
            });
        if started.is_err() {
            log_line!("envcloakd: could not start a connection thread");
        }
    }
}

/// The wait for a frame to start: [`IDLE_CONNECTION`], or a test build's
/// override ([`envcloak_sys::idle_connection_override`]).
fn idle_connection() -> Duration {
    static WAIT: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *WAIT.get_or_init(|| envcloak_sys::idle_connection_override().unwrap_or(IDLE_CONNECTION))
}

/// Reads with a deadline: [`IDLE_CONNECTION`] until the first byte of a
/// frame, then [`FRAME_DEADLINE`] for the rest of it.
struct FrameReader<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
    started: bool,
}

impl<'a> FrameReader<'a> {
    fn new(stream: &'a UnixStream) -> Self {
        FrameReader {
            stream,
            deadline: Instant::now() + idle_connection(),
            started: false,
        }
    }
}

impl Read for FrameReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let now = Instant::now();
        if now >= self.deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(self.deadline - now))?;
        let mut stream: &UnixStream = self.stream;
        let n = stream.read(buf)?;
        if n > 0 && !self.started {
            self.started = true;
            self.deadline = Instant::now() + FRAME_DEADLINE;
        }
        Ok(n)
    }
}

/// Serves one connection until it closes, stalls or breaks the framing.
fn serve(stream: &UnixStream, peer: &PeerIdentity, shared: &Shared) {
    if stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err() {
        return;
    }
    loop {
        let frame = match Frame::read_from(&mut FrameReader::new(stream)) {
            Ok(f) => f,
            Err(e @ (FrameError::TooLarge | FrameError::Empty)) => {
                // The stream is out of step now: answer, then close.
                let kind = if e == FrameError::TooLarge {
                    ErrorKind::FrameTooLarge
                } else {
                    ErrorKind::InvalidRequest
                };
                if let Ok(f) = proto::error_frame(None, &RpcError::new(kind)) {
                    let _ = f.write_to(&mut &*stream);
                }
                return;
            }
            Err(e) => {
                // A test build's trace says when the idle bound closed a
                // connection: a waiter must never leave one open long.
                let idle = matches!(
                    e,
                    FrameError::Io(io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
                );
                if envcloak_sys::test_trace() && idle {
                    log_line!("envcloakd: test: idle connection closed pid={}", peer.pid);
                }
                return;
            }
        };
        // The process that sent this frame must be the one identified at
        // accept, for proofs above all (review T7 open 1).
        if !matches!(envcloak_sys::peer_unchanged(stream.as_fd(), peer), Ok(true)) {
            log_line!(
                "envcloakd: closed a connection now used by another process than pid {}, the \
                 one identified when it was accepted",
                peer.pid
            );
            return;
        }
        let response = dispatch(&frame, peer, shared);
        drop(frame);
        match response {
            Some(r) if r.write_to(&mut &*stream).is_ok() => {}
            _ => return,
        }
    }
}

/// Answers one request frame.
fn dispatch(frame: &Frame, peer: &PeerIdentity, shared: &Shared) -> Option<Frame> {
    let req = match IncomingRequest::parse(frame) {
        Ok(r) => r,
        Err(e) => return proto::error_frame(None, &e).ok(),
    };
    let id = req.id;
    // The sleep and idle checks run before every request too.
    observe(shared);
    if required_role(req.method) == Role::App {
        shared.audit(AuditEvent::RoleDenied {
            method: loggable_method(req.method),
            pid: peer.pid,
            uid: peer.uid,
        });
        return proto::error_frame(Some(id), &RpcError::new(ErrorKind::RoleDenied)).ok();
    }
    match req.method {
        Status::NAME => answer::<Status>(id, &req, |_| Ok(status(shared))),
        Lock::NAME => answer::<Lock>(id, &req, |_| {
            let was_unlocked = locked(&shared.state).lock(LockReason::Request);
            if was_unlocked {
                log_line!("envcloakd: vault locked (reason: request)");
            }
            Ok(LockedView { was_unlocked })
        }),
        Unlock::NAME => answer::<Unlock>(id, &req, |p| unlock(shared, peer, p)),
        VaultCreate::NAME => answer::<VaultCreate>(id, &req, |p| create(shared, peer, p)),
        RunRequest::NAME => {
            answer::<RunRequest>(id, &req, |p| requests::run_request(shared, peer, p))
        }
        PendingGet::NAME => {
            answer::<PendingGet>(id, &req, |p| requests::pending_get(shared, peer, p))
        }
        PendingPoll::NAME => {
            answer::<PendingPoll>(id, &req, |p| requests::pending_state(shared, peer, p))
        }
        PendingList::NAME => {
            answer::<PendingList>(id, &req, |p| requests::pending_list(shared, peer, p))
        }
        Approve::NAME => answer::<Approve>(id, &req, |p| requests::approve(shared, peer, p)),
        Deny::NAME => answer::<Deny>(id, &req, |p| requests::deny(shared, peer, p)),
        GrantsList::NAME => answer::<GrantsList>(id, &req, |_| requests::grants_list(shared)),
        GrantsRevoke::NAME => {
            answer::<GrantsRevoke>(id, &req, |p| requests::grants_revoke(shared, peer, p))
        }
        AuditVerify::NAME => {
            answer::<AuditVerify>(id, &req, |_| locked(&shared.state).audit_verify())
        }
        ItemsList::NAME => answer::<ItemsList>(id, &req, |p| items::list(shared, p)),
        ItemsShow::NAME => answer::<ItemsShow>(id, &req, |p| items::show(shared, p)),
        ItemsCheck::NAME => answer::<ItemsCheck>(id, &req, |p| items::check(shared, p)),
        ItemsAdd::NAME => answer::<ItemsAdd>(id, &req, |p| items::add(shared, peer, p)),
        ItemsTarget::NAME => {
            answer::<ItemsTarget>(id, &req, |p| items::target_view(shared, peer, p))
        }
        ItemsRotate::NAME => answer::<ItemsRotate>(id, &req, |p| items::rotate(shared, peer, p)),
        ItemsRemove::NAME => answer::<ItemsRemove>(id, &req, |p| items::remove(shared, peer, p)),
        ImportPlan::NAME => {
            answer::<ImportPlan>(id, &req, |p| import::import_plan(shared, peer, p))
        }
        ImportCommit::NAME => {
            answer::<ImportCommit>(id, &req, |p| import::import_commit(shared, peer, p))
        }
        ImportVerify::NAME => {
            answer::<ImportVerify>(id, &req, |p| import::import_verify(shared, peer, p))
        }
        FilesBackup::NAME => {
            answer::<FilesBackup>(id, &req, |p| import::files_backup(shared, peer, p))
        }
        FilesRestore::NAME => {
            answer::<FilesRestore>(id, &req, |p| import::files_restore(shared, peer, p))
        }
        RecoveryConfirm::NAME => {
            answer::<RecoveryConfirm>(id, &req, |p| import::recovery_confirm(shared, peer, p))
        }
        BackupCreate::NAME => answer::<BackupCreate>(id, &req, |p| backup::create(shared, peer, p)),
        VaultRecover::NAME => {
            answer::<VaultRecover>(id, &req, |p| backup::recover(shared, peer, p))
        }
        BackupBegin::NAME => answer::<BackupBegin>(id, &req, |p| backups::begin(shared, peer, p)),
        BackupPut::NAME => answer::<BackupPut>(id, &req, |p| backups::put(shared, peer, p)),
        BackupCommit::NAME => {
            answer::<BackupCommit>(id, &req, |p| backups::commit(shared, peer, p))
        }
        BackupRecordResult::NAME => {
            answer::<BackupRecordResult>(id, &req, |p| backups::record_result(shared, peer, p))
        }
        BackupOpenRestore::NAME => {
            answer::<BackupOpenRestore>(id, &req, |p| backups::open_restore(shared, peer, p))
        }
        BackupRead::NAME => answer::<BackupRead>(id, &req, |p| backups::read(shared, peer, p)),
        BackupList::NAME => answer::<BackupList>(id, &req, |p| backups::list(shared, p)),
        _ => proto::error_frame(Some(id), &RpcError::new(ErrorKind::MethodNotFound)).ok(),
    }
}

/// Parses `M`'s parameters, runs `f` and frames the result or error.
fn answer<'a, M: Method>(
    id: u64,
    req: &IncomingRequest<'a>,
    f: impl FnOnce(M::Params) -> Result<M::Output, RpcError>,
) -> Option<Frame> {
    let result = req.params::<M::Params>().and_then(f);
    match result {
        Ok(out) => proto::result_frame(id, &out)
            .or_else(|_| proto::error_frame(Some(id), &RpcError::new(ErrorKind::Internal)))
            .ok(),
        Err(e) => proto::error_frame(Some(id), &e).ok(),
    }
}

fn status(shared: &Shared) -> StatusView {
    let daemon = DaemonView {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        pid: std::process::id(),
        hardening: envcloak_sys::hardening_status().into(),
        runtime_dir_fallback: shared.runtime_dir_fallback,
    };
    let now = Reading::now(&shared.clocks);
    let at = now_of(&shared.clocks);
    locked(&shared.state).status(now, &at, daemon)
}

/// The daemon handles no secret under a tracer.
pub(crate) fn refuse_if_traced() -> Result<(), RpcError> {
    match envcloak_sys::tracer_present() {
        Ok(false) => Ok(()),
        _ => Err(RpcError::new(ErrorKind::Traced)),
    }
}

/// `unlock` is a proof (SPEC §10b): refused from a caller that may not
/// give one (an agent by any evidence, or no terminal session), and
/// subject to the attempt limiter. The evidence is
/// read before the vault is looked at, so an agent learns nothing from
/// the order of the checks.
fn unlock(shared: &Shared, peer: &PeerIdentity, p: UnlockParams) -> Result<UnlockedView, RpcError> {
    let pass = p.passphrase.into_inner();
    refuse_if_traced()?;
    let claims =
        Claims::from_markers(&p.claims).map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
    let evidence = gather(peer, claims, &shared.catalog)
        .map_err(|e| RpcError::with_reason(ErrorKind::Evidence, e.token()))?;
    requests::refuse_unless_prover(shared, peer, &evidence, "unlock")?;
    let _gate = locked(&shared.proof_gate);
    let begin = {
        let mut s = locked(&shared.state);
        let at = now_of(&shared.clocks);
        s.limiter()
            .check(&at)
            .map_err(|_| RpcError::new(ErrorKind::TooManyAttempts))?;
        s.begin_unlock()?
    };
    let (vault, generation) = match begin {
        BeginUnlock::Already(v) => return Ok(v),
        BeginUnlock::Proceed(v, g) => (v, g),
    };
    let result = vault.unlock_with_passphrase(&pass);
    drop(pass);
    let now = Reading::now(&shared.clocks);
    let at = now_of(&shared.clocks);
    let mut s = locked(&shared.state);
    let r = s.finish_unlock(generation, now, result);
    match &r {
        Ok(_) => {
            s.limiter().succeeded();
            log_line!("envcloakd: vault unlocked");
            // File backups over 7 days old go (SPEC §6.4); they are purged
            // when one is written, too. Both kinds are purged, whatever the
            // other's purge did; no backup v2 is in progress at an unlock,
            // since a lock ended every one.
            let secs = at
                .wall
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let v1 = envcloak_core::file_backup::purge_file_backups(s.paths(), secs);
            let v2 = envcloak_core::file_backup_v2::purge_file_backups_v2(s.paths(), secs);
            if v1.is_err() || v2.is_err() {
                log_line!("envcloakd: old file backups could not be removed");
            }
            s.audit(AuditEvent::Unlocked {
                pid: peer.pid,
                created: false,
            });
        }
        Err(e) if e.kind == ErrorKind::WrongPassphrase => {
            s.limiter().failed(&at);
            s.audit(AuditEvent::UnlockFailed { pid: peer.pid });
        }
        Err(_) => {}
    }
    r
}

fn create(
    shared: &Shared,
    peer: &PeerIdentity,
    p: VaultCreateParams,
) -> Result<CreatedView, RpcError> {
    let pass = p.passphrase.into_inner();
    let kit_text = p.recovery_kit.into_inner();
    let kdf = p
        .kdf_memory_kib
        .map_or_else(KdfParams::current_defaults, KdfParams::with_memory);
    kdf.check_bounds()
        .map_err(|_| RpcError::new(ErrorKind::KdfParams))?;
    check_passphrase(&pass).map_err(passphrase_error)?;
    let kit = RecoveryKit::parse(&kit_text).map_err(|_| RpcError::new(ErrorKind::InvalidParams))?;
    drop(kit_text);
    refuse_if_traced()?;
    let _gate = locked(&shared.proof_gate);
    let (generation, paths) = {
        let mut s = locked(&shared.state);
        (s.begin_create()?, s.paths().clone())
    };
    let result = create_vault_with_kit(&paths, &pass, &kit, kdf);
    drop((pass, kit));
    let now = Reading::now(&shared.clocks);
    let mut s = locked(&shared.state);
    let r = s.finish_create(generation, now, result);
    match &r {
        Ok(v) if v.locked => {
            log_line!(
                "envcloakd: vault created, then locked (a lock arrived while it was created)"
            );
        }
        Ok(_) => {
            log_line!("envcloakd: vault created and unlocked");
            s.audit(AuditEvent::Unlocked {
                pid: peer.pid,
                created: true,
            });
        }
        Err(_) => {}
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn places_are_limited_in_all_and_per_process() {
        let mut p = Places::default();
        for _ in 0..MAX_PER_PROCESS {
            p.take(7).unwrap();
        }
        assert_eq!(p.take(7), Err(Full::Process));
        let mut pid = 100;
        while p.total < MAX_CONNECTIONS {
            if p.take(pid).is_err() {
                pid += 1;
            }
        }
        assert_eq!(p.take(9999), Err(Full::All));
        p.give_back(7);
        assert_eq!(p.take(9999), Ok(()));
        assert_eq!(p.take(7), Err(Full::All));
        p.give_back(9999);
        p.take(7).unwrap();
        // Back at its own limit and at the total.
        assert_eq!(p.by_pid[&7], MAX_PER_PROCESS);
        assert_eq!(p.take(8), Err(Full::All));
        // Giving every place back leaves nothing behind.
        for _ in 0..MAX_PER_PROCESS {
            p.give_back(7);
        }
        assert!(!p.by_pid.contains_key(&7));
    }
}
