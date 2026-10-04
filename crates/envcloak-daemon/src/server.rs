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
use std::io::{self, Read, Write};
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
    FilesRestore, FilesShow, GrantsList, GrantsRevoke, ImportCommit, ImportPlan, ImportVerify,
    IncomingRequest, ItemsAdd, ItemsCheck, ItemsList, ItemsMarkExposed, ItemsRemove, ItemsRotate,
    ItemsShow, ItemsTarget, Lock, Method, PendingGet, PendingList, PendingPoll, RecoveryConfirm,
    Role, RunRequest, ScanMatch, Status, Unlock, UnlockParams, VaultCreate, VaultCreateParams,
    VaultRecover, loggable_method, required_role,
};
use envcloak_ipc::view::{
    CreatedView, DaemonView, LockReason, LockedView, StatusView, UnlockedView,
};
use envcloak_ipc::{Frame, FrameError, RpcError, RunPathErrorKind, RunPaths};
use envcloak_policy::AgentCatalog;
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
/// A response must be written within this long, as a whole.
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
    /// The digests of the executables in callers' ancestries (Linux; M2
    /// plan D-09), which every request's evidence reads through.
    pub(crate) exe_hashes: crate::exe_hash::ExeHashCache,
    /// The provider registry compiled into this build, whose key patterns
    /// mask keys in the command lines the audit log keeps.
    pub(crate) registry: Option<Registry>,
    /// Values compared with the vault, per subject root: those of the
    /// import methods and the guessable candidates of `scan.match`
    /// (`ValueChecks`).
    pub(crate) value_checks: Mutex<crate::import::ValueChecks>,
    /// `scan.match`'s candidates that are not guessable, per subject root
    /// (`ScanChecks`, M2 plan D-32). Taken after `value_checks`, never
    /// before.
    pub(crate) scan_checks: Mutex<crate::import::ValueChecks>,
    /// The restore chunks on their way out, which a lock waits for.
    pub(crate) deliveries: backups::Deliveries,
}

impl Shared {
    /// Records an event in the audit log. Takes the state lock: callers
    /// that hold it use [`State::audit`].
    pub(crate) fn audit(&self, e: AuditEvent) {
        locked(&self.state).audit(e);
    }

    /// What the daemon shares, as `run_daemon` makes it (the builtin
    /// catalog, the production hash cache, no registry), with its vault
    /// at `paths`, for tests of what requests read through it (on Linux,
    /// where executables are hashed).
    #[cfg(all(test, any(target_os = "linux", target_os = "android")))]
    pub(crate) fn for_tests(paths: VaultPaths) -> Shared {
        let clocks = SystemClocks;
        let state = State::open(paths, crate::lock::DEFAULT_IDLE, Reading::now(&clocks));
        Shared {
            state: Mutex::new(state),
            proof_gate: Mutex::new(()),
            clocks,
            places: Mutex::new(Places::default()),
            runtime_dir_fallback: false,
            catalog: AgentCatalog::builtin(),
            exe_hashes: crate::exe_hash::ExeHashCache::new(),
            registry: None,
            value_checks: Mutex::new(crate::import::ValueChecks::default()),
            scan_checks: Mutex::new(crate::import::ValueChecks::with_limit(
                crate::scan_match::MAX_SCAN_CHECKS,
            )),
            deliveries: backups::Deliveries::default(),
        }
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
        exe_hashes: crate::exe_hash::ExeHashCache::new(),
        registry,
        value_checks: Mutex::new(crate::import::ValueChecks::default()),
        scan_checks: Mutex::new(crate::import::ValueChecks::with_limit(
            crate::scan_match::MAX_SCAN_CHECKS,
        )),
        deliveries: backups::Deliveries::default(),
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
    backups::wait_for_deliveries(&shared.state, &shared.deliveries);
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

/// The sleep and idle checks. A lock they make waits for the restore
/// chunks on their way out, as every lock does.
fn observe(shared: &Shared) {
    observe_at(
        &shared.state,
        &shared.deliveries,
        Reading::now(&shared.clocks),
    );
}

/// [`observe`] at the reading `now`.
fn observe_at(state: &Mutex<State>, deliveries: &backups::Deliveries, now: Reading) {
    let reason = locked(state).observe(now);
    if let Some(reason) = reason {
        log_line!("envcloakd: vault locked (reason: {})", reason.as_str());
        backups::wait_for_deliveries(state, deliveries);
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

/// Writes an answer within one deadline, [`WRITE_TIMEOUT`] from its
/// first byte, however slowly the client reads it: a lock waits for a
/// restore chunk's answer to be written ([`backups::Deliveries`]), so the
/// whole write is bounded, not each part of it. Each write waits for the
/// socket (`poll`) only for the time left and then writes without
/// blocking: a blocking write with a send timeout stays in the kernel as
/// long as the reader keeps taking a little, since the timeout starts
/// again at every wait inside one call (macOS), so it would bound nothing.
struct FrameWriter<'a> {
    stream: &'a UnixStream,
    deadline: Instant,
}

impl<'a> FrameWriter<'a> {
    fn new(stream: &'a UnixStream) -> Self {
        Self::until(stream, Instant::now() + WRITE_TIMEOUT)
    }

    /// A writer whose every write ends by `deadline`.
    fn until(stream: &'a UnixStream, deadline: Instant) -> Self {
        FrameWriter { stream, deadline }
    }
}

impl FrameWriter<'_> {
    /// Writes what the socket takes now of `buf`, once it takes any, on a
    /// socket left non-blocking; past the deadline, `TimedOut`.
    fn write_when_ready(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let left = self
                .deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(io::ErrorKind::TimedOut)?;
            match envcloak_sys::wait_writable(self.stream.as_fd(), left) {
                // Not ready in the time left: past the deadline that is the
                // timeout, at the top of the loop.
                Ok(false) => continue,
                Ok(true) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
            let mut stream: &UnixStream = self.stream;
            match stream.write(buf) {
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

impl Write for FrameWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Non-blocking for the write only: the next request is read with
        // the socket blocking again.
        self.stream.set_nonblocking(true)?;
        let written = self.write_when_ready(buf);
        let blocking = self.stream.set_nonblocking(false);
        let n = written?;
        blocking?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Serves one connection until it closes, stalls or breaks the framing.
fn serve(stream: &UnixStream, peer: &PeerIdentity, shared: &Shared) {
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
                    let _ = f.write_to(&mut FrameWriter::new(stream));
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
        let (response, delivering) = dispatch(&frame, peer, shared);
        drop(frame);
        let written = response.is_some_and(|r| r.write_to(&mut FrameWriter::new(stream)).is_ok());
        // A restore chunk's delivery ends once its answer is written, or
        // its write failed: a lock waiting for it goes on.
        if let Some(d) = delivering {
            envcloak_sys::test_event("backup.v2 chunk written");
            drop(d);
        }
        if !written {
            return;
        }
    }
}

/// Answers one request frame: the answer and, for a restore chunk, its
/// delivery, which the caller holds until the answer is written.
fn dispatch<'s>(
    frame: &Frame,
    peer: &PeerIdentity,
    shared: &'s Shared,
) -> (Option<Frame>, Option<backups::Delivering<'s>>) {
    let mut delivering = None;
    let answer = respond(frame, peer, shared, &mut delivering);
    (answer, delivering)
}

/// Answers one request frame, putting a restore chunk's delivery in
/// `delivering`.
fn respond<'s>(
    frame: &Frame,
    peer: &PeerIdentity,
    shared: &'s Shared,
    delivering: &mut Option<backups::Delivering<'s>>,
) -> Option<Frame> {
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
            // Answered once no restore chunk checked before it is still
            // going out.
            backups::wait_for_deliveries(&shared.state, &shared.deliveries);
            envcloak_sys::test_event("lock answered");
            Ok(LockedView { was_unlocked })
        }),
        Unlock::NAME => answer::<Unlock>(id, &req, |p| unlock(shared, peer, p)),
        VaultCreate::NAME => answer::<VaultCreate>(id, &req, |p| create(shared, peer, p)),
        RunRequest::NAME => {
            framed::<RunRequest>(id, &req, |p| requests::run_request(shared, peer, id, p))
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
        ItemsMarkExposed::NAME => {
            answer::<ItemsMarkExposed>(id, &req, |p| items::mark_exposed(shared, peer, p))
        }
        ScanMatch::NAME => {
            answer::<ScanMatch>(id, &req, |p| crate::scan_match::scan_match(shared, peer, p))
        }
        ImportPlan::NAME => {
            answer::<ImportPlan>(id, &req, |p| import::import_plan(shared, peer, p))
        }
        ImportCommit::NAME => {
            framed::<ImportCommit>(id, &req, |p| import::import_commit(shared, peer, id, p))
        }
        ImportVerify::NAME => {
            answer::<ImportVerify>(id, &req, |p| import::import_verify(shared, peer, p))
        }
        FilesBackup::NAME => {
            answer::<FilesBackup>(id, &req, |p| import::files_backup(shared, peer, p))
        }
        FilesShow::NAME => answer::<FilesShow>(id, &req, |p| import::files_show(shared, peer, p)),
        FilesRestore::NAME => {
            framed::<FilesRestore>(id, &req, |p| import::files_restore(shared, peer, id, p))
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
        BackupRead::NAME => answer::<BackupRead>(id, &req, |p| {
            backups::read(shared, peer, p).map(|(chunk, d)| {
                *delivering = Some(d);
                chunk
            })
        }),
        BackupList::NAME => answer::<BackupList>(id, &req, |p| backups::list(shared, p)),
        _ => proto::error_frame(Some(id), &RpcError::new(ErrorKind::MethodNotFound)).ok(),
    }
}

/// Parses `M`'s parameters, runs `f` and frames the result or error. A
/// result too large for one frame is answered `frame_too_large`, never
/// `internal`.
fn answer<'a, M: Method>(
    id: u64,
    req: &IncomingRequest<'a>,
    f: impl FnOnce(M::Params) -> Result<M::Output, RpcError>,
) -> Option<Frame> {
    match req.params::<M::Params>().and_then(f) {
        Ok(out) => match result_framed::<M>(id, &out) {
            Ok(frame) => Some(frame),
            Err(e) => proto::error_frame(Some(id), &e).ok(),
        },
        Err(e) => proto::error_frame(Some(id), &e).ok(),
    }
}

/// `answer`, `M`'s result, framed as the answer to request `id`: one that
/// does not fit in a frame is `frame_too_large`, any other failure
/// `internal`.
pub(crate) fn result_framed<M: Method>(id: u64, answer: &M::Output) -> Result<Frame, RpcError> {
    proto::result_frame(id, answer).map_err(|e| match e {
        FrameError::TooLarge => RpcError::new(ErrorKind::FrameTooLarge),
        _ => RpcError::new(ErrorKind::Internal),
    })
}

/// A method's answer that commits something (a vault write, an audited
/// delivery): `answer` is framed as the result of request `id` first, and
/// `commit` runs only once it is known to fit (F-77's order), so an
/// answer too large for a frame commits nothing. The frame is given back
/// only when `commit` succeeded, and dropped (wiped) otherwise.
pub(crate) fn commit_framed<M: Method>(
    id: u64,
    answer: &M::Output,
    commit: impl FnOnce() -> Result<(), RpcError>,
) -> Result<Frame, RpcError> {
    let frame = result_framed::<M>(id, answer)?;
    commit()?;
    Ok(frame)
}

/// As [`answer`], for a method that frames its own result: a covered
/// `run.request`, `files.restore` and `import.commit` frame their answer
/// before they commit it (F-77, [`commit_framed`]).
fn framed<'a, M: Method>(
    id: u64,
    req: &IncomingRequest<'a>,
    f: impl FnOnce(M::Params) -> Result<Frame, RpcError>,
) -> Option<Frame> {
    match req.params::<M::Params>().and_then(f) {
        Ok(frame) => Some(frame),
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
    let evidence = requests::evidence(shared, peer, &p.claims)?;
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
            let purged = purge_both(
                || envcloak_core::file_backup::purge_file_backups(s.paths(), secs),
                || envcloak_core::file_backup_v2::purge_file_backups_v2(s.paths(), secs),
            );
            if !purged {
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

/// Runs the purge of v1 file backups, then the purge of v2 ones, each
/// whatever the other did. Returns whether both succeeded.
fn purge_both<E>(
    v1: impl FnOnce() -> Result<usize, E>,
    v2: impl FnOnce() -> Result<usize, E>,
) -> bool {
    let v1 = v1();
    let v2 = v2();
    v1.is_ok() && v2.is_ok()
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

    /// F-77's order for every method that commits something: the answer
    /// is framed first, and the commit runs only when it fits. One larger
    /// than a frame is `frame_too_large` with nothing committed; one that
    /// fits commits once and is given back; a commit that fails gives its
    /// error, not the frame.
    ///
    /// Mutation: commit, then frame (the oversized answer commits).
    #[test]
    fn an_answer_is_framed_before_anything_is_committed() {
        let plan = |digest: String| envcloak_ipc::view::ImportPlanView {
            digest,
            entries: Vec::new(),
            items: Vec::new(),
        };
        let big = plan("x".repeat(envcloak_ipc::MAX_FRAME));
        let mut commits = 0;
        let got = commit_framed::<ImportCommit>(7, &big, || {
            commits += 1;
            Ok(())
        });
        assert_eq!(got.unwrap_err(), RpcError::new(ErrorKind::FrameTooLarge));
        assert_eq!(commits, 0, "committed an answer that was never sent");
        assert_eq!(
            result_framed::<ImportCommit>(7, &big).unwrap_err().kind,
            ErrorKind::FrameTooLarge
        );

        let small = plan("x".to_owned());
        let frame = commit_framed::<ImportCommit>(7, &small, || {
            commits += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(commits, 1);
        assert_eq!(
            frame.len(),
            result_framed::<ImportCommit>(7, &small).unwrap().len()
        );
        let failed = RpcError::new(ErrorKind::AuditFailed);
        assert_eq!(
            commit_framed::<ImportCommit>(7, &small, || Err(failed)).unwrap_err(),
            failed
        );
    }

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

    /// An unlock purges the v2 backups whatever the v1 purge did, and the
    /// v1 ones whatever the v2 purge did; a failure of either is reported.
    #[test]
    fn an_unlock_runs_each_purge_whatever_the_other_did() {
        for v1_fails in [true, false] {
            let (mut v1_ran, mut v2_ran) = (false, false);
            let purged = purge_both(
                || {
                    v1_ran = true;
                    if v1_fails { Err(()) } else { Ok(1) }
                },
                || {
                    v2_ran = true;
                    if v1_fails { Ok(1) } else { Err(()) }
                },
            );
            assert!(
                v1_ran && v2_ran,
                "v1 failing: {v1_fails}: a purge's failure kept the other from running"
            );
            assert!(!purged, "v1 failing: {v1_fails}: a failure not reported");
        }
        assert!(purge_both::<()>(|| Ok(0), || Ok(2)));
    }

    /// A lock by idle time or by sleep waits for a restore chunk on its way
    /// out, as one by request does: with a chunk counted as going out (as
    /// `read` counts one that passed its last check), the tick's checks at
    /// a reading past the idle limit, and at one after the machine slept,
    /// lock the vault and then wait (a barrier: the lock is seen waiting)
    /// until the chunk's answer is written, and return only then.
    #[test]
    fn an_idle_or_sleep_lock_waits_for_a_chunk_on_its_way_out() {
        use crate::clock::FakeClocks;
        use envcloak_core::SecretBytes;
        for asleep in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let paths = VaultPaths::under(dir.path().join("data"));
            let clocks = FakeClocks::new();
            let mut st = State::open(
                paths.clone(),
                crate::lock::DEFAULT_IDLE,
                Reading::now(&clocks),
            );
            let generation = st.begin_create().unwrap();
            let v = create_vault_with_kit(
                &paths,
                &SecretBytes::copy_from(b"a passphrase long enough to pass"),
                &RecoveryKit::generate(),
                KdfParams::minimum(),
            );
            st.finish_create(generation, Reading::now(&clocks), v)
                .unwrap();
            let state = Mutex::new(st);
            let deliveries = backups::Deliveries::default();
            let held = deliveries.start(locked(&state).backups().locks());
            if asleep {
                clocks.sleep(Duration::from_secs(600));
            } else {
                clocks.run(crate::lock::DEFAULT_IDLE + Duration::from_secs(1));
            }
            let now = Reading::now(&clocks);
            thread::scope(|scope| {
                let observing = scope.spawn(|| observe_at(&state, &deliveries, now));
                while deliveries.waiting() == 0 {
                    assert!(
                        !observing.is_finished(),
                        "asleep: {asleep}: the lock did not wait for a chunk on its way out"
                    );
                    thread::yield_now();
                }
                assert!(
                    locked(&state).unlocked().is_err(),
                    "asleep: {asleep}: not locked"
                );
                assert!(!observing.is_finished());
                drop(held);
                observing.join().unwrap();
            });
            assert_eq!(deliveries.waiting(), 0);
        }
    }

    /// An answer is written within one deadline as a whole, however slowly
    /// the client reads it (a lock waits for a restore chunk's answer, so
    /// that wait is bounded too): a client reading 4 KiB every 20 ms keeps
    /// every write making progress, and the writer still stops at its
    /// deadline (300 ms here, [`WRITE_TIMEOUT`] in the daemon), long before
    /// 4 MiB is through. The client stops reading after 3 seconds, so a
    /// writer that took its deadline afresh at each write would stop only
    /// after that.
    #[test]
    fn an_answer_is_written_within_one_deadline_however_slowly_it_is_read() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        theirs
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let start = Instant::now();
        let reader = thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            let mut theirs = theirs;
            while start.elapsed() < Duration::from_secs(3) {
                if matches!(theirs.read(&mut buf), Ok(0)) {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        });
        let written = FrameWriter::until(&ours, start + Duration::from_millis(300))
            .write_all(&vec![0u8; 4 << 20]);
        let took = start.elapsed();
        drop(ours);
        let _ = reader.join();
        assert!(written.is_err(), "4 MiB went through a slow reader");
        assert!(
            took < Duration::from_secs(2),
            "the writer ran past its deadline: {took:?}"
        );
    }
}
