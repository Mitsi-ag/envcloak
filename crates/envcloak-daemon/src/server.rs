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
//!   [`MAX_CONNECTIONS`] are served at a time;
//! - one thread per connection: frames of at most 1 MiB, a body that must
//!   arrive within [`FRAME_DEADLINE`] of its first byte, and an idle limit
//!   between frames;
//! - a tick every second for the sleep and idle checks, which also run
//!   before every request; and the signal thread, which locks, removes the
//!   socket and exits.
//!
//! Argon2id runs on the connection's thread, outside the state lock, and
//! one run at a time (the proof gate), so parallel unlock attempts cannot
//! multiply its memory.

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use envcloak_core::crypto::KdfParams;
use envcloak_core::vault::VaultPaths;
use envcloak_core::{RecoveryKit, check_passphrase, create_vault_with_kit};
use envcloak_ipc::proto::{
    self, ErrorKind, IncomingRequest, Lock, Method, Role, Status, Unlock, UnlockParams,
    VaultCreate, VaultCreateParams, loggable_method, required_role,
};
use envcloak_ipc::view::{
    CreatedView, DaemonView, LockReason, LockedView, StatusView, UnlockedView,
};
use envcloak_ipc::{Frame, FrameError, RpcError, RunPathErrorKind, RunPaths};
use envcloak_sys::{PeerIdentity, TerminationSignals};

use crate::audit::{Audit, AuditEvent};
use crate::clock::SystemClocks;
use crate::lock::Reading;
use crate::state::{BeginUnlock, State, passphrase_error};

/// Connections served at once. Each holds at most one frame (1 MiB) and a
/// thread, so this bounds the daemon's memory.
pub const MAX_CONNECTIONS: usize = 32;
/// A frame's body must arrive within this long of its first byte.
pub const FRAME_DEADLINE: Duration = Duration::from_secs(10);
/// A connection with no frame for this long is closed. Long enough for a
/// person to type a passphrase between connecting and sending it.
pub const IDLE_CONNECTION: Duration = Duration::from_secs(600);
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
struct Shared {
    state: Mutex<State>,
    /// Held while Argon2id runs, so only one runs at a time.
    proof_gate: Mutex<()>,
    clocks: SystemClocks,
    audit: Audit,
    connections: AtomicUsize,
    runtime_dir_fallback: bool,
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
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
        eprintln!(
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
    let state = State::open(vault_paths, cfg.idle_limit, Reading::now(&clocks));
    eprintln!(
        "envcloakd: listening on {} (pid {}, version {})",
        run.socket.display(),
        std::process::id(),
        env!("CARGO_PKG_VERSION")
    );
    let shared = Arc::new(Shared {
        state: Mutex::new(state),
        proof_gate: Mutex::new(()),
        clocks,
        audit: Audit,
        connections: AtomicUsize::new(0),
        runtime_dir_fallback: run.fallback,
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
                    observe(&shared);
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
    eprintln!(
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
        eprintln!("envcloakd: vault locked (reason: {})", reason.as_str());
    }
}

/// Frees a connection's place when its thread ends, or when the thread
/// could not be started.
struct ConnectionSlot(Arc<Shared>);

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.connections.fetch_sub(1, Ordering::SeqCst);
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
                eprintln!("envcloakd: closed a connection whose peer could not be identified");
                continue;
            }
        };
        if peer.uid != own_uid {
            shared
                .audit
                .record(AuditEvent::ForeignPeer { uid: peer.uid });
            continue;
        }
        if shared.connections.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            shared.connections.fetch_sub(1, Ordering::SeqCst);
            eprintln!("envcloakd: connection limit reached; closed a connection");
            continue;
        }
        let slot = ConnectionSlot(Arc::clone(shared));
        let started = thread::Builder::new()
            .name("connection".into())
            .spawn(move || {
                serve(&stream, &peer, &slot.0);
                drop(slot);
            });
        if started.is_err() {
            eprintln!("envcloakd: could not start a connection thread");
        }
    }
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
            deadline: Instant::now() + IDLE_CONNECTION,
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
            Err(_) => return,
        };
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
        shared.audit.record(AuditEvent::RoleDenied {
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
                eprintln!("envcloakd: vault locked (reason: request)");
            }
            Ok(LockedView { was_unlocked })
        }),
        Unlock::NAME => answer::<Unlock>(id, &req, |p| unlock(shared, peer, p)),
        VaultCreate::NAME => answer::<VaultCreate>(id, &req, |p| create(shared, p)),
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
    locked(&shared.state).status(now, daemon)
}

/// The daemon handles no secret under a tracer.
fn refuse_if_traced() -> Result<(), RpcError> {
    match envcloak_sys::tracer_present() {
        Ok(false) => Ok(()),
        _ => Err(RpcError::new(ErrorKind::Traced)),
    }
}

fn unlock(shared: &Shared, peer: &PeerIdentity, p: UnlockParams) -> Result<UnlockedView, RpcError> {
    let pass = p.passphrase.into_inner();
    refuse_if_traced()?;
    let _gate = locked(&shared.proof_gate);
    let begin = locked(&shared.state).begin_unlock()?;
    let (vault, generation) = match begin {
        BeginUnlock::Already(v) => return Ok(v),
        BeginUnlock::Proceed(v, g) => (v, g),
    };
    let result = vault.unlock_with_passphrase(&pass);
    drop(pass);
    let now = Reading::now(&shared.clocks);
    let r = locked(&shared.state).finish_unlock(generation, now, result);
    match &r {
        Ok(_) => eprintln!("envcloakd: vault unlocked"),
        Err(e) if e.kind == ErrorKind::WrongPassphrase => {
            shared
                .audit
                .record(AuditEvent::UnlockFailed { pid: peer.pid });
        }
        Err(_) => {}
    }
    r
}

fn create(shared: &Shared, p: VaultCreateParams) -> Result<CreatedView, RpcError> {
    let pass = p.passphrase.into_inner();
    let kit_text = p.recovery_kit.into_inner();
    let mut kdf = KdfParams::current_defaults();
    if let Some(m) = p.kdf_memory_kib {
        kdf.m_kib = m;
    }
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
    let r = locked(&shared.state).finish_create(generation, now, result);
    match &r {
        Ok(v) if v.locked => {
            eprintln!(
                "envcloakd: vault created, then locked (a lock arrived while it was created)"
            );
        }
        Ok(_) => eprintln!("envcloakd: vault created and unlocked"),
        Err(_) => {}
    }
    r
}
