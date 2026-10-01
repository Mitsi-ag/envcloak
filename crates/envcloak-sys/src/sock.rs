//! A client's connection to a Unix socket, bounded in time from the start
//! (SPEC §4.2; M2 plan D-04).
//!
//! `std`'s `UnixStream::connect` takes no timeout, and its socket's
//! timeouts can only be set once it is connected. A connect to a listener
//! whose backlog is full waits on Linux until a place frees, without limit
//! (macOS refuses it at once). A waiter (`envcloak run --wait`) must never
//! wait on the daemon past its deadline, so [`connect_unix`] sets the
//! socket's send and receive timeouts before it connects: Linux bounds
//! that wait by the send timeout and then answers `EAGAIN`
//! ([`io::ErrorKind::WouldBlock`]).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Connects a stream socket, close-on-exec, to the Unix socket at `path`,
/// with `timeout` as its send and receive timeouts from before the connect
/// (see the module documentation). A `timeout` under a microsecond is
/// taken as one.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] for a path that does not fit in
/// `sun_path` or holds a NUL byte; [`io::ErrorKind::WouldBlock`] when the
/// listener's backlog stayed full for `timeout` (Linux); otherwise the
/// error `connect` gave, such as [`io::ErrorKind::NotFound`] or
/// [`io::ErrorKind::ConnectionRefused`] when nothing listens there.
pub fn connect_unix(path: &Path, timeout: Duration) -> io::Result<UnixStream> {
    let (addr, len) = sockaddr(path)?;
    let fd = stream_socket()?;
    let tv = to_timeval(timeout);
    for option in [libc::SO_SNDTIMEO, libc::SO_RCVTIMEO] {
        // SAFETY: `fd` is an open socket this function owns; `tv` is a
        // valid `timeval` that outlives the call, and its size is passed.
        let r = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&raw const tv).cast::<libc::c_void>(),
                socklen(size_of::<libc::timeval>()),
            )
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let mut interrupted = false;
    loop {
        // SAFETY: `addr` is an initialized `sockaddr_un` that outlives the
        // call, and `len` does not exceed its size.
        let r = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&raw const addr).cast::<libc::sockaddr>(),
                len,
            )
        };
        if r == 0 {
            break;
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EINTR) => interrupted = true,
            // A connect retried after a signal, which the kernel had
            // finished meanwhile.
            Some(libc::EISCONN) if interrupted => break,
            _ => return Err(e),
        }
    }
    Ok(UnixStream::from(fd))
}

/// A new `AF_UNIX` stream socket, close-on-exec.
fn stream_socket() -> io::Result<OwnedFd> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let ty = libc::SOCK_STREAM | libc::SOCK_CLOEXEC;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let ty = libc::SOCK_STREAM;
    // SAFETY: a plain system call with constant arguments.
    let raw = unsafe { libc::socket(libc::AF_UNIX, ty, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a descriptor the kernel just returned, owned by no
    // one else.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // macOS has no SOCK_CLOEXEC: the flag is set before anything else is
    // done with the socket, as std sets it.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        // SAFETY: `fd` is open and owned here.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(fd)
}

/// The address of `path`, and its length.
fn sockaddr(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: `sockaddr_un` is plain data, for which all zeros is valid.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    // One byte is left for the terminating NUL.
    if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= addr.sun_path.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the socket path does not fit in a Unix socket address",
        ));
    }
    addr.sun_family = libc::sa_family_t::try_from(libc::AF_UNIX)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    for (to, from) in addr.sun_path.iter_mut().zip(bytes) {
        *to = libc::c_char::from_ne_bytes([*from]);
    }
    let len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    #[cfg(target_os = "macos")]
    {
        addr.sun_len =
            u8::try_from(len).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    }
    Ok((addr, socklen(len)))
}

fn socklen(n: usize) -> libc::socklen_t {
    libc::socklen_t::try_from(n).unwrap_or(libc::socklen_t::MAX)
}

/// `d`, at least a microsecond (a zero timeout would mean none).
fn to_timeval(d: Duration) -> libc::timeval {
    let d = d.max(Duration::from_micros(1));
    libc::timeval {
        tv_sec: libc::time_t::try_from(d.as_secs()).unwrap_or(libc::time_t::MAX),
        tv_usec: libc::suseconds_t::try_from(d.subsec_micros()).unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::Instant;

    /// A directory under /tmp for one test, short enough for `sun_path`,
    /// removed with its contents when dropped.
    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Dir {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let p = PathBuf::from(format!(
                "/tmp/ecs{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&p).unwrap();
            Dir(p)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The connection works as `UnixStream::connect`'s does: bytes cross
    /// both ways, the descriptor is close-on-exec, and the timeouts are
    /// the ones asked for.
    #[test]
    fn a_connection_carries_bytes_and_its_timeouts() {
        use std::io::{Read, Write};
        let dir = Dir::new();
        let sock = dir.0.join("s");
        let l = UnixListener::bind(&sock).unwrap();
        let mut c = connect_unix(&sock, Duration::from_millis(1500)).unwrap();
        let (mut s, _) = l.accept().unwrap();
        c.write_all(b"ping").unwrap();
        let mut got = [0u8; 4];
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"ping");
        s.write_all(b"pong").unwrap();
        c.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"pong");
        assert_eq!(c.read_timeout().unwrap(), Some(Duration::from_millis(1500)));
        assert_eq!(
            c.write_timeout().unwrap(),
            Some(Duration::from_millis(1500))
        );
        assert!(crate::cloexec_flag(std::os::fd::AsFd::as_fd(&c)).unwrap());
    }

    /// Nothing listening, no socket file, and a path too long: the errors
    /// `UnixStream::connect` gives, and nothing waits.
    #[test]
    fn no_listener_is_refused_at_once() {
        let dir = Dir::new();
        let missing = dir.0.join("none");
        assert_eq!(
            connect_unix(&missing, Duration::from_secs(5))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        let sock = dir.0.join("s");
        drop(UnixListener::bind(&sock).unwrap());
        assert_eq!(
            connect_unix(&sock, Duration::from_secs(5))
                .unwrap_err()
                .kind(),
            io::ErrorKind::ConnectionRefused
        );
        let long = dir.0.join("x".repeat(200));
        assert_eq!(
            connect_unix(&long, Duration::from_secs(5))
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    /// A listener that never accepts, its backlog full: the next connect
    /// gives up within its timeout (Linux, `WouldBlock`) or is refused at
    /// once (macOS); it never waits for a place.
    ///
    /// Mutation: set the timeouts after the connect, as std allows: on
    /// Linux the connect waits for a place without end and this fails at
    /// its 20-second bound.
    #[test]
    fn a_full_backlog_holds_a_connect_no_longer_than_its_timeout() {
        let dir = Dir::new();
        let sock = dir.0.join("s");
        let l = UnixListener::bind(&sock).unwrap();
        // SAFETY: `l` is a bound, listening socket; listening again only
        // sets its backlog.
        assert_eq!(unsafe { libc::listen(l.as_raw_fd(), 1) }, 0);
        let (tx, rx) = mpsc::channel();
        let path = sock.clone();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for _ in 0..64 {
                let started = Instant::now();
                match connect_unix(&path, Duration::from_millis(300)) {
                    Ok(s) => held.push(s),
                    Err(e) => {
                        let _ = tx.send((e.kind(), started.elapsed(), held.len()));
                        return;
                    }
                }
            }
            let _ = tx.send((io::ErrorKind::Other, Duration::ZERO, held.len()));
        });
        let (kind, took, queued) = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("a connect waited on a full backlog past its timeout");
        assert!(queued >= 1, "{queued}");
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            assert_eq!(kind, io::ErrorKind::WouldBlock);
            assert!(took >= Duration::from_millis(250), "{took:?}");
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        assert_eq!(kind, io::ErrorKind::ConnectionRefused);
        assert!(took < Duration::from_secs(10), "{took:?}");
        drop(l);
    }
}
