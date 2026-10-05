//! Descriptors handed over a Unix socket as `SCM_RIGHTS` (M2 plan D-36,
//! task M2-27): the pipe ends a daemon-started runner or relay uses, which
//! a client sends with its request and never as data.
//!
//! - [`send_with_fds`] writes bytes with descriptors attached to the first
//!   of them, and the rest of the bytes as plain writes.
//! - [`recv_with_fds`] reads bytes and takes every descriptor that came
//!   with them, each close-on-exec, at most [`MAX_FDS`] in one read. A
//!   read that brought more, or whose descriptors did not all fit
//!   (`MSG_CTRUNC`), is an error, and every one that came is closed with
//!   it (the kernel discards the ones that did not fit).
//!
//! A descriptor taken here is a capability the sender chose: the caller
//! decides what it may be ([`descriptor_kind`]) before it uses one, and
//! closes every one it did not expect.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// The most descriptors one read takes: four for a request (standard
/// input, output and error and a lifeline), with room to see that a
/// sender sent more than that. A read that brings more is refused
/// ([`recv_with_fds`]).
pub const MAX_FDS: usize = 8;

/// Room for the control message of [`MAX_FDS`] descriptors, aligned as
/// `cmsghdr` must be.
const CMSG_WORDS: usize = 16;

/// Sends `data` on the connected Unix socket `sock`, with `fds` attached
/// to its first byte. Restarts after a signal; a short write goes on with
/// plain writes, which carry no descriptor.
///
/// # Errors
/// [`io::ErrorKind::InvalidInput`] for more than [`MAX_FDS`] descriptors
/// or empty `data` (descriptors need a byte to ride on), and `sendmsg`'s
/// and `send`'s errors.
pub fn send_with_fds(sock: BorrowedFd<'_>, data: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<()> {
    if fds.len() > MAX_FDS || data.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut sent = 0;
    if !fds.is_empty() {
        sent = send_first(sock, data, fds)?;
    }
    while sent < data.len() {
        let rest = &data[sent..];
        // SAFETY: `rest` is a valid slice for its length; send only reads
        // it.
        let n = unsafe {
            libc::send(
                sock.as_raw_fd(),
                rest.as_ptr().cast(),
                rest.len(),
                SEND_FLAGS,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        sent += usize::try_from(n).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    }
    Ok(())
}

/// No SIGPIPE on Linux for a peer that is gone: the error comes back
/// instead. macOS has no such flag; Rust programs ignore SIGPIPE anyway.
#[cfg(any(target_os = "linux", target_os = "android"))]
const SEND_FLAGS: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const SEND_FLAGS: libc::c_int = 0;

/// One `sendmsg` of `data` with `fds` in an `SCM_RIGHTS` message: how many
/// bytes went (at least one, which carries the descriptors).
fn send_first(sock: BorrowedFd<'_>, data: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<usize> {
    let mut space = [0u64; CMSG_WORDS];
    let raw: Vec<libc::c_int> = fds.iter().map(AsRawFd::as_raw_fd).collect();
    let payload = std::mem::size_of_val(raw.as_slice());
    let payload32 =
        u32::try_from(payload).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: CMSG_SPACE only computes a length.
    let needed = unsafe { libc::CMSG_SPACE(payload32) } as usize;
    if needed > std::mem::size_of_val(&space) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    // SAFETY: msghdr is plain data; zero is a valid empty value for it.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = space.as_mut_ptr().cast();
    msg.msg_controllen = needed as _;
    // SAFETY: `msg` points at `space`, which is large enough for one
    // control message of `payload` bytes (checked above), so the first
    // header and its data are inside it.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(payload32) as _;
        std::ptr::copy_nonoverlapping(raw.as_ptr().cast::<u8>(), libc::CMSG_DATA(cmsg), payload);
    }
    loop {
        // SAFETY: `msg` and everything it points at live until the call
        // returns; sendmsg only reads them.
        let n = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, SEND_FLAGS) };
        if n >= 0 {
            return usize::try_from(n).map_err(|_| io::ErrorKind::InvalidData.into());
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

/// Reads at most `buf.len()` bytes from the Unix socket `sock` and appends
/// every descriptor that came with them to `fds`, each close-on-exec: on
/// Linux as it is received (`MSG_CMSG_CLOEXEC`), on macOS just after.
/// Returns how many bytes were read: 0 at the end of the stream.
///
/// # Errors
/// [`io::ErrorKind::InvalidData`] when more than [`MAX_FDS`] descriptors
/// came with the read, or they did not all fit (`MSG_CTRUNC`): every one
/// that came is closed (the kernel discarded the ones that did not fit),
/// and none is appended. `recvmsg`'s errors otherwise: a read with a
/// timeout set on the socket times out as a `read` does.
pub fn recv_with_fds(
    sock: BorrowedFd<'_>,
    buf: &mut [u8],
    fds: &mut Vec<OwnedFd>,
) -> io::Result<usize> {
    let mut space = [0u64; CMSG_WORDS];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: msghdr is plain data; zero is a valid empty value for it.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = space.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&space) as _;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let flags = libc::MSG_CMSG_CLOEXEC;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let flags = 0;
    let n = loop {
        // SAFETY: `msg` points at `buf` and `space`, both writable for the
        // lengths it gives.
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, flags) };
        if n >= 0 {
            break usize::try_from(n).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    };
    let mut got: Vec<OwnedFd> = Vec::new();
    // SAFETY: the kernel filled `space` with `msg_controllen` bytes of
    // control messages; CMSG_FIRSTHDR and CMSG_NXTHDR stay inside them.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        // SAFETY: `cmsg` is a header inside `space` (see above).
        let (level, kind, len) =
            unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type, (*cmsg).cmsg_len) };
        if level == libc::SOL_SOCKET && kind == libc::SCM_RIGHTS {
            // SAFETY: CMSG_LEN only computes a length.
            let header = unsafe { libc::CMSG_LEN(0) } as usize;
            // `cmsg_len` is a `usize` on Linux and a `u32` on macOS.
            #[allow(clippy::unnecessary_cast)]
            let bytes = (len as usize).saturating_sub(header);
            let count = bytes / std::mem::size_of::<libc::c_int>();
            // SAFETY: the data of an SCM_RIGHTS message is `count` ints,
            // inside `space`; read unaligned, as CMSG_DATA need not be
            // aligned for an int.
            let data = unsafe { libc::CMSG_DATA(cmsg) }.cast::<libc::c_int>();
            for i in 0..count {
                // SAFETY: `i < count`, inside the message's data.
                let raw = unsafe { data.add(i).read_unaligned() };
                if raw >= 0 {
                    // SAFETY: the kernel installed `raw` in this process for
                    // this message; nothing else owns it.
                    got.push(unsafe { OwnedFd::from_raw_fd(raw) });
                }
            }
        }
        // SAFETY: as above.
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    for fd in &got {
        // SAFETY: F_SETFD on a descriptor owned here.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 || got.len() > MAX_FDS {
        // More than one read takes (the control buffer has room for
        // more): every one that came is closed here, with `got`.
        return Err(io::ErrorKind::InvalidData.into());
    }
    fds.extend(got);
    Ok(n)
}

/// What a descriptor refers to, as far as a hand-off cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DescriptorKind {
    /// A pipe or FIFO.
    Pipe,
    /// A socket.
    Socket,
    /// Anything else: a regular file, a directory, a device.
    Other,
}

/// Which way a descriptor may be used, from its open flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Access {
    Read,
    Write,
    ReadWrite,
}

/// What `fd` refers to and how it was opened: `fstat`'s file type and
/// `F_GETFL`'s access mode.
///
/// # Errors
/// `fstat`'s and `fcntl`'s errors.
pub fn descriptor_kind(fd: BorrowedFd<'_>) -> io::Result<(DescriptorKind, Access)> {
    // SAFETY: stat is plain data; fstat fills it in.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is writable; `fd` is open for as long as it is borrowed.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let kind = match st.st_mode & libc::S_IFMT {
        libc::S_IFIFO => DescriptorKind::Pipe,
        libc::S_IFSOCK => DescriptorKind::Socket,
        _ => DescriptorKind::Other,
    };
    // SAFETY: F_GETFL only reads the open file's status flags.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let access = match flags & libc::O_ACCMODE {
        libc::O_RDONLY => Access::Read,
        libc::O_WRONLY => Access::Write,
        _ => Access::ReadWrite,
    };
    Ok((kind, access))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    use super::*;

    /// A descriptor sent with the first byte arrives with it, open and
    /// close-on-exec, and names the same pipe: what is written to the
    /// sent end is read from the end kept.
    #[test]
    fn a_pipe_end_crosses_with_its_bytes() {
        let (a, b) = UnixStream::pair().unwrap();
        let (r, w) = crate::pipe_cloexec().unwrap();
        send_with_fds(a.as_fd(), b"hello", &[w.as_fd()]).unwrap();
        drop(w);
        let mut fds = Vec::new();
        let mut buf = [0u8; 16];
        let n = recv_with_fds(b.as_fd(), &mut buf, &mut fds).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(fds.len(), 1);
        assert!(crate::cloexec_flag(fds[0].as_fd()).unwrap());
        assert_eq!(
            descriptor_kind(fds[0].as_fd()).unwrap(),
            (DescriptorKind::Pipe, Access::Write)
        );
        let mut sent = std::fs::File::from(fds.pop().unwrap());
        sent.write_all(b"through").unwrap();
        drop(sent);
        let mut out = String::new();
        std::fs::File::from(r).read_to_string(&mut out).unwrap();
        assert_eq!(out, "through");
    }

    /// The most one read takes arrive; one more than that is refused by
    /// the sender, before anything is sent.
    #[test]
    fn at_most_max_fds_cross_in_one_message() {
        let (a, b) = UnixStream::pair().unwrap();
        let ends: Vec<(OwnedFd, OwnedFd)> = (0..MAX_FDS)
            .map(|_| crate::pipe_cloexec().unwrap())
            .collect();
        let borrowed: Vec<BorrowedFd<'_>> = ends.iter().map(|(r, _)| r.as_fd()).collect();
        send_with_fds(a.as_fd(), b"x", &borrowed).unwrap();
        let mut fds = Vec::new();
        let mut buf = [0u8; 4];
        let n = recv_with_fds(b.as_fd(), &mut buf, &mut fds).unwrap();
        assert_eq!((n, fds.len()), (1, MAX_FDS));
        let one_more: Vec<(OwnedFd, OwnedFd)> = (0..=MAX_FDS)
            .map(|_| crate::pipe_cloexec().unwrap())
            .collect();
        let borrowed: Vec<BorrowedFd<'_>> = one_more.iter().map(|(r, _)| r.as_fd()).collect();
        assert_eq!(
            send_with_fds(a.as_fd(), b"x", &borrowed)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    /// Bytes without descriptors read as bytes, and a closed peer reads as
    /// the end of the stream.
    #[test]
    fn plain_bytes_and_the_end_of_the_stream() {
        let (mut a, b) = UnixStream::pair().unwrap();
        a.write_all(b"abc").unwrap();
        drop(a);
        let mut fds = Vec::new();
        let mut buf = [0u8; 8];
        assert_eq!(recv_with_fds(b.as_fd(), &mut buf, &mut fds).unwrap(), 3);
        assert_eq!(recv_with_fds(b.as_fd(), &mut buf, &mut fds).unwrap(), 0);
        assert!(fds.is_empty());
    }
}
