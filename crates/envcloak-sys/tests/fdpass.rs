//! Descriptor passing (`SCM_RIGHTS`; M2 plan D-36, task M2-27) as hostile
//! input. Whatever a sender attaches to its bytes, [`recv_with_fds`] takes
//! at most [`MAX_FDS`] descriptors in one read, each close-on-exec, and
//! refuses a read that brought more, closing every one it was given; the
//! bytes arrive whole, in order, whatever their content. The sender here
//! is `sendmsg` itself, so it can attach more than [`send_with_fds`]
//! allows.
#![allow(unsafe_code, clippy::unwrap_used)]

use std::io::Read as _;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;

use envcloak_sys::cloexec_flag as closes_on_exec;
use envcloak_sys::fdpass::{MAX_FDS, recv_with_fds, send_with_fds};
use proptest::prelude::*;

/// Sends `data` with `fds` attached to its first byte in one `sendmsg`,
/// with no bound on their number.
fn sendmsg_raw(sock: BorrowedFd<'_>, data: &[u8], fds: &[BorrowedFd<'_>]) -> std::io::Result<()> {
    let raw: Vec<libc::c_int> = fds.iter().map(AsRawFd::as_raw_fd).collect();
    let bytes = std::mem::size_of_val(raw.as_slice());
    // SAFETY: CMSG_SPACE only computes a length.
    let space = unsafe { libc::CMSG_SPACE(u32::try_from(bytes).unwrap()) } as usize;
    let mut control = vec![0u64; space.div_ceil(8).max(1)];
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    // SAFETY: msghdr is plain data; zero is a valid empty value for it.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !raw.is_empty() {
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;
        // SAFETY: `control` holds `space` bytes, room for one header and
        // `raw`; CMSG_FIRSTHDR and CMSG_DATA stay inside it.
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(u32::try_from(bytes).unwrap()) as _;
            std::ptr::copy_nonoverlapping(raw.as_ptr().cast::<u8>(), libc::CMSG_DATA(c), bytes);
        }
    }
    // SAFETY: `msg` points at `data` and `control`, valid for the lengths
    // it gives; sendmsg only reads them.
    let n = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, 0) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    assert_eq!(usize::try_from(n).unwrap(), data.len(), "a short sendmsg");
    Ok(())
}

/// Whether `w`'s pipe still has a read end open somewhere: a write of one
/// byte succeeds.
fn reader_open(w: &OwnedFd) -> bool {
    use std::io::Write as _;
    std::fs::File::from(w.try_clone().unwrap())
        .write_all(b"x")
        .is_ok()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Up to [`MAX_FDS`] descriptors arrive with the first read, each
    /// close-on-exec; more are refused and every one of them closed (the
    /// pipes' write ends then find no reader). The bytes arrive whole when
    /// the descriptors are taken.
    #[test]
    fn a_read_takes_at_most_max_fds_and_closes_a_larger_batch(
        data in proptest::collection::vec(any::<u8>(), 1..600),
        k in 0usize..=(3 * MAX_FDS),
    ) {
        let (a, b) = UnixStream::pair().unwrap();
        let pipes: Vec<(OwnedFd, OwnedFd)> =
            (0..k).map(|_| envcloak_sys::pipe_cloexec().unwrap()).collect();
        let ends: Vec<BorrowedFd<'_>> = pipes.iter().map(|(r, _)| r.as_fd()).collect();
        sendmsg_raw(a.as_fd(), &data, &ends).unwrap();
        drop(ends);
        drop(a);
        let (readers, writers): (Vec<OwnedFd>, Vec<OwnedFd>) = pipes.into_iter().unzip();
        drop(readers);
        let mut fds = Vec::new();
        let mut buf = vec![0u8; data.len()];
        let first = recv_with_fds(b.as_fd(), &mut buf, &mut fds);
        match first {
            Ok(n) => {
                prop_assert!(k <= MAX_FDS, "{} descriptors taken in one read", k);
                prop_assert_eq!(fds.len(), k);
                for fd in &fds {
                    prop_assert!(closes_on_exec(fd.as_fd()).unwrap());
                }
                let mut got = buf[..n].to_vec();
                let mut rest = Vec::new();
                let mut s = &b;
                s.read_to_end(&mut rest).unwrap();
                got.extend_from_slice(&rest);
                prop_assert_eq!(got, data);
            }
            Err(e) => {
                prop_assert!(k > MAX_FDS, "a read of {} descriptors refused: {}", k, e);
                prop_assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
                prop_assert!(fds.is_empty());
                for (i, w) in writers.iter().enumerate() {
                    prop_assert!(!reader_open(w), "descriptor {} of {} left open", i, k);
                }
            }
        }
    }

    /// The sender's own bound: more than [`MAX_FDS`], or no byte to carry
    /// them, is refused before anything is sent.
    #[test]
    fn the_sender_refuses_more_than_max_fds_or_no_byte(k in 0usize..=(2 * MAX_FDS)) {
        let (a, b) = UnixStream::pair().unwrap();
        let pipes: Vec<(OwnedFd, OwnedFd)> =
            (0..k).map(|_| envcloak_sys::pipe_cloexec().unwrap()).collect();
        let ends: Vec<BorrowedFd<'_>> = pipes.iter().map(|(r, _)| r.as_fd()).collect();
        prop_assert_eq!(
            send_with_fds(a.as_fd(), b"", &ends).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        let sent = send_with_fds(a.as_fd(), b"x", &ends);
        prop_assert_eq!(sent.is_ok(), k <= MAX_FDS);
        drop(a);
        let mut rest = Vec::new();
        let mut s = &b;
        s.read_to_end(&mut rest).unwrap();
        let expected: &[u8] = if k <= MAX_FDS { b"x" } else { b"" };
        prop_assert_eq!(rest.as_slice(), expected);
    }
}
