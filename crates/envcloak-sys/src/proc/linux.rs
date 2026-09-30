//! Linux: `/proc/<pid>/{stat,status,exe,cmdline}`.
//!
//! Each file is read by path. A pid can be reused between two reads, but
//! only after its process exited, and then [`super::ancestry_in`]'s
//! re-validation sees another start time, so a mixed reading never
//! passes.

use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;

use zeroize::Zeroizing;

use super::{
    Argv, ExeIdentity, MAX_ARGV, MAX_ARGV_BYTES, ProcInfo, parse_cmdline, parse_proc_stat,
    parse_status_euid,
};

/// A process that is gone, or never was, is [`io::ErrorKind::NotFound`].
fn gone(e: io::Error) -> io::Error {
    if e.raw_os_error() == Some(libc::ESRCH) {
        io::Error::from(io::ErrorKind::NotFound)
    } else {
        e
    }
}

fn open_proc(pid: i32, name: &str) -> io::Result<File> {
    File::open(format!("/proc/{pid}/{name}")).map_err(gone)
}

/// Reads at most `cap` bytes of `/proc/<pid>/<name>`.
fn read_proc(pid: i32, name: &str, cap: usize) -> io::Result<Vec<u8>> {
    let f = open_proc(pid, name)?;
    let mut buf = Vec::with_capacity(cap.min(4096));
    f.take(cap as u64).read_to_end(&mut buf).map_err(gone)?;
    Ok(buf)
}

/// Reads at most `cap` bytes of `/proc/<pid>/<name>` into a buffer
/// allocated once, at `cap` bytes, and wiped on drop. Each `read` asks for
/// no more than the room left, so the kernel never hands over more.
fn read_proc_wiped(pid: i32, name: &str, cap: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut f = open_proc(pid, name)?;
    let mut buf = Zeroizing::new(vec![0u8; cap]);
    let mut n = 0;
    while n < cap {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(gone(e)),
        }
    }
    buf.truncate(n);
    Ok(buf)
}

fn exe(pid: i32) -> Option<ExeIdentity> {
    let link = format!("/proc/{pid}/exe");
    let path = std::fs::read_link(&link).ok()?;
    // Follows the link to the file the process runs, even when that file
    // was renamed or removed since.
    let file = std::fs::metadata(&link).ok().map(|m| (m.dev(), m.ino()));
    Some(ExeIdentity {
        path,
        file,
        signature: None,
    })
}

pub(super) fn proc_info(pid: i32) -> io::Result<ProcInfo> {
    let stat = read_proc(pid, "stat", 4096)?;
    let f = parse_proc_stat(&stat)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "a malformed /proc stat file"))?;
    if f.pid != pid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a /proc stat file for another pid",
        ));
    }
    let status = read_proc(pid, "status", 16 * 1024)?;
    let uid = parse_status_euid(&status).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "a malformed /proc status file")
    })?;
    Ok(ProcInfo {
        pid,
        ppid: f.ppid,
        start_time: f.start_time,
        uid,
        sid: (f.session > 0).then_some(f.session),
        controlling_tty: (f.tty_nr != 0).then(|| u64::from_ne_bytes(f.tty_nr.to_ne_bytes())),
        comm: OsString::from_vec(f.comm),
        exe: exe(pid),
        argv: None,
    })
}

pub(super) fn proc_argv(pid: i32) -> io::Result<Argv> {
    // The arguments, their NULs, and one byte to tell a cut last argument.
    let mut cap = MAX_ARGV_BYTES + MAX_ARGV + 1;
    // No more than the argument area as the kernel records it: `cmdline`
    // runs on into the environment when the process overwrote the NUL that
    // ends the area (see the module documentation of `proc`). Unknown for
    // a process this one may not trace; the cap alone bounds the read then.
    let stat = read_proc(pid, "stat", 4096)?;
    if let Some(len) = parse_proc_stat(&stat)
        .filter(|f| f.pid == pid)
        .and_then(|f| f.arg_area_len())
    {
        cap = cap.min(len);
    }
    let bytes = read_proc_wiped(pid, "cmdline", cap)?;
    Ok(parse_cmdline(&bytes))
}
