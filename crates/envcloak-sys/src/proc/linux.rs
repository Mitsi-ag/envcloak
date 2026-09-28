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

use super::{
    ExeIdentity, MAX_ARGV, MAX_ARGV_BYTES, ProcInfo, parse_cmdline, parse_proc_stat,
    parse_status_euid,
};

/// Reads at most `cap` bytes of `/proc/<pid>/<name>`. A process that is
/// gone, or never was, is [`io::ErrorKind::NotFound`].
fn read_proc(pid: i32, name: &str, cap: usize) -> io::Result<Vec<u8>> {
    let gone = |e: io::Error| {
        if e.raw_os_error() == Some(libc::ESRCH) {
            io::Error::from(io::ErrorKind::NotFound)
        } else {
            e
        }
    };
    let f = File::open(format!("/proc/{pid}/{name}")).map_err(gone)?;
    let mut buf = Vec::with_capacity(cap.min(4096));
    f.take(cap as u64).read_to_end(&mut buf).map_err(gone)?;
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
        controlling_tty: f.tty_nr != 0,
        comm: OsString::from_vec(f.comm),
        exe: exe(pid),
        argv: None,
    })
}

pub(super) fn proc_argv(pid: i32) -> io::Result<Vec<OsString>> {
    // The arguments, their NULs, and one byte to tell a cut last argument.
    let bytes = read_proc(pid, "cmdline", MAX_ARGV_BYTES + MAX_ARGV + 1)?;
    Ok(parse_cmdline(&bytes))
}
