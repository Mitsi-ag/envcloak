//! macOS: `sysctl(KERN_PROC_PID)`, `getsid`, `proc_pidpath`, `csops` and
//! `sysctl(KERN_PROCARGS2)`.
//!
//! `proc_pidinfo(PROC_PIDTBSDINFO)` refuses processes of other users
//! (`EPERM` for `login` and `launchd`), which sit in every terminal
//! session's ancestry, so the walk reads `kinfo_proc` instead, as `ps`
//! does. Its start time is the same kernel field (`p_start`) that
//! [`crate::process_start_time`] reads.
//!
//! Each call reads by pid. A pid can be reused between two calls, but only
//! after its process exited, and then [`super::ancestry_in`]'s
//! re-validation sees another start time, so a mixed reading never
//! passes.

use std::ffi::OsString;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use zeroize::Zeroizing;

use super::{CDHASH_LEN, CodeSignature, ExeIdentity, ProcInfo, parse_procargs2};
use crate::StartTime;

/// `struct extern_proc` from `<sys/proc.h>`, LP64. Only a few fields are
/// read; the rest give the layout, which the assertions below pin to the
/// SDK's offsets.
#[repr(C)]
#[allow(dead_code)]
struct ExternProc {
    /// A union of two queue pointers and `p_starttime`, both 16 bytes.
    p_starttime: libc::timeval,
    p_vmspace: *mut libc::c_void,
    p_sigacts: *mut libc::c_void,
    p_flag: libc::c_int,
    p_stat: libc::c_char,
    p_pid: libc::pid_t,
    p_oppid: libc::pid_t,
    p_dupfd: libc::c_int,
    user_stack: *mut libc::c_char,
    exit_thread: *mut libc::c_void,
    p_debugger: libc::c_int,
    sigwait: libc::c_int,
    p_estcpu: libc::c_uint,
    p_cpticks: libc::c_int,
    p_pctcpu: u32,
    p_wchan: *mut libc::c_void,
    p_wmesg: *mut libc::c_char,
    p_swtime: libc::c_uint,
    p_slptime: libc::c_uint,
    p_realtimer: libc::itimerval,
    p_rtime: libc::timeval,
    p_uticks: u64,
    p_sticks: u64,
    p_iticks: u64,
    p_traceflag: libc::c_int,
    p_tracep: *mut libc::c_void,
    p_siglist: libc::c_int,
    p_textvp: *mut libc::c_void,
    p_holdcnt: libc::c_int,
    p_sigmask: libc::sigset_t,
    p_sigignore: libc::sigset_t,
    p_sigcatch: libc::sigset_t,
    p_priority: libc::c_uchar,
    p_usrpri: libc::c_uchar,
    p_nice: libc::c_char,
    p_comm: [u8; 17],
    p_pgrp: *mut libc::c_void,
    p_addr: *mut libc::c_void,
    p_xstat: libc::c_ushort,
    p_acflag: libc::c_ushort,
    p_ru: *mut libc::c_void,
}

/// `struct _pcred` from `<sys/sysctl.h>`.
#[repr(C)]
#[allow(dead_code)]
struct Pcred {
    pc_lock: [libc::c_char; 72],
    pc_ucred: *mut libc::c_void,
    p_ruid: libc::uid_t,
    p_svuid: libc::uid_t,
    p_rgid: libc::gid_t,
    p_svgid: libc::gid_t,
    p_refcnt: libc::c_int,
}

/// `struct _ucred` from `<sys/sysctl.h>`.
#[repr(C)]
#[allow(dead_code)]
struct Ucred {
    cr_ref: i32,
    cr_uid: libc::uid_t,
    cr_ngroups: libc::c_short,
    cr_groups: [libc::gid_t; 16],
}

/// `struct vmspace` from `<sys/vm.h>`.
#[repr(C)]
#[allow(dead_code)]
struct Vmspace {
    dummy: i32,
    dummy2: *mut libc::c_char,
    dummy3: [i32; 5],
    dummy4: [*mut libc::c_char; 3],
}

/// `struct eproc` from `<sys/sysctl.h>`.
#[repr(C)]
#[allow(dead_code)]
struct Eproc {
    e_paddr: *mut libc::c_void,
    e_sess: *mut libc::c_void,
    e_pcred: Pcred,
    e_ucred: Ucred,
    e_vm: Vmspace,
    e_ppid: libc::pid_t,
    e_pgid: libc::pid_t,
    e_jobc: libc::c_short,
    e_tdev: libc::dev_t,
    e_tpgid: libc::pid_t,
    e_tsess: *mut libc::c_void,
    e_wmesg: [libc::c_char; 8],
    e_xsize: i32,
    e_xrssize: libc::c_short,
    e_xccount: libc::c_short,
    e_xswrss: libc::c_short,
    e_flag: i32,
    e_login: [libc::c_char; 12],
    e_spare: [i32; 4],
}

/// `struct kinfo_proc` from `<sys/sysctl.h>`.
#[repr(C)]
struct KinfoProc {
    kp_proc: ExternProc,
    kp_eproc: Eproc,
}

// The macOS SDK's layout (clang, arm64 and x86_64 alike).
const _: () = {
    assert!(size_of::<KinfoProc>() == 648);
    assert!(std::mem::offset_of!(KinfoProc, kp_proc.p_flag) == 32);
    assert!(std::mem::offset_of!(KinfoProc, kp_proc.p_pid) == 40);
    assert!(std::mem::offset_of!(KinfoProc, kp_proc.p_comm) == 243);
    assert!(std::mem::offset_of!(KinfoProc, kp_eproc) == 296);
    assert!(std::mem::offset_of!(KinfoProc, kp_eproc.e_ucred.cr_uid) == 420);
    assert!(std::mem::offset_of!(KinfoProc, kp_eproc.e_ppid) == 560);
    assert!(std::mem::offset_of!(KinfoProc, kp_eproc.e_tdev) == 572);
    assert!(std::mem::offset_of!(KinfoProc, kp_eproc.e_flag) == 612);
};

/// `<sys/proc.h>`: the process has a controlling terminal.
const P_CONTROLT: libc::c_int = 0x0000_0002;
/// `<sys/types.h>`: no device.
const NODEV: libc::dev_t = -1;

// Declared in the kernel's <sys/codesign.h>; exported by libSystem.
unsafe extern "C" {
    fn csops(
        pid: libc::pid_t,
        ops: libc::c_uint,
        useraddr: *mut libc::c_void,
        usersize: libc::size_t,
    ) -> libc::c_int;
}

const CS_OPS_STATUS: libc::c_uint = 0;
const CS_OPS_CDHASH: libc::c_uint = 5;
const CS_OPS_IDENTITY: libc::c_uint = 11;
const CS_OPS_TEAMID: libc::c_uint = 14;
/// The kernel validated the signature and every page run so far.
const CS_VALID: u32 = 0x0000_0001;

fn kinfo(pid: i32) -> io::Result<KinfoProc> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    // SAFETY: KinfoProc is plain old data (integers, arrays and raw
    // pointers); all zeros is a valid value.
    let mut kp: KinfoProc = unsafe { std::mem::zeroed() };
    let mut len = size_of::<KinfoProc>();
    // SAFETY: `mib` names four ints; `kp` is writable for `len` bytes, and
    // the kernel writes at most `len` and reports how many it wrote.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            (&raw mut kp).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        return Err(if err.raw_os_error() == Some(libc::ESRCH) {
            io::ErrorKind::NotFound.into()
        } else {
            err
        });
    }
    // No such process: the call succeeds and writes nothing.
    if len != size_of::<KinfoProc>() || kp.kp_proc.p_pid != pid {
        return Err(io::ErrorKind::NotFound.into());
    }
    Ok(kp)
}

/// A NUL-terminated string blob from `csops` (`CS_OPS_IDENTITY`,
/// `CS_OPS_TEAMID`): an 8-byte header (magic, then the blob's length with
/// the header, both big-endian), then the string. Only printable ASCII up
/// to 128 bytes is kept.
fn cs_string(pid: i32, op: libc::c_uint) -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is writable for its length, which is passed; the
    // kernel writes at most that many bytes.
    let rc = unsafe { csops(pid, op, buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return None;
    }
    let len = u32::from_be_bytes(buf.get(4..8)?.try_into().ok()?) as usize;
    let body = buf.get(8..len.min(buf.len()))?;
    let end = body.iter().position(|b| *b == 0).unwrap_or(body.len());
    let s = &body[..end];
    if s.is_empty() || s.len() > 128 || !s.iter().all(|b| b.is_ascii_graphic()) {
        return None;
    }
    String::from_utf8(s.to_vec()).ok()
}

/// The code directory hash the kernel validated the running executable
/// against (`CS_OPS_CDHASH`, which answers for any process).
fn cdhash(pid: i32) -> Option<[u8; CDHASH_LEN]> {
    let mut hash = [0u8; CDHASH_LEN];
    // SAFETY: `hash` is writable for its length, which is passed; the
    // kernel refuses any other size and writes exactly that many bytes.
    let rc = unsafe { csops(pid, CS_OPS_CDHASH, hash.as_mut_ptr().cast(), hash.len()) };
    (rc == 0).then_some(hash)
}

fn signature(pid: i32) -> Option<CodeSignature> {
    let mut flags: u32 = 0;
    // SAFETY: CS_OPS_STATUS writes one u32 into `flags`, whose size we pass.
    let rc = unsafe {
        csops(
            pid,
            CS_OPS_STATUS,
            (&raw mut flags).cast(),
            size_of::<u32>(),
        )
    };
    if rc != 0 || flags & CS_VALID == 0 {
        return None;
    }
    Some(CodeSignature {
        identifier: cs_string(pid, CS_OPS_IDENTITY)?,
        team_id: cs_string(pid, CS_OPS_TEAMID),
        cdhash: cdhash(pid),
    })
}

fn exe(pid: i32) -> Option<ExeIdentity> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buf` is writable for the size passed.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    let n = usize::try_from(n)
        .ok()
        .filter(|n| *n > 0 && *n < buf.len())?;
    buf.truncate(n);
    Some(ExeIdentity {
        path: PathBuf::from(OsString::from_vec(buf)),
        file: None,
        signature: signature(pid),
    })
}

pub(super) fn proc_info(pid: i32) -> io::Result<ProcInfo> {
    let kp = kinfo(pid)?;
    let start = &kp.kp_proc.p_starttime;
    let secs = u64::try_from(start.tv_sec)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "a negative start time"))?;
    let micros = u64::try_from(start.tv_usec)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "a negative start time"))?;
    let comm = &kp.kp_proc.p_comm;
    let comm_len = comm.iter().position(|b| *b == 0).unwrap_or(comm.len());
    // SAFETY: getsid has no preconditions.
    let sid = unsafe { libc::getsid(pid) };
    Ok(ProcInfo {
        pid,
        ppid: kp.kp_eproc.e_ppid,
        start_time: StartTime::from_raw(secs.saturating_mul(1_000_000).saturating_add(micros)),
        uid: kp.kp_eproc.e_ucred.cr_uid,
        sid: (sid > 0).then_some(sid),
        controlling_tty: kp.kp_proc.p_flag & P_CONTROLT != 0 && kp.kp_eproc.e_tdev != NODEV,
        comm: OsString::from_vec(comm[..comm_len].to_vec()),
        exe: exe(pid),
        argv: None,
    })
}

/// `kern.argmax`: the size of the largest argument area, and so of the
/// buffer `KERN_PROCARGS2` needs.
fn argmax() -> io::Result<usize> {
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    let mut v: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>();
    // SAFETY: `mib` names two ints; `v` is writable for `len` bytes.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&raw mut v).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    usize::try_from(v)
        .ok()
        .filter(|n| *n >= 4 && *n <= 16 << 20)
        .ok_or_else(|| io::Error::other("an unusable kern.argmax"))
}

pub(super) fn proc_argv(pid: i32) -> io::Result<Vec<OsString>> {
    // The kernel copies the end of the argument area, environment
    // included, so the buffer must hold all of it. It is wiped on drop.
    let mut buf = Zeroizing::new(vec![0u8; argmax()?]);
    let mut len = buf.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    // SAFETY: `mib` names three ints; `buf` is writable for `len` bytes,
    // and the kernel writes at most that many and reports how many.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let filled = buf
        .get(..len)
        .ok_or_else(|| io::Error::other("the kernel reported more than it wrote"))?;
    parse_procargs2(filled)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed process arguments"))
}
