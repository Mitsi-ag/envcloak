//! A managed server's launch, resolved and checked by the daemon itself
//! (SPEC §6.6; M2 plan D-33; task M2-27). Nothing here reads a requester's
//! executable (D-36): the daemon checks the program it will start, never
//! the process that asked.
//!
//! **Registration** ([`resolve`]): the declaration `migrate-mcp` gave is
//! checked ([`envcloak_policy::managed::check_declaration`]: no variable or
//! interpreter option that selects code), a bare `argv[0]` is found once,
//! here, on the declared `PATH` (absolute entries only), the executable is
//! canonicalized and opened (`O_NOFOLLOW`), and its identity read through
//! that descriptor: on Linux its SHA-256, on macOS the hash of the code
//! directory the kernel uses (cdhash, [`envcloak_sys::codesign`]) or, for a
//! file without one, its SHA-256. Its class: `native` for an ELF or Mach-O
//! file, `script` for an interpreter with an absolute entry file or a
//! `#!` file (whose interpreter is then the executable checked), and
//! `package_runner` for `npx` and its kin. Its strength: `bound` for a
//! native file whose image can be bound (Linux: no `$ORIGIN` in its run
//! path; macOS: a code directory), `checked_at_rest` otherwise. The
//! working directory is the declared one, else the managed directory,
//! canonicalized and identified by device and inode.
//!
//! **The check before release** ([`check`]): the recorded executable is
//! opened again and its device, inode and identity compared with the
//! record, a script's entry file the same way, and the working directory's
//! device and inode; any difference is [`CheckError::Changed`]
//! (`managed_launch_changed`). On Linux a `bound` launch is copied into a
//! sealed memory file through the descriptor checked
//! ([`envcloak_sys::launch::SealedImage`]), and the identity compared is
//! the copy's: the copy is what the runner runs, so a file rewritten or
//! replaced after this check never runs. A system that refuses the copy
//! is [`CheckError::RunnerUnavailable`]: never the file instead.

use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use envcloak_core::vault::{
    BindingStrength, CodeDigest, DirIdentity, FileIdentity, LaunchClass, LaunchDecl, LaunchEnv,
    RegisteredLaunch,
};
use envcloak_ipc::RpcError;
#[cfg(any(target_os = "linux", target_os = "android"))]
use envcloak_ipc::control::Stamp;
use envcloak_ipc::proto::ErrorKind;
use envcloak_policy::managed::{
    ArgvClass, CodeSelecting, DeclError, check_declaration, classify_argv,
};
use envcloak_sys::codesign::{self, ExecutableFormat};
use sha2::{Digest, Sha256};

use crate::audit::IdentityMeta;

/// The `PATH` a declaration without one resolves a bare name on.
pub(crate) const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Why a declaration was not resolved. Carries no byte of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResolveError {
    Decl(DeclError),
    /// No executable of that name on the declared `PATH`, or none at the
    /// path; or an entry file or a directory that is not there.
    NotFound,
    /// A file that is not a regular, executable file (or a directory that
    /// is not one).
    NotExecutable,
    /// A program of no format EnvCloak can bind or check (not ELF, Mach-O
    /// or a `#!` file), or a `#!` line it cannot read.
    Unsupported,
    /// Larger than the 512 MiB EnvCloak hashes.
    TooLarge,
}

impl ResolveError {
    /// The error the protocol reports.
    pub(crate) fn rpc(self) -> RpcError {
        match self {
            ResolveError::Decl(DeclError::CodeSelecting(c)) => RpcError::with_reason(
                ErrorKind::CodeSelectingEnv,
                match c {
                    CodeSelecting::Variable => "code_selecting_variable",
                    CodeSelecting::InterpreterOption => "interpreter_option",
                },
            ),
            ResolveError::Decl(DeclError::TooLarge) | ResolveError::TooLarge => {
                RpcError::with_reason(ErrorKind::InvalidParams, "too_large")
            }
            ResolveError::Decl(DeclError::BadName) => {
                RpcError::with_reason(ErrorKind::InvalidParams, "invalid_env_name")
            }
            ResolveError::Decl(DeclError::NotAbsolute | DeclError::NoEntry) => {
                RpcError::with_reason(ErrorKind::InvalidParams, "invalid_path")
            }
            ResolveError::Decl(DeclError::Empty) => RpcError::new(ErrorKind::InvalidParams),
            ResolveError::NotFound => RpcError::with_reason(ErrorKind::InvalidParams, "not_found"),
            ResolveError::NotExecutable => {
                RpcError::with_reason(ErrorKind::InvalidParams, "not_regular_file")
            }
            ResolveError::Unsupported => RpcError::new(ErrorKind::InvalidParams),
        }
    }
}

impl From<DeclError> for ResolveError {
    fn from(e: DeclError) -> Self {
        ResolveError::Decl(e)
    }
}

/// Opens `path` (absolute) as a regular file without following a link in
/// its last component, and without blocking on a FIFO.
fn open_file(path: &Path) -> Result<File, ResolveError> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => ResolveError::NotFound,
            _ => ResolveError::NotExecutable,
        })?;
    let m = f.metadata().map_err(|_| ResolveError::NotFound)?;
    if !m.is_file() {
        return Err(ResolveError::NotExecutable);
    }
    if m.len() > codesign::MAX_EXECUTABLE {
        return Err(ResolveError::TooLarge);
    }
    Ok(f)
}

/// Opens `path` (absolute, canonical) as a directory without following a
/// link.
fn open_dir(path: &Path) -> Result<File, ResolveError> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ResolveError::NotFound)?;
    Ok(f)
}

/// The first executable regular file named `name` in a directory of
/// `path_env`, absolute directories only (an empty or relative entry,
/// which names the working directory, is skipped: the conservative
/// reading). A name with a `/` must be absolute and is taken as it is.
fn find_program(name: &str, path_env: &str) -> Result<PathBuf, ResolveError> {
    if name.contains('/') {
        if !name.starts_with('/') {
            return Err(DeclError::NotAbsolute.into());
        }
        return Ok(PathBuf::from(name));
    }
    for dir in path_env.split(':') {
        if !dir.starts_with('/') {
            continue;
        }
        let candidate = Path::new(dir).join(name);
        let runs = std::fs::metadata(&candidate)
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0);
        if runs {
            return Ok(candidate);
        }
    }
    Err(ResolveError::NotFound)
}

/// SHA-256 of the file `f` refers to, read through its descriptor.
pub(crate) fn sha256_of(f: &File) -> std::io::Result<[u8; 32]> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut at = 0u64;
    loop {
        let n = envcloak_sys::launch::read_at(f.as_fd(), &mut buf, at)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        at += n as u64;
        if at > codesign::MAX_EXECUTABLE {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
    }
    Ok(h.finalize().into())
}

/// The cdhash of a code directory: its hash by its own hash type, the
/// first 20 bytes (`CS_CDHASH_LEN`). `None` for SHA-1, which this build
/// does not compute: such a file is checked by its SHA-256 instead.
pub(crate) fn cdhash_of(cd: &codesign::CodeDirectory) -> Option<Vec<u8>> {
    let full: Vec<u8> = match cd.hash_type {
        2 | 3 => Sha256::digest(cd.cdhash_input()).to_vec(),
        4 => sha2::Sha384::digest(cd.cdhash_input()).to_vec(),
        _ => return None,
    };
    Some(full[..20].to_vec())
}

/// A file's identity as the record keeps it: on macOS a Mach-O file's
/// cdhash when it has a code directory, otherwise (and always on Linux)
/// its SHA-256.
fn identity(f: &File) -> Result<CodeDigest, ResolveError> {
    let mach_o = matches!(
        codesign::executable_format(f),
        Ok(ExecutableFormat::MachO | ExecutableFormat::MachOUniversal)
    );
    if cfg!(target_os = "macos") && mach_o {
        let cd = codesign::code_directory(f).map_err(|_| ResolveError::Unsupported)?;
        if let Some((cd, cdhash)) = cd.and_then(|cd| cdhash_of(&cd).map(|h| (cd, h))) {
            return Ok(CodeDigest::CdHash {
                cdhash,
                team: cd.team,
                identifier: cd.identifier,
            });
        }
    }
    sha256_of(f)
        .map(CodeDigest::Sha256)
        .map_err(|_| ResolveError::TooLarge)
}

fn file_identity(path: &Path) -> Result<FileIdentity, ResolveError> {
    let canonical = std::fs::canonicalize(path).map_err(|_| ResolveError::NotFound)?;
    let f = open_file(&canonical)?;
    let m = f.metadata().map_err(|_| ResolveError::NotFound)?;
    Ok(FileIdentity {
        path: canonical.as_os_str().as_bytes().to_vec(),
        dev: m.dev(),
        ino: m.ino(),
        digest: identity(&f)?,
    })
}

/// The interpreter a `#!` file names, resolved: an absolute path, or
/// `/usr/bin/env NAME` with `NAME` found on `path_env`. A line EnvCloak
/// cannot read (no interpreter, a relative one, `env` with options) is
/// [`ResolveError::Unsupported`].
fn shebang_interpreter(f: &File, path_env: &str) -> Result<PathBuf, ResolveError> {
    let mut head = [0u8; 256];
    let n = envcloak_sys::launch::read_at(f.as_fd(), &mut head, 0)
        .map_err(|_| ResolveError::Unsupported)?;
    let line = head[..n]
        .split(|b| *b == b'\n')
        .next()
        .and_then(|l| l.strip_prefix(b"#!"))
        .ok_or(ResolveError::Unsupported)?;
    let line = std::str::from_utf8(line).map_err(|_| ResolveError::Unsupported)?;
    let mut words = line.split_ascii_whitespace();
    let interp = words.next().ok_or(ResolveError::Unsupported)?;
    if !interp.starts_with('/') {
        return Err(ResolveError::Unsupported);
    }
    if Path::new(interp).file_name().and_then(|n| n.to_str()) == Some("env") {
        let name = words.next().ok_or(ResolveError::Unsupported)?;
        if name.starts_with('-') || name.contains('=') || words.next().is_some() {
            return Err(ResolveError::Unsupported);
        }
        return find_program(name, path_env);
    }
    Ok(PathBuf::from(interp))
}

/// Resolves `decl` into the registered launch `launch_id` at `revision`
/// (see the module documentation). `managed_dir` is the managed project's
/// directory, the working directory when the declaration names none;
/// `binding_names` the variables its manifest binds.
pub(crate) fn resolve(
    decl: &LaunchDecl,
    managed_dir: &Path,
    binding_names: Vec<String>,
    launch_id: [u8; 16],
    revision: u64,
) -> Result<RegisteredLaunch, ResolveError> {
    check_declaration(decl)?;
    let argv_class = classify_argv(&decl.argv)?;
    let path_env = decl
        .path_env
        .clone()
        .unwrap_or_else(|| DEFAULT_PATH.to_owned());
    let program = find_program(&decl.argv[0], &path_env)?;
    let canonical = std::fs::canonicalize(&program).map_err(|_| ResolveError::NotFound)?;
    let file = open_file(&canonical)?;
    let meta = file.metadata().map_err(|_| ResolveError::NotFound)?;
    if meta.permissions().mode() & 0o111 == 0 {
        return Err(ResolveError::NotExecutable);
    }
    let format = codesign::executable_format(&file).map_err(|_| ResolveError::Unsupported)?;
    let (class, executable, entry) = match argv_class {
        ArgvClass::PackageRunner { .. } => {
            (LaunchClass::PackageRunner, file_identity(&canonical)?, None)
        }
        ArgvClass::Interpreter { entry } => (
            LaunchClass::Script,
            file_identity(&canonical)?,
            Some(file_identity(Path::new(&decl.argv[entry]))?),
        ),
        ArgvClass::Program => match format {
            ExecutableFormat::Elf | ExecutableFormat::MachO | ExecutableFormat::MachOUniversal => {
                (LaunchClass::Native, file_identity(&canonical)?, None)
            }
            ExecutableFormat::Script => {
                // The interpreter is the executable checked; the `#!` file
                // is the entry the kernel hands it.
                let interp = shebang_interpreter(&file, &path_env)?;
                (
                    LaunchClass::Script,
                    file_identity(&interp)?,
                    Some(file_identity(&canonical)?),
                )
            }
            ExecutableFormat::Other => return Err(ResolveError::Unsupported),
        },
    };
    let strength = match class {
        LaunchClass::Native => native_strength(&file, &executable.digest)?,
        LaunchClass::Script | LaunchClass::PackageRunner => BindingStrength::CheckedAtRest,
    };
    let cwd_path = match &decl.cwd {
        Some(c) => PathBuf::from(c),
        None => managed_dir.to_path_buf(),
    };
    let cwd_canonical = std::fs::canonicalize(&cwd_path).map_err(|_| ResolveError::NotFound)?;
    let dir = open_dir(&cwd_canonical)?;
    let dm = dir.metadata().map_err(|_| ResolveError::NotFound)?;
    Ok(RegisteredLaunch {
        launch_id,
        revision,
        class,
        executable,
        argv: decl.argv.iter().map(|a| a.as_bytes().to_vec()).collect(),
        cwd: DirIdentity {
            path: cwd_canonical.as_os_str().as_bytes().to_vec(),
            dev: dm.dev(),
            ino: dm.ino(),
        },
        env: LaunchEnv {
            path_env: path_env.into_bytes(),
            vars: decl.env.clone(),
            binding_names,
        },
        entry,
        strength,
        declaration: decl.clone(),
    })
}

/// A native file's strength: on Linux `bound` unless its run path names
/// `$ORIGIN` (a sealed copy has no directory of its own); on macOS
/// `bound` only with a code directory (the suspended start's check).
fn native_strength(file: &File, digest: &CodeDigest) -> Result<BindingStrength, ResolveError> {
    if cfg!(target_os = "macos") {
        return Ok(match digest {
            CodeDigest::CdHash { .. } => BindingStrength::Bound,
            CodeDigest::Sha256(_) => BindingStrength::CheckedAtRest,
        });
    }
    let origin = codesign::elf_uses_origin(file).map_err(|_| ResolveError::Unsupported)?;
    Ok(if origin {
        BindingStrength::CheckedAtRest
    } else {
        BindingStrength::Bound
    })
}

/// The first 8 bytes of a digest, for an audit entry.
pub(crate) fn digest_prefix(d: &CodeDigest) -> u64 {
    let bytes: &[u8] = match d {
        CodeDigest::Sha256(h) => h,
        CodeDigest::CdHash { cdhash, .. } => cdhash,
    };
    let mut a = [0u8; 8];
    for (o, b) in a.iter_mut().zip(bytes) {
        *o = *b;
    }
    u64::from_be_bytes(a)
}

fn meta_of(f: &FileIdentity) -> IdentityMeta {
    IdentityMeta {
        dev: f.dev,
        ino: f.ino,
        digest_prefix: Some(digest_prefix(&f.digest)),
    }
}

/// Which part of a launch changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Part {
    Executable,
    EntryFile,
    WorkingDirectory,
}

impl Part {
    /// The part's name, as the audit entry records it.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Part::Executable => "executable",
            Part::EntryFile => "entry_file",
            Part::WorkingDirectory => "working_directory",
        }
    }
}

/// Why a launch was not released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckError {
    /// `managed_launch_changed`: the part, the recorded identity and what
    /// is there now (`None` when nothing could be read there).
    Changed {
        part: Part,
        old: IdentityMeta,
        new: Option<IdentityMeta>,
    },
    /// `runner_unavailable`: the sealed copy could not be made (the
    /// system's policy refuses an executable memory file). Linux only.
    #[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
    RunnerUnavailable,
}

/// How the runner is to run the checked program.
#[derive(Debug)]
pub(crate) enum CheckedExec {
    /// Linux, `bound`: the sealed copy whose digest is the record's.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Image(envcloak_sys::launch::SealedImage),
    /// Linux, `checked_at_rest`: the descriptor checked, and its stamp.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Descriptor { file: File, stamp: Stamp },
    /// The registered path; with `confirm` (macOS, a code directory hash
    /// recorded) the runner starts it suspended and the daemon compares
    /// the started program's cdhash with `cdhash` before it runs.
    Path {
        path: PathBuf,
        confirm: Option<Vec<u8>>,
    },
}

/// A launch that passed the check: how to run it, and the working
/// directory, opened.
#[derive(Debug)]
pub(crate) struct CheckedLaunch {
    pub exec: CheckedExec,
    pub cwd: File,
}

/// A file's stamp, read through its descriptor.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn stamp(f: &File) -> std::io::Result<Stamp> {
    let m = f.metadata()?;
    let ns = |s: i64, n: i64| i128::from(s) * 1_000_000_000 + i128::from(n);
    Ok(Stamp {
        dev: m.dev(),
        ino: m.ino(),
        size: m.len(),
        mtime_ns: ns(m.mtime(), m.mtime_nsec()),
        ctime_ns: ns(m.ctime(), m.ctime_nsec()),
    })
}

/// Opens the recorded file and compares its device, inode and identity
/// with `rec`: the open file when they match.
fn recheck(rec: &FileIdentity, part: Part) -> Result<File, CheckError> {
    let changed = |new| CheckError::Changed {
        part,
        old: meta_of(rec),
        new,
    };
    let path = Path::new(std::ffi::OsStr::from_bytes(&rec.path));
    let f = open_file(path).map_err(|_| changed(None))?;
    let m = f.metadata().map_err(|_| changed(None))?;
    let here = |digest: Option<u64>| IdentityMeta {
        dev: m.dev(),
        ino: m.ino(),
        digest_prefix: digest,
    };
    if (m.dev(), m.ino()) != (rec.dev, rec.ino) {
        // Another file: its identity too, for the audit entry, when it
        // can be read.
        let now = identity(&f).ok().map(|d| digest_prefix(&d));
        return Err(changed(Some(here(now))));
    }
    let now = identity(&f).map_err(|_| changed(Some(here(None))))?;
    if now != rec.digest {
        return Err(changed(Some(here(Some(digest_prefix(&now))))));
    }
    Ok(f)
}

/// Checks `l` before its values are released (see the module
/// documentation).
///
/// # Errors
/// [`CheckError`].
pub(crate) fn check(l: &RegisteredLaunch) -> Result<CheckedLaunch, CheckError> {
    let file = recheck(&l.executable, Part::Executable)?;
    // A `#!` file: its interpreter was the executable checked, the file
    // the entry, and the kernel runs the file by its path.
    let shebang = l.class == LaunchClass::Script
        && matches!(classify_argv(&l.declaration.argv), Ok(ArgvClass::Program));
    if let Some(entry) = &l.entry {
        drop(recheck(entry, Part::EntryFile)?);
    }
    let cwd_path = Path::new(std::ffi::OsStr::from_bytes(&l.cwd.path));
    let dir_changed = |new| CheckError::Changed {
        part: Part::WorkingDirectory,
        old: IdentityMeta {
            dev: l.cwd.dev,
            ino: l.cwd.ino,
            digest_prefix: None,
        },
        new,
    };
    let cwd = open_dir(cwd_path).map_err(|_| dir_changed(None))?;
    let dm = cwd.metadata().map_err(|_| dir_changed(None))?;
    if (dm.dev(), dm.ino()) != (l.cwd.dev, l.cwd.ino) {
        return Err(dir_changed(Some(IdentityMeta {
            dev: dm.dev(),
            ino: dm.ino(),
            digest_prefix: None,
        })));
    }
    if shebang {
        let entry = l.entry.as_ref().map(|e| e.path.clone()).unwrap_or_default();
        return Ok(CheckedLaunch {
            exec: CheckedExec::Path {
                path: PathBuf::from(std::ffi::OsStr::from_bytes(&entry)),
                confirm: None,
            },
            cwd,
        });
    }
    // An executable that is itself a `#!` file (a package runner such as
    // `npx` is one) is run by its path: the kernel opens it again to read
    // its interpreter line, which a descriptor cannot give it.
    if matches!(
        codesign::executable_format(&file),
        Ok(ExecutableFormat::Script)
    ) {
        return Ok(CheckedLaunch {
            exec: CheckedExec::Path {
                path: PathBuf::from(std::ffi::OsStr::from_bytes(&l.executable.path)),
                confirm: None,
            },
            cwd,
        });
    }
    let exec = exec_for(l, file)?;
    Ok(CheckedLaunch { exec, cwd })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn exec_for(l: &RegisteredLaunch, file: File) -> Result<CheckedExec, CheckError> {
    use envcloak_sys::launch::{ImageError, SealedImage};
    if l.strength != BindingStrength::Bound {
        let st = stamp(&file).map_err(|_| CheckError::Changed {
            part: Part::Executable,
            old: meta_of(&l.executable),
            new: None,
        })?;
        return Ok(CheckedExec::Descriptor { file, stamp: st });
    }
    let image =
        SealedImage::copy_from(file.as_fd(), codesign::MAX_EXECUTABLE).map_err(|e| match e {
            ImageError::Create(_) => CheckError::RunnerUnavailable,
            _ => CheckError::Changed {
                part: Part::Executable,
                old: meta_of(&l.executable),
                new: None,
            },
        })?;
    // The identity compared is the sealed copy's, the bytes that will run;
    // a digest of the file before the copy proves nothing about the copy.
    let digest = sha256_of_image(&image).map_err(|_| CheckError::RunnerUnavailable)?;
    if CodeDigest::Sha256(digest) != l.executable.digest {
        return Err(CheckError::Changed {
            part: Part::Executable,
            old: meta_of(&l.executable),
            new: Some(IdentityMeta {
                dev: l.executable.dev,
                ino: l.executable.ino,
                digest_prefix: Some(digest_prefix(&CodeDigest::Sha256(digest))),
            }),
        });
    }
    // A test stops here, after the sealed copy's digest was compared and
    // before the runner is started with it (M2-27's check-to-spawn
    // barrier).
    envcloak_sys::pause_point("launch.checked");
    Ok(CheckedExec::Image(image))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn sha256_of_image(
    image: &envcloak_sys::launch::SealedImage,
) -> std::io::Result<[u8; 32]> {
    image.check_seals()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut at = 0u64;
    loop {
        let n = image.read_at(&mut buf, at)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        at += n as u64;
    }
    if at != image.len() {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok(h.finalize().into())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn exec_for(l: &RegisteredLaunch, file: File) -> Result<CheckedExec, CheckError> {
    drop(file);
    let confirm = match (&l.executable.digest, l.strength) {
        (CodeDigest::CdHash { cdhash, .. }, _) => Some(cdhash.clone()),
        (CodeDigest::Sha256(_), _) => None,
    };
    if confirm.is_some() {
        // As on Linux: after the check, before the runner starts.
        envcloak_sys::pause_point("launch.checked");
    }
    Ok(CheckedExec::Path {
        path: PathBuf::from(std::ffi::OsStr::from_bytes(&l.executable.path)),
        confirm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decl(argv: &[&str]) -> LaunchDecl {
        LaunchDecl {
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            cwd: None,
            env: Vec::new(),
            path_env: Some("/usr/bin:/bin".to_owned()),
        }
    }

    /// A bare name is found on the declared PATH, once, and the record
    /// keeps the canonical executable; a script's interpreter and entry
    /// are both identified; the working directory defaults to the managed
    /// directory.
    #[test]
    fn a_declaration_resolves_to_its_files() {
        let dir = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(dir.path()).unwrap();
        let l = resolve(&decl(&["true"]), &dir, vec!["KEY".into()], [1; 16], 1).unwrap();
        assert_eq!(l.class, LaunchClass::Native);
        assert!(l.executable.path.starts_with(b"/"));
        assert_eq!(l.cwd.path, dir.as_os_str().as_bytes());
        assert_eq!(l.env.binding_names, vec!["KEY".to_owned()]);
        let script = dir.join("server.sh");
        std::fs::write(&script, "#!/bin/sh\necho hi\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let s = resolve(&decl(&[script.to_str().unwrap()]), &dir, vec![], [2; 16], 1).unwrap();
        assert_eq!(s.class, LaunchClass::Script);
        assert_eq!(s.strength, BindingStrength::CheckedAtRest);
        assert!(s.entry.is_some());
        let i = resolve(
            &decl(&["sh", script.to_str().unwrap()]),
            &dir,
            vec![],
            [3; 16],
            1,
        )
        .unwrap();
        assert_eq!(i.class, LaunchClass::Script);
        assert_eq!(
            i.entry.as_ref().unwrap().path,
            script.as_os_str().as_bytes()
        );
        // A program not on PATH, and a relative one, are refused.
        assert_eq!(
            resolve(
                &decl(&["envcloak-no-such-program"]),
                &dir,
                vec![],
                [4; 16],
                1
            )
            .unwrap_err(),
            ResolveError::NotFound
        );
        assert!(resolve(&decl(&["./x"]), &dir, vec![], [5; 16], 1).is_err());
    }

    /// The check passes for the file as registered and is
    /// `managed_launch_changed` for one replaced at the same path or a
    /// working directory renamed over.
    #[test]
    fn the_check_refuses_a_replaced_file_or_directory() {
        let dir = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(dir.path()).unwrap();
        let prog = dir.join("prog");
        std::fs::copy("/bin/sh", &prog).unwrap();
        let cwd = dir.join("cwd");
        std::fs::create_dir(&cwd).unwrap();
        let mut d = decl(&[prog.to_str().unwrap()]);
        d.cwd = Some(cwd.to_str().unwrap().to_owned());
        let l = resolve(&d, &dir, vec![], [6; 16], 1).unwrap();
        check(&l).unwrap();
        // The directory renamed over by another.
        std::fs::rename(&cwd, dir.join("cwd-old")).unwrap();
        std::fs::create_dir(&cwd).unwrap();
        assert!(matches!(
            check(&l),
            Err(CheckError::Changed {
                part: Part::WorkingDirectory,
                ..
            })
        ));
        std::fs::remove_dir(&cwd).unwrap();
        std::fs::rename(dir.join("cwd-old"), &cwd).unwrap();
        check(&l).unwrap();
        // Another program renamed over the executable.
        let other = dir.join("other");
        std::fs::copy("/bin/ls", &other).unwrap();
        std::fs::rename(&other, &prog).unwrap();
        assert!(matches!(
            check(&l),
            Err(CheckError::Changed {
                part: Part::Executable,
                ..
            })
        ));
    }
}
