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
//! directory the kernel uses (cdhash, [`envcloak_sys::codesign`], with its
//! signing identifier and Team ID) or, for a file without one or without a
//! signing identifier, its SHA-256. Its class: `native` for an ELF or
//! Mach-O file, `script` for an interpreter with an absolute entry file or a
//! `#!` file, and `package_runner` for `npx` and its kin. What runs is
//! what was checked: the argv names an entry file by its canonical path,
//! and a `#!` file (a script's, or a package runner's own) is run by its
//! interpreter explicitly, the line read once here, its option checked
//! as the interpreter's own and an `env NAME` line's interpreter found
//! once on the declared `PATH`; an interpreter that is itself a `#!` file
//! is refused. Its strength: `bound` for a native file whose image can be
//! bound (Linux: no `$ORIGIN` in its run path; macOS: a code directory)
//! and that is given no file to run (no argument names an existing
//! regular file), `checked_at_rest` otherwise. The working directory is
//! the declared one, else the managed directory, canonicalized and
//! identified by device and inode.
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
    ArgvClass, CodeSelecting, DeclError, check_declaration, classify_argv, refuse_disguised,
    shebang_argv,
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
            // What a wrapper or a disguised launcher runs could not be
            // checked: reported manual, as a code-selecting declaration is.
            ResolveError::Decl(e @ (DeclError::Wrapper | DeclError::Disguised)) => {
                RpcError::with_reason(ErrorKind::CodeSelectingEnv, e.word())
            }
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
        // A code directory without a signing identifier the kernel would
        // report is not an identity the suspended start can compare in
        // full: such a file is checked by its SHA-256, at rest.
        if let Some((cd, cdhash)) = cd
            .filter(|cd| cd.identifier.is_some())
            .and_then(|cd| cdhash_of(&cd).map(|h| (cd, h)))
        {
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

/// What a `#!` line names: the interpreter as the line writes it (or, for
/// `/usr/bin/env NAME`, as `NAME` was found on the declared `PATH`), and
/// the line's one option, if any.
struct Shebang {
    interp: PathBuf,
    opt: Option<String>,
}

/// Reads the `#!` line of `f`: an absolute interpreter and at most one
/// word after it (the kernel hands the rest of the line over as one
/// argument), or `/usr/bin/env NAME` with `NAME` found once, here, on
/// `path_env`. A line EnvCloak cannot read (no interpreter, a relative
/// one, more than one word after it, `env` with options or a second word,
/// a line longer than the read) is [`ResolveError::Unsupported`]. The
/// interpreter found is the one the launch runs, explicitly: nothing looks
/// it up again when the server starts.
fn read_shebang(f: &File, path_env: &str) -> Result<Shebang, ResolveError> {
    let mut head = [0u8; 256];
    let n = envcloak_sys::launch::read_at(f.as_fd(), &mut head, 0)
        .map_err(|_| ResolveError::Unsupported)?;
    let head = &head[..n];
    let end = head
        .iter()
        .position(|b| *b == b'\n')
        .ok_or(ResolveError::Unsupported)?;
    let line = head[..end]
        .strip_prefix(b"#!")
        .ok_or(ResolveError::Unsupported)?;
    let line = std::str::from_utf8(line).map_err(|_| ResolveError::Unsupported)?;
    let mut words = line.split_ascii_whitespace();
    let interp = words.next().ok_or(ResolveError::Unsupported)?;
    let opt = words.next().map(str::to_owned);
    if !interp.starts_with('/') || words.next().is_some() {
        return Err(ResolveError::Unsupported);
    }
    if Path::new(interp).file_name().and_then(|n| n.to_str()) == Some("env") {
        let name = opt.ok_or(ResolveError::Unsupported)?;
        if name.starts_with('-') || name.contains('=') || name.contains('/') {
            return Err(ResolveError::Unsupported);
        }
        return Ok(Shebang {
            interp: find_program(&name, path_env)?,
            opt: None,
        });
    }
    Ok(Shebang {
        interp: PathBuf::from(interp),
        opt,
    })
}

/// The identity of a native interpreter at `path` (canonicalized): a
/// regular, executable ELF or Mach-O file. An interpreter that is itself a
/// `#!` file (a version manager's shim) would choose its own interpreter
/// when it starts: [`ResolveError::Unsupported`], reported manual.
fn native_interpreter(path: &Path) -> Result<(PathBuf, FileIdentity), ResolveError> {
    let canonical = std::fs::canonicalize(path).map_err(|_| ResolveError::NotFound)?;
    let f = open_file(&canonical)?;
    let m = f.metadata().map_err(|_| ResolveError::NotFound)?;
    if m.permissions().mode() & 0o111 == 0 {
        return Err(ResolveError::NotExecutable);
    }
    match codesign::executable_format(&f).map_err(|_| ResolveError::Unsupported)? {
        ExecutableFormat::Elf | ExecutableFormat::MachO | ExecutableFormat::MachOUniversal => {}
        ExecutableFormat::Script | ExecutableFormat::Other => {
            return Err(ResolveError::Unsupported);
        }
    }
    let id = file_identity(&canonical)?;
    Ok((canonical, id))
}

/// A `#!` file at `canonical` run explicitly: its interpreter, checked as
/// native, the explicit argv ([`shebang_argv`]: the line's option checked,
/// the file's canonical path as the entry) and the file's identity.
fn through_shebang(
    file: &File,
    canonical: &Path,
    args: &[String],
    path_env: &str,
) -> Result<(FileIdentity, Vec<String>, FileIdentity), ResolveError> {
    let sb = read_shebang(file, path_env)?;
    let (interp_canonical, interp) = native_interpreter(&sb.interp)?;
    let written = sb.interp.to_str().ok_or(ResolveError::Unsupported)?;
    let script = canonical.to_str().ok_or(ResolveError::Unsupported)?;
    let argv = shebang_argv(
        written,
        sb.opt.as_deref(),
        script,
        args,
        interp_canonical.to_str().unwrap_or(""),
    )?;
    Ok((interp, argv, file_identity(canonical)?))
}

/// Whether an argument or a declared variable's value of a native launch
/// may name a file: a program given a file may run what it holds (a
/// script, a plug-in, a configuration that loads one), which nothing
/// binds. Such a launch is `checked_at_rest`. Looked at: each argument
/// whole, the value of an `--option=value` or `-o=value`, the value glued
/// to a short option (`-c/srv/x.conf`, any letter of a cluster), and each
/// variable's value. Any of them that holds a `/` or starts with `~` is
/// taken for a path whether or not the file exists yet (one created after
/// registration loads all the same); any other that names an entry of the
/// working directory `cwd` now, of any type, is one too.
fn names_a_file(args: &[String], values: &[&str], cwd: &Path) -> bool {
    let path_like = |c: &str| {
        !c.is_empty()
            && (c.contains('/')
                || c.starts_with('~')
                || std::fs::symlink_metadata(cwd.join(c)).is_ok())
    };
    args.iter().any(|a| {
        let mut candidates = vec![a.as_str()];
        if let Some(o) = a.strip_prefix('-') {
            if let Some((_, v)) = o.split_once('=') {
                candidates.push(v);
            }
            if !o.starts_with('-') {
                candidates.extend(o.char_indices().skip(1).map(|(i, _)| &o[i..]));
            }
        }
        candidates
            .into_iter()
            .any(|c| !c.starts_with('-') && path_like(c))
    }) || values.iter().any(|v| path_like(v))
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
    // A launcher known by another name is classed by its file's name.
    refuse_disguised(
        &decl.argv,
        canonical.file_name().and_then(|n| n.to_str()).unwrap_or(""),
    )?;
    let file = open_file(&canonical)?;
    let meta = file.metadata().map_err(|_| ResolveError::NotFound)?;
    if meta.permissions().mode() & 0o111 == 0 {
        return Err(ResolveError::NotExecutable);
    }
    let format = codesign::executable_format(&file).map_err(|_| ResolveError::Unsupported)?;
    // What runs is what was checked: every path the launch runs is the
    // canonical one identified here (an entry file named through a link
    // runs by the file's own path), and a `#!` file is never handed to the
    // kernel, which would read its line, and look its interpreter up,
    // again: its interpreter, checked, runs it explicitly.
    let (class, executable, argv, entry) = match argv_class {
        ArgvClass::PackageRunner { .. } => match format {
            ExecutableFormat::Script => {
                let (interp, argv, runner) =
                    through_shebang(&file, &canonical, &decl.argv[1..], &path_env)?;
                (LaunchClass::PackageRunner, interp, argv, Some(runner))
            }
            ExecutableFormat::Elf | ExecutableFormat::MachO | ExecutableFormat::MachOUniversal => (
                LaunchClass::PackageRunner,
                file_identity(&canonical)?,
                decl.argv.clone(),
                None,
            ),
            ExecutableFormat::Other => return Err(ResolveError::Unsupported),
        },
        ArgvClass::Interpreter { entry } => {
            let (_, interp) = native_interpreter(&canonical)?;
            let script = file_identity(Path::new(&decl.argv[entry]))?;
            let mut argv = decl.argv.clone();
            argv[entry] = std::str::from_utf8(&script.path)
                .map_err(|_| ResolveError::Unsupported)?
                .to_owned();
            (LaunchClass::Script, interp, argv, Some(script))
        }
        ArgvClass::Program => match format {
            ExecutableFormat::Elf | ExecutableFormat::MachO | ExecutableFormat::MachOUniversal => (
                LaunchClass::Native,
                file_identity(&canonical)?,
                decl.argv.clone(),
                None,
            ),
            ExecutableFormat::Script => {
                let (interp, argv, script) =
                    through_shebang(&file, &canonical, &decl.argv[1..], &path_env)?;
                (LaunchClass::Script, interp, argv, Some(script))
            }
            ExecutableFormat::Other => return Err(ResolveError::Unsupported),
        },
    };
    let cwd_path = match &decl.cwd {
        Some(c) => PathBuf::from(c),
        None => managed_dir.to_path_buf(),
    };
    let cwd_canonical = std::fs::canonicalize(&cwd_path).map_err(|_| ResolveError::NotFound)?;
    let dir = open_dir(&cwd_canonical)?;
    let dm = dir.metadata().map_err(|_| ResolveError::NotFound)?;
    let strength = match class {
        LaunchClass::Native
            if names_a_file(
                &argv[1..],
                &decl.env.iter().map(|(_, v)| v.as_str()).collect::<Vec<_>>(),
                &cwd_canonical,
            ) =>
        {
            BindingStrength::CheckedAtRest
        }
        LaunchClass::Native => native_strength(&file, &executable.digest)?,
        LaunchClass::Script | LaunchClass::PackageRunner => BindingStrength::CheckedAtRest,
    };
    Ok(RegisteredLaunch {
        launch_id,
        revision,
        class,
        executable,
        argv: argv.iter().map(|a| a.as_bytes().to_vec()).collect(),
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
    /// the started program's code identity with `confirm` before it runs.
    /// macOS only: on Linux every launch runs from a descriptor.
    #[cfg_attr(any(target_os = "linux", target_os = "android"), allow(dead_code))]
    Path {
        path: PathBuf,
        confirm: Option<ExpectedCode>,
    },
}

/// The code identity a suspended server must show the kernel before it
/// runs (macOS): the record's cdhash, signing identifier and Team ID, each
/// compared exactly. A Team ID of `None` is an ad hoc or platform
/// signature, which the started program must have too; an identifier of
/// `None` (a record that has none) matches no program.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    all(not(test), any(target_os = "linux", target_os = "android")),
    allow(dead_code)
)]
pub(crate) struct ExpectedCode {
    pub cdhash: Vec<u8>,
    pub identifier: Option<String>,
    pub team: Option<String>,
}

impl ExpectedCode {
    /// Whether the kernel's view of a started program, `sig`, is this.
    #[cfg_attr(
        all(not(test), any(target_os = "linux", target_os = "android")),
        allow(dead_code)
    )]
    pub(crate) fn matches(&self, sig: &envcloak_sys::CodeSignature) -> bool {
        sig.cdhash.is_some_and(|h| h[..] == self.cdhash[..])
            && self.identifier.as_deref() == Some(sig.identifier.as_str())
            && self.team == sig.team_id
    }
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

/// A record may predate stricter declaration or interpreter policy. Check
/// both its original declaration and its prepared argv/environment, then
/// require its cached class, entry and strength to agree. Nothing here
/// resolves PATH or reads a shebang again: the recorded images stay fixed.
fn stored_policy_matches(l: &RegisteredLaunch) -> bool {
    if check_declaration(&l.declaration).is_err()
        || l.env
            .vars
            .iter()
            .any(|(name, _)| envcloak_policy::managed::is_code_selecting(name))
    {
        return false;
    }
    let declaration_class = match classify_argv(&l.declaration.argv) {
        Ok(class) => class,
        Err(_) => return false,
    };
    let class_matches = match declaration_class {
        ArgvClass::Program => matches!(l.class, LaunchClass::Native | LaunchClass::Script),
        ArgvClass::Interpreter { .. } => l.class == LaunchClass::Script,
        ArgvClass::PackageRunner { .. } => l.class == LaunchClass::PackageRunner,
    };
    if !class_matches {
        return false;
    }
    let Ok(argv) = l
        .argv
        .iter()
        .map(|a| String::from_utf8(a.clone()))
        .collect::<Result<Vec<_>, _>>()
    else {
        return false;
    };
    let canonical = Path::new(std::ffi::OsStr::from_bytes(&l.executable.path));
    let canonical_name = canonical.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let Ok(class) = refuse_disguised(&argv, canonical_name) else {
        return false;
    };
    let entry_at = |at: usize| {
        l.entry
            .as_ref()
            .is_some_and(|e| argv.get(at).is_some_and(|a| a.as_bytes() == e.path))
    };
    let at_rest = l.strength == BindingStrength::CheckedAtRest;
    match class {
        ArgvClass::Program if l.class == LaunchClass::Native => l.entry.is_none(),
        ArgvClass::Program => at_rest && entry_at(1),
        ArgvClass::Interpreter { entry } => {
            l.class != LaunchClass::Native && at_rest && entry_at(entry)
        }
        ArgvClass::PackageRunner { .. } => {
            l.class == LaunchClass::PackageRunner && at_rest && l.entry.is_none()
        }
    }
}

/// Checks `l` before its values are released (see the module
/// documentation).
///
/// # Errors
/// [`CheckError`].
pub(crate) fn check(l: &RegisteredLaunch) -> Result<CheckedLaunch, CheckError> {
    if !stored_policy_matches(l) {
        return Err(CheckError::Changed {
            part: Part::Executable,
            old: meta_of(&l.executable),
            new: None,
        });
    }
    let file = recheck(&l.executable, Part::Executable)?;
    // The executable runs itself, never through a `#!` line the kernel
    // would read again: registration ran a `#!` file through its checked
    // interpreter, so one here was not what was registered.
    if !matches!(
        codesign::executable_format(&file),
        Ok(ExecutableFormat::Elf | ExecutableFormat::MachO | ExecutableFormat::MachOUniversal)
    ) {
        return Err(CheckError::Changed {
            part: Part::Executable,
            old: meta_of(&l.executable),
            new: None,
        });
    }
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
    let confirm = match &l.executable.digest {
        CodeDigest::CdHash {
            cdhash,
            team,
            identifier,
        } => Some(ExpectedCode {
            cdhash: cdhash.clone(),
            identifier: identifier.clone(),
            team: team.clone(),
        }),
        CodeDigest::Sha256(_) => None,
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

    /// Mutation: trust the sealed declaration under yesterday's policy.
    #[test]
    fn stored_declarations_obey_current_policy() {
        let home = tempfile::Builder::new()
            .prefix("ecl")
            .tempdir_in("/tmp")
            .unwrap();
        let fixture_root = home.path().canonicalize().unwrap();
        let base = resolve(
            &decl(&["true"]),
            fixture_root.as_path(),
            vec![],
            [21; 16],
            1,
        )
        .unwrap();
        assert!(check(&base).is_ok());
        let entry = fixture_root.as_path().join("entry");
        script(&entry, "#!/bin/sh\nexit 0\n");
        for (name, option) in [
            ("bash", "--login"),
            ("php", "-f/selected.php"),
            ("python3", "-Xpresite=observer"),
            ("python3", "-Wignore::observer.Notice"),
            ("luajit", "-jv"),
            ("luajit", "-b"),
            ("ruby", "-We'puts 1'"),
            ("ruby", "-KUe'puts 1'"),
            ("ruby", "-Te'puts 1'"),
            ("bash", "-oposix"),
        ] {
            let interpreter = fixture_root.as_path().join(name);
            std::fs::copy(
                Path::new(std::ffi::OsStr::from_bytes(&base.executable.path)),
                &interpreter,
            )
            .unwrap();
            let mut old = base.clone();
            old.class = LaunchClass::Script;
            old.strength = BindingStrength::CheckedAtRest;
            old.entry = Some(file_identity(&entry).unwrap());
            old.executable = file_identity(&interpreter).unwrap();
            old.declaration.argv = vec![
                interpreter.to_str().unwrap().into(),
                option.into(),
                entry.to_str().unwrap().into(),
            ];
            old.argv = old
                .declaration
                .argv
                .iter()
                .map(|a| a.as_bytes().to_vec())
                .collect();
            // Control every other predicate, including canonical entry paths.
            let mut safe = old.clone();
            safe.declaration.argv.remove(1);
            safe.argv.remove(1);
            assert!(check(&safe).is_ok(), "healthy {name}");
            assert!(
                matches!(check(&old), Err(CheckError::Changed { .. })),
                "{name} {option}"
            );
        }
        for name in [
            "PYTHON_PRESITE",
            "PYTHONWARNINGS",
            "NpM_cOnFiG_sCrIpT_ShElL",
        ] {
            let mut old = base.clone();
            old.declaration.env.push((name.into(), "observer".into()));
            old.env.vars = old.declaration.env.clone();
            assert!(
                matches!(check(&old), Err(CheckError::Changed { .. })),
                "{name}"
            );
        }
        // The recorded executable remains authoritative. The launch check
        // must not look a bare command up again on a changed PATH.
        let mut retained = base;
        retained.declaration.path_env = Some("/no-such-recorded-path".into());
        retained.env.path_env = b"/no-such-recorded-path".to_vec();
        assert!(check(&retained).is_ok());
    }

    /// Mutation: reuse an old native class after a name becomes an interpreter.
    #[test]
    fn stored_native_classes_cannot_outlive_interpreter_policy() {
        let home = tempfile::Builder::new()
            .prefix("ecl")
            .tempdir_in("/tmp")
            .unwrap();
        let base = resolve(&decl(&["true"]), home.path(), vec![], [22; 16], 1).unwrap();
        let entry = home.path().join("entry");
        std::fs::write(&entry, "entry\n").unwrap();
        assert!(check(&base).is_ok());
        for name in [
            "Python",
            "Python3",
            "luajit-2.1.1736781742",
            "node-22",
            "python3.12-intel64",
            "pythonw3",
            "graalpy",
            "micropython",
            "truffleruby",
            "php-cgi",
            "php8.4-fpm",
        ] {
            let mut old = base.clone();
            old.declaration.argv = vec![name.into(), entry.to_str().unwrap().into()];
            old.argv = old
                .declaration
                .argv
                .iter()
                .map(|a| a.as_bytes().to_vec())
                .collect();
            // Earlier classifiers kept this native, with no entry identity;
            // its file argument made it checked_at_rest, still unchecked.
            old.strength = BindingStrength::CheckedAtRest;
            assert!(
                matches!(check(&old), Err(CheckError::Changed { .. })),
                "{name}"
            );
        }
    }

    /// A record stored under the earlier shared prefix list, `node
    /// --allow-fs-read <file> -e <code>` with `<file>` checked as its entry
    /// (Node takes `<file>` as the option's value and runs `<code>`), is
    /// refused by the launch check, which classes the stored argv again;
    /// the same record with Node's boolean `--allow-child-process` is the
    /// control. Mutation checked: one prefix list for every family in
    /// `boolean_long` (the previous rule): the stored record passes and
    /// this fails.
    #[test]
    fn a_stored_value_taking_long_option_cannot_keep_its_entry() {
        let home = tempfile::Builder::new()
            .prefix("ecl")
            .tempdir_in("/tmp")
            .unwrap();
        let root = home.path().canonicalize().unwrap();
        let base = resolve(&decl(&["true"]), &root, vec![], [24; 16], 1).unwrap();
        let node = root.join("node");
        std::fs::copy(
            Path::new(std::ffi::OsStr::from_bytes(&base.executable.path)),
            &node,
        )
        .unwrap();
        let other = root.join("other.js");
        std::fs::write(&other, "0\n").unwrap();
        let (n, o) = (node.to_str().unwrap(), other.to_str().unwrap());
        let stored = |argv: &[&str]| {
            let mut l = base.clone();
            l.declaration = decl(argv);
            l.argv = argv.iter().map(|a| a.as_bytes().to_vec()).collect();
            l.executable = file_identity(&node).unwrap();
            l.entry = Some(file_identity(&other).unwrap());
            l.class = LaunchClass::Script;
            l.strength = BindingStrength::CheckedAtRest;
            l
        };
        assert!(check(&stored(&[n, "--allow-child-process", o])).is_ok());
        for option in ["--allow-fs-read", "--allow-fs-write", "--disable-warning"] {
            assert!(
                matches!(
                    check(&stored(&[n, option, o, "-e", "0"])),
                    Err(CheckError::Changed { .. })
                ),
                "{option}"
            );
        }
    }

    /// Mutation: validate only the original declaration, ignoring derived argv/env.
    #[test]
    fn stored_effective_arguments_and_entries_obey_current_policy() {
        let home = tempfile::Builder::new()
            .prefix("ecl")
            .tempdir_in("/tmp")
            .unwrap();
        let fixture_root = home.path().canonicalize().unwrap();
        let entry = fixture_root.as_path().join("entry");
        script(&entry, "#!/bin/sh\nexit 0\n");
        let base = resolve(
            &decl(&[entry.to_str().unwrap()]),
            fixture_root.as_path(),
            vec![],
            [23; 16],
            1,
        )
        .unwrap();
        assert!(check(&base).is_ok());
        for (name, option) in [
            ("bash", "--login"),
            ("php", "-f/selected.php"),
            ("python3", "-Xpresite=observer"),
            ("luajit", "-jv"),
            ("ruby", "-We'puts 1'"),
            ("ruby", "-KUe'puts 1'"),
        ] {
            let interpreter = fixture_root.as_path().join(name);
            std::fs::copy(
                Path::new(std::ffi::OsStr::from_bytes(&base.executable.path)),
                &interpreter,
            )
            .unwrap();
            let legacy_entry = fixture_root.as_path().join(format!("entry-{name}"));
            script(
                &legacy_entry,
                &format!("#!{} {option}\nentry\n", interpreter.display()),
            );
            let mut old = base.clone();
            old.declaration = decl(&[legacy_entry.to_str().unwrap()]);
            old.executable = file_identity(&interpreter).unwrap();
            old.entry = Some(file_identity(&legacy_entry).unwrap());
            old.argv = [
                interpreter.to_str().unwrap(),
                option,
                legacy_entry.to_str().unwrap(),
            ]
            .iter()
            .map(|a| a.as_bytes().to_vec())
            .collect();
            let mut safe = old.clone();
            safe.argv.remove(1);
            assert!(check(&safe).is_ok(), "healthy prepared {name}");
            assert!(
                matches!(check(&old), Err(CheckError::Changed { .. })),
                "{name} {option}"
            );
        }
        let mut old = base.clone();
        old.env
            .vars
            .push(("PYTHONWARNINGS".into(), "ignore::observer.Notice".into()));
        assert!(matches!(check(&old), Err(CheckError::Changed { .. })));
        let mut old = base.clone();
        old.argv[1] = b"/different-entry".to_vec();
        assert!(matches!(check(&old), Err(CheckError::Changed { .. })));
        let mut old = base;
        old.strength = BindingStrength::Bound;
        assert!(matches!(check(&old), Err(CheckError::Changed { .. })));
        // A shebang may name a native program unknown to the interpreter
        // table; without an option its checked entry is argv[1].
        let cat = fixture_root.as_path().join("cat-entry");
        script(&cat, "#!/bin/cat\nentry\n");
        let cat = resolve(
            &decl(&[cat.to_str().unwrap()]),
            fixture_root.as_path(),
            vec![],
            [24; 16],
            1,
        )
        .unwrap();
        assert!(check(&cat).is_ok());
        let package = fixture_root.as_path().join("npx");
        script(&package, "#!/bin/sh\nexit 0\n");
        let package = resolve(
            &decl(&[package.to_str().unwrap(), "-y", "fixture"]),
            fixture_root.as_path(),
            vec![],
            [25; 16],
            1,
        )
        .unwrap();
        assert!(check(&package).is_ok());
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

    fn script(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn argv_of(l: &RegisteredLaunch) -> Vec<String> {
        l.argv
            .iter()
            .map(|a| String::from_utf8(a.clone()).unwrap())
            .collect()
    }

    /// What runs is what was checked: an entry file named through a link
    /// runs by the file's own path, so the link pointed elsewhere changes
    /// nothing that runs; a `#!` file runs through its interpreter,
    /// checked, with the line's option checked as the interpreter's own,
    /// and an `env` line's interpreter found once, at registration; a
    /// package runner that is a `#!` file runs the same way; an
    /// interpreter that is itself a `#!` file (a shim) is refused.
    ///
    /// Mutations checked: the declared entry path kept in the argv (the
    /// previous `argv: decl.argv`): the argv names the link, and this
    /// fails; a `#!` file run by its path (the previous `CheckedExec::Path`
    /// of the entry): the executable is not the interpreter, and this
    /// fails; the line's option not checked: `#!/bin/sh -c` registers, and
    /// this fails.
    #[test]
    fn what_runs_is_the_file_checked() {
        let dir = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(dir.path()).unwrap();
        let sh = std::fs::canonicalize("/bin/sh").unwrap();
        let real = dir.join("server.sh");
        script(&real, "#!/bin/sh\nexit 0\n");
        let link = dir.join("link.sh");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let l = resolve(
            &decl(&["sh", link.to_str().unwrap(), "--port"]),
            &dir,
            vec![],
            [7; 16],
            1,
        )
        .unwrap();
        assert_eq!(argv_of(&l), vec!["sh", real.to_str().unwrap(), "--port"]);
        assert_eq!(l.entry.as_ref().unwrap().path, real.as_os_str().as_bytes());
        let other = dir.join("other.sh");
        script(&other, "#!/bin/sh\nexit 9\n");
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&other, &link).unwrap();
        check(&l).unwrap();
        // A `#!` file, directly: its interpreter runs it, explicitly.
        let direct = dir.join("direct.sh");
        script(&direct, "#!/bin/sh -u\nexit 0\n");
        let l = resolve(
            &decl(&[direct.to_str().unwrap(), "x"]),
            &dir,
            vec![],
            [8; 16],
            1,
        )
        .unwrap();
        assert_eq!(l.class, LaunchClass::Script);
        assert_eq!(l.executable.path, sh.as_os_str().as_bytes());
        assert_eq!(
            argv_of(&l),
            vec!["/bin/sh", "-u", direct.to_str().unwrap(), "x"]
        );
        check(&l).unwrap();
        // The line's option, checked.
        let loads = dir.join("loads.sh");
        script(&loads, "#!/bin/sh -c\nexit 0\n");
        assert_eq!(
            resolve(&decl(&[loads.to_str().unwrap()]), &dir, vec![], [9; 16], 1).unwrap_err(),
            ResolveError::Decl(DeclError::CodeSelecting(CodeSelecting::InterpreterOption))
        );
        let two = dir.join("two.sh");
        script(&two, "#!/bin/sh -u -x\nexit 0\n");
        assert_eq!(
            resolve(&decl(&[two.to_str().unwrap()]), &dir, vec![], [9; 16], 1).unwrap_err(),
            ResolveError::Unsupported
        );
        // `env NAME`: NAME found once, on the declared PATH.
        let tools = dir.join("tools");
        std::fs::create_dir(&tools).unwrap();
        std::fs::copy(&sh, tools.join("myinterp")).unwrap();
        let via_env = dir.join("env.sh");
        script(&via_env, "#!/usr/bin/env myinterp\nexit 0\n");
        let mut d = decl(&[via_env.to_str().unwrap()]);
        d.path_env = Some(format!("{}:/usr/bin:/bin", tools.display()));
        let l = resolve(&d, &dir, vec![], [10; 16], 1).unwrap();
        assert_eq!(
            l.executable.path,
            tools.join("myinterp").as_os_str().as_bytes()
        );
        assert_eq!(argv_of(&l)[0], tools.join("myinterp").to_str().unwrap());
        // A package runner that is a `#!` file.
        script(&tools.join("npx"), "#!/bin/sh\nexit 0\n");
        let mut d = decl(&["npx", "-y", "pkg"]);
        d.path_env = Some(tools.to_str().unwrap().to_owned());
        let l = resolve(&d, &dir, vec![], [11; 16], 1).unwrap();
        assert_eq!(l.class, LaunchClass::PackageRunner);
        assert_eq!(l.executable.path, sh.as_os_str().as_bytes());
        assert_eq!(
            argv_of(&l),
            vec!["/bin/sh", tools.join("npx").to_str().unwrap(), "-y", "pkg"]
        );
        check(&l).unwrap();
        // An interpreter that is a shim: refused.
        script(&tools.join("node"), "#!/bin/sh\nexit 0\n");
        let js = dir.join("s.js");
        std::fs::write(&js, "1\n").unwrap();
        let mut d = decl(&["node", js.to_str().unwrap()]);
        d.path_env = Some(tools.to_str().unwrap().to_owned());
        assert_eq!(
            resolve(&d, &dir, vec![], [12; 16], 1).unwrap_err(),
            ResolveError::Unsupported
        );
    }

    /// A native program given a file (an argument, an `--option=value`,
    /// a value glued to a short option, a declared variable's value;
    /// absolute, relative to its working directory or under `~`; there now
    /// or created later) may run what the file holds: `checked_at_rest`,
    /// never `bound`. The positive controls: the same program with a port
    /// and a plain variable is `bound`.
    ///
    /// Mutations checked: the file arguments not looked at (the previous
    /// strength rule): the launch given a script file is `bound`, and this
    /// fails; only existing files counted (the round-4 rule): `--config
    /// /later.conf` is `bound`, and this fails; the glued short value not
    /// looked at: `-c/later.conf` is `bound`, and this fails.
    #[test]
    fn a_native_program_given_a_file_is_checked_at_rest() {
        let dir = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(dir.path()).unwrap();
        let prog = dir.join("prog");
        std::fs::copy("/bin/ls", &prog).unwrap();
        let file = dir.join("plugin.conf");
        std::fs::write(&file, "x\n").unwrap();
        std::fs::create_dir(dir.join("plugins")).unwrap();
        let later = dir.join("later.conf");
        let p = prog.to_str().unwrap();
        let mut plain = decl(&[p, "--port", "1", "-v"]);
        plain.env.push(("MODE".into(), "dev".into()));
        let bound = resolve(&plain, &dir, vec![], [13; 16], 1).unwrap();
        assert_eq!(bound.class, LaunchClass::Native);
        assert_eq!(bound.strength, BindingStrength::Bound);
        let conf = format!("--config={}", file.display());
        let glued = format!("-c{}", later.display());
        let glued_cluster = format!("-vc{}", later.display());
        let glued_relative = "-cplugin.conf";
        let short_eq = format!("-c={}", later.display());
        for argv in [
            vec![p, file.to_str().unwrap()],
            vec![p, conf.as_str()],
            vec![p, "plugin.conf"],
            vec![p, "--plugins", "plugins"],
            vec![p, "--config", later.to_str().unwrap()],
            vec![p, glued.as_str()],
            vec![p, glued_cluster.as_str()],
            vec![p, glued_relative],
            vec![p, short_eq.as_str()],
            vec![p, "--config=~/later.conf"],
            vec![p, "conf.d/later.conf"],
        ] {
            assert!(!later.exists());
            let l = resolve(&decl(&argv), &dir, vec![], [14; 16], 1).unwrap();
            assert_eq!(l.strength, BindingStrength::CheckedAtRest, "{argv:?}");
        }
        for value in [later.to_str().unwrap(), "plugin.conf", "~/x.conf"] {
            let mut d = decl(&[p, "--port", "1"]);
            d.env.push(("SERVER_CONFIG".into(), value.to_owned()));
            let l = resolve(&d, &dir, vec![], [15; 16], 1).unwrap();
            assert_eq!(l.strength, BindingStrength::CheckedAtRest, "{value}");
        }
    }

    /// A native interpreter installed under an ABI-flagged name
    /// (`python3.14t`, `python3.13d`) runs as a `script` launch: its entry
    /// file is identified and named by its canonical path, the receipt's
    /// strength is `checked_at_rest`, and a code-loading option is refused
    /// at registration. A link named as a program to it is refused.
    ///
    /// Mutation checked: the interpreter match without the ABI flags (the
    /// previous one): `python3.14t` is a native program, `bound` with no
    /// entry, and this fails.
    #[test]
    fn an_abi_flagged_interpreter_is_a_script_launch() {
        let dir = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(dir.path()).unwrap();
        let tools = dir.join("tools");
        std::fs::create_dir(&tools).unwrap();
        let s_py = dir.join("s.py");
        std::fs::write(&s_py, "1\n").unwrap();
        for name in ["python3.14t", "python3.13d"] {
            let interp = tools.join(name);
            std::fs::copy("/bin/ls", &interp).unwrap();
            let mut d = decl(&[name, s_py.to_str().unwrap()]);
            d.path_env = Some(tools.to_str().unwrap().to_owned());
            let l = resolve(&d, &dir, vec![], [16; 16], 1).unwrap();
            assert_eq!(l.class, LaunchClass::Script, "{name}");
            assert_eq!(l.strength, BindingStrength::CheckedAtRest, "{name}");
            assert_eq!(
                l.entry.as_ref().unwrap().path,
                s_py.as_os_str().as_bytes(),
                "{name}"
            );
            let mut loads = decl(&[name, "-c", "import x"]);
            loads.path_env = d.path_env.clone();
            assert_eq!(
                resolve(&loads, &dir, vec![], [17; 16], 1).unwrap_err(),
                ResolveError::Decl(DeclError::CodeSelecting(CodeSelecting::InterpreterOption)),
                "{name}"
            );
            let link = tools.join(format!("server-{name}"));
            std::os::unix::fs::symlink(&interp, &link).unwrap();
            assert_eq!(
                resolve(&decl(&[link.to_str().unwrap()]), &dir, vec![], [18; 16], 1).unwrap_err(),
                ResolveError::Decl(DeclError::Disguised),
                "{name}"
            );
        }
    }

    /// A started program is the expected code only when its cdhash, its
    /// signing identifier and its Team ID are each the expected one: an
    /// ad hoc build (no Team ID) is not a Developer ID one, nor the other
    /// way round, and an expectation without an identifier matches
    /// nothing. Mutations checked: the Team ID compared only when one is
    /// expected (the previous `team.is_none() || ...`): the Developer ID
    /// program passes for an ad hoc expectation, and this fails; the
    /// identifier not compared: the renamed identity passes, and this
    /// fails.
    #[test]
    fn the_expected_code_is_compared_in_full() {
        let sig = |id: &str, team: Option<&str>| envcloak_sys::CodeSignature {
            identifier: id.to_owned(),
            team_id: team.map(str::to_owned),
            cdhash: Some([7; envcloak_sys::CDHASH_LEN]),
        };
        let adhoc = ExpectedCode {
            cdhash: vec![7; 20],
            identifier: Some("envcloak".to_owned()),
            team: None,
        };
        assert!(adhoc.matches(&sig("envcloak", None)));
        assert!(!adhoc.matches(&sig("envcloak", Some("TEAM123456"))));
        assert!(!adhoc.matches(&sig("other", None)));
        let mut other_hash = sig("envcloak", None);
        other_hash.cdhash = Some([8; envcloak_sys::CDHASH_LEN]);
        assert!(!adhoc.matches(&other_hash));
        let mut unread = sig("envcloak", None);
        unread.cdhash = None;
        assert!(!adhoc.matches(&unread));
        let team = ExpectedCode {
            team: Some("TEAM123456".to_owned()),
            ..adhoc.clone()
        };
        assert!(team.matches(&sig("envcloak", Some("TEAM123456"))));
        assert!(!team.matches(&sig("envcloak", None)));
        assert!(!team.matches(&sig("envcloak", Some("OTHER12345"))));
        let none = ExpectedCode {
            identifier: None,
            ..adhoc
        };
        assert!(!none.matches(&sig("envcloak", None)));
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
