//! `envcloak check [--json]` (story S3): whether this project's references
//! resolve, and whether its env files hold keys in plaintext. Metadata
//! only: it prints names, lines and provider ids, never a value.
//!
//! 1. The nearest `envcloak.toml` is found upward from the working
//!    directory, and its path sent to a verified daemon, which opens the
//!    manifest itself and answers, binding by binding, in `[env]` and in
//!    each profile, whether the vault has the item and field.
//! 2. The project's env files (`.env` and `.env.*` in the manifest's
//!    directory, or the working directory without one; the first
//!    [`MAX_ENV_FILES`] by name, the rest counted as not read) are read
//!    here, as
//!    `run --env-file` reads one: through the directory's descriptor, never
//!    following a symlink, never blocking on a FIFO, regular files of this
//!    user of at most 1 MiB, into wiped buffers. Their `envcloak://`
//!    references go to the daemon with the manifest's. Each ordinary
//!    variable's value is matched against the providers' key patterns in
//!    place (`envcloak_providers::Registry::detect`), and a match is
//!    reported by line, variable and provider. The values are wiped when
//!    the file's parse is dropped.
//!
//! Exit 0 when everything checks out (docs/MANIFEST.md: every reference
//! sent resolves, no env file holds a plaintext key, and every env file
//! was read: none left past the bound, and the directory listed in full);
//! otherwise the report says what, and the exit is 1 with `check_failed`.
//! A directory that cannot be opened or listed, or whose listing breaks
//! off, is reported as such (`env_scan_error`), never as holding no env
//! files. With no manifest and no
//! reference in any env file nothing is sent to the daemon. When the
//! daemon cannot be asked (not running, the vault locked), the env files
//! are still checked, and the report says the references were not and
//! why, never that they do not resolve.

use std::ffi::{OsStr, OsString};
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::ExitCode;

use envcloak_core::SecretBuf;
use envcloak_ipc::view::{
    CheckReport, EnvFileState, EnvFileView, EnvRefView, PlaintextView, RefStatus,
};
use envcloak_policy::{MAX_ENV_FILE, find_manifest, parse_env_file_refs};
use zeroize::Zeroize;

use crate::connect::connect;
use crate::fail::{FAILURE, Failure, usage};
use crate::render::{looks_like_value, print, registry};

const USAGE: &str = "envcloak check [--json]";

/// Env files looked at in one directory, at most.
pub const MAX_ENV_FILES: usize = 64;

pub fn run(args: &[&str]) -> ExitCode {
    let json = match args {
        [] => false,
        ["--json"] => true,
        _ => return usage(USAGE),
    };
    check(json).unwrap_or_else(|f| f.report(FAILURE))
}

/// Whether `name` is an env file's: `.env`, or `.env.<anything>`.
fn is_env_file(name: &OsStr) -> bool {
    let b = name.as_bytes();
    b == b".env" || (b.starts_with(b".env.") && b.len() > 5)
}

fn check(json: bool) -> Result<ExitCode, Failure> {
    let manifest = find_manifest(Path::new(".")).map_err(|_| {
        Failure::new(
            "manifest_invalid",
            "the working directory could not be read while looking for envcloak.toml",
        )
    })?;
    let manifest_text = match &manifest {
        Some(p) => Some(p.to_str().map(str::to_owned).ok_or_else(|| {
            Failure::new(
                "manifest_invalid",
                "the manifest's path is not valid UTF-8, which this build cannot send",
            )
        })?),
        None => None,
    };
    let dir = match manifest.as_deref().and_then(Path::parent) {
        Some(d) => d.to_path_buf(),
        None => std::fs::canonicalize(".")
            .map_err(|_| Failure::new("io", "the working directory could not be read"))?,
    };
    let Scan {
        mut files,
        skipped: env_files_skipped,
        error: env_scan_error,
    } = scan(&dir);
    // Every env-file reference, in file order, for the daemon.
    let mut sent = Vec::new();
    for (_, refs) in &files {
        sent.extend(refs.iter().cloned());
    }
    let answer = if manifest_text.is_none() && sent.is_empty() {
        Err(CheckReport::NOTHING_SENT.to_owned())
    } else {
        connect()
            .and_then(|mut c| {
                c.items_check(manifest_text.as_deref(), &sent)
                    .map_err(Failure::from)
            })
            .map_err(|f| f.token.to_owned())
    };
    let (references, unchecked) = match answer {
        Ok(v) => (Some(v), None),
        Err(token) => (None, Some(token)),
    };
    let mut statuses = references
        .as_ref()
        .map(|r| r.refs.clone())
        .unwrap_or_default()
        .into_iter();
    for (view, refs) in &mut files {
        for (r, _) in view.references.iter_mut().zip(refs.iter()) {
            r.status = statuses.next().unwrap_or(RefStatus::Unchecked);
        }
    }
    let report = CheckReport {
        manifest: manifest_text,
        references,
        unchecked,
        env_files: files.into_iter().map(|(v, _)| v).collect(),
        env_files_skipped,
        env_scan_error: env_scan_error.map(str::to_owned),
    };
    print(&report, json);
    if report.clean() {
        Ok(ExitCode::SUCCESS)
    } else {
        Err(Failure::new(
            "check_failed",
            "the check found problems; the report above says which",
        ))
    }
}

/// What [`scan`] found in a directory.
struct Scan {
    /// Each env file read: its view, and the references it holds as
    /// `NAME=<slug>[#field]` for the daemon.
    files: Vec<(EnvFileView, Vec<String>)>,
    /// How many env files there were past the bound, which were not read.
    skipped: u64,
    /// Why the directory could not be listed in full
    /// ([`CheckReport::DIRECTORY_UNREADABLE`],
    /// [`CheckReport::LISTING_FAILED`]); `None` when it was.
    error: Option<&'static str>,
}

/// Reads the env files in `dir`, the first [`MAX_ENV_FILES`] by name. A
/// directory that cannot be opened or listed is an error, never an empty
/// directory; after a listing that broke off, the env files named before
/// the break are read, and the error says more may remain.
fn scan(dir: &Path) -> Scan {
    let unreadable = Scan {
        files: Vec::new(),
        skipped: 0,
        error: Some(CheckReport::DIRECTORY_UNREADABLE),
    };
    let Ok(handle) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
    else {
        return unreadable;
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return unreadable;
    };
    let (mut names, error) = env_file_names(entries.map(|e| e.map(|e| e.file_name())));
    names.sort();
    let skipped = u64::try_from(names.len().saturating_sub(MAX_ENV_FILES)).unwrap_or(u64::MAX);
    names.truncate(MAX_ENV_FILES);
    let files = names.iter().map(|name| read_one(&handle, name)).collect();
    Scan {
        files,
        skipped,
        error,
    }
}

/// The env files' names in a directory listing, and
/// [`CheckReport::LISTING_FAILED`] when the listing broke off: the names
/// before the error are kept, and the rest are unknown.
fn env_file_names(
    entries: impl Iterator<Item = io::Result<OsString>>,
) -> (Vec<OsString>, Option<&'static str>) {
    let mut names = Vec::new();
    for entry in entries {
        match entry {
            Ok(name) if is_env_file(&name) => names.push(name),
            Ok(_) => {}
            Err(_) => return (names, Some(CheckReport::LISTING_FAILED)),
        }
    }
    (names, None)
}

fn view(name: &OsStr, state: EnvFileState) -> EnvFileView {
    EnvFileView {
        file: name.to_string_lossy().into_owned(),
        state,
        error_line: None,
        error: None,
        plaintext: Vec::new(),
        references: Vec::new(),
    }
}

/// Reads and parses one env file. See the module documentation.
fn read_one(dir: &std::fs::File, name: &OsStr) -> (EnvFileView, Vec<String>) {
    let mut f = match envcloak_sys::open_beneath(dir, name) {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return (view(name, EnvFileState::Symlink), Vec::new());
        }
        Err(_) => return (view(name, EnvFileState::Unreadable), Vec::new()),
    };
    let Ok(meta) = f.metadata() else {
        return (view(name, EnvFileState::Unreadable), Vec::new());
    };
    if !meta.file_type().is_file() {
        return (view(name, EnvFileState::NotRegular), Vec::new());
    }
    if meta.uid() != envcloak_sys::effective_uid() {
        return (view(name, EnvFileState::NotOwned), Vec::new());
    }
    let len = usize::try_from(meta.len()).unwrap_or(usize::MAX);
    if len > MAX_ENV_FILE {
        return (view(name, EnvFileState::TooLarge), Vec::new());
    }
    let mut buf = SecretBuf::with_capacity(len);
    if buf.read_exact_from(&mut f, len).is_err() {
        return (view(name, EnvFileState::Unreadable), Vec::new());
    }
    // Bytes past the length it had: a file still being written.
    let mut more = [0u8; 1];
    let grew = f.read(&mut more);
    more.zeroize();
    if !matches!(grew, Ok(0)) {
        return (view(name, EnvFileState::Unreadable), Vec::new());
    }
    let parsed = match parse_env_file_refs(&buf.freeze()) {
        Ok(p) => p,
        Err(e) => {
            let mut v = view(name, EnvFileState::Invalid);
            v.error_line = Some(e.line()).filter(|l| *l > 0);
            v.error = Some(e.message().to_owned());
            return (v, Vec::new());
        }
    };
    let mut v = view(name, EnvFileState::Read);
    let shown_name = |n: &str| (!looks_like_value(n)).then(|| n.to_owned());
    for p in &parsed.plain {
        let Some(r) = registry() else { break };
        let d = r.detect(&p.value, Some(p.name.as_str()));
        if !d.candidates.is_empty() {
            v.plaintext.push(PlaintextView {
                line: p.line,
                env_name: shown_name(p.name.as_str()),
                provider: d.provider.map(|id| id.as_str().to_owned()),
            });
        }
    }
    let mut sent = Vec::new();
    for r in &parsed.refs {
        let reference = r.binding.reference.to_string();
        let hidden = looks_like_value(r.binding.env_name.as_str()) || looks_like_value(&reference);
        v.references.push(EnvRefView {
            line: r.line,
            env_name: (!hidden).then(|| r.binding.env_name.as_str().to_owned()),
            reference: (!hidden).then_some(reference.clone()),
            status: if hidden {
                RefStatus::LooksLikeValue
            } else {
                RefStatus::Unchecked
            },
        });
        sent.push(format!("{}={reference}", r.binding.env_name));
    }
    // The values are wiped here, as `parsed` is dropped.
    drop(parsed);
    (v, sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The F-48 follow-up (Codex, cycle 152): a listing that breaks off is
    /// an error, with the env files named before it kept; one that ends is
    /// not.
    #[test]
    fn a_listing_that_breaks_off_is_an_error() {
        let name = |n: &str| Ok(OsString::from(n));
        let whole = vec![name(".env"), name("README"), name(".env.local")];
        assert_eq!(
            env_file_names(whole.into_iter()),
            (
                vec![OsString::from(".env"), OsString::from(".env.local")],
                None
            )
        );
        let broken = vec![
            name(".env"),
            name("src"),
            Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            name(".env.local"),
        ];
        assert_eq!(
            env_file_names(broken.into_iter()),
            (
                vec![OsString::from(".env")],
                Some(CheckReport::LISTING_FAILED)
            )
        );
        assert_eq!(
            env_file_names(std::iter::once(Err(io::Error::from(io::ErrorKind::Other)))),
            (vec![], Some(CheckReport::LISTING_FAILED))
        );
    }

    /// A directory this process may search but not list (mode 0100) is
    /// unreadable, not empty.
    #[test]
    fn a_directory_that_cannot_be_listed_is_unreadable() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("project");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join(".env"), "PORT=8080\n").unwrap();
        let listed = scan(&dir);
        assert_eq!(listed.error, None);
        assert_eq!(listed.files.len(), 1);
        if std::fs::metadata(d.path()).unwrap().uid() == 0 {
            eprintln!("root lists any directory: the unlistable case did not run");
            return;
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o100)).unwrap();
        let unlisted = scan(&dir);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(unlisted.error, Some(CheckReport::DIRECTORY_UNREADABLE));
        assert!(unlisted.files.is_empty());
        assert_eq!(unlisted.skipped, 0);
    }

    #[test]
    fn env_files_are_dot_env_and_its_variants() {
        for yes in [".env", ".env.local", ".env.example", ".env.production"] {
            assert!(is_env_file(OsStr::new(yes)), "{yes}");
        }
        for no in [".envrc", "env", ".env.", "x.env", ".environment", "README"] {
            assert!(!is_env_file(OsStr::new(no)), "{no}");
        }
    }

    /// Files are read safely and reported by kind and line only; a value
    /// never reaches the report.
    #[test]
    fn env_files_are_read_safely_and_reported_without_values() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path();
        let seed = envcloak_testkit::fresh_seed();
        let cs = envcloak_testkit::canaries(seed);
        let key = envcloak_testkit::by_label(&cs, envcloak_testkit::labels::GITHUB_TOKEN);
        let stripe = envcloak_testkit::by_label(&cs, envcloak_testkit::labels::STRIPE_SECRET_KEY);
        std::fs::write(
            dir.join(".env"),
            format!(
                "# comment\nGITHUB_TOKEN={}\nPORT=8080\nexport STRIPE_SECRET_KEY='{}'\n\
                 OPENAI_API_KEY=envcloak://openai/acme-web\n",
                key.as_str(),
                stripe.as_str()
            ),
        )
        .unwrap();
        std::fs::write(dir.join(".env.example"), "GITHUB_TOKEN=\nPORT=8080\n").unwrap();
        std::fs::write(dir.join(".env.broken"), format!("A='{}\n", key.as_str())).unwrap();
        std::fs::write(dir.join("outside"), key.as_str()).unwrap();
        std::os::unix::fs::symlink(dir.join("outside"), dir.join(".env.link")).unwrap();
        std::fs::write(dir.join(".env.big"), vec![b'#'; MAX_ENV_FILE + 1]).unwrap();
        let status = std::process::Command::new("mkfifo")
            .arg(dir.join(".env.fifo"))
            .status()
            .unwrap();
        assert!(status.success());

        let Scan {
            files: found,
            skipped,
            error,
        } = scan(dir);
        assert_eq!(skipped, 0);
        assert_eq!(error, None);
        let by_name = |n: &str| {
            found
                .iter()
                .find(|(v, _)| v.file == n)
                .unwrap_or_else(|| panic!("{n} was not scanned"))
        };
        let (env, refs) = by_name(".env");
        assert_eq!(env.state, EnvFileState::Read);
        assert_eq!(
            env.plaintext,
            vec![
                PlaintextView {
                    line: 2,
                    env_name: Some("GITHUB_TOKEN".into()),
                    provider: Some("github".into()),
                },
                PlaintextView {
                    line: 4,
                    env_name: Some("STRIPE_SECRET_KEY".into()),
                    provider: Some("stripe".into()),
                },
            ]
        );
        assert_eq!(refs, &vec!["OPENAI_API_KEY=openai/acme-web".to_owned()]);
        assert_eq!(env.references.len(), 1);
        assert_eq!(env.references[0].line, 5);
        assert!(by_name(".env.example").0.clean());
        let broken = &by_name(".env.broken").0;
        assert_eq!(broken.state, EnvFileState::Invalid);
        assert_eq!(broken.error_line, Some(1));
        assert_eq!(
            broken.error.as_deref(),
            Some("a quoted value is not closed")
        );
        assert_eq!(by_name(".env.link").0.state, EnvFileState::Symlink);
        assert_eq!(by_name(".env.big").0.state, EnvFileState::TooLarge);
        assert_eq!(by_name(".env.fifo").0.state, EnvFileState::NotRegular);
        assert!(!found.iter().any(|(v, _)| v.file == "outside"));

        let json = serde_json::to_vec(&found.iter().map(|(v, _)| v).collect::<Vec<_>>()).unwrap();
        envcloak_testkit::assert_no_canary(&json, &cs);
    }
}
