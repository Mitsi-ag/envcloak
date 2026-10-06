//! Opt-in git object scanning. The executable is absolute, its environment is
//! cleared, no working-tree filter runs, and diagnostics never leave the child.
use crate::candidates::{Budget, Candidate, Source};
use crate::source::ConfigFormat;
use crate::transcript::{StreamReport, scan_reader};
use crate::{ScanError, ScanErrorKind, ScanRoot};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

struct Git {
    child: Arc<Mutex<Child>>,
    stop: mpsc::Sender<()>,
    watcher: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Git {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(w) = self.watcher.take() {
            let _ = w.join();
        }
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct GitLocation {
    dir: File,
    git_dir: &'static str,
}

// Do not interpret Git's pointer-file grammar here. Any nonempty pointer is
// refused, even when its target might stay inside this root.
// This also covers transitive alternates and common stores beyond that pointer.
fn refuse_pointer(
    repo: &ScanRoot,
    dir: &File,
    name: &str,
    reason: &'static str,
    source: &Source,
    report: &mut StreamReport,
) -> Result<bool, ScanErrorKind> {
    let (_, metadata) = match crate::root::open_file(dir, OsStr::new(name), crate::MAX_DOTENV) {
        Ok(file) => file,
        Err(ScanErrorKind::NotFound) => return Ok(false),
        Err(e) => return Err(e),
    };
    if metadata.dev() != repo.dev() {
        return Err(ScanErrorKind::MountPoint);
    }
    if metadata.nlink() > 1 {
        report.issue(source, "hard_link");
    }
    if metadata.len() != 0 {
        report.issue(source, reason);
    }
    Ok(metadata.len() != 0)
}

fn git_location(
    repo: &ScanRoot,
    source: &Source,
    report: &mut StreamReport,
) -> Result<Option<GitLocation>, ScanErrorKind> {
    // Open first, then inspect that descriptor. A kind-only preflight would
    // leave Git free to follow a replaced .git pathname after inspection.
    let dir = match envcloak_sys::open_beneath(repo.dir(), OsStr::new(".git")) {
        Ok(file) => {
            let metadata = file.metadata().map_err(|e| crate::root::io_kind(&e))?;
            if metadata.dev() != repo.dev() {
                return Err(ScanErrorKind::MountPoint);
            }
            if metadata.is_dir() {
                file
            } else if metadata.is_file() {
                if metadata.uid() != envcloak_sys::effective_uid() {
                    return Err(ScanErrorKind::NotOwned);
                }
                if metadata.len() > crate::MAX_DOTENV as u64 {
                    return Err(ScanErrorKind::TooLarge);
                }
                if metadata.nlink() > 1 {
                    report.issue(source, "hard_link");
                }
                // A gitfile delegates path resolution to Git and drops the
                // inspected descriptor. Refuse it before any child can read.
                report.issue(source, "gitfile_indirection");
                return Ok(None);
            } else {
                return Err(ScanErrorKind::NotRegular);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => repo
            .dir()
            .try_clone()
            .map_err(|e| crate::root::io_kind(&e))?,
        Err(e) => return Err(crate::root::io_kind(&e)),
    };
    if refuse_pointer(repo, &dir, "commondir", "git_common_dir", source, report)? {
        return Ok(None);
    }
    match repo.open_subdir(&dir, OsStr::new("objects")) {
        Ok(objects) => {
            match repo.open_subdir(&objects, OsStr::new("info")) {
                Ok(info) => {
                    if refuse_pointer(repo, &info, "alternates", "git_alternates", source, report)?
                    {
                        return Ok(None);
                    }
                }
                Err(ScanErrorKind::NotFound) => {}
                Err(e) => return Err(e),
            }
            let mut remaining = envcloak_sys::MAX_DIR_ENTRIES;
            inspect_objects(
                repo,
                &objects,
                ObjectDir::Root,
                &mut remaining,
                source,
                report,
            )?;
        }
        Err(ScanErrorKind::NotFound) => {}
        Err(e) => return Err(e),
    }
    Ok(Some(GitLocation { dir, git_dir: "." }))
}

enum ObjectDir {
    Root,
    Info,
    Files,
}

// Git reads pack files, loose-object fanouts and info metadata by pathname.
// Inspect every entry through held directory descriptors, including unknown
// entry kinds, before allowing that traversal. Bound the whole walk as well as
// each listing so many small directories cannot evade the metadata cap.
fn inspect_objects(
    repo: &ScanRoot,
    dir: &File,
    layout: ObjectDir,
    remaining: &mut usize,
    source: &Source,
    report: &mut StreamReport,
) -> Result<(), ScanErrorKind> {
    let entries = envcloak_sys::list_dir(dir, (*remaining).min(envcloak_sys::MAX_DIR_ENTRIES))
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::OutOfMemory {
                ScanErrorKind::TooManyEntries
            } else {
                crate::root::io_kind(&e)
            }
        })?;
    *remaining = remaining
        .checked_sub(entries.len())
        .ok_or(ScanErrorKind::TooManyEntries)?;
    for entry in entries {
        let file =
            envcloak_sys::open_beneath(dir, &entry.name).map_err(|e| crate::root::io_kind(&e))?;
        let metadata = file.metadata().map_err(|e| crate::root::io_kind(&e))?;
        check_store_metadata(&metadata, repo.dev(), envcloak_sys::effective_uid())?;
        if metadata.is_dir() {
            // The only nested directory Git uses here is info/commit-graphs.
            // A directory in a fanout or pack file's place is not an object.
            let next = match layout {
                ObjectDir::Root if entry.name == "info" => ObjectDir::Info,
                ObjectDir::Root => ObjectDir::Files,
                ObjectDir::Info if entry.name == "commit-graphs" => ObjectDir::Files,
                _ => return Err(ScanErrorKind::NotRegular),
            };
            inspect_objects(repo, &file, next, remaining, source, report)?;
        } else if !metadata.is_file() {
            return Err(ScanErrorKind::NotRegular);
        } else if metadata.nlink() > 1 {
            report.issue(source, "hard_link");
        }
    }
    Ok(())
}

fn check_store_metadata(
    metadata: &std::fs::Metadata,
    device: u64,
    owner: u32,
) -> Result<(), ScanErrorKind> {
    if metadata.dev() != device {
        return Err(ScanErrorKind::MountPoint);
    }
    if metadata.uid() != owner {
        return Err(ScanErrorKind::NotOwned);
    }
    Ok(())
}

/// Scan the object database, including blobs no longer present in HEAD.
/// Git ranges identify object bytes and are never eligible for file rewriting.
pub fn scan_git_history(
    repo: &ScanRoot,
    budget: Budget,
    emit: &mut impl FnMut(Candidate) -> bool,
) -> Result<StreamReport, ScanError> {
    let source = Source {
        path: repo.path().to_path_buf(),
        object: None,
    };
    let mut report = StreamReport::default();
    let location = match git_location(repo, &source, &mut report) {
        Ok(Some(location)) => location,
        Ok(None) => return Ok(report),
        Err(e) => {
            report.issue(&source, e.token());
            return Ok(report);
        }
    };
    scan_location(location, source, budget, report, emit)
}

fn scan_location(
    location: GitLocation,
    source: Source,
    budget: Budget,
    mut report: StreamReport,
    emit: &mut impl FnMut(Candidate) -> bool,
) -> Result<StreamReport, ScanError> {
    let error = || ScanError {
        rel: std::path::PathBuf::new(),
        kind: ScanErrorKind::Io(std::io::ErrorKind::Other),
    };
    let mut command = Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/dev/null")
        .env("XDG_CONFIG_HOME", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        // Partial clones may fetch missing or corrupt objects while reading.
        // The protocol guard also covers Git versions without lazy-fetch opt-out.
        .env("GIT_NO_LAZY_FETCH", "1")
        // An empty allowlist overrides repository protocol.<name>.allow too.
        .env("GIT_ALLOW_PROTOCOL", "")
        .args(["--git-dir", location.git_dir, "--work-tree", "."])
        .env("LC_ALL", "C")
        .args([
            "--no-pager",
            "--no-replace-objects",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "protocol.allow=never",
            "cat-file",
            "--batch-all-objects",
            "--batch",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    envcloak_sys::chdir_on_spawn(&mut command, &location.dir).map_err(|_| error())?;
    let mut process = command.spawn().map_err(|_| error())?;
    let stdout = process.stdout.take().ok_or_else(error)?;
    let child = Arc::new(Mutex::new(process));
    let observed = Arc::clone(&child);
    let (stop, wait) = mpsc::channel();
    let watcher = std::thread::spawn(move || {
        if wait.recv_timeout(Duration::from_secs(30)).is_err() {
            if let Ok(mut child) = observed.lock() {
                let _ = child.kill();
            }
        }
    });
    let child = Git {
        child,
        stop,
        watcher: Some(watcher),
    };
    let mut reader = BufReader::with_capacity(8192, stdout.take(budget.bytes));
    let mut objects = 0;
    let mut reached_eof = false;
    loop {
        // Headers contain only an object id, type and size. An oversized or
        // malformed header is never copied into an error.
        let mut header = Vec::with_capacity(128);
        let n = reader
            .by_ref()
            .take(256)
            .read_until(b'\n', &mut header)
            .map_err(|_| error())?;
        if n == 0 {
            if reader.get_ref().limit() == 0 {
                report.issue(&source, "byte_budget");
            } else {
                reached_eof = true;
            }
            break;
        }
        if n == 256 || header.last() != Some(&b'\n') {
            report.issue(&source, "invalid_git_frame");
            break;
        }
        if objects >= budget.objects {
            report.issue(&source, "object_budget");
            break;
        }
        objects += 1;
        let Ok(text) = std::str::from_utf8(&header) else {
            report.issue(&source, "invalid_git_frame");
            break;
        };
        let fields: Vec<_> = text.trim_end_matches('\n').split(' ').collect();
        if fields.len() != 3
            || !matches!(fields[0].len(), 40 | 64)
            || !fields[0].bytes().all(|b| b.is_ascii_hexdigit())
        {
            report.issue(&source, "invalid_git_frame");
            break;
        }
        let Ok(size) = fields[2].parse::<u64>() else {
            report.issue(&source, "invalid_git_frame");
            break;
        };
        if size > budget.bytes.saturating_sub(report.bytes) {
            report.issue(&source, "byte_budget");
            break;
        }
        if matches!(fields[1], "blob" | "commit" | "tag") {
            // One extra byte of allowance lets the size-limited object reader
            // prove EOF without a false exact-budget failure.
            let slice_budget = Budget {
                bytes: size.saturating_add(1),
                occurrences: budget
                    .occurrences
                    .saturating_sub(report.candidates as usize),
                ..budget
            };
            let object_source = Source {
                path: source.path.clone(),
                object: Some(fields[0].to_owned()),
            };
            let part = scan_reader(
                &mut reader.by_ref().take(size),
                ConfigFormat::Raw,
                object_source,
                slice_budget,
                &mut |mut c| {
                    c.occurrence.rewritable = false;
                    emit(c)
                },
            )?;
            report.bytes += part.bytes;
            report.candidates += part.candidates;
            report.not_scanned += part.not_scanned;
            let stopped = part.issues.iter().any(|i| {
                matches!(
                    i.reason,
                    "byte_budget" | "occurrence_budget" | "candidate_budget" | "unreadable"
                )
            });
            report.issues.extend(part.issues);
            if stopped || part.bytes != size {
                if part.bytes != size {
                    report.issue(&source, "truncated_git_object");
                }
                break;
            }
        } else if fields[1] == "tree" {
            let count = std::io::copy(&mut reader.by_ref().take(size), &mut std::io::sink())
                .map_err(|_| error())?;
            report.bytes += count;
            if count != size {
                report.issue(&source, "truncated_git_object");
                break;
            }
        } else {
            report.issue(&source, "invalid_git_frame");
            break;
        }
        let mut separator = [0u8; 1];
        if reader.read_exact(&mut separator).is_err() || separator[0] != b'\n' {
            report.issue(&source, "invalid_git_frame");
            break;
        }
    }
    report.bytes = budget.bytes.saturating_sub(reader.get_ref().limit());
    if reached_eof {
        let status = loop {
            if let Some(status) = child
                .child
                .lock()
                .map_err(|_| error())?
                .try_wait()
                .map_err(|_| error())?
            {
                break status;
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        if !status.success() {
            report.issue(&source, "git_failed");
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository(path: &std::path::Path, value: &[u8]) {
        std::fs::create_dir(path).expect("directory");
        std::fs::write(path.join("fixture"), value).expect("fixture");
        for args in [["init", "-q"], ["add", "fixture"]] {
            let output = Command::new("/usr/bin/git")
                .args(args)
                .current_dir(path)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", path)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .output()
                .expect("git");
            assert!(output.status.success(), "fixture preparation failed");
        }
    }

    #[test]
    fn prepared_git_directory_survives_path_replacement() {
        let d = tempfile::tempdir_in("/tmp").expect("temporary root");
        let project = d.path().join("project");
        let other = d.path().join("other");
        repository(&project, b"fixtureZheldGitDirectory");
        repository(&other, b"fixtureZreplacedGitDirectory");
        let root = crate::open_root(&project).expect("root");
        let source = Source {
            path: root.path().to_path_buf(),
            object: None,
        };
        let mut report = StreamReport::default();
        let location = git_location(&root, &source, &mut report)
            .expect("location")
            .expect("confined store");
        // This is the exact boundary between selecting the directory and
        // starting the child. No scheduling delay is needed for the gate.
        std::fs::rename(project.join(".git"), d.path().join("held")).expect("move");
        std::os::unix::fs::symlink(other.join(".git"), project.join(".git")).expect("link");
        let mut found = false;
        let report = scan_location(location, source, Budget::default(), report, &mut |c| {
            assert!(
                !c.value.ct_eq(b"fixtureZreplacedGitDirectory"),
                "reopened Git directory"
            );
            found |= c.value.ct_eq(b"fixtureZheldGitDirectory");
            true
        })
        .expect("scan");
        assert!(report.complete(), "{report:?}");
        assert!(found, "held Git directory was not scanned");
    }
    #[test]
    fn prepared_git_directory_survives_gitfile_replacement() {
        let d = tempfile::tempdir_in("/tmp").expect("temporary root");
        let project = d.path().join("project");
        let other = d.path().join("other");
        repository(&project, b"fixtureZheldGitDirectory");
        repository(&other, b"fixtureZreplacedGitDirectory");
        let root = crate::open_root(&project).expect("root");
        let source = Source {
            path: root.path().to_path_buf(),
            object: None,
        };
        let mut report = StreamReport::default();
        let location = git_location(&root, &source, &mut report)
            .expect("location")
            .expect("confined store");
        // This is the exact boundary between selecting the directory and
        // starting the child. No scheduling delay is needed for the gate.
        std::fs::rename(project.join(".git"), d.path().join("held")).expect("move");
        std::fs::write(
            project.join(".git"),
            format!("gitdir: {}\n", other.join(".git").display()),
        )
        .expect("gitfile");
        let mut found = false;
        let report = scan_location(location, source, Budget::default(), report, &mut |c| {
            assert!(
                !c.value.ct_eq(b"fixtureZreplacedGitDirectory"),
                "reopened Git directory"
            );
            found |= c.value.ct_eq(b"fixtureZheldGitDirectory");
            true
        })
        .expect("scan");
        assert!(report.complete(), "{report:?}");
        assert!(found, "held Git directory was not scanned");
    }
    #[test]
    fn git_store_metadata_requires_the_same_device_and_owner() {
        let d = tempfile::tempdir_in("/tmp").expect("fixture");
        let file = File::create(d.path().join("file")).expect("file");
        let metadata = file.metadata().expect("metadata");
        assert_eq!(
            check_store_metadata(&metadata, metadata.dev(), metadata.uid()),
            Ok(())
        );
        // Recording models avoid privileged chown or a real mount on the host.
        assert_eq!(
            check_store_metadata(&metadata, metadata.dev() ^ 1, metadata.uid()),
            Err(ScanErrorKind::MountPoint)
        );
        assert_eq!(
            check_store_metadata(&metadata, metadata.dev(), metadata.uid() ^ 1),
            Err(ScanErrorKind::NotOwned)
        );
    }

    #[test]
    fn git_store_entry_limit_covers_all_directories() {
        let d = tempfile::tempdir_in("/tmp").expect("fixture");
        for fanout in ["aa", "bb"] {
            std::fs::create_dir(d.path().join(fanout)).expect("fanout");
            std::fs::write(d.path().join(fanout).join("object"), b"").expect("object");
        }
        let root = crate::open_root(d.path()).expect("root");
        let source = Source::default();
        for cap in [3, 4] {
            let result = inspect_objects(
                &root,
                root.dir(),
                ObjectDir::Root,
                &mut { cap },
                &source,
                &mut StreamReport::default(),
            );
            assert_eq!(
                result,
                if cap == 4 {
                    Ok(())
                } else {
                    Err(ScanErrorKind::TooManyEntries)
                }
            );
        }
    }
}
