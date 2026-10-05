//! Opt-in git object scanning. The executable is absolute, its environment is
//! cleared, no working-tree filter runs, and diagnostics never leave the child.
use crate::candidates::{Budget, Candidate, Source};
use crate::source::ConfigFormat;
use crate::transcript::{StreamReport, scan_reader};
use crate::{ScanError, ScanErrorKind, ScanRoot};
use std::io::{BufRead, BufReader, Read};
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
    let error = || ScanError {
        rel: std::path::PathBuf::new(),
        kind: ScanErrorKind::Io(std::io::ErrorKind::Other),
    };
    let mut report = StreamReport::default();
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
        .env("LC_ALL", "C")
        .args([
            "--no-pager",
            "--no-replace-objects",
            "-c",
            "core.fsmonitor=false",
            "cat-file",
            "--batch-all-objects",
            "--batch",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    envcloak_sys::chdir_on_spawn(&mut command, repo.dir()).map_err(|_| error())?;
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
        if fields[1] == "blob" {
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
            let complete = part.complete();
            report.issues.extend(part.issues);
            if !complete || part.bytes != size {
                if part.bytes != size {
                    report.issue(&source, "truncated_git_object");
                }
                break;
            }
        } else if matches!(fields[1], "tree" | "commit" | "tag") {
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
    if report.complete() {
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
