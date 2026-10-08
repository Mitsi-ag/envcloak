//! Scrub admission from the daemon's own host settings, never client claims.
//! The CLI catalog parity gate covers every writable transcript descriptor.

use envcloak_core::file_backup_v2::BackupPurpose;
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

enum Rule {
    Tree(PathBuf),
    File(PathBuf),
    Named(PathBuf, &'static str),
}

pub(super) struct Scope(Vec<Rule>);
impl Scope {
    pub(super) fn new(env: &dyn Fn(&str) -> Option<OsString>, purpose: BackupPurpose) -> Self {
        if purpose != BackupPurpose::Scrub {
            return Self(Vec::new());
        }
        let absolute = |key| env(key).map(PathBuf::from).filter(|p| p.is_absolute());
        let Some(home) = absolute("HOME") else {
            return Self(Vec::new());
        };
        let custom = absolute("CLAUDE_CONFIG_DIR");
        let claude = custom.clone().unwrap_or_else(|| home.join(".claude"));
        let codex = absolute("CODEX_HOME").unwrap_or_else(|| home.join(".codex"));
        let claude_tmp = absolute("CLAUDE_CODE_TMPDIR").unwrap_or_else(|| "/tmp".into());
        let tmp = absolute("TMPDIR").unwrap_or_else(|| "/tmp".into());
        let mut rules = Vec::new();
        for sub in [
            "projects",
            "paste-cache",
            "file-history",
            "plans",
            "sessions",
            "session-env",
            "shell-snapshots",
            "todos",
            "tasks",
            "debug",
            "telemetry",
            "backups",
        ] {
            rules.push(Rule::Tree(claude.join(sub)));
        }
        rules.push(Rule::File(claude.join("history.jsonl")));
        rules.push(Rule::Named(
            custom.unwrap_or_else(|| home.clone()),
            ".claude.json.backup",
        ));
        rules.push(Rule::Tree(
            claude_tmp.join(format!("claude-{}", envcloak_sys::effective_uid())),
        ));
        rules.push(Rule::Named(claude_tmp, "-cwd"));
        for sub in [
            "sessions",
            "archived_sessions",
            "log",
            "shell_snapshots",
            "memories",
        ] {
            rules.push(Rule::Tree(codex.join(sub)));
        }
        rules.push(Rule::File(codex.join("history.jsonl")));
        rules.push(Rule::Tree(tmp.join("hook_outputs")));
        if let Some(log) = moved_log(&codex, &home) {
            rules.push(Rule::Tree(log));
        }
        Self(rules)
    }

    pub(super) fn allows(&self, path: &str) -> bool {
        if !super::valid_path(path) {
            return false;
        }
        let path = system_spelling(Path::new(path));
        self.0.iter().any(|rule| {
            let (Rule::Tree(root) | Rule::File(root) | Rule::Named(root, _)) = rule;
            if !root.to_str().is_some_and(super::valid_path) {
                return false;
            }
            let root = system_spelling(root);
            match rule {
                Rule::Tree(_) => path != root && path.starts_with(root),
                Rule::File(_) => path == root,
                Rule::Named(_, name) => {
                    path.parent() == Some(root.as_path())
                        && path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.contains(name))
                }
            }
        })
    }
}

// Resolve only fixed root-owned system aliases. Canonicalizing an entire
// catalog root would let a user-controlled symlink grant an unrelated tree.
fn system_spelling(path: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    for (alias, target) in [
        ("/tmp", "/private/tmp"),
        ("/var", "/private/var"),
        ("/etc", "/private/etc"),
    ] {
        if let Ok(rest) = path.strip_prefix(alias) {
            if std::fs::symlink_metadata(alias)
                .is_ok_and(|m| m.uid() == 0 && m.file_type().is_symlink())
                && std::fs::read_link(alias)
                    .is_ok_and(|p| p == Path::new(target) || p == Path::new(&target[1..]))
            {
                return Path::new(target).join(rest);
            }
        }
    }
    path.to_path_buf()
}

fn moved_log(codex: &Path, home: &Path) -> Option<PathBuf> {
    // Re-read for every begin. A cached log_dir must never outlive its setting.
    const MAX_CONFIG: u64 = 1024 * 1024;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(codex.join("config.toml"))
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file()
        || metadata.uid() != envcloak_sys::effective_uid()
        || metadata.nlink() != 1
        || metadata.len() > MAX_CONFIG
    {
        return None;
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(MAX_CONFIG + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_CONFIG {
        return None;
    }
    let doc = toml_edit::Document::parse(std::str::from_utf8(&bytes).ok()?).ok()?;
    let value = doc.get("log_dir")?.as_str()?;
    if value.is_empty() {
        return None;
    }
    Some(match value.strip_prefix('~') {
        Some("") => home.to_path_buf(),
        Some(rest) if rest.starts_with('/') => home.join(rest.trim_start_matches('/')),
        _ => codex.join(value),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn env(root: &Path, key: &str) -> Option<OsString> {
        let relative = match key {
            "HOME" => "home",
            "CODEX_HOME" => "stores/x",
            "CLAUDE_CONFIG_DIR" => "stores/c",
            "CLAUDE_CODE_TMPDIR" => "claude-temp",
            "TMPDIR" => "codex-temp",
            _ => return None,
        };
        Some(root.join(relative).into_os_string())
    }

    #[test]
    fn gate37_catalog_scope_preserves_name_root_and_purpose_boundaries() {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let root = d.path();
        let scope = Scope::new(&|k| env(root, k), BackupPurpose::Scrub);
        let uid = envcloak_sys::effective_uid();
        for relative in [
            "stores/c/projects/tool.txt".to_owned(),
            "stores/c/.claude.json.backup.fixture".to_owned(),
            "stores/x/sessions/capture".to_owned(),
            "stores/x/history.jsonl".to_owned(),
            format!("claude-temp/claude-{uid}/tasks/output"),
            "claude-temp/fixture-cwd".to_owned(),
            "codex-temp/hook_outputs/output".to_owned(),
        ] {
            let p = root.join(relative);
            assert!(scope.allows(p.to_str().unwrap()));
            assert!(scope.allows(system_spelling(&p).to_str().unwrap()));
            for purpose in [
                BackupPurpose::Init,
                BackupPurpose::Agents,
                BackupPurpose::Migrate,
            ] {
                assert!(!Scope::new(&|k| env(root, k), purpose).allows(p.to_str().unwrap()));
            }
        }
        for relative in [
            "stores/c/unrelated.txt".to_owned(),
            "stores/c/nested/.claude.json.backup.fixture".to_owned(),
            "stores/x/sessions-other/capture".to_owned(),
            "stores/x/history.jsonl/child".to_owned(),
            format!("claude-temp/claude-{}/tasks/output", u64::from(uid) + 1),
            "claude-temp/nested/fixture-cwd".to_owned(),
            "claude-temp/unrelated.txt".to_owned(),
            "codex-temp/other/output".to_owned(),
            "client-only/sessions/capture".to_owned(),
            "stores/x/sessions/../outside".to_owned(),
            "stores/x/sessions/./capture".to_owned(),
            "stores/x/sessions//capture".to_owned(),
            "stores/x/sessions/capture/".to_owned(),
            "stores/x/sessions/nul\0name".to_owned(),
        ] {
            assert!(!scope.allows(root.join(relative).to_str().unwrap()));
        }
        assert!(!scope.allows(&format!(
            "{}/stores/x/sessions/{}",
            root.display(),
            "x".repeat(4096)
        )));
        std::fs::create_dir_all(root.join("stores/x")).unwrap();
        std::fs::create_dir(root.join("foreign")).unwrap();
        std::os::unix::fs::symlink(root.join("foreign"), root.join("stores/x/sessions")).unwrap();
        assert!(
            !scope.allows(root.join("foreign/capture").to_str().unwrap()),
            "symlink widened a catalog root"
        );
    }

    #[test]
    fn gate37_catalog_log_setting_is_bounded_typed_and_recomputed() {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let root = d.path();
        let config = root.join("stores/x/config.toml");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        let allows = |path: &Path| {
            Scope::new(&|k| env(root, k), BackupPurpose::Scrub).allows(path.to_str().unwrap())
        };
        for setting in [
            "../logs",
            "~/logs",
            root.join("absolute-logs").to_str().unwrap(),
        ] {
            std::fs::write(&config, format!("log_dir = {setting:?}\n")).unwrap();
            // Parent components are refused by path admission, as by discovery.
            if setting == "../logs" {
                assert!(!allows(&root.join("stores/logs/capture")));
            } else {
                let expected = if setting.starts_with('~') {
                    root.join("home/logs/capture")
                } else {
                    root.join("absolute-logs/capture")
                };
                assert!(allows(&expected));
            }
        }
        let previous = root.join("absolute-logs/capture");
        std::fs::write(&config, "log_dir = 'fresh-logs'\n").unwrap();
        assert!(!allows(&previous), "stale configured root retained");
        assert!(allows(&root.join("stores/x/fresh-logs/capture")));
        for invalid in [
            b"log_dir = [1]\n".to_vec(),
            b"log_dir = ''\n".to_vec(),
            b"log_dir = '\xff'\n".to_vec(),
            b"log_dir = 'unfinished\n".to_vec(),
            b"log_dir = 'fresh-logs'\nlog_dir = 'other'\n".to_vec(),
            [
                b"log_dir = 'fresh-logs'\n#".as_slice(),
                &vec![b'x'; 1024 * 1024],
            ]
            .concat(),
        ] {
            std::fs::write(&config, invalid).unwrap();
            assert!(!allows(&previous));
            assert!(!allows(&root.join("stores/x/fresh-logs/capture")));
        }
        std::fs::remove_file(&config).unwrap();
        assert!(!allows(&previous));
        let held = root.join("held-config");
        std::fs::write(&held, "log_dir = 'fresh-logs'\n").unwrap();
        std::os::unix::fs::symlink(&held, &config).unwrap();
        assert!(!allows(&root.join("stores/x/fresh-logs/capture")));
        std::fs::remove_file(&config).unwrap();
        std::fs::hard_link(&held, &config).unwrap();
        assert!(!allows(&root.join("stores/x/fresh-logs/capture")));
    }
}
