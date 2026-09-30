//! `envcloak check` over more env files than it reads (review finding
//! F-48), with a real daemon and an unlocked vault: at most 64 env files
//! are read, the first by name, and the ones past the bound are counted,
//! shown and fail the check, so a plaintext key in the 65th file is never
//! passed over as a clean result. A project directory that cannot be
//! listed fails the check too (the F-48 follow-up).
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use common::{
    MANIFEST, cli_command, finish_within, on_terminal_command, outside_dir, project, secret_file,
    seed_vault, start_daemon, stderr, stdout,
};
use envcloak_testkit::{
    Canary, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};

/// `envcloak check` in `dir`, as an agent runs it, swept for canaries.
fn check(home: &TestHome, dir: &Path, cs: &[Canary], json: bool) -> Output {
    let args: &[&str] = if json {
        &["check", "--json"]
    } else {
        &["check"]
    };
    let mut cmd = cli_command(home, args, &[]);
    cmd.current_dir(dir);
    let out = finish_within(cmd, Duration::from_secs(60));
    assert_no_canary(&out.stdout, cs);
    assert_no_canary(&out.stderr, cs);
    out
}

/// Fills `dir` with `empty` empty env files named `.env.f00` onwards, and
/// one more named `key_file` holding a plaintext GitHub token.
fn env_files(dir: &Path, empty: usize, key_file: &str, cs: &[Canary]) {
    for i in 0..empty {
        std::fs::write(dir.join(format!(".env.f{i:02}")), "").unwrap();
    }
    std::fs::write(
        dir.join(key_file),
        format!(
            "GITHUB_TOKEN={}\n",
            by_label(cs, labels::GITHUB_TOKEN).as_str()
        ),
    )
    .unwrap();
}

#[test]
fn env_files_past_the_bound_are_counted_and_fail_the_check() {
    let mut cs = canaries(fresh_seed());
    let home = TestHome::new();
    let kit = seed_vault(&home, &cs);
    cs.push(kit);
    let d = start_daemon(&home);
    let files = outside_dir();
    let pass: PathBuf = secret_file(
        files.path(),
        "pass",
        by_label(&cs, labels::VAULT_PASSPHRASE).value(),
    );
    let out = finish_within(
        on_terminal_command(
            &home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &pass, true)],
        ),
        Duration::from_secs(60),
    );
    assert!(out.status.success(), "{}{}", stdout(&out), stderr(&out));

    // 64 empty env files: every one is read, and the check passes.
    let bounded = project(&home, "bounded", MANIFEST);
    for i in 0..64 {
        std::fs::write(bounded.join(format!(".env.f{i:02}")), "").unwrap();
    }
    let out = check(&home, &bounded, &cs, true);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["env_files"].as_array().unwrap().len(), 64);
    assert_eq!(r["env_files_skipped"], 0);

    // The key in the 64th file by name: read, and reported.
    let inside = project(&home, "inside", MANIFEST);
    env_files(&inside, 63, ".env.zz", &cs);
    let out = check(&home, &inside, &cs, true);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["env_files_skipped"], 0);
    let last = &r["env_files"][63];
    assert_eq!(last["file"], ".env.zz");
    assert_eq!(last["plaintext"][0]["env_name"], "GITHUB_TOKEN");

    // The key in the 65th: not read, but counted, shown, and failing.
    let past = project(&home, "past", MANIFEST);
    env_files(&past, 64, ".env.zz", &cs);
    let out = check(&home, &past, &cs, true);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    assert!(stderr(&out).contains("check_failed"), "{}", stderr(&out));
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let read = r["env_files"].as_array().unwrap();
    assert_eq!(read.len(), 64);
    assert!(read.iter().all(|f| f["file"] != ".env.zz"));
    assert_eq!(r["env_files_skipped"], 1);
    let out = check(&home, &past, &cs, false);
    assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
    let text = stdout(&out);
    assert!(
        text.contains(
            "  1 more env file was not read: at most 64 are checked, the first by name\n"
        ),
        "{text}"
    );
    assert!(
        text.ends_with("result: 1 env file was not read\n"),
        "{text}"
    );

    // The keys were put there for `check` to find; the sweep is about what
    // EnvCloak wrote.
    std::fs::remove_file(inside.join(".env.zz")).unwrap();
    std::fs::remove_file(past.join(".env.zz")).unwrap();
    assert_no_canary(&d.log_bytes(), &cs);
    home.assert_clean(&cs);
    drop(files);
}

/// Gives a directory back its mode 0700 when dropped, whatever the test
/// did meanwhile.
struct ModeBack<'a>(&'a Path);

impl Drop for ModeBack<'_> {
    fn drop(&mut self) {
        let _ = std::fs::set_permissions(self.0, std::fs::Permissions::from_mode(0o700));
    }
}

/// The F-48 follow-up (Codex, cycle 152): a project directory that
/// cannot be listed is not a clean check. The same directory, without a
/// manifest (so nothing goes to a daemon, and none runs): empty, it
/// passes; with a plaintext key, the key is reported; searchable but not
/// listable, the check fails with `env_scan_error` and reports no files
/// as if there were none; listable again, the key is reported again.
#[test]
fn a_directory_that_cannot_be_listed_fails_the_check() {
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let dir = home.root().join("plain");
    std::fs::create_dir(&dir).unwrap();

    let out = check(&home, &dir, &cs, true);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(r["env_files"].as_array().unwrap().len(), 0);
    assert!(r["env_scan_error"].is_null());
    assert_eq!(r["unchecked"], "no_manifest");

    env_files(&dir, 0, ".env", &cs);
    let found = |out: &Output| {
        assert_eq!(out.status.code(), Some(1), "{}", stdout(out));
        let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(r["env_scan_error"].is_null());
        assert_eq!(
            r["env_files"][0]["plaintext"][0]["env_name"],
            "GITHUB_TOKEN"
        );
    };
    found(&check(&home, &dir, &cs, true));

    if std::fs::metadata(home.root()).unwrap().uid() == 0 {
        eprintln!("root lists any directory: the unlistable case did not run");
    } else {
        let back = ModeBack(&dir);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o100)).unwrap();
        assert!(std::fs::read_dir(&dir).is_err());
        let out = check(&home, &dir, &cs, true);
        assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
        assert!(stderr(&out).contains("check_failed"), "{}", stderr(&out));
        let r: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(r["env_scan_error"], "directory_unreadable");
        assert_eq!(r["env_files"].as_array().unwrap().len(), 0);
        assert_eq!(r["env_files_skipped"], 0);
        let out = check(&home, &dir, &cs, false);
        assert_eq!(out.status.code(), Some(1), "{}", stdout(&out));
        let text = stdout(&out);
        assert!(
            text.contains(
                "env files: the project directory could not be listed, so its env files were \
                 not read\n"
            ),
            "{text}"
        );
        assert!(!text.contains("env files: none"), "{text}");
        assert!(
            text.ends_with(
                "result: the env-file check is incomplete: the project directory could not be \
                 listed in full; make it readable and run the check again\n"
            ),
            "{text}"
        );
        drop(back);
    }

    found(&check(&home, &dir, &cs, true));
    // The key was put there for `check` to find; the sweep is about what
    // EnvCloak wrote.
    std::fs::remove_file(dir.join(".env")).unwrap();
    home.assert_clean(&cs);
}
