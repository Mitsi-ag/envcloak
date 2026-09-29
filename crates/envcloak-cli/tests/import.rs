//! `envcloak init`, `envcloak import --scan` and `envcloak recovery
//! confirm` (SPEC §6.4; T13), with a real daemon:
//! - story steps S2 and S3: a dry run first, then the import with
//!   providers detected, `envcloak.toml` and `.gitignore` written, the
//!   delete refused until the Recovery Kit is confirmed, then the files
//!   deleted after an encrypted backup, metadata-only `ls`, `show` and
//!   `check`, and `init --undo` putting the files back byte for byte;
//! - `.gitignore` edits are idempotent, and template files contribute
//!   names only;
//! - one value in two repos becomes one item both reference, found by
//!   keyed hash in the daemon;
//! - gate 15 through the commands: a symlinked `.env` outside the root, a
//!   FIFO, a 2 GB file, a directory symlink loop, a hard link and an
//!   unreadable file: no hang, nothing followed or modified, no value in
//!   the report;
//! - gate 16: each of the four conditions refuses the deletion on its
//!   own, and `kill -9` at every step leaves either the plaintext file or
//!   the committed item.
//!
//! Every command's output, the daemon's log and the home are swept for
//! the canaries.
#![allow(clippy::unwrap_used)]

mod common;

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, SystemTime};

use common::{
    cli_command, data_dir, finish_within, on_terminal_command, outside_dir, secret_file,
    start_daemon, stderr, stdout,
};
use envcloak_core::crypto::{ItemClass, KdfParams};
use envcloak_core::vault::{FieldName, ItemDetails, NewItem, Slug, VaultPaths};
use envcloak_core::{RecoveryKit, SecretBytes, create_vault_with_kit};
use envcloak_ipc::proto::{
    BackupFileParams, FilesBackupParams, ImportCommitParams, VerifyEntry, VerifyFile, VerifyParams,
};
use envcloak_ipc::view::EntryStatus;
use envcloak_ipc::{Client, RunPaths, WireSecret};
use envcloak_scan::{
    DeleteGate, DeleteStep, EntryKind, FileStamp, MAX_DOTENV, delete_plaintext, open_root,
    parse_dotenv, read_capped,
};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};

/// Runs `envcloak <args>` in `dir`, detached from any terminal.
fn run_in(home: &TestHome, dir: &Path, args: &[&str]) -> Output {
    let mut cmd = cli_command(home, args, &[]);
    cmd.current_dir(dir);
    finish_within(cmd, Duration::from_secs(120))
}

/// Runs `envcloak <args>` in `dir` on a terminal of its own, as a person
/// gives a proof, with `fds` opened.
fn person_in(home: &TestHome, dir: &Path, args: &[&str], fds: &[(i32, &Path, bool)]) -> Output {
    let mut cmd = on_terminal_command(home, args, fds);
    cmd.current_dir(dir);
    finish_within(cmd, Duration::from_secs(120))
}

/// Sets a file's modification time `ago` in the past: files changed in
/// the last two minutes are never deleted.
fn age(p: &Path, ago: Duration) {
    File::options()
        .write(true)
        .open(p)
        .unwrap()
        .set_modified(SystemTime::now() - ago)
        .unwrap();
}

/// A dotenv double-quoted value.
fn dq(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The story's fixture repo `acme-web` (SPEC §15.1): `.env`, `.env.short`
/// and `.env.example`. Returns the directory and the files' bytes.
fn acme_web(home: &TestHome, cs: &[Canary]) -> (PathBuf, Vec<(&'static str, Vec<u8>)>) {
    let dir = home.root().join("acme-web");
    std::fs::create_dir_all(&dir).unwrap();
    let v = |l| by_label(cs, l).as_str();
    let env = format!(
        "# acme-web\nOPENAI_API_KEY={}\nexport STRIPE_SECRET_KEY={}\nGITHUB_TOKEN='{}'\n\
         DATABASE_URL={}\nPORT=8080\n",
        v(labels::OPENAI_API_KEY),
        v(labels::STRIPE_SECRET_KEY),
        v(labels::GITHUB_TOKEN),
        dq(v(labels::DATABASE_URL)),
    );
    let short = format!("SHORT_TOKEN={}\r\n", v(labels::SHORT_TOKEN));
    // A template's values never leave the CLI: this one is a real key's
    // shape, which must not reach the vault or any output.
    let example = format!(
        "OPENAI_API_KEY={}\nSTRIPE_SECRET_KEY=\nGITHUB_TOKEN=\n",
        v(labels::OPENAI_API_KEY_ROTATED)
    );
    let files = vec![
        (".env", env.into_bytes()),
        (".env.short", short.into_bytes()),
        (".env.example", example.into_bytes()),
    ];
    for (name, body) in &files {
        std::fs::write(dir.join(name), body).unwrap();
        age(&dir.join(name), Duration::from_secs(600));
    }
    (dir, files)
}

fn ok(out: &Output, cs: &[Canary]) -> String {
    assert_no_canary(&out.stdout, cs);
    assert_no_canary(&out.stderr, cs);
    assert!(out.status.success(), "{}\n{}", stdout(out), stderr(out));
    stdout(out)
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap()
}

/// A vault created through the CLI (story S1): the passphrase on
/// descriptor 3, the kit written to descriptor 4.
struct Story {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    _files: tempfile::TempDir,
    pass: PathBuf,
    kit: PathBuf,
}

impl Story {
    fn new() -> Self {
        let cs = canaries(fresh_seed());
        let home = TestHome::new();
        let d = start_daemon(&home);
        let files = outside_dir();
        let pass = secret_file(
            files.path(),
            "pass",
            by_label(&cs, labels::VAULT_PASSPHRASE).value(),
        );
        let kit = files.path().join("kit");
        let out = finish_within(
            cli_command(
                &home,
                &[
                    "vault",
                    "create",
                    "--passphrase-fd",
                    "3",
                    "--kit-fd",
                    "4",
                    "--kdf-memory",
                    "64MiB",
                ],
                &[(3, &pass, true), (4, &kit, false)],
            ),
            Duration::from_secs(120),
        );
        assert!(out.status.success(), "{}{}", stderr(&out), d.log());
        let mut cs = cs;
        let text = std::fs::read_to_string(&kit).unwrap();
        cs.push(Canary::new("RECOVERY_KIT", text.trim_end().to_owned()));
        Story {
            cs,
            home,
            d,
            _files: files,
            pass,
            kit,
        }
    }

    fn sweep(&self) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

/// Story steps S2 and S3, then `init --undo`.
#[test]
fn story_s2_and_s3_import_confirm_delete_and_undo() {
    let s = Story::new();
    let (repo, files) = acme_web(&s.home, &s.cs);

    // A dry run writes nothing and imports nothing.
    let out = run_in(&s.home, &repo, &["init", "--import"]);
    let text = ok(&out, &s.cs);
    assert!(text.contains("dry run"), "{text}");
    assert!(text.contains("openai/acme-web"), "{text}");
    assert!(!repo.join("envcloak.toml").exists());
    assert!(!repo.join(".gitignore").exists());
    let ls = run_in(&s.home, &repo, &["ls", "--json"]);
    assert_eq!(json(&ls)["items"].as_array().unwrap().len(), 0);

    // S2: the import.
    let out = run_in(&s.home, &repo, &["init", "--import", "--yes", "--json"]);
    ok(&out, &s.cs);
    let r = json(&out);
    assert_eq!(r["import"]["committed"], true);
    let p = &r["import"]["projects"][0];
    assert_eq!(p["manifest"], "created");
    assert_eq!(p["gitignore"], "created");
    assert_eq!(p["resolves"], true);
    let manifest = std::fs::read_to_string(repo.join("envcloak.toml")).unwrap();
    let m = envcloak_policy::parse_manifest(manifest.as_bytes()).unwrap();
    let bound: Vec<String> = m
        .env
        .iter()
        .map(|b| format!("{}={}", b.env_name, b.reference))
        .collect();
    assert_eq!(
        bound,
        [
            "DATABASE_URL=database-url/acme-web",
            "GITHUB_TOKEN=github/acme-web",
            "OPENAI_API_KEY=openai/acme-web",
            "STRIPE_SECRET_KEY=stripe/acme-web",
        ]
    );
    let short = &m.profiles[&envcloak_policy::ProfileName::new("short").unwrap()];
    assert_eq!(short[0].reference.to_string(), "short-token/acme-web-short");
    let gitignore = std::fs::read_to_string(repo.join(".gitignore")).unwrap();
    assert!(gitignore.lines().any(|l| l == "/.env"), "{gitignore}");
    assert!(gitignore.lines().any(|l| l == "/.env.short"), "{gitignore}");
    assert!(!gitignore.contains(".env.example"), "{gitignore}");

    // S3: metadata only. (`check` passes once the plaintext is gone.)
    let ls = run_in(&s.home, &repo, &["ls", "--json"]);
    ok(&ls, &s.cs);
    let mut slugs: Vec<String> = json(&ls)["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["slug"].as_str().unwrap().to_owned())
        .collect();
    slugs.sort();
    assert_eq!(
        slugs,
        [
            "database-url/acme-web",
            "github/acme-web",
            "openai/acme-web",
            "short-token/acme-web-short",
            "stripe/acme-web",
        ]
    );
    let show = run_in(&s.home, &repo, &["show", "openai/acme-web"]);
    assert!(ok(&show, &s.cs).contains("openai"));

    // Run again: nothing new, and the files it wrote are as they were.
    let out = run_in(&s.home, &repo, &["init", "--import", "--yes", "--json"]);
    ok(&out, &s.cs);
    let p = &json(&out)["import"]["projects"][0];
    assert_eq!(p["manifest"], "unchanged");
    assert_eq!(p["gitignore"], "unchanged");
    assert_eq!(
        std::fs::read_to_string(repo.join(".gitignore")).unwrap(),
        gitignore
    );
    assert_eq!(
        std::fs::read_to_string(repo.join("envcloak.toml")).unwrap(),
        manifest
    );
    let ls = run_in(&s.home, &repo, &["ls", "--json"]);
    assert_eq!(json(&ls)["items"].as_array().unwrap().len(), 5);

    // The deletion waits for the Recovery Kit.
    let out = run_in(&s.home, &repo, &["init", "--delete-plaintext"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).starts_with("envcloak: recovery_kit_unconfirmed:"),
        "{}",
        stderr(&out)
    );
    assert_no_canary(&out.stdout, &s.cs);
    for (name, body) in &files {
        assert_eq!(&std::fs::read(repo.join(name)).unwrap(), body);
    }
    let out = person_in(
        &s.home,
        &repo,
        &["recovery", "confirm", "--kit-fd", "4"],
        &[(4, &s.kit, true)],
    );
    assert!(ok(&out, &s.cs).contains("Recovery Kit confirmed"));

    // Now it deletes, after an encrypted backup.
    let out = run_in(&s.home, &repo, &["init", "--delete-plaintext", "--json"]);
    ok(&out, &s.cs);
    let d = &json(&out)["delete"];
    let mut removed: Vec<&str> = d["removed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect();
    removed.sort_unstable();
    assert_eq!(removed, [".env", ".env.short"]);
    let backup = d["backup"].as_str().unwrap().to_owned();
    assert_eq!(backup.len(), 26);
    assert!(!repo.join(".env").exists());
    assert!(!repo.join(".env.short").exists());
    assert!(repo.join(".env.example").exists());
    // PORT went with the file, and the report says so.
    let port = d["verify"]["files"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|f| f["entries"].as_array().unwrap())
        .find(|e| e["name"] == "PORT")
        .unwrap();
    assert_eq!(port["status"], "left_out");
    assert_eq!(port["skipped"], "too_short");
    // The template holds a key's shape on purpose, which `check` reports
    // as it should; it was never read for its values.
    std::fs::remove_file(repo.join(".env.example")).unwrap();
    ok(&run_in(&s.home, &repo, &["check"]), &s.cs);
    let backups = data_dir(&s.home).join("backups");
    let names: Vec<String> = std::fs::read_dir(&backups)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        names
            .iter()
            .any(|n| n.ends_with(&format!("-{backup}.ecfiles"))),
        "{names:?}"
    );
    // Everything EnvCloak wrote is ciphertext or metadata.
    s.sweep();
    let files = &files[..2];

    // The undo is a proof, and puts back the files byte for byte.
    let mut cmd = cli_command(
        &s.home,
        &["init", "--undo", &backup, "--passphrase-fd", "3"],
        &[(3, &s.pass, true)],
    );
    cmd.current_dir(&repo);
    let out = finish_within(cmd, Duration::from_secs(120));
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("proof_refused"), "{}", stderr(&out));
    assert!(!repo.join(".env").exists());
    let out = person_in(
        &s.home,
        &repo,
        &["init", "--undo", &backup, "--passphrase-fd", "3", "--json"],
        &[(3, &s.pass, true)],
    );
    ok(&out, &s.cs);
    for (name, body) in files {
        assert_eq!(&std::fs::read(repo.join(name)).unwrap(), body, "{name}");
    }
    let mode = std::fs::metadata(repo.join(".env")).unwrap().mode() & 0o777;
    assert_eq!(mode & !0o644, 0);
    // A second undo writes nothing over the files.
    let out = person_in(
        &s.home,
        &repo,
        &["init", "--undo", &backup, "--passphrase-fd", "3", "--json"],
        &[(3, &s.pass, true)],
    );
    ok(&out, &s.cs);
    let undone = json(&out);
    let states: Vec<&str> = undone["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["state"].as_str().unwrap())
        .collect();
    assert_eq!(states, ["unchanged", "unchanged"]);
    // The plaintext is back where the person asked for it; take it away
    // before the last sweep.
    for (name, _) in files {
        std::fs::remove_file(repo.join(name)).unwrap();
    }
    s.sweep();
}

/// One value in two repos is one item both reference; the dry run
/// writes nothing and is value-free as text and JSON.
#[test]
fn import_scan_dedups_across_repos_and_its_dry_run_is_value_free() {
    let s = Story::new();
    let root = s.home.root().join("dev");
    let key = by_label(&s.cs, labels::OPENAI_API_KEY).as_str();
    for repo in ["repo-a", "repo-b"] {
        std::fs::create_dir_all(root.join(repo)).unwrap();
        std::fs::write(
            root.join(repo).join(".env"),
            format!("OPENAI_API_KEY={key}\n"),
        )
        .unwrap();
    }
    // Skipped: dependency directories.
    std::fs::create_dir_all(root.join("repo-a/node_modules/pkg")).unwrap();
    std::fs::write(
        root.join("repo-a/node_modules/pkg/.env"),
        format!("OPENAI_API_KEY={key}\n"),
    )
    .unwrap();
    let dir = root.to_str().unwrap();
    for args in [
        &["import", "--scan", dir][..],
        &["import", "--scan", dir, "--json"],
    ] {
        let out = run_in(&s.home, &s.home.home(), args);
        ok(&out, &s.cs);
    }
    assert!(!root.join("repo-a/envcloak.toml").exists());
    let out = run_in(
        &s.home,
        &s.home.home(),
        &["import", "--scan", dir, "--yes", "--json"],
    );
    ok(&out, &s.cs);
    let r = json(&out);
    let items = r["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{r}");
    assert_eq!(items[0]["slug"], "openai/repo-a");
    assert_eq!(items[0]["projects"], 2);
    assert_eq!(items[0]["entries"], 2);
    assert_eq!(r["projects"].as_array().unwrap().len(), 2);
    for repo in ["repo-a", "repo-b"] {
        let m = std::fs::read_to_string(root.join(repo).join("envcloak.toml")).unwrap();
        assert!(m.contains("OPENAI_API_KEY = \"openai/repo-a\""), "{m}");
        assert!(root.join(repo).join(".gitignore").exists());
    }
    assert!(!root.join("repo-a/node_modules/pkg/envcloak.toml").exists());
    let ls = run_in(&s.home, &s.home.home(), &["ls", "--json"]);
    assert_eq!(json(&ls)["items"].as_array().unwrap().len(), 1);
    // The env files hold plaintext on purpose.
    for repo in ["repo-a", "repo-b", "repo-a/node_modules/pkg"] {
        std::fs::remove_file(root.join(repo).join(".env")).unwrap();
    }
    s.sweep();
}

/// An existing `.gitignore` that covers the files is left as it is; one
/// that does not gets the lines once, and a manifest binding to another
/// item is kept and reported.
#[test]
fn gitignore_and_manifest_edits_keep_what_is_there() {
    let s = Story::new();
    let (repo, _) = acme_web(&s.home, &s.cs);
    std::fs::write(repo.join(".gitignore"), "target/\n.env*\n!.env.example\n").unwrap();
    std::fs::write(
        repo.join("envcloak.toml"),
        "# mine\n[project]\nname = \"acme-web\"\n\n[env]\nOPENAI_API_KEY = \"openai/elsewhere\" # kept\n",
    )
    .unwrap();
    let out = run_in(&s.home, &repo, &["init", "--import", "--yes", "--json"]);
    ok(&out, &s.cs);
    let p = &json(&out)["import"]["projects"][0];
    assert_eq!(p["gitignore"], "unchanged");
    assert_eq!(p["manifest"], "updated");
    assert_eq!(p["conflicts"][0], "OPENAI_API_KEY");
    assert_eq!(
        std::fs::read_to_string(repo.join(".gitignore")).unwrap(),
        "target/\n.env*\n!.env.example\n"
    );
    let m = std::fs::read_to_string(repo.join("envcloak.toml")).unwrap();
    assert!(m.starts_with("# mine\n"), "{m}");
    assert!(
        m.contains("OPENAI_API_KEY = \"openai/elsewhere\" # kept"),
        "{m}"
    );
    assert!(m.contains("STRIPE_SECRET_KEY = \"stripe/acme-web\""), "{m}");
    // The binding to another item keeps the file from being deleted.
    let key = s.home.root().join("confirm-kit");
    std::fs::copy(&s.kit, &key).unwrap();
    let out = person_in(
        &s.home,
        &repo,
        &["recovery", "confirm", "--kit-fd", "4"],
        &[(4, &key, true)],
    );
    ok(&out, &s.cs);
    std::fs::remove_file(&key).unwrap();
    let out = run_in(&s.home, &repo, &["init", "--delete-plaintext"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("unresolved_reference") || stderr(&out).contains("not_imported"),
        "{}",
        stderr(&out)
    );
    assert!(repo.join(".env").exists());
    for f in [".env", ".env.short", ".env.example"] {
        std::fs::remove_file(repo.join(f)).unwrap();
    }
    s.sweep();
}

/// Snapshot of what must not change: bytes (a symlink's target; nothing
/// of a FIFO or a large file), size, mode, links and modification time.
fn snapshot(p: &Path) -> (Vec<u8>, u64, u32, u64, i64) {
    let m = std::fs::symlink_metadata(p).unwrap();
    let bytes = if m.file_type().is_symlink() {
        std::fs::read_link(p)
            .unwrap()
            .into_os_string()
            .into_encoded_bytes()
    } else if m.file_type().is_file() && m.len() <= 1 << 20 && m.mode() & 0o400 != 0 {
        std::fs::read(p).unwrap()
    } else {
        Vec::new()
    };
    (bytes, m.len(), m.mode(), m.nlink(), m.mtime())
}

/// Gate 15 through `import` and `init`: nothing hangs, nothing outside
/// the root is followed, nothing is modified or deleted, and no value is
/// in the report.
#[test]
fn gate_15_hostile_files_through_the_commands() {
    let s = Story::new();
    let root = s.home.root().join("hostile");
    let outside = s.home.root().join("outside");
    std::fs::create_dir_all(root.join("loop")).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    let key = by_label(&s.cs, labels::OPENAI_API_KEY).as_str();
    let token = by_label(&s.cs, labels::GITHUB_TOKEN).as_str();
    std::fs::write(outside.join("real.env"), format!("OPENAI_API_KEY={key}\n")).unwrap();
    symlink(outside.join("real.env"), root.join(".env")).unwrap();
    assert!(
        Command::new("/usr/bin/mkfifo")
            .arg(root.join(".env.fifo"))
            .status()
            .unwrap()
            .success()
    );
    File::create(root.join(".env.big"))
        .unwrap()
        .set_len(2 * 1024 * 1024 * 1024)
        .unwrap();
    symlink("..", root.join("loop/self")).unwrap();
    std::fs::write(
        outside.join("linked.env"),
        format!("GITHUB_TOKEN={token}\n"),
    )
    .unwrap();
    std::fs::hard_link(outside.join("linked.env"), root.join(".env.linked")).unwrap();
    std::fs::write(root.join(".env.locked"), format!("OPENAI_API_KEY={key}\n")).unwrap();
    std::fs::set_permissions(
        root.join(".env.locked"),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    for p in [outside.join("real.env"), outside.join("linked.env")] {
        age(&p, Duration::from_secs(600));
    }
    let watched: Vec<PathBuf> = [
        ".env",
        ".env.fifo",
        ".env.big",
        "loop/self",
        ".env.linked",
        ".env.locked",
    ]
    .iter()
    .map(|n| root.join(n))
    .chain([outside.join("real.env"), outside.join("linked.env")])
    .collect();
    let before: Vec<_> = watched.iter().map(|p| snapshot(p)).collect();
    let dir = root.to_str().unwrap();
    let key = s.home.root().join("confirm-kit");
    std::fs::copy(&s.kit, &key).unwrap();
    let out = person_in(
        &s.home,
        &root,
        &["recovery", "confirm", "--kit-fd", "4"],
        &[(4, &key, true)],
    );
    ok(&out, &s.cs);
    std::fs::remove_file(&key).unwrap();
    for (cwd, args) in [
        (s.home.home(), &["import", "--scan", dir, "--json"][..]),
        (s.home.home(), &["import", "--scan", dir, "--yes"]),
        (
            root.clone(),
            &["init", "--import", "--yes", "--delete-plaintext", "--json"],
        ),
        (root.clone(), &["init", "--delete-plaintext"]),
    ] {
        // finish_within fails the test if a command hangs.
        let out = run_in(&s.home, &cwd, args);
        assert_no_canary(&out.stdout, &s.cs);
        assert_no_canary(&out.stderr, &s.cs);
        assert!(
            matches!(out.status.code(), Some(0 | 1)),
            "{args:?}: {}",
            stderr(&out)
        );
    }
    let out = run_in(
        &s.home,
        &s.home.home(),
        &["import", "--scan", dir, "--json"],
    );
    let r = json(&out);
    let mut skipped: Vec<(String, String)> = r["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["path"].as_str().unwrap().to_owned(),
                x["reason"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    skipped.sort();
    let mut want = vec![
        (".env".to_owned(), "symlink".to_owned()),
        (".env.big".to_owned(), "too_large".to_owned()),
        (".env.fifo".to_owned(), "not_regular".to_owned()),
    ];
    if envcloak_sys::effective_uid() != 0 {
        want.push((".env.locked".to_owned(), "unreadable".to_owned()));
    }
    assert_eq!(skipped, want);
    let after: Vec<_> = watched.iter().map(|p| snapshot(p)).collect();
    assert_eq!(before, after, "a command changed a file it must not touch");
    // The hard-linked file was imported (it is this user's), never deleted.
    assert!(root.join(".env.linked").exists());
    for p in [
        outside.join("real.env"),
        outside.join("linked.env"),
        root.join(".env.linked"),
    ] {
        std::fs::remove_file(p).unwrap();
    }
    std::fs::remove_file(root.join(".env.locked")).unwrap();
    s.sweep();
}

/// A seeded vault whose Recovery Kit is confirmed, behind an unlocked
/// daemon, and the project `acme-web`: gate 16's fixture.
struct Gate16 {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    repo: PathBuf,
    files: Vec<(&'static str, Vec<u8>)>,
    _dir: tempfile::TempDir,
}

impl Gate16 {
    fn new(confirm_kit: bool) -> Self {
        let cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = RecoveryKit::generate();
        let paths = VaultPaths::under(data_dir(&home));
        let pass = SecretBytes::copy_from(by_label(&cs, labels::VAULT_PASSPHRASE).value());
        let mut v = create_vault_with_kit(&paths, &pass, &kit, KdfParams::minimum()).unwrap();
        if confirm_kit {
            v.confirm_recovery_kit(&kit).unwrap();
        }
        // An item the import will not make, for a manifest to bind.
        v.transact(|t| {
            let id = t.create_item(NewItem {
                class: ItemClass::Secret,
                slug: Slug::new("other/item").unwrap(),
                details: ItemDetails::default(),
            })?;
            t.add_field(
                id,
                FieldName::new("value").unwrap(),
                SecretBytes::copy_from(b"a value no file holds, long enough"),
            )?;
            Ok(())
        })
        .unwrap();
        drop(v);
        let mut cs = cs;
        cs.push(Canary::new("RECOVERY_KIT", kit.to_display().to_string()));
        let d = start_daemon(&home);
        let dir = outside_dir();
        let pass = secret_file(
            dir.path(),
            "pass",
            by_label(&cs, labels::VAULT_PASSPHRASE).value(),
        );
        let out = finish_within(
            on_terminal_command(
                &home,
                &["unlock", "--passphrase-fd", "3"],
                &[(3, &pass, true)],
            ),
            Duration::from_secs(120),
        );
        assert!(out.status.success(), "{}{}", stderr(&out), d.log());
        let (repo, mut files) = acme_web(&home, &cs);
        // The template stays: gate 16 is about the files that hold values.
        files.retain(|(n, _)| *n != ".env.example");
        Gate16 {
            cs,
            home,
            d,
            repo,
            files,
            _dir: dir,
        }
    }

    fn present(&self) -> Vec<bool> {
        self.files
            .iter()
            .map(|(n, _)| self.repo.join(n).exists())
            .collect()
    }

    fn delete(&self) -> Output {
        run_in(&self.home, &self.repo, &["init", "--delete-plaintext"])
    }

    fn cleanup(&self) {
        for (n, _) in &self.files {
            let _ = std::fs::remove_file(self.repo.join(n));
        }
        let _ = std::fs::remove_file(self.repo.join(".env.example"));
    }
}

/// Gate 16: each condition, failing alone, refuses the deletion, and
/// nothing is deleted; with all four, the files go.
#[test]
fn gate_16_each_condition_refuses_the_deletion_alone() {
    // 1. Not imported: the manifest exists, the values are not in the
    //    vault.
    let g = Gate16::new(true);
    ok(&run_in(&g.home, &g.repo, &["init"]), &g.cs);
    let out = g.delete();
    assert!(
        stderr(&out).starts_with("envcloak: not_imported:"),
        "{}",
        stderr(&out)
    );
    assert_eq!(g.present(), [true, true]);
    assert_no_canary(&out.stdout, &g.cs);

    // 2. A reference that does not resolve.
    ok(
        &run_in(&g.home, &g.repo, &["init", "--import", "--yes"]),
        &g.cs,
    );
    let manifest = g.repo.join("envcloak.toml");
    let good = std::fs::read_to_string(&manifest).unwrap();
    std::fs::write(
        &manifest,
        format!("{good}\n[env.extra]\nGONE = \"no/such-item\"\n"),
    )
    .unwrap();
    let out = g.delete();
    assert!(
        stderr(&out).starts_with("envcloak: unresolved_reference:"),
        "{}",
        stderr(&out)
    );
    assert_eq!(g.present(), [true, true]);
    std::fs::write(&manifest, &good).unwrap();

    // 3. No encrypted backup: a file stands where the backups directory
    //    goes, so none can be written.
    let backups = data_dir(&g.home).join("backups");
    let _ = std::fs::remove_dir(&backups);
    std::fs::write(&backups, b"not a directory").unwrap();
    let out = g.delete();
    std::fs::remove_file(&backups).unwrap();
    assert!(
        stderr(&out).starts_with("envcloak: files_backup_failed:"),
        "{}",
        stderr(&out)
    );
    assert_eq!(g.present(), [true, true]);

    // With the three that hold, the files go (the kit was confirmed).
    let out = g.delete();
    ok(&out, &g.cs);
    assert_eq!(g.present(), [false, false]);
    g.cleanup();
    assert_no_canary(&g.d.log_bytes(), &g.cs);
    g.home.assert_clean(&g.cs);

    // 4. The Recovery Kit unconfirmed.
    let g = Gate16::new(false);
    ok(
        &run_in(&g.home, &g.repo, &["init", "--import", "--yes"]),
        &g.cs,
    );
    let out = g.delete();
    assert!(
        stderr(&out).starts_with("envcloak: recovery_kit_unconfirmed:"),
        "{}",
        stderr(&out)
    );
    assert_eq!(g.present(), [true, true]);
    // And a file changed in the last two minutes is kept.
    let kit = g.home.root().join("kit");
    std::fs::write(
        &kit,
        format!("{}\n", by_label(&g.cs, "RECOVERY_KIT").as_str()),
    )
    .unwrap();
    ok(
        &person_in(
            &g.home,
            &g.repo,
            &["recovery", "confirm", "--kit-fd", "4"],
            &[(4, &kit, true)],
        ),
        &g.cs,
    );
    std::fs::remove_file(&kit).unwrap();
    std::fs::write(g.repo.join(".env.short"), &g.files[1].1).unwrap();
    let out = g.delete();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).starts_with("envcloak: not_deleted:"),
        "{}",
        stderr(&out)
    );
    assert!(
        stdout(&out).contains("modified in the last 2 minutes"),
        "{}",
        stdout(&out)
    );
    assert_eq!(g.present(), [false, true]);
    g.cleanup();
    assert_no_canary(&g.d.log_bytes(), &g.cs);
    g.home.assert_clean(&g.cs);
}

/// The environment variable that makes [`gate_16_kill_child`] run.
const KILL_CHILD: &str = "ENVCLOAK_T13_KILL_REPO";

/// The steps the child passes, in order.
const STEPS: [&str; 9] = [
    "start",
    "planned",
    "committed",
    "manifest",
    "verified",
    "backed_up",
    "reverified",
    "removed_0",
    "removed_1",
];

/// The prefix of a step's line. The test harness prints the test's name
/// before its output, on the same line, so the line starts afresh.
const STEP: &str = "ENVCLOAK-STEP ";

/// Says `step` on standard output and waits for a line on standard input:
/// the parent kills this process at the step it chose.
fn at_step(step: &str) {
    println!("\n{STEP}{step}");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).unwrap();
}

/// The delete gate as `envcloak init` answers it, through the daemon.
struct ChildGate<'a> {
    client: &'a mut Client,
    root: &'a envcloak_scan::ScanRoot,
    manifest: String,
    files: Vec<(PathBuf, FileStamp, SecretBytes)>,
}

impl DeleteGate for ChildGate<'_> {
    type Refusal = String;

    fn verify(&mut self) -> Result<(), String> {
        let p = VerifyParams {
            manifest: self.manifest.clone(),
            files: self
                .files
                .iter()
                .map(|(rel, _, bytes)| VerifyFile {
                    file: rel.to_string_lossy().into_owned(),
                    profile: (rel.to_str() == Some(".env.short")).then(|| "short".to_owned()),
                    entries: parse_dotenv(bytes)
                        .unwrap()
                        .into_iter()
                        .filter(|e| e.kind == EntryKind::Plain)
                        .map(|e| VerifyEntry {
                            line: e.line,
                            name: e.name.as_str().to_owned(),
                            value: WireSecret::new(e.value),
                        })
                        .collect(),
                })
                .collect(),
        };
        let v = self.client.import_verify(&p).map_err(|e| e.to_string())?;
        if v.deletable() {
            Ok(())
        } else {
            Err("refused".into())
        }
    }

    fn backup(&mut self) -> Result<String, String> {
        let mut files = Vec::new();
        for (rel, stamp, _) in &self.files {
            let (bytes, now) =
                read_capped(self.root, rel, MAX_DOTENV).map_err(|e| e.to_string())?;
            assert_eq!(now, *stamp);
            files.push(BackupFileParams {
                path: self.root.path().join(rel).to_string_lossy().into_owned(),
                mode: 0o600,
                content: WireSecret::new(bytes),
            });
        }
        self.client
            .files_backup(&FilesBackupParams {
                files,
                claims: Vec::new(),
            })
            .map(|v| v.id)
            .map_err(|e| e.to_string())
    }
}

/// Gate 16's child: the whole of `init --import --yes --delete-plaintext`
/// through the library and the daemon, stopping at each step until the
/// parent says to go on. Does nothing unless the parent started it.
#[test]
fn gate_16_kill_child() {
    let Some(repo) = std::env::var_os(KILL_CHILD) else {
        return;
    };
    let root = open_root(Path::new(&repo)).unwrap();
    let paths = RunPaths::for_user().unwrap();
    let mut client = Client::connect(&paths).unwrap();
    at_step("start");
    let names = [".env", ".env.short"];
    let mut files = Vec::new();
    for n in names {
        let (bytes, stamp) = read_capped(&root, Path::new(n), MAX_DOTENV).unwrap();
        files.push((PathBuf::from(n), stamp, bytes));
    }
    let params = || {
        let mut entries = Vec::new();
        for (rel, _, bytes) in &files {
            let profile = (rel.to_str() == Some(".env.short")).then(|| "short".to_owned());
            for e in parse_dotenv(bytes).unwrap() {
                entries.push(envcloak_ipc::proto::ImportEntry {
                    project: 0,
                    file: rel.to_string_lossy().into_owned(),
                    line: e.line,
                    profile: profile.clone(),
                    name: e.name.as_str().to_owned(),
                    value: WireSecret::new(e.value),
                });
            }
        }
        envcloak_ipc::proto::ImportParams {
            projects: vec![envcloak_ipc::proto::ImportProject {
                dir: root.path().to_string_lossy().into_owned(),
                name: "acme-web".into(),
            }],
            entries,
            claims: Vec::new(),
        }
    };
    let plan = client.import_plan(&params()).unwrap();
    at_step("planned");
    let done = client
        .import_commit(&ImportCommitParams {
            import: params(),
            digest: plan.digest,
        })
        .unwrap();
    at_step("committed");
    // The manifest, as `init` writes it: each entry's reference.
    let mut env = String::from("[env]\n");
    let mut short = String::from("\n[env.short]\n");
    let mut i = 0;
    for (rel, _, bytes) in &files {
        for e in parse_dotenv(bytes).unwrap() {
            if let Some(at) = done.entries[i].item {
                let line = format!("{} = \"{}\"\n", e.name, done.items[at as usize].reference);
                if rel.to_str() == Some(".env.short") {
                    short.push_str(&line);
                } else {
                    env.push_str(&line);
                }
            }
            i += 1;
        }
    }
    std::fs::write(root.path().join("envcloak.toml"), env + &short).unwrap();
    at_step("manifest");
    let stamps: Vec<(PathBuf, FileStamp)> = files.iter().map(|(p, s, _)| (p.clone(), *s)).collect();
    // The gate reads the files again, as `init` does.
    let mut gate = ChildGate {
        client: &mut client,
        root: &root,
        manifest: root
            .path()
            .join("envcloak.toml")
            .to_string_lossy()
            .into_owned(),
        files: files
            .iter()
            .map(|(p, s, _)| {
                let (bytes, now) = read_capped(&root, p, MAX_DOTENV).unwrap();
                assert_eq!(now, *s);
                (p.clone(), now, bytes)
            })
            .collect(),
    };
    let out = delete_plaintext(&root, &stamps, &mut gate, &mut |s| {
        at_step(match s {
            DeleteStep::Verified => "verified",
            DeleteStep::BackedUp => "backed_up",
            DeleteStep::Reverified => "reverified",
            DeleteStep::Removed(0) => "removed_0",
            DeleteStep::Removed(_) => "removed_1",
        });
    })
    .unwrap();
    assert!(out.kept.is_empty(), "{:?}", out.kept);
    println!("\n{STEP}done");
}

/// After a kill: each file is there as it was, or its values are
/// committed where the manifest binds them.
fn file_or_item(g: &Gate16) {
    let manifest = g.repo.join("envcloak.toml");
    let mut c =
        Client::connect(&RunPaths::under(envcloak_testkit::daemon_run_dir(&g.home)).unwrap())
            .unwrap();
    for (name, body) in &g.files {
        let path = g.repo.join(name);
        if path.exists() {
            assert_eq!(&std::fs::read(&path).unwrap(), body, "{name} changed");
            continue;
        }
        assert!(
            manifest.exists(),
            "{name} is gone, and no manifest binds its values"
        );
        let entries = parse_dotenv(&SecretBytes::copy_from(body))
            .unwrap()
            .into_iter()
            .map(|e| VerifyEntry {
                line: e.line,
                name: e.name.as_str().to_owned(),
                value: WireSecret::new(e.value),
            })
            .collect();
        let v = c
            .import_verify(&VerifyParams {
                manifest: manifest.to_str().unwrap().to_owned(),
                files: vec![VerifyFile {
                    file: (*name).to_owned(),
                    profile: (*name == ".env.short").then(|| "short".to_owned()),
                    entries,
                }],
            })
            .unwrap();
        assert!(
            v.files[0].covered,
            "{name} is gone and its values are not all committed"
        );
        assert!(
            v.files[0]
                .entries
                .iter()
                .any(|e| e.status == EntryStatus::Stored),
            "{name}"
        );
    }
}

/// Gate 16: `kill -9` at every step of `init --import --yes
/// --delete-plaintext` leaves either the plaintext file or the committed
/// item. The child ([`gate_16_kill_child`]) is this test binary, stopping
/// at each step until told to go on; the parent kills it at one step per
/// run, then checks every file.
#[test]
fn gate_16_kill_9_at_every_step_leaves_the_file_or_the_item() {
    for (k, step) in STEPS.iter().enumerate() {
        let g = Gate16::new(true);
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        g.home
            .apply(&mut cmd)
            .env(KILL_CHILD, &g.repo)
            .args([
                "--exact",
                "gate_16_kill_child",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let mut seen = Vec::new();
        let reached = loop {
            let mut line = String::new();
            if out.read_line(&mut line).unwrap() == 0 {
                break false;
            }
            let Some(s) = line.trim_end().strip_prefix(STEP) else {
                continue;
            };
            seen.push(s.to_owned());
            if s == *step {
                break true;
            }
            stdin.write_all(b"\n").unwrap();
        };
        // SIGKILL, at the step.
        let _ = child.kill();
        child.wait().unwrap();
        assert!(reached, "the child ended before {step}; it passed {seen:?}");
        assert_eq!(seen, STEPS[..=k], "the steps came out of order");
        file_or_item(&g);
        // Nothing is removed before the gate has verified twice.
        if k < STEPS.iter().position(|s| *s == "removed_0").unwrap() {
            assert_eq!(g.present(), [true, true], "killed at {step}");
        }
        g.cleanup();
        assert_no_canary(&g.d.log_bytes(), &g.cs);
        g.home.assert_clean(&g.cs);
    }
}
