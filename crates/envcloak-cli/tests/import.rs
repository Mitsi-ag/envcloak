//! `envcloak init`, `envcloak import --scan` and `envcloak recovery
//! confirm` (SPEC §6.4; T13), with a real daemon:
//! - story steps S2 and S3: a dry run first, then the import with
//!   providers detected, `envcloak.toml` and `.gitignore` written, the
//!   delete refused until the Recovery Kit is confirmed, then the imported
//!   entries taken out of the files after an encrypted backup (a file with
//!   entries that are not imported is rewritten to hold them), metadata-only
//!   `ls`, `show` and `check`, and `init --undo` putting the files back
//!   byte for byte;
//! - `.gitignore` edits are idempotent, and template files contribute
//!   names only;
//! - one value in two repos becomes one item both reference, found by
//!   keyed hash in the daemon;
//! - gate 15 through the commands: a symlinked `.env` outside the root, a
//!   FIFO, a 2 GB file, a directory symlink loop, a hard link and an
//!   unreadable file: no hang, nothing followed or modified, no value in
//!   the report;
//! - gate 16: each of the four conditions refuses the deletion on its
//!   own, and `kill -9` of `envcloak init --import --yes
//!   --delete-plaintext` at every step (inside each file's change too)
//!   leaves every entry of every file in its file or committed in the
//!   vault where the manifest binds it. The fixture holds entries that are
//!   not imported: configuration, an interpolated value with a literal
//!   password in it (`${...}` and `$NAME`), a reference, and a secret the
//!   daemon cannot tell from configuration.
//!
//! Every command's output, the daemon's log and the home are swept for
//! the canaries.
#![allow(clippy::unwrap_used)]

mod common;

use std::fs::File;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime};

use common::{
    cli_command, daemon_exe, data_dir, finish_within, on_terminal_command, outside_dir,
    secret_file, start_daemon, stderr, stdout,
};
use envcloak_core::crypto::{ItemClass, KdfParams};
use envcloak_core::vault::{FieldName, ItemDetails, NewItem, Slug, VaultPaths};
use envcloak_core::{RecoveryKit, SecretBytes, create_vault_with_kit};
use envcloak_ipc::proto::{
    BackupFileParams, FileLeft, FilesBackupParams, VerifyEntry, VerifyFile, VerifyParams,
};
use envcloak_ipc::view::EntryStatus;
use envcloak_ipc::{Client, RunPaths, WireSecret};
use envcloak_scan::{EntryKind, parse_dotenv, trimmed_from};
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
/// runs it, with `fds` opened.
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

/// `n` random lowercase letters and digits, generated here.
fn word(n: usize) -> String {
    let mut out = String::new();
    while out.len() < n {
        let seed = fresh_seed();
        for i in 0..10 {
            let k = usize::try_from((seed >> (i * 6)) % 36).unwrap();
            out.push(char::from(b"abcdefghijklmnopqrstuvwxyz0123456789"[k]));
        }
    }
    out.truncate(n);
    out
}

/// The fixture's values that stay in `.env`: a password inside an
/// interpolated URL (`${...}`), another inside one written `$NAME`, and a
/// 14-character secret whose name says nothing of a secret, which the
/// daemon takes for configuration.
const REPLICA_PASSWORD: &str = "REPLICA_PASSWORD";
const QUEUE_PASSWORD: &str = "QUEUE_PASSWORD";
const APP_SEED: &str = "APP_SEED";

fn with_kept_values(mut cs: Vec<Canary>) -> Vec<Canary> {
    cs.push(Canary::new(REPLICA_PASSWORD, word(16)));
    cs.push(Canary::new(QUEUE_PASSWORD, word(16)));
    cs.push(Canary::new(APP_SEED, word(14)));
    cs
}

/// The story's fixture repo `acme-web` (SPEC §15.1): `.env`, `.env.short`
/// and `.env.example`. Returns the directory and the files' bytes.
fn acme_web(home: &TestHome, cs: &[Canary]) -> (PathBuf, Vec<(&'static str, Vec<u8>)>) {
    let dir = home.root().join("acme-web");
    std::fs::create_dir_all(&dir).unwrap();
    let v = |l| by_label(cs, l).as_str();
    let env = format!(
        "# acme-web\nOPENAI_API_KEY={}\nexport STRIPE_SECRET_KEY={}\nGITHUB_TOKEN='{}'\n\
         DATABASE_URL={}\nPORT=8080\nREPLICA_URL=\"postgres://app:{}@${{DB_HOST}}/app\"\n\
         QUEUE_URL=amqp://app:{}@$MQ_HOST/jobs\nLEGACY_KEY=envcloak://openai/acme-web\n\
         APP_SEED={}\n",
        v(labels::OPENAI_API_KEY),
        v(labels::STRIPE_SECRET_KEY),
        v(labels::GITHUB_TOKEN),
        dq(v(labels::DATABASE_URL)),
        v(REPLICA_PASSWORD),
        v(QUEUE_PASSWORD),
        v(APP_SEED),
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

/// What the deletion leaves of the fixture's `.env`: every line but the
/// four imported entries'.
fn env_left(body: &[u8]) -> Vec<u8> {
    let imported = [
        "OPENAI_API_KEY=",
        "export STRIPE_SECRET_KEY=",
        "GITHUB_TOKEN=",
        "DATABASE_URL=",
    ];
    body.split_inclusive(|&b| b == b'\n')
        .filter(|l| !imported.iter().any(|p| l.starts_with(p.as_bytes())))
        .flatten()
        .copied()
        .collect()
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

fn strings(v: &serde_json::Value) -> Vec<String> {
    let mut out: Vec<String> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_owned())
        .collect();
    out.sort();
    out
}

/// Whether git ignores `name` in `dir` by `dir`'s `.gitignore`: `git
/// check-ignore` in a repository there (made if there is none), with no
/// global or system configuration and no excludes file.
fn git_ignores(dir: &Path, name: &str) -> bool {
    let git = |args: &[&str]| {
        Command::new("git")
            .args(["-c", "core.excludesFile=/dev/null"])
            .args(args)
            .current_dir(dir)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap()
    };
    if !dir.join(".git").exists() {
        assert!(git(&["init", "-q"]).status.success());
    }
    let out = git(&["check-ignore", "-q", "--no-index", "--", name]);
    match out.status.code() {
        Some(0) => true,
        Some(1) => false,
        _ => panic!("git check-ignore: {}", stderr(&out)),
    }
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
        let cs = with_kept_values(canaries(fresh_seed()));
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

    // A dry run writes nothing and imports nothing. (The person imports:
    // `SHORT_TOKEN`, short enough to guess, is imported only for them.)
    let out = person_in(&s.home, &repo, &["init", "--import"], &[]);
    let text = ok(&out, &s.cs);
    assert!(text.contains("dry run"), "{text}");
    assert!(text.contains("openai/acme-web"), "{text}");
    assert!(!repo.join("envcloak.toml").exists());
    assert!(!repo.join(".gitignore").exists());
    let ls = run_in(&s.home, &repo, &["ls", "--json"]);
    assert_eq!(json(&ls)["items"].as_array().unwrap().len(), 0);

    // S2: the import.
    let out = person_in(
        &s.home,
        &repo,
        &["init", "--import", "--yes", "--json"],
        &[],
    );
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
    // A crash while a file changes leaves it under a temporary name, which
    // stays out of git too.
    assert!(
        gitignore.lines().any(|l| l == ".*.envcloak-*.tmp"),
        "{gitignore}"
    );
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
    let out = person_in(
        &s.home,
        &repo,
        &["init", "--import", "--yes", "--json"],
        &[],
    );
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
    let out = person_in(&s.home, &repo, &["init", "--delete-plaintext"], &[]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).starts_with("envcloak: recovery_kit_unconfirmed:"),
        "{}",
        stderr(&out)
    );
    assert_no_canary(&out.stdout, &s.cs);
    for (name, body) in &files {
        assert!(
            std::fs::read(repo.join(name)).unwrap() == *body,
            "{name} is not its original"
        );
    }
    let out = person_in(
        &s.home,
        &repo,
        &["recovery", "confirm", "--kit-fd", "4"],
        &[(4, &s.kit, true)],
    );
    assert!(ok(&out, &s.cs).contains("Recovery Kit confirmed"));

    // Now it deletes, after an encrypted backup: the imported entries
    // leave; `.env` keeps the ones that were not imported, as they were.
    let out = person_in(
        &s.home,
        &repo,
        &["init", "--delete-plaintext", "--json"],
        &[],
    );
    ok(&out, &s.cs);
    let d = &json(&out)["delete"];
    assert_eq!(strings(&d["removed"]), [".env.short"]);
    assert_eq!(strings(&d["rewritten"]), [".env"]);
    assert_eq!(strings(&d["unchanged"]), Vec::<String>::new());
    let backup = d["backup"].as_str().unwrap().to_owned();
    assert_eq!(backup.len(), 26);
    assert_eq!(
        std::fs::read(repo.join(".env")).unwrap(),
        env_left(&files[0].1)
    );
    assert!(!repo.join(".env.short").exists());
    assert!(repo.join(".env.example").exists());
    // The report names each entry that stays, and why.
    let left: Vec<(String, String)> = d["verify"]["files"][0]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["status"] == "left_out")
        .map(|e| {
            (
                e["name"].as_str().unwrap().to_owned(),
                e["skipped"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        left,
        [
            ("PORT".to_owned(), "too_short".to_owned()),
            ("REPLICA_URL".to_owned(), "interpolated".to_owned()),
            ("QUEUE_URL".to_owned(), "interpolated".to_owned()),
            ("LEGACY_KEY".to_owned(), "reference".to_owned()),
            ("APP_SEED".to_owned(), "not_secret".to_owned()),
        ]
    );
    // The template holds a key's shape on purpose, which `check` reports
    // as it should; it was never read for its values. What `.env` keeps
    // holds no key's shape, and its reference resolves.
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
    // Everything EnvCloak wrote is ciphertext or metadata; `.env` still
    // holds what was not imported, on purpose.
    let kept_env = std::fs::read(repo.join(".env")).unwrap();
    std::fs::remove_file(repo.join(".env")).unwrap();
    s.sweep();
    std::fs::write(repo.join(".env"), &kept_env).unwrap();
    let files = &files[..2];

    // The undo is a proof, and puts back the files byte for byte: the
    // rewritten `.env` is replaced, since it is what the deletion left.
    let mut cmd = cli_command(
        &s.home,
        &["init", "--undo", &backup, "--passphrase-fd", "3"],
        &[(3, &s.pass, true)],
    );
    cmd.current_dir(&repo);
    let out = finish_within(cmd, Duration::from_secs(120));
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("proof_refused"), "{}", stderr(&out));
    assert!(!repo.join(".env.short").exists());
    let out = person_in(
        &s.home,
        &repo,
        &["init", "--undo", &backup, "--passphrase-fd", "3", "--json"],
        &[(3, &s.pass, true)],
    );
    ok(&out, &s.cs);
    let states: Vec<String> = json(&out)["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["state"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(states, ["restored", "restored"]);
    for (name, body) in files {
        assert!(
            std::fs::read(repo.join(name)).unwrap() == *body,
            "{name} is not its original"
        );
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

/// An existing `.gitignore` keeps its lines: one that ignores the env
/// files gets only the line for the temporary names a crash may leave,
/// once; one whose `!` line takes an env file back in gets that file's
/// line after it, as git reads it (the last matching line wins). A
/// manifest binding to another item is kept and reported.
#[test]
fn gitignore_and_manifest_edits_keep_what_is_there() {
    let s = Story::new();
    let (repo, _) = acme_web(&s.home, &s.cs);
    let mine = "target/\n.env*\n!.env.example\n";
    std::fs::write(repo.join(".gitignore"), mine).unwrap();
    std::fs::write(
        repo.join("envcloak.toml"),
        "# mine\n[project]\nname = \"acme-web\"\n\n[env]\nOPENAI_API_KEY = \"openai/elsewhere\" # kept\n",
    )
    .unwrap();
    let out = run_in(&s.home, &repo, &["init", "--import", "--yes", "--json"]);
    ok(&out, &s.cs);
    let p = &json(&out)["import"]["projects"][0];
    assert_eq!(p["gitignore"], "updated");
    assert_eq!(p["manifest"], "updated");
    assert_eq!(p["conflicts"][0], "OPENAI_API_KEY");
    let gitignore = format!(
        "{mine}\n# Plaintext env files stay out of git (envcloak init).\n.*.envcloak-*.tmp\n"
    );
    assert_eq!(
        std::fs::read_to_string(repo.join(".gitignore")).unwrap(),
        gitignore
    );
    for name in [
        ".env",
        ".env.short",
        "..env.envcloak-del-0123456789abcdef.tmp",
        "..env.short.envcloak-new-0123456789abcdef.tmp",
    ] {
        assert!(git_ignores(&repo, name), "{name}");
    }
    assert!(!git_ignores(&repo, ".env.example"));
    let out = run_in(&s.home, &repo, &["init", "--import", "--yes", "--json"]);
    ok(&out, &s.cs);
    assert_eq!(
        json(&out)["import"]["projects"][0]["gitignore"],
        "unchanged"
    );
    assert_eq!(
        std::fs::read_to_string(repo.join(".gitignore")).unwrap(),
        gitignore
    );

    // A `!` line takes `.env.local` back in: it gets a line after it.
    let api = s.home.root().join("acme-api");
    std::fs::create_dir_all(&api).unwrap();
    let key = by_label(&s.cs, labels::GITHUB_TOKEN).as_str();
    for f in [".env", ".env.local"] {
        std::fs::write(api.join(f), format!("GITHUB_TOKEN={key}\n")).unwrap();
    }
    std::fs::write(api.join(".gitignore"), ".env*\n!.env.local\n").unwrap();
    assert!(git_ignores(&api, ".env"));
    assert!(!git_ignores(&api, ".env.local"));
    let out = run_in(&s.home, &api, &["init", "--import", "--yes", "--json"]);
    ok(&out, &s.cs);
    assert_eq!(json(&out)["import"]["projects"][0]["gitignore"], "updated");
    for name in [
        ".env",
        ".env.local",
        "..env.local.envcloak-del-0123456789abcdef.tmp",
    ] {
        assert!(git_ignores(&api, name), "{name}");
    }
    let text = std::fs::read_to_string(api.join(".gitignore")).unwrap();
    assert!(text.starts_with(".env*\n!.env.local\n"), "{text}");
    assert!(
        text.ends_with("\n/.env.local\n.*.envcloak-*.tmp\n"),
        "{text}"
    );
    for f in [".env", ".env.local"] {
        std::fs::remove_file(api.join(f)).unwrap();
    }
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
        Self::with_daemon_env(confirm_kit, &[])
    }

    /// As [`Gate16::new`], with `env` added to the daemon's environment.
    fn with_daemon_env(confirm_kit: bool, env: &[(&str, &str)]) -> Self {
        let cs = with_kept_values(canaries(fresh_seed()));
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
        let mut cmd = Command::new(daemon_exe());
        home.apply(&mut cmd).envs(env.iter().copied());
        let d = Daemon::start_command(cmd, &[]);
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

    /// Whether each file is there as it was.
    fn intact(&self) -> Vec<bool> {
        self.files
            .iter()
            .map(|(n, body)| std::fs::read(self.repo.join(n)).is_ok_and(|b| b == *body))
            .collect()
    }

    /// `envcloak init --import --yes`, as a person runs it.
    fn import(&self) -> Output {
        person_in(&self.home, &self.repo, &["init", "--import", "--yes"], &[])
    }

    /// `envcloak init --delete-plaintext`, as a person runs it.
    fn delete(&self) -> Output {
        person_in(&self.home, &self.repo, &["init", "--delete-plaintext"], &[])
    }

    fn cleanup(&self) {
        for e in std::fs::read_dir(&self.repo).unwrap() {
            let n = e.unwrap().file_name();
            if n.to_string_lossy().contains(".env") {
                std::fs::remove_file(self.repo.join(n)).unwrap();
            }
        }
    }

    fn sweep(&self) {
        self.cleanup();
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

/// Gate 16: each condition, failing alone, refuses the deletion, and
/// nothing is deleted; with all four, the imported entries leave.
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
    assert_eq!(g.intact(), [true, true]);
    assert_no_canary(&out.stdout, &g.cs);

    // 2. A reference that does not resolve.
    ok(&g.import(), &g.cs);
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
    assert_eq!(g.intact(), [true, true]);
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
    assert_eq!(g.intact(), [true, true]);

    // With the three that hold (the kit was confirmed), the imported
    // entries leave: `.env` keeps the rest, `.env.short` goes.
    let out = g.delete();
    ok(&out, &g.cs);
    assert_eq!(
        std::fs::read(g.repo.join(".env")).unwrap(),
        env_left(&g.files[0].1)
    );
    assert!(!g.repo.join(".env.short").exists());
    g.sweep();

    // 4. The Recovery Kit unconfirmed.
    let g = Gate16::new(false);
    ok(&g.import(), &g.cs);
    let out = g.delete();
    assert!(
        stderr(&out).starts_with("envcloak: recovery_kit_unconfirmed:"),
        "{}",
        stderr(&out)
    );
    assert_eq!(g.intact(), [true, true]);
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
    assert_eq!(g.intact(), [false, true]);
    file_or_item(&g);
    g.sweep();
}

/// `init --import --yes --delete-plaintext` whose deletion fails before
/// any condition is checked (here the backup cannot be written) still
/// reports the import it committed, then the failure.
#[test]
fn a_failed_deletion_still_reports_the_import_it_follows() {
    let g = Gate16::new(true);
    let backups = data_dir(&g.home).join("backups");
    let _ = std::fs::remove_dir(&backups);
    std::fs::write(&backups, b"not a directory").unwrap();
    let out = person_in(
        &g.home,
        &g.repo,
        &["init", "--import", "--yes", "--delete-plaintext", "--json"],
        &[],
    );
    assert_no_canary(&out.stdout, &g.cs);
    assert_no_canary(&out.stderr, &g.cs);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).starts_with("envcloak: files_backup_failed:"),
        "{}",
        stderr(&out)
    );
    let r = json(&out);
    assert_eq!(r["import"]["committed"], true, "{r}");
    assert_eq!(r["import"]["projects"][0]["manifest"], "created", "{r}");
    assert_eq!(r["delete"], serde_json::Value::Null, "{r}");
    assert_eq!(g.intact(), [true, true]);
    // As text too.
    let out = person_in(
        &g.home,
        &g.repo,
        &["init", "--import", "--yes", "--delete-plaintext"],
        &[],
    );
    std::fs::remove_file(&backups).unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("project acme-web"),
        "{}",
        stdout(&out)
    );
    assert_eq!(g.intact(), [true, true]);
    file_or_item(&g);
    g.sweep();
}

/// A value short enough to guess is matched against the vault only for a
/// person: a deletion run with no terminal, as an agent runs one, leaves
/// `.env.short` as it is and says why; the person's takes the value out.
#[test]
fn a_deletion_without_a_person_leaves_short_values_in_place() {
    let g = Gate16::new(true);
    ok(&g.import(), &g.cs);
    let out = run_in(&g.home, &g.repo, &["init", "--delete-plaintext", "--json"]);
    ok(&out, &g.cs);
    let d = &json(&out)["delete"];
    assert_eq!(strings(&d["rewritten"]), [".env"]);
    assert_eq!(strings(&d["unchanged"]), [".env.short"]);
    assert_eq!(strings(&d["removed"]), Vec::<String>::new());
    let short = &d["verify"]["files"][1]["entries"][0];
    assert_eq!(short["name"], "SHORT_TOKEN");
    assert_eq!(short["status"], "left_out");
    assert_eq!(short["skipped"], "guessable");
    assert_eq!(g.intact(), [false, true]);
    file_or_item(&g);
    let out = g.delete();
    ok(&out, &g.cs);
    assert!(!g.repo.join(".env.short").exists());
    file_or_item(&g);
    g.sweep();
}

/// F-57 follow-up (Codex): `init --delete-plaintext` makes git ignore
/// every temporary name before any file changes, run on its own too: a
/// `.gitignore` that lost the line, or ignores only some of the names,
/// gets it back; one that cannot be edited (here it has another hard
/// link) stops the deletion (`gitignore_refused`), and nothing is deleted.
#[test]
fn a_deletion_makes_git_ignore_its_temporary_names_first() {
    let g = Gate16::new(true);
    ok(&g.import(), &g.cs);
    let path = g.repo.join(".gitignore");
    let partial = "/.env\n/.env.short\n*f.tmp\n";
    std::fs::write(&path, partial).unwrap();
    let other = g.home.root().join("gitignore-link");
    std::fs::hard_link(&path, &other).unwrap();
    let out = g.delete();
    assert_no_canary(&out.stdout, &g.cs);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(
        stderr(&out).starts_with("envcloak: gitignore_refused:"),
        "{}",
        stderr(&out)
    );
    assert_eq!(g.intact(), [true, true]);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), partial);
    std::fs::remove_file(&other).unwrap();
    // As JSON: the refusal, and no file changed.
    std::fs::hard_link(&path, &other).unwrap();
    let out = person_in(
        &g.home,
        &g.repo,
        &["init", "--delete-plaintext", "--json"],
        &[],
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let d = &json(&out)["delete"];
    assert_eq!(d["gitignore"], "refused", "{d}");
    assert_eq!(strings(&d["removed"]), Vec::<String>::new());
    assert_eq!(strings(&d["rewritten"]), Vec::<String>::new());
    assert_eq!(g.intact(), [true, true]);
    std::fs::remove_file(&other).unwrap();

    // Editable, it gets the line, and the deletion goes on.
    let out = person_in(
        &g.home,
        &g.repo,
        &["init", "--delete-plaintext", "--json"],
        &[],
    );
    ok(&out, &g.cs);
    let d = &json(&out)["delete"];
    assert_eq!(d["gitignore"], "updated", "{d}");
    assert_eq!(strings(&d["removed"]), [".env.short"]);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.starts_with(partial), "{text}");
    assert!(text.lines().any(|l| l == ".*.envcloak-*.tmp"), "{text}");
    for last in "0123456789abcdef".chars() {
        for what in ["del", "new", "swap"] {
            let t = format!("..env.envcloak-{what}-{:015x}{last}.tmp", fresh_seed() >> 4);
            assert!(git_ignores(&g.repo, &t), "{t}");
        }
    }
    file_or_item(&g);
    g.sweep();
}

/// A template named with its part anywhere (`.env.local.example`) gives
/// names only, and a profile shaped like a key (`.env.<hash>`) is skipped
/// whole: neither is imported, named in `envcloak.toml` or `.gitignore`,
/// or changed by the deletion.
#[test]
fn compound_templates_and_key_shaped_profiles_are_never_imported_or_changed() {
    let g = Gate16::new(true);
    let hash = format!("{}7{}", word(15), word(15));
    let key = by_label(&g.cs, labels::OPENAI_API_KEY_ROTATED).as_str();
    let template = format!("OPENAI_API_KEY={key}\nPORT=\n");
    let hashed = format!(".env.{hash}");
    let kept = [
        (".env.local.example".to_owned(), template.clone()),
        (".env.example.local".to_owned(), template),
        (hashed.clone(), format!("STRIPE_SECRET_KEY={key}\n")),
    ];
    for (name, body) in &kept {
        std::fs::write(g.repo.join(name), body).unwrap();
        age(&g.repo.join(name), Duration::from_secs(600));
    }
    let out = person_in(
        &g.home,
        &g.repo,
        &["init", "--import", "--yes", "--json"],
        &[],
    );
    ok(&out, &g.cs);
    let r = &json(&out)["import"];
    let slugs: Vec<&str> = r["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["slug"].as_str().unwrap())
        .collect();
    assert!(
        slugs
            .iter()
            .all(|s| !s.contains("example") && !s.contains("local")),
        "{slugs:?}"
    );
    let files = r["projects"][0]["files"].as_array().unwrap();
    for name in [".env.local.example", ".env.example.local"] {
        let f = files.iter().find(|f| f["file"] == name).unwrap();
        assert_eq!(f["template"], true, "{name}");
        assert_eq!(f["profile"], serde_json::Value::Null, "{name}");
    }
    assert!(files.iter().all(|f| f["file"] != hashed.as_str()));
    // F-59 (Codex): the skipped file is reported without its name, which
    // appears in no output, JSON or text.
    assert!(
        r["skipped"].as_array().unwrap().iter().any(|x| x["path"]
            == ".env.[not shown: looks like a key or token]"
            && x["reason"] == "not_a_profile_name"),
        "{}",
        r["skipped"]
    );
    assert!(!stdout(&out).contains(&hash), "{}", stdout(&out));
    for args in [&["init"][..], &["init", "--json"], &["init", "--import"]] {
        let out = person_in(&g.home, &g.repo, args, &[]);
        ok(&out, &g.cs);
        assert!(!stdout(&out).contains(&hash), "{args:?}: {}", stdout(&out));
        assert!(!stderr(&out).contains(&hash), "{args:?}: {}", stderr(&out));
        assert!(
            stdout(&out).contains(".env.[not shown: looks like a key or token]"),
            "{args:?}: {}",
            stdout(&out)
        );
    }
    for written in ["envcloak.toml", ".gitignore"] {
        let text = std::fs::read_to_string(g.repo.join(written)).unwrap();
        assert!(!text.contains(&hash), "{written}: {text}");
        assert!(!text.contains("example"), "{written}: {text}");
        assert!(!text.contains("local"), "{written}: {text}");
    }
    // Git ignores it by a line that spells none of its name.
    let gitignore = std::fs::read_to_string(g.repo.join(".gitignore")).unwrap();
    let unnamed = format!("/.env.{}", "?".repeat(hash.len()));
    assert!(gitignore.lines().any(|l| l == unnamed), "{gitignore}");
    assert!(git_ignores(&g.repo, &hashed));
    // No item holds the key the templates and the skipped file hold.
    let ls = run_in(&g.home, &g.repo, &["ls", "--json"]);
    assert_eq!(
        json(&ls)["items"].as_array().unwrap().len(),
        slugs.len() + 1,
        "the import's items and the fixture's other/item"
    );
    // The deletion changes only `.env` and `.env.short`.
    let out = g.delete();
    ok(&out, &g.cs);
    assert!(!g.repo.join(".env.short").exists());
    for (name, body) in &kept {
        assert_eq!(
            std::fs::read_to_string(g.repo.join(name)).unwrap(),
            *body,
            "{name}"
        );
    }
    g.sweep();
}

/// `init --undo` writes only into the project it runs for, which its
/// statement names, and puts a rewritten file back only when it is what
/// the deletion left: one edited since is left alone (`exists`).
#[test]
fn undo_replaces_only_what_the_deletion_left() {
    let g = Gate16::new(true);
    ok(&g.import(), &g.cs);
    let out = person_in(
        &g.home,
        &g.repo,
        &["init", "--delete-plaintext", "--json"],
        &[],
    );
    ok(&out, &g.cs);
    let backup = json(&out)["delete"]["backup"].as_str().unwrap().to_owned();
    let env = g.repo.join(".env");
    let mut edited = std::fs::read(&env).unwrap();
    edited.extend_from_slice(b"ADDED=later\n");
    std::fs::write(&env, &edited).unwrap();
    let pass = g.home.root().join("pass");
    std::fs::write(
        &pass,
        format!("{}\n", by_label(&g.cs, labels::VAULT_PASSPHRASE).as_str()),
    )
    .unwrap();
    // Run in another directory, the undo names that one before the
    // passphrase and writes nothing: the files are not in it.
    let elsewhere = g.home.root().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    let out = person_in(
        &g.home,
        &elsewhere,
        &["init", "--undo", &backup, "--passphrase-fd", "3", "--json"],
        &[(3, &pass, true)],
    );
    assert_no_canary(&out.stdout, &g.cs);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let named = std::fs::canonicalize(&elsewhere).unwrap();
    assert!(
        stderr(&out).contains(&format!("into {}.", named.display())),
        "{}",
        stderr(&out)
    );
    let r = json(&out);
    let states: Vec<&str> = r["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["state"].as_str().unwrap())
        .collect();
    assert_eq!(states, ["elsewhere", "elsewhere"]);
    assert!(!g.repo.join(".env.short").exists());
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    let out = person_in(
        &g.home,
        &g.repo,
        &["init", "--undo", &backup, "--passphrase-fd", "3", "--json"],
        &[(3, &pass, true)],
    );
    std::fs::remove_file(&pass).unwrap();
    assert_no_canary(&out.stdout, &g.cs);
    assert_no_canary(&out.stderr, &g.cs);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("undo_incomplete"), "{}", stderr(&out));
    let states: Vec<(String, String)> = json(&out)["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["path"]
                    .as_str()
                    .unwrap()
                    .rsplit('/')
                    .next()
                    .unwrap()
                    .to_owned(),
                f["state"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        states,
        [
            (".env".to_owned(), "exists".to_owned()),
            (".env.short".to_owned(), "restored".to_owned()),
        ]
    );
    assert!(
        std::fs::read(&env).unwrap() == edited,
        "the edit was undone"
    );
    assert_eq!(g.intact(), [false, true]);
    g.sweep();
}

/// The undo report's files, by name, with their states.
fn undo_states(out: &Output) -> Vec<(String, String)> {
    json(out)["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["path"]
                    .as_str()
                    .unwrap()
                    .rsplit('/')
                    .next()
                    .unwrap()
                    .to_owned(),
                f["state"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// F-78, end to end: after `init --delete-plaintext`, a whole entry the
/// person then takes out of the rewritten `.env` stays out: `init --undo`
/// leaves that file as it is (`exists`) and puts back `.env.short`, which
/// the deletion removed. Once `.env` is again exactly what the deletion
/// left, the same backup puts its original back (`restored`).
#[test]
fn undo_keeps_an_entry_taken_out_after_the_deletion() {
    let g = Gate16::new(true);
    ok(&g.import(), &g.cs);
    let out = person_in(
        &g.home,
        &g.repo,
        &["init", "--delete-plaintext", "--json"],
        &[],
    );
    ok(&out, &g.cs);
    let backup = json(&out)["delete"]["backup"].as_str().unwrap().to_owned();
    let env = g.repo.join(".env");
    let left = std::fs::read(&env).unwrap();
    let (name, original) = &g.files[0];
    assert_eq!(*name, ".env");
    // Compared without printing either side: a regression could leave a
    // fixture value in the file (SPEC §15.1).
    assert!(left == env_left(original), "not what the deletion leaves");
    // The person then takes a whole configuration entry out.
    let edited: Vec<u8> = left
        .split_inclusive(|&b| b == b'\n')
        .filter(|l| !l.starts_with(b"PORT="))
        .flatten()
        .copied()
        .collect();
    assert!(edited != left, "no entry taken out");
    std::fs::write(&env, &edited).unwrap();
    let pass = g.home.root().join("pass");
    std::fs::write(
        &pass,
        format!("{}\n", by_label(&g.cs, labels::VAULT_PASSPHRASE).as_str()),
    )
    .unwrap();
    let undo = || {
        let out = person_in(
            &g.home,
            &g.repo,
            &["init", "--undo", &backup, "--passphrase-fd", "3", "--json"],
            &[(3, &pass, true)],
        );
        assert_no_canary(&out.stdout, &g.cs);
        assert_no_canary(&out.stderr, &g.cs);
        out
    };
    let out = undo();
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("undo_incomplete"), "{}", stderr(&out));
    assert_eq!(
        undo_states(&out),
        [
            (".env".to_owned(), "exists".to_owned()),
            (".env.short".to_owned(), "restored".to_owned()),
        ]
    );
    assert!(
        std::fs::read(&env).unwrap() == edited,
        "the entry came back"
    );
    assert_eq!(g.intact(), [false, true]);

    // Exactly what the deletion left again: the original comes back.
    std::fs::write(&env, &left).unwrap();
    let out = undo();
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        undo_states(&out),
        [
            (".env".to_owned(), "restored".to_owned()),
            (".env.short".to_owned(), "unchanged".to_owned()),
        ]
    );
    assert_eq!(g.intact(), [true, true]);
    std::fs::remove_file(&pass).unwrap();
    g.sweep();
}

/// A backup an agent stored (any client may store one) is not written
/// back by `init --undo` unless the person ticks `--created-by-agent`:
/// the daemon seals who made it, so a backup crafted to replace `.env`
/// (its `left` the SHA-256 of the file there now, its contents the
/// agent's) is refused before the passphrase is looked at, and the file
/// is left as it is. Ticked, the statement says so, the file is written
/// back and the report names the agent as its maker (its kind `unknown`
/// here, the test process having no terminal session).
///
/// Mutations: the daemon ignoring who made a backup (the unticked undo
/// replaces `.env`); the CLI not sending the tick (the ticked undo is
/// refused).
#[test]
fn undo_writes_an_agents_backup_back_only_when_ticked() {
    let g = Gate16::new(true);
    let env = std::fs::canonicalize(&g.repo).unwrap().join(".env");
    let now: &[u8] = b"PORT=8080\n";
    let planted: &[u8] = b"PLANTED=by an agent\n";
    std::fs::write(&env, now).unwrap();
    let left = SecretBytes::copy_from(now)
        .sha256()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    // The agent's backup: a claimed agent marker, which only tightens.
    let id = Client::connect(&RunPaths::under(envcloak_testkit::daemon_run_dir(&g.home)).unwrap())
        .unwrap()
        .files_backup(&FilesBackupParams {
            files: vec![BackupFileParams {
                path: env.to_str().unwrap().to_owned(),
                mode: 0o600,
                content: WireSecret::new(SecretBytes::copy_from(planted)),
                left: FileLeft::Rewritten(left),
            }],
            claims: vec!["ENVCLOAK_FIXTURE_AGENT".to_owned()],
        })
        .unwrap()
        .id;
    let pass = g.home.root().join("pass");
    std::fs::write(
        &pass,
        format!("{}\n", by_label(&g.cs, labels::VAULT_PASSPHRASE).as_str()),
    )
    .unwrap();
    let undo = |extra: &[&str]| {
        let mut args = vec!["init", "--undo", &id];
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--passphrase-fd", "3", "--json"]);
        let out = person_in(&g.home, &g.repo, &args, &[(3, &pass, true)]);
        assert_no_canary(&out.stdout, &g.cs);
        assert_no_canary(&out.stderr, &g.cs);
        out
    };

    let out = undo(&[]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let e = stderr(&out);
    assert!(
        e.contains("envcloak: restore_refused:") && e.contains("--created-by-agent"),
        "{e}"
    );
    assert!(
        std::fs::read(&env).unwrap() == now,
        "the agent's backup replaced .env"
    );

    let out = undo(&["--created-by-agent"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("--created-by-agent: this backup may have been made by an agent"),
        "{}",
        stderr(&out)
    );
    assert!(std::fs::read(&env).unwrap() == planted, "not written back");
    // Not a terminal's: an agent, or (this test process has no terminal
    // session) an unknown process, under the fixture agent's label.
    let r = json(&out);
    let kind = r["creator"]["kind"].as_str().unwrap_or("none");
    assert!(kind == "agent" || kind == "unknown", "made by {kind}");
    assert!(r["creator"]["agent"].is_string(), "no agent named");
    assert_eq!(
        undo_states(&out),
        [(".env".to_owned(), "restored".to_owned())]
    );
    std::fs::remove_file(&pass).unwrap();
    g.sweep();
}

/// After a kill: every entry of every file is in its file, or committed in
/// the vault where the manifest binds it. A file that is there is the one
/// read, or what the deletion leaves of it (some entries taken out whole,
/// nothing else changed); an entry that left it is a value the vault
/// holds, as the daemon answers a person at a terminal.
fn file_or_item(g: &Gate16) {
    envcloak_sys::testing::enter_terminal_session().unwrap();
    let manifest = g.repo.join("envcloak.toml");
    let mut c =
        Client::connect(&RunPaths::under(envcloak_testkit::daemon_run_dir(&g.home)).unwrap())
            .unwrap();
    for (name, body) in &g.files {
        let original = SecretBytes::copy_from(body);
        let path = g.repo.join(name);
        let kept: Vec<String> = match std::fs::read(&path) {
            Ok(now) => {
                let now = SecretBytes::copy_from(&now);
                assert!(
                    now.ct_eq(body) || trimmed_from(&original, &now),
                    "{name} holds something else than it did"
                );
                parse_dotenv(&now)
                    .unwrap()
                    .iter()
                    .map(|e| e.name.as_str().to_owned())
                    .collect()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => panic!("{name}: {e}"),
        };
        let gone: Vec<_> = parse_dotenv(&original)
            .unwrap()
            .into_iter()
            .filter(|e| !kept.iter().any(|k| k == e.name.as_str()))
            .collect();
        if gone.is_empty() {
            continue;
        }
        assert!(
            manifest.exists(),
            "entries of {name} are gone, and no manifest binds them"
        );
        for e in &gone {
            assert_eq!(
                e.kind,
                EntryKind::Plain,
                "{name}: {} left the file, and is no value the vault can hold",
                e.name
            );
        }
        let v = c
            .import_verify(&VerifyParams {
                manifest: manifest.to_str().unwrap().to_owned(),
                files: vec![VerifyFile {
                    file: (*name).to_owned(),
                    profile: (*name == ".env.short").then(|| "short".to_owned()),
                    entries: gone
                        .into_iter()
                        .map(|e| VerifyEntry {
                            line: e.line,
                            name: e.name.as_str().to_owned(),
                            value: WireSecret::new(e.value),
                        })
                        .collect(),
                }],
                claims: Vec::new(),
            })
            .unwrap();
        for e in &v.files[0].entries {
            assert_eq!(
                e.status,
                EntryStatus::Stored,
                "{name}: {:?} left the file and is not committed where the manifest binds it",
                e.name
            );
        }
    }
}

/// The pause points of `envcloak init --import --yes --delete-plaintext`
/// on the fixture, in order: `.env` (file 0) is rewritten, `.env.short`
/// (file 1) removed.
const STEPS: [&str; 11] = [
    "planned",
    "committed",
    "written",
    "verified",
    "backed_up",
    "reverified",
    "staged_0",
    "swapped_0",
    "rewritten_0",
    "moved_aside_1",
    "removed_1",
];

/// Runs `envcloak init --import --yes --delete-plaintext` on a terminal of
/// its own, as a person does, stopping it at each pause point
/// ([`envcloak_scan::pause_point`], compiled into test builds only) and
/// sending `kill -9` to it at `at`. Returns the points it passed.
fn run_until(g: &Gate16, at: &str) -> Vec<String> {
    run_steps(g, at, Duration::ZERO)
}

/// As [`run_until`], waiting `linger` at each pause point before letting
/// the run go on.
fn run_steps(g: &Gate16, at: &str, linger: Duration) -> Vec<String> {
    let pause = tempfile::Builder::new()
        .prefix("ecp")
        .tempdir_in("/tmp")
        .unwrap();
    let mut cmd = on_terminal_command(
        &g.home,
        &["init", "--import", "--yes", "--delete-plaintext"],
        &[],
    );
    cmd.current_dir(&g.repo)
        .env(envcloak_scan::testing::PAUSE_DIR, pause.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut seen = Vec::new();
    loop {
        let prefix = format!("{:03}.", seen.len());
        let point = std::fs::read_dir(pause.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .find(|n| n.starts_with(&prefix) && !n.ends_with(".go"));
        let Some(point) = point else {
            if child.try_wait().unwrap().is_some() {
                return seen;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("stuck after {seen:?}");
            }
            std::thread::sleep(Duration::from_millis(5));
            continue;
        };
        let step = point[prefix.len()..].to_owned();
        seen.push(step.clone());
        if step == at {
            let pid = std::fs::read_to_string(pause.path().join(&point)).unwrap();
            let killed = Command::new("/bin/kill")
                .args(["-9", pid.trim()])
                .status()
                .unwrap();
            assert!(killed.success());
            child.wait().unwrap();
            return seen;
        }
        std::thread::sleep(linger);
        File::create(pause.path().join(format!("{prefix}go"))).unwrap();
    }
}

/// Review T7 open 2: the daemon closes a connection on which no frame
/// starts within its bound (30 seconds; here a test build's override of
/// 300 ms, which a quiet connection is seen to meet). `envcloak init
/// --import --yes --delete-plaintext` stopped for 900 ms at every step
/// still goes through as an unstopped run does: no step holds a
/// connection across local work, each connects again.
#[test]
fn a_short_idle_bound_breaks_no_step_of_init() {
    let g = Gate16::with_daemon_env(true, &[(envcloak_sys::testing::IDLE_CONNECTION_MS, "300")]);
    let mut quiet =
        std::os::unix::net::UnixStream::connect(envcloak_testkit::daemon_socket(&g.home)).unwrap();
    quiet
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let t = Instant::now();
    let mut b = [0u8; 1];
    assert_eq!(std::io::Read::read(&mut quiet, &mut b).unwrap(), 0);
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());

    assert_eq!(run_steps(&g, "none", Duration::from_millis(900)), STEPS);
    file_or_item(&g);
    assert_eq!(
        std::fs::read(g.repo.join(".env")).unwrap(),
        env_left(&g.files[0].1)
    );
    assert!(!g.repo.join(".env.short").exists());
    g.sweep();
}

/// Gate 16: `kill -9` of `envcloak init --import --yes --delete-plaintext`
/// at every step, the moments inside each file's change included (the
/// old file under its temporary name after the swap, too), leaves every
/// entry in its file or committed where the manifest binds it. A file
/// left under a temporary name is reported by the next scan, and git
/// ignores it by the `.gitignore` the import edited, which ignored the env
/// files already, and one temporary name's digits (F-57 follow-up): not
/// the random ones of the real leftover.
#[test]
fn gate_16_kill_9_at_every_step_leaves_the_file_or_the_item() {
    // Unstopped, the run passes every point, in order.
    let g = Gate16::new(true);
    assert_eq!(run_until(&g, "none"), STEPS);
    file_or_item(&g);
    assert_eq!(
        std::fs::read(g.repo.join(".env")).unwrap(),
        env_left(&g.files[0].1)
    );
    assert!(!g.repo.join(".env.short").exists());
    g.sweep();
    for (k, step) in STEPS.iter().enumerate() {
        let g = Gate16::new(true);
        // The env files are ignored already; the temporary names are not,
        // but for one sample's digits, until the import adds their line.
        std::fs::write(
            g.repo.join(".gitignore"),
            "/.env\n/.env.short\n.*.envcloak-*-0123456789abcdef.tmp\n",
        )
        .unwrap();
        let seen = run_until(&g, step);
        assert_eq!(seen, STEPS[..=k], "the points came out of order");
        file_or_item(&g);
        // Nothing changes before the gate has verified twice.
        if k < STEPS.iter().position(|s| *s == "staged_0").unwrap() {
            assert_eq!(g.intact(), [true, true], "killed at {step}");
        }
        let leftovers: Vec<String> = std::fs::read_dir(&g.repo)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".envcloak-"))
            .collect();
        let want_leftover = matches!(*step, "staged_0" | "swapped_0" | "moved_aside_1");
        assert_eq!(
            !leftovers.is_empty(),
            want_leftover,
            "{step}: {leftovers:?}"
        );
        if want_leftover {
            let out = run_in(&g.home, &g.repo, &["init", "--json"]);
            ok(&out, &g.cs);
            let skipped = &json(&out)["import"]["skipped"];
            for l in &leftovers {
                assert!(
                    skipped
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|s| s["path"] == l.as_str() && s["reason"] == "leftover"),
                    "{step}: {l} is not reported: {skipped}"
                );
            }
            let gitignore = std::fs::read_to_string(g.repo.join(".gitignore")).unwrap();
            assert!(gitignore.lines().any(|l| l == ".*.envcloak-*.tmp"));
            for l in &leftovers {
                assert!(git_ignores(&g.repo, l), "{step}: git would track {l}");
            }
        }
        g.sweep();
    }
}
