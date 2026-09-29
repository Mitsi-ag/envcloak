//! `envcloak backup create` and `envcloak recover` (SPEC §5, §15.1 step
//! 11; story S11), with a real daemon:
//! - a backup is written to the vault's `backups` directory, and holds
//!   ciphertext only;
//! - the Recovery Kit is a proof: without a terminal session it is refused
//!   before the vault is touched; a wrong kit is refused and counted; a
//!   file that is not a backup (missing, a symlink, altered) is refused,
//!   and each leaves the vault it had;
//! - after the vault directory is lost, `recover` puts the backed-up vault
//!   back, unlocked, under the new passphrase: its items are there, the
//!   old passphrase no longer opens it and the new one does.
//!
//! Every command's output, the daemon's log and the home are swept for
//! the passphrases, the kit and the values.
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use common::{
    cli_command, data_dir, finish_within, on_terminal_command, outside_dir, secret_file,
    start_daemon, stderr, stdout,
};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};

/// A vault created through the CLI, with the kit on a file, and one item.
struct Setup {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    _files: tempfile::TempDir,
    pass: PathBuf,
    new_pass: PathBuf,
    kit: PathBuf,
    wrong_kit: PathBuf,
}

impl Setup {
    fn new() -> Self {
        let mut cs = canaries(fresh_seed());
        let new_words = format!("restored vault passphrase {:016x}", fresh_seed());
        cs.push(Canary::new("NEW_PASSPHRASE", new_words));
        let home = TestHome::new();
        let d = start_daemon(&home);
        let files = outside_dir();
        let pass = secret_file(
            files.path(),
            "pass",
            by_label(&cs, labels::VAULT_PASSPHRASE).value(),
        );
        let new_pass = secret_file(files.path(), "new", by_label(&cs, "NEW_PASSPHRASE").value());
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
        let text = std::fs::read_to_string(&kit).unwrap();
        cs.push(Canary::new("RECOVERY_KIT", text.trim_end().to_owned()));
        // Another vault's kit: well formed, and wrong for this one.
        let wrong_kit = files.path().join("wrong-kit");
        std::fs::write(
            &wrong_kit,
            format!("{}\n", *envcloak_core::RecoveryKit::generate().to_display()),
        )
        .unwrap();
        let value = secret_file(
            files.path(),
            "value",
            by_label(&cs, labels::OPENAI_API_KEY).value(),
        );
        let s = Setup {
            cs,
            home,
            d,
            _files: files,
            pass,
            new_pass,
            kit,
            wrong_kit,
        };
        let out = s.detached(
            &["add", "--slug", "openai/acme-web", "--stdin"],
            &[(0, &value, true)],
        );
        s.ok(&out);
        s
    }

    /// `envcloak <args>` with no terminal, as a service manager's job runs.
    fn detached(&self, args: &[&str], fds: &[(i32, &Path, bool)]) -> Output {
        let out = finish_within(cli_command(&self.home, args, fds), Duration::from_secs(120));
        self.clean(&out);
        out
    }

    /// `envcloak <args>` on a terminal of its own, as a person runs it.
    fn person(&self, args: &[&str], fds: &[(i32, &Path, bool)]) -> Output {
        let out = finish_within(
            on_terminal_command(&self.home, args, fds),
            Duration::from_secs(120),
        );
        self.clean(&out);
        out
    }

    fn clean(&self, out: &Output) {
        assert_no_canary(&out.stdout, &self.cs);
        assert_no_canary(&out.stderr, &self.cs);
    }

    fn ok(&self, out: &Output) -> String {
        assert!(out.status.success(), "{}{}", stdout(out), stderr(out));
        stdout(out)
    }

    fn json(&self, args: &[&str]) -> serde_json::Value {
        let out = self.detached(args, &[]);
        serde_json::from_str(&self.ok(&out)).unwrap()
    }

    fn slugs(&self) -> Vec<String> {
        self.json(&["ls", "--json"])["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["slug"].as_str().unwrap().to_owned())
            .collect()
    }

    fn state(&self) -> String {
        self.json(&["status", "--json"])["vault"]["state"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// `envcloak recover --backup <backup>` from a terminal, the kit on
    /// descriptor 4 and the new passphrase on 3.
    fn recover(&self, backup: &Path, kit: &Path) -> Output {
        self.person(
            &[
                "recover",
                "--backup",
                backup.to_str().unwrap(),
                "--kit-fd",
                "4",
                "--new-passphrase-fd",
                "3",
                "--json",
            ],
            &[(3, &self.new_pass, true), (4, kit, true)],
        )
    }

    fn sweep(&self) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

fn token(out: &Output) -> String {
    let e = stderr(out);
    e.strip_prefix("envcloak: ")
        .and_then(|r| r.split(':').next())
        .unwrap_or("")
        .to_owned()
}

#[test]
fn backup_then_recover_after_the_vault_is_lost() {
    let mut s = Setup::new();

    // A backup, in the vault's backups directory.
    let b = s.json(&["backup", "create", "--json"]);
    let path = PathBuf::from(b["path"].as_str().unwrap());
    assert_eq!(b["items"], 1);
    let backups = data_dir(&s.home).join("backups");
    assert_eq!(
        path.parent().unwrap(),
        std::fs::canonicalize(&backups).unwrap()
    );
    let name = b["file_name"].as_str().unwrap();
    assert!(
        name.starts_with("vault-") && name.ends_with(".ecbackup"),
        "{name}"
    );
    assert_eq!(
        std::fs::metadata(&path).unwrap().len(),
        b["bytes"].as_u64().unwrap()
    );
    let text = s.ok(&s.detached(&["backup", "create"], &[]));
    assert!(text.starts_with("Backup written: "), "{text}");
    assert!(
        text.contains("`envcloak recover --backup <file>`"),
        "{text}"
    );
    s.sweep();

    // Without a terminal session the kit is refused, before the vault is
    // touched: it stays unlocked.
    let out = s.detached(
        &[
            "recover",
            "--backup",
            path.to_str().unwrap(),
            "--kit-fd",
            "4",
            "--new-passphrase-fd",
            "3",
        ],
        &[(3, &s.new_pass, true), (4, &s.kit, true)],
    );
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(token(&out), "proof_refused", "{}", stderr(&out));
    assert_eq!(s.state(), "unlocked");

    // What is not a regular file is refused before the vault is touched:
    // it stays unlocked.
    let files = outside_dir();
    let missing = files.path().join("missing.ecbackup");
    let link = files.path().join("link.ecbackup");
    symlink(&path, &link).unwrap();
    for bad in [&missing, &link, &files.path().to_path_buf()] {
        let out = s.recover(bad, &s.kit);
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(token(&out), "backup_unusable", "{}", stderr(&out));
        assert_eq!(s.state(), "unlocked");
    }
    // A file that is not the backup it claims to be is found out only as
    // it is read, once the vault was locked and closed for the restore:
    // the vault it had is there, locked, and opens with its passphrase.
    let altered = files.path().join("altered.ecbackup");
    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&altered, bytes).unwrap();
    let out = s.recover(&altered, &s.kit);
    assert_eq!(token(&out), "backup_unusable", "{}", stderr(&out));
    assert_eq!(s.state(), "locked");
    s.ok(&s.person(&["unlock", "--passphrase-fd", "3"], &[(3, &s.pass, true)]));
    assert_eq!(s.slugs(), ["openai/acme-web"]);

    // A wrong kit: refused and counted, and the vault it had is there.
    let out = s.recover(&path, &s.wrong_kit);
    assert_eq!(token(&out), "wrong_passphrase", "{}", stderr(&out));
    let st = s.json(&["status", "--json"]);
    assert_eq!(st["approvals"]["proof_failures"], 1);
    assert_eq!(st["vault"]["state"], "locked");
    s.ok(&s.person(&["unlock", "--passphrase-fd", "3"], &[(3, &s.pass, true)]));
    assert_eq!(s.slugs(), ["openai/acme-web"]);

    let log = s.d.log();
    assert!(
        log.contains("envcloakd: audit: vault backed up id="),
        "{log}"
    );
    assert!(
        log.contains("envcloakd: audit: recover failed reason=wrong_secret"),
        "{log}"
    );

    // The vault is lost: the daemon stops, `vault/` goes, a daemon starts
    // with no vault. `recover` puts the backup's vault back, unlocked.
    s.sweep();
    s.d.signal("-TERM");
    assert!(s.d.wait_exit(Duration::from_secs(30)).is_some());
    std::fs::remove_dir_all(data_dir(&s.home).join("vault")).unwrap();
    s.d = start_daemon(&s.home);
    assert_eq!(s.state(), "absent");
    let out = s.recover(&path, &s.kit);
    let r: serde_json::Value = serde_json::from_str(&s.ok(&out)).unwrap();
    assert_eq!(r["items"], 1);
    assert_eq!(r["locked"], false);
    assert_eq!(r["replaced"], 0);
    assert_eq!(s.state(), "unlocked");
    assert_eq!(s.slugs(), ["openai/acme-web"]);

    // The new passphrase opens it; the old one does not.
    s.ok(&s.detached(&["lock"], &[]));
    let out = s.person(&["unlock", "--passphrase-fd", "3"], &[(3, &s.pass, true)]);
    assert_eq!(token(&out), "wrong_passphrase", "{}", stderr(&out));
    s.ok(&s.person(
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &s.new_pass, true)],
    ));

    // Recovering over an unlocked vault replaces it, and keeps the one it
    // replaced beside it.
    let out = s.recover(&path, &s.kit);
    let r: serde_json::Value = serde_json::from_str(&s.ok(&out)).unwrap();
    assert_eq!(r["replaced"], 1);
    assert_eq!(s.state(), "unlocked");
    let kept: Vec<String> = std::fs::read_dir(data_dir(&s.home).join("vault"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("replaced-"))
        .collect();
    assert_eq!(kept.len(), 1, "{kept:?}");
    let log = s.d.log();
    assert!(
        log.contains("envcloakd: audit: vault recovered id="),
        "{log}"
    );
    s.sweep();
}

#[test]
fn recover_takes_the_kit_and_the_new_passphrase_on_the_terminal() {
    let s = Setup::new();
    let b = s.json(&["backup", "create", "--json"]);
    let path = b["path"].as_str().unwrap().to_owned();
    let kit = std::fs::read_to_string(&s.kit).unwrap();
    let new = String::from_utf8(by_label(&s.cs, "NEW_PASSPHRASE").value().to_vec()).unwrap();
    let (out, code) = common::drive(
        &s.home,
        &[
            common::cli().to_str().unwrap(),
            "recover",
            "--backup",
            &path,
        ],
        &[
            (
                "Recovery Kit (typing is hidden): ",
                &format!("{}\r", kit.trim_end()),
            ),
            ("New vault passphrase", &format!("{new}\r")),
            ("Repeat the passphrase: ", &format!("{new}\r")),
        ],
    );
    s.clean(&out);
    assert_eq!(code, 0, "{}", stdout(&out));
    assert!(
        stdout(&out).contains("Vault restored from the backup made"),
        "{}",
        stdout(&out)
    );
    assert_eq!(s.slugs(), ["openai/acme-web"]);
    s.sweep();
}
