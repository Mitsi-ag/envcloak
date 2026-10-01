//! Every M1 command's output, as a person and an agent see it, against a
//! value-free snapshot (T11 acceptance): `vault create`, `unlock`,
//! `status`, `ls`, `show`, `check` (with and without a manifest, and on a
//! locked vault), `ref`, `add`, `run`'s refusal,
//! `approve`, `grants list`, `rotate`, `rm`, `deny`, `grants revoke`,
//! `audit verify`, `backup create`, `recover` and `lock`, in one story on
//! the fixture vault. The
//! output of `daemon install` is tested with the service managers in
//! tests/service.rs.
//!
//! The JSON form (`--json`) of every command that has one is a snapshot
//! too, and so are the help and usage text of every command (M2-02: the
//! CLI's rendering, failure and terminal code moved into `envcloak-client`
//! with these snapshots taken before the move and compared byte for byte
//! after it).
//!
//! Each command's standard output and error are swept for every canary
//! first (a failure names the canary's label, never its value), and only
//! then compared, after what changes from run to run is replaced: times,
//! ids, pids, durations, the test's paths and a backup's name. The
//! snapshots are the files in `tests/snapshots/`; with
//! `ENVCLOAK_SNAPSHOT_UPDATE=1` the test writes them instead. At the end the
//! daemon's log and the whole home are swept.
#![allow(clippy::unwrap_used)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{
    MANIFEST, cli, cli_command, finish_within, on_terminal_command, outside_dir, project,
    secret_file, seed_vault, start_daemon, stderr,
};
use envcloak_testkit::{
    Canary, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};
use regex::Regex;

/// Replaces what changes between runs with fixed words.
struct Normalizer {
    replacements: Vec<(String, String)>,
    patterns: Vec<(Regex, &'static str)>,
}

impl Normalizer {
    fn new(home: &TestHome) -> Self {
        let target = cli().parent().unwrap().to_str().unwrap().to_owned();
        // The data directory differs between macOS and Linux; a backup's
        // path is in it.
        let data = common::data_dir(home);
        std::fs::create_dir_all(&data).unwrap();
        let real_data = std::fs::canonicalize(&data)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let data = data.to_str().unwrap().to_owned();
        let root = home.root().to_str().unwrap().to_owned();
        let real_root = std::fs::canonicalize(home.root())
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let p = |re: &str| Regex::new(re).unwrap();
        Normalizer {
            replacements: vec![
                (real_data, "<DATA>".into()),
                (data, "<DATA>".into()),
                (real_root, "<ROOT>".into()),
                (root, "<ROOT>".into()),
                (target, "<TARGET>".into()),
            ],
            patterns: vec![
                (
                    p(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} UTC"),
                    "<TIME>",
                ),
                (p(r"[0-9]{4}-[0-9]{2}-[0-9]{2}"), "<DATE>"),
                (p(r"vault-[0-9A-Za-z-]+\.ecbackup"), "<BACKUP>"),
                (p(r"size: [0-9]+ bytes"), "size: <BYTES> bytes"),
                (p(r"(?-u:\b)[0-9A-HJKMNP-TV-Z]{26}(?-u:\b)"), "<ULID>"),
                (p(r"(?-u:\b)[0-9]+h( [0-9]+m)?( [0-9]+s)?(?-u:\b)"), "<DUR>"),
                (p(r"(?-u:\b)[0-9]+m( [0-9]+s)?(?-u:\b)"), "<DUR>"),
                (p(r"(?-u:\b)[0-9]+s(?-u:\b)"), "<DUR>"),
                (p(r"pid [0-9]+"), "pid <PID>"),
                // The root's start time, and its executable where the
                // system lets the daemon read it (not a non-dumpable
                // process's on Linux).
                (p(r"(?m)started at [0-9]+(, .*)?$"), "started at <START>"),
                (
                    p(r#""(created|updated|rotated|expires|last_used)_secs":[0-9]+"#),
                    r#""${1}_secs":"<SECS>""#,
                ),
                (p(r"version [0-9]+\.[0-9]+\.[0-9]+"), "version <VER>"),
                (
                    p(r"(?m)^(daemon|cli) hardening: .*$"),
                    "$1 hardening: <HARDENING>",
                ),
                (p(r"(?m)^(  \[0\] ).*python3.*$"), "$1<PYTHON>"),
                // The same in the JSON forms.
                (p(r#""pid":[0-9]+"#), r#""pid":"<PID>""#),
                (
                    p(r#""version":"[0-9]+\.[0-9]+\.[0-9]+""#),
                    r#""version":"<VER>""#,
                ),
                (
                    p(r#""hardened":(true|false),"hardening":\{[^}]*\}"#),
                    r#""hardened":"<H>","hardening":"<HARDENING>""#,
                ),
                (
                    p(r#""idle_remaining_secs":[0-9]+"#),
                    r#""idle_remaining_secs":"<SECS>""#,
                ),
                (
                    p(r#""([a-z_]+)_secs":[0-9]{10,}"#),
                    r#""${1}_secs":"<SECS>""#,
                ),
                (p(r#""bytes":[0-9]+"#), r#""bytes":"<BYTES>""#),
            ],
        }
    }

    fn apply(&self, text: &str, ids: &[(&str, &str)]) -> String {
        let mut s = text.to_owned();
        for (from, to) in &self.replacements {
            s = s.replace(from, to);
        }
        for (from, to) in ids {
            s = s.replace(from, to);
        }
        for (re, to) in &self.patterns {
            s = re.replace_all(&s, *to).into_owned();
        }
        s
    }
}

/// What `out` printed, as one text: exit code, standard output, standard
/// error.
fn raw_text(out: &Output) -> String {
    format!(
        "exit: {}\n--- stdout\n{}--- stderr\n{}",
        out.status
            .code()
            .map_or("signal".to_owned(), |c| c.to_string()),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    )
}

/// Checks `got` against the snapshot `name`, or writes it with
/// `ENVCLOAK_SNAPSHOT_UPDATE=1`.
fn compare(name: &str, got: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/snapshots")
        .join(format!("{name}.txt"));
    if std::env::var_os("ENVCLOAK_SNAPSHOT_UPDATE").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, got).unwrap();
        return;
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("no snapshot {name}: run with ENVCLOAK_SNAPSHOT_UPDATE=1"));
    assert_eq!(got, want, "the output of {name} is not its snapshot");
}

struct Story {
    cs: Vec<Canary>,
    home: TestHome,
    norm: Normalizer,
    files: tempfile::TempDir,
    pass: PathBuf,
    project: PathBuf,
    /// Request ids seen so far, and what they print as.
    ids: Vec<(String, String)>,
}

impl Story {
    /// What `out` printed, swept for canaries, as one text: exit code,
    /// standard output, standard error.
    fn text(&self, out: &Output) -> String {
        assert_no_canary(&out.stdout, &self.cs);
        assert_no_canary(&out.stderr, &self.cs);
        let ids: Vec<(&str, &str)> = self
            .ids
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        self.norm.apply(&raw_text(out), &ids)
    }

    /// Checks `out` against the snapshot `name`.
    fn snap(&self, name: &str, out: &Output) {
        compare(name, &self.text(out));
    }

    /// `envcloak <args>` in the project, as an agent runs it: no terminal.
    fn agent(&self, args: &[&str], fds: &[common::Fd<'_>]) -> Output {
        self.agent_in(&self.project, args, fds)
    }

    /// `envcloak <args>` in `dir`, as an agent runs it.
    fn agent_in(&self, dir: &Path, args: &[&str], fds: &[common::Fd<'_>]) -> Output {
        let mut cmd = cli_command(&self.home, args, fds);
        cmd.current_dir(dir);
        finish_within(cmd, std::time::Duration::from_secs(60))
    }

    /// `envcloak <args>` in the project on a terminal of its own, as a
    /// person runs it, with the passphrase on descriptor 3.
    fn person(&self, args: &[&str], more: &[common::Fd<'_>]) -> Output {
        let mut fds = vec![(3, self.pass.as_path(), true)];
        fds.extend_from_slice(more);
        let mut cmd = on_terminal_command(&self.home, args, &fds);
        cmd.current_dir(&self.project);
        finish_within(cmd, std::time::Duration::from_secs(60))
    }

    /// The request id in `run`'s refusal, remembered as `<REQn>`.
    fn request_id(&mut self, out: &Output) -> String {
        let err = stderr(out);
        let id = err
            .split("request=")
            .nth(1)
            .and_then(|r| r.get(..8))
            .unwrap_or_else(|| panic!("no request id: {err}"))
            .to_owned();
        let n = self.ids.len() + 1;
        self.ids.push((id.clone(), format!("<REQ{n}>")));
        id
    }
}

#[test]
fn every_command_prints_its_value_free_snapshot() {
    // A vault made from nothing, as story step S1 makes it.
    {
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
        let s = Story {
            norm: Normalizer::new(&home),
            cs,
            home,
            files,
            pass,
            project: PathBuf::new(),
            ids: Vec::new(),
        };
        let mut cmd = cli_command(
            &s.home,
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
            &[(3, &s.pass, true), (4, &kit, false)],
        );
        cmd.current_dir(s.home.home());
        let out = finish_within(cmd, std::time::Duration::from_secs(120));
        s.snap("vault-create", &out);
        let kit_text = std::fs::read_to_string(&kit).unwrap();
        let mut cs = s.cs.clone();
        cs.push(Canary::new("RECOVERY_KIT", kit_text.trim().to_owned()));
        assert_no_canary(&d.log_bytes(), &cs);
        s.home.assert_clean(&cs);
        let _ = &s.files;
    }

    // The story's vault.
    let mut cs = canaries(fresh_seed());
    let home = TestHome::new();
    let kit = seed_vault(&home, &cs);
    cs.push(kit);
    let d = start_daemon(&home);
    let files = outside_dir();
    let pass = secret_file(
        files.path(),
        "pass",
        by_label(&cs, labels::VAULT_PASSPHRASE).value(),
    );
    let project = project(&home, "acme-web", MANIFEST);
    std::fs::write(
        project.join(".env"),
        format!(
            "# left over from before EnvCloak\nGITHUB_TOKEN={}\nPORT=8080\n\
             OPENAI_API_KEY=envcloak://openai/acme-web\n",
            by_label(&cs, labels::GITHUB_TOKEN).as_str()
        ),
    )
    .unwrap();
    std::fs::write(project.join(".env.example"), "GITHUB_TOKEN=\nPORT=8080\n").unwrap();
    let mut s = Story {
        norm: Normalizer::new(&home),
        cs,
        home,
        files,
        pass,
        project,
        ids: Vec::new(),
    };

    s.snap("status-locked", &s.agent(&["status"], &[]));
    s.snap("ls-locked", &s.agent(&["ls"], &[]));
    s.snap(
        "unlock",
        &s.person(&["unlock", "--passphrase-fd", "3"], &[]),
    );
    s.snap("status", &s.agent(&["status"], &[]));
    s.snap("ls", &s.agent(&["ls"], &[]));
    s.snap("ls-long", &s.agent(&["ls", "--long"], &[]));
    s.snap("ls-json", &s.agent(&["ls", "--json"], &[]));
    s.snap("show", &s.agent(&["show", "openai/acme-web"], &[]));
    s.snap(
        "show-json",
        &s.agent(&["show", "openai/acme-web", "--json"], &[]),
    );
    s.snap("check", &s.agent(&["check"], &[]));
    s.snap("check-json", &s.agent(&["check", "--json"], &[]));
    // No manifest in this directory or above it: the env file's references
    // are sent on their own, resolve, and the check passes.
    let loose = s.home.root().join("loose");
    std::fs::create_dir(&loose).unwrap();
    std::fs::write(
        loose.join(".env"),
        "OPENAI_API_KEY=envcloak://openai/acme-web\nPORT=8080\n",
    )
    .unwrap();
    s.snap("check-no-manifest", &s.agent_in(&loose, &["check"], &[]));
    // The plaintext key was put there for `check` to find; the sweep at the
    // end is about what EnvCloak wrote.
    std::fs::remove_file(s.project.join(".env")).unwrap();
    s.snap(
        "ref",
        &s.agent(&["ref", "GITHUB_TOKEN=github/acme-web"], &[]),
    );
    s.snap(
        "ref-again",
        &s.agent(&["ref", "GITHUB_TOKEN=github/acme-web", "--json"], &[]),
    );
    s.snap(
        "ref-missing",
        &s.agent(&["ref", "EXTRA=misc/extra", "--profile", "short"], &[]),
    );
    let value = secret_file(
        s.files.path(),
        "value",
        by_label(&s.cs, labels::DATABASE_URL).value(),
    );
    s.snap(
        "add",
        &s.agent(
            &[
                "add",
                "--stdin",
                "--slug",
                "misc/extra",
                "--account",
                "dev@acme.example",
                "--env",
                "DATABASE_URL",
            ],
            &[(0, &value, true)],
        ),
    );
    s.snap("add-no-terminal", &s.agent(&["add"], &[]));

    let out = s.agent(&["run", "--", "./emit"], &[]);
    let id = s.request_id(&out);
    s.snap("run-approval-required", &out);
    s.snap(
        "approve",
        &s.person(&["approve", &id, "--passphrase-fd", "3"], &[]),
    );
    s.snap("grants-list", &s.agent(&["grants", "list"], &[]));
    s.snap(
        "rotate-no-terminal",
        &s.agent(&["rotate", "openai/acme-web", "--stdin"], &[]),
    );
    let new = secret_file(
        s.files.path(),
        "new",
        by_label(&s.cs, labels::OPENAI_API_KEY_ROTATED).value(),
    );
    s.snap(
        "rotate",
        &s.person(
            &[
                "rotate",
                "openai/acme-web",
                "--stdin",
                "--passphrase-fd",
                "3",
            ],
            &[(0, &new, true)],
        ),
    );
    s.snap(
        "grants-list-after-rotate",
        &s.agent(&["grants", "list"], &[]),
    );
    let out = s.agent(&["run", "--profile", "short", "--", "./emit"], &[]);
    let id = s.request_id(&out);
    s.snap("run-profile-approval-required", &out);
    s.snap("deny", &s.agent(&["deny", &id], &[]));
    s.snap(
        "rm",
        &s.person(&["rm", "misc/extra", "--passphrase-fd", "3"], &[]),
    );
    s.snap(
        "run-after-rm",
        &s.agent(&["run", "--profile", "short", "--", "./emit"], &[]),
    );
    s.snap(
        "grants-revoke",
        &s.agent(&["grants", "revoke", "--all"], &[]),
    );
    s.snap("audit-verify", &s.agent(&["audit", "verify"], &[]));
    let out = s.agent(&["backup", "create", "--json"], &[]);
    let backup = serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["path"]
        .as_str()
        .unwrap()
        .to_owned();
    s.snap("backup-create", &s.agent(&["backup", "create"], &[]));
    let kit = secret_file(
        s.files.path(),
        "kit",
        by_label(&s.cs, "RECOVERY_KIT").value(),
    );
    let new_pass = secret_file(
        s.files.path(),
        "new-pass",
        b"a new passphrase for the vault",
    );
    s.snap(
        "recover",
        &s.person(
            &[
                "recover",
                "--backup",
                &backup,
                "--kit-fd",
                "4",
                "--new-passphrase-fd",
                "5",
            ],
            &[(4, &kit, true), (5, &new_pass, true)],
        ),
    );
    s.snap("lock", &s.agent(&["lock"], &[]));
    s.snap("status-after-lock", &s.agent(&["status"], &[]));
    s.snap("check-locked", &s.agent(&["check"], &[]));
    // The env file's references were not checked, which is not the same
    // as not resolving.
    std::fs::write(
        s.project.join(".env"),
        "OPENAI_API_KEY=envcloak://openai/acme-web\nPORT=8080\n",
    )
    .unwrap();
    s.snap("check-locked-env-refs", &s.agent(&["check"], &[]));
    std::fs::remove_file(s.project.join(".env")).unwrap();

    assert_no_canary(&d.log_bytes(), &s.cs);
    s.home.assert_clean(&s.cs);
}

/// `envcloak init`, `import --scan` and `recovery confirm` (T13), on a new
/// vault and the fixture repo: each command's output against its
/// value-free snapshot.
#[test]
fn import_commands_print_their_value_free_snapshots() {
    import_story(false);
}

/// The same story with `--json` on every command that takes it: the form
/// an agent reads.
#[test]
fn import_commands_print_their_value_free_json_snapshots() {
    import_story(true);
}

fn strs(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

/// The import story, its commands' output as text or, with `json`, as
/// JSON, against the snapshots of that form (`<name>-json`).
fn import_story(json: bool) {
    use envcloak_core::crypto::KdfParams;
    use envcloak_core::vault::VaultPaths;
    use envcloak_core::{RecoveryKit, SecretBytes, create_vault_with_kit};

    let mut cs = canaries(fresh_seed());
    let home = TestHome::new();
    let kit = RecoveryKit::generate();
    let paths = VaultPaths::under(common::data_dir(&home));
    let secret = SecretBytes::copy_from(by_label(&cs, labels::VAULT_PASSPHRASE).value());
    drop(create_vault_with_kit(&paths, &secret, &kit, KdfParams::minimum()).unwrap());
    let kit_text = kit.to_display().to_string();
    cs.push(Canary::new("RECOVERY_KIT", kit_text.clone()));
    let d = start_daemon(&home);
    let files = outside_dir();
    let pass = secret_file(
        files.path(),
        "pass",
        by_label(&cs, labels::VAULT_PASSPHRASE).value(),
    );
    let kit_file = secret_file(files.path(), "kit", kit_text.as_bytes());
    let project = home.root().join("acme-web");
    std::fs::create_dir_all(&project).unwrap();
    let v = |l| by_label(&cs, l).as_str().to_owned();
    let bodies = [
        (
            ".env",
            format!(
                "OPENAI_API_KEY={}\nSTRIPE_SECRET_KEY={}\nDATABASE_URL='{}'\nPORT=8080\n\
                 NODE_ENV=production\n",
                v(labels::OPENAI_API_KEY),
                v(labels::STRIPE_SECRET_KEY),
                v(labels::DATABASE_URL).replace('\'', ""),
            ),
        ),
        (
            ".env.short",
            format!("SHORT_TOKEN={}\n", v(labels::SHORT_TOKEN)),
        ),
        (
            ".env.example",
            "OPENAI_API_KEY=\nSTRIPE_SECRET_KEY=\n".to_owned(),
        ),
    ];
    for (name, body) in &bodies {
        let p = project.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(600))
            .unwrap();
    }
    let s = Story {
        norm: Normalizer::new(&home),
        cs,
        home,
        files,
        pass,
        project,
        ids: Vec::new(),
    };
    let out = s.person(&["unlock", "--passphrase-fd", "3"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));

    // The command line and snapshot name of each step, in the form asked
    // for.
    let form = |args: &[&str]| -> Vec<String> {
        let mut v: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        if json {
            v.push("--json".to_owned());
        }
        v
    };
    let name = |n: &str| {
        if json {
            format!("{n}-json")
        } else {
            n.to_owned()
        }
    };

    // The person imports: `SHORT_TOKEN`, short enough to guess, is
    // imported only for them. The unconfirmed deletion below is an
    // agent's, which leaves it where it is.
    let args = form(&["init", "--import"]);
    s.snap(&name("init-dry-run"), &s.person(&strs(&args), &[]));
    let args = form(&["init", "--import", "--yes"]);
    s.snap(&name("init-import"), &s.person(&strs(&args), &[]));
    let args = form(&["init", "--delete-plaintext"]);
    s.snap(
        &name("init-delete-unconfirmed"),
        &s.agent(&strs(&args), &[]),
    );
    let args = form(&["recovery", "confirm", "--kit-fd", "4"]);
    s.snap(
        &name("recovery-confirm"),
        &s.person(&strs(&args), &[(4, &kit_file, true)]),
    );
    // Both forms take the JSON here, which names the backup to undo.
    let out = s.person(&["init", "--delete-plaintext", "--json"], &[]);
    let backup =
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["delete"]["backup"]
            .as_str()
            .unwrap()
            .to_owned();
    s.snap("init-delete-json", &out);
    let args = form(&["init", "--undo", &backup, "--passphrase-fd", "3"]);
    s.snap(&name("init-undo"), &s.person(&strs(&args), &[]));
    // The files are back, in plaintext, as the person asked.
    for (name, _) in &bodies[..2] {
        std::fs::remove_file(s.project.join(name)).unwrap();
    }
    let root = s.home.root().to_str().unwrap().to_owned();
    let args = form(&["import", "--scan", &root]);
    s.snap(&name("import-scan"), &s.agent(&strs(&args), &[]));
    assert_no_canary(&d.log_bytes(), &s.cs);
    s.home.assert_clean(&s.cs);
}

/// The commands of the first story that print JSON with `--json`, in that
/// form, on a vault of their own: `status` (locked and unlocked), `add`,
/// `grants list`, `rotate`, `rm`, `audit verify`, `backup create` and
/// `recover`. `ls`, `show`, `check` and `ref` have their JSON snapshots in
/// the first story, and `init`, `import` and `recovery confirm` in the
/// import story's JSON form.
#[test]
fn every_command_prints_its_value_free_json_snapshot() {
    let mut cs = canaries(fresh_seed());
    let home = TestHome::new();
    let kit = seed_vault(&home, &cs);
    cs.push(kit);
    let d = start_daemon(&home);
    let files = outside_dir();
    let pass = secret_file(
        files.path(),
        "pass",
        by_label(&cs, labels::VAULT_PASSPHRASE).value(),
    );
    let project = project(&home, "acme-web", MANIFEST);
    let mut s = Story {
        norm: Normalizer::new(&home),
        cs,
        home,
        files,
        pass,
        project,
        ids: Vec::new(),
    };

    s.snap("status-locked-json", &s.agent(&["status", "--json"], &[]));
    let out = s.person(&["unlock", "--passphrase-fd", "3"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    s.snap("status-json", &s.agent(&["status", "--json"], &[]));
    let value = secret_file(
        s.files.path(),
        "value",
        by_label(&s.cs, labels::DATABASE_URL).value(),
    );
    s.snap(
        "add-json",
        &s.agent(
            &[
                "add",
                "--stdin",
                "--slug",
                "misc/extra",
                "--account",
                "dev@acme.example",
                "--env",
                "DATABASE_URL",
                "--json",
            ],
            &[(0, &value, true)],
        ),
    );
    let out = s.agent(&["run", "--", "./emit"], &[]);
    let id = s.request_id(&out);
    // The grant ends with its root, the request's own process, as in the
    // first story: the list is empty (tests/approve.rs lists live ones).
    let out = s.person(&["approve", &id, "--passphrase-fd", "3"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    s.snap(
        "grants-list-json",
        &s.agent(&["grants", "list", "--json"], &[]),
    );
    let new = secret_file(
        s.files.path(),
        "new",
        by_label(&s.cs, labels::OPENAI_API_KEY_ROTATED).value(),
    );
    s.snap(
        "rotate-json",
        &s.person(
            &[
                "rotate",
                "openai/acme-web",
                "--stdin",
                "--passphrase-fd",
                "3",
                "--json",
            ],
            &[(0, &new, true)],
        ),
    );
    s.snap(
        "rm-json",
        &s.person(&["rm", "misc/extra", "--passphrase-fd", "3", "--json"], &[]),
    );
    s.snap(
        "audit-verify-json",
        &s.agent(&["audit", "verify", "--json"], &[]),
    );
    let out = s.agent(&["backup", "create", "--json"], &[]);
    let backup = serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()["path"]
        .as_str()
        .unwrap()
        .to_owned();
    s.snap("backup-create-json", &out);
    let kit = secret_file(
        s.files.path(),
        "kit",
        by_label(&s.cs, "RECOVERY_KIT").value(),
    );
    let new_pass = secret_file(
        s.files.path(),
        "new-pass",
        b"a new passphrase for the vault",
    );
    s.snap(
        "recover-json",
        &s.person(
            &[
                "recover",
                "--backup",
                &backup,
                "--kit-fd",
                "4",
                "--new-passphrase-fd",
                "5",
                "--json",
            ],
            &[(4, &kit, true), (5, &new_pass, true)],
        ),
    );
    assert_no_canary(&d.log_bytes(), &s.cs);
    s.home.assert_clean(&s.cs);
}

/// What `help-and-usage` runs: the top-level help and version, an unknown
/// command, and each command's `--help` or a usage error of it (M1's, and
/// those M2-03 landed: `run --wait`, `run --manifest`, `pending`). (`-h`
/// and `help` take the arm of `--help`, and `-V` that of `--version`.)
const HELP_AND_USAGE: &[&[&str]] = &[
    &["--help"],
    &["--version"],
    &["no-such-command"],
    &["vault"],
    &["vault", "create", "--bogus"],
    &["unlock", "--bogus"],
    &["lock", "--bogus"],
    &["status", "--bogus"],
    &["daemon"],
    &["daemon", "install", "--bogus"],
    &["run", "--help"],
    &["run"],
    &["run", "--bogus", "--", "true"],
    &["run", "--wait", "11m", "--", "true"],
    &["run", "--manifest", "envcloak.toml", "--", "true"],
    &["pending", "--help"],
    &["pending", "--bogus"],
    &["approve"],
    &["deny"],
    &["grants"],
    &["grants", "revoke"],
    &["audit"],
    &["add", "--help"],
    &["add", "--bogus"],
    &["ls", "--bogus"],
    &["show"],
    &["ref", "--help"],
    &["ref"],
    &["check", "--bogus"],
    &["rotate"],
    &["rm"],
    &["init", "--help"],
    &["init", "--bogus"],
    &["import", "--help"],
    &["import"],
    &["recovery", "--help"],
    &["recovery"],
    &["backup"],
    &["recover", "--help"],
    &["recover"],
];

/// The help and usage text a person or an agent reads before running a
/// command, as one snapshot, compared as printed (the version aside). Each
/// of these stops at its arguments, so no daemon is needed.
#[test]
fn help_and_usage_print_their_snapshot() {
    let home = TestHome::new();
    let mut got = String::new();
    for args in HELP_AND_USAGE {
        let out = common::run(&home, args, &[]);
        got.push_str(&format!("$ envcloak {}\n", args.join(" ")));
        got.push_str(&raw_text(&out).replace(env!("CARGO_PKG_VERSION"), "<VER>"));
    }
    compare("help-and-usage", &got);
}
