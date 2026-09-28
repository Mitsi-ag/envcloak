//! Every M1 command's output, as a person and an agent see it, against a
//! value-free snapshot (T11 acceptance): `vault create`, `unlock`,
//! `status`, `ls`, `show`, `check`, `ref`, `add`, `run`'s refusal,
//! `approve`, `grants list`, `rotate`, `rm`, `deny`, `grants revoke`,
//! `audit verify` and `lock`, in one story on the fixture vault. The
//! output of `daemon install` is tested with the service managers in
//! tests/service.rs.
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
        let root = home.root().to_str().unwrap().to_owned();
        let real_root = std::fs::canonicalize(home.root())
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let p = |re: &str| Regex::new(re).unwrap();
        Normalizer {
            replacements: vec![
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
        let raw = format!(
            "exit: {}\n--- stdout\n{}--- stderr\n{}",
            out.status
                .code()
                .map_or("signal".to_owned(), |c| c.to_string()),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        self.norm.apply(&raw, &ids)
    }

    /// Checks `out` against the snapshot `name`.
    fn snap(&self, name: &str, out: &Output) {
        let got = self.text(out);
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/snapshots")
            .join(format!("{name}.txt"));
        if std::env::var_os("ENVCLOAK_SNAPSHOT_UPDATE").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &got).unwrap();
            return;
        }
        let want = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("no snapshot {name}: run with ENVCLOAK_SNAPSHOT_UPDATE=1"));
        assert_eq!(got, want, "the output of {name} is not its snapshot");
    }

    /// `envcloak <args>` in the project, as an agent runs it: no terminal.
    fn agent(&self, args: &[&str], fds: &[common::Fd<'_>]) -> Output {
        let mut cmd = cli_command(&self.home, args, fds);
        cmd.current_dir(&self.project);
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
    s.snap("lock", &s.agent(&["lock"], &[]));
    s.snap("status-after-lock", &s.agent(&["status"], &[]));
    s.snap("check-locked", &s.agent(&["check"], &[]));

    assert_no_canary(&d.log_bytes(), &s.cs);
    s.home.assert_clean(&s.cs);
}
