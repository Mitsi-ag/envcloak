//! The M1 fixture acceptance story (SPEC §15.1), steps S1 to S13 of the
//! M1 plan, as one ordered test on the built binaries: a person (a
//! terminal session of its own, no agent in its ancestry) and an agent
//! (`fixture-agent` running one shell, no terminal) in one isolated home,
//! with `envcloakd --foreground` started by absolute path.
//!
//! The fixture repo `acme-web` is generated here, with values from
//! `envcloak-testkit`: `OPENAI_API_KEY` (an `sk-proj-` prefix, 64 bytes),
//! `STRIPE_SECRET_KEY`, `GITHUB_TOKEN`, `DATABASE_URL` (a password with
//! `/`, `"`, `+`, a space and a non-ASCII character), `SHORT_TOKEN` (10
//! bytes, in the `short` profile only), `PORT=8080`, and a `.env.example`.
//! Its command, `./emit`, prints each value through every serializer gate
//! 8 names (tests/fixtures/emitters), whole and split, on both streams,
//! then each serializer's SHA-256 of each value.
//!
//! After every step everything any process printed, every daemon's log
//! and the whole home are swept for every canary and every encoding of
//! one, and for what each serializer makes of each value, as the
//! serializer made it outside EnvCloak. Only the fixture repo's env files
//! hold plaintext, on purpose, until S2 takes it out.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::Duration;

use envcloak_e2e::{
    Emitters, Harness, Human, NAMES, NEW_PASSPHRASE, RECOVERY_KIT, WRONG_PASSPHRASE, age,
    sha256_hex, text, token, write_script,
};
use envcloak_testkit::{Canary, labels};

/// The request id in `approval_required: request=<ID>: ...`.
fn request_id(o: &Output) -> String {
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert_eq!(token(&o.stderr), "approval_required", "{}", text(o));
    err.split("request=")
        .nth(1)
        .and_then(|r| r.get(..8))
        .unwrap_or_else(|| panic!("no request id: {err}"))
        .to_owned()
}

/// `sha256 <serializer> <NAME> <hex>` lines.
fn digests(stdout: &[u8]) -> BTreeMap<(String, String), String> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|l| {
            let mut w = l.split(' ');
            (w.next() == Some("sha256")).then_some(())?;
            let (tag, name, hex) = (w.next()?, w.next()?, w.next()?);
            Some(((tag.to_owned(), name.to_owned()), hex.to_owned()))
        })
        .collect()
}

/// The fixture repo: `.env`, `.env.short`, `.env.example`, and `./emit`
/// with its configuration. The env files are dated ten minutes back: the
/// delete gate leaves alone a file changed in the last two.
fn write_repo(h: &mut Harness, emitters: &Emitters) -> PathBuf {
    let repo = h.home.root().join("acme-web");
    std::fs::create_dir_all(&repo).unwrap();
    let v = |l: &str| h.canary(l).as_str().to_owned();
    let dq = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
    let env = format!(
        "# acme-web\nOPENAI_API_KEY={}\nSTRIPE_SECRET_KEY={}\nGITHUB_TOKEN={}\nDATABASE_URL={}\n\
         PORT=8080\n",
        v(labels::OPENAI_API_KEY),
        v(labels::STRIPE_SECRET_KEY),
        v(labels::GITHUB_TOKEN),
        dq(&v(labels::DATABASE_URL)),
    );
    let short = format!("SHORT_TOKEN={}\n", v(labels::SHORT_TOKEN));
    let example = "OPENAI_API_KEY=\nSTRIPE_SECRET_KEY=\nGITHUB_TOKEN=\nDATABASE_URL=\nPORT=8080\n";
    for (name, body) in [
        (".env", env.as_str()),
        (".env.short", short.as_str()),
        (".env.example", example),
    ] {
        std::fs::write(repo.join(name), body).unwrap();
        age(&repo.join(name), Duration::from_secs(600));
    }
    h.allow_plaintext(repo.join(".env"));
    h.allow_plaintext(repo.join(".env.short"));
    let config = repo.join("emit.json");
    emitters.write_config(&config, &["DATABASE_URL"]);
    write_script(&repo.join("emit"), &emitters.script(&config));
    repo
}

/// What `emit` printed, checked: exit 0, every serializer ran, every
/// result's frames went through, the digests equal the values', and
/// redaction markers stand where the values were. The output was swept
/// already.
fn check_emit(
    o: &Output,
    emitters: &Emitters,
    results: &[(String, Vec<u8>)],
    values: &BTreeMap<&str, Vec<u8>>,
    framed: bool,
) {
    assert_eq!(o.status.code(), Some(0), "{}", text(o));
    let (out, err) = (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    );
    let tags = emitters.tags();
    assert!(
        err.contains(&format!("SERIALIZERS {} RESULTS", tags.join(","))),
        "{err}"
    );
    assert!(err.contains("DONE\n"), "{err}");
    let got = digests(&o.stdout);
    for tag in &tags {
        for name in NAMES {
            let want = sha256_hex(&values[name]);
            assert_eq!(
                got.get(&(tag.clone(), name.to_owned())),
                Some(&want),
                "the {tag} digest of {name}"
            );
        }
    }
    if framed {
        let both = format!("{out}{err}");
        for (label, _) in results {
            for frame in ["<W|", "<B|"] {
                assert!(
                    both.contains(&format!("{frame}{label}=")),
                    "no {frame}{label} frame"
                );
            }
        }
        for slug in [
            "openai/acme-web",
            "stripe/acme-web",
            "github/acme-web",
            "database-url/acme-web",
        ] {
            let marker = format!("[envcloak:{slug}]");
            assert!(out.contains(&marker) && err.contains(&marker), "{marker}");
        }
    }
}

/// `envcloak approve <id> --for 1h` by the person, typing `pass`.
fn approve(h: &mut Harness, repo: &Path, id: &str, pass: &str) -> Human {
    let typed = format!("{}\r", h.canary(pass).as_str());
    h.human(
        repo,
        &["approve", id, "--for", "1h"],
        &[],
        &[("Vault passphrase to approve this: ", &typed)],
    )
}

/// The independent view of a process's hardening, as `envcloak status`
/// must word it: on macOS whether the binary is signed with the hardened
/// runtime (`codesign`); on Linux whether the process is non-dumpable
/// (its `/proc` entries then belong to root) and its core limit is 0.
fn expected_hardening(exe: &Path, pid: Option<u32>) -> Option<&'static str> {
    if cfg!(target_os = "macos") {
        let out = std::process::Command::new("codesign")
            .args(["--display", "--verbose=2"])
            .arg(exe)
            .output()
            .ok()?;
        let shown = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let runtime = shown
            .lines()
            .filter(|l| l.starts_with("CodeDirectory "))
            .any(|l| l.contains("runtime"));
        Some(if runtime {
            "hardened"
        } else {
            "unhardened (not signed with the hardened runtime)"
        })
    } else {
        let pid = pid?;
        let owner = std::os::unix::fs::MetadataExt::uid(
            &std::fs::metadata(format!("/proc/{pid}/status")).ok()?,
        );
        let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).ok()?;
        let core_off = limits
            .lines()
            .find(|l| l.starts_with("Max core file size"))
            .is_some_and(|l| l.split_whitespace().nth(4) == Some("0"));
        Some(if owner == 0 && core_off {
            "hardened"
        } else {
            "unhardened"
        })
    }
}

#[test]
fn fixture_story_s1_to_s13() {
    let mut h = Harness::start();
    let emitters = Emitters::prepare(
        &Path::new(env!("CARGO_TARGET_TMPDIR")).join("e2e-emitters"),
        Path::new(env!("CARGO_BIN_EXE_ec-emit-serde")),
    );
    if !emitters.missing.is_empty() {
        eprintln!(
            "fixture story: not installed here, so left out: {}",
            emitters.missing.join(", ")
        );
    }
    let repo = write_repo(&mut h, &emitters);
    let home = h.home.home();

    // What every serializer makes of each value, the rotated one too, as
    // the serializer made it outside EnvCloak: looked for as it is.
    let original: BTreeMap<&str, Vec<u8>> =
        NAMES.iter().map(|n| (*n, h.value(n).to_vec())).collect();
    let mut rotated = original.clone();
    rotated.insert(
        "OPENAI_API_KEY",
        h.value(labels::OPENAI_API_KEY_ROTATED).to_vec(),
    );
    let config = repo.join("emit.json");
    let mut results = Vec::new();
    for values in [&original, &rotated] {
        let pairs: Vec<(&str, &[u8])> = values.iter().map(|(n, v)| (*n, v.as_slice())).collect();
        let r = emitters.oracle(&config, &pairs);
        for (label, bytes) in &r {
            h.add_needle(format!("{label} of a fixture"), bytes.clone());
        }
        results = r;
    }
    h.assert_swept("setup");

    // S1: the vault, with the passphrase from a descriptor and the kit
    // written only to another.
    let pass = h.secret_file(labels::VAULT_PASSPHRASE, true);
    let kit = h.files().join("kit");
    let s1 = h.human(
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
        &[],
    );
    assert_eq!(s1.code, 0, "{}", s1.all());
    assert!(
        s1.out().contains("Vault created and unlocked."),
        "{}",
        s1.all()
    );
    assert!(
        s1.out()
            .contains("The Recovery Kit went only to the descriptor you named."),
        "{}",
        s1.all()
    );
    let kit_text = std::fs::read_to_string(&kit).unwrap();
    h.add_canary(Canary::new(RECOVERY_KIT, kit_text.trim_end().to_owned()));
    h.assert_swept("S1");

    // S2: the import, with providers detected, `envcloak.toml` and
    // `.gitignore` written and every reference resolving; the plaintext
    // stays until the Recovery Kit is confirmed, then goes after an
    // encrypted backup.
    let dry = h.human(&repo, &["init", "--import"], &[], &[]);
    assert_eq!(dry.code, 0, "{}", dry.all());
    assert!(dry.out().contains("dry run"), "{}", dry.all());
    assert!(!repo.join("envcloak.toml").exists());
    let s2 = h.human(&repo, &["init", "--import", "--yes"], &[], &[]);
    assert_eq!(s2.code, 0, "{}", s2.all());
    for line in [
        "OPENAI_API_KEY     -> openai/acme-web",
        "STRIPE_SECRET_KEY  -> stripe/acme-web",
        "GITHUB_TOKEN       -> github/acme-web",
        "DATABASE_URL       -> database-url/acme-web",
        "SHORT_TOKEN  -> short-token/acme-web-short",
        "envcloak.toml: created",
        ".gitignore: created",
        "references: every one resolves",
        "openai/acme-web  (new, openai,",
        "stripe/acme-web  (new, stripe,",
        "github/acme-web  (new, github,",
    ] {
        assert!(s2.out().contains(line), "{line}\n{}", s2.all());
    }
    let gitignore = std::fs::read_to_string(repo.join(".gitignore")).unwrap();
    assert!(gitignore.lines().any(|l| l == "/.env"), "{gitignore}");
    let refused = h.human(&repo, &["init", "--delete-plaintext"], &[], &[]);
    assert_eq!(refused.code, 1, "{}", refused.all());
    assert_eq!(token(&refused.stderr), "recovery_kit_unconfirmed");
    assert!(repo.join(".env").exists() && repo.join(".env.short").exists());
    let confirmed = h.human(
        &repo,
        &["recovery", "confirm", "--kit-fd", "4"],
        &[(4, &kit, true)],
        &[],
    );
    assert_eq!(confirmed.code, 0, "{}", confirmed.all());
    let deleted = h.human(&repo, &["init", "--delete-plaintext", "--json"], &[], &[]);
    assert_eq!(deleted.code, 0, "{}", deleted.all());
    let d: serde_json::Value = serde_json::from_slice(&deleted.stdout).unwrap();
    assert_eq!(d["delete"]["removed"], serde_json::json!([".env.short"]));
    assert_eq!(d["delete"]["rewritten"], serde_json::json!([".env"]));
    let file_backup = d["delete"]["backup"].as_str().unwrap().to_owned();
    assert!(
        std::fs::read_dir(h.data_dir().join("backups"))
            .unwrap()
            .any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(&format!("-{file_backup}.ecfiles"))),
        "no encrypted backup of the files"
    );
    // What stays in `.env` is what was not imported: `PORT`, a comment.
    assert_eq!(
        std::fs::read_to_string(repo.join(".env")).unwrap(),
        "# acme-web\nPORT=8080\n"
    );
    assert!(!repo.join(".env.short").exists());
    h.allow_no_plaintext();
    h.assert_swept("S2");

    // S3: the agent looks around: metadata only.
    let ls = h.agent(&repo, &["ls"]);
    assert_eq!(ls.status.code(), Some(0), "{}", text(&ls));
    let s3_ls = String::from_utf8_lossy(&ls.stdout).into_owned();
    for slug in [
        "database-url/acme-web",
        "github/acme-web",
        "openai/acme-web",
        "short-token/acme-web-short",
        "stripe/acme-web",
    ] {
        assert!(s3_ls.contains(slug), "{s3_ls}");
    }
    let show = h.agent(&repo, &["show", "openai/acme-web"]);
    assert_eq!(show.status.code(), Some(0), "{}", text(&show));
    let check = h.agent(&repo, &["check"]);
    assert_eq!(check.status.code(), Some(0), "{}", text(&check));
    // `status` says truthfully what this build cannot guarantee.
    let status = h.agent(&repo, &["status"]);
    let st = String::from_utf8_lossy(&status.stdout).into_owned();
    assert!(
        st.contains("daemon identity: unverified (this build pins no code signature"),
        "{st}"
    );
    let daemon_pid = u32::try_from(h.daemon.pid()).ok();
    if let Some(want) = expected_hardening(&h.daemon_exe(), daemon_pid) {
        let line = st
            .lines()
            .find_map(|l| l.strip_prefix("daemon hardening: "))
            .unwrap_or("");
        assert!(
            line.starts_with(want),
            "daemon hardening: {line}, want {want}"
        );
    }
    if cfg!(target_os = "macos") {
        let want = expected_hardening(&h.cli(), None).unwrap_or("");
        assert!(st.contains(&format!("cli hardening: {want}")), "{st}");
    }
    h.assert_swept("S3");

    // S4: the agent's run waits for a person: nothing released, and the
    // request is pending in the audit log.
    let s4 = h.agent(&repo, &["run", "--", "./emit"]);
    assert_eq!(s4.status.code(), Some(125), "{}", text(&s4));
    assert!(s4.stdout.is_empty(), "{}", text(&s4));
    let id = request_id(&s4);
    assert!(
        h.daemon.log().contains(&format!(
            "envcloakd: audit: request decision=pending id={id}"
        )),
        "{}",
        h.daemon.log()
    );
    h.assert_swept("S4");

    // S5: the person approves on a terminal: the statement shows the
    // escaped command line, the bindings and a new project. A wrong
    // passphrase is refused and counted; the right one makes the grant.
    let wrong = approve(&mut h, &repo, &id, WRONG_PASSPHRASE);
    assert_eq!(wrong.code, 1, "{}", wrong.all());
    assert_eq!(token(&wrong.stderr), "wrong_passphrase", "{}", wrong.all());
    for part in [
        "new project",
        "command (1 arguments):",
        "[0] ./emit",
        "DATABASE_URL = database-url/acme-web#value",
        "GITHUB_TOKEN = github/acme-web#value",
        "OPENAI_API_KEY = openai/acme-web#value",
        "STRIPE_SECRET_KEY = stripe/acme-web#value",
        "requested by: agent EnvCloak test fixture agent",
    ] {
        assert!(wrong.shown().contains(part), "{part}\n{}", wrong.all());
    }
    let st: serde_json::Value =
        serde_json::from_slice(&h.agent(&repo, &["status", "--json"]).stdout).unwrap();
    assert_eq!(st["approvals"]["proof_failures"], 1);
    let right = approve(&mut h, &repo, &id, labels::VAULT_PASSPHRASE);
    assert_eq!(right.code, 0, "{}", right.all());
    assert!(
        right
            .out()
            .contains(&format!("Approved request {id}: grant ")),
        "{}",
        right.all()
    );
    h.assert_swept("S5");

    // S6: the agent's run now gets the values: every serializer's output,
    // whole and split, on both streams, is redacted, and the digests match
    // the fixtures. The short profile's 10-byte value is refused.
    let s6 = h.agent(&repo, &["run", "--", "./emit"]);
    check_emit(&s6, &emitters, &results, &original, true);
    let short = h.agent(
        &repo,
        &[
            "run",
            "--profile",
            "short",
            "--",
            "./emit",
            "--digests-only",
        ],
    );
    assert_eq!(short.status.code(), Some(125), "{}", text(&short));
    let short_id = request_id(&short);
    let ok = approve(&mut h, &repo, &short_id, labels::VAULT_PASSPHRASE);
    assert_eq!(ok.code, 0, "{}", ok.all());
    let short = h.agent(
        &repo,
        &[
            "run",
            "--profile",
            "short",
            "--",
            "./emit",
            "--digests-only",
        ],
    );
    assert_eq!(short.status.code(), Some(125), "{}", text(&short));
    assert_eq!(token(&short.stderr), "value_too_short", "{}", text(&short));
    assert!(
        String::from_utf8_lossy(&short.stderr).contains("short-token/acme-web-short"),
        "{}",
        text(&short)
    );
    assert!(short.stdout.is_empty(), "{}", text(&short));
    h.assert_swept("S6");

    // S7: the person rotates the OpenAI key: the new value on standard
    // input, the proof typed on the terminal. One prior version is kept,
    // and the grant stays.
    let new = h.secret_file(labels::OPENAI_API_KEY_ROTATED, false);
    let typed = format!("{}\r", h.canary(labels::VAULT_PASSPHRASE).as_str());
    let s7 = h.human(
        &repo,
        &["rotate", "openai/acme-web", "--stdin"],
        &[(0, &new, true)],
        &[("Vault passphrase to rotate this: ", &typed)],
    );
    assert_eq!(s7.code, 0, "{}", s7.all());
    assert!(
        s7.out().contains(
            "Rotated openai/acme-web#value: the new value is in place, and 1 prior value is kept."
        ),
        "{}",
        s7.all()
    );
    let grants: serde_json::Value =
        serde_json::from_slice(&h.agent(&repo, &["grants", "list", "--json"]).stdout).unwrap();
    assert_eq!(grants["grants"].as_array().unwrap().len(), 2, "{grants}");
    h.assert_swept("S7");

    // S8: the agent's rerun gets the new value; neither it nor the old
    // one shows.
    let s8 = h.agent(&repo, &["run", "--", "./emit", "--quick"]);
    check_emit(&s8, &emitters, &results, &rotated, true);
    h.assert_swept("S8");

    // S9: the agent locks: its run is refused, and the grants are gone.
    let lock = h.agent(&repo, &["lock"]);
    assert_eq!(lock.status.code(), Some(0), "{}", text(&lock));
    let s9 = h.agent(&repo, &["run", "--", "./emit", "--digests-only"]);
    assert_eq!(s9.status.code(), Some(125), "{}", text(&s9));
    assert_eq!(token(&s9.stderr), "vault_locked", "{}", text(&s9));
    let grants = h.agent(&repo, &["grants", "list", "--json"]);
    let listed: serde_json::Value = serde_json::from_slice(&grants.stdout).unwrap();
    assert_eq!(listed["grants"], serde_json::json!([]), "{}", text(&grants));
    h.assert_swept("S9");

    // S10: the person unlocks on a terminal; the agent's run needs a new
    // approval, since the lock ended the grants.
    let s10 = h.human(&home, &["unlock"], &[], &[("Vault passphrase: ", &typed)]);
    assert_eq!(s10.code, 0, "{}", s10.all());
    let again = h.agent(&repo, &["run", "--", "./emit", "--digests-only"]);
    assert_eq!(again.status.code(), Some(125), "{}", text(&again));
    request_id(&again);
    h.assert_swept("S10");

    // S11: a backup; the daemon stops; the vault directory is lost; a new
    // daemon starts; the person recovers from the backup with the kit and
    // a new passphrase. The vault is back, unlocked, with the same items;
    // after an approval the run gets the rotated value.
    let before = h.agent(&repo, &["ls"]);
    let before = String::from_utf8_lossy(&before.stdout).into_owned();
    let backup = h.human(&home, &["backup", "create", "--json"], &[], &[]);
    assert_eq!(backup.code, 0, "{}", backup.all());
    let b: serde_json::Value = serde_json::from_slice(&backup.stdout).unwrap();
    let backup_path = b["path"].as_str().unwrap().to_owned();
    assert_eq!(b["items"], 5);
    h.stop_daemon();
    std::fs::remove_dir_all(h.data_dir().join("vault")).unwrap();
    h.start_daemon(&[]);
    let new_pass = h.secret_file(NEW_PASSPHRASE, true);
    let s11 = h.human(
        &home,
        &[
            "recover",
            "--backup",
            &backup_path,
            "--kit-fd",
            "4",
            "--new-passphrase-fd",
            "3",
            "--json",
        ],
        &[(3, &new_pass, true), (4, &kit, true)],
        &[],
    );
    assert_eq!(s11.code, 0, "{}", s11.all());
    let r: serde_json::Value = serde_json::from_slice(&s11.stdout).unwrap();
    assert_eq!(r["items"], 5);
    assert_eq!(r["locked"], false);
    let after = h.agent(&repo, &["ls"]);
    let after = String::from_utf8_lossy(&after.stdout).into_owned();
    assert_eq!(after, before, "the restored vault lists other items");
    // S3's listing, but for the rotation's date.
    let dates = |s: &str| {
        s.lines()
            .map(|l| l.split_whitespace().take(4).collect::<Vec<_>>().join(" "))
            .collect::<Vec<_>>()
    };
    assert_eq!(dates(&after), dates(&s3_ls));
    let run = h.agent(&repo, &["run", "--", "./emit", "--digests-only"]);
    let id = request_id(&run);
    let ok = approve(&mut h, &repo, &id, NEW_PASSPHRASE);
    assert_eq!(ok.code, 0, "{}", ok.all());
    let s11_run = h.agent(&repo, &["run", "--", "./emit", "--digests-only"]);
    check_emit(&s11_run, &emitters, &results, &rotated, false);
    h.assert_swept("S11");

    // S12: the audit log's chain holds up to the anchor, and the entries
    // after it are reported as an unanchored tail.
    let verify = h.agent(&repo, &["audit", "verify", "--json"]);
    assert_eq!(verify.status.code(), Some(0), "{}", text(&verify));
    let v: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(v["first_problem"], serde_json::Value::Null, "{v}");
    assert_eq!(v["problems"], 0, "{v}");
    assert_eq!(v["anchor"]["state"], "matched", "{v}");
    let shown = h.agent(&repo, &["audit", "verify"]);
    let shown = String::from_utf8_lossy(&shown.stdout).into_owned();
    if v["unanchored_tail"].is_null() {
        assert!(!shown.contains("unanchored tail:"), "{shown}");
    } else {
        assert!(shown.contains("unanchored tail: entries "), "{shown}");
    }

    // S13: nothing anywhere: every stream, every daemon's log, the fixture
    // repo, the home and its temporary directory. The vault, the audit log
    // and the backups hold ciphertext only.
    h.assert_swept("S13");
    for dir in ["vault", "audit", "backups"] {
        let hits = envcloak_testkit::sweep_dir(&h.data_dir().join(dir), &h.canaries);
        assert!(hits.is_empty(), "{dir}: {hits:?}");
        assert!(h.data_dir().join(dir).is_dir(), "no {dir}");
    }
}
