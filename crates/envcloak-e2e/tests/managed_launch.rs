//! Managed server records and registered launches (SPEC §6.6; M2 plan
//! D-05, D-18, D-33, CR-2, F-72; task M2-27; gates 39, 33, 23 and the
//! launch half of 40), end to end through the built `envcloak` and
//! `envcloakd`: what a managed project's key is released for, and
//! nothing else.
//!
//! - Every other command against the managed project is refused before
//!   any pending request, under no grant and under a live session grant,
//!   and after a daemon restart (the record survives it).
//! - A registered launch whose executable, script entry or working
//!   directory changed is refused `managed_launch_changed` before any
//!   pending request, with nothing released; a bare name runs the
//!   registered absolute executable; the server gets the launch's
//!   environment only.
//! - At the check-to-spawn barrier the approved image runs, never a file
//!   put in its place (Linux: the sealed copy; macOS: the suspended
//!   child's code directory hash).
//! - Registration takes a terminal's proof and refuses code-selecting
//!   declarations; an update is built from the stored declaration, needs
//!   a proof and a statement unchanged since its plan, and its next
//!   revision is covered by no grant made for the old one.
//! - A bridged server's origin is part of its record and of its bindings.
//! - Launch classes and their receipts.
#![allow(clippy::unwrap_used)]

mod managed_common;

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use envcloak_e2e::{python3, sha256_hex, text};
use managed_common::{
    KEY, World, appears, error_of, file_identity, helper_main, other_build, pending_id,
    receipt_identity, report, reported_identity, started,
};
use serde_json::{Value, json};

/// Runs only as the helper (`managed_common`).
#[test]
fn helper() {
    helper_main();
}

/// `envcloak run` by the agent against the managed project: with
/// `--manifest`, and from inside it (upward search), `printenv` of the
/// key. Both refused `managed_command_mismatch` (exit 125) with no
/// pending request and nothing released.
fn other_commands_refused(w: &mut World, when: &str) {
    let manifest = w.project.join("envcloak.toml");
    let pending = w.pending_count();
    let released = w.released();
    let home = w.h.home.home();
    let project = w.project.clone();
    let printenv = format!("printenv {KEY}");
    for (cwd, args) in [
        (
            home,
            vec![
                "run",
                "--manifest",
                manifest.to_str().unwrap(),
                "--",
                "sh",
                "-c",
                printenv.as_str(),
            ],
        ),
        (project, vec!["run", "--", "sh", "-c", printenv.as_str()]),
    ] {
        let out = w.h.agent(&cwd, &args);
        assert_eq!(out.status.code(), Some(125), "{when}: {}", text(&out));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("envcloak: managed_command_mismatch: "),
            "{when}: {}",
            text(&out)
        );
    }
    assert_eq!(
        w.pending_count(),
        pending,
        "{when}: a pending request exists"
    );
    assert_eq!(w.released(), released, "{when}: something was released");
}

/// D-05, R-M2-24: a managed project's key is for its registered launch
/// only. `envcloak run --manifest <managed> -- sh -c 'printenv KEY'`, and
/// `envcloak run -- ...` from inside the managed directory, are refused
/// with no pending request under no grant, under a live session grant for
/// the launch (whose own request is the positive control), and after a
/// daemon restart, which the record survives (the launch is still
/// managed).
///
/// Mutation checked: the request check skipped for a request that names
/// no launch (a managed project's other commands taken as an unmanaged
/// project's): `envcloak run` gets a pending request and this fails.
#[test]
fn every_other_command_is_refused_before_a_pending_request() {
    if managed_common::release_run("every_other_command_is_refused_before_a_pending_request") {
        return;
    }
    let mut w = World::new(&[]);
    let (launch, _) = w.register_fixture();
    other_commands_refused(&mut w, "no grant");
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let answer = w.request(&launch);
    assert!(started(&answer), "{answer}");
    other_commands_refused(&mut w, "a live session grant");
    let _ = w.h.stop_daemon();
    w.h.start_daemon(&[]);
    let pass =
        w.h.secret_file(envcloak_testkit::labels::VAULT_PASSPHRASE, true);
    let home = w.h.home.home();
    let unlocked = w.h.human(
        &home,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &pass, true)],
        &[],
    );
    assert_eq!(unlocked.code, 0, "{}", unlocked.all());
    other_commands_refused(&mut w, "after a restart");
    let again = w.request(&launch);
    pending_id(&again);
    w.h.assert_swept("after the refusals");
}

/// Changes the stopped daemon's vault with SQLite itself: `flip` flips one
/// bit of every policy row's sealed bytes (the managed record's among
/// them); otherwise every policy row is deleted, as if the project had
/// never been managed.
fn tamper_policies(w: &World, flip: bool) {
    let db = w.h.data_dir().join("vault").join("vault.db");
    let script = if flip {
        "import sqlite3, sys\n\
         c = sqlite3.connect(sys.argv[1])\n\
         rows = c.execute('select id, sealed from policies').fetchall()\n\
         assert rows, 'no policy row'\n\
         for i, s in rows:\n    \
             b = bytearray(s)\n    \
             b[len(b) // 2] ^= 0x10\n    \
             c.execute('update policies set sealed = ? where id = ?', (bytes(b), i))\n\
         c.commit()\n"
    } else {
        "import sqlite3, sys\n\
         c = sqlite3.connect(sys.argv[1])\n\
         assert c.execute('delete from policies').rowcount > 0, 'no policy row'\n\
         c.commit()\n"
    };
    let out = std::process::Command::new(python3())
        .arg("-c")
        .arg(script)
        .arg(&db)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
}

/// Gate 39 with the vault's integrity (M2-07): the managed record changed
/// on disk while the daemon was stopped, one bit of its sealed row flipped
/// or its row deleted (which would leave the project looking unmanaged).
/// The new daemon opens the vault read-only, and the registered launch and
/// `envcloak run -- printenv KEY` in the managed project are both refused
/// `vault_tampered`, with no pending request and nothing released. The
/// positive control: before the change, the launch's request is pending.
///
/// Mutation checked: a vault that failed its integrity check served as if
/// it had passed (`Vault::trusted` always `Ok`, and the daemon's
/// `State::unlocked` and `refuse_if_tampered` not looking at integrity):
/// the record is gone, the launch is `managed_command_mismatch` rather
/// than `vault_tampered`, and this fails. (Either layer alone refuses.)
#[test]
fn a_tampered_record_refuses_every_request() {
    if managed_common::release_run("a_tampered_record_refuses_every_request") {
        return;
    }
    for flip in [true, false] {
        let how = if flip {
            "a flipped bit"
        } else {
            "a deleted row"
        };
        let mut w = World::new(&[]);
        let (launch, _) = w.register_fixture();
        pending_id(&w.request(&launch));
        let _ = w.h.stop_daemon();
        tamper_policies(&w, flip);
        w.h.start_daemon(&[]);
        let pass =
            w.h.secret_file(envcloak_testkit::labels::VAULT_PASSPHRASE, true);
        let home = w.h.home.home();
        let unlocked = w.h.human(
            &home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &pass, true)],
            &[],
        );
        assert_eq!(unlocked.code, 0, "{how}: {}", unlocked.all());
        let pending = w.pending_count();
        let released = w.released();
        let answer = w.request(&launch);
        assert_eq!(error_of(&answer), "vault_tampered", "{how}: {answer}");
        let manifest = w.project.join("envcloak.toml");
        let printenv = format!("printenv {KEY}");
        let out = w.h.agent(
            &home,
            &[
                "run",
                "--manifest",
                manifest.to_str().unwrap(),
                "--",
                "sh",
                "-c",
                printenv.as_str(),
            ],
        );
        assert_eq!(out.status.code(), Some(125), "{how}: {}", text(&out));
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("envcloak: vault_tampered: "),
            "{how}: {}",
            text(&out)
        );
        assert_eq!(
            w.pending_count(),
            pending,
            "{how}: a pending request exists"
        );
        assert_eq!(w.released(), released, "{how}: something was released");
        w.h.assert_swept(how);
    }
}

/// Gate 33 for managed servers: the audit entries of a registration and of
/// one whose passphrase was wrong (`managed_register`), and of a launch
/// refused because its executable changed (`managed_launch`), hold counts
/// and digests only. Read from the sealed log with the vault's key once
/// the daemon stopped: each entry is there (the positive control), the
/// registration's counts are its fixed tokens (the launch's revision,
/// numbers of arguments, variables and bindings, and its digest prefix),
/// the refusal's the part that changed and the old and new device, inode
/// and digest prefix, and no argument, variable value, executable path or
/// marker path appears in any of them.
///
/// Mutation checked: the registration's entry naming the launch by its
/// argv instead of its id: the fixture's path is in the entry, and this
/// fails.
#[test]
fn managed_audit_entries_hold_counts_and_digests_only() {
    if managed_common::release_run("managed_audit_entries_hold_counts_and_digests_only") {
        return;
    }
    let mut w = World::new(&[]);
    let mode = format!("ec-mode-{:016x}", envcloak_testkit::fresh_seed());
    let argv = w.fixture_argv();
    let reg = w.register(json!({"argv": argv, "env": [["MODE", mode]]}));
    let launch = reg["launch"].as_str().unwrap().to_owned();
    let pass_file =
        w.h.secret_file(envcloak_testkit::labels::VAULT_PASSPHRASE, true);
    let wrong = w.h.files().join("wrong");
    std::fs::write(
        &wrong,
        format!("wrong {:016x}\n", envcloak_testkit::fresh_seed()),
    )
    .unwrap();
    let mut input = json!({
        "name": "claude-code/fixture",
        "manifest": w.project.join("envcloak.toml").to_str().unwrap(),
        "argv": argv,
        "passphrase_file": pass_file.to_str().unwrap(),
    });
    let by_agent = w.agent("register", &input);
    assert_eq!(error_of(&by_agent), "proof_refused", "{by_agent}");
    input["passphrase_file"] = json!(wrong.to_str().unwrap());
    let (i, o) = w.io_paths();
    std::fs::write(&i, input.to_string()).unwrap();
    let helper = World::helper_argv("register", &i, &o);
    let helper: Vec<&str> = helper.iter().map(String::as_str).collect();
    let home = w.h.home.home();
    let ran = w.h.human_argv(&home, &helper, &[], &[]);
    assert_eq!(ran.code, 0, "{}", ran.all());
    let failed = w.read_out(&o, "the registration with a wrong passphrase");
    assert_eq!(error_of(&failed), "wrong_passphrase", "{failed}");
    let other = w.fixture.with_extension("other");
    other_build(&other);
    std::fs::rename(&other, &w.fixture).unwrap();
    let changed = w.request(&launch);
    assert_eq!(error_of(&changed), "managed_launch_changed", "{changed}");
    let _ = w.h.stop_daemon();
    let pass = envcloak_core::SecretBytes::copy_from(
        w.h.value(envcloak_testkit::labels::VAULT_PASSPHRASE),
    );
    let vault = envcloak_core::vault::LockedVault::open(&envcloak_core::vault::VaultPaths::under(
        w.h.data_dir(),
    ))
    .unwrap()
    .unlock_with_passphrase(&pass)
    .map_err(|(_, e)| e)
    .unwrap();
    let (entries, _) = vault.read_audit().unwrap();
    drop(vault);
    use envcloak_core::audit::AuditKind;
    let managed: Vec<_> = entries
        .iter()
        .filter(|e| {
            matches!(
                e.record.kind,
                AuditKind::ManagedRegister | AuditKind::ManagedLaunch
            )
        })
        .collect();
    let registered = managed
        .iter()
        .find(|e| {
            e.record.kind == AuditKind::ManagedRegister && e.record.decision.outcome == "registered"
        })
        .unwrap_or_else(|| panic!("no managed_register entry: {managed:?}"));
    assert!(
        managed
            .iter()
            .any(|e| e.record.kind == AuditKind::ManagedRegister
                && e.record.decision.outcome == "wrong_passphrase"),
        "no entry for the wrong passphrase: {managed:?}"
    );
    let names = |e: &envcloak_core::audit::AuditEntry| -> Vec<String> {
        e.record
            .decision
            .counts
            .iter()
            .map(|(k, _)| k.clone())
            .collect()
    };
    assert_eq!(
        names(registered),
        [
            "revision",
            "arguments",
            "variables",
            "bindings",
            "launch_digest"
        ],
        "{registered:?}"
    );
    let refused = managed
        .iter()
        .find(|e| e.record.kind == AuditKind::ManagedLaunch)
        .unwrap_or_else(|| panic!("no managed_launch entry: {managed:?}"));
    assert_eq!(
        refused.record.decision.outcome, "managed_launch_changed",
        "{refused:?}"
    );
    assert_eq!(
        refused.record.decision.reason.as_deref(),
        Some("executable"),
        "{refused:?}"
    );
    for want in ["old_digest", "new_digest", "old_ino", "new_ino"] {
        assert!(
            names(refused).iter().any(|n| n == want),
            "{want}: {refused:?}"
        );
    }
    let fixture = w.fixture.to_str().unwrap().to_owned();
    let marker = w.marker.to_str().unwrap().to_owned();
    for e in &managed {
        assert!(e.record.argv_redacted.is_empty(), "{e:?}");
        assert!(e.record.items.is_empty(), "{e:?}");
        let shown = format!("{:?}", e.record);
        for needle in [
            fixture.as_str(),
            marker.as_str(),
            mode.as_str(),
            "--marker",
            "--var",
        ] {
            assert!(!shown.contains(needle), "{needle} in {shown}");
        }
    }
}

/// Moves `path` away to `aside`, and renames `with` into its place.
fn swap_in(path: &Path, aside: &Path, with: &Path) {
    std::fs::rename(path, aside).unwrap();
    std::fs::rename(with, path).unwrap();
}

/// The request for `launch` refused `managed_launch_changed` with no
/// pending request and nothing more released.
fn refused_changed(w: &mut World, launch: &str, part: &str) {
    let pending = w.pending_count();
    let released = w.released();
    let answer = w.request(launch);
    assert_eq!(error_of(&answer), "managed_launch_changed", "{answer}");
    assert_eq!(w.pending_count(), pending, "a pending request exists");
    assert_eq!(w.released(), released, "something was released");
    w.h.expect_log(
        &format!("managed launch refused reason=managed_launch_changed part={part}"),
        Duration::from_secs(10),
    );
}

/// F-72, D-33: the registered launch's executable replaced at the same
/// path by another build (renamed over), or moved away and another file
/// put in its place, with argv unchanged, and the registered working
/// directory replaced by another renamed over it, are each refused
/// `managed_launch_changed` before any pending request exists, with no
/// value released, under no grant and under a live session grant; the
/// launch as registered runs between them (the positive control), in the
/// registered working directory. The managed directory itself renamed
/// over by another with the same manifest leaves the launch naming a
/// project without a record: `managed_command_mismatch`, likewise before
/// any pending request.
///
/// Mutations checked: the target-identity comparison removed, keeping
/// only the launch id and argv (F-72's original predicate: the daemon's
/// check opens the recorded file and takes it, and the sealed copy is not
/// compared): the replaced executable is started, and this fails under
/// no grant (a pending request) and under the session grant (a release).
/// A request naming a launch with descriptors for a project without a
/// record taken as malformed (`invalid_params`) rather than refused: this
/// fails.
#[test]
fn a_changed_launch_is_refused_before_any_pending_request() {
    if managed_common::release_run("a_changed_launch_is_refused_before_any_pending_request") {
        return;
    }
    let mut w = World::new(&[]);
    let work = w.project.join("work");
    std::fs::create_dir(&work).unwrap();
    let argv = w.fixture_argv();
    let reg = w.register(json!({"argv": argv, "cwd": work.to_str().unwrap()}));
    let launch = reg["launch"].as_str().unwrap().to_owned();
    let bin = w.fixture.parent().unwrap().to_path_buf();
    let original = bin.join("fixture.original");
    let other = bin.join("fixture.other");
    // No grant: renamed over by another build.
    other_build(&other);
    swap_in(&w.fixture, &original, &other);
    refused_changed(&mut w, &launch, "executable");
    std::fs::rename(&original, &w.fixture).unwrap();
    // The positive control, and a live session grant.
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let answer = w.request(&launch);
    assert!(started(&answer), "{answer}");
    assert_eq!(reported_identity(&report(&answer)), receipt_identity(&reg));
    assert_eq!(
        report(&answer)["cwd_sha256"],
        sha256_hex(work.as_os_str().as_encoded_bytes())
    );
    // Under the grant: moved away, another file in its place.
    std::fs::rename(&w.fixture, &original).unwrap();
    other_build(&w.fixture);
    refused_changed(&mut w, &launch, "executable");
    std::fs::rename(&original, &w.fixture).unwrap();
    // The registered working directory renamed over by another.
    let fresh = w.project.join("work.new");
    std::fs::create_dir(&fresh).unwrap();
    std::fs::rename(&work, w.project.join("work.aside")).unwrap();
    std::fs::rename(&fresh, &work).unwrap();
    refused_changed(&mut w, &launch, "working_directory");
    // The managed directory itself renamed over by another holding the
    // same manifest: the launch names a project that has no record now.
    let fresh = w.h.home.root().join("fixture.new");
    std::fs::create_dir(&fresh).unwrap();
    std::fs::copy(w.project.join("envcloak.toml"), fresh.join("envcloak.toml")).unwrap();
    std::fs::rename(&w.project, w.h.home.root().join("fixture.aside")).unwrap();
    std::fs::rename(&fresh, &w.project).unwrap();
    let pending = w.pending_count();
    let released = w.released();
    let answer = w.request(&launch);
    assert_eq!(error_of(&answer), "managed_command_mismatch", "{answer}");
    assert_eq!(w.pending_count(), pending, "a pending request exists");
    assert_eq!(w.released(), released, "something was released");
    w.h.assert_swept("after the changes");
}

/// D-33: a launch registered by bare name runs the registered absolute
/// executable, found once on the declared `PATH`, though a different
/// program of that name comes first in the client's and the daemon's
/// `PATH`.
///
/// Mutation checked: `argv[0]` resolved through the daemon's own `PATH`
/// rather than the declared one: the decoy is registered, and this fails.
#[test]
fn a_bare_name_runs_the_registered_executable() {
    if managed_common::release_run("a_bare_name_runs_the_registered_executable") {
        return;
    }
    let decoys = tempfile::Builder::new()
        .prefix("ecd")
        .tempdir_in("/tmp")
        .unwrap();
    let decoy = decoys.path().join("ec-launch-fixture");
    envcloak_e2e::write_script(&decoy, "#!/bin/sh\nexit 3\n");
    let path = format!(
        "{}:{}",
        decoys.path().display(),
        envcloak_testkit::TEST_PATH
    );
    let mut w = World::new(&[("PATH", &path)]);
    let bin = w.fixture.parent().unwrap().to_str().unwrap().to_owned();
    let argv = w.fixture_argv_for("ec-launch-fixture");
    let reg = w.register(json!({"argv": argv, "path_env": bin}));
    let launch = reg["launch"].as_str().unwrap().to_owned();
    assert_eq!(
        reg["receipt"]["executable"],
        w.fixture.to_str().unwrap(),
        "{reg}"
    );
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let answer = w.request(&launch);
    assert!(started(&answer), "{answer}");
    assert_eq!(reported_identity(&report(&answer)), receipt_identity(&reg));
    assert_eq!(report(&answer)["vars"][KEY], w.key_digest());
}

/// D-33, SPEC §6.6: the server's environment is the launch's: `LD_PRELOAD`
/// naming a file that is not there, `NODE_OPTIONS=--require ...`,
/// `PYTHONPATH` and `DYLD_LIBRARY_PATH`, set for the client and the
/// daemon alike, never reach it (it reports their names absent), and it
/// has only the passthrough list, `PATH` and the key.
///
/// Mutation checked: the bridge's and the daemon's environment inherited
/// (the daemon passing its whole environment to the runner, and the
/// environment builder taking every inherited variable): the
/// code-selecting variables reach the server and this fails.
#[test]
fn the_server_gets_only_the_launch_environment() {
    if managed_common::release_run("the_server_gets_only_the_launch_environment") {
        return;
    }
    let mut w = World::new(&[
        ("LD_PRELOAD", "/nonexistent/ec-preload.so"),
        ("NODE_OPTIONS", "--require /nonexistent/ec.js"),
        ("PYTHONPATH", "/nonexistent"),
        ("DYLD_LIBRARY_PATH", "/nonexistent"),
    ]);
    let (launch, _) = w.register_fixture();
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let answer = w.request(&launch);
    assert!(started(&answer), "{answer}");
    let r = report(&answer);
    for v in [
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "PYTHONPATH",
        "DYLD_LIBRARY_PATH",
    ] {
        assert!(r["vars"][v].is_null(), "{v} reached the server: {r}");
    }
    assert_eq!(r["vars"][KEY], w.key_digest(), "{r}");
    let allowed = [
        KEY, "HOME", "USER", "LOGNAME", "LANG", "TZ", "TMPDIR", "PATH",
    ];
    for name in r["env"].as_array().unwrap() {
        let name = name.as_str().unwrap();
        assert!(
            allowed.contains(&name) || name.starts_with("LC_"),
            "{name} reached the server: {r}"
        );
    }
}

/// SPEC §6.6, D-33: a declaration that sets a code-selecting variable
/// (`NODE_OPTIONS`, `LD_PRELOAD`) or gives its interpreter a code-loading
/// option (`node -r x.js server.js`) is refused `code_selecting_env` at
/// registration (with its reason) and no record is written: the project
/// stays unmanaged (a plain run of it is pending, not refused).
///
/// Mutation checked: the declaration's variables not checked: the
/// `NODE_OPTIONS` declaration is registered and this fails.
#[test]
fn code_selecting_declarations_are_refused_at_registration() {
    if managed_common::release_run("code_selecting_declarations_are_refused_at_registration") {
        return;
    }
    let mut w = World::new(&[]);
    let argv = w.fixture_argv();
    for (decl, reason) in [
        (
            json!({"argv": argv, "env": [["NODE_OPTIONS", "--require /x.js"]]}),
            "code_selecting_variable",
        ),
        (
            json!({"argv": argv, "env": [["LD_PRELOAD", "/x.so"]]}),
            "code_selecting_variable",
        ),
        (
            json!({"argv": ["node", "-r", "/x.js", "/srv/server.js"]}),
            "interpreter_option",
        ),
    ] {
        let reg = w.register(decl);
        assert_eq!(error_of(&reg), "code_selecting_env", "{reg}");
        assert_eq!(reg["reason"], reason, "{reg}");
    }
    let manifest = w.project.join("envcloak.toml");
    let home = w.h.home.home();
    let out = w.h.agent(
        &home,
        &[
            "run",
            "--manifest",
            manifest.to_str().unwrap(),
            "--",
            "true",
        ],
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("approval_required"),
        "{}",
        text(&out)
    );
}

/// Gate 23 for registration (T9-3, F-70): `managed.register` from an
/// agent's process, and from a process without a terminal, is refused
/// `proof_refused` before the passphrase is checked; a wrong passphrase
/// is `wrong_passphrase`; the person on a terminal of their own registers
/// (the positive control).
///
/// Mutation checked: registration without the prover check: the agent's
/// registration succeeds and this fails.
#[test]
fn registration_needs_a_terminal_proof() {
    if managed_common::release_run("registration_needs_a_terminal_proof") {
        return;
    }
    let mut w = World::new(&[]);
    let pass =
        w.h.secret_file(envcloak_testkit::labels::VAULT_PASSPHRASE, true);
    let input = json!({
        "name": "claude-code/fixture",
        "manifest": w.project.join("envcloak.toml").to_str().unwrap(),
        "argv": w.fixture_argv(),
        "passphrase_file": pass.to_str().unwrap(),
    });
    let by_agent = w.agent("register", &input);
    assert_eq!(error_of(&by_agent), "proof_refused", "{by_agent}");
    // No terminal: started by the test itself.
    let no_terminal = w.no_terminal("register", &input);
    assert_eq!(error_of(&no_terminal), "proof_refused", "{no_terminal}");
    // A wrong passphrase, from the person.
    let wrong = w.h.files().join("wrong");
    std::fs::write(
        &wrong,
        format!("wrong {:016x}\n", envcloak_testkit::fresh_seed()),
    )
    .unwrap();
    let mut bad = input.clone();
    bad["passphrase_file"] = json!(wrong.to_str().unwrap());
    let (i, o) = w.io_paths();
    std::fs::write(&i, bad.to_string()).unwrap();
    let argv = World::helper_argv("register", &i, &o);
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let home = w.h.home.home();
    let ran = w.h.human_argv(&home, &argv, &[], &[]);
    assert_eq!(ran.code, 0, "{}", ran.all());
    let wrong = w.read_out(&o, "the registration with a wrong passphrase");
    assert_eq!(error_of(&wrong), "wrong_passphrase", "{wrong}");
    // The person, as the positive control.
    let (launch, _) = w.register_fixture();
    assert_eq!(launch.len(), 26);
}

/// CR-2: an update is built from the declaration stored in the record.
/// After the fixture's executable is replaced (the launch is then
/// refused), `managed.update_plan` with no changes shows the old and the
/// new identity; one with a new argv, working directory, a variable set
/// and one unset shows each; one setting `NODE_OPTIONS` is
/// `code_selecting_env`; an agent's plan, and one from a process without a
/// terminal, is answered nothing; an update whose statement changed
/// since its plan is `statement_mismatch`; the update with the proof
/// makes revision 2, which the session grant made for revision 1 does not
/// cover (a fresh pending request), and once approved, it runs the new
/// image.
///
/// Mutation checked: a grant that ignores the launch revision: the
/// request after the update is started at once, and this fails.
#[test]
fn an_update_comes_from_the_stored_declaration() {
    if managed_common::release_run("an_update_comes_from_the_stored_declaration") {
        return;
    }
    let mut w = World::new(&[]);
    let argv = w.fixture_argv();
    let reg = w.register(json!({"argv": argv, "env": [["MODE", "dev"]]}));
    let launch = reg["launch"].as_str().unwrap().to_owned();
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let answer = w.request(&launch);
    assert!(started(&answer), "{answer}");
    assert_eq!(reported_identity(&report(&answer)), receipt_identity(&reg));
    // Another build renamed over the executable.
    let other = w.fixture.with_extension("other");
    other_build(&other);
    std::fs::rename(&other, &w.fixture).unwrap();
    let changed = w.request(&launch);
    assert_eq!(error_of(&changed), "managed_launch_changed", "{changed}");
    let by_agent = w.agent("plan", &json!({"launch": launch}));
    assert!(by_agent["statement"].is_null(), "{by_agent}");
    let no_terminal = w.no_terminal("plan", &json!({"launch": launch}));
    assert!(no_terminal["statement"].is_null(), "{no_terminal}");
    let plan = w.person("plan", json!({"launch": launch}));
    let st = plan["statement"].clone();
    assert_eq!(st["revision"], 1, "{plan}");
    assert_eq!(st["old"]["identity"], receipt_identity(&reg), "{plan}");
    assert_eq!(st["new"]["identity"], file_identity(&w.fixture), "{plan}");
    let names = |v: &Value| -> Vec<String> {
        serde_json::from_value(v["env_names"].clone()).unwrap_or_default()
    };
    assert!(names(&st["new"]).contains(&"MODE".to_owned()), "{plan}");
    let sub = w.project.join("sub");
    std::fs::create_dir(&sub).unwrap();
    let mut argv = w.fixture_argv();
    argv.as_array_mut().unwrap().push(json!("--var"));
    argv.as_array_mut().unwrap().push(json!("LEVEL"));
    let changes = json!({
        "argv": argv,
        "cwd": sub.to_str().unwrap(),
        "set_env": [["LEVEL", "2"]],
        "unset_env": ["MODE"],
    });
    let shown = w.person("plan", json!({"launch": launch, "changes": changes}));
    let new = &shown["statement"]["new"];
    assert_eq!(new["cwd"], sub.to_str().unwrap(), "{shown}");
    assert!(names(new).contains(&"LEVEL".to_owned()), "{shown}");
    assert!(!names(new).contains(&"MODE".to_owned()), "{shown}");
    assert!(
        names(&shown["statement"]["old"]).contains(&"MODE".to_owned()),
        "{shown}"
    );
    assert_ne!(shown["statement"]["digest"], st["digest"], "{shown}");
    let refused = w.person(
        "plan",
        json!({"launch": launch, "changes": {"set_env": [["NODE_OPTIONS", "--require /x.js"]]}}),
    );
    assert_eq!(error_of(&refused), "code_selecting_env", "{refused}");
    let digest = st["digest"].as_str().unwrap().to_owned();
    let mismatch = w.person(
        "update",
        json!({"launch": launch, "digest": "0".repeat(64)}),
    );
    assert_eq!(error_of(&mismatch), "statement_mismatch", "{mismatch}");
    let updated = w.person("update", json!({"launch": launch, "digest": digest}));
    assert_eq!(updated["revision"], 2, "{updated}");
    let next = w.request(&launch);
    w.approve(&pending_id(&next));
    let answer = w.request(&launch);
    assert!(started(&answer), "{answer}");
    assert_eq!(
        reported_identity(&report(&answer)),
        file_identity(&w.fixture)
    );
    w.h.assert_swept("after the update");
}

/// D-18: a bridged server's record holds its origin and header names, and
/// each of its manifest's bindings carries the origin's digest. A request
/// naming the registered origin and header names is pending (the positive
/// control); one with an edited origin is `managed_command_mismatch`, and
/// so is one with an edited origin and a manifest edited to its digest,
/// until the server is registered again with that origin, after which the
/// new binding asks for approval.
///
/// Mutation checked: the origin treated as a plain manifest field (the
/// request's origin not compared with the record's): the edited origin's
/// request is pending, and this fails.
#[test]
fn an_edited_origin_is_refused_until_registered_again() {
    if managed_common::release_run("an_edited_origin_is_refused_until_registered_again") {
        return;
    }
    let mut w = World::new(&[]);
    let origin = "https://api.example.test";
    let edited = "https://api.example.test:8443";
    let project = w.h.home.root().join("remote");
    std::fs::create_dir_all(&project).unwrap();
    let manifest = project.join("envcloak.toml");
    let write_manifest = |origin: &str| {
        let suffix = envcloak_policy::managed::bridge_binding_suffix(origin);
        std::fs::write(
            &manifest,
            format!(
                "[project]\nname = \"remote\"\n\n[env]\nAPI_KEY{suffix} = \"stripe/fixture\"\n"
            ),
        )
        .unwrap();
    };
    write_manifest(origin);
    let manifest_text = manifest.to_str().unwrap().to_owned();
    let register = |w: &mut World, origin: &str| {
        let reg = w.person(
            "register",
            json!({
                "name": "claude-code/remote",
                "manifest": manifest_text,
                "origin": origin,
                "headers": ["Authorization"],
            }),
        );
        assert_eq!(reg["receipt"]["transport"], "bridge", "{reg}");
    };
    register(&mut w, origin);
    let ask = |w: &mut World, origin: &str| {
        w.agent(
            "request",
            &json!({
                "manifest": manifest_text,
                "origin": origin,
                "headers": ["Authorization"],
            }),
        )
    };
    let declared = ask(&mut w, origin);
    pending_id(&declared);
    let pending = w.pending_count();
    let answer = ask(&mut w, edited);
    assert_eq!(error_of(&answer), "managed_command_mismatch", "{answer}");
    write_manifest(edited);
    let answer = ask(&mut w, edited);
    assert_eq!(error_of(&answer), "managed_command_mismatch", "{answer}");
    assert_eq!(w.pending_count(), pending, "a pending request exists");
    register(&mut w, edited);
    let answer = ask(&mut w, edited);
    pending_id(&answer);
}

/// D-33's classes and receipts: a `script` launch (`sh /abs/server.sh`)
/// registers `checked_at_rest` with its entry file's identity and a
/// receipt that says what is not checked, runs, and is refused once its
/// entry file changed; a `package_runner` launch (`npx -y <package>`)
/// registers `checked_at_rest` with its label; a native file whose image
/// cannot be bound (an `$ORIGIN` run path on Linux; no code directory on
/// macOS) registers `checked_at_rest`.
///
/// Mutation checked: the entry file's check removed: the changed script
/// starts, and this fails.
#[test]
fn launch_classes_and_their_receipts() {
    if managed_common::release_run("launch_classes_and_their_receipts") {
        return;
    }
    let mut w = World::new(&[]);
    // A script, through an interpreter.
    let script = w.project.join("server.sh");
    let body = format!(
        "#!/bin/sh\nexec {} --var {KEY}\n",
        envcloak_e2e::quoted(w.fixture.to_str().unwrap())
    );
    envcloak_e2e::write_script(&script, &body);
    let reg = w.register(json!({"argv": ["sh", script.to_str().unwrap()]}));
    let receipt = &reg["receipt"];
    assert_eq!(receipt["class"], "script", "{reg}");
    assert_eq!(receipt["strength"], "checked_at_rest", "{reg}");
    assert_eq!(receipt["entry"], script.to_str().unwrap(), "{reg}");
    assert_eq!(
        receipt["entry_identity"],
        format!("sha256:{}", sha256_hex(body.as_bytes())),
        "{reg}"
    );
    assert!(
        receipt["sentences"]
            .to_string()
            .contains("not the modules it loads"),
        "{reg}"
    );
    let launch = reg["launch"].as_str().unwrap().to_owned();
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let answer = w.request(&launch);
    assert!(started(&answer), "{answer}");
    assert_eq!(report(&answer)["vars"][KEY], w.key_digest());
    // The entry file changed in place.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&script)
        .unwrap();
    f.write_all(b"# changed\n").unwrap();
    drop(f);
    let answer = w.request(&launch);
    assert_eq!(error_of(&answer), "managed_launch_changed", "{answer}");
    w.h.expect_log(
        "managed launch refused reason=managed_launch_changed part=entry_file",
        Duration::from_secs(10),
    );
    // A package runner: a stand-in `npx` on the declared PATH.
    let tools = w.project.join("tools");
    std::fs::create_dir(&tools).unwrap();
    envcloak_e2e::write_script(&tools.join("npx"), "#!/bin/sh\nexit 0\n");
    let reg = w.person(
        "register",
        json!({
            "name": "claude-code/packaged",
            "manifest": w.project.join("envcloak.toml").to_str().unwrap(),
            "argv": ["npx", "-y", "ec-fixture-server"],
            "path_env": tools.to_str().unwrap(),
        }),
    );
    assert_eq!(reg["receipt"]["class"], "package_runner", "{reg}");
    assert_eq!(reg["receipt"]["strength"], "checked_at_rest", "{reg}");
    assert!(
        reg["receipt"]["sentences"].to_string().contains("npx"),
        "{reg}"
    );
    // A native file whose image cannot be bound.
    let unbound = w.project.join("bin").join("unbound");
    if cfg!(target_os = "linux") {
        let src = w.h.files().join("origin.c");
        std::fs::write(&src, "int main(void) { return 0; }\n").unwrap();
        let built = std::process::Command::new("cc")
            .arg("-o")
            .arg(&unbound)
            .arg("-Wl,-rpath,$ORIGIN/../lib")
            .arg(&src)
            .output()
            .unwrap_or_else(|e| panic!("cc is needed: {e}"));
        assert!(built.status.success(), "{}", text(&built));
    } else {
        std::fs::copy(managed_common::fixture_bin(), &unbound).unwrap();
        let stripped = std::process::Command::new("/usr/bin/codesign")
            .arg("--remove-signature")
            .arg(&unbound)
            .output()
            .unwrap();
        assert!(stripped.status.success(), "{}", text(&stripped));
    }
    let reg = w.person(
        "register",
        json!({
            "name": "claude-code/unbound",
            "manifest": w.project.join("envcloak.toml").to_str().unwrap(),
            "argv": [unbound.to_str().unwrap()],
        }),
    );
    assert_eq!(reg["receipt"]["class"], "native", "{reg}");
    assert_eq!(reg["receipt"]["strength"], "checked_at_rest", "{reg}");
    w.h.assert_swept("after the classes");
}

/// Writes `from`'s bytes over `to` in place: same inode, new contents.
fn rewrite_in_place(to: &Path, from: &Path) {
    let bytes = std::fs::read(from).unwrap();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(to)
        .unwrap();
    f.write_all(&bytes).unwrap();
    f.sync_all().unwrap();
}

/// How many times the daemons' logs say the daemon stopped at `site`.
fn paused(w: &World, site: &str) -> usize {
    w.logs().matches(&format!("paused at {site}")).count()
}

/// Waits until the daemon stopped at `site` `n` times.
fn wait_paused(w: &World, site: &str, n: usize) {
    let end = std::time::Instant::now() + Duration::from_secs(60);
    while paused(w, site) < n {
        assert!(
            std::time::Instant::now() < end,
            "the daemon never stopped at {site}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The client asks for `launch` while the daemon is held at `site`
/// (`release` renamed to `held` holds it), `change` runs there, and the
/// daemon goes on: the client's answer.
fn at_barrier(
    w: &mut World,
    launch: &str,
    gate: (&Path, &Path),
    site: &str,
    change: &dyn Fn(&World),
) -> Value {
    let (release, held) = gate;
    let stops = paused(w, site);
    std::fs::rename(release, held).unwrap();
    let out = w.agent_background("request", &json!({"launch": launch, "send": ["report"]}));
    wait_paused(w, site, stops + 1);
    change(w);
    std::fs::rename(held, release).unwrap();
    w.wait_out(&out, Duration::from_secs(60), "the client at the barrier")
}

/// A daemon that stops at `site` while `held` exists in place of
/// `release`: the world, and the two names.
fn held_world(site: &str) -> (World, tempfile::TempDir) {
    let gate = tempfile::Builder::new()
        .prefix("ecg")
        .tempdir_in("/tmp")
        .unwrap();
    let release = gate.path().join("release");
    std::fs::write(&release, b"").unwrap();
    let w = World::new(&[
        ("ENVCLOAK_TEST_PAUSE", site),
        ("ENVCLOAK_TEST_PAUSE_RELEASE", release.to_str().unwrap()),
    ]);
    (w, gate)
}

/// D-33's spawn binding at the `testing` check-to-spawn barrier (after
/// the daemon's check, before the runner starts): on Linux, an in-place
/// rewrite of the original and a rename-over each made after the final
/// sealed-copy check, the launch runs the approved image (its digest),
/// never the replacement; on macOS, a rename-over at the barrier fails
/// the suspended child's code directory hash check: the child is killed
/// before it resumes (its start marker never appears) and the client is
/// answered `managed_launch_changed`.
///
/// Mutations checked: Linux, the source path reopened instead of the
/// prepared copy (the rename-over's build runs, and this fails); macOS,
/// the child resumed before the daemon's answer (the start marker
/// appears, and this fails).
#[test]
fn the_approved_image_runs_whatever_happens_at_the_barrier() {
    if managed_common::release_run("the_approved_image_runs_whatever_happens_at_the_barrier") {
        return;
    }
    let site = "launch.checked";
    let (mut w, gate) = held_world(site);
    let release = gate.path().join("release");
    let held = gate.path().join("held");
    let (launch, reg, _) = w.launched();
    let original = w.h.files().join("fixture.copy");
    std::fs::copy(&w.fixture, &original).unwrap();
    let other = w.h.files().join("fixture.other");
    other_build(&other);
    let rename_over = |w: &World| {
        let tmp = w.fixture.with_extension("new");
        std::fs::copy(&other, &tmp).unwrap();
        std::fs::rename(&tmp, &w.fixture).unwrap();
    };
    // The marker of the positive control's run.
    std::fs::rename(&w.marker, w.marker.with_extension("seen")).unwrap();
    if cfg!(target_os = "linux") {
        let answer = at_barrier(&mut w, &launch, (&release, &held), site, &|w| {
            rewrite_in_place(&w.fixture, &other);
        });
        assert!(started(&answer), "{answer}");
        assert_eq!(reported_identity(&report(&answer)), receipt_identity(&reg));
        rewrite_in_place(&w.fixture, &original);
        let answer = at_barrier(&mut w, &launch, (&release, &held), site, &rename_over);
        assert!(started(&answer), "{answer}");
        assert_eq!(reported_identity(&report(&answer)), receipt_identity(&reg));
    } else {
        let answer = at_barrier(&mut w, &launch, (&release, &held), site, &rename_over);
        assert_eq!(error_of(&answer), "managed_launch_changed", "{answer}");
        assert!(
            !appears(&w.marker, Duration::from_secs(2)),
            "the refused child ran"
        );
    }
    w.h.assert_swept("after the barrier");
}

/// D-33 on macOS: the runner starts the server suspended and lets it run
/// only on the daemon's `Confirmed`. With the daemon held after it
/// received the runner's `ConfirmSpawn` and before it answers (a `testing`
/// barrier), the server has run nothing (its start marker, its first act,
/// never appears, though the test waits two seconds); once the daemon
/// answers, it runs (the marker appears: the positive control) and serves
/// the client as the record's image.
///
/// Mutation checked: the runner resuming the child before the daemon's
/// answer: the marker appears while the daemon is held, and this fails.
#[test]
fn a_suspended_server_runs_nothing_until_the_daemon_confirms() {
    if managed_common::release_run("a_suspended_server_runs_nothing_until_the_daemon_confirms") {
        return;
    }
    if !cfg!(target_os = "macos") {
        eprintln!(
            "a_suspended_server_runs_nothing_until_the_daemon_confirms: macOS only (Linux runs \
             the sealed copy and asks no confirmation)"
        );
        return;
    }
    let site = "launch.confirm";
    let (mut w, gate) = held_world(site);
    let release = gate.path().join("release");
    let held = gate.path().join("held");
    let (launch, reg, _) = w.launched();
    std::fs::rename(&w.marker, w.marker.with_extension("seen")).unwrap();
    let stops = paused(&w, site);
    std::fs::rename(&release, &held).unwrap();
    let out = w.agent_background("request", &json!({"launch": launch, "send": ["report"]}));
    wait_paused(&w, site, stops + 1);
    assert!(
        !appears(&w.marker, Duration::from_secs(2)),
        "the server ran before the daemon answered"
    );
    std::fs::rename(&held, &release).unwrap();
    let answer = w.wait_out(&out, Duration::from_secs(60), "the client");
    assert!(started(&answer), "{answer}");
    assert_eq!(reported_identity(&report(&answer)), receipt_identity(&reg));
    assert!(w.marker.exists(), "the confirmed server never ran");
    w.h.assert_swept("after the confirmation");
}

/// D-33: the source changed while the daemon copies it into the sealed
/// memory file (a `testing` barrier inside the copy): the launch either
/// runs the exact approved image or is refused before release; it never
/// runs anything else (Linux).
///
/// Mutation checked: the digest taken of the file before copying instead
/// of the sealed copy: the rewritten bytes run, and this fails.
#[test]
fn a_source_changed_while_copied_never_runs() {
    if managed_common::release_run("a_source_changed_while_copied_never_runs") {
        return;
    }
    if !cfg!(target_os = "linux") {
        eprintln!("a_source_changed_while_copied_never_runs: Linux only (sealed copies)");
        return;
    }
    let site = "launch.copying";
    let (mut w, gate) = held_world(site);
    let release = gate.path().join("release");
    let held = gate.path().join("held");
    let (launch, reg, _) = w.launched();
    let other = w.h.files().join("fixture.other");
    other_build(&other);
    let answer = at_barrier(&mut w, &launch, (&release, &held), site, &|w| {
        rewrite_in_place(&w.fixture, &other);
    });
    if started(&answer) {
        assert_eq!(reported_identity(&report(&answer)), receipt_identity(&reg));
    } else {
        assert_eq!(error_of(&answer), "managed_launch_changed", "{answer}");
    }
}
