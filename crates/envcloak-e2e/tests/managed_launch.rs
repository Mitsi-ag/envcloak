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

/// The agent's client names `launch` but hands over no descriptors, too
/// few, or a lifeline it can only write: each refused
/// `managed_command_mismatch` with no pending request and nothing
/// released, to the client or a runner.
fn refused_without_ends(w: &mut World, launch: &str, when: &str) {
    let pending = w.pending_count();
    let released = w.released();
    for mode in ["none", "too_few", "wrong_access"] {
        let answer = w.agent(
            "request",
            &json!({"launch": launch, "fds": mode, "send": ["report"], "hold_ms": 0}),
        );
        assert_eq!(
            error_of(&answer),
            "managed_command_mismatch",
            "{when}, {mode}: {answer}"
        );
    }
    assert_eq!(
        w.pending_count(),
        pending,
        "{when}: a pending request exists"
    );
    assert_eq!(w.released(), released, "{when}: something was released");
}

/// Gate 39, R-M2-24: a request that names the registered launch is the
/// launch's only with the ends its runner is started on. Without them
/// (none, too few, one of the wrong access) it is refused
/// `managed_command_mismatch` with no pending request and nothing
/// released, under no grant and under a live session grant, whose own
/// requests before and after are the positive controls; the daemon is
/// swept clean after.
///
/// Mutations checked: the request check's refusal of a managed request
/// without ends removed (`check_request`'s `has_fds` guard made
/// `let _ = has_fds;`): the requests reach the decision's backstop
/// (`route`), are refused `internal`, and this fails; with the backstop
/// also made to route them to the client, the first is pending under no
/// grant, and this fails.
#[test]
fn a_launch_asked_for_without_its_ends_is_refused() {
    let mut w = World::new(&[]);
    let (launch, _) = w.register_fixture();
    refused_without_ends(&mut w, &launch, "no grant");
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let answer = w.request(&launch);
    assert!(started(&answer), "{answer}");
    refused_without_ends(&mut w, &launch, "a live session grant");
    let again = w.request(&launch);
    assert!(started(&again), "{again}");
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
    w.expect_trace(&format!(
        "managed launch refused reason=managed_launch_changed part={part}"
    ));
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
/// agent's process (on the agent's pipes, and on a terminal the agent
/// opened for it), and from a process without a terminal, is refused
/// `proof_refused` before the passphrase is checked; a wrong passphrase
/// is `wrong_passphrase`; the person on a terminal of their own registers
/// (the positive control).
///
/// Mutation checked: registration without the prover check: the agent's
/// registration succeeds and this fails.
#[test]
fn registration_needs_a_terminal_proof() {
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
    // On a terminal of its own that the agent opened (Python's
    // `pty.spawn`): its session, not the person's.
    let (i, o) = w.io_paths();
    std::fs::write(&i, input.to_string()).unwrap();
    let argv = World::helper_argv("register", &i, &o);
    let quoted: Vec<String> = argv.iter().map(|a| envcloak_e2e::quoted(a)).collect();
    let line = format!(
        "{} -c {} {}",
        envcloak_e2e::quoted(envcloak_e2e::python3().to_str().unwrap()),
        envcloak_e2e::quoted("import pty, sys; pty.spawn(sys.argv[1:])"),
        quoted.join(" ")
    );
    let home = w.h.home.home();
    let ran = w.h.agent_line(&home, &line);
    assert!(ran.status.success(), "{}", text(&ran));
    let on_pty = w.read_out(&o, "the agent's registration on a terminal of its own");
    assert_eq!(error_of(&on_pty), "proof_refused", "{on_pty}");
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
                "[project]\nname = \"remote\"\n\n[env]\nAUTHORIZATION{suffix} = \"stripe/fixture\"\n"
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
    // The declared bridge asked for without descriptors: refused, with no
    // pending request (gate 39's bridge half).
    let pending = w.pending_count();
    let bare = w.agent(
        "request",
        &json!({
            "manifest": manifest_text,
            "origin": edited,
            "headers": ["Authorization"],
            "fds": "none",
        }),
    );
    assert_eq!(error_of(&bare), "managed_command_mismatch", "{bare}");
    assert_eq!(w.pending_count(), pending, "a pending request exists");
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
    w.expect_trace("managed launch refused reason=managed_launch_changed part=entry_file");
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

/// What runs is the file checked (Codex review of M2-27): a script whose
/// entry is named through a link runs the file the link named at
/// registration, though the link points at another file since; a `#!`
/// file whose line is `/usr/bin/env NAME` runs the `NAME` found on the
/// declared `PATH` at registration, though a program of that name comes
/// first on that `PATH` since; and a `#!` line whose option loads code is
/// refused at registration. Each started launch is the positive control:
/// it reports the key.
///
/// Mutations checked: the declared entry path kept in the argv (the link
/// runs, now the other file, which reports nothing), and a `#!` file run
/// by its path (the kernel's `env` finds the newer program, which reports
/// nothing): each fails here.
#[test]
fn the_entry_and_interpreter_checked_are_the_ones_that_run() {
    let mut w = World::new(&[]);
    let fixture = envcloak_e2e::quoted(w.fixture.to_str().unwrap());
    let real = w.project.join("server.sh");
    envcloak_e2e::write_script(&real, &format!("#!/bin/sh\nexec {fixture} --var {KEY}\n"));
    let other = w.project.join("other.sh");
    envcloak_e2e::write_script(&other, "#!/bin/sh\nexit 7\n");
    let link = w.project.join("link.sh");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let reg = w.register(json!({"argv": ["sh", link.to_str().unwrap()]}));
    assert_eq!(reg["receipt"]["entry"], real.to_str().unwrap(), "{reg}");
    let launch = reg["launch"].as_str().unwrap().to_owned();
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&other, &link).unwrap();
    let answer = w.request(&launch);
    assert!(started(&answer), "{answer}");
    assert_eq!(report(&answer)["vars"][KEY], w.key_digest(), "{answer}");
    // `#!/usr/bin/env NAME`, NAME found on the declared PATH once.
    let early = w.project.join("early");
    let late = w.project.join("late");
    std::fs::create_dir(&early).unwrap();
    std::fs::create_dir(&late).unwrap();
    // A link `sh` to the system shell (a copy of a platform binary is
    // killed on macOS by its launch constraints, and a link of another
    // name would be a disguised launcher): the interpreter checked is the
    // link's canonical file.
    std::os::unix::fs::symlink("/bin/sh", late.join("sh")).unwrap();
    let by_env = w.project.join("by-env.sh");
    envcloak_e2e::write_script(
        &by_env,
        &format!("#!/usr/bin/env sh\nexec {fixture} --var {KEY}\n"),
    );
    let reg = w.person(
        "register",
        json!({
            "name": "claude-code/by-env",
            "manifest": w.project.join("envcloak.toml").to_str().unwrap(),
            "argv": [by_env.to_str().unwrap()],
            "path_env": format!("{}:{}:/usr/bin:/bin", early.display(), late.display()),
        }),
    );
    assert_eq!(reg["receipt"]["class"], "script", "{reg}");
    assert_eq!(
        reg["receipt"]["executable"],
        std::fs::canonicalize("/bin/sh").unwrap().to_str().unwrap(),
        "{reg}"
    );
    let launch = reg["launch"].as_str().unwrap().to_owned();
    envcloak_e2e::write_script(&early.join("sh"), "#!/bin/sh\nexit 7\n");
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let answer = w.request(&launch);
    assert!(started(&answer), "{answer}");
    assert_eq!(report(&answer)["vars"][KEY], w.key_digest(), "{answer}");
    // A `#!` line whose option loads code.
    let loads = w.project.join("loads.sh");
    envcloak_e2e::write_script(&loads, "#!/bin/sh -c\nexit 0\n");
    let reg = w.register(json!({"argv": [loads.to_str().unwrap()]}));
    assert_eq!(error_of(&reg), "code_selecting_env", "{reg}");
    assert_eq!(reg["reason"], "interpreter_option", "{reg}");
    w.h.assert_swept("after the entries");
}

/// D-18, Codex review of M2-27: each header of a bridged server has the
/// one binding its name and the origin give, and the manifest binds
/// exactly those. Two headers register with their two bindings (the
/// positive control: the request is pending); a manifest missing a
/// header's binding, or holding one no header carries, is refused at
/// registration; a request naming other header names, or a header renamed
/// so that its binding is another, is `managed_command_mismatch` before
/// any pending request.
///
/// Mutation checked: registration not comparing the manifest's bindings
/// with the headers' (the previous rule, origin digest only): the
/// manifest missing `X-Api-Key`'s binding registers, and this fails.
#[test]
fn each_header_of_a_bridged_server_has_its_binding() {
    let mut w = World::new(&[]);
    let origin = "https://api.example.test";
    let remote = w.h.home.root().join("remote");
    std::fs::create_dir_all(&remote).unwrap();
    let manifest = remote.join("envcloak.toml");
    let suffix = envcloak_policy::managed::bridge_binding_suffix(origin);
    let write = |names: &[&str]| {
        let mut body = "[project]\nname = \"remote\"\n\n[env]\n".to_owned();
        for n in names {
            body.push_str(&format!("{n}{suffix} = \"stripe/fixture\"\n"));
        }
        std::fs::write(&manifest, body).unwrap();
    };
    let manifest_text = manifest.to_str().unwrap().to_owned();
    let register = |w: &mut World, headers: Value| {
        w.person(
            "register",
            json!({
                "name": "claude-code/remote",
                "manifest": manifest_text,
                "origin": origin,
                "headers": headers,
            }),
        )
    };
    let both = json!(["Authorization", "X-Api-Key"]);
    for names in [
        &["AUTHORIZATION"][..],
        &["AUTHORIZATION", "X_API_KEY", "OTHER"],
    ] {
        write(names);
        let reg = register(&mut w, both.clone());
        assert_eq!(error_of(&reg), "invalid_params", "{names:?} {reg}");
        assert_eq!(reg["reason"], "header_bindings", "{names:?} {reg}");
    }
    write(&["AUTHORIZATION", "X_API_KEY"]);
    let reg = register(&mut w, both.clone());
    assert_eq!(reg["receipt"]["transport"], "bridge", "{reg}");
    let ask = |w: &mut World, headers: Value| {
        w.agent(
            "request",
            &json!({"manifest": manifest_text, "origin": origin, "headers": headers}),
        )
    };
    pending_id(&ask(&mut w, both));
    let pending = w.pending_count();
    for headers in [
        json!(["Authorization"]),
        json!(["Authorization", "X-Other-Key"]),
    ] {
        let answer = ask(&mut w, headers.clone());
        assert_eq!(
            error_of(&answer),
            "managed_command_mismatch",
            "{headers} {answer}"
        );
    }
    assert_eq!(w.pending_count(), pending, "a pending request exists");
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
/// never the replacement; on macOS, an in-place rewrite and a rename-over
/// at the barrier each fail the suspended child's code directory hash
/// check: the child is killed before it resumes (its start marker never
/// appears) and the client is answered `managed_launch_changed`.
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
        // Rewritten in place (the same file, another build's bytes), then
        // the original's bytes put back in place for the next case, which
        // the daemon's own check, before the barrier, reads.
        let answer = at_barrier(&mut w, &launch, (&release, &held), site, &|w| {
            rewrite_in_place(&w.fixture, &other);
        });
        assert_eq!(error_of(&answer), "managed_launch_changed", "{answer}");
        assert!(
            !appears(&w.marker, Duration::from_secs(2)),
            "the refused child ran"
        );
        rewrite_in_place(&w.fixture, &original);
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

// ------------------------------------------------- removal and races

/// Gate 23 for removal (`managed.unregister`, which `migrate-mcp --undo`
/// and `agents uninstall` call; T9-3, F-70): an agent's removal and one
/// from a process without a terminal are `proof_refused`, a wrong
/// passphrase is `wrong_passphrase`, and the record stays (the launch is
/// still served: the positive control). The person's removal, audited
/// `removed`, ends what the record covered: its launch id is no longer
/// one (`managed_command_mismatch`), and the session grant made for the
/// launch covers nothing of the project, whose plain run now asks for
/// approval; a bridged server's removal likewise leaves its session grant
/// covering nothing of the plain run.
///
/// Mutation checked: `managed.unregister` without its prover check and
/// proof (`refuse_unless_prover` and `prove` removed): the agent's removal
/// succeeds, and this fails.
#[test]
fn removal_needs_a_terminal_proof_and_ends_what_the_record_covered() {
    let mut w = World::new(&[]);
    let (launch, _, _) = w.launched();
    let pass =
        w.h.secret_file(envcloak_testkit::labels::VAULT_PASSPHRASE, true);
    let input = json!({
        "id": "claude-code/fixture",
        "passphrase_file": pass.to_str().unwrap(),
    });
    let by_agent = w.agent("unregister", &input);
    assert_eq!(error_of(&by_agent), "proof_refused", "{by_agent}");
    let no_terminal = w.no_terminal("unregister", &input);
    assert_eq!(error_of(&no_terminal), "proof_refused", "{no_terminal}");
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
    let argv = World::helper_argv("unregister", &i, &o);
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let home = w.h.home.home();
    let ran = w.h.human_argv(&home, &argv, &[], &[]);
    assert_eq!(ran.code, 0, "{}", ran.all());
    let wrong = w.read_out(&o, "the removal with a wrong passphrase");
    assert_eq!(error_of(&wrong), "wrong_passphrase", "{wrong}");
    // The record stayed: the launch is served under its session grant.
    let still = w.request(&launch);
    assert!(started(&still), "{still}");
    // The person removes it.
    let removed = w.person("unregister", json!({"id": "claude-code/fixture"}));
    assert_eq!(removed["removed"], true, "{removed}");
    w.expect_trace("managed server removed launch=");
    let stale = w.request(&launch);
    assert_eq!(error_of(&stale), "managed_command_mismatch", "{stale}");
    let manifest = w.project.join("envcloak.toml");
    let run = w.h.agent(
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
        String::from_utf8_lossy(&run.stderr).contains("approval_required"),
        "{}",
        text(&run)
    );
    // A bridged server: its session grant, then its removal.
    let origin = "https://api.example.test";
    let remote = w.h.home.root().join("remote");
    std::fs::create_dir_all(&remote).unwrap();
    let suffix = envcloak_policy::managed::bridge_binding_suffix(origin);
    std::fs::write(
        remote.join("envcloak.toml"),
        format!(
            "[project]\nname = \"remote\"\n\n[env]\nAUTHORIZATION{suffix} = \"stripe/fixture\"\n"
        ),
    )
    .unwrap();
    let remote_manifest = remote.join("envcloak.toml");
    let reg = w.person(
        "register",
        json!({
            "name": "claude-code/remote",
            "manifest": remote_manifest.to_str().unwrap(),
            "origin": origin,
            "headers": ["Authorization"],
        }),
    );
    assert_eq!(reg["receipt"]["transport"], "bridge", "{reg}");
    let asked = w.agent(
        "request",
        &json!({
            "manifest": remote_manifest.to_str().unwrap(),
            "origin": origin,
            "headers": ["Authorization"],
        }),
    );
    w.approve(&pending_id(&asked));
    let removed = w.person("unregister", json!({"id": "claude-code/remote"}));
    assert_eq!(removed["removed"], true, "{removed}");
    let run = w.h.agent(
        &home,
        &[
            "run",
            "--manifest",
            remote_manifest.to_str().unwrap(),
            "--",
            "true",
        ],
    );
    assert!(
        String::from_utf8_lossy(&run.stderr).contains("approval_required"),
        "the bridge-era grant covered the plain run: {}",
        text(&run)
    );
    w.h.assert_swept("after the removals");
}

/// The agent's `envcloak run` against `manifest` started in the
/// background (`printenv` of the key, discarded): the files its exit code
/// and its standard error go to.
fn run_in_background(w: &mut World, manifest: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let code =
        w.h.files()
            .join(format!("bg-{:016x}.code", envcloak_testkit::fresh_seed()));
    let err = code.with_extension("err");
    let q = |p: &Path| envcloak_e2e::quoted(p.to_str().unwrap());
    let line = format!(
        "( {} run --manifest {} -- sh -c {} >/dev/null 2>{}; echo $? >{}.tmp; mv {}.tmp {} )",
        q(&w.h.cli()),
        q(manifest),
        envcloak_e2e::quoted(&format!("printenv {KEY} >/dev/null")),
        q(&err),
        q(&code),
        q(&code),
        q(&code)
    );
    let home = w.h.home.home();
    w.h.agent_spawn(&home, &line);
    (code, err)
}

/// The record a request is decided on is the record as it is at the
/// decision (review: a stale snapshot): the daemon held between its
/// managed check and its decision (a `testing` barrier) while the record
/// changes. A plain run of a project that was not managed when it was
/// checked, under a session grant for it (the positive control: the same
/// run covered before), is refused `managed_command_mismatch` once the
/// project is registered meanwhile, and releases nothing; a launch's
/// request checked at revision 1, under a session grant for revision 1,
/// is a fresh pending request once `managed.update` makes revision 2
/// meanwhile.
///
/// Mutation checked: the decision taken on the record read before the
/// check, without reading it again under the decision's lock: the plain
/// run is covered (exit 0) and the launch is `started` under the old
/// revision's grant, and this fails.
#[test]
fn a_request_is_decided_on_the_record_as_it_is_then() {
    if managed_common::release_run("a_request_is_decided_on_the_record_as_it_is_then") {
        return;
    }
    let site = "launch.checked_before_decision";
    let (mut w, gate) = held_world(site);
    let release = gate.path().join("release");
    let held = gate.path().join("held");
    let manifest = w.project.join("envcloak.toml");
    let home = w.h.home.home();
    // A session grant for the plain run, while the project is not managed.
    let printenv = format!("printenv {KEY} >/dev/null");
    let args = [
        "run",
        "--manifest",
        manifest.to_str().unwrap(),
        "--",
        "sh",
        "-c",
        printenv.as_str(),
    ];
    let first = w.h.agent(&home, &args);
    let err = String::from_utf8_lossy(&first.stderr).into_owned();
    assert_eq!(
        envcloak_e2e::token(&first.stderr),
        "approval_required",
        "{}",
        text(&first)
    );
    let pending = err
        .split("request=")
        .nth(1)
        .and_then(|r| r.get(..8))
        .unwrap_or_else(|| panic!("no request id: {err}"))
        .to_owned();
    w.approve(&pending);
    let covered = w.h.agent(&home, &args);
    assert_eq!(covered.status.code(), Some(0), "{}", text(&covered));
    // Held at the barrier; the project is registered meanwhile.
    let stops = paused(&w, site);
    std::fs::rename(&release, &held).unwrap();
    let (code, err) = run_in_background(&mut w, &manifest);
    wait_paused(&w, site, stops + 1);
    let (launch, reg) = w.register_fixture();
    std::fs::rename(&held, &release).unwrap();
    assert!(
        appears(&code, Duration::from_secs(60)),
        "the run never ended"
    );
    let stderr = std::fs::read(&err).unwrap_or_default();
    w.h.record("the held run", &stderr);
    assert_eq!(
        std::fs::read_to_string(&code).unwrap().trim(),
        "125",
        "{}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(
        String::from_utf8_lossy(&stderr).contains("managed_command_mismatch"),
        "{}",
        String::from_utf8_lossy(&stderr)
    );
    // A session grant for revision 1 of the launch.
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let answer = w.request(&launch);
    assert!(started(&answer), "{answer}");
    assert_eq!(reported_identity(&report(&answer)), receipt_identity(&reg));
    // Held at the barrier; revision 2 is made meanwhile.
    let stops = paused(&w, site);
    std::fs::rename(&release, &held).unwrap();
    let out = w.agent_background("request", &json!({"launch": launch, "send": ["report"]}));
    wait_paused(&w, site, stops + 1);
    let plan = w.person("plan", json!({"launch": launch}));
    let digest = plan["statement"]["digest"].as_str().unwrap().to_owned();
    let updated = w.person("update", json!({"launch": launch, "digest": digest}));
    assert_eq!(updated["revision"], 2, "{updated}");
    std::fs::rename(&held, &release).unwrap();
    let answer = w.wait_out(&out, Duration::from_secs(60), "the held request");
    pending_id(&answer);
    w.h.assert_swept("after the held requests");
}

/// A registration takes its launch id and revision from the record as it
/// is when it commits (review: a revision computed before resolution and
/// the proof): a registration held after its resolution and before its
/// proof and commit (a `testing` barrier)
/// while an update makes revision 2 commits revision 3, never a second
/// revision 2; a session grant made for the update's revision 2 then
/// covers nothing of the registration's launch (a fresh pending request).
///
/// Mutation checked: the revision computed before resolution, as before
/// (`prior` read once, outside the commit's lock): the registration
/// commits revision 2 again, the grant for revision 2 covers its launch,
/// and this fails.
#[test]
fn a_registration_takes_its_revision_at_its_commit() {
    if managed_common::release_run("a_registration_takes_its_revision_at_its_commit") {
        return;
    }
    let site = "managed.register_resolved";
    let (mut w, gate) = held_world(site);
    let release = gate.path().join("release");
    let held = gate.path().join("held");
    let (launch, _) = w.register_fixture();
    // The registration again, with another argument, held at its commit.
    let stops = paused(&w, site);
    std::fs::rename(&release, &held).unwrap();
    let mut argv = w.fixture_argv();
    argv.as_array_mut().unwrap().push(json!("--linger"));
    argv.as_array_mut().unwrap().push(json!("0"));
    let again = w.person_background(
        "register",
        json!({
            "name": "claude-code/fixture",
            "manifest": w.project.join("envcloak.toml").to_str().unwrap(),
            "argv": argv,
        }),
    );
    wait_paused(&w, site, stops + 1);
    let plan = w.person("plan", json!({"launch": launch}));
    let digest = plan["statement"]["digest"].as_str().unwrap().to_owned();
    let updated = w.person("update", json!({"launch": launch, "digest": digest}));
    assert_eq!(updated["revision"], 2, "{updated}");
    // A session grant for revision 2.
    let first = w.request(&launch);
    w.approve(&pending_id(&first));
    let answer = w.request(&launch);
    assert!(started(&answer), "{answer}");
    std::fs::rename(&held, &release).unwrap();
    let registered = w.person_done(again);
    assert_eq!(registered["launch"], launch.as_str(), "{registered}");
    assert_eq!(registered["revision"], 3, "{registered}");
    let next = w.request(&launch);
    pending_id(&next);
}

/// CR-2: an update statement shows the declaration as it is stored and
/// as the update would store it, whole: a change to an argument, to
/// `PATH` and to a variable's value each shows there, though the receipts
/// (which show names and identities) read alike. A statement that changed
/// between its plan and the update (the executable replaced meanwhile) is
/// `statement_mismatch`, and nothing is committed (the revision stays).
///
/// Mutation checked: the statement without the declarations (receipts
/// only, as before): the argument, `PATH` and value changes are not shown,
/// and this fails.
#[test]
fn an_update_statement_shows_every_change_of_the_declaration() {
    let mut w = World::new(&[]);
    let argv = w.fixture_argv();
    let bin = w.fixture.parent().unwrap().to_str().unwrap().to_owned();
    let reg = w.register(json!({"argv": argv, "env": [["MODE", "dev"]], "path_env": bin}));
    let launch = reg["launch"].as_str().unwrap().to_owned();
    let mut new_argv = w.fixture_argv();
    new_argv.as_array_mut().unwrap().push(json!("--linger"));
    new_argv.as_array_mut().unwrap().push(json!("0"));
    let path = format!("{bin}:/usr/bin");
    let changes = json!({
        "argv": new_argv,
        "set_env": [["MODE", "fast"]],
        "path_env": path,
    });
    let shown = w.person("plan", json!({"launch": launch, "changes": changes}));
    let st = &shown["statement"];
    assert_eq!(st["old_declaration"]["argv"], argv, "{shown}");
    assert_eq!(st["new_declaration"]["argv"], new_argv, "{shown}");
    assert_eq!(
        st["old_declaration"]["env"],
        json!([["MODE", "dev"]]),
        "{shown}"
    );
    assert_eq!(
        st["new_declaration"]["env"],
        json!([["MODE", "fast"]]),
        "{shown}"
    );
    assert_eq!(st["old_declaration"]["path_env"], bin.as_str(), "{shown}");
    assert_eq!(st["new_declaration"]["path_env"], path.as_str(), "{shown}");
    // The receipts alone do not show the value change.
    assert_eq!(st["old"]["env_names"], st["new"]["env_names"], "{shown}");
    // A statement changed between its plan and the update.
    let plan = w.person("plan", json!({"launch": launch}));
    let digest = plan["statement"]["digest"].as_str().unwrap().to_owned();
    let other = w.fixture.with_extension("other");
    other_build(&other);
    std::fs::rename(&other, &w.fixture).unwrap();
    let mismatch = w.person("update", json!({"launch": launch, "digest": digest}));
    assert_eq!(error_of(&mismatch), "statement_mismatch", "{mismatch}");
    let again = w.person("plan", json!({"launch": launch}));
    assert_eq!(again["statement"]["revision"], 1, "{again}");
}

/// Gate 13 in the daemon (behind the client's own check, which lane B's
/// typed helpers do not run): a registration or an update plan whose
/// argument or variable value looks like a key is refused `invalid_params`
/// (`key_shaped`) before anything is stored, and the key is in no
/// answer; the project stays unmanaged.
///
/// Mutation checked: the daemon's refusal removed: the registration with
/// the key in its argv is stored and its receipt is answered, and this
/// fails (the sweep finds the key in the answer).
#[test]
fn a_key_in_a_declaration_is_refused_by_the_daemon() {
    let mut w = World::new(&[]);
    let key = managed_common::stripe_test_key();
    w.h.add_needle("the key in a declaration".into(), key.clone().into_bytes());
    let mut argv = w.fixture_argv();
    argv.as_array_mut().unwrap().push(json!(key));
    let reg = w.register(json!({ "argv": argv }));
    assert_eq!(error_of(&reg), "invalid_params", "{reg}");
    assert_eq!(reg["reason"], "key_shaped", "{reg}");
    let reg = w.register(json!({"argv": w.fixture_argv(), "env": [["TOKEN", key]]}));
    assert_eq!(reg["reason"], "key_shaped", "{reg}");
    let (launch, _) = w.register_fixture();
    let plan = w.person(
        "plan",
        json!({"launch": launch, "changes": {"set_env": [["TOKEN", key]]}}),
    );
    assert_eq!(plan["reason"], "key_shaped", "{plan}");
    w.h.assert_swept("after the refusals");
}

/// D-18 against the bindings a request resolves to: a bridged project's
/// request whose profile or reference names a binding without the
/// origin's digest is `managed_command_mismatch`, though every binding of
/// the manifest's defaults carries it (the plain request is pending: the
/// positive control).
///
/// Mutation checked: the origin check on the manifest's default bindings
/// only (as before): the profile's and the reference's requests are
/// pending, and this fails.
#[test]
fn a_bridged_request_is_checked_on_every_binding_it_names() {
    let mut w = World::new(&[]);
    let origin = "https://api.example.test";
    let remote = w.h.home.root().join("remote");
    std::fs::create_dir_all(&remote).unwrap();
    let suffix = envcloak_policy::managed::bridge_binding_suffix(origin);
    std::fs::write(
        remote.join("envcloak.toml"),
        format!(
            "[project]\nname = \"remote\"\n\n[env]\nAUTHORIZATION{suffix} = \"stripe/fixture\"\n\n\
             [env.extra]\nPLAIN_KEY = \"stripe/fixture\"\n"
        ),
    )
    .unwrap();
    let manifest = remote.join("envcloak.toml");
    let manifest = manifest.to_str().unwrap();
    let reg = w.person(
        "register",
        json!({
            "name": "claude-code/remote",
            "manifest": manifest,
            "origin": origin,
            "headers": ["Authorization"],
        }),
    );
    assert_eq!(reg["receipt"]["transport"], "bridge", "{reg}");
    let ask = |w: &mut World, extra: Value| {
        let mut input = json!({
            "manifest": manifest,
            "origin": origin,
            "headers": ["Authorization"],
        });
        for (k, v) in extra.as_object().unwrap() {
            input[k] = v.clone();
        }
        w.agent("request", &input)
    };
    pending_id(&ask(&mut w, json!({})));
    let pending = w.pending_count();
    let by_profile = ask(&mut w, json!({"profile": "extra"}));
    assert_eq!(
        error_of(&by_profile),
        "managed_command_mismatch",
        "{by_profile}"
    );
    let by_ref = ask(&mut w, json!({"refs": ["PLAIN_KEY=stripe/fixture"]}));
    assert_eq!(error_of(&by_ref), "managed_command_mismatch", "{by_ref}");
    assert_eq!(w.pending_count(), pending, "a pending request exists");
}
