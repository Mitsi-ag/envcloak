//! The daemon's lock state machine over its socket (SPEC §5 "Unlock
//! flow", "Lock"): `vault.create`, `unlock`, `lock` and `status`, the
//! rules checked before any key derivation, and a termination signal that
//! locks and exits. Every test sweeps the home and the daemon's log for the
//! passphrase and the Recovery Kit.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use common::{client, create_vault, exe, passphrase, run_paths, start};
use envcloak_core::{RecoveryKit, SecretBytes};
use envcloak_ipc::view::{Integrity, LockReason, VaultState};
use envcloak_ipc::{Client, ClientError, ErrorKind};
use envcloak_testkit::{Daemon, TestHome, assert_no_canary, canaries, fresh_seed};

fn rpc_kind(e: ClientError) -> ErrorKind {
    match e {
        ClientError::Rpc(r) => r.kind,
        other => panic!("expected an error response, got {other:?}"),
    }
}

#[test]
fn create_lock_unlock_and_status() {
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let d = start(&home);
    let mut c = client(&home);

    let st = c.status().unwrap();
    assert_eq!(st.vault.state, VaultState::Absent);
    assert_eq!(i64::from(st.daemon.pid), i64::from(d.pid()));
    assert_eq!(st.daemon.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(st.lock.idle_limit_secs, 8 * 3600);
    let e = c.unlock(passphrase(&cs), &[]).unwrap_err();
    assert_eq!(rpc_kind(e), ErrorKind::NoVault);

    let kit = create_vault(&home, &cs);
    let st = c.status().unwrap();
    assert_eq!(st.vault.state, VaultState::Unlocked);
    assert_eq!(st.vault.integrity, Some(Integrity::Ok));
    assert!(st.lock.idle_remaining_secs.unwrap() > 8 * 3600 - 60);
    let e = c
        .vault_create(
            passphrase(&cs),
            SecretBytes::copy_from(RecoveryKit::generate().to_display().as_bytes()),
            Some(common::TEST_KDF_KIB),
        )
        .unwrap_err();
    assert_eq!(rpc_kind(e), ErrorKind::VaultExists);

    assert!(c.lock().unwrap().was_unlocked);
    assert!(!c.lock().unwrap().was_unlocked);
    let st = c.status().unwrap();
    assert_eq!(st.vault.state, VaultState::Locked);
    assert_eq!(st.lock.last_reason, Some(LockReason::Request));
    assert_eq!(st.lock.idle_remaining_secs, None);

    let e = c
        .unlock(
            SecretBytes::copy_from(b"not the passphrase, not at all"),
            &[],
        )
        .unwrap_err();
    assert_eq!(rpc_kind(e), ErrorKind::WrongPassphrase);
    assert_eq!(c.status().unwrap().vault.failed_unlocks, 1);
    assert_eq!(c.status().unwrap().vault.state, VaultState::Locked);
    let v = c.unlock(passphrase(&cs), &[]).unwrap();
    assert!(!v.already);
    assert!(c.unlock(passphrase(&cs), &[]).unwrap().already);
    assert_eq!(c.status().unwrap().vault.state, VaultState::Unlocked);
    drop(c);

    // A second client sees the same daemon state.
    assert_eq!(
        client(&home).status().unwrap().vault.state,
        VaultState::Unlocked
    );
    let log = d.log();
    assert!(
        log.contains("audit: unlock failed reason=wrong_passphrase"),
        "{log}"
    );
    let mut all = cs.clone();
    all.push(kit);
    assert_no_canary(&d.log_bytes(), &all);
    home.assert_clean(&all);
}

#[test]
fn rules_and_bounds_are_checked_before_any_key_derivation() {
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let _d = start(&home);
    let mut c = client(&home);
    let kit = || SecretBytes::copy_from(RecoveryKit::generate().to_display().as_bytes());

    let e = c
        .vault_create(
            SecretBytes::copy_from(b"short"),
            kit(),
            Some(common::TEST_KDF_KIB),
        )
        .unwrap_err();
    match e {
        ClientError::Rpc(r) => {
            assert_eq!(r.kind, ErrorKind::PassphraseRejected);
            assert_eq!(r.reason, Some("too_short"));
        }
        other => panic!("{other:?}"),
    }
    for kib in [1024, 64 * 1024 - 1, 4 * 1024 * 1024 + 1, u32::MAX] {
        let e = c
            .vault_create(passphrase(&cs), kit(), Some(kib))
            .unwrap_err();
        assert_eq!(rpc_kind(e), ErrorKind::KdfParams, "{kib}");
    }
    let e = c
        .vault_create(
            passphrase(&cs),
            SecretBytes::copy_from(b"not a recovery kit"),
            Some(common::TEST_KDF_KIB),
        )
        .unwrap_err();
    assert_eq!(rpc_kind(e), ErrorKind::InvalidParams);
    assert_eq!(c.status().unwrap().vault.state, VaultState::Absent);
    home.assert_clean(&cs);
}

/// SPEC §5 "Lock": the daemon locks on stop. SIGTERM, SIGINT and SIGHUP
/// each lock the vault, remove the socket and exit 0; a daemon started
/// again finds the vault locked.
#[test]
fn a_termination_signal_locks_and_exits() {
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let mut d = start(&home);
    let kit = create_vault(&home, &cs);
    for sig in ["-TERM", "-INT", "-HUP"] {
        let mut c = client(&home);
        if c.status().unwrap().vault.state != VaultState::Unlocked {
            c.unlock(passphrase(&cs), &[]).unwrap();
        }
        drop(c);
        d.signal(sig);
        let status = d
            .wait_exit(Duration::from_secs(20))
            .expect("the daemon did not exit");
        assert!(status.success(), "{sig}: {status:?}");
        let log = d.log();
        assert!(log.contains("stopping on signal"), "{log}");
        assert!(log.contains("vault locked"), "{sig}: {log}");
        assert!(!run_paths(&home).socket.exists(), "the socket is removed");
        assert!(matches!(
            Client::connect(&run_paths(&home)).unwrap_err(),
            ClientError::Unavailable
        ));

        d = start(&home);
        let st = client(&home).status().unwrap();
        assert_eq!(st.vault.state, VaultState::Locked, "{sig}");
    }
    let mut all = cs.clone();
    all.push(kit);
    home.assert_clean(&all);
}

/// A `lock` that arrives while `vault.create` runs Argon2id: the vault is
/// still created, under the passphrase and kit sent, and then locked, and
/// the answer says so (the client told the user to keep that kit). A
/// second create is refused, and the passphrase unlocks the vault.
#[test]
fn a_lock_during_vault_create_leaves_it_created_and_locked() {
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let d = start(&home);
    let kit = RecoveryKit::generate();
    let text = kit.to_display().to_string();
    let creating = {
        let paths = run_paths(&home);
        let pass = passphrase(&cs);
        let text = SecretBytes::copy_from(text.as_bytes());
        std::thread::spawn(move || {
            Client::connect(&paths)
                .unwrap()
                .vault_create(pass, text, Some(256 * 1024))
        })
    };
    let mut c = client(&home);
    let end = std::time::Instant::now() + Duration::from_secs(30);
    while !c.status().unwrap().vault.busy {
        assert!(std::time::Instant::now() < end, "vault.create never ran");
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(!c.lock().unwrap().was_unlocked);
    let created = creating.join().unwrap().unwrap();
    assert!(created.locked, "{created:?}");
    let st = c.status().unwrap();
    assert_eq!(st.vault.state, VaultState::Locked);
    assert_eq!(st.lock.last_reason, Some(LockReason::Request));
    let e = c
        .vault_create(
            passphrase(&cs),
            SecretBytes::copy_from(RecoveryKit::generate().to_display().as_bytes()),
            Some(common::TEST_KDF_KIB),
        )
        .unwrap_err();
    assert_eq!(rpc_kind(e), ErrorKind::VaultExists);
    assert!(!c.unlock(passphrase(&cs), &[]).unwrap().already);
    assert!(
        d.log().contains("vault created, then locked"),
        "{}",
        d.log()
    );
    let mut all = cs.clone();
    all.push(envcloak_testkit::Canary::new("RECOVERY_KIT", text));
    assert_no_canary(&d.log_bytes(), &all);
    home.assert_clean(&all);
}

#[test]
fn the_idle_limit_is_configurable_within_bounds() {
    let home = TestHome::new();
    let d = Daemon::start(&home, exe(), &["--idle-lock", "90m"]);
    assert_eq!(client(&home).status().unwrap().lock.idle_limit_secs, 5400);
    drop(d);
    for bad in [&["--idle-lock", "25h"][..], &["--idle-lock"], &["--bogus"]] {
        let mut d = Daemon::spawn(&home, exe(), bad);
        let status = d.wait_exit(Duration::from_secs(10)).unwrap();
        assert_eq!(status.code(), Some(2), "{bad:?}");
    }
}
