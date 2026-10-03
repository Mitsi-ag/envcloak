//! Gate b18's `run` and `ref` part through the built CLI (plan task M2-07,
//! SPEC §6.8 "Login fields are typed"): with a login in the vault, planted
//! through the core API as `login.add` (M2b-03) will plant it, a person's
//! `envcloak run` naming any of its fields, by `--ref` or in a manifest,
//! exits 125 with `login_reference` and starts nothing, and `envcloak ref`
//! refuses it with `login_reference` and leaves `envcloak.toml` as it was.
//! A reference to a secret still binds (the control). No login value is in
//! any output, the daemon's log or the home.
//!
//! `ref` never writes a binding the daemon did not check: with no daemon
//! running, and with the daemon's vault locked, a login's field and a
//! secret alike are refused (`daemon_unavailable`, `vault_locked`) and
//! `envcloak.toml` is left as it was. Mutation checked: the class check's
//! failure taken as "not a login" (the `.ok()` fallback ref had), which
//! writes the login's binding here and fails.
//!
//! The person's commands run on a terminal of their own, as tests/run.rs's
//! approver's do; under a developer's Claude Code the unlock is refused,
//! so run them outside the agent's tree then.
#![allow(clippy::unwrap_used)]

mod common;

use std::path::Path;
use std::process::Output;
use std::time::Duration;

use common::{
    Fd, MANIFEST, data_dir, finish_within, on_terminal_command, outside_dir, project,
    run_on_terminal, secret_file, seed_vault, start_daemon, stderr, stdout,
};
use envcloak_core::SecretBytes;
use envcloak_core::vault::{
    ItemDetails, LockedVault, LoginMeta, LoginTier, NewLogin, Slug, TotpAlgorithm, TotpEnrollment,
    TotpParams, VaultPaths,
};
use envcloak_testkit::{
    Canary, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};

/// Plants `fixture/editor`, a login whose every field is a fixture of its
/// own, before the daemon starts; returns the fixtures.
fn plant_login(home: &TestHome, cs: &[Canary]) -> Vec<Canary> {
    let login: Vec<Canary> = ["USERNAME", "PASSWORD", "TOTP_SEED", "ADAPTER_KEY"]
        .into_iter()
        .map(|label| {
            Canary::new(
                format!("LOGIN_{label}"),
                format!("login-{}-{:016x}", label.to_ascii_lowercase(), fresh_seed()),
            )
        })
        .collect();
    let value = |n: usize| SecretBytes::copy_from(login[n].value());
    let pass = SecretBytes::copy_from(by_label(cs, labels::VAULT_PASSPHRASE).value());
    let mut v = LockedVault::open(&VaultPaths::under(data_dir(home)))
        .unwrap()
        .unlock_with_passphrase(&pass)
        .map_err(|(_, e)| e)
        .unwrap();
    v.transact(|t| {
        t.create_login(NewLogin {
            slug: Slug::new("fixture/editor").unwrap(),
            details: ItemDetails {
                title: "fixture editor".into(),
                ..ItemDetails::default()
            },
            meta: LoginMeta {
                tier: LoginTier::Dev,
                session_lifetime: 900,
            },
            username: value(0),
            password: value(1),
            totp: Some(TotpEnrollment {
                params: TotpParams::new(TotpAlgorithm::Sha1, 6, 30).unwrap(),
                seed: value(2),
            }),
            adapter_key: Some(value(3)),
        })
    })
    .unwrap();
    login
}

/// `envcloak <args>` by the person on a terminal of their own, in `dir`.
fn in_dir(home: &TestHome, dir: &Path, args: &[&str], fds: &[Fd<'_>]) -> Output {
    let mut cmd = on_terminal_command(home, args, fds);
    cmd.current_dir(dir);
    finish_within(cmd, Duration::from_secs(60))
}

#[test]
fn b18_run_and_ref_refuse_a_login_field() {
    let mut cs = canaries(fresh_seed());
    let home = TestHome::new();
    let kit = seed_vault(&home, &cs);
    cs.push(kit);
    let login = plant_login(&home, &cs);
    cs.extend(login);
    let story = project(&home, "acme-web", MANIFEST);
    let manifest = std::fs::read(story.join("envcloak.toml")).unwrap();
    let swept = |o: &Output| {
        assert_no_canary(&o.stdout, &cs);
        assert_no_canary(&o.stderr, &cs);
    };
    // `ref` that the daemon could not check writes nothing, for a login's
    // field and a secret's reference alike.
    let unchecked = |token: &str| {
        for binding in [
            "PASSWORD=fixture/editor#password",
            "PASSWORD=fixture/editor",
            "GITHUB_TOKEN=github/acme-web",
        ] {
            let o = in_dir(&home, &story, &["ref", binding], &[]);
            swept(&o);
            assert_eq!(o.status.code(), Some(1), "ref {binding}: {}", stderr(&o));
            let err = stderr(&o);
            assert!(
                err.starts_with(&format!("envcloak: {token}: ")),
                "ref {binding}: {err}"
            );
            assert!(err.contains("nothing was written"), "ref {binding}: {err}");
            assert!(stdout(&o).is_empty(), "ref {binding}: {}", stdout(&o));
            assert_eq!(
                std::fs::read(story.join("envcloak.toml")).unwrap(),
                manifest,
                "ref {binding} changed envcloak.toml with {token}"
            );
        }
    };
    // No daemon running.
    unchecked("daemon_unavailable");
    let d = start_daemon(&home);
    // The daemon's vault locked.
    unchecked("vault_locked");
    let files = outside_dir();
    let pass = secret_file(
        files.path(),
        "pass",
        by_label(&cs, labels::VAULT_PASSPHRASE).value(),
    );
    let out = run_on_terminal(
        &home,
        &["unlock", "--passphrase-fd", "3"],
        &[(3, &pass, true)],
    );
    assert!(out.status.success(), "{}{}", stderr(&out), d.log());
    let refused = |o: &Output, code: i32, what: &str| {
        swept(o);
        assert_eq!(o.status.code(), Some(code), "{what}: {}", stderr(o));
        assert!(
            stderr(o).starts_with("envcloak: login_reference: "),
            "{what}: {}",
            stderr(o)
        );
        assert!(stdout(o).is_empty(), "{what}: {}", stdout(o));
    };
    let marker = story.join("started");
    let command = format!("touch {}", marker.display());
    for reference in [
        "fixture/editor",
        "fixture/editor#username",
        "fixture/editor#password",
        "fixture/editor#totp",
        "fixture/editor#adapter_key",
    ] {
        let binding = format!("PASSWORD={reference}");
        let o = in_dir(
            &home,
            &story,
            &["run", "--ref", &binding, "--", "/bin/sh", "-c", &command],
            &[],
        );
        refused(&o, 125, &format!("run --ref {binding}"));
        assert!(!marker.exists(), "the command started");
        let o = in_dir(&home, &story, &["ref", &binding], &[]);
        refused(&o, 1, &format!("ref {binding}"));
        assert_eq!(
            std::fs::read(story.join("envcloak.toml")).unwrap(),
            manifest,
            "ref {binding} changed envcloak.toml"
        );
    }
    // A manifest that binds one.
    let bound = project(
        &home,
        "login-bound",
        "[env]\nOPENAI_API_KEY = \"openai/acme-web\"\nPASSWORD = \"fixture/editor#password\"\n",
    );
    let o = in_dir(
        &home,
        &bound,
        &["run", "--", "/bin/sh", "-c", &command],
        &[],
    );
    refused(&o, 125, "a manifest binding a login's password");
    assert!(!marker.exists(), "the command started");

    // The control: a secret's reference is still written.
    let o = in_dir(&home, &story, &["ref", "GITHUB_TOKEN=github/acme-web"], &[]);
    swept(&o);
    assert!(o.status.success(), "{}", stderr(&o));
    assert_ne!(
        std::fs::read(story.join("envcloak.toml")).unwrap(),
        manifest
    );

    assert_no_canary(&d.log_bytes(), &cs);
    home.assert_clean(&cs);
    drop(files);
}
