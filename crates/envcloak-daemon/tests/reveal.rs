//! M2-21: the actual socket boundary, including callers that bypass CLI checks.
#![allow(clippy::unwrap_used)]

mod common;

use envcloak_ipc::proto::{ErrorKind, ItemsReveal, RevealParams};
use envcloak_ipc::{ClientError, WireSecret};
use envcloak_testkit::{TestHome, canaries, fresh_seed};

fn params(cs: &[envcloak_testkit::Canary]) -> RevealParams {
    RevealParams {
        slug: common::SLUGS[0].into(),
        field: None,
        passphrase: WireSecret::new(common::passphrase(cs)),
        claims: Vec::new(),
    }
}

fn kind(e: ClientError) -> ErrorKind {
    match e {
        ClientError::Rpc(e) => e.kind,
        _ => panic!("not an RPC refusal"),
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_has_no_terminal_value_method() {
    let home = TestHome::new();
    let cs = canaries(fresh_seed());
    let d = common::start(&home);
    assert_eq!(
        kind(
            common::client(&home)
                .call::<ItemsReveal>(&params(&cs))
                .unwrap_err()
        ),
        ErrorKind::MethodNotFound
    );
    envcloak_testkit::assert_no_canary(&d.log_bytes(), &cs);
    home.assert_clean(&cs);
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use envcloak_core::{
        SecretBytes,
        vault::{LockedVault, VaultPaths},
    };
    use envcloak_testkit::{Canary, Daemon, assert_no_canary, by_label, labels};
    use std::os::unix::fs::PermissionsExt;

    struct Fixture {
        home: TestHome,
        cs: Vec<Canary>,
        d: Daemon,
    }
    impl Fixture {
        fn new() -> Self {
            common::terminal_session();
            let home = TestHome::new();
            let mut cs = canaries(fresh_seed());
            cs.push(common::seed_vault(&home, &cs));
            let d = common::start(&home);
            common::client(&home)
                .unlock(common::passphrase(&cs), &[])
                .unwrap();
            Self { home, cs, d }
        }
        fn reveal(
            &self,
            p: &RevealParams,
        ) -> Result<envcloak_ipc::proto::RevealOutput, ClientError> {
            common::client(&self.home).call::<ItemsReveal>(p)
        }
        fn sweep(&self) {
            assert_no_canary(&self.d.log_bytes(), &self.cs);
            self.home.assert_clean(&self.cs);
        }
    }

    #[test]
    fn reveal_requires_a_fresh_proof_and_uses_the_shared_limiter() {
        let f = Fixture::new();
        let p = params(&f.cs);
        let value = f.reveal(&p).unwrap();
        assert!(
            value
                .value
                .into_inner()
                .ct_eq(by_label(&f.cs, labels::OPENAI_API_KEY).value())
        );
        let mut wrong = params(&f.cs);
        wrong.passphrase = WireSecret::new(SecretBytes::copy_from(b"wrong proof"));
        assert_eq!(
            kind(f.reveal(&wrong).unwrap_err()),
            ErrorKind::WrongPassphrase
        );
        // Wrong rotations spend the same limiter as reveal. Unlock on
        // an already unlocked vault intentionally does not check a proof.
        let target = common::client(&f.home)
            .items_target(common::SLUGS[0], None, &[])
            .unwrap();
        for _ in 0..4 {
            assert_eq!(
                kind(
                    common::client(&f.home)
                        .items_rotate(
                            &target,
                            common::passphrase(&f.cs),
                            SecretBytes::copy_from(b"wrong proof"),
                            &[]
                        )
                        .unwrap_err()
                ),
                ErrorKind::WrongPassphrase
            );
        }
        assert_eq!(kind(f.reveal(&p).unwrap_err()), ErrorKind::TooManyAttempts);
        f.sweep();
    }

    #[test]
    fn terminal_less_rpc_caller_cannot_reveal_even_with_the_proof() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let f = Fixture::new();
        let mut command = Command::new("/usr/bin/python3");
        f.home
            .apply(&mut command)
            .args([
                "-c",
                r#"
import json, os, socket, struct, sys
os.setsid()
s = socket.socket(socket.AF_UNIX)
s.settimeout(10)
s.connect(sys.argv[1])
body = sys.stdin.buffer.read()
s.sendall(struct.pack('>I', len(body)) + body)
def exact(n):
    b = b''
    while len(b) < n:
        part = s.recv(n - len(b))
        if not part:
            raise RuntimeError('short frame')
        b += part
    return b
length, = struct.unpack('>I', exact(4))
assert length <= 1048576
sys.stdout.buffer.write(exact(length))
"#,
            ])
            .arg(common::run_paths(&f.home).socket)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().unwrap();
        let request = serde_json::json!({"jsonrpc":"2.0", "id":1, "method":"items.reveal", "params":params(&f.cs)});
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&request).unwrap())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        assert_no_canary(&out.stdout, &f.cs);
        let answer: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(answer["error"]["data"]["kind"], "proof_refused");
        assert!(f.reveal(&params(&f.cs)).is_ok());
        f.sweep();
    }

    #[test]
    fn reveal_audit_failure_releases_nothing_and_recovery_is_real() {
        let f = Fixture::new();
        let audit = common::data_dir(&f.home).join("audit");
        std::fs::remove_dir_all(&audit).unwrap();
        std::fs::write(&audit, b"blocked").unwrap();
        assert_eq!(
            kind(f.reveal(&params(&f.cs)).unwrap_err()),
            ErrorKind::AuditFailed
        );
        assert!(!String::from_utf8_lossy(&f.d.log_bytes()).contains("audit: revealed"));
        std::fs::remove_file(&audit).unwrap();
        std::fs::create_dir(&audit).unwrap();
        std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(f.reveal(&params(&f.cs)).is_ok());
        assert!(String::from_utf8_lossy(&f.d.log_bytes()).contains("audit: revealed"));
        f.sweep();
    }

    #[test]
    fn reveals_are_audited_and_rotation_is_fresh() {
        let mut f = Fixture::new();
        assert!(
            f.reveal(&params(&f.cs))
                .unwrap()
                .value
                .into_inner()
                .ct_eq(by_label(&f.cs, labels::OPENAI_API_KEY).value())
        );
        let target = common::client(&f.home)
            .items_target(common::SLUGS[0], None, &[])
            .unwrap();
        common::client(&f.home)
            .items_rotate(
                &target,
                SecretBytes::copy_from(by_label(&f.cs, labels::OPENAI_API_KEY_ROTATED).value()),
                common::passphrase(&f.cs),
                &[],
            )
            .unwrap();
        assert!(
            f.reveal(&params(&f.cs))
                .unwrap()
                .value
                .into_inner()
                .ct_eq(by_label(&f.cs, labels::OPENAI_API_KEY_ROTATED).value())
        );
        f.d.signal("-TERM");
        assert!(f.d.wait_exit(std::time::Duration::from_secs(30)).is_some());
        let vault = LockedVault::open(&VaultPaths::under(common::data_dir(&f.home)))
            .unwrap()
            .unlock_with_passphrase(&common::passphrase(&f.cs))
            .map_err(|(_, e)| e)
            .unwrap();
        let (entries, _) = vault.read_audit().unwrap();
        let reveals: Vec<_> = entries
            .iter()
            .filter(|e| e.record.kind == envcloak_core::audit::AuditKind::Reveal)
            .collect();
        assert_eq!(reveals.len(), 2);
        for entry in reveals {
            assert_eq!(entry.record.decision.outcome, "revealed");
            assert_eq!(
                entry.record.decision.method.as_deref(),
                Some("items.reveal")
            );
            assert_eq!(entry.record.items.len(), 1);
            assert_no_canary(format!("{:?}", entry.record).as_bytes(), &f.cs);
        }
        f.sweep();
    }

    #[test]
    fn reveal_refuses_claimed_agents_and_hostile_targets_before_proof() {
        let f = Fixture::new();
        let mut p = params(&f.cs);
        p.claims = vec!["CLAUDECODE".into()];
        p.passphrase = WireSecret::new(SecretBytes::copy_from(b"wrong proof"));
        assert_eq!(kind(f.reveal(&p).unwrap_err()), ErrorKind::ProofRefused);
        p.claims.clear();
        for slug in [
            "",
            "unknown/item",
            "a\u{1b}[31m",
            "a\u{202e}",
            &"x".repeat(100_000),
        ] {
            p.slug = slug.into();
            assert_eq!(kind(f.reveal(&p).unwrap_err()), ErrorKind::NoSuchItem);
        }
        p.slug = common::SLUGS[0].into();
        for field in ["", "unknown", "a#b", "a\n", "é"] {
            p.field = Some(field.into());
            assert_eq!(kind(f.reveal(&p).unwrap_err()), ErrorKind::NoSuchItem);
        }
        // All these refusals precede even a wrong-proof attempt.
        assert!(f.reveal(&params(&f.cs)).is_ok());
        f.sweep();
    }

    #[test]
    fn reveal_refuses_cards_logins_and_ambiguous_fields() {
        use envcloak_core::crypto::ItemClass;
        use envcloak_core::vault::{FieldName, ItemDetails, NewItem, Slug};
        common::terminal_session();
        let home = TestHome::new();
        let cs = canaries(fresh_seed());
        common::seed_vault(&home, &cs);
        let mut vault = LockedVault::open(&VaultPaths::under(common::data_dir(&home)))
            .unwrap()
            .unlock_with_passphrase(&common::passphrase(&cs))
            .map_err(|(_, e)| e)
            .unwrap();
        vault
            .transact(|t| {
                t.create_login(envcloak_core::vault::NewLogin {
                    slug: Slug::new("example/login").unwrap(),
                    details: ItemDetails::default(),
                    meta: envcloak_core::vault::LoginMeta {
                        tier: envcloak_core::vault::LoginTier::Dev,
                        session_lifetime: 900,
                    },
                    username: SecretBytes::copy_from(b"editor@example.test"),
                    password: common::passphrase(&cs),
                    totp: None,
                    adapter_key: None,
                })?;
                for (slug, class) in [
                    ("example/card", ItemClass::Card),
                    ("example/issuer", ItemClass::IssuerCredential),
                    ("example/multi", ItemClass::Secret),
                ] {
                    let id = t.create_item(NewItem {
                        slug: Slug::new(slug).unwrap(),
                        class,
                        details: ItemDetails::default(),
                    })?;
                    for name in ["first", "second"] {
                        t.add_field(id, FieldName::new(name).unwrap(), common::passphrase(&cs))?;
                    }
                }
                Ok(())
            })
            .unwrap();
        drop(vault);
        let d = common::start(&home);
        common::client(&home)
            .unlock(common::passphrase(&cs), &[])
            .unwrap();
        let mut p = params(&cs);
        p.passphrase = WireSecret::new(SecretBytes::copy_from(b"wrong proof"));
        for (slug, field) in [
            ("example/card", "first"),
            ("example/issuer", "first"),
            ("example/login", "password"),
        ] {
            p.slug = slug.into();
            for selected in [None, Some(field.into())] {
                p.field = selected;
                let error = common::client(&home).call::<ItemsReveal>(&p).unwrap_err();
                let ClientError::Rpc(error) = error else {
                    panic!("not an RPC refusal")
                };
                assert_eq!(error.kind, ErrorKind::NoSuchItem);
                assert_eq!(error.reason, Some("unknown_item_class"));
            }
        }
        p.slug = "example/multi".into();
        p.field = None;
        assert_eq!(
            kind(common::client(&home).call::<ItemsReveal>(&p).unwrap_err()),
            ErrorKind::NoSuchItem
        );
        p.passphrase = WireSecret::new(common::passphrase(&cs));
        p.field = Some("second".into());
        let value = common::client(&home).call::<ItemsReveal>(&p).unwrap();
        assert!(
            value
                .value
                .into_inner()
                .ct_eq_secret(&common::passphrase(&cs))
        );
        assert_no_canary(&d.log_bytes(), &cs);
        home.assert_clean(&cs);
    }
}
