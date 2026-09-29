//! Import over the daemon's socket (SPEC §6.4, gates 10 and 16; T13):
//! - `import.plan` sorts entries into secrets and configuration, groups
//!   equal values by keyed hash, computed here in the daemon (the CLI has
//!   no key), across projects, binds a value the vault holds to its item,
//!   and reports every item that holds it (gate 10); it writes nothing;
//! - `import.commit` writes exactly the plan whose digest it is given;
//! - `import.verify` answers the delete gate from the manifest the daemon
//!   opens itself;
//! - `files.restore` and `recovery.confirm` are proofs.
//!
//! Every response, the daemon's log, the audit entries and the home are
//! swept for the canaries.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use common::{client, data_dir, passphrase, project, seed_vault, start};
use envcloak_core::audit::{AuditEntry, AuditKind};
use envcloak_core::crypto::ItemClass;
use envcloak_core::vault::{FieldName, ItemDetails, LockedVault, NewItem, Slug, Vault, VaultPaths};
use envcloak_core::{RecoveryKit, SecretBytes};
use envcloak_ipc::proto::{
    BackupFileParams, ErrorKind, FilesBackupParams, ImportCommitParams, ImportEntry, ImportParams,
    ImportProject, VerifyEntry, VerifyFile, VerifyParams,
};
use envcloak_ipc::view::{EntryStatus, ImportPlanView, LengthClass, SkipReason};
use envcloak_ipc::{ClientError, WireSecret};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};

fn rpc(e: ClientError) -> ErrorKind {
    match e {
        ClientError::Rpc(r) => r.kind,
        other => panic!("expected an error response, got {other:?}"),
    }
}

fn json(v: &impl envcloak_ipc::view::View) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

/// A seeded, unlocked vault behind a running daemon.
struct Fixture {
    cs: Vec<Canary>,
    kit: Canary,
    home: TestHome,
    d: Daemon,
    /// A 10-byte token the vault does not hold.
    short: String,
}

impl Fixture {
    /// The story's seeded vault; `more` adds items before the daemon
    /// starts.
    fn new(more: impl FnOnce(&mut Vault, &[Canary])) -> Self {
        common::terminal_session();
        let cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        {
            let mut v = LockedVault::open(&VaultPaths::under(data_dir(&home)))
                .unwrap()
                .unlock_with_passphrase(&passphrase(&cs))
                .map_err(|(_, e)| e)
                .unwrap();
            more(&mut v, &cs);
        }
        let mut cs = cs;
        cs.push(kit.clone());
        // Generated here, never written down: 10 letters and digits.
        let seed = fresh_seed();
        let short: String = (0..10)
            .map(|i| {
                let n = (seed >> (i * 6)) as usize % 36;
                char::from(b"abcdefghijklmnopqrstuvwxyz0123456789"[n])
            })
            .collect();
        cs.push(Canary::new("SHORT_NEW", short.clone()));
        let d = start(&home);
        client(&home).unlock(passphrase(&cs), &[]).unwrap();
        Fixture {
            cs,
            kit,
            home,
            d,
            short,
        }
    }

    fn value(&self, label: &str) -> SecretBytes {
        SecretBytes::copy_from(by_label(&self.cs, label).value())
    }

    fn dir(&self, name: &str) -> String {
        self.home.root().join(name).to_str().unwrap().to_owned()
    }

    fn stop_and_open(&mut self) -> Vault {
        self.d.signal("-TERM");
        assert!(self.d.wait_exit(Duration::from_secs(30)).is_some());
        LockedVault::open(&VaultPaths::under(data_dir(&self.home)))
            .unwrap()
            .unlock_with_passphrase(&passphrase(&self.cs))
            .map_err(|(_, e)| e)
            .unwrap()
    }

    fn sweep(&self) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

fn entry(project: u32, file: &str, profile: Option<&str>, name: &str, v: &[u8]) -> ImportEntry {
    ImportEntry {
        project,
        file: file.to_owned(),
        line: 1,
        profile: profile.map(str::to_owned),
        name: name.to_owned(),
        value: WireSecret::new(SecretBytes::copy_from(v)),
    }
}

/// Two repos, as `envcloak import --scan` sends them: the same new OpenAI
/// key in both, a database URL, a short token in a profile, configuration,
/// an empty value, a key pasted as a name, and a GitHub token the vault
/// holds already.
fn two_repos(f: &Fixture) -> ImportParams {
    let rotated = by_label(&f.cs, labels::OPENAI_API_KEY_ROTATED).value();
    let url = by_label(&f.cs, labels::DATABASE_URL).value();
    let github = by_label(&f.cs, labels::GITHUB_TOKEN).value();
    let pasted = format!(
        "A{}",
        by_label(&f.cs, labels::STRIPE_SECRET_KEY).as_str()[8..].to_owned()
    );
    ImportParams {
        projects: vec![
            ImportProject {
                dir: f.dir("repo-a"),
                name: "repo-a".into(),
            },
            ImportProject {
                dir: f.dir("repo-b"),
                name: "repo-b".into(),
            },
        ],
        entries: vec![
            entry(0, ".env", None, "OPENAI_API_KEY", rotated),
            entry(0, ".env", None, "DATABASE_URL", url),
            entry(0, ".env", None, "PORT", b"8080"),
            entry(0, ".env", None, "NODE_ENV", b"production"),
            entry(0, ".env", None, "EMPTY", b""),
            entry(0, ".env", None, &pasted, b"a value long enough"),
            entry(
                0,
                ".env.short",
                Some("short"),
                "SHORT_TOKEN",
                f.short.as_bytes(),
            ),
            entry(1, ".env", None, "OPENAI_API_KEY", rotated),
            entry(1, ".env", None, "GITHUB_TOKEN", github),
        ],
        claims: Vec::new(),
    }
}

fn item_of(p: &ImportPlanView, entry: usize) -> &envcloak_ipc::view::ImportItemView {
    let at = p.entries[entry].item.unwrap();
    &p.items[at as usize]
}

/// The plan: secrets are told from configuration, equal values in two
/// repos become one item that both use, a value the vault holds binds to
/// its item, new items are named after their provider or variable and
/// project, and nothing is written. The commit makes exactly those items.
#[test]
fn a_plan_dedups_across_projects_and_the_commit_makes_it() {
    let mut f = Fixture::new(|_, _| {});
    let mut c = client(&f.home);
    let before = c.items_list(false).unwrap().items.len();
    let plan = c.import_plan(&two_repos(&f)).unwrap();
    let skipped: Vec<Option<SkipReason>> = plan.entries.iter().map(|e| e.skipped).collect();
    assert_eq!(
        skipped,
        [
            None,
            None,
            Some(SkipReason::TooShort),
            Some(SkipReason::NotSecret),
            Some(SkipReason::Empty),
            Some(SkipReason::LooksLikeValue),
            None,
            None,
            None,
        ]
    );
    let openai = item_of(&plan, 0);
    assert_eq!(openai.slug, "openai/repo-a");
    assert_eq!(openai.reference, "openai/repo-a");
    assert!(!openai.existing);
    assert_eq!(openai.provider.as_deref(), Some("openai"));
    assert_eq!((openai.entries, openai.projects), (2, 2));
    // The same value in repo-b: the same item.
    assert_eq!(plan.entries[7].item, plan.entries[0].item);
    assert_eq!(item_of(&plan, 1).slug, "database-url/repo-a");
    let short = item_of(&plan, 6);
    assert_eq!(short.slug, "short-token/repo-a-short");
    assert_eq!(short.length, LengthClass::Short);
    let github = item_of(&plan, 8);
    assert!(github.existing);
    assert_eq!(github.slug, "github/acme-web");
    assert_eq!(github.holders, ["github/acme-web"]);
    assert_eq!(plan.items.len(), 4);
    assert_no_canary(&json(&plan), &f.cs);
    // A plan writes nothing, and the same plan has the same digest.
    assert_eq!(c.items_list(false).unwrap().items.len(), before);
    assert_eq!(c.import_plan(&two_repos(&f)).unwrap().digest, plan.digest);

    let done = c
        .import_commit(&ImportCommitParams {
            import: two_repos(&f),
            digest: plan.digest.clone(),
        })
        .unwrap();
    assert_eq!(done, plan);
    let slugs: Vec<String> = c
        .items_list(false)
        .unwrap()
        .items
        .into_iter()
        .map(|i| i.slug)
        .collect();
    assert_eq!(slugs.len(), before + 3);
    for s in [
        "openai/repo-a",
        "database-url/repo-a",
        "short-token/repo-a-short",
    ] {
        assert!(slugs.iter().any(|x| x == s), "{s}");
    }
    // Committed again, the values bind to the items just made: another
    // plan, so the old digest is refused.
    let again = c.import_plan(&two_repos(&f)).unwrap();
    assert!(item_of(&again, 0).existing);
    assert_ne!(again.digest, plan.digest);
    let e = c
        .import_commit(&ImportCommitParams {
            import: two_repos(&f),
            digest: plan.digest.clone(),
        })
        .unwrap_err();
    assert_eq!(rpc(e), ErrorKind::PlanChanged);
    drop(c);
    let v = f.stop_and_open();
    let key = |slug: &str| {
        let item = v.find(&Slug::new(slug).unwrap()).unwrap();
        v.read_value(item.fields[0].id).unwrap()
    };
    assert!(key("openai/repo-a").ct_eq(by_label(&f.cs, labels::OPENAI_API_KEY_ROTATED).value()));
    assert!(key("short-token/repo-a-short").ct_eq(f.short.as_bytes()));
    let (entries, _) = v.read_audit().unwrap();
    let imports: Vec<&AuditEntry> = entries
        .iter()
        .filter(|e| e.record.kind == AuditKind::Import)
        .collect();
    assert_eq!(imports.len(), 1);
    assert_eq!(imports[0].record.items.len(), 3);
    assert_eq!(imports[0].record.decision.count, Some(1));
    for e in &entries {
        assert_no_canary(format!("{:?}", e.record).as_bytes(), &f.cs);
    }
    f.sweep();
}

/// Gate 10: a value two items hold is reported for both, and binds to the
/// first by slug.
#[test]
fn gate_10_a_value_two_items_hold_is_reported_for_both() {
    let f = Fixture::new(|v, cs| {
        v.transact(|t| {
            let id = t.create_item(NewItem {
                class: ItemClass::Secret,
                slug: Slug::new("openai/copy").unwrap(),
                details: ItemDetails::default(),
            })?;
            t.add_field(
                id,
                FieldName::new("value").unwrap(),
                SecretBytes::copy_from(by_label(cs, labels::OPENAI_API_KEY).value()),
            )?;
            Ok(())
        })
        .unwrap();
    });
    let p = ImportParams {
        projects: vec![ImportProject {
            dir: f.dir("acme-web"),
            name: "acme-web".into(),
        }],
        entries: vec![entry(
            0,
            ".env",
            None,
            "OPENAI_API_KEY",
            by_label(&f.cs, labels::OPENAI_API_KEY).value(),
        )],
        claims: Vec::new(),
    };
    let plan = client(&f.home).import_plan(&p).unwrap();
    let item = item_of(&plan, 0);
    assert!(item.existing);
    assert_eq!(item.holders, ["openai/acme-web", "openai/copy"]);
    assert_eq!(item.reference, "openai/acme-web");
    assert_no_canary(&json(&plan), &f.cs);
    f.sweep();
}

/// The commit is refused when the plan changed after it was shown: here
/// an item holding one of the values was added meanwhile.
#[test]
fn a_commit_is_refused_when_the_plan_changed() {
    let f = Fixture::new(|_, _| {});
    let mut c = client(&f.home);
    let plan = c.import_plan(&two_repos(&f)).unwrap();
    let before = c.items_list(false).unwrap().items.len();
    c.items_add(&envcloak_ipc::proto::AddParams {
        slug: Some("database/meanwhile".into()),
        provider: None,
        field: None,
        account: None,
        env_hint: None,
        allow_short: false,
        value: WireSecret::new(f.value(labels::DATABASE_URL)),
        claims: Vec::new(),
    })
    .unwrap();
    let e = c
        .import_commit(&ImportCommitParams {
            import: two_repos(&f),
            digest: plan.digest.clone(),
        })
        .unwrap_err();
    assert_eq!(rpc(e), ErrorKind::PlanChanged);
    assert_eq!(c.items_list(false).unwrap().items.len(), before + 1);
    let e = c
        .import_commit(&ImportCommitParams {
            import: two_repos(&f),
            digest: "00".repeat(32),
        })
        .unwrap_err();
    assert_eq!(rpc(e), ErrorKind::PlanChanged);
    f.sweep();
}

/// The delete gate's answers: an entry is stored only where the manifest
/// the daemon opens binds its variable to an item holding its value;
/// configuration is left out; a reference that does not resolve and an
/// unconfirmed kit are reported. Then `recovery.confirm`, a proof.
#[test]
fn verify_answers_the_delete_gate_and_the_kit_is_confirmed_with_a_proof() {
    let mut f = Fixture::new(|_, _| {});
    let manifest = project(
        &f.home,
        "acme-web",
        "[project]\nname = \"acme-web\"\n\n[env]\nOPENAI_API_KEY = \"openai/acme-web\"\nGITHUB_TOKEN = \"stripe/acme-web\"\n\n[env.short]\nSHORT_TOKEN = \"short/acme-web\"\n",
    );
    let manifest = manifest.to_str().unwrap().to_owned();
    let verify = |f: &Fixture, manifest: &str| VerifyParams {
        manifest: manifest.to_owned(),
        files: vec![
            VerifyFile {
                file: ".env".into(),
                profile: None,
                entries: vec![
                    VerifyEntry {
                        line: 1,
                        name: "OPENAI_API_KEY".into(),
                        value: WireSecret::new(f.value(labels::OPENAI_API_KEY)),
                    },
                    VerifyEntry {
                        line: 2,
                        name: "PORT".into(),
                        value: WireSecret::new(SecretBytes::copy_from(b"8080")),
                    },
                    // Bound, but to an item holding another value.
                    VerifyEntry {
                        line: 3,
                        name: "GITHUB_TOKEN".into(),
                        value: WireSecret::new(f.value(labels::GITHUB_TOKEN)),
                    },
                ],
            },
            VerifyFile {
                file: ".env.short".into(),
                profile: Some("short".into()),
                entries: vec![VerifyEntry {
                    line: 1,
                    name: "SHORT_TOKEN".into(),
                    value: WireSecret::new(f.value(labels::SHORT_TOKEN)),
                }],
            },
        ],
        claims: Vec::new(),
    };
    let mut c = client(&f.home);
    let v = c.import_verify(&verify(&f, &manifest)).unwrap();
    assert!(!v.recovery_confirmed);
    assert!(v.resolves);
    let status: Vec<EntryStatus> = v.files[0].entries.iter().map(|e| e.status).collect();
    assert_eq!(
        status,
        [
            EntryStatus::Stored,
            EntryStatus::LeftOut,
            EntryStatus::NotStored
        ]
    );
    assert_eq!(v.files[0].entries[1].skipped, Some(SkipReason::TooShort));
    assert!(!v.files[0].covered);
    assert!(v.files[1].covered);
    assert!(!v.deletable());
    assert_no_canary(&json(&v), &f.cs);

    // A manifest whose reference does not resolve.
    let bad = project(
        &f.home,
        "broken",
        "[env]\nOPENAI_API_KEY = \"openai/acme-web\"\nGONE = \"no/such-item\"\n",
    );
    let v = c.import_verify(&verify(&f, bad.to_str().unwrap())).unwrap();
    assert!(!v.resolves);

    // The kit: a wrong one is refused and counted, a malformed one too;
    // the right one confirms it, once.
    let wrong = RecoveryKit::generate().to_display();
    let e = c
        .recovery_confirm(SecretBytes::copy_from(wrong.as_bytes()), &[])
        .unwrap_err();
    assert_eq!(rpc(e), ErrorKind::WrongPassphrase);
    let e = c
        .recovery_confirm(SecretBytes::copy_from(b"not a kit at all"), &[])
        .unwrap_err();
    assert_eq!(rpc(e), ErrorKind::WrongPassphrase);
    // An agent's marker: refused before the kit is looked at.
    let e = c
        .recovery_confirm(
            SecretBytes::copy_from(f.kit.value()),
            &["ENVCLOAK_FIXTURE_AGENT".to_owned()],
        )
        .unwrap_err();
    assert_eq!(rpc(e), ErrorKind::ProofRefused);
    let ok = c
        .recovery_confirm(SecretBytes::copy_from(f.kit.value()), &[])
        .unwrap();
    assert!(!ok.already);
    let ok = c
        .recovery_confirm(SecretBytes::copy_from(f.kit.value()), &[])
        .unwrap();
    assert!(ok.already);
    assert!(
        c.import_verify(&verify(&f, &manifest))
            .unwrap()
            .recovery_confirmed
    );
    drop(c);
    let vault = f.stop_and_open();
    assert!(vault.recovery_confirmed().unwrap());
    let (entries, _) = vault.read_audit().unwrap();
    let confirms: Vec<&str> = entries
        .iter()
        .filter(|e| e.record.kind == AuditKind::RecoveryConfirm)
        .map(|e| e.record.decision.outcome.as_str())
        .collect();
    assert_eq!(confirms, ["failed", "confirmed", "confirmed"]);
    for e in &entries {
        assert_no_canary(format!("{:?}", e.record).as_bytes(), &f.cs);
    }
    f.sweep();
}

/// `files.backup` writes ciphertext; `files.restore` hands the bytes back
/// only with the passphrase from a terminal subject.
#[test]
fn a_file_backup_comes_back_only_with_a_proof() {
    let mut f = Fixture::new(|_, _| {});
    let key = by_label(&f.cs, labels::OPENAI_API_KEY).as_str();
    let body = format!("OPENAI_API_KEY={key}\nPORT=8080\n");
    let path = f.home.root().join("acme-web/.env");
    let mut c = client(&f.home);
    let b = c
        .files_backup(&FilesBackupParams {
            files: vec![BackupFileParams {
                path: path.to_str().unwrap().to_owned(),
                mode: 0o600,
                content: WireSecret::new(SecretBytes::copy_from(body.as_bytes())),
            }],
            claims: Vec::new(),
        })
        .unwrap();
    assert_eq!(b.id.len(), 26);
    assert_eq!(b.files, 1);
    assert!(b.file_name.ends_with(".ecfiles"));
    // A relative path is refused.
    let e = c
        .files_backup(&FilesBackupParams {
            files: vec![BackupFileParams {
                path: "relative/.env".into(),
                mode: 0o600,
                content: WireSecret::new(SecretBytes::copy_from(b"A=1")),
            }],
            claims: Vec::new(),
        })
        .unwrap_err();
    assert_eq!(rpc(e), ErrorKind::InvalidParams);

    let wrong = SecretBytes::copy_from(b"not the passphrase, not at all");
    let e = c.files_restore(&b.id, wrong, &[]).unwrap_err();
    assert_eq!(rpc(e), ErrorKind::WrongPassphrase);
    let e = c
        .files_restore(
            &b.id,
            passphrase(&f.cs),
            &["ENVCLOAK_FIXTURE_AGENT".to_owned()],
        )
        .unwrap_err();
    assert_eq!(rpc(e), ErrorKind::ProofRefused);
    let e = c
        .files_restore("0000000000000000000000000Z", passphrase(&f.cs), &[])
        .unwrap_err();
    assert_eq!(rpc(e), ErrorKind::NoSuchBackup);
    let e = c.files_restore("nope", passphrase(&f.cs), &[]).unwrap_err();
    assert_eq!(rpc(e), ErrorKind::NoSuchBackup);
    let back = c.files_restore(&b.id, passphrase(&f.cs), &[]).unwrap();
    assert_eq!(back.files.len(), 1);
    assert_eq!(back.files[0].path, path.to_str().unwrap());
    assert_eq!(back.files[0].mode, 0o600);
    assert!(back.files[0].content.as_secret().ct_eq(body.as_bytes()));
    drop((c, back));
    let v = f.stop_and_open();
    let (entries, _) = v.read_audit().unwrap();
    let kinds: Vec<(AuditKind, &str)> = entries
        .iter()
        .filter(|e| {
            matches!(
                e.record.kind,
                AuditKind::FilesBackup | AuditKind::FilesRestore
            )
        })
        .map(|e| (e.record.kind, e.record.decision.outcome.as_str()))
        .collect();
    assert_eq!(
        kinds,
        [
            (AuditKind::FilesBackup, "backed_up"),
            (AuditKind::FilesRestore, "failed"),
            (AuditKind::FilesRestore, "restored"),
        ]
    );
    for e in &entries {
        assert_no_canary(format!("{:?}", e.record).as_bytes(), &f.cs);
    }
    f.sweep();
}
