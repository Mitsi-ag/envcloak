//! Import over the daemon's socket (SPEC §6.4, gates 10 and 16; T13):
//! - `import.plan` sorts entries into secrets and configuration, groups
//!   equal values by keyed hash, computed here in the daemon (the CLI has
//!   no key), across projects, binds a value the vault holds to its item,
//!   and reports every item that holds it (gate 10); it writes nothing;
//! - `import.commit` writes exactly the plan whose digest it is given;
//! - `import.verify` answers the delete gate from the manifest the daemon
//!   opens itself;
//! - no caller but a person learns whether the vault holds a value short
//!   enough to guess, and values compared are limited per subject root
//!   and audited by count;
//! - `files.restore` and `recovery.confirm` are proofs.
//!
//! Every response, the daemon's log, the audit entries and the home are
//! swept for the canaries.
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::PermissionsExt;
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
use envcloak_ipc::view::{EntryStatus, ImportPlanView, LengthClass, SkipReason, VerifyView};
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
        .filter(|e| e.record.kind == AuditKind::Import && e.record.decision.outcome == "imported")
        .collect();
    assert_eq!(imports.len(), 1);
    assert_eq!(imports[0].record.items.len(), 3);
    assert_eq!(imports[0].record.decision.count, Some(1));
    // Every call that compared values is audited with their count (the
    // five secrets of the nine entries), the refused commit too.
    let checks: Vec<(&str, Option<u64>)> = entries
        .iter()
        .filter(|e| e.record.kind == AuditKind::Import && e.record.decision.outcome == "checked")
        .map(|e| {
            (
                e.record.decision.method.as_deref().unwrap(),
                e.record.decision.count,
            )
        })
        .collect();
    assert_eq!(
        checks,
        [
            ("import.plan", Some(5)),
            ("import.plan", Some(5)),
            ("import.commit", Some(5)),
            ("import.plan", Some(5)),
            ("import.commit", Some(5)),
        ]
    );
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
    // A relative path is refused, and so is a file that is not an env
    // file: a backup is written back by `init --undo`, so none may stage
    // another file there (a launch agent, a shell profile).
    let home = f.home.home();
    for path in [
        "relative/.env".to_owned(),
        home.join("Library/LaunchAgents/x.plist")
            .to_string_lossy()
            .into_owned(),
        home.join(".zshrc").to_string_lossy().into_owned(),
        home.join(".envrc").to_string_lossy().into_owned(),
        home.join("dir/.env/").to_string_lossy().into_owned(),
    ] {
        let e = c
            .files_backup(&FilesBackupParams {
                files: vec![BackupFileParams {
                    path: path.clone(),
                    mode: 0o600,
                    content: WireSecret::new(SecretBytes::copy_from(b"A=1")),
                }],
                claims: Vec::new(),
            })
            .unwrap_err();
        assert_eq!(rpc(e), ErrorKind::InvalidParams, "{path}");
    }

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

/// The marker the fixture catalog knows as an agent's.
const AGENT: &str = "ENVCLOAK_FIXTURE_AGENT";

/// One project, `acme-web`, with `entries`, asked as `claims` says.
fn one_project(f: &Fixture, entries: Vec<ImportEntry>, claims: &[&str]) -> ImportParams {
    ImportParams {
        projects: vec![ImportProject {
            dir: f.dir("acme-web"),
            name: "acme-web".into(),
        }],
        entries,
        claims: claims.iter().map(|c| (*c).to_owned()).collect(),
    }
}

/// `n` random lowercase letters and digits.
fn word(n: usize) -> String {
    let mut out = String::new();
    while out.len() < n {
        let seed = fresh_seed();
        for i in 0..10 {
            let k = usize::try_from((seed >> (i * 6)) % 36).unwrap();
            out.push(char::from(b"abcdefghijklmnopqrstuvwxyz0123456789"[k]));
        }
    }
    out.truncate(n);
    out
}

/// A verify answer as it reads for one entry.
fn statuses(v: &VerifyView) -> Vec<(EntryStatus, Option<SkipReason>)> {
    v.files[0]
        .entries
        .iter()
        .map(|e| (e.status, e.skipped))
        .collect()
}

/// Review finding (high): `import.plan` and `import.verify` confirmed
/// guesses against the vault for any caller. A value short enough to
/// guess (the vault's 10-byte `short/acme-web`) is imported and compared
/// only for a person: an agent's right guess and wrong guess get the same
/// answer, alone or among many, from `import.plan`, `import.commit` and
/// `import.verify`, and nothing is imported; a person's are told apart. A
/// value of 16 bytes or more, which cannot be guessed, is compared for
/// anyone.
#[test]
fn an_agent_guessing_a_short_value_learns_nothing() {
    let mut f = Fixture::new(|_, _| {});
    let right = by_label(&f.cs, labels::SHORT_TOKEN).value().to_vec();
    let wrong = f.short.as_bytes().to_vec();
    let guess = |v: &[u8], claims: &[&str]| {
        one_project(&f, vec![entry(0, ".env", None, "DB_PASSWORD", v)], claims)
    };
    let mut c = client(&f.home);
    let hit = c.import_plan(&guess(&right, &[AGENT])).unwrap();
    let miss = c.import_plan(&guess(&wrong, &[AGENT])).unwrap();
    assert_eq!(hit, miss);
    assert_eq!(hit.entries[0].skipped, Some(SkipReason::Guessable));
    assert!(hit.items.is_empty());

    // 200 guesses in one request, the right one among them.
    let mut many: Vec<ImportEntry> = (0..200)
        .map(|n| {
            let w = word(10);
            entry(
                0,
                ".env",
                None,
                &format!("GUESS_{n}_PASSWORD"),
                w.as_bytes(),
            )
        })
        .collect();
    many[123] = entry(0, ".env", None, "GUESS_123_PASSWORD", &right);
    let plan = c.import_plan(&one_project(&f, many, &[AGENT])).unwrap();
    assert!(plan.items.is_empty());
    assert!(
        plan.entries
            .iter()
            .all(|e| e.skipped == Some(SkipReason::Guessable))
    );

    // The delete gate, with a manifest binding the variable to the item
    // that holds the value: the same answer for both guesses.
    let manifest = project(
        &f.home,
        "guessing",
        "[env]\nDB_PASSWORD = \"short/acme-web\"\n",
    );
    let ask = |c: &mut envcloak_ipc::Client, v: &[u8], claims: &[&str]| {
        c.import_verify(&VerifyParams {
            manifest: manifest.to_str().unwrap().to_owned(),
            files: vec![VerifyFile {
                file: ".env".into(),
                profile: None,
                entries: vec![VerifyEntry {
                    line: 1,
                    name: "DB_PASSWORD".into(),
                    value: WireSecret::new(SecretBytes::copy_from(v)),
                }],
            }],
            claims: claims.iter().map(|c| (*c).to_owned()).collect(),
        })
        .unwrap()
    };
    let hit = ask(&mut c, &right, &[AGENT]);
    let miss = ask(&mut c, &wrong, &[AGENT]);
    assert_eq!(hit, miss);
    assert_eq!(
        statuses(&hit),
        [(EntryStatus::LeftOut, Some(SkipReason::Guessable))]
    );
    // The file is still covered: an entry left out stays in its file.
    assert!(hit.files[0].covered);

    // The commit of an agent's plan imports nothing.
    let before = c.items_list(false).unwrap().items.len();
    let plan = c.import_plan(&guess(&right, &[AGENT])).unwrap();
    let done = c
        .import_commit(&ImportCommitParams {
            import: guess(&right, &[AGENT]),
            digest: plan.digest.clone(),
        })
        .unwrap();
    assert_eq!(done, plan);
    assert_eq!(c.items_list(false).unwrap().items.len(), before);

    // A person (this test is a terminal session with no agent) is told.
    let plan = c.import_plan(&guess(&right, &[])).unwrap();
    assert!(item_of(&plan, 0).existing);
    assert_eq!(item_of(&plan, 0).holders, ["short/acme-web"]);
    let plan = c.import_plan(&guess(&wrong, &[])).unwrap();
    assert!(!item_of(&plan, 0).existing);
    assert_eq!(
        statuses(&ask(&mut c, &right, &[])),
        [(EntryStatus::Stored, None)]
    );
    assert_eq!(
        statuses(&ask(&mut c, &wrong, &[])),
        [(EntryStatus::NotStored, None)]
    );

    // 16 bytes or more is compared for anyone.
    let key = by_label(&f.cs, labels::OPENAI_API_KEY).value().to_vec();
    let plan = c
        .import_plan(&one_project(
            &f,
            vec![entry(0, ".env", None, "OPENAI_API_KEY", &key)],
            &[AGENT],
        ))
        .unwrap();
    assert!(item_of(&plan, 0).existing);
    drop(c);

    let v = f.stop_and_open();
    let (entries, _) = v.read_audit().unwrap();
    let agent_checks: Vec<(&str, Option<u64>)> = entries
        .iter()
        .filter(|e| {
            e.record.kind == AuditKind::Import
                && e.record.decision.outcome == "checked"
                && e.record.subject.kind.as_deref() == Some("agent")
        })
        .map(|e| {
            (
                e.record.decision.method.as_deref().unwrap(),
                e.record.decision.count,
            )
        })
        .collect();
    // An agent's guesses are never compared: counted as none.
    assert_eq!(
        agent_checks,
        [
            ("import.plan", Some(0)),
            ("import.plan", Some(0)),
            ("import.plan", Some(0)),
            ("import.verify", Some(0)),
            ("import.verify", Some(0)),
            ("import.plan", Some(0)),
            ("import.commit", Some(0)),
            ("import.plan", Some(1)),
        ]
    );
    for e in &entries {
        assert_no_canary(format!("{:?}", e.record).as_bytes(), &f.cs);
    }
    f.sweep();
}

/// `n` characters drawn at random from `alphabet`.
fn chars_of(alphabet: &[char], n: usize) -> String {
    let mut out = String::new();
    while out.chars().count() < n {
        let seed = fresh_seed();
        for i in 0..8 {
            let k = usize::try_from((seed >> (i * 8)) % alphabet.len() as u64).unwrap();
            out.push(alphabet[k]);
        }
    }
    out.chars().take(n).collect()
}

/// Review finding F-58 (Codex): the cutoff counted bytes, so a short
/// password of two-byte letters (8 characters, 16 bytes) was compared with
/// the vault for an agent, which then told a right guess from a wrong one.
/// Counted in characters, a value under 16 of them is left out for an
/// agent, hit or miss, with two-, three- and four-byte characters; a
/// person's guesses are still told apart, and 16 characters are compared
/// for anyone.
#[test]
fn short_values_are_counted_in_characters() {
    let mut f = Fixture::new(|_, _| {});
    let mut c = client(&f.home);
    for (width, alphabet) in [
        (2, ['\u{e9}', '\u{fc}', '\u{f1}', '\u{f8}']),
        (3, ['\u{20ac}', '\u{3042}', '\u{4e2d}', '\u{d55c}']),
        (4, ['\u{1f600}', '\u{1d538}', '\u{1f980}', '\u{10348}']),
    ] {
        let (right, wrong, long) = (
            chars_of(&alphabet, 8),
            chars_of(&alphabet, 8),
            chars_of(&alphabet, 16),
        );
        assert!(right.len() >= 16 && right != wrong);
        for (label, v) in [("RIGHT", &right), ("WRONG", &wrong), ("LONG", &long)] {
            f.cs.push(Canary::new(format!("{label}_{width}"), v.clone()));
        }
        for (slug, v) in [("right", &right), ("long", &long)] {
            c.items_add(&envcloak_ipc::proto::AddParams {
                slug: Some(format!("multibyte-{slug}/w{width}")),
                provider: None,
                field: None,
                account: None,
                env_hint: None,
                allow_short: false,
                value: WireSecret::new(SecretBytes::copy_from(v.as_bytes())),
                claims: Vec::new(),
            })
            .unwrap();
        }
        let guess = |v: &str, claims: &[&str]| {
            one_project(
                &f,
                vec![entry(0, ".env", None, "DB_PASSWORD", v.as_bytes())],
                claims,
            )
        };
        let hit = c.import_plan(&guess(&right, &[AGENT])).unwrap();
        let miss = c.import_plan(&guess(&wrong, &[AGENT])).unwrap();
        assert_eq!(hit, miss, "{width}-byte characters");
        assert_eq!(hit.entries[0].skipped, Some(SkipReason::Guessable));
        assert!(hit.items.is_empty());
        // A person is told.
        let plan = c.import_plan(&guess(&right, &[])).unwrap();
        assert_eq!(
            item_of(&plan, 0).holders,
            [format!("multibyte-right/w{width}")]
        );
        let plan = c.import_plan(&guess(&wrong, &[])).unwrap();
        assert!(!item_of(&plan, 0).existing);
        // 16 characters cannot be guessed: compared for anyone.
        let plan = c.import_plan(&guess(&long, &[AGENT])).unwrap();
        assert_eq!(
            item_of(&plan, 0).holders,
            [format!("multibyte-long/w{width}")]
        );
    }
    // A value that is not UTF-8 is counted four bytes a character: 60
    // bytes are short, 64 are not.
    let short = c
        .import_plan(&one_project(
            &f,
            vec![entry(0, ".env", None, "DB_PASSWORD", &[0xff; 60])],
            &[AGENT],
        ))
        .unwrap();
    assert_eq!(short.entries[0].skipped, Some(SkipReason::Guessable));
    let long = c
        .import_plan(&one_project(
            &f,
            vec![entry(0, ".env", None, "DB_PASSWORD", &[0xff; 64])],
            &[AGENT],
        ))
        .unwrap();
    assert_eq!(long.entries[0].skipped, None);
    let plans = [json(&short), json(&long)];
    for p in &plans {
        assert_no_canary(p, &f.cs);
    }
    f.sweep();
}

/// A value that holds a password: a name for its slug and canaries, the
/// variable it is imported from, the value around a password, and a right
/// and a wrong password.
struct Shape {
    name: &'static str,
    var: &'static str,
    value: ValueOf,
    right: String,
    wrong: String,
}

/// A value around a password: the password in, the value out.
type ValueOf = fn(&str) -> String;

/// Adds `value` to the vault as `slug`, as a person would.
fn add_item(c: &mut envcloak_ipc::Client, slug: &str, value: &str) {
    c.items_add(&envcloak_ipc::proto::AddParams {
        slug: Some(slug.to_owned()),
        provider: None,
        field: None,
        account: None,
        env_hint: None,
        allow_short: false,
        value: WireSecret::new(SecretBytes::copy_from(value.as_bytes())),
        claims: Vec::new(),
    })
    .unwrap();
}

/// For each shape, with the vault holding its value around the right
/// password (`pw-<name>/acme-web`): an agent's right and wrong guesses get
/// the same answer (`guessable`) from `import.plan`, `import.commit` and
/// `import.verify`, and nothing is imported; a person's are told apart.
fn guesses_are_hidden(f: &mut Fixture, c: &mut envcloak_ipc::Client, shapes: &[Shape]) {
    for s in shapes {
        let (right, wrong) = ((s.value)(&s.right), (s.value)(&s.wrong));
        // 16 characters or more: measured whole, the value would be
        // compared for anyone.
        assert!(right.chars().count() >= 16 && right != wrong, "{}", s.name);
        for (label, v) in [
            ("RIGHT", &right),
            ("WRONG", &wrong),
            ("RIGHT_PASSWORD", &s.right),
            ("WRONG_PASSWORD", &s.wrong),
        ] {
            f.cs.push(Canary::new(format!("{label}_{}", s.name), v.clone()));
        }
        let slug = format!("pw-{}/acme-web", s.name);
        add_item(c, &slug, &right);
        let guess = |v: &str, claims: &[&str]| {
            one_project(f, vec![entry(0, ".env", None, s.var, v.as_bytes())], claims)
        };
        let hit = c.import_plan(&guess(&right, &[AGENT])).unwrap();
        let miss = c.import_plan(&guess(&wrong, &[AGENT])).unwrap();
        assert_eq!(hit, miss, "{}", s.name);
        assert_eq!(
            hit.entries[0].skipped,
            Some(SkipReason::Guessable),
            "{}",
            s.name
        );
        assert!(hit.items.is_empty(), "{}", s.name);
        // The commit of an agent's plan imports nothing.
        let before = c.items_list(false).unwrap().items.len();
        let done = c
            .import_commit(&ImportCommitParams {
                import: guess(&right, &[AGENT]),
                digest: hit.digest.clone(),
            })
            .unwrap();
        assert_eq!(done, hit, "{}", s.name);
        assert_eq!(c.items_list(false).unwrap().items.len(), before);
        // The delete gate, with the variable bound to the item that holds
        // the right value: the same answer for both guesses.
        let manifest = project(
            &f.home,
            &format!("pw-{}", s.name),
            &format!("[env]\n{} = \"{slug}\"\n", s.var),
        );
        let ask = |c: &mut envcloak_ipc::Client, v: &str, claims: &[&str]| {
            c.import_verify(&VerifyParams {
                manifest: manifest.to_str().unwrap().to_owned(),
                files: vec![VerifyFile {
                    file: ".env".into(),
                    profile: None,
                    entries: vec![VerifyEntry {
                        line: 1,
                        name: s.var.into(),
                        value: WireSecret::new(SecretBytes::copy_from(v.as_bytes())),
                    }],
                }],
                claims: claims.iter().map(|c| (*c).to_owned()).collect(),
            })
            .unwrap()
        };
        let hit = ask(c, &right, &[AGENT]);
        let miss = ask(c, &wrong, &[AGENT]);
        assert_eq!(hit, miss, "{}", s.name);
        assert_eq!(
            statuses(&hit),
            [(EntryStatus::LeftOut, Some(SkipReason::Guessable))],
            "{}",
            s.name
        );
        // A person is told.
        let plan = c.import_plan(&guess(&right, &[])).unwrap();
        assert_eq!(
            item_of(&plan, 0).holders,
            std::slice::from_ref(&slug),
            "{}",
            s.name
        );
        let plan = c.import_plan(&guess(&wrong, &[])).unwrap();
        assert!(!item_of(&plan, 0).existing, "{}", s.name);
        assert_eq!(
            statuses(&ask(c, &right, &[])),
            [(EntryStatus::Stored, None)],
            "{}",
            s.name
        );
        assert_eq!(
            statuses(&ask(c, &wrong, &[])),
            [(EntryStatus::NotStored, None)],
            "{}",
            s.name
        );
        for p in [json(&hit), json(&plan)] {
            assert_no_canary(&p, &f.cs);
        }
    }
}

/// Each value (a name for its slug, its variable, the value around a
/// password, and the password), which no reading gives a password under
/// 16 characters, is compared for anyone: the vault holds it as
/// `long-<name>/acme-web`, and an agent's plan binds it there.
fn compared_for_anyone(
    f: &mut Fixture,
    c: &mut envcloak_ipc::Client,
    values: &[(&str, &str, ValueOf, String)],
) {
    for (name, var, value, pw) in values {
        let v = value(pw);
        f.cs.push(Canary::new(format!("LONG_{name}"), v.clone()));
        f.cs.push(Canary::new(format!("LONG_PASSWORD_{name}"), pw.clone()));
        let slug = format!("long-{name}/acme-web");
        add_item(c, &slug, &v);
        let plan = c
            .import_plan(&one_project(
                f,
                vec![entry(0, ".env", None, var, v.as_bytes())],
                &[AGENT],
            ))
            .unwrap();
        assert_eq!(plan.entries[0].skipped, None, "{name}");
        assert_eq!(item_of(&plan, 0).holders, [slug], "{name}");
        assert_no_canary(&json(&plan), &f.cs);
    }
}

/// `%XX` escapes of every byte of `w`.
fn escaped(w: &str) -> String {
    w.bytes().map(|b| format!("%{b:02X}")).collect()
}

/// Review finding (medium): a URL with a password was measured whole,
/// always 16 characters or more, so `import.plan` and `import.verify`
/// told an agent's right guess of a short database password from a wrong
/// one. In a URL only the password counts: with 8 characters, 10 with no
/// user, or 6 written as `%XX` escapes (18 bytes), it is left out for an
/// agent, hit or miss, from `import.plan`, `import.commit` and
/// `import.verify`, and nothing is imported; a person is told; a URL
/// whose password has 16 characters is compared for anyone.
#[test]
fn a_short_password_in_a_long_url_is_guessable() {
    let mut f = Fixture::new(|_, _| {});
    let mut c = client(&f.home);
    let shapes = [
        Shape {
            name: "postgres",
            var: "DATABASE_URL",
            value: |pw| format!("postgres://app:{pw}@db.internal:5432/app"),
            right: word(8),
            wrong: word(8),
        },
        Shape {
            name: "redis",
            var: "DATABASE_URL",
            value: |pw| format!("redis://:{pw}@cache.internal:6379/0"),
            right: word(10),
            wrong: word(10),
        },
        Shape {
            name: "escaped",
            var: "DATABASE_URL",
            value: |pw| format!("mysql://app:{pw}@db.internal:3306/app"),
            right: escaped(&word(6)),
            wrong: escaped(&word(6)),
        },
    ];
    guesses_are_hidden(&mut f, &mut c, &shapes);
    compared_for_anyone(
        &mut f,
        &mut c,
        &[(
            "url",
            "DATABASE_URL",
            |pw| format!("postgres://app:{pw}@db.internal:5432/app"),
            word(16),
        )],
    );
    drop(c);
    f.sweep();
}

/// Review finding F-61 (Codex): the password ran to the last `@` of the
/// URL, so with an `@` in its path, query or fragment
/// (`?application_name=api@prod`) the host and the rest counted as
/// password, an 8-character password counted over 16, and an agent's
/// right guess was told from a wrong one. Every reading of the password a
/// server could take is counted and any under 16 characters makes it
/// guessable: with an `@` in the query, the path or the fragment, escaped,
/// or after a password holding `/`, an agent's guesses get one answer and
/// a person's are told apart; 16 characters with an `@` in the query are
/// compared for anyone.
#[test]
fn an_at_sign_after_the_authority_leaves_a_short_password_short() {
    let mut f = Fixture::new(|_, _| {});
    let mut c = client(&f.home);
    let shapes = [
        Shape {
            name: "query",
            var: "DATABASE_URL",
            value: |pw| {
                format!("postgres://app:{pw}@db.internal:5432/app?application_name=api@prod")
            },
            right: word(8),
            wrong: word(8),
        },
        Shape {
            name: "path",
            var: "DATABASE_URL",
            value: |pw| format!("postgres://app:{pw}@db.internal:5432/app@v2/data"),
            right: word(8),
            wrong: word(8),
        },
        Shape {
            name: "fragment",
            var: "DATABASE_URL",
            value: |pw| format!("https://app:{pw}@api.internal/v1#section@anchor"),
            right: word(8),
            wrong: word(8),
        },
        Shape {
            name: "escaped-query",
            var: "DATABASE_URL",
            value: |pw| format!("mysql://app:{pw}@db.internal:3306/app?tag=x@y"),
            right: escaped(&word(6)),
            wrong: escaped(&word(6)),
        },
        Shape {
            name: "slash",
            var: "DATABASE_URL",
            value: |pw| {
                format!("postgres://app:{pw}/x@db.internal:5432/app?application_name=api@prod")
            },
            right: word(6),
            wrong: word(6),
        },
    ];
    guesses_are_hidden(&mut f, &mut c, &shapes);
    compared_for_anyone(
        &mut f,
        &mut c,
        &[(
            "query",
            "DATABASE_URL",
            |pw| format!("postgres://app:{pw}@db.internal:5432/app?application_name=api@prod"),
            word(16),
        )],
    );
    drop(c);
    f.sweep();
}

/// Review R-4: only the first `://` of a value was read, so in a value
/// listing several URLs (Redis Sentinel's list, a proxy's URL before a
/// database's) a password in a later one was measured from the first
/// one's port, and an agent's right guess of an 8-character password was
/// told from a wrong one. Every `://` starts a URL whose password counts:
/// an agent's guesses get one answer and a person's are told apart; 16
/// characters there are compared for anyone.
#[test]
fn a_short_password_in_a_later_url_is_guessable() {
    let mut f = Fixture::new(|_, _| {});
    let mut c = client(&f.home);
    let sentinel: ValueOf =
        |pw| format!("redis://s1.internal:26379,redis://:{pw}@s2.internal:26379");
    let proxied: ValueOf =
        |pw| format!("https://proxy.internal:8443/x postgres://app:{pw}@db.internal/app");
    let shapes = [("sentinel", sentinel), ("proxied", proxied)].map(|(name, value)| Shape {
        name,
        var: "DATABASE_URL",
        value,
        right: word(8),
        wrong: word(8),
    });
    guesses_are_hidden(&mut f, &mut c, &shapes);
    compared_for_anyone(
        &mut f,
        &mut c,
        &[
            ("sentinel", "DATABASE_URL", sentinel, word(16)),
            ("proxied", "DATABASE_URL", proxied, word(16)),
        ],
    );
    drop(c);
    f.sweep();
}

/// Review T13 open 2: only `scheme://user:password@` was known, so under a
/// DSN-named variable a short password in Go's MySQL DSN, the libpq
/// keyword form, a JDBC query or an ADO.NET string was measured with the
/// whole value, and an agent's right guess of an 8-character password
/// was told from a wrong one. Each form's password counts alone: an
/// agent's guesses get one answer from plan, commit and verify, a
/// person's are told apart, and 16 characters in each form are compared
/// for anyone. The DSN is read with an address and, since review R-3,
/// with a protocol and no address (`app:<8>@tcp/app`, 20 characters);
/// since review R-11, also when its password starts with `//`
/// (`app://<8>@tcp(db.internal:3306)/app`, a password of 10 characters in
/// 40), whose control has 16 characters, `//` included; and since review
/// R-18, with an address and no protocol name
/// (`app:<8>@(db.internal:3306)/app`, 36 characters).
#[test]
fn a_short_password_in_a_connection_string_is_guessable() {
    let mut f = Fixture::new(|_, _| {});
    let mut c = client(&f.home);
    let go: ValueOf = |pw| format!("app:{pw}@tcp(db.internal:3306)/app?parseTime=true");
    // Review R-3: a protocol and no address, `@tcp/`, the default address.
    let go_default: ValueOf = |pw| format!("app:{pw}@tcp/app");
    // Review R-11: a password starting with `//`, so the first `:` starts
    // `://`.
    let go_slashes: ValueOf = |pw| format!("app://{pw}@tcp(db.internal:3306)/app");
    // Review R-18: an address and no protocol name, which the driver reads
    // as tcp.
    let go_no_protocol: ValueOf = |pw| format!("app:{pw}@(db.internal:3306)/app");
    let libpq: ValueOf = |pw| {
        format!("host=db.internal port=5432 dbname=app user=app password={pw} sslmode=require")
    };
    let jdbc: ValueOf =
        |pw| format!("jdbc:postgresql://db.internal:5432/app?user=app&password={pw}&ssl=true");
    let ado: ValueOf = |pw| format!("Server=db.internal;Database=app;User Id=app;Password={pw};");
    let shapes = [
        ("go-dsn", go),
        ("go-dsn-default", go_default),
        ("go-dsn-slashes", go_slashes),
        ("go-dsn-no-protocol", go_no_protocol),
        ("libpq", libpq),
        ("jdbc", jdbc),
        ("ado", ado),
    ]
    .map(|(name, value)| Shape {
        name,
        var: "DATABASE_DSN",
        value,
        right: word(8),
        wrong: word(8),
    });
    guesses_are_hidden(&mut f, &mut c, &shapes);
    compared_for_anyone(
        &mut f,
        &mut c,
        &[
            ("go-dsn", "DATABASE_DSN", go, word(16)),
            ("go-dsn-default", "DATABASE_DSN", go_default, word(16)),
            ("go-dsn-slashes", "DATABASE_DSN", go_slashes, word(14)),
            (
                "go-dsn-no-protocol",
                "DATABASE_DSN",
                go_no_protocol,
                word(16),
            ),
            ("libpq", "DATABASE_DSN", libpq, word(16)),
            ("jdbc", "DATABASE_DSN", jdbc, word(16)),
            ("ado", "DATABASE_DSN", ado, word(16)),
        ],
    );
    drop(c);
    f.sweep();
}

/// `l` and `r` random letters and digits either side of one backslash,
/// written as libpq's keyword form escapes it (`\\`): `l + r + 1`
/// characters to libpq, one byte more as written.
fn backslashed(l: usize, r: usize) -> String {
    format!("{}\\\\{}", word(l), word(r))
}

/// Review finding F-65 (Codex): a password in libpq's keyword form was
/// counted as written, but libpq decodes a backslash before any byte, so
/// a 15-character password holding one backslash, written with it
/// escaped, counted 16, and an agent's right guess was told from a wrong
/// one. Each field's password is also counted as libpq decodes it: 15
/// characters, unquoted or quoted, get one answer for an agent and are
/// told apart for a person; 16 characters, escaped the same way, are
/// compared for anyone (tests/fixtures/libpq in envcloak-providers holds
/// libpq's own counts of these forms).
#[test]
fn a_short_libpq_password_with_escapes_is_guessable() {
    let mut f = Fixture::new(|_, _| {});
    let mut c = client(&f.home);
    let unquoted: ValueOf = |pw| {
        format!("host=db.internal port=5432 dbname=app user=app password={pw} sslmode=require")
    };
    let quoted: ValueOf = |pw| format!("host=db.internal password='{pw}' dbname=app");
    let shapes =
        [("libpq-escaped", unquoted), ("libpq-quoted", quoted)].map(|(name, value)| Shape {
            name,
            var: "DATABASE_DSN",
            value,
            right: backslashed(7, 7),
            wrong: backslashed(7, 7),
        });
    guesses_are_hidden(&mut f, &mut c, &shapes);
    compared_for_anyone(
        &mut f,
        &mut c,
        &[
            ("libpq-escaped", "DATABASE_DSN", unquoted, backslashed(7, 8)),
            ("libpq-quoted", "DATABASE_DSN", quoted, backslashed(7, 8)),
        ],
    );
    drop(c);
    f.sweep();
}

/// Values compared with the vault are limited per subject root: 20
/// requests of 5,000 secrets reach the hour's 100,000, and the next
/// comparison is refused (`too_many_checks`) and audited; a request that
/// compares nothing (configuration only) still passes.
#[test]
fn values_compared_are_limited_per_subject_root() {
    let mut f = Fixture::new(|_, _| {});
    let value = word(24);
    f.cs.push(Canary::new("BUDGET_VALUE", value.clone()));
    let batch = |n: usize| {
        one_project(
            &f,
            (0..n)
                .map(|_| entry(0, ".env", None, "API_TOKEN", value.as_bytes()))
                .collect(),
            &[],
        )
    };
    let mut c = client(&f.home);
    for _ in 0..20 {
        let plan = c.import_plan(&batch(5_000)).unwrap();
        assert_eq!(plan.items.len(), 1);
    }
    let e = c.import_plan(&batch(1)).unwrap_err();
    assert_eq!(rpc(e), ErrorKind::TooManyChecks);
    let e = c
        .import_verify(&VerifyParams {
            manifest: project(&f.home, "budget", "[env]\n")
                .to_str()
                .unwrap()
                .to_owned(),
            files: vec![VerifyFile {
                file: ".env".into(),
                profile: None,
                entries: vec![VerifyEntry {
                    line: 1,
                    name: "API_TOKEN".into(),
                    value: WireSecret::new(SecretBytes::copy_from(value.as_bytes())),
                }],
            }],
            claims: Vec::new(),
        })
        .unwrap_err();
    assert_eq!(rpc(e), ErrorKind::TooManyChecks);
    let config = one_project(&f, vec![entry(0, ".env", None, "PORT", b"8080")], &[]);
    assert_eq!(
        c.import_plan(&config).unwrap().entries[0].skipped,
        Some(SkipReason::TooShort)
    );
    drop(c);
    let v = f.stop_and_open();
    let (entries, _) = v.read_audit().unwrap();
    let refused: Vec<(&str, Option<&str>)> = entries
        .iter()
        .filter(|e| e.record.kind == AuditKind::Import && e.record.decision.outcome == "refused")
        .map(|e| {
            (
                e.record.decision.method.as_deref().unwrap(),
                e.record.decision.reason.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        refused,
        [
            ("import.plan", Some("too_many_checks")),
            ("import.verify", Some("too_many_checks")),
        ]
    );
    f.sweep();
}

/// Review finding F-53 (Codex): a directory named like a key (a hash, as
/// worktrees and CI checkouts are) never becomes part of a slug: the
/// project is `project` instead, a profile shaped like a key is left out,
/// and neither comes back in the plan, the commit or the item list. The
/// control: `items.add` refuses the same name as a slug.
#[test]
fn a_project_named_like_a_key_is_not_kept_in_slugs() {
    let mut f = Fixture::new(|_, _| {});
    // Letters and digits, 40 and 31 long: shaped like keys.
    let hash = format!("{}7{}", word(20), word(19));
    let profile = format!("{}7{}", word(15), word(15));
    f.cs.push(Canary::new("HASH_NAME", hash.clone()));
    f.cs.push(Canary::new("HASH_PROFILE", profile.clone()));
    let mut c = client(&f.home);
    let e = c
        .items_add(&envcloak_ipc::proto::AddParams {
            slug: Some(format!("openai/{hash}")),
            provider: None,
            field: None,
            account: None,
            env_hint: None,
            allow_short: false,
            value: WireSecret::new(f.value(labels::OPENAI_API_KEY_ROTATED)),
            claims: Vec::new(),
        })
        .unwrap_err();
    assert_eq!(rpc(e), ErrorKind::InvalidItem);
    let rotated = by_label(&f.cs, labels::OPENAI_API_KEY_ROTATED)
        .value()
        .to_vec();
    let params = || ImportParams {
        projects: vec![ImportProject {
            dir: f.dir(&hash),
            name: hash.clone(),
        }],
        entries: vec![
            entry(0, ".env", None, "OPENAI_API_KEY", &rotated),
            entry(
                0,
                ".env.x",
                Some(&profile),
                "SHORT_TOKEN",
                f.short.as_bytes(),
            ),
        ],
        claims: Vec::new(),
    };
    let plan = c.import_plan(&params()).unwrap();
    let slugs: Vec<&str> = plan.items.iter().map(|i| i.slug.as_str()).collect();
    assert_eq!(slugs, ["openai/project", "short-token/project"]);
    let done = c
        .import_commit(&ImportCommitParams {
            import: params(),
            digest: plan.digest.clone(),
        })
        .unwrap();
    assert_eq!(done, plan);
    let list = c.items_list(false).unwrap();
    assert!(list.items.iter().any(|i| i.slug == "openai/project"));
    assert_no_canary(&json(&plan), &f.cs);
    assert_no_canary(&json(&list), &f.cs);
    f.sweep();
}

/// Review finding F-54 (Codex): `files.restore` hands plaintext back, so
/// it is a delivery: when its audit entry cannot be written (another
/// program put a file where the log's directory was), it is refused
/// (`audit_failed`) and releases nothing; once the log can be written
/// again, the same restore succeeds, and the log holds that one.
#[test]
fn a_restore_whose_audit_entry_cannot_be_written_releases_nothing() {
    let mut f = Fixture::new(|_, _| {});
    let key = by_label(&f.cs, labels::OPENAI_API_KEY).as_str();
    let body = format!("OPENAI_API_KEY={key}\n");
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
    let audit = data_dir(&f.home).join("audit");
    std::fs::remove_dir_all(&audit).unwrap();
    std::fs::write(&audit, b"in the way").unwrap();
    let e = c.files_restore(&b.id, passphrase(&f.cs), &[]).unwrap_err();
    assert_eq!(rpc(e), ErrorKind::AuditFailed);
    std::fs::remove_file(&audit).unwrap();
    std::fs::create_dir(&audit).unwrap();
    std::fs::set_permissions(&audit, std::fs::Permissions::from_mode(0o700)).unwrap();
    let back = c.files_restore(&b.id, passphrase(&f.cs), &[]).unwrap();
    assert!(back.files[0].content.as_secret().ct_eq(body.as_bytes()));
    drop((c, back));
    let v = f.stop_and_open();
    let (entries, _) = v.read_audit().unwrap();
    let restored = entries
        .iter()
        .filter(|e| e.record.kind == AuditKind::FilesRestore)
        .filter(|e| e.record.decision.outcome == "restored")
        .count();
    assert_eq!(restored, 1);
    for e in &entries {
        assert_no_canary(format!("{:?}", e.record).as_bytes(), &f.cs);
    }
    f.sweep();
}
