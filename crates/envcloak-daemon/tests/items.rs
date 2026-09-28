//! The item methods over the daemon's socket (SPEC §5 "Items", §6.3,
//! §10b "Writes that need a proof"; T11): `items.list`, `items.show`,
//! `items.check` and `items.add` answer with metadata only; `items.rotate`
//! and `items.remove` need the passphrase as a proof, a rotation keeps the
//! old value as a prior value and leaves grants in force, and a removal
//! writes an encrypted backup first and ends the grants that bind the
//! item.
//!
//! The caller is this test process, made a terminal session so the daemon
//! takes its proofs (see crates/envcloak-daemon/tests/grants.rs; a caller
//! without one is in tests/proofs.rs). After the daemon stops, the test
//! opens the vault itself with the canary passphrase to read values and
//! the audit log back. Every response, the daemon's log, the audit entries
//! and the home are swept for the canaries.
#![allow(clippy::unwrap_used)]

mod common;

use std::time::Duration;

use common::{MANIFEST, SLUGS, client, data_dir, passphrase, project, seed_vault, start};
use envcloak_core::audit::{AuditEntry, AuditKind};
use envcloak_core::vault::{LockedVault, Slug, Vault, VaultPaths};
use envcloak_core::{RecoveryKit, SecretBytes, restore_backup};
use envcloak_ipc::proto::{AddParams, ErrorKind, RunRequestParams};
use envcloak_ipc::view::{ClassificationView, DecisionView, LengthClass, RefStatus, TargetView};
use envcloak_ipc::{ClientError, WireSecret};
use envcloak_policy::{ApprovalOptions, PendingId, statement_digest};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};

fn rpc(e: ClientError) -> (ErrorKind, Option<&'static str>) {
    match e {
        ClientError::Rpc(r) => (r.kind, r.reason),
        other => panic!("expected an error response, got {other:?}"),
    }
}

/// A seeded, unlocked vault behind a running daemon, and the project.
struct Fixture {
    cs: Vec<Canary>,
    kit: Canary,
    home: TestHome,
    d: Daemon,
    manifest: String,
}

impl Fixture {
    fn new() -> Self {
        common::terminal_session();
        let cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        let mut cs = cs;
        cs.push(kit.clone());
        let d = start(&home);
        client(&home).unlock(passphrase(&cs), &[]).unwrap();
        let manifest = project(&home, "acme-web", MANIFEST);
        Fixture {
            cs,
            kit,
            home,
            d,
            manifest: manifest.to_str().unwrap().to_owned(),
        }
    }

    fn value(&self, label: &str) -> SecretBytes {
        SecretBytes::copy_from(by_label(&self.cs, label).value())
    }

    fn pass(&self) -> SecretBytes {
        passphrase(&self.cs)
    }

    /// An `items.add` with `value` and no names.
    fn add_params(&self, value: SecretBytes) -> AddParams {
        AddParams {
            slug: None,
            provider: None,
            field: None,
            account: None,
            env_hint: None,
            allow_short: false,
            value: WireSecret::new(value),
            claims: Vec::new(),
        }
    }

    /// A grant for the project's default profile (OpenAI and Stripe),
    /// through `run.request` and `approve`. Returns the grant's id.
    fn grant(&self) -> String {
        let params = RunRequestParams {
            manifest: self.manifest.clone(),
            profile: None,
            refs: Vec::new(),
            env_file: None,
            argv: vec!["./emit".into()],
            claims: Vec::new(),
        };
        let DecisionView::Pending { request } = client(&self.home).run_request(&params).unwrap()
        else {
            panic!("expected a pending request");
        };
        PendingId::parse(&request).unwrap();
        let mut c = client(&self.home);
        let d = c.pending_get(&request, &[]).unwrap();
        let opts = ApprovalOptions::session(Duration::from_secs(3600));
        let digest = statement_digest(&d, &opts);
        let grant = c
            .approve(&request, opts, &digest, self.pass(), &[])
            .unwrap()
            .grant;
        assert!(matches!(
            client(&self.home).run_request(&params).unwrap(),
            DecisionView::Covered { .. }
        ));
        grant
    }

    fn run_decision(&self) -> Result<DecisionView, ClientError> {
        client(&self.home).run_request(&RunRequestParams {
            manifest: self.manifest.clone(),
            profile: None,
            refs: Vec::new(),
            env_file: None,
            argv: vec!["./emit".into()],
            claims: Vec::new(),
        })
    }

    fn target(&self, slug: &str) -> TargetView {
        client(&self.home).items_target(slug, None, &[]).unwrap()
    }

    /// Stops the daemon (SIGTERM locks the vault first) and opens the vault
    /// here with the passphrase.
    fn stop_and_open(&mut self) -> Vault {
        self.d.signal("-TERM");
        assert!(self.d.wait_exit(Duration::from_secs(30)).is_some());
        LockedVault::open(&VaultPaths::under(data_dir(&self.home)))
            .unwrap()
            .unlock_with_passphrase(&self.pass())
            .map_err(|(_, e)| e)
            .unwrap()
    }

    /// Sweeps what the daemon wrote: its log and the home, the vault,
    /// audit log and backups included (ciphertext only).
    fn sweep(&self) {
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

/// Every entry's text, swept for the canaries: entries hold metadata only.
fn sweep_entries(entries: &[AuditEntry], cs: &[Canary]) {
    for e in entries {
        assert_no_canary(format!("{:?}", e.record).as_bytes(), cs);
    }
}

fn json(v: &impl envcloak_ipc::view::View) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

/// `items.add`, `items.list` and `items.show`: the provider comes from the
/// value's shape, a free slug is picked, and no answer holds a value. The
/// account is sent only for `ls --long` and `show`.
#[test]
fn metadata_answers_are_value_free_and_accounts_only_when_asked() {
    let f = Fixture::new();
    let mut c = client(&f.home);
    let mut p = f.add_params(f.value(labels::OPENAI_API_KEY_ROTATED));
    p.account = Some("dev@acme.example".into());
    p.env_hint = Some("OPENAI_API_KEY".into());
    let added = c.items_add(&p).unwrap();
    assert_eq!(added.item.slug, "openai");
    assert_eq!(added.item.provider.as_deref(), Some("openai"));
    assert_eq!(added.item.classification, ClassificationView::Live);
    assert_eq!(added.field, "value");
    assert_eq!(added.length, LengthClass::Ok);
    assert_eq!(added.detected, None);
    assert!(
        added
            .item
            .account
            .as_ref()
            .is_some_and(|a| a.email.as_deref() == Some("dev@acme.example"))
    );
    // Another provider's key gets that provider's slug, and a second item
    // for a provider the next free one.
    let again = c
        .items_add(&f.add_params(f.value(labels::GITHUB_TOKEN)))
        .unwrap();
    assert_eq!(again.item.slug, "github");
    let named = AddParams {
        provider: Some("openai".into()),
        ..f.add_params(SecretBytes::copy_from(b"not an openai key, but named so"))
    };
    let named = c.items_add(&named).unwrap();
    assert_eq!(named.item.slug, "openai-2");
    assert_eq!(named.item.classification, ClassificationView::Unknown);

    let list = c.items_list(false).unwrap();
    let slugs: Vec<&str> = list.items.iter().map(|i| i.slug.as_str()).collect();
    assert_eq!(
        slugs,
        [
            "github",
            "github/acme-web",
            "openai",
            "openai-2",
            "openai/acme-web",
            "short/acme-web",
            "stripe/acme-web",
        ]
    );
    assert!(
        list.items
            .iter()
            .all(|i| i.account.is_none() && i.detail.is_none())
    );
    assert!(
        !String::from_utf8(json(&list))
            .unwrap()
            .contains("dev@acme.example")
    );
    let long = c.items_list(true).unwrap();
    assert!(
        long.items
            .iter()
            .all(|i| i.account.is_some() && i.detail.is_none())
    );
    let show = c.items_show("openai").unwrap();
    let detail = show.detail.as_ref().unwrap();
    assert_eq!(detail.allowed_hosts, vec!["api.openai.com".to_owned()]);
    assert!(detail.links.keys_page.is_some());
    assert_eq!(show.fields.len(), 1);
    for body in [
        json(&added),
        json(&again),
        json(&named),
        json(&list),
        json(&long),
        json(&show),
    ] {
        assert_no_canary(&body, &f.cs);
    }
    // A slug the vault does not have, or not a slug at all.
    for slug in ["nope/nothing", "Not A Slug"] {
        assert_eq!(
            rpc(c.items_show(slug).unwrap_err()),
            (ErrorKind::NoSuchItem, Some("unknown_item"))
        );
    }
    f.sweep();
}

/// `items.add` refuses a name shaped like a key or token in every name it
/// takes, with a fixed reason (gate 13's daemon half: a value sent as a
/// name is not kept), and refuses malformed names and values.
#[test]
fn add_refuses_value_shaped_names_and_bad_values() {
    let mut f = Fixture::new();
    let mut c = client(&f.home);
    let hex: String = (0..40)
        .map(|i| char::from(b"0123456789abcdef"[(i * 7 + 3) % 16]))
        .collect();
    let values = [
        by_label(&f.cs, labels::GITHUB_TOKEN).as_str().to_owned(),
        by_label(&f.cs, labels::STRIPE_SECRET_KEY)
            .as_str()
            .to_owned(),
        by_label(&f.cs, labels::OPENAI_API_KEY).as_str().to_owned(),
        hex.clone(),
    ];
    for v in &values {
        for which in 0..5 {
            let mut p = f.add_params(SecretBytes::copy_from(b"an ordinary value here"));
            let slot = match which {
                0 => &mut p.slug,
                1 => &mut p.provider,
                2 => &mut p.field,
                3 => &mut p.account,
                _ => &mut p.env_hint,
            };
            *slot = Some(v.clone());
            assert_eq!(
                rpc(c.items_add(&p).unwrap_err()),
                (ErrorKind::InvalidItem, Some("looks_like_value")),
                "name {which}"
            );
        }
    }
    let bad = |c: &mut envcloak_ipc::Client, p: AddParams| rpc(c.items_add(&p).unwrap_err());
    let named = |f: &Fixture, set: &dyn Fn(&mut AddParams)| {
        let mut p = f.add_params(SecretBytes::copy_from(b"an ordinary value here"));
        set(&mut p);
        p
    };
    for (params, want) in [
        (
            named(&f, &|p| p.slug = Some("Bad Slug".into())),
            (ErrorKind::InvalidItem, Some("invalid_slug")),
        ),
        (
            named(&f, &|p| p.provider = Some("nosuchprovider".into())),
            (ErrorKind::InvalidItem, Some("unknown_provider")),
        ),
        (
            named(&f, &|p| p.field = Some("Not-A-Field".into())),
            (ErrorKind::InvalidItem, Some("invalid_field")),
        ),
        (
            named(&f, &|p| p.account = Some("two words".into())),
            (ErrorKind::InvalidItem, Some("invalid_account")),
        ),
        (
            named(&f, &|p| p.env_hint = Some("not-a-var".into())),
            (ErrorKind::InvalidItem, Some("invalid_env_name")),
        ),
        (
            named(&f, &|p| p.slug = Some("openai/acme-web".into())),
            (ErrorKind::ItemExists, None),
        ),
        (
            f.add_params(SecretBytes::copy_from(b"")),
            (ErrorKind::InvalidItem, Some("empty_value")),
        ),
        (
            f.add_params(SecretBytes::copy_from(b"nul\0inside a value")),
            (ErrorKind::InvalidItem, Some("nul_byte")),
        ),
        (
            f.add_params(SecretBytes::copy_from(&vec![b'a'; 64 * 1024 + 1])),
            (ErrorKind::InvalidItem, Some("value_too_large")),
        ),
    ] {
        assert_eq!(bad(&mut c, params), want);
    }
    // Nothing was added, and no name holds a value.
    let list = c.items_list(true).unwrap();
    assert_eq!(list.items.len(), SLUGS.len());
    let body = json(&list);
    assert_no_canary(&body, &f.cs);
    assert!(!String::from_utf8(body).unwrap().contains(&hex));
    drop(c);
    let v = f.stop_and_open();
    for v2 in &values {
        assert!(
            v.find_by_value(&SecretBytes::copy_from(v2.as_bytes()))
                .len()
                <= 1
        );
    }
    let (entries, _) = v.read_audit().unwrap();
    assert!(!entries.iter().any(|e| e.record.kind == AuditKind::Add));
    sweep_entries(&entries, &f.cs);
    f.sweep();
}

/// `items.rotate` is a proof: a wrong passphrase changes nothing and is
/// counted; the right one replaces the value, keeps the old one as the
/// newest prior value, and leaves the grant that binds the item in force
/// (story S7). A target whose slug now names another item is refused.
#[test]
fn rotate_needs_the_passphrase_keeps_the_prior_value_and_the_grant() {
    let mut f = Fixture::new();
    let grant = f.grant();
    let target = f.target("openai/acme-web");
    assert_eq!(target.field.as_deref(), Some("value"));
    assert_eq!(target.grants, 1);
    assert_no_canary(&json(&target), &f.cs);

    let new = || f.value(labels::OPENAI_API_KEY_ROTATED);
    let mut c = client(&f.home);
    let e = c
        .items_rotate(
            &target,
            new(),
            SecretBytes::copy_from(b"not the passphrase at all, no"),
            &[],
        )
        .unwrap_err();
    assert_eq!(rpc(e), (ErrorKind::WrongPassphrase, None));
    assert_eq!(c.status().unwrap().approvals.proof_failures, 1);

    // A target made for another item under this slug is refused.
    let mut stale = target.clone();
    stale.item.id = "01K00000000000000000000000".into();
    let e = c.items_rotate(&stale, new(), f.pass(), &[]).unwrap_err();
    assert_eq!(rpc(e), (ErrorKind::NoSuchItem, Some("item_changed")));

    let rotated = c.items_rotate(&target, new(), f.pass(), &[]).unwrap();
    assert_eq!(
        (
            rotated.slug.as_str(),
            rotated.field.as_str(),
            rotated.prior_count
        ),
        ("openai/acme-web", "value", 1)
    );
    assert_eq!(c.status().unwrap().approvals.proof_failures, 0);
    assert_no_canary(&json(&rotated), &f.cs);
    // The grant survives the rotation and still covers the run.
    let grants = c.grants_list().unwrap();
    assert_eq!(grants.grants.len(), 1);
    assert_eq!(grants.grants[0].id, grant);
    assert!(matches!(
        f.run_decision().unwrap(),
        DecisionView::Covered { .. }
    ));
    assert_eq!(
        c.items_show("openai/acme-web").unwrap().fields[0].prior_count,
        1
    );
    drop(c);

    let v = f.stop_and_open();
    let item = v.find(&Slug::new("openai/acme-web").unwrap()).unwrap();
    let field = item.fields[0].id;
    assert!(
        v.read_value(field)
            .unwrap()
            .ct_eq(by_label(&f.cs, labels::OPENAI_API_KEY_ROTATED).value())
    );
    assert!(
        v.read_prior(field, 0)
            .unwrap()
            .ct_eq(by_label(&f.cs, labels::OPENAI_API_KEY).value())
    );
    let (entries, _) = v.read_audit().unwrap();
    let rotations: Vec<&str> = entries
        .iter()
        .filter(|e| e.record.kind == AuditKind::Rotate)
        .map(|e| e.record.decision.outcome.as_str())
        .collect();
    assert_eq!(rotations, ["failed", "rotated"]);
    sweep_entries(&entries, &f.cs);
    f.sweep();
}

/// `items.remove` is a proof; a wrong passphrase removes nothing. The
/// right one writes an encrypted backup of the vault, removes the item,
/// and ends the grant that binds it, so the run no longer resolves. The
/// backup restores the item with its value.
#[test]
fn remove_needs_the_passphrase_backs_up_first_and_ends_grants() {
    let mut f = Fixture::new();
    f.grant();
    let target = f.target("openai/acme-web");
    let mut c = client(&f.home);
    let e = c
        .items_remove(
            &target,
            SecretBytes::copy_from(b"not the passphrase at all, no"),
            &[],
        )
        .unwrap_err();
    assert_eq!(rpc(e), (ErrorKind::WrongPassphrase, None));
    assert!(c.items_show("openai/acme-web").is_ok());
    assert_eq!(c.grants_list().unwrap().grants.len(), 1);

    let removed = c.items_remove(&target, f.pass(), &[]).unwrap();
    assert_eq!(removed.slug, "openai/acme-web");
    assert_eq!(removed.grants_ended, 1);
    assert!(removed.backup.ends_with(".ecbackup"), "{}", removed.backup);
    assert!(c.grants_list().unwrap().grants.is_empty());
    assert_eq!(
        rpc(c.items_show("openai/acme-web").unwrap_err()),
        (ErrorKind::NoSuchItem, Some("unknown_item"))
    );
    assert_eq!(
        rpc(f.run_decision().unwrap_err()),
        (ErrorKind::BindingUnresolved, Some("unknown_item"))
    );
    // A second removal with the same target finds nothing.
    assert_eq!(
        rpc(c.items_remove(&target, f.pass(), &[]).unwrap_err()),
        (ErrorKind::NoSuchItem, Some("unknown_item"))
    );
    drop(c);

    let backup = data_dir(&f.home).join("backups").join(&removed.backup);
    assert!(backup.is_file());
    let v = f.stop_and_open();
    assert!(v.find(&Slug::new("openai/acme-web").unwrap()).is_none());
    assert!(v.find_by_value(&f.value(labels::OPENAI_API_KEY)).is_empty());
    let (entries, _) = v.read_audit().unwrap();
    let removals: Vec<(&str, Option<u64>)> = entries
        .iter()
        .filter(|e| e.record.kind == AuditKind::Remove)
        .map(|e| (e.record.decision.outcome.as_str(), e.record.decision.count))
        .collect();
    assert_eq!(removals, [("failed", None), ("removed", Some(1))]);
    sweep_entries(&entries, &f.cs);
    drop(v);
    f.sweep();

    // The backup brings the item back, value and all.
    let kit = RecoveryKit::parse(&SecretBytes::copy_from(f.kit.value())).unwrap();
    let (restored, _) = restore_backup(
        &VaultPaths::under(data_dir(&f.home)),
        &backup,
        &kit,
        &f.pass(),
    )
    .unwrap();
    let item = restored
        .find(&Slug::new("openai/acme-web").unwrap())
        .unwrap();
    assert!(
        restored
            .read_value(item.fields[0].id)
            .unwrap()
            .ct_eq(by_label(&f.cs, labels::OPENAI_API_KEY).value())
    );
}

/// A caller whose environment claims an agent gives no proof: the target
/// is not shown, and nothing is rotated or removed, before the passphrase
/// is looked at (no attempt is counted).
#[test]
fn claimed_agents_get_no_target_and_give_no_proof() {
    let f = Fixture::new();
    let target = f.target("openai/acme-web");
    let mut c = client(&f.home);
    let claims = vec!["CLAUDECODE".to_owned()];
    assert_eq!(
        rpc(c
            .items_target("openai/acme-web", None, &claims)
            .unwrap_err()),
        (ErrorKind::ProofRefused, None)
    );
    let e = c
        .items_rotate(
            &target,
            f.value(labels::OPENAI_API_KEY_ROTATED),
            f.pass(),
            &claims,
        )
        .unwrap_err();
    assert_eq!(rpc(e), (ErrorKind::ProofRefused, None));
    let e = c.items_remove(&target, f.pass(), &claims).unwrap_err();
    assert_eq!(rpc(e), (ErrorKind::ProofRefused, None));
    assert_eq!(c.status().unwrap().approvals.proof_failures, 0);
    assert_eq!(
        c.items_show("openai/acme-web").unwrap().fields[0].prior_count,
        0
    );
    f.sweep();
}

/// `items.check`: every binding of the manifest, in `[env]` and each
/// profile, and each reference sent, resolves or says why not. A reference
/// shaped like a key is reported without its text.
#[test]
fn check_reports_each_binding_and_hides_value_shaped_ones() {
    let f = Fixture::new();
    let hex: String = (0..40)
        .map(|i| char::from(b"0123456789abcdef"[(i * 5 + 1) % 16]))
        .collect();
    let manifest = project(
        &f.home,
        "checked",
        &format!(
            "[project]\nname = \"checked\"\n\n[env]\nOPENAI_API_KEY = \"openai/acme-web\"\n\
             MISSING = \"nope/missing\"\nWRONG_FIELD = \"stripe/acme-web#other\"\n\
             PASTED = \"{hex}\"\n\n[env.short]\nSHORT_TOKEN = \"short/acme-web\"\n"
        ),
    );
    let mut c = client(&f.home);
    let refs = vec![
        "GITHUB_TOKEN=github/acme-web".to_owned(),
        "X=nope/nothing".to_owned(),
        "not a reference".to_owned(),
        format!("Y={hex}"),
    ];
    let v = c
        .items_check(Some(manifest.to_str().unwrap()), &refs)
        .unwrap();
    assert_eq!(v.project_name.as_deref(), Some("checked"));
    let got: Vec<(Option<&str>, Option<&str>, RefStatus)> = v
        .bindings
        .iter()
        .map(|b| (b.profile.as_deref(), b.env_name.as_deref(), b.status))
        .collect();
    assert_eq!(
        got,
        [
            (None, Some("MISSING"), RefStatus::UnknownItem),
            (None, Some("OPENAI_API_KEY"), RefStatus::Ok),
            (None, None, RefStatus::LooksLikeValue),
            (None, Some("WRONG_FIELD"), RefStatus::UnknownField),
            (Some("short"), Some("SHORT_TOKEN"), RefStatus::Ok),
        ]
    );
    assert_eq!(
        v.refs,
        [
            RefStatus::Ok,
            RefStatus::UnknownItem,
            RefStatus::InvalidReference,
            RefStatus::LooksLikeValue,
        ]
    );
    let body = String::from_utf8(json(&v)).unwrap();
    assert!(!body.contains(&hex), "{body}");
    // No manifest: the references alone.
    let v = c.items_check(None, &refs[..1]).unwrap();
    assert!(v.bindings.is_empty() && v.project_dir.is_none());
    assert_eq!(v.refs, [RefStatus::Ok]);
    assert_eq!(
        rpc(c
            .items_check(Some("relative/envcloak.toml"), &[])
            .unwrap_err()),
        (ErrorKind::ManifestInvalid, Some("invalid_path"))
    );
    // Locked, nothing is answered.
    c.lock().unwrap();
    assert_eq!(
        rpc(c.items_list(false).unwrap_err()),
        (ErrorKind::VaultLocked, None)
    );
    assert_eq!(
        rpc(c.items_check(None, &refs).unwrap_err()),
        (ErrorKind::VaultLocked, None)
    );
    f.sweep();
}
