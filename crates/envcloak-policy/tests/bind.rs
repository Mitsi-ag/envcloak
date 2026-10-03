//! Gate 17, card half: a reference to a card, an issuer credential or an
//! item of unknown class is rejected when the manifest's bindings are bound
//! to the vault's items. Gate b18's `run` and `ref` part (plan task M2-07):
//! so is a reference to a login's field, as `login_reference`. Also how a
//! reference picks its field.
#![allow(clippy::unwrap_used)]

use envcloak_core::crypto::{ItemClass, KdfParams};
use envcloak_core::vault::{
    Classification, FieldKind, FieldName, ItemDetails, ItemId, ItemMeta, LoginMeta, LoginTier,
    NewItem, NewLogin, Slug, TotpAlgorithm, TotpEnrollment, TotpParams, Vault, VaultPaths,
};
use envcloak_core::{SecretBytes, create_vault};
use envcloak_policy::{BindErrorKind, Binding, EnvName, bind_items, parse_manifest, resolve};
use envcloak_testkit::{TestHome, by_label, canaries, fresh_seed, labels};

struct Fixture {
    _home: TestHome,
    vault: Vault,
}

fn add(v: &mut Vault, class: ItemClass, slug: &str, fields: &[&str], c: Classification) -> ItemId {
    let cs = canaries(fresh_seed());
    let value = by_label(&cs, labels::GITHUB_TOKEN).value();
    v.transact(|t| {
        let id = t.create_item(NewItem {
            class,
            slug: Slug::new(slug).unwrap(),
            details: ItemDetails {
                title: slug.to_owned(),
                classification: c,
                ..ItemDetails::default()
            },
        })?;
        for f in fields {
            t.add_field(
                id,
                FieldName::new(f).unwrap(),
                SecretBytes::copy_from(value),
            )?;
        }
        Ok(id)
    })
    .unwrap()
}

fn fixture() -> Fixture {
    let home = TestHome::new();
    let paths = VaultPaths::under(home.root().join("data"));
    let pass = SecretBytes::copy_from(b"correct horse battery staple, bound");
    let (mut vault, _kit) = create_vault(&paths, &pass, KdfParams::minimum()).unwrap();
    add(
        &mut vault,
        ItemClass::Secret,
        "openai/work",
        &["api_key"],
        Classification::Live,
    );
    add(
        &mut vault,
        ItemClass::Secret,
        "stripe/acme",
        &["publishable_key", "secret_key"],
        Classification::Test,
    );
    add(
        &mut vault,
        ItemClass::Secret,
        "empty/item",
        &[],
        Classification::Unknown,
    );
    add(
        &mut vault,
        ItemClass::Card,
        "amex/work",
        &["number"],
        Classification::Unknown,
    );
    add(
        &mut vault,
        ItemClass::IssuerCredential,
        "airwallex/acme",
        &["api_key"],
        Classification::Unknown,
    );
    vault
        .transact(|t| {
            t.create_login(NewLogin {
                slug: Slug::new("fixture/editor").unwrap(),
                details: ItemDetails {
                    classification: Classification::Test,
                    ..ItemDetails::default()
                },
                meta: LoginMeta {
                    tier: LoginTier::Dev,
                    session_lifetime: 900,
                },
                username: SecretBytes::copy_from(b"editor@example.test"),
                password: SecretBytes::copy_from(b"a login password for bind"),
                totp: Some(TotpEnrollment {
                    params: TotpParams::new(TotpAlgorithm::Sha1, 6, 30).unwrap(),
                    seed: SecretBytes::copy_from(b"a totp seed for bind"),
                }),
                adapter_key: Some(SecretBytes::copy_from(b"an adapter key for bind")),
            })
        })
        .unwrap();
    Fixture { _home: home, vault }
}

fn bindings(manifest: &str) -> Vec<Binding> {
    let m = parse_manifest(manifest.as_bytes()).unwrap();
    resolve(&m, None, &[], None).unwrap()
}

#[test]
fn gate17_cards_issuer_credentials_and_unknown_classes_are_rejected() {
    let f = fixture();
    let items = f.vault.items();
    for (reference, kind) in [
        ("amex/work", BindErrorKind::CardReference),
        ("amex/work#number", BindErrorKind::CardReference),
        ("airwallex/acme", BindErrorKind::IssuerCredentialReference),
        (
            "airwallex/acme#api_key",
            BindErrorKind::IssuerCredentialReference,
        ),
    ] {
        let manifest = format!("[env]\nOPENAI_API_KEY = \"openai/work\"\nCARD = \"{reference}\"\n");
        let e = bind_items(&bindings(&manifest), items).unwrap_err();
        assert_eq!(e.kind(), kind, "{reference}");
        assert_eq!(e.env_name().as_str(), "CARD");
        // Surfaced as a manifest the daemon refuses, not a missing item.
        assert_eq!(e.token(), "manifest_invalid");
    }
    // A class this version does not know (the vault gives `None` for a row
    // that is not an item) is rejected too.
    let mut odd: Vec<ItemMeta> = items.to_vec();
    let i = odd
        .iter()
        .position(|m| m.slug.as_str() == "openai/work")
        .unwrap();
    odd[i].class = ItemClass::None;
    let e = bind_items(&bindings("[env]\nA = \"openai/work\"\n"), &odd).unwrap_err();
    assert_eq!(e.kind(), BindErrorKind::UnknownItemClass);
    assert_eq!(e.token(), "manifest_invalid");
}

#[test]
fn a_reference_picks_its_field() {
    let f = fixture();
    let items = f.vault.items();
    let find = |slug: &str| items.iter().find(|m| m.slug.as_str() == slug).unwrap();
    let bound = bind_items(
        &bindings(
            "[env]\nOPENAI_API_KEY = \"openai/work\"\nSTRIPE_SECRET_KEY = \"stripe/acme#secret_key\"\n\
             OPENAI_AGAIN = { ref = \"openai/work\", field = \"api_key\" }\n",
        ),
        items,
    )
    .unwrap();
    let openai = find("openai/work");
    let stripe = find("stripe/acme");
    let got: Vec<(&str, ItemId, &str, Classification)> = bound
        .iter()
        .map(|b| {
            let item = find_by_id(items, b.item);
            let field = item.fields.iter().find(|f| f.id == b.field).unwrap();
            (
                b.env_name.as_str(),
                b.item,
                field.name.as_str(),
                b.classification,
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            ("OPENAI_AGAIN", openai.id, "api_key", Classification::Live),
            ("OPENAI_API_KEY", openai.id, "api_key", Classification::Live),
            (
                "STRIPE_SECRET_KEY",
                stripe.id,
                "secret_key",
                Classification::Test
            ),
        ]
    );

    for (manifest, kind) in [
        ("A = \"missing/item\"", BindErrorKind::UnknownItem),
        ("A = \"openai/work#nope\"", BindErrorKind::UnknownField),
        ("A = \"stripe/acme\"", BindErrorKind::AmbiguousField),
        ("A = \"empty/item\"", BindErrorKind::NoField),
    ] {
        let e = bind_items(&bindings(&format!("[env]\n{manifest}\n")), items).unwrap_err();
        assert_eq!(e.kind(), kind, "{manifest}");
        assert_eq!(e.env_name(), &EnvName::new("A").unwrap());
        assert_eq!(e.token(), "binding_unresolved", "{manifest}");
        // Names the variable and the kind; the reference is the caller's.
        assert!(e.to_string().starts_with("A: "), "{e}");
    }
}

fn find_by_id(items: &[ItemMeta], id: ItemId) -> &ItemMeta {
    items.iter().find(|m| m.id == id).unwrap()
}

/// Gate b18, `run` and `ref` part (plan task M2-07): every field of a login
/// is refused when bound, named or not, alone or beside a secret, in
/// `[env]`, in a profile and as a `--ref`, as `login_reference`: no login
/// field becomes a variable, whatever names it. Its typed fields are there
/// to be named (the control), and a secret beside it still binds.
#[test]
fn b18_login_fields_are_refused_when_bound() {
    let f = fixture();
    let items = f.vault.items();
    let login = items
        .iter()
        .find(|m| m.slug.as_str() == "fixture/editor")
        .unwrap();
    let kinds: Vec<FieldKind> = login.fields.iter().map(|f| f.kind).collect();
    assert_eq!(kinds.len(), 4);
    assert!(kinds.iter().all(|k| k.is_login()));
    let mut refs = vec!["fixture/editor".to_owned()];
    refs.extend(
        login
            .fields
            .iter()
            .map(|f| format!("fixture/editor#{}", f.name)),
    );
    refs.push("fixture/editor#value".to_owned());
    for reference in &refs {
        for manifest in [
            format!("[env]\nPASSWORD = \"{reference}\"\n"),
            format!("[env]\nOPENAI_API_KEY = \"openai/work\"\nPASSWORD = \"{reference}\"\n"),
            format!(
                "[env]\nOPENAI_API_KEY = \"openai/work\"\n[env.e2e]\nPASSWORD = \"{reference}\"\n"
            ),
        ] {
            let m = parse_manifest(manifest.as_bytes()).unwrap();
            let profile = manifest
                .contains("[env.e2e]")
                .then(|| envcloak_policy::ProfileName::new("e2e").unwrap());
            let b = resolve(&m, profile.as_ref(), &[], None).unwrap();
            let e = bind_items(&b, items).unwrap_err();
            assert_eq!(e.kind(), BindErrorKind::LoginReference, "{manifest}");
            assert_eq!(e.token(), "login_reference");
            assert_eq!(e.kind().token(), "login_reference");
            assert_eq!(e.env_name().as_str(), "PASSWORD");
        }
        let arg = Binding::parse_arg(&format!("PASSWORD={reference}")).unwrap();
        let e = bind_items(&[arg], items).unwrap_err();
        assert_eq!(e.kind(), BindErrorKind::LoginReference, "{reference}");
        // The message names the rule, never the reference or a value.
        let shown = e.to_string();
        assert!(!shown.contains("fixture/editor") && !shown.contains("editor@"));
    }
    assert!(
        bind_items(
            &bindings("[env]\nOPENAI_API_KEY = \"openai/work\"\n"),
            items
        )
        .is_ok()
    );
}
