//! The registry compiled into the release (SPEC §8 "Registry safety"): it
//! is `providers/` byte for byte, so an edit that was not regenerated with
//! scripts/gen-providers.py fails here; it loads under the gate 18 rules;
//! and its providers carry what import and `add` pre-fill.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use envcloak_providers::{AuthSlot, SUFFIX_FILE, embedded_files, load_embedded};

fn providers_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../providers")
}

#[test]
fn the_embedded_files_are_the_providers_directory() {
    let mut on_disk = BTreeMap::new();
    for entry in std::fs::read_dir(providers_dir()).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if name.ends_with(".toml") || name == SUFFIX_FILE {
            on_disk.insert(name, std::fs::read_to_string(entry.path()).unwrap());
        }
    }
    let compiled: BTreeMap<String, String> = embedded_files()
        .iter()
        .map(|(name, text)| ((*name).to_owned(), (*text).to_owned()))
        .collect();
    let stale = "run python3 scripts/gen-providers.py";
    assert_eq!(
        compiled.keys().collect::<Vec<_>>(),
        on_disk.keys().collect::<Vec<_>>(),
        "the embedded file list differs from providers/: {stale}"
    );
    for (name, text) in &on_disk {
        assert!(
            compiled[name] == *text,
            "providers/{name} differs from its embedded copy: {stale}"
        );
    }
    // Sorted by name, as the generator writes them.
    let names: Vec<&str> = embedded_files().iter().map(|(n, _)| *n).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted);
}

#[test]
fn the_embedded_registry_loads() {
    let r = load_embedded().unwrap();
    let ids: Vec<&str> = r.providers().iter().map(|p| p.id.as_str()).collect();
    assert_eq!(
        ids,
        ["anthropic", "aws", "deepseek", "github", "openai", "stripe"]
    );
    for p in r.providers() {
        // Every provider links to the page where its keys are rotated
        // (SPEC §6.5), and names at least one variable.
        assert!(p.links.keys_page.is_some(), "{}", p.id);
        assert!(p.links.docs.is_some(), "{}", p.id);
        assert!(!p.env_hints.is_empty(), "{}", p.id);
        assert!(!p.key_patterns.is_empty(), "{}", p.id);
        // No wildcard hosts ship yet: each key goes to named hosts only.
        assert!(p.allowed_hosts.iter().all(|h| !h.is_wildcard()), "{}", p.id);
        // A balance request goes to an allowed host in a declared slot, and
        // not to a denied path.
        if let Some(b) = &p.balance {
            assert!(p.host_allowed(b.request.url.host()), "{}", p.id);
            assert!(p.auth_slots.contains(&b.request.auth), "{}", p.id);
            assert!(!p.path_denied(b.request.url.path()), "{}", p.id);
        }
    }

    let hosts = |id: &str| -> Vec<String> {
        r.get(id)
            .unwrap()
            .allowed_hosts
            .iter()
            .map(ToString::to_string)
            .collect()
    };
    assert_eq!(hosts("openai"), ["api.openai.com"]);
    assert_eq!(hosts("anthropic"), ["api.anthropic.com"]);
    assert_eq!(hosts("stripe"), ["api.stripe.com", "files.stripe.com"]);
    assert_eq!(hosts("github"), ["api.github.com", "uploads.github.com"]);
    assert_eq!(hosts("deepseek"), ["api.deepseek.com"]);
    // AWS signs with SigV4, which proxy mode does not support: no hosts.
    assert!(hosts("aws").is_empty());
    assert!(r.get("aws").unwrap().auth_slots.is_empty());

    let bearer = AuthSlot::Header {
        name: "authorization".into(),
        scheme: Some("Bearer".into()),
    };
    assert_eq!(
        r.get("openai").unwrap().auth_slots,
        std::slice::from_ref(&bearer)
    );
    assert_eq!(
        r.get("anthropic").unwrap().auth_slots,
        [AuthSlot::Header {
            name: "x-api-key".into(),
            scheme: None
        }]
    );
    assert_eq!(
        r.get("stripe").unwrap().auth_slots,
        [bearer.clone(), AuthSlot::BasicUser]
    );

    let deepseek = r.get("deepseek").unwrap();
    let b = deepseek.balance.as_ref().unwrap();
    assert_eq!(
        b.request.url.as_str(),
        "https://api.deepseek.com/user/balance"
    );
    assert_eq!(b.request.auth, bearer);
    assert_eq!(b.value.as_str(), "$.balance_infos[0].total_balance");

    // The admin and key-management paths are denied.
    let openai = r.get("openai").unwrap();
    assert!(openai.path_denied("/v1/organization/admin_api_keys"));
    assert!(!openai.path_denied("/v1/chat/completions"));
    // Spellings a server could strip back to a denied path.
    for odd in [
        "/v1/organization;x=1/admin_api_keys",
        "/v1/organization;/admin_api_keys",
        "/v1/organization./admin_api_keys",
        "/v1/organization /admin_api_keys",
    ] {
        assert!(openai.path_denied(odd), "{odd}");
    }
    let anthropic = r.get("anthropic").unwrap();
    assert!(anthropic.path_denied("/v1/organizations/api_keys"));
    assert!(!anthropic.path_denied("/v1/messages"));
    let github = r.get("github").unwrap();
    assert!(github.path_denied("/repos/acme/web/keys"));
    assert!(github.path_denied("/repos/acme/web/actions/runners/registration-token"));
    assert!(!github.path_denied("/repos/acme/web/pulls"));
    let stripe = r.get("stripe").unwrap();
    assert!(stripe.path_denied("/v1/ephemeral_keys"));
    assert!(!stripe.path_denied("/v1/charges"));
}

#[test]
fn env_hint_suggestions() {
    let r = load_embedded().unwrap();
    let id = |n: &str| r.by_env_hint(n).map(|p| p.id.to_string());
    assert_eq!(id("AWS_SECRET_ACCESS_KEY").as_deref(), Some("aws"));
    assert_eq!(
        id("NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY").as_deref(),
        Some("stripe")
    );
    assert_eq!(id("GH_TOKEN").as_deref(), Some("github"));
    assert_eq!(id("DATABASE_URL"), None);
    // Named by two providers' hints: no suggestion.
    assert_eq!(id("OPENAI_API_KEY_OR_DEEPSEEK_API_KEY"), None);
}
