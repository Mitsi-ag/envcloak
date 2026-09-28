//! Provider detection and test or live classification (SPEC §6.3, §6.4)
//! over values generated at test time, and pre-filling an item from a
//! detection. Nothing key-shaped is in this file: prefixes are split, and
//! every body is random per run. A failure prints the seed and the case's
//! name, never the value.
#![allow(clippy::unwrap_used)]

use envcloak_core::SecretBytes;
use envcloak_core::vault::{Classification, ItemDetails};
use envcloak_providers::{Detection, Registry, load_embedded};
use envcloak_testkit::{Canary, assert_no_canary, by_label, canaries, fresh_seed, labels};

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const KEY_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const HEX: &[u8] = b"0123456789abcdef";
const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// SplitMix64, seeded per run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn s(&mut self, alphabet: &[u8], len: usize) -> String {
        (0..len)
            .map(|_| char::from(alphabet[(self.next() % alphabet.len() as u64) as usize]))
            .collect()
    }

    /// A 48-character user-key body with an uppercase letter, so it is not
    /// hex.
    fn legacy(&mut self) -> String {
        format!("Z{}", self.s(ALNUM, 47))
    }
}

fn detect(r: &Registry, value: &str, env: Option<&str>) -> Detection {
    r.detect(&SecretBytes::copy_from(value.as_bytes()), env)
}

/// Checks a detection without printing the value on failure.
fn expect(
    r: &Registry,
    seed: u64,
    case: &str,
    value: &str,
    env: Option<&str>,
    provider: Option<&str>,
    class: Classification,
) {
    let d = detect(r, value, env);
    let got = d.provider.as_ref().map(|p| p.as_str());
    assert!(
        got == provider && d.classification == class && !d.ambiguous,
        "seed {seed}, case {case}: got {got:?} {:?} ambiguous={}, want {provider:?} {class:?}",
        d.classification,
        d.ambiguous
    );
    // One provider, one candidate: the pattern decided alone.
    if provider.is_some() {
        assert_eq!(d.candidates.len(), 1, "seed {seed}, case {case}");
    } else {
        assert!(d.candidates.is_empty(), "seed {seed}, case {case}");
    }
    // An empty value is found in any text; the rest must not be in the
    // detection's Debug output.
    if !value.is_empty() {
        assert_no_canary(
            format!("{d:?}").as_bytes(),
            &[Canary::new(case, value.to_owned())],
        );
    }
}

#[test]
fn detection_table() {
    let r = load_embedded().unwrap();
    let seed = fresh_seed();
    let mut g = Rng(seed);
    use Classification::{Live, Test, Unknown};
    let sk = concat!("s", "k-");
    let ant = concat!("sk", "-ant-");
    let cases: Vec<(&str, String, &str, Classification)> = vec![
        // OpenAI: project, service-account, admin and user keys.
        (
            "openai-proj",
            format!("{sk}proj-{}", g.s(KEY_CHARS, 156)),
            "openai",
            Live,
        ),
        (
            "openai-svcacct",
            format!("{sk}svcacct-{}", g.s(KEY_CHARS, 120)),
            "openai",
            Live,
        ),
        (
            "openai-admin",
            format!("{sk}admin-{}", g.s(KEY_CHARS, 120)),
            "openai",
            Live,
        ),
        (
            "openai-none",
            format!("{sk}None-{}", g.s(KEY_CHARS, 40)),
            "openai",
            Live,
        ),
        ("openai-user", format!("{sk}{}", g.legacy()), "openai", Live),
        // Anthropic: API, admin and OAuth token shapes.
        (
            "anthropic-api",
            format!("{ant}api03-{}AA", g.s(KEY_CHARS, 93)),
            "anthropic",
            Live,
        ),
        (
            "anthropic-admin",
            format!("{ant}admin01-{}", g.s(KEY_CHARS, 95)),
            "anthropic",
            Live,
        ),
        (
            "anthropic-oauth",
            format!("{ant}oat01-{}", g.s(KEY_CHARS, 95)),
            "anthropic",
            Live,
        ),
        // Stripe: live and test secret, restricted and publishable keys,
        // and a webhook secret, which is neither.
        (
            "stripe-sk-live",
            format!("{}{}", concat!("sk", "_live_"), g.s(ALNUM, 99)),
            "stripe",
            Live,
        ),
        (
            "stripe-sk-test",
            format!("{}{}", concat!("sk", "_test_"), g.s(ALNUM, 99)),
            "stripe",
            Test,
        ),
        (
            "stripe-rk-live",
            format!("{}{}", concat!("rk", "_live_"), g.s(ALNUM, 99)),
            "stripe",
            Live,
        ),
        (
            "stripe-rk-test",
            format!("{}{}", concat!("rk", "_test_"), g.s(ALNUM, 99)),
            "stripe",
            Test,
        ),
        (
            "stripe-pk-test",
            format!("{}{}", concat!("pk", "_test_"), g.s(ALNUM, 99)),
            "stripe",
            Test,
        ),
        (
            "stripe-whsec",
            format!("{}{}", concat!("wh", "sec_"), g.s(BASE64, 32)),
            "stripe",
            Unknown,
        ),
        // GitHub: every classic token kind, and fine-grained tokens.
        (
            "github-ghp",
            format!("{}{}", concat!("gh", "p_"), g.s(ALNUM, 36)),
            "github",
            Live,
        ),
        (
            "github-gho",
            format!("{}{}", concat!("gh", "o_"), g.s(ALNUM, 36)),
            "github",
            Live,
        ),
        (
            "github-ghu",
            format!("{}{}", concat!("gh", "u_"), g.s(ALNUM, 36)),
            "github",
            Live,
        ),
        (
            "github-ghs",
            format!("{}{}", concat!("gh", "s_"), g.s(ALNUM, 36)),
            "github",
            Live,
        ),
        (
            "github-ghr",
            format!("{}{}", concat!("gh", "r_"), g.s(ALNUM, 76)),
            "github",
            Live,
        ),
        (
            "github-pat",
            format!(
                "{}{}_{}",
                concat!("github", "_pat_"),
                g.s(ALNUM, 22),
                g.s(ALNUM, 59)
            ),
            "github",
            Live,
        ),
        // AWS access key ids, long-term and temporary.
        (
            "aws-akia",
            format!("{}{}", concat!("AK", "IA"), g.s(BASE32, 16)),
            "aws",
            Live,
        ),
        (
            "aws-asia",
            format!("{}{}", concat!("AS", "IA"), g.s(BASE32, 16)),
            "aws",
            Live,
        ),
    ];
    for (case, value, provider, class) in &cases {
        for env in [None, Some("SOME_VAR"), Some("DEEPSEEK_API_KEY")] {
            expect(&r, seed, case, value, env, Some(provider), *class);
        }
    }

    // Values that are no provider's key: detected as nothing.
    let no: Vec<(&str, String)> = vec![
        ("empty", String::new()),
        ("sk-short", format!("{sk}{}", g.s(ALNUM, 10))),
        (
            "ghp-one-short",
            format!("{}{}", concat!("gh", "p_"), g.s(ALNUM, 35)),
        ),
        (
            "stripe-body-short",
            format!("{}{}", concat!("sk", "_live_"), g.s(ALNUM, 9)),
        ),
        (
            "stripe-unknown-mode",
            format!("{}{}", concat!("sk", "_prod_"), g.s(ALNUM, 30)),
        ),
        (
            "aws-lowercase",
            format!("{}{}", concat!("AK", "IA"), g.s(b"abcdefgh", 16)),
        ),
        ("aws-secret-shape", g.s(BASE64, 40)),
        ("hex-32", g.s(HEX, 32)),
        (
            "uuid",
            format!(
                "{}-{}-{}-{}-{}",
                g.s(HEX, 8),
                g.s(HEX, 4),
                g.s(HEX, 4),
                g.s(HEX, 4),
                g.s(HEX, 12)
            ),
        ),
        (
            "url",
            format!("https://user:{}@db.example.internal/app", g.s(ALNUM, 20)),
        ),
        // Whole values only: a key with anything around it is not a key.
        (
            "ghp-newline",
            format!("{}{}\n", concat!("gh", "p_"), g.s(ALNUM, 36)),
        ),
        (
            "ghp-space",
            format!(" {}{}", concat!("gh", "p_"), g.s(ALNUM, 36)),
        ),
        (
            "ghp-in-text",
            format!("token={}{}", concat!("gh", "p_"), g.s(ALNUM, 36)),
        ),
        (
            "proj-with-suffix",
            format!("{sk}proj-{}!", g.s(KEY_CHARS, 60)),
        ),
        (
            "non-ascii",
            format!("{}{}\u{e9}", concat!("gh", "p_"), g.s(ALNUM, 35)),
        ),
    ];
    for (case, value) in &no {
        for env in [None, Some("OPENAI_API_KEY"), Some("GITHUB_TOKEN")] {
            expect(&r, seed, case, value, env, None, Unknown);
        }
    }
    // Not UTF-8: matched as bytes, detected as nothing.
    let bytes = [concat!("gh", "p_").as_bytes(), &[0xff; 36]].concat();
    let d = r.detect(&SecretBytes::copy_from(&bytes), None);
    assert_eq!(d.provider, None, "seed {seed}");
}

/// A value both OpenAI's user-key pattern and DeepSeek's pattern match:
/// `sk-` and 32 lowercase hex digits. The variable name picks one; without
/// a name that does, the tie stands and the caller asks.
#[test]
fn ambiguity_between_openai_and_deepseek_is_resolved_by_env_hint() {
    let r = load_embedded().unwrap();
    let seed = fresh_seed();
    let mut g = Rng(seed);
    for _ in 0..32 {
        let value = format!("{}{}", concat!("s", "k-"), g.s(HEX, 32));
        let pick = |env: Option<&str>| {
            let d = detect(&r, &value, env);
            assert_no_canary(
                format!("{d:?}").as_bytes(),
                &[Canary::new("sk-hex", value.clone())],
            );
            let ids: Vec<&str> = d.candidates.iter().map(|c| c.as_str()).collect();
            assert_eq!(ids, ["deepseek", "openai"], "seed {seed}");
            // Both providers call every key live, so the classification is
            // known even while the provider is not.
            assert_eq!(d.classification, Classification::Live, "seed {seed}");
            (d.provider.map(|p| p.to_string()), d.ambiguous)
        };
        for env in [
            "DEEPSEEK_API_KEY",
            "deepseek_api_key",
            "VITE_DEEPSEEK_API_KEY",
            "DEEPSEEK_API_KEY_PROD",
        ] {
            assert_eq!(pick(Some(env)), (Some("deepseek".into()), false), "{env}");
        }
        for env in [
            "OPENAI_API_KEY",
            "NEXT_PUBLIC_OPENAI_API_KEY",
            "OPENAI_ADMIN_KEY",
        ] {
            assert_eq!(pick(Some(env)), (Some("openai".into()), false), "{env}");
        }
        for env in [
            None,
            Some("API_KEY"),
            Some("LLM_KEY"),
            // A name that hints both is no tie-breaker.
            Some("OPENAI_API_KEY_DEEPSEEK_API_KEY"),
            // A hint of a provider that is not a candidate does not count.
            Some("GITHUB_TOKEN"),
        ] {
            assert_eq!(pick(env), (None, true), "{env:?}");
        }
    }
    // A hint never overrides a pattern: a GitHub token in OPENAI_API_KEY is
    // still GitHub's, and a DeepSeek-only shape is DeepSeek's.
    let gh = format!("{}{}", concat!("gh", "p_"), g.s(ALNUM, 36));
    let d = detect(&r, &gh, Some("OPENAI_API_KEY"));
    assert_eq!(d.provider.unwrap(), "github", "seed {seed}");
    let user = format!("{}{}", concat!("s", "k-"), g.legacy());
    let d = detect(&r, &user, Some("DEEPSEEK_API_KEY"));
    assert_eq!(d.provider.unwrap(), "openai", "seed {seed}");
}

/// The acceptance story's fixture values (SPEC §15.1).
#[test]
fn the_story_fixtures() {
    let r = load_embedded().unwrap();
    let seed = fresh_seed();
    let cs = canaries(seed);
    for (label, provider, class) in [
        (labels::OPENAI_API_KEY, Some("openai"), Classification::Live),
        (
            labels::OPENAI_API_KEY_ROTATED,
            Some("openai"),
            Classification::Live,
        ),
        (
            labels::STRIPE_SECRET_KEY,
            Some("stripe"),
            Classification::Test,
        ),
        (labels::GITHUB_TOKEN, Some("github"), Classification::Live),
        (labels::DATABASE_URL, None, Classification::Unknown),
        (labels::SHORT_TOKEN, None, Classification::Unknown),
        (labels::VAULT_PASSPHRASE, None, Classification::Unknown),
    ] {
        let c = by_label(&cs, label);
        let d = r.detect(&SecretBytes::copy_from(c.value()), Some(label));
        assert_eq!(
            (d.provider.as_ref().map(|p| p.as_str()), d.classification),
            (provider, class),
            "seed {seed}, {label}"
        );
        assert_no_canary(format!("{d:?}").as_bytes(), &cs);
    }
}

/// What import and `add` store for a detected key (SPEC §5 "Items", §6.3):
/// the provider, its links, a snapshot of its allowed hosts, and the
/// classification.
#[test]
fn prefill_from_a_detection() {
    let r = load_embedded().unwrap();
    let seed = fresh_seed();
    let cs = canaries(seed);
    let value = SecretBytes::copy_from(by_label(&cs, labels::OPENAI_API_KEY).value());
    let d = r.detect(&value, Some("OPENAI_API_KEY"));

    let mut item = ItemDetails::default();
    r.prefill(&d, &mut item);
    assert_eq!(item.provider.as_deref(), Some("openai"));
    assert_eq!(item.title, "OpenAI");
    assert_eq!(item.env_hint.as_deref(), Some("OPENAI_API_KEY"));
    assert_eq!(item.classification, Classification::Live);
    assert_eq!(item.allowed_hosts, ["api.openai.com"]);
    let openai = r.get("openai").unwrap();
    assert_eq!(item.links, openai.links);
    assert!(item.links.keys_page.is_some() && item.links.billing.is_some());

    // Fields the caller set are kept.
    let mut item = ItemDetails {
        title: "OpenAI (work)".into(),
        env_hint: Some("OPENAI_KEY_WORK".into()),
        allowed_hosts: vec!["gateway.acme.internal".into()],
        ..ItemDetails::default()
    };
    item.links.docs = Some("https://wiki.acme.internal/openai".into());
    r.prefill(&d, &mut item);
    assert_eq!(item.title, "OpenAI (work)");
    assert_eq!(item.env_hint.as_deref(), Some("OPENAI_KEY_WORK"));
    assert_eq!(item.allowed_hosts, ["gateway.acme.internal"]);
    assert_eq!(
        item.links.docs.as_deref(),
        Some("https://wiki.acme.internal/openai")
    );
    assert_eq!(item.links.keys_page, openai.links.keys_page);

    // An item already filed under another provider is left alone.
    let mut item = ItemDetails {
        provider: Some("azure-openai".into()),
        ..ItemDetails::default()
    };
    r.prefill(&d, &mut item);
    assert_eq!(item.provider.as_deref(), Some("azure-openai"));
    assert_eq!(item.classification, Classification::Unknown);
    assert!(item.allowed_hosts.is_empty() && item.links == Default::default());

    // An ambiguous detection fills the classification only.
    let mut g = Rng(seed);
    let tie = SecretBytes::copy_from(format!("{}{}", concat!("s", "k-"), g.s(HEX, 32)).as_bytes());
    let d = r.detect(&tie, None);
    assert!(d.ambiguous);
    let mut item = ItemDetails::default();
    r.prefill(&d, &mut item);
    assert_eq!(item.provider, None);
    assert_eq!(item.classification, Classification::Live);
    assert!(item.allowed_hosts.is_empty() && item.title.is_empty());

    // Nothing detected: nothing filled.
    let none = SecretBytes::copy_from(by_label(&cs, labels::DATABASE_URL).value());
    let d = r.detect(&none, Some("DATABASE_URL"));
    let mut item = ItemDetails::default();
    r.prefill(&d, &mut item);
    assert_eq!(item, ItemDetails::default());
}

/// Key-shaped words in a command line are masked, whatever surrounds them
/// (`KEY=`, `Bearer `, a URL query, quotes, a trailing period), and nothing
/// else changes: the audit log keeps command lines agents ran, and agents
/// paste keys into them.
#[test]
fn key_shaped_words_in_a_command_line_are_masked() {
    let r = load_embedded().unwrap();
    let cs = canaries(fresh_seed());
    let openai = by_label(&cs, labels::OPENAI_API_KEY).as_str();
    let stripe = by_label(&cs, labels::STRIPE_SECRET_KEY).as_str();
    let github = by_label(&cs, labels::GITHUB_TOKEN).as_str();
    let lines = [
        format!("OPENAI_API_KEY={openai}"),
        format!("Authorization: Bearer {openai}"),
        format!("https://api.example.test/v1?key={stripe}&x=1"),
        format!("'{github}'"),
        format!("token {github}."),
        format!("{stripe}.{openai}"),
    ];
    for line in &lines {
        let masked = r.mask_keys(line);
        assert_no_canary(masked.as_bytes(), &cs);
        assert!(masked.contains("[envcloak:key:"), "a key was not masked");
    }
    assert_eq!(
        r.mask_keys(&lines[0]),
        "OPENAI_API_KEY=[envcloak:key:openai]"
    );
    assert_eq!(
        r.mask_keys(&lines[2]),
        "https://api.example.test/v1?key=[envcloak:key:stripe]&x=1"
    );
    assert_eq!(r.mask_keys(&lines[4]), "token [envcloak:key:github].");
    // Text without a key, non-ASCII text and short key-like words stay.
    for plain in [
        "./emit --flag",
        "caf\u{e9} \u{1F600} sk-short",
        "",
        "--output=/tmp/some/long/path/name.txt",
    ] {
        assert_eq!(r.mask_keys(plain), plain);
    }
}
