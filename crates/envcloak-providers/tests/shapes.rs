//! Recorded response-shape tests for M4-07 (`m4-plan.md` D4-05, Review log F17
//! and F29): verifies that DeepSeek (CNY-first multi-currency), OpenRouter
//! (`GET /api/v1/key`), Moonshot (`GET /v1/users/me/balance`), and GitHub
//! (`GET /rate_limit` `GitHub-Authentication-Token-Expiration` header) all
//! load under registry grammar v2 and extract exact typed values without floats.
#![allow(clippy::unwrap_used)]

use std::path::PathBuf;

use envcloak_providers::{
    MAX_JSON_DEPTH, MetricName, MetricValue, MetricsExtractError, SUFFIX_FILE, ScaledAmount,
    load_embedded, load_from,
};

const SUFFIXES: &str = "vercel.app\nco.uk\n";

fn shape_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/shapes")
        .join(name)
}

#[test]
fn deepseek_cny_first_fixture_extracts_both_usd_and_cny() {
    let reg = load_embedded().unwrap();
    let deepseek = reg.get("deepseek").unwrap();
    let adapter = deepseek.metrics.as_ref().unwrap();

    // CNY appears before USD in `balance_infos`; field-equality selection
    // (`balance_infos[currency=USD]` and `balance_infos[currency=CNY]`) reads
    // each currency into its own entry regardless of array order.
    let cny_first_body = br#"{
        "is_available": true,
        "balance_infos": [
            {
                "currency": "CNY",
                "total_balance": "128.50",
                "granted_balance": "28.50",
                "topped_up_balance": "100.00"
            },
            {
                "currency": "USD",
                "total_balance": "14.25",
                "granted_balance": "0.00",
                "topped_up_balance": "14.25"
            }
        ]
    }"#;

    let extracted = adapter.extract(cny_first_body, &[]).unwrap();
    let usd = extracted
        .get_selected(MetricName::Balance, "currency", "USD")
        .unwrap();
    let cny = extracted
        .get_selected(MetricName::Balance, "currency", "CNY")
        .unwrap();

    assert_eq!(
        usd.value,
        Some(MetricValue::Amount(ScaledAmount {
            minor: 1425,
            scale: 2,
        }))
    );
    assert_eq!(
        cny.value,
        Some(MetricValue::Amount(ScaledAmount {
            minor: 12850,
            scale: 2,
        }))
    );
}

#[test]
fn openrouter_recorded_key_shape_loads_with_literals_enum_and_null_limit() {
    let openrouter_toml = r#"id = "openrouter"
name = "OpenRouter"
key_patterns = ['^sk-or-v1-[a-f0-9]{64}$']
live_patterns = ['^sk-or-v1-']
env_hints = ["OPENROUTER_API_KEY"]
allowed_hosts = ["openrouter.ai"]
auth = [{ header = "authorization", scheme = "Bearer" }]
denied_paths = ["/api/v1/keys"]

[links]
docs = "https://openrouter.ai/docs"
billing = "https://openrouter.ai/settings/credits"
keys = "https://openrouter.ai/settings/keys"

[metrics]
request = { method = "GET", url = "https://openrouter.ai/api/v1/key", auth = "bearer" }
values = [
    { name = "credit_limit", path = "$.data.limit", unit = "major", nullable = true },
    { name = "limit_remaining", path = "$.data.limit_remaining", unit = "major", nullable = true },
    { name = "limit_reset", path = "$.data.limit_reset", unit = "enum(daily, weekly, monthly)", nullable = true },
    { name = "spend_total", path = "$.data.usage", unit = "major" },
    { name = "spend_day", path = "$.data.usage_daily", unit = "major" },
    { name = "spend_week", path = "$.data.usage_weekly", unit = "major" },
    { name = "spend_month", path = "$.data.usage_monthly", unit = "major" },
    { name = "byok_in_limit", path = "$.data.include_byok_in_limit", unit = "bool" },
    { name = "is_management_key", path = "$.data.is_management_key", unit = "bool" },
    { name = "expires_at", path = "$.data.expires_at", unit = "rfc3339", nullable = true },
    { name = "currency", literal = "USD", source = "https://openrouter.ai/docs/api-reference/limits", unit = "iso4217" },
    { name = "cap_scope", literal = "key", source = "https://openrouter.ai/docs/api-reference/limits", unit = "enum(key, account, organization, provider)" },
    { name = "cap_enforced", literal = true, source = "https://openrouter.ai/docs/api-reference/limits", unit = "bool" },
]
"#;

    let reg = load_from(&[
        ("openrouter.toml", openrouter_toml.as_bytes()),
        (SUFFIX_FILE, SUFFIXES.as_bytes()),
    ])
    .unwrap();
    let p = reg.get("openrouter").unwrap();
    assert!(p.path_denied("/api/v1/keys"));
    assert!(p.path_denied("/api/v1/keys/abc"));

    let adapter = p.metrics.as_ref().unwrap();
    let body = std::fs::read(shape_path("openrouter_key.json")).unwrap();
    let out = adapter.extract(&body, &[]).unwrap();

    // D4-05: JSON `null` at `limit` and `limit_remaining` means "not set" (`None`),
    // never zero and never an error.
    assert_eq!(out.get(MetricName::CreditLimit).unwrap().value, None);
    assert_eq!(out.get(MetricName::LimitRemaining).unwrap().value, None);
    assert_eq!(
        out.get(MetricName::LimitReset).unwrap().value,
        Some(MetricValue::Enum("monthly".into()))
    );
    assert_eq!(
        out.get(MetricName::SpendTotal).unwrap().value,
        Some(MetricValue::Amount(ScaledAmount {
            minor: 18425,
            scale: 3,
        }))
    );
    assert_eq!(
        out.get(MetricName::SpendDay).unwrap().value,
        Some(MetricValue::Amount(ScaledAmount {
            minor: 125,
            scale: 2,
        }))
    );
    assert_eq!(
        out.get(MetricName::ByokInLimit).unwrap().value,
        Some(MetricValue::Bool(false))
    );
    assert_eq!(
        out.get(MetricName::IsManagementKey).unwrap().value,
        Some(MetricValue::Bool(false))
    );
    assert_eq!(
        out.get(MetricName::ExpiresAt).unwrap().value,
        Some(MetricValue::Timestamp(1_798_761_599))
    );
    assert_eq!(
        out.get(MetricName::Currency).unwrap().value,
        Some(MetricValue::Currency("USD".into()))
    );
    assert_eq!(
        out.get(MetricName::CapScope).unwrap().value,
        Some(MetricValue::Enum("key".into()))
    );
    assert_eq!(
        out.get(MetricName::CapEnforced).unwrap().value,
        Some(MetricValue::Bool(true))
    );
}

#[test]
fn moonshot_recorded_balance_shape_loads_negative_cash_balance_and_currency_literal() {
    let moonshot_toml = r#"id = "moonshot"
name = "Moonshot"
key_patterns = ['^sk-[A-Za-z0-9]{48}$']
live_patterns = ['^sk-']
env_hints = ["MOONSHOT_API_KEY"]
allowed_hosts = ["api.moonshot.ai"]
auth = [{ header = "authorization", scheme = "Bearer" }]

[links]
docs = "https://platform.moonshot.ai/docs"
billing = "https://platform.moonshot.ai/console/pay"
keys = "https://platform.moonshot.ai/console/api-keys"

[metrics]
request = { method = "GET", url = "https://api.moonshot.ai/v1/users/me/balance", auth = "bearer" }
values = [
    { name = "balance", path = "$.data.available_balance", unit = "major" },
    { name = "voucher_balance", path = "$.data.voucher_balance", unit = "major" },
    { name = "cash_balance", path = "$.data.cash_balance", unit = "major" },
    { name = "currency", literal = "USD", source = "m4/research.md §2.13", unit = "iso4217" },
]
"#;

    let reg = load_from(&[
        ("moonshot.toml", moonshot_toml.as_bytes()),
        (SUFFIX_FILE, SUFFIXES.as_bytes()),
    ])
    .unwrap();
    let adapter = reg.get("moonshot").unwrap().metrics.as_ref().unwrap();
    let body = std::fs::read(shape_path("moonshot_balance.json")).unwrap();
    let out = adapter.extract(&body, &[]).unwrap();

    assert_eq!(
        out.get(MetricName::Balance).unwrap().value,
        Some(MetricValue::Amount(ScaledAmount {
            minor: 425,
            scale: 1,
        }))
    );
    assert_eq!(
        out.get(MetricName::VoucherBalance).unwrap().value,
        Some(MetricValue::Amount(ScaledAmount {
            minor: 4575,
            scale: 2,
        }))
    );
    // Negative cash balance stays negative.
    let cash = out
        .get(MetricName::CashBalance)
        .unwrap()
        .value
        .as_ref()
        .unwrap();
    assert_eq!(
        cash,
        &MetricValue::Amount(ScaledAmount {
            minor: -325,
            scale: 2,
        })
    );
    assert_eq!(
        out.get(MetricName::Currency).unwrap().value,
        Some(MetricValue::Currency("USD".into()))
    );
}

#[test]
fn github_recorded_expiry_header_parses_as_github_expiry_and_absent_header_is_none() {
    let github_toml = r#"id = "github"
name = "GitHub"
key_patterns = ['^ghp_[A-Za-z0-9]{36}$']
live_patterns = ['^ghp_']
env_hints = ["GITHUB_TOKEN"]
allowed_hosts = ["api.github.com"]
auth = [{ header = "authorization", scheme = "Bearer" }]
denied_paths = ["/repos/*/*/keys"]

[links]
docs = "https://docs.github.com/en/rest"
keys = "https://github.com/settings/tokens"

[metrics]
request = { method = "GET", url = "https://api.github.com/rate_limit", auth = "bearer" }
values = [
    { name = "expires_at", header = "github-authentication-token-expiration", unit = "github_expiry", nullable = true },
    { name = "rate_limit_remaining", header = "x-ratelimit-remaining", unit = "minor", nullable = true },
    { name = "rate_limit_reset", header = "x-ratelimit-reset", unit = "unix_seconds", nullable = true },
]
"#;

    let reg = load_from(&[
        ("github.toml", github_toml.as_bytes()),
        (SUFFIX_FILE, SUFFIXES.as_bytes()),
    ])
    .unwrap();
    let adapter = reg.get("github").unwrap().metrics.as_ref().unwrap();

    let fixture_bytes = std::fs::read(shape_path("github_rate_limit_headers.json")).unwrap();
    let fixture_text = std::str::from_utf8(&fixture_bytes).unwrap();
    assert!(fixture_text.contains("2026-11-15 08:30:00 UTC"));

    let headers = [
        (
            "GitHub-Authentication-Token-Expiration",
            "2026-11-15 08:30:00 UTC",
        ),
        ("X-RateLimit-Remaining", "4999"),
        ("X-RateLimit-Reset", "1761526800"),
    ];
    let out = adapter.extract(b"{}", &headers).unwrap();
    assert_eq!(
        out.get(MetricName::ExpiresAt).unwrap().value,
        Some(MetricValue::Timestamp(1_794_731_400))
    );
    assert_eq!(
        out.get(MetricName::RateLimitRemaining).unwrap().value,
        Some(MetricValue::Amount(ScaledAmount {
            minor: 4999,
            scale: 2,
        }))
    );
    assert_eq!(
        out.get(MetricName::RateLimitReset).unwrap().value,
        Some(MetricValue::Timestamp(1_761_526_800))
    );

    // When a GitHub token has no expiration date, the header is absent:
    // `nullable = true` yields `None` ("no expiry").
    let no_expiry = adapter.extract(b"{}", &[]).unwrap();
    assert_eq!(no_expiry.get(MetricName::ExpiresAt).unwrap().value, None);
}

#[test]
fn extractor_refuses_deep_json_and_duplicate_keys() {
    let reg = load_embedded().unwrap();
    let adapter = reg.get("deepseek").unwrap().metrics.as_ref().unwrap();

    let deep = format!(
        "{}0{}",
        "[".repeat(MAX_JSON_DEPTH + 2),
        "]".repeat(MAX_JSON_DEPTH + 2)
    );
    assert_eq!(
        adapter.extract(deep.as_bytes(), &[]),
        Err(MetricsExtractError::JsonTooDeep)
    );

    let dup = br#"{"balance_infos": [], "balance_infos": []}"#;
    assert_eq!(
        adapter.extract(dup, &[]),
        Err(MetricsExtractError::MalformedJson)
    );
}
