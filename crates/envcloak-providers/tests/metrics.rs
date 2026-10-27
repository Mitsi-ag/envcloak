//! Loader refusal and validation tests for registry grammar v2 (`[metrics]`,
//! SPEC §8 "Adapters", D4-04, D4-05, M4-07).
#![allow(clippy::unwrap_used)]

use envcloak_providers::{
    AllowedHeader, LiteralValue, MetricName, MetricSource, MetricUnit, Registry,
    RegistryErrorKind as K, SUFFIX_FILE, load_from,
};

const SUFFIXES: &str = "vercel.app\nco.uk\n";

const GOOD_METRICS: &str = r#"# Metrics provider fixture
id = "example"
name = "Example"
key_patterns = ['^ex_(?:live|test)_[A-Za-z0-9]{24}$']
live_patterns = ['^ex_live_']
test_patterns = ['^ex_test_']
env_hints = ["EXAMPLE_API_KEY"]
allowed_hosts = ["api.example.com"]
auth = [
    { header = "authorization", scheme = "Bearer" },
    { query = "key" },
]
denied_paths = ["/v1/organization", "/v1/keys/*"]

[links]
docs = "https://docs.example.com"
keys = "https://console.example.com/keys"

[metrics]
request = { method = "GET", url = "https://api.example.com/v1/usage", auth = "bearer" }
values = [
    { name = "balance", path = "$.data.balance", unit = "decimal_string" },
    { name = "currency", literal = "USD", source = "https://docs.example.com/billing", unit = "iso4217" },
    { name = "expires_at", header = "github-authentication-token-expiration", unit = "github_expiry", nullable = true },
]
"#;

fn load(toml: &str) -> Result<Registry, envcloak_providers::RegistryError> {
    load_from(&[
        ("example.toml", toml.as_bytes()),
        (SUFFIX_FILE, SUFFIXES.as_bytes()),
    ])
}

fn fails(toml: &str) -> K {
    let err = load(toml).expect_err("expected registry file to be refused");
    assert_eq!(err.file(), "example.toml");
    err.kind()
}

fn edit(old: &str, new: &str) -> String {
    assert!(
        GOOD_METRICS.contains(old),
        "substring {old:?} not in GOOD_METRICS"
    );
    GOOD_METRICS.replacen(old, new, 1)
}

#[test]
fn valid_metrics_section_loads_all_three_source_kinds() {
    let r = load(GOOD_METRICS).unwrap();
    let p = r.get("example").unwrap();
    assert!(p.balance.is_none());
    let m = p.metrics.as_ref().unwrap();
    assert_eq!(m.request.url.as_str(), "https://api.example.com/v1/usage");
    assert_eq!(m.values.len(), 3);

    assert_eq!(m.values[0].name, MetricName::Balance);
    assert_eq!(m.values[0].unit, MetricUnit::DecimalString);
    assert!(!m.values[0].nullable);

    assert_eq!(m.values[1].name, MetricName::Currency);
    assert_eq!(
        m.values[1].source,
        MetricSource::Literal {
            value: LiteralValue::Str("USD".into()),
            cited: "https://docs.example.com/billing".into(),
        }
    );
    assert_eq!(m.values[1].unit, MetricUnit::Iso4217);

    assert_eq!(m.values[2].name, MetricName::ExpiresAt);
    assert_eq!(
        m.values[2].source,
        MetricSource::Header(AllowedHeader::GithubAuthenticationTokenExpiration)
    );
    assert_eq!(m.values[2].unit, MetricUnit::GithubExpiry);
    assert!(m.values[2].nullable);
}

#[test]
fn metrics_request_refuses_non_allowed_host_and_http() {
    for url in [
        "https://evil.example.com/v1/usage",
        "https://example.com/v1/usage",
        "https://api.example.com.evil.test/v1/usage",
    ] {
        let f = edit("https://api.example.com/v1/usage", url);
        assert_eq!(fails(&f), K::RequestHostNotAllowed, "{url}");
    }

    for url in [
        "http://api.example.com/v1/usage",
        "HTTPS://api.example.com/v1/usage",
        "//api.example.com/v1/usage",
    ] {
        let f = edit("https://api.example.com/v1/usage", url);
        assert_eq!(fails(&f), K::NotHttps, "{url}");
    }
}

#[test]
fn metrics_request_refuses_denied_paths_in_every_spelling() {
    for path in [
        "/v1/organization",
        "/v1/organization/",
        "/v1/organization/admin_api_keys",
        "/V1/Organization/admin_api_keys",
        "/v1/%6frganization/admin_api_keys",
        "/v1/organization%2Fadmin_api_keys",
        "/v1/usage/../organization",
        "/v1/./organization",
        "/v1//organization",
        "/v1/organization;x=1/admin_api_keys",
        "/v1/organization./admin_api_keys",
        "/v1/organization.json",
        "/v1/organization.json/admin_api_keys",
        "/v1/keys/abc",
        "/v1/keys.json/abc",
    ] {
        let url = format!("https://api.example.com{path}");
        let f = edit("https://api.example.com/v1/usage", &url);
        assert_eq!(fails(&f), K::RequestPathDenied, "{path}");
    }
}

#[test]
fn metrics_request_refuses_post_and_query_auth() {
    for method in ["POST", "PUT", "DELETE", "PATCH", "HEAD", "get"] {
        let f = edit("method = \"GET\"", &format!("method = \"{method}\""));
        assert_eq!(fails(&f), K::InvalidMethod, "{method}");
    }

    // D4-04, Review log F12: `query:` auth slot is refused on every adapter request.
    for query_slot in ["query:key", "query:token", "query:api_key"] {
        let f = edit("auth = \"bearer\"", &format!("auth = \"{query_slot}\""));
        assert_eq!(fails(&f), K::QueryAuthRefused, "{query_slot}");
    }
}

#[test]
fn metrics_refuses_unlisted_headers_and_17_step_json_paths() {
    for hdr in [
        "set-cookie",
        "Set-Cookie",
        "authorization",
        "Authorization",
        "cookie",
        "x-api-key",
        "x-custom-header",
        "GITHUB-AUTHENTICATION-TOKEN-EXPIRATION",
        "",
    ] {
        let f = edit(
            "header = \"github-authentication-token-expiration\"",
            &format!("header = \"{hdr}\""),
        );
        assert_eq!(fails(&f), K::HeaderNotAllowed, "{hdr}");
    }

    let ok_16 = format!("${}", ".a".repeat(16));
    let f_16 = edit("$.data.balance", &ok_16);
    assert!(load(&f_16).is_ok());

    let bad_17 = format!("${}", ".a".repeat(17));
    let f_17 = edit("$.data.balance", &bad_17);
    assert_eq!(fails(&f_17), K::InvalidJsonPath);
}

#[test]
fn metrics_refuses_literal_without_citation_or_with_mismatched_unit() {
    let no_source = edit(
        r#"{ name = "currency", literal = "USD", source = "https://docs.example.com/billing", unit = "iso4217" }"#,
        r#"{ name = "currency", literal = "USD", unit = "iso4217" }"#,
    );
    assert_eq!(fails(&no_source), K::LiteralMissingSource);

    for bad_source in ["", "   ", "guessed by hand", "http://insecure.example.com"] {
        let f = edit(
            r#"source = "https://docs.example.com/billing""#,
            &format!("source = {bad_source:?}"),
        );
        assert_eq!(fails(&f), K::LiteralMissingSource, "{bad_source:?}");
    }

    // Citation naming `research.md` or `SPEC.md` is accepted alongside `https://`.
    let research_cite = edit(
        r#"source = "https://docs.example.com/billing""#,
        r#"source = "m4/research.md §2.9""#,
    );
    assert!(load(&research_cite).is_ok());

    // Literal value must match the declared unit.
    let bad_iso = edit(r#"literal = "USD""#, r#"literal = "usd""#);
    assert_eq!(fails(&bad_iso), K::InvalidLiteral);

    let bad_enum = edit(
        r#"{ name = "currency", literal = "USD", source = "https://docs.example.com/billing", unit = "iso4217" }"#,
        r#"{ name = "cap_scope", literal = "invalid_scope", source = "https://docs.example.com/billing", unit = "enum(key, account, organization)" }"#,
    );
    assert_eq!(fails(&bad_enum), K::InvalidLiteral);
}

#[test]
fn metrics_refuses_builtin_in_inference_provider_file() {
    let top_level_builtin = format!("{GOOD_METRICS}\nbuiltin = \"openai_costs\"\n");
    assert_eq!(fails(&top_level_builtin), K::BuiltinRefused);

    let section_builtin = edit("[metrics]\n", "[metrics]\nbuiltin = \"openai_costs\"\n");
    assert_eq!(fails(&section_builtin), K::BuiltinRefused);
}

#[test]
fn metrics_refuses_duplicate_balance_and_invalid_names_units_or_selects() {
    let both = format!(
        "{GOOD_METRICS}\n[balance]\n\
         request = {{ method = \"GET\", url = \"https://api.example.com/v1/usage\", auth = \"bearer\" }}\n\
         value = \"$.data.balance\"\n"
    );
    assert_eq!(fails(&both), K::DuplicateKey);

    let empty_values = edit(
        r#"values = [
    { name = "balance", path = "$.data.balance", unit = "decimal_string" },
    { name = "currency", literal = "USD", source = "https://docs.example.com/billing", unit = "iso4217" },
    { name = "expires_at", header = "github-authentication-token-expiration", unit = "github_expiry", nullable = true },
]"#,
        "values = []",
    );
    assert_eq!(fails(&empty_values), K::NoMetricValues);

    let bad_name = edit(r#"name = "balance""#, r#"name = "unknown_metric""#);
    assert_eq!(fails(&bad_name), K::InvalidMetricName);

    for bad_unit in ["float", "enum()", "enum(a, a)", "enum(a b)"] {
        let f = edit(
            r#"unit = "decimal_string""#,
            &format!("unit = {bad_unit:?}"),
        );
        assert_eq!(fails(&f), K::InvalidUnit, "{bad_unit}");
    }

    let mismatched_select = edit(
        r#"{ name = "balance", path = "$.data.balance", unit = "decimal_string" }"#,
        r#"{ name = "balance", path = "$.data[currency=USD].balance", unit = "decimal_string", select = "currency=CNY" }"#,
    );
    assert_eq!(fails(&mismatched_select), K::InvalidSelect);
}
