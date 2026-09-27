//! Gate 18 (SPEC §15.2): the registry loader refuses a request host outside
//! `allowed_hosts`, an `http://` URL, and a wildcard under (or over) a
//! multi-tenant suffix; and the loader's other rules (docs/PROVIDERS.md). Each case
//! changes one line of a provider file that loads, and checks the kind and
//! the line of the error, so a case passes only for the reason it names.
#![allow(clippy::unwrap_used)]

use envcloak_providers::{
    AuthSlot, HostPattern, Method, PathSegment, Registry, RegistryError, RegistryErrorKind as K,
    SUFFIX_FILE, embedded_files, load_embedded, load_from,
};
use envcloak_testkit::{Canary, assert_no_canary, canaries, fresh_seed};

/// A provider file that loads and uses every key. Line numbers matter: the
/// tests below check them.
const GOOD: &str = r#"id = "example"
name = "Example"
key_patterns = ['^ex_(?:live|test)_[a-z0-9]{24}$']
live_patterns = ['^ex_live_']
test_patterns = ['^ex_test_']
env_hints = ["EXAMPLE_API_KEY"]
allowed_hosts = ["api.example.com", "*.example.net"]
auth = [{ header = "authorization", scheme = "Bearer" }, { query = "key" }]
denied_paths = ["/v1/keys", "/orgs/*/tokens"]

[links]
docs = "https://docs.example.com/api"
billing = "https://example.com/billing"
keys = "https://example.com/settings/keys#new"
dashboard = "https://example.com/"

[balance]
request = { method = "GET", url = "https://api.example.com/v1/balance", auth = "bearer" }
value = "$.data[0].balance"
currency = "$.data[0].currency"
"#;

const REQUEST_URL: &str = "https://api.example.com/v1/balance";
const REQUEST_LINE: u32 = 18;

/// The shipped multi-tenant suffix list.
fn suffixes() -> &'static str {
    embedded_files()
        .iter()
        .find(|(name, _)| *name == SUFFIX_FILE)
        .unwrap()
        .1
}

fn load(file: &str) -> Result<Registry, RegistryError> {
    load_from(&[
        ("example.toml", file.as_bytes()),
        (SUFFIX_FILE, suffixes().as_bytes()),
    ])
}

/// `GOOD` with `from`, which must occur exactly once, replaced by `to`.
fn edit(from: &str, to: &str) -> String {
    assert_eq!(GOOD.matches(from).count(), 1, "{from} must occur once");
    GOOD.replacen(from, to, 1)
}

/// The kind and line of the error loading `file`, which must be blamed.
fn fails(file: &str) -> (K, Option<u32>) {
    let e = load(file).unwrap_err();
    assert_eq!(e.file(), "example.toml", "{e}");
    (e.kind(), e.line())
}

#[test]
fn the_fixture_loads_with_every_key() {
    let r = load(GOOD).unwrap();
    assert_eq!(r.providers().len(), 1);
    let p = r.get("example").unwrap();
    assert_eq!(p.id, "example");
    assert_eq!(p.name, "Example");
    let pats = |v: &[envcloak_providers::KeyPattern]| {
        v.iter().map(|k| k.as_str().to_owned()).collect::<Vec<_>>()
    };
    assert_eq!(pats(&p.key_patterns), ["^ex_(?:live|test)_[a-z0-9]{24}$"]);
    assert_eq!(pats(&p.live_patterns), ["^ex_live_"]);
    assert_eq!(pats(&p.test_patterns), ["^ex_test_"]);
    assert_eq!(p.env_hints, ["EXAMPLE_API_KEY"]);
    let hosts: Vec<&str> = p.allowed_hosts.iter().map(HostPattern::as_str).collect();
    assert_eq!(hosts, ["api.example.com", "*.example.net"]);
    assert_eq!(
        p.auth_slots,
        [
            AuthSlot::Header {
                name: "authorization".into(),
                scheme: Some("Bearer".into())
            },
            AuthSlot::Query { name: "key".into() }
        ]
    );
    assert_eq!(p.denied_paths, ["/v1/keys", "/orgs/*/tokens"]);
    assert!(p.path_denied("/v1/keys/k_1") && p.path_denied("/orgs/acme/tokens"));
    assert!(!p.path_denied("/v1/balance"));
    assert!(p.host_allowed("api.example.com") && p.host_allowed("eu.example.net"));
    assert!(!p.host_allowed("example.net") && !p.host_allowed("docs.example.com"));
    assert_eq!(
        p.links.docs.as_deref(),
        Some("https://docs.example.com/api")
    );
    assert_eq!(
        p.links.billing.as_deref(),
        Some("https://example.com/billing")
    );
    assert_eq!(
        p.links.keys_page.as_deref(),
        Some("https://example.com/settings/keys#new")
    );
    assert_eq!(p.links.dashboard.as_deref(), Some("https://example.com/"));
    let b = p.balance.as_ref().unwrap();
    assert_eq!(b.request.method, Method::Get);
    assert_eq!(b.request.url.as_str(), REQUEST_URL);
    assert_eq!(b.request.url.host(), "api.example.com");
    assert_eq!(b.request.auth, p.auth_slots[0]);
    assert_eq!(
        b.value.segments(),
        [
            PathSegment::Key("data".into()),
            PathSegment::Index(0),
            PathSegment::Key("balance".into())
        ]
    );
    assert_eq!(b.currency.as_ref().unwrap().as_str(), "$.data[0].currency");

    // The optional keys may be left out.
    let minimal = "id = \"example\"\nname = \"Example\"\nkey_patterns = ['^ex_[a-z0-9]{24}$']\n\
                   allowed_hosts = []\n";
    let r = load(minimal).unwrap();
    let p = r.get("example").unwrap();
    assert!(p.live_patterns.is_empty() && p.auth_slots.is_empty() && p.balance.is_none());
    assert_eq!(p.links, Default::default());
}

#[test]
fn gate18_a_request_host_outside_allowed_hosts_fails_to_load() {
    for url in [
        // Another domain.
        "https://api.example.org/v1/balance",
        // The allowed host as a prefix of another name.
        "https://api.example.com.evil.test/v1/balance",
        // The allowed host in the path or query.
        "https://evil.test/api.example.com/v1/balance",
        "https://evil.test/v1/balance?h=api.example.com",
        // The parent of an exact host, and a name under it.
        "https://example.com/v1/balance",
        "https://www.api.example.com/v1/balance",
        // The wildcard's own domain, which it does not cover.
        "https://example.net/v1/balance",
    ] {
        assert_eq!(
            fails(&edit(REQUEST_URL, url)),
            (K::RequestHostNotAllowed, Some(REQUEST_LINE)),
            "{url}"
        );
    }
    // The request's host taken off the list, the request unchanged.
    for hosts in [r#"["*.example.net"]"#, "[]"] {
        let f = edit(r#"["api.example.com", "*.example.net"]"#, hosts);
        assert_eq!(
            fails(&f),
            (K::RequestHostNotAllowed, Some(REQUEST_LINE)),
            "{hosts}"
        );
    }
    // Spellings that hide another host, or no host, are refused outright.
    for url in [
        "https://api.example.com@evil.test/v1/balance",
        "https://evil.test#@api.example.com/v1/balance",
        // A TOML backslash escape: the URL holds one backslash.
        "https://api.example.com\\\\@evil.test/v1/balance",
        "https://api.example.com:8443/v1/balance",
        "https://API.EXAMPLE.COM/v1/balance",
        "https://api.example.com./v1/balance",
        "https://93.184.216.34/v1/balance",
        "https://[::1]/v1/balance",
        "https://api.example.com/v1/balance#fragment",
        "https://api.example.com/v1/bal ance",
        "https:///v1/balance",
    ] {
        assert_eq!(
            fails(&edit(REQUEST_URL, url)),
            (K::InvalidUrl, Some(REQUEST_LINE)),
            "{url}"
        );
    }
    // Hosts the wildcard covers load.
    for url in [
        "https://eu.example.net/v1/balance",
        "https://a.b.example.net/v1/balance",
    ] {
        let r = load(&edit(REQUEST_URL, url)).unwrap();
        let b = r.get("example").unwrap().balance.clone().unwrap();
        assert_eq!(b.request.url.as_str(), url);
    }
}

#[test]
fn gate18_an_http_url_fails_to_load() {
    let http = |url: &str| url.replacen("https://", "http://", 1);
    assert_eq!(
        fails(&edit(REQUEST_URL, &http(REQUEST_URL))),
        (K::NotHttps, Some(REQUEST_LINE))
    );
    // Every link, too: a link opens in the browser, not with the key, but it
    // must not be downgraded either.
    for (line, url) in [
        (12, "https://docs.example.com/api"),
        (13, "https://example.com/billing"),
        (14, "https://example.com/settings/keys#new"),
        (15, "https://example.com/"),
    ] {
        let f = edit(&format!("\"{url}\""), &format!("\"{}\"", http(url)));
        assert_eq!(fails(&f), (K::NotHttps, Some(line)), "{url}");
    }
    // Anything else that is not https:// exactly.
    for url in [
        "HTTPS://api.example.com/v1/balance",
        "Https://api.example.com/v1/balance",
        "ftp://api.example.com/v1/balance",
        "ws://api.example.com/v1/balance",
        "//api.example.com/v1/balance",
        "https:/api.example.com/v1/balance",
        "api.example.com/v1/balance",
        " https://api.example.com/v1/balance",
    ] {
        assert_eq!(
            fails(&edit(REQUEST_URL, url)),
            (K::NotHttps, Some(REQUEST_LINE)),
            "{url}"
        );
    }
}

#[test]
fn gate18_a_wildcard_under_a_multi_tenant_suffix_fails_to_load() {
    let registry = load_embedded().unwrap();
    let list = registry.multi_tenant_suffixes();
    // The suffixes SPEC §8 names are on the shipped list.
    for s in [
        "supabase.co",
        "workers.dev",
        "vercel.app",
        "herokuapp.com",
        "netlify.app",
        "amazonaws.com",
    ] {
        assert!(list.iter().any(|x| x == s), "{s} is missing from the list");
    }
    assert!(list.len() >= 30, "the list has {} entries", list.len());

    const WILDCARD: &str = "\"*.example.net\"";
    for s in list {
        for host in [
            format!("*.{s}"),
            format!("*.acme.{s}"),
            format!("*.a.b.{s}"),
        ] {
            let f = edit(WILDCARD, &format!("\"{host}\""));
            assert_eq!(
                fails(&f),
                (K::WildcardUnderMultiTenantSuffix, Some(7)),
                "{host}"
            );
        }
        // Not wildcards under the suffix: an exact tenant host, and a
        // wildcard under a domain that merely contains the suffix. The
        // request line goes, since these hosts do not cover it.
        for host in [format!("acme.{s}"), format!("*.{s}.example.com")] {
            let f = edit(WILDCARD, &format!("\"{host}\""));
            let f = f.replacen(REQUEST_URL, "https://api.example.com/", 1);
            assert!(load(&f).is_ok(), "{host}");
        }
    }
    // A wildcard over a whole top-level domain, and malformed wildcards.
    for (host, kind) in [
        ("*.com", K::WildcardTooBroad),
        ("*.net", K::WildcardTooBroad),
        ("*", K::InvalidHost),
        ("*.*.example.net", K::InvalidHost),
        ("api.*.example.net", K::InvalidHost),
        ("*example.net", K::InvalidHost),
        ("**.example.net", K::InvalidHost),
    ] {
        let f = edit(WILDCARD, &format!("\"{host}\""));
        assert_eq!(fails(&f), (kind, Some(7)), "{host}");
    }

    // A wildcard over a whole public suffix of two labels, which the list
    // need not name, and multi-tenant platforms the list does name.
    for host in ["*.com.sg", "*.co.kr", "*.com.tw", "*.net.br", "*.org.il"] {
        let f = edit(WILDCARD, &format!("\"{host}\""));
        assert_eq!(fails(&f), (K::WildcardTooBroad, Some(7)), "{host}");
    }
    for s in [
        "amplifyapp.com",
        "elasticbeanstalk.com",
        "azurefd.net",
        "azurecontainerapps.io",
        "aliyuncs.com",
        "github.dev",
        "ts.net",
        "csb.app",
        "myshopify.com",
        "blogspot.com",
    ] {
        assert!(list.iter().any(|x| x == s), "{s} is missing from the list");
    }

    // The list is what refuses them: without an entry for vercel.app the same
    // wildcard loads, and with an entry for example.net the fixture fails.
    let f = edit(WILDCARD, "\"*.vercel.app\"");
    assert!(load_from(&[("example.toml", f.as_bytes()), (SUFFIX_FILE, b"# none\n")]).is_ok());
    let e = load_from(&[
        ("example.toml", GOOD.as_bytes()),
        (SUFFIX_FILE, b"example.net\n"),
    ])
    .unwrap_err();
    assert_eq!(
        (e.kind(), e.line()),
        (K::WildcardUnderMultiTenantSuffix, Some(7))
    );
}

/// A wildcard over a multi-tenant suffix matches every tenant host under
/// it, so it is refused like one under the suffix. The shipped list has
/// two-label entries only, where the domain above is a top-level domain;
/// these lists have deeper entries, as public-suffix private entries do.
#[test]
fn gate18_a_wildcard_over_a_multi_tenant_suffix_fails_to_load() {
    const WILDCARD: &str = "\"*.example.net\"";
    let list = b"tenants.example.net\napp.region.example.org\n";
    let with = |file: &str| load_from(&[("example.toml", file.as_bytes()), (SUFFIX_FILE, list)]);
    let host = |h: &str| {
        edit(WILDCARD, &format!("\"{h}\"")).replacen(REQUEST_URL, "https://api.example.com/", 1)
    };

    // The fixture's *.example.net is over tenants.example.net: it would let a
    // request reach evil.tenants.example.net.
    let e = with(GOOD).unwrap_err();
    assert_eq!(
        (e.kind(), e.file(), e.line()),
        (K::WildcardOverMultiTenantSuffix, "example.toml", Some(7))
    );
    // Over the parent and over the grandparent of a three-label entry.
    for h in ["*.region.example.org", "*.example.org"] {
        let e = with(&host(h)).unwrap_err();
        assert_eq!(
            (e.kind(), e.line()),
            (K::WildcardOverMultiTenantSuffix, Some(7)),
            "{h}"
        );
    }
    for h in ["*.tenants.example.net", "*.app.region.example.org"] {
        let e = with(&host(h)).unwrap_err();
        assert_eq!(
            (e.kind(), e.line()),
            (K::WildcardUnderMultiTenantSuffix, Some(7)),
            "{h}"
        );
    }
    // A sibling of an entry loads, and covers no tenant host.
    for (h, inside) in [
        ("*.other.example.net", "a.other.example.net"),
        ("*.other.region.example.org", "a.other.region.example.org"),
    ] {
        let r = with(&host(h)).unwrap();
        let p = r.get("example").unwrap();
        assert!(p.host_allowed(inside), "{h}");
        assert!(!p.host_allowed("evil.tenants.example.net"), "{h}");
        assert!(!p.host_allowed("evil.app.region.example.org"), "{h}");
    }
    // An exact tenant host is stored as it is.
    assert!(with(&host("acme.tenants.example.net")).is_ok());
    // Without the deep entries the fixture loads: the list is what refuses it.
    assert!(
        load_from(&[
            ("example.toml", GOOD.as_bytes()),
            (SUFFIX_FILE, b"# none\n")
        ])
        .is_ok()
    );
}

/// A balance request is sent with the key, so it may not go to one of the
/// provider's own denied paths (SPEC §6.2 rule 4), in any spelling a server
/// could normalize to one.
#[test]
fn a_balance_request_to_a_denied_path_fails_to_load() {
    for path in [
        "/v1/keys",
        "/v1/keys/",
        "/v1/keys/k_1/balance",
        "/V1/Keys",
        "/v1/keys?limit=1",
        "/orgs/acme/tokens",
        "/orgs/acme/tokens/t_1",
        // Not normalized: denied wherever the oddity is.
        "/v1/%6beys",
        "/v1/balance/../keys",
        "/v1//keys",
        "/v1/keys;x=1",
        "/v1/keys.",
        "/v1/balance;x",
    ] {
        let url = format!("https://api.example.com{path}");
        assert_eq!(
            fails(&edit(REQUEST_URL, &url)),
            (K::RequestPathDenied, Some(REQUEST_LINE)),
            "{url}"
        );
    }
    // Near misses load.
    for path in [
        "/v1/keysx",
        "/v1/balance/keys",
        "/orgs/acme",
        "",
        "/",
        "?x=/v1/keys",
    ] {
        let url = format!("https://api.example.com{path}");
        assert!(load(&edit(REQUEST_URL, &url)).is_ok(), "{url}");
    }
    // The denied paths are what refuse it: without them the same request
    // loads.
    let f = edit("denied_paths = [\"/v1/keys\", \"/orgs/*/tokens\"]\n", "").replacen(
        REQUEST_URL,
        "https://api.example.com/v1/keys",
        1,
    );
    assert!(load(&f).is_ok());
}

#[test]
fn one_bad_provider_fails_the_whole_registry() {
    let bad = edit(REQUEST_URL, "https://evil.test/v1/balance");
    let mut files: Vec<(&str, &[u8])> = embedded_files()
        .iter()
        .map(|(name, text)| (*name, text.as_bytes()))
        .collect();
    files.push(("example.toml", GOOD.as_bytes()));
    let good = load_from(&files).unwrap();
    assert_eq!(good.providers().len(), embedded_files().len());
    files.pop();
    files.push(("example.toml", bad.as_bytes()));
    let e = load_from(&files).unwrap_err();
    assert_eq!(
        (e.kind(), e.file(), e.line()),
        (K::RequestHostNotAllowed, "example.toml", Some(REQUEST_LINE))
    );
    assert_eq!(
        e.to_string(),
        "providers/example.toml line 18: a request URL's host is not in allowed_hosts"
    );
}

#[test]
fn key_pattern_rules() {
    const KEYS: &str = "['^ex_(?:live|test)_[a-z0-9]{24}$']";
    for (pats, kind) in [
        ("[]", K::NoKeyPatterns),
        ("['^ex_(live|test)_[a-z0-9]{24}$']", K::PatternHasCaptures),
        (
            "['^ex_(?P<mode>live|test)_[a-z0-9]{24}$']",
            K::PatternHasCaptures,
        ),
        ("['ex_(?:live|test)_[a-z0-9]{24}$']", K::PatternNotAnchored),
        ("['^ex_(?:live|test)_[a-z0-9]{24}']", K::PatternNotAnchored),
        (
            "['^ex_live_[a-z0-9]{24}|ex_test_[a-z0-9]{24}$']",
            K::PatternNotAnchored,
        ),
        (
            "['(?m)^ex_(?:live|test)_[a-z0-9]{24}$']",
            K::PatternNotAnchored,
        ),
        ("['^ex_[a-z0-9]{12}$']", K::PatternTooShort),
        ("['^.*$']", K::PatternTooShort),
        ("['^(?s:.){16,}$']", K::PatternNoLiteralPrefix),
        ("['^[A-Za-z0-9_-]{24,}$']", K::PatternNoLiteralPrefix),
        ("['^ex[a-z0-9]{24}$']", K::PatternNoLiteralPrefix),
        (
            "['^ex_(?:live|test)_[a-z0-9]{24}$', '^.{16,}$']",
            K::PatternNoLiteralPrefix,
        ),
        ("['^ex_[a-z0-9{24}$']", K::InvalidPattern),
        ("['^ex_\\p{L}{24}$']", K::InvalidPattern),
        ("[3]", K::WrongType),
        ("'^ex_[a-z0-9]{24}$'", K::WrongType),
    ] {
        assert_eq!(fails(&edit(KEYS, pats)), (kind, Some(3)), "{pats}");
    }
    let long = format!("['^{}$']", "a".repeat(300));
    assert_eq!(fails(&edit(KEYS, &long)), (K::InvalidPattern, Some(3)));
    // The shortest whole value a key pattern may match is 16 bytes.
    assert!(load(&edit(KEYS, "['^ex_[a-z0-9]{13}$']")).is_ok());

    for (line, from) in [(4, "['^ex_live_']"), (5, "['^ex_test_']")] {
        assert_eq!(
            fails(&edit(from, "['ex_']")),
            (K::PatternNotAnchored, Some(line))
        );
        assert_eq!(
            fails(&edit(from, "['^(ex)_']")),
            (K::PatternHasCaptures, Some(line))
        );
        // Live and test patterns are anchored at the start only, and may be
        // short: they are tried only on values a key pattern matched.
        assert!(load(&edit(from, "['^ex_[lt]', '^ex_.*$']")).is_ok());
    }
}

#[test]
fn identity_and_name_rules() {
    assert_eq!(
        fails(&edit("id = \"example\"", "id = \"Example\"")),
        (K::InvalidId, Some(1))
    );
    assert_eq!(
        fails(&edit("id = \"example\"", "id = \"other\"")),
        (K::IdNotFileName, Some(1))
    );
    assert_eq!(
        fails(&edit("id = \"example\"", "id = 7")),
        (K::WrongType, Some(1))
    );
    for bad in ["\"\"", "\"Ex\\u202Eample\"", "\"Ex\\nample\""] {
        let f = edit("name = \"Example\"", &format!("name = {bad}"));
        assert_eq!(fails(&f), (K::InvalidName, Some(2)), "{bad}");
    }
    for line in [
        "id = \"example\"\n",
        "name = \"Example\"\n",
        "key_patterns = ['^ex_(?:live|test)_[a-z0-9]{24}$']\n",
        "allowed_hosts = [\"api.example.com\", \"*.example.net\"]\n",
    ] {
        assert_eq!(fails(&edit(line, "")).0, K::MissingKey, "{line}");
    }
    // Two files with one id.
    let e = load_from(&[
        ("example.toml", GOOD.as_bytes()),
        ("example.toml", GOOD.as_bytes()),
        (SUFFIX_FILE, suffixes().as_bytes()),
    ])
    .unwrap_err();
    assert_eq!(e.kind(), K::DuplicateId);
}

#[test]
fn structure_rules() {
    let top = |extra: &str| format!("{extra}\n{GOOD}");
    assert_eq!(fails(&top("extra = 1")), (K::UnknownKey, Some(1)));
    assert_eq!(fails(&top("[extra]")), (K::UnknownKey, Some(1)));
    let f = edit(
        "dashboard = \"https://example.com/\"",
        "status = \"https://status.example.com/\"",
    );
    assert_eq!(fails(&f), (K::UnknownKey, Some(15)));
    let f = edit(
        "value = \"$.data[0].balance\"",
        "total = \"$.data[0].balance\"",
    );
    assert_eq!(fails(&f), (K::UnknownKey, Some(19)));
    let f = edit(
        "auth = \"bearer\" }",
        "auth = \"bearer\", follow = \"yes\" }",
    );
    assert_eq!(fails(&f), (K::UnknownKey, Some(REQUEST_LINE)));
    // A balance adapter needs a request and a value; a request needs all
    // three keys.
    let f = edit("value = \"$.data[0].balance\"\n", "");
    assert_eq!(fails(&f), (K::MissingKey, Some(17)));
    let f = edit(", auth = \"bearer\"", "");
    assert_eq!(fails(&f), (K::MissingKey, Some(REQUEST_LINE)));

    let f = edit(
        "allowed_hosts = [\"api.example.com\", \"*.example.net\"]",
        "allowed_hosts = \"api.example.com\"",
    );
    assert_eq!(fails(&f), (K::WrongType, Some(7)));
    let links_table = &GOOD[GOOD.find("[links]").unwrap()..GOOD.find("[balance]").unwrap()];
    let f = top("links = 3").replacen(links_table, "", 1);
    assert_eq!(fails(&f), (K::WrongType, Some(1)));
    let f = edit("docs = \"https://docs.example.com/api\"", "docs = 3");
    assert_eq!(fails(&f), (K::WrongType, Some(12)));
    let f = edit("value = \"$.data[0].balance\"", "value = 1");
    assert_eq!(fails(&f), (K::WrongType, Some(19)));

    // TOML errors: syntax and a key defined twice, with their lines.
    let f = edit("name = \"Example\"", "name = \"Example");
    assert_eq!(fails(&f), (K::Syntax, Some(2)));
    let f = edit("name = \"Example\"", "name = \"Example\"\nname = \"Other\"");
    assert_eq!(fails(&f), (K::DuplicateKey, Some(3)));

    // Size and encoding.
    let mut big = GOOD.to_owned();
    big.push_str(&format!("# {}\n", "x".repeat(64 * 1024)));
    assert_eq!(fails(&big), (K::TooLarge, None));
    let mut bytes = GOOD.as_bytes().to_vec();
    bytes.extend_from_slice(b"# \xff\n");
    let e = load_from(&[
        ("example.toml", &bytes),
        (SUFFIX_FILE, suffixes().as_bytes()),
    ])
    .unwrap_err();
    assert_eq!((e.kind(), e.line()), (K::NotUtf8, Some(21)));

    // Lists are bounded.
    let many: Vec<String> = (0..65).map(|i| format!("\"HINT_{i}\"")).collect();
    let f = edit("[\"EXAMPLE_API_KEY\"]", &format!("[{}]", many.join(", ")));
    assert_eq!(fails(&f), (K::TooManyEntries, Some(6)));
}

#[test]
fn hint_host_and_path_rules() {
    for bad in ["example_api_key", "1KEY", "EXAMPLE-KEY", ""] {
        let f = edit("[\"EXAMPLE_API_KEY\"]", &format!("[\"{bad}\"]"));
        assert_eq!(fails(&f), (K::InvalidEnvHint, Some(6)), "{bad}");
    }
    let f = edit(
        "[\"api.example.com\", \"*.example.net\"]",
        "[\"api.example.com\", \"*.example.net\", \"api.example.com\"]",
    );
    assert_eq!(fails(&f), (K::DuplicateHost, Some(7)));
    for bad in [
        "API.example.com",
        "api.example.com.",
        "api.example.com:443",
        "https://api.example.com",
        "api.example.com/v1",
        "localhost",
        "10.0.0.1",
        "",
    ] {
        let f = edit("\"api.example.com\", ", &format!("\"{bad}\", "));
        assert_eq!(fails(&f), (K::InvalidHost, Some(7)), "{bad}");
    }
    for bad in [
        "v1/keys",
        "/v1/keys/",
        "/v1//keys",
        "/v1/../keys",
        "/v1/keys?x=1",
        "/v1/key*",
        "/",
    ] {
        let f = edit("\"/v1/keys\"", &format!("\"{bad}\""));
        assert_eq!(fails(&f), (K::InvalidDeniedPath, Some(9)), "{bad}");
    }
}

#[test]
fn auth_slot_rules() {
    const AUTH: &str = "[{ header = \"authorization\", scheme = \"Bearer\" }, { query = \"key\" }]";
    for (slots, kind) in [
        (
            "[{ header = \"cookie\" }, { query = \"key\" }]",
            K::InvalidAuthSlot,
        ),
        (
            "[{ header = \"host\" }, { query = \"key\" }]",
            K::InvalidAuthSlot,
        ),
        (
            "[{ header = \"authorization\", scheme = \"Basic\" }, { query = \"key\" }]",
            K::InvalidAuthSlot,
        ),
        (
            "[{ basic = \"both\" }, { query = \"key\" }]",
            K::InvalidAuthSlot,
        ),
        (
            "[{ header = \"x-key\", query = \"key\" }]",
            K::InvalidAuthSlot,
        ),
        ("[{ scheme = \"Bearer\" }]", K::InvalidAuthSlot),
        ("[{ header = \"x-key\", where = \"body\" }]", K::UnknownKey),
        ("[\"bearer\"]", K::WrongType),
        (
            "[{ header = \"authorization\", scheme = \"Bearer\" }, { header = \"Authorization\", \
             scheme = \"bearer\" }]",
            K::InvalidAuthSlot,
        ),
        (
            "[{ header = \"authorization\", scheme = \"Bearer\" }, { header = \"authorization\", \
             scheme = \"bearer\" }]",
            K::DuplicateAuthSlot,
        ),
    ] {
        assert_eq!(fails(&edit(AUTH, slots)), (kind, Some(8)), "{slots}");
    }
    // `[[auth]]` tables are not the format.
    let f = edit(&format!("auth = {AUTH}\n"), "").replacen(
        "[links]",
        "[[auth]]\nheader = \"x-key\"\n\n[links]",
        1,
    );
    assert_eq!(fails(&f).0, K::WrongType);

    // A request's key goes only into a declared slot.
    let with = |label: &str| edit("auth = \"bearer\"", &format!("auth = \"{label}\""));
    for label in [
        "basic:user",
        "basic:password",
        "query:token",
        "header:x-api-key",
    ] {
        assert_eq!(
            fails(&with(label)),
            (K::AuthSlotNotDeclared, Some(REQUEST_LINE)),
            "{label}"
        );
    }
    for label in ["cookie:session", "Bearer", "body", ""] {
        assert_eq!(
            fails(&with(label)),
            (K::InvalidAuthSlot, Some(REQUEST_LINE)),
            "{label}"
        );
    }
    for label in ["query:key", "header:authorization"] {
        assert!(load(&with(label)).is_ok(), "{label}");
    }
    // A Basic slot names one part (SPEC §6.2 rule 3): a provider that takes
    // its key as the user name, as Stripe does, declares that part only, and
    // a request cannot put the key in the other.
    let basic_user =
        |label: &str| with(label).replacen(AUTH, "[{ basic = \"user\" }, { query = \"key\" }]", 1);
    let r = load(&basic_user("basic:user")).unwrap();
    let p = r.get("example").unwrap();
    assert_eq!(p.auth_slots[0], AuthSlot::BasicUser);
    assert_eq!(
        p.balance.as_ref().unwrap().request.auth,
        AuthSlot::BasicUser
    );
    assert_eq!(
        fails(&basic_user("basic:password")),
        (K::AuthSlotNotDeclared, Some(REQUEST_LINE))
    );
    let f = edit("method = \"GET\"", "method = \"POST\"");
    assert_eq!(fails(&f), (K::InvalidMethod, Some(REQUEST_LINE)));
    for bad in ["balance", "$", "$..balance", "$.data[01]", "$.data['x']"] {
        let f = edit("\"$.data[0].balance\"", &format!("\"{bad}\""));
        assert_eq!(fails(&f), (K::InvalidJsonPath, Some(19)), "{bad}");
    }
}

#[test]
fn file_set_rules() {
    let good = GOOD.as_bytes();
    let e = load_from(&[("example.toml", good)]).unwrap_err();
    assert_eq!((e.kind(), e.file()), (K::MissingFile, SUFFIX_FILE));
    let e = load_from(&[(SUFFIX_FILE, suffixes().as_bytes())]).unwrap_err();
    assert_eq!(e.kind(), K::MissingFile);
    let e = load_from(&[
        ("example.toml", good),
        ("README.md", b"# providers\n"),
        (SUFFIX_FILE, suffixes().as_bytes()),
    ])
    .unwrap_err();
    assert_eq!((e.kind(), e.file()), (K::UnknownFile, "README.md"));
    for (list, line) in [
        ("vercel.app\n*.netlify.app\n", 2),
        ("# c\nVercel.app\n", 2),
        ("app\n", 1),
        ("vercel.app.\n", 1),
    ] {
        let e = load_from(&[("example.toml", good), (SUFFIX_FILE, list.as_bytes())]).unwrap_err();
        assert_eq!(
            (e.kind(), e.file(), e.line()),
            (K::InvalidSuffix, SUFFIX_FILE, Some(line)),
            "{list}"
        );
    }
}

/// Registry files hold no secrets, but a value pasted into one by mistake
/// must not come back in an error: messages are fixed text.
#[test]
fn errors_never_quote_the_file() {
    let cs: Vec<Canary> = canaries(fresh_seed());
    for c in &cs {
        let v = c.as_str().replace(['\\', '"', '\''], "x");
        for f in [
            edit("name = \"Example\"", &format!("name = \"{v}")),
            edit("name = \"Example\"", &format!("name = {v}")),
            edit("[\"EXAMPLE_API_KEY\"]", &format!("[\"{v}\"]")),
            edit("\"api.example.com\", ", &format!("\"{v}\", ")),
            edit("['^ex_live_']", &format!("['^({v})']")),
            edit(REQUEST_URL, &format!("https://{v}/")),
            edit(REQUEST_URL, &format!("http://api.example.com/{v}")),
            format!("{v} = 1\n{GOOD}"),
        ] {
            let e = load(&f).unwrap_err();
            let shown = format!("{e} {e:?}");
            assert_no_canary(shown.as_bytes(), std::slice::from_ref(c));
        }
    }
}
