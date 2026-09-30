//! The project manifest (SPEC §5 "Project manifest"): its grammar, profile
//! inheritance, the reference forms, names, and the first half of gate 17
//! (`agents = "allow"` fails to parse). `effective.rs` has the rest of gate
//! 17's policy half and `bind.rs` its card half.
#![allow(clippy::unwrap_used)]

use envcloak_policy::{
    AgentsPolicy, Binding, EnvName, Manifest, ManifestErrorKind, Mode, Origin, ProfileName,
    Reference, parse_manifest, resolve,
};
use sha2::{Digest, Sha256};

/// The example from SPEC §5, with `mode = "proxy"`.
const SPEC_EXAMPLE: &str = r#"
[project]
name = "acme-web"

[env]                                  # default profile
OPENAI_API_KEY = "openai/work"         # <slug>[#field]
STRIPE_SECRET_KEY = "stripe/acme-live#secret_key"
DATABASE_URL = { ref = "neon/acme", field = "url" }

[env.production]                       # optional profiles, inherit [env]
STRIPE_SECRET_KEY = "stripe/acme-live"

[policy]                     # can only tighten your vault policy for this project
agents = "approve"           # approve | deny
redact = true                # false is ignored for agent subjects
mode = "proxy"               # proxy | inject; the stricter of manifest and vault wins
"#;

fn env(s: &str) -> EnvName {
    EnvName::new(s).unwrap()
}

fn profile(s: &str) -> ProfileName {
    ProfileName::new(s).unwrap()
}

fn reference(s: &str) -> Reference {
    Reference::parse(s).unwrap()
}

fn binding(name: &str, r: &str) -> Binding {
    Binding {
        env_name: env(name),
        reference: reference(r),
    }
}

fn parse(s: &str) -> Manifest {
    parse_manifest(s.as_bytes()).unwrap()
}

/// The kind and manifest line of the error parsing `s` gives.
fn err(s: &str) -> (ManifestErrorKind, Option<u32>) {
    let e = parse_manifest(s.as_bytes()).unwrap_err();
    let line = match e.origin() {
        Some(Origin::Manifest { line }) => Some(line),
        None => None,
        Some(o) => panic!("unexpected origin {o:?}"),
    };
    (e.kind(), line)
}

#[test]
fn the_spec_example_parses() {
    let m = parse(SPEC_EXAMPLE);
    assert_eq!(m.project_name.as_deref(), Some("acme-web"));
    // Sorted by variable name.
    assert_eq!(
        m.env,
        vec![
            binding("DATABASE_URL", "neon/acme#url"),
            binding("OPENAI_API_KEY", "openai/work"),
            binding("STRIPE_SECRET_KEY", "stripe/acme-live#secret_key"),
        ]
    );
    assert_eq!(m.profiles.len(), 1);
    assert_eq!(
        m.profiles[&profile("production")],
        vec![binding("STRIPE_SECRET_KEY", "stripe/acme-live")]
    );
    assert_eq!(m.policy.agents, AgentsPolicy::Approve);
    assert_eq!(m.policy.redact, Some(true));
    assert_eq!(m.policy.mode, Some(Mode::Proxy));
    assert_eq!(m.sha256, <[u8; 32]>::from(Sha256::digest(SPEC_EXAMPLE)));
}

#[test]
fn an_empty_manifest_binds_nothing_and_sets_no_policy() {
    for s in ["", "# only a comment\n", "[env]\n", "[project]\n[policy]\n"] {
        let m = parse(s);
        assert_eq!(m.project_name, None);
        assert!(m.env.is_empty() && m.profiles.is_empty());
        assert_eq!(m.policy.agents, AgentsPolicy::Approve);
        assert_eq!(m.policy.redact, None);
        assert_eq!(m.policy.mode, None);
    }
}

#[test]
fn gate17_agents_allow_fails_to_parse() {
    let (kind, line) = err("[policy]\nagents = \"allow\"\n");
    assert_eq!(kind, ManifestErrorKind::LoosePolicy);
    assert_eq!(line, Some(2));
    // Any spelling of it, inline or dotted.
    for s in [
        "[policy]\nagents = \"Allow\"",
        "[policy]\nagents = \"ALLOW\"",
        "policy = { agents = \"allow\" }",
        "policy.agents = \"allow\"",
    ] {
        assert_eq!(err(s).0, ManifestErrorKind::LoosePolicy, "{s}");
    }
    // Other loosening shapes are not values the manifest knows.
    for s in [
        "[policy]\nagents = \"auto\"",
        "[policy]\nagents = \"\"",
        "[policy]\nmode = \"passthrough\"",
        "[policy]\nmode = \"Inject\"",
    ] {
        assert_eq!(err(s).0, ManifestErrorKind::InvalidPolicy, "{s}");
    }
    for s in [
        "[policy]\nagents = true",
        "[policy]\nredact = \"false\"",
        "[policy]\nredact = 0",
        "[policy]\nmode = 1",
        "policy = \"allow\"",
    ] {
        assert_eq!(err(s).0, ManifestErrorKind::WrongType, "{s}");
    }
    // Keys that would loosen something are unknown keys.
    for s in [
        "[policy]\nallow = true",
        "[policy]\nstanding = true",
        "[policy]\nredact_agents = false",
        "[policy]\napprove = \"never\"",
    ] {
        assert_eq!(err(s), (ManifestErrorKind::UnknownKey, Some(2)), "{s}");
    }
}

#[test]
fn the_policy_values_the_manifest_may_set() {
    let m = parse("[policy]\nagents = \"deny\"\nredact = false\nmode = \"inject\"\n");
    assert_eq!(m.policy.agents, AgentsPolicy::Deny);
    assert_eq!(m.policy.redact, Some(false));
    assert_eq!(m.policy.mode, Some(Mode::Inject));
}

#[test]
fn unknown_keys_fail_to_parse() {
    for (s, line) in [
        ("foo = 1", 1),
        ("[project]\nname = \"a\"\nowner = \"b\"", 3),
        ("[env]\nA = { ref = \"a/b\", extra = 1 }", 2),
        ("[env]\nA = { ref = \"amex/work\", class = \"card\" }", 2),
        ("[secrets]\nA = \"a/b\"", 1),
    ] {
        assert_eq!(err(s), (ManifestErrorKind::UnknownKey, Some(line)), "{s}");
    }
}

#[test]
fn profiles_inherit_the_default_profile() {
    let m = parse(
        r#"
[env]
A = "a/one"
B = "b/one#key"

[env.production]
B = "b/two"
C = "c/one"

[env.empty]
"#,
    );
    let none = resolve(&m, None, &[], None).unwrap();
    assert_eq!(none, vec![binding("A", "a/one"), binding("B", "b/one#key")]);
    let prod = resolve(&m, Some(&profile("production")), &[], None).unwrap();
    assert_eq!(
        prod,
        vec![
            binding("A", "a/one"),
            binding("B", "b/two"),
            binding("C", "c/one")
        ]
    );
    // A profile without bindings is the default profile.
    assert_eq!(
        resolve(&m, Some(&profile("empty")), &[], None).unwrap(),
        none
    );
    let e = resolve(&m, Some(&profile("staging")), &[], None).unwrap_err();
    assert_eq!(e.kind(), ManifestErrorKind::UnknownProfile);
    assert_eq!(e.origin(), None);
}

#[test]
fn dotted_and_inline_forms_mean_the_same() {
    let long = parse(
        "[env]\nA = \"a/one\"\n[env.production]\nB = \"b/one\"\n[policy]\nmode = \"proxy\"\n",
    );
    for s in [
        "env.A = \"a/one\"\nenv.production.B = \"b/one\"\npolicy.mode = \"proxy\"\n",
        "[env]\nA = \"a/one\"\nproduction.B = \"b/one\"\n[policy]\nmode = \"proxy\"\n",
        "policy = { mode = \"proxy\" }\n[env]\nA = \"a/one\"\n[env.production]\nB = \"b/one\"\n",
    ] {
        let m = parse(s);
        assert_eq!(m.env, long.env, "{s}");
        assert_eq!(m.profiles, long.profiles, "{s}");
        assert_eq!(m.policy, long.policy, "{s}");
    }
    // An inline table cannot be extended by a later header: TOML says so.
    assert_eq!(
        err("env = { A = \"a/one\" }\n[env.production]\nB = \"b/one\"\n").0,
        ManifestErrorKind::Syntax
    );
    // An inline env holds bindings only.
    let m = parse("env = { A = \"a/one\", B = { ref = \"b/one\", field = \"k\" } }\n");
    assert_eq!(m.env, vec![binding("A", "a/one"), binding("B", "b/one#k")]);
}

#[test]
fn inline_tables_are_bindings_and_standard_tables_are_profiles() {
    // Inside an inline `env`, a table is a binding, never a profile.
    let (kind, _) = err("env = { production = { B = \"b/one\" } }");
    assert_eq!(kind, ManifestErrorKind::UnknownKey);
    // A binding written inline under [env] with the reference keys.
    let m = parse("[env]\nref = { ref = \"a/one\" }\n");
    assert_eq!(m.env, vec![binding("ref", "a/one")]);
    assert!(m.profiles.is_empty());
}

#[test]
fn both_reference_forms() {
    let m = parse(
        r#"[env]
PLAIN = "openai/work"
FIELD = "stripe/acme-live#secret_key"
TABLE = { ref = "neon/acme" }
TABLE_FIELD = { ref = "neon/acme", field = "url" }
FIELD_FIRST = { field = "url", ref = "neon/acme" }
"#,
    );
    let got: Vec<(String, String)> = m
        .env
        .iter()
        .map(|b| (b.env_name.to_string(), b.reference.to_string()))
        .collect();
    assert_eq!(
        got,
        [
            ("FIELD", "stripe/acme-live#secret_key"),
            ("FIELD_FIRST", "neon/acme#url"),
            ("PLAIN", "openai/work"),
            ("TABLE", "neon/acme"),
            ("TABLE_FIELD", "neon/acme#url"),
        ]
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
    );
    let r = reference("stripe/acme-live#secret_key");
    assert_eq!(r.slug.as_str(), "stripe/acme-live");
    assert_eq!(r.field.as_ref().unwrap().as_str(), "secret_key");
    assert_eq!(reference("openai/work").field, None);

    for bad in [
        "\"\"",
        "\"Openai/work\"",
        "\"openai/work#\"",
        "\"openai/work#Key\"",
        "\"openai/work#a#b\"",
        "\"#field\"",
        "\"openai work\"",
        "\"envcloak://openai/work\"",
        "{ field = \"url\" }",
        "{ ref = \"neon/acme#url\" }",
        "{ ref = \"neon/acme#url\", field = \"url\" }",
        "{ ref = \"neon/acme\", field = \"\" }",
        "{}",
    ] {
        let s = format!("[env]\nA = {bad}\n");
        assert_eq!(
            err(&s),
            (ManifestErrorKind::InvalidReference, Some(2)),
            "{bad}"
        );
    }
    for bad in [
        "1",
        "true",
        "[\"a/b\"]",
        "{ ref = 1 }",
        "{ ref = \"a/b\", field = 2 }",
        "1979-05-27",
    ] {
        let s = format!("[env]\nA = {bad}\n");
        assert_eq!(err(&s), (ManifestErrorKind::WrongType, Some(2)), "{bad}");
    }
    assert_eq!(err("[[env]]\nA = \"a/b\"").0, ManifestErrorKind::WrongType);
    assert_eq!(err("env = \"a/b\"").0, ManifestErrorKind::WrongType);
}

#[test]
fn duplicate_env_names_fail_to_parse() {
    for (s, line) in [
        ("[env]\nA = \"a/b\"\nA = \"c/d\"\n", 3),
        ("[env]\nA = \"a/b\"\n\"A\" = \"c/d\"\n", 3),
        ("[env]\nA = \"a/b\"\n'A' = { ref = \"c/d\" }\n", 3),
        ("[env.prod]\nA = \"a/b\"\nA = \"a/b\"\n", 3),
        ("[env]\nA = \"a/b\"\n[env]\nB = \"c/d\"\n", 3),
    ] {
        assert_eq!(err(s), (ManifestErrorKind::DuplicateKey, Some(line)), "{s}");
    }
}

#[test]
fn invalid_env_names_fail_to_parse() {
    let long = "A".repeat(EnvName::MAX_LEN + 1);
    for name in [
        "\"\"",
        "1ABC",
        "\"A-B\"",
        "\"A B\"",
        "\"A.B\"",
        "\"\u{c9}T\u{c9}\"",
        "\"A\\u0000\"",
        "\"A=B\"",
        long.as_str(),
    ] {
        let s = format!("[env]\n{name} = \"a/b\"\n");
        assert_eq!(
            err(&s),
            (ManifestErrorKind::InvalidEnvName, Some(2)),
            "{name}"
        );
    }
    let longest = "A".repeat(EnvName::MAX_LEN);
    for ok in ["_", "a", "_1", "Path", "OPENAI_API_KEY", longest.as_str()] {
        let m = parse(&format!("[env]\n{ok} = {{ ref = \"a/b\" }}\n"));
        assert_eq!(m.env[0].env_name.as_str(), ok);
    }
}

#[test]
fn profile_names_and_nesting() {
    for (s, kind) in [
        (
            "[env.Production]\nA = \"a/b\"",
            ManifestErrorKind::InvalidProfileName,
        ),
        (
            "[env.\"pro duction\"]\nA = \"a/b\"",
            ManifestErrorKind::InvalidProfileName,
        ),
        (
            "[env.\"\"]\nA = \"a/b\"",
            ManifestErrorKind::InvalidProfileName,
        ),
        (
            "[env.-prod]\nA = \"a/b\"",
            ManifestErrorKind::InvalidProfileName,
        ),
        (
            "[env.OPENAI]\nKEY = \"a/b\"",
            ManifestErrorKind::InvalidProfileName,
        ),
        (
            "[env.prod.eu]\nA = \"a/b\"",
            ManifestErrorKind::NestedProfile,
        ),
        (
            "[env.prod]\neu.A = \"a/b\"",
            ManifestErrorKind::NestedProfile,
        ),
        ("[[env.prod]]\nA = \"a/b\"", ManifestErrorKind::WrongType),
    ] {
        assert_eq!(err(s).0, kind, "{s}");
    }
    let m = parse("[env.prod-eu_2]\nA = \"a/b\"\n[env.0]\n");
    let names: Vec<&str> = m.profiles.keys().map(ProfileName::as_str).collect();
    assert_eq!(names, ["0", "prod-eu_2"]);
}

#[test]
fn the_project_name_is_display_text() {
    assert_eq!(
        parse("[project]\nname = \"Acme Web \u{e9}\"")
            .project_name
            .as_deref(),
        Some("Acme Web \u{e9}")
    );
    let long = "n".repeat(129);
    for bad in [
        "\"\"",
        "\"a\\u001bb\"",
        "\"a\\rb\"",
        "\"a\\u202eb\"",
        "\"a\\u200bb\"",
        &format!("\"{long}\""),
        // Review T5 open 1: the whole Bidi_Control set, line and paragraph
        // separators, every format character and variation selectors.
        "\"a\\u061cb\"",
        "\"a\\u200eb\"",
        "\"a\\u200fb\"",
        "\"a\\u202ab\"",
        "\"a\\u2066b\"",
        "\"a\\u2069b\"",
        "\"a\\u2028b\"",
        "\"a\\u2029b\"",
        "\"a\\u00adb\"",
        "\"a\\u180eb\"",
        "\"a\\u0600b\"",
        "\"a\\u06ddb\"",
        "\"a\\u070fb\"",
        "\"a\\u08e2b\"",
        "\"a\\u2064b\"",
        "\"a\\ufff9b\"",
        "\"a\\U000110bdb\"",
        "\"a\\U00013430b\"",
        "\"a\\U0001d173b\"",
        "\"a\\U000e0001b\"",
        "\"a\\U000e0041b\"",
        "\"a\\U000e007fb\"",
        "\"a\\u180bb\"",
        "\"a\\ufe00b\"",
        "\"a\\ufe0fb\"",
        "\"a\\U000e0100b\"",
        "\"a\\U000e01efb\"",
    ] {
        let s = format!("[project]\nname = {bad}\n");
        assert_eq!(
            err(&s),
            (ManifestErrorKind::InvalidProjectName, Some(2)),
            "{bad}"
        );
    }
    // Visible text from the same scripts stays a name: Arabic, Mongolian,
    // an emoji with its presentation selector left out, a hyphen.
    for good in [
        "\u{627}\u{644}\u{645}\u{634}\u{631}\u{648}\u{639}",
        "\u{1820}\u{1821}",
        "acme \u{1f680}",
        "acme-web \u{2010} 2",
    ] {
        let s = format!("[project]\nname = \"{good}\"\n");
        assert_eq!(parse(&s).project_name.as_deref(), Some(good), "{good:?}");
    }
    assert_eq!(err("[project]\nname = 1").0, ManifestErrorKind::WrongType);
    assert_eq!(err("project = 1").0, ManifestErrorKind::WrongType);
}

#[test]
fn size_encoding_and_syntax() {
    let mut big = String::from("# padding\n");
    while big.len() <= Manifest::MAX_LEN {
        big.push_str("# more padding to push the manifest over its cap\n");
    }
    assert_eq!(err(&big), (ManifestErrorKind::TooLarge, None));
    let exact = "#".repeat(Manifest::MAX_LEN);
    parse(&exact);

    let e = parse_manifest(b"[env]\nA = \"a/b\"\n# \xff\n").unwrap_err();
    assert_eq!(e.kind(), ManifestErrorKind::NotUtf8);
    assert_eq!(e.origin(), Some(Origin::Manifest { line: 3 }));

    for (s, line) in [
        ("[env\nA = \"a/b\"", 1),
        ("[env]\nA = \"a/b\nB = \"c/d\"", 2),
        ("[env]\n\nA = = \"a/b\"", 3),
    ] {
        assert_eq!(err(s), (ManifestErrorKind::Syntax, Some(line)), "{s}");
    }

    // Nesting as deep as the size cap allows is an error, not a stack
    // overflow: the parser bounds its recursion.
    let n = Manifest::MAX_LEN / 4;
    for deep in [
        format!("[env]\nA = {}{}\n", "[".repeat(n), "]".repeat(n)),
        format!(
            "[env]\nA = {}1{}\n",
            "{ a = ".repeat(n / 2),
            "}".repeat(n / 2)
        ),
        format!("env.{} = \"a/b\"\n", vec!["a"; n].join(".")),
        format!("[env.{}]\n", vec!["a"; n].join(".")),
    ] {
        assert!(deep.len() <= Manifest::MAX_LEN);
        assert_eq!(err(&deep).0, ManifestErrorKind::Syntax);
    }
}

#[test]
fn a_comment_changes_the_hash_and_nothing_else() {
    let a = parse(SPEC_EXAMPLE);
    let edited = format!("# reviewed\n{SPEC_EXAMPLE}\n# end\n");
    let b = parse(&edited);
    assert_ne!(a.sha256, b.sha256);
    assert_eq!(b.sha256, <[u8; 32]>::from(Sha256::digest(&edited)));
    assert_eq!(
        (&a.env, &a.profiles, &a.policy),
        (&b.env, &b.profiles, &b.policy)
    );
    for p in [None, Some(profile("production"))] {
        assert_eq!(
            resolve(&a, p.as_ref(), &[], None).unwrap(),
            resolve(&b, p.as_ref(), &[], None).unwrap()
        );
    }
}

#[test]
fn ref_arguments() {
    let b = Binding::parse_arg("OPENAI_API_KEY=openai/work#api_key").unwrap();
    assert_eq!(b, binding("OPENAI_API_KEY", "openai/work#api_key"));
    assert_eq!(Binding::parse_arg("A=a/b").unwrap(), binding("A", "a/b"));
    for (arg, kind) in [
        ("A", ManifestErrorKind::InvalidReference),
        ("A=", ManifestErrorKind::InvalidReference),
        ("=a/b", ManifestErrorKind::InvalidEnvName),
        ("1A=a/b", ManifestErrorKind::InvalidEnvName),
        ("A B=a/b", ManifestErrorKind::InvalidEnvName),
        ("A=envcloak://a/b", ManifestErrorKind::InvalidReference),
        ("A=a/b#c#d", ManifestErrorKind::InvalidReference),
        ("A= a/b", ManifestErrorKind::InvalidReference),
    ] {
        let e = Binding::parse_arg(arg).unwrap_err();
        assert_eq!(e.kind(), kind, "{arg}");
        assert_eq!(e.origin(), None);
    }
}

#[test]
fn explicit_bindings_replace_the_manifests() {
    let m = parse(SPEC_EXAMPLE);
    let refs = [
        binding("OPENAI_API_KEY", "openai/personal"),
        binding("EXTRA", "extra/one#k"),
    ];
    let got = resolve(&m, None, &refs, None).unwrap();
    assert_eq!(
        got,
        vec![
            binding("DATABASE_URL", "neon/acme#url"),
            binding("EXTRA", "extra/one#k"),
            binding("OPENAI_API_KEY", "openai/personal"),
            binding("STRIPE_SECRET_KEY", "stripe/acme-live#secret_key"),
        ]
    );
    // The profile's override is replaced too.
    let refs = [binding("STRIPE_SECRET_KEY", "stripe/other")];
    let got = resolve(&m, Some(&profile("production")), &refs, None).unwrap();
    assert!(got.contains(&binding("STRIPE_SECRET_KEY", "stripe/other")));
    assert_eq!(got.len(), 3);
}

#[test]
fn a_variable_named_twice_by_ref_is_an_error() {
    let m = parse(SPEC_EXAMPLE);
    let refs = [
        binding("A", "a/one"),
        binding("B", "b/one"),
        binding("A", "a/one"),
    ];
    let e = resolve(&m, None, &refs, None).unwrap_err();
    assert_eq!(e.kind(), ManifestErrorKind::DuplicateEnvName);
    assert_eq!(e.origin(), Some(Origin::Ref { index: 2 }));
}
