//! `--env-file` parsing (SPEC §6.1): `envcloak://<slug>[#field]` references
//! become bindings, every other line an ordinary variable kept in
//! `SecretBytes`, and errors carry a line number and a kind only.
#![allow(clippy::unwrap_used)]

use envcloak_core::SecretBytes;
use envcloak_policy::{
    Binding, EnvFileErrorKind, EnvFileRefs, EnvName, ManifestErrorKind, Origin, Reference,
    parse_env_file_refs, parse_manifest, resolve,
};
use envcloak_testkit::{Canary, assert_no_canary, by_label, canaries, fresh_seed, labels};

fn parse(s: &[u8]) -> EnvFileRefs {
    parse_env_file_refs(&SecretBytes::copy_from(s)).unwrap()
}

fn err(s: &[u8]) -> (EnvFileErrorKind, u32) {
    let e = parse_env_file_refs(&SecretBytes::copy_from(s)).unwrap_err();
    (e.kind(), e.line())
}

/// The plain variables as (name, line), checking each value.
fn plain(r: &EnvFileRefs, want: &[(&str, &[u8], u32)]) {
    assert_eq!(r.plain.len(), want.len(), "{:?}", r.plain);
    for (p, (name, value, line)) in r.plain.iter().zip(want) {
        assert_eq!(p.name.as_str(), *name);
        assert_eq!(p.line, *line, "{name}");
        assert!(p.value.ct_eq(value), "{name}: value differs");
    }
}

fn refs(r: &EnvFileRefs) -> Vec<(String, String, u32)> {
    r.refs
        .iter()
        .map(|e| {
            (
                e.binding.env_name.to_string(),
                e.binding.reference.to_string(),
                e.line,
            )
        })
        .collect()
}

#[test]
fn references_and_plain_variables() {
    let r = parse(
        b"# a comment\n\
          \n\
          OPENAI_API_KEY=envcloak://openai/work\n\
          export STRIPE_SECRET_KEY = envcloak://stripe/acme#secret_key   # trailing comment\n\
          DATABASE_URL=\"envcloak://neon/acme#url\"\n\
          GITHUB_TOKEN='envcloak://github/me'\n\
          PORT=8080\n\
          \tINDENTED = value with spaces   \n\
          HASH=a#b # the first # after a blank starts a comment\n\
          EMPTY=\n\
          EMPTY_QUOTED=\"\"\n",
    );
    assert_eq!(
        refs(&r),
        [
            ("OPENAI_API_KEY", "openai/work", 3),
            ("STRIPE_SECRET_KEY", "stripe/acme#secret_key", 4),
            ("DATABASE_URL", "neon/acme#url", 5),
            ("GITHUB_TOKEN", "github/me", 6),
        ]
        .map(|(a, b, l)| (a.to_owned(), b.to_owned(), l))
    );
    plain(
        &r,
        &[
            ("PORT", b"8080", 7),
            ("INDENTED", b"value with spaces", 8),
            ("HASH", b"a#b", 9),
            ("EMPTY", b"", 10),
            ("EMPTY_QUOTED", b"", 11),
        ],
    );
    // The reference is the whole value, not a prefix of it.
    let r = parse(b"A=xenvcloak://a/b\nB=envcloak:/a/b\nC=ENVCLOAK://a/b\n");
    assert!(r.refs.is_empty());
    assert_eq!(r.plain.len(), 3);
}

#[test]
fn quoting_escapes_and_line_endings() {
    // Adjacent quoted strings are not concatenated, as a shell would.
    let e = err(b"SINGLE='a''b'\n");
    assert_eq!(e, (EnvFileErrorKind::TrailingCharacters, 1));

    let r = parse(
        b"SQ='a \\n $HOME \"x\" # not a comment'\n\
          DQ=\"tab\\there\\nnew \\\"q\\\" \\\\ \\' \\$ \\x\"\n\
          CRLF=value\r\n\
          MULTI=\"line one\r\nline two\n\"\n\
          AFTER='x' # comment\n\
          SQ_MULTI='a\nb'\n\
          LAST=end",
    );
    plain(
        &r,
        &[
            ("SQ", b"a \\n $HOME \"x\" # not a comment", 1),
            ("DQ", b"tab\there\nnew \"q\" \\ ' \\$ \\x", 2),
            ("CRLF", b"value", 3),
            ("MULTI", b"line one\nline two\n", 4),
            ("AFTER", b"x", 7),
            ("SQ_MULTI", b"a\nb", 8),
            ("LAST", b"end", 10),
        ],
    );
    // A byte-order mark before the first line is skipped.
    let r = parse(b"\xef\xbb\xbfA=1\n");
    plain(&r, &[("A", b"1", 1)]);
    // Values are bytes, not text.
    let r = parse(b"BIN=\xff\xfe\x80\n");
    plain(&r, &[("BIN", b"\xff\xfe\x80", 1)]);
}

#[test]
fn errors_carry_a_line_and_a_kind() {
    for (s, kind, line) in [
        (&b"A=1\nB\n"[..], EnvFileErrorKind::MissingEquals, 2),
        (b"A=1\nexport B\n", EnvFileErrorKind::MissingEquals, 2),
        (b"=1\n", EnvFileErrorKind::InvalidName, 1),
        (b"1A=1\n", EnvFileErrorKind::InvalidName, 1),
        (b"A-B=1\n", EnvFileErrorKind::InvalidName, 1),
        (b"A B=1\n", EnvFileErrorKind::InvalidName, 1),
        (b"\n\nA.B = 1\n", EnvFileErrorKind::InvalidName, 3),
        (
            b"A=1\nB=\"open\n\nC=2\n",
            EnvFileErrorKind::UnterminatedQuote,
            2,
        ),
        (b"B='open", EnvFileErrorKind::UnterminatedQuote, 1),
        (b"B=\"a\\\"", EnvFileErrorKind::UnterminatedQuote, 1),
        (b"A=\"x\" y\n", EnvFileErrorKind::TrailingCharacters, 1),
        (b"A=\"x\"y\n", EnvFileErrorKind::TrailingCharacters, 1),
        (b"A=\"x\ny\" z\n", EnvFileErrorKind::TrailingCharacters, 2),
        (b"A=a\x00b\n", EnvFileErrorKind::NulByte, 1),
        (b"A=\"a\x00b\"\n", EnvFileErrorKind::NulByte, 1),
        (b"A=envcloak://\n", EnvFileErrorKind::InvalidReference, 1),
        (
            b"A=envcloak://Openai/work\n",
            EnvFileErrorKind::InvalidReference,
            1,
        ),
        (
            b"A=envcloak://a/b#\n",
            EnvFileErrorKind::InvalidReference,
            1,
        ),
        (
            b"A=envcloak://a/b#c#d\n",
            EnvFileErrorKind::InvalidReference,
            1,
        ),
        (
            b"A='envcloak://a/b '\n",
            EnvFileErrorKind::InvalidReference,
            1,
        ),
        (b"A=1\nB=2\nA=3\n", EnvFileErrorKind::DuplicateName, 3),
        (
            b"A=envcloak://a/b\nexport A=x\n",
            EnvFileErrorKind::DuplicateName,
            2,
        ),
    ] {
        assert_eq!(err(s), (kind, line), "{}", String::from_utf8_lossy(s));
    }
    let long = format!("{}=1\n", "A".repeat(EnvName::MAX_LEN + 1));
    assert_eq!(err(long.as_bytes()), (EnvFileErrorKind::InvalidName, 1));
}

#[test]
fn the_size_cap() {
    let mut big = Vec::with_capacity(envcloak_policy::MAX_ENV_FILE + 16);
    while big.len() <= envcloak_policy::MAX_ENV_FILE {
        big.extend_from_slice(b"# padding line for the size cap\n");
    }
    let e = parse_env_file_refs(&SecretBytes::copy_from(&big)).unwrap_err();
    assert_eq!(e.kind(), EnvFileErrorKind::TooLarge);
    assert_eq!(e.line(), 0);
    big.truncate(envcloak_policy::MAX_ENV_FILE);
    parse(&big);
}

/// Every malformed shape with a fixture value in it, parsed as an env file,
/// as a manifest and as a `--ref`: the errors' text names a line and a kind,
/// never the value. (A shape a canary happens to fit, such as a short
/// alphanumeric token as a variable name, parses and is skipped.)
#[test]
fn errors_never_carry_a_value() {
    let cs = canaries(fresh_seed());
    let mut texts = Vec::new();
    let mut note = |r: Result<(), String>| {
        if let Err(t) = r {
            texts.push(t);
        }
    };
    for c in &cs {
        let v = c.as_str();
        let env_files = [
            format!("{v}\n"),
            format!("A={v}\nB\n"),
            format!("A=\"{v}\n"),
            format!("A='{v}"),
            format!("A=\"{v}\" {v}\n"),
            format!("A={v}\x00\n"),
            format!("A=envcloak://{v}\n"),
            format!("A='envcloak://{v}'\n"),
            format!("A={v}\nA={v}\n"),
            format!("{v}={v}\n"),
            format!("export {v}\n"),
        ];
        for f in env_files {
            note(
                parse_env_file_refs(&SecretBytes::copy_from(f.as_bytes()))
                    .map(drop)
                    .map_err(|e| format!("{e} {e:?}")),
            );
        }
        let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
        let manifests = [
            format!("[env]\nA = \"{escaped}\"\n"),
            format!("[env]\nA = {{ ref = \"{escaped}\" }}\n"),
            format!("[env]\nA = {{ ref = \"a/b\", field = \"{escaped}\" }}\n"),
            format!("[env]\n\"{escaped}\" = \"a/b\"\n"),
            format!("[env.\"{escaped}\"]\nA = \"a/b\"\n"),
            format!("[project]\nname = \"{escaped}\\u0007\"\n"),
            format!("[policy]\nagents = \"{escaped}\"\n"),
            format!("[policy]\n\"{escaped}\" = true\n"),
            format!("[env]\nA = {v}\n"),
            format!("[env]\nA = \"a/b\" {v}\n"),
            format!("{v}\n"),
        ];
        for m in manifests {
            note(
                parse_manifest(m.as_bytes())
                    .map(drop)
                    .map_err(|e| format!("{e} {e:?}")),
            );
        }
        for arg in [format!("A={v}"), format!("{v}=a/b"), v.to_owned()] {
            note(
                Binding::parse_arg(&arg)
                    .map(drop)
                    .map_err(|e| format!("{e} {e:?}")),
            );
        }
    }
    // Nearly every shape fails for nearly every canary.
    assert!(texts.len() > 17 * cs.len(), "{} errors", texts.len());
    for t in &texts {
        assert_no_canary(t.as_bytes(), &cs);
    }
    // Debug of a parsed file shows no value either.
    let c: &Canary = by_label(&cs, labels::DATABASE_URL);
    let file = format!("A='{}'\n", c.as_str().replace('\'', ""));
    let r = parse(file.as_bytes());
    assert_no_canary(format!("{r:?}").as_bytes(), &cs);
    // Nor do the names the daemon is sent.
    let names = r.names();
    assert_eq!(names.plain.len(), 1);
    assert_eq!(names.plain[0].name.as_str(), "A");
    assert_no_canary(format!("{names:?}").as_bytes(), &cs);
}

#[test]
fn env_file_entries_join_the_resolution() {
    let m = parse_manifest(b"[env]\nA = \"a/one\"\nB = \"b/one\"\nC = \"c/one\"\n").unwrap();
    let file = parse(b"B=envcloak://b/two#k\nC=plain value\nD=envcloak://d/one\n");
    let names = file.names();
    let got = resolve(&m, None, &[], Some(&names)).unwrap();
    let want: Vec<Binding> = [("A", "a/one"), ("B", "b/two#k"), ("D", "d/one")]
        .iter()
        .map(|(n, r)| Binding {
            env_name: EnvName::new(n).unwrap(),
            reference: Reference::parse(r).unwrap(),
        })
        .collect();
    // C is set from the file, so the manifest's binding of it is dropped.
    assert_eq!(got, want);

    // `--ref` and `--env-file` may not both name a variable.
    for name in ["B", "C"] {
        let refs = [Binding::parse_arg(&format!("{name}=x/y")).unwrap()];
        let e = resolve(&m, None, &refs, Some(&names)).unwrap_err();
        assert_eq!(e.kind(), ManifestErrorKind::DuplicateEnvName, "{name}");
        assert_eq!(e.origin(), Some(Origin::Ref { index: 0 }));
    }
}
