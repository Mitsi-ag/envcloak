//! Dotenv parsing for import (SPEC §6.4; T13): `export` prefixes, single,
//! double and backtick quotes, multi-line values, CRLF and `#` comments,
//! `$VAR` and `${VAR}` never expanded, `envcloak://` references, entries
//! taken out of a file by their spans, and errors that carry
//! a line number and a kind only. Every input is hostile: bytes that are
//! not UTF-8, multi-byte characters at every boundary, empty, oversized
//! and control-character values are handled without a panic, and a
//! refusal never echoes the file.
#![allow(clippy::unwrap_used)]

use envcloak_core::SecretBytes;
use envcloak_scan::{
    DotenvEntry, DotenvError, DotenvErrorKind, EntryKind, MAX_DOTENV, parse_dotenv, trimmed_from,
    without_entries,
};
use envcloak_testkit::{assert_no_canary, by_label, canaries, fresh_seed, labels};

fn parse(s: &[u8]) -> Vec<DotenvEntry> {
    parse_dotenv(&SecretBytes::copy_from(s)).unwrap()
}

fn err(s: &[u8]) -> DotenvError {
    parse_dotenv(&SecretBytes::copy_from(s)).unwrap_err()
}

/// Checks each entry's name, value, kind and line.
fn expect(got: &[DotenvEntry], want: &[(&str, &[u8], EntryKind, u32)]) {
    assert_eq!(got.len(), want.len(), "{got:?}");
    for (e, (name, value, kind, line)) in got.iter().zip(want) {
        assert_eq!(e.name.as_str(), *name);
        assert_eq!(&e.kind, kind, "{name}");
        assert_eq!(e.line, *line, "{name}");
        assert!(e.value.ct_eq(value), "{name}: the value differs");
    }
}

const P: EntryKind = EntryKind::Plain;
const T: EntryKind = EntryKind::Template;

#[test]
fn plain_lines_comments_and_export() {
    let got = parse(
        b"# a comment\n\
          \n\
          PORT=8080\n\
          export NODE_ENV=production\n\
          export\tTABBED = value with spaces   \n\
          \t  INDENTED=x\n\
          HASH=a#b # a comment starts at a # after a blank\n\
          EMPTY=\n\
          export=not-a-prefix\n\
          exported=also-a-name\n\
          LEADING_HASH=#kept\n\
          ONLY_COMMENT= # gone\n",
    );
    expect(
        &got,
        &[
            ("PORT", b"8080", P, 3),
            ("NODE_ENV", b"production", P, 4),
            ("TABBED", b"value with spaces", P, 5),
            ("INDENTED", b"x", P, 6),
            ("HASH", b"a#b", P, 7),
            ("EMPTY", b"", P, 8),
            ("export", b"not-a-prefix", P, 9),
            ("exported", b"also-a-name", P, 10),
            ("LEADING_HASH", b"#kept", P, 11),
            ("ONLY_COMMENT", b"", P, 12),
        ],
    );
}

#[test]
fn crlf_and_a_byte_order_mark() {
    let got = parse(b"\xef\xbb\xbfA=1\r\n\r\nB=\"two\"\r\n# c\r\nC='3' # x\r\nD=4");
    expect(
        &got,
        &[
            ("A", b"1", P, 1),
            ("B", b"two", P, 3),
            ("C", b"3", P, 5),
            ("D", b"4", P, 6),
        ],
    );
}

#[test]
fn quotes_single_double_and_backtick() {
    let got = parse(
        b"SINGLE='a \\n b # not a comment'\n\
          DOUBLE=\"tab\\there \\\"q\\\" \\\\ \\' \\x kept\"\n\
          BACKTICK=`it's \"both\" \\n kept`\n\
          AFTER=\"v\"   # comment after the quote\n\
          EMPTY_D=\"\"\n\
          EMPTY_S=''\n\
          EMPTY_B=``\n",
    );
    expect(
        &got,
        &[
            ("SINGLE", b"a \\n b # not a comment", P, 1),
            ("DOUBLE", b"tab\there \"q\" \\ ' \\x kept", P, 2),
            ("BACKTICK", b"it's \"both\" \\n kept", P, 3),
            ("AFTER", b"v", P, 4),
            ("EMPTY_D", b"", P, 5),
            ("EMPTY_S", b"", P, 6),
            ("EMPTY_B", b"", P, 7),
        ],
    );
}

#[test]
fn multi_line_values_in_every_quote() {
    let got = parse(
        b"KEY=\"-----BEGIN KEY-----\nline two\r\nline three\n-----END KEY-----\"\n\
          S='one\ntwo'\n\
          B=`x\r\ny`\n\
          NEXT=after\n",
    );
    expect(
        &got,
        &[
            (
                "KEY",
                b"-----BEGIN KEY-----\nline two\nline three\n-----END KEY-----",
                P,
                1,
            ),
            ("S", b"one\ntwo", P, 5),
            ("B", b"x\ny", P, 7),
            ("NEXT", b"after", P, 9),
        ],
    );
}

#[test]
fn variables_are_never_expanded() {
    let got = parse(
        b"BASE=secret-base\n\
          URL=https://u:${BASE}@host\n\
          QUOTED=\"${BASE}\"\n\
          TICK=`${BASE}`\n\
          LITERAL='${BASE}'\n\
          DOLLAR=pa$$word$BASE\n\
          ESCAPED=\"\\${BASE}\"\n\
          COMMAND=$(cat /tmp/pw)\n\
          POSITIONAL=\"a$1\"\n\
          SINGLE='pa$word'\n\
          PRICE=5$\n\
          SPACED=$ 5\n\
          MARKS=a$-b$@c$$\n",
    );
    expect(
        &got,
        &[
            ("BASE", b"secret-base", P, 1),
            ("URL", b"https://u:${BASE}@host", T, 2),
            ("QUOTED", b"${BASE}", T, 3),
            ("TICK", b"${BASE}", T, 4),
            // Single quotes are literal everywhere: no interpolation.
            ("LITERAL", b"${BASE}", P, 5),
            // `$NAME` without braces interpolates too (dotenv-expand,
            // docker compose, godotenv), and `$(...)` runs a command.
            ("DOLLAR", b"pa$$word$BASE", T, 6),
            ("ESCAPED", b"\\${BASE}", T, 7),
            ("COMMAND", b"$(cat /tmp/pw)", T, 8),
            ("POSITIONAL", b"a$1", T, 9),
            ("SINGLE", b"pa$word", P, 10),
            // A `$` before nothing a tool expands is a character.
            ("PRICE", b"5$", P, 11),
            ("SPACED", b"$ 5", P, 12),
            ("MARKS", b"a$-b$@c$$", P, 13),
        ],
    );
}

#[test]
fn references_are_whole_values() {
    let got = parse(
        b"OPENAI_API_KEY=envcloak://openai/work\n\
          STRIPE=\"envcloak://stripe/acme#secret_key\"\n",
    );
    assert_eq!(got.len(), 2);
    for (e, want) in got.iter().zip(["openai/work", "stripe/acme#secret_key"]) {
        match &e.kind {
            EntryKind::Reference(r) => assert_eq!(r.to_string(), want),
            k => panic!("{k:?}"),
        }
    }
    for bad in [
        &b"A=envcloak://\n"[..],
        b"A=envcloak://Upper/case\n",
        b"A=envcloak://a/b c\n",
        b"A=envcloak://a#\n",
    ] {
        let e = err(bad);
        assert_eq!(e.kind(), DotenvErrorKind::InvalidReference, "{bad:?}");
        assert_eq!(e.line(), 1);
    }
}

#[test]
fn each_error_has_a_kind_and_a_line() {
    for (text, kind, line) in [
        (&b"A=1\nB\n"[..], DotenvErrorKind::MissingEquals, 2),
        (
            b"A=1\n\nno equals here\n",
            DotenvErrorKind::MissingEquals,
            3,
        ),
        (b"1A=x\n", DotenvErrorKind::InvalidName, 1),
        (b"A-B=x\n", DotenvErrorKind::InvalidName, 1),
        (b"A B=x\n", DotenvErrorKind::InvalidName, 1),
        (b"=x\n", DotenvErrorKind::InvalidName, 1),
        (b"A=\"open\n", DotenvErrorKind::UnterminatedQuote, 1),
        (
            b"A=1\nB='open\nmore\n",
            DotenvErrorKind::UnterminatedQuote,
            2,
        ),
        (b"A=`open", DotenvErrorKind::UnterminatedQuote, 1),
        (b"A=\"v\" tail\n", DotenvErrorKind::TrailingCharacters, 1),
        (b"A='v'x\n", DotenvErrorKind::TrailingCharacters, 1),
        (b"A=\"a\nb\" tail\n", DotenvErrorKind::TrailingCharacters, 2),
        (b"A=a\0b\n", DotenvErrorKind::NulByte, 1),
        (b"A=\"a\0b\"\n", DotenvErrorKind::NulByte, 1),
        (b"A=1\nB=2\nA=3\n", DotenvErrorKind::DuplicateName, 3),
        (b"A=1\nexport A=2\n", DotenvErrorKind::DuplicateName, 2),
    ] {
        let e = err(text);
        assert_eq!((e.kind(), e.line()), (kind, line), "{text:?}");
        // The message is fixed text with the line.
        assert_eq!(e.to_string(), format!("line {line}: {}", kind.message()));
    }
}

#[test]
fn a_file_over_the_cap_is_refused_whole() {
    let mut big = b"A=".to_vec();
    big.resize(MAX_DOTENV + 1, b'x');
    let e = err(&big);
    assert_eq!((e.kind(), e.line()), (DotenvErrorKind::TooLarge, 0));
    assert_eq!(e.to_string(), DotenvErrorKind::TooLarge.message());
    // At the cap it parses.
    big.truncate(MAX_DOTENV);
    assert_eq!(parse(&big).len(), 1);
}

#[test]
fn errors_never_hold_text_from_the_file() {
    let cs = canaries(fresh_seed());
    let key = by_label(&cs, labels::OPENAI_API_KEY).as_str();
    let url = by_label(&cs, labels::DATABASE_URL).as_str();
    for text in [
        format!("{key}\n"),
        format!("A={key}\n{key}\n"),
        format!("{key}=x\n"),
        format!("A=\"{url}\" {key}\n"),
        format!("A=\"{url}\n"),
        format!("A={key}\nA={key}\n"),
        format!("A=envcloak://{key}\n"),
        format!("A={key}\0\n"),
    ] {
        let e = err(text.as_bytes());
        let shown = format!("{e} {e:?} {:?} {}", e.kind(), e.kind().message());
        assert_no_canary(shown.as_bytes(), &cs);
    }
    // Nor does a parsed entry's Debug show its value.
    let dq = url.replace('\\', "\\\\").replace('"', "\\\"");
    let entries = parse(format!("A={key}\nB=\"{dq}\"\n").as_bytes());
    assert!(entries[1].value.ct_eq(url.as_bytes()));
    assert_no_canary(format!("{entries:?}").as_bytes(), &cs);
}

#[test]
fn bytes_that_are_not_utf8_and_multibyte_characters() {
    // Values are bytes: invalid UTF-8 is kept as it is.
    let got = parse(b"A=\xff\xfe\x80\nB=\"\xc3\xa9\"\nC='\xe2\x82\xac'\nD=`\xf0\x9f\x94\x91`\n");
    expect(
        &got,
        &[
            ("A", b"\xff\xfe\x80", P, 1),
            ("B", b"\xc3\xa9", P, 2),
            ("C", b"\xe2\x82\xac", P, 3),
            ("D", b"\xf0\x9f\x94\x91", P, 4),
        ],
    );
    // A multi-byte character next to every token the parser looks for.
    let e = "\u{e9}";
    let got = parse(
        format!("A={e}\nB={e} #{e}\nC=\"{e}\"\nD='{e}'#{e}\nE={e}#{e}\nF=\"{e}\\n{e}\"\nG= {e} \n")
            .as_bytes(),
    );
    let values: Vec<String> = [e, e, e, e, &format!("{e}#{e}"), &format!("{e}\n{e}"), e]
        .map(str::to_owned)
        .into();
    assert_eq!(got.len(), values.len());
    for (g, v) in got.iter().zip(&values) {
        assert!(g.value.ct_eq(v.as_bytes()), "{}", g.name.as_str());
    }
    // A name is ASCII: a multi-byte character or a stray byte in it fails
    // as a name, wherever it is.
    for bad in [
        &b"\xc3\xa9=1\n"[..],
        b"A\xc3\xa9=1\n",
        b"\xffA=1\n",
        b"A\x80=1\n",
    ] {
        assert_eq!(err(bad).kind(), DotenvErrorKind::InvalidName, "{bad:?}");
    }
    // A quote that is cut off inside a multi-byte character is unterminated.
    assert_eq!(err(b"A=\"\xc3").kind(), DotenvErrorKind::UnterminatedQuote);
}

#[test]
fn control_characters_stay_in_values() {
    let got = parse(b"A=a\x1b[31mb\x07\nB=\"\x7f\"\nC=\x01\n");
    expect(
        &got,
        &[
            ("A", b"a\x1b[31mb\x07", P, 1),
            ("B", b"\x7f", P, 2),
            ("C", b"\x01", P, 3),
        ],
    );
    // A lone carriage return ends nothing and is kept.
    let got = parse(b"A=x\ry\n");
    expect(&got, &[("A", b"x\ry", P, 1)]);
}

#[test]
fn values_are_exact_size() {
    let got = parse(b"A=\"escaped\\n\\t\"\nB=  spaced  \n");
    assert_eq!(got[0].value.len(), 9);
    assert_eq!(got[1].value.len(), 6);
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(2000))]

    /// Any bytes at all parse or fail with a kind and a line in range;
    /// nothing panics.
    #[test]
    fn arbitrary_bytes_never_panic(b in proptest::collection::vec(proptest::num::u8::ANY, 0..512)) {
        let lines = u32::try_from(b.iter().filter(|&&c| c == b'\n').count() + 1).unwrap();
        match parse_dotenv(&SecretBytes::copy_from(&b)) {
            Ok(entries) => {
                for e in entries {
                    proptest::prop_assert!(e.line >= 1 && e.line <= lines);
                }
            }
            Err(e) => proptest::prop_assert!(e.line() <= lines),
        }
    }

    /// Lines built from the grammar's own pieces parse or fail cleanly.
    #[test]
    fn grammar_pieces_never_panic(
        pieces in proptest::collection::vec(
            proptest::sample::select(vec![
                "A", "export ", "=", "\"", "'", "`", "\\", "#", " ", "\n", "\r\n", "\r",
                "${X}", "envcloak://a/b", "\u{e9}", "\u{1f511}", "\0", "\u{feff}",
            ]),
            0..64,
        )
    ) {
        let text: String = pieces.concat();
        let _ = parse_dotenv(&SecretBytes::copy_from(text.as_bytes()));
    }
}

/// Each entry's span is its whole lines, the line ending included, from
/// the start of its first line: leading blanks, `export`, a comment after
/// the value, a quoted value over several lines, CRLF, and a byte-order
/// mark kept out of the first entry's span.
#[test]
fn spans_are_whole_lines() {
    let text = b"\xef\xbb\xbfA=1\r\n# note\n  export B = \"x\ny\" # c\n\nC=3";
    let got = parse(text);
    let spans: Vec<&[u8]> = got.iter().map(|e| &text[e.span.clone()]).collect();
    assert_eq!(
        spans,
        [&b"A=1\r\n"[..], b"  export B = \"x\ny\" # c\n", b"C=3",]
    );
}

/// Entries leave a file whole by their spans; every other byte stays as
/// it was. `trimmed_from` recognises exactly such a file.
#[test]
fn entries_leave_a_file_whole_and_a_trimmed_file_is_recognised() {
    let text = b"# acme\nKEY=k1\nPORT=8080\n\nexport TOKEN=\"t\n2\"\nURL=${HOST}/x\n";
    let file = SecretBytes::copy_from(text);
    let got = parse(text);
    let spans = |names: &[&str]| -> Vec<std::ops::Range<usize>> {
        got.iter()
            .filter(|e| names.contains(&e.name.as_str()))
            .map(|e| e.span.clone())
            .collect()
    };
    let left = without_entries(&file, &spans(&["KEY", "TOKEN"]));
    assert!(left.ct_eq(b"# acme\nPORT=8080\n\nURL=${HOST}/x\n"));
    assert!(trimmed_from(&file, &left));
    // Every entry out: the comment and the blank line stay.
    let none = without_entries(&file, &spans(&["KEY", "PORT", "TOKEN", "URL"]));
    assert!(none.ct_eq(b"# acme\n\n"));
    assert!(trimmed_from(&file, &none));
    // Nothing taken out, or anything else changed, is not a trimmed file.
    assert!(!trimmed_from(&file, &file));
    for other in [
        &b"# acme\nPORT=8081\n\nURL=${HOST}/x\n"[..],
        b"# acme\nPORT=8080\n\nURL=${HOST}/x\nNEW=1\n",
        b"PORT=8080\n\nURL=${HOST}/x\n",
        b"# acme\nPORT=8080\n\nURL=${HOST}/x",
        b"not a dotenv file\n",
    ] {
        assert!(
            !trimmed_from(&file, &SecretBytes::copy_from(other)),
            "{}",
            String::from_utf8_lossy(other)
        );
    }
    // Spans out of range are ignored.
    #[allow(clippy::reversed_empty_ranges)]
    let odd = without_entries(&file, &[3..1, 0..(text.len() + 1)]);
    assert!(odd.ct_eq(text));
}
