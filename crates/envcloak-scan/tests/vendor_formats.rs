//! M2-23 fixtures: documented format, not tool output.
#![allow(clippy::unwrap_used)]
use envcloak_scan::formats::{self, Entry, FormatError, Kind};
use envcloak_testkit::{assert_no_canary, canaries};
use serde_json::json;
use std::io::{self, Read};

struct Chunks<'a> {
    bytes: &'a [u8],
    size: usize,
}
impl Read for Chunks<'_> {
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let n = into.len().min(self.size).min(self.bytes.len());
        into[..n].copy_from_slice(&self.bytes[..n]);
        self.bytes = &self.bytes[n..];
        Ok(n)
    }
}
fn parse(
    kind: Kind,
    bytes: &[u8],
    size: usize,
) -> (Result<formats::FormatReport, FormatError>, Vec<Entry>) {
    let mut entries = Vec::new();
    let result = formats::parse(kind, Chunks { bytes, size }, &mut |e| entries.push(e));
    (result, entries)
}
fn infisical(value: &str) -> serde_json::Value {
    json!({"key":"SERVICE_TOKEN","value":value,"workspace":"","type":"shared","_id":"","secretPath":"/","tags":null,"comment":"","Etag":"","skipMultilineEncoding":false})
}
#[test]
fn documented_json_selects_exact_current_values_and_keeps_repeated_labels() {
    let value = ["private", "with space\r\n雪\\n\""].join("_");
    for (kind, bytes, names) in [
        (Kind::DopplerJson, serde_json::to_vec(&json!({"SERVICE_TOKEN":value})).unwrap(), vec!["SERVICE_TOKEN"]),
        (Kind::InfisicalJson, serde_json::to_vec(&json!([infisical(&value),infisical(&value)])).unwrap(), vec!["SERVICE_TOKEN","SERVICE_TOKEN"]),
        (Kind::BitwardenJson, serde_json::to_vec(&json!({"folders":[],"collections":[],"items":[{"type":1,"name":"fixture","login":{"password":value},"passwordHistory":[{"password":"old"}],"fields":[{"name":"SERVICE_TOKEN","type":1,"value":value}]}],"encrypted":false})).unwrap(), vec!["PASSWORD","SERVICE_TOKEN"]),
    ] {
        for size in [1,2,7,4096] {
            let (r, entries) = parse(kind, &bytes, size);
            assert!(r.is_ok());
            assert_eq!(entries.len(), names.len());
            for (entry, name) in entries.iter().zip(&names) {
                assert!(entry.name.ct_eq(name.as_bytes()));
                assert!(entry.value.ct_eq(value.as_bytes()));
            }
        }
    }
}
#[test]
fn unknown_shapes_duplicates_and_late_errors_publish_nothing() {
    for (kind, bad) in [
        (Kind::DopplerJson, b"[]".as_slice()),
        (Kind::DopplerJson, b"{\"A\":{\"value\":\"x\"}}"),
        (Kind::DopplerJson, b"{\"A\":\"x\",\"\\u0041\":\"y\"}"),
        (Kind::DopplerJson, b"{\"A\":\"x\"} trailing"),
        (Kind::InfisicalJson, b"{\"secrets\":[]}"),
        (Kind::InfisicalJson, b"[{\"key\":\"A\",\"value\":\"x\"}]"),
        (Kind::BitwardenJson, b"{\"items\":[{\"type\":1,\"name\":\"x\",\"login\":{\"password\":\"x\"}}],\"encrypted\":true}"),
        (Kind::BitwardenJson, b"{\"items\":[],\"encrypted\":0}"),
        (Kind::BitwardenJson, b"{\"projects\":[],\"secrets\":[]}"),
        (Kind::BitwardenJson, b"{\"items\":[],\"future\":[]}"),
        (Kind::BitwardenJson, b"{\"items\":[{\"type\":true,\"name\":\"x\",\"login\":{}}]}"),
    ] {
        let (r,e) = parse(kind,bad,1);
        assert!(r.is_err(), "unknown or ambiguous shape accepted");
        assert!(e.is_empty(), "failed parse published a prefix");
    }
}
#[test]
fn bitwarden_reports_unsupported_fields_without_history_fallback() {
    let bytes = serde_json::to_vec(&json!({"items":[
        {"type":1,"name":"x","login":{"password":null,"totp":"otp"},"passwordHistory":[{"password":"old"}],"fields":[{"name":"human label","type":1,"value":"private"},{"name":"SERVICE_TOKEN","type":3,"value":"linked"}]},
        {"type":2,"name":"x","secureNote":{"type":0},"fields":[{"name":"SERVICE_TOKEN","type":0,"value":"current"}]}
    ]})).unwrap();
    let (r, e) = parse(Kind::BitwardenJson, &bytes, 7);
    let r = r.unwrap();
    assert_eq!(e.len(), 1);
    assert!(e[0].value.ct_eq(b"current"));
    assert!(r.unsupported > 0 && r.manual > 0);
}
#[test]
fn infisical_metadata_is_typed_and_never_a_credential() {
    for member in [
        "workspace",
        "type",
        "_id",
        "secretPath",
        "comment",
        "Etag",
        "tags",
        "skipMultilineEncoding",
    ] {
        for replacement in [None, Some(json!(17)), Some(json!({"value":"private"}))] {
            let mut row = infisical("current");
            match replacement {
                Some(v) => {
                    row[member] = v;
                }
                None => {
                    row.as_object_mut().unwrap().remove(member);
                }
            }
            let bytes = serde_json::to_vec(&json!([infisical("positive"), row])).unwrap();
            let (r, e) = parse(Kind::InfisicalJson, &bytes, 2);
            assert!(r.is_err());
            assert!(e.is_empty());
        }
    }
}
const HEADER: &str = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\r\n";
#[test]
fn hostile_csv_preserves_quotes_bom_crlf_and_embedded_newlines() {
    let value = "  雪\r\nline\n\\\"tail  ";
    let wire = format!(
        "\u{feff}{HEADER}title,url,user,\"{}\",,false,false,,note\r\n",
        value.replace('"', "\"\"")
    );
    for size in [1, 2, 7, 4096] {
        let (r, e) = parse(Kind::OnePasswordCsv, wire.as_bytes(), size);
        assert!(r.is_ok());
        assert_eq!(e.len(), 1);
        assert!(e[0].value.ct_eq(value.as_bytes()));
    }
    for tail in [
        "a,b,c,\"unterminated",
        "a,b,c,bad\"quote,,,,,",
        "a,b,c,\"x\"tail,,,,,",
        "a,b,c,x,,,,,\r",
        "a,b,c,x,,,,",
        "a,b,c,\0,,,,,",
    ] {
        let bad = format!("{HEADER}a,b,c,positive,,,,,\n{tail}");
        let (r, e) = parse(Kind::OnePasswordCsv, bad.as_bytes(), 1);
        assert!(r.is_err());
        assert!(e.is_empty());
    }
    let bad = HEADER.replacen("Title", "title", 1);
    assert!(parse(Kind::OnePasswordCsv, bad.as_bytes(), 1).0.is_err());
}
#[test]
fn caps_refuse_before_reading_a_ten_megabyte_field() {
    struct Huge {
        read: usize,
    }
    impl Read for Huge {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            let n = b.len().min((10 << 20) - self.read);
            b[..n].fill(b'x');
            self.read += n;
            Ok(n)
        }
    }
    let mut huge = Huge { read: 0 };
    let prefix = format!("{HEADER}a,b,c,\"");
    let (r, e) = {
        let mut e = Vec::new();
        let r = formats::parse(
            Kind::OnePasswordCsv,
            prefix.as_bytes().chain(&mut huge),
            &mut |v| e.push(v),
        );
        (r, e)
    };
    assert_eq!(r.unwrap_err(), FormatError::Limit);
    assert!(e.is_empty());
    assert!(huge.read < 100_000);
    let values = vec![infisical(&"x".repeat(65537))];
    assert!(
        parse(
            Kind::InfisicalJson,
            &serde_json::to_vec(&values).unwrap(),
            7
        )
        .0
        .is_err()
    );
}
#[test]
fn failures_and_debug_never_echo_rows_or_io_errors() {
    let values = canaries(23);
    if std::env::var_os("ENVCLOAK_VENDOR_DIAGNOSTIC_CHILD").is_none() {
        let home = tempfile::tempdir_in("/tmp").unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "failures_and_debug_never_echo_rows_or_io_errors",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path())
            .env("XDG_DATA_HOME", home.path())
            .env("XDG_RUNTIME_DIR", home.path())
            .env("ENVCLOAK_VENDOR_DIAGNOSTIC_CHILD", "1")
            .output()
            .unwrap();
        assert_no_canary(&output.stdout, &values);
        assert_no_canary(&output.stderr, &values);
        assert!(output.status.success());
        return;
    }
    let needle = values[0].as_str();
    assert!(!envcloak_testkit::find(needle.as_bytes(), &values).is_empty());
    for kind in Kind::ALL {
        let wire = match kind {
            Kind::DopplerJson => format!("{{\"SERVICE_TOKEN\":{needle}}}"),
            Kind::InfisicalJson => format!("[{needle}]"),
            Kind::BitwardenJson => format!("{{\"items\":[{needle}]}}"),
            _ => format!("{needle} invalid"),
        };
        let (r, e) = parse(kind, wire.as_bytes(), 7);
        assert!(r.is_err());
        assert_no_canary(format!("{r:?}{e:?}").as_bytes(), &values);
        struct Bad(String);
        impl Read for Bad {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other(self.0.clone()))
            }
        }
        let r = formats::parse(kind, Bad(needle.into()), &mut |_| {
            panic!("error emitted entry")
        });
        assert!(r.is_err());
        assert_no_canary(format!("{r:?}").as_bytes(), &values);
    }
}

#[test]
fn production_budgets_count_metadata_rows_and_all_selected_values() {
    let prefix = serde_json::to_vec(&infisical("positive")).unwrap();
    let count = formats::MAX_ENTRIES + 1;
    let mut bytes = Vec::new();
    bytes.push(b'[');
    for i in 0..count {
        if i > 0 {
            bytes.push(b',');
        }
        bytes.extend_from_slice(&prefix);
    }
    bytes.push(b']');
    assert_eq!(
        parse(Kind::InfisicalJson, &bytes, 4096).0.unwrap_err(),
        FormatError::Limit
    );
    let row = infisical(&"x".repeat(formats::MAX_FIELD));
    let bytes = serde_json::to_vec(&vec![row; 5]).unwrap();
    let (r, e) = parse(Kind::InfisicalJson, &bytes, 4096);
    assert_eq!(r.unwrap_err(), FormatError::Limit);
    assert!(e.is_empty());
    let input = format!(
        "{HEADER}{}",
        "a,b,c,,,,,,\r\n".repeat(formats::MAX_RECORDS + 1)
    );
    assert!(
        parse(Kind::OnePasswordCsv, input.as_bytes(), 4096)
            .0
            .is_err()
    );
    let mut row = infisical("positive");
    row["comment"] = json!("x".repeat(formats::MAX_FIELD + 1));
    assert_eq!(
        parse(
            Kind::InfisicalJson,
            &serde_json::to_vec(&json!([row])).unwrap(),
            4096
        )
        .0
        .unwrap_err(),
        FormatError::Limit
    );
    let bytes = format!("{{\"A\":{}}}", "[".repeat(65) + &"]".repeat(65));
    assert!(parse(Kind::DopplerJson, bytes.as_bytes(), 1).0.is_err());
    for kind in [
        Kind::DopplerJson,
        Kind::InfisicalJson,
        Kind::BitwardenJson,
        Kind::OnePasswordCsv,
    ] {
        assert!(parse(kind, b"", 1).0.is_err());
        assert!(parse(kind, b"\xff", 1).0.is_err());
    }
}

#[test]
fn multiline_csv_caps_count_decoded_bytes_in_password_and_ignored_notes() {
    for suffix in ["\r\n", "\n\r", "\",", "雪🙂\r\n"] {
        let field = format!("{}{suffix}", "x".repeat(formats::MAX_FIELD - suffix.len()));
        for ending in ["\r\n", "\n"] {
            for bom in ["", "\u{feff}"] {
                for final_ending in ["", ending] {
                    for column in [3, 8] {
                        let mut cells = vec!["fixed".to_owned(); 9];
                        cells[4].clear();
                        cells[column] = field.clone();
                        let encode = |cells: &[String]| {
                            cells
                                .iter()
                                .map(|v| format!("\"{}\"", v.replace('"', "\"\"")))
                                .collect::<Vec<_>>()
                                .join(",")
                        };
                        let head = HEADER.trim_end_matches(['\r', '\n']);
                        let wire = format!("{bom}{head}{ending}{}{final_ending}", encode(&cells));
                        let (result, entries) = parse(Kind::OnePasswordCsv, wire.as_bytes(), 7);
                        assert!(result.is_ok());
                        assert_eq!(entries.len(), 1);
                        assert!(entries[0].value.ct_eq(cells[3].as_bytes()));
                        cells[column].push('x');
                        let bad = format!("{bom}{head}{ending}{}{final_ending}", encode(&cells));
                        let (result, entries) = parse(Kind::OnePasswordCsv, bad.as_bytes(), 7);
                        assert_eq!(result.unwrap_err(), FormatError::Limit);
                        assert!(entries.is_empty());
                    }
                }
            }
        }
    }
}
