//! Gate 37 planner and stream controls. Expected bytes are assembled separately.
#![allow(clippy::unwrap_used)]
use envcloak_core::SecretBytes;
use envcloak_scan::candidates::{Candidate, Encoding, Form, Occurrence, Source};
use envcloak_scan::scrub::{Match, plan, preview};
use envcloak_scan::{FileStamp, source::ConfigFormat};
use std::path::PathBuf;

fn candidate(id: u64, range: std::ops::Range<u64>, size: u64) -> Candidate {
    Candidate {
        id,
        value: SecretBytes::copy_from(b"fixtureZcomparisonValue"),
        form: Form::Raw,
        occurrence: Occurrence {
            source: Source {
                path: PathBuf::from("/fixture/events"),
                object: None,
            },
            range,
            encoding: Encoding::Raw,
            stamp: Some(FileStamp {
                dev: 1,
                ino: 2,
                size,
                mtime: 0,
                mtime_nsec: 0,
                ctime: 0,
                ctime_nsec: 0,
                mode: 0o600,
                nlink: 1,
                uid: 1,
            }),
            rewritable: true,
        },
    }
}
fn association(id: u64) -> Match {
    Match {
        candidate: id,
        item: "fixture-item".into(),
        slug: "fixture/value".into(),
    }
}
#[test]
fn gate37_plan_preserves_occurrences_coalesces_duplicates_and_accepts_adjacency() {
    let bytes = b"before AABB after AA";
    let candidates = [
        candidate(0, 7..9, 20),
        candidate(1, 9..11, 20),
        candidate(0, 7..9, 20),
        candidate(0, 18..20, 20),
    ];
    for reverse in [false, true] {
        let mut refs: Vec<_> = candidates.iter().collect();
        if reverse {
            refs.reverse();
        }
        let p = plan(&refs, &[association(0), association(1)]);
        assert!(p.complete());
        assert_eq!(p.files[0].edits.len(), 3);
        let actual = preview(&p.files[0], bytes, ConfigFormat::Raw).unwrap();
        assert!(actual.ct_eq(b"before [envcloak:redacted:fixture/value][envcloak:redacted:fixture/value] after [envcloak:redacted:fixture/value]"));
    }
}
#[test]
fn gate37_plan_refuses_overlap_stale_and_nonrewritable_provenance() {
    for how in [
        "overlap",
        "stale",
        "unsupported",
        "bounds",
        "ambiguous",
        "object",
        "missing",
    ] {
        let a = candidate(0, 0..8, 16);
        let mut b = candidate(1, 8..16, 16);
        let mut matches = vec![association(0), association(1)];
        match how {
            "overlap" => b.occurrence.range = 7..16,
            "stale" => b.occurrence.stamp.as_mut().unwrap().ctime = 1,
            "unsupported" => b.occurrence.rewritable = false,
            "bounds" => b.occurrence.range = 8..17,
            "ambiguous" => {
                let mut m = association(0);
                m.slug = "another/item".into();
                matches.push(m);
            }
            "object" => b.occurrence.source.object = Some("object".into()),
            "missing" => b.occurrence.stamp = None,
            _ => unreachable!(),
        }
        let p = plan(&[&a, &b], &matches);
        assert!(!p.complete(), "{how}");
        assert!(!p.files[0].reasons.is_empty(), "{how}");
        assert!(
            preview(&p.files[0], b"abcdefghijklmnop", ConfigFormat::Raw).is_err(),
            "{how}"
        );
    }
}
#[test]
fn gate37_json_preview_preserves_escape_boundaries_and_refuses_invalid_json() {
    let bytes = b"{\"text\":\"prefix \\u0061\\u0062 suffix\"}\r\n";
    let c = candidate(0, 16..28, bytes.len() as u64);
    let p = plan(&[&c], &[association(0)]);
    let actual = preview(&p.files[0], bytes, ConfigFormat::Jsonl).unwrap();
    assert!(actual.ct_eq(b"{\"text\":\"prefix [envcloak:redacted:fixture/value] suffix\"}\r\n"));
    for range in [17..28, 16..27, 1..7] {
        let c = candidate(0, range, bytes.len() as u64);
        let p = plan(&[&c], &[association(0)]);
        assert!(preview(&p.files[0], bytes, ConfigFormat::Jsonl).is_err());
    }
}

// A sibling test's fork briefly inherits all this process's descriptors until
// exec. Keep the filesystem gates apart so the closed controls have no holder.
static FILES: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn file_plan(path: &std::path::Path) -> envcloak_scan::scrub::FilePlan {
    let stamp = FileStamp::of(&std::fs::metadata(path).unwrap());
    let mut c = candidate(0, 0..stamp.size, stamp.size);
    c.occurrence.source.path = path.to_path_buf();
    c.occurrence.stamp = Some(stamp);
    plan(&[&c], &[association(0)]).files.remove(0)
}
fn age(path: &std::path::Path) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(300))
        .unwrap();
}
#[test]
fn gate37_recent_linked_and_stale_sources_refused() {
    let _files = FILES.lock().unwrap();
    use envcloak_scan::scrub::OpenFile;
    use std::os::unix::fs::symlink;
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join("events");
    std::fs::write(&p, b"fixtureZoriginalTranscript").unwrap();
    assert!(matches!(
        OpenFile::open(&file_plan(&p)),
        Err("recently_changed")
    ));
    age(&p);
    let f = file_plan(&p);
    assert!(OpenFile::open(&f).is_ok(), "aged positive control");
    let link = d.path().join("link");
    symlink(&p, &link).unwrap();
    let mut linked = file_plan(&p);
    linked.path = link;
    assert!(OpenFile::open(&linked).is_err(), "symlink accepted");
    std::fs::hard_link(&p, d.path().join("hard")).unwrap();
    assert!(
        OpenFile::open(&file_plan(&p)).is_err(),
        "hard link accepted"
    );
    std::fs::remove_file(d.path().join("hard")).unwrap();
    let f = file_plan(&p);
    // Same length and restored mtime: only ctime distinguishes this change.
    let stamp = std::fs::metadata(&p).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_permissions(stamp.permissions())
        .unwrap();
    assert!(OpenFile::open(&f).is_err(), "ctime change accepted");
}
#[test]
fn gate37_apply_streams_only_scrubbed_temporary_bytes_and_keeps_mode() {
    let _files = FILES.lock().unwrap();
    use envcloak_scan::scrub::OpenFile;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let p = d.path().join("events");
    std::fs::write(&p, b"fixtureZoriginalTranscript").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
    age(&p);
    let f = file_plan(&p);
    let mut opened = OpenFile::open(&f).unwrap();
    opened.validate(&f, ConfigFormat::Raw).unwrap();
    let digest = opened.apply(&f, ConfigFormat::Raw).unwrap();
    let bytes = std::fs::read(&p).unwrap();
    assert!(bytes == b"[envcloak:redacted:fixture/value]");
    assert_eq!(SecretBytes::copy_from(&bytes).sha256(), digest);
    assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o777, 0o640);
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
}
#[test]
fn gate37_whole_encoded_tokens_rewrite_but_embedded_runs_remain_manual() {
    use base64::Engine;
    let value = b"fixtureZencodedValue";
    for embedded in [false, true] {
        let decoded = if embedded {
            [b"before ".as_slice(), value, b" after"].concat()
        } else {
            value.to_vec()
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(&decoded);
        let mut found = Vec::new();
        envcloak_scan::transcript::scan_reader(
            &mut std::io::Cursor::new(encoded.as_bytes()),
            ConfigFormat::Raw,
            Source::default(),
            envcloak_scan::candidates::Budget::default(),
            &mut |c| {
                if c.value.ct_eq(value) {
                    found.push(c);
                }
                true
            },
        )
        .unwrap();
        assert!(!found.is_empty());
        assert!(found.iter().all(|c| c.occurrence.rewritable != embedded));
    }
}

proptest::proptest! {
    #[test]
    fn hostile_preview_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(),0..1024),
        a in 0u64..2048,b in 0u64..2048,jsonl in proptest::prelude::any::<bool>()) {
        let c=candidate(0,a..b,bytes.len() as u64);
        let p=plan(&[&c],&[association(0)]);
        let _=preview(&p.files[0],&bytes,if jsonl {ConfigFormat::Jsonl} else {ConfigFormat::Raw});
    }
}

#[test]
fn gate37_open_elsewhere_refuses_aged_source_with_a_closed_control() {
    let _files = FILES.lock().unwrap();
    use std::io::BufRead;
    let d = tempfile::tempdir_in("/tmp").unwrap();
    let path = d.path().join("events");
    std::fs::write(&path, b"fixtureZheldByAnotherProcess").unwrap();
    age(&path);
    let plan = file_plan(&path);
    let mut opened = envcloak_scan::scrub::OpenFile::open(&plan).unwrap();
    opened.check().unwrap();
    opened.validate(&plan, ConfigFormat::Raw).unwrap();
    let mut holder=std::process::Command::new("/usr/bin/python3").args(["-I","-B","-c",
        "import sys\nf=open(sys.argv[1],'rb')\nprint('ready',flush=True)\nsys.stdin.readline()\nf.close()\n"])
        .arg(&path).env_clear().env("HOME",d.path()).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).spawn().unwrap();
    let mut line = String::new();
    std::io::BufReader::new(holder.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line, "ready\n");
    let held_check = opened.check();
    let held_validate = opened.validate(&plan, ConfigFormat::Raw);
    let held_apply = opened.apply(&plan, ConfigFormat::Raw);
    // Only the Python holder may explain the fresh open's refusal on Linux.
    drop(opened);
    let refused = envcloak_scan::scrub::OpenFile::open(&plan);
    holder.stdin.take();
    assert!(holder.wait().unwrap().success());
    assert_eq!(held_check, Err("open_elsewhere"));
    assert_eq!(held_validate, Err("open_elsewhere"));
    assert_eq!(held_apply, Err("open_elsewhere"));
    assert!(matches!(refused, Err("open_elsewhere")));
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"fixtureZheldByAnotherProcess"
    );
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
    let mut closed = envcloak_scan::scrub::OpenFile::open(&plan).unwrap();
    closed.check().unwrap();
    closed.validate(&plan, ConfigFormat::Raw).unwrap();
}
