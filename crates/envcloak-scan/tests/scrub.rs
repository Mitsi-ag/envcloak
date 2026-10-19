//! Gate 37 planner and stream controls. Expected bytes are assembled separately.
#![allow(clippy::unwrap_used)]
use envcloak_core::SecretBytes;
use envcloak_scan::candidates::{Candidate, Encoding, Form, Occurrence, Source};
use envcloak_scan::scrub::{Match, plan, preview};
use envcloak_scan::{FileStamp, source::ConfigFormat};
use std::path::PathBuf;

#[test]
fn gate37_format_provenance_debug_never_discloses_paths() {
    let canaries = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
    let value = envcloak_testkit::by_label(&canaries, envcloak_testkit::labels::OPENAI_API_KEY);
    let mut report = envcloak_scan::candidates::ScanReport::default();
    report.transcript_formats.insert(
        PathBuf::from("/fixture").join(value.as_str()),
        ConfigFormat::Raw,
    );
    let shown = format!("{report:?}");
    envcloak_testkit::assert_no_canary(shown.as_bytes(), &canaries);
    assert!(shown.contains("transcript_formats: 1"));
}

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

fn escaped_json_line(value: &str) -> Vec<u8> {
    let first = value.as_bytes()[0];
    let rest = &value[1..];
    format!("{{\"text\":\"\\u{first:04x}{rest}\"}}\n").into_bytes()
}

#[test]
fn gate37_identity_aware_catalog_format_discovery_and_classification() {
    let _files = FILES.lock().unwrap();
    use envcloak_scan::candidates::Budget;
    use envcloak_scan::scrub::{ResolveOptions, resolve_beneath, selected_sources};
    use envcloak_scan::source::{ConfigSource, SourceKind};
    use envcloak_scan::transcript::scan_transcript_sources;

    let canaries = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
    let secret = envcloak_testkit::by_label(&canaries, envcloak_testkit::labels::STRIPE_SECRET_KEY);
    let escaped = escaped_json_line(secret.as_str());
    let raw_line = format!("{} suffix\n", secret.as_str()).into_bytes();

    let d = tempfile::tempdir_in("/tmp").unwrap();
    let root = envcloak_scan::sources::system_path(d.path()).unwrap();
    let store = root.join("store");
    let sessions = store.join("sessions");
    let outside = root.join("outside");
    let nested = outside.join("nested");
    std::fs::create_dir_all(&sessions).unwrap();
    std::fs::create_dir_all(&nested).unwrap();

    for p in [
        sessions.join("record"),
        sessions.join("record.log"),
        root.join("memo.backup"),
        outside.join("notes.json"),
        outside.join("record.log"),
        nested.join("memo.backup"),
    ] {
        std::fs::write(&p, &escaped).unwrap();
        age(&p);
    }
    let raw_path = outside.join("raw.txt");
    std::fs::write(&raw_path, &raw_line).unwrap();
    age(&raw_path);

    let canonical_catalog = vec![
        ConfigSource {
            path: store.clone(),
            format: ConfigFormat::Jsonl,
            source_kind: SourceKind::Transcript,
            label: "store".into(),
            names: None,
        },
        ConfigSource {
            path: root.clone(),
            format: ConfigFormat::Json,
            source_kind: SourceKind::HostBackup,
            label: "backup".into(),
            names: Some("memo.backup".into()),
        },
    ];

    // All 8 classification controls from Cycle 592.
    let classification_controls = [
        ("store-directory", sessions.clone(), ConfigFormat::Jsonl),
        (
            "store-extensionless-file",
            sessions.join("record"),
            ConfigFormat::Jsonl,
        ),
        (
            "store-log-file",
            sessions.join("record.log"),
            ConfigFormat::Jsonl,
        ),
        (
            "named-backup-file",
            root.join("memo.backup"),
            ConfigFormat::Json,
        ),
        ("named-backup-parent-dir", root.clone(), ConfigFormat::Mixed),
        (
            "nested-named-backup-file",
            nested.join("memo.backup"),
            ConfigFormat::Mixed,
        ),
        (
            "outside-json-file",
            outside.join("notes.json"),
            ConfigFormat::Json,
        ),
        (
            "outside-log-file",
            outside.join("record.log"),
            ConfigFormat::Mixed,
        ),
    ];
    for (name, path, expected_format) in classification_controls {
        let sel = selected_sources(path, &canonical_catalog);
        assert_eq!(sel.last().unwrap().format, expected_format, "{name}");
    }

    let case_insensitive_fs = resolve_beneath(
        &root,
        std::path::Path::new("sTORE/sESSIONS/RECORD.LOG"),
        ResolveOptions::default(),
    )
    .is_ok();

    let alias_file_path = if case_insensitive_fs {
        root.join("sTORE/sESSIONS/RECORD.LOG")
    } else {
        root.join("store/./sessions/./record.log")
    };
    let alias_dir_path = if case_insensitive_fs {
        root.join("sTORE/sESSIONS")
    } else {
        root.join("store/./sessions")
    };
    let alias_cat_root = if case_insensitive_fs {
        root.join("sTORE")
    } else {
        root.join("store/.")
    };
    let alias_both_path = if case_insensitive_fs {
        root.join("StOrE/SeSsIoNs/ReCoRd.LoG")
    } else {
        root.join("store/./sessions/./record.log")
    };
    let alias_named_path = if case_insensitive_fs {
        root.join("MEMO.BACKUP")
    } else {
        root.join("./memo.backup")
    };
    let alias_raw_path = if case_insensitive_fs {
        root.join("OUTSIDE/RAW.TXT")
    } else {
        root.join("outside/./raw.txt")
    };

    let alias_catalog = vec![
        ConfigSource {
            path: alias_cat_root,
            format: ConfigFormat::Jsonl,
            source_kind: SourceKind::Transcript,
            label: "store".into(),
            names: None,
        },
        ConfigSource {
            path: root.clone(),
            format: ConfigFormat::Json,
            source_kind: SourceKind::HostBackup,
            label: "backup".into(),
            names: Some("memo.backup".into()),
        },
    ];

    // All 13 rows of the Cycle 600 discovery table.
    let rows: [(&str, PathBuf, &[ConfigSource], ConfigFormat, usize); 13] = [
        (
            "canonical-catalog",
            store.clone(),
            &canonical_catalog,
            ConfigFormat::Jsonl,
            2,
        ),
        (
            "canonical-directory",
            sessions.clone(),
            &canonical_catalog,
            ConfigFormat::Jsonl,
            2,
        ),
        (
            "canonical-file",
            sessions.join("record.log"),
            &canonical_catalog,
            ConfigFormat::Jsonl,
            1,
        ),
        (
            "alias-file",
            alias_file_path,
            &canonical_catalog,
            ConfigFormat::Jsonl,
            1,
        ),
        (
            "alias-directory",
            alias_dir_path,
            &canonical_catalog,
            ConfigFormat::Jsonl,
            2,
        ),
        (
            "alias-catalog",
            sessions.join("record.log"),
            &alias_catalog,
            ConfigFormat::Jsonl,
            1,
        ),
        (
            "alias-both",
            alias_both_path,
            &alias_catalog,
            ConfigFormat::Jsonl,
            1,
        ),
        (
            "alias-named-backup",
            alias_named_path,
            &canonical_catalog,
            ConfigFormat::Json,
            1,
        ),
        (
            "outside-json",
            outside.join("notes.json"),
            &canonical_catalog,
            ConfigFormat::Json,
            1,
        ),
        (
            "outside-log-control",
            outside.join("record.log"),
            &canonical_catalog,
            ConfigFormat::Raw,
            0,
        ),
        (
            "nested-named-backup-control",
            nested.join("memo.backup"),
            &canonical_catalog,
            ConfigFormat::Raw,
            0,
        ),
        (
            "raw-positive",
            raw_path.clone(),
            &canonical_catalog,
            ConfigFormat::Raw,
            1,
        ),
        (
            "alias-raw-positive",
            alias_raw_path,
            &canonical_catalog,
            ConfigFormat::Raw,
            1,
        ),
    ];

    for (name, path, cat, expected_format, expected_count) in rows {
        let sources = selected_sources(path, cat);
        let mut found = Vec::new();
        let report = scan_transcript_sources(&sources, Budget::default(), &mut |c| {
            if c.value.ct_eq(secret.value()) {
                found.push(c);
            }
            true
        })
        .unwrap();
        assert!(report.complete(), "{name}: {:?}", report.issues);
        assert_eq!(found.len(), expected_count, "{name}");
        if expected_count > 0 {
            for (idx, c) in found.iter().enumerate() {
                assert!(c.occurrence.rewritable, "{name} candidate {idx}");
                let file_format = *report
                    .transcript_formats
                    .get(&c.occurrence.source.path)
                    .unwrap();
                assert_eq!(file_format, expected_format, "{name}");
                let cid = c.id;
                let p = plan(&[c], &[association(cid)]);
                assert!(p.complete(), "{name}");
                let disk_bytes = std::fs::read(&c.occurrence.source.path).unwrap();
                let rewritten = preview(&p.files[0], &disk_bytes, file_format).unwrap();
                let expected_bytes: &[u8] = if file_format == ConfigFormat::Raw {
                    b"[envcloak:redacted:fixture/value] suffix\n"
                } else {
                    b"{\"text\":\"[envcloak:redacted:fixture/value]\"}\n"
                };
                assert!(rewritten.ct_eq(expected_bytes), "{name}");
            }
        }
    }
}

#[test]
fn gate37_identity_refusal_controls_and_distinct_case_sensitive_inodes() {
    let _files = FILES.lock().unwrap();
    use envcloak_scan::candidates::Budget;
    use envcloak_scan::scrub::{
        ObjectIdentity, ResolveOptions, resolve_beneath, select_sources_with_options,
        selected_sources,
    };
    use envcloak_scan::source::{ConfigSource, SourceKind};
    use envcloak_scan::transcript::scan_transcript_sources;
    use std::os::unix::fs::symlink;

    // 1. Pure ObjectIdentity controls: (st_dev, st_ino, st_mode & S_IFMT) vs inode-only.
    #[allow(clippy::unnecessary_cast)]
    let reg_kind = libc::S_IFREG as u32;
    #[allow(clippy::unnecessary_cast)]
    let dir_kind = libc::S_IFDIR as u32;
    let base_id = ObjectIdentity {
        dev: 7,
        ino: 11,
        kind: reg_kind,
    };
    let id_controls = [
        (
            "equal",
            ObjectIdentity {
                dev: 7,
                ino: 11,
                kind: reg_kind,
            },
            true,
            true,
        ),
        (
            "different-inode",
            ObjectIdentity {
                dev: 7,
                ino: 12,
                kind: reg_kind,
            },
            false,
            false,
        ),
        (
            "different-device",
            ObjectIdentity {
                dev: 8,
                ino: 11,
                kind: reg_kind,
            },
            false,
            true,
        ),
        (
            "different-kind",
            ObjectIdentity {
                dev: 7,
                ino: 11,
                kind: dir_kind,
            },
            false,
            true,
        ),
    ];
    let mut inode_only_misses = 0usize;
    for (name, other, expected_same, ino_same) in id_controls {
        assert_eq!(base_id == other, expected_same, "{name}");
        assert_eq!(base_id.ino == other.ino, ino_same, "{name}");
        if (base_id.ino == other.ino) != expected_same {
            inode_only_misses += 1;
        }
    }
    assert_eq!(inode_only_misses, 2);

    // 2. All 10 refusal controls.
    let canaries = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
    let secret = envcloak_testkit::by_label(&canaries, envcloak_testkit::labels::OPENAI_API_KEY);
    let raw_line = format!("{} suffix\n", secret.as_str()).into_bytes();

    let d = tempfile::tempdir_in("/tmp").unwrap();
    let other_d = tempfile::tempdir_in("/tmp").unwrap();
    let root = envcloak_scan::sources::system_path(d.path()).unwrap();
    let other_root = envcloak_scan::sources::system_path(other_d.path()).unwrap();

    let sessions = root.join("store/sessions");
    std::fs::create_dir_all(&sessions).unwrap();
    let record = sessions.join("record.log");
    std::fs::write(&record, &raw_line).unwrap();
    age(&record);

    // Control 1: leaf-symlink
    let leaf_link = sessions.join("link.log");
    symlink(&record, &leaf_link).unwrap();

    // Control 2: parent-symlink
    let parent_link = root.join("linked-store");
    symlink(root.join("store"), &parent_link).unwrap();

    // Control 3: catalog-symlink
    let cat_sym_d = tempfile::tempdir_in("/tmp").unwrap();
    let cat_sym_root = envcloak_scan::sources::system_path(cat_sym_d.path()).unwrap();
    std::fs::create_dir_all(cat_sym_root.join("real-store/sessions")).unwrap();
    let cat_sym_rec = cat_sym_root.join("real-store/sessions/record.log");
    std::fs::write(&cat_sym_rec, &raw_line).unwrap();
    age(&cat_sym_rec);
    symlink(cat_sym_root.join("real-store"), cat_sym_root.join("store")).unwrap();

    // Control 4: hardlink-alias
    let hard_d = tempfile::tempdir_in("/tmp").unwrap();
    let hard_root = envcloak_scan::sources::system_path(hard_d.path()).unwrap();
    std::fs::create_dir_all(hard_root.join("store/sessions")).unwrap();
    let hard_target = hard_root.join("store/sessions/record.log");
    std::fs::write(&hard_target, &raw_line).unwrap();
    age(&hard_target);
    let hard_alias = hard_root.join("hardlink.log");
    std::fs::hard_link(&hard_target, &hard_alias).unwrap();

    // Control 5: hardlinked-catalog-file
    let hard_cat = root.join("memo.backup.json");
    std::fs::write(&hard_cat, &raw_line).unwrap();
    age(&hard_cat);
    let hard_plain = root.join("plain.txt");
    std::fs::hard_link(&hard_cat, &hard_plain).unwrap();

    // Control 6: outside-root
    let outside_file = other_root.join("outside.txt");
    std::fs::write(&outside_file, &raw_line).unwrap();
    age(&outside_file);

    // Control 8: depth-budget
    let deep_dir = root.join("a/b/c");
    std::fs::create_dir_all(&deep_dir).unwrap();
    let deep_file = deep_dir.join("d.txt");
    std::fs::write(&deep_file, &raw_line).unwrap();
    age(&deep_file);

    // Control 9: entry-budget
    let crowded = root.join("crowded");
    std::fs::create_dir_all(&crowded).unwrap();
    for idx in 0..4 {
        let p = crowded.join(format!("{idx}.txt"));
        std::fs::write(&p, &raw_line).unwrap();
        age(&p);
    }

    let base_catalog = vec![
        ConfigSource {
            path: root.join("store"),
            format: ConfigFormat::Jsonl,
            source_kind: SourceKind::Transcript,
            label: "store".into(),
            names: None,
        },
        ConfigSource {
            path: root.clone(),
            format: ConfigFormat::Json,
            source_kind: SourceKind::HostBackup,
            label: "backup".into(),
            names: Some("memo.backup".into()),
        },
    ];
    let sym_catalog = vec![ConfigSource {
        path: cat_sym_root.join("store"),
        format: ConfigFormat::Jsonl,
        source_kind: SourceKind::Transcript,
        label: "store".into(),
        names: None,
    }];
    let hard_catalog = vec![ConfigSource {
        path: hard_root.join("store"),
        format: ConfigFormat::Jsonl,
        source_kind: SourceKind::Transcript,
        label: "store".into(),
        names: None,
    }];

    let refusals = [
        (
            "leaf-symlink",
            root.as_path(),
            leaf_link,
            base_catalog.as_slice(),
            ResolveOptions::default(),
            "symlink",
        ),
        (
            "parent-symlink",
            &root,
            parent_link.join("sessions/record.log"),
            &base_catalog,
            ResolveOptions::default(),
            "symlink",
        ),
        (
            "catalog-symlink",
            &cat_sym_root,
            cat_sym_root.join("store/sessions/record.log"),
            &sym_catalog,
            ResolveOptions::default(),
            "symlink",
        ),
        (
            "hardlink-alias",
            &hard_root,
            hard_alias,
            &hard_catalog,
            ResolveOptions::default(),
            "hard_link",
        ),
        (
            "hardlinked-catalog-file",
            &root,
            hard_plain.clone(),
            &base_catalog,
            ResolveOptions::default(),
            "hard_link",
        ),
        (
            "outside-root",
            &root,
            outside_file,
            &base_catalog,
            ResolveOptions::default(),
            "invalid_path",
        ),
        (
            "parent-traversal",
            &root,
            PathBuf::from("../outside.txt"),
            &base_catalog,
            ResolveOptions::default(),
            "invalid_path",
        ),
        (
            "depth-budget",
            &root,
            deep_file.clone(),
            &base_catalog,
            ResolveOptions {
                max_depth: 3,
                ..ResolveOptions::default()
            },
            "too_deep",
        ),
        (
            "entry-budget",
            &root,
            crowded.join("0.txt"),
            &base_catalog,
            ResolveOptions {
                max_entries: 3,
                ..ResolveOptions::default()
            },
            "too_many_entries",
        ),
        (
            "missing-file",
            &root,
            sessions.join("missing.log"),
            &base_catalog,
            ResolveOptions::default(),
            "not_found",
        ),
    ];

    for (name, r_root, cand, cat, opts, expected_reason) in refusals {
        let res = resolve_beneath(r_root, &cand, opts);
        assert_eq!(res, Err(expected_reason), "{name} resolve_beneath");

        if name != "outside-root" {
            let sources = select_sources_with_options(cand.clone(), cat, opts);
            let mut emitted = 0usize;
            let report = scan_transcript_sources(&sources, Budget::default(), &mut |_| {
                emitted += 1;
                true
            })
            .unwrap();
            assert!(!report.complete(), "{name} must not complete");
            assert_eq!(emitted, 0, "{name} must emit zero candidates");
            assert!(
                report.issues.iter().any(|i| i.reason == expected_reason),
                "{name}: expected {expected_reason}, got {:?}",
                report.issues
            );
        }
    }

    // M2-22F-F1 & F2 controls:
    // - An unrelated broken/symlinked/hardlinked catalog entry in another subtree does not
    //   poison `record.log`.
    // - `depth-budget` and `entry-budget` still trigger when `catalog` is empty (`&[]`) or
    //   only contains deeper entries (`[root.join("store/sessions")]`).
    let mut mixed_catalog = base_catalog.clone();
    mixed_catalog.extend(sym_catalog.clone());
    mixed_catalog.push(ConfigSource {
        path: parent_link.clone(),
        format: ConfigFormat::Jsonl,
        source_kind: SourceKind::Transcript,
        label: "sibling-symlink-store".into(),
        names: None,
    });
    mixed_catalog.push(ConfigSource {
        path: hard_plain,
        format: ConfigFormat::Json,
        source_kind: SourceKind::Transcript,
        label: "unrelated-hardlink".into(),
        names: None,
    });
    let valid_record = sessions.join("valid.log");
    std::fs::write(&valid_record, b"{\"msg\":\"ok\"}\n").unwrap();
    age(&valid_record);
    let ok_sources = selected_sources(valid_record, &mixed_catalog);
    assert_eq!(ok_sources.last().unwrap().format, ConfigFormat::Jsonl);
    let ok_report = scan_transcript_sources(&ok_sources, Budget::default(), &mut |_| true).unwrap();
    assert!(ok_report.complete(), "{:?}", ok_report.issues);

    let deep_catalog = vec![ConfigSource {
        path: root.join("store/sessions"),
        format: ConfigFormat::Jsonl,
        source_kind: SourceKind::Transcript,
        label: "deep-store".into(),
        names: None,
    }];
    for cat in [&[][..], deep_catalog.as_slice()] {
        let depth_sel = select_sources_with_options(
            deep_file.clone(),
            cat,
            ResolveOptions {
                max_depth: 3,
                ..ResolveOptions::default()
            },
        );
        let rep = scan_transcript_sources(&depth_sel, Budget::default(), &mut |_| true).unwrap();
        assert!(!rep.complete());
        assert!(rep.issues.iter().any(|i| i.reason == "too_deep"));

        let entry_sel = select_sources_with_options(
            crowded.join("0.txt"),
            cat,
            ResolveOptions {
                max_entries: 3,
                ..ResolveOptions::default()
            },
        );
        let rep = scan_transcript_sources(&entry_sel, Budget::default(), &mut |_| true).unwrap();
        assert!(!rep.complete());
        assert!(rep.issues.iter().any(|i| i.reason == "too_many_entries"));
    }

    // 3. Case-sensitive distinct-inode control on a real case-sensitive filesystem:
    // two case-fold-equivalent paths pointing to distinct kernel inodes must NOT share
    // catalog format grammar.
    struct CaseSensitiveDir {
        #[allow(dead_code)]
        holder: tempfile::TempDir,
        #[cfg(target_os = "macos")]
        dmg: PathBuf,
        #[cfg(target_os = "macos")]
        mnt: PathBuf,
        root: PathBuf,
    }
    impl CaseSensitiveDir {
        fn new() -> Self {
            let holder = tempfile::tempdir_in("/tmp").unwrap();
            #[cfg(target_os = "macos")]
            {
                let base = envcloak_scan::sources::system_path(holder.path()).unwrap();
                let dmg = base.join("cs.dmg");
                let mnt = base.join("mnt");
                std::fs::create_dir_all(&mnt).unwrap();
                let st = std::process::Command::new("/usr/bin/hdiutil")
                    .args([
                        "create",
                        "-size",
                        "10m",
                        "-fs",
                        "Case-sensitive APFS",
                        "-volname",
                        "ec_cs",
                    ])
                    .arg(&dmg)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .unwrap();
                assert!(st.success(), "hdiutil create failed");
                let st = std::process::Command::new("/usr/bin/hdiutil")
                    .args(["attach", "-nobrowse", "-mountpoint"])
                    .arg(&mnt)
                    .arg(&dmg)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .unwrap();
                assert!(st.success(), "hdiutil attach failed");
                let root = mnt.join("work");
                std::fs::create_dir_all(&root).unwrap();
                Self {
                    holder,
                    dmg,
                    mnt,
                    root,
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                let root = envcloak_scan::sources::system_path(holder.path()).unwrap();
                Self { holder, root }
            }
        }
    }
    #[cfg(target_os = "macos")]
    impl Drop for CaseSensitiveDir {
        fn drop(&mut self) {
            let _ = std::process::Command::new("/usr/bin/hdiutil")
                .args(["detach", "-force"])
                .arg(&self.mnt)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            let _ = std::fs::remove_file(&self.dmg);
        }
    }

    let cs_env = CaseSensitiveDir::new();
    let cs_root = cs_env.root.clone();

    let cat_leaf = cs_root.join("Store/Sessions/record");
    std::fs::create_dir_all(cat_leaf.parent().unwrap()).unwrap();
    let escaped = escaped_json_line(secret.as_str());
    std::fs::write(&cat_leaf, &escaped).unwrap();
    age(&cat_leaf);

    let cat_memo = cs_root.join("memo.backup");
    std::fs::write(&cat_memo, &escaped).unwrap();
    age(&cat_memo);

    let alt_leaf = cs_root.join("sTORE/sESSIONS/RECORD");
    std::fs::create_dir_all(alt_leaf.parent().unwrap()).unwrap();
    std::fs::write(&alt_leaf, &escaped).unwrap();
    age(&alt_leaf);

    let alt_memo = cs_root.join("MEMO.BACKUP");
    std::fs::write(&alt_memo, &escaped).unwrap();
    age(&alt_memo);

    let cs_catalog = vec![
        ConfigSource {
            path: cs_root.join("Store"),
            format: ConfigFormat::Jsonl,
            source_kind: SourceKind::Transcript,
            label: "store".into(),
            names: None,
        },
        ConfigSource {
            path: cs_root.clone(),
            format: ConfigFormat::Json,
            source_kind: SourceKind::HostBackup,
            label: "backup".into(),
            names: Some("memo.backup".into()),
        },
    ];

    let resolved_cat_leaf =
        resolve_beneath(&cs_root, &cat_leaf, ResolveOptions::default()).unwrap();
    let resolved_alt_leaf =
        resolve_beneath(&cs_root, &alt_leaf, ResolveOptions::default()).unwrap();
    assert_ne!(
        resolved_cat_leaf.identity, resolved_alt_leaf.identity,
        "distinct case-variant inodes required"
    );

    let resolved_cat_memo =
        resolve_beneath(&cs_root, &cat_memo, ResolveOptions::default()).unwrap();
    let resolved_alt_memo =
        resolve_beneath(&cs_root, &alt_memo, ResolveOptions::default()).unwrap();
    assert_ne!(
        resolved_cat_memo.identity, resolved_alt_memo.identity,
        "distinct named-backup case-variant inodes required"
    );

    for (label, target, expected_fmt, expected_hits) in [
        ("catalog-store-leaf", cat_leaf, ConfigFormat::Jsonl, 1usize),
        (
            "distinct-inode-store-case-variant",
            alt_leaf,
            ConfigFormat::Mixed,
            0usize,
        ),
        ("catalog-memo-leaf", cat_memo, ConfigFormat::Json, 1usize),
        (
            "distinct-inode-memo-case-variant",
            alt_memo,
            ConfigFormat::Mixed,
            0usize,
        ),
    ] {
        let sel = selected_sources(target, &cs_catalog);
        assert_eq!(sel.last().unwrap().format, expected_fmt, "{label}");
        let mut hits = 0usize;
        let report = scan_transcript_sources(&sel, Budget::default(), &mut |c| {
            if c.value.ct_eq(secret.value()) {
                hits += 1;
            }
            true
        })
        .unwrap();
        assert!(report.complete(), "{label}: {:?}", report.issues);
        assert_eq!(hits, expected_hits, "{label}");
    }
}

#[test]
fn gate37_replacement_barrier_rechecks_selection_witness_at_scanner_open() {
    let _files = FILES.lock().unwrap();
    use envcloak_scan::candidates::Budget;
    use envcloak_scan::scrub::{perturb_witness_device, selected_sources};
    use envcloak_scan::source::{ConfigSource, SourceKind};
    use envcloak_scan::transcript::scan_transcript_sources;
    use std::os::unix::fs::symlink;

    let canaries = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
    let secret = envcloak_testkit::by_label(&canaries, envcloak_testkit::labels::GITHUB_TOKEN);
    let escaped = escaped_json_line(secret.as_str());

    for barrier in [
        "unchanged-positive",
        "leaf-symlink",
        "leaf-inode",
        "parent-symlink",
        "parent-inode",
        "catalog-symlink",
        "catalog-inode",
        "device-perturbed",
    ] {
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let root = envcloak_scan::sources::system_path(d.path()).unwrap();
        let store = root.join("store");
        let sessions = store.join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let record = sessions.join("record.log");
        std::fs::write(&record, &escaped).unwrap();
        age(&record);

        let catalog = vec![ConfigSource {
            path: store.clone(),
            format: ConfigFormat::Jsonl,
            source_kind: SourceKind::Transcript,
            label: "store".into(),
            names: None,
        }];

        let sources = selected_sources(record.clone(), &catalog);
        assert_eq!(sources.last().unwrap().format, ConfigFormat::Jsonl);

        // Keep displaced objects alive on disk so their inodes cannot be reused.
        let held_path = root.join("displaced");
        let expected_reason = match barrier {
            "unchanged-positive" => None,
            "leaf-symlink" => {
                std::fs::rename(&record, &held_path).unwrap();
                symlink(&held_path, &record).unwrap();
                Some("symlink")
            }
            "leaf-inode" => {
                std::fs::rename(&record, &held_path).unwrap();
                std::fs::write(&record, &escaped).unwrap();
                age(&record);
                Some("changed")
            }
            "parent-symlink" => {
                std::fs::rename(&sessions, &held_path).unwrap();
                symlink(&held_path, &sessions).unwrap();
                Some("symlink")
            }
            "parent-inode" => {
                std::fs::rename(&sessions, &held_path).unwrap();
                std::fs::create_dir_all(&sessions).unwrap();
                std::fs::write(&record, &escaped).unwrap();
                age(&record);
                Some("changed")
            }
            "catalog-symlink" => {
                std::fs::rename(&store, &held_path).unwrap();
                symlink(&held_path, &store).unwrap();
                Some("symlink")
            }
            "catalog-inode" => {
                std::fs::rename(&store, &held_path).unwrap();
                std::fs::create_dir_all(&sessions).unwrap();
                std::fs::write(&record, &escaped).unwrap();
                age(&record);
                Some("changed")
            }
            "device-perturbed" => {
                assert!(perturb_witness_device(sources.last().unwrap()));
                Some("changed")
            }
            _ => unreachable!(),
        };

        let mut emitted = 0usize;
        let report = scan_transcript_sources(&sources, Budget::default(), &mut |c| {
            if c.value.ct_eq(secret.value()) {
                emitted += 1;
            }
            true
        })
        .unwrap();

        if let Some(reason) = expected_reason {
            assert!(!report.complete(), "{barrier} must fail completeness");
            assert_eq!(emitted, 0, "{barrier} must emit zero candidates");
            assert!(
                report.issues.iter().any(|i| i.reason == reason),
                "{barrier}: expected {reason}, got {:?}",
                report.issues
            );
        } else {
            assert!(report.complete(), "{barrier}: {:?}", report.issues);
            assert_eq!(emitted, 1, "{barrier}");
        }
    }
}
