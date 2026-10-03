//! The approval statement (SPEC §10a "Bounds and display", §10b
//! "Approval proofs"; gate 31): argv renders as a list with control
//! characters, bidirectional overrides and zero-width characters shown as
//! escapes, text beyond 2 KB is truncated with a marker, and the canonical
//! statement, which the passphrase approves, always covers the full argv
//! and the options.
#![allow(clippy::unwrap_used)]

use envcloak_policy::{
    ApprovalOptions, BindingSummary, EnvName, Mode, PendingDescriptor, ProcessSummary,
    ProjectSummary, RENDER_LIMIT, SubjectKind, SubjectSummary, Uses, canonical_statement,
    escape_for_display, render_statement, statement_digest,
};

fn descriptor(argv: Vec<String>) -> PendingDescriptor {
    PendingDescriptor {
        request: "ABCDEFGH".to_owned(),
        nonce: "00".repeat(32),
        created_secs: 1_800_000_000,
        expires_in_secs: 600,
        subject: SubjectSummary {
            kind: SubjectKind::Agent,
            label: Some("EnvCloak test fixture agent".to_owned()),
            caller_pid: 92,
            root: ProcessSummary {
                pid: 80,
                start_time: 800,
                exe: Some("/opt/fixture-agent".to_owned()),
            },
        },
        project: ProjectSummary {
            dir: "/src/acme-web".to_owned(),
            manifest: "/src/acme-web/envcloak.toml".to_owned(),
            manifest_sha256: "ab".repeat(32),
            new_project: true,
        },
        bindings: vec![
            BindingSummary {
                env_name: "OPENAI_API_KEY".to_owned(),
                slug: "openai/acme-web".to_owned(),
                item: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned(),
                field: "01ARZ3NDEKTSV4RRFFQ69G5FAW".to_owned(),
                field_name: "value".to_owned(),
                classification: "test".to_owned(),
                first_use: true,
                granted: false,
            },
            BindingSummary {
                env_name: "STRIPE_SECRET_KEY".to_owned(),
                slug: "stripe/acme-web".to_owned(),
                item: "01ARZ3NDEKTSV4RRFFQ69G5FAX".to_owned(),
                field: "01ARZ3NDEKTSV4RRFFQ69G5FAY".to_owned(),
                field_name: "value".to_owned(),
                classification: "live".to_owned(),
                first_use: false,
                granted: false,
            },
        ],
        mode: Mode::Inject,
        argv,
    }
}

fn opts() -> ApprovalOptions {
    ApprovalOptions {
        uses: Uses::Session,
        ttl_secs: 3600,
        live: vec![EnvName::new("STRIPE_SECRET_KEY").unwrap()],
    }
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn control_and_invisible_characters_render_as_escapes() {
    let argv = strings(&[
        "./emit",
        "\x1b[31mred\x1b[0m",
        "line\r\nnext",
        "\u{202e}gnp.exe",
        "zero\u{200b}width\u{feff}",
        "tab\there",
        "back\\slash",
        "plain é ü 中",
    ]);
    let text = render_statement(&descriptor(argv), &opts());
    // Nothing raw: no control character, override or zero-width
    // character reaches the terminal.
    for c in text.chars() {
        assert!(
            c == '\n'
                || (!c.is_control()
                    && !matches!(c as u32, 0x200B..=0x200F | 0x202A..=0x202E | 0x2066..=0x2069 | 0xFEFF)),
            "raw {c:?} in the rendering"
        );
    }
    assert!(text.contains("[1] \\u{1b}[31mred\\u{1b}[0m"), "{text}");
    assert!(text.contains("[2] line\\r\\nnext"), "{text}");
    assert!(text.contains("[3] \\u{202e}gnp.exe"), "{text}");
    assert!(text.contains("[4] zero\\u{200b}width\\u{feff}"), "{text}");
    assert!(text.contains("[5] tab\\there"), "{text}");
    assert!(text.contains("[6] back\\\\slash"), "{text}");
    assert!(text.contains("[7] plain é ü 中"), "{text}");
    // The rest of the statement is there, escaped the same way.
    assert!(text.contains("ABCDEFGH"), "{text}");
    assert!(text.contains("new project"), "{text}");
    assert!(text.contains("first use"), "{text}");
    assert!(text.contains("OPENAI_API_KEY = openai/acme-web"), "{text}");
    assert!(
        text.contains("STRIPE_SECRET_KEY = stripe/acme-web"),
        "{text}"
    );
    assert!(text.contains("EnvCloak test fixture agent"), "{text}");
    assert!(text.contains("/src/acme-web"), "{text}");
    assert!(text.contains("1h"), "{text}");
    assert!(!text.contains("more bytes"), "{text}");

    assert_eq!(
        escape_for_display("a\u{1b}b\u{85}c\u{7f}"),
        "a\\u{1b}b\\u{85}c\\u{7f}"
    );
    assert_eq!(
        escape_for_display("\u{ad}\u{2066}\u{e0001}"),
        "\\u{ad}\\u{2066}\\u{e0001}"
    );
    // Every format character, as a manifest's project name refuses them.
    assert_eq!(
        escape_for_display("\u{600}\u{6dd}\u{70f}\u{8e2}\u{110bd}\u{13430}"),
        "\\u{600}\\u{6dd}\\u{70f}\\u{8e2}\\u{110bd}\\u{13430}"
    );
    assert_eq!(escape_for_display("ok"), "ok");
}

#[test]
fn long_argv_is_truncated_with_a_marker_and_still_covered() {
    let long = "A".repeat(100 * 1024);
    let argv = strings(&["./emit", &long, "after"]);
    let d = descriptor(argv.clone());
    let text = render_statement(&d, &opts());
    assert!(text.len() < RENDER_LIMIT + 1024, "{} bytes", text.len());
    assert!(!text.contains("after"), "{text}");
    let marker = text
        .lines()
        .find(|l| l.contains("more bytes)"))
        .unwrap_or_else(|| panic!("no marker: {text}"));
    let n: usize = marker
        .trim()
        .trim_start_matches('(')
        .split(' ')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(n > 90 * 1024, "{marker}");

    // The statement the passphrase approves covers every byte, including
    // the part not shown: a change there changes the digest.
    let digest = statement_digest(&d, &opts());
    let mut changed = argv.clone();
    changed[1].replace_range(99 * 1024..99 * 1024 + 1, "B");
    assert_ne!(statement_digest(&descriptor(changed), &opts()), digest);
    let mut changed = argv.clone();
    changed[2] = "after!".to_owned();
    assert_ne!(statement_digest(&descriptor(changed), &opts()), digest);
    let mut changed = argv;
    changed.push(String::new());
    assert_ne!(statement_digest(&descriptor(changed), &opts()), digest);

    // Truncation cuts on a character boundary.
    let wide = "中".repeat(2000);
    let text = render_statement(&descriptor(strings(&[&wide])), &opts());
    assert!(text.contains("more bytes)"), "{text}");
}

#[test]
fn the_canonical_statement_is_unambiguous_and_covers_the_options() {
    let d = descriptor(strings(&["./emit", "a b"]));
    let o = opts();
    let bytes = canonical_statement(&d, &o);
    assert!(bytes.starts_with(b"envcloak-statement/1\n"));
    assert_eq!(statement_digest(&d, &o).len(), 32);
    // Deterministic.
    assert_eq!(canonical_statement(&d, &o), bytes);
    // Splitting or joining arguments differently changes it.
    assert_ne!(
        canonical_statement(&descriptor(strings(&["./emit a b"])), &o),
        bytes
    );
    assert_ne!(
        canonical_statement(&descriptor(strings(&["./emit", "a", "b"])), &o),
        bytes
    );
    // Every option is covered.
    let mut once = o.clone();
    once.uses = Uses::Once;
    assert_ne!(canonical_statement(&d, &once), bytes);
    let mut shorter = o.clone();
    shorter.ttl_secs = 3599;
    assert_ne!(canonical_statement(&d, &shorter), bytes);
    let mut no_live = o.clone();
    no_live.live.clear();
    assert_ne!(canonical_statement(&d, &no_live), bytes);
    // And every field of the request: the nonce, the project, a binding.
    let mut nonce = d.clone();
    nonce.nonce = "01".repeat(32);
    assert_ne!(canonical_statement(&nonce, &o), bytes);
    let mut project = d.clone();
    project.project.new_project = false;
    assert_ne!(canonical_statement(&project, &o), bytes);
    let mut binding = d.clone();
    binding.bindings[0].item = "01ARZ3NDEKTSV4RRFFQ69G5FAZ".to_owned();
    assert_ne!(canonical_statement(&binding, &o), bytes);
    let mut granted = d.clone();
    granted.bindings[1].granted = true;
    assert_ne!(canonical_statement(&granted, &o), bytes);
    let mut mode = d.clone();
    mode.mode = Mode::Proxy;
    assert_ne!(canonical_statement(&mode, &o), bytes);
    let mut root = d;
    root.subject.root.start_time += 1;
    assert_ne!(canonical_statement(&root, &o), bytes);
}

#[test]
fn descriptors_and_options_cross_the_wire_as_json() {
    let d = descriptor(strings(&["./emit"]));
    let json = serde_json::to_string(&d).unwrap();
    let back: PendingDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
    let o = opts();
    let json = serde_json::to_string(&o).unwrap();
    assert_eq!(
        json,
        r#"{"uses":"session","ttl_secs":3600,"live":["STRIPE_SECRET_KEY"]}"#
    );
    let back: ApprovalOptions = serde_json::from_str(&json).unwrap();
    assert_eq!(back, o);
    // A live name that is not a variable name, or an unknown field, is
    // refused at parse.
    assert!(
        serde_json::from_str::<ApprovalOptions>(
            r#"{"uses":"once","ttl_secs":1,"live":["not a name"]}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<ApprovalOptions>(r#"{"uses":"once","ttl_secs":1,"live":[],"x":1}"#)
            .is_err()
    );
}

/// Gate 28's statement: when a grant already covers some of a request's
/// bindings, the statement asks for the difference first and lists the
/// rest apart, saying the new grant holds them too, so a person sees all
/// the passphrase grants.
#[test]
fn the_statement_asks_for_the_difference_first() {
    let d = descriptor(strings(&["./emit"]));
    let text = render_statement(&d, &opts());
    assert!(text.contains("  bindings (inject mode):"), "{text}");
    assert!(!text.contains("also held by this grant"), "{text}");

    let mut d = d;
    d.bindings[0].granted = true;
    let text = render_statement(&d, &opts());
    let asks = text
        .find("which this asks for:")
        .unwrap_or_else(|| panic!("{text}"));
    let covered = text
        .find("  also held by this grant (")
        .unwrap_or_else(|| panic!("{text}"));
    let stripe = text.find("STRIPE_SECRET_KEY = ").unwrap();
    let openai = text.find("OPENAI_API_KEY = ").unwrap();
    assert!(
        asks < stripe && stripe < covered && covered < openai,
        "{text}"
    );
}

/// The pids a descriptor can carry: the edges of an `i32`, and around 0.
const SIGNED: [i32; 9] = [i32::MIN, -1000, -2, -1, 0, 1, 2, 1000, i32::MAX];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `d` with its caller's pid (`caller`) or its root's pid set to `pid`.
fn with_pid(mut d: PendingDescriptor, caller: bool, pid: i32) -> PendingDescriptor {
    if caller {
        d.subject.caller_pid = pid;
    } else {
        d.subject.root.pid = pid;
    }
    d
}

/// F-81 (gate 23): each pid is bound with its sign. Set to each of
/// [`SIGNED`], the caller's pid and the root's each give a statement of
/// their own; a pid and its negative render differently and so must
/// differ in the digest. A positive pid encodes as it always did: the
/// digest of this file's descriptor is the one the encoding before the
/// change gave, so a statement already shown approves as before.
#[test]
fn each_pid_is_bound_with_its_sign() {
    let o = opts();
    for caller in [true, false] {
        let mut seen = std::collections::HashSet::new();
        for pid in SIGNED {
            let d = with_pid(descriptor(strings(&["./emit"])), caller, pid);
            assert!(
                seen.insert(statement_digest(&d, &o)),
                "caller {caller}: pid {pid} shares its digest"
            );
        }
        let d = descriptor(strings(&["./emit"]));
        let pid = if caller {
            d.subject.caller_pid
        } else {
            d.subject.root.pid
        };
        let negative = with_pid(d.clone(), caller, -pid);
        assert_ne!(render_statement(&d, &o), render_statement(&negative, &o));
        assert_ne!(statement_digest(&d, &o), statement_digest(&negative, &o));
    }
    assert_eq!(
        hex(&statement_digest(
            &descriptor(strings(&["./emit", "a b"])),
            &o
        )),
        "825ff7c19353506ba2da685f5081d90f44238198147ad60708dd84276201053f"
    );
}

/// The canonical statement against an independent encoder of
/// docs/GRANTS.md's format (`tests/oracles/statement.py`, Python): byte
/// for byte, for each pid of [`SIGNED`] in each field, and for
/// descriptors with no label or executable, no bindings, empty, multibyte
/// and control-character arguments, and `once` options without live
/// names. The oracle's encoding before F-81 (absolute pids) is its
/// positive control: it gives a pid and its negative the same bytes, and
/// differs from the crate for every negative pid; for the rest it is the
/// same as now.
#[test]
fn the_canonical_statement_matches_an_independent_encoder() {
    let o = opts();
    let mut cases: Vec<(PendingDescriptor, ApprovalOptions)> = Vec::new();
    for caller in [true, false] {
        for pid in SIGNED {
            cases.push((
                with_pid(descriptor(strings(&["./emit"])), caller, pid),
                o.clone(),
            ));
        }
    }
    let mut bare = descriptor(strings(&["", "中文 argument", "a\u{202e}b", "\u{0}"]));
    bare.subject.label = None;
    bare.subject.root.exe = None;
    bare.subject.kind = SubjectKind::Unknown;
    bare.bindings.clear();
    bare.mode = Mode::Proxy;
    let once = ApprovalOptions {
        uses: Uses::Once,
        ttl_secs: 1,
        live: Vec::new(),
    };
    cases.push((bare, once.clone()));
    cases.push((descriptor(Vec::new()), once));
    let input = serde_json::to_vec(
        &cases
            .iter()
            .map(|(d, o)| serde_json::json!({"descriptor": d, "options": o}))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let oracle =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracles/statement.py");
    let mut child = std::process::Command::new("python3")
        .arg("-I")
        .arg(&oracle)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("python3 is needed on PATH");
    {
        use std::io::Write;
        child.stdin.take().unwrap().write_all(&input).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let got: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(got.len(), cases.len());
    let mut negatives = 0;
    for ((d, o), g) in cases.iter().zip(&got) {
        let ours = hex(&canonical_statement(d, o));
        assert_eq!(ours, g["signed"], "{d:?}");
        if d.subject.caller_pid < 0 || d.subject.root.pid < 0 {
            assert_ne!(ours, g["legacy"], "{d:?}");
            negatives += 1;
        } else {
            assert_eq!(g["legacy"], g["signed"], "{d:?}");
        }
    }
    assert_eq!(negatives, 8);
    // The control: the legacy encoding gives each pid and its negative
    // the same bytes (i32::MIN has no positive).
    for (i, pid) in SIGNED.iter().enumerate() {
        let Some(j) = SIGNED
            .iter()
            .position(|p| *pid < 0 && i64::from(*p) == -i64::from(*pid))
        else {
            continue;
        };
        for field in [0, SIGNED.len()] {
            assert_eq!(got[field + i]["legacy"], got[field + j]["legacy"]);
            assert_ne!(got[field + i]["signed"], got[field + j]["signed"]);
        }
    }
}
