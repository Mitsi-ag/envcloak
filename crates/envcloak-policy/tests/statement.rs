//! The approval statement (SPEC §10a "Bounds and display", §10b
//! "Approval proofs", "Live-key guard"; gates 31 and 40): argv renders as
//! a list with control characters, bidirectional overrides and zero-width
//! characters shown as escapes, text beyond 2 KB is truncated with a
//! marker, and the canonical statement (`envcloak-statement/2`), which the
//! passphrase approves, always covers the full argv, the options, the
//! classifications, the live ticks and the test items proposed in place
//! of live ones, which the rendering lists before the live bindings.
#![allow(clippy::unwrap_used)]

use envcloak_policy::{
    ApprovalOptions, BindingSummary, EnvName, Mode, PendingDescriptor, ProcessSummary,
    ProjectSummary, Proposal, RENDER_LIMIT, STATEMENT_DOMAIN, SubjectKind, SubjectSummary, Uses,
    canonical_statement, escape_for_display, live_guarded, render_statement, statement_digest,
    unticked_live,
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
        proposals: Vec::new(),
        mode: Mode::Inject,
        argv,
    }
}

/// The test item `test` proposed for the variable `env`, bound to the live
/// item `live`.
fn proposal(env: &str, live: &str, test: &str, field: Option<&str>) -> Proposal {
    Proposal {
        env_name: env.to_owned(),
        live_slug: live.to_owned(),
        test_slug: test.to_owned(),
        test_field: field.map(str::to_owned),
    }
}

/// [`descriptor`] with the Stripe test item proposed for its live
/// binding.
fn proposing(argv: Vec<String>) -> PendingDescriptor {
    let mut d = descriptor(argv);
    d.proposals = vec![proposal(
        "STRIPE_SECRET_KEY",
        "stripe/acme-web",
        "stripe/acme-test",
        None,
    )];
    d
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
    assert!(bytes.starts_with(STATEMENT_DOMAIN));
    assert_eq!(STATEMENT_DOMAIN, b"envcloak-statement/2\n");
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
    let mut root = d.clone();
    root.subject.root.start_time += 1;
    assert_ne!(canonical_statement(&root, &o), bytes);
    // A classification, a tick and every field of a proposal.
    let mut class = d.clone();
    class.bindings[1].classification = "test".to_owned();
    assert_ne!(canonical_statement(&class, &o), bytes);
    let mut tick = o.clone();
    tick.live.push(EnvName::new("OPENAI_API_KEY").unwrap());
    assert_ne!(canonical_statement(&d, &tick), bytes);
    let proposed = proposing(strings(&["./emit", "a b"]));
    let with = canonical_statement(&proposed, &o);
    assert_ne!(with, bytes);
    let changes: [fn(&mut Proposal); 5] = [
        |x| x.env_name.push('X'),
        |x| x.live_slug.push('x'),
        |x| x.test_slug.push('x'),
        |x| x.test_field = Some("value".to_owned()),
        |x| x.test_field = Some(String::new()),
    ];
    for change in changes {
        let mut other = proposed.clone();
        change(&mut other.proposals[0]);
        assert_ne!(canonical_statement(&other, &o), with, "{other:?}");
    }
    // An absent field and an empty one differ.
    let mut empty = proposed.clone();
    empty.proposals[0].test_field = Some(String::new());
    let mut absent = proposed.clone();
    absent.proposals[0].test_field = None;
    assert_ne!(
        canonical_statement(&empty, &o),
        canonical_statement(&absent, &o)
    );
    // A proposal does not run into the bindings or the mode: a binding
    // moved into a proposal's place encodes differently.
    let mut two = proposed.clone();
    two.proposals.push(proposal("A", "a/b", "c/d", None));
    assert_ne!(canonical_statement(&two, &o), with);
}

#[test]
fn descriptors_and_options_cross_the_wire_as_json() {
    for d in [
        descriptor(strings(&["./emit"])),
        proposing(strings(&["./emit"])),
    ] {
        let json = serde_json::to_string(&d).unwrap();
        let back: PendingDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }
    // A descriptor without its proposals, or with a field a proposal does
    // not have, is refused: both sides are one build.
    let mut v = serde_json::to_value(proposing(strings(&["./emit"]))).unwrap();
    v["proposals"][0]["extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<PendingDescriptor>(v.clone()).is_err());
    v.as_object_mut().unwrap().remove("proposals");
    assert!(serde_json::from_value::<PendingDescriptor>(v).is_err());
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
/// differ in the digest.
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
}

/// Golden vectors of `envcloak-statement/2` (M2-13): the digests of this
/// file's descriptor without and with a proposal, as the independent
/// encoder (`tests/oracles/statement.py`) gives them, fixed here so a
/// change to the format is a change to this test. The version 1 digest of
/// the same descriptor (M1's golden vector, which the encoder's version 1
/// reproduces) is not what the crate gives: a statement shown before the
/// upgrade approves nothing after it (SPEC §10b; docs/IPC.md "Statement
/// domains"), and version 1 gives the same digest with or without the
/// proposal, which version 2 tells apart.
#[test]
fn statement_v2_golden_vectors() {
    let o = opts();
    let plain = statement_digest(&descriptor(strings(&["./emit", "a b"])), &o);
    let proposed = statement_digest(&proposing(strings(&["./emit", "a b"])), &o);
    assert_eq!(
        hex(&plain),
        "2baf6aace098d0cc3a679fea6b125744ed8470253537437432f67c0db2028118"
    );
    assert_eq!(
        hex(&proposed),
        "76a96288a2d66e0bcb1168fd6c7684d478a78c381063241df613b132b7844a89"
    );
    const V1: &str = "825ff7c19353506ba2da685f5081d90f44238198147ad60708dd84276201053f";
    assert_ne!(hex(&plain), V1);
    assert_ne!(hex(&proposed), V1);
}

/// The canonical statement against an independent encoder of
/// docs/GRANTS.md's format (`tests/oracles/statement.py`, Python): byte
/// for byte, for each pid of [`SIGNED`] in each field, and for
/// descriptors with no label or executable, no bindings, empty, multibyte
/// and control-character arguments, `once` options without live names,
/// and proposals with and without a field, empty and multibyte. Two
/// positive controls: the oracle's encoding before F-81 (absolute pids)
/// gives a pid and its negative the same bytes, and differs from the crate
/// for every negative pid, for the rest it is the same as now; and its
/// version 1 encoding, which has no proposals, differs from the crate for
/// every case (a version 1 digest approves nothing) and gives two
/// descriptors that differ in their proposals alone the same bytes, which
/// the crate tells apart.
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
    cases.push((descriptor(Vec::new()), once.clone()));
    // Proposals: none and one (a pair differing in proposals alone), with
    // a field, several, empty and multibyte strings.
    let first_proposal = cases.len();
    cases.push((descriptor(strings(&["./emit"])), o.clone()));
    cases.push((proposing(strings(&["./emit"])), o.clone()));
    let mut several = proposing(strings(&["./emit"]));
    several.proposals.push(proposal(
        "OPENAI_API_KEY",
        "openai/live",
        "openai/test",
        Some("api_key"),
    ));
    several.proposals.push(proposal("", "", "", Some("")));
    several
        .proposals
        .push(proposal("中文", "a\u{202e}b", "c\u{0}d", Some("é")));
    cases.push((several, once));
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
        assert_ne!(ours, g["v1"], "{d:?}");
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
    // The second control: version 1 cannot tell the pair apart.
    let (a, b) = (&got[first_proposal], &got[first_proposal + 1]);
    assert_eq!(a["v1"], b["v1"]);
    assert_ne!(a["signed"], b["signed"]);
}

/// A descriptor of `kind` whose bindings are `(variable, slug,
/// classification)`.
fn of_kind(kind: SubjectKind, bindings: &[(&str, &str, &str)]) -> PendingDescriptor {
    let mut d = descriptor(strings(&["./emit"]));
    d.subject.kind = kind;
    if kind != SubjectKind::Agent {
        d.subject.label = None;
    }
    d.bindings = bindings
        .iter()
        .map(|(env, slug, class)| BindingSummary {
            env_name: (*env).to_owned(),
            slug: (*slug).to_owned(),
            item: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned(),
            field: "01ARZ3NDEKTSV4RRFFQ69G5FAW".to_owned(),
            field_name: "value".to_owned(),
            classification: (*class).to_owned(),
            first_use: false,
            granted: false,
        })
        .collect();
    d
}

fn ticking(names: &[&str]) -> ApprovalOptions {
    ApprovalOptions {
        uses: Uses::Once,
        ttl_secs: 600,
        live: names.iter().map(|n| EnvName::new(n).unwrap()).collect(),
    }
}

/// Gate 40, sentence 1 (SPEC §10b "Live-key guard"): for an agent or an
/// unknown subject every live binding must be ticked, each by its own
/// variable; test and unknown classifications need none; a terminal
/// subject needs none. The statement says which ticks are missing.
#[test]
fn the_live_key_guard_names_every_unticked_live_binding() {
    assert!(live_guarded(SubjectKind::Agent));
    assert!(live_guarded(SubjectKind::Unknown));
    assert!(!live_guarded(SubjectKind::Terminal));
    let bindings = [
        ("STRIPE_SECRET_KEY", "stripe/acme-live", "live"),
        ("OPENAI_API_KEY", "openai/acme-web", "live"),
        ("STRIPE_TEST_KEY", "stripe/acme-test", "test"),
        ("DATABASE_URL", "postgres/acme-web", "unknown"),
    ];
    for kind in [SubjectKind::Agent, SubjectKind::Unknown] {
        let d = of_kind(kind, &bindings);
        assert_eq!(
            unticked_live(&d, &ticking(&[])),
            ["STRIPE_SECRET_KEY", "OPENAI_API_KEY"],
            "{kind:?}"
        );
        assert_eq!(
            unticked_live(&d, &ticking(&["OPENAI_API_KEY"])),
            ["STRIPE_SECRET_KEY"],
            "{kind:?}"
        );
        // A tick of a test binding stands for no live one.
        assert_eq!(
            unticked_live(&d, &ticking(&["STRIPE_TEST_KEY", "OPENAI_API_KEY"])),
            ["STRIPE_SECRET_KEY"],
            "{kind:?}"
        );
        assert!(
            unticked_live(&d, &ticking(&["STRIPE_SECRET_KEY", "OPENAI_API_KEY"])).is_empty(),
            "{kind:?}"
        );
        let text = render_statement(&d, &ticking(&["OPENAI_API_KEY"]));
        assert!(
            text.contains(
                "STRIPE_SECRET_KEY = stripe/acme-live#value  (live key, live: not allowed by \
                 you, so this approval is refused unless you add --live STRIPE_SECRET_KEY)"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "OPENAI_API_KEY = openai/acme-web#value  (live key, live: allowed by you)"
            ),
            "{text}"
        );
        assert!(
            text.contains("(live_not_ticked). Approve again with --live STRIPE_SECRET_KEY."),
            "{text}"
        );
        let all = render_statement(&d, &ticking(&["STRIPE_SECRET_KEY", "OPENAI_API_KEY"]));
        assert!(!all.contains("not allowed"), "{all}");
        assert!(!all.contains("live_not_ticked"), "{all}");
    }
    // A terminal subject: M1's rules, no tick needed and none asked for.
    let d = of_kind(SubjectKind::Terminal, &bindings);
    assert!(unticked_live(&d, &ticking(&[])).is_empty());
    let text = render_statement(&d, &ticking(&[]));
    assert!(!text.contains("not allowed"), "{text}");
    assert!(!text.contains("live_not_ticked"), "{text}");
}

/// The whole statement of [`the_statement_lists_the_test_item_before_the_live_one`],
/// as a snapshot.
const PROPOSED_SNAPSHOT: &str = "\
Approval request ABCDEFGH
  requested by: agent EnvCloak test fixture agent (caller pid 92), rooted at pid 80 started at 800, /opt/fixture-agent
  project: /src/acme-web (new project: the vault has no record of it)
  manifest: /src/acme-web/envcloak.toml sha256 abababababababababababababababababababababababababababababababab
  test keys of the same provider, proposed instead of live ones (EnvCloak never swaps them in: bind one, then run the command again):
    STRIPE_SECRET_KEY: the test key stripe/acme-test, not the live key stripe/acme-web
      envcloak ref STRIPE_SECRET_KEY=stripe/acme-test
    OPENAI_API_KEY: the test key openai/acme-\\u{1b}[31mtest#api\\u{200b}key, not the live key openai/acme\\u{202e}-live
      envcloak ref OPENAI_API_KEY=openai/acme-\\u{1b}[31mtest#api\\u{200b}key
  bindings (inject mode):
    OPENAI_API_KEY = openai/acme-web#value  (test key, first use: no project uses this item yet)
    STRIPE_SECRET_KEY = stripe/acme-web#value  (live key, live: not allowed by you, so this approval is refused unless you add --live STRIPE_SECRET_KEY)
  command (1 arguments):
    [0] ./emit
  grant: once, for the next matching request within 10m
  live keys: agent EnvCloak test fixture agent gets a live key only where you tick it, and this approval leaves 1 unticked, so it creates no grant (live_not_ticked). Approve again with --live STRIPE_SECRET_KEY, or bind a test key proposed above.
The passphrase you enter approves exactly this, and nothing else.
";

/// Gate 40, sentence 2 (SPEC §10b): the test item is proposed first.
/// The rendering lists each proposal, with the `envcloak ref` line that
/// binds it, before the bindings and their ticks, every string escaped:
/// a program answering in the daemon's place could send anything. The
/// whole statement is compared ([`PROPOSED_SNAPSHOT`]).
#[test]
fn the_statement_lists_the_test_item_before_the_live_one() {
    let mut d = proposing(strings(&["./emit"]));
    d.proposals.push(proposal(
        "OPENAI_API_KEY",
        "openai/acme\u{202e}-live",
        "openai/acme-\u{1b}[31mtest",
        Some("api\u{200b}key"),
    ));
    let text = render_statement(&d, &ticking(&[]));
    assert_eq!(text, PROPOSED_SNAPSHOT);
    // The test item comes before the live one.
    let test = text.find("stripe/acme-test").unwrap();
    let live = text.find("STRIPE_SECRET_KEY = stripe/acme-web").unwrap();
    assert!(test < live, "{text}");
    // With no proposal, no such section.
    let none = render_statement(&descriptor(strings(&["./emit"])), &ticking(&[]));
    assert!(!none.contains("test keys of the same provider"), "{none}");
    assert!(!none.contains("or bind a test key"), "{none}");
}
