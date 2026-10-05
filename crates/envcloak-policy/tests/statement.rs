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
    ApprovalOptions, BindingSource, BindingSummary, EnvName, Mode, PendingDescriptor,
    ProcessSummary, ProjectSummary, Proposal, RENDER_LIMIT, STATEMENT_DOMAIN, SubjectKind,
    SubjectSummary, Uses, canonical_statement, escape_for_display, live_guarded, render_statement,
    statement_digest, unticked_live,
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
        source: BindingSource::Env,
    }
}

/// `x` with its live binding from `source`.
fn from(x: Proposal, source: BindingSource) -> Proposal {
    Proposal { source, ..x }
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
/// file's descriptor without a proposal, with one from `[env]` and with one
/// from a profile, as the independent encoder
/// (`tests/oracles/statement.py`) gives them, fixed here so a change to
/// the format is a change to this test. The version 1 digest of
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
        "b53bf8045a752e521fedd2fe72df290b21a29e7831891d3b3b01beb6dc87b015"
    );
    let mut d = proposing(strings(&["./emit", "a b"]));
    d.proposals[0].source = BindingSource::Profile {
        profile: "dev".into(),
    };
    let profiled = statement_digest(&d, &o);
    assert_eq!(
        hex(&profiled),
        "fe3898bdc573ccb385aa0b41706119ac6619eddb64d829e3e055b97651b27d36"
    );
    const V1: &str = "825ff7c19353506ba2da685f5081d90f44238198147ad60708dd84276201053f";
    assert_ne!(hex(&plain), V1);
    assert_ne!(hex(&proposed), V1);
    assert_ne!(hex(&profiled), V1);
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
    // Each layer, a profile's name empty and multibyte, a line at its
    // bounds.
    for source in [
        BindingSource::Profile {
            profile: "dev".into(),
        },
        BindingSource::Profile {
            profile: String::new(),
        },
        BindingSource::Profile {
            profile: "中\u{202e}".into(),
        },
        BindingSource::EnvFile { line: 1 },
        BindingSource::EnvFile { line: u32::MAX },
        BindingSource::Ref,
    ] {
        several
            .proposals
            .push(from(proposal("X", "x/live", "x/test", None), source));
    }
    cases.push((several, once));
    // A pair whose proposals differ in their layer alone.
    let first_layer = cases.len();
    for source in [
        BindingSource::Env,
        BindingSource::Profile {
            profile: "env".into(),
        },
    ] {
        let mut d = proposing(strings(&["./emit"]));
        d.proposals[0].source = source;
        cases.push((d, o.clone()));
    }
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
    // The third: without the layers, the pair that differs in its layer
    // alone encodes alike; the crate tells it apart.
    let (a, b) = (&got[first_layer], &got[first_layer + 1]);
    assert_eq!(a["unsourced"], b["unsourced"]);
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
      to bind it: run `envcloak ref --manifest /src/acme-web/envcloak.toml STRIPE_SECRET_KEY=stripe/acme-test`
    OPENAI_API_KEY: the test key openai/acme-\\u{1b}[31mtest#api\\u{200b}key, not the live key openai/acme\\u{202e}-live
      to bind it: run `envcloak ref --manifest /src/acme-web/envcloak.toml OPENAI_API_KEY=openai/acme-\\u{1b}[31mtest#api\\u{200b}key`
  bindings (inject mode):
    OPENAI_API_KEY = openai/acme-web#value  (test key, first use: no project uses this item yet)
    STRIPE_SECRET_KEY = stripe/acme-web#value  (live key, live: not allowed by you, so this approval is refused unless you add --live STRIPE_SECRET_KEY)
  command (1 arguments):
    [0] ./emit
  grant: once, for the next matching request within 10m
  live keys: agent EnvCloak test fixture agent gets a live key only where you tick it, and this approval leaves 1 unticked, so it creates no grant (live_not_ticked). Approve again with --live STRIPE_SECRET_KEY, or bind the test key proposed above for STRIPE_SECRET_KEY.
Nothing is approved: no passphrase is asked for an approval that leaves a live key unticked.
";

/// Gate 40, sentence 2 (SPEC §10b): the test item is proposed first.
/// The rendering lists each proposal, with how to bind it (here the
/// `envcloak ref --manifest` line naming the request's manifest, for
/// bindings of `[env]`), before the bindings and
/// their ticks, every string escaped: a program answering in the daemon's
/// place could send anything. The whole statement is compared
/// ([`PROPOSED_SNAPSHOT`]); refused as it stands, it says that nothing is
/// approved, not what a passphrase approves.
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
    // With no proposal, no such section, and the refusal names no test
    // key.
    let none = render_statement(&descriptor(strings(&["./emit"])), &ticking(&[]));
    assert!(!none.contains("test keys of the same provider"), "{none}");
    assert!(!none.contains("or bind"), "{none}");
    assert!(none.contains("Nothing is approved"), "{none}");
    assert!(!none.contains("The passphrase you enter"), "{none}");
    // Ticked, the approval goes ahead: the statement says what the
    // passphrase approves.
    let ticked = render_statement(&d, &ticking(&["STRIPE_SECRET_KEY"]));
    assert!(
        ticked.ends_with("The passphrase you enter approves exactly this, and nothing else.\n")
    );
    assert!(!ticked.contains("Nothing is approved"), "{ticked}");
}

/// The refusal's tail names a test key only for an unticked binding a
/// proposal is for (verifier, round 2: it said "or bind a test key" when
/// the only proposal was for another binding, or for none).
///
/// Mutation: the tail on any proposal at all (`!p.proposals.is_empty()`
/// in place of `proposed_for`): the statement whose proposal is for a
/// ticked binding says "or bind" and this fails.
#[test]
fn the_refusal_names_a_test_key_only_for_an_unticked_binding() {
    let mut d = of_kind(
        SubjectKind::Agent,
        &[("A_KEY", "a/live", "live"), ("B_KEY", "b/live", "live")],
    );
    d.proposals = vec![proposal("B_KEY", "b/live", "b/test", None)];
    // B is ticked, A is not: A has no test key to bind.
    let text = render_statement(&d, &ticking(&["B_KEY"]));
    assert!(text.contains("Approve again with --live A_KEY."), "{text}");
    assert!(!text.contains("or bind"), "{text}");
    // Neither ticked: B's test key is named, for B alone.
    let text = render_statement(&d, &ticking(&[]));
    assert!(
        text.contains(
            "Approve again with --live A_KEY --live B_KEY, or bind the test key proposed \
             above for B_KEY."
        ),
        "{text}"
    );
}

/// How to bind the test item follows the layer the live binding came from
/// (verifier and Codex, round 2: `envcloak ref NAME=...` writes `[env]`,
/// which a profile, an env file or a `--ref` replaces, so following it
/// asked for the live item again): `[env]` and a profile name the
/// `envcloak ref` line, with `--profile` for a profile; an env file names
/// its line; a `--ref` says to give another. The `envcloak ref` line names
/// the request's manifest (Codex, round 3: alone, it edits the manifest
/// nearest the directory of the terminal that follows it, which need not
/// be the project's, after `run --manifest` or in a person's own
/// terminal). That following each binds the test item, from an unrelated
/// directory too, is checked end to end in
/// `crates/envcloak-cli/tests/live_guard.rs`.
///
/// Mutations: every layer advised as `[env]` (`advice` answering
/// `envcloak ref NAME=...` whatever the source): the profile, env file and
/// `--ref` cases fail; the manifest left out of the line: the `[env]` and
/// profile cases fail.
#[test]
fn the_advice_follows_the_layer_the_live_binding_came_from() {
    const M: &str = "/src/acme-web/envcloak.toml";
    let none = |_: &str| false;
    let with = |source| {
        from(
            proposal("STRIPE_KEY", "stripe/live", "stripe/test", Some("secret")),
            source,
        )
    };
    let cases = [
        (
            BindingSource::Env,
            "run `envcloak ref --manifest /src/acme-web/envcloak.toml \
             STRIPE_KEY=stripe/test#secret`",
        ),
        (
            BindingSource::Profile {
                profile: "dev".into(),
            },
            "run `envcloak ref --manifest /src/acme-web/envcloak.toml --profile dev \
             STRIPE_KEY=stripe/test#secret`",
        ),
        (
            BindingSource::EnvFile { line: 7 },
            "set line 7 of the --env-file to `STRIPE_KEY=envcloak://stripe/test#secret`",
        ),
        (
            BindingSource::Ref,
            "give `--ref STRIPE_KEY=stripe/test#secret` in place of the --ref for STRIPE_KEY",
        ),
    ];
    for (source, advice) in cases {
        let x = with(source);
        assert_eq!(x.advice(M, &none), advice);
        // The statement shows the same advice.
        let mut d = proposing(strings(&["./emit"]));
        d.proposals = vec![x];
        let text = render_statement(&d, &ticking(&[]));
        assert!(
            text.contains(&format!("      to bind it: {advice}\n")),
            "{text}"
        );
    }
}

/// The manifest in the `envcloak ref` line is one shell word: as it is
/// when a shell takes every character as itself, else in single quotes,
/// a quote in it closed, escaped and reopened, so a path with spaces, a
/// quote or a shell's own characters, or one a program answering in the
/// daemon's place chose (SPEC §1.1), is that one argument when the line
/// is pasted and runs nothing. A path with a character the display
/// escapes (a control or an invisible one) cannot be shown as the word
/// it is: the line names the manifest, escaped, and says to run it in its
/// directory. A `/bin/sh` reading each word back is the independent check
/// that the quoting gives the path whole and runs nothing.
///
/// Mutation: the path put in the line as it is (`shell_word` answering
/// `Some(s.to_owned())`): the space, quote and `$(...)` cases split or
/// run, and this fails.
#[test]
fn the_manifest_in_the_line_is_one_shell_word() {
    use envcloak_policy::shell_word;
    let none = |_: &str| false;
    let x = proposal("STRIPE_KEY", "stripe/live", "stripe/test", None);
    assert_eq!(
        shell_word("/src/acme-web/envcloak.toml").as_deref(),
        Some("/src/acme-web/envcloak.toml")
    );
    let ran = std::env::temp_dir().join(format!("ecsw-{}", std::process::id()));
    let hostile = [
        "/src/my project/envcloak.toml".to_owned(),
        "/src/it's/envcloak.toml".to_owned(),
        "/src/a\\b/envcloak.toml".to_owned(),
        format!("/src/$(touch {})/envcloak.toml", ran.display()),
        "/src/`id`;*?[x]~/envcloak.toml".to_owned(),
        "/src/''\"\"/envcloak.toml".to_owned(),
    ];
    for path in &hostile {
        let word = shell_word(path).unwrap();
        assert!(word.starts_with('\''), "{word}");
        // Read back by a shell: the one argument, nothing run.
        let out = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(format!("printf '%s\\n' {word}"))
            .env_clear()
            .output()
            .unwrap();
        assert!(out.status.success(), "{word}");
        let mut expected = path.as_bytes().to_vec();
        expected.push(b'\n');
        assert_eq!(out.stdout, expected, "{word}");
        let advice = x.advice(path, &none);
        assert!(
            advice.starts_with(&format!("run `envcloak ref --manifest {word} STRIPE_KEY=")),
            "{advice}"
        );
    }
    assert!(!ran.exists(), "a quoted path ran a command");
    // Shown escaped, a control or an invisible character is not itself:
    // the line names the manifest and says where to run it.
    for path in [
        "/src/a\nb/envcloak.toml",
        "/src/a\u{202e}b/envcloak.toml",
        "",
    ] {
        assert_eq!(shell_word(path), None, "{path:?}");
        let advice = x.advice(path, &none);
        assert_eq!(
            advice,
            format!(
                "run `envcloak ref STRIPE_KEY=stripe/test` in the directory of the manifest {}",
                envcloak_policy::escape_for_display(path)
            )
        );
    }
}

/// A proposal is not approved, so a name of one shaped like a key or
/// token is not shown: generated canaries, each a valid variable name,
/// slug, field or profile name of a key's shape, never reach the statement
/// or the advice, and [`HIDDEN`] stands in their place (Codex, round 2:
/// the proposal paths escaped names but did not mask them). The bindings,
/// which the passphrase approves, are shown whole (gate 23). The positive
/// control: the same names, not taken for keys, are shown.
///
/// Mutation: the names escaped only (`shown_name` answering
/// `escape_for_display` whatever it is asked): the canaries are in the
/// text and this fails.
#[test]
fn a_proposed_name_shaped_like_a_key_is_not_shown() {
    use envcloak_policy::{HIDDEN, render_statement_with, value_shaped};
    // A key's shape from generated canaries: their letters and digits,
    // lower case (a slug's, a field's and a profile's grammar), 48 of them.
    let cs = envcloak_testkit::canaries(envcloak_testkit::fresh_seed());
    let token: String = cs
        .iter()
        .flat_map(|c| c.value().to_vec())
        .filter(u8::is_ascii_alphanumeric)
        .map(|b| char::from(b).to_ascii_lowercase())
        .take(42)
        .chain("x1y2z3".chars())
        .collect();
    assert_eq!(token.len(), 48);
    assert!(value_shaped(&token), "{token}");
    let upper = token.to_ascii_uppercase();
    for x in [
        proposal(&format!("K{upper}"), "stripe/live", "stripe/test", None),
        proposal("KEY", &format!("stripe/{token}"), "stripe/test", None),
        proposal("KEY", "stripe/live", &format!("stripe/{token}"), None),
        proposal("KEY", "stripe/live", "stripe/test", Some(&token)),
        from(
            proposal("KEY", "stripe/live", "stripe/test", None),
            BindingSource::Profile {
                profile: token.clone(),
            },
        ),
    ] {
        assert!(x.well_formed(), "{x:?}");
        let mut d = proposing(strings(&["./emit"]));
        d.proposals = vec![x.clone()];
        for text in [
            render_statement(&d, &ticking(&[])),
            render_statement_with(&d, &ticking(&[]), &value_shaped),
        ] {
            assert!(!text.to_ascii_lowercase().contains(&token), "{text}");
            assert!(text.contains(HIDDEN), "{text}");
        }
        // The advice names no live slug; the rest is hidden there too.
        let advice = x.advice("/src/acme-web/envcloak.toml", &value_shaped);
        assert!(!advice.to_ascii_lowercase().contains(&token), "{advice}");
        // The control: not taken for a key, the name is shown.
        let shown = render_statement_with(&d, &ticking(&[]), &|_| false);
        assert!(shown.to_ascii_lowercase().contains(&token[..24]), "{shown}");
        assert!(!shown.contains(HIDDEN), "{shown}");
    }
    // A binding's own name is shown whole: the passphrase approves it.
    let mut d = of_kind(SubjectKind::Terminal, &[("KEY", "stripe/live", "live")]);
    d.bindings[0].slug = format!("stripe/{token}");
    let text = render_statement(&d, &ticking(&[]));
    assert!(text.contains(&format!("stripe/{token}")), "{text}");
}
