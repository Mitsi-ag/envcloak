//! Standing approvals (SPEC §10b "Standing approvals", M2 plan D-10,
//! task M2-15): code-identity extraction (macOS Team ID + signing ID, Linux
//! SHA-256 inside `install_trees`), direct vs managed launch conditions,
//! `classification = "test"` enforcement, 30-day TTL cap, scope matching and
//! grant minting, statement rendering and canonical bytes (`envcloak-statement/2`
//! and `envcloak-standing-confirm/1`), and `integrations/agents-digests.toml`
//! parity.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use envcloak_core::crypto::ItemClass;
use envcloak_core::vault::{
    Classification, CodeIdentity, FieldId, FieldKind, FieldMeta, FieldName, ItemDetails, ItemId,
    ItemMeta, LaunchRef, Slug,
};
use envcloak_policy::{
    AGENTS_DIGESTS_TOML, AccessRequest, AgentCatalog, AgentLabel, Ancestor, ApprovalOptions,
    ApprovalProof, ApproveError, BindingSource, BoundBinding, BoundRef, CatalogSource, ChainEnd,
    Claims, Decision, EnvName, GrantStore, MAX_STANDING_TTL, ManagedRequest, MatchBasis, Mode, Now,
    OptionsError, ProcessInstance, ProjectIdentity, ProofKind, STANDING_CONFIRM_DOMAIN,
    StandingError, StandingId, StandingRecord, StandingRecordSummary, StandingStore,
    SubjectEvidence, SubjectKind, canonical_confirm_statement, canonical_statement,
    check_test_bindings, confirm_statement_digest, describe_standing, extract_code_identity,
    extract_launch, recognized_release, render_confirm_statement, render_statement,
    statement_digest,
};
use envcloak_sys::{CodeSignature, ExeIdentity, StartTime};

fn now_at(secs: u64) -> Now {
    Now {
        wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000 + secs),
        awake: Duration::from_secs(1000 + secs),
        including_sleep: Duration::from_secs(1000 + secs),
    }
}

fn inst(pid: i32, exe: Option<ExeIdentity>) -> ProcessInstance {
    ProcessInstance {
        pid,
        start_time: StartTime::from_raw(10 * u64::try_from(pid).unwrap()),
        pidversion: None,
        exe,
    }
}

fn claude_label(basis: MatchBasis, source: CatalogSource) -> AgentLabel {
    AgentLabel {
        id: "claude-code".to_owned(),
        name: "Claude Code".to_owned(),
        product: "claude".to_owned(),
        source,
        basis,
    }
}

fn ancestor(pid: i32, sid: i32, exe: Option<ExeIdentity>, agent: Option<AgentLabel>) -> Ancestor {
    Ancestor {
        instance: inst(pid, exe),
        sid: Some(sid),
        terminal: None,
        agent,
    }
}

fn terminal_approver() -> SubjectEvidence {
    SubjectEvidence::from_chain(
        vec![
            ancestor(90, 70, None, None),
            ancestor(70, 70, None, None),
            ancestor(1, 1, None, None),
        ],
        ChainEnd::Top,
        true,
        Claims::default(),
        None,
    )
    .unwrap()
}

fn macos_claude_evidence(
    team: Option<&str>,
    identifier: &str,
    basis: MatchBasis,
    source: CatalogSource,
    env_selects_code: bool,
) -> SubjectEvidence {
    let exe = ExeIdentity {
        path: PathBuf::from("/Users/alice/.local/share/claude/versions/2.1.280"),
        file: None,
        sha256: None,
        signature: Some(CodeSignature {
            identifier: identifier.to_owned(),
            team_id: team.map(str::to_owned),
            cdhash: Some([0x11; 20]),
        }),
    };
    SubjectEvidence::from_chain(
        vec![
            ancestor(92, 70, None, None),
            ancestor(80, 70, Some(exe), Some(claude_label(basis, source))),
            ancestor(70, 70, None, None),
            ancestor(1, 1, None, None),
        ],
        ChainEnd::Top,
        false,
        Claims::default(),
        None,
    )
    .unwrap()
    .with_nearest_agent_env_selects_code(env_selects_code)
}

fn linux_claude_evidence(
    exe_path: &str,
    sha256: [u8; 32],
    env_selects_code: bool,
) -> SubjectEvidence {
    let exe = ExeIdentity {
        path: PathBuf::from(exe_path),
        file: Some((1, 100)),
        sha256: Some(sha256),
        signature: None,
    };
    SubjectEvidence::from_chain(
        vec![
            ancestor(92, 70, None, None),
            ancestor(
                80,
                70,
                Some(exe),
                Some(claude_label(MatchBasis::Executable, CatalogSource::Builtin)),
            ),
            ancestor(70, 70, None, None),
            ancestor(1, 1, None, None),
        ],
        ChainEnd::Top,
        false,
        Claims::default(),
        None,
    )
    .unwrap()
    .with_nearest_agent_env_selects_code(env_selects_code)
}

fn acme() -> ProjectIdentity {
    ProjectIdentity {
        canonical_dir: PathBuf::from("/src/acme-web"),
        dev: 1,
        ino: 100,
        manifest_path: PathBuf::from("/src/acme-web/envcloak.toml"),
    }
}

fn make_binding(env: &str, slug_str: &str, class: Classification) -> (ItemMeta, BoundRef) {
    let item = ItemId::generate();
    let field = FieldId::generate();
    let slug = Slug::new(slug_str).unwrap();
    let meta = ItemMeta {
        id: item,
        class: ItemClass::Secret,
        slug: slug.clone(),
        details: ItemDetails {
            classification: class,
            ..ItemDetails::default()
        },
        created_at: 0,
        updated_at: 0,
        fields: vec![FieldMeta {
            id: field,
            name: FieldName::new("value").unwrap(),
            kind: FieldKind::Value,
            prior_count: 0,
            created_at: 0,
            updated_at: 0,
        }],
        classification_changed_at: None,
        exposure: None,
        rotate_recommended: false,
        login: None,
    };
    let br = BoundRef {
        binding: BoundBinding {
            env_name: EnvName::new(env).unwrap(),
            item,
            field,
            classification: class,
        },
        slug,
        field_name: FieldName::new("value").unwrap(),
        first_use: false,
        source: BindingSource::Env,
    };
    (meta, br)
}

fn make_request(
    subject: SubjectEvidence,
    bindings: Vec<BoundRef>,
    managed: Option<ManagedRequest>,
) -> AccessRequest {
    AccessRequest {
        subject,
        project: acme(),
        manifest_sha256: [0xab; 32],
        bindings,
        mode: Mode::Inject,
        argv_display: vec!["./emit".to_owned()],
        new_project: false,
        managed,
    }
}

#[test]
fn agents_digests_toml_matches_integrations_file_and_resolves_pinned_releases() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let on_disk = std::fs::read_to_string(repo_root.join("integrations/agents-digests.toml"))
        .expect("integrations/agents-digests.toml must exist");
    assert_eq!(AGENTS_DIGESTS_TOML, on_disk);

    // Known Claude Code digest (2.1.280 x86_64-linux from versions.toml).
    let claude_x64 = [
        0x1e, 0x08, 0x50, 0x3d, 0xbd, 0xf3, 0xc2, 0xcb, 0x0d, 0x70, 0x6d, 0x32, 0xf3, 0x40, 0x82,
        0x77, 0x38, 0x8d, 0x1c, 0x76, 0xef, 0x10, 0x86, 0x73, 0xe8, 0xfe, 0x42, 0xc1, 0xb3, 0x22,
        0x92, 0x5b,
    ];
    assert_eq!(
        recognized_release("claude-code", &claude_x64).as_deref(),
        Some("2.1.280")
    );
    assert_eq!(recognized_release("codex", &claude_x64), None);
    assert_eq!(recognized_release("claude-code", &[0xff; 32]), None);
    assert_eq!(recognized_release("claude-code", &[0x00; 32]), None);
    // Empty-file SHA-256 must never be treated as a recognized release (F-04).
    let empty_sha256 = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];
    assert_eq!(recognized_release("claude-code", &empty_sha256), None);
}

#[test]
fn code_identity_extraction_enforces_macos_signature_and_linux_install_tree() {
    let catalog = AgentCatalog::builtin();
    let home = Path::new("/Users/alice");

    // 1. Terminal subject is refused.
    let term = terminal_approver();
    assert_eq!(
        extract_code_identity(&term, &catalog, Some(home)),
        Err(StandingError::IdentityNotStandingCapable)
    );

    // 2. Asserted match basis or Extension catalog source or code-selecting env is refused.
    for (basis, cat, env_sel) in [
        (MatchBasis::Asserted, CatalogSource::Builtin, false),
        (MatchBasis::Executable, CatalogSource::Extension, false),
        (MatchBasis::Executable, CatalogSource::Builtin, true),
    ] {
        let ev = macos_claude_evidence(
            Some("Q6L2SF6YDW"),
            "com.anthropic.claude-code",
            basis,
            cat,
            env_sel,
        );
        assert_eq!(
            extract_code_identity(&ev, &catalog, Some(home)),
            Err(StandingError::IdentityNotStandingCapable)
        );
    }

    // 3. macOS: valid Team ID + signing ID succeeds; ad-hoc (no team) or wrong Team ID fails.
    let mac_ok = macos_claude_evidence(
        Some("Q6L2SF6YDW"),
        "com.anthropic.claude-code",
        MatchBasis::Executable,
        CatalogSource::Builtin,
        false,
    );
    assert_eq!(
        extract_code_identity(&mac_ok, &catalog, Some(home)),
        Ok((
            "claude-code".to_owned(),
            CodeIdentity::MacSignature {
                team: "Q6L2SF6YDW".to_owned(),
                identifier: "com.anthropic.claude-code".to_owned(),
            }
        ))
    );

    let adhoc = macos_claude_evidence(
        None,
        "com.anthropic.claude-code",
        MatchBasis::Executable,
        CatalogSource::Builtin,
        false,
    );
    assert_eq!(
        extract_code_identity(&adhoc, &catalog, Some(home)),
        Err(StandingError::IdentityNotStandingCapable)
    );

    let wrong_team = macos_claude_evidence(
        Some("WRONGTEAM1"),
        "com.anthropic.claude-code",
        MatchBasis::Executable,
        CatalogSource::Builtin,
        false,
    );
    assert_eq!(
        extract_code_identity(&wrong_team, &catalog, Some(home)),
        Err(StandingError::IdentityNotStandingCapable)
    );

    // 4. Linux: path inside install_trees succeeds; path outside install_trees fails with
    //    IdentityOutsideInstallTree.
    let linux_ok = linux_claude_evidence(
        "/Users/alice/.local/share/claude/versions/2.1.280",
        [0x42; 32],
        false,
    );
    assert_eq!(
        extract_code_identity(&linux_ok, &catalog, Some(home)),
        Ok((
            "claude-code".to_owned(),
            CodeIdentity::LinuxSha256 {
                digests: vec![[0x42; 32]],
            }
        ))
    );

    let linux_outside = linux_claude_evidence("/tmp/claude", [0x42; 32], false);
    assert_eq!(
        extract_code_identity(&linux_outside, &catalog, Some(home)),
        Err(StandingError::IdentityOutsideInstallTree)
    );

    // 5. Completely unsigned / unhashed binary is refused.
    let unsigned_exe = ExeIdentity {
        path: PathBuf::from("/Users/alice/.local/share/claude/versions/2.1.280"),
        file: None,
        sha256: None,
        signature: None,
    };
    let unsigned_ev = SubjectEvidence::from_chain(
        vec![
            ancestor(92, 70, None, None),
            ancestor(
                80,
                70,
                Some(unsigned_exe),
                Some(claude_label(MatchBasis::Executable, CatalogSource::Builtin)),
            ),
            ancestor(70, 70, None, None),
            ancestor(1, 1, None, None),
        ],
        ChainEnd::Top,
        false,
        Claims::default(),
        None,
    )
    .unwrap();
    assert_eq!(
        extract_code_identity(&unsigned_ev, &catalog, Some(home)),
        Err(StandingError::IdentityNotStandingCapable)
    );
}

#[test]
fn launch_condition_enforces_bound_strength_and_refuses_bridged_launch() {
    let ev = macos_claude_evidence(
        Some("Q6L2SF6YDW"),
        "com.anthropic.claude-code",
        MatchBasis::Executable,
        CatalogSource::Builtin,
        false,
    );
    let (_, br) = make_binding(
        "STRIPE_SECRET_KEY",
        "stripe/acme-test",
        Classification::Test,
    );

    // Direct (no managed launch) -> Ok(None).
    let direct_req = make_request(ev.clone(), vec![br.clone()], None);
    assert_eq!(extract_launch(&direct_req), Ok(None));

    // Bound stdio launch -> Ok(Some(launch_ref)).
    let lref = LaunchRef {
        launch_id: [0x55; 16],
        revision: 1,
    };
    let bound_req = make_request(
        ev.clone(),
        vec![br.clone()],
        Some(ManagedRequest {
            launch: Some(lref),
            name: "claude-code/demo-mcp".to_owned(),
            written_by_migrate_mcp: false,
            registered_by: SubjectKind::Terminal,
            class: Some("native"),
            strength: Some("bound"),
            origin: None,
        }),
    );
    assert_eq!(extract_launch(&bound_req), Ok(Some(lref)));

    // Bridged or non-bound managed launch -> Err(LaunchNotStandingCapable).
    let bridged_req = make_request(
        ev,
        vec![br],
        Some(ManagedRequest {
            launch: Some(lref),
            name: "claude-code/demo-mcp".to_owned(),
            written_by_migrate_mcp: false,
            registered_by: SubjectKind::Terminal,
            class: None,
            strength: Some("bridged"),
            origin: Some("127.0.0.1:8080".to_owned()),
        }),
    );
    assert_eq!(
        extract_launch(&bridged_req),
        Err(StandingError::LaunchNotStandingCapable)
    );
}

#[test]
fn standing_store_create_match_self_update_and_revoke() {
    let catalog = AgentCatalog::builtin();
    let home = Path::new("/Users/alice");
    let now = now_at(0);

    let (meta_test, br_test) = make_binding(
        "STRIPE_SECRET_KEY",
        "stripe/acme-test",
        Classification::Test,
    );
    let (meta_live, br_live) = make_binding(
        "STRIPE_SECRET_KEY",
        "stripe/acme-live",
        Classification::Live,
    );

    let ev_linux = linux_claude_evidence(
        "/Users/alice/.local/share/claude/versions/2.1.280",
        [0xaa; 32],
        false,
    );

    // Non-test binding is refused by check_test_bindings and build_record.
    let live_req = make_request(ev_linux.clone(), vec![br_live], None);
    assert_eq!(
        check_test_bindings(&live_req, &[meta_live]),
        Err(StandingError::InvalidOptions(OptionsError::StandingNotTest))
    );

    let req = make_request(ev_linux.clone(), vec![br_test.clone()], None);
    let mut store = StandingStore::new();
    let ttl = Duration::from_secs(7 * 86_400);

    // Exceeding 30d TTL is refused.
    let too_long = ApprovalOptions::standing(MAX_STANDING_TTL + Duration::from_secs(1));
    assert_eq!(
        store.build_record(
            &req,
            &too_long,
            None,
            &catalog,
            Some(home),
            now.wall,
            std::slice::from_ref(&meta_test),
        ),
        Err(StandingError::InvalidOptions(OptionsError::TtlTooLong))
    );

    let opts = ApprovalOptions::standing(ttl);
    let rec = store
        .build_record(
            &req,
            &opts,
            None,
            &catalog,
            Some(home),
            now.wall,
            std::slice::from_ref(&meta_test),
        )
        .unwrap();
    let sid = rec.id;
    store.insert(rec);

    // Matching request on Linux with the same SHA-256 mints a session grant.
    let mut grants = GrantStore::new();
    grants.set_epochs(1, 1);
    let (matched_sid, _gid) = store
        .match_request(
            &req,
            &ev_linux,
            None,
            &now,
            std::slice::from_ref(&meta_test),
            &catalog,
            &mut grants,
        )
        .unwrap();
    assert_eq!(matched_sid, sid);

    // Subsequent request under the same agent root is covered by the minted session grant!
    assert!(matches!(
        grants.decide(req.clone(), &now),
        Decision::Covered(_)
    ));

    // Linux self-update (new SHA-256) does not match the standing record, but self_update_target
    // identifies the existing record for in-place digest append on re-approval.
    let ev_updated = linux_claude_evidence(
        "/Users/alice/.local/share/claude/versions/2.1.281",
        [0xcc; 32],
        false,
    );
    let req_updated = make_request(ev_updated.clone(), vec![br_test.clone()], None);
    assert!(
        store
            .find_matching(
                &req_updated,
                &ev_updated,
                None,
                now.wall,
                std::slice::from_ref(&meta_test),
                &catalog,
            )
            .is_none()
    );
    assert_eq!(
        store.self_update_target(
            &req_updated,
            &catalog,
            Some(home),
            now.wall,
            std::slice::from_ref(&meta_test),
        ),
        Some(sid)
    );

    let updated_rec = store
        .build_record(
            &req_updated,
            &opts,
            None,
            &catalog,
            Some(home),
            now.wall,
            std::slice::from_ref(&meta_test),
        )
        .unwrap();
    assert_eq!(updated_rec.id, sid);
    assert_eq!(
        updated_rec.code_identity,
        CodeIdentity::LinuxSha256 {
            digests: vec![[0xaa; 32], [0xcc; 32]],
        }
    );
    store.insert(updated_rec);

    // Now the updated binary matches!
    assert!(
        store
            .find_matching(
                &req_updated,
                &ev_updated,
                None,
                now.wall,
                std::slice::from_ref(&meta_test),
                &catalog,
            )
            .is_some()
    );

    // Poisoned direct launch (code_selecting_env present) does not match.
    let ev_poisoned = linux_claude_evidence(
        "/Users/alice/.local/share/claude/versions/2.1.280",
        [0xaa; 32],
        true,
    );
    let req_poisoned = make_request(ev_poisoned.clone(), vec![br_test], None);
    assert!(
        store
            .find_matching(
                &req_poisoned,
                &ev_poisoned,
                None,
                now.wall,
                std::slice::from_ref(&meta_test),
                &catalog,
            )
            .is_none()
    );

    // Reclassifying the bound item to Live or Unknown stops find_matching at use.
    let mut meta_reclassified = meta_test.clone();
    meta_reclassified.details.classification = Classification::Live;
    assert!(
        store
            .find_matching(
                &req,
                &ev_linux,
                None,
                now.wall,
                std::slice::from_ref(&meta_reclassified),
                &catalog,
            )
            .is_none()
    );
    meta_reclassified.details.classification = Classification::Unknown;
    assert!(
        store
            .find_matching(
                &req,
                &ev_linux,
                None,
                now.wall,
                std::slice::from_ref(&meta_reclassified),
                &catalog,
            )
            .is_none()
    );

    // Expiry invalidates matching.
    let after_expiry = now_at(7 * 86_400);
    assert!(
        store
            .find_matching(
                &req,
                &ev_linux,
                None,
                after_expiry.wall,
                std::slice::from_ref(&meta_test),
                &catalog,
            )
            .is_none()
    );

    // Revoke by id removes the record.
    assert!(store.remove(sid).is_some());
    assert!(store.is_empty(now.wall));
}

#[test]
fn grant_store_standing_approval_and_statement_rendering() {
    let now = now_at(0);
    let (meta_test, br_test) = make_binding(
        "STRIPE_SECRET_KEY",
        "stripe/acme-test",
        Classification::Test,
    );

    let unrecognized_ev = linux_claude_evidence(
        "/Users/alice/.local/share/claude/versions/2.1.280",
        [0x99; 32],
        false,
    );
    let req = make_request(unrecognized_ev, vec![br_test], None);
    let existing_sid = StandingId::generate();
    let standing_summary = describe_standing(&req, Some(existing_sid)).unwrap();
    assert_eq!(standing_summary.recognized_release, None);

    let mut grants = GrantStore::new();
    grants.set_epochs(1, 1);
    let pid = match grants.decide(req, &now) {
        Decision::Pending(id) => id,
        other => panic!("expected pending, got {other:?}"),
    };
    grants.set_pending_standing(&pid, Some(standing_summary.clone()));

    let desc = grants
        .pending_descriptor(&pid, &now, std::slice::from_ref(&meta_test))
        .unwrap();
    assert_eq!(desc.standing.as_ref(), Some(&standing_summary));

    let opts = ApprovalOptions::standing(Duration::from_secs(7 * 86_400));
    let rendered = render_statement(&desc, &opts);
    assert!(
        rendered.contains(
            "any Claude Code session in this project, including one started by another program, gets these keys without asking"
        ),
        "rendered:\n{rendered}"
    );
    assert!(
        rendered.contains("warning: unrecognized build: EnvCloak has not seen this binary"),
        "rendered:\n{rendered}"
    );
    assert!(
        rendered.contains("self-update: the approved binary changed; adds this binary's digest in place to standing record"),
        "rendered:\n{rendered}"
    );

    // Canonical statement commits to standing options and differs from a regular session approval.
    let session_opts = ApprovalOptions::session(Duration::from_secs(7 * 86_400));
    assert_ne!(
        canonical_statement(&desc, &opts),
        canonical_statement(&desc, &session_opts)
    );

    // Approve with standing succeeds for test bindings and fails if standing TTL > 30d.
    let bad_opts = ApprovalOptions::standing(MAX_STANDING_TTL + Duration::from_secs(1));
    let bad_digest = statement_digest(&desc, &bad_opts);
    assert_eq!(
        grants.check_approval(
            &pid,
            &bad_opts,
            bad_digest,
            &now,
            std::slice::from_ref(&meta_test)
        ),
        Err(ApproveError::InvalidOptions(OptionsError::TtlTooLong))
    );

    let digest = statement_digest(&desc, &opts);
    let gid = grants
        .approve(
            &pid,
            ApprovalProof {
                approver: terminal_approver(),
                kind: ProofKind::Passphrase,
            },
            opts,
            digest,
            &now,
            std::slice::from_ref(&meta_test),
        )
        .unwrap();
    assert!(grants.grants().any(|g| g.id == gid));

    // Confirm statement commits to records and renders cleanly.
    let summary = StandingRecordSummary {
        id: StandingId::generate().to_string(),
        agent_id: "claude-code".to_owned(),
        agent_name: "Claude Code".to_owned(),
        identity: "macos:Q6L2SF6YDW:com.anthropic.claude-code".to_owned(),
        project_dir: "/src/acme-web".to_owned(),
        launch: None,
        revision: None,
        bindings: vec!["STRIPE_SECRET_KEY=stripe/acme-test.value".to_owned()],
        created_secs: 1_800_000_000,
        remaining_secs: 86_400,
        not_after_secs: 1_800_086_400,
    };
    let cbytes = canonical_confirm_statement(std::slice::from_ref(&summary));
    assert!(cbytes.starts_with(STANDING_CONFIRM_DOMAIN));
    let cdigest = confirm_statement_digest(std::slice::from_ref(&summary));
    assert_ne!(cdigest, confirm_statement_digest(&[]));
    let crendered = render_confirm_statement(std::slice::from_ref(&summary));
    assert!(crendered.contains("Confirm standing approvals"));
    assert!(crendered.contains("Claude Code (claude-code)"));
}

#[test]
fn standing_record_round_trips_vault_format() {
    let catalog = AgentCatalog::builtin();
    let home = Path::new("/Users/alice");
    let now = now_at(0);
    let (meta_test, br_test) = make_binding(
        "STRIPE_SECRET_KEY",
        "stripe/acme-test",
        Classification::Test,
    );
    let ev = macos_claude_evidence(
        Some("Q6L2SF6YDW"),
        "com.anthropic.claude-code",
        MatchBasis::Executable,
        CatalogSource::Builtin,
        false,
    );
    let req = make_request(ev, vec![br_test], None);
    let store = StandingStore::new();
    let rec = store
        .build_record(
            &req,
            &ApprovalOptions::standing(Duration::from_secs(86_400)),
            None,
            &catalog,
            Some(home),
            now.wall,
            std::slice::from_ref(&meta_test),
        )
        .unwrap();
    let (pid, vrec) = rec.to_vault();
    let round_tripped = StandingRecord::from_vault(pid, &vrec);
    assert_eq!(round_tripped.id, rec.id);
    assert_eq!(round_tripped.agent_id, rec.agent_id);
    assert_eq!(round_tripped.code_identity, rec.code_identity);
    assert_eq!(round_tripped.bindings, rec.bindings);
}

#[test]
fn subset_session_grant_ends_on_sibling_item_reclassify_and_recently_denied_blocks_standing() {
    let catalog = AgentCatalog::builtin();
    let home = Path::new("/Users/alice");
    let now = now_at(0);

    let (meta_a, br_a) = make_binding(
        "STRIPE_SECRET_KEY",
        "stripe/acme-test",
        Classification::Test,
    );
    let (meta_b, br_b) = make_binding(
        "SENDGRID_API_KEY",
        "sendgrid/acme-test",
        Classification::Test,
    );
    let items = vec![meta_a.clone(), meta_b.clone()];

    let ev = linux_claude_evidence(
        "/Users/alice/.local/share/claude/versions/2.1.280",
        [0xaa; 32],
        false,
    );
    let full_req = make_request(ev.clone(), vec![br_a.clone(), br_b], None);
    let subset_req = make_request(ev.clone(), vec![br_a], None);

    let mut store = StandingStore::new();
    let rec = store
        .build_record(
            &full_req,
            &ApprovalOptions::standing(Duration::from_secs(86_400)),
            None,
            &catalog,
            Some(home),
            now.wall,
            &items,
        )
        .unwrap();
    store.insert(rec);

    let mut grants = GrantStore::new();
    grants.set_epochs(1, 1);

    // 1. Subset request for item A only mints a session grant from the (A, B) standing record.
    assert!(grants.can_try_standing(&subset_req, &now));
    let (_, gid) = store
        .match_request(&subset_req, &ev, None, &now, &items, &catalog, &mut grants)
        .unwrap();
    assert_eq!(grants.binding_item(meta_b.id), 1);

    // Reclassifying sibling item B ends the subset-derived session grant `gid` (F-02)!
    assert_eq!(grants.on_item_reclassified(meta_b.id), 1);
    assert!(grants.grant(gid).is_none());

    // 2. A recently denied request fingerprint is not eligible for `can_try_standing` (F-03).
    let mut store_empty = StandingStore::new();
    let _ = &mut store_empty;
    let pid = match grants.decide(subset_req.clone(), &now) {
        Decision::Pending(id) => id,
        other => panic!("expected pending, got {other:?}"),
    };
    grants.deny(&pid, &now).unwrap();
    assert!(!grants.can_try_standing(&subset_req, &now));
}
