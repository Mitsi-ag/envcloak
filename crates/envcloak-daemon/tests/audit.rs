//! The audit log through a running daemon (SPEC §6.1 step 5, §15.2 gate
//! 33): every decision has a sealed entry, a covered request's entry is
//! written before the answer and a failure to write it denies the request,
//! command lines are masked before they are sealed, the head is saved in
//! the vault's header at stop, and `audit.verify` reports tampering at its
//! sequence number.
//!
//! The caller is this test process, made a terminal session so the daemon
//! takes its proofs (see crates/envcloak-daemon/tests/grants.rs). After
//! the daemon stops, the test opens the vault itself with the canary
//! passphrase and reads the entries back.
#![allow(clippy::unwrap_used)]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use base64::Engine as _;
use common::{MANIFEST, client, data_dir, passphrase, project, seed_vault, start};
use envcloak_core::SecretBytes;
use envcloak_core::audit::{AuditEntry, AuditKind, ProblemKind, VerifyReport};
use envcloak_core::crypto::ItemClass;
use envcloak_core::vault::{FieldName, ItemDetails, LockedVault, NewItem, Slug, VaultPaths};
use envcloak_ipc::ClientError;
use envcloak_ipc::proto::{ErrorKind, RunRequestParams};
use envcloak_ipc::view::{AnchorState, AuditProblemKind, DecisionView};
use envcloak_policy::{ApprovalOptions, DenyReason, GrantId, PendingId, statement_digest};
use envcloak_testkit::{
    Canary, Daemon, TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels,
};

struct Fixture {
    cs: Vec<Canary>,
    home: TestHome,
    d: Daemon,
    manifest: String,
}

impl Fixture {
    fn new() -> Self {
        Self::with(|_| {}, MANIFEST)
    }

    /// The story's vault, then `more` done to it before the daemon starts,
    /// and a project with `manifest`.
    fn with(more: impl FnOnce(&mut envcloak_core::vault::Vault), manifest: &str) -> Self {
        common::terminal_session();
        let cs = canaries(fresh_seed());
        let home = TestHome::new();
        let kit = seed_vault(&home, &cs);
        let mut cs = cs;
        cs.push(kit);
        let mut v = LockedVault::open(&VaultPaths::under(data_dir(&home)))
            .unwrap()
            .unlock_with_passphrase(&passphrase(&cs))
            .map_err(|(_, e)| e)
            .unwrap();
        more(&mut v);
        drop(v);
        let d = start(&home);
        client(&home).unlock(passphrase(&cs), &[]).unwrap();
        let manifest = project(&home, "acme-web", manifest);
        Fixture {
            cs,
            home,
            d,
            manifest: manifest.to_str().unwrap().to_owned(),
        }
    }

    fn value(&self, label: &str) -> String {
        by_label(&self.cs, label).as_str().to_owned()
    }

    fn request(&self, argv: &[String], profile: Option<&str>) -> DecisionView {
        client(&self.home)
            .run_request(&RunRequestParams {
                manifest: self.manifest.clone(),
                profile: profile.map(str::to_owned),
                refs: Vec::new(),
                env_file: None,
                argv: argv.to_vec(),
                claims: Vec::new(),
            })
            .unwrap()
            .decision
    }

    fn approve(&self, id: &str, opts: ApprovalOptions, pass: &[u8]) -> Option<String> {
        let mut c = client(&self.home);
        let d = c.pending_get(id, &[]).unwrap();
        let digest = statement_digest(&d, &opts);
        c.approve(id, opts, &digest, SecretBytes::copy_from(pass), &[])
            .ok()
            .map(|a| a.grant)
    }

    fn pass(&self) -> &[u8] {
        by_label(&self.cs, labels::VAULT_PASSPHRASE).value()
    }

    fn audit_dir(&self) -> std::path::PathBuf {
        data_dir(&self.home).join("audit")
    }

    /// Stops the daemon with SIGTERM, which locks the vault (and saves the
    /// log's head), then opens the vault here and reads the log.
    fn stop_and_read(&mut self) -> (Vec<AuditEntry>, VerifyReport, Option<u64>) {
        self.d.signal("-TERM");
        assert!(self.d.wait_exit(Duration::from_secs(30)).is_some());
        let v = LockedVault::open(&VaultPaths::under(data_dir(&self.home)))
            .unwrap()
            .unlock_with_passphrase(&passphrase(&self.cs))
            .map_err(|(_, e)| e)
            .unwrap();
        let (entries, report) = v.read_audit().unwrap();
        let saved = v.header().unwrap().audit_head.map(|h| h.seq);
        (entries, report, saved)
    }

    fn sweep(&self, entries: &[AuditEntry]) {
        for e in entries {
            assert_no_canary(format!("{:?}", e.record).as_bytes(), &self.cs);
        }
        assert_no_canary(&self.d.log_bytes(), &self.cs);
        self.home.assert_clean(&self.cs);
    }
}

fn pending(d: &DecisionView) -> String {
    match d {
        DecisionView::Pending { request } => {
            PendingId::parse(request).unwrap();
            request.clone()
        }
        other => panic!("expected pending, got {other:?}"),
    }
}

fn covered(d: &DecisionView) -> String {
    match d {
        DecisionView::Covered { grant, .. } => {
            GrantId::parse(grant).unwrap();
            grant.clone()
        }
        other => panic!("expected covered, got {other:?}"),
    }
}

/// What each entry says, as (kind, outcome, reason).
fn outline(entries: &[AuditEntry]) -> Vec<(AuditKind, String, Option<String>)> {
    entries
        .iter()
        .map(|e| {
            (
                e.record.kind,
                e.record.decision.outcome.clone(),
                e.record.decision.reason.clone(),
            )
        })
        .collect()
}

fn o(kind: AuditKind, outcome: &str, reason: Option<&str>) -> (AuditKind, String, Option<String>) {
    (kind, outcome.to_owned(), reason.map(str::to_owned))
}

/// Gate 33: each decision has an entry, in order, with the caller, the
/// project, the items and the grant or request; the command line an agent
/// might paste keys into is masked (the request's values by the redactor,
/// other keys by the registry's patterns) before it is sealed; no canary
/// is in any entry, the log's files or the daemon's output; and the head
/// is saved at stop.
#[test]
fn every_decision_is_sealed_with_its_command_line_masked() {
    let mut f = Fixture::new();
    let openai = f.value(labels::OPENAI_API_KEY);
    let stripe = f.value(labels::STRIPE_SECRET_KEY);
    let github = f.value(labels::GITHUB_TOKEN);
    let argv: Vec<String> = vec![
        "./emit".into(),
        format!("--key={openai}"),
        format!("Authorization: Bearer {github}"),
        stripe.clone(),
        "--flag".into(),
    ];

    let id = pending(&f.request(&argv, None));
    assert_eq!(
        f.approve(
            &id,
            ApprovalOptions::session(Duration::from_secs(3600)),
            b"not the passphrase at all"
        ),
        None
    );
    let grant = f
        .approve(
            &id,
            ApprovalOptions::session(Duration::from_secs(3600)),
            f.pass(),
        )
        .unwrap();
    assert_eq!(covered(&f.request(&argv, None)), grant);
    let short = pending(&f.request(&["./emit".to_owned()], Some("short")));
    client(&f.home).deny(&short).unwrap();
    assert_eq!(client(&f.home).grants_revoke(None).unwrap().revoked, 1);

    let (entries, report, saved) = f.stop_and_read();
    assert!(report.ok(), "{report:?}");
    let last = entries.last().unwrap().seq;
    assert_eq!(saved, Some(last), "the head is saved at stop");
    assert_eq!(report.unanchored_tail, None);
    assert_eq!(
        outline(&entries),
        vec![
            o(AuditKind::Unlock, "unlocked", None),
            o(AuditKind::Run, "pending", None),
            o(AuditKind::Approve, "failed", Some("wrong_passphrase")),
            o(AuditKind::Approve, "approved", Some("session")),
            o(AuditKind::Run, "covered", None),
            o(AuditKind::Run, "pending", None),
            o(AuditKind::Deny, "denied", None),
            o(AuditKind::Revoke, "revoked", None),
            o(AuditKind::Lock, "locked", Some("signal")),
        ]
    );
    let seqs: Vec<u64> = entries.iter().map(|e| e.seq).collect();
    assert_eq!(seqs, (1..=9).collect::<Vec<u64>>());

    let delivery = &entries[4].record;
    assert_eq!(delivery.grant_id.as_deref(), Some(grant.as_str()));
    let slugs: Vec<&str> = delivery.items.iter().map(|(_, s)| s.as_str()).collect();
    assert_eq!(slugs, vec!["openai/acme-web", "stripe/acme-web"]);
    let me = i32::try_from(std::process::id()).unwrap();
    assert_eq!(delivery.subject.pid, me);
    assert_eq!(delivery.subject.kind.as_deref(), Some("terminal"));
    assert!(
        delivery.project.as_ref().unwrap().dir.ends_with("acme-web"),
        "{:?}",
        delivery.project
    );
    assert_eq!(
        delivery.argv_redacted,
        vec![
            "./emit",
            "--key=[envcloak:openai/acme-web]",
            "Authorization: Bearer [envcloak:key:github]",
            "[envcloak:stripe/acme-web]",
            "--flag",
        ]
    );
    assert_eq!(entries[1].record.argv_redacted, delivery.argv_redacted);
    assert_eq!(entries[1].record.request_id.as_deref(), Some(id.as_str()));
    assert_eq!(entries[3].record.grant_id.as_deref(), Some(grant.as_str()));
    assert_eq!(
        entries[6].record.request_id.as_deref(),
        Some(short.as_str())
    );
    assert_eq!(entries[7].record.decision.count, Some(1));
    f.sweep(&entries);
}

/// Gate 33: when a covered request's entry cannot be written, the request
/// is denied (`audit_failed`), nothing is released, and a `once` grant is
/// left for the next try; the denial itself waits in memory and is
/// written once the log can be. The removed entries are flagged.
#[test]
fn an_audit_write_failure_denies_the_request_and_keeps_the_once_grant() {
    let mut f = Fixture::new();
    let argv = vec!["./emit".to_owned()];
    let id = pending(&f.request(&argv, None));
    let grant = f
        .approve(
            &id,
            ApprovalOptions::once(Duration::from_secs(3600)),
            f.pass(),
        )
        .unwrap();

    // Another program running as the user removes the log's directory and
    // puts a file in its place: no entry can be written.
    let dir = f.audit_dir();
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::write(&dir, b"in the way").unwrap();
    let d = f.request(&argv, None);
    assert_eq!(
        d,
        DecisionView::Denied {
            reason: "audit_failed".into()
        }
    );
    assert_eq!(d.deny_reason(), Some(DenyReason::AuditFailed));
    let grants = client(&f.home).grants_list().unwrap().grants;
    assert_eq!(grants.len(), 1, "the once grant was not used");
    assert_eq!(grants[0].id, grant);
    let st = client(&f.home).status().unwrap();
    assert_eq!(st.audit.queued, 1);

    std::fs::remove_file(&dir).unwrap();
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(covered(&f.request(&argv, None)), grant);
    pending(&f.request(&argv, None));
    assert_eq!(client(&f.home).status().unwrap().audit.queued, 0);

    let (entries, report, _) = f.stop_and_read();
    // Entries 1 to 3 went with the removed directory.
    assert_eq!(report.first_problem.map(|p| p.seq), Some(1), "{report:?}");
    assert_eq!(
        outline(&entries),
        vec![
            o(AuditKind::Run, "denied", Some("audit_failed")),
            o(AuditKind::Run, "covered", None),
            o(AuditKind::Run, "pending", None),
            o(AuditKind::Lock, "locked", Some("signal")),
        ]
    );
    assert_eq!(entries[0].seq, 4);
    assert_eq!(entries[0].record.grant_id.as_deref(), Some(grant.as_str()));
    f.sweep(&entries);
}

/// `audit.verify` over the socket: the chain checks out with the whole
/// log as the unanchored tail until a head is saved; after a lock and an
/// unlock the anchor matches; an entry changed on disk is reported at its
/// sequence number; and a log cut back while the daemon runs no longer
/// ends where the daemon last wrote it.
#[test]
fn audit_verify_reports_the_anchor_the_tail_and_tampering() {
    let f = Fixture::new();
    let mut c = client(&f.home);
    pending(&f.request(&["./emit".to_owned()], None));
    let v = c.audit_verify().unwrap();
    assert_eq!(v.first_problem, None);
    assert_eq!(v.anchor.state, AnchorState::None);
    assert_eq!(v.last_seq, 2);
    assert_eq!(v.unanchored_tail.map(|t| (t.first, t.last)), Some((1, 2)));
    assert_eq!(v.live_head_matches, Some(true));

    c.lock().unwrap();
    match c.audit_verify() {
        Err(ClientError::Rpc(r)) => assert_eq!(r.kind, ErrorKind::VaultLocked),
        other => panic!("expected vault_locked, got {other:?}"),
    }
    c.unlock(passphrase(&f.cs), &[]).unwrap();
    let v = c.audit_verify().unwrap();
    assert_eq!(v.first_problem, None);
    assert_eq!(
        (v.anchor.state, v.anchor.seq),
        (AnchorState::Matched, Some(3))
    );
    assert_eq!(v.unanchored_tail.map(|t| (t.first, t.last)), Some((4, 4)));
    let st = c.status().unwrap();
    assert!(st.audit.open);
    assert_eq!(st.audit.head_seq, Some(4));
    assert_eq!(st.audit.unanchored, 1);

    // Flip a byte in entry 2's sealed bytes.
    let seg = f.audit_dir().join(format!("{:020}.seg", 1));
    let orig = std::fs::read(&seg).unwrap();
    let header = envcloak_core::audit::HEADER_LEN;
    let first_len = u32::from_be_bytes(orig[header..header + 4].try_into().unwrap()) as usize;
    let second = header + 12 + first_len + 32;
    let mut b = orig.clone();
    b[second + 12 + 30] ^= 1;
    std::fs::write(&seg, &b).unwrap();
    let v = c.audit_verify().unwrap();
    let p = v.first_problem.unwrap();
    assert_eq!((p.seq, p.kind), (2, AuditProblemKind::Altered));

    // Cut back to entry 1: the anchor (3) is gone, and the daemon's own
    // head is not where the log ends.
    std::fs::write(&seg, &orig[..second]).unwrap();
    let v = c.audit_verify().unwrap();
    assert_eq!(v.first_problem.map(|p| p.seq), Some(2));
    assert_eq!(v.anchor.state, AnchorState::Missing);
    assert_eq!(v.live_head_matches, Some(false));
    assert_no_canary(&f.d.log_bytes(), &f.cs);
}

/// Codex F-44, through the daemon: after the log's segment is renamed out
/// of its directory, and after the directory itself is renamed away, a
/// covered request's entry still goes into the log before the answer, in a
/// new segment where the log is; nothing goes into the moved files. The
/// entries that went with them are flagged as missing.
#[test]
fn a_moved_segment_or_directory_does_not_take_a_delivery_with_it() {
    let mut f = Fixture::new();
    let argv = vec!["./emit".to_owned()];
    let id = pending(&f.request(&argv, None));
    let grant = f
        .approve(
            &id,
            ApprovalOptions::session(Duration::from_secs(3600)),
            f.pass(),
        )
        .unwrap();
    let dir = f.audit_dir();
    let seg = |n: u64| format!("{n:020}.seg");
    let outside = f.home.root().join("moved");
    std::fs::create_dir(&outside).unwrap();

    // Entries 1 to 3 (unlock, pending, approve) are in segment 1: it is
    // renamed out of the directory.
    let renamed = outside.join("renamed");
    std::fs::rename(dir.join(seg(1)), &renamed).unwrap();
    let renamed_len = std::fs::metadata(&renamed).unwrap().len();
    assert_eq!(covered(&f.request(&argv, None)), grant);
    assert_eq!(std::fs::metadata(&renamed).unwrap().len(), renamed_len);
    assert!(dir.join(seg(4)).is_file(), "entry 4 started a new segment");

    // The directory renamed away.
    let aside = f.home.root().join("audit.aside");
    std::fs::rename(&dir, &aside).unwrap();
    let aside_len = std::fs::metadata(aside.join(seg(4))).unwrap().len();
    assert_eq!(covered(&f.request(&argv, None)), grant);
    assert_eq!(
        std::fs::metadata(aside.join(seg(4))).unwrap().len(),
        aside_len
    );
    assert!(dir.join(seg(5)).is_file(), "entry 5 is where the log is");

    let (entries, report, saved) = f.stop_and_read();
    assert_eq!(
        report.first_problem.map(|p| (p.seq, p.kind)),
        Some((1, ProblemKind::Missing)),
        "{report:?}"
    );
    assert_eq!(
        outline(&entries),
        vec![
            o(AuditKind::Run, "covered", None),
            o(AuditKind::Lock, "locked", Some("signal")),
        ]
    );
    assert_eq!(entries[0].seq, 5);
    assert_eq!(entries[0].record.grant_id.as_deref(), Some(grant.as_str()));
    assert_eq!(saved, Some(6));
    f.sweep(&entries);
}

/// Gate 33: the redactor does not look for a value under its 8-byte floor,
/// raw or encoded, so a request that binds one keeps none of its command
/// line; a value in an encoding the redactor covers (base64, hex) is masked
/// like the raw one.
#[test]
fn a_short_value_withholds_the_command_line_and_an_encoded_one_is_masked() {
    const PIN: &str = "Zq!7x";
    let add_pin = |v: &mut envcloak_core::vault::Vault| {
        v.transact(|t| {
            let id = t.create_item(NewItem {
                class: ItemClass::Secret,
                slug: Slug::new("pin/acme-web").unwrap(),
                details: ItemDetails {
                    title: "pin".to_owned(),
                    ..ItemDetails::default()
                },
            })?;
            t.add_field(
                id,
                FieldName::new("value").unwrap(),
                SecretBytes::copy_from(PIN.as_bytes()),
            )?;
            Ok(())
        })
        .unwrap();
    };
    let manifest = format!("{MANIFEST}\n[env.pin]\nPIN_CODE = \"pin/acme-web\"\n");
    let mut f = Fixture::with(add_pin, &manifest);
    let b64 = base64::engine::general_purpose::STANDARD;
    let openai = f.value(labels::OPENAI_API_KEY);
    let stripe = f.value(labels::STRIPE_SECRET_KEY);
    let hex: String = stripe.bytes().map(|b| format!("{b:02x}")).collect();
    pending(&f.request(
        &[
            "./emit".to_owned(),
            format!("--b64={}", b64.encode(&openai)),
            hex,
        ],
        None,
    ));
    let pin_b64 = b64.encode(PIN);
    pending(&f.request(
        &[
            "./emit".to_owned(),
            format!("--pin={PIN}"),
            format!("--pin64={pin_b64}"),
        ],
        Some("pin"),
    ));

    let (entries, report, _) = f.stop_and_read();
    assert!(report.ok(), "{report:?}");
    assert_eq!(
        entries[1].record.argv_redacted,
        vec![
            "./emit",
            "--b64=[envcloak:openai/acme-web]",
            "[envcloak:stripe/acme-web]"
        ]
    );
    assert_eq!(
        entries[2].record.argv_redacted,
        vec!["[envcloak: command line not kept: the request binds a value too short to mask]"]
    );
    for e in &entries {
        let text = format!("{:?}", e.record);
        assert!(!text.contains(PIN) && !text.contains(&pin_b64), "{text}");
    }
    f.sweep(&entries);
}

/// Gate 33: a value of 8 to 10 bytes is masked raw, but the redactor does
/// not find it inside a longer base64 stream at every alignment (it lists
/// the value as partial), so `Authorization: Basic base64(user:<value>)`
/// would be sealed with the value recoverable. A request that binds one
/// keeps none of its command line, as for a value under the floor.
#[test]
fn a_value_masked_only_in_part_withholds_the_command_line() {
    // Eight letters, made at run time.
    let seed = fresh_seed();
    let token: String = (0..8u32)
        .map(|i| char::from(b'a' + u8::try_from((seed >> (5 * i)) % 26).unwrap()))
        .collect();
    let value = token.clone();
    let add_token = move |v: &mut envcloak_core::vault::Vault| {
        v.transact(|t| {
            let id = t.create_item(NewItem {
                class: ItemClass::Secret,
                slug: Slug::new("basic/acme-web").unwrap(),
                details: ItemDetails {
                    title: "basic".to_owned(),
                    allow_short: true,
                    ..ItemDetails::default()
                },
            })?;
            t.add_field(
                id,
                FieldName::new("value").unwrap(),
                SecretBytes::copy_from(value.as_bytes()),
            )?;
            Ok(())
        })
        .unwrap();
    };
    let manifest = format!("{MANIFEST}\n[env.basic]\nBASIC_TOKEN = \"basic/acme-web\"\n");
    let mut f = Fixture::with(add_token, &manifest);
    let b64 = base64::engine::general_purpose::STANDARD;
    let header = format!(
        "Authorization: Basic {}",
        b64.encode(format!("user:{token}"))
    );
    pending(&f.request(
        &[
            "curl".to_owned(),
            "-H".to_owned(),
            header,
            "--flag".to_owned(),
        ],
        Some("basic"),
    ));

    let (entries, report, _) = f.stop_and_read();
    assert!(report.ok(), "{report:?}");
    assert_eq!(
        outline(&entries)[1],
        o(AuditKind::Run, "pending", None),
        "{entries:?}"
    );
    // Neither the value nor any encoding the testkit knows (base64 at
    // each alignment among them) is in any entry.
    let canary = Canary::new("BASIC_TOKEN", token);
    for e in &entries {
        assert_no_canary(
            format!("{:?}", e.record).as_bytes(),
            std::slice::from_ref(&canary),
        );
    }
    assert_eq!(
        entries[1].record.argv_redacted,
        vec!["[envcloak: command line not kept: the request binds a value too short to mask]"]
    );
    f.sweep(&entries);
}
