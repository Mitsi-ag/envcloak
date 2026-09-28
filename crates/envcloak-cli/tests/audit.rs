//! `envcloak audit verify` (SPEC §15.2 gate 33, story S12): exit 0 with
//! "chain OK" and the unanchored tail when the log checks out, the anchor
//! after a lock, exit 1 with `audit_problem` and the entry's number when
//! an entry was changed, `vault_locked` while locked; `--json` carries the
//! same. `envcloak status` says whether the log is open. No output holds a
//! canary.
#![allow(clippy::unwrap_used)]

mod common;

use common::{
    outside_dir, run, run_on_terminal, secret_file, seed_vault, start_daemon, stderr, stdout,
};
use envcloak_testkit::{TestHome, assert_no_canary, by_label, canaries, fresh_seed, labels};

#[test]
fn audit_verify_reports_the_chain_the_anchor_and_tampering() {
    let cs = canaries(fresh_seed());
    let home = TestHome::new();
    let kit = seed_vault(&home, &cs);
    let mut cs = cs;
    cs.push(kit);
    let d = start_daemon(&home);
    let files = outside_dir();
    let pass = secret_file(
        files.path(),
        "pass",
        by_label(&cs, labels::VAULT_PASSPHRASE).value(),
    );
    let clean = |o: &std::process::Output| {
        assert_no_canary(&o.stdout, &cs);
        assert_no_canary(&o.stderr, &cs);
    };

    let locked = run(&home, &["audit", "verify"], &[]);
    clean(&locked);
    assert_eq!(locked.status.code(), Some(1));
    assert!(
        stderr(&locked).starts_with("envcloak: vault_locked:"),
        "{}",
        stderr(&locked)
    );
    let st = run(&home, &["status"], &[]);
    assert!(
        stdout(&st).contains("audit log: closed while the vault is locked"),
        "{}",
        stdout(&st)
    );

    let unlock = |home: &TestHome| {
        let o = run_on_terminal(
            home,
            &["unlock", "--passphrase-fd", "3"],
            &[(3, &pass, true)],
        );
        assert!(o.status.success(), "{}{}", stderr(&o), d.log());
    };
    unlock(&home);
    let ok = run(&home, &["audit", "verify"], &[]);
    clean(&ok);
    assert!(ok.status.success(), "{}", stderr(&ok));
    let out = stdout(&ok);
    assert!(
        out.contains("audit log: 1 entry in 1 segment, through entry 1"),
        "{out}"
    );
    assert!(out.contains("anchor: none saved in the vault yet"), "{out}");
    assert!(out.contains("check: OK"), "{out}");
    assert!(
        out.contains("unanchored tail: entry 1 was written after the anchor"),
        "{out}"
    );
    let st = run(&home, &["status"], &[]);
    assert!(
        stdout(&st).contains("audit log: open, last entry 1 (1 not yet anchored in the vault)"),
        "{}",
        stdout(&st)
    );

    // A lock saves the head; the unlock after it is the tail.
    assert!(run(&home, &["lock"], &[]).status.success());
    unlock(&home);
    let ok = run(&home, &["audit", "verify", "--json"], &[]);
    clean(&ok);
    assert!(ok.status.success(), "{}", stderr(&ok));
    let v: serde_json::Value = serde_json::from_slice(&ok.stdout).unwrap();
    assert_eq!(v["first_problem"], serde_json::Value::Null);
    assert_eq!(v["anchor"]["state"], "matched");
    assert_eq!(v["anchor"]["seq"], 2);
    assert_eq!(v["unanchored_tail"]["first"], 3);
    assert_eq!(v["live_head_matches"], true);

    // Entry 2 (the lock) changed on disk.
    let dir = if cfg!(target_os = "macos") {
        home.home()
            .join("Library/Application Support/EnvCloak/audit")
    } else {
        home.root().join("data/envcloak/audit")
    };
    let seg = dir.join(format!("{:020}.seg", 1));
    let mut b = std::fs::read(&seg).unwrap();
    let header = envcloak_core::audit::HEADER_LEN;
    let first_len = u32::from_be_bytes(b[header..header + 4].try_into().unwrap()) as usize;
    let second = header + 12 + first_len + 32;
    b[second + 12 + 30] ^= 0x04;
    std::fs::write(&seg, &b).unwrap();
    let bad = run(&home, &["audit", "verify"], &[]);
    clean(&bad);
    assert_eq!(bad.status.code(), Some(1));
    assert!(
        stdout(&bad).contains("check: PROBLEM at entry 2: the entry was changed"),
        "{}",
        stdout(&bad)
    );
    assert!(
        stderr(&bad).starts_with(
            "envcloak: audit_problem: the audit log was changed or damaged; the first problem is \
             at entry 2"
        ),
        "{}",
        stderr(&bad)
    );

    // Entry 2 as it was, then the start of an entry after entry 3: what a
    // crash in the middle of a write leaves. It is noted with its size,
    // and the check passes.
    b[second + 12 + 30] ^= 0x04;
    let mut torn = 200u32.to_be_bytes().to_vec();
    torn.extend_from_slice(&4u64.to_be_bytes());
    torn.extend_from_slice(&[0; 8]);
    std::fs::write(&seg, [b, torn].concat()).unwrap();
    let noted = run(&home, &["audit", "verify"], &[]);
    clean(&noted);
    assert!(noted.status.success(), "{}", stderr(&noted));
    assert!(
        stdout(&noted).contains(
            "note: the log ends in 20 bytes as a crash in the middle of a write leaves them"
        ),
        "{}",
        stdout(&noted)
    );

    let usage = run(&home, &["audit", "list"], &[]);
    assert_eq!(usage.status.code(), Some(2));
    assert_no_canary(&d.log_bytes(), &cs);
    home.assert_clean(&cs);
}
