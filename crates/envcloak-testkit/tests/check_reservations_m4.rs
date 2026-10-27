//! `scripts/check-reservations.py` on the M4 reservations (M4 plan, task
//! M4-01), on the real tree and on copies of the files it reads, each
//! changed one way. The M4 rows are read under their own heading as one
//! table with M2's and M3's per registry: a number or name taken in two
//! sections fails, a row under another milestone's heading fails, the M4
//! task ids (`M4-01` to `M4-25`, with `M4-06a`/`M4-06b`, `M4-09a`/`M4-09b`
//! and `M4-J1` to `M4-J6`) are known and no other `M4-` id is, every row
//! the M4 plan lists is reserved whatever its status, and no M4 name is
//! one another registry holds.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use envcloak_testkit::TestHome;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

const SCRIPT: &str = "scripts/check-reservations.py";
const VAULT: &str = "docs/VAULT.md";
const IPC: &str = "docs/IPC.md";
const BASELINE: &str = "scripts/check-reservations-baseline.txt";
const M4: &str = "\n## Reserved for M4\n";

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let ty = entry.file_type().unwrap();
        let dest = to.join(entry.file_name());
        if ty.is_dir() {
            copy_dir(&entry.path(), &dest);
        } else if ty.is_file() {
            std::fs::copy(entry.path(), dest).unwrap();
        }
    }
}

fn fixture() -> TestHome {
    let t = TestHome::new();
    let root = t.home();
    for rel in [
        IPC,
        VAULT,
        BASELINE,
        "Cargo.toml",
        "security/sys-build-script.sha256",
    ] {
        let dest = root.join(rel);
        std::fs::create_dir_all(dest.parent().unwrap()).unwrap();
        std::fs::copy(repo_root().join(rel), dest).unwrap();
    }
    for entry in std::fs::read_dir(repo_root().join("crates")).unwrap() {
        let entry = entry.unwrap();
        let src = entry.path().join("src");
        if src.is_dir() {
            let dest = root.join("crates").join(entry.file_name());
            copy_dir(&src, &dest.join("src"));
            for file in ["Cargo.toml", "build.rs"] {
                if entry.path().join(file).is_file() {
                    std::fs::copy(entry.path().join(file), dest.join(file)).unwrap();
                }
            }
        }
    }
    t
}

fn edit(t: &TestHome, rel: &str, from: &str, to: &str) {
    let path = t.home().join(rel);
    let text = std::fs::read_to_string(&path).unwrap();
    assert_eq!(text.matches(from).count(), 1, "{from:?} in {rel}");
    std::fs::write(path, text.replacen(from, to, 1)).unwrap();
}

fn run(root: &Path) -> Output {
    let t = TestHome::new();
    let mut cmd = Command::new("python3");
    t.apply(&mut cmd)
        .arg(repo_root().join(SCRIPT))
        .arg("--root")
        .arg(root)
        .output()
        .unwrap()
}

fn assert_passes(root: &Path) {
    let out = run(root);
    assert!(
        out.status.success(),
        "expected a pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("check-reservations: ok"));
}

fn assert_fails(t: &TestHome, expect_in_message: &str) {
    let out = run(&t.home());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "expected a failure: {stderr}");
    assert!(
        stderr.contains(expect_in_message),
        "expected {expect_in_message:?} in: {stderr}"
    );
}

#[test]
fn the_real_tree_passes() {
    assert_passes(&repo_root());
}

fn m4_section_of(text: &str) -> &str {
    let start = text.find(M4).unwrap() + 1;
    let rest = &text[start..];
    let end = rest[3..].find("\n## ").map_or(rest.len(), |i| i + 3);
    &rest[..end]
}

fn add_m4_row(t: &TestHome, doc: &str, registry: &str, row: &str) {
    let path = t.home().join(doc);
    let text = std::fs::read_to_string(&path).unwrap();
    let section = text.find(M4).unwrap();
    let marker = format!("<!-- reservations:{registry} -->");
    let open = section + text[section..].find(&marker).unwrap();
    let close = open + text[open..].find("<!-- /reservations -->").unwrap();
    std::fs::write(
        &path,
        format!("{}{row}\n{}", &text[..close], &text[close..]),
    )
    .unwrap();
}

const M4_ROWS: &[(&str, &str)] = &[
    (IPC, "| `poll_disabled` | -32060 | M4-09b |"),
    (IPC, "| `adapter_unavailable` | -32061 | M4-09b |"),
    (IPC, "| `currency_mismatch` | -32062 | M4-11 |"),
    (IPC, "| `card_refused` | -32063 | M4-16 |"),
    (IPC, "| `human_only` | -32064 | M4-03 |"),
    (IPC, "| `admin_shaped` | -32065 | M4-19 |"),
    (IPC, "| `ingest_limited` | -32066 | M4-03 |"),
    (IPC, "| `card_opt_in_required` | M4-16 |"),
    (IPC, "| `codexbar_invalid` | M4-18 |"),
    (IPC, "| `downgrade_refused` | M4-03 |"),
    (IPC, "| `duplicate_subscription` | M4-03 |"),
    (IPC, "| `poller_failed` | M4-09a |"),
    (IPC, "| `provider_denied` | M4-07 |"),
    (IPC, "| `stale_figure` | M4-05 |"),
    (IPC, "| `usage_credential_refused` | M4-19 |"),
    (IPC, "| `spend.summary` | M4-03 |"),
    (IPC, "| `spend.item` | M4-03 |"),
    (IPC, "| `spend.manual.set` | M4-03 |"),
    (IPC, "| `spend.ingest` | M4-03 |"),
    (IPC, "| `spend.poll.enable` | M4-09b |"),
    (IPC, "| `spend.poll.disable` | M4-09b |"),
    (IPC, "| `spend.poll.now` | M4-09b |"),
    (IPC, "| `spend.link` | M4-20 |"),
    (IPC, "| `spend.codexbar.set_path` | M4-18 |"),
    (IPC, "| `subs.add` | M4-03 |"),
    (IPC, "| `subs.list` | M4-03 |"),
    (IPC, "| `subs.remove` | M4-03 |"),
    (IPC, "| `budget.add` | M4-11 |"),
    (IPC, "| `budget.list` | M4-11 |"),
    (IPC, "| `budget.remove` | M4-11 |"),
    (IPC, "| `alerts.list` | M4-12 |"),
    (IPC, "| `alerts.ack` | M4-12 |"),
    (IPC, "| `alerts.snooze` | M4-12 |"),
    (IPC, "| `items.edit` | M4-03 |"),
    (IPC, "| `items.set_class` | M4-19 |"),
    (IPC, "| `card.add` | M4-16 |"),
    (IPC, "| `card.list` | M4-16 |"),
    (IPC, "| `card.show` | M4-16 |"),
    (IPC, "| `card.remove` | M4-16 |"),
    (IPC, "| `card.optin` | M4-16 |"),
    (IPC, "| `app.card.paste` | M4-23 |"),
    (IPC, "| `status` | `spend` | M4-12 |"),
    (IPC, "| `poll_failed` | M4-09b |"),
    (IPC, "| `card_invalid` | M4-16 |"),
    (IPC, "| `budget_invalid` | M4-13 |"),
    (IPC, "| `sub_invalid` | M4-04 |"),
    (IPC, "| `alert_unknown` | M4-13 |"),
    (IPC, "| `codexbar_unverified` | M4-18 |"),
    (IPC, "| `poller` | `PollJobFrame` | M4-09a |"),
    (IPC, "| `poller` | `PollResultFrame` | M4-09a |"),
    (IPC, "| `poller` | `PollAbort` | M4-09a |"),
    (IPC, "| `envcloak-reveal-statement/2` | M4-23 |"),
    (VAULT, "| 60 | `spend_poll` | M4-09b |"),
    (VAULT, "| 61 | `spend_poll_result` | M4-09b |"),
    (VAULT, "| 62 | `spend_ingest` | M4-03 |"),
    (VAULT, "| 63 | `spend_config` | M4-03 |"),
    (VAULT, "| 64 | `budget_change` | M4-11 |"),
    (VAULT, "| 65 | `card_add` | M4-16 |"),
    (VAULT, "| 66 | `card_change` | M4-16 |"),
    (VAULT, "| 67 | `card_optin` | M4-16 |"),
    (VAULT, "| 68 | `item_edit` | M4-03 |"),
    (VAULT, "| 69 | `item_class_change` | M4-19 |"),
    (VAULT, "| 70 | `usage_link` | M4-20 |"),
    (VAULT, "| 5 | `usage_credential` | M4-19 |"),
    (VAULT, "| 17 | `card_meta` | M4-15 |"),
    (VAULT, "| 18 | `card_number` | M4-15 |"),
    (VAULT, "| 19 | `card_cvv` | M4-15 |"),
    (VAULT, "| 5 | `subscription` | M4-02 |"),
    (VAULT, "| 6 | `budget` | M4-02 |"),
    (VAULT, "| 7 | `alert_rule` | M4-02 |"),
    (VAULT, "| 8 | `manual_fact` | M4-02 |"),
    (VAULT, "| 9 | `control_fact` | M4-02 |"),
    (VAULT, "| 10 | `spend_snapshot` | M4-02 |"),
    (VAULT, "| 11 | `account_link` | M4-02 |"),
];

fn with_status(text: &str, lead: &str, status: &str) -> String {
    let section = text.find(M4).unwrap();
    let at = section + text[section..].find(&format!("\n{lead}")).unwrap() + 1;
    let end = at + text[at..].find('\n').unwrap();
    let rest = &text[at + lead.len()..end];
    let cell = 1 + rest[1..].find('|').unwrap();
    format!(
        "{}{lead} {status} {}{}",
        &text[..at],
        &rest[cell..],
        &text[end..]
    )
}

fn m4_row_problems(ipc: &str, vault: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let section = |doc: &str| m4_section_of(if doc == IPC { ipc } else { vault }).to_owned();
    for (doc, lead) in M4_ROWS {
        let text = section(doc);
        let rows: Vec<&str> = text.lines().filter(|l| l.starts_with(lead)).collect();
        if rows.len() != 1 {
            problems.push(format!(
                "{lead} is under {doc}'s heading {} times",
                rows.len()
            ));
            continue;
        }
        let status = rows[0][lead.len()..].trim_start();
        if !["reserved |", "landed |", "reuse |"]
            .iter()
            .any(|s| status.starts_with(s))
        {
            problems.push(format!("{lead} has no status"));
        }
    }
    problems
}

#[test]
fn every_row_the_m4_plan_reserves_is_under_its_heading() {
    let read = |doc: &str| std::fs::read_to_string(repo_root().join(doc)).unwrap();
    let (ipc, vault) = (read(IPC), read(VAULT));
    assert_eq!(m4_row_problems(&ipc, &vault), Vec::<String>::new());

    let lead = "| `spend.summary` | M4-03 |";
    for first in ["reserved", "landed"] {
        let base = with_status(&ipc, lead, first);
        for status in ["reserved", "landed", "reuse"] {
            let changed = with_status(&base, lead, status);
            assert!(
                changed.contains(&format!("\n{lead} {status} | ")),
                "{status}"
            );
            assert_eq!(m4_row_problems(&changed, &vault), Vec::<String>::new());
        }
        let unknown = with_status(&base, lead, "pending");
        assert_eq!(
            m4_row_problems(&unknown, &vault),
            vec![format!("{lead} has no status")]
        );
    }

    let gone = ipc.replacen(
        "| `spend.summary` | M4-03 |",
        "| `spend.overview` | M4-03 |",
        1,
    );
    assert_ne!(gone, ipc);
    assert!(
        m4_row_problems(&gone, &vault)
            .iter()
            .any(|p| p.contains("`spend.summary` | M4-03 |"))
    );
}

#[test]
fn every_m4_task_is_known_and_no_other_m4_id() {
    let ids = [
        "M4-01", "M4-02", "M4-03", "M4-04", "M4-05", "M4-06a", "M4-06b", "M4-07", "M4-08",
        "M4-09a", "M4-09b", "M4-10", "M4-11", "M4-12", "M4-13", "M4-14", "M4-15", "M4-16", "M4-17",
        "M4-18", "M4-19", "M4-20", "M4-21", "M4-22", "M4-23", "M4-24", "M4-25", "M4-J1", "M4-J2",
        "M4-J3", "M4-J4", "M4-J5", "M4-J6",
    ];
    let t = fixture();
    for (i, id) in ids.iter().enumerate() {
        add_m4_row(
            &t,
            IPC,
            "exit_token",
            &format!("| `zz_m4_probe_{i}` | {id} | reserved | a probe row |"),
        );
    }
    assert_passes(&t.home());

    let t = fixture();
    let bad = ["M4-00", "M4-06", "M4-09", "M4-26", "M4-99", "M4-1", "M4-J7"];
    for (i, id) in bad.iter().enumerate() {
        add_m4_row(
            &t,
            IPC,
            "exit_token",
            &format!("| `zz_m4_bad_{i}` | {id} | reserved | a probe row |"),
        );
    }
    let out = run(&t.home());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    for id in bad {
        let why = format!("names '{id}', which is not an M2, M2b or M3 task, an M4 task");
        assert!(stderr.contains(&why), "expected {why:?} in: {stderr}");
    }
}

#[test]
fn m4_section_and_duplicate_rules_hold() {
    // Duplicate error code in M4 fails.
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `adapter_unavailable` | -32061 |",
        "| `adapter_unavailable` | -32060 |",
    );
    assert_fails(
        &t,
        "`error_kind`: number -32060 is reserved twice (`poll_disabled` and `adapter_unavailable`)",
    );

    // Duplicate audit kind across M3 and M4 fails.
    let t = fixture();
    edit(&t, VAULT, "| 60 | `spend_poll` |", "| 46 | `spend_poll` |");
    assert_fails(
        &t,
        "`audit_kind`: number 46 is reserved twice (`unlocker_add` and `spend_poll`)",
    );

    // An M4 task under "Reserved for M3" or an M3 task under "Reserved for M4" fails.
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `projects.list` | M3-04 |",
        "| `projects.list` | M4-03 |",
    );
    assert_fails(
        &t,
        "`projects.list` is M4-03's, so its row belongs under \"Reserved for M4\", not \"Reserved for M3\"",
    );

    let t = fixture();
    edit(
        &t,
        IPC,
        "| `spend.summary` | M4-03 |",
        "| `spend.summary` | M3-04 |",
    );
    assert_fails(
        &t,
        "`spend.summary` is M3-04's, so its row belongs under \"Reserved for M3\", not \"Reserved for M4\"",
    );

    // A bare M4 milestone under "Reserved for M4" fails because it is not after milestone 4.
    let t = fixture();
    edit(
        &t,
        IPC,
        "| `spend.summary` | M4-03 |",
        "| `spend.summary` | M4 |",
    );
    assert_fails(
        &t,
        "`spend.summary` names M4, which is not a milestone after the one \"Reserved for M4\" reserves for",
    );
}
