//! Gate `s7` (logic half) and `M4-05` tests: control model, five-control table,
//! `D4-07` hard-cap truth table, `D4-28` availability states, `gen-controls.py`
//! and `check-spend-labels.sh` (`SPEC §2a-bis`, `SPEC §15.2` gate `s7`).

use std::path::{Path, PathBuf};
use std::process::Command;

use envcloak_core::money::{Iso4217, Money};
use envcloak_core::vault::{ItemId, ProjectId, SpendAccountId};
use envcloak_spend::account::{Source, SubjectKindRecord};
use envcloak_spend::controls::{
    Availability, BudgetDataFeed, BudgetEvalContext, BudgetScope, CONTROL_TABLE, CapEnforcement,
    CapResetPeriod, CapScope, Control, EnforcingBasis, KeySet, MAX_FRESH_CAP_AGE_SECS,
    ProviderCapFact, UnverifiedReason, controls_for, covers, format_cap_amount, hard_cap_words,
    label,
};

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "envcloak-spend-labels-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn key_set(items: &[&str]) -> KeySet {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn usd(dollars: i64) -> Money {
    Money::new(dollars * 100, 2, Iso4217::USD).unwrap()
}

fn eur(euros: i64) -> Money {
    Money::new(euros * 100, 2, Iso4217::EUR).unwrap()
}

/// Gate `s7` / `M4-05` exhaustive truth-table property test across every
/// combination of source, enforcement kind, age (`0`, `25 h 59 min`, `26 h`,
/// `26 h 1 min`, `27 h`), currency pair, amount pair (`below`, `equal`,
/// `above`), reset pair (`Monthly/Monthly`, `Daily/Monthly`, `None` with
/// remaining `<=` and `>`), scope pair (`equal`, `key inside account`,
/// `account inside provider`, and each reverse) and key count (`1` key, `2`
/// keys) and control.
#[test]
fn gate_s7_exhaustive_truth_table_hard_cap_iff_d4_07_holds() {
    let now: u64 = 1_760_000_000;

    let sources: Vec<(&str, Source, bool)> = vec![
        ("poll", Source::Poll, true),
        (
            "manual",
            Source::Manual {
                subject: SubjectKindRecord::Terminal,
            },
            false,
        ),
        (
            "client_reported",
            Source::ClientReported {
                subject: SubjectKindRecord::Terminal,
                tool: "codexbar".to_owned(),
            },
            false,
        ),
    ];

    let enforcements: Vec<(&str, CapEnforcement, bool)> = vec![
        (
            "enforcing_read",
            CapEnforcement::Enforcing(EnforcingBasis::Read),
            true,
        ),
        (
            "enforcing_doc",
            CapEnforcement::Enforcing(EnforcingBasis::Documented {
                source: "https://openrouter.ai/docs/api-reference/api-keys".to_owned(),
            }),
            true,
        ),
        ("inactive", CapEnforcement::Inactive, false),
        ("unknown", CapEnforcement::Unknown, false),
    ];

    // Ages: 0s, 25h59m (93_540s), 26h (93_600s), 26h01m (93_660s), 27h (97_200s)
    let ages: Vec<(&str, u64, bool)> = vec![
        ("0s", 0, true),
        ("25h59m", 25 * 3600 + 59 * 60, true),
        ("26h", MAX_FRESH_CAP_AGE_SECS, true),
        ("26h01m", 26 * 3600 + 60, false),
        ("27h", 27 * 3600, false),
    ];

    // (name, cap_amount, cap_reset, cap_rem, budget_amount, budget_reset, budget_rem, cond1_and_2_ok)
    let money_cases: Vec<(
        &str,
        Money,
        Option<CapResetPeriod>,
        Option<Money>,
        Money,
        CapResetPeriod,
        Option<Money>,
        bool,
    )> = vec![
        (
            "same_curr_below_monthly",
            usd(15),
            Some(CapResetPeriod::Monthly),
            Some(usd(10)),
            usd(20),
            CapResetPeriod::Monthly,
            Some(usd(12)),
            true,
        ),
        (
            "same_curr_equal_monthly",
            usd(20),
            Some(CapResetPeriod::Monthly),
            Some(usd(20)),
            usd(20),
            CapResetPeriod::Monthly,
            Some(usd(20)),
            true,
        ),
        (
            "same_curr_above_monthly_1000_on_20",
            usd(1000),
            Some(CapResetPeriod::Monthly),
            Some(usd(1000)),
            usd(20),
            CapResetPeriod::Monthly,
            Some(usd(20)),
            false,
        ),
        (
            "diff_curr_eur_on_usd",
            eur(15),
            Some(CapResetPeriod::Monthly),
            Some(eur(10)),
            usd(20),
            CapResetPeriod::Monthly,
            Some(usd(12)),
            false,
        ),
        (
            "diff_reset_daily_on_monthly",
            usd(15),
            Some(CapResetPeriod::Daily),
            Some(usd(10)),
            usd(20),
            CapResetPeriod::Monthly,
            Some(usd(12)),
            false,
        ),
        (
            "no_reset_remaining_le_budget_remaining",
            usd(50),
            None,
            Some(usd(10)),
            usd(20),
            CapResetPeriod::Monthly,
            Some(usd(12)),
            true,
        ),
        (
            "no_reset_remaining_gt_budget_remaining",
            usd(50),
            None,
            Some(usd(15)),
            usd(20),
            CapResetPeriod::Monthly,
            Some(usd(12)),
            false,
        ),
    ];

    // Scope & key-count pairs:
    // equal, key inside account, account inside provider, and each reverse,
    // with 1 key and 2 keys, plus disjoint organization cap on a key budget.
    let k1 = key_set(&["openrouter/work"]);
    let k2 = key_set(&["openrouter/work", "openrouter/ci"]);
    let other_org = key_set(&["openrouter/other-org-key"]);
    let work_item_id = ItemId::from_bytes([1u8; 16]);
    let proj_id = ProjectId::from_bytes([2u8; 16]);
    let or_acct = SpendAccountId {
        provider: "openrouter".into(),
        account: "acct-1".into(),
    };

    let scope_cases: Vec<(&str, CapScope, KeySet, BudgetScope, KeySet, bool)> = vec![
        (
            "equal_key_1",
            CapScope::Key("openrouter/work".into()),
            k1.clone(),
            BudgetScope::Key(work_item_id),
            k1.clone(),
            true,
        ),
        (
            "equal_account_2",
            CapScope::Account {
                provider: "openrouter".into(),
                account_id: "acct-1".into(),
            },
            k2.clone(),
            BudgetScope::Account(or_acct.clone()),
            k2.clone(),
            true,
        ),
        (
            "equal_provider_2",
            CapScope::Provider("openrouter".into()),
            k2.clone(),
            BudgetScope::Provider("openrouter".into()),
            k2.clone(),
            true,
        ),
        (
            "equal_project_1",
            CapScope::Key("openrouter/work".into()),
            k1.clone(),
            BudgetScope::Project(proj_id),
            k1.clone(),
            true,
        ),
        (
            "key_budget_inside_account_cap_2_keys",
            CapScope::Account {
                provider: "openrouter".into(),
                account_id: "acct-1".into(),
            },
            k2.clone(),
            BudgetScope::Key(work_item_id),
            k1.clone(),
            true,
        ),
        (
            "reverse_key_cap_on_account_budget_1_key",
            CapScope::Key("openrouter/work".into()),
            k1.clone(),
            BudgetScope::Account(or_acct.clone()),
            k1.clone(),
            true,
        ),
        (
            "reverse_key_cap_on_account_budget_2_keys",
            CapScope::Key("openrouter/work".into()),
            k1.clone(),
            BudgetScope::Account(or_acct.clone()),
            k2.clone(),
            false,
        ),
        (
            "account_budget_inside_provider_cap_2_keys",
            CapScope::Provider("openrouter".into()),
            k2.clone(),
            BudgetScope::Account(or_acct),
            k1.clone(),
            true,
        ),
        (
            "reverse_account_cap_on_provider_budget_1_key",
            CapScope::Account {
                provider: "openrouter".into(),
                account_id: "acct-1".into(),
            },
            k1.clone(),
            BudgetScope::Provider("openrouter".into()),
            k1.clone(),
            true,
        ),
        (
            "reverse_account_cap_on_provider_budget_2_keys",
            CapScope::Account {
                provider: "openrouter".into(),
                account_id: "acct-1".into(),
            },
            k1.clone(),
            BudgetScope::Provider("openrouter".into()),
            k2.clone(),
            false,
        ),
        (
            "reverse_key_cap_on_provider_budget_2_keys",
            CapScope::Key("openrouter/work".into()),
            k1.clone(),
            BudgetScope::Provider("openrouter".into()),
            k2.clone(),
            false,
        ),
        (
            "disjoint_org_cap_on_key_budget",
            CapScope::Organization {
                provider: "openrouter".into(),
                org_id: "org-other".into(),
            },
            other_org,
            BudgetScope::Key(work_item_id),
            k1.clone(),
            false,
        ),
    ];

    let mut total_checked = 0usize;
    let mut hard_cap_count = 0usize;

    for (src_name, src, src_ok) in &sources {
        for (enf_name, enf, enf_ok) in &enforcements {
            for (age_name, age, age_ok) in &ages {
                for (m_name, cap_amt, cap_reset, cap_rem, bud_amt, bud_reset, bud_rem, money_ok) in
                    &money_cases
                {
                    for (sc_name, cap_scope, cap_keys, bud_scope, bud_keys, scope_ok) in
                        &scope_cases
                    {
                        assert_eq!(covers(cap_keys, bud_keys), *scope_ok);

                        let cap = ProviderCapFact {
                            provider: "openrouter".to_owned(),
                            amount: *cap_amt,
                            reset: *cap_reset,
                            remaining: *cap_rem,
                            scope: cap_scope.clone(),
                            keys: cap_keys.clone(),
                            enforcement: enf.clone(),
                            byok_in_limit: Some(false),
                            source: src.clone(),
                            read_at: now - *age,
                            lag: None,
                        };

                        let budget = BudgetEvalContext {
                            scope: bud_scope.clone(),
                            amount: *bud_amt,
                            reset: *bud_reset,
                            remaining: *bud_rem,
                            keys: bud_keys.clone(),
                            cap: Some(cap.clone()),
                            data_feed: BudgetDataFeed::Active,
                            vault_locked: false,
                            now,
                        };

                        let expect_hard_cap =
                            *src_ok && *enf_ok && *age_ok && *money_ok && *scope_ok;

                        let hw = hard_cap_words(&cap, &budget);
                        assert_eq!(
                            hw.is_some(),
                            expect_hard_cap,
                            "hard_cap_words mismatch on ({src_name}, {enf_name}, {age_name}, {m_name}, {sc_name})"
                        );

                        let rows = controls_for(&budget);
                        assert_eq!(rows.len(), 5);

                        for row in &rows {
                            total_checked += 1;
                            let has_hard_cap =
                                row.headline().to_ascii_lowercase().contains("hard cap");
                            if row.control() == Control::ProviderCap && expect_hard_cap {
                                hard_cap_count += 1;
                                assert!(
                                    has_hard_cap,
                                    "expected 'Hard cap' headline on ({src_name}, {enf_name}, {age_name}, {m_name}, {sc_name}), got {:?}",
                                    row.headline()
                                );
                                assert_eq!(row.availability(), Availability::Active);
                            } else {
                                assert!(
                                    !has_hard_cap,
                                    "unexpected 'Hard cap' headline on {:?} ({src_name}, {enf_name}, {age_name}, {m_name}, {sc_name}): {:?}",
                                    row.control(),
                                    row.headline()
                                );
                            }

                            if row.control() == Control::ProviderCap {
                                // Every cap row prints its own amount, reset period (when present) and scope.
                                let expected_amt = format_cap_amount(cap_amt);
                                assert!(
                                    row.headline().contains(&expected_amt),
                                    "cap headline {:?} must contain its amount {:?}",
                                    row.headline(),
                                    expected_amt
                                );
                                if let Some(r) = cap_reset {
                                    let r_word = match r {
                                        CapResetPeriod::Daily => "daily",
                                        CapResetPeriod::Weekly => "weekly",
                                        CapResetPeriod::Monthly => "monthly",
                                    };
                                    assert!(
                                        row.headline().contains(r_word),
                                        "cap headline {:?} must contain its reset period {r_word:?}",
                                        row.headline()
                                    );
                                }
                                let scope_present =
                                    row.headline().contains(&cap_scope.display_scope())
                                        || row.headline().contains(cap_scope.hard_cap_qualifier());
                                assert!(
                                    scope_present,
                                    "cap headline {:?} must contain its scope",
                                    row.headline()
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    assert!(total_checked > 20_000);
    assert!(hard_cap_count > 0);
}

/// Verifies the exact wording and availability for acceptance story steps `A7`,
/// `A8`, `A10`, `A11`, `A13`, and `A19`.
#[test]
fn story_steps_a7_a8_a10_a11_a13_a19_headlines_and_availabilities() {
    let now: u64 = 1_760_000_000;
    let work_key = key_set(&["openrouter/work"]);
    let two_keys = key_set(&["openrouter/work", "openrouter/ci"]);

    // A7 & A10 key budget: openrouter/work cap of 15 USD monthly on a 20 USD key budget
    let or_cap = ProviderCapFact {
        provider: "openrouter".to_owned(),
        amount: usd(15),
        reset: Some(CapResetPeriod::Monthly),
        remaining: Some(usd(4)),
        scope: CapScope::Key("openrouter/work".to_owned()),
        keys: work_key.clone(),
        enforcement: CapEnforcement::Enforcing(EnforcingBasis::Documented {
            source: "https://openrouter.ai/docs/api-reference/api-keys".to_owned(),
        }),
        byok_in_limit: Some(false),
        source: Source::Poll,
        read_at: now - 60,
        lag: None,
    };

    let key_budget = BudgetEvalContext {
        scope: BudgetScope::Key(ItemId::from_bytes([1u8; 16])),
        amount: usd(20),
        reset: CapResetPeriod::Monthly,
        remaining: Some(usd(9)),
        keys: work_key.clone(),
        cap: Some(or_cap.clone()),
        data_feed: BudgetDataFeed::Active,
        vault_locked: false,
        now,
    };

    let rows = controls_for(&key_budget);
    assert_eq!(rows.len(), 5);
    assert_eq!(
        rows[0].headline(),
        "Hard cap of 15 USD monthly (OpenRouter, this key only, per OpenRouter's documentation)"
    );
    assert_eq!(rows[0].availability(), Availability::Active);
    assert!(
        rows[0]
            .stops()
            .contains("excluding bring-your-own-key usage")
    );
    assert!(rows[0].does_not_stop().contains("bring-your-own-key usage"));

    for idx in [1, 2, 3] {
        assert_eq!(rows[idx].headline(), "Not in this release");
        assert_eq!(rows[idx].availability(), Availability::NotInThisRelease);
    }
    assert_eq!(rows[4].headline(), "Stops nothing");
    assert_eq!(rows[4].availability(), Availability::Active);
    assert!(
        rows[4]
            .does_not_stop()
            .ends_with("and is not evaluated while the vault is locked or the machine sleeps")
    );

    // A8: no successful OpenRouter read for 27 hours -> Stale
    let stale_budget = BudgetEvalContext {
        now: or_cap.read_at + 27 * 3600,
        ..key_budget.clone()
    };
    let stale_cap_row = label(Control::ProviderCap, &stale_budget);
    assert_eq!(
        stale_cap_row.headline(),
        "Provider cap of 15 USD on key openrouter/work, last checked 27 hours ago, not confirmed (monthly)"
    );
    assert_eq!(
        stale_cap_row.availability(),
        Availability::Stale {
            since: or_cap.read_at
        }
    );

    // A10 provider budget with two keys (openrouter/ci has no limit): does not enforce this budget
    let provider_budget = BudgetEvalContext {
        scope: BudgetScope::Provider("openrouter".to_owned()),
        keys: two_keys.clone(),
        ..key_budget.clone()
    };
    let prov_cap_row = label(Control::ProviderCap, &provider_budget);
    assert_eq!(
        prov_cap_row.headline(),
        "Provider cap of 15 USD on key openrouter/work; does not enforce this budget (monthly)"
    );
    assert_eq!(
        prov_cap_row.availability(),
        Availability::Unverified(UnverifiedReason::DoesNotEnforceBudget)
    );

    // Non-resetting cap (`reset: None`) must not duplicate `(<amount>)` in Stale or DoesNotEnforceBudget
    let no_reset_cap = ProviderCapFact {
        reset: None,
        remaining: Some(usd(15)),
        ..or_cap.clone()
    };
    let no_reset_prov_row = label(
        Control::ProviderCap,
        &BudgetEvalContext {
            cap: Some(no_reset_cap),
            ..provider_budget.clone()
        },
    );
    assert_eq!(
        no_reset_prov_row.headline(),
        "Provider cap of 15 USD on key openrouter/work; does not enforce this budget"
    );

    // Documented enforcement with an empty citation source is rejected
    let empty_doc_cap = ProviderCapFact {
        enforcement: CapEnforcement::Enforcing(EnforcingBasis::Documented {
            source: "   ".to_owned(),
        }),
        ..or_cap.clone()
    };
    let empty_doc_budget = BudgetEvalContext {
        cap: Some(empty_doc_cap.clone()),
        ..key_budget.clone()
    };
    assert!(hard_cap_words(&empty_doc_cap, &empty_doc_budget).is_none());
    let empty_doc_row = label(Control::ProviderCap, &empty_doc_budget);
    assert_eq!(
        empty_doc_row.availability(),
        Availability::Unverified(UnverifiedReason::UnknownEnforcement)
    );

    // A10 mistral/dev budget with polling off and nothing entered -> NoData
    let mistral_budget = BudgetEvalContext {
        scope: BudgetScope::Key(ItemId::from_bytes([3u8; 16])),
        amount: usd(30),
        reset: CapResetPeriod::Monthly,
        remaining: Some(usd(30)),
        keys: key_set(&["mistral/dev"]),
        cap: None,
        data_feed: BudgetDataFeed::NoDataPollingOff,
        vault_locked: false,
        now,
    };
    let mistral_rows = controls_for(&mistral_budget);
    assert_eq!(mistral_rows[0].availability(), Availability::NotSet);
    assert_eq!(
        mistral_rows[4].headline(),
        "Alert only: no data, polling off"
    );
    assert_eq!(mistral_rows[4].availability(), Availability::NoData);

    // A11: manual cap of 50 USD -> Unverified(ManualEntry), never "Hard cap"
    let manual_cap = ProviderCapFact {
        amount: usd(50),
        source: Source::Manual {
            subject: SubjectKindRecord::Terminal,
        },
        ..or_cap
    };
    let manual_budget = BudgetEvalContext {
        cap: Some(manual_cap),
        ..key_budget.clone()
    };
    let manual_row = label(Control::ProviderCap, &manual_budget);
    assert_eq!(
        manual_row.headline(),
        "Provider cap, you entered this, EnvCloak has not checked it (50 USD monthly on key openrouter/work)"
    );
    assert!(
        !manual_row
            .headline()
            .to_ascii_lowercase()
            .contains("hard cap")
    );
    assert_eq!(
        manual_row.availability(),
        Availability::Unverified(UnverifiedReason::ManualEntry)
    );

    // A13: moonshot polling disabled after poll at `since` -> Alert only reads "stale since <time>, polling off"
    let stale_poll_off = BudgetEvalContext {
        data_feed: BudgetDataFeed::StalePollingOff {
            since: 1_759_900_000,
        },
        ..mistral_budget
    };
    let alert_row = label(Control::AlertOnly, &stale_poll_off);
    assert_eq!(
        alert_row.headline(),
        "Alert only: stale since 1759900000, polling off"
    );
    assert_eq!(
        alert_row.availability(),
        Availability::Stale {
            since: 1_759_900_000
        }
    );

    // A19: OpenAI organization limit `inactive` vs `enforcing`
    let org_keys = key_set(&["openai/prod", "openai/dev"]);
    let openai_inactive = ProviderCapFact {
        provider: "openai".to_owned(),
        amount: usd(100),
        reset: Some(CapResetPeriod::Monthly),
        remaining: None,
        scope: CapScope::Organization {
            provider: "openai".to_owned(),
            org_id: "org-main".to_owned(),
        },
        keys: org_keys.clone(),
        enforcement: CapEnforcement::Inactive,
        byok_in_limit: None,
        source: Source::Poll,
        read_at: now - 30,
        lag: None,
    };
    let org_budget = BudgetEvalContext {
        scope: BudgetScope::Account(SpendAccountId {
            provider: "openai".to_owned(),
            account: "org-main".to_owned(),
        }),
        amount: usd(100),
        reset: CapResetPeriod::Monthly,
        remaining: Some(usd(60)),
        keys: org_keys,
        cap: Some(openai_inactive.clone()),
        data_feed: BudgetDataFeed::Active,
        vault_locked: false,
        now,
    };
    let inactive_row = label(Control::ProviderCap, &org_budget);
    assert!(
        inactive_row
            .headline()
            .contains("configured, not enforcing")
    );
    assert_eq!(
        inactive_row.availability(),
        Availability::Unverified(UnverifiedReason::InactiveLimit)
    );

    let openai_enforcing = ProviderCapFact {
        enforcement: CapEnforcement::Enforcing(EnforcingBasis::Read),
        ..openai_inactive
    };
    let enforcing_budget = BudgetEvalContext {
        cap: Some(openai_enforcing),
        ..org_budget
    };
    let enforcing_row = label(Control::ProviderCap, &enforcing_budget);
    assert_eq!(
        enforcing_row.headline(),
        "Hard cap of 100 USD monthly (OpenAI, organization)"
    );
    assert_eq!(enforcing_row.availability(), Availability::Active);
}

/// Verifies that `CONTROL_TABLE` matches `docs/SPEC.md` §2a-bis byte for byte,
/// `scripts/gen-controls.py --check` passes on the workspace, and editing one
/// SPEC cell causes `gen-controls.py --check` to fail.
#[test]
fn control_table_matches_spec_and_gen_controls_detects_spec_mutation() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().unwrap().parent().unwrap();
    let script = root.join("scripts/gen-controls.py");

    let status = Command::new("python3")
        .arg(&script)
        .arg("--check")
        .arg("--root")
        .arg(root)
        .status()
        .unwrap();
    assert!(status.success(), "gen-controls.py --check must pass");

    // Verify all 5 rows in CONTROL_TABLE are non-empty and in SPEC order.
    assert_eq!(CONTROL_TABLE.len(), 5);
    assert_eq!(CONTROL_TABLE[0].control, Control::ProviderCap);
    assert_eq!(CONTROL_TABLE[1].control, Control::ProxyGate);
    assert_eq!(CONTROL_TABLE[2].control, Control::AutoKeyDisable);
    assert_eq!(CONTROL_TABLE[3].control, Control::CardAuthLimit);
    assert_eq!(CONTROL_TABLE[4].control, Control::AlertOnly);

    // Mutation check: edit one cell in a temporary copy of docs/SPEC.md and
    // verify `gen-controls.py --check` fails.
    let tmp = ScratchDir::new("spec-mutation");
    let tmp_toml_dir = tmp.path().join("crates/envcloak-spend/src/controls");
    let tmp_docs_dir = tmp.path().join("docs");
    std::fs::create_dir_all(&tmp_toml_dir).unwrap();
    std::fs::create_dir_all(&tmp_docs_dir).unwrap();
    std::fs::copy(
        root.join("crates/envcloak-spend/src/controls/controls.toml"),
        tmp_toml_dir.join("controls.toml"),
    )
    .unwrap();
    std::fs::copy(
        root.join("crates/envcloak-spend/src/controls/table.rs"),
        tmp_toml_dir.join("table.rs"),
    )
    .unwrap();

    let spec_src = std::fs::read_to_string(root.join("docs/SPEC.md")).unwrap();
    let mutated_spec = spec_src.replace(
        "| Alert only | Notifications | Nothing |",
        "| Alert only | Notifications | Requests |",
    );
    assert_ne!(spec_src, mutated_spec);
    std::fs::write(tmp_docs_dir.join("SPEC.md"), mutated_spec).unwrap();

    let bad = Command::new("python3")
        .arg(&script)
        .arg("--check")
        .arg("--root")
        .arg(tmp.path())
        .output()
        .unwrap();
    assert!(
        !bad.status.success(),
        "gen-controls.py --check must fail when a SPEC cell is edited"
    );
}

/// Verifies `scripts/check-spend-labels.sh` passes on the workspace and refuses
/// `"Hard cap"` or control-table text literals in a CLI or daemon file (`§5`
/// rule 2).
#[test]
fn check_spend_labels_passes_and_refuses_hard_cap_in_cli() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent().unwrap().parent().unwrap();
    let script = root.join("scripts/check-spend-labels.sh");

    let status = Command::new("bash")
        .arg(&script)
        .arg(root)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "check-spend-labels.sh must pass on workspace"
    );

    // Refusal fixture 1: "Hard cap" in a CLI file.
    let tmp = ScratchDir::new("cli-refusal");
    let tmp_ctrl_dir = tmp.path().join("crates/envcloak-spend/src/controls");
    let tmp_cli_dir = tmp.path().join("crates/envcloak-cli/src/cmd");
    std::fs::create_dir_all(&tmp_ctrl_dir).unwrap();
    std::fs::create_dir_all(&tmp_cli_dir).unwrap();
    std::fs::copy(
        root.join("crates/envcloak-spend/src/controls/controls.toml"),
        tmp_ctrl_dir.join("controls.toml"),
    )
    .unwrap();
    std::fs::write(
        tmp_cli_dir.join("budget.rs"),
        "pub fn bad() -> &'static str { \"Hard cap of 20 USD\" }\n",
    )
    .unwrap();

    let out1 = Command::new("bash")
        .arg(&script)
        .arg(tmp.path())
        .output()
        .unwrap();
    assert!(
        !out1.status.success(),
        "check-spend-labels.sh must refuse 'Hard cap' in a CLI file"
    );

    // Refusal fixture 2: a control-table text literal outside envcloak-spend/src/controls/.
    std::fs::write(
        tmp_cli_dir.join("budget.rs"),
        "pub fn bad() -> &'static str { \"The provider (a spend or key limit set in its API or dashboard)\" }\n",
    )
    .unwrap();
    let out2 = Command::new("bash")
        .arg(&script)
        .arg(tmp.path())
        .output()
        .unwrap();
    assert!(
        !out2.status.success(),
        "check-spend-labels.sh must refuse a control-table literal in a CLI file"
    );

    // Refusal fixture 3: character literal `'"'` before `"Hard cap"` and raw string literal.
    std::fs::write(
        tmp_cli_dir.join("budget.rs"),
        "pub fn bad(c: char) -> &'static str { if c == '\"' { return \"q\"; } r#\"Hard cap of 20 USD\"# }\n",
    )
    .unwrap();
    let out3 = Command::new("bash")
        .arg(&script)
        .arg(tmp.path())
        .output()
        .unwrap();
    assert!(
        !out3.status.success(),
        "check-spend-labels.sh must refuse 'Hard cap' after a double-quote character literal or inside a raw string"
    );
}
