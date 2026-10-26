//! M4-02 integration tests: money, PAN detection, M4 spend policy records
//! (kinds 5 to 11), gate s9 (no byte-string over 64 bytes or unbounded string),
//! crash consistency on snapshot overwrite (gate 5), read-only open on unknown
//! policy kind/version (gate 6), and the D4-09 / K4-04 write-cost measurement.

use std::collections::BTreeMap;
use std::process::Command;
use std::time::Instant;

use envcloak_core::crypto::{
    Argon2id, EnvelopeCtx, ItemClass, KdfParams, UnlockerId, UnlockerKind, VaultId, Vmk,
    wrap_vmk_with,
};
use envcloak_core::money::{
    Iso4217, Money, MoneyError, Rounding, Unit, parse_decimal, parse_decimal_with_rounding,
};
use envcloak_core::pan::{CardBrand, find_pan_in_text, luhn_bin};
use envcloak_core::secret::SecretBytes;
use envcloak_core::vault::{
    Account, AccountLinkRecord, AlertRuleKind, AlertRuleRecord, BillingCadence, BudgetPeriod,
    BudgetRecord, BudgetScope, CapEnforcement, CapScope, Classification, ControlFactRecord,
    FieldName, INITIAL_EPOCH, Integrity, ItemDetails, ItemId, KeySpendMetric, LimitResetPeriod,
    Links, LockedVault, MAX_DAILY_BUCKETS, MAX_FIELD, MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_KEYS,
    MAX_SPEND_STR, ManualFactRecord, ManualFactTarget, NewItem, PolicyId, PolicyKind, PolicyRecord,
    Slug, SnapshotBucket, SnapshotResultClass, SpendAccountId, SpendAttribution, SpendSnapshot,
    SpendSource, SubjectKindRecord, SubscriptionRecord, TamperKind, Vault, VaultErrorKind,
    VaultPaths,
};
use rusqlite::Connection;

fn test_vault() -> (tempfile::TempDir, VaultPaths, Vec<u8>, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let paths = VaultPaths::under(dir.path().join("data"));
    let vault_id = VaultId::generate();
    let vmk = Vmk::generate();
    let raw_vmk = vmk.export_for_testing();
    let env = wrap_vmk_with(
        &vmk,
        &SecretBytes::copy_from(b"spend-write-cost-passphrase"),
        UnlockerKind::Passphrase,
        &EnvelopeCtx {
            vault_id,
            unlocker_id: UnlockerId::generate(),
            epoch: INITIAL_EPOCH,
        },
        &KdfParams::minimum(),
        &Argon2id,
    )
    .unwrap();
    let vault = Vault::create(&paths, vault_id, vmk, vec![env]).unwrap();
    (dir, paths, raw_vmk, vault)
}

fn sample_snapshot(provider: &str, account: &str, read_at: u64, key_count: usize) -> SpendSnapshot {
    let usd = Iso4217::USD;
    let key_metrics = (0..key_count)
        .map(|i| {
            let mut id = [0u8; 16];
            id[0] = (i >> 8) as u8;
            id[1] = (i & 0xff) as u8;
            KeySpendMetric {
                item: ItemId::from_bytes(id),
                attribution: SpendAttribution::SameKey,
                spend_month: Some(Money::new(1250 + i as i64, 2, usd).unwrap()),
                spend_total: Some(Money::new(9800 + i as i64, 2, usd).unwrap()),
                limit: Some(Money::new(50_000, 2, usd).unwrap()),
                limit_remaining: Some(Money::new(48_750 - i as i64, 2, usd).unwrap()),
                expires_at: Some(1_800_000_000),
                invalid: false,
                is_management_key: false,
            }
        })
        .collect();
    let buckets = (0..MAX_DAILY_BUCKETS)
        .map(|d| SnapshotBucket {
            day_index: 20_000 + d as u32,
            spend: Money::new(350 + d as i64, 2, usd).unwrap(),
            partial: d % 7 == 0,
        })
        .collect();
    SpendSnapshot {
        account: SpendAccountId {
            provider: provider.to_owned(),
            account: account.to_owned(),
        },
        polling_enabled: true,
        read_at,
        source: SpendSource::Poll,
        attribution: SpendAttribution::SameKey,
        last_result: SnapshotResultClass::Ok,
        balance: Some(Money::new(42_50, 2, usd).unwrap()),
        credit_limit: Some(Money::new(100_00, 2, usd).unwrap()),
        limit_remaining: Some(Money::new(57_50, 2, usd).unwrap()),
        limit_reset: Some(LimitResetPeriod::Monthly),
        spend_day: Some(Money::new(3_50, 2, usd).unwrap()),
        spend_week: Some(Money::new(21_00, 2, usd).unwrap()),
        spend_month: Some(Money::new(42_50, 2, usd).unwrap()),
        spend_total: Some(Money::new(142_50, 2, usd).unwrap()),
        expires_at: Some(1_800_000_000),
        is_management_key: Some(false),
        byok_in_limit: Some(false),
        key_metrics,
        buckets,
    }
}

#[test]
fn golden_money_units_and_mixed_currency_refusal() {
    let c = parse_decimal("1234", Unit::CentsString(Iso4217::USD)).unwrap();
    assert_eq!(c, Money::new(1234, 2, Iso4217::USD).unwrap());
    assert_eq!(c.to_string(), "12.34 USD");

    let d = parse_decimal("1234", Unit::DecimalString(Iso4217::USD)).unwrap();
    assert_eq!(d, Money::new(123_400, 2, Iso4217::USD).unwrap());
    assert_eq!(d.to_string(), "1234.00 USD");

    assert_eq!(
        parse_decimal("0.1", Unit::Major(Iso4217::USD)).unwrap(),
        Money::new(10, 2, Iso4217::USD).unwrap()
    );
    assert_eq!(
        parse_decimal("1e2", Unit::Major(Iso4217::USD)).unwrap(),
        Money::new(10_000, 2, Iso4217::USD).unwrap()
    );
    assert_eq!(
        parse_decimal("-0", Unit::Major(Iso4217::USD)).unwrap(),
        Money::new(0, 2, Iso4217::USD).unwrap()
    );
    assert_eq!(
        parse_decimal_with_rounding(
            "12.345678901",
            &Unit::Major(Iso4217::USD),
            Rounding::HalfAwayFromZero
        )
        .unwrap(),
        Money::new(12_345_679, 6, Iso4217::USD).unwrap()
    );

    let usd = Money::new(500, 2, Iso4217::USD).unwrap();
    let eur = Money::new(500, 2, Iso4217::EUR).unwrap();
    assert_eq!(
        usd.checked_add(&eur),
        Err(MoneyError::CurrencyMismatch {
            expected: Iso4217::USD,
            actual: Iso4217::EUR,
        })
    );
}

#[test]
fn luhn_recognises_test_cards_and_rejects_order_ids() {
    let visa = luhn_bin(b"4111111111111111").expect("Visa test number");
    assert_eq!(visa.brand(), CardBrand::Visa);
    assert_eq!(visa.last4_str(), "1111");
    assert_eq!(luhn_bin(b"1000000000000008"), None);
    assert_eq!(find_pan_in_text("order 1000000000000008"), None);
}

#[test]
fn snapshot_size_stays_under_48_kib_and_oversized_records_are_refused() {
    // Largest valid snapshot: 64-byte provider & account, 256 key metrics, 35 daily buckets.
    let max_provider = "p".repeat(MAX_SPEND_STR);
    let max_account = "a".repeat(MAX_SPEND_STR);
    let largest = sample_snapshot(
        &max_provider,
        &max_account,
        1_750_000_000,
        MAX_SNAPSHOT_KEYS,
    );
    let record = PolicyRecord::SpendSnapshot(largest.clone());
    record.check().expect("largest valid snapshot in bounds");
    let encoded = record.encode();
    assert!(
        encoded.len() <= MAX_SNAPSHOT_BYTES,
        "largest snapshot encoded to {} bytes (> {} bytes)",
        encoded.len(),
        MAX_SNAPSHOT_BYTES
    );
    assert_eq!(PolicyRecord::decode(&encoded).unwrap(), record);

    // 36th daily bucket is refused (Buckets appended without bound -> size/bounds test fails).
    let mut unbounded_buckets = largest.clone();
    unbounded_buckets.buckets.push(SnapshotBucket {
        day_index: 20_000 + MAX_DAILY_BUCKETS as u32,
        spend: Money::new(100, 2, Iso4217::USD).unwrap(),
        partial: false,
    });
    let bad_buckets = PolicyRecord::SpendSnapshot(unbounded_buckets);
    assert_eq!(
        bad_buckets.check().unwrap_err().kind(),
        VaultErrorKind::InvalidRecord
    );
    assert_eq!(
        PolicyRecord::decode(&bad_buckets.encode())
            .unwrap_err()
            .kind(),
        VaultErrorKind::Corrupt
    );

    // A 65 KiB raw policy record is refused before write with TooLarge.
    let (_dir, _paths, _raw, mut v) = test_vault();
    let err = v
        .transact(|t| t.put_raw_policy_for_testing(PolicyId::generate(), &vec![0u8; 65 * 1024]))
        .unwrap_err();
    assert_eq!(err.kind(), VaultErrorKind::TooLarge);
    assert!(65 * 1024 > MAX_FIELD);
}

/// Gate s9: Spend records hold no value; any byte-string field over 64 bytes
/// or empty string is refused across all 7 M4 policy record kinds, and the
/// schema defines no arbitrary `Vec<u8>` field.
#[test]
fn gate_s9_spend_records_refuse_strings_over_64_bytes() {
    let over64 = "x".repeat(MAX_SPEND_STR + 1);
    let usd20 = Money::new(2000, 2, Iso4217::USD).unwrap();
    let valid_acc = SpendAccountId {
        provider: "openrouter".into(),
        account: "default".into(),
    };

    let bad_records = vec![
        // Kind 5: SubscriptionRecord
        PolicyRecord::Subscription(SubscriptionRecord {
            name: over64.clone(),
            provider: Some("anthropic".into()),
            account: None,
            amount: usd20,
            cadence: BillingCadence::Monthly,
            renewal_at: None,
            linked_items: Vec::new(),
            created_at: 100,
            updated_at: 100,
        }),
        PolicyRecord::Subscription(SubscriptionRecord {
            name: "Claude".into(),
            provider: Some(over64.clone()),
            account: None,
            amount: usd20,
            cadence: BillingCadence::Monthly,
            renewal_at: None,
            linked_items: Vec::new(),
            created_at: 100,
            updated_at: 100,
        }),
        // Kind 6: BudgetRecord
        PolicyRecord::Budget(BudgetRecord {
            scope: BudgetScope::Provider(over64.clone()),
            amount: usd20,
            period: BudgetPeriod::Monthly,
            tz: "UTC".into(),
            thresholds: vec![50, 100],
            created_at: 100,
            updated_at: 100,
        }),
        PolicyRecord::Budget(BudgetRecord {
            scope: BudgetScope::Provider("openai".into()),
            amount: usd20,
            period: BudgetPeriod::Monthly,
            tz: over64.clone(),
            thresholds: vec![50, 100],
            created_at: 100,
            updated_at: 100,
        }),
        // Kind 7: AlertRuleRecord
        PolicyRecord::AlertRule(AlertRuleRecord {
            rule: AlertRuleKind::Spike,
            scope: BudgetScope::Provider("openai".into()),
            raised_at: Some(100),
            raised_source: Some(SpendSource::ClientReported {
                subject: SubjectKindRecord::Terminal,
                tool: over64.clone(),
            }),
            dedupe_period: None,
            acked_at: None,
            snoozed_until: None,
            created_at: 100,
            updated_at: 100,
        }),
        // Kind 8: ManualFactRecord
        PolicyRecord::ManualFact(ManualFactRecord {
            target: ManualFactTarget::Account(valid_acc.clone()),
            balance: Some(usd20),
            spend_mtd: None,
            renewal_at: None,
            plan: Some(over64.clone()),
            read_at: 100,
            source: SpendSource::Manual {
                subject: SubjectKindRecord::Terminal,
            },
            attribution: SpendAttribution::Manual,
        }),
        // Kind 9: ControlFactRecord
        PolicyRecord::ControlFact(ControlFactRecord {
            target: ManualFactTarget::Account(valid_acc),
            amount: usd20,
            reset: Some(LimitResetPeriod::Monthly),
            remaining: None,
            scope: CapScope::Key,
            enforcement: CapEnforcement::EnforcingDocumented {
                citation: over64.clone(),
            },
            byok_in_limit: None,
            source: SpendSource::Poll,
            read_at: 100,
        }),
        // Kind 10: SpendSnapshot
        PolicyRecord::SpendSnapshot(sample_snapshot(&over64, "default", 100, 1)),
        PolicyRecord::SpendSnapshot(sample_snapshot("openrouter", &over64, 100, 1)),
        // Kind 11: AccountLinkRecord
        PolicyRecord::AccountLink(AccountLinkRecord {
            item: ItemId::from_bytes([1; 16]),
            usage_credential: None,
            provider: "openai".into(),
            provider_key_id: over64,
            attribution: SpendAttribution::AdminMatchedByHint,
            linked_at: 100,
        }),
    ];

    let (_dir, _paths, _raw, mut v) = test_vault();
    for bad in bad_records {
        assert_eq!(
            bad.check().unwrap_err().kind(),
            VaultErrorKind::InvalidRecord,
            "check() must reject >64-byte string in {:?}",
            bad.kind()
        );
        let bytes = bad.encode();
        assert_eq!(
            PolicyRecord::decode(&bytes).unwrap_err().kind(),
            VaultErrorKind::Corrupt,
            "decode() must reject >64-byte string in {:?}",
            bad.kind()
        );
        assert_eq!(
            v.transact(|t| t.put_policy(PolicyId::generate(), &bad))
                .unwrap_err()
                .kind(),
            VaultErrorKind::InvalidRecord
        );
    }

    // Structural schema check on crates/envcloak-core/src/vault/policy/: no
    // M4 spend policy record encodes or decodes raw byte strings (`e.bytes(`,
    // `d.bytes(`, `opt_bytes(`) and every decoded string goes through
    // `spend_str_ok` (`MAX_SPEND_STR` = 64).
    let policy_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/vault/policy");
    for entry in std::fs::read_dir(&policy_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            let src = std::fs::read_to_string(&path).unwrap();
            for forbidden in ["e.bytes(", "d.bytes(", ".opt_bytes(", ".strings("] {
                assert!(
                    !src.contains(forbidden),
                    "{} must not use `{forbidden}` (gate s9: no arbitrary byte-string or unbounded string list)",
                    path.display()
                );
            }
        }
    }
}

/// Gate 6: An unknown policy kind or unknown version opens the vault read-only
/// (`Integrity::Tampered(TamperKind::RowInconsistent)`).
#[test]
fn unknown_policy_kind_or_version_opens_vault_read_only() {
    for (kind_byte, version_byte) in [
        (PolicyKind::Subscription as u8, 2u8),
        (PolicyKind::SpendSnapshot as u8, 2u8),
        (PolicyKind::AccountLink as u8, 99u8),
        (12u8, 1u8),
    ] {
        let (_dir, paths, raw_vmk, mut v) = test_vault();
        let snap = PolicyRecord::SpendSnapshot(sample_snapshot("openrouter", "default", 100, 1));
        let mut raw_bytes = snap.encode();
        raw_bytes[0] = kind_byte;
        raw_bytes[1] = version_byte;
        v.transact(|t| t.put_raw_policy_for_testing(PolicyId::generate(), &raw_bytes))
            .unwrap();
        drop(v);

        let reopened = LockedVault::open(&paths)
            .unwrap()
            .unlock(Vmk::import_for_testing(&raw_vmk).unwrap())
            .map_err(|(_, e)| e)
            .unwrap();
        assert_eq!(
            reopened.integrity(),
            Integrity::Tampered(TamperKind::RowInconsistent),
            "kind={kind_byte} version={version_byte} must open read-only"
        );
        assert_eq!(
            reopened.policies().err().unwrap().kind(),
            VaultErrorKind::Tampered
        );
    }
}

/// Gate 5: `kill -9` (`SIGKILL`) during a `SpendSnapshot` overwrite loop
/// reopens cleanly at the last committed transaction with `Integrity::Ok`.
#[test]
fn sigkill_during_snapshot_overwrite_reopens_at_last_commit() {
    const CHILD_ENV: &str = "ENVCLOAK_SPEND_CRASH_CHILD";
    if let Ok(dir_str) = std::env::var(CHILD_ENV) {
        let dir = std::path::PathBuf::from(dir_str);
        let paths = VaultPaths::under(dir.join("data"));
        let raw_vmk = std::fs::read(dir.join("vmk.bin")).unwrap();
        let raw_id: [u8; 16] = std::fs::read(dir.join("policy_id.bin"))
            .unwrap()
            .try_into()
            .unwrap();
        let policy_id = PolicyId::from_bytes(raw_id);
        let mut vault = LockedVault::open(&paths)
            .unwrap()
            .unlock(Vmk::import_for_testing(&raw_vmk).unwrap())
            .map_err(|(_, e)| e)
            .unwrap();
        let marker = dir.join("committed.txt");
        for step in 1u64..=5_000 {
            let snap = PolicyRecord::SpendSnapshot(sample_snapshot(
                "openrouter",
                "default",
                1_750_000_000 + step,
                4,
            ));
            vault.transact(|t| t.put_policy(policy_id, &snap)).unwrap();
            std::fs::write(&marker, step.to_string()).unwrap();
        }
        return;
    }

    let (dir, paths, raw_vmk, mut v) = test_vault();
    let policy_id = PolicyId::generate();
    let initial =
        PolicyRecord::SpendSnapshot(sample_snapshot("openrouter", "default", 1_750_000_000, 4));
    v.transact(|t| t.put_policy(policy_id, &initial)).unwrap();
    drop(v);

    std::fs::write(dir.path().join("vmk.bin"), &raw_vmk).unwrap();
    std::fs::write(dir.path().join("policy_id.bin"), policy_id.as_bytes()).unwrap();
    std::fs::write(dir.path().join("committed.txt"), "0").unwrap();

    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .arg("--exact")
        .arg("sigkill_during_snapshot_overwrite_reopens_at_last_commit")
        .arg("--nocapture")
        .env(CHILD_ENV, dir.path())
        .spawn()
        .unwrap();

    // Wait until the child has completed at least one overwrite commit, then
    // send SIGKILL mid-stream.
    let marker = dir.path().join("committed.txt");
    let start = Instant::now();
    while start.elapsed().as_millis() < 2_000 {
        if let Ok(s) = std::fs::read_to_string(&marker) {
            if s.trim().parse::<u64>().unwrap_or(0) >= 2 {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let _ = child.kill();
    let _ = child.wait();

    let last_reported: u64 = std::fs::read_to_string(&marker)
        .unwrap_or_else(|_| "0".into())
        .trim()
        .parse()
        .unwrap_or(0);

    let reopened = LockedVault::open(&paths)
        .unwrap()
        .unlock(Vmk::import_for_testing(&raw_vmk).unwrap())
        .map_err(|(_, e)| e)
        .unwrap();
    assert_eq!(reopened.integrity(), Integrity::Ok);
    let mut policies = reopened.policies().unwrap();
    let Some((_, PolicyRecord::SpendSnapshot(snap))) = policies.find(|(id, _)| *id == policy_id)
    else {
        panic!("expected SpendSnapshot policy row after crash recovery");
    };
    let committed_step = snap.read_at - 1_750_000_000;
    // The kill may land either before the marker write (committed_step ==
    // last_reported + 1) or after the marker write (committed_step ==
    // last_reported).
    assert!(
        committed_step == last_reported || committed_step == last_reported + 1,
        "committed_step={committed_step}, last_reported={last_reported}"
    );
}

fn snapshot_db_rows(db_path: &std::path::Path) -> BTreeMap<(String, Vec<u8>), (i64, Vec<u8>)> {
    let snap_dir = tempfile::tempdir().unwrap();
    let copy_db = snap_dir.path().join("vault.db");
    std::fs::copy(db_path, &copy_db).unwrap();
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut src_side = db_path.as_os_str().to_os_string();
        src_side.push(suffix);
        let src_side = std::path::PathBuf::from(src_side);
        if src_side.exists() {
            let mut dst_side = copy_db.as_os_str().to_os_string();
            dst_side.push(suffix);
            std::fs::copy(&src_side, std::path::PathBuf::from(dst_side)).unwrap();
        }
    }
    let conn = Connection::open(&copy_db).unwrap();
    let mut out = BTreeMap::new();
    for (table, sql) in [
        (
            "header",
            "SELECT CAST(epoch AS BLOB), schema_version, sealed FROM header",
        ),
        ("items", "SELECT id, row_version, sealed_meta FROM items"),
        ("fields", "SELECT id, row_version, sealed_value FROM fields"),
        ("projects", "SELECT id, row_version, sealed FROM projects"),
        ("policies", "SELECT id, row_version, sealed FROM policies"),
        ("unlockers", "SELECT id, kind, envelope FROM unlockers"),
    ] {
        let mut st = conn.prepare(sql).unwrap();
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .unwrap();
        for row in rows {
            let (id, rv, sealed) = row.unwrap();
            out.insert((table.to_owned(), id), (rv, sealed));
        }
    }
    out
}

/// D4-09 / K4-04 write-cost measurement:
/// - Vault populated with 500 `secret` items (500 `items` rows + 500 `fields`
///   rows + 1 `unlockers` row = 1,001 baseline stamped rows).
/// - Measures 1, 10, and 50 provider accounts (`SpendSnapshot` policy rows).
/// - Verifies the machine-independent kill-criterion gates:
///   1. Transactions per account update == 1 (`<= 1`).
///   2. Rows re-sealed per account update == 2 (`1` policy row + `1` header row,
///      `<= 2`; none of the other policy rows or 1,000 item/field rows is
///      re-sealed).
///   3. State-digest input bytes hashed per commit (`stamped_rows * 58` bytes)
///      at 50 accounts is `1,051 * 58 = 60,958` bytes (`<= 64 KiB = 65,536`).
///   4. Snapshot encoded size is under `48 KiB`.
#[test]
fn d4_09_write_cost_measurement_retires_k4_04() {
    const ITEM_COUNT: usize = 500;
    const STAMP_BYTES_PER_ROW: usize = 58; // table(2) + row_id(16) + row_version(8) + sha256(32)

    let (_dir, paths, raw_vmk, mut v) = test_vault();

    // Populate 500 secret items with 1 field each in one setup transaction.
    v.transact(|t| {
        for i in 0..ITEM_COUNT {
            let slug = Slug::new(&format!("service-{i:03}/api-key")).unwrap();
            let details = ItemDetails {
                title: format!("Service {i}"),
                provider: Some("openrouter".into()),
                account: Account::default(),
                env_hint: Some("API_KEY".into()),
                classification: Classification::Live,
                allowed_hosts: vec!["openrouter.ai".into()],
                allow_short: false,
                tags: Vec::new(),
                links: Links::default(),
                expires_at: None,
                rotated_at: None,
                last_used_at: None,
                notes: String::new(),
            };
            let item_id = t
                .create_item(NewItem {
                    class: ItemClass::Secret,
                    slug,
                    details,
                })
                .unwrap();
            t.add_field(
                item_id,
                FieldName::new("value").unwrap(),
                SecretBytes::copy_from(format!("sk-or-v1-test-value-{i:04}-padding").as_bytes()),
            )
            .unwrap();
        }
        Ok(())
    })
    .unwrap();

    for account_count in [1usize, 10, 50] {
        let mut policy_ids = Vec::with_capacity(account_count);
        v.transact(|t| {
            for a in 0..account_count {
                let id = PolicyId::from_bytes({
                    let mut b = [0u8; 16];
                    b[0] = account_count as u8;
                    b[1] = a as u8;
                    b
                });
                let snap = PolicyRecord::SpendSnapshot(sample_snapshot(
                    "openrouter",
                    &format!("acct-{a:02}"),
                    1_750_000_000,
                    4,
                ));
                t.put_policy(id, &snap)?;
                policy_ids.push(id);
            }
            Ok(())
        })
        .unwrap();

        let db_file = paths.vault_dir.join("vault.db");
        let before_rows = snapshot_db_rows(&db_file);
        let counter_before = v.header().unwrap().write_counter;

        // Overwrite account 0's snapshot and verify exact row-reseal and transaction counts.
        let updated_snap =
            PolicyRecord::SpendSnapshot(sample_snapshot("openrouter", "acct-00", 1_750_003_600, 4));
        let encoded_len = updated_snap.encode().len();
        assert!(encoded_len <= MAX_SNAPSHOT_BYTES);

        v.transact(|t| t.put_policy(policy_ids[0], &updated_snap))
            .unwrap();

        let counter_after = v.header().unwrap().write_counter;
        let txns_per_account = counter_after - counter_before;
        assert_eq!(
            txns_per_account, 1,
            "expected 1 transaction per account update"
        );

        let after_rows = snapshot_db_rows(&db_file);
        assert_eq!(before_rows.len(), after_rows.len());
        let changed_tables: Vec<&str> = before_rows
            .iter()
            .filter(|(k, old_val)| after_rows.get(*k) != Some(*old_val))
            .map(|((table, _), _)| table.as_str())
            .collect();
        assert_eq!(
            changed_tables,
            vec!["header", "policies"],
            "at {account_count} accounts, updating one snapshot must re-seal only 1 policy row and 1 header row"
        );

        let stamped_row_count = after_rows.len() - 1; // exclude header row
        let digest_bytes_per_commit = stamped_row_count * STAMP_BYTES_PER_ROW;
        assert!(
            digest_bytes_per_commit <= 64 * 1024,
            "at {account_count} accounts, state-digest input per commit is {digest_bytes_per_commit} bytes (> 64 KiB)"
        );

        // Measure median wall time over 20 single-account poll update commits.
        let mut samples_us = Vec::with_capacity(20);
        for run in 0..20u64 {
            let target_idx = (run as usize) % account_count;
            let snap = PolicyRecord::SpendSnapshot(sample_snapshot(
                "openrouter",
                &format!("acct-{target_idx:02}"),
                1_750_010_000 + run,
                4,
            ));
            let t0 = Instant::now();
            v.transact(|t| t.put_policy(policy_ids[target_idx], &snap))
                .unwrap();
            samples_us.push(t0.elapsed().as_micros());
        }
        samples_us.sort_unstable();
        let median_us = samples_us[samples_us.len() / 2];
        // Generous upper bound for CI machines (500 ms per commit).
        assert!(
            median_us < 500_000,
            "median single-account snapshot commit took {median_us} us"
        );

        // Clean up this tier's policy rows before the next tier.
        if account_count < 50 {
            v.transact(|t| {
                for id in &policy_ids {
                    t.delete_policy(*id)?;
                }
                Ok(())
            })
            .unwrap();
        }
    }

    // Verify unlock record count and unlock latency with 500 items + 50 account snapshots.
    drop(v);
    let t_unlock = Instant::now();
    let reopened = LockedVault::open(&paths)
        .unwrap()
        .unlock(Vmk::import_for_testing(&raw_vmk).unwrap())
        .map_err(|(_, e)| e)
        .unwrap();
    let unlock_ms = t_unlock.elapsed().as_millis();
    assert_eq!(reopened.integrity(), Integrity::Ok);
    assert_eq!(reopened.items().len(), ITEM_COUNT);
    assert_eq!(reopened.policies().unwrap().count(), 50);
    assert!(unlock_ms < 5_000, "unlock took {unlock_ms} ms");
}

#[test]
fn check_spend_floats_script_passes_and_catches_float_mutations() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let script = root.join("scripts/check-spend-floats.sh");
    let status = Command::new("bash")
        .arg(&script)
        .arg(root)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "check-spend-floats.sh must pass on workspace"
    );

    // Mutation check: a synthetic workspace with `f64` in money.rs fails.
    let tmp = tempfile::tempdir().unwrap();
    let fake_money = tmp.path().join("crates/envcloak-core/src");
    std::fs::create_dir_all(&fake_money).unwrap();
    std::fs::write(
        fake_money.join("money.rs"),
        "pub fn bad(x: i64) -> f64 { x as f64 }\n",
    )
    .unwrap();
    let out = Command::new("bash")
        .arg(&script)
        .arg(tmp.path())
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "check-spend-floats.sh must reject f64 in money.rs"
    );
}
