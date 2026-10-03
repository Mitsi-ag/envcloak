//! File backups v2 (SPEC §6.4 "Backups", M2 plan D-07; the format is in
//! docs/VAULT.md "File backups v2"): a backup holds ciphertext only and
//! gives each file back byte for byte, chunk by chunk, at every chunk
//! boundary; a chunk swapped, reordered, duplicated or cut does not open
//! where it is read, and a backup missing a chunk (its final one included)
//! never opens, so a restore is never partial; the creator and purpose
//! are sealed with it; a result is recorded once per file; caps refuse
//! rather than cut; backups go after 7 days, and so do the staging
//! directories interrupted backups left, never one still being written;
//! a backup the purge cannot remove stops no other and is never listed
//! again, and a purge removes nothing outside the directories it opened.
#![allow(clippy::unwrap_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{KitFixture, dir_names};
use envcloak_core::SecretBytes;
use envcloak_core::file_backup::{FILE_BACKUP_RETENTION, FileBackupId, STAGING_GRACE};
use envcloak_core::file_backup_v2::{
    BackupCreator, BackupOwner, BackupPurpose, CHUNK_V2, CreatorKind, CreatorProcess,
    FileBackupV2Writer, HEADER_LEN_V2, MAX_FILE_V2, MAX_FILES_V2, MAX_LABEL_V2, MAX_PATH_V2,
    PlannedFile, PurgeStepV2, StepV2, chunk_len, chunks_of, list_file_backups_v2,
    purge_file_backups_v2, purge_file_backups_v2_except, purge_file_backups_v2_observed,
};
use envcloak_core::vault::{Vault, VaultErrorKind};
use envcloak_testkit::{assert_no_canary, by_label, labels};
use sha2::{Digest, Sha256};

const MIB: usize = 1 << 20;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn creator(kind: CreatorKind) -> BackupCreator {
    BackupCreator {
        kind,
        evidence_digest: [0x5a; 32],
        agent: (kind == CreatorKind::Agent).then(|| "Claude Code".to_owned()),
        owner: BackupOwner {
            pid: 4242,
            start_time: 99,
            token: None,
            boot: Some([0x11; 16]),
        },
        chain: vec![
            CreatorProcess {
                pid: 4242,
                start_time: 99,
                token: None,
                sid: Some(4240),
                terminal: None,
            },
            CreatorProcess {
                pid: 4240,
                start_time: 98,
                token: Some(3),
                sid: Some(4240),
                terminal: Some(0x1000_0004),
            },
        ],
    }
}

/// Bytes of `len` that hold every fixture, one of them across the first
/// chunk boundary when the file is long enough, and bytes that are not
/// UTF-8.
fn content(f: &KitFixture, len: usize, salt: u8) -> Vec<u8> {
    let mut out: Vec<u8> = (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(salt) | 0x80)
        .collect();
    let mut at = 0;
    for c in &f.cs {
        let v = c.value();
        if at + v.len() > len {
            break;
        }
        out[at..at + v.len()].copy_from_slice(v);
        at += v.len() + 3;
    }
    let key = by_label(&f.cs, labels::GITHUB_TOKEN).value();
    if len > CHUNK_V2 + key.len() {
        let start = CHUNK_V2 - key.len() / 2;
        out[start..start + key.len()].copy_from_slice(key);
    }
    out
}

/// Writes a backup of `files` (path, mode, bytes) chunk by chunk.
fn write(v: &Vault, files: &[(&str, u32, &[u8])], kind: CreatorKind) -> FileBackupId {
    let plan = files
        .iter()
        .map(|(p, m, b)| PlannedFile {
            path: (*p).to_owned(),
            mode: *m,
            size: b.len() as u64,
        })
        .collect();
    let mut w = v
        .begin_file_backup_v2(BackupPurpose::Scrub, creator(kind), plan, now())
        .unwrap();
    put_all(&mut w, files);
    w.commit().unwrap().id
}

fn put_all(w: &mut FileBackupV2Writer, files: &[(&str, u32, &[u8])]) {
    for (i, (_, _, b)) in files.iter().enumerate() {
        let n = chunks_of(b.len() as u64);
        for c in 0..n {
            let start = c as usize * CHUNK_V2;
            let end = start + chunk_len(b.len() as u64, c).unwrap();
            let last = w
                .put(i, c, &SecretBytes::copy_from(&b[start..end]))
                .unwrap();
            assert_eq!(last, c + 1 == n);
        }
    }
    assert_eq!(w.next(), None);
}

/// Reads every file of backup `id` back through its chunks, each chunk
/// compared with the bytes at its place in `bodies`, after the backup's
/// own check.
fn assert_reads_back(v: &Vault, id: &FileBackupId, bodies: &[&[u8]]) {
    let r = v.open_file_backup_v2(id).unwrap();
    r.verify().unwrap();
    assert_eq!(r.meta().files.len(), bodies.len());
    for (i, (f, body)) in r.meta().files.iter().zip(bodies).enumerate() {
        assert_eq!(f.size, body.len() as u64);
        let n = chunks_of(f.size);
        for c in 0..n {
            let (data, last) = r.chunk(i, c).unwrap();
            assert_eq!(last, c + 1 == n);
            let start = c as usize * CHUNK_V2;
            let end = start + chunk_len(f.size, c).unwrap();
            assert!(data.ct_eq(&body[start..end]), "file {i} chunk {c}");
        }
        assert_eq!(
            r.chunk(i, n).unwrap_err().kind(),
            VaultErrorKind::InvalidRecord
        );
    }
}

fn data_file(v: &Vault, id: &FileBackupId) -> PathBuf {
    list_file_backups_v2(v.paths())
        .unwrap()
        .into_iter()
        .find(|b| b.id == *id)
        .unwrap()
        .dir
        .join("data")
}

/// Every file in the backups directory and below it.
fn backup_bytes(v: &Vault) -> Vec<u8> {
    fn walk(p: &Path, out: &mut Vec<u8>) {
        for e in std::fs::read_dir(p).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                walk(&e.path(), out);
            } else {
                out.extend(std::fs::read(e.path()).unwrap());
            }
        }
    }
    let mut out = Vec::new();
    walk(&v.paths().backups_dir, &mut out);
    out
}

/// Byte-for-byte at every chunk boundary: 0 bytes, 1 byte, one short of a
/// chunk, exactly a chunk and one more, exactly 1 MiB and one more. Each
/// file's SHA-256 is the one sealed; the backups directory holds no
/// fixture in any file, and the home holds none anywhere.
#[test]
fn every_size_comes_back_byte_for_byte() {
    let (f, v) = KitFixture::create();
    let sizes = [0, 1, CHUNK_V2 - 1, CHUNK_V2, CHUNK_V2 + 1, MIB, MIB + 1];
    let bodies: Vec<Vec<u8>> = sizes
        .iter()
        .enumerate()
        .map(|(i, n)| content(&f, *n, i as u8))
        .collect();
    let paths: Vec<String> = (0..sizes.len())
        .map(|i| format!("/h/.claude/projects/p/s{i}.jsonl"))
        .collect();
    let files: Vec<(&str, u32, &[u8])> = paths
        .iter()
        .zip(&bodies)
        .map(|(p, b)| (p.as_str(), 0o640, b.as_slice()))
        .collect();
    let id = write(&v, &files, CreatorKind::Terminal);
    assert_reads_back(
        &v,
        &id,
        &bodies.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    );
    let r = v.open_file_backup_v2(&id).unwrap();
    for (m, b) in r.meta().files.iter().zip(&bodies) {
        assert_eq!(m.size, b.len() as u64);
        assert_eq!(m.sha256, <[u8; 32]>::from(Sha256::digest(b)));
        assert_eq!(m.mode, 0o640);
    }
    assert_eq!(
        r.meta()
            .files
            .iter()
            .map(|m| m.path.clone())
            .collect::<Vec<_>>(),
        paths
    );
    assert_no_canary(&backup_bytes(&v), &f.cs);
    f.home.assert_clean(&f.cs);
}

/// The daemon, not the client, says who made a backup and why: what it
/// gives at the start is what the backup holds, sealed. A changed byte of
/// the metadata, the header or the key is refused, and so is a backup of
/// another vault.
#[test]
fn the_creator_and_purpose_are_sealed_with_the_backup() {
    let (f, v) = KitFixture::create();
    let body = content(&f, 100, 1);
    let id = write(
        &v,
        &[("/h/.claude/settings.json", 0o600, &body)],
        CreatorKind::Agent,
    );
    let r = v.open_file_backup_v2(&id).unwrap();
    assert_eq!(r.meta().creator, creator(CreatorKind::Agent));
    assert_eq!(r.meta().purpose, BackupPurpose::Scrub);
    drop(r);
    let path = data_file(&v, &id);
    let good = std::fs::read(&path).unwrap();
    // The header (its time and id included), the sealed key, a chunk, the
    // metadata and the trailer: one bit each.
    let len = good.len();
    for at in [
        0,
        30,
        45,
        HEADER_LEN_V2 + 10,
        HEADER_LEN_V2 + 90,
        len - 40,
        len - 1,
    ] {
        let mut bad = good.clone();
        bad[at] ^= 0x01;
        std::fs::write(&path, &bad).unwrap();
        let e = v.open_file_backup_v2(&id).and_then(|r| r.verify());
        assert_eq!(e.unwrap_err().kind(), VaultErrorKind::BackupDamaged, "{at}");
    }
    std::fs::write(&path, &good).unwrap();
    assert_reads_back(&v, &id, &[&body]);

    // Another vault's backup, in this vault's directory, does not open.
    let (other, ov) = KitFixture::create();
    let oid = write(&ov, &[("/h/.env", 0o600, b"A=1\n")], CreatorKind::Terminal);
    let from = data_file(&ov, &oid).parent().unwrap().to_owned();
    let to = v.paths().backups_dir.join(from.file_name().unwrap());
    std::fs::create_dir(&to).unwrap();
    std::fs::copy(from.join("data"), to.join("data")).unwrap();
    assert_eq!(
        v.open_file_backup_v2(&oid).unwrap_err().kind(),
        VaultErrorKind::BackupDamaged
    );
    drop(other);
}

/// The `index`th chunk record, as its bytes in the data file: each record
/// is its 4-byte length, then that many bytes.
fn chunk_span(good: &[u8], first_chunk_at: usize, index: usize) -> std::ops::Range<usize> {
    let mut start = first_chunk_at;
    for i in 0..=index {
        let len = u32::from_be_bytes(good[start..start + 4].try_into().unwrap()) as usize;
        if i == index {
            return start..start + 4 + len;
        }
        start += 4 + len;
    }
    unreachable!()
}

/// Swapped, reordered, duplicated or cut chunks are refused with a
/// value-free error (`backup_damaged`) where they are read, and the
/// backup as a whole fails its check. Two files of three and two chunks:
/// every chunk record but the two last is full, so moving one keeps the
/// layout, and only its associated data (file, chunk index, final flag)
/// can tell. A backup missing its final chunk (the metadata still after
/// the others, the trailer pointing at it) never opens: no restore is
/// ever partial.
#[test]
fn moved_chunks_never_open_and_a_missing_one_refuses_the_backup() {
    let (f, v) = KitFixture::create();
    let a = content(&f, 2 * CHUNK_V2 + 1, 3);
    let b = content(&f, 2 * CHUNK_V2, 4);
    let id = write(
        &v,
        &[
            ("/h/.codex/a.jsonl", 0o600, &a),
            ("/h/.codex/b.jsonl", 0o600, &b),
        ],
        CreatorKind::Terminal,
    );
    let path = data_file(&v, &id);
    let good = std::fs::read(&path).unwrap();
    let key_len = u32::from_be_bytes(good[HEADER_LEN_V2..HEADER_LEN_V2 + 4].try_into().unwrap());
    let first = HEADER_LEN_V2 + 4 + key_len as usize;
    // Records 0, 1 (full) and 2 (1 byte) of `a`; 3 and 4 (full) of `b`.
    let rec = |i: usize| chunk_span(&good, first, i);
    let refused = |bytes: &[u8], at: (usize, u64), what: &str| {
        std::fs::write(&path, bytes).unwrap();
        let r = v.open_file_backup_v2(&id).unwrap();
        assert_eq!(
            r.chunk(at.0, at.1).unwrap_err().kind(),
            VaultErrorKind::BackupDamaged,
            "{what}"
        );
        assert_eq!(
            r.verify().unwrap_err().kind(),
            VaultErrorKind::BackupDamaged,
            "{what}"
        );
    };
    let swapped = |x: usize, y: usize| {
        let mut bad = good.clone();
        let (rx, ry) = (rec(x), rec(y));
        let cx = good[rx.clone()].to_vec();
        bad[rx].copy_from_slice(&good[ry.clone()]);
        bad[ry].copy_from_slice(&cx);
        bad
    };
    // Swapped within a file, and reordered across files.
    refused(&swapped(0, 1), (0, 0), "a's chunks 0 and 1 swapped");
    refused(&swapped(0, 1), (0, 1), "a's chunks 0 and 1 swapped");
    refused(
        &swapped(1, 3),
        (0, 1),
        "a's chunk 1 and b's chunk 0 swapped",
    );
    refused(
        &swapped(1, 4),
        (1, 1),
        "a's chunk 1 and b's final chunk swapped",
    );
    // Duplicated: one chunk's record in another full chunk's place.
    for (x, y) in [(0, 1), (3, 4), (0, 3)] {
        let mut bad = good.clone();
        bad[rec(y)].copy_from_slice(&good[rec(x)]);
        let at = if y < 3 {
            (0, y as u64)
        } else {
            (1, (y - 3) as u64)
        };
        refused(&bad, at, "a chunk duplicated");
    }
    // Cut: shorter by one byte, or ending inside a chunk.
    for keep in [good.len() - 1, rec(1).start + 100, rec(4).end] {
        std::fs::write(&path, &good[..keep]).unwrap();
        assert_eq!(
            v.open_file_backup_v2(&id).unwrap_err().kind(),
            VaultErrorKind::BackupDamaged,
            "cut at {keep}"
        );
    }
    // Missing a final chunk: `a`'s last record taken out, the metadata
    // moved up to follow the others and the trailer pointing at it.
    let meta_at = u64::from_be_bytes(good[good.len() - 8..].try_into().unwrap()) as usize;
    let drop_rec = rec(2);
    let mut without = good[..drop_rec.start].to_vec();
    without.extend_from_slice(&good[drop_rec.end..meta_at]);
    let new_meta = without.len() as u64;
    without.extend_from_slice(&good[meta_at..good.len() - 8]);
    without.extend_from_slice(&new_meta.to_be_bytes());
    std::fs::write(&path, &without).unwrap();
    assert_eq!(
        v.open_file_backup_v2(&id).unwrap_err().kind(),
        VaultErrorKind::BackupDamaged
    );
    // One chunk too many: a's last record twice.
    let mut extra = good[..drop_rec.end].to_vec();
    extra.extend_from_slice(&good[drop_rec.clone()]);
    extra.extend_from_slice(&good[drop_rec.end..meta_at]);
    let new_meta = extra.len() as u64;
    extra.extend_from_slice(&good[meta_at..good.len() - 8]);
    extra.extend_from_slice(&new_meta.to_be_bytes());
    std::fs::write(&path, &extra).unwrap();
    assert_eq!(
        v.open_file_backup_v2(&id).unwrap_err().kind(),
        VaultErrorKind::BackupDamaged
    );
    // Put back, it reads whole again.
    std::fs::write(&path, &good).unwrap();
    assert_reads_back(&v, &id, &[&a, &b]);
}

/// A chunk is taken only in its place and at its exact length; a commit
/// needs every chunk; nothing is listed before the commit, and a writer
/// dropped before it leaves nothing behind.
#[test]
fn chunks_go_in_order_at_their_length_and_only_a_whole_backup_is_listed() {
    let (f, v) = KitFixture::create();
    let body = content(&f, CHUNK_V2 + 10, 5);
    let plan = vec![
        PlannedFile {
            path: "/h/.env".into(),
            mode: 0o600,
            size: body.len() as u64,
        },
        PlannedFile {
            path: "/h/.env.local".into(),
            mode: 0o600,
            size: 0,
        },
    ];
    let mut w = v
        .begin_file_backup_v2(
            BackupPurpose::Migrate,
            creator(CreatorKind::Terminal),
            plan.clone(),
            now(),
        )
        .unwrap();
    let chunk = |r: std::ops::Range<usize>| SecretBytes::copy_from(&body[r]);
    let invalid = VaultErrorKind::InvalidRecord;
    // Out of order, the wrong file, the wrong length.
    assert_eq!(
        w.put(0, 1, &chunk(CHUNK_V2..body.len()))
            .unwrap_err()
            .kind(),
        invalid
    );
    assert_eq!(
        w.put(1, 0, &SecretBytes::copy_from(b""))
            .unwrap_err()
            .kind(),
        invalid
    );
    assert_eq!(
        w.put(0, 0, &chunk(0..CHUNK_V2 - 1)).unwrap_err().kind(),
        invalid
    );
    assert_eq!(w.commit().unwrap_err().kind(), invalid);
    assert!(!w.put(0, 0, &chunk(0..CHUNK_V2)).unwrap());
    // The same chunk again: not the next one.
    assert_eq!(
        w.put(0, 0, &chunk(0..CHUNK_V2)).unwrap_err().kind(),
        invalid
    );
    assert_eq!(
        w.put(0, 1, &chunk(CHUNK_V2..body.len() - 1))
            .unwrap_err()
            .kind(),
        invalid
    );
    assert!(w.put(0, 1, &chunk(CHUNK_V2..body.len())).unwrap());
    assert_eq!(w.commit().unwrap_err().kind(), invalid);
    // A non-empty chunk for an empty file.
    assert_eq!(
        w.put(1, 0, &SecretBytes::copy_from(b"x"))
            .unwrap_err()
            .kind(),
        invalid
    );
    assert!(list_file_backups_v2(v.paths()).unwrap().is_empty());
    let staging: Vec<String> = dir_names(&v.paths().backups_dir);
    assert_eq!(staging.len(), 1, "{staging:?}");
    assert!(staging[0].starts_with(".files2-") && staging[0].ends_with(".tmp"));
    drop(w);
    // Dropped uncommitted: nothing is left.
    assert!(dir_names(&v.paths().backups_dir).is_empty());

    let mut w = v
        .begin_file_backup_v2(
            BackupPurpose::Migrate,
            creator(CreatorKind::Terminal),
            plan,
            now(),
        )
        .unwrap();
    put_all(
        &mut w,
        &[("/h/.env", 0o600, &body), ("/h/.env.local", 0o600, b"")],
    );
    let done = w.commit().unwrap();
    // Committed: frozen.
    assert_eq!(w.commit().unwrap_err().kind(), invalid);
    assert_eq!(
        w.put(0, 0, &chunk(0..CHUNK_V2)).unwrap_err().kind(),
        invalid
    );
    drop(w);
    let listed = list_file_backups_v2(v.paths()).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, done.id);
    assert_reads_back(&v, &done.id, &[&body, b""]);
}

/// What the change left is recorded once per file, sealed under the
/// backup's key and bound to its file: a second record, a result for a
/// file the backup lacks, a changed result and one moved to another
/// file's name are refused.
#[test]
fn a_result_is_recorded_once_per_file_and_sealed() {
    let (f, v) = KitFixture::create();
    let a = content(&f, 10, 6);
    let b = content(&f, 20, 7);
    let id = write(
        &v,
        &[
            ("/h/.claude.json", 0o600, &a),
            ("/h/.codex/config.toml", 0o600, &b),
        ],
        CreatorKind::Terminal,
    );
    let r = v.open_file_backup_v2(&id).unwrap();
    assert_eq!(r.results().unwrap(), [None, None]);
    let after: [u8; 32] = Sha256::digest(b"what scrub left").into();
    v.record_file_backup_v2_result(&id, 1, &after).unwrap();
    assert_eq!(r.results().unwrap(), [None, Some(after)]);
    assert_eq!(
        v.record_file_backup_v2_result(&id, 1, &[0; 32])
            .unwrap_err()
            .kind(),
        VaultErrorKind::AlreadyExists
    );
    assert_eq!(r.results().unwrap(), [None, Some(after)]);
    assert_eq!(
        v.record_file_backup_v2_result(&id, 2, &after)
            .unwrap_err()
            .kind(),
        VaultErrorKind::InvalidRecord
    );
    let dir = data_file(&v, &id).parent().unwrap().to_owned();
    // Moved to file 0's name: does not open as file 0's.
    std::fs::rename(dir.join("result-1"), dir.join("result-0")).unwrap();
    assert_eq!(
        r.results().unwrap_err().kind(),
        VaultErrorKind::BackupDamaged
    );
    std::fs::rename(dir.join("result-0"), dir.join("result-1")).unwrap();
    let good = std::fs::read(dir.join("result-1")).unwrap();
    let mut bad = good.clone();
    bad[30] ^= 1;
    std::fs::write(dir.join("result-1"), &bad).unwrap();
    assert_eq!(
        r.results().unwrap_err().kind(),
        VaultErrorKind::BackupDamaged
    );
    std::fs::write(dir.join("result-1"), &good).unwrap();
    v.record_file_backup_v2_result(&id, 0, &after).unwrap();
    assert_eq!(r.results().unwrap(), [Some(after), Some(after)]);
    assert_no_canary(&backup_bytes(&v), &f.cs);
}

/// Over a cap, a backup is refused (`too_large`) before anything is
/// written: a 300 MiB file, five of 256 MiB (over 1 GiB), 4,097 files.
#[test]
fn a_backup_over_its_caps_is_refused_before_anything_is_written() {
    let (_f, v) = KitFixture::create();
    let file = |size| PlannedFile {
        path: "/h/.claude/projects/p/big.jsonl".into(),
        mode: 0o600,
        size,
    };
    for plan in [
        vec![file(300 << 20)],
        vec![file(MAX_FILE_V2 + 1)],
        vec![file(MAX_FILE_V2); 5],
        vec![file(0); 4097],
    ] {
        let e = v
            .begin_file_backup_v2(
                BackupPurpose::Scrub,
                creator(CreatorKind::Terminal),
                plan,
                now(),
            )
            .unwrap_err();
        assert_eq!(e.kind(), VaultErrorKind::TooLarge);
    }
    assert!(!v.paths().backups_dir.exists() || dir_names(&v.paths().backups_dir).is_empty());
}

/// At both maxima together, 4,096 files each at the longest path (and the
/// longest agent label), a backup is taken, and it opens again whole:
/// the reader's bound on the metadata is the encoding's own.
#[test]
fn a_backup_at_every_maximum_at_once_opens_again() {
    let (_f, v) = KitFixture::create();
    let plan: Vec<PlannedFile> = (0..MAX_FILES_V2)
        .map(|i| {
            let name = format!("/h/.claude/projects/{i:04}/");
            PlannedFile {
                path: format!("{name}{}", "x".repeat(MAX_PATH_V2 - name.len())),
                mode: 0o600,
                size: 0,
            }
        })
        .collect();
    assert!(plan.iter().all(|p| p.path.len() == MAX_PATH_V2));
    let mut c = creator(CreatorKind::Agent);
    c.agent = Some("l".repeat(MAX_LABEL_V2));
    let mut w = v
        .begin_file_backup_v2(BackupPurpose::Scrub, c.clone(), plan.clone(), now())
        .unwrap();
    for i in 0..MAX_FILES_V2 {
        assert!(w.put(i, 0, &SecretBytes::copy_from(b"")).unwrap());
    }
    let id = w.commit().unwrap().id;
    let r = v.open_file_backup_v2(&id).unwrap();
    r.verify().unwrap();
    assert_eq!(r.meta().creator, c);
    assert_eq!(r.meta().files.len(), MAX_FILES_V2);
    assert!(
        r.meta()
            .files
            .iter()
            .zip(&plan)
            .all(|(f, p)| f.path == p.path)
    );
}

/// The 7-day purge, by the time in each header (an injected clock: `now`
/// is given), and the staging directories an interrupted backup left,
/// once unchanged for an hour; a fresh one stays, and so does a symlink
/// of that name, and its target.
#[test]
fn backups_are_purged_after_7_days_and_staging_after_an_hour() {
    let (f, v) = KitFixture::create();
    let t = now();
    let week = FILE_BACKUP_RETENTION.as_secs();
    let one = |at: u64| {
        let plan = vec![PlannedFile {
            path: "/h/.env".into(),
            mode: 0o600,
            size: 4,
        }];
        let mut w = v
            .begin_file_backup_v2(
                BackupPurpose::Init,
                creator(CreatorKind::Terminal),
                plan,
                at,
            )
            .unwrap();
        w.put(0, 0, &SecretBytes::copy_from(b"A=1\n")).unwrap();
        w.commit().unwrap().id
    };
    let old = one(t - week - 1);
    let young = one(t - week + 60);
    assert_eq!(list_file_backups_v2(v.paths()).unwrap().len(), 2);
    let dir = v.paths().backups_dir.clone();
    let stage = |name: &str, ago: u64| {
        let p = dir.join(name);
        std::fs::create_dir(&p).unwrap();
        std::fs::write(p.join("data"), b"sealed bytes only").unwrap();
        std::fs::File::open(&p)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(t - ago))
            .unwrap();
        p
    };
    let hour = STAGING_GRACE.as_secs() + 60;
    let stale = stage(".files2-20260901T000000Z-A.tmp", hour);
    let fresh = stage(".files2-20260901T000000Z-B.tmp", 5);
    let target = dir.join("elsewhere");
    std::fs::create_dir(&target).unwrap();
    let link = dir.join(".files2-20260901T000000Z-C.tmp");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_eq!(purge_file_backups_v2(v.paths(), t).unwrap(), 2);
    let ids: Vec<FileBackupId> = list_file_backups_v2(v.paths())
        .unwrap()
        .into_iter()
        .map(|b| b.id)
        .collect();
    assert_eq!(ids, [young]);
    assert_eq!(
        v.open_file_backup_v2(&old).unwrap_err().kind(),
        VaultErrorKind::NotFound
    );
    assert!(!stale.exists() && fresh.exists());
    assert!(link.symlink_metadata().is_ok() && target.exists());
    // A week on, the young one goes too.
    assert_eq!(purge_file_backups_v2(v.paths(), t + week).unwrap(), 2);
    assert!(list_file_backups_v2(v.paths()).unwrap().is_empty());
    drop(f);
}

/// Sets the modification time of `p` (a directory) to `at` (Unix seconds).
fn set_time(p: &Path, at: u64) {
    std::fs::File::open(p)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(at))
        .unwrap();
}

/// A committed backup of one 4-byte file, made at `at`.
fn small(v: &Vault, at: u64) -> FileBackupId {
    let plan = vec![PlannedFile {
        path: "/h/.env".into(),
        mode: 0o600,
        size: 4,
    }];
    let mut w = v
        .begin_file_backup_v2(
            BackupPurpose::Init,
            creator(CreatorKind::Terminal),
            plan,
            at,
        )
        .unwrap();
    w.put(0, 0, &SecretBytes::copy_from(b"A=1\n")).unwrap();
    w.commit().unwrap().id
}

/// Whether this process may write into a directory whose owner has only
/// read and search permission on it (it may as root).
fn writes_past_permissions(scratch: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let d = scratch.join("permission-probe");
    std::fs::create_dir(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o500)).unwrap();
    let wrote = std::fs::write(d.join("probe"), b"").is_ok();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_dir_all(&d).unwrap();
    wrote
}

/// Where the purge puts a backup's directory before it removes it:
/// `.files2-<time>-<id>.purge`, beside it.
fn purging(dir: &Path) -> PathBuf {
    let name = dir.file_name().unwrap().to_str().unwrap();
    dir.with_file_name(format!(".{name}.purge"))
}

/// A purge goes on past a backup it cannot remove. Three expired backups,
/// in the order the purge meets them: the first's directory holds a file
/// the purge does not own (a `.DS_Store`), which stays with its directory
/// while its `data` goes, deliberately and not as a failure; the second's
/// directory is made read-only, so its files cannot be removed (skipped
/// as root, which removes them anyway); the third is removed. The purge
/// then reports the second's failure, after the third went; once the
/// second can be removed, it goes too and the first is still kept. A
/// backup the purge began to remove is never listed again: the directory
/// kept for the `.DS_Store` is renamed out of the listing first.
#[test]
fn a_backup_the_purge_cannot_remove_stops_no_other() {
    use std::os::unix::fs::PermissionsExt;
    let (f, v) = KitFixture::create();
    let t = now();
    let expired = t - FILE_BACKUP_RETENTION.as_secs() - 1;
    for _ in 0..3 {
        small(&v, expired);
    }
    let listed = list_file_backups_v2(v.paths()).unwrap();
    let (kept, stuck, plain) = (&listed[0], &listed[1], &listed[2]);
    std::fs::write(kept.dir.join(".DS_Store"), b"finder").unwrap();
    let guarded = !writes_past_permissions(f.home.root());
    if guarded {
        std::fs::set_permissions(&stuck.dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
    let first = purge_file_backups_v2(v.paths(), t);
    assert!(
        list_file_backups_v2(v.paths()).unwrap().is_empty(),
        "a backup the purge began to remove is still listed"
    );
    assert!(!plain.dir.exists(), "a failure stopped the purge");
    if guarded {
        assert_eq!(
            first.unwrap_err().kind(),
            VaultErrorKind::Io(std::io::ErrorKind::PermissionDenied)
        );
        assert!(purging(&stuck.dir).join("data").exists());
        std::fs::set_permissions(purging(&stuck.dir), std::fs::Permissions::from_mode(0o700))
            .unwrap();
        assert_eq!(purge_file_backups_v2(v.paths(), t).unwrap(), 1);
    } else {
        assert_eq!(first.unwrap(), 2);
    }
    for gone in [stuck, plain] {
        assert!(!gone.dir.exists() && !purging(&gone.dir).exists());
    }
    assert!(!kept.dir.exists());
    assert_eq!(dir_names(&purging(&kept.dir)), [".DS_Store"]);
    // Kept again, and never counted as a failure.
    assert_eq!(purge_file_backups_v2(v.paths(), t).unwrap(), 0);
    assert_eq!(dir_names(&purging(&kept.dir)), [".DS_Store"]);
    // Once the foreign file is gone, the next purge removes the rest.
    std::fs::remove_file(purging(&kept.dir).join(".DS_Store")).unwrap();
    assert_eq!(purge_file_backups_v2(v.paths(), t).unwrap(), 1);
    assert!(dir_names(&v.paths().backups_dir).is_empty());
    drop(f);
}

/// A backup acts on the directories it opened, whatever takes their names
/// (L-11). A writer dropped unfinished removes its staging directory's
/// `data` through the handle it made it with: with that directory moved
/// away and a symlink to another directory in its place, the other
/// directory's `data` is kept, and so is the symlink. A reader records a
/// result in the backup's directory it opened: with that directory moved
/// away and a symlink in its place, the result is in the moved directory
/// and reads back, and nothing is written in the other directory.
#[test]
fn a_backup_acts_on_the_directories_it_opened() {
    let (f, v) = KitFixture::create();
    let t = now();
    let backups = v.paths().backups_dir.clone();
    let victim = f.home.root().join("victim");
    std::fs::create_dir(&victim).unwrap();
    std::fs::write(victim.join("data"), b"not the backup's").unwrap();
    let plan = vec![PlannedFile {
        path: "/h/.env".into(),
        mode: 0o600,
        size: 4,
    }];
    let w = v
        .begin_file_backup_v2(BackupPurpose::Init, creator(CreatorKind::Terminal), plan, t)
        .unwrap();
    let staging = dir_names(&backups);
    assert_eq!(staging.len(), 1);
    let away = f.home.root().join("staging-moved");
    std::fs::rename(backups.join(&staging[0]), &away).unwrap();
    std::os::unix::fs::symlink(&victim, backups.join(&staging[0])).unwrap();
    drop(w);
    assert_eq!(
        std::fs::read(victim.join("data")).ok().as_deref(),
        Some(&b"not the backup's"[..]),
        "a writer removed a file outside its staging directory"
    );
    assert!(dir_names(&away).is_empty(), "{:?}", dir_names(&away));
    assert!(
        backups
            .join(&staging[0])
            .symlink_metadata()
            .unwrap()
            .is_symlink()
    );
    std::fs::remove_file(backups.join(&staging[0])).unwrap();

    let id = small(&v, t);
    let r = v.open_file_backup_v2(&id).unwrap();
    let dir = data_file(&v, &id).parent().unwrap().to_owned();
    let moved = f.home.root().join("backup-moved");
    std::fs::rename(&dir, &moved).unwrap();
    std::os::unix::fs::symlink(&victim, &dir).unwrap();
    let after: [u8; 32] = Sha256::digest(b"what init left").into();
    r.record_result(0, &after).unwrap();
    assert_eq!(dir_names(&victim), ["data"], "a result written elsewhere");
    assert_eq!(dir_names(&moved), ["data", "result-0"]);
    assert_eq!(r.results().unwrap(), [Some(after)]);
    drop(f);
}

/// A purge removes nothing outside the directory it opened (L-11): right
/// before it removes the files of an expired backup's directory (renamed
/// out of the listing) and of an interrupted staging directory, a test
/// moves each directory away and puts a symlink to another directory in
/// its place, one holding files of the names a backup holds (`data`, a
/// result, a result's temporary name). Every one of those files is kept,
/// and so is each symlink; the backup's own files go from where its
/// directory went, through the handle the purge opened; and the purge
/// reports that a directory it was removing was replaced.
#[test]
fn a_purge_removes_nothing_outside_the_directory_it_opened() {
    let (f, v) = KitFixture::create();
    let t = now();
    small(&v, t - FILE_BACKUP_RETENTION.as_secs() - 1);
    let backups = v.paths().backups_dir.clone();
    let stale = backups.join(".files2-20260901T000000Z-00112233445566778899aabbccddeeff.tmp");
    std::fs::create_dir(&stale).unwrap();
    std::fs::write(stale.join("data"), b"sealed bytes only").unwrap();
    set_time(&stale, t - STAGING_GRACE.as_secs() - 60);
    let victim = f.home.root().join("victim");
    std::fs::create_dir(&victim).unwrap();
    let theirs = [
        "data",
        "result-0",
        ".result-0-00112233445566778899aabbccddeeff.tmp",
    ];
    for n in theirs {
        std::fs::write(victim.join(n), b"not the purge's").unwrap();
    }
    let mut moved = Vec::new();
    let e = purge_file_backups_v2_observed(
        v.paths(),
        t,
        |_| false,
        |step| {
            let PurgeStepV2::Removing(name) = step else {
                return;
            };
            let away = f.home.root().join(format!("moved-{}", moved.len()));
            std::fs::rename(backups.join(name), &away).unwrap();
            std::os::unix::fs::symlink(&victim, backups.join(name)).unwrap();
            moved.push((name.to_owned(), away));
        },
    )
    .unwrap_err();
    assert_eq!(moved.len(), 2, "{moved:?}");
    for n in theirs {
        assert_eq!(
            std::fs::read(victim.join(n)).ok().as_deref(),
            Some(&b"not the purge's"[..]),
            "{n}: a file outside backups/ was removed"
        );
    }
    for (name, away) in &moved {
        assert!(backups.join(name).symlink_metadata().unwrap().is_symlink());
        assert!(dir_names(away).is_empty(), "{name}: {:?}", dir_names(away));
    }
    assert_eq!(
        e.kind(),
        VaultErrorKind::Io(std::io::ErrorKind::NotADirectory)
    );
    drop(f);
}

/// A purge keeps the staging directory of a backup still being written,
/// however long ago the directory last changed (the chunks go to its
/// `data` file, which leaves the directory's time as it was), and removes
/// an interrupted one as old: it asks about each due staging directory,
/// and the backup in progress is then committed and reads back whole.
#[test]
fn a_purge_keeps_a_backup_in_progress() {
    let (f, v) = KitFixture::create();
    let t = now();
    let body = content(&f, CHUNK_V2 + 9, 3);
    let plan = vec![PlannedFile {
        path: "/h/.claude/projects/p/s.jsonl".into(),
        mode: 0o600,
        size: body.len() as u64,
    }];
    let mut w = v
        .begin_file_backup_v2(BackupPurpose::Scrub, creator(CreatorKind::Agent), plan, t)
        .unwrap();
    w.put(0, 0, &SecretBytes::copy_from(&body[..CHUNK_V2]))
        .unwrap();
    let dir = v.paths().backups_dir.clone();
    let staging: Vec<PathBuf> = dir_names(&dir)
        .into_iter()
        .filter(|n| n.starts_with(".files2-"))
        .map(|n| dir.join(n))
        .collect();
    assert_eq!(staging.len(), 1);
    let aged = t - STAGING_GRACE.as_secs() - 60;
    set_time(&staging[0], aged);
    let orphan_id = FileBackupId::generate();
    let orphan = dir.join(format!(".files2-20260901T000000Z-{orphan_id}.tmp"));
    std::fs::create_dir(&orphan).unwrap();
    std::fs::write(orphan.join("data"), b"sealed bytes only").unwrap();
    set_time(&orphan, aged);
    let mut asked = Vec::new();
    let removed = purge_file_backups_v2_except(v.paths(), t, |id| {
        asked.push(*id);
        *id == w.id()
    })
    .unwrap();
    assert_eq!(removed, 1);
    asked.sort_by_key(ToString::to_string);
    let mut due = vec![w.id(), orphan_id];
    due.sort_by_key(ToString::to_string);
    assert_eq!(asked, due);
    assert!(staging[0].exists() && !orphan.exists());
    w.put(0, 1, &SecretBytes::copy_from(&body[CHUNK_V2..]))
        .unwrap();
    let id = w.commit().unwrap().id;
    assert_reads_back(&v, &id, &[&body]);
    drop(f);
}

/// A purge renames a committed backup out of the listing only while its
/// name still names the directory it opened (L-11): once an expired
/// backup's directory is opened and found due, a test moves it away and
/// puts another directory of that name in its place, holding a `data` of
/// its own. That directory keeps its name, is still listed and keeps its
/// file; the one opened, moved away, keeps its files too; nothing is
/// renamed for the purge, and nothing is counted as removed.
#[test]
fn a_purge_renames_only_the_directory_it_opened() {
    let (f, v) = KitFixture::create();
    let t = now();
    let id = small(&v, t - FILE_BACKUP_RETENTION.as_secs() - 1);
    let backups = v.paths().backups_dir.clone();
    let dir = list_file_backups_v2(v.paths()).unwrap().remove(0).dir;
    let name = dir.file_name().unwrap().to_owned();
    let moved = f.home.root().join("opened-moved");
    let mut swapped = 0;
    let removed = purge_file_backups_v2_observed(
        v.paths(),
        t,
        |_| false,
        |step| {
            if let PurgeStepV2::Due(n) = step {
                std::fs::rename(backups.join(n), &moved).unwrap();
                std::fs::create_dir(backups.join(n)).unwrap();
                std::fs::write(backups.join(n).join("data"), b"not the purge's").unwrap();
                swapped += 1;
            }
        },
    )
    .unwrap();
    assert_eq!((swapped, removed), (1, 0));
    assert_eq!(
        std::fs::read(backups.join(&name).join("data"))
            .ok()
            .as_deref(),
        Some(&b"not the purge's"[..]),
        "the directory put in the backup's place was renamed or emptied"
    );
    assert!(!purging(&dir).exists());
    let listed: Vec<FileBackupId> = list_file_backups_v2(v.paths())
        .unwrap()
        .into_iter()
        .map(|b| b.id)
        .collect();
    assert_eq!(listed, [id]);
    assert_eq!(dir_names(&moved), ["data"]);
    drop(f);
}

/// A backup makes its staging directory in the `backups/` it opened, never
/// by its path again (L-11): right after `backups/` is opened, a test
/// moves it away and puts a symlink to another directory in its place.
/// The staging directory is made in the directory opened, nothing is made
/// in the other one, and the backup is committed where it was begun and
/// reads back.
#[test]
fn a_backup_makes_its_staging_directory_in_the_directory_it_opened() {
    let (f, v) = KitFixture::create();
    let backups = v.paths().backups_dir.clone();
    std::fs::create_dir_all(&backups).unwrap();
    let decoy = f.home.root().join("decoy");
    let held = f.home.root().join("backups-held");
    std::fs::create_dir(&decoy).unwrap();
    let plan = vec![PlannedFile {
        path: "/h/.env".into(),
        mode: 0o600,
        size: 4,
    }];
    let (from, to, link) = (backups.clone(), held.clone(), decoy.clone());
    let mut w = v
        .begin_file_backup_v2_observed(
            BackupPurpose::Init,
            creator(CreatorKind::Terminal),
            plan,
            now(),
            move |s| {
                if s == StepV2::Opened {
                    std::fs::rename(&from, &to).unwrap();
                    std::os::unix::fs::symlink(&link, &from).unwrap();
                }
            },
        )
        .unwrap();
    assert!(
        dir_names(&decoy).is_empty(),
        "a staging directory was made through the path: {:?}",
        dir_names(&decoy)
    );
    let staged = dir_names(&held);
    assert_eq!(staged.len(), 1, "{staged:?}");
    assert!(staged[0].starts_with(".files2-"), "{staged:?}");
    w.put(0, 0, &SecretBytes::copy_from(b"A=1\n")).unwrap();
    w.commit().unwrap();
    assert!(dir_names(&decoy).is_empty());
    let committed = dir_names(&held);
    assert_eq!(committed.len(), 1);
    assert!(committed[0].starts_with("files2-"), "{committed:?}");
    std::fs::remove_file(&backups).unwrap();
    std::fs::rename(&held, &backups).unwrap();
    let only = list_file_backups_v2(v.paths()).unwrap().remove(0).id;
    assert_reads_back(&v, &only, &[b"A=1\n"]);
    drop(f);
}

/// Nothing outside the vault's own `backups/` is listed, read, made or
/// removed when `backups/` itself, or the data directory that holds it,
/// is replaced by a symlink to a private directory of this user's
/// elsewhere holding backup-shaped entries (L-11, Codex round 8 high):
/// `backups/` is opened through the data directory, never through a
/// symlink in place of either, and checked through the descriptor opened;
/// its path is never resolved first. Here the real `backups/`, holding an
/// expired backup, a fresh one, an interrupted staging directory and a
/// directory a purge left, is moved away and a symlink to it put in its
/// place: a purge, a listing, an open by id or as listed, a recorded
/// result and a begin each fail (`Path(Symlink)`), and every file in the
/// moved directory stays as it was. The same with the data directory
/// replaced by a symlink to where it was moved. Once both are back, the
/// purge removes the expired backup, the staging directory and the
/// purge's leftover, and the fresh backup reads back.
#[test]
fn a_symlink_in_place_of_backups_or_the_data_directory_is_never_followed() {
    use envcloak_core::vault::PathErrorKind;
    let (f, v) = KitFixture::create();
    let t = now();
    let p = v.paths().clone();
    let backups = p.backups_dir.clone();
    small(&v, t - FILE_BACKUP_RETENTION.as_secs() - 1);
    let fresh = small(&v, t);
    let listed = list_file_backups_v2(&p)
        .unwrap()
        .into_iter()
        .find(|b| b.id == fresh)
        .unwrap();
    let stale = backups.join(format!(
        ".files2-20260901T000000Z-{}.tmp",
        FileBackupId::generate()
    ));
    let left = backups.join(format!(
        ".files2-20260901T000000Z-{}.purge",
        FileBackupId::generate()
    ));
    for d in [&stale, &left] {
        std::fs::create_dir(d).unwrap();
        std::fs::write(d.join("data"), b"sealed bytes only").unwrap();
        set_time(d, t - STAGING_GRACE.as_secs() - 60);
    }
    let plan = || {
        vec![PlannedFile {
            path: "/h/.env".into(),
            mode: 0o600,
            size: 4,
        }]
    };
    let after: [u8; 32] = Sha256::digest(b"what init left").into();
    // Each call's error kind, or `None` when it went through.
    let every_call = |v: &Vault| {
        let kind = |r: Result<(), envcloak_core::vault::VaultError>| r.err().map(|e| e.kind());
        vec![
            ("purge", kind(purge_file_backups_v2(&p, t).map(drop))),
            (
                "purge except",
                kind(purge_file_backups_v2_except(&p, t, |_| false).map(drop)),
            ),
            ("list", kind(list_file_backups_v2(&p).map(drop))),
            ("open", kind(v.open_file_backup_v2(&fresh).map(drop))),
            (
                "open listed",
                kind(v.file_backups_v2().unwrap().open_listed(&listed).map(drop)),
            ),
            (
                "record result",
                kind(v.record_file_backup_v2_result(&fresh, 0, &after)),
            ),
            (
                "begin",
                kind(
                    v.begin_file_backup_v2(
                        BackupPurpose::Init,
                        creator(CreatorKind::Terminal),
                        plan(),
                        t,
                    )
                    .map(drop),
                ),
            ),
        ]
    };
    let refused = |got: Vec<(&str, Option<VaultErrorKind>)>| {
        for (call, kind) in got {
            assert_eq!(
                kind,
                Some(VaultErrorKind::Path(PathErrorKind::Symlink)),
                "{call} through a symlink"
            );
        }
    };

    let elsewhere = f.home.root().join("elsewhere");
    let before = common::tree(&backups);
    std::fs::rename(&backups, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &backups).unwrap();
    let got = every_call(&v);
    assert_eq!(
        common::tree(&elsewhere),
        before,
        "a call through a symlink in place of backups/ changed what it points at"
    );
    refused(got);
    std::fs::remove_file(&backups).unwrap();
    std::fs::rename(&elsewhere, &backups).unwrap();

    let data_elsewhere = f.home.root().join("data-elsewhere");
    std::fs::rename(&p.data_dir, &data_elsewhere).unwrap();
    std::os::unix::fs::symlink(&data_elsewhere, &p.data_dir).unwrap();
    let got = every_call(&v);
    assert_eq!(
        common::tree(&data_elsewhere.join("backups")),
        before,
        "a call through a symlink in place of the data directory changed what it points at"
    );
    refused(got);
    std::fs::remove_file(&p.data_dir).unwrap();
    std::fs::rename(&data_elsewhere, &p.data_dir).unwrap();

    assert_eq!(purge_file_backups_v2(&p, t).unwrap(), 3);
    let ids: Vec<FileBackupId> = list_file_backups_v2(&p)
        .unwrap()
        .into_iter()
        .map(|b| b.id)
        .collect();
    assert_eq!(ids, [fresh]);
    assert_eq!(dir_names(&backups).len(), 1);
    assert_reads_back(&v, &fresh, &[b"A=1\n"]);
    drop(f);
}

/// A backup is made durable through `envcloak_sys::sync_file`
/// (`F_FULLFSYNC` on macOS), in order, and a flush that fails fails the
/// step it belongs to. Its commit flushes the `data` file, then the
/// staging directory, then, once renamed, `backups/` (the counting shim
/// records each by device and inode). A failed flush of `data` or of the
/// staging directory fails the commit and lists nothing, and the writer
/// dropped leaves nothing behind; a failed flush of `backups/` after the
/// rename fails the commit too, with the whole backup in place. A result
/// flushes its file, then the backup's directory: a failed flush of the
/// file records nothing, and one of the directory fails the call. A purge
/// flushes `backups/` once a backup is renamed out of the listing and
/// again after its removals, and a failed flush fails it.
#[test]
fn a_backup_is_flushed_in_order_and_a_failed_flush_fails_its_step() {
    use envcloak_sys::testing::{fail_sync_after, record_syncs, take_synced};
    use std::os::unix::fs::MetadataExt;
    let id_of = |p: &Path| {
        let m = std::fs::metadata(p).unwrap();
        (m.dev(), m.ino())
    };
    let (f, v) = KitFixture::create();
    let body = content(&f, CHUNK_V2 + 5, 9);
    let files: [(&str, u32, &[u8]); 1] = [("/h/.claude/settings.json", 0o600, &body)];
    let begin = || {
        let plan = files
            .iter()
            .map(|(p, m, b)| PlannedFile {
                path: (*p).to_owned(),
                mode: *m,
                size: b.len() as u64,
            })
            .collect();
        let mut w = v
            .begin_file_backup_v2(
                BackupPurpose::Agents,
                creator(CreatorKind::Agent),
                plan,
                now(),
            )
            .unwrap();
        put_all(&mut w, &files);
        w
    };
    let backups = v.paths().backups_dir.clone();

    let mut w = begin();
    record_syncs();
    let c = w.commit().unwrap();
    let flushed = take_synced();
    assert_eq!(
        flushed,
        [id_of(&c.dir.join("data")), id_of(&c.dir), id_of(&backups)],
        "a commit's flushes: data, the staging directory, backups/"
    );
    assert_reads_back(&v, &c.id, &[&body]);

    for n in 0..2 {
        let mut w = begin();
        fail_sync_after(n);
        assert!(
            w.commit().is_err(),
            "flush {n} failed and the commit went on"
        );
        assert!(
            list_file_backups_v2(v.paths()).unwrap().len() == 1,
            "flush {n} failed and a backup was listed"
        );
        drop(w);
        assert_eq!(dir_names(&backups).len(), 1, "flush {n}: staging left");
    }
    let mut w = begin();
    fail_sync_after(2);
    assert!(
        w.commit().is_err(),
        "the flush of backups/ failed unreported"
    );
    drop(w);
    let listed = list_file_backups_v2(v.paths()).unwrap();
    assert_eq!(listed.len(), 2, "the backup renamed before the flush");
    let late = listed.iter().find(|b| b.id != c.id).unwrap().id;
    assert_reads_back(&v, &late, &[&body]);

    let r = v.open_file_backup_v2(&c.id).unwrap();
    let after: [u8; 32] = Sha256::digest(b"what the change left").into();
    fail_sync_after(0);
    assert!(r.record_result(0, &after).is_err());
    assert_eq!(r.results().unwrap(), [None], "a result whose flush failed");
    record_syncs();
    r.record_result(0, &after).unwrap();
    assert_eq!(
        take_synced(),
        [id_of(&c.dir.join("result-0")), id_of(&c.dir)],
        "a result's flushes: its file, then the backup's directory"
    );
    let r2 = v.open_file_backup_v2(&late).unwrap();
    fail_sync_after(1);
    assert!(
        r2.record_result(0, &after).is_err(),
        "the flush of a backup's directory failed unreported"
    );

    let t = now() + FILE_BACKUP_RETENTION.as_secs() + 10;
    fail_sync_after(0);
    assert!(
        purge_file_backups_v2(v.paths(), t).is_err(),
        "the purge's flush failed unreported"
    );
    assert!(list_file_backups_v2(v.paths()).unwrap().is_empty());
    assert_eq!(purge_file_backups_v2(v.paths(), t).unwrap(), 1);
    small(&v, now() - FILE_BACKUP_RETENTION.as_secs() - 1);
    record_syncs();
    assert_eq!(purge_file_backups_v2(v.paths(), now()).unwrap(), 1);
    assert_eq!(
        take_synced(),
        [id_of(&backups), id_of(&backups)],
        "a purge's flushes: backups/ once the backup is out of the listing, again once it went"
    );
    assert!(dir_names(&backups).is_empty());
    drop(f);
}

/// A purge flushes every change it made, also when no directory went and
/// when it fails part way. An expired backup whose directory holds a file
/// the purge does not own (a `.DS_Store`) is renamed out of the listing
/// and `backups/` flushed before any of its records goes (what the shim
/// recorded by the purge's `Removing` step is `backups/` alone); then its
/// records go and the directory kept is flushed, and the purge answers 0.
/// With the flush of the rename failing, the purge fails, the backup is
/// not listed, none of its records goes, and `backups/` is flushed again
/// before the purge returns; the next purge removes the records. With the
/// flush of the kept directory failing, the purge fails.
#[test]
fn a_purge_flushes_every_change_also_when_no_backup_goes() {
    use envcloak_sys::testing::{fail_sync_after, record_syncs, take_synced};
    use std::os::unix::fs::MetadataExt;
    let id_of = |p: &Path| {
        let m = std::fs::metadata(p).unwrap();
        (m.dev(), m.ino())
    };
    let (f, v) = KitFixture::create();
    let t = now();
    let backups = v.paths().backups_dir.clone();
    let blocked = |v: &Vault| {
        let id = small(v, t - FILE_BACKUP_RETENTION.as_secs() - 1);
        let dir = list_file_backups_v2(v.paths())
            .unwrap()
            .into_iter()
            .find(|b| b.id == id)
            .unwrap()
            .dir;
        std::fs::write(dir.join(".DS_Store"), b"finder").unwrap();
        dir
    };

    let dir = blocked(&v);
    let mut by_removing = None;
    record_syncs();
    let removed = purge_file_backups_v2_observed(
        v.paths(),
        t,
        |_| false,
        |step| {
            if matches!(step, PurgeStepV2::Removing(_)) {
                by_removing = Some(take_synced());
                record_syncs();
            }
        },
    )
    .unwrap();
    assert_eq!(removed, 0);
    let kept = purging(&dir);
    assert_eq!(
        by_removing,
        Some(vec![id_of(&backups)]),
        "the rename out of the listing was not flushed before the records went"
    );
    assert_eq!(
        take_synced(),
        [id_of(&kept)],
        "the records' removal from the directory kept was not flushed"
    );
    assert_eq!(dir_names(&kept), [".DS_Store"]);
    std::fs::remove_dir_all(&kept).unwrap();

    let dir = blocked(&v);
    record_syncs();
    fail_sync_after(0);
    assert!(
        purge_file_backups_v2(v.paths(), t).is_err(),
        "the rename's failed flush unreported"
    );
    assert_eq!(
        take_synced(),
        [id_of(&backups)],
        "the rename whose flush failed was not flushed again"
    );
    assert!(list_file_backups_v2(v.paths()).unwrap().is_empty());
    assert_eq!(
        dir_names(&purging(&dir)),
        [".DS_Store", "data"],
        "records removed after the rename's flush failed"
    );
    assert_eq!(purge_file_backups_v2(v.paths(), t).unwrap(), 0);
    assert_eq!(dir_names(&purging(&dir)), [".DS_Store"]);
    std::fs::remove_dir_all(purging(&dir)).unwrap();

    let dir = blocked(&v);
    fail_sync_after(1);
    assert!(
        purge_file_backups_v2(v.paths(), t).is_err(),
        "the failed flush of the directory kept unreported"
    );
    assert_eq!(dir_names(&purging(&dir)), [".DS_Store"]);
    drop(f);
}

/// A purge's last flush of `backups/`, after its removals, is the step
/// that makes them durable, and a failure of it fails the purge, whatever
/// went (Codex and verifier, M2-05 round 8: the earlier test's injected
/// failure had moved onto the rename's flush). An expired backup: the
/// first flush (`backups/` once it is out of the listing) runs, the second
/// (`backups/` once it went) fails, and the purge fails, with its
/// directory gone (the rename out of the listing was flushed, so a crash
/// could bring it back only as a `.purge` directory, never listed, which
/// the next purge removes). An interrupted staging directory and a
/// directory an earlier purge left (`.purge`) are flushed only by that
/// last flush: with it failing, the purge fails too.
#[test]
fn a_failed_last_flush_of_backups_fails_the_purge() {
    use envcloak_sys::testing::{fail_sync_after, record_syncs, take_synced};
    use std::os::unix::fs::MetadataExt;
    let (f, v) = KitFixture::create();
    let t = now();
    let backups = v.paths().backups_dir.clone();
    let id_of = |p: &Path| {
        let m = std::fs::metadata(p).unwrap();
        (m.dev(), m.ino())
    };

    small(&v, t - FILE_BACKUP_RETENTION.as_secs() - 1);
    let dir = list_file_backups_v2(v.paths()).unwrap().remove(0).dir;
    record_syncs();
    fail_sync_after(1);
    assert!(
        purge_file_backups_v2(v.paths(), t).is_err(),
        "the failed flush of backups/ after the removal was unreported"
    );
    assert_eq!(
        take_synced(),
        [id_of(&backups)],
        "the flush before the removal did not run"
    );
    assert!(!dir.exists() && !purging(&dir).exists());
    assert!(list_file_backups_v2(v.paths()).unwrap().is_empty());
    assert_eq!(purge_file_backups_v2(v.paths(), t).unwrap(), 0);

    for name in [
        format!(".files2-20260901T000000Z-{}.tmp", FileBackupId::generate()),
        format!(
            ".files2-20260901T000000Z-{}.purge",
            FileBackupId::generate()
        ),
    ] {
        let d = backups.join(&name);
        std::fs::create_dir(&d).unwrap();
        std::fs::write(d.join("data"), b"sealed bytes only").unwrap();
        set_time(&d, t - STAGING_GRACE.as_secs() - 60);
        fail_sync_after(0);
        assert!(
            purge_file_backups_v2(v.paths(), t).is_err(),
            "{name}: the failed flush of its removal was unreported"
        );
        assert!(!d.exists(), "{name}");
    }
    assert!(dir_names(&backups).is_empty());
    drop(f);
}

/// A commit answers that the backup is in place only for the directory it
/// sealed (L-11; a rename moves whatever has the staging directory's name
/// then). Before the rename (the staging directory moved away and a
/// symlink to another directory, or another directory, put under its
/// name) or right after it (the same done to the backup's name), the
/// commit fails (`InvalidRecord`) and reports no `Done` step, and a second
/// try fails too. Dropped, the writer removes nothing: the sealed `data`
/// is whole where the directory was moved, and the other directory, the
/// symlink and what it points at are as they were. With the sealed
/// directory put back under the backup's name, the backup reads back.
fn refuses_a_substituted_publication(after_rename: bool, symlink: bool) {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (f, v) = KitFixture::create();
    let body = content(&f, CHUNK_V2 + 17, 7);
    let files: [(&str, u32, &[u8]); 1] = [("/h/.claude/settings.json", 0o600, &body)];
    let backups = v.paths().backups_dir.clone();
    let held = f.home.root().join("held-sealed");
    let victim = f.home.root().join("foreign");
    std::fs::create_dir(&victim).unwrap();
    std::fs::write(victim.join("keep"), []).unwrap();
    let replace = move |p: &Path, victim: &Path| {
        if symlink {
            std::os::unix::fs::symlink(victim, p).unwrap();
        } else {
            std::fs::create_dir(p).unwrap();
            std::fs::write(p.join("keep"), []).unwrap();
        }
    };
    let installed = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicUsize::new(0));
    let (seen_installed, seen_done) = (installed.clone(), done.clone());
    let (parent, moved, outside) = (backups.clone(), held.clone(), victim.clone());
    let mut w = v
        .begin_file_backup_v2_observed(
            BackupPurpose::Scrub,
            creator(CreatorKind::Agent),
            vec![PlannedFile {
                path: files[0].0.into(),
                mode: 0o600,
                size: body.len() as u64,
            }],
            now(),
            move |step| {
                if step == StepV2::Installed {
                    seen_installed.fetch_add(1, Ordering::SeqCst);
                    if after_rename {
                        let names = dir_names(&parent);
                        assert_eq!(names.len(), 1);
                        let named = parent.join(&names[0]);
                        std::fs::rename(&named, &moved).unwrap();
                        replace(&named, &outside);
                    }
                } else if step == StepV2::Done {
                    seen_done.fetch_add(1, Ordering::SeqCst);
                }
            },
        )
        .unwrap();
    let id = w.id();
    put_all(&mut w, &files);
    w.seal().unwrap();
    let names = dir_names(&backups);
    assert_eq!(names.len(), 1);
    let staging = backups.join(&names[0]);
    assert_eq!(dir_names(&staging), ["data"]);
    let sealed = std::fs::read(staging.join("data")).unwrap();
    assert_no_canary(&sealed, &f.cs);
    if !after_rename {
        std::fs::rename(&staging, &held).unwrap();
        replace(&staging, &victim);
    }
    assert_eq!(
        w.install().unwrap_err().kind(),
        VaultErrorKind::Substituted,
        "a commit answered for a directory it did not seal"
    );
    assert_eq!(installed.load(Ordering::SeqCst), 1);
    assert_eq!(done.load(Ordering::SeqCst), 0);
    assert_eq!(
        w.install().unwrap_err().kind(),
        VaultErrorKind::InvalidRecord
    );
    drop(w);
    let names = dir_names(&backups);
    assert_eq!(names.len(), 1);
    let published = backups.join(&names[0]);
    assert!(std::fs::read(held.join("data")).unwrap() == sealed);
    assert_eq!(dir_names(&victim), ["keep"]);
    if symlink {
        assert!(published.symlink_metadata().unwrap().is_symlink());
        assert_eq!(std::fs::read_link(&published).unwrap(), victim);
        std::fs::remove_file(&published).unwrap();
    } else {
        assert!(published.symlink_metadata().unwrap().is_dir());
        assert_eq!(dir_names(&published), ["keep"]);
        std::fs::remove_dir_all(&published).unwrap();
    }
    std::fs::rename(&held, &published).unwrap();
    assert_reads_back(&v, &id, &[&body]);
    assert_no_canary(&backup_bytes(&v), &f.cs);
    drop(f);
}

#[test]
fn a_commit_refuses_a_symlink_put_under_the_staging_name() {
    refuses_a_substituted_publication(false, true);
}

#[test]
fn a_commit_refuses_a_directory_put_under_the_staging_name() {
    refuses_a_substituted_publication(false, false);
}

#[test]
fn a_commit_refuses_a_symlink_put_under_the_backup_name() {
    refuses_a_substituted_publication(true, true);
}

#[test]
fn a_commit_refuses_a_directory_put_under_the_backup_name() {
    refuses_a_substituted_publication(true, false);
}

/// A result is answered as recorded only when its name holds the file
/// written (the class of the commit's check above: a link takes whatever
/// has the temporary name at that moment). Once the result's temporary
/// file is flushed, another file is put under its name, or a symlink to
/// a file elsewhere: the call fails, the other file and the symlink's
/// target are as they were, and a result recorded after that one is
/// refused (`AlreadyExists`), never taken for the change's.
#[test]
fn a_result_is_recorded_only_for_the_file_written() {
    use envcloak_core::file_backup_v2::ResultStepV2;
    for symlink in [false, true] {
        let (f, v) = KitFixture::create();
        let id = small(&v, now());
        let r = v.open_file_backup_v2(&id).unwrap();
        let dir = data_file(&v, &id).parent().unwrap().to_owned();
        let outside = f.home.root().join("outside");
        std::fs::write(&outside, b"not a result").unwrap();
        let after: [u8; 32] = Sha256::digest(b"what init left").into();
        let mut did = 0;
        let e = r.record_result_observed(0, &after, |step| {
            if step != ResultStepV2::Synced {
                return;
            }
            let temp = dir_names(&dir)
                .into_iter()
                .find(|n| n.starts_with(".result-0-"))
                .unwrap();
            let other = dir.join("other");
            if symlink {
                std::os::unix::fs::symlink(&outside, &other).unwrap();
            } else {
                std::fs::write(&other, b"not a result either").unwrap();
            }
            std::fs::rename(&other, dir.join(temp)).unwrap();
            did += 1;
        });
        assert_eq!(did, 1);
        assert_eq!(
            e.map_err(|e| e.kind()),
            Err(VaultErrorKind::Substituted),
            "symlink {symlink}: a result answered as recorded for a file it did not write"
        );
        assert_eq!(std::fs::read(&outside).unwrap(), b"not a result");
        assert!(r.record_result(0, &after).is_err());
        drop(f);
    }
}

/// A writer dropped unfinished removes its staging directory's name only
/// while it still names the directory it made: with that directory moved
/// away and an empty directory put under its name, the empty directory
/// stays, and the moved one loses its `data` through the handle held.
#[test]
fn a_writer_dropped_unfinished_removes_only_its_own_staging_directory() {
    let (f, v) = KitFixture::create();
    let backups = v.paths().backups_dir.clone();
    let plan = vec![PlannedFile {
        path: "/h/.env".into(),
        mode: 0o600,
        size: 4,
    }];
    let w = v
        .begin_file_backup_v2(
            BackupPurpose::Init,
            creator(CreatorKind::Terminal),
            plan,
            now(),
        )
        .unwrap();
    let staging = dir_names(&backups);
    assert_eq!(staging.len(), 1);
    let away = f.home.root().join("staging-moved");
    std::fs::rename(backups.join(&staging[0]), &away).unwrap();
    std::fs::create_dir(backups.join(&staging[0])).unwrap();
    drop(w);
    assert!(
        backups.join(&staging[0]).is_dir(),
        "an empty directory put under the staging name was removed"
    );
    assert!(dir_names(&away).is_empty(), "{:?}", dir_names(&away));
    drop(f);
}
