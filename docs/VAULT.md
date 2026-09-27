# EnvCloak: vault storage format

Status: schema version 1 (M1). This file fixes how SPEC §5 "Vault", "Integrity" and "Items" are stored on disk: the SQLite schema, what each column holds, the records sealed into rows, the state digest, how writes, crashes and migrations are handled, and how a vault is unlocked, backed up and restored. The crypto it builds on (sealing, associated data, subkeys, keyed hashes, envelopes, the Recovery Kit) is in [CRYPTO.md](CRYPTO.md). The code is in `crates/envcloak-core/src/vault/`, `unlock.rs` and `backup.rs`.

A change to any layout, label or number here is a format change: it needs a new schema version and a migration.

## Location

| | macOS | Linux |
|---|---|---|
| Data directory | `~/Library/Application Support/EnvCloak/` | `$XDG_DATA_HOME/envcloak/`, default `~/.local/share/envcloak/` |
| Database | `<data>/vault/vault.db` | same |
| Audit log, backups | `<data>/audit/`, `<data>/backups/` | same |

- Every directory is 0700 and every file 0600. The process sets its umask to 077 before creating or opening anything, and SQLite gives its side files the database file's mode.
- A directory or file EnvCloak trusts must not be a symlink, must be owned by the effective uid, and must not be writable by group or others. One that is only readable by others is tightened; one that fails another check is refused.
- A relative `XDG_DATA_HOME` is ignored, as the XDG specification says. A missing or relative `HOME` is an error.

## Connection settings

Every connection to a vault file:
- opens it with `SQLITE_OPEN_NOFOLLOW` on its canonical path, without `SQLITE_OPEN_URI`;
- turns on the defensive flag, turns off triggers, views, the trusted schema, double-quoted string literals, and `ATTACH` creating or writing files;
- sets `busy_timeout` to 0 and `locking_mode=EXCLUSIVE`, so it holds the file's lock until it closes. Another EnvCloak process, or any other SQLite client, gets "busy". The WAL index then lives in process memory, so there is no `-shm` file;
- sets `journal_mode=WAL`, `synchronous=FULL`, `secure_delete=ON`, `temp_store=MEMORY`, `cell_size_check=ON` and `foreign_keys=OFF`;
- on macOS, sets `fullfsync=ON` and `checkpoint_fullfsync=ON`, because a plain `fsync` there does not flush the drive's cache.

`PRAGMA application_id` is `0x45435631` ("ECV1"). A file with another id is refused.

## Schema version 1

All tables are `STRICT`. Row ids are ULIDs: 48 bits of creation time in milliseconds, then 80 random bits.

```
meta      (vault_id BLOB, schema_version INTEGER, created_at INTEGER)
header    (epoch INTEGER, vault_id BLOB, schema_version INTEGER, sealed BLOB)
unlockers (id BLOB PRIMARY KEY, vault_id BLOB, kind INTEGER, envelope BLOB, created_at INTEGER)
items     (id BLOB PRIMARY KEY, row_version INTEGER, class INTEGER, slug_hash BLOB UNIQUE,
           sealed_meta BLOB, updated_at INTEGER)
fields    (id BLOB PRIMARY KEY, item_id BLOB, row_version INTEGER, sealed_name BLOB,
           sealed_value BLOB, value_hash BLOB, sealed_prior BLOB NULL)
projects  (id BLOB PRIMARY KEY, row_version INTEGER, dir_hash BLOB UNIQUE, sealed BLOB)
policies  (id BLOB PRIMARY KEY, row_version INTEGER, sealed BLOB)
```

`meta` and `header` hold exactly one row each. There are no other tables, indexes, triggers or views; the exact DDL is `SCHEMA_V1` in `schema.rs`.

The vault id is stored in `meta`, in the header and in every unlocker, and the schema version in `meta` and in the header, so that no single row decides them (see Unlock).

### What each column holds

| Column | Contents | Key |
|---|---|---|
| `meta.*` | Plaintext. `vault_id` and `schema_version` are in the associated data of every sealed value, so nothing opens under wrong ones. `created_at` is informational and not authenticated. | |
| `header.epoch`, `vault_id`, `schema_version` | Plaintext: the key epoch, vault id and schema version the header was sealed under (its subkey and associated data use them). | |
| `header.sealed` | The header record | `header` |
| `unlockers.envelope` | A 159-byte envelope (CRYPTO.md) | its own KEK |
| `unlockers.vault_id` | Plaintext; the envelope's commitment binds it. Covered by the state digest. | |
| `unlockers.kind`, `created_at` | Plaintext, covered by the state digest | |
| `items.class` | Plaintext: 1 secret, 2 card, 3 issuer credential | |
| `items.slug_hash` | `keyed_hash(index, "envcloak/v1/slug", slug)` | `index` |
| `items.sealed_meta` | The item record | `card` for cards, `data` otherwise |
| `fields.item_id` | Plaintext, covered by the state digest | |
| `fields.sealed_name` | The field record | as its item |
| `fields.sealed_value` | The value | as its item |
| `fields.value_hash` | `keyed_hash(index, "envcloak/v1/value", value)` | `index` |
| `fields.sealed_prior` | The prior list, or NULL when there is none | as its item |
| `projects.dir_hash` | `keyed_hash(index, "envcloak/v1/project", project key)` | `index` |
| `projects.sealed` | The project record | `data` |
| `policies.sealed` | A policy record, whose format the policy layer owns | `data` |

Every sealed column is bound to the associated data of CRYPTO.md: the vault id, the schema version, the key epoch, the table, the row id, the field tag of the column, the item's class (`none` outside items and fields) and the row's `row_version`. The header uses row id all zeros and row version 0. All sealed columns of a row carry the same `row_version`, and every write to a row bumps it and re-seals all of them, so one column restored from an older version does not open.

## Records

Integers are big-endian. A byte string is a `u32` length then the bytes; text is a byte string of UTF-8. An optional value is `0`, or `1` then the value. A list is a `u32` count then the items. Each record starts with its format version, `1`.

**Header** (91 bytes): `version(1) write_counter(8) state_digest(32) policy_epoch(8) audit_present(1) audit_seq(8) audit_mac(32) recovery_confirmed(1)`. `write_counter` is 1 after `create` and goes up by one with every write transaction.

**Item**: `version(1) slug title provider? account.email? account.label? account.org_id? env_hint? classification(1) allowed_hosts[] allow_short(1) tags[] links.docs? links.billing? links.keys_page? links.dashboard? created_at(8) expires_at? rotated_at? last_used_at? notes`. Classification: 0 unknown, 1 test, 2 live.

**Field**: `version(1) name prior_count(1) created_at(8) updated_at(8)`. `prior_count` is 0 exactly when `sealed_prior` is NULL.

**Prior list**: `version(1) count(1)`, then `u32 length || value` for each prior value, newest first. At most 3. Its count must equal the field's `prior_count`: unlock checks that the list is present exactly when the count is not 0, and a read or rotation of prior values while the vault is open checks both (a list set to NULL has no seal to fail).

**Project**: `version(1) key(bytes) display_path manifest_sha256(32) count(4) (env_name reference)... last_seen(8)`.

Slugs are one or more parts separated by `/`; each part starts with a lowercase ASCII letter or digit and continues with those, `.`, `_` or `-`; at most 128 bytes. Field names start with a lowercase ASCII letter, digit or `_` and continue with those, `.` or `-`; at most 64 bytes.

## Size caps

- 64 KiB for a value, and for the plaintext of every other sealed record except the prior list.
- The prior list packs up to three prior values into one sealed column. Each was a value, so each is at most 64 KiB; the list is at most 2 + 3 × (4 + 64 KiB) bytes, about 192 KiB.
- 1 MiB per row. A field row with a full-size value and three full-size prior values stays under it.

## State digest

Each row of `unlockers`, `items`, `fields`, `projects` and `policies` has a stamp: its row version (0 for unlockers) and the SHA-256 of its stored columns, laid out as follows (`len` is a 4-byte length, integers are 8 bytes):

| Table | Hashed bytes |
|---|---|
| unlockers | `len vault_id kind(8) created_at(8) envelope` |
| items | `class(8) len slug_hash updated_at(8) sealed_meta` |
| fields | `len item_id len value_hash len sealed_name len sealed_value has_prior(1) [sealed_prior]` |
| projects | `len dir_hash sealed` |
| policies | `sealed` |

```
state_digest = keyed_hash(index subkey, "envcloak/v1/state-digest",
                          for each row sorted by (table tag, row id):
                              table(2) || row_id(16) || row_version(8) || sha256(hashed bytes)(32))
```

The table tags are CRYPTO.md's: unlockers 7, items 2, fields 3, projects 4, policies 5. The `index` subkey keys every keyed hash in the vault, each in its own domain; the `header` subkey only seals the header. Unlock compares the digests in constant time.

## Unlock

`LockedVault::open` checks the directories and the file, takes the exclusive lock, and reads the plaintext that names the vault. No single row decides it, so one deleted, doubled or altered row still lets the vault open (and unlock then reports it):
- the vault id is the one most of the `meta`, header and unlocker rows hold (a tie is refused as damaged);
- the epoch is the header's when an envelope carries it, otherwise the one every envelope carries;
- the schema version is the header's, then `meta`'s. When every row that names one names a version newer than this build's, the vault is refused and nothing is written.

Unlocker envelopes of that epoch can then be listed without the key and unwrapped with that vault id.

`unlock` with the VMK then:
1. derives the subkeys for the vault id and epoch;
2. compares `sqlite_schema` with the objects the schema version defines;
3. checks that `meta` is one row naming that vault id and schema version, and opens every header row, checking its plaintext columns;
4. reads every row, computes its stamp, and decrypts the item, field, project and policy records. It never opens `sealed_value` or `sealed_prior`: values are decrypted one at a time, on request;
5. checks each row's plaintext columns against its sealed contents (the slug and project hashes, the item a field belongs to, unique slugs and field names, an unlocker's id, vault id, kind and epoch);
6. recomputes the state digest and compares it with the header's.

Unlock first drops SQLite's page cache (see Writes), so it checks the file as it is at that moment, also when it goes through the handle that `lock` kept open.

When the header and the rows name different schema versions, unlock uses the first one under which the header or a row opens. If the file holds a header row or a sealed row and nothing opens under the key, unlock fails with a key mismatch (or, when some row names a newer version, with an unsupported version). An empty vault whose header was deleted holds nothing sealed to check the key against: it opens read-only and empty. Otherwise any failure in steps 2 to 6 opens the vault read-only and reports the first one found:

| Report | Meaning |
|---|---|
| header unreadable | The header is missing, doubled or does not open, while rows open |
| meta altered | The `meta` row is missing or doubled, or names another vault id or schema version |
| digest mismatch | A row was deleted, added, altered, or restored from an older copy |
| row unreadable | A sealed column does not open (moved, altered, or a changed class) |
| row inconsistent | Plaintext columns disagree with the sealed contents, the header's included |
| schema altered | A table, index, trigger or view was added or changed |
| changed while open | A row on disk no longer matches what this process wrote |

A read-only vault refuses every write and still serves the items and values that open, so their owner can recover them. It serves no policies, project records or header (those calls fail as tampered): a deleted or rolled-back row must never loosen a decision. No grant is evaluated, no value is released to an agent, and no item's allowed hosts or classification is trusted from a vault whose integrity is not `Ok`, which can change while it is open.

Without an anchor (Linux, and macOS before M3), restoring the whole file together with its header is not detected locally (SPEC §5). `tests/vault_integrity.rs` pins this limit.

## Unlockers

The code is in `crates/envcloak-core/src/unlock.rs`; the envelope, passphrase and Recovery Kit formats are in CRYPTO.md.
- `create_vault` checks the passphrase against the rules, then generates the vault id, the VMK and the Recovery Kit, wraps the VMK under the passphrase (kind 1) and the kit (kind 2) with the chosen Argon2id parameters and a salt each, and creates the vault with both envelopes. It returns the kit for the caller to show once; the vault never stores it. `recovery_confirmed` starts false.
- `unlock_with_passphrase` and `unlock_with_kit` try each envelope of that kind from `LockedVault::unlockers` with the vault id and epoch the file names, then unlock with the VMK the first one gives. A wrong secret and a damaged envelope give the one generic error, also when the damage is in the envelope's plaintext header (its magic, version, kind, epoch or Argon2id parameters), which keeps it off the list: an unlocker row whose `kind` column names that kind but holds no well-formed envelope of that kind and epoch counts as a damaged envelope. Only a vault with no unlocker row of that kind says it has none. The locked vault comes back with the error, for another try.
- `change_passphrase` checks the new passphrase, wraps the VMK under it with the current default parameters and a fresh salt, and in one transaction replaces the passphrase envelope under the same unlocker id (and removes any other passphrase envelope). The kit envelope is unchanged. The caller has already checked a proof.
- `confirm_recovery_kit` unwraps a kit envelope with the kit and requires the result to equal the vault's VMK (compared in constant time); it then sets `recovery_confirmed` in the sealed header. SPEC §6.4 deletes imported plaintext only after that.
- A vault that failed its integrity check, or could not be migrated, refuses a passphrase change and a kit confirmation before any key derivation.

## Backups

`Vault::create_backup` writes `backups/vault-<YYYYMMDDTHHMMSSZ>-<8 hex digits>.ecbackup`, mode 0600. The code is in `crates/envcloak-core/src/backup.rs`.

It refuses a vault that failed its integrity check, and one without a Recovery Kit envelope. A vault that could not be migrated is backed up at its on-disk version.

**The database image.** The vault's own connection serializes the database (`sqlite3_serialize`), which reads every page through SQLite, WAL included, so the image is the committed state. Bytes 18 and 19 are set to 1 (rollback journal): the WAL is already folded in. The image is then opened in memory and verified with the vault's keys: the digest must verify and the header must equal the one this process last committed. An image that fails, because the file was changed behind the open vault, is not written, and the vault turns read-only ("changed while open"). The image holds exactly what `vault.db` holds: sealed columns, keyed hashes, ids, row versions and timestamps.

**The file**, all integers big-endian:

```
magic "ECBK"(4) version 1(1) vault_id(16) schema_version(2) epoch(4) backup_id(16) n(1)
n Recovery Kit envelopes (159 bytes each, CRYPTO.md), 1 <= n <= 8
record 0: the manifest
records 1 to chunk_count: the image, in chunks of 1 MiB (the last one shorter)
```

Each record is `len(4)` followed by a sealed value (CRYPTO.md): XChaCha20-Poly1305 under the `backup` subkey of the vault's epoch, with the associated data `(vault_id, schema_version, epoch, table 8, row_id = backup_id, field, item_class 0, row_version = index)`, field 9 for the manifest and 10 for a chunk. `len` is at most 1 MiB plus the 40 bytes of nonce and tag.

The manifest (93 bytes): `version 1(1) header_sha256(32) created_at(8) write_counter(8) state_digest(32) image_len(8) chunk_count(4)`. `header_sha256` covers every byte before record 0. Every chunk but the last is full and the last is not empty, so `image_len` fixes `chunk_count`.

The passphrase envelope is not in the header: a copied backup offers nothing to guess but the 128-bit kit. Everything else opens only with the VMK, which only the kit unwraps. A record that is altered, moved to another index, taken from another backup, dropped, repeated or appended fails to open or breaks the count, and a changed header breaks the manifest's digest.

A backup is written to `backups/.<name>.tmp` (created exclusively, not following symlinks), synced, hard-linked to its name, and the directory is synced. A leftover `.tmp` file is removed by the next backup.

## Restore

`restore_backup` takes the paths, the backup file, the Recovery Kit and a new passphrase, and returns the restored vault unlocked. In order:
1. The new passphrase is checked against the rules. The backup is opened without following a symlink or blocking on a FIFO; anything but a regular file is refused.
2. The header is read and its envelopes parsed (out-of-bounds Argon2id parameters are refused before any key derivation). The kit unwraps the VMK, with the header's vault id and epoch; a wrong kit gives the generic unlock error.
3. The manifest is opened and its digest of the header compared.
4. If `vault.db` starts as a vault does (SQLite's magic and the application id), it is opened, which takes its lock (a vault open elsewhere fails as busy) and folds in its WAL. A file that is not a vault is not opened, so SQLite does not delete a WAL beside it.
5. The chunks are decrypted into `vault/.vault.db.new-<16 hex digits>` (created exclusively), the length is checked, the end of the file is required, and the file is synced.
6. The temporary file is opened as a vault in rollback-journal mode and unlocked with the VMK. Its digest must verify, and its vault id, epoch, write counter and state digest must be the manifest's.
7. The VMK is wrapped under the new passphrase with the current default parameters and a fresh salt, and one transaction makes that the only passphrase envelope (under the old one's unlocker id) and sets `recovery_confirmed`: the kit was just used. The file is closed, its journal removed, and it is synced.
8. Only now is the current vault touched: its handle is closed, which folds in and removes its WAL; `vault.db` is hard-linked to `vault/replaced-<YYYYMMDDTHHMMSSZ>.db` (with a numeric suffix if that name, or one of its side files' names, is taken), and any side file of it is renamed along under the same name with its suffix. Side files left beside a missing `vault.db` (a WAL a killed daemon left before a checkpoint, say) are moved aside the same way: SQLite replays any WAL, and rolls back any hot journal, that it finds beside a database when it opens it, and a WAL is not tied to the file it was written for. The directory is synced.
9. The temporary file is renamed over `vault.db`, and the directory is synced.
10. The vault is opened and unlocked with the VMK, and its digest must verify. If it does not open or verify (something changed the directory during the restore), the restore fails with "the backup was installed as the vault, but the installed vault did not open or verify" instead of handing back a vault it did not check; the replaced vault is still kept aside, and restoring again moves the failed file aside too.

`vault.db` is the old vault until step 9 and the new one from then on; it is never missing. A crash before step 9 leaves the temporary file, which the next open or create removes, and possibly a second link to the old vault named `replaced-...`. `tests/restore_crash.rs` kills a restorer with `kill -9` after each step, at random moments within the step's measured duration, and checks each time that the vault opens with a verified digest and is exactly the old vault or exactly the restored one; it also restores where no vault exists.

The core library takes no lock across a restore or a create: a restore holds the old vault's SQLite lock only up to step 8, and none when there is no vault, and an open or create removes any `.vault.db.new-` file it finds, a restore's staging file included. The caller keeps every other EnvCloak process away for the whole call: the daemon runs both under its instance lock, after locking and dropping its own handle.

## Writes

- A write transaction is one `BEGIN IMMEDIATE` SQLite transaction. Values are sealed before they are bound to a statement; only sealed bytes, keyed hashes, ids, row versions, kinds and timestamps are bound.
- Each write names the row version it replaces (`WHERE id = ? AND row_version = ?`). A row that is not there means the file changed behind the process's back: the transaction fails and the vault turns read-only.
- At commit the state digest is recomputed from the stamps held in memory, which only this process's writes change, and the header is rewritten in the same transaction. A row changed on disk while the vault is open is therefore never folded into a fresh digest.
- The exclusive lock does not stop another program from writing the file directly, and in exclusive mode SQLite never checks the file for such a change: it would serve pages cached before it, and a commit to another row on a cached page would write the old copy back over it, erasing the change unreported. Every unlock and every write transaction therefore first drops SQLite's page cache and reads the file as it is. A read between them may still be served from the cache, and so sees what this process wrote; the change is met at the next write or unlock. A page whose newer copy is in the WAL is read from the WAL, so a change to its older copy in `vault.db` is never read and is overwritten at the next checkpoint.
- A read or write that meets a row changed on disk (its sealed columns no longer open under the row version held in memory, or its prior list does not match the field's prior count) turns the vault read-only, reporting "changed while open", and the next unlock reports the change. A write that meets it is refused, so it never seals what it read into a new row. `tests/vault_integrity.rs` writes to the file behind an open vault and checks both, that a commit to another row on the same page does not vouch for the changed one or erase it, that a removed prior list is refused by a rotation, and that a row deleted, restored or altered while the vault is locked is reported by the next unlock through the same handle.
- Replacing a value makes the old one the newest prior value; three are kept.
- Deleting an item deletes its fields; `secure_delete` overwrites the freed pages.

## Create

`create` builds the database under a temporary name (`vault/.vault.db.new-<16 hex digits>`) in rollback-journal mode, commits, closes and syncs it, moves aside any side file left beside a missing `vault.db` (as a restore does, step 8), then hard-links it to `vault.db` (which fails if a vault is already there), removes the temporary name and syncs the directory. A crash leaves either no `vault.db` or a complete one. A leftover temporary name, and any side file of it, is removed by the next `create` or, once it holds the lock, by the next open (a crash between the link and the removal leaves it as a second link to the vault). A restore builds the new file under the same prefix (see Restore). The first open switches the file to WAL.

## Crash safety

SQLite's WAL with `synchronous=FULL` (and `fullfsync` on macOS) makes each transaction atomic and durable, and the header is part of the same transaction as the rows it vouches for. `tests/vault_crash.rs` kills a writer with `kill -9` at 1,000 random points and checks, each time, that the vault reopens at the last reported commit (or the one after, when the kill landed between the commit and its report), that the digest verifies, and that every value and prior value matches a model of the seeded workload (gate 5). Some of those kills are followed by a second writer started on the WAL the first one left, killed while it recovers that WAL, before the check.

## Migrations

The schema version is in the associated data of every sealed value, so a migration re-seals every sealed column. It runs at unlock, only on a vault that verified, in one SQLite transaction:
1. each step runs its DDL, re-seals every sealed column from its old version to its new one, then runs its data transform;
2. `meta.schema_version` is set, and the schema is compared with the one the new version defines;
3. the state digest is recomputed from the migrated rows, and the header is written with the write counter one higher, sealed under the new version.

Any failure, or a crash, rolls all of it back: the vault stays at its old version, intact and openable (gate 7). A build whose migration failed still unlocks the vault, read-only at its old version and with the failure reported, so its owner can read and back up what it holds; it refuses writes, and every unlock tries the migration again. Version 1 is the first format, so the shipped plan has no steps; the tests migrate through test-only plans.

## Gates

| Gate (SPEC §15.2) | Test |
|---|---|
| 2, storage part: no fixture in the main, WAL, shared-memory or journal bytes | `tests/vault_bytes.rs` |
| 5: crash consistency | `tests/vault_crash.rs` |
| 6: integrity digest | `tests/vault_integrity.rs` |
| 7: migration failure | `tests/vault_migrate.rs` |
| 11, storage part: no fixture in freed memory | `tests/vault_probe.rs` |
| 3, unlocker part: one generic error for a wrong passphrase, a wrong kit or a damaged envelope; a passphrase change and a restore re-wrap with the current defaults | `tests/unlock.rs`, `tests/backup.rs` |
| 4: after the passphrase is lost, the kit restores identical items; a wrong kit fails | `tests/recovery.rs` |
| Backups: unusable without the kit, any change refused, a changed vault never backed up, a restored digest verifies (also next to side files left without a vault, and a restore that cannot verify what it installed fails) | `tests/backup.rs` |
| Restore is atomic: `kill -9` leaves the old or the new vault | `tests/restore_crash.rs` |
| 11, unlocker part: no passphrase, kit or fixture in freed memory | `tests/unlock_probe.rs` |
