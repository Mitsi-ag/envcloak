# EnvCloak: crypto formats

Status: format version 1 (M1). This file fixes the byte layouts that SPEC §5 describes in prose, so a vault can be read by any implementation that follows it. How these are stored in the vault file is in [VAULT.md](VAULT.md). The code is in `crates/envcloak-core/src/crypto/`. `crates/envcloak-core/tests/crypto_kat.rs` checks each layout against vectors that `scripts/crypto-kat-vectors.py` computes with independent implementations: OpenSSL's Argon2id, pycryptodome's XChaCha20-Poly1305, Python's HMAC, and a BLAKE3 written from its specification.

A change to any layout, label or number here is a format change: it needs a new format version and a migration.

## Primitives

| Use | Algorithm | Crate (pinned) |
|---|---|---|
| Sealing | XChaCha20-Poly1305, 24-byte nonce, 16-byte tag | `chacha20poly1305` 0.11.0 |
| Subkeys, envelope keys | HKDF-SHA256 | `hkdf` 0.13.0, `sha2` 0.11.0 |
| Passphrase and Recovery Kit | Argon2id, version 0x13, 32-byte output | `argon2` 0.6.0 |
| Keyed hashes, commitments | BLAKE3 keyed mode, 32-byte output | `blake3` 1.8.7 |
| Constant-time comparison | | `subtle` 2.6.1 |
| Randomness | The OS CSPRNG (`getrandom`) | `getrandom` 0.4.3 |

All integers are unsigned and big-endian. `||` is concatenation.

## Key hierarchy

```
VMK (32 random bytes, one per epoch)
 └─ subkey(purpose) = HKDF-SHA256(ikm = VMK, salt = vault_id, info = "envcloak/v1/" || purpose || "/e" || epoch)
```

- `vault_id` is the vault's 16 random bytes.
- `epoch` is written in decimal ASCII with no leading zeros: epoch 7 gives `envcloak/v1/data/e7`.
- The purposes are `data`, `index`, `audit`, `sync`, `card`, `backup`, `header` and `anchor`.
- Each subkey is the first 32 bytes of the HKDF output.

## Keyed hash

```
keyed_hash(subkey, domain, v) = BLAKE3-keyed(subkey, u32(len(domain)) || domain || v)
```

The domain is a fixed label such as `envcloak/v1/slug`. Its length prefix keeps every (domain, value) pair distinct. In the vault every keyed hash (slugs, project keys, values, the state digest) is under the `index` subkey, each in its own domain, and the `data`, `card` and `header` subkeys only seal, so no subkey serves two primitives.

## Associated data

Every sealed value is bound to this 53-byte encoding:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | format version, `1` |
| 1 | 16 | vault_id |
| 17 | 2 | schema_version |
| 19 | 4 | key_epoch |
| 23 | 2 | table |
| 25 | 16 | row_id |
| 41 | 2 | field |
| 43 | 2 | item_class |
| 45 | 8 | row_version |

The tag numbers are fixed and never reused.

| table | | field | | item_class | |
|---|---|---|---|---|---|
| header | 1 | header.sealed | 1 | none (not an item) | 0 |
| items | 2 | items.sealed_meta | 2 | secret | 1 |
| fields | 3 | fields.sealed_name | 3 | card | 2 |
| projects | 4 | fields.sealed_value | 4 | issuer_credential | 3 |
| policies | 5 | fields.sealed_prior | 5 | | |
| audit | 6 | projects.sealed | 6 | | |
| unlockers | 7 | policies.sealed | 7 | | |
| backup | 8 | audit entry | 8 | | |
| file backup | 9 | backup manifest | 9 | | |
| | | backup chunk | 10 | | |
| | | file backup key | 11 | | |
| | | file backup manifest | 12 | | |
| | | file backup content | 13 | | |

No sealed value uses table 7: unlocker envelopes authenticate themselves. The number names the `unlockers` rows in the vault's state digest (docs/VAULT.md).

A backup file's records use table 8, with the backup's random id as the row id and the record's index as the row version: 0 for the manifest (field 9) and 1 and up for the chunks of the database image (field 10). Their layout is in VAULT.md, "Backups".

A file backup's records (the files `envcloak init --delete-plaintext` deletes) use table 9, with the backup's random id as the row id and the record's index as the row version: 0 for the backup's own 256-bit key (field 11), sealed under the `backup` subkey; 1 for the manifest (field 12) and 2 and up for each file's contents (field 13), sealed under that key. Their layout is in VAULT.md, "File backups".

An audit log entry uses table 6 and field 8, sealed under the `audit` subkey, with row id all zeros and its sequence number as the row version. Its schema version slot holds the audit log's own format version, `1`, since the log outlives the vault's schema migrations. The entries are chained with keyed hashes under the `index` subkey in the domains `envcloak/v1/audit-chain`, `envcloak/v1/audit-genesis` and `envcloak/v1/audit-segment`, so the `audit` subkey only seals. The layout is in VAULT.md, "Audit log".

## Sealed values

```
nonce (24 random bytes) || XChaCha20-Poly1305(key = subkey, nonce, aad = associated data, plaintext) || tag (16)
```

- Each seal draws a fresh nonce from the OS CSPRNG. Counters are never used.
- A sealed value is at least 40 bytes long.
- Opening checks the tag before it decrypts. Any change to the nonce, ciphertext, tag, key or associated data fails with one error that carries no data.

## Unlocker envelopes

An envelope wraps the VMK under a passphrase or a Recovery Kit. It is 159 bytes long:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `ECEV` |
| 4 | 1 | format version, `1` |
| 5 | 1 | kind: `1` passphrase, `2` Recovery Kit |
| 6 | 16 | unlocker_id |
| 22 | 4 | epoch |
| 26 | 1 | KDF: `1` Argon2id version 0x13 |
| 27 | 4 | m (KiB) |
| 31 | 4 | t (passes) |
| 35 | 4 | p (lanes) |
| 39 | 16 | salt |
| 55 | 24 | nonce |
| 79 | 32 | commitment |
| 111 | 48 | sealed VMK: 32 bytes of ciphertext, then the 16-byte tag |

The header is bytes 0 to 78. The authenticated header is the header followed by the vault_id, which is not stored in the envelope:

```
KEK        = Argon2id(password = secret, salt, m, t, p, version 0x13, 32 bytes, no key or associated data)
wrap       = HKDF-SHA256(ikm = KEK, no salt, info = "envcloak/v1/wrap")
commit     = HKDF-SHA256(ikm = KEK, no salt, info = "envcloak/v1/commit")
auth       = header || vault_id
commitment = BLAKE3-keyed(commit, auth)
sealed VMK = XChaCha20-Poly1305(key = wrap, nonce, aad = auth, plaintext = VMK)
```

Unwrapping runs these steps in order:

1. Parameters outside the bounds are refused before any key derivation. The bounds are 64 MiB ≤ m ≤ 4 GiB, 2 ≤ t ≤ 16 and 1 ≤ p ≤ 16. They are checked when the bytes are parsed and again before derivation.
2. An envelope whose unlocker_id or epoch differs from the caller's record is refused, also before derivation.
3. The KEK is derived, and the commitment is compared in constant time.
4. Only then is the VMK decrypted.

A failure in step 3 or 4 gives the same error, whatever the cause: a wrong passphrase or Recovery Kit, a damaged envelope, or an envelope from another vault.

XChaCha20-Poly1305 does not commit to its key: one ciphertext can be made to open under many keys. Checking the commitment before decryption stops a wrong KEK there, so unlock attempts cannot be used as a partitioning oracle over guessed passphrases.

New envelopes, and every re-wrap, use the current defaults (m = 256 MiB, t = 3, p = 4) with a fresh salt, never the stored parameters. `vault create` may choose a lower memory setting for small machines, down to the 64 MiB bound. Every envelope has a salt of its own, including the two `vault create` makes. A passphrase change and a restore's new passphrase envelope are re-wraps: they use the current defaults whatever the old envelope used. The code holds this by type: a wrap takes memory, passes and lanes from `KdfParams`, whose only constructors are the defaults, the minimum and the defaults at a chosen memory, and draws the salt itself for each envelope; an envelope's stored parameters and salt are a `StoredKdfParams`, which only unwrapping reads and no wrap accepts.

## Passphrases

A new passphrase (at `vault create`, a passphrase change, or a restore) must:
- be UTF-8 text without control characters (a newline, a tab, DEL, and the C1 controls);
- be at least 12 characters (Unicode scalar values) long;
- not equal, ignoring ASCII case, any entry of the bundled list of common passwords: the 29,932 entries of 12 or more printable ASCII characters in the Pwdb-Public top 1,000,000 list, lowercased (`crates/envcloak-core/src/wordlists/`, generated by `scripts/gen-wordlists.py`; sources and licenses in THIRD_PARTY_NOTICES.md).

The passphrase bytes are Argon2id's password as given: nothing is normalized or trimmed. `vault create` offers a generated passphrase: six words drawn uniformly and independently from the EFF Large Wordlist (7,776 words, about 77.5 bits), joined by single spaces.

## Recovery Kit

The kit is 16 bytes from the OS CSPRNG. Its envelope (kind 2) is wrapped under those 16 raw bytes as Argon2id's password.

The user sees it once, as 28 symbols of Crockford's base32 alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, in seven groups of four joined by hyphens:
- symbols 0 to 25 carry the 128 bits, most significant first, five bits each; the last two bits of symbol 25 are zero;
- symbols 26 and 27 are check symbols. With the symbols read as elements of GF(32) (polynomial x^5 + x^2 + 1, alpha = x), a kit is valid when `sum(s_i) = 0` and `sum(alpha^i * s_i) = 0` over i = 0 to 27. This is a Reed-Solomon code of minimum distance 3: any one or two wrong symbols, and any two swapped symbols, are caught before any key derivation.

Parsing ignores case, hyphens, spaces, tabs and line ends, and reads `O` as 0 and `I` and `L` as 1. Anything else, a `U` included, is refused, as is a count other than 28 or a nonzero padding bit. Parse errors carry no part of the input.

The kit's text is built in a buffer that is wiped when freed, and EnvCloak writes it only to the terminal or to a file descriptor the user names, never to stdout. A wrong kit gives the same error as a wrong passphrase.

## Errors

Every crypto error comes from this fixed set of messages. No error carries a value, a secret's length or upstream error text.

| Kind | Message |
|---|---|
| Seal | encryption failed |
| Open | decryption failed: the data is damaged or belongs elsewhere |
| Malformed | sealed data is malformed |
| Random | the system random number generator failed |
| KdfParams | key derivation parameters are out of bounds |
| Kdf | key derivation failed |
| EnvelopeFormat | unlocker envelope is malformed or has an unsupported format |
| EnvelopeMismatch | unlocker envelope belongs to another unlocker or key epoch |
| Unlock | wrong passphrase or Recovery Kit, or the unlocker envelope is damaged |
