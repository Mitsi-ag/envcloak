# EnvCloak: crypto formats

Status: format version 1 (M1). This file fixes the byte layouts that SPEC §5 describes in prose, so a vault can be read by any implementation that follows it. The code is in `crates/envcloak-core/src/crypto/`. `crates/envcloak-core/tests/crypto_kat.rs` checks each layout against vectors that `scripts/crypto-kat-vectors.py` computes with independent implementations: OpenSSL's Argon2id, pycryptodome's XChaCha20-Poly1305, Python's HMAC, and a BLAKE3 written from its specification.

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

The domain is a fixed label such as `envcloak/v1/slug`. Its length prefix keeps every (domain, value) pair distinct.

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
| | | policies.sealed | 7 | | |
| | | audit entry | 8 | | |

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

New envelopes, and every re-wrap, use the current defaults (m = 256 MiB, t = 3, p = 4) with a fresh salt, never the stored parameters. `vault create` may choose a lower memory setting for small machines, down to the 64 MiB bound.

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
