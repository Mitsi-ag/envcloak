#!/usr/bin/env python3
"""Computes the EnvCloak format vectors in crates/envcloak-core/tests/crypto_kat.rs
with implementations independent of the Rust crates the vault uses:

- Argon2id: pyca/cryptography (OpenSSL 3.2 or later);
- XChaCha20-Poly1305: pycryptodome;
- HKDF-SHA256: the standard library's hmac and hashlib;
- BLAKE3: the pure-Python implementation below, written from the BLAKE3
  specification and checked here against published test vectors.

The formats are documented in docs/CRYPTO.md. Every input is a fixed test
pattern, never a real secret. Run it and compare the output with the
constants in crypto_kat.rs:

    python3 -m pip install cryptography pycryptodome
    python3 scripts/crypto-kat-vectors.py
"""

import hashlib
import hmac
import struct

from Crypto.Cipher import ChaCha20_Poly1305  # pycryptodome; a 24-byte nonce selects XChaCha20
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# --- BLAKE3, from the specification -----------------------------------------

B3_IV = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
         0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
B3_PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]
CHUNK_START, CHUNK_END, PARENT, ROOT, KEYED_HASH = 1, 2, 4, 8, 16
BLOCK_LEN, CHUNK_LEN = 64, 1024
MASK = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK


def _g(s, a, b, c, d, mx, my):
    s[a] = (s[a] + s[b] + mx) & MASK
    s[d] = _rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK
    s[b] = _rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + my) & MASK
    s[d] = _rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK
    s[b] = _rotr(s[b] ^ s[c], 7)


def _compress(cv, block, counter, block_len, flags):
    s = list(cv) + B3_IV[:4] + [counter & MASK, (counter >> 32) & MASK, block_len, flags]
    m = list(block)
    for r in range(7):
        _g(s, 0, 4, 8, 12, m[0], m[1])
        _g(s, 1, 5, 9, 13, m[2], m[3])
        _g(s, 2, 6, 10, 14, m[4], m[5])
        _g(s, 3, 7, 11, 15, m[6], m[7])
        _g(s, 0, 5, 10, 15, m[8], m[9])
        _g(s, 1, 6, 11, 12, m[10], m[11])
        _g(s, 2, 7, 8, 13, m[12], m[13])
        _g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[i] for i in B3_PERM]
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def _words(b):
    b = b + bytes(64 - len(b))
    return [int.from_bytes(b[4 * i:4 * i + 4], "little") for i in range(16)]


def _chunk_output(key, chunk, counter, flags):
    cv = key
    blocks = [chunk[i:i + BLOCK_LEN] for i in range(0, len(chunk), BLOCK_LEN)] or [b""]
    for i, blk in enumerate(blocks):
        f = flags | (CHUNK_START if i == 0 else 0)
        if i == len(blocks) - 1:
            return (cv, _words(blk), counter, len(blk), f | CHUNK_END)
        cv = _compress(cv, _words(blk), counter, BLOCK_LEN, f)[:8]
    raise AssertionError("unreachable")


def _cv(out):
    cv, w, ctr, bl, f = out
    return _compress(cv, w, ctr, bl, f)[:8]


def _blake3(key_words, data, flags):
    chunks = [data[i:i + CHUNK_LEN] for i in range(0, len(data), CHUNK_LEN)] or [b""]
    stack = []
    out = None
    for n, chunk in enumerate(chunks):
        out = _chunk_output(key_words, chunk, n, flags)
        if n == len(chunks) - 1:
            break
        cv = _cv(out)
        total = n + 1
        while total & 1 == 0:
            cv = _cv((key_words, stack.pop() + cv, 0, BLOCK_LEN, flags | PARENT))
            total >>= 1
        stack.append(cv)
    while stack:
        out = (key_words, stack.pop() + _cv(out), 0, BLOCK_LEN, flags | PARENT)
    cv, w, _, bl, f = out
    s = _compress(cv, w, 0, bl, f | ROOT)
    return b"".join(x.to_bytes(4, "little") for x in s[:8])


def blake3_hash(data):
    return _blake3(B3_IV, data, 0)


def blake3_keyed(key, data):
    assert len(key) == 32
    return _blake3([int.from_bytes(key[4 * i:4 * i + 4], "little") for i in range(8)], data, KEYED_HASH)


# Published BLAKE3 test vectors (BLAKE3 repository, test_vectors.json): the
# first 32 output bytes for inputs of 0, 1 and 1025 bytes of (i % 251).
_B3_KEY = b"whats the Elvish word for friend"
for _n, _h, _k in (
    (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26"),
    (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b"),
    (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
           "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69"),
):
    _inp = bytes(i % 251 for i in range(_n))
    assert blake3_hash(_inp).hex() == _h, _n
    assert blake3_keyed(_B3_KEY, _inp).hex() == _k, _n

# --- HKDF-SHA256 (RFC 5869) -------------------------------------------------


def hkdf_sha256(salt, ikm, info, length=32):
    prk = hmac.new(salt if salt else bytes(32), ikm, hashlib.sha256).digest()
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


# RFC 5869 A.1, to check the function above.
assert hkdf_sha256(bytes(range(13)), bytes([0x0B] * 22), bytes(range(0xF0, 0xFA)), 42).hex() == (
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

# --- EnvCloak formats (docs/CRYPTO.md) --------------------------------------

PURPOSES = ["data", "index", "audit", "sync", "card", "backup", "header", "anchor"]


def aad(vault_id, schema_version, key_epoch, table, row_id, field, item_class, row_version):
    return (b"\x01" + vault_id + struct.pack(">HIH", schema_version, key_epoch, table) + row_id
            + struct.pack(">HHQ", field, item_class, row_version))


def subkey(vmk, vault_id, epoch, purpose):
    return hkdf_sha256(vault_id, vmk, f"envcloak/v1/{purpose}/e{epoch}".encode())


def keyed_hash(key, domain, value):
    return blake3_keyed(key, struct.pack(">I", len(domain)) + domain + value)


def xchacha_seal(key, nonce, aad_bytes, pt):
    c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    c.update(aad_bytes)
    ct, tag = c.encrypt_and_digest(pt)
    return ct + tag


def envelope(vault_id, kind, unlocker_id, epoch, m_kib, t, p, salt, nonce, secret, vmk):
    kek = Argon2id(salt=salt, length=32, iterations=t, lanes=p, memory_cost=m_kib).derive(secret)
    wrap_key = hkdf_sha256(None, kek, b"envcloak/v1/wrap")
    commit_key = hkdf_sha256(None, kek, b"envcloak/v1/commit")
    header = (b"ECEV" + bytes([1, kind]) + unlocker_id + struct.pack(">I", epoch) + b"\x01"
              + struct.pack(">III", m_kib, t, p) + salt + nonce)
    authenticated = header + vault_id
    commitment = blake3_keyed(commit_key, authenticated)
    return header + commitment + xchacha_seal(wrap_key, nonce, authenticated, vmk)


def main():
    # Longer inputs than the published vectors above check, whose trees are
    # more than one level deep: keyed hashes of (i % 251) for i < n.
    for n in (2049, 8193, 31744):
        print("BLAKE3_KEYED", n, blake3_keyed(_B3_KEY, bytes(i % 251 for i in range(n))).hex())

    vault_id = bytes(range(0x00, 0x10))
    row_id = bytes(range(0x10, 0x20))
    vmk = bytes(range(0x20, 0x40))
    epoch = 7

    # Fields table (3), field value (4), secret item (1), schema 1, row version 42.
    a = aad(vault_id, 1, epoch, 3, row_id, 4, 1, 42)
    print("AAD", a.hex())

    for purpose in PURPOSES:
        k = subkey(vmk, vault_id, epoch, purpose)
        print("KEYED_HASH", purpose, keyed_hash(k, b"envcloak/v1/kat", b"abc").hex())

    data_key = subkey(vmk, vault_id, epoch, "data")
    nonce = bytes(range(0x40, 0x58))
    sealed = nonce + xchacha_seal(data_key, nonce, a, b"envcloak open known answer")
    print("SEALED", sealed.hex())

    env = envelope(vault_id, 1, bytes(range(0x50, 0x60)), epoch, 65536, 2, 1,
                   bytes(range(0x60, 0x70)), bytes(range(0x70, 0x88)),
                   b"envcloak envelope known answer", vmk)
    print("ENVELOPE", env.hex())


if __name__ == "__main__":
    main()
