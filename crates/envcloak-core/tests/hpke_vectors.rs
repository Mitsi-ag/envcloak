//! Cross-implementation HPKE vector checks between `envcloak-core` (`hpke`
//! 0.14.1) and macOS CryptoKit (`apps/macos/Tools/hpke-vectors/main.swift`),
//! as SPEC §11 and M3-08 require.
//!
//! Vectors are generated at run time from fresh keys and random VMKs:
//! - Suite 1 (`DHKEM(P-256, HKDF-SHA256)`, `HKDF-SHA256`, `AES-256-GCM`,
//!   `info = "envcloak/v1/unlocker/se" || vault_id || unlocker_id || epoch`):
//!   CryptoKit seals to a Rust P-256 key and Rust opens; Rust seals to a
//!   CryptoKit P-256 key and CryptoKit opens; a wrong `info` fails in both.
//! - Suite 2 (`DHKEM(X25519, HKDF-SHA256)`, `HKDF-SHA256`,
//!   `ChaCha20-Poly1305`, empty `info`, `aad = request_id || challenge`):
//!   CryptoKit seals to a Rust ephemeral X25519 key and Rust opens; Rust
//!   seals to a CryptoKit X25519 key and CryptoKit opens; a wrong AAD fails
//!   in both.
//! - End-to-end SPEC §5 unlock flow across implementations: Rust seals the
//!   VMK envelope to a CryptoKit P-256 `unlock` key, CryptoKit opens the
//!   envelope and reseals the VMK to a Rust ephemeral X25519 key with AAD
//!   `request_id || challenge`, and Rust opens the resealed VMK.

#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

use envcloak_core::crypto::{
    SE_CHALLENGE_LEN, SeEphemeralKey, SeHpkeEnvelope, UnlockerId, VaultId, Vmk,
    check_p256_public_key, derive_p256_keypair, open_se_envelope, se_hpke_info, se_reseal_aad,
    seal_vmk_to_daemon, seal_vmk_to_se,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    let b = s.trim().as_bytes();
    assert_eq!(b.len() % 2, 0, "odd hex length");
    b.chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn build_swift_tool(dir: &Path) -> PathBuf {
    let src = repo_root().join("apps/macos/Tools/hpke-vectors/main.swift");
    let bin = dir.join("hpke-vectors");
    let out = Command::new("xcrun")
        .args(["swiftc", "-O"])
        .arg(&src)
        .arg("-o")
        .arg(&bin)
        .output()
        .expect("xcrun swiftc must run on macOS");
    assert!(
        out.status.success(),
        "swiftc failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    bin
}

fn run_tool(bin: &Path, args: &[&str]) -> String {
    let out = Command::new(bin).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "hpke-vectors {:?} failed:\n{}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

fn run_tool_fails(bin: &Path, args: &[&str]) {
    let out = Command::new(bin).args(args).output().unwrap();
    assert!(
        !out.status.success(),
        "hpke-vectors {:?} unexpectedly succeeded",
        args
    );
}

#[test]
fn cryptokit_and_rust_interoperate_in_both_directions_for_both_hpke_suites() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = build_swift_tool(tmp.path());

    // --- Suite 1: P-256 + HKDF-SHA256 + AES-256-GCM ---
    // 1a. CryptoKit seals to a Rust P-256 key; Rust opens.
    let mut ikm = [0u8; 32];
    getrandom::fill(&mut ikm).unwrap();
    let (rust_sk, rust_pub) = derive_p256_keypair(&ikm);
    let vault_id = VaultId::generate();
    let unlocker_id = UnlockerId::generate();
    let epoch = 7u32;
    let info = se_hpke_info(vault_id, unlocker_id, epoch);
    let vmk1 = Vmk::generate();
    let vmk1_raw = vmk1.export_for_testing();

    let sealed_line = run_tool(
        &bin,
        &["p256-seal", &hex(&rust_pub), &hex(&info), &hex(&vmk1_raw)],
    );
    let (enc_hex, ct_hex) = sealed_line.split_once(' ').unwrap();
    let enc: [u8; 65] = unhex(enc_hex).try_into().unwrap();
    let ciphertext: [u8; 48] = unhex(ct_hex).try_into().unwrap();
    let env = SeHpkeEnvelope { enc, ciphertext };

    let opened1 = open_se_envelope(&rust_sk, vault_id, unlocker_id, epoch, &env).unwrap();
    assert_eq!(opened1.export_for_testing(), vmk1_raw);
    assert!(open_se_envelope(&rust_sk, vault_id, unlocker_id, epoch + 1, &env).is_err());

    // 1b. Rust seals to a CryptoKit P-256 key; CryptoKit opens.
    let key_line = run_tool(&bin, &["p256-keygen"]);
    let (ck_priv_hex, ck_pub_hex) = key_line.split_once(' ').unwrap();
    let ck_pub = check_p256_public_key(&unhex(ck_pub_hex)).unwrap();
    let vmk2 = Vmk::generate();
    let vmk2_raw = vmk2.export_for_testing();
    let rust_env = seal_vmk_to_se(&vmk2, &ck_pub, vault_id, unlocker_id, epoch).unwrap();
    let ck_opened = run_tool(
        &bin,
        &[
            "p256-open",
            ck_priv_hex,
            &hex(&info),
            &hex(&rust_env.enc),
            &hex(&rust_env.ciphertext),
        ],
    );
    assert_eq!(unhex(&ck_opened), vmk2_raw);

    // Wrong info in CryptoKit fails to open.
    let wrong_info = se_hpke_info(vault_id, unlocker_id, epoch + 1);
    run_tool_fails(
        &bin,
        &[
            "p256-open",
            ck_priv_hex,
            &hex(&wrong_info),
            &hex(&rust_env.enc),
            &hex(&rust_env.ciphertext),
        ],
    );

    // --- Suite 2: X25519 + HKDF-SHA256 + ChaCha20-Poly1305 ---
    // 2a. CryptoKit seals to a Rust ephemeral X25519 key; Rust opens.
    let eph = SeEphemeralKey::generate().unwrap();
    let mut challenge = [0u8; SE_CHALLENGE_LEN];
    getrandom::fill(&mut challenge).unwrap();
    let request_id = "8NP2W7KM";
    let aad = se_reseal_aad(request_id, &challenge);
    let vmk3 = Vmk::generate();
    let vmk3_raw = vmk3.export_for_testing();

    let ck_sealed_hex = run_tool(
        &bin,
        &[
            "x25519-seal",
            &hex(eph.public_key()),
            &hex(&aad),
            &hex(&vmk3_raw),
        ],
    );
    let ck_sealed = unhex(&ck_sealed_hex);
    let opened3 = eph.open_vmk(request_id, &challenge, &ck_sealed).unwrap();
    assert_eq!(opened3.export_for_testing(), vmk3_raw);

    // Wrong AAD in Rust fails to open.
    let eph_wrong = SeEphemeralKey::generate().unwrap();
    let ck_sealed_wrong = unhex(&run_tool(
        &bin,
        &[
            "x25519-seal",
            &hex(eph_wrong.public_key()),
            &hex(&aad),
            &hex(&vmk3_raw),
        ],
    ));
    let mut other_challenge = challenge;
    other_challenge[0] ^= 0xff;
    assert!(
        eph_wrong
            .open_vmk(request_id, &other_challenge, &ck_sealed_wrong)
            .is_err()
    );

    // 2b. Rust seals to a CryptoKit X25519 key; CryptoKit opens.
    let x_line = run_tool(&bin, &["x25519-keygen"]);
    let (ck_x_priv_hex, ck_x_pub_hex) = x_line.split_once(' ').unwrap();
    let ck_x_pub: [u8; 32] = unhex(ck_x_pub_hex).try_into().unwrap();
    let vmk4 = Vmk::generate();
    let vmk4_raw = vmk4.export_for_testing();
    let rust_resealed = seal_vmk_to_daemon(&ck_x_pub, request_id, &challenge, &vmk4).unwrap();
    let ck_x_opened = run_tool(
        &bin,
        &[
            "x25519-open",
            ck_x_priv_hex,
            &hex(&aad),
            &hex(&rust_resealed),
        ],
    );
    assert_eq!(unhex(&ck_x_opened), vmk4_raw);

    // Wrong AAD in CryptoKit fails to open.
    let wrong_aad = se_reseal_aad(request_id, &other_challenge);
    run_tool_fails(
        &bin,
        &[
            "x25519-open",
            ck_x_priv_hex,
            &hex(&wrong_aad),
            &hex(&rust_resealed),
        ],
    );

    // --- End-to-end SPEC §5 unlock flow across Rust and CryptoKit ---
    let flow_vmk = Vmk::generate();
    let flow_vmk_raw = flow_vmk.export_for_testing();
    let flow_env = seal_vmk_to_se(&flow_vmk, &ck_pub, vault_id, unlocker_id, epoch).unwrap();
    let daemon_eph = SeEphemeralKey::generate().unwrap();
    let app_opened_hex = run_tool(
        &bin,
        &[
            "p256-open",
            ck_priv_hex,
            &hex(&info),
            &hex(&flow_env.enc),
            &hex(&flow_env.ciphertext),
        ],
    );
    let app_resealed_hex = run_tool(
        &bin,
        &[
            "x25519-seal",
            &hex(daemon_eph.public_key()),
            &hex(&aad),
            &app_opened_hex,
        ],
    );
    let daemon_opened = daemon_eph
        .open_vmk(request_id, &challenge, &unhex(&app_resealed_hex))
        .unwrap();
    assert_eq!(daemon_opened.export_for_testing(), flow_vmk_raw);
}
