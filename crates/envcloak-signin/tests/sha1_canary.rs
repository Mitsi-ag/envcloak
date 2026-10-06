//! Deliberately uses SHA-1 outside totp.rs. check-totp-lint.sh requires
//! clippy to refuse every marked line. Ordinary tests compile no items.
#![cfg(envcloak_lint_canary)]
#![deny(clippy::disallowed_types)]

pub fn direct(_: sha1::Sha1) {} // EXPECT-SHA1-REFUSAL

pub fn through_hmac(_: hmac::Hmac<sha1::Sha1>) {} // EXPECT-SHA1-REFUSAL

pub fn core(_: sha1::block_api::Sha1Core) {} // EXPECT-SHA1-REFUSAL

pub fn compress_direct() {
    sha1::block_api::compress(&mut [0; 5], &[[0; 64]]); // EXPECT-SHA1-REFUSAL
}

pub fn compress_alias() {
    use sha1::block_api::compress as compress_blocks;
    compress_blocks(&mut [0; 5], &[[0; 64]]); // EXPECT-SHA1-REFUSAL
}

pub fn compress_pointer() {
    let compress_blocks = sha1::block_api::compress; // EXPECT-SHA1-REFUSAL
    compress_blocks(&mut [0; 5], &[[0; 64]]);
}
