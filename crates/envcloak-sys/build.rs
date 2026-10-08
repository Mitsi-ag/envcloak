//! Reviewed build configuration only. No generated Rust, dependencies or tools.
//! Cargo's profile, not debug_assertions, separates test support from releases.
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=ENVCLOAK_TEST_CERT_SHA1");
    let testing = env::var_os("CARGO_FEATURE_TESTING").is_some();
    let release = env::var("PROFILE").as_deref() != Ok("debug");
    assert!(
        !(testing && release),
        "EnvCloak testing features must not be compiled into release artifacts"
    );
    let pin = match env::var_os("ENVCLOAK_TEST_CERT_SHA1") {
        None => String::new(),
        Some(raw) => {
            assert!(
                testing && !release,
                "test certificate requires a testing build"
            );
            let pin = raw
                .into_string()
                .unwrap_or_else(|_| panic!("invalid test certificate fingerprint"));
            assert!(
                pin.len() == 40 && pin.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid test certificate fingerprint"
            );
            pin
        }
    };
    // A compile-time value; runtime environment changes cannot replace it.
    println!("cargo:rustc-env=ENVCLOAK_COMPILED_TEST_CERT={pin}");
}
