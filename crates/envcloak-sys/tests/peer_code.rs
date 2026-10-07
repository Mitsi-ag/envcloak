//! Runtime policy is strict even when an entitlement's value is false.
#![allow(clippy::unwrap_used)]
use envcloak_sys::peer_code::{CodeVerdict, EXCEPTION_ENTITLEMENTS, Why, runtime_verdict};

#[test]
fn gate19_runtime_and_every_exception_are_required() {
    assert_eq!(runtime_verdict(true, false, &[]), CodeVerdict::Satisfies);
    assert_eq!(
        runtime_verdict(false, false, &[]),
        CodeVerdict::Fails(Why::RuntimeFlagMissing)
    );
    assert_eq!(
        runtime_verdict(true, true, &[]),
        CodeVerdict::Fails(Why::Debuggable)
    );
    for name in EXCEPTION_ENTITLEMENTS {
        assert_eq!(
            runtime_verdict(true, false, &[name]),
            CodeVerdict::Fails(Why::ExceptionEntitlement)
        );
    }
    for name in [
        "",
        "com.apple.security.cs.allow-jit\0",
        "ALLOW-JIT",
        "é",
        "com.apple.security.app-sandbox",
    ] {
        assert_eq!(
            runtime_verdict(true, false, &[name]),
            CodeVerdict::Satisfies
        );
    }
}
