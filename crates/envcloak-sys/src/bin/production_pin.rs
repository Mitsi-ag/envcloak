//! Packaging preflight, compiled with the same release profile as the bundle.
use envcloak_sys::peer_code::pins;
use std::process::ExitCode;

fn main() -> ExitCode {
    if pins::TEAM_ID.is_none()
        || !matches!(pins::app(), Ok(Some(_)))
        || !matches!(pins::agent(), Ok(Some(_)))
    {
        eprintln!("Q3-01: production signing requirement is not configured");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

#[test]
fn unconfigured_production_build_refuses_packaging() {
    // Once Q3-01 is configured macOS becomes the signed-build positive control.
    let expected = if !cfg!(target_os = "macos") || pins::TEAM_ID.is_none() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    };
    assert_eq!(main(), expected);
}
