//! M3-04: the built CLI removes one binding without a daemon or a value.
#![allow(clippy::unwrap_used)]

mod common;

use std::process::Command;

use envcloak_testkit::{TestHome, assert_no_canary, canaries, fresh_seed};

#[test]
fn unset_matches_independent_toml_and_byte_oracle() {
    let home = TestHome::new();
    let mut cmd = Command::new(common::python3());
    home.apply(&mut cmd)
        .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracles/ref_unset.py"))
        .arg(common::cli())
        .arg(home.root());
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "oracle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn unset_refuses_value_shaped_names_without_echo_or_write() {
    let home = TestHome::new();
    let dir = common::project(&home, "project", "[env]\nKEEP = 'ordinary'\n");
    let path = dir.join("envcloak.toml");
    let before = std::fs::read(&path).unwrap();
    let cs = canaries(fresh_seed());
    for c in &cs {
        let name = std::str::from_utf8(c.value()).unwrap();
        for args in [
            vec!["ref", "--unset", name, "--json"],
            vec!["ref", "--unset", "KEEP", "--profile", name],
        ] {
            let mut cmd = common::cli_command(&home, &args, &[]);
            cmd.current_dir(&dir);
            let out = common::finish_within(cmd, std::time::Duration::from_secs(30));
            assert!(!out.status.success());
            assert_no_canary(&out.stdout, &cs);
            assert_no_canary(&out.stderr, &cs);
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
    }
}
