//! M3-04: the built CLI removes one binding without a daemon or a value.
#![allow(clippy::unwrap_used)]

mod common;

use std::process::Command;

use envcloak_client::fail::USAGE;
use envcloak_testkit::{TestHome, assert_no_canary, canaries, fresh_seed, labels};

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
    let cs = canaries(fresh_seed());
    // These four fixtures are provider key shapes. The short token,
    // passphrase and URL fixtures are not necessarily value-shaped names.
    for c in cs.iter().filter(|c| {
        matches!(
            c.label.as_str(),
            labels::OPENAI_API_KEY
                | labels::OPENAI_API_KEY_ROTATED
                | labels::STRIPE_SECRET_KEY
                | labels::GITHUB_TOKEN
        )
    }) {
        let name = std::str::from_utf8(c.value()).unwrap();
        for bound in [false, true] {
            let before = if bound {
                // GitHub and Stripe key shapes are valid EnvNames. If
                // argv screening is skipped, those bindings are removed.
                format!("[env]\nKEEP = 'ordinary'\n'{name}' = 'ordinary'\n")
            } else {
                "[env]\nKEEP = 'ordinary'\n".to_owned()
            };
            std::fs::write(&path, before.as_bytes()).unwrap();
            for json in [false, true] {
                for mut args in [
                    vec!["ref", "--unset", name],
                    vec!["ref", "--unset", "KEEP", "--profile", name],
                ] {
                    if json {
                        args.push("--json");
                    }
                    let mut cmd = common::cli_command(&home, &args, &[]);
                    cmd.current_dir(&dir);
                    let out = common::finish_within(cmd, std::time::Duration::from_secs(30));
                    assert_no_canary(&out.stdout, &cs);
                    assert_no_canary(&out.stderr, &cs);
                    assert_eq!(out.status.code(), Some(i32::from(USAGE)), "{}", c.label);
                    assert!(out.stdout.is_empty());
                    let error = std::str::from_utf8(&out.stderr).unwrap();
                    assert!(error.starts_with("envcloak: value_on_argv:"), "{}", c.label);
                    assert!(error.contains("rotate it"), "{}", c.label);
                    assert!(std::fs::read(&path).unwrap() == before.as_bytes());
                }
            }
        }
    }
}

#[test]
fn edits_refuse_value_shaped_previous_references_without_echo_or_write() {
    let home = TestHome::new();
    let dir = common::project(&home, "previous", "[env]\n");
    let path = dir.join("envcloak.toml");
    let cs = canaries(fresh_seed());
    let key = cs
        .iter()
        .find(|c| c.label == labels::GITHUB_TOKEN)
        .unwrap()
        .as_str()
        .to_ascii_lowercase();
    for reference in [key.to_owned(), format!("ordinary#{key}")] {
        for source in [
            format!("[env]\nKEEP='{reference}'\n"),
            if reference.contains('#') {
                format!("[env]\nKEEP={{ref='ordinary',field='{key}'}}\n")
            } else {
                format!("[env]\nKEEP={{ref='{reference}'}}\n")
            },
        ] {
            for args in [
                vec!["ref", "--unset", "KEEP", "--json"],
                vec!["ref", "--unset", "KEEP"],
            ] {
                std::fs::write(&path, &source).unwrap();
                let mut cmd = common::cli_command(&home, &args, &[]);
                cmd.current_dir(&dir);
                let out = common::finish_within(cmd, std::time::Duration::from_secs(30));
                assert_no_canary(&out.stdout, &cs);
                assert_no_canary(&out.stderr, &cs);
                assert!(!out.stdout.windows(key.len()).any(|w| w == key.as_bytes()));
                assert!(!out.stderr.windows(key.len()).any(|w| w == key.as_bytes()));
                assert_eq!(out.status.code(), Some(1));
                assert!(out.stdout.is_empty());
                assert!(
                    std::str::from_utf8(&out.stderr)
                        .unwrap()
                        .contains("manifest_invalid")
                );
                assert!(std::fs::read(&path).unwrap() == source.as_bytes());
            }
        }
    }
}
