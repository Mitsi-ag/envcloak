//! Gate 11: all three secret-bearing parsers, success and failure, under the
//! production wiping allocator. A raw-copy control proves the detector works.
#![allow(clippy::unwrap_used)]
use envcloak_core::SecretBytes;
use envcloak_scan::{
    agent_config::parse_config,
    candidates::Budget,
    profile::{Shell, parse_profile},
    source::ConfigFormat,
    transcript::scan_reader,
};
use envcloak_testkit::{ProbeAllocator, ProbeMode, canaries, fresh_seed, probe_canaries};
#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;
#[test]
fn three_parsers_leave_no_fixture_in_freed_memory() {
    let cs = canaries(fresh_seed());
    let control = probe_canaries(&cs, ProbeMode::Unwiped);
    for c in &cs {
        drop(std::hint::black_box(c.value().to_vec()));
    }
    assert!(control.finish().released_with_needle > 0);
    let mut inputs = Vec::new();
    for c in &cs {
        let escaped = serde_json::to_string(c.as_str()).unwrap();
        for (text, format, valid) in [
            (format!("A='{}'\n", c.as_str()), 0, true),
            (format!("A='{}'; other\n", c.as_str()), 0, false),
            (
                format!("{{\"mcpServers\":{{\"s\":{{\"env\":{{\"A\":{escaped}}}}}}}}}"),
                1,
                true,
            ),
            (format!("[mcp_servers.s.env]\nA={escaped}\n"), 2, true),
            (format!("{{\"text\":{escaped}}}\n"), 3, true),
            (format!("{{\"text\":{escaped},BROKEN"), 1, false),
            (
                format!("[mcp_servers.s.env]\nA={escaped}\nBROKEN"),
                2,
                false,
            ),
            (format!("{{\"text\":{escaped},BROKEN\n"), 3, false),
        ] {
            let expected = if valid && (format != 3 || c.as_str().chars().count() >= 16) {
                Some(c.value())
            } else {
                None
            };
            inputs.push((
                SecretBytes::from_vec(text.into_bytes()),
                format,
                valid,
                expected,
            ));
        }
    }
    for mode in [ProbeMode::Unwiped, ProbeMode::Wiping] {
        let session = probe_canaries(&cs, mode);
        for (input, format, valid, expected) in &inputs {
            if mode == ProbeMode::Unwiped && *format == 2 {
                continue;
            }
            match format {
                0..=2 => {
                    let parsed = match format {
                        0 => parse_profile(input, Shell::Posix),
                        1 => parse_config(input, ConfigFormat::Json),
                        _ => parse_config(input, ConfigFormat::Toml),
                    };
                    assert_eq!(parsed.complete(), *valid);
                    if *valid {
                        assert!(
                            parsed.findings.iter().any(|f| f
                                .value
                                .as_ref()
                                .is_some_and(|v| expected.is_some_and(|want| v.ct_eq(want)))),
                            "parser did not retain the fixture"
                        );
                    }
                    drop(parsed);
                }
                _ => {
                    use secrecy::ExposeSecret;
                    #[allow(clippy::disallowed_methods)]
                    let bytes = input.expose_secret();
                    let mut matched = false;
                    let mut emitted = 0;
                    let report = scan_reader(
                        &mut std::io::Cursor::new(bytes),
                        ConfigFormat::Jsonl,
                        Default::default(),
                        Budget::default(),
                        &mut |c| {
                            emitted += 1;
                            matched |= expected.is_some_and(|want| c.value.ct_eq(want));
                            true
                        },
                    )
                    .unwrap();
                    assert_eq!(report.complete(), *valid);
                    assert_eq!(
                        matched,
                        expected.is_some(),
                        "transcript candidate eligibility"
                    );
                    if *valid && expected.is_none() {
                        assert_eq!(emitted, 0);
                    }
                    drop(report);
                }
            }
        }
        let report = session.finish();
        assert!(report.freed > 0);
        assert_eq!(report.released_with_needle, 0, "{report:?}");
        if mode == ProbeMode::Wiping {
            assert_eq!(report.not_zeroed, 0, "{report:?}");
        }
    }
}
