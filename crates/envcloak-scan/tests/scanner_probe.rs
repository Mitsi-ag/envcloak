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
        inputs.push((
            SecretBytes::from_vec(format!("A='{}'\n", c.as_str()).into_bytes()),
            0,
            true,
        ));
        inputs.push((
            SecretBytes::from_vec(
                format!("{{\"mcpServers\":{{\"s\":{{\"env\":{{\"A\":{escaped}}}}}}}}}")
                    .into_bytes(),
            ),
            1,
            true,
        ));
        inputs.push((
            SecretBytes::from_vec(format!("[mcp_servers.s.env]\nA={escaped}\n").into_bytes()),
            2,
            true,
        ));
        inputs.push((
            SecretBytes::from_vec(format!("{{\"text\":{escaped}}}\n").into_bytes()),
            3,
            c.as_str().chars().count() >= 16,
        ));
        inputs.push((
            SecretBytes::from_vec(format!("{{\"text\":{escaped},BROKEN").into_bytes()),
            1,
            false,
        ));
        inputs.push((
            SecretBytes::from_vec(format!("[mcp_servers.s.env]\nA={escaped}\nBROKEN").into_bytes()),
            2,
            false,
        ));
    }
    for mode in [ProbeMode::Unwiped, ProbeMode::Wiping] {
        let session = probe_canaries(&cs, mode);
        for (input, format, valid) in &inputs {
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
                        assert!(!parsed.findings.is_empty(), "parser was not exercised");
                    }
                    drop(parsed);
                }
                _ => {
                    use secrecy::ExposeSecret;
                    #[allow(clippy::disallowed_methods)]
                    let bytes = input.expose_secret();
                    let mut matched = false;
                    let report = scan_reader(
                        &mut std::io::Cursor::new(bytes),
                        ConfigFormat::Jsonl,
                        Default::default(),
                        Budget::default(),
                        &mut |c| {
                            matched |= cs.iter().any(|v| c.value.ct_eq(v.value()));
                            true
                        },
                    )
                    .unwrap();
                    assert!(report.complete());
                    assert_eq!(matched, *valid, "transcript candidate eligibility");
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
