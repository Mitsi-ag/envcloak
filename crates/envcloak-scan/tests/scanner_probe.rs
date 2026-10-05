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
        ));
        inputs.push((
            SecretBytes::from_vec(
                format!("{{\"mcpServers\":{{\"s\":{{\"env\":{{\"A\":{escaped}}}}}}}}}")
                    .into_bytes(),
            ),
            1,
        ));
        inputs.push((
            SecretBytes::from_vec(format!("[mcp_servers.s.env]\nA={escaped}\n").into_bytes()),
            2,
        ));
        inputs.push((
            SecretBytes::from_vec(format!("{{\"text\":{escaped}}}\n").into_bytes()),
            3,
        ));
        inputs.push((
            SecretBytes::from_vec(format!("{{\"text\":{escaped},BROKEN").into_bytes()),
            1,
        ));
        inputs.push((
            SecretBytes::from_vec(format!("[mcp_servers.s.env]\nA={escaped}\nBROKEN").into_bytes()),
            2,
        ));
    }
    for mode in [ProbeMode::Unwiped, ProbeMode::Wiping] {
        let session = probe_canaries(&cs, mode);
        for (input, format) in &inputs {
            if mode == ProbeMode::Unwiped && *format == 2 {
                continue;
            }
            match format {
                0 => drop(parse_profile(input, Shell::Posix)),
                1 => drop(parse_config(input, ConfigFormat::Json)),
                2 => drop(parse_config(input, ConfigFormat::Toml)),
                _ => {
                    use secrecy::ExposeSecret;
                    #[allow(clippy::disallowed_methods)]
                    let bytes = input.expose_secret();
                    drop(
                        scan_reader(
                            &mut std::io::Cursor::new(bytes),
                            ConfigFormat::Jsonl,
                            Default::default(),
                            Budget::default(),
                            &mut |_| true,
                        )
                        .unwrap(),
                    );
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
