//! Bounded parser fuzz targets; longer campaigns belong to milestone hardening.
#![allow(clippy::unwrap_used)]
use envcloak_core::SecretBytes;
use envcloak_scan::{
    agent_config::parse_config,
    candidates::Budget,
    profile::{Shell, parse_profile},
    source::ConfigFormat,
    transcript::scan_reader,
};
use proptest::prelude::*;
proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn hostile_parser_bytes_are_bounded_and_errors_are_value_free(bytes in prop::collection::vec(any::<u8>(),0..16384)) {
        let secret=SecretBytes::copy_from(&bytes);
        for shell in [Shell::Posix,Shell::Fish] { let r=parse_profile(&secret,shell);for f in r.findings {prop_assert!(f.range.start<=f.range.end&&f.range.end<=bytes.len() as u64);}}
        for format in [ConfigFormat::Json,ConfigFormat::Toml,ConfigFormat::Yaml] {let _=parse_config(&secret,format);}
        for format in [ConfigFormat::Jsonl,ConfigFormat::Raw] {
            let r=scan_reader(&mut std::io::Cursor::new(&bytes),format,Default::default(),Budget {bytes:16385,..Budget::default()},&mut |c| {assert!(c.occurrence.range.start<=c.occurrence.range.end&&c.occurrence.range.end<=bytes.len() as u64);true});
            prop_assert!(r.is_ok());
        }
    }
}
