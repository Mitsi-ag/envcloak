//! Bounded vendor-parser fuzz target; all input-holding Debug stays value-free.
#![allow(clippy::unwrap_used)]
use envcloak_scan::formats::{self, Kind};
use proptest::prelude::*;
proptest! {
    #![proptest_config(ProptestConfig {cases:256,failure_persistence:None,..ProptestConfig::default()})]
    #[test]
    fn hostile_vendor_streams_never_panic_or_publish_failed_prefixes(bytes in prop::collection::vec(any::<u8>(),0..32768)) {
        for kind in Kind::ALL {
            let mut entries=Vec::new();
            let result=formats::parse(kind,bytes.as_slice(),&mut |e|entries.push(e));
            if result.is_err() {prop_assert!(entries.is_empty());}
            prop_assert!(entries.len()<=formats::MAX_ENTRIES);
            prop_assert!(entries.iter().map(|e|e.value.len()).sum::<usize>()<=formats::MAX_VALUES);
        }
    }
}
