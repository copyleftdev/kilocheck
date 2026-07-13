#![no_main]

use kilo_core::SnapshotManifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = SnapshotManifest::parse_json(data);
});
