#![no_main]

use std::str::FromStr;

use kilo_core::Target;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = std::str::from_utf8(data) {
        let _ = Target::from_str(value);
    }
});
