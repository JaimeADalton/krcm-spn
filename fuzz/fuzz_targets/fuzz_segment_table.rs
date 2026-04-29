#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = krcm_core::format_v5::parse_segment_table_for_fuzz(data, 1024);
});
