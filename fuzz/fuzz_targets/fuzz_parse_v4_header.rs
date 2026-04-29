#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = krcm_core::header_v4::HeaderV4::from_json_bytes(data);
});
