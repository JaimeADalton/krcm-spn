#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = krcm_core::format_v5::unpack_inner_for_fuzz(data);
});
