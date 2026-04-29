#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = krcm_core::decrypt_auto(data, b"fuzz-password");
});
