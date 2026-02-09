#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // TODO: fuzz printf format string parsing
    // Test that arbitrary format strings don't panic or corrupt memory
    if data.is_empty() {
        return;
    }

    // Convert to string for format parsing
    let _format = String::from_utf8_lossy(data);
    // TODO: wire to printf format engine once implemented
});
