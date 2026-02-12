#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // TODO: fuzz string functions with arbitrary byte inputs
    // Test: strlen, strcmp, strcpy, strstr, etc.
    if data.len() < 2 {
        return;
    }

    // Ensure we have a null-terminated string for C-like functions
    let mut buf = data.to_vec();
    if buf.last() != Some(&0) {
        buf.push(0);
    }

    // Find null terminator position
    let _len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
});
