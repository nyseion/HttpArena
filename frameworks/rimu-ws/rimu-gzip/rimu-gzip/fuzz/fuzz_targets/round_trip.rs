//! Every encoder output inflates to its input: see `rimu_gzip::check`.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| rimu_gzip::check::check_bytes(data));
