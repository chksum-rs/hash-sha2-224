#![no_main]

use chksum_hash_sha2_224 as sha2_224;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    sha2_224::hash(data);
});
