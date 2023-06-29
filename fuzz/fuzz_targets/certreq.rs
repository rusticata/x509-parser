#![no_main]
use libfuzzer_sys::fuzz_target;
use x509_parser::prelude::*;

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let _ = X509CertificationRequest::from_der(data);
});
