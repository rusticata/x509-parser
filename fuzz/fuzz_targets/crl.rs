#![no_main]
use libfuzzer_sys::fuzz_target;

use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;

fuzz_target!(|data: &[u8]| {
    let _ = CertificateRevocationList::from_der(data);
});
