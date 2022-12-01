// Currently, this file is only used to test 'verify' features, so we guard it to this feature
// To be removed if other test functions with different features are added
#![cfg(feature = "verify")]

use x509_parser::prelude::*;

const CA_DATA: &[u8] = include_bytes!("../assets/ca_minimalcrl.der");
const CRL_DATA: &[u8] = include_bytes!("../assets/minimal.crl");

#[cfg(feature = "verify")]
#[test]
fn read_crl_verify() {
    let (_, x509_ca) = X509Certificate::from_der(CA_DATA).expect("could not parse certificate");
    let (_, crl) = parse_x509_crl(CRL_DATA).expect("could not parse revocation list");
    let res = crl.verify_signature(&x509_ca.tbs_certificate.subject_pki);
    eprintln!("Verification: {:?}", res);
    assert!(res.is_ok());
}
