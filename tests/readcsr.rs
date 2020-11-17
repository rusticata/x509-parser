use oid_registry::OID_PKCS1_SHA256WITHRSA;
use x509_parser::{parse_x509_csr_der, X509Version};

const CSR_DATA_EMPTY_ATTRIB: &[u8] = include_bytes!("../assets/csr-empty-attributes.csr");

#[test]
fn read_csr_empty_attrib() {
    let (rem, csr) = parse_x509_csr_der(CSR_DATA_EMPTY_ATTRIB).expect("could not parse CSR");

    assert!(rem.is_empty());
    let cri = &csr.certification_request_info;
    assert_eq!(cri.version, X509Version(0));
    assert_eq!(cri.attributes.len(), 0);
    assert_eq!(csr.signature_algorithm.algorithm, OID_PKCS1_SHA256WITHRSA);
}
