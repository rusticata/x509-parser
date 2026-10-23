use std::convert::TryFrom;
use x509_parser::prelude::*;
use x509_parser::signature_algorithm::SignatureAlgorithm;

// AlgorithmIdentifier { OID 1.2.840.113549.1.1.<last>, params } where params =
// SEQUENCE {
//   [0] { SEQUENCE { OID sha256, NULL } }                           -- hash
//   [1] { SEQUENCE { OID id-mgf1, SEQUENCE { OID sha256, NULL } } }   -- mgf1 with sha256 (RFC 4055 / RFC 8017)
// }
// RSASSA-PSS-params and RSAES-OAEP-params share this shape for [0] and [1].
fn alg_id(last: u8) -> Vec<u8> {
    let mut v = vec![
        0x30, 0x3c, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, last,
    ];
    v.extend_from_slice(&[
        0x30, 0x2f, //
        0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, //
        0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x08, //
        0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    ]);
    v
}

const SHA256: &str = "2.16.840.1.101.3.4.2.1";

#[test]
fn repro_pss_mask_gen_algorithm() {
    let der = alg_id(0x0a); // id-RSASSA-PSS
    let (_, alg) = AlgorithmIdentifier::parse_der(Input::from(&der[..])).unwrap();
    let SignatureAlgorithm::RSASSA_PSS(params) = SignatureAlgorithm::try_from(&alg).unwrap() else {
        panic!("not PSS")
    };
    let mgf = params.mask_gen_algorithm().expect("PSS mgf1");
    assert_eq!(mgf.hash.to_id_string(), SHA256);
}

#[test]
fn repro_oaep_mask_gen_algorithm() {
    let der = alg_id(0x07); // id-RSAES-OAEP
    let (_, alg) = AlgorithmIdentifier::parse_der(Input::from(&der[..])).unwrap();
    let SignatureAlgorithm::RSAAES_OAEP(params) = SignatureAlgorithm::try_from(&alg).unwrap()
    else {
        panic!("not OAEP")
    };
    assert_eq!(params.hash_algorithm_oid().to_id_string(), SHA256);
    let mgf = params.mask_gen_algorithm().expect("OAEP mgf1");
    assert_eq!(mgf.hash.to_id_string(), SHA256);
}

// DER omits DEFAULT fields, so `[2] pSourceFunc` (default pSpecifiedEmpty) is normally absent.
// Parsed directly, bypassing `SignatureAlgorithm::try_from`.
#[test]
fn repro_oaep_params_without_psource() {
    use asn1_rs::DerParser;
    use x509_parser::signature_algorithm::RsaAesOaepParams;
    let der = alg_id(0x07);
    let (_, alg) = AlgorithmIdentifier::parse_der(Input::from(&der[..])).unwrap();
    let any = alg.parameters().expect("params");
    let (_, params) = RsaAesOaepParams::from_der_content(&any.header, any.data.clone()).unwrap();
    assert_eq!(params.hash_algorithm_oid().to_id_string(), SHA256);
    let mgf = params.mask_gen_algorithm().expect("OAEP mgf1");
    assert_eq!(mgf.hash.to_id_string(), SHA256);
}
