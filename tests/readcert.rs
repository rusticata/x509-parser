extern crate nom;
extern crate der_parser;
extern crate x509_parser;
extern crate rusticata_macros;

use der_parser::oid::Oid;
use x509_parser::{parse_subject_public_key_info,parse_x509_der,X509Extension};
use x509_parser::objects::{nid2obj, Nid};

static IGCA_DER: &'static [u8] = include_bytes!("../assets/IGC_A.der");
static NO_EXTENSIONS_DER: &'static [u8] = include_bytes!("../assets/no_extensions.der");

#[test]
fn test_x509_parser() {
    let empty = &b""[..];
    //assert_eq!(x509_parser(IGCA_DER), IResult::Done(empty, (1)));
    let res = parse_x509_der(IGCA_DER);
    // println!("res: {:?}", res);
    match res {
        Ok((e, cert)) => {
            assert_eq!(e,empty);
            //
            let tbs_cert = cert.tbs_certificate;
            assert_eq!(tbs_cert.version, 2);
            //
            let expected_subject = "C=FR, ST=France, L=Paris, O=PM/SGDN, OU=DCSSI, CN=IGC/A, Email=igca@sgdn.pm.gouv.fr";
            assert_eq!(format!("{}", tbs_cert.subject), expected_subject);
            //
            let sig = &tbs_cert.signature;
            assert_eq!(sig.algorithm, Oid::from(&[1, 2, 840, 113549, 1, 1, 5]));
            //
            let expected_issuer = "C=FR, ST=France, L=Paris, O=PM/SGDN, OU=DCSSI, CN=IGC/A, Email=igca@sgdn.pm.gouv.fr";
            assert_eq!(format!("{}", tbs_cert.issuer), expected_issuer);
            //
            let sig_alg = &cert.signature_algorithm;
            assert_eq!(sig_alg.algorithm, Oid::from(&[1, 2, 840, 113549, 1, 1, 5]));
            //
            let not_before = tbs_cert.validity.not_before;
            let not_after = tbs_cert.validity.not_after;
            assert_eq!(not_before.tm_year, 102);
            assert_eq!(not_before.tm_mon, 11);
            assert_eq!(not_before.tm_mday, 13);
            assert_eq!(not_after.tm_year, 120);
            assert_eq!(not_after.tm_mon, 9);
            assert_eq!(not_after.tm_mday, 17);
            //
            let expected_extensions = vec![
                X509Extension {
                    oid: Oid::from(&[2, 5, 29, 19]),
                    critical: true,
                    value: &[48, 3, 1, 1, 255] },
                X509Extension {
                    oid: Oid::from(&[2, 5, 29, 15]),
                    critical: false,
                    value: &[3, 2, 1, 70] },
                X509Extension {
                    oid: Oid::from(&[2, 5, 29, 32]),
                    critical: false,
                    value: &[48, 12, 48, 10, 6, 8, 42, 129, 122, 1, 121, 1, 1, 1] },
                X509Extension {
                    oid: Oid::from(&[2, 5, 29, 14]),
                    critical: false,
                    value: &[4, 20, 163, 5, 47, 24, 96, 80, 194, 137, 10, 221, 43, 33, 79, 255, 142, 78, 168, 48, 49, 54] },
                X509Extension {
                    oid: Oid::from(&[2, 5, 29, 35]),
                    critical: false,
                    value: &[48, 22, 128, 20, 163, 5, 47, 24, 96, 80, 194, 137, 10, 221, 43, 33, 79, 255, 142, 78, 168, 48, 49, 54] },
            ];
            assert_eq!(tbs_cert.extensions.iter().eq(expected_extensions.iter()), true);
            //
            assert_eq!(tbs_cert.is_ca(), true);
        },
        _ => panic!("x509 parsing failed: {:?}", res),
    }
}

#[test]
fn test_x509_parser_no_extensions() {
    let empty = &b""[..];
    let res = parse_x509_der(NO_EXTENSIONS_DER);
    match res {
        Ok((e, cert)) => {
            assert_eq!(e, empty);

            let tbs_cert = cert.tbs_certificate;
            assert_eq!(tbs_cert.version, 2);
            assert_eq!(tbs_cert.extensions.len(), 0);
        }
        _ => panic!("x509 parsing failed: {:?}", res),
    }
}

#[test]
fn test_parse_subject_public_key_info() {
    let res = parse_subject_public_key_info(&IGCA_DER[339..]).expect("Parse public key info").1;
    let oid = nid2obj(&Nid::RsaEncryption).expect("Obj from Nid RsaEncryption");
    assert_eq!(res.algorithm.algorithm, oid);
    let (tag, p) = res.algorithm.parameters.as_context_specific().expect("algorithm parameters");
    assert_eq!(tag, 0);
    let params = p.expect("algorithm parameters");
    assert_eq!(params.tag, 5);
    let spk = res.subject_public_key;
    println!("spk.data.len {}", spk.data.len());
    assert_eq!(spk.data.len(), 270);
}
