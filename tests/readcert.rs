extern crate nom;
extern crate der_parser;
extern crate x509_parser;
extern crate rusticata_macros;

use nom::IResult;
use der_parser::oid::Oid;
use x509_parser::{x509_parser,X509Extension};

static IGCA_DER: &'static [u8] = include_bytes!("../assets/IGC_A.der");

#[test]
fn test_x509_parser() {
    let empty = &b""[..];
    //assert_eq!(x509_parser(IGCA_DER), IResult::Done(empty, (1)));
    let res = x509_parser(IGCA_DER);
    match res {
        IResult::Done(e, cert) => {
            assert_eq!(e,empty);
            //
            let tbs_cert = cert.tbs_certificate().unwrap();
            assert_eq!(tbs_cert.version(), Ok(2));
            //
            let expected_subject = "C=FR, ST=France, L=Paris, O=PM/SGDN, OU=DCSSI, CN=IGC/A, Email=igca@sgdn.pm.gouv.fr";
            assert_eq!(format!("{}", tbs_cert.subject()), expected_subject);
            //
            let sig = tbs_cert.signature().unwrap();
            assert_eq!(sig.algorithm, Oid::from(&[1, 2, 840, 113549, 1, 1, 5]));
            //
            let expected_issuer = "C=FR, ST=France, L=Paris, O=PM/SGDN, OU=DCSSI, CN=IGC/A, Email=igca@sgdn.pm.gouv.fr";
            assert_eq!(format!("{}", tbs_cert.issuer()), expected_issuer);
            //
            let sig_alg = cert.signature_algorithm().unwrap();
            assert_eq!(sig_alg.algorithm, Oid::from(&[1, 2, 840, 113549, 1, 1, 5]));
            //
            let validity = tbs_cert.validity().unwrap();
            assert_eq!(validity.len(), 2);
            assert_eq!(validity[0].tm_year, 102);
            assert_eq!(validity[0].tm_mon, 11);
            assert_eq!(validity[0].tm_mday, 13);
            assert_eq!(validity[1].tm_year, 120);
            assert_eq!(validity[1].tm_mon, 9);
            assert_eq!(validity[1].tm_mday, 17);
            //
            let expected_extensions = vec![
                X509Extension {
                    oid: Oid::from(&[2, 5, 29, 35]),
                    critical: false,
                    value: &[48, 22, 128, 20, 163, 5, 47, 24, 96, 80, 194, 137, 10, 221, 43, 33, 79, 255, 142, 78, 168, 48, 49, 54] },
                X509Extension {
                    oid: Oid::from(&[2, 5, 29, 14]),
                    critical: false,
                    value: &[4, 20, 163, 5, 47, 24, 96, 80, 194, 137, 10, 221, 43, 33, 79, 255, 142, 78, 168, 48, 49, 54] },
                X509Extension {
                    oid: Oid::from(&[2, 5, 29, 32]),
                    critical: false,
                    value: &[48, 12, 48, 10, 6, 8, 42, 129, 122, 1, 121, 1, 1, 1] },
                X509Extension {
                    oid: Oid::from(&[2, 5, 29, 15]),
                    critical: false,
                    value: &[3, 2, 1, 70] },
                X509Extension {
                    oid: Oid::from(&[2, 5, 29, 19]),
                    critical: true,
                    value: &[48, 3, 1, 1, 255] },
            ];
            assert_eq!(tbs_cert.extensions().iter().eq(expected_extensions.iter()), true);
            //
            assert_eq!(tbs_cert.is_ca(), true);
        },
        _ => panic!("x509 parsing failed: {:?}", res),
    }
}
