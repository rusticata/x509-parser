use der_parser::{oid, oid::Oid};
use std::collections::HashMap;
use x509_parser::extensions::*;
use x509_parser::objects::*;
use x509_parser::{parse_crl_der, parse_subject_public_key_info, parse_x509_der, X509Extension};

static IGCA_DER: &[u8] = include_bytes!("../assets/IGC_A.der");
static NO_EXTENSIONS_DER: &[u8] = include_bytes!("../assets/no_extensions.der");
static V1: &[u8] = include_bytes!("../assets/v1.der");
static CRL_DER: &[u8] = include_bytes!("../assets/example.crl");
static EMPTY_CRL_DER: &[u8] = include_bytes!("../assets/empty.crl");
static MINIMAL_CRL_DER: &[u8] = include_bytes!("../assets/minimal.crl");

#[test]
fn test_x509_parser() {
    let empty = &b""[..];
    //assert_eq!(x509_parser(IGCA_DER), IResult::Done(empty, (1)));
    let res = parse_x509_der(IGCA_DER);
    // println!("res: {:?}", res);
    match res {
        Ok((e, cert)) => {
            assert_eq!(e, empty);
            //
            let tbs_cert = cert.tbs_certificate;
            assert_eq!(tbs_cert.version, 2);
            //
            let s = tbs_cert.raw_serial_as_string();
            assert_eq!(&s, "39:11:45:10:94");
            //
            let expected_subject = "C=FR, ST=France, L=Paris, O=PM/SGDN, OU=DCSSI, CN=IGC/A, Email=igca@sgdn.pm.gouv.fr";
            assert_eq!(format!("{}", tbs_cert.subject), expected_subject);
            //
            let sig = &tbs_cert.signature;
            assert_eq!(sig.algorithm, oid!(1.2.840.113549.1.1.5));
            //
            let expected_issuer = "C=FR, ST=France, L=Paris, O=PM/SGDN, OU=DCSSI, CN=IGC/A, Email=igca@sgdn.pm.gouv.fr";
            assert_eq!(format!("{}", tbs_cert.issuer), expected_issuer);
            //
            let sig_alg = &cert.signature_algorithm;
            assert_eq!(sig_alg.algorithm, OID_RSA_SHA1);
            //
            let not_before = tbs_cert.validity.not_before;
            let not_after = tbs_cert.validity.not_after;
            assert_eq!(not_before.tm_year, 102);
            assert_eq!(not_before.tm_mon, 11);
            assert_eq!(not_before.tm_mday, 13);
            assert_eq!(not_after.tm_year, 120);
            assert_eq!(not_after.tm_mon, 9);
            assert_eq!(not_after.tm_mday, 17);
            let policies = vec![(oid!(1.2.250.1.121.1.1.1), [].as_ref())]
                .into_iter()
                .collect();
            let expected_extensions_list = vec![
                X509Extension::new(
                    oid!(2.5.29.19),
                    true,
                    &[48, 3, 1, 1, 255],
                    ParsedExtension::BasicConstraints(BasicConstraints {
                        ca: true,
                        path_len_constraint: None,
                    }),
                ),
                X509Extension::new(
                    oid!(2.5.29.15),
                    false,
                    &[3, 2, 1, 70],
                    ParsedExtension::KeyUsage(KeyUsage { flags: 98 }),
                ),
                X509Extension::new(
                    oid!(2.5.29.32),
                    false,
                    &[48, 12, 48, 10, 6, 8, 42, 129, 122, 1, 121, 1, 1, 1],
                    ParsedExtension::CertificatePolicies(CertificatePolicies { policies }),
                ),
                X509Extension::new(
                    oid!(2.5.29.14),
                    false,
                    &[
                        4, 20, 163, 5, 47, 24, 96, 80, 194, 137, 10, 221, 43, 33, 79, 255, 142, 78,
                        168, 48, 49, 54,
                    ],
                    ParsedExtension::SubjectKeyIdentifier(KeyIdentifier(&[
                        163, 5, 47, 24, 96, 80, 194, 137, 10, 221, 43, 33, 79, 255, 142, 78, 168,
                        48, 49, 54,
                    ])),
                ),
                X509Extension::new(
                    oid!(2.5.29.35),
                    false,
                    &[
                        48, 22, 128, 20, 163, 5, 47, 24, 96, 80, 194, 137, 10, 221, 43, 33, 79,
                        255, 142, 78, 168, 48, 49, 54,
                    ],
                    ParsedExtension::UnsupportedExtension,
                ),
            ];
            let expected_extensions: HashMap<Oid, X509Extension> = expected_extensions_list
                .into_iter()
                .map(|e| (e.oid.clone(), e))
                .collect();
            assert_eq!(tbs_cert.extensions(), &expected_extensions);
            //
            assert!(tbs_cert.is_ca());
            //
            assert_eq!(tbs_cert.as_ref(), &IGCA_DER[4..(8 + 746)]);
        }
        _ => panic!("x509 parsing failed: {:?}", res),
    }
}

#[test]
fn test_x509_no_extensions() {
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
    let res = parse_subject_public_key_info(&IGCA_DER[339..])
        .expect("Parse public key info")
        .1;
    let oid = nid2obj(Nid::RsaEncryption).expect("Obj from Nid RsaEncryption");
    assert_eq!(res.algorithm.algorithm, *oid);
    let (tag, p) = res
        .algorithm
        .parameters
        .as_context_specific()
        .expect("algorithm parameters");
    assert_eq!(tag.0, 0);
    let params = p.expect("algorithm parameters");
    assert_eq!(params.header.tag.0, 5);
    let spk = res.subject_public_key;
    println!("spk.data.len {}", spk.data.len());
    assert_eq!(spk.data.len(), 270);
}

#[test]
fn test_version_v1() {
    let res = parse_x509_der(V1);
    assert!(res.is_ok());
    assert!(res.as_ref().unwrap().0.is_empty());
    let tbs_cert = res.unwrap().1.tbs_certificate;
    assert_eq!(tbs_cert.version, 1);
    assert_eq!(format!("{}", tbs_cert.subject), "CN=marquee");
    assert_eq!(format!("{}", tbs_cert.issuer), "CN=marquee");
}

#[test]
fn test_crl_parse() {
    match parse_crl_der(CRL_DER) {
        Ok((e, cert)) => {
            assert!(e.is_empty());

            let tbs_cert_list = cert.tbs_cert_list;
            assert_eq!(tbs_cert_list.version, Some(1));

            let sig = &tbs_cert_list.signature;
            assert_eq!(sig.algorithm, OID_RSA_SHA1);

            let expected_issuer =
                "O=Sample Signer Organization, OU=Sample Signer Unit, CN=Sample Signer Cert";
            assert_eq!(format!("{}", tbs_cert_list.issuer), expected_issuer);

            let sig_alg = &cert.signature_algorithm;
            assert_eq!(sig_alg.algorithm, OID_RSA_SHA1);

            let this_update = tbs_cert_list.this_update;
            let next_update = tbs_cert_list.next_update.unwrap();
            assert_eq!(this_update.tm_year, 113);
            assert_eq!(this_update.tm_mon, 1);
            assert_eq!(this_update.tm_mday, 18);
            assert_eq!(next_update.tm_year, 113);
            assert_eq!(next_update.tm_mon, 1);
            assert_eq!(next_update.tm_mday, 18);

            let revoked_certs = &tbs_cert_list.revoked_certificates;
            assert_eq!(
                revoked_certs[0],
                x509_parser::RevokedCertificate {
                    user_certificate: 1_341_767_u32.into(),
                    revocation_date: time::Tm {
                        tm_sec: 12,
                        tm_min: 22,
                        tm_hour: 10,
                        tm_mon: 1,
                        tm_mday: 18,
                        tm_year: 113,
                        tm_wday: 0,
                        tm_yday: 0,
                        tm_isdst: 0,
                        tm_utcoff: 0,
                        tm_nsec: 0,
                    },
                    extensions: vec![
                        X509Extension::new(
                            oid!(2.5.29.21),
                            false,
                            &[10, 1, 3],
                            ParsedExtension::UnsupportedExtension,
                        ),
                        X509Extension::new(
                            oid!(2.5.29.24),
                            false,
                            &[24, 15, 50, 48, 49, 51, 48, 50, 49, 56, 49, 48, 50, 50, 48, 48, 90],
                            ParsedExtension::UnsupportedExtension,
                        )
                    ]
                }
            );

            assert_eq!(revoked_certs.len(), 5);
            assert_eq!(revoked_certs[4].user_certificate, 1_341_771_u32.into());

            let expected_extensions = vec![
                X509Extension::new(
                    oid!(2.5.29.35),
                    false,
                    &[
                        48, 22, 128, 20, 190, 18, 1, 204, 170, 234, 17, 128, 218, 46, 173, 178,
                        234, 199, 181, 251, 159, 249, 173, 52,
                    ],
                    ParsedExtension::UnsupportedExtension,
                ),
                X509Extension::new(
                    oid!(2.5.29.20),
                    false,
                    &[2, 1, 3],
                    ParsedExtension::UnsupportedExtension,
                ),
            ];

            assert!(tbs_cert_list
                .extensions
                .iter()
                .eq(expected_extensions.iter()));

            assert_eq!(tbs_cert_list.as_ref(), &CRL_DER[4..(4 + 4 + 508)]);
        }
        err => panic!("x509 parsing failed: {:?}", err),
    }
}

#[test]
fn test_crl_parse_empty() {
    match parse_crl_der(EMPTY_CRL_DER) {
        Ok((e, cert)) => {
            assert!(e.is_empty());
            assert!(cert.tbs_cert_list.revoked_certificates.is_empty());

            let expected_extensions = vec![
                X509Extension::new(
                    oid!(2.5.29.20),
                    false,
                    &[2, 1, 2],
                    ParsedExtension::UnsupportedExtension,
                ),
                X509Extension::new(
                    OID_EXT_AUTHORITYKEYIDENTIFIER,
                    false,
                    &[
                        48, 22, 128, 20, 34, 101, 12, 214, 90, 157, 52, 137, 243, 131, 180, 149,
                        82, 191, 80, 27, 57, 39, 6, 172,
                    ],
                    ParsedExtension::UnsupportedExtension,
                ),
            ];
            assert!(cert
                .tbs_cert_list
                .extensions
                .iter()
                .eq(expected_extensions.iter()));
            assert_eq!(
                cert.tbs_cert_list.as_ref(),
                &EMPTY_CRL_DER[4..(4 + 3 + 200)]
            );
        }
        err => panic!("x509 parsing failed: {:?}", err),
    }
}

#[test]
fn test_crl_parse_minimal() {
    match parse_crl_der(MINIMAL_CRL_DER) {
        Ok((e, cert)) => {
            assert!(e.is_empty());
            let expected_revocations = &[x509_parser::RevokedCertificate {
                user_certificate: 42u32.into(),
                revocation_date: time::Tm {
                    tm_nsec: 0,
                    tm_sec: 0,
                    tm_min: 0,
                    tm_hour: 0,
                    tm_mon: 0,
                    tm_year: 70,
                    tm_wday: 0,
                    tm_mday: 1,
                    tm_yday: 0,
                    tm_isdst: 0,
                    tm_utcoff: 0,
                },
                extensions: vec![],
            }];
            assert_eq!(
                cert.tbs_cert_list.revoked_certificates,
                expected_revocations
            );
            assert!(cert.tbs_cert_list.extensions.is_empty());
            assert_eq!(cert.tbs_cert_list.as_ref(), &MINIMAL_CRL_DER[4..(4 + 79)]);
        }
        err => panic!("x509 parsing failed: {:?}", err),
    }
}
