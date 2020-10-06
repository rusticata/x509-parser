use chrono::offset::{TimeZone, Utc};
use chrono::Datelike;
use der_parser::{oid, oid::Oid};
use std::collections::HashMap;
use x509_parser::error::*;
use x509_parser::extensions::*;
use x509_parser::objects::*;
use x509_parser::{
    parse_crl_der, parse_subject_public_key_info, parse_x509_der, ASN1Time, X509Extension,
};

static IGCA_DER: &[u8] = include_bytes!("../assets/IGC_A.der");
static NO_EXTENSIONS_DER: &[u8] = include_bytes!("../assets/no_extensions.der");
static V1: &[u8] = include_bytes!("../assets/v1.der");
static CRL_DER: &[u8] = include_bytes!("../assets/example.crl");
static EMPTY_CRL_DER: &[u8] = include_bytes!("../assets/empty.crl");
static MINIMAL_CRL_DER: &[u8] = include_bytes!("../assets/minimal.crl");
static DUPLICATE_VALUE_IN_AIA: &[u8] =
    include_bytes!("../assets/duplicate_value_in_authority_info_access.der");

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
            let tbs_cert = &cert.tbs_certificate;
            assert_eq!(tbs_cert.version, 2);
            //
            let s = tbs_cert.raw_serial_as_string();
            assert_eq!(&s, "39:11:45:10:94");
            //
            let expected_subject = "C=FR, ST=France, L=Paris, O=PM/SGDN, OU=DCSSI, CN=IGC/A, Email=igca@sgdn.pm.gouv.fr";
            assert_eq!(format!("{}", tbs_cert.subject), expected_subject);
            //
            let cn_list: Result<Vec<_>, X509Error> = cert
                .subject()
                .iter_common_name()
                .map(|attr| attr.as_str())
                .collect();
            assert_eq!(cn_list, Ok(vec!["IGC/A"]));
            //
            let sig = &tbs_cert.signature;
            assert_eq!(sig.algorithm, oid!(1.2.840.113549.1.1.5));
            //
            let expected_issuer = "C=FR, ST=France, L=Paris, O=PM/SGDN, OU=DCSSI, CN=IGC/A, Email=igca@sgdn.pm.gouv.fr";
            assert_eq!(format!("{}", tbs_cert.issuer), expected_issuer);
            let expected_issuer_der = &IGCA_DER[35..171];
            assert_eq!(tbs_cert.issuer.as_raw(), expected_issuer_der);
            //
            let sig_alg = &cert.signature_algorithm;
            assert_eq!(sig_alg.algorithm, OID_RSA_SHA1);
            //
            let not_before = tbs_cert.validity.not_before;
            let not_after = tbs_cert.validity.not_after;
            let nb = Utc.timestamp(not_before.timestamp(), 0);
            let na = Utc.timestamp(not_after.timestamp(), 0);
            assert_eq!(nb.year(), 2002);
            assert_eq!(nb.month(), 12);
            assert_eq!(nb.day(), 13);
            assert_eq!(na.year(), 2020);
            assert_eq!(na.month(), 10);
            assert_eq!(na.day(), 17);
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
                    ParsedExtension::AuthorityKeyIdentifier(AuthorityKeyIdentifier {
                        key_identifier: Some(KeyIdentifier(&[
                            163, 5, 47, 24, 96, 80, 194, 137, 10, 221, 43, 33, 79, 255, 142, 78,
                            168, 48, 49, 54,
                        ])),
                        authority_cert_issuer: None,
                        authority_cert_serial: None,
                    }),
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
            let tu = Utc.timestamp(this_update.timestamp(), 0);
            let nu = Utc.timestamp(next_update.timestamp(), 0);
            assert_eq!(tu.year(), 2013);
            assert_eq!(tu.month(), 2);
            assert_eq!(tu.day(), 18);
            assert_eq!(nu.year(), 2013);
            assert_eq!(nu.month(), 2);
            assert_eq!(nu.day(), 18);

            let revocation_date =
                ASN1Time::from_timestamp(Utc.ymd(2013, 2, 18).and_hms(10, 22, 12).timestamp());

            let revoked_certs = &tbs_cert_list.revoked_certificates;
            assert_eq!(
                revoked_certs[0],
                x509_parser::RevokedCertificate {
                    user_certificate: 1_341_767_u32.into(),
                    revocation_date,
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
                    ParsedExtension::AuthorityKeyIdentifier(AuthorityKeyIdentifier {
                        key_identifier: Some(KeyIdentifier(&[
                            190, 18, 1, 204, 170, 234, 17, 128, 218, 46, 173, 178, 234, 199, 181,
                            251, 159, 249, 173, 52,
                        ])),
                        authority_cert_issuer: None,
                        authority_cert_serial: None,
                    }),
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
                    ParsedExtension::AuthorityKeyIdentifier(AuthorityKeyIdentifier {
                        key_identifier: Some(KeyIdentifier(&[
                            34, 101, 12, 214, 90, 157, 52, 137, 243, 131, 180, 149, 82, 191, 80,
                            27, 57, 39, 6, 172,
                        ])),
                        authority_cert_issuer: None,
                        authority_cert_serial: None,
                    }),
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
            let revocation_date =
                ASN1Time::from_timestamp(Utc.ymd(1970, 1, 1).and_hms(0, 0, 0).timestamp());
            let expected_revocations = &[x509_parser::RevokedCertificate {
                user_certificate: 42u32.into(),
                revocation_date,
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

#[test]
fn test_duplicate_authority_info_access() {
    match parse_x509_der(DUPLICATE_VALUE_IN_AIA) {
        Ok((_, cert)) => {
            let extension = cert
                .tbs_certificate
                .extensions
                .get(sn2oid("authorityInfoAccess").unwrap())
                .unwrap();
            let mut accessdescs = HashMap::new();
            let ca_issuers = vec![
                GeneralName::URI("http://cdp1.pca.dfn.de/dfn-ca-global-g2/pub/cacert/cacert.crt"),
                GeneralName::URI("http://cdp2.pca.dfn.de/dfn-ca-global-g2/pub/cacert/cacert.crt"),
            ];
            let ocsp = vec![GeneralName::URI("http://ocsp.pca.dfn.de/OCSP-Server/OCSP")];
            accessdescs.insert(OID_ACCESSDESCRIPTOR_CAISSUERS, ca_issuers);
            accessdescs.insert(OID_ACCESSDESCRIPTOR_OCSP, ocsp);
            let expected_aia =
                ParsedExtension::AuthorityInfoAccess(AuthorityInfoAccess { accessdescs });
            assert_eq!(*extension.parsed_extension(), expected_aia);
        }
        err => panic!("x509 parsing failed: {:?}", err),
    }
}
