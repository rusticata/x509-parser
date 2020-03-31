extern crate der_parser;
extern crate nom;
extern crate rusticata_macros;
extern crate x509_parser;

use std::io::Cursor;
use x509_parser::parse_x509_der;
use x509_parser::pem::{pem_to_der, Pem};

static IGCA_PEM: &'static [u8] = include_bytes!("../assets/IGC_A.pem");

#[test]
fn test_x509_parse_pem() {
    let res = pem_to_der(IGCA_PEM);
    match res {
        Ok((rem, pem)) => {
            // println!("{:?}", pem);
            assert!(rem.is_empty());
            assert_eq!(pem.label, String::from("CERTIFICATE"));
            //
            // now check that the content is indeed a certificate
            let res = parse_x509_der(&pem.contents);
            // println!("res: {:?}", res);
            match res {
                Ok((rem, crt)) => {
                    assert!(rem.is_empty());
                    assert_eq!(crt.tbs_certificate.version, 2);
                }
                _e => {
                    eprintln!("{:?}", _e);
                    assert!(false);
                }
            }
        }
        _e => {
            eprintln!("{:?}", _e);
            assert!(false);
        }
    }
}

#[test]
fn test_pem_read() {
    let reader = Cursor::new(IGCA_PEM);
    let (pem, bytes_read) = Pem::read(reader).expect("Reading PEM failed");
    // println!("{:?}", pem);
    assert_eq!(bytes_read, IGCA_PEM.len());
    assert_eq!(pem.label, String::from("CERTIFICATE"));
    //
    // now check that the content is indeed a certificate
    let x509 = pem.parse_x509().expect("X.509: decoding DER failed");
    assert_eq!(x509.tbs_certificate.version, 2);
}

#[test]
fn test_pem_not_pem() {
    let bytes = vec![0x1, 0x2, 0x3, 0x4, 0x5];
    let reader = Cursor::new(bytes);
    let res = Pem::read(reader);
    assert!(res.is_err());
}

static NO_END: &'static [u8] = include_bytes!("../assets/no_end.pem");

#[test]
fn test_pem_no_end() {
    let reader = Cursor::new(NO_END);
    let res = Pem::read(reader);
    assert!(res.is_err());
}
