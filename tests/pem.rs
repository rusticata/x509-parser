extern crate nom;
extern crate der_parser;
extern crate x509_parser;
extern crate rusticata_macros;

use x509_parser::parse_x509_der;
use x509_parser::pem::pem_to_der;

static IGCA_PEM: &'static [u8] = include_bytes!("../assets/IGC_A.pem");

#[test]
fn test_x509_parse_pem() {
    let res = pem_to_der(IGCA_PEM);
    match res {
        Ok((rem,pem)) => {
            // println!("{:?}", pem);
            assert!(rem.is_empty());
            assert_eq!(pem.label, String::from("CERTIFICATE"));
            //
            // now check that the content is indeed a certificate
            let res = parse_x509_der(&pem.contents);
            // println!("res: {:?}", res);
            match res {
                Ok((rem,crt)) => {
                    assert!(rem.is_empty());
                    assert_eq!(crt.tbs_certificate.version,2);
                },
                _e            => { eprintln!("{:?}", _e); assert!(false); },
            }
        },
        _e            => { eprintln!("{:?}", _e); assert!(false); },
    }
}
