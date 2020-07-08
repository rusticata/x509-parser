use der_parser::oid::Oid;
use std::env;
use std::io;
use x509_parser::extensions::*;
use x509_parser::objects::*;
use x509_parser::pem::pem_to_der;
use x509_parser::x509::X509Certificate;
use x509_parser::{parse_x509_der, X509Extension};

fn print_x509_extension(oid: &Oid, ext: &X509Extension) {
    match oid2sn(oid) {
        Ok(sn) => print!("    {}:", sn),
        _ => print!("    {}:", oid),
    }
    print!(" Critical={}", ext.critical);
    print!(" len={}", ext.value.len());
    println!();
    match ext.parsed_extension() {
        ParsedExtension::BasicConstraints(bc) => {
            println!("      X509v3 CA: {}", bc.ca);
        }
        ParsedExtension::KeyUsage(ku) => {
            println!("      X509v3 Key Usage: {}", ku);
        }
        ParsedExtension::SubjectAlternativeName(san) => {
            for name in &san.general_names {
                println!("      X509v3 SAN: {:?}", name);
            }
        }
        ParsedExtension::SubjectKeyIdentifier(id) => {
            let mut s =
                id.0.iter()
                    .fold(String::with_capacity(3 * id.0.len()), |a, b| {
                        a + &format!("{:02x}:", b)
                    });
            s.pop();
            println!("      X509v3 Subject Key Identifier: {}", &s);
        }
        x => println!("      {:?}", x),
    }
}

fn print_x509_info(file_name: &str, x509: &X509Certificate) {
    println!("File: {}", file_name);
    println!("  Subject: {}", x509.subject());
    println!("  Issuer: {}", x509.issuer());
    println!("  Serial: {}", x509.tbs_certificate.raw_serial_as_string());
    println!("  Validity:");
    println!("    NotBefore: {}", x509.validity().not_before.to_rfc2822());
    println!("    NotAfter:  {}", x509.validity().not_after.to_rfc2822());
    println!("    is_valid:  {}", x509.validity().is_valid());
    println!("  Extensions:");
    for (oid, ext) in x509.extensions() {
        print_x509_extension(oid, ext);
    }
    println!();
}

pub fn main() -> io::Result<()> {
    for file_name in env::args().skip(1) {
        // placeholder to store decoded PEM data, if needed
        let tmpdata;

        let data = std::fs::read(file_name.clone()).expect("Unable to read file");
        let der_data: &[u8] = if (data[0], data[1]) == (0x30, 0x82) {
            // probably DER
            &data
        } else {
            // try as PEM
            let (_, data) = pem_to_der(&data).expect("Could not decode the PEM file");
            tmpdata = data;
            &tmpdata.contents
        };
        let (_, x509) = parse_x509_der(&der_data).expect("Could not decode DER data");
        print_x509_info(&file_name, &x509);
    }
    Ok(())
}
