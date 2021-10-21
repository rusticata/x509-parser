use der_parser::oid::Oid;
use nom::HexDisplay;
use std::cmp::min;
use std::env;
use std::io;
use x509_parser::prelude::*;

const PARSE_ERRORS_FATAL: bool = false;
#[cfg(feature = "validate")]
const VALIDATE_ERRORS_FATAL: bool = false;

fn print_hex_dump(bytes: &[u8], max_len: usize) {
    let m = min(bytes.len(), max_len);
    print!("{}", &bytes[..m].to_hex(16));
    if bytes.len() > max_len {
        println!("... <continued>");
    }
}

fn format_oid(oid: &Oid) -> String {
    match oid2sn(oid, oid_registry()) {
        Ok(s) => s.to_owned(),
        _ => format!("{}", oid),
    }
}

fn generalname_to_string(gn: &GeneralName) -> String {
    match gn {
        GeneralName::DNSName(name) => format!("DNSName:{}", name),
        GeneralName::DirectoryName(n) => format!("DirName:{}", n),
        GeneralName::EDIPartyName(obj) => format!("EDIPartyName:{:?}", obj),
        GeneralName::IPAddress(n) => format!("IPAddress:{:?}", n),
        GeneralName::OtherName(oid, n) => format!("OtherName:{}, {:?}", oid, n),
        GeneralName::RFC822Name(n) => format!("RFC822Name:{}", n),
        GeneralName::RegisteredID(oid) => format!("RegisteredID:{}", oid),
        GeneralName::URI(n) => format!("URI:{}", n),
        GeneralName::X400Address(obj) => format!("X400Address:{:?}", obj),
    }
}

fn print_x509_extension(oid: &Oid, ext: &X509Extension) {
    println!(
        "    [crit:{} l:{}] {}: ",
        ext.critical,
        ext.value.len(),
        format_oid(oid)
    );
    match ext.parsed_extension() {
        ParsedExtension::AuthorityKeyIdentifier(aki) => {
            println!("      X509v3 Authority Key Identifier");
            if let Some(key_id) = &aki.key_identifier {
                println!("        Key Identifier: {:x}", key_id);
            }
            if let Some(issuer) = &aki.authority_cert_issuer {
                for name in issuer {
                    println!("        Cert Issuer: {}", name);
                }
            }
            if let Some(serial) = aki.authority_cert_serial {
                println!("        Cert Serial: {}", format_serial(serial));
            }
        }
        ParsedExtension::BasicConstraints(bc) => {
            println!("      X509v3 CA: {}", bc.ca);
        }
        ParsedExtension::CRLDistributionPoints(points) => {
            println!("      X509v3 CRL Distribution Points:");
            for point in points {
                if let Some(name) = &point.distribution_point {
                    println!("        Full Name: {:?}", name);
                }
                if let Some(reasons) = &point.reasons {
                    println!("        Reasons: {}", reasons);
                }
                if let Some(crl_issuer) = &point.crl_issuer {
                    print!("        CRL Issuer: ");
                    for gn in crl_issuer {
                        print!("{} ", generalname_to_string(gn));
                    }
                    println!();
                }
                println!();
            }
        }
        ParsedExtension::KeyUsage(ku) => {
            println!("      X509v3 Key Usage: {}", ku);
        }
        ParsedExtension::NSCertType(ty) => {
            println!("      Netscape Cert Type: {}", ty);
        }
        ParsedExtension::SubjectAlternativeName(san) => {
            for name in &san.general_names {
                println!("      X509v3 SAN: {:?}", name);
            }
        }
        ParsedExtension::SubjectKeyIdentifier(id) => {
            println!("      X509v3 Subject Key Identifier: {:x}", id);
        }
        x => println!("      {:?}", x),
    }
}

fn print_x509_digest_algorithm(alg: &AlgorithmIdentifier, level: usize) {
    println!(
        "{:indent$}Oid: {}",
        "",
        format_oid(&alg.algorithm),
        indent = level
    );
    if let Some(parameter) = &alg.parameters {
        println!(
            "{:indent$}Parameter: <PRESENT> {:?}",
            "",
            parameter.header.tag,
            indent = level
        );
        if let Ok(bytes) = parameter.as_slice() {
            print_hex_dump(bytes, 32);
        }
    } else {
        println!("{:indent$}Parameter: <ABSENT>", "", indent = level);
    }
}

fn print_x509_info(x509: &X509Certificate) -> io::Result<()> {
    println!("  Subject: {}", x509.subject());
    println!("  Signature Algorithm:");
    print_x509_digest_algorithm(&x509.signature_algorithm, 4);
    println!("  Issuer: {}", x509.issuer());
    println!("  Serial: {}", x509.tbs_certificate.raw_serial_as_string());
    println!("  Validity:");
    println!("    NotBefore: {}", x509.validity().not_before.to_rfc2822());
    println!("    NotAfter:  {}", x509.validity().not_after.to_rfc2822());
    println!("    is_valid:  {}", x509.validity().is_valid());
    println!("  Extensions:");
    for ext in x509.extensions() {
        print_x509_extension(&ext.oid, ext);
    }
    println!();
    print!("Structure validation status: ");
    #[cfg(feature = "validate")]
    {
        let mut logger = VecLogger::default();
        // structure validation status
        let ok = X509StructureValidator
            .chain(X509CertificateValidator)
            .validate(x509, &mut logger);
        if ok {
            println!("Ok");
        } else {
            println!("FAIL");
        }
        for warning in logger.warnings() {
            println!("  [W] {}", warning);
        }
        for error in logger.errors() {
            println!("  [E] {}", error);
        }
        println!();
        if VALIDATE_ERRORS_FATAL && !logger.errors().is_empty() {
            return Err(io::Error::new(io::ErrorKind::Other, "validation failed"));
        }
    }
    #[cfg(not(feature = "validate"))]
    {
        println!("Unknown (feature 'validate' not enabled)");
    }
    Ok(())
}

fn handle_certificate(file_name: &str, data: &[u8]) -> io::Result<()> {
    match parse_x509_certificate(data) {
        Ok((_, x509)) => {
            print_x509_info(&x509)?;
            Ok(())
        }
        Err(e) => {
            let s = format!("Error while parsing {}: {}", file_name, e);
            if PARSE_ERRORS_FATAL {
                Err(io::Error::new(io::ErrorKind::Other, s))
            } else {
                eprintln!("{}", s);
                Ok(())
            }
        }
    }
}

pub fn main() -> io::Result<()> {
    for file_name in env::args().skip(1) {
        println!("File: {}", file_name);
        let data = std::fs::read(file_name.clone()).expect("Unable to read file");
        if matches!((data[0], data[1]), (0x30, 0x81..=0x83)) {
            // probably DER
            handle_certificate(&file_name, &data)?;
        } else {
            // try as PEM
            for (n, pem) in Pem::iter_from_buffer(&data).enumerate() {
                let pem = pem.expect("Could not decode the PEM file");
                let data = &pem.contents;
                println!("Certificate [{}]", n);
                handle_certificate(&file_name, data)?;
            }
        }
    }
    Ok(())
}
