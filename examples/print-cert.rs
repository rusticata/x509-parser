use std::env;
use std::io;
use x509_parser::objects::oid2sn;
use x509_parser::parse_x509_der;
use x509_parser::pem::pem_to_der;
use x509_parser::x509::X509Certificate;

fn print_x509_info(file_name: &str, x509: &X509Certificate) {
    println!("File: {}", file_name);
    println!("  Subject: {}", x509.subject());
    println!("  Issuer: {}", x509.issuer());
    println!("  Serial: {}", x509.tbs_certificate.raw_serial_as_string());
    println!("  Validity:");
    println!("    NotBefore: {}", x509.validity().not_before.rfc822());
    println!("    NotAfter:  {}", x509.validity().not_after.rfc822());
    println!("  Extensions:");
    for (oid, _ext) in x509.extensions() {
        match oid2sn(oid) {
            Ok(sn) => println!("    {}", sn),
            _ => println!("    {}", oid),
        }
    }
    println!("");
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
            let (_, data) = pem_to_der(&data).or(Err(io::Error::new(
                io::ErrorKind::Other,
                "Could not decode the PEM file",
            )))?;
            tmpdata = data;
            &tmpdata.contents
        };
        let (_, x509) = parse_x509_der(&der_data).or(Err(io::Error::new(
            io::ErrorKind::Other,
            "Could not decode DER data",
        )))?;
        print_x509_info(&file_name, &x509);
    }
    Ok(())
}
