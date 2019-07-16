//! Decoding functions for PEM-encoded data
//!
//! # Examples
//!
//! To parse a certificate in PEM format, first create the `Pem` object, then decode
//! contents:
//!
//! ```rust,no_run
//! # extern crate nom;
//! # #[macro_use] extern crate x509_parser;
//! use std::io::Cursor;
//! use x509_parser::pem::{pem_to_der, Pem};
//! use x509_parser::parse_x509_der;
//!
//! static IGCA_PEM: &'static [u8] = include_bytes!("../assets/IGC_A.pem");
//!
//! # fn main() {
//! let res = pem_to_der(IGCA_PEM);
//! let reader = Cursor::new(IGCA_PEM);
//! let (pem,bytes_read) = Pem::read(reader).expect("Reading PEM failed");
//! let x509 = pem.parse_x509().expect("X.509: decoding DER failed");
//! assert_eq!(x509.tbs_certificate.version, 2);
//! # }
//! ```
//!
//! This is the most direct method to parse PEM data.
//!
//! Another method to parse the certificate is to use `pem_to_der`:
//!
//! ```rust,no_run
//! # extern crate nom;
//! # #[macro_use] extern crate x509_parser;
//! use x509_parser::pem::pem_to_der;
//! use x509_parser::parse_x509_der;
//!
//! static IGCA_PEM: &'static [u8] = include_bytes!("../assets/IGC_A.pem");
//!
//! # fn main() {
//! let res = pem_to_der(IGCA_PEM);
//! match res {
//!     Ok((rem, pem)) => {
//!         assert!(rem.is_empty());
//!         //
//!         assert_eq!(pem.label, String::from("CERTIFICATE"));
//!         //
//!         let res_x509 = parse_x509_der(&pem.contents);
//!         assert!(res_x509.is_ok());
//!     },
//!     _ => panic!("PEM parsing failed: {:?}", res),
//! }
//! # }
//! ```
//!
//! Note that all methods require to store the `Pem` object in a variable, mainly because decoding
//! the PEM object requires allocation of buffers, and that the lifetime of X.509 certificates will
//! be bound to these buffers.

use crate::error::PEMError;
use crate::x509::X509Certificate;
use crate::x509_parser::parse_x509_der;
use base64;
use nom::{Err, ErrorKind, IResult};
use std::io::{BufRead, Cursor};

/// Representation of PEM data
#[derive(PartialEq, Debug)]
pub struct Pem {
    /// The PEM label
    pub label: String,
    /// The PEM decoded data
    pub contents: Vec<u8>,
}

/// Read a PEM-encoded structure, and decode the base64 data
///
/// Allocates a new buffer for the decoded data.
pub fn pem_to_der<'a>(i: &'a [u8]) -> IResult<&'a [u8], Pem, PEMError> {
    let reader = Cursor::new(i);
    let res = Pem::read(reader);
    match res {
        Ok((pem, bytes_read)) => Ok((&i[bytes_read..], pem)),
        Err(e) => Err(Err::Error(error_position!(i, ErrorKind::Custom(e)))),
    }
}

impl Pem {
    /// Read a PEM-encoded structure, and decode the base64 data
    ///
    /// Returns the certificate (encoded in DER) and the number of bytes read.
    /// Allocates a new buffer for the decoded data.
    pub fn read<T>(mut r: Cursor<T>) -> Result<(Pem, usize), PEMError>
    where
        T: AsRef<[u8]>,
    {
        let mut first_line = String::new();
        r.read_line(&mut first_line)?;
        let mut iter = first_line.split_whitespace();
        if iter.next() != Some("-----BEGIN") {
            return Err(PEMError::MissingHeader);
        }
        let label = iter.next().ok_or(PEMError::InvalidHeader)?;
        let label = label.split('-').next().ok_or(PEMError::InvalidHeader)?;
        let mut s = String::new();
        loop {
            let mut l = String::new();
            r.read_line(&mut l)?;
            if l.starts_with("-----END ") {
                // finished reading
                break;
            }
            s.push_str(l.trim_end());
        }

        let contents = base64::decode(&s).or(Err(PEMError::Base64DecodeError))?;
        let pem = Pem {
            label: label.to_string(),
            contents,
        };
        Ok((pem, r.position() as usize))
    }

    /// Decode the PEM contents into a X.509 object
    pub fn parse_x509<'pem>(&'pem self) -> Result<X509Certificate<'pem>, Err<&[u8]>> {
        parse_x509_der(&self.contents)
            .map(|(_,x509)| x509)
    }
}
