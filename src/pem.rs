//! Decoding functions for PEM-encoded data
//!
//! # Examples
//!
//! Parsing a certificate in PEM format:
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

use std::str;
use base64;
use nom::IResult;

/// Representation of PEM data
#[derive(PartialEq,Debug)]
pub struct Pem {
    /// The PEM label
    pub label:    String,
    /// The PEM decoded data
    pub contents: Vec<u8>,
}

/// Read a PEM-encoded structure, and decode the base64 data
///
/// Allocates a new buffer for the decoded data.
pub fn pem_to_der<'a>(i:&'a[u8]) -> IResult<&'a[u8],Pem> {
    do_parse!(
        i,
           tag_s!("-----BEGIN ") >>
        l: map_res!(
                take_until!("-"),
                |x:&'a[u8]| str::from_utf8(x)
           ) >>
           tag_s!("-----") >>
        r: map_res!(
               take_until!("-----END"),
               |lines:&[u8]| {
                   let v = lines.split(|&x| x==0xa).fold(
                       Vec::new(),
                       |mut acc,line| {
                           if !line.is_empty() { acc.extend_from_slice(line); }
                           acc
                       }
                   );
                   base64::decode(&v)
               }
           ) >>
           tag_s!("-----END ") >>
           take_until!("-") >>
           tag_s!("-----") >>
           opt!(tag!(b"\n")) >>
        (
            Pem{
                label:    l.to_string(),
                contents: r
            }
        )
    )
}
