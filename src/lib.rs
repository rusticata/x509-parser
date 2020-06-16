//! # X.509 Parser
//!
//! A X.509 v3 ([RFC5280]) parser, implemented with the [nom](https://github.com/Geal/nom)
//! parser combinator framework.
//!
//! It is written in pure Rust, fast, and makes extensive use of zero-copy. A lot of care is taken
//! to ensure security and safety of this crate, including design (recursion limit, defensive
//! programming), tests, and fuzzing. It also aims to be panic-free.
//!
//! The code is available on [Github](https://github.com/rusticata/x509-parser)
//! and is part of the [Rusticata](https://github.com/rusticata) project.
//!
//! The main parsing method is [`parse_x509_der`](fn.parse_x509_der.html), which takes a DER-encoded
//! certificate as input, and builds a [`X509Certificate`](x509/struct.X509Certificate.html) object.
//!
//! For PEM-encoded certificates, use the [`pem`](pem/index.html) module.
//!
//! # Examples
//!
//! Parsing a certificate in DER format:
//!
//! ```rust,no_run
//! use x509_parser::parse_x509_der;
//!
//! static IGCA_DER: &'static [u8] = include_bytes!("../assets/IGC_A.der");
//!
//! # fn main() {
//! let res = parse_x509_der(IGCA_DER);
//! match res {
//!     Ok((rem, cert)) => {
//!         assert!(rem.is_empty());
//!         //
//!         assert_eq!(cert.tbs_certificate.version, 2);
//!     },
//!     _ => panic!("x509 parsing failed: {:?}", res),
//! }
//! # }
//! ```
//!
//! [RFC5280]: https://tools.ietf.org/html/rfc5280

#![deny(/*missing_docs,*/
        unstable_features,
        unused_import_braces, unused_qualifications)]
#![forbid(unsafe_code)]

pub use x509::*;
pub mod x509;

pub mod error;
pub mod extensions;
pub mod objects;
pub mod pem;
mod x509_parser;
pub use crate::x509_parser::*;
