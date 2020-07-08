//! [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
//! [![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
//! [![docs.rs](https://docs.rs/x509-parser/badge.svg)](https://docs.rs/x509-parser)
//! [![crates.io](https://img.shields.io/crates/v/x509-parser.svg)](https://crates.io/crates/x509-parser)
//! [![Download numbers](https://img.shields.io/crates/d/x509-parser.svg)](https://crates.io/crates/x509-parser)
//! [![Travis CI](https://travis-ci.org/rusticata/x509-parser.svg?branch=master)](https://travis-ci.org/rusticata/x509-parser)
//! [![Github CI](https://github.com/rusticata/x509-parser/workflows/Continuous%20integration/badge.svg)](https://github.com/rusticata/x509-parser/actions)
//!
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
//! The main parsing method is [`parse_x509_der`](fn.parse_x509_der.html), which takes a
//! DER-encoded certificate as input, and builds a
//! [`X509Certificate`](x509/struct.X509Certificate.html) object.
//!
//! For PEM-encoded certificates, use the [`pem`](pem/index.html) module.
//!
//! # Examples
//!
//! Parsing a certificate in DER format:
//!
//! ```rust
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
//! See also `examples/print-cert.rs`.
//!
//! # Features
//!
//! - The `verify` feature adds support for (cryptographic) signature verification, based on ring.
//!   It adds the `verify_signature` to `X509Certificate`.
//!
//! ```rust
//! # #[cfg(feature = "verify")]
//! # use x509_parser::X509Certificate;
//! /// Cryptographic signature verification: returns true if certificate was signed by issuer
//! #[cfg(feature = "verify")]
//! pub fn check_signature(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
//!     let issuer_public_key = &issuer.tbs_certificate.subject_pki;
//!     cert
//!         .verify_signature(Some(issuer_public_key))
//!         .is_ok()
//! }
//! ```
//!
//! [RFC5280]: https://tools.ietf.org/html/rfc5280

#![deny(/*missing_docs,*/
        unstable_features,
        unused_import_braces, unused_qualifications)]
#![warn(
    missing_debug_implementations,
    /* missing_docs,
    rust_2018_idioms,*/
    unreachable_pub
)]
#![forbid(unsafe_code)]
#![deny(intra_doc_link_resolution_failure)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub use x509::*;
pub mod x509;

pub mod error;
pub mod extensions;
pub mod objects;
pub mod pem;
mod time;
pub use time::*;
mod x509_parser;
pub use crate::x509_parser::*;
mod verify;
pub use verify::*;
