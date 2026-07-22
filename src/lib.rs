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
//! Certificates are usually encoded in two main formats: PEM (usually the most common format) or
//! DER.  A PEM-encoded certificate is a container, storing a DER object. See the
//! [`pem`] module for more documentation.
//!
//! To decode a DER-encoded certificate, the main parsing method is
//! `X509Certificate::parse_der` (from the [`DerParser`](asn1_rs::DerParser) trait)
//! which builds a [`X509Certificate`] object.
//!
//! The [`parse_der`](asn1_rs::DerParser) trait takes an [`Input`](asn1_rs::Input)
//! object, which can be built from the input bytes. This helps tracking offsets (in case of
//! error).
//! For convenience,
//! the [`X509Certificate::from_der`] method (part of the [`FromDer`] trait)
//! does the same directly on the input bytes, but it can loose the precise error location.
//!
//! An alternative method is to use [`X509CertificateParser`](crate::certificate::X509CertificateParser),
//! which allows specifying parsing options (for example, not automatically parsing option contents).
//!
//! Similar methods are provided for other X.509 objects:
//! - [`X509Certificate`] for X.509 Certificates
//! - [`CertificateRevocationList`] for X.509 v2 Certificate Revocation List (CRL)
//! - [`X509CertificationRequest`](crate::certification_request::X509CertificationRequest) for Certification Signing Request (CSR)

//!
//! The returned objects for parsers follow the definitions of the RFC. This means that accessing
//! fields is done by accessing struct members recursively. Some helper functions are provided, for
//! example [`X509Certificate::issuer()`](crate::certificate::TbsCertificate::issuer()) returns the
//! same as accessing `<object>.tbs_certificate.issuer`.
//!
//! For PEM-encoded certificates, use the [`pem`] module.
//!
//! This crate also provides visitor traits: [`X509CertificateVisitor`](crate::visitor::X509CertificateVisitor), [`CertificateRevocationListVisitor`](crate::visitor::CertificateRevocationListVisitor).
//! See the [`visitor`] module.
//!
//! # Examples
//!
//! Parsing a certificate in DER format:
//!
//! ```rust
//! use x509_parser::prelude::*;
//!
//! static IGCA_DER: &[u8] = include_bytes!("../assets/IGC_A.der");
//!
//! # fn main() {
//! let input = Input::from(IGCA_DER);
//! let res = X509Certificate::parse_der(input);
//! match res {
//!     Ok((rem, cert)) => {
//!         assert!(rem.is_empty());
//!         //
//!         assert_eq!(cert.version(), X509Version::V3);
//!     },
//!     _ => panic!("x509 parsing failed: {:?}", res),
//! }
//! # }
//! ```
//!
//! To parse a CRL and print information about revoked certificates:
//!
//! ```rust
//! # use x509_parser::prelude::*;
//! #
//! # static DER: &[u8] = include_bytes!("../assets/example.crl");
//! #
//! # fn main() {
//! let input = Input::from(DER);
//! let res = CertificateRevocationList::parse_der(input);
//! match res {
//!     Ok((_rem, crl)) => {
//!         for revoked in crl.iter_revoked_certificates() {
//!             println!("Revoked certificate serial: {}", revoked.raw_serial_as_string());
//!             println!("  Reason: {}", revoked.reason_code().unwrap_or_default().1);
//!         }
//!     },
//!     _ => panic!("CRL parsing failed: {:?}", res),
//! }
//! # }
//! ```
//!
//! See also `examples/print-cert.rs`.
//!
//! # Features
//!
//! - The `verify` and `verify-aws` features add support for (cryptographic) signature verification, based on `ring` or `aws-lc` respectively.
//!   It adds the
//!   [`X509Certificate::verify_signature()`] method
//!   to `X509Certificate`.
//!
//! ```rust
//! # #[cfg(any(feature = "verify", feature = "verify-aws"))]
//! # use x509_parser::certificate::X509Certificate;
//! /// Cryptographic signature verification: returns true if certificate was signed by issuer
//! #[cfg(any(feature = "verify", feature = "verify-aws"))]
//! pub fn check_signature(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
//!     let issuer_public_key = issuer.public_key();
//!     cert
//!         .verify_signature(Some(issuer_public_key))
//!         .is_ok()
//! }
//! ```
//!
//! - The `verify-aws` feature offers the same support for signature verification, but based on
//!   `aws-lc-rs` instead of `ring`.
//!
//! - _Note_: if both `verify` and `verify-aws` features are enabled (which happens when using
//!   `--all-features`), the verification will use `aws-lc-rs`. It also has the side-effect of
//!   having a dependency on `ring`, even if it is not used.
//!
//! - The `validate` feature adds methods to run more validation functions on the certificate structure
//!   and values using the [`Validate`](crate::validate::Validate) trait.
//!   It does not validate any cryptographic parameter (see `verify` above).
//!
//! ## Rust version requirements
//!
//! `x509-parser` requires **Rustc version 1.85 or greater**
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
#![deny(rustdoc::broken_intra_doc_links)]
#![doc(test(
    no_crate_inject,
    attr(deny(warnings, rust_2018_idioms), allow(dead_code, unused_variables))
))]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod certificate;
pub mod certification_request;
pub mod cri_attributes;
pub mod error;
pub mod extensions;
pub mod objects;
pub mod parser_utils;
pub mod pem;
pub mod prelude;
pub mod public_key;
pub mod revocation_list;
pub mod signature_algorithm;
pub mod signature_value;
pub mod time;
#[cfg(feature = "validate")]
#[cfg_attr(docsrs, doc(cfg(feature = "validate")))]
pub mod validate;
#[cfg(any(feature = "verify", feature = "verify-aws"))]
#[cfg_attr(docsrs, doc(cfg(any(feature = "verify", feature = "verify-aws"))))]
pub mod verify;
pub mod visitor;
pub mod x509;

// reexports
pub use asn1_rs;
pub use asn1_rs::num_bigint;
pub use nom;
pub use oid_registry;

use asn1_rs::FromDer;
use certificate::X509Certificate;
use error::X509Result;
use revocation_list::CertificateRevocationList;

/// Parse a **DER-encoded** X.509 Certificate, and return the remaining of the input and the built
/// object.
///
///
/// This function is an alias to [X509Certificate::from_der](certificate::X509Certificate::from_der). See this function
/// for more information.
///
/// For PEM-encoded certificates, use the [`pem`](pem/index.html) module.
#[inline]
pub fn parse_x509_certificate(i: &[u8]) -> X509Result<'_, X509Certificate<'_>> {
    X509Certificate::from_der(i)
}

/// Parse a DER-encoded X.509 v2 CRL, and return the remaining of the input and the built
/// object.
///
/// This function is an alias to [CertificateRevocationList::from_der](revocation_list::CertificateRevocationList::from_der). See this function
/// for more information.
#[inline]
pub fn parse_x509_crl(i: &[u8]) -> X509Result<'_, CertificateRevocationList<'_>> {
    CertificateRevocationList::from_der(i)
}

/// Parse a DER-encoded X.509 Certificate, and return the remaining of the input and the built
#[deprecated(
    since = "0.9.0",
    note = "please use `parse_x509_certificate` or `X509Certificate::from_der` instead"
)]
#[inline]
pub fn parse_x509_der(i: &[u8]) -> X509Result<'_, X509Certificate<'_>> {
    X509Certificate::from_der(i)
}

/// Parse a DER-encoded X.509 v2 CRL, and return the remaining of the input and the built
/// object.
#[deprecated(
    since = "0.9.0",
    note = "please use `parse_x509_crl` or `CertificateRevocationList::from_der` instead"
)]
#[inline]
pub fn parse_crl_der(i: &[u8]) -> X509Result<'_, CertificateRevocationList<'_>> {
    CertificateRevocationList::from_der(i)
}
