//! X.509 errors

use der_parser::DerError;

/// An error that can occur while converting an OID to a Nid.
#[derive(Debug,PartialEq)]
pub struct NidError;

/// An error that can occur while parsing or validating a certificate.
#[derive(Debug,PartialEq)]
pub enum X509Error {
    Generic,

    InvalidVersion,
    InvalidSerial,
    InvalidAlgorithmIdentifier,
    InvalidX509Name,
    InvalidDate,
    InvalidExtensions,
    InvalidTbsCertificate,

    /// Top-level certificate structure is invalid
    InvalidCertificate,

    Der(DerError),
}

impl From<DerError> for X509Error {
    fn from(e: DerError) -> X509Error { X509Error::Der(e) }
}




