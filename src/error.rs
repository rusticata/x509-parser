//! X.509 errors

use der_parser::error::BerError;
use std;

/// An error that can occur while converting an OID to a Nid.
#[derive(Debug,PartialEq)]
pub struct NidError;

/// An error that can occur while parsing or validating a certificate.
#[derive(Debug)]
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

    Der(BerError),
}

impl From<BerError> for X509Error {
    fn from(e: BerError) -> X509Error { X509Error::Der(e) }
}

/// An error that can occur while parsing or validating a certificate.
#[derive(Debug)]
pub enum PEMError {
    Base64DecodeError,
    IncompletePEM,
    InvalidHeader,
    MissingHeader,

    IOError(std::io::Error),
}

impl From<std::io::Error> for PEMError {
    fn from(e: std::io::Error) -> PEMError { PEMError::IOError(e) }
}
