//! X.509 errors

use der_parser::error::BerError;
use nom::error::{ErrorKind, ParseError};
use std;

/// An error that can occur while converting an OID to a Nid.
#[derive(Debug, PartialEq)]
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
    NomError(ErrorKind),
}

impl From<BerError> for X509Error {
    fn from(e: BerError) -> X509Error {
        X509Error::Der(e)
    }
}

impl From<ErrorKind> for X509Error {
    fn from(e: ErrorKind) -> X509Error {
        X509Error::NomError(e)
    }
}

impl<I> ParseError<I> for X509Error {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        X509Error::NomError(kind)
    }
    fn append(_input: I, kind: ErrorKind, _other: Self) -> Self {
        X509Error::NomError(kind)
    }
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
    fn from(e: std::io::Error) -> PEMError {
        PEMError::IOError(e)
    }
}
