//! X.509 errors

use der_parser::error::BerError;
use nom::error::{ErrorKind, ParseError};

/// An error that can occur while converting an OID to a Nid.
#[derive(Debug, PartialEq)]
pub struct NidError;

/// An error that can occur while parsing or validating a certificate.
#[derive(Debug, PartialEq, thiserror::Error)]
pub enum X509Error {
    #[error("invalid X.509 name")]
    InvalidX509Name,
    #[error("invalid date")]
    InvalidDate,

    #[error("signature verification error")]
    SignatureVerificationError,
    #[error("signature unsupported algorithm")]
    SignatureUnsupportedAlgorithm,

    #[error("BER error: {0}")]
    Der(#[from] BerError),
    #[error("nom error: {0:?}")]
    NomError(ErrorKind),
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
#[derive(Debug, thiserror::Error)]
pub enum PEMError {
    #[error("base64 decode error")]
    Base64DecodeError,
    #[error("incomplete PEM")]
    IncompletePEM,
    #[error("invalid header")]
    InvalidHeader,
    #[error("missing header")]
    MissingHeader,

    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
}
