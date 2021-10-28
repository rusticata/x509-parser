use crate::error::*;
use crate::traits::FromDer;
use der_parser::{
    der::{parse_der_integer, parse_der_sequence_defined_g},
    error::BerResult,
};

#[derive(Debug, PartialEq)]
pub enum PublicKey<'a> {
    RSA(RSAPublicKey<'a>),

    Unknown(&'a [u8]),
}

/// RSA public Key, defined in rfc3279
#[derive(Debug, PartialEq)]
pub struct RSAPublicKey<'a> {
    /// Raw bytes of the modulus
    ///
    /// This possibly includes a leading 0 if the MSB is 1
    pub modulus: &'a [u8],
    /// Raw bytes of the exponent
    ///
    /// This possibly includes a leading 0 if the MSB is 1
    pub exponent: &'a [u8],
}

impl<'a> RSAPublicKey<'a> {
    /// Attempt to convert exponent to u64
    ///
    /// Returns an error if integer is too large, empty, or negative
    pub fn try_exponent(&self) -> Result<u64, X509Error> {
        let mut buf = [0u8; 8];
        if self.exponent.is_empty() || self.exponent[0] & 0x80 != 0 {
            return Err(X509Error::InvalidNumber);
        }
        buf[8_usize.saturating_sub(self.exponent.len())..].copy_from_slice(self.exponent);
        let int = <u64>::from_be_bytes(buf);
        Ok(int)
    }
}

// helper function to parse with error type BerError
fn parse_rsa_key(bytes: &[u8]) -> BerResult<RSAPublicKey> {
    parse_der_sequence_defined_g(move |i, _| {
        let (i, obj_modulus) = parse_der_integer(i)?;
        let (i, obj_exponent) = parse_der_integer(i)?;
        let modulus = obj_modulus.as_slice()?;
        let exponent = obj_exponent.as_slice()?;
        let key = RSAPublicKey { modulus, exponent };
        Ok((i, key))
    })(bytes)
}

impl<'a> FromDer<'a> for RSAPublicKey<'a> {
    fn from_der(bytes: &'a [u8]) -> X509Result<'a, Self> {
        parse_rsa_key(bytes).map_err(|_| nom::Err::Error(X509Error::InvalidSPKI))
    }
}
