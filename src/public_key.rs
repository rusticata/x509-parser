use crate::error::*;
use asn1_rs::{DerParser, FromDer, InnerError, Input, Integer};
use nom::{Err, IResult};

/// Public Key value
#[derive(Debug, PartialEq, Eq)]
pub enum PublicKey<'a> {
    RSA(RSAPublicKey<'a>),
    EC(ECPoint<'a>),
    /// DSAPublicKey ::= INTEGER -- public key, Y (RFC 3279)
    DSA(&'a [u8]),
    /// GostR3410-94-PublicKey ::= OCTET STRING -- public key, Y (RFC 4491)
    GostR3410(&'a [u8]),
    /// GostR3410-2012-256-PublicKey ::= OCTET STRING (64),
    /// GostR3410-2012-512-PublicKey ::= OCTET STRING (128). (RFC 4491-bis)
    GostR3410_2012(&'a [u8]),

    Unknown(&'a [u8]),
}

impl PublicKey<'_> {
    /// Return the key size (in bits) or 0
    pub fn key_size(&self) -> usize {
        match self {
            Self::EC(ec) => ec.key_size(),
            Self::RSA(rsa) => rsa.key_size(),
            Self::DSA(y) | Self::GostR3410(y) => y.len() * 8,
            _ => 0,
        }
    }
}

/// RSA public Key, defined in rfc3279
#[derive(Debug, PartialEq, Eq)]
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

impl RSAPublicKey<'_> {
    /// Attempt to convert exponent to u64
    ///
    /// Returns an error if integer is too large, empty, or negative
    pub fn try_exponent(&self) -> Result<u64, X509Error> {
        let mut buf = [0u8; 8];
        if self.exponent.is_empty() || self.exponent[0] & 0x80 != 0 || self.exponent.len() > 8 {
            return Err(X509Error::InvalidNumber);
        }
        buf[8_usize.saturating_sub(self.exponent.len())..].copy_from_slice(self.exponent);
        let int = <u64>::from_be_bytes(buf);
        Ok(int)
    }

    /// Return the key size (in bits) or 0
    pub fn key_size(&self) -> usize {
        if !self.modulus.is_empty() && self.modulus[0] & 0x80 == 0 {
            // XXX len must substract leading zeroes
            let modulus = &self.modulus[1..];
            8 * modulus.len()
        } else {
            0
        }
    }
}

fn parse_rsa_key(bytes: &[u8]) -> IResult<&[u8], RSAPublicKey, X509Error> {
    let input = Input::from(bytes);
    let (rem, (o1, o2)) = <(Integer, Integer)>::parse_der(input).map_err(Err::convert)?;
    let modulus = o1
        .as_raw_slice()
        .ok_or(Err::Error(InnerError::LifetimeError.into()))?;
    let exponent = o2
        .as_raw_slice()
        .ok_or(Err::Error(InnerError::LifetimeError.into()))?;
    let key = RSAPublicKey { modulus, exponent };
    Ok((rem.as_bytes2(), key))
}

impl<'a> FromDer<'a, X509Error> for RSAPublicKey<'a> {
    fn from_der(bytes: &'a [u8]) -> X509Result<'a, Self> {
        parse_rsa_key(bytes).map_err(|_| Err::Error(X509Error::InvalidSPKI))
    }
}

/// Elliptic Curve point, as defined in [RFC5480](https://datatracker.ietf.org/doc/html/rfc5480)
#[derive(Debug, PartialEq, Eq)]
pub struct ECPoint<'a> {
    data: &'a [u8],
}

impl<'a> ECPoint<'a> {
    /// EC Point content (See Standards for Efficient Cryptography Group (SECG), "SEC1: Elliptic Curve Cryptography")
    pub fn data(&'a self) -> &'a [u8] {
        self.data
    }

    /// Return the key size (in bits) or 0
    pub fn key_size(&self) -> usize {
        match self.data {
            [] => {
                // empty
                0
            }
            [4, rem @ ..] => {
                // uncompressed
                rem.len() * 8 / 2
            }
            [2..=3, rem @ ..] => {
                // compressed
                rem.len() * 8
            }
            _ => {
                // invalid
                0
            }
        }
    }
}

impl<'a> From<&'a [u8]> for ECPoint<'a> {
    fn from(data: &'a [u8]) -> Self {
        ECPoint { data }
    }
}
