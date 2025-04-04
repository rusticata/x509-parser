use crate::error::{X509Error, X509Result};
use asn1_rs::{bitvec::field::BitField, oid, BitString, Error, FromDer, Oid};
use nom::{Err, IResult};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyUsage {
    pub flags: u16,
}

impl KeyUsage {
    pub fn digital_signature(&self) -> bool {
        self.flags & 1 == 1
    }
    pub fn non_repudiation(&self) -> bool {
        (self.flags >> 1) & 1u16 == 1
    }
    pub fn key_encipherment(&self) -> bool {
        (self.flags >> 2) & 1u16 == 1
    }
    pub fn data_encipherment(&self) -> bool {
        (self.flags >> 3) & 1u16 == 1
    }
    pub fn key_agreement(&self) -> bool {
        (self.flags >> 4) & 1u16 == 1
    }
    pub fn key_cert_sign(&self) -> bool {
        (self.flags >> 5) & 1u16 == 1
    }
    pub fn crl_sign(&self) -> bool {
        (self.flags >> 6) & 1u16 == 1
    }
    pub fn encipher_only(&self) -> bool {
        (self.flags >> 7) & 1u16 == 1
    }
    pub fn decipher_only(&self) -> bool {
        (self.flags >> 8) & 1u16 == 1
    }
}

// This list must have the same order as KeyUsage flags declaration (4.2.1.3)
const KEY_USAGE_FLAGS: &[&str] = &[
    "Digital Signature",
    "Non Repudiation",
    "Key Encipherment",
    "Data Encipherment",
    "Key Agreement",
    "Key Cert Sign",
    "CRL Sign",
    "Encipher Only",
    "Decipher Only",
];

impl fmt::Display for KeyUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = KEY_USAGE_FLAGS
            .iter()
            .enumerate()
            .fold(String::new(), |acc, (idx, s)| {
                if (self.flags >> idx) & 1 != 0 {
                    acc + s + ", "
                } else {
                    acc
                }
            });
        s.pop();
        s.pop();
        f.write_str(&s)
    }
}

impl<'a> FromDer<'a, X509Error> for KeyUsage {
    fn from_der(i: &'a [u8]) -> X509Result<'a, Self> {
        parse_keyusage(i).map_err(Err::convert)
    }
}

pub(crate) fn parse_keyusage(i: &[u8]) -> IResult<&[u8], KeyUsage, Error> {
    let (rest, mut obj) = BitString::from_der(i)?;
    let bits = obj.as_mut_bitslice();
    if bits.len() > 16 {
        return Err(Err::Error(Error::BerValueError));
    }
    bits.reverse();
    let flags = bits.load::<u16>();
    Ok((rest, KeyUsage { flags }))
}
