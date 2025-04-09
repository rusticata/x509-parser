use crate::error::X509Error;
use asn1_rs::{bitvec::field::BitField, BitString, DerParser, Header, Input, Tag, Tagged};
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

impl Tagged for KeyUsage {
    const TAG: Tag = Tag::BitString;
}

impl<'i> DerParser<'i> for KeyUsage {
    type Error = X509Error;

    fn from_der_content(
        header: &'_ Header<'i>,
        input: Input<'i>,
    ) -> IResult<Input<'i>, Self, Self::Error> {
        let (rem, mut obj) = BitString::from_der_content(header, input).map_err(Err::convert)?;
        let bitslice = obj.as_mut_bitslice();
        if bitslice.len() > 16 {
            return Err(Err::Error(X509Error::InvalidAttributes));
        }
        if bitslice.is_empty() {
            return Ok((rem, Self { flags: 0 }));
        }
        bitslice.reverse();
        let flags = bitslice.load_be::<u16>();
        Ok((rem, Self { flags }))
    }
}
