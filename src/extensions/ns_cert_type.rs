use core::fmt;

use asn1_rs::{bitvec::field::BitField, BitString, DerParser, Tag, Tagged};
use nom::Err;

use crate::error::X509Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NSCertType(u8);

// The value is a bit-string, where the individual bit positions are defined as:
//
//     bit-0 SSL client - this cert is certified for SSL client authentication use
//     bit-1 SSL server - this cert is certified for SSL server authentication use
//     bit-2 S/MIME - this cert is certified for use by clients (New in PR3)
//     bit-3 Object Signing - this cert is certified for signing objects such as Java applets and plugins(New in PR3)
//     bit-4 Reserved - this bit is reserved for future use
//     bit-5 SSL CA - this cert is certified for issuing certs for SSL use
//     bit-6 S/MIME CA - this cert is certified for issuing certs for S/MIME use (New in PR3)
//     bit-7 Object Signing CA - this cert is certified for issuing certs for Object Signing (New in PR3)
impl NSCertType {
    pub fn ssl_client(&self) -> bool {
        self.0 & 0x1 == 1
    }
    pub fn ssl_server(&self) -> bool {
        (self.0 >> 1) & 1 == 1
    }
    pub fn smime(&self) -> bool {
        (self.0 >> 2) & 1 == 1
    }
    pub fn object_signing(&self) -> bool {
        (self.0 >> 3) & 1 == 1
    }
    pub fn ssl_ca(&self) -> bool {
        (self.0 >> 5) & 1 == 1
    }
    pub fn smime_ca(&self) -> bool {
        (self.0 >> 6) & 1 == 1
    }
    pub fn object_signing_ca(&self) -> bool {
        (self.0 >> 7) & 1 == 1
    }
}

const NS_CERT_TYPE_FLAGS: &[&str] = &[
    "SSL CLient",
    "SSL Server",
    "S/MIME",
    "Object Signing",
    "Reserved",
    "SSL CA",
    "S/MIME CA",
    "Object Signing CA",
];

impl fmt::Display for NSCertType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        let mut acc = self.0;
        for flag_text in NS_CERT_TYPE_FLAGS {
            if acc & 1 != 0 {
                s = s + flag_text + ", ";
            }
            acc >>= 1;
        }
        s.pop();
        s.pop();
        f.write_str(&s)
    }
}

impl Tagged for NSCertType {
    const TAG: Tag = Tag::BitString;
}

impl<'i> DerParser<'i> for NSCertType {
    type Error = X509Error;

    fn from_der_content(
        header: &'_ asn1_rs::Header<'i>,
        input: asn1_rs::Input<'i>,
    ) -> nom::IResult<asn1_rs::Input<'i>, Self, Self::Error> {
        let (rem, mut obj) = BitString::from_der_content(header, input).map_err(Err::convert)?;
        let bitslice = obj.as_mut_bitslice();
        if bitslice.len() > 8 {
            return Err(Err::Error(X509Error::InvalidAttributes));
        }
        if bitslice.is_empty() {
            return Ok((rem, Self(0)));
        }
        bitslice.reverse();
        let flags = bitslice.load::<u8>();
        Ok((rem, Self(flags)))
    }
}
