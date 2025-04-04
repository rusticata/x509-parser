use core::fmt;

use asn1_rs::bitvec::field::BitField;
use asn1_rs::{Alias, BitString, Choice, DerParser, Sequence, Tag, Tagged};
use nom::Err;

use crate::error::X509Error;
use crate::x509::RelativeDistinguishedName;

use super::GeneralName;

/// <pre>
/// -- IMPLICIT tags
/// DistributionPointName ::= CHOICE {
///     fullName                [0]     GeneralNames,
///     nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
/// </pre>
#[derive(Clone, Debug, PartialEq, Choice)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
#[tagged_implicit]
pub enum DistributionPointName<'a> {
    FullName(Vec<GeneralName<'a>>),
    NameRelativeToCRLIssuer(RelativeDistinguishedName<'a>),
}

/// <pre>
/// ReasonFlags ::= BIT STRING {
/// unused                  (0),
/// keyCompromise           (1),
/// cACompromise            (2),
/// affiliationChanged      (3),
/// superseded              (4),
/// cessationOfOperation    (5),
/// certificateHold         (6),
/// privilegeWithdrawn      (7),
/// aACompromise            (8) }
/// </pre>
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReasonFlags {
    pub flags: u16,
}

impl ReasonFlags {
    pub fn key_compromise(&self) -> bool {
        (self.flags >> 1) & 1 == 1
    }
    pub fn ca_compromise(&self) -> bool {
        (self.flags >> 2) & 1 == 1
    }
    pub fn affilation_changed(&self) -> bool {
        (self.flags >> 3) & 1 == 1
    }
    pub fn superseded(&self) -> bool {
        (self.flags >> 4) & 1 == 1
    }
    pub fn cessation_of_operation(&self) -> bool {
        (self.flags >> 5) & 1 == 1
    }
    pub fn certificate_hold(&self) -> bool {
        (self.flags >> 6) & 1 == 1
    }
    pub fn privelege_withdrawn(&self) -> bool {
        (self.flags >> 7) & 1 == 1
    }
    pub fn aa_compromise(&self) -> bool {
        (self.flags >> 8) & 1 == 1
    }
}

const REASON_FLAGS: &[&str] = &[
    "Unused",
    "Key Compromise",
    "CA Compromise",
    "Affiliation Changed",
    "Superseded",
    "Cessation Of Operation",
    "Certificate Hold",
    "Privilege Withdrawn",
    "AA Compromise",
];

impl fmt::Display for ReasonFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        let mut acc = self.flags;
        for flag_text in REASON_FLAGS {
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

impl Tagged for ReasonFlags {
    const TAG: Tag = Tag::BitString;
}

impl<'i> DerParser<'i> for ReasonFlags {
    type Error = X509Error;

    fn from_der_content(
        header: &'_ asn1_rs::Header<'i>,
        input: asn1_rs::Input<'i>,
    ) -> nom::IResult<asn1_rs::Input<'i>, Self, Self::Error> {
        let (rem, mut obj) = BitString::from_der_content(header, input).map_err(Err::convert)?;
        let bitslice = obj.as_mut_bitslice();
        if bitslice.len() > 9 {
            return Err(Err::Error(X509Error::InvalidAttributes));
        }
        bitslice.reverse();
        let flags = bitslice.load::<u16>();
        Ok((rem, Self { flags }))
    }
}

/// <pre>
/// -- IMPLICIT tags
/// DistributionPoint ::= SEQUENCE {
///     distributionPoint       [0]     DistributionPointName OPTIONAL,
///     reasons                 [1]     ReasonFlags OPTIONAL,
///     cRLIssuer               [2]     GeneralNames OPTIONAL }
/// </pre>
#[derive(Clone, Debug, PartialEq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct CRLDistributionPoint<'a> {
    #[tag_implicit(0)]
    #[optional]
    pub distribution_point: Option<DistributionPointName<'a>>,
    #[tag_implicit(1)]
    #[optional]
    pub reasons: Option<ReasonFlags>,
    #[tag_implicit(2)]
    #[optional]
    pub crl_issuer: Option<Vec<GeneralName<'a>>>,
}

/// <pre>
/// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
/// </pre>
#[derive(Clone, Debug, PartialEq, Alias)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct CRLDistributionPoints<'a>(pub Vec<CRLDistributionPoint<'a>>);

impl<'a> std::ops::Deref for CRLDistributionPoints<'a> {
    type Target = Vec<CRLDistributionPoint<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
