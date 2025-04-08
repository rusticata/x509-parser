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
    pub fn affiliation_changed(&self) -> bool {
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
    pub fn privilege_withdrawn(&self) -> bool {
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
        let flags = bitslice.load_be::<u16>();
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
///
/// Note: this object has implicit tags, however ASN.1 specifications (X.680) contain the following note:
///
/// <pre>
/// The tagging construction specifies explicit tagging if any of the following holds:
///
/// c) the "Tag Type" alternative is used and the value of "TagDefault" for the module is
/// IMPLICIT TAGS or AUTOMATIC TAGS, but the type defined by "Type" is an untagged choice type,
/// an untagged open type, or an untagged "DummyReference"
/// (see Rec. ITU-T X.683 | ISO/IEC 8824-4, 8.3).
/// </pre>
///
/// Thus, the fields using tags (like `DistributionPointName`) use *explicit* tags here.
#[derive(Clone, Debug, PartialEq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
// #[debug_derive]
pub struct CRLDistributionPoint<'a> {
    #[tag_explicit(0)]
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

#[cfg(test)]
mod tests {
    use asn1_rs::{DerParser, Input};
    use hex_literal::hex;

    use crate::prelude::CRLDistributionPoint;

    use super::{CRLDistributionPoints, DistributionPointName};

    #[test]
    fn parse_crl_distribution_points() {
        let bytes = &hex!(
            "30 23 30 21
             A0 1F A0 1D 86 1B 68 74  74 70 3A 2F 2F 65 78 61
             6D 70 6C 65 2E 63 6F 6D  2F 6D 79 63 61 2E 63 72
             6C"
        );

        let (rem, crl_distribution_points) =
            CRLDistributionPoints::parse_der(Input::from(bytes)).expect("Parsing failed");
        assert!(rem.is_empty());
        assert_eq!(crl_distribution_points.0.len(), 1);
    }

    #[test]
    fn parse_distribution_point() {
        let bytes: &[u8; 35] = &hex!(
            "30 21
             A0 1F A0 1D 86 1B 68 74  74 70 3A 2F 2F 65 78 61
             6D 70 6C 65 2E 63 6F 6D  2F 6D 79 63 61 2E 63 72
             6C"
        );

        let (rem, obj) =
            CRLDistributionPoint::parse_der(Input::from(bytes)).expect("Parsing failed");
        assert!(rem.is_empty());
        assert!(obj.distribution_point.is_some());
    }

    #[test]
    fn parse_distribution_point_name() {
        let bytes = &hex!(
            "A0 1D 86 1B 68 74  74 70 3A 2F 2F 65 78 61
             6D 70 6C 65 2E 63 6F 6D  2F 6D 79 63 61 2E 63 72
             6C"
        );

        let (rem, obj) =
            DistributionPointName::parse_der(Input::from(bytes)).expect("Parsing failed");
        assert!(rem.is_empty());
        assert!(matches!(obj, DistributionPointName::FullName(_)));
    }
}
