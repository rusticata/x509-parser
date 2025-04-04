//! X.509 objects and types
//!
//! Based on RFC5280
//!

use crate::error::{X509Error, X509Result};
use crate::objects::*;
use crate::parser_utils::get_span;
use crate::public_key::*;

use asn1_rs::num_bigint::BigUint;
use asn1_rs::{
    Alias, Any, AnyIterator, BerError, BitString, BmpString, DerMode, DerParser,
    FromDer, Header, Input, Integer, OptTaggedExplicit, OptTaggedParser, Sequence, Tag,
    Tagged,
};
use core::convert::TryFrom;
use data_encoding::HEXUPPER;
use nom::combinator::map;
use nom::{Err, IResult, Parser as _};
use oid_registry::*;
use rusticata_macros::newtype_enum;
use std::fmt;
use std::iter::FromIterator;
use std::ops::Range;

/// The version of the encoded certificate.
///
/// When extensions are used, as expected in this profile, version MUST be 3
/// (value is `2`).  If no extensions are present, but a UniqueIdentifier
/// is present, the version SHOULD be 2 (value is `1`); however, the
/// version MAY be 3.  If only basic fields are present, the version
/// SHOULD be 1 (the value is omitted from the certificate as the default
/// value); however, the version MAY be 2 or 3.
///
/// <pre>
/// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
/// </pre>
#[derive(Debug, PartialEq, Eq, Clone, Copy, Alias)]
#[asn1(parse = "DER", encode = "")]
pub struct X509Version(pub u32);

impl X509Version {
    /// Parse `[0]` EXPLICIT Version DEFAULT v1
    pub(crate) fn from_der_tagged_0(i: &[u8]) -> X509Result<X509Version> {
        let (rem, opt_version) = OptTaggedParser::from(0)
            .parse_der(i, |_, data| Self::from_der(data))
            .map_err(Err::convert)?;
        let version = opt_version.unwrap_or(X509Version::V1);
        Ok((rem, version))
    }

    /// Parse `[0]` EXPLICIT Version DEFAULT v1
    pub(crate) fn parse_der_tagged_0<'a>(
        input: Input<'a>,
    ) -> IResult<Input<'a>, X509Version, X509Error> {
        type T<'a> = OptTaggedExplicit<X509Version, BerError<Input<'a>>, 0>;
        let (rem, opt_version) = <T>::parse_der(input).map_err(Err::convert)?;
        let version = opt_version
            .map(|t| t.into_inner())
            .unwrap_or(X509Version::V1);
        Ok((rem, version))
    }
}

// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
impl<'a> FromDer<'a, X509Error> for X509Version {
    fn from_der(i: &'a [u8]) -> X509Result<'a, Self> {
        map(<u32>::from_der, X509Version)
            .parse(i)
            .map_err(|_| Err::Error(X509Error::InvalidVersion))
    }
}

newtype_enum! {
    impl display X509Version {
        V1 = 0,
        V2 = 1,
        V3 = 2,
    }
}

/// A generic attribute type and value
///
/// These objects are used as [`RelativeDistinguishedName`] components.
/// <pre>
/// AttributeTypeAndValue   ::= SEQUENCE {
///     type    AttributeType,
///     value   AttributeValue }
/// </pre>
#[derive(Clone, Debug, PartialEq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct AttributeTypeAndValue<'a> {
    attr_type: Oid<'a>,
    attr_value: Any<'a>, // ANY -- DEFINED BY AttributeType
}

impl<'a> AttributeTypeAndValue<'a> {
    /// Builds a new `AttributeTypeAndValue`
    #[inline]
    pub const fn new(attr_type: Oid<'a>, attr_value: Any<'a>) -> Self {
        AttributeTypeAndValue {
            attr_type,
            attr_value,
        }
    }

    /// Returns the attribute type
    #[inline]
    pub const fn attr_type(&self) -> &Oid<'a> {
        &self.attr_type
    }

    /// Returns the attribute value, as `ANY`
    #[inline]
    pub const fn attr_value(&self) -> &Any<'a> {
        &self.attr_value
    }

    /// Attempt to get the content as `str`.
    /// This can fail if the object does not contain a string type.
    ///
    /// Note: the [`TryFrom`] trait is implemented for `&str`, so this is
    /// equivalent to `attr.try_into()`.
    ///
    /// Only NumericString, PrintableString, UTF8String and IA5String
    /// are considered here. Other string types can be read using `as_slice`.
    #[inline]
    pub fn as_str(&'a self) -> Result<&'a str, X509Error> {
        self.attr_value
            .as_any_str()
            .map_err(|_| X509Error::InvalidAttributes)
    }

    /// Get the content as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        self.attr_value.as_bytes()
    }
}

impl<'a, 'b> TryFrom<&'a AttributeTypeAndValue<'b>> for &'a str {
    type Error = X509Error;

    fn try_from(value: &'a AttributeTypeAndValue<'b>) -> Result<Self, Self::Error> {
        value.attr_value.as_str().map_err(|e| e.into())
    }
}

impl<'a, 'b> From<&'a AttributeTypeAndValue<'b>> for &'a [u8] {
    fn from(value: &'a AttributeTypeAndValue<'b>) -> Self {
        value.as_slice()
    }
}

/// A Relative Distinguished Name element.
///
/// These objects are used as [`X509Name`] components.
/// <pre>
/// RelativeDistinguishedName ::=
///     SET SIZE (1..MAX) OF AttributeTypeAndValue
/// </pre>
#[derive(Clone, Debug, PartialEq)]
pub struct RelativeDistinguishedName<'a> {
    set: Vec<AttributeTypeAndValue<'a>>,
}

impl<'a> RelativeDistinguishedName<'a> {
    /// Builds a new `RelativeDistinguishedName`
    #[inline]
    pub const fn new(set: Vec<AttributeTypeAndValue<'a>>) -> Self {
        RelativeDistinguishedName { set }
    }

    /// Return an iterator over the components of this object
    pub fn iter(&self) -> impl Iterator<Item = &AttributeTypeAndValue<'a>> {
        self.set.iter()
    }
}

impl<'a> FromIterator<AttributeTypeAndValue<'a>> for RelativeDistinguishedName<'a> {
    fn from_iter<T: IntoIterator<Item = AttributeTypeAndValue<'a>>>(iter: T) -> Self {
        let set = iter.into_iter().collect();
        RelativeDistinguishedName { set }
    }
}

impl Tagged for RelativeDistinguishedName<'_> {
    const CONSTRUCTED: bool = true;

    const TAG: Tag = Tag::Sequence;
}

impl<'a> DerParser<'a> for RelativeDistinguishedName<'a> {
    type Error = X509Error;

    fn from_der_content(
        _header: &'_ Header<'a>,
        input: Input<'a>,
    ) -> IResult<Input<'a>, Self, Self::Error> {
        let (rem, set) = AnyIterator::<DerMode>::new(input).try_parse_collect()?;
        Ok((rem, RelativeDistinguishedName { set }))
    }
}

#[derive(Clone, Debug, PartialEq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    /// A raw unparsed PKIX, ASN.1 DER form (see RFC 5280, Section 4.1).
    ///
    /// Note: use the [`Self::parsed()`] function to parse this object.
    pub subject_public_key: BitString,

    #[asn1(parse = "|input| get_span(header, input).map_err(Err::convert)")]
    pub(crate) range: Range<usize>,
}

impl SubjectPublicKeyInfo<'_> {
    /// Attempt to parse the public key, and return the parsed version or an error
    pub fn parsed(&self) -> Result<PublicKey, X509Error> {
        let b = self.subject_public_key.as_raw_slice();
        if self.algorithm.algorithm == OID_PKCS1_RSAENCRYPTION {
            let (_, key) = RSAPublicKey::from_der(b).map_err(|_| X509Error::InvalidSPKI)?;
            Ok(PublicKey::RSA(key))
        } else if self.algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY {
            let key = ECPoint::from(b.as_ref());
            Ok(PublicKey::EC(key))
        } else if self.algorithm.algorithm == OID_KEY_TYPE_DSA {
            let s = Integer::from_der(b)
                .map(|(_rem, i)| i.as_raw_slice())
                .map_err(|_| Err::Error(X509Error::InvalidSPKI))?
                // note: this `ok_or` cannot fail, as_raw_slice after parsing always succeeds
                .ok_or(Err::Error(X509Error::InvalidSPKI))?;
            Ok(PublicKey::DSA(s))
        } else if self.algorithm.algorithm == OID_GOST_R3410_2001 {
            let (_, s) = <&[u8]>::from_der(b).or(Err(X509Error::InvalidSPKI))?;
            Ok(PublicKey::GostR3410(s))
        } else if self.algorithm.algorithm == OID_KEY_TYPE_GOST_R3410_2012_256
            || self.algorithm.algorithm == OID_KEY_TYPE_GOST_R3410_2012_512
        {
            let (_, s) = <&[u8]>::from_der(b).or(Err(X509Error::InvalidSPKI))?;
            Ok(PublicKey::GostR3410_2012(s))
        } else {
            Ok(PublicKey::Unknown(b))
        }
    }
}

/// Algorithm identifier
///
/// An algorithm identifier is defined by the following ASN.1 structure:
///
/// <pre>
/// AlgorithmIdentifier  ::=  SEQUENCE  {
///      algorithm               OBJECT IDENTIFIER,
///      parameters              ANY DEFINED BY algorithm OPTIONAL  }
/// </pre>
///
/// The algorithm identifier is used to identify a cryptographic
/// algorithm.  The OBJECT IDENTIFIER component identifies the algorithm
/// (such as DSA with SHA-1).  The contents of the optional parameters
/// field will vary according to the algorithm identified.
#[derive(Clone, Debug, PartialEq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct AlgorithmIdentifier<'a> {
    #[map_err(|_| X509Error::InvalidAlgorithmIdentifier)]
    pub algorithm: Oid<'a>,
    #[optional]
    pub parameters: Option<Any<'a>>,
}

pub const SHA1_IDENTIFIER: AlgorithmIdentifier = AlgorithmIdentifier {
    algorithm: OID_HASH_SHA1,
    parameters: None,
};

impl<'a> AlgorithmIdentifier<'a> {
    /// Create a new `AlgorithmIdentifier`
    pub const fn new(algorithm: Oid<'a>, parameters: Option<Any<'a>>) -> Self {
        Self {
            algorithm,
            parameters,
        }
    }

    /// Get the algorithm OID
    pub const fn oid(&'a self) -> &'a Oid<'a> {
        &self.algorithm
    }

    /// Get a reference to the algorithm parameters, if present
    pub const fn parameters(&'a self) -> Option<&'a Any<'a>> {
        self.parameters.as_ref()
    }
}

/// X.509 Name (as used in `Issuer` and `Subject` fields)
///
/// The Name describes a hierarchical name composed of attributes, such
/// as country name, and corresponding values, such as US.  The type of
/// the component AttributeValue is determined by the AttributeType; in
/// general it will be a DirectoryString.
///
/// <pre>
/// Name ::= CHOICE { -- only one possibility for now --
///     rdnSequence  RDNSequence }
///
/// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
/// </pre>
#[derive(Clone, Debug, PartialEq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct X509Name<'a> {
    pub(crate) rdn_seq: Vec<RelativeDistinguishedName<'a>>,

    #[asn1(parse = "|input| get_span(header, input).map_err(Err::convert)")]
    pub(crate) range: Range<usize>,
}

impl fmt::Display for X509Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match x509name_to_string(&self.rdn_seq, oid_registry()) {
            Ok(o) => write!(f, "{}", o),
            Err(_) => write!(f, "<X509Error: Invalid X.509 name>"),
        }
    }
}

impl<'a> X509Name<'a> {
    /// Builds a new `X509Name` from the provided elements.
    #[inline]
    pub const fn new(rdn_seq: Vec<RelativeDistinguishedName<'a>>, range: Range<usize>) -> Self {
        X509Name { rdn_seq, range }
    }

    /// Attempt to format the current name, using the given registry to convert OIDs to strings.
    ///
    /// Note: a default registry is provided with this crate, and is returned by the
    /// [`oid_registry()`] method.
    pub fn to_string_with_registry(&self, oid_registry: &OidRegistry) -> Result<String, X509Error> {
        x509name_to_string(&self.rdn_seq, oid_registry)
    }

    // Return the parsed data span (start and end offset of bytes)
    pub fn range(&self) -> Range<usize> {
        self.range.clone()
    }

    /// Return an iterator over the `RelativeDistinguishedName` components of the name
    pub fn iter(&self) -> impl Iterator<Item = &RelativeDistinguishedName<'a>> {
        self.rdn_seq.iter()
    }

    /// Return an iterator over the `RelativeDistinguishedName` components of the name
    pub fn iter_rdn(&self) -> impl Iterator<Item = &RelativeDistinguishedName<'a>> {
        self.rdn_seq.iter()
    }

    /// Return an iterator over the attribute types and values of the name
    pub fn iter_attributes(&self) -> impl Iterator<Item = &AttributeTypeAndValue<'a>> {
        self.rdn_seq.iter().flat_map(|rdn| rdn.set.iter())
    }

    /// Return an iterator over the components identified by the given OID
    ///
    /// The type of the component AttributeValue is determined by the AttributeType; in
    /// general it will be a DirectoryString.
    ///
    /// Attributes with same OID may be present multiple times, so the returned object is
    /// an iterator.
    /// Expected number of objects in this iterator are
    ///   - 0: not found
    ///   - 1: present once (common case)
    ///   - 2 or more: attribute is present multiple times
    pub fn iter_by_oid(&self, oid: &Oid<'a>) -> impl Iterator<Item = &AttributeTypeAndValue<'a>> {
        // this is necessary, otherwise rustc complains
        // that caller creates a temporary value for reference (for ex.
        // `self.iter_by_oid(&OID_X509_LOCALITY_NAME)`
        // )
        let oid = oid.clone();
        self.iter_attributes()
            .filter(move |obj| obj.attr_type == oid)
    }

    /// Return an iterator over the `CommonName` attributes of the X.509 Name.
    ///
    /// Returned iterator can be empty if there are no `CommonName` attributes.
    /// If you expect only one `CommonName` to be present, then using `next()` will
    /// get an `Option<&AttributeTypeAndValue>`.
    ///
    /// A common operation is to extract the `CommonName` as a string.
    ///
    /// ```
    /// use x509_parser::x509::X509Name;
    ///
    /// fn get_first_cn_as_str<'a>(name: &'a X509Name<'_>) -> Option<&'a str> {
    ///     name.iter_common_name()
    ///         .next()
    ///         .and_then(|cn| cn.as_str().ok())
    /// }
    /// ```
    ///
    /// Note that there are multiple reasons for failure or incorrect behavior, for ex. if
    /// the attribute is present multiple times, or is not a UTF-8 encoded string (it can be
    /// UTF-16, or even an OCTETSTRING according to the standard).
    pub fn iter_common_name(&self) -> impl Iterator<Item = &AttributeTypeAndValue<'a>> {
        self.iter_by_oid(&OID_X509_COMMON_NAME)
    }

    /// Return an iterator over the `Country` attributes of the X.509 Name.
    pub fn iter_country(&self) -> impl Iterator<Item = &AttributeTypeAndValue<'a>> {
        self.iter_by_oid(&OID_X509_COUNTRY_NAME)
    }

    /// Return an iterator over the `Organization` attributes of the X.509 Name.
    pub fn iter_organization(&self) -> impl Iterator<Item = &AttributeTypeAndValue<'a>> {
        self.iter_by_oid(&OID_X509_ORGANIZATION_NAME)
    }

    /// Return an iterator over the `OrganizationalUnit` attributes of the X.509 Name.
    pub fn iter_organizational_unit(&self) -> impl Iterator<Item = &AttributeTypeAndValue<'a>> {
        self.iter_by_oid(&OID_X509_ORGANIZATIONAL_UNIT)
    }

    /// Return an iterator over the `StateOrProvinceName` attributes of the X.509 Name.
    pub fn iter_state_or_province(&self) -> impl Iterator<Item = &AttributeTypeAndValue<'a>> {
        self.iter_by_oid(&OID_X509_STATE_OR_PROVINCE_NAME)
    }

    /// Return an iterator over the `Locality` attributes of the X.509 Name.
    pub fn iter_locality(&self) -> impl Iterator<Item = &AttributeTypeAndValue<'a>> {
        self.iter_by_oid(&OID_X509_LOCALITY_NAME)
    }

    /// Return an iterator over the `EmailAddress` attributes of the X.509 Name.
    pub fn iter_email(&self) -> impl Iterator<Item = &AttributeTypeAndValue<'a>> {
        self.iter_by_oid(&OID_PKCS9_EMAIL_ADDRESS)
    }
}

impl<'a> FromIterator<RelativeDistinguishedName<'a>> for X509Name<'a> {
    fn from_iter<T: IntoIterator<Item = RelativeDistinguishedName<'a>>>(iter: T) -> Self {
        let rdn_seq = iter.into_iter().collect();
        X509Name {
            rdn_seq,
            range: Range { start: 0, end: 0 },
        }
    }
}

impl<'a> From<X509Name<'a>> for Vec<RelativeDistinguishedName<'a>> {
    fn from(name: X509Name<'a>) -> Self {
        name.rdn_seq
    }
}

// impl<'a> FromDer<'a, X509Error> for X509Name<'a> {
//     /// Parse the X.501 type Name, used for ex in issuer and subject of a X.509 certificate
//     fn from_der(i: &'a [u8]) -> X509Result<'a, Self> {
//         let start_i = i;
//         parse_der_sequence_defined_g(move |i, _| {
//             let (i, rdn_seq) = many0(complete(RelativeDistinguishedName::from_der)).parse(i)?;
//             let len = start_i.offset(i);
//             let name = X509Name {
//                 rdn_seq,
//                 raw: &start_i[..len],
//             };
//             Ok((i, name))
//         })(i)
//     }
// }

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct ReasonCode(pub u8);

newtype_enum! {
impl display ReasonCode {
    Unspecified = 0,
    KeyCompromise = 1,
    CACompromise = 2,
    AffiliationChanged = 3,
    Superseded = 4,
    CessationOfOperation = 5,
    CertificateHold = 6,
    // value 7 is not used
    RemoveFromCRL = 8,
    PrivilegeWithdrawn = 9,
    AACompromise = 10,
}
}

impl Default for ReasonCode {
    fn default() -> Self {
        ReasonCode::Unspecified
    }
}

// Attempt to convert attribute to string. If type is not a string, return value is the hex
// encoding of the attribute value
fn attribute_value_to_string(attr: &Any, _attr_type: &Oid) -> Result<String, X509Error> {
    // TODO: replace this with helper function, when it is added to asn1-rs
    match attr.tag() {
        Tag::NumericString
        | Tag::VisibleString
        | Tag::PrintableString
        | Tag::GeneralString
        | Tag::ObjectDescriptor
        | Tag::GraphicString
        | Tag::T61String
        | Tag::VideotexString
        | Tag::Utf8String
        | Tag::Ia5String => {
            let s = core::str::from_utf8(attr.data.as_bytes2())
                .map_err(|_| X509Error::InvalidAttributes)?;
            Ok(s.to_owned())
        }
        Tag::BmpString => {
            // TODO: remove this when a new release of asn1-rs removes the need to consume attr in try_from
            let any = attr.clone();
            let s = BmpString::try_from(any).map_err(|_| X509Error::InvalidAttributes)?;
            Ok(s.string())
        }
        _ => {
            // type is not a string, get slice and convert it to base64
            Ok(HEXUPPER.encode(attr.as_bytes()))
        }
    }
}

/// Convert a DER representation of a X.509 name to a human-readable string
///
/// RDNs are separated with ","
/// Multiple RDNs are separated with "+"
///
/// Attributes that cannot be represented by a string are hex-encoded
fn x509name_to_string(
    rdn_seq: &[RelativeDistinguishedName],
    oid_registry: &OidRegistry,
) -> Result<String, X509Error> {
    rdn_seq.iter().try_fold(String::new(), |acc, rdn| {
        rdn.set
            .iter()
            .try_fold(String::new(), |acc2, attr| {
                let val_str = attribute_value_to_string(&attr.attr_value, &attr.attr_type)?;
                // look ABBREV, and if not found, use shortname
                let abbrev = match oid2abbrev(&attr.attr_type, oid_registry) {
                    Ok(s) => String::from(s),
                    _ => format!("{:?}", attr.attr_type),
                };
                let rdn = format!("{}={}", abbrev, val_str);
                match acc2.len() {
                    0 => Ok(rdn),
                    _ => Ok(acc2 + " + " + &rdn),
                }
            })
            .map(|v| match acc.len() {
                0 => v,
                _ => acc + ", " + &v,
            })
    })
}

/// helper function to parse BIT STRING with correct error type
pub(crate) fn parse_signature_value<'a>(
    input: Input<'a>,
) -> IResult<Input<'a>, BitString, X509Error> {
    BitString::parse_der(input).or(Err(Err::Error(X509Error::InvalidSignatureValue)))
}

pub(crate) fn parse_serial<'a>(
    input: Input<'a>,
) -> IResult<Input<'a>, (&'a [u8], BigUint), X509Error> {
    let (rem, any) = Any::parse_der(input).map_err(|_| X509Error::InvalidSerial)?;
    // RFC 5280 4.1.2.2: "The serial number MUST be a positive integer"
    // however, many CAs do not respect this and send integers with MSB set,
    // so we do not use `as_biguint()`
    any.tag()
        .assert_eq(Tag::Integer)
        .map_err(|_| X509Error::InvalidSerial)?;
    let slice = any.data.as_bytes2();
    let big = BigUint::from_bytes_be(slice);
    Ok((rem, (slice, big)))
}

#[cfg(test)]
mod tests {
    use asn1_rs::oid;

    use super::*;

    #[test]
    fn test_x509_version() {
        // correct version
        let data: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x00];
        let r = X509Version::from_der_tagged_0(data);
        assert!(r.is_ok());

        // wrong tag
        let data: &[u8] = &[0xa1, 0x03, 0x02, 0x01, 0x00];
        let r = X509Version::from_der_tagged_0(data);
        assert!(r.is_ok());

        // short read
        let data: &[u8] = &[0xa0, 0x01];
        let r = X509Version::from_der_tagged_0(data);
        assert!(r.is_err());

        // short read with wrong tag
        let data: &[u8] = &[0xa1, 0x01];
        let r = X509Version::from_der_tagged_0(data);
        assert!(r.is_err());
    }

    #[test]
    fn test_x509_name() {
        let name = X509Name {
            rdn_seq: vec![
                RelativeDistinguishedName {
                    set: vec![AttributeTypeAndValue {
                        attr_type: oid! {2.5.4.6}, // countryName
                        attr_value: Any::from_tag_and_data(Tag::PrintableString, b"FR".into()),
                    }],
                },
                RelativeDistinguishedName {
                    set: vec![AttributeTypeAndValue {
                        attr_type: oid! {2.5.4.8}, // stateOrProvinceName
                        attr_value: Any::from_tag_and_data(
                            Tag::PrintableString,
                            b"Some-State".into(),
                        ),
                    }],
                },
                RelativeDistinguishedName {
                    set: vec![AttributeTypeAndValue {
                        attr_type: oid! {2.5.4.10}, // organizationName
                        attr_value: Any::from_tag_and_data(
                            Tag::PrintableString,
                            b"Internet Widgits Pty Ltd".into(),
                        ),
                    }],
                },
                RelativeDistinguishedName {
                    set: vec![
                        AttributeTypeAndValue {
                            attr_type: oid! {2.5.4.3}, // CN
                            attr_value: Any::from_tag_and_data(
                                Tag::PrintableString,
                                b"Test1".into(),
                            ),
                        },
                        AttributeTypeAndValue {
                            attr_type: oid! {2.5.4.3}, // CN
                            attr_value: Any::from_tag_and_data(
                                Tag::PrintableString,
                                b"Test2".into(),
                            ),
                        },
                    ],
                },
            ],
            range: Range { start: 0, end: 0 }, // incorrect, but enough for testing
        };
        assert_eq!(
            name.to_string(),
            "C=FR, ST=Some-State, O=Internet Widgits Pty Ltd, CN=Test1 + CN=Test2"
        );
    }
}
