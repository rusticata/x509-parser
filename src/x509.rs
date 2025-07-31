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
    Alias, Any, BerError, BitString, BmpString, Choice, DerParser, Enumerated, FromDer, Header,
    Input, Integer, OptTaggedExplicit, PrintableString, Sequence, Tag, Tagged, TeletexString,
    UniversalString, Utf8String,
};
use core::convert::TryFrom;
use data_encoding::HEXUPPER;
use nom::combinator::map;
use nom::{Err, IResult, Input as _, Parser as _};
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
#[error(X509Error)]
pub struct X509Version(pub u32);

impl X509Version {
    /// Parse `[0]` EXPLICIT Version DEFAULT v1
    pub(crate) fn parse_der_tagged_0(
        input: Input<'_>,
    ) -> IResult<Input<'_>, X509Version, X509Error> {
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

/// The DirectoryString type is defined as a choice of PrintableString, TeletexString,
/// BMPString, UTF8String, and UniversalString.
///
/// <pre>
/// RFC 5280, 4.1.2.4.  Issuer
///    DirectoryString ::= CHOICE {
///          teletexString           TeletexString (SIZE (1..MAX)),
///          printableString         PrintableString (SIZE (1..MAX)),
///          universalString         UniversalString (SIZE (1..MAX)),
///          utf8String              UTF8String (SIZE (1..MAX)),
///          bmpString               BMPString (SIZE (1..MAX))
///    }
/// </pre>
#[derive(Debug, PartialEq, Eq, Choice)]
#[asn1(parse = "DER", encode = "")]
pub enum DirectoryString<'a> {
    Teletex(TeletexString<'a>),
    Printable(PrintableString<'a>),
    Universal(UniversalString<'a>),
    Utf8(Utf8String<'a>),
    Bmp(BmpString<'a>),
}

impl fmt::Display for DirectoryString<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DirectoryString::Teletex(s) => f.write_str(s.as_ref()),
            DirectoryString::Printable(s) => f.write_str(s.as_ref()),
            DirectoryString::Universal(s) => f.write_str(s.as_ref()),
            DirectoryString::Utf8(s) => f.write_str(s.as_ref()),
            DirectoryString::Bmp(s) => f.write_str(s.as_ref()),
        }
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

    const TAG: Tag = Tag::Set;
}

impl<'a> DerParser<'a> for RelativeDistinguishedName<'a> {
    type Error = X509Error;

    fn from_der_content(
        header: &'_ Header<'a>,
        input: Input<'a>,
    ) -> IResult<Input<'a>, Self, Self::Error> {
        let (rem, set) = <Vec<AttributeTypeAndValue>>::from_der_content(header, input)?;
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
    pub fn parsed(&self) -> Result<PublicKey<'_>, X509Error> {
        let b = self.subject_public_key.as_raw_slice();
        if self.algorithm.algorithm == OID_PKCS1_RSAENCRYPTION {
            let (_, key) = RSAPublicKey::from_der(b).map_err(|_| X509Error::InvalidSPKI)?;
            Ok(PublicKey::RSA(key))
        } else if self.algorithm.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY {
            let key = ECPoint::from(b);
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
#[derive(Clone, Debug, PartialEq)]
pub struct X509Name<'a> {
    pub(crate) rdn_seq: Vec<RelativeDistinguishedName<'a>>,

    pub(crate) raw: Input<'a>,
}

impl fmt::Display for X509Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match x509name_to_string(&self.rdn_seq, oid_registry()) {
            Ok(o) => write!(f, "{o}"),
            Err(_) => write!(f, "<X509Error: Invalid X.509 name>"),
        }
    }
}

impl<'a> X509Name<'a> {
    /// Builds a new `X509Name` from the provided elements.
    #[inline]
    pub const fn new(rdn_seq: Vec<RelativeDistinguishedName<'a>>, raw: Input<'a>) -> Self {
        X509Name { rdn_seq, raw }
    }

    /// Attempt to format the current name, using the given registry to convert OIDs to strings.
    ///
    /// Note: a default registry is provided with this crate, and is returned by the
    /// [`oid_registry()`] method.
    pub fn to_string_with_registry(&self, oid_registry: &OidRegistry) -> Result<String, X509Error> {
        x509name_to_string(&self.rdn_seq, oid_registry)
    }

    // Return the parsed data bytes
    pub fn as_raw(&self) -> &'a [u8] {
        self.raw.as_bytes2()
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
            raw: Input::default(),
        }
    }
}

impl<'a> From<X509Name<'a>> for Vec<RelativeDistinguishedName<'a>> {
    fn from(name: X509Name<'a>) -> Self {
        name.rdn_seq
    }
}

impl Tagged for X509Name<'_> {
    const CONSTRUCTED: bool = false;
    const TAG: Tag = Tag::Sequence;
}

impl<'i> DerParser<'i> for X509Name<'i> {
    type Error = X509Error;

    fn parse_der(input: Input<'i>) -> IResult<Input<'i>, Self, Self::Error> {
        let orig_input = input.clone();
        let (rem, mut name) = Sequence::parse_der_and_then(input, |header, input| {
            Self::from_der_content(&header, input)
        })?;
        // update `raw` field to contain full sequence (including header)
        // this is safe because `rem` is built from `orig_input`
        let raw = orig_input.take(rem.start() - orig_input.start());
        name.raw = raw;
        Ok((rem, name))
    }

    fn from_der_content(
        header: &'_ Header<'i>,
        input: Input<'i>,
    ) -> IResult<Input<'i>, Self, Self::Error> {
        header
            .assert_constructed_input(&input)
            .map_err(|e| Err::Error(e.into()))?;

        let orig_input = input.clone();
        let (rem, rdn_seq) = <Vec<RelativeDistinguishedName>>::from_der_content(header, input)?;
        // this is safe because `rem` is built from `orig_input`
        let raw = orig_input.take(rem.start() - orig_input.start());
        let name = X509Name { rdn_seq, raw };
        Ok((rem, name))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Enumerated)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
#[derive(Default)]
#[repr(u8)]
pub enum ReasonCode {
    #[default]
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

impl fmt::Display for ReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            ReasonCode::Unspecified => "Unspecified",
            ReasonCode::KeyCompromise => "KeyCompromise",
            ReasonCode::CACompromise => "CACompromise",
            ReasonCode::AffiliationChanged => "AffiliationChanged",
            ReasonCode::Superseded => "Superseded",
            ReasonCode::CessationOfOperation => "CessationOfOperation",
            ReasonCode::CertificateHold => "CertificateHold",
            ReasonCode::RemoveFromCRL => "RemoveFromCRL",
            ReasonCode::PrivilegeWithdrawn => "PrivilegeWithdrawn",
            ReasonCode::AACompromise => "AACompromise",
        };
        write!(f, "{s}")
    }
}

// Attempt to convert attribute to string. If type is not a string, return value is the hex
// encoding of the attribute value
fn attribute_value_to_string(attr: &Any, _attr_type: &Oid) -> Result<String, X509Error> {
    match attr.as_any_string() {
        Ok(s) => Ok(s),
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
                let rdn = format!("{abbrev}={val_str}");
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
pub(crate) fn parse_signature_value(input: Input<'_>) -> IResult<Input<'_>, BitString, X509Error> {
    BitString::parse_der(input).or(Err(Err::Error(X509Error::InvalidSignatureValue)))
}

pub(crate) fn parse_serial(input: Input<'_>) -> IResult<Input<'_>, (&[u8], BigUint), X509Error> {
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

/// Formats a slice to a colon-separated hex string (for ex `01:02:ff:ff`)
pub fn format_serial(i: &[u8]) -> String {
    let mut s = i.iter().fold(String::with_capacity(3 * i.len()), |a, b| {
        a + &format!("{b:02x}:")
    });
    s.pop();
    s
}

#[cfg(test)]
mod tests {
    use crate::certificate::Validity;
    use asn1_rs::oid;
    use hex_literal::hex;

    use super::*;

    #[test]
    fn test_x509_version() {
        // correct version
        let data: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x00];
        let r = X509Version::parse_der_tagged_0(Input::from(data));
        assert!(r.is_ok());

        // wrong tag
        let data: &[u8] = &[0xa1, 0x03, 0x02, 0x01, 0x00];
        let r = X509Version::parse_der_tagged_0(Input::from(data));
        assert!(r.is_ok());

        // short read
        let data: &[u8] = &[0xa0, 0x01];
        let r = X509Version::parse_der_tagged_0(Input::from(data));
        assert!(r.is_err());

        // short read with wrong tag: no fail, since tag is wrong and object is optional, it returns None
        let data: &[u8] = &[0xa1, 0x01];
        let r = X509Version::parse_der_tagged_0(Input::from(data));
        assert!(r.is_ok());
    }

    #[test]
    fn test_format_serial() {
        let b: &[u8] = &[1, 2, 3, 4, 0xff];
        assert_eq!("01:02:03:04:ff", format_serial(b));
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
            raw: Input::default(), // incorrect, but enough for testing
        };
        assert_eq!(
            name.to_string(),
            "C=FR, ST=Some-State, O=Internet Widgits Pty Ltd, CN=Test1 + CN=Test2"
        );
    }

    #[test]
    fn parse_algorithm_identifier() {
        // AlgorithmIdentifier for RSA Encryption (PKCS1)
        let bytes = &hex!("30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00");

        let (rem, alg) =
            AlgorithmIdentifier::parse_der(Input::from(bytes)).expect("algorithm identifier");
        assert!(rem.is_empty());
        assert_eq!(*alg.oid(), OID_PKCS1_RSAENCRYPTION);
        assert_eq!(alg.parameters().map(|any| any.tag()), Some(Tag::Null));
    }

    #[test]
    fn parse_x509_name() {
        // bytes for Subject in assets/v1.der
        let bytes = &hex!("30 12 31 10 30 0E 06 03 55 04 03 0C 07 6D 61 72 71 75 65 65");

        let (rem, name) = X509Name::parse_der(Input::from(bytes)).expect("algorithm identifier");
        assert!(rem.is_empty());
        assert_eq!(name.to_string(), String::from("CN=marquee"));
    }

    #[test]
    fn parse_x509_validity() {
        // bytes for Validity in assets/v1.der
        let bytes = &hex!("30 1E 17 0D 31 39 31 31 32 37 31 34 35 33 33 31 5A 17 0D 32 39 31 31 32 37 31 34 35 35 31 31 5A");

        let (rem, v) = Validity::parse_der(Input::from(bytes)).expect("algorithm identifier");
        assert!(rem.is_empty());
        assert!(v.not_before.is_utctime());
        assert!(v.not_after.is_utctime());
        assert_eq!(v.not_before.to_datetime().year(), 2019);
        assert_eq!(v.not_after.to_datetime().year(), 2029);
    }
}
