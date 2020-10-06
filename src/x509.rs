//! X.509 objects
//!
//! Based on RFC5280
//!

use std::fmt;

use num_bigint::BigUint;

use crate::error::X509Error;
use crate::extensions::*;
use crate::objects::*;
use crate::time::ASN1Time;
use data_encoding::HEXUPPER;
use der_parser::ber::{BerObjectContent, BitStringObject};
use der_parser::der::DerObject;
use der_parser::oid::Oid;
use std::collections::HashMap;

#[derive(Debug, PartialEq)]
pub enum X509Version {
    V1,
    V2,
    V3,
    Invalid(u32),
}

#[derive(Debug, PartialEq)]
pub struct X509Extension<'a> {
    pub oid: Oid<'a>,
    pub critical: bool,
    pub value: &'a [u8],
    pub(crate) parsed_extension: ParsedExtension<'a>,
}

impl<'a> X509Extension<'a> {
    pub fn new(
        oid: Oid<'a>,
        critical: bool,
        value: &'a [u8],
        parsed_extension: ParsedExtension<'a>,
    ) -> X509Extension<'a> {
        X509Extension {
            oid,
            critical,
            value,
            parsed_extension,
        }
    }

    /// Return the extension type or `None` if the extension is not implemented.
    pub fn parsed_extension(&self) -> &ParsedExtension<'a> {
        &self.parsed_extension
    }
}

#[derive(Debug, PartialEq)]
pub struct AttributeTypeAndValue<'a> {
    pub attr_type: Oid<'a>,
    pub attr_value: DerObject<'a>, // XXX DirectoryString ?
}

impl<'a> AttributeTypeAndValue<'a> {
    /// Attempt to get the content as `str`.
    /// This can fail if the object does not contain a string type.
    ///
    /// Only NumericString, PrintableString, UTF8String and IA5String
    /// are considered here. Other string types can be read using `as_slice`.
    pub fn as_str(&self) -> Result<&'a str, X509Error> {
        self.attr_value.as_str().map_err(|e| e.into())
    }

    /// Attempt to get the content as a slice.
    /// This can fail if the object does not contain a type directly equivalent to a slice (e.g a
    /// sequence).
    pub fn as_slice(&self) -> Result<&'a [u8], X509Error> {
        self.attr_value.as_slice().map_err(|e| e.into())
    }
}

#[derive(Debug, PartialEq)]
pub struct RelativeDistinguishedName<'a> {
    pub set: Vec<AttributeTypeAndValue<'a>>,
}

#[derive(Debug, PartialEq)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub subject_public_key: BitStringObject<'a>,
}

#[derive(Debug, PartialEq)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm: Oid<'a>,
    pub parameters: DerObject<'a>,
}

#[derive(Debug, PartialEq)]
pub struct X509Name<'a> {
    pub rdn_seq: Vec<RelativeDistinguishedName<'a>>,
    pub(crate) raw: &'a [u8],
}

impl<'a> X509Name<'a> {
    // Not using the AsRef trait, as that would not give back the full 'a lifetime
    pub fn as_raw(&self) -> &'a [u8] {
        self.raw
    }
}

impl<'a> fmt::Display for X509Name<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match x509name_to_string(&self.rdn_seq) {
            Ok(o) => write!(f, "{}", o),
            Err(_) => write!(f, "<X509Error: Invalid X.509 name>"),
        }
    }
}

impl<'a> X509Name<'a> {
    /// Return an iterator over the `RelativeDistinguishedName` components of the name
    pub fn iter_rdn(&self) -> impl Iterator<Item = &RelativeDistinguishedName<'a>> {
        self.rdn_seq.iter()
    }

    /// Return an iterator over the attribute types and values of the name
    pub fn iter_attributes(&self) -> impl Iterator<Item = &AttributeTypeAndValue<'a>> {
        self.rdn_seq.iter().map(|rdn| rdn.set.iter()).flatten()
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
        // `self.iter_by_oid(&OID_L)`
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
    /// use x509_parser::X509Name;
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
    pub fn iter_common_name(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(&OID_CN)
    }

    /// Return an iterator over the `Country` attributes of the X.509 Name.
    pub fn iter_country(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(&OID_C)
    }

    /// Return an iterator over the `Organization` attributes of the X.509 Name.
    pub fn iter_organization(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(&OID_O)
    }

    /// Return an iterator over the `OrganizationalUnit` attributes of the X.509 Name.
    pub fn iter_organizational_unit(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(&OID_OU)
    }

    /// Return an iterator over the `StateOrProvinceName` attributes of the X.509 Name.
    pub fn iter_state_or_province(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(&OID_ST)
    }

    /// Return an iterator over the `Locality` attributes of the X.509 Name.
    pub fn iter_locality(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(&OID_L)
    }

    /// Return an iterator over the `EmailAddress` attributes of the X.509 Name.
    pub fn iter_email(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(&OID_EMAIL)
    }
}

/// The sequence TBSCertificate contains information associated with the
/// subject of the certificate and the CA that issued it.
///
/// RFC5280 definition:
///
/// <pre>
///   TBSCertificate  ::=  SEQUENCE  {
///        version         [0]  EXPLICIT Version DEFAULT v1,
///        serialNumber         CertificateSerialNumber,
///        signature            AlgorithmIdentifier,
///        issuer               Name,
///        validity             Validity,
///        subject              Name,
///        subjectPublicKeyInfo SubjectPublicKeyInfo,
///        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///                             -- If present, version MUST be v2 or v3
///        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///                             -- If present, version MUST be v2 or v3
///        extensions      [3]  EXPLICIT Extensions OPTIONAL
///                             -- If present, version MUST be v3
///        }
/// </pre>
#[derive(Debug, PartialEq)]
pub struct TbsCertificate<'a> {
    /// Raw encoding of the version: 0 for v1, 1 for v2, 2 for v3
    pub version: u32,
    pub serial: BigUint,
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: X509Name<'a>,
    pub validity: Validity,
    pub subject: X509Name<'a>,
    pub subject_pki: SubjectPublicKeyInfo<'a>,
    pub issuer_uid: Option<UniqueIdentifier<'a>>,
    pub subject_uid: Option<UniqueIdentifier<'a>>,
    pub extensions: HashMap<Oid<'a>, X509Extension<'a>>,
    pub(crate) raw: &'a [u8],
    pub(crate) raw_serial: &'a [u8],
}

impl<'a> AsRef<[u8]> for TbsCertificate<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

#[derive(Debug, PartialEq)]
pub struct Validity {
    pub not_before: ASN1Time,
    pub not_after: ASN1Time,
}

impl Validity {
    /// The time left before the certificate expires.
    ///
    /// If the certificate is not currently valid, then `None` is
    /// returned.  Otherwise, the `Duration` until the certificate
    /// expires is returned.
    pub fn time_to_expiration(&self) -> Option<std::time::Duration> {
        let now = ASN1Time::now();
        if !self.is_valid_at(now) {
            return None;
        }
        // Note that the duration below is guaranteed to be positive,
        // since we just checked that now < na
        self.not_after - now
    }

    /// Check the certificate time validity for the provided date/time
    #[inline]
    pub fn is_valid_at(&self, time: ASN1Time) -> bool {
        time >= self.not_before && time < self.not_after
    }

    /// Check the certificate time validity
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.is_valid_at(ASN1Time::now())
    }
}

#[test]
fn check_validity_expiration() {
    let mut v = Validity {
        not_before: ASN1Time::now(),
        not_after: ASN1Time::now(),
    };
    assert_eq!(v.time_to_expiration(), None);
    v.not_after = (v.not_after + std::time::Duration::new(60, 0)).unwrap();
    assert!(v.time_to_expiration().is_some());
    assert!(v.time_to_expiration().unwrap() <= std::time::Duration::from_secs(60));
    // The following assumes this timing won't take 10 seconds... I
    // think that is safe.
    assert!(v.time_to_expiration().unwrap() > std::time::Duration::from_secs(50));
}

#[derive(Debug, PartialEq)]
pub struct UniqueIdentifier<'a>(pub BitStringObject<'a>);

impl<'a> TbsCertificate<'a> {
    /// Get a reference to the map of extensions.
    pub fn extensions(&self) -> &HashMap<Oid, X509Extension> {
        &self.extensions
    }

    pub fn basic_constraints(&self) -> Option<(bool, &BasicConstraints)> {
        let ext = self.extensions.get(&OID_EXT_BC)?;
        match ext.parsed_extension {
            ParsedExtension::BasicConstraints(ref bc) => Some((ext.critical, bc)),
            _ => None,
        }
    }

    pub fn key_usage(&self) -> Option<(bool, &KeyUsage)> {
        let ext = self.extensions.get(&OID_EXT_KU)?;
        match ext.parsed_extension {
            ParsedExtension::KeyUsage(ref ku) => Some((ext.critical, ku)),
            _ => None,
        }
    }

    pub fn extended_key_usage(&self) -> Option<(bool, &ExtendedKeyUsage)> {
        let ext = self.extensions.get(&OID_EXT_EKU)?;
        match ext.parsed_extension {
            ParsedExtension::ExtendedKeyUsage(ref eku) => Some((ext.critical, eku)),
            _ => None,
        }
    }

    pub fn policy_constraints(&self) -> Option<(bool, &PolicyConstraints)> {
        let ext = self.extensions.get(&OID_EXT_POLICYCONSTRAINTS)?;
        match ext.parsed_extension {
            ParsedExtension::PolicyConstraints(ref pc) => Some((ext.critical, pc)),
            _ => None,
        }
    }

    pub fn inhibit_anypolicy(&self) -> Option<(bool, &InhibitAnyPolicy)> {
        let ext = self.extensions.get(&OID_EXT_INHIBITANYPOLICY)?;
        match ext.parsed_extension {
            ParsedExtension::InhibitAnyPolicy(ref iap) => Some((ext.critical, iap)),
            _ => None,
        }
    }

    pub fn policy_mappings(&self) -> Option<(bool, &PolicyMappings)> {
        let ext = self.extensions.get(&OID_EXT_POLICYMAPPINGS)?;
        match ext.parsed_extension {
            ParsedExtension::PolicyMappings(ref pm) => Some((ext.critical, pm)),
            _ => None,
        }
    }

    pub fn subject_alternative_name(&self) -> Option<(bool, &SubjectAlternativeName)> {
        let ext = self.extensions.get(&OID_EXT_SAN)?;
        match ext.parsed_extension {
            ParsedExtension::SubjectAlternativeName(ref san) => Some((ext.critical, san)),
            _ => None,
        }
    }

    pub fn name_constraints(&self) -> Option<(bool, &NameConstraints)> {
        let ext = self.extensions.get(&OID_EXT_NAMECONSTRAINTS)?;
        match ext.parsed_extension {
            ParsedExtension::NameConstraints(ref nc) => Some((ext.critical, nc)),
            _ => None,
        }
    }

    /// Returns true if certificate has `basicConstraints CA:true`
    pub fn is_ca(&self) -> bool {
        self.basic_constraints()
            .map(|(_, bc)| bc.ca)
            .unwrap_or(false)
    }

    /// Get the raw bytes of the certificate serial number
    pub fn raw_serial(&self) -> &[u8] {
        self.raw_serial
    }

    /// Get a formatted string of the certificate serial number, separated by ':'
    pub fn raw_serial_as_string(&self) -> String {
        let mut s = self
            .raw_serial
            .iter()
            .fold(String::with_capacity(3 * self.raw_serial.len()), |a, b| {
                a + &format!("{:02x}:", b)
            });
        s.pop();
        s
    }
}

/// The sequence TBSCertList contains information about the certificates that have
/// been revoked by the CA that issued the CRL.
///
/// RFC5280 definition:
///
/// <pre>
/// TBSCertList  ::=  SEQUENCE  {
///         version                 Version OPTIONAL,
///                                      -- if present, MUST be v2
///         signature               AlgorithmIdentifier,
///         issuer                  Name,
///         thisUpdate              Time,
///         nextUpdate              Time OPTIONAL,
///         revokedCertificates     SEQUENCE OF SEQUENCE  {
///             userCertificate         CertificateSerialNumber,
///             revocationDate          Time,
///             crlEntryExtensions      Extensions OPTIONAL
///                                      -- if present, version MUST be v2
///                                   } OPTIONAL,
///         crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
///                                      -- if present, version MUST be v2
///                             }
/// </pre>
#[derive(Debug, PartialEq)]
pub struct TbsCertList<'a> {
    pub version: Option<u32>,
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: X509Name<'a>,
    pub this_update: ASN1Time,
    pub next_update: Option<ASN1Time>,
    pub revoked_certificates: Vec<RevokedCertificate<'a>>,
    pub extensions: Vec<X509Extension<'a>>,
    pub(crate) raw: &'a [u8],
}

impl<'a> AsRef<[u8]> for TbsCertList<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

#[derive(Debug, PartialEq)]
pub struct RevokedCertificate<'a> {
    pub user_certificate: BigUint,
    pub revocation_date: ASN1Time,
    pub extensions: Vec<X509Extension<'a>>,
}

// Attempt to convert attribute to string. If type is not a string, return value is the hex
// encoding of the attribute value
fn attribute_value_to_string(attr: &DerObject, _attr_type: &Oid) -> Result<String, X509Error> {
    match attr.content {
        BerObjectContent::NumericString(s)
        | BerObjectContent::PrintableString(s)
        | BerObjectContent::UTF8String(s)
        | BerObjectContent::IA5String(s) => Ok(s.to_owned()),
        _ => {
            // type is not a string, get slice and convert it to base64
            attr.as_slice()
                .map(|s| HEXUPPER.encode(s))
                .or(Err(X509Error::InvalidX509Name))
        }
    }
}

/// Convert a DER representation of a X.509 name to a human-readable string
///
/// RDNs are separated with ","
/// Multiple RDNs are separated with "+"
///
/// Attributes that cannot be represented by a string are hex-encoded
fn x509name_to_string(rdn_seq: &[RelativeDistinguishedName]) -> Result<String, X509Error> {
    rdn_seq.iter().fold(Ok(String::new()), |acc, rdn| {
        acc.and_then(|mut _vec| {
            rdn.set
                .iter()
                .fold(Ok(String::new()), |acc2, attr| {
                    acc2.and_then(|mut _vec2| {
                        let val_str = attribute_value_to_string(&attr.attr_value, &attr.attr_type)?;
                        let sn_str = match oid2sn(&attr.attr_type) {
                            Ok(s) => String::from(s),
                            _ => format!("{:?}", attr.attr_type),
                        };
                        let rdn = format!("{}={}", sn_str, val_str);
                        match _vec2.len() {
                            0 => Ok(rdn),
                            _ => Ok(_vec2 + " + " + &rdn),
                        }
                    })
                })
                .map(|v| match _vec.len() {
                    0 => v,
                    _ => _vec + ", " + &v,
                })
        })
    })
}

/// An X.509 v3 Certificate.
///
/// X.509 v3 certificates are defined in [RFC5280](https://tools.ietf.org/html/rfc5280), section
/// 4.1. This object uses the same structure for content, so for ex the subject can be accessed
/// using the path `x509.tbs_certificate.subject`.
///
/// `X509Certificate` also contains convenience methods to access the most common fields (subject,
/// issuer, etc.).
///
/// A `X509Certificate` is a zero-copy view over a buffer, so the lifetime is the same as the
/// buffer containing the binary representation.
///
/// ```rust
/// # use x509_parser::parse_x509_der;
/// # use x509_parser::x509::X509Certificate;
/// #
/// # static DER: &'static [u8] = include_bytes!("../assets/IGC_A.der");
/// #
/// fn display_x509_info(x509: &X509Certificate<'_>) {
///      let subject = &x509.tbs_certificate.subject;
///      let issuer = &x509.tbs_certificate.issuer;
///      println!("X.509 Subject: {}", subject);
///      println!("X.509 Issuer: {}", issuer);
///      println!("X.509 serial: {}", x509.tbs_certificate.raw_serial_as_string());
/// }
/// #
/// # fn main() {
/// # let res = parse_x509_der(DER);
/// # match res {
/// #     Ok((_rem, x509)) => {
/// #         display_x509_info(&x509);
/// #     },
/// #     _ => panic!("x509 parsing failed: {:?}", res),
/// # }
/// # }
/// ```
#[derive(Debug, PartialEq)]
pub struct X509Certificate<'a> {
    pub tbs_certificate: TbsCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: BitStringObject<'a>,
}

impl<'a> X509Certificate<'a> {
    /// Get the version of the encoded certificate
    pub fn version(&self) -> X509Version {
        match self.tbs_certificate.version {
            0 => X509Version::V1,
            1 => X509Version::V2,
            2 => X509Version::V3,
            n => X509Version::Invalid(n),
        }
    }

    /// Get the certificate subject.
    #[inline]
    pub fn subject(&self) -> &X509Name {
        &self.tbs_certificate.subject
    }

    /// Get the certificate issuer.
    #[inline]
    pub fn issuer(&self) -> &X509Name {
        &self.tbs_certificate.issuer
    }

    /// Get the certificate validity.
    #[inline]
    pub fn validity(&self) -> &Validity {
        &self.tbs_certificate.validity
    }

    /// Get the certificate extensions.
    #[inline]
    pub fn extensions(&self) -> &HashMap<Oid, X509Extension> {
        self.tbs_certificate.extensions()
    }
}

/// An X.509 v2 Certificate Revocaton List (CRL).
///
/// X.509 v2 CRLs are defined in [RFC5280](https://tools.ietf.org/html/rfc5280).
#[derive(Debug)]
pub struct CertificateRevocationList<'a> {
    pub tbs_cert_list: TbsCertList<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: BitStringObject<'a>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use der_parser::ber::BerObjectContent;
    use der_parser::oid;

    #[test]
    fn test_x509_name() {
        let name = X509Name {
            rdn_seq: vec![
                RelativeDistinguishedName {
                    set: vec![AttributeTypeAndValue {
                        attr_type: oid!(2.5.4.6), // countryName
                        attr_value: DerObject::from_obj(BerObjectContent::PrintableString("FR")),
                    }],
                },
                RelativeDistinguishedName {
                    set: vec![AttributeTypeAndValue {
                        attr_type: oid!(2.5.4.8), // stateOrProvinceName
                        attr_value: DerObject::from_obj(BerObjectContent::PrintableString(
                            "Some-State",
                        )),
                    }],
                },
                RelativeDistinguishedName {
                    set: vec![AttributeTypeAndValue {
                        attr_type: oid!(2.5.4.10), // organizationName
                        attr_value: DerObject::from_obj(BerObjectContent::PrintableString(
                            "Internet Widgits Pty Ltd",
                        )),
                    }],
                },
                RelativeDistinguishedName {
                    set: vec![
                        AttributeTypeAndValue {
                            attr_type: oid!(2.5.4.3), // CN
                            attr_value: DerObject::from_obj(BerObjectContent::PrintableString(
                                "Test1",
                            )),
                        },
                        AttributeTypeAndValue {
                            attr_type: oid!(2.5.4.3), // CN
                            attr_value: DerObject::from_obj(BerObjectContent::PrintableString(
                                "Test2",
                            )),
                        },
                    ],
                },
            ],
            raw: &[], // incorrect, but enough for testing
        };
        assert_eq!(
            name.to_string(),
            "C=FR, ST=Some-State, O=Internet Widgits Pty Ltd, CN=Test1 + CN=Test2"
        );
    }
}
