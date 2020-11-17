//! X.509 objects and types
//!
//! Based on RFC5280
//!

use std::collections::HashMap;
use std::fmt;

use data_encoding::HEXUPPER;
use der_parser::ber::*;
use der_parser::der::*;
use der_parser::error::*;
use der_parser::oid::Oid;
use der_parser::*;
use nom::combinator::{complete, map, map_res, opt};
use nom::multi::{many0, many1};
use nom::{Err, Offset};
use num_bigint::BigUint;
use oid_registry::*;
use rusticata_macros::newtype_enum;

use crate::cri_attributes::*;
use crate::error::{X509Error, X509Result};
use crate::extensions::*;
use crate::objects::*;
use crate::time::ASN1Time;
use crate::x509_parser;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct X509Version(pub u32);

impl X509Version {
    // Parse [0] EXPLICIT Version DEFAULT v1
    pub(crate) fn from_der(i: &[u8]) -> X509Result<X509Version> {
        let (rem, hdr) =
            ber_read_element_header(i).or(Err(Err::Error(X509Error::InvalidVersion)))?;
        match hdr.tag {
            BerTag(0) => {
                map(parse_ber_u32, X509Version)(rem).or(Err(Err::Error(X509Error::InvalidVersion)))
            }
            _ => Ok((i, X509Version::V1)),
        }
    }

    fn from_der_required(i: &[u8]) -> X509Result<X509Version> {
        let (rem, hdr) =
            ber_read_element_header(i).or(Err(Err::Error(X509Error::InvalidVersion)))?;
        match hdr.tag {
            BerTag(0) => {
                map(parse_ber_u32, X509Version)(rem).or(Err(Err::Error(X509Error::InvalidVersion)))
            }
            _ => Ok((&rem[1..], X509Version::V1)),
        }
    }
}

newtype_enum! {
    impl display X509Version {
        V1 = 0,
        V2 = 1,
        V3 = 2,
    }
}

#[derive(Debug, PartialEq)]
pub struct AttributeTypeAndValue<'a> {
    pub attr_type: Oid<'a>,
    pub attr_value: DerObject<'a>, // ANY -- DEFINED BY AttributeType
}

impl<'a> AttributeTypeAndValue<'a> {
    // AttributeTypeAndValue   ::= SEQUENCE {
    //     type    AttributeType,
    //     value   AttributeValue }
    fn from_der(i: &'a [u8]) -> X509Result<Self> {
        parse_ber_sequence_defined_g(|_, i| {
            let (i, attr_type) = map_res(parse_der_oid, |x: DerObject<'a>| x.as_oid_val())(i)
                .or(Err(X509Error::InvalidX509Name))?;
            let (i, attr_value) =
                x509_parser::parse_attribute_value(i).or(Err(X509Error::InvalidX509Name))?;
            let attr = AttributeTypeAndValue {
                attr_type,
                attr_value,
            };
            Ok((i, attr))
        })(i)
    }

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

impl<'a> RelativeDistinguishedName<'a> {
    fn from_der(i: &'a [u8]) -> X509Result<Self> {
        parse_ber_set_defined_g(|_, i| {
            let (i, set) = many1(complete(AttributeTypeAndValue::from_der))(i)?;
            let rdn = RelativeDistinguishedName { set };
            Ok((i, rdn))
        })(i)
    }
}

#[derive(Debug, PartialEq)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm: AlgorithmIdentifier<'a>,
    pub subject_public_key: BitStringObject<'a>,
}

impl<'a> SubjectPublicKeyInfo<'a> {
    /// Parse the SubjectPublicKeyInfo struct portion of a DER-encoded X.509 Certificate
    pub fn from_der(i: &'a [u8]) -> X509Result<Self> {
        parse_ber_sequence_defined_g(|_, i| {
            let (i, algorithm) = AlgorithmIdentifier::from_der(i)?;
            let (i, subject_public_key) = map_res(parse_der_bitstring, |x: DerObject<'a>| {
                match x.content {
                    BerObjectContent::BitString(_, ref b) => Ok(b.to_owned()), // XXX padding ignored
                    _ => Err(BerError::BerTypeError),
                }
            })(i)
            .or(Err(X509Error::InvalidSPKI))?;
            let spki = SubjectPublicKeyInfo {
                algorithm,
                subject_public_key,
            };
            Ok((i, spki))
        })(i)
    }
}

#[derive(Debug, PartialEq)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm: Oid<'a>,
    pub parameters: Option<DerObject<'a>>,
}

impl<'a> AlgorithmIdentifier<'a> {
    /// Parse an algorithm identifier
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
    // lifetime is *not* useless, it is required to tell the compiler the content of the temporary
    // DerObject has the same lifetime as the input
    #[allow(clippy::needless_lifetimes)]
    pub fn from_der(i: &[u8]) -> X509Result<AlgorithmIdentifier> {
        parse_ber_sequence_defined_g(|_, i| {
            let (i, algorithm) = map_res(parse_der_oid, |x| x.as_oid_val())(i)
                .or(Err(X509Error::InvalidAlgorithmIdentifier))?;
            let (i, parameters) =
                opt(complete(parse_der))(i).or(Err(X509Error::InvalidAlgorithmIdentifier))?;

            let alg = AlgorithmIdentifier {
                algorithm,
                parameters,
            };
            Ok((i, alg))
        })(i)
    }
}

#[derive(Debug, PartialEq)]
pub struct X509Name<'a> {
    pub rdn_seq: Vec<RelativeDistinguishedName<'a>>,
    pub(crate) raw: &'a [u8],
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
    /// Parse the X.501 type Name, used for ex in issuer and subject of a X.509 certificate
    pub fn from_der(i: &'a [u8]) -> X509Result<Self> {
        let start_i = i;
        parse_ber_sequence_defined_g(move |_, i| {
            let (i, rdn_seq) = many0(complete(RelativeDistinguishedName::from_der))(i)?;
            let len = start_i.offset(i);
            let name = X509Name {
                rdn_seq,
                raw: &start_i[..len],
            };
            Ok((i, name))
        })(i)
    }

    // Not using the AsRef trait, as that would not give back the full 'a lifetime
    pub fn as_raw(&self) -> &'a [u8] {
        self.raw
    }

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
        self.iter_by_oid(&OID_X509_COMMON_NAME)
    }

    /// Return an iterator over the `Country` attributes of the X.509 Name.
    pub fn iter_country(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(&OID_X509_COUNTRY_NAME)
    }

    /// Return an iterator over the `Organization` attributes of the X.509 Name.
    pub fn iter_organization(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(&OID_X509_ORGANIZATION_NAME)
    }

    /// Return an iterator over the `OrganizationalUnit` attributes of the X.509 Name.
    pub fn iter_organizational_unit(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(&OID_X509_ORGANIZATIONAL_UNIT)
    }

    /// Return an iterator over the `StateOrProvinceName` attributes of the X.509 Name.
    pub fn iter_state_or_province(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(&OID_X509_STREET_ADDRESS)
    }

    /// Return an iterator over the `Locality` attributes of the X.509 Name.
    pub fn iter_locality(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(&OID_X509_LOCALITY_NAME)
    }

    /// Return an iterator over the `EmailAddress` attributes of the X.509 Name.
    pub fn iter_email(&self) -> impl Iterator<Item = &AttributeTypeAndValue> {
        self.iter_by_oid(&OID_PKCS9_EMAIL_ADDRESS)
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
    pub version: Option<X509Version>,
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: X509Name<'a>,
    pub this_update: ASN1Time,
    pub next_update: Option<ASN1Time>,
    pub revoked_certificates: Vec<RevokedCertificate<'a>>,
    pub extensions: HashMap<Oid<'a>, X509Extension<'a>>,
    pub(crate) raw: &'a [u8],
}

impl<'a> TbsCertList<'a> {
    fn from_der(i: &'a [u8]) -> X509Result<Self> {
        let start_i = i;
        parse_ber_sequence_defined_g(move |_, i| {
            let (i, version) =
                opt(map(parse_ber_u32, X509Version))(i).or(Err(X509Error::InvalidVersion))?;
            let (i, signature) = AlgorithmIdentifier::from_der(i)?;
            let (i, issuer) = X509Name::from_der(i)?;
            let (i, this_update) = ASN1Time::from_der(i)?;
            let (i, next_update) = ASN1Time::from_der_opt(i)?;
            let (i, revoked_certificates) =
                opt(complete(x509_parser::parse_revoked_certificates))(i)?;
            let (i, extensions) = parse_extensions(i, BerTag(0))?;
            let len = start_i.offset(i);
            let tbs = TbsCertList {
                version,
                signature,
                issuer,
                this_update,
                next_update,
                revoked_certificates: revoked_certificates.unwrap_or_default(),
                extensions,
                raw: &start_i[..len],
            };
            Ok((i, tbs))
        })(i)
    }
}

impl<'a> AsRef<[u8]> for TbsCertList<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

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

#[derive(Debug, PartialEq)]
pub struct RevokedCertificate<'a> {
    /// The Serial number of the revoked certificate
    pub user_certificate: BigUint,
    /// The date on which the revocation occurred is specified.
    pub revocation_date: ASN1Time,
    /// Additional information about revocation
    pub extensions: HashMap<Oid<'a>, X509Extension<'a>>,
    pub(crate) raw_serial: &'a [u8],
}

impl<'a> RevokedCertificate<'a> {
    // revokedCertificates     SEQUENCE OF SEQUENCE  {
    //     userCertificate         CertificateSerialNumber,
    //     revocationDate          Time,
    //     crlEntryExtensions      Extensions OPTIONAL
    //                                   -- if present, MUST be v2
    //                          }  OPTIONAL,
    pub(crate) fn from_der(i: &'a [u8]) -> X509Result<Self> {
        parse_ber_sequence_defined_g(|_, i| {
            let (i, (raw_serial, user_certificate)) = x509_parser::parse_serial(i)?;
            let (i, revocation_date) = ASN1Time::from_der(i)?;
            let (i, extensions) = opt(complete(|i| {
                let (rem, v) = parse_extension_sequence(i)?;
                extensions_sequence_to_map(rem, v)
            }))(i)?;
            let revoked = RevokedCertificate {
                user_certificate,
                revocation_date,
                extensions: extensions.unwrap_or_default(),
                raw_serial,
            };
            Ok((i, revoked))
        })(i)
    }

    /// Return the serial number of the revoked certificate
    pub fn serial(&self) -> &BigUint {
        &self.user_certificate
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

    /// Get the code identifying the reason for the revocation, if present
    pub fn reason_code(&self) -> Option<(bool, ReasonCode)> {
        let ext = self.extensions.get(&OID_X509_EXT_REASON_CODE)?;
        match ext.parsed_extension {
            ParsedExtension::ReasonCode(code) => Some((ext.critical, code)),
            _ => None,
        }
    }

    /// Get the invalidity date, if present
    ///
    /// The invalidity date is the date on which it is known or suspected that the private
    ///  key was compromised or that the certificate otherwise became invalid.
    pub fn invalidity_date(&self) -> Option<(bool, ASN1Time)> {
        let ext = self.extensions.get(&OID_X509_EXT_INVALIDITY_DATE)?;
        match ext.parsed_extension {
            ParsedExtension::InvalidityDate(date) => Some((ext.critical, date)),
            _ => None,
        }
    }

    /// Get the certificate extensions.
    #[inline]
    pub fn extensions(&self) -> &HashMap<Oid, X509Extension> {
        &self.extensions
    }
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
                        // look ABBREV, and if not found, use shortname
                        let abbrev = match oid2abbrev(&attr.attr_type) {
                            Ok(s) => String::from(s),
                            _ => format!("{:?}", attr.attr_type),
                        };
                        let rdn = format!("{}={}", abbrev, val_str);
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

#[derive(Debug, PartialEq)]
pub struct X509CertificationRequestInfo<'a> {
    pub version: X509Version,
    pub subject: X509Name<'a>,
    pub subject_pki: SubjectPublicKeyInfo<'a>,
    pub attributes: HashMap<Oid<'a>, X509CriAttribute<'a>>,
    pub raw: &'a [u8],
}

impl<'a> X509CertificationRequestInfo<'a> {
    /// Parse a certification request info structure
    ///
    /// Certification request information is defined by the following ASN.1 structure:
    ///
    /// <pre>
    /// CertificationRequestInfo ::= SEQUENCE {
    ///      version       INTEGER { v1(0) } (v1,...),
    ///      subject       Name,
    ///      subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
    ///      attributes    [0] Attributes{{ CRIAttributes }}
    /// }
    /// </pre>
    ///
    /// version is the version number; subject is the distinguished name of the certificate
    /// subject; subject_pki contains information about the public key being certified, and
    /// attributes is a collection of attributes providing additional information about the
    /// subject of the certificate.
    pub fn from_der(i: &'a [u8]) -> X509Result<Self> {
        let start_i = i;
        parse_ber_sequence_defined_g(move |_, i| {
            let (i, version) = X509Version::from_der_required(i)?;
            let (i, subject) = X509Name::from_der(i)?;
            let (i, subject_pki) = SubjectPublicKeyInfo::from_der(i)?;
            let (i, attributes) = parse_cri_attributes(i)?;
            let len = start_i.offset(i);
            let tbs = X509CertificationRequestInfo {
                version,
                subject,
                subject_pki,
                attributes,
                raw: &start_i[..len],
            };
            Ok((i, tbs))
        })(i)
    }
}

#[derive(Debug, PartialEq)]
pub struct X509CertificationRequest<'a> {
    pub certification_request_info: X509CertificationRequestInfo<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: BitStringObject<'a>,
}

impl<'a> X509CertificationRequest<'a> {
    /// Parse a certification signing request (CSR)
    ///
    /// <pre>
    /// CertificationRequest ::= SEQUENCE {
    ///     certificationRequestInfo CertificationRequestInfo,
    ///     signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
    ///     signature          BIT STRING
    /// }
    /// </pre>
    ///
    /// certificateRequestInfo is the "Certification request information", it is the value being
    /// signed; signatureAlgorithm identifies the signature algorithm; and signature is the result
    /// of signing the certification request information with the subject's private key.
    pub fn from_der(i: &'a [u8]) -> X509Result<Self> {
        parse_ber_sequence_defined_g(|_, i| {
            let (i, certification_request_info) = X509CertificationRequestInfo::from_der(i)?;
            let (i, signature_algorithm) = AlgorithmIdentifier::from_der(i)?;
            let (i, signature_value) = x509_parser::parse_signature_value(i)?;
            let cert = X509CertificationRequest {
                certification_request_info,
                signature_algorithm,
                signature_value,
            };
            Ok((i, cert))
        })(i)
    }

    pub fn requested_extensions(&self) -> Option<impl Iterator<Item = &ParsedExtension<'a>>> {
        self.certification_request_info
            .attributes
            .values()
            .find_map(|attr| {
                if let ParsedCriAttribute::ExtensionRequest(requested) = &attr.parsed_attribute {
                    Some(
                        requested
                            .extensions
                            .values()
                            .map(|ext| &ext.parsed_extension),
                    )
                } else {
                    None
                }
            })
    }

    /// Verify the cryptographic signature of this certificate
    ///
    /// `public_key` is the public key of the **signer**. For a self-signed certificate,
    /// (for ex. a public root certificate authority), this is the key from the certificate,
    /// so you can use `None`.
    ///
    /// For a leaf certificate, this is the public key of the certificate that signed it.
    /// It is usually an intermediate authority.
    #[cfg(feature = "verify")]
    pub fn verify_signature(
        &self,
        public_key: Option<&SubjectPublicKeyInfo>,
    ) -> Result<(), X509Error> {
        use ring::signature;
        let spki = public_key.unwrap_or(&self.certification_request_info.subject_pki);
        let signature_alg = &self.signature_algorithm.algorithm;
        // identify verification algorithm
        let verification_alg: &dyn signature::VerificationAlgorithm =
            if *signature_alg == OID_PKCS1_SHA1WITHRSA {
                &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
            } else if *signature_alg == OID_PKCS1_SHA256WITHRSA {
                &signature::RSA_PKCS1_2048_8192_SHA256
            } else if *signature_alg == OID_PKCS1_SHA384WITHRSA {
                &signature::RSA_PKCS1_2048_8192_SHA384
            } else if *signature_alg == OID_PKCS1_SHA512WITHRSA {
                &signature::RSA_PKCS1_2048_8192_SHA512
            } else if *signature_alg == OID_SIG_ECDSA_WITH_SHA256 {
                &signature::ECDSA_P256_SHA256_ASN1
            } else if *signature_alg == OID_SIG_ECDSA_WITH_SHA384 {
                &signature::ECDSA_P384_SHA384_ASN1
            } else {
                return Err(X509Error::SignatureUnsupportedAlgorithm);
            };
        // get public key
        let key = signature::UnparsedPublicKey::new(verification_alg, spki.subject_public_key.data);
        // verify signature
        let sig = self.signature_value.data;
        key.verify(self.certification_request_info.raw, sig)
            .or(Err(X509Error::SignatureVerificationError))
    }
}

/// An X.509 v2 Certificate Revocation List (CRL).
///
/// X.509 v2 CRLs are defined in [RFC5280](https://tools.ietf.org/html/rfc5280).
#[derive(Debug)]
pub struct CertificateRevocationList<'a> {
    pub tbs_cert_list: TbsCertList<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: BitStringObject<'a>,
}

impl<'a> CertificateRevocationList<'a> {
    /// Parse a DER-encoded X.509 v2 CRL, and return the remaining of the input and the built
    /// object.
    ///
    /// The returned object uses zero-copy, and so has the same lifetime as the input.
    ///
    /// <pre>
    /// CertificateList  ::=  SEQUENCE  {
    ///      tbsCertList          TBSCertList,
    ///      signatureAlgorithm   AlgorithmIdentifier,
    ///      signatureValue       BIT STRING  }
    /// </pre>
    ///
    /// # Example
    ///
    /// To parse a CRL and print information about revoked certificates:
    ///
    /// ```rust
    /// # use x509_parser::parse_certificate_list;
    /// #
    /// # static DER: &'static [u8] = include_bytes!("../assets/example.crl");
    /// #
    /// # fn main() {
    /// let res = parse_certificate_list(DER);
    /// match res {
    ///     Ok((_rem, crl)) => {
    ///         for revoked in crl.iter_revoked_certificates() {
    ///             println!("Revoked certificate serial: {}", revoked.raw_serial_as_string());
    ///             println!("  Reason: {}", revoked.reason_code().unwrap_or_default().1);
    ///         }
    ///     },
    ///     _ => panic!("CRL parsing failed: {:?}", res),
    /// }
    /// # }
    /// ```
    pub fn from_der(i: &'a [u8]) -> X509Result<Self> {
        parse_ber_sequence_defined_g(|_, i| {
            let (i, tbs_cert_list) = TbsCertList::from_der(i)?;
            let (i, signature_algorithm) = AlgorithmIdentifier::from_der(i)?;
            let (i, signature_value) = x509_parser::parse_signature_value(i)?;
            let crl = CertificateRevocationList {
                tbs_cert_list,
                signature_algorithm,
                signature_value,
            };
            Ok((i, crl))
        })(i)
    }

    /// Get the version of the encoded certificateu
    pub fn version(&self) -> Option<X509Version> {
        self.tbs_cert_list.version
    }

    /// Get the certificate issuer.
    #[inline]
    pub fn issuer(&self) -> &X509Name {
        &self.tbs_cert_list.issuer
    }

    /// Get the date and time of the last (this) update.
    #[inline]
    pub fn last_update(&self) -> ASN1Time {
        self.tbs_cert_list.this_update
    }

    /// Get the date and time of the next update, if present.
    #[inline]
    pub fn next_update(&self) -> Option<ASN1Time> {
        self.tbs_cert_list.next_update
    }

    /// Return an iterator over the `RevokedCertificate` objects
    pub fn iter_revoked_certificates(&self) -> impl Iterator<Item = &RevokedCertificate<'a>> {
        self.tbs_cert_list.revoked_certificates.iter()
    }

    /// Get the certificate extensions.
    #[inline]
    pub fn extensions(&self) -> &HashMap<Oid, X509Extension> {
        &self.tbs_cert_list.extensions
    }

    /// Get the CRL number, if present
    ///
    /// Note that the returned value is a `BigUint`, because of the following RFC specification:
    /// <pre>
    /// Given the requirements above, CRL numbers can be expected to contain long integers.  CRL
    /// verifiers MUST be able to handle CRLNumber values up to 20 octets.  Conformant CRL issuers
    /// MUST NOT use CRLNumber values longer than 20 octets.
    /// </pre>
    pub fn crl_number(&self) -> Option<&BigUint> {
        let ext = self.extensions().get(&OID_X509_EXT_CRL_NUMBER)?;
        match ext.parsed_extension {
            ParsedExtension::CRLNumber(ref num) => Some(num),
            _ => None,
        }
    }
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
