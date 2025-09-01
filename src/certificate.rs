//! X.509 Certificate object definitions and operations

use crate::error::{X509Error, X509Result};
use crate::extensions::*;
use crate::time::ASN1Time;
#[cfg(feature = "validate")]
use crate::validate::*;
use crate::x509::{
    format_serial, parse_serial, parse_signature_value, AlgorithmIdentifier, SubjectPublicKeyInfo,
    X509Name, X509Version,
};

#[cfg(any(feature = "verify", feature = "verify-aws"))]
use crate::verify::verify_signature;
use asn1_rs::{
    Alias, BerError, BigUint, BitString, DerParser, Error, FromDer, Header, Input,
    OptTaggedImplicit, Sequence, Tag, Tagged,
};
use core::ops::Deref;
use nom::{Err, IResult, Input as _, Mode, Parser};
use oid_registry::*;
use std::collections::HashMap;
use time::Duration;

/// An X.509 v3 Certificate.
///
/// X.509 v3 certificates are defined in [RFC5280](https://tools.ietf.org/html/rfc5280), section
/// 4.1. This object uses the same structure for content, so for ex the subject can be accessed
/// using the path `x509.tbs_certificate.subject`.
///
/// `X509Certificate` also contains convenience methods to access the most common fields (subject,
/// issuer, etc.). These are provided using `Deref<Target = TbsCertificate>`, so documentation for
/// these methods can be found in the [`TbsCertificate`] object.
///
/// A `X509Certificate` is a zero-copy view over a buffer, so the lifetime is the same as the
/// buffer containing the binary representation.
///
/// ```rust
/// # use x509_parser::prelude::FromDer;
/// # use x509_parser::certificate::X509Certificate;
/// #
/// # static DER: &'static [u8] = include_bytes!("../assets/IGC_A.der");
/// #
/// fn display_x509_info(x509: &X509Certificate<'_>) {
///      let subject = x509.subject();
///      let issuer = x509.issuer();
///      println!("X.509 Subject: {}", subject);
///      println!("X.509 Issuer: {}", issuer);
///      println!("X.509 serial: {}", x509.tbs_certificate.raw_serial_as_string());
/// }
/// #
/// # fn main() {
/// # let res = X509Certificate::from_der(DER);
/// # match res {
/// #     Ok((_rem, x509)) => {
/// #         display_x509_info(&x509);
/// #     },
/// #     _ => panic!("x509 parsing failed: {:?}", res),
/// # }
/// # }
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct X509Certificate<'a> {
    pub tbs_certificate: TbsCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: BitString,
}

impl X509Certificate<'_> {
    /// Verify the cryptographic signature of this certificate
    ///
    /// `public_key` is the public key of the **signer**. For a self-signed certificate,
    /// (for ex. a public root certificate authority), this is the key from the certificate,
    /// so you can use `None`.
    ///
    /// For a leaf certificate, this is the public key of the certificate that signed it.
    /// It is usually an intermediate authority.
    ///
    /// Not all algorithms are supported, this function is limited to what `ring` supports.
    #[cfg(any(feature = "verify", feature = "verify-aws"))]
    #[cfg_attr(docsrs, doc(cfg(any(feature = "verify", feature = "verify-aws"))))]
    pub fn verify_signature(
        &self,
        public_key: Option<&SubjectPublicKeyInfo>,
    ) -> Result<(), X509Error> {
        let spki = public_key.unwrap_or_else(|| self.public_key());
        verify_signature(
            spki,
            &self.signature_algorithm,
            &self.signature_value,
            self.tbs_certificate.raw.as_bytes2(),
        )
    }
}

impl<'a> Deref for X509Certificate<'a> {
    type Target = TbsCertificate<'a>;

    fn deref(&self) -> &Self::Target {
        &self.tbs_certificate
    }
}

impl Tagged for X509Certificate<'_> {
    const CONSTRUCTED: bool = true;
    const TAG: Tag = Tag::Sequence;
}

impl<'a> DerParser<'a> for X509Certificate<'a> {
    type Error = X509Error;

    fn parse_der(input: Input<'a>) -> IResult<Input<'a>, Self, Self::Error> {
        X509CertificateParser::new().parse(input)
    }

    fn from_der_content(
        header: &'_ Header<'a>,
        input: Input<'a>,
    ) -> IResult<Input<'a>, Self, Self::Error> {
        header
            .assert_constructed_input(&input)
            .map_err(|e| Err::Error(e.into()))?;
        let (rem, tbs_certificate) = TbsCertificate::parse_der(input)?;
        let (rem, signature_algorithm) = AlgorithmIdentifier::parse_der(rem)?;
        let (rem, signature_value) = BitString::parse_der(rem).map_err(Err::convert)?;

        let cert = X509Certificate {
            tbs_certificate,
            signature_algorithm,
            signature_value,
        };
        Ok((rem, cert))
    }
}

impl<'a> FromDer<'a, X509Error> for X509Certificate<'a> {
    /// Parse a DER-encoded X.509 Certificate, and return the remaining of the input and the built
    /// object.
    ///
    /// The returned object uses zero-copy, and so has the same lifetime as the input.
    ///
    /// Note that only parsing is done, not validation.
    ///
    /// <pre>
    /// Certificate  ::=  SEQUENCE  {
    ///         tbsCertificate       TBSCertificate,
    ///         signatureAlgorithm   AlgorithmIdentifier,
    ///         signatureValue       BIT STRING  }
    /// </pre>
    ///
    /// # Example
    ///
    /// To parse a certificate and print the subject and issuer:
    ///
    /// ```rust
    /// # use x509_parser::parse_x509_certificate;
    /// #
    /// # static DER: &'static [u8] = include_bytes!("../assets/IGC_A.der");
    /// #
    /// # fn main() {
    /// let res = parse_x509_certificate(DER);
    /// match res {
    ///     Ok((_rem, x509)) => {
    ///         let subject = x509.subject();
    ///         let issuer = x509.issuer();
    ///         println!("X.509 Subject: {}", subject);
    ///         println!("X.509 Issuer: {}", issuer);
    ///     },
    ///     _ => panic!("x509 parsing failed: {:?}", res),
    /// }
    /// # }
    /// ```
    fn from_der(i: &'a [u8]) -> X509Result<'a, Self> {
        let input = Input::from(i);
        // run parser with default options
        match X509CertificateParser::new().parse(input) {
            Ok((rem, res)) => Ok((rem.as_bytes2(), res)),
            Err(e) => Err(e),
        }
    }
}

/// X.509 Certificate parser
///
/// This object is a parser builder, and allows specifying parsing options.
/// Currently, the only option is to control deep parsing of X.509v3 extensions:
/// a parser can decide to skip deep-parsing to be faster (the structure of extensions is still
/// parsed, and the contents can be parsed later using the [`from_der`](FromDer::from_der)
/// method from individual extension objects).
///
/// This object uses the `nom::Parser` trait, which must be imported.
///
/// # Example
///
/// To parse a certificate without parsing extensions:
///
/// ```rust
/// use x509_parser::certificate::X509CertificateParser;
/// use x509_parser::nom::Parser;
/// use x509_parser::asn1_rs::Input;
///
/// # static DER: &'static [u8] = include_bytes!("../assets/IGC_A.der");
/// #
/// # fn main() {
/// // create a parser that will not parse extensions
/// let mut parser = X509CertificateParser::new()
///     .with_deep_parse_extensions(false);
/// let res = parser.parse(Input::from(DER));
/// match res {
///     Ok((_rem, x509)) => {
///         let subject = x509.subject();
///         let issuer = x509.issuer();
///         println!("X.509 Subject: {}", subject);
///         println!("X.509 Issuer: {}", issuer);
///     },
///     _ => panic!("x509 parsing failed: {:?}", res),
/// }
/// # }
/// ```
#[derive(Clone, Copy, Debug)]
pub struct X509CertificateParser {
    deep_parse_extensions: bool,
    // strict: bool,
}

impl X509CertificateParser {
    #[inline]
    pub const fn new() -> Self {
        X509CertificateParser {
            deep_parse_extensions: true,
        }
    }

    #[inline]
    pub const fn with_deep_parse_extensions(self, deep_parse_extensions: bool) -> Self {
        X509CertificateParser {
            deep_parse_extensions,
        }
    }
}

impl Default for X509CertificateParser {
    fn default() -> Self {
        X509CertificateParser::new()
    }
}

impl<'a> Parser<Input<'a>> for X509CertificateParser {
    type Output = X509Certificate<'a>;
    type Error = X509Error;

    fn parse(&mut self, input: Input<'a>) -> IResult<Input<'a>, X509Certificate<'a>, X509Error> {
        Sequence::parse_der_and_then(input, |_, i| {
            // pass options to TbsCertificate parser
            let mut tbs_parser =
                TbsCertificateParser::new().with_deep_parse_extensions(self.deep_parse_extensions);
            let (i, tbs_certificate) = tbs_parser.parse(i)?;
            let (i, signature_algorithm) = AlgorithmIdentifier::parse_der(i)?;
            let (i, signature_value) = parse_signature_value(i)?;
            let cert = X509Certificate {
                tbs_certificate,
                signature_algorithm,
                signature_value,
            };
            Ok((i, cert))
        })
    }

    fn process<OM: nom::OutputMode>(
        &mut self,
        input: Input<'a>,
    ) -> nom::PResult<OM, Input<'a>, Self::Output, Self::Error> {
        // inspired from nom `impl Parser for F: FnMut`
        let (i, o) = self.parse(input).map_err(|e| match e {
            Err::Incomplete(i) => Err::Incomplete(i),
            Err::Error(e) => Err::Error(OM::Error::bind(|| e)),
            Err::Failure(e) => Err::Failure(e),
        })?;

        Ok((i, OM::Output::bind(|| o)))
    }
}

#[allow(deprecated)]
#[cfg(feature = "validate")]
#[cfg_attr(docsrs, doc(cfg(feature = "validate")))]
impl Validate for X509Certificate<'_> {
    fn validate<W, E>(&self, warn: W, err: E) -> bool
    where
        W: FnMut(&str),
        E: FnMut(&str),
    {
        X509StructureValidator.validate(self, &mut CallbackLogger::new(warn, err))
    }
}

/// The sequence `TBSCertificate` contains information associated with the
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
#[derive(Clone, Debug, PartialEq)]
pub struct TbsCertificate<'a> {
    pub version: X509Version,
    pub serial: BigUint,
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: X509Name<'a>,
    pub validity: Validity,
    pub subject: X509Name<'a>,
    pub subject_pki: SubjectPublicKeyInfo<'a>,
    pub issuer_uid: Option<UniqueIdentifier>,
    pub subject_uid: Option<UniqueIdentifier>,
    extensions: Vec<X509Extension<'a>>,
    /// `raw` is used to verify signature
    pub(crate) raw: Input<'a>,
    pub(crate) raw_serial: &'a [u8],
}

impl<'a> TbsCertificate<'a> {
    /// Get the version of the encoded certificate
    pub fn version(&self) -> X509Version {
        self.version
    }

    /// Get the certificate subject.
    #[inline]
    pub fn subject(&self) -> &X509Name<'_> {
        &self.subject
    }

    /// Get the certificate issuer.
    #[inline]
    pub fn issuer(&self) -> &X509Name<'_> {
        &self.issuer
    }

    /// Get the certificate validity.
    #[inline]
    pub fn validity(&self) -> &Validity {
        &self.validity
    }

    /// Get the certificate public key information.
    #[inline]
    pub fn public_key(&self) -> &SubjectPublicKeyInfo<'_> {
        &self.subject_pki
    }

    /// Returns the certificate extensions
    #[inline]
    pub fn extensions(&self) -> &[X509Extension<'a>] {
        &self.extensions
    }

    /// Returns an iterator over the certificate extensions
    #[inline]
    pub fn iter_extensions(&self) -> impl Iterator<Item = &X509Extension<'a>> {
        self.extensions.iter()
    }

    /// Searches for an extension with the given `Oid`.
    ///
    /// Return `Ok(Some(extension))` if exactly one was found, `Ok(None)` if none was found,
    /// or an error `DuplicateExtensions` if the extension is present twice or more.
    #[inline]
    pub fn get_extension_unique(&self, oid: &Oid) -> Result<Option<&X509Extension<'a>>, X509Error> {
        get_extension_unique(&self.extensions, oid)
    }

    /// Searches for an extension with the given `Oid`.
    ///
    /// ## Duplicate extensions
    ///
    /// Note: if there are several extensions with the same `Oid`, the first one is returned, masking other values.
    ///
    /// RFC5280 forbids having duplicate extensions, but does not specify how errors should be handled.
    ///
    /// **Because of this, the `find_extension` method is not safe and should not be used!**
    /// The [`get_extension_unique`](Self::get_extension_unique) method checks for duplicate extensions and should be
    /// preferred.
    #[deprecated(
        since = "0.13.0",
        note = "Do not use this function (duplicate extensions are not checked), use `get_extension_unique`"
    )]
    pub fn find_extension(&self, oid: &Oid) -> Option<&X509Extension<'a>> {
        self.extensions.iter().find(|&ext| ext.oid == *oid)
    }

    /// Builds and returns a map of extensions.
    ///
    /// If an extension is present twice, this will fail and return `DuplicateExtensions`.
    pub fn extensions_map(&self) -> Result<HashMap<Oid<'_>, &X509Extension<'a>>, X509Error> {
        self.extensions
            .iter()
            .try_fold(HashMap::new(), |mut m, ext| {
                if m.contains_key(&ext.oid) {
                    return Err(X509Error::DuplicateExtensions);
                }
                m.insert(ext.oid.clone(), ext);
                Ok(m)
            })
    }

    /// Attempt to get the certificate Basic Constraints extension
    ///
    /// Return `Ok(Some(extension))` if exactly one was found, `Ok(None)` if none was found,
    /// or an error if the extension is present twice or more.
    pub fn basic_constraints(
        &self,
    ) -> Result<Option<BasicExtension<&BasicConstraints>>, X509Error> {
        let r = self
            .get_extension_unique(&OID_X509_EXT_BASIC_CONSTRAINTS)?
            .and_then(|ext| match ext.parsed_extension {
                ParsedExtension::BasicConstraints(ref bc) => {
                    Some(BasicExtension::new(ext.critical, bc))
                }
                _ => None,
            });
        Ok(r)
    }

    /// Attempt to get the certificate Key Usage extension
    ///
    /// Return `Ok(Some(extension))` if exactly one was found, `Ok(None)` if none was found,
    /// or an error if the extension is invalid, or is present twice or more.
    pub fn key_usage(&self) -> Result<Option<BasicExtension<&KeyUsage>>, X509Error> {
        self.get_extension_unique(&OID_X509_EXT_KEY_USAGE)?
            .map_or(Ok(None), |ext| match ext.parsed_extension {
                ParsedExtension::KeyUsage(ref value) => {
                    Ok(Some(BasicExtension::new(ext.critical, value)))
                }
                _ => Err(X509Error::InvalidExtensions),
            })
    }

    /// Attempt to get the certificate Extended Key Usage extension
    ///
    /// Return `Ok(Some(extension))` if exactly one was found, `Ok(None)` if none was found,
    /// or an error if the extension is invalid, or is present twice or more.
    pub fn extended_key_usage(
        &self,
    ) -> Result<Option<BasicExtension<&ExtendedKeyUsage<'_>>>, X509Error> {
        self.get_extension_unique(&OID_X509_EXT_EXTENDED_KEY_USAGE)?
            .map_or(Ok(None), |ext| match ext.parsed_extension {
                ParsedExtension::ExtendedKeyUsage(ref value) => {
                    Ok(Some(BasicExtension::new(ext.critical, value)))
                }
                _ => Err(X509Error::InvalidExtensions),
            })
    }

    /// Attempt to get the certificate Policy Constraints extension
    ///
    /// Return `Ok(Some(extension))` if exactly one was found, `Ok(None)` if none was found,
    /// or an error if the extension is invalid, or is present twice or more.
    pub fn policy_constraints(
        &self,
    ) -> Result<Option<BasicExtension<&PolicyConstraints>>, X509Error> {
        self.get_extension_unique(&OID_X509_EXT_POLICY_CONSTRAINTS)?
            .map_or(Ok(None), |ext| match ext.parsed_extension {
                ParsedExtension::PolicyConstraints(ref value) => {
                    Ok(Some(BasicExtension::new(ext.critical, value)))
                }
                _ => Err(X509Error::InvalidExtensions),
            })
    }

    /// Attempt to get the certificate Policy Constraints extension
    ///
    /// Return `Ok(Some(extension))` if exactly one was found, `Ok(None)` if none was found,
    /// or an error if the extension is invalid, or is present twice or more.
    pub fn inhibit_anypolicy(
        &self,
    ) -> Result<Option<BasicExtension<&InhibitAnyPolicy>>, X509Error> {
        self.get_extension_unique(&OID_X509_EXT_INHIBIT_ANY_POLICY)?
            .map_or(Ok(None), |ext| match ext.parsed_extension {
                ParsedExtension::InhibitAnyPolicy(ref value) => {
                    Ok(Some(BasicExtension::new(ext.critical, value)))
                }
                _ => Err(X509Error::InvalidExtensions),
            })
    }

    /// Attempt to get the certificate Policy Mappings extension
    ///
    /// Return `Ok(Some(extension))` if exactly one was found, `Ok(None)` if none was found,
    /// or an error if the extension is invalid, or is present twice or more.
    pub fn policy_mappings(
        &self,
    ) -> Result<Option<BasicExtension<&PolicyMappings<'_>>>, X509Error> {
        self.get_extension_unique(&OID_X509_EXT_POLICY_MAPPINGS)?
            .map_or(Ok(None), |ext| match ext.parsed_extension {
                ParsedExtension::PolicyMappings(ref value) => {
                    Ok(Some(BasicExtension::new(ext.critical, value)))
                }
                _ => Err(X509Error::InvalidExtensions),
            })
    }

    /// Attempt to get the certificate Subject Alternative Name extension
    ///
    /// Return `Ok(Some(extension))` if exactly one was found, `Ok(None)` if none was found,
    /// or an error if the extension is invalid, or is present twice or more.
    pub fn subject_alternative_name(
        &self,
    ) -> Result<Option<BasicExtension<&SubjectAlternativeName<'a>>>, X509Error> {
        self.get_extension_unique(&OID_X509_EXT_SUBJECT_ALT_NAME)?
            .map_or(Ok(None), |ext| match ext.parsed_extension {
                ParsedExtension::SubjectAlternativeName(ref value) => {
                    Ok(Some(BasicExtension::new(ext.critical, value)))
                }
                _ => Err(X509Error::InvalidExtensions),
            })
    }

    /// Attempt to get the certificate Name Constraints extension
    ///
    /// Return `Ok(Some(extension))` if exactly one was found, `Ok(None)` if none was found,
    /// or an error if the extension is invalid, or is present twice or more.
    pub fn name_constraints(
        &self,
    ) -> Result<Option<BasicExtension<&NameConstraints<'_>>>, X509Error> {
        self.get_extension_unique(&OID_X509_EXT_NAME_CONSTRAINTS)?
            .map_or(Ok(None), |ext| match ext.parsed_extension {
                ParsedExtension::NameConstraints(ref value) => {
                    Ok(Some(BasicExtension::new(ext.critical, value)))
                }
                _ => Err(X509Error::InvalidExtensions),
            })
    }

    /// Returns true if certificate has `basicConstraints CA:true`
    pub fn is_ca(&self) -> bool {
        self.basic_constraints()
            .unwrap_or(None)
            .map(|ext| ext.value.ca)
            .unwrap_or(false)
    }

    /// Get the raw bytes of the certificate serial number
    pub fn raw_serial(&self) -> &'a [u8] {
        self.raw_serial
    }

    /// Get a formatted string of the certificate serial number, separated by ':'
    pub fn raw_serial_as_string(&self) -> String {
        format_serial(self.raw_serial)
    }
}

/// Searches for an extension with the given `Oid`.
///
/// Note: if there are several extensions with the same `Oid`, an error `DuplicateExtensions` is returned.
fn get_extension_unique<'a, 'b>(
    extensions: &'a [X509Extension<'b>],
    oid: &Oid,
) -> Result<Option<&'a X509Extension<'b>>, X509Error> {
    let mut res = None;
    for ext in extensions {
        if ext.oid == *oid {
            if res.is_some() {
                return Err(X509Error::DuplicateExtensions);
            }
            res = Some(ext);
        }
    }
    Ok(res)
}

impl AsRef<[u8]> for TbsCertificate<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.raw.as_bytes2()
    }
}

impl Tagged for TbsCertificate<'_> {
    const CONSTRUCTED: bool = true;
    const TAG: Tag = Tag::Sequence;
}

/// Parse a DER-encoded TbsCertificate object
///
/// <pre>
/// -- EXPLICIT tags
/// TBSCertificate  ::=  SEQUENCE  {
///      version         [0]  Version DEFAULT v1,
///      serialNumber         CertificateSerialNumber,
///      signature            AlgorithmIdentifier,
///      issuer               Name,
///      validity             Validity,
///      subject              Name,
///      subjectPublicKeyInfo SubjectPublicKeyInfo,
///      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///                           -- If present, version MUST be v2 or v3
///      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///                           -- If present, version MUST be v2 or v3
///      extensions      [3]  Extensions OPTIONAL
///                           -- If present, version MUST be v3 --  }
/// </pre>
impl<'a> DerParser<'a> for TbsCertificate<'a> {
    type Error = X509Error;

    fn parse_der(input: Input<'a>) -> IResult<Input<'a>, Self, Self::Error> {
        TbsCertificateParser::new().parse(input)
    }

    fn from_der_content(
        header: &'_ Header<'a>,
        input: Input<'a>,
    ) -> IResult<Input<'a>, Self, Self::Error> {
        header
            .assert_constructed_input(&input)
            .map_err(|e| Err::Error(e.into()))?;
        let orig_input = input.clone();
        let (rem, version) = X509Version::parse_der_tagged_0(input)?;
        let (rem, serial) = parse_serial(rem)?;
        let (rem, signature) = AlgorithmIdentifier::parse_der(rem)?;
        let (rem, issuer) = X509Name::parse_der(rem)?;
        let (rem, validity) = Validity::parse_der(rem)?;
        let (rem, subject) = X509Name::parse_der(rem)?;
        let (rem, subject_pki) = SubjectPublicKeyInfo::parse_der(rem)?;
        let (rem, issuer_uid) = UniqueIdentifier::parse_der_issuer(rem)?;
        let (rem, subject_uid) = UniqueIdentifier::parse_der_subject(rem)?;
        let (rem, extensions) = parse_opt_tagged_extensions::<3>(rem)?;
        // this is safe because `rem` is built from `orig_input`
        let raw = orig_input.take(rem.start() - orig_input.start());
        let tbs = TbsCertificate {
            version,
            serial: serial.1,
            signature,
            issuer,
            validity,
            subject,
            subject_pki,
            issuer_uid,
            subject_uid,
            extensions,

            raw,
            raw_serial: serial.0,
        };
        Ok((rem, tbs))
    }
}

/// `TbsCertificate` parser builder
#[derive(Clone, Copy, Debug)]
pub struct TbsCertificateParser {
    deep_parse_extensions: bool,
}

impl TbsCertificateParser {
    #[inline]
    pub const fn new() -> Self {
        TbsCertificateParser {
            deep_parse_extensions: true,
        }
    }

    #[inline]
    pub const fn with_deep_parse_extensions(self, deep_parse_extensions: bool) -> Self {
        TbsCertificateParser {
            deep_parse_extensions,
        }
    }
}

impl Default for TbsCertificateParser {
    fn default() -> Self {
        TbsCertificateParser::new()
    }
}

impl<'a> Parser<Input<'a>> for TbsCertificateParser {
    type Output = TbsCertificate<'a>;
    type Error = X509Error;

    fn parse(&mut self, input: Input<'a>) -> IResult<Input<'a>, TbsCertificate<'a>, X509Error> {
        let orig_input = input.clone();
        let (rem, mut tbs) = Sequence::parse_der_and_then(input, |_, input| {
            let (rem, version) = X509Version::parse_der_tagged_0(input)?;
            let (rem, serial) = parse_serial(rem)?;
            let (rem, signature) = AlgorithmIdentifier::parse_der(rem)?;
            let (rem, issuer) = X509Name::parse_der(rem)?;
            let (rem, validity) = Validity::parse_der(rem)?;
            let (rem, subject) = X509Name::parse_der(rem)?;
            let (rem, subject_pki) = SubjectPublicKeyInfo::parse_der(rem)?;
            let (rem, issuer_uid) = UniqueIdentifier::parse_der_issuer(rem)?;
            let (rem, subject_uid) = UniqueIdentifier::parse_der_subject(rem)?;
            let (rem, extensions) = if self.deep_parse_extensions {
                parse_opt_tagged_extensions::<3>(rem)?
            } else {
                parse_opt_tagged_extensions_envelope_only::<3>(rem)?
            };
            // do no set `raw` here, it will be updated just after closure return;
            let raw = Input::default();
            let tbs = TbsCertificate {
                version,
                serial: serial.1,
                signature,
                issuer,
                validity,
                subject,
                subject_pki,
                issuer_uid,
                subject_uid,
                extensions,

                raw,
                raw_serial: serial.0,
            };
            Ok((rem, tbs))
        })?;
        // update `raw` field to contain full sequence (including header)
        // this is safe because `rem` is built from `orig_input`
        let raw = orig_input.take(rem.start() - orig_input.start());
        tbs.raw = raw;
        Ok((rem, tbs))
    }

    fn process<OM: nom::OutputMode>(
        &mut self,
        input: Input<'a>,
    ) -> nom::PResult<OM, Input<'a>, Self::Output, Self::Error> {
        // inspired from nom `impl Parser for F: FnMut`
        let (i, o) = self.parse(input).map_err(|e| match e {
            Err::Incomplete(i) => Err::Incomplete(i),
            Err::Error(e) => Err::Error(OM::Error::bind(|| e)),
            Err::Failure(e) => Err::Failure(e),
        })?;

        Ok((i, OM::Output::bind(|| o)))
    }
}

#[allow(deprecated)]
#[cfg(feature = "validate")]
#[cfg_attr(docsrs, doc(cfg(feature = "validate")))]
impl Validate for TbsCertificate<'_> {
    fn validate<W, E>(&self, warn: W, err: E) -> bool
    where
        W: FnMut(&str),
        E: FnMut(&str),
    {
        TbsCertificateStructureValidator.validate(self, &mut CallbackLogger::new(warn, err))
    }
}

/// Basic extension structure, used in search results
#[derive(Debug, PartialEq, Eq)]
pub struct BasicExtension<T> {
    pub critical: bool,
    pub value: T,
}

impl<T> BasicExtension<T> {
    pub const fn new(critical: bool, value: T) -> Self {
        Self { critical, value }
    }
}

/// <pre>
/// Validity ::= SEQUENCE {
///     notBefore      Time,
///     notAfter       Time  }
/// </pre>
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
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
    pub fn time_to_expiration(&self) -> Option<Duration> {
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
        time >= self.not_before && time <= self.not_after
    }

    /// Check the certificate time validity
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.is_valid_at(ASN1Time::now())
    }
}

/// <pre>
/// UniqueIdentifier  ::=  BIT STRING
/// </pre>
#[derive(Clone, Debug, PartialEq, Eq, Alias)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct UniqueIdentifier(pub BitString);

impl UniqueIdentifier {
    // issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL
    fn parse_der_issuer(i: Input<'_>) -> IResult<Input<'_>, Option<Self>, X509Error> {
        Self::parse::<1>(i).map_err(|_| X509Error::InvalidIssuerUID.into())
    }

    // subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL
    fn parse_der_subject(i: Input<'_>) -> IResult<Input<'_>, Option<Self>, X509Error> {
        Self::parse::<2>(i).map_err(|_| X509Error::InvalidSubjectUID.into())
    }

    // Parse a [tag] UniqueIdentifier OPTIONAL
    //
    // UniqueIdentifier  ::=  BIT STRING
    fn parse<const TAG: u32>(
        i: Input<'_>,
    ) -> IResult<Input<'_>, Option<Self>, BerError<Input<'_>>> {
        let (rem, unique_id) = OptTaggedImplicit::<BitString, Error, TAG>::parse_der(i)?;
        let unique_id = unique_id.map(|u| UniqueIdentifier(u.into_inner()));
        Ok((rem, unique_id))
    }
}

#[cfg(test)]
mod tests {
    use asn1_rs::oid;

    use super::*;

    #[test]
    fn check_validity_expiration() {
        let mut v = Validity {
            not_before: ASN1Time::now(),
            not_after: ASN1Time::now(),
        };
        assert_eq!(v.time_to_expiration(), None);
        v.not_after = (v.not_after + Duration::new(60, 0)).unwrap();
        assert!(v.time_to_expiration().is_some());
        assert!(v.time_to_expiration().unwrap() <= Duration::new(60, 0));
        // The following assumes this timing won't take 10 seconds... I
        // think that is safe.
        assert!(v.time_to_expiration().unwrap() > Duration::new(50, 0));
    }

    #[test]
    fn extension_duplication() {
        let extensions = vec![
            X509Extension::new(
                oid! {1.2},
                true,
                Input::default(),
                ParsedExtension::Unparsed,
            ),
            X509Extension::new(
                oid! {1.3},
                true,
                Input::default(),
                ParsedExtension::Unparsed,
            ),
            X509Extension::new(
                oid! {1.2},
                true,
                Input::default(),
                ParsedExtension::Unparsed,
            ),
            X509Extension::new(
                oid! {1.4},
                true,
                Input::default(),
                ParsedExtension::Unparsed,
            ),
            X509Extension::new(
                oid! {1.4},
                true,
                Input::default(),
                ParsedExtension::Unparsed,
            ),
        ];

        let r2 = get_extension_unique(&extensions, &oid! {1.2});
        assert!(r2.is_err());
        let r3 = get_extension_unique(&extensions, &oid! {1.3});
        assert!(r3.is_ok());
        let r4 = get_extension_unique(&extensions, &oid! {1.4});
        assert!(r4.is_err());
    }
}
