use crate::error::{X509Error, X509Result};
use crate::extensions::*;
use crate::time::ASN1Time;
use crate::x509::{
    format_serial, parse_serial, AlgorithmIdentifier, ReasonCode, X509Name, X509Version,
};

#[cfg(feature = "verify")]
use crate::verify::verify_signature;
#[cfg(feature = "verify")]
use crate::x509::SubjectPublicKeyInfo;
use asn1_rs::num_bigint::BigUint;
use asn1_rs::{BitString, DerParser, FromDer, Header, Input, Sequence, Tag, Tagged};
use nom::{Err, IResult, Input as _};
use oid_registry::*;
use std::collections::HashMap;

/// An X.509 v2 Certificate Revocation List (CRL).
///
/// X.509 v2 CRLs are defined in [RFC5280](https://tools.ietf.org/html/rfc5280).
///
/// # Example
///
/// To parse a CRL and print information about revoked certificates:
///
/// ```rust
/// use x509_parser::prelude::FromDer;
/// use x509_parser::revocation_list::CertificateRevocationList;
///
/// # static DER: &'static [u8] = include_bytes!("../assets/example.crl");
/// #
/// # fn main() {
/// let res = CertificateRevocationList::from_der(DER);
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
///
/// <pre>
/// CertificateList  ::=  SEQUENCE  {
///      tbsCertList          TBSCertList,
///      signatureAlgorithm   AlgorithmIdentifier,
///      signatureValue       BIT STRING  }
/// </pre>
#[derive(Clone, Debug)]
pub struct CertificateRevocationList<'a> {
    pub tbs_cert_list: TbsCertList<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: BitString,

    pub(crate) raw: Input<'a>,
}

impl<'a> CertificateRevocationList<'a> {
    /// Get the version of the encoded certificate
    pub fn version(&self) -> Option<X509Version> {
        self.tbs_cert_list.version
    }

    /// Get the certificate issuer.
    #[inline]
    pub fn issuer(&self) -> &X509Name<'_> {
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

    /// Get the CRL extensions.
    #[inline]
    pub fn extensions(&self) -> &[X509Extension<'_>] {
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
        self.extensions()
            .iter()
            .find(|&ext| ext.oid == OID_X509_EXT_CRL_NUMBER)
            .and_then(|ext| match ext.parsed_extension {
                ParsedExtension::CRLNumber(ref num) => Some(num),
                _ => None,
            })
    }

    /// Return a reference to the raw bytes used to parse the Certificate Revocation List
    // Not using the AsRef trait, as that would not give back the full 'a lifetime
    pub fn as_raw(&self) -> &'a [u8] {
        self.raw.as_bytes2()
    }

    /// Return a reference to the raw input used to parse the Certificate Revocation List
    // Not using the AsRef trait, as that would not give back the full 'a lifetime
    pub fn as_raw_input(&self) -> Input<'a> {
        self.raw.clone()
    }

    /// Verify the cryptographic signature of this certificate revocation list
    ///
    /// `public_key` is the public key of the **signer**.
    ///
    /// Not all algorithms are supported, this function is limited to what `ring` supports.
    #[cfg(feature = "verify")]
    #[cfg_attr(docsrs, doc(cfg(feature = "verify")))]
    pub fn verify_signature(&self, public_key: &SubjectPublicKeyInfo) -> Result<(), X509Error> {
        verify_signature(
            public_key,
            &self.signature_algorithm,
            &self.signature_value,
            self.tbs_cert_list.raw.as_bytes2(),
        )
    }
}

impl Tagged for CertificateRevocationList<'_> {
    const CONSTRUCTED: bool = true;
    const TAG: Tag = Tag::Sequence;
}

impl<'a> DerParser<'a> for CertificateRevocationList<'a> {
    type Error = X509Error;

    fn parse_der(input: Input<'a>) -> IResult<Input<'a>, Self, Self::Error> {
        let orig_input = input.clone();
        let (rem, (header, content)) = Sequence::parse_der_as_input(input).map_err(Err::convert)?;
        let (_, mut cert_list) = Self::from_der_content(&header, content)?;
        // safe because this is parsed from same input and orig_input.len() > rem.len()
        let total_len = orig_input.len() - rem.len();
        // limit to real number of bytes, orig_input can contain more
        cert_list.raw = orig_input.take(total_len);
        Ok((rem, cert_list))
    }

    fn from_der_content(
        header: &'_ Header<'a>,
        input: Input<'a>,
    ) -> IResult<Input<'a>, Self, Self::Error> {
        header
            .assert_constructed_input(&input)
            .map_err(|e| Err::Error(e.into()))?;
        let orig_input = input.clone();
        let (rem, tbs_cert_list) = TbsCertList::parse_der(input)?;
        let (rem, signature_algorithm) = AlgorithmIdentifier::parse_der(rem)?;
        let (rem, signature_value) = BitString::parse_der(rem).map_err(Err::convert)?;
        // this is safe because `rem` is built from `orig_input`
        let raw = orig_input.take(rem.start() - orig_input.start());

        let cert = CertificateRevocationList {
            tbs_cert_list,
            signature_algorithm,
            signature_value,
            raw,
        };
        Ok((rem, cert))
    }
}

impl<'a> FromDer<'a, X509Error> for CertificateRevocationList<'a> {
    fn from_der(i: &'a [u8]) -> X509Result<'a, Self> {
        let input = Input::from(i);
        // run parser with default options
        match Self::parse_der(input) {
            Ok((rem, res)) => Ok((rem.as_bytes2(), res)),
            Err(e) => Err(e),
        }
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
#[derive(Clone, Debug, PartialEq)]
pub struct TbsCertList<'a> {
    pub version: Option<X509Version>,
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: X509Name<'a>,
    pub this_update: ASN1Time,
    pub next_update: Option<ASN1Time>,
    pub revoked_certificates: Vec<RevokedCertificate<'a>>,
    extensions: Vec<X509Extension<'a>>,
    /// `raw` is used for signature verification
    raw: Input<'a>,
    // raw: &'a [u8],
}

impl TbsCertList<'_> {
    /// Returns the certificate extensions
    #[inline]
    pub fn extensions(&self) -> &[X509Extension<'_>] {
        &self.extensions
    }

    /// Returns an iterator over the certificate extensions
    #[inline]
    pub fn iter_extensions(&self) -> impl Iterator<Item = &X509Extension<'_>> {
        self.extensions.iter()
    }

    /// Searches for an extension with the given `Oid`.
    ///
    /// Note: if there are several extensions with the same `Oid`, the first one is returned.
    pub fn find_extension(&self, oid: &Oid) -> Option<&X509Extension<'_>> {
        self.extensions.iter().find(|&ext| ext.oid == *oid)
    }

    /// Builds and returns a map of extensions.
    ///
    /// If an extension is present twice, this will fail and return `DuplicateExtensions`.
    pub fn extensions_map(&self) -> Result<HashMap<Oid<'_>, &X509Extension<'_>>, X509Error> {
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
}

impl AsRef<[u8]> for TbsCertList<'_> {
    fn as_ref(&self) -> &[u8] {
        self.raw.as_bytes2()
    }
}

impl Tagged for TbsCertList<'_> {
    const CONSTRUCTED: bool = true;
    const TAG: Tag = Tag::Sequence;
}

impl<'i> DerParser<'i> for TbsCertList<'i> {
    type Error = X509Error;

    fn parse_der(input: Input<'i>) -> IResult<Input<'i>, Self, Self::Error> {
        let orig_input = input.clone();

        let (rem, mut tbs) = Sequence::parse_der_and_then(input, |header, input| {
            Self::from_der_content(&header, input)
        })?;

        // update `raw` field to contain full sequence (including header)
        // this is safe because `rem` is built from `orig_input`
        let raw = orig_input.take(rem.start() - orig_input.start());
        tbs.raw = raw;
        Ok((rem, tbs))
    }

    fn from_der_content(
        header: &'_ Header<'i>,
        input: Input<'i>,
    ) -> IResult<Input<'i>, Self, Self::Error> {
        header
            .assert_constructed_input(&input)
            .map_err(|e| Err::Error(e.into()))?;

        let raw = input.clone();
        let (rem, version) = X509Version::parse_der_optional(input)?;
        let (rem, signature) = AlgorithmIdentifier::parse_der(rem)?;
        let (rem, issuer) = X509Name::parse_der(rem)?;
        let (rem, this_update) = ASN1Time::parse_der(rem)?;
        let (rem, next_update) = ASN1Time::parse_der_optional(rem)?;
        let (rem, revoked_certificates) = <Vec<RevokedCertificate>>::parse_der_optional(rem)?;
        let (rem, extensions) = parse_opt_tagged_extensions::<0>(rem)?;
        let tbs = TbsCertList {
            version,
            signature,
            issuer,
            this_update,
            next_update,
            revoked_certificates: revoked_certificates.unwrap_or_default(),
            extensions,
            raw,
        };
        Ok((rem, tbs))
    }
}

/// <pre>
/// revokedCertificates     SEQUENCE OF SEQUENCE  {
///     userCertificate         CertificateSerialNumber,
///     revocationDate          Time,
///     crlEntryExtensions      Extensions OPTIONAL
///                                   -- if present, MUST be v2
///                          }  OPTIONAL,
/// </pre>
#[derive(Clone, Debug, PartialEq)]
pub struct RevokedCertificate<'a> {
    /// The Serial number of the revoked certificate
    pub user_certificate: BigUint,
    /// The date on which the revocation occurred is specified.
    pub revocation_date: ASN1Time,
    /// Additional information about revocation
    extensions: Vec<X509Extension<'a>>,
    pub(crate) raw_serial: &'a [u8],
}

impl RevokedCertificate<'_> {
    /// Return the serial number of the revoked certificate
    pub fn serial(&self) -> &BigUint {
        &self.user_certificate
    }

    /// Get the CRL entry extensions.
    #[inline]
    pub fn extensions(&self) -> &[X509Extension<'_>] {
        &self.extensions
    }

    /// Returns an iterator over the CRL entry extensions
    #[inline]
    pub fn iter_extensions(&self) -> impl Iterator<Item = &X509Extension<'_>> {
        self.extensions.iter()
    }

    /// Searches for a CRL entry extension with the given `Oid`.
    ///
    /// Note: if there are several extensions with the same `Oid`, the first one is returned.
    pub fn find_extension(&self, oid: &Oid) -> Option<&X509Extension<'_>> {
        self.extensions.iter().find(|&ext| ext.oid == *oid)
    }

    /// Builds and returns a map of CRL entry extensions.
    ///
    /// If an extension is present twice, this will fail and return `DuplicateExtensions`.
    pub fn extensions_map(&self) -> Result<HashMap<Oid<'_>, &X509Extension<'_>>, X509Error> {
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

    /// Get the raw bytes of the certificate serial number
    pub fn raw_serial(&self) -> &[u8] {
        self.raw_serial
    }

    /// Get a formatted string of the certificate serial number, separated by ':'
    pub fn raw_serial_as_string(&self) -> String {
        format_serial(self.raw_serial)
    }

    /// Get the code identifying the reason for the revocation, if present
    pub fn reason_code(&self) -> Option<(bool, ReasonCode)> {
        self.find_extension(&OID_X509_EXT_REASON_CODE)
            .and_then(|ext| match ext.parsed_extension {
                ParsedExtension::ReasonCode(code) => Some((ext.critical, code)),
                _ => None,
            })
    }

    /// Get the invalidity date, if present
    ///
    /// The invalidity date is the date on which it is known or suspected that the private
    ///  key was compromised or that the certificate otherwise became invalid.
    pub fn invalidity_date(&self) -> Option<(bool, ASN1Time)> {
        self.find_extension(&OID_X509_EXT_INVALIDITY_DATE)
            .and_then(|ext| match ext.parsed_extension {
                ParsedExtension::InvalidityDate(date) => Some((ext.critical, date)),
                _ => None,
            })
    }
}

impl Tagged for RevokedCertificate<'_> {
    const CONSTRUCTED: bool = true;
    const TAG: Tag = Tag::Sequence;
}

impl<'i> DerParser<'i> for RevokedCertificate<'i> {
    type Error = X509Error;

    fn from_der_content(
        header: &'_ Header<'i>,
        input: Input<'i>,
    ) -> IResult<Input<'i>, Self, Self::Error> {
        header
            .assert_constructed_input(&input)
            .map_err(|e| Err::Error(e.into()))?;

        let (rem, (raw_serial, user_certificate)) = parse_serial(input)?;
        let (rem, revocation_date) = ASN1Time::parse_der(rem)?;
        let (rem, extensions) = <Vec<X509Extension>>::parse_der_optional(rem)?;
        let revoked = RevokedCertificate {
            user_certificate,
            revocation_date,
            extensions: extensions.unwrap_or_default(),
            raw_serial,
        };
        Ok((rem, revoked))
    }
}
