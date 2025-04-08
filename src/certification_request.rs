use crate::cri_attributes::*;
use crate::error::{X509Error, X509Result};
use crate::extensions::*;
use crate::x509::{
    parse_signature_value, AlgorithmIdentifier, SubjectPublicKeyInfo, X509Name, X509Version,
};

#[cfg(feature = "verify")]
use crate::verify::verify_signature;
use asn1_rs::{
    BitString, DerParser, FromDer, Header, Input, Oid, OptTaggedImplicit, Sequence, Tag, Tagged,
};
use nom::{Err, IResult, Input as _};
use std::collections::HashMap;

/// Certification Signing Request (CSR)
///
/// <pre>
/// CertificationRequest ::= SEQUENCE {
///     certificationRequestInfo CertificationRequestInfo,
///     signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
///     signature          BIT STRING
/// }
/// </pre>
#[derive(Debug, PartialEq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct X509CertificationRequest<'a> {
    pub certification_request_info: X509CertificationRequestInfo<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    #[asn1(parse = "parse_signature_value")]
    pub signature_value: BitString,
}

impl X509CertificationRequest<'_> {
    /// Return an iterator over the Requested Extensions
    ///
    /// The requested extensions can be specified in different attributes, each attribute being a set of values.
    /// The iterator will go through every value of type 'ExtensionRequest` of every attribute.
    ///
    /// The returned iterator can be empty.
    ///
    /// _Note_: only successfully parsed values are returned (invalid extensions are *not* returned)
    pub fn requested_extensions(&self) -> impl Iterator<Item = &ParsedExtension> {
        // iterator on all attribute, and flatten for each value of attribute
        self.certification_request_info
            .iter_attributes()
            .flat_map(|cri_attribute| {
                // return an iterator matching ExtensionRequest only
                cri_attribute
                    .parsed_attributes()
                    .iter()
                    .filter_map(|p| {
                        if let ParsedCriAttribute::ExtensionRequest(r) = &p {
                            Some(r.extensions.iter().map(|ext| &ext.parsed_extension))
                        } else {
                            None
                        }
                    })
                    .flatten()
            })
    }

    /// Verify the cryptographic signature of this certification request
    ///
    /// Uses the public key contained in the CSR, which must be the one of the entity
    /// requesting the certification for this verification to succeed.
    #[cfg(feature = "verify")]
    pub fn verify_signature(&self) -> Result<(), X509Error> {
        let spki = &self.certification_request_info.subject_pki;
        verify_signature(
            spki,
            &self.signature_algorithm,
            &self.signature_value,
            self.certification_request_info.raw.as_bytes2(),
        )
    }
}

/// <pre>
/// CertificationRequest ::= SEQUENCE {
///     certificationRequestInfo CertificationRequestInfo,
///     signatureAlgorithm AlgorithmIdentifier{{ SignatureAlgorithms }},
///     signature          BIT STRING
/// }
/// </pre>
impl<'a> FromDer<'a, X509Error> for X509CertificationRequest<'a> {
    fn from_der(i: &'a [u8]) -> X509Result<'a, Self> {
        let input = Input::from(i);
        // run parser with default options
        match Self::parse_der(input) {
            Ok((rem, res)) => Ok((rem.as_bytes2(), res)),
            Err(e) => Err(e),
        }
    }
}

/// Certification Request Info structure (RFC 2986 Section 4.1)
///
/// Certification request information is defined by the following ASN.1 structure:
///
/// <pre>
/// -- IMPLICIT tags
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
#[derive(Debug, PartialEq)]
pub struct X509CertificationRequestInfo<'a> {
    pub version: X509Version,
    pub subject: X509Name<'a>,
    pub subject_pki: SubjectPublicKeyInfo<'a>,
    attributes: Vec<X509CriAttribute<'a>>,
    /// `raw` is used for signature verification
    raw: Input<'a>,
}

impl X509CertificationRequestInfo<'_> {
    /// Get the CRL entry extensions.
    #[inline]
    pub fn attributes(&self) -> &[X509CriAttribute] {
        &self.attributes
    }

    /// Returns an iterator over the CRL entry extensions
    #[inline]
    pub fn iter_attributes(&self) -> impl Iterator<Item = &X509CriAttribute> {
        self.attributes.iter()
    }

    /// Searches for a CRL entry extension with the given `Oid`.
    ///
    /// Note: if there are several extensions with the same `Oid`, the first one is returned.
    pub fn find_attribute(&self, oid: &Oid) -> Option<&X509CriAttribute> {
        self.attributes.iter().find(|&ext| ext.oid == *oid)
    }

    /// Builds and returns a map of CRL entry extensions.
    ///
    /// If an extension is present twice, this will fail and return `DuplicateExtensions`.
    pub fn attributes_map(&self) -> Result<HashMap<Oid, &X509CriAttribute>, X509Error> {
        self.attributes
            .iter()
            .try_fold(HashMap::new(), |mut m, ext| {
                if m.contains_key(&ext.oid) {
                    return Err(X509Error::DuplicateAttributes);
                }
                m.insert(ext.oid.clone(), ext);
                Ok(m)
            })
    }

    /// Return a pointer to the raw data
    pub fn raw(&self) -> &[u8] {
        self.raw.as_bytes2()
    }
}

impl Tagged for X509CertificationRequestInfo<'_> {
    const CONSTRUCTED: bool = true;
    const TAG: Tag = Tag::Sequence;
}

impl<'i> DerParser<'i> for X509CertificationRequestInfo<'i> {
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
        let (rem, version) = X509Version::parse_der(input)?;
        let (rem, subject) = X509Name::parse_der(rem)?;
        let (rem, subject_pki) = SubjectPublicKeyInfo::parse_der(rem)?;
        let (rem, opt_attributes) =
            <OptTaggedImplicit<Vec<X509CriAttribute>, X509Error, 0>>::parse_der(rem)?;
        let attributes = opt_attributes.map(|o| o.into_inner()).unwrap_or_default();

        let tbs = X509CertificationRequestInfo {
            version,
            subject,
            subject_pki,
            attributes,
            raw,
        };
        Ok((rem, tbs))
    }
}
