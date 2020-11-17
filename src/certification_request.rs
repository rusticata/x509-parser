use std::collections::HashMap;

use der_parser::ber::*;
use der_parser::oid::Oid;
use der_parser::*;
use nom::Offset;
#[cfg(feature = "verify")]
use oid_registry::*;

use crate::cri_attributes::*;
#[cfg(feature = "verify")]
use crate::error::X509Error;
use crate::error::X509Result;
use crate::extensions::*;
use crate::x509::{
    parse_signature_value, AlgorithmIdentifier, SubjectPublicKeyInfo, X509Name, X509Version,
};

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
            let (i, signature_value) = parse_signature_value(i)?;
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
