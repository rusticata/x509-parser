use asn1_rs::BitString;
use der_parser::num_bigint::BigUint;
use oid_registry::*;

use crate::extensions::*;
use crate::revocation_list::*;
use crate::time::ASN1Time;
use crate::x509::*;

/// Visitor pattern for [`CertificateRevocationList`]
///
/// # Extensions
///
/// Visitor methods are provided for extensions, both in a generic way (receiving a [`X509Extension`]
/// object) and in a specific way for standard extensions (for ex, `visit_extension_aki` receives a
/// [`AuthorityKeyIdentifier`]).
///
/// For a specific method to be called, the extension OID must be correct and the extension must be
/// successfully parsed as the specific type.
///
/// A specific method can be called multiple times, if the extension is present multiple times.
///
/// Extension parsing methods are redundant. This is not a problem because default methods do nothing,
/// but if a trait implementation provides several `visit_extension...` methods it must be aware
/// that it will visit the same extension multiple times.
///
/// # Example
///
/// ```rust
/// use der_parser::num_bigint::BigUint;
/// use x509_parser::prelude::*;
/// use x509_parser::visitor::CertificateRevocationListVisitor;
/// #[derive(Debug, Default)]
/// struct RevokedCertsVisitor {
///     certificates: Vec<BigUint>,
/// }
///
/// impl CertificateRevocationListVisitor for RevokedCertsVisitor {
///     fn visit_revoked_certificate(&mut self, certificate: &RevokedCertificate<'_>) {
///         self.certificates.push(certificate.user_certificate.clone());
///     }
/// }
/// ```
pub trait CertificateRevocationListVisitor {
    /// Run the provided visitor (`self`) over the Certificate Revocation List
    fn walk(&mut self, crl: &CertificateRevocationList)
    where
        Self: Sized,
    {
        crl.walk(self);
    }

    /// Invoked for the "tbsCertList" field of the Certificate Revocation List, before visiting children
    fn visit_tbs_cert_list(&mut self, _tbs: &TbsCertList) {}

    /// Invoked for the "signatureAlgorithm" field of the Certificate Revocation List
    ///
    /// Note: this is the "signatureAlgorithm" in the "CertificateList" sequence. According to the
    /// specifications, it should be equal to "signature" field from the "TBSCertificate" sequence.
    fn visit_signature_algorithm(&mut self, _algorithm: &AlgorithmIdentifier) {}

    /// Invoked for the "signatureValue" field of the TBSCertList
    fn visit_signature_value(&mut self, _signature: &BitString) {}

    /// Invoked for the "version" field of the TBSCertList
    fn visit_version(&mut self, _version: Option<&X509Version>) {}

    /// Invoked for the "signature" field of the TBSCertList
    ///
    /// Note: this is the "signature" field from the "TBSCertList" sequence. According to the
    /// specifications, it should be equal to "signatureAlgorithm" in the "CertificateList" sequence.
    fn visit_tbs_signature_algorithm(&mut self, _algorithm: &AlgorithmIdentifier) {}

    /// Invoked for the "issuer" field of the TBSCertList
    fn visit_issuer(&mut self, _name: &X509Name) {}

    /// Invoked for the "thisUpdate" field of the TBSCertList
    fn visit_this_update(&mut self, _time: &ASN1Time) {}

    /// Invoked for the "nextUpdate" field of the TBSCertList
    fn visit_next_update(&mut self, _time: Option<&ASN1Time>) {}

    /// Invoked for revoked certificate that appear in the TBSCertList
    fn visit_revoked_certificates(&mut self, _certificate: &[RevokedCertificate]) {}

    /// Invoked for any revoked certificates that appear in the TBSCertList
    ///
    /// Note: this function is redundant with `visit_revoked_certificates`
    fn visit_revoked_certificate(&mut self, _certificate: &RevokedCertificate) {}

    /// Invoked for extensions, before visiting children
    fn pre_visit_extensions(&mut self, _extensions: &[X509Extension]) {}

    /// Invoked for any extension that appear in the TBSCertList
    ///
    /// Note: this method may be redundant with any other extension visitor method
    fn visit_extension(&mut self, _extension: &X509Extension) {}

    /// Invoked for extensions, after visiting children
    fn post_visit_extensions(&mut self, _extensions: &[X509Extension]) {}

    /// Invoked for the "Authority Key Identifier" (if present)
    fn visit_extension_aki(&mut self, _aki: &AuthorityKeyIdentifier) {}

    /// Invoked for the "Issuer Alternative Name" (if present)
    fn visit_extension_issuer_alternative_name(&mut self, _ian: &IssuerAlternativeName) {}

    /// Invoked for the "CRL Number" (if present)
    fn visit_extension_crl_number(&mut self, _number: &BigUint) {}

    /// Invoked for the "Issuing Distribution Point" (if present)
    fn visit_extension_issuing_distribution_point(&mut self, _dp: &IssuingDistributionPoint) {}

    /// Invoked for the "Authority Information Access" (if present)
    fn visit_extension_authority_information_access(&mut self, _info: &AuthorityInfoAccess) {}

    /// Invoked for the "Reason Code" (if present)
    fn visit_extension_reason_code(&mut self, _code: &ReasonCode) {}

    /// Invoked for the "Invalidity Date" (if present)
    fn visit_extension_invalidity_date(&mut self, _time: &ASN1Time) {}

    /// Invoked for the "Signed Certificate Timestamp" (SCT) (if present)
    fn visit_extension_sct(&mut self, _sct: &[SignedCertificateTimestamp]) {}
}

impl CertificateRevocationList<'_> {
    /// Run the provided [`CertificateRevocationListVisitor`] over the Certificate Revocation List (`self`)
    pub fn walk<V: CertificateRevocationListVisitor>(&self, visitor: &mut V) {
        visitor.visit_tbs_cert_list(&self.tbs_cert_list);
        self.tbs_cert_list.walk(visitor);
        visitor.visit_signature_algorithm(&self.signature_algorithm);
        visitor.visit_signature_value(&self.signature_value);
    }
}

impl TbsCertList<'_> {
    /// Run the provided `visitor` over the [`TbsCertList`] object
    pub fn walk<V: CertificateRevocationListVisitor>(&self, visitor: &mut V) {
        visitor.visit_version(self.version.as_ref());
        visitor.visit_tbs_signature_algorithm(&self.signature);
        visitor.visit_issuer(&self.issuer);
        visitor.visit_this_update(&self.this_update);
        visitor.visit_next_update(self.next_update.as_ref());
        visitor.visit_revoked_certificates(&self.revoked_certificates);
        for certificate in &self.revoked_certificates {
            visitor.visit_revoked_certificate(certificate);
        }
        visitor.pre_visit_extensions(self.extensions());
        for extension in self.extensions() {
            visitor.visit_extension(extension);

            if extension.oid == OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER {
                if let ParsedExtension::AuthorityKeyIdentifier(aki) = &extension.parsed_extension {
                    visitor.visit_extension_aki(aki);
                }
            } else if extension.oid == OID_X509_EXT_ISSUER_ALT_NAME {
                if let ParsedExtension::IssuerAlternativeName(ian) = &extension.parsed_extension {
                    visitor.visit_extension_issuer_alternative_name(ian);
                }
            } else if extension.oid == OID_X509_EXT_CRL_NUMBER {
                if let ParsedExtension::CRLNumber(number) = &extension.parsed_extension {
                    visitor.visit_extension_crl_number(number);
                }
            } else if extension.oid == OID_X509_EXT_ISSUER_DISTRIBUTION_POINT {
                if let ParsedExtension::IssuingDistributionPoint(dp) = &extension.parsed_extension {
                    visitor.visit_extension_issuing_distribution_point(dp);
                }
            } else if extension.oid == OID_PKIX_AUTHORITY_INFO_ACCESS {
                if let ParsedExtension::AuthorityInfoAccess(info) = &extension.parsed_extension {
                    visitor.visit_extension_authority_information_access(info);
                }
            } else if extension.oid == OID_X509_EXT_REASON_CODE {
                if let ParsedExtension::ReasonCode(code) = &extension.parsed_extension {
                    visitor.visit_extension_reason_code(code);
                }
            } else if extension.oid == OID_X509_EXT_INVALIDITY_DATE {
                if let ParsedExtension::InvalidityDate(time) = &extension.parsed_extension {
                    visitor.visit_extension_invalidity_date(time);
                }
            } else if extension.oid == OID_CT_LIST_SCT {
                if let ParsedExtension::SCT(sct) = &extension.parsed_extension {
                    visitor.visit_extension_sct(sct);
                }
            }
        }
        visitor.post_visit_extensions(self.extensions());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FromDer;

    static CRL: &[u8] = include_bytes!("../../assets/example.crl");

    #[test]
    fn visitor_crl() {
        #[derive(Debug, Default)]
        struct RevokedCertsVisitor {
            certificates: Vec<BigUint>,
        }

        impl CertificateRevocationListVisitor for RevokedCertsVisitor {
            fn visit_revoked_certificate(&mut self, certificate: &RevokedCertificate) {
                self.certificates.push(certificate.user_certificate.clone());
            }
        }

        let mut visitor = RevokedCertsVisitor::default();
        let (_, crl) = CertificateRevocationList::from_der(CRL).unwrap();

        crl.walk(&mut visitor);
        assert_eq!(visitor.certificates.len(), 5);
    }
}
