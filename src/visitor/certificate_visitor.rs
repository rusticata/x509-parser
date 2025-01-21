use asn1_rs::BitString;
use oid_registry::*;

use crate::certificate::*;
use crate::extensions::*;
use crate::x509::*;

/// Visitor pattern for [`X509Certificate`]
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
/// use x509_parser::prelude::*;
/// use x509_parser::visitor::X509CertificateVisitor;
/// #[derive(Debug, Default)]
/// struct SubjectIssuerVisitor {
///     issuer: String,
///     subject: String,
///     is_ca: bool,
/// }
///
/// impl X509CertificateVisitor for SubjectIssuerVisitor {
///     fn visit_issuer(&mut self, name: &X509Name<'_>) {
///         self.issuer = name.to_string();
///     }
///
///     fn visit_subject(&mut self, name: &X509Name<'_>) {
///         self.subject = name.to_string();
///     }
///
///     fn visit_extension_basic_constraints(&mut self, bc: &BasicConstraints) {
///         self.is_ca = bc.ca;
///     }
/// }
/// ```
pub trait X509CertificateVisitor {
    /// Run the provided visitor (`self`) over the [`X509Certificate`] object
    fn walk(&mut self, x509: &X509Certificate)
    where
        Self: Sized,
    {
        x509.walk(self);
    }

    /// Invoked for the "TBSCertificate" field of the X.509 Certificate, before visiting children
    fn visit_tbs_certificate(&mut self, _tbs: &TbsCertificate) {}

    /// Invoked for the "signatureAlgorithm" field of the X.509 Certificate
    ///
    /// Note: this is the "signatureAlgorithm" in the "Certificate" sequence. According to the
    /// specifications, it should be equal to "signature" field from the "TBSCertificate" sequence.
    fn visit_signature_algorithm(&mut self, _algorithm: &AlgorithmIdentifier) {}

    /// Invoked for the "signatureValue" field of the TBSCertificate
    fn visit_signature_value(&mut self, _signature: &BitString) {}

    /// Invoked for the "version" field of the TBSCertificate
    fn visit_version(&mut self, _version: &X509Version) {}

    /// Invoked for the "serialNumber" field of the TBSCertificate
    fn visit_serial_number(&mut self, _serial: &[u8]) {}

    /// Invoked for the "signature" field of the TBSCertificate
    ///
    /// Note: this is the "signature" field from the "TBSCertificate" sequence. According to the
    /// specifications, it should be equal to "signatureAlgorithm" in the "Certificate" sequence.
    fn visit_tbs_signature_algorithm(&mut self, _algorithm: &AlgorithmIdentifier) {}

    /// Invoked for the "issuer" field of the TBSCertificate
    fn visit_issuer(&mut self, _name: &X509Name) {}

    /// Invoked for the "validity" field of the TBSCertificate
    fn visit_validity(&mut self, _validity: &Validity) {}

    /// Invoked for the "subject" field of the TBSCertificate
    fn visit_subject(&mut self, _name: &X509Name) {}

    /// Invoked for the "subjectPublicKeyInfo" field of the TBSCertificate
    fn visit_subject_public_key_info(&mut self, _subject_pki: &SubjectPublicKeyInfo) {}

    /// Invoked for the "issuerUniqueID" field of the TBSCertificate
    fn visit_issuer_unique_id(&mut self, _id: Option<&UniqueIdentifier>) {}

    /// Invoked for the "subjectUniqueID" field of the TBSCertificate
    fn visit_subject_unique_id(&mut self, _id: Option<&UniqueIdentifier>) {}

    /// Invoked for extensions, before visiting children
    fn pre_visit_extensions(&mut self, _extensions: &[X509Extension]) {}

    /// Invoked for any extension that appear in the X.509 Certificate
    ///
    /// Note: this method may be redundant with any other extension visitor method
    fn visit_extension(&mut self, _extension: &X509Extension) {}

    /// Invoked for extensions, after visiting children
    fn post_visit_extensions(&mut self, _extensions: &[X509Extension]) {}

    /// Invoked for the "Authority Key Identifier" (if present)
    fn visit_extension_aki(&mut self, _aki: &AuthorityKeyIdentifier) {}

    /// Invoked for the "Subject Key Identifier" (if present)
    fn visit_extension_ski(&mut self, _id: &KeyIdentifier) {}

    /// Invoked for the "Key Usage" (if present)
    fn visit_extension_key_usage(&mut self, _usage: &KeyUsage) {}

    /// Invoked for the "Certificate Policies" (if present)
    fn visit_extension_certificate_policies(&mut self, _policies: &CertificatePolicies) {}

    /// Invoked for the "Subject Alternative Name" (if present)
    fn visit_extension_subject_alternative_name(&mut self, _san: &SubjectAlternativeName) {}

    /// Invoked for the "Issuer Alternative Name" (if present)
    fn visit_extension_issuer_alternative_name(&mut self, _ian: &IssuerAlternativeName) {}

    /// Invoked for the "Basic Constraints" (if present)
    fn visit_extension_basic_constraints(&mut self, _bc: &BasicConstraints) {}

    /// Invoked for the "Name Constraints" (if present)
    fn visit_extension_name_constraints(&mut self, _constraints: &NameConstraints) {}

    /// Invoked for the "Policy Constraints" (if present)
    fn visit_extension_policy_constraints(&mut self, _constraints: &PolicyConstraints) {}

    /// Invoked for the "Extended Key Usage" (if present)
    fn visit_extension_extended_key_usage(&mut self, _usage: &ExtendedKeyUsage) {}

    /// Invoked for the "CRL Distribution Points" (if present)
    fn visit_extension_crl_distribution_points(&mut self, _crl: &CRLDistributionPoints) {}

    /// Invoked for the "Inhibit anyPolicy" (if present)
    fn visit_extension_inhibit_anypolicy(&mut self, _policy: &InhibitAnyPolicy) {}

    /// Invoked for the "Authority Information Access" (if present)
    fn visit_extension_authority_information_access(&mut self, _info: &AuthorityInfoAccess) {}

    /// Invoked for the "Signed Certificate Timestamp" (SCT) (if present)
    fn visit_extension_sct(&mut self, _sct: &[SignedCertificateTimestamp]) {}
}

impl X509Certificate<'_> {
    /// Run the provided [`X509CertificateVisitor`] over the X.509 Certificate (`self`)
    pub fn walk<V: X509CertificateVisitor>(&self, visitor: &mut V) {
        visitor.visit_tbs_certificate(&self.tbs_certificate);
        self.tbs_certificate.walk(visitor);
        visitor.visit_signature_algorithm(&self.signature_algorithm);
        visitor.visit_signature_value(&self.signature_value);
    }
}

impl TbsCertificate<'_> {
    /// Run the provided `visitor` over the [`TbsCertificate`] object
    pub fn walk<V: X509CertificateVisitor>(&self, visitor: &mut V) {
        visitor.visit_version(&self.version);
        visitor.visit_serial_number(self.raw_serial());
        visitor.visit_tbs_signature_algorithm(&self.signature);
        visitor.visit_issuer(&self.issuer);
        visitor.visit_validity(&self.validity);
        visitor.visit_subject(&self.subject);
        visitor.visit_subject_public_key_info(&self.subject_pki);
        visitor.visit_issuer_unique_id(self.issuer_uid.as_ref());
        visitor.visit_subject_unique_id(self.subject_uid.as_ref());
        visitor.pre_visit_extensions(self.extensions());
        for extension in self.extensions() {
            visitor.visit_extension(extension);

            if extension.oid == OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER {
                if let ParsedExtension::AuthorityKeyIdentifier(aki) = &extension.parsed_extension {
                    visitor.visit_extension_aki(aki);
                }
            } else if extension.oid == OID_X509_EXT_SUBJECT_KEY_IDENTIFIER {
                if let ParsedExtension::SubjectKeyIdentifier(id) = &extension.parsed_extension {
                    visitor.visit_extension_ski(id);
                }
            } else if extension.oid == OID_X509_EXT_KEY_USAGE {
                if let ParsedExtension::KeyUsage(usage) = &extension.parsed_extension {
                    visitor.visit_extension_key_usage(usage);
                }
            } else if extension.oid == OID_X509_EXT_CERTIFICATE_POLICIES {
                if let ParsedExtension::CertificatePolicies(policies) = &extension.parsed_extension
                {
                    visitor.visit_extension_certificate_policies(policies);
                }
            } else if extension.oid == OID_X509_EXT_SUBJECT_ALT_NAME {
                if let ParsedExtension::SubjectAlternativeName(san) = &extension.parsed_extension {
                    visitor.visit_extension_subject_alternative_name(san);
                }
            } else if extension.oid == OID_X509_EXT_ISSUER_ALT_NAME {
                if let ParsedExtension::IssuerAlternativeName(ian) = &extension.parsed_extension {
                    visitor.visit_extension_issuer_alternative_name(ian);
                }
            } else if extension.oid == OID_X509_EXT_BASIC_CONSTRAINTS {
                if let ParsedExtension::BasicConstraints(bc) = &extension.parsed_extension {
                    visitor.visit_extension_basic_constraints(bc);
                }
            } else if extension.oid == OID_X509_EXT_NAME_CONSTRAINTS {
                if let ParsedExtension::NameConstraints(constraints) = &extension.parsed_extension {
                    visitor.visit_extension_name_constraints(constraints);
                }
            } else if extension.oid == OID_X509_EXT_POLICY_CONSTRAINTS {
                if let ParsedExtension::PolicyConstraints(constraints) = &extension.parsed_extension
                {
                    visitor.visit_extension_policy_constraints(constraints);
                }
            } else if extension.oid == OID_X509_EXT_EXTENDED_KEY_USAGE {
                if let ParsedExtension::ExtendedKeyUsage(usage) = &extension.parsed_extension {
                    visitor.visit_extension_extended_key_usage(usage);
                }
            } else if extension.oid == OID_X509_EXT_CRL_DISTRIBUTION_POINTS {
                if let ParsedExtension::CRLDistributionPoints(crl) = &extension.parsed_extension {
                    visitor.visit_extension_crl_distribution_points(crl);
                }
            } else if extension.oid == OID_X509_EXT_INHIBITANT_ANY_POLICY {
                if let ParsedExtension::InhibitAnyPolicy(policy) = &extension.parsed_extension {
                    visitor.visit_extension_inhibit_anypolicy(policy);
                }
            } else if extension.oid == OID_PKIX_AUTHORITY_INFO_ACCESS {
                if let ParsedExtension::AuthorityInfoAccess(info) = &extension.parsed_extension {
                    visitor.visit_extension_authority_information_access(info);
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

    static IGCA_DER: &[u8] = include_bytes!("../../assets/IGC_A.der");

    #[test]
    fn visitor_certificate() {
        #[derive(Debug, Default)]
        struct SubjectIssuerVisitor {
            issuer: String,
            subject: String,
            is_ca: bool,
        }

        impl X509CertificateVisitor for SubjectIssuerVisitor {
            fn visit_issuer(&mut self, name: &X509Name) {
                self.issuer = name.to_string();
            }

            fn visit_subject(&mut self, name: &X509Name) {
                self.subject = name.to_string();
            }

            fn visit_extension_basic_constraints(&mut self, bc: &BasicConstraints) {
                self.is_ca = bc.ca;
            }
        }

        let mut visitor = SubjectIssuerVisitor::default();
        let (_, x509) = X509Certificate::from_der(IGCA_DER).unwrap();

        x509.walk(&mut visitor);
        assert!(!visitor.issuer.is_empty());
        assert!(visitor.is_ca);
        assert_eq!(&visitor.issuer, &visitor.subject);
    }
}
