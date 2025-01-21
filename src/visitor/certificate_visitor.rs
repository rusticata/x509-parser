use asn1_rs::BitString;

use crate::certificate::*;
use crate::extensions::*;
use crate::x509::*;

/// Visitor pattern for [`X509Certificate`]
pub trait X509CertificateVisitor {
    /// Invoked for the "TBSCertificate" field of the X.509 Certificate, before visiting children
    fn visit_tbs_certificate(&mut self, _tbs: &TbsCertificate) {}

    /// Invoked for the "signatureAlgorithm" field of the X.509 Certificate
    ///
    /// Note: this is the "signatureAlgorithm" in the "Certificate" sequence. According to the
    /// specifications, it should be equal to "signature" field from the "TBSCertificate" sequence.
    fn visit_signature_algorithm(&mut self, _algorithm: &AlgorithmIdentifier) {}

    /// Invoked for the "signatureValue" field of the X.509 Certificate
    fn visit_signature_value(&mut self, _signature: &BitString) {}

    /// Invoked for the "version" field of the X.509 Certificate
    fn visit_version(&mut self, _version: &X509Version) {}

    /// Invoked for the "serialNumber" field of the X.509 Certificate
    fn visit_serial_number(&mut self, _serial: &[u8]) {}

    /// Invoked for the "signature" field of the X.509 Certificate
    ///
    /// Note: this is the "signature" field from the "TBSCertificate" sequence. According to the
    /// specifications, it should be equal to "signatureAlgorithm" in the "Certificate" sequence.
    fn visit_tbs_signature_algorithm(&mut self, _algorithm: &AlgorithmIdentifier) {}

    /// Invoked for the "issuer" field of the X.509 Certificate
    fn visit_issuer(&mut self, _name: &X509Name) {}

    /// Invoked for the "validity" field of the X.509 Certificate
    fn visit_validity(&mut self, _validity: &Validity) {}

    /// Invoked for the "subject" field of the X.509 Certificate
    fn visit_subject(&mut self, _name: &X509Name) {}

    /// Invoked for the "subjectPublicKeyInfo" field of the X.509 Certificate
    fn visit_subject_public_key_info(&mut self, _subject_pki: &SubjectPublicKeyInfo) {}

    /// Invoked for the "issuerUniqueID" field of the X.509 Certificate
    fn visit_issuer_unique_id(&mut self, _id: Option<&UniqueIdentifier>) {}

    /// Invoked for the "subjectUniqueID" field of the X.509 Certificate
    fn visit_subject_unique_id(&mut self, _id: Option<&UniqueIdentifier>) {}

    /// Invoked for extensions, before visiting children
    fn pre_visit_extensions(&mut self, _extensions: &[X509Extension]) {}

    /// Invoked for any extension that appear in the X.509 Certificate
    fn visit_extension(&mut self, _extension: &X509Extension) {}

    /// Invoked for extensions, after visiting children
    fn post_visit_extensions(&mut self, _extensions: &[X509Extension]) {}
}

impl X509Certificate<'_> {
    /// Run the provided `visitor` over the [`X509Certificate`] object
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
        }
        visitor.post_visit_extensions(self.extensions());
    }
}
