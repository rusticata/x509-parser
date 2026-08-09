use asn1_rs::{Any, Input, Oid};

use crate::certification_request::*;
use crate::cri_attributes::*;
use crate::x509::{SubjectPublicKeyInfo, X509Name, X509Version};

/// Visitor pattern for [`X509CertificationRequestInfo`]
///
/// The trait lifetime is the lifetime of the Certification Request Info (CRI).
/// It is required so the visitor object (the implementer) can declare that
/// it will outlive the CRI, allowing it to keep references on attribute data.
///
/// To visit the attribute values, see the [`X509CriAttributeVisitor`] trait.
///
/// # Examples
///
/// The following visitor implementation will count the number of attributes from this
/// Certification Request Info.
///
/// ```rust
/// use x509_parser::prelude::*;
/// use x509_parser::visitor::X509CertificationRequestInfoVisitor;
///
/// #[derive(Default)]
/// struct CRIVisitor {
///     num_attributes: usize,
/// }
///
/// impl X509CertificationRequestInfoVisitor<'_> for CRIVisitor {
///     fn visit_attribute(&mut self, attribute: &X509CriAttribute<'_>) {
///         self.num_attributes += 1;
///     }
///
///     fn visit_subject(&mut self, name: &X509Name<'_>) {
///         eprintln!("{name:?}");
///     }
/// }
/// ```
#[allow(unused_variables)]
pub trait X509CertificationRequestInfoVisitor<'cri> {
    /// Run the provided visitor (`self`) over the [`X509CertificationRequestInfo`] object
    fn walk(&mut self, cri: &'cri X509CertificationRequestInfo)
    where
        Self: Sized,
    {
        cri.walk(self);
    }

    /// Invoked for the "version" field of the Certification Request Info
    fn visit_version(&mut self, version: &'cri X509Version) {}

    /// Invoked for the "subject" field of the Certification Request Info
    fn visit_subject(&mut self, name: &'cri X509Name) {}

    /// Invoked for the "subjectPublicKeyInfo" field of the Certification Request Info
    fn visit_subject_public_key_info(&mut self, subject_pki: &'cri SubjectPublicKeyInfo) {}

    /// Invoked for attributes, before visiting children
    fn pre_visit_attributes(&mut self, attributes: &'cri [X509CriAttribute]) {}

    /// Invoked for any attribute that appear in the X.509 Certification Request Info
    ///
    /// To visit the attribute values, see the [`X509CriAttributeVisitor`] trait.
    ///
    /// Note: this method may be redundant with any other attribute visitor method
    fn visit_attribute(&mut self, attribute: &'cri X509CriAttribute) {}

    /// Invoked for attributes, after visiting children
    fn post_visit_attributes(&mut self, attributes: &'cri [X509CriAttribute]) {}
}

impl X509CertificationRequestInfo<'_> {
    /// Run the provided [`X509CertificationRequestInfoVisitor`] over the X.509 Certification Request Info (`self`)
    pub fn walk<'cri, V: X509CertificationRequestInfoVisitor<'cri>>(&'cri self, visitor: &mut V) {
        let v = visitor;
        v.visit_version(&self.version);
        v.visit_subject(&self.subject);
        v.visit_subject_public_key_info(&self.subject_pki);

        v.pre_visit_attributes(self.attributes());
        for attribute in self.attributes() {
            v.visit_attribute(attribute);
        }
        v.post_visit_attributes(self.attributes());
    }
}

/// Visitor pattern for [`X509CriAttribute`]
///
/// An Attribute contains a `SET OF AttributeValue`. Different methods are provided:
/// - `visit_raw_input`: inspects the raw `SET` contents (unparsed)
/// - `visit_raw_value`: inspects each raw `AttributeValue` (parsed as `ANY`) from the SET
/// - `visit_attribute_...`: inspect a parsed `AttributeValue` with a specific type
///
/// Note that some methods are (voluntarily) redundant, as they provide alternative methods
/// to handle data. This is not a problem because default methods do nothing,
/// but if a trait implementation provides methods for ex visiting both raw input and parsed attributes,
/// it must be aware that it will visit the same attributes multiple times.
///
/// The trait lifetime is the lifetime of the CRI Attribute. It is required so the visitor object
/// (the implementer) can declare that it will outlive the Attribute, allowing it to keep
/// references on attribute data.
///
/// # Examples
///
/// This visitor implementation will count the number of values in the attribute, and display
/// extension requests.
///
/// ```rust
/// use asn1_rs::Any;
/// use x509_parser::prelude::*;
/// use x509_parser::visitor::X509CriAttributeVisitor;
///
/// #[derive(Default)]
/// struct CRIAttributeVisitor {
///     num_extensions: usize,
/// }
///
/// impl X509CriAttributeVisitor<'_> for CRIAttributeVisitor {
///     fn visit_raw_value(&mut self, _value: Any<'_>) {
///         self.num_extensions += 1;
///     }
///
///     fn visit_attribute_extension_request(&mut self, extension_request: &ExtensionRequest<'_>) {
///         eprintln!("{extension_request:?}");
///     }
/// }
/// ```
#[allow(unused_variables)]
pub trait X509CriAttributeVisitor<'a> {
    /// Run the provided visitor (`self`) over the [`X509CriAttribute`] object
    fn walk(&mut self, attribute: &'a X509CriAttribute)
    where
        Self: Sized,
    {
        attribute.walk(self);
    }

    /// Invoked for the "oid" field of the Certification Request Info Attribute
    fn visit_oid(&mut self, oid: &'a Oid) {}

    /// Invoked for the raw input (unparsed) of the Certification Request Info Attribute
    ///
    /// The raw value contains a SET (without header) of ASN.1 values
    ///
    /// See also [X509CriAttributeVisitor::visit_raw_value] (called for each value from the raw input).
    fn visit_raw_input(&mut self, input: &'a Input) {}

    /// Invoked for each raw value (unparsed) of the Certification Request Info Attribute
    ///
    /// Note that if a particular value could not be parsed, this method will not be called.
    /// To iterate on the raw input of the attribute, use [X509CriAttributeVisitor::visit_raw_input].
    ///
    /// Note: this method may be redundant with any other attribute visitor method
    fn visit_raw_value(&mut self, value: Any<'a>) {}

    /// Invoked for each `ChallengePassword` value of the Certification Request Info Attribute
    fn visit_attribute_challenge_password(&mut self, challenge_password: &'a ChallengePassword) {}

    /// Invoked for each `ExtensionRequest` value of the Certification Request Info Attribute
    fn visit_attribute_extension_request(&mut self, extension_request: &'a ExtensionRequest<'a>) {}

    // NOTE: to be called when UnsupportedAttribute contains some data
    // /// Invoked for each Unsupported attribute of the Certification Request Info Attribute
    // fn visit_attribute_unsupported_attribute(&mut self, _unsupported_attribute: &UnsupportedAttribute) {}
}

impl X509CriAttribute<'_> {
    /// Run the provided [`X509CriAttributeVisitor`] over the X.509 Certification Request Info Attribute (`self`)
    pub fn walk<'a, V: X509CriAttributeVisitor<'a>>(&'a self, visitor: &mut V) {
        let v = visitor;
        v.visit_oid(&self.oid);
        v.visit_raw_input(&self.value);
        for (_, value) in self.iter_raw_values().flatten() {
            v.visit_raw_value(value);
        }
        for parsed_attribute in self.parsed_attributes() {
            match parsed_attribute {
                ParsedCriAttribute::ChallengePassword(challenge_password) => {
                    v.visit_attribute_challenge_password(challenge_password)
                }
                ParsedCriAttribute::ExtensionRequest(extension_request) => {
                    v.visit_attribute_extension_request(extension_request)
                }
                ParsedCriAttribute::UnsupportedAttribute => (),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use asn1_rs::{DerParser, Input};

    use crate::{pem::Pem, prelude::X509Extension};

    use super::*;

    const CSR_TEST: &str = "assets/test.csr";

    #[test]
    fn csr_visitors() {
        #[derive(Default)]
        struct CRIAttributeVisitor {
            num_extensions: usize,
        }

        impl X509CriAttributeVisitor<'_> for CRIAttributeVisitor {
            fn visit_attribute_extension_request(&mut self, extension_request: &ExtensionRequest) {
                eprintln!("{extension_request:?}");

                self.num_extensions += 1;
            }
        }

        #[derive(Default)]
        struct CRIVisitor {
            num_attributes: usize,
            num_extensions: usize,
        }

        impl X509CertificationRequestInfoVisitor<'_> for CRIVisitor {
            fn visit_attribute(&mut self, attribute: &X509CriAttribute) {
                let mut v = CRIAttributeVisitor::default();
                v.walk(attribute);

                self.num_attributes += 1;
                self.num_extensions += v.num_extensions;
            }
        }

        let data = std::fs::read(CSR_TEST).expect("Could not read CSR file");

        let pem_iter = Pem::iter_from_buffer(&data);
        let mut v = CRIVisitor::default();

        for entry in pem_iter {
            let entry = entry.expect("error in PEM data");
            let (_, csr) = X509CertificationRequest::parse_der(Input::from(&entry.contents))
                .expect("Parsing CSR failed");

            v.walk(&csr.certification_request_info);
        }

        assert_eq!(v.num_attributes, 1);
        assert_eq!(v.num_extensions, 1);
    }

    /// This test checks the possibility to define a visitor storing references to parsed data
    #[test]
    fn csr_visitor_zero_copy() {
        #[derive(Default)]
        struct CRIAttributeVisitor<'a> {
            extensions: Vec<&'a X509Extension<'a>>,

            raw_values: Vec<Any<'a>>,
        }

        impl<'v, 'a> X509CriAttributeVisitor<'a> for CRIAttributeVisitor<'v>
        where
            'a: 'v,
        {
            fn visit_attribute_extension_request(
                &mut self,
                extension_request: &'a ExtensionRequest,
            ) {
                // eprintln!("{extension_request:?}");

                for ext in &extension_request.extensions {
                    self.extensions.push(ext);
                }
            }

            fn visit_raw_value(&mut self, value: Any<'a>) {
                self.raw_values.push(value);
            }
        }

        #[derive(Default)]
        struct CRIVisitor {
            num_attributes: usize,
            num_raw_values: usize,
        }

        impl X509CertificationRequestInfoVisitor<'_> for CRIVisitor {
            fn visit_attribute(&mut self, attribute: &X509CriAttribute) {
                let mut v = CRIAttributeVisitor::default();
                v.walk(attribute);

                self.num_attributes += 1;
                self.num_raw_values += v.raw_values.len();

                for &ext in &v.extensions {
                    // eprintln!("{ext:?}");
                    let _ = ext;
                }
                for raw_value in &v.raw_values {
                    // eprintln!("{raw_value:?}");
                    let _ = raw_value;
                }
            }
        }

        let data = std::fs::read(CSR_TEST).expect("Could not read CSR file");

        let pem_iter = Pem::iter_from_buffer(&data);
        let mut v = CRIVisitor::default();

        for entry in pem_iter {
            let entry = entry.expect("error in PEM data");
            let (_, csr) = X509CertificationRequest::parse_der(Input::from(&entry.contents))
                .expect("Parsing CSR failed");

            v.walk(&csr.certification_request_info);
        }

        assert_eq!(v.num_attributes, 1);
        assert_eq!(v.num_raw_values, 1);
    }
}
