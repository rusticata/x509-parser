use std::collections::HashSet;

use der_parser::der::DerObjectContent;

use super::{Logger, Validator};
use crate::certificate::*;
use crate::extensions::{GeneralName, ParsedExtension};
use crate::x509::X509Version;

/// Default X.509 structure validator for `X509Certificate`
///
/// This [`Validator`] iterates the X.509 Certificate fields, and verifies the
/// DER encoding and structure:
/// - numbers with wrong encoding/sign (for ex. serial number)
/// - strings with characters not allowed in DER type (for ex. '*' in `PrintableString`)
///
/// # Examples
///
/// Validate structure, collect warnings and errors to a `Vec`:
///
/// ```
/// use x509_parser::certificate::X509Certificate;
/// use x509_parser::validate::*;
///
/// # #[allow(deprecated)]
/// #[cfg(feature = "validate")]
/// fn validate_certificate(x509: &X509Certificate<'_>) -> Result<(), &'static str> {
///     let mut logger = VecLogger::default();
///     println!("  Subject: {}", x509.subject());
///     // validate and print warnings and errors to stderr
///     let ok = X509StructureValidator::validate(&x509, &mut logger);
///     print!("Structure validation status: ");
///     if ok {
///         println!("Ok");
///     } else {
///         println!("FAIL");
///     }
///     for warning in logger.warnings() {
///         eprintln!("  [W] {}", warning);
///     }
///     for error in logger.errors() {
///         eprintln!("  [E] {}", error);
///     }
///     println!();
///     if !logger.errors().is_empty() {
///         return Err("validation failed");
///     }
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct X509StructureValidator;

impl<'a> Validator<'a> for X509StructureValidator {
    type Item = X509Certificate<'a>;

    fn validate<L: Logger>(item: &'a Self::Item, l: &'a mut L) -> bool {
        let mut res = true;
        res |= TbsCertificateStructureValidator::validate(&item.tbs_certificate, l);
        res
    }
}

/// Default X.509 structure validator for `TbsCertificate`
#[derive(Debug)]
pub struct TbsCertificateStructureValidator;

impl<'a> Validator<'a> for TbsCertificateStructureValidator {
    type Item = TbsCertificate<'a>;

    fn validate<L: Logger>(item: &'a Self::Item, l: &'a mut L) -> bool {
        let mut res = true;
        // version must be 0, 1 or 2
        if item.version.0 >= 3 {
            l.err("Invalid version");
            res = false;
        }
        // extensions require v3
        if !item.extensions().is_empty() && item.version != X509Version::V3 {
            l.err("Extensions present but version is not 3");
            res = false;
        }
        let b = item.raw_serial();
        if b.is_empty() {
            l.err("Serial is empty");
            res = false;
        } else {
            // check MSB of serial
            if b[0] & 0x80 != 0 {
                l.warn("Serial number is negative");
            }
            // check leading zeroes in serial
            if b.len() > 1 && b[0] == 0 && b[1] & 0x80 == 0 {
                l.warn("Leading zeroes in serial number");
            }
        }
        // subject/issuer: verify charsets
        // - wildcards in PrintableString
        // - non-IA5 in IA5String
        for attr in item.subject.iter_attributes() {
            match attr.attr_value().content {
                DerObjectContent::PrintableString(s) | DerObjectContent::IA5String(s) => {
                    if !s.as_bytes().iter().all(u8::is_ascii) {
                        l.warn(&format!(
                            "Invalid charset in 'Subject', component {}",
                            attr.attr_type()
                        ));
                    }
                }
                _ => (),
            }
        }
        // check for parse errors or unsupported extensions
        for ext in item.extensions() {
            if let ParsedExtension::UnsupportedExtension { .. } = &ext.parsed_extension {
                l.warn(&format!("Unsupported extension {}", ext.oid));
            }
            if let ParsedExtension::ParseError { error } = &ext.parsed_extension {
                l.err(&format!("Parse error in extension {}: {}", ext.oid, error));
                res = false;
            }
        }
        // check for duplicate extensions
        let mut m = HashSet::new();
        for ext in item.extensions() {
            if m.contains(&ext.oid) {
                l.err(&format!("Duplicate extension {}", ext.oid));
                res = false;
            } else {
                m.insert(ext.oid.clone());
            }
            // specific extension checks
            // SAN
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(ref s) | GeneralName::RFC822Name(ref s) => {
                            // should be an ia5string
                            if !s.as_bytes().iter().all(u8::is_ascii) {
                                l.warn(&format!("Invalid charset in 'SAN' entry '{}'", s));
                            }
                        }
                        _ => (),
                    }
                }
            }
        }
        res
    }
}
