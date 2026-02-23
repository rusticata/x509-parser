use super::{Logger, Validator, X509NameStructureValidator};
use crate::certificate::*;
use crate::extensions::{GeneralName, ParsedExtension};
use crate::public_key::PublicKey;
use crate::x509::{SubjectPublicKeyInfo, X509Version};

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
///     let ok = X509StructureValidator.validate(&x509, &mut logger);
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
#[derive(Debug, Default)]
pub struct X509StructureValidator;

impl<'a> Validator<'a> for X509StructureValidator {
    type Item = X509Certificate<'a>;

    fn validate<L: Logger>(&self, item: &'a Self::Item, l: &'_ mut L) -> bool {
        let mut res = true;
        res &= TbsCertificateStructureValidator.validate(&item.tbs_certificate, l);
        res
    }
}

/// Default X.509 structure validator for `TbsCertificate`
#[derive(Debug, Default)]
pub struct TbsCertificateStructureValidator;

impl<'a> Validator<'a> for TbsCertificateStructureValidator {
    type Item = TbsCertificate<'a>;

    // Tell clippy to _not_ suggest merging a long `if` check into an already long pattern match
    #[expect(clippy::collapsible_match)]
    fn validate<L: Logger>(&self, item: &'a Self::Item, l: &'_ mut L) -> bool {
        let mut res = true;
        // version must be 0, 1 or 2
        if item.version.0 >= 3 {
            l.err("Invalid version");
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
        res &= X509NameStructureValidator.validate(&item.subject, l);
        res &= X509NameStructureValidator.validate(&item.issuer, l);
        // subject public key
        res &= X509PublicKeyValidator.validate(&item.subject_pki, l);
        // validity: dates <= 2049 must use UTCTime, >= 2050 must use GeneralizedTime
        let validity = item.validity();
        let year_notbefore = validity.not_before.to_datetime().year();
        if year_notbefore <= 2049 {
            if !validity.not_before.is_utctime() {
                l.warn("year <= 2049 should use UTCTime (notBefore)");
            }
        } else if !validity.not_before.is_generalizedtime() {
            l.warn("year >= 2050 should use GeneralizedTime (notBefore)");
        }
        let year_notafter = validity.not_after.to_datetime().year();
        if year_notafter <= 2049 {
            if !validity.not_after.is_utctime() {
                l.warn("year <= 2049 should use UTCTime (notAfter)");
            }
        } else if !validity.not_after.is_generalizedtime() {
            l.warn("year >= 2050 should use GeneralizedTime (notAfter)");
        }
        if item.version == X509Version::V1 {
            // unique identifiers: version must 2 or 3
            if item.issuer_uid.is_some() {
                l.warn("issuerUniqueID present but version 1");
            }
            if item.subject_uid.is_some() {
                l.warn("subjectUniqueID present but version 1");
            }
        }
        // extensions require v3
        if !item.extensions().is_empty() && item.version != X509Version::V3 {
            l.err("Extensions present but version is not 3");
            res = false;
        }
        // check for parse errors or unsupported extensions
        // RFC 5280 4.2: "if a certificate contains a critical extension that
        // is not recognized, it MUST be rejected"
        for ext in item.extensions() {
            if let ParsedExtension::UnsupportedExtension { .. } = &ext.parsed_extension {
                if ext.critical {
                    l.err(&format!("Unsupported critical extension {}", ext.oid));
                    res = false;
                } else {
                    l.warn(&format!("Unsupported extension {}", ext.oid));
                }
            }
            if let ParsedExtension::ParseError { error } = &ext.parsed_extension {
                l.err(&format!("Parse error in extension {}: {}", ext.oid, error));
                res = false;
            }
        }
        // check extensions
        for ext in item.extensions() {
            // specific extension checks
            // SAN
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for name in san.general_names() {
                    match name {
                        GeneralName::DNSName(ref s) | GeneralName::RFC822Name(ref s) => {
                            // should be an ia5string
                            if !s.as_bytes().iter().all(u8::is_ascii) {
                                l.warn(&format!("Invalid charset in 'SAN' entry '{s}'"));
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

#[derive(Debug, Default)]
pub struct X509PublicKeyValidator;

impl<'a> Validator<'a> for X509PublicKeyValidator {
    type Item = SubjectPublicKeyInfo<'a>;

    fn validate<L: Logger>(&self, item: &'a Self::Item, l: &'_ mut L) -> bool {
        let mut res = true;
        // res &= TbsCertificateStructureValidator.validate(&item.tbs_certificate, l);
        match item.parsed() {
            Ok(PublicKey::RSA(rsa)) => {
                if rsa.modulus[0] & 0x80 != 0 {
                    l.warn("Public key: (RSA) modulus is negative");
                }
                if rsa.exponent[0] & 0x80 != 0 {
                    l.warn("Public key: (RSA) exponent is negative");
                }
            }
            Ok(PublicKey::Unknown(_b)) => {
                l.warn("Unknown public key type");
            }
            Ok(_) => {}
            Err(_) => {
                l.err("Invalid public key");
                res = false;
            }
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;

    #[test]
    fn validate_unsupported_noncritical_extension_warns() {
        let der = include_bytes!("../../assets/unsupported_noncritical_ext.der");
        let (_, cert) = X509Certificate::from_der(der).expect("could not parse certificate");
        let mut logger = VecLogger::default();
        let res = TbsCertificateStructureValidator.validate(&cert.tbs_certificate, &mut logger);

        // Unsupported non-critical extension should produce a warning but not fail
        assert!(
            res,
            "validator should return true for non-critical unsupported extension"
        );
        assert!(
            logger
                .warnings()
                .iter()
                .any(|w| w.contains("Unsupported extension")),
            "expected warning about unsupported extension, got: {:?}",
            logger.warnings()
        );
        assert!(
            !logger
                .errors()
                .iter()
                .any(|e| e.contains("Unsupported critical extension")),
            "should not have critical extension error for non-critical extension"
        );
    }

    #[test]
    fn validate_unsupported_critical_extension_errors() {
        let der = include_bytes!("../../assets/unsupported_critical_ext.der");
        let (_, cert) = X509Certificate::from_der(der).expect("could not parse certificate");
        let mut logger = VecLogger::default();
        let res = TbsCertificateStructureValidator.validate(&cert.tbs_certificate, &mut logger);

        // Unsupported critical extension must cause validation failure per RFC 5280 4.2
        assert!(
            !res,
            "validator should return false for critical unsupported extension"
        );
        assert!(
            logger
                .errors()
                .iter()
                .any(|e| e.contains("Unsupported critical extension")),
            "expected error about unsupported critical extension, got: {:?}",
            logger.errors()
        );
    }

    #[test]
    fn validate_known_good_certificate() {
        let der = include_bytes!("../../assets/IGC_A.der");
        let (_, cert) = X509Certificate::from_der(der).expect("could not parse certificate");
        let mut logger = VecLogger::default();
        let res = X509StructureValidator.validate(&cert, &mut logger);

        // Known good certificate should pass validation
        assert!(
            res,
            "IGC_A.der should pass validation, errors: {:?}",
            logger.errors()
        );
        assert!(
            !logger
                .errors()
                .iter()
                .any(|e| e.contains("Unsupported critical extension")),
            "known good cert should not have unsupported critical extension errors"
        );
    }
}
