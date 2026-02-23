use crate::validate::*;
use crate::x509::*;
use asn1_rs::Tag;

#[derive(Debug)]
pub struct X509NameStructureValidator;

impl<'a> Validator<'a> for X509NameStructureValidator {
    type Item = X509Name<'a>;

    fn validate<L: Logger>(&self, item: &'a Self::Item, l: &'_ mut L) -> bool {
        let mut res = true;
        // subject/issuer: verify charsets
        // - wildcards in PrintableString
        // - non-IA5 in IA5String
        for attr in item.iter_attributes() {
            match attr.attr_value().tag() {
                Tag::PrintableString | Tag::Ia5String => {
                    let b = attr.attr_value().as_bytes();
                    if !b.iter().all(u8::is_ascii) {
                        l.warn(&format!(
                            "Invalid charset in X.509 Name, component {}",
                            attr.attr_type()
                        ));
                        res = false;
                    }
                }
                _ => (),
            }
        }
        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::{AttributeTypeAndValue, RelativeDistinguishedName, X509Name};
    use asn1_rs::{Any, Input, Tag};

    /// Helper to build an X509Name with a single attribute using the given tag and data.
    fn make_name(tag: Tag, data: &[u8]) -> X509Name<'_> {
        X509Name::new(
            vec![RelativeDistinguishedName::new(vec![
                AttributeTypeAndValue::new(
                    asn1_rs::oid!(2.5.4 .3), // commonName
                    Any::from_tag_and_data(tag, data.into()),
                ),
            ])],
            Input::default(),
        )
    }

    #[test]
    fn valid_printable_string_returns_true() {
        let name = make_name(Tag::PrintableString, b"example.com");
        let mut logger = VecLogger::default();
        let result = X509NameStructureValidator.validate(&name, &mut logger);
        assert!(result);
        assert!(logger.warnings().is_empty());
    }

    #[test]
    fn valid_ia5_string_returns_true() {
        let name = make_name(Tag::Ia5String, b"test@example.com");
        let mut logger = VecLogger::default();
        let result = X509NameStructureValidator.validate(&name, &mut logger);
        assert!(result);
        assert!(logger.warnings().is_empty());
    }

    #[test]
    fn non_ascii_printable_string_returns_false() {
        // 0xFF is not valid ASCII
        let name = make_name(Tag::PrintableString, &[0x74, 0x65, 0x73, 0x74, 0xFF]);
        let mut logger = VecLogger::default();
        let result = X509NameStructureValidator.validate(&name, &mut logger);
        assert!(
            !result,
            "validator must return false for non-ASCII bytes in PrintableString"
        );
        assert_eq!(logger.warnings().len(), 1);
        assert!(logger.warnings()[0].contains("Invalid charset"));
    }

    #[test]
    fn non_ascii_ia5_string_returns_false() {
        // 0x80 is not valid ASCII
        let name = make_name(Tag::Ia5String, &[0x68, 0x69, 0x80]);
        let mut logger = VecLogger::default();
        let result = X509NameStructureValidator.validate(&name, &mut logger);
        assert!(
            !result,
            "validator must return false for non-ASCII bytes in IA5String"
        );
        assert_eq!(logger.warnings().len(), 1);
        assert!(logger.warnings()[0].contains("Invalid charset"));
    }

    #[test]
    fn utf8_string_is_not_checked() {
        // Non-ASCII in a UTF8String should not trigger the validator (it only checks
        // PrintableString and IA5String).
        let name = make_name(Tag::Utf8String, &[0xC3, 0xA9]); // 'e' with acute accent
        let mut logger = VecLogger::default();
        let result = X509NameStructureValidator.validate(&name, &mut logger);
        assert!(result);
        assert!(logger.warnings().is_empty());
    }
}
