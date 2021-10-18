use crate::validate::*;
use crate::x509::*;
use der_parser::der::DerObjectContent;

#[derive(Debug)]
pub struct X509NameStructureValidator;

impl<'a> Validator<'a> for X509NameStructureValidator {
    type Item = X509Name<'a>;

    fn validate<L: Logger>(&self, item: &'a Self::Item, l: &'_ mut L) -> bool {
        let res = true;
        // subject/issuer: verify charsets
        // - wildcards in PrintableString
        // - non-IA5 in IA5String
        for attr in item.iter_attributes() {
            match attr.attr_value().content {
                DerObjectContent::PrintableString(s) | DerObjectContent::IA5String(s) => {
                    if !s.as_bytes().iter().all(u8::is_ascii) {
                        l.warn(&format!(
                            "Invalid charset in X.509 Name, component {}",
                            attr.attr_type()
                        ));
                    }
                }
                _ => (),
            }
        }
        res
    }
}
