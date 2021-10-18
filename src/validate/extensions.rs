use crate::extensions::*;
use crate::validate::*;
use std::collections::HashSet;

#[derive(Debug)]
pub struct X509ExtensionsValidator;

impl<'a> Validator<'a> for X509ExtensionsValidator {
    type Item = &'a [X509Extension<'a>];

    fn validate<L: Logger>(&self, item: &'a Self::Item, l: &'_ mut L) -> bool {
        let mut res = true;
        // check for duplicate extensions
        let mut m = HashSet::new();
        for ext in item.iter() {
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
