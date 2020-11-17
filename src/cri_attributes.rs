use std::collections::HashMap;

use der_parser::oid::Oid;
use oid_registry::*;

use crate::extensions::X509Extension;

/// Section 3.1 of rfc 5272
#[derive(Debug, PartialEq)]
pub struct ExtensionRequest<'a> {
    pub extensions: HashMap<Oid<'a>, X509Extension<'a>>,
}

/// Attributes for Certification Request
#[derive(Debug, PartialEq)]
pub enum ParsedCriAttribute<'a> {
    ExtensionRequest(ExtensionRequest<'a>),
    UnsupportedAttribute,
}

pub(crate) mod parser {
    use crate::cri_attributes::*;
    use der_parser::error::BerError;
    use der_parser::{oid::Oid, *};
    use lazy_static::lazy_static;
    use nom::{Err, IResult};

    type AttrParser = fn(&[u8]) -> IResult<&[u8], ParsedCriAttribute, BerError>;

    lazy_static! {
        static ref ATTRIBUTE_PARSERS: HashMap<Oid<'static>, AttrParser> = {
            macro_rules! add {
                ($m:ident, $oid:ident, $p:ident) => {
                    $m.insert($oid, $p as AttrParser);
                };
            }

            let mut m = HashMap::new();
            add!(m, OID_PKCS9_EXTENSION_REQUEST, parse_extension_request);
            m
        };
    }

    // look into the parser map if the extension is known, and parse it
    // otherwise, leave it as UnsupportedExtension
    pub(crate) fn parse_attribute<'a>(
        i: &'a [u8],
        oid: &Oid,
    ) -> IResult<&'a [u8], ParsedCriAttribute<'a>, BerError> {
        if let Some(parser) = ATTRIBUTE_PARSERS.get(oid) {
            parser(i)
        } else {
            Ok((i, ParsedCriAttribute::UnsupportedAttribute))
        }
    }

    fn parse_extension_request<'a>(
        i: &'a [u8],
    ) -> IResult<&'a [u8], ParsedCriAttribute<'a>, BerError> {
        crate::extensions::parse_extension_sequence(i)
            .and_then(|(i, extensions)| {
                crate::extensions::extensions_sequence_to_map(i, extensions)
            })
            .map(|(i, extensions)| {
                (
                    i,
                    ParsedCriAttribute::ExtensionRequest(ExtensionRequest { extensions }),
                )
            })
            .map_err(|_| Err::Error(BerError::BerTypeError))
    }
}
