use crate::{
    error::{X509Error, X509Result},
    extensions::X509Extension,
    traits::FromDer,
};

use der_parser::der::{
    der_read_element_header, parse_der_oid, parse_der_sequence_defined_g, DerTag,
};
use der_parser::error::BerError;
use der_parser::oid::Oid;
use nom::combinator::map_res;
use nom::Err;
use oid_registry::*;
use std::collections::HashMap;

/// Attributes for Certification Request
#[derive(Clone, Debug, PartialEq)]
pub struct X509CriAttribute<'a> {
    pub oid: Oid<'a>,
    pub value: &'a [u8],
    pub(crate) parsed_attribute: ParsedCriAttribute<'a>,
}

impl<'a> FromDer<'a> for X509CriAttribute<'a> {
    fn from_der(i: &'a [u8]) -> X509Result<X509CriAttribute> {
        parse_der_sequence_defined_g(|i, _| {
            let (i, oid) = map_res(parse_der_oid, |x| x.as_oid_val())(i)?;
            let value_start = i;
            let (i, hdr) = der_read_element_header(i)?;
            if hdr.tag != DerTag::Set {
                return Err(Err::Error(BerError::BerTypeError));
            };

            let (i, parsed_attribute) = crate::cri_attributes::parser::parse_attribute(i, &oid)?;
            let ext = X509CriAttribute {
                oid,
                value: &value_start[..value_start.len() - i.len()],
                parsed_attribute,
            };
            Ok((i, ext))
        })(i)
        .map_err(|_| X509Error::InvalidAttributes.into())
    }
}

/// Section 3.1 of rfc 5272
#[derive(Clone, Debug, PartialEq)]
pub struct ExtensionRequest<'a> {
    pub extensions: Vec<X509Extension<'a>>,
}

impl<'a> FromDer<'a> for ExtensionRequest<'a> {
    fn from_der(i: &'a [u8]) -> X509Result<'a, Self> {
        parser::parse_extension_request(i).map_err(Err::convert)
    }
}

/// Attributes for Certification Request
#[derive(Clone, Debug, PartialEq)]
pub enum ParsedCriAttribute<'a> {
    ExtensionRequest(ExtensionRequest<'a>),
    UnsupportedAttribute,
}

pub(crate) mod parser {
    use crate::cri_attributes::*;
    use der_parser::error::BerError;
    use der_parser::{oid::Oid, *};
    use lazy_static::lazy_static;
    use nom::combinator::map;
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
            add!(m, OID_PKCS9_EXTENSION_REQUEST, parse_extension_request_ext);
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

    pub(super) fn parse_extension_request(i: &[u8]) -> IResult<&[u8], ExtensionRequest, BerError> {
        crate::extensions::parse_extension_sequence(i)
            .map(|(i, extensions)| (i, ExtensionRequest { extensions }))
            .map_err(|_| Err::Error(BerError::BerTypeError))
    }

    fn parse_extension_request_ext(i: &[u8]) -> IResult<&[u8], ParsedCriAttribute, BerError> {
        map(
            parse_extension_request,
            ParsedCriAttribute::ExtensionRequest,
        )(i)
    }
}

pub(crate) fn parse_cri_attributes(i: &[u8]) -> X509Result<Vec<X509CriAttribute>> {
    let (i, hdr) = der_read_element_header(i).or(Err(Err::Error(X509Error::InvalidAttributes)))?;
    if i.is_empty() {
        return Ok((i, Vec::new()));
    }
    (0..hdr.structured)
        .into_iter()
        .try_fold((i, Vec::new()), |(i, mut attrs), _| {
            let (rem, attr) = X509CriAttribute::from_der(i)?;
            attrs.push(attr);
            Ok((rem, attrs))
        })
}
