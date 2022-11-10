use crate::{
    error::{X509Error, X509Result},
    extensions::X509Extension,
};

use asn1_rs::{Error, FromDer, Header, Oid, Sequence, Tag};
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

impl<'a> FromDer<'a, X509Error> for X509CriAttribute<'a> {
    fn from_der(i: &'a [u8]) -> X509Result<X509CriAttribute> {
        Sequence::from_ber_and_then(i, |i| {
            let (i, oid) = Oid::from_der(i)?;
            let value_start = i;
            let (i, hdr) = Header::from_der(i)?;
            if hdr.tag() != Tag::Set {
                return Err(Err::Error(Error::BerTypeError));
            };

            let (i, parsed_attribute) = crate::cri_attributes::parser::parse_attribute(i, &oid)
                .map_err(|_| Err::Error(Error::BerValueError))?;
            let ext = X509CriAttribute {
                oid,
                value: &value_start[..value_start.len() - i.len()],
                parsed_attribute,
            };
            Ok((i, ext))
        })
        .map_err(|_| X509Error::InvalidAttributes.into())
    }
}

/// Section 3.1 of rfc 5272
#[derive(Clone, Debug, PartialEq)]
pub struct ExtensionRequest<'a> {
    pub extensions: Vec<X509Extension<'a>>,
}

impl<'a> FromDer<'a, X509Error> for ExtensionRequest<'a> {
    fn from_der(i: &'a [u8]) -> X509Result<'a, Self> {
        parser::parse_extension_request(i).map_err(Err::convert)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ChallengePassword(String);

/// Attributes for Certification Request
#[derive(Clone, Debug, PartialEq)]
pub enum ParsedCriAttribute<'a> {
    ChallengePassword(ChallengePassword),
    ExtensionRequest(ExtensionRequest<'a>),
    UnsupportedAttribute,
}

pub(crate) mod parser {
    use crate::cri_attributes::*;
    use der_parser::ber::BerObjectContent;
    use der_parser::der::{parse_der_printablestring, parse_der_utf8string};
    use lazy_static::lazy_static;
    use nom::combinator::map;

    type AttrParser = fn(&[u8]) -> X509Result<ParsedCriAttribute>;

    lazy_static! {
        static ref ATTRIBUTE_PARSERS: HashMap<Oid<'static>, AttrParser> = {
            macro_rules! add {
                ($m:ident, $oid:ident, $p:ident) => {
                    $m.insert($oid, $p as AttrParser);
                };
            }

            let mut m = HashMap::new();
            add!(m, OID_PKCS9_EXTENSION_REQUEST, parse_extension_request_attr);
            add!(
                m,
                OID_PKCS9_CHALLENGE_PASSWORD,
                parse_challenge_password_attr
            );
            m
        };
    }

    // look into the parser map if the extension is known, and parse it
    // otherwise, leave it as UnsupportedExtension
    pub(crate) fn parse_attribute<'a>(
        i: &'a [u8],
        oid: &Oid,
    ) -> X509Result<'a, ParsedCriAttribute<'a>> {
        if let Some(parser) = ATTRIBUTE_PARSERS.get(oid) {
            parser(i)
        } else {
            Ok((i, ParsedCriAttribute::UnsupportedAttribute))
        }
    }

    pub(super) fn parse_extension_request(i: &[u8]) -> X509Result<ExtensionRequest> {
        crate::extensions::parse_extension_sequence(i)
            .map(|(i, extensions)| (i, ExtensionRequest { extensions }))
    }

    fn parse_extension_request_attr(i: &[u8]) -> X509Result<ParsedCriAttribute> {
        map(
            parse_extension_request,
            ParsedCriAttribute::ExtensionRequest,
        )(i)
    }

    pub(super) fn parse_challenge_password(i: &[u8]) -> X509Result<ChallengePassword> {
        // I'm sure, there is a more elegant way to try multiple parsers until the first succeeds,
        // but I don't know nom well enough to implement it.
        let (rem, obj) = {
            if let Ok((rem, obj)) = parse_der_utf8string(i) {
                (rem, obj)
            } else if let Ok((rem, obj)) = parse_der_printablestring(i) {
                (rem, obj)
            } else {
                return Err(Err::Error(X509Error::InvalidAttributes));
            }
        };
        match obj.content {
            BerObjectContent::PrintableString(s) | BerObjectContent::UTF8String(s) => {
                Ok((rem, ChallengePassword { 0: s.to_string() }))
            }
            _ => Err(Err::Error(X509Error::InvalidAttributes)),
        }
    }

    fn parse_challenge_password_attr(i: &[u8]) -> X509Result<ParsedCriAttribute> {
        map(
            parse_challenge_password,
            ParsedCriAttribute::ChallengePassword,
        )(i)
    }
}

pub(crate) fn parse_cri_attributes(i: &[u8]) -> X509Result<Vec<X509CriAttribute>> {
    let (i, hdr) = Header::from_der(i).map_err(|_| Err::Error(X509Error::InvalidAttributes))?;
    if i.is_empty() {
        return Ok((i, Vec::new()));
    }
    let constructed = if hdr.constructed() { 1 } else { 0 };
    (0..constructed)
        .into_iter()
        .try_fold((i, Vec::new()), |(i, mut attrs), _| {
            let (rem, attr) = X509CriAttribute::from_der(i)?;
            attrs.push(attr);
            Ok((rem, attrs))
        })
}
