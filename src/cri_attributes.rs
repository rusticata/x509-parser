use crate::{error::X509Error, extensions::X509Extension};

use asn1_rs::{DerParser, Header, Input, Oid, Tag, Tagged};
use nom::Err;
use nom::Parser as _;
use nom::{IResult, Input as _};
use oid_registry::*;
use std::collections::HashMap;

/// Attributes for Certification Request
///
/// <pre>
/// Attribute               ::= SEQUENCE {
///     type             AttributeType,
///     values    SET OF AttributeValue }
///           -- at least one value is required
/// </pre>
#[derive(Clone, Debug, PartialEq)]
pub struct X509CriAttribute<'a> {
    /// Atribute identifier
    pub oid: Oid<'a>,
    /// Unparsed data
    pub value: Input<'a>,
    pub(crate) parsed_attribute: ParsedCriAttribute<'a>,
}

impl<'a> X509CriAttribute<'a> {
    /// Return the attribute type or `UnsupportedAttribute` if the attribute is unknown.
    #[inline]
    pub fn parsed_attribute(&self) -> &ParsedCriAttribute<'a> {
        &self.parsed_attribute
    }
}

impl Tagged for X509CriAttribute<'_> {
    const CONSTRUCTED: bool = true;
    const TAG: Tag = Tag::Sequence;
}

impl<'i> DerParser<'i> for X509CriAttribute<'i> {
    type Error = X509Error;

    fn from_der_content(
        header: &'_ Header<'i>,
        input: Input<'i>,
    ) -> IResult<Input<'i>, Self, Self::Error> {
        header
            .assert_constructed_input(&input)
            .map_err(|e| Err::Error(e.into()))?;

        let (rem, oid) = Oid::parse_der(input).map_err(Err::convert)?;
        let (rem, value) = rem.take_split(rem.input_len());
        let (_, parsed_attribute) = parser::parse_attribute(&oid, value.clone())
            .map_err(|_| Err::Error(X509Error::InvalidAttributes))?;

        let attribute = X509CriAttribute {
            oid,
            value,
            parsed_attribute,
        };
        Ok((rem, attribute))
    }
}

/// Section 3.1 of rfc 5272
#[derive(Clone, Debug, PartialEq)]
pub struct ExtensionRequest<'a> {
    pub extensions: Vec<X509Extension<'a>>,
}

// impl<'a> FromDer<'a, X509Error> for ExtensionRequest<'a> {
//     fn from_der(i: &'a [u8]) -> X509Result<'a, Self> {
//         parser::parse_extension_request(i).map_err(Err::convert)
//     }
// }

impl Tagged for ExtensionRequest<'_> {
    const CONSTRUCTED: bool = true;
    const TAG: Tag = Tag::Sequence;
}

impl<'i> DerParser<'i> for ExtensionRequest<'i> {
    type Error = X509Error;

    fn from_der_content(
        _: &'_ Header<'i>,
        input: Input<'i>,
    ) -> IResult<Input<'i>, Self, Self::Error> {
        parser::parse_extension_request(input)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChallengePassword(pub String);

/// Attributes for Certification Request
#[derive(Clone, Debug, PartialEq)]
pub enum ParsedCriAttribute<'a> {
    ChallengePassword(ChallengePassword),
    ExtensionRequest(ExtensionRequest<'a>),
    UnsupportedAttribute,
}

pub(crate) mod parser {
    use crate::cri_attributes::*;
    use crate::utils::DirectoryString;
    use asn1_rs::{DerParser, Input};
    // use der_parser::der::{
    //     parse_der_bmpstring, parse_der_printablestring, parse_der_t61string,
    //     parse_der_universalstring, parse_der_utf8string,
    // };
    use lazy_static::lazy_static;
    use nom::combinator::map;

    type AttrParser =
        for<'a> fn(Input<'a>) -> IResult<Input<'a>, ParsedCriAttribute<'a>, X509Error>;

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
        oid: &Oid,
        value: Input<'a>,
    ) -> IResult<Input<'a>, ParsedCriAttribute<'a>, X509Error> {
        if let Some(parser) = ATTRIBUTE_PARSERS.get(oid) {
            parser(value)
        } else {
            Ok((Input::default(), ParsedCriAttribute::UnsupportedAttribute))
        }
    }

    pub(super) fn parse_extension_request<'a>(
        input: Input<'a>,
    ) -> IResult<Input<'a>, ExtensionRequest<'a>, X509Error> {
        crate::extensions::parse_extension_sequence(input)
            .map(|(i, extensions)| (i, ExtensionRequest { extensions }))
    }

    fn parse_extension_request_attr<'a>(
        value: Input<'a>,
    ) -> IResult<Input<'a>, ParsedCriAttribute<'a>, X509Error> {
        map(
            parse_extension_request,
            ParsedCriAttribute::ExtensionRequest,
        )
        .parse(value)
    }

    // RFC 2985, 5.4.1 Challenge password
    //    challengePassword ATTRIBUTE ::= {
    //            WITH SYNTAX DirectoryString {pkcs-9-ub-challengePassword}
    //            EQUALITY MATCHING RULE caseExactMatch
    //            SINGLE VALUE TRUE
    //            ID pkcs-9-at-challengePassword
    //    }
    pub(super) fn parse_challenge_password<'a>(
        input: Input<'a>,
    ) -> IResult<Input<'a>, ChallengePassword, X509Error> {
        let (rem, ds) = DirectoryString::parse_der(input)
            .map_err(|_| Err::Error(X509Error::InvalidAttributes))?;

        Ok((rem, ChallengePassword(ds.to_string())))
    }

    fn parse_challenge_password_attr<'a>(
        value: Input<'a>,
    ) -> IResult<Input<'a>, ParsedCriAttribute<'a>, X509Error> {
        map(
            parse_challenge_password,
            ParsedCriAttribute::ChallengePassword,
        )
        .parse(value)
    }
}
