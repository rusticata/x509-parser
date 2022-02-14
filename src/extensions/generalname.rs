use super::UnparsedObject;
use crate::error::X509Result;
use crate::prelude::format_serial;
use crate::traits::FromDer;
use crate::x509::X509Name;
use der_parser::der::*;
use der_parser::error::BerError;
use der_parser::oid::Oid;
use nom::bytes::streaming::take;
use nom::combinator::{all_consuming, verify};
use nom::{Err, IResult, Needed};
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
/// Represents a GeneralName as defined in RFC5280. There
/// is no support X.400 addresses and EDIPartyName.
///
/// String formats are not validated.
pub enum GeneralName<'a> {
    OtherName(Oid<'a>, &'a [u8]),
    /// More or less an e-mail, the format is not checked.
    RFC822Name(&'a str),
    /// A hostname, format is not checked.
    DNSName(&'a str),
    /// X400Address,
    X400Address(UnparsedObject<'a>),
    /// RFC5280 defines several string types, we always try to parse as utf-8
    /// which is more or less a superset of the string types.
    DirectoryName(X509Name<'a>),
    /// EDIPartyName
    EDIPartyName(UnparsedObject<'a>),
    /// An uniform resource identifier. The format is not checked.
    URI(&'a str),
    /// An ip address, provided as encoded.
    IPAddress(&'a [u8]),
    RegisteredID(Oid<'a>),
}

impl<'a> FromDer<'a> for GeneralName<'a> {
    fn from_der(i: &'a [u8]) -> X509Result<'a, Self> {
        parse_generalname(i).map_err(Err::convert)
    }
}

impl<'a> fmt::Display for GeneralName<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GeneralName::OtherName(oid, _) => write!(f, "OtherName({}, [...])", oid),
            GeneralName::RFC822Name(s) => write!(f, "RFC822Name({})", s),
            GeneralName::DNSName(s) => write!(f, "DNSName({})", s),
            GeneralName::X400Address(_) => write!(f, "X400Address(<unparsed>)"),
            GeneralName::DirectoryName(dn) => write!(f, "DirectoryName({})", dn),
            GeneralName::EDIPartyName(_) => write!(f, "EDIPartyName(<unparsed>)"),
            GeneralName::URI(s) => write!(f, "URI({})", s),
            GeneralName::IPAddress(b) => write!(f, "IPAddress({})", format_serial(b)),
            GeneralName::RegisteredID(oid) => write!(f, "RegisteredID({})", oid),
        }
    }
}

pub(crate) fn parse_generalname<'a>(i: &'a [u8]) -> IResult<&'a [u8], GeneralName, BerError> {
    let (rest, hdr) = verify(der_read_element_header, |hdr| hdr.is_contextspecific())(i)?;
    let len = hdr.length().definite()?;
    if len > rest.len() {
        let needed = Needed::new(len - rest.len());
        return Err(nom::Err::Failure(BerError::Incomplete(needed)));
    }
    fn ia5str<'a>(i: &'a [u8], hdr: Header) -> Result<&'a str, Err<BerError>> {
        // Relax constraints from RFC here: we are expecting an IA5String, but many certificates
        // are using unicode characters
        der_read_element_content_as(i, Tag::Utf8String, hdr.length(), hdr.is_constructed(), 1)?
            .1
            .as_slice()
            .and_then(|s| std::str::from_utf8(s).map_err(|_| BerError::BerValueError))
            .map_err(nom::Err::Failure)
    }
    let name = match hdr.tag().0 {
        0 => {
            // otherName SEQUENCE { OID, [0] explicit any defined by oid }
            let (any, oid) = parse_der_oid(rest)?;
            let oid = oid.as_oid_val().map_err(nom::Err::Failure)?;
            GeneralName::OtherName(oid, any)
        }
        1 => GeneralName::RFC822Name(ia5str(rest, hdr)?),
        2 => GeneralName::DNSName(ia5str(rest, hdr)?),
        3 => {
            // XXX Not yet implemented
            let (_, data) = take(len)(rest)?;
            let obj = UnparsedObject { header: hdr, data };
            GeneralName::X400Address(obj)
        }
        4 => {
            // directoryName, name
            let (_, name) = all_consuming(X509Name::from_der)(&rest[..len])
                .or(Err(BerError::Unsupported)) // XXX remove me
                ?;
            GeneralName::DirectoryName(name)
        }
        5 => {
            // XXX Not yet implemented
            let (_, data) = take(len)(rest)?;
            let obj = UnparsedObject { header: hdr, data };
            GeneralName::EDIPartyName(obj)
        }
        6 => GeneralName::URI(ia5str(rest, hdr)?),
        7 => {
            // IPAddress, OctetString
            let ip = der_read_element_content_as(
                rest,
                Tag::OctetString,
                hdr.length(),
                hdr.is_constructed(),
                1,
            )?
            .1
            .as_slice()
            .map_err(nom::Err::Failure)?;
            GeneralName::IPAddress(ip)
        }
        8 => {
            let oid =
                der_read_element_content_as(rest, Tag::Oid, hdr.length(), hdr.is_constructed(), 1)?
                    .1
                    .as_oid_val()
                    .map_err(nom::Err::Failure)?;
            GeneralName::RegisteredID(oid)
        }
        _ => return Err(Err::Failure(BerError::unexpected_tag(None, hdr.tag()))),
    };
    Ok((&rest[len..], name))
}
