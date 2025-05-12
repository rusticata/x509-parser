use crate::error::X509Error;
use crate::prelude::format_serial;
use crate::x509::X509Name;
use asn1_rs::{Any, DerParser, DynTagged, Header, InnerError, Input, Oid, Tag};
use nom::{Err, IResult, Input as _};
use std::fmt;

/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
pub type GeneralNames<'a> = Vec<GeneralName<'a>>;

/// Represents a GeneralName as defined in RFC5280. There
/// is no support X.400 addresses and EDIPartyName.
///
/// String formats are not validated (except for valid UTF-8).
///
/// <pre>
/// -- Note: IMPLICIT Tags
/// GeneralName ::= CHOICE {
///     otherName                 [0]  AnotherName,
///     rfc822Name                [1]  IA5String,
///     dNSName                   [2]  IA5String,
///     x400Address               [3]  ORAddress,
///     directoryName             [4]  Name,
///     ediPartyName              [5]  EDIPartyName,
///     uniformResourceIdentifier [6]  IA5String,
///     iPAddress                 [7]  OCTET STRING,
///     registeredID              [8]  OBJECT IDENTIFIER }
/// </pre>
#[derive(Clone, Debug, PartialEq)]
pub enum GeneralName<'a> {
    OtherName(Oid<'a>, Any<'a>),
    /// More or less an e-mail, the format is not checked.
    RFC822Name(&'a str),
    /// A hostname, format is not checked.
    DNSName(&'a str),
    /// X400Address,
    X400Address(Any<'a>),
    /// RFC5280 defines several string types, we always try to parse as utf-8
    /// which is more or less a superset of the string types.
    DirectoryName(X509Name<'a>),
    /// EDIPartyName
    EDIPartyName(Any<'a>),
    /// An uniform resource identifier. The format is not checked.
    URI(&'a str),
    /// An ip address, provided as encoded.
    IPAddress(&'a [u8]),
    RegisteredID(Oid<'a>),
    /// Invalid data (for ex. invalid UTF-8 data in DNSName entry)
    Invalid(Any<'a>),
}

impl DynTagged for GeneralName<'_> {
    fn constructed(&self) -> bool {
        matches!(
            self,
            GeneralName::OtherName(_, _)
                | GeneralName::X400Address(_)
                | GeneralName::DirectoryName(_)
                | GeneralName::EDIPartyName(_)
        )
    }

    fn tag(&self) -> Tag {
        match self {
            GeneralName::OtherName(_, _) => Tag(0),
            GeneralName::RFC822Name(_) => Tag(1),
            GeneralName::DNSName(_) => Tag(2),
            GeneralName::X400Address(_) => Tag(3),
            GeneralName::DirectoryName(_) => Tag(4),
            GeneralName::EDIPartyName(_) => Tag(5),
            GeneralName::URI(_) => Tag(6),
            GeneralName::IPAddress(_) => Tag(7),
            GeneralName::RegisteredID(_) => Tag(8),
            GeneralName::Invalid(any) => any.tag(),
        }
    }

    fn accept_tag(tag: Tag) -> bool {
        (0..9).contains(&tag.0)
    }
}

impl<'a> DerParser<'a> for GeneralName<'a> {
    type Error = X509Error;

    fn from_der_content(
        header: &'_ Header<'a>,
        input: Input<'a>,
    ) -> IResult<Input<'a>, Self, Self::Error> {
        let (rem, gn) = match header.tag().0 {
            0 => {
                // AnotherName ::= SEQUENCE {
                //     type-id    OBJECT IDENTIFIER,
                //     value      [0] EXPLICIT ANY DEFINED BY type-id }
                let (rem, (type_id, value)) =
                    <(Oid, Any)>::from_der_content(header, input).map_err(Err::convert)?;
                (rem, GeneralName::OtherName(type_id, value))
            }
            1 => {
                let (rem, s) = ia5str_relaxed(input)?;
                (rem, GeneralName::RFC822Name(s))
            }
            2 => {
                let (rem, s) = ia5str_relaxed(input)?;
                (rem, GeneralName::DNSName(s))
            }
            3 => {
                // XXX Not yet implemented
                let rem = input.take_from(input.input_len());
                let any = Any::new(header.clone(), input);
                (rem, GeneralName::X400Address(any))
            }
            4 => {
                // Field is 'IMPLICIT [4] Name', but name is a CHOICE { RDNSequence }
                // so tags are EXPLICIT
                let (rem, name) = X509Name::parse_der(input)?;
                (rem, GeneralName::DirectoryName(name))
            }
            5 => {
                // Deep parsing not yet implemented, so just read Any
                let rem = input.take_from(input.input_len());
                let any = Any::new(header.clone(), input);
                (rem, GeneralName::EDIPartyName(any))
            }
            6 => {
                let (rem, s) = ia5str_relaxed(input)?;
                (rem, GeneralName::URI(s))
            }
            7 => {
                let (rem, b) = <&[u8]>::from_der_content(header, input).map_err(Err::convert)?;
                (rem, GeneralName::IPAddress(b))
            }
            8 => {
                let (rem, oid) = Oid::from_der_content(header, input).map_err(Err::convert)?;
                (rem, GeneralName::RegisteredID(oid))
            }
            _ => {
                let rem = input.take_from(input.input_len());
                let any = Any::new(header.clone(), input);
                (rem, GeneralName::Invalid(any))
            }
        };
        Ok((rem, gn))
    }
}

impl fmt::Display for GeneralName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GeneralName::OtherName(oid, _) => write!(f, "OtherName({oid}, [...])"),
            GeneralName::RFC822Name(s) => write!(f, "RFC822Name({s})"),
            GeneralName::DNSName(s) => write!(f, "DNSName({s})"),
            GeneralName::X400Address(_) => write!(f, "X400Address(<unparsed>)"),
            GeneralName::DirectoryName(dn) => write!(f, "DirectoryName({dn})"),
            GeneralName::EDIPartyName(_) => write!(f, "EDIPartyName(<unparsed>)"),
            GeneralName::URI(s) => write!(f, "URI({s})"),
            GeneralName::IPAddress(b) => write!(f, "IPAddress({})", format_serial(b)),
            GeneralName::RegisteredID(oid) => write!(f, "RegisteredID({oid})"),
            GeneralName::Invalid(any) => {
                write!(
                    f,
                    "Invalid(tag={}, data={})",
                    any.tag(),
                    format_serial(any.data.as_bytes2())
                )
            }
        }
    }
}

fn ia5str_relaxed(input: Input) -> Result<(Input, &str), Err<X509Error>> {
    let (rem, input) = input.take_split(input.input_len());
    // Relax constraints from RFC here: we are expecting an IA5String, but many certificates
    // are using unicode characters
    let s = std::str::from_utf8(input.as_bytes2())
        .map_err(|_| Err::Failure(X509Error::DerParser(InnerError::StringInvalidCharset)))?;
    Ok((rem, s))
}
