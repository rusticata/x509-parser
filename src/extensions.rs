use crate::objects::*;
use der_parser::ber::BerTag;
use der_parser::oid::Oid;
use nom::combinator::{complete, opt};
use nom::multi::many0;
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum ParsedExtension<'a> {
    /// Crate parser does not support this extension (yet)
    UnsupportedExtension,
    ParseError,
    /// Section 4.2.1.1 of rfc 5280
    AuthorityKeyIdentifier(AuthorityKeyIdentifier<'a>),
    /// Section 4.2.1.2 of rfc 5280
    SubjectKeyIdentifier(KeyIdentifier<'a>),
    /// Section 4.2.1.3 of rfc 5280
    KeyUsage(KeyUsage),
    /// Section 4.2.1.4 of rfc 5280
    CertificatePolicies(CertificatePolicies<'a>),
    /// Section 4.2.1.5 of rfc 5280
    PolicyMappings(PolicyMappings<'a>),
    /// Section 4.2.1.6 of rfc 5280
    SubjectAlternativeName(SubjectAlternativeName<'a>),
    /// Section 4.2.1.9 of rfc 5280
    BasicConstraints(BasicConstraints),
    /// Section 4.2.1.10 of rfc 5280
    NameConstraints(NameConstraints<'a>),
    /// Section 4.2.1.11 of rfc 5280
    PolicyConstraints(PolicyConstraints),
    /// Section 4.2.1.12 of rfc 5280
    ExtendedKeyUsage(ExtendedKeyUsage<'a>),
    /// Section 4.2.1.14 of rfc 5280
    InhibitAnyPolicy(InhibitAnyPolicy),
    /// Section 4.2.2.1 of rfc 5280
    AuthorityInfoAccess(AuthorityInfoAccess<'a>),
}

#[derive(Debug, PartialEq)]
pub struct AuthorityKeyIdentifier<'a> {
    pub key_identifier: Option<KeyIdentifier<'a>>,
    pub authority_cert_issuer: Option<Vec<GeneralName<'a>>>,
    pub authority_cert_serial: Option<&'a [u8]>,
}

#[derive(Debug, PartialEq)]
pub struct CertificatePolicies<'a> {
    pub policies: HashMap<Oid<'a>, &'a [u8]>,
}

/// Identifies whether the subject of the certificate is a CA, and the max validation depth.
#[derive(Debug, PartialEq)]
pub struct BasicConstraints {
    pub ca: bool,
    pub path_len_constraint: Option<u32>,
}

#[derive(Debug, PartialEq)]
pub struct KeyIdentifier<'a>(pub &'a [u8]);

#[derive(Debug, PartialEq)]
pub struct KeyUsage {
    pub flags: u16,
}

impl KeyUsage {
    pub fn digital_signature(&self) -> bool {
        self.flags & 1 == 1
    }
    pub fn non_repudiation(&self) -> bool {
        (self.flags >> 1) & 1u16 == 1
    }
    pub fn key_encipherment(&self) -> bool {
        (self.flags >> 2) & 1u16 == 1
    }
    pub fn data_encipherment(&self) -> bool {
        (self.flags >> 3) & 1u16 == 1
    }
    pub fn key_agreement(&self) -> bool {
        (self.flags >> 4) & 1u16 == 1
    }
    pub fn key_cert_sign(&self) -> bool {
        (self.flags >> 5) & 1u16 == 1
    }
    pub fn crl_sign(&self) -> bool {
        (self.flags >> 6) & 1u16 == 1
    }
    pub fn encipher_only(&self) -> bool {
        (self.flags >> 7) & 1u16 == 1
    }
    pub fn decipher_only(&self) -> bool {
        (self.flags >> 8) & 1u16 == 1
    }
}

// This list must have the same order as KeyUsage flags declaration (4.2.1.3)
const KEY_USAGE_FLAGS: &[&str] = &[
    "Digital Signature",
    "Non Repudiation",
    "Key Encipherment",
    "Data Encipherment",
    "Key Agreement",
    "Key Cert Sign",
    "CRL Sign",
    "Encipher Only",
    "Decipher Only",
];

impl fmt::Display for KeyUsage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = KEY_USAGE_FLAGS
            .iter()
            .enumerate()
            .fold(String::new(), |acc, (idx, s)| {
                if self.flags >> idx != 0 {
                    acc + s + ", "
                } else {
                    acc
                }
            });
        s.pop();
        s.pop();
        f.write_str(&s)
    }
}

#[derive(Debug, PartialEq)]
pub struct ExtendedKeyUsage<'a> {
    pub any: bool,
    pub server_auth: bool,
    pub client_auth: bool,
    pub code_signing: bool,
    pub email_protection: bool,
    pub time_stamping: bool,
    pub ocscp_signing: bool,
    pub other: Vec<Oid<'a>>,
}

#[derive(Debug, PartialEq)]
pub struct AuthorityInfoAccess<'a> {
    pub accessdescs: HashMap<Oid<'a>, Vec<GeneralName<'a>>>,
}

#[derive(Debug, PartialEq)]
pub struct InhibitAnyPolicy {
    pub skip_certs: u32,
}

#[derive(Debug, PartialEq)]
pub struct PolicyMappings<'a> {
    pub mappings: HashMap<Oid<'a>, Vec<Oid<'a>>>,
}

#[derive(Debug, PartialEq)]
pub struct PolicyConstraints {
    pub require_explicit_policy: Option<u32>,
    pub inhibit_policy_mapping: Option<u32>,
}

#[derive(Debug, PartialEq)]
pub struct SubjectAlternativeName<'a> {
    pub general_names: Vec<GeneralName<'a>>,
}

#[derive(Debug, PartialEq)]
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
    // X400Address,
    /// RFC5280 defines several string types, we always try to parse as utf-8
    /// which is more or less a superset of the string types.
    DirectoryName(crate::x509::X509Name<'a>),
    // EDIPartyName { name_assigner: Option<&'a str>, party_name: &'a str },
    /// An uniform resource identifier. The format is not checked.
    URI(&'a str),
    /// An ip address, provided as encoded.
    IPAddress(&'a [u8]),
    RegisteredID(Oid<'a>),
}

#[derive(Debug, PartialEq)]
pub struct NameConstraints<'a> {
    pub permitted_subtrees: Option<Vec<GeneralSubtree<'a>>>,
    pub excluded_subtrees: Option<Vec<GeneralSubtree<'a>>>,
}

#[derive(Debug, PartialEq)]
/// Represents the structure used in the name contraints extensions.
/// The fields minimum and maximum are not supported (openssl also has no support).
pub struct GeneralSubtree<'a> {
    pub base: GeneralName<'a>,
    // minimum: u32,
    // maximum: Option<u32>,
}

pub(crate) mod parser {
    use crate::extensions::*;
    use der_parser::ber::{BerObject, BerObjectHeader};
    use der_parser::der::*;
    use der_parser::error::BerError;
    use der_parser::{oid::Oid, *};
    use nom::{alt, call, do_parse, eof, exact, many1, opt, take, verify, Err, IResult};

    fn parse_extension0<'a>(
        orig_i: &'a [u8],
        i: &'a [u8],
        oid: &Oid,
    ) -> IResult<&'a [u8], ParsedExtension<'a>, BerError> {
        let ext = if *oid == OID_EXT_SUBJECTKEYIDENTIFIER {
            let (_ret, ki) = parse_keyidentifier(i)?;
            ParsedExtension::SubjectKeyIdentifier(ki)
        } else if *oid == OID_EXT_KEYUSAGE {
            let (_ret, ku) = parse_keyusage(i)?;
            ParsedExtension::KeyUsage(ku)
        } else if *oid == OID_EXT_SAN {
            let (_ret, san) = parse_subjectalternativename(i)?;
            ParsedExtension::SubjectAlternativeName(san)
        } else if *oid == OID_EXT_BASICCONSTRAINTS {
            let (_ret, bc) = parse_basicconstraints(i)?;
            ParsedExtension::BasicConstraints(bc)
        } else if *oid == OID_EXT_NAMECONSTRAINTS {
            let (_ret, name) = parse_nameconstraints(i)?;
            ParsedExtension::NameConstraints(name)
        } else if *oid == OID_EXT_CPOL {
            let (_ret, cp) = parse_certificatepolicies(i)?;
            ParsedExtension::CertificatePolicies(cp)
        } else if *oid == OID_EXT_POLICYMAPPINGS {
            let (_ret, pm) = parse_policymappings(i)?;
            ParsedExtension::PolicyMappings(pm)
        } else if *oid == OID_EXT_POLICYCONSTRAINTS {
            let (_ret, pc) = parse_policyconstraints(i)?;
            ParsedExtension::PolicyConstraints(pc)
        } else if *oid == OID_EXT_EKU {
            let (_ret, eku) = parse_extendedkeyusage(i)?;
            ParsedExtension::ExtendedKeyUsage(eku)
        } else if *oid == OID_EXT_INHIBITANYPOLICY {
            let (_ret, iap) = parse_inhibitanyplicy(i)?;
            ParsedExtension::InhibitAnyPolicy(iap)
        } else if *oid == OID_EXT_AUTHORITYINFOACCESS {
            let (_ret, aia) = parse_authorityinfoaccess(i)?;
            ParsedExtension::AuthorityInfoAccess(aia)
        } else if *oid == OID_EXT_AUTHORITYKEYIDENTIFIER {
            let (_ret, aki) = parse_authoritykeyidentifier(i)?;
            ParsedExtension::AuthorityKeyIdentifier(aki)
        } else {
            ParsedExtension::UnsupportedExtension
        };
        Ok((orig_i, ext))
    }

    pub(crate) fn parse_extension<'a>(
        orig_i: &'a [u8],
        i: &'a [u8],
        oid: &Oid,
    ) -> IResult<&'a [u8], ParsedExtension<'a>, BerError> {
        let r = parse_extension0(orig_i, i, oid);
        if let Err(nom::Err::Incomplete(_)) = r {
            return Ok((orig_i, ParsedExtension::UnsupportedExtension));
        }
        r
    }

    /// Parse a "Basic Constraints" extension
    ///
    /// <pre>
    ///   id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
    ///   BasicConstraints ::= SEQUENCE {
    ///        cA                      BOOLEAN DEFAULT FALSE,
    ///        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
    /// </pre>
    ///
    /// Note the maximum length of the `pathLenConstraint` field is limited to the size of a 32-bits
    /// unsigned integer, and parsing will fail if value if larger.
    fn parse_basicconstraints(i: &[u8]) -> IResult<&[u8], BasicConstraints, BerError> {
        let (rem, obj) = parse_der_sequence(i)?;
        if let Ok(seq) = obj.as_sequence() {
            let (ca, path_len_constraint) = match seq.len() {
                0 => (false, None),
                1 => {
                    if let Ok(b) = seq[0].as_bool() {
                        (b, None)
                    } else if let Ok(u) = seq[0].as_u32() {
                        (false, Some(u))
                    } else {
                        return Err(nom::Err::Error(BerError::InvalidTag));
                    }
                }
                2 => {
                    let ca = seq[0]
                        .as_bool()
                        .or(Err(nom::Err::Error(BerError::InvalidLength)))?;
                    let pl = seq[1]
                        .as_u32()
                        .or(Err(nom::Err::Error(BerError::InvalidLength)))?;
                    (ca, Some(pl))
                }
                _ => return Err(nom::Err::Error(BerError::InvalidLength)),
            };
            Ok((
                rem,
                BasicConstraints {
                    ca,
                    path_len_constraint,
                },
            ))
        } else {
            Err(nom::Err::Error(BerError::InvalidLength))
        }
    }

    fn parse_nameconstraints<'a>(i: &'a [u8]) -> IResult<&'a [u8], NameConstraints, BerError> {
        fn parse_subtree<'a>(i: &'a [u8]) -> IResult<&'a [u8], GeneralSubtree, BerError> {
            do_parse!(
                i,
                _hdr: verify!(complete!(der_read_element_header), |hdr| hdr.tag
                    == DerTag::Sequence)
                    >> subtree: map!(parse_generalname, |base| GeneralSubtree { base })
                    >> (subtree)
            )
        }

        let (ret, (permitted_subtrees, excluded_subtrees)) = do_parse!(
            i,
            verify!(der_read_element_header, |hdr| hdr.tag == DerTag::Sequence)
                >> a: opt!(complete!(
                    parse_der_tagged!(EXPLICIT 0, many1!(parse_subtree))
                ))
                >> b: alt!(
                    opt!(complete!(
                        parse_der_tagged!(EXPLICIT 1, many1!(parse_subtree))
                    )) | map!(eof!(), |_| None)
                )
                >> ((a, b))
        )?;
        Ok((
            ret,
            NameConstraints {
                permitted_subtrees,
                excluded_subtrees,
            },
        ))
    }

    fn parse_generalname<'a>(i: &'a [u8]) -> IResult<&'a [u8], GeneralName, BerError> {
        use crate::x509_parser::parse_x509_name;
        let (rest, hdr) = verify!(i, der_read_element_header, |hdr| hdr.is_contextspecific())?;
        if hdr.len as usize > rest.len() {
            return Err(nom::Err::Failure(BerError::ObjectTooShort));
        }
        fn ia5str<'a>(i: &'a [u8], hdr: BerObjectHeader) -> Result<&'a str, Err<BerError>> {
            der_read_element_content_as(
                i,
                DerTag::Ia5String,
                hdr.len as usize,
                hdr.is_constructed(),
                0,
            )?
            .1
            .as_slice()
            .and_then(|s| std::str::from_utf8(s).map_err(|_| BerError::BerValueError))
            .map_err(nom::Err::Failure)
        }
        let name = match hdr.tag.0 {
            0 => {
                // otherName SEQUENCE { OID, [0] explicit any defined by oid }
                let (any, oid) = parse_der_oid(rest)?;
                let oid = oid.as_oid_val().map_err(nom::Err::Failure)?;
                GeneralName::OtherName(oid, any)
            }
            1 => GeneralName::RFC822Name(ia5str(rest, hdr)?),
            2 => GeneralName::DNSName(ia5str(rest, hdr)?),
            3 => return Err(Err::Failure(BerError::Unsupported)), // x400Address
            4 => {
                // directoryName, name
                let (_, name) = exact!(&rest[..(hdr.len as usize)], parse_x509_name)?;
                GeneralName::DirectoryName(name)
            }
            5 => return Err(Err::Failure(BerError::Unsupported)), // ediPartyName
            6 => GeneralName::URI(ia5str(rest, hdr)?),
            7 => {
                // IPAddress, OctetString
                let ip = der_read_element_content_as(
                    rest,
                    DerTag::OctetString,
                    hdr.len as usize,
                    hdr.is_constructed(),
                    0,
                )?
                .1
                .as_slice()
                .map_err(nom::Err::Failure)?;
                GeneralName::IPAddress(ip)
            }
            8 => {
                let oid = der_read_element_content_as(
                    rest,
                    DerTag::Oid,
                    hdr.len as usize,
                    hdr.is_constructed(),
                    0,
                )?
                .1
                .as_oid_val()
                .map_err(nom::Err::Failure)?;
                GeneralName::RegisteredID(oid)
            }
            _ => return Err(Err::Failure(BerError::UnknownTag)),
        };
        Ok((&rest[(hdr.len as usize)..], name))
    }

    fn parse_subjectalternativename<'a>(
        mut i: &'a [u8],
    ) -> IResult<&'a [u8], SubjectAlternativeName, BerError> {
        let (rest, _) = verify!(i, der_read_element_header, |hdr| hdr.tag
            == DerTag::Sequence)?;
        i = rest;
        let mut general_names = Vec::new();
        while !i.is_empty() {
            let (rest, general_name) = parse_generalname(i)?;
            i = rest;
            general_names.push(general_name);
        }
        Ok((i, SubjectAlternativeName { general_names }))
    }

    fn parse_policyconstraints<'a>(i: &'a [u8]) -> IResult<&'a [u8], PolicyConstraints, BerError> {
        let (ret, (require_explicit_policy, inhibit_policy_mapping)) = do_parse!(
            i,
            verify!(der_read_element_header, |hdr| hdr.tag == DerTag::Sequence)
                >> a: opt!(complete!(map_res!(
                    parse_der_tagged!(IMPLICIT 0, DerTag::Integer),
                    |x: BerObject| x.as_u32()
                )))
                >> b: alt!(
                    opt!(complete!(map_res!(
                        parse_der_tagged!(IMPLICIT 1, DerTag::Integer),
                        |x: BerObject| x.as_u32()
                    ))) | map!(eof!(), |_| None)
                )
                >> ((a, b))
        )?;
        Ok((
            ret,
            PolicyConstraints {
                require_explicit_policy,
                inhibit_policy_mapping,
            },
        ))
    }

    fn parse_policymappings<'a>(i: &'a [u8]) -> IResult<&'a [u8], PolicyMappings<'a>, BerError> {
        fn parse_oid_pair<'b>(i: &'b [u8]) -> IResult<&'b [u8], DerObject<'b>, BerError> {
            let (ret, pair) = parse_der_sequence_defined!(i, parse_der_oid >> parse_der_oid)?;
            Ok((ret, pair))
        }
        let (ret, pairs) = parse_der_sequence_of!(i, parse_oid_pair)?;
        let mut mappings: HashMap<Oid, Vec<Oid>> = HashMap::new();
        for pair in pairs.as_sequence().map_err(nom::Err::Failure)?.iter() {
            let pair = pair.as_sequence().map_err(nom::Err::Failure)?;
            let left = pair[0].as_oid_val().map_err(nom::Err::Failure)?;
            let right = pair[1].as_oid_val().map_err(nom::Err::Failure)?;
            if left.bytes() == oid!(raw 2.5.29.32.0) || right.bytes() == oid!(raw 2.5.29.32.0) {
                // mapping to or from anyPolicy is not allowed
                return Err(Err::Failure(BerError::InvalidTag));
            }
            mappings
                .entry(left)
                .and_modify(|v| v.push(right.clone()))
                .or_insert_with(|| vec![right.clone()]);
        }
        Ok((ret, PolicyMappings { mappings }))
    }

    fn parse_inhibitanyplicy<'a>(i: &'a [u8]) -> IResult<&'a [u8], InhibitAnyPolicy, BerError> {
        let (ret, skip_certs) = map_res!(i, parse_der_integer, |x: BerObject| x.as_u32())?;
        Ok((ret, InhibitAnyPolicy { skip_certs }))
    }

    fn parse_extendedkeyusage<'a>(
        i: &'a [u8],
    ) -> IResult<&'a [u8], ExtendedKeyUsage<'a>, BerError> {
        let (ret, seq) = parse_der_sequence_of!(i, parse_der_oid)?;
        let mut seen = std::collections::HashSet::new();
        let mut eku = ExtendedKeyUsage {
            any: false,
            server_auth: false,
            client_auth: false,
            code_signing: false,
            email_protection: false,
            time_stamping: false,
            ocscp_signing: false,
            other: Vec::new(),
        };
        for oid in seq.as_sequence().map_err(nom::Err::Failure)?.iter() {
            let oid = oid.as_oid_val().map_err(nom::Err::Failure)?;
            if !seen.insert(oid.clone()) {
                continue;
            }
            let asn1 = oid.bytes();
            if asn1 == oid!(raw 2.5.29.37.0) {
                eku.any = true;
            } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.1) {
                eku.server_auth = true;
            } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.2) {
                eku.client_auth = true;
            } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.3) {
                eku.code_signing = true;
            } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.4) {
                eku.email_protection = true;
            } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.8) {
                eku.time_stamping = true;
            } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.9) {
                eku.ocscp_signing = true;
            } else {
                eku.other.push(oid);
            }
        }
        Ok((ret, eku))
    }

    fn parse_authorityinfoaccess(i: &[u8]) -> IResult<&[u8], AuthorityInfoAccess, BerError> {
        fn parse_aia<'a>(i: &'a [u8]) -> IResult<&'a [u8], (Oid<'a>, GeneralName<'a>), BerError> {
            let (ret, content) = do_parse!(
                i,
                hdr: verify!(call!(der_read_element_header), |h| h.tag
                    == DerTag::Sequence)
                    >> content: take!(hdr.len)
                    >> (content)
            )?;
            // Read first element, an oid.
            let (gn, oid) = map_res!(content, parse_der_oid, |x: BerObject<'a>| x.as_oid_val())?;
            // Parse second element
            let (_rest, gn) = parse_generalname(gn)?;
            Ok((ret, (oid, gn)))
        }
        let (ret, mut aia_raw) = do_parse!(
            i,
            hdr: verify!(call!(der_read_element_header), |s| s.tag
                == DerTag::Sequence)
                >> aia_raw: take!(hdr.len)
                >> (aia_raw)
        )?;
        let mut accessdescs: HashMap<Oid, Vec<GeneralName>> = HashMap::new();
        while !aia_raw.is_empty() {
            let (rest, (oid, gn)) = parse_aia(aia_raw)?;
            aia_raw = rest;
            if let Some(general_names) = accessdescs.get_mut(&oid) {
                general_names.push(gn);
            } else {
                accessdescs.insert(oid, vec![gn]);
            }
        }
        Ok((ret, AuthorityInfoAccess { accessdescs }))
    }

    use helper::*;

    fn parse_aki_content(i: &[u8]) -> IResult<&[u8], AuthorityKeyIdentifier, BerError> {
        let (i, key_identifier) = opt(complete(parse_der_tagged_implicit(0, |d, _, _| {
            Ok((&[], KeyIdentifier(d)))
        })))(i)?;
        let (i, authority_cert_issuer) = opt(complete(parse_der_tagged_implicit(1, |d, _, _| {
            many0(complete(parse_generalname))(d)
        })))(i)?;
        let (i, authority_cert_serial) = opt(complete(parse_der_tagged_implicit(
            2,
            parse_ber_content(BerTag::Integer),
        )))(i)?;
        let authority_cert_serial = authority_cert_serial.and_then(|o| o.as_slice().ok());
        let aki = AuthorityKeyIdentifier {
            key_identifier,
            authority_cert_issuer,
            authority_cert_serial,
        };
        Ok((i, aki))
    }

    // RFC 5280 section 4.2.1.1: Authority Key Identifier
    fn parse_authoritykeyidentifier(i: &[u8]) -> IResult<&[u8], AuthorityKeyIdentifier, BerError> {
        parse_der_sequence_defined(parse_aki_content)(i)
    }

    #[rustversion::not(since(1.37))]
    fn reverse_bits(n: u8) -> u8 {
        let mut out = 0;
        for i in 0..=7 {
            if n & (1 << i) != 0 {
                out |= 1 << (7 - i);
            }
        }
        out
    }

    #[rustversion::since(1.37)]
    #[inline]
    fn reverse_bits(n: u8) -> u8 {
        n.reverse_bits()
    }

    fn parse_keyidentifier<'a>(i: &'a [u8]) -> IResult<&'a [u8], KeyIdentifier, BerError> {
        let (rest, obj) = parse_der_octetstring(i)?;
        let id = obj
            .content
            .as_slice()
            .or(Err(Err::Error(BerError::BerTypeError)))?;
        Ok((rest, KeyIdentifier(id)))
    }

    fn parse_keyusage<'a>(i: &'a [u8]) -> IResult<&'a [u8], KeyUsage, BerError> {
        let (rest, obj) = parse_der_bitstring(i)?;
        let bitstring = obj
            .content
            .as_bitstring()
            .or(Err(Err::Error(BerError::BerTypeError)))?;
        let flags = bitstring
            .data
            .iter()
            .rev()
            .fold(0, |acc, x| acc << 8 | (reverse_bits(*x) as u16));
        Ok((rest, KeyUsage { flags }))
    }

    fn parse_certificatepolicies(i: &[u8]) -> IResult<&[u8], CertificatePolicies, BerError> {
        fn parse_policy<'a>(i: &'a [u8]) -> IResult<&'a [u8], (Oid<'a>, &'a [u8]), BerError> {
            let (ret, content) = do_parse!(
                i,
                hdr: verify!(call!(der_read_element_header), |h| h.tag
                    == DerTag::Sequence)
                    >> content: take!(hdr.len)
                    >> (content)
            )?;
            // Read first element, an oid.
            let (qualifier_set, oid) =
                map_res!(content, parse_der_oid, |x: BerObject<'a>| x.as_oid_val())?;
            Ok((ret, (oid, qualifier_set)))
        }
        let (ret, mut policies_raw) = do_parse!(
            i,
            hdr: verify!(call!(der_read_element_header), |s| s.tag
                == DerTag::Sequence)
                >> policies_raw: take!(hdr.len)
                >> (policies_raw)
        )?;
        let mut policies = HashMap::new();
        while !policies_raw.is_empty() {
            let (rest, (oid, qualifier_set)) = parse_policy(policies_raw)?;
            policies_raw = rest;
            if policies.insert(oid, qualifier_set).is_some() {
                // duplicate policies are not allowed
                return Err(Err::Failure(BerError::InvalidTag));
            }
        }
        Ok((ret, CertificatePolicies { policies }))
    }
}

/// Helper functions - until merged in der_parser
mod helper {
    use der_parser::{ber::*, der::*, error::*};
    use nom::bytes::complete::take;
    use nom::Err;
    use nom::IResult;

    #[allow(dead_code)]
    pub(crate) fn parse_der_sequence_of<'a, T, F>(
        f: F,
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], Vec<T>, BerError>
    where
        F: Fn(&'a [u8]) -> IResult<&'a [u8], T, BerError>,
    {
        move |i: &[u8]| {
            let (i, hdr) = der_read_element_header(i)?;
            if hdr.tag != der_parser::ber::BerTag::Sequence {
                return Err(Err::Error(BerError::BerTypeError));
            }
            let (i, mut data) = take(hdr.len as usize)(i)?;
            let mut v = Vec::new();
            while !data.is_empty() {
                let (rest, item) = f(data)?;
                data = rest;
                v.push(item);
            }
            Ok((i, v))
        }
    }

    pub(crate) fn parse_der_sequence_defined<'a, T, F>(
        f: F,
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], T, BerError>
    where
        F: Fn(&'a [u8]) -> IResult<&'a [u8], T, BerError>,
    {
        move |i: &[u8]| {
            let (i, hdr) = der_read_element_header(i)?;
            if hdr.tag != der_parser::ber::BerTag::Sequence {
                return Err(Err::Error(BerError::BerTypeError));
            }
            let (i, data) = take(hdr.len as usize)(i)?;
            let (_rest, item) = f(data)?;
            Ok((i, item))
        }
    }

    #[allow(dead_code)]
    pub(crate) fn parse_der_tagged_explicit<'a, T, F>(
        tag: u32,
        f: F,
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], T, BerError>
    where
        F: Fn(&'a [u8]) -> IResult<&'a [u8], T, BerError>,
    {
        move |i: &[u8]| {
            let (i, hdr) = der_read_element_header(i)?;
            if hdr.tag.0 != tag {
                return Err(Err::Error(BerError::InvalidTag));
            }
            let (i, data) = take(hdr.len as usize)(i)?;
            let (_rest, item) = f(data)?;
            Ok((i, item))
        }
    }

    pub(crate) fn parse_der_tagged_implicit<'a, T, F>(
        tag: u32,
        f: F,
    ) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], T, BerError>
    where
        F: Fn(&'a [u8], &BerObjectHeader, usize) -> IResult<&'a [u8], T, BerError>,
    {
        move |i: &[u8]| {
            let (i, hdr) = der_read_element_header(i)?;
            // eprintln!("tag is [{}], expected {}", hdr.tag.0, tag);
            if hdr.tag.0 != tag {
                return Err(Err::Error(BerError::InvalidTag));
            }
            let (i, data) = take(hdr.len as usize)(i)?;
            let (_rest, item) = f(data, &hdr, MAX_RECURSION)?;
            // XXX check that _rest.is_empty()?
            Ok((i, item))
        }
    }

    pub(crate) fn parse_ber_content<'a>(
        tag: BerTag,
    ) -> impl Fn(&'a [u8], &'_ BerObjectHeader, usize) -> IResult<&'a [u8], BerObjectContent<'a>, BerError>
    {
        move |i: &[u8], hdr: &BerObjectHeader, max_recursion: usize| {
            ber_read_element_content_as(
                i,
                tag,
                hdr.len as usize,
                hdr.is_constructed(),
                max_recursion,
            )
        }
    }
}

#[test]
fn test_keyusage_flags() {
    let ku = KeyUsage { flags: 98 };
    assert!(!ku.digital_signature());
    assert!(ku.non_repudiation());
    assert!(!ku.key_encipherment());
    assert!(!ku.data_encipherment());
    assert!(!ku.key_agreement());
    assert!(ku.key_cert_sign());
    assert!(ku.crl_sign());
    assert!(!ku.encipher_only());
    assert!(!ku.decipher_only());
}

#[test]
fn test_extensions1() {
    use der_parser::oid;
    let crt = crate::parse_x509_der(include_bytes!("../assets/extension1.der"))
        .unwrap()
        .1;
    let tbs = crt.tbs_certificate;
    assert_eq!(
        tbs.basic_constraints().unwrap().1,
        &BasicConstraints {
            ca: true,
            path_len_constraint: Some(1)
        }
    );
    {
        let ku = tbs.key_usage().unwrap().1;
        assert!(ku.digital_signature());
        assert!(!ku.non_repudiation());
        assert!(ku.key_encipherment());
        assert!(ku.data_encipherment());
        assert!(ku.key_agreement());
        assert!(!ku.key_cert_sign());
        assert!(!ku.crl_sign());
        assert!(ku.encipher_only());
        assert!(ku.decipher_only());
    }
    {
        let eku = tbs.extended_key_usage().unwrap().1;
        assert!(!eku.any);
        assert!(eku.server_auth);
        assert!(!eku.client_auth);
        assert!(eku.code_signing);
        assert!(!eku.email_protection);
        assert!(eku.time_stamping);
        assert!(!eku.ocscp_signing);
        assert_eq!(eku.other, vec![oid!(1.2.3.4.0.42)]);
    }
    assert_eq!(
        tbs.policy_constraints().unwrap().1,
        &PolicyConstraints {
            require_explicit_policy: None,
            inhibit_policy_mapping: Some(10)
        }
    );
    assert_eq!(
        tbs.inhibit_anypolicy().unwrap().1,
        &InhibitAnyPolicy { skip_certs: 2 }
    );
    {
        let alt_names = &tbs.subject_alternative_name().unwrap().1.general_names;
        assert_eq!(alt_names[0], GeneralName::RFC822Name("foo@example.com"));
        assert_eq!(alt_names[1], GeneralName::URI("http://my.url.here/"));
        assert_eq!(
            alt_names[2],
            GeneralName::IPAddress([192, 168, 7, 1].as_ref())
        );
        assert_eq!(
            format!(
                "{}",
                match alt_names[3] {
                    GeneralName::DirectoryName(ref dn) => dn,
                    _ => unreachable!(),
                }
            ),
            "C=UK, O=My Organization, OU=My Unit, CN=My Name"
        );
        assert_eq!(alt_names[4], GeneralName::DNSName("localhost"));
        assert_eq!(alt_names[5], GeneralName::RegisteredID(oid!(1.2.90.0)));
        assert_eq!(
            alt_names[6],
            GeneralName::OtherName(oid!(1.2.3.4), b"\xA0\x17\x0C\x15some other identifier")
        );
    }

    {
        let name_constraints = &tbs.name_constraints().unwrap().1;
        assert_eq!(name_constraints.permitted_subtrees, None);
        assert_eq!(
            name_constraints.excluded_subtrees,
            Some(vec![
                GeneralSubtree {
                    base: GeneralName::IPAddress([192, 168, 0, 0, 255, 255, 0, 0].as_ref())
                },
                GeneralSubtree {
                    base: GeneralName::RFC822Name("foo.com")
                },
            ])
        );
    }
}

#[test]
fn test_extensions2() {
    use der_parser::oid;
    let crt = crate::parse_x509_der(include_bytes!("../assets/extension2.der"))
        .unwrap()
        .1;
    let tbs = crt.tbs_certificate;
    assert_eq!(
        tbs.policy_constraints().unwrap().1,
        &PolicyConstraints {
            require_explicit_policy: Some(5000),
            inhibit_policy_mapping: None
        }
    );
    {
        let pm = tbs.policy_mappings().unwrap().1;
        let mut pm_ref = HashMap::new();
        pm_ref.insert(oid!(2.34.23), vec![oid!(2.2)]);
        pm_ref.insert(oid!(1.1), vec![oid!(0.0.4)]);
        pm_ref.insert(oid!(2.2), vec![oid!(2.2.1), oid!(2.2.3)]);
        assert_eq!(pm.mappings, pm_ref);
    }
}

// Test cases for:
// - parsing SubjectAlternativeName
// - parsing NameConstraints
