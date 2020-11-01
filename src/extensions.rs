use crate::objects::*;
use der_parser::ber::*;
use der_parser::oid::Oid;
use nom::combinator::{all_consuming, complete, map_res, opt};
use nom::multi::{many0, many1};
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
    /// https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server (OID 1.2.840.113635.100.8.2)
    AppleDataSecurityAttestationData(&'a [u8])
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
/// Represents the structure used in the name constraints extensions.
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
    use nom::combinator::{map, verify};
    use nom::{Err, IResult};

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
        } else if *oid == OID_EXT_APPLEDATASECURITY_ATTESTATION {
            let (_ret, data) = parse_sequence_single_octet_string(i)?;
            ParsedExtension::AppleDataSecurityAttestationData(data)
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
            parse_ber_sequence_defined_g(|_, input| {
                map(parse_generalname, |base| GeneralSubtree { base })(input)
            })(i)
        }
        fn parse_subtrees(i: &[u8]) -> IResult<&[u8], Vec<GeneralSubtree>, BerError> {
            all_consuming(many1(complete(parse_subtree)))(i)
        }

        let (ret, named_constraints) = parse_ber_sequence_defined_g(|_, input| {
            let (rem, permitted_subtrees) =
                opt(complete(parse_ber_tagged_explicit_g(0, |_, input| {
                    parse_subtrees(input)
                })))(input)?;
            let (rem, excluded_subtrees) =
                opt(complete(parse_ber_tagged_explicit_g(1, |_, input| {
                    parse_subtrees(input)
                })))(rem)?;
            let named_constraints = NameConstraints {
                permitted_subtrees,
                excluded_subtrees,
            };
            Ok((rem, named_constraints))
        })(i)?;

        Ok((ret, named_constraints))
    }

    fn parse_generalname<'a>(i: &'a [u8]) -> IResult<&'a [u8], GeneralName, BerError> {
        use crate::x509_parser::parse_x509_name;
        let (rest, hdr) = verify(der_read_element_header, |hdr| hdr.is_contextspecific())(i)?;
        let len = hdr.len.primitive()?;
        if len > rest.len() {
            return Err(nom::Err::Failure(BerError::ObjectTooShort));
        }
        fn ia5str<'a>(i: &'a [u8], hdr: BerObjectHeader) -> Result<&'a str, Err<BerError>> {
            der_read_element_content_as(i, DerTag::Ia5String, hdr.len, hdr.is_constructed(), 0)?
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
                let (_, name) = all_consuming(parse_x509_name)(&rest[..len])
                    .or(Err(BerError::Unsupported)) // XXX remove me
                    ?;
                GeneralName::DirectoryName(name)
            }
            5 => return Err(Err::Failure(BerError::Unsupported)), // ediPartyName
            6 => GeneralName::URI(ia5str(rest, hdr)?),
            7 => {
                // IPAddress, OctetString
                let ip = der_read_element_content_as(
                    rest,
                    DerTag::OctetString,
                    hdr.len,
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
                    hdr.len,
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
        Ok((&rest[len..], name))
    }

    fn parse_subjectalternativename<'a>(
        i: &'a [u8],
    ) -> IResult<&'a [u8], SubjectAlternativeName, BerError> {
        parse_ber_sequence_defined_g(|_, input| {
            let (i, general_names) = all_consuming(many0(complete(parse_generalname)))(input)?;
            Ok((i, SubjectAlternativeName { general_names }))
        })(i)
    }

    fn parse_policyconstraints(i: &[u8]) -> IResult<&[u8], PolicyConstraints, BerError> {
        parse_ber_sequence_defined_g(|_, input| {
            let (i, require_explicit_policy) = opt(complete(map_res(
                parse_ber_tagged_implicit(0, parse_ber_content(BerTag::Integer)),
                |x| x.as_u32(),
            )))(input)?;
            let (i, inhibit_policy_mapping) = all_consuming(opt(complete(map_res(
                parse_ber_tagged_implicit(1, parse_ber_content(BerTag::Integer)),
                |x| x.as_u32(),
            ))))(i)?;
            let policy_constraint = PolicyConstraints {
                require_explicit_policy,
                inhibit_policy_mapping,
            };
            Ok((i, policy_constraint))
        })(i)
    }

    // PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
    //  issuerDomainPolicy      CertPolicyId,
    //  subjectDomainPolicy     CertPolicyId }
    fn parse_policymappings(i: &[u8]) -> IResult<&[u8], PolicyMappings<'_>, BerError> {
        fn parse_oid_pair(i: &[u8]) -> IResult<&[u8], Vec<DerObject<'_>>, BerError> {
            // read 2 OID as a SEQUENCE OF OID - length will be checked later
            parse_ber_sequence_of_v(parse_der_oid)(i)
        }
        let (ret, pairs) = parse_ber_sequence_of_v(parse_oid_pair)(i)?;
        let mut mappings: HashMap<Oid, Vec<Oid>> = HashMap::new();
        for pair in pairs.iter() {
            if pair.len() != 2 {
                return Err(Err::Failure(BerError::BerValueError));
            }
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

    fn parse_inhibitanyplicy(i: &[u8]) -> IResult<&[u8], InhibitAnyPolicy, BerError> {
        let (ret, skip_certs) = map_res(parse_der_integer, |x: BerObject| x.as_u32())(i)?;
        Ok((ret, InhibitAnyPolicy { skip_certs }))
    }

    fn parse_extendedkeyusage(i: &[u8]) -> IResult<&[u8], ExtendedKeyUsage<'_>, BerError> {
        let (ret, seq) = parse_ber_sequence_of(parse_der_oid)(i)?;
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

    // AuthorityInfoAccessSyntax  ::=
    //         SEQUENCE SIZE (1..MAX) OF AccessDescription
    //
    // AccessDescription  ::=  SEQUENCE {
    //         accessMethod          OBJECT IDENTIFIER,
    //         accessLocation        GeneralName  }
    fn parse_authorityinfoaccess(i: &[u8]) -> IResult<&[u8], AuthorityInfoAccess, BerError> {
        fn parse_aia<'a>(i: &'a [u8]) -> IResult<&'a [u8], (Oid<'a>, GeneralName<'a>), BerError> {
            parse_ber_sequence_defined_g(|_, content| {
                // Read first element, an oid.
                let (gn, oid) = map_res(parse_der_oid, |x: BerObject<'a>| x.as_oid_val())(content)?;
                // Parse second element
                let (rest, gn) = parse_generalname(gn)?;
                Ok((rest, (oid, gn)))
            })(i)
        }
        let (ret, mut aia_list) = parse_ber_sequence_of_v(parse_aia)(i)?;
        // create the hashmap and merge entries with same OID
        let mut accessdescs: HashMap<Oid, Vec<GeneralName>> = HashMap::new();
        for (oid, gn) in aia_list.drain(..) {
            if let Some(general_names) = accessdescs.get_mut(&oid) {
                general_names.push(gn);
            } else {
                accessdescs.insert(oid, vec![gn]);
            }
        }
        Ok((ret, AuthorityInfoAccess { accessdescs }))
    }

    fn parse_aki_content<'a>(
        _hdr: BerObjectHeader<'_>,
        i: &'a [u8],
    ) -> IResult<&'a [u8], AuthorityKeyIdentifier<'a>, BerError> {
        let (i, key_identifier) = opt(complete(parse_ber_tagged_implicit_g(0, |d, _, _| {
            Ok((&[], KeyIdentifier(d)))
        })))(i)?;
        let (i, authority_cert_issuer) =
            opt(complete(parse_ber_tagged_implicit_g(1, |d, _, _| {
                many0(complete(parse_generalname))(d)
            })))(i)?;
        let (i, authority_cert_serial) = opt(complete(parse_ber_tagged_implicit(
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
        parse_ber_sequence_defined_g(parse_aki_content)(i)
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

    fn parse_keyusage(i: &[u8]) -> IResult<&[u8], KeyUsage, BerError> {
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

    // CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
    //
    // PolicyInformation ::= SEQUENCE {
    //      policyIdentifier   CertPolicyId,
    //      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
    //              PolicyQualifierInfo OPTIONAL }
    //
    // CertPolicyId ::= OBJECT IDENTIFIER
    //
    // PolicyQualifierInfo ::= SEQUENCE {
    //      policyQualifierId  PolicyQualifierId,
    //      qualifier          ANY DEFINED BY policyQualifierId }
    //
    // -- Implementations that recognize additional policy qualifiers MUST
    // -- augment the following definition for PolicyQualifierId
    //
    // PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
    fn parse_certificatepolicies(i: &[u8]) -> IResult<&[u8], CertificatePolicies, BerError> {
        fn parse_policy_information<'a>(
            i: &'a [u8],
        ) -> IResult<&'a [u8], (Oid<'a>, &'a [u8]), BerError> {
            parse_ber_sequence_defined_g(|_, content| {
                let (qualifier_set, oid) =
                    map_res(parse_der_oid, |x: BerObject<'a>| x.as_oid_val())(content)?;
                Ok((&[], (oid, qualifier_set)))
            })(i)
        }
        let (ret, mut policy_list) = parse_ber_sequence_of_v(parse_policy_information)(i)?;
        // create the policy hashmap
        let mut policies = HashMap::new();
        for (oid, qualifier_set) in policy_list.drain(..) {
            if policies.insert(oid, qualifier_set).is_some() {
                // duplicate policies are not allowed
                return Err(Err::Failure(BerError::InvalidTag));
            }
        }
        Ok((ret, CertificatePolicies { policies }))
    }

    fn parse_sequence_single_octet_string<'a>(i: &'a [u8]) -> IResult<&'a [u8], &'a [u8], BerError> {
        let (rest, obj) = parse_der_with_tag(i, BerTag::Sequence)?;
        let seq = obj
            .content
            .as_sequence()
            .or(Err(Err::Error(BerError::BerTypeError)))?
            .first()
            .ok_or(Err::Error(BerError::BerTypeError))?
            .as_slice()
            .or(Err(Err::Error(BerError::BerTypeError)))?;

        let (_, obj) = parse_der_with_tag(seq, BerTag::OctetString)?;
        let value = obj
            .content
            .as_slice()
            .or(Err(Err::Error(BerError::BerTypeError)))?;

        Ok((rest, value))
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
