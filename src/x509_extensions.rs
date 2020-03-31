use std::collections::HashMap;

use der_parser::oid::Oid;

use crate::objects;
use crate::x509::X509Name;

#[derive(Debug, PartialEq)]
pub enum ExtensionType<'a> {
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
    /// Marker for an extension that is currently not supported by this crate
    Unknown,
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
pub struct KeyUsage {
    pub flags: u16,
}

impl KeyUsage {
    pub fn digital_signature(&self) -> bool {
        (self.flags >> 0) & 1 == 1
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
pub struct InhibitAnyPolicy {
    /// The value indicates the number of additional non-self-issued
    /// certificates that may appear in the path before anyPolicy
    /// is no longer permitted.
    pub skip_certs: u32,
}

#[derive(Debug, PartialEq)]
pub struct PolicyMappings<'a> {
    pub mappings: HashMap<Oid<'a>, Vec<Oid<'a>>>,
}

#[derive(Debug, PartialEq)]
pub struct PolicyConstraints {
    /// If present, number of additional certificates
    /// that may appear in the path before an explicit policy is required for
    /// the entire path.
    pub require_explicit_policy: Option<u32>,
    /// If present, number of additional certificates that may appear in the
    /// path before policy mapping is no longer permitted.
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
    DirectoryName(X509Name<'a>),
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
    use der_parser::{ber::BerObject, oid::Oid, *};
    use nom::{alt, call, do_parse, eof, exact, many1, opt, take, verify, Err, IResult};

    use der_parser::der::*;
    use der_parser::error::BerError;

    use crate::x509_extensions::*;

    pub(crate) fn parse_extension_type<'a>(
        i: &'a [u8],
        oid: &Oid,
    ) -> IResult<&'a [u8], ExtensionType<'a>, BerError> {
        match oid.bytes() {
            objects::OID_EXT_KEYUSAGE => parse_keyusage(i),
            objects::OID_EXT_SUBJALTNAME => parse_subjectalternativename(i),
            objects::OID_EXT_BASICCONSTRAINTS => parse_basicconstraints(i),
            objects::OID_EXT_NAMECONSTRAINTS => parse_nameconstraints(i),
            objects::OID_EXT_CERTIFICATEPOLICIES => parse_certificatepolicies(i),
            objects::OID_EXT_POLICYMAPPINGS => parse_policymappings(i),
            objects::OID_EXT_POLICYCONSTRAINTS => parse_policyconstraints(i),
            objects::OID_EXT_EXTENDEDKEYUSAGE => parse_extendedkeyusage(i),
            objects::OID_EXT_INHIBITANYPLICY => parse_inhibitanyplicy(i),
            _ => Ok((&[], ExtensionType::Unknown)),
        }
    }

    fn parse_nameconstraints<'a>(i: &'a [u8]) -> IResult<&'a [u8], ExtensionType, BerError> {
        fn parse_subtree<'a>(i: &'a [u8]) -> IResult<&'a [u8], GeneralSubtree, BerError> {
            do_parse!(i,
                _hdr: verify!(complete!(der_read_element_header), |hdr| hdr.tag == DerTag::Sequence) >>
                subtree: map!(parse_generalname, |base| GeneralSubtree { base }) >>
                (subtree)
            )
        }

        let (ret, (permitted_subtrees, excluded_subtrees)) = do_parse!(i,
            verify!(der_read_element_header, |hdr| hdr.tag == DerTag::Sequence) >>
            a: opt!(complete!(parse_der_tagged!(EXPLICIT 0, many1!(parse_subtree)))) >>
            b: alt!(
                opt!(complete!(parse_der_tagged!(EXPLICIT 1, many1!(parse_subtree)))) |
                map!(eof!(), |_| None)) >>
            ((a, b))
        )?;
        Ok((
            ret,
            ExtensionType::NameConstraints(NameConstraints {
                permitted_subtrees,
                excluded_subtrees,
            }),
        ))
    }

    fn parse_generalname<'a>(i: &'a [u8]) -> IResult<&'a [u8], GeneralName, BerError> {
        use crate::x509_parser::parse_name;
        let (rest, hdr) = verify!(i, der_read_element_header, |hdr| hdr.is_contextspecific())?;
        if hdr.len as usize > rest.len() {
            return Err(nom::Err::Failure(BerError::ObjectTooShort));
        }
        fn ia5str<'a>(
            i: &'a [u8],
            hdr: der_parser::ber::BerObjectHeader,
        ) -> Result<&'a str, Err<BerError>> {
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
            .map_err(|e| nom::Err::Failure(e))
        }
        let name = match hdr.tag.0 {
            0 => {
                // otherName SEQUENCE { OID, [0] explicit any defined by oid }
                let (any, oid) = parse_der_oid(rest)?;
                let oid = oid.as_oid_val().map_err(|e| nom::Err::Failure(e))?;
                GeneralName::OtherName(oid, any)
            }
            1 => GeneralName::RFC822Name(ia5str(rest, hdr)?),
            2 => GeneralName::DNSName(ia5str(rest, hdr)?),
            3 => return Err(Err::Failure(BerError::Unsupported)), // x400Address
            4 => {
                // directoryName, name
                let (_, name) = exact!(&rest[..(hdr.len as usize)], parse_name)?;
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
                .map_err(|e| nom::Err::Failure(e))?;
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
                .map_err(|e| nom::Err::Failure(e))?;
                GeneralName::RegisteredID(oid)
            }
            _ => return Err(Err::Failure(BerError::UnknownTag)),
        };
        Ok((&rest[(hdr.len as usize)..], name))
    }

    fn parse_subjectalternativename<'a>(mut i: &'a [u8]) -> IResult<&'a [u8], ExtensionType, BerError> {
        let (rest, _) = verify!(i, der_read_element_header, |hdr| hdr.tag == DerTag::Sequence)?;
        i = rest;
        let mut general_names = Vec::new();
        while !i.is_empty() {
            let (rest, general_name) = parse_generalname(i)?;
            i = rest;
            general_names.push(general_name);
        }
        Ok((
            i,
            ExtensionType::SubjectAlternativeName(SubjectAlternativeName { general_names }),
        ))
    }

    fn parse_policyconstraints<'a>(i: &'a [u8]) -> IResult<&'a [u8], ExtensionType, BerError> {
        let (ret, (require_explicit_policy, inhibit_policy_mapping)) = do_parse!(i,
            verify!(der_read_element_header, |hdr| hdr.tag == DerTag::Sequence) >>
            a: opt!(complete!(map_res!(parse_der_tagged!(IMPLICIT 0, DerTag::Integer), |x: BerObject| x.as_u32()))) >>
            b: alt!(
                opt!(complete!(map_res!(parse_der_tagged!(IMPLICIT 1, DerTag::Integer), |x: BerObject| x.as_u32()))) |
                map!(eof!(), |_| None)) >>
            ((a, b))
        )?;
        Ok((
            ret,
            ExtensionType::PolicyConstraints(PolicyConstraints {
                require_explicit_policy,
                inhibit_policy_mapping,
            }),
        ))
    }

    fn parse_policymappings<'a>(i: &'a [u8]) -> IResult<&'a [u8], ExtensionType<'a>, BerError> {
        fn parse_oid_pair<'b>(i: &'b [u8]) -> IResult<&'b [u8], DerObject<'b>, BerError> {
            let (ret, pair) = parse_der_sequence_defined!(i, parse_der_oid >> parse_der_oid)?;
            Ok((ret, pair))
        }
        let (ret, pairs) = parse_der_sequence_of!(i, parse_oid_pair)?;
        let mut mappings: HashMap<Oid, Vec<Oid>> = HashMap::new();
        for pair in pairs
            .as_sequence()
            .map_err(|e| nom::Err::Failure(e))?
            .into_iter()
        {
            let pair = pair.as_sequence().map_err(|e| nom::Err::Failure(e))?;
            let left = pair[0].as_oid_val().map_err(|e| nom::Err::Failure(e))?;
            let right = pair[1].as_oid_val().map_err(|e| nom::Err::Failure(e))?;
            if left.bytes() == oid!(raw 2.5.29.32.0) || right.bytes() == oid!(raw 2.5.29.32.0) {
                // mapping to or from anyPolicy is not allowed
                return Err(Err::Failure(BerError::InvalidTag));
            }
            mappings
                .entry(left)
                .and_modify(|v| v.push(right.clone()))
                .or_insert_with(|| vec![right.clone()]);
        }
        Ok((
            ret,
            ExtensionType::PolicyMappings(PolicyMappings { mappings }),
        ))
    }

    fn parse_inhibitanyplicy<'a>(i: &'a [u8]) -> IResult<&'a [u8], ExtensionType, BerError> {
        let (ret, skip_certs) = map_res!(i, parse_der_integer, |x: BerObject| x.as_u32())?;
        Ok((
            ret,
            ExtensionType::InhibitAnyPolicy(InhibitAnyPolicy { skip_certs }),
        ))
    }

    const OID_EKU_ANY: &[u8] = &oid!(raw 2.5.29.37.0);
    const OID_EKU_SERVER_AUTH: &[u8] = &oid!(raw 1.3.6.1.5.5.7.3.1);
    const OID_EKU_CLIENT_AUTH: &[u8] = &oid!(raw 1.3.6.1.5.5.7.3.2);
    const OID_EKU_CODE_SIGNING: &[u8] = &oid!(raw 1.3.6.1.5.5.7.3.3);
    const OID_EKU_EMAIL_PROTECTION: &[u8] = &oid!(raw 1.3.6.1.5.5.7.3.4);
    const OID_EKU_TIME_STAMPING: &[u8] = &oid!(raw 1.3.6.1.5.5.7.3.8);
    const OID_EKU_OCSCP_SIGNING: &[u8] = &oid!(raw 1.3.6.1.5.5.7.3.9);

    fn parse_extendedkeyusage<'a>(i: &'a [u8]) -> IResult<&'a [u8], ExtensionType<'a>, BerError> {
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
        for oid in seq
            .as_sequence()
            .map_err(|e| nom::Err::Failure(e))?
            .into_iter()
        {
            let oid = oid.as_oid_val().map_err(|e| nom::Err::Failure(e))?;
            if !seen.insert(oid.clone()) {
                continue;
            }
            match oid.bytes() {
                OID_EKU_ANY => eku.any = true,
                OID_EKU_SERVER_AUTH => eku.server_auth = true,
                OID_EKU_CLIENT_AUTH => eku.client_auth = true,
                OID_EKU_CODE_SIGNING => eku.code_signing = true,
                OID_EKU_EMAIL_PROTECTION => eku.email_protection = true,
                OID_EKU_TIME_STAMPING => eku.time_stamping = true,
                OID_EKU_OCSCP_SIGNING => eku.ocscp_signing = true,
                _ => eku.other.push(oid),
            };
        }
        Ok((ret, ExtensionType::ExtendedKeyUsage(eku)))
    }

    fn parse_keyusage<'a>(i: &'a [u8]) -> IResult<&'a [u8], ExtensionType, BerError> {
        let (rest, flags) = map_res!(
            i,
            parse_der_bitstring,
            |x: DerObject<'a>| -> Result<u16, BerError> {
                let bitstring = x
                    .content
                    .as_bitstring()
                    .map_err(|_| BerError::BerTypeError)?;
                let flags = bitstring
                    .data
                    .into_iter()
                    .rev()
                    .fold(0, |acc, x| acc << 8 | ((*x).reverse_bits() as u16));
                Ok(flags)
            }
        )?;
        Ok((rest, ExtensionType::KeyUsage(KeyUsage { flags })))
    }

    fn parse_certificatepolicies(i: &[u8]) -> IResult<&[u8], ExtensionType, BerError> {
        fn parse_policy<'a>(i: &'a [u8]) -> IResult<&'a [u8], (Oid<'a>, &'a [u8]), BerError> {
            let (ret, content) = do_parse!(
                i,
                hdr: verify!(call!(der_read_element_header), |h| h.tag == DerTag::Sequence) >>
                content: take!(hdr.len) >>
                (content)
            )?;
            // Read first element, an oid.
            let (qualifier_set, oid) = map_res!(
                content,
                parse_der_oid,
                |x: BerObject<'a>| x.as_oid_val()
            )?;
            Ok((ret, (oid, qualifier_set)))
        }
        let (ret, mut policies_raw) = do_parse!(
            i,
            hdr: verify!(call!(der_read_element_header), |s| s.tag == DerTag::Sequence) >>
            policies_raw: take!(hdr.len) >>
            (policies_raw)
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
        Ok((
            ret,
            ExtensionType::CertificatePolicies(CertificatePolicies { policies }),
        ))
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
    fn parse_basicconstraints(i: &[u8]) -> IResult<&[u8], ExtensionType, BerError> {
        parse_der_struct!(
            i,
            TAG DerTag::Sequence,
            ca:                 map_res!(parse_der_bool, |x: DerObject| x.as_bool()) >>
            path_len_constraint: alt!(
                complete!(opt!(map_res!(parse_der_integer, |x: DerObject| x.as_u32()))) |
                map!(eof!(), |_| None)) >>
            ( ExtensionType::BasicConstraints(BasicConstraints{ ca, path_len_constraint }) )
        )
        .map(|(rem, x)| (rem, x.1))
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
