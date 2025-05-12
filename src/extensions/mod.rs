//! X.509 Extensions objects and types

use crate::error::X509Error;
use crate::time::ASN1Time;
use crate::x509::ReasonCode;

use asn1_rs::{
    Any, BigUint, DerParser, DynTagged, Header, Input, Sequence, Tag, Tagged, TaggedExplicit,
};
use nom::combinator::{all_consuming, complete, map};
use nom::multi::many0;
use nom::{Err, IResult, Input as _, Mode, Parser};
use oid_registry::*;
use std::collections::HashMap;

mod authority_info_access;
mod authority_key_identifier;
mod basic_constraints;
mod certificate_policies;
mod distribution_point;
mod extended_key_usage;
mod generalname;
mod inhibitant_policy;
mod issuer_alt_name;
mod issuing_distribution_point;
mod key_usage;
mod name_constraints;
mod ns_cert_type;
mod ns_comment;
mod policy_constraints;
mod policy_mappings;
mod sct;
mod subject_alt_name;
mod subject_info_access;
mod subject_key_identifier;

pub use authority_info_access::{AccessDescription, AuthorityInfoAccess};
pub use authority_key_identifier::AuthorityKeyIdentifier;
pub use basic_constraints::BasicConstraints;
pub use certificate_policies::{CertificatePolicies, PolicyInformation, PolicyQualifierInfo};
pub use distribution_point::{
    CRLDistributionPoint, CRLDistributionPoints, DistributionPointName, ReasonFlags,
};
pub use extended_key_usage::ExtendedKeyUsage;
pub use generalname::*;
pub use inhibitant_policy::{InhibitAnyPolicy, SkipCerts};
pub use issuer_alt_name::IssuerAlternativeName;
pub use issuing_distribution_point::IssuingDistributionPoint;
pub use key_usage::*;
pub use name_constraints::{GeneralSubtree, NameConstraints};
pub use ns_cert_type::NSCertType;
pub use ns_comment::parse_der_nscomment;
pub use policy_constraints::PolicyConstraints;
pub use policy_mappings::*;
pub use sct::*;
pub use subject_alt_name::SubjectAlternativeName;
pub use subject_info_access::SubjectInfoAccess;
pub use subject_key_identifier::{KeyIdentifier, SubjectKeyIdentifier};

/// X.509 version 3 extension
///
/// X.509 extensions allow adding attributes to objects like certificates or revocation lists.
///
/// Each extension in a certificate is designated as either critical or non-critical.  A
/// certificate using system MUST reject the certificate if it encounters a critical extension it
/// does not recognize; however, a non-critical extension MAY be ignored if it is not recognized.
///
/// Each extension includes an OID and an ASN.1 structure.  When an extension appears in a
/// certificate, the OID appears as the field extnID and the corresponding ASN.1 encoded structure
/// is the value of the octet string extnValue.  A certificate MUST NOT include more than one
/// instance of a particular extension.
///
/// When parsing an extension, the global extension structure (described above) is parsed,
/// and the object is returned if it succeeds.
/// During this step, it also attempts to parse the content of the extension, if known.
/// The returned object has a
/// [`X509Extension::parsed_extension()`] method. The returned
/// enum is either a known extension, or the special value `ParsedExtension::UnsupportedExtension`.
///
/// # Example
///
/// ```rust
/// use x509_parser::prelude::DerParser;
/// use x509_parser::extensions::{X509Extension, ParsedExtension};
/// use x509_parser::asn1_rs::Input;
///
/// static DER: &[u8] = &[
///    0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0xA3, 0x05, 0x2F, 0x18,
///    0x60, 0x50, 0xC2, 0x89, 0x0A, 0xDD, 0x2B, 0x21, 0x4F, 0xFF, 0x8E, 0x4E, 0xA8, 0x30, 0x31,
///    0x36 ];
///
/// # fn main() {
/// let res = X509Extension::parse_der(Input::from(DER));
/// match res {
///     Ok((_rem, ext)) => {
///         println!("Extension OID: {}", ext.oid);
///         println!("  Critical: {}", ext.critical);
///         let parsed_ext = ext.parsed_extension();
///         assert!(!parsed_ext.unsupported());
///         assert!(parsed_ext.error().is_none());
///         if let ParsedExtension::SubjectKeyIdentifier(key_id) = parsed_ext {
///             assert!(key_id.0.len() > 0);
///         } else {
///             panic!("Extension has wrong type");
///         }
///     },
///     _ => panic!("x509 extension parsing failed: {:?}", res),
/// }
/// # }
/// ```
///
/// <pre>
/// Extension  ::=  SEQUENCE  {
///     extnID      OBJECT IDENTIFIER,
///     critical    BOOLEAN DEFAULT FALSE,
///     extnValue   OCTET STRING  }
/// </pre>
#[derive(Clone, Debug, PartialEq)]
pub struct X509Extension<'a> {
    /// OID describing the extension content
    pub oid: Oid<'a>,
    /// Boolean value describing the 'critical' attribute of the extension
    ///
    /// An extension includes the boolean critical, with a default value of FALSE.
    pub critical: bool,
    /// Raw content of the extension
    pub value: Input<'a>,
    pub(crate) parsed_extension: ParsedExtension<'a>,
}

impl<'a> X509Extension<'a> {
    /// Creates a new extension with the provided values.
    #[inline]
    pub const fn new(
        oid: Oid<'a>,
        critical: bool,
        value: Input<'a>,
        parsed_extension: ParsedExtension<'a>,
    ) -> X509Extension<'a> {
        X509Extension {
            oid,
            critical,
            value,
            parsed_extension,
        }
    }

    /// Return the extension type or `UnsupportedExtension` if the extension is not implemented.
    #[inline]
    pub fn parsed_extension(&self) -> &ParsedExtension<'a> {
        &self.parsed_extension
    }
}

impl Tagged for X509Extension<'_> {
    const CONSTRUCTED: bool = true;

    const TAG: Tag = Tag::Sequence;
}

impl<'a> DerParser<'a> for X509Extension<'a> {
    type Error = X509Error;

    fn parse_der(input: Input<'a>) -> IResult<Input<'a>, Self, Self::Error> {
        X509ExtensionParser::new().parse(input)
    }

    fn from_der_content(
        _header: &'_ Header<'a>,
        input: Input<'a>,
    ) -> IResult<Input<'a>, Self, Self::Error> {
        let (rem, oid) = Oid::parse_der(input).map_err(Err::convert)?;
        let (rem, critical) = der_read_critical(rem)?;
        // OCTET STRING encapsulates [...]
        let (rem, (_, value)) = <&[u8]>::parse_der_as_input(rem)
            .map_err(|_| Err::Error(X509Error::InvalidExtensions))?;

        let (_, parsed_extension) = parser::parse_extension(value.clone(), &oid)?;
        let ext = X509Extension {
            oid,
            critical,
            value,
            parsed_extension,
        };
        Ok((rem, ext))
    }
}

/// `X509Extension` parser builder
#[derive(Clone, Copy, Debug)]
pub struct X509ExtensionParser {
    deep_parse_extensions: bool,
}

impl X509ExtensionParser {
    #[inline]
    pub const fn new() -> Self {
        X509ExtensionParser {
            deep_parse_extensions: true,
        }
    }

    #[inline]
    pub const fn with_deep_parse_extensions(self, deep_parse_extensions: bool) -> Self {
        X509ExtensionParser {
            deep_parse_extensions,
        }
    }
}

impl Default for X509ExtensionParser {
    fn default() -> Self {
        X509ExtensionParser::new()
    }
}

impl<'i> Parser<Input<'i>> for X509ExtensionParser {
    type Output = X509Extension<'i>;
    type Error = X509Error;

    fn parse(&mut self, input: Input<'i>) -> IResult<Input<'i>, X509Extension<'i>, X509Error> {
        Sequence::parse_der_and_then(input, |_, input| {
            let (rem, oid) = Oid::parse_der(input).map_err(Err::convert)?;
            let (rem, critical) = der_read_critical(rem)?;
            // OCTET STRING encapsulates [...]
            let (rem, (_, value)) = <&[u8]>::parse_der_as_input(rem)
                .map_err(|_| Err::Error(X509Error::InvalidExtensions))?;

            let (_, parsed_extension) = if self.deep_parse_extensions {
                parser::parse_extension(value.clone(), &oid)?
            } else {
                (rem.take(rem.input_len()), ParsedExtension::Unparsed)
            };

            let ext = X509Extension {
                oid,
                critical,
                value,
                parsed_extension,
            };
            Ok((rem, ext))
        })
        .map_err(|_| X509Error::InvalidExtensions.into())
    }

    fn process<OM: nom::OutputMode>(
        &mut self,
        input: Input<'i>,
    ) -> nom::PResult<OM, Input<'i>, Self::Output, Self::Error> {
        // inspired from nom `impl Parser for F: FnMut`
        let (i, o) = self.parse(input).map_err(|e| match e {
            Err::Incomplete(i) => Err::Incomplete(i),
            Err::Error(e) => Err::Error(OM::Error::bind(|| e)),
            Err::Failure(e) => Err::Failure(e),
        })?;

        Ok((i, OM::Output::bind(|| o)))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ParsedExtension<'a> {
    /// Crate parser does not support this extension (yet)
    UnsupportedExtension {
        oid: Oid<'a>,
    },
    ParseError {
        error: Err<X509Error>,
    },
    /// Section 4.2.1.1 of rfc 5280
    AuthorityKeyIdentifier(AuthorityKeyIdentifier<'a>),
    /// Section 4.2.1.2 of rfc 5280
    SubjectKeyIdentifier(SubjectKeyIdentifier<'a>),
    /// Section 4.2.1.3 of rfc 5280
    KeyUsage(KeyUsage),
    /// Section 4.2.1.4 of rfc 5280
    CertificatePolicies(CertificatePolicies<'a>),
    /// Section 4.2.1.5 of rfc 5280
    PolicyMappings(PolicyMappings<'a>),
    /// Section 4.2.1.6 of rfc 5280
    SubjectAlternativeName(SubjectAlternativeName<'a>),
    /// Section 4.2.1.7 of rfc 5280
    IssuerAlternativeName(IssuerAlternativeName<'a>),
    /// Section 4.2.1.9 of rfc 5280
    BasicConstraints(BasicConstraints),
    /// Section 4.2.1.10 of rfc 5280
    NameConstraints(NameConstraints<'a>),
    /// Section 4.2.1.11 of rfc 5280
    PolicyConstraints(PolicyConstraints),
    /// Section 4.2.1.12 of rfc 5280
    ExtendedKeyUsage(ExtendedKeyUsage<'a>),
    /// Section 4.2.1.13 of rfc 5280
    CRLDistributionPoints(CRLDistributionPoints<'a>),
    /// Section 4.2.1.14 of rfc 5280
    InhibitAnyPolicy(InhibitAnyPolicy),
    /// Section 4.2.2.1 of rfc 5280
    AuthorityInfoAccess(AuthorityInfoAccess<'a>),
    /// Section 4.2.2.2 of rfc 5280
    SubjectInfoAccess(SubjectInfoAccess<'a>),
    /// Netscape certificate type (subject is SSL client, an SSL server, or a CA)
    NSCertType(NSCertType),
    /// Netscape certificate comment
    NsCertComment(&'a str),
    /// Section 5.2.5 of rfc 5280
    IssuingDistributionPoint(IssuingDistributionPoint<'a>),
    /// Section 5.3.1 of rfc 5280
    CRLNumber(BigUint),
    /// Section 5.3.1 of rfc 5280
    ReasonCode(ReasonCode),
    /// Section 5.3.3 of rfc 5280
    InvalidityDate(ASN1Time),
    /// rfc 6962
    SCT(Vec<SignedCertificateTimestamp<'a>>),
    /// Unparsed extension (was not requested in parsing options)
    Unparsed,
}

impl ParsedExtension<'_> {
    /// Return `true` if the extension is unsupported
    pub fn unsupported(&self) -> bool {
        matches!(self, &ParsedExtension::UnsupportedExtension { .. })
    }

    /// Return a reference on the parsing error if the extension parsing failed
    pub fn error(&self) -> Option<&Err<X509Error>> {
        match self {
            ParsedExtension::ParseError { error } => Some(error),
            _ => None,
        }
    }
}

pub(crate) mod parser {
    use crate::extensions::*;
    use asn1_rs::{GeneralizedTime, Integer};
    use lazy_static::lazy_static;

    type ExtParser = fn(Input) -> IResult<Input, ParsedExtension, X509Error>;

    lazy_static! {
        static ref EXTENSION_PARSERS: HashMap<Oid<'static>, ExtParser> = {
            macro_rules! add {
                ($m:ident, $oid:ident, $p:ident) => {
                    $m.insert($oid, $p as ExtParser);
                };
            }

            let mut m = HashMap::new();
            add!(
                m,
                OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
                parse_keyidentifier_ext
            );
            add!(m, OID_X509_EXT_KEY_USAGE, parse_keyusage_ext);
            add!(
                m,
                OID_X509_EXT_SUBJECT_ALT_NAME,
                parse_subjectalternativename_ext
            );
            add!(
                m,
                OID_X509_EXT_ISSUER_ALT_NAME,
                parse_issueralternativename_ext
            );
            add!(
                m,
                OID_X509_EXT_BASIC_CONSTRAINTS,
                parse_basicconstraints_ext
            );
            add!(m, OID_X509_EXT_NAME_CONSTRAINTS, parse_nameconstraints_ext);
            add!(
                m,
                OID_X509_EXT_CERTIFICATE_POLICIES,
                parse_certificatepolicies_ext
            );
            add!(m, OID_X509_EXT_POLICY_MAPPINGS, parse_policymappings_ext);
            add!(
                m,
                OID_X509_EXT_POLICY_CONSTRAINTS,
                parse_policyconstraints_ext
            );
            add!(
                m,
                OID_X509_EXT_EXTENDED_KEY_USAGE,
                parse_extendedkeyusage_ext
            );
            add!(
                m,
                OID_X509_EXT_CRL_DISTRIBUTION_POINTS,
                parse_crldistributionpoints_ext
            );
            add!(
                m,
                OID_X509_EXT_INHIBIT_ANY_POLICY,
                parse_inhibitanypolicy_ext
            );
            add!(
                m,
                OID_PKIX_AUTHORITY_INFO_ACCESS,
                parse_authorityinfoaccess_ext
            );
            add!(m, OID_PKIX_SUBJECT_INFO_ACCESS, parse_subjectinfoaccess_ext);
            add!(
                m,
                OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER,
                parse_authoritykeyidentifier_ext
            );
            add!(m, OID_CT_LIST_SCT, parse_sct_ext);
            add!(m, OID_X509_EXT_CERT_TYPE, parse_nscerttype_ext);
            add!(m, OID_X509_EXT_CERT_COMMENT, parse_nscomment_ext);
            add!(m, OID_X509_EXT_CRL_NUMBER, parse_crl_number);
            add!(m, OID_X509_EXT_REASON_CODE, parse_reason_code);
            add!(m, OID_X509_EXT_INVALIDITY_DATE, parse_invalidity_date);
            add!(
                m,
                OID_X509_EXT_ISSUER_DISTRIBUTION_POINT,
                parse_issuingdistributionpoint_ext
            );
            m
        };
    }

    // look into the parser map if the extension is known, and parse it
    // otherwise, leave it as UnsupportedExtension
    fn parse_extension0<'i>(
        input: Input<'i>,
        oid: &Oid,
    ) -> IResult<Input<'i>, ParsedExtension<'i>, X509Error> {
        if let Some(parser) = EXTENSION_PARSERS.get(oid) {
            match parser(input.clone()) {
                Ok((rem, ext)) => Ok((rem, ext)),
                Err(error) => Ok((input, ParsedExtension::ParseError { error })),
            }
        } else {
            Ok((
                input,
                ParsedExtension::UnsupportedExtension {
                    oid: oid.to_owned(),
                },
            ))
        }
    }

    pub(crate) fn parse_extension<'i>(
        input: Input<'i>,
        oid: &Oid,
    ) -> IResult<Input<'i>, ParsedExtension<'i>, X509Error> {
        parse_extension0(input, oid)
    }

    fn parse_basicconstraints_ext(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        map(
            BasicConstraints::parse_der,
            ParsedExtension::BasicConstraints,
        )
        .parse(input)
    }

    fn parse_nameconstraints_ext(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        map(NameConstraints::parse_der, ParsedExtension::NameConstraints).parse(input)
    }

    pub(super) fn parse_subjectalternativename_ext(
        input: Input,
    ) -> IResult<Input, ParsedExtension, X509Error> {
        map(
            SubjectAlternativeName::parse_der,
            ParsedExtension::SubjectAlternativeName,
        )
        .parse(input)
    }

    pub(super) fn parse_issueralternativename_ext(
        input: Input,
    ) -> IResult<Input, ParsedExtension, X509Error> {
        map(
            IssuerAlternativeName::parse_der,
            ParsedExtension::IssuerAlternativeName,
        )
        .parse(input)
    }

    fn parse_policyconstraints_ext(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        map(
            PolicyConstraints::parse_der,
            ParsedExtension::PolicyConstraints,
        )
        .parse(input)
    }

    fn parse_policymappings_ext(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        map(PolicyMappings::parse_der, ParsedExtension::PolicyMappings).parse(input)
    }

    fn parse_inhibitanypolicy_ext(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        map(
            InhibitAnyPolicy::parse_der,
            ParsedExtension::InhibitAnyPolicy,
        )
        .parse(input)
    }

    fn parse_extendedkeyusage_ext(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        map(
            ExtendedKeyUsage::parse_der,
            ParsedExtension::ExtendedKeyUsage,
        )
        .parse(input)
    }

    fn parse_crldistributionpoints_ext(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        map(
            CRLDistributionPoints::parse_der,
            ParsedExtension::CRLDistributionPoints,
        )
        .parse(input)
    }

    fn parse_issuingdistributionpoint_ext(
        input: Input,
    ) -> IResult<Input, ParsedExtension, X509Error> {
        map(
            IssuingDistributionPoint::parse_der,
            ParsedExtension::IssuingDistributionPoint,
        )
        .parse(input)
    }

    fn parse_authorityinfoaccess_ext(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        map(
            AuthorityInfoAccess::parse_der,
            ParsedExtension::AuthorityInfoAccess,
        )
        .parse(input)
    }

    fn parse_subjectinfoaccess_ext(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        map(
            SubjectInfoAccess::parse_der,
            ParsedExtension::SubjectInfoAccess,
        )
        .parse(input)
    }

    fn parse_authoritykeyidentifier_ext(
        input: Input,
    ) -> IResult<Input, ParsedExtension, X509Error> {
        map(
            AuthorityKeyIdentifier::parse_der,
            ParsedExtension::AuthorityKeyIdentifier,
        )
        .parse(input)
    }

    fn parse_keyidentifier_ext(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        map(
            SubjectKeyIdentifier::parse_der,
            ParsedExtension::SubjectKeyIdentifier,
        )
        .parse(input)
    }

    fn parse_keyusage_ext(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        map(KeyUsage::parse_der, ParsedExtension::KeyUsage).parse(input)
    }

    fn parse_nscerttype_ext(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        map(NSCertType::parse_der, ParsedExtension::NSCertType).parse(input)
    }

    fn parse_nscomment_ext(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        map(parse_der_nscomment, ParsedExtension::NsCertComment).parse(input)
    }

    fn parse_certificatepolicies_ext(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        map(
            CertificatePolicies::parse_der,
            ParsedExtension::CertificatePolicies,
        )
        .parse(input)
    }

    // CRLReason ::= ENUMERATED { ...
    fn parse_reason_code(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        map(ReasonCode::parse_der, ParsedExtension::ReasonCode).parse(input)
    }

    // invalidityDate ::=  GeneralizedTime
    fn parse_invalidity_date(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        let (rem, t) = GeneralizedTime::parse_der(input).map_err(Err::convert)?;
        let dt = t.utc_datetime().map_err(|e| Err::Error(e.into()))?;
        Ok((rem, ParsedExtension::InvalidityDate(ASN1Time::new(dt))))
    }

    // CRLNumber ::= INTEGER (0..MAX)
    // Note from RFC 3280: "CRL verifiers MUST be able to handle CRLNumber values up to 20 octets."
    fn parse_crl_number(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        let (rem, obj) = Integer::parse_der(input).map_err(Err::convert)?;
        let uint = obj.as_biguint().map_err(|e| Err::Error(e.into()))?;
        Ok((rem, ParsedExtension::CRLNumber(uint)))
    }

    fn parse_sct_ext(input: Input) -> IResult<Input, ParsedExtension, X509Error> {
        map(
            parse_ct_signed_certificate_timestamp_list,
            ParsedExtension::SCT,
        )
        .parse(input)
    }
}

/// Parse a sequence of extensions
///
/// <pre>
/// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
/// </pre>
pub(crate) fn parse_extension_sequence(
    i: Input<'_>,
) -> IResult<Input<'_>, Vec<X509Extension<'_>>, X509Error> {
    <Vec<X509Extension>>::parse_der(i)
}

/// Parse a tagged (optional) sequence of extensions (with extensions content parsed)
///
/// <pre>
/// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
/// </pre>
pub(crate) fn parse_opt_tagged_extensions<const TAG: u32>(
    input: Input<'_>,
) -> IResult<Input<'_>, Vec<X509Extension<'_>>, X509Error> {
    if input.is_empty() {
        return Ok((input, Vec::new()));
    }

    let (rem, tagged) = TaggedExplicit::<Any, X509Error, TAG>::parse_der(input)
        .map_err(|_| Err::Error(X509Error::InvalidExtensions))?;

    // in the above parser, TaggedExplicit will consume the outer tag, and Any will contain the Sequence tag
    let any = tagged.into_inner();
    if any.tag() != Tag::Sequence || !any.constructed() {
        return Err(Err::Error(X509Error::InvalidExtensions));
    }

    let parser = X509ExtensionParser::new();
    let inner_data = any.data;

    let (_, seq) = all_consuming(many0(complete(parser))).parse(inner_data)?;

    Ok((rem, seq))
}

/// Parse a tagged sequence (optional) of extensions (not going into extensions content)
///
/// <pre>
/// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
/// </pre>
pub(crate) fn parse_opt_tagged_extensions_envelope_only<const TAG: u32>(
    input: Input<'_>,
) -> IResult<Input<'_>, Vec<X509Extension<'_>>, X509Error> {
    if input.is_empty() {
        return Ok((input, Vec::new()));
    }

    let (rem, tagged) = TaggedExplicit::<Any, X509Error, TAG>::parse_der(input)
        .map_err(|_| Err::Error(X509Error::InvalidExtensions))?;

    // in the above parser, TaggedExplicit will consume the outer tag, and Any will contain the Sequence tag
    let any = tagged.into_inner();
    if any.tag() != Tag::Sequence || !any.constructed() {
        return Err(Err::Error(X509Error::InvalidExtensions));
    }

    let parser = X509ExtensionParser::new().with_deep_parse_extensions(false);
    let inner_data = any.data;

    let (_, seq) = all_consuming(many0(complete(parser))).parse(inner_data)?;

    Ok((rem, seq))
}

fn der_read_critical(input: Input<'_>) -> IResult<Input<'_>, bool, X509Error> {
    // Some certificates do not respect the DER BOOLEAN constraint (true must be encoded as 0xff)
    // so we attempt to parse as BER
    use asn1_rs::BerParser;
    let (rem, obj) = <bool>::parse_ber_optional(input).map_err(Err::convert)?;
    let value = obj
        .unwrap_or(false) // default critical value
        ;
    Ok((rem, value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1_rs::oid;

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
        let crt = crate::parse_x509_certificate(include_bytes!("../../assets/extension1.der"))
            .unwrap()
            .1;
        let tbs = &crt.tbs_certificate;
        let bc = crt
            .basic_constraints()
            .expect("could not get basic constraints")
            .expect("no basic constraints found");
        assert_eq!(
            bc.value,
            &BasicConstraints {
                ca: true,
                path_len_constraint: Some(1)
            }
        );
        {
            let ku = tbs
                .key_usage()
                .expect("could not get key usage")
                .expect("no key usage found")
                .value;
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
            let eku = tbs
                .extended_key_usage()
                .expect("could not get extended key usage")
                .expect("no extended key usage found")
                .value;
            assert!(!eku.any);
            assert!(eku.server_auth);
            assert!(!eku.client_auth);
            assert!(eku.code_signing);
            assert!(!eku.email_protection);
            assert!(eku.time_stamping);
            assert!(!eku.ocsp_signing);
            assert_eq!(eku.other, vec![oid!(1.2.3 .4 .0 .42)]);
        }
        assert_eq!(
            tbs.policy_constraints()
                .expect("could not get policy constraints")
                .expect("no policy constraints found")
                .value,
            &PolicyConstraints {
                require_explicit_policy: None,
                inhibit_policy_mapping: Some(10)
            }
        );
        let val = tbs
            .inhibit_anypolicy()
            .expect("could not get inhibit_anypolicy")
            .expect("no inhibit_anypolicy found")
            .value;
        assert_eq!(val, &InhibitAnyPolicy(2));
        {
            let alt_names = &tbs
                .subject_alternative_name()
                .expect("could not get subject alt names")
                .expect("no subject alt names found")
                .value
                .0;
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
            assert_eq!(alt_names[5], GeneralName::RegisteredID(oid! {1.2.90.0}));
            assert!(matches!(
                &alt_names[6],
                GeneralName::OtherName(oid , any) if *oid == oid! {1.2.3.4} && any.data.as_bytes2() == b"\x0C\x15some other identifier"
            ));
        }

        {
            let name_constraints = &tbs
                .name_constraints()
                .expect("could not get name constraints")
                .expect("no name constraints found")
                .value;
            assert_eq!(name_constraints.permitted_subtrees, None);
            assert_eq!(
                name_constraints.excluded_subtrees,
                Some(vec![
                    GeneralSubtree {
                        base: GeneralName::IPAddress([192, 168, 0, 0, 255, 255, 0, 0].as_ref()),
                        minimum: 0,
                        maximum: None,
                    },
                    GeneralSubtree {
                        base: GeneralName::RFC822Name("foo.com"),
                        minimum: 0,
                        maximum: None,
                    },
                ])
            );
        }
    }

    #[test]
    fn test_extensions2() {
        let crt = crate::parse_x509_certificate(include_bytes!("../../assets/extension2.der"))
            .unwrap()
            .1;
        let tbs = crt.tbs_certificate;
        assert_eq!(
            tbs.policy_constraints()
                .expect("could not get policy constraints")
                .expect("no policy constraints found")
                .value,
            &PolicyConstraints {
                require_explicit_policy: Some(5000),
                inhibit_policy_mapping: None
            }
        );
        {
            let pm = tbs
                .policy_mappings()
                .expect("could not get policy_mappings")
                .expect("no policy_mappings found")
                .value
                .clone()
                .into_hashmap();
            let mut pm_ref = HashMap::new();
            pm_ref.insert(oid!(2.34.23), vec![oid!(2.2)]);
            pm_ref.insert(oid!(1.1), vec![oid!(0.0.4)]);
            pm_ref.insert(oid!(2.2), vec![oid!(2.2.1), oid!(2.2.3)]);
            assert_eq!(pm, pm_ref);
        }
    }

    #[test]
    fn test_extensions_crl_distribution_points() {
        // Extension not present
        {
            let crt = crate::parse_x509_certificate(include_bytes!(
                "../../assets/crl-ext/crl-no-crl.der"
            ))
            .unwrap()
            .1;
            assert!(!crt
                .tbs_certificate
                .extensions_map()
                .unwrap()
                .contains_key(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS));
        }
        // CRLDistributionPoints has 1 entry with 1 URI
        {
            let (_, crt) = crate::parse_x509_certificate(include_bytes!(
                "../../assets/crl-ext/crl-simple.der"
            ))
            .unwrap();
            let crl = crt
                .tbs_certificate
                .extensions_map()
                .unwrap()
                .get(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
                .unwrap()
                .parsed_extension();
            eprintln!("crl distribution point: {crl:?}");
            assert!(matches!(crl, ParsedExtension::CRLDistributionPoints(_)));
            if let ParsedExtension::CRLDistributionPoints(crl) = crl {
                assert_eq!(crl.len(), 1);
                assert!(crl[0].reasons.is_none());
                assert!(crl[0].crl_issuer.is_none());
                let distribution_point = crl[0].distribution_point.as_ref().unwrap();
                assert!(matches!(
                    distribution_point,
                    DistributionPointName::FullName(_)
                ));
                if let DistributionPointName::FullName(names) = distribution_point {
                    assert_eq!(names.len(), 1);
                    assert!(matches!(names[0], GeneralName::URI(_)));
                    if let GeneralName::URI(uri) = names[0] {
                        assert_eq!(uri, "http://example.com/myca.crl")
                    }
                }
            }
        }
        // CRLDistributionPoints has 2 entries
        {
            let crt = crate::parse_x509_certificate(include_bytes!(
                "../../assets/crl-ext/crl-complex.der"
            ))
            .unwrap()
            .1;
            let crl = crt
                .tbs_certificate
                .extensions_map()
                .unwrap()
                .get(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
                .unwrap()
                .parsed_extension();
            assert!(matches!(crl, ParsedExtension::CRLDistributionPoints(_)));
            if let ParsedExtension::CRLDistributionPoints(crl) = crl {
                assert_eq!(crl.len(), 2);
                // First CRL Distribution point
                let reasons = crl[0].reasons.as_ref().unwrap();
                assert!(reasons.key_compromise());
                assert!(reasons.ca_compromise());
                assert!(!reasons.affiliation_changed());
                assert!(!reasons.superseded());
                assert!(!reasons.cessation_of_operation());
                assert!(!reasons.certificate_hold());
                assert!(!reasons.privilege_withdrawn());
                assert!(reasons.aa_compromise());
                assert_eq!(
                    format!("{}", reasons),
                    "Key Compromise, CA Compromise, AA Compromise"
                );
                let issuers = crl[0].crl_issuer.as_ref().unwrap();
                assert_eq!(issuers.len(), 1);
                assert!(matches!(issuers[0], GeneralName::DirectoryName(_)));
                if let GeneralName::DirectoryName(name) = &issuers[0] {
                    assert_eq!(name.to_string(), "C=US, O=Organisation, CN=Some Name");
                }
                let distribution_point = crl[0].distribution_point.as_ref().unwrap();
                assert!(matches!(
                    distribution_point,
                    DistributionPointName::FullName(_)
                ));
                if let DistributionPointName::FullName(names) = distribution_point {
                    assert_eq!(names.len(), 1);
                    assert!(matches!(names[0], GeneralName::URI(_)));
                    if let GeneralName::URI(uri) = names[0] {
                        assert_eq!(uri, "http://example.com/myca.crl")
                    }
                }
                // Second CRL Distribution point
                let reasons = crl[1].reasons.as_ref().unwrap();
                assert!(reasons.key_compromise());
                assert!(reasons.ca_compromise());
                assert!(!reasons.affiliation_changed());
                assert!(!reasons.superseded());
                assert!(!reasons.cessation_of_operation());
                assert!(!reasons.certificate_hold());
                assert!(!reasons.privilege_withdrawn());
                assert!(!reasons.aa_compromise());
                assert_eq!(format!("{}", reasons), "Key Compromise, CA Compromise");
                assert!(crl[1].crl_issuer.is_none());
                let distribution_point = crl[1].distribution_point.as_ref().unwrap();
                assert!(matches!(
                    distribution_point,
                    DistributionPointName::FullName(_)
                ));
                if let DistributionPointName::FullName(names) = distribution_point {
                    assert_eq!(names.len(), 1);
                    assert!(matches!(names[0], GeneralName::URI(_)));
                    if let GeneralName::URI(uri) = names[0] {
                        assert_eq!(uri, "http://example.com/myca2.crl")
                    }
                }
            }
        }
    }

    // Test cases for:
    // - parsing SubjectAlternativeName
    // - parsing NameConstraints
}
