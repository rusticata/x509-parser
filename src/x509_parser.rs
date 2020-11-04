//! X.509 certificate parser
//!
//! Based on RFC5280
//!

use crate::error::{X509Error, X509Result};
use crate::time::ASN1Time;
use crate::x509::*;
use chrono::offset::TimeZone;
use chrono::{DateTime, Datelike, Utc};
use nom::branch::alt;
use nom::bytes::complete::take;
use nom::combinator::{all_consuming, complete, map_opt, map_res, opt};
use nom::multi::{many0, many1};
use nom::{exact, Err, IResult, Offset};
use num_bigint::BigUint;
use std::collections::HashMap;

use der_parser::ber::*;
use der_parser::der::*;
use der_parser::error::*;
use der_parser::oid::Oid;
use der_parser::*;

fn parse_malformed_string(i: &[u8]) -> DerResult {
    let (rem, hdr) = ber_read_element_header(i)?;
    let len = hdr.len.primitive()?;
    if len > MAX_OBJECT_SIZE {
        return Err(nom::Err::Error(BerError::InvalidLength));
    }
    match hdr.tag {
        BerTag::PrintableString => {
            // if we are in this function, the PrintableString could not be validated.
            // Accept it without validating charset, because some tools do not respect the charset
            // restrictions (for ex. they use '*' while explicingly disallowed)
            let (rem, data) = take(len as usize)(rem)?;
            let s = std::str::from_utf8(data).map_err(|_| BerError::BerValueError)?;
            let content = BerObjectContent::PrintableString(s);
            let obj = DerObject::from_header_and_content(hdr, content);
            Ok((rem, obj))
        }
        _ => Err(nom::Err::Error(BerError::InvalidTag)),
    }
}

// allow relaxed parsing of UTCTime (ex: 370116130016+0000)
fn parse_malformed_date(i: &[u8]) -> DerResult {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    fn check_char(b: &u8) -> bool {
        (0x20 <= *b && *b <= 0x7f) || (*b == b'+')
    }
    let (rem, hdr) = ber_read_element_header(i)?;
    let len = hdr.len.primitive()?;
    if len > MAX_OBJECT_SIZE {
        return Err(nom::Err::Error(BerError::InvalidLength));
    }
    match hdr.tag {
        BerTag::UtcTime => {
            // if we are in this function, the PrintableString could not be validated.
            // Accept it without validating charset, because some tools do not respect the charset
            // restrictions (for ex. they use '*' while explicingly disallowed)
            let (rem, data) = take(len as usize)(rem)?;
            if !data.iter().all(check_char) {
                return Err(nom::Err::Error(BerError::BerValueError));
            }
            let s = std::str::from_utf8(data).map_err(|_| BerError::BerValueError)?;
            let content = BerObjectContent::UTCTime(s);
            let obj = DerObject::from_header_and_content(hdr, content);
            Ok((rem, obj))
        }
        _ => Err(nom::Err::Error(BerError::InvalidTag)),
    }
}

// AttributeValue          ::= ANY -- DEFINED BY AttributeType
#[inline]
fn parse_attribute_value(i: &[u8]) -> DerResult {
    alt((parse_der, parse_malformed_string))(i)
}

// AttributeTypeAndValue   ::= SEQUENCE {
//     type    AttributeType,
//     value   AttributeValue }
fn parse_attr_type_and_value<'a>(i: &'a [u8]) -> X509Result<AttributeTypeAndValue<'a>> {
    parse_ber_sequence_defined_g(|_, i| {
        let (i, attr_type) = map_res(parse_der_oid, |x: DerObject<'a>| x.as_oid_val())(i)
            .or(Err(X509Error::InvalidX509Name))?;
        let (i, attr_value) = parse_attribute_value(i).or(Err(X509Error::InvalidX509Name))?;
        let attr = AttributeTypeAndValue {
            attr_type,
            attr_value,
        };
        Ok((i, attr))
    })(i)
}

fn parse_rdn(i: &[u8]) -> X509Result<RelativeDistinguishedName> {
    parse_ber_set_defined_g(|_, i| {
        let (i, set) = many1(complete(parse_attr_type_and_value))(i)?;
        let rdn = RelativeDistinguishedName { set };
        Ok((i, rdn))
    })(i)
}

/// Parse the X.501 type Name, used for ex in issuer and subject of a X.509 certificate
pub fn parse_x509_name(i: &[u8]) -> X509Result<X509Name> {
    let start_i = i;
    parse_ber_sequence_defined_g(move |_, i| {
        let (i, rdn_seq) = many0(complete(parse_rdn))(i)?;
        let len = start_i.offset(i);
        let name = X509Name {
            rdn_seq,
            raw: &start_i[..len],
        };
        Ok((i, name))
    })(i)
}

fn parse_version(i: &[u8]) -> X509Result<u32> {
    parse_ber_tagged_explicit_g(0, |_, a| parse_ber_u32(a))(i).or(Ok((i, 0)))
}

fn parse_serial(i: &[u8]) -> X509Result<(&[u8], BigUint)> {
    map_opt(parse_der_integer, get_serial_info)(i).map_err(|_| X509Error::InvalidSerial.into())
}

fn parse_choice_of_time(i: &[u8]) -> DerResult {
    alt((
        complete(parse_der_utctime),
        complete(parse_der_generalizedtime),
        complete(parse_malformed_date),
    ))(i)
}

fn der_to_utctime(obj: DerObject) -> Result<ASN1Time, X509Error> {
    if let BerObjectContent::UTCTime(s) = obj.content {
        let dt = if s.ends_with('Z') {
            // UTC
            if s.len() == 11 {
                // some implementations do not encode the number of seconds
                // accept certificate even if date is not correct
                Utc.datetime_from_str(s, "%y%m%d%H%MZ")
            } else {
                Utc.datetime_from_str(s, "%y%m%d%H%M%SZ")
            }
        } else {
            DateTime::parse_from_str(s, "%y%m%d%H%M%S%z").map(|dt| dt.with_timezone(&Utc))
        };
        match dt {
            Ok(mut tm) => {
                if tm.year() < 50 {
                    tm = tm
                        .with_year(tm.year() + 100)
                        .ok_or(X509Error::InvalidDate)?;
                }
                // tm = tm.with_year(tm.year() + 1900).ok_or(X509Error::InvalidDate)?;
                // eprintln!("date: {}", tm.rfc822());
                Ok(ASN1Time::from_datetime_utc(tm))
            }
            Err(_e) => Err(X509Error::InvalidDate),
        }
    } else if let BerObjectContent::GeneralizedTime(s) = obj.content {
        let dt = if s.ends_with('Z') {
            // UTC
            if s.len() == 11 {
                // some implementations do not encode the number of seconds
                // accept certificate even if date is not correct
                Utc.datetime_from_str(s, "%Y%m%d%H%MZ")
            } else {
                Utc.datetime_from_str(s, "%Y%m%d%H%M%SZ")
            }
        } else {
            DateTime::parse_from_str(s, "%Y%m%d%H%M%S%z").map(|dt| dt.with_timezone(&Utc))
        };
        dt.map(ASN1Time::from_datetime_utc)
            .or(Err(X509Error::InvalidDate))
    } else {
        Err(X509Error::InvalidDate)
    }
}

fn parse_validity(i: &[u8]) -> X509Result<Validity> {
    parse_ber_sequence_defined_g(|_, i| {
        let (i, not_before) =
            map_res(parse_choice_of_time, der_to_utctime)(i).or(Err(X509Error::InvalidDate))?;
        let (i, not_after) =
            map_res(parse_choice_of_time, der_to_utctime)(i).or(Err(X509Error::InvalidDate))?;
        let v = Validity {
            not_before,
            not_after,
        };
        Ok((i, v))
    })(i)
}

/// Parse the SubjectPublicKeyInfo struct portion of a DER-encoded X.509 Certificate
pub fn parse_subject_public_key_info<'a>(i: &'a [u8]) -> X509Result<SubjectPublicKeyInfo<'a>> {
    parse_ber_sequence_defined_g(|_, i| {
        let (i, algorithm) = parse_algorithm_identifier(i)?;
        let (i, subject_public_key) = map_res(parse_der_bitstring, |x: DerObject<'a>| {
            match x.content {
                BerObjectContent::BitString(_, ref b) => Ok(b.to_owned()), // XXX padding ignored
                _ => Err(BerError::BerTypeError),
            }
        })(i)
        .or(Err(X509Error::InvalidSPKI))?;
        let spki = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key,
        };
        Ok((i, spki))
    })(i)
}

fn bitstring_to_unique_id(x: BerObject) -> Result<Option<UniqueIdentifier>, BerError> {
    match x.content {
        BerObjectContent::Optional(None) => Ok(None),
        BerObjectContent::Optional(Some(o)) => match o.content {
            BerObjectContent::BitString(_, b) => Ok(Some(UniqueIdentifier(b.to_owned()))),
            _ => Err(BerError::BerTypeError),
        },
        _ => Err(BerError::BerTypeError),
    }
}

// Parse a [tag] UniqueIdentifier OPTIONAL
//
// UniqueIdentifier  ::=  BIT STRING
fn parse_tagged_implicit_unique_identifier(
    i: &[u8],
    tag: u32,
) -> BerResult<Option<UniqueIdentifier>> {
    let (rem, obj) = parse_ber_optional(parse_ber_tagged_implicit(
        tag,
        parse_ber_content(BerTag::BitString),
    ))(i)?;
    let unique_id = bitstring_to_unique_id(obj)?;
    Ok((rem, unique_id))
}

// issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL
fn parse_issuer_unique_id(i: &[u8]) -> X509Result<Option<UniqueIdentifier>> {
    parse_tagged_implicit_unique_identifier(i, 1).map_err(|_| X509Error::InvalidIssuerUID.into())
}

// subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL
fn parse_subject_unique_id(i: &[u8]) -> X509Result<Option<UniqueIdentifier>> {
    parse_tagged_implicit_unique_identifier(i, 2).map_err(|_| X509Error::InvalidIssuerUID.into())
}

fn der_read_critical(i: &[u8]) -> BerResult<bool> {
    // parse_der_optional!(i, parse_der_bool)
    let (rem, obj) = opt(parse_der_bool)(i)?;
    let value = obj
        .map(|o| o.as_bool().unwrap_or_default()) // unwrap cannot fail, we just read a bool
        .unwrap_or(false) // default critical value
        ;
    Ok((rem, value))
}

/// Parse a DER-encoded X.509 extension
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
/// This function parses the global structure (described above), and will return the object if it
/// succeeds. During this step, it also attempts to parse the content of the extension, if known.
/// The returned object has a
/// [parsed_extension](x509/struct.X509Extension.html#method.parsed_extension) method. The returned
/// enum is either a known extension, or the special value `ParsedExtension::UnsupportedExtension`.
///
/// <pre>
/// Extension  ::=  SEQUENCE  {
///     extnID      OBJECT IDENTIFIER,
///     critical    BOOLEAN DEFAULT FALSE,
///     extnValue   OCTET STRING  }
/// </pre>
///
/// # Example
///
/// ```rust
/// # use x509_parser::{parse_extension, extensions::ParsedExtension};
/// #
/// static DER: &[u8] = &[
///    0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0xA3, 0x05, 0x2F, 0x18,
///    0x60, 0x50, 0xC2, 0x89, 0x0A, 0xDD, 0x2B, 0x21, 0x4F, 0xFF, 0x8E, 0x4E, 0xA8, 0x30, 0x31,
///    0x36 ];
///
/// # fn main() {
/// let res = parse_extension(DER);
/// match res {
///     Ok((_rem, ext)) => {
///         println!("Extension OID: {}", ext.oid);
///         println!("  Critical: {}", ext.critical);
///         let parsed_ext = ext.parsed_extension();
///         assert!(*parsed_ext != ParsedExtension::UnsupportedExtension);
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
pub fn parse_extension(i: &[u8]) -> X509Result<X509Extension> {
    parse_ber_sequence_defined_g(|_, i| {
        let (i, oid) = map_res(parse_der_oid, |x| x.as_oid_val())(i)?;
        let (i, critical) = der_read_critical(i)?;
        let (i, value) = map_res(parse_der_octetstring, |x| x.as_slice())(i)?;
        let (i, parsed_extension) = crate::extensions::parser::parse_extension(i, value, &oid)?;
        let ext = X509Extension {
            oid,
            critical,
            value,
            parsed_extension,
        };
        Ok((i, ext))
    })(i)
    .map_err(|_| X509Error::InvalidExtensions.into())
}

/// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
fn parse_extension_sequence(i: &[u8]) -> X509Result<Vec<X509Extension>> {
    parse_ber_sequence_defined_g(|_, a| all_consuming(many0(complete(parse_extension)))(a))(i)
}

fn parse_extensions(i: &[u8], explicit_tag: BerTag) -> X509Result<HashMap<Oid, X509Extension>> {
    if i.is_empty() {
        return Ok((i, HashMap::new()));
    }

    match der_read_element_header(i) {
        Ok((rem, hdr)) => {
            if hdr.tag != explicit_tag {
                return Err(Err::Error(X509Error::InvalidExtensions));
            }
            let mut extensions = HashMap::new();
            let (rem, list) = exact!(rem, parse_extension_sequence)?;
            for ext in list.into_iter() {
                if extensions.insert(ext.oid.clone(), ext).is_some() {
                    // duplicate extensions are not allowed
                    return Err(Err::Failure(X509Error::DuplicateExtensions));
                }
            }
            Ok((rem, extensions))
        }
        Err(_) => Err(X509Error::InvalidExtensions.into()),
    }
}

fn get_serial_info(o: DerObject) -> Option<(&[u8], BigUint)> {
    let big = o.as_biguint()?;
    let slice = o.as_slice().ok()?;

    Some((slice, big))
}

/// Parse a DER-encoded TbsCertificate object
///
/// <pre>
/// TBSCertificate  ::=  SEQUENCE  {
///      version         [0]  Version DEFAULT v1,
///      serialNumber         CertificateSerialNumber,
///      signature            AlgorithmIdentifier,
///      issuer               Name,
///      validity             Validity,
///      subject              Name,
///      subjectPublicKeyInfo SubjectPublicKeyInfo,
///      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///                           -- If present, version MUST be v2 or v3
///      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///                           -- If present, version MUST be v2 or v3
///      extensions      [3]  Extensions OPTIONAL
///                           -- If present, version MUST be v3 --  }
/// </pre>
pub fn parse_tbs_certificate<'a>(i: &'a [u8]) -> X509Result<TbsCertificate<'a>> {
    let start_i = i;
    parse_ber_sequence_defined_g(move |_, i| {
        let (i, version) = parse_version(i)?;
        let (i, serial) = parse_serial(i)?;
        let (i, signature) = parse_algorithm_identifier(i)?;
        let (i, issuer) = parse_x509_name(i)?;
        let (i, validity) = parse_validity(i)?;
        let (i, subject) = parse_x509_name(i)?;
        let (i, subject_pki) = parse_subject_public_key_info(i)?;
        let (i, issuer_uid) = parse_issuer_unique_id(i)?;
        let (i, subject_uid) = parse_subject_unique_id(i)?;
        let (i, extensions) = parse_extensions(i, BerTag(3))?;
        let len = start_i.offset(i);
        let tbs = TbsCertificate {
            version,
            serial: serial.1,
            signature,
            issuer,
            validity,
            subject,
            subject_pki,
            issuer_uid,
            subject_uid,
            extensions,

            raw: &start_i[..len],
            raw_serial: serial.0,
        };
        Ok((i, tbs))
    })(i)
}

fn parse_tbs_cert_list(i: &[u8]) -> X509Result<TbsCertList> {
    let start_i = i;
    parse_ber_sequence_defined_g(move |_, i| {
        let (i, version) = opt(parse_ber_u32)(i).or(Err(X509Error::InvalidVersion))?;
        let (i, signature) = parse_algorithm_identifier(i)?;
        let (i, issuer) = parse_x509_name(i)?;
        let (i, this_update) =
            map_res(parse_choice_of_time, der_to_utctime)(i).or(Err(X509Error::InvalidDate))?;
        let (i, next_update) = opt(map_res(parse_choice_of_time, der_to_utctime))(i)
            .or(Err(X509Error::InvalidDate))?;
        let (i, revoked_certificates) = opt(complete(parse_revoked_certificates))(i)?;
        let (i, extensions) = parse_extensions(i, BerTag(0))?;
        let len = start_i.offset(i);
        let tbs = TbsCertList {
            version,
            signature,
            issuer,
            this_update,
            next_update,
            revoked_certificates: revoked_certificates.unwrap_or_default(),
            extensions,
            raw: &start_i[..len],
        };
        Ok((i, tbs))
    })(i)
}

fn parse_revoked_certificates(i: &[u8]) -> X509Result<Vec<RevokedCertificate>> {
    parse_ber_sequence_defined_g(|_, a| {
        all_consuming(many1(complete(parse_revoked_certificate)))(a)
    })(i)
}

fn parse_revoked_certificate(i: &[u8]) -> X509Result<RevokedCertificate> {
    parse_ber_sequence_defined_g(|_, i| {
        let (i, (raw_serial, user_certificate)) = parse_serial(i)?;
        let (i, revocation_date) =
            map_res(parse_choice_of_time, der_to_utctime)(i).or(Err(X509Error::InvalidDate))?;
        let (i, extensions) = opt(complete(parse_extension_sequence))(i)?;
        let revoked = RevokedCertificate {
            user_certificate,
            revocation_date,
            extensions: extensions.unwrap_or_default(),
            raw_serial,
        };
        Ok((i, revoked))
    })(i)
}

/// Parse an algorithm identifier
///
/// An algorithm identifier is defined by the following ASN.1 structure:
///
/// <pre>
/// AlgorithmIdentifier  ::=  SEQUENCE  {
///      algorithm               OBJECT IDENTIFIER,
///      parameters              ANY DEFINED BY algorithm OPTIONAL  }
/// </pre>
///
/// The algorithm identifier is used to identify a cryptographic
/// algorithm.  The OBJECT IDENTIFIER component identifies the algorithm
/// (such as DSA with SHA-1).  The contents of the optional parameters
/// field will vary according to the algorithm identified.
// lifetime is *not* useless, it is required to tell the compiler the content of the temporary
// DerObject has the same lifetime as the input
#[allow(clippy::needless_lifetimes)]
pub fn parse_algorithm_identifier(i: &[u8]) -> X509Result<AlgorithmIdentifier> {
    parse_ber_sequence_defined_g(|_, i| {
        let (i, algorithm) = map_res(parse_der_oid, |x| x.as_oid_val())(i)
            .or(Err(X509Error::InvalidAlgorithmIdentifier))?;
        let (i, parameters) =
            opt(complete(parse_der))(i).or(Err(X509Error::InvalidAlgorithmIdentifier))?;

        let alg = AlgorithmIdentifier {
            algorithm,
            parameters,
        };
        Ok((i, alg))
    })(i)
}

/// Parse a DER-encoded X.509 Certificate, and return the remaining of the input and the built
/// object.
///
/// The returned object uses zero-copy, and so has the same lifetime as the input.
///
/// Note that only parsing is done, not validation.
///
/// # Example
///
/// To parse a certificate and print the subject and issuer:
///
/// ```rust
/// # use x509_parser::parse_x509_der;
/// #
/// # static DER: &'static [u8] = include_bytes!("../assets/IGC_A.der");
/// #
/// # fn main() {
/// let res = parse_x509_der(DER);
/// match res {
///     Ok((_rem, x509)) => {
///         let subject = &x509.tbs_certificate.subject;
///         let issuer = &x509.tbs_certificate.issuer;
///         println!("X.509 Subject: {}", subject);
///         println!("X.509 Issuer: {}", issuer);
///     },
///     _ => panic!("x509 parsing failed: {:?}", res),
/// }
/// # }
/// ```
pub fn parse_x509_der<'a>(i: &'a [u8]) -> X509Result<X509Certificate<'a>> {
    parse_ber_sequence_defined_g(|_, i| {
        let (i, tbs_certificate) = parse_tbs_certificate(i)?;
        let (i, signature_algorithm) = parse_algorithm_identifier(i)?;
        let (i, signature_value) = parse_signature_value(i)?;
        let cert = X509Certificate {
            tbs_certificate,
            signature_algorithm,
            signature_value,
        };
        Ok((i, cert))
    })(i)
}

/// Parse a DER-encoded X.509 v2 CRL, and return the remaining of the input and the built
/// object.
///
/// The returned object uses zero-copy, and so has the same lifetime as the input.
///
/// <pre>
/// CertificateList  ::=  SEQUENCE  {
///      tbsCertList          TBSCertList,
///      signatureAlgorithm   AlgorithmIdentifier,
///      signatureValue       BIT STRING  }
/// </pre>
///
/// # Example
///
/// To parse a CRL and print information about revoked certificates:
///
/// ```rust
/// # use x509_parser::parse_crl_der;
/// #
/// # static DER: &'static [u8] = include_bytes!("../assets/example.crl");
/// #
/// # fn main() {
/// let res = parse_crl_der(DER);
/// match res {
///     Ok((_rem, crl)) => {
///         for revoked in crl.iter_revoked_certificates() {
///             println!("Revoked certificate serial: {}", revoked.raw_serial_as_string());
///             println!("  Reason: {}", revoked.reason_code().unwrap_or_default());
///         }
///     },
///     _ => panic!("CRL parsing failed: {:?}", res),
/// }
/// # }
/// ```
pub fn parse_crl_der(i: &[u8]) -> X509Result<CertificateRevocationList> {
    parse_ber_sequence_defined_g(|_, i| {
        let (i, tbs_cert_list) = parse_tbs_cert_list(i)?;
        let (i, signature_algorithm) = parse_algorithm_identifier(i)?;
        let (i, signature_value) = parse_signature_value(i)?;
        let crl = CertificateRevocationList {
            tbs_cert_list,
            signature_algorithm,
            signature_value,
        };
        Ok((i, crl))
    })(i)
}

fn parse_signature_value(i: &[u8]) -> X509Result<BitStringObject> {
    map_res(parse_der_bitstring, |x: DerObject| {
        match x.content {
            BerObjectContent::BitString(_, ref b) => Ok(b.to_owned()), // XXX padding ignored
            _ => Err(BerError::BerTypeError),
        }
    })(i)
    .or(Err(Err::Error(X509Error::InvalidSignatureValue)))
}

#[deprecated(since = "0.4.0", note = "please use `parse_x509_der` instead")]
pub fn x509_parser(i: &[u8]) -> IResult<&[u8], X509Certificate<'_>, X509Error> {
    parse_x509_der(i)
}
