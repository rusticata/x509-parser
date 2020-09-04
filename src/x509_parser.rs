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
use nom::combinator::{complete, map_opt, map_res, opt};
use nom::multi::{many0, many1};
use nom::{exact, Err, IResult, Offset};
use num_bigint::BigUint;
use std::collections::HashMap;
use std::str;

use der_parser::ber::*;
use der_parser::der::*;
use der_parser::error::*;
use der_parser::oid::Oid;
use der_parser::*;

// AttributeValue          ::= ANY -- DEFINED BY AttributeType
#[inline]
fn parse_attribute_value(i: &[u8]) -> BerResult<DerObject> {
    parse_der(i)
}

// AttributeTypeAndValue   ::= SEQUENCE {
//     type    AttributeType,
//     value   AttributeValue }
fn parse_attr_type_and_value<'a>(i: &'a [u8]) -> X509Result<AttributeTypeAndValue<'a>> {
    parse_ber_sequence_defined_g(|i| {
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
    parse_ber_set_defined_g(|i| {
        let (i, set) = many1(complete(parse_attr_type_and_value))(i)?;
        let rdn = RelativeDistinguishedName { set };
        Ok((i, rdn))
    })(i)
}

/// Parse the X.501 type Name, used for ex in issuer and subject of a X.509 certificate
pub fn parse_x509_name(i: &[u8]) -> X509Result<X509Name> {
    let start_i = i;
    parse_ber_sequence_defined_g(move |i| {
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
    parse_ber_tagged_explicit(0, parse_ber_u32)(i).or(Ok((i, 0)))
}

fn parse_serial(i: &[u8]) -> X509Result<(&[u8], BigUint)> {
    map_opt(parse_der_integer, get_serial_info)(i).map_err(|_| X509Error::InvalidSerial.into())
}

fn parse_choice_of_time(i: &[u8]) -> DerResult {
    alt((
        complete(parse_der_utctime),
        complete(parse_der_generalizedtime),
    ))(i)
}

fn der_to_utctime(obj: DerObject) -> Result<ASN1Time, X509Error> {
    if let BerObjectContent::UTCTime(s) = obj.content {
        let xs = str::from_utf8(s).or(Err(X509Error::InvalidDate))?;
        let dt = if xs.ends_with('Z') {
            // UTC
            Utc.datetime_from_str(xs, "%y%m%d%H%M%SZ")
        } else {
            DateTime::parse_from_str(xs, "%y%m%d%H%M%S%z").map(|dt| dt.with_timezone(&Utc))
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
        let xs = str::from_utf8(s).or(Err(X509Error::InvalidDate))?;
        let dt = if xs.ends_with('Z') {
            // UTC
            Utc.datetime_from_str(xs, "%Y%m%d%H%M%SZ")
        } else {
            DateTime::parse_from_str(xs, "%Y%m%d%H%M%S%z").map(|dt| dt.with_timezone(&Utc))
        };
        dt.map(ASN1Time::from_datetime_utc)
            .or(Err(X509Error::InvalidDate))
    } else {
        Err(X509Error::InvalidDate)
    }
}

fn parse_validity(i: &[u8]) -> X509Result<Validity> {
    parse_ber_sequence_defined_g(|i| {
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
    parse_ber_sequence_defined_g(|i| {
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

fn bitstring_to_unique_id(x: BerObjectContent) -> Result<Option<UniqueIdentifier>, BerError> {
    let (_, y) = x.as_context_specific()?;
    match y {
        None => Ok(None),
        Some(x) => match x.content {
            BerObjectContent::BitString(_, b) => Ok(Some(UniqueIdentifier(b.to_owned()))),
            _ => Err(BerError::BerTypeError),
        },
    }
}

fn parse_issuer_unique_id(i: &[u8]) -> X509Result<Option<UniqueIdentifier>> {
    match parse_ber_tagged_implicit(1, parse_ber_content(BerTag::BitString))(i) {
        Ok((i, obj)) => bitstring_to_unique_id(obj)
            .map(|uid| (i, uid))
            .map_err(|_| X509Error::InvalidIssuerUID.into()),
        Err(_) => Ok((i, None)),
    }
}

fn parse_subject_unique_id(i: &[u8]) -> X509Result<Option<UniqueIdentifier>> {
    match parse_ber_tagged_implicit(2, parse_ber_content(BerTag::BitString))(i) {
        Ok((i, obj)) => bitstring_to_unique_id(obj)
            .map(|uid| (i, uid))
            .map_err(|_| X509Error::InvalidSubjectUID.into()),
        Err(_) => Ok((i, None)),
    }
}

#[inline]
fn der_read_opt_bool(i: &[u8]) -> DerResult {
    parse_der_optional!(i, parse_der_bool)
}

fn parse_extension<'a>(i: &'a [u8]) -> X509Result<X509Extension<'a>> {
    parse_ber_sequence_defined_g(|i| {
        let (i, oid) = map_res(parse_der_oid, |x: DerObject<'a>| x.as_oid_val())(i)?;
        let (i, critical) = map_res(der_read_opt_bool, |x: DerObject| {
            match x.as_context_specific() {
                Ok((_, Some(obj))) => obj.as_bool(),
                _ => Ok(false), // default critical value
            }
        })(i)?;
        let (i, value) = map_res(parse_der_octetstring, |x: DerObject<'a>| x.as_slice())(i)?;
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
    parse_ber_sequence_defined_g(many0(complete(parse_extension)))(i)
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

fn parse_tbs_certificate<'a>(i: &'a [u8]) -> X509Result<TbsCertificate<'a>> {
    let start_i = i;
    parse_ber_sequence_defined_g(move |i| {
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
    parse_ber_sequence_defined_g(move |i| {
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
    parse_ber_sequence_defined_g(many1(complete(parse_revoked_certificate)))(i)
}

fn parse_revoked_certificate(i: &[u8]) -> X509Result<RevokedCertificate> {
    parse_ber_sequence_defined_g(|i| {
        let (i, user_certificate) = map_opt(parse_der_integer, |x: DerObject| x.as_biguint())(i)
            .or(Err(X509Error::InvalidUserCertificate))?;
        let (i, revocation_date) =
            map_res(parse_choice_of_time, der_to_utctime)(i).or(Err(X509Error::InvalidDate))?;
        let (i, extensions) = opt(complete(parse_extension_sequence))(i)?;
        let revoked = RevokedCertificate {
            user_certificate,
            revocation_date,
            extensions: extensions.unwrap_or_default(),
        };
        Ok((i, revoked))
    })(i)
}

// lifetime is *not* useless, it is required to tell the compiler the content of the temporary
// DerObject has the same lifetime as the input
#[allow(clippy::needless_lifetimes)]
fn parse_algorithm_identifier<'a>(i: &'a [u8]) -> X509Result<AlgorithmIdentifier> {
    parse_ber_sequence_defined_g(|i| {
        let (i, algorithm) = map_res(parse_der_oid, |x: DerObject<'a>| x.as_oid_val())(i)
            .or(Err(X509Error::InvalidAlgorithmIdentifier))?;
        let (i, parameters) =
            parse_der_optional!(i, parse_der).or(Err(X509Error::InvalidAlgorithmIdentifier))?;

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
/// For example, to parse a certificate and print the subject and issuer:
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
    parse_ber_sequence_defined_g(|i| {
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

pub fn parse_crl_der<'a>(i: &'a [u8]) -> X509Result<CertificateRevocationList<'a>> {
    parse_ber_sequence_defined_g(|i| {
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
pub fn x509_parser<'a>(i: &'a [u8]) -> IResult<&'a [u8], X509Certificate<'a>, X509Error> {
    parse_x509_der(i)
}
