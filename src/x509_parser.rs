//! X.509 certificate parser
//!
//! Based on RFC5280
//!

use crate::error::X509Error;
use crate::time::ASN1Time;
use crate::x509::*;
use chrono::offset::TimeZone;
use chrono::{DateTime, Datelike, Utc};
use nom::{alt, exact, many1, map_opt, opt, take, Err, IResult};
use num_bigint::BigUint;
use std::collections::HashMap;
use std::str;

use der_parser::ber::{ber_read_element_header, BerObjectContent, BerTag};
use der_parser::der::*;
use der_parser::error::*;
use der_parser::oid::Oid;
use der_parser::*;
use rusticata_macros::{flat_take, upgrade_error};

fn parse_malformed_string(i: &[u8]) -> DerResult {
    let (rem, hdr) = ber_read_element_header(i)?;
    if hdr.len > u64::from(std::u32::MAX) {
        return Err(nom::Err::Error(BerError::InvalidLength));
    }
    match hdr.tag {
        BerTag::PrintableString => {
            // if we are in this function, the PrintableString could not be validated.
            // Accept it without validating charset, because some tools do not respect the charset
            // restrictions (for ex. they use '*' while explicingly disallowed)
            let (rem, data) = take!(rem, hdr.len as usize)?;
            let s = std::str::from_utf8(data).map_err(|_| BerError::BerValueError)?;
            let content = BerObjectContent::PrintableString(s);
            let obj = DerObject::from_header_and_content(hdr, content);
            Ok((rem, obj))
        }
        _ => Err(nom::Err::Error(BerError::InvalidTag)),
    }
}

// AttributeValue          ::= ANY -- DEFINED BY AttributeType
#[inline]
fn parse_attribute_value(i: &[u8]) -> DerResult {
    alt!(i, parse_der | parse_malformed_string)
}

// AttributeTypeAndValue   ::= SEQUENCE {
//     type    AttributeType,
//     value   AttributeValue }
fn parse_attr_type_and_value<'a>(i: &'a [u8]) -> BerResult<AttributeTypeAndValue<'a>> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        oid: map_res!(parse_der_oid, |x:DerObject<'a>| x.as_oid_val()) >>
        val: parse_attribute_value >>
        ( AttributeTypeAndValue{ attr_type:oid, attr_value:val } )
    )
    .map(|(rem, x)| (rem, x.1))
}

fn parse_rdn(i: &[u8]) -> BerResult<RelativeDistinguishedName> {
    parse_der_struct!(
        i,
        TAG DerTag::Set,
        v: many1!(complete!(parse_attr_type_and_value)) >>
        ( RelativeDistinguishedName{ set:v } )
    )
    .map(|(rem, x)| (rem, x.1))
}

/// Parse the X.501 type Name, used for ex in issuer and subject of a X.509 certificate
pub fn parse_x509_name(i: &[u8]) -> BerResult<X509Name> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        v: many0!(complete!(parse_rdn)) >>
        ( v )
    )
    .map(|(rem, x)| {
        let len = i.len() - rem.len();
        (
            rem,
            X509Name {
                rdn_seq: x.1,
                raw: &i[..len],
            },
        )
    })
}

fn parse_version(i: &[u8]) -> BerResult<u32> {
    map_res!(
        i,
        call!(parse_der_explicit_optional, BerTag(0), parse_der_integer),
        |x: DerObject| {
            match x.as_context_specific() {
                Ok((BerTag::EndOfContent, None)) => Ok(1),
                Ok((_, Some(obj))) => obj.as_u32(),
                _ => Err(BerError::BerTypeError),
            }
        }
    )
}

#[inline]
fn parse_choice_of_time(i: &[u8]) -> DerResult {
    alt!(
        i,
        complete!(parse_der_utctime) | complete!(parse_der_generalizedtime)
    )
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

fn parse_validity(i: &[u8]) -> BerResult<Validity> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        start: map_res!(parse_choice_of_time, der_to_utctime) >>
        end:   map_res!(parse_choice_of_time, der_to_utctime) >>
        (
            Validity{ not_before:start,not_after:end }
        )
    )
    .map(|(rem, x)| (rem, x.1))
}

/// Parse the SubjectPublicKeyInfo struct portion of a DER-encoded X.509 Certificate
pub fn parse_subject_public_key_info<'a>(i: &'a [u8]) -> BerResult<SubjectPublicKeyInfo<'a>> {
    parse_der_struct!(
        i,
        alg: parse_algorithm_identifier >>
        spk: map_res!(parse_der_bitstring, |x:DerObject<'a>| {
            match x.content {
                BerObjectContent::BitString(_, ref b) => Ok(b.to_owned()), // XXX padding ignored
                _ => Err(BerError::BerTypeError),
            }
        }) >>
        // spk: map_res!(parse_der_bitstring, |x:DerObject<'a>| x.content.as_bitstring()) >>
        (
            SubjectPublicKeyInfo{
                algorithm: alg,
                subject_public_key: spk
            }
        )
    )
    .map(|(rem, x)| (rem, x.1))
}

#[inline]
fn der_read_bitstring_content(i: &[u8], _tag: BerTag, len: usize) -> BerResult<BerObjectContent> {
    der_read_element_content_as(i, DerTag::BitString, len, false, 0)
}

fn bitstring_to_unique_id(x: DerObject) -> Result<Option<UniqueIdentifier>, BerError> {
    let (_, y) = x.as_context_specific()?;
    match y {
        None => Ok(None),
        Some(x) => match x.content {
            BerObjectContent::BitString(_, b) => Ok(Some(UniqueIdentifier(b.to_owned()))),
            _ => Err(BerError::BerTypeError),
        },
    }
}

fn parse_issuer_unique_id(i: &[u8]) -> BerResult<Option<UniqueIdentifier>> {
    map_res!(
        i,
        call!(parse_der_implicit, BerTag(1), der_read_bitstring_content),
        bitstring_to_unique_id
    )
}

fn parse_subject_unique_id(i: &[u8]) -> BerResult<Option<UniqueIdentifier>> {
    map_res!(
        i,
        call!(parse_der_implicit, BerTag(2), der_read_bitstring_content),
        bitstring_to_unique_id
    )
}

#[inline]
fn der_read_opt_bool(i: &[u8]) -> DerResult {
    parse_der_optional!(i, parse_der_bool)
}

fn parse_extension<'a>(i: &'a [u8]) -> BerResult<X509Extension<'a>> {
    parse_der_struct!(
        i,
        oid: map_res!(parse_der_oid, |x: DerObject<'a>| x.as_oid_val())
            >> critical: map_res!(der_read_opt_bool, |x: DerObject| {
                match x.as_context_specific() {
                    Ok((_, Some(obj))) => obj.as_bool(),
                    _ => Ok(false), // default critical value
                }
            })
            >> value: map_res!(parse_der_octetstring, |x: DerObject<'a>| x.as_slice())
            >> parsed_extension: call!(crate::extensions::parser::parse_extension, value, &oid)
            >> (X509Extension {
                oid,
                critical,
                value,
                parsed_extension,
            })
    )
    .map(|(rem, x)| (rem, x.1))
}

/// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
fn parse_extension_sequence(i: &[u8]) -> BerResult<Vec<X509Extension>> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        v: many0!(complete!(parse_extension)) >>
        ( v )
    )
    .map(|(rem, x)| (rem, x.1))
}

fn parse_extensions(i: &[u8]) -> BerResult<HashMap<Oid, X509Extension>> {
    if i.is_empty() {
        return Ok((&[], HashMap::new()));
    }

    match der_read_element_header(i) {
        Ok((rem, hdr)) => {
            if hdr.tag != BerTag(3) {
                return Err(Err::Error(BerError::InvalidTag));
            }
            let mut extensions = HashMap::new();
            // The allocation of the Vec could be avoided with an iterator
            let (_, list) = exact!(rem, parse_extension_sequence)?;
            for ext in list.into_iter() {
                if extensions.insert(ext.oid.clone(), ext).is_some() {
                    // duplicate extensions are not allowed
                    return Err(Err::Failure(BerError::InvalidTag));
                }
            }
            Ok((rem, extensions))
        }
        Err(e) => Err(e),
    }
}

fn get_serial_info(o: DerObject) -> Option<(&[u8], BigUint)> {
    let big = o.as_biguint()?;
    let slice = o.as_slice().ok()?;

    Some((slice, big))
}

fn parse_tbs_certificate<'a>(i: &'a [u8]) -> BerResult<TbsCertificate<'a>> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        version:     parse_version >>
        serial:      map_opt!(parse_der_integer, get_serial_info) >>
        signature:   parse_algorithm_identifier >>
        issuer:      parse_x509_name >>
        validity:    parse_validity >>
        subject:     parse_x509_name >>
        subject_pki: parse_subject_public_key_info >>
        issuer_uid:  parse_issuer_unique_id >>
        subject_uid: parse_subject_unique_id >>
        extensions:  parse_extensions >>
        (
            TbsCertificate{
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
                raw: &[],
                raw_serial: serial.0,
            }
        )
    )
    .map(|(rem, (_hdr, mut tbs))| {
        tbs.raw = &i[..(i.len() - rem.len())];
        (rem, tbs)
    })
}

fn parse_tbs_cert_list(i: &[u8]) -> IResult<&[u8], TbsCertList, BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        version:              opt!(map_res!(parse_der_integer, |x:DerObject| x.as_u32())) >>
        signature:            parse_algorithm_identifier >>
        issuer:               parse_x509_name >>
        this_update:          map_res!(parse_choice_of_time, der_to_utctime) >>
        next_update:          opt!(map_res!(parse_choice_of_time, der_to_utctime)) >>
        revoked_certificates: opt!(complete!(parse_revoked_certificates)) >>
        extensions:           opt!(complete!(parse_crl_extensions)) >>
        (
            TbsCertList{
                version,
                signature,
                issuer,
                this_update,
                next_update,
                revoked_certificates: revoked_certificates.unwrap_or_default(),
                extensions: extensions.unwrap_or_default(),
                raw: &[]
            }
        )
    )
    .map(|(rem, (_hdr, mut tbs))| {
        tbs.raw = &i[..(i.len() - rem.len())];
        (rem, tbs)
    })
}

fn parse_revoked_certificates(i: &[u8]) -> IResult<&[u8], Vec<RevokedCertificate>, BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        v: many1!(complete!(parse_revoked_certificate)) >>
        ( v )
    )
    .map(|(rem, x)| (rem, x.1))
}

fn parse_revoked_certificate(i: &[u8]) -> IResult<&[u8], RevokedCertificate, BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        user_certificate: map_opt!(parse_der_integer, |x:DerObject| x.as_biguint()) >>
        revocation_date:  map_res!(parse_choice_of_time, der_to_utctime) >>
        extensions:       opt!(complete!(parse_extension_sequence)) >>
        (
            RevokedCertificate{
                user_certificate,
                revocation_date,
                extensions: extensions.unwrap_or_default(),
            }
        )
    )
    .map(|(rem, x)| (rem, x.1))
}

fn parse_crl_extensions(i: &[u8]) -> IResult<&[u8], Vec<X509Extension>, BerError> {
    parse_der_struct!(
        i,
        TAG BerTag(0x0),
        extensions: parse_extension_sequence >>
        ( extensions )
    )
    .map(|(rem, x)| (rem, x.1))
}

// lifetime is *not* useless, it is required to tell the compiler the content of the temporary
// DerObject has the same lifetime as the input
#[allow(clippy::needless_lifetimes)]
fn parse_algorithm_identifier<'a>(i: &'a [u8]) -> BerResult<AlgorithmIdentifier> {
    parse_der_struct!(
        i,
        oid: map_res!(parse_der_oid, |x: DerObject<'a>| x.as_oid_val())
            >> params: parse_der_optional!(parse_der)
            >> (AlgorithmIdentifier {
                algorithm: oid,
                parameters: params
            })
    )
    .map(|(rem, x)| (rem, x.1))
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
pub fn parse_x509_der<'a>(i: &'a [u8]) -> IResult<&'a [u8], X509Certificate<'a>, X509Error> {
    upgrade_error!(parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        tbs: parse_tbs_certificate >>
        alg: parse_algorithm_identifier >>
        sig: map_res!(parse_der_bitstring, |x:DerObject<'a>| {
            match x.content {
                BerObjectContent::BitString(_, ref b) => Ok(b.to_owned()), // XXX padding ignored
                _ => Err(BerError::BerTypeError),
            }
        }) >>
        (
            X509Certificate{
                tbs_certificate: tbs,
                signature_algorithm: alg,
                signature_value: sig
            }
        )
    )
    .map(|(rem, x)| (rem, x.1)))
}

pub fn parse_crl_der<'a>(
    i: &'a [u8],
) -> IResult<&'a [u8], CertificateRevocationList<'a>, X509Error> {
    upgrade_error!(parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        tbs: parse_tbs_cert_list >>
        alg: parse_algorithm_identifier >>
        sig: map_res!(parse_der_bitstring, |x:DerObject<'a>| {
            match x.content {
                BerObjectContent::BitString(_, ref b) => Ok(b.to_owned()), // XXX padding ignored
                _ => Err(BerError::BerTypeError),
            }
        }) >>
        (
            CertificateRevocationList{
                tbs_cert_list: tbs,
                signature_algorithm: alg,
                signature_value: sig
            }
        )
    )
    .map(|(rem, x)| (rem, x.1)))
}

#[deprecated(since = "0.4.0", note = "please use `parse_x509_der` instead")]
pub fn x509_parser<'a>(i: &'a [u8]) -> IResult<&'a [u8], X509Certificate<'a>, X509Error> {
    parse_x509_der(i)
}
