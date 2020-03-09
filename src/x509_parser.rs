//! X.509 certificate parser
//!
//! Based on RFC5280
//!

use std::str;
use nom::{IResult,Err};
use num_bigint::BigUint;
use time::{strptime,Tm};

use der_parser::*;
use der_parser::ber::{BerObjectContent, BerTag};
use der_parser::der::*;
use der_parser::error::*;
use rusticata_macros::{flat_take, upgrade_error};
use x509::*;
use x509_extensions::*;
use error::X509Error;

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
pub fn parse_ext_basicconstraints(i:&[u8]) -> BerResult<BasicConstraints> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        ca:                 map_res!(parse_der_bool, |x:DerObject| x.as_bool()) >>
        path_len_contraint: map!(der_read_opt_integer, |x:DerObject| {
            match x.as_context_specific() {
                Ok((_,Some(obj))) => obj.as_u32().ok(),
                _                 => None
            }
        }) >>
        ( BasicConstraints{ ca, path_len_contraint } )
    ).map(|(rem,x)| (rem,x.1))
}

#[inline]
fn der_read_opt_integer(i:&[u8]) -> DerResult {
    parse_der_optional!(i, parse_der_integer)
}

#[inline]
fn parse_directory_string(i:&[u8]) -> DerResult {
    alt!(i,
         complete!(parse_der_utf8string) |
         complete!(parse_der_printablestring) |
         complete!(parse_der_ia5string) |
         complete!(parse_der_t61string) |
         complete!(parse_der_bmpstring))
}

fn parse_attr_type_and_value(i:&[u8]) -> BerResult<AttributeTypeAndValue> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        oid: map_res!(parse_der_oid, |x:DerObject| x.as_oid_val()) >>
        val: parse_directory_string >>
        ( AttributeTypeAndValue{ attr_type:oid, attr_value:val } )
    ).map(|(rem,x)| (rem,x.1))
}

fn parse_rdn(i:&[u8]) -> BerResult<RelativeDistinguishedName> {
    parse_der_struct!(
        i,
        TAG DerTag::Set,
        v: many1!(complete!(parse_attr_type_and_value)) >>
        ( RelativeDistinguishedName{ set:v } )
    ).map(|(rem,x)| (rem,x.1))
}

fn parse_name(i:&[u8]) -> BerResult<X509Name> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        v: many1!(complete!(parse_rdn)) >>
        ( X509Name{ rdn_seq:v } )
    ).map(|(rem,x)| (rem,x.1))
}

fn parse_version(i:&[u8]) -> BerResult<u32> {
    map_res!(
        i,
        call!(parse_der_explicit, BerTag(0), parse_der_integer),
        |x:DerObject| {
            match x.as_context_specific() {
                Ok((BerTag::EndOfContent, None)) => Ok(1),
                Ok((_,Some(obj))) => obj.as_u32(),
                _                 => Err(BerError::BerTypeError),
            }
        }
    )
}

#[inline]
fn parse_choice_of_time(i:&[u8]) -> DerResult {
    alt!(i, complete!(parse_der_utctime) | complete!(parse_der_generalizedtime))
}

fn der_to_utctime(obj:DerObject) -> Result<Tm,X509Error> {
    if let BerObjectContent::UTCTime(s) = obj.content {
        let xs = str::from_utf8(s).or(Err(X509Error::InvalidDate))?;
        match strptime(xs,"%y%m%d%H%M%S%Z") {
            Ok(mut tm) => {
                if tm.tm_year < 50 { tm.tm_year += 100; }
                // eprintln!("date: {}", tm.rfc822());
                Ok(tm)
            },
            Err(_e) => {
                // eprintln!("Error: {:?}",_e);
                Err(X509Error::InvalidDate)
            },
        }
    } else if let BerObjectContent::GeneralizedTime(s) = obj.content {
        let xs = str::from_utf8(s)
            .or(Err(X509Error::InvalidDate))?;
        strptime(xs,"%Y%m%d%H%M%S%Z").or(Err(X509Error::InvalidDate))
    } else {
        Err(X509Error::InvalidDate)
    }
}

fn parse_validity(i:&[u8]) -> BerResult<Validity> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        start: map_res!(parse_choice_of_time, der_to_utctime) >>
        end:   map_res!(parse_choice_of_time, der_to_utctime) >>
        (
            Validity{ not_before:start,not_after:end }
        )
    ).map(|(rem,x)| (rem,x.1))
}

/// Parse the SubjectPublicKeyInfo struct portion of a DER-encoded X.509 Certificate
pub fn parse_subject_public_key_info<'a>(i:&'a[u8]) -> BerResult<SubjectPublicKeyInfo<'a>> {
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
    ).map(|(rem,x)| (rem,x.1))
}

#[inline]
fn der_read_bitstring_content(i:&[u8], _tag:BerTag, len: usize) -> BerResult<BerObjectContent> {
    der_read_element_content_as(i, DerTag::BitString, len, false, 0)
}

fn bitstring_to_unique_id<'a>(x: DerObject<'a>) -> Result<Option<UniqueIdentifier<'a>>,BerError> {
    let (_,y) = x.as_context_specific()?;
    match y {
        None => Ok(None),
        Some(x) => {
            match x.content {
                BerObjectContent::BitString(_, b) => Ok(Some(UniqueIdentifier(b.to_owned()))),
                _                                 => Err(BerError::BerTypeError)
            }
        }
    }
}

fn parse_issuer_unique_id(i:&[u8]) -> BerResult<Option<UniqueIdentifier>> {
    map_res!(
        i,
        call!(parse_der_implicit, BerTag(1), der_read_bitstring_content),
        bitstring_to_unique_id
    )
}

fn parse_subject_unique_id(i:&[u8]) -> BerResult<Option<UniqueIdentifier>> {
    map_res!(
        i,
        call!(parse_der_implicit, BerTag(2), der_read_bitstring_content),
        bitstring_to_unique_id
    )
}

#[inline]
fn der_read_opt_bool(i:&[u8]) -> DerResult {
    parse_der_optional!(i, parse_der_bool)
}

fn parse_extension<'a>(i:&'a[u8]) -> BerResult<X509Extension<'a>> {
    parse_der_struct!(
        i,
        oid:      map_res!(parse_der_oid,|x:DerObject| x.as_oid_val()) >>
        critical: map_res!(der_read_opt_bool, |x:DerObject| {
            match x.as_context_specific() {
                Ok((_,Some(obj))) => obj.as_bool(),
                _                 => Ok(false)   // default critical value
            }
        }) >>
        value:    map_res!(parse_der_octetstring, |x:DerObject<'a>| x.as_slice()) >>
        (
            X509Extension{
                oid,
                critical,
                value
            }
        )
    ).map(|(rem,x)| (rem,x.1))
}

/// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
fn parse_extension_sequence(i:&[u8]) -> BerResult<Vec<X509Extension>> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        v: many1!(complete!(parse_extension)) >>
        ( v )
    ).map(|(rem,x)| (rem,x.1))
}

fn parse_extensions(i:&[u8]) -> BerResult<Vec<X509Extension>> {
    if i.len() == 0 {
        return Ok((&[], Vec::new()));
    }

    match der_read_element_header(i) {
        Ok((rem,hdr)) => {
            if hdr.tag != BerTag(3) {
                return Err(Err::Error(BerError::InvalidTag));
            }
            parse_extension_sequence(rem)
        }
        Err(e)        => Err(e)
    }
    // parse_der_explicit(i, 3, parse_extension_sequence)
}

fn get_serial_info<'a>(o: DerObject<'a>) -> Option<(&'a [u8], BigUint)> {
    let big = o.as_biguint()?;
    let slice = o.as_slice().ok()?;

    Some((slice, big))
}

fn parse_tbs_certificate<'a>(i:&'a [u8]) -> BerResult<TbsCertificate<'a>> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        version:     parse_version >>
        serial:      map_opt!(parse_der_integer, get_serial_info) >>
        signature:   parse_algorithm_identifier >>
        issuer:      parse_name >>
        validity:    parse_validity >>
        subject:     parse_name >>
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
    ).map(|(rem, (_hdr, mut tbs))| {
        tbs.raw = &i[..(i.len() - rem.len())];
        (rem, tbs)
    })
}

fn parse_tbs_cert_list(i:&[u8]) -> IResult<&[u8],TbsCertList,BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        version:              opt!(map_res!(parse_der_integer, |x:DerObject| x.as_u32())) >>
        signature:            parse_algorithm_identifier >>
        issuer:               parse_name >>
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
    ).map(|(rem, (_hdr, mut tbs))| {
        tbs.raw = &i[..(i.len() - rem.len())];
        (rem, tbs)
    })
}

fn parse_revoked_certificates(i:&[u8]) -> IResult<&[u8],Vec<RevokedCertificate>,BerError> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        v: many1!(complete!(parse_revoked_certificate)) >>
        ( v )
    ).map(|(rem,x)| (rem,x.1))
}

fn parse_revoked_certificate(i:&[u8]) -> IResult<&[u8],RevokedCertificate,BerError> {
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
    ).map(|(rem,x)| (rem,x.1))
}

fn parse_crl_extensions(i:&[u8]) -> IResult<&[u8],Vec<X509Extension>,BerError> {
    parse_der_struct!(
        i,
        TAG BerTag(0x0),
        extensions: parse_extension_sequence >>
        ( extensions )
    ).map(|(rem,x)| (rem,x.1))
}

fn parse_algorithm_identifier(i:&[u8]) -> IResult<&[u8],AlgorithmIdentifier,BerError> {
    parse_der_struct!(
        i,
        oid:    map_res!(parse_der_oid, |x:DerObject| x.as_oid_val()) >>
        params: parse_der_optional!(parse_der) >>
        (
            AlgorithmIdentifier{
                algorithm: oid,
                parameters: params
            }
        )
    ).map(|(rem,x)| (rem,x.1))
}

// XXX validate X509 structure
/// Parse a DER-encoded X.509 Certificate
///
/// Note that only parsing is done, not validation.
pub fn parse_x509_der<'a>(i:&'a[u8]) -> IResult<&'a[u8],X509Certificate<'a>,X509Error> {
    upgrade_error!(
    parse_der_struct!(
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
    ).map(|(rem,x)| (rem,x.1))
    )
}

pub fn parse_crl_der<'a>(i:&'a[u8]) -> IResult<&'a[u8],CertificateRevocationList<'a>,X509Error> {
    upgrade_error!(
    parse_der_struct!(
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
    ).map(|(rem,x)| (rem,x.1))
    )
}

#[deprecated(since="0.4.0", note="please use `parse_x509_der` instead")]
pub fn x509_parser<'a>(i:&'a[u8]) -> IResult<&'a[u8],X509Certificate<'a>,X509Error> {
    parse_x509_der(i)
}

