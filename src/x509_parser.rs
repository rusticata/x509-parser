//! X.509 certificate parser
//!
//! Based on RFC5280
//!

use std::str;
use nom::{IResult,Err,ErrorKind};
use time::{strptime,Tm};

use der_parser::*;
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
pub fn parse_ext_basicconstraints(i:&[u8]) -> IResult<&[u8],BasicConstraints> {
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
fn der_read_opt_integer(i:&[u8]) -> IResult<&[u8],DerObject,u32> {
    parse_der_optional!(i, parse_der_integer)
}

#[inline]
fn parse_directory_string(i:&[u8]) -> IResult<&[u8],DerObject> {
    alt_complete!(i,
                  parse_der_utf8string |
                  parse_der_printablestring |
                  parse_der_ia5string |
                  parse_der_t61string |
                  parse_der_bmpstring)
}

fn parse_attr_type_and_value(i:&[u8]) -> IResult<&[u8],AttributeTypeAndValue> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        oid: map_res!(parse_der_oid, |x:DerObject| x.as_oid_val()) >>
        val: parse_directory_string >>
        ( AttributeTypeAndValue{ attr_type:oid, attr_value:val } )
    ).map(|(rem,x)| (rem,x.1))
}

fn parse_rdn(i:&[u8]) -> IResult<&[u8],RelativeDistinguishedName> {
    parse_der_struct!(
        i,
        TAG DerTag::Set,
        v: many1!(complete!(parse_attr_type_and_value)) >>
        ( RelativeDistinguishedName{ set:v } )
    ).map(|(rem,x)| (rem,x.1))
}

fn parse_name(i:&[u8]) -> IResult<&[u8],X509Name> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        v: many1!(complete!(parse_rdn)) >>
        ( X509Name{ rdn_seq:v } )
    ).map(|(rem,x)| (rem,x.1))
}

fn parse_version(i:&[u8]) -> IResult<&[u8],u32> {
    map_res!(
        i,
        apply!(parse_der_explicit, 0, parse_der_integer),
        |x:DerObject| {
            match x.as_context_specific() {
                Ok((_,Some(obj))) => obj.as_u32(),
                _                 => Err(DerError::DerTypeError)
            }
        }
    )
}

#[inline]
fn parse_choice_of_time(i:&[u8]) -> IResult<&[u8],DerObject> {
    alt_complete!(i, parse_der_utctime | parse_der_generalizedtime)
}

fn der_to_utctime(obj:DerObject) -> Result<Tm,X509Error> {
    if let DerObjectContent::UTCTime(s) = obj.content {
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
    } else if let DerObjectContent::GeneralizedTime(s) = obj.content {
        let xs = str::from_utf8(s)
            .or(Err(X509Error::InvalidDate))?;
        match strptime(xs,"%Y%m%d%H%M%S%Z") {
            Ok(mut tm) => {
                Ok(tm)
            },
            Err(_e) => {
                Err(X509Error::InvalidDate)
            },
        }
    } else {
        Err(X509Error::InvalidDate)
    }
}

fn parse_validity(i:&[u8]) -> IResult<&[u8],Validity> {
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
pub fn parse_subject_public_key_info<'a>(i:&'a[u8]) -> IResult<&'a[u8],SubjectPublicKeyInfo<'a>> {
    parse_der_struct!(
        i,
        alg: parse_algorithm_identifier >>
        spk: map_res!(parse_der_bitstring, |x:DerObject<'a>| {
            match x.content {
                DerObjectContent::BitString(_, ref b) => Ok(b.to_owned()), // XXX padding ignored
                _ => Err(DerError::DerTypeError),
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
fn der_read_bitstring_content(i:&[u8], _tag:u8, len: usize) -> IResult<&[u8],DerObjectContent,u32> {
    der_read_element_content_as(i, DerTag::BitString as u8, len)
}

fn bitstring_to_unique_id<'a>(x: DerObject<'a>) -> Result<Option<UniqueIdentifier<'a>>,DerError> {
    let (_,y) = x.as_context_specific()?;
    match y {
        None => Ok(None),
        Some(x) => {
            match x.content {
                DerObjectContent::BitString(_, b) => Ok(Some(UniqueIdentifier(b.to_owned()))),
                _                                 => Err(DerError::DerTypeError)
            }
        }
    }
}

fn parse_issuer_unique_id(i:&[u8]) -> IResult<&[u8],Option<UniqueIdentifier>> {
    map_res!(
        i,
        apply!(parse_der_implicit, 1, der_read_bitstring_content),
        bitstring_to_unique_id
    )
}

fn parse_subject_unique_id(i:&[u8]) -> IResult<&[u8],Option<UniqueIdentifier>> {
    map_res!(
        i,
        apply!(parse_der_implicit, 2, der_read_bitstring_content),
        bitstring_to_unique_id
    )
}

#[inline]
fn der_read_opt_bool(i:&[u8]) -> IResult<&[u8],DerObject,u32> {
    parse_der_optional!(i, parse_der_bool)
}

fn parse_extension<'a>(i:&'a[u8]) -> IResult<&'a[u8],X509Extension<'a>> {
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
fn parse_extension_sequence(i:&[u8]) -> IResult<&[u8],Vec<X509Extension>> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        v: many1!(complete!(parse_extension)) >>
        ( v )
    ).map(|(rem,x)| (rem,x.1))
}

fn parse_extensions(i:&[u8]) -> IResult<&[u8],Vec<X509Extension>> {
    if i.len() == 0 {
        return Ok((&[], Vec::new()));
    }

    match der_read_element_header(i) {
        Ok((rem,hdr)) => {
            if hdr.tag != 3 {
                return Err(Err::Error(error_position!(i, ErrorKind::Custom(DER_TAG_ERROR))));
            }
            parse_extension_sequence(rem)
        }
        Err(e)        => Err(e)
    }
    // parse_der_explicit(i, 3, parse_extension_sequence)
}


fn parse_tbs_certificate(i:&[u8]) -> IResult<&[u8],TbsCertificate> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        version:     parse_version >>
        serial:      map_opt!(parse_der_integer, |x:DerObject| x.as_biguint()) >>
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
                serial,
                signature,
                issuer,
                validity,
                subject,
                subject_pki,
                issuer_uid,
                subject_uid,
                extensions
            }
        )
    ).map(|(rem,x)| (rem,x.1))
}

fn parse_algorithm_identifier(i:&[u8]) -> IResult<&[u8],AlgorithmIdentifier> {
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
pub fn parse_x509_der<'a>(i:&'a[u8]) -> IResult<&'a[u8],X509Certificate<'a>> {
    parse_der_struct!(
        i,
        TAG DerTag::Sequence,
        tbs: parse_tbs_certificate >>
        alg: parse_algorithm_identifier >>
        sig: map_res!(parse_der_bitstring, |x:DerObject<'a>| {
            match x.content {
                DerObjectContent::BitString(_, ref b) => Ok(b.to_owned()), // XXX padding ignored
                _ => Err(DerError::DerTypeError),
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
}

#[deprecated(since="0.4.0", note="please use `parse_x509_der` instead")]
pub fn x509_parser<'a>(i:&'a[u8]) -> IResult<&'a[u8],X509Certificate<'a>> {
    parse_x509_der(i)
}

