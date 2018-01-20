//! X.509 certificate parser
//!
//! Based on RFC5280
//!

use nom::{IResult,ErrorKind};
// use nom::HexDisplay;

use der_parser::*;
use x509::*;

pub fn parse_ext_basicconstraints(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_sequence_defined_m!(
        i,
        parse_der_bool >>
        der_read_opt_integer
    )
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

#[inline]
fn parse_attr_type_and_value(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_sequence_defined_m!(i,
                                parse_der_oid >>
                                parse_directory_string
                               )
}

#[inline]
fn parse_rdn(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_set_of!(i, parse_attr_type_and_value)
}

#[inline]
fn parse_name(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_sequence_of!(i, parse_rdn)
}

#[inline]
pub fn parse_version(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_explicit(i, 0, parse_der_integer)
}

#[inline]
fn parse_choice_of_time(i:&[u8]) -> IResult<&[u8],DerObject> {
    alt_complete!(i, parse_der_utctime | parse_der_generalizedtime)
}

#[inline]
fn parse_validity(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_sequence_defined_m!(i,
                                parse_choice_of_time >>
                                parse_choice_of_time
                               )
}

#[inline]
fn parse_subject_public_key_info(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_sequence_defined_m!(i,
                                parse_algorithm_identifier >>
                                parse_der_bitstring
                               )
}

#[inline]
fn der_read_bitstring_content(i:&[u8], _tag:u8, len: usize) -> IResult<&[u8],DerObjectContent,u32> {
    der_read_element_content_as(i, DerTag::BitString as u8, len)
}

#[inline]
fn parse_issuer_unique_id(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_implicit(i, 1, der_read_bitstring_content)
}

#[inline]
fn parse_subject_unique_id(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_implicit(i, 2, der_read_bitstring_content)
}

#[inline]
fn der_read_opt_bool(i:&[u8]) -> IResult<&[u8],DerObject,u32> {
    parse_der_optional!(i, parse_der_bool)
}

#[inline]
fn parse_extension(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_sequence_defined_m!(
        i,
        parse_der_oid >>
        der_read_opt_bool >>
        parse_der_octetstring
    )
}

#[inline]
fn parse_extension_sequence(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_sequence_of!(i, parse_extension)
}

#[inline]
fn parse_extensions(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_explicit(i, 3, parse_extension_sequence)
}


pub fn parse_tbs_certificate(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_sequence_defined_m!(i,
        parse_version >>
        parse_der_integer >> // serialNumber
        parse_algorithm_identifier >>
        parse_name >> // issuer
        parse_validity >>
        parse_name >> // subject
        parse_subject_public_key_info >>
        parse_issuer_unique_id >>
        parse_subject_unique_id >>
        parse_extensions
    )
}

#[inline]
fn der_read_opt_der(i:&[u8]) -> IResult<&[u8],DerObject,u32> {
    parse_der_optional!(i, parse_der)
}

#[inline]
pub fn parse_algorithm_identifier(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_sequence_defined_m!(i, parse_der_oid >> der_read_opt_der)
}

#[inline]
pub fn parse_signature_value(i:&[u8]) -> IResult<&[u8],DerObject> {
    parse_der_bitstring(i)
}

// XXX validate X509 structure
pub fn x509_parser(i:&[u8]) -> IResult<&[u8],X509Certificate> {
    map_res!(i,
         parse_der_sequence_defined_m!(
             parse_tbs_certificate >>
             parse_algorithm_identifier >>
             parse_der_bitstring
         ),
         X509Certificate::from_der_object
    )
}



#[cfg(test)]
mod tests {
    use super::x509_parser;
    use nom::IResult;
    // use nom::HexDisplay;
    use objects::*;
    use rusticata_macros::debug::HexSlice;

static IGCA_DER: &'static [u8] = include_bytes!("../assets/IGC_A.der");

#[test]
fn test_x509_parser() {
    let empty = &b""[..];
    //assert_eq!(x509_parser(IGCA_DER), IResult::Done(empty, (1)));
    let res = x509_parser(IGCA_DER);
    match res {
        IResult::Done(e, cert) => {
            assert_eq!(e,empty);
            // println!("tbsCertificate: {:?}", cert.tbs_certificate.as_pretty(0,2));
            // println!("signatureAlgorithm: {:?}", cert.signature_algorithm.as_pretty(0,2));
            // println!("signatureValue:\n{}", cert.signature_value.to_hex(16));

            let tbs_cert = cert.tbs_certificate().unwrap();
            println!("version: {:?}", tbs_cert.version());
            println!("subject: {}", tbs_cert.subject());
            println!("signature: {:?}", tbs_cert.signature());
            println!("issuer: {}", tbs_cert.issuer());
            let sig_alg = cert.signature_algorithm();
            println!("signature_algorithm: {:?}", sig_alg);
            println!("validity: {:?}", tbs_cert.validity());

            for ext in tbs_cert.extensions() {
                match oid2nid(&ext.oid) {
                    Ok(nid) => println!("Extension OID: {:?}", nid2sn(nid)),
                    Err(_)  => println!("Extension OID: {:?} (Unknown)", ext.oid),
                }
                println!("    critical: {}",ext.critical);
                println!("    value: {:?}",HexSlice{d:ext.value});
            }
            println!("CA? {}",tbs_cert.is_ca());
        },
        _ => panic!("x509 parsing failed: {:?}", res),
    }
}

}
