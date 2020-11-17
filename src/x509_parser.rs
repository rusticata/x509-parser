//! X.509 certificate parser
//!
//! Based on RFC5280
//!

use der_parser::ber::*;
use der_parser::der::*;
use der_parser::error::*;
use der_parser::*;
use nom::branch::alt;
use nom::bytes::complete::take;
use nom::combinator::{all_consuming, complete, map_opt, map_res};
use nom::multi::many1;
use nom::Err;
use num_bigint::BigUint;

use crate::certificate::*;
use crate::revocation_list::*;
use crate::error::{X509Error, X509Result};

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

// AttributeValue          ::= ANY -- DEFINED BY AttributeType
#[inline]
pub(crate) fn parse_attribute_value(i: &[u8]) -> DerResult {
    alt((parse_der, parse_malformed_string))(i)
}

pub(crate) fn parse_serial(i: &[u8]) -> X509Result<(&[u8], BigUint)> {
    map_opt(parse_der_integer, get_serial_info)(i).map_err(|_| X509Error::InvalidSerial.into())
}

fn get_serial_info(o: DerObject) -> Option<(&[u8], BigUint)> {
    let big = o.as_biguint()?;
    let slice = o.as_slice().ok()?;

    Some((slice, big))
}

pub(crate) fn parse_revoked_certificates(i: &[u8]) -> X509Result<Vec<RevokedCertificate>> {
    parse_ber_sequence_defined_g(|_, a| {
        all_consuming(many1(complete(RevokedCertificate::from_der)))(a)
    })(i)
}

/// Parse a **DER-encoded** X.509 Certificate, and return the remaining of the input and the built
/// object.
///
///
/// This function is an alias to [X509Certificate::from_der](x509/struct.X509Certificate.html#method.from_der). See this function
/// for more information.
///
/// For PEM-encoded certificates, use the [`pem`](pem/index.html) module.
#[inline]
pub fn parse_x509_certificate<'a>(i: &'a [u8]) -> X509Result<X509Certificate<'a>> {
    X509Certificate::from_der(i)
}

/// Parse a DER-encoded X.509 v2 CRL, and return the remaining of the input and the built
/// object.
///
/// This function is an alias to [CertificateRevocationList::from_der](x509/struct.CertificateRevocationList.html#method.from_der). See this function
/// for more information.
#[inline]
pub fn parse_certificate_list(i: &[u8]) -> X509Result<CertificateRevocationList> {
    CertificateRevocationList::from_der(i)
}

pub(crate) fn parse_signature_value(i: &[u8]) -> X509Result<BitStringObject> {
    map_res(parse_der_bitstring, |x: DerObject| {
        match x.content {
            BerObjectContent::BitString(_, ref b) => Ok(b.to_owned()), // XXX padding ignored
            _ => Err(BerError::BerTypeError),
        }
    })(i)
    .or(Err(Err::Error(X509Error::InvalidSignatureValue)))
}
