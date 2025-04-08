use asn1_rs::{DerParser, Ia5String, InnerError, Input};
use nom::{Err, IResult, Input as _};

use crate::error::X509Error;

/// The value is an IA5String representing a comment
/// that may be displayed to the user when the certificate is viewed
pub fn parse_der_nscomment(input: Input) -> IResult<Input, &str, X509Error> {
    match Ia5String::parse_der(input.clone()) {
        Ok((rem, obj)) => {
            let s = obj
                .as_raw_str()
                .ok_or(Err::Error(X509Error::DerParser(InnerError::LifetimeError)))?;
            Ok((rem, s))
        }
        Err(_) => {
            // Some implementations encode the comment directly, without
            // wrapping it in an IA5String
            if let Ok(s) = std::str::from_utf8(input.as_bytes2()) {
                Ok((input.take(input.input_len()), s))
            } else {
                Err(Err::Error(X509Error::DerParser(
                    InnerError::StringInvalidCharset,
                )))
            }
        }
    }
}
