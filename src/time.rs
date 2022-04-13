use der_parser::ber::{ber_read_element_header, BerObjectContent, Tag, MAX_OBJECT_SIZE};
use der_parser::der::{parse_der_generalizedtime, parse_der_utctime, DerObject};
use der_parser::error::{BerError, DerResult};
use nom::branch::alt;
use nom::combinator::{complete, map_res, opt};
use std::ops::{Add, Sub};
use time::{Date, Duration, OffsetDateTime};

use crate::error::{X509Error, X509Result};
use crate::traits::FromDer;

/// An ASN.1 timestamp.
#[derive(Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct ASN1Time(OffsetDateTime);

impl ASN1Time {
    pub(crate) fn from_der_opt(i: &[u8]) -> X509Result<Option<Self>> {
        opt(map_res(parse_choice_of_time, der_to_utctime))(i)
            .map_err(|_| X509Error::InvalidDate.into())
    }

    #[inline]
    pub const fn to_datetime(&self) -> OffsetDateTime {
        self.0
    }

    /// Makes a new `ASN1Time` from the number of non-leap seconds since Epoch
    pub fn from_timestamp(secs: i64) -> Self {
        ASN1Time(OffsetDateTime::from_unix_timestamp(secs).unwrap())
    }

    /// Returns the number of non-leap seconds since January 1, 1970 0:00:00 UTC (aka "UNIX timestamp").
    #[inline]
    pub fn timestamp(&self) -> i64 {
        self.0.unix_timestamp()
    }

    /// Returns a `ASN1Time` which corresponds to the current date.
    #[inline]
    pub fn now() -> Self {
        ASN1Time(OffsetDateTime::now_utc())
    }

    /// Returns an RFC 2822 date and time string such as `Tue, 1 Jul 2003 10:52:37 +0200`.
    ///
    /// Note: this will fail if year < 1900
    #[inline]
    pub fn to_rfc2822(self) -> String {
        self.0
            .format(&time::format_description::well_known::Rfc2822)
            .unwrap_or_else(|e| format!("Invalid date: {}", e))
    }
}

impl<'a> FromDer<'a> for ASN1Time {
    fn from_der(i: &[u8]) -> X509Result<Self> {
        map_res(parse_choice_of_time, der_to_utctime)(i).map_err(|_| X509Error::InvalidDate.into())
    }
}

fn parse_choice_of_time(i: &[u8]) -> DerResult {
    alt((
        complete(parse_der_utctime),
        complete(parse_der_generalizedtime),
        complete(parse_malformed_date),
    ))(i)
}

// allow relaxed parsing of UTCTime (ex: 370116130016+0000)
fn parse_malformed_date(i: &[u8]) -> DerResult {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    // fn check_char(b: &u8) -> bool {
    //     (0x20 <= *b && *b <= 0x7f) || (*b == b'+')
    // }
    let (_rem, hdr) = ber_read_element_header(i)?;
    let len = hdr.length().definite()?;
    if len > MAX_OBJECT_SIZE {
        return Err(nom::Err::Error(BerError::InvalidLength));
    }
    match hdr.tag() {
        Tag::UtcTime => {
            // // if we are in this function, the PrintableString could not be validated.
            // // Accept it without validating charset, because some tools do not respect the charset
            // // restrictions (for ex. they use '*' while explicingly disallowed)
            // let (rem, data) = take(len as usize)(rem)?;
            // if !data.iter().all(check_char) {
            //     return Err(nom::Err::Error(BerError::BerValueError));
            // }
            // let s = std::str::from_utf8(data).map_err(|_| BerError::BerValueError)?;
            // let content = BerObjectContent::UTCTime(s);
            // let obj = DerObject::from_header_and_content(hdr, content);
            // Ok((rem, obj))
            Err(nom::Err::Error(BerError::BerValueError))
        }
        _ => Err(nom::Err::Error(BerError::unexpected_tag(None, hdr.tag()))),
    }
}

pub(crate) fn der_to_utctime(obj: DerObject) -> Result<ASN1Time, X509Error> {
    match obj.content {
        BerObjectContent::UTCTime(s) => {
            let dt = s.to_datetime().map_err(|_| X509Error::InvalidDate)?;
            let year = dt.year();
            // RFC 5280 rules for interpreting the year
            let year = if year >= 50 { year + 1900 } else { year + 2000 };
            let date = Date::from_calendar_date(year, dt.month(), dt.day())
                .map_err(|_| X509Error::InvalidDate)?;
            let dt = dt.replace_date(date);

            Ok(ASN1Time(dt))
        }
        BerObjectContent::GeneralizedTime(s) => {
            let dt = s.to_datetime().map_err(|_| X509Error::InvalidDate)?;
            Ok(ASN1Time(dt))
        }
        _ => Err(X509Error::InvalidDate),
    }
}

impl Add<Duration> for ASN1Time {
    type Output = Option<ASN1Time>;

    #[inline]
    fn add(self, rhs: Duration) -> Option<ASN1Time> {
        Some(ASN1Time(self.0 + rhs))
    }
}

impl Sub<ASN1Time> for ASN1Time {
    type Output = Option<Duration>;

    #[inline]
    fn sub(self, rhs: ASN1Time) -> Option<Duration> {
        if self.0 > rhs.0 {
            Some(self.0 - rhs.0)
        } else {
            None
        }
    }
}

impl From<OffsetDateTime> for ASN1Time {
    fn from(dt: OffsetDateTime) -> Self {
        ASN1Time(dt)
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::ASN1Time;

    #[test]
    fn test_nonrfc2822_date() {
        // test year < 1900
        let d = datetime!(1 - 1 - 1 00:00:00 UTC);
        let t = ASN1Time::from(d);
        assert!(t.to_rfc2822().contains("Invalid"));
    }
}
