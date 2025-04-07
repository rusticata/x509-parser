use asn1_rs::nom::Err;
use asn1_rs::{
    BerError, DerParser, DynTagged, GeneralizedTime, Header, InnerError, Input, Tag, UtcTime,
};
use nom::IResult;
use std::fmt;
use std::ops::{Add, Sub};
use time::macros::format_description;
use time::{Duration, OffsetDateTime};

use crate::error::X509Error;

/// An ASN.1 timestamp.
///
/// <pre>
/// Time ::= CHOICE {
///     utcTime        UTCTime,
///     generalTime    GeneralizedTime }
/// </pre>
#[derive(Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct ASN1Time {
    time: OffsetDateTime,
    generalized: bool,
}

impl ASN1Time {
    #[inline]
    pub const fn new(dt: OffsetDateTime) -> Self {
        let generalized = dt.year() > 2049;
        Self {
            time: dt,
            generalized,
        }
    }

    #[inline]
    pub const fn new_generalized(dt: OffsetDateTime) -> Self {
        Self {
            time: dt,
            generalized: true,
        }
    }

    #[inline]
    pub const fn new_utc(dt: OffsetDateTime) -> Self {
        Self {
            time: dt,
            generalized: false,
        }
    }

    #[inline]
    pub const fn to_datetime(&self) -> OffsetDateTime {
        self.time
    }

    /// Makes a new `ASN1Time` from the number of non-leap seconds since Epoch
    pub fn from_timestamp(secs: i64) -> Result<Self, X509Error> {
        let dt = OffsetDateTime::from_unix_timestamp(secs).map_err(|_| X509Error::InvalidDate)?;
        Ok(ASN1Time::new(dt))
    }

    /// Returns the number of non-leap seconds since January 1, 1970 0:00:00 UTC (aka "UNIX timestamp").
    #[inline]
    pub fn timestamp(&self) -> i64 {
        self.time.unix_timestamp()
    }

    /// Returns a `ASN1Time` which corresponds to the current date.
    #[inline]
    pub fn now() -> Self {
        ASN1Time::new(OffsetDateTime::now_utc())
    }

    /// Returns an RFC 2822 date and time string such as `Tue, 1 Jul 2003 10:52:37 +0200`.
    ///
    /// Conversion to RFC2822 date can fail if date cannot be represented in this format,
    /// for example if year < 1900.
    ///
    /// For an infallible conversion to string, use `.to_string()`.
    #[inline]
    pub fn to_rfc2822(self) -> Result<String, String> {
        self.time
            .format(&time::format_description::well_known::Rfc2822)
            .map_err(|e| e.to_string())
    }

    /// Return `true` if date is encoded as UTCTime
    ///
    /// According to RFC 5280, dates though year 2049 should be encoded as UTCTime, and
    /// GeneralizedTime after 2029.
    #[inline]
    pub const fn is_utctime(&self) -> bool {
        !self.generalized
    }

    /// Return `true` if date is encoded as GeneralizedTime
    ///
    /// According to RFC 5280, dates though year 2049 should be encoded as UTCTime, and
    /// GeneralizedTime after 2029.
    #[inline]
    pub const fn is_generalizedtime(&self) -> bool {
        self.generalized
    }
}

// impl FromDer<'_, X509Error> for ASN1Time {
//     fn from_der(i: &[u8]) -> X509Result<Self> {
//         let (rem, time) = parse_choice_of_time(i).map_err(|_| X509Error::InvalidDate)?;
//         Ok((rem, time))
//     }
// }

impl DynTagged for ASN1Time {
    fn tag(&self) -> Tag {
        if self.is_generalizedtime() {
            Tag::GeneralizedTime
        } else {
            Tag::UtcTime
        }
    }

    fn accept_tag(tag: Tag) -> bool {
        tag == Tag::GeneralizedTime || tag == Tag::UtcTime
    }
}

impl<'a> DerParser<'a> for ASN1Time {
    type Error = X509Error;

    fn from_der_content(
        header: &'_ Header<'a>,
        input: Input<'a>,
    ) -> IResult<Input<'a>, Self, Self::Error> {
        match header.tag() {
            Tag::GeneralizedTime => {
                let (rem, t) = GeneralizedTime::from_der_content(header, input)
                    .map_err(|_| X509Error::InvalidDate)?;
                let dt = t.utc_datetime().map_err(|e| Err::Error(e.into()))?;
                Ok((rem, ASN1Time::new_utc(dt)))
            }
            Tag::UtcTime => {
                if let Ok((rem, t)) = UtcTime::from_der_content(header, input.clone()) {
                    let dt = t
                        .utc_adjusted_datetime()
                        .map_err(|e| Err::Error(e.into()))?;
                    Ok((rem, ASN1Time::new_utc(dt)))
                } else {
                    parse_malformed_date(input).map_err(Err::convert)
                }
            }
            _ => Err(Err::Error(X509Error::InvalidDate)),
        }
        // if let Ok((rem, t)) = UtcTime::parse_der(input.clone()) {
        //     let dt = t
        //         .utc_adjusted_datetime()
        //         .map_err(|e| Err::Error(e.into()))?;
        //     Ok((rem, ASN1Time::new_utc(dt)))
        // } else if let Ok((rem, t)) = GeneralizedTime::parse_der(input.clone()) {
        //     let dt = t.utc_datetime().map_err(|e| Err::Error(e.into()))?;
        //     Ok((rem, ASN1Time::new_utc(dt)))
        // } else {
        //     parse_malformed_date(input).map_err(Err::convert)
        // }
    }
}

// pub(crate) fn parse_choice_of_time(i: &[u8]) -> ParseResult<ASN1Time> {
//     if let Ok((rem, t)) = UtcTime::from_der(i) {
//         let dt = t.utc_adjusted_datetime()?;
//         return Ok((rem, ASN1Time::new_utc(dt)));
//     }
//     if let Ok((rem, t)) = GeneralizedTime::from_der(i) {
//         let dt = t.utc_datetime()?;
//         return Ok((rem, ASN1Time::new_generalized(dt)));
//     }
//     parse_malformed_date(i)
// }

// allow relaxed parsing of UTCTime (ex: 370116130016+0000)
fn parse_malformed_date(input: Input<'_>) -> IResult<Input<'_>, ASN1Time, BerError<Input<'_>>> {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    // fn check_char(b: &u8) -> bool {
    //     (0x20 <= *b && *b <= 0x7f) || (*b == b'+')
    // }
    let (_rem, hdr) = Header::parse_der(input.clone())?;
    // let len = hdr.length().definite()?;
    // if len > MAX_OBJECT_SIZE {
    //     return Err(Err::Error(Error::InvalidLength));
    // }
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
            Err(BerError::nom_err_input(&input, InnerError::BerValueError))
        }
        _ => Err(Err::Error(BerError::unexpected_tag(
            input,
            Some(Tag::UtcTime),
            hdr.tag(),
        ))),
    }
}

impl fmt::Display for ASN1Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let format = format_description!("[month repr:short] [day padding:space] [hour]:[minute]:[second] [year padding:none] [offset_hour sign:mandatory]:[offset_minute]");
        let s = self
            .time
            .format(format)
            .unwrap_or_else(|e| format!("Invalid date: {}", e));
        f.write_str(&s)
    }
}

impl Add<Duration> for ASN1Time {
    type Output = Option<ASN1Time>;

    #[inline]
    fn add(self, rhs: Duration) -> Option<ASN1Time> {
        Some(ASN1Time::new(self.time + rhs))
    }
}

impl Sub<ASN1Time> for ASN1Time {
    type Output = Option<Duration>;

    #[inline]
    fn sub(self, rhs: ASN1Time) -> Option<Duration> {
        if self.time > rhs.time {
            Some(self.time - rhs.time)
        } else {
            None
        }
    }
}

impl From<OffsetDateTime> for ASN1Time {
    fn from(dt: OffsetDateTime) -> Self {
        ASN1Time::new(dt)
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::ASN1Time;

    #[test]
    fn test_time_to_string() {
        let d = datetime!(1 - 1 - 1 12:34:56 UTC);
        let t = ASN1Time::from(d);
        assert_eq!(t.to_string(), "Jan  1 12:34:56 1 +00:00".to_string());
    }

    #[test]
    fn test_nonrfc2822_date() {
        // test year < 1900
        let d = datetime!(1 - 1 - 1 00:00:00 UTC);
        let t = ASN1Time::from(d);
        assert!(t.to_rfc2822().is_err());
    }
}
