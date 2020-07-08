use chrono::offset::{TimeZone, Utc};
use chrono::DateTime;
use std::ops::{Add, Sub};
use std::time::Duration;
use std::time::SystemTime;

/// An ASN.1 timestamp.
#[derive(Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct ASN1Time(DateTime<Utc>);

impl ASN1Time {
    #[inline]
    pub(crate) fn from_datetime_utc(dt: DateTime<Utc>) -> Self {
        ASN1Time(dt)
    }

    /// Makes a new `ASN1Time` from the number of non-leap seconds since Epoch
    pub fn from_timestamp(secs: i64) -> Self {
        ASN1Time(Utc.timestamp(secs, 0))
    }

    /// Returns the number of non-leap seconds since January 1, 1970 0:00:00 UTC (aka "UNIX timestamp").
    #[inline]
    pub fn timestamp(&self) -> i64 {
        self.0.timestamp()
    }

    /// Returns a `ASN1Time` which corresponds to the current date.
    #[inline]
    pub fn now() -> Self {
        ASN1Time(SystemTime::now().into())
    }

    /// Returns an RFC 2822 date and time string such as `Tue, 1 Jul 2003 10:52:37 +0200`.
    #[inline]
    pub fn to_rfc2822(&self) -> String {
        self.0.to_rfc2822()
    }
}

impl Add<Duration> for ASN1Time {
    type Output = Option<ASN1Time>;

    #[inline]
    fn add(self, rhs: Duration) -> Option<ASN1Time> {
        let secs = rhs.as_secs();
        // u32::MAX is not supported in rust 1.34
        const MAX_U32: u64 = 4_294_967_295;
        if secs > MAX_U32 {
            return None;
        }
        let duration = chrono::Duration::seconds(secs as i64);
        let dt = self.0.checked_add_signed(duration)?;
        Some(ASN1Time(dt))
    }
}

impl Sub<ASN1Time> for ASN1Time {
    type Output = Option<Duration>;

    #[inline]
    fn sub(self, rhs: ASN1Time) -> Option<Duration> {
        self.0.signed_duration_since(rhs.0).to_std().ok()
    }
}
