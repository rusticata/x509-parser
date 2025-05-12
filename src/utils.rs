use core::fmt;

use asn1_rs::{BmpString, Choice, PrintableString, TeletexString, UniversalString, Utf8String};

/// The DirectoryString type is defined as a choice of PrintableString, TeletexString,
/// BMPString, UTF8String, and UniversalString.
///
/// <pre>
/// RFC 5280, 4.1.2.4.  Issuer
///    DirectoryString ::= CHOICE {
///          teletexString           TeletexString (SIZE (1..MAX)),
///          printableString         PrintableString (SIZE (1..MAX)),
///          universalString         UniversalString (SIZE (1..MAX)),
///          utf8String              UTF8String (SIZE (1..MAX)),
///          bmpString               BMPString (SIZE (1..MAX))
///    }
/// </pre>
#[derive(Debug, PartialEq, Eq, Choice)]
#[asn1(parse = "DER", encode = "")]
pub enum DirectoryString<'a> {
    Teletex(TeletexString<'a>),
    Printable(PrintableString<'a>),
    Universal(UniversalString<'a>),
    Utf8(Utf8String<'a>),
    Bmp(BmpString<'a>),
}

impl fmt::Display for DirectoryString<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectoryString::Teletex(s) => f.write_str(s.as_ref()),
            DirectoryString::Printable(s) => f.write_str(s.as_ref()),
            DirectoryString::Universal(s) => f.write_str(s.as_ref()),
            DirectoryString::Utf8(s) => f.write_str(s.as_ref()),
            DirectoryString::Bmp(s) => f.write_str(s.as_ref()),
        }
    }
}

/// Formats a slice to a colon-separated hex string (for ex `01:02:ff:ff`)
pub fn format_serial(i: &[u8]) -> String {
    let mut s = i.iter().fold(String::with_capacity(3 * i.len()), |a, b| {
        a + &format!("{b:02x}:")
    });
    s.pop();
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_serial() {
        let b: &[u8] = &[1, 2, 3, 4, 0xff];
        assert_eq!("01:02:03:04:ff", format_serial(b));
    }
}
