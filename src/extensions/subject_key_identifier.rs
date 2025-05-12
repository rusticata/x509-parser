use core::fmt;
use std::ops::Deref;

use asn1_rs::Alias;

use crate::error::X509Error;
use crate::x509::format_serial;

/// <pre>
/// SubjectKeyIdentifier ::= KeyIdentifier
/// </pre>
#[derive(Clone, Debug, PartialEq, Alias)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct SubjectKeyIdentifier<'a>(pub KeyIdentifier<'a>);

impl<'a> Deref for SubjectKeyIdentifier<'a> {
    type Target = KeyIdentifier<'a>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// <pre>
// KeyIdentifier ::= OCTET STRING
// </pre>
#[derive(Clone, Debug, PartialEq, Eq, Alias)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct KeyIdentifier<'a>(pub &'a [u8]);

impl KeyIdentifier<'_> {
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub const fn len(&self) -> usize {
        self.0.len()
    }
}

impl<'a> Deref for KeyIdentifier<'a> {
    type Target = &'a [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> AsRef<[u8]> for KeyIdentifier<'a> {
    fn as_ref(&self) -> &'a [u8] {
        self.0
    }
}

impl fmt::LowerHex for KeyIdentifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = format_serial(self.0);
        f.write_str(&s)
    }
}
