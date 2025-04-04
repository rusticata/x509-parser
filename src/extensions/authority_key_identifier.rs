use core::fmt;
use std::fmt::LowerHex;

use asn1_rs::{Alias, Integer, Sequence};

use crate::error::X509Error;
use crate::utils::format_serial;

use super::GeneralName;

/// <pre>
/// -- IMPLICIT tags
/// AuthorityKeyIdentifier ::= SEQUENCE {
///     keyIdentifier             [0] KeyIdentifier            OPTIONAL,
///     authorityCertIssuer       [1] GeneralNames             OPTIONAL,
///     authorityCertSerialNumber [2] CertificateSerialNumber  OPTIONAL }
///     -- authorityCertIssuer and authorityCertSerialNumber MUST both
///     -- be present or both be absent
///
/// CertificateSerialNumber  ::=  INTEGER
/// </pre>
#[derive(Clone, Debug, PartialEq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct AuthorityKeyIdentifier<'a> {
    #[tag_implicit(0)]
    #[optional]
    pub key_identifier: Option<KeyIdentifier<'a>>,

    #[tag_implicit(1)]
    #[optional]
    pub authority_cert_issuer: Option<Vec<GeneralName<'a>>>,

    #[tag_implicit(2)]
    #[optional]
    pub authority_cert_serial: Option<Integer<'a>>,
}

// <pre>
// KeyIdentifier ::= OCTET STRING
// </pre>
#[derive(Clone, Debug, PartialEq, Eq, Alias)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct KeyIdentifier<'a>(pub &'a [u8]);

impl LowerHex for KeyIdentifier<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = format_serial(self.0);
        f.write_str(&s)
    }
}
