use asn1_rs::Alias;

use crate::error::X509Error;

/// <pre>
/// SkipCerts ::= INTEGER (0..MAX)
/// </pre>
pub type SkipCerts = u32;

/// <pre>
/// InhibitAnyPolicy ::= SkipCerts
/// </pre>
#[derive(Clone, Debug, PartialEq, Eq, Alias)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct InhibitAnyPolicy(pub SkipCerts);
