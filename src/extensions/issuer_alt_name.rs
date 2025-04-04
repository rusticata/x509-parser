use asn1_rs::Alias;

use crate::error::X509Error;

use super::GeneralNames;

/// Issuer Alternative Name
///
/// Note: empty sequences are accepted
///
/// <pre>
/// IssuerAltName ::= GeneralNames
///
/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
/// </pre>
#[derive(Clone, Debug, PartialEq, Alias)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct IssuerAlternativeName<'a>(pub GeneralNames<'a>);
