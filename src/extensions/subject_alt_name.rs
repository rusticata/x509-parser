use asn1_rs::Alias;

use crate::error::X509Error;

use super::GeneralNames;

/// Subject Alternative Name
///
/// Note: empty sequences are accepted
///
/// <pre>
/// SubjectAltName ::= GeneralNames
///
/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
/// </pre>
#[derive(Clone, Debug, PartialEq, Alias)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct SubjectAlternativeName<'a>(pub GeneralNames<'a>);
