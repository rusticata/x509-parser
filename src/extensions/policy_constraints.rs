use asn1_rs::Sequence;

use crate::error::X509Error;

use super::SkipCerts;

/// <pre>
/// -- IMPLICIT tags
/// PolicyConstraints ::= SEQUENCE {
///     requireExplicitPolicy   [0]     SkipCerts OPTIONAL,
///     inhibitPolicyMapping    [1]     SkipCerts OPTIONAL }
///
/// SkipCerts ::= INTEGER (0..MAX)
/// </pre>
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct PolicyConstraints {
    #[tag_implicit(0)]
    #[optional]
    pub require_explicit_policy: Option<SkipCerts>,
    #[tag_implicit(1)]
    #[optional]
    pub inhibit_policy_mapping: Option<SkipCerts>,
}
