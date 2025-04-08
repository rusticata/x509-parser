use asn1_rs::{Any, Oid, Sequence};

use crate::error::X509Error;

/// <pre>
/// CertificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
/// </pre>
pub type CertificatePolicies<'a> = Vec<PolicyInformation<'a>>;

/// <pre>
/// PolicyInformation ::= SEQUENCE {
///      policyIdentifier   CertPolicyId,
///      policyQualifiers   SEQUENCE SIZE (1..MAX) OF
///              PolicyQualifierInfo OPTIONAL }
///
/// CertPolicyId ::= OBJECT IDENTIFIER
/// </pre>
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct PolicyInformation<'a> {
    pub policy_id: Oid<'a>,
    #[optional]
    pub policy_qualifiers: Option<Vec<PolicyQualifierInfo<'a>>>,
}

/// <pre>
/// PolicyQualifierInfo ::= SEQUENCE {
///      policyQualifierId  PolicyQualifierId,
///      qualifier          ANY DEFINED BY policyQualifierId }
/// </pre>
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct PolicyQualifierInfo<'a> {
    pub policy_qualifier_id: Oid<'a>,
    pub qualifier: Any<'a>,
}

// <pre>
// -- Implementations that recognize additional policy qualifiers MUST
// -- augment the following definition for PolicyQualifierId
//
// PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
// </pre>
