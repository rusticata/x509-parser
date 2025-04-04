use crate::error::X509Error;
use asn1_rs::{Alias, Oid, Sequence};
use std::collections::HashMap;

/// <pre>
/// PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
///  issuerDomainPolicy      CertPolicyId,
///  subjectDomainPolicy     CertPolicyId }
/// </pre>
#[derive(Clone, Debug, PartialEq, Eq, Alias)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct PolicyMappings<'a>(pub Vec<PolicyMapping<'a>>);

impl<'a> PolicyMappings<'a> {
    /// Returns a `HashMap` mapping `Oid` to the list of references to `Oid`
    ///
    /// If several names match the same `Oid`, they are merged in the same entry.
    pub fn as_hashmap(&self) -> HashMap<Oid<'a>, Vec<&Oid<'a>>> {
        // create the hashmap and merge entries with same OID
        let mut m: HashMap<Oid, Vec<&_>> = HashMap::new();
        for desc in &self.0 {
            let PolicyMapping {
                issuer_domain_policy: left,
                subject_domain_policy: right,
            } = desc;
            if let Some(l) = m.get_mut(left) {
                l.push(right);
            } else {
                m.insert(left.clone(), vec![right]);
            }
        }
        m
    }

    /// Returns a `HashMap` mapping `Oid` to the list of `Oid` (consuming the input)
    ///
    /// If several names match the same `Oid`, they are merged in the same entry.
    pub fn into_hashmap(self) -> HashMap<Oid<'a>, Vec<Oid<'a>>> {
        let mut l = self.0;
        // create the hashmap and merge entries with same OID
        let mut m: HashMap<Oid, Vec<_>> = HashMap::new();
        for mapping in l.drain(..) {
            let PolicyMapping {
                issuer_domain_policy: left,
                subject_domain_policy: right,
            } = mapping;
            if let Some(general_names) = m.get_mut(&left) {
                general_names.push(right);
            } else {
                m.insert(left, vec![right]);
            }
        }
        m
    }
}

/// <pre>
/// SEQUENCE {
///  issuerDomainPolicy      CertPolicyId,
///  subjectDomainPolicy     CertPolicyId }
/// </pre>
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct PolicyMapping<'a> {
    pub issuer_domain_policy: Oid<'a>,
    pub subject_domain_policy: Oid<'a>,
}

impl<'a> PolicyMapping<'a> {
    pub const fn new(issuer_domain_policy: Oid<'a>, subject_domain_policy: Oid<'a>) -> Self {
        PolicyMapping {
            issuer_domain_policy,
            subject_domain_policy,
        }
    }
}
