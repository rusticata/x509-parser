use std::collections::HashMap;

use asn1_rs::{Alias, Oid, Sequence};

use crate::error::X509Error;

use super::GeneralName;

/// <pre>
/// AuthorityInfoAccessSyntax  ::=
///         SEQUENCE SIZE (1..MAX) OF AccessDescription
/// </pre>
#[derive(Clone, Debug, PartialEq, Alias)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct AuthorityInfoAccess<'a>(pub Vec<AccessDescription<'a>>);

impl<'a> AuthorityInfoAccess<'a> {
    /// Returns an iterator over the Access Descriptors
    pub fn iter(&self) -> impl Iterator<Item = &AccessDescription<'a>> {
        self.0.iter()
    }

    /// Returns a `HashMap` mapping `Oid` to the list of references to `GeneralNames`
    ///
    /// If several names match the same `Oid`, they are merged in the same entry.
    pub fn as_hashmap(&self) -> HashMap<Oid<'a>, Vec<&GeneralName<'a>>> {
        // create the hashmap and merge entries with same OID
        let mut m: HashMap<Oid, Vec<&GeneralName>> = HashMap::new();
        for desc in &self.0 {
            let AccessDescription {
                access_method: oid,
                access_location: gn,
            } = desc;
            if let Some(general_names) = m.get_mut(oid) {
                general_names.push(gn);
            } else {
                m.insert(oid.clone(), vec![gn]);
            }
        }
        m
    }

    /// Returns a `HashMap` mapping `Oid` to the list of `GeneralNames` (consuming the input)
    ///
    /// If several names match the same `Oid`, they are merged in the same entry.
    pub fn into_hashmap(self) -> HashMap<Oid<'a>, Vec<GeneralName<'a>>> {
        let mut aia_list = self.0;
        // create the hashmap and merge entries with same OID
        let mut m: HashMap<Oid, Vec<GeneralName>> = HashMap::new();
        for desc in aia_list.drain(..) {
            let AccessDescription {
                access_method: oid,
                access_location: gn,
            } = desc;
            if let Some(general_names) = m.get_mut(&oid) {
                general_names.push(gn);
            } else {
                m.insert(oid, vec![gn]);
            }
        }
        m
    }
}

/// <pre>
/// AccessDescription  ::=  SEQUENCE {
///         accessMethod          OBJECT IDENTIFIER,
///         accessLocation        GeneralName  }
/// </pre>
#[derive(Clone, Debug, PartialEq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct AccessDescription<'a> {
    pub access_method: Oid<'a>,
    pub access_location: GeneralName<'a>,
}

impl<'a> AccessDescription<'a> {
    pub const fn new(access_method: Oid<'a>, access_location: GeneralName<'a>) -> Self {
        AccessDescription {
            access_method,
            access_location,
        }
    }
}
