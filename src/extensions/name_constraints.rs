use asn1_rs::Sequence;

use super::GeneralName;
use crate::error::X509Error;

/// <pre>
/// -- IMPLICIT tags
/// NameConstraints ::= SEQUENCE {
///     permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
///     excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
/// </pre>
#[derive(Clone, Debug, PartialEq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct NameConstraints<'a> {
    #[tag_implicit(0)]
    #[optional]
    pub permitted_subtrees: Option<Vec<GeneralSubtree<'a>>>,

    #[tag_implicit(1)]
    #[optional]
    pub excluded_subtrees: Option<Vec<GeneralSubtree<'a>>>,
}

/// Represents the structure used in the name constraints extensions.
/// The fields minimum and maximum are not supported (openssl also has no support).
///
/// <pre>
/// -- IMPLICIT tags
/// GeneralSubtree ::= SEQUENCE {
///     base                    GeneralName,
///     minimum         [0]     BaseDistance DEFAULT 0,
///     maximum         [1]     BaseDistance OPTIONAL }
///
/// BaseDistance ::= INTEGER (0..MAX)
/// </pre>
#[derive(Clone, Debug, PartialEq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct GeneralSubtree<'a> {
    pub base: GeneralName<'a>,

    #[tag_implicit(0)]
    #[default(0)]
    pub minimum: u32,

    #[tag_implicit(1)]
    #[optional]
    pub maximum: Option<u32>,
}

#[cfg(test)]
mod tests {
    use asn1_rs::{DerParser, Input};
    use hex_literal::hex;

    use crate::prelude::GeneralName;

    use super::NameConstraints;

    #[test]
    fn extension_name_constraints() {
        // permitted subtree with 1 item DNS:".example.com"
        let bytes = &hex!("30 12 A0 10 30 0E 82 0C 2E 65 78 61 6D 70 6C 65 2E 63 6F 6D");

        let (rem, res) = NameConstraints::parse_der(Input::from(bytes)).expect("NameConstraints");
        assert!(rem.is_empty());
        assert!(res.permitted_subtrees.is_some());
        let permitted0 = &res.permitted_subtrees.as_ref().unwrap()[0];
        assert_eq!(permitted0.base, GeneralName::DNSName(".example.com"));
    }
}
