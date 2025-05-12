use asn1_rs::Sequence;

use crate::error::X509Error;

/// "Basic Constraints" extension: identifies whether the subject of the certificate
/// is a CA, and the max validation depth.
///
/// <pre>
///   id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }
///   BasicConstraints ::= SEQUENCE {
///        cA                      BOOLEAN DEFAULT FALSE,
///        pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
/// </pre>
///
/// Note the maximum length of the `pathLenConstraint` field is limited to the size of a 32-bits
/// unsigned integer, and parsing will fail if value if larger.
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct BasicConstraints {
    #[default(false)]
    pub ca: bool,
    pub path_len_constraint: Option<u32>,
}

#[cfg(test)]
mod tests {
    use crate::extensions::BasicConstraints;
    use asn1_rs::{DerParser, Input};
    use hex_literal::hex;

    #[test]
    fn extension_basic_constraints() {
        //--- CA=false
        let bytes = &hex!("30 00");
        let (rem, res) = BasicConstraints::parse_der(Input::from(bytes)).expect("BasicConstraints");
        assert!(rem.is_empty());
        assert_eq!(
            res,
            BasicConstraints {
                ca: false,
                path_len_constraint: None
            }
        );

        //--- CA=true, pathlen omitted
        let bytes = &hex!("30 03 01 01 FF");
        let (rem, res) = BasicConstraints::parse_der(Input::from(bytes)).expect("BasicConstraints");
        assert!(rem.is_empty());
        assert_eq!(
            res,
            BasicConstraints {
                ca: true,
                path_len_constraint: None
            }
        );

        //--- CA=true, pathlen=<integer>>
        let bytes = &hex!("30 06 01 01 FF 02 01 0a");
        let (rem, res) = BasicConstraints::parse_der(Input::from(bytes)).expect("BasicConstraints");
        assert!(rem.is_empty());
        assert_eq!(
            res,
            BasicConstraints {
                ca: true,
                path_len_constraint: Some(0xa),
            }
        );
    }
}
