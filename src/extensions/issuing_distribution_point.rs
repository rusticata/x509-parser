use asn1_rs::Sequence;

use crate::error::X509Error;

use super::{DistributionPointName, ReasonFlags};

/// <pre>
/// -- IMPLICIT tags
/// IssuingDistributionPoint ::= SEQUENCE {
///     distributionPoint          [0] DistributionPointName OPTIONAL,
///     onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
///     onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
///     onlySomeReasons            [3] ReasonFlags OPTIONAL,
///     indirectCRL                [4] BOOLEAN DEFAULT FALSE,
///     onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }
///     -- at most one of onlyContainsUserCerts, onlyContainsCACerts,
///     -- and onlyContainsAttributeCerts may be set to TRUE.
/// </pre>
#[derive(Clone, Debug, PartialEq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct IssuingDistributionPoint<'a> {
    #[tag_implicit(0)]
    #[optional]
    pub distribution_point: Option<DistributionPointName<'a>>,

    #[tag_implicit(1)]
    #[default(false)]
    pub only_contains_user_certs: bool,

    #[tag_implicit(2)]
    #[default(false)]
    pub only_contains_ca_certs: bool,

    #[tag_implicit(3)]
    #[optional]
    pub only_some_reasons: Option<ReasonFlags>,

    #[tag_implicit(4)]
    #[default(false)]
    pub indirect_crl: bool,

    #[tag_implicit(5)]
    #[default(false)]
    pub only_contains_attribute_certs: bool,
}
