use asn1_rs::{oid, DerParser, Input, Oid, Tag, Tagged};
use nom::{Err, IResult};

use crate::error::X509Error;

/// <pre>
/// ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
///
/// KeyPurposeId ::= OBJECT IDENTIFIER
/// </pre>
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedKeyUsage<'a> {
    pub any: bool,
    pub server_auth: bool,
    pub client_auth: bool,
    pub code_signing: bool,
    pub email_protection: bool,
    pub time_stamping: bool,
    pub ocsp_signing: bool,
    pub other: Vec<Oid<'a>>,
}

impl Tagged for ExtendedKeyUsage<'_> {
    const CONSTRUCTED: bool = true;
    const TAG: Tag = Tag::Sequence;
}

impl<'a> DerParser<'a> for ExtendedKeyUsage<'a> {
    type Error = X509Error;

    fn from_der_content(
        header: &'_ asn1_rs::Header<'a>,
        input: Input<'a>,
    ) -> IResult<Input<'a>, Self, Self::Error> {
        let (rem, seq) = <Vec<Oid>>::from_der_content(header, input).map_err(Err::convert)?;
        let mut seen = std::collections::HashSet::new();
        let mut eku = ExtendedKeyUsage {
            any: false,
            server_auth: false,
            client_auth: false,
            code_signing: false,
            email_protection: false,
            time_stamping: false,
            ocsp_signing: false,
            other: Vec::new(),
        };
        for oid in &seq {
            if !seen.insert(oid.clone()) {
                continue;
            }
            let asn1 = oid.as_bytes();
            if asn1 == oid!(raw 2.5.29.37.0) {
                eku.any = true;
            } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.1) {
                eku.server_auth = true;
            } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.2) {
                eku.client_auth = true;
            } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.3) {
                eku.code_signing = true;
            } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.4) {
                eku.email_protection = true;
            } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.8) {
                eku.time_stamping = true;
            } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.9) {
                eku.ocsp_signing = true;
            } else {
                eku.other.push(oid.clone());
            }
        }
        Ok((rem, eku))
    }
}

// pub(crate) fn parse_extendedkeyusage(input: Input) -> IResult<Input, ExtendedKeyUsage, X509Error> {
//     let (ret, seq) = <Vec<Oid>>::parse_der(input).map_err(Err::convert)?;
//     let mut seen = std::collections::HashSet::new();
//     let mut eku = ExtendedKeyUsage {
//         any: false,
//         server_auth: false,
//         client_auth: false,
//         code_signing: false,
//         email_protection: false,
//         time_stamping: false,
//         ocsp_signing: false,
//         other: Vec::new(),
//     };
//     for oid in &seq {
//         if !seen.insert(oid.clone()) {
//             continue;
//         }
//         let asn1 = oid.as_bytes();
//         if asn1 == oid!(raw 2.5.29.37.0) {
//             eku.any = true;
//         } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.1) {
//             eku.server_auth = true;
//         } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.2) {
//             eku.client_auth = true;
//         } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.3) {
//             eku.code_signing = true;
//         } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.4) {
//             eku.email_protection = true;
//         } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.8) {
//             eku.time_stamping = true;
//         } else if asn1 == oid!(raw 1.3.6.1.5.5.7.3.9) {
//             eku.ocsp_signing = true;
//         } else {
//             eku.other.push(oid.clone());
//         }
//     }
//     Ok((ret, eku))
// }
