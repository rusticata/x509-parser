//! X.509 objects
//!
//! Based on RFC5280
//!

use std::fmt;

use num_bigint::BigUint;
use time::Tm;

use der_parser::ber::BitStringObject;
use der_parser::der::DerObject;
use der_parser::oid::Oid;
use objects::{oid2nid,nid2sn};
use error::X509Error;
use x509_parser::parse_ext_basicconstraints;


#[derive(Debug, PartialEq)]
pub struct X509Extension<'a> {
    pub oid:  Oid,
    pub critical: bool,
    pub value: &'a[u8],
}

#[derive(Debug, PartialEq)]
pub struct AttributeTypeAndValue<'a> {
    pub attr_type: Oid,
    pub attr_value: DerObject<'a>, // XXX DirectoryString ?
}

#[derive(Debug, PartialEq)]
pub struct RelativeDistinguishedName<'a> {
    pub set: Vec<AttributeTypeAndValue<'a>>
}

#[derive(Debug, PartialEq)]
pub struct SubjectPublicKeyInfo<'a> {
    pub algorithm:  AlgorithmIdentifier<'a>,
    pub subject_public_key: BitStringObject<'a>,
}

#[derive(Debug, PartialEq)]
pub struct AlgorithmIdentifier<'a> {
    pub algorithm:  Oid,
    pub parameters: DerObject<'a>,
}

#[derive(Debug, PartialEq)]
pub struct X509Name<'a> {
    pub rdn_seq: Vec<RelativeDistinguishedName<'a>>,
}

impl<'a> fmt::Display for X509Name<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match x509name_to_string(&self.rdn_seq) {
            Ok(o)  => write!(f, "{}", o),
            Err(_) => write!(f, "<X509Error: Invalid X.509 name>"),
        }
    }
}



/// The sequence TBSCertificate contains information associated with the
/// subject of the certificate and the CA that issued it.
///
/// RFC5280 definition:
///
/// <pre>
///   TBSCertificate  ::=  SEQUENCE  {
///        version         [0]  EXPLICIT Version DEFAULT v1,
///        serialNumber         CertificateSerialNumber,
///        signature            AlgorithmIdentifier,
///        issuer               Name,
///        validity             Validity,
///        subject              Name,
///        subjectPublicKeyInfo SubjectPublicKeyInfo,
///        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///                             -- If present, version MUST be v2 or v3
///        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///                             -- If present, version MUST be v2 or v3
///        extensions      [3]  EXPLICIT Extensions OPTIONAL
///                             -- If present, version MUST be v3
///        }
/// </pre>
#[derive(Debug, PartialEq)]
pub struct TbsCertificate<'a> {
    pub version: u32,
    pub serial: BigUint,
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: X509Name<'a>,
    pub validity: Validity,
    pub subject: X509Name<'a>,
    pub subject_pki: SubjectPublicKeyInfo<'a>,
    pub issuer_uid: Option<UniqueIdentifier<'a>>,
    pub subject_uid: Option<UniqueIdentifier<'a>>,
    pub extensions: Vec<X509Extension<'a>>,
    pub(crate) raw: &'a [u8],
    pub(crate) raw_serial: &'a [u8],
}

impl<'a> AsRef<[u8]> for TbsCertificate<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

#[derive(Debug, PartialEq)]
pub struct Validity {
    pub not_before: Tm,
    pub not_after:  Tm,
}

impl Validity {
    /// The time left before the certificate expires.
    ///
    /// If the certificate is not currently valid, then `None` is
    /// returned.  Otherwise, the `Duration` until the certificate
    /// expires is returned.
    pub fn time_to_expiration(&self) -> Option<std::time::Duration> {
        let now = time::now().to_timespec();
        let nb = self.not_before.to_timespec();
        let na = self.not_after.to_timespec();
        if now < nb {
            // Not yet valid...
            return None;
        }
        if now.sec >= na.sec {
            // Has already expired (or within a second, so who cares?).
            return None;
        }
        // Note that the duration below is guaranteed to be positive,
        // since we just checked that now.sec >= na.sec.
        Some(std::time::Duration::from_secs((na.sec - now.sec) as u64))
    }
}

#[test]
fn check_validity_expiration() {
    let mut v = Validity {
        not_before: time::now(),
        not_after: time::now(),
    };
    assert_eq!(v.time_to_expiration(), None);
    v.not_after = v.not_after + time::Duration::minutes(1);
    assert!(v.time_to_expiration().is_some());
    assert!(v.time_to_expiration().unwrap() <= std::time::Duration::from_secs(60));
    // The following assumes this timing won't take 10 seconds... I
    // think that is safe.
    assert!(v.time_to_expiration().unwrap() > std::time::Duration::from_secs(50));
}

#[derive(Debug, PartialEq)]
pub struct UniqueIdentifier<'a>(pub BitStringObject<'a>);

impl<'a> TbsCertificate<'a> {
    /// Returns true if certificate has `basicConstraints CA:true`
    pub fn is_ca(&self) -> bool {
        // filter on ext: OId(basicConstraints)
        self.extensions.iter().find(|ext| {
            ext.oid == Oid::from(&[2, 5, 29, 19])
        }).and_then(|ext| {
            // parse DER sequence
            if let Ok((_,bc)) = parse_ext_basicconstraints(ext.value) {
                Some(bc.ca)
            } else {
                None
            }
        }).unwrap_or(false)
    }

    /// Get the raw bytes of the certificate serial number
    pub fn raw_serial(&self) -> &[u8] {
        self.raw_serial
    }
}

/// The sequence TBSCertList contains information about the certificates that have
/// been revoked by the CA that issued the CRL.
///
/// RFC5280 definition:
///
/// <pre>
/// TBSCertList  ::=  SEQUENCE  {
///         version                 Version OPTIONAL,
///                                      -- if present, MUST be v2
///         signature               AlgorithmIdentifier,
///         issuer                  Name,
///         thisUpdate              Time,
///         nextUpdate              Time OPTIONAL,
///         revokedCertificates     SEQUENCE OF SEQUENCE  {
///             userCertificate         CertificateSerialNumber,
///             revocationDate          Time,
///             crlEntryExtensions      Extensions OPTIONAL
///                                      -- if present, version MUST be v2
///                                   } OPTIONAL,
///         crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
///                                      -- if present, version MUST be v2
///                             }
/// </pre>
#[derive(Debug, PartialEq)]
pub struct TbsCertList<'a> {
    pub version: Option<u32>,
    pub signature: AlgorithmIdentifier<'a>,
    pub issuer: X509Name<'a>,
    pub this_update: Tm,
    pub next_update: Option<Tm>,
    pub revoked_certificates: Vec<RevokedCertificate<'a>>,
    pub extensions: Vec<X509Extension<'a>>,
    pub(crate) raw: &'a [u8],
}

impl<'a> AsRef<[u8]> for TbsCertList<'a> {
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

#[derive(Debug, PartialEq)]
pub struct RevokedCertificate<'a> {
    pub user_certificate: BigUint,
    pub revocation_date: Tm,
    pub extensions: Vec<X509Extension<'a>>
}


/// Convert a DER representation of a X.509 name to a human-readble string
///
/// RDNs are separated with ","
/// Multiple RDNs are separated with "+"
fn x509name_to_string(rdn_seq: &[RelativeDistinguishedName]) -> Result<String,X509Error> {
    rdn_seq.iter().fold(
        Ok(String::new()),
        |acc, rdn| {
            acc.and_then(|mut _vec| {
                rdn.set.iter().fold(
                    Ok(String::new()),
                    |acc2, attr| {
                        acc2.and_then(|mut _vec2| {
                            match attr.attr_value.as_slice() {
                                Ok(s) => {
                                    // println!("object: *** {:?} {:?}", oid, str::from_utf8(s));
                                    let sn_res = oid2nid(&attr.attr_type).and_then(nid2sn);
                                    let sn_str = match sn_res {
                                        Ok(s) => String::from(s),
                                        _     => format!("{:?}",attr.attr_type),
                                    };
                                    let val_str = String::from_utf8_lossy(s);
                                    let rdn = format!("{}={}", sn_str, val_str);
                                    match _vec2.len() {
                                        0 => Ok(rdn),
                                        _ => Ok(_vec2 + " + " + &rdn),
                                    }
                                },
                                _ => { Err(X509Error::InvalidX509Name) },
                            }
                        })
            }).and_then(|v| {
                match _vec.len() {
                    0 => Ok(v),
                    _ => Ok(_vec + ", " + &v),
                }
            })
        })
    })
}

/// An X.509 v3 Certificate.
///
/// X.509 v3 certificates are defined in [RFC5280](https://tools.ietf.org/html/rfc5280).
#[derive(Debug, PartialEq)]
pub struct X509Certificate<'a> {
    pub tbs_certificate: TbsCertificate<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: BitStringObject<'a>
}

/// An X.509 v2 Certificate Revocaton List (CRL).
///
/// X.509 v2 CRLs are defined in [RFC5280](https://tools.ietf.org/html/rfc5280).
#[derive(Debug)]
pub struct CertificateRevocationList<'a> {
    pub tbs_cert_list: TbsCertList<'a>,
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    pub signature_value: BitStringObject<'a>,
}





#[cfg(test)]
mod tests {
    use x509::*;
    use der_parser::ber::BerObjectContent;
    use der_parser::oid::Oid;

#[test]
fn test_x509_name() {
    let name = X509Name{
        rdn_seq: vec![
            RelativeDistinguishedName{ set: vec![
                AttributeTypeAndValue{
                    attr_type:  Oid::from(&[2, 5, 4, 6]), // countryName
                    attr_value: DerObject::from_obj(BerObjectContent::PrintableString(b"FR")),
                }
            ]},
            RelativeDistinguishedName{ set: vec![
                AttributeTypeAndValue{
                    attr_type:  Oid::from(&[2, 5, 4, 8]), // stateOrProvinceName
                    attr_value: DerObject::from_obj(BerObjectContent::PrintableString(b"Some-State")),
                }
            ]},
            RelativeDistinguishedName{ set: vec![
                AttributeTypeAndValue{
                    attr_type:  Oid::from(&[2, 5, 4, 10]), // organizationName
                    attr_value: DerObject::from_obj(BerObjectContent::PrintableString(b"Internet Widgits Pty Ltd")),
                }
            ]},
            RelativeDistinguishedName{ set: vec![
                AttributeTypeAndValue{
                    attr_type:  Oid::from(&[2, 5, 4, 3]), // CN
                    attr_value: DerObject::from_obj(BerObjectContent::PrintableString(b"Test1")),
                },
                AttributeTypeAndValue{
                    attr_type:  Oid::from(&[2, 5, 4, 3]), // CN
                    attr_value: DerObject::from_obj(BerObjectContent::PrintableString(b"Test2")),
                }
            ]},
        ]
    };
    assert_eq!(name.to_string(), "C=FR, ST=Some-State, O=Internet Widgits Pty Ltd, CN=Test1 + CN=Test2");
}

}
