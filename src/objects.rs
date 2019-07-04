//! X.509 helper objects definitions: OID, short and long names, NID (internal ID)
//!
//! Most definitions taken from OpenSSL: /usr/include/openssl/objects.h
//! Note: values does not match openssl, for ex. NIDs
//!
//! Note: the objects registry is implemented as a static array with linear search. This is not the
//! most efficient method, but makes maintainance easier.

// use std::convert::From;
use der_parser::oid::Oid;

use error::NidError;

/// ASN.1 node internal identifier
///
/// This enumeration lists the node IDs used (and/or supported) in X.509 certificates.
/// It is not guaranteed to be exhaustive.
#[derive(Debug,PartialEq,Clone,Copy)]
#[repr(u8)]
pub enum Nid{
    Undef,
    Algorithm,
    RsaDsi,
    Pkcs,
    Md2,
    Md5,
    Rc4,
    RsaEncryption,
    RsaMd2,
    RsaMd5,
    PbdMd2Des,
    PbeMd5Des,
    X500,
    X509,
    CommonName,
    CountryName,
    LocalityName,
    StateOrProvinceName,
    OrganizationName,
    OrganizationalUnitName,
    Rsa,
    Pkcs7,
    Pkcs7Data,
    Pkcs7SignedData,
    Pkcs7EnvelopedData,
    Pkcs7SignedAndEnvelopedData,
    Pkcs7DigestData,
    Pkcs7EncryptedData,
    Pkcs3,
    DhKeyAgreement,
    DesEcb,
    DesCfb,
    DesCbc,
    DesEde,
    DesEde3,
    IdeaCbc,
    IdeaCfb,
    IdeaEcb,
    Rc2Cbc,
    Rc2Ecb,
    Rc2Cfb,
    Rc2Ofb,
    Sha,
    Sha1WithRsaEncryption,
    DesEdeCbc,
    DesEde3Cbc,
    DesOfb,
    IdeaOfb,
    Pkcs9,
    EmailAddress,
    UnstructuredName,
    ContentType,
    MessageDigest,
    SigningTime,
    Countersignature,
    ChallengePassword,
    UnstructuredAddress,
    ExtendedCertificateAttributes,

    RsaSha1,

    SubjectKeyIdentifier,
    KeyUsage,
    PrivateKeyUsagePeriod,
    SubjectAltName,

    BasicConstraints,

    CertificatePolicies,
    AuthorityKeyIdentifier,
}

// impl From<u32> for Nid {
//     fn from(u: u32) -> Nid { Nid(u) }
// }

// helper macros to be able to use the node OID of the parent, and only append the child values
macro_rules! rsadsi {
    ( )                =>    { &[ 1, 2, 840, 113549 ] };
    ( $( $x:expr ),* ) =>    { &[ 1, 2, 840, 113549, $( $x ),* ] }
}
macro_rules! pkcs1 {
    ( )                =>    { rsadsi!( 1, 1 ) };
    ( $( $x:expr ),* ) =>    { rsadsi!( 1, 1, $( $x ),* ) }
}
macro_rules! pkcs9 {
    ( )                =>    { rsadsi!( 1, 9 ) };
    ( $( $x:expr ),* ) =>    { rsadsi!( 1, 9, $( $x ),* ) }
}
macro_rules! algo {
    ( $( $x:expr ),* ) =>    { &[ 1, 3, 14, 3, 2, $( $x ),* ] }
}
macro_rules! x509 {
    ( $( $x:expr ),* ) =>    { &[ 2, 5, 4, $( $x ),* ] }
}
macro_rules! idce {
    ( $( $x:expr ),* ) =>    { &[ 2, 5, 29, $( $x ),* ] }
}

const OBJ_ALGO : &[u64]    = algo!();
const OBJ_RSADSI : &[u64]  = rsadsi!();
const OBJ_X500 : &[u64]    = &[2, 5];
const OBJ_X509 : &[u64]    = x509!();
const OBJ_CN : &[u64]      = x509!(3);
const OBJ_C : &[u64]       = x509!(6);
const OBJ_L : &[u64]       = x509!(7);
const OBJ_ST : &[u64]      = x509!(8);
const OBJ_O : &[u64]       = x509!(10);
const OBJ_OU : &[u64]      = x509!(11);

const OBJ_PKCS9 : &[u64]   = pkcs9!();
const OBJ_EMAIL : &[u64]   = pkcs9!(1);

// XXX ...

const OBJ_RSAENCRYPTION : &[u64] = pkcs1!(1);
const OBJ_RSASHA1 : &[u64] = pkcs1!(5);

// other constants

// const OBJ_IDCE : &[u64]    = idce!();
const OBJ_SKI : &[u64]     = idce!(14);
const OBJ_KU : &[u64]      = idce!(15);
const OBJ_PKUP : &[u64]    = idce!(16);
const OBJ_SAN : &[u64]     = idce!(17);

const OBJ_BC : &[u64]      = idce!(19);

const OBJ_CPOL : &[u64]    = idce!(32);

const OBJ_AKI : &[u64]     = idce!(35);



struct OidEntry {
    sn: &'static str,
    ln: &'static str,
    nid: Nid,
    oid: &'static [u64],
}

const OID_REGISTRY : &[OidEntry] = &[
    OidEntry{ sn:"UNDEF", ln:"undefined", nid:Nid::Undef, oid:&[0] },
    OidEntry{ sn:"Algorithm", ln:"algorithm", nid:Nid::Algorithm, oid:OBJ_ALGO },
    OidEntry{ sn:"rsadsi", ln:"rsadsi", nid:Nid::RsaDsi, oid:OBJ_RSADSI },
    OidEntry{ sn:"X500", ln:"X500", nid:Nid::X500, oid:OBJ_X500 },
    OidEntry{ sn:"X509", ln:"X509", nid:Nid::X509, oid:OBJ_X509 },
    OidEntry{ sn:"CN", ln:"commonName", nid:Nid::CommonName, oid:OBJ_CN },
    OidEntry{ sn:"C", ln:"countryName", nid:Nid::CountryName, oid:OBJ_C },
    OidEntry{ sn:"L", ln:"localityName", nid:Nid::LocalityName, oid:OBJ_L },
    OidEntry{ sn:"ST", ln:"stateOrProvinceName", nid:Nid::StateOrProvinceName, oid:OBJ_ST },
    OidEntry{ sn:"O", ln:"organizationName", nid:Nid::OrganizationName, oid:OBJ_O },
    OidEntry{ sn:"OU", ln:"organizationalUnitName", nid:Nid::OrganizationalUnitName, oid:OBJ_OU },

    OidEntry{ sn:"pkcs9", ln:"pkcs9", nid:Nid::Pkcs9, oid:OBJ_PKCS9 },
    OidEntry{ sn:"Email", ln:"emailAddress", nid:Nid::EmailAddress, oid:OBJ_EMAIL },

    OidEntry{ sn:"RSA-ENC", ln:"rsaEncryption", nid:Nid::RsaEncryption, oid:OBJ_RSAENCRYPTION },
    OidEntry{ sn:"RSA-SHA1", ln:"sha1WithRSAEncryption", nid:Nid::RsaSha1, oid:OBJ_RSASHA1 },

    OidEntry{ sn:"subjectKeyIdentifier", ln:"X509v3 Subject Key Identifier", nid:Nid::SubjectKeyIdentifier, oid:OBJ_SKI },
    OidEntry{ sn:"keyUsage", ln:"X509v3 Key Usage", nid:Nid::KeyUsage, oid:OBJ_KU },
    OidEntry{ sn:"privateKeyUsagePeriod", ln:"X509v3 Private Key Usage Period", nid:Nid::PrivateKeyUsagePeriod, oid:OBJ_PKUP },
    OidEntry{ sn:"subjectAltName", ln:"X509v3 Subject Alternative Name", nid:Nid::SubjectAltName, oid:OBJ_SAN },

    OidEntry{ sn:"basicConstraints", ln:"X509v3 Basic Constraints", nid:Nid::BasicConstraints, oid:OBJ_BC },

    OidEntry{ sn:"certificatePolicies", ln:"X509v3 Certificate Policies", nid:Nid::CertificatePolicies, oid:OBJ_CPOL },
    OidEntry{ sn:"authorityKeyIdentifier", ln:"X509v3 Authority Key Identifier", nid:Nid::AuthorityKeyIdentifier, oid:OBJ_AKI },
];


/// Returns the short name corresponding to the Nid
pub fn nid2sn(nid: Nid) -> Result<&'static str,NidError> {
    // XXX pattern matching would be faster, but harder to maintain
    OID_REGISTRY
        .iter()
        .find(|ref o| o.nid == nid)
        .map(|ref o| o.sn)
        .ok_or(NidError)
}

/// Returns the long name corresponding to the Nid
pub fn nid2ln(nid: Nid) -> Result<&'static str,NidError> {
    // XXX pattern matching would be faster, but harder to maintain
    OID_REGISTRY
        .iter()
        .find(|ref o| o.nid == nid)
        .map(|ref o| o.ln)
        .ok_or(NidError)
}


pub fn nid2obj(nid: &Nid) -> Result<Oid,NidError> {
    OID_REGISTRY
        .iter()
        .find(|ref o| o.nid == *nid)
        .map(|ref o| Oid::from(o.oid))
        .ok_or(NidError)
    // XXX pattern matching would be faster, but harder to maintain
    // match nid {
    //     &Nid::RsaDsi => Ok(Oid::from(OBJ_RSADSI)),
    //     &Nid::RsaSha1 => Ok(Oid::from(OBJ_RSASHA1)),
    //     _ => Err(NidError),
    // }
}

pub fn oid2nid(obj: &Oid) -> Result<Nid,NidError> {
    // XXX could be faster by matching on known prefixes to filter subtree
    // true if obj starts with OBJ_RSADSI
    // let x = obj.iter().zip(OBJ_RSADSI).all(|(a,b)| a == b);

    // true if obj and OBJ_RSADSI are entirely equal
    // // or
    // if obj.iter().eq(OBJ_RSADSI) { return Ok(Nid::RsaDsi); }

    // if obj.iter().eq(OBJ_RSASHA1) { return Ok(Nid::RsaSha1); }

    // Err(NidError)
    OID_REGISTRY
        .iter()
        .find(|ref o| obj.iter().eq(o.oid.iter()))
        .map(|ref o| o.nid)
        .ok_or(NidError)
}

/// Returns the short name corresponding to the OID
pub fn oid2sn(obj: &Oid) -> Result<&'static str,NidError> {
    // XXX pattern matching would be faster, but harder to maintain
    OID_REGISTRY
        .iter()
        .find(|ref o| obj.iter().eq(o.oid.iter()))
        .map(|ref o| o.sn)
        .ok_or(NidError)
}

/// Given a short name, returns the matching OID
pub fn sn2oid(sn: &str) -> Result<Oid, NidError> {
    // XXX pattern matching would be faster, but harder to maintain
    OID_REGISTRY
        .iter()
        .find(|ref o| o.sn == sn)
        .map(|ref o| Oid::from(o.oid))
        .ok_or(NidError)
}


#[cfg(test)]
mod tests {
    use objects::*;
    use der_parser::oid::Oid;

#[test]
fn test_obj2nid() {
    let oid = Oid::from(&[1, 2, 840, 113549, 1, 1, 5]);
    assert_eq!(oid2nid(&oid), Ok(Nid::RsaSha1));

    let invalid_oid = Oid::from(&[5, 4, 3, 2, 1]);
    assert_eq!(oid2nid(&invalid_oid), Err(NidError));
}

#[test]
fn test_nid2sn() {
    assert_eq!(nid2sn(Nid::Undef), Ok("UNDEF"));
    assert_eq!(nid2sn(Nid::RsaSha1), Ok("RSA-SHA1"));
}

#[test]
fn test_sn2oid() {
    let oid = Oid::from(&[1, 2, 840, 113549, 1, 1, 5]);
    assert_eq!(sn2oid("RSA-SHA1"), Ok(oid));
    assert_eq!(sn2oid("invalid sn"), Err(NidError));
}

}
