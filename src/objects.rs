//! X.509 helper objects definitions: OID, short and long names, NID (internal ID)
//!
//! Most definitions taken from OpenSSL: /usr/include/openssl/objects.h
//! Note: values does not match openssl, for ex. NIDs
//!
//! Note: the objects registry is implemented as a static array with linear search. This is not the
//! most efficient method, but makes maintainance easier.
use std::borrow::Cow;

use der_parser::{oid, oid::Oid};

use crate::error::NidError;

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

const OBJ_ALGO : &[u8]    = &oid!(raw 1.3.14.3.2);
const OBJ_RSADSI : &[u8]  = &oid!(raw 1.2.840.113549);
const OBJ_X500 : &[u8]    = &oid!(raw 2.5);
const OBJ_X509 : &[u8]    = &oid!(raw 2.5.4);
const OBJ_CN : &[u8]      = &oid!(raw 2.5.4.3);
const OBJ_C : &[u8]       = &oid!(raw 2.5.4.6);
const OBJ_L : &[u8]       = &oid!(raw 2.5.4.7);
const OBJ_ST : &[u8]      = &oid!(raw 2.5.4.8);
const OBJ_O : &[u8]       = &oid!(raw 2.5.4.10);
const OBJ_OU : &[u8]      = &oid!(raw 2.5.4.11);

const OBJ_PKCS9 : &[u8]   = &oid!(raw 1.2.840.113549.1.9);
const OBJ_EMAIL : &[u8]   = &oid!(raw 1.2.840.113549.1.9.1);

// XXX ...

const OBJ_RSAENCRYPTION : &[u8] = &oid!(raw 1.2.840.113549.1.1.1);
const OBJ_RSASHA1 : &[u8]       = &oid!(raw 1.2.840.113549.1.1.5);

// other constants

const OBJ_SKI : &[u8]     = &oid!(raw 2.5.29.14);
const OBJ_KU : &[u8]      = &oid!(raw 2.5.29.15);
const OBJ_PKUP : &[u8]    = &oid!(raw 2.5.29.16);
const OBJ_SAN : &[u8]     = &oid!(raw 2.5.29.17);

const OBJ_BC : &[u8]      = &oid!(raw 2.5.29.19);

const OBJ_CPOL : &[u8]    = &oid!(raw 2.5.29.32);

const OBJ_AKI : &[u8]     = &oid!(raw 2.5.29.35);

// Extension constants

pub const OID_EXT_KEYUSAGE: &[u8] = &oid!(raw 2.5.29.15);
pub const OID_EXT_SUBJALTNAME: &[u8] = &oid!(raw 2.5.29.17);
pub const OID_EXT_BASICCONSTRAINTS: &[u8] = &oid!(raw 2.5.29.19);
pub const OID_EXT_NAMECONSTRAINTS: &[u8] = &oid!(raw 2.5.29.30);
pub const OID_EXT_CERTIFICATEPOLICIES: &[u8] = &oid!(raw 2.5.29.32);
pub const OID_EXT_POLICYMAPPINGS: &[u8] = &oid!(raw 2.5.29.33);
pub const OID_EXT_POLICYCONSTRAINTS: &[u8] = &oid!(raw 2.5.29.36);
pub const OID_EXT_EXTENDEDKEYUSAGE: &[u8] = &oid!(raw 2.5.29.37);
pub const OID_EXT_INHIBITANYPLICY: &[u8] = &oid!(raw 2.5.29.54);


struct OidEntry {
    sn: &'static str,
    ln: &'static str,
    nid: Nid,
    oid: &'static [u8],
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
        .map(|ref o| Oid::new(Cow::Borrowed(o.oid)))
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
        .find(|ref o| obj == &Oid::new(Cow::Borrowed(o.oid)))
        .map(|ref o| o.nid)
        .ok_or(NidError)
}

/// Returns the short name corresponding to the OID
pub fn oid2sn(obj: &Oid) -> Result<&'static str,NidError> {
    // XXX pattern matching would be faster, but harder to maintain
    OID_REGISTRY
        .iter()
        .find(|ref o| obj == &Oid::new(Cow::Borrowed(o.oid)))
        .map(|ref o| o.sn)
        .ok_or(NidError)
}

/// Given a short name, returns the matching OID
pub fn sn2oid(sn: &str) -> Result<Oid, NidError> {
    // XXX pattern matching would be faster, but harder to maintain
    OID_REGISTRY
        .iter()
        .find(|ref o| o.sn == sn)
        .map(|ref o| Oid::new(Cow::Borrowed(o.oid)))
        .ok_or(NidError)
}


#[cfg(test)]
mod tests {
    use der_parser::oid;
    use crate::objects::*;

#[test]
fn test_obj2nid() {
    let oid = oid!(1.2.840.113549.1.1.5);
    assert_eq!(oid2nid(&oid), Ok(Nid::RsaSha1));

    let invalid_oid = oid!(5.4.3.2.1);
    assert_eq!(oid2nid(&invalid_oid), Err(NidError));
}

#[test]
fn test_nid2sn() {
    assert_eq!(nid2sn(Nid::Undef), Ok("UNDEF"));
    assert_eq!(nid2sn(Nid::RsaSha1), Ok("RSA-SHA1"));
}

#[test]
fn test_sn2oid() {
    let oid = oid!(1.2.840.113549.1.1.5);
    assert_eq!(sn2oid("RSA-SHA1"), Ok(oid));
    assert_eq!(sn2oid("invalid sn"), Err(NidError));
}

}
