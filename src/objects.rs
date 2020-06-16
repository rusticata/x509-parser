//! X.509 helper objects definitions: OID, short and long names, NID (internal ID)
//!
//! Most definitions taken from OpenSSL: /usr/include/openssl/objects.h
//! Note: values does not match openssl, for ex. NIDs
//!
//! Note: the objects registry is implemented as a static array with linear search. This is not the
//! most efficient method, but makes maintainance easier.

use crate::error::NidError;
use der_parser::{oid, oid::Oid};
use lazy_static::lazy_static;
use std::collections::HashMap;

/// ASN.1 node internal identifier
///
/// This enumeration lists the node IDs used (and/or supported) in X.509 certificates.
/// It is not guaranteed to be exhaustive.
#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum Nid {
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
    NameConstraints,
    CertificatePolicies,
    PolicyMappings,
    AuthorityKeyIdentifier,
    PolicyConstraints,
    ExtendedKeyUsage,
    InhibitAnyPolicy,
}

struct OidEntry {
    sn: &'static str,
    ln: &'static str,
    nid: Nid,
}

const OID_ALGO: Oid<'static> = oid!(1.3.14.3.2);
const OID_RSADSI: Oid<'static> = oid!(1.2.840.113549);
const OID_X500: Oid<'static> = oid!(2.5);
const OID_X509: Oid<'static> = oid!(2.5.4);
const OID_CN: Oid<'static> = oid!(2.5.4.3);
const OID_C: Oid<'static> = oid!(2.5.4.6);
const OID_L: Oid<'static> = oid!(2.5.4.7);
const OID_ST: Oid<'static> = oid!(2.5.4.8);
const OID_O: Oid<'static> = oid!(2.5.4.10);
const OID_OU: Oid<'static> = oid!(2.5.4.11);

const OID_PKCS9: Oid<'static> = oid!(1.2.840.113549.1.9);
const OID_EMAIL: Oid<'static> = oid!(1.2.840.113549.1.9.1);

// XXX ...

const OID_RSAENCRYPTION: Oid<'static> = oid!(1.2.840.113549.1.1.1);
const OID_RSASHA1: Oid<'static> = oid!(1.2.840.113549.1.1.5);

// certificateExtension (2.5.29)

const OID_EXT_SUBJECTKEYIDENTIFIER: Oid<'static> = oid!(2.5.29.14);
const OID_EXT_SKI: Oid<'static> = OID_EXT_SUBJECTKEYIDENTIFIER;
const OID_EXT_KEYUSAGE: Oid<'static> = oid!(2.5.29.15);
const OID_EXT_KU: Oid<'static> = OID_EXT_KEYUSAGE;
const OID_EXT_PRIVATEKEYUSAGEPERIOD: Oid<'static> = oid!(2.5.29.16);
const OID_EXT_PKUP: Oid<'static> = OID_EXT_PRIVATEKEYUSAGEPERIOD;
const OID_EXT_SUBJECTALTNAME: Oid<'static> = oid!(2.5.29.17);
const OID_EXT_SAN: Oid<'static> = OID_EXT_SUBJECTALTNAME;
const OID_EXT_BASICCONSTRAINTS: Oid<'static> = oid!(2.5.29.19);
const OID_EXT_BC: Oid<'static> = OID_EXT_BASICCONSTRAINTS;
const OID_EXT_NAMECONSTRAINTS: Oid<'static> = oid!(2.5.29.30);
const OID_EXT_CERTIFICATEPOLICIES: Oid<'static> = oid!(2.5.29.32);
const OID_EXT_CPOL: Oid<'static> = OID_EXT_CERTIFICATEPOLICIES;
const OID_EXT_POLICYMAPPINGS: Oid<'static> = oid!(2.5.29.33);
const OID_EXT_AUTHORITYKEYIDENTIFIER: Oid<'static> = oid!(2.5.29.35);
const OID_EXT_AKI: Oid<'static> = OID_EXT_AUTHORITYKEYIDENTIFIER;
const OID_EXT_POLICYCONSTRAINTS: Oid<'static> = oid!(2.5.29.36);
const OID_EXT_EXTENDEDKEYUSAGE: Oid<'static> = oid!(2.5.29.37);
const OID_EXT_EKU: Oid<'static> = OID_EXT_EXTENDEDKEYUSAGE;
const OID_EXT_INHIBITANYPOLICY: Oid<'static> = oid!(2.5.29.54);

lazy_static! {
    static ref OID_REGISTRY: HashMap<Oid<'static>, OidEntry> = {
        let mut m = HashMap::new();
        m.insert(oid!(0), OidEntry {sn: "UNDEF", ln: "undefined", nid: Nid::Undef});
        m.insert(OID_ALGO, OidEntry {sn: "Algorithm", ln: "algorithm", nid: Nid::Algorithm});
        m.insert(OID_RSADSI, OidEntry{sn:"rsadsi", ln:"rsadsi", nid:Nid::RsaDsi});
        m.insert(OID_X500, OidEntry{sn:"X500", ln:"X500", nid:Nid::X500});
        m.insert(OID_X509, OidEntry{sn:"X509", ln:"X509", nid:Nid::X509});
        m.insert(OID_CN, OidEntry{sn:"CN", ln:"commonName", nid:Nid::CommonName});
        m.insert(OID_C, OidEntry{sn:"C", ln:"countryName", nid:Nid::CountryName});
        m.insert(OID_L, OidEntry{sn:"L", ln:"localityName", nid:Nid::LocalityName});
        m.insert(OID_ST, OidEntry{sn:"ST", ln:"stateOrProvinceName", nid:Nid::StateOrProvinceName});
        m.insert(OID_O, OidEntry{sn:"O", ln:"organizationName", nid:Nid::OrganizationName});
        m.insert(OID_OU, OidEntry{sn:"OU", ln:"organizationalUnitName", nid:Nid::OrganizationalUnitName});
        //
        m.insert(OID_PKCS9, OidEntry{sn:"pkcs9", ln:"pkcs9", nid:Nid::Pkcs9});
        m.insert(OID_EMAIL, OidEntry{sn:"Email", ln:"emailAddress", nid:Nid::EmailAddress});
        //
        m.insert(OID_RSAENCRYPTION, OidEntry{sn:"RSA-ENC", ln:"rsaEncryption", nid:Nid::RsaEncryption});
        m.insert(OID_RSASHA1, OidEntry{sn:"RSA-SHA1", ln:"sha1WithRSAEncryption", nid:Nid::RsaSha1});
        //
        // extensions
        m.insert(OID_EXT_SKI, OidEntry{sn:"subjectKeyIdentifier", ln:"X509v3 Subject Key Identifier", nid:Nid::SubjectKeyIdentifier});
        m.insert(OID_EXT_KU, OidEntry{sn:"keyUsage", ln:"X509v3 Key Usage", nid:Nid::KeyUsage});
        m.insert(OID_EXT_PKUP, OidEntry{sn:"privateKeyUsagePeriod", ln:"X509v3 Private Key Usage Period", nid:Nid::PrivateKeyUsagePeriod});
        m.insert(OID_EXT_SAN, OidEntry{sn:"subjectAltName", ln:"X509v3 Subject Alternative Name", nid:Nid::SubjectAltName});
        //
        m.insert(OID_EXT_BC, OidEntry{sn:"basicConstraints", ln:"X509v3 Basic Constraints", nid:Nid::BasicConstraints});
        m.insert(OID_EXT_NAMECONSTRAINTS, OidEntry{sn:"nameConstraints", ln:"X509v3 Name Constraints", nid:Nid::NameConstraints});
        //
        m.insert(OID_EXT_CPOL, OidEntry{sn:"certificatePolicies", ln:"X509v3 Certificate Policies", nid:Nid::CertificatePolicies});
        m.insert(OID_EXT_POLICYMAPPINGS, OidEntry{sn:"policyMappings", ln:"X509v3 Policy Mappings", nid:Nid::PolicyMappings});
        m.insert(OID_EXT_AKI, OidEntry{sn:"authorityKeyIdentifier", ln:"X509v3 Authority Key Identifier", nid:Nid::AuthorityKeyIdentifier});
        m.insert(OID_EXT_POLICYCONSTRAINTS, OidEntry{sn:"policyConstraints", ln:"X509v3 Policy Constraints", nid:Nid::PolicyConstraints});
        m.insert(OID_EXT_EKU, OidEntry{sn:"extendedKeyUsage", ln:"X509v3 Extended Key Usage", nid:Nid::ExtendedKeyUsage});
        m.insert(OID_EXT_INHIBITANYPOLICY, OidEntry{sn:"inhibitAnyPolicy", ln:"X509v3 Inhibit Any-Policy", nid:Nid::InhibitAnyPolicy});
        m
    };
}

/// Returns the short name corresponding to the Nid
pub fn nid2sn(nid: Nid) -> Result<&'static str, NidError> {
    OID_REGISTRY
        .values()
        .find(|o| o.nid == nid)
        .map(|o| o.sn)
        .ok_or(NidError)
}

/// Returns the long name corresponding to the Nid
pub fn nid2ln(nid: Nid) -> Result<&'static str, NidError> {
    OID_REGISTRY
        .values()
        .find(|o| o.nid == nid)
        .map(|o| o.ln)
        .ok_or(NidError)
}

pub fn nid2obj(nid: Nid) -> Result<&'static Oid<'static>, NidError> {
    OID_REGISTRY
        .iter()
        .find(|(_, o)| o.nid == nid)
        .map(|(oid, _)| oid)
        .ok_or(NidError)
}

pub fn oid2nid(oid: &Oid) -> Result<Nid, NidError> {
    OID_REGISTRY.get(oid).map(|ref o| o.nid).ok_or(NidError)
}

/// Returns the short name corresponding to the OID
pub fn oid2sn(oid: &Oid) -> Result<&'static str, NidError> {
    OID_REGISTRY.get(oid).map(|ref o| o.sn).ok_or(NidError)
}

/// Given a short name, returns the matching OID
pub fn sn2oid(sn: &str) -> Result<&Oid, NidError> {
    OID_REGISTRY
        .iter()
        .find(|(_, o)| o.sn == sn)
        .map(|(oid, _)| oid)
        .ok_or(NidError)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(sn2oid("RSA-SHA1"), Ok(&oid));
        assert_eq!(sn2oid("invalid sn"), Err(NidError));
    }
}
