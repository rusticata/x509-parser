#![cfg(any(
    feature = "verify",
    feature = "verify-aws",
    feature = "verify-rustcrypto"
))]

use x509_parser::parse_x509_certificate;

static CA_DER: &[u8] = include_bytes!("../assets/IGC_A.der");
static CA_LETSENCRYPT_X3: &[u8] = include_bytes!("../assets/lets-encrypt-x3-cross-signed.der");
static CERT_DER: &[u8] = include_bytes!("../assets/certificate.der");

#[test]
fn test_signature_verification() {
    // for a root CA, verify self-signature
    let (_, x509_ca) = parse_x509_certificate(CA_DER).expect("could not parse certificate");
    let res = x509_ca.verify_signature(None);
    eprintln!("Verification: {res:?}");
    assert!(res.is_ok());

    // for a standard certificate, first load the authority, then the certificate, and verify it
    let (_, x509_ca) =
        parse_x509_certificate(CA_LETSENCRYPT_X3).expect("could not parse certificate");
    let (_, x509_cert) = parse_x509_certificate(CERT_DER).expect("could not parse certificate");
    let res = x509_cert.verify_signature(Some(&x509_ca.tbs_certificate.subject_pki));
    eprintln!("Verification: {res:?}");
    assert!(res.is_ok());
}

static ED25519_DER: &[u8] = include_bytes!("../assets/ed25519.der");

#[test]
fn test_signature_verification_ed25519() {
    // this certificate is self-signed
    let (_, x509_ca) = parse_x509_certificate(ED25519_DER).expect("could not parse certificate");
    let res = x509_ca.verify_signature(None);
    eprintln!("Verification: {res:?}");
    assert!(res.is_ok());
}

static ECDSA_P256_SHA256_DER: &[u8] = include_bytes!("../assets/ecdsa_p256_sha256.der");
static ECDSA_P256_SHA384_DER: &[u8] = include_bytes!("../assets/ecdsa_p256_sha384.der");
static ECDSA_P384_SHA256_DER: &[u8] = include_bytes!("../assets/ecdsa_p384_sha256.der");
static ECDSA_P384_SHA384_DER: &[u8] = include_bytes!("../assets/ecdsa_p384_sha384.der");

#[test]
fn test_signature_verification_ecdsa_p256_sha256() {
    let (_, x509) =
        parse_x509_certificate(ECDSA_P256_SHA256_DER).expect("could not parse certificate");
    let res = x509.verify_signature(None);
    eprintln!("Verification: {res:?}");
    assert!(res.is_ok());
}

#[test]
fn test_signature_verification_ecdsa_p384_sha384() {
    let (_, x509) =
        parse_x509_certificate(ECDSA_P384_SHA384_DER).expect("could not parse certificate");
    let res = x509.verify_signature(None);
    eprintln!("Verification: {res:?}");
    assert!(res.is_ok());
}

#[test]
fn test_signature_verification_ecdsa_p256_sha384() {
    let (_, x509) =
        parse_x509_certificate(ECDSA_P256_SHA384_DER).expect("could not parse certificate");
    let res = x509.verify_signature(None);
    eprintln!("Verification: {res:?}");
    assert!(res.is_ok());
}

#[test]
fn test_signature_verification_ecdsa_p384_sha256() {
    let (_, x509) =
        parse_x509_certificate(ECDSA_P384_SHA256_DER).expect("could not parse certificate");
    let res = x509.verify_signature(None);
    eprintln!("Verification: {res:?}");
    assert!(res.is_ok());
}

static RSA_PSS_SELF_SIGNED_SHA256: &[u8] =
    include_bytes!("../assets/rsa-pss/self_signed_sha256.der");
static RSA_PSS_SELF_SIGNED_SHA384: &[u8] =
    include_bytes!("../assets/rsa-pss/self_signed_sha384.der");
static RSA_PSS_SELF_SIGNED_SHA512: &[u8] =
    include_bytes!("../assets/rsa-pss/self_signed_sha512.der");
#[cfg(all(
    feature = "verify-rustcrypto",
    not(feature = "verify"),
    not(feature = "verify-aws")
))]
static RSA_PSS_SELF_SIGNED_SHA256_SALTLEN42: &[u8] =
    include_bytes!("../assets/rsa-pss/self_signed_sha256_saltlen42.der");

#[test]
fn test_signature_verification_rsa_pss_sha256() {
    let (_, x509) =
        parse_x509_certificate(RSA_PSS_SELF_SIGNED_SHA256).expect("could not parse certificate");
    let res = x509.verify_signature(None);
    eprintln!("Verification: {res:?}");
    assert!(res.is_ok());
}

#[test]
fn test_signature_verification_rsa_pss_sha384() {
    let (_, x509) =
        parse_x509_certificate(RSA_PSS_SELF_SIGNED_SHA384).expect("could not parse certificate");
    let res = x509.verify_signature(None);
    eprintln!("Verification: {res:?}");
    assert!(res.is_ok());
}

#[test]
fn test_signature_verification_rsa_pss_sha512() {
    let (_, x509) =
        parse_x509_certificate(RSA_PSS_SELF_SIGNED_SHA512).expect("could not parse certificate");
    let res = x509.verify_signature(None);
    eprintln!("Verification: {res:?}");
    assert!(res.is_ok());
}

/// This test exercises non-default PSS salt length (42 bytes instead of hash-length 32).
/// Only the RustCrypto backend honors the full RSASSA-PSS-params including salt length;
/// ring and aws-lc-rs use fixed params (salt_len = hash_len) that cannot represent this.
#[cfg(all(
    feature = "verify-rustcrypto",
    not(feature = "verify"),
    not(feature = "verify-aws")
))]
#[test]
fn test_signature_verification_rsa_pss_custom_salt_len() {
    let (_, x509) = parse_x509_certificate(RSA_PSS_SELF_SIGNED_SHA256_SALTLEN42)
        .expect("could not parse certificate");
    let res = x509.verify_signature(None);
    eprintln!("Verification: {res:?}");
    assert!(res.is_ok());
}
