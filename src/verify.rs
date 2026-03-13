use crate::prelude::*;
use crate::signature_algorithm::RsaSsaPssParams;
use asn1_rs::{Any, BitString};
use oid_registry::{
    OID_EC_P256, OID_NIST_EC_P384, OID_NIST_HASH_SHA256, OID_NIST_HASH_SHA384,
    OID_NIST_HASH_SHA512, OID_PKCS1_RSASSAPSS, OID_PKCS1_SHA1WITHRSA, OID_PKCS1_SHA256WITHRSA,
    OID_PKCS1_SHA384WITHRSA, OID_PKCS1_SHA512WITHRSA, OID_SHA1_WITH_RSA, OID_SIG_ECDSA_WITH_SHA256,
    OID_SIG_ECDSA_WITH_SHA384, OID_SIG_ED25519,
};
use std::convert::TryFrom;

// ---- Ring / aws-lc-rs backend ----

// Since the `signature` object is similar in ring and in aws-lc-rs, we just use simple logic
// to determine which one to use.
// If both verify and verify-aws features are enabled, aws will be used.
#[cfg(feature = "verify-aws")]
use aws_lc_rs::signature;
#[cfg(all(feature = "verify", not(feature = "verify-aws")))]
use ring::signature;

/// Verify the cryptographic signature of the raw data (can be a certificate, a CRL or a CSR).
///
/// `public_key` is the public key of the **signer**.
///
/// Not all algorithms are supported, this function is limited to what `aws_lc_rs` or `ring` supports.
#[cfg(any(feature = "verify-aws", feature = "verify"))]
pub fn verify_signature(
    public_key: &SubjectPublicKeyInfo,
    signature_algorithm: &AlgorithmIdentifier,
    signature_value: &BitString,
    raw_data: &[u8],
) -> Result<(), X509Error> {
    let AlgorithmIdentifier {
        algorithm: signature_algorithm,
        parameters: signature_algorithm_parameters,
    } = &signature_algorithm;

    // identify verification algorithm
    let verification_alg: &dyn signature::VerificationAlgorithm = if *signature_algorithm
        == OID_PKCS1_SHA1WITHRSA
        || *signature_algorithm == OID_SHA1_WITH_RSA
    {
        &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
    } else if *signature_algorithm == OID_PKCS1_SHA256WITHRSA {
        &signature::RSA_PKCS1_2048_8192_SHA256
    } else if *signature_algorithm == OID_PKCS1_SHA384WITHRSA {
        &signature::RSA_PKCS1_2048_8192_SHA384
    } else if *signature_algorithm == OID_PKCS1_SHA512WITHRSA {
        &signature::RSA_PKCS1_2048_8192_SHA512
    } else if *signature_algorithm == OID_PKCS1_RSASSAPSS {
        get_rsa_pss_verification_algo(signature_algorithm_parameters)
            .ok_or(X509Error::SignatureUnsupportedAlgorithm)?
    } else if *signature_algorithm == OID_SIG_ECDSA_WITH_SHA256 {
        get_ec_curve_sha(&public_key.algorithm, 256)
            .ok_or(X509Error::SignatureUnsupportedAlgorithm)?
    } else if *signature_algorithm == OID_SIG_ECDSA_WITH_SHA384 {
        get_ec_curve_sha(&public_key.algorithm, 384)
            .ok_or(X509Error::SignatureUnsupportedAlgorithm)?
    } else if *signature_algorithm == OID_SIG_ED25519 {
        &signature::ED25519
    } else {
        return Err(X509Error::SignatureUnsupportedAlgorithm);
    };
    // get public key
    let key =
        signature::UnparsedPublicKey::new(verification_alg, &public_key.subject_public_key.data);
    // verify signature
    key.verify(raw_data, &signature_value.data)
        .or(Err(X509Error::SignatureVerificationError))
}

/// Find the verification algorithm for the given EC curve and SHA digest size
///
/// Not all algorithms are supported, we are limited to what `aws_lc_rs`  or `ring`supports.
#[cfg(any(feature = "verify-aws", feature = "verify"))]
fn get_ec_curve_sha(
    pubkey_alg: &AlgorithmIdentifier,
    sha_len: usize,
) -> Option<&'static dyn signature::VerificationAlgorithm> {
    let curve_oid = pubkey_alg.parameters.as_ref()?.as_oid().ok()?;
    // let curve_oid = pubkey_alg.parameters.as_ref()?.as_oid().ok()?;
    if curve_oid == OID_EC_P256 {
        match sha_len {
            256 => Some(&signature::ECDSA_P256_SHA256_ASN1),
            384 => Some(&signature::ECDSA_P256_SHA384_ASN1),
            _ => None,
        }
    } else if curve_oid == OID_NIST_EC_P384 {
        match sha_len {
            256 => Some(&signature::ECDSA_P384_SHA256_ASN1),
            384 => Some(&signature::ECDSA_P384_SHA384_ASN1),
            _ => None,
        }
    } else {
        None
    }
}

/// Find the verification algorithm for the given RSA-PSS parameters
///
/// Not all algorithms are supported, we are limited to what `aws_lc_rs` or `ring` supports.
/// Notably, the SHA-1 hash algorithm is not supported.
#[cfg(any(feature = "verify-aws", feature = "verify"))]
fn get_rsa_pss_verification_algo(
    params: &Option<Any>,
) -> Option<&'static dyn signature::VerificationAlgorithm> {
    let params = params.as_ref()?;
    let params = RsaSsaPssParams::try_from(params).ok()?;
    let hash_algo = params.hash_algorithm_oid();

    if *hash_algo == OID_NIST_HASH_SHA256 {
        Some(&signature::RSA_PSS_2048_8192_SHA256)
    } else if *hash_algo == OID_NIST_HASH_SHA384 {
        Some(&signature::RSA_PSS_2048_8192_SHA384)
    } else if *hash_algo == OID_NIST_HASH_SHA512 {
        Some(&signature::RSA_PSS_2048_8192_SHA512)
    } else {
        None
    }
}

// ---- RustCrypto backend ----

/// Verify the cryptographic signature of the raw data (can be a certificate, a CRL or a CSR).
///
/// `public_key` is the public key of the **signer**.
///
/// Not all algorithms are supported, this function is limited to what the RustCrypto crates support.
#[cfg(all(
    feature = "verify-rustcrypto",
    not(feature = "verify"),
    not(feature = "verify-aws")
))]
pub fn verify_signature(
    public_key: &SubjectPublicKeyInfo,
    signature_algorithm: &AlgorithmIdentifier,
    signature_value: &BitString,
    raw_data: &[u8],
) -> Result<(), X509Error> {
    let AlgorithmIdentifier {
        algorithm: sig_alg,
        parameters: sig_params,
    } = &signature_algorithm;

    let key_bytes: &[u8] = public_key.subject_public_key.as_ref();
    let sig_bytes: &[u8] = signature_value.as_ref();

    if *sig_alg == OID_PKCS1_SHA1WITHRSA || *sig_alg == OID_SHA1_WITH_RSA {
        rc_verify_rsa_pkcs1v15::<sha1::Sha1>(key_bytes, sig_bytes, raw_data)
    } else if *sig_alg == OID_PKCS1_SHA256WITHRSA {
        rc_verify_rsa_pkcs1v15::<sha2::Sha256>(key_bytes, sig_bytes, raw_data)
    } else if *sig_alg == OID_PKCS1_SHA384WITHRSA {
        rc_verify_rsa_pkcs1v15::<sha2::Sha384>(key_bytes, sig_bytes, raw_data)
    } else if *sig_alg == OID_PKCS1_SHA512WITHRSA {
        rc_verify_rsa_pkcs1v15::<sha2::Sha512>(key_bytes, sig_bytes, raw_data)
    } else if *sig_alg == OID_PKCS1_RSASSAPSS {
        rc_verify_rsa_pss(key_bytes, sig_params, sig_bytes, raw_data)
    } else if *sig_alg == OID_SIG_ECDSA_WITH_SHA256 {
        rc_verify_ecdsa(&public_key.algorithm, key_bytes, sig_bytes, raw_data, 256)
    } else if *sig_alg == OID_SIG_ECDSA_WITH_SHA384 {
        rc_verify_ecdsa(&public_key.algorithm, key_bytes, sig_bytes, raw_data, 384)
    } else if *sig_alg == OID_SIG_ED25519 {
        rc_verify_ed25519(key_bytes, sig_bytes, raw_data)
    } else {
        Err(X509Error::SignatureUnsupportedAlgorithm)
    }
}

#[cfg(all(
    feature = "verify-rustcrypto",
    not(feature = "verify"),
    not(feature = "verify-aws")
))]
fn rc_verify_rsa_pkcs1v15<D>(
    key_bytes: &[u8],
    sig_bytes: &[u8],
    data: &[u8],
) -> Result<(), X509Error>
where
    D: sha2::digest::Digest + sha2::digest::const_oid::AssociatedOid,
{
    use core::convert::TryFrom;
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::signature::Verifier;

    let rsa_key = rsa::RsaPublicKey::from_pkcs1_der(key_bytes)
        .map_err(|_| X509Error::SignatureVerificationError)?;
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<D>::new(rsa_key);
    let sig = rsa::pkcs1v15::Signature::try_from(sig_bytes)
        .map_err(|_| X509Error::SignatureVerificationError)?;
    verifying_key
        .verify(data, &sig)
        .map_err(|_| X509Error::SignatureVerificationError)
}

/// Verify an RSA-PSS signature using RustCrypto.
///
/// Validates the full RSASSA-PSS-params: hash algorithm, mask generation algorithm,
/// salt length, and trailer field. The SHA-1 hash algorithm is not supported.
#[cfg(all(
    feature = "verify-rustcrypto",
    not(feature = "verify"),
    not(feature = "verify-aws")
))]
fn rc_verify_rsa_pss(
    key_bytes: &[u8],
    params: &Option<Any>,
    sig_bytes: &[u8],
    data: &[u8],
) -> Result<(), X509Error> {
    let params = params
        .as_ref()
        .ok_or(X509Error::SignatureUnsupportedAlgorithm)?;
    let params =
        RsaSsaPssParams::try_from(params).map_err(|_| X509Error::SignatureUnsupportedAlgorithm)?;

    // RFC 4055: trailerField must be 1
    if params.trailer_field() != 1 {
        return Err(X509Error::SignatureUnsupportedAlgorithm);
    }

    let hash_oid = params.hash_algorithm_oid();

    // Validate that the MGF1 hash matches the signature hash.
    // The rsa crate uses the same digest for both, so we must reject mismatches.
    let mgf = params
        .mask_gen_algorithm()
        .map_err(|_| X509Error::SignatureUnsupportedAlgorithm)?;
    // id-mgf1 OID: 1.2.840.113549.1.1.8
    if mgf.mgf != asn1_rs::oid!(1.2.840 .113549 .1 .1 .8) {
        return Err(X509Error::SignatureUnsupportedAlgorithm);
    }
    if mgf.hash != *hash_oid {
        return Err(X509Error::SignatureUnsupportedAlgorithm);
    }

    let salt_len = params.salt_length() as usize;

    if *hash_oid == OID_NIST_HASH_SHA256 {
        rc_verify_rsa_pss_with_hash::<sha2::Sha256>(key_bytes, sig_bytes, data, salt_len)
    } else if *hash_oid == OID_NIST_HASH_SHA384 {
        rc_verify_rsa_pss_with_hash::<sha2::Sha384>(key_bytes, sig_bytes, data, salt_len)
    } else if *hash_oid == OID_NIST_HASH_SHA512 {
        rc_verify_rsa_pss_with_hash::<sha2::Sha512>(key_bytes, sig_bytes, data, salt_len)
    } else {
        Err(X509Error::SignatureUnsupportedAlgorithm)
    }
}

#[cfg(all(
    feature = "verify-rustcrypto",
    not(feature = "verify"),
    not(feature = "verify-aws")
))]
fn rc_verify_rsa_pss_with_hash<D>(
    key_bytes: &[u8],
    sig_bytes: &[u8],
    data: &[u8],
    salt_len: usize,
) -> Result<(), X509Error>
where
    D: sha2::digest::Digest + sha2::digest::FixedOutputReset,
{
    use core::convert::TryFrom;
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::signature::Verifier;

    let rsa_key = rsa::RsaPublicKey::from_pkcs1_der(key_bytes)
        .map_err(|_| X509Error::SignatureVerificationError)?;
    let verifying_key = rsa::pss::VerifyingKey::<D>::new_with_salt_len(rsa_key, salt_len);
    let sig = rsa::pss::Signature::try_from(sig_bytes)
        .map_err(|_| X509Error::SignatureVerificationError)?;
    verifying_key
        .verify(data, &sig)
        .map_err(|_| X509Error::SignatureVerificationError)
}

/// Find the verification function for the given EC curve and SHA digest size.
///
/// Only the standard curve/hash pairings (P-256/SHA-256, P-384/SHA-384) are supported.
/// Cross-pairings (P-256/SHA-384, P-384/SHA-256) are not supported by the RustCrypto backend.
#[cfg(all(
    feature = "verify-rustcrypto",
    not(feature = "verify"),
    not(feature = "verify-aws")
))]
fn rc_verify_ecdsa(
    pubkey_alg: &AlgorithmIdentifier,
    key_bytes: &[u8],
    sig_bytes: &[u8],
    data: &[u8],
    sha_len: usize,
) -> Result<(), X509Error> {
    let curve_oid = pubkey_alg
        .parameters
        .as_ref()
        .and_then(|p| p.as_oid().ok())
        .ok_or(X509Error::SignatureUnsupportedAlgorithm)?;

    if curve_oid == OID_EC_P256 && sha_len == 256 {
        use p256::ecdsa::signature::Verifier;
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
            .map_err(|_| X509Error::SignatureVerificationError)?;
        let sig = p256::ecdsa::DerSignature::from_bytes(sig_bytes)
            .map_err(|_| X509Error::SignatureVerificationError)?;
        vk.verify(data, &sig)
            .map_err(|_| X509Error::SignatureVerificationError)
    } else if curve_oid == OID_NIST_EC_P384 && sha_len == 384 {
        use p384::ecdsa::signature::Verifier;
        let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
            .map_err(|_| X509Error::SignatureVerificationError)?;
        let sig = p384::ecdsa::DerSignature::from_bytes(sig_bytes)
            .map_err(|_| X509Error::SignatureVerificationError)?;
        vk.verify(data, &sig)
            .map_err(|_| X509Error::SignatureVerificationError)
    } else {
        Err(X509Error::SignatureUnsupportedAlgorithm)
    }
}

#[cfg(all(
    feature = "verify-rustcrypto",
    not(feature = "verify"),
    not(feature = "verify-aws")
))]
fn rc_verify_ed25519(key_bytes: &[u8], sig_bytes: &[u8], data: &[u8]) -> Result<(), X509Error> {
    use core::convert::TryInto;
    use ed25519_dalek::Verifier;

    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| X509Error::SignatureVerificationError)?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&key_array)
        .map_err(|_| X509Error::SignatureVerificationError)?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| X509Error::SignatureVerificationError)?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
    vk.verify(data, &sig)
        .map_err(|_| X509Error::SignatureVerificationError)
}
