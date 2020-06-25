#[cfg(feature = "verify")]
#[cfg_attr(docsrs, doc(cfg(feature = "verify")))]
mod x509_verify {
    use crate::error::X509Error;
    use crate::objects::*;
    use crate::x509::{SubjectPublicKeyInfo, X509Certificate};
    use ring::signature;

    impl<'a> X509Certificate<'a> {
        /// Verify the cryptographic signature of this certificate
        ///
        /// `public_key` is the public key of the **signer**. For a self-signed certificate,
        /// (for ex. a public root certificate authority), this is the key from the certificate,
        /// so you can use `None`.
        ///
        /// For a leaf certificate, this is the public key of the certificate that signed it.
        /// It is usually an intermediate authority.
        pub fn verify_signature(
            &self,
            public_key: Option<&SubjectPublicKeyInfo>,
        ) -> Result<(), X509Error> {
            let spki = public_key.unwrap_or(&self.tbs_certificate.subject_pki);
            let signature_alg = &self.signature_algorithm.algorithm;
            // identify verification algorithm
            let verification_alg: &dyn signature::VerificationAlgorithm =
                if *signature_alg == OID_RSA_SHA1 {
                    &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
                } else if *signature_alg == OID_RSA_SHA256 {
                    &signature::RSA_PKCS1_2048_8192_SHA256
                } else if *signature_alg == OID_RSA_SHA384 {
                    &signature::RSA_PKCS1_2048_8192_SHA384
                } else if *signature_alg == OID_RSA_SHA512 {
                    &signature::RSA_PKCS1_2048_8192_SHA512
                } else if *signature_alg == OID_ECDSA_SHA256 {
                    &signature::ECDSA_P256_SHA256_ASN1
                } else if *signature_alg == OID_ECDSA_SHA384 {
                    &signature::ECDSA_P384_SHA384_ASN1
                } else {
                    return Err(X509Error::SignatureUnsupportedAlgorithm);
                };
            // get public key
            let key =
                signature::UnparsedPublicKey::new(verification_alg, spki.subject_public_key.data);
            // verify signature
            let sig = self.signature_value.data;
            key.verify(self.tbs_certificate.raw, sig)
                .or(Err(X509Error::SignatureVerificationError))
        }
    }
}
