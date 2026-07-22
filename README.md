[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![docs.rs](https://docs.rs/x509-parser/badge.svg)](https://docs.rs/x509-parser)
[![crates.io](https://img.shields.io/crates/v/x509-parser.svg)](https://crates.io/crates/x509-parser)
[![Download numbers](https://img.shields.io/crates/d/x509-parser.svg)](https://crates.io/crates/x509-parser)
[![Github CI](https://github.com/rusticata/x509-parser/workflows/Continuous%20integration/badge.svg)](https://github.com/rusticata/x509-parser/actions)
[![Minimum rustc version](https://img.shields.io/badge/rustc-1.85+-lightgray.svg)](#rust-version-requirements)

<!-- To generate the README, use `cargo rdme install-rust-toolchain-for-intralinks && cargo rdme --intralinks-all-features` -->
<!-- cargo-rdme start -->

# X.509 Parser

A X.509 v3 ([RFC5280]) parser, implemented with the [nom](https://github.com/Geal/nom)
parser combinator framework.

It is written in pure Rust, fast, and makes extensive use of zero-copy. A lot of care is taken
to ensure security and safety of this crate, including design (recursion limit, defensive
programming), tests, and fuzzing. It also aims to be panic-free.

The code is available on [Github](https://github.com/rusticata/x509-parser)
and is part of the [Rusticata](https://github.com/rusticata) project.

Certificates are usually encoded in two main formats: PEM (usually the most common format) or
DER.  A PEM-encoded certificate is a container, storing a DER object. See the
[`pem`](https://docs.rs/x509-parser/latest/x509_parser/pem/) module for more documentation.

To decode a DER-encoded certificate, the main parsing method is
`X509Certificate::parse_der` (from the [`DerParser`](https://docs.rs/asn1_rs/latest/asn1_rs/from_der/trait.DerParser.html) trait)
which builds a [`X509Certificate`](https://docs.rs/x509-parser/latest/x509_parser/certificate/struct.X509Certificate.html) object.

The [`parse_der`](https://docs.rs/asn1_rs/latest/asn1_rs/from_der/trait.DerParser.html) trait takes an [`Input`](https://docs.rs/asn1_rs/latest/asn1_rs/input/struct.Input.html)
object, which can be built from the input bytes. This helps tracking offsets (in case of
error).
For convenience,
the [`X509Certificate::from_der`] method (part of the [`FromDer`](https://docs.rs/asn1_rs/latest/asn1_rs/from_der/trait.FromDer.html) trait)
does the same directly on the input bytes, but it can loose the precise error location.

An alternative method is to use [`X509CertificateParser`](https://docs.rs/x509-parser/latest/x509_parser/certificate/struct.X509CertificateParser.html),
which allows specifying parsing options (for example, not automatically parsing option contents).

Similar methods are provided for other X.509 objects:
- [`X509Certificate`](https://docs.rs/x509-parser/latest/x509_parser/certificate/struct.X509Certificate.html) for X.509 Certificates
- [`CertificateRevocationList`](https://docs.rs/x509-parser/latest/x509_parser/revocation_list/struct.CertificateRevocationList.html) for X.509 v2 Certificate Revocation List (CRL)
- [`X509CertificationRequest`](https://docs.rs/x509-parser/latest/x509_parser/certification_request/struct.X509CertificationRequest.html) for Certification Signing Request (CSR)

The returned objects for parsers follow the definitions of the RFC. This means that accessing
fields is done by accessing struct members recursively. Some helper functions are provided, for
example [`X509Certificate::issuer()`](https://docs.rs/x509-parser/latest/x509_parser/certificate/struct.TbsCertificate.html#method.issuer) returns the
same as accessing `<object>.tbs_certificate.issuer`.

For PEM-encoded certificates, use the [`pem`](https://docs.rs/x509-parser/latest/x509_parser/pem/) module.

This crate also provides visitor traits: [`X509CertificateVisitor`](https://docs.rs/x509-parser/latest/x509_parser/visitor/certificate_visitor/trait.X509CertificateVisitor.html), [`CertificateRevocationListVisitor`](https://docs.rs/x509-parser/latest/x509_parser/visitor/crl_visitor/trait.CertificateRevocationListVisitor.html).
See the [`visitor`](https://docs.rs/x509-parser/latest/x509_parser/visitor/) module.

# Examples

Parsing a certificate in DER format:

```rust
use x509_parser::prelude::*;

static IGCA_DER: &[u8] = include_bytes!("../assets/IGC_A.der");

let input = Input::from(IGCA_DER);
let res = X509Certificate::parse_der(input);
match res {
    Ok((rem, cert)) => {
        assert!(rem.is_empty());
        //
        assert_eq!(cert.version(), X509Version::V3);
    },
    _ => panic!("x509 parsing failed: {:?}", res),
}
```

To parse a CRL and print information about revoked certificates:

```rust
let input = Input::from(DER);
let res = CertificateRevocationList::parse_der(input);
match res {
    Ok((_rem, crl)) => {
        for revoked in crl.iter_revoked_certificates() {
            println!("Revoked certificate serial: {}", revoked.raw_serial_as_string());
            println!("  Reason: {}", revoked.reason_code().unwrap_or_default().1);
        }
    },
    _ => panic!("CRL parsing failed: {:?}", res),
}
```

See also `examples/print-cert.rs`.

# Features

- The `verify` and `verify-aws` features add support for (cryptographic) signature verification, based on `ring` or `aws-lc` respectively.
  It adds the
  [`X509Certificate::verify_signature()`](https://docs.rs/x509-parser/latest/x509_parser/certificate/struct.X509Certificate.html#method.verify_signature) method
  to `X509Certificate`.

```rust
/// Cryptographic signature verification: returns true if certificate was signed by issuer
#[cfg(any(feature = "verify", feature = "verify-aws"))]
pub fn check_signature(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
    let issuer_public_key = issuer.public_key();
    cert
        .verify_signature(Some(issuer_public_key))
        .is_ok()
}
```

- The `verify-aws` feature offers the same support for signature verification, but based on
  `aws-lc-rs` instead of `ring`.

- _Note_: if both `verify` and `verify-aws` features are enabled (which happens when using
  `--all-features`), the verification will use `aws-lc-rs`. It also has the side-effect of
  having a dependency on `ring`, even if it is not used.

- The `validate` feature add methods to run more validation functions on the certificate structure
  and values using the [`Validate`](https://docs.rs/x509-parser/latest/x509_parser/validate/trait.Validate.html) trait.
  It does not validate any cryptographic parameter (see `verify` above).

## Rust version requirements

`x509-parser` requires **Rustc version 1.85 or greater**

[RFC5280]: https://tools.ietf.org/html/rfc5280

<!-- cargo-rdme end -->

## MSRV policy

This projects tries to maintain compatibility with older versions of the rust compiler for the following
durations:
- `master` branch: _12 months_ minimum
- older releases: about 24 months

However, due to dependencies and the fact that some crate writers tend to require very recent
versions of the compiler, this can prove to be difficult. These numbers are given as _best-effort_.

We do not consider MSRV changes to be breaking for the purposes of semver.

We try to make no change to MSRV in stable branches and in security patches, with the exception of
a dependency that must be updated for security and requires a new MSRV.

## Changes

See [CHANGELOG.md](CHANGELOG.md) and [`UPGRADING.md`](UPGRADING.md) for instructions for upgrading major versions.

# License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
