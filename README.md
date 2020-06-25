<!-- cargo-sync-readme start -->

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![docs.rs](https://docs.rs/x509-parser/badge.svg)](https://docs.rs/x509-parser)
[![crates.io](https://img.shields.io/crates/v/x509-parser.svg)](https://crates.io/crates/x509-parser)
[![Download numbers](https://img.shields.io/crates/d/x509-parser.svg)](https://crates.io/crates/x509-parser)
[![Travis CI](https://travis-ci.org/rusticata/x509-parser.svg?branch=master)](https://travis-ci.org/rusticata/x509-parser)
[![AppVeyor CI](https://ci.appveyor.com/api/projects/status/github/rusticata/x509-parser?svg=true)](https://ci.appveyor.com/project/chifflier/x509-parser)

# X.509 Parser

A X.509 v3 ([RFC5280]) parser, implemented with the [nom](https://github.com/Geal/nom)
parser combinator framework.

It is written in pure Rust, fast, and makes extensive use of zero-copy. A lot of care is taken
to ensure security and safety of this crate, including design (recursion limit, defensive
programming), tests, and fuzzing. It also aims to be panic-free.

The code is available on [Github](https://github.com/rusticata/x509-parser)
and is part of the [Rusticata](https://github.com/rusticata) project.

The main parsing method is
[`parse_x509_der`](https://docs.rs/x509-parser/latest/x509_parser/fn.parse_x509_der.html),
which takes a DER-encoded
certificate as input, and builds a
[`X509Certificate`](https://docs.rs/x509-parser/latest/x509_parser/x509/struct.X509Certificate.html)
object.

For PEM-encoded certificates, use the
[`pem`](https:///docs.rs/x509-parser/latest/x509_parser/pem/index.html) module.

# Examples

Parsing a certificate in DER format:

```rust
use x509_parser::parse_x509_der;

static IGCA_DER: &'static [u8] = include_bytes!("../assets/IGC_A.der");

let res = parse_x509_der(IGCA_DER);
match res {
    Ok((rem, cert)) => {
        assert!(rem.is_empty());
        //
        assert_eq!(cert.tbs_certificate.version, 2);
    },
    _ => panic!("x509 parsing failed: {:?}", res),
}
```

See also `examples/print-cert.rs`.

# Features

- The `verify` feature adds support for (cryptographic) signature verification, based on ring.
  It adds the `verify_signature` to `X509Certificate`.

```rust
/// Cryptographic signature verification: returns true if certificate was signed by issuer
#[cfg(feature = "verify")]
pub fn check_signature(cert: &X509Certificate<'_>, issuer: &X509Certificate<'_>) -> bool {
    let issuer_public_key = &issuer.tbs_certificate.subject_pki;
    cert
        .verify_signature(Some(issuer_public_key))
        .is_ok()
}
```

[RFC5280]: https://tools.ietf.org/html/rfc5280

<!-- cargo-sync-readme end -->

## Compatibility with older rust versions

### 1.34

There is a build error in `arrayvec` with rust 1.34: `error[E0658]: use of unstable library feature 'maybe_uninit'`

To fix it, force the version of `lexical-core` down:
```
cargo update -p lexical-core --precise 0.6.7
```

## Changes

### 0.8.0

- Upgrade to `der-parser` 4.0
- Fix clippy warnings
  - `nid2obj` argument is now passed by copy, not reference
- Add method to get a formatted string of the certificate serial number
- Add method to get decoded version
- Add convenience methods to access the most common fields (subject, issuer, etc.)
- Make OID objects public
- Implement parsing for some extensions
  - Support for extensions is not complete, support for more types will be added later
- Add example to decode and print certificates
- Add `verify` feature to verify cryptographic signature by a public key

Thanks: @jannschu

### 0.7.0

- Expose raw bytes of the certificate serial number
- Set edition to 2018

### 0.6.4

- Fix infinite loop when certificate has no END mark

### 0.6.3

- Fix infinite loop when reading non-pem data (#28)

### 0.6.2

- Remove debug code left in `Pem::read`

### 0.6.1

- Add CRL parser
- Expose CRL tbs bytes
- PEM: ignore lines before BEGIN label (#21)
- Fix parsing default values for TbsCertificate version field (#24)
- Use BerResult from der-parser for simpler function signatures
- Expose tbsCertificate bytes
- Upgrade dependencies (base64)

### 0.6.0

- Update to der-parser 3.0 and nom 5
- Breaks API, cleaner error types

### 0.5.1

- Add `time_to_expiration` to `Validity` object
- Add method to read a `Pem` object from `BufRead + Seek`
- Add method to `Pem` to decode and extract certificate

### 0.5.0

- Update to der-parser 2.0

### 0.4.3

- Make `parse_subject_public_key_info` public
- Add function `sn2oid` (get an OID by short name)

### 0.4.2

- Support GeneralizedTime conversion

### 0.4.1

- Fix case where certificate has no extensions

### 0.4.0

- Upgrade to der-parser 1.1, and Use num-bigint over num
- Rename x509_parser to parse_x509_der
- Do not export subparsers
- Improve documentation

### 0.3.0

- Upgrade to nom 4

### 0.2.0

- Rewrite X.509 structures and parsing code to work in one pass
  **Warning: this is a breaking change**
- Add support for PEM-encoded certificates
- Add some documentation

## License

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
