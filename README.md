<!-- cargo-sync-readme start -->

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![docs.rs](https://docs.rs/x509-parser/badge.svg)](https://docs.rs/x509-parser)
[![crates.io](https://img.shields.io/crates/v/x509-parser.svg)](https://crates.io/crates/x509-parser)
[![Download numbers](https://img.shields.io/crates/d/x509-parser.svg)](https://crates.io/crates/x509-parser)
[![Travis CI](https://travis-ci.org/rusticata/x509-parser.svg?branch=master)](https://travis-ci.org/rusticata/x509-parser)
[![Github CI](https://github.com/rusticata/x509-parser/workflows/Continuous%20integration/badge.svg)](https://github.com/rusticata/x509-parser/actions)

# X.509 Parser

A X.509 v3 ([RFC5280]) parser, implemented with the [nom](https://github.com/Geal/nom)
parser combinator framework.

It is written in pure Rust, fast, and makes extensive use of zero-copy. A lot of care is taken
to ensure security and safety of this crate, including design (recursion limit, defensive
programming), tests, and fuzzing. It also aims to be panic-free.

The code is available on [Github](https://github.com/rusticata/x509-parser)
and is part of the [Rusticata](https://github.com/rusticata) project.

The main parsing method is [`parse_x509_der`](https://docs.rs/x509-parser/latest/x509_parser/fn.parse_x509_der.html), which takes a
DER-encoded certificate as input, and builds a
[`X509Certificate`](https://docs.rs/x509-parser/latest/x509_parser/x509/struct.X509Certificate.html) object.

For PEM-encoded certificates, use the [`pem`](https://docs.rs/x509-parser/latest/x509_parser/pem/index.html) module.

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

The `verify` feature is not compatible with rustc 1.34.

## Changes

See [CHANGELOG.md](CHANGELOG.md)

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
