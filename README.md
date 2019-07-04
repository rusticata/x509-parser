# x509-parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build Status](https://travis-ci.org/rusticata/x509-parser.svg?branch=master)](https://travis-ci.org/rusticata/x509-parser)
[![Crates.io Version](https://img.shields.io/crates/v/x509-parser.svg)](https://crates.io/crates/x509-parser)

<!-- cargo-sync-readme start -->

# X.509 Parser

A X.509 v3 ([RFC5280]) parser, implemented with the [nom](https://github.com/Geal/nom)
parser combinator framework.

The code is available on [Github](https://github.com/rusticata/x509-parser)
and is part of the [Rusticata](https://github.com/rusticata) project.

The main parsing method is [`parse_x509_der`](fn.parse_x509_der.html), which takes a DER-encoded
certificate as input, and builds a [`X509Certificate`](x509/struct.X509Certificate.html) object.

For PEM-encoded certificates, use the [`pem`](pem/index.html) module.

# Examples

Parsing a certificate in DER format:

```rust,no_run
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

[RFC5280]: https://tools.ietf.org/html/rfc5280

<!-- cargo-sync-readme end -->

## Changes

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
