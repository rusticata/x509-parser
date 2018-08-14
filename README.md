# x509-parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build Status](https://travis-ci.org/rusticata/x509-parser.svg?branch=master)](https://travis-ci.org/rusticata/x509-parser)
[![Crates.io Version](https://img.shields.io/crates/v/x509-parser.svg)](https://crates.io/crates/x509-parser)

## Overview

x509-parser is a parser for the X.509 v3 format ([RFC 5280](https://tools.ietf.org/html/rfc5280)).

## Important

*This parser is still experimental and very incomplete*

## Changes

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
