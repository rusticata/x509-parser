## Upgrading from 0.17 to 0.18

The major changes in version 0.18 are described here.

### Cargo and dependencies

Dependencies:

- `nom` updated to 8.0 `asn1-rs` updated to 0.8
	- note that `bigint` is enabled in `asn1-rs` import
	- `bitvec` is present by default
- `der-parser` dependency (and re-export) removed

### Global API

- The default parsing trait is now `DerParser`. The parsing function `.parse_der()` now expects an `Input` object, which can be built from bytes using `Input::from`. All X.509 objects and sub-objects will provide this trait
	+ This improves error handling (`Input` tracks offsets) and helps simplifying code for parsers
- The legacy trait `FromDer` is still provided for compatibility, for top-level objects.

### Changed struct fields and methods

General:
- `UniqueIdentifier` has no lifetime anymore
- Removed constant `MAX_OBJECT_SIZE`. This is not required in this crate since `asn1-rs` takes care of reading valid data.
- Module `utils.rs` has been removed, functions are now part of `x509.rs`

CSR:
- `X509CertificationRequest` extensions contains a **SET** of values, not a single value
- `csr.requested_extensions()` returns an `Iterator`, not an `Option<Iterator>`

Extensions:

- `InhibitAnyPolicy` is now an anonymous struct:
`InhibitAnyPolicy { skip_certs: 2 }` => `InhibitAnyPolicy(2)`
- `SubjectAlternativeName` iteration changed from `&san.general_names` to `san.general_names()` (or `.0`)

### Changes in types from `asn1-rs`

The following changes are not part of this crate, but are exposed in `Any` objects:

- Any.data() now has type `Input`
	- Use `.as_bytes2()` to get `&[u8]`
		+ Note: recoding `.as_bytes()` or `.as_ref()` may seem useless, but this is necessary to work around problem with lifetimes.
- `BitString` does not have a lifetime parameter anymore
	- `bitstring.data` is replaced by `bitstring.as_raw_slice()`

### Changes in types from `nom`

- The nom `Parser` trait has changed (it now uses associated types)
- Add `.parse`, for ex: `length_data(be_u16).parse(i)`

### Notes for crate developers

- Many parsers have been replaced by derive attributes (like `Sequence` or `Choice`) when possible. This reduces risks of errors and makes code more easier to maintain
	+ Encoders are not derived for now
- File `extensions/mod.rs` has been split in multiple files