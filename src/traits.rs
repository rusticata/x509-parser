use crate::error::X509Result;

/// Parse a DER-encoded object, and return the remaining of the input and the built
/// object.
///
/// The returned object uses zero-copy, and so has the same lifetime as the input.
///
#[cfg_attr(
    feature = "validate",
    doc = r#"
Note that only parsing is done, not validation (see the [`Validate`](crate::validate::Validate) trait).
"#
)]
#[cfg_attr(
    not(feature = "validate"),
    doc = r#"
Note that only parsing is done, not validation.
"#
)]
///
/// # Example
///
/// To parse a certificate and print the subject and issuer:
///
/// ```rust
/// # use x509_parser::prelude::*;
/// #
/// # static DER: &'static [u8] = include_bytes!("../assets/IGC_A.der");
/// #
/// # fn main() {
/// let res = X509Certificate::from_der(DER);
/// match res {
///     Ok((_rem, x509)) => {
///         let subject = x509.subject();
///         let issuer = x509.issuer();
///         println!("X.509 Subject: {}", subject);
///         println!("X.509 Issuer: {}", issuer);
///     },
///     _ => panic!("x509 parsing failed: {:?}", res),
/// }
/// # }
/// ```

pub trait FromDer<'a>: Sized {
    /// Attempt to parse input bytes into a DER object
    fn from_der(bytes: &'a [u8]) -> X509Result<'a, Self>;
}
