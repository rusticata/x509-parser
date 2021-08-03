/// Trait for validating item (for ex. validate X.509 structure)
///
/// # Examples
///
/// Using callbacks:
///
/// ```
/// use x509_parser::certificate::X509Certificate;
/// use x509_parser::validate::Validate;
///
/// #[cfg(feature = "validate")]
/// fn validate_certificate(x509: &X509Certificate<'_>) -> Result<(), &'static str> {
///     println!("  Subject: {}", x509.subject());
///     // validate and print warnings and errors to stderr
///     let ok = x509.validate(
///         |msg| {
///             eprintln!("  [W] {}", msg);
///         },
///         |msg| {
///             eprintln!("  [E] {}", msg);
///         },
///     );
///     print!("Structure validation status: ");
///     if ok {
///         println!("Ok");
///         Ok(())
///     } else {
///         println!("FAIL");
///         Err("validation failed")
///     }
/// }
/// ```
///
/// Collecting warnings and errors to `Vec`:
///
/// ```
/// use x509_parser::certificate::X509Certificate;
/// use x509_parser::validate::Validate;
///
/// #[cfg(feature = "validate")]
/// fn validate_certificate(x509: &X509Certificate<'_>) -> Result<(), &'static str> {
///     println!("  Subject: {}", x509.subject());
///     // validate and print warnings and errors to stderr
///     let (ok, warnings, errors) = x509.validate_to_vec();
///     print!("Structure validation status: ");
///     if ok {
///         println!("Ok");
///     } else {
///         println!("FAIL");
///     }
///     for warning in &warnings {
///         eprintln!("  [W] {}", warning);
///     }
///     for error in &errors {
///         eprintln!("  [E] {}", error);
///     }
///     println!();
///     if !errors.is_empty() {
///         return Err("validation failed");
///     }
///     Ok(())
/// }
/// ```
pub trait Validate {
    /// Attempts to validate current item.
    ///
    /// Returns `true` if item was validated.
    ///
    /// Call `warn()` if a non-fatal error was encountered, and `err()`
    /// if the error is fatal. These fucntions receive a description of the error.
    fn validate<W, E>(&self, warn: W, err: E) -> bool
    where
        W: FnMut(&str),
        E: FnMut(&str);

    /// Attempts to validate current item, storing warning and errors in `Vec`.
    ///
    /// Returns the validation result (`true` if validated), the list of warnings,
    /// and the list of errors.
    fn validate_to_vec(&self) -> (bool, Vec<String>, Vec<String>) {
        let mut warn_list = Vec::new();
        let mut err_list = Vec::new();
        let res = self.validate(
            |s| warn_list.push(s.to_owned()),
            |s| err_list.push(s.to_owned()),
        );
        (res, warn_list, err_list)
    }
}

#[cfg(test)]
mod tests {
    use super::Validate;

    struct V1 {
        a: u32,
    }

    impl Validate for V1 {
        fn validate<W, E>(&self, mut warn: W, _err: E) -> bool
        where
            W: FnMut(&str),
            E: FnMut(&str),
        {
            if self.a > 10 {
                warn("a is greater than 10");
            }
            true
        }
    }

    #[test]
    fn validate_warn() {
        let v1 = V1 { a: 1 };
        let (res, warn, err) = v1.validate_to_vec();
        assert!(res);
        assert!(warn.is_empty());
        assert!(err.is_empty());
        // same, with one warning
        let v20 = V1 { a: 20 };
        let (res, warn, err) = v20.validate_to_vec();
        assert!(res);
        assert_eq!(warn, vec!["a is greater than 10".to_string()]);
        assert!(err.is_empty());
    }
}
