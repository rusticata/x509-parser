//! This file is used to test the time crate with wasm.
//! This needs the `wasm-bindgen-test` crate to compile
//!
//! ```sh
//! # cargo add wasm-bindgen-test --dev
//! wasm-pack test --node
//! ```
//!

#![cfg(target_arch = "wasm32")]

use x509_parser::pem::Pem;

static IGCA_PEM: &[u8] = include_bytes!("../assets/IGC_A.pem");

/// This test is used to check if the time crate is working correctly on wasm32 target
/// because it is used in the x509 parser to check the validity of the certificate
#[wasm_bindgen_test::wasm_bindgen_test]
fn test_x509_parse_pem() {
    let pem: Vec<Pem> = Pem::iter_from_buffer(IGCA_PEM)
        .collect::<Result<_, _>>()
        .ok()
        .unwrap();
    let x509 = pem[0].parse_x509().unwrap();
    assert_eq!(x509.validity.is_valid(), false);
}
