#[test]
fn test01() {
    let data = b"0\x88\xff\xff\xff\xff\xff\xff\xff\xff00\x0f\x02\x000\x00\x00\x00\x00\x00\x0000\x0f\x00\xff\x0a\xbb\xff";
    let _ = x509_parser::parse_x509_certificate(data);
}

#[cfg(not(target_arch = "wasm32"))]
fn parser02(input: &[u8]) -> nom::IResult<&[u8], ()> {
    use nom::bytes::complete::take;
    let (_hdr, input) = take(1_usize)(input)?;
    let (_data, input) = take(18_446_744_073_709_551_615_usize)(input)?;
    Ok((input, ()))
}

/// This test is not running on wasm32 because `parser02` needs a big usize
/// Therefore on wasm32 target it triggers a compilation error:
/// literal out of range for `usize``
#[cfg(not(target_arch = "wasm32"))]
#[test]
fn test02() {
    let data = b"0\x88\xff\xff\xff\xff\xff\xff\xff\xff00\x0f\x02\x000\x00\x00\x00\x00\x00\x0000\x0f\x00\xff\x0a\xbb\xff";
    let _ = parser02(data);
}
