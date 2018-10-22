#[macro_use]
extern crate nom;

extern crate x509_parser;

#[test]
fn test01() {
    let data = b"0\x88\xff\xff\xff\xff\xff\xff\xff\xff00\x0f\x02\x000\x00\x00\x00\x00\x00\x0000\x0f\x00\xff\x0a\xbb\xff";
    let _ = x509_parser::parse_x509_der(data);
}

named!(parser02<&[u8],()>,
    do_parse!(
        _hdr: take!(1) >>
        _data: take!(18446744073709551615) >>
        ( () )
    )
);

#[test]
fn test02() {
    let data = b"0\x88\xff\xff\xff\xff\xff\xff\xff\xff00\x0f\x02\x000\x00\x00\x00\x00\x00\x0000\x0f\x00\xff\x0a\xbb\xff";
    let _ = parser02(data);
}
