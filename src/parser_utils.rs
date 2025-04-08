use std::ops::Range;

use asn1_rs::{BerError, Header, Input};
use nom::IResult;

pub fn get_span<'a>(
    header: &Header<'a>,
    input: Input<'a>,
) -> IResult<Input<'a>, Range<usize>, BerError<Input<'a>>> {
    let start = header.raw_header().map(|h| h.start()).unwrap_or(0);
    let end = input.end();
    Ok((input, Range { start, end }))
}
