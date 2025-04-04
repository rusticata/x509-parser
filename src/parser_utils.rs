use std::ops::Range;

use asn1_rs::{BerError, DerParser, Header, InnerError, Input, Tagged};
use nom::{Err, IResult, Input as _};

pub fn get_span<'a>(
    header: &Header<'a>,
    input: Input<'a>,
) -> IResult<Input<'a>, Range<usize>, BerError<Input<'a>>> {
    let start = header.raw_header().map(|h| h.start()).unwrap_or(0);
    let end = input.end();
    Ok((input, Range { start, end }))
}

// FIXME: remove this?
/// Parse sequence, returning the object and a reference over entire object input
pub fn parse_object_with_span<'i, T>(
    input: Input<'i>,
) -> IResult<Input<'i>, (T, Input<'i>), <T as DerParser<'i>>::Error>
where
    T: DerParser<'i>,
    T: Tagged,
    // <T as DerParser<'i>>::Error: From<BerError<Input<'i>>>,
    <T as DerParser<'i>>::Error: From<InnerError>,
{
    let orig_input = input.clone();
    let (rem, header) = Header::parse_der(input).map_err(Err::convert)?;
    header
        .tag()
        .assert_eq_inner(T::TAG)
        .map_err(|e| Err::Error(e.into()))?;
    if header.constructed() != T::CONSTRUCTED {
        let e = if T::CONSTRUCTED {
            InnerError::ConstructExpected
        } else {
            InnerError::ConstructUnexpected
        };
        return Err(Err::Error(e.into()));
    }
    let (rem, obj) = T::from_der_content(&header, rem)?;
    // adjust `raw` to reference entire input (including header)
    // note: cannot underflow, rem is >= orig_input
    let obj_span = orig_input.take(rem.start() - orig_input.start());
    Ok((rem, (obj, obj_span)))
}
