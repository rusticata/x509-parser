#![no_main]
use libfuzzer_sys::{fuzz_mutator, fuzz_target};
use rand::rngs::ThreadRng;
use rand::seq::SliceRandom;
use rand::Rng;
use std::cell::RefCell;
use std::ops::DerefMut;

thread_local! {
    pub static RNG: RefCell<ThreadRng> = RefCell::new(rand::thread_rng());
}

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let _ = x509_parser::parse_x509_certificate(data);
});

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    const MUTATORS: &[fn(&mut [u8], usize, usize, u32) -> usize] = &[
        mutator_flip_constructed,
        mutator_change_type,
        mutator_change_length,
    ];

    let mut rng = rand::thread_rng();
    let idx = rng.gen_range(0..MUTATORS.len());
    MUTATORS[idx](data, size, max_size, seed)
});

// adapted from https://searchfox.org/mozilla-central/source/security/nss/fuzz/asn1_mutators.cc
// with changes to port to rust, and new mutators (length, etc.)

fn mutator_flip_constructed(data: &mut [u8], size: usize, _max_size: usize, _seed: u32) -> usize {
    // eprintln!("FLIP");
    let items = parse_items(data);
    let s = RNG.with(|rng| items.choose(rng.borrow_mut().deref_mut()).unwrap());
    let s: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(s.as_ptr() as *mut _, s.len()) };
    // Flip "constructed" type bit
    s[0] ^= 0x20;
    size
}

fn mutator_change_type(data: &mut [u8], size: usize, _max_size: usize, _seed: u32) -> usize {
    // eprintln!("CHANGE TYPE");
    let items = parse_items(data);
    let s = RNG.with(|rng| items.choose(rng.borrow_mut().deref_mut()).unwrap());
    let s: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(s.as_ptr() as *mut _, s.len()) };
    // Change type to a random int [0..=30]
    let ty = RNG.with(|rng| rng.borrow_mut().gen_range(0..=30));
    s[0] = ty;
    size
}

fn mutator_change_length(data: &mut [u8], size: usize, _max_size: usize, _seed: u32) -> usize {
    // eprintln!("CHANGE LENGTH");
    let items = parse_items(data);
    let s = RNG.with(|rng| items.choose(rng.borrow_mut().deref_mut()).unwrap());
    let s: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(s.as_ptr() as *mut _, s.len()) };
    // Change type to a random int [0..=30]
    let rand = RNG.with(|rng| rng.borrow_mut().gen_range(0..=1));
    // check if using short-form length
    if s.len() < 2 {
        return size;
    }
    if s[1] & 0x80 == 0 {
        match rand {
            0 => s[1] = s[1].wrapping_sub(1),
            _ => s[1] = s[1].wrapping_add(1),
        }
    }
    size
}

fn parse_items(data: &[u8]) -> Vec<&[u8]> {
    // eprintln!("PARSE_ITEMS (len: {})", data.len());
    // use nom::HexDisplay;
    // let l = std::cmp::min(data.len(), 32);
    // eprintln!("{}", data[..l].to_hex(16));

    let mut v = Vec::new();

    // The first item is always the whole corpus.
    v.push(data);

    // we cannot use iterators here, since we are iterating and modifying v
    // this is safe because we call v.len() at each iteration, and we only
    // append elements
    let mut i = 0;
    while i < v.len() {
        let mut item = v[i].clone();
        let mut remaining = item.len();

        // Empty or primitive items have no children.
        if remaining == 0 || (0x20 & item[0]) == 0 {
            i += 1;
            continue;
        }

        while remaining > 2 {
            // dbg!(remaining);
            // dbg!(item);
            if item.len() < 2 {
                break;
            }
            let content = parse_item(item);
            if !content.is_empty() {
                // Record the item
                v.push(content);
            } else {
                break;
            }

            // Reduce number of bytes left in current item.
            // if remaining < content.len() {
            //     eprintln!("remaining: {}", remaining);
            //     eprintln!("content.len: {}", content.len());
            //     let l = std::cmp::min(content.len(), 32);
            //     dbg!(&content[..l]);
            //     panic!();
            // }
            remaining -= std::cmp::min(content.len(), remaining);

            // Skip the item we just parsed
            item = &item[content.len()..];
        }

        i += 1;
    }

    // eprintln!("#v: {}", v.len());
    // for s in &v {
    //     eprintln!("  0x{:x} +{}", s.as_ptr() as usize, s.len());
    //     // use nom::HexDisplay;
    //     let l = std::cmp::min(s.len(), 32);
    //     eprintln!("{}", s[..l].to_hex(16));
    // }

    // loop {
    //     //
    // }

    v
}

// ASSERT: data.len() > 2
fn parse_item(data: &[u8]) -> &[u8] {
    // Short form. Bit 8 has value "0" and bits 7-1 give the length.
    if data[0] & 0x80 == 0 {
        let length = std::cmp::min(2 + data[1] as usize, data.len());
        return &data[2..length];
    }

    // Constructed, indefinite length. Read until {0x00, 0x00}.
    if data[1] == 0x80 {
        let length = data[2..]
            .windows(2)
            .position(|window| window == &[0, 0])
            .unwrap_or(data.len() - 2);

        return &data[2..2 + length];
    }

    // Long form. Two to 127 octets. Bit 8 of first octet has value "1"
    // and bits 7-1 give the number of additional length octets.
    let octets = std::cmp::min((data[1] & 0x7f) as usize, data.len() - 2);

    // Handle lengths bigger than 32 bits.
    if octets > 4 {
        // Ignore any further children, assign remaining length.
        return &data[2 + octets..];
    }

    // parse the length
    let length = (0..octets).fold(0usize, |acc, b| (acc << 8) | (data[2 + b] as usize));

    let length = std::cmp::min(2 + octets + length, data.len());

    &data[2 + octets..length]
}
