//! On-demand decoding: every streaming codec must give the same output
//! however its input is chunked, and must produce output before it has
//! seen the whole input (so a lazily decoded source only reads what its
//! readers reach).

#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fillyfoal::codec::Codec;
use fillyfoal::codec::pipeline::Status;

/// Decodes `input` fed in pieces of `chunk` bytes (eof only at the end),
/// `step` output bytes at a time.
pub fn chunked(codec: &Codec, input: &[u8], chunk: usize, step: usize) -> Vec<u8> {
    let mut decoder = codec.decoder().unwrap();
    let mut out = Vec::new();
    let mut fed = 0;
    loop {
        let eof = fed == input.len();
        match decoder.decode(&input[..fed], eof, &mut out, step, 1 << 30).unwrap() {
            Status::Done => return out,
            Status::More => {}
            Status::NeedInput => {
                assert!(!eof, "decoder wants input after the end");
                fed = (fed + chunk).min(input.len());
            }
        }
    }
}

/// How many bytes the decoder produces from the first `prefix` bytes of
/// `input` (no eof), decoding until it needs more input.
pub fn produced_from_prefix(codec: &Codec, input: &[u8], prefix: usize) -> usize {
    let mut decoder = codec.decoder().unwrap();
    let mut out = Vec::new();
    while decoder.decode(&input[..prefix], false, &mut out, 16 * 1024, 1 << 30).unwrap() == Status::More {}
    out.len()
}

/// The standard checks: chunk-independence (several chunk sizes, plus
/// byte-at-a-time for small inputs) and output from half the input.
pub fn assert_on_demand(codec: &Codec, input: &[u8], expected: &[u8]) {
    let mut chunks = vec![4096, 65_536, 1 << 20];
    if input.len() <= 64 * 1024 {
        chunks.extend([1, 13]);
    }
    for chunk in chunks {
        assert!(chunked(codec, input, chunk, 16 * 1024) == expected, "{codec:?}: output differs with {chunk}-byte input chunks");
    }
    if expected.len() >= 256 * 1024 {
        let half = produced_from_prefix(codec, input, input.len() / 2);
        assert!(half > 0, "{codec:?}: nothing decoded from the first half of the input");
    }
}

#[test]
fn deflate_is_on_demand() {
    // A large zlib stream from the existing test data.
    let text: Vec<u8> = (0..200_000u32).flat_map(|i| format!("line {i} of the on-demand test\n").into_bytes()).collect();
    let mut z = vec![0x78, 0x01];
    // Stored blocks are enough to exercise the plumbing.
    for block in text.chunks(65_535) {
        let last = u8::from(block.as_ptr_range().end == text.as_ptr_range().end);
        z.push(last);
        let len = block.len() as u16;
        z.extend_from_slice(&len.to_le_bytes());
        z.extend_from_slice(&(!len).to_le_bytes());
        z.extend_from_slice(block);
    }
    z.extend_from_slice(&fillyfoal::codec::adler32(&text).to_be_bytes());
    assert_on_demand(&Codec::Zlib, &z, &text);
}
