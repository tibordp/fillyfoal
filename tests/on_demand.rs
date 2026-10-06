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

/// The sample the LZMA-family test files were made from (`xz` 5.8 CLI):
/// text lines with x86 CALLs and ARM64 BLs mixed in, so the BCJ filters
/// have work to do. `lzma_sample(2000)` is a prefix of `lzma_sample(7500)`.
fn lzma_sample(records: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut x: u32 = 12345;
    for i in 0..records {
        x = x.wrapping_mul(1103515245).wrapping_add(12345) & 0x7fff_ffff;
        out.extend_from_slice(format!("line {i}: the quick brown fox {}\n", (x >> 16) & 0xff).as_bytes());
        if i % 3 == 0 {
            out.push(0xe8);
            out.extend_from_slice(&(i * 16).to_le_bytes());
        }
        if i % 5 == 0 {
            out.extend_from_slice(&(0x9400_0000 | i).to_le_bytes());
        }
    }
    out
}

fn lzma_file(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/lzma/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// Decodes `input` fed in 4 KiB pieces and returns the input consumed.
fn lzma_consumed(codec: &Codec, input: &[u8]) -> usize {
    let mut decoder = codec.decoder().unwrap();
    let mut out = Vec::new();
    let mut fed = 0;
    loop {
        let eof = fed == input.len();
        match decoder.decode(&input[..fed], eof, &mut out, 16 * 1024, 1 << 30).unwrap() {
            Status::Done => return decoder.consumed(),
            Status::More => {}
            Status::NeedInput => fed = (fed + 4096).min(input.len()),
        }
    }
}

#[test]
fn xz_is_on_demand() {
    let big = lzma_sample(7500);
    // One block (CRC-64), 64 KiB blocks (CRC-32), x86 BCJ, and two streams
    // (CRC-32, SHA-256) with stream padding between and after them.
    for name in ["big.xz", "big-blocks.xz", "big-x86.xz", "big-streams.xz"] {
        assert_on_demand(&Codec::Xz, &lzma_file(name), &big);
    }
    let small = lzma_sample(2000);
    // The last has a 4 KiB dictionary, so the filtered block's window of
    // unfiltered bytes is compacted along the way.
    for name in ["small-sha256.xz", "small-none.xz", "small-arm64.xz", "small-delta.xz", "small-x86-delta.xz", "small-x86-dict4k.xz"] {
        assert_on_demand(&Codec::Xz, &lzma_file(name), &small);
    }
}

#[test]
fn lzma_is_on_demand() {
    let big = lzma_sample(7500);
    assert_on_demand(&Codec::LzmaAlone, &lzma_file("big.lzma"), &big);
    assert_on_demand(&Codec::Lzma2, &lzma_file("big.lzma2"), &big);
    let props = fillyfoal::codec::lzma::Props::from_byte(0x5d).unwrap();
    let raw = lzma_file("big.lzma1");
    assert_on_demand(&Codec::LzmaRaw { props, size: None }, &raw, &big);
    assert_on_demand(&Codec::LzmaRaw { props, size: Some(big.len()) }, &raw, &big);
    assert_on_demand(&Codec::LzmaRaw { props, size: Some(1000) }, &raw, &big[..1000]);
}

#[test]
fn lzma_family_consumes_exactly() {
    let props = fillyfoal::codec::lzma::Props::from_byte(0x5d).unwrap();
    let cases = [
        (Codec::Xz, "big-streams.xz"),
        (Codec::Xz, "small-x86-delta.xz"),
        (Codec::LzmaAlone, "big.lzma"),
        (Codec::Lzma2, "big.lzma2"),
        (Codec::LzmaRaw { props, size: None }, "big.lzma1"),
        // A known size and an end marker as well: the marker is consumed.
        (Codec::LzmaRaw { props, size: Some(lzma_sample(7500).len()) }, "big.lzma1"),
    ];
    for (codec, name) in cases {
        let data = lzma_file(name);
        let trailing = [data.clone(), b"trailing data".to_vec()].concat();
        assert_eq!(lzma_consumed(&codec, &data), data.len(), "{name}");
        assert_eq!(lzma_consumed(&codec, &trailing), data.len(), "{name} with trailing data");
    }
}
