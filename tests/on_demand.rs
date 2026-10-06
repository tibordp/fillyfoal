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

/// The text behind `tests/data/{zstd,bzip2}/lines-*` (850,250 bytes).
fn zstd_bzip2_lines() -> Vec<u8> {
    (0..24000u32).map(|i| format!("line {i}: the quick brown fox {}\n", i * 7919 % 1000)).collect::<String>().into_bytes()
}

/// The data behind `mixed.zst` and `mixed-1.bz2`: text, 140,000
/// pseudo-random bytes (raw zstd blocks), 300,000 zeros (RLE blocks), text.
fn zstd_bzip2_mixed() -> Vec<u8> {
    let mut out = zstd_bzip2_lines()[..100_000].to_vec();
    let mut x: u32 = 12345;
    for _ in 0..140_000 {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345) & 0x7fff_ffff;
        out.push((x >> 16) as u8);
    }
    out.resize(out.len() + 300_000, 0);
    out.extend(b"tail\n".repeat(1000));
    out
}

fn zstd_bzip2_data(dir: &str, name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{dir}/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// Decodes all of `input` (eof) and returns the output and the consumed
/// count, or the error message.
fn zstd_bzip2_decode(codec: &Codec, input: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut decoder = codec.decoder().unwrap();
    let mut out = Vec::new();
    loop {
        match decoder.decode(input, true, &mut out, 16 * 1024, 1 << 30) {
            Ok(Status::Done) => return Ok((out, decoder.consumed())),
            Ok(Status::More) => {}
            Ok(Status::NeedInput) => return Err("needs input".into()),
            Err(e) => return Err(e.message),
        }
    }
}

/// `zstd` 1.5 CLI output: levels 1 and 19, `--long=27`, `--no-check`,
/// `--no-content-size`, `--content-size`, two frames around a skippable
/// frame, and a frame with raw and RLE blocks.
#[test]
fn zstd_is_on_demand() {
    let lines = zstd_bzip2_lines();
    for name in ["lines-1.zst", "lines-19.zst", "lines-long.zst", "lines-nocheck.zst", "lines-nosize.zst", "lines-size.zst", "lines-frames.zst"] {
        assert_on_demand(&Codec::Zstd, &zstd_bzip2_data("zstd", name), &lines);
    }
    assert_on_demand(&Codec::Zstd, &zstd_bzip2_data("zstd", "mixed.zst"), &zstd_bzip2_mixed());
}

#[test]
fn zstd_consumed_and_checks() {
    let lines = zstd_bzip2_lines();
    let one = zstd_bzip2_data("zstd", "lines-1.zst");
    // Trailing data is left unconsumed.
    let mut trailing = one.clone();
    trailing.extend_from_slice(b"trailing junk");
    for codec in [Codec::Zstd, Codec::ZstdFrame] {
        let (out, consumed) = zstd_bzip2_decode(&codec, &trailing).unwrap();
        assert!(out == lines);
        assert_eq!(consumed, one.len());
    }
    // A single frame stops before the next one (here a skippable frame).
    let frames = zstd_bzip2_data("zstd", "lines-frames.zst");
    let (out, consumed) = zstd_bzip2_decode(&Codec::ZstdFrame, &frames).unwrap();
    assert!(out == lines[..150_000]);
    assert_eq!(frames[consumed..consumed + 4], [0x5a, 0x2a, 0x4d, 0x18]);
    assert_on_demand(&Codec::ZstdFrame, &frames, &lines[..150_000]);
    let (out, consumed) = zstd_bzip2_decode(&Codec::Zstd, &frames).unwrap();
    assert!(out == lines);
    assert_eq!(consumed, frames.len());
    // A corrupted content checksum.
    let mut bad = one.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    assert_eq!(zstd_bzip2_decode(&Codec::Zstd, &bad).unwrap_err(), "zstd: content checksum mismatch");
    // A wrong content size (a 4-byte field, after the window descriptor
    // unless the frame is a single segment).
    let mut bad = zstd_bzip2_data("zstd", "lines-size.zst");
    assert_eq!(bad[4] >> 6, 2);
    let at = if bad[4] & 0x20 != 0 { 5 } else { 6 };
    assert_eq!(u32::from_le_bytes(bad[at..at + 4].try_into().unwrap()), lines.len() as u32);
    bad[at] ^= 1;
    assert_eq!(zstd_bzip2_decode(&Codec::Zstd, &bad).unwrap_err(), "zstd: frame content size mismatch");
}

/// `bzip2` 1.0.8 output: `-1` (five 100k blocks), two concatenated streams
/// (`-9` and `-3`), and `-1` on the mixed data.
#[test]
fn bzip2_is_on_demand() {
    let lines = zstd_bzip2_lines();
    assert_on_demand(&Codec::Bzip2, &zstd_bzip2_data("bzip2", "lines-1.bz2"), &lines);
    assert_on_demand(&Codec::Bzip2, &zstd_bzip2_data("bzip2", "lines-streams.bz2"), &lines);
    assert_on_demand(&Codec::Bzip2, &zstd_bzip2_data("bzip2", "mixed-1.bz2"), &zstd_bzip2_mixed());
}

#[test]
fn bzip2_consumed_and_checks() {
    let lines = zstd_bzip2_lines();
    let one = zstd_bzip2_data("bzip2", "lines-1.bz2");
    let mut trailing = one.clone();
    trailing.extend_from_slice(b"trailing junk");
    let (out, consumed) = zstd_bzip2_decode(&Codec::Bzip2, &trailing).unwrap();
    assert!(out == lines);
    assert_eq!(consumed, one.len());
    // The stream's combined CRC ends just before the last byte's padding.
    let mut bad = one.clone();
    let n = bad.len();
    bad[n - 2] ^= 1;
    assert_eq!(zstd_bzip2_decode(&Codec::Bzip2, &bad).unwrap_err(), "bzip2: stream CRC mismatch");
}
