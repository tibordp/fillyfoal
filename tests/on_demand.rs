//! On-demand decoding: every streaming codec must give the same output
//! however its input is chunked, and must produce output before it has
//! seen the whole input (so a lazily decoded source only reads what its
//! readers reach).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

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
        match decoder
            .decode(&input[..fed], eof, &mut out, step, 1 << 30)
            .unwrap()
        {
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
    while decoder
        .decode(&input[..prefix], false, &mut out, 16 * 1024, 1 << 30)
        .unwrap()
        == Status::More
    {}
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
        assert!(
            chunked(codec, input, chunk, 16 * 1024) == expected,
            "{codec:?}: output differs with {chunk}-byte input chunks"
        );
    }
    if expected.len() >= 256 * 1024 {
        let half = produced_from_prefix(codec, input, input.len() / 2);
        assert!(
            half > 0,
            "{codec:?}: nothing decoded from the first half of the input"
        );
    }
}

#[test]
fn deflate_is_on_demand() {
    // A large zlib stream from the existing test data.
    let text: Vec<u8> = (0..200_000u32)
        .flat_map(|i| format!("line {i} of the on-demand test\n").into_bytes())
        .collect();
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
    (0..24000u32)
        .map(|i| format!("line {i}: the quick brown fox {}\n", i * 7919 % 1000))
        .collect::<String>()
        .into_bytes()
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
    std::fs::read(format!(
        "{}/tests/data/{dir}/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
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
    for name in [
        "lines-1.zst",
        "lines-19.zst",
        "lines-long.zst",
        "lines-nocheck.zst",
        "lines-nosize.zst",
        "lines-size.zst",
        "lines-frames.zst",
    ] {
        assert_on_demand(&Codec::Zstd, &zstd_bzip2_data("zstd", name), &lines);
    }
    assert_on_demand(
        &Codec::Zstd,
        &zstd_bzip2_data("zstd", "mixed.zst"),
        &zstd_bzip2_mixed(),
    );
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
    assert_eq!(
        zstd_bzip2_decode(&Codec::Zstd, &bad).unwrap_err(),
        "zstd: content checksum mismatch"
    );
    // A wrong content size (a 4-byte field, after the window descriptor
    // unless the frame is a single segment).
    let mut bad = zstd_bzip2_data("zstd", "lines-size.zst");
    assert_eq!(bad[4] >> 6, 2);
    let at = if bad[4] & 0x20 != 0 { 5 } else { 6 };
    assert_eq!(
        u32::from_le_bytes(bad[at..at + 4].try_into().unwrap()),
        lines.len() as u32
    );
    bad[at] ^= 1;
    assert_eq!(
        zstd_bzip2_decode(&Codec::Zstd, &bad).unwrap_err(),
        "zstd: frame content size mismatch"
    );
}

/// `bzip2` 1.0.8 output: `-1` (five 100k blocks), two concatenated streams
/// (`-9` and `-3`), and `-1` on the mixed data.
#[test]
fn bzip2_is_on_demand() {
    let lines = zstd_bzip2_lines();
    assert_on_demand(
        &Codec::Bzip2,
        &zstd_bzip2_data("bzip2", "lines-1.bz2"),
        &lines,
    );
    assert_on_demand(
        &Codec::Bzip2,
        &zstd_bzip2_data("bzip2", "lines-streams.bz2"),
        &lines,
    );
    assert_on_demand(
        &Codec::Bzip2,
        &zstd_bzip2_data("bzip2", "mixed-1.bz2"),
        &zstd_bzip2_mixed(),
    );
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
    assert_eq!(
        zstd_bzip2_decode(&Codec::Bzip2, &bad).unwrap_err(),
        "bzip2: stream CRC mismatch"
    );
}

/// Block- and chunk-framed LZ codecs and containers: LZFSE, LZ4 frames,
/// framed Snappy, lzop, pbz, WIM resources and Unix `compress`.
///
/// `lines.*` (354,318 bytes of `lz::lines`; 713,767 of `lz::lines_n(14000)`
/// for LZFSE, whose blocks are larger) come from the real encoders: Apple
/// `compression_tool -encode -a lzfse`, `lz4 -B4 -BD -BX
/// --content-size` (64 KiB linked blocks with checksums), cramjam's Snappy
/// framing, `/usr/bin/compress`, and `aa archive -a lzfse|lzma -b 64k` (pbz
/// chunks around an Apple Archive of the text). No lzop or WIM encoder is
/// at hand: lzop streams are concatenations of the liblzo-based members in
/// `tests/data/lzo`, and the WIM resource is built here around the LZX chunk
/// from the spec-derived test encoder in `tests/data/cab`.
mod lz {
    use super::assert_on_demand;
    use fillyfoal::codec::{Codec, pipeline, wim};

    pub fn read(path: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    pub fn eager(codec: &Codec, input: &[u8]) -> Vec<u8> {
        pipeline::decode_all(codec.decoder().unwrap().as_mut(), input, 1 << 30).unwrap()
    }

    pub fn lines() -> Vec<u8> {
        lines_n(7000)
    }

    pub fn lines_n(n: u32) -> Vec<u8> {
        (0..n)
            .map(|i| {
                format!(
                    "line {i}: the quick brown fox {} jumps over {}\n",
                    i * 7919 % 1000,
                    i * 104_729 % 9973
                )
            })
            .collect::<String>()
            .into_bytes()
    }

    /// `lzma_text` of tests/core.rs.
    pub fn text() -> Vec<u8> {
        (0..2000)
            .map(|i: u32| format!("line {i}: the quick brown fox {}\n", i * 7919 % 1000))
            .collect::<String>()
            .into_bytes()
    }

    /// `legacy_mixed` of tests/core.rs.
    pub fn mixed() -> Vec<u8> {
        let mut x: u32 = 12345;
        let noise: Vec<u8> = (0..9000)
            .map(|_| {
                x = x.wrapping_mul(1103515245).wrapping_add(12345) & 0x7fff_ffff;
                ((x >> 16) & 0xff) as u8
            })
            .collect();
        let text = text();
        [&text[..20000], &noise, &text[..30000]].concat()
    }

    /// Checks a fixture against its own eager decoding.
    fn self_consistent(codec: &Codec, path: &str) {
        let input = read(path);
        assert_on_demand(codec, &input, &eager(codec, &input));
    }

    #[test]
    fn lzfse_is_on_demand() {
        let random: Vec<u8> = (0..70000u32)
            .map(|i| ((i * 131 + (i >> 3)) & 0xff) as u8)
            .collect();
        assert_on_demand(&Codec::Lzfse, &read("data/lzfse/text.lzfse"), &text());
        assert_on_demand(&Codec::Lzfse, &read("data/lzfse/rnd.lzfse"), &random);
        assert_on_demand(
            &Codec::Lzfse,
            &read("data/lzfse/small.lzfse"),
            b"hello lzvn hello lzvn hello lzvn small input\n",
        );
        assert_on_demand(
            &Codec::Lzfse,
            &read("data/lzfse/lines.lzfse"),
            &lines_n(14000),
        );
    }

    #[test]
    fn lz4_frames_are_on_demand() {
        let big = read("data/lz4/lines.lz4");
        assert_on_demand(&Codec::Lz4Frame, &big, &lines());
        for path in [
            "fixtures/external/lz4/bottles.txt.lz4",
            "fixtures/external/lz4/uncompressed-block.lz4",
            "fixtures/external/lz4-legacy/legacy.lz4",
        ] {
            self_consistent(&Codec::Lz4Frame, path);
        }
        // A skippable frame, a frame and a legacy frame, concatenated.
        let legacy = read("fixtures/external/lz4-legacy/legacy.lz4");
        let mut input = vec![0x5a, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 1, 2, 3];
        input.extend_from_slice(&big);
        input.extend_from_slice(&legacy);
        let expected = [lines(), eager(&Codec::Lz4Frame, &legacy)].concat();
        assert_on_demand(&Codec::Lz4Frame, &input, &expected);
    }

    #[test]
    fn lz4_block_ignores_zero_padding() {
        // "abcabcabcabcabc!" then zeros, as a fixed-size slot leaves it.
        let block = [0x38, b'a', b'b', b'c', 3, 0, 0x10, b'!', 0, 0, 0, 0];
        assert_eq!(eager(&Codec::Lz4Block, &block), b"abcabcabcabcabc!");
    }

    #[test]
    fn framed_snappy_is_on_demand() {
        assert_on_demand(
            &Codec::SnappyFramed,
            &read("data/snappy/lines.sz"),
            &lines(),
        );
        self_consistent(&Codec::SnappyFramed, "fixtures/synthetic/snappy/hello.sz");
    }

    #[test]
    fn lzop_is_on_demand() {
        let text_lzo = read("data/lzo/text.lzo");
        let mixed_lzo = read("data/lzo/mixed.lzo");
        assert_on_demand(&Codec::Lzop, &text_lzo, &text());
        assert_on_demand(&Codec::Lzop, &mixed_lzo, &mixed());
        // Concatenated members.
        let input = [&text_lzo[..], &text_lzo, &mixed_lzo, &text_lzo, &text_lzo].concat();
        let expected = [text(), text(), mixed(), text(), text()].concat();
        assert_on_demand(&Codec::Lzop, &input, &expected);
    }

    #[test]
    fn pbz_is_on_demand() {
        for path in ["data/pbz/lines-lzfse.aar", "data/pbz/lines-lzma.aar"] {
            let input = read(path);
            let expected = eager(&Codec::Pbz, &input);
            // An Apple Archive holding the text.
            assert!(
                expected.starts_with(b"AA01")
                    && expected.windows(lines().len()).any(|w| w == lines()),
                "{path}"
            );
            assert_on_demand(&Codec::Pbz, &input, &expected);
        }
        for path in [
            "synthetic/pbzx/Payload",
            "external/pbzx/pbz4.aar",
            "external/pbzx/pbze.aar",
            "external/pbzx/pbzz.aar",
        ] {
            self_consistent(&Codec::Pbz, &format!("fixtures/{path}"));
        }
    }

    #[test]
    fn wim_resources_are_on_demand() {
        let (codec, input, expected) = wim_resource();
        assert_on_demand(&codec, &input, &expected);
    }

    /// A WIM resource (its codec, encoded bytes and decoded bytes).
    pub fn wim_resource() -> (Codec, Vec<u8>, Vec<u8>) {
        // LZX chunks (32 KiB each) and stored ones, the last one short.
        let lzx = read("data/cab/wim-chunk.lzx");
        let lzx_out = eager(
            &Codec::Lzx(fillyfoal::codec::lzx::Params::wim_chunk(32768)),
            &lzx,
        );
        assert_eq!(lzx_out.len(), 32768);
        let text = lines();
        let stored: Vec<&[u8]> = text.chunks(32768).collect();
        let chunks: Vec<(&[u8], &[u8])> = vec![
            (&lzx, &lzx_out),
            (stored[0], stored[0]),
            (&lzx, &lzx_out),
            (&lzx, &lzx_out),
            (stored[1], stored[1]),
            (&lzx, &lzx_out),
            (&lzx, &lzx_out),
            (&lzx, &lzx_out),
            (&lzx, &lzx_out),
            (&text[..1000], &text[..1000]),
        ];
        let mut table = Vec::new();
        let mut body = Vec::new();
        for (i, (data, _)) in chunks.iter().enumerate() {
            if i > 0 {
                table.extend_from_slice(&(body.len() as u32).to_le_bytes());
            }
            body.extend_from_slice(data);
        }
        let input = [table, body].concat();
        let expected: Vec<u8> = chunks
            .iter()
            .flat_map(|(_, out)| out.iter().copied())
            .collect();
        let codec = Codec::WimResource(wim::Resource {
            kind: wim::Kind::Lzx,
            chunk: 32768,
            original: expected.len() as u64,
        });
        (codec, input, expected)
    }

    #[test]
    fn unix_compress_is_on_demand() {
        let random: Vec<u8> = (0..70000u32)
            .map(|i| ((i * 131 + (i >> 3)) & 0xff) as u8)
            .collect();
        assert_on_demand(&Codec::UnixCompress, &read("data/compress/text.Z"), &text());
        assert_on_demand(
            &Codec::UnixCompress,
            &read("data/compress/text12.Z"),
            &text(),
        );
        assert_on_demand(&Codec::UnixCompress, &read("data/compress/rnd.Z"), &random);
        assert_on_demand(
            &Codec::UnixCompress,
            &read("data/compress/lines.Z"),
            &lines(),
        );
    }
}

/// The sample the LZMA-family test files were made from (`xz` 5.8 CLI):
/// text lines with x86 CALLs and ARM64 BLs mixed in, so the BCJ filters
/// have work to do. `lzma_sample(2000)` is a prefix of `lzma_sample(7500)`.
fn lzma_sample(records: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut x: u32 = 12345;
    for i in 0..records {
        x = x.wrapping_mul(1103515245).wrapping_add(12345) & 0x7fff_ffff;
        out.extend_from_slice(
            format!("line {i}: the quick brown fox {}\n", (x >> 16) & 0xff).as_bytes(),
        );
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
    std::fs::read(format!(
        "{}/tests/data/lzma/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// Decodes `input` fed in 4 KiB pieces and returns the input consumed.
fn lzma_consumed(codec: &Codec, input: &[u8]) -> usize {
    let mut decoder = codec.decoder().unwrap();
    let mut out = Vec::new();
    let mut fed = 0;
    loop {
        let eof = fed == input.len();
        match decoder
            .decode(&input[..fed], eof, &mut out, 16 * 1024, 1 << 30)
            .unwrap()
        {
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
    for name in [
        "small-sha256.xz",
        "small-none.xz",
        "small-arm64.xz",
        "small-delta.xz",
        "small-x86-delta.xz",
        "small-x86-dict4k.xz",
    ] {
        assert_on_demand(&Codec::Xz, &lzma_file(name), &small);
    }
}

#[test]
fn lzma_is_on_demand() {
    let big = lzma_sample(7500);
    assert_on_demand(&Codec::LzmaAlone, &lzma_file("big.lzma"), &big);
    assert_on_demand(&Codec::Lzma2 { dict: None }, &lzma_file("big.lzma2"), &big);
    let props = fillyfoal::codec::lzma::Props::from_byte(0x5d).unwrap();
    let raw = lzma_file("big.lzma1");
    assert_on_demand(
        &Codec::LzmaRaw {
            props,
            size: None,
            dict: None,
        },
        &raw,
        &big,
    );
    assert_on_demand(
        &Codec::LzmaRaw {
            props,
            size: Some(big.len()),
            dict: None,
        },
        &raw,
        &big,
    );
    assert_on_demand(
        &Codec::LzmaRaw {
            props,
            size: Some(1000),
            dict: None,
        },
        &raw,
        &big[..1000],
    );
}

#[test]
fn lzma_family_consumes_exactly() {
    let props = fillyfoal::codec::lzma::Props::from_byte(0x5d).unwrap();
    let cases = [
        (Codec::Xz, "big-streams.xz"),
        (Codec::Xz, "small-x86-delta.xz"),
        (Codec::LzmaAlone, "big.lzma"),
        (Codec::Lzma2 { dict: None }, "big.lzma2"),
        (
            Codec::LzmaRaw {
                props,
                size: None,
                dict: None,
            },
            "big.lzma1",
        ),
        // A known size and an end marker as well: the marker is consumed.
        (
            Codec::LzmaRaw {
                props,
                size: Some(lzma_sample(7500).len()),
                dict: None,
            },
            "big.lzma1",
        ),
    ];
    for (codec, name) in cases {
        let data = lzma_file(name);
        let trailing = [data.clone(), b"trailing data".to_vec()].concat();
        assert_eq!(lzma_consumed(&codec, &data), data.len(), "{name}");
        assert_eq!(
            lzma_consumed(&codec, &trailing),
            data.len(),
            "{name} with trailing data"
        );
    }
}

/// Decodes `input` (fed in 64 KiB pieces) while releasing everything the
/// decoder allows after every step, reassembling the output from what was
/// released. Returns the output and the most output and input ever held.
pub fn released(codec: &Codec, input: &[u8]) -> (Vec<u8>, usize, usize) {
    let mut decoder = codec.decoder().unwrap();
    let (mut out, mut held_in) = (Vec::new(), Vec::new());
    let mut done = Vec::new();
    let mut fed = 0;
    let (mut max_out, mut max_in) = (0, 0);
    loop {
        let eof = fed == input.len();
        let status = decoder
            .decode(&held_in, eof, &mut out, 16 * 1024, 1 << 30)
            .unwrap();
        max_out = max_out.max(out.len());
        max_in = max_in.max(held_in.len());
        let n = decoder.releasable_input().min(held_in.len());
        decoder.release_input(n);
        held_in.drain(..n);
        let n = decoder.releasable_output(out.len()).min(out.len());
        decoder.release_output(n);
        done.extend(out.drain(..n));
        match status {
            Status::Done => {
                done.extend(out);
                return (done, max_out, max_in);
            }
            Status::More => {}
            Status::NeedInput => {
                assert!(!eof, "decoder wants input after the end");
                let to = (fed + 65_536).min(input.len());
                held_in.extend_from_slice(&input[fed..to]);
                fed = to;
            }
        }
    }
}

/// Releasing gives the same output, and holds at most `max_out` bytes of
/// output (the window plus a step) and about a few pieces of input.
pub fn assert_releases(codec: &Codec, input: &[u8], expected: &[u8], max_out: usize) {
    let (out, held_out, held_in) = released(codec, input);
    assert!(out == expected, "{codec:?}: output differs when releasing");
    assert!(
        held_out <= max_out,
        "{codec:?}: held {held_out} bytes of output (> {max_out})"
    );
    assert!(
        held_in <= 4 * 65_536 + 1024,
        "{codec:?}: held {held_in} bytes of input"
    );
}

#[test]
fn inflate_releases() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/lazy/big.zlib"
    ))
    .unwrap();
    let expected: Vec<u8> = (0..64u64 << 20)
        .map(|i| ((i * 7) + (i >> 12)) as u8)
        .collect();
    assert_releases(
        &Codec::Zlib,
        &data,
        &expected,
        32 * 1024 + 2 * 16 * 1024 + 65_536,
    );
}

/// Releasing for the LZ-family, chunked and stream-cipher codecs, on the
/// real-encoder data of `mod lz`.
mod lz_releases {
    use super::assert_releases;
    use super::lz::{eager, lines, lines_n, mixed, read, text, wim_resource};
    use fillyfoal::codec::Codec;
    use fillyfoal::codec::crypto::stream::{Key, ZipCryptoKeys};

    const STEPS: usize = 2 * 16 * 1024;

    #[test]
    fn lzfse_releases() {
        // The window, plus a block (the encoder's are up to about 200 KiB).
        let max = fillyfoal::codec::lzfse::WINDOW + STEPS + 256 * 1024;
        assert_releases(
            &Codec::Lzfse,
            &read("data/lzfse/lines.lzfse"),
            &lines_n(14000),
            max,
        );
        let words = read("data/lzfse/words.lzfse");
        let expected = eager(&Codec::Lzfse, &words);
        assert_eq!(expected.len(), 2_493_885);
        assert_releases(&Codec::Lzfse, &words, &expected, max);
    }

    #[test]
    fn lz4_frames_release() {
        // Linked 64 KiB blocks: the 64 KiB window, plus a block.
        let big = read("data/lz4/lines.lz4");
        assert_releases(&Codec::Lz4Frame, &big, &lines(), 65_536 + STEPS + 65_536);
        // A skippable frame, a frame and a legacy frame, concatenated.
        let legacy = read("fixtures/external/lz4-legacy/legacy.lz4");
        let mut input = vec![0x5a, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 1, 2, 3];
        input.extend_from_slice(&big);
        input.extend_from_slice(&legacy);
        let expected = [lines(), eager(&Codec::Lz4Frame, &legacy)].concat();
        assert_releases(&Codec::Lz4Frame, &input, &expected, 65_536 + STEPS + 65_536);
    }

    #[test]
    fn framed_snappy_releases() {
        // Independent chunks of at most 64 KiB: only the last step is held.
        assert_releases(
            &Codec::SnappyFramed,
            &read("data/snappy/lines.sz"),
            &lines(),
            STEPS + 65_536,
        );
    }

    #[test]
    fn lzop_releases() {
        let text_lzo = read("data/lzo/text.lzo");
        let mixed_lzo = read("data/lzo/mixed.lzo");
        let input = [&text_lzo[..], &text_lzo, &mixed_lzo, &text_lzo, &text_lzo].concat();
        let expected = [text(), text(), mixed(), text(), text()].concat();
        // Independent blocks of up to 256 KiB.
        assert_releases(&Codec::Lzop, &input, &expected, STEPS + 256 * 1024);
    }

    #[test]
    fn pbz_releases() {
        for path in ["data/pbz/lines-lzfse.aar", "data/pbz/lines-lzma.aar"] {
            let input = read(path);
            let expected = eager(&Codec::Pbz, &input);
            // Independent 64 KiB chunks.
            assert_releases(&Codec::Pbz, &input, &expected, STEPS + 65_536);
        }
    }

    #[test]
    fn wim_resources_release() {
        let (codec, input, expected) = wim_resource();
        // Independent 32 KiB chunks; the table is copied out of the input.
        assert_releases(&codec, &input, &expected, STEPS + 32 * 1024);
    }

    #[test]
    fn unix_compress_releases() {
        let random: Vec<u8> = (0..70000u32)
            .map(|i| ((i * 131 + (i >> 3)) & 0xff) as u8)
            .collect();
        // Output is never read back: a step (and a string) at most.
        let max = STEPS + 65_536;
        assert_releases(
            &Codec::UnixCompress,
            &read("data/compress/text.Z"),
            &text(),
            max,
        );
        assert_releases(
            &Codec::UnixCompress,
            &read("data/compress/text12.Z"),
            &text(),
            max,
        );
        assert_releases(
            &Codec::UnixCompress,
            &read("data/compress/rnd.Z"),
            &random,
            max,
        );
        assert_releases(
            &Codec::UnixCompress,
            &read("data/compress/lines.Z"),
            &lines(),
            max,
        );
        let words = read("data/compress/words.Z");
        let expected = eager(&Codec::UnixCompress, &words);
        assert_eq!(expected.len(), 2_493_885);
        assert_releases(&Codec::UnixCompress, &words, &expected, max);
    }

    /// The raw DEFLATE stream of tests/data/lazy/big.zlib and its 64 MiB
    /// output.
    fn big_deflate() -> (Vec<u8>, Vec<u8>) {
        let zlib = read("data/lazy/big.zlib");
        let raw = zlib[2..zlib.len() - 4].to_vec();
        let expected: Vec<u8> = (0..64u64 << 20)
            .map(|i| ((i * 7) + (i >> 12)) as u8)
            .collect();
        (raw, expected)
    }

    /// ZipCrypto encryption (with a 12-byte header), through the
    /// decryption keys: the keystream byte is what decrypting 0 yields.
    fn zipcrypto_encrypt(password: &[u8], plain: &[u8]) -> Vec<u8> {
        let mut keys = ZipCryptoKeys::new(password);
        [&[0x5au8; 12][..], plain]
            .concat()
            .into_iter()
            .map(|p| {
                let c = p ^ keys.clone().decrypt(0);
                keys.decrypt(c);
                c
            })
            .collect()
    }

    fn deflate_after(cipher: Codec) -> Codec {
        Codec::chain(
            "decrypt+deflate",
            "decrypt+deflate (lazy)",
            vec![cipher, Codec::Deflate],
        )
    }

    #[test]
    fn zipcrypto_deflate_chain_releases() {
        let max = 32 * 1024 + STEPS + 65_536;
        let codec = deflate_after(Codec::ZipCrypto(Key::new(b"fillyfoal".to_vec())));
        // The deflated member of tests/fixtures/external/zip/zipcrypto.zip.
        let zip = read("fixtures/external/zip/zipcrypto.zip");
        let le16 = |at: usize| usize::from(u16::from_le_bytes([zip[at], zip[at + 1]]));
        let le32 = |at: usize| u32::from_le_bytes(zip[at..at + 4].try_into().unwrap()) as usize;
        assert_eq!(&zip[..4], b"PK\x03\x04");
        assert_eq!(le16(8), 8, "deflated");
        let data = 30 + le16(26) + le16(28);
        let member = &zip[data..data + le32(18)];
        let expected = eager(&codec, member);
        assert_eq!(expected.len(), le32(22));
        assert_releases(&codec, member, &expected, max);
        // 64 MiB through the chain.
        let (raw, expected) = big_deflate();
        assert_releases(
            &codec,
            &zipcrypto_encrypt(b"fillyfoal", &raw),
            &expected,
            max,
        );
    }

    #[test]
    fn ctr_and_rc4_release() {
        let max = 32 * 1024 + STEPS + 65_536;
        let (raw, expected) = big_deflate();
        // Both are their own inverse.
        let aes = Codec::AesCtrLe(Key::new((0..32u8).collect::<Vec<u8>>()));
        assert_releases(
            &deflate_after(aes.clone()),
            &eager(&aes, &raw),
            &expected,
            max,
        );
        let rc4 = Codec::Rc4(Key::new(b"fillyfoal".to_vec()));
        assert_releases(
            &deflate_after(rc4.clone()),
            &eager(&rc4, &raw),
            &expected,
            max,
        );
        // On their own, with the last AES block partial.
        let odd = &lines()[..100_001];
        assert_releases(&aes, &eager(&aes, odd), odd, STEPS + 16);
        assert_releases(&rc4, &eager(&rc4, odd), odd, STEPS);
    }
}

/// zstd: within a frame, output before its window (Window_Size, or the
/// content size of a single-segment frame) goes; between frames, all of it.
#[test]
fn zstd_releases() {
    let lines = zstd_bzip2_lines();
    // A 512 KiB window: held output is the window, a step and a 128 KiB block.
    let one = zstd_bzip2_data("zstd", "lines-1.zst");
    assert_releases(
        &Codec::Zstd,
        &one,
        &lines,
        512 * 1024 + 2 * 16 * 1024 + 128 * 1024,
    );
    assert_releases(
        &Codec::ZstdFrame,
        &one,
        &lines,
        512 * 1024 + 2 * 16 * 1024 + 128 * 1024,
    );
    // Single-segment frames (of 150,000 and 700,250 bytes), released between
    // frames.
    let frames = zstd_bzip2_data("zstd", "lines-frames.zst");
    assert_releases(
        &Codec::Zstd,
        &frames,
        &lines,
        700_250 + 2 * 16 * 1024 + 128 * 1024,
    );
    assert_releases(
        &Codec::ZstdFrame,
        &frames,
        &lines[..150_000],
        150_000 + 2 * 16 * 1024 + 128 * 1024,
    );
    // The content checksum is checked as output is released.
    let mut bad = one.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    let mut d = Codec::Zstd.decoder().unwrap();
    let mut out = Vec::new();
    let err = loop {
        match d.decode(&bad, true, &mut out, 16 * 1024, 1 << 30) {
            Ok(Status::More) => {
                let n = d.releasable_output(out.len());
                d.release_output(n);
                out.drain(..n);
            }
            Ok(s) => break format!("{s:?}"),
            Err(e) => break e.message,
        }
    };
    assert_eq!(err, "zstd: content checksum mismatch");
}

/// bzip2: blocks never refer to earlier output, so all of it goes.
#[test]
fn bzip2_releases() {
    let lines = zstd_bzip2_lines();
    // 100k blocks (-1): a step's worth plus a block.
    assert_releases(
        &Codec::Bzip2,
        &zstd_bzip2_data("bzip2", "lines-1.bz2"),
        &lines,
        2 * 16 * 1024 + 100_000,
    );
    // Two streams (-9 and -3).
    assert_releases(
        &Codec::Bzip2,
        &zstd_bzip2_data("bzip2", "lines-streams.bz2"),
        &lines,
        2 * 16 * 1024 + 900_000,
    );
    let (out, _, _) = released(&Codec::Bzip2, &zstd_bzip2_data("bzip2", "mixed-1.bz2"));
    assert!(out == zstd_bzip2_mixed());
}

fn data_file(path: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn eager_decode(codec: &Codec, input: &[u8]) -> Vec<u8> {
    fillyfoal::codec::pipeline::decode_all(codec.decoder().unwrap().as_mut(), input, 1 << 30)
        .unwrap()
}

/// Brotli: output before the window (`2^WBITS - 16`) goes; longer
/// distances are dictionary words, which do not read the output.
#[test]
fn brotli_releases() {
    // 300,000 bytes in several meta-blocks with a 2^18 window.
    let words = data_file("brotli/words.q1.br");
    let expected = eager_decode(&Codec::Brotli, &words);
    assert_eq!(
        (expected.len(), fillyfoal::codec::crc32(&expected)),
        (300_000, 0xe11b_b7a0)
    );
    assert_releases(
        &Codec::Brotli,
        &words,
        &expected,
        262_144 + 2 * 16 * 1024 + 65_536,
    );
    // The other streams (dictionary words and transforms, a 2^10 window,
    // uncompressed meta-blocks), released and fed in pieces: each is a
    // single meta-block or fits its window, so only consumed input goes.
    for name in [
        "prose.w10.br",
        "prose.q11.br",
        "dict.q11.br",
        "transforms.br",
        "struct.q11.br",
        "noise.br",
        "text.w16.br",
        "zeros.br",
        "empty.br",
    ] {
        let input = data_file(&format!("brotli/{name}"));
        let expected = eager_decode(&Codec::Brotli, &input);
        let (out, _, _) = released(&Codec::Brotli, &input);
        assert!(out == expected, "{name}");
        // (Byte-at-a-time feeding retries a whole meta-block per byte.)
        assert!(
            chunked(&Codec::Brotli, &input, 4096, 16 * 1024) == expected,
            "{name}"
        );
    }
    let text = data_file("brotli/text.w16.br");
    assert_on_demand(&Codec::Brotli, &text, &eager_decode(&Codec::Brotli, &text));
}

/// A cabinet's folders: (compression type, the folder's data blocks).
fn cab_folders(cab: &[u8]) -> Vec<(u16, std::ops::Range<usize>)> {
    let u16le = |o: usize| u16::from_le_bytes([cab[o], cab[o + 1]]);
    let u32le = |o: usize| u32::from_le_bytes(cab[o..o + 4].try_into().unwrap()) as usize;
    (0..usize::from(u16le(26)))
        .map(|i| {
            let at = 36 + 8 * i;
            let start = u32le(at);
            let mut end = start;
            for _ in 0..u16le(at + 4) {
                end += 8 + usize::from(u16le(end + 4));
            }
            (u16le(at + 6), start..end)
        })
        .collect()
}

/// CAB folders and raw LZX: no method reads `out` back (MSZIP keeps its
/// own 32 KiB dictionary, Quantum and LZX their own history), so all output
/// goes.
#[test]
fn cab_and_lzx_release() {
    use fillyfoal::codec::{cab::Folder, lzx};
    for name in ["mszip.cab", "lzx16.cab", "lzx21.cab", "quantum.cab"] {
        let cab = data_file(&format!("cab/{name}"));
        for (kind, range) in cab_folders(&cab) {
            let codec = Codec::CabFolder(Folder {
                kind,
                data_reserve: 0,
            });
            let data = &cab[range];
            let expected = eager_decode(&codec, data);
            assert_releases(&codec, data, &expected, 2 * 16 * 1024 + 32 * 1024);
            if kind & 0x0f != 3 {
                continue;
            }
            // The blocks' data concatenated is a raw LZX stream of 32 KiB
            // frames.
            let (mut raw, mut at, mut len) = (Vec::new(), 0, 0u64);
            while at < data.len() {
                let packed = usize::from(u16::from_le_bytes([data[at + 4], data[at + 5]]));
                len += u64::from(u16::from_le_bytes([data[at + 6], data[at + 7]]));
                raw.extend_from_slice(&data[at + 8..at + 8 + packed]);
                at += 8 + packed;
            }
            let codec = Codec::Lzx(lzx::Params {
                len: Some(len),
                ..lzx::Params::cab((kind >> 8 & 0x1f) as u8)
            });
            assert!(eager_decode(&codec, &raw) == expected, "{name}: raw LZX");
            assert_releases(&codec, &raw, &expected, 2 * 16 * 1024 + 32 * 1024);
        }
    }
}

#[test]
fn lzma_family_releases() {
    let big = lzma_sample(7500);
    let small = lzma_sample(2000);
    let step = 2 * 16 * 1024;
    // A 4 KiB dictionary (`xz --lzma2=dict=4KiB`, `--format=lzma
    // --lzma1=dict=4KiB`): the window slides, holding the dictionary plus
    // a step and at most one match.
    assert_releases(
        &Codec::Xz,
        &lzma_file("big-dict4k.xz"),
        &big,
        4096 + step + 512,
    );
    assert_releases(
        &Codec::LzmaAlone,
        &lzma_file("big-dict4k.lzma"),
        &big,
        4096 + step + 512,
    );
    // 64 KiB blocks: a block's output goes once it ends (its 8 MiB
    // dictionary holds all of it until then).
    assert_releases(&Codec::Xz, &lzma_file("big-blocks.xz"), &big, 65_536 + step);
    // Filtered blocks decode into a private window: `out` holds a step.
    assert_releases(&Codec::Xz, &lzma_file("big-x86.xz"), &big, step + 1024);
    for name in [
        "small-delta.xz",
        "small-x86-delta.xz",
        "small-x86-dict4k.xz",
        "small-arm64.xz",
    ] {
        assert_releases(&Codec::Xz, &lzma_file(name), &small, step + 1024);
    }
    // Two streams with padding, and single blocks whose dictionary is
    // larger than the data.
    for name in ["big-streams.xz", "big.xz"] {
        assert_releases(&Codec::Xz, &lzma_file(name), &big, big.len());
    }
    for name in ["small-sha256.xz", "small-none.xz"] {
        assert_releases(&Codec::Xz, &lzma_file(name), &small, small.len());
    }
    assert_releases(&Codec::LzmaAlone, &lzma_file("big.lzma"), &big, big.len());
    // Raw LZMA and LZMA2 are not told their dictionary size: they release
    // input as they go, and output only before a dictionary reset or at
    // the end.
    assert_releases(
        &Codec::Lzma2 { dict: None },
        &lzma_file("big.lzma2"),
        &big,
        big.len(),
    );
    let props = fillyfoal::codec::lzma::Props::from_byte(0x5d).unwrap();
    assert_releases(
        &Codec::LzmaRaw {
            props,
            size: None,
            dict: None,
        },
        &lzma_file("big.lzma1"),
        &big,
        big.len(),
    );
    assert_releases(
        &Codec::LzmaRaw {
            props,
            size: Some(1000),
            dict: None,
        },
        &lzma_file("big.lzma1"),
        &big[..1000],
        1000,
    );
}

/// Raw LZMA given its dictionary size (as zip, 7z, SWF and lzip containers
/// record it) releases output before the dictionary: the stream of the
/// 4 KiB-dictionary `.lzma` file, without its 13-byte header.
#[test]
fn raw_lzma_with_a_known_dictionary_releases() {
    let file = lzma_file("big-dict4k.lzma");
    let expected = fillyfoal::codec::pipeline::decode_all(
        Codec::LzmaAlone.decoder().unwrap().as_mut(),
        &file,
        1 << 30,
    )
    .unwrap();
    let props = fillyfoal::codec::lzma::Props::from_byte(file[0]).unwrap();
    let dict = u32::from_le_bytes(file[1..5].try_into().unwrap());
    assert_eq!(dict, 4096);
    let codec = Codec::LzmaRaw {
        props,
        size: Some(expected.len()),
        dict: Some(dict),
    };
    assert_releases(&codec, &file[13..], &expected, 4096 + 2 * 16 * 1024 + 512);
    // The LZMA2 property byte: (2 | (p & 1)) << (p / 2 + 11), 40 = 4 GiB - 1.
    assert_eq!(fillyfoal::codec::lzma::lzma2_dict(0), Some(4096));
    assert_eq!(fillyfoal::codec::lzma::lzma2_dict(18), Some(2 << 20));
    assert_eq!(fillyfoal::codec::lzma::lzma2_dict(19), Some(3 << 20));
    assert_eq!(fillyfoal::codec::lzma::lzma2_dict(40), Some(u32::MAX));
}

/// PDF, PostScript, TIFF and Type 1 filters, and AES-CBC: incremental, a
/// bounded step per call. No encoders for these are at hand, so the data is
/// `lz::lines` and `lz::mixed` encoded here from the specs (cross-checked
/// against the PDF reference's LZW example and the decoders' unit tests),
/// plus the eexec section of the Type 1 fixtures.
mod filters {
    use super::assert_on_demand;
    use super::lz::{eager, lines, mixed, read};
    use fillyfoal::codec::Codec;
    use fillyfoal::codec::crypto::cipher::Aes;
    use fillyfoal::codec::crypto::stream::Key;
    use fillyfoal::codec::pipeline::Status;
    use std::collections::HashMap;

    /// Text, a run of zeros, then text with noise.
    fn data() -> Vec<u8> {
        [lines(), vec![0; 5000], mixed()].concat()
    }

    fn with_newlines(text: &[u8], every: usize) -> Vec<u8> {
        text.chunks(every)
            .flat_map(|c| [c, b"\n"].concat())
            .collect()
    }

    fn hex(data: &[u8]) -> Vec<u8> {
        let digits: String = data.iter().map(|b| format!("{b:02x}")).collect();
        [with_newlines(digits.as_bytes(), 64), b">trailing".to_vec()].concat()
    }

    fn ascii85(data: &[u8]) -> Vec<u8> {
        let mut text = Vec::new();
        for group in data.chunks(4) {
            if group == [0; 4] {
                text.push(b'z');
                continue;
            }
            let mut padded = [0u8; 4];
            padded[..group.len()].copy_from_slice(group);
            let mut v = u32::from_be_bytes(padded);
            let mut digits = [0u8; 5];
            for d in digits.iter_mut().rev() {
                *d = (v % 85) as u8 + b'!';
                v /= 85;
            }
            text.extend_from_slice(&digits[..group.len() + 1]);
        }
        [b"<~".to_vec(), with_newlines(&text, 70), b"~>".to_vec()].concat()
    }

    /// RunLength (`end`: with the 128 end marker) or PackBits (no-ops
    /// sprinkled in instead).
    fn runs(data: &[u8], end: bool) -> Vec<u8> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let run = data[i..]
                .iter()
                .take(128)
                .take_while(|&&b| b == data[i])
                .count();
            if run >= 3 {
                out.extend([(257 - run) as u8, data[i]]);
                i += run;
            } else {
                let n = (data.len() - i).min(100);
                if !end && i % 7 == 0 {
                    out.push(128);
                }
                out.push((n - 1) as u8);
                out.extend_from_slice(&data[i..i + n]);
                i += n;
            }
        }
        if end {
            out.push(128);
        }
        out
    }

    /// MSB-first LZW with a clear code first and every 4000 entries.
    fn lzw(data: &[u8], early: bool) -> Vec<u8> {
        let e = usize::from(early);
        let width = |next: usize| match next - 1 + e {
            0..512 => 9,
            512..1024 => 10,
            1024..2048 => 11,
            _ => 12,
        };
        let (mut out, mut acc, mut bits) = (Vec::new(), 0u64, 0u32);
        let mut emit = |code: usize, w: u32| {
            acc = (acc << w) | code as u64;
            bits += w;
            while bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
            }
        };
        let mut dict: HashMap<(usize, u8), usize> = HashMap::new();
        let mut next = 258;
        emit(256, 9);
        let mut w: Option<usize> = None;
        for &c in data {
            let Some(p) = w else {
                w = Some(usize::from(c));
                continue;
            };
            if let Some(&code) = dict.get(&(p, c)) {
                w = Some(code);
                continue;
            }
            emit(p, width(next));
            dict.insert((p, c), next);
            next += 1;
            w = Some(usize::from(c));
            if next == 4000 {
                emit(256, width(next));
                dict.clear();
                next = 258;
            }
        }
        if let Some(p) = w {
            emit(p, width(next));
            next += 1;
        }
        emit(257, width(next));
        emit(0, 7);
        out
    }

    fn paeth(a: u8, b: u8, c: u8) -> u8 {
        let p = i16::from(a) + i16::from(b) - i16::from(c);
        let (pa, pb, pc) = (
            (p - i16::from(a)).abs(),
            (p - i16::from(b)).abs(),
            (p - i16::from(c)).abs(),
        );
        if pa <= pb && pa <= pc {
            a
        } else if pb <= pc {
            b
        } else {
            c
        }
    }

    /// PNG-predicted rows, cycling through the five filter types.
    fn png(data: &[u8], bpp: usize, row: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut prev = vec![0u8; row];
        for (r, raw) in data.chunks(row).enumerate() {
            let kind = (r % 5) as u8;
            out.push(kind);
            for i in 0..raw.len() {
                let left = if i >= bpp { raw[i - bpp] } else { 0 };
                let up = prev[i];
                let up_left = if i >= bpp { prev[i - bpp] } else { 0 };
                let pred = match kind {
                    1 => left,
                    2 => up,
                    3 => ((u16::from(left) + u16::from(up)) / 2) as u8,
                    4 => paeth(left, up, up_left),
                    _ => 0,
                };
                out.push(raw[i].wrapping_sub(pred));
            }
            prev[..raw.len()].copy_from_slice(raw);
        }
        out
    }

    fn tiff(data: &[u8], bpp: usize, row: usize) -> Vec<u8> {
        data.chunks(row)
            .flat_map(|raw| {
                (0..raw.len()).map(move |i| {
                    if i >= bpp {
                        raw[i].wrapping_sub(raw[i - bpp])
                    } else {
                        raw[i]
                    }
                })
            })
            .collect()
    }

    fn eexec(data: &[u8]) -> Vec<u8> {
        let mut r = 55665u16;
        [b"rand".as_slice(), data]
            .concat()
            .iter()
            .map(|&p| {
                let c = p ^ (r >> 8) as u8;
                r = (u16::from(c).wrapping_add(r))
                    .wrapping_mul(52845)
                    .wrapping_add(22719);
                c
            })
            .collect()
    }

    fn aes_cbc(key: &[u8], data: &[u8]) -> Vec<u8> {
        let aes = Aes::new(key).unwrap();
        let n = 16 - data.len() % 16;
        let padded = [data, &vec![n as u8; n]].concat();
        let mut prev: [u8; 16] = std::array::from_fn(|i| (i * 37 + 5) as u8);
        let mut out = prev.to_vec();
        for chunk in padded.chunks(16) {
            let mut block: [u8; 16] = chunk.try_into().unwrap();
            for (b, p) in block.iter_mut().zip(prev) {
                *b ^= p;
            }
            aes.encrypt_block(&mut block);
            out.extend_from_slice(&block);
            prev = block;
        }
        out
    }

    /// Every case: (codec, encoded, decoded).
    fn cases(data: &[u8]) -> Vec<(Codec, Vec<u8>)> {
        let key = b"0123456789abcdef";
        let mut cases = vec![
            (Codec::AsciiHex, hex(data)),
            (Codec::Ascii85, ascii85(data)),
            (Codec::RunLength, runs(data, true)),
            (Codec::PackBits, runs(data, false)),
            (Codec::Lzw { early_change: true }, lzw(data, true)),
            (
                Codec::Lzw {
                    early_change: false,
                },
                lzw(data, false),
            ),
            (Codec::Eexec { hex: false }, eexec(data)),
            (
                Codec::Eexec { hex: true },
                [&hex(&eexec(data))[..], b"%end"].concat(),
            ),
            (Codec::AesCbc(Key::new(key.to_vec())), aes_cbc(key, data)),
        ];
        for (bpp, row) in [(1, 7), (3, 300), (4, 4096)] {
            cases.push((Codec::PngPredictor { bpp, row }, png(data, bpp, row)));
            cases.push((Codec::TiffPredictor { bpp, row }, tiff(data, bpp, row)));
        }
        cases
    }

    #[test]
    fn filters_are_on_demand() {
        let data = data();
        // Large (output from half the input), and small (byte at a time).
        for sample in [&data[..], &data[..30_000]] {
            for (codec, input) in cases(sample) {
                assert!(eager(&codec, &input) == sample, "{codec:?}");
                assert_on_demand(&codec, &input, sample);
            }
        }
    }

    /// Each call decodes a bounded step, and the whole input is consumed
    /// (data after an end-of-data marker too, as before).
    #[test]
    fn filters_decode_in_bounded_steps() {
        const STEP: usize = 4096;
        let data = data();
        for (codec, input) in cases(&data) {
            let mut decoder = codec.decoder().unwrap();
            let mut out = Vec::new();
            let mut calls = 0;
            loop {
                let before = out.len();
                let status = decoder
                    .decode(&input, true, &mut out, STEP, 1 << 30)
                    .unwrap();
                calls += 1;
                assert!(
                    out.len() - before <= 2 * STEP,
                    "{codec:?}: {} bytes in one call",
                    out.len() - before
                );
                assert!(
                    status != Status::NeedInput,
                    "{codec:?} wants input after the end"
                );
                if status == Status::Done {
                    break;
                }
            }
            assert!(out == data, "{codec:?}: output differs");
            assert!(calls >= data.len() / (2 * STEP), "{codec:?}: {calls} calls");
            assert_eq!(decoder.consumed(), input.len(), "{codec:?}");
        }
    }

    /// Releasing as they go: the filters keep nothing but their state
    /// (the predictors two rows of output).
    #[test]
    fn filters_release() {
        let data = data();
        for (codec, input) in cases(&data) {
            super::assert_releases(&codec, &input, &data, 2 * 16 * 1024 + 4096 + 2 * 4096);
        }
    }

    /// The eexec sections of the Type 1 fixtures, against their eager
    /// decoding.
    #[test]
    fn eexec_fixtures_are_on_demand() {
        for path in [
            "fixtures/synthetic/pfa/tiny.pfa",
            "fixtures/synthetic/pfa/fillytest.pfa",
        ] {
            let file = read(path);
            let at = file.windows(5).position(|w| w == b"eexec").unwrap() + 5;
            let codec = Codec::Eexec { hex: true };
            let expected = eager(&codec, &file[at..]);
            assert!(!expected.is_empty(), "{path}");
            assert_on_demand(&codec, &file[at..], &expected);
        }
    }

    /// Malformed data fails, at the end of the input.
    #[test]
    fn filter_errors() {
        let fails = |codec: &Codec, input: &[u8]| {
            let mut decoder = codec.decoder().unwrap();
            let mut out = Vec::new();
            loop {
                match decoder.decode(input, true, &mut out, 16, 1 << 20) {
                    Ok(Status::Done) => return false,
                    Ok(_) => {}
                    Err(_) => return true,
                }
            }
        };
        let key = Key::new(b"0123456789abcdef".to_vec());
        let good = aes_cbc(b"0123456789abcdef", b"some text");
        assert!(!fails(&Codec::AesCbc(key.clone()), &good));
        assert!(fails(&Codec::AesCbc(key.clone()), &good[..good.len() - 1]));
        assert!(fails(&Codec::AesCbc(key.clone()), &good[..16]));
        assert!(!fails(&Codec::AesCbc(key), b""));
        assert!(fails(&Codec::AesCbc(Key::new(vec![1, 2, 3])), b"x"));
        assert!(fails(&Codec::AsciiHex, b"41 42 4x>"));
        assert!(fails(&Codec::Ascii85, b"9jqo^9~>"));
        assert!(fails(&Codec::RunLength, &[5, b'a']));
        assert!(fails(
            &Codec::Lzw { early_change: true },
            &[0xff, 0xff, 0xff]
        ));
    }
}

/// LZNT1, Xpress (plain and Huffman), PKWARE implode (method 6) and DCL
/// implode: the fixtures of `tests/core.rs` (`tests/data/{xca,implode,dcl}`)
/// decoded on demand, with release, and in bounded steps.
mod xca_implode {
    use super::lz::{eager, mixed, read, text};
    use super::{assert_on_demand, assert_releases, produced_from_prefix};
    use fillyfoal::codec::Codec;
    use fillyfoal::codec::implode::Implode;
    use fillyfoal::codec::pipeline::Status;

    fn noise(n: usize) -> Vec<u8> {
        let mut x: u32 = 12345;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(1103515245).wrapping_add(12345) & 0x7fff_ffff;
                ((x >> 16) & 0xff) as u8
            })
            .collect()
    }

    /// The XCA fixtures' names and decoded data.
    fn xca() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("text", text()),
            (
                "rnd",
                (0..70000u32)
                    .map(|i| ((i * 131 + (i >> 3)) & 0xff) as u8)
                    .collect(),
            ),
            ("zeros", vec![0u8; 150_000]),
            ("noise", noise(9000)),
        ]
    }

    /// Every case: codec, encoded input, decoded output.
    fn cases() -> Vec<(Codec, Vec<u8>, Vec<u8>)> {
        let mut cases = Vec::new();
        for (name, data) in xca() {
            let size = data.len() as u64;
            let lznt1 = read(&format!("data/xca/{name}.lznt1"));
            let xpress = read(&format!("data/xca/{name}.xpress"));
            let xpressh = read(&format!("data/xca/{name}.xpressh"));
            cases.push((Codec::Lznt1 { size: None }, lznt1.clone(), data.clone()));
            let mut unit = data.clone();
            unit.resize(unit.len().next_multiple_of(65536), 0);
            cases.push((
                Codec::Lznt1 {
                    size: Some(unit.len() as u64),
                },
                lznt1,
                unit,
            ));
            cases.push((Codec::Xpress { size: None }, xpress.clone(), data.clone()));
            cases.push((Codec::Xpress { size: Some(size) }, xpress, data.clone()));
            cases.push((Codec::XpressHuffman { size }, xpressh, data));
        }
        let text = text();
        let mixed = mixed();
        let runs = [vec![b'A'; 5000], text[..3000].repeat(4), vec![0; 2000]].concat();
        let implode: [(&str, bool, bool, &[u8]); 5] = [
            ("text_8k_lit", true, true, &text),
            ("text_4k", false, false, &text),
            ("mixed_8k", true, false, &mixed),
            ("mixed_4k_lit", false, true, &mixed[..30000]),
            ("runs_4k_lit", false, true, &runs),
        ];
        for (name, large_window, literal_tree, expected) in implode {
            let params = Implode {
                large_window,
                literal_tree,
                size: Some(expected.len() as u64),
            };
            let input = read(&format!("data/implode/{name}.imploded"));
            cases.push((Codec::Implode(params), input.clone(), expected.to_vec()));
            // Without a size, padding bits may decode as one more literal.
            let unsized_codec = Codec::Implode(Implode {
                size: None,
                ..params
            });
            let out = eager(&unsized_codec, &input);
            assert!(out.starts_with(expected) && out.len() <= expected.len() + 1);
            cases.push((unsized_codec, input, out));
        }
        for (name, expected) in [
            ("text_ascii4k", &text[..]),
            ("text_binary2k", &text[..5000]),
            ("mixed_binary1k", &mixed[..]),
        ] {
            let input = read(&format!("data/dcl/{name}.pk"));
            cases.push((Codec::DclImplode, input, expected.to_vec()));
        }
        cases
    }

    #[test]
    fn decode_on_demand() {
        for (codec, input, expected) in cases() {
            assert_on_demand(&codec, &input, &expected);
            // (Highly compressed inputs may need more than half for a step.)
            if input.len() > 4096 && expected.len() >= 64 * 1024 {
                assert!(
                    produced_from_prefix(&codec, &input, input.len() / 2) > 0,
                    "{codec:?}: nothing decoded from the first half of the input"
                );
            }
        }
    }

    #[test]
    fn release() {
        let step = 16 * 1024;
        for (codec, input, expected) in cases() {
            // The window, a step, and a chunk or symbol of slack.
            let window = match codec {
                Codec::XpressHuffman { .. } => 65536,
                Codec::Lznt1 { .. } | Codec::Xpress { .. } | Codec::Implode(_) => 8192,
                _ => 4096,
            };
            assert_releases(&codec, &input, &expected, window + step + 1024);
        }
    }

    /// Decodes all of `input` `step` bytes at a time; returns the output,
    /// the number of calls and the most output a call produced.
    fn stepped(codec: &Codec, input: &[u8], step: usize) -> (Vec<u8>, usize, usize) {
        let mut decoder = codec.decoder().unwrap();
        let mut out = Vec::new();
        let (mut calls, mut most) = (0, 0);
        loop {
            let before = out.len();
            let status = decoder
                .decode(input, true, &mut out, step, 1 << 30)
                .unwrap();
            calls += 1;
            most = most.max(out.len() - before);
            assert!(
                status != Status::NeedInput,
                "{codec:?}: wants input after the end"
            );
            if status == Status::Done {
                return (out, calls, most);
            }
        }
    }

    #[test]
    fn bounded_steps() {
        let step = 4096;
        for (codec, input, expected) in cases() {
            let (out, calls, most) = stepped(&codec, &input, step);
            assert!(out == expected, "{codec:?}: output differs");
            assert!(
                calls >= expected.len() / (3 * step),
                "{codec:?}: {calls} calls"
            );
            // A chunk (and its padding) or a symbol past the step at most.
            assert!(most <= 3 * step, "{codec:?}: {most} bytes in one call");
        }
        // A large NTFS compression unit is zero-filled a step at a time.
        let lznt1 = read("data/xca/text.lznt1");
        let unit = Codec::Lznt1 {
            size: Some(16 << 20),
        };
        let (out, calls, most) = stepped(&unit, &lznt1, step);
        assert_eq!(out.len(), 16 << 20);
        assert!(out[..text().len()] == text()[..]);
        assert!(calls >= (16 << 20) / step && most <= 3 * step);
        // One 16 MiB plain Xpress match is copied across calls: a literal
        // `a`, then offset 1 with a 32-bit length (16 MiB + 3).
        let mut big = vec![0, 0, 0, 0x40, b'a', 7, 0, 0x0f, 0xff, 0, 0];
        big.extend_from_slice(&(16u32 << 20).to_le_bytes());
        let (out, calls, most) = stepped(&Codec::Xpress { size: None }, &big, step);
        assert_eq!(out.len(), (16 << 20) + 4);
        assert!(out.iter().all(|&b| b == b'a'));
        assert!(calls >= (16 << 20) / step && most <= step);
        // Concatenated LZNT1 streams: output from half the input.
        let many = lznt1.repeat(8);
        let codec = Codec::Lznt1 { size: None };
        let all = eager(&codec, &many);
        assert!(all.len() > 256 * 1024);
        assert_on_demand(&codec, &many, &all);
    }
}

/// The token-at-a-time LZ77 decoders (LZ4 and Snappy blocks, LZF, ADC,
/// LZO1X, compressed RTF, SAS row compression): chunk independence on
/// real-encoder data, and large synthetic streams decoded in bounded steps
/// with the window released behind them.
mod lz_units {
    use super::lz::{eager, lines, mixed, read, text};
    use super::{assert_on_demand, assert_releases};
    use fillyfoal::codec::Codec;
    use fillyfoal::codec::pipeline::Status;

    /// Decodes all of `input` 4 KiB at a time, checking that no call
    /// produces more than `max_per_call` bytes.
    fn assert_steps(codec: &Codec, input: &[u8], expected: &[u8], max_per_call: usize) {
        let mut decoder = codec.decoder().unwrap();
        let mut out = Vec::new();
        let mut calls = 0usize;
        loop {
            let before = out.len();
            let status = decoder
                .decode(input, true, &mut out, 4096, 1 << 30)
                .unwrap();
            calls += 1;
            assert!(
                out.len() - before <= max_per_call,
                "{codec:?}: one call produced {} bytes",
                out.len() - before
            );
            if status == Status::Done {
                break;
            }
            assert_eq!(status, Status::More);
        }
        assert!(out == expected, "{codec:?}: output differs");
        assert!(
            calls >= expected.len() / max_per_call,
            "{codec:?}: {calls} calls"
        );
        assert_eq!(decoder.consumed(), input.len(), "{codec:?}: consumed");
    }

    /// Appends a match of `len` bytes `dist` back.
    fn repeat(out: &mut Vec<u8>, dist: usize, len: usize) {
        for _ in 0..len {
            out.push(out[out.len() - dist]);
        }
    }

    fn lz4_len(v: &mut Vec<u8>, mut n: usize) {
        while n >= 255 {
            v.push(255);
            n -= 255;
        }
        v.push(n as u8);
    }

    /// An LZ4 sequence: literals, then a match (`len` >= 4) unless last.
    fn lz4_seq(v: &mut Vec<u8>, lit: &[u8], m: Option<(usize, usize)>) {
        let ml = m.map_or(0, |(_, len)| len - 4);
        v.push(((lit.len().min(15) as u8) << 4) | ml.min(15) as u8);
        if lit.len() >= 15 {
            lz4_len(v, lit.len() - 15);
        }
        v.extend_from_slice(lit);
        if let Some((dist, _)) = m {
            v.extend_from_slice(&(dist as u16).to_le_bytes());
            if ml >= 15 {
                lz4_len(v, ml - 15);
            }
        }
    }

    #[test]
    fn lz4_blocks() {
        // The first block of an `lz4` CLI frame (after FLG, BD, the content
        // size and HC).
        let frame = read("data/lz4/lines.lz4");
        let size = u32::from_le_bytes(frame[15..19].try_into().unwrap()) as usize;
        let block = &frame[19..19 + size];
        assert_on_demand(&Codec::Lz4Block, block, &lines()[..65536]);
        let padded = [block, &[0; 300]].concat();
        assert_on_demand(&Codec::Lz4Block, &padded, &lines()[..65536]);
        // Long literals, a 3 MB match from a few KiB of input, more matches.
        let mut input = Vec::new();
        let mut expected = text();
        lz4_seq(&mut input, &expected.clone(), Some((1000, 3_000_000)));
        repeat(&mut expected, 1000, 3_000_000);
        for i in 0..2000 {
            lz4_seq(&mut input, b"0123456789", Some((65_535 - i, 300 + i)));
            expected.extend_from_slice(b"0123456789");
            repeat(&mut expected, 65_535 - i, 300 + i);
        }
        lz4_seq(&mut input, b"end", None);
        expected.extend_from_slice(b"end");
        assert_on_demand(&Codec::Lz4Block, &input, &expected);
        assert_steps(&Codec::Lz4Block, &input, &expected, 4096);
        assert_releases(&Codec::Lz4Block, &input, &expected, 65_536 + 2 * 16_384);
        // Long zero padding is scanned in pieces too.
        input.extend_from_slice(&[0; 300_000]);
        assert_steps(&Codec::Lz4Block, &input, &expected, 4096);
    }

    #[test]
    fn snappy_raw() {
        // The first chunk of a framed stream (type, length, CRC, data).
        let framed = read("data/snappy/lines.sz");
        assert_eq!(framed[10], 0);
        let len = u32::from_le_bytes([framed[11], framed[12], framed[13], 0]) as usize;
        let raw = &framed[18..14 + len];
        let out = eager(&Codec::Snappy, raw);
        assert!(lines().starts_with(&out) && out.len() > 30_000);
        assert_on_demand(&Codec::Snappy, raw, &out);
        // A long literal, then 20,000 copies.
        let mut expected = text();
        let mut body = vec![62 << 2];
        body.extend_from_slice(&(expected.len() as u32 - 1).to_le_bytes()[..3]);
        body.extend_from_slice(&expected);
        for i in 0..20_000usize {
            let (dist, len) = (1000 + i % 3000, 1 + i % 64);
            body.push((((len - 1) as u8) << 2) | 2);
            body.extend_from_slice(&(dist as u16).to_le_bytes());
            repeat(&mut expected, dist, len);
        }
        let mut input = Vec::new();
        let mut n = expected.len();
        while n >= 0x80 {
            input.push(n as u8 | 0x80);
            n >>= 7;
        }
        input.push(n as u8);
        input.extend_from_slice(&body);
        assert_on_demand(&Codec::Snappy, &input, &expected);
        assert_steps(&Codec::Snappy, &input, &expected, 4096 + 64);
    }

    #[test]
    fn lzf_and_adc() {
        assert_on_demand(&Codec::Lzf, &read("data/lzf/text.lzf"), &text());
        let zv = read("data/lzf/mixed.zv");
        let zv_out = [mixed(), text()].concat();
        assert_on_demand(&Codec::LzfFramed, &zv, &zv_out);
        let gpt = read("data/adc/gpt.adc");
        assert_on_demand(&Codec::Adc, &gpt, &read("data/adc/gpt.bin"));
        let adc = read("data/adc/text.adc");
        assert_on_demand(&Codec::Adc, &adc, &eager(&Codec::Adc, &adc));

        // Concatenated ZV files.
        let input = zv.repeat(10);
        let expected = zv_out.repeat(10);
        assert_on_demand(&Codec::LzfFramed, &input, &expected);
        assert_steps(&Codec::LzfFramed, &input, &expected, 4096 + 65_535);
        assert_releases(&Codec::LzfFramed, &input, &expected, 2 * 16_384 + 65_535);

        // Raw LZF: literals, then 5,000 long matches.
        let mut expected = text();
        let mut input = Vec::new();
        for lit in expected.chunks(32) {
            input.push(lit.len() as u8 - 1);
            input.extend_from_slice(lit);
        }
        for i in 0..5000usize {
            let dist = 8192 - i % 7000;
            input.extend_from_slice(&[(7 << 5) | ((dist - 1) >> 8) as u8, 255, (dist - 1) as u8]);
            repeat(&mut expected, dist, 264);
        }
        assert_on_demand(&Codec::Lzf, &input, &expected);
        assert_steps(&Codec::Lzf, &input, &expected, 4096 + 264);
        assert_releases(&Codec::Lzf, &input, &expected, 8192 + 2 * 16_384);

        // ADC: literals, then 20,000 long matches.
        let mut expected = text();
        let mut input = Vec::new();
        for lit in expected.chunks(128) {
            input.push(0x80 | (lit.len() as u8 - 1));
            input.extend_from_slice(lit);
        }
        for i in 0..20_000usize {
            let dist = 65_536 - i;
            input.push(0x40 | 63);
            input.extend_from_slice(&((dist - 1) as u16).to_be_bytes());
            repeat(&mut expected, dist, 67);
        }
        assert_on_demand(&Codec::Adc, &input, &expected);
        assert_steps(&Codec::Adc, &input, &expected, 4096 + 128);
        assert_releases(&Codec::Adc, &input, &expected, 65_536 + 2 * 16_384);
    }

    /// An LZO1X extended length: zeros worth 255 each, then a final byte.
    fn lzo_len(v: &mut Vec<u8>, n: usize) {
        let k = (n - 1) / 255;
        v.extend(std::iter::repeat_n(0, k));
        v.push((n - 255 * k) as u8);
    }

    #[test]
    fn lzo1x() {
        for (name, expected) in [
            ("text.lzo1x_1", text()),
            ("text.lzo1x_999", text()),
            ("mixed.lzo1x_1_15", mixed()),
        ] {
            let input = read(&format!("data/lzo/{name}"));
            assert_on_demand(&Codec::Lzo1x, &input, &expected);
            // Input after the end marker is ignored.
            let trailing = [&input[..], b"trailing"].concat();
            assert_on_demand(&Codec::Lzo1x, &trailing, &expected);
        }
        // A long literal run, a 3 MB match, the end marker.
        let mut expected = lines();
        let mut input = vec![0];
        lzo_len(&mut input, expected.len() - 3 - 15);
        input.extend_from_slice(&expected);
        let (dist, len) = (10_000usize, 3_000_000usize);
        input.push(32);
        lzo_len(&mut input, len - 2 - 31);
        input.extend_from_slice(&[(((dist - 1) & 63) << 2) as u8, ((dist - 1) >> 6) as u8]);
        input.extend_from_slice(&[0x11, 0, 0]);
        repeat(&mut expected, dist, len);
        assert_on_demand(&Codec::Lzo1x, &input, &expected);
        assert_steps(&Codec::Lzo1x, &input, &expected, 4096);
        assert_releases(&Codec::Lzo1x, &input, &expected, 0xc000 + 2 * 16_384);
    }

    fn rtf(kind: &[u8; 4], raw: usize, body: &[u8]) -> Vec<u8> {
        let mut v = ((body.len() + 12) as u32).to_le_bytes().to_vec();
        v.extend_from_slice(&(raw as u32).to_le_bytes());
        v.extend_from_slice(kind);
        v.extend_from_slice(&[0; 4]);
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn compressed_rtf() {
        let data = lines();
        let data = &data[..data.len() / 8 * 8];
        // LZFu literals (control bytes of 0), a reference to 100 bytes
        // back, and the end marker (a reference to the write position).
        let mut body = Vec::new();
        for group in data.chunks(8) {
            body.push(0);
            body.extend_from_slice(group);
        }
        let back = ((207 + data.len() - 100) & 0xfff) as u16;
        let write = ((207 + data.len() + 11) & 0xfff) as u16;
        body.push(0b11);
        body.extend_from_slice(&((back << 4) | 9).to_be_bytes());
        body.extend_from_slice(&(write << 4).to_be_bytes());
        let lzfu = rtf(b"LZFu", data.len() + 11, &body);
        let tail = data.len() - 100;
        let expected = [data, &data[tail..tail + 11]].concat();
        assert_on_demand(&Codec::Lzfu, &lzfu, &expected);
        assert_steps(&Codec::Lzfu, &lzfu, &expected, 4096 + 17);
        assert_releases(&Codec::Lzfu, &lzfu, &expected, 2 * 16_384);
        // The raw size cuts the output short.
        let short = rtf(b"LZFu", 1000, &body);
        assert_on_demand(&Codec::Lzfu, &short, &data[..1000]);
        // Uncompressed (MELA).
        let mela = rtf(b"MELA", data.len(), data);
        assert_on_demand(&Codec::Lzfu, &mela, data);
        assert_steps(&Codec::Lzfu, &mela, data, 4096);
    }

    #[test]
    fn sas_rows() {
        let data = lines();
        // RLE: long literal copies and long zero runs.
        let mut rle = Vec::new();
        let mut expected = Vec::new();
        for (i, chunk) in data.chunks(4160).enumerate() {
            if chunk.len() == 4160 {
                rle.extend_from_slice(&[0x10, 0]);
                rle.extend_from_slice(chunk);
                expected.extend_from_slice(chunk);
            }
            rle.extend_from_slice(&[0x7f, (i % 256) as u8]);
            expected.resize(expected.len() + 17 + 15 * 256 + i % 256, 0);
        }
        assert_on_demand(&Codec::SasRle, &rle, &expected);
        assert_steps(&Codec::SasRle, &rle, &expected, 4096 + 8500);
        assert_releases(&Codec::SasRle, &rle, &expected, 2 * 16_384 + 8500);

        // RDC: 16 literals, then groups of long runs and back-references.
        let mut rdc = vec![0, 0];
        let mut expected = b"ABCDEFGHIJKLMNOP".to_vec();
        rdc.extend_from_slice(&expected);
        for g in 0..400usize {
            rdc.extend_from_slice(&[0xff, 0xff]);
            for i in 0..8usize {
                // A run of 4,114 bytes, then 271 bytes from 4,098 back.
                rdc.extend_from_slice(&[0x1f, 0xff, (g + i) as u8]);
                expected.resize(expected.len() + 4114, (g + i) as u8);
                rdc.extend_from_slice(&[0x2f, 0xff, 255]);
                repeat(&mut expected, 4098, 271);
            }
        }
        assert_on_demand(&Codec::SasRdc, &rdc, &expected);
        assert_steps(&Codec::SasRdc, &rdc, &expected, 4096 + 4114);
        assert_releases(&Codec::SasRdc, &rdc, &expected, 4098 + 2 * 16_384 + 4114);
    }
}

/// Codecs that used to decode a whole chunk, block or stream per call: BCJ
/// and Delta filters (7z), pbz chunks, PSARC blocks, Yaz0 and BinHex.
mod bounded_steps {
    use super::assert_on_demand;
    use fillyfoal::codec::lzma::Post;
    use fillyfoal::codec::pipeline::{Status, decode_all};
    use fillyfoal::codec::psarc::Entry;
    use fillyfoal::codec::{Codec, adler32};

    const STEP: usize = 16 * 1024;

    fn read(path: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    fn eager(codec: &Codec, input: &[u8]) -> Vec<u8> {
        decode_all(codec.decoder().unwrap().as_mut(), input, 1 << 30).unwrap()
    }

    /// Decodes the whole of `input` `STEP` bytes at a time, checking that
    /// no call produces more than a few steps' worth; returns the output
    /// and the number of calls.
    fn stepped(codec: &Codec, input: &[u8]) -> (Vec<u8>, usize) {
        let mut decoder = codec.decoder().unwrap();
        let mut out = Vec::new();
        for calls in 1.. {
            let before = out.len();
            let status = decoder
                .decode(input, true, &mut out, STEP, 1 << 30)
                .unwrap();
            assert!(
                out.len() - before <= 4 * STEP,
                "{codec:?}: one call produced {} bytes",
                out.len() - before
            );
            match status {
                Status::Done => return (out, calls),
                Status::More => {}
                Status::NeedInput => unreachable!("{codec:?}: wants input after the end"),
            }
        }
        unreachable!()
    }

    /// Pseudo-random bytes with plenty of x86 CALL/JMP opcodes and ARM BL
    /// words.
    fn code(n: usize) -> Vec<u8> {
        let mut x: u32 = 7;
        (0..n)
            .map(|i| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345) & 0x7fff_ffff;
                match (x >> 16) % 7 {
                    0 => 0xe8,
                    1 => 0xeb,
                    2 => 0,
                    3 => 0xff,
                    _ => (x >> 8) as u8 ^ i as u8,
                }
            })
            .collect()
    }

    #[test]
    fn post_filters_are_on_demand() {
        let input = code(300_000);
        for post in [
            Post::X86,
            Post::Arm,
            Post::Arm64,
            Post::Delta(1),
            Post::Delta(4),
        ] {
            let mut expected = input.clone();
            post.apply(&mut expected);
            let codec = Codec::PostFilter(post);
            assert_on_demand(&codec, &input, &expected);
            let (out, calls) = stepped(&codec, &input);
            assert!(out == expected && calls > 10, "{post:?}: {calls} calls");
        }
        // Small inputs, chunked byte by byte too.
        let input = code(5000);
        for post in [Post::X86, Post::Arm, Post::Delta(3)] {
            let mut expected = input.clone();
            post.apply(&mut expected);
            assert_on_demand(&Codec::PostFilter(post), &input, &expected);
        }
    }

    /// A stored-block zlib stream of `data`.
    fn zlib_stored(data: &[u8]) -> Vec<u8> {
        let mut z = vec![0x78, 0x01];
        let blocks: Vec<&[u8]> = data.chunks(65_535).collect();
        for (i, block) in blocks.iter().enumerate() {
            z.push(u8::from(i + 1 == blocks.len()));
            let len = block.len() as u16;
            z.extend_from_slice(&len.to_le_bytes());
            z.extend_from_slice(&(!len).to_le_bytes());
            z.extend_from_slice(block);
        }
        z.extend_from_slice(&adler32(data).to_be_bytes());
        z
    }

    #[test]
    fn large_pbz_chunks_take_many_steps() {
        let data = code(1 << 20);
        // One stored chunk, then one zlib chunk, of 1 MiB each.
        let mut pbz = b"pbzz".to_vec();
        pbz.extend_from_slice(&(1u64 << 20).to_be_bytes());
        for body in [data.clone(), zlib_stored(&data)] {
            pbz.extend_from_slice(&(data.len() as u64).to_be_bytes());
            pbz.extend_from_slice(&(body.len() as u64).to_be_bytes());
            pbz.extend_from_slice(&body);
        }
        let expected = [data.clone(), data.clone()].concat();
        let (out, calls) = stepped(&Codec::Pbz, &pbz);
        assert!(out == expected && calls > 64, "{calls} calls");
        assert_on_demand(&Codec::Pbz, &pbz, &expected);
    }

    #[test]
    fn large_psarc_blocks_take_many_steps() {
        let data = code(3 << 20);
        // 1 MiB blocks: stored whole (0), zlib, and stored by length.
        let block = 1 << 20;
        let z = zlib_stored(&data[block..2 * block]);
        let input = [&data[..block], &z, &data[2 * block..]].concat();
        let codec = Codec::Psarc(Entry {
            block_size: block as u32,
            size: data.len() as u64,
            blocks: vec![0, z.len() as u32, block as u32].into(),
        });
        let (out, calls) = stepped(&codec, &input);
        assert!(out == data && calls > 3 * 64, "{calls} calls");
        assert_on_demand(&codec, &input, &data);
    }

    /// Yaz0 of `data` (a multiple of 8 bytes) as literals, then a run of
    /// its last byte as copies.
    fn yaz0(data: &[u8], run: usize) -> (Vec<u8>, Vec<u8>) {
        assert!(data.len().is_multiple_of(8));
        let mut out = Vec::new();
        for group in data.chunks(8) {
            out.push(0xff);
            out.extend_from_slice(group);
        }
        let mut expected = data.to_vec();
        let last = *data.last().unwrap();
        let mut copies = Vec::new();
        let mut left = run;
        while left > 0 {
            let n = left.min(0x111);
            copies.push([0x00, 0x00, (n - 0x12) as u8]);
            expected.extend(std::iter::repeat_n(last, n));
            left -= n;
        }
        for group in copies.chunks(8) {
            out.push(0);
            out.extend(group.iter().flatten());
        }
        (out, expected)
    }

    #[test]
    fn yaz0_is_on_demand() {
        let file = read("fixtures/synthetic/yaz0/icon.szs");
        let size = u32::from_be_bytes(file[4..8].try_into().unwrap()) as u64;
        let codec = Codec::Yaz0 { size };
        let expected = eager(&codec, &file[16..]);
        assert_eq!(expected.len() as u64, size);
        assert_on_demand(&codec, &file[16..], &expected);

        let (input, expected) = yaz0(&code(600_000), 0x111 * 2000);
        let codec = Codec::Yaz0 {
            size: expected.len() as u64,
        };
        assert_on_demand(&codec, &input, &expected);
        let (out, calls) = stepped(&codec, &input);
        assert!(out == expected && calls > 64, "{calls} calls");
    }

    /// BinHex 6-bit text of `data` (already run-length encoded), in lines
    /// of 64 characters.
    fn binhex(data: &[u8]) -> Vec<u8> {
        const ALPHABET: &[u8] =
            b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";
        let mut out = Vec::new();
        for chunk in data.chunks(3) {
            let mut w = [0u8; 3];
            w[..chunk.len()].copy_from_slice(chunk);
            let v = u32::from(w[0]) << 16 | u32::from(w[1]) << 8 | u32::from(w[2]);
            for i in 0..=chunk.len() {
                out.push(ALPHABET[(v >> (18 - 6 * i) & 63) as usize]);
                if out.len() % 65 == 64 {
                    out.push(b'\n');
                }
            }
        }
        out
    }

    #[test]
    fn binhex_is_on_demand() {
        for path in ["ReadMe.hqx", "tiny.hqx"] {
            let file = read(&format!("fixtures/synthetic/binhex/{path}"));
            let start = file.iter().position(|&b| b == b':').unwrap() + 1;
            let end = start + file[start..].iter().position(|&b| b == b':').unwrap();
            let input = &file[start..end];
            let expected = eager(&Codec::BinHex, input);
            assert!(!expected.is_empty());
            assert_on_demand(&Codec::BinHex, input, &expected);
        }
        // Text with runs: each 0x90 0xff repeats the byte before 254 times.
        let mut raw = Vec::new();
        let mut expected = Vec::new();
        for (i, b) in code(200_000).into_iter().enumerate() {
            let b = if b == 0x90 { 0x91 } else { b };
            raw.push(b);
            expected.push(b);
            if i % 50 == 0 {
                raw.extend_from_slice(&[0x90, 0xff]);
                expected.extend(std::iter::repeat_n(b, 254));
            }
        }
        let input = binhex(&raw);
        assert_on_demand(&Codec::BinHex, &input, &expected);
        let (out, calls) = stepped(&Codec::BinHex, &input);
        assert!(out == expected && calls > 64, "{calls} calls");
    }
}

// ---------------------------------------------------------------------------
// ACE and StuffIt

fn fixture(path: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{path}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// Decodes all of `input` `step` bytes at a time: the output, and how much
/// each call produced.
fn per_call(codec: &Codec, input: &[u8], step: usize) -> (Vec<u8>, Vec<usize>) {
    let mut decoder = codec.decoder().unwrap();
    let mut out = Vec::new();
    let mut sizes = Vec::new();
    loop {
        let before = out.len();
        let status = decoder
            .decode(input, true, &mut out, step, 1 << 30)
            .unwrap();
        sizes.push(out.len() - before);
        assert_ne!(
            status,
            Status::NeedInput,
            "{codec:?}: wants input after the end"
        );
        if status == Status::Done {
            return (out, sizes);
        }
    }
}

type AceFile = (fillyfoal::codec::ace::Member, std::ops::Range<usize>);

/// The files of an ACE archive: header fields and packed data.
fn ace_files(archive: &[u8]) -> Vec<AceFile> {
    let u32_at = |at: usize| u32::from_le_bytes(archive[at..at + 4].try_into().unwrap());
    let mut at = 0;
    let mut out = Vec::new();
    while at + 7 <= archive.len() {
        let size = usize::from(u16::from_le_bytes([archive[at + 2], archive[at + 3]]));
        let end = at + 4 + size;
        if archive[at + 4] == 0 {
            at = end;
            continue;
        }
        let packed = u32_at(at + 7) as usize;
        let member = fillyfoal::codec::ace::Member {
            packed: packed as u64,
            size: u32_at(at + 11).into(),
            crc: u32_at(at + 23),
            method: archive[at + 27],
        };
        out.push((member, end..end + packed));
        at = end + packed;
    }
    out
}

/// The codec and input for `files` decoded as one (solid) stream.
fn ace_stream(archive: &[u8], files: &[AceFile]) -> (Codec, Vec<u8>) {
    let members: Vec<_> = files.iter().map(|(m, _)| *m).collect();
    let input = files
        .iter()
        .flat_map(|(_, r)| archive[r.clone()].to_vec())
        .collect();
    let codec = Codec::Ace(fillyfoal::codec::ace::Params {
        members: members.into(),
    });
    (codec, input)
}

/// ACE (LZ77, and blocked with its DELTA, EXE, SOUND and PIC modes):
/// chunking, releasing, and a large solid stream decoded once, a bounded
/// run per call.
#[test]
fn ace_is_on_demand() {
    for (name, solid) in [
        ("lz77.ace", false),
        ("blocked.ace", false),
        ("solid.ace", true),
    ] {
        let archive = fixture(&format!("synthetic/ace/{name}"));
        let files = ace_files(&archive);
        let groups: Vec<Vec<_>> = if solid {
            vec![files]
        } else {
            files.into_iter().map(|f| vec![f]).collect()
        };
        for group in groups {
            let (codec, input) = ace_stream(&archive, &group);
            let expected = eager_decode(&codec, &input);
            let mut at = 0;
            for (m, _) in &group {
                let size = m.size as usize;
                let data = &expected[at..at + size];
                assert_eq!(fillyfoal::codec::ace::ace_crc32(data), m.crc, "{name}");
                at += size;
            }
            assert_eq!(at, expected.len());
            assert_on_demand(&codec, &input, &expected);
            assert_releases(&codec, &input, &expected, 64 * 1024);
        }
    }

    // blocked.ace's files over and over as one solid stream (a file never
    // refers to the files before it, so each round decodes the same).
    let archive = fixture("synthetic/ace/blocked.ace");
    let files = ace_files(&archive);
    let (codec, one) = ace_stream(&archive, &files);
    let round = eager_decode(&codec, &one);
    let many: Vec<_> = (0..400).flat_map(|_| files.clone()).collect();
    let (codec, input) = ace_stream(&archive, &many);
    let expected = round.repeat(400);
    assert!(expected.len() > 512 * 1024);
    assert_on_demand(&codec, &input, &expected);
    assert_releases(&codec, &input, &expected, 64 * 1024);
    let step = 16 * 1024;
    let (out, sizes) = per_call(&codec, &input, step);
    assert!(out == expected);
    assert!(
        sizes.len() >= expected.len() / (2 * step),
        "{} calls",
        sizes.len()
    );
    let most = sizes.iter().max().unwrap();
    assert!(*most <= 2 * step, "{most} bytes in one call");
}

/// The forks of a classic StuffIt archive: method, packed data, size, CRC.
fn sit_forks(archive: &[u8]) -> Vec<(u8, std::ops::Range<usize>, usize, u16)> {
    let u32_at = |h: &[u8], o: usize| u32::from_be_bytes(h[o..o + 4].try_into().unwrap()) as usize;
    let u16_at = |h: &[u8], o: usize| u16::from_be_bytes([h[o], h[o + 1]]);
    let mut at = 22;
    let mut out = Vec::new();
    while at + 112 <= archive.len() {
        let h = &archive[at..at + 112];
        at += 112;
        if h[0] >= 32 {
            continue;
        }
        for (method, size, packed, crc) in [
            (h[0], u32_at(h, 84), u32_at(h, 92), u16_at(h, 100)),
            (h[1], u32_at(h, 88), u32_at(h, 96), u16_at(h, 102)),
        ] {
            if packed > 0 {
                out.push((method & 0x0f, at..at + packed, size, crc));
            }
            at += packed;
        }
    }
    out
}

fn sit_codec(method: u8, size: usize, crc: Option<u16>) -> Codec {
    Codec::StuffIt(fillyfoal::codec::stuffit::Params {
        method,
        size: size as u64,
        crc,
    })
}

/// StuffIt forks of every method: chunking, releasing, and small steps.
#[test]
fn stuffit_is_on_demand() {
    let mut methods = Vec::new();
    let archive = fixture("synthetic/stuffit/methods.sit");
    for (method, range, size, crc) in sit_forks(&archive) {
        let codec = sit_codec(method, size, (method != 15).then_some(crc));
        let input = &archive[range];
        let expected = eager_decode(&codec, input);
        assert_eq!(expected.len(), size, "method {method}");
        assert_eq!(fillyfoal::codec::crc::crc16_arc(&expected), crc);
        assert_on_demand(&codec, input, &expected);
        assert_releases(&codec, input, &expected, 3 * 64 * 1024);
        // Small steps: many calls, each a bounded run (Arsenic's
        // block symbols and transform count as work too).
        let step = 256;
        let (out, sizes) = per_call(&codec, input, step);
        assert!(out == expected, "method {method}");
        assert!(sizes.len() > size / (8 * step), "method {method}");
        let most = sizes.iter().max().unwrap();
        assert!(
            *most <= 8 * step,
            "method {method}: {most} bytes in one call"
        );
        methods.push(method);
    }
    methods.sort_unstable();
    methods.dedup();
    assert_eq!(methods, [0, 1, 2, 3, 5, 13, 15]);
}

/// Large RLE90 and Huffman forks (built here), decoded from half their
/// input and a bounded run per call.
#[test]
fn stuffit_large_forks() {
    let mut x: u32 = 7;
    let mut next = || {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345) & 0x7fff_ffff;
        x >> 16
    };
    // RLE90: literals, escaped 0x90s and runs.
    let (mut rle, mut plain) = (Vec::new(), Vec::new());
    while plain.len() < 700_000 {
        let r = next();
        if r % 7 == 0 && !plain.is_empty() {
            let n = (r % 250 + 2) as u8;
            rle.extend([0x90, n]);
            let last = *plain.last().unwrap();
            plain.extend(std::iter::repeat_n(last, usize::from(n) - 1));
        } else {
            let b = (r % 256) as u8;
            if b == 0x90 {
                rle.extend([0x90, 0]);
            } else {
                rle.push(b);
            }
            plain.push(b);
        }
    }
    // Huffman: a = 0, b = 10, c = 11 after the tree 0 1a 0 1b 1c.
    let mut bits: Vec<bool> = Vec::new();
    let byte = |bits: &mut Vec<bool>, v: u8| bits.extend((0..8).rev().map(|i| v >> i & 1 == 1));
    bits.extend([false, true]);
    byte(&mut bits, b'a');
    bits.extend([false, true]);
    byte(&mut bits, b'b');
    bits.push(true);
    byte(&mut bits, b'c');
    let mut text = Vec::new();
    for _ in 0..600_000 {
        let (sym, code): (u8, &[bool]) = match next() % 4 {
            0 | 1 => (b'a', &[false]),
            2 => (b'b', &[true, false]),
            _ => (b'c', &[true, true]),
        };
        text.push(sym);
        bits.extend_from_slice(code);
    }
    let huff: Vec<u8> = bits
        .chunks(8)
        .map(|c| {
            c.iter()
                .enumerate()
                .fold(0u8, |v, (i, &b)| v | u8::from(b) << (7 - i))
        })
        .collect();
    for (method, input, expected) in [(1u8, rle, plain), (3, huff, text)] {
        let codec = sit_codec(method, expected.len(), None);
        assert!(eager_decode(&codec, &input) == expected, "method {method}");
        assert_on_demand(&codec, &input, &expected);
        assert_releases(&codec, &input, &expected, 3 * 16 * 1024);
        let step = 16 * 1024;
        let (_, sizes) = per_call(&codec, &input, step);
        assert!(sizes.len() > expected.len() / step);
        assert!(*sizes.iter().max().unwrap() <= step + 256);
    }
}

/// Containers whose blocks used to be decoded whole per call (LZ4 frame
/// and legacy blocks, framed Snappy chunks, lzop blocks and pbz `bv4`
/// blocks): one large block is decoded across many bounded calls, with its
/// checks intact.
mod large_blocks {
    use super::{assert_on_demand, assert_releases};
    use fillyfoal::codec::pipeline::{Status, decode_all};
    use fillyfoal::codec::{Codec, adler32, crc32};

    const STEP: usize = 16 * 1024;

    /// Decodes all of `input` `STEP` bytes at a time, checking each call
    /// produces at most a few steps' worth; returns the output and calls.
    fn stepped(codec: &Codec, input: &[u8]) -> (Vec<u8>, usize) {
        let mut decoder = codec.decoder().unwrap();
        let mut out = Vec::new();
        for calls in 1.. {
            let before = out.len();
            let status = decoder
                .decode(input, true, &mut out, STEP, 1 << 30)
                .unwrap();
            assert!(
                out.len() - before <= 4 * STEP,
                "{codec:?}: one call produced {} bytes",
                out.len() - before
            );
            match status {
                Status::Done => return (out, calls),
                Status::More => {}
                Status::NeedInput => unreachable!("{codec:?}: wants input after the end"),
            }
        }
        unreachable!()
    }

    fn decode(codec: &Codec, input: &[u8]) -> Result<Vec<u8>, String> {
        decode_all(codec.decoder().unwrap().as_mut(), input, 1 << 30).map_err(|e| e.message)
    }

    fn noise(n: usize) -> Vec<u8> {
        let mut x: u32 = 99;
        (0..n)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345) & 0x7fff_ffff;
                (x >> 16) as u8
            })
            .collect()
    }

    /// An LZ4 block of `n` bytes: `a`, a long match of it, then `bbbbb`.
    fn lz4_run(n: usize) -> (Vec<u8>, Vec<u8>) {
        let mut block = vec![0x1f, b'a', 1, 0];
        let mut extra = n - 6 - 4 - 15;
        while extra >= 255 {
            block.push(255);
            extra -= 255;
        }
        block.push(extra as u8);
        block.extend_from_slice(&[0x50, b'b', b'b', b'b', b'b', b'b']);
        let expected = [vec![b'a'; n - 5], vec![b'b'; 5]].concat();
        (block, expected)
    }

    #[test]
    fn lz4_blocks() {
        let (block, run) = lz4_run(4 << 20);
        let data = noise(1 << 20);
        // A frame with independent blocks and block checksums: one
        // compressed and one stored block.
        let mut input = vec![0x04, 0x22, 0x4d, 0x18, 0x70, 0x70, 0];
        input.extend_from_slice(&(block.len() as u32).to_le_bytes());
        input.extend_from_slice(&block);
        input.extend_from_slice(&[0; 4]);
        input.extend_from_slice(&(data.len() as u32 | 0x8000_0000).to_le_bytes());
        input.extend_from_slice(&data);
        input.extend_from_slice(&[0; 4]);
        input.extend_from_slice(&[0; 4]);
        // A legacy frame with the same block.
        input.extend_from_slice(&[0x02, 0x21, 0x4c, 0x18]);
        input.extend_from_slice(&(block.len() as u32).to_le_bytes());
        input.extend_from_slice(&block);
        let expected = [&run[..], &data, &run].concat();
        let (out, calls) = stepped(&Codec::Lz4Frame, &input);
        assert!(out == expected && calls > 256, "{calls} calls");
        assert_on_demand(&Codec::Lz4Frame, &input, &expected);
        assert_releases(&Codec::Lz4Frame, &input, &expected, 2 * STEP + 65_536);
        // A block cut short is still an error.
        assert_eq!(
            decode(&Codec::Lz4Frame, &input[..input.len() - 10]).unwrap_err(),
            "truncated legacy LZ4 block"
        );
    }

    #[test]
    fn snappy_chunks() {
        let n = 1 + 64 * 65_536;
        let mut raw = Vec::new();
        let mut v = n;
        while v >= 0x80 {
            raw.push(v as u8 | 0x80);
            v >>= 7;
        }
        raw.push(v as u8);
        raw.extend_from_slice(&[0x00, b'a']);
        for _ in 0..65_536 {
            raw.extend_from_slice(&[(63 << 2) | 2, 1, 0]);
        }
        let data = noise(1 << 20);
        let mut input = vec![0xff, 6, 0, 0];
        input.extend_from_slice(b"sNaPpY");
        for (kind, body) in [(0u8, &raw), (1, &data)] {
            let len = (body.len() + 4) as u32;
            input.push(kind);
            input.extend_from_slice(&len.to_le_bytes()[..3]);
            input.extend_from_slice(&[0; 4]);
            input.extend_from_slice(body);
        }
        let expected = [vec![b'a'; n], data].concat();
        let (out, calls) = stepped(&Codec::SnappyFramed, &input);
        assert!(out == expected && calls > 256, "{calls} calls");
        assert_on_demand(&Codec::SnappyFramed, &input, &expected);
        // A compressed chunk's window is its own output, which is held.
        assert_releases(&Codec::SnappyFramed, &input, &expected, n + 2 * STEP);
        assert_eq!(
            decode(&Codec::SnappyFramed, &input[..input.len() - 10]).unwrap_err(),
            "truncated Snappy chunk"
        );
    }

    /// An LZO1X stream of `n` bytes of `a`: a literal, then one long match.
    fn lzo_run(n: usize) -> Vec<u8> {
        let mut s = vec![18, b'a', 32];
        let extra = n - 34;
        let k = (extra - 1) / 255;
        s.extend(std::iter::repeat_n(0, k));
        s.push((extra - 255 * k) as u8);
        s.extend_from_slice(&[0, 0, 0x11, 0, 0]);
        s
    }

    /// An lzop member (38-byte header) of `(raw, packed)` blocks, with
    /// Adler-32 and CRC-32 checks of both the data and the compressed bytes.
    fn lzop(blocks: &[(&[u8], &[u8])]) -> Vec<u8> {
        let flags = 0x1u32 | 0x2 | 0x100 | 0x200;
        let mut h = b"\x89LZO\0\r\n\x1a\n".to_vec();
        h.extend_from_slice(&[0x10, 0x30, 0x20, 0x80, 0x09, 0x40, 1, 5]);
        h.extend_from_slice(&flags.to_be_bytes());
        h.extend_from_slice(&[0; 12]);
        h.push(0);
        let check = adler32(&h[9..]);
        h.extend_from_slice(&check.to_be_bytes());
        for (raw, packed) in blocks {
            h.extend_from_slice(&(raw.len() as u32).to_be_bytes());
            h.extend_from_slice(&(packed.len() as u32).to_be_bytes());
            h.extend_from_slice(&adler32(raw).to_be_bytes());
            h.extend_from_slice(&crc32(raw).to_be_bytes());
            if packed.len() < raw.len() {
                h.extend_from_slice(&adler32(packed).to_be_bytes());
                h.extend_from_slice(&crc32(packed).to_be_bytes());
            }
            h.extend_from_slice(packed);
        }
        h.extend_from_slice(&[0; 4]);
        h
    }

    #[test]
    fn lzop_blocks() {
        let run = vec![b'a'; 8 << 20];
        let data = noise(1 << 20);
        let packed = lzo_run(run.len());
        let input = lzop(&[(&run, &packed), (&data, &data)]);
        let expected = [&run[..], &data].concat();
        let (out, calls) = stepped(&Codec::Lzop, &input);
        assert!(out == expected && calls > 512, "{calls} calls");
        assert_on_demand(&Codec::Lzop, &input, &expected);
        assert_releases(&Codec::Lzop, &input, &expected, 2 * STEP + 0xc000);
        // Each check (Adler-32 and CRC-32 of the data, then of the
        // compressed bytes) is still verified.
        for at in [46, 50, 54, 58] {
            let mut bad = input.clone();
            bad[at] ^= 1;
            assert_eq!(
                decode(&Codec::Lzop, &bad).unwrap_err(),
                "LZO: lzop block checksum mismatch",
                "check at {at}"
            );
        }
        // So are the stored block's.
        let mut bad = input.clone();
        let stored_check = 62 + packed.len() + 8;
        bad[stored_check] ^= 1;
        assert_eq!(
            decode(&Codec::Lzop, &bad).unwrap_err(),
            "LZO: lzop block checksum mismatch"
        );
        assert_eq!(
            decode(&Codec::Lzop, &input[..input.len() - 10]).unwrap_err(),
            "LZO: truncated lzop block"
        );
    }

    #[test]
    fn pbz_lz4_blocks() {
        let (block, run) = lz4_run(4 << 20);
        let data = noise(1 << 20);
        let mut chunk = b"bv41".to_vec();
        chunk.extend_from_slice(&(run.len() as u32).to_le_bytes());
        chunk.extend_from_slice(&(block.len() as u32).to_le_bytes());
        chunk.extend_from_slice(&block);
        chunk.extend_from_slice(b"bv4-");
        chunk.extend_from_slice(&(data.len() as u32).to_le_bytes());
        chunk.extend_from_slice(&data);
        chunk.extend_from_slice(b"bv4$");
        let expected = [&run[..], &data].concat();
        let mut input = b"pbz4".to_vec();
        input.extend_from_slice(&(16u64 << 20).to_be_bytes());
        input.extend_from_slice(&(expected.len() as u64).to_be_bytes());
        input.extend_from_slice(&(chunk.len() as u64).to_be_bytes());
        input.extend_from_slice(&chunk);
        let (out, calls) = stepped(&Codec::Pbz, &input);
        assert!(out == expected && calls > 256, "{calls} calls");
        // pbz waits for a whole chunk's input: only chunking is checked.
        assert!(super::chunked(&Codec::Pbz, &input, 65_536, STEP) == expected);
    }
}
