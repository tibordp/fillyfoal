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
