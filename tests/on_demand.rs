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

    fn read(path: &str) -> Vec<u8> {
        std::fs::read(format!("{}/tests/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    fn eager(codec: &Codec, input: &[u8]) -> Vec<u8> {
        pipeline::decode_all(codec.decoder().unwrap().as_mut(), input, 1 << 30).unwrap()
    }

    pub fn lines() -> Vec<u8> {
        lines_n(7000)
    }

    fn lines_n(n: u32) -> Vec<u8> {
        (0..n)
            .map(|i| format!("line {i}: the quick brown fox {} jumps over {}\n", i * 7919 % 1000, i * 104_729 % 9973))
            .collect::<String>()
            .into_bytes()
    }

    /// `lzma_text` of tests/core.rs.
    fn text() -> Vec<u8> {
        (0..2000).map(|i: u32| format!("line {i}: the quick brown fox {}\n", i * 7919 % 1000)).collect::<String>().into_bytes()
    }

    /// `legacy_mixed` of tests/core.rs.
    fn mixed() -> Vec<u8> {
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
        let random: Vec<u8> = (0..70000u32).map(|i| ((i * 131 + (i >> 3)) & 0xff) as u8).collect();
        assert_on_demand(&Codec::Lzfse, &read("data/lzfse/text.lzfse"), &text());
        assert_on_demand(&Codec::Lzfse, &read("data/lzfse/rnd.lzfse"), &random);
        assert_on_demand(&Codec::Lzfse, &read("data/lzfse/small.lzfse"), b"hello lzvn hello lzvn hello lzvn small input\n");
        assert_on_demand(&Codec::Lzfse, &read("data/lzfse/lines.lzfse"), &lines_n(14000));
    }

    #[test]
    fn lz4_frames_are_on_demand() {
        let big = read("data/lz4/lines.lz4");
        assert_on_demand(&Codec::Lz4Frame, &big, &lines());
        for path in ["fixtures/lz4/bottles.txt.lz4", "fixtures/lz4/uncompressed-block.lz4", "fixtures/lz4-legacy/legacy.lz4"] {
            self_consistent(&Codec::Lz4Frame, path);
        }
        // A skippable frame, a frame and a legacy frame, concatenated.
        let legacy = read("fixtures/lz4-legacy/legacy.lz4");
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
        assert_on_demand(&Codec::SnappyFramed, &read("data/snappy/lines.sz"), &lines());
        self_consistent(&Codec::SnappyFramed, "fixtures/snappy/hello.sz");
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
            assert!(expected.starts_with(b"AA01") && expected.windows(lines().len()).any(|w| w == lines()), "{path}");
            assert_on_demand(&Codec::Pbz, &input, &expected);
        }
        for name in ["Payload", "pbz4.aar", "pbze.aar", "pbzz.aar"] {
            self_consistent(&Codec::Pbz, &format!("fixtures/pbzx/{name}"));
        }
    }

    #[test]
    fn wim_resources_are_on_demand() {
        // LZX chunks (32 KiB each) and stored ones, the last one short.
        let lzx = read("data/cab/wim-chunk.lzx");
        let lzx_out = eager(&Codec::Lzx(fillyfoal::codec::lzx::Params::wim_chunk(32768)), &lzx);
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
        let expected: Vec<u8> = chunks.iter().flat_map(|(_, out)| out.iter().copied()).collect();
        let codec = Codec::WimResource(wim::Resource {
            kind: wim::Kind::Lzx,
            chunk: 32768,
            original: expected.len() as u64,
        });
        assert_on_demand(&codec, &input, &expected);
    }

    #[test]
    fn unix_compress_is_on_demand() {
        let random: Vec<u8> = (0..70000u32).map(|i| ((i * 131 + (i >> 3)) & 0xff) as u8).collect();
        assert_on_demand(&Codec::UnixCompress, &read("data/compress/text.Z"), &text());
        assert_on_demand(&Codec::UnixCompress, &read("data/compress/text12.Z"), &text());
        assert_on_demand(&Codec::UnixCompress, &read("data/compress/rnd.Z"), &random);
        assert_on_demand(&Codec::UnixCompress, &read("data/compress/lines.Z"), &lines());
    }
}
