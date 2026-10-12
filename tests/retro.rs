//! Retro formats beyond what fixtures can show: D64 is known only by its
//! size, so files of those sizes that are not disk images must not be shown
//! as one; NES 2.0 ROM sizes too large for a fixture.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use fillyfoal::formats::{Head, identify};

fn identified(data: &[u8]) -> Option<&'static str> {
    let probe = Head {
        data: &data[..data.len().min(fillyfoal::formats::HEAD_LEN as usize)],
        tail: &data[data
            .len()
            .saturating_sub(fillyfoal::formats::TAIL_LEN as usize)..],
        len: data.len() as u64,
        len_known: true,
    };
    identify(&probe).map(|f| f.name)
}

fn noise(len: usize) -> Vec<u8> {
    let mut rng = common::Rng(0xd64);
    (0..len).map(|_| rng.next() as u8).collect()
}

/// A 40-track-sized blob of noise is offered to D64 (only its size is
/// visible to probes), but without a BAM it is rejected instead of showing
/// a made-up disk name and directory.
#[test]
fn d64_sized_noise_is_not_a_disk() {
    let data = noise(196_608);
    assert_eq!(identified(&data), Some("d64"));
    let render = common::explore("blob.bin", &data);
    assert!(!render.contains("Disk name"), "{render}");
    assert!(!render.contains("Directory"), "{render}");
    assert!(render.contains("no 1541 BAM"), "{render}");
}

/// Text of a D64 size is text.
#[test]
fn d64_sized_text_is_text() {
    let data: Vec<u8> = b"fillyfoal line of text\n"
        .iter()
        .copied()
        .cycle()
        .take(174_848)
        .collect();
    assert_eq!(identified(&data), Some("text"));
}

/// The error-info variants end in one small error code per sector.
#[test]
fn d64_error_block_must_hold_error_codes() {
    let mut data = vec![0u8; 175_531];
    assert_eq!(identified(&data), Some("d64"));
    let n = data.len();
    data[n - 10] = 0xc3;
    assert_ne!(identified(&data), Some("d64"));
}

/// NES 2.0 ROM sizes take their high nibbles from byte 9: PRG LSB 2 with
/// MSB nibble 1 is 258 units of 16 KiB, CHR LSB 0 with MSB nibble 1 is 256
/// units of 8 KiB (the exponent form is pinned by `nes/nes2-exp.nes`).
#[test]
fn nes2_sizes_use_byte_9() {
    let prg = 258 * 16 * 1024;
    let chr = 256 * 8 * 1024;
    let mut data = b"NES\x1a".to_vec();
    data.extend_from_slice(&[2, 0, 0x00, 0x08, 0x00, 0x11, 0, 0, 0, 0, 0, 0]);
    data.resize(16 + prg + chr, 0xea);
    let render = common::explore("big.nes", &data);
    assert!(render.contains("4128 KiB PRG, 2 MiB CHR"), "{render}");
    assert!(!render.contains("Extra data"), "{render}");
}

/// The v5 CHD hunks we decode (LZMA, and CD Deflate with its sync headers
/// and ECC regenerated) match what `chdman extractraw` (0.251) writes,
/// hunk by hunk (SHA-1s of its output, recorded below).
#[test]
fn chd_hunks_decode_like_chdman() {
    use fillyfoal::codec::crypto::{Hash, Sha1};
    let cases: [(&str, &[&str], usize); 2] = [
        (
            "chdman-hd.chd",
            &[
                "50098c101431b63d70901e41a7436b0d496915db",
                "32ef83f804cce2f1fa0a735c6e5d2c50431c2119",
                "6ef31456b520ab62dd8b85973fb7d8a27f98679c",
                "cdad6eae43bc203e63caca07432b0cc61aedc243",
                "3794a637cde268c71aec185ad1b92b981784c8d0",
                "6ef31456b520ab62dd8b85973fb7d8a27f98679c",
                "2e8c7c9c6374a8e45d624b9d211fd3f3ca6ca06d",
                "8e855fc69f67d40af1e63305bd9cdd8b59e57157",
                "6d9d7e864c0e2584839230d00ebf46a556e47914",
                "6ef31456b520ab62dd8b85973fb7d8a27f98679c",
                "85236ae77b9361014231a127580012feacb11ad9",
                "5f18e2418b197ef1fffcbcd70bd687b7d0998e9b",
                "1ceaf73df40e531df3bfb26b4fb7cd95fb7bff1d",
                "1ceaf73df40e531df3bfb26b4fb7cd95fb7bff1d",
                "1ceaf73df40e531df3bfb26b4fb7cd95fb7bff1d",
                "1ceaf73df40e531df3bfb26b4fb7cd95fb7bff1d",
            ],
            // chdman info: 10 LZMA hunks (the others are copies and FLAC).
            10,
        ),
        (
            "chdman-cd.chd",
            &[
                "326bf7a991840c66904900cd9689f589f47310fa",
                "326bf7a991840c66904900cd9689f589f47310fa",
                "af131a11c6580ded7141fa2fa88a6e8c133b6984",
                "326bf7a991840c66904900cd9689f589f47310fa",
                "c2ca8016425aeda8ab12a6ac0751fcc4e7246012",
            ],
            // Two CD Deflate hunks.
            2,
        ),
    ];
    for (file, hashes, want) in cases {
        let path = std::path::Path::new("tests/fixtures/external/chd").join(file);
        let data = std::fs::read(&path).unwrap();
        let hunk_len = if file.contains("-cd") { 19_584 } else { 4096 };
        let mut host = common::Host::named(file, data, fillyfoal::Limits::default());
        let mut id = host.root;
        for name in ["Hunk map (compressed)", "Hunks"] {
            host.session.expand_more(id, 10_000);
            host.run();
            id = host
                .child(id, name)
                .unwrap_or_else(|| panic!("no {name}:\n{}", host.render()));
        }
        host.session.expand_more(id, 10_000);
        host.run();
        let root_source = host.session.node(host.root).unwrap().span.unwrap().source;
        let mut verified = 0;
        for (i, expected) in hashes.iter().enumerate() {
            let Some(hunk) = host.child(id, &format!("Hunk {i}")) else {
                panic!("no hunk {i}:\n{}", host.render());
            };
            host.explore(hunk, 3, 1000);
            // A decoded hunk's children read from its derived source.
            let mut stack = vec![hunk];
            let mut source = None;
            while let Some(n) = stack.pop() {
                if let Some(span) = host.session.node(n).and_then(|n| n.span)
                    && span.source != root_source
                {
                    source = Some(span.source);
                    break;
                }
                if let Some(c) = host.session.children(n) {
                    stack.extend(c.ids.iter().copied());
                }
            }
            let Some(source) = source else { continue };
            let span = fillyfoal::span::Span::new(source, 0, hunk_len);
            let bytes = loop {
                match host.session.read(span) {
                    Ok(b) => break b,
                    Err(requests) => host.supply(requests),
                }
            };
            let mut h = Sha1::new();
            h.update(&bytes);
            let got: String = h.finish().iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(&got, expected, "{file} hunk {i}");
            verified += 1;
        }
        assert_eq!(verified, want, "{file}: hunks decoded\n{}", host.render());
    }
}
