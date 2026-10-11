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
