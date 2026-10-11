//! md RAID members whose superblock is near the end of the device
//! (versions 1.0 and 0.90), out of the probe window: opened as `mdraid`.
//! The superblocks are written here from mdadm's layouts (`super1.c`,
//! `super0.c`); the kernel used for the other fixtures has no md driver.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::Limits;
use fillyfoal::formats::disk;

const MAGIC: u32 = 0xa92b_4efc;
const LEN: usize = 1 << 20;

fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
    buf[at..at + bytes.len()].copy_from_slice(bytes);
}

fn member() -> Vec<u8> {
    vec![0u8; LEN]
}

/// md's version 1 checksum.
fn checksum(sb: &[u8]) -> u32 {
    let mut sum = 0u64;
    for (i, w) in sb.chunks(4).enumerate() {
        if i != 216 / 4 {
            sum += u64::from(u32::from_le_bytes(w.try_into().unwrap()));
        }
    }
    ((sum & 0xffff_ffff) + (sum >> 32)) as u32
}

fn explore(dev: Vec<u8>) -> String {
    let mut host = Host::open(
        "member.img",
        dev,
        Limits::default(),
        Some(&disk::mdraid::FORMAT),
    );
    host.explore_all();
    host.render()
}

#[test]
fn a_version_1_0_superblock_is_found_at_the_end() {
    let mut dev = member();
    let at = ((LEN / 512 - 16) & !7) * 512;
    let mut sb = vec![0u8; 256 + 2 * 2];
    put(&mut sb, 0, &MAGIC.to_le_bytes());
    put(&mut sb, 4, &1u32.to_le_bytes());
    put(&mut sb, 32, b"fillyfoal:0");
    put(&mut sb, 72, &1u32.to_le_bytes()); // RAID1
    let sectors = (at / 512) as u64;
    put(&mut sb, 80, &sectors.to_le_bytes());
    put(&mut sb, 92, &2u32.to_le_bytes()); // raid disks
    put(&mut sb, 128, &0u64.to_le_bytes()); // data offset
    put(&mut sb, 136, &sectors.to_le_bytes()); // data size
    put(&mut sb, 144, &sectors.to_le_bytes()); // superblock offset (sectors)
    put(&mut sb, 220, &2u32.to_le_bytes()); // max_dev
    put(&mut sb, 256, &[0, 0, 1, 0]);
    let sum = checksum(&sb);
    put(&mut sb, 216, &sum.to_le_bytes());
    put(&mut dev, at, &sb);
    let tree = explore(dev);
    assert!(tree.contains("version 1.0"), "{tree}");
    assert!(tree.contains("RAID1"), "{tree}");
    assert!(!tree.contains("checksum mismatch"), "{tree}");
    // The data runs up to the superblock.
    assert!(
        tree.contains("Data — RAID1 data, 1016 KiB  [0x0+0xfe000]"),
        "{tree}"
    );
}

#[test]
fn a_version_0_90_superblock_is_found_in_the_last_64_kib() {
    let mut dev = member();
    let at = (LEN & !0xffff) - 0x10000;
    let words: [u32; 16] = [
        MAGIC,
        0,
        90,
        0,
        0,
        0x1234_5678,
        1_700_000_000,
        1, // RAID1
        (at / 1024) as u32,
        2,
        2,
        0,
        0,
        1,
        2,
        3,
    ];
    for (i, w) in words.iter().enumerate() {
        put(&mut dev, at + i * 4, &w.to_le_bytes());
    }
    let tree = explore(dev);
    assert!(tree.contains("version 0.90"), "{tree}");
    assert!(
        tree.contains("Data — RAID1 data, 960 KiB  [0x0+0xf0000]"),
        "{tree}"
    );
}
