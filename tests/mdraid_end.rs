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

/// Writes a version 1.0 superblock (RAID1, two disks) at its place near
/// the end of `dev`.
fn put_v10(dev: &mut [u8]) {
    let len = dev.len();
    let at = ((len / 512 - 16) & !7) * 512;
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
    put(dev, at, &sb);
}

#[test]
fn a_version_1_0_superblock_is_found_at_the_end() {
    let mut dev = member();
    put_v10(&mut dev);
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

/// Writes a version 0.90 superblock (RAID1, two disks) in the last whole
/// 64 KiB block of `dev`.
fn put_v090(dev: &mut [u8]) {
    let at = (dev.len() & !0xffff) - 0x10000;
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
        put(dev, at + i * 4, &w.to_le_bytes());
    }
}

#[test]
fn a_version_0_90_superblock_is_found_in_the_last_64_kib() {
    let mut dev = member();
    put_v090(&mut dev);
    let tree = explore(dev);
    assert!(tree.contains("version 0.90"), "{tree}");
    assert!(
        tree.contains("Data — RAID1 data, 960 KiB  [0x0+0xf0000]"),
        "{tree}"
    );
}

// ---------------------------------------------------------------------------
// Identification: the second-phase probe over the deeper tail.

/// Opens `dev` under `name` (identified, not forced) and expands the root;
/// returns the host and every byte range it was asked for.
fn open_identified(name: &str, dev: Vec<u8>) -> (Host, Vec<(u64, u64)>) {
    let mut host = Host::named(
        name,
        dev,
        Limits {
            chunk_size: 4096,
            ..Limits::default()
        },
    );
    host.session.expand(host.root, 100);
    let mut reads = Vec::new();
    loop {
        match host.session.poll(1_000_000) {
            fillyfoal::Progress::Idle => break,
            fillyfoal::Progress::NeedBytes(requests) => {
                reads.extend(requests.iter().map(|r| (r.offset, r.len)));
                host.supply(requests);
            }
            fillyfoal::Progress::Yielded => {}
            other => panic!("unexpected {other:?}"),
        }
    }
    (host, reads)
}

fn format_of(host: &Host, id: fillyfoal::NodeId) -> Option<&'static str> {
    host.session
        .interpretation(id)
        .and_then(|i| i.format)
        .map(|f| f.name)
}

#[test]
fn end_superblocks_are_identified() {
    for put_sb in [put_v10 as fn(&mut [u8]), put_v090] {
        let mut dev = member();
        put_sb(&mut dev);
        let (host, _) = open_identified("member.img", dev);
        assert_eq!(
            format_of(&host, host.root),
            Some("mdraid"),
            "{}",
            host.render()
        );
    }
}

/// An ext2 image made by mke2fs (an external fixture) with room for a
/// superblock after it.
fn ext2_member() -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/external/ext/mke2fs-ext2.img.raw.zst");
    let mut dev = common::fixture_bytes(&path);
    dev.resize(dev.len() + 0x2_0000, 0);
    dev
}

#[test]
fn a_raid1_member_holding_a_file_system_is_identified_as_the_member() {
    // Without a superblock, the image is the file system.
    let (host, _) = open_identified("member.img", ext2_member());
    assert_eq!(format_of(&host, host.root), Some("ext"));
    for put_sb in [put_v10 as fn(&mut [u8]), put_v090] {
        let mut dev = ext2_member();
        put_sb(&mut dev);
        let (mut host, _) = open_identified("member.img", dev);
        assert_eq!(
            format_of(&host, host.root),
            Some("mdraid"),
            "{}",
            host.render()
        );
        // The data, which ends before the superblock, is the file system.
        let data = host.child(host.root, "Data").expect("Data");
        host.session.expand(data, 10);
        host.run();
        assert_eq!(format_of(&host, data), Some("ext"), "{}", host.render());
    }
}

#[test]
fn only_unidentified_files_and_listed_formats_read_the_deeper_tail() {
    // Reads come in 4 KiB chunks; the last one holds the ordinary tail.
    let in_deep_window = |reads: &[(u64, u64)], len: u64| {
        let window = len - fillyfoal::formats::DEEP_TAIL_LEN..len - 4096;
        reads
            .iter()
            .any(|&(at, n)| at < window.end && at + n > window.start)
    };
    // Unrecognised: the second phase reads the deeper tail.
    let (host, reads) = open_identified("unknown.bin", member());
    assert_eq!(format_of(&host, host.root), None);
    assert!(in_deep_window(&reads, LEN as u64), "{reads:x?}");
    // Recognised by the first phase as a format no second-phase probe may
    // take precedence over (an ELF header with no tables): never read.
    let mut elf = member();
    put(&mut elf, 0, b"\x7fELF\x02\x01\x01");
    put(&mut elf, 16, &[2, 0, 0x3e, 0, 1, 0, 0, 0]);
    put(&mut elf, 52, &[64, 0]);
    let (host, reads) = open_identified("a.out", elf);
    assert_eq!(
        format_of(&host, host.root),
        Some("elf"),
        "{}",
        host.render()
    );
    assert!(!in_deep_window(&reads, LEN as u64), "{reads:x?}");
}
