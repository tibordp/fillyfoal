//! Backup formats: a VMA archive's disks are reassembled from its clusters
//! exactly, and a huge, almost empty device costs work in proportion to
//! what the archive stores, not to its size.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{Limits, NodeId, ReadProgress, Span};

fn expand(host: &mut Host, id: NodeId) {
    host.session.expand_more(id, 10_000);
    host.run();
}

fn open(host: &mut Host, path: &[&str]) -> NodeId {
    let mut id = host.root;
    for name in path {
        expand(host, id);
        id = host
            .child(id, name)
            .unwrap_or_else(|| panic!("no {name:?} under:\n{}", host.render()));
    }
    expand(host, id);
    id
}

/// The whole source behind the first child of an expanded node.
fn assembled(host: &mut Host, node: NodeId) -> Vec<u8> {
    let first = host.session.children(node).unwrap().ids[0];
    let source = host.session.node(first).unwrap().span.unwrap().source;
    let span = Span::new(source, 0, host.session.source_len(source));
    loop {
        match host.session.read_step(span, 1_000_000) {
            ReadProgress::Done(bytes) => return bytes,
            ReadProgress::NeedBytes(requests) => host.supply(requests),
            ReadProgress::Yielded => {}
        }
    }
}

/// The fixture's disks are the ones `vma create` was given: a 4 MiB FAT12
/// volume and a 1 MiB disk with one sector of text at 320 KiB.
#[test]
fn vma_disks_are_reassembled() {
    let data = std::fs::read("tests/fixtures/external/proxmox-vma/vm.vma").unwrap();
    let mut host = Host::named("vm.vma", data, Limits::default());

    let small = open(&mut host, &["drive-scsi1"]);
    let disk = assembled(&mut host, small);
    assert_eq!(disk.len(), 1 << 20);
    let text = b"second disk: sparse except for this sector\n";
    assert_eq!(&disk[327_680..327_680 + text.len()], text);
    assert!(disk[..327_680].iter().all(|&b| b == 0));
    assert!(disk[327_680 + text.len()..].iter().all(|&b| b == 0));

    let fat = open(&mut host, &["drive-scsi0"]);
    let disk = assembled(&mut host, fat);
    assert_eq!(disk.len(), 4 << 20);
    assert_eq!(&disk[..3], b"\xeb\x3c\x90");
    assert_eq!(&disk[0x2b..0x34], b"FILLYFOAL");
    let inside = b"A text file inside a FAT volume inside a VMA archive.";
    assert!(disk.windows(inside.len()).any(|w| w == inside));
}

/// A VMA archive with one 1 TiB device of which one 4 KiB block, a
/// million clusters in, is stored.
fn sparse_vma() -> Vec<u8> {
    let mut v = vec![0u8; 12_800];
    v[..8].copy_from_slice(b"VMA\0\0\0\0\x01");
    v[48..52].copy_from_slice(&12_288u32.to_be_bytes()); // blob buffer offset
    v[52..56].copy_from_slice(&512u32.to_be_bytes()); // blob buffer size
    v[56..60].copy_from_slice(&12_800u32.to_be_bytes()); // header size
    // Blob 1: the device name (little-endian length).
    v[12_289..12_291].copy_from_slice(&6u16.to_le_bytes());
    v[12_291..12_297].copy_from_slice(b"disk0\0");
    // Device 1: name blob 1, 1 TiB.
    v[4096 + 32..4096 + 36].copy_from_slice(&1u32.to_be_bytes());
    v[4096 + 40..4096 + 48].copy_from_slice(&(1u64 << 40).to_be_bytes());
    let mut extent = vec![0u8; 512];
    extent[..4].copy_from_slice(b"VMAE");
    extent[6..8].copy_from_slice(&1u16.to_be_bytes());
    let info: u64 = (1 << 48) | (1 << 32) | (1 << 20);
    extent[40..48].copy_from_slice(&info.to_be_bytes());
    v.extend_from_slice(&extent);
    let mut block = vec![0u8; 4096];
    block[..9].copy_from_slice(b"far block");
    v.extend_from_slice(&block);
    v
}

#[test]
fn vma_sparse_device_is_bounded() {
    let mut host = Host::named("sparse.vma", sparse_vma(), Limits::default());
    let disk = open(&mut host, &["disk0"]);
    assert!(
        host.session.work_done() < 200_000,
        "assembling took {} units",
        host.session.work_done()
    );
    let first = host.session.children(disk).unwrap().ids[0];
    let source = host.session.node(first).unwrap().span.unwrap().source;
    assert_eq!(host.session.source_len(source), 1 << 40);
    let far = Span::new(source, (1u64 << 20) * 65_536, 16);
    let bytes = loop {
        match host.session.read_step(far, 1_000_000) {
            ReadProgress::Done(bytes) => break bytes,
            ReadProgress::NeedBytes(requests) => host.supply(requests),
            ReadProgress::Yielded => {}
        }
    };
    assert_eq!(&bytes[..9], b"far block");
}
