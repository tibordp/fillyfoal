//! Compressed virtual disks and files are decoded as far as reads reach:
//! opening the virtual disk of a compressed QCOW2 image or stream-optimized
//! VMDK, or the content of a zisofs file, reads the start of it, not every
//! compressed cluster, grain or block.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{Limits, NodeId};

/// Units of compressed data in each image.
const UNITS: usize = 512;

/// `len` bytes of text naming `unit`.
fn text(unit: usize, len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut line = 0;
    while out.len() < len {
        out.extend_from_slice(format!("unit {unit:05}, line {line:05}\n").as_bytes());
        line += 1;
    }
    out.truncate(len);
    out
}

/// Raw DEFLATE stored blocks holding `data`.
fn deflate_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chunks = data.chunks(0xffff).peekable();
    while let Some(c) = chunks.next() {
        out.push(u8::from(chunks.peek().is_none()));
        out.extend_from_slice(&(c.len() as u16).to_le_bytes());
        out.extend_from_slice(&(!(c.len() as u16)).to_le_bytes());
        out.extend_from_slice(c);
    }
    out
}

/// A zlib stream of stored blocks holding `data`.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    out.extend(deflate_stored(data));
    out.extend_from_slice(&fillyfoal::codec::adler32(data).to_be_bytes());
    out
}

fn put(buf: &mut Vec<u8>, at: usize, bytes: &[u8]) {
    if buf.len() < at + bytes.len() {
        buf.resize(at + bytes.len(), 0);
    }
    buf[at..at + bytes.len()].copy_from_slice(bytes);
}

/// Expands `id` completely.
fn expand(host: &mut Host, id: NodeId) {
    host.session.expand_more(id, 10_000);
    host.run();
}

/// Expands the path of child names from the root, returning the last node.
fn open_path(host: &mut Host, path: &[&str]) -> NodeId {
    let mut id = host.root;
    for name in path {
        expand(host, id);
        id = host.child(id, name).unwrap_or_else(|| {
            panic!("no {name:?} under:\n{}", host.render());
        });
    }
    id
}

/// Opens `path` and expands its last node; returns the bytes read for that
/// last expansion and the rendered tree.
fn bytes_to_open(data: Vec<u8>, name: &str, path: &[&str]) -> (u64, u64, String) {
    let len = data.len() as u64;
    let mut host = Host::named(name, data, Limits::default());
    let id = open_path(&mut host, path);
    let before = host.bytes_supplied;
    expand(&mut host, id);
    (host.bytes_supplied - before, len, host.render())
}

/// QCOW2 version 2, 4 KiB clusters, every cluster compressed.
fn qcow2() -> Vec<u8> {
    const CLUSTER: usize = 4096;
    let tables = UNITS.div_ceil(CLUSTER / 8);
    let mut img = Vec::new();
    put(&mut img, 0, b"QFI\xfb");
    put(&mut img, 4, &2u32.to_be_bytes());
    put(&mut img, 20, &12u32.to_be_bytes()); // cluster bits
    put(&mut img, 24, &((UNITS * CLUSTER) as u64).to_be_bytes());
    put(&mut img, 36, &(tables as u32).to_be_bytes()); // L1 entries
    put(&mut img, 40, &(CLUSTER as u64).to_be_bytes()); // L1 at cluster 1
    // L2 tables after the L1 table, then the compressed clusters, each
    // in 9 sectors (the descriptor counts the 8 after the first).
    let data_at = (2 + tables) * CLUSTER;
    for t in 0..tables {
        let l2 = (2 + t) * CLUSTER;
        put(&mut img, CLUSTER + t * 8, &(l2 as u64).to_be_bytes());
    }
    for k in 0..UNITS {
        let at = data_at + k * 9 * 512;
        let entry = (1u64 << 62) | (8u64 << 58) | at as u64;
        put(&mut img, 2 * CLUSTER + k * 8, &entry.to_be_bytes());
        put(&mut img, at, &deflate_stored(&text(k, CLUSTER)));
    }
    let end = img.len().next_multiple_of(512);
    img.resize(end, 0);
    img
}

/// A stream-optimized VMDK (grain tables up front, as QEMU writes it),
/// 4 KiB grains, every grain compressed behind a grain marker.
fn vmdk() -> Vec<u8> {
    const GRAIN: usize = 4096;
    const GTES: usize = 512;
    let tables = UNITS.div_ceil(GTES);
    let gt_sectors = GTES * 4 / 512;
    let mut img = Vec::new();
    put(&mut img, 0, b"KDMV");
    put(&mut img, 4, &3u32.to_le_bytes());
    put(&mut img, 8, &0x3_0001u32.to_le_bytes()); // newline test, compressed, markers
    put(&mut img, 12, &((UNITS * GRAIN / 512) as u64).to_le_bytes());
    put(&mut img, 20, &((GRAIN / 512) as u64).to_le_bytes());
    put(&mut img, 44, &(GTES as u32).to_le_bytes());
    put(&mut img, 56, &1u64.to_le_bytes()); // grain directory at sector 1
    let first_gt = 2;
    let data_sector = first_gt + tables * gt_sectors;
    put(&mut img, 64, &(data_sector as u64).to_le_bytes()); // overhead
    put(&mut img, 73, b"\n \r\n");
    put(&mut img, 77, &1u16.to_le_bytes());
    for t in 0..tables {
        put(
            &mut img,
            512 + t * 4,
            &((first_gt + t * gt_sectors) as u32).to_le_bytes(),
        );
    }
    for k in 0..UNITS {
        let sector = data_sector + k * 9;
        put(
            &mut img,
            first_gt * 512 + k * 4,
            &(sector as u32).to_le_bytes(),
        );
        let z = zlib_stored(&text(k, GRAIN));
        let mut marker = ((k * GRAIN / 512) as u64).to_le_bytes().to_vec();
        marker.extend_from_slice(&(z.len() as u32).to_le_bytes());
        marker.extend(z);
        put(&mut img, sector * 512, &marker);
    }
    let end = img.len().next_multiple_of(512);
    img.resize(end, 0);
    img
}

fn both32(v: u32) -> Vec<u8> {
    let mut b = v.to_le_bytes().to_vec();
    b.extend_from_slice(&v.to_be_bytes());
    b
}

/// A directory record (`name` raw, `su` its System Use area).
fn record(extent: u32, size: u32, flags: u8, name: &[u8], su: &[u8]) -> Vec<u8> {
    let pad = usize::from(name.len().is_multiple_of(2));
    let len = 33 + name.len() + pad + su.len();
    let mut r = vec![0u8; 33];
    r[0] = len as u8;
    r[2..10].copy_from_slice(&both32(extent));
    r[10..18].copy_from_slice(&both32(size));
    r[25] = flags;
    r[28] = 1; // volume sequence number (both-endian 16-bit)
    r[31] = 1;
    r[32] = name.len() as u8;
    r.extend_from_slice(name);
    r.resize(33 + name.len() + pad, 0);
    r.extend_from_slice(su);
    r
}

/// An ISO 9660 image holding one zisofs file of 32 KiB blocks.
fn zisofs_iso() -> Vec<u8> {
    const SECTOR: usize = 2048;
    const BLOCK: usize = 1 << 15;
    let size = UNITS * BLOCK / 8;
    let blocks = size / BLOCK;
    // The file: header, block pointers, zlib blocks.
    let mut file = Vec::new();
    file.extend_from_slice(&[0x37, 0xe4, 0x53, 0x96, 0xc9, 0xdb, 0xd6, 0x07]);
    file.extend_from_slice(&(size as u32).to_le_bytes());
    file.extend_from_slice(&[4, 15, 0, 0]);
    let table_at = file.len();
    file.resize(table_at + (blocks + 1) * 4, 0);
    for b in 0..blocks {
        let at = file.len() as u32;
        file[table_at + b * 4..table_at + b * 4 + 4].copy_from_slice(&at.to_le_bytes());
        file.extend(zlib_stored(&text(b, BLOCK)));
    }
    let end = file.len() as u32;
    file[table_at + blocks * 4..table_at + blocks * 4 + 4].copy_from_slice(&end.to_le_bytes());

    let root = 18u32;
    let file_at = 19u32;
    let sectors = file_at as usize + file.len().div_ceil(SECTOR);
    let mut img = vec![0u8; sectors * SECTOR];
    let mut pvd = vec![0u8; SECTOR];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[80..88].copy_from_slice(&both32(sectors as u32));
    pvd[120..124].copy_from_slice(&[1, 0, 0, 1]); // volume set size
    pvd[124..128].copy_from_slice(&[1, 0, 0, 1]); // volume sequence number
    pvd[128..132].copy_from_slice(&[0, 8, 8, 0]); // block size 2048
    let root_record = record(root, SECTOR as u32, 2, &[0], &[]);
    pvd[156..156 + 34].copy_from_slice(&root_record);
    pvd[881] = 1;
    put(&mut img, 16 * SECTOR, &pvd);
    put(
        &mut img,
        17 * SECTOR,
        &[255, b'C', b'D', b'0', b'0', b'1', 1],
    );
    let mut zf = b"ZF\x10\x01pz\x04\x0f".to_vec();
    zf.extend_from_slice(&both32(size as u32));
    let mut dir = record(root, SECTOR as u32, 2, &[0], &[]);
    dir.extend(record(root, SECTOR as u32, 2, &[1], &[]));
    dir.extend(record(file_at, file.len() as u32, 0, b"Z.BIN;1", &zf));
    put(&mut img, root as usize * SECTOR, &dir);
    put(&mut img, file_at as usize * SECTOR, &file);
    img
}

#[test]
fn a_compressed_qcow2_disk_is_decoded_on_demand() {
    let (read, len, tree) = bytes_to_open(qcow2(), "c.qcow2", &["Virtual disk"]);
    assert!(tree.contains("unit 00000, line 00000"), "{tree}");
    assert!(read < len / 4, "read {read} of {len} bytes:\n{tree}");
}

#[test]
fn a_stream_optimized_vmdk_is_decoded_on_demand() {
    let (read, len, tree) = bytes_to_open(vmdk(), "s.vmdk", &["Virtual disk"]);
    assert!(tree.contains("unit 00000, line 00000"), "{tree}");
    assert!(read < len / 4, "read {read} of {len} bytes:\n{tree}");
}

#[test]
fn a_zisofs_file_is_decoded_on_demand() {
    let (read, len, tree) = bytes_to_open(
        zisofs_iso(),
        "z.iso",
        &["Root directory", "Z.BIN", "Compressed content", "Content"],
    );
    assert!(tree.contains("unit 00000, line 00000"), "{tree}");
    assert!(read < len / 4, "read {read} of {len} bytes:\n{tree}");
}
