//! decmpfs compression types the macOS fixtures do not carry (`ditto
//! --hfsCompression` writes LZVN in the resource fork, type 8): hand-built
//! attributes and resource forks in the layouts of Apple's `decmpfs.c`
//! and afsctool, decoded by `decmpfs::content` and compared with the
//! bytes they hold. Inline types 1, 3, 7 and 11; resource-fork types 4
//! (zlib behind a resource-fork header and a `cmpf` table) and 12 (LZFSE
//! behind an offset table), each with one chunk stored raw (marker byte)
//! and one compressed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::formats::disk::decmpfs;
use fillyfoal::formats::{Format, Input, Probe};
use fillyfoal::node::Node;
use fillyfoal::{Cx, Limits, Span};

/// The test container: a little-endian u32 attribute length, the
/// `com.apple.decmpfs` attribute, then the resource fork (if any).
async fn container(cx: Cx, input: Input) -> fillyfoal::error::Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 4)).await?;
    let attr_len = u64::from(u32::from_le_bytes(head[..4].try_into().unwrap()));
    let attr = file.sub(4, attr_len);
    let rsrc = file.tail(4 + attr_len);
    let rsrc = (rsrc.len > 0).then_some(rsrc);
    let (_, data) = decmpfs::content(&cx, attr, rsrc).await?;
    cx.emit(Node::new("Content").span(data));
    Ok(())
}

static CONTAINER: Format = Format {
    name: "decmpfs-test",
    title: "decmpfs test container",
    extensions: &[],
    mime: "application/octet-stream",
    probe: Probe::Never,
    dissect: fillyfoal::expander!(container: Input),
};

/// The bytes decmpfs decodes from `attr` and `rsrc`.
fn decode(attr: &[u8], rsrc: &[u8]) -> Vec<u8> {
    let mut data = (attr.len() as u32).to_le_bytes().to_vec();
    data.extend(attr);
    data.extend(rsrc);
    let mut host = Host::open("file", data, Limits::default(), Some(&CONTAINER));
    host.session.expand_more(host.root, 100);
    host.run();
    let id = host
        .child(host.root, "Content")
        .unwrap_or_else(|| panic!("no content:\n{}", host.render()));
    let span: Span = host.session.node(id).unwrap().span.unwrap();
    let diags = &host.session.node(host.root).unwrap().diagnostics;
    assert!(diags.is_empty(), "{diags:?}");
    loop {
        match host.session.read(span) {
            Ok(bytes) => return bytes,
            Err(requests) => host.supply(requests),
        }
    }
}

fn header(kind: u32, size: usize) -> Vec<u8> {
    let mut h = b"fpmc".to_vec();
    h.extend(kind.to_le_bytes());
    h.extend((size as u64).to_le_bytes());
    h
}

fn attr(kind: u32, size: usize, payload: &[u8]) -> Vec<u8> {
    let mut a = header(kind, size);
    a.extend(payload);
    a
}

/// zlib, as stored blocks.
fn zlib(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    let mut chunks = data.chunks(0xffff).peekable();
    if data.is_empty() {
        out.extend([1, 0, 0, 0xff, 0xff]);
    }
    while let Some(c) = chunks.next() {
        out.push(u8::from(chunks.peek().is_none()));
        out.extend((c.len() as u16).to_le_bytes());
        out.extend((!(c.len() as u16)).to_le_bytes());
        out.extend(c);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + u32::from(x)) % 65521;
        b = (b + a) % 65521;
    }
    out.extend((b << 16 | a).to_be_bytes());
    out
}

/// LZVN of literals only: large-literal opcodes (`0xe0`, a length byte,
/// 16 to 271 bytes) and small ones (`0xe1`..`0xef`), then end of stream.
fn lzvn(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let n = rest.len().min(271);
        if n >= 16 {
            out.extend([0xe0, (n - 16) as u8]);
        } else {
            out.push(0xe0 | n as u8);
        }
        out.extend(&rest[..n]);
        rest = &rest[n..];
    }
    out.extend([0x06, 0, 0, 0, 0, 0, 0, 0]);
    out
}

/// LZFSE of one uncompressed block (`bvx-`) and the end of stream.
fn lzfse(data: &[u8]) -> Vec<u8> {
    let mut out = b"bvx-".to_vec();
    out.extend((data.len() as u32).to_le_bytes());
    out.extend(data);
    out.extend(b"bvx$");
    out
}

/// Text of `n` bytes that is not all one byte.
fn text(n: usize) -> Vec<u8> {
    (0..n).map(|i| b"fillyfoal decmpfs "[i % 18]).collect()
}

#[test]
fn inline_types() {
    let small = text(300);
    // Type 1: the bytes themselves.
    assert_eq!(decode(&attr(1, 300, &small), &[]), small);
    // Type 3: zlib, and a payload stored raw after a 0xff marker.
    assert_eq!(decode(&attr(3, 300, &zlib(&small)), &[]), small);
    let mut raw = vec![0xff];
    raw.extend(&small);
    assert_eq!(decode(&attr(3, 300, &raw), &[]), small);
    // Type 7: LZVN, and raw after a 0x06 marker.
    assert_eq!(decode(&attr(7, 300, &lzvn(&small)), &[]), small);
    raw[0] = 0x06;
    assert_eq!(decode(&attr(7, 300, &raw), &[]), small);
    // Type 11: LZFSE, and raw after a marker that is not `b` (afsctool
    // writes 0xcc).
    assert_eq!(decode(&attr(11, 300, &lzfse(&small)), &[]), small);
    raw[0] = 0xcc;
    assert_eq!(decode(&attr(11, 300, &raw), &[]), small);
}

/// The file of the resource-fork tests: one whole 64 KiB chunk (stored
/// raw) and a short second chunk (compressed).
fn two_chunks() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let data = text(0x1_0000 + 500);
    let (a, b) = data.split_at(0x1_0000);
    (data.clone(), a.to_vec(), b.to_vec())
}

#[test]
fn zlib_resource_fork() {
    let (data, first, second) = two_chunks();
    let mut c0 = vec![0xff];
    c0.extend(&first);
    let c1 = zlib(&second);
    // The cmpf table: a count, then (offset, length) pairs from the
    // table's start.
    let table_len = 4 + 2 * 8;
    let mut table = 2u32.to_le_bytes().to_vec();
    table.extend((table_len as u32).to_le_bytes());
    table.extend((c0.len() as u32).to_le_bytes());
    table.extend(((table_len + c0.len()) as u32).to_le_bytes());
    table.extend((c1.len() as u32).to_le_bytes());
    let mut body = table;
    body.extend(&c0);
    body.extend(&c1);
    // A classic resource fork: header (data offset 0x100, map offset,
    // data length, map length), reserved to 0x100, then the resource data
    // with its 4-byte length; the resource map follows (afsctool writes a
    // `cmpf` map; it is not read).
    let data_len = 4 + body.len();
    let mut rsrc = Vec::new();
    rsrc.extend(0x100u32.to_be_bytes());
    rsrc.extend(((0x100 + data_len) as u32).to_be_bytes());
    rsrc.extend((data_len as u32).to_be_bytes());
    rsrc.extend(0x32u32.to_be_bytes());
    rsrc.resize(0x100, 0);
    rsrc.extend((body.len() as u32).to_be_bytes());
    rsrc.extend(&body);
    rsrc.extend([0u8; 0x32]);
    assert_eq!(decode(&header(4, data.len()), &rsrc), data);
}

#[test]
fn lzfse_resource_fork() {
    let (data, first, second) = two_chunks();
    let mut c0 = vec![0xcc];
    c0.extend(&first);
    let c1 = lzfse(&second);
    // Offsets of the chunks and of their end, from the fork's start.
    let table_len = 3 * 4;
    let mut rsrc = Vec::new();
    for off in [
        table_len,
        table_len + c0.len(),
        table_len + c0.len() + c1.len(),
    ] {
        rsrc.extend((off as u32).to_le_bytes());
    }
    rsrc.extend(&c0);
    rsrc.extend(&c1);
    assert_eq!(decode(&header(12, data.len()), &rsrc), data);
    // The same layout with LZVN chunks (type 8, what ditto writes).
    let c1 = lzvn(&second);
    let mut c0 = vec![0x06];
    c0.extend(&first);
    let mut rsrc = Vec::new();
    for off in [
        table_len,
        table_len + c0.len(),
        table_len + c0.len() + c1.len(),
    ] {
        rsrc.extend((off as u32).to_le_bytes());
    }
    rsrc.extend(&c0);
    rsrc.extend(&c1);
    assert_eq!(decode(&header(8, data.len()), &rsrc), data);
}
