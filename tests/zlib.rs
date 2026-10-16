//! zlib streams: the probe accepts real streams and leaves text and random
//! data with a valid-looking header alone; large streams decode lazily and
//! have their Adler-32 checked on request.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::formats::{HEAD_LEN, Head, TAIL_LEN};
use fillyfoal::{Limits, NodeId};

/// A zlib stream of stored DEFLATE blocks holding `data`.
fn zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    let mut chunks = data.chunks(0xffff).peekable();
    while let Some(c) = chunks.next() {
        out.push(u8::from(chunks.peek().is_none()));
        out.extend_from_slice(&(c.len() as u16).to_le_bytes());
        out.extend_from_slice(&(!(c.len() as u16)).to_le_bytes());
        out.extend_from_slice(c);
    }
    out.extend_from_slice(&fillyfoal::codec::adler32(data).to_be_bytes());
    out
}

fn identify(data: &[u8]) -> Option<&'static str> {
    let head = &data[..data.len().min(HEAD_LEN as usize)];
    let probe = Head {
        data: head,
        tail: &data[data.len().saturating_sub(TAIL_LEN as usize)..],
        len: data.len() as u64,
        len_known: true,
    };
    fillyfoal::formats::identify_all(&probe, &[], None).map(|f| f.name)
}

/// 2 MiB of numbered binary records (binary, so that the content's own
/// dissector reads only what it shows).
fn big_data() -> Vec<u8> {
    let mut v = Vec::new();
    let mut i = 0u32;
    while v.len() < 2 << 20 {
        v.extend_from_slice(b"\0\x01rec");
        v.extend_from_slice(&i.to_le_bytes());
        v.extend_from_slice(&[0xff; 8]);
        i += 1;
    }
    v
}

#[test]
fn probe_takes_streams_and_leaves_lookalikes() {
    assert_eq!(identify(&zlib_stored(b"hello zlib")), Some("zlib"));
    // A stream larger than the probe's window: identified from its head.
    assert_eq!(identify(&zlib_stored(&big_data())), Some("zlib"));
    // A valid header followed by anything else is not zlib.
    let mut rng = common::Rng(7);
    for &(cmf, flg) in &[(0x78, 0x9c), (0x78, 0x01), (0x78, 0xda), (0x48, 0x4b)] {
        for len in [8usize, 100, 5000, 100_000] {
            let mut data = vec![cmf, flg];
            data.extend((0..len).map(|_| rng.next() as u8));
            assert_ne!(identify(&data), Some("zlib"), "{cmf:#x} {flg:#x} {len}");
        }
    }
    // A whole small stream with a wrong checksum, or with bytes after it.
    let mut bad = zlib_stored(b"hello zlib");
    *bad.last_mut().unwrap() ^= 1;
    assert_ne!(identify(&bad), Some("zlib"));
    let mut extra = zlib_stored(b"hello zlib");
    extra.extend_from_slice(b"junk");
    assert_ne!(identify(&extra), Some("zlib"));
}

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

/// A large stream: the content decodes on demand (opening it reads only
/// the start of the file), and the trailer is checked when expanded.
#[test]
fn large_streams_decode_lazily() {
    let data = big_data();
    let z = zlib_stored(&data);
    let len = z.len() as u64;
    let mut host = Host::named("big.zz", z.clone(), Limits::default());
    open(&mut host, &["Decompressed"]);
    assert!(
        host.bytes_supplied < len / 4,
        "{} of {len} bytes read",
        host.bytes_supplied
    );
    open(&mut host, &["Adler-32"]);
    let tree = host.render();
    assert!(
        tree.contains(&format!("Decompressed size: {}", data.len())),
        "{tree}"
    );
    assert!(!tree.contains("!"), "{tree}");

    // A wrong checksum is reported where it is.
    let mut bad = z;
    let n = bad.len();
    bad[n - 1] ^= 0xff;
    let mut host = Host::named("bad.zz", bad, Limits::default());
    open(&mut host, &["Adler-32"]);
    let tree = host.render();
    assert!(tree.contains("the data decodes to"), "{tree}");
}

/// A small stream is decoded when expanded: its trailer is checked at
/// once, and bytes after the stream are pointed out.
#[test]
fn small_streams_are_checked_at_once() {
    let mut z = zlib_stored(b"hello zlib, hello zlib");
    z.extend_from_slice(b"junk");
    let mut host = Host::open(
        "small.zz",
        z,
        Limits::default(),
        fillyfoal::formats::by_name("zlib"),
    );
    let root = host.root;
    expand(&mut host, root);
    let tree = host.render();
    assert!(tree.contains("22 bytes uncompressed"), "{tree}");
    assert!(tree.contains("4 bytes after the stream"), "{tree}");
}

/// Damage found by the decode of a small stream at expansion is shown on
/// the compressed data at once, not only once its content is expanded.
#[test]
fn small_streams_show_their_damage() {
    // A stored block whose length check (NLEN) does not match.
    let mut z = zlib_stored(b"hello zlib, hello zlib");
    z[5] ^= 0xff;
    let mut host = Host::open(
        "bad.zz",
        z,
        Limits::default(),
        fillyfoal::formats::by_name("zlib"),
    );
    let root = host.root;
    expand(&mut host, root);
    let data = host.child(root, "Compressed data").unwrap();
    let node = host.session.node(data).unwrap();
    assert!(!node.diagnostics.is_empty(), "{}", host.render());
}
