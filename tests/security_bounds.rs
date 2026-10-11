//! Crafted security-format inputs whose structure could make a dissector
//! recurse or work without bound.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::cast_possible_truncation
)]

mod common;

use common::Host;
use fillyfoal::Limits;

/// DER identifier and definite length octets.
fn header(id: u8, len: usize) -> Vec<u8> {
    let mut out = vec![id];
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
    out
}

/// `1.2.840.113549.1.12.10.1.6` (safeContentsBag) as a complete OID TLV.
const SAFE_CONTENTS_BAG: [u8; 13] = [
    0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x06,
];
/// `1.2.840.113549.1.7.1` (data) as a complete OID TLV.
const DATA: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
];

/// A password-less PFX whose only bag is a chain of `depth` nested
/// safeContentsBags. Written outside-in from precomputed lengths, since
/// every level ends where its child ends (no quadratic copying).
fn nested_pfx(depth: usize) -> Vec<u8> {
    // contents[k]: content length of the SafeContents at level k (the
    // innermost, at `depth`, is empty).
    let mut contents = vec![0usize; depth + 1];
    for k in (1..=depth).rev() {
        let seq = header(0x30, contents[k]).len() + contents[k];
        let bag = SAFE_CONTENTS_BAG.len() + header(0xa0, seq).len() + seq;
        contents[k - 1] = header(0x30, bag).len() + bag;
    }
    let mut safe_contents = header(0x30, contents[0]);
    for &child in &contents[1..] {
        let seq = header(0x30, child).len() + child;
        let bag = SAFE_CONTENTS_BAG.len() + header(0xa0, seq).len() + seq;
        safe_contents.extend(header(0x30, bag));
        safe_contents.extend(SAFE_CONTENTS_BAG);
        safe_contents.extend(header(0xa0, seq));
        safe_contents.extend(header(0x30, child));
    }
    let wrap = |id: u8, body: Vec<u8>| [header(id, body.len()), body].concat();
    let content_info =
        |body: Vec<u8>| wrap(0x30, [DATA.to_vec(), wrap(0xa0, wrap(0x04, body))].concat());
    let auth_safe = content_info(wrap(0x30, content_info(safe_contents)));
    wrap(0x30, [vec![0x02, 0x01, 0x03], auth_safe].concat())
}

#[test]
fn pkcs12_nested_safe_contents_stop_at_a_depth_limit() {
    // 40,000 levels (about 1 MB) overflowed the stack before the cap.
    let data = nested_pfx(40_000);
    let mut host = Host::open("deep.p12", data, Limits::default(), None);
    host.session.expand(host.root, 10);
    host.run();
    let contents = host
        .child(host.root, "Contents")
        .expect("identified as PKCS#12");
    host.explore(contents, 64, 100);
    let rendered = host.render();
    assert!(
        rendered.contains("safe contents nested deeper than 8"),
        "{rendered}"
    );
    // The cap bounds the tree, whatever the input's depth.
    assert!(host.session.live_nodes() < 100, "{rendered}");
}
