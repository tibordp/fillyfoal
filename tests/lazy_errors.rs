//! What a lazily decoded stream reports when its decoder fails long before
//! the end of a large input: the decoder's own error, not "no progress".
//!
//! The streaming adapter retries a step that failed while more input was
//! still to come, since the failure may only be a shortage of input. Errors
//! that cannot be one (a limit, an unsupported feature) are final at once;
//! ambiguous ones (malformed data, such as a checksum mismatch) are final
//! once the decoder has stalled over a lot of input, and are then reported
//! as the decoder sees them.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::codec::Codec;
use fillyfoal::{Cx, Limits, Node, Result, Span, Value};

/// Raw zstd blocks carrying `len` bytes, the last one marked last.
fn raw_blocks(len: usize) -> Vec<u8> {
    const BLOCK: usize = 128 * 1024;
    let chunk: Vec<u8> = (0..BLOCK).map(|i| (i * 7 + 3) as u8).collect();
    let mut out = Vec::with_capacity(len + len / BLOCK * 3 + 3);
    let mut left = len;
    while left > 0 {
        let n = left.min(BLOCK);
        left -= n;
        let header = (n as u32) << 3 | u32::from(left == 0);
        out.extend_from_slice(&header.to_le_bytes()[..3]);
        out.extend_from_slice(&chunk[..n]);
    }
    out
}

/// A zstd frame of `len` bytes in raw blocks, with a 2 MiB window and,
/// optionally, a one-byte Dictionary_ID.
fn zstd_frame(len: usize, dictionary: bool) -> Vec<u8> {
    let mut out = 0xfd2f_b528u32.to_le_bytes().to_vec();
    out.push(u8::from(dictionary)); // FHD: Dictionary_ID_Flag
    out.push(0x58); // Window_Descriptor: 2 MiB
    if dictionary {
        out.push(7);
    }
    out.extend(raw_blocks(len));
    out
}

const BIG: usize = 70 << 20;

/// Reads the first 4 KiB of `file` decoded with `codec` and emits the
/// outcome as text.
async fn first_page(cx: Cx, (file, codec): (Span, Codec)) -> Result<()> {
    let s = cx.decode_lazy_unsized(file, &codec)?;
    let outcome = match cx.read(s.sub(0, 4096)).await {
        Ok(bytes) => format!("ok: {} bytes", bytes.len()),
        Err(e) => format!("{}: {}", e.kind, e.message),
    };
    cx.emit(Node::new("outcome").value(Value::Text(outcome)));
    Ok(())
}

/// Decodes the start of `data` lazily; returns the outcome and the bytes
/// the host supplied.
fn outcome(data: Vec<u8>, codec: Codec, limits: Limits) -> (String, u64) {
    let file = Span::new(fillyfoal::SourceId::default_host(), 0, data.len() as u64);
    let mut host = Host::new(data, limits);
    host.max_polls = 10_000_000;
    let root = host
        .session
        .add_root(Node::new("stream").lazy(first_page, (file, codec)));
    host.session.expand(root, 10);
    host.run();
    let child = host.session.children(root).unwrap().ids[0];
    let Some(Value::Text(text)) = host.session.node(child).unwrap().value.clone() else {
        panic!("no outcome");
    };
    (text, host.bytes_supplied)
}

/// An error that cannot be a shortage of input (here an unsupported
/// feature) is reported at once, without reading on: a 70 MiB zstd frame
/// using a dictionary says so, like a small one does.
#[test]
fn unsupported_feature_is_reported_at_once_on_a_large_stream() {
    let (small, _) = outcome(zstd_frame(2048, true), Codec::Zstd, Limits::default());
    assert!(
        small.contains("zstd frame using a dictionary"),
        "small: {small}"
    );
    let (big, read) = outcome(zstd_frame(BIG, true), Codec::Zstd, Limits::default());
    assert!(big.contains("zstd frame using a dictionary"), "big: {big}");
    assert!(!big.contains("no progress"), "big: {big}");
    assert!(read <= 1 << 20, "read {read:#x} bytes before reporting it");
    // The same frame without a dictionary decodes.
    let (plain, _) = outcome(zstd_frame(BIG, false), Codec::Zstd, Limits::default());
    assert_eq!(plain, "ok: 4096 bytes");
}

/// A limit is reported at once too: a Snappy stream whose preamble claims
/// more (4 GiB) than the session may decode, followed by 70 MiB.
#[test]
fn limit_is_reported_at_once_on_a_large_stream() {
    let mut data = vec![0xff, 0xff, 0xff, 0xff, 0x0f]; // varint 0xffffffff
    data.resize(5 + BIG, 0);
    let (text, read) = outcome(data, Codec::Snappy, Limits::default());
    assert!(text.starts_with("limit: "), "{text}");
    assert!(text.contains("Snappy data claims"), "{text}");
    assert!(read <= 1 << 20, "read {read:#x} bytes before reporting it");
}

/// A checksum mismatch is malformed data, which a decoder may also report
/// when it merely ran out of input: it is retried as more input comes, and
/// once the decoder has stalled over a lot of it, reported as the decoder
/// sees it, rather than as "no progress". Here the first frame's content
/// checksum is wrong and a 70 MiB frame follows.
#[test]
fn checksum_mismatch_is_reported_on_a_large_stream() {
    // `printf hello | zstd --check`, with the last checksum byte changed.
    let mut data = vec![
        0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x58, 0x29, 0x00, 0x00, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0xa3,
        0x6d, 0x9f, 0x89,
    ];
    let mut good = data.clone();
    *good.last_mut().unwrap() = 0x88;
    data.extend(zstd_frame(BIG, false));
    let (text, _) = outcome(data, Codec::Zstd, Limits::default());
    assert!(text.contains("content checksum mismatch"), "{text}");
    // The intact frame decodes, and the next one after it.
    good.extend(zstd_frame(BIG, false));
    let (text, _) = outcome(good, Codec::Zstd, Limits::default());
    assert_eq!(text, "ok: 4096 bytes");
}
