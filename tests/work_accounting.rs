//! Shared helpers charge for the work they do, not only for the reads under
//! it: a byte-at-a-time parse over a buffered window and a hash of a large
//! in-memory buffer both yield in bounded steps.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::formats::util::datakit::{ByteReader, sha1, sha1_paced};
use fillyfoal::{Cx, Limits, Node, Progress, Result, SourceId, Span, Value};

/// Sums the bytes of `file`, one `ByteReader::byte` call per byte.
async fn sum_bytes(cx: Cx, file: Span) -> Result<()> {
    let mut r = ByteReader::new(&cx, file);
    let mut sum = 0u64;
    for at in 0..file.len {
        sum += u64::from(r.byte(at).await?);
    }
    cx.emit(Node::new("sum").value(Value::UInt {
        value: sum,
        bits: 64,
        radix: fillyfoal::value::Radix::Dec,
    }));
    Ok(())
}

#[test]
fn byte_reader_charges_per_call() {
    let data: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let expected: u64 = data.iter().map(|&b| u64::from(b)).sum();
    let mut host = Host::new(data.clone(), Limits::default());
    let file = Span::new(SourceId::default_host(), 0, data.len() as u64);
    host.session.supply(file.source, 0, &data);
    let root = host.session.add_root(Node::new("t").lazy(sum_bytes, file));
    host.session.expand(root, 10);
    // The windows cost about 64 units; the 256Ki calls about 1024.
    assert_eq!(host.session.poll_node(root, 300), Progress::Yielded);
    host.run();
    let children = host.session.children(root).unwrap();
    let node = host.session.node(children.ids[0]).unwrap();
    assert_eq!(
        node.value,
        Some(Value::UInt {
            value: expected,
            bits: 64,
            radix: fillyfoal::value::Radix::Dec,
        })
    );
}

/// SHA-1 of 4 MiB held in memory (no reads to pay for it).
async fn hash_big(cx: Cx, (): ()) -> Result<()> {
    let data = vec![0x61u8; 4 << 20];
    let digest = sha1_paced(&cx, &data).await;
    assert_eq!(digest, sha1(&data));
    cx.emit(Node::new("digest").value(Value::Bytes(digest.to_vec())));
    Ok(())
}

#[test]
fn paced_hash_yields_in_bounded_steps() {
    let mut host = Host::new(Vec::new(), Limits::default());
    let root = host.session.add_root(Node::new("t").lazy(hash_big, ()));
    host.session.expand(root, 10);
    let mut yields = 0;
    while host.session.poll_node(root, 500) == Progress::Yielded {
        yields += 1;
    }
    // 4096 units of hashing in steps of 500.
    assert!(yields >= 8, "{yields}");
    let children = host.session.children(root).unwrap();
    assert_eq!(children.ids.len(), 1);
}
