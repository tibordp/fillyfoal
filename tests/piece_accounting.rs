//! Piecewise sources and the disk dissectors that build them stay bounded
//! per step on very fragmented or hugely declared inputs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{Cx, Limits, Node, Origin, Progress, Result, SourceId, Span, Value};

/// Registers every other byte of `file` as its own piece, then reads the
/// assembled source back.
async fn every_other_byte(cx: Cx, file: Span) -> Result<()> {
    let pieces: Vec<Span> = (0..file.len).step_by(2).map(|o| file.sub(o, 1)).collect();
    let span = cx
        .add_pieces_stepped(
            Origin {
                parent: file,
                transform: "test-every-other",
            },
            &pieces,
        )
        .await?;
    let data = cx.read(span).await?;
    cx.emit(Node::new("joined").value(Value::Bytes(data)));
    Ok(())
}

#[test]
fn stepped_pieces_yield_and_read_back() {
    let data: Vec<u8> = (0..1u32 << 20).map(|i| (i % 253) as u8).collect();
    let expected: Vec<u8> = data.iter().copied().step_by(2).collect();
    let mut host = Host::new(data.clone(), Limits::default());
    let file = Span::new(SourceId::default_host(), 0, data.len() as u64);
    host.session.supply(file.source, 0, &data);
    let root = host
        .session
        .add_root(Node::new("t").lazy(every_other_byte, file));
    host.session.expand(root, 10);
    // 512Ki pieces are indexed 1Ki per unit: many short steps, not one.
    let mut yields = 0;
    while host.session.poll_node(root, 64) == Progress::Yielded {
        yields += 1;
    }
    assert!(yields >= 8, "{yields}");
    let children = host.session.children(root).unwrap();
    let node = host.session.node(children.ids[0]).unwrap();
    assert_eq!(node.value, Some(Value::Bytes(expected)));
}

fn vhdx_fixture() -> Vec<u8> {
    let gz = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/synthetic/vhdx/disk.vhdx.gz"
    ))
    .unwrap();
    fillyfoal::codec::inflate::inflate(&gz[10..], 16 << 20).unwrap()
}

/// A VHDX declaring a 1 PiB disk (2^30 blocks) with a 64 KiB BAT: only the
/// blocks the BAT lists are walked; the rest is one run of zeros.
#[test]
fn vhdx_huge_declared_size_settles() {
    let mut data = vhdx_fixture();
    // The "Virtual disk size" metadata item (see the fixture's snapshot).
    let at = 0x58008;
    assert_eq!(
        u64::from_le_bytes(data[at..at + 8].try_into().unwrap()),
        32 << 10
    );
    data[at..at + 8].copy_from_slice(&(1u64 << 50).to_le_bytes());
    let mut host = Host::named("disk.vhdx", data, Limits::default());
    host.max_polls = 10_000;
    // Only the virtual disk: the BAT listing pages through all 2^30 entries.
    host.explore(host.root, 1, 1000);
    let disk = host.child(host.root, "Virtual disk").unwrap();
    host.explore(disk, 1, 1000);
    let rendered = host.render();
    assert!(
        rendered.contains("Virtual disk — MBR partition table"),
        "{rendered}"
    );
    let kinds = common::diagnostic_kinds(&host);
    assert!(!kinds.contains(&fillyfoal::DiagKind::Limit), "{kinds:?}");
    assert!(!kinds.contains(&fillyfoal::DiagKind::Internal), "{kinds:?}");
}
