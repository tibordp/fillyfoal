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

/// Polls `host` to idle in steps of `budget` units, answering byte requests;
/// returns how many steps ran out of budget.
fn run_counting_yields(host: &mut Host, budget: u64) -> u64 {
    let mut yields = 0;
    for _ in 0..1_000_000 {
        match host.session.poll(budget) {
            Progress::Idle => return yields,
            Progress::Yielded => yields += 1,
            Progress::NeedBytes(requests) => {
                for r in requests {
                    let start = r.offset as usize;
                    let end = (start + r.len as usize).min(host.data.len());
                    host.session
                        .supply(r.source, r.offset, &host.data[start..end]);
                }
            }
            Progress::NeedSecret(_) => panic!("no secrets here"),
        }
    }
    panic!("session did not settle");
}

/// An MSF (PDB) file whose stream 1 is `blocks` blocks of 4 KiB, all
/// the same block: a small file with a huge piece list.
fn fragmented_pdb(blocks: u32) -> Vec<u8> {
    const BS: usize = 4096;
    let dir_bytes = 4 + 2 * 4 + blocks as usize * 4;
    let dir_blocks = dir_bytes.div_ceil(BS);
    let map_blocks = (dir_blocks * 4).div_ceil(BS);
    // Block 0: superblock; 1: the stream's data; then the block map, then
    // the directory.
    let map_at = 2;
    let dir_at = map_at + map_blocks;
    let total = dir_at + dir_blocks;
    let mut w = common::Image::new(total * BS);
    w.bytes(0, b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0")
        .u32(32, BS as u32)
        .u32(36, 1)
        .u32(40, total as u32)
        .u32(44, dir_bytes as u32)
        .u32(52, map_at as u32);
    for i in 0..BS {
        w.bytes(BS + i, &[(i % 251) as u8]);
    }
    for i in 0..dir_blocks {
        w.u32(map_at * BS + i * 4, (dir_at + i) as u32);
    }
    let dir = dir_at * BS;
    w.u32(dir, 2)
        .u32(dir + 4, 0)
        .u32(dir + 8, blocks * BS as u32);
    for i in 0..blocks as usize {
        w.u32(dir + 12 + i * 4, 1);
    }
    w.finish()
}

/// 256Ki pieces in one stream: listing, indexing and reading them back
/// happen over many bounded steps, and the stream reads as the block
/// repeated.
#[test]
fn fragmented_pdb_stream_yields() {
    let blocks = 1u32 << 18;
    let data = fragmented_pdb(blocks);
    let mut host = Host::named("big.pdb", data, Limits::default());
    host.session.expand(host.root, 100);
    let yields = run_counting_yields(&mut host, 16);
    // 256Ki entries: ~64 units to parse them, 64 to list the pieces and
    // 256 to index them, on top of the reads (about 2 steps of 16 units
    // when the pieces were built and indexed in one go).
    assert!(yields >= 16, "{yields}");
    let streams = host.child(host.root, "Streams").unwrap_or_else(|| {
        panic!("{}", host.render());
    });
    host.session.expand(streams, 100);
    run_counting_yields(&mut host, 1_000_000);
    let info = host.child(streams, "Stream 1: PDB info").unwrap();
    let span = host.session.node(info).unwrap().span.unwrap();
    assert_eq!(span.len, u64::from(blocks) * 4096);
    let tail = span.sub(span.len - 8192, 8192);
    let bytes = loop {
        match host.session.read(tail) {
            Ok(bytes) => break bytes,
            Err(requests) => {
                for r in requests {
                    let start = r.offset as usize;
                    let end = (start + r.len as usize).min(host.data.len());
                    host.session
                        .supply(r.source, r.offset, &host.data[start..end]);
                }
            }
        }
    };
    let block: Vec<u8> = (0..4096).map(|i| (i % 251) as u8).collect();
    assert_eq!(bytes, [block.clone(), block].concat());
}
