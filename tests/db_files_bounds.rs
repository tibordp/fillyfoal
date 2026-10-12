//! Database server files are large (an InnoDB system tablespace, a WAL
//! segment, a data file): expanding them reads their headers, not their
//! pages, and corrupt links between records or pages end the walks.

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

fn fixture(path: &str) -> Vec<u8> {
    common::fixture_bytes(std::path::Path::new(path))
}

/// Expands `id` by one page of `page` children.
fn page(host: &mut Host, id: NodeId, page: u64) -> Vec<NodeId> {
    host.session.expand_more(id, page);
    host.run();
    host.session.children(id).unwrap().ids.to_vec()
}

fn name(host: &Host, id: NodeId) -> String {
    host.session.node(id).unwrap().name.to_string()
}

#[test]
fn a_large_tablespace_is_listed_without_reading_its_pages() {
    // The 8-page MySQL tablespace grown to 64 MiB of never-written pages.
    let mut data = fixture("tests/fixtures/external/innodb/mysql-fruit.ibd.gz");
    data.resize(64 << 20, 0);
    let mut host = Host::named("big.ibd", data, Limits::default());
    let root = host.root;
    let top = page(&mut host, root, 100);
    let names: Vec<String> = top.iter().map(|&id| name(&host, id)).collect();
    assert_eq!(
        names,
        [
            "File space header",
            "Serialized dictionary (SDI)",
            "Indexes",
            "Pages"
        ]
    );
    // Page 0's header and the SDI page.
    assert!(
        host.bytes_supplied < 256 * 1024,
        "{} bytes read",
        host.bytes_supplied
    );
    let work = host.session.work_done();
    assert!(work < 50_000, "{work} units to open the tablespace");

    // A page of the 4,096 pages reads that page's headers only.
    let before = host.bytes_supplied;
    let pages = page(&mut host, top[3], 50);
    assert_eq!(pages.len(), 50);
    assert!(
        host.bytes_supplied - before < 1 << 20,
        "{} bytes read for 50 pages",
        host.bytes_supplied - before
    );
}

#[test]
fn a_record_chain_that_loops_ends() {
    // Page 4 is the clustered index's only page; its second record's
    // next-record link (relative, compact format) is bent back to the first.
    let mut data = fixture("tests/fixtures/external/innodb/mysql-fruit.ibd.gz");
    let base = 4 * 16384;
    let first = 0x7f_i32;
    let second = 0xa2_i32;
    let at = base + second as usize - 2;
    data[at..at + 2].copy_from_slice(&((first - second) as i16).to_be_bytes());
    let mut host = Host::named("loop.ibd", data, Limits::default());
    host.max_nodes = 20_000;
    host.explore_all();
    let root = host.root;
    let pages = host.child(root, "Pages").unwrap();
    let page4 = host.child(pages, "Page 4").unwrap();
    let records = host.child(page4, "Records").unwrap();
    let listed = host.session.children(records).unwrap().ids.len();
    assert_eq!(listed, 2, "{}", host.render());
}

#[test]
fn a_wal_segment_ends_its_walk_at_the_first_unwritten_record() {
    // The segment's first page, in a 16 MiB segment of zeros.
    let wal = fixture("tests/fixtures/external/pg-wal/00000001000000000000000D.gz");
    let mut data = wal[..8192].to_vec();
    // Cut the first page after its first record, so the rest is zero.
    let first_len = u32::from_le_bytes(data[40..44].try_into().unwrap()) as usize;
    let end = (40 + first_len).next_multiple_of(8);
    data[end..].fill(0);
    // Segment size and the page address (a multiple of it) of a 16 MiB
    // segment.
    data[32..36].copy_from_slice(&(16u32 << 20).to_le_bytes());
    data[8..16].copy_from_slice(&(16u64 << 20).to_le_bytes());
    data.resize(16 << 20, 0);
    let mut host = Host::named("000000010000000000000001", data, Limits::default());
    let root = host.root;
    let top = page(&mut host, root, 10);
    let records = top
        .iter()
        .copied()
        .find(|&id| name(&host, id) == "Records")
        .unwrap();
    let before = host.bytes_supplied;
    let list = page(&mut host, records, 100);
    let names: Vec<String> = list.iter().map(|&id| name(&host, id)).collect();
    assert_eq!(names.len(), 2, "{names:?}");
    assert_eq!(names[1], "Unused");
    assert!(
        host.bytes_supplied - before < 256 * 1024,
        "{} bytes read",
        host.bytes_supplied - before
    );
}
