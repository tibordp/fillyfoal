//! Disk formats that probes cannot detect yet: Btrfs keeps its superblock at
//! 64 KiB, beyond the probe window, so it is dissected by name here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::formats::{Input, disk, embedded_as};
use fillyfoal::{Limits, Span};

fn btrfs_image() -> Vec<u8> {
    let data = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/btrfs.img.gz")).unwrap();
    fillyfoal::codec::inflate::inflate(&data[10..], 1 << 20).unwrap()
}

fn btrfs_host(data: Vec<u8>, chunk_size: u64) -> Host {
    let len = data.len() as u64;
    let mut host = Host::named(
        "btrfs.img",
        data,
        Limits {
            chunk_size,
            ..Limits::default()
        },
    );
    let span = Span::new(fillyfoal::SourceId::default_host(), 0, len);
    host.root = host
        .session
        .add_root(embedded_as("btrfs.img", Input::root(span), &disk::btrfs::FORMAT));
    host
}

#[test]
fn btrfs_by_name() {
    let mut host = btrfs_host(btrfs_image(), 64);
    host.explore(host.root, 24, 1000);
    let kinds = common::diagnostic_kinds(&host);
    assert!(!kinds.contains(&fillyfoal::DiagKind::Internal));
    insta::assert_snapshot!(host.render());
}

#[test]
fn btrfs_truncations_and_mutations_settle() {
    let data = btrfs_image();
    let mut rng = common::Rng(0xb7f5);
    for i in 0..120 {
        let mut variant = data.clone();
        if i % 2 == 0 {
            variant.truncate(i * data.len() / 120);
        } else {
            for _ in 0..4 {
                let at = 0x10000 + rng.below(0x3000);
                variant[at] = rng.next() as u8;
            }
        }
        let mut host = btrfs_host(variant, 256);
        host.max_polls = 100_000;
        host.explore(host.root, 24, 1000);
        assert!(!common::diagnostic_kinds(&host).contains(&fillyfoal::DiagKind::Internal));
    }
}
