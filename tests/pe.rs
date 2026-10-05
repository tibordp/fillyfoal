#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::{Host, Rng, fixture};
use fillyfoal::{ChildState, Count, DiagKind, NodeId, Progress, Session};

/// Every node and child error in the materialised tree.
fn diagnostics(host: &Host) -> Vec<DiagKind> {
    let mut out = Vec::new();
    let mut stack = vec![host.root];
    while let Some(id) = stack.pop() {
        let node = host.session.node(id).unwrap();
        out.extend(node.diagnostics.iter().map(|d| d.kind));
        let children = host.session.children(id).unwrap();
        out.extend(children.error.map(|e| e.kind));
        stack.extend(children.ids.iter().copied());
    }
    out
}

#[test]
fn full_tree_snapshot() {
    let mut host = Host::with_chunk(fixture(), 64);
    host.explore_all();
    insta::assert_snapshot!(host.render());
}

#[test]
fn top_level_reads_only_headers() {
    let mut host = Host::with_chunk(fixture(), 16);
    host.session.expand(host.root, 100);
    host.run();
    let children = host.session.children(host.root).unwrap();
    assert_eq!(children.state, ChildState::Complete);
    // DOS header, NT headers, section table and data directories end at 0x200.
    assert!(
        host.bytes_supplied <= 0x200,
        "read {:#x} bytes",
        host.bytes_supplied
    );
    let summary = host.session.node(host.root).unwrap().summary.clone();
    assert_eq!(summary.as_deref(), Some("PE32+ DLL, AMD64, WINDOWS_GUI"));
}

#[test]
fn nothing_happens_until_polled() {
    let mut session = Session::new(Default::default());
    let root = session.open("x", 0x1000);
    session.expand(root, 10);
    assert_eq!(
        session.children(root).unwrap().state,
        ChildState::Running(fillyfoal::Wait::Ready)
    );
    match session.poll(100) {
        Progress::NeedBytes(r) => assert_eq!(r.len(), 1),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(
        session.children(root).unwrap().state,
        ChildState::Running(fillyfoal::Wait::Bytes)
    );
}

#[test]
fn results_do_not_depend_on_chunking_or_budget() {
    let mut reference = Host::with_chunk(fixture(), 64 * 1024);
    reference.explore_all();
    let expected = reference.render();

    for chunk in [1, 7, 512] {
        let mut host = Host::with_chunk(fixture(), chunk);
        host.explore_all();
        assert_eq!(host.render(), expected, "chunk size {chunk}");
    }

    let mut host = Host::with_chunk(fixture(), 64);
    host.budget = 1;
    host.explore_all();
    assert_eq!(host.render(), expected, "budget 1");
    assert!(host.polls > 100, "budget 1 should yield often");
}

#[test]
fn paging_produces_the_same_children() {
    let mut reference = Host::with_chunk(fixture(), 4096);
    reference.explore(reference.root, 32, 1000);
    let mut host = Host::with_chunk(fixture(), 4096);
    host.explore(host.root, 32, 1);
    assert_eq!(host.render(), reference.render());
}

#[test]
fn pages_stop_early_and_resume() {
    let mut host = Host::with_chunk(fixture(), 4096);
    host.session.expand(host.root, 100);
    host.run();
    let imports = host.child(host.root, "Import Table").unwrap();
    let kernel32 = {
        host.session.expand(imports, 100);
        host.run();
        host.child(imports, "KERNEL32.dll").unwrap()
    };
    // Descriptor + first function.
    host.session.expand(kernel32, 2);
    host.run();
    let children = host.session.children(kernel32).unwrap();
    assert_eq!(children.ids.len(), 2);
    assert_eq!(children.state, ChildState::More);
    host.session.expand_more(kernel32, 10);
    host.run();
    let children = host.session.children(kernel32).unwrap();
    assert_eq!(children.ids.len(), 3);
    assert_eq!(children.state, ChildState::Complete);
    assert_eq!(children.count, Count::Exact(3));
}

#[test]
fn collapse_and_expand_again_is_identical() {
    let mut host = Host::with_chunk(fixture(), 64);
    host.explore_all();
    let before = host.render();
    let children: Vec<NodeId> = host.session.children(host.root).unwrap().ids.to_vec();
    host.session.collapse(host.root);
    assert!(host.session.node(children[0]).is_none(), "stale handle");
    host.explore_all();
    assert_eq!(host.render(), before);
}

#[test]
fn resource_cycle_is_reported_not_followed() {
    let mut host = Host::with_chunk(fixture(), 4096);
    host.explore_all();
    let rendered = host.render();
    assert!(rendered.contains("directory at offset 0x0 contains itself"));
}

#[test]
fn embedded_pe_is_dissected() {
    let mut host = Host::with_chunk(fixture(), 4096);
    host.explore_all();
    assert!(host.render().contains("Content — PE32 executable, I386, WINDOWS_CUI"));
}

#[test]
fn truncation_keeps_partial_results() {
    let data = fixture();
    // Cut inside the optional header: DOS header and NT headers survive.
    let mut host = Host::with_chunk(data[..0x100].to_vec(), 64);
    host.explore_all();
    let root = host.session.children(host.root).unwrap();
    assert_eq!(root.state, ChildState::Failed);
    assert_eq!(root.error.unwrap().kind, DiagKind::Truncated);
    let nt = host.child(host.root, "NT Headers").unwrap();
    let file_header = host.child(nt, "File Header").unwrap();
    assert_eq!(host.session.children(file_header).unwrap().ids.len(), 7);
    insta::assert_snapshot!(host.render());
}

#[test]
fn every_truncation_settles_without_internal_errors() {
    let data = fixture();
    for len in 0..=data.len() {
        let mut host = Host::with_chunk(data[..len].to_vec(), 256);
        host.max_polls = 100_000;
        host.explore_all();
        let kinds = diagnostics(&host);
        assert!(!kinds.contains(&DiagKind::Internal), "len {len}");
        if len < data.len() && len > 0 {
            assert!(!kinds.is_empty(), "len {len}: truncation went unnoticed");
        }
    }
}

#[test]
fn mutations_settle_without_internal_errors() {
    let data = fixture();
    let mut rng = Rng(0x5eed_f111_f0a1);
    const INTERESTING: [u8; 6] = [0x00, 0xff, 0x7f, 0x80, 0x01, 0x10];
    for round in 0..3000 {
        let mut mutated = data.clone();
        for _ in 0..1 + rng.below(4) {
            let at = rng.below(mutated.len());
            mutated[at] = if rng.below(2) == 0 {
                INTERESTING[rng.below(INTERESTING.len())]
            } else {
                rng.next() as u8
            };
        }
        let mut host = Host::with_chunk(mutated, 256);
        host.max_polls = 100_000;
        host.explore_all();
        assert!(
            !diagnostics(&host).contains(&DiagKind::Internal),
            "round {round}"
        );
    }
}

#[test]
fn absurd_counts_are_rejected_before_reading() {
    let mut data = fixture();
    // NumberOfFunctions = 0xffffffff
    data[0x600 + 0x14..0x600 + 0x18].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut host = Host::with_chunk(data, 4096);
    host.explore_all();
    let rendered = host.render();
    assert!(
        rendered.contains("truncated: needed 0x3fffffffc bytes at 0x640"),
        "{rendered}"
    );
}

#[test]
fn reads_beyond_the_limit_fail_locally() {
    let mut host = Host::new(
        fixture(),
        fillyfoal::Limits {
            chunk_size: 64,
            max_read: 0x80,
            ..Default::default()
        },
    );
    host.explore_all();
    // The 0xf0-byte optional header exceeds the limit; what came before stays.
    let root = host.session.children(host.root).unwrap();
    assert_eq!(root.error.unwrap().kind, DiagKind::Limit);
    let dos = host.child(host.root, "DOS Header").unwrap();
    assert_eq!(host.session.children(dos).unwrap().ids.len(), 19);
    assert!(host.child(host.root, "NT Headers").is_some());
}
