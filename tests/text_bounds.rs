//! Text walkers do work in proportion to the text: a UTF-16 line walk costs
//! about what the same walk over UTF-8 costs (not a read per code unit),
//! and a Markdown section with an unclosed fence of long lines reads each
//! byte once.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{Limits, NodeId, Progress};

/// Expands `id` fully (pages of `page`), polling with a small budget;
/// returns how many polls ran out of budget, a measure of the work done.
fn work_to_expand(host: &mut Host, id: NodeId, page: u64) -> u64 {
    let mut yields = 0u64;
    loop {
        host.session.expand_more(id, page);
        for _ in 0..10_000_000 {
            match host.session.poll(50) {
                Progress::Idle => break,
                Progress::Yielded => yields += 1,
                Progress::NeedSecret(_) => panic!("unexpected secret request"),
                Progress::NeedBytes(requests) => host.supply(requests),
            }
        }
        let state = host.session.children(id).map(|c| c.state);
        if state != Some(fillyfoal::ChildState::More) {
            return yields;
        }
    }
}

/// The work of walking the lines of `data` as plain text.
fn lines_work(name: &str, data: Vec<u8>) -> u64 {
    let plain = &fillyfoal::formats::text::plain::FORMAT;
    let mut host = Host::open(name, data, Limits::default(), Some(plain));
    let root = host.root;
    host.session.expand(root, 100);
    host.run();
    let lines = host.child(root, "Lines").expect("a Lines node");
    work_to_expand(&mut host, lines, 100_000)
}

#[test]
fn utf16_lines_cost_about_what_utf8_lines_cost() {
    let text: String = (0..40_000)
        .map(|i| format!("this is log line number {i} of the test\n"))
        .collect();
    let utf8 = text.clone().into_bytes();
    let mut utf16 = vec![0xff, 0xfe];
    for u in text.encode_utf16() {
        utf16.extend_from_slice(&u.to_le_bytes());
    }
    let narrow = lines_work("a.txt", utf8);
    let wide = lines_work("b.txt", utf16);
    // A read per code unit made the wide walk cost ~1.7M units (about
    // twenty times the narrow one).
    assert!(
        wide <= narrow * 3 + 50,
        "UTF-16 walk: {wide} budgets, UTF-8 walk: {narrow}"
    );
}

#[test]
fn markdown_unclosed_fence_reads_each_line_once() {
    let mut data = b"# Title\n\nSome text.\n\n```\n".to_vec();
    let line = vec![b'x'; 100_000];
    for _ in 0..40 {
        data.extend_from_slice(&line);
        data.push(b'\n');
    }
    let mut host = Host::named("a.md", data, Limits::default());
    let root = host.root;
    host.session.expand(root, 100);
    host.run();
    let title = host.child(root, "Title").expect("the Title section");
    let section = work_to_expand(&mut host, title, 100);
    // Lines longer than the scan window were read twice and a peek for a
    // setext underline read every line again: 33 budgets, 20 now. (The
    // other half of the fix, keeping at most BLOCK_CAP bytes of the
    // unclosed fence instead of every line, is not visible from here.)
    assert!(
        section <= 26,
        "the section took {section} budgets of 50 units"
    );
    let children = host.session.children(title).unwrap();
    assert_eq!(children.ids.len(), 2, "a paragraph and the code block");
}
