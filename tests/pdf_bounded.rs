//! PDF objects and content streams of any size are parsed in bounded,
//! budgeted steps: a huge `/Kids` array, a long string or an inline image
//! with megabytes of data make the expansion yield again and again instead
//! of stalling one poll.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::time::{Duration, Instant};

use common::Host;
use fillyfoal::{ChildState, Limits, NodeId, Progress};

/// A PDF with one page whose parent lists it `kids` times, and whose
/// content stream is `content`.
fn big_pdf(kids: usize, content: &[u8]) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    let mut object = |out: &mut Vec<u8>, num: usize, body: &[u8]| {
        offsets.push(out.len());
        out.extend_from_slice(format!("{num} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    };
    object(&mut out, 1, b"<< /Type /Catalog /Pages 2 0 R >>");
    let pages = [
        format!("<< /Type /Pages /Count {kids} /Kids [").into_bytes(),
        b"3 0 R ".repeat(kids),
        b"] >>".to_vec(),
    ]
    .concat();
    object(&mut out, 2, &pages);
    object(
        &mut out,
        3,
        b"<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>",
    );
    let stream = [
        format!("<< /Length {} >>\nstream\n", content.len()).into_bytes(),
        content.to_vec(),
        b"\nendstream".to_vec(),
    ]
    .concat();
    object(&mut out, 4, &stream);
    let xref = out.len();
    out.extend_from_slice(b"xref\n0 5\n0000000000 65535 f \n");
    for at in offsets {
        out.extend_from_slice(format!("{at:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    out
}

/// A host holding all of `data` in its cache, so polls end only when
/// their budget does.
fn open(data: Vec<u8>) -> Host {
    let mut host = Host::named("big.pdf", data, Limits::default());
    let source = host.session.node(host.root).unwrap().span.unwrap().source;
    let data = host.data.clone();
    host.session.supply(source, 0, &data);
    host
}

/// Polls the expansion of `id` with a small budget until it settles or has
/// `children` children; returns how often it yielded. Every poll must be
/// quick.
fn poll(host: &mut Host, id: NodeId, children: usize) -> usize {
    let mut yields = 0;
    for _ in 0..100_000 {
        let start = Instant::now();
        let progress = host.session.poll_node(id, 200);
        // 200 units are a fraction of a millisecond; allow for a slow machine.
        assert!(start.elapsed() < Duration::from_millis(500));
        match progress {
            Progress::Yielded => yields += 1,
            Progress::NeedBytes(requests) => {
                for r in requests {
                    let start = r.offset as usize;
                    let end = (start + r.len as usize).min(host.data.len());
                    let bytes = host.data[start..end].to_vec();
                    host.session.supply(r.source, r.offset, &bytes);
                }
            }
            Progress::Idle => {}
            other => panic!("unexpected {other:?}"),
        }
        let state = host.session.children(id).unwrap();
        if state.ids.len() >= children || !matches!(state.state, ChildState::Running(_)) {
            return yields;
        }
    }
    panic!("did not settle");
}

/// The node named `name` under `id`, expanding `id` fully first.
fn child(host: &mut Host, id: NodeId, name: &str) -> NodeId {
    host.session.expand(id, 1000);
    host.run();
    host.child(id, name)
        .unwrap_or_else(|| panic!("no {name:?} in\n{}", host.render()))
}

#[test]
fn a_huge_kids_array_is_parsed_in_steps() {
    let mut host = open(big_pdf(400_000, b"q Q"));
    let root = host.root;
    host.session.expand(root, 100);
    let yields = poll(&mut host, root, usize::MAX);
    assert!(yields >= 50, "{yields} yields\n{}", host.render());
    let summary = host.session.node(host.root).unwrap().summary.clone();
    assert!(
        format!("{summary:?}").contains("400000 pages"),
        "{summary:?}"
    );
}

/// The content operators of object 4.
fn operators(host: &mut Host) -> NodeId {
    let root = host.root;
    let revisions = child(host, root, "Revisions");
    let revision = child(host, revisions, "Revision 1");
    let body = child(host, revision, "Body");
    let object = child(host, body, "Object 4 0");
    let operators = child(host, object, "Operators");
    host.session.expand(operators, 2);
    operators
}

#[test]
fn a_long_inline_image_is_scanned_in_steps() {
    let content = [
        b"q BI /W 8 /H 8 ID ".to_vec(),
        b"xE I".repeat(1 << 20),
        b" EI Q".to_vec(),
    ]
    .concat();
    let mut host = open(big_pdf(1, &content));
    let operators = operators(&mut host);
    let yields = poll(&mut host, operators, 2);
    assert!(
        yields >= 10,
        "{yields} yields {:?}\n{}",
        host.session.children(operators).map(|c| c.state),
        host.render()
    );
    let ids = host.session.children(operators).unwrap().ids.to_vec();
    let image = host.session.node(ids[1]).unwrap();
    assert_eq!(image.name, "BI … ID … EI");
    assert_eq!(image.span.unwrap().len as usize, content.len() - 4);
}

#[test]
fn a_long_string_operand_is_parsed_in_steps() {
    let content = [
        b"BT (".to_vec(),
        b"a\\(b\\)".repeat(1 << 19),
        b") Tj ET".to_vec(),
    ]
    .concat();
    let mut host = open(big_pdf(1, &content));
    let operators = operators(&mut host);
    let yields = poll(&mut host, operators, 2);
    assert!(
        yields >= 10,
        "{yields} yields {:?}\n{}",
        host.session.children(operators).map(|c| c.state),
        host.render()
    );
    let ids = host.session.children(operators).unwrap().ids.to_vec();
    assert_eq!(host.session.node(ids[1]).unwrap().name, "Tj");
}
