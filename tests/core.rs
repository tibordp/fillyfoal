//! Core behaviour not tied to a particular format.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{Cx, Limits, Node, Origin, Result, Span, Value};

/// Reassembles "fragments" of the input in a scrambled order and emits the
/// reassembled text, plus a piecewise source built on top of the first one.
async fn reassemble(cx: Cx, file: Span) -> Result<()> {
    let at = |offset, len| Span::new(file.source, offset, len);
    let first = cx.add_pieces(
        Origin { parent: file, transform: "test-chain" },
        vec![at(10, 5), at(0, 5), at(20, 6), at(5, 5)],
    )?;
    let text = cx.read(first).await?;
    cx.emit(Node::new("first").span(first).value(Value::Text(String::from_utf8(text).unwrap())));
    // Pieces of a piecewise source.
    let second = cx.add_pieces(
        Origin { parent: first, transform: "test-nested" },
        vec![first.sub(15, 6), first.sub(0, 5)],
    )?;
    let text = cx.read(second).await?;
    cx.emit(Node::new("second").span(second).value(Value::Text(String::from_utf8(text).unwrap())));
    Ok(())
}

#[test]
fn piecewise_sources_reassemble_and_resolve() {
    let data = b"HELLO, wor_ld! ____ IGNORE_this_".to_vec();
    for chunk in [1, 3, 64] {
        let mut host = Host::with_chunk(data.clone(), chunk);
        let file = Span::new(fillyfoal::SourceId::default_host(), 0, data.len() as u64);
        let root = host.session.add_root(Node::new("test").lazy(reassemble, file));
        host.session.expand(root, 10);
        host.run();
        let children = host.session.children(root).unwrap();
        assert!(children.error.is_none(), "{:?}", children.error);
        let values: Vec<_> = children
            .ids
            .iter()
            .map(|&id| host.session.node(id).unwrap().value.clone().unwrap())
            .collect();
        // data[10..15] + data[0..5] + data[20..26] + data[5..10]
        assert_eq!(values[0], Value::Text("_ld! HELLOIGNORE, wor".into()), "chunk {chunk}");
        // first[15..21] + first[0..5]
        assert_eq!(values[1], Value::Text("E, wor_ld! ".into()), "chunk {chunk}");

        // Provenance: bytes 3..8 of the nested source come from two places.
        let second = host.session.node(children.ids[1]).unwrap().span.unwrap();
        let resolved = host.session.resolve(Span::new(second.source, 3, 5));
        assert_eq!(
            resolved,
            vec![Span::new(file.source, 7, 3), Span::new(file.source, 10, 2)]
        );
    }
    let _ = Limits::default();
}
