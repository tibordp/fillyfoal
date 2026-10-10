//! Session and Cx behaviour under awkward host and budget patterns: window
//! moves, sources shorter than announced, tiny caches, competing
//! expansions, corrupt streams and memory pressure.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use fillyfoal::codec::Codec;
use fillyfoal::{ChildState, Cx, Limits, Node, NodeId, Origin, Progress, Result, Session, Span};

/// Answers byte requests from `data`; a request past its end shrinks the
/// source the way `sync::Driver` does. Panics if the session does not
/// settle within `max_polls`.
fn run(session: &mut Session, data: &[u8], budget: u64, max_polls: u64) {
    for _ in 0..max_polls {
        match session.poll(budget) {
            Progress::Idle => return,
            Progress::Yielded | Progress::NeedSecret(_) => {}
            Progress::NeedBytes(requests) => {
                for r in requests {
                    let start = (r.offset as usize).min(data.len());
                    let end = ((r.offset + r.len) as usize).min(data.len());
                    session.supply(r.source, r.offset, &data[start..end]);
                    if end - start < r.len as usize {
                        session.set_source_len(r.source, end as u64);
                    }
                }
            }
        }
    }
    panic!("session did not settle within {max_polls} polls");
}

fn names(session: &Session, id: NodeId) -> (u64, Vec<String>) {
    let children = session.children(id).unwrap();
    let names = children
        .ids
        .iter()
        .map(|&c| session.node(c).unwrap().name.to_string())
        .collect();
    (children.first, names)
}

/// Each child's name must be its index.
fn assert_indexed(session: &Session, id: NodeId) {
    let (first, names) = names(session, id);
    for (i, name) in names.iter().enumerate() {
        assert_eq!(name, &(first + i as u64).to_string(), "children {names:?}");
    }
}

async fn numbers(cx: Cx, n: u64) -> Result<()> {
    for i in 0..n {
        cx.push(Node::new(i.to_string())).await;
    }
    Ok(())
}

fn numbers_root(session: &mut Session, n: u64) -> NodeId {
    session.add_root(Node::new("numbers").lazy(numbers, n))
}

#[test]
fn shrinking_the_window_then_growing_it_keeps_indices() {
    let mut session = Session::new(Limits::default());
    let root = numbers_root(&mut session, 1000);
    session.expand(root, 200);
    run(&mut session, &[], 1_000_000, 100);
    session.seek(root, 0, 50);
    session.expand(root, 300);
    run(&mut session, &[], 1_000_000, 100);
    assert_indexed(&session, root);
    assert_eq!(names(&session, root).1.len(), 300);
}

#[test]
fn seeking_forward_in_a_complete_collection_produces_the_window() {
    let mut session = Session::new(Limits::default());
    let root = numbers_root(&mut session, 100);
    session.expand(root, 100);
    run(&mut session, &[], 1_000_000, 100);
    assert_eq!(session.children(root).unwrap().state, ChildState::Complete);
    session.seek(root, 50, 10);
    run(&mut session, &[], 1_000_000, 100);
    session.seek(root, 80, 10);
    run(&mut session, &[], 1_000_000, 100);
    let (first, names) = names(&session, root);
    assert_eq!(first, 80);
    assert_eq!(names.len(), 10, "{names:?}");
    assert_indexed(&session, root);
}

async fn read_far(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    cx.emit(Node::new(format!("{} bytes", data.len())));
    Ok(())
}

#[test]
fn a_source_shorter_than_announced_does_not_strand_reads() {
    let chunk = 4096u64;
    let mut session = Session::new(Limits {
        chunk_size: chunk,
        ..Limits::default()
    });
    let data = vec![7u8; 2 * chunk as usize];
    let source = session.add_source(10 * chunk);
    let root = session.add_root(Node::new("far").lazy(read_far, Span::new(source, 5 * chunk, 100)));
    session.expand(root, 10);
    run(&mut session, &data, 1_000_000, 100);
    let state = session.children(root).unwrap().state;
    assert!(
        matches!(state, ChildState::Complete | ChildState::Failed),
        "{state:?}"
    );
}

async fn scattered(cx: Cx, (file, chunk, n): (Span, u64, u64)) -> Result<()> {
    // One byte from each of `n` chunks.
    let pieces = (0..n)
        .map(|i| Span::new(file.source, i * chunk, 1))
        .collect();
    let joined = cx.add_pieces(
        Origin {
            parent: file,
            transform: "scatter",
        },
        pieces,
    )?;
    // Warm the cache with part of it in small reads, then read it all.
    cx.read(joined.sub(0, 6)).await?;
    cx.read(joined.sub(6, 5)).await?;
    let all = cx.read_avail(joined).await;
    cx.emit(Node::new(format!("{:?}", all.map(|d| d.len()))));
    Ok(())
}

#[test]
fn scattered_reads_larger_than_the_cache_fail_instead_of_thrashing() {
    let chunk = 4096u64;
    let limits = Limits {
        chunk_size: chunk,
        max_read: 64 * 1024,
        cache_bytes: 0, // raised to the floor: max_read + 2 chunks
        ..Limits::default()
    };
    let mut session = Session::new(limits);
    let n = 20;
    let data = vec![1u8; (n * chunk) as usize];
    let source = session.add_source(data.len() as u64);
    let file = Span::new(source, 0, data.len() as u64);
    let root = session.add_root(Node::new("scatter").lazy(scattered, (file, chunk, n)));
    session.expand(root, 10);
    run(&mut session, &data, 1_000_000, 10_000);
    assert!(matches!(
        session.children(root).unwrap().state,
        ChildState::Complete | ChildState::Failed
    ));
}

async fn spin(cx: Cx, n: u64) -> Result<()> {
    for _ in 0..n {
        cx.checkpoint().await;
    }
    cx.emit(Node::new("done"));
    Ok(())
}

#[test]
fn a_long_expansion_does_not_starve_others() {
    let mut session = Session::new(Limits::default());
    let long = session.add_root(Node::new("long").lazy(spin, 10_000_000));
    let short = session.add_root(Node::new("short").lazy(spin, 50));
    session.expand(long, 10);
    session.expand(short, 10);
    for _ in 0..20 {
        session.poll(100);
    }
    assert_eq!(
        session.children(short).unwrap().state,
        ChildState::Complete,
        "the short expansion never got a turn"
    );
}

/// Raw DEFLATE stored blocks holding `data`.
fn deflate_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chunks = data.chunks(0xffff).peekable();
    while let Some(c) = chunks.next() {
        out.push(u8::from(chunks.peek().is_none()));
        out.extend_from_slice(&(c.len() as u16).to_le_bytes());
        out.extend_from_slice(&(!(c.len() as u16)).to_le_bytes());
        out.extend_from_slice(c);
    }
    out
}

async fn lazy_reads(cx: Cx, (span, len, reads): (Span, u64, Vec<(u64, u64)>)) -> Result<()> {
    let decoded = cx.decode_lazy(span, &Codec::Deflate, len)?;
    for (offset, n) in reads {
        let got = cx.read_avail(decoded.sub(offset, n)).await;
        cx.emit(Node::new(match got {
            Ok(d) => format!("{offset}: {} bytes", d.len()),
            Err(e) => format!("{offset}: {}", e.message),
        }));
    }
    cx.emit(Node::new(format!("len {}", cx.source_len(decoded.source))));
    Ok(())
}

#[test]
fn a_corrupt_stream_is_not_buffered_whole() {
    // 1 KiB of good data, then an invalid block, then 32 MiB of junk.
    let mut stream = deflate_stored(&[0x55; 1024]);
    stream[0] = 0; // not the final block
    stream.push(0b110); // BTYPE 3: invalid
    stream.resize(stream.len() + (32 << 20), 0);
    let limits = Limits {
        max_derived: 16 << 20,
        ..Limits::default()
    };
    let mut session = Session::new(limits);
    let source = session.add_source(stream.len() as u64);
    let span = Span::new(source, 0, stream.len() as u64);
    let root =
        session.add_root(Node::new("lazy").lazy(lazy_reads, (span, 1 << 20, vec![(4096, 16)])));
    session.expand(root, 10);
    run(&mut session, &stream, 1_000_000, 100_000);
    assert!(
        session.derived_bytes() < 8 << 20,
        "{} bytes held after a corrupt stream",
        session.derived_bytes()
    );
}

async fn crowded(cx: Cx, (span, len): (Span, u64)) -> Result<()> {
    // Bytes nothing can make again fill nearly all derived memory.
    let filler = cx.limits().max_derived - 8 * 1024;
    cx.add_derived(
        Origin {
            parent: span,
            transform: "filler",
        },
        vec![0; filler as usize],
        0,
        None,
    )?;
    lazy_reads(cx, (span, len, vec![(0, 100), (len - 100, 100)])).await
}

#[test]
fn memory_pressure_does_not_truncate_lazy_streams() {
    let content = vec![0x33u8; 2 << 20];
    let stream = deflate_stored(&content);
    let limits = Limits {
        max_derived: 4 << 20,
        ..Limits::default()
    };
    let mut session = Session::new(limits);
    let source = session.add_source(stream.len() as u64);
    let span = Span::new(source, 0, stream.len() as u64);
    let len = content.len() as u64;
    let root = session.add_root(Node::new("crowded").lazy(crowded, (span, len)));
    session.expand(root, 10);
    run(&mut session, &stream, 1_000_000, 100_000);
    let (_, names) = names(&session, root);
    assert_eq!(
        names,
        vec![
            "0: 100 bytes".to_owned(),
            format!("{}: 100 bytes", len - 100),
            format!("len {len}")
        ]
    );
}

#[test]
fn the_work_limit_bounds_work_between_pages_not_a_whole_listing() {
    let mut session = Session::new(Limits {
        max_work: 1000,
        ..Limits::default()
    });
    let root = numbers_root(&mut session, 5000);
    for page in 1..=50 {
        session.expand(root, page * 100);
        run(&mut session, &[], 1_000_000, 100);
    }
    let children = session.children(root).unwrap();
    assert!(children.error.is_none(), "{:?}", children.error);
    assert_eq!(children.ids.len(), 5000);
}

#[test]
fn exploring_twice_gives_the_same_tree() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/external/gzip/large-member.tar.gz"
    ))
    .unwrap();
    let explore = |host: &mut Session, root: NodeId| {
        fn walk(session: &mut Session, data: &[u8], id: NodeId, depth: usize) {
            if depth == 0 {
                return;
            }
            session.expand(id, 1000);
            run(session, data, 1_000_000, 10_000);
            let ids = session.children(id).unwrap().ids.to_vec();
            for c in ids {
                walk(session, data, c, depth - 1);
            }
        }
        walk(host, &data, root, 24);
        fillyfoal::render::tree(host, root)
    };
    let mut session = Session::new(Limits {
        chunk_size: 64,
        ..Limits::default()
    });
    let source = session.add_source(data.len() as u64);
    let root = session.add_root(fillyfoal::formats::root(
        "large-member.tar.gz",
        Span::new(source, 0, data.len() as u64),
    ));
    let first = explore(&mut session, root);
    session.collapse(root);
    let second = explore(&mut session, root);
    assert_eq!(first, second);
}
