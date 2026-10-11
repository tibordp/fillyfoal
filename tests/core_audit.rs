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

// ---------------------------------------------------------------------------
// Checkpoints in lazily decoded streams

/// Bytes that differ along the stream, so a read from the wrong place shows.
fn pattern(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u32).wrapping_mul(2_654_435_761).to_le_bytes()[1])
        .collect()
}

async fn lazy_source(cx: Cx, (span, codec, len): (Span, Codec, u64)) -> Result<()> {
    let decoded = cx.decode_lazy(span, &codec, len)?;
    cx.emit(Node::new("decoded").span(decoded));
    Ok(())
}

/// A session over `encoded` with one lazily decoded source; returns the
/// session and the decoded span.
fn lazy_session(encoded: &[u8], codec: Codec, len: u64, limits: Limits) -> (Session, Span) {
    let mut session = Session::new(limits);
    let source = session.add_source(encoded.len() as u64);
    let span = Span::new(source, 0, encoded.len() as u64);
    let root = session.add_root(Node::new("lazy").lazy(lazy_source, (span, codec, len)));
    session.expand(root, 10);
    run(&mut session, encoded, 1_000_000, 100);
    let child = session.children(root).unwrap().ids[0];
    let decoded = session.node(child).unwrap().span.unwrap();
    (session, decoded)
}

/// Reads `span` in steps of `budget` work units, supplying host bytes;
/// returns the data and the number of steps.
fn read_in_steps(session: &mut Session, data: &[u8], span: Span, budget: u64) -> (Vec<u8>, u64) {
    let mut steps = 0;
    loop {
        steps += 1;
        assert!(steps < 1_000_000, "read did not finish");
        match session.read_step(span, budget) {
            fillyfoal::ReadProgress::Done(bytes) => return (bytes, steps),
            fillyfoal::ReadProgress::Yielded => {}
            fillyfoal::ReadProgress::NeedBytes(requests) => {
                steps -= 1;
                for r in requests {
                    let end = ((r.offset + r.len) as usize).min(data.len());
                    session.supply(r.source, r.offset, &data[r.offset as usize..end]);
                }
            }
        }
    }
}

fn checkpoint_limits() -> Limits {
    // A quarter of this is kept behind the decoding front: 4 MiB.
    Limits {
        max_derived: 16 << 20,
        ..Limits::default()
    }
}

#[test]
fn reading_behind_a_lazy_stream_resumes_from_a_checkpoint() {
    let content = pattern(24 << 20);
    let encoded = deflate_stored(&content);
    let (mut session, decoded) = lazy_session(
        &encoded,
        Codec::Deflate,
        content.len() as u64,
        checkpoint_limits(),
    );
    // Decode it all: the front is now far past 12 MiB.
    let (tail, _) = read_in_steps(
        &mut session,
        &encoded,
        decoded.sub(decoded.len - 16, 16),
        1 << 20,
    );
    assert_eq!(tail, content[content.len() - 16..]);
    // Reading back at 12 MiB decodes from a checkpoint nearby, not from the
    // start (about 6,000 units).
    let at = 12 << 20;
    let (bytes, steps) = read_in_steps(&mut session, &encoded, decoded.sub(at, 4096), 50);
    assert_eq!(bytes, content[at as usize..at as usize + 4096]);
    assert!(steps <= 10, "{steps} steps of 50 units");
    // And everywhere else, byte for byte.
    for at in [0u64, 1 << 20, 5_000_000, 23 << 20] {
        let (bytes, _) = read_in_steps(&mut session, &encoded, decoded.sub(at, 1000), 1 << 20);
        assert_eq!(bytes, content[at as usize..at as usize + 1000], "at {at}");
    }
}

async fn crowd_out(cx: Cx, (span, n): (Span, u64)) -> Result<()> {
    cx.add_derived(
        Origin {
            parent: span,
            transform: "crowd",
        },
        vec![0; n as usize],
        0,
        None,
    )?;
    Ok(())
}

#[test]
fn evicting_a_lazy_stream_keeps_its_checkpoints() {
    let content = pattern(24 << 20);
    let encoded = deflate_stored(&content);
    let limits = checkpoint_limits();
    let (mut session, decoded) =
        lazy_session(&encoded, Codec::Deflate, content.len() as u64, limits);
    read_in_steps(
        &mut session,
        &encoded,
        decoded.sub(decoded.len - 16, 16),
        1 << 20,
    );
    // Something else needs nearly all derived memory: the stream's buffers
    // go, its checkpoints (about 2 MiB) stay.
    let filler = Span::new(fillyfoal::SourceId::default_host(), 0, 1);
    let root = session
        .add_root(Node::new("crowd").lazy(crowd_out, (filler, limits.max_derived - (3 << 20))));
    session.expand(root, 1);
    run(&mut session, &encoded, 1_000_000, 100);
    assert!(session.children(root).unwrap().error.is_none());
    let at = 20 << 20;
    let (bytes, steps) = read_in_steps(&mut session, &encoded, decoded.sub(at, 4096), 50);
    assert_eq!(bytes, content[at as usize..at as usize + 4096]);
    assert!(steps <= 10, "{steps} steps of 50 units");
}

#[test]
fn chains_checkpoint_when_little_is_in_flight() {
    // DEFLATE inside DEFLATE: stage one's output is stage two's input.
    let content = pattern(12 << 20);
    let encoded = deflate_stored(&deflate_stored(&content));
    let codec = Codec::chain("test", "test (lazy)", vec![Codec::Deflate, Codec::Deflate]);
    let (mut session, decoded) =
        lazy_session(&encoded, codec, content.len() as u64, checkpoint_limits());
    read_in_steps(
        &mut session,
        &encoded,
        decoded.sub(decoded.len - 16, 16),
        1 << 20,
    );
    let at = 2 << 20;
    let (bytes, steps) = read_in_steps(&mut session, &encoded, decoded.sub(at, 4096), 50);
    assert_eq!(bytes, content[at as usize..at as usize + 4096]);
    assert!(steps <= 10, "{steps} steps of 50 units");
}

async fn seeded_source(cx: Cx, (span, len, block): (Span, u64, u64)) -> Result<()> {
    // Stored DEFLATE blocks need no history: every block start is a point
    // the stream can be decoded from.
    let seeds = (1..len.div_ceil(block))
        .map(|i| fillyfoal::Seed {
            out_pos: i * block,
            in_pos: i * (block + 5),
            decoder: Codec::Deflate.decoder().unwrap(),
        })
        .collect();
    let decoded = cx.decode_lazy_seeded(span, &Codec::Deflate, len, seeds)?;
    cx.emit(Node::new("decoded").span(decoded));
    Ok(())
}

#[test]
fn seeded_streams_start_decoding_near_a_read() {
    let content = pattern(24 << 20);
    let encoded = deflate_stored(&content);
    let mut session = Session::new(checkpoint_limits());
    let source = session.add_source(encoded.len() as u64);
    let span = Span::new(source, 0, encoded.len() as u64);
    let len = content.len() as u64;
    let root = session.add_root(Node::new("seeded").lazy(seeded_source, (span, len, 0xffff)));
    session.expand(root, 10);
    run(&mut session, &encoded, 1_000_000, 100);
    let child = session.children(root).unwrap().ids[0];
    let decoded = session.node(child).unwrap().span.unwrap();
    // The first read, 20 MiB in, decodes from the block before it.
    let at = 20 << 20;
    let (bytes, steps) = read_in_steps(&mut session, &encoded, decoded.sub(at, 4096), 50);
    assert_eq!(bytes, content[at as usize..at as usize + 4096]);
    assert!(steps <= 5, "{steps} steps of 50 units");
    // Then back to the start, and to the end.
    for at in [0u64, 7_777_777, len - 1000] {
        let (bytes, _) = read_in_steps(&mut session, &encoded, decoded.sub(at, 1000), 1 << 20);
        assert_eq!(bytes, content[at as usize..at as usize + 1000], "at {at}");
    }
}

// ---------------------------------------------------------------------------
// Resume marks

type Walk = std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>;

/// Children named by index; records marks but never resumes from them.
async fn forgetful(cx: Cx, n: u64) -> Result<()> {
    for i in 0..n {
        cx.mark(move || i);
        cx.push(Node::new(i.to_string())).await;
    }
    Ok(())
}

/// Resumes from its marks, after probing for a key of another type.
async fn probing(cx: Cx, n: u64) -> Result<()> {
    let _probe: Option<String> = cx.resume::<String>();
    let from = cx.resume::<u64>().unwrap_or(0);
    for i in from..n {
        cx.mark(move || i);
        cx.push(Node::new(i.to_string())).await;
    }
    Ok(())
}

fn jump_back(dissector: fn(Cx, u64) -> Walk) -> Session {
    let mut session = Session::new(Limits::default());
    let root = session.add_root(Node::new("walk").lazy(dissector, 2000));
    session.expand(root, 2000);
    run(&mut session, &[], 1_000_000, 100);
    // Back into the middle: restarts from a mark.
    session.seek(root, 0, 10);
    session.seek(root, 1000, 10);
    run(&mut session, &[], 1_000_000, 100);
    assert_indexed(&session, root);
    assert_eq!(names(&session, root).0, 1000);
    session
}

fn forgetful_boxed(cx: Cx, n: u64) -> Walk {
    Box::pin(forgetful(cx, n))
}

fn probing_boxed(cx: Cx, n: u64) -> Walk {
    Box::pin(probing(cx, n))
}

#[test]
fn a_dissector_that_never_resumes_keeps_indices() {
    jump_back(forgetful_boxed);
}

#[test]
fn a_probe_for_another_key_type_leaves_the_resume_key() {
    jump_back(probing_boxed);
}

/// Children named by where the walk started.
async fn reporting(cx: Cx, n: u64) -> Result<()> {
    let from = cx.resume::<u64>();
    for i in from.unwrap_or(0)..n {
        cx.mark(move || i);
        cx.push(Node::new(format!("{i} from {from:?}"))).await;
    }
    Ok(())
}

#[test]
fn reinterpreting_drops_resume_marks() {
    let mut session = Session::new(Limits::default());
    let root = session.add_root(Node::new("walk").lazy(reporting, 2000));
    session.expand(root, 2000);
    run(&mut session, &[], 1_000_000, 100);
    let format = fillyfoal::formats::by_name("tar").unwrap();
    session.reinterpret(root, Some(format));
    session.seek(root, 1000, 1);
    run(&mut session, &[], 1_000_000, 100);
    assert_eq!(names(&session, root).1, vec!["1000 from None".to_owned()]);
}

// ---------------------------------------------------------------------------
// Piece tables and seeds

async fn many_pieces(cx: Cx, (file, n, transform): (Span, u64, &'static str)) -> Result<()> {
    let pieces = (0..n)
        .map(|i| Span::new(file.source, i % file.len, 1))
        .collect::<Vec<_>>();
    let joined = cx
        .add_pieces_stepped(
            Origin {
                parent: file,
                transform,
            },
            &pieces,
        )
        .await;
    cx.emit(Node::new(match joined {
        Ok(span) => format!("{} bytes", span.len),
        Err(e) => e.message,
    }));
    Ok(())
}

#[test]
fn piece_tables_count_against_derived_memory() {
    let mut session = Session::new(Limits {
        max_derived: 1 << 20,
        ..Limits::default()
    });
    let source = session.add_source(4096);
    let file = Span::new(source, 0, 4096);
    // 32 bytes a piece: 10,000 fit in 1 MiB, 100,000 do not.
    let small = session.add_root(Node::new("small").lazy(many_pieces, (file, 10_000, "small")));
    let large = session.add_root(Node::new("large").lazy(many_pieces, (file, 100_000, "large")));
    session.expand(small, 1);
    session.expand(large, 1);
    run(&mut session, &[0; 4096], 1_000_000, 10_000);
    assert_eq!(names(&session, small).1, vec!["10000 bytes".to_owned()]);
    assert!(names(&session, large).1[0].starts_with("piece table would exceed"));
    assert!(session.derived_bytes() >= 10_000 * 32);
}

/// A gzip member: header, stored DEFLATE, trailer.
fn gzip_member(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    out.extend(deflate_stored(data));
    out.extend(fillyfoal::codec::crc32(data).to_le_bytes());
    out.extend((data.len() as u32).to_le_bytes());
    out
}

async fn lying_index(
    cx: Cx,
    (span, members, member_len, lie): (Span, Vec<u64>, u64, u64),
) -> Result<()> {
    // Member starts, as an index would record them; member `lie` claims
    // the wrong output position.
    let seeds = members
        .iter()
        .enumerate()
        .skip(1)
        .map(|(i, &at)| fillyfoal::Seed {
            out_pos: i as u64 * member_len + if i as u64 == lie { 5000 } else { 0 },
            in_pos: at,
            decoder: Box::new(fillyfoal::codec::pipeline::Streaming(
                fillyfoal::codec::gzip::Gzip::at_member(i as u64),
            )),
        })
        .collect();
    let len = members.len() as u64 * member_len;
    let decoded = cx.decode_lazy_seeded(span, &Codec::Gzip, len, seeds)?;
    cx.emit(Node::new("decoded").span(decoded));
    Ok(())
}

#[test]
fn an_index_that_disagrees_with_the_stream_is_dropped() {
    let member_len = 300_000u64;
    let content = pattern(member_len as usize * 20);
    let mut stream = Vec::new();
    let mut starts = Vec::new();
    for chunk in content.chunks(member_len as usize) {
        starts.push(stream.len() as u64);
        stream.extend(gzip_member(chunk));
    }
    // Codec::Gzip starts after the first member's header.
    let body = &stream[10..];
    let starts: Vec<u64> = starts.iter().map(|s| s.saturating_sub(10)).collect();
    let mut session = Session::new(checkpoint_limits());
    let source = session.add_source(body.len() as u64);
    let span = Span::new(source, 0, body.len() as u64);
    let root =
        session.add_root(Node::new("lying").lazy(lying_index, (span, starts, member_len, 7)));
    session.expand(root, 10);
    run(&mut session, body, 1_000_000, 100);
    let child = session.children(root).unwrap().ids[0];
    let decoded = session.node(child).unwrap().span.unwrap();
    // A read across the end of member 6, decoded from member 6's seed,
    // reaches member 7's start at a different output position than the
    // index claims: the seeds are dropped and the read is decoded again from
    // a point that can be trusted.
    let at = 7 * member_len - 100;
    let (bytes, _) = read_in_steps(&mut session, body, decoded.sub(at, 200), 1 << 20);
    assert_eq!(bytes, content[at as usize..at as usize + 200]);
    // And member 7 itself now comes out right.
    let at = 7 * member_len + 6000;
    let (bytes, _) = read_in_steps(&mut session, body, decoded.sub(at, 1000), 1 << 20);
    assert_eq!(bytes, content[at as usize..at as usize + 1000]);
}
