//! Host control over the work a session does: polling one node, bounded
//! reads of lazily decoded sources, progress, and node addresses.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{
    ChildState, Count, Cx, Limits, Node, NodeId, Progress, ReadProgress, Result, Span, Value, Wait,
    formats,
};

const BIG_LEN: u64 = 64 << 20;

fn big_zlib() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/lazy/big.zlib"
    ))
    .unwrap()
}

/// The bytes of `tests/data/lazy/big.zlib` decoded, at `i`.
fn big_byte(i: u64) -> u8 {
    ((i * 7) + (i >> 12)) as u8
}

/// Emits one node spanning the 64 MiB lazily decoded stream.
async fn lazy_stream(cx: Cx, file: Span) -> Result<()> {
    let s = cx.decode_lazy(file, &fillyfoal::codec::Codec::Zlib, BIG_LEN)?;
    cx.emit(Node::new("stream").span(s));
    Ok(())
}

/// Reads the last 16 bytes of the lazily decoded stream.
async fn read_end(cx: Cx, file: Span) -> Result<()> {
    let s = cx.decode_lazy(file, &fillyfoal::codec::Codec::Zlib, BIG_LEN)?;
    let bytes = cx.read(s.sub(BIG_LEN - 16, 16)).await?;
    cx.emit(Node::new("end").value(Value::Bytes(bytes)));
    Ok(())
}

fn big_host() -> (Host, Span) {
    let data = big_zlib();
    let file = Span::new(fillyfoal::SourceId::default_host(), 0, data.len() as u64);
    let mut host = Host::new(data, Limits::default());
    host.max_polls = 10_000_000;
    (host, file)
}

fn supply(host: &mut Host, requests: Vec<fillyfoal::ByteRequest>) {
    for r in requests {
        let start = r.offset as usize;
        let end = (start + r.len as usize).min(host.data.len());
        let bytes = host.data[start..end].to_vec();
        host.session.supply(r.source, r.offset, &bytes);
    }
}

/// A far read into a lazily decoded stream can be done in bounded steps:
/// each `read_step` decodes a little and yields, and the next continues.
#[test]
fn read_step_decodes_in_bounded_resumable_steps() {
    let (mut host, file) = big_host();
    let root = host
        .session
        .add_root(Node::new("big").lazy(lazy_stream, file));
    host.session.expand(root, 10);
    host.run();
    let stream = host.session.children(root).unwrap().ids[0];
    let span = host.session.node(stream).unwrap().span.unwrap();
    let tail = span.sub(BIG_LEN - 16, 16);

    let mut yields = 0;
    let data = loop {
        match host.session.read_step(tail, 1000) {
            ReadProgress::Done(data) => break data,
            ReadProgress::NeedBytes(requests) => supply(&mut host, requests),
            ReadProgress::Yielded => yields += 1,
        }
        assert!(yields < 100_000, "read_step makes no progress");
    };
    let want: Vec<u8> = (BIG_LEN - 16..BIG_LEN).map(big_byte).collect();
    assert_eq!(data, want);
    // 1000 units are about 4 MiB of decoding: a 64 MiB stream takes many.
    assert!(yields >= 10, "only {yields} yields");
    // The work is kept: reading there again is immediate.
    assert_eq!(host.session.read_step(tail, 1), ReadProgress::Done(want));
}

/// A read inside an expansion is bounded the same way: one poll decodes
/// about its budget's worth, not the whole stream.
#[test]
fn expansion_reads_spend_the_budget() {
    let (mut host, file) = big_host();
    let root = host.session.add_root(Node::new("big").lazy(read_end, file));
    host.session.expand(root, 10);
    host.budget = 1000;
    host.run();
    let want: Vec<u8> = (BIG_LEN - 16..BIG_LEN).map(big_byte).collect();
    let c = host.session.children(root).unwrap();
    assert!(c.error.is_none(), "{:?}", c.error);
    let got = host.session.node(c.ids[0]).unwrap().value.clone();
    assert_eq!(got, Some(Value::Bytes(want)));
    assert!(host.polls >= 10, "decoded in {} polls", host.polls);
}

/// Emits `n` numbered children, reporting progress.
async fn numbers(cx: Cx, n: u64) -> Result<()> {
    for i in 0..n {
        cx.progress(i, n);
        cx.push(Node::new(format!("n{i}")).value(Value::UInt {
            value: i,
            bits: 64,
            radix: fillyfoal::Radix::Dec,
        }))
        .await;
    }
    Ok(())
}

async fn two_walks(cx: Cx, n: u64) -> Result<()> {
    cx.emit(Node::new("a").lazy(numbers, n));
    cx.emit(Node::new("b").lazy(numbers, n));
    Ok(())
}

fn values(host: &Host, id: NodeId) -> Vec<u64> {
    host.session
        .children(id)
        .unwrap()
        .ids
        .iter()
        .map(|&c| match host.session.node(c).unwrap().value {
            Some(Value::UInt { value, .. }) => value,
            ref other => panic!("{other:?}"),
        })
        .collect()
}

/// `poll_node` runs one expansion; the others stay parked with their
/// children and continue, without restarting, when polled later.
#[test]
fn poll_node_runs_only_that_node_and_others_stay_parked() {
    const N: u64 = 50_000;
    let mut host = Host::new(Vec::new(), Limits::default());
    let root = host.session.add_root(Node::new("root").lazy(two_walks, N));
    host.session.expand(root, 10);
    host.run();
    let ids = host.session.children(root).unwrap().ids.to_vec();
    let (a, b) = (ids[0], ids[1]);
    host.session.expand(a, N);
    host.session.expand(b, N);

    // A few steps of each, then only `a` to the end.
    for _ in 0..3 {
        assert_eq!(host.session.poll_node(a, 500), Progress::Yielded);
        assert_eq!(host.session.poll_node(b, 500), Progress::Yielded);
    }
    let b_before = values(&host, b);
    let b_first = host.session.children(b).unwrap().ids[0];
    assert!(!b_before.is_empty() && (b_before.len() as u64) < N);
    let (done, total) = host.session.progress(b).unwrap();
    assert_eq!(total, N);
    assert!(done > 0 && done < N);

    let mut polls = 0;
    while host.session.poll_node(a, 500) != Progress::Idle {
        polls += 1;
        assert!(polls < 1_000_000);
    }
    assert_eq!(
        host.session.children(a).unwrap().state,
        ChildState::Complete
    );
    assert_eq!(host.session.progress(a), None, "finished");
    assert_eq!(values(&host, a), (0..N).collect::<Vec<_>>());

    // `b` did not move while it was not polled.
    let cb = host.session.children(b).unwrap();
    assert_eq!(cb.state, ChildState::Running(Wait::Budget));
    assert_eq!(values(&host, b), b_before);

    // Trimming keeps a parked expansion.
    host.session.trim(0, &[]);
    assert_eq!(host.session.children(b).unwrap().ids[0], b_first);

    // Polling it again continues where it stopped.
    while host.session.poll_node(b, 500) != Progress::Idle {}
    assert_eq!(host.session.children(b).unwrap().ids[0], b_first);
    assert_eq!(values(&host, b), (0..N).collect::<Vec<_>>());
    assert_eq!(host.session.children(b).unwrap().count, Count::Exact(N));
}

/// `poll_node` reports only the node's own needs.
#[test]
fn poll_node_reports_its_own_byte_requests() {
    let (mut host, file) = big_host();
    let root = host.session.add_root(Node::new("big").lazy(read_end, file));
    host.session.expand(root, 10);
    let other = host.session.add_root(Node::new("other").lazy(numbers, 5));
    host.session.expand(other, 10);
    assert_eq!(host.session.poll_node(other, 1000), Progress::Idle);
    assert_eq!(values(&host, other), vec![0, 1, 2, 3, 4]);
    // The big root has not run at all.
    assert_eq!(
        host.session.children(root).unwrap().state,
        ChildState::Running(Wait::Ready)
    );
    match host.session.poll_node(root, 1000) {
        Progress::NeedBytes(requests) => assert!(!requests.is_empty()),
        other => panic!("{other:?}"),
    }
}

fn member_content(host: &mut Host, archive: NodeId, name: &str) -> NodeId {
    let member = host.child(archive, name).expect("member");
    host.session.expand(member, 100);
    host.run();
    let content = host.child(member, "Content").expect("member content");
    host.session.expand(content, 100);
    host.run();
    content
}

fn tarball() -> Host {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/external/zstd/large-member.tar.zst"
    ))
    .unwrap();
    let mut host = Host::with_chunk(data, 4096);
    host.session.expand(host.root, 100);
    host.run();
    host
}

/// A node's address names it in another session over the same bytes, so a
/// host can carry an "inspect as" choice over: `reinterpret_at` applies it
/// when the node is reached.
#[test]
fn addresses_carry_reinterpretation_across_sessions() {
    let mut first = tarball();
    let content = first.child(first.root, "Decompressed").unwrap();
    first.session.expand(content, 100);
    first.run();
    let member = member_content(&mut first, content, "a.txt");
    let (root, path) = first.session.address(member).unwrap();
    assert_eq!(root, first.root);
    assert_eq!(first.session.node_at(root, &path), Some(member));
    assert_eq!(first.session.node_at(root, &[999]), None);

    let der = formats::by_name("der").unwrap();
    let mut second = tarball();
    second.session.reinterpret_at(second.root, &path, Some(der));
    assert_eq!(
        second
            .session
            .reinterpretations(second.root)
            .iter()
            .map(|(p, f)| (p.clone(), f.name))
            .collect::<Vec<_>>(),
        vec![(path.clone(), "der")]
    );
    // Walk down the same path.
    let mut id = second.root;
    for &index in &path {
        second.session.expand(id, index + 1);
        second.run();
        id = second.session.node_at(id, &[index]).expect("child");
    }
    second.session.expand(id, 100);
    second.run();
    let i = second.session.interpretation(id).unwrap();
    assert_eq!((i.format.map(|f| f.name), i.forced), (Some("der"), true));
}

/// A ustar archive of `files` members of `size` bytes each.
fn ustar(files: usize, size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..files {
        let mut h = [0u8; 512];
        let name = format!("member{i}.bin");
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[108..116].copy_from_slice(b"0000000\0");
        h[116..124].copy_from_slice(b"0000000\0");
        h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        h[136..148].copy_from_slice(b"00000000000\0");
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        out.extend_from_slice(&h);
        out.extend((0..size).map(|j| (i * 31 + j * 7) as u8));
        out.resize(out.len().next_multiple_of(512), 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

/// A zstd frame of raw blocks with no content size, as `zstd` writes when
/// compressing a pipe.
fn zstd_unsized(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x58]; // no FCS; 8 MiB window
    let chunks: Vec<&[u8]> = data.chunks(128 * 1024).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        let last = u32::from(i + 1 == chunks.len());
        let header = last | ((chunk.len() as u32) << 3); // raw block
        out.extend_from_slice(&header.to_le_bytes()[..3]);
        out.extend_from_slice(chunk);
    }
    out
}

/// A large compressed stream whose decoded size nothing records is decoded
/// on demand: its first member is listed after reading a small part of the
/// file (not after decoding all of it), with a provisional length that
/// becomes the real one once the stream has been read to its end.
#[test]
fn unsized_streams_are_decoded_on_demand() {
    let tar = ustar(6, 1 << 20);
    let file = zstd_unsized(&tar);
    let mut host = Host::named("big.tar.zst", file.clone(), Limits::default());
    host.session.expand(host.root, 1);
    let root = host.root;
    while host.child(root, "Decompressed").is_none() {
        match host.session.poll_node(root, 10_000) {
            Progress::NeedBytes(r) => supply(&mut host, r),
            Progress::Idle => break,
            _ => {}
        }
    }
    let content = host.child(root, "Decompressed").unwrap();
    host.bytes_supplied = 0;
    host.session.expand(content, 1);
    let mut first = None;
    while first.is_none() {
        match host.session.poll_node(content, 10_000) {
            Progress::NeedBytes(r) => {
                host.bytes_supplied += r.iter().map(|r| r.len).sum::<u64>();
                supply(&mut host, r);
            }
            Progress::Idle => panic!("no members"),
            _ => {}
        }
        first = host.session.children(content).unwrap().ids.first().copied();
    }
    let member = host.session.node(first.unwrap()).unwrap();
    assert_eq!(member.name, "member0.bin");
    assert!(
        host.bytes_supplied < file.len() as u64 / 3,
        "read {} of {} bytes before the first member",
        host.bytes_supplied,
        file.len()
    );
    let source = member.span.unwrap().source;
    assert!(!host.session.source_len_known(source));
    assert!(host.session.source_len(source) >= tar.len() as u64);

    // Reading to the end finds the real length.
    let all = Span::new(source, 0, host.session.source_len(source));
    let data = loop {
        match host
            .session
            .read_step(all.sub(tar.len() as u64 - 16, 1 << 20), 10_000)
        {
            ReadProgress::Done(data) => break data,
            ReadProgress::NeedBytes(r) => supply(&mut host, r),
            ReadProgress::Yielded => {}
        }
    };
    assert_eq!(data, tar[tar.len() - 16..]);
    assert!(host.session.source_len_known(source));
    assert_eq!(host.session.source_len(source), tar.len() as u64);
}

/// gzip's ISIZE is the size modulo 2^32: a body that could decode to 4 GiB
/// or more is decoded on demand with its size found at the end, not cut off
/// at a length that may have wrapped.
#[test]
fn gzip_size_is_trusted_only_when_it_cannot_have_wrapped() {
    let payload: Vec<u8> = (0..(5u32 << 20))
        .map(|i| (i * 7 + (i >> 9)) as u8)
        .collect();
    // Stored DEFLATE blocks.
    let mut gz = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    let chunks: Vec<&[u8]> = payload.chunks(65_535).collect();
    for (i, chunk) in chunks.iter().enumerate() {
        gz.push(u8::from(i + 1 == chunks.len()));
        gz.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
        gz.extend_from_slice(&(!(chunk.len() as u16)).to_le_bytes());
        gz.extend_from_slice(chunk);
    }
    gz.extend_from_slice(&0u32.to_le_bytes()); // CRC (not checked here)
    gz.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    let mut host = Host::named("big.gz", gz, Limits::default());
    host.explore(host.root, 1, 100);
    let content = host.child(host.root, "Content").unwrap();
    host.session.expand(content, 1);
    host.run();
    let first = host.session.children(content).unwrap().ids[0];
    let source = host.session.node(first).unwrap().span.unwrap().source;
    assert!(!host.session.source_len_known(source));
    let tail = Span::new(source, payload.len() as u64 - 16, 1 << 20);
    let data = loop {
        match host.session.read_step(tail, 100_000) {
            ReadProgress::Done(data) => break data,
            ReadProgress::NeedBytes(r) => supply(&mut host, r),
            ReadProgress::Yielded => {}
        }
    };
    assert_eq!(data, payload[payload.len() - 16..]);
    assert_eq!(host.session.source_len(source), payload.len() as u64);
}
