//! Data dissectors under crafted inputs: Parquet DELTA streams that claim
//! huge counts from a few bytes, and R serializations nested deeply,
//! claiming huge lengths or cut short. Work stays charged and bounded,
//! and what is shown stays in proportion to the limits.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{ChildState, DiagKind, Limits, NodeId, Value};

/// Expands `id` by `page` more children and returns them all.
fn page(host: &mut Host, id: NodeId, page: u64) -> Vec<NodeId> {
    host.session.expand_more(id, page);
    host.run();
    host.session.children(id).unwrap().ids.to_vec()
}

/// Follows a path of child names from the root, expanding as it goes.
fn walk(host: &mut Host, names: &[&str]) -> NodeId {
    let mut id = host.root;
    for name in names {
        page(host, id, 64);
        id = host
            .child(id, name)
            .unwrap_or_else(|| panic!("no {name:?} in\n{}", host.render()));
    }
    id
}

fn summary(host: &Host, id: NodeId) -> String {
    host.session
        .node(id)
        .unwrap()
        .summary
        .clone()
        .unwrap_or_default()
}

/// Every diagnostic kind under `id` (its own, its children's, the
/// expansion's error).
fn kinds_under(host: &Host, id: NodeId) -> Vec<DiagKind> {
    let mut out = Vec::new();
    let mut stack = vec![id];
    while let Some(id) = stack.pop() {
        out.extend(
            host.session
                .node(id)
                .unwrap()
                .diagnostics
                .iter()
                .map(|d| d.kind),
        );
        if let Some(c) = host.session.children(id) {
            out.extend(c.error.map(|e| e.kind));
            stack.extend(c.ids.iter().copied());
        }
    }
    out
}

/// Expands `id` by `n` children with a small budget per poll; returns how
/// many polls yielded and the work charged.
fn stepped(host: &mut Host, id: NodeId, n: u64, budget: u64) -> (u32, u64) {
    let before = host.session.work_done();
    let saved = host.budget;
    host.budget = budget;
    let polls = host.polls;
    page(host, id, n);
    host.budget = saved;
    let yields = u32::try_from(host.polls - polls).unwrap();
    (yields, host.session.work_done() - before)
}

// ---------------------------------------------------------------------------
// Parquet: a minimal writer (Thrift compact protocol)

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push(v as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

/// A Thrift compact struct being written: tracks the last field id.
struct Thrift<'a> {
    out: &'a mut Vec<u8>,
    last: i16,
}

impl<'a> Thrift<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        Thrift { out, last: 0 }
    }
    fn header(&mut self, id: i16, t: u8) {
        let delta = id - self.last;
        assert!((1..=15).contains(&delta));
        self.out.push((delta as u8) << 4 | t);
        self.last = id;
    }
    fn int(&mut self, id: i16, v: i64) -> &mut Self {
        self.header(id, 6);
        varint(self.out, zigzag(v));
        self
    }
    fn i32(&mut self, id: i16, v: i32) -> &mut Self {
        self.header(id, 5);
        varint(self.out, zigzag(v.into()));
        self
    }
    fn binary(&mut self, id: i16, b: &[u8]) -> &mut Self {
        self.header(id, 8);
        varint(self.out, b.len() as u64);
        self.out.extend_from_slice(b);
        self
    }
    /// A list of `n` elements of type `t`, written by `f`.
    fn list(&mut self, id: i16, t: u8, n: usize, f: impl FnOnce(&mut Vec<u8>)) -> &mut Self {
        self.header(id, 9);
        assert!(n < 15);
        self.out.push((n as u8) << 4 | t);
        f(self.out);
        self
    }
    fn structure(&mut self, id: i16, f: impl FnOnce(&mut Thrift<'_>)) -> &mut Self {
        self.header(id, 12);
        let mut inner = Thrift::new(self.out);
        f(&mut inner);
        inner.out.push(0);
        self
    }
}

fn thrift_struct(out: &mut Vec<u8>, f: impl FnOnce(&mut Thrift<'_>)) {
    let mut t = Thrift::new(out);
    f(&mut t);
    out.push(0);
}

/// A Parquet file of one required column `c` of physical type `phys`, one
/// row group and one uncompressed v1 data page of `num_values` values in
/// `encoding`, holding `body`.
fn parquet(phys: i32, encoding: i32, num_values: i32, body: &[u8]) -> Vec<u8> {
    let mut page = Vec::new();
    thrift_struct(&mut page, |t| {
        t.i32(1, 0)
            .i32(2, body.len() as i32)
            .i32(3, body.len() as i32)
            .structure(5, |d| {
                d.i32(1, num_values).i32(2, encoding).i32(3, 3).i32(4, 3);
            });
    });
    let chunk = (page.len() + body.len()) as i64;
    let mut out = b"PAR1".to_vec();
    out.extend_from_slice(&page);
    out.extend_from_slice(body);
    let mut footer = Vec::new();
    thrift_struct(&mut footer, |t| {
        t.i32(1, 1)
            .list(2, 12, 2, |o| {
                thrift_struct(o, |s| {
                    s.binary(4, b"schema").i32(5, 1);
                });
                thrift_struct(o, |s| {
                    s.i32(1, phys).i32(3, 0).binary(4, b"c");
                });
            })
            .int(3, i64::from(num_values))
            .list(4, 12, 1, |o| {
                thrift_struct(o, |g| {
                    g.list(1, 12, 1, |o| {
                        thrift_struct(o, |c| {
                            c.int(2, 4).structure(3, |m| {
                                m.i32(1, phys)
                                    .list(2, 5, 1, |o| varint(o, zigzag(encoding.into())))
                                    .list(3, 8, 1, |o| {
                                        varint(o, 1);
                                        o.push(b'c');
                                    })
                                    .i32(4, 0)
                                    .int(5, i64::from(num_values))
                                    .int(6, chunk)
                                    .int(7, chunk)
                                    .int(9, 4);
                            });
                        });
                    })
                    .int(2, chunk)
                    .int(3, i64::from(num_values));
                });
            });
    });
    out.extend_from_slice(&footer);
    out.extend_from_slice(&(footer.len() as u32).to_le_bytes());
    out.extend_from_slice(b"PAR1");
    out
}

/// A DELTA_BINARY_PACKED header.
fn delta_header(block: u64, minis: u64, total: u64, first: i64) -> Vec<u8> {
    let mut out = Vec::new();
    for v in [block, minis, total, zigzag(first)] {
        varint(&mut out, v);
    }
    out
}

const VALUES: &[&str] = &[
    "Row groups",
    "Row group 0",
    "c",
    "Data page 0",
    "Page data",
    "Values",
];

const MAX_DELTA: usize = 1 << 20;

#[test]
fn parquet_delta_huge_count_from_a_few_bytes_is_capped() {
    // One block of 2^30 values in one miniblock of bit width 0, claiming
    // 2^62 values: 13 bytes that would expand without end.
    let mut body = delta_header(1 << 30, 1, 1 << 62, 5);
    varint(&mut body, zigzag(1));
    body.push(0);
    let data = parquet(2, 5, i32::MAX, &body);
    let mut host = Host::named("huge.parquet", data, Limits::default());
    let values = walk(&mut host, VALUES);
    let (yields, work) = stepped(&mut host, values, 10, 200);
    let ids = host.session.children(values).unwrap().ids.to_vec();
    let names: Vec<String> = ids
        .iter()
        .map(|&id| host.session.node(id).unwrap().name.to_string())
        .collect();
    assert_eq!(names[..3], ["Header", "Blocks", "[0]"]);
    // Decoding the capped 2^20 values is charged and runs in steps.
    assert!(work > 200, "{work} units");
    assert!(yields > 1, "{yields} yields");
    let kinds = kinds_under(&host, values);
    assert!(kinds.contains(&DiagKind::Limit), "{kinds:?}");
    // The values stop at the cap.
    let all = page(&mut host, values, u64::MAX / 2);
    assert_eq!(all.len(), 2 + MAX_DELTA);
    assert_eq!(
        host.session.children(values).unwrap().state,
        ChildState::Complete
    );
    let last = *all.last().unwrap();
    assert_eq!(
        host.session.node(last).unwrap().name,
        format!("[{}]", MAX_DELTA - 1)
    );
}

#[test]
fn parquet_delta_many_tiny_miniblocks_are_charged() {
    // One block of 131072 miniblocks of 8 values, all of bit width 0:
    // every miniblock is a loop iteration that reads nothing.
    let minis = 1u64 << 17;
    let mut body = delta_header(8 * minis, minis, 8 * minis, 0);
    varint(&mut body, zigzag(1));
    body.extend(std::iter::repeat_n(0u8, minis as usize));
    let data = parquet(2, 5, (8 * minis) as i32, &body);
    let mut host = Host::named("minis.parquet", data, Limits::default());
    let values = walk(&mut host, VALUES);
    let (yields, work) = stepped(&mut host, values, 10, 200);
    // 2^20 values in 2^17 miniblocks: well over a thousand units, charged
    // as the decode goes rather than in one step.
    assert!(work > 1000, "{work} units");
    assert!(yields > 4, "{yields} yields");
    // The block lists its miniblocks lazily, in pages.
    let blocks = host.child(values, "Blocks").unwrap();
    assert_eq!(summary(&host, blocks), "1");
    let block = page(&mut host, blocks, 10)[0];
    let first = page(&mut host, block, 100);
    assert_eq!(first.len(), 100);
    assert_eq!(
        summary(&host, first[1]),
        "bit width 0, 8 values",
        "{}",
        host.render()
    );
}

#[test]
fn parquet_delta_truncated_stream_shows_what_decoded() {
    // 1000 values in blocks of 128 (4 miniblocks of 32) at bit width 4,
    // cut in the third block.
    let mut body = delta_header(128, 4, 1000, 0);
    for _ in 0..2 {
        varint(&mut body, zigzag(-3));
        body.extend_from_slice(&[4, 4, 4, 4]);
        body.extend(std::iter::repeat_n(0x21u8, 4 * 16));
    }
    varint(&mut body, zigzag(0));
    body.extend_from_slice(&[4, 4]);
    body.extend_from_slice(&[0x11; 5]);
    let data = parquet(1, 5, 1000, &body);
    let mut host = Host::named("cut.parquet", data, Limits::default());
    let values = walk(&mut host, VALUES);
    let all = page(&mut host, values, 10_000);
    // Header, blocks, the first value and two whole blocks of deltas.
    assert_eq!(all.len(), 2 + 1 + 256, "{}", host.render());
    let kinds = kinds_under(&host, values);
    assert!(kinds.contains(&DiagKind::Truncated), "{kinds:?}");
    // Deltas alternate 1 - 3 and 2 - 3.
    let v = |i: usize| format!("{:?}", host.session.node(all[2 + i]).unwrap().value);
    let int = |value: i64| format!("{:?}", Some(Value::Int { value, bits: 32 }));
    assert_eq!(
        [v(0), v(1), v(2), v(255)],
        [int(0), int(-2), int(-3), int(-383)]
    );
}

#[test]
fn parquet_delta_byte_array_huge_count_is_capped() {
    // DELTA_LENGTH_BYTE_ARRAY: 2^62 lengths, all zero, in 13 bytes.
    let mut body = delta_header(1 << 30, 1, 1 << 62, 0);
    varint(&mut body, 0);
    body.push(0);
    let data = parquet(6, 6, i32::MAX, &body);
    let mut host = Host::named("bytes.parquet", data, Limits::default());
    let values = walk(&mut host, VALUES);
    let (yields, work) = stepped(&mut host, values, 10, 200);
    assert!(work > 200, "{work} units");
    assert!(yields > 1, "{yields} yields");
    let lengths = host.child(values, "Lengths").unwrap();
    assert_eq!(
        summary(&host, lengths),
        format!("{MAX_DELTA} DELTA_BINARY_PACKED values")
    );
    let shown = host.session.children(values).unwrap().ids.len();
    assert!(shown <= 2 + 10 + 64, "{shown}");
}

// ---------------------------------------------------------------------------
// R serialization (XDR)

/// An RDS stream (version 2) holding `item`.
fn rds(item: &[u8]) -> Vec<u8> {
    let mut out = b"X\n".to_vec();
    for v in [2u32, 0x040401, 0x020300] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(item);
    out
}

fn be(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

const VECSXP: u32 = 19;
const INTSXP: u32 = 13;
const NILVALUE: u32 = 254;

#[test]
fn r_deeply_nested_lists_hit_the_stack_limit_in_steps() {
    // list(list(list(... NULL ...), NULL), NULL), 100000 deep: skipping
    // the outermost item stacks one pending NULL per level.
    let depth = 100_000;
    let mut item = Vec::new();
    for _ in 0..depth {
        be(&mut item, VECSXP);
        be(&mut item, 2);
    }
    for _ in 0..=depth {
        be(&mut item, NILVALUE);
    }
    let mut host = Host::named("deep.rds", rds(&item), Limits::default());
    let top = walk(&mut host, &["Top-level object"]);
    assert_eq!(summary(&host, top), "list, 2 elements");
    let (yields, work) = stepped(&mut host, top, 10, 500);
    assert!(yields > 10, "{yields} yields, {work} units");
    let kinds = kinds_under(&host, top);
    assert!(kinds.contains(&DiagKind::Limit), "{kinds:?}");
}

#[test]
fn r_nested_lists_explore_level_by_level() {
    // 40 levels: each expansion measures what is below it, so the work of
    // exploring all of them stays modest.
    let depth = 40;
    let mut item = Vec::new();
    for _ in 0..depth {
        be(&mut item, VECSXP);
        be(&mut item, 2);
    }
    for _ in 0..=depth {
        be(&mut item, NILVALUE);
    }
    let mut host = Host::named("nested.rds", rds(&item), Limits::default());
    host.explore(host.root, 64, 100);
    assert!(
        host.session.work_done() < 200_000,
        "{}",
        host.session.work_done()
    );
    let kinds = common::diagnostic_kinds(&host);
    assert!(kinds.is_empty(), "{kinds:?}");
}

#[test]
fn r_huge_lengths_are_rejected_before_reading() {
    // An integer vector claiming 2^31 - 1 elements, and a long vector
    // claiming 2^62, each followed by four.
    for header in [vec![0x7fff_ffffu32], vec![u32::MAX, 0x4000_0000, 0]] {
        let mut item = Vec::new();
        be(&mut item, INTSXP);
        for v in &header {
            be(&mut item, *v);
        }
        for v in 1..=4 {
            be(&mut item, v);
        }
        let mut host = Host::named("long.rds", rds(&item), Limits::default());
        host.explore_all();
        // Four elements read, then the truncation.
        let top = host.child(host.root, "Top-level object").unwrap();
        let kids = host.session.children(top).unwrap();
        assert_eq!(kids.ids.len(), 4, "{}", host.render());
        assert!(host.session.live_nodes() < 64);
        let kinds = common::diagnostic_kinds(&host);
        assert!(kinds.contains(&DiagKind::Truncated), "{kinds:?}");
    }
}

#[test]
fn r_list_claiming_more_elements_than_present_shows_those_present() {
    // A list claiming 2^40 elements holding 50000 NULLs: walking the
    // list (for its attributes) runs in steps and stops at the end; the
    // elements present are still listed.
    let present = 50_000;
    let mut item = Vec::new();
    be(&mut item, VECSXP);
    for v in [u32::MAX, 0x100, 0] {
        be(&mut item, v);
    }
    for _ in 0..present {
        be(&mut item, NILVALUE);
    }
    let mut host = Host::named("short.rds", rds(&item), Limits::default());
    let top = walk(&mut host, &["Top-level object"]);
    let (yields, _) = stepped(&mut host, top, 10, 500);
    assert!(yields > 4, "{yields} yields");
    let first = host.session.children(top).unwrap().ids.to_vec();
    assert_eq!(first.len(), 10, "{}", host.render());
    let all = page(&mut host, top, 1 << 20);
    assert_eq!(all.len(), present);
    let kinds = kinds_under(&host, top);
    assert!(kinds.contains(&DiagKind::Truncated), "{kinds:?}");
}

#[test]
fn r_cut_short_at_every_length_settles() {
    // A data frame-like list with names, cut everywhere.
    let mut item = Vec::new();
    be(&mut item, VECSXP | 0x200);
    be(&mut item, 2);
    be(&mut item, INTSXP);
    be(&mut item, 3);
    for v in [1, 2, 3] {
        be(&mut item, v);
    }
    be(&mut item, 16);
    be(&mut item, 1);
    be(&mut item, 9 | 0x40 << 12);
    be(&mut item, 2);
    item.extend_from_slice(b"hi");
    // Attributes: names = c("a", "b").
    be(&mut item, 2 | 0x400);
    be(&mut item, 1);
    be(&mut item, 9 | 0x40 << 12);
    be(&mut item, 5);
    item.extend_from_slice(b"names");
    be(&mut item, 16);
    be(&mut item, 2);
    for s in [b"a", b"b"] {
        be(&mut item, 9 | 0x40 << 12);
        be(&mut item, 1);
        item.extend_from_slice(s);
    }
    be(&mut item, NILVALUE);
    let full = rds(&item);
    let mut host = Host::named("df.rds", full.clone(), Limits::default());
    host.explore_all();
    let text = host.render();
    assert!(text.contains("a — integer vector, 3 values"), "{text}");
    assert!(text.contains("b — character vector"), "{text}");
    for len in 14..full.len() {
        let mut host = Host::named("df.rds", full[..len].to_vec(), Limits::default());
        host.explore_all();
        assert!(host.session.live_nodes() < 100, "{len}");
    }
}

// ---------------------------------------------------------------------------
// Ruby Marshal and Erlang terms: a large top-level container lists its
// first elements without scanning to its end first.

/// Expands the root by one page and returns (bytes read, work charged).
fn first_page(name: &str, data: Vec<u8>) -> (u64, u64) {
    let mut host = Host::named(name, data, Limits::default());
    let root = host.root;
    page(&mut host, root, 16);
    let kids = host.session.children(root).unwrap();
    assert!(kids.ids.len() >= 16, "{}", host.render());
    (host.bytes_supplied, host.session.work_done())
}

#[test]
fn marshal_large_array_lists_its_start_without_scanning_it_all() {
    // Marshal.dump of 400,000 fixnums: '[', a packed count, 'i' and one
    // byte each (about 800 KB).
    let n: u32 = 400_000;
    let mut data = vec![4, 8, b'[', 3];
    data.extend_from_slice(&n.to_le_bytes()[..3]);
    for i in 0..n {
        data.extend_from_slice(&[b'i', u8::try_from(i % 100).unwrap() + 5]);
    }
    let len = data.len() as u64;
    let (read, work) = first_page("big.marshal", data);
    assert!(read < len / 4, "read {read} of {len} bytes");
    assert!(work < 20_000, "{work} units");
}

#[test]
fn etf_large_list_lists_its_start_without_scanning_it_all() {
    // term_to_binary of a list of 400,000 small integers: 131, 'l', the
    // count, 'a' and one byte each, then nil.
    let n: u32 = 400_000;
    let mut data = vec![131, 108];
    data.extend_from_slice(&n.to_be_bytes());
    for i in 0..n {
        data.extend_from_slice(&[97, u8::try_from(i % 200).unwrap()]);
    }
    data.push(106);
    let len = data.len() as u64;
    let (read, work) = first_page("big.etf", data);
    assert!(read < len / 4, "read {read} of {len} bytes");
    assert!(work < 20_000, "{work} units");
}

#[test]
fn marshal_and_etf_trailing_data_is_listed_after_the_members() {
    let cases: [(&str, Vec<u8>, &str); 4] = [
        // [1, 2] then a stray byte.
        (
            "t.marshal",
            vec![4, 8, b'[', 7, b'i', 6, b'i', 7, 0xff],
            "[1]",
        ),
        // {} with default nil, then two stray bytes.
        ("d.marshal", vec![4, 8, b'}', 0, b'0', 1, 2], "(default)"),
        // [1, 2] (a proper list) then a stray byte.
        (
            "t.etf",
            vec![131, 108, 0, 0, 0, 2, 97, 1, 97, 2, 106, 0xff],
            "[1]",
        ),
        // {1} then a stray byte.
        ("u.etf", vec![131, 104, 1, 97, 1, 0xff], "[0]"),
    ];
    for (name, data, last) in cases {
        // Trailing data fails the probes: open them as their format.
        let format = if name.ends_with("etf") {
            "erlang-etf"
        } else {
            "ruby-marshal"
        };
        let format = fillyfoal::formats::by_name(format).unwrap();
        let len = data.len();
        let mut host = Host::open(name, data, Limits::default(), Some(format));
        host.explore_all();
        let text = host.render();
        let at_last = text.find(last).unwrap_or_else(|| panic!("{text}"));
        let at_trailing = text
            .find("Trailing data")
            .unwrap_or_else(|| panic!("{text}"));
        assert!(at_last < at_trailing, "{text}");
        assert_eq!(
            text.matches("Trailing data").count(),
            1,
            "{name}, {len}: {text}"
        );
    }
    // No trailing data: none listed.
    let mut host = Host::named(
        "ok.etf",
        vec![131, 108, 0, 0, 0, 1, 97, 1, 106],
        Limits::default(),
    );
    host.explore_all();
    assert!(!host.render().contains("Trailing"), "{}", host.render());
}
