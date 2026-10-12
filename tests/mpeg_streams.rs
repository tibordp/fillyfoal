//! Elementary streams of MPEG transport and program streams are
//! reassembled from PES payloads as pieces sources in bounded parts: the
//! first part of a long stream is listed after reading about two parts
//! worth of packets (plus read-ahead), not the whole file, and no part holds more than
//! `PART_PIECES` packets.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::cast_possible_truncation
)]

mod common;

use common::Host;
use fillyfoal::{Limits, NodeId};

fn crc32_mpeg(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= u32::from(b) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 != 0 {
                (crc << 1) ^ 0x04c1_1db7
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// A PSI section with the syntax indicator and a CRC.
fn section(table: u8, ext: u16, body: &[u8]) -> Vec<u8> {
    let mut payload = ext.to_be_bytes().to_vec();
    payload.extend_from_slice(&[0xc1, 0, 0]);
    payload.extend_from_slice(body);
    let len = (payload.len() + 4) as u16;
    let mut out = vec![table];
    out.extend_from_slice(&(0xb000 | len).to_be_bytes());
    out.extend_from_slice(&payload);
    let crc = crc32_mpeg(&out);
    out.extend_from_slice(&crc.to_be_bytes());
    out
}

fn packet(out: &mut Vec<u8>, pid: u16, pusi: bool, cc: u8, payload: &[u8]) {
    let mut p = vec![0x47];
    p.extend_from_slice(&((u16::from(pusi) << 14) | pid).to_be_bytes());
    if payload.len() < 184 {
        // Adaptation field stuffing.
        let af = 183 - payload.len();
        p.push(0x30 | (cc & 15));
        p.push(af as u8);
        if af > 0 {
            p.push(0);
            p.extend(std::iter::repeat_n(0xff, af - 1));
        }
    } else {
        p.push(0x10 | (cc & 15));
    }
    p.extend_from_slice(&payload[..payload.len().min(184)]);
    out.extend_from_slice(&p);
}

/// A transport stream: PAT, PMT (one MPEG-2 video stream on PID 0x100),
/// then one long PES packet spread over `packets` packets.
fn ts(packets: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let pat = section(0, 1, &[0, 1, 0xe0, 0x20]);
    packet(&mut out, 0, true, 0, &[[0].as_slice(), &pat].concat());
    let pmt = section(2, 1, &[0xe1, 0x00, 0xf0, 0, 0x02, 0xe1, 0x00, 0xf0, 0]);
    packet(&mut out, 0x20, true, 0, &[[0].as_slice(), &pmt].concat());
    // PES header without a length (allowed for video), then a sequence
    // header so the stream is recognised.
    let mut first = vec![0, 0, 1, 0xe0, 0, 0, 0x80, 0, 0];
    first.extend_from_slice(&[
        0, 0, 1, 0xb3, 0x02, 0x00, 0x20, 0x13, 0xff, 0xff, 0xe0, 0x18,
    ]);
    first.resize(184, 0);
    packet(&mut out, 0x100, true, 0, &first);
    for i in 1..packets {
        packet(&mut out, 0x100, false, i as u8, &[0x11; 184]);
    }
    out
}

/// Opens `path` (names from the root) and returns the node.
fn open(host: &mut Host, path: &[&str]) -> NodeId {
    let mut id = host.root;
    for name in path {
        host.session.expand_more(id, 100);
        host.run();
        id = host
            .child(id, name)
            .unwrap_or_else(|| panic!("no {name:?} under:\n{}", host.render()));
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

#[test]
fn a_long_transport_stream_is_cut_into_parts() {
    const PACKETS: usize = 40_000;
    let data = ts(PACKETS);
    let mut host = Host::named("long.ts", data, Limits::default());
    let stream = open(&mut host, &["Elementary streams", "PID 0x0100"]);
    let before = host.bytes_supplied;
    host.session.expand_more(stream, 1);
    host.run();
    let read = host.bytes_supplied - before;
    let children = host.session.children(stream).unwrap();
    assert_eq!(children.ids.len(), 1, "{}", host.render());
    assert_eq!(host.session.node(children.ids[0]).unwrap().name, "Part 1");
    assert!(
        read < (PACKETS * 188 / 3) as u64,
        "the first part read {read} bytes of {}",
        PACKETS * 188
    );
    host.explore(stream, 1, 100);
    let children = host.session.children(stream).unwrap();
    // 4096 packets per part.
    assert_eq!(children.ids.len(), PACKETS.div_ceil(4096));
    for &c in children.ids.iter() {
        let s = summary(&host, c);
        let pieces: usize = s
            .rsplit("from ")
            .next()
            .and_then(|t| t.split(' ').next())
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("{s}"));
        assert!(pieces <= 4096, "{s}");
    }
    // A part opens as the stream's format.
    let first = children.ids[0];
    host.session.expand_more(first, 10);
    host.run();
    assert!(
        host.child(first, "Sequence header").is_some(),
        "{}",
        host.render()
    );
}

/// A program stream: pack headers and `packets` video PES packets of
/// 2000 payload bytes each.
fn ps(packets: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let pack = [0, 0, 1, 0xba, 0x44, 0, 4, 0, 4, 1, 0x01, 0x89, 0xc3, 0xf8];
    for i in 0..packets {
        out.extend_from_slice(&pack);
        let mut payload = vec![0x22; 2000];
        if i == 0 {
            payload[..12].copy_from_slice(&[
                0, 0, 1, 0xb3, 0x02, 0x00, 0x20, 0x13, 0xff, 0xff, 0xe0, 0x18,
            ]);
        }
        let len = (payload.len() + 3) as u16;
        out.extend_from_slice(&[0, 0, 1, 0xe0]);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&[0x80, 0, 0]);
        out.extend_from_slice(&payload);
    }
    out.extend_from_slice(&[0, 0, 1, 0xb9]);
    out
}

#[test]
fn a_long_program_stream_is_cut_into_parts() {
    // 2000 bytes per packet: parts end at 4 MiB of payload.
    const PACKETS: usize = 6_000;
    let mut host = Host::named("long.mpg", ps(PACKETS), Limits::default());
    let stream = open(&mut host, &["Elementary streams", "Video stream 0"]);
    host.explore(stream, 1, 100);
    let children = host.session.children(stream).unwrap();
    let per_part = (4usize << 20) / 2000;
    assert_eq!(
        children.ids.len(),
        PACKETS.div_ceil(per_part),
        "{}",
        host.render()
    );
    let first = children.ids[0];
    host.session.expand_more(first, 10);
    host.run();
    assert!(
        host.child(first, "Sequence header").is_some(),
        "{}",
        host.render()
    );
}
