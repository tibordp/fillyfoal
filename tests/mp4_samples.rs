//! The per-track "Samples" view of an MP4 reads its sample tables a window
//! at a time: listing the first samples of a track with a large table
//! reads a few KiB, not the table, and a track claiming millions of
//! samples is listed in pages.

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

/// A box: size, type, body.
fn bx(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut out = ((body.len() + 8) as u32).to_be_bytes().to_vec();
    out.extend_from_slice(kind);
    out.extend_from_slice(body);
    out
}

/// A FullBox with version 0 and no flags.
fn full(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut b = vec![0; 4];
    b.extend_from_slice(body);
    bx(kind, &b)
}

fn be32(values: &[u32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_be_bytes()).collect()
}

/// An MP4 with one track of `samples` samples in one chunk at the start
/// of `mdat`; sizes listed per sample (all 1) when `table`, else fixed.
fn mp4(samples: u32, table: bool) -> Vec<u8> {
    let ftyp = bx(b"ftyp", b"isom\0\0\x02\0isommp41");
    let stsd = full(b"stsd", &be32(&[0]));
    let stsc = full(b"stsc", &be32(&[1, 1, samples, 1]));
    let stsz = if table {
        let mut b = be32(&[0, samples]);
        b.extend(std::iter::repeat_n(1u32.to_be_bytes(), samples as usize).flatten());
        full(b"stsz", &b)
    } else {
        full(b"stsz", &be32(&[1, samples]))
    };
    let mdat_body = vec![0u8; 64];
    let build = |offset: u32| {
        let stco = full(b"stco", &be32(&[1, offset]));
        let stbl = bx(
            b"stbl",
            &[stsd.clone(), stsc.clone(), stsz.clone(), stco].concat(),
        );
        let minf = bx(b"minf", &stbl);
        let hdlr = full(
            b"hdlr",
            &[be32(&[0]), b"vide".to_vec(), vec![0; 13]].concat(),
        );
        let mdia = bx(b"mdia", &[hdlr, minf].concat());
        let trak = bx(b"trak", &mdia);
        bx(b"moov", &trak)
    };
    let moov_len = build(0).len();
    let offset = (ftyp.len() + moov_len + 8) as u32;
    [ftyp, build(offset), bx(b"mdat", &mdat_body)].concat()
}

fn open_samples(host: &mut Host) -> NodeId {
    let mut id = host.root;
    for name in ["moov", "trak", "mdia", "minf", "stbl", "Samples"] {
        host.session.expand_more(id, 100);
        host.run();
        id = host
            .child(id, name)
            .unwrap_or_else(|| panic!("no {name:?} under:\n{}", host.render()));
    }
    id
}

#[test]
fn the_first_samples_of_a_large_table_read_a_window_of_it() {
    const SAMPLES: u32 = 250_000;
    let data = mp4(SAMPLES, true);
    assert!(data.len() > 1_000_000);
    let mut host = Host::named("big.mp4", data, Limits::default());
    let samples = open_samples(&mut host);
    let before = host.bytes_supplied;
    host.session.expand_more(samples, 100);
    host.run();
    let read = host.bytes_supplied - before;
    let children = host.session.children(samples).unwrap();
    assert_eq!(children.ids.len(), 100, "{}", host.render());
    assert!(read < 256 * 1024, "listing 100 samples read {read} bytes");
    let first = host.session.node(children.ids[0]).unwrap();
    assert_eq!(first.name, "Sample 1");
}

#[test]
fn millions_of_fixed_size_samples_are_listed_in_pages() {
    let mut host = Host::named("many.mp4", mp4(4_000_000, false), Limits::default());
    let samples = open_samples(&mut host);
    let polls = host.polls;
    host.session.expand_more(samples, 500);
    host.run();
    let children = host.session.children(samples).unwrap();
    assert_eq!(children.ids.len(), 500);
    assert!(host.polls - polls < 50, "{} polls", host.polls - polls);
    // Sizes run past the 64-byte mdat: later samples are truncated, not
    // read.
    let last = host.session.node(*children.ids.last().unwrap()).unwrap();
    assert_eq!(last.name, "Sample 500");
}

/// A fragment whose `trun` claims 2^32-1 samples of the `tfhd` default
/// size (1 byte, no per-sample fields) over a 64-byte `mdat`: its "Sample
/// data" lists the samples that lie in the file and stops.
#[test]
fn a_fragment_run_stops_at_the_end_of_the_file() {
    let ftyp = bx(b"ftyp", b"isom\0\0\x02\0isomiso6");
    let moov = bx(b"moov", &full(b"mvhd", &[0; 96]));
    // tfhd: default-base-is-moof + default sample size; track 1, size 1.
    let mut tfhd = vec![0, 0x02, 0, 0x10];
    tfhd.extend_from_slice(&be32(&[1, 1]));
    let tfhd = bx(b"tfhd", &tfhd);
    let build = |offset: u32| {
        // trun: data offset only.
        let mut trun = vec![0, 0, 0, 0x01];
        trun.extend_from_slice(&be32(&[u32::MAX, offset]));
        let traf = bx(b"traf", &[tfhd.clone(), bx(b"trun", &trun)].concat());
        bx(b"moof", &[full(b"mfhd", &be32(&[1])), traf].concat())
    };
    let moof_len = build(0).len();
    let moof = build((moof_len + 8) as u32);
    let data = [ftyp, moov, moof, bx(b"mdat", &[0u8; 64])].concat();
    let mut host = Host::named("frag.mp4", data, Limits::default());
    let mut id = host.root;
    for name in ["moof", "traf", "trun", "Sample data"] {
        host.session.expand_more(id, 100);
        host.run();
        id = host
            .child(id, name)
            .unwrap_or_else(|| panic!("no {name:?} under:\n{}", host.render()));
    }
    host.explore(id, 1, 1000);
    let children = host.session.children(id).unwrap();
    assert_eq!(children.ids.len(), 64, "{}", host.render());
}
