//! Synchronous parsers of input-sized structures (BUFR data, OpenFOAM
//! dictionaries, Gerber and S-expression files, OASIS records, FCS TEXT,
//! vector-tile layers, safetensors headers) run in bounded steps: a large
//! input makes the expansion yield again and again, and record walkers
//! report how far they have got.

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
use fillyfoal::{Limits, NodeId, Progress, formats};

/// Polls `id` with budgets of `budget` until it settles, answering byte
/// requests; returns how many polls yielded. Every poll must return
/// quickly.
fn poll_steps(host: &mut Host, id: NodeId, budget: u64) -> u32 {
    let mut yields = 0;
    for _ in 0..1_000_000 {
        let start = Instant::now();
        match host.session.poll_node(id, budget) {
            Progress::Idle => return yields,
            Progress::Yielded => yields += 1,
            Progress::NeedSecret(_) => panic!("no secrets here"),
            Progress::NeedBytes(requests) => {
                for r in requests {
                    let start = r.offset as usize;
                    let end = (start + r.len as usize).min(host.data.len());
                    let bytes = host.data[start..end].to_vec();
                    host.session.supply(r.source, r.offset, &bytes);
                }
            }
        }
        assert!(start.elapsed() < Duration::from_millis(500));
    }
    panic!("did not settle");
}

/// Opens `data` as `format` and expands its root in small steps; returns
/// the host and how many polls yielded.
fn expand_as(name: &str, format: &str, data: Vec<u8>, budget: u64) -> (Host, u32) {
    let format = formats::by_name(format).unwrap();
    let mut host = Host::open(name, data, Limits::default(), Some(format));
    let root = host.root;
    host.session.expand(root, 100);
    let yields = poll_steps(&mut host, root, budget);
    (host, yields)
}

fn child_starting(host: &Host, id: NodeId, prefix: &str) -> NodeId {
    let children = host.session.children(id).unwrap();
    children
        .ids
        .iter()
        .copied()
        .find(|&c| host.session.node(c).unwrap().name.starts_with(prefix))
        .unwrap_or_else(|| panic!("no child {prefix}"))
}

#[test]
fn bufr_decodes_a_long_replication_in_steps() {
    // Edition 4, one uncompressed subset: delayed replication (extended
    // factor) of air temperature, 60000 times.
    let n = 60_000u32;
    let mut sec1 = vec![0u8; 22];
    sec1[..3].copy_from_slice(&[0, 0, 22]);
    sec1[15..17].copy_from_slice(&2024u16.to_be_bytes());
    sec1[17] = 1;
    sec1[18] = 1;
    let descs = [0x4100u16, 0x1f02, 0x0c65];
    let mut sec3 = vec![0, 0, 0, 0, 0, 1, 0x80];
    for d in descs {
        sec3.extend_from_slice(&d.to_be_bytes());
    }
    sec3.push(0);
    let l3 = sec3.len() as u32;
    sec3[..3].copy_from_slice(&l3.to_be_bytes()[1..]);
    let mut data = (n as u16).to_be_bytes().to_vec();
    for _ in 0..n {
        data.extend_from_slice(&29_315u16.to_be_bytes());
    }
    let mut sec4 = vec![0, 0, 0, 0];
    sec4.extend_from_slice(&data);
    let l4 = sec4.len() as u32;
    sec4[..3].copy_from_slice(&l4.to_be_bytes()[1..]);
    let total = 8 + sec1.len() + sec3.len() + sec4.len() + 4;
    let mut msg = b"BUFR".to_vec();
    msg.extend_from_slice(&(total as u32).to_be_bytes()[1..]);
    msg.push(4);
    msg.extend_from_slice(&sec1);
    msg.extend_from_slice(&sec3);
    msg.extend_from_slice(&sec4);
    msg.extend_from_slice(b"7777");

    let (mut host, _) = expand_as("big.bufr", "bufr", msg, 2_000);
    let message = child_starting(&host, host.root, "Message 1");
    host.session.expand(message, 100);
    poll_steps(&mut host, message, 2_000);
    let section = child_starting(&host, message, "Section 4");
    host.session.expand(section, 100);
    let yields = poll_steps(&mut host, section, 100);
    assert!(yields >= 5, "{yields} yields");
    let rendered = host.render();
    assert!(rendered.contains("1 subset(s)"), "{rendered}");
}

#[test]
fn openfoam_splits_a_large_dictionary_in_steps() {
    let mut data = b"/* p */\nFoamFile\n{\n    version 2.0;\n    format ascii;\n    class volScalarField;\n    object p;\n}\n// a comment\ninternalField nonuniform List<scalar> 1000000 (".to_vec();
    for _ in 0..1_000_000 {
        data.extend_from_slice(b"0 ");
    }
    data.extend_from_slice(b");\nboundaryField\n{\n    wall { type zeroGradient; }\n}\n");
    let (host, yields) = expand_as("p", "openfoam", data, 100);
    assert!(yields >= 5, "{yields} yields");
    let rendered = host.render();
    assert!(rendered.contains("internalField"), "{rendered}");
    assert!(rendered.contains("volScalarField"), "{rendered}");
}

#[test]
fn gerber_splits_a_large_file_in_steps() {
    let mut data = b"%FSLAX26Y26*%\n%MOMM*%\n%ADD10C,0.1*%\nD10*\n".to_vec();
    // One long extended block, then many words.
    data.push(b'%');
    data.extend(std::iter::repeat_n(b'A', 2 << 20));
    data.extend_from_slice(b"*%\n");
    for _ in 0..50 {
        data.extend_from_slice(b"X0Y0D02*\n");
    }
    data.extend_from_slice(b"M02*\n");
    let (host, yields) = expand_as("big.gbr", "gerber", data, 100);
    assert!(yields >= 5, "{yields} yields");
    assert!(host.render().contains("1 aperture(s)"));
}

#[test]
fn sexpr_splits_a_large_list_in_steps() {
    // One list with many elements (each nested list costs a push; a long
    // flat one does not).
    let mut data = b"(kicad_pcb (version 20211014) (generator pcbnew)\n  (nets".to_vec();
    for i in 0..200_000 {
        data.extend_from_slice(format!(" n{i} \"x\"").as_bytes());
    }
    data.extend_from_slice(b"))\n");
    let (mut host, yields) = expand_as("big.kicad_pcb", "kicad-pcb", data, 100);
    assert!(yields >= 5, "{yields} yields");
    assert!(host.render().contains("1 nets"), "{}", host.render());
    let list = child_starting(&host, host.root, "(kicad_pcb");
    host.session.expand(list, 10);
    let yields = poll_steps(&mut host, list, 100);
    assert!(yields >= 5, "{yields} yields");
}

#[test]
fn oasis_parses_a_long_point_list_in_steps() {
    let mut data = b"%SEMI-OASIS\r\n".to_vec();
    // START: version "1.0", unit 1000, offsets in the END record.
    data.extend_from_slice(&[1, 3, b'1', b'.', b'0', 0, 0xe8, 0x07, 1]);
    // POLYGON with a point list of 2M one-byte deltas.
    let n = 2u32 << 20;
    data.extend_from_slice(&[21, 0x20, 0]);
    let mut v = n;
    while v >= 0x80 {
        data.push((v & 0x7f) as u8 | 0x80);
        v >>= 7;
    }
    data.push(v as u8);
    data.extend(std::iter::repeat_n(0u8, n as usize));
    let (host, yields) = expand_as("big.oas", "oasis", data, 100);
    assert!(yields >= 5, "{yields} yields");
    assert!(
        host.render().contains("2097152 point(s)"),
        "{}",
        host.render()
    );
}

#[test]
fn fcs_splits_a_large_text_segment_in_steps() {
    let mut text = b"/$PAR/0/$TOT/0/".to_vec();
    for i in 0..90_000 {
        text.extend_from_slice(format!("K{i}/V{i}//x/").as_bytes());
    }
    let mut data = b"FCS3.0    ".to_vec();
    let begin = 58u64;
    let end = begin + text.len() as u64 - 1;
    for v in [begin, end, 0, 0, 0, 0] {
        data.extend_from_slice(format!("{v:>8}").as_bytes());
    }
    data.extend_from_slice(&text);
    let (host, yields) = expand_as("big.fcs", "fcs", data, 100);
    assert!(yields >= 5, "{yields} yields");
    assert!(
        host.render().contains("90002 keyword(s)"),
        "{}",
        host.render()
    );
}

/// A protobuf length-delimited field.
fn pb_len(out: &mut Vec<u8>, number: u64, payload: &[u8]) {
    let mut key = (number << 3) | 2;
    let mut len = payload.len() as u64;
    for v in [&mut key, &mut len] {
        while *v >= 0x80 {
            out.push((*v & 0x7f) as u8 | 0x80);
            *v >>= 7;
        }
        out.push(*v as u8);
    }
    out.extend_from_slice(payload);
}

#[test]
fn vector_tile_layer_parses_in_steps() {
    let mut layer = vec![0x78, 2];
    pb_len(&mut layer, 1, b"big");
    for _ in 0..300_000 {
        pb_len(&mut layer, 3, b"k");
    }
    layer.extend_from_slice(&[0x28, 0x80, 0x20]);
    let mut tile = Vec::new();
    pb_len(&mut tile, 3, &layer);
    let (mut host, yields) = expand_as("big.mvt", "mvt", tile, 100);
    assert!(yields >= 5, "{yields} yields");
    let layer = child_starting(&host, host.root, "Layer big");
    host.session.expand(layer, 10);
    let yields = poll_steps(&mut host, layer, 100);
    assert!(yields >= 5, "{yields} yields");
}

#[test]
fn safetensors_header_parses_in_steps() {
    let mut json = String::from("{\"__metadata__\":{\"format\":\"pt\"}");
    for i in 0..50_000 {
        json.push_str(&format!(
            ",\"t{i}\":{{\"dtype\":\"F32\",\"shape\":[1],\"data_offsets\":[{},{}]}}",
            i * 4,
            i * 4 + 4
        ));
    }
    json.push('}');
    let mut data = (json.len() as u64).to_le_bytes().to_vec();
    data.extend_from_slice(json.as_bytes());
    data.extend(std::iter::repeat_n(0u8, 50_000 * 4));
    let (host, yields) = expand_as("big.safetensors", "safetensors", data, 100);
    assert!(yields >= 5, "{yields} yields");
    assert!(host.render().contains("50000 tensors"), "{}", host.render());
}

/// Polls `id` a few times with a small budget, then checks the progress
/// it reports.
fn assert_reports_progress(host: &mut Host, id: NodeId) {
    for _ in 0..40 {
        let Progress::NeedBytes(requests) = host.session.poll_node(id, 50) else {
            continue;
        };
        for r in requests {
            let start = r.offset as usize;
            let end = (start + r.len as usize).min(host.data.len());
            let bytes = host.data[start..end].to_vec();
            host.session.supply(r.source, r.offset, &bytes);
        }
    }
    let (done, total) = host.session.progress(id).expect("progress");
    assert!(done > 0 && done < total, "{done} of {total}");
}

#[test]
fn step_reports_progress() {
    let mut data = b"ISO-10303-21;\nHEADER;\nFILE_DESCRIPTION(('x'),'2;1');\nFILE_NAME('a.stp','',(''),(''),'','','');\nFILE_SCHEMA(('AP214'));\nENDSEC;\nDATA;\n".to_vec();
    for i in 1..=100_000 {
        data.extend_from_slice(format!("#{i}=CARTESIAN_POINT('',(0.,0.,0.));\n").as_bytes());
    }
    data.extend_from_slice(b"ENDSEC;\nEND-ISO-10303-21;\n");
    let format = formats::by_name("step").unwrap();
    let mut host = Host::open("big.stp", data, Limits::default(), Some(format));
    let root = host.root;
    host.session.expand(root, 100);
    assert_reports_progress(&mut host, root);
}

#[test]
fn gdsii_reports_progress() {
    fn record(out: &mut Vec<u8>, kind: u8, datatype: u8, payload: &[u8]) {
        out.extend_from_slice(&((payload.len() + 4) as u16).to_be_bytes());
        out.extend_from_slice(&[kind, datatype]);
        out.extend_from_slice(payload);
    }
    let mut data = Vec::new();
    record(&mut data, 0x00, 0x02, &600u16.to_be_bytes());
    record(&mut data, 0x01, 0x02, &[0; 24]);
    record(&mut data, 0x02, 0x06, b"LIB\0");
    record(&mut data, 0x03, 0x05, &[0; 16]);
    record(&mut data, 0x05, 0x02, &[0; 24]);
    record(&mut data, 0x06, 0x06, b"TOP\0");
    for _ in 0..100_000 {
        record(&mut data, 0x08, 0x00, &[]);
        record(&mut data, 0x0d, 0x02, &1u16.to_be_bytes());
        record(&mut data, 0x11, 0x00, &[]);
    }
    record(&mut data, 0x07, 0x00, &[]);
    record(&mut data, 0x04, 0x00, &[]);
    let format = formats::by_name("gdsii").unwrap();
    let mut host = Host::open("big.gds", data, Limits::default(), Some(format));
    let root = host.root;
    host.session.expand(root, 100);
    assert_reports_progress(&mut host, root);
}
