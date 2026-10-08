//! Formats whose structures used to be parsed synchronously in one step (a
//! Delphi form, a Guitar Pro measure, a PDF string) now parse in budgeted
//! steps: a large input makes the expansion yield again and again instead
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
use fillyfoal::{Limits, NodeId, Progress};

/// Polls `id` with small budgets until it settles, answering byte
/// requests; returns how many polls yielded. Every poll must return
/// quickly.
fn poll_stepped(host: &mut Host, id: NodeId) -> u32 {
    let mut yields = 0;
    for _ in 0..1_000_000 {
        let start = Instant::now();
        match host.session.poll_node(id, 2_000) {
            Progress::Idle => return yields,
            Progress::Yielded => yields += 1,
            Progress::NeedSecret(_) => panic!("unexpected secret request"),
            Progress::NeedBytes(requests) => {
                for r in requests {
                    let start = r.offset as usize;
                    let end = (start + r.len as usize).min(host.data.len());
                    let bytes = host.data[start..end].to_vec();
                    host.session.supply(r.source, r.offset, &bytes);
                }
            }
        }
        // 2000 units are about a millisecond; allow for a slow machine.
        assert!(start.elapsed() < Duration::from_millis(500));
    }
    panic!("did not settle");
}

/// Expands `id` (a page of `page` children) and polls it to the end.
fn open(host: &mut Host, id: NodeId, page: u64) -> u32 {
    host.session.expand(id, page);
    poll_stepped(host, id)
}

fn short(s: &str) -> Vec<u8> {
    let mut out = vec![s.len() as u8];
    out.extend_from_slice(s.as_bytes());
    out
}

#[test]
fn delphi_form_with_a_huge_list_parses_in_steps() {
    let n = 2_000_000;
    let mut data = b"TPF0".to_vec();
    data.extend(short("TForm1"));
    data.extend(short("Form1"));
    data.extend(short("Items"));
    data.push(1); // vaList
    for i in 0..n {
        data.extend([2, (i % 100) as u8]); // vaInt8
    }
    data.push(0); // end of list
    data.push(0); // end of properties
    data.push(0); // end of children
    let mut host = Host::named("big.dfm", data, Limits::default());
    let root = host.root;
    let yields = open(&mut host, root, 10);
    assert!(yields >= 2, "{yields} yields");
    let form = host.child(root, "Form1: TForm1").expect("component");
    assert!(host.render().contains("1 properties, 0 children"));
    open(&mut host, form, 10);
    let items = host.child(form, "Items").expect("property");
    open(&mut host, items, 10);
    let rendered = host.render();
    assert!(rendered.contains("[9]: 9"), "{rendered}");
}

#[test]
fn guitar_pro_measure_with_a_million_beats_parses_in_steps() {
    let fixture = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/external/guitar-pro/pyguitarpro.gp5"
    ))
    .unwrap();
    // Measure 1, track 1, voice 2 has no beats (its count is at 0x83d):
    // give it a million empty quarter beats (flags, duration, strings,
    // display flags).
    let n: u32 = 1_000_000;
    assert_eq!(&fixture[0x83d..0x841], &[0, 0, 0, 0]);
    let mut data = fixture[..0x83d].to_vec();
    data.extend(n.to_le_bytes());
    data.extend(std::iter::repeat_n([0u8; 5], n as usize).flatten());
    data.extend_from_slice(&fixture[0x841..]);
    let mut host = Host::named("big.gp5", data, Limits::default());
    let root = host.root;
    open(&mut host, root, 100);
    let measures = host.child(root, "Measures").expect("measures");
    let yields = open(&mut host, measures, 1);
    assert!(yields >= 4, "{yields} yields");
    let rendered = host.render();
    assert!(rendered.contains("1000013 beats, 19 notes"), "{rendered}");
    let measure = host.child(measures, "Measure 1").expect("measure");
    assert!(open(&mut host, measure, 10) >= 4);
    let track = host.child(measure, "Track 1").expect("track");
    assert!(open(&mut host, track, 10) >= 4);
    let voice = host.child(track, "Voice 2").expect("voice");
    open(&mut host, voice, 10);
    let rendered = host.render();
    assert!(
        rendered.contains("Voice 2 — 1000000 beats, 0 notes"),
        "{rendered}"
    );
    assert!(rendered.contains("Beat 9 — quarter"), "{rendered}");
}

#[test]
fn pdf_shows_a_prefix_of_a_huge_string() {
    let text = "a".repeat(1 << 20);
    let mut out = b"%PDF-1.7\n".to_vec();
    let catalog = out.len();
    out.extend_from_slice(
        format!("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /X ({text}) >>\nendobj\n").as_bytes(),
    );
    let pages = out.len();
    out.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n");
    let xref = out.len();
    out.extend_from_slice(b"xref\n0 3\n0000000000 65535 f \n");
    for at in [catalog, pages] {
        out.extend_from_slice(format!("{at:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes(),
    );
    let mut host = Host::named("big.pdf", out, Limits::default());
    host.explore_all();
    let rendered = host.render();
    assert!(
        rendered.contains("1048576 bytes, the first 65536 shown"),
        "{}",
        &rendered[..rendered.len().min(4000)]
    );
}
