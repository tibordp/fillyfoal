//! Resume marks in the text walkers (CSV, JSON Lines, JSON, XML, YAML,
//! mbox, SubRip, WebVTT): seeking back into a large collection restarts from a mark near
//! the window instead of re-walking from the start, and produces exactly
//! the children a fresh walk produces.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{Limits, NodeId};

const N: u64 = 20_000;
const FAR: u64 = 18_000;
const BACK: u64 = 9_000;

fn host(name: &str, data: &[u8]) -> Host {
    let mut host = Host::named(
        name,
        data.to_vec(),
        Limits {
            chunk_size: 65_536,
            ..Limits::default()
        },
    );
    host.max_polls = 10_000_000;
    host
}

/// The collection: the root, or the descendant reached by `path`.
fn collection(host: &mut Host, path: &[&str]) -> NodeId {
    let mut id = host.root;
    host.session.expand(id, 10);
    host.run();
    for name in path {
        id = host
            .child(id, name)
            .unwrap_or_else(|| panic!("no child {name}"));
        host.session.expand(id, 10);
        host.run();
    }
    id
}

/// The window of `id`: its first index and each child's name, summary,
/// value, span and diagnostics.
fn window(host: &Host, id: NodeId) -> (u64, Vec<String>) {
    let c = host.session.children(id).unwrap();
    let nodes = c
        .ids
        .iter()
        .map(|&i| {
            let n = host.session.node(i).unwrap();
            format!(
                "{} | {:?} | {:?} | {:?} | {:?}",
                n.name, n.summary, n.value, n.span, n.diagnostics
            )
        })
        .collect();
    (c.first, nodes)
}

/// Seeks far into the collection, then back: the back seek must use a mark
/// (a fraction of the work of walking there) and give the same children as
/// a fresh walk to the same window.
fn seeks_back_from_a_mark(name: &str, data: &[u8], path: &[&str], first: &str) {
    let mut h = host(name, data);
    let id = collection(&mut h, path);
    let before = h.session.work_done();
    h.session.seek(id, FAR, 5);
    h.run();
    let forward = h.session.work_done() - before;
    assert_eq!(window(&h, id).0, FAR, "{name}");

    let before = h.session.work_done();
    h.session.seek(id, BACK, 5);
    h.run();
    let back = h.session.work_done() - before;
    let (start, resumed) = window(&h, id);
    assert_eq!(start, BACK, "{name}");
    assert!(
        resumed[0].starts_with(first),
        "{name}: {} is not {first}",
        resumed[0]
    );
    // Without marks the restart walks BACK children: half of `forward`,
    // plus identifying the window's children, which both seeks pay (about
    // a tenth of `forward` for the YAML input).
    assert!(
        back * 4 < forward,
        "{name}: seeking back took {back} work units, walking forward {forward}"
    );

    let mut fresh = host(name, data);
    let id = collection(&mut fresh, path);
    fresh.session.seek(id, BACK, 5);
    fresh.run();
    assert_eq!(window(&fresh, id), (start, resumed), "{name}");

    // Paging on from the resumed window continues in order.
    h.session.seek(id, BACK + 3, 5);
    h.run();
    fresh.session.seek(id, BACK + 3, 5);
    fresh.run();
    assert_eq!(window(&h, id), window(&fresh, id), "{name}");
}

#[test]
fn csv_resumes_after_its_header_and_bom() {
    let mut data = b"\xef\xbb\xbfid,name,score\n".to_vec();
    for i in 0..N {
        data.extend_from_slice(format!("{i},\"row {i}\",{}\n", i % 97).as_bytes());
        if i % 1000 == 0 {
            data.push(b'\n'); // blank lines are skipped
        }
    }
    // BOM, Delimiter and Header come before the records.
    seeks_back_from_a_mark("big.csv", &data, &[], &format!("Record {}", BACK - 2));
}

#[test]
fn ndjson_resumes() {
    let mut data = Vec::new();
    for i in 0..N {
        data.extend_from_slice(format!("{{\"id\":{i},\"tags\":[\"a\",\"b\"]}}\n").as_bytes());
        if i % 1000 == 0 {
            data.push(b'\n');
        }
    }
    seeks_back_from_a_mark("big.jsonl", &data, &[], "Line ");
}

#[test]
fn json_resumes_at_top_level_and_nested() {
    let items: Vec<String> = (0..N)
        .map(|i| format!("{{\"id\": {i}, \"name\": \"item {i}\"}}"))
        .collect();
    let array = format!("[\n{}\n]\n", items.join(",\n"));
    seeks_back_from_a_mark("big.json", array.as_bytes(), &[], &format!("[{BACK}]"));
    let object = format!("{{\"meta\": 1, \"items\": {array}}}");
    seeks_back_from_a_mark(
        "nested.json",
        object.as_bytes(),
        &["items"],
        &format!("[{BACK}]"),
    );
}

#[test]
fn xml_resumes_after_the_attributes() {
    let mut data = String::from("<?xml version=\"1.0\"?>\n<items a=\"1\" b=\"2\">\n");
    for i in 0..N {
        data.push_str(&format!("  <item id=\"{i}\">value {i}</item>\n"));
        if i % 1000 == 0 {
            data.push_str("  <!-- a comment -->\n");
        }
    }
    data.push_str("</items>\n");
    seeks_back_from_a_mark("big.xml", data.as_bytes(), &["items"], "item ");
}

#[test]
fn yaml_resumes_in_blocks_and_documents() {
    let mut data = String::from("%YAML 1.2\n---\n");
    for i in 0..N {
        data.push_str(&format!("- id: {i}\n  name: item {i}\n"));
        if i % 1000 == 0 {
            data.push_str("# a comment\n");
        }
    }
    // The directive comes before the entries.
    seeks_back_from_a_mark("big.yaml", data.as_bytes(), &[], &format!("[{}]", BACK - 1));
    let nested = format!(
        "items:\n{}",
        data.replace("%YAML 1.2\n---\n", "")
            .replace("- ", "  - ")
            .replace("\n  name", "\n    name")
    );
    seeks_back_from_a_mark(
        "nested.yaml",
        nested.as_bytes(),
        &["items"],
        &format!("[{BACK}]"),
    );
    let mut docs = String::new();
    for i in 0..N {
        docs.push_str(&format!("---\nid: {i}\n"));
    }
    seeks_back_from_a_mark(
        "docs.yaml",
        docs.as_bytes(),
        &[],
        &format!("Document {}", BACK + 1), // the first document's entry comes first
    );
}

#[test]
fn mbox_resumes() {
    let mut data = String::new();
    for i in 0..N {
        data.push_str(&format!(
            "From sender@example.com Mon Jan  1 00:00:00 2024\nFrom: sender@example.com\nSubject: message {i}\n\nBody {i}.\n\n"
        ));
    }
    seeks_back_from_a_mark(
        "big.mbox",
        data.as_bytes(),
        &[],
        &format!("Message {}", BACK + 1),
    );
}

fn clock(ms: u64, sep: char) -> String {
    format!(
        "{:02}:{:02}:{:02}{sep}{:03}",
        ms / 3_600_000,
        ms / 60_000 % 60,
        ms / 1000 % 60,
        ms % 1000
    )
}

#[test]
fn subtitles_resume() {
    let mut srt = String::new();
    for i in 0..N {
        let (a, b) = (i * 2000, i * 2000 + 1500);
        srt.push_str(&format!(
            "{}\n{} --> {}\nLine {i}\n\n",
            i + 1,
            clock(a, ','),
            clock(b, ',')
        ));
    }
    seeks_back_from_a_mark("big.srt", srt.as_bytes(), &[], &format!("Cue {}", BACK + 1));
    let mut vtt = String::from("WEBVTT\nKind: captions\n\n");
    for i in 0..N {
        let (a, b) = (i * 2000, i * 2000 + 1500);
        vtt.push_str(&format!(
            "{} --> {}\nLine {i}\n\n",
            clock(a, '.'),
            clock(b, '.')
        ));
    }
    // The header and its setting come before the cues.
    seeks_back_from_a_mark("big.vtt", vtt.as_bytes(), &[], &format!("Cue {}", BACK - 1));
}

#[test]
fn markdown_resumes_in_sections() {
    // Top level: front matter, then paragraphs, fenced code (with lines
    // that would be headings outside the fence), lists and quotes.
    let mut doc = String::from("---\ntitle: big\n---\n");
    for i in 0..N {
        match i % 4 {
            0 => doc.push_str(&format!("Paragraph {i}\ncontinues here.\n\n")),
            1 => doc.push_str(&format!("```\n# not a heading {i}\n```\n\n")),
            2 => doc.push_str(&format!("- item {i}\n- item {i}b\n\n")),
            _ => doc.push_str(&format!("> quote {i}\n\n")),
        }
    }
    // The front matter comes before the blocks: child BACK is block
    // BACK - 1, a quote.
    seeks_back_from_a_mark("big.md", doc.as_bytes(), &[], "Quote");
    // A section of subsections: each mark carries the open subsection.
    let mut outline = String::from("# Doc\n\nIntro.\n\n");
    for i in 0..N {
        outline.push_str(&format!("## Part {i}\n\nText {i}.\n\n"));
        if i % 1000 == 0 {
            outline.push_str(&format!("Setext {i}\n---\n\nMore.\n\n"));
        }
    }
    seeks_back_from_a_mark("outline.md", outline.as_bytes(), &["Doc"], "Part ");
}
