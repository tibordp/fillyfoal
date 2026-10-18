//! `formats::Identify`: sans-IO identification with a text answer.

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fillyfoal::formats::{ByteRange, Identification, Identified, Identify};

/// Identifies `data` under `name`, returning the answer and every range
/// asked for.
fn run(data: &[u8], name: &str) -> (Identification, Vec<ByteRange>) {
    let mut id = Identify::new(data.len() as u64, Some(name));
    let mut asked = Vec::new();
    loop {
        match id.poll() {
            Identified::NeedBytes(ranges) => {
                for r in ranges {
                    asked.push(r);
                    let from = (r.offset as usize).min(data.len());
                    let to = (from + r.len as usize).min(data.len());
                    id.provide(r.offset, &data[from..to]);
                }
            }
            Identified::Done(found) => return (found, asked),
        }
    }
}

#[test]
fn text_is_reported_whatever_the_format() {
    let (json, _) = run(br#"{"name": "fillyfoal", "formats": 1640}"#, "a.json");
    assert_eq!(json.format.map(|f| f.name), Some("json"));
    assert!(json.text);

    let (plain, _) = run(b"just some words\nand another line\n", "notes.txt");
    assert_eq!(plain.format.map(|f| f.name), Some("text"));
    assert!(plain.text);

    let png = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/external/png/gray-alpha16.png"
    ))
    .unwrap();
    let (image, _) = run(&png, "picture.png");
    assert_eq!(image.format.map(|f| f.name), Some("png"));
    assert!(!image.text);

    // Text in a file named like an image is still text.
    let (fake, _) = run(b"hello\n", "fake.png");
    assert!(fake.text);
}

#[test]
fn only_the_head_and_tail_are_read_for_a_large_file() {
    let mut data = vec![b'a'; 4 << 20];
    data.push(b'\n');
    let (found, asked) = run(&data, "big.txt");
    assert!(found.text);
    let total: u64 = asked.iter().map(|r| r.len).sum();
    assert!(total < 256 * 1024, "read {total} bytes: {asked:?}");
}

#[test]
fn empty_input_needs_no_bytes() {
    let (found, asked) = run(b"", "empty");
    assert!(asked.is_empty());
    assert!(found.format.is_none());
    assert!(!found.text);
}

#[test]
fn names_break_ties_for_short_text() {
    let name_of = |data: &[u8], name: &str| run(data, name).0.format.map(|f| f.name);
    // Too short to tell from the content alone...
    let md = b"Notes\n\nSome text, nothing more.\n";
    assert_eq!(name_of(md, "notes.txt"), Some("text"));
    // ...but a Markdown name settles it: any text is valid Markdown.
    assert_eq!(name_of(md, "notes.md"), Some("markdown"));
    // A two-line table with the right name is a table.
    assert_eq!(name_of(b"name,age\nbob,3\n", "people.csv"), Some("csv"));
    assert_eq!(name_of(b"name\tage\nbob\t3\n", "people.tsv"), Some("tsv"));
    // Prose named .csv stays text: the records don't agree.
    assert_eq!(
        name_of(
            b"Hello, world.\nThis is just prose, really, with commas.\n",
            "prose.csv"
        ),
        Some("text")
    );
    // The name never claims binary content.
    assert_ne!(
        name_of(&[0u8, 159, 146, 150, 1, 2, 3], "x.md"),
        Some("markdown")
    );
}

#[test]
fn ranges_may_be_supplied_in_any_order() {
    // Large, binary and unrecognised: the first phase finds nothing, so
    // the second phase runs and wants the deep tail too.
    let data: Vec<u8> = (0..300_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
        .collect();
    let name = "blob.bin";
    let (in_order, asked) = run(&data, name);
    assert!(asked.len() >= 3, "{asked:?}");

    let mut id = Identify::new(data.len() as u64, Some(name));
    let reversed = loop {
        match id.poll() {
            Identified::NeedBytes(ranges) => {
                // Bytes nobody asked for are ignored...
                id.provide(12_345, b"junk");
                // ...and the ranges asked for may come in any order.
                for r in ranges.into_iter().rev() {
                    let from = r.offset as usize;
                    let to = (from + r.len as usize).min(data.len());
                    id.provide(r.offset, &data[from..to]);
                }
            }
            Identified::Done(found) => break found,
        }
    };
    assert_eq!(
        reversed.format.map(|f| f.name),
        in_order.format.map(|f| f.name)
    );
    assert_eq!(reversed.text, in_order.text);
}
