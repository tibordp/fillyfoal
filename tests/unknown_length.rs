//! Content whose length is unknown (decoded on demand from a stream that
//! records no size, see `Cx::decode_lazy_unsized`) is identified from its
//! head with only an upper bound for its length. Probes must not accept on
//! that bound (`Head::len` "fits"): a format they claim then must be the
//! one the content is, or the generic container or fallback it reads as
//! without the evidence the bound hides (a trailer, a length equation, a
//! file name). Every fixture is identified both ways; a difference not
//! listed below is a probe that overclaims.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::path::{Path, PathBuf};

use fillyfoal::formats::{HEAD_LEN, Head, REGISTRY, TAIL_LEN};

/// Fixtures identified differently when their length is unknown, all for a
/// reason the bound can't help: identified by their end (VHD footer, DMG
/// trailer, AFF4/zip, shapefile lengths, tag-only ID3, a GBX footer) or
/// their file name
/// (INI variants, trashinfo), so they read as the container or the generic
/// format they also are; `hello.byte` starts with a shebang; a TFM file,
/// recognised by its length equation, falls to CGM's weak probe.
const EXPECTED: &[&str] = &[
    "external/aff4/fat-snappy-hole.aff4",
    "external/aff4/fat-zlib.aff4",
    "external/dmg/fat-ulfo.dmg",
    "external/dmg/fat-ulmo.dmg",
    "external/dmg/hfs-udbz.dmg",
    "external/dmg/hfs-udro.dmg.raw.zst",
    "external/doc/long.doc",
    "external/id3/tag-only.id3",
    "external/ppt/powerpoint-encrypted.ppt",
    "external/shp/empty.shp",
    "external/shx/empty.shx",
    "external/shx/polygonz.shx",
    "external/vhd/ntfs-attrlist.vhd.raw.zst",
    "external/vhd/ntfs-lznt1.vhd.raw.zst",
    "external/vhd/ntfs-wof.vhd.raw.zst",
    "external/vhd/qemu-fixed.vhd.raw.zst",
    "synthetic/apple-strings/Localizable.strings",
    "synthetic/autorun-inf/autorun.inf",
    "synthetic/desktop-ini/desktop.ini",
    "synthetic/emlx/1.emlx",
    "synthetic/gamemaker/data.win",
    "synthetic/gbx/pokemon.gbx.gz",
    "synthetic/id3/v22.id3",
    "synthetic/id3/v23-compressed.id3",
    "synthetic/id3/v23-unsync.id3",
    "synthetic/id3/v24-flags.id3",
    "synthetic/id3/v24-plain-sizes.id3",
    "synthetic/ocaml-bytecode/hello.byte",
    "synthetic/shx/points.shx",
    "synthetic/tex-tfm/fixture.tfm",
    "synthetic/trashinfo/report%20final.pdf.trashinfo",
    "synthetic/vhd/fixed.vhd",
];

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_none_or(|e| e != "md") {
            out.push(path);
        }
    }
}

#[test]
fn probes_do_not_accept_on_an_unknown_length() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut files = Vec::new();
    walk(&root, &mut files);
    files.sort();
    let mut unexpected = Vec::new();
    for path in &files {
        let data = common::fixture_bytes(path);
        let head = &data[..data.len().min(HEAD_LEN as usize)];
        let tail = &data[data.len().saturating_sub(TAIL_LEN as usize)..];
        let len = data.len() as u64;
        let known = REGISTRY.identify(&Head {
            data: head,
            tail,
            len,
            len_known: true,
        });
        let bound = len.saturating_mul(1000).max(1 << 40);
        let unknown = REGISTRY.identify(&Head {
            data: head,
            tail: &[],
            len: bound,
            len_known: false,
        });
        let rel = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let differs = unknown.is_some_and(|u| known.map(|k| k.name) != Some(u.name));
        if differs && !EXPECTED.contains(&rel.as_str()) {
            unexpected.push(format!(
                "{rel}: {:?} with its length, {} without",
                known.map(|k| k.name),
                unknown.map_or("-", |u| u.name)
            ));
        }
    }
    assert!(unexpected.is_empty(), "{}", unexpected.join("\n"));
}
