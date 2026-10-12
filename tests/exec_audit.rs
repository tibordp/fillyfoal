//! Executable and object formats keep their work and memory bounded on
//! crafted inputs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use common::Host;
use fillyfoal::{ChildState, Limits};

/// An OMF object: THEADR, `n` COMENT records, MODEND.
fn omf_comments(n: usize) -> Vec<u8> {
    fn record(out: &mut Vec<u8>, kind: u8, body: &[u8]) {
        let start = out.len();
        out.push(kind);
        out.extend_from_slice(&((body.len() + 1) as u16).to_le_bytes());
        out.extend_from_slice(body);
        let sum = out[start..].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        out.push(sum.wrapping_neg());
    }
    let mut out = Vec::new();
    record(&mut out, 0x80, b"\x05t.asm");
    for _ in 0..n {
        record(&mut out, 0x88, b"\x00\x00hi");
    }
    record(&mut out, 0x8a, b"\x00");
    out
}

#[test]
fn omf_pushes_records_as_it_walks() {
    let data = omf_comments(200_000);
    let len = data.len() as u64;
    let mut host = Host::named("t.obj", data, Limits::default());
    host.session.expand(host.root, 100);
    host.run();
    let children = host.session.children(host.root).unwrap();
    assert_eq!(children.ids.len(), 100);
    assert_eq!(children.state, ChildState::More);
    // The first page needs the first records, not the whole 1.6 MB file.
    assert!(
        host.bytes_supplied < len / 4,
        "{} of {len}",
        host.bytes_supplied
    );

    // The whole walk ends with the record count in the summary.
    host.explore(host.root, 1, 100_000);
    let summary = host.session.node(host.root).unwrap().summary.clone();
    assert_eq!(
        summary.as_deref(),
        Some("OMF object module t.asm, 200002 records")
    );
}

/// A 64-bit little-endian ELF executable with no segments and the given
/// PROGBITS sections (name, bytes), plus `.shstrtab`.
fn elf_with_sections(sections: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut shstrtab = vec![0u8];
    let mut names = Vec::new();
    for (name, _) in sections {
        names.push(shstrtab.len() as u32);
        shstrtab.extend_from_slice(name.as_bytes());
        shstrtab.push(0);
    }
    let shstrtab_name = shstrtab.len() as u32;
    shstrtab.extend_from_slice(b".shstrtab\0");
    let mut out = vec![0u8; 64];
    let mut headers = vec![0u8; 64]; // the null section
    let mut add = |out: &mut Vec<u8>, name: u32, kind: u32, data: &[u8]| {
        let offset = out.len() as u64;
        out.extend_from_slice(data);
        headers.extend_from_slice(&name.to_le_bytes());
        headers.extend_from_slice(&kind.to_le_bytes());
        headers.extend_from_slice(&0u64.to_le_bytes()); // flags
        headers.extend_from_slice(&0u64.to_le_bytes()); // addr
        headers.extend_from_slice(&offset.to_le_bytes());
        headers.extend_from_slice(&(data.len() as u64).to_le_bytes());
        headers.extend_from_slice(&0u32.to_le_bytes()); // link
        headers.extend_from_slice(&0u32.to_le_bytes()); // info
        headers.extend_from_slice(&1u64.to_le_bytes()); // align
        headers.extend_from_slice(&0u64.to_le_bytes()); // entsize
    };
    for ((_, data), &name) in sections.iter().zip(&names) {
        add(&mut out, name, 1, data);
    }
    add(&mut out, shstrtab_name, 3, &shstrtab);
    let shoff = out.len() as u64;
    let shnum = (sections.len() + 2) as u16;
    out.extend_from_slice(&headers);
    out[..4].copy_from_slice(b"\x7fELF");
    out[4] = 2; // 64-bit
    out[5] = 1; // little-endian
    out[6] = 1;
    out[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    out[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86-64
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[40..48].copy_from_slice(&shoff.to_le_bytes());
    out[52..54].copy_from_slice(&64u16.to_le_bytes());
    out[58..60].copy_from_slice(&64u16.to_le_bytes());
    out[60..62].copy_from_slice(&shnum.to_le_bytes());
    out[62..64].copy_from_slice(&(shnum - 1).to_le_bytes());
    out
}

/// DWARF 4: a compile unit holding `n` base types, without `DW_AT_sibling`.
fn dwarf_many_dies(n: usize) -> Vec<u8> {
    // [1] compile_unit, children, name:string; [2] base_type, no
    // children, name:string, byte_size:data1.
    let abbrev = vec![
        1, 0x11, 1, 0x03, 0x08, 0, 0, 2, 0x24, 0, 0x03, 0x08, 0x0b, 0x0b, 0, 0, 0,
    ];
    let mut dies = vec![1];
    dies.extend_from_slice(b"cu\0");
    for _ in 0..n {
        dies.extend_from_slice(&[2, b't', 0, 4]);
    }
    dies.push(0);
    let mut info = Vec::new();
    info.extend_from_slice(&((dies.len() + 7) as u32).to_le_bytes());
    info.extend_from_slice(&4u16.to_le_bytes());
    info.extend_from_slice(&0u32.to_le_bytes());
    info.push(8);
    info.extend_from_slice(&dies);
    elf_with_sections(&[(".debug_abbrev", abbrev), (".debug_info", info)])
}

#[test]
fn dwarf_dies_are_paged() {
    let n = 200_000;
    let data = dwarf_many_dies(n);
    let len = data.len() as u64;
    let mut host = Host::named("dies", data, Limits::default());
    host.explore(host.root, 1, 100);
    let sections = host.child(host.root, "Section Headers").unwrap();
    host.explore(sections, 1, 100);
    let info = host.child(sections, ".debug_info").unwrap();
    host.explore(info, 1, 100);
    let decoded = host.child(info, "Debug Information").unwrap();
    host.explore(decoded, 1, 100);
    let unit = host.child(decoded, "Compile unit at 0x0").unwrap();
    host.explore(unit, 1, 100);
    let cu = host.child(unit, "DW_TAG_compile_unit").unwrap();
    let (bytes, work) = (host.bytes_supplied, host.session.work_done());
    host.session.expand(cu, 100);
    host.run();
    let children = host.session.children(cu).unwrap();
    assert_eq!(children.ids.len(), 100);
    assert_eq!(children.state, ChildState::More);
    // The first page reads and decodes the first DIEs, not the whole unit.
    let read = host.bytes_supplied - bytes;
    assert!(read < len / 16, "read {read} of {len}");
    let work = host.session.work_done() - work;
    assert!(work < 20_000, "work {work}");

    // Paging on reaches every DIE: the name attribute, the children and
    // the NULL that ends them.
    host.explore(cu, 1, 10_000);
    let children = host.session.children(cu).unwrap();
    assert_eq!(children.ids.len(), n + 2);
}
