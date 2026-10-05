//! Test fixtures and an in-memory host.

#![allow(dead_code)]

use fillyfoal::{ChildState, Limits, NodeId, Progress, Session, Span, formats, render};

// ---------------------------------------------------------------------------
// Byte-level image writer

pub struct Image(Vec<u8>);

impl Image {
    pub fn new(len: usize) -> Self {
        Image(vec![0; len])
    }
    pub fn bytes(&mut self, at: usize, b: &[u8]) -> &mut Self {
        self.0[at..at + b.len()].copy_from_slice(b);
        self
    }
    pub fn u16(&mut self, at: usize, v: u16) -> &mut Self {
        self.bytes(at, &v.to_le_bytes())
    }
    pub fn u32(&mut self, at: usize, v: u32) -> &mut Self {
        self.bytes(at, &v.to_le_bytes())
    }
    pub fn u64(&mut self, at: usize, v: u64) -> &mut Self {
        self.bytes(at, &v.to_le_bytes())
    }
    pub fn cstr(&mut self, at: usize, s: &str) -> &mut Self {
        self.bytes(at, s.as_bytes()).bytes(at + s.len(), &[0])
    }
    pub fn finish(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

/// A headers-only PE32 image (no sections), for embedding.
pub fn mini_pe32() -> Vec<u8> {
    let mut w = Image::new(0x140);
    w.bytes(0, b"MZ").u32(0x3c, 0x40).bytes(0x40, b"PE\0\0");
    // File header
    w.u16(0x44, 0x14c).u32(0x48, 0x5000_0000).u16(0x54, 224).u16(0x56, 0x0102);
    // Optional header (PE32)
    let o = 0x58;
    w.u16(o, 0x10b)
        .u32(o + 28, 0x40_0000)
        .u32(o + 32, 0x1000)
        .u32(o + 36, 0x200)
        .u32(o + 56, 0x1000)
        .u32(o + 60, 0x200)
        .u16(o + 68, 3)
        .u32(o + 92, 16);
    w.finish()
}

/// A PE32+ DLL exercising most of the dissector:
///
/// - `.text`, `.rdata`, `.rsrc` sections
/// - exports: two named (one forwarded) and one exported by ordinal only
/// - imports from two DLLs, by name and by ordinal
/// - a CodeView (RSDS) debug entry
/// - a resource tree with a named entry, an embedded PE32, and a cycle
/// - a certificate table and an overlay
pub fn fixture() -> Vec<u8> {
    const RDATA: usize = 0x600; // file offset of RVA 0x2000
    const RSRC: usize = 0xa00; // file offset of RVA 0x3000
    let rd = |rva: usize| RDATA + rva - 0x2000;
    let rs = |off: usize| RSRC + off;

    let mut w = Image::new(0xe18);
    w.bytes(0, b"MZ").u16(2, 0x90).u16(4, 3).u32(0x3c, 0x80);
    w.bytes(0x4e, b"This program cannot be run in DOS mode.");
    w.bytes(0x80, b"PE\0\0");

    // File header
    w.u16(0x84, 0x8664) // AMD64
        .u16(0x86, 3) // sections
        .u32(0x88, 0x6500_0000)
        .u16(0x94, 0xf0) // SizeOfOptionalHeader
        .u16(0x96, 0x2022); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL

    // Optional header (PE32+)
    let o = 0x98;
    w.u16(o, 0x20b)
        .bytes(o + 2, &[14, 0])
        .u32(o + 4, 0x200)
        .u32(o + 8, 0x800)
        .u32(o + 16, 0x1000) // entry point
        .u32(o + 20, 0x1000)
        .u64(o + 24, 0x1_8000_0000)
        .u32(o + 32, 0x1000)
        .u32(o + 36, 0x200)
        .u16(o + 40, 6)
        .u16(o + 48, 6)
        .u32(o + 56, 0x4000) // SizeOfImage
        .u32(o + 60, 0x400) // SizeOfHeaders
        .u16(o + 68, 2) // WINDOWS_GUI
        .u16(o + 70, 0x0160)
        .u64(o + 72, 0x10_0000)
        .u64(o + 80, 0x1000)
        .u64(o + 88, 0x10_0000)
        .u64(o + 96, 0x1000)
        .u32(o + 108, 16);
    let dd = o + 112;
    w.u32(dd, 0x2000).u32(dd + 4, 0x140); // export
    w.u32(dd + 8, 0x2200).u32(dd + 12, 0x3c); // import
    w.u32(dd + 16, 0x3000).u32(dd + 20, 0x400); // resource
    w.u32(dd + 32, 0xe00).u32(dd + 36, 0x10); // certificate (file offset)
    w.u32(dd + 48, 0x2340).u32(dd + 52, 28); // debug
    w.u32(dd + 96, 0x2280).u32(dd + 100, 0x30); // IAT

    // Section table
    let mut section = |i: usize, name: &[u8], vsize, va, raw_size, raw_ptr, chars| {
        let s = 0x188 + i * 40;
        w.bytes(s, name)
            .u32(s + 8, vsize)
            .u32(s + 12, va)
            .u32(s + 16, raw_size)
            .u32(s + 20, raw_ptr)
            .u32(s + 36, chars);
    };
    section(0, b".text", 0x10, 0x1000, 0x200, 0x400, 0x6000_0020);
    section(1, b".rdata", 0x400, 0x2000, 0x400, 0x600, 0x4000_0040);
    section(2, b".rsrc", 0x400, 0x3000, 0x400, 0xa00, 0x4000_0040);

    w.bytes(0x400, &[0xc3]);

    // Exports
    w.u32(rd(0x2004), 0x6500_0000)
        .u32(rd(0x200c), 0x2100) // Name
        .u32(rd(0x2010), 1) // Base
        .u32(rd(0x2014), 3) // NumberOfFunctions
        .u32(rd(0x2018), 2) // NumberOfNames
        .u32(rd(0x201c), 0x2040)
        .u32(rd(0x2020), 0x2050)
        .u32(rd(0x2024), 0x2058);
    w.u32(rd(0x2040), 0x1000).u32(rd(0x2044), 0x1008).u32(rd(0x2048), 0x2110);
    w.u32(rd(0x2050), 0x2120).u32(rd(0x2054), 0x2128);
    w.u16(rd(0x2058), 0).u16(rd(0x205a), 2);
    w.cstr(rd(0x2100), "fixture.dll")
        .cstr(rd(0x2110), "KERNEL32.Sleep")
        .cstr(rd(0x2120), "alpha")
        .cstr(rd(0x2128), "beta");

    // Imports
    let mut descriptor = |at: usize, ilt, name, iat| {
        w.u32(rd(at), ilt).u32(rd(at + 12), name).u32(rd(at + 16), iat);
    };
    descriptor(0x2200, 0x2240, 0x2300, 0x2280);
    descriptor(0x2214, 0x2260, 0x2310, 0x22a0);
    for base in [0x2240, 0x2280] {
        w.u64(rd(base), 0x2320).u64(rd(base + 8), 0x8000_0000_0000_0010);
    }
    for base in [0x2260, 0x22a0] {
        w.u64(rd(base), 0x2330);
    }
    w.cstr(rd(0x2300), "KERNEL32.dll").cstr(rd(0x2310), "USER32.dll");
    w.u16(rd(0x2320), 0x123).cstr(rd(0x2322), "ExitProcess");
    w.u16(rd(0x2330), 0x42).cstr(rd(0x2332), "MessageBoxW");

    // Debug directory + RSDS
    w.u32(rd(0x2344), 0x6500_0000)
        .u32(rd(0x234c), 2)
        .u32(rd(0x2350), 36)
        .u32(rd(0x2354), 0x2360)
        .u32(rd(0x2358), rd(0x2360) as u32);
    w.bytes(rd(0x2360), b"RSDS")
        .bytes(rd(0x2364), &(0u8..16).collect::<Vec<_>>())
        .u32(rd(0x2374), 1)
        .cstr(rd(0x2378), "fixture.pdb");

    // Resources: root -> [RT_ICON (cycle back to root), RT_RCDATA -> "PAYLOAD" -> 0x409]
    let payload = mini_pe32();
    w.u16(rs(0x0e), 2)
        .u32(rs(0x10), 3)
        .u32(rs(0x14), 0x8000_0000)
        .u32(rs(0x18), 10)
        .u32(rs(0x1c), 0x8000_0020);
    w.u16(rs(0x2c), 1)
        .u32(rs(0x30), 0x8000_0060)
        .u32(rs(0x34), 0x8000_0038);
    w.u16(rs(0x46), 1).u32(rs(0x48), 0x409).u32(rs(0x4c), 0x50);
    w.u32(rs(0x50), 0x3100).u32(rs(0x54), payload.len() as u32);
    w.u16(rs(0x60), 7);
    for (i, c) in "PAYLOAD".encode_utf16().enumerate() {
        w.u16(rs(0x62 + 2 * i), c);
    }
    w.bytes(rs(0x100), &payload);

    // Certificate table and overlay
    w.u32(0xe00, 0x10).u16(0xe04, 0x200).u16(0xe06, 2).bytes(0xe08, &[0x30; 8]);
    w.bytes(0xe10, b"OVERLAY!");
    w.finish()
}

// ---------------------------------------------------------------------------
// In-memory host

pub struct Host {
    pub session: Session,
    pub data: Vec<u8>,
    pub root: NodeId,
    pub budget: u64,
    pub polls: u64,
    pub bytes_supplied: u64,
    pub max_polls: u64,
}

impl Host {
    pub fn new(data: Vec<u8>, limits: Limits) -> Self {
        let mut session = Session::new(limits);
        let len = data.len() as u64;
        let source = session.add_source(len);
        let root = session.add_root(formats::root("fixture.dll", Span::new(source, 0, len)));
        Host {
            session,
            data,
            root,
            budget: 1_000_000,
            polls: 0,
            bytes_supplied: 0,
            max_polls: 1_000_000,
        }
    }

    pub fn with_chunk(data: Vec<u8>, chunk_size: u64) -> Self {
        Host::new(
            data,
            Limits {
                chunk_size,
                ..Limits::default()
            },
        )
    }

    /// Polls until idle, answering byte requests from memory.
    pub fn run(&mut self) {
        loop {
            self.polls += 1;
            assert!(self.polls < self.max_polls, "session did not settle");
            match self.session.poll(self.budget) {
                Progress::Idle => return,
                Progress::Yielded => {}
                Progress::NeedBytes(requests) => {
                    assert!(!requests.is_empty());
                    for r in requests {
                        let start = r.offset as usize;
                        let end = (start + r.len as usize).min(self.data.len());
                        let bytes = self.data.get(start..end).unwrap_or_default();
                        self.bytes_supplied += bytes.len() as u64;
                        self.session.supply(r.source, r.offset, bytes);
                    }
                }
            }
        }
    }

    /// Expands everything under `id` down to `depth`, fetching pages of
    /// `page` children until each collection is exhausted.
    pub fn explore(&mut self, id: NodeId, depth: usize, page: u64) {
        if depth == 0 {
            return;
        }
        loop {
            self.session.expand_more(id, page);
            self.run();
            let state = self.session.children(id).map(|c| c.state);
            if state != Some(ChildState::More) {
                break;
            }
        }
        let children = self.session.children(id).map(|c| c.ids.to_vec()).unwrap_or_default();
        for child in children {
            self.explore(child, depth - 1, page);
        }
    }

    pub fn explore_all(&mut self) {
        self.explore(self.root, 32, 1000);
    }

    pub fn render(&self) -> String {
        render::tree(&self.session, self.root)
    }

    /// Finds a direct child by name.
    pub fn child(&self, id: NodeId, name: &str) -> Option<NodeId> {
        let children = self.session.children(id)?;
        children
            .ids
            .iter()
            .copied()
            .find(|&c| self.session.node(c).is_some_and(|n| n.name == name))
    }
}

/// Deterministic xorshift, so mutation sweeps are reproducible.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}
