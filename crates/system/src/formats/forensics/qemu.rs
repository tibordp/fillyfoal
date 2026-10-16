//! QEMU migration streams (a saved VM state: `migrate "exec:cat > f"`,
//! `migrate file:`, the state inside `virsh save` images and snapshots)
//! and libvirt save images, which wrap one.
//!
//! A migration stream is `QEVM`, a version (3), then a sequence of
//! sections, each introduced by a type byte: the configuration (machine
//! type and optional subsections: target page bits, capabilities, UUID),
//! section starts and full sections (section ID, ID string, instance and
//! version), parts and ends of iterative sections (section ID only),
//! commands, and `QEMU_VM_EOF`; each section ends with a footer
//! (`0x7e` and its section ID) on machine types that send them (all since
//! QEMU 2.6). After the end, QEMU appends the JSON VM description
//! (`QEMU_VM_VMDESCRIPTION`, a big-endian length, then the JSON), which
//! lists every device section's fields with their sizes.
//!
//! RAM is the iterative section `ram`: its start lists the RAM blocks
//! (ID string and used length); its parts and end carry page records, a
//! 64-bit page address whose low bits are flags (zero page with a fill
//! byte, full page, XBZRLE delta, zlib-compressed page, "same block as
//! before", multifd flush, end of section). Zero pages are a flag and a
//! byte, so a mostly idle guest costs little. Pages are shown as runs
//! of contiguous pages of one kind; data runs list their pages.
//!
//! Device sections are VMState structures whose layout lives in QEMU's
//! code, not in the stream: their payload ends at the footer, found by
//! scanning for it (and checking that a section follows). When the VM
//! description is present the payload is decoded into named fields (it
//! records each field's size, array length, nested structures and the
//! subsections that were sent). Without footers, the description gives
//! the sizes instead.
//!
//! Layout from QEMU's `docs/devel/migration/` and the stream as written by
//! QEMU 10.0 (`migration/savevm.c`, `migration/ram.c`, GPL-2.0-or-later,
//! read for the facts); checked against streams QEMU wrote (external
//! fixtures: x86 microvm and q35, aarch64 virt, SPARC64 sun4u, footer-less
//! and postcopy). The target page size is in the configuration only for
//! targets whose page size varies (Arm); otherwise it is taken from the VM
//! description when that is cheap to read, or from the machine type for
//! the 8 KiB targets (SPARC64, Alpha), else assumed to be 4 KiB. In a
//! `mapped-ram` stream (libvirt's "sparse" saves) each RAM block's header
//! is followed by a header giving the file offsets of its page bitmap and
//! pages, and the stream resumes after the pages; the blocks are shown
//! with their bitmap and pages. Not handled: RDMA hooks (unsupported
//! diagnostic); with both `postcopy-ram` and
//! `x-ignore-shared`, a RAM block's optional page size is guessed.
//!
//! libvirt save images (`virsh save`, `managedsave`): a 92-byte header
//! (`LibvirtQemudSave`, or `LibvirtQemudPart` while the save is not
//! complete; version, length of the XML data, whether the domain was
//! running, the compression of the stream, and where the migration cookie
//! starts), the domain XML and cookie (NUL-terminated, then zeros up to an
//! alignment), then the migration stream, raw or compressed by an external
//! program (gzip, bzip2, xz, lzop, zstd). The header is in the host's byte
//! order. From libvirt's `src/qemu/qemu_saveimage.c` (LGPL-2.1-or-later,
//! facts only) and checked against images `virsh save` wrote.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, u16_be, u32_be, u32_le};
use crate::cx::{Block, Cx};
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{DiagKind, Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::far;
use crate::formats::util::fmt::{clip, plural, size};
use crate::formats::util::json::{self, Json};
use crate::formats::util::val::{int, text, uint};
use crate::formats::{Codec, Head, Input, Probe, content, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, flag};

const BE: Endian = Endian::Big;
const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// QEMU migration stream

fn qemu_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"QEVM") && matches!(u32_be(h.data, 4), Some(2 | 3))
}

declare_format!(pub QEMU_VMSTATE = "qemu-vmstate", "QEMU migration stream / saved VM state", ["vmstate", "mig"], "application/x-qemu-vmstate",
    Probe::Custom(qemu_probe), qemu);

const T_EOF: u8 = 0x00;
const T_START: u8 = 0x01;
const T_PART: u8 = 0x02;
const T_END: u8 = 0x03;
const T_FULL: u8 = 0x04;
const T_SUBSECTION: u8 = 0x05;
const T_VMDESC: u8 = 0x06;
const T_CONFIG: u8 = 0x07;
const T_COMMAND: u8 = 0x08;
const T_FOOTER: u8 = 0x7e;

const SECTION_TYPES: EnumTable = &[
    (0x00, "QEMU_VM_EOF"),
    (0x01, "QEMU_VM_SECTION_START"),
    (0x02, "QEMU_VM_SECTION_PART"),
    (0x03, "QEMU_VM_SECTION_END"),
    (0x04, "QEMU_VM_SECTION_FULL"),
    (0x05, "QEMU_VM_SUBSECTION"),
    (0x06, "QEMU_VM_VMDESCRIPTION"),
    (0x07, "QEMU_VM_CONFIGURATION"),
    (0x08, "QEMU_VM_COMMAND"),
    (0x7e, "QEMU_VM_SECTION_FOOTER"),
];

const COMMANDS: EnumTable = &[
    (1, "MIG_CMD_OPEN_RETURN_PATH"),
    (2, "MIG_CMD_PING"),
    (3, "MIG_CMD_POSTCOPY_ADVISE"),
    (4, "MIG_CMD_POSTCOPY_LISTEN"),
    (5, "MIG_CMD_POSTCOPY_RUN"),
    (6, "MIG_CMD_POSTCOPY_RAM_DISCARD"),
    (7, "MIG_CMD_PACKAGED"),
    (8, "MIG_CMD_ENABLE_COLO"),
    (9, "MIG_CMD_POSTCOPY_RESUME"),
    (10, "MIG_CMD_RECV_BITMAP"),
    (11, "MIG_CMD_SWITCHOVER_START"),
];
const CMD_PACKAGED: u16 = 7;

// RAM page record flags (the low bits of the page address).
const F_ZERO: u64 = 0x02;
const F_MEM_SIZE: u64 = 0x04;
const F_PAGE: u64 = 0x08;
const F_EOS: u64 = 0x10;
const F_CONTINUE: u64 = 0x20;
const F_XBZRLE: u64 = 0x40;
const F_HOOK: u64 = 0x80;
const F_COMPRESS: u64 = 0x100;
const F_FLUSH: u64 = 0x200;

const RAM_FLAGS: FlagTable = &[
    flag(0x01, "FULL"),
    flag(F_ZERO, "ZERO"),
    flag(F_MEM_SIZE, "MEM_SIZE"),
    flag(F_PAGE, "PAGE"),
    flag(F_EOS, "EOS"),
    flag(F_CONTINUE, "CONTINUE"),
    flag(F_XBZRLE, "XBZRLE"),
    flag(F_HOOK, "HOOK"),
    flag(F_COMPRESS, "COMPRESS_PAGE"),
    flag(F_FLUSH, "MULTIFD_FLUSH"),
];

/// What the walker knows about the stream so far (kept in resume marks).
#[derive(Clone, Debug)]
struct Stream {
    /// Target page size (from the configuration; 4 KiB by default).
    page: u64,
    caps: Vec<String>,
    /// Section ID to ID string, from section starts.
    names: BTreeMap<u32, String>,
    /// Whether sections end with footers (seen after the RAM setup).
    footers: bool,
    /// The machine type, from the configuration.
    machine: String,
    /// The RAM block of the last page record: a page record that
    /// continues it may start the next RAM part.
    block: String,
    sections: u64,
    ram_total: u64,
    ram_blocks: u64,
}

impl Stream {
    fn new() -> Self {
        Stream {
            page: 4096,
            caps: Vec::new(),
            names: BTreeMap::new(),
            footers: true,
            machine: String::new(),
            block: String::new(),
            sections: 0,
            ram_total: 0,
            ram_blocks: 0,
        }
    }

    fn cap(&self, name: &str) -> bool {
        self.caps.iter().any(|c| c == name)
    }

    fn ram_ctx(&self) -> RamCtx {
        RamCtx {
            page: self.page,
            postcopy: self.cap("postcopy-ram"),
            ignore_shared: self.cap("x-ignore-shared"),
            mapped: self.cap("mapped-ram"),
        }
    }
}

/// Where the stream lives: the outer stream (for its VM description) and
/// the region being walked (the stream, or a packaged stream inside it).
#[derive(Clone)]
struct Walk {
    input: Input,
    stream: Span,
    region: Span,
    header: bool,
    depth: u32,
    /// For a packaged stream: what the outer stream had set up (page
    /// size, capabilities, footers, the last RAM block).
    outer: Option<Arc<Stream>>,
}

async fn qemu(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    walk(
        cx,
        Walk {
            input,
            stream: span,
            region: span,
            header: true,
            depth: 0,
            outer: None,
        },
    )
    .await
}

fn header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Magic", 4).emit()?;
    f.u32("Version")
        .desc("QEMU_VM_FILE_VERSION (2 is the pre-0.13 compatible version)")
        .emit()?;
    Ok(())
}

/// Walks the sections of a stream (or of a packaged stream inside one).
async fn walk(cx: Cx, w: Walk) -> Result<()> {
    let region = w.region;
    let mut cur = Cursor::new(&cx, region, BE);
    let mut st = match &w.outer {
        Some(outer) => Stream {
            page: outer.page,
            caps: outer.caps.clone(),
            footers: outer.footers,
            block: outer.block.clone(),
            ..Stream::new()
        },
        None => Stream::new(),
    };
    if let Some((pos, saved)) = cx.resume::<(u64, Stream)>() {
        cur.seek(pos);
        st = saved;
    } else if w.header {
        cx.emit(struct_node(
            "Header",
            region.sub(0, 8),
            BE,
            (),
            header_layout,
        ));
        cur.seek(8);
        let head = cx.read_avail(region.sub(4, 4)).await?;
        if u32_be(&head, 0) == Some(2) {
            // QEMU_VM_FILE_VERSION_COMPAT: records of ID string, instance,
            // version and a 64-bit length, with no section types; QEMU
            // stopped writing it in 0.13 and refuses to read it.
            return Err(
                Diagnostic::unsupported("version 2 (pre-0.13) stream layout").at(region.sub(8, 0)),
            );
        }
    }
    loop {
        if cur.at_end() {
            if !w.header {
                // A packaged stream ends with its package (after
                // MIG_CMD_POSTCOPY_RUN), not with QEMU_VM_EOF.
                break;
            }
            cx.diag(
                Diagnostic::new(DiagKind::Truncated, "the stream ends before QEMU_VM_EOF")
                    .at(region.sub(cur.pos(), 0)),
            );
            break;
        }
        let start = cur.pos();
        cx.mark(|| (start, st.clone()));
        cx.progress_in(region, region.offset.saturating_add(start));
        let ty = cur.u8().await?;
        let step = match ty {
            T_CONFIG => config_section(&cx, &w, &mut cur, &mut st).await,
            T_START | T_FULL => start_section(&cx, &w, &mut cur, &mut st, ty).await,
            T_PART | T_END => part_section(&cx, &w, &mut cur, &mut st, ty).await,
            T_COMMAND => command(&w, &mut cur, &st).await,
            T_EOF => {
                eof(&cx, &w, &mut cur).await?;
                break;
            }
            _ => Err(
                Diagnostic::malformed(format!("unknown section type {ty:#04x}"))
                    .at(region.sub(start, 1)),
            ),
        };
        match step {
            Ok(node) => cx.push(node).await,
            Err(e) => {
                cx.diag(e);
                break;
            }
        }
    }
    if w.header {
        let mut label = String::from("QEMU migration stream");
        if !st.machine.is_empty() {
            label.push_str(&format!(", {}", clip(&st.machine, 40)));
        }
        if st.ram_blocks > 0 {
            label.push_str(&format!(
                ", {} RAM in {}",
                size(st.ram_total),
                plural(st.ram_blocks, "block")
            ));
        }
        if st.sections > 0 {
            label.push_str(&format!(", {}", plural(st.sections, "section")));
        }
        cx.annotate(label);
    }
    Ok(())
}

// --- Configuration ---------------------------------------------------------

#[derive(Default)]
struct Config {
    machine: String,
    page_bits: Option<u32>,
    caps: Vec<String>,
}

/// The configuration section, type byte included. Subsections whose
/// layout is not known stop the parse (their length is not recorded).
fn config_layout(f: &mut Fields<'_>, _: &()) -> Result<Config> {
    f.u8("Section type").enumeration(SECTION_TYPES).emit()?;
    let n = f.u32("Name length").emit()?;
    let machine = f.ascii("Machine type", n.into()).emit()?;
    let mut config = Config {
        machine,
        ..Config::default()
    };
    while f.block().data.get(crate::bytes::to_usize(f.pos())) == Some(&T_SUBSECTION) {
        let start = f.pos();
        let mut g = Fields::new(f.block(), BE);
        g.seek(start);
        let (name, sub) = config_subsection(&mut g, &())?;
        let len = g.pos().saturating_sub(start);
        if let Some(bits) = sub.page_bits {
            config.page_bits = Some(bits);
        }
        config.caps.extend(sub.caps);
        f.node(struct_node(name, f.peek_span(len), BE, (), config_subsection).summary(sub.summary));
        f.skip(len);
    }
    Ok(config)
}

#[derive(Default)]
struct ConfigSub {
    page_bits: Option<u32>,
    caps: Vec<String>,
    summary: String,
}

fn config_subsection(f: &mut Fields<'_>, _: &()) -> Result<(String, ConfigSub)> {
    f.u8("Subsection marker")
        .enumeration(SECTION_TYPES)
        .emit()?;
    let n = f.u8("Name length").emit()?;
    let name = f.ascii("Name", n.into()).emit()?;
    f.u32("Version").emit()?;
    let mut sub = ConfigSub::default();
    match name.as_str() {
        "configuration/target-page-bits" => {
            let bits = f
                .u32("Target page bits")
                .check(|&b| {
                    (!(9..=22).contains(&b))
                        .then(|| Diagnostic::malformed(format!("page size 2^{b}")))
                })
                .with(|&b, node: Node| node.summary(size(1u64.checked_shl(b).unwrap_or(0))))
                .emit()?;
            sub.summary = format!("{bits} bits");
            sub.page_bits = Some(bits);
        }
        "configuration/capabilities" => {
            let count = f.u32("Capability count").emit()?;
            for _ in 0..count.min(256) {
                let len = f.u8("Length").get()?;
                let cap = f.ascii("Capability", len.into()).emit()?;
                sub.caps.push(cap);
            }
            sub.summary = clip(&sub.caps.join(", "), 120);
        }
        "configuration/uuid" => {
            let uuid = f.bytes("UUID", 16).emit()?;
            sub.summary = crate::formats::util::fmt::uuid(&uuid);
        }
        _ => {
            return Err(Diagnostic::unsupported(format!(
                "configuration subsection {name} (its length is not recorded)"
            ))
            .at(f.peek_span(1)));
        }
    }
    Ok((name, sub))
}

/// How much of a section's start is read to parse what has no length
/// field (the configuration, the RAM block list).
const SETUP_MAX: u64 = 256 * 1024;

/// Machine types of targets whose pages are fixed at 8 KiB
/// (`TARGET_PAGE_BITS` 13: SPARC64 and Alpha).
const PAGES_8K: &[&str] = &["sun4u", "sun4v", "niagara", "clipper"];

/// The page size of a stream with no `target-page-bits` subsection, which
/// QEMU sends only for targets whose page size varies (Arm): from the VM
/// description when reading it is cheap (it is at the end of the stream),
/// else from the machine type for the 8 KiB targets, else unknown (4 KiB:
/// x86 and most others).
async fn fixed_page(cx: &Cx, w: &Walk, machine: &str) -> Result<Option<u64>> {
    if cx.read_is_cheap(w.stream.tail(w.stream.len.saturating_sub(1)))
        && let Some(page) = vmdesc(cx, w.stream)
            .await?
            .and_then(|d| d.page_size)
            .filter(|p| p.is_power_of_two() && (512..=1 << 20).contains(p))
    {
        return Ok(Some(page));
    }
    let base = machine.split('-').next().unwrap_or_default();
    Ok(PAGES_8K.contains(&base).then_some(8192))
}

async fn config_section(cx: &Cx, w: &Walk, cur: &mut Cursor<'_>, st: &mut Stream) -> Result<Node> {
    let start = cur.pos().saturating_sub(1);
    let region = cur.region();
    let span = region.sub(start, SETUP_MAX);
    let block = Block {
        span,
        data: cx.read_avail(span).await?,
    };
    let mut f = Fields::new(&block, BE);
    let config = config_layout(&mut f, &())?;
    let len = f.pos();
    cx.charge(len / 64).await;
    if let Some(bits) = config.page_bits {
        st.page = 1u64.checked_shl(bits).unwrap_or(4096);
    } else if let Some(page) = fixed_page(cx, w, &config.machine).await? {
        st.page = page;
    }
    st.caps = config.caps;
    st.machine = config.machine.clone();
    cur.seek(start.saturating_add(len));
    let mut summary = config.machine.clone();
    if !st.caps.is_empty() {
        summary.push_str(&format!(", {}", plural(st.caps.len(), "capability")));
    }
    Ok(struct_node(
        "Configuration",
        region.sub(start, len),
        BE,
        (),
        config_layout,
    )
    .summary(summary))
}

// --- Sections ----------------------------------------------------------------

/// A section as found by the walker, for its lazy expansion.
#[derive(Clone)]
struct Section {
    walk: Walk,
    ty: u8,
    idstr: String,
    instance: u32,
    /// Offsets in the region: the section, its header, its payload.
    start: u64,
    payload: u64,
    payload_end: u64,
    footer: bool,
    ram: RamCtx,
    /// Page counts, for a RAM part's pages node.
    counts: Counts,
    /// The RAM block of the page record before the section.
    block: String,
}

impl Section {
    fn span(&self, from: u64, to: u64) -> Span {
        self.walk.region.sub(from, to.saturating_sub(from))
    }
}

fn section_header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let ty = f.u8("Section type").enumeration(SECTION_TYPES).emit()?;
    f.u32("Section ID").emit()?;
    if matches!(ty, T_START | T_FULL) {
        let n = f.u8("ID string length").emit()?;
        f.ascii("ID string", n.into()).emit()?;
        f.u32("Instance ID").emit()?;
        f.u32("Version ID").emit()?;
    }
    Ok(())
}

fn footer_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Marker").enumeration(SECTION_TYPES).emit()?;
    f.u32("Section ID").emit()?;
    Ok(())
}

async fn start_section(
    cx: &Cx,
    w: &Walk,
    cur: &mut Cursor<'_>,
    st: &mut Stream,
    ty: u8,
) -> Result<Node> {
    let start = cur.pos().saturating_sub(1);
    let id = cur.u32().await?;
    let n = cur.u8().await?;
    let idstr = crate::text::latin1(&cur.bytes(n.into()).await?);
    let instance = cur.u32().await?;
    let version = cur.u32().await?;
    st.names.insert(id, idstr.clone());
    st.sections = st.sections.saturating_add(1);
    let payload = cur.pos();
    let mut sec = Section {
        walk: w.clone(),
        ty,
        idstr: idstr.clone(),
        instance,
        start,
        payload,
        payload_end: payload,
        footer: false,
        ram: st.ram_ctx(),
        counts: Counts::default(),
        block: st.block.clone(),
    };
    let kind = if ty == T_START { "start" } else { "full" };
    let mut summary = format!("{kind}, instance {instance}, version {version}");
    if idstr == "ram" && ty == T_START {
        let setup = ram_setup(cx, cur, &sec.ram).await?;
        sec.payload_end = cur.pos();
        st.ram_total = setup.total;
        st.ram_blocks = to_u64(setup.blocks);
        summary.push_str(&format!(
            ", {} RAM in {}",
            size(setup.total),
            plural(setup.blocks, "block")
        ));
        // The first section tells whether this stream has footers.
        st.footers = footer_at(cx, cur, id).await?;
        sec.footer = st.footers;
    } else {
        let end = payload_end(cx, w, cur, st, id, &idstr, instance).await?;
        sec.payload_end = end;
        cur.seek(end);
        sec.footer = st.footers && footer_at(cx, cur, id).await?;
        summary.push_str(&format!(", {}", size(end.saturating_sub(payload))));
    }
    if sec.footer {
        cur.skip(5);
    }
    let span = cur.since(start);
    Ok(Node::new(idstr)
        .span(span)
        .summary(summary)
        .lazy(expand_section, sec))
}

async fn part_section(
    cx: &Cx,
    w: &Walk,
    cur: &mut Cursor<'_>,
    st: &mut Stream,
    ty: u8,
) -> Result<Node> {
    let start = cur.pos().saturating_sub(1);
    let id = cur.u32().await?;
    let payload = cur.pos();
    let idstr = st.names.get(&id).cloned();
    let Some(idstr) = idstr else {
        return Err(
            Diagnostic::malformed(format!("section part for unknown section ID {id}"))
                .at(cur.since(start)),
        );
    };
    let mut sec = Section {
        walk: w.clone(),
        ty,
        idstr: idstr.clone(),
        instance: 0,
        start,
        payload,
        payload_end: payload,
        footer: false,
        ram: st.ram_ctx(),
        counts: Counts::default(),
        block: st.block.clone(),
    };
    let kind = if ty == T_PART { "part" } else { "end" };
    let summary = if idstr == "ram" {
        let counts = ram_count(cx, cur, &sec.ram, &mut st.block).await?;
        sec.payload_end = cur.pos();
        sec.counts = counts.clone();
        format!("{kind}: {}", counts.describe())
    } else {
        let end = payload_end(cx, w, cur, st, id, &idstr, u32::MAX).await?;
        sec.payload_end = end;
        cur.seek(end);
        format!("{kind}, {}", size(end.saturating_sub(payload)))
    };
    sec.footer = st.footers && footer_at(cx, cur, id).await?;
    if sec.footer {
        cur.skip(5);
    }
    let name = format!("{idstr} ({kind})");
    Ok(Node::new(name)
        .span(cur.since(start))
        .summary(summary)
        .lazy(expand_section, sec))
}

/// Whether the footer of section `id` is at the cursor.
async fn footer_at(cx: &Cx, cur: &Cursor<'_>, id: u32) -> Result<bool> {
    let b = cx.read_avail(cur.region().sub(cur.pos(), 5)).await?;
    Ok(b.first() == Some(&T_FOOTER) && u32_be(&b, 1) == Some(id))
}

/// Where the payload of a section with no recorded length ends: at its
/// footer, or (without footers) where the VM description says.
async fn payload_end(
    cx: &Cx,
    w: &Walk,
    cur: &Cursor<'_>,
    st: &Stream,
    id: u32,
    idstr: &str,
    instance: u32,
) -> Result<u64> {
    let from = cur.pos();
    if st.footers {
        if let Some(at) = find_footer(cx, w.region, from, id, &st.names).await? {
            return Ok(at);
        }
        return Err(
            Diagnostic::malformed(format!("no footer for section {id} ({idstr})"))
                .at(w.region.sub(from, 1)),
        );
    }
    // No footers: only the VM description knows the size.
    if instance != u32::MAX
        && let Some(desc) = vmdesc(cx, w.stream).await?
        && let Some(dev) = desc.device(idstr, instance)
    {
        return Ok(from.saturating_add(dev.total));
    }
    Err(Diagnostic::unsupported(format!(
        "the length of section {idstr} (no footers and no VM description)"
    ))
    .at(w.region.sub(from, 1)))
}

/// Scans for the footer of section `id` from `from`: `0x7e`, the ID, and
/// then something that can follow a section.
async fn find_footer(
    cx: &Cx,
    region: Span,
    from: u64,
    id: u32,
    names: &BTreeMap<u32, String>,
) -> Result<Option<u64>> {
    const WINDOW: u64 = 0x10000;
    // A footer and the next section's header (up to 1 + 4 + 1 + 255).
    const OVERLAP: u64 = 0x110;
    let mut pat = [T_FOOTER, 0, 0, 0, 0];
    if let Some(dst) = pat.get_mut(1..) {
        dst.copy_from_slice(&id.to_be_bytes());
    }
    let mut at = from;
    while at < region.len {
        cx.progress_in(region, region.offset.saturating_add(at));
        let buf = cx
            .read_avail(region.sub(at, WINDOW.saturating_add(OVERLAP)))
            .await?;
        let whole = to_u64(buf.len()) <= WINDOW;
        let limit = if whole {
            buf.len()
        } else {
            crate::bytes::to_usize(WINDOW)
        };
        let mut i = 0usize;
        while let Some(p) = buf
            .get(i..limit.saturating_add(4).min(buf.len()))
            .and_then(|b| b.windows(5).position(|x| x == pat))
        {
            let pos = i.saturating_add(p);
            let next = pos.saturating_add(5);
            let at_end = at.saturating_add(to_u64(next)) >= region.len;
            if follows_section(&buf, next, at_end, names) {
                return Ok(Some(at.saturating_add(to_u64(pos))));
            }
            i = pos.saturating_add(1);
        }
        cx.charge(64).await;
        if whole {
            break;
        }
        at = at.saturating_add(WINDOW);
    }
    Ok(None)
}

/// Whether what starts at `q` in `buf` can follow a section footer.
fn follows_section(buf: &[u8], q: usize, at_end: bool, names: &BTreeMap<u32, String>) -> bool {
    let Some(&ty) = buf.get(q) else {
        return at_end;
    };
    let after = q.saturating_add(1);
    match ty {
        T_EOF => buf.get(after).is_none_or(|&b| b == T_VMDESC),
        T_START | T_FULL => {
            let len = usize::from(buf.get(q.saturating_add(5)).copied().unwrap_or(0));
            let name = q.saturating_add(6);
            len > 0
                && buf
                    .get(name..name.saturating_add(len))
                    .is_some_and(|n| n.iter().all(|b| b.is_ascii_graphic()))
        }
        T_PART | T_END => u32_be(buf, after).is_some_and(|id| names.contains_key(&id)),
        T_COMMAND => u16_be(buf, after).is_some_and(|c| (1..=11).contains(&c)),
        _ => false,
    }
}

async fn command(w: &Walk, cur: &mut Cursor<'_>, st: &Stream) -> Result<Node> {
    let start = cur.pos().saturating_sub(1);
    let cmd = cur.u16().await?;
    let len = cur.u16().await?;
    let data = cur.span(len.into());
    let raw = cur.bytes(len.into()).await?;
    let name = crate::formats::util::val::name_or(COMMANDS, cmd.into(), "command");
    let mut node = Node::new(name).summary(plural(len, "byte"));
    if cmd == CMD_PACKAGED {
        // A whole stream (without its header) follows the command.
        let n = u32_be(&raw, 0).unwrap_or(0);
        let inner = cur.span(n.into());
        if inner.len < u64::from(n) {
            return Err(Diagnostic::truncated(
                Span::new(inner.source, inner.offset, n.into()),
                inner.len,
            ));
        }
        cur.skip(n.into());
        node = node.summary(format!("{} packaged stream", size(n.into())));
        let sub = Walk {
            input: w.input,
            stream: w.stream,
            region: inner,
            header: false,
            depth: w.depth.saturating_add(1),
            outer: Some(Arc::new(st.clone())),
        };
        if sub.depth > 4 {
            node = node.diag(Diagnostic::limit("packaged streams nested too deeply").at(inner));
        } else {
            let span = cur.since(start);
            return Ok(node.span(span).lazy(packaged, (data, sub)));
        }
    }
    let span = cur.since(start);
    Ok(node.span(span).lazy(command_fields, data))
}

async fn command_fields(cx: Cx, data: Span) -> Result<()> {
    let head = Span::new(data.source, data.offset.saturating_sub(5), 5);
    let block = cx.block(head).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u8("Section type").enumeration(SECTION_TYPES).emit()?;
    f.u16("Command").enumeration(COMMANDS).emit()?;
    f.u16("Length").emit()?;
    if data.len > 0 {
        cx.emit(Node::new("Data").span(data));
    }
    Ok(())
}

async fn packaged(cx: Cx, (data, sub): (Span, Walk)) -> Result<()> {
    command_fields(cx.clone(), data).await?;
    cx.emit(
        Node::new("Packaged stream")
            .span(sub.region)
            .lazy(crate::expander!(self::walk: Walk), sub),
    );
    Ok(())
}

/// The end of the stream, the VM description and anything after it.
async fn eof(cx: &Cx, w: &Walk, cur: &mut Cursor<'_>) -> Result<()> {
    let start = cur.pos().saturating_sub(1);
    cx.push(
        Node::new("End of stream")
            .span(cur.since(start))
            .value(Value::Enum {
                raw: 0,
                bits: 8,
                name: Some("QEMU_VM_EOF".into()),
            }),
    )
    .await;
    if !w.header {
        return Ok(());
    }
    if !cur.at_end() && cur.peek(1).await?.first() == Some(&T_VMDESC) {
        let vstart = cur.pos();
        cur.skip(1);
        let len = cur.u32().await?;
        let json_span = cur.span(len.into());
        cur.skip(len.into());
        let mut node = Node::new("VM description")
            .span(cur.since(vstart))
            .summary(format!("JSON, {}", size(len.into())))
            .lazy(vmdesc_node, (json_span, w.input));
        if json_span.len < u64::from(len) {
            node = node.diag(Diagnostic::truncated(
                Span::new(json_span.source, json_span.offset, len.into()),
                json_span.len,
            ));
        }
        cx.push(node).await;
    }
    if !cur.at_end() {
        let rest = cur.span(cur.remaining());
        cx.push(
            Node::new("Trailing data")
                .span(rest)
                .diag(Diagnostic::note("bytes follow the end of the stream").at(rest)),
        )
        .await;
    }
    Ok(())
}

async fn vmdesc_node(cx: Cx, (json_span, input): (Span, Input)) -> Result<()> {
    let head = Span::new(json_span.source, json_span.offset.saturating_sub(5), 5);
    let block = cx.block(head).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u8("Section type").enumeration(SECTION_TYPES).emit()?;
    f.u32("Length").emit()?;
    cx.emit(embedded_as(
        "JSON",
        input.nested(json_span),
        &crate::formats::text::json::FORMAT,
    ));
    Ok(())
}

async fn expand_section(cx: Cx, sec: Section) -> Result<()> {
    cx.emit(struct_node(
        "Section header",
        sec.span(sec.start, sec.payload),
        BE,
        (),
        section_header_layout,
    ));
    let payload = sec.span(sec.payload, sec.payload_end);
    if sec.idstr == "ram" && sec.ty == T_START && sec.ram.mapped {
        cx.emit(
            Node::new("RAM blocks")
                .span(payload)
                .lazy(mapped_blocks, sec.clone()),
        );
    } else if sec.idstr == "ram" && sec.ty == T_START {
        cx.emit(struct_node(
            "RAM blocks",
            payload,
            BE,
            sec.ram.clone(),
            ram_setup_layout,
        ));
    } else if sec.idstr == "ram" {
        cx.emit(
            Node::new("Pages")
                .span(payload)
                .summary(sec.counts.describe())
                .lazy(page_runs, sec.clone()),
        );
    } else if matches!(sec.ty, T_FULL) {
        cx.emit(
            Node::new("State")
                .span(payload)
                .summary(size(payload.len))
                .lazy(device_state, sec.clone()),
        );
    } else {
        cx.emit(Node::new("Data").span(payload).summary(size(payload.len)));
    }
    if sec.footer {
        cx.emit(struct_node(
            "Footer",
            sec.span(sec.payload_end, sec.payload_end.saturating_add(5)),
            BE,
            (),
            footer_layout,
        ));
    }
    Ok(())
}

// --- RAM ----------------------------------------------------------------------

/// What the RAM block list depends on.
#[derive(Clone, Debug)]
struct RamCtx {
    page: u64,
    postcopy: bool,
    ignore_shared: bool,
    /// `mapped-ram`: each block's pages at a fixed place in the file.
    mapped: bool,
}

struct RamSetup {
    total: u64,
    blocks: usize,
}

/// The RAM section's start: total size (with `MEM_SIZE`), each block's
/// ID string and used length (and, with postcopy, a page size where it
/// differs from the host's; with `x-ignore-shared`, its address), then
/// the end-of-section flags.
fn ram_setup_layout(f: &mut Fields<'_>, ctx: &RamCtx) -> Result<RamSetup> {
    let mask = ctx.page.saturating_sub(1);
    let first = f
        .u64("Total RAM")
        .with(move |&v, node: Node| {
            node.value(Value::UInt {
                value: v & !mask,
                bits: 64,
                radix: Radix::Hex,
            })
            .summary(format!("{}, flags {:#x}", size(v & !mask), v & mask))
        })
        .emit()?;
    if first & mask != F_MEM_SIZE {
        return Err(Diagnostic::malformed(format!(
            "RAM setup does not start with MEM_SIZE (flags {:#x})",
            first & mask
        ))
        .at(f.peek_span(0)));
    }
    let total = first & !mask;
    let mut seen = 0u64;
    let mut blocks = 0usize;
    while seen < total && f.remaining() > 0 {
        let start = f.pos();
        let mut g = Fields::new(f.block(), BE);
        g.seek(start);
        let (name, used) = ram_block(&mut g, ctx)?;
        let len = g.pos().saturating_sub(start);
        f.node(struct_node(name, f.peek_span(len), BE, ctx.clone(), ram_block).summary(size(used)));
        f.skip(len);
        seen = seen.saturating_add(used);
        blocks = blocks.saturating_add(1);
        if used == 0 && blocks > 4096 {
            return Err(Diagnostic::limit("too many empty RAM blocks").at(f.peek_span(0)));
        }
    }
    if seen != total {
        f.node(Node::new("Block sizes").diag(Diagnostic::malformed(format!(
            "blocks add up to {seen:#x}, not {total:#x}"
        ))));
    }
    loop {
        let v = f.u64("Flags").flags(RAM_FLAGS).hex().emit()?;
        if v & mask == F_EOS {
            break;
        }
        if v & mask != F_FLUSH {
            return Err(Diagnostic::malformed(format!(
                "unexpected flags {:#x} after the RAM block list",
                v & mask
            ))
            .at(f.peek_span(0)));
        }
    }
    Ok(RamSetup { total, blocks })
}

fn ram_block(f: &mut Fields<'_>, ctx: &RamCtx) -> Result<(String, u64)> {
    let n = f.u8("ID string length").emit()?;
    let name = f.ascii("ID string", n.into()).emit()?;
    let used = f
        .u64("Used length")
        .hex()
        .with(|&v, node: Node| node.summary(size(v)))
        .emit()?;
    let next_is_zero = f.block().data.get(crate::bytes::to_usize(f.pos())) == Some(&0);
    if ctx.postcopy && next_is_zero {
        let after = f
            .pos()
            .saturating_add(if ctx.ignore_shared { 16 } else { 8 });
        let nonzero_after = f.block().data.get(crate::bytes::to_usize(after)) != Some(&0);
        if !ctx.ignore_shared || nonzero_after {
            f.u64("Page size").hex().emit()?;
        }
    }
    if ctx.ignore_shared {
        f.u64("Address").hex().emit()?;
    }
    Ok((name, used))
}

async fn ram_setup(cx: &Cx, cur: &mut Cursor<'_>, ctx: &RamCtx) -> Result<RamSetup> {
    if ctx.mapped {
        return mapped_walk(cx, cur, ctx, false).await;
    }
    let at = cur.pos();
    let span = cur.region().sub(at, SETUP_MAX);
    let block = Block {
        span,
        data: cx.read_avail(span).await?,
    };
    let mut f = Fields::new(&block, BE);
    let setup = ram_setup_layout(&mut f, ctx)?;
    cx.charge(f.pos() / 64).await;
    cur.seek(at.saturating_add(f.pos()));
    Ok(setup)
}

// --- mapped-ram ---------------------------------------------------------------

/// The `MappedRamHeader` after each block of a `mapped-ram` RAM setup
/// (QEMU `migration/ram.c`, `docs/devel/migration/mapped-ram.rst`): its
/// version, the target page size, and where in the file the block's page
/// bitmap and pages are. The stream goes on after the block's pages, at
/// the pages' offset plus the block's used length.
fn mapped_header(f: &mut Fields<'_>, _: &()) -> Result<(u64, u64, u64)> {
    f.u32("Version").emit()?;
    let page = f.u64("Page size").emit()?;
    let bitmap = f.u64("Bitmap offset").hex().emit()?;
    let pages = f.u64("Pages offset").hex().emit()?;
    Ok((page, bitmap, pages))
}

const MAPPED_HEADER: u64 = 28;

/// Walks a `mapped-ram` RAM setup, whose blocks are spread over the file,
/// leaving the cursor after its end flags; with `emit`, pushes a node per
/// field and block. The headers give file offsets: the first header's
/// bitmap offset, which is where that header ends, places the stream in
/// its file.
async fn mapped_walk(cx: &Cx, cur: &mut Cursor<'_>, ctx: &RamCtx, emit: bool) -> Result<RamSetup> {
    let region = cur.region();
    let mask = ctx.page.saturating_sub(1);
    let at = cur.pos();
    let first = cur.u64().await?;
    if first & mask != F_MEM_SIZE {
        return Err(Diagnostic::malformed(format!(
            "RAM setup does not start with MEM_SIZE (flags {:#x})",
            first & mask
        ))
        .at(region.sub(at, 8)));
    }
    let total = first & !mask;
    if emit {
        cx.push(
            Node::new("Total RAM")
                .span(region.sub(at, 8))
                .value(Value::UInt {
                    value: total,
                    bits: 64,
                    radix: Radix::Hex,
                })
                .summary(size(total)),
        )
        .await;
    }
    let mut seen = 0u64;
    let mut blocks = 0usize;
    // File offset minus region offset, from the first header.
    let mut base: Option<u64> = None;
    while seen < total {
        let start = cur.pos();
        let n = cur.u8().await?;
        let name = crate::text::latin1(&cur.bytes(n.into()).await?);
        let used = cur.u64().await?;
        if ctx.ignore_shared {
            cur.skip(8);
        }
        let hstart = cur.pos();
        let hspan = region.sub_exact(hstart, MAPPED_HEADER)?;
        let block = Block {
            span: hspan,
            data: cx.read(hspan).await?,
        };
        let (_, bitmap, pages) = mapped_header(&mut Fields::new(&block, BE), &())?;
        let hend = hstart.saturating_add(MAPPED_HEADER);
        let delta = *base.get_or_insert(bitmap.saturating_sub(hend));
        let rel = |off: u64| {
            off.checked_sub(delta)
                .filter(|&r| r >= hend)
                .ok_or_else(|| {
                    Diagnostic::malformed(format!("mapped-ram offset {off:#x} before its header"))
                        .at(hspan)
                })
        };
        let (bitmap, pages) = (rel(bitmap)?, rel(pages)?);
        let npages = used.checked_div(ctx.page).unwrap_or(0);
        let bitmap_len = npages.div_ceil(64).saturating_mul(8);
        let end = pages.saturating_add(used);
        if end > region.len {
            return Err(Diagnostic::truncated(
                Span::new(region.source, region.offset.saturating_add(pages), used),
                region.len.saturating_sub(pages),
            ));
        }
        if emit {
            let state = (
                region.sub(start, hstart.saturating_sub(start)),
                hspan,
                region.sub(bitmap, bitmap_len),
                region.sub(pages, used),
                ctx.clone(),
            );
            cx.push(
                Node::new(name)
                    .span(region.sub(start, end.saturating_sub(start)))
                    .summary(size(used))
                    .lazy(mapped_block, state),
            )
            .await;
        }
        cur.seek(end);
        seen = seen.saturating_add(used);
        blocks = blocks.saturating_add(1);
        if used == 0 && blocks > 4096 {
            return Err(Diagnostic::limit("too many empty RAM blocks").at(region.sub(start, 0)));
        }
    }
    loop {
        let at = cur.pos();
        let v = cur.u64().await?;
        if emit {
            cx.push(
                Node::new("Flags")
                    .span(region.sub(at, 8))
                    .value(Value::UInt {
                        value: v,
                        bits: 64,
                        radix: Radix::Hex,
                    }),
            )
            .await;
        }
        if v & mask == F_EOS {
            break;
        }
        if v & mask != F_FLUSH {
            return Err(Diagnostic::malformed(format!(
                "unexpected flags {:#x} after the RAM block list",
                v & mask
            ))
            .at(region.sub(at, 8)));
        }
    }
    Ok(RamSetup { total, blocks })
}

/// The blocks of a `mapped-ram` RAM setup.
async fn mapped_blocks(cx: Cx, sec: Section) -> Result<()> {
    let mut cur = Cursor::new(&cx, sec.walk.region, BE);
    cur.seek(sec.payload);
    mapped_walk(&cx, &mut cur, &sec.ram, true).await?;
    Ok(())
}

/// One block of a `mapped-ram` RAM setup: its ID and length, its header,
/// its page bitmap and its pages (the block's memory; pages never written
/// read as zeros).
async fn mapped_block(
    cx: Cx,
    (fields, header, bitmap, pages, ctx): (Span, Span, Span, Span, RamCtx),
) -> Result<()> {
    cx.emit(struct_node("Block", fields, BE, ctx, ram_block));
    cx.emit(struct_node(
        "Mapped-ram header",
        header,
        BE,
        (),
        mapped_header,
    ));
    cx.emit(
        Node::new("Page bitmap")
            .span(bitmap)
            .summary(format!("{}, a bit per page", plural(bitmap.len, "byte"))),
    );
    cx.emit(Node::new("Pages").span(pages).summary(size(pages.len)));
    Ok(())
}

/// Page counts of a RAM part, by kind.
#[derive(Clone, Debug, Default)]
struct Counts {
    zero: u64,
    data: u64,
    xbzrle: u64,
    compressed: u64,
}

impl Counts {
    fn describe(&self) -> String {
        let mut parts = Vec::new();
        for (n, what) in [
            (self.zero, "zero"),
            (self.data, "data"),
            (self.xbzrle, "XBZRLE"),
            (self.compressed, "compressed"),
        ] {
            if n > 0 {
                parts.push(format!("{n} {what}"));
            }
        }
        if parts.is_empty() {
            "no pages".into()
        } else {
            format!("{} pages", parts.join(", "))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Zero,
    Data,
    Xbzrle,
    Compressed,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Zero => "zero",
            Kind::Data => "data",
            Kind::Xbzrle => "XBZRLE",
            Kind::Compressed => "compressed",
        }
    }
}

/// One record of a RAM part.
enum Rec {
    Page {
        kind: Kind,
        addr: u64,
        /// The fill byte of a zero page, or the page's encoded data.
        fill: u8,
        data: Span,
    },
    Flush,
    Eos,
}

/// Reads one page record; `block` is the block of the previous record
/// (for `CONTINUE`).
async fn ram_record(cur: &mut Cursor<'_>, ctx: &RamCtx, block: &mut String) -> Result<Rec> {
    let start = cur.pos();
    let v = cur.u64().await?;
    let mask = ctx.page.saturating_sub(1);
    let flags = v & mask;
    let addr = v & !mask;
    let kind = match flags & !F_CONTINUE {
        F_EOS => return Ok(Rec::Eos),
        F_FLUSH => return Ok(Rec::Flush),
        F_ZERO => Kind::Zero,
        F_PAGE => Kind::Data,
        F_XBZRLE => Kind::Xbzrle,
        F_COMPRESS => Kind::Compressed,
        F_HOOK => {
            return Err(Diagnostic::unsupported("RDMA hook records").at(cur.since(start)));
        }
        other => {
            return Err(
                Diagnostic::malformed(format!("RAM record flags {other:#x}")).at(cur.since(start)),
            );
        }
    };
    if flags & F_CONTINUE == 0 {
        let n = cur.u8().await?;
        *block = crate::text::latin1(&cur.bytes(n.into()).await?);
    } else if block.is_empty() {
        return Err(Diagnostic::malformed("CONTINUE without a previous block").at(cur.since(start)));
    }
    let (fill, len) = match kind {
        Kind::Zero => (cur.u8().await?, 0),
        Kind::Data => (0, ctx.page),
        Kind::Xbzrle => {
            let enc = cur.u8().await?;
            if enc != 1 {
                return Err(
                    Diagnostic::malformed(format!("XBZRLE encoding {enc:#x}")).at(cur.since(start))
                );
            }
            (0, u64::from(cur.u16().await?))
        }
        Kind::Compressed => (0, u64::from(cur.u32().await?)),
    };
    let data = cur.span(len);
    if data.len < len {
        return Err(Diagnostic::truncated(
            Span::new(data.source, data.offset, len),
            data.len,
        ));
    }
    cur.skip(len);
    Ok(Rec::Page {
        kind,
        addr,
        fill,
        data,
    })
}

/// Counts a RAM part's pages, leaving the cursor after its end flags.
async fn ram_count(
    cx: &Cx,
    cur: &mut Cursor<'_>,
    ctx: &RamCtx,
    block: &mut String,
) -> Result<Counts> {
    let region = cur.region();
    let mut counts = Counts::default();
    let mut n = 0u32;
    loop {
        n = n.wrapping_add(1);
        if n.is_multiple_of(4096) {
            cx.progress_in(region, region.offset.saturating_add(cur.pos()));
        }
        match ram_record(cur, ctx, block).await? {
            Rec::Eos => break,
            Rec::Flush => {}
            Rec::Page { kind, .. } => {
                let c = match kind {
                    Kind::Zero => &mut counts.zero,
                    Kind::Data => &mut counts.data,
                    Kind::Xbzrle => &mut counts.xbzrle,
                    Kind::Compressed => &mut counts.compressed,
                };
                *c = c.saturating_add(1);
            }
        }
    }
    Ok(counts)
}

/// A run of contiguous pages of one kind in one block.
struct Run {
    kind: Kind,
    block: String,
    first: u64,
    count: u64,
    start: u64,
    end: u64,
    fills: bool,
}

/// Lists a RAM part as runs of pages.
async fn page_runs(cx: Cx, sec: Section) -> Result<()> {
    let region = sec.walk.region;
    let mut cur = Cursor::new(&cx, region, BE);
    let (pos, mut block) = cx
        .resume::<(u64, String)>()
        .unwrap_or_else(|| (sec.payload, sec.block.clone()));
    cur.seek(pos);
    let page = sec.ram.page;
    let mut run: Option<Run> = None;
    while cur.pos() < sec.payload_end {
        let start = cur.pos();
        if run.is_none() {
            cx.mark(|| (start, block.clone()));
        }
        cx.progress_in(region, region.offset.saturating_add(start));
        let rec = ram_record(&mut cur, &sec.ram, &mut block).await?;
        let end = cur.pos();
        let (kind, addr, fill) = match rec {
            Rec::Page {
                kind, addr, fill, ..
            } => (kind, addr, fill),
            Rec::Flush | Rec::Eos => {
                if let Some(r) = run.take() {
                    cx.push(run_node(&sec, r)).await;
                }
                let name = if matches!(rec, Rec::Eos) {
                    "End of section"
                } else {
                    "Multifd flush"
                };
                cx.push(Node::new(name).span(region.sub(start, 8)).value(
                    crate::formats::util::val::flagsv(
                        if matches!(rec, Rec::Eos) {
                            F_EOS
                        } else {
                            F_FLUSH
                        },
                        16,
                        RAM_FLAGS,
                    ),
                ))
                .await;
                if matches!(rec, Rec::Eos) {
                    break;
                }
                continue;
            }
        };
        let extends = run.as_ref().is_some_and(|r| {
            r.kind == kind
                && r.block == block
                && r.first.saturating_add(r.count.saturating_mul(page)) == addr
        });
        if extends {
            if let Some(r) = run.as_mut() {
                r.count = r.count.saturating_add(1);
                r.end = end;
                r.fills |= fill != 0;
            }
            continue;
        }
        if let Some(r) = run.take() {
            cx.push(run_node(&sec, r)).await;
            cx.mark(|| (start, block.clone()));
        }
        run = Some(Run {
            kind,
            block: block.clone(),
            first: addr,
            count: 1,
            start,
            end,
            fills: fill != 0,
        });
    }
    if let Some(r) = run.take() {
        cx.push(run_node(&sec, r)).await;
    }
    Ok(())
}

fn run_node(sec: &Section, r: Run) -> Node {
    let page = sec.ram.page;
    let last = r
        .first
        .saturating_add(r.count.saturating_mul(page))
        .saturating_sub(1);
    let span = sec.span(r.start, r.end);
    let mut node = Node::new(format!("{} {:#x}", r.block, r.first))
        .span(span)
        .summary(format!(
            "{:#x}–{last:#x}, {} {} {} ({})",
            r.first,
            r.count,
            r.kind.name(),
            if r.count == 1 { "page" } else { "pages" },
            size(r.count.saturating_mul(page))
        ));
    if r.fills {
        node = node.diag(Diagnostic::note(
            "zero-page records with a non-zero fill byte (pages filled with that byte)",
        ));
    }
    if r.kind != Kind::Zero || r.fills {
        node = node.lazy(run_pages, (sec.clone(), r.start, r.end, r.block));
    }
    node
}

/// The pages of one run.
async fn run_pages(cx: Cx, (sec, start, end, block): (Section, u64, u64, String)) -> Result<()> {
    let region = sec.walk.region;
    let mut cur = Cursor::new(&cx, region, BE);
    // All pages of a run are in one block (which its first record may
    // name only by continuing it).
    let mut block = block;
    cur.seek(cx.resume::<u64>().unwrap_or(start));
    while cur.pos() < end {
        let rstart = cur.pos();
        cx.mark(|| rstart);
        let Rec::Page {
            kind,
            addr,
            fill,
            data,
        } = ram_record(&mut cur, &sec.ram, &mut block).await?
        else {
            break;
        };
        let name = format!("{addr:#x}");
        let span = cur.since(rstart);
        let node = match kind {
            Kind::Zero => Node::new(name)
                .span(span)
                .summary(format!("filled with {fill:#04x}")),
            Kind::Data => Node::new(name).span(span).target(data).summary("data"),
            Kind::Xbzrle => Node::new(name)
                .span(span)
                .target(data)
                .summary(format!("XBZRLE delta, {}", plural(data.len, "byte"))),
            Kind::Compressed => {
                content(name, sec.walk.input, data, Codec::Zlib, Some(sec.ram.page))
                    .summary(format!("zlib, {}", plural(data.len, "byte")))
            }
        };
        cx.push(node).await;
    }
    Ok(())
}

// --- Device state and the VM description -----------------------------------

/// One VMState structure as the VM description records it.
#[derive(Debug)]
struct SDesc {
    name: String,
    version: u64,
    fields: Vec<FDesc>,
    subs: Vec<Arc<SDesc>>,
    /// Bytes it takes in the stream, subsections included.
    total: u64,
}

#[derive(Debug)]
struct FDesc {
    name: String,
    ty: String,
    /// Size of one element.
    size: u64,
    count: u64,
    /// A nested structure (whose size matches `size`).
    nested: Option<Arc<SDesc>>,
}

#[derive(Debug)]
struct Dev {
    name: String,
    instance: u64,
    desc: Arc<SDesc>,
    total: u64,
}

#[derive(Debug)]
struct VmDesc {
    devices: Vec<Dev>,
    /// The target page size (`page_size`).
    page_size: Option<u64>,
}

impl VmDesc {
    fn device(&self, name: &str, instance: u32) -> Option<&Dev> {
        self.devices
            .iter()
            .find(|d| d.name == name && d.instance == u64::from(instance))
    }
}

const JSON_MAX: u64 = 16 * 1024 * 1024;

/// Finds the VM description at the end of the stream: scanning back from
/// the end over the JSON text (which has no control bytes) to its
/// big-endian length and `QEMU_VM_VMDESCRIPTION`.
async fn locate_vmdesc(cx: &Cx, stream: Span) -> Result<Option<Span>> {
    const STEP: u64 = 0x10000;
    let end = stream.len;
    let mut hi = end;
    let floor = end.saturating_sub(JSON_MAX);
    while hi > floor {
        let lo = hi.saturating_sub(STEP).max(floor);
        let buf = cx.read_avail(stream.sub(lo, hi.saturating_sub(lo))).await?;
        let found = buf
            .iter()
            .rposition(|&b| b < 0x20 && !matches!(b, b'\n' | b'\r' | b'\t'));
        cx.charge(16).await;
        if let Some(i) = found {
            // A byte of the length or the marker itself: the length's
            // other bytes may be anything, so try each place the marker
            // can be.
            let last = lo.saturating_add(to_u64(i));
            let from = last.saturating_sub(4);
            let head = cx.read_avail(stream.sub(from, 10)).await?;
            for k in 0..5usize {
                let marker = from.saturating_add(to_u64(k));
                if marker > last {
                    break;
                }
                let json_at = marker.saturating_add(5);
                let len = u32_be(&head, k.saturating_add(1)).map(u64::from);
                if head.get(k) == Some(&T_VMDESC)
                    && head.get(k.saturating_add(5)) == Some(&b'{')
                    && len == Some(end.saturating_sub(json_at))
                {
                    return Ok(Some(stream.sub(json_at, end.saturating_sub(json_at))));
                }
            }
            return Ok(None);
        }
        hi = lo;
    }
    Ok(None)
}

/// The parsed VM description of `stream`, if it has one (cached).
async fn vmdesc(cx: &Cx, stream: Span) -> Result<Option<Arc<VmDesc>>> {
    if let Some(d) = cx.cached::<Option<Arc<VmDesc>>>(stream, "qemu-vmdesc") {
        return Ok((*d).clone());
    }
    let parsed = match locate_vmdesc(cx, stream).await? {
        Some(span) => {
            let data = cx.read(span).await?;
            match json::parse(cx, &data).await {
                Ok(j) => {
                    let mut nodes = 0u64;
                    let desc = build_vmdesc(&j, &mut nodes);
                    cx.charge(nodes / 16).await;
                    desc.map(Arc::new)
                }
                Err(_) => None,
            }
        }
        None => None,
    };
    cx.cache(stream, "qemu-vmdesc", Arc::new(parsed.clone()));
    Ok(parsed)
}

fn build_vmdesc(j: &Json, nodes: &mut u64) -> Option<VmDesc> {
    let devices = j.get("devices")?.as_array()?;
    let mut out = Vec::new();
    for d in devices {
        let Some(name) = d.get("name").and_then(Json::as_str) else {
            continue;
        };
        let instance = d.get("instance_id").and_then(Json::as_u64).unwrap_or(0);
        let desc = build_struct(d, nodes, 0);
        let total = desc.total;
        out.push(Dev {
            name: name.to_owned(),
            instance,
            desc: Arc::new(desc),
            total,
        });
    }
    let page_size = j.get("page_size").and_then(Json::as_u64);
    Some(VmDesc {
        devices: out,
        page_size,
    })
}

fn build_struct(j: &Json, nodes: &mut u64, depth: u32) -> SDesc {
    *nodes = nodes.saturating_add(1);
    let mut s = SDesc {
        name: j
            .get("vmsd_name")
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_owned(),
        version: j.get("version").and_then(Json::as_u64).unwrap_or(0),
        fields: Vec::new(),
        subs: Vec::new(),
        total: 0,
    };
    if depth > 32 {
        return s;
    }
    let child = depth.saturating_add(1);
    for f in j.get("fields").and_then(Json::as_array).unwrap_or_default() {
        *nodes = nodes.saturating_add(1);
        let size = f.get("size").and_then(Json::as_u64).unwrap_or(0);
        let count = f.get("array_len").and_then(Json::as_u64).unwrap_or(1);
        // Nested structures: `struct`, or the fields inline (`tmp`).
        let nested = match (f.get("struct"), f.get("fields")) {
            (Some(n), _) => Some(build_struct(n, nodes, child)),
            (None, Some(_)) => Some(build_struct(f, nodes, child)),
            _ => None,
        }
        .filter(|n| n.total == size)
        .map(Arc::new);
        s.total = s.total.saturating_add(size.saturating_mul(count));
        s.fields.push(FDesc {
            name: f
                .get("name")
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_owned(),
            ty: f
                .get("type")
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_owned(),
            size,
            count,
            nested,
        });
    }
    for sub in j
        .get("subsections")
        .and_then(Json::as_array)
        .unwrap_or_default()
    {
        let sub = build_struct(sub, nodes, child);
        // Marker, name length, name, version.
        let head = 6u64.saturating_add(to_u64(sub.name.len()));
        s.total = s.total.saturating_add(head).saturating_add(sub.total);
        s.subs.push(Arc::new(sub));
    }
    s
}

async fn device_state(cx: Cx, sec: Section) -> Result<()> {
    let stream = sec.walk.stream;
    let last = stream.sub(stream.len.saturating_sub(1), 1);
    if far::is_far(&cx, last) {
        let payload = sec.span(sec.payload, sec.payload_end);
        cx.emit(Node::new("Data").span(payload));
        cx.emit(far::deferred(
            "Fields",
            payload,
            "named by the VM description at the end of the stream",
            device_fields,
            sec,
        ));
        return Ok(());
    }
    device_fields(cx, sec).await
}

async fn device_fields(cx: Cx, sec: Section) -> Result<()> {
    let payload = sec.span(sec.payload, sec.payload_end);
    let desc = vmdesc(&cx, sec.walk.stream).await?;
    let Some(desc) = desc else {
        cx.emit(Node::new("Data").span(payload).diag(Diagnostic::note(
            "no VM description: the layout of device state is not in the stream",
        )));
        return Ok(());
    };
    match desc.device(&sec.idstr, sec.instance) {
        Some(dev) if dev.total == payload.len => {
            cx.annotate(format!("{} version {}", dev.desc.name, dev.desc.version));
            vm_fields(cx, (payload, dev.desc.clone())).await
        }
        Some(dev) => {
            cx.emit(
                Node::new("Data")
                    .span(payload)
                    .diag(Diagnostic::warning(format!(
                        "the VM description gives {} bytes, the section holds {}",
                        dev.total, payload.len
                    ))),
            );
            Ok(())
        }
        None => {
            cx.emit(Node::new("Data").span(payload).diag(Diagnostic::note(
                "the VM description does not list this section",
            )));
            Ok(())
        }
    }
}

/// The fields of one structure, then its subsections.
async fn vm_fields(cx: Cx, (span, desc): (Span, Arc<SDesc>)) -> Result<()> {
    let mut pos = 0u64;
    for (i, f) in desc.fields.iter().enumerate() {
        let len = f.size.saturating_mul(f.count);
        let fspan = span.sub(pos, len);
        let node = if f.count > 1 {
            Node::new(f.name.clone())
                .span(fspan)
                .summary(format!("{} × {}", f.count, f.ty))
                .lazy(
                    crate::expander!(self::vm_array: (Span, Arc<SDesc>, usize)),
                    (fspan, desc.clone(), i),
                )
        } else {
            field_node(&cx, f, f.name.clone(), fspan).await?
        };
        cx.push(node).await;
        pos = pos.saturating_add(len);
    }
    for sub in &desc.subs {
        let len = 6u64
            .saturating_add(to_u64(sub.name.len()))
            .saturating_add(sub.total);
        let sspan = span.sub(pos, len);
        cx.push(
            Node::new(format!("Subsection {}", sub.name))
                .span(sspan)
                .summary(format!("version {}", sub.version))
                .lazy(
                    crate::expander!(self::vm_sub: (Span, Arc<SDesc>)),
                    (sspan, sub.clone()),
                ),
        )
        .await;
        pos = pos.saturating_add(len);
    }
    Ok(())
}

async fn vm_array(cx: Cx, (span, desc, i): (Span, Arc<SDesc>, usize)) -> Result<()> {
    let Some(f) = desc.fields.get(i) else {
        return Ok(());
    };
    let mut pos = 0u64;
    // Zero-sized elements take no bytes: show a few.
    let count = if f.size == 0 {
        f.count.min(64)
    } else {
        f.count
    };
    for k in 0..count {
        if pos >= span.len && f.size > 0 {
            break;
        }
        let espan = span.sub(pos, f.size);
        cx.push(field_node(&cx, f, format!("[{k}]"), espan).await?)
            .await;
        pos = pos.saturating_add(f.size);
    }
    Ok(())
}

async fn vm_sub(cx: Cx, (span, desc): (Span, Arc<SDesc>)) -> Result<()> {
    let head_len = 6u64.saturating_add(to_u64(desc.name.len()));
    let block = cx.block(span.sub(0, head_len)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u8("Marker").enumeration(SECTION_TYPES).emit()?;
    let n = f.u8("Name length").emit()?;
    let name = f.ascii("Name", n.into()).emit()?;
    f.u32("Version").emit()?;
    if name != desc.name {
        cx.diag(Diagnostic::warning(format!(
            "subsection {name}, the VM description has {}",
            desc.name
        )));
    }
    vm_fields(cx, (span.sub(head_len, desc.total), desc)).await
}

async fn field_node(cx: &Cx, f: &FDesc, name: String, span: Span) -> Result<Node> {
    if let Some(nested) = &f.nested {
        return Ok(Node::new(name)
            .span(span)
            .summary(nested.name.clone())
            .lazy(
                crate::expander!(self::vm_fields: (Span, Arc<SDesc>)),
                (span, nested.clone()),
            ));
    }
    let node = Node::new(name).span(span);
    let ty = f.ty.as_str();
    if ty == "unused_buffer" {
        return Ok(node.summary(format!("unused, {}", plural(f.size, "byte"))));
    }
    // Buffers that hold a NUL-padded string (`globalstate.runstate`,
    // `configuration.name`) are shown as text.
    if ty == "buffer" && f.size <= BUFFER_TEXT_MAX {
        let raw = cx.read(span).await?;
        if let Some(s) = padded_text(&raw) {
            return Ok(node.value(text(s)).summary(ty.to_owned()));
        }
    }
    if f.size > 16 {
        return Ok(node.summary(format!("{ty}, {}", size(f.size))));
    }
    let raw = cx.read(span).await?;
    let be = crate::formats::util::datakit::be_uint(&raw);
    let bits = u8::try_from(raw.len().saturating_mul(8)).unwrap_or(64);
    let whole = to_u64(raw.len()) == f.size;
    let int_size = matches!(f.size, 1 | 2 | 4 | 8) && whole;
    Ok(if ty == "bool" && f.size == 1 && whole {
        node.value(Value::Bool(be != 0))
    } else if int_size && (ty.starts_with("int") || ty == "timer") {
        let shift = 64u32.saturating_sub(u32::from(bits));
        let signed = i64::from_ne_bytes(be.to_ne_bytes())
            .checked_shl(shift)
            .and_then(|v| v.checked_shr(shift))
            .unwrap_or(0);
        let node = node.value(int(signed, bits));
        if ty == "int32" || ty == "int64" || ty == "int8" || ty == "int16" {
            node
        } else {
            node.summary(ty.to_owned())
        }
    } else if int_size && ty.starts_with("uint") {
        let node = node.value(if bits == 64 {
            crate::formats::util::val::hex(be, bits)
        } else {
            uint(be, bits)
        });
        if ty.contains(' ') {
            node.summary(ty.to_owned())
        } else {
            node
        }
    } else if ty == "float64" && f.size == 8 && whole {
        node.value(Value::f64(f64::from_bits(be)))
    } else {
        node.value(Value::Bytes(raw)).summary(ty.to_owned())
    })
}

/// Largest `buffer` field checked for a string.
const BUFFER_TEXT_MAX: u64 = 256;

/// The string in a NUL-padded buffer: printable ASCII up to the first NUL,
/// only NULs after it.
fn padded_text(raw: &[u8]) -> Option<String> {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let (s, rest) = raw.split_at_checked(end)?;
    (!s.is_empty() && s.iter().all(|&b| (0x20..0x7f).contains(&b)) && rest.iter().all(|&b| b == 0))
        .then(|| String::from_utf8_lossy(s).into_owned())
}

// ---------------------------------------------------------------------------
// libvirt save image

declare_format!(pub LIBVIRT_SAVE = "libvirt-save", "libvirt saved domain (virsh save)", ["sav", "save"], "application/x-libvirt-save",
    Probe::Magic(&[(0, b"LibvirtQemudSave"), (0, b"LibvirtQemudPart")]), libvirt);

const LIBVIRT_HEADER: u64 = 92;

const SAVE_FORMATS: EnumTable = &[
    (0, "raw"),
    (1, "gzip"),
    (2, "bzip2"),
    (3, "xz"),
    (4, "lzop"),
    (5, "zstd"),
    (6, "sparse"),
];

fn libvirt_header(f: &mut Fields<'_>, _: &()) -> Result<(u32, u32, u32)> {
    f.ascii("Magic", 16).emit()?;
    f.u32("Version").emit()?;
    let data_len = f
        .u32("Data length")
        .desc("Domain XML, cookie and padding before the migration stream")
        .emit()?;
    f.u32("Was running")
        .with(|&v, node: Node| node.value(Value::Bool(v != 0)))
        .emit()?;
    let format = f.u32("Image format").enumeration(SAVE_FORMATS).emit()?;
    let cookie = f
        .u32("Cookie offset")
        .desc("Where the migration cookie XML starts in the data (0: none)")
        .emit()?;
    f.bytes("Unused", 56).emit()?;
    Ok((data_len, format, cookie))
}

async fn libvirt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, LIBVIRT_HEADER);
    let head = cx.read(hspan).await?;
    // Written in the host's byte order: version 1 or 2 tells which.
    let endian = if u32_le(&head, 16).is_some_and(|v| v <= 0xffff) {
        LE
    } else {
        BE
    };
    let block = Block {
        span: hspan,
        data: head.clone(),
    };
    let (data_len, format, cookie) = libvirt_header(&mut Fields::new(&block, endian), &())?;
    let mut hnode = struct_node("Header", hspan, endian, (), libvirt_header);
    let partial = head.get(..16) == Some(b"LibvirtQemudPart");
    if partial {
        hnode = hnode.diag(Diagnostic::warning(
            "LibvirtQemudPart: the save did not complete",
        ));
    }
    cx.emit(hnode);
    let data = file.sub(LIBVIRT_HEADER, data_len.into());
    let raw = cx.read(data.sub(0, 1 << 20)).await?;
    let xml_end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let xml_end = if cookie > 0 {
        xml_end.min(crate::bytes::to_usize(cookie.into()))
    } else {
        xml_end
    };
    let xml = data.sub(0, to_u64(xml_end));
    let name = crate::text::latin1(raw.get(..xml_end.min(4096)).unwrap_or_default());
    let domain = name
        .split_once("<name>")
        .and_then(|(_, r)| r.split_once("</name>"))
        .map(|(n, _)| n.trim().to_owned());
    cx.emit(embedded_as(
        "Domain XML",
        input.nested(xml),
        &crate::formats::text::xml::FORMAT,
    ));
    let mut used = xml.len;
    if cookie > 0 {
        let c = u64::from(cookie);
        let rest = raw.get(crate::bytes::to_usize(c)..).unwrap_or_default();
        let len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        let cookie = data.sub(c, to_u64(len));
        used = used.max(c.saturating_add(cookie.len));
        cx.emit(embedded_as(
            "Migration cookie",
            input.nested(cookie),
            &crate::formats::text::xml::FORMAT,
        ));
    }
    // The rest of the data: the XML's terminating NUL and the zeros libvirt
    // reserves for the XML to grow (64 KiB in the fixtures).
    let padding = data.tail(used);
    if padding.len > 0 {
        cx.emit(
            Node::new("Padding")
                .span(padding)
                .summary(plural(padding.len, "byte")),
        );
    }
    if data.len < u64::from(data_len) {
        cx.diag(Diagnostic::truncated(
            Span::new(data.source, data.offset, data_len.into()),
            data.len,
        ));
        return Ok(());
    }
    let stream = file.tail(LIBVIRT_HEADER.saturating_add(data_len.into()));
    let fmt = crate::formats::util::val::name_or(SAVE_FORMATS, format.into(), "format");
    let codec = match format {
        // sparse: an uncompressed `mapped-ram` stream (pages at fixed offsets).
        0 | 6 => Some(Codec::Stored),
        1 => Some(Codec::Gzip),
        2 => Some(Codec::Bzip2),
        3 => Some(Codec::Xz),
        4 => Some(Codec::Lzop),
        5 => Some(Codec::Zstd),
        _ => None,
    };
    match codec {
        Some(Codec::Stored) => cx.emit(embedded_as(
            "Migration stream",
            input.nested(stream),
            &QEMU_VMSTATE,
        )),
        Some(codec) => cx.emit(
            content("Migration stream", input, stream, codec, None)
                .summary(format!("{fmt}-compressed")),
        ),
        None => cx.emit(
            Node::new("Migration stream")
                .span(stream)
                .diag(Diagnostic::unsupported(format!("save image format {fmt}")).at(stream)),
        ),
    }
    let mut label = String::from("libvirt saved domain");
    if let Some(d) = domain {
        label.push_str(&format!(" '{}'", clip(&d, 60)));
    }
    label.push_str(&format!(", {fmt} QEMU state"));
    if partial {
        label.push_str(" (incomplete)");
    }
    cx.annotate(label);
    Ok(())
}
