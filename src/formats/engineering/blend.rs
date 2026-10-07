//! Blender `.blend` files.
//!
//! The layout below is from memory of Blender's reader and writer
//! (`readfile`, `writefile`, `makesdna`, `dna_genfile`); no specification
//! or real file was at hand, so the fixtures are our own (see
//! `tests/data/blend/make_blend.py`).
//!
//! - **File header**: `BLENDER`, the pointer size (`_` 4 bytes, `-` 8
//!   bytes), the byte order (`v` little, `V` big) and the version as three
//!   digits (`293` is 2.93). Blender 5 writes a 17-byte header instead:
//!   `BLENDER`, the header size (`17`), the pointer size character, a
//!   file-format version (`01`), the byte order and a four-digit version
//!   (`0500`); its block headers are the 32-byte "large" form.
//! - **File blocks** follow until `ENDB`: a four-byte code, then (classic)
//!   the data length (int32), the block's address when written (pointer
//!   sized, the "old address" other blocks' pointers refer to), the index
//!   of its struct in the SDNA and the number of structs; or (large) the
//!   code, SDNA index (int32), old address (uint64), length (int64) and
//!   count (int64). Codes with two letters and two NULs (`OB`, `ME`, ...)
//!   start an ID datablock, whose struct begins with `ID id`, whose
//!   `name` begins with the code.
//! - **DNA1** holds the SDNA catalogue that makes the rest interpretable:
//!   `SDNA`, then `NAME` (count, NUL-terminated field declarators like
//!   `*next` or `obmat[4][4]`), `TYPE` (count, type names), `TLEN` (an
//!   int16 size per type) and `STRC` (count, then per struct its type and
//!   field count, and per field a type and a name index), each section
//!   aligned to four bytes. Structs carry their padding explicitly, so field
//!   offsets are running sums: pointers (`*` or `(*`) take the pointer size,
//!   everything else the type size, times the array dimensions.
//! - **TEST** is the thumbnail: width and height (int32), then RGBA pixels,
//!   rows bottom to top. **REND** has the start and end frame (int32) and
//!   the scene name. **GLOB** is a `FileGlobal` struct.
//! - Blender 3.0 and later compress the whole file with Zstandard (seekable
//!   frames) when compression is on; older versions used gzip. Such files
//!   are identified as zstd or gzip and the decompressed file is
//!   recognised inside; when one is opened as Blender explicitly, the
//!   decompressed file is offered as a child.
//!
//! Struct instances are shown by walking the SDNA definition: scalars as
//! numbers, `char` arrays as text, pointers as old addresses resolved to
//! the block (and offset) they point into, nested structs and arrays
//! lazily. Data a block's size does not account for (pointer arrays and
//! other raw data written with struct 0) is left raw.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, Prim, struct_node};
use crate::formats::{Codec, Head, Input, Probe, content, embedded_as};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{Radix, Value};

declare_format!(pub FORMAT = "blend", "Blender scene", ["blend"], "application/x-blender",
    Probe::Custom(probe), dissect);

/// Blocks listed at most; files have thousands, not millions.
const MAX_BLOCKS: usize = 1 << 22;
/// How deeply struct members nest by value.
const MAX_DEPTH: usize = 32;
/// Elements previewed in an array's summary.
const PREVIEW: u64 = 16;

fn probe(h: &Head<'_>) -> bool {
    header(h.data).is_some()
}

#[derive(Clone, Copy, Debug)]
struct Layout {
    header: u64,
    pointer: u64,
    endian: Endian,
    large: bool,
    version: u32,
}

impl Layout {
    fn bhead(&self) -> u64 {
        if self.large {
            32
        } else {
            16u64.saturating_add(self.pointer)
        }
    }

    fn version(&self) -> String {
        format!(
            "{}.{}",
            self.version.checked_div(100).unwrap_or(0),
            self.version.checked_rem(100).unwrap_or(0)
        )
    }
}

fn number(b: &[u8]) -> Option<u32> {
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(b).ok()?.parse().ok()
}

fn pointer_size(c: u8) -> Option<u64> {
    match c {
        b'_' => Some(4),
        b'-' => Some(8),
        _ => None,
    }
}

fn byte_order(c: u8) -> Option<Endian> {
    match c {
        b'v' => Some(Endian::Little),
        b'V' => Some(Endian::Big),
        _ => None,
    }
}

fn header(b: &[u8]) -> Option<Layout> {
    if b.get(..7)? != b"BLENDER" {
        return None;
    }
    if let Some(pointer) = pointer_size(*b.get(7)?) {
        return Some(Layout {
            header: 12,
            pointer,
            endian: byte_order(*b.get(8)?)?,
            large: false,
            version: number(b.get(9..12)?)?,
        });
    }
    if number(b.get(7..9)?)? != 17 {
        return None;
    }
    let pointer = pointer_size(*b.get(9)?)?;
    number(b.get(10..12)?)?;
    Some(Layout {
        header: 17,
        pointer,
        endian: byte_order(*b.get(12)?)?,
        large: true,
        version: number(b.get(13..17)?)?,
    })
}

/// ID codes: (code, singular, plural).
const ID_TYPES: &[(&[u8; 2], &str, &str)] = &[
    (b"SC", "scene", "scenes"),
    (b"LI", "library", "libraries"),
    (b"OB", "object", "objects"),
    (b"ME", "mesh", "meshes"),
    (b"CU", "curve", "curves"),
    (b"MB", "metaball", "metaballs"),
    (b"MA", "material", "materials"),
    (b"TE", "texture", "textures"),
    (b"IM", "image", "images"),
    (b"LT", "lattice", "lattices"),
    (b"LA", "light", "lights"),
    (b"CA", "camera", "cameras"),
    (b"IP", "IPO curve", "IPO curves"),
    (b"KE", "shape key", "shape keys"),
    (b"WO", "world", "worlds"),
    (b"SN", "screen", "screens"),
    (b"SR", "screen", "screens"),
    (b"PY", "script", "scripts"),
    (b"VF", "font", "fonts"),
    (b"TX", "text", "texts"),
    (b"SK", "speaker", "speakers"),
    (b"SO", "sound", "sounds"),
    (b"GR", "collection", "collections"),
    (b"AR", "armature", "armatures"),
    (b"AC", "action", "actions"),
    (b"NT", "node tree", "node trees"),
    (b"BR", "brush", "brushes"),
    (b"PA", "particle settings", "particle settings"),
    (b"GD", "grease pencil (legacy)", "grease pencils (legacy)"),
    (b"GP", "grease pencil", "grease pencils"),
    (b"WM", "window manager", "window managers"),
    (b"MC", "movie clip", "movie clips"),
    (b"MS", "mask", "masks"),
    (b"LS", "line style", "line styles"),
    (b"PL", "palette", "palettes"),
    (b"PC", "paint curve", "paint curves"),
    (b"CF", "cache file", "cache files"),
    (b"WS", "workspace", "workspaces"),
    (b"LP", "light probe", "light probes"),
    (b"CV", "curves", "curves"),
    (b"HA", "hair", "hair"),
    (b"PT", "point cloud", "point clouds"),
    (b"VO", "volume", "volumes"),
    (b"ID", "linked placeholder", "linked placeholders"),
];

/// Non-ID block codes and what they hold.
const BLOCK_KINDS: &[(&[u8; 4], &str)] = &[
    (b"DNA1", "struct definitions"),
    (b"ENDB", "end of file"),
    (b"GLOB", "global settings"),
    (b"REND", "render info"),
    (b"TEST", "thumbnail"),
    (b"USER", "user preferences"),
];

fn is_id(code: &[u8; 4]) -> bool {
    code[2] == 0 && code[3] == 0 && code[0].is_ascii_uppercase() && code[1].is_ascii_uppercase()
}

fn id_type(code: &[u8; 4]) -> Option<(&'static str, &'static str)> {
    ID_TYPES
        .iter()
        .find(|(c, ..)| c[..] == code[..2])
        .map(|&(_, one, many)| (one, many))
}

fn label(code: &[u8; 4]) -> String {
    let text = crate::text::until_nul(code);
    if text.chars().all(|c| c.is_ascii_graphic()) && !text.is_empty() {
        text
    } else {
        format!("{:#010x}", u32::from_be_bytes(*code))
    }
}

// ---------------------------------------------------------------------------
// SDNA

#[derive(Debug)]
struct Sdna {
    span: Span,
    pointer: u64,
    /// Field declarators and their offsets in the DNA1 data.
    names: Vec<(String, u64)>,
    types: Vec<(String, u64)>,
    tlen: Vec<u16>,
    tlen_at: u64,
    structs: Vec<SStruct>,
    /// The struct defining each type, if any.
    struct_of: Vec<Option<usize>>,
    /// (title, offset, length) of each section.
    sections: Vec<(&'static str, u64, u64)>,
}

#[derive(Debug)]
struct SStruct {
    ty: u16,
    fields: Vec<(u16, u16)>,
    at: u64,
}

#[derive(Clone, Debug)]
struct Member {
    ty: u16,
    name: u16,
    offset: u64,
    size: u64,
    pointer: bool,
    count: u64,
    /// Offset of the field's definition in the DNA1 data.
    def: u64,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    endian: Endian,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let b = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(b)
    }

    fn tag(&mut self, tag: &[u8; 4]) -> bool {
        self.take(4) == Some(tag)
    }

    fn u16(&mut self) -> Option<u16> {
        u16::decode(self.take(2)?, self.endian)
    }

    fn u32(&mut self) -> Option<u32> {
        u32::decode(self.take(4)?, self.endian)
    }

    fn cstr(&mut self) -> Option<String> {
        let rest = self.data.get(self.pos..)?;
        let len = rest.iter().position(|&b| b == 0)?;
        let text = String::from_utf8_lossy(rest.get(..len)?).into_owned();
        self.pos = self.pos.checked_add(len)?.checked_add(1)?;
        Some(text)
    }

    fn align(&mut self) {
        self.pos = self.pos.checked_next_multiple_of(4).unwrap_or(usize::MAX);
    }

    fn at(&self) -> u64 {
        to_u64(self.pos)
    }
}

impl Sdna {
    fn parse(data: &[u8], span: Span, endian: Endian, pointer: u64) -> Option<Sdna> {
        let mut r = Reader {
            data,
            pos: 0,
            endian,
        };
        let mut sections = Vec::new();
        if !r.tag(b"SDNA") {
            return None;
        }
        let strings = |r: &mut Reader<'_>, tag: &[u8; 4]| -> Option<Vec<(String, u64)>> {
            if !r.tag(tag) {
                return None;
            }
            let count = r.u32()?;
            let mut out = Vec::new();
            for _ in 0..count {
                let at = r.at();
                out.push((r.cstr()?, at));
            }
            r.align();
            Some(out)
        };
        let start = r.at();
        let names = strings(&mut r, b"NAME")?;
        sections.push(("Names", start, r.at().saturating_sub(start)));
        let start = r.at();
        let types = strings(&mut r, b"TYPE")?;
        sections.push(("Types", start, r.at().saturating_sub(start)));
        let start = r.at();
        if !r.tag(b"TLEN") {
            return None;
        }
        let tlen_at = r.at();
        let mut tlen = Vec::new();
        for _ in 0..types.len() {
            tlen.push(r.u16()?);
        }
        r.align();
        sections.push(("Type sizes", start, r.at().saturating_sub(start)));
        let start = r.at();
        if !r.tag(b"STRC") {
            return None;
        }
        let count = r.u32()?;
        let mut structs = Vec::new();
        let mut struct_of = vec![None; types.len()];
        for index in 0..count {
            let at = r.at();
            let ty = r.u16()?;
            let n = r.u16()?;
            let mut fields = Vec::new();
            for _ in 0..n {
                fields.push((r.u16()?, r.u16()?));
            }
            if let Some(slot @ None) = struct_of.get_mut(usize::from(ty)) {
                *slot = Some(to_usize(index.into()));
            }
            structs.push(SStruct { ty, fields, at });
        }
        sections.push(("Structs", start, r.at().saturating_sub(start)));
        Some(Sdna {
            span,
            pointer,
            names,
            types,
            tlen,
            tlen_at,
            structs,
            struct_of,
            sections,
        })
    }

    fn name(&self, n: u16) -> &str {
        self.names.get(usize::from(n)).map_or("?", |(s, _)| s)
    }

    fn type_name(&self, t: u16) -> &str {
        self.types.get(usize::from(t)).map_or("?", |(s, _)| s)
    }

    fn type_size(&self, t: u16) -> u64 {
        self.tlen.get(usize::from(t)).copied().map_or(0, u64::from)
    }

    fn struct_of(&self, t: u16) -> Option<usize> {
        self.struct_of.get(usize::from(t)).copied().flatten()
    }

    fn struct_name(&self, s: usize) -> &str {
        self.structs.get(s).map_or("?", |st| self.type_name(st.ty))
    }

    fn struct_size(&self, s: usize) -> u64 {
        self.structs.get(s).map_or(0, |st| self.type_size(st.ty))
    }

    fn find(&self, name: &str) -> Option<usize> {
        self.structs
            .iter()
            .position(|s| self.type_name(s.ty) == name)
    }

    fn members(&self, s: usize) -> Vec<Member> {
        let Some(st) = self.structs.get(s) else {
            return Vec::new();
        };
        let mut offset = 0u64;
        let mut out = Vec::with_capacity(st.fields.len());
        let mut def = st.at.saturating_add(4);
        for &(ty, name) in &st.fields {
            let (pointer, count) = declarator(self.name(name));
            let unit = if pointer {
                self.pointer
            } else {
                self.type_size(ty)
            };
            let size = unit.saturating_mul(count);
            out.push(Member {
                ty,
                name,
                offset,
                size,
                pointer,
                count,
                def,
            });
            offset = offset.saturating_add(size);
            def = def.saturating_add(4);
        }
        out
    }

    /// Offset and length of `ID.name`.
    fn id_name(&self) -> Option<(u64, u64)> {
        let id = self.find("ID")?;
        self.members(id)
            .into_iter()
            .find(|m| {
                !m.pointer && self.type_name(m.ty) == "char" && base(self.name(m.name)) == "name"
            })
            .map(|m| (m.offset, m.size))
    }
}

/// Whether a declarator is a pointer, and its element count.
fn declarator(name: &str) -> (bool, u64) {
    let pointer = name.starts_with('*') || name.starts_with('(');
    let mut count = 1u64;
    let mut rest = name;
    while let Some(open) = rest.find('[') {
        let after = rest.get(open.saturating_add(1)..).unwrap_or_default();
        let Some(close) = after.find(']') else {
            break;
        };
        let n = after
            .get(..close)
            .and_then(|n| n.trim().parse::<u64>().ok())
            .unwrap_or(1);
        count = count.saturating_mul(n);
        rest = after.get(close.saturating_add(1)..).unwrap_or_default();
    }
    (pointer, count)
}

/// The identifier in a declarator (`*mat[16]` → `mat`).
fn base(name: &str) -> &str {
    name.trim_start_matches(['*', '('])
        .split(['[', ')'])
        .next()
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// The block index

#[derive(Clone, Debug)]
struct BHead {
    code: [u8; 4],
    sdna: u32,
    old: u64,
    len: u64,
    nr: u64,
    header: Span,
    data: Span,
}

#[derive(Debug)]
struct Blend {
    layout: Layout,
    blocks: Vec<BHead>,
    /// The ID name of each block (without its code), if it is an ID.
    names: Vec<Option<String>>,
    /// (old address, block index), sorted.
    by_addr: Vec<(u64, usize)>,
    sdna: Option<Sdna>,
    problems: Vec<Diagnostic>,
}

type Shared = Arc<Blend>;

async fn load(cx: &Cx, file: Span, layout: Layout) -> Result<Shared> {
    if let Some(blend) = cx.cached::<Blend>(file, "blend") {
        return Ok(blend);
    }
    let mut problems = Vec::new();
    let mut blocks = Vec::new();
    let region = file.tail(layout.header);
    let mut pos = 0u64;
    let bhead = layout.bhead();
    let mut ended = false;
    while pos < region.len {
        let hspan = region.sub(pos, bhead);
        if hspan.len < bhead {
            problems.push(Diagnostic::malformed("trailing bytes after the last block").at(hspan));
            break;
        }
        let h = cx.read(hspan).await?;
        let e = layout.endian;
        let u32_at = |at: usize| {
            h.get(at..at.saturating_add(4))
                .and_then(|b| u32::decode(b, e))
                .unwrap_or(0)
        };
        let u64_at = |at: usize| {
            h.get(at..at.saturating_add(8))
                .and_then(|b| u64::decode(b, e))
                .unwrap_or(0)
        };
        let code: [u8; 4] = h
            .get(..4)
            .and_then(|c| c.try_into().ok())
            .unwrap_or_default();
        let (sdna, old, len, nr) = if layout.large {
            (u32_at(4), u64_at(8), u64_at(16), u64_at(24))
        } else if layout.pointer == 8 {
            (u32_at(16), u64_at(8), u32_at(4).into(), u32_at(20).into())
        } else {
            (
                u32_at(12),
                u32_at(8).into(),
                u32_at(4).into(),
                u32_at(16).into(),
            )
        };
        let data = region.sub(pos.saturating_add(bhead), len);
        pos = pos.saturating_add(bhead).saturating_add(len);
        blocks.push(BHead {
            code,
            sdna,
            old,
            len,
            nr,
            header: hspan,
            data,
        });
        if data.len < len {
            problems.push(Diagnostic::truncated(
                Span::new(data.source, data.offset, len),
                data.len,
            ));
            break;
        }
        if &code == b"ENDB" {
            ended = true;
            break;
        }
        if blocks.len() >= MAX_BLOCKS {
            problems.push(Diagnostic::limit(format!(
                "more than {MAX_BLOCKS} blocks; the rest are not listed"
            )));
            break;
        }
    }
    if !ended && problems.is_empty() {
        problems.push(Diagnostic::malformed("no ENDB block").at(region.tail(region.len)));
    }

    let dna = blocks
        .iter()
        .rev()
        .find(|b| &b.code == b"DNA1")
        .map(|b| b.data);
    let sdna = match dna {
        None => {
            problems.push(Diagnostic::malformed(
                "no DNA1 block: struct contents cannot be interpreted",
            ));
            None
        }
        Some(span) if span.len > cx.limits().max_read => {
            problems.push(Diagnostic::limit("DNA1 block too large to read").at(span));
            None
        }
        Some(span) => {
            let data = cx.read_avail(span).await?;
            let sdna = Sdna::parse(&data, span, layout.endian, layout.pointer);
            if sdna.is_none() {
                problems.push(Diagnostic::malformed("unreadable SDNA in the DNA1 block").at(span));
            }
            sdna
        }
    };

    let id_name = sdna.as_ref().and_then(Sdna::id_name);
    let mut names = Vec::new();
    for b in &blocks {
        let name = match id_name {
            Some((offset, len)) if is_id(&b.code) => {
                let raw = cx.read_avail(b.data.sub(offset, len)).await?;
                let full = crate::text::until_nul(&raw);
                Some(
                    match full.strip_prefix(&*String::from_utf8_lossy(&b.code[..2])) {
                        Some(rest) => rest.to_owned(),
                        None => full,
                    },
                )
            }
            _ => None,
        };
        names.push(name);
    }

    let mut by_addr: Vec<(u64, usize)> = blocks
        .iter()
        .enumerate()
        .filter(|(_, b)| b.old != 0)
        .map(|(i, b)| (b.old, i))
        .collect();
    by_addr.sort_unstable();

    let blend = Arc::new(Blend {
        layout,
        blocks,
        names,
        by_addr,
        sdna,
        problems,
    });
    cx.cache(file, "blend", blend.clone());
    Ok(blend)
}

impl Blend {
    fn block(&self, i: usize) -> Option<&BHead> {
        self.blocks.get(i)
    }

    fn sdna(&self) -> Result<&Sdna> {
        self.sdna
            .as_ref()
            .ok_or_else(|| Diagnostic::unsupported("no usable SDNA (DNA1 block)"))
    }

    /// The struct a block holds `nr` of, if its size agrees.
    fn block_struct(&self, b: &BHead) -> Option<usize> {
        let sdna = self.sdna.as_ref()?;
        let s = to_usize(b.sdna.into());
        let size = sdna.struct_size(s);
        (sdna.structs.get(s).is_some()
            && size > 0
            && b.nr > 0
            && size.checked_mul(b.nr) == Some(b.len))
        .then_some(s)
    }

    /// The block an old address falls in, and the offset within it.
    fn resolve(&self, addr: u64) -> Option<(usize, u64)> {
        let at = self.by_addr.partition_point(|&(old, _)| old <= addr);
        let &(old, i) = self.by_addr.get(at.checked_sub(1)?)?;
        let b = self.blocks.get(i)?;
        let off = addr.checked_sub(old)?;
        (off < b.len.max(1)).then_some((i, off))
    }

    /// "OB Cube", "DATA MVert ×8", "DATA (raw)".
    fn title(&self, i: usize) -> String {
        let Some(b) = self.block(i) else {
            return String::new();
        };
        let code = label(&b.code);
        if let Some(Some(name)) = self.names.get(i) {
            return format!("{code} {name}");
        }
        if &b.code == b"DATA" {
            return match (self.block_struct(b), &self.sdna) {
                (Some(s), Some(sdna)) if b.nr == 1 => format!("DATA {}", sdna.struct_name(s)),
                (Some(s), Some(sdna)) => format!("DATA {} ×{}", sdna.struct_name(s), b.nr),
                _ => "DATA (raw)".to_owned(),
            };
        }
        code
    }

    fn count(&self, code: &[u8; 2]) -> usize {
        self.blocks
            .iter()
            .filter(|b| b.code[..2] == code[..] && is_id(&b.code))
            .count()
    }

    fn thumbnail(&self) -> Option<&BHead> {
        self.blocks.iter().find(|b| &b.code == b"TEST")
    }
}

// ---------------------------------------------------------------------------
// The file

async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 17)).await?;
    if head.starts_with(b"\x28\xb5\x2f\xfd") {
        cx.annotate("Blender file, zstd-compressed");
        cx.emit(content("Decompressed", input, file, Codec::Zstd, None));
        return Ok(());
    }
    if head.starts_with(b"\x1f\x8b") {
        cx.annotate("Blender file, gzip-compressed");
        cx.emit(embedded_as(
            "Gzip stream",
            input.nested(file),
            &crate::formats::compression::gzip::FORMAT,
        ));
        return Ok(());
    }
    let layout = header(&head)
        .ok_or_else(|| Diagnostic::malformed("not a Blender file header").at(file.sub(0, 17)))?;
    let byte_order = match layout.endian {
        Endian::Little => "little-endian",
        Endian::Big => "big-endian",
    };
    let bits = layout.pointer.saturating_mul(8);
    let description = format!("Blender {}, {bits}-bit {byte_order}", layout.version());
    cx.annotate(description.clone());
    cx.emit(
        struct_node(
            "Header",
            file.sub(0, layout.header),
            layout.endian,
            layout,
            header_fields,
        )
        .summary(format!("{bits}-bit pointers, {byte_order}")),
    );

    let blend = load(&cx, file, layout).await?;
    for problem in &blend.problems {
        cx.diag(problem.clone());
    }
    let ids = blend.blocks.iter().filter(|b| is_id(&b.code)).count();
    cx.emit(
        Node::new("File blocks")
            .span(file.tail(layout.header))
            .summary(format!("{} blocks", blend.blocks.len()))
            .lazy(file_blocks, blend.clone()),
    );
    if ids > 0 {
        cx.emit(
            Node::new("Datablocks")
                .summary(format!("{ids} ID blocks"))
                .lazy(datablocks, blend.clone()),
        );
    }
    if let Some(test) = blend.thumbnail() {
        let dims = cx.read_avail(test.data.sub(0, 8)).await?;
        let e = layout.endian;
        let int = |at: usize| {
            dims.get(at..at.saturating_add(4))
                .and_then(|b| i32::decode(b, e))
                .unwrap_or(0)
        };
        cx.emit(thumbnail_node(&blend, test).summary(format!("{}×{} RGBA", int(0), int(4))));
    }
    if let Some(sdna) = &blend.sdna {
        cx.emit(sdna_node(&blend, sdna));
    }

    let mut parts = Vec::new();
    for code in [b"OB", b"ME", b"MA", b"SC"] {
        let n = blend.count(code);
        if let (true, Some((one, many))) = (n > 0, id_type(&[code[0], code[1], 0, 0])) {
            parts.push(format!("{n} {}", if n == 1 { one } else { many }));
        }
    }
    if parts.is_empty() {
        cx.annotate(description);
    } else {
        cx.annotate(format!("{description}: {}", parts.join(", ")));
    }
    Ok(())
}

fn header_fields(f: &mut Fields<'_>, layout: &Layout) -> Result<()> {
    f.ascii("Magic", 7).emit()?;
    let pointer = format!("{}-byte pointers", layout.pointer);
    let order = match layout.endian {
        Endian::Little => "little-endian",
        Endian::Big => "big-endian",
    };
    if layout.large {
        f.ascii("Header size", 2).emit()?;
        f.ascii("Pointer size", 1).summary(pointer).emit()?;
        f.ascii("File format version", 2)
            .desc("01: 32-byte block headers")
            .emit()?;
        f.ascii("Byte order", 1).summary(order).emit()?;
        f.ascii("Version", 4).summary(layout.version()).emit()?;
    } else {
        f.ascii("Pointer size", 1).summary(pointer).emit()?;
        f.ascii("Byte order", 1).summary(order).emit()?;
        f.ascii("Version", 3).summary(layout.version()).emit()?;
    }
    Ok(())
}

async fn file_blocks(cx: Cx, blend: Shared) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(blend.blocks.len())));
    let start = cx.resume::<usize>().unwrap_or(0);
    for i in start..blend.blocks.len() {
        cx.mark(move || i);
        cx.push(block_node(&blend, i)).await;
    }
    Ok(())
}

/// ID blocks grouped by type, in order of first appearance.
async fn datablocks(cx: Cx, blend: Shared) -> Result<()> {
    let mut seen: Vec<[u8; 4]> = Vec::new();
    for b in &blend.blocks {
        if is_id(&b.code) && !seen.contains(&b.code) {
            seen.push(b.code);
        }
    }
    for code in seen {
        let n = blend.blocks.iter().filter(|b| b.code == code).count();
        let title = match id_type(&code) {
            Some((_, many)) => {
                let mut t = many.to_owned();
                if let Some(first) = t.get_mut(..1) {
                    first.make_ascii_uppercase();
                }
                t
            }
            None => label(&code),
        };
        cx.push(
            Node::new(title)
                .value(Value::Text(label(&code)))
                .summary(format!("{n}"))
                .lazy(datablocks_of, (blend.clone(), code)),
        )
        .await;
    }
    Ok(())
}

async fn datablocks_of(cx: Cx, (blend, code): (Shared, [u8; 4])) -> Result<()> {
    for (i, b) in blend.blocks.iter().enumerate() {
        if b.code == code {
            cx.push(block_node(&blend, i)).await;
        }
    }
    Ok(())
}

fn block_node(blend: &Shared, i: usize) -> Node {
    let Some(b) = blend.block(i) else {
        return Node::new("?");
    };
    let mut parts = Vec::new();
    if let Some((_, kind)) = BLOCK_KINDS.iter().find(|(c, _)| *c == &b.code) {
        parts.push((*kind).to_owned());
    }
    if is_id(&b.code)
        && let Some((one, _)) = id_type(&b.code)
    {
        parts.push(one.to_owned());
    }
    if &b.code != b"DATA"
        && let (Some(s), Some(sdna)) = (blend.block_struct(b), &blend.sdna)
    {
        let name = sdna.struct_name(s);
        parts.push(if b.nr == 1 {
            name.to_owned()
        } else {
            format!("{name} ×{}", b.nr)
        });
    }
    parts.push(format!("{} bytes", b.len));
    let span = Span::new(
        b.header.source,
        b.header.offset,
        b.header.len.saturating_add(b.data.len),
    );
    Node::new(blend.title(i))
        .span(span)
        .summary(parts.join(", "))
        .lazy(block_children, (blend.clone(), i))
}

#[derive(Clone)]
struct BlockCtx {
    large: bool,
    wide: bool,
    structure: String,
}

fn bhead_fields(f: &mut Fields<'_>, ctx: &BlockCtx) -> Result<()> {
    f.ascii("Code", 4).emit()?;
    if ctx.large {
        f.u32("SDNA index").summary(ctx.structure.clone()).emit()?;
        f.u64("Old address")
            .hex()
            .desc("Where the data was in memory when written; pointers refer to it")
            .emit()?;
        f.u64("Length").emit()?;
        f.u64("Count").emit()?;
    } else {
        f.u32("Length").emit()?;
        f.uword("Old address", ctx.wide)
            .hex()
            .desc("Where the data was in memory when written; pointers refer to it")
            .emit()?;
        f.u32("SDNA index").summary(ctx.structure.clone()).emit()?;
        f.u32("Count").emit()?;
    }
    Ok(())
}

async fn block_children(cx: Cx, (blend, i): (Shared, usize)) -> Result<()> {
    let b = blend
        .block(i)
        .ok_or_else(|| Diagnostic::internal("no such block"))?
        .clone();
    let structure = match (&blend.sdna, blend.block_struct(&b)) {
        (Some(sdna), Some(s)) => sdna.struct_name(s).to_owned(),
        (Some(sdna), None) if to_usize(b.sdna.into()) >= sdna.structs.len() => {
            "no such struct".to_owned()
        }
        (Some(_), None) => "raw data".to_owned(),
        (None, _) => String::new(),
    };
    let ctx = BlockCtx {
        large: blend.layout.large,
        wide: blend.layout.pointer == 8,
        structure,
    };
    cx.emit(struct_node(
        "Block header",
        b.header,
        blend.layout.endian,
        ctx,
        bhead_fields,
    ));
    match &b.code {
        b"ENDB" => {}
        b"DNA1" => {
            if let Some(sdna) = &blend.sdna {
                cx.emit(sdna_node(&blend, sdna));
            } else {
                cx.emit(Node::new("Data").span(b.data));
            }
        }
        b"TEST" => cx.emit(thumbnail_node(&blend, &b)),
        b"REND" => {
            let data = cx.read_avail(b.data).await?;
            let e = blend.layout.endian;
            let int = |at: usize| {
                data.get(at..at.saturating_add(4))
                    .and_then(|x| i32::decode(x, e))
                    .map(|v| Value::Int {
                        value: v.into(),
                        bits: 32,
                    })
            };
            if let Some(v) = int(0) {
                cx.emit(Node::new("Start frame").span(b.data.sub(0, 4)).value(v));
            }
            if let Some(v) = int(4) {
                cx.emit(Node::new("End frame").span(b.data.sub(4, 4)).value(v));
            }
            if b.data.len > 8 {
                let name = crate::text::until_nul(data.get(8..).unwrap_or_default());
                cx.emit(
                    Node::new("Scene name")
                        .span(b.data.tail(8))
                        .value(Value::Text(name)),
                );
            }
        }
        _ => match (blend.block_struct(&b), &blend.sdna) {
            (Some(s), Some(_)) if b.nr == 1 => {
                emit_members(&cx, &blend, s, b.data, &Path::new()).await?;
            }
            (Some(s), Some(sdna)) => cx.emit(
                Node::new(format!("{} ×{}", sdna.struct_name(s), b.nr))
                    .span(b.data)
                    .lazy(
                        crate::expander!(self::elements: Elements),
                        Elements {
                            blend: blend.clone(),
                            s,
                            span: b.data,
                            count: b.nr,
                            path: Path::new(),
                        },
                    ),
            ),
            _ => {
                if let Some(count) = pointer_array(&cx, &blend, &b).await? {
                    cx.emit(
                        Node::new("Pointers")
                            .span(b.data)
                            .summary(format!(
                                "{count}, inferred: raw data of resolvable addresses"
                            ))
                            .lazy(pointers, (blend.clone(), b.data, count)),
                    );
                } else if b.data.len > 0 {
                    cx.emit(Node::new("Data").span(b.data).summary("raw"));
                }
            }
        },
    }
    Ok(())
}

/// Blender writes pointer arrays (`Material **mat`, ...) as raw data. A small
/// raw block whose words are all null or addresses of blocks in the file is
/// shown as one; the count of pointers if so.
async fn pointer_array(cx: &Cx, blend: &Blend, b: &BHead) -> Result<Option<u64>> {
    let size = blend.layout.pointer;
    let count = b.len.checked_div(size).unwrap_or(0);
    if count == 0 || count.saturating_mul(size) != b.len || b.len > 4096 {
        return Ok(None);
    }
    let data = cx.read_avail(b.data).await?;
    let e = blend.layout.endian;
    let mut any = false;
    for word in data.chunks_exact(to_usize(size)) {
        let addr = match word.len() {
            4 => u32::decode(word, e).map(u64::from),
            _ => u64::decode(word, e),
        }
        .unwrap_or(0);
        if addr != 0 {
            if blend.resolve(addr).is_none() {
                return Ok(None);
            }
            any = true;
        }
    }
    Ok((any && to_u64(data.len()) == b.len).then_some(count))
}

fn thumbnail_node(blend: &Shared, b: &BHead) -> Node {
    Node::new("Thumbnail")
        .span(b.data)
        .lazy(thumbnail, (blend.clone(), b.data))
}

async fn thumbnail(cx: Cx, (blend, span): (Shared, Span)) -> Result<()> {
    let head = cx.read(span.sub_exact(0, 8)?).await?;
    let e = blend.layout.endian;
    let width = head.get(..4).and_then(|b| i32::decode(b, e)).unwrap_or(0);
    let height = head.get(4..8).and_then(|b| i32::decode(b, e)).unwrap_or(0);
    let int = |v: i32| Value::Int {
        value: v.into(),
        bits: 32,
    };
    cx.emit(Node::new("Width").span(span.sub(0, 4)).value(int(width)));
    cx.emit(Node::new("Height").span(span.sub(4, 4)).value(int(height)));
    let expected = u64::try_from(width)
        .unwrap_or(0)
        .saturating_mul(u64::try_from(height).unwrap_or(0))
        .saturating_mul(4);
    let mut pixels = Node::new("Pixels")
        .span(span.tail(8))
        .summary(format!("{width}×{height} RGBA"))
        .desc("8-bit RGBA, rows from bottom to top");
    if expected != span.len.saturating_sub(8) {
        pixels = pixels.diag(Diagnostic::malformed(format!(
            "{width}×{height} RGBA needs {expected} bytes, the block has {}",
            span.len.saturating_sub(8)
        )));
    }
    cx.emit(pixels);
    cx.annotate(format!("{width}×{height} RGBA"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Struct instances

#[derive(Clone)]
struct Instance {
    blend: Shared,
    s: usize,
    span: Span,
    path: Path,
}

#[derive(Clone)]
struct Elements {
    blend: Shared,
    s: usize,
    span: Span,
    count: u64,
    path: Path,
}

async fn instance(cx: Cx, st: Instance) -> Result<()> {
    emit_members(&cx, &st.blend, st.s, st.span, &st.path).await
}

async fn emit_members(cx: &Cx, blend: &Shared, s: usize, span: Span, path: &Path) -> Result<()> {
    let sdna = blend.sdna()?;
    let path = path.enter(to_u64(s), MAX_DEPTH).map_err(|d| d.at(span))?;
    let data = cx.read_avail(span).await?;
    if to_u64(data.len()) < span.len {
        cx.diag(Diagnostic::truncated(span, to_u64(data.len())));
    }
    for m in sdna.members(s) {
        cx.push(member(blend, sdna, &m, &data, span, &path)).await;
    }
    Ok(())
}

async fn elements(cx: Cx, st: Elements) -> Result<()> {
    let sdna = st.blend.sdna()?;
    let size = sdna.struct_size(st.s);
    if size == 0 {
        return Ok(());
    }
    cx.set_count(Count::Exact(st.count));
    let start = cx.resume::<u64>().unwrap_or(0);
    for i in start..st.count {
        let span = st.span.sub(i.saturating_mul(size), size);
        if span.is_empty() {
            break;
        }
        cx.mark(move || i);
        cx.push(Node::new(format!("[{i}]")).span(span).lazy(
            crate::expander!(self::instance: Instance),
            Instance {
                blend: st.blend.clone(),
                s: st.s,
                span,
                path: st.path.clone(),
            },
        ))
        .await;
    }
    Ok(())
}

fn slice(data: &[u8], offset: u64, len: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(len).ok()?)?;
    data.get(start..end)
}

fn member(blend: &Shared, sdna: &Sdna, m: &Member, data: &[u8], base: Span, path: &Path) -> Node {
    let span = base.sub(m.offset, m.size);
    let ty = sdna.type_name(m.ty);
    let node = Node::new(sdna.name(m.name).to_owned()).span(span);
    let Some(bytes) = slice(data, m.offset, m.size) else {
        return node.summary(ty.to_owned());
    };
    if m.pointer {
        if m.count == 1 {
            return pointer(blend, node, bytes);
        }
        return node
            .summary(format!("{ty} pointers ×{}", m.count))
            .lazy(pointers, (blend.clone(), span, m.count));
    }
    if let Some(s) = sdna.struct_of(m.ty) {
        if m.count == 1 {
            return node.summary(ty.to_owned()).lazy(
                crate::expander!(self::instance: Instance),
                Instance {
                    blend: blend.clone(),
                    s,
                    span,
                    path: path.clone(),
                },
            );
        }
        return node.summary(format!("{ty} ×{}", m.count)).lazy(
            crate::expander!(self::elements: Elements),
            Elements {
                blend: blend.clone(),
                s,
                span,
                count: m.count,
                path: path.clone(),
            },
        );
    }
    let unit = sdna.type_size(m.ty);
    let e = blend.layout.endian;
    if ty == "char" && m.count > 1 {
        return node.value(Value::Text(crate::text::until_nul(bytes)));
    }
    if m.count == 1 {
        return match scalar(ty, bytes, e) {
            Some((v, _)) => node.value(v),
            None if bytes.len() <= 64 => node
                .value(Value::Bytes(bytes.to_vec()))
                .summary(ty.to_owned()),
            None => node.summary(ty.to_owned()),
        };
    }
    let mut preview = Vec::new();
    for i in 0..m.count.min(PREVIEW) {
        match slice(bytes, i.saturating_mul(unit), unit).and_then(|b| scalar(ty, b, e)) {
            Some((_, text)) => preview.push(text),
            None => break,
        }
    }
    let summary = if preview.is_empty() {
        format!("{ty} ×{}", m.count)
    } else {
        let more = if m.count > PREVIEW { ", …" } else { "" };
        format!("({}{more})", preview.join(", "))
    };
    node.summary(summary)
        .lazy(scalars, (blend.clone(), m.ty, span, m.count))
}

fn scalar(ty: &str, b: &[u8], e: Endian) -> Option<(Value, String)> {
    fn int<T: Prim + std::fmt::Display>(b: &[u8], e: Endian) -> Option<(Value, String)> {
        T::decode(b, e).map(|v| (v.value(Radix::Dec), v.to_string()))
    }
    match (ty, b.len()) {
        ("char" | "int8_t", 1) => int::<i8>(b, e),
        ("uchar" | "uint8_t", 1) => int::<u8>(b, e),
        ("bool", 1) => {
            let v = b.first().is_some_and(|&x| x != 0);
            Some((Value::Bool(v), v.to_string()))
        }
        ("short" | "int16_t", 2) => int::<i16>(b, e),
        ("ushort" | "uint16_t", 2) => int::<u16>(b, e),
        ("int" | "int32_t" | "long", 4) => int::<i32>(b, e),
        ("uint" | "uint32_t" | "ulong", 4) => int::<u32>(b, e),
        ("int64_t" | "long" | "int64", 8) => int::<i64>(b, e),
        ("uint64_t" | "ulong" | "uint64", 8) => int::<u64>(b, e),
        ("float", 4) => int::<f32>(b, e),
        ("double", 8) => int::<f64>(b, e),
        _ => None,
    }
}

async fn scalars(cx: Cx, (blend, ty, span, count): (Shared, u16, Span, u64)) -> Result<()> {
    let sdna = blend.sdna()?;
    let unit = sdna.type_size(ty);
    if unit == 0 {
        return Ok(());
    }
    let name = sdna.type_name(ty);
    cx.set_count(Count::Exact(count));
    let start = cx.resume::<u64>().unwrap_or(0);
    for i in start..count {
        let at = span.sub(i.saturating_mul(unit), unit);
        if at.is_empty() {
            break;
        }
        cx.mark(move || i);
        let bytes = cx.read_avail(at).await?;
        let mut node = Node::new(format!("[{i}]")).span(at);
        if let Some((v, _)) = scalar(name, &bytes, blend.layout.endian) {
            node = node.value(v);
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn pointers(cx: Cx, (blend, span, count): (Shared, Span, u64)) -> Result<()> {
    let size = blend.layout.pointer;
    cx.set_count(Count::Exact(count));
    let start = cx.resume::<u64>().unwrap_or(0);
    for i in start..count {
        let at = span.sub(i.saturating_mul(size), size);
        if at.is_empty() {
            break;
        }
        cx.mark(move || i);
        let bytes = cx.read_avail(at).await?;
        cx.push(pointer(
            &blend,
            Node::new(format!("[{i}]")).span(at),
            &bytes,
        ))
        .await;
    }
    Ok(())
}

fn pointer(blend: &Blend, node: Node, bytes: &[u8]) -> Node {
    let e = blend.layout.endian;
    let addr = match bytes.len() {
        4 => u32::decode(bytes, e).map(u64::from),
        8 => u64::decode(bytes, e),
        _ => None,
    };
    let Some(addr) = addr else {
        return node;
    };
    let node = node.value(Value::UInt {
        value: addr,
        bits: u8::try_from(blend.layout.pointer.saturating_mul(8)).unwrap_or(64),
        radix: Radix::Hex,
    });
    if addr == 0 {
        return node.summary("null");
    }
    match blend.resolve(addr) {
        Some((i, off)) => {
            let target = blend.blocks.get(i).map(|b| b.data.tail(off));
            let mut summary = blend.title(i);
            if off > 0 {
                summary.push_str(&format!(" +{off:#x}"));
            }
            let node = node.summary(summary);
            match target {
                Some(t) => node.target(t),
                None => node,
            }
        }
        None => node.summary("no block at this address"),
    }
}

// ---------------------------------------------------------------------------
// The SDNA catalogue

fn sdna_node(blend: &Shared, sdna: &Sdna) -> Node {
    Node::new("Structure DNA")
        .span(sdna.span)
        .summary(format!(
            "{} structs, {} types, {} names",
            sdna.structs.len(),
            sdna.types.len(),
            sdna.names.len()
        ))
        .lazy(sdna_children, blend.clone())
}

async fn sdna_children(cx: Cx, blend: Shared) -> Result<()> {
    let sdna = blend.sdna()?;
    cx.emit(
        Node::new("Magic")
            .span(sdna.span.sub(0, 4))
            .value(Value::Text("SDNA".into())),
    );
    for &(title, at, len) in &sdna.sections {
        let count = match title {
            "Names" => sdna.names.len(),
            "Types" | "Type sizes" => sdna.types.len(),
            _ => sdna.structs.len(),
        };
        let node = Node::new(title)
            .span(sdna.span.sub(at, len))
            .summary(format!("{count}"));
        cx.emit(match title {
            "Names" => node.lazy(sdna_names, blend.clone()),
            "Types" => node.lazy(sdna_types, blend.clone()),
            "Type sizes" => node,
            _ => node.lazy(sdna_structs, blend.clone()),
        });
    }
    Ok(())
}

async fn sdna_names(cx: Cx, blend: Shared) -> Result<()> {
    let sdna = blend.sdna()?;
    cx.set_count(Count::Exact(to_u64(sdna.names.len())));
    let start = cx.resume::<usize>().unwrap_or(0);
    for (i, (name, at)) in sdna.names.iter().enumerate().skip(start) {
        cx.mark(move || i);
        cx.push(
            Node::new(format!("[{i}]"))
                .span(sdna.span.sub(*at, to_u64(name.len()).saturating_add(1)))
                .value(Value::Text(name.clone())),
        )
        .await;
    }
    Ok(())
}

async fn sdna_types(cx: Cx, blend: Shared) -> Result<()> {
    let sdna = blend.sdna()?;
    cx.set_count(Count::Exact(to_u64(sdna.types.len())));
    let start = cx.resume::<usize>().unwrap_or(0);
    for (i, (name, at)) in sdna.types.iter().enumerate().skip(start) {
        cx.mark(move || i);
        let t = u16::try_from(i).unwrap_or(u16::MAX);
        let kind = if sdna.struct_of(t).is_some() {
            ", struct"
        } else {
            ""
        };
        cx.push(
            Node::new(format!("[{i}]"))
                .span(sdna.span.sub(*at, to_u64(name.len()).saturating_add(1)))
                .value(Value::Text(name.clone()))
                .summary(format!("{} bytes{kind}", sdna.type_size(t)))
                .target(
                    sdna.span
                        .sub(sdna.tlen_at.saturating_add(to_u64(i).saturating_mul(2)), 2),
                ),
        )
        .await;
    }
    Ok(())
}

async fn sdna_structs(cx: Cx, blend: Shared) -> Result<()> {
    let sdna = blend.sdna()?;
    cx.set_count(Count::Exact(to_u64(sdna.structs.len())));
    let start = cx.resume::<usize>().unwrap_or(0);
    for (i, st) in sdna.structs.iter().enumerate().skip(start) {
        cx.mark(move || i);
        let size = sdna.type_size(st.ty);
        let def = to_u64(st.fields.len()).saturating_mul(4).saturating_add(4);
        let mut node = Node::new(sdna.type_name(st.ty).to_owned())
            .span(sdna.span.sub(st.at, def))
            .value(Value::UInt {
                value: to_u64(i),
                bits: 32,
                radix: Radix::Dec,
            })
            .summary(format!("{size} bytes, {} fields", st.fields.len()))
            .lazy(sdna_struct, (blend.clone(), i));
        let sum = sdna
            .members(i)
            .iter()
            .fold(0u64, |acc, m| acc.saturating_add(m.size));
        if sum != size {
            node = node.diag(Diagnostic::warning(format!(
                "fields add up to {sum} bytes, the type is {size}"
            )));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn sdna_struct(cx: Cx, (blend, s): (Shared, usize)) -> Result<()> {
    let sdna = blend.sdna()?;
    for m in sdna.members(s) {
        let name = sdna.name(m.name);
        let stars = name
            .chars()
            .take_while(|&c| c == '*' || c == '(')
            .filter(|&c| c == '*')
            .count();
        let ty = format!("{}{}", sdna.type_name(m.ty), "*".repeat(stars));
        cx.push(
            Node::new(sdna.name(m.name).to_owned())
                .span(sdna.span.sub(m.def, 4))
                .value(Value::Text(ty))
                .summary(format!("at {:#x}, {} bytes", m.offset, m.size)),
        )
        .await;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{base, declarator, header};

    #[test]
    fn declarators() {
        assert_eq!(declarator("*next"), (true, 1));
        assert_eq!(declarator("obmat[4][4]"), (false, 16));
        assert_eq!(declarator("*mtex[18]"), (true, 18));
        assert_eq!(declarator("(*func)()"), (true, 1));
        assert_eq!(base("**mat"), "mat");
        assert_eq!(base("(*func)()"), "func");
        assert_eq!(base("name[66]"), "name");
    }

    #[test]
    fn headers() {
        let classic = header(b"BLENDER-v293").unwrap();
        assert_eq!((classic.pointer, classic.version), (8, 293));
        let modern = header(b"BLENDER17-01v0500").unwrap();
        assert!(modern.large);
        assert_eq!(modern.version(), "5.0");
        assert!(header(b"BLENDER?v293").is_none());
    }
}
