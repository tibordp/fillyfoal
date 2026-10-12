//! DWARF call frame information as found in `.eh_frame` (ELF) and
//! `__eh_frame` (Mach-O): CIE and FDE headers, with pointers decoded by
//! their `DW_EH_PE_*` encodings, and the ELF `.eh_frame_hdr` lookup table.
//! The call frame instructions are decoded one per node on expansion, and
//! `.debug_frame` (the DWARF form: all-ones CIE ids, section-offset CIE
//! pointers, plain addresses) is walked by the same code.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::binutil::{Reader, get_at};
use crate::formats::util::fmt::{plural, size};
use crate::formats::util::val::{hex, text, uint};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

use super::dwarf::Arch;
use super::dwarf::tables::{register, register_name};

/// What the walker needs from the image the section belongs to.
pub(crate) trait Image {
    fn endian(&self) -> Endian;
    /// 64-bit pointers.
    fn wide(&self) -> bool;
    /// A label for an address (the symbol or section it falls in).
    fn describe(&self, addr: u64) -> String;
    /// The file bytes at an address, for navigation.
    fn target(&self, addr: u64) -> Option<Span>;
    /// The architecture whose register numbers the CFI uses (`eh` for
    /// `.eh_frame`, which Darwin i386 numbers differently).
    fn arch(&self, eh: bool) -> Arch {
        let _ = eh;
        Arch::Unknown
    }
}

fn bits(img: &dyn Image) -> u8 {
    if img.wide() { 64 } else { 32 }
}

/// A node whose children are `children`, listed on expansion.
fn group(name: &'static str, span: Span, children: Vec<Node>) -> Node {
    let node = Node::new(name).span(span);
    if children.is_empty() {
        node
    } else {
        node.lazy(
            crate::formats::util::arcutil::push_nodes,
            Arc::new(children),
        )
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Cie {
    augmented: bool,
    fde_encoding: u8,
    lsda_encoding: u8,
    code_align: u64,
    data_align: i64,
    /// The address size of a version 4 `.debug_frame` CIE.
    address_size: Option<u8>,
}

/// Which flavour of call frame information a section holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// `.eh_frame`: CIE id 0, CIE pointers relative to themselves,
    /// pointers in `DW_EH_PE_*` encodings.
    Eh,
    /// `.debug_frame`: CIE id all ones, CIE pointers are section offsets,
    /// addresses are plain target addresses.
    Debug,
}

/// Reads a DWARF-encoded pointer (`DW_EH_PE_*`); `here` is the address of
/// the field, for pc-relative encodings.
fn encoded(r: &mut Reader<'_>, enc: u8, wide: bool, endian: Endian, here: u64) -> Option<u64> {
    if enc == 0xff {
        return None;
    }
    let value: i64 = match enc & 0x0f {
        0x00 => {
            if wide {
                i64::from_ne_bytes(r.int::<u64>(endian)?.to_ne_bytes())
            } else {
                r.int::<u32>(endian)?.into()
            }
        }
        0x01 => i64::from_ne_bytes(r.uleb()?.to_ne_bytes()),
        0x02 => r.int::<u16>(endian)?.into(),
        0x03 => r.int::<u32>(endian)?.into(),
        0x04 => i64::from_ne_bytes(r.int::<u64>(endian)?.to_ne_bytes()),
        0x09 => r.sleb()?,
        0x0a => r.int::<i16>(endian)?.into(),
        0x0b => r.int::<i32>(endian)?.into(),
        0x0c => r.int::<i64>(endian)?,
        _ => return None,
    };
    Some(if enc & 0x70 == 0x10 {
        here.wrapping_add_signed(value)
    } else {
        u64::from_ne_bytes(value.to_ne_bytes())
    })
}

fn encoding_name(enc: u8) -> String {
    if enc == 0xff {
        return "DW_EH_PE_omit".to_owned();
    }
    let format = match enc & 0x0f {
        0x00 => "absptr",
        0x01 => "uleb128",
        0x02 => "udata2",
        0x03 => "udata4",
        0x04 => "udata8",
        0x09 => "sleb128",
        0x0a => "sdata2",
        0x0b => "sdata4",
        0x0c => "sdata8",
        _ => "?",
    };
    let mut s = format!("DW_EH_PE_{format}");
    match enc & 0x70 {
        0x10 => s.push_str(" | pcrel"),
        0x20 => s.push_str(" | textrel"),
        0x30 => s.push_str(" | datarel"),
        0x40 => s.push_str(" | funcrel"),
        0x50 => s.push_str(" | aligned"),
        _ => {}
    }
    if enc & 0x80 != 0 {
        s.push_str(" | indirect");
    }
    s
}

/// How much of a record is read to decode its header.
const RECORD_HEAD: u64 = 0x400;

/// Parses a CIE's header from `data` (the record from its length field);
/// returns what FDEs need and the field nodes. `at` maps a range of `data`
/// to a span.
fn parse_cie(
    data: &[u8],
    header: usize,
    img: &dyn Image,
    at: &dyn Fn(usize, usize) -> Span,
    addr: u64,
    arch: Arch,
) -> (Cie, Vec<Node>, String, usize) {
    let mut cie = Cie {
        fde_encoding: 0,
        lsda_encoding: 0xff,
        augmented: false,
        code_align: 1,
        data_align: 1,
        address_size: None,
    };
    let mut nodes = Vec::new();
    let mut r = Reader::at(data, header);
    let mut summary = Vec::new();
    let mut s = r.pos();
    let Some(version) = r.u8() else {
        return (cie, nodes, String::new(), r.pos());
    };
    nodes.push(
        Node::new("version")
            .span(at(s, r.pos()))
            .value(uint(version, 8)),
    );
    s = r.pos();
    let aug = r.cstr().unwrap_or_default();
    let aug = String::from_utf8_lossy(aug).into_owned();
    nodes.push(
        Node::new("augmentation")
            .span(at(s, r.pos()))
            .value(text(aug.clone())),
    );
    summary.push(format!("version {version}, augmentation \"{aug}\""));
    if version >= 4 {
        s = r.pos();
        if let Some(size) = r.u8() {
            cie.address_size = Some(size);
            nodes.push(
                Node::new("address_size")
                    .span(at(s, r.pos()))
                    .value(uint(size, 8)),
            );
        }
        s = r.pos();
        if let Some(size) = r.u8() {
            nodes.push(
                Node::new("segment_selector_size")
                    .span(at(s, r.pos()))
                    .value(uint(size, 8)),
            );
        }
    }
    if aug.contains("eh") {
        s = r.pos();
        let v = if img.wide() {
            r.int::<u64>(img.endian())
        } else {
            r.int::<u32>(img.endian()).map(u64::from)
        };
        nodes.push(
            Node::new("eh_data")
                .span(at(s, r.pos()))
                .value(hex(v.unwrap_or(0), bits(img))),
        );
    }
    s = r.pos();
    if let Some(v) = r.uleb() {
        cie.code_align = v;
        nodes.push(
            Node::new("code_alignment_factor")
                .span(at(s, r.pos()))
                .value(uint(v, 64)),
        );
    }
    s = r.pos();
    if let Some(v) = r.sleb() {
        cie.data_align = v;
        nodes.push(
            Node::new("data_alignment_factor")
                .span(at(s, r.pos()))
                .value(Value::Int { value: v, bits: 64 }),
        );
        summary.push(format!("data alignment {v}"));
    }
    s = r.pos();
    let ra = if version == 1 {
        r.u8().map(u64::from)
    } else {
        r.uleb()
    };
    if let Some(v) = ra {
        let mut node = Node::new("return_address_register")
            .span(at(s, r.pos()))
            .value(uint(v, 64));
        if let Some(name) = register_name(arch, v) {
            node = node.summary(name);
        }
        nodes.push(node);
    }
    if aug.starts_with('z') {
        cie.augmented = true;
        s = r.pos();
        let len = r.uleb().unwrap_or(0);
        nodes.push(
            Node::new("augmentation_length")
                .span(at(s, r.pos()))
                .value(uint(len, 64)),
        );
        let end = r.pos().saturating_add(to_usize(len));
        for c in aug.chars().skip(1) {
            s = r.pos();
            match c {
                'P' => {
                    let enc = r.u8().unwrap_or(0xff);
                    nodes.push(
                        Node::new("personality_encoding")
                            .span(at(s, r.pos()))
                            .value(hex(enc, 8))
                            .summary(encoding_name(enc)),
                    );
                    s = r.pos();
                    let here = addr.saturating_add(to_u64(s));
                    let p = encoded(&mut r, enc & 0x7f, img.wide(), img.endian(), here);
                    let mut node = Node::new("personality")
                        .span(at(s, r.pos()))
                        .value(hex(p.unwrap_or(0), 64));
                    if let Some(p) = p {
                        node = node.summary(img.describe(p));
                    }
                    nodes.push(node);
                }
                'L' => {
                    cie.lsda_encoding = r.u8().unwrap_or(0xff);
                    nodes.push(
                        Node::new("lsda_encoding")
                            .span(at(s, r.pos()))
                            .value(hex(cie.lsda_encoding, 8))
                            .summary(encoding_name(cie.lsda_encoding)),
                    );
                }
                'R' => {
                    cie.fde_encoding = r.u8().unwrap_or(0);
                    nodes.push(
                        Node::new("fde_encoding")
                            .span(at(s, r.pos()))
                            .value(hex(cie.fde_encoding, 8))
                            .summary(encoding_name(cie.fde_encoding)),
                    );
                }
                _ => {}
            }
            if r.pos() >= end {
                break;
            }
        }
        r = Reader::at(data, end);
    }
    (cie, nodes, summary.join(", "), r.pos())
}

/// Walks the call frame information in `span` (an `.eh_frame` or
/// `__eh_frame` section at address `section_addr`): one node per CIE and
/// FDE, up to a zero terminator.
pub(crate) async fn walk(
    cx: &Cx,
    img: &(dyn Image + Sync),
    span: Span,
    section_addr: u64,
) -> Result<()> {
    walk_mode(cx, img, span, section_addr, Mode::Eh).await
}

/// Walks a `.debug_frame` section: CIEs and FDEs in the DWARF form.
pub(crate) async fn walk_debug_frame(cx: &Cx, img: &(dyn Image + Sync), span: Span) -> Result<()> {
    walk_mode(cx, img, span, 0, Mode::Debug).await
}

/// A plain target address of `size` bytes.
fn address(r: &mut Reader<'_>, size: u8, endian: Endian) -> Option<u64> {
    match size {
        8 => r.int::<u64>(endian),
        4 => r.int::<u32>(endian).map(u64::from),
        2 => r.int::<u16>(endian).map(u64::from),
        1 => r.u8().map(u64::from),
        _ => None,
    }
}

async fn walk_mode(
    cx: &Cx,
    img: &(dyn Image + Sync),
    span: Span,
    section_addr: u64,
    mode: Mode,
) -> Result<()> {
    let mut cies: BTreeMap<u64, Cie> = BTreeMap::new();
    let mut pos = 0u64;
    let endian = img.endian();
    let arch = img.arch(mode == Mode::Eh);
    while pos < span.len {
        let head = cx.read_avail(span.sub(pos, 12)).await?;
        let len32 = get_at::<u32>(&head, 0, endian).unwrap_or(0);
        if len32 == 0 && mode == Mode::Eh {
            cx.push(
                Node::new("Terminator")
                    .span(span.sub(pos, 4))
                    .value(hex(0u32, 32))
                    .desc("A zero length ends the frame information"),
            )
            .await;
            pos = pos.saturating_add(4);
            if let Some(rest) = (pos < span.len).then(|| span.tail(pos)) {
                cx.push(Node::new("Padding").span(rest).summary(size(rest.len)))
                    .await;
            }
            break;
        }
        let (length, header) = if len32 == 0xffff_ffff {
            (get_at::<u64>(&head, 4, endian).unwrap_or(0), 12usize)
        } else {
            (u64::from(len32), 4usize)
        };
        // `.debug_frame` CIE ids and pointers are as wide as the offsets.
        let id_size: usize = if mode == Mode::Debug && header == 12 {
            8
        } else {
            4
        };
        let total = to_u64(header).saturating_add(length);
        let record = span.sub(pos, total);
        let data = cx.read_avail(record.sub(0, RECORD_HEAD)).await?;
        let at = |a: usize, b: usize| record.sub(to_u64(a), to_u64(b.saturating_sub(a)));
        let id_at = header;
        let id = if id_size == 8 {
            get_at::<u64>(&data, to_u64(id_at), endian).unwrap_or(0)
        } else {
            get_at::<u32>(&data, to_u64(id_at), endian).map_or(0, u64::from)
        };
        let is_cie = match mode {
            Mode::Eh => id == 0,
            Mode::Debug => id == if id_size == 8 { u64::MAX } else { 0xffff_ffff },
        };
        let id_end = id_at.saturating_add(id_size);
        let id_bits = if id_size == 8 { 64 } else { 32 };
        let mut nodes = vec![
            Node::new("length")
                .span(at(0, header))
                .value(hex(length, if header == 4 { 32 } else { 64 })),
        ];
        let record_addr = section_addr.saturating_add(pos);
        let (node, end, cie, pc) = if is_cie {
            nodes.push(
                Node::new("CIE_id")
                    .span(at(id_at, id_end))
                    .value(hex(id, id_bits)),
            );
            let (cie, fields, summary, end) = parse_cie(&data, id_end, img, &at, record_addr, arch);
            cies.insert(pos, cie);
            nodes.extend(fields);
            (("CIE", summary), end, cie, None)
        } else {
            let cie_pos = match mode {
                Mode::Eh => pos.saturating_add(to_u64(id_at)).wrapping_sub(id),
                Mode::Debug => id,
            };
            nodes.push(
                Node::new("CIE_pointer")
                    .span(at(id_at, id_end))
                    .value(hex(id, id_bits))
                    .summary(format!("CIE at {cie_pos:#x}"))
                    .target(span.sub(cie_pos, 0)),
            );
            let cie = match cies.get(&cie_pos) {
                Some(c) => *c,
                None => {
                    // A CIE after its FDEs: read it on demand.
                    let cie_data = cx.read_avail(span.sub(cie_pos, RECORD_HEAD)).await?;
                    let cie_record = span.sub(cie_pos, RECORD_HEAD);
                    let cat =
                        |a: usize, b: usize| cie_record.sub(to_u64(a), to_u64(b.saturating_sub(a)));
                    let cie_header = match get_at::<u32>(&cie_data, 0, endian) {
                        Some(0xffff_ffff) => 12usize,
                        _ => 4,
                    };
                    let cie_id = if mode == Mode::Debug && cie_header == 12 {
                        8
                    } else {
                        4
                    };
                    let cie = parse_cie(
                        &cie_data,
                        cie_header.saturating_add(cie_id),
                        img,
                        &cat,
                        section_addr.saturating_add(cie_pos),
                        arch,
                    )
                    .0;
                    cies.insert(cie_pos, cie);
                    cie
                }
            };
            let mut r = Reader::at(&data, id_end);
            let s = r.pos();
            let addr_size = cie.address_size.unwrap_or(if img.wide() { 8 } else { 4 });
            let begin = match mode {
                Mode::Eh => encoded(
                    &mut r,
                    cie.fde_encoding,
                    img.wide(),
                    endian,
                    record_addr.saturating_add(to_u64(s)),
                ),
                Mode::Debug => address(&mut r, addr_size, endian),
            }
            .unwrap_or(0);
            let mut field = Node::new(match mode {
                Mode::Eh => "pc_begin",
                Mode::Debug => "initial_location",
            })
            .span(at(s, r.pos()))
            .value(hex(begin, 64))
            .summary(img.describe(begin));
            if let Some(t) = img.target(begin) {
                field = field.target(t);
            }
            nodes.push(field);
            let s = r.pos();
            let range = match mode {
                Mode::Eh => encoded(&mut r, cie.fde_encoding & 0x0f, img.wide(), endian, 0),
                Mode::Debug => address(&mut r, addr_size, endian),
            }
            .unwrap_or(0);
            nodes.push(
                Node::new(match mode {
                    Mode::Eh => "pc_range",
                    Mode::Debug => "address_range",
                })
                .span(at(s, r.pos()))
                .value(hex(range, 64)),
            );
            if cie.augmented {
                let s = r.pos();
                let len = r.uleb().unwrap_or(0);
                nodes.push(
                    Node::new("augmentation_length")
                        .span(at(s, r.pos()))
                        .value(uint(len, 64)),
                );
                let end = r.pos().saturating_add(to_usize(len));
                if cie.lsda_encoding != 0xff && len > 0 {
                    let s = r.pos();
                    let lsda = encoded(
                        &mut r,
                        cie.lsda_encoding,
                        img.wide(),
                        endian,
                        record_addr.saturating_add(to_u64(s)),
                    )
                    .unwrap_or(0);
                    nodes.push(
                        Node::new("lsda")
                            .span(at(s, r.pos()))
                            .value(hex(lsda, 64))
                            .summary(img.describe(lsda)),
                    );
                }
                r = Reader::at(&data, end);
            }
            (
                (
                    "FDE",
                    format!(
                        "{}..{:#x}",
                        img.describe(begin),
                        begin.saturating_add(range)
                    ),
                ),
                r.pos(),
                cie,
                Some(begin),
            )
        };
        let instructions = record.tail(to_u64(end));
        if instructions.len > 0 {
            let ctx = Cfi {
                span: instructions,
                code_align: cie.code_align,
                data_align: cie.data_align,
                address_size: cie.address_size.unwrap_or(if img.wide() { 8 } else { 4 }),
                fde_encoding: if mode == Mode::Eh {
                    Some(cie.fde_encoding)
                } else {
                    None
                },
                wide: img.wide(),
                endian,
                pc,
                arch,
            };
            nodes.push(
                Node::new("Call Frame Instructions")
                    .span(instructions)
                    .summary(size(instructions.len))
                    .lazy(cfi_instructions, ctx),
            );
        }
        let (name, summary) = node;
        cx.progress_in(span, record.end());
        cx.push(group(name, record, nodes).summary(summary)).await;
        if total == 0 {
            break;
        }
        pos = pos.saturating_add(total);
    }
    Ok(())
}

/// What decoding a record's call frame instructions needs.
#[derive(Clone, Copy, Debug)]
struct Cfi {
    span: Span,
    code_align: u64,
    data_align: i64,
    address_size: u8,
    /// `.eh_frame`'s pointer encoding for `DW_CFA_set_loc`.
    fde_encoding: Option<u8>,
    wide: bool,
    endian: Endian,
    /// The FDE's initial location (CIE instructions have none).
    pc: Option<u64>,
    /// For register names.
    arch: Arch,
}

/// Bytes read per instruction (an expression longer than this is shown
/// cut short and skipped).
const INSTRUCTION_WINDOW: u64 = 0x100;

/// The call frame instructions of a CIE or FDE, one node each, with
/// factored offsets multiplied out and the location they advance to.
async fn cfi_instructions(cx: Cx, c: Cfi) -> Result<()> {
    use crate::formats::executable::dwarf::expr::{Sizes, describe};
    use crate::formats::executable::dwarf::tables::cfa_name;
    let (mut pos, mut pc) = cx.resume::<(u64, Option<u64>)>().unwrap_or((0, c.pc));
    let sizes = Sizes {
        address: c.address_size,
        offset: if c.wide { 8 } else { 4 },
        endian: c.endian,
        arch: c.arch,
    };
    let factored = |v: u64| -> i64 {
        i64::try_from(v)
            .unwrap_or(i64::MAX)
            .saturating_mul(c.data_align)
    };
    while pos < c.span.len {
        let state = (pos, pc);
        cx.mark(move || state);
        let data = cx.read_avail(c.span.sub(pos, INSTRUCTION_WINDOW)).await?;
        let mut r = Reader::new(&data);
        let Some(op) = r.u8() else {
            break;
        };
        let name = cfa_name(op);
        let mut skip = 0u64;
        let advance = |delta: u64, pc: &mut Option<u64>| -> String {
            let d = delta.saturating_mul(c.code_align);
            match pc {
                Some(p) => {
                    *p = p.wrapping_add(d);
                    format!("{d} to {:#x}", *p)
                }
                None => format!("{d}"),
            }
        };
        let expression = |r: &mut Reader<'_>, skip: &mut u64| -> Option<String> {
            let len = r.uleb()?;
            let have = r.rest();
            let bytes = have.get(..to_usize(len)).unwrap_or(have);
            *skip = len.saturating_sub(to_u64(bytes.len()));
            r.bytes(bytes.len());
            Some(describe(bytes, sizes))
        };
        let reg = |n: u64| register(c.arch, n);
        let operands: Option<String> = match op >> 6 {
            1 => Some(advance(u64::from(op & 0x3f), &mut pc)),
            2 => r
                .uleb()
                .map(|off| format!("{} {:+}", reg(u64::from(op & 0x3f)), factored(off))),
            3 => Some(reg(u64::from(op & 0x3f))),
            _ => match op {
                0x00 | 0x0a | 0x0b | 0x2c | 0x2d => Some(String::new()),
                0x01 => {
                    let loc = match c.fde_encoding {
                        Some(enc) => encoded(&mut r, enc & 0x0f, c.wide, c.endian, 0),
                        None => address(&mut r, c.address_size, c.endian),
                    };
                    loc.map(|a| {
                        pc = Some(a);
                        format!("{a:#x}")
                    })
                }
                0x02 => r.u8().map(|d| advance(d.into(), &mut pc)),
                0x03 => r.int::<u16>(c.endian).map(|d| advance(d.into(), &mut pc)),
                0x04 => r.int::<u32>(c.endian).map(|d| advance(d.into(), &mut pc)),
                0x05 | 0x14 => (|| {
                    let n = r.uleb()?;
                    Some(format!("{} {:+}", reg(n), factored(r.uleb()?)))
                })(),
                0x06 | 0x07 | 0x08 | 0x0d => r.uleb().map(reg),
                0x09 => (|| {
                    let n = r.uleb()?;
                    Some(format!("{} {}", reg(n), reg(r.uleb()?)))
                })(),
                0x0c => (|| {
                    let n = r.uleb()?;
                    Some(format!("{} {:+}", reg(n), r.uleb()?))
                })(),
                0x0e => r.uleb().map(|off| format!("{off:+}")),
                0x0f => expression(&mut r, &mut skip),
                0x10 | 0x16 => (|| {
                    let n = r.uleb()?;
                    Some(format!("{} {}", reg(n), expression(&mut r, &mut skip)?))
                })(),
                0x11 | 0x12 | 0x15 => (|| {
                    let n = r.uleb()?;
                    let off = r.sleb()?.saturating_mul(c.data_align);
                    Some(format!("{} {off:+}", reg(n)))
                })(),
                0x13 => r
                    .sleb()
                    .map(|off| format!("{:+}", off.saturating_mul(c.data_align))),
                0x2e => r.uleb().map(|n| format!("{n}")),
                0x2f => (|| {
                    let n = r.uleb()?;
                    Some(format!(
                        "{} {:+}",
                        reg(n),
                        factored(r.uleb()?).saturating_neg()
                    ))
                })(),
                _ => None,
            },
        };
        let Some(operands) = operands else {
            cx.push(
                Node::new(name)
                    .span(c.span.sub(pos, 1))
                    .diag(Diagnostic::malformed("unknown or truncated instruction")),
            )
            .await;
            break;
        };
        let len = to_u64(r.pos()).saturating_add(skip);
        let mut node = Node::new(name).span(c.span.sub(pos, len));
        if !operands.is_empty() {
            node = node.value(text(operands));
        }
        cx.push(node).await;
        pos = pos.saturating_add(len.max(1));
    }
    Ok(())
}

/// Size of a fixed-size `DW_EH_PE_*` value, if it has one.
fn encoded_size(enc: u8, wide: bool) -> Option<u64> {
    match enc & 0x0f {
        0x00 => Some(if wide { 8 } else { 4 }),
        0x02 | 0x0a => Some(2),
        0x03 | 0x0b => Some(4),
        0x04 | 0x0c => Some(8),
        _ => None,
    }
}

/// Reads an encoded pointer at `r`; `here` is its address and `base` the
/// address `datarel` values are relative to.
fn pointer(r: &mut Reader<'_>, enc: u8, img: &dyn Image, here: u64, base: u64) -> Option<u64> {
    let v = encoded(r, enc & 0x7f, img.wide(), img.endian(), here)?;
    Some(if enc & 0x70 == 0x30 {
        base.wrapping_add(v)
    } else {
        v
    })
}

impl<T: Image + ?Sized> Image for Arc<T> {
    fn endian(&self) -> Endian {
        (**self).endian()
    }

    fn wide(&self) -> bool {
        (**self).wide()
    }

    fn describe(&self, addr: u64) -> String {
        (**self).describe(addr)
    }

    fn target(&self, addr: u64) -> Option<Span> {
        (**self).target(addr)
    }

    fn arch(&self, eh: bool) -> Arch {
        (**self).arch(eh)
    }
}

/// Most `.eh_frame_hdr` table entries read at once.
const TABLE_BATCH: u64 = 4096;

/// Walks an `.eh_frame_hdr` section at address `section_addr`: its header
/// (encodings, the `.eh_frame` pointer, the FDE count), then the sorted
/// table of initial locations and FDE addresses (usually datarel: relative
/// to the section).
pub(crate) async fn header<I: Image + Clone + Send + Sync + 'static>(
    cx: &Cx,
    img: I,
    span: Span,
    section_addr: u64,
) -> Result<()> {
    let head = cx.read_avail(span.sub(0, 4 + 16)).await?;
    let mut r = Reader::at(&head, 0);
    let (Some(version), Some(ptr_enc), Some(count_enc), Some(table_enc)) =
        (r.u8(), r.u8(), r.u8(), r.u8())
    else {
        return Err(Diagnostic::truncated(span, span.len));
    };
    let at = |a: usize, b: usize| span.sub(to_u64(a), to_u64(b.saturating_sub(a)));
    cx.emit(Node::new("version").span(at(0, 1)).value(uint(version, 8)));
    for (i, (name, enc)) in [
        ("eh_frame_ptr_enc", ptr_enc),
        ("fde_count_enc", count_enc),
        ("table_enc", table_enc),
    ]
    .into_iter()
    .enumerate()
    {
        cx.emit(
            Node::new(name)
                .span(at(i.saturating_add(1), i.saturating_add(2)))
                .value(hex(enc, 8))
                .summary(encoding_name(enc)),
        );
    }
    if version != 1 {
        cx.diag(Diagnostic::unsupported(format!(
            ".eh_frame_hdr version {version}"
        )));
        return Ok(());
    }
    let s = r.pos();
    let here = section_addr.saturating_add(to_u64(s));
    if let Some(frame) = pointer(&mut r, ptr_enc, &img, here, section_addr) {
        let mut node = Node::new("eh_frame_ptr")
            .span(at(s, r.pos()))
            .value(hex(frame, 64))
            .summary(img.describe(frame));
        if let Some(t) = img.target(frame) {
            node = node.target(t);
        }
        cx.emit(node);
    }
    let s = r.pos();
    let here = section_addr.saturating_add(to_u64(s));
    let Some(count) = pointer(&mut r, count_enc, &img, here, section_addr) else {
        return Ok(());
    };
    cx.emit(
        Node::new("fde_count")
            .span(at(s, r.pos()))
            .value(uint(count, 64)),
    );
    let Some(field) = encoded_size(table_enc, img.wide()) else {
        if count > 0 {
            cx.diag(Diagnostic::unsupported(format!(
                "table encoding {}",
                encoding_name(table_enc)
            )));
        }
        return Ok(());
    };
    let entry = field.saturating_mul(2);
    let start = to_u64(r.pos());
    let table = span.tail(start);
    let n = count.min(table.len.checked_div(entry).unwrap_or(0));
    let table = table.sub(0, n.saturating_mul(entry));
    let mut node = Node::new("Table")
        .span(table)
        .summary(plural(n, "entry"))
        .lazy(
            self::table::<I>,
            (
                img,
                table,
                section_addr,
                section_addr.saturating_add(start),
                table_enc,
                n,
            ),
        );
    if n < count {
        node = node.diag(Diagnostic::truncated(table, n.saturating_mul(entry)));
    }
    cx.emit(node);
    Ok(())
}

/// The `.eh_frame_hdr` table: `n` pairs of `enc`-encoded initial location
/// and FDE address, the first at address `table_addr`.
async fn table<I: Image + Clone + Send + Sync + 'static>(
    cx: Cx,
    (img, table, section_addr, table_addr, enc, n): (I, Span, u64, u64, u8, u64),
) -> Result<()> {
    let field = encoded_size(enc, img.wide()).unwrap_or(4);
    let entry = field.saturating_mul(2);
    cx.set_count(Count::Exact(n));
    let mut i = 0u64;
    while i < n {
        let batch = n.saturating_sub(i).min(TABLE_BATCH);
        let at = i.saturating_mul(entry);
        let data = cx
            .read(table.sub_exact(at, batch.saturating_mul(entry))?)
            .await?;
        for k in 0..batch {
            let rel = at.saturating_add(k.saturating_mul(entry));
            let mut r = Reader::at(&data, to_usize(k.saturating_mul(entry)));
            let here = table_addr.saturating_add(rel);
            let loc = pointer(&mut r, enc, &img, here, section_addr).unwrap_or(0);
            let here = here.saturating_add(field);
            let fde = pointer(&mut r, enc, &img, here, section_addr).unwrap_or(0);
            let mut node = Node::new(format!("[{}]", i.saturating_add(k)))
                .span(table.sub(rel, entry))
                .value(hex(fde, 64))
                .summary(format!("{} → FDE", img.describe(loc)));
            if let Some(t) = img.target(fde) {
                node = node.target(t);
            }
            cx.push(node).await;
        }
        i = i.saturating_add(batch);
    }
    Ok(())
}
