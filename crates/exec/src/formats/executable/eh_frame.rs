//! DWARF call frame information as found in `.eh_frame` (ELF) and
//! `__eh_frame` (Mach-O): CIE and FDE headers, with pointers decoded by
//! their `DW_EH_PE_*` encodings, and the ELF `.eh_frame_hdr` lookup table.
//! The call frame instructions are not decoded.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::binutil::{Reader, get_at};
use crate::formats::util::fmt::size;
use crate::formats::util::val::{hex, text, uint};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

/// What the walker needs from the image the section belongs to.
pub(crate) trait Image {
    fn endian(&self) -> Endian;
    /// 64-bit pointers.
    fn wide(&self) -> bool;
    /// A label for an address (the symbol or section it falls in).
    fn describe(&self, addr: u64) -> String;
    /// The file bytes at an address, for navigation.
    fn target(&self, addr: u64) -> Option<Span>;
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
) -> (Cie, Vec<Node>, String, usize) {
    let mut cie = Cie {
        fde_encoding: 0,
        lsda_encoding: 0xff,
        augmented: false,
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
        nodes.push(
            Node::new("code_alignment_factor")
                .span(at(s, r.pos()))
                .value(uint(v, 64)),
        );
    }
    s = r.pos();
    if let Some(v) = r.sleb() {
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
        nodes.push(
            Node::new("return_address_register")
                .span(at(s, r.pos()))
                .value(uint(v, 64)),
        );
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
    let mut cies: BTreeMap<u64, Cie> = BTreeMap::new();
    let mut pos = 0u64;
    while pos < span.len {
        let head = cx.read_avail(span.sub(pos, 12)).await?;
        let len32 = get_at::<u32>(&head, 0, img.endian()).unwrap_or(0);
        if len32 == 0 {
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
            (get_at::<u64>(&head, 4, img.endian()).unwrap_or(0), 12usize)
        } else {
            (u64::from(len32), 4usize)
        };
        let total = to_u64(header).saturating_add(length);
        let record = span.sub(pos, total);
        let data = cx.read_avail(record.sub(0, RECORD_HEAD)).await?;
        let at = |a: usize, b: usize| record.sub(to_u64(a), to_u64(b.saturating_sub(a)));
        let id_at = header;
        let id = get_at::<u32>(&data, to_u64(id_at), img.endian()).unwrap_or(0);
        let mut nodes = vec![
            Node::new("length")
                .span(at(0, header))
                .value(hex(length, if header == 4 { 32 } else { 64 })),
        ];
        let record_addr = section_addr.saturating_add(pos);
        let (node, end) = if id == 0 {
            nodes.push(
                Node::new("CIE_id")
                    .span(at(id_at, id_at.saturating_add(4)))
                    .value(hex(0u32, 32)),
            );
            let (cie, fields, summary, end) =
                parse_cie(&data, id_at.saturating_add(4), img, &at, record_addr);
            cies.insert(pos, cie);
            nodes.extend(fields);
            (("CIE", summary), end)
        } else {
            let cie_pos = pos.saturating_add(to_u64(id_at)).wrapping_sub(id.into());
            nodes.push(
                Node::new("CIE_pointer")
                    .span(at(id_at, id_at.saturating_add(4)))
                    .value(hex(id, 32))
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
                    let cie = parse_cie(
                        &cie_data,
                        8,
                        img,
                        &cat,
                        section_addr.saturating_add(cie_pos),
                    )
                    .0;
                    cies.insert(cie_pos, cie);
                    cie
                }
            };
            let mut r = Reader::at(&data, id_at.saturating_add(4));
            let s = r.pos();
            let begin = encoded(
                &mut r,
                cie.fde_encoding,
                img.wide(),
                img.endian(),
                record_addr.saturating_add(to_u64(s)),
            )
            .unwrap_or(0);
            let mut field = Node::new("pc_begin")
                .span(at(s, r.pos()))
                .value(hex(begin, 64))
                .summary(img.describe(begin));
            if let Some(t) = img.target(begin) {
                field = field.target(t);
            }
            nodes.push(field);
            let s = r.pos();
            let range =
                encoded(&mut r, cie.fde_encoding & 0x0f, img.wide(), img.endian(), 0).unwrap_or(0);
            nodes.push(
                Node::new("pc_range")
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
                        img.endian(),
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
            )
        };
        let instructions = record.tail(to_u64(end));
        if instructions.len > 0 {
            nodes.push(
                Node::new("Call Frame Instructions")
                    .span(instructions)
                    .summary(size(instructions.len)),
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
        .summary(format!("{n} entries"))
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
