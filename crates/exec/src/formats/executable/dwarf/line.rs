//! `.debug_line`: line number program headers (versions 2 to 5, with the
//! version 5 entry formats) and the programs, run through the line state
//! machine one opcode at a time so each row is shown where it is made.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::binutil::Reader;
use crate::formats::util::val::{hex, int, name_or, text, uint};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::tables::{FORMS, LINE_CONTENT, LINE_EXTENDED, LINE_STANDARD};
use super::{Dwarf, Sec, initial_length, uint_of};

/// A line program header's fields the program and the entry lists need.
#[derive(Clone, Debug, Default)]
struct Header {
    offset: u64,
    end: u64,
    version: u16,
    offset_size: u8,
    address_size: u8,
    min_inst: u8,
    max_ops: u8,
    default_is_stmt: bool,
    line_base: i8,
    line_range: u8,
    opcode_base: u8,
    std_lengths: Vec<u8>,
    /// Section offsets of the directory and file lists (v2-4: the string
    /// lists; v5: the formats, count and entries), and of the program.
    dirs: u64,
    files: u64,
    program: u64,
}

/// Reads a header (the whole of it, up to its `header_length`).
async fn header(cx: &Cx, dw: &Dwarf, offset: u64) -> Result<(Header, Vec<u8>)> {
    let section = dw.span_or_empty(Sec::Line);
    let head = dw.read(cx, Sec::Line, offset, 24).await?;
    let e = dw.endian;
    let (length, offset_size, at) = initial_length(&head, e)
        .ok_or_else(|| Diagnostic::malformed("bad unit length").at(section.sub(offset, 4)))?;
    let end = offset
        .saturating_add(at)
        .saturating_add(length)
        .min(section.len);
    let version = uint_of(head.get(to_usize(at)..).unwrap_or_default(), 2, e).unwrap_or(0);
    // The fixed part before header_length.
    let fixed = at.saturating_add(if version >= 5 { 4 } else { 2 });
    let hl = uint_of(
        head.get(to_usize(fixed)..).unwrap_or_default(),
        offset_size,
        e,
    )
    .unwrap_or(0);
    let program = offset
        .saturating_add(fixed)
        .saturating_add(offset_size.into())
        .saturating_add(hl);
    if program > end {
        return Err(Diagnostic::malformed("header_length runs past the unit")
            .at(section.sub(offset, end.saturating_sub(offset))));
    }
    let data = dw
        .read(cx, Sec::Line, offset, program.saturating_sub(offset))
        .await?;
    let mut r = Reader::at(&data, to_usize(fixed));
    let mut h = Header {
        offset,
        end,
        version: u16::try_from(version).unwrap_or(0),
        offset_size,
        address_size: dw.address_size,
        program,
        ..Header::default()
    };
    if version >= 5 {
        r = Reader::at(&data, to_usize(at.saturating_add(2)));
        h.address_size = r.u8().unwrap_or(0);
        r.u8();
    }
    r.bytes(offset_size.into());
    let short = || Diagnostic::truncated(section.sub(offset, program.saturating_sub(offset)), 0);
    h.min_inst = r.u8().ok_or_else(short)?;
    h.max_ops = if version >= 4 {
        r.u8().ok_or_else(short)?
    } else {
        1
    };
    h.default_is_stmt = r.u8().ok_or_else(short)? != 0;
    h.line_base = i8::from_ne_bytes([r.u8().ok_or_else(short)?]);
    h.line_range = r.u8().ok_or_else(short)?;
    h.opcode_base = r.u8().ok_or_else(short)?;
    h.std_lengths = r
        .bytes(usize::from(h.opcode_base.saturating_sub(1)))
        .ok_or_else(short)?
        .to_vec();
    h.dirs = offset.saturating_add(to_u64(r.pos()));
    if version >= 5 {
        // Skip the directory formats, count and entries to find the files.
        let formats = formats(&mut r).ok_or_else(short)?;
        let count = r.uleb().ok_or_else(short)?;
        for _ in 0..count {
            for &(_, form) in &formats {
                skip_form(&mut r, form, offset_size, e).ok_or_else(short)?;
            }
            if r.at_end() {
                break;
            }
        }
    } else {
        while let Some(s) = r.cstr() {
            if s.is_empty() {
                break;
            }
        }
    }
    h.files = offset.saturating_add(to_u64(r.pos()));
    cx.charge(to_u64(data.len()) / 64).await;
    Ok((h, data))
}

/// A v5 entry format list: (content type, form) pairs.
fn formats(r: &mut Reader<'_>) -> Option<Vec<(u64, u64)>> {
    let n = r.u8()?;
    let mut out = Vec::new();
    for _ in 0..n {
        out.push((r.uleb()?, r.uleb()?));
    }
    Some(out)
}

/// Skips one value of `form` (the forms entry formats use).
fn skip_form(
    r: &mut Reader<'_>,
    form: u64,
    offset_size: u8,
    e: crate::fields::Endian,
) -> Option<()> {
    form_value(r, form, offset_size, e).map(|_| ())
}

enum EntryVal {
    U(u64),
    Str(String),
    Bytes(Vec<u8>),
}

fn form_value(
    r: &mut Reader<'_>,
    form: u64,
    offset_size: u8,
    e: crate::fields::Endian,
) -> Option<EntryVal> {
    let fixed = |r: &mut Reader<'_>, n: u8| uint_of(r.bytes(usize::from(n))?, n, e);
    Some(match form {
        0x08 => EntryVal::Str(String::from_utf8_lossy(r.cstr()?).into_owned()),
        0x0e | 0x1f | 0x17 => EntryVal::U(fixed(r, offset_size)?),
        0x0b | 0x25 => EntryVal::U(fixed(r, 1)?),
        0x05 | 0x26 => EntryVal::U(fixed(r, 2)?),
        0x27 => EntryVal::U(fixed(r, 3)?),
        0x06 | 0x28 => EntryVal::U(fixed(r, 4)?),
        0x07 => EntryVal::U(fixed(r, 8)?),
        0x0f | 0x1a => EntryVal::U(r.uleb()?),
        0x1e => EntryVal::Bytes(r.bytes(16)?.to_vec()),
        0x09 => {
            let n = usize::try_from(r.uleb()?).ok()?;
            EntryVal::Bytes(r.bytes(n)?.to_vec())
        }
        _ => return None,
    })
}

/// Expander for `.debug_line`: one node per line table.
pub(super) async fn tables(cx: &Cx, dw: &Arc<Dwarf>) -> Result<()> {
    let Some(section) = dw.span(Sec::Line) else {
        return Ok(());
    };
    let mut pos = cx.resume::<u64>().unwrap_or(0);
    while pos < section.len {
        cx.mark(move || pos);
        cx.progress_in(section, pos);
        let head = dw.read(cx, Sec::Line, pos, 16).await?;
        let Some((length, _, at)) = initial_length(&head, dw.endian) else {
            cx.diag(Diagnostic::malformed("bad unit length").at(section.sub(pos, 4)));
            break;
        };
        let end = pos.saturating_add(at).saturating_add(length);
        let span = section.sub(pos, end.saturating_sub(pos));
        let version =
            uint_of(head.get(to_usize(at)..).unwrap_or_default(), 2, dw.endian).unwrap_or(0);
        let node = Node::new(format!("Line table at {pos:#x}"))
            .span(span)
            .summary(format!("version {version}, {:#x} bytes", span.len))
            .lazy(table, (dw.clone(), pos));
        cx.push(node).await;
        if end <= pos {
            break;
        }
        pos = end;
    }
    Ok(())
}

/// One line table: header fields, directories, files and the program.
async fn table(cx: Cx, (dw, offset): (Arc<Dwarf>, u64)) -> Result<()> {
    let section = dw.span_or_empty(Sec::Line);
    let (h, data) = header(&cx, &dw, offset).await?;
    let e = dw.endian;
    let field = |name: &'static str, a: u64, b: u64, value: Value| {
        Node::new(name)
            .span(section.sub(offset.saturating_add(a), b.saturating_sub(a)))
            .value(value)
    };
    let (_, offset_size, at) = initial_length(&data, e).unwrap_or((0, 4, 4));
    let length = h.end.saturating_sub(offset).saturating_sub(at);
    cx.emit(
        field("unit_length", 0, at, hex(length, 64)).summary(if offset_size == 8 {
            "DWARF64"
        } else {
            "DWARF32"
        }),
    );
    cx.emit(field(
        "version",
        at,
        at.saturating_add(2),
        uint(h.version, 16),
    ));
    let mut p = at.saturating_add(2);
    if h.version >= 5 {
        cx.emit(field(
            "address_size",
            p,
            p.saturating_add(1),
            uint(h.address_size, 8),
        ));
        let seg = data
            .get(to_usize(p.saturating_add(1)))
            .copied()
            .unwrap_or(0);
        cx.emit(field(
            "seg_select_size",
            p.saturating_add(1),
            p.saturating_add(2),
            uint(seg, 8),
        ));
        p = p.saturating_add(2);
    }
    let hl = h
        .program
        .saturating_sub(offset)
        .saturating_sub(p)
        .saturating_sub(offset_size.into());
    let q = p.saturating_add(offset_size.into());
    cx.emit(field("header_length", p, q, hex(hl, 64)));
    let mut p = q;
    let mut one = |name: &'static str, value: Value| {
        let n = field(name, p, p.saturating_add(1), value);
        p = p.saturating_add(1);
        n
    };
    cx.emit(one("minimum_instruction_length", uint(h.min_inst, 8)));
    if h.version >= 4 {
        cx.emit(one(
            "maximum_operations_per_instruction",
            uint(h.max_ops, 8),
        ));
    }
    cx.emit(one("default_is_stmt", Value::Bool(h.default_is_stmt)));
    cx.emit(one("line_base", int(h.line_base, 8)));
    cx.emit(one("line_range", uint(h.line_range, 8)));
    cx.emit(one("opcode_base", uint(h.opcode_base, 8)));
    let lengths = h
        .std_lengths
        .iter()
        .enumerate()
        .map(|(i, &n)| {
            let op = u64::try_from(i).unwrap_or(0).saturating_add(1);
            Node::new(name_or(LINE_STANDARD, op, "opcode"))
                .span(
                    section.sub(
                        offset
                            .saturating_add(p)
                            .saturating_add(op)
                            .saturating_sub(1),
                        1,
                    ),
                )
                .value(uint(n, 8))
        })
        .collect::<Vec<_>>();
    if !lengths.is_empty() {
        cx.emit(
            Node::new("standard_opcode_lengths")
                .span(section.sub(offset.saturating_add(p), to_u64(lengths.len())))
                .lazy(crate::formats::util::arcutil::push_nodes, Arc::new(lengths)),
        );
    }
    let h = Arc::new(h);
    cx.emit(
        Node::new("include_directories")
            .span(section.sub(h.dirs, h.files.saturating_sub(h.dirs)))
            .lazy(entries, (dw.clone(), h.clone(), false)),
    );
    cx.emit(
        Node::new("file_names")
            .span(section.sub(h.files, h.program.saturating_sub(h.files)))
            .lazy(entries, (dw.clone(), h.clone(), true)),
    );
    let program = section.sub(h.program, h.end.saturating_sub(h.program));
    cx.emit(
        Node::new("Program")
            .span(program)
            .summary(format!("{:#x} bytes", program.len))
            .lazy(self::program, (dw.clone(), h)),
    );
    Ok(())
}

/// The include directories (`files == false`) or file names of a header.
async fn entries(cx: Cx, (dw, h, files): (Arc<Dwarf>, Arc<Header>, bool)) -> Result<()> {
    let section = dw.span_or_empty(Sec::Line);
    let data = dw
        .read(&cx, Sec::Line, h.offset, h.program.saturating_sub(h.offset))
        .await?;
    let e = dw.endian;
    let start = if files { h.files } else { h.dirs };
    let mut r = Reader::at(&data, to_usize(start.saturating_sub(h.offset)));
    let span_of = |a: usize, b: usize| {
        section.sub(
            h.offset.saturating_add(to_u64(a)),
            to_u64(b.saturating_sub(a)),
        )
    };
    let first = if h.version >= 5 { 0u64 } else { 1 };
    let mut index = first;
    if h.version >= 5 {
        let Some(formats) = formats(&mut r) else {
            return Err(Diagnostic::truncated(section.sub(start, 1), 0));
        };
        let Some(count) = r.uleb() else {
            return Err(Diagnostic::truncated(section.sub(start, 1), 0));
        };
        for _ in 0..count {
            let s = r.pos();
            let mut fields = Vec::new();
            let mut name = String::new();
            for &(content, form) in &formats {
                let fs = r.pos();
                let Some(v) = form_value(&mut r, form, h.offset_size, e) else {
                    return Err(Diagnostic::truncated(span_of(fs, data.len()), 0));
                };
                let label = name_or(LINE_CONTENT, content, "DW_LNCT");
                let form_name = name_or(FORMS, form, "DW_FORM");
                let mut node = Node::new(label).span(span_of(fs, r.pos()));
                let mut summary = form_name.clone();
                node = match v {
                    EntryVal::Str(s) => {
                        if content == 1 {
                            name = s.clone();
                        }
                        node.value(text(s))
                    }
                    EntryVal::Bytes(b) => node.value(Value::Bytes(b)),
                    EntryVal::U(v) => {
                        let string = match form {
                            0x1f => dw.string(&cx, Sec::LineStr, v).await,
                            0x0e => dw.string(&cx, Sec::Str, v).await,
                            _ => None,
                        };
                        match string {
                            Some(s) => {
                                summary = format!("{form_name} at {v:#x}");
                                if content == 1 {
                                    name = s.clone();
                                }
                                node.value(text(s))
                            }
                            None => node.value(uint(v, 64)),
                        }
                    }
                };
                fields.push(node.summary(summary));
            }
            let mut node = Node::new(format!("[{index}]")).span(span_of(s, r.pos()));
            if !name.is_empty() {
                node = node.value(text(name));
            }
            if !fields.is_empty() {
                node = node.lazy(crate::formats::util::arcutil::push_nodes, Arc::new(fields));
            }
            cx.push(node).await;
            index = index.saturating_add(1);
            if r.at_end() {
                break;
            }
        }
        return Ok(());
    }
    loop {
        let s = r.pos();
        let Some(name) = r.cstr() else {
            cx.diag(Diagnostic::truncated(span_of(s, data.len()), 0));
            break;
        };
        if name.is_empty() {
            break;
        }
        let name = String::from_utf8_lossy(name).into_owned();
        let mut node = Node::new(format!("[{index}]"));
        if files {
            let n = r.pos();
            let dir = r.uleb();
            let d = r.pos();
            let time = r.uleb();
            let t = r.pos();
            let size = r.uleb();
            let (Some(dir), Some(time), Some(size)) = (dir, time, size) else {
                cx.diag(Diagnostic::truncated(span_of(s, data.len()), 0));
                break;
            };
            let fields = vec![
                Node::new("name")
                    .span(span_of(s, n))
                    .value(text(name.clone())),
                Node::new("dir_index")
                    .span(span_of(n, d))
                    .value(uint(dir, 64)),
                Node::new("mod_time")
                    .span(span_of(d, t))
                    .value(hex(time, 64)),
                Node::new("length")
                    .span(span_of(t, r.pos()))
                    .value(uint(size, 64)),
            ];
            node = node
                .summary(format!("directory {dir}"))
                .lazy(crate::formats::util::arcutil::push_nodes, Arc::new(fields));
        }
        cx.push(node.span(span_of(s, r.pos())).value(text(name)))
            .await;
        index = index.saturating_add(1);
    }
    Ok(())
}

/// The line state machine's registers.
#[derive(Clone, Copy, Debug)]
struct Regs {
    address: u64,
    op_index: u64,
    file: u64,
    line: u64,
    column: u64,
    is_stmt: bool,
    basic_block: bool,
    prologue_end: bool,
    epilogue_begin: bool,
    isa: u64,
    discriminator: u64,
}

impl Regs {
    fn new(h: &Header) -> Self {
        Regs {
            address: 0,
            op_index: 0,
            file: 1,
            line: 1,
            column: 0,
            is_stmt: h.default_is_stmt,
            basic_block: false,
            prologue_end: false,
            epilogue_begin: false,
            isa: 0,
            discriminator: 0,
        }
    }

    /// The row a copy/special opcode appends, as text.
    fn row(&self, end: bool) -> String {
        let mut s = format!(
            "row {:#x} line {} column {} file {}",
            self.address, self.line, self.column, self.file
        );
        for (on, flag) in [
            (self.is_stmt, " is_stmt"),
            (self.basic_block, " basic_block"),
            (self.prologue_end, " prologue_end"),
            (self.epilogue_begin, " epilogue_begin"),
            (end, " end_sequence"),
        ] {
            if on {
                s.push_str(flag);
            }
        }
        if self.discriminator != 0 {
            s.push_str(&format!(" discriminator {}", self.discriminator));
        }
        s
    }

    /// Advances by `n` operations.
    fn advance(&mut self, h: &Header, n: u64) -> u64 {
        let min = u64::from(h.min_inst);
        if h.max_ops <= 1 {
            let d = n.saturating_mul(min);
            self.address = self.address.wrapping_add(d);
            d
        } else {
            let max = u64::from(h.max_ops);
            let total = self.op_index.saturating_add(n);
            let d = min.saturating_mul(total.checked_div(max).unwrap_or(0));
            self.address = self.address.wrapping_add(d);
            self.op_index = total.checked_rem(max).unwrap_or(0);
            d
        }
    }

    fn reset_after_row(&mut self) {
        self.basic_block = false;
        self.prologue_end = false;
        self.epilogue_begin = false;
        self.discriminator = 0;
    }
}

/// The program: one node per opcode, with the row it appends.
async fn program(cx: Cx, (dw, h): (Arc<Dwarf>, Arc<Header>)) -> Result<()> {
    let section = dw.span_or_empty(Sec::Line);
    let e = dw.endian;
    let (mut pos, mut regs) = cx
        .resume::<(u64, Regs)>()
        .unwrap_or((h.program, Regs::new(&h)));
    while pos < h.end {
        let state = (pos, regs);
        cx.mark(move || state);
        let data = dw
            .read(&cx, Sec::Line, pos, 32.min(h.end.saturating_sub(pos)))
            .await?;
        let mut r = Reader::new(&data);
        let Some(op) = r.u8() else {
            break;
        };
        let mut name: String;
        let mut detail = String::new();
        let mut row = None;
        let mut skip_to = None;
        if op >= h.opcode_base {
            let adjusted = op.saturating_sub(h.opcode_base);
            if h.line_range == 0 {
                cx.diag(Diagnostic::malformed("line_range is zero").at(section.sub(pos, 1)));
                break;
            }
            let ops = u64::from(adjusted.checked_div(h.line_range).unwrap_or(0));
            let dl = i64::from(h.line_base)
                .saturating_add(i64::from(adjusted.checked_rem(h.line_range).unwrap_or(0)));
            let da = regs.advance(&h, ops);
            regs.line = regs.line.saturating_add_signed(dl);
            name = format!("special opcode {op:#04x}");
            detail = format!("address += {da}, line += {dl}");
            row = Some(regs.row(false));
            regs.reset_after_row();
        } else if op == 0 {
            let len = r.uleb();
            let body = r.pos();
            let Some(len) = len else {
                cx.diag(Diagnostic::truncated(
                    section.sub(pos, to_u64(data.len())),
                    0,
                ));
                break;
            };
            let sub = r.u8().unwrap_or(0);
            name = name_or(LINE_EXTENDED, sub.into(), "DW_LNE");
            skip_to = Some(pos.saturating_add(to_u64(body)).saturating_add(len));
            match sub {
                0x01 => {
                    row = Some(regs.row(true));
                    regs = Regs::new(&h);
                }
                0x02 => {
                    let n = u8::try_from(len.saturating_sub(1)).unwrap_or(0);
                    if let Some(a) = r.bytes(usize::from(n)).and_then(|b| uint_of(b, n, e)) {
                        regs.address = a;
                        regs.op_index = 0;
                        detail = format!("{a:#x}");
                    }
                }
                0x04 => {
                    if let Some(d) = r.uleb() {
                        regs.discriminator = d;
                        detail = format!("{d}");
                    }
                }
                0x03 => {
                    if let Some(s) = r.cstr() {
                        detail = String::from_utf8_lossy(s).into_owned();
                    }
                }
                _ => {}
            }
        } else {
            name = name_or(LINE_STANDARD, op.into(), "DW_LNS");
            match op {
                0x01 => {
                    row = Some(regs.row(false));
                    regs.reset_after_row();
                }
                0x02 => {
                    let n = r.uleb().unwrap_or(0);
                    let da = regs.advance(&h, n);
                    detail = format!("address += {da}");
                }
                0x03 => {
                    let d = r.sleb().unwrap_or(0);
                    regs.line = regs.line.saturating_add_signed(d);
                    detail = format!("line {} ({d:+})", regs.line);
                }
                0x04 => {
                    regs.file = r.uleb().unwrap_or(0);
                    detail = format!("{}", regs.file);
                }
                0x05 => {
                    regs.column = r.uleb().unwrap_or(0);
                    detail = format!("{}", regs.column);
                }
                0x06 => regs.is_stmt = !regs.is_stmt,
                0x07 => regs.basic_block = true,
                0x08 => {
                    let adjusted = 255u8.saturating_sub(h.opcode_base);
                    let ops = u64::from(adjusted.checked_div(h.line_range).unwrap_or(0));
                    let da = regs.advance(&h, ops);
                    detail = format!("address += {da}");
                }
                0x09 => {
                    let d = r.bytes(2).and_then(|b| uint_of(b, 2, e)).unwrap_or(0);
                    regs.address = regs.address.wrapping_add(d);
                    regs.op_index = 0;
                    detail = format!("address += {d}");
                }
                0x0a => regs.prologue_end = true,
                0x0b => regs.epilogue_begin = true,
                0x0c => {
                    regs.isa = r.uleb().unwrap_or(0);
                    detail = format!("{}", regs.isa);
                }
                _ => {
                    // An opcode this version does not define: skip the
                    // operands the header says it has.
                    let n = h
                        .std_lengths
                        .get(usize::from(op.saturating_sub(1)))
                        .copied()
                        .unwrap_or(0);
                    for _ in 0..n {
                        r.uleb();
                    }
                    name = format!("opcode {op:#04x}");
                }
            }
        }
        let next = skip_to.unwrap_or_else(|| pos.saturating_add(to_u64(r.pos())));
        let next = if next <= pos {
            pos.saturating_add(1)
        } else {
            next
        };
        let span: Span = section.sub(pos, next.min(h.end).saturating_sub(pos));
        let mut node = Node::new(name).span(span).summary(format!("{pos:#010x}"));
        let value = match (detail.is_empty(), row) {
            (true, None) => None,
            (false, None) => Some(detail),
            (true, Some(row)) => Some(row),
            (false, Some(row)) => Some(format!("{detail}: {row}")),
        };
        if let Some(v) = value {
            node = node.value(text(v));
        }
        cx.push(node).await;
        pos = next;
    }
    Ok(())
}
