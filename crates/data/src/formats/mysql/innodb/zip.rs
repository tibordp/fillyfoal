//! Compressed index pages (`ROW_FORMAT=COMPRESSED`, `page0zip.cc` in MySQL
//! and MariaDB), rebuilt into the uncompressed page InnoDB works on.
//!
//! A compressed page keeps the FIL header and the index page header as
//! they are. A zlib stream follows: first, flushed into a deflate block
//! of its own, a description of the index's fields (enough to find field
//! boundaries without the table definition), then the page's record heap
//! without the records' 5-byte headers and without the columns kept
//! uncompressed at the end of the page. After the stream comes the
//! modification log: records written since the page was last compressed,
//! each as its heap number, its extra bytes backwards and its data. The
//! page ends with the dense directory (two bytes per record in the heap,
//! user records in key order and then the free list, with "owned" and
//! "deleted" flags) and, before it, per record in heap order, the columns
//! stored uncompressed: `DB_TRX_ID` and `DB_ROLL_PTR` on clustered index
//! leaves (and the 20-byte references of off-page columns), the child
//! page number on node pointer pages.
//!
//! [`decompress`] follows `page_zip_decompress_low` step by step:
//! directory, system records, stream, record headers, log, uncompressed
//! columns.

use std::sync::Arc;

use super::dict::{Field, IndexDef, Ty};
use super::index;
use crate::bytes::{to_u64, to_usize, u16_be, u32_be};
use crate::codec::inflate::{Inflate, Step};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::span::{Origin, Span};

const PAGE_DATA: usize = 94;
/// Where the record heap starts (after the supremum).
const ZIP_START: usize = 120;
const INFIMUM: usize = 99;
const SUPREMUM: usize = 112;
/// The compact record header.
const EXTRA: usize = 5;
const SLOT_MASK: u16 = 0x3fff;
const SLOT_OWNED: u16 = 0x4000;
const SLOT_DEL: u16 = 0x8000;
/// `DB_TRX_ID` and `DB_ROLL_PTR`.
const TRX_ROLL: usize = 13;
const NODE_PTR: usize = 4;
const EXTERN_REF: usize = 20;
/// The uncompressed page's trailer (`PAGE_DIR`).
const PAGE_DIR: usize = 8;

/// What kind of records a compressed page holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Clustered index leaf: transaction ID and roll pointer kept apart.
    Clustered,
    /// Secondary index leaf: everything compressed.
    Secondary,
    /// Node pointers: child page numbers kept apart.
    NodePtr,
}

/// One modification log entry.
#[derive(Clone, Debug)]
pub struct LogEntry {
    /// Offset in the compressed page and length.
    pub at: u64,
    pub len: u64,
    pub heap_no: u64,
    /// The record's data was cleared (deleted and purged).
    pub cleared: bool,
}

/// A compressed page, decoded.
#[derive(Debug)]
pub struct Zip {
    /// The uncompressed page.
    pub page: Vec<u8>,
    /// The fields as the page describes them.
    pub def: Arc<IndexDef>,
    pub kind: Kind,
    /// Decompressed bytes of the field description, and in all.
    pub fields_len: u64,
    pub inflated: u64,
    /// Bytes of the zlib stream from `PAGE_DATA` (header to checksum).
    pub stream: u64,
    /// The zlib stream's Adler-32, checked against the inflated data.
    pub adler: crate::value::Check,
    /// The modification log's terminating zero byte (page offset).
    pub log_end: u64,
    pub entries: Vec<LogEntry>,
    /// Records in the heap (not counting the system records).
    pub n_dense: u64,
    /// Uncompressed bytes per record before the dense directory.
    pub per_record: u64,
    /// Off-page column references kept uncompressed.
    pub n_blobs: u64,
    /// Records whose bytes came from the stream (the rest are in the log).
    pub from_stream: u64,
    pub problem: Option<String>,
}

impl Zip {
    /// Where the dense directory starts in the compressed page.
    pub fn dir_start(&self, phys: u64) -> u64 {
        phys.saturating_sub(self.n_dense.saturating_mul(2))
    }

    /// Where the uncompressed columns start.
    pub fn trailer_start(&self, phys: u64) -> u64 {
        self.dir_start(phys)
            .saturating_sub(self.n_dense.saturating_mul(self.per_record))
            .saturating_sub(self.n_blobs.saturating_mul(to_u64(EXTERN_REF)))
    }
}

/// One field of the description.
#[derive(Clone, Copy, Debug)]
struct Col {
    fixed: Option<u64>,
    nullable: bool,
    big: bool,
}

/// Decodes the field description (`page_zip_fields_decode`): the fields,
/// and the trailing number (transaction ID position on leaves, nullable
/// fields on node pointer pages).
fn decode_fields(b: &[u8]) -> Option<(Vec<Col>, u64)> {
    let mut values = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        let first = u64::from(*b.get(i)?);
        i = i.saturating_add(1);
        let v = if first & 0x80 != 0 {
            let second = u64::from(*b.get(i)?);
            i = i.saturating_add(1);
            ((first & 0x7f) << 8) | second | (1 << 16)
        } else {
            first
        };
        values.push(v);
    }
    let (&last, fields) = values.split_last()?;
    if fields.is_empty() || fields.len() > 1023 {
        return None;
    }
    let cols = fields
        .iter()
        .map(|&v| {
            let long = v & (1 << 16) != 0;
            let v = v & 0xffff;
            let (fixed, big) = if long {
                (Some(v >> 1), false)
            } else if v >= 126 {
                (None, true)
            } else if v <= 1 {
                (None, false)
            } else {
                (Some(v >> 1), false)
            };
            Col {
                fixed,
                nullable: v & 1 == 0,
                big,
            }
        })
        .collect();
    Some((cols, last & 0xffff))
}

fn field(name: String, ty: Ty, col: Col) -> Field {
    Field {
        name,
        ty,
        nullable: col.nullable,
        fixed: col.fixed,
        big: col.big,
        hidden: false,
        key: true,
    }
}

/// The definition records are decoded with: one field per described
/// field (consecutive fixed-length columns that cannot be NULL are
/// described as one), padded with nullable fields on node pointer pages
/// whose null flags cover more fields than the records hold.
fn raw_def(cols: &[Col], n_nullable: usize, id: u64) -> IndexDef {
    let mut fields: Vec<Field> = cols
        .iter()
        .enumerate()
        .map(|(i, &c)| field(format!("Field {i}"), Ty::Raw, c))
        .collect();
    let counted = cols.iter().filter(|c| c.nullable).count();
    for _ in counted..n_nullable.min(1023) {
        fields.push(field(
            "(not in node pointers)".to_owned(),
            Ty::Raw,
            Col {
                fixed: None,
                nullable: true,
                big: false,
            },
        ));
    }
    IndexDef {
        id,
        name: format!("index {id} (fields as the page describes them)"),
        table: String::new(),
        root: 0,
        fields,
        n_uniq: cols.len(),
        instant: false,
        versions: Vec::new(),
    }
}

/// The definition records are shown with: the raw one, with the field
/// that starts with the transaction ID split into `DB_TRX_ID`,
/// `DB_ROLL_PTR` and the columns after them.
fn shown_def(cols: &[Col], trx: Option<usize>, n_nullable: usize, id: u64) -> IndexDef {
    let mut def = raw_def(cols, n_nullable, id);
    let Some(t) = trx else {
        return def;
    };
    let Some(len) = cols.get(t).and_then(|c| c.fixed).filter(|&l| l >= 13) else {
        return def;
    };
    let fixed = |name: &str, ty: Ty, n: u64, hidden: bool| Field {
        name: name.to_owned(),
        ty,
        nullable: false,
        fixed: Some(n),
        big: false,
        hidden,
        key: false,
    };
    let mut split = vec![
        fixed("DB_TRX_ID", Ty::TrxId, 6, true),
        fixed("DB_ROLL_PTR", Ty::RollPtr, 7, true),
    ];
    if len > 13 {
        split.push(fixed(
            &format!("Field {t}+"),
            Ty::Raw,
            len.saturating_sub(13),
            false,
        ));
    }
    let tail = def.fields.split_off(t.min(def.fields.len()));
    def.fields.extend(split);
    def.fields.extend(tail.into_iter().skip(1));
    def.n_uniq = t;
    def
}

/// The record heap and the stream being copied into it.
struct Rebuild<'a> {
    page: Vec<u8>,
    out: &'a [u8],
    pos: usize,
    next: usize,
}

impl Rebuild<'_> {
    /// Copies `n` stream bytes to the page at `next`; `false` if the
    /// stream ends first (InnoDB's `Z_STREAM_END`: the remaining records
    /// are in the modification log).
    fn take(&mut self, n: usize) -> std::result::Result<bool, String> {
        let left = self.out.len().saturating_sub(self.pos);
        let k = n.min(left);
        let src = self
            .out
            .get(self.pos..self.pos.saturating_add(k))
            .unwrap_or_default();
        put(&mut self.page, self.next, src)?;
        self.pos = self.pos.saturating_add(k);
        self.next = self.next.saturating_add(k);
        Ok(k == n)
    }
}

/// Writes `src` at `at`.
fn put(page: &mut [u8], at: usize, src: &[u8]) -> std::result::Result<(), String> {
    let end = at.saturating_add(src.len());
    page.get_mut(at..end)
        .ok_or_else(|| format!("data at {at:#x} runs past the page"))?
        .copy_from_slice(src);
    Ok(())
}

fn put16(page: &mut [u8], at: usize, v: u16) -> std::result::Result<(), String> {
    put(page, at, &v.to_be_bytes())
}

/// Sets a record's next-record link (relative in the compact format).
fn set_next(page: &mut [u8], rec: usize, next: usize) -> std::result::Result<(), String> {
    let rel = if next == 0 {
        0
    } else {
        u16::try_from(next & 0xffff)
            .unwrap_or(0)
            .wrapping_sub(u16::try_from(rec & 0xffff).unwrap_or(0))
    };
    put16(page, rec.saturating_sub(2), rel)
}

/// A record's fields as the log stores them: extra bytes backwards, so
/// the null flags come first and the lengths after them
/// (`rec_get_offsets_reverse`). Returns the extra bytes' length, every
/// field's (offset, length, external) and the data length.
type Offsets = (usize, Vec<(usize, usize, bool)>, usize);

fn offsets_reverse(log: &[u8], def: &IndexDef, node_ptr: bool) -> Option<Offsets> {
    let n = if node_ptr {
        def.n_uniq.min(def.fields.len())
    } else {
        def.fields.len()
    };
    let n_nullable = def.fields.iter().filter(|f| f.nullable).count();
    let mut li = n_nullable.div_ceil(8);
    let mut null_i = 0usize;
    let mut off = 0usize;
    let mut out = Vec::new();
    for f in def.fields.iter().take(n) {
        if f.nullable {
            let b = *log.get(null_i / 8)?;
            let bit = 1u8 << (null_i % 8);
            null_i = null_i.saturating_add(1);
            if b & bit != 0 {
                out.push((off, 0, false));
                continue;
            }
        }
        let (len, ext) = match f.fixed {
            Some(n) => (to_usize(n), false),
            None => {
                let b1 = *log.get(li)?;
                li = li.saturating_add(1);
                if f.big && b1 & 0x80 != 0 {
                    let b2 = *log.get(li)?;
                    li = li.saturating_add(1);
                    (
                        (usize::from(b1 & 0x3f) << 8) | usize::from(b2),
                        b1 & 0x40 != 0,
                    )
                } else {
                    (usize::from(b1), false)
                }
            }
        };
        out.push((off, len, ext));
        off = off.saturating_add(len);
    }
    if node_ptr {
        off = off.saturating_add(NODE_PTR);
    }
    Some((li, out, off))
}

/// A record's fields in the page being rebuilt, relative to its origin.
fn offsets(page: &[u8], rec: usize, def: &IndexDef) -> std::result::Result<Offsets, String> {
    let p = index::parse(page, to_u64(rec), Some(def), true);
    if let Some(problem) = p.problem {
        return Err(format!("record at {rec:#x}: {problem}"));
    }
    let end = p
        .end
        .ok_or_else(|| format!("record at {rec:#x} has no end"))?;
    let fields = p
        .fields
        .iter()
        .map(|s| {
            (
                to_usize(s.off).saturating_sub(rec),
                to_usize(s.len),
                s.external,
            )
        })
        .collect();
    Ok((
        to_usize(to_u64(rec).saturating_sub(p.start)).saturating_sub(EXTRA),
        fields,
        to_usize(end).saturating_sub(rec),
    ))
}

/// The input a decompression starts from.
struct Setup {
    n_dense: usize,
    n_recs: usize,
    heap_top: usize,
    leaf: bool,
    min_rec: bool,
    n_slots: usize,
}

/// Rebuilds the uncompressed page (`logical` bytes) from compressed page
/// `zp`. Problems after the stream was decoded are reported in
/// [`Zip::problem`] with the page as far as it was rebuilt.
pub fn decompress(zp: &[u8], logical: usize, index_id: u64) -> Result<Zip> {
    let phys = zp.len();
    let n_heap = usize::from(u16_be(zp, 42).unwrap_or(0));
    if n_heap & 0x8000 == 0 {
        return Err(Diagnostic::malformed(
            "compressed page in the redundant record format",
        ));
    }
    let setup = Setup {
        n_dense: (n_heap & 0x7fff).saturating_sub(2),
        n_recs: usize::from(u16_be(zp, 54).unwrap_or(0)),
        heap_top: usize::from(u16_be(zp, 40).unwrap_or(0)),
        leaf: u16_be(zp, 64).unwrap_or(0) == 0,
        min_rec: u32_be(zp, 8) == Some(super::FIL_NULL),
        n_slots: usize::from(u16_be(zp, 38).unwrap_or(0)),
    };
    if setup.n_dense.saturating_mul(2).saturating_add(PAGE_DATA) >= phys
        || setup.n_recs > setup.n_dense
        || setup.heap_top > logical.saturating_sub(PAGE_DIR)
        || setup.heap_top < ZIP_START
    {
        return Err(Diagnostic::malformed(format!(
            "compressed page header is inconsistent: {} records of {} in the heap, heap top {:#x}",
            setup.n_recs, setup.n_dense, setup.heap_top
        )));
    }
    // The stream: a zlib header, deflate blocks, the Adler-32.
    let body = zp
        .get(PAGE_DATA..phys.saturating_sub(1))
        .unwrap_or_default();
    let (cmf, flg) = (
        u16::from(body.first().copied().unwrap_or(0)),
        u16::from(body.get(1).copied().unwrap_or(0)),
    );
    if cmf & 0x0f != 8 || ((cmf << 8) | flg) % 31 != 0 || flg & 0x20 != 0 {
        return Err(Diagnostic::malformed(
            "no zlib stream after the page header",
        ));
    }
    let deflate = body.get(2..).unwrap_or_default();
    let mut inflater = Inflate::new().stop_at_blocks();
    let mut out = Vec::new();
    let mut fields_len = None;
    let limit = logical.saturating_sub(ZIP_START);
    loop {
        let step = inflater
            .step(deflate, &mut out, usize::MAX, limit)
            .map_err(|e| Diagnostic::malformed(format!("compressed records: {}", e.message)))?;
        if fields_len.is_none() && inflater.at_block_boundary() {
            fields_len = Some(out.len());
        }
        if step == Step::Done {
            break;
        }
    }
    let fields_len = fields_len.unwrap_or(out.len());
    let consumed = inflater.consumed();
    let adler_at = consumed.saturating_add(2);
    let adler = crate::value::Check::new("Adler-32", u32_be(body, adler_at).unwrap_or(0))
        .verify(crate::codec::adler32(&out));
    let stream = adler_at.saturating_add(4);
    let (cols, last) =
        decode_fields(out.get(..fields_len).unwrap_or_default()).ok_or_else(|| {
            Diagnostic::malformed("the compressed page's field description is invalid")
        })?;
    let (kind, trx, n_nullable) = if setup.leaf {
        if last == 0 {
            (
                Kind::Secondary,
                None,
                cols.iter().filter(|c| c.nullable).count(),
            )
        } else if to_usize(last) < cols.len() {
            (
                Kind::Clustered,
                Some(to_usize(last)),
                cols.iter().filter(|c| c.nullable).count(),
            )
        } else {
            return Err(Diagnostic::malformed(format!(
                "transaction ID at field {last} of {}",
                cols.len()
            )));
        }
    } else {
        let counted = cols.iter().filter(|c| c.nullable).count();
        if to_usize(last) < counted {
            return Err(Diagnostic::malformed(format!(
                "{last} nullable fields, but {counted} are described"
            )));
        }
        (Kind::NodePtr, None, to_usize(last))
    };
    let raw = raw_def(&cols, n_nullable, index_id);
    let mut zip = Zip {
        page: Vec::new(),
        def: Arc::new(shown_def(&cols, trx, n_nullable, index_id)),
        kind,
        fields_len: to_u64(fields_len),
        inflated: to_u64(out.len()),
        stream: to_u64(stream),
        adler,
        log_end: to_u64(PAGE_DATA.saturating_add(stream)),
        entries: Vec::new(),
        n_dense: to_u64(setup.n_dense),
        per_record: match kind {
            Kind::Clustered => 13,
            Kind::NodePtr => 4,
            Kind::Secondary => 0,
        },
        n_blobs: 0,
        from_stream: 0,
        problem: None,
    };
    let mut rb = Rebuild {
        page: vec![0u8; logical],
        out: &out,
        pos: fields_len,
        next: ZIP_START,
    };
    if let Err(problem) = rebuild(zp, &setup, &raw, trx, &mut rb, &mut zip) {
        zip.problem = Some(problem);
    }
    zip.page = rb.page;
    Ok(zip)
}

/// The dense directory's entry `i`.
fn dir(zp: &[u8], i: usize) -> u16 {
    let at = zp
        .len()
        .saturating_sub(i.saturating_add(1).saturating_mul(2));
    u16_be(zp, at).unwrap_or(0)
}

fn rebuild(
    zp: &[u8],
    s: &Setup,
    raw: &IndexDef,
    trx: Option<usize>,
    rb: &mut Rebuild<'_>,
    zip: &mut Zip,
) -> std::result::Result<(), String> {
    let logical = rb.page.len();
    put(&mut rb.page, 0, zp.get(..PAGE_DATA).unwrap_or_default())?;
    // The sparse directory from the owners in the dense one
    // (`page_zip_dir_decode`).
    let mut slot = logical.saturating_sub(PAGE_DIR).saturating_sub(2);
    put16(&mut rb.page, slot, to_u16(INFIMUM))?;
    let mut recs = Vec::with_capacity(s.n_dense);
    for i in 0..s.n_recs {
        let offs = dir(zp, i);
        if offs & SLOT_OWNED != 0 {
            slot = slot.saturating_sub(2);
            put16(&mut rb.page, slot, offs & SLOT_MASK)?;
        }
        recs.push(usize::from(offs & SLOT_MASK));
    }
    slot = slot.saturating_sub(2);
    put16(&mut rb.page, slot, to_u16(SUPREMUM))?;
    let slots = logical
        .saturating_sub(PAGE_DIR)
        .saturating_sub(slot)
        .saturating_div(2);
    if slots != s.n_slots {
        return Err(format!(
            "the dense directory gives {slots} directory slots, the header {}",
            s.n_slots
        ));
    }
    for i in s.n_recs..s.n_dense {
        let offs = dir(zp, i);
        if offs & !SLOT_MASK != 0 {
            return Err(format!("free record {i} is flagged in the dense directory"));
        }
        recs.push(usize::from(offs));
    }
    if let Some(bad) = recs.iter().find(|&&r| r < ZIP_START.saturating_add(EXTRA)) {
        return Err(format!(
            "dense directory entry {bad:#x} is inside the page header"
        ));
    }
    let free: std::collections::BTreeSet<usize> = recs.iter().skip(s.n_recs).copied().collect();
    recs.sort_unstable();
    if recs.windows(2).any(|w| w.first() == w.get(1)) {
        return Err("the dense directory lists a record twice".to_owned());
    }
    // The system records.
    put(
        &mut rb.page,
        INFIMUM.saturating_sub(EXTRA),
        &[0x01, 0x00, 0x02],
    )?;
    let first = if s.n_recs == 0 {
        SUPREMUM
    } else {
        usize::from(dir(zp, 0) & SLOT_MASK)
    };
    set_next(&mut rb.page, INFIMUM, first)?;
    put(&mut rb.page, INFIMUM, b"infimum\0")?;
    put(
        &mut rb.page,
        SUPREMUM.saturating_sub(EXTRA).saturating_add(1),
        b"\x00\x0b\x00\x00supremum",
    )?;
    // The records from the stream.
    let status: u16 = if zip.kind == Kind::NodePtr { 1 } else { 0 };
    let mut hs: u16 = (2 << 3) | status;
    let mut ended = false;
    for &rec in &recs {
        let need = rec
            .saturating_sub(EXTRA)
            .checked_sub(rb.next)
            .ok_or_else(|| format!("record at {rec:#x} overlaps the one before"))?;
        if !rb.take(need)? {
            if rb.next == rec.saturating_sub(EXTRA) {
                put16(&mut rb.page, rec.saturating_sub(4), hs)?;
            }
            ended = true;
            break;
        }
        rb.next = rec;
        put16(&mut rb.page, rec.saturating_sub(4), hs)?;
        hs = hs.saturating_add(8);
        if zip.kind == Kind::Secondary {
            zip.from_stream = zip.from_stream.saturating_add(1);
            continue;
        }
        let (_, fields, data) = offsets(&rb.page, rec, raw)?;
        let mut complete = true;
        if zip.kind == Kind::NodePtr {
            complete = rb.take(data.saturating_sub(NODE_PTR))?;
            rb.next = rb.next.saturating_add(NODE_PTR);
        } else {
            let t = trx.unwrap_or(0);
            for (i, &(off, len, ext)) in fields.iter().enumerate() {
                if i == t {
                    if len < TRX_ROLL || ext {
                        return Err(format!(
                            "record at {rec:#x}: transaction ID field too short"
                        ));
                    }
                    complete = rb.take(rec.saturating_add(off).saturating_sub(rb.next))?;
                    rb.next = rec.saturating_add(off).saturating_add(TRX_ROLL);
                } else if ext {
                    let at = rec.saturating_add(off).saturating_add(len);
                    complete = rb.take(at.saturating_sub(EXTERN_REF).saturating_sub(rb.next))?;
                    rb.next = at;
                }
                if !complete {
                    break;
                }
            }
            if complete {
                complete = rb.take(rec.saturating_add(data).saturating_sub(rb.next))?;
            }
        }
        if !complete {
            ended = true;
            break;
        }
        zip.from_stream = zip.from_stream.saturating_add(1);
    }
    if !ended {
        // Anything up to the heap top (a record that took the place of a
        // longer deleted one leaves garbage).
        rb.take(s.heap_top.saturating_sub(rb.next))?;
        if rb.pos < rb.out.len() {
            return Err(format!(
                "the compressed stream runs {} bytes past the heap top",
                rb.out.len().saturating_sub(rb.pos)
            ));
        }
    }
    set_extra_bytes(zp, s, &mut rb.page)?;
    // The modification log.
    let mut at = to_usize(zip.log_end);
    loop {
        let start = at;
        let first = *zp.get(at).ok_or("the modification log runs off the page")?;
        if first == 0 {
            break;
        }
        at = at.saturating_add(1);
        let mut val = usize::from(first);
        if first & 0x80 != 0 {
            val = ((val & 0x7f) << 8) | usize::from(*zp.get(at).ok_or("log entry cut short")?);
            at = at.saturating_add(1);
        }
        let n = val >> 1;
        if n == 0 || n > s.n_dense || at >= zp.len() {
            return Err(format!("log entry at {start:#x} names heap record {n}"));
        }
        let rec = *recs.get(n.saturating_sub(1)).unwrap_or(&0);
        let ehs = (to_u16(n.saturating_add(1)) << 3) | (hs & 7);
        if ehs > hs {
            return Err(format!("log entry at {start:#x} skips heap numbers"));
        } else if ehs == hs {
            if val & 1 != 0 {
                return Err(format!("log entry at {start:#x} clears a new record"));
            }
            hs = hs.saturating_add(8);
        }
        put16(&mut rb.page, rec.saturating_sub(4), ehs)?;
        let mut entry = LogEntry {
            at: to_u64(start),
            len: 0,
            heap_no: to_u64(n.saturating_add(1)),
            cleared: val & 1 != 0,
        };
        if entry.cleared {
            let (_, _, data) = offsets(&rb.page, rec, raw)?;
            put(&mut rb.page, rec, &vec![0u8; data])?;
            entry.len = to_u64(at.saturating_sub(start));
            zip.entries.push(entry);
            continue;
        }
        let rest = zp.get(at..).unwrap_or_default();
        let (extra, fields, data) = offsets_reverse(rest, raw, zip.kind == Kind::NodePtr)
            .ok_or_else(|| format!("log entry at {start:#x} is cut short"))?;
        let ex = rest.get(..extra).ok_or("log entry cut short")?;
        let below = rec.saturating_sub(EXTRA);
        let lo = below
            .checked_sub(extra)
            .ok_or_else(|| format!("record at {rec:#x} starts before the page"))?;
        let reversed: Vec<u8> = ex.iter().rev().copied().collect();
        put(&mut rb.page, lo, &reversed)?;
        at = at.saturating_add(extra);
        let mut copy =
            |from: usize, len: usize, at: &mut usize| -> std::result::Result<(), String> {
                let end = at.saturating_add(len);
                if end >= zp.len() {
                    return Err(format!("log entry at {start:#x} runs past the page"));
                }
                put(&mut rb.page, from, zp.get(*at..end).unwrap_or_default())?;
                *at = end;
                Ok(())
            };
        let any_ext = fields.iter().any(|f| f.2);
        if any_ext {
            let t = trx.ok_or_else(|| {
                format!("log entry at {start:#x}: off-page column outside a clustered leaf")
            })?;
            let mut next = 0usize;
            for (i, &(off, len, ext)) in fields.iter().enumerate() {
                if i == t {
                    if len < TRX_ROLL || ext {
                        return Err(format!(
                            "log entry at {start:#x}: transaction ID field too short"
                        ));
                    }
                    copy(rec.saturating_add(next), off.saturating_sub(next), &mut at)?;
                    next = off.saturating_add(TRX_ROLL);
                } else if ext {
                    let n = off
                        .saturating_add(len)
                        .saturating_sub(EXTERN_REF)
                        .saturating_sub(next);
                    copy(rec.saturating_add(next), n, &mut at)?;
                    next = off.saturating_add(len);
                }
            }
            copy(rec.saturating_add(next), data.saturating_sub(next), &mut at)?;
        } else {
            match zip.kind {
                Kind::NodePtr => copy(rec, data.saturating_sub(NODE_PTR), &mut at)?,
                Kind::Secondary => copy(rec, data, &mut at)?,
                Kind::Clustered => {
                    let t = trx.unwrap_or(0);
                    let &(off, len, _) = fields.get(t).ok_or_else(|| {
                        format!("log entry at {start:#x} lacks the transaction ID")
                    })?;
                    if len < TRX_ROLL {
                        return Err(format!(
                            "log entry at {start:#x}: transaction ID field too short"
                        ));
                    }
                    copy(rec, off, &mut at)?;
                    let b = off.saturating_add(TRX_ROLL);
                    copy(rec.saturating_add(b), data.saturating_sub(b), &mut at)?;
                }
            }
        }
        entry.len = to_u64(at.saturating_sub(start));
        zip.entries.push(entry);
    }
    zip.log_end = to_u64(at);
    // The columns kept uncompressed, in heap order before the directory.
    let mut storage = zp.len().saturating_sub(s.n_dense.saturating_mul(2));
    let mut externs = storage.saturating_sub(s.n_dense.saturating_mul(to_usize(zip.per_record)));
    for &rec in &recs {
        let (_, fields, data) = offsets(&rb.page, rec, raw)?;
        match zip.kind {
            Kind::Secondary => {}
            Kind::NodePtr => {
                storage = storage.saturating_sub(NODE_PTR);
                let src = zp
                    .get(storage..storage.saturating_add(NODE_PTR))
                    .unwrap_or_default();
                put(
                    &mut rb.page,
                    rec.saturating_add(data).saturating_sub(NODE_PTR),
                    src,
                )?;
            }
            Kind::Clustered => {
                let t = trx.unwrap_or(0);
                let &(off, _, _) = fields.get(t).ok_or("record lacks the transaction ID")?;
                storage = storage.saturating_sub(TRX_ROLL);
                let src = zp
                    .get(storage..storage.saturating_add(TRX_ROLL))
                    .unwrap_or_default();
                put(&mut rb.page, rec.saturating_add(off), src)?;
                for &(off, len, ext) in &fields {
                    if !ext {
                        continue;
                    }
                    let dst = rec
                        .saturating_add(off)
                        .saturating_add(len)
                        .saturating_sub(EXTERN_REF);
                    if free.contains(&rec) {
                        put(&mut rb.page, dst, &[0u8; EXTERN_REF])?;
                        continue;
                    }
                    externs = externs.saturating_sub(EXTERN_REF);
                    if externs <= to_usize(zip.log_end) {
                        return Err(
                            "off-page column references overlap the modification log".to_owned()
                        );
                    }
                    let src = zp
                        .get(externs..externs.saturating_add(EXTERN_REF))
                        .unwrap_or_default();
                    put(&mut rb.page, dst, src)?;
                    zip.n_blobs = zip.n_blobs.saturating_add(1);
                }
            }
        }
    }
    if zip.trailer_start(to_u64(zp.len())) <= zip.log_end {
        return Err("the modification log runs into the uncompressed columns".to_owned());
    }
    Ok(())
}

fn to_u16(v: usize) -> u16 {
    u16::try_from(v).unwrap_or(u16::MAX)
}

/// Info bits, owned counts and next-record links from the dense directory
/// (`page_zip_set_extra_bytes`).
fn set_extra_bytes(zp: &[u8], s: &Setup, page: &mut [u8]) -> std::result::Result<(), String> {
    let mut info: u8 = if !s.leaf && s.min_rec { 0x10 } else { 0 };
    let mut owned: u8 = 1;
    let mut rec = INFIMUM;
    for i in 0..s.n_recs {
        let offs = dir(zp, i);
        if offs & SLOT_DEL != 0 {
            info |= 0x20;
        }
        if offs & SLOT_OWNED != 0 {
            info |= owned & 0x0f;
            owned = 1;
        } else {
            owned = owned.saturating_add(1);
        }
        let to = usize::from(offs & SLOT_MASK);
        set_next(page, rec, to)?;
        rec = to;
        put(page, rec.saturating_sub(EXTRA), &[info])?;
        info = 0;
    }
    set_next(page, rec, SUPREMUM)?;
    put(page, SUPREMUM.saturating_sub(EXTRA), &[owned & 0x0f])?;
    if s.n_recs >= s.n_dense {
        return Ok(());
    }
    for i in s.n_recs..s.n_dense {
        let r = usize::from(dir(zp, i));
        put(page, r.saturating_sub(EXTRA), &[0])?;
        let next = if i.saturating_add(1) < s.n_dense {
            usize::from(dir(zp, i.saturating_add(1)))
        } else {
            0
        };
        set_next(page, r, next)?;
    }
    Ok(())
}

/// A decoded compressed page and the source holding the rebuilt page.
pub struct View {
    pub zip: Zip,
    pub span: Span,
}

/// The compressed index page at `span`, decoded once.
pub async fn view(cx: &Cx, span: Span, logical: u64) -> Result<Arc<View>> {
    if let Some(v) = cx.cached::<View>(span, "innodb-zip") {
        return Ok(v);
    }
    let zp = cx.read(span).await?;
    // Inflating and rebuilding is linear in the page.
    cx.charge(to_u64(zp.len()).saturating_add(logical) / 64)
        .await;
    let id = crate::bytes::u64_be(&zp, 66).unwrap_or(0);
    let mut zip = decompress(&zp, to_usize(logical), id)?;
    let page = std::mem::take(&mut zip.page);
    let decoded = cx.add_derived(
        Origin {
            parent: span,
            transform: "innodb-zip-page",
        },
        page,
        span.len,
        None,
    )?;
    let v = Arc::new(View {
        zip,
        span: decoded.span,
    });
    cx.cache(span, "innodb-zip", v.clone());
    Ok(v)
}
