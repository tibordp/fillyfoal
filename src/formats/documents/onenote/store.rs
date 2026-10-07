//! The revision store container ([MS-ONESTORE]): chunk references, file
//! node lists (chained fragments), the transaction log and file node bodies.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u32_le, u64_le};
use crate::cx::{Block, Cx};
use crate::error::{Diagnostic, Result};
use crate::fields::Fields;
use crate::formats::disk::guid_le;
use crate::node::Node;
use crate::span::Span;
use crate::value::{Guid, Value, lookup};

use super::tables::{FILE_NODE_IDS, JCID_IS_PROPERTY_SET, JCIDS};

pub const LIST_MAGIC: u64 = 0xA456_7AB1_F5F7_F4C4;
pub const LIST_FOOTER: u64 = 0x8BC2_15C3_8233_BA4B;
/// Fragments one file node list may have.
const MAX_FRAGMENTS: usize = 4096;
/// Fragments the transaction log may have.
const MAX_LOG_FRAGMENTS: usize = 1024;

/// A 20-byte ExtendedGUID: a GUID and a number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExGuid {
    pub guid: [u8; 16],
    pub n: u32,
}

impl ExGuid {
    pub fn parse(b: &[u8]) -> Option<ExGuid> {
        Some(ExGuid {
            guid: crate::bytes::array(b, 0)?,
            n: u32_le(b, 16)?,
        })
    }

    pub fn is_nil(&self) -> bool {
        self.guid == [0; 16] && self.n == 0
    }

    pub fn label(&self) -> String {
        if self.is_nil() {
            "nil".to_owned()
        } else {
            format!("{}, {}", guid_le(&self.guid), self.n)
        }
    }
}

/// A CompactID: an index into the global identification table and `n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompactId {
    pub n: u8,
    pub index: u32,
}

impl CompactId {
    pub fn from_raw(raw: u32) -> CompactId {
        CompactId {
            n: (raw & 0xFF) as u8,
            index: raw >> 8,
        }
    }

    pub fn resolve(self, table: &IdTable) -> Option<ExGuid> {
        if self.n == 0 && self.index == 0 && !table.contains_key(&0) {
            return Some(ExGuid::default());
        }
        table.get(&self.index).map(|guid| ExGuid {
            guid: *guid,
            n: self.n.into(),
        })
    }

    pub fn label(self, table: Option<&IdTable>) -> String {
        match table.and_then(|t| self.resolve(t)) {
            Some(ex) => ex.label(),
            None => format!("unresolved (guidIndex {}, n {})", self.index, self.n),
        }
    }
}

/// The global identification table in effect: index → GUID.
pub type IdTable = BTreeMap<u32, [u8; 16]>;

/// A reference to a chunk of the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fcr {
    pub stp: u64,
    pub cb: u64,
    pub nil: bool,
}

impl Fcr {
    pub fn is_zero(&self) -> bool {
        !self.nil && self.stp == 0 && self.cb == 0
    }

    /// fcrNil or fcrZero: refers to nothing.
    pub fn is_null(&self) -> bool {
        self.nil || self.is_zero()
    }

    pub fn span(&self, file: Span) -> Span {
        file.sub(self.stp, self.cb)
    }

    pub fn label(&self) -> String {
        if self.nil {
            "fcrNil".to_owned()
        } else if self.is_zero() {
            "fcrZero".to_owned()
        } else {
            format!("{:#x} + {:#x}", self.stp, self.cb)
        }
    }
}

/// FileChunkReference64x32: `stp` u64, `cb` u32.
pub fn fcr64x32(b: &[u8], at: usize) -> Option<Fcr> {
    let stp = u64_le(b, at)?;
    let cb = u32_le(b, at.checked_add(8)?)?;
    Some(Fcr {
        stp,
        cb: cb.into(),
        nil: stp == u64::MAX && cb == 0,
    })
}

/// FileChunkReference32: `stp` u32, `cb` u32.
pub fn fcr32(b: &[u8], at: usize) -> Option<Fcr> {
    let stp = u32_le(b, at)?;
    let cb = u32_le(b, at.checked_add(4)?)?;
    Some(Fcr {
        stp: stp.into(),
        cb: cb.into(),
        nil: stp == u32::MAX && cb == 0,
    })
}

/// FileChunkReference64: `stp` u64, `cb` u64.
pub fn fcr64(b: &[u8], at: usize) -> Option<Fcr> {
    let stp = u64_le(b, at)?;
    let cb = u64_le(b, at.checked_add(8)?)?;
    Some(Fcr {
        stp,
        cb,
        nil: stp == u64::MAX && cb == 0,
    })
}

/// The 32-bit header of a FileNode.
#[derive(Clone, Copy, Debug)]
pub struct Hdr {
    pub id: u16,
    pub size: u16,
    pub stp_format: u8,
    pub cb_format: u8,
    pub base_type: u8,
}

impl Hdr {
    pub fn new(raw: u32) -> Hdr {
        Hdr {
            id: (raw & 0x3FF) as u16,
            size: ((raw >> 10) & 0x1FFF) as u16,
            stp_format: ((raw >> 23) & 3) as u8,
            cb_format: ((raw >> 25) & 3) as u8,
            base_type: ((raw >> 27) & 0xF) as u8,
        }
    }

    pub fn name(&self) -> String {
        match lookup(FILE_NODE_IDS, self.id.into()) {
            Some(n) => n.to_owned(),
            None => format!("FileNode {:#05x}", self.id),
        }
    }

    /// Size of the FileNodeChunkReference these formats select.
    pub fn ref_len(&self) -> u64 {
        let stp: u64 = match self.stp_format {
            0 => 8,
            1 | 3 => 4,
            _ => 2,
        };
        let cb: u64 = match self.cb_format {
            0 => 4,
            1 => 8,
            2 => 1,
            _ => 2,
        };
        stp.saturating_add(cb)
    }

    /// Decodes a FileNodeChunkReference in this node's formats.
    pub fn decode_ref(&self, b: &[u8]) -> Option<Fcr> {
        let (stp, stp_len, stp_ones, stp_scale) = match self.stp_format {
            0 => (u64_le(b, 0)?, 8usize, u64::MAX, 1u64),
            1 => (u32_le(b, 0)?.into(), 4, u32::MAX.into(), 1),
            2 => (crate::bytes::u16_le(b, 0)?.into(), 2, u16::MAX.into(), 8),
            _ => (u32_le(b, 0)?.into(), 4, u32::MAX.into(), 8),
        };
        let (cb, cb_scale) = match self.cb_format {
            0 => (u64::from(u32_le(b, stp_len)?), 1u64),
            1 => (u64_le(b, stp_len)?, 1),
            2 => (u64::from(*b.get(stp_len)?), 8),
            _ => (u64::from(crate::bytes::u16_le(b, stp_len)?), 8),
        };
        Some(Fcr {
            nil: stp == stp_ones && cb == 0,
            stp: stp.saturating_mul(stp_scale),
            cb: cb.saturating_mul(cb_scale),
        })
    }
}

/// One FileNode as read from a fragment.
#[derive(Clone, Debug)]
pub struct FileNode {
    pub hdr: Hdr,
    pub span: Span,
    pub data: Vec<u8>,
}

impl FileNode {
    pub fn block(&self) -> Block {
        Block {
            span: self.span,
            data: self.data.clone(),
        }
    }

    /// Parses the body silently.
    pub fn body(&self, file: Span, table: Option<&IdTable>) -> Result<Body> {
        let block = self.block();
        let mut f = Fields::new(&block, crate::fields::Endian::Little);
        f.seek(4);
        body(&mut f, &self.hdr, file, table)
    }
}

/// One fragment of a file node list.
#[derive(Clone, Debug)]
pub struct Fragment {
    pub span: Span,
    pub magic: u64,
    pub list_id: u32,
    pub sequence: u32,
    pub next: Option<Fcr>,
    pub footer: Option<u64>,
    pub nodes: usize,
}

/// A file node list: its fragments and the nodes in them.
#[derive(Clone, Debug, Default)]
pub struct NodeList {
    pub id: Option<u32>,
    pub fragments: Vec<Fragment>,
    pub nodes: Vec<FileNode>,
    pub diags: Vec<Diagnostic>,
}

/// What the file header says, and the committed node count of each list.
#[derive(Clone, Debug)]
pub struct Store {
    pub file: Span,
    pub toc: bool,
    pub root: Fcr,
    pub transaction_log: Fcr,
    pub transactions: u32,
    pub hashed_chunks: Fcr,
    pub free_chunks: Fcr,
    pub log: Arc<TxLog>,
}

impl Store {
    pub fn parse_header(file: Span, head: &[u8]) -> Store {
        let nil = Fcr {
            stp: u64::MAX,
            cb: 0,
            nil: true,
        };
        let get = |at: usize| fcr64x32(head, at).unwrap_or(nil);
        Store {
            file,
            toc: u32_le(head, 0) == Some(0x43FF_2FA1),
            hashed_chunks: get(0x94),
            transaction_log: get(0xA0),
            root: get(0xAC),
            free_chunks: get(0xB8),
            transactions: u32_le(head, 0x60).unwrap_or(0),
            log: Arc::default(),
        }
    }
}

/// One TransactionEntry.
#[derive(Clone, Debug)]
pub struct TxEntry {
    pub span: Span,
    pub src: u32,
    pub switch: u32,
    /// The transaction it belongs to (counting from 0).
    pub transaction: u32,
}

/// The transaction log: committed node counts per file node list.
#[derive(Clone, Debug, Default)]
pub struct TxLog {
    pub fragments: Vec<(Span, Option<Fcr>)>,
    pub entries: Vec<TxEntry>,
    pub counts: BTreeMap<u32, u32>,
    pub committed: u32,
    pub diags: Vec<Diagnostic>,
}

/// Reads the transaction log up to the last committed transaction.
pub async fn read_log(cx: &Cx, file: Span, first: Fcr, transactions: u32) -> TxLog {
    let mut log = TxLog::default();
    let mut fcr = first;
    let mut seen = BTreeSet::new();
    while !fcr.is_null() && log.committed < transactions {
        if log.fragments.len() >= MAX_LOG_FRAGMENTS || !seen.insert(fcr.stp) {
            log.diags.push(Diagnostic::malformed(
                "transaction log fragments form a cycle or are too many",
            ));
            break;
        }
        let span = match file.sub_exact(fcr.stp, fcr.cb) {
            Ok(s) => s,
            Err(e) => {
                log.diags.push(e);
                break;
            }
        };
        let data = match cx.read(span).await {
            Ok(d) => d,
            Err(e) => {
                log.diags.push(e);
                break;
            }
        };
        let table_len = to_usize(fcr.cb.saturating_sub(12));
        let next = fcr64x32(&data, table_len);
        log.fragments.push((span, next));
        let mut at = 0usize;
        while at.saturating_add(8) <= table_len && log.committed < transactions {
            let (Some(src), Some(switch)) =
                (u32_le(&data, at), u32_le(&data, at.saturating_add(4)))
            else {
                break;
            };
            log.entries.push(TxEntry {
                span: span.sub(to_u64(at), 8),
                src,
                switch,
                transaction: log.committed,
            });
            if src == 1 {
                log.committed = log.committed.saturating_add(1);
            } else if src != 0 {
                log.counts.insert(src, switch);
            }
            at = at.saturating_add(8);
        }
        match next {
            Some(n) => fcr = n,
            None => break,
        }
    }
    if log.committed < transactions {
        log.diags.push(Diagnostic::warning(format!(
            "the header promises {transactions} transactions, the log holds {}",
            log.committed
        )));
    }
    log
}

/// Reads a file node list, following its fragments. Never fails: problems
/// end the list early and are recorded in `diags`.
pub async fn read_list(cx: &Cx, store: &Store, first: Fcr) -> NodeList {
    let mut list = NodeList::default();
    let mut fcr = first;
    let mut seen = BTreeSet::new();
    let mut expected: Option<u32> = None;
    let mut counted = 0u32;
    'fragments: while !fcr.is_null() {
        if list.fragments.len() >= MAX_FRAGMENTS || !seen.insert(fcr.stp) {
            list.diags.push(Diagnostic::malformed(
                "list fragments form a cycle or are too many",
            ));
            break;
        }
        if fcr.cb < 36 {
            list.diags.push(Diagnostic::malformed(format!(
                "fragment at {:#x} is only {:#x} bytes",
                fcr.stp, fcr.cb
            )));
            break;
        }
        let span = match store.file.sub_exact(fcr.stp, fcr.cb) {
            Ok(s) => s,
            Err(e) => {
                list.diags.push(e);
                break;
            }
        };
        let data = match cx.read(span).await {
            Ok(d) => d,
            Err(e) => {
                list.diags.push(e);
                break;
            }
        };
        let magic = u64_le(&data, 0).unwrap_or(0);
        let list_id = u32_le(&data, 8).unwrap_or(0);
        let sequence = u32_le(&data, 12).unwrap_or(0);
        if magic != LIST_MAGIC {
            list.diags.push(
                Diagnostic::malformed("bad file node list fragment magic").at(span.sub(0, 8)),
            );
            break;
        }
        match list.id {
            None => {
                list.id = Some(list_id);
                expected = store.log.counts.get(&list_id).copied();
            }
            Some(id) if id != list_id => list.diags.push(
                Diagnostic::malformed(format!(
                    "fragment belongs to list {list_id:#x}, not {id:#x}"
                ))
                .at(span.sub(8, 4)),
            ),
            Some(_) => {}
        }
        let end = to_usize(fcr.cb.saturating_sub(20));
        let mut pos = 16usize;
        let first_node = list.nodes.len();
        let mut broken = false;
        while pos.saturating_add(4) <= end {
            if expected.is_some_and(|e| counted >= e) {
                break;
            }
            let Some(raw) = u32_le(&data, pos) else { break };
            let hdr = Hdr::new(raw);
            if hdr.id == 0 {
                break;
            }
            let size = usize::from(hdr.size);
            if size < 4 || pos.saturating_add(size) > end {
                list.diags.push(
                    Diagnostic::malformed(format!(
                        "file node of {size:#x} bytes does not fit its fragment"
                    ))
                    .at(span.sub(to_u64(pos), 4)),
                );
                broken = true;
                break;
            }
            let bytes = data
                .get(pos..pos.saturating_add(size))
                .unwrap_or_default()
                .to_vec();
            list.nodes.push(FileNode {
                hdr,
                span: span.sub(to_u64(pos), to_u64(size)),
                data: bytes,
            });
            pos = pos.saturating_add(size);
            if hdr.id == 0xFF {
                break;
            }
            counted = counted.saturating_add(1);
        }
        let next = fcr64x32(&data, end);
        list.fragments.push(Fragment {
            span,
            magic,
            list_id,
            sequence,
            next,
            footer: u64_le(&data, end.saturating_add(12)),
            nodes: list.nodes.len().saturating_sub(first_node),
        });
        if broken || expected.is_some_and(|e| counted >= e) {
            break 'fragments;
        }
        match next {
            Some(n) => fcr = n,
            None => break,
        }
    }
    if let Some(e) = expected
        && counted < e
    {
        list.diags.push(Diagnostic::warning(format!(
            "the transaction log commits {e} file nodes to list {:#x}, found {counted}",
            list.id.unwrap_or(0)
        )));
    }
    list
}

/// An object ID as declared: compact (resolved through the global
/// identification table) or a full ExtendedGUID.
#[derive(Clone, Copy, Debug)]
pub enum Oid {
    Compact(CompactId),
    Full(ExGuid),
}

impl Oid {
    pub fn resolve(self, table: Option<&IdTable>) -> Option<ExGuid> {
        match self {
            Oid::Full(ex) => Some(ex),
            Oid::Compact(c) => table.and_then(|t| c.resolve(t)),
        }
    }
}

/// The fields of a file node body that the model needs.
#[derive(Clone, Debug, Default)]
pub struct Body {
    pub fcr: Option<Fcr>,
    /// gosid, ObjectGroupID, object group oid or data signature group.
    pub id: Option<ExGuid>,
    pub rid: Option<ExGuid>,
    pub dependent: Option<ExGuid>,
    pub role: Option<u32>,
    pub context: Option<ExGuid>,
    pub oid: Option<Oid>,
    pub jcid: Option<u32>,
    pub index: Option<u32>,
    pub guid: Option<[u8; 16]>,
    pub file_ref: Option<String>,
    pub extension: Option<String>,
    pub cref: Option<u32>,
}

impl Body {
    /// Whether the referenced data is an ObjectSpaceObjectPropSet.
    pub fn has_property_set(&self, id: u16) -> bool {
        match id {
            0x02D | 0x02E | 0x041 | 0x042 => true,
            0x0A4 | 0x0A5 | 0x0C4 | 0x0C5 => {
                self.jcid.is_some_and(|j| j & JCID_IS_PROPERTY_SET != 0)
            }
            _ => false,
        }
    }
}

fn exguid(f: &mut Fields<'_>, name: &'static str) -> Result<ExGuid> {
    let span = f.peek_span(20);
    let b = f.bytes(name, 20).get()?;
    let ex = ExGuid::parse(&b).unwrap_or_default();
    f.node(Node::new(name).span(span).value(Value::Text(ex.label())));
    Ok(ex)
}

fn compact(f: &mut Fields<'_>, name: &'static str, table: Option<&IdTable>) -> Result<CompactId> {
    let span = f.peek_span(4);
    let raw = f.u32(name).get()?;
    let c = CompactId::from_raw(raw);
    f.node(
        Node::new(name)
            .span(span)
            .value(Value::Text(c.label(table)))
            .summary(format!("guidIndex {}, n {}", c.index, c.n)),
    );
    Ok(c)
}

fn reference(f: &mut Fields<'_>, hdr: &Hdr, file: Span, name: &'static str) -> Result<Fcr> {
    let len = hdr.ref_len();
    let span = f.peek_span(len);
    let b = f.bytes(name, len).get()?;
    let fcr = hdr
        .decode_ref(&b)
        .ok_or_else(|| Diagnostic::truncated(span, to_u64(b.len())))?;
    let mut node = Node::new(name).span(span).value(Value::Text(fcr.label()));
    if !fcr.is_null() {
        node = node.target(fcr.span(file));
    }
    f.node(node);
    Ok(fcr)
}

fn jcid(f: &mut Fields<'_>, name: &'static str) -> Result<u32> {
    let span = f.peek_span(4);
    let v = f.u32(name).get()?;
    f.node(
        Node::new(name)
            .span(span)
            .value(jcid_value(v))
            .summary(jcid_flags(v)),
    );
    Ok(v)
}

pub fn jcid_value(v: u32) -> Value {
    Value::Enum {
        raw: v.into(),
        bits: 32,
        name: lookup(JCIDS, v.into()),
    }
}

pub fn jcid_name(v: u32) -> String {
    match lookup(JCIDS, v.into()) {
        Some(n) => n.to_owned(),
        None => format!("JCID {v:#010x}"),
    }
}

pub fn jcid_flags(v: u32) -> String {
    use super::tables::{JCID_IS_BINARY, JCID_IS_FILE_DATA, JCID_IS_GRAPH_NODE, JCID_IS_READ_ONLY};
    let mut parts = vec![format!("index {:#x}", v & 0xFFFF)];
    for (bit, name) in [
        (JCID_IS_BINARY, "binary"),
        (JCID_IS_PROPERTY_SET, "property set"),
        (JCID_IS_GRAPH_NODE, "graph node"),
        (JCID_IS_FILE_DATA, "file data"),
        (JCID_IS_READ_ONLY, "read-only"),
    ] {
        if v & bit != 0 {
            parts.push(name.to_owned());
        }
    }
    parts.join(", ")
}

/// A StringInStorageBuffer: `cch` and that many UTF-16 code units.
fn storage_string(f: &mut Fields<'_>, name: &'static str) -> Result<String> {
    let start = f.peek_span(4);
    let cch = f.u32("cch").get()?;
    let text_span = f.peek_span(u64::from(cch).saturating_mul(2));
    let text = f.utf16(name, cch.into()).get()?;
    let span = Span::new(
        start.source,
        start.offset,
        4u64.saturating_add(text_span.len),
    );
    f.node(Node::new(name).span(span).value(Value::Text(text.clone())));
    Ok(text)
}

fn md5(f: &mut Fields<'_>) -> Result<()> {
    f.bytes("md5Hash", 16).emit()?;
    Ok(())
}

/// ObjectInfoDependencyOverrideData.
pub fn overrides(f: &mut Fields<'_>, table: Option<&IdTable>) -> Result<()> {
    let small = f.u32("c8BitOverrides").emit()?;
    let large = f.u32("c32BitOverrides").emit()?;
    f.u32("crc").hex().emit()?;
    let total = u64::from(small).saturating_add(large.into());
    if total.saturating_mul(5) > f.remaining() {
        return Err(Diagnostic::malformed("more overrides than bytes"));
    }
    for _ in 0..small {
        compact(f, "oid", table)?;
        f.u8("cRef").emit()?;
    }
    for _ in 0..large {
        compact(f, "oid", table)?;
        f.u32("cRef").emit()?;
    }
    Ok(())
}

/// Decodes (and, with an emitting cursor, shows) a file node body; the
/// cursor stands after the 4-byte header.
pub fn body(f: &mut Fields<'_>, hdr: &Hdr, file: Span, table: Option<&IdTable>) -> Result<Body> {
    let mut b = Body::default();
    match hdr.id {
        0x004 => b.id = Some(exguid(f, "gosidRoot")?),
        0x008 => {
            b.fcr = Some(reference(f, hdr, file, "ref")?);
            b.id = Some(exguid(f, "gosid")?);
        }
        0x00C => b.id = Some(exguid(f, "gosid")?),
        0x010 | 0x090 | 0x07C => b.fcr = Some(reference(f, hdr, file, "ref")?),
        0x014 => {
            b.id = Some(exguid(f, "gosid")?);
            f.u32("nInstance").emit()?;
        }
        0x01B | 0x01E | 0x01F => {
            b.rid = Some(exguid(f, "rid")?);
            b.dependent = Some(exguid(f, "ridDependent")?);
            if hdr.id == 0x01B {
                f.u64("timeCreation").filetime().emit()?;
            }
            b.role = Some(f.u32("RevisionRole").emit()?);
            f.u16("odcsDefault").hex().emit()?;
            if hdr.id == 0x01F {
                b.context = Some(exguid(f, "gctxid")?);
            }
        }
        0x021 => {
            f.u8("Reserved").emit()?;
        }
        0x024 => {
            b.index = Some(f.u32("index").emit()?);
            let g = f.guid("guid").emit()?;
            b.guid = Some(guid_bytes(&g));
        }
        0x025 => {
            f.u32("iIndexMapFrom").emit()?;
            f.u32("iIndexMapTo").emit()?;
        }
        0x026 => {
            f.u32("iIndexCopyFromStart").emit()?;
            f.u32("cEntriesToCopy").emit()?;
            f.u32("iIndexCopyToStart").emit()?;
        }
        0x02D | 0x02E => {
            b.fcr = Some(reference(f, hdr, file, "ObjectRef")?);
            b.oid = Some(Oid::Compact(compact(f, "oid", table)?));
            let jci_span = f.peek_span(2);
            let bits = f.u16("jci, odcs").get()?;
            let jci = u32::from(bits & 0x3FF);
            let full = JCID_IS_PROPERTY_SET | jci;
            b.jcid = Some(full);
            f.node(
                Node::new("jci")
                    .span(jci_span)
                    .value(jcid_value(full))
                    .summary(format!("odcs {}", (bits >> 10) & 0xF)),
            );
            let flags_span = f.peek_span(4);
            let flags = f.u32("Flags").get()?;
            f.node(
                Node::new("Flags")
                    .span(flags_span)
                    .value(Value::UInt {
                        value: flags.into(),
                        bits: 32,
                        radix: crate::value::Radix::Hex,
                    })
                    .summary(ref_flags(flags)),
            );
            b.cref = Some(if hdr.id == 0x02D {
                f.u8("cRef").emit()?.into()
            } else {
                f.u32("cRef").emit()?
            });
        }
        0x041 => {
            b.fcr = Some(reference(f, hdr, file, "ref")?);
            b.oid = Some(Oid::Compact(compact(f, "oid", table)?));
            let v = f
                .u8("fHasOidReferences, fHasOsidReferences, cRef")
                .with(|&v, n| n.summary(format!("{}, cRef {}", ref_flags(v.into()), v >> 2)))
                .emit()?;
            b.cref = Some((v >> 2).into());
        }
        0x042 => {
            b.fcr = Some(reference(f, hdr, file, "ref")?);
            b.oid = Some(Oid::Compact(compact(f, "oid", table)?));
            f.u32("Flags")
                .hex()
                .with(|&v, n| n.summary(ref_flags(v)))
                .emit()?;
            b.cref = Some(f.u32("cRef").emit()?);
        }
        0x059 => {
            b.oid = Some(Oid::Compact(compact(f, "oidRoot", table)?));
            b.role = Some(
                f.u32("RootRole")
                    .enumeration(super::tables::ROOT_ROLES)
                    .emit()?,
            );
        }
        0x05A => {
            b.oid = Some(Oid::Full(exguid(f, "oidRoot")?));
            b.role = Some(
                f.u32("RootRole")
                    .enumeration(super::tables::ROOT_ROLES)
                    .emit()?,
            );
        }
        0x05C | 0x05D => {
            b.rid = Some(exguid(f, "rid")?);
            b.role = Some(f.u32("RevisionRole").emit()?);
            if hdr.id == 0x05D {
                b.context = Some(exguid(f, "gctxid")?);
            }
        }
        0x072 | 0x073 => {
            b.oid = Some(Oid::Compact(compact(f, "oid", table)?));
            b.jcid = Some(jcid(f, "jcid")?);
            b.cref = Some(if hdr.id == 0x072 {
                f.u8("cRef").emit()?.into()
            } else {
                f.u32("cRef").emit()?
            });
            b.file_ref = Some(storage_string(f, "FileDataReference")?);
            b.extension = Some(storage_string(f, "Extension")?);
        }
        0x084 => {
            let fcr = reference(f, hdr, file, "ref")?;
            b.fcr = Some(fcr);
            if fcr.nil {
                overrides(f, table)?;
            }
        }
        0x08C | 0x0B4 => {
            b.id = Some(exguid(
                f,
                if hdr.id == 0x08C {
                    "DataSignatureGroup"
                } else {
                    "oid"
                },
            )?)
        }
        0x094 => {
            b.fcr = Some(reference(f, hdr, file, "ref")?);
            let g = f.guid("guidReference").emit()?;
            b.guid = Some(guid_bytes(&g));
        }
        0x0A4 | 0x0A5 | 0x0C4 | 0x0C5 => {
            b.fcr = Some(reference(f, hdr, file, "ref")?);
            b.oid = Some(Oid::Compact(compact(f, "oid", table)?));
            b.jcid = Some(jcid(f, "jcid")?);
            f.u8("Flags")
                .hex()
                .with(|&v, n| n.summary(ref_flags(v.into())))
                .emit()?;
            b.cref = Some(if matches!(hdr.id, 0x0A4 | 0x0C4) {
                f.u8("cRef").emit()?.into()
            } else {
                f.u32("cRef").emit()?
            });
            if matches!(hdr.id, 0x0C4 | 0x0C5) {
                md5(f)?;
            }
        }
        0x0B0 => {
            b.fcr = Some(reference(f, hdr, file, "ref")?);
            b.id = Some(exguid(f, "ObjectGroupID")?);
        }
        0x0C2 => {
            b.fcr = Some(reference(f, hdr, file, "BlobRef")?);
            f.bytes("guidHash", 16).emit()?;
        }
        _ => {}
    }
    Ok(b)
}

fn ref_flags(v: u32) -> String {
    let mut parts = Vec::new();
    if v & 1 != 0 {
        parts.push("has object references");
    }
    if v & 2 != 0 {
        parts.push("has object space references");
    }
    if parts.is_empty() {
        "no references".to_owned()
    } else {
        parts.join(", ")
    }
}

pub fn guid_bytes(g: &Guid) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut parts = g
        .data1
        .to_le_bytes()
        .into_iter()
        .chain(g.data2.to_le_bytes())
        .chain(g.data3.to_le_bytes())
        .chain(g.data4);
    for b in out.iter_mut() {
        *b = parts.next().unwrap_or(0);
    }
    out
}

/// Parses `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` (case-insensitive) into
/// the GUID's on-disk bytes.
pub fn parse_guid(text: &str) -> Option<[u8; 16]> {
    let inner = text.trim().strip_prefix('{')?.strip_suffix('}')?;
    let hex: String = inner.chars().filter(|&c| c != '-').collect();
    if hex.len() != 32 || inner.len() != 36 {
        return None;
    }
    let byte = |i: usize| {
        u8::from_str_radix(
            hex.get(i.saturating_mul(2)..i.saturating_mul(2).saturating_add(2))?,
            16,
        )
        .ok()
    };
    let mut be = [0u8; 16];
    for (i, b) in be.iter_mut().enumerate() {
        *b = byte(i)?;
    }
    // data1..data3 are little-endian on disk.
    let order = [3usize, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];
    let mut out = [0u8; 16];
    for (o, &i) in out.iter_mut().zip(order.iter()) {
        *o = *be.get(i)?;
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn guid_strings_round_trip() {
        let bytes = parse_guid("{BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}").unwrap();
        assert_eq!(
            guid_le(&bytes).to_string(),
            "{bde316e7-2665-4511-a4c4-8d4d0b7a9eac}"
        );
        assert_eq!(guid_bytes(&guid_le(&bytes)), bytes);
        assert!(parse_guid("{BDE316E7-2665-4511-A4C4-8D4D0B7A9EA}").is_none());
    }

    #[test]
    fn node_references_scale_and_detect_nil() {
        // stpFormat 3 (4 bytes ×8), cbFormat 2 (1 byte ×8)
        let hdr = Hdr::new((3 << 23) | (2 << 25) | (1 << 27) | (24 << 10) | 0xA4);
        assert_eq!(hdr.ref_len(), 5);
        let r = hdr.decode_ref(&[0x10, 0, 0, 0, 3]).unwrap();
        assert_eq!((r.stp, r.cb, r.nil), (0x80, 24, false));
        let nil = hdr.decode_ref(&[0xFF, 0xFF, 0xFF, 0xFF, 0]).unwrap();
        assert!(nil.nil);
    }
}
