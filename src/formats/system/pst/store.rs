//! The messaging layer ([MS-PST] 2.4) and views of the lower layers.

use super::ltp::{self, Cell, NodeRef, Raw, Tc};
use super::ndb::{self, Bref, Entry, Pst};
use super::props;
use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::embedded;
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Radix, Value, lookup};

const NID_MESSAGE_STORE: u32 = 0x21;
const NID_NAME_TO_ID_MAP: u32 = 0x61;
const NID_ROOT_FOLDER: u32 = 0x122;
const NID_RECIPIENT_TABLE: u32 = 0x692;
const NID_ATTACHMENT_TABLE: u32 = 0x671;

/// Deepest folder tree and chain of attached messages followed.
const MAX_FOLDER_DEPTH: usize = 64;
const MAX_MESSAGE_DEPTH: usize = 16;
/// Deepest chain of subnode trees shown in node views.
const MAX_SUBNODE_DEPTH: usize = 16;

const PROP_ROW_ID: u16 = 0x67f2;

const SPECIAL_NIDS: EnumTable = &[
    (0x21, "message store"),
    (0x61, "name-to-ID map"),
    (0xa1, "normal folder template"),
    (0xc1, "search folder template"),
    (0x122, "root folder"),
    (0x1e1, "search management queue"),
    (0x201, "search activity list"),
    (0x261, "search domain object"),
    (0x281, "search gatherer queue"),
    (0x2a1, "search gatherer descriptor"),
    (0x321, "search gatherer folder queue"),
    (0x60d, "hierarchy table template"),
    (0x60e, "contents table template"),
    (0x60f, "associated contents table template"),
    (0x610, "search contents table template"),
    (0x617, "receive folder table"),
    (0x64c, "outgoing queue table"),
    (0x671, "attachment table"),
    (0x692, "recipient table"),
    (0x6b6, "search table index template"),
];

/// A NID's index, type and (for special NIDs) role.
pub fn nid_name(nid: u32) -> String {
    let ty = (nid & 0x1f) as usize;
    let kind = super::NID_TYPES
        .get(ty)
        .copied()
        .unwrap_or("?")
        .trim_start_matches("NID_TYPE_")
        .to_lowercase()
        .replace('_', " ");
    match lookup(SPECIAL_NIDS, nid.into()) {
        Some(role) => format!("NID {nid:#x} ({role})"),
        None => format!("NID {nid:#x} ({kind} {})", nid >> 5),
    }
}

async fn node_ref(cx: &Cx, pst: &Pst, nid: u32) -> Result<NodeRef> {
    let e = ndb::find_node(cx, pst, nid).await?.ok_or_else(|| {
        Diagnostic::malformed(format!("{} is not in the node B-tree", nid_name(nid)))
    })?;
    Ok(NodeRef {
        nid: e.nid,
        data: e.data,
        sub: e.sub,
    })
}

// ---------------------------------------------------------------------------
// Top level

/// Emits the message store, the name-to-ID map and the folder tree;
/// returns the store's display name.
pub async fn top(cx: &Cx, pst: &Pst) -> Result<Option<String>> {
    let store = node_ref(cx, pst, NID_MESSAGE_STORE).await?;
    let pc = ltp::pc(cx, pst, store).await?;
    let name = string_prop(cx, pst, &pc, 0x3001).await.map(|(s, _)| s);
    let mut node = Node::new("Message store")
        .span(pc.heap.header)
        .lazy(properties, (*pst, store));
    if let Some(n) = &name {
        node = node.summary(format!("{n:?}"));
    }
    cx.emit(node);
    if let Ok(map) = node_ref(cx, pst, NID_NAME_TO_ID_MAP).await {
        let names = props::name_map(cx, pst).await;
        cx.emit(
            Node::new("Named property map")
                .summary(format!(
                    "{} named properties",
                    names.iter().flatten().count()
                ))
                .lazy(properties, (*pst, map)),
        );
    }
    cx.emit(Node::new("Folders").lazy(
        crate::expander!(self::folder: (Pst, u32, Path)),
        (*pst, NID_ROOT_FOLDER, Path::new()),
    ));
    Ok(name)
}

/// The value of a string property of a property context.
async fn string_prop(cx: &Cx, pst: &Pst, pc: &ltp::Pc, id: u16) -> Option<(String, Span)> {
    let p = pc
        .props
        .iter()
        .find(|p| p.id == id && matches!(p.ty, 0x1e | 0x1f))?;
    let raw = ltp::prop_value(cx, pst, &pc.heap, p).await.ok()?;
    let (bytes, span) = props::read_raw(cx, &raw).await.ok()?;
    Some((props::text(p.ty, &bytes), span))
}

async fn int_prop(cx: &Cx, pst: &Pst, pc: &ltp::Pc, id: u16) -> Option<(u64, Span)> {
    let p = pc.props.iter().find(|p| p.id == id)?;
    let raw = ltp::prop_value(cx, pst, &pc.heap, p).await.ok()?;
    let (bytes, span) = props::read_raw(cx, &raw).await.ok()?;
    let v = match p.ty {
        0x0002 => u64::from(u16_le(&bytes, 0)?),
        0x0003 | 0x000b => u64::from(u32_le(&bytes, 0)?),
        0x0014 | 0x0040 => u64_le(&bytes, 0)?,
        _ => return None,
    };
    Some((v, span))
}

/// All properties of a property context, named and typed.
async fn properties(cx: Cx, (pst, node): (Pst, NodeRef)) -> Result<()> {
    let pc = ltp::pc(&cx, &pst, node).await?;
    let names = props::name_map(&cx, &pst).await;
    cx.set_count(Count::Exact(to_u64(pc.props.len())));
    for p in &pc.props {
        let name = if node.nid == NID_NAME_TO_ID_MAP && p.id >= 0x1000 && p.id < 0x8000 {
            format!("Hash bucket {}", p.id.saturating_sub(0x1000))
        } else {
            props::name(p.id, &names)
        };
        let tag = (u32::from(p.id) << 16) | u32::from(p.ty);
        let ty = lookup(props::TYPES, p.ty.into()).unwrap_or("unknown type");
        let base = Node::new(name).desc(format!("{ty}, tag {tag:#010x}"));
        let node = match ltp::prop_value(&cx, &pst, &pc.heap, p).await {
            Ok(raw) => match props::read_raw(&cx, &raw).await {
                Ok((bytes, span)) => props::value_node(&pst, base, p.id, p.ty, &bytes, span),
                Err(e) => base.span(p.record).diag(e),
            },
            Err(e) => base.span(p.record).diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Folders

async fn folder(cx: Cx, (pst, nid, path): (Pst, u32, Path)) -> Result<()> {
    let path = path.enter(nid.into(), MAX_FOLDER_DEPTH)?;
    let node = node_ref(&cx, &pst, nid).await?;
    let pc = ltp::pc(&cx, &pst, node).await?;
    cx.emit(
        Node::new("Properties")
            .span(pc.heap.header)
            .summary(format!("{} properties", pc.props.len()))
            .lazy(properties, (pst, node)),
    );
    let base = nid & !0x1f;
    // Subfolders, from the hierarchy table.
    if let Ok(table) = node_ref(&cx, &pst, base | 0x0d).await {
        let tc = ltp::tc(&cx, &pst, table).await?;
        let count = tc.count(&pst);
        for i in 0..count {
            let (row, span) = read_row(&cx, &pst, &tc, i).await?;
            let get = |id| tc.column(id).copied();
            let child = match get(PROP_ROW_ID) {
                Some(c) => fixed_u32(&cx, &pst, &tc, &row, span, &c).await,
                None => None,
            };
            let Some(child) = child else { continue };
            let name = text_cell(&cx, &pst, &tc, &row, span, 0x3001)
                .await
                .unwrap_or_else(|| nid_name(child));
            let messages = int_cell(&cx, &pst, &tc, &row, span, 0x3602).await;
            let unread = int_cell(&cx, &pst, &tc, &row, span, 0x3603).await;
            let mut n = Node::new(name).span(span).lazy(
                crate::expander!(self::folder: (Pst, u32, Path)),
                (pst, child, path.clone()),
            );
            if let Some(m) = messages {
                n = n.summary(match unread {
                    Some(u) if u > 0 => format!("{m} messages, {u} unread"),
                    _ => format!("{m} messages"),
                });
            }
            cx.emit(n);
        }
    }
    for (ty, label) in [(0x0e, "Messages"), (0x0f, "Associated contents")] {
        let Ok(table) = node_ref(&cx, &pst, base | ty).await else {
            continue;
        };
        let tc = ltp::tc(&cx, &pst, table).await?;
        let count = tc.count(&pst);
        if count == 0 && ty == 0x0f {
            continue;
        }
        cx.emit(
            Node::new(label)
                .span(tc.info)
                .summary(format!("{count} rows"))
                .lazy(contents, (pst, table, path.clone())),
        );
    }
    Ok(())
}

async fn read_row(cx: &Cx, pst: &Pst, tc: &Tc, index: u64) -> Result<(Vec<u8>, Span)> {
    let span = tc.row(cx, pst, index).await?;
    Ok((cx.read(span).await?, span))
}

async fn fixed_u32(
    cx: &Cx,
    pst: &Pst,
    tc: &Tc,
    row: &[u8],
    span: Span,
    col: &ltp::Column,
) -> Option<u32> {
    match ltp::cell(cx, pst, tc, row, span, col).await.ok()?? {
        Cell::Fixed(b, _) => u32_le(&b, 0),
        Cell::Data(_) => None,
    }
}

async fn int_cell(cx: &Cx, pst: &Pst, tc: &Tc, row: &[u8], span: Span, id: u16) -> Option<u64> {
    let col = *tc.column(id)?;
    match ltp::cell(cx, pst, tc, row, span, &col).await.ok()?? {
        Cell::Fixed(b, _) => match b.len() {
            1 => b.first().map(|&v| u64::from(v)),
            2 => u16_le(&b, 0).map(u64::from),
            4 => u32_le(&b, 0).map(u64::from),
            _ => u64_le(&b, 0),
        },
        Cell::Data(_) => None,
    }
}

async fn text_cell(cx: &Cx, pst: &Pst, tc: &Tc, row: &[u8], span: Span, id: u16) -> Option<String> {
    let col = *tc.column(id)?;
    if !matches!(col.ty(), 0x1e | 0x1f) {
        return None;
    }
    match ltp::cell(cx, pst, tc, row, span, &col).await.ok()?? {
        Cell::Data(s) => {
            let bytes = cx.read_avail(s.sub(0, 4096)).await.ok()?;
            Some(props::text(col.ty(), &bytes))
        }
        Cell::Fixed(..) => None,
    }
}

/// The messages of a contents table, in table order.
async fn contents(cx: Cx, (pst, table, path): (Pst, NodeRef, Path)) -> Result<()> {
    let tc = ltp::tc(&cx, &pst, table).await?;
    let count = tc.count(&pst);
    cx.set_count(Count::Exact(count));
    let start = cx.resume::<u64>().unwrap_or(0);
    for i in start..count {
        cx.mark(move || i);
        if cx.skipping() {
            cx.push(Node::new("Message")).await;
            continue;
        }
        let (row, span) = read_row(&cx, &pst, &tc, i).await?;
        let Some(col) = tc.column(PROP_ROW_ID).copied() else {
            return Err(
                Diagnostic::malformed("contents table without a row ID column").at(tc.info),
            );
        };
        let nid = fixed_u32(&cx, &pst, &tc, &row, span, &col)
            .await
            .unwrap_or(0);
        let subject = text_cell(&cx, &pst, &tc, &row, span, 0x0037).await;
        let mut sender = None;
        for id in [0x0042, 0x0c1a, 0x0065, 0x0c1f] {
            sender = text_cell(&cx, &pst, &tc, &row, span, id)
                .await
                .filter(|s| !s.is_empty());
            if sender.is_some() {
                break;
            }
        }
        let date = match int_cell(&cx, &pst, &tc, &row, span, 0x0e06).await {
            Some(d) if d != 0 => Some(d),
            _ => int_cell(&cx, &pst, &tc, &row, span, 0x0039).await,
        };
        let name = match subject {
            Some(s) if !s.is_empty() => strip_prefix(&s),
            _ => "(no subject)".to_owned(),
        };
        let mut node = Node::new(name).span(span).lazy(
            crate::expander!(self::message: (Pst, Msg, Path)),
            (pst, Msg::Top(nid), path.clone()),
        );
        if let Some(d) = date.filter(|&d| d != 0) {
            node = node.value(Value::Timestamp {
                unix_seconds: crate::text::filetime_to_unix(d),
            });
        }
        if let Some(s) = sender {
            node = node.summary(format!("from {s}"));
        }
        cx.push(node).await;
    }
    Ok(())
}

/// Subjects may start with a two-character prefix marker (0x01, length).
fn strip_prefix(s: &str) -> String {
    let mut chars = s.chars();
    if chars.next() == Some('\u{1}') {
        chars.next();
        return chars.collect();
    }
    s.to_owned()
}

// ---------------------------------------------------------------------------
// Messages

/// A message: a top-level node (by NID) or an attached message (a subnode).
#[derive(Clone, Copy, Debug)]
pub enum Msg {
    Top(u32),
    Sub(NodeRef),
}

async fn message(cx: Cx, (pst, msg, path): (Pst, Msg, Path)) -> Result<()> {
    let node = match msg {
        Msg::Top(nid) => node_ref(&cx, &pst, nid).await?,
        Msg::Sub(n) => n,
    };
    let path = path.enter(node.data, MAX_MESSAGE_DEPTH)?;
    let pc = ltp::pc(&cx, &pst, node).await?;
    cx.emit(
        Node::new("Properties")
            .span(pc.heap.header)
            .summary(format!("{} properties", pc.props.len()))
            .lazy(properties, (pst, node)),
    );
    // The usual header fields.
    let from = if pc.props.iter().any(|p| p.id == 0x0042) {
        0x0042
    } else {
        0x0c1a
    };
    for (id, label) in [
        (0x0037, "Subject"),
        (from, "From"),
        (0x0e04, "To"),
        (0x0e03, "Cc"),
        (0x0e02, "Bcc"),
    ] {
        if let Some((mut text, span)) = string_prop(&cx, &pst, &pc, id).await {
            if id == 0x0037 {
                text = strip_prefix(&text);
            }
            if text.is_empty() && id != 0x0037 {
                continue;
            }
            let mut n = Node::new(label).span(span).value(Value::Text(text));
            let address = if id == 0x0042 { 0x0065 } else { 0x0c1f };
            if label == "From"
                && let Some((addr, _)) = string_prop(&cx, &pst, &pc, address).await
            {
                n = n.summary(format!("<{addr}>"));
            }
            cx.emit(n);
        }
    }
    for (id, label) in [(0x0039, "Sent"), (0x0e06, "Received")] {
        if let Some((t, span)) = int_prop(&cx, &pst, &pc, id).await
            && t != 0
        {
            cx.emit(Node::new(label).span(span).value(Value::Timestamp {
                unix_seconds: crate::text::filetime_to_unix(t),
            }));
        }
    }
    if let Some((size, span)) = int_prop(&cx, &pst, &pc, 0x0e08).await {
        cx.emit(Node::new("Size").span(span).value(Value::UInt {
            value: size,
            bits: 32,
            radix: Radix::Dec,
        }));
    }
    // Bodies.
    for (id, label) in [
        (0x1000, "Body"),
        (0x1013, "HTML body"),
        (0x007d, "Transport headers"),
        (0x1009, "RTF body"),
    ] {
        let Some(p) = pc.props.iter().find(|p| p.id == id) else {
            continue;
        };
        let Ok(Raw::Data(span)) = ltp::prop_value(&cx, &pst, &pc.heap, p).await else {
            continue;
        };
        let node = if p.ty == 0x1f {
            match utf16_text(&cx, span).await {
                Ok(text) => embedded(label, pst.input.nested(text))
                    .summary(format!("{} characters", span.len / 2)),
                Err(e) => Node::new(label).span(span).diag(e),
            }
        } else if id == 0x1009 {
            // The header's second word is the decompressed size; stored
            // (`MELA`) RTF is the rest of the data, whatever it says.
            let head = cx.read_avail(span.sub(0, 12)).await.unwrap_or_default();
            let size = if head.get(8..12) == Some(b"LZFu") {
                u32_le(&head, 4).map(u64::from)
            } else {
                Some(span.len.saturating_sub(16))
            };
            let mut n =
                crate::formats::content(label, pst.input, span, crate::codec::Codec::Lzfu, size);
            if let Some(s) = size {
                n = n.summary(format!("{s} bytes"));
            }
            n
        } else {
            embedded(label, pst.input.nested(span)).summary(format!("{} bytes", span.len))
        };
        cx.emit(node);
    }
    // Recipients and attachments live in subnodes.
    let subs = ndb::subnodes(&cx, &pst, node.sub).await?;
    if let Some(e) = subs.iter().find(|e| e.nid == NID_RECIPIENT_TABLE) {
        let table = NodeRef::from_sub(e);
        cx.emit(
            Node::new("Recipients")
                .span(e.span)
                .lazy(recipients, (pst, table)),
        );
    }
    if let Some(e) = subs.iter().find(|e| e.nid == NID_ATTACHMENT_TABLE) {
        let table = NodeRef::from_sub(e);
        let count = match ltp::tc(&cx, &pst, table).await {
            Ok(tc) => tc.count(&pst),
            Err(_) => 0,
        };
        if count > 0 {
            cx.emit(
                Node::new("Attachments")
                    .span(e.span)
                    .summary(format!("{count}"))
                    .lazy(attachments, (pst, node, table, path)),
            );
        }
    }
    Ok(())
}

/// UTF-16 text as a UTF-8 derived source (for text dissectors).
async fn utf16_text(cx: &Cx, span: Span) -> Result<Span> {
    let origin = Origin {
        parent: span,
        transform: "utf-16le",
    };
    if let Some(found) = cx.derived(origin) {
        return Ok(found.span);
    }
    let data = cx.read(span).await?;
    let text = crate::text::utf16(&data, Endian::Little);
    let text = text.trim_end_matches('\0').as_bytes().to_vec();
    Ok(cx.add_derived(origin, text, span.len, None)?.span)
}

async fn recipients(cx: Cx, (pst, table): (Pst, NodeRef)) -> Result<()> {
    let tc = ltp::tc(&cx, &pst, table).await?;
    let count = tc.count(&pst);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let (row, span) = read_row(&cx, &pst, &tc, i).await?;
        let name = text_cell(&cx, &pst, &tc, &row, span, 0x3001).await;
        let smtp = match text_cell(&cx, &pst, &tc, &row, span, 0x39fe).await {
            Some(s) => Some(s),
            None => text_cell(&cx, &pst, &tc, &row, span, 0x3003).await,
        };
        let kind = int_cell(&cx, &pst, &tc, &row, span, 0x0c15).await;
        let mut n = Node::new(name.unwrap_or_else(|| "(no name)".to_owned()))
            .span(span)
            .lazy(row_cells, (pst, table, i));
        if let Some(a) = smtp {
            n = n.value(Value::Text(a));
        }
        if let Some(k) = kind {
            n = n.summary(
                lookup(&[(1, "To"), (2, "Cc"), (3, "Bcc")], k & 0xf)
                    .map_or_else(|| format!("type {k}"), str::to_owned),
            );
        }
        cx.push(n).await;
    }
    Ok(())
}

async fn attachments(cx: Cx, (pst, msg, table, path): (Pst, NodeRef, NodeRef, Path)) -> Result<()> {
    let tc = ltp::tc(&cx, &pst, table).await?;
    let count = tc.count(&pst);
    cx.set_count(Count::Exact(count));
    let subs = ndb::subnodes(&cx, &pst, msg.sub).await?;
    for i in 0..count {
        let (row, span) = read_row(&cx, &pst, &tc, i).await?;
        let nid = match tc.column(PROP_ROW_ID).copied() {
            Some(c) => fixed_u32(&cx, &pst, &tc, &row, span, &c).await,
            None => None,
        };
        let name = match text_cell(&cx, &pst, &tc, &row, span, 0x3707).await {
            Some(s) if !s.is_empty() => s,
            _ => text_cell(&cx, &pst, &tc, &row, span, 0x3704)
                .await
                .unwrap_or_else(|| format!("Attachment {i}")),
        };
        let Some(entry) = nid.and_then(|n| subs.iter().find(|e| e.nid == n)) else {
            cx.push(
                Node::new(name)
                    .span(span)
                    .diag(Diagnostic::malformed("attachment subnode not found")),
            )
            .await;
            continue;
        };
        let mut node = Node::new(name)
            .span(entry.span)
            .lazy(attachment, (pst, NodeRef::from_sub(entry), path.clone()));
        let size = int_cell(&cx, &pst, &tc, &row, span, 0x0e20).await;
        let method = int_cell(&cx, &pst, &tc, &row, span, 0x3705).await;
        let mut summary = Vec::new();
        if let Some(m) = method.and_then(|m| lookup(props::ATTACH_METHOD, m)) {
            summary.push(m.to_lowercase());
        }
        if let Some(s) = size {
            summary.push(format!("{s} bytes"));
        }
        if !summary.is_empty() {
            node = node.summary(summary.join(", "));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn attachment(cx: Cx, (pst, node, path): (Pst, NodeRef, Path)) -> Result<()> {
    let pc = ltp::pc(&cx, &pst, node).await?;
    cx.emit(
        Node::new("Properties")
            .span(pc.heap.header)
            .summary(format!("{} properties", pc.props.len()))
            .lazy(properties, (pst, node)),
    );
    let name = match string_prop(&cx, &pst, &pc, 0x3707).await {
        Some((s, _)) if !s.is_empty() => s,
        _ => string_prop(&cx, &pst, &pc, 0x3704)
            .await
            .map_or_else(|| "Data".to_owned(), |(s, _)| s),
    };
    let Some(p) = pc.props.iter().find(|p| p.id == 0x3701) else {
        return Ok(());
    };
    if p.ty == 0x000d {
        // PtypObject: an HID holding (NID, size); the NID is a subnode
        // holding the attached message.
        let nid = if p.raw & 0x1f == 0 {
            let span = ltp::item(&cx, &pst, &pc.heap, p.raw).await?;
            u32_le(&cx.read(span).await?, 0).unwrap_or(0)
        } else {
            p.raw
        };
        let entry = ltp::find_sub(&cx, &pst, node.sub, nid).await?;
        let msg = NodeRef::from_sub(&entry);
        cx.emit(Node::new("Attached message").span(entry.span).lazy(
            crate::expander!(self::message: (Pst, Msg, Path)),
            (pst, Msg::Sub(msg), path),
        ));
        return Ok(());
    }
    match ltp::prop_value(&cx, &pst, &pc.heap, p).await? {
        Raw::Data(span) => {
            cx.emit(embedded(name, pst.input.nested(span)).summary(format!("{} bytes", span.len)))
        }
        Raw::Inline(_, span) => cx.emit(Node::new(name).span(span)),
    }
    Ok(())
}

/// The cells of one table row, as properties.
async fn row_cells(cx: Cx, (pst, table, index): (Pst, NodeRef, u64)) -> Result<()> {
    let tc = ltp::tc(&cx, &pst, table).await?;
    let (row, span) = read_row(&cx, &pst, &tc, index).await?;
    let names = props::name_map(&cx, &pst).await;
    for col in &tc.columns {
        let Some(cell) = ltp::cell(&cx, &pst, &tc, &row, span, col).await.transpose() else {
            continue;
        };
        let name = props::name(col.id(), &names);
        let base = Node::new(name);
        let node = match cell {
            Ok(Cell::Fixed(bytes, s)) => {
                props::value_node(&pst, base, col.id(), col.ty(), &bytes, s)
            }
            Ok(Cell::Data(s)) => match cx.read_avail(s.sub(0, props::MAX_TEXT)).await {
                Ok(bytes) => props::value_node(&pst, base, col.id(), col.ty(), &bytes, s),
                Err(e) => base.diag(e),
            },
            Err(e) => base.diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}

/// A table context: its columns and rows.
async fn table(cx: Cx, (pst, node): (Pst, NodeRef)) -> Result<()> {
    let tc = ltp::tc(&cx, &pst, node).await?;
    let mut cols = Node::new("Columns").span(tc.info).summary(format!(
        "{} columns, {}-byte rows",
        tc.columns.len(),
        tc.row_size()
    ));
    if let Some(first) = tc.columns.first() {
        cols = cols.span(first.span);
    }
    cx.emit(cols.lazy(columns, (pst, node)));
    let count = tc.count(&pst);
    cx.set_count(Count::Exact(count.saturating_add(1)));
    for i in 0..count {
        let span = tc.row(&cx, &pst, i).await?;
        cx.push(
            Node::new(format!("Row {i}"))
                .span(span)
                .lazy(row_cells, (pst, node, i)),
        )
        .await;
    }
    Ok(())
}

async fn columns(cx: Cx, (pst, node): (Pst, NodeRef)) -> Result<()> {
    let tc = ltp::tc(&cx, &pst, node).await?;
    let names = props::name_map(&cx, &pst).await;
    for c in &tc.columns {
        let ty = lookup(props::TYPES, c.ty().into()).unwrap_or("unknown type");
        cx.emit(
            Node::new(props::name(c.id(), &names))
                .span(c.span)
                .value(Value::UInt {
                    value: c.tag.into(),
                    bits: 32,
                    radix: Radix::Hex,
                })
                .summary(format!(
                    "{ty}, {} bytes at {}, existence bit {}",
                    c.size, c.offset, c.bit
                )),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Views of the NDB layer

pub fn btree_node(name: &'static str, pst: Pst, root: Bref) -> Node {
    Node::new(name)
        .summary(format!("root page {:#x} at {:#x}", root.bid, root.ib))
        .lazy(
            crate::expander!(self::btree_page: (Pst, Bref, u8)),
            (pst, root, 9u8),
        )
}

async fn btree_page(cx: Cx, (pst, bref, parent_level): (Pst, Bref, u8)) -> Result<()> {
    let page = ndb::page(&cx, &pst, bref).await?;
    if page.level >= parent_level {
        return Err(Diagnostic::malformed("B-tree levels do not decrease").at(page.span));
    }
    for p in &page.problems {
        cx.diag(p.clone().at(page.span));
    }
    cx.emit(
        Node::new("Page trailer")
            .span(page.trailer)
            .summary(format!(
                "{} page, BID {:#x}",
                if page.ptype == ndb::PTYPE_NBT {
                    "NBT"
                } else {
                    "BBT"
                },
                bref.bid
            )),
    );
    cx.emit(Node::new("Page metadata").span(page.meta).summary(format!(
        "{} of {} entries of {} bytes, level {}",
        page.entries.len(),
        page.max,
        page.cb_ent,
        page.level
    )));
    for (entry, span) in &page.entries {
        let node = match *entry {
            Entry::Branch { key, child } => Node::new(format!("Key {key:#x}"))
                .span(*span)
                .summary(format!("page {:#x} at {:#x}", child.bid, child.ib))
                .lazy(
                    crate::expander!(self::btree_page: (Pst, Bref, u8)),
                    (pst, child, page.level),
                ),
            Entry::Node(n) => {
                let node = NodeRef {
                    nid: n.nid,
                    data: n.data,
                    sub: n.sub,
                };
                let mut s = format!("data {:#x}", n.data);
                if n.sub != 0 {
                    s.push_str(&format!(", subnodes {:#x}", n.sub));
                }
                if n.parent != 0 {
                    s.push_str(&format!(", parent {:#x}", n.parent));
                }
                Node::new(nid_name(n.nid)).span(*span).summary(s).lazy(
                    crate::expander!(self::node_view: (Pst, NodeRef, Path)),
                    (pst, node, Path::new()),
                )
            }
            Entry::Block(b) => Node::new(format!("BID {:#x}", b.bref.bid))
                .span(*span)
                .summary(format!(
                    "{} bytes at {:#x}, {} references{}",
                    b.cb,
                    b.bref.ib,
                    b.refs,
                    if b.bref.bid & 2 != 0 {
                        ", internal"
                    } else {
                        ""
                    }
                ))
                .lazy(block_view, (pst, b.bref.bid)),
        };
        cx.push(node).await;
    }
    Ok(())
}

/// A node: its data (decoded and interpreted) and its subnodes.
async fn node_view(cx: Cx, (pst, node, path): (Pst, NodeRef, Path)) -> Result<()> {
    let path = path.enter(node.data, MAX_SUBNODE_DEPTH)?;
    if node.data != 0 {
        let blocks = ndb::data_tree(&cx, &pst, node.data).await?;
        let total: u64 = blocks
            .iter()
            .map(|b| b.raw.len)
            .fold(0, u64::saturating_add);
        cx.emit(
            Node::new("Data blocks")
                .summary(format!("{} blocks, {total} bytes", blocks.len()))
                .lazy(data_blocks, (pst, node.data)),
        );
        let stream = ndb::stream(&cx, &pst, node.data).await?;
        let mut data = Node::new("Data").span(stream);
        // Interpret it as LTP data when it starts with a heap header.
        let head = cx.read_avail(stream.sub(0, 4)).await?;
        if head.get(2) == Some(&ltp::SIG_HN) {
            match head.get(3).copied() {
                Some(ltp::SIG_PC) => {
                    data = data.summary("property context");
                    // Folders, messages, attachments and the store are
                    // shown with their properties under "Folders" and
                    // "Message store"; other objects only here.
                    if !shown_elsewhere(node.nid) {
                        data = data.lazy(properties, (pst, node));
                    }
                }
                Some(ltp::SIG_TC) => {
                    data = data.summary("table context").lazy(table, (pst, node));
                }
                Some(other) => {
                    data = data.summary(format!("heap-on-node, client {other:#04x}"));
                }
                None => {}
            }
        }
        // Other data (bodies, attachment contents, row matrices) is
        // interpreted where the messaging view shows it.
        cx.emit(data);
    }
    let subs = ndb::subnodes(&cx, &pst, node.sub).await?;
    for e in subs.iter() {
        cx.push(
            Node::new(format!("Subnode {}", nid_name(e.nid)))
                .span(e.span)
                .summary(format!("data {:#x}, subnodes {:#x}", e.data, e.sub))
                .lazy(
                    crate::expander!(self::node_view: (Pst, NodeRef, Path)),
                    (pst, NodeRef::from_sub(e), path.clone()),
                ),
        )
        .await;
    }
    Ok(())
}

/// Whether a property context's properties are listed by the messaging
/// view (so the node view need not repeat them).
fn shown_elsewhere(nid: u32) -> bool {
    matches!(nid & 0x1f, 0x02 | 0x04 | 0x05)
        || matches!(nid, NID_MESSAGE_STORE | NID_NAME_TO_ID_MAP)
}

async fn data_blocks(cx: Cx, (pst, bid): (Pst, u64)) -> Result<()> {
    for b in ndb::data_tree(&cx, &pst, bid).await? {
        cx.push(
            Node::new(format!("BID {:#x}", b.bid))
                .span(b.alloc)
                .summary(format!("{} bytes", b.raw.len))
                .lazy(block_view, (pst, b.bid)),
        )
        .await;
    }
    Ok(())
}

async fn block_view(cx: Cx, (pst, bid): (Pst, u64)) -> Result<()> {
    let b = ndb::block(&cx, &pst, bid).await?;
    let trailer = b.trailer(&pst);
    let t = cx.read(trailer).await?;
    let cb = u16_le(&t, 0).unwrap_or(0);
    let sig = u16_le(&t, 2).unwrap_or(0);
    let (crc, tbid) = if pst.wide() {
        (u32_le(&t, 4).unwrap_or(0), u64_le(&t, 8).unwrap_or(0))
    } else {
        (
            u32_le(&t, 8).unwrap_or(0),
            u32_le(&t, 4).map_or(0, u64::from),
        )
    };
    let raw = cx.read(b.raw).await?;
    let computed = ndb::PST_CRC.checksum(&raw) as u32;
    let mut tn = Node::new("Block trailer").span(trailer).summary(format!(
        "cb {cb}, signature {sig:#06x}, CRC {crc:#010x}, BID {tbid:#x}"
    ));
    if crc != computed {
        tn = tn.diag(Diagnostic::warning(format!(
            "CRC {crc:#010x} does not match the computed {computed:#010x}"
        )));
    }
    let expected = ndb::signature(b.alloc.offset.saturating_sub(pst.file().offset), b.bid);
    if sig != expected {
        tn = tn.diag(Diagnostic::warning(format!(
            "signature {sig:#06x} does not match the computed {expected:#06x}"
        )));
    }
    if tbid & !1 != b.bid & !1 {
        tn = tn.diag(Diagnostic::warning(format!(
            "trailer BID {tbid:#x} differs"
        )));
    }
    if u64::from(cb) != b.raw.len {
        tn = tn.diag(Diagnostic::warning(
            "trailer size differs from the block B-tree's",
        ));
    }
    if b.internal() {
        let btype = raw.first().copied().unwrap_or(0);
        let level = raw.get(1).copied().unwrap_or(0);
        let kind = match (btype, level) {
            (1, 1) => "XBLOCK (data tree)",
            (1, 2) => "XXBLOCK (data tree)",
            (2, 0) => "SLBLOCK (subnodes)",
            (2, 1) => "SIBLOCK (subnode index)",
            _ => "unknown internal block",
        };
        let count = u16_le(&raw, 2).unwrap_or(0);
        let mut s = format!("{kind}, {count} entries");
        if btype == 1 {
            s.push_str(&format!(
                ", {} bytes in total",
                u32_le(&raw, 4).unwrap_or(0)
            ));
        }
        cx.emit(Node::new("Data").span(b.raw).summary(s));
    } else {
        let plain = ndb::plain(&cx, &pst, &b).await?;
        if plain != b.raw {
            cx.emit(Node::new("Data (encoded)").span(b.raw));
        }
        cx.emit(Node::new("Data").span(plain));
    }
    cx.emit(tn);
    Ok(())
}
