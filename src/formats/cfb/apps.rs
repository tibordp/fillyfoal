//! What the compound file is used for: recognising the application,
//! naming entries (MSI's encoded stream names, Outlook's property streams),
//! and choosing a decoder for each stream.

use super::{
    Cfb, DirEntry, StreamState, TreeWalk, display_name, entry_name, msg, propset, read_entry,
};
use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::Input;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Guid, Value};

use super::rec::LE;

/// What kind of storage a stream lives in, which decides how entries are
/// named and decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    Plain,
    Msi,
    /// The top level of an Outlook message.
    MsgRoot,
    /// A message embedded in an attachment.
    MsgEmbedded,
    /// A recipient or attachment storage.
    Msg,
    /// The named property mapping storage.
    MsgNameid,
    Thumbs,
    /// A VBA project's `VBA` storage.
    Vba,
}

impl Context {
    pub fn child(parent: Context, name: &str) -> Context {
        match parent {
            Context::MsgRoot | Context::Msg | Context::MsgEmbedded | Context::MsgNameid => {
                if name == "__substg1.0_3701000D" {
                    Context::MsgEmbedded
                } else if name == "__nameid_version1.0" {
                    Context::MsgNameid
                } else {
                    Context::Msg
                }
            }
            _ if name == "VBA" => Context::Vba,
            Context::Vba => Context::Plain,
            other => other,
        }
    }

    pub fn is_msg(self) -> bool {
        matches!(
            self,
            Context::MsgRoot | Context::Msg | Context::MsgEmbedded | Context::MsgNameid
        )
    }
}

/// The Windows Installer CLSIDs of the root storage.
pub fn installer_kind(clsid: &[u8; 16]) -> Option<&'static str> {
    const TAIL: [u8; 12] = [
        0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ];
    if clsid.get(4..) != Some(&TAIL[..]) {
        return None;
    }
    match u32_le(clsid, 0)? {
        0x000c_1084 => Some("Windows Installer package"),
        0x000c_1086 => Some("Windows Installer patch"),
        0x000c_1082 => Some("Windows Installer transform"),
        _ => None,
    }
}

fn guid_bytes(g: &Guid) -> [u8; 16] {
    let mut out = [0u8; 16];
    let d1 = g.data1.to_le_bytes();
    let d2 = g.data2.to_le_bytes();
    let d3 = g.data3.to_le_bytes();
    for (slot, b) in out
        .iter_mut()
        .zip(d1.iter().chain(&d2).chain(&d3).chain(&g.data4))
    {
        *slot = *b;
    }
    out
}

/// Recognises the application from the root storage, and finds a title.
pub async fn application(
    cx: &Cx,
    cfb: &super::CfbRef,
    root: &DirEntry,
) -> (Option<String>, Context) {
    if let Some(kind) = installer_kind(&guid_bytes(&root.clsid)) {
        let title = match super::msi::product(cx, cfb).await {
            Some(p) => Some(p),
            None => summary_title(cx, cfb, root).await,
        };
        return (Some(with_title(kind, title)), Context::Msi);
    }
    let mut names = Vec::new();
    let mut walk = TreeWalk::new(root.child);
    while let Some((id, entry)) = walk.next(cx, cfb).await {
        names.push((entry_name(&entry), id));
        if names.len() >= super::MAX_ROOT_SCAN {
            break;
        }
    }
    let has = |n: &str| names.iter().any(|(name, _)| name == n);
    let (kind, context) = if has("WordDocument") {
        ("Word 97-2003 document", Context::Plain)
    } else if has("Workbook") {
        ("Excel 97-2003 workbook", Context::Plain)
    } else if has("Book") {
        ("Excel 5.0/95 workbook", Context::Plain)
    } else if has("PowerPoint Document") {
        ("PowerPoint 97-2003 presentation", Context::Plain)
    } else if has("__properties_version1.0") || has("__nameid_version1.0") {
        ("Outlook message", Context::MsgRoot)
    } else if has("Catalog") {
        ("Thumbs.db thumbnail cache", Context::Thumbs)
    } else if has("VisioDocument") {
        ("Visio drawing", Context::Plain)
    } else if has("Quill") {
        ("Publisher document", Context::Plain)
    } else if has("VBA") && has("PROJECT") {
        ("VBA project", Context::Plain)
    } else if has("\u{1}Ole10Native") {
        ("OLE 1.0 embedded object", Context::Plain)
    } else {
        return (None, Context::Plain);
    };
    let title = if context == Context::MsgRoot {
        let subject = names
            .iter()
            .find(|(n, _)| n == "__substg1.0_0037001F" || n == "__substg1.0_0037001E");
        match subject {
            Some((n, id)) => stream_text(cx, cfb, *id, n.ends_with('F')).await,
            None => None,
        }
    } else {
        summary_title(cx, cfb, root).await
    };
    (Some(with_title(kind, title)), context)
}

fn with_title(kind: &str, title: Option<String>) -> String {
    match title {
        Some(t) if !t.is_empty() => format!("{kind} {t:?}"),
        _ => kind.to_owned(),
    }
}

/// The title from the root's `\x05SummaryInformation`, if any.
async fn summary_title(cx: &Cx, cfb: &Cfb, root: &DirEntry) -> Option<String> {
    let mut walk = TreeWalk::new(root.child);
    let mut scanned = 0usize;
    while let Some((id, entry)) = walk.next(cx, cfb).await {
        scanned = scanned.saturating_add(1);
        if scanned > super::MAX_ROOT_SCAN {
            return None;
        }
        if entry_name(&entry) == "\u{5}SummaryInformation" {
            let (span, _) = super::stream(cx, cfb, id, &entry).await.ok()?;
            return propset::title(cx, span).await;
        }
    }
    None
}

async fn stream_text(cx: &Cx, cfb: &Cfb, id: u32, wide: bool) -> Option<String> {
    let entry = read_entry(cx, cfb, id).await.ok()?;
    let (span, _) = super::stream(cx, cfb, id, &entry).await.ok()?;
    let data = cx.read_avail(span.sub(0, 1024)).await.ok()?;
    Some(if wide {
        crate::text::utf16z(&data, Endian::Little).0
    } else {
        crate::text::until_nul(&data)
    })
}

/// MSI stream names pack two base-64 characters into one code point
/// (U+3800..U+47FF), one into U+4800..U+483F, and mark tables with U+4840.
pub fn msi_name(raw: &str) -> Option<String> {
    const ALPHABET: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";
    let b64 = |v: u32| {
        usize::try_from(v & 0x3f)
            .ok()
            .and_then(|i| ALPHABET.get(i))
            .map_or('?', |&c| char::from(c))
    };
    if !raw.chars().any(|c| ('\u{3800}'..='\u{4840}').contains(&c)) {
        return None;
    }
    let mut out = String::new();
    for c in raw.chars() {
        let u = u32::from(c);
        match u {
            0x3800..0x4800 => {
                let v = u.saturating_sub(0x3800);
                out.push(b64(v));
                out.push(b64(v >> 6));
            }
            0x4800..0x4840 => out.push(b64(u.saturating_sub(0x4800))),
            0x4840 => out.push('!'),
            _ => out.push(c),
        }
    }
    Some(out)
}

/// A display label for an entry, and a short description.
pub fn label(
    raw: &str,
    context: Context,
    names: Option<&msg::NameMap>,
) -> (String, Option<String>) {
    if context == Context::Msi
        && let Some(name) = msi_name(raw)
    {
        return match name.strip_prefix('!') {
            Some(table) => {
                let detail = match table {
                    "_StringPool" => "string pool: lengths and reference counts",
                    "_StringData" => "string pool: characters",
                    "_Tables" => "table catalog",
                    "_Columns" => "column catalog",
                    "_Validation" => "validation table",
                    _ => "MSI table",
                };
                (table.to_owned(), Some(detail.to_owned()))
            }
            None => (name, None),
        };
    }
    if context.is_msg()
        && let Some((name, detail)) = msg::label(raw, names, context == Context::MsgNameid)
    {
        return (name, Some(detail));
    }
    let detail = match raw {
        "\u{5}SummaryInformation" => Some("summary information property set"),
        "\u{5}DocumentSummaryInformation" => Some("document summary property set"),
        "WordDocument" => Some("Word document stream"),
        "0Table" | "1Table" => Some("Word table stream"),
        "Data" => Some("Word data stream (pictures, form fields)"),
        "Workbook" => Some("Excel BIFF8 workbook stream"),
        "Book" => Some("Excel BIFF5 workbook stream"),
        "PowerPoint Document" => Some("PowerPoint document stream"),
        "Current User" => Some("PowerPoint current user"),
        "Pictures" => Some("embedded pictures"),
        "\u{1}CompObj" => Some("OLE class information"),
        "\u{1}Ole" => Some("OLE object information"),
        "\u{1}Ole10Native" => Some("OLE 1.0 native data"),
        "Macros" | "_VBA_PROJECT_CUR" => Some("VBA project storage"),
        "VBA" => Some("VBA modules"),
        "PROJECT" => Some("VBA project properties"),
        "PROJECTwm" => Some("VBA module names"),
        "dir" if context == Context::Vba => Some("VBA project information (compressed)"),
        "_VBA_PROJECT" => Some("VBA version and performance cache"),
        "ObjectPool" => Some("embedded objects"),
        "Catalog" => Some("thumbnail catalog"),
        "EscherStm" | "EscherDelayStm" => Some("Office Art drawing records"),
        "Contents" => Some("Publisher contents"),
        _ => None,
    };
    if context == Context::Thumbs && !raw.is_empty() && raw.chars().all(|c| c.is_ascii_digit()) {
        let index: String = raw.chars().rev().collect();
        return (raw.to_owned(), Some(format!("thumbnail {index}")));
    }
    let detail = detail.map(str::to_owned).or_else(|| {
        (context == Context::Vba && !raw.starts_with("__SRP_"))
            .then(|| "VBA module stream".to_owned())
    });
    (display_name(raw), detail)
}

/// Emits the decoded content of a stream.
pub async fn content(cx: &Cx, state: &StreamState, span: Span) -> Result<()> {
    let cfb = &state.cfb;
    let input = cfb.input;
    let name = state.name.as_str();
    match (state.context, name) {
        (_, n) if n.starts_with('\u{5}') => propset::emit(cx, span).await,
        (_, "\u{1}CompObj") => compobj(cx, span).await,
        (_, "\u{1}Ole") => ole_stream(cx, span).await,
        (Context::Plain, "WordDocument") => {
            let t0 = super::child_stream(cx, cfb, state.parent, "0Table").await;
            let t1 = super::child_stream(cx, cfb, state.parent, "1Table").await;
            super::word::word(cx, input, span, [t0, t1]).await
        }
        (Context::Plain, "0Table" | "1Table") => {
            cx.emit(
                raw_content(input, span)
                    .desc("The structures in this stream are located and decoded through the FIB, under WordDocument"),
            );
            Ok(())
        }
        (Context::Plain, "Workbook" | "Book") => super::biff::workbook(cx, input, span).await,
        (Context::Plain, "PowerPoint Document") => {
            let current = super::child_stream(cx, cfb, state.parent, "Current User").await;
            super::ppt::document(cx, input, span, current).await
        }
        (Context::Plain, "Current User" | "Pictures" | "EscherStm" | "EscherDelayStm") => {
            super::officeart::walk(cx.clone(), (input, span, 0)).await
        }
        (Context::Plain, "PROJECT") => super::vba::project_stream(cx, span).await,
        (Context::Plain, "PROJECTwm") => super::vba::project_wm(cx, span).await,
        (Context::Vba, "dir") => super::vba::dir(cx, span).await,
        (Context::Vba, "_VBA_PROJECT") => super::vba::vba_project(cx, span).await,
        (Context::Vba, n) => {
            match super::vba::module(cx, cfb, input, state.parent, n, span).await {
                Some(r) => r,
                None => {
                    cx.emit(raw_content(input, span));
                    Ok(())
                }
            }
        }
        (
            Context::MsgRoot | Context::Msg | Context::MsgEmbedded | Context::MsgNameid,
            "__properties_version1.0",
        ) => {
            let level = match state.context {
                Context::MsgRoot => msg::Level::Top,
                Context::MsgEmbedded => msg::Level::Embedded,
                _ => msg::Level::Child,
            };
            msg::properties(cx, cfb, span, level).await
        }
        (c, n) if c.is_msg() && msg::tag(n).is_some() => {
            msg::value_stream(cx, cfb, input, n, span).await
        }
        (Context::Msi, n) => match msi_name(n).as_deref().and_then(|d| d.strip_prefix('!')) {
            Some("_StringPool") => super::msi::string_pool(cx, cfb, span).await,
            Some("_StringData") => super::msi::string_data(cx, cfb, span).await,
            Some(table) => super::msi::table(cx, cfb, table, span).await,
            None => {
                cx.emit(raw_content(input, span));
                Ok(())
            }
        },
        (Context::Thumbs, "Catalog") => super::thumbs::catalog(cx, span).await,
        (Context::Thumbs, n) if n.chars().all(|c| c.is_ascii_digit()) => {
            super::thumbs::thumbnail(cx, input, span).await
        }
        _ => {
            cx.emit(raw_content(input, span));
            Ok(())
        }
    }
}

/// The stream's bytes, identified and dissected on expansion.
fn raw_content(input: Input, span: Span) -> Node {
    Node::new("Content")
        .span(span)
        .summary(format!("{} bytes", span.len))
        .lazy(crate::formats::dissect_or_data, input.nested(span))
}

const CLIPBOARD_MARKERS: EnumTable = &[
    (0xffff_ffff, "Windows clipboard format follows"),
    (0xffff_fffe, "Macintosh clipboard format follows"),
    (0, "none"),
];

/// `\x01CompObj`: the class's user-visible name, clipboard format and
/// program ID, in ANSI and (optionally) Unicode.
async fn compobj(cx: &Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(cx, &block, LE);
    f.u32("Reserved1").hex().desc("0xFFFE0001").emit()?;
    f.u32("Version").hex().emit()?;
    f.bytes("Reserved2", 20).emit()?;
    for step in 0..3 {
        if f.remaining() < 4 {
            break;
        }
        match step {
            0 => ansi(&mut f, "AnsiUserType")?,
            1 => clipboard(&mut f, false)?,
            _ => ansi(&mut f, "ProgID")?,
        }
    }
    if f.remaining() >= 4 {
        let marker = f
            .u32("UnicodeMarker")
            .hex()
            .desc("0x71B239F4 if Unicode strings follow")
            .emit()?;
        if marker == 0x71b2_39f4 {
            wide(&mut f, "UnicodeUserType")?;
            clipboard(&mut f, true)?;
            wide(&mut f, "UnicodeProgID")?;
        }
    }
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Remaining data", rest).emit()?;
    }
    Ok(())
}

fn ansi(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    let at = crate::bytes::to_usize(f.pos());
    let len = u64::from(u32_le(&f.block().data, at).unwrap_or(0));
    f.u32("Length").emit()?;
    let text = crate::text::until_nul(
        f.block()
            .data
            .get(
                at.saturating_add(4)
                    ..at.saturating_add(4)
                        .saturating_add(crate::bytes::to_usize(len)),
            )
            .unwrap_or_default(),
    );
    f.node(
        Node::new(name)
            .span(f.peek_span(len))
            .value(Value::Text(text)),
    );
    f.skip(len);
    Ok(())
}

fn wide(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    let at = crate::bytes::to_usize(f.pos());
    let len = u64::from(u32_le(&f.block().data, at).unwrap_or(0));
    f.u32("Length (characters)").emit()?;
    f.utf16(name, len).emit()?;
    Ok(())
}

fn clipboard(f: &mut Fields<'_>, unicode: bool) -> Result<()> {
    let at = crate::bytes::to_usize(f.pos());
    let marker = u32_le(&f.block().data, at).unwrap_or(0);
    if marker == 0xffff_ffff || marker == 0xffff_fffe {
        f.u32("ClipboardFormat marker")
            .enumeration(CLIPBOARD_MARKERS)
            .emit()?;
        f.u32("ClipboardFormat").emit()?;
    } else if marker == 0 {
        f.u32("ClipboardFormat")
            .enumeration(CLIPBOARD_MARKERS)
            .emit()?;
    } else if unicode {
        wide(f, "ClipboardFormat")?;
    } else {
        ansi(f, "ClipboardFormat")?;
    }
    Ok(())
}

const OLE_FLAGS: crate::value::FlagTable = &[
    crate::value::flag(0x1, "linked object"),
    crate::value::flag(0x8, "implementation-specific hint"),
];

/// `\x01Ole`: the OLE object header (embedded or linked).
async fn ole_stream(cx: &Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(cx, &block, LE);
    f.u32("Version").hex().desc("0x02000001").emit()?;
    f.u32("Flags").flags(OLE_FLAGS).emit()?;
    f.u32("LinkUpdateOption").emit()?;
    f.u32("Reserved1").emit()?;
    let moniker = f.u32("ReservedMonikerStreamSize").emit()?;
    if moniker > 0 && f.remaining() > 0 {
        let n = u64::from(moniker).saturating_sub(4).min(f.remaining());
        f.bytes("ReservedMonikerStream", n).emit()?;
    }
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Remaining data", rest)
            .desc("Relative and absolute moniker streams, local update time, check times (linked objects)")
            .emit()?;
    }
    Ok(())
}
