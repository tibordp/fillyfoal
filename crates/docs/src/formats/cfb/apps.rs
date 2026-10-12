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
    /// A Windows Installer transform (the root of an .mst, or a storage
    /// inside a package or patch): its tables are stored row by row, each
    /// row with a mask of the columns it changes, against its own string
    /// pool (see [`super::msi::transform_table`]).
    MsiTransform,
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
            Context::Msi | Context::MsiTransform => Context::MsiTransform,
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
pub fn installer_kind(clsid: &Guid) -> Option<&'static str> {
    if clsid.data2 != 0 || clsid.data3 != 0 || clsid.data4 != [0xc0, 0, 0, 0, 0, 0, 0, 0x46] {
        return None;
    }
    match clsid.data1 {
        0x000c_1084 => Some("Windows Installer package"),
        0x000c_1086 => Some("Windows Installer patch"),
        0x000c_1082 => Some("Windows Installer transform"),
        _ => None,
    }
}

/// Recognises the application from the root storage, and finds a title.
pub async fn application(
    cx: &Cx,
    cfb: &super::CfbRef,
    root: &DirEntry,
) -> (Option<String>, Context) {
    if let Some(kind) = installer_kind(&root.clsid) {
        let context = if root.clsid.data1 == 0x000c_1082 {
            Context::MsiTransform
        } else {
            Context::Msi
        };
        // A transform's Property stream holds changes, not the product.
        let product = match context {
            Context::Msi => super::msi::product(cx, cfb).await,
            _ => None,
        };
        let title = match product {
            Some(p) => Some(p),
            None => summary_title(cx, cfb, root).await,
        };
        return (Some(with_title(kind, title)), context);
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
    let has_ci = |n: &str| names.iter().any(|(name, _)| name.eq_ignore_ascii_case(n));
    let (kind, context) = if has("WordDocument") {
        // Word 6.0/95 files carry their own class, CLSID_WordDocument6;
        // Word 97 and later use {00020906-...}.
        let word6 = root.clsid.data1 == 0x0002_0900
            && root.clsid.data2 == 0
            && root.clsid.data3 == 0
            && root.clsid.data4 == [0xc0, 0, 0, 0, 0, 0, 0, 0x46];
        if word6 {
            ("Word 6.0/95 document", Context::Plain)
        } else {
            ("Word 97-2003 document", Context::Plain)
        }
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
    } else if has_ci("SwDocContentMgr") && has_ci("SwDocMgrTempStorage") {
        ("SolidWorks document", Context::Plain)
    } else if has_ci("RSeStorage") && has_ci("RSeDb") {
        // The class of part documents (libmagic's ole2compounddocs).
        let part = root.clsid.data1 == 0x4d29_b490
            && root.clsid.data2 == 0x49b2
            && root.clsid.data3 == 0x11d0
            && root.clsid.data4 == [0x93, 0xc3, 0x7e, 0x07, 0x06, 0, 0, 0];
        if part {
            ("Inventor part", Context::Plain)
        } else {
            ("Inventor document", Context::Plain)
        }
    } else if has_ci("BasicFileInfo")
        && (has_ci("TransmissionData") || (has_ci("Global") && has_ci("Partitions")))
    {
        // Only family files carry PartAtom.
        if has_ci("PartAtom") {
            ("Revit family", Context::Plain)
        } else {
            ("Revit project", Context::Plain)
        }
    } else if has("Quill") {
        ("Publisher document", Context::Plain)
    } else if has("VBA") && has("PROJECT") {
        ("VBA project", Context::Plain)
    } else if has("EncryptionInfo") && has("EncryptedPackage") {
        let info = match names.iter().find(|(n, _)| n == "EncryptionInfo") {
            Some((_, id)) => encryption_summary(cx, cfb, *id).await,
            None => None,
        };
        let kind = match info {
            Some(info) => format!("Encrypted Office Open XML document ({info})"),
            None => "Encrypted Office Open XML document".to_owned(),
        };
        return (Some(kind), Context::Plain);
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

/// The scheme an `EncryptionInfo` stream names.
async fn encryption_summary(cx: &Cx, cfb: &Cfb, id: u32) -> Option<String> {
    let entry = read_entry(cx, cfb, id).await.ok()?;
    let (span, _) = super::stream(cx, cfb, id, &entry).await.ok()?;
    let head = span.sub(0, 0x1000);
    let data = cx.read_avail(head).await.ok()?;
    Some(super::offcrypto::summary(&data, head))
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
    if matches!(context, Context::Msi | Context::MsiTransform)
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
        "EncryptionInfo" => Some("encryption parameters and password verifier"),
        "EncryptedPackage" => Some("the encrypted Office Open XML package"),
        "\u{6}DataSpaces" => Some("data space definitions (how the package is transformed)"),
        "VisioDocument" => Some("Visio document stream"),
        "BasicFileInfo" => Some("Revit file information (version, build, worksharing, paths)"),
        "PartAtom" => Some("Revit family types and parameters (Atom XML)"),
        "TransmissionData" => Some("Revit external reference states"),
        "RevitPreview4.0" => Some("Revit preview (PNG image)"),
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
        (_, n) if n.starts_with('\u{5}') => propset::emit(cx, input, span).await,
        (_, "\u{1}CompObj") => compobj(cx, span).await,
        (_, "\u{1}Ole") => ole_stream(cx, span).await,
        (_, "\u{1}Ole10Native") => ole10_native(cx, input, span).await,
        (Context::Plain, "WordDocument") => {
            let t0 = super::child_stream(cx, cfb, state.parent, "0Table").await;
            let t1 = super::child_stream(cx, cfb, state.parent, "1Table").await;
            let data = super::child_stream(cx, cfb, state.parent, "Data").await;
            super::word::word(cx, input, span, [t0, t1], data).await
        }
        (Context::Plain, "0Table" | "1Table") => {
            cx.emit(
                raw_content(input, span)
                    .desc("The structures in this stream are located and decoded through the FIB, under WordDocument"),
            );
            Ok(())
        }
        (Context::Plain, "EncryptionInfo") => {
            super::offcrypto::encryption_info(cx, input, span).await
        }
        (Context::Plain, "EncryptedPackage") => super::offcrypto::encrypted_package(cx, span).await,
        (Context::Plain, "Workbook" | "Book") => super::biff::workbook(cx, input, span).await,
        (Context::Plain, "PowerPoint Document") => {
            let current = super::child_stream(cx, cfb, state.parent, "Current User").await;
            let pictures = super::child_stream(cx, cfb, state.parent, "Pictures").await;
            super::ppt::document(cx, input, span, current, pictures).await
        }
        (Context::Plain, "Current User" | "Pictures" | "EscherStm" | "EscherDelayStm") => {
            super::officeart::walk(cx.clone(), (input, span, 0, None)).await
        }
        (Context::Plain, "VisioDocument") => super::visio::document(cx, input, span).await,
        (Context::Plain, "RevitPreview4.0") => png_after_header(cx, input, span).await,
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
            Some("_StringPool") => super::msi::string_pool(cx, cfb, (0, false), span).await,
            Some("_StringData") => super::msi::string_data(cx, cfb, (0, false), span).await,
            Some(table) => super::msi::table(cx, cfb, table, span).await,
            None => {
                cx.emit(raw_content(input, span));
                Ok(())
            }
        },
        (Context::MsiTransform, n) => {
            let at = (state.parent, true);
            match msi_name(n).as_deref().and_then(|d| d.strip_prefix('!')) {
                Some("_StringPool") => super::msi::string_pool(cx, cfb, at, span).await,
                Some("_StringData") => super::msi::string_data(cx, cfb, at, span).await,
                Some(table) => {
                    super::msi::transform_table(cx, cfb, state.parent, table, span).await
                }
                None => {
                    cx.emit(raw_content(input, span));
                    Ok(())
                }
            }
        }
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

/// A stream holding a PNG image after a header of its own (Revit's
/// `RevitPreview4.0`): the header is not documented, so the image is found
/// by its signature in the first 64 KiB.
async fn png_after_header(cx: &Cx, input: Input, span: Span) -> Result<()> {
    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";
    let head = cx.read_avail(span.sub(0, 0x10000)).await?;
    let found = head.windows(PNG.len()).position(|w| w == PNG);
    let Some(at) = found.map(crate::bytes::to_u64) else {
        cx.emit(raw_content(input, span));
        return Ok(());
    };
    if at > 0 {
        cx.emit(
            Node::new("Header")
                .span(span.sub(0, at))
                .summary(format!("{at} bytes")),
        );
    }
    let image = span.tail(at);
    cx.emit(crate::formats::embedded_as(
        "Preview image",
        input.nested(image),
        &crate::formats::image::png::FORMAT,
    ));
    Ok(())
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

const PACKAGE_TYPES: EnumTable = &[(1, "linked file"), (3, "embedded file")];

/// Where the parts of an OLE Packager object lie, relative to the start of
/// its native data.
struct Package {
    data_at: u64,
    data_len: u64,
}

/// Recognises the Packager object layout (the class of files dropped into
/// a document): signature 2, the label and source path as NUL-terminated
/// ANSI strings, the type (3 = embedded), the temporary path with its
/// length, then the file's size and bytes. `head` starts at the native
/// data; the file must fit within `native_len`.
fn package(head: &[u8], native_len: u64) -> Option<Package> {
    if crate::bytes::u16_le(head, 0)? != 2 {
        return None;
    }
    let mut at = 2usize;
    for _ in 0..2 {
        let n = head.get(at..)?.iter().position(|&b| b == 0)?;
        at = at.checked_add(n)?.checked_add(1)?;
    }
    if u32_le(head, at)? != 0x0003_0000 {
        return None;
    }
    let temp = usize::try_from(u32_le(head, at.checked_add(4)?)?).ok()?;
    at = at.checked_add(8)?.checked_add(temp)?;
    let data_len = u64::from(u32_le(head, at)?);
    let data_at = crate::bytes::to_u64(at.checked_add(4)?);
    (data_at.checked_add(data_len)? <= native_len).then_some(Package { data_at, data_len })
}

/// `\x01Ole10Native`: an OLE 1.0 object's native data, after its size.
/// For a Packager object (an arbitrary file embedded in a document) the
/// file is located and dissected; other classes' data is shown as is.
async fn ole10_native(cx: &Cx, input: Input, span: Span) -> Result<()> {
    let head = cx.block(span.sub(0, 0x2000)).await?;
    let mut f = Fields::emitting(cx, &head, LE);
    let size = f
        .u32("NativeDataSize")
        .desc("Bytes of native data that follow")
        .emit()?;
    let native = span.sub(4, u64::from(size));
    if native.len < u64::from(size) {
        cx.diag(crate::error::Diagnostic::truncated(native, native.len));
    }
    let Some(p) = package(head.data.get(4..).unwrap_or_default(), native.len) else {
        cx.emit(
            Node::new("Native data")
                .span(native)
                .summary(format!("{} bytes", native.len))
                .desc("Data in the format of the object's OLE 1.0 class")
                .lazy(crate::formats::dissect_or_data, input.nested(native)),
        );
        return Ok(());
    };
    f.u16("Signature").desc("2 for a Packager object").emit()?;
    let label = f
        .cstr("Label")
        .desc("The name shown under the object's icon")
        .emit()?;
    f.cstr("Source path")
        .desc("Where the file was packaged from")
        .emit()?;
    f.u16("Reserved").emit()?;
    f.u16("Type").enumeration(PACKAGE_TYPES).emit()?;
    let temp = f.u32("Temporary path length").emit()?;
    f.ascii("Temporary path", u64::from(temp))
        .desc("Where the file is extracted to when opened")
        .emit()?;
    f.u32("File size").emit()?;
    let data = native.sub(p.data_at, p.data_len);
    cx.emit(
        Node::new("Embedded file")
            .span(data)
            .summary(format!("{label:?}, {} bytes", data.len))
            .lazy(crate::formats::dissect_or_data, input.nested(data)),
    );
    // Newer packagers repeat the temporary path, label and source path in
    // UTF-16 after the file.
    let after = p.data_at.saturating_add(p.data_len);
    let rest = native.len.saturating_sub(after);
    if rest >= 4 {
        let tail = cx.block(native.sub(after, rest.min(0x2000))).await?;
        let mut t = Fields::emitting(cx, &tail, LE);
        for name in [
            "Temporary path (UTF-16)",
            "Label (UTF-16)",
            "Source path (UTF-16)",
        ] {
            if t.remaining() < 4 {
                break;
            }
            let n = t.u32("Length (characters)").emit()?;
            t.utf16(name, u64::from(n)).emit()?;
        }
        let left = t.remaining();
        if left > 0 {
            t.bytes("Remaining data", left).emit()?;
        }
    }
    Ok(())
}
