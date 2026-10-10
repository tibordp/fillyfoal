//! Word 6.0 and Word 95 documents (wIdent 0xA5DC). Their File Information
//! Block has a fixed layout: the header, where the text is (fcMin..fcMac),
//! the character counts of the stories, and fc/lcb pairs that match the
//! first 38 of Word 97's, except that the structures they locate are in
//! the WordDocument stream itself (there is no table stream). Text is 8-bit,
//! in the code page of the character set it was typed in, which the file
//! does not record: it is taken from the font table.
//!
//! Decoded: the FIB, the text (directly, or through the piece table of a
//! fast-saved document), the font table and the associated strings. The
//! stylesheet, sections and formatting pages use Word 6 sprms (one-byte
//! opcodes), which differ from Word 97's, and are only located.

use std::sync::Arc;

use super::super::rec::{self, LE, bits, quoted};
use super::{
    ASSOC, CHARSETS, Doc, ENVR, FIB_FLAGS2, FONT_FAMILY, Fib, NFIB, PAIRS, PITCH, PREVIEW, pair,
    pair_desc, pieces, text_node, text_range,
};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Fields;
use crate::formats::util::val::{hex, uint};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

/// Where the fc/lcb pairs start, how many there are, and where the FIB's
/// trailing page numbers end.
const PAIRS_AT: u64 = 0x58;
const PAIR_COUNT: usize = 38;
const TAIL_AT: u64 = 0x188;
const FIB_END: u64 = 0x192;

const FIB6_FLAGS: FlagTable = &[
    flag(0x0001, "fDot"),
    flag(0x0002, "fGlsy"),
    flag(0x0004, "fComplex"),
    flag(0x0008, "fHasPic"),
    crate::value::field(0x00f0, 0x0000, "cQuickSaves=0"),
    flag(0x0100, "fEncrypted"),
    flag(0x0400, "fReadOnlyRecommended"),
    flag(0x0800, "fWriteReservation"),
    flag(0x1000, "fExtChar"),
];

const CHSE: EnumTable = &[(0, "Windows ANSI"), (256, "Macintosh")];

record! {
    /// The fixed part of a Word 6.0/95 FIB, up to the fc/lcb pairs.
    pub struct Fib6 {
        ident: u16 "wIdent" .hex() .desc("0xA5DC for Word 6.0/95"),
        nfib: u16 "nFib" .hex() .enumeration(NFIB) .desc("File format version"),
        product: u16 "nProduct" .hex() .desc("Build of the program that saved the file"),
        lid: u16 "lid" .hex() .with(|&v, n| n.summary(crate::formats::util::lcid::describe(v.into()))) .desc("Language of the installation that created the document"),
        pn_next: u16 "pnNext" .desc("512-byte page of the AutoText FIB, if any"),
        flags: u16 "Flags" .flags(FIB6_FLAGS) .with(|&v, n| n.summary(format!("cQuickSaves {}", (v >> 4) & 0xf))),
        nfib_back: u16 "nFibBack" .hex() .desc("Oldest version that can read the file"),
        key: u32 "lKey" .hex() .desc("Encryption key, if fEncrypted"),
        envr: u8 "envr" .enumeration(ENVR),
        flags2: u8 "Flags 2" .flags(FIB_FLAGS2),
        chse: u16 "chse" .enumeration(CHSE) .desc("Character set of the text: Windows or Macintosh"),
        chse_tables: u16 "chseTables" .enumeration(CHSE) .desc("Character set of the strings in the internal structures"),
        fc_min: u32 "fcMin" .hex() .desc("Offset of the first character of text"),
        fc_mac: u32 "fcMac" .hex() .desc("Offset just past the last character of text"),
        cb_mac: u32 "cbMac" .desc("Bytes of the WordDocument stream in use"),
        _spare0: u32 "fcSpare0",
        _spare1: u32 "fcSpare1",
        _spare2: u32 "fcSpare2",
        _spare3: u32 "fcSpare3",
        ccp_text: u32 "ccpText" .desc("Characters in the main document"),
        ccp_ftn: u32 "ccpFtn" .desc("Characters in the footnote subdocument"),
        ccp_hdd: u32 "ccpHdd" .desc("Characters in the header subdocument"),
        ccp_mcr: u32 "ccpMcr" .desc("Characters in the macro subdocument"),
        ccp_atn: u32 "ccpAtn" .desc("Characters in the annotation subdocument"),
        ccp_edn: u32 "ccpEdn" .desc("Characters in the endnote subdocument"),
        ccp_txbx: u32 "ccpTxbx" .desc("Characters in the textbox subdocument"),
        ccp_hdr_txbx: u32 "ccpHdrTxbx" .desc("Characters in the header textbox subdocument"),
        _spare_ccp: u32 "ccpSpare2",
    }
}

record! {
    /// The page numbers after the fc/lcb pairs.
    pub struct Fib6Tail {
        _spare: u16 "wSpare4Fib",
        pn_chp_first: u16 "pnChpFirst" .desc("First page of character formatting (FKPs)"),
        pn_pap_first: u16 "pnPapFirst" .desc("First page of paragraph formatting (FKPs)"),
        cpn_bte_chp: u16 "cpnBteChp" .desc("Pages of character formatting"),
        cpn_bte_pap: u16 "cpnBtePap" .desc("Pages of paragraph formatting"),
    }
}

/// The code page of each Windows font charset that is not Western.
const CHARSET_CODEPAGES: &[(u8, u16)] = &[
    (128, 932),
    (129, 949),
    (134, 936),
    (136, 950),
    (161, 1253),
    (162, 1254),
    (163, 1258),
    (177, 1255),
    (178, 1256),
    (186, 1257),
    (204, 1251),
    (222, 874),
    (238, 1250),
];

/// One FFN of a Word 6 font table: offset and size within the table, name,
/// charset.
struct Font {
    at: usize,
    len: usize,
    name: String,
    chs: u8,
}

/// The fonts of a Word 6 SttbfFfn: a 16-bit total size, then FFNs (a size
/// byte, flags, weight, charset, alternative-name index, 8-bit names).
fn font_list(data: &[u8]) -> Vec<Font> {
    let end = usize::from(u16_le(data, 0).unwrap_or(0)).min(data.len());
    let mut at = 2usize;
    let mut out = Vec::new();
    while at < end {
        let Some(&cb_m1) = data.get(at) else { break };
        let len = usize::from(cb_m1).saturating_add(1);
        let ffn = data.get(at..at.saturating_add(len)).unwrap_or_default();
        let name = ffn.get(6..).unwrap_or_default();
        let name = name.split(|&b| b == 0).next().unwrap_or_default();
        out.push(Font {
            at,
            len,
            name: crate::text::latin1(name),
            chs: ffn.get(4).copied().unwrap_or(0),
        });
        at = at.saturating_add(len);
    }
    out
}

/// The code page of the text, and why. The FIB only says Windows or Mac;
/// on Windows, the text is in the code page of the charset of its fonts.
/// A non-Western charset among them names it (Word installed the "CE",
/// "Cyr", ... variants of the system fonts on such systems).
fn codepage(chse: u16, fonts: &[Font]) -> (u16, String) {
    if chse == 256 {
        return (
            10000,
            "the FIB says the text is in the Macintosh character set".into(),
        );
    }
    for font in fonts {
        if let Some(&(chs, cp)) = CHARSET_CODEPAGES.iter().find(|(c, _)| *c == font.chs) {
            return (
                cp,
                format!(
                    "the code page of the font {:?} ({}); the file does not record it",
                    font.name,
                    lookup(CHARSETS, chs.into()).unwrap_or("charset")
                ),
            );
        }
    }
    (
        1252,
        "no font has a non-Western charset; the file does not record the code page".into(),
    )
}

pub(super) async fn word6(cx: &Cx, wd: Span, head: &[u8]) -> Result<()> {
    let at = |o: u64| to_usize(o);
    let (Some(flags), Some(chse), Some(fc_min), Some(fc_mac), Some(_)) = (
        u16_le(head, 0x0a),
        u16_le(head, 0x14),
        u32_le(head, 0x18),
        u32_le(head, 0x1c),
        u16_le(head, at(FIB_END).saturating_sub(2)),
    ) else {
        cx.emit(Fib6::node(
            "File Information Block",
            wd.sub(0, Fib6::SIZE),
            LE,
        ));
        return Err(Diagnostic::truncated(
            wd.sub(0, FIB_END),
            to_u64(head.len()),
        ));
    };
    let lw_at = |i: u64| u32_le(head, at(0x34u64.saturating_add(i.saturating_mul(4)))).unwrap_or(0);
    // Word 97's FibRgLw order, so the stories are found the same way.
    let lw = vec![
        u32_le(head, 0x20).unwrap_or(0),
        0,
        0,
        lw_at(0),
        lw_at(1),
        lw_at(2),
        lw_at(3),
        lw_at(4),
        lw_at(5),
        lw_at(6),
        lw_at(7),
    ];
    let pairs = (0..PAIR_COUNT)
        .map(|i| {
            let p = at(PAIRS_AT.saturating_add(to_u64(i).saturating_mul(8)));
            (
                u32_le(head, p).unwrap_or(0),
                u32_le(head, p.saturating_add(4)).unwrap_or(0),
            )
        })
        .collect();
    let mut fib = Fib {
        nfib: u16_le(head, 2).unwrap_or(0),
        flags,
        lw,
        pairs,
        end: FIB_END,
        text_fcs: Some((fc_min, fc_mac)),
        ..Fib::default()
    };
    let located = Doc {
        wd,
        table: Some(wd),
        fib: Arc::new(fib.clone()),
    };
    let fonts = match located.table_span(pair::STTBF_FFN) {
        Some(span) => font_list(&cx.read(span).await?),
        None => Vec::new(),
    };
    let (cp, why) = codepage(chse, &fonts);
    fib.codepage = Some(cp);
    let doc = Doc {
        wd,
        table: Some(wd),
        fib: Arc::new(fib),
    };
    let fib = doc.fib.clone();
    cx.emit(
        Node::new("File Information Block")
            .span(wd.sub(0, FIB_END))
            .summary(format!(
                "nFib {:#06x} ({}), text at {fc_min:#x}–{fc_mac:#x}",
                fib.nfib,
                lookup(NFIB, fib.nfib.into()).unwrap_or("unknown version"),
            ))
            .lazy(fib_node, doc.clone()),
    );
    let main = fib.lw(3);
    cx.annotate(format!(
        "Word 6.0/95 document, {main} characters of main text"
    ));
    if flags & 0x0100 != 0 {
        cx.emit(Node::new("Encryption").diag(Diagnostic::unsupported(
            "the document is encrypted: its text is not readable",
        )));
        return Ok(());
    }
    let pieces = pieces(cx, &doc).await;
    let preview = match &pieces {
        Ok(p) => text_range(cx, &doc, p, 0, main.into(), to_u64(PREVIEW)).await,
        Err(_) => String::new(),
    };
    let mut text = Node::new("Text").summary(quoted(&preview, PREVIEW));
    text = match doc.table_span(pair::CLX) {
        Some(clx) if flags & 0x0004 != 0 => text.span(clx),
        _ => text.span(wd.sub(fc_min.into(), fc_mac.saturating_sub(fc_min).into())),
    };
    let desc = format!("Decoded as Windows-{cp}: {why}");
    let desc = if cp == 10000 {
        format!("Decoded as Mac Roman: {why}")
    } else {
        desc
    };
    match pieces {
        Ok(_) => cx.emit(text.desc(desc).lazy(text_node, doc.clone())),
        Err(e) => cx.emit(text.diag(e)),
    }
    if let Some(span) = doc.table_span(pair::STTBF_FFN) {
        let names: Vec<&str> = fonts.iter().take(4).map(|f| f.name.as_str()).collect();
        let more = if fonts.len() > 4 { ", ..." } else { "" };
        cx.emit(
            Node::new("Fonts")
                .span(span)
                .summary(format!("{} fonts: {}{more}", fonts.len(), names.join(", ")))
                .lazy(font_table, span),
        );
    }
    if let Some(span) = doc.table_span(pair::STTBF_ASSOC) {
        cx.emit(
            Node::new("Associated strings")
                .span(span)
                .summary(assoc_summary(&cx.read(span).await?, cp))
                .lazy(assoc, (span, cp)),
        );
    }
    if let Some(span) = doc.table_span(pair::DOP) {
        cx.emit(
            Node::new("Document properties")
                .span(span)
                .summary(dop_summary(&cx.read_avail(span).await?))
                .lazy(dop, span),
        );
    }
    for (name, index) in [
        ("Stylesheet", pair::STSHF),
        ("Sections", pair::PLCF_SED),
        ("Character formatting", pair::PLCF_BTE_CHPX),
        ("Paragraph formatting", pair::PLCF_BTE_PAPX),
    ] {
        if let Some(span) = doc.table_span(index) {
            cx.emit(
                Node::new(name)
                    .span(span)
                    .summary(format!("{} bytes", span.len))
                    .diag(Diagnostic::unsupported("Word 6.0/95 structure")),
            );
        }
    }
    Ok(())
}

async fn fib_node(cx: Cx, doc: Doc) -> Result<()> {
    let wd = doc.wd;
    cx.emit(Fib6::node("Header", wd.sub(0, Fib6::SIZE), LE));
    cx.emit(
        Node::new("fc/lcb pairs")
            .span(wd.sub(PAIRS_AT, TAIL_AT.saturating_sub(PAIRS_AT)))
            .summary(format!(
                "{} pairs, structures in the WordDocument stream",
                doc.fib.pairs.len()
            ))
            .lazy(fc_lcb, doc.clone()),
    );
    cx.emit(Fib6Tail::node(
        "Formatting pages",
        wd.sub(TAIL_AT, FIB_END.saturating_sub(TAIL_AT)),
        LE,
    ));
    Ok(())
}

async fn fc_lcb(cx: Cx, doc: Doc) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(doc.fib.pairs.len())));
    for (i, &(fc, lcb)) in doc.fib.pairs.iter().enumerate() {
        let span = doc
            .wd
            .sub(PAIRS_AT.saturating_add(to_u64(i).saturating_mul(8)), 8);
        let name = PAIRS.get(i).copied().unwrap_or("reserved");
        let mut node = Node::new(name).span(span).value(hex(fc, 32));
        node = if lcb == 0 {
            node.summary("absent")
        } else {
            node.summary(format!("{lcb} bytes at {fc:#x}"))
                .target(doc.wd.sub(fc.into(), lcb.into()))
        };
        let desc = pair_desc(name);
        if !desc.is_empty() {
            node = node.desc(desc);
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn font_table(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    cx.emit(
        Node::new("cbSttbfFfn")
            .span(span.sub(0, 2))
            .value(uint(u16_le(&data, 0).unwrap_or(0), 16)),
    );
    for (i, font) in font_list(&data).into_iter().enumerate() {
        if i.is_multiple_of(64) {
            cx.checkpoint().await;
        }
        let first = data.get(font.at.saturating_add(1)).copied().unwrap_or(0);
        let ffn = span.sub(to_u64(font.at), to_u64(font.len));
        cx.push(
            Node::new(format!("Font {i}"))
                .span(ffn)
                .value(Value::Text(font.name))
                .summary(format!(
                    "{}, {}{}",
                    lookup(FONT_FAMILY, bits(first.into(), 4, 3)).unwrap_or("family ?"),
                    lookup(CHARSETS, font.chs.into()).unwrap_or("charset ?"),
                    if first & 4 != 0 { ", TrueType" } else { "" }
                ))
                .lazy(ffn_node, ffn),
        )
        .await;
    }
    Ok(())
}

async fn ffn_node(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u8("cbFfnM1")
        .desc("Size of the FFN in bytes, minus 1")
        .emit()?;
    f.u8("Flags")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "pitch {}, {}{}",
                lookup(PITCH, (v & 3).into()).unwrap_or("?"),
                lookup(FONT_FAMILY, bits(v.into(), 4, 3)).unwrap_or("family ?"),
                if v & 4 != 0 { ", TrueType" } else { "" }
            ))
        })
        .desc("prq (bits 0–1), fTrueType (bit 2), ff font family (bits 4–6)")
        .emit()?;
    f.int::<i16>("wWeight").emit()?;
    f.u8("chs").enumeration(CHARSETS).emit()?;
    f.u8("ibszAlt")
        .desc("Offset of the alternative font name within szFfn, or 0")
        .emit()?;
    f.cstr("szFfn").emit()?;
    if f.remaining() > 0 {
        f.cstr("szAlt").emit()?;
    }
    Ok(())
}

/// The strings of a Word 6 Sttbf: a 16-bit total size, then Pascal
/// strings (offset, size, text).
fn sttb_entries(data: &[u8], cp: u16) -> Vec<(usize, usize, String)> {
    let end = usize::from(u16_le(data, 0).unwrap_or(0)).min(data.len());
    let mut at = 2usize;
    let mut out = Vec::new();
    while at < end {
        let Some(&n) = data.get(at) else { break };
        let n = usize::from(n);
        let raw = data
            .get(at.saturating_add(1)..at.saturating_add(1).saturating_add(n))
            .unwrap_or_default();
        out.push((at, n.saturating_add(1), rec::codepage_text(cp, raw)));
        at = at.saturating_add(1).saturating_add(n);
    }
    out
}

fn assoc_summary(data: &[u8], cp: u16) -> String {
    let entries = sttb_entries(data, cp);
    let shown: Vec<String> = entries
        .iter()
        .filter(|(_, _, t)| !t.is_empty())
        .take(3)
        .map(|(_, _, t)| quoted(t, 40))
        .collect();
    format!("{} strings: {}", entries.len(), shown.join(", "))
}

async fn assoc(cx: Cx, (span, cp): (Span, u16)) -> Result<()> {
    let data = cx.read(span).await?;
    cx.emit(
        Node::new("cbSttbf")
            .span(span.sub(0, 2))
            .value(uint(u16_le(&data, 0).unwrap_or(0), 16)),
    );
    for (i, (at, len, text)) in sttb_entries(&data, cp).into_iter().enumerate() {
        let name = ASSOC
            .get(i)
            .map_or_else(|| format!("String {i}"), |n| (*n).to_owned());
        cx.push(
            Node::new(name)
                .span(span.sub(to_u64(at), to_u64(len)))
                .value(Value::Text(text)),
        )
        .await;
    }
    Ok(())
}

const WEEKDAYS: &[&str] = &[
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];

/// A DTTM: a local date and time to the minute, with the day of the week,
/// packed into 32 bits. Word records no time zone with it.
fn dttm(v: u32) -> String {
    if v == 0 {
        return "not set".into();
    }
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02} ({}), local time",
        1900u32.saturating_add((v >> 20) & 0x1ff),
        (v >> 16) & 0xf,
        (v >> 11) & 0x1f,
        (v >> 6) & 0x1f,
        v & 0x3f,
        WEEKDAYS
            .get(to_usize(((v >> 29) & 7).into()))
            .unwrap_or(&"?")
    )
}

fn dop_summary(data: &[u8]) -> String {
    match (u32_le(data, 0x14), u16_le(data, 0x20)) {
        (Some(created), Some(revision)) => format!(
            "created {}, revision {revision}",
            dttm(created).trim_end_matches(", local time")
        ),
        _ => format!("{} bytes", data.len()),
    }
}

/// The DOP of Word 6/95: settings, then the dates and statistics that
/// Word 97's DopBase keeps at the same offsets.
async fn dop(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.bytes("Settings", 0x14)
        .desc("Footnote, page and compatibility options")
        .emit()?;
    for (name, desc) in [
        ("dttmCreated", "When the document was created"),
        ("dttmRevised", "When it was last saved"),
        ("dttmLastPrint", "When it was last printed"),
    ] {
        f.u32(name)
            .hex()
            .with(|&v, n| n.summary(dttm(v)))
            .desc(desc)
            .emit()?;
    }
    f.u16("nRevision")
        .desc("Number of times the document was saved")
        .emit()?;
    f.u32("tmEdited")
        .desc("Minutes spent editing the document")
        .emit()?;
    f.u32("cWords").desc("Words, as last counted").emit()?;
    f.u32("cCh").desc("Characters, as last counted").emit()?;
    f.u16("cPg").desc("Pages, as last counted").emit()?;
    f.u32("cParas").desc("Paragraphs, as last counted").emit()?;
    if f.remaining() > 0 {
        let rest = f.remaining();
        f.bytes("Remaining settings", rest).emit()?;
    }
    Ok(())
}
