//! Word 97–2007 binary documents ([MS-DOC]): the File Information Block at
//! the start of the `WordDocument` stream, and the structures it points to
//! in the table stream (`0Table` or `1Table`): the piece table that maps
//! character positions to text, the stylesheet, the font table, sections,
//! fields, string tables, and the character and paragraph formatting pages
//! (FKPs) in the `WordDocument` stream itself. Word 6.0/95 files are in
//! [`word6`].

use std::sync::Arc;

use super::rec::{self, K, LE, Spec, bits, enumv, hex, quoted, uint};
use super::sprm;
use crate::bytes::{i16_le, i32_le, to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::Input;
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

mod word6;

/// Characters of text shown in one value.
const MAX_TEXT: u64 = 4096;
/// Characters of text shown in a summary.
const PREVIEW: usize = 60;
/// FKP pages are 512 bytes.
const PAGE: u64 = 512;

const NFIB: EnumTable = &[
    (0x0065, "Word 6.0"),
    (0x0068, "Word 95"),
    (0x00c1, "Word 97"),
    (0x00d9, "Word 2000"),
    (0x0101, "Word 2002"),
    (0x010c, "Word 2003"),
    (0x0112, "Word 2007"),
];

const FIB_FLAGS: FlagTable = &[
    flag(0x0001, "fDot"),
    flag(0x0002, "fGlsy"),
    flag(0x0004, "fComplex"),
    flag(0x0008, "fHasPic"),
    crate::value::field(0x00f0, 0x0000, "cQuickSaves=0"),
    flag(0x0100, "fEncrypted"),
    flag(0x0200, "fWhichTblStm"),
    flag(0x0400, "fReadOnlyRecommended"),
    flag(0x0800, "fWriteReservation"),
    flag(0x1000, "fExtChar"),
    flag(0x2000, "fLoadOverride"),
    flag(0x4000, "fFarEast"),
    flag(0x8000, "fObfuscated"),
];

const FIB_FLAGS2: FlagTable = &[
    flag(0x01, "fMac"),
    flag(0x02, "fEmptySpecial"),
    flag(0x04, "fLoadOverridePage"),
    flag(0x08, "reserved1"),
    flag(0x10, "reserved2"),
];

const ENVR: EnumTable = &[(0, "Windows"), (1, "Macintosh")];

record! {
    /// FibBase: the fixed start of the File Information Block.
    pub struct FibBase {
        ident: u16 "wIdent" .hex() .desc("0xA5EC for Word 97 and later, 0xA5DC for Word 6/95"),
        nfib: u16 "nFib" .hex() .enumeration(NFIB) .desc("File format version (superseded by nFibNew when present)"),
        _unused: u16 "unused",
        lid: u16 "lid" .hex() .with(|&v, n| n.summary(crate::formats::util::lcid::describe(v.into()))) .desc("Language of the installation that created the document"),
        pn_next: u16 "pnNext" .desc("512-byte page of the AutoText FIB, if any"),
        flags: u16 "Flags" .flags(FIB_FLAGS) .with(|&v, n| n.summary(format!("cQuickSaves {}", (v >> 4) & 0xf))),
        nfib_back: u16 "nFibBack" .hex() .desc("Oldest version that can read the file (0xBF or 0xC1)"),
        key: u32 "lKey" .hex() .desc("Size of the encryption header, or the obfuscation key"),
        envr: u8 "envr" .enumeration(ENVR),
        flags2: u8 "Flags 2" .flags(FIB_FLAGS2),
        _reserved3: u16 "reserved3",
        _reserved4: u16 "reserved4",
        _reserved5: u32 "reserved5",
        _reserved6: u32 "reserved6",
    }
}

const RG_W: &[&str] = &[
    "reserved1",
    "reserved2",
    "reserved3",
    "reserved4",
    "reserved5",
    "reserved6",
    "reserved7",
    "reserved8",
    "reserved9",
    "reserved10",
    "reserved11",
    "reserved12",
    "reserved13",
    "lidFE",
];

const RG_LW: &[&str] = &[
    "cbMac",
    "reserved1",
    "reserved2",
    "ccpText",
    "ccpFtn",
    "ccpHdd",
    "reserved3",
    "ccpAtn",
    "ccpEdn",
    "ccpTxbx",
    "ccpHdrTxbx",
    "reserved4",
    "reserved5",
    "reserved6",
    "reserved7",
    "reserved8",
    "reserved9",
    "reserved10",
    "reserved11",
    "reserved12",
    "reserved13",
    "reserved14",
];

const RG_LW_DESC: &[(&str, &str)] = &[
    ("cbMac", "Bytes of the WordDocument stream in use"),
    ("ccpText", "Characters in the main document"),
    ("ccpFtn", "Characters in the footnote subdocument"),
    ("ccpHdd", "Characters in the header subdocument"),
    ("ccpAtn", "Characters in the comment subdocument"),
    ("ccpEdn", "Characters in the endnote subdocument"),
    ("ccpTxbx", "Characters in the textbox subdocument"),
    ("ccpHdrTxbx", "Characters in the header textbox subdocument"),
];

/// Names of the fc/lcb pairs of FibRgFcLcb97, 2000, 2002, 2003 and 2007, in
/// order (without the `fc`/`lcb` prefix). Index 87 is a FILETIME.
const PAIRS: &[&str] = &[
    // FibRgFcLcb97
    "StshfOrig",
    "Stshf",
    "PlcffndRef",
    "PlcffndTxt",
    "PlcfandRef",
    "PlcfandTxt",
    "PlcfSed",
    "PlcPad",
    "PlcfPhe",
    "SttbfGlsy",
    "PlcfGlsy",
    "PlcfHdd",
    "PlcfBteChpx",
    "PlcfBtePapx",
    "PlcfSea",
    "SttbfFfn",
    "PlcfFldMom",
    "PlcfFldHdr",
    "PlcfFldFtn",
    "PlcfFldAtn",
    "PlcfFldMcr",
    "SttbfBkmk",
    "PlcfBkf",
    "PlcfBkl",
    "Cmds",
    "Unused1",
    "SttbfMcr",
    "PrDrvr",
    "PrEnvPort",
    "PrEnvLand",
    "Wss",
    "Dop",
    "SttbfAssoc",
    "Clx",
    "PlcfPgdFtn",
    "AutosaveSource",
    "GrpXstAtnOwners",
    "SttbfAtnBkmk",
    "Unused2",
    "Unused3",
    "PlcSpaMom",
    "PlcSpaHdr",
    "PlcfAtnBkf",
    "PlcfAtnBkl",
    "Pms",
    "FormFldSttbs",
    "PlcfendRef",
    "PlcfendTxt",
    "PlcfFldEdn",
    "Unused4",
    "DggInfo",
    "SttbfRMark",
    "SttbfCaption",
    "SttbfAutoCaption",
    "PlcfWkb",
    "PlcfSpl",
    "PlcftxbxTxt",
    "PlcfFldTxbx",
    "PlcfHdrtxbxTxt",
    "PlcffldHdrTxbx",
    "StwUser",
    "SttbTtmbd",
    "CookieData",
    "PgdMotherOldOld",
    "BkdMotherOldOld",
    "PgdFtnOldOld",
    "BkdFtnOldOld",
    "PgdEdnOldOld",
    "BkdEdnOldOld",
    "SttbfIntlFld",
    "RouteSlip",
    "SttbSavedBy",
    "SttbFnm",
    "PlfLst",
    "PlfLfo",
    "PlcfTxbxBkd",
    "PlcfTxbxHdrBkd",
    "DocUndoWord9",
    "RgbUse",
    "Usp",
    "Uskf",
    "PlcupcRgbUse",
    "PlcupcUsp",
    "SttbGlsyStyle",
    "Plgosl",
    "Plcocx",
    "PlcfBteLvc",
    "ftModified",
    "PlcfLvcPre10",
    "PlcfAsumy",
    "PlcfGram",
    "SttbListNames",
    "SttbfUssr",
    // FibRgFcLcb2000
    "PlcfTch",
    "RmdThreading",
    "Mid",
    "SttbRgtplc",
    "MsoEnvelope",
    "PlcfLad",
    "RgDofr",
    "Plcosl",
    "PlcfCookieOld",
    "PgdMotherOld",
    "BkdMotherOld",
    "PgdFtnOld",
    "BkdFtnOld",
    "PgdEdnOld",
    "BkdEdnOld",
    // FibRgFcLcb2002
    "Unused1 (2002)",
    "PlcfPgp",
    "Plcfuim",
    "PlfguidUim",
    "AtrdExtra",
    "Plrsid",
    "SttbfBkmkFactoid",
    "PlcfBkfFactoid",
    "Plcfcookie",
    "PlcfBklFactoid",
    "FactoidData",
    "DocUndo",
    "SttbfBkmkFcc",
    "PlcfBkfFcc",
    "PlcfBklFcc",
    "SttbfbkmkBPRepairs",
    "PlcfbkfBPRepairs",
    "PlcfbklBPRepairs",
    "PmsNew",
    "ODSO",
    "PlcfpmiOldXP",
    "PlcfpmiNewXP",
    "PlcfpmiMixedXP",
    "Unused2 (2002)",
    "Plcffactoid",
    "PlcflvcOldXP",
    "PlcflvcNewXP",
    "PlcflvcMixedXP",
    // FibRgFcLcb2003
    "Hplxsdr",
    "SttbfBkmkSdt",
    "PlcfBkfSdt",
    "PlcfBklSdt",
    "CustomXForm",
    "SttbfBkmkProt",
    "PlcfBkfProt",
    "PlcfBklProt",
    "SttbProtUser",
    "Unused (2003)",
    "PlcfpmiOld",
    "PlcfpmiOldInline",
    "PlcfpmiNew",
    "PlcfpmiNewInline",
    "PlcflvcOld",
    "PlcflvcOldInline",
    "PlcflvcNew",
    "PlcflvcNewInline",
    "PgdMother",
    "BkdMother",
    "AfdMother",
    "PgdFtn",
    "BkdFtn",
    "AfdFtn",
    "PgdEdn",
    "BkdEdn",
    "AfdEdn",
    "Afd",
    // FibRgFcLcb2007
    "Plcfmthd",
    "SttbfBkmkMoveFrom",
    "PlcfBkfMoveFrom",
    "PlcfBklMoveFrom",
    "SttbfBkmkMoveTo",
    "PlcfBkfMoveTo",
    "PlcfBklMoveTo",
    "Unused1 (2007)",
    "Unused2 (2007)",
    "Unused3 (2007)",
    "SttbfBkmkArto",
    "PlcfBkfArto",
    "PlcfBklArto",
    "ArtoData",
    "Unused4 (2007)",
    "Unused5 (2007)",
    "Unused6 (2007)",
    "OssTheme",
    "ColorSchemeMapping",
];

/// Pair indices of the structures decoded below.
mod pair {
    pub const STSHF: usize = 1;
    pub const PLCF_SED: usize = 6;
    pub const PLCF_BTE_CHPX: usize = 12;
    pub const PLCF_BTE_PAPX: usize = 13;
    pub const STTBF_FFN: usize = 15;
    pub const PLCF_FLD_MOM: usize = 16;
    pub const PLCF_FLD_HDR: usize = 17;
    pub const PLCF_FLD_FTN: usize = 18;
    pub const PLCF_FLD_ATN: usize = 19;
    pub const STTBF_BKMK: usize = 21;
    pub const DOP: usize = 31;
    pub const STTBF_ASSOC: usize = 32;
    pub const CLX: usize = 33;
    pub const PLCF_FLD_EDN: usize = 48;
    pub const DGG_INFO: usize = 50;
    pub const STTBF_RMARK: usize = 51;
    pub const PLCF_FLD_TXBX: usize = 57;
    pub const PLCF_FLD_HDR_TXBX: usize = 59;
    pub const STTB_SAVED_BY: usize = 71;
    pub const STTB_FNM: usize = 72;
    pub const FT_MODIFIED: usize = 87;
    pub const STTB_LIST_NAMES: usize = 91;
}

/// What a pair is, for its description.
fn pair_desc(name: &str) -> &'static str {
    match name {
        "Stshf" => "Stylesheet",
        "StshfOrig" => "Original stylesheet (unused; equals Stshf)",
        "Clx" => "Piece table: where each run of text is stored",
        "SttbfFfn" => "Font table",
        "PlcfSed" => "Section descriptors",
        "PlcfBteChpx" => "Character formatting pages (bin table)",
        "PlcfBtePapx" => "Paragraph formatting pages (bin table)",
        "Dop" => "Document properties",
        "PlcfFldMom" => "Fields of the main document",
        "SttbfAssoc" => "Associated strings (template, title, author, ...)",
        "SttbSavedBy" => "Authors and paths of the last saves",
        "SttbfBkmk" => "Bookmark names",
        "PlcfBkf" | "PlcfBkl" => "Bookmark positions",
        "PlfLst" => "List definitions",
        "PlfLfo" => "List format overrides",
        "DggInfo" => "Office Art drawing data",
        "PlcffndRef" | "PlcffndTxt" => "Footnote references and text",
        "PlcfendRef" | "PlcfendTxt" => "Endnote references and text",
        "PlcfandRef" | "PlcfandTxt" => "Comment references and text",
        "PlcfHdd" => "Header and footer stories",
        "PlcfSpl" | "PlcfGram" => "Proofing state",
        "Plcfuim" | "PlfguidUim" => "Unique identifiers of inline elements",
        "Plrsid" => "Revision save IDs",
        "SttbListNames" => "List names",
        _ => "",
    }
}

// ---------------------------------------------------------------------------
// The FIB

/// The parts of the FIB the rest of the document is located by.
#[derive(Clone, Debug, Default)]
pub struct Fib {
    pub nfib: u16,
    pub flags: u16,
    pub lw: Vec<u32>,
    pub pairs: Vec<(u32, u32)>,
    /// Offsets of the variable parts, relative to the stream.
    rg_w: (u64, u64),
    rg_lw: (u64, u64),
    rg_fc_lcb: (u64, u64),
    rg_csw_new: (u64, u64),
    pub nfib_new: Option<u16>,
    pub end: u64,
    /// Word 6.0/95: the code page of the 8-bit text.
    pub codepage: Option<u16>,
    /// Word 6.0/95: where the text is when there is no piece table
    /// (fcMin, fcMac).
    pub text_fcs: Option<(u32, u32)>,
}

impl Fib {
    fn pair(&self, index: usize) -> Option<(u32, u32)> {
        if index == pair::FT_MODIFIED {
            return None;
        }
        self.pairs.get(index).copied().filter(|&(_, lcb)| lcb > 0)
    }

    pub fn version(&self) -> u16 {
        self.nfib_new.unwrap_or(self.nfib)
    }

    fn lw(&self, i: usize) -> u32 {
        self.lw.get(i).copied().unwrap_or(0)
    }

    pub fn table_name(&self) -> &'static str {
        if self.flags & 0x0200 != 0 {
            "1Table"
        } else {
            "0Table"
        }
    }

    pub fn encrypted(&self) -> bool {
        self.flags & 0x0100 != 0
    }
}

fn parse_fib(data: &[u8]) -> Option<Fib> {
    let mut fib = Fib {
        nfib: u16_le(data, 2)?,
        flags: u16_le(data, 10)?,
        ..Fib::default()
    };
    let mut at = 32usize;
    let csw = usize::from(u16_le(data, at)?);
    fib.rg_w = (to_u64(at), to_u64(csw.saturating_mul(2).saturating_add(2)));
    at = at.checked_add(2)?.checked_add(csw.checked_mul(2)?)?;
    let cslw = usize::from(u16_le(data, at)?);
    fib.rg_lw = (to_u64(at), to_u64(cslw.saturating_mul(4).saturating_add(2)));
    fib.lw = (0..cslw)
        .map_while(|i| {
            u32_le(
                data,
                at.saturating_add(2).saturating_add(i.saturating_mul(4)),
            )
        })
        .collect();
    at = at.checked_add(2)?.checked_add(cslw.checked_mul(4)?)?;
    let pairs = usize::from(u16_le(data, at)?);
    fib.rg_fc_lcb = (
        to_u64(at),
        to_u64(pairs.saturating_mul(8).saturating_add(2)),
    );
    fib.pairs = (0..pairs)
        .map_while(|i| {
            let p = at.saturating_add(2).saturating_add(i.saturating_mul(8));
            Some((u32_le(data, p)?, u32_le(data, p.saturating_add(4))?))
        })
        .collect();
    at = at.checked_add(2)?.checked_add(pairs.checked_mul(8)?)?;
    match u16_le(data, at) {
        Some(csw_new) => {
            let n = usize::from(csw_new);
            fib.rg_csw_new = (to_u64(at), to_u64(n.saturating_mul(2).saturating_add(2)));
            if n > 0 {
                fib.nfib_new = u16_le(data, at.saturating_add(2));
            }
            fib.end = to_u64(at.saturating_add(2).saturating_add(n.saturating_mul(2)));
        }
        None => fib.end = to_u64(at),
    }
    Some(fib)
}

/// The locations a Word document is decoded from.
#[derive(Clone)]
pub struct Doc {
    pub wd: Span,
    pub table: Option<Span>,
    pub fib: Arc<Fib>,
}

impl Doc {
    /// The table-stream span of pair `index`, if present.
    fn table_span(&self, index: usize) -> Option<Span> {
        let (fc, lcb) = self.fib.pair(index)?;
        Some(self.table?.sub(fc.into(), lcb.into()))
    }
}

/// The WordDocument stream, with the `0Table` and `1Table` streams if they
/// exist (the FIB says which one is in use).
pub async fn word(cx: &Cx, input: Input, wd: Span, tables: [Option<Span>; 2]) -> Result<()> {
    let base_span = wd.sub(0, FibBase::SIZE);
    let head = cx.read_avail(wd.sub(0, 4096)).await?;
    let base = crate::fields::parse(cx, base_span, LE, &(), FibBase::layout).await?;
    if base.ident == 0xa5dc {
        return word6::word6(cx, wd, &head).await;
    }
    if base.ident != 0xa5ec {
        cx.emit(
            FibBase::node("FibBase", base_span, LE).diag(Diagnostic::malformed(format!(
                "wIdent is {:#06x}, not 0xA5EC",
                base.ident
            ))),
        );
        return Ok(());
    }
    let Some(fib) = parse_fib(&head) else {
        cx.emit(FibBase::node("FibBase", base_span, LE));
        return Err(Diagnostic::truncated(wd.sub(0, 154), to_u64(head.len())));
    };
    let fib = Arc::new(fib);
    let version = fib.version();
    let table_name = fib.table_name();
    let [table0, table1] = tables;
    let table = if fib.flags & 0x0200 != 0 {
        table1
    } else {
        table0
    };
    let doc = Doc {
        wd,
        table,
        fib: fib.clone(),
    };
    cx.emit(
        Node::new("File Information Block")
            .span(wd.sub(0, fib.end))
            .summary(format!(
                "nFib {version:#06x} ({}), {} fc/lcb pairs, table stream {table_name}",
                lookup(NFIB, version.into()).unwrap_or("unknown version"),
                fib.pairs.len()
            ))
            .lazy(fib_node, doc.clone()),
    );
    let main = fib.lw(3);
    cx.annotate(format!("Word document, {main} characters of main text"));
    if fib.encrypted() {
        cx.emit(Node::new("Encryption").diag(Diagnostic::unsupported(
            "the document is encrypted: the table stream and text are not readable",
        )));
        return Ok(());
    }
    if table.is_none() {
        cx.diag(Diagnostic::malformed(format!(
            "the table stream {table_name} named by the FIB is missing"
        )));
        return Ok(());
    }
    let pieces = pieces(cx, &doc).await;
    let preview = match &pieces {
        Ok(p) => text_range(cx, &doc, p, 0, main.into(), to_u64(PREVIEW)).await,
        Err(_) => String::new(),
    };
    let mut text = Node::new("Text").summary(quoted(&preview, PREVIEW));
    if let Some(span) = doc.table_span(pair::CLX) {
        text = text.span(span);
    }
    match pieces {
        Ok(_) => cx.emit(
            text.desc("The piece table (CLX) and the document's stories")
                .lazy(text_node, doc.clone()),
        ),
        Err(e) => cx.emit(text.diag(e)),
    }
    for (name, index) in [
        ("Stylesheet", pair::STSHF),
        ("Fonts", pair::STTBF_FFN),
        ("Sections", pair::PLCF_SED),
        ("Fields", pair::PLCF_FLD_MOM),
        ("Character formatting", pair::PLCF_BTE_CHPX),
        ("Paragraph formatting", pair::PLCF_BTE_PAPX),
        ("Document properties", pair::DOP),
    ] {
        let Some(span) = doc.table_span(index) else {
            continue;
        };
        let summary = match index {
            pair::STSHF => style_count(cx, span).await,
            pair::STTBF_FFN => font_summary(cx, span).await,
            pair::PLCF_SED => format!("{} sections", plc_count(span.len, 12)),
            pair::PLCF_FLD_MOM => format!("{} field characters", plc_count(span.len, 2)),
            pair::PLCF_BTE_CHPX | pair::PLCF_BTE_PAPX => {
                format!("{} formatting pages", plc_count(span.len, 4))
            }
            _ => format!("{} bytes", span.len),
        };
        let node = Node::new(name).span(span).summary(summary);
        let state = doc.clone();
        cx.emit(match index {
            pair::STSHF => node.lazy(stylesheet, state),
            pair::STTBF_FFN => node.lazy(fonts, state),
            pair::PLCF_SED => node.lazy(sections, state),
            pair::PLCF_FLD_MOM => node.lazy(fields, state),
            pair::PLCF_BTE_CHPX => node.lazy(chpx_bins, state),
            pair::PLCF_BTE_PAPX => node.lazy(papx_bins, state),
            _ => node.lazy(dop, state),
        });
    }
    for (name, index) in [
        ("Associated strings", pair::STTBF_ASSOC),
        ("Saved by", pair::STTB_SAVED_BY),
        ("Bookmarks", pair::STTBF_BKMK),
        ("Revision authors", pair::STTBF_RMARK),
        ("List names", pair::STTB_LIST_NAMES),
        ("File names", pair::STTB_FNM),
    ] {
        if let Some(span) = doc.table_span(index) {
            let (summary, _) = sttb_summary(cx, span).await;
            cx.emit(
                Node::new(name)
                    .span(span)
                    .summary(summary)
                    .lazy(sttb_node, (span, index)),
            );
        }
    }
    if let Some(span) = doc.table_span(pair::DGG_INFO) {
        cx.emit(
            Node::new("Drawings")
                .span(span)
                .summary(format!("Office Art, {} bytes", span.len))
                .lazy(super::officeart::records_at, (input, span)),
        );
    }
    cx.emit(
        Node::new("Other structures")
            .summary("table-stream structures located by the FIB")
            .lazy(other_structures, doc.clone()),
    );
    cx.emit(
        Node::new("Unreferenced space")
            .desc("Bytes of the WordDocument and table streams that nothing in the FIB, the piece table, the formatting pages or the section table points to: slack and padding")
            .lazy(unreferenced, doc),
    );
    Ok(())
}

/// Ranges of `len` bytes not covered by `used` (which is sorted here).
fn gaps(mut used: Vec<(u64, u64)>, len: u64) -> Vec<(u64, u64)> {
    used.sort_unstable();
    let mut out = Vec::new();
    let mut at = 0u64;
    for (start, end) in used {
        if start > at {
            out.push((at, start.min(len)));
        }
        at = at.max(end);
        if at >= len {
            break;
        }
    }
    if at < len {
        out.push((at, len));
    }
    out.retain(|(a, b)| b > a);
    out
}

async fn unreferenced(cx: Cx, doc: Doc) -> Result<()> {
    // The WordDocument stream: FIB, text, FKP pages, SEPXs.
    let mut used = vec![(0u64, doc.fib.end)];
    if let Ok(p) = pieces(&cx, &doc).await {
        for piece in &p.list {
            used.push(piece.fc_range());
        }
    }
    for index in [pair::PLCF_BTE_CHPX, pair::PLCF_BTE_PAPX] {
        if let Some(span) = doc.table_span(index) {
            let data = cx.read(span).await?;
            let n = plc_count(span.len, 4);
            for i in 0..n {
                let at = n.saturating_add(1).saturating_add(i).saturating_mul(4);
                let pn = u64::from(u32_le(&data, to_usize(at)).unwrap_or(0) & 0x003f_ffff);
                let start = pn.saturating_mul(PAGE);
                used.push((start, start.saturating_add(PAGE)));
            }
        }
    }
    if let Some(span) = doc.table_span(pair::PLCF_SED) {
        let data = cx.read(span).await?;
        let n = plc_count(span.len, 12);
        let base = n.saturating_add(1).saturating_mul(4);
        for i in 0..n {
            let at = base.saturating_add(i.saturating_mul(12)).saturating_add(2);
            if let Some(fc) = i32_le(&data, to_usize(at)).filter(|&v| v >= 0) {
                let fc = u64::from(fc.unsigned_abs());
                let len = cx
                    .read_avail(doc.wd.sub(fc, 2))
                    .await
                    .ok()
                    .and_then(|b| i16_le(&b, 0))
                    .map_or(0, |v| u64::from(v.unsigned_abs()));
                used.push((fc, fc.saturating_add(len).saturating_add(2)));
            }
        }
    }
    let cb_mac = u64::from(doc.fib.lw(0));
    for (a, b) in gaps(used, doc.wd.len) {
        let what = if cb_mac > 0 && a >= cb_mac {
            "after cbMac"
        } else {
            "unreferenced"
        };
        cx.push(gap_node(&cx, "WordDocument", doc.wd, a, b, what).await)
            .await;
    }
    // The table stream: everything the FIB points to.
    if let Some(table) = doc.table {
        let mut used = Vec::new();
        for i in 0..doc.fib.pairs.len() {
            if let Some((fc, lcb)) = doc.fib.pair(i) {
                used.push((u64::from(fc), u64::from(fc).saturating_add(lcb.into())));
            }
        }
        for (a, b) in gaps(used, table.len) {
            cx.push(gap_node(&cx, doc.fib.table_name(), table, a, b, "unreferenced").await)
                .await;
        }
    }
    Ok(())
}

async fn gap_node(cx: &Cx, stream: &str, span: Span, a: u64, b: u64, what: &str) -> Node {
    let gap = span.sub(a, b.saturating_sub(a));
    let data = cx.read_avail(gap.sub(0, 4096)).await.unwrap_or_default();
    let zero = data.iter().all(|&x| x == 0);
    Node::new(format!("{stream} {a:#x}–{b:#x}"))
        .span(gap)
        .summary(format!(
            "{} bytes, {what}{}",
            gap.len,
            if zero { ", zeros" } else { "" }
        ))
}

fn plc_count(len: u64, data: u64) -> u64 {
    len.saturating_sub(4)
        .checked_div(data.saturating_add(4))
        .unwrap_or(0)
}

async fn fib_node(cx: Cx, doc: Doc) -> Result<()> {
    let fib = &doc.fib;
    let wd = doc.wd;
    cx.emit(FibBase::node("FibBase", wd.sub(0, FibBase::SIZE), LE));
    let (at, len) = fib.rg_w;
    cx.emit(
        struct_node("fibRgW", wd.sub(at, len), LE, (), rg_w)
            .summary(format!("{} 16-bit values", len.saturating_sub(2) / 2)),
    );
    let (at, len) = fib.rg_lw;
    cx.emit(
        struct_node("fibRgLw", wd.sub(at, len), LE, (), rg_lw).summary(format!(
            "{} characters of main text, {} bytes in use",
            fib.lw(3),
            fib.lw(0)
        )),
    );
    let (at, len) = fib.rg_fc_lcb;
    cx.emit(
        Node::new("fibRgFcLcb")
            .span(wd.sub(at, len))
            .summary(format!(
                "{} pairs ({})",
                fib.pairs.len(),
                match fib.pairs.len() {
                    93 => "FibRgFcLcb97",
                    108 => "FibRgFcLcb2000",
                    136 => "FibRgFcLcb2002",
                    164 => "FibRgFcLcb2003",
                    183 => "FibRgFcLcb2007",
                    _ => "nonstandard size",
                }
            ))
            .desc("Offsets and sizes of the structures in the table stream")
            .lazy(fc_lcb, doc.clone()),
    );
    let (at, len) = fib.rg_csw_new;
    if len > 0 {
        cx.emit(struct_node(
            "fibRgCswNew",
            wd.sub(at, len),
            LE,
            (),
            rg_csw_new,
        ));
    }
    Ok(())
}

fn rg_w(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let csw = f.u16("csw").emit()?;
    for i in 0..usize::from(csw) {
        match RG_W.get(i) {
            Some(&"lidFE") => {
                f.u16("lidFE")
                    .hex()
                    .with(|&v, n| n.summary(crate::formats::util::lcid::describe(v.into())))
                    .emit()?;
            }
            Some(name) => {
                f.u16(name).emit()?;
            }
            None => {
                f.u16("extra").emit()?;
            }
        }
    }
    Ok(())
}

fn rg_lw(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let cslw = f.u16("cslw").emit()?;
    for i in 0..usize::from(cslw) {
        let name = RG_LW.get(i).copied().unwrap_or("extra");
        let desc = RG_LW_DESC
            .iter()
            .find(|(n, _)| *n == name)
            .map_or("", |(_, d)| *d);
        let field = f.u32(name);
        if desc.is_empty() {
            field.emit()?;
        } else {
            field.desc(desc).emit()?;
        }
    }
    Ok(())
}

fn rg_csw_new(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let n = f.u16("cswNew").emit()?;
    if n == 0 {
        return Ok(());
    }
    f.u16("nFibNew").hex().enumeration(NFIB).emit()?;
    if n >= 2 {
        f.u16("cQuickSavesNew").emit()?;
    }
    if n >= 5 {
        f.u16("lidThemeOther").hex().emit()?;
        f.u16("lidThemeFE").hex().emit()?;
        f.u16("lidThemeCS").hex().emit()?;
    }
    for _ in 5..n {
        f.u16("extra").emit()?;
    }
    Ok(())
}

async fn fc_lcb(cx: Cx, doc: Doc) -> Result<()> {
    let fib = &doc.fib;
    let (at, _) = fib.rg_fc_lcb;
    let wd = doc.wd;
    cx.emit(
        Node::new("cbRgFcLcb")
            .span(wd.sub(at, 2))
            .value(uint(to_u64(fib.pairs.len()), 16)),
    );
    cx.set_count(Count::Exact(to_u64(fib.pairs.len()).saturating_add(1)));
    for (i, &(fc, lcb)) in fib.pairs.iter().enumerate() {
        let span = wd.sub(
            at.saturating_add(2)
                .saturating_add(to_u64(i).saturating_mul(8)),
            8,
        );
        let name = PAIRS.get(i).copied().unwrap_or("reserved");
        if i == pair::FT_MODIFIED {
            let t = u64::from(fc) | (u64::from(lcb) << 32);
            let node = Node::new("ftModified").span(span);
            cx.push(if t == 0 {
                node.value(uint(0u64, 64)).summary("not set")
            } else {
                node.value(Value::Timestamp {
                    unix_seconds: crate::text::filetime_to_unix(t),
                })
            })
            .await;
            continue;
        }
        let mut node = Node::new(name).span(span).value(hex(fc, 32));
        node = if lcb == 0 {
            node.summary("absent")
        } else {
            node.summary(format!("{lcb} bytes at {fc:#x}"))
        };
        if lcb > 0
            && let Some(table) = doc.table
        {
            node = node.target(table.sub(fc.into(), lcb.into()));
        }
        let desc = pair_desc(name);
        if !desc.is_empty() {
            node = node.desc(desc);
        }
        cx.push(node).await;
    }
    Ok(())
}

/// Opaque nodes for every structure the FIB locates and nothing above
/// decodes, so that the table stream is accounted for.
async fn other_structures(cx: Cx, doc: Doc) -> Result<()> {
    const DECODED: &[usize] = &[
        pair::STSHF,
        pair::STTBF_FFN,
        pair::PLCF_SED,
        pair::PLCF_FLD_MOM,
        pair::PLCF_BTE_CHPX,
        pair::PLCF_BTE_PAPX,
        pair::DOP,
        pair::STTBF_ASSOC,
        pair::STTB_SAVED_BY,
        pair::STTBF_BKMK,
        pair::STTBF_RMARK,
        pair::STTB_LIST_NAMES,
        pair::STTB_FNM,
        pair::DGG_INFO,
        pair::CLX,
    ];
    for i in 0..doc.fib.pairs.len() {
        if DECODED.contains(&i) || i == 0 {
            continue;
        }
        let Some(span) = doc.table_span(i) else {
            continue;
        };
        let name = PAIRS.get(i).copied().unwrap_or("reserved");
        let mut node = Node::new(name).span(span);
        let desc = pair_desc(name);
        node = node.summary(if desc.is_empty() {
            format!("{} bytes", span.len)
        } else {
            format!("{desc}, {} bytes", span.len)
        });
        if matches!(
            i,
            pair::PLCF_FLD_HDR
                | pair::PLCF_FLD_FTN
                | pair::PLCF_FLD_ATN
                | pair::PLCF_FLD_EDN
                | pair::PLCF_FLD_TXBX
                | pair::PLCF_FLD_HDR_TXBX
        ) {
            node = node.lazy(fields_of, (doc.clone(), i));
        } else if name.starts_with("Sttb") {
            node = node.lazy(sttb_node, (span, i));
        } else if name.starts_with("Plc") {
            node = node.lazy(plc_node, span);
        }
        cx.push(node).await;
    }
    Ok(())
}

/// A PLC whose data elements we do not decode: its character positions.
async fn plc_node(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    // Without the element size the count is unknown; show the CPs that are
    // certainly CPs (the first and the last).
    if let Some(first) = u32_le(&data, 0) {
        cx.emit(
            Node::new("First CP")
                .span(span.sub(0, 4))
                .value(uint(first, 32)),
        );
    }
    cx.emit(
        Node::new("Elements")
            .span(span.tail(4))
            .summary(format!("{} bytes", span.len.saturating_sub(4))),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The piece table and text

/// How a piece stores its characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PieceText {
    /// UTF-16LE at `fc`.
    Utf16,
    /// Windows-1252 at `fc / 2` (fCompressed).
    Compressed,
    /// Word 6.0/95: 8-bit at `fc`, in this code page.
    Legacy(u16),
}

#[derive(Clone, Copy, Debug)]
pub struct Piece {
    pub cp: u32,
    pub cp_end: u32,
    pub fc: u32,
    pub text: PieceText,
}

impl Piece {
    /// Bytes per character.
    fn width(&self) -> u64 {
        match self.text {
            PieceText::Utf16 => 2,
            PieceText::Compressed | PieceText::Legacy(_) => 1,
        }
    }

    /// Where the piece's first character is in the WordDocument stream.
    fn start(&self) -> u64 {
        match self.text {
            PieceText::Compressed => u64::from(self.fc / 2),
            PieceText::Utf16 | PieceText::Legacy(_) => u64::from(self.fc),
        }
    }

    /// The bytes of characters `from..to` (absolute CPs within the piece).
    fn bytes(&self, wd: Span, from: u32, to: u32) -> Span {
        let skip = u64::from(from.saturating_sub(self.cp));
        let n = u64::from(to.saturating_sub(from));
        wd.sub(
            self.start().saturating_add(skip.saturating_mul(self.width())),
            n.saturating_mul(self.width()),
        )
    }

    /// The byte range this piece occupies in the WordDocument stream.
    fn fc_range(&self) -> (u64, u64) {
        let n = u64::from(self.cp_end.saturating_sub(self.cp));
        let start = self.start();
        (start, start.saturating_add(n.saturating_mul(self.width())))
    }
}

pub struct Pieces {
    pub list: Vec<Piece>,
    /// Offset of the PlcPcd within the CLX, and the number of Prc bytes.
    plc_at: u64,
    prc_len: u64,
}

async fn pieces(cx: &Cx, doc: &Doc) -> Result<Arc<Pieces>> {
    // A Word 6/95 document that was not fast-saved has no piece table: its
    // text is one run of bytes.
    if let (Some(codepage), Some((fc_min, fc_mac))) = (doc.fib.codepage, doc.fib.text_fcs)
        && doc.fib.flags & 0x0004 == 0
    {
        return Ok(Arc::new(Pieces {
            list: vec![Piece {
                cp: 0,
                cp_end: fc_mac.saturating_sub(fc_min),
                fc: fc_min,
                text: PieceText::Legacy(codepage),
            }],
            plc_at: 0,
            prc_len: 0,
        }));
    }
    let Some(clx) = doc.table_span(pair::CLX) else {
        return Err(Diagnostic::malformed("the FIB locates no piece table"));
    };
    if let Some(found) = cx.cached::<Pieces>(clx, "word-pieces") {
        return Ok(found);
    }
    let data = cx.read(clx).await?;
    let mut at = 0usize;
    // Prc: property modifiers referenced by pieces.
    while data.get(at) == Some(&1) {
        cx.checkpoint().await;
        let n = usize::from(
            i16_le(&data, at.saturating_add(1))
                .unwrap_or(0)
                .unsigned_abs(),
        );
        at = at.saturating_add(3).saturating_add(n);
    }
    if data.get(at) != Some(&2) {
        return Err(Diagnostic::malformed("the CLX has no Pcdt").at(clx.sub(to_u64(at), 1)));
    }
    let lcb = u64::from(u32_le(&data, at.saturating_add(1)).unwrap_or(0));
    let plc_at = to_u64(at.saturating_add(5));
    let n = to_usize(lcb.saturating_sub(4) / 12);
    let cp_at = |i: usize| u32_le(&data, to_usize(plc_at).saturating_add(i.saturating_mul(4)));
    let pcd_base = to_usize(plc_at).saturating_add(n.saturating_add(1).saturating_mul(4));
    let mut list = Vec::new();
    for i in 0..n {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let pcd = pcd_base.saturating_add(i.saturating_mul(8));
        let (Some(cp), Some(cp_end), Some(fc), Some(_prm)) = (
            cp_at(i),
            cp_at(i.saturating_add(1)),
            u32_le(&data, pcd.saturating_add(2)),
            u16_le(&data, pcd.saturating_add(6)),
        ) else {
            break;
        };
        list.push(match doc.fib.codepage {
            Some(codepage) => Piece {
                cp,
                cp_end,
                fc,
                text: PieceText::Legacy(codepage),
            },
            None => Piece {
                cp,
                cp_end,
                fc: fc & 0x3fff_ffff,
                text: if fc & 0x4000_0000 != 0 {
                    PieceText::Compressed
                } else {
                    PieceText::Utf16
                },
            },
        });
    }
    let pieces = Arc::new(Pieces {
        list,
        plc_at,
        prc_len: to_u64(at),
    });
    cx.cache(clx, "word-pieces", pieces.clone());
    Ok(pieces)
}

fn decode_text(piece: &Piece, data: &[u8]) -> String {
    match piece.text {
        PieceText::Utf16 => crate::text::utf16(data, LE),
        PieceText::Compressed => rec::codepage_text(1252, data),
        PieceText::Legacy(codepage) => rec::codepage_text(codepage, data),
    }
}

/// The text of characters `from..to`, at most `max` characters.
async fn text_range(cx: &Cx, doc: &Doc, pieces: &Pieces, from: u64, to: u64, max: u64) -> String {
    let mut out = String::new();
    let to = to.min(from.saturating_add(max));
    let start = pieces.list.partition_point(|p| u64::from(p.cp_end) <= from);
    for p in pieces.list.iter().skip(start) {
        let (a, b) = (u64::from(p.cp).max(from), u64::from(p.cp_end).min(to));
        if a >= to {
            break;
        }
        if a >= b {
            continue;
        }
        let span = p.bytes(
            doc.wd,
            u32::try_from(a).unwrap_or(u32::MAX),
            u32::try_from(b).unwrap_or(u32::MAX),
        );
        let Ok(data) = cx.read_avail(span).await else {
            break;
        };
        out.push_str(&decode_text(p, &data));
    }
    out
}

/// The text of the bytes `from..to` of the WordDocument stream, through the
/// piece table, at most `max` characters.
async fn fc_text(cx: &Cx, doc: &Doc, pieces: &Pieces, from: u64, to: u64, max: u64) -> String {
    let mut out = String::new();
    let mut left = max;
    for p in &pieces.list {
        let (start, end) = p.fc_range();
        let (a, b) = (start.max(from), end.min(to));
        if a >= b || left == 0 {
            continue;
        }
        let width = p.width();
        let chars = b
            .saturating_sub(a)
            .checked_div(width)
            .unwrap_or(0)
            .min(left);
        let span = doc.wd.sub(a, chars.saturating_mul(width));
        let Ok(data) = cx.read_avail(span).await else {
            break;
        };
        out.push_str(&decode_text(p, &data));
        left = left.saturating_sub(chars);
    }
    out
}

const STORIES: &[(usize, &str)] = &[
    (3, "Main document"),
    (4, "Footnotes"),
    (5, "Headers and footers"),
    (6, "Macros"),
    (7, "Comments"),
    (8, "Endnotes"),
    (9, "Text boxes"),
    (10, "Header text boxes"),
];

/// Start CP of each story.
fn story_starts(fib: &Fib) -> Vec<(usize, &'static str, u64, u64)> {
    let mut at = 0u64;
    let mut out = Vec::new();
    for &(i, name) in STORIES {
        let n = u64::from(fib.lw(i));
        out.push((i, name, at, n));
        at = at.saturating_add(n);
    }
    out
}

async fn text_node(cx: Cx, doc: Doc) -> Result<()> {
    let pieces = pieces(&cx, &doc).await?;
    for (_, name, start, n) in story_starts(&doc.fib) {
        if n == 0 {
            continue;
        }
        let text = text_range(&cx, &doc, &pieces, start, start.saturating_add(n), MAX_TEXT).await;
        let mut node = Node::new(name).value(Value::Text(text));
        node = node.summary(format!("{n} characters from CP {start}"));
        if n > MAX_TEXT {
            node = node.desc("The value shows the first 4096 characters");
        }
        cx.emit(node);
    }
    let Some(clx) = doc.table_span(pair::CLX) else {
        return Ok(());
    };
    if pieces.prc_len > 0 {
        cx.emit(
            Node::new("Property modifiers (Prc)")
                .span(clx.sub(0, pieces.prc_len))
                .lazy(prcs, clx.sub(0, pieces.prc_len)),
        );
    }
    let n = to_u64(pieces.list.len());
    cx.emit(
        Node::new("Pcdt")
            .span(clx.tail(pieces.prc_len))
            .summary(format!("{n} pieces"))
            .lazy(piece_list, doc.clone()),
    );
    Ok(())
}

async fn prcs(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let mut at = 0usize;
    let mut i = 0u32;
    while data.get(at) == Some(&1) {
        let n = usize::from(
            i16_le(&data, at.saturating_add(1))
                .unwrap_or(0)
                .unsigned_abs(),
        );
        let grpprl = data
            .get(at.saturating_add(3)..at.saturating_add(3).saturating_add(n))
            .unwrap_or_default();
        let node_span = span.sub(to_u64(at), to_u64(n.saturating_add(3)));
        let mut node = Node::new(format!("Prc {i}"))
            .span(node_span)
            .summary(sprm::summary(grpprl));
        node = node.lazy(
            grpprl_node,
            (node_span.tail(3), Some(node_span.sub(0, 3)), H_PRC),
        );
        cx.push(node).await;
        at = at.saturating_add(3).saturating_add(n);
        i = i.saturating_add(1);
    }
    Ok(())
}

const PCD_FLAGS: FlagTable = &[
    flag(0x1, "fNoParaLast"),
    flag(0x2, "fR1"),
    flag(0x4, "fDirty"),
];

async fn piece_list(cx: Cx, doc: Doc) -> Result<()> {
    let pieces = pieces(&cx, &doc).await?;
    let Some(clx) = doc.table_span(pair::CLX) else {
        return Ok(());
    };
    let pcdt = clx.tail(pieces.prc_len);
    cx.emit(Node::new("clxt").span(pcdt.sub(0, 1)).value(hex(2u8, 8)));
    cx.emit(Node::new("lcb").span(pcdt.sub(1, 4)).value(uint(
        clx.len.saturating_sub(pieces.prc_len).saturating_sub(5),
        32,
    )));
    let n = to_u64(pieces.list.len());
    let plc = clx.tail(pieces.plc_at);
    cx.emit(
        Node::new("CPs")
            .span(plc.sub(0, n.saturating_add(1).saturating_mul(4)))
            .summary(format!("{} character positions", n.saturating_add(1)))
            .lazy(cp_list, plc.sub(0, n.saturating_add(1).saturating_mul(4))),
    );
    let pcds = plc.tail(n.saturating_add(1).saturating_mul(4));
    cx.set_count(Count::Exact(n.saturating_add(3)));
    for (i, p) in pieces.list.iter().enumerate() {
        let pcd = pcds.sub(to_u64(i).saturating_mul(8), 8);
        let (_, end) = p.fc_range();
        let bytes = p.bytes(doc.wd, p.cp, p.cp_end);
        let text = text_range(&cx, &doc, &pieces, p.cp.into(), p.cp_end.into(), MAX_TEXT).await;
        let kind = if p.width() == 1 { "8-bit" } else { "UTF-16" };
        cx.push(
            Node::new(format!("Piece {i}"))
                .span(pcd)
                .summary(format!(
                    "CP {}–{}, {kind} at {:#x}–{end:#x}: {}",
                    p.cp,
                    p.cp_end,
                    bytes.offset.saturating_sub(doc.wd.offset),
                    quoted(&text, PREVIEW)
                ))
                .lazy(piece_node, (pcd, bytes, text, p.text)),
        )
        .await;
    }
    Ok(())
}

async fn cp_list(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    for (i, c) in data.as_chunks::<4>().0.iter().enumerate() {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        cx.push(
            Node::new(format!("CP {i}"))
                .span(span.sub(to_u64(i).saturating_mul(4), 4))
                .value(uint(u32::from_le_bytes(*c), 32)),
        )
        .await;
    }
    Ok(())
}

async fn piece_node(
    cx: Cx,
    (pcd, bytes, text, kind): (Span, Span, String, PieceText),
) -> Result<()> {
    let block = cx.block(pcd).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u16("Flags").flags(PCD_FLAGS).emit()?;
    if let PieceText::Legacy(codepage) = kind {
        f.u32("fc")
            .hex()
            .desc("Offset of the piece's 8-bit text in the WordDocument stream")
            .emit()?;
        f.u16("prm").hex().desc("Property modifier").emit()?;
        cx.emit(
            Node::new("Text")
                .span(bytes)
                .value(Value::Text(text))
                .summary(format!("{} characters, Windows-{codepage}", bytes.len)),
        );
        return Ok(());
    }
    let compressed = kind == PieceText::Compressed;
    f.u32("fc")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "{} at {:#x}",
                if v & 0x4000_0000 != 0 {
                    "8-bit (fCompressed)"
                } else {
                    "UTF-16"
                },
                if v & 0x4000_0000 != 0 {
                    (v & 0x3fff_ffff) / 2
                } else {
                    v & 0x3fff_ffff
                }
            ))
        })
        .desc("Bit 30 (fCompressed) selects 8-bit text at fc/2; otherwise UTF-16 at fc")
        .emit()?;
    f.u16("prm")
        .hex()
        .with(|&v, n| {
            n.summary(if v & 1 != 0 {
                format!("Prc {}", v >> 1)
            } else if v == 0 {
                "none".to_owned()
            } else {
                format!("{} = {}", sprm_short(v >> 1), (v >> 8) & 0xff)
            })
        })
        .desc("Property modifier: an index into the Prcs, or one sprm with a 1-byte operand")
        .emit()?;
    let mut node = Node::new("Text").span(bytes).value(Value::Text(text));
    node = node.summary(format!(
        "{} characters, {}",
        if compressed { bytes.len } else { bytes.len / 2 },
        if compressed {
            "Windows-1252"
        } else {
            "UTF-16LE"
        }
    ));
    cx.emit(node);
    Ok(())
}

/// The sprm of a one-sprm prm (`isprm` is the index into a fixed table of
/// 128 opcodes; shown as the index).
fn sprm_short(v: u16) -> String {
    format!("isprm {}", v & 0x7f)
}

// ---------------------------------------------------------------------------
// Property lists

/// The sprms of a grpprl, with an optional header node before them.
/// Header fields before a grpprl: names and sizes.
type HeaderFields = &'static [(&'static str, u8)];

const H_PRC: HeaderFields = &[("clxt", 1), ("cbGrpprl", 2)];
const H_UPX: HeaderFields = &[("cbUpx", 2)];
const H_UPX_ISTD: HeaderFields = &[("cbUpx", 2), ("istd", 2)];
const H_SEPX: HeaderFields = &[("cb", 2)];
const H_CHPX: HeaderFields = &[("cb", 1)];
const H_PAPX: HeaderFields = &[("cb", 1), ("istd", 2)];
const H_PAPX_LONG: HeaderFields = &[("cb (0)", 1), ("cb'", 1), ("istd", 2)];

async fn grpprl_node(
    cx: Cx,
    (span, header, fields): (Span, Option<Span>, HeaderFields),
) -> Result<()> {
    if let Some(h) = header {
        let block = cx.block(h).await?;
        let mut f = Fields::emitting(&cx, &block, LE);
        for &(name, size) in fields {
            match size {
                1 => {
                    f.u8(name).emit()?;
                }
                _ => {
                    f.u16(name).emit()?;
                }
            }
        }
    }
    let data = cx.read(span).await?;
    for node in sprm::nodes(&data, span) {
        cx.emit(node);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Stylesheet

const STK: EnumTable = &[
    (1, "paragraph"),
    (2, "character"),
    (3, "table"),
    (4, "numbering"),
];

const GRFSTD: FlagTable = &[
    flag(0x0001, "fAutoRedef"),
    flag(0x0002, "fHidden"),
    flag(0x0004, "f97LidsSet"),
    flag(0x0008, "fCopyLang"),
    flag(0x0010, "fPersonalCompose"),
    flag(0x0020, "fPersonalReply"),
    flag(0x0040, "fPersonal"),
    flag(0x0080, "fNoHtmlExport"),
    flag(0x0100, "fSemiHidden"),
    flag(0x0200, "fLocked"),
    flag(0x0400, "fInternalUse"),
    flag(0x0800, "fUnhideWhenUsed"),
    flag(0x1000, "fQFormat"),
];

/// Style names by istd, parsed once.
struct Styles {
    names: Vec<Option<String>>,
    cb_base: u16,
    cb_stshi: u64,
}

async fn styles(cx: &Cx, span: Span) -> Result<Arc<Styles>> {
    if let Some(found) = cx.cached::<Styles>(span, "word-styles") {
        return Ok(found);
    }
    let data = cx.read(span).await?;
    let cb_stshi = u64::from(u16_le(&data, 0).unwrap_or(0));
    let cstd = u16_le(&data, 2).unwrap_or(0);
    let cb_base = u16_le(&data, 4).unwrap_or(10);
    let mut at = to_usize(cb_stshi.saturating_add(2));
    let mut names = Vec::new();
    for i in 0..cstd {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let Some(cb) = u16_le(&data, at) else { break };
        let std = at.saturating_add(2);
        let name = if cb == 0 {
            None
        } else {
            let name_at = std.saturating_add(usize::from(cb_base));
            let cch = usize::from(u16_le(&data, name_at).unwrap_or(0));
            data.get(
                name_at.saturating_add(2)
                    ..name_at
                        .saturating_add(2)
                        .saturating_add(cch.saturating_mul(2)),
            )
            .map(|b| crate::text::utf16(b, LE))
        };
        names.push(name);
        at = std.saturating_add(usize::from(cb));
    }
    let styles = Arc::new(Styles {
        names,
        cb_base,
        cb_stshi,
    });
    cx.cache(span, "word-styles", styles.clone());
    Ok(styles)
}

async fn style_count(cx: &Cx, span: Span) -> String {
    match styles(cx, span).await {
        Ok(s) => format!(
            "{} styles ({} defined)",
            s.names.len(),
            s.names.iter().filter(|n| n.is_some()).count()
        ),
        Err(_) => format!("{} bytes", span.len),
    }
}

const STSHI: Spec = &[
    ("cstd", K::U16),
    ("cbSTDBaseInFile", K::U16),
    ("Flags", K::H16),
    ("stiMaxWhenSaved", K::U16),
    ("istdMaxFixedWhenSaved", K::U16),
    ("nVerBuiltInNamesWhenSaved", K::U16),
    ("ftcAsci", K::U16),
    ("ftcFE", K::U16),
    ("ftcOther", K::U16),
];

async fn stylesheet(cx: Cx, doc: Doc) -> Result<()> {
    let Some(span) = doc.table_span(pair::STSHF) else {
        return Ok(());
    };
    let styles = styles(&cx, span).await?;
    cx.emit(
        Node::new("cbStshi")
            .span(span.sub(0, 2))
            .value(uint(styles.cb_stshi, 16)),
    );
    let stshi = span.sub(2, styles.cb_stshi);
    let mut stshi_node = struct_node("Stshi", stshi, LE, STSHI, rec::layout);
    stshi_node = stshi_node.summary(format!(
        "{} styles, {}-byte base",
        styles.names.len(),
        styles.cb_base
    ));
    cx.emit(stshi_node);
    if styles.cb_stshi > 18 {
        cx.emit(
            Node::new("StshiLsd")
                .span(stshi.tail(18))
                .summary("latent style data"),
        );
    }
    let data = cx.read(span).await?;
    let mut at = to_usize(styles.cb_stshi.saturating_add(2));
    for (istd, name) in styles.names.iter().enumerate() {
        let Some(cb) = u16_le(&data, at) else { break };
        let lpstd = span.sub(to_u64(at), u64::from(cb).saturating_add(2));
        at = at.saturating_add(2).saturating_add(usize::from(cb));
        let node = Node::new(format!("Style {istd}")).span(lpstd);
        cx.push(match name {
            None => node.summary("empty slot"),
            Some(n) => {
                let std = data
                    .get(to_usize(lpstd.offset.saturating_sub(span.offset)).saturating_add(2)..)
                    .unwrap_or_default();
                let w0 = u16_le(std, 0).unwrap_or(0);
                let w1 = u16_le(std, 2).unwrap_or(0);
                let stk = lookup(STK, (w1 & 0xf).into()).unwrap_or("unknown");
                node.value(Value::Text(n.clone()))
                    .summary(format!(
                        "{stk} style, sti {}, based on {}",
                        w0 & 0xfff,
                        match w1 >> 4 {
                            0xfff => "nothing".to_owned(),
                            b => format!("style {b}"),
                        }
                    ))
                    .lazy(style_node, (lpstd, styles.cb_base))
            }
        })
        .await;
    }
    Ok(())
}

async fn style_node(cx: Cx, (span, cb_base): (Span, u16)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let cb = f.u16("cbStd").emit()?;
    f.u16("sti / flags")
        .with(|&v, n| {
            n.summary(format!(
                "sti {}{}{}{}{}",
                v & 0xfff,
                if v & 0x1000 != 0 { ", fScratch" } else { "" },
                if v & 0x2000 != 0 {
                    ", fInvalHeight"
                } else {
                    ""
                },
                if v & 0x4000 != 0 { ", fHasUpe" } else { "" },
                if v & 0x8000 != 0 { ", fMassCopy" } else { "" },
            ))
        })
        .desc("Built-in style identifier (bits 0–11; 4094 is a user style) and flags")
        .emit()?;
    let stk_word = f
        .u16("stk / istdBase")
        .with(|&v, n| {
            n.summary(format!(
                "{} style, based on {}",
                lookup(STK, (v & 0xf).into()).unwrap_or("unknown"),
                v >> 4
            ))
        })
        .emit()?;
    let upx_count = stk_word & 0xf;
    f.u16("cupx / istdNext")
        .with(|&v, n| n.summary(format!("{} UPXs, next style {}", v & 0xf, v >> 4)))
        .emit()?;
    f.u16("bchUpe")
        .desc("Size of the style without its UPXs")
        .emit()?;
    f.u16("grfstd").flags(GRFSTD).emit()?;
    if cb_base >= 18 {
        f.u16("istdLink").emit()?;
        f.u32("rsid").hex().emit()?;
        f.u16("iPriority").emit()?;
    }
    f.seek(u64::from(cb_base).saturating_add(2));
    let data = &block.data;
    let name_at = to_usize(f.pos());
    let cch = u64::from(u16_le(data, name_at).unwrap_or(0));
    f.u16("cch").emit()?;
    f.utf16("xstzName", cch).emit()?;
    f.u16("Terminator").emit()?;
    // UPXs: each a 16-bit size, data, and padding to an even offset.
    let names: &[&str] = match upx_count {
        1 => &["UPX (paragraph)", "UPX (character)", "UPX"],
        2 => &["UPX (character)", "UPX"],
        3 => &["UPX (table)", "UPX (paragraph)", "UPX (character)"],
        4 => &["UPX (numbering)", "UPX"],
        _ => &["UPX", "UPX", "UPX"],
    };
    let mut i = 0usize;
    while f.pos().saturating_add(2) <= u64::from(cb).saturating_add(2) && i < 3 {
        let at = to_usize(f.pos());
        let len = u64::from(u16_le(data, at).unwrap_or(0));
        let name = names.get(i).copied().unwrap_or("UPX");
        let upx = f.peek_span(len.saturating_add(2));
        // Paragraph and table UPXs start with an istd.
        let istd_first = name.contains("paragraph") || name.contains("table");
        let inner = upx.tail(if istd_first { 4 } else { 2 });
        let grpprl = data
            .get(
                to_usize(inner.offset.saturating_sub(span.offset))
                    ..to_usize(upx.end().saturating_sub(span.offset)),
            )
            .unwrap_or_default();
        f.node(
            Node::new(name)
                .span(upx)
                .summary(sprm::summary(grpprl))
                .lazy(
                    grpprl_node,
                    (
                        inner,
                        Some(upx.sub(0, if istd_first { 4 } else { 2 })),
                        if istd_first { H_UPX_ISTD } else { H_UPX },
                    ),
                ),
        );
        f.skip(len.saturating_add(2));
        if f.pos() % 2 == 1 && f.pos() < u64::from(cb).saturating_add(2) {
            f.u8("Padding").emit()?;
        }
        i = i.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fonts

const FONT_FAMILY: EnumTable = &[
    (0, "FF_DONTCARE"),
    (1, "FF_ROMAN"),
    (2, "FF_SWISS"),
    (3, "FF_MODERN"),
    (4, "FF_SCRIPT"),
    (5, "FF_DECORATIVE"),
];

const PITCH: EnumTable = &[(0, "default"), (1, "fixed"), (2, "variable")];

pub const CHARSETS: EnumTable = &[
    (0, "ANSI_CHARSET"),
    (1, "DEFAULT_CHARSET"),
    (2, "SYMBOL_CHARSET"),
    (77, "MAC_CHARSET"),
    (128, "SHIFTJIS_CHARSET"),
    (129, "HANGUL_CHARSET"),
    (130, "JOHAB_CHARSET"),
    (134, "GB2312_CHARSET"),
    (136, "CHINESEBIG5_CHARSET"),
    (161, "GREEK_CHARSET"),
    (162, "TURKISH_CHARSET"),
    (163, "VIETNAMESE_CHARSET"),
    (177, "HEBREW_CHARSET"),
    (178, "ARABIC_CHARSET"),
    (186, "BALTIC_CHARSET"),
    (204, "RUSSIAN_CHARSET"),
    (222, "THAI_CHARSET"),
    (238, "EASTEUROPE_CHARSET"),
    (255, "OEM_CHARSET"),
];

/// Font names and record offsets of an SttbfFfn.
fn font_list(data: &[u8]) -> Vec<(usize, usize, String)> {
    let count = usize::from(u16_le(data, 0).unwrap_or(0));
    let mut at = 4usize;
    let mut out = Vec::new();
    for _ in 0..count {
        let Some(&cch) = data.get(at) else { break };
        let ffn = data
            .get(at.saturating_add(1)..at.saturating_add(1).saturating_add(usize::from(cch)))
            .unwrap_or_default();
        let name = crate::text::utf16z(ffn.get(39..).unwrap_or_default(), LE).0;
        out.push((at, usize::from(cch).saturating_add(1), name));
        at = at.saturating_add(1).saturating_add(usize::from(cch));
    }
    out
}

async fn font_summary(cx: &Cx, span: Span) -> String {
    let Ok(data) = cx.read(span).await else {
        return String::new();
    };
    let list = font_list(&data);
    let names: Vec<&str> = list.iter().take(4).map(|(_, _, n)| n.as_str()).collect();
    let more = if list.len() > 4 { ", ..." } else { "" };
    format!("{} fonts: {}{more}", list.len(), names.join(", "))
}

async fn fonts(cx: Cx, doc: Doc) -> Result<()> {
    let Some(span) = doc.table_span(pair::STTBF_FFN) else {
        return Ok(());
    };
    let data = cx.read(span).await?;
    cx.emit(
        Node::new("cData")
            .span(span.sub(0, 2))
            .value(uint(u16_le(&data, 0).unwrap_or(0), 16)),
    );
    cx.emit(
        Node::new("cbExtra")
            .span(span.sub(2, 2))
            .value(uint(u16_le(&data, 2).unwrap_or(0), 16)),
    );
    for (i, (at, len, name)) in font_list(&data).into_iter().enumerate() {
        if i.is_multiple_of(64) {
            cx.checkpoint().await;
        }
        let ffn = span.sub(to_u64(at), to_u64(len));
        let first = data.get(at.saturating_add(1)).copied().unwrap_or(0);
        let charset = data.get(at.saturating_add(4)).copied().unwrap_or(0);
        cx.push(
            Node::new(format!("Font {i}"))
                .span(ffn)
                .value(Value::Text(name))
                .summary(format!(
                    "{}, {}{}",
                    lookup(FONT_FAMILY, bits(first.into(), 4, 3)).unwrap_or("family ?"),
                    lookup(CHARSETS, charset.into()).unwrap_or("charset ?"),
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
    let cb = f.u8("cchData").desc("Size of the FFN in bytes").emit()?;
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
    f.u8("ixchSzAlt")
        .desc("Index of the alternative font name within xszFfn, or 0")
        .emit()?;
    f.bytes("panose", 10).emit()?;
    f.bytes("fs", 24)
        .desc("FONTSIGNATURE: Unicode and code page ranges")
        .emit()?;
    let rest = u64::from(cb).saturating_sub(38);
    let names = crate::text::utf16(block.data.get(40..).unwrap_or_default(), LE);
    let shown: Vec<&str> = names.split('\0').filter(|s| !s.is_empty()).collect();
    f.node(
        Node::new("xszFfn")
            .span(f.peek_span(rest))
            .value(Value::Text(shown.join(" / "))),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Sections

async fn sections(cx: Cx, doc: Doc) -> Result<()> {
    let Some(span) = doc.table_span(pair::PLCF_SED) else {
        return Ok(());
    };
    let data = cx.read(span).await?;
    let n = plc_count(span.len, 12);
    let seds = to_usize(n.saturating_add(1).saturating_mul(4));
    let cp = |i: u64| u32_le(&data, to_usize(i.saturating_mul(4))).unwrap_or(0);
    cx.emit(
        Node::new("CPs")
            .span(span.sub(0, to_u64(seds)))
            .lazy(cp_list, span.sub(0, to_u64(seds))),
    );
    for i in 0..n {
        let at = to_u64(seds).saturating_add(i.saturating_mul(12));
        let sed = span.sub(at, 12);
        let fc_sepx = i32_le(&data, to_usize(at).saturating_add(2)).unwrap_or(-1);
        let sepx = if fc_sepx >= 0 {
            let at = u64::from(fc_sepx.unsigned_abs());
            let len = cx
                .read_avail(doc.wd.sub(at, 2))
                .await
                .ok()
                .and_then(|b| i16_le(&b, 0))
                .unwrap_or(0);
            Some(
                doc.wd
                    .sub(at, u64::from(len.unsigned_abs()).saturating_add(2)),
            )
        } else {
            None
        };
        let summary = match sepx {
            Some(s) => {
                let grpprl = cx.read_avail(s.tail(2)).await?;
                sprm::summary(&grpprl)
            }
            None => "default properties".to_owned(),
        };
        cx.push(
            Node::new(format!(
                "Section {i}: CP {}–{}",
                cp(i),
                cp(i.saturating_add(1))
            ))
            .span(sed)
            .summary(summary)
            .lazy(sed_node, (sed, sepx)),
        )
        .await;
    }
    Ok(())
}

async fn sed_node(cx: Cx, (sed, sepx): (Span, Option<Span>)) -> Result<()> {
    let block = cx.block(sed).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.int::<i16>("fn").emit()?;
    f.i32("fcSepx")
        .desc("Offset of the SEPX in the WordDocument stream, or -1")
        .emit()?;
    f.int::<i16>("fnMpr").emit()?;
    f.i32("fcMpr").emit()?;
    if let Some(s) = sepx {
        cx.emit(
            Node::new("SEPX")
                .span(s)
                .lazy(grpprl_node, (s.tail(2), Some(s.sub(0, 2)), H_SEPX)),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fields

const FIELD_TYPES: EnumTable = &[
    (1, "(unnamed)"),
    (3, "REF"),
    (6, "SET"),
    (7, "IF"),
    (8, "INDEX"),
    (10, "STYLEREF"),
    (12, "SEQ"),
    (13, "TOC"),
    (14, "INFO"),
    (15, "TITLE"),
    (16, "SUBJECT"),
    (17, "AUTHOR"),
    (18, "KEYWORDS"),
    (19, "COMMENTS"),
    (20, "LASTSAVEDBY"),
    (21, "CREATEDATE"),
    (22, "SAVEDATE"),
    (23, "PRINTDATE"),
    (24, "REVNUM"),
    (25, "EDITTIME"),
    (26, "NUMPAGES"),
    (27, "NUMWORDS"),
    (28, "NUMCHARS"),
    (29, "FILENAME"),
    (30, "TEMPLATE"),
    (31, "DATE"),
    (32, "TIME"),
    (33, "PAGE"),
    (34, "="),
    (35, "QUOTE"),
    (36, "INCLUDE"),
    (37, "PAGEREF"),
    (38, "ASK"),
    (39, "FILLIN"),
    (40, "DATA"),
    (41, "NEXT"),
    (42, "NEXTIF"),
    (43, "SKIPIF"),
    (44, "MERGEREC"),
    (45, "DDE"),
    (46, "DDEAUTO"),
    (47, "GLOSSARY"),
    (48, "PRINT"),
    (49, "EQ"),
    (50, "GOTOBUTTON"),
    (51, "MACROBUTTON"),
    (52, "AUTONUMOUT"),
    (53, "AUTONUMLGL"),
    (54, "AUTONUM"),
    (55, "IMPORT"),
    (56, "LINK"),
    (57, "SYMBOL"),
    (58, "EMBED"),
    (59, "MERGEFIELD"),
    (60, "USERNAME"),
    (61, "USERINITIALS"),
    (62, "USERADDRESS"),
    (63, "BARCODE"),
    (64, "DOCVARIABLE"),
    (65, "SECTION"),
    (66, "SECTIONPAGES"),
    (67, "INCLUDEPICTURE"),
    (68, "INCLUDETEXT"),
    (69, "FILESIZE"),
    (70, "FORMTEXT"),
    (71, "FORMCHECKBOX"),
    (72, "NOTEREF"),
    (73, "TOA"),
    (74, "TA"),
    (75, "MERGESEQ"),
    (77, "PRIVATE"),
    (78, "DATABASE"),
    (79, "AUTOTEXT"),
    (80, "COMPARE"),
    (81, "ADDIN"),
    (83, "FORMDROPDOWN"),
    (84, "ADVANCE"),
    (85, "DOCPROPERTY"),
    (87, "CONTROL"),
    (88, "HYPERLINK"),
    (89, "AUTOTEXTLIST"),
    (90, "LISTNUM"),
    (91, "HTMLCONTROL"),
    (92, "BIDIOUTLINE"),
    (93, "ADDRESSBLOCK"),
    (94, "GREETINGLINE"),
    (95, "SHAPE"),
];

const FIELD_END_FLAGS: FlagTable = &[
    flag(0x01, "fDiffer"),
    flag(0x02, "fZombieEmbed"),
    flag(0x04, "fResultsDirty"),
    flag(0x08, "fResultsEdited"),
    flag(0x10, "fLocked"),
    flag(0x20, "fPrivateResult"),
    flag(0x40, "fNested"),
    flag(0x80, "fHasSep"),
];

async fn fields(cx: Cx, doc: Doc) -> Result<()> {
    fields_of(cx, (doc, pair::PLCF_FLD_MOM)).await
}

/// A PlcFld: the field characters of one story.
async fn fields_of(cx: Cx, (doc, index): (Doc, usize)) -> Result<()> {
    let Some(span) = doc.table_span(index) else {
        return Ok(());
    };
    let story = match index {
        pair::PLCF_FLD_FTN => 4,
        pair::PLCF_FLD_HDR => 5,
        pair::PLCF_FLD_ATN => 7,
        pair::PLCF_FLD_EDN => 8,
        pair::PLCF_FLD_TXBX => 9,
        pair::PLCF_FLD_HDR_TXBX => 10,
        _ => 3,
    };
    let base = story_starts(&doc.fib)
        .iter()
        .find(|(i, ..)| *i == story)
        .map_or(0, |(_, _, start, _)| *start);
    let pieces = pieces(&cx, &doc).await.ok();
    let data = cx.read(span).await?;
    let n = plc_count(span.len, 2);
    let cps_len = n.saturating_add(1).saturating_mul(4);
    cx.emit(
        Node::new("CPs")
            .span(span.sub(0, cps_len))
            .lazy(cp_list, span.sub(0, cps_len)),
    );
    // Field codes run from a begin character to its separator (or end).
    let mut open: Vec<u64> = Vec::new();
    for i in 0..n {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let cp = u64::from(u32_le(&data, to_usize(i.saturating_mul(4))).unwrap_or(0));
        let at = cps_len.saturating_add(i.saturating_mul(2));
        let ch = data.get(to_usize(at)).copied().unwrap_or(0) & 0x1f;
        let arg = data
            .get(to_usize(at).saturating_add(1))
            .copied()
            .unwrap_or(0);
        let fld = span.sub(at, 2);
        let (kind, summary, value) = match ch {
            0x13 => {
                open.push(cp);
                (
                    "begin",
                    lookup(FIELD_TYPES, arg.into())
                        .unwrap_or("unknown field type")
                        .to_owned(),
                    enumv(arg, 8, FIELD_TYPES),
                )
            }
            0x14 | 0x15 => {
                let mut code = String::new();
                if (ch == 0x14
                    || data.get(to_usize(at).saturating_sub(2)).map(|c| c & 0x1f) != Some(0x14))
                    && let (Some(start), Some(p)) = (open.last(), &pieces)
                {
                    {
                        code = text_range(
                            &cx,
                            &doc,
                            p,
                            base.saturating_add(*start).saturating_add(1),
                            base.saturating_add(cp),
                            200,
                        )
                        .await;
                    }
                }
                if ch == 0x15 {
                    open.pop();
                }
                let kind = if ch == 0x14 { "separator" } else { "end" };
                let flags = rec::flagsv(arg, 8, FIELD_END_FLAGS);
                let summary = if code.is_empty() {
                    String::new()
                } else {
                    format!("code {}", quoted(code.trim(), 80))
                };
                (kind, summary, if ch == 0x15 { flags } else { hex(arg, 8) })
            }
            _ => ("invalid", String::new(), hex(arg, 8)),
        };
        let mut node = Node::new(format!("Field {kind} at CP {cp}"))
            .span(fld)
            .value(value);
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// String tables

const ASSOC: &[&str] = &[
    "ibstAssocFileNext",
    "ibstAssocDot (template)",
    "ibstAssocTitle",
    "ibstAssocSubject",
    "ibstAssocKeyWords",
    "ibstAssocComments",
    "ibstAssocAuthor",
    "ibstAssocLastRevBy",
    "ibstAssocDataDoc",
    "ibstAssocHeaderDoc",
    "ibstAssocCriteria1",
    "ibstAssocCriteria2",
    "ibstAssocCriteria3",
    "ibstAssocCriteria4",
    "ibstAssocCriteria5",
    "ibstAssocCriteria6",
    "ibstAssocCriteria7",
    "ibstAssocMaxUnused",
];

/// The strings of an Sttb: (offset, size, text) of each entry, the size of
/// the extra data per entry, and the header size.
fn sttb_entries(data: &[u8]) -> (Vec<(usize, usize, String)>, usize, usize, bool) {
    let extended = u16_le(data, 0) == Some(0xffff);
    let header = if extended { 2 } else { 0 };
    let count = usize::from(u16_le(data, header).unwrap_or(0));
    let extra = usize::from(u16_le(data, header.saturating_add(2)).unwrap_or(0));
    let mut at = header.saturating_add(4);
    let mut out = Vec::new();
    for _ in 0..count {
        let (len, text) = if extended {
            let Some(cch) = u16_le(data, at) else { break };
            let n = usize::from(cch).saturating_mul(2);
            let raw = data
                .get(at.saturating_add(2)..at.saturating_add(2).saturating_add(n))
                .unwrap_or_default();
            (n.saturating_add(2), crate::text::utf16(raw, LE))
        } else {
            let Some(&cch) = data.get(at) else { break };
            let n = usize::from(cch);
            let raw = data
                .get(at.saturating_add(1)..at.saturating_add(1).saturating_add(n))
                .unwrap_or_default();
            (n.saturating_add(1), crate::text::latin1(raw))
        };
        out.push((at, len.saturating_add(extra), text));
        at = at.saturating_add(len).saturating_add(extra);
    }
    (out, extra, header.saturating_add(4), extended)
}

async fn sttb_summary(cx: &Cx, span: Span) -> (String, usize) {
    let Ok(data) = cx.read(span).await else {
        return (String::new(), 0);
    };
    let (entries, ..) = sttb_entries(&data);
    let shown: Vec<String> = entries
        .iter()
        .filter(|(_, _, t)| !t.is_empty())
        .take(3)
        .map(|(_, _, t)| quoted(t, 40))
        .collect();
    (
        format!("{} strings: {}", entries.len(), shown.join(", ")),
        entries.len(),
    )
}

async fn sttb_node(cx: Cx, (span, index): (Span, usize)) -> Result<()> {
    let data = cx.read(span).await?;
    let (entries, extra, header, extended) = sttb_entries(&data);
    if extended {
        cx.emit(
            Node::new("fExtend")
                .span(span.sub(0, 2))
                .value(hex(0xffffu16, 16))
                .summary("UTF-16 strings"),
        );
    }
    let h = if extended { 2u64 } else { 0 };
    cx.emit(
        Node::new("cData")
            .span(span.sub(h, 2))
            .value(uint(to_u64(entries.len()), 16)),
    );
    cx.emit(
        Node::new("cbExtra")
            .span(span.sub(h.saturating_add(2), 2))
            .value(uint(to_u64(extra), 16)),
    );
    let _ = header;
    for (i, (at, len, text)) in entries.into_iter().enumerate() {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let name = if index == pair::STTBF_ASSOC {
            ASSOC
                .get(i)
                .map_or_else(|| format!("String {i}"), |n| (*n).to_owned())
        } else if index == pair::STTB_SAVED_BY {
            if i % 2 == 0 {
                format!("Save {} author", i / 2)
            } else {
                format!("Save {} path", i / 2)
            }
        } else {
            format!("String {i}")
        };
        cx.push(
            Node::new(name)
                .span(span.sub(to_u64(at), to_u64(len)))
                .value(Value::Text(text)),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Formatting: bin tables and FKP pages

#[derive(Clone, Copy, PartialEq, Eq)]
enum FkpKind {
    Chpx,
    Papx,
}

async fn chpx_bins(cx: Cx, doc: Doc) -> Result<()> {
    bins(cx, doc, FkpKind::Chpx).await
}

async fn papx_bins(cx: Cx, doc: Doc) -> Result<()> {
    bins(cx, doc, FkpKind::Papx).await
}

/// A PlcBteChpx or PlcBtePapx: FC ranges and the FKP page holding each.
async fn bins(cx: Cx, doc: Doc, kind: FkpKind) -> Result<()> {
    let index = match kind {
        FkpKind::Chpx => pair::PLCF_BTE_CHPX,
        FkpKind::Papx => pair::PLCF_BTE_PAPX,
    };
    let Some(span) = doc.table_span(index) else {
        return Ok(());
    };
    let data = cx.read(span).await?;
    let n = plc_count(span.len, 4);
    let fcs_len = n.saturating_add(1).saturating_mul(4);
    cx.emit(
        Node::new("FCs")
            .span(span.sub(0, fcs_len))
            .summary(format!("{} file positions", n.saturating_add(1)))
            .lazy(cp_list, span.sub(0, fcs_len)),
    );
    let fc = |i: u64| u32_le(&data, to_usize(i.saturating_mul(4))).unwrap_or(0);
    cx.set_count(Count::Exact(n.saturating_add(1)));
    for i in 0..n {
        let at = fcs_len.saturating_add(i.saturating_mul(4));
        let pn = u32_le(&data, to_usize(at)).unwrap_or(0) & 0x003f_ffff;
        let page = doc.wd.sub(u64::from(pn).saturating_mul(PAGE), PAGE);
        let what = match kind {
            FkpKind::Chpx => "character",
            FkpKind::Papx => "paragraph",
        };
        cx.push(
            Node::new(format!("FKP page {pn}"))
                .span(span.sub(at, 4))
                .value(uint(pn, 32))
                .summary(format!(
                    "{what} formatting for FC {:#x}–{:#x}",
                    fc(i),
                    fc(i.saturating_add(1))
                ))
                .target(page)
                .lazy(fkp, (doc.clone(), page, kind == FkpKind::Papx)),
        )
        .await;
    }
    Ok(())
}

/// One 512-byte formatted disk page.
async fn fkp(cx: Cx, (doc, page, papx): (Doc, Span, bool)) -> Result<()> {
    let data = cx.read(page).await?;
    let count = u64::from(data.get(511).copied().unwrap_or(0));
    let pieces = pieces(&cx, &doc).await.ok();
    let styles = match doc.table_span(pair::STSHF) {
        Some(s) => styles(&cx, s).await.ok(),
        None => None,
    };
    let rgfc_len = count.saturating_add(1).saturating_mul(4);
    cx.emit(
        Node::new("rgfc")
            .span(page.sub(0, rgfc_len))
            .summary(format!("{} file positions", count.saturating_add(1)))
            .lazy(cp_list, page.sub(0, rgfc_len)),
    );
    let entry = if papx { 13u64 } else { 1 };
    let rgb = page.sub(rgfc_len, count.saturating_mul(entry));
    cx.emit(
        Node::new(if papx { "rgbx" } else { "rgb" })
            .span(rgb)
            .summary(if papx {
                "word offsets of the PAPXs and paragraph height info"
            } else {
                "word offsets of the CHPXs (0: default formatting)"
            })
            .lazy(offsets, (rgb, entry)),
    );
    let fc = |i: u64| u64::from(u32_le(&data, to_usize(i.saturating_mul(4))).unwrap_or(0));
    let mut lowest = 511u64;
    for i in 0..count {
        let at = to_usize(rgfc_len.saturating_add(i.saturating_mul(entry)));
        let offset = u64::from(data.get(at).copied().unwrap_or(0)).saturating_mul(2);
        let (from, to) = (fc(i), fc(i.saturating_add(1)));
        let text = match &pieces {
            Some(p) => fc_text(&cx, &doc, p, from, to, 40).await,
            None => String::new(),
        };
        let label = if papx { "Paragraph" } else { "Run" };
        let mut node = Node::new(format!("{label} {i}: FC {from:#x}–{to:#x}"));
        if offset == 0 {
            node = node.summary(format!("{}: default", quoted(&text, 40)));
            cx.push(node).await;
            continue;
        }
        lowest = lowest.min(offset);
        let (span, grpprl_at, istd) = if papx {
            let cb = u64::from(data.get(to_usize(offset)).copied().unwrap_or(0));
            let (len, start) = if cb == 0 {
                let cb2 = u64::from(
                    data.get(to_usize(offset).saturating_add(1))
                        .copied()
                        .unwrap_or(0),
                );
                (cb2.saturating_mul(2).saturating_add(2), 2u64)
            } else {
                (
                    cb.saturating_mul(2).saturating_sub(1).saturating_add(1),
                    1u64,
                )
            };
            let istd = u16_le(&data, to_usize(offset.saturating_add(start))).unwrap_or(0);
            (page.sub(offset, len), start.saturating_add(2), Some(istd))
        } else {
            let cb = u64::from(data.get(to_usize(offset)).copied().unwrap_or(0));
            (page.sub(offset, cb.saturating_add(1)), 1u64, None)
        };
        let rel = to_usize(span.offset.saturating_sub(page.offset));
        let grpprl = data
            .get(rel.saturating_add(to_usize(grpprl_at))..rel.saturating_add(to_usize(span.len)))
            .unwrap_or_default();
        let style = istd.map(|s| {
            let name = styles
                .as_ref()
                .and_then(|st| st.names.get(usize::from(s)).cloned().flatten())
                .unwrap_or_else(|| format!("style {s}"));
            format!("{name}; ")
        });
        node = node
            .span(span)
            .summary(format!(
                "{}: {}{}",
                quoted(&text, 40),
                style.unwrap_or_default(),
                sprm::summary(grpprl)
            ))
            .lazy(
                grpprl_node,
                (
                    span.tail(grpprl_at),
                    Some(span.sub(0, grpprl_at)),
                    match grpprl_at {
                        1 => H_CHPX,
                        3 => H_PAPX,
                        _ => H_PAPX_LONG,
                    },
                ),
            );
        cx.push(node).await;
    }
    let free_at = rgfc_len.saturating_add(count.saturating_mul(entry));
    if lowest > free_at {
        cx.emit(
            Node::new("Free space")
                .span(page.sub(free_at, lowest.saturating_sub(free_at)))
                .summary(format!("{} bytes", lowest.saturating_sub(free_at))),
        );
    }
    cx.emit(
        Node::new(if papx { "cpara" } else { "crun" })
            .span(page.sub(511, 1))
            .value(uint(count, 8)),
    );
    Ok(())
}

async fn offsets(cx: Cx, (span, entry): (Span, u64)) -> Result<()> {
    let data = cx.read(span).await?;
    let n = span.len.checked_div(entry).unwrap_or(0);
    for i in 0..n {
        let at = i.saturating_mul(entry);
        let v = data.get(to_usize(at)).copied().unwrap_or(0);
        let mut node = Node::new(format!("Offset {i}"))
            .span(span.sub(at, 1))
            .value(uint(v, 8));
        if v != 0 {
            node = node.summary(format!("byte {}", u32::from(v).saturating_mul(2)));
        }
        cx.push(node).await;
        if entry == 13 {
            cx.push(
                Node::new(format!("PHE {i}"))
                    .span(span.sub(at.saturating_add(1), 12))
                    .value(Value::Bytes(
                        data.get(to_usize(at).saturating_add(1)..to_usize(at).saturating_add(13))
                            .unwrap_or_default()
                            .to_vec(),
                    ))
                    .summary("paragraph height (layout cache)"),
            )
            .await;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Document properties

/// The DOP: its size tells the version of the structure.
async fn dop(cx: Cx, doc: Doc) -> Result<()> {
    let Some(span) = doc.table_span(pair::DOP) else {
        return Ok(());
    };
    let version = match span.len {
        84 => "DopBase (Word 6/95)",
        500 => "Dop97",
        544 => "Dop2000",
        594 => "Dop2002",
        616 => "Dop2003",
        674 => "Dop2007",
        _ => "nonstandard size",
    };
    cx.emit(
        Node::new("Dop")
            .span(span)
            .summary(format!("{version}, {} bytes", span.len))
            .desc("Document-wide settings (tab width, footnote and endnote options, compatibility flags, statistics)"),
    );
    Ok(())
}
