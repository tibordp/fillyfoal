//! Legacy Office streams: the Word File Information Block, Excel BIFF
//! records and PowerPoint records.

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, field, flag, lookup};

const LE: Endian = Endian::Little;
/// Nesting of PowerPoint containers followed.
const MAX_PPT_DEPTH: u32 = 32;

// ---------------------------------------------------------------------------
// Word

const NFIB: EnumTable = &[
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
    field(0x00f0, 0x00f0, "cQuickSaves=15"),
    flag(0x0100, "fEncrypted"),
    flag(0x0200, "fWhichTblStm (1Table)"),
    flag(0x0400, "fReadOnlyRecommended"),
    flag(0x0800, "fWriteReservation"),
    flag(0x1000, "fExtChar"),
    flag(0x2000, "fLoadOverride"),
    flag(0x4000, "fFarEast"),
    flag(0x8000, "fObfuscated"),
];

record! {
    /// FibBase: the fixed start of the File Information Block.
    pub struct FibBase {
        ident: u16 "wIdent" .hex() .desc("0xA5EC for Word 97 and later"),
        nfib: u16 "nFib" .enumeration(NFIB),
        _unused: u16 "unused",
        lid: u16 "lid" .hex() .desc("Language of the document"),
        pn_next: u16 "pnNext",
        flags: u16 "Flags" .flags(FIB_FLAGS),
        nfib_back: u16 "nFibBack",
        key: u32 "lKey" .hex() .desc("Encryption key or obfuscation verifier"),
        envr: u8 "envr" .desc("0 for Windows, 1 for Macintosh"),
        flags2: u8 "Flags 2" .hex(),
        _reserved3: u16 "reserved3",
        _reserved4: u16 "reserved4",
        _reserved5: u32 "reserved5",
        _reserved6: u32 "reserved6",
    }
}

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
];

fn fib_rg_lw(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("cslw").emit()?;
    for name in RG_LW {
        f.u32(name).emit()?;
    }
    Ok(())
}

pub async fn word(cx: &Cx, span: Span) -> Result<()> {
    let base_span = span.sub(0, FibBase::SIZE);
    let base = crate::fields::parse(cx, base_span, LE, &(), FibBase::layout).await?;
    let mut node = FibBase::node("FibBase", base_span, LE);
    if base.ident != 0xa5ec {
        node = node.diag(Diagnostic::malformed(format!(
            "wIdent is {:#06x}, not 0xA5EC",
            base.ident
        )));
    }
    cx.emit(node);
    let csw_data = cx.read(span.sub(FibBase::SIZE, 2)).await?;
    let csw = u64::from(u16_le(&csw_data, 0).unwrap_or(0));
    let rg_w = span.sub(FibBase::SIZE, csw.saturating_mul(2).saturating_add(2));
    cx.emit(
        Node::new("fibRgW")
            .span(rg_w)
            .summary(format!("{csw} 16-bit values")),
    );
    let lw_at = rg_w.end().saturating_sub(span.offset);
    let lw_span = span.sub(
        lw_at,
        2u64.saturating_add(to_u64(RG_LW.len()).saturating_mul(4)),
    );
    cx.emit(struct_node("fibRgLw", lw_span, LE, (), fib_rg_lw));
    let lw = cx.read_avail(lw_span).await?;
    let cslw = u64::from(u16_le(&lw, 0).unwrap_or(0));
    let after_lw = lw_at
        .saturating_add(2)
        .saturating_add(cslw.saturating_mul(4));
    let count = cx.read_avail(span.sub(after_lw, 2)).await?;
    let pairs = u64::from(u16_le(&count, 0).unwrap_or(0));
    cx.emit(
        Node::new("fibRgFcLcb")
            .span(span.sub(after_lw, pairs.saturating_mul(8).saturating_add(2)))
            .summary(format!("{pairs} offset/size pairs into the table stream")),
    );
    if let Some(chars) = u32_le(&lw, 14) {
        cx.annotate(format!("{chars} characters of main text"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Excel

const BIFF: EnumTable = &[
    (0x0006, "FORMULA"),
    (0x000a, "EOF"),
    (0x000c, "CALCCOUNT"),
    (0x000d, "CALCMODE"),
    (0x0012, "PROTECT"),
    (0x0013, "PASSWORD"),
    (0x0014, "HEADER"),
    (0x0015, "FOOTER"),
    (0x0017, "EXTERNSHEET"),
    (0x0018, "NAME"),
    (0x0019, "WINDOWPROTECT"),
    (0x0022, "DATEMODE"),
    (0x0031, "FONT"),
    (0x003c, "CONTINUE"),
    (0x003d, "WINDOW1"),
    (0x0040, "BACKUP"),
    (0x0042, "CODEPAGE"),
    (0x0055, "DEFCOLWIDTH"),
    (0x005c, "WRITEACCESS"),
    (0x007d, "COLINFO"),
    (0x0085, "BOUNDSHEET"),
    (0x008c, "COUNTRY"),
    (0x00bd, "MULRK"),
    (0x00be, "MULBLANK"),
    (0x00e0, "XF"),
    (0x00e1, "INTERFACEHDR"),
    (0x00e2, "INTERFACEEND"),
    (0x00fc, "SST"),
    (0x00fd, "LABELSST"),
    (0x00ff, "EXTSST"),
    (0x013d, "TABID"),
    (0x0160, "USESELFS"),
    (0x0161, "DSF"),
    (0x01ae, "SUPBOOK"),
    (0x01b6, "TXO"),
    (0x01ba, "CODENAME"),
    (0x01c1, "RECALCID"),
    (0x0200, "DIMENSIONS"),
    (0x0201, "BLANK"),
    (0x0203, "NUMBER"),
    (0x0204, "LABEL"),
    (0x0205, "BOOLERR"),
    (0x0207, "STRING"),
    (0x0208, "ROW"),
    (0x020b, "INDEX"),
    (0x0225, "DEFAULTROWHEIGHT"),
    (0x023e, "WINDOW2"),
    (0x027e, "RK"),
    (0x0293, "STYLE"),
    (0x041e, "FORMAT"),
    (0x0809, "BOF"),
    (0x0862, "SHEETEXT"),
    (0x0892, "STYLEEXT"),
    (0x0896, "THEME"),
    (0x08a3, "FORCEFULLCALCULATION"),
];

const BOF_TYPES: EnumTable = &[
    (0x0005, "workbook globals"),
    (0x0006, "Visual Basic module"),
    (0x0010, "worksheet"),
    (0x0020, "chart"),
    (0x0040, "macro sheet"),
    (0x0100, "workspace"),
];

/// A BIFF8 short Unicode string (`cch`, flags, characters).
fn short_string(data: &[u8]) -> String {
    let n = usize::from(data.first().copied().unwrap_or(0));
    let wide = data.get(1).is_some_and(|f| f & 1 != 0);
    let body = data.get(2..).unwrap_or_default();
    if wide {
        crate::text::utf16(body.get(..n.saturating_mul(2)).unwrap_or(body), LE)
    } else {
        crate::text::latin1(body.get(..n).unwrap_or(body))
    }
}

fn biff_detail(kind: u16, data: &[u8]) -> Option<String> {
    match kind {
        0x0809 => lookup(BOF_TYPES, u16_le(data, 2)?.into()).map(str::to_owned),
        0x0085 => Some(format!("sheet {:?}", short_string(data.get(6..)?))),
        0x00fc => Some(format!("{} unique strings", u32_le(data, 4)?)),
        0x00fd => Some(format!(
            "row {}, column {}, string {}",
            u16_le(data, 0)?,
            u16_le(data, 2)?,
            u32_le(data, 6)?
        )),
        0x0203 => Some(format!(
            "row {}, column {}, {}",
            u16_le(data, 0)?,
            u16_le(data, 2)?,
            f64::from_le_bytes(crate::bytes::array(data, 6)?)
        )),
        0x0042 => Some(format!("code page {}", u16_le(data, 0)?)),
        0x0208 => Some(format!("row {}", u16_le(data, 0)?)),
        _ => None,
    }
}

/// Excel BIFF records, paged.
pub async fn biff(cx: &Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(cx, span, LE);
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let kind = cur.u16().await?;
        let len = cur.u16().await?;
        let data_span = cur.span(len.into());
        let data = cx.read_avail(data_span.sub(0, 64)).await?;
        cur.skip(len.into());
        let mut node = Node::new(
            lookup(BIFF, kind.into()).map_or_else(|| format!("Record {kind:#06x}"), str::to_owned),
        )
        .span(cur.since(start))
        .value(Value::UInt {
            value: kind.into(),
            bits: 16,
            radix: Radix::Hex,
        });
        node = match biff_detail(kind, &data) {
            Some(d) => node.summary(d),
            None => node.summary(format!("{len} bytes")),
        };
        if data_span.len < u64::from(len) {
            node = node.diag(Diagnostic::truncated(cur.since(start), data_span.len));
        }
        cx.progress_in(span, cur.since(start).offset);
        cx.push(node.lazy(record_fields, (cur.since(start), 4u64)))
            .await;
    }
    Ok(())
}

/// The header and data of a type/length record.
async fn record_fields(cx: Cx, (span, header): (Span, u64)) -> Result<()> {
    let head = cx.read_avail(span.sub(0, header)).await?;
    if header == 4 {
        let uint = |v: u16, bits| Value::UInt {
            value: v.into(),
            bits,
            radix: Radix::Hex,
        };
        cx.emit(
            Node::new("Type")
                .span(span.sub(0, 2))
                .value(uint(u16_le(&head, 0).unwrap_or(0), 16)),
        );
        cx.emit(Node::new("Length").span(span.sub(2, 2)).value(Value::UInt {
            value: u16_le(&head, 2).unwrap_or(0).into(),
            bits: 16,
            radix: Radix::Dec,
        }));
    }
    let data = span.tail(header);
    let preview = cx.read_avail(data.sub(0, 32)).await?;
    cx.emit(Node::new("Data").span(data).value(Value::Bytes(preview)));
    Ok(())
}

// ---------------------------------------------------------------------------
// PowerPoint

const PPT: EnumTable = &[
    (0x03e8, "DocumentContainer"),
    (0x03e9, "DocumentAtom"),
    (0x03ea, "EndDocumentAtom"),
    (0x03ee, "SlideContainer"),
    (0x03ef, "SlideAtom"),
    (0x03f0, "NotesContainer"),
    (0x03f1, "NotesAtom"),
    (0x03f2, "EnvironmentContainer"),
    (0x03f3, "SlidePersistAtom"),
    (0x03f8, "MainMasterContainer"),
    (0x03f9, "SlideShowSlideInfoAtom"),
    (0x03fa, "SlideViewInfoContainer"),
    (0x03ff, "VbaInfoContainer"),
    (0x0401, "SlideShowDocInfoAtom"),
    (0x0407, "SlideViewInfoAtom"),
    (0x040c, "DrawingGroupContainer"),
    (0x0411, "SlideListWithTextContainer"),
    (0x0fa0, "TextCharsAtom"),
    (0x0fa1, "StyleTextPropAtom"),
    (0x0fa3, "TextHeaderAtom"),
    (0x0fa8, "TextBytesAtom"),
    (0x0fa9, "TextSpecialInfoAtom"),
    (0x0faa, "TextRulerAtom"),
    (0x0fb7, "FontEntityAtom"),
    (0x0fc1, "TextRulerAtom"),
    (0x0fd9, "HeadersFootersContainer"),
    (0x0fda, "HeadersFootersAtom"),
    (0x0ff0, "SlideListWithText"),
    (0x0ff5, "UserEditAtom"),
    (0x0ff6, "CurrentUserAtom"),
    (0x0ff7, "DateTimeMCAtom"),
    (0x0ff9, "ExObjListContainer"),
    (0x1388, "ProgTagsContainer"),
    (0x1772, "PersistDirectoryAtom"),
    (0xf000, "OfficeArtDggContainer"),
    (0xf002, "OfficeArtDgContainer"),
    (0xf003, "OfficeArtSpgrContainer"),
    (0xf004, "OfficeArtSpContainer"),
    (0xf008, "OfficeArtFDG"),
    (0xf00a, "OfficeArtFSP"),
    (0xf00b, "OfficeArtFOPT"),
];

/// PowerPoint records (also used for the `Current User` stream).
pub async fn ppt(cx: &Cx, span: Span) -> Result<()> {
    ppt_level(cx.clone(), (span, 0)).await
}

async fn ppt_level(cx: Cx, (span, depth): (Span, u32)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let ver_instance = cur.u16().await?;
        let kind = cur.u16().await?;
        let len = cur.u32().await?;
        let body = cur.span(len.into());
        cur.skip(len.into());
        let whole = cur.since(start);
        let container = ver_instance & 0x0f == 0x0f;
        let name =
            lookup(PPT, kind.into()).map_or_else(|| format!("Record {kind:#06x}"), str::to_owned);
        let mut node = Node::new(name).span(whole).value(Value::UInt {
            value: kind.into(),
            bits: 16,
            radix: Radix::Hex,
        });
        if body.len < u64::from(len) {
            node = node.diag(Diagnostic::truncated(whole, body.len.saturating_add(8)));
        }
        if container {
            node = node.summary(format!("container, {len} bytes"));
            node = if depth >= MAX_PPT_DEPTH {
                node.diag(Diagnostic::limit(format!(
                    "containers nested deeper than {MAX_PPT_DEPTH}"
                )))
            } else {
                node.lazy(
                    crate::expander!(self::ppt_level: (Span, u32)),
                    (body, depth.saturating_add(1)),
                )
            };
        } else {
            let text = match kind {
                0x0fa0 => Some(crate::text::utf16(
                    &cx.read_avail(body.sub(0, 4096)).await?,
                    LE,
                )),
                0x0fa8 => Some(crate::text::latin1(
                    &cx.read_avail(body.sub(0, 2048)).await?,
                )),
                _ => None,
            };
            node = match text {
                Some(t) => node.summary(format!("{t:?}")),
                None => node.summary(format!("atom, {len} bytes")),
            };
            node = node.lazy(record_fields, (whole, 8u64));
        }
        cx.progress_in(span, whole.offset);
        cx.push(node).await;
    }
    Ok(())
}
