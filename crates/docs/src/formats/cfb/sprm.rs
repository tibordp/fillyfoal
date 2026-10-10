//! Word single property modifiers ([MS-DOC] 2.6): the formatting
//! instructions of character, paragraph, section, table and picture
//! properties. A sprm is a 16-bit opcode whose top bits give the operand
//! size, followed by the operand.

use crate::bytes::{to_u64, u16_le};
use crate::formats::util::val::{hex, uint};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

pub const NAMES: EnumTable = &[
    // Character
    (0x0800, "sprmCFRMarkDel"),
    (0x0801, "sprmCFRMarkIns"),
    (0x0802, "sprmCFFldVanish"),
    (0x6a03, "sprmCPicLocation"),
    (0x4804, "sprmCIbstRMark"),
    (0x6805, "sprmCDttmRMark"),
    (0x0806, "sprmCFData"),
    (0x4807, "sprmCIdslRMark"),
    (0x6a09, "sprmCSymbol"),
    (0x080a, "sprmCFOle2"),
    (0x2a0c, "sprmCHighlight"),
    (0x080e, "sprmCFWebHidden"),
    (0x6815, "sprmCRsidProp"),
    (0x6816, "sprmCRsidText"),
    (0x6817, "sprmCRsidRMDel"),
    (0x0818, "sprmCFSpecVanish"),
    (0x4a30, "sprmCIstd"),
    (0xca31, "sprmCIstdPermute"),
    (0x2a33, "sprmCPlain"),
    (0x2a34, "sprmCKcd"),
    (0x0835, "sprmCFBold"),
    (0x0836, "sprmCFItalic"),
    (0x0837, "sprmCFStrike"),
    (0x0838, "sprmCFOutline"),
    (0x0839, "sprmCFShadow"),
    (0x083a, "sprmCFSmallCaps"),
    (0x083b, "sprmCFCaps"),
    (0x083c, "sprmCFVanish"),
    (0x2a3e, "sprmCKul"),
    (0x8840, "sprmCDxaSpace"),
    (0x2a42, "sprmCIco"),
    (0x4a43, "sprmCHps"),
    (0x4845, "sprmCHpsPos"),
    (0xca47, "sprmCMajority"),
    (0x2a48, "sprmCIss"),
    (0x484b, "sprmCHpsKern"),
    (0x484e, "sprmCHresi"),
    (0x4a4f, "sprmCRgFtc0"),
    (0x4a50, "sprmCRgFtc1"),
    (0x4a51, "sprmCRgFtc2"),
    (0x4852, "sprmCCharScale"),
    (0x2a53, "sprmCFDStrike"),
    (0x0854, "sprmCFImprint"),
    (0x0855, "sprmCFSpec"),
    (0x0856, "sprmCFObj"),
    (0xca57, "sprmCPropRMark90"),
    (0x0858, "sprmCFEmboss"),
    (0x2859, "sprmCSfxText"),
    (0x085a, "sprmCFBiDi"),
    (0x085c, "sprmCFBoldBi"),
    (0x085d, "sprmCFItalicBi"),
    (0x4a5e, "sprmCFtcBi"),
    (0x485f, "sprmCLidBi"),
    (0x4a60, "sprmCIcoBi"),
    (0x4a61, "sprmCHpsBi"),
    (0xca62, "sprmCDispFldRMark"),
    (0x4863, "sprmCIbstRMarkDel"),
    (0x6864, "sprmCDttmRMarkDel"),
    (0x6865, "sprmCBrc80"),
    (0x4866, "sprmCShd80"),
    (0x4867, "sprmCIdslRMarkDel"),
    (0x0868, "sprmCFUsePgsuSettings"),
    (0x486d, "sprmCRgLid0_80"),
    (0x486e, "sprmCRgLid1_80"),
    (0x286f, "sprmCIdctHint"),
    (0x6870, "sprmCCv"),
    (0xca71, "sprmCShd"),
    (0xca72, "sprmCBrc"),
    (0x4873, "sprmCRgLid0"),
    (0x4874, "sprmCRgLid1"),
    (0x0875, "sprmCFNoProof"),
    (0xca76, "sprmCFitText"),
    (0x6877, "sprmCCvUl"),
    (0xca78, "sprmCFELayout"),
    (0x2879, "sprmCLbcCRJ"),
    (0x0882, "sprmCFComplexScripts"),
    (0x2a83, "sprmCWall"),
    (0xca85, "sprmCCnf"),
    (0x2a86, "sprmCNeedFontFixup"),
    (0x6887, "sprmCPbiIBullet"),
    (0x4888, "sprmCPbiGrf"),
    (0xca89, "sprmCPropRMark"),
    (0x2a90, "sprmCFSdtVanish"),
    // Paragraph
    (0x4600, "sprmPIstd"),
    (0xc601, "sprmPIstdPermute"),
    (0x2602, "sprmPIncLvl"),
    (0x2403, "sprmPJc80"),
    (0x2405, "sprmPFKeep"),
    (0x2406, "sprmPFKeepFollow"),
    (0x2407, "sprmPFPageBreakBefore"),
    (0x260a, "sprmPIlvl"),
    (0x460b, "sprmPIlfo"),
    (0x240c, "sprmPFNoLineNumb"),
    (0xc60d, "sprmPChgTabsPapx"),
    (0x840e, "sprmPDxaRight80"),
    (0x840f, "sprmPDxaLeft80"),
    (0x4610, "sprmPNest80"),
    (0x8411, "sprmPDxaLeft180"),
    (0x6412, "sprmPDyaLine"),
    (0xa413, "sprmPDyaBefore"),
    (0xa414, "sprmPDyaAfter"),
    (0xc615, "sprmPChgTabs"),
    (0x2416, "sprmPFInTable"),
    (0x2417, "sprmPFTtp"),
    (0x8418, "sprmPDxaAbs"),
    (0x8419, "sprmPDyaAbs"),
    (0x841a, "sprmPDxaWidth"),
    (0x261b, "sprmPPc"),
    (0x2423, "sprmPWr"),
    (0x6424, "sprmPBrcTop80"),
    (0x6425, "sprmPBrcLeft80"),
    (0x6426, "sprmPBrcBottom80"),
    (0x6427, "sprmPBrcRight80"),
    (0x6428, "sprmPBrcBetween80"),
    (0x6629, "sprmPBrcBar80"),
    (0x242a, "sprmPFNoAutoHyph"),
    (0x442b, "sprmPWHeightAbs"),
    (0x442c, "sprmPDcs"),
    (0x442d, "sprmPShd80"),
    (0x842e, "sprmPDyaFromText"),
    (0x842f, "sprmPDxaFromText"),
    (0x2430, "sprmPFLocked"),
    (0x2431, "sprmPFWidowControl"),
    (0x2433, "sprmPFKinsoku"),
    (0x2434, "sprmPFWordWrap"),
    (0x2435, "sprmPFOverflowPunct"),
    (0x2436, "sprmPFTopLinePunct"),
    (0x2437, "sprmPFAutoSpaceDE"),
    (0x2438, "sprmPFAutoSpaceDN"),
    (0x4439, "sprmPWAlignFont"),
    (0x443a, "sprmPFrameTextFlow"),
    (0x2640, "sprmPOutLvl"),
    (0x2441, "sprmPFBiDi"),
    (0x2443, "sprmPFNumRMIns"),
    (0xc645, "sprmPNumRM"),
    (0x6646, "sprmPHugePapx"),
    (0x2447, "sprmPFUsePgsuSettings"),
    (0x2448, "sprmPFAdjustRight"),
    (0x6649, "sprmPItap"),
    (0x664a, "sprmPDtap"),
    (0x244b, "sprmPFInnerTableCell"),
    (0x244c, "sprmPFInnerTtp"),
    (0xc64d, "sprmPShd"),
    (0xc64e, "sprmPBrcTop"),
    (0xc64f, "sprmPBrcLeft"),
    (0xc650, "sprmPBrcBottom"),
    (0xc651, "sprmPBrcRight"),
    (0xc652, "sprmPBrcBetween"),
    (0xc653, "sprmPBrcBar"),
    (0x4455, "sprmPDxcRight"),
    (0x4456, "sprmPDxcLeft"),
    (0x4457, "sprmPDxcLeft1"),
    (0x4458, "sprmPDylBefore"),
    (0x4459, "sprmPDylAfter"),
    (0x245a, "sprmPFOpenTch"),
    (0x245b, "sprmPFDyaBeforeAuto"),
    (0x245c, "sprmPFDyaAfterAuto"),
    (0x845d, "sprmPDxaRight"),
    (0x845e, "sprmPDxaLeft"),
    (0x465f, "sprmPNest"),
    (0x8460, "sprmPDxaLeft1"),
    (0x2461, "sprmPJc"),
    (0x2462, "sprmPFNoAllowOverlap"),
    (0x2664, "sprmPWall"),
    (0x6465, "sprmPIpgp"),
    (0xc666, "sprmPCnf"),
    (0x6467, "sprmPRsid"),
    (0xc669, "sprmPIstdListPermute"),
    (0x646b, "sprmPTableProps"),
    (0xc66c, "sprmPTIstdInfo"),
    (0x246d, "sprmPFContextualSpacing"),
    (0xc66f, "sprmPPropRMark"),
    (0x2470, "sprmPFMirrorIndents"),
    (0x2471, "sprmPTtwo"),
    // Table
    (0x5400, "sprmTJc90"),
    (0x9601, "sprmTDxaLeft"),
    (0x9602, "sprmTDxaGapHalf"),
    (0x3403, "sprmTFCantSplit90"),
    (0x3404, "sprmTTableHeader"),
    (0xd605, "sprmTTableBorders80"),
    (0x9407, "sprmTDyaRowHeight"),
    (0xd608, "sprmTDefTable"),
    (0xd609, "sprmTDefTableShd80"),
    (0x740a, "sprmTTlp"),
    (0x560b, "sprmTFBiDi"),
    (0xd612, "sprmTDefTableShd"),
    (0xd613, "sprmTTableBorders"),
    (0xf614, "sprmTTableWidth"),
    (0x3615, "sprmTFAutofit"),
    (0xd616, "sprmTDefTableShd2nd"),
    (0xf617, "sprmTWidthBefore"),
    (0xf618, "sprmTWidthAfter"),
    (0xd620, "sprmTSetBrc80"),
    (0x7621, "sprmTInsert"),
    (0x5622, "sprmTDelete"),
    (0x7623, "sprmTDxaCol"),
    (0x5624, "sprmTMerge"),
    (0x5625, "sprmTSplit"),
    (0x7627, "sprmTTextFlow"),
    (0xd62b, "sprmTVertMerge"),
    (0xd62c, "sprmTVertAlign"),
    (0xd634, "sprmTCellPadding"),
    (0x548a, "sprmTJc"),
    // Section
    (0x3000, "sprmScnsPgn"),
    (0x3001, "sprmSiHeadingPgn"),
    (0xd202, "sprmSOlstAnm80"),
    (0xf203, "sprmSDxaColWidth"),
    (0xf204, "sprmSDxaColSpacing"),
    (0x3005, "sprmSFEvenlySpaced"),
    (0x3006, "sprmSFProtected"),
    (0x5007, "sprmSDmBinFirst"),
    (0x5008, "sprmSDmBinOther"),
    (0x3009, "sprmSBkc"),
    (0x300a, "sprmSFTitlePage"),
    (0x500b, "sprmSCcolumns"),
    (0x900c, "sprmSDxaColumns"),
    (0x300e, "sprmSNfcPgn"),
    (0x3011, "sprmSFPgnRestart"),
    (0x3012, "sprmSFEndnote"),
    (0x3013, "sprmSLnc"),
    (0x5015, "sprmSNLnnMod"),
    (0x9016, "sprmSDxaLnn"),
    (0xb017, "sprmSDyaHdrTop"),
    (0xb018, "sprmSDyaHdrBottom"),
    (0x3019, "sprmSLBetween"),
    (0x301a, "sprmSVjc"),
    (0x501b, "sprmSLnnMin"),
    (0x501c, "sprmSPgnStart97"),
    (0x301d, "sprmSBOrientation"),
    (0xb01f, "sprmSXaPage"),
    (0xb020, "sprmSYaPage"),
    (0xb021, "sprmSDxaLeft"),
    (0xb022, "sprmSDxaRight"),
    (0x9023, "sprmSDyaTop"),
    (0x9024, "sprmSDyaBottom"),
    (0xb025, "sprmSDzaGutter"),
    (0x5026, "sprmSDmPaperReq"),
    (0x3228, "sprmSFBiDi"),
    (0x322a, "sprmSFRTLGutter"),
    (0x702b, "sprmSBrcTop80"),
    (0x702c, "sprmSBrcLeft80"),
    (0x702d, "sprmSBrcBottom80"),
    (0x702e, "sprmSBrcRight80"),
    (0x522f, "sprmSPgbProp"),
    (0x7030, "sprmSDxtCharSpace"),
    (0x9031, "sprmSDyaLinePitch"),
    (0x5032, "sprmSClm"),
    (0x5033, "sprmSTextFlow"),
    (0xd234, "sprmSBrcTop"),
    (0xd235, "sprmSBrcLeft"),
    (0xd236, "sprmSBrcBottom"),
    (0xd237, "sprmSBrcRight"),
    (0x5239, "sprmSWall"),
    (0x703a, "sprmSRsid"),
    (0x303b, "sprmSFpc"),
    (0x303c, "sprmSRncFtn"),
    (0x303e, "sprmSRncEdn"),
    (0x503f, "sprmSNFtn"),
    (0x5040, "sprmSNfcFtnRef"),
    (0x5041, "sprmSNEdn"),
    (0x5042, "sprmSNfcEdnRef"),
    (0x7044, "sprmSPgnStart"),
    // Picture
    (0x6c02, "sprmPicBrcTop80"),
    (0x6c03, "sprmPicBrcLeft80"),
    (0x6c04, "sprmPicBrcBottom80"),
    (0x6c05, "sprmPicBrcRight80"),
    (0xce08, "sprmPicBrcTop"),
    (0xce09, "sprmPicBrcLeft"),
    (0xce0a, "sprmPicBrcBottom"),
    (0xce0b, "sprmPicBrcRight"),
];

const GROUPS: EnumTable = &[
    (1, "paragraph"),
    (2, "character"),
    (3, "picture"),
    (4, "section"),
    (5, "table"),
];

const JUSTIFICATION: EnumTable = &[
    (0, "left"),
    (1, "center"),
    (2, "right"),
    (3, "justify"),
    (4, "distribute"),
];

const UNDERLINE: EnumTable = &[
    (0, "none"),
    (1, "single"),
    (2, "words"),
    (3, "double"),
    (4, "dotted"),
    (6, "thick"),
    (7, "dash"),
    (9, "dot dash"),
    (10, "dot dot dash"),
    (11, "wave"),
];

const BREAK: EnumTable = &[
    (0, "continuous"),
    (1, "new column"),
    (2, "new page"),
    (3, "even page"),
    (4, "odd page"),
];

/// A sprm's name, or its group and number.
pub fn name(sprm: u16) -> String {
    match lookup(NAMES, sprm.into()) {
        Some(n) => n.to_owned(),
        None => {
            let group = lookup(GROUPS, ((sprm >> 10) & 7).into()).unwrap_or("unknown");
            format!("sprm {sprm:#06x} ({group})")
        }
    }
}

/// The operand size of a sprm whose operand starts at `data[at..]`, or
/// `None` if it does not fit.
pub fn operand_len(sprm: u16, data: &[u8], at: usize) -> Option<usize> {
    let len = match sprm >> 13 {
        0 | 1 => 1,
        2 | 4 | 5 => 2,
        3 => 4,
        7 => 3,
        _ => {
            if sprm == 0xd608 || sprm == 0xd606 {
                // sprmTDefTable: a 16-bit size counting itself less one.
                let cb = usize::from(u16_le(data, at)?);
                cb.saturating_add(1)
            } else if sprm == 0xc615 && data.get(at).copied() == Some(255) {
                // sprmPChgTabs with deletions carrying close tolerances.
                let del = usize::from(*data.get(at.checked_add(1)?)?);
                let add_at = at.checked_add(2)?.checked_add(del.checked_mul(4)?)?;
                let add = usize::from(*data.get(add_at)?);
                2usize
                    .checked_add(del.checked_mul(4)?)?
                    .checked_add(1)?
                    .checked_add(add.checked_mul(3)?)?
            } else {
                usize::from(*data.get(at)?).saturating_add(1)
            }
        }
    };
    Some(len)
}

/// One sprm: where it starts and its size with the opcode.
pub struct Sprm {
    pub at: usize,
    pub len: usize,
}

/// Splits a grpprl into sprms. Stops at the first one that does not fit.
pub fn split(data: &[u8]) -> (Vec<Sprm>, bool) {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos.saturating_add(2) <= data.len() {
        let Some(op) = u16_le(data, pos) else { break };
        let operand = pos.saturating_add(2);
        let Some(len) = operand_len(op, data, operand) else {
            return (out, false);
        };
        let end = operand.saturating_add(len);
        if end > data.len() {
            return (out, false);
        }
        out.push(Sprm {
            at: pos,
            len: len.saturating_add(2),
        });
        pos = end;
    }
    (out, pos == data.len())
}

/// The operand of a fixed-size sprm as a number.
fn operand(data: &[u8], at: usize, len: usize) -> Option<u64> {
    let raw = data.get(at..at.checked_add(len)?)?;
    let mut v = 0u64;
    for (i, b) in raw.iter().enumerate().take(4) {
        v |= u64::from(*b) << (i.saturating_mul(8) & 63);
    }
    Some(v)
}

/// Two-byte operands of spra 4 (lengths and offsets in twips) are signed.
fn signed(op: u16, v: u64) -> Option<i64> {
    (op >> 13 == 4).then(|| i64::from((v as u16).cast_signed()))
}

/// A short rendering of a sprm's operand, for summaries.
pub fn describe(op: u16, data: &[u8], s: &Sprm) -> String {
    let operand_at = s.at.saturating_add(2);
    let len = s.len.saturating_sub(2);
    let short = name(op);
    let short = short.strip_prefix("sprm").unwrap_or(&short).to_owned();
    if op >> 13 == 6 {
        return format!("{short} ({len} bytes)");
    }
    let Some(v) = operand(data, operand_at, len) else {
        return short;
    };
    let toggle = |v: u64| match v {
        0 => "off".to_owned(),
        1 => "on".to_owned(),
        0x80 => "as style".to_owned(),
        0x81 => "opposite of style".to_owned(),
        n => format!("{n:#x}"),
    };
    match op {
        0x0835..=0x083c | 0x0854 | 0x0858 | 0x085c | 0x085d | 0x0875 | 0x2a53 => {
            format!("{short}={}", toggle(v))
        }
        0x4a43 | 0x4a61 => format!("{short}={} pt", v as f64 / 2.0),
        0x2403 | 0x2461 => format!(
            "{short}={}",
            lookup(JUSTIFICATION, v).map_or_else(|| v.to_string(), str::to_owned)
        ),
        0x2a3e => format!(
            "{short}={}",
            lookup(UNDERLINE, v).map_or_else(|| v.to_string(), str::to_owned)
        ),
        0x3009 => format!(
            "{short}={}",
            lookup(BREAK, v).map_or_else(|| v.to_string(), str::to_owned)
        ),
        // LSPD: a line height in twips, or a multiple of 240 when flagged.
        0x6412 => {
            let dya = i64::from(((v & 0xffff) as u16).cast_signed());
            if v >> 16 != 0 {
                format!("{short}={:.2} lines", dya as f64 / 240.0)
            } else {
                format!("{short}={dya} twips")
            }
        }
        // COLORREF: red in the low byte.
        0x6870 | 0x6877 => format!(
            "{short}=#{:02x}{:02x}{:02x}",
            v & 0xff,
            (v >> 8) & 0xff,
            (v >> 16) & 0xff
        ),
        _ => match signed(op, v) {
            Some(n) => format!("{short}={n}"),
            None => format!("{short}={v}"),
        },
    }
}

/// Nodes for the sprms of a grpprl at `span` (whose bytes are `data`).
pub fn nodes(data: &[u8], span: Span) -> Vec<Node> {
    let (sprms, complete) = split(data);
    let mut out = Vec::with_capacity(sprms.len());
    let mut end = 0usize;
    for s in &sprms {
        let op = u16_le(data, s.at).unwrap_or(0);
        let len = s.len.saturating_sub(2);
        let operand_at = s.at.saturating_add(2);
        let mut node = Node::new(name(op))
            .span(span.sub(to_u64(s.at), to_u64(s.len)))
            .summary(describe(op, data, s));
        node = match operand(data, operand_at, len) {
            Some(v) if op >> 13 != 6 => node.value(match signed(op, v) {
                Some(n) => crate::value::Value::Int { value: n, bits: 16 },
                None if len >= 3 => hex(v, 32),
                None => uint(v, 16),
            }),
            _ => node.value(crate::value::Value::Bytes(
                data.get(operand_at..operand_at.saturating_add(len.min(64)))
                    .unwrap_or_default()
                    .to_vec(),
            )),
        };
        node = node.desc(sprm_desc(op));
        out.push(node);
        end = s.at.saturating_add(s.len);
    }
    if !complete && end.saturating_add(1) == data.len() {
        out.push(
            Node::new("Padding")
                .span(span.sub(to_u64(end), 1))
                .value(uint(data.get(end).copied().unwrap_or(0), 8)),
        );
    } else if !complete && end < data.len() {
        out.push(
            Node::new("Undecoded")
                .span(span.sub(to_u64(end), to_u64(data.len().saturating_sub(end))))
                .diag(crate::error::Diagnostic::malformed(
                    "a sprm runs past the end of its property list",
                )),
        );
    }
    out
}

fn sprm_desc(op: u16) -> String {
    let group = lookup(GROUPS, ((op >> 10) & 7).into()).unwrap_or("unknown");
    let size = match op >> 13 {
        0 | 1 => "1-byte",
        2 | 4 | 5 => "2-byte",
        3 => "4-byte",
        7 => "3-byte",
        _ => "variable-length",
    };
    format!(
        "Opcode {op:#06x}: {group} property {}, {size} operand{}",
        op & 0x1ff,
        if op & 0x200 != 0 {
            ", special handling"
        } else {
            ""
        }
    )
}

/// A one-line summary of a grpprl (up to a few sprms).
pub fn summary(data: &[u8]) -> String {
    let (sprms, _) = split(data);
    let mut parts: Vec<String> = sprms
        .iter()
        .take(6)
        .map(|s| describe(u16_le(data, s.at).unwrap_or(0), data, s))
        .collect();
    if sprms.len() > 6 {
        parts.push(format!("+{} more", sprms.len().saturating_sub(6)));
    }
    if parts.is_empty() {
        "no properties".to_owned()
    } else {
        parts.join(", ")
    }
}
