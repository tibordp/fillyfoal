//! Embedded OpenType (`.eot`), Internet Explorer's web font container.
//!
//! A little-endian header with font metadata and four or more length-prefixed
//! UTF-16 names precedes the font data, which is a plain sfnt unless it is
//! MicroType Express compressed or XOR-obfuscated.

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::font::SFNT;
use crate::formats::{Format, Head, Input, Probe, embedded_as};
use crate::node::Node;
use crate::record;
use crate::value::{EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "eot",
    title: "Embedded OpenType font",
    extensions: &["eot"],
    mime: "application/vnd.ms-fontobject",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    u16_le(h.data, 34) == Some(0x504c)
        && matches!(
            u32_le(h.data, 8),
            Some(0x0001_0000 | 0x0002_0001 | 0x0002_0002)
        )
        && u32_le(h.data, 0).is_some_and(|n| u64::from(n) == h.len)
}

const FLAGS: FlagTable = &[
    flag(0x0000_0001, "TTEMBED_SUBSET"),
    flag(0x0000_0004, "TTEMBED_TTCOMPRESSED"),
    flag(0x1000_0000, "TTEMBED_XORENCRYPTDATA"),
];

/// Windows GDI character sets (`LOGFONT.lfCharSet`, `.FNT dfCharSet`).
pub const CHARSETS: EnumTable = &[
    (0, "ANSI"),
    (1, "DEFAULT"),
    (2, "SYMBOL"),
    (77, "MAC"),
    (128, "SHIFTJIS"),
    (129, "HANGUL"),
    (130, "JOHAB"),
    (134, "GB2312"),
    (136, "CHINESEBIG5"),
    (161, "GREEK"),
    (162, "TURKISH"),
    (163, "VIETNAMESE"),
    (177, "HEBREW"),
    (178, "ARABIC"),
    (186, "BALTIC"),
    (204, "RUSSIAN"),
    (222, "THAI"),
    (238, "EASTEUROPE"),
    (255, "OEM"),
];

record! {
    pub struct Header {
        eot_size: u32 "EOTSize",
        font_size: u32 "FontDataSize",
        version: u32 "Version" .hex(),
        flags: u32 "Flags" .flags(FLAGS),
        panose: bytes[10] "FontPANOSE",
        charset: u8 "Charset" .enumeration(CHARSETS),
        italic: u8 "Italic",
        weight: u32 "Weight",
        fs_type: u16 "fsType" .hex(),
        magic: u16 "MagicNumber" .hex(),
        unicode1: u32 "UnicodeRange1" .hex(),
        unicode2: u32 "UnicodeRange2" .hex(),
        unicode3: u32 "UnicodeRange3" .hex(),
        unicode4: u32 "UnicodeRange4" .hex(),
        codepage1: u32 "CodePageRange1" .hex(),
        codepage2: u32 "CodePageRange2" .hex(),
        checksum: u32 "CheckSumAdjustment" .hex(),
        _reserved: bytes[16] "Reserved",
        _padding: u16 "Padding1",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let (h, span) = cur.record::<Header>().await?;
    cx.emit(Header::node("Header", span, LE));
    let mut names = Vec::new();
    let labels: &[&'static str] = match h.version {
        0x0001_0000 => &["FamilyName", "StyleName", "VersionName", "FullName"],
        _ => &[
            "FamilyName",
            "StyleName",
            "VersionName",
            "FullName",
            "RootString",
        ],
    };
    for (i, label) in labels.iter().enumerate() {
        if i > 0 {
            cur.skip(2); // padding
        }
        let start = cur.pos();
        let len = cur.u16().await?;
        let bytes = cur.bytes(len.into()).await?;
        let text = crate::text::utf16(&bytes, LE);
        names.push(text.clone());
        cx.emit(
            Node::new(*label)
                .span(cur.since(start))
                .value(Value::Text(text)),
        );
    }
    if h.version == 0x0002_0002 {
        let start = cur.pos();
        cur.skip(4 + 4 + 2); // RootStringCheckSum, EUDCCodePage, Padding6
        let sig = cur.u16().await?;
        cur.skip(sig.into());
        cur.skip(4); // EUDCFlags
        let eudc = cur.u32().await?;
        cur.skip(eudc.into());
        cx.emit(Node::new("EUDC and signature").span(cur.since(start)));
    }
    let data = file.sub(cur.pos(), h.font_size.into());
    let full = names.get(3).cloned().unwrap_or_default();
    let mut summary = format!("Embedded OpenType, {full:?}");
    let node = if h.flags & 0x4 != 0 {
        summary.push_str(", MicroType Express compressed");
        Node::new("Font data")
            .span(data)
            .diag(Diagnostic::unsupported("MicroType Express compression"))
    } else if h.flags & 0x1000_0000 != 0 {
        summary.push_str(", XOR-obfuscated");
        Node::new("Font data")
            .span(data)
            .diag(Diagnostic::unsupported("XOR-obfuscated font data"))
    } else {
        embedded_as("Font data", input.nested(data), &SFNT)
    };
    cx.annotate(summary);
    cx.emit(node.summary(format!("{} bytes", h.font_size)));
    Ok(())
}
