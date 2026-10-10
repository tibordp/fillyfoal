//! Less common PE structures: the Rich header, plain DOS executables, base
//! relocations and the certificate table.

use super::tables::{CERTIFICATE_REVISION, CERTIFICATE_TYPE};
use super::{Directory, LE, Pe, dos_header, overflow, padding_node};
use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, parse, struct_node};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

// ---------------------------------------------------------------------------
// Rich header

/// Product IDs of the "@comp.id" high word: Microsoft's internal tool
/// identifiers, in the order of the `prodid` enumeration recovered from
/// `msobj*.dll` (as listed by tools such as richprint).
const RICH_PRODUCTS: EnumTable = &[
    (0x0000, "Unknown (imports)"),
    (0x0001, "Import0"),
    (0x0002, "Linker510"),
    (0x0003, "Cvtomf510"),
    (0x0004, "Linker600"),
    (0x0005, "Cvtomf600"),
    (0x0006, "Cvtres500"),
    (0x0007, "Utc11_Basic"),
    (0x0008, "Utc11_C"),
    (0x0009, "Utc12_Basic"),
    (0x000a, "Utc12_C"),
    (0x000b, "Utc12_CPP"),
    (0x000c, "AliasObj60"),
    (0x000d, "VisualBasic60"),
    (0x000e, "Masm613"),
    (0x000f, "Masm710"),
    (0x0010, "Linker511"),
    (0x0011, "Cvtomf511"),
    (0x0012, "Masm614"),
    (0x0013, "Linker512"),
    (0x0014, "Cvtomf512"),
    (0x0015, "Utc12_C_Std"),
    (0x0016, "Utc12_CPP_Std"),
    (0x0017, "Utc12_C_Book"),
    (0x0018, "Utc12_CPP_Book"),
    (0x0019, "Implib700"),
    (0x001a, "Cvtomf700"),
    (0x001b, "Utc13_Basic"),
    (0x001c, "Utc13_C"),
    (0x001d, "Utc13_CPP"),
    (0x001e, "Linker610"),
    (0x001f, "Cvtomf610"),
    (0x0020, "Linker601"),
    (0x0021, "Cvtomf601"),
    (0x0022, "Utc12_1_Basic"),
    (0x0023, "Utc12_1_C"),
    (0x0024, "Utc12_1_CPP"),
    (0x0025, "Linker620"),
    (0x0026, "Cvtomf620"),
    (0x0027, "AliasObj70"),
    (0x0028, "Linker621"),
    (0x0029, "Cvtomf621"),
    (0x002a, "Masm615"),
    (0x002b, "Utc13_LTCG_C"),
    (0x002c, "Utc13_LTCG_CPP"),
    (0x002d, "Masm620"),
    (0x002e, "ILAsm100"),
    (0x002f, "Utc12_2_Basic"),
    (0x0030, "Utc12_2_C"),
    (0x0031, "Utc12_2_CPP"),
    (0x0032, "Utc12_2_C_Std"),
    (0x0033, "Utc12_2_CPP_Std"),
    (0x0034, "Utc12_2_C_Book"),
    (0x0035, "Utc12_2_CPP_Book"),
    (0x0036, "Implib622"),
    (0x0037, "Cvtomf622"),
    (0x0038, "Cvtres501"),
    (0x0039, "Utc13_C_Std"),
    (0x003a, "Utc13_CPP_Std"),
    (0x003b, "Cvtpgd1300"),
    (0x003c, "Linker622"),
    (0x003d, "Linker700"),
    (0x003e, "Export622"),
    (0x003f, "Export700"),
    (0x0040, "Masm700"),
    (0x0041, "Utc13_POGO_I_C"),
    (0x0042, "Utc13_POGO_I_CPP"),
    (0x0043, "Utc13_POGO_O_C"),
    (0x0044, "Utc13_POGO_O_CPP"),
    (0x0045, "Cvtres700"),
    (0x0046, "Cvtres710p"),
    (0x0047, "Linker710p"),
    (0x0048, "Cvtomf710p"),
    (0x0049, "Export710p"),
    (0x004a, "Implib710p"),
    (0x004b, "Masm710p"),
    (0x004c, "Utc1310p_C"),
    (0x004d, "Utc1310p_CPP"),
    (0x004e, "Utc1310p_C_Std"),
    (0x004f, "Utc1310p_CPP_Std"),
    (0x0050, "Utc1310p_LTCG_C"),
    (0x0051, "Utc1310p_LTCG_CPP"),
    (0x0052, "Utc1310p_POGO_I_C"),
    (0x0053, "Utc1310p_POGO_I_CPP"),
    (0x0054, "Utc1310p_POGO_O_C"),
    (0x0055, "Utc1310p_POGO_O_CPP"),
    (0x0056, "Linker624"),
    (0x0057, "Cvtomf624"),
    (0x0058, "Export624"),
    (0x0059, "Implib624"),
    (0x005a, "Linker710"),
    (0x005b, "Cvtomf710"),
    (0x005c, "Export710"),
    (0x005d, "Implib710"),
    (0x005e, "Cvtres710"),
    (0x005f, "Utc1310_C"),
    (0x0060, "Utc1310_CPP"),
    (0x0061, "Utc1310_C_Std"),
    (0x0062, "Utc1310_CPP_Std"),
    (0x0063, "Utc1310_LTCG_C"),
    (0x0064, "Utc1310_LTCG_CPP"),
    (0x0065, "Utc1310_POGO_I_C"),
    (0x0066, "Utc1310_POGO_I_CPP"),
    (0x0067, "Utc1310_POGO_O_C"),
    (0x0068, "Utc1310_POGO_O_CPP"),
    (0x0069, "AliasObj710"),
    (0x006a, "AliasObj710p"),
    (0x006b, "Cvtpgd1310"),
    (0x006c, "Cvtpgd1310p"),
    (0x006d, "Utc1400_C"),
    (0x006e, "Utc1400_CPP"),
    (0x006f, "Utc1400_C_Std"),
    (0x0070, "Utc1400_CPP_Std"),
    (0x0071, "Utc1400_LTCG_C"),
    (0x0072, "Utc1400_LTCG_CPP"),
    (0x0073, "Utc1400_POGO_I_C"),
    (0x0074, "Utc1400_POGO_I_CPP"),
    (0x0075, "Utc1400_POGO_O_C"),
    (0x0076, "Utc1400_POGO_O_CPP"),
    (0x0077, "Cvtpgd1400"),
    (0x0078, "Linker800"),
    (0x0079, "Cvtomf800"),
    (0x007a, "Export800"),
    (0x007b, "Implib800"),
    (0x007c, "Cvtres800"),
    (0x007d, "Masm800"),
    (0x007e, "AliasObj800"),
    (0x007f, "PhoenixPrerelease"),
    (0x0080, "Utc1400_CVTCIL_C"),
    (0x0081, "Utc1400_CVTCIL_CPP"),
    (0x0082, "Utc1400_LTCG_MSIL"),
    (0x0083, "Utc1500_C"),
    (0x0084, "Utc1500_CPP"),
    (0x0085, "Utc1500_C_Std"),
    (0x0086, "Utc1500_CPP_Std"),
    (0x0087, "Utc1500_CVTCIL_C"),
    (0x0088, "Utc1500_CVTCIL_CPP"),
    (0x0089, "Utc1500_LTCG_C"),
    (0x008a, "Utc1500_LTCG_CPP"),
    (0x008b, "Utc1500_LTCG_MSIL"),
    (0x008c, "Utc1500_POGO_I_C"),
    (0x008d, "Utc1500_POGO_I_CPP"),
    (0x008e, "Utc1500_POGO_O_C"),
    (0x008f, "Utc1500_POGO_O_CPP"),
    (0x0090, "Cvtpgd1500"),
    (0x0091, "Linker900"),
    (0x0092, "Export900"),
    (0x0093, "Implib900"),
    (0x0094, "Cvtres900"),
    (0x0095, "Masm900"),
    (0x0096, "AliasObj900"),
    (0x0097, "Resource"),
    (0x0098, "AliasObj1000"),
    (0x0099, "Cvtpgd1600"),
    (0x009a, "Cvtres1000"),
    (0x009b, "Export1000"),
    (0x009c, "Implib1000"),
    (0x009d, "Linker1000"),
    (0x009e, "Masm1000"),
    (0x009f, "Phx1600_C"),
    (0x00a0, "Phx1600_CPP"),
    (0x00a1, "Phx1600_CVTCIL_C"),
    (0x00a2, "Phx1600_CVTCIL_CPP"),
    (0x00a3, "Phx1600_LTCG_C"),
    (0x00a4, "Phx1600_LTCG_CPP"),
    (0x00a5, "Phx1600_LTCG_MSIL"),
    (0x00a6, "Phx1600_POGO_I_C"),
    (0x00a7, "Phx1600_POGO_I_CPP"),
    (0x00a8, "Phx1600_POGO_O_C"),
    (0x00a9, "Phx1600_POGO_O_CPP"),
    (0x00aa, "Utc1600_C"),
    (0x00ab, "Utc1600_CPP"),
    (0x00ac, "Utc1600_CVTCIL_C"),
    (0x00ad, "Utc1600_CVTCIL_CPP"),
    (0x00ae, "Utc1600_LTCG_C"),
    (0x00af, "Utc1600_LTCG_CPP"),
    (0x00b0, "Utc1600_LTCG_MSIL"),
    (0x00b1, "Utc1600_POGO_I_C"),
    (0x00b2, "Utc1600_POGO_I_CPP"),
    (0x00b3, "Utc1600_POGO_O_C"),
    (0x00b4, "Utc1600_POGO_O_CPP"),
    (0x00b5, "AliasObj1010"),
    (0x00b6, "Cvtpgd1610"),
    (0x00b7, "Cvtres1010"),
    (0x00b8, "Export1010"),
    (0x00b9, "Implib1010"),
    (0x00ba, "Linker1010"),
    (0x00bb, "Masm1010"),
    (0x00bc, "Utc1610_C"),
    (0x00bd, "Utc1610_CPP"),
    (0x00be, "Utc1610_CVTCIL_C"),
    (0x00bf, "Utc1610_CVTCIL_CPP"),
    (0x00c0, "Utc1610_LTCG_C"),
    (0x00c1, "Utc1610_LTCG_CPP"),
    (0x00c2, "Utc1610_LTCG_MSIL"),
    (0x00c3, "Utc1610_POGO_I_C"),
    (0x00c4, "Utc1610_POGO_I_CPP"),
    (0x00c5, "Utc1610_POGO_O_C"),
    (0x00c6, "Utc1610_POGO_O_CPP"),
    (0x00c7, "AliasObj1100"),
    (0x00c8, "Cvtpgd1700"),
    (0x00c9, "Cvtres1100"),
    (0x00ca, "Export1100"),
    (0x00cb, "Implib1100"),
    (0x00cc, "Linker1100"),
    (0x00cd, "Masm1100"),
    (0x00ce, "Utc1700_C"),
    (0x00cf, "Utc1700_CPP"),
    (0x00d0, "Utc1700_CVTCIL_C"),
    (0x00d1, "Utc1700_CVTCIL_CPP"),
    (0x00d2, "Utc1700_LTCG_C"),
    (0x00d3, "Utc1700_LTCG_CPP"),
    (0x00d4, "Utc1700_LTCG_MSIL"),
    (0x00d5, "Utc1700_POGO_I_C"),
    (0x00d6, "Utc1700_POGO_I_CPP"),
    (0x00d7, "Utc1700_POGO_O_C"),
    (0x00d8, "Utc1700_POGO_O_CPP"),
    (0x00d9, "AliasObj1200"),
    (0x00da, "Cvtpgd1800"),
    (0x00db, "Cvtres1200"),
    (0x00dc, "Export1200"),
    (0x00dd, "Implib1200"),
    (0x00de, "Linker1200"),
    (0x00df, "Masm1200"),
    (0x00e0, "Utc1800_C"),
    (0x00e1, "Utc1800_CPP"),
    (0x00e2, "Utc1800_CVTCIL_C"),
    (0x00e3, "Utc1800_CVTCIL_CPP"),
    (0x00e4, "Utc1800_LTCG_C"),
    (0x00e5, "Utc1800_LTCG_CPP"),
    (0x00e6, "Utc1800_LTCG_MSIL"),
    (0x00e7, "Utc1800_POGO_I_C"),
    (0x00e8, "Utc1800_POGO_I_CPP"),
    (0x00e9, "Utc1800_POGO_O_C"),
    (0x00ea, "Utc1800_POGO_O_CPP"),
    (0x00eb, "AliasObj1210"),
    (0x00ec, "Cvtpgd1810"),
    (0x00ed, "Cvtres1210"),
    (0x00ee, "Export1210"),
    (0x00ef, "Implib1210"),
    (0x00f0, "Linker1210"),
    (0x00f1, "Masm1210"),
    (0x00f2, "Utc1810_C"),
    (0x00f3, "Utc1810_CPP"),
    (0x00f4, "Utc1810_CVTCIL_C"),
    (0x00f5, "Utc1810_CVTCIL_CPP"),
    (0x00f6, "Utc1810_LTCG_C"),
    (0x00f7, "Utc1810_LTCG_CPP"),
    (0x00f8, "Utc1810_LTCG_MSIL"),
    (0x00f9, "Utc1810_POGO_I_C"),
    (0x00fa, "Utc1810_POGO_I_CPP"),
    (0x00fb, "Utc1810_POGO_O_C"),
    (0x00fc, "Utc1810_POGO_O_CPP"),
    (0x00fd, "AliasObj1400"),
    (0x00fe, "Cvtpgd1900"),
    (0x00ff, "Cvtres1400"),
    (0x0100, "Export1400"),
    (0x0101, "Implib1400"),
    (0x0102, "Linker1400"),
    (0x0103, "Masm1400"),
    (0x0104, "Utc1900_C"),
    (0x0105, "Utc1900_CPP"),
    (0x0106, "Utc1900_CVTCIL_C"),
    (0x0107, "Utc1900_CVTCIL_CPP"),
    (0x0108, "Utc1900_LTCG_C"),
    (0x0109, "Utc1900_LTCG_CPP"),
    (0x010a, "Utc1900_LTCG_MSIL"),
    (0x010b, "Utc1900_POGO_I_C"),
    (0x010c, "Utc1900_POGO_I_CPP"),
    (0x010d, "Utc1900_POGO_O_C"),
    (0x010e, "Utc1900_POGO_O_CPP"),
];

/// The Visual Studio release a 14.x toolset build number belongs to
/// (product IDs 0x00fd and later are shared by VS2015 to VS2022).
fn vs_release(product: u32, build: u32) -> Option<&'static str> {
    if product < 0x00fd {
        return None;
    }
    Some(match build {
        0..=24999 => "VS2015",
        25000..=27499 => "VS2017",
        27500..=30399 => "VS2019",
        _ => "VS2022",
    })
}

/// The Rich header found between the DOS stub and the PE header.
pub(super) struct Rich {
    pub node: Node,
    /// File offsets of "DanS" and of the end of the key after "Rich".
    pub start: u64,
    pub end: u64,
}

#[derive(Clone)]
struct RichState {
    span: Span,
    key: u32,
    computed: u32,
    entries: Vec<(u32, u32)>,
}

/// The Rich header checksum: the header's offset, plus every byte of the
/// DOS header and stub before it rotated left by its offset (skipping
/// `e_lfanew`), plus each `@comp.id` rotated left by its count.
fn rich_checksum(stub: &[u8], start: usize, entries: &[(u32, u32)]) -> u32 {
    let mut sum = u32::try_from(start).unwrap_or(0);
    for (i, &b) in stub.iter().take(start).enumerate() {
        if (0x3c..0x40).contains(&i) {
            continue;
        }
        let shift = u32::try_from(i % 32).unwrap_or(0);
        sum = sum.wrapping_add(u32::from(b).rotate_left(shift));
    }
    for &(comp, count) in entries {
        sum = sum.wrapping_add(comp.rotate_left(count % 32));
    }
    sum
}

/// Finds and decodes the Rich header between the DOS stub and `lfanew`.
pub(super) async fn rich_header(cx: &Cx, file: Span, lfanew: u64) -> Result<Option<Rich>> {
    if lfanew <= 0x80 || lfanew > 0x1000 {
        return Ok(None);
    }
    let stub = cx.read(file.sub(0, lfanew)).await?;
    let Some(rich) = stub.windows(4).rposition(|w| w == b"Rich") else {
        return Ok(None);
    };
    let key = u32_le(&stub, rich.saturating_add(4)).unwrap_or(0);
    // Scan back in 4-byte steps for "DanS" xor key.
    let mut start = None;
    let mut at = rich;
    while at >= 4 {
        at = at.saturating_sub(4);
        if u32_le(&stub, at).map(|v| v ^ key) == Some(0x536e_6144) {
            start = Some(at);
            break;
        }
    }
    let Some(start) = start else {
        return Ok(None);
    };
    let end = rich.saturating_add(8);
    let span = file.sub(to_u64(start), to_u64(end.saturating_sub(start)));
    let mut entries = Vec::new();
    // Entries start after "DanS" and three padding words.
    let mut e = start.saturating_add(16);
    while e.saturating_add(8) <= rich {
        let comp = u32_le(&stub, e).unwrap_or(0) ^ key;
        let count = u32_le(&stub, e.saturating_add(4)).unwrap_or(0) ^ key;
        entries.push((comp, count));
        e = e.saturating_add(8);
    }
    let computed = rich_checksum(&stub, start, &entries);
    let mut node = Node::new("Rich Header")
        .span(span)
        .summary(format!(
            "{} tools, key {key:#010x}{}",
            entries.len(),
            if computed == key { " (valid)" } else { "" }
        ))
        .desc("Undocumented record of the Microsoft tools that built the image, XOR-masked with a checksum");
    if computed != key {
        node = node.diag(Diagnostic::warning(format!(
            "checksum mismatch: computed {computed:#010x}"
        )));
    }
    Ok(Some(Rich {
        node: node.lazy(
            rich_entries,
            RichState {
                span,
                key,
                computed,
                entries,
            },
        ),
        start: to_u64(start),
        end: to_u64(end),
    }))
}

async fn rich_entries(cx: Cx, st: RichState) -> Result<()> {
    let hex = |v: u32| Value::UInt {
        value: v.into(),
        bits: 32,
        radix: Radix::Hex,
    };
    cx.emit(
        Node::new("Marker")
            .span(st.span.sub(0, 4))
            .value(Value::Text("DanS".to_owned()))
            .desc("\"DanS\" XOR the key"),
    );
    cx.emit(
        Node::new("Padding")
            .span(st.span.sub(4, 12))
            .value(Value::Bytes(vec![0; 12]))
            .desc("Three zero words XOR the key"),
    );
    for (i, &(comp, count)) in st.entries.iter().enumerate() {
        let product = comp >> 16;
        let build = comp & 0xffff;
        let name = lookup(RICH_PRODUCTS, product.into())
            .map_or_else(|| format!("product {product:#06x}"), str::to_owned);
        let release = vs_release(product, build)
            .map(|r| format!(" ({r})"))
            .unwrap_or_default();
        cx.push(
            Node::new(name)
                .span(st.span.sub(16u64.saturating_add(to_u64(i).saturating_mul(8)), 8))
                .value(hex(comp))
                .summary(format!(
                    "build {build}{release}, {count} object{}",
                    if count == 1 { "" } else { "s" }
                ))
                .desc("@comp.id (product << 16 | build) and the number of objects it produced, XOR the key"),
        )
        .await;
    }
    let at = 16u64.saturating_add(to_u64(st.entries.len()).saturating_mul(8));
    cx.emit(
        Node::new("Signature")
            .span(st.span.sub(at, 4))
            .value(Value::Text("Rich".to_owned())),
    );
    let mut key = Node::new("Key")
        .span(st.span.sub(at.saturating_add(4), 4))
        .value(hex(st.key))
        .desc("Checksum of the DOS header, stub and entries; also the XOR mask");
    key = if st.key == st.computed {
        key.summary("valid")
    } else {
        key.diag(Diagnostic::warning(format!(
            "checksum mismatch: computed {:#010x}",
            st.computed
        )))
    };
    cx.emit(key);
    Ok(())
}

// ---------------------------------------------------------------------------
// Plain MS-DOS executables (MZ without a PE/NE/LE/LX header)

fn dos_probe(h: &Head<'_>) -> bool {
    if !h.starts_with(b"MZ") && !h.starts_with(b"ZM") {
        return false;
    }
    // A PE/NE/LE/LX signature at e_lfanew means a newer executable format.
    let lfanew = u32_le(h.data, 0x3c).unwrap_or(0);
    let at = usize::try_from(lfanew).unwrap_or(usize::MAX);
    let newer = h.at(at, b"PE\0\0") || h.at(at, b"NE") || h.at(at, b"LE") || h.at(at, b"LX");
    if newer {
        return false;
    }
    // If e_lfanew points beyond what the probe can see, it may still be a
    // PE with a huge stub; only claim it when it cannot be a valid offset.
    at.saturating_add(4) <= h.data.len() || u64::from(lfanew) >= h.len
}

declare_format!(pub DOS_EXE = "dos-exe", "MS-DOS executable", ["exe", "com"], "application/x-dosexec",
    Probe::Custom(dos_probe), dos_exe);

/// The fixed part of the MZ header (28 bytes), for executables without the
/// extended 64-byte header.
fn mz_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("e_magic", 2).desc("\"MZ\" (or \"ZM\")").emit()?;
    f.u16("e_cblp")
        .desc("Bytes used on the last 512-byte page (0: all)")
        .check(|&v| (v > 511).then(|| Diagnostic::warning("more than 511 bytes on the last page")))
        .emit()?;
    f.u16("e_cp").desc("512-byte pages in the image").emit()?;
    f.u16("e_crlc").desc("Relocation entries").emit()?;
    f.u16("e_cparhdr")
        .desc("Size of the header in 16-byte paragraphs")
        .emit()?;
    f.u16("e_minalloc")
        .desc("Extra paragraphs the program needs beyond the image (BSS, stack)")
        .emit()?;
    f.u16("e_maxalloc")
        .desc("Extra paragraphs the program would like (0xffff: all memory)")
        .emit()?;
    f.u16("e_ss")
        .hex()
        .desc("Initial SS, relative to the load segment")
        .emit()?;
    f.u16("e_sp").hex().desc("Initial SP").emit()?;
    f.u16("e_csum").hex().desc("Checksum (rarely set)").emit()?;
    f.u16("e_ip").hex().desc("Initial IP").emit()?;
    f.u16("e_cs")
        .hex()
        .desc("Initial CS, relative to the load segment")
        .emit()?;
    f.u16("e_lfarlc")
        .hex()
        .desc("File offset of the relocation table")
        .emit()?;
    f.u16("e_ovno")
        .desc("Overlay number (0: main program)")
        .emit()?;
    Ok(())
}

/// Signatures that packers and compilers leave after the fixed header.
fn header_tag(data: &[u8]) -> Option<&'static str> {
    let at = |o: usize, s: &[u8]| data.get(o..o.saturating_add(s.len())) == Some(s);
    if at(0x1c, b"LZ91") || at(0x1c, b"LZ09") {
        Some("LZEXE-compressed")
    } else if data.windows(6).any(|w| w == b"PKLITE") {
        Some("PKLITE-compressed")
    } else if at(0x1c, b"RJSX") {
        Some("ARJ self-extractor")
    } else if data.windows(5).any(|w| w == b"LHarc" || w == b"LHA's") {
        Some("LHA self-extractor")
    } else {
        None
    }
}

async fn dos_exe(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header = cx.read_avail(file.sub(0, 0x200)).await?;
    let pages = u16_le(&header, 4).unwrap_or(0);
    let last = u16_le(&header, 2).unwrap_or(0);
    let relocations = u16_le(&header, 6).unwrap_or(0);
    let paragraphs = u16_le(&header, 8).unwrap_or(0);
    let min_alloc = u16_le(&header, 0x0a).unwrap_or(0);
    let ss = u16_le(&header, 0x0e).unwrap_or(0);
    let sp = u16_le(&header, 0x10).unwrap_or(0);
    let ip = u16_le(&header, 0x14).unwrap_or(0);
    let cs = u16_le(&header, 0x16).unwrap_or(0);
    let table = u16_le(&header, 0x18).unwrap_or(0);
    let module_start = u64::from(paragraphs).saturating_mul(16);
    // The extended 64-byte header only exists in "new" executables, whose
    // relocation table starts at 0x40.
    let header_len = if table >= 0x40 { 64u64 } else { 0x1c };
    if header_len == 64 {
        cx.emit(struct_node(
            "DOS Header",
            file.sub(0, 64),
            LE,
            file,
            dos_header,
        ));
    } else {
        cx.emit(struct_node(
            "DOS Header",
            file.sub(0, 0x1c),
            LE,
            (),
            mz_header,
        ));
    }
    let reloc_span = file.sub(table.into(), u64::from(relocations).saturating_mul(4));
    // Bytes of the header that are neither fields nor relocations.
    let mut filled = header_len;
    if relocations > 0 {
        if u64::from(table) > filled && u64::from(table) <= module_start {
            cx.emit(extra_header(
                file.sub(filled, u64::from(table).saturating_sub(filled)),
                &header,
                filled,
            ));
        }
        cx.emit(
            Node::new("Relocation Table")
                .span(reloc_span)
                .summary(format!("{relocations} entries"))
                .desc("Segment:offset of each word the loader adds the load segment to")
                .lazy(dos_relocations, (reloc_span, module_start)),
        );
        filled = filled.max(reloc_span.end().saturating_sub(file.offset));
    }
    if module_start > filled {
        cx.emit(extra_header(
            file.sub(filled, module_start.saturating_sub(filled)),
            &header,
            filled,
        ));
    }
    let image_end = u64::from(pages)
        .saturating_mul(512)
        .saturating_sub(if last == 0 {
            0
        } else {
            512u64.saturating_sub(last.into())
        });
    let module_len = image_end.saturating_sub(module_start);
    let module = file.sub(module_start, module_len);
    let entry = u64::from(cs).saturating_mul(16).saturating_add(ip.into());
    let mut node = Node::new("Load Module")
        .span(module)
        .summary(format!("{module_len} bytes of code and data"))
        .desc("Copied to memory at the load segment; execution starts at CS:IP");
    if entry < module_len {
        node = node.target(module.sub(entry, 1));
    }
    if module.len < module_len {
        node = node.diag(Diagnostic::truncated(
            Span::new(module.source, module.offset, module_len),
            module.len,
        ));
    }
    cx.emit(node);
    if image_end < file.len && image_end > 0 {
        cx.emit(
            embedded("Overlay", input.nested(file.tail(image_end)))
                .summary(format!("{} bytes", file.len.saturating_sub(image_end)))
                .desc("Data after the load module (overlays, self-extractor payloads, debug info)"),
        );
    }
    let mut summary = format!(
        "MS-DOS executable, {module_len} bytes of code and data, entry {cs:04x}:{ip:04x}, stack {ss:04x}:{sp:04x}, {} KiB minimum extra memory",
        u64::from(min_alloc).saturating_mul(16) / 1024
    );
    if relocations > 0 {
        summary.push_str(&format!(", {relocations} relocations"));
    }
    if let Some(tag) = header_tag(&header) {
        summary.push_str(&format!(", {tag}"));
    }
    cx.annotate(summary);
    Ok(())
}

fn extra_header(span: Span, header: &[u8], at: u64) -> Node {
    let tag = header_tag(header);
    let start = crate::bytes::to_usize(at);
    let end = start.saturating_add(crate::bytes::to_usize(span.len));
    let zero = header
        .get(start..end.min(header.len()))
        .is_some_and(|b| b.iter().all(|&c| c == 0));
    let node = Node::new(if zero {
        "Header Padding"
    } else {
        "Header Data"
    })
    .span(span);
    match tag {
        Some(t) if !zero => node.summary(t),
        _ if zero => node.summary(format!("{} zero bytes", span.len)),
        _ => {
            node.desc("Bytes in the header not described by the MZ format (linker or packer data)")
        }
    }
}

async fn dos_relocations(cx: Cx, (span, module_start): (Span, u64)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let count = data.len() / 4;
    cx.set_count(Count::Exact(to_u64(count)));
    for i in 0..count {
        let at = i.saturating_mul(4);
        let offset = u16_le(&data, at).unwrap_or(0);
        let segment = u16_le(&data, at.saturating_add(2)).unwrap_or(0);
        let linear = u64::from(segment)
            .saturating_mul(16)
            .saturating_add(offset.into());
        cx.push(
            Node::new(format!("#{i}"))
                .span(span.sub(to_u64(at), 4))
                .value(Value::Text(format!("{segment:04x}:{offset:04x}")))
                .summary(format!(
                    "word at load module offset {linear:#x} (file offset {:#x})",
                    module_start.saturating_add(linear)
                )),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Base relocations

const RELOCATION_TYPES: EnumTable = &[
    (0, "ABSOLUTE"),
    (1, "HIGH"),
    (2, "LOW"),
    (3, "HIGHLOW"),
    (4, "HIGHADJ"),
    (5, "MACHINE_SPECIFIC_5"),
    (6, "RESERVED"),
    (7, "MACHINE_SPECIFIC_7"),
    (8, "MACHINE_SPECIFIC_8"),
    (9, "MACHINE_SPECIFIC_9"),
    (10, "DIR64"),
];

/// The name of relocation type `kind` on `machine`.
fn relocation_type(machine: u16, kind: u16) -> Option<&'static str> {
    let name = match (kind, machine) {
        (5, 0x1c0 | 0x1c2 | 0x1c4) => "ARM_MOV32",
        (5, 0x5032 | 0x5064 | 0x5128) => "RISCV_HIGH20",
        (5, _)
            if matches!(
                machine,
                0x162 | 0x166 | 0x168 | 0x169 | 0x266 | 0x366 | 0x466
            ) =>
        {
            "MIPS_JMPADDR"
        }
        (7, 0x1c0 | 0x1c2 | 0x1c4) => "THUMB_MOV32",
        (7, 0x5032 | 0x5064 | 0x5128) => "RISCV_LOW12I",
        (8, 0x5032 | 0x5064 | 0x5128) => "RISCV_LOW12S",
        (8, 0x6232 | 0x6264) => "LOONGARCH_MARK_LA",
        (9, _) if machine == 0xebc => "IA64_IMM64",
        (9, _) => "MIPS_JMPADDR16",
        _ => return lookup(RELOCATION_TYPES, kind.into()),
    };
    Some(name)
}

pub(super) async fn base_relocations(cx: Cx, (pe, dir): (Pe, Directory)) -> Result<()> {
    let mut pos = 0u64;
    let mut blocks = 0u32;
    let mut entries = 0u64;
    while pos.saturating_add(8) <= dir.span.len {
        let head = cx.read(dir.span.sub(pos, 8)).await?;
        let page = u32_le(&head, 0).unwrap_or(0);
        let size = u64::from(u32_le(&head, 4).unwrap_or(0));
        if size < 8 {
            cx.diag(
                Diagnostic::malformed("relocation block smaller than its header")
                    .at(dir.span.sub(pos, 8)),
            );
            break;
        }
        let span = dir.span.sub(pos, size);
        blocks = blocks.saturating_add(1);
        let n = size.saturating_sub(8) / 2;
        entries = entries.saturating_add(n);
        cx.progress_in(dir.span, span.end());
        cx.push(
            Node::new(format!("Page {page:#x}"))
                .span(span)
                .summary(format!("{n} entries, {}", pe.describe_rva(page)))
                .lazy(relocation_block, (pe.clone(), span, page)),
        )
        .await;
        pos = pos.saturating_add(size);
    }
    cx.annotate(format!("{blocks} pages, {entries} entries"));
    Ok(())
}

async fn relocation_block(cx: Cx, (pe, span, page): (Pe, Span, u32)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let block = cx.block(span.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    super::rva_field(f.u32("VirtualAddress"), &pe)
        .desc("RVA of the 4 KiB page the entries apply to")
        .emit()?;
    f.u32("SizeOfBlock")
        .hex()
        .desc("Including this header")
        .emit()?;
    let count = data.len().saturating_sub(8) / 2;
    for i in 0..count {
        let at = 8usize.saturating_add(i.saturating_mul(2));
        let entry = u16_le(&data, at).unwrap_or(0);
        let kind = entry >> 12;
        let rva = page.saturating_add(u32::from(entry & 0x0fff));
        let width = match kind {
            10 => 8,
            0 => 0,
            1 | 2 | 4 => 2,
            _ => 4,
        };
        let mut node = Node::new(if kind == 0 {
            "Padding".to_owned()
        } else {
            format!("{rva:#x}")
        })
        .span(span.sub(to_u64(at), 2))
        .value(Value::Enum {
            raw: kind.into(),
            bits: 4,
            name: relocation_type(pe.machine, kind),
        });
        if kind == 0 {
            node = node.desc("ABSOLUTE entries pad the block to a multiple of 4 bytes");
        } else if let Ok(target) = pe.rva_span(rva, width) {
            node = node
                .target(target)
                .summary(format!("offset {:#x}", entry & 0xfff));
        }
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Certificates

#[derive(Clone, Copy, Debug)]
struct WinCertificate {
    length: u32,
    kind: u16,
}

fn win_certificate(f: &mut Fields<'_>, _: &()) -> Result<WinCertificate> {
    let length = f
        .u32("dwLength")
        .hex()
        .desc("Length including this header")
        .emit()?;
    f.u16("wRevision")
        .enumeration(CERTIFICATE_REVISION)
        .emit()?;
    let kind = f
        .u16("wCertificateType")
        .enumeration(CERTIFICATE_TYPE)
        .emit()?;
    Ok(WinCertificate { length, kind })
}

pub(super) async fn certificates(cx: Cx, (input, dir): (Input, Directory)) -> Result<()> {
    let table = dir.span;
    let mut offset = 0u64;
    let mut count = 0u32;
    while offset < table.len {
        let header = table.sub(offset, 8);
        let cert = parse(&cx, header, LE, &(), win_certificate).await?;
        if cert.length < 8 {
            return Err(Diagnostic::malformed(format!(
                "certificate length {:#x} is shorter than its header",
                cert.length
            ))
            .at(header));
        }
        let span = table.sub(offset, cert.length.into());
        let label = match cert.kind {
            2 => "Authenticode signature",
            1 => "X.509 certificate",
            _ => lookup(CERTIFICATE_TYPE, cert.kind.into()).unwrap_or("Certificate"),
        };
        cx.push(
            Node::new(label)
                .span(span)
                .summary(format!("{:#x} bytes", cert.length))
                .lazy(certificate, (input, span, cert.kind)),
        )
        .await;
        count = count.saturating_add(1);
        let step = u64::from(cert.length)
            .checked_next_multiple_of(8)
            .ok_or_else(overflow)?;
        if step > u64::from(cert.length) && offset.saturating_add(step) <= table.len {
            cx.push(padding_node(
                "Padding",
                table.sub(
                    offset.saturating_add(cert.length.into()),
                    step.saturating_sub(cert.length.into()),
                ),
                "Certificates are aligned to 8 bytes",
            ))
            .await;
        }
        offset = offset.saturating_add(step);
    }
    cx.annotate(format!(
        "{count} certificate{}",
        if count == 1 { "" } else { "s" }
    ));
    Ok(())
}

async fn certificate(cx: Cx, (input, span, kind): (Input, Span, u16)) -> Result<()> {
    let block = cx.block(span.sub(0, 8)).await?;
    win_certificate(&mut Fields::emitting(&cx, &block, LE), &())?;
    let body = span.tail(8);
    cx.emit(match kind {
        2 => crate::formats::embedded_as(
            "bCertificate",
            input.nested(body),
            &crate::formats::asn1::PKCS7,
        )
        .desc("PKCS #7 SignedData over the image's Authenticode hash (SpcIndirectDataContent)"),
        _ => Node::new("bCertificate")
            .span(body)
            .desc("Certificate data of a type other than PKCS #7 SignedData"),
    });
    Ok(())
}
