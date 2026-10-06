//! Firmware and boot containers: Android sparse images, Android boot images
//! and U-Boot legacy images (`uImage`).
//!
//! All three are a fixed header in front of payloads that are themselves
//! files (kernels, gzip/lz4 ramdisks, filesystem images), which are
//! dissected as embedded content.

use std::sync::Arc;

use crate::bytes::{to_u64, u32_be};
use crate::codec::crc32;
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::arcutil::{count, emit_nodes, human_size, uint};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

pub static ANDROID_SPARSE: Format = Format {
    name: "android-sparse",
    title: "Android sparse image",
    extensions: &["img", "simg"],
    mime: "application/octet-stream",
    probe: Probe::Magic(&[(0, b"\x3a\xff\x26\xed\x01\x00")]),
    dissect: crate::expander!(dissect_sparse: Input),
};

pub static ANDROID_BOOT: Format = Format {
    name: "android-boot",
    title: "Android boot image",
    extensions: &["img"],
    mime: "application/octet-stream",
    probe: Probe::Magic(&[(0, b"ANDROID!")]),
    dissect: crate::expander!(dissect_boot: Input),
};

pub static UIMAGE: Format = Format {
    name: "uimage",
    title: "U-Boot legacy image",
    extensions: &["uimg", "ub", "itb"],
    mime: "application/octet-stream",
    probe: Probe::Magic(&[(0, b"\x27\x05\x19\x56")]),
    dissect: crate::expander!(dissect_uimage: Input),
};

// ---------------------------------------------------------------------------
// Android sparse images

const CHUNK_TYPE: EnumTable = &[
    (0xcac1, "raw"),
    (0xcac2, "fill"),
    (0xcac3, "don't care"),
    (0xcac4, "CRC32"),
];

record! {
    pub struct SparseHeader {
        magic: u32 "Magic" .hex(),
        major: u16 "Major version",
        minor: u16 "Minor version",
        header_size: u16 "File header size",
        chunk_header_size: u16 "Chunk header size",
        block_size: u32 "Block size" .with(|&b, n| n.summary(human_size(b.into()))),
        blocks: u32 "Total blocks",
        chunks: u32 "Total chunks",
        checksum: u32 "Image checksum" .hex(),
    }
}

pub async fn dissect_sparse(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = crate::fields::parse(
        &cx,
        file.sub(0, SparseHeader::SIZE),
        LE,
        &(),
        SparseHeader::layout,
    )
    .await?;
    let header_span = file.sub(0, h.header_size.into());
    cx.emit(SparseHeader::node("Header", header_span, LE));
    let image = u64::from(h.blocks).saturating_mul(h.block_size.into());
    cx.annotate(format!(
        "Android sparse image, {} expanded, {}",
        human_size(image),
        count(h.chunks.into(), "chunk", "chunks")
    ));
    cx.emit(
        Node::new("Chunks")
            .span(file.tail(h.header_size.into()))
            .summary(count(h.chunks.into(), "chunk", "chunks"))
            .lazy(
                sparse_chunks,
                (
                    input,
                    h.header_size,
                    h.chunk_header_size,
                    h.chunks,
                    h.block_size,
                ),
            ),
    );
    Ok(())
}

async fn sparse_chunks(
    cx: Cx,
    (input, at, chunk_header, chunks, block_size): (Input, u16, u16, u32, u32),
) -> Result<()> {
    cx.set_count(Count::Exact(chunks.into()));
    let mut cur = Cursor::new(&cx, input.span, LE);
    cur.seek(at.into());
    let mut block = 0u64;
    for i in 0..chunks {
        if cur.at_end() {
            cx.diag(Diagnostic::truncated(cur.span(12), 0));
            break;
        }
        let start = cur.pos();
        let kind = cur.u16().await?;
        cur.skip(2);
        let blocks = cur.u32().await?;
        let total = cur.u32().await?;
        if u64::from(total) < u64::from(chunk_header) {
            return Err(Diagnostic::malformed("chunk smaller than its header").at(cur.since(start)));
        }
        cur.seek(start.saturating_add(total.into()));
        let span = cur.since(start);
        let data = span.tail(chunk_header.into());
        let name = crate::value::lookup(CHUNK_TYPE, kind.into()).unwrap_or("unknown");
        let bytes = u64::from(blocks).saturating_mul(block_size.into());
        let mut fields = vec![
            Node::new("Chunk type")
                .span(span.sub(0, 2))
                .value(Value::Enum {
                    raw: kind.into(),
                    bits: 16,
                    name: crate::value::lookup(CHUNK_TYPE, kind.into()),
                }),
            Node::new("Reserved").span(span.sub(2, 2)),
            Node::new("Output blocks")
                .span(span.sub(4, 4))
                .value(uint(blocks.into())),
            Node::new("Total size")
                .span(span.sub(8, 4))
                .value(uint(total.into())),
        ];
        match kind {
            0xcac1 => fields.push(embedded("Data", input.nested(data))),
            0xcac2 => fields.push(Node::new("Fill value").span(data)),
            0xcac4 => fields.push(Node::new("CRC32").span(data)),
            _ => {}
        }
        cx.push(
            Node::new(format!("Chunk {i}"))
                .span(span)
                .summary(format!(
                    "{name}, blocks {block}..+{blocks} ({})",
                    human_size(bytes)
                ))
                .lazy(emit_nodes, Arc::new(fields)),
        )
        .await;
        block = block.saturating_add(blocks.into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Android boot images

/// Header fields that locate the payloads.
#[derive(Clone, Copy, Debug, Default)]
struct Boot {
    version: u32,
    page: u64,
    kernel: u64,
    ramdisk: u64,
    second: u64,
    dtbo: u64,
    dtb: u64,
    signature: u64,
}

fn os_version(v: u32) -> String {
    let a = v >> 25;
    let b = (v >> 18) & 0x7f;
    let c = (v >> 11) & 0x7f;
    let y = ((v >> 4) & 0x7f).saturating_add(2000);
    let m = v & 0xf;
    format!("Android {a}.{b}.{c}, patch level {y}-{m:02}")
}

fn boot_layout(f: &mut Fields<'_>, _: &()) -> Result<Boot> {
    f.ascii("Magic", 8).emit()?;
    let version = u32::from_le_bytes(
        f.block()
            .data
            .get(40..44)
            .and_then(|b| b.try_into().ok())
            .unwrap_or([0; 4]),
    );
    let mut b = Boot {
        version,
        ..Boot::default()
    };
    let size = |f: &mut Fields<'_>, name: &'static str| -> Result<u64> {
        Ok(f.u32(name)
            .with(|&s, n| n.summary(human_size(s.into())))
            .emit()?
            .into())
    };
    if version >= 3 {
        b.page = 4096;
        b.kernel = size(f, "Kernel size")?;
        b.ramdisk = size(f, "Ramdisk size")?;
        f.u32("OS version")
            .with(|&v, n| n.summary(os_version(v)))
            .emit()?;
        f.u32("Header size").emit()?;
        f.bytes("Reserved", 16).emit()?;
        f.u32("Header version").emit()?;
        f.ascii("Command line", 1536).emit()?;
        if version >= 4 {
            b.signature = size(f, "Boot signature size")?;
        }
        return Ok(b);
    }
    b.kernel = size(f, "Kernel size")?;
    f.u32("Kernel load address").hex().emit()?;
    b.ramdisk = size(f, "Ramdisk size")?;
    f.u32("Ramdisk load address").hex().emit()?;
    b.second = size(f, "Second stage size")?;
    f.u32("Second stage load address").hex().emit()?;
    f.u32("Tags address").hex().emit()?;
    b.page = f.u32("Page size").emit()?.into();
    f.u32("Header version").emit()?;
    f.u32("OS version")
        .with(|&v, n| n.summary(os_version(v)))
        .emit()?;
    f.ascii("Product name", 16).emit()?;
    f.ascii("Command line", 512).emit()?;
    f.bytes("ID (digest)", 32).emit()?;
    f.ascii("Extra command line", 1024).emit()?;
    if version >= 1 {
        b.dtbo = size(f, "Recovery DTBO size")?;
        f.u64("Recovery DTBO offset").hex().emit()?;
        f.u32("Header size").emit()?;
    }
    if version >= 2 {
        b.dtb = size(f, "DTB size")?;
        f.u64("DTB load address").hex().emit()?;
    }
    Ok(b)
}

pub async fn dissect_boot(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = file.sub(0, 1660);
    let b = crate::fields::parse(&cx, head, LE, &(), boot_layout).await?;
    let page = b.page;
    if page == 0 || !page.is_power_of_two() || page > 1 << 20 {
        return Err(Diagnostic::malformed(format!("page size {page}")).at(file.sub(36, 4)));
    }
    let header_len = if b.version >= 3 { 4096 } else { page };
    cx.emit(
        struct_node(
            "Header",
            file.sub(0, header_len.min(1660)),
            LE,
            (),
            boot_layout,
        )
        .summary(format!("version {}", b.version)),
    );
    let mut at = header_len.div_ceil(page).saturating_mul(page);
    let mut parts = Vec::new();
    for (name, size) in [
        ("Kernel", b.kernel),
        ("Ramdisk", b.ramdisk),
        ("Second stage", b.second),
        ("Recovery DTBO", b.dtbo),
        ("DTB", b.dtb),
        ("Boot signature", b.signature),
    ] {
        if size == 0 {
            continue;
        }
        let span = file.sub(at, size);
        let node = embedded(name, input.nested(span)).summary(human_size(size));
        cx.emit(crate::formats::arcutil::check_len(node, span, size));
        parts.push(format!("{} {}", name.to_lowercase(), human_size(size)));
        at = at.saturating_add(size.div_ceil(page).saturating_mul(page));
    }
    cx.annotate(format!(
        "Android boot image v{}, {}",
        b.version,
        parts.join(", ")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// U-Boot legacy images

const UIMAGE_OS: EnumTable = &[
    (0, "invalid"),
    (1, "OpenBSD"),
    (2, "NetBSD"),
    (3, "FreeBSD"),
    (4, "4.4BSD"),
    (5, "Linux"),
    (6, "SVR4"),
    (7, "Esix"),
    (8, "Solaris"),
    (9, "Irix"),
    (10, "SCO"),
    (11, "Dell"),
    (12, "NCR"),
    (13, "LynxOS"),
    (14, "VxWorks"),
    (15, "pSOS"),
    (16, "QNX"),
    (17, "U-Boot firmware"),
    (18, "RTEMS"),
    (19, "ARTOS"),
    (20, "Unity OS"),
    (21, "INTEGRITY"),
    (22, "OSE"),
    (23, "Plan 9"),
    (24, "OpenRTOS"),
    (25, "ARM Trusted Firmware"),
    (26, "Trusted Execution Environment"),
    (27, "OpenSBI"),
    (28, "EFI firmware"),
];

const UIMAGE_ARCH: EnumTable = &[
    (0, "invalid"),
    (1, "Alpha"),
    (2, "ARM"),
    (3, "x86"),
    (4, "IA-64"),
    (5, "MIPS"),
    (6, "MIPS64"),
    (7, "PowerPC"),
    (8, "IBM S390"),
    (9, "SuperH"),
    (10, "SPARC"),
    (11, "SPARC64"),
    (12, "M68K"),
    (13, "Nios-32"),
    (14, "MicroBlaze"),
    (15, "Nios-II"),
    (16, "Blackfin"),
    (17, "AVR32"),
    (18, "ST200"),
    (19, "Sandbox"),
    (20, "NDS32"),
    (21, "OpenRISC"),
    (22, "ARM64"),
    (23, "ARC"),
    (24, "x86-64"),
    (25, "Xtensa"),
    (26, "RISC-V"),
];

const UIMAGE_TYPE: EnumTable = &[
    (0, "invalid"),
    (1, "standalone program"),
    (2, "kernel"),
    (3, "ramdisk"),
    (4, "multi-file"),
    (5, "firmware"),
    (6, "script"),
    (7, "filesystem"),
    (8, "flattened device tree"),
    (9, "Kirkwood boot"),
    (10, "Freescale IMX boot"),
];

const UIMAGE_COMP: EnumTable = &[
    (0, "none"),
    (1, "gzip"),
    (2, "bzip2"),
    (3, "LZMA"),
    (4, "LZO"),
    (5, "LZ4"),
    (6, "zstd"),
];

record! {
    pub struct UImage {
        magic: u32 "Magic" .hex(),
        header_crc: u32 "Header CRC" .hex(),
        time: u32 "Creation time" .timestamp(),
        size: u32 "Data size" .with(|&s, n| n.summary(human_size(s.into()))),
        load: u32 "Load address" .hex(),
        entry: u32 "Entry point" .hex(),
        data_crc: u32 "Data CRC" .hex(),
        os: u8 "Operating system" .enumeration(UIMAGE_OS),
        arch: u8 "Architecture" .enumeration(UIMAGE_ARCH),
        kind: u8 "Image type" .enumeration(UIMAGE_TYPE),
        comp: u8 "Compression" .enumeration(UIMAGE_COMP),
        name: ascii[32] "Name",
    }
}

pub async fn dissect_uimage(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, UImage::SIZE);
    let h = crate::fields::parse(&cx, hspan, BE, &(), UImage::layout).await?;
    let mut raw = cx.read(hspan).await?;
    if let Some(field) = raw.get_mut(4..8) {
        field.fill(0);
    }
    let mut header = UImage::node("Header", hspan, BE).summary(h.name.clone());
    let computed = crc32(&raw);
    header = if computed == h.header_crc {
        header.summary(format!("{}, header CRC valid", h.name))
    } else {
        header.diag(Diagnostic::warning(format!(
            "header CRC mismatch: computed {computed:#010x}"
        )))
    };
    cx.emit(header);
    let data = file.sub(UImage::SIZE, h.size.into());
    let lookup = |t: EnumTable, v: u8| crate::value::lookup(t, v.into()).unwrap_or("unknown");
    let mut node = if h.kind == 4 {
        Node::new("Images").span(data).lazy(multi, (input, data))
    } else {
        embedded("Data", input.nested(data))
    };
    node = node.summary(format!(
        "{}, {}",
        lookup(UIMAGE_COMP, h.comp),
        human_size(h.size.into())
    ));
    if data.len <= cx.limits().max_read && data.len == u64::from(h.size) {
        let bytes = cx.read(data).await?;
        let computed = crc32(&bytes);
        if computed != h.data_crc {
            node = node.diag(Diagnostic::warning(format!(
                "data CRC mismatch: computed {computed:#010x}"
            )));
        }
    }
    cx.emit(crate::formats::arcutil::check_len(
        node,
        data,
        h.size.into(),
    ));
    cx.annotate(format!(
        "U-Boot image {:?}: {} {} {}, {}, {}",
        h.name,
        lookup(UIMAGE_OS, h.os),
        lookup(UIMAGE_ARCH, h.arch),
        lookup(UIMAGE_TYPE, h.kind),
        lookup(UIMAGE_COMP, h.comp),
        human_size(h.size.into())
    ));
    Ok(())
}

/// Multi-file images: a zero-terminated list of sizes, then the images,
/// each padded to four bytes.
async fn multi(cx: Cx, (input, data): (Input, Span)) -> Result<()> {
    let mut sizes = Vec::new();
    let mut at = 0u64;
    loop {
        let b = cx.read(data.sub(at, 4)).await?;
        let s = u32_be(&b, 0).unwrap_or(0);
        at = at.saturating_add(4);
        if s == 0 || at >= data.len {
            break;
        }
        sizes.push(s);
    }
    cx.emit(
        Node::new("Size table")
            .span(data.sub(0, at))
            .value(uint(to_u64(sizes.len())))
            .summary(count(to_u64(sizes.len()), "image", "images")),
    );
    for (i, s) in sizes.into_iter().enumerate() {
        let span = data.sub(at, s.into());
        cx.push(embedded(format!("Image {i}"), input.nested(span)).summary(human_size(s.into())))
            .await;
        at = at.saturating_add(u64::from(s).div_ceil(4).saturating_mul(4));
    }
    Ok(())
}
