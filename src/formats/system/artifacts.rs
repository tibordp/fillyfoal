//! System and platform artifacts: firmware tables, kernels, journals, dumps.

use crate::bytes::{u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

// ---------------------------------------------------------------------------
// Flattened device tree (DTB)

declare_format!(pub DTB = "dtb", "Flattened device tree blob", ["dtb", "dtbo"], "application/x-dtb",
    Probe::Magic(&[(0, b"\xd0\x0d\xfe\xed")]), dtb);

record! {
    pub struct DtbHeader {
        magic: u32 "Magic" .hex(),
        total_size: u32 "Total size",
        structure: u32 "Structure block offset" .hex(),
        strings: u32 "Strings block offset" .hex(),
        reservations: u32 "Memory reservation map offset" .hex(),
        version: u32 "Version",
        last_compatible: u32 "Last compatible version",
        boot_cpu: u32 "Boot CPU ID",
        strings_size: u32 "Strings block size",
        structure_size: u32 "Structure block size",
    }
}

const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

#[derive(Clone, Copy, Debug)]
struct Fdt {
    structure: Span,
    strings: Span,
}

async fn dtb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: DtbHeader = read_record(&cx, file.sub(0, DtbHeader::SIZE), BE).await?;
    cx.emit(DtbHeader::node("Header", file.sub(0, DtbHeader::SIZE), BE));
    let fdt = Fdt {
        structure: file.sub(h.structure.into(), h.structure_size.into()),
        strings: file.sub(h.strings.into(), h.strings_size.into()),
    };
    cx.emit(Node::new("Reserved memory map").span(file.sub(
        h.reservations.into(),
        u64::from(h.structure).saturating_sub(h.reservations.into()),
    )));
    // The root node starts the structure block.
    cx.emit(
        Node::new("/")
            .span(fdt.structure)
            .lazy(dt_node, (fdt, 0u64, 0u32)),
    );
    cx.emit(Node::new("Strings").span(fdt.strings));
    let model = dt_property(&cx, fdt, "model").await.ok().flatten();
    cx.annotate(match model {
        Some(m) => format!("{m:?}, DTB v{}", h.version),
        None => format!("DTB v{}", h.version),
    });
    Ok(())
}

/// Finds a property of the root node (for the summary).
async fn dt_property(cx: &Cx, fdt: Fdt, wanted: &str) -> Result<Option<String>> {
    let mut cur = Cursor::new(cx, fdt.structure, BE);
    while !cur.at_end() {
        match cur.u32().await? {
            FDT_BEGIN_NODE => {
                let (_, span) = cur.cstr(256).await?;
                cur.seek(cur.pos().next_multiple_of(4));
                if span.len > 1 {
                    return Ok(None); // a child node: root properties are over
                }
            }
            FDT_PROP => {
                let len = cur.u32().await?;
                let name_off = cur.u32().await?;
                let value = cur.bytes(len.into()).await?;
                cur.seek(cur.pos().next_multiple_of(4));
                let (name, _) = cx
                    .cstr(fdt.strings.tail(name_off.into()).sub(0, 256))
                    .await?;
                if name == wanted {
                    return Ok(Some(crate::text::until_nul(&value)));
                }
            }
            FDT_NOP => {}
            _ => return Ok(None),
        }
    }
    Ok(None)
}

/// Expands the node whose `FDT_BEGIN_NODE` token is at `offset` in the
/// structure block: its properties, then its children (lazily).
async fn dt_node(cx: Cx, (fdt, offset, depth): (Fdt, u64, u32)) -> Result<()> {
    if depth > 64 {
        return Err(Diagnostic::limit("device tree nested too deeply"));
    }
    let mut cur = Cursor::new(&cx, fdt.structure, BE);
    cur.seek(offset);
    if cur.u32().await? != FDT_BEGIN_NODE {
        return Err(
            Diagnostic::malformed("expected FDT_BEGIN_NODE").at(fdt.structure.sub(offset, 4))
        );
    }
    cur.cstr(256).await?;
    cur.seek(cur.pos().next_multiple_of(4));
    let mut level = 0u32;
    loop {
        let start = cur.pos();
        let token = cur.u32().await?;
        match token {
            FDT_PROP => {
                let len = cur.u32().await?;
                let name_off = cur.u32().await?;
                let value_span = cur.span(len.into());
                let value = cur.bytes(len.into()).await?;
                cur.seek(cur.pos().next_multiple_of(4));
                if level == 0 {
                    let (name, _) = cx
                        .cstr(fdt.strings.tail(name_off.into()).sub(0, 256))
                        .await?;
                    cx.push(
                        Node::new(name)
                            .span(cur.since(start))
                            .value(dt_value(&value))
                            .target(value_span),
                    )
                    .await;
                }
            }
            FDT_BEGIN_NODE => {
                let (name, _) = cur.cstr(256).await?;
                cur.seek(cur.pos().next_multiple_of(4));
                if level == 0 {
                    cx.push(Node::new(name).span(fdt.structure.sub(start, 0)).lazy(
                        crate::expander!(self::dt_node: (Fdt, u64, u32)),
                        (fdt, start, depth.saturating_add(1)),
                    ))
                    .await;
                }
                level = level.saturating_add(1);
            }
            FDT_END_NODE => {
                if level == 0 {
                    return Ok(());
                }
                level = level.saturating_sub(1);
            }
            FDT_NOP => {}
            FDT_END => return Ok(()),
            other => {
                return Err(
                    Diagnostic::malformed(format!("unknown token {other:#x}")).at(cur.since(start))
                );
            }
        }
    }
}

/// Property values are untyped: show printable NUL-separated strings as
/// text, otherwise 32-bit cells.
fn dt_value(value: &[u8]) -> Value {
    let printable = !value.is_empty()
        && value.last() == Some(&0)
        && value.first() != Some(&0)
        && value.iter().all(|&b| b == 0 || (0x20..0x7f).contains(&b));
    if printable {
        let parts: Vec<String> = value
            .split(|&b| b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect();
        return text(parts.join(", "));
    }
    if value.len().is_multiple_of(4) && !value.is_empty() {
        let cells: Vec<String> = (0..value.len() / 4)
            .filter_map(|i| u32_be(value, i.saturating_mul(4)))
            .map(|c| format!("{c:#x}"))
            .collect();
        return text(format!("<{}>", cells.join(" ")));
    }
    Value::Bytes(value.to_vec())
}

// ---------------------------------------------------------------------------
// ACPI tables

const ACPI_SIGNATURES: &[(&[u8; 4], &str)] = &[
    (b"APIC", "Multiple APIC Description Table"),
    (b"BERT", "Boot Error Record Table"),
    (b"BGRT", "Boot Graphics Resource Table"),
    (b"DBG2", "Debug Port Table 2"),
    (b"DMAR", "DMA Remapping Table"),
    (b"DSDT", "Differentiated System Description Table"),
    (b"ECDT", "Embedded Controller Boot Resources Table"),
    (b"FACP", "Fixed ACPI Description Table"),
    (b"FPDT", "Firmware Performance Data Table"),
    (b"HPET", "High Precision Event Timer Table"),
    (b"IVRS", "I/O Virtualization Reporting Structure"),
    (b"MCFG", "PCI Express Memory-mapped Configuration"),
    (b"MSDM", "Microsoft Data Management Table"),
    (b"RSDT", "Root System Description Table"),
    (b"SLIC", "Software Licensing Description Table"),
    (b"SRAT", "System Resource Affinity Table"),
    (b"SSDT", "Secondary System Description Table"),
    (b"TPM2", "Trusted Platform Module 2 Table"),
    (b"UEFI", "UEFI ACPI Data Table"),
    (b"WSMT", "Windows SMM Security Mitigations Table"),
    (b"XSDT", "Extended System Description Table"),
];

fn acpi_probe(h: &Head<'_>) -> bool {
    let Some(sig) = h.data.get(..4) else {
        return false;
    };
    ACPI_SIGNATURES.iter().any(|(s, _)| &s[..] == sig)
        && u32_le(h.data, 4).is_some_and(|len| u64::from(len) == h.len)
}

declare_format!(pub ACPI = "acpi", "ACPI system description table", ["aml", "dat", "bin"], "application/x-acpi",
    Probe::Custom(acpi_probe), acpi);

record! {
    pub struct AcpiHeader {
        signature: ascii[4] "Signature",
        length: u32 "Length",
        revision: u8 "Revision",
        checksum: u8 "Checksum" .hex(),
        oem: ascii[6] "OEM ID",
        oem_table: ascii[8] "OEM table ID",
        oem_revision: u32 "OEM revision" .hex(),
        creator: ascii[4] "Creator ID",
        creator_revision: u32 "Creator revision" .hex(),
    }
}

async fn acpi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, AcpiHeader::SIZE);
    let h: AcpiHeader = read_record(&cx, span, LE).await?;
    let mut node = AcpiHeader::node("Header", span, LE);
    if u64::from(h.length) <= cx.limits().max_read {
        let all = cx.read(file.sub(0, h.length.into())).await?;
        let sum = all.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        node = if sum == 0 {
            node.summary("checksum valid")
        } else {
            node.diag(Diagnostic::warning("checksum does not sum to zero"))
        };
    }
    cx.emit(node);
    let body = file.tail(AcpiHeader::SIZE);
    match h.signature.as_str() {
        "RSDT" | "XSDT" => {
            let width: u64 = if h.signature == "XSDT" { 8 } else { 4 };
            let data = cx.read_avail(body).await?;
            for i in 0..body.len.checked_div(width).unwrap_or(0) {
                let at = crate::bytes::to_usize(i.saturating_mul(width));
                let address = if width == 8 {
                    crate::bytes::u64_le(&data, at)
                } else {
                    u32_le(&data, at).map(u64::from)
                }
                .unwrap_or(0);
                cx.push(
                    Node::new(format!("Entry {i}"))
                        .span(body.sub(i.saturating_mul(width), width))
                        .value(Value::UInt {
                            value: address,
                            bits: 64,
                            radix: Radix::Hex,
                        }),
                )
                .await;
            }
        }
        "DSDT" | "SSDT" => cx.emit(Node::new("AML bytecode").span(body)),
        _ => cx.emit(Node::new("Table data").span(body)),
    }
    let name = ACPI_SIGNATURES
        .iter()
        .find(|(s, _)| &s[..] == h.signature.as_bytes())
        .map_or("ACPI table", |(_, n)| n);
    cx.annotate(format!(
        "{} ({name}), {} {}",
        h.signature,
        h.oem.trim(),
        h.oem_table.trim()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Linux kernel image (bzImage)

fn bzimage_probe(h: &Head<'_>) -> bool {
    h.at(0x202, b"HdrS") && h.at(0x1fe, b"\x55\xaa")
}

declare_format!(pub BZIMAGE = "linux-kernel", "Linux kernel image (bzImage)", ["bzimage", "vmlinuz"], "application/x-linux-kernel",
    Probe::Custom(bzimage_probe), bzimage);

const LOAD_FLAGS: FlagTable = &[
    flag(0x01, "LOADED_HIGH"),
    flag(0x02, "KASLR_FLAG"),
    flag(0x20, "QUIET_FLAG"),
    flag(0x40, "KEEP_SEGMENTS"),
    flag(0x80, "CAN_USE_HEAP"),
];

record! {
    pub struct SetupHeader {
        setup_sects: u8 "setup_sects",
        root_flags: u16 "root_flags",
        syssize: u32 "syssize (16-byte paragraphs)",
        ram_size: u16 "ram_size",
        vid_mode: u16 "vid_mode" .hex(),
        root_dev: u16 "root_dev" .hex(),
        boot_flag: u16 "boot_flag" .hex(),
        jump: u16 "jump" .hex(),
        header: ascii[4] "header",
        version: u16 "Boot protocol version" .hex(),
        realmode_swtch: u32 "realmode_swtch" .hex(),
        start_sys_seg: u16 "start_sys_seg" .hex(),
        kernel_version: u16 "kernel_version (offset - 0x200)" .hex(),
        type_of_loader: u8 "type_of_loader" .hex(),
        loadflags: u8 "loadflags" .flags(LOAD_FLAGS),
        setup_move_size: u16 "setup_move_size" .hex(),
        code32_start: u32 "code32_start" .hex(),
        ramdisk_image: u32 "ramdisk_image" .hex(),
        ramdisk_size: u32 "ramdisk_size",
        bootsect_kludge: u32 "bootsect_kludge" .hex(),
        heap_end_ptr: u16 "heap_end_ptr" .hex(),
        ext_loader_ver: u8 "ext_loader_ver",
        ext_loader_type: u8 "ext_loader_type",
        cmd_line_ptr: u32 "cmd_line_ptr" .hex(),
        initrd_addr_max: u32 "initrd_addr_max" .hex(),
        kernel_alignment: u32 "kernel_alignment" .hex(),
        relocatable_kernel: u8 "relocatable_kernel",
        min_alignment: u8 "min_alignment",
        xloadflags: u16 "xloadflags" .hex(),
        cmdline_size: u32 "cmdline_size",
        hardware_subarch: u32 "hardware_subarch",
        hardware_subarch_data: u64 "hardware_subarch_data" .hex(),
        payload_offset: u32 "payload_offset" .hex(),
        payload_length: u32 "payload_length",
    }
}

async fn bzimage(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0x1f1, SetupHeader::SIZE);
    let h: SetupHeader = read_record(&cx, span, LE).await?;
    cx.emit(Node::new("Boot sector").span(file.sub(0, 0x1f1)));
    cx.emit(SetupHeader::node("Setup header", span, LE));
    let setup = u64::from(if h.setup_sects == 0 { 4 } else { h.setup_sects })
        .saturating_add(1)
        .saturating_mul(512);
    cx.emit(Node::new("Real-mode setup code").span(file.sub(0, setup)));
    let protected = file.tail(setup);
    cx.emit(Node::new("Protected-mode kernel").span(protected));
    if h.payload_length > 0 {
        let payload = protected.sub(h.payload_offset.into(), h.payload_length.into());
        cx.emit(
            embedded("Compressed payload", input.nested(payload))
                .summary(format!("{} bytes", h.payload_length)),
        );
    }
    let version = if h.kernel_version != 0 {
        cx.cstr(file.sub(u64::from(h.kernel_version).saturating_add(0x200), 256))
            .await
            .map(|(v, _)| v)
            .ok()
    } else {
        None
    };
    cx.annotate(format!(
        "Linux kernel {}, boot protocol {}.{:02}",
        version
            .as_deref()
            .and_then(|v| v.split_whitespace().next())
            .unwrap_or("(unknown version)"),
        h.version >> 8,
        h.version & 0xff
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// systemd journal

declare_format!(pub JOURNAL = "journald", "systemd journal", ["journal", "journal~"], "application/x-systemd-journal",
    Probe::Magic(&[(0, b"LPKSHHRH")]), journal);

const JOURNAL_STATES: EnumTable = &[(0, "offline"), (1, "online"), (2, "archived")];
const JOURNAL_INCOMPATIBLE: FlagTable = &[
    flag(1, "COMPRESSED_XZ"),
    flag(2, "COMPRESSED_LZ4"),
    flag(4, "KEYED_HASH"),
    flag(8, "COMPRESSED_ZSTD"),
    flag(16, "COMPACT"),
];

record! {
    pub struct JournalHeader {
        signature: ascii[8] "Signature",
        compatible: u32 "Compatible flags" .hex(),
        incompatible: u32 "Incompatible flags" .flags(JOURNAL_INCOMPATIBLE),
        state: u8 "State" .enumeration(JOURNAL_STATES),
        _reserved: bytes[7] "Reserved",
        file_id: guid "File ID",
        machine_id: guid "Machine ID",
        tail_boot_id: guid "Tail entry boot ID",
        seqnum_id: guid "Sequence number ID",
        header_size: u64 "Header size",
        arena_size: u64 "Arena size",
        data_hash_offset: u64 "Data hash table offset" .hex(),
        data_hash_size: u64 "Data hash table size",
        field_hash_offset: u64 "Field hash table offset" .hex(),
        field_hash_size: u64 "Field hash table size",
        tail_object: u64 "Tail object offset" .hex(),
        objects: u64 "Objects",
        entries: u64 "Entries",
        tail_seqnum: u64 "Tail entry sequence number",
        head_seqnum: u64 "Head entry sequence number",
        entry_array: u64 "Entry array offset" .hex(),
        head_realtime: u64 "Head entry realtime (µs)",
        tail_realtime: u64 "Tail entry realtime (µs)",
        tail_monotonic: u64 "Tail entry monotonic (µs)",
    }
}

async fn journal(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: JournalHeader = read_record(&cx, file.sub(0, JournalHeader::SIZE), LE).await?;
    cx.emit(JournalHeader::node(
        "Header",
        file.sub(0, h.header_size.min(file.len)),
        LE,
    ));
    let arena = file.sub(h.header_size, h.arena_size);
    cx.emit(
        Node::new("Objects")
            .span(arena)
            .summary(format!("{} objects", h.objects))
            .lazy(journal_objects, arena),
    );
    let state = lookup(JOURNAL_STATES, h.state.into()).unwrap_or("unknown");
    let first = crate::render::value(&Value::Timestamp {
        unix_seconds: i64::try_from(h.head_realtime / 1_000_000).unwrap_or(0),
    });
    let last = crate::render::value(&Value::Timestamp {
        unix_seconds: i64::try_from(h.tail_realtime / 1_000_000).unwrap_or(0),
    });
    cx.annotate(format!("{} entries, {state}, {first} – {last}", h.entries));
    Ok(())
}

const JOURNAL_OBJECTS: EnumTable = &[
    (0, "UNUSED"),
    (1, "DATA"),
    (2, "FIELD"),
    (3, "ENTRY"),
    (4, "DATA_HASH_TABLE"),
    (5, "FIELD_HASH_TABLE"),
    (6, "ENTRY_ARRAY"),
    (7, "TAG"),
];

async fn journal_objects(cx: Cx, arena: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, arena, LE);
    while cur.remaining() >= 16 {
        let start = cur.pos();
        let header = cur.bytes(16).await?;
        let kind = header.first().copied().unwrap_or(0);
        let size = crate::bytes::u64_le(&header, 8).unwrap_or(0);
        if size < 16 {
            break;
        }
        let span = arena.sub(start, size);
        let mut node = Node::new(
            lookup(JOURNAL_OBJECTS, kind.into())
                .unwrap_or("unknown")
                .to_owned(),
        )
        .span(span);
        if kind == 1 {
            // DATA: payload is "FIELD=value" after a 64-byte header.
            let payload = cx.read_avail(span.sub(64, 200)).await?;
            node = node.summary(String::from_utf8_lossy(&payload).into_owned());
        } else {
            node = node.summary(format!("{size} bytes"));
        }
        cx.push(node).await;
        cur.seek(start.saturating_add(size).next_multiple_of(8));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Redis RDB dumps

declare_format!(pub REDIS_RDB = "redis-rdb", "Redis database dump", ["rdb"], "application/x-redis-rdb",
    Probe::Magic(&[(0, b"REDIS00")]), redis_rdb);

async fn redis_rdb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 9)).await?;
    let version = String::from_utf8_lossy(head.get(5..9).unwrap_or_default()).into_owned();
    cx.emit(Node::new("Magic").span(file.sub(0, 5)).value(text("REDIS")));
    cx.emit(
        Node::new("Version")
            .span(file.sub(5, 4))
            .value(text(version.clone())),
    );
    // Auxiliary fields (opcode 0xfa) come first: name/value string pairs.
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(9);
    let mut redis_version = None;
    while !cur.at_end() {
        let start = cur.pos();
        let op = cur.u8().await?;
        match op {
            0xfa => {
                let key = rdb_string(&mut cur).await?;
                let value = rdb_string(&mut cur).await?;
                if key == "redis-ver" {
                    redis_version = Some(value.clone());
                }
                cx.push(Node::new(key).span(cur.since(start)).value(text(value)))
                    .await;
            }
            0xfe => {
                let db = rdb_length(&mut cur).await?;
                cx.push(Node::new(format!("SELECTDB {db}")).span(cur.since(start)))
                    .await;
            }
            0xfb => {
                let keys = rdb_length(&mut cur).await?;
                let expires = rdb_length(&mut cur).await?;
                cx.push(
                    Node::new("RESIZEDB")
                        .span(cur.since(start))
                        .summary(format!("{keys} keys, {expires} with expiry")),
                )
                .await;
                // Key/value pairs follow; their encodings vary by type.
                cx.emit(Node::new("Key-value pairs").span(file.tail(cur.pos())));
                break;
            }
            0xff => {
                cx.push(Node::new("EOF").span(file.tail(start))).await;
                break;
            }
            _ => {
                cx.emit(Node::new("Key-value pairs").span(file.tail(start)));
                break;
            }
        }
    }
    cx.annotate(format!(
        "RDB v{}, Redis {}",
        version.trim_start_matches('0'),
        redis_version.unwrap_or_else(|| "?".to_owned())
    ));
    Ok(())
}

async fn rdb_length(cur: &mut Cursor<'_>) -> Result<u64> {
    let first = cur.u8().await?;
    Ok(match first >> 6 {
        0 => u64::from(first & 0x3f),
        1 => u64::from(first & 0x3f) << 8 | u64::from(cur.u8().await?),
        2 if first == 0x80 => u64::from(u32::from_be_bytes(
            cur.bytes(4).await?.try_into().unwrap_or([0; 4]),
        )),
        2 => u64::from_be_bytes(cur.bytes(8).await?.try_into().unwrap_or([0; 8])),
        _ => u64::from(first & 0x3f) | 0x8000_0000_0000_0000,
    })
}

async fn rdb_string(cur: &mut Cursor<'_>) -> Result<String> {
    let len = rdb_length(cur).await?;
    if len & 0x8000_0000_0000_0000 != 0 {
        // Integer encodings.
        return Ok(match len & 0x3f {
            0 => (cur.u8().await? as i8).to_string(),
            1 => (cur.u16().await? as i16).to_string(),
            2 => (cur.u32().await? as i32).to_string(),
            3 => {
                // LZF: compressed and uncompressed lengths, then the data.
                let packed = rdb_length(cur).await?;
                let size = rdb_length(cur).await?;
                if packed > 1 << 20 {
                    return Err(Diagnostic::limit("LZF-compressed string over 1 MiB"));
                }
                let data = cur.bytes(packed).await?;
                let mut out = Vec::new();
                crate::codec::legacy::lzf(
                    &data,
                    &mut out,
                    usize::try_from(size.min(1 << 20)).unwrap_or(0),
                )?;
                String::from_utf8_lossy(&out).into_owned()
            }
            _ => return Err(Diagnostic::malformed("unknown string encoding")),
        });
    }
    Ok(String::from_utf8_lossy(&cur.bytes(len.min(1 << 20)).await?).into_owned())
}

// ---------------------------------------------------------------------------
// Outlook PST / OST

declare_format!(pub PST = "pst", "Outlook personal folders", ["pst", "ost"], "application/vnd.ms-outlook",
    Probe::Magic(&[(0, b"!BDN")]), pst);

async fn pst(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x20)).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    f.u32("CRC (partial)").hex().emit()?;
    let client = f.ascii("Client magic", 2).emit()?;
    let version = f.u16("File format version").emit()?;
    f.u16("Client version").emit()?;
    f.u8("Platform create").emit()?;
    f.u8("Platform access").emit()?;
    let kind = match (client.as_str(), version) {
        ("SM", 14 | 15) => "ANSI PST",
        ("SM", 23) => "Unicode PST",
        ("SM", 36) => "Unicode PST (4K pages)",
        ("SO", _) => "OST (offline storage)",
        _ => "PST",
    };
    cx.annotate(format!("{kind}, format version {version}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Solaris snoop captures

declare_format!(pub SNOOP = "snoop", "Solaris snoop capture", ["snoop", "cap"], "application/x-snoop",
    Probe::Magic(&[(0, b"snoop\0\0\0")]), snoop);

const SNOOP_LINKS: EnumTable = &[
    (0, "IEEE 802.3"),
    (1, "IEEE 802.4"),
    (2, "IEEE 802.5"),
    (3, "IEEE 802.6"),
    (4, "Ethernet"),
    (5, "HDLC"),
    (6, "Character synchronous"),
    (7, "IBM channel-to-channel"),
    (8, "FDDI"),
    (9, "Other"),
    (18, "InfiniBand"),
    (26, "IP over InfiniBand"),
];

async fn snoop(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 8).emit()?;
    let version = f.u32("Version").emit()?;
    let link = f.u32("Datalink type").enumeration(SNOOP_LINKS).emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(16);
    let mut packets = 0u32;
    while cur.remaining() >= 24 {
        let start = cur.pos();
        let original = cur.u32().await?;
        let included = cur.u32().await?;
        let record = cur.u32().await?;
        let _drops = cur.u32().await?;
        let seconds = cur.u32().await?;
        let micros = cur.u32().await?;
        if record < 24 {
            break;
        }
        cur.seek(start.saturating_add(record.into()));
        packets = packets.saturating_add(1);
        cx.push(
            Node::new(format!("Packet {packets}"))
                .span(cur.since(start))
                .value(Value::Timestamp {
                    unix_seconds: seconds.into(),
                })
                .summary(format!("{included}/{original} bytes, +{micros} µs")),
        )
        .await;
    }
    let link = lookup(SNOOP_LINKS, link.into()).unwrap_or("unknown link");
    cx.annotate(format!("snoop v{version}, {link}, {packets} packets"));
    Ok(())
}
