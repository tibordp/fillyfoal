//! Platform artifacts: Linux tooling, Android boot security, firmware
//! images, Java module files and Mac resource forks.

use std::sync::Arc;

use crate::bytes::{u16_be, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, Layout, parse, struct_node};
use crate::formats::util::arcutil::emit_nodes;
use crate::formats::util::val::text;
use crate::formats::{Head, Input, Probe, embedded, embedded_as};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// perf.data

declare_format!(pub PERF = "perf-data", "Linux perf profile data", ["data", "perf"], "application/x-perf-data",
    Probe::Magic(&[(0, b"PERFILE2"), (0, b"2ELIFREP")]), perf);

record! {
    pub struct PerfHeader {
        magic: ascii[8] "Magic",
        size: u64 "Header size",
        attr_size: u64 "Attribute size",
        attrs_offset: u64 "Attributes offset" .hex(),
        attrs_size: u64 "Attributes size",
        data_offset: u64 "Data offset" .hex(),
        data_size: u64 "Data size",
        event_types_offset: u64 "Event types offset" .hex(),
        event_types_size: u64 "Event types size",
        features: bytes[32] "Feature bitmap",
    }
}

const PERF_FEATURES: [&str; 32] = [
    "reserved",
    "tracing data",
    "build ids",
    "hostname",
    "osrelease",
    "version",
    "arch",
    "nrcpus",
    "cpudesc",
    "cpuid",
    "total memory",
    "cmdline",
    "event desc",
    "cpu topology",
    "numa topology",
    "branch stack",
    "pmu mappings",
    "group desc",
    "auxtrace",
    "stat",
    "cache",
    "sample time",
    "memory topology",
    "clockid",
    "dir format",
    "bpf prog info",
    "bpf btf",
    "compressed",
    "cpu pmu caps",
    "clock data",
    "hybrid topology",
    "pmu caps",
];

async fn perf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: PerfHeader = read_record(&cx, file.sub(0, PerfHeader::SIZE), LE).await?;
    cx.emit(PerfHeader::node(
        "Header",
        file.sub(0, PerfHeader::SIZE),
        LE,
    ));
    cx.emit(
        Node::new("Attributes")
            .span(file.sub(h.attrs_offset, h.attrs_size))
            .summary(format!(
                "{} event(s)",
                h.attrs_size.checked_div(h.attr_size).unwrap_or(0)
            )),
    );
    cx.emit(Node::new("Samples").span(file.sub(h.data_offset, h.data_size)));
    let features: Vec<&str> = PERF_FEATURES
        .iter()
        .enumerate()
        .filter(|(i, _)| h.features.get(i / 8).is_some_and(|b| b >> (i % 8) & 1 == 1))
        .map(|(_, n)| *n)
        .collect();
    cx.emit(
        Node::new("Features")
            .span(file.sub(0x48, 32))
            .value(text(features.join(", "))),
    );
    cx.annotate(format!(
        "perf.data, {} bytes of samples, {} feature sections",
        h.data_size,
        features.len()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// ld.so.cache

declare_format!(pub LDSO_CACHE = "ldso-cache", "glibc dynamic linker cache", ["cache"], "application/x-ldso-cache",
    Probe::Magic(&[(0, b"glibc-ld.so.cache1.1"), (0, b"ld.so-1.7.0")]), ldso_cache);

async fn ldso_cache(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut base = 0u64;
    if cx.read(file.sub(0, 11)).await? == b"ld.so-1.7.0" {
        // The old format: skip its entries to reach the new-format header.
        let n = u32_le(&cx.read(file.sub(12, 4)).await?, 0).unwrap_or(0);
        base = 16u64
            .saturating_add(u64::from(n).saturating_mul(12))
            .next_multiple_of(8);
        cx.emit(
            Node::new("Old-format table")
                .span(file.sub(0, base))
                .summary(format!("{n} entries")),
        );
    }
    let head = cx.block(file.sub(base, 48)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 20).emit()?;
    let count = f.u32("Libraries").emit()?;
    let strings_len = f.u32("String table size").emit()?;
    let entries = file.sub_exact(base.saturating_add(48), u64::from(count).saturating_mul(24))?;
    cx.emit(
        Node::new("Libraries")
            .span(entries)
            .summary(format!("{count} entries"))
            .lazy(ldso_entries, (file, entries, base)),
    );
    cx.annotate(format!(
        "ld.so cache, {count} libraries, {strings_len}-byte string table"
    ));
    Ok(())
}

async fn ldso_entries(cx: Cx, (file, entries, base): (Span, Span, u64)) -> Result<()> {
    let count = entries.len / 24;
    cx.set_count(Count::Exact(count));
    let mut cur = Cursor::new(&cx, entries, LE);
    for _ in 0..count {
        let start = cur.pos();
        let _flags = cur.u32().await?;
        let key = cur.u32().await?;
        let value = cur.u32().await?;
        cur.skip(12);
        // String offsets are relative to the new-format header.
        let (name, _) = cx
            .cstr(file.sub(base.saturating_add(key.into()), 256))
            .await?;
        let (path, _) = cx
            .cstr(file.sub(base.saturating_add(value.into()), 1024))
            .await?;
        cx.push(Node::new(name).span(cur.since(start)).value(text(path)))
            .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SELinux binary policy

declare_format!(pub SELINUX = "selinux-policy", "SELinux binary policy", ["policy"], "application/x-selinux-policy",
    Probe::Magic(&[(0, b"\x8c\xff\x7c\xf9")]), selinux);

async fn selinux(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let len = u64::from(u32_le(&head, 4).unwrap_or(0));
    let id = String::from_utf8_lossy(&cx.read(file.sub(8, len.min(64))).await?).into_owned();
    let after = 8u64.saturating_add(len);
    let block = cx.block(file.sub(after, 16)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let version = f.u32("Policy version").emit()?;
    f.u32("Config").hex().emit()?;
    f.u32("Symbol tables").emit()?;
    f.u32("Object contexts").emit()?;
    cx.emit(
        Node::new("Identifier")
            .span(file.sub(8, len))
            .value(text(id.clone())),
    );
    cx.emit(Node::new("Policy").span(file.tail(after.saturating_add(16))));
    cx.annotate(format!("{id} version {version}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Android Verified Boot (vbmeta) and DTBO tables

declare_format!(pub VBMETA = "vbmeta", "Android Verified Boot metadata", ["img"], "application/x-android-vbmeta",
    Probe::Magic(&[(0, b"AVB0")]), vbmeta);

const AVB_ALGORITHMS: EnumTable = &[
    (0, "NONE"),
    (1, "SHA256_RSA2048"),
    (2, "SHA256_RSA4096"),
    (3, "SHA256_RSA8192"),
    (4, "SHA512_RSA2048"),
    (5, "SHA512_RSA4096"),
    (6, "SHA512_RSA8192"),
];

record! {
    pub struct VbmetaHeader {
        magic: ascii[4] "Magic",
        major: u32 "Required libavb major version",
        minor: u32 "Required libavb minor version",
        auth_size: u64 "Authentication block size",
        aux_size: u64 "Auxiliary block size",
        algorithm: u32 "Algorithm" .enumeration(AVB_ALGORITHMS),
        hash_offset: u64 "Hash offset",
        hash_size: u64 "Hash size",
        signature_offset: u64 "Signature offset",
        signature_size: u64 "Signature size",
        key_offset: u64 "Public key offset",
        key_size: u64 "Public key size",
        key_metadata_offset: u64 "Public key metadata offset",
        key_metadata_size: u64 "Public key metadata size",
        descriptors_offset: u64 "Descriptors offset",
        descriptors_size: u64 "Descriptors size",
        rollback_index: u64 "Rollback index",
        flags: u32 "Flags" .hex(),
        rollback_location: u32 "Rollback index location",
        release: ascii[48] "Release string",
    }
}

const AVB_DESCRIPTORS: EnumTable = &[
    (0, "Property"),
    (1, "Hashtree"),
    (2, "Hash"),
    (3, "Kernel cmdline"),
    (4, "Chain partition"),
];

async fn vbmeta(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: VbmetaHeader = read_record(&cx, file.sub(0, VbmetaHeader::SIZE), BE).await?;
    cx.emit(VbmetaHeader::node("Header", file.sub(0, 256), BE));
    let auth = file.sub(256, h.auth_size);
    let aux = file.sub(256u64.saturating_add(h.auth_size), h.aux_size);
    let mut auth_parts = Vec::new();
    for (name, offset, size) in [
        ("Hash", h.hash_offset, h.hash_size),
        ("Signature", h.signature_offset, h.signature_size),
    ] {
        if size > 0 {
            auth_parts.push(Node::new(name).span(auth.sub(offset, size)));
        }
    }
    cx.emit(
        Node::new("Authentication block")
            .span(auth)
            .lazy(emit_nodes, Arc::new(auth_parts)),
    );
    let descriptors = aux.sub(h.descriptors_offset, h.descriptors_size);
    cx.emit(
        Node::new("Descriptors")
            .span(descriptors)
            .lazy(avb_descriptors, descriptors),
    );
    for (name, offset, size) in [
        ("Public key", h.key_offset, h.key_size),
        (
            "Public key metadata",
            h.key_metadata_offset,
            h.key_metadata_size,
        ),
    ] {
        if size > 0 {
            cx.emit(Node::new(name).span(aux.sub(offset, size)));
        }
    }
    cx.annotate(format!(
        "vbmeta {}.{}, {}, {}",
        h.major,
        h.minor,
        lookup(AVB_ALGORITHMS, h.algorithm.into()).unwrap_or("unknown algorithm"),
        h.release.trim_end_matches('\0')
    ));
    Ok(())
}

/// Bytes of one descriptor decoded at most; longer ones (no real
/// descriptor comes close) are shown truncated.
const MAX_DESCRIPTOR: u64 = 1 << 16;

async fn avb_descriptors(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    // Resume marks: (position, index).
    let (pos, first) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    cur.seek(pos);
    let mut index = first;
    while cur.remaining() >= 16 {
        let start = cur.pos();
        let mark = (start, index);
        cx.mark(move || mark);
        let tag = cur.u64().await?;
        let len = cur.u64().await?;
        cur.skip(len);
        let whole = cur.since(start);
        let name = lookup(AVB_DESCRIPTORS, tag).unwrap_or("Unknown descriptor");
        let layout: Option<Layout<(), String>> = match tag {
            0 => Some(avb_property),
            1 => Some(avb_hashtree),
            2 => Some(avb_hash),
            3 => Some(avb_cmdline),
            4 => Some(avb_chain),
            _ => None,
        };
        let node = match layout {
            Some(layout) => {
                let shown = whole.sub(0, MAX_DESCRIPTOR);
                match parse(&cx, shown, BE, &(), layout).await {
                    Ok(summary) => struct_node(name, shown, BE, (), layout).summary(summary),
                    Err(e) => struct_node(name, shown, BE, (), layout).diag(e),
                }
                .span(whole)
            }
            None => Node::new(name).span(whole).summary(format!("tag {tag}")),
        };
        cx.push(node).await;
        index = index.saturating_add(1);
    }
    Ok(())
}

/// The tag and length every descriptor starts with.
fn avb_descriptor_header(f: &mut Fields<'_>) -> Result<()> {
    f.u64("Tag").enumeration(AVB_DESCRIPTORS).emit()?;
    f.u64("Length").emit()?;
    Ok(())
}

/// `AvbPropertyDescriptor`: key and value, each NUL-terminated.
fn avb_property(f: &mut Fields<'_>, _: &()) -> Result<String> {
    avb_descriptor_header(f)?;
    let key_len = f.u64("Key length").emit()?;
    let value_len = f.u64("Value length").emit()?;
    let key = f.ascii("Key", key_len).emit()?;
    f.skip(1);
    let value = f.ascii("Value", value_len).emit()?;
    Ok(format!("{key} = {}", text_clip(&value)))
}

fn text_clip(s: &str) -> String {
    crate::formats::util::fmt::clip(s, 200)
}

/// `AvbHashtreeDescriptor`: dm-verity parameters, then the partition
/// name, salt and root digest.
fn avb_hashtree(f: &mut Fields<'_>, _: &()) -> Result<String> {
    avb_descriptor_header(f)?;
    f.u32("dm-verity version").emit()?;
    let image = f
        .u64("Image size")
        .with(|&s, n| n.summary(crate::formats::util::fmt::size(s)))
        .emit()?;
    f.u64("Tree offset").hex().emit()?;
    f.u64("Tree size").emit()?;
    f.u32("Data block size").emit()?;
    f.u32("Hash block size").emit()?;
    f.u32("FEC roots").emit()?;
    f.u64("FEC offset").hex().emit()?;
    f.u64("FEC size").emit()?;
    let alg = f.ascii("Hash algorithm", 32).emit()?;
    let name_len = f.u32("Partition name length").emit()?;
    let salt_len = f.u32("Salt length").emit()?;
    let digest_len = f.u32("Root digest length").emit()?;
    f.u32("Flags").flags(AVB_HASHTREE_FLAGS).emit()?;
    f.bytes("Reserved", 60).emit()?;
    let name = f.ascii("Partition name", name_len.into()).emit()?;
    f.bytes("Salt", salt_len.into()).emit()?;
    f.bytes("Root digest", digest_len.into()).emit()?;
    Ok(format!(
        "{name}, {}, {}",
        crate::formats::util::fmt::size(image),
        alg.trim_end_matches('\0')
    ))
}

const AVB_HASHTREE_FLAGS: FlagTable = &[flag(1, "DO_NOT_USE_AB"), flag(2, "CHECK_AT_MOST_ONCE")];

/// `AvbHashDescriptor`: the image's size and digest, then the partition
/// name, salt and digest.
fn avb_hash(f: &mut Fields<'_>, _: &()) -> Result<String> {
    avb_descriptor_header(f)?;
    let image = f
        .u64("Image size")
        .with(|&s, n| n.summary(crate::formats::util::fmt::size(s)))
        .emit()?;
    let alg = f.ascii("Hash algorithm", 32).emit()?;
    let name_len = f.u32("Partition name length").emit()?;
    let salt_len = f.u32("Salt length").emit()?;
    let digest_len = f.u32("Digest length").emit()?;
    f.u32("Flags").flags(AVB_HASH_FLAGS).emit()?;
    f.bytes("Reserved", 60).emit()?;
    let name = f.ascii("Partition name", name_len.into()).emit()?;
    f.bytes("Salt", salt_len.into()).emit()?;
    f.bytes("Digest", digest_len.into()).emit()?;
    Ok(format!(
        "{name}, {}, {}",
        crate::formats::util::fmt::size(image),
        alg.trim_end_matches('\0')
    ))
}

const AVB_HASH_FLAGS: FlagTable = &[flag(1, "DO_NOT_USE_AB")];

/// `AvbKernelCmdlineDescriptor`.
fn avb_cmdline(f: &mut Fields<'_>, _: &()) -> Result<String> {
    avb_descriptor_header(f)?;
    f.u32("Flags").flags(AVB_CMDLINE_FLAGS).emit()?;
    let len = f.u32("Command line length").emit()?;
    let cmdline = f.ascii("Command line", len.into()).emit()?;
    Ok(text_clip(&cmdline))
}

const AVB_CMDLINE_FLAGS: FlagTable = &[
    flag(1, "USE_ONLY_IF_HASHTREE_NOT_DISABLED"),
    flag(2, "USE_ONLY_IF_HASHTREE_DISABLED"),
];

/// `AvbChainPartitionDescriptor`: the partition whose vbmeta is signed by
/// the given public key.
fn avb_chain(f: &mut Fields<'_>, _: &()) -> Result<String> {
    avb_descriptor_header(f)?;
    let location = f.u32("Rollback index location").emit()?;
    let name_len = f.u32("Partition name length").emit()?;
    let key_len = f.u32("Public key length").emit()?;
    f.u32("Flags").flags(AVB_CHAIN_FLAGS).emit()?;
    f.bytes("Reserved", 60).emit()?;
    let name = f.ascii("Partition name", name_len.into()).emit()?;
    f.bytes("Public key", key_len.into()).emit()?;
    Ok(format!("{name}, rollback index location {location}"))
}

const AVB_CHAIN_FLAGS: FlagTable = &[flag(1, "DO_NOT_USE_AB")];

record! {
    /// `AvbFooter`, the last 64 bytes of a partition whose image is
    /// followed by its vbmeta.
    pub struct AvbFooter {
        magic: ascii[4] "Magic",
        major: u32 "Footer major version",
        minor: u32 "Footer minor version",
        original_size: u64 "Original image size",
        vbmeta_offset: u64 "VBMeta offset" .hex(),
        vbmeta_size: u64 "VBMeta size",
        _reserved: bytes[28] "Reserved",
    }
}

/// Nodes for what follows an Android image's payloads, from `end` to the
/// end of the file: with an AVB footer (avbtool `add_hash_footer`), the
/// vbmeta it points to, the padding around it and the footer; otherwise
/// the trailing bytes as embedded content.
pub async fn avb_trailer(cx: &Cx, input: Input, end: u64) -> Result<()> {
    let file = input.span;
    if end >= file.len {
        return Ok(());
    }
    let at = file.len.saturating_sub(AvbFooter::SIZE);
    let footer = file.sub(at, AvbFooter::SIZE);
    let found = if at >= end && cx.read(footer.sub(0, 4)).await?.as_slice() == b"AVBf" {
        Some(read_record::<AvbFooter>(cx, footer, BE).await?)
    } else {
        None
    };
    let Some(f) = found else {
        let rest = file.tail(end);
        cx.emit(
            embedded("Trailing data", input.nested(rest))
                .summary(crate::formats::util::fmt::size(rest.len)),
        );
        return Ok(());
    };
    let gap = |from: u64, to: u64| {
        if to > from {
            let span = file.sub(from, to.saturating_sub(from));
            cx.emit(
                Node::new("Padding")
                    .span(span)
                    .summary(crate::formats::util::fmt::size(span.len)),
            );
        }
    };
    let vb_end = f.vbmeta_offset.saturating_add(f.vbmeta_size);
    if f.vbmeta_offset >= end && vb_end <= at {
        gap(end, f.vbmeta_offset);
        let span = file.sub(f.vbmeta_offset, f.vbmeta_size);
        cx.emit(
            embedded_as("AVB metadata", input.nested(span), &VBMETA)
                .summary(crate::formats::util::fmt::size(span.len)),
        );
        gap(vb_end, at);
    } else {
        gap(end, at);
    }
    let mut node = AvbFooter::node("AVB footer", footer, BE).summary(format!(
        "image {}, vbmeta at {:#x}",
        crate::formats::util::fmt::size(f.original_size),
        f.vbmeta_offset
    ));
    if f.vbmeta_offset < end || vb_end > at {
        node = node.diag(
            Diagnostic::malformed("vbmeta lies outside the space after the image")
                .at(footer.sub(20, 16)),
        );
    }
    if f.original_size != end {
        node = node.diag(Diagnostic::note(format!(
            "original image size {:#x}, payloads end at {end:#x}",
            f.original_size
        )));
    }
    cx.emit(node);
    Ok(())
}

declare_format!(pub DTBO = "dtbo", "Android device tree overlay table", ["img"], "application/x-android-dtbo",
    Probe::Magic(&[(0, b"\xd7\xb7\xab\x1e")]), dtbo);

async fn dtbo(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u32("Magic").hex().emit()?;
    f.u32("Total size").emit()?;
    let header_size = f.u32("Header size").emit()?;
    let entry_size = f.u32("Entry size").emit()?;
    let count = f.u32("Entries").emit()?;
    let entries_offset = f.u32("Entries offset").hex().emit()?;
    f.u32("Page size").emit()?;
    f.u32("Version").emit()?;
    let _ = header_size;
    for i in 0..count.min(256) {
        let at = u64::from(entries_offset)
            .saturating_add(u64::from(i).saturating_mul(entry_size.into()));
        let entry = cx.read(file.sub(at, 32)).await?;
        let size = u64::from(u32_be(&entry, 0).unwrap_or(0));
        let offset = u64::from(u32_be(&entry, 4).unwrap_or(0));
        let id = u32_be(&entry, 8).unwrap_or(0);
        cx.push(
            embedded(format!("Overlay {i}"), input.nested(file.sub(offset, size)))
                .summary(format!("id {id:#x}, {size} bytes"))
                .target(file.sub(at, entry_size.into())),
        )
        .await;
    }
    cx.annotate(format!("DTBO table, {count} overlays"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Firmware: Intel flash descriptor, coreboot CBFS, ARM FIP, UEFI capsules

fn ifd_probe(h: &Head<'_>) -> bool {
    h.at(16, b"\x5a\xa5\xf0\x0f")
}

declare_format!(pub INTEL_FLASH = "intel-flash", "Intel firmware flash image", ["bin", "rom"], "application/x-intel-flash",
    Probe::Custom(ifd_probe), intel_flash);

const IFD_REGIONS: [&str; 9] = [
    "Descriptor",
    "BIOS",
    "Management Engine",
    "Gigabit Ethernet",
    "Platform Data",
    "Device Expansion",
    "BIOS 2",
    "Reserved",
    "Embedded Controller",
];

async fn intel_flash(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let map = cx.read(file.sub(16, 16)).await?;
    let flmap0 = u32_le(&map, 4).unwrap_or(0);
    let frba = u64::from(flmap0 >> 16 & 0xff) << 4;
    cx.emit(Node::new("Descriptor signature").span(file.sub(16, 4)));
    let regions = cx.read(file.sub(frba, 36)).await?;
    let mut present = Vec::new();
    for (i, name) in IFD_REGIONS.iter().enumerate() {
        let flreg = u32_le(&regions, i.saturating_mul(4)).unwrap_or(0);
        let base = u64::from(flreg & 0x7fff) << 12;
        let limit = (u64::from(flreg >> 16 & 0x7fff) << 12) | 0xfff;
        if limit <= base || flreg == 0 {
            continue;
        }
        present.push(*name);
        let span = file.sub(base, limit.saturating_sub(base).saturating_add(1));
        cx.push(embedded(*name, input.nested(span)).summary(format!("{base:#x}..{limit:#x}")))
            .await;
    }
    cx.annotate(format!(
        "Intel flash image, regions: {}",
        present.join(", ")
    ));
    Ok(())
}

fn cbfs_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"LARCHIVE")
}

declare_format!(pub CBFS = "cbfs", "coreboot file system", ["rom", "cbfs"], "application/x-cbfs",
    Probe::Custom(cbfs_probe), cbfs);

const CBFS_TYPES: EnumTable = &[
    (0x0000_0001, "bootblock"),
    (0x0000_0002, "cbfs header"),
    (0x0000_0010, "stage"),
    (0x0000_0020, "simple ELF (payload)"),
    (0x0000_0030, "fit"),
    (0x0000_0040, "optionrom"),
    (0x0000_0050, "bootsplash"),
    (0x0000_0060, "raw"),
    (0x0000_0061, "vsa"),
    (0x0000_0062, "mbi"),
    (0x0000_0063, "microcode"),
    (0x0000_0065, "fsp"),
    (0x0000_0066, "mrc"),
    (0x0000_0067, "mma"),
    (0x0000_0068, "efi"),
    (0x0000_0069, "struct"),
    (0x0000_00aa, "cmos default"),
    (0x0000_01aa, "cmos layout"),
    (0xffff_ffff, "null (free space)"),
];

async fn cbfs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut files = 0u32;
    while pos.saturating_add(24) <= file.len {
        let head = cx.read(file.sub(pos, 24)).await?;
        if !head.starts_with(b"LARCHIVE") {
            break;
        }
        let len = u64::from(u32_be(&head, 8).unwrap_or(0));
        let kind = u32_be(&head, 12).unwrap_or(0);
        let offset = u64::from(u32_be(&head, 20).unwrap_or(0));
        let (name, _) = cx
            .cstr(file.sub(pos.saturating_add(24), offset.saturating_sub(24).max(1)))
            .await?;
        let data = file.sub(pos.saturating_add(offset), len);
        files = files.saturating_add(1);
        cx.push(
            embedded(
                if name.is_empty() {
                    "(unnamed)".to_owned()
                } else {
                    name
                },
                input.nested(data),
            )
            .summary(format!(
                "{}, {len} bytes",
                lookup(CBFS_TYPES, kind.into()).unwrap_or("unknown type")
            ))
            .target(file.sub(pos, offset)),
        )
        .await;
        if offset < 24 {
            break;
        }
        pos = pos
            .saturating_add(offset)
            .saturating_add(len)
            .next_multiple_of(64);
    }
    cx.annotate(format!("CBFS, {files} files"));
    Ok(())
}

declare_format!(pub ARM_FIP = "arm-fip", "Arm Trusted Firmware image package (FIP)", ["fip", "bin"], "application/x-arm-fip",
    Probe::Magic(&[(0, b"\x01\x00\x64\xaa")]), arm_fip);

/// ToC entry UUIDs in byte order, as fiptool (TF-A 2.12) writes them, with
/// fiptool's names. Read back from a FIP made with every `fiptool create`
/// image option (`tests/data/arm-fip/fip.sh`).
const FIP_UUIDS: &[(&str, &str)] = &[
    (
        "65922703-2f74-e644-8dff-579ac1ff0610",
        "SCP Firmware Updater Configuration FWU SCP_BL2U",
    ),
    (
        "60b3eb37-c1e5-ea41-9df3-19eda11f6801",
        "AP Firmware Updater Configuration BL2U",
    ),
    (
        "4f511d11-2be5-4e49-b4c5-83c2f715840a",
        "Firmware Updater NS_BL2U",
    ),
    (
        "71408ab2-18d6-874c-8b2e-c6dccd50f096",
        "Non-Trusted Firmware Updater certificate",
    ),
    (
        "5ff9ec0b-4d22-3e4d-a544-c39d81c73f0a",
        "Trusted Boot Firmware BL2",
    ),
    (
        "9766fd3d-89be-e849-ae5d-78a140608213",
        "SCP Firmware SCP_BL2",
    ),
    (
        "47d4086d-4cfe-9846-9b95-2950cbbd5a00",
        "EL3 Runtime Firmware BL31",
    ),
    (
        "05d0e189-53dc-1347-8d2b-500a4b7a3e38",
        "Secure Payload BL32 (Trusted OS)",
    ),
    (
        "0b70c29b-2a5a-7840-9f65-0a5682738288",
        "Secure Payload BL32 Extra1 (Trusted OS Extra1)",
    ),
    (
        "8ea87bb1-cfa2-3f4d-85fd-e7bba50220d9",
        "Secure Payload BL32 Extra2 (Trusted OS Extra2)",
    ),
    (
        "d6d0eea7-fcea-d54b-9782-9934f234b6e4",
        "Non-Trusted Firmware BL33",
    ),
    (
        "6c0762a6-12f2-4b56-92cb-ba8f633606d9",
        "Realm Monitor Management Firmware",
    ),
    ("5807e16a-8459-47be-8ed5-648e8dddab0e", "FW_CONFIG"),
    ("08b8f1d9-c9cf-9349-a962-6fbc6b7265cc", "HW_CONFIG"),
    ("6c0458ff-af6b-7d4f-82ed-aa27bc69bfd2", "TB_FW_CONFIG"),
    ("9979814b-0376-fb46-8c8e-8d267f7859e0", "SOC_FW_CONFIG"),
    ("26257c1a-dbc6-7f47-8d96-c4c4b0248021", "TOS_FW_CONFIG"),
    ("28da9815-93e8-7e44-ac66-1aaf801550f9", "NT_FW_CONFIG"),
    (
        "862d1d72-f860-e411-920b-8be762160f24",
        "Root Of Trust key certificate",
    ),
    (
        "827ee890-f860-e411-a1b4-777a21b4f94c",
        "Trusted key certificate",
    ),
    (
        "024221a1-f860-e411-8d9b-f33c0e15a014",
        "SCP Firmware key certificate",
    ),
    (
        "8ab8becc-f960-e411-9ad0-eb4822d8dcf8",
        "SoC Firmware key certificate",
    ),
    (
        "9477d603-fb60-e411-85dd-b7105b8cee04",
        "Trusted OS Firmware key certificate",
    ),
    (
        "8ad5832a-fb60-e411-8aaf-df30bbc49859",
        "Non-Trusted Firmware key certificate",
    ),
    (
        "d6e269ea-5d63-e411-8d8c-9fbabe9956a5",
        "Trusted Boot Firmware BL2 certificate",
    ),
    (
        "44be6f04-5e63-e411-b28b-73d8eaae9656",
        "SCP Firmware content certificate",
    ),
    (
        "e2b20c20-5e63-e411-9ce8-abccf92bb666",
        "SoC Firmware content certificate",
    ),
    (
        "a49f4411-5e63-e411-8728-3f05722af33d",
        "Trusted OS Firmware content certificate",
    ),
    (
        "8ec4c1f3-5d63-e411-a7a9-87ee40b23fa7",
        "Non-Trusted Firmware content certificate",
    ),
    (
        "776dfd44-8697-4c3b-91eb-c13e025a2a6f",
        "SiP owned Secure Partition content certificate",
    ),
    (
        "ddcbbf4a-cad6-11ea-87d0-0242ac130003",
        "Platform owned Secure Partition content certificate",
    ),
    (
        "36d83d85-761d-4daf-96f1-cd99d6569b00",
        "CCA Content Certificate",
    ),
    (
        "52222d31-820f-494d-8bbc-ea6825d3c35a",
        "Core Secure World Key Certificate",
    ),
    (
        "d43cd902-5b9f-412e-8ac6-92b6d18be60d",
        "Platform Key Certificate",
    ),
];

/// The ToC: a 16-byte header, then 40-byte entries (UUID, offset, size,
/// flags) up to a terminator whose UUID is all zeros (fiptool gives it the
/// end-of-data offset and size 0).
async fn arm_fip(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("Name").hex().emit()?;
    f.u32("Serial number").emit()?;
    f.u64("Flags").hex().emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(16);
    let mut images = 0u32;
    while cur.remaining() >= 40 {
        let start = cur.pos();
        let uuid = cur.bytes(16).await?;
        let offset = cur.u64().await?;
        let size = cur.u64().await?;
        let _flags = cur.u64().await?;
        if uuid.iter().all(|&b| b == 0) {
            cx.emit(
                Node::new("ToC end marker")
                    .span(cur.since(start))
                    .summary(format!("data ends at {offset:#x}")),
            );
            break;
        }
        let entry = cur.since(start);
        let id = crate::formats::util::fmt::uuid(&uuid);
        let name = FIP_UUIDS
            .iter()
            .find(|(u, _)| *u == id)
            .map_or_else(|| id.clone(), |(_, n)| (*n).to_owned());
        if offset.checked_add(size).is_none_or(|end| end > file.len) {
            cx.push(
                Node::new(name)
                    .span(entry)
                    .summary(format!("{size} bytes at {offset:#x}"))
                    .diag(
                        Diagnostic::malformed("image extends past the end of the file").at(entry),
                    ),
            )
            .await;
            break;
        }
        images = images.saturating_add(1);
        cx.push(
            embedded(name, input.nested(file.sub(offset, size)))
                .summary(format!("{size} bytes"))
                .target(entry),
        )
        .await;
    }
    cx.annotate(format!("FIP, {images} images"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Java modules (JMOD) and runtime images (jimage)

declare_format!(pub JMOD = "jmod", "Java module (JMOD)", ["jmod"], "application/x-java-jmod",
    Probe::Magic(&[(0, b"JM\x01\x00PK\x03\x04")]), jmod);

async fn jmod(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Header").span(file.sub(0, 4)).summary("JMOD 1.0"));
    cx.emit(crate::formats::embedded_as(
        "Module contents (ZIP)",
        input.nested(file.tail(4)),
        &crate::formats::archive::zip::FORMAT,
    ));
    cx.annotate("Java module");
    Ok(())
}

declare_format!(pub JIMAGE = "jimage", "Java runtime image (jimage)", ["jimage", "modules"], "application/x-java-jimage",
    Probe::Magic(&[(0, b"\xda\xda\xfe\xca")]), jimage);

record! {
    pub struct JimageHeader {
        magic: u32 "Magic" .hex(),
        minor: u16 "Minor version",
        major: u16 "Major version",
        flags: u32 "Flags" .hex(),
        resources: u32 "Resource count",
        table_length: u32 "Table length",
        locations_size: u32 "Locations size",
        strings_size: u32 "Strings size",
    }
}

async fn jimage(cx: Cx, input: Input) -> Result<()> {
    let h: JimageHeader = emit_record(&cx, input.span.sub(0, JimageHeader::SIZE), LE).await?;
    let index = JimageHeader::SIZE
        .saturating_add(u64::from(h.table_length).saturating_mul(8))
        .saturating_add(h.locations_size.into())
        .saturating_add(h.strings_size.into());
    cx.emit(
        Node::new("Index").span(
            input
                .span
                .sub(JimageHeader::SIZE, index.saturating_sub(JimageHeader::SIZE)),
        ),
    );
    cx.emit(Node::new("Resources").span(input.span.tail(index)));
    cx.annotate(format!(
        "jimage {}.{}, {} resources",
        h.major, h.minor, h.resources
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Classic Mac OS resource forks

fn rsrc_probe(h: &Head<'_>) -> bool {
    let (Some(data), Some(map), Some(data_len), Some(map_len)) = (
        u32_be(h.data, 0),
        u32_be(h.data, 4),
        u32_be(h.data, 8),
        u32_be(h.data, 12),
    ) else {
        return false;
    };
    data == 0x100
        && map_len >= 30
        && u64::from(map).saturating_add(map_len.into()) == h.len
        && u64::from(data).saturating_add(data_len.into()) <= u64::from(map)
}

declare_format!(pub MAC_RESOURCE = "mac-rsrc", "Mac OS resource fork", ["rsrc", "rsr"], "application/x-mac-resource",
    Probe::Custom(rsrc_probe), mac_rsrc);

async fn mac_rsrc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 16)).await?;
    let data = u64::from(u32_be(&head, 0).unwrap_or(0));
    let map = u64::from(u32_be(&head, 4).unwrap_or(0));
    cx.emit(Node::new("Header").span(file.sub(0, 16)));
    let map_head = cx.read(file.sub(map, 30)).await?;
    let types_offset = map.saturating_add(u16_be(&map_head, 24).unwrap_or(0).into());
    let names_offset = map.saturating_add(u16_be(&map_head, 26).unwrap_or(0).into());
    let count_bytes = cx.read(file.sub(types_offset, 2)).await?;
    let type_count = u16_be(&count_bytes, 0).unwrap_or(0).wrapping_add(1);
    let mut kinds = Vec::new();
    for i in 0..type_count.min(1024) {
        let at = types_offset
            .saturating_add(2)
            .saturating_add(u64::from(i).saturating_mul(8));
        let entry = cx.read(file.sub(at, 8)).await?;
        let kind = String::from_utf8_lossy(entry.get(..4).unwrap_or_default()).into_owned();
        let count = u16_be(&entry, 4).unwrap_or(0).wrapping_add(1);
        let refs = types_offset.saturating_add(u16_be(&entry, 6).unwrap_or(0).into());
        kinds.push(format!("{kind}×{count}"));
        cx.push(
            Node::new(kind.clone())
                .span(file.sub(at, 8))
                .summary(format!("{count} resource(s)"))
                .lazy(rsrc_refs, (input, refs, count, data, names_offset)),
        )
        .await;
    }
    let shown: Vec<String> = kinds.iter().take(12).cloned().collect();
    let more = if kinds.len() > 12 { ", …" } else { "" };
    cx.annotate(format!("resource fork: {}{more}", shown.join(", ")));
    Ok(())
}

async fn rsrc_refs(
    cx: Cx,
    (input, refs, count, data, names): (Input, u64, u16, u64, u64),
) -> Result<()> {
    let file = input.span;
    for i in 0..count.min(4096) {
        let at = refs.saturating_add(u64::from(i).saturating_mul(12));
        let entry = cx.read(file.sub(at, 12)).await?;
        let id = u16_be(&entry, 0).unwrap_or(0) as i16;
        let name_offset = u16_be(&entry, 2).unwrap_or(0xffff);
        let attrs = entry.get(4).copied().unwrap_or(0);
        let offset = u64::from(crate::bytes::u24_be(&entry, 5).unwrap_or(0));
        let len_bytes = cx.read(file.sub(data.saturating_add(offset), 4)).await?;
        let len = u64::from(u32_be(&len_bytes, 0).unwrap_or(0));
        let mut label = format!("#{id}");
        if name_offset != 0xffff {
            let n = cx
                .read(file.sub(names.saturating_add(name_offset.into()), 256))
                .await?;
            let l = usize::from(n.first().copied().unwrap_or(0));
            label = format!(
                "#{id} {:?}",
                crate::text::latin1(n.get(1..1usize.saturating_add(l)).unwrap_or_default())
            );
        }
        let body = file.sub(data.saturating_add(offset).saturating_add(4), len);
        cx.push(
            embedded(label, input.nested(body))
                .summary(format!("{len} bytes, attributes {attrs:#04x}"))
                .target(file.sub(at, 12)),
        )
        .await;
    }
    Ok(())
}
