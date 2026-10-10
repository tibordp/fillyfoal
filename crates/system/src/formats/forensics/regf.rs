//! Windows registry hives (`regf`): SYSTEM, SOFTWARE, NTUSER.DAT, ... and
//! their transaction logs (`.LOG`, `.LOG1`, `.LOG2`).
//!
//! A 4 KiB base block is followed by hive bins (`hbin`), which are carved
//! into cells (negative size: allocated; positive: free). Cell offsets are
//! relative to the first bin. The key tree is walked lazily from the root
//! key node (`nk`): subkeys come from index cells (`lf`, `lh`, `li`, and
//! `ri` over further lists), values from a value list of `vk` cells whose
//! data is stored inline (up to 4 bytes), in a data cell, or (hive 1.4 and
//! later, over 16 344 bytes) in segments listed by a big-data (`db`) cell.
//! Keys share security descriptors (`sk` cells, decoded with their ACLs).
//! The bin view lists every cell, including free ones, where deleted keys,
//! values and index lists often survive.
//!
//! Transaction logs start with a base block of their own; new-format logs
//! (Windows 8.1 and later) hold `HvLE` entries of dirty pages, old-format
//! ones a `DIRT` bitmap of dirty pages followed by the pages.

use std::sync::Arc;

use crate::bytes::{i32_le, to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::forensics::winsec::{KEY_RIGHTS, sd_summary, security_descriptor};
use crate::formats::util::datakit::{clip, hex, uint};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BINS: u64 = 0x1000;
const NO_CELL: u32 = u32::MAX;
const MAX_DEPTH: usize = 512;
/// Largest value data decoded into a node value.
const MAX_DATA: u64 = 0x4000;
/// Largest data stored in one cell before hive 1.4 switched to big data.
const BIG_DATA: u32 = 16344;

pub static FORMAT: Format = Format {
    name: "regf",
    title: "Windows registry hive",
    extensions: &["dat", "hve", "hiv", "log1", "log2"],
    mime: "application/x-windows-registry-hive",
    probe: Probe::Magic(&[(0, b"regf")]),
    dissect: crate::expander!(dissect: Input),
};

const FILE_TYPES: EnumTable = &[
    (0, "primary"),
    (1, "transaction log (old format)"),
    (2, "transaction log (old format, second)"),
    (6, "transaction log (new format)"),
];

const BASE_FLAGS: FlagTable = &[flag(0x1, "KTM_LOCKED"), flag(0x2, "DEFRAGMENTED")];

const BOOT_TYPES: EnumTable = &[
    (0, "normal"),
    (1, "boot-time recovery"),
    (2, "boot-time recovery (second)"),
];

const VALUE_TYPES: EnumTable = &[
    (0, "REG_NONE"),
    (1, "REG_SZ"),
    (2, "REG_EXPAND_SZ"),
    (3, "REG_BINARY"),
    (4, "REG_DWORD"),
    (5, "REG_DWORD_BIG_ENDIAN"),
    (6, "REG_LINK"),
    (7, "REG_MULTI_SZ"),
    (8, "REG_RESOURCE_LIST"),
    (9, "REG_FULL_RESOURCE_DESCRIPTOR"),
    (10, "REG_RESOURCE_REQUIREMENTS_LIST"),
    (11, "REG_QWORD"),
];

const KEY_FLAGS: FlagTable = &[
    flag(0x0001, "KEY_VOLATILE"),
    flag(0x0002, "KEY_HIVE_EXIT"),
    flag(0x0004, "KEY_HIVE_ENTRY"),
    flag(0x0008, "KEY_NO_DELETE"),
    flag(0x0010, "KEY_SYM_LINK"),
    flag(0x0020, "KEY_COMP_NAME"),
    flag(0x0040, "KEY_PREDEF_HANDLE"),
    flag(0x0080, "KEY_VIRT_MIRRORED"),
    flag(0x0100, "KEY_VIRT_TARGET"),
    flag(0x0200, "KEY_VIRTUAL_STORE"),
];

const VALUE_FLAGS: FlagTable = &[
    flag(0x0001, "VALUE_COMP_NAME"),
    flag(0x0002, "IS_TOMBSTONE"),
];

/// Upper bits of the "largest subkey name length" field (Windows 7+).
const VIRT_FLAGS: FlagTable = &[
    flag(0x1, "REG_KEY_DONT_VIRTUALIZE"),
    flag(0x2, "REG_KEY_DONT_SILENT_FAIL"),
    flag(0x4, "REG_KEY_RECURSE_FLAG"),
];

const LOG_ENTRY_FLAGS: FlagTable = &[flag(0x1, "BOOT_RECOVERY")];

record! {
    pub struct BaseBlock {
        signature: ascii[4] "Signature",
        primary_seq: u32 "Primary sequence number",
        secondary_seq: u32 "Secondary sequence number" .desc("Equal to the primary one when the hive was written completely"),
        written: u64 "Last written" .filetime(),
        major: u32 "Major version",
        minor: u32 "Minor version",
        file_type: u32 "File type" .enumeration(FILE_TYPES),
        file_format: u32 "File format" .desc("1 = direct memory load"),
        root: u32 "Root cell offset" .hex(),
        bins_size: u32 "Hive bins data size" .hex(),
        clustering: u32 "Clustering factor",
        file_name: utf16[32] "File name" .desc("Last 32 characters of the hive's path"),
        rm_id: guid "RmId" .desc("Resource manager GUID (Kernel Transaction Manager)"),
        log_id: guid "LogId",
        flags: u32 "Flags" .flags(BASE_FLAGS),
        tm_id: guid "TmId",
        guid_signature: ascii[4] "GUID signature" .desc("\"rmtm\" when the GUIDs above are set"),
        reorganized: u64 "Last reorganized" .filetime(),
    }
}

record! {
    pub struct BinHeader {
        signature: ascii[4] "Signature",
        offset: u32 "Offset" .hex() .desc("Relative to the first hive bin"),
        size: u32 "Size" .hex(),
        _reserved: u64 "Reserved",
        timestamp: u64 "Timestamp" .filetime() .desc("Meaningful in the first bin only: last reorganization"),
        spare: u32 "Spare",
    }
}

struct Hive {
    /// The hive bins region.
    bins: Span,
    /// Minor version (big data cells from 1.4).
    minor: u32,
}

type H = Arc<Hive>;

impl Hive {
    /// The data of the cell at `offset` (without its size field).
    async fn cell(&self, cx: &Cx, offset: u32) -> Result<Span> {
        if offset == NO_CELL {
            return Err(Diagnostic::malformed("null cell reference"));
        }
        let at = u64::from(offset);
        let size = cx.read(self.bins.sub_exact(at, 4)?).await?;
        let size = i32_le(&size, 0).unwrap_or(0).unsigned_abs();
        if size < 4 {
            return Err(
                Diagnostic::malformed(format!("cell at {offset:#x} has size {size}"))
                    .at(self.bins.sub(at, 4)),
            );
        }
        self.bins
            .sub_exact(at.saturating_add(4), u64::from(size).saturating_sub(4))
    }

    /// The whole cell at `offset`, size field included (for targets).
    fn whole(&self, data: Span) -> Span {
        Span::new(
            data.source,
            data.offset.saturating_sub(4),
            data.len.saturating_add(4),
        )
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let base_span = file.sub(0, BaseBlock::SIZE);
    let base = parse(&cx, base_span, LE, &(), BaseBlock::layout).await?;
    let checksum = base_checksum(&cx, file).await;
    // Transaction logs keep only the first 512 bytes of the base block.
    let base_len = if base.file_type == 0 { BINS } else { 512 };
    let mut base_node = Node::new("Base block")
        .span(file.sub(0, base_len))
        .summary(format!(
            "regf {}.{}, {}, sequence {}/{}",
            base.major,
            base.minor,
            lookup(FILE_TYPES, base.file_type.into()).unwrap_or("unknown type"),
            base.primary_seq,
            base.secondary_seq
        ))
        .lazy(base_block, file.sub(0, base_len));
    if let Some((stored, computed)) = checksum
        && stored != computed
    {
        base_node = base_node.diag(Diagnostic::warning(format!(
            "checksum mismatch: stored {stored:#010x}, computed {computed:#010x}"
        )));
    }
    cx.emit(base_node);
    let name = base
        .file_name
        .rsplit('\\')
        .next()
        .unwrap_or_default()
        .to_owned();

    if base.file_type != 0 {
        // A transaction log: the base block is followed by log data.
        let mut summary = format!(
            "registry transaction log {}.{} ({})",
            base.major,
            base.minor,
            lookup(FILE_TYPES, base.file_type.into()).unwrap_or("unknown type")
        );
        if !name.is_empty() {
            summary = format!("{summary}, {name}");
        }
        cx.annotate(summary);
        log_entries(&cx, file).await?;
        return Ok(());
    }

    let hive: H = Arc::new(Hive {
        bins: file.tail(BINS),
        minor: base.minor,
    });
    let mut summary = format!("registry hive {}.{}", base.major, base.minor);
    if !name.is_empty() {
        summary = format!("{summary}, {name}");
    }
    if base.primary_seq != base.secondary_seq {
        summary.push_str(", dirty (sequence numbers differ)");
    }
    match key_info(&cx, &hive, base.root).await {
        Ok(root) => {
            summary = format!(
                "{summary}, root {:?} ({} subkeys, {} values)",
                root.name, root.subkeys, root.values
            );
            cx.annotate(summary);
            cx.emit(key_node(&hive, base.root, &root, &[]));
        }
        Err(e) => {
            cx.annotate(summary);
            cx.emit(Node::new("Root key").diag(e));
        }
    }
    let declared = u64::from(base.bins_size);
    let mut bins_node = Node::new("Hive bins")
        .span(hive.bins.sub(0, declared))
        .summary(format!("{declared:#x} bytes"))
        .lazy(bins, (hive.clone(), declared));
    if hive.bins.len < declared {
        bins_node = bins_node.diag(Diagnostic::truncated(
            hive.bins.sub(0, declared),
            hive.bins.len,
        ));
    }
    cx.emit(bins_node);
    if hive.bins.len > declared {
        cx.emit(
            Node::new("Trailing data")
                .span(hive.bins.tail(declared))
                .summary(format!("{} bytes", hive.bins.len.saturating_sub(declared)))
                .desc("Bytes after the hive bins (often left over from a larger hive)"),
        );
    }
    Ok(())
}

/// (stored, computed) base block checksums: the XOR of the first 127
/// dwords, with 0 and 0xffffffff mapped to 1 and 0xfffffffe.
async fn base_checksum(cx: &Cx, file: Span) -> Option<(u32, u32)> {
    let data = cx.read(file.sub(0, 512)).await.ok()?;
    let stored = u32_le(&data, 508)?;
    let computed = data
        .as_chunks::<4>()
        .0
        .iter()
        .take(127)
        .fold(0u32, |acc, c| acc ^ u32::from_le_bytes(*c));
    let computed = match computed {
        0 => 1,
        u32::MAX => u32::MAX.saturating_sub(1),
        c => c,
    };
    Some((stored, computed))
}

async fn base_block(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, BaseBlock::SIZE)).await?;
    BaseBlock::read(&mut Fields::emitting(&cx, &block, LE))?;
    cx.emit(
        Node::new("Reserved")
            .span(span.sub(BaseBlock::SIZE, 508u64.saturating_sub(BaseBlock::SIZE))),
    );
    let check_span = span.sub(508, 4);
    if let Some((stored, computed)) = base_checksum(&cx, span).await {
        let node = Node::new("Checksum")
            .span(check_span)
            .value(hex(stored, 32))
            .desc("XOR of the first 127 dwords");
        cx.emit(if computed == stored {
            node.summary("valid")
        } else {
            node.diag(Diagnostic::warning(format!(
                "checksum mismatch: computed {computed:#010x}"
            )))
        });
    }
    if span.len >= BINS {
        cx.emit(Node::new("Reserved").span(span.sub(512, 0xdc8)));
        let tail = cx.block(span.sub(0xfc8, 0x38)).await?;
        let mut f = Fields::emitting(&cx, &tail, LE);
        f.guid("ThawTmId").emit()?;
        f.guid("ThawRmId").emit()?;
        f.guid("ThawLogId").emit()?;
        f.u32("Boot type").enumeration(BOOT_TYPES).emit()?;
        f.u32("Boot recover").emit()?;
    }
    Ok(())
}

/// What a key listing needs to know about a key node.
struct KeyInfo {
    span: Span,
    name: String,
    flags: u16,
    written: u64,
    parent: u32,
    subkeys: u32,
    subkey_list: u32,
    values: u32,
    value_list: u32,
    security: u32,
    class: u32,
    class_len: u16,
    name_len: u16,
}

async fn key_info(cx: &Cx, hive: &Hive, offset: u32) -> Result<KeyInfo> {
    let span = hive.cell(cx, offset).await?;
    let data = cx.read(span.sub(0, 0x4c)).await?;
    if data.get(..2) != Some(b"nk") {
        return Err(
            Diagnostic::malformed(format!("cell {offset:#x} is not a key node")).at(span.sub(0, 2)),
        );
    }
    let flags = u16_le(&data, 2).unwrap_or(0);
    let name_len = u16_le(&data, 0x48).unwrap_or(0);
    let name = cx.read(span.sub_exact(0x4c, name_len.into())?).await?;
    let name = if flags & 0x20 != 0 {
        crate::text::latin1(&name)
    } else {
        crate::text::utf16(&name, LE)
    };
    Ok(KeyInfo {
        span,
        name,
        flags,
        written: u64_le(&data, 4).unwrap_or(0),
        parent: u32_le(&data, 0x10).unwrap_or(NO_CELL),
        subkeys: u32_le(&data, 0x14).unwrap_or(0),
        subkey_list: u32_le(&data, 0x1c).unwrap_or(NO_CELL),
        values: u32_le(&data, 0x24).unwrap_or(0),
        value_list: u32_le(&data, 0x28).unwrap_or(NO_CELL),
        security: u32_le(&data, 0x2c).unwrap_or(NO_CELL),
        class: u32_le(&data, 0x30).unwrap_or(NO_CELL),
        class_len: u16_le(&data, 0x4a).unwrap_or(0),
        name_len,
    })
}

#[derive(Clone)]
struct Key {
    hive: H,
    offset: u32,
    /// Cell offsets of this key and its ancestors.
    path: Vec<u32>,
}

fn key_node(hive: &H, offset: u32, info: &KeyInfo, path: &[u32]) -> Node {
    let name = if info.name.is_empty() {
        "(unnamed)".to_owned()
    } else {
        clip(&info.name, 120)
    };
    let mut node = Node::new(name)
        .span(hive.whole(info.span))
        .value(Value::Timestamp {
            unix_seconds: crate::text::filetime_to_unix(info.written),
        })
        .summary(format!("{} subkeys, {} values", info.subkeys, info.values));
    if info.flags & 0x10 != 0 {
        node = node.desc("Symbolic link");
    }
    if path.contains(&offset) {
        return node.diag(Diagnostic::malformed("key is its own ancestor"));
    }
    if path.len() >= MAX_DEPTH {
        return node.diag(Diagnostic::limit(format!(
            "keys nested deeper than {MAX_DEPTH}"
        )));
    }
    let mut path = path.to_vec();
    path.push(offset);
    node.lazy(
        crate::expander!(self::key: Key),
        Key {
            hive: hive.clone(),
            offset,
            path,
        },
    )
}

/// Where a key node's references lead, for its fields' targets.
#[derive(Clone, Default)]
struct KeyRefs {
    parent: Option<Span>,
    subkey_list: Option<Span>,
    value_list: Option<Span>,
    security: Option<(Span, String)>,
    class: Option<(Span, String)>,
}

async fn key_refs(cx: &Cx, hive: &Hive, info: &KeyInfo) -> KeyRefs {
    let at = |o: u32| async move {
        if o == NO_CELL {
            None
        } else {
            hive.cell(cx, o).await.ok()
        }
    };
    let mut refs = KeyRefs {
        parent: at(info.parent).await.map(|s| hive.whole(s)),
        subkey_list: at(info.subkey_list).await.map(|s| hive.whole(s)),
        value_list: at(info.value_list).await.map(|s| hive.whole(s)),
        ..KeyRefs::default()
    };
    if let Some(sk) = at(info.security).await
        && let Ok(head) = cx.read(sk.sub(0, 0x14)).await
        && head.get(..2) == Some(b"sk")
    {
        let size = u32_le(&head, 0x10).unwrap_or(0);
        let sd = cx
            .read_avail(sk.sub(0x14, u64::from(size).min(0x10000)))
            .await
            .unwrap_or_default();
        refs.security = Some((hive.whole(sk), sd_summary(&sd)));
    }
    if info.class_len > 0
        && let Some(class) = at(info.class).await
    {
        let span = class.sub(0, info.class_len.into());
        let text = cx.read_avail(span).await.unwrap_or_default();
        refs.class = Some((span, crate::text::utf16(&text, LE)));
    }
    refs
}

async fn key(cx: Cx, k: Key) -> Result<()> {
    let hive = &k.hive;
    let info = key_info(&cx, hive, k.offset).await?;
    let refs = key_refs(&cx, hive, &info).await;
    let nk = info
        .span
        .sub(0, 0x4c_u64.saturating_add(info.name_len.into()));
    cx.emit(struct_node(
        "Key node",
        nk,
        LE,
        refs.clone(),
        key_node_fields,
    ));
    if let Some((span, class)) = &refs.class {
        cx.emit(
            Node::new("Class name")
                .span(*span)
                .value(Value::Text(class.clone())),
        );
    }
    if info.values > 0 {
        let mut node = Node::new("Values")
            .value(uint(info.values, 32))
            .lazy(values, (hive.clone(), info.value_list, info.values));
        if let Ok(list) = hive.cell(&cx, info.value_list).await {
            node = node.span(list.sub(0, u64::from(info.values).saturating_mul(4)));
        }
        cx.emit(node);
    }
    if info.subkeys == 0 {
        return Ok(());
    }
    // Index cells, walked depth-first (an `ri` refers to further lists).
    let mut stack = vec![(info.subkey_list, 0u32)];
    let mut emitted = 0u32;
    while let Some((list, index)) = stack.pop() {
        if stack.len() > 8 {
            return Err(Diagnostic::limit("subkey index nested too deeply"));
        }
        let span = hive.cell(&cx, list).await?;
        let head = cx.read(span.sub_exact(0, 4)?).await?;
        let sig = head.get(..2).unwrap_or_default().to_vec();
        let count = u32::from(u16_le(&head, 2).unwrap_or(0));
        if index >= count {
            continue;
        }
        let stride: u64 = match sig.as_slice() {
            b"lf" | b"lh" => 8,
            b"li" | b"ri" => 4,
            _ => {
                return Err(Diagnostic::malformed("unknown subkey index cell").at(span.sub(0, 2)));
            }
        };
        stack.push((list, index.saturating_add(1)));
        let at = 4u64.saturating_add(u64::from(index).saturating_mul(stride));
        let entry = cx.read(span.sub_exact(at, 4)?).await?;
        let child = u32_le(&entry, 0).unwrap_or(NO_CELL);
        if sig == b"ri" {
            stack.push((child, 0));
            continue;
        }
        let node = match key_info(&cx, hive, child).await {
            Ok(info) => key_node(hive, child, &info, &k.path),
            Err(e) => Node::new(format!("Key at {child:#x}")).diag(e),
        };
        cx.push(node).await;
        emitted = emitted.saturating_add(1);
    }
    if emitted != info.subkeys {
        cx.diag(Diagnostic::warning(format!(
            "key node announces {} subkeys, index lists {emitted}",
            info.subkeys
        )));
    }
    Ok(())
}

fn key_node_fields(f: &mut Fields<'_>, refs: &KeyRefs) -> Result<()> {
    let target = |node: Node, t: Option<Span>| match t {
        Some(t) => node.target(t),
        None => node,
    };
    f.ascii("Signature", 2).emit()?;
    let flags = f.u16("Flags").flags(KEY_FLAGS).emit()?;
    f.u64("Last written").filetime().emit()?;
    f.u32("Access bits")
        .hex()
        .desc("Windows 8+: 0x1 accessed before boot completed, 0x2 after")
        .emit()?;
    f.u32("Parent")
        .hex()
        .with(|_, n| target(n, refs.parent))
        .emit()?;
    f.u32("Subkeys").emit()?;
    f.u32("Volatile subkeys").emit()?;
    f.u32("Subkey list")
        .hex()
        .with(|_, n| target(n, refs.subkey_list))
        .emit()?;
    f.u32("Volatile subkey list").hex().emit()?;
    f.u32("Values").emit()?;
    f.u32("Value list")
        .hex()
        .with(|_, n| target(n, refs.value_list))
        .emit()?;
    f.u32("Security")
        .hex()
        .with(|_, n| match &refs.security {
            Some((span, summary)) => n.target(*span).summary(summary.clone()),
            None => n,
        })
        .emit()?;
    f.u32("Class name offset")
        .hex()
        .with(|_, n| match &refs.class {
            Some((span, _)) => n.target(*span),
            None => n,
        })
        .emit()?;
    f.u32("Largest subkey name length")
        .with(|&v, n| {
            let upper = v >> 16;
            if upper == 0 {
                n
            } else {
                let (set, _) = crate::value::decode_flags(VIRT_FLAGS, u64::from(upper & 0xf));
                n.summary(format!(
                    "name length {} bytes, virtualization flags {:#x} [{}], user flags {:#x}",
                    v & 0xffff,
                    upper & 0xf,
                    set.join(" | "),
                    (upper >> 4) & 0xf
                ))
            }
        })
        .emit()?;
    f.u32("Largest subkey class length").emit()?;
    f.u32("Largest value name length").emit()?;
    f.u32("Largest value data size").emit()?;
    f.u32("WorkVar").emit()?;
    let len = f.u16("Key name length").emit()?;
    f.u16("Class name length").emit()?;
    if flags & 0x20 != 0 {
        f.ascii("Key name", len.into()).emit()?;
    } else {
        f.utf16("Key name", u64::from(len / 2)).emit()?;
    }
    Ok(())
}

async fn values(cx: Cx, (hive, list, count): (H, u32, u32)) -> Result<()> {
    let span = hive.cell(&cx, list).await?;
    let table = span.sub_exact(0, u64::from(count).saturating_mul(4))?;
    cx.set_count(Count::Exact(count.into()));
    for i in 0..u64::from(count) {
        let entry = cx.read(table.sub(i.saturating_mul(4), 4)).await?;
        let offset = u32_le(&entry, 0).unwrap_or(NO_CELL);
        let node = match value_node(&cx, &hive, offset).await {
            Ok(n) => n,
            Err(e) => Node::new(format!("Value at {offset:#x}")).diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}

/// Where a value's data lives: one span (inline or a data cell), or the
/// segments of a big-data cell gathered into a piece source.
struct Data {
    span: Span,
    /// The `db` cell, for big data.
    big: Option<Span>,
    inline: bool,
}

async fn value_data(cx: &Cx, hive: &Hive, vk: Span, size: u32, offset: u32) -> Result<Data> {
    if size & 0x8000_0000 != 0 {
        // Small data is stored in the offset field itself.
        return Ok(Data {
            span: vk.sub(0x08, u64::from(size & 0x7fff_ffff).min(4)),
            big: None,
            inline: true,
        });
    }
    let cell = hive.cell(cx, offset).await?;
    let head = cx.read_avail(cell.sub(0, 8)).await?;
    if head.get(..2) == Some(b"db") && size > BIG_DATA && hive.minor >= 4 {
        let segments = u16_le(&head, 2).unwrap_or(0);
        let list = u32_le(&head, 4).unwrap_or(NO_CELL);
        let list = hive.cell(cx, list).await?;
        let offsets = cx
            .read(list.sub_exact(0, u64::from(segments).saturating_mul(4))?)
            .await?;
        let mut pieces = Vec::new();
        let mut left = u64::from(size);
        for o in offsets.as_chunks::<4>().0 {
            cx.checkpoint().await;
            if left == 0 {
                break;
            }
            let seg = hive.cell(cx, u32_le(o, 0).unwrap_or(NO_CELL)).await?;
            let take = left.min(seg.len).min(u64::from(BIG_DATA));
            pieces.push(seg.sub(0, take));
            left = left.saturating_sub(take);
        }
        if left > 0 {
            return Err(Diagnostic::malformed(format!(
                "big data segments hold {left} bytes too few"
            ))
            .at(hive.whole(cell)));
        }
        let span = cx.add_pieces(
            Origin {
                parent: hive.whole(cell),
                transform: "regf-big-data",
            },
            pieces,
        )?;
        return Ok(Data {
            span,
            big: Some(cell),
            inline: false,
        });
    }
    Ok(Data {
        span: cell.sub(0, size.into()),
        big: None,
        inline: false,
    })
}

/// A value's data as a node value, by type.
fn data_value(kind: u32, bytes: &[u8]) -> Value {
    match kind {
        1 | 2 | 6 => Value::Text(crate::text::utf16z(bytes, LE).0),
        7 => Value::Text(multi_sz(bytes).join(" | ")),
        4 if bytes.len() >= 4 => uint(u32_le(bytes, 0).unwrap_or(0), 32),
        5 if bytes.len() >= 4 => uint(crate::bytes::u32_be(bytes, 0).unwrap_or(0), 32),
        11 if bytes.len() >= 8 => uint(u64_le(bytes, 0).unwrap_or(0), 64),
        _ => Value::Bytes(bytes.get(..32).unwrap_or(bytes).to_vec()),
    }
}

/// The strings of a REG_MULTI_SZ (empty strings at the end dropped).
fn multi_sz(bytes: &[u8]) -> Vec<String> {
    let text = crate::text::utf16(bytes, LE);
    let mut strings: Vec<String> = text.split('\0').map(str::to_owned).collect();
    while strings.last().is_some_and(String::is_empty) {
        strings.pop();
    }
    strings
}

async fn value_node(cx: &Cx, hive: &H, offset: u32) -> Result<Node> {
    let vk = hive.cell(cx, offset).await?;
    let head = cx.read(vk.sub_exact(0, 0x14)?).await?;
    if head.get(..2) != Some(b"vk") {
        return Err(Diagnostic::malformed("not a value cell").at(vk.sub(0, 2)));
    }
    let name_len = u16_le(&head, 2).unwrap_or(0);
    let size = u32_le(&head, 4).unwrap_or(0);
    let data_offset = u32_le(&head, 8).unwrap_or(NO_CELL);
    let kind = u32_le(&head, 0x0c).unwrap_or(0);
    let flags = u16_le(&head, 0x10).unwrap_or(0);
    let name = cx.read(vk.sub_exact(0x14, name_len.into())?).await?;
    let name = if flags & 1 != 0 {
        crate::text::latin1(&name)
    } else {
        crate::text::utf16(&name, LE)
    };
    let name = if name.is_empty() {
        "(default)".to_owned()
    } else {
        clip(&name, 120)
    };
    let type_name =
        lookup(VALUE_TYPES, kind.into()).map_or_else(|| format!("type {kind:#x}"), str::to_owned);
    let mut node = Node::new(name).span(hive.whole(vk));
    let vk_fields = vk.sub(0, 0x14u64.saturating_add(name_len.into()));
    let data = match value_data(cx, hive, vk, size, data_offset).await {
        Ok(d) => d,
        Err(e) => {
            return Ok(node
                .summary(type_name)
                .diag(e)
                .lazy(value_fields, (vk_fields, None, None, kind)));
        }
    };
    let bytes = cx.read_avail(data.span.sub(0, MAX_DATA)).await?;
    let mut summary = format!("{type_name}, {} bytes", size & 0x7fff_ffff);
    if data.big.is_some() {
        summary.push_str(" in big data segments");
    } else if data.inline {
        summary.push_str(" inline");
    }
    node = node.value(data_value(kind, &bytes)).summary(summary).lazy(
        value_fields,
        (
            vk_fields,
            Some(data.span),
            data.big.map(|b| hive.whole(b)),
            kind,
        ),
    );
    Ok(node)
}

async fn value_fields(
    cx: Cx,
    (vk, data, big, kind): (Span, Option<Span>, Option<Span>, u32),
) -> Result<()> {
    let block = cx.block(vk).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("Signature", 2).emit()?;
    let len = f.u16("Name length").emit()?;
    f.u32("Data size")
        .hex()
        .with(|&s, n| {
            if s & 0x8000_0000 != 0 {
                n.summary(format!("{} bytes, stored inline", s & 0x7fff_ffff))
            } else {
                n.summary(format!("{s} bytes"))
            }
        })
        .emit()?;
    f.u32("Data offset")
        .hex()
        .with(|_, n| match (data, big) {
            (_, Some(b)) => n.target(b),
            (Some(d), None) if d.offset != vk.offset.saturating_add(8) => n.target(d),
            _ => n,
        })
        .emit()?;
    f.u32("Data type").enumeration(VALUE_TYPES).emit()?;
    let flags = f.u16("Flags").flags(VALUE_FLAGS).emit()?;
    f.u16("Spare").emit()?;
    if flags & 1 != 0 {
        f.ascii("Value name", len.into()).emit()?;
    } else {
        f.utf16("Value name", u64::from(len / 2)).emit()?;
    }
    if let Some(data) = data {
        let mut node = Node::new("Data")
            .span(data)
            .summary(format!("{} bytes", data.len));
        let bytes = cx.read_avail(data.sub(0, MAX_DATA)).await?;
        node = node.value(data_value(kind, &bytes));
        if kind == 7 {
            node = node.lazy(multi_sz_strings, data);
        }
        cx.emit(node);
    }
    Ok(())
}

/// The strings of a REG_MULTI_SZ value, with their spans.
async fn multi_sz_strings(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, MAX_DATA)).await?;
    let mut pos = 0usize;
    let mut i = 0u32;
    while pos < data.len() {
        cx.checkpoint().await;
        let rest = data.get(pos..).unwrap_or_default();
        let (text, len, _) = crate::text::utf16z(rest, LE);
        if text.is_empty() {
            // The terminating empty string (and any padding).
            cx.emit(
                Node::new("Terminator")
                    .span(span.sub(to_u64(pos), to_u64(rest.len())))
                    .value(Value::Text(String::new())),
            );
            break;
        }
        cx.emit(
            Node::new(format!("String {i}"))
                .span(span.sub(to_u64(pos), to_u64(len)))
                .value(Value::Text(text)),
        );
        pos = pos.saturating_add(len.max(2));
        i = i.saturating_add(1);
    }
    Ok(())
}

/// Hive bins, listed in pages.
async fn bins(cx: Cx, (hive, declared): (H, u64)) -> Result<()> {
    let region = hive.bins.sub(0, declared);
    let mut pos = 0u64;
    while pos < region.len {
        cx.progress_in(region, region.offset.saturating_add(pos));
        let h = parse(
            &cx,
            region.sub(pos, BinHeader::SIZE),
            LE,
            &(),
            BinHeader::layout,
        )
        .await?;
        if h.signature != "hbin" {
            return Err(Diagnostic::malformed("expected a hive bin").at(region.sub(pos, 4)));
        }
        if h.size < 0x20 || !u64::from(h.size).is_multiple_of(0x1000) {
            return Err(
                Diagnostic::malformed(format!("bad hive bin size {:#x}", h.size))
                    .at(region.sub(pos, 0x20)),
            );
        }
        let span = region.sub(pos, h.size.into());
        let mut node = Node::new(format!("hbin {pos:#x}"))
            .span(span)
            .summary(format!("{:#x} bytes", h.size))
            .lazy(cells, (hive.clone(), span, pos));
        if u64::from(h.offset) != pos {
            node = node.diag(Diagnostic::warning(format!(
                "bin says it is at {:#x}",
                h.offset
            )));
        }
        cx.push(node).await;
        pos = pos.saturating_add(h.size.into());
    }
    Ok(())
}

const CELL_TYPES: EnumTable = &[
    (u16::from_le_bytes(*b"nk") as u64, "key node"),
    (u16::from_le_bytes(*b"vk") as u64, "value"),
    (u16::from_le_bytes(*b"sk") as u64, "security descriptor"),
    (u16::from_le_bytes(*b"lf") as u64, "subkey index (lf)"),
    (u16::from_le_bytes(*b"lh") as u64, "subkey index (lh)"),
    (u16::from_le_bytes(*b"li") as u64, "subkey index (li)"),
    (u16::from_le_bytes(*b"ri") as u64, "index root (ri)"),
    (u16::from_le_bytes(*b"db") as u64, "big data"),
];

/// The cells of one bin.
async fn cells(cx: Cx, (hive, bin, base): (H, Span, u64)) -> Result<()> {
    cx.emit(BinHeader::node("Header", bin.sub(0, BinHeader::SIZE), LE));
    let data = cx.read_avail(bin).await?;
    let mut pos = BinHeader::SIZE;
    while pos.saturating_add(4) <= to_u64(data.len()) {
        let at = to_usize(pos);
        let size = i32_le(&data, at).unwrap_or(0);
        let len = u64::from(size.unsigned_abs());
        if len < 8 || !len.is_multiple_of(8) {
            return Err(Diagnostic::malformed(format!("bad cell size {size}")).at(bin.sub(pos, 4)));
        }
        let sig = u16_le(&data, at.saturating_add(4)).unwrap_or(0);
        let span = bin.sub(pos, len);
        let offset = base.saturating_add(pos);
        let body = data
            .get(at.saturating_add(4)..at.saturating_add(to_usize(len)))
            .unwrap_or_default();
        let node = cell_node(&hive, offset, span, size < 0, sig, body);
        cx.push(node).await;
        pos = pos.saturating_add(len);
    }
    Ok(())
}

/// One cell of the bin listing. Key and value cells that the key tree
/// shows are leaves here; structures it does not show (security
/// descriptors, index lists, big data) and free cells that still look like
/// structures (deleted keys and values) are decoded.
fn cell_node(hive: &H, offset: u64, span: Span, allocated: bool, sig: u16, body: &[u8]) -> Node {
    let len = span.len;
    let kind = lookup(CELL_TYPES, sig.into());
    let data = span.tail(4);
    let mut node = Node::new(format!("Cell {offset:#x}")).span(span);
    let Some(kind) = kind else {
        return if allocated {
            node.summary(format!("data, {len} bytes"))
        } else {
            node.summary(format!("free, {len} bytes"))
                .desc("Unallocated cell (slack)")
        };
    };
    let state = if allocated { "" } else { "free, " };
    let sig2 = body.get(..2).unwrap_or_default();
    match sig2 {
        b"nk" => {
            let name = nk_name(body);
            node = node
                .value(Value::Text(name.clone()))
                .summary(format!("{state}key node, {len} bytes"));
            if !allocated {
                let name_len = u16_le(body, 0x48).unwrap_or(0);
                node = node.desc("Deleted key node").lazy(
                    deleted_key,
                    (data.sub(0, 0x4cu64.saturating_add(name_len.into())), ()),
                );
            }
        }
        b"vk" => {
            let name_len = u16_le(body, 2).unwrap_or(0);
            let flags = u16_le(body, 0x10).unwrap_or(0);
            let raw = body
                .get(0x14..0x14usize.saturating_add(name_len.into()))
                .unwrap_or_default();
            let name = if flags & 1 != 0 {
                crate::text::latin1(raw)
            } else {
                crate::text::utf16(raw, LE)
            };
            let kind = u32_le(body, 0x0c).unwrap_or(0);
            node = node
                .value(Value::Text(if name.is_empty() {
                    "(default)".to_owned()
                } else {
                    clip(&name, 120)
                }))
                .summary(format!(
                    "{state}value, {}",
                    lookup(VALUE_TYPES, kind.into()).unwrap_or("unknown type")
                ));
            if !allocated {
                let vk = data.sub(0, 0x14u64.saturating_add(name_len.into()));
                node = node
                    .desc("Deleted value")
                    .lazy(value_fields, (vk, None, None, kind));
            }
        }
        b"sk" => {
            let refs = u32_le(body, 0x0c).unwrap_or(0);
            let sd = body.get(0x14..).unwrap_or_default();
            node = node
                .value(Value::Text(sd_summary(sd)))
                .summary(format!("{state}security descriptor, {refs} references"))
                .lazy(sk_cell, (hive.clone(), data));
        }
        b"lf" | b"lh" | b"li" | b"ri" | b"db" => {
            let count = u16_le(body, 2).unwrap_or(0);
            node = node
                .value(Value::UInt {
                    value: count.into(),
                    bits: 16,
                    radix: crate::value::Radix::Dec,
                })
                .summary(format!("{state}{kind}, {len} bytes"))
                .lazy(index_cell, (hive.clone(), data, allocated));
        }
        _ => {}
    }
    node
}

fn nk_name(body: &[u8]) -> String {
    let flags = u16_le(body, 2).unwrap_or(0);
    let len = u16_le(body, 0x48).unwrap_or(0);
    let raw = body
        .get(0x4c..0x4cusize.saturating_add(len.into()))
        .unwrap_or_default();
    let name = if flags & 0x20 != 0 {
        crate::text::latin1(raw)
    } else {
        crate::text::utf16(raw, LE)
    };
    clip(&name, 120)
}

async fn deleted_key(cx: Cx, (span, _): (Span, ())) -> Result<()> {
    let block = cx.block(span).await?;
    key_node_fields(&mut Fields::emitting(&cx, &block, LE), &KeyRefs::default())
}

async fn sk_cell(cx: Cx, (hive, data): (H, Span)) -> Result<()> {
    let block = cx.block(data.sub(0, 0x14)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("Signature", 2).emit()?;
    f.u16("Reserved").emit()?;
    for name in ["Flink", "Blink"] {
        let at = f.peek_span(4);
        let o = f.u32(name).get()?;
        let mut n = Node::new(name).span(at).value(hex(o, 32));
        if let Ok(target) = hive.cell(&cx, o).await {
            n = n.target(hive.whole(target));
        }
        cx.emit(n.desc("Next/previous security descriptor in the hive's list"));
    }
    f.u32("Reference count")
        .desc("Number of keys using this descriptor")
        .emit()?;
    let size = f.u32("Descriptor size").emit()?;
    let sd = data.sub(0x14, size.into());
    cx.emit(
        Node::new("Security descriptor")
            .span(sd)
            .lazy(security_descriptor, (sd, KEY_RIGHTS)),
    );
    Ok(())
}

/// An index or big-data cell's fields and entries.
async fn index_cell(cx: Cx, (hive, data, _allocated): (H, Span, bool)) -> Result<()> {
    let head = cx.block(data.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let sig = f.ascii("Signature", 2).emit()?;
    let count = f
        .u16(if sig == "db" { "Segments" } else { "Count" })
        .emit()?;
    if sig == "db" {
        let block = cx.block(data.sub(4, 4)).await?;
        let list = Fields::new(&block, LE).u32("Segment list").get()?;
        let mut n = Node::new("Segment list")
            .span(data.sub(4, 4))
            .value(hex(list, 32));
        if let Ok(cell) = hive.cell(&cx, list).await {
            let table = cell.sub(0, u64::from(count).saturating_mul(4));
            n = n
                .target(hive.whole(cell))
                .lazy(segment_list, (hive.clone(), table));
        }
        cx.emit(n);
        return Ok(());
    }
    let stride: u64 = if matches!(sig.as_str(), "lf" | "lh") {
        8
    } else {
        4
    };
    let table = data.sub(4, u64::from(count).saturating_mul(stride));
    let entries = cx.read_avail(table).await?;
    if to_u64(entries.len()) < table.len {
        cx.diag(Diagnostic::truncated(table, to_u64(entries.len())));
    }
    for (i, e) in entries.chunks_exact(to_usize(stride)).enumerate() {
        cx.checkpoint().await;
        let offset = u32_le(e, 0).unwrap_or(NO_CELL);
        let at = table.sub(to_u64(i).saturating_mul(stride), stride);
        let mut n = Node::new(format!("Entry {i}"))
            .span(at)
            .value(hex(offset, 32));
        let mut summary = Vec::new();
        if let Ok(cell) = hive.cell(&cx, offset).await {
            n = n.target(hive.whole(cell));
            if sig != "ri"
                && let Ok(head) = cx.read_avail(cell.sub(0, 0x4c)).await
                && head.get(..2) == Some(b"nk")
            {
                let len = u16_le(&head, 0x48).unwrap_or(0);
                let name = cx
                    .read_avail(cell.sub(0x4c, len.into()))
                    .await
                    .unwrap_or_default();
                let mut body = head.clone();
                body.extend_from_slice(&name);
                summary.push(nk_name(&body));
            }
        }
        match sig.as_str() {
            "lf" => {
                let hint = e.get(4..8).unwrap_or_default();
                summary.push(format!(
                    "hint {:?}",
                    String::from_utf8_lossy(hint).trim_end_matches('\0')
                ));
            }
            "lh" => summary.push(format!("hash {:#010x}", u32_le(e, 4).unwrap_or(0))),
            _ => {}
        }
        if !summary.is_empty() {
            n = n.summary(summary.join(", "));
        }
        cx.emit(n);
    }
    Ok(())
}

async fn segment_list(cx: Cx, (hive, table): (H, Span)) -> Result<()> {
    let data = cx.read_avail(table).await?;
    for (i, o) in data.as_chunks::<4>().0.iter().enumerate() {
        cx.checkpoint().await;
        let offset = u32_le(o, 0).unwrap_or(NO_CELL);
        let mut n = Node::new(format!("Segment {i}"))
            .span(table.sub(to_u64(i).saturating_mul(4), 4))
            .value(hex(offset, 32));
        if let Ok(cell) = hive.cell(&cx, offset).await {
            n = n
                .target(hive.whole(cell))
                .summary(format!("{} bytes", cell.len));
        }
        cx.emit(n);
    }
    Ok(())
}

record! {
    pub struct LogEntryHeader {
        signature: ascii[4] "Signature",
        size: u32 "Size" .hex(),
        flags: u32 "Flags" .flags(LOG_ENTRY_FLAGS),
        sequence: u32 "Sequence number",
        bins_size: u32 "Hive bins data size" .hex(),
        dirty: u32 "Dirty pages count",
        hash1: u64 "Hash-1" .hex() .desc("Marvin32 hash of the dirty page references and pages"),
        hash2: u64 "Hash-2" .hex() .desc("Marvin32 hash of the first 32 bytes of this entry"),
    }
}

/// The log data after a transaction log's base block.
async fn log_entries(cx: &Cx, file: Span) -> Result<()> {
    let mut pos = 0x200u64;
    let head = cx.read_avail(file.sub(pos, 4)).await?;
    if head == b"DIRT" {
        // Old format: a bitmap of dirty 512-byte pages, then the pages.
        let bins_size = u32_le(&cx.read(file.sub(0x28, 4)).await?, 0).unwrap_or(0);
        let pages = u64::from(bins_size) / 512;
        let bitmap_len = pages.div_ceil(8);
        let bitmap = file.sub(pos.saturating_add(4), bitmap_len);
        let bits = cx.read_avail(bitmap).await?;
        let dirty: u64 = bits.iter().map(|b| u64::from(b.count_ones())).sum();
        cx.emit(
            Node::new("Dirty vector")
                .span(file.sub(pos, bitmap_len.saturating_add(4)))
                .value(uint(dirty, 64))
                .summary(format!("{dirty} of {pages} pages dirty")),
        );
        let start = pos
            .saturating_add(4)
            .saturating_add(bitmap_len)
            .next_multiple_of(512);
        cx.emit(
            Node::new("Dirty pages")
                .span(file.tail(start).sub(0, dirty.saturating_mul(512)))
                .summary(format!("{dirty} pages of 512 bytes, in bitmap order")),
        );
        return Ok(());
    }
    let mut index = 0u32;
    while pos < file.len {
        cx.progress_in(file, file.offset.saturating_add(pos));
        let at = file.sub(pos, LogEntryHeader::SIZE);
        let Ok(h) = parse(cx, at, LE, &(), LogEntryHeader::layout).await else {
            break;
        };
        if h.signature != "HvLE" {
            if index == 0 {
                cx.emit(
                    Node::new("Log data")
                        .span(file.tail(pos))
                        .diag(Diagnostic::unsupported("unrecognised transaction log data")),
                );
            } else {
                cx.push(
                    Node::new("Unused")
                        .span(file.tail(pos))
                        .summary("after the last log entry"),
                )
                .await;
            }
            break;
        }
        if h.size < 40 || !u64::from(h.size).is_multiple_of(512) {
            cx.diag(Diagnostic::malformed(format!("bad log entry size {:#x}", h.size)).at(at));
            break;
        }
        let span = file.sub(pos, h.size.into());
        cx.push(
            Node::new(format!("Log entry {index}"))
                .span(span)
                .summary(format!(
                    "sequence {}, {} dirty pages, {} bytes",
                    h.sequence, h.dirty, h.size
                ))
                .lazy(log_entry, span),
        )
        .await;
        pos = pos.saturating_add(h.size.into());
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn log_entry(cx: Cx, span: Span) -> Result<()> {
    let h = parse(
        &cx,
        span.sub(0, LogEntryHeader::SIZE),
        LE,
        &(),
        LogEntryHeader::layout,
    )
    .await?;
    cx.emit(LogEntryHeader::node(
        "Header",
        span.sub(0, LogEntryHeader::SIZE),
        LE,
    ));
    let refs = span.sub(LogEntryHeader::SIZE, u64::from(h.dirty).saturating_mul(8));
    let table = cx.read_avail(refs).await?;
    let mut data_at = LogEntryHeader::SIZE.saturating_add(refs.len);
    for (i, r) in table.as_chunks::<8>().0.iter().enumerate() {
        cx.checkpoint().await;
        let offset = u32_le(r, 0).unwrap_or(0);
        let size = u32_le(r, 4).unwrap_or(0);
        let page = span.sub(data_at, size.into());
        cx.emit(
            Node::new(format!("Dirty page {i}"))
                .span(refs.sub(to_u64(i).saturating_mul(8), 8))
                .value(hex(offset, 32))
                .summary(format!("{size:#x} bytes at hive bins offset {offset:#x}"))
                .target(page),
        );
        data_at = data_at.saturating_add(size.into());
    }
    let pages = span.sub(
        LogEntryHeader::SIZE.saturating_add(refs.len),
        data_at.saturating_sub(LogEntryHeader::SIZE.saturating_add(refs.len)),
    );
    if pages.len > 0 {
        cx.emit(
            Node::new("Dirty pages")
                .span(pages)
                .summary(format!("{} bytes", pages.len))
                .desc("Page contents to write back into the hive bins"),
        );
    }
    if data_at < span.len {
        cx.emit(
            Node::new("Padding")
                .span(span.tail(data_at))
                .desc("Up to the next multiple of 512 bytes"),
        );
    }
    Ok(())
}
