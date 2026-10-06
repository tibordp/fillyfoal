//! Windows registry hives (`regf`): SYSTEM, SOFTWARE, NTUSER.DAT, ...
//!
//! A 4 KiB base block is followed by hive bins (`hbin`), which are carved
//! into cells. Cell offsets are relative to the first bin. The key tree is
//! walked lazily from the root key node (`nk`): subkeys come from index
//! cells (`lf`, `lh`, `li`, `ri`), values from a value list of `vk` cells.

use std::sync::Arc;

use crate::bytes::{i32_le, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::datakit::{clip, enumv, uint};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BINS: u64 = 0x1000;
const NO_CELL: u32 = u32::MAX;
const MAX_DEPTH: usize = 512;
/// Largest value data decoded into a node value.
const MAX_DATA: u64 = 0x4000;

pub static FORMAT: Format = Format {
    name: "regf",
    title: "Windows registry hive",
    extensions: &["dat", "hve", "hiv"],
    mime: "application/x-windows-registry-hive",
    probe: Probe::Magic(&[(0, b"regf")]),
    dissect: crate::expander!(dissect: Input),
};

const FILE_TYPES: EnumTable = &[
    (0, "primary"),
    (1, "transaction log (old)"),
    (2, "transaction log"),
    (6, "transaction log (new)"),
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

record! {
    pub struct BaseBlock {
        signature: ascii[4] "Signature",
        primary_seq: u32 "Primary sequence number",
        secondary_seq: u32 "Secondary sequence number",
        written: u64 "Last written" .filetime(),
        major: u32 "Major version",
        minor: u32 "Minor version",
        file_type: u32 "File type" .enumeration(FILE_TYPES),
        file_format: u32 "File format" .desc("1 = direct memory load"),
        root: u32 "Root cell offset" .hex(),
        bins_size: u32 "Hive bins data size" .hex(),
        clustering: u32 "Clustering factor",
        file_name: utf16[32] "File name" .desc("Last 32 characters of the hive's path"),
    }
}

record! {
    pub struct BinHeader {
        signature: ascii[4] "Signature",
        offset: u32 "Offset" .hex() .desc("Relative to the first hive bin"),
        size: u32 "Size" .hex(),
        _reserved: u64 "Reserved",
        timestamp: u64 "Timestamp" .filetime(),
        spare: u32 "Spare",
    }
}

struct Hive {
    /// The hive bins region.
    bins: Span,
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
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let base_span = file.sub(0, BaseBlock::SIZE);
    let base = parse(&cx, base_span, LE, &(), BaseBlock::layout).await?;
    cx.emit(
        Node::new("Base block")
            .span(file.sub(0, BINS))
            .lazy(base_block, file.sub(0, BINS)),
    );
    let hive: H = Arc::new(Hive {
        bins: file.tail(BINS),
    });
    let name = base
        .file_name
        .rsplit('\\')
        .next()
        .unwrap_or_default()
        .to_owned();
    let mut summary = format!("registry hive {}.{}", base.major, base.minor);
    if !name.is_empty() {
        summary = format!("{summary}, {name}");
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
    cx.emit(
        Node::new("Hive bins")
            .span(hive.bins)
            .summary(format!("{:#x} bytes", hive.bins.len))
            .lazy(bins, hive.clone()),
    );
    Ok(())
}

async fn base_block(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, BaseBlock::SIZE)).await?;
    BaseBlock::read(&mut Fields::emitting(&cx, &block, LE))?;
    let data = cx.read_avail(span.sub(0, 512)).await?;
    let check_span = span.sub(508, 4);
    if let Some(stored) = u32_le(&data, 508) {
        let computed = data
            .as_chunks::<4>()
            .0
            .iter()
            .take(127)
            .fold(0u32, |acc, c| acc ^ u32::from_le_bytes(*c));
        let node = Node::new("Checksum")
            .span(check_span)
            .value(crate::formats::util::datakit::hex(stored, 32));
        cx.emit(if computed == stored {
            node.summary("valid")
        } else {
            node.diag(Diagnostic::warning(format!(
                "checksum mismatch: computed {computed:#010x}"
            )))
        });
    }
    Ok(())
}

/// What a key listing needs to know about a key node.
struct KeyInfo {
    span: Span,
    name: String,
    flags: u16,
    written: u64,
    subkeys: u32,
    subkey_list: u32,
    values: u32,
    value_list: u32,
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
        subkeys: u32_le(&data, 0x14).unwrap_or(0),
        subkey_list: u32_le(&data, 0x1c).unwrap_or(NO_CELL),
        values: u32_le(&data, 0x24).unwrap_or(0),
        value_list: u32_le(&data, 0x28).unwrap_or(NO_CELL),
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
        .span(info.span)
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

async fn key(cx: Cx, k: Key) -> Result<()> {
    let hive = &k.hive;
    let info = key_info(&cx, hive, k.offset).await?;
    let nk = info
        .span
        .sub(0, 0x4c_u64.saturating_add(name_len(&cx, info.span).await));
    cx.emit(struct_node("Key node", nk, LE, (), key_node_fields));
    if info.values > 0 {
        cx.emit(
            Node::new("Values")
                .summary(format!("{}", info.values))
                .lazy(values, (hive.clone(), info.value_list, info.values)),
        );
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

async fn name_len(cx: &Cx, nk: Span) -> u64 {
    match cx.read(nk.sub(0x48, 2)).await {
        Ok(b) => u16_le(&b, 0).map_or(0, u64::from),
        Err(_) => 0,
    }
}

fn key_node_fields(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Signature", 2).emit()?;
    let flags = f.u16("Flags").flags(KEY_FLAGS).emit()?;
    f.u64("Last written").filetime().emit()?;
    f.u32("Access bits").hex().emit()?;
    f.u32("Parent").hex().emit()?;
    f.u32("Subkeys").emit()?;
    f.u32("Volatile subkeys").emit()?;
    f.u32("Subkey list").hex().emit()?;
    f.u32("Volatile subkey list").hex().emit()?;
    f.u32("Values").emit()?;
    f.u32("Value list").hex().emit()?;
    f.u32("Security").hex().emit()?;
    f.u32("Class name offset").hex().emit()?;
    f.u32("Largest subkey name length").emit()?;
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

/// Where a value's data lives.
async fn value_data(cx: &Cx, hive: &Hive, vk: Span, size: u32, offset: u32) -> Result<Span> {
    if size & 0x8000_0000 != 0 {
        // Small data is stored in the offset field itself.
        return Ok(vk.sub(0x08, u64::from(size & 0x7fff_ffff).min(4)));
    }
    let cell = hive.cell(cx, offset).await?;
    let head = cx.read_avail(cell.sub(0, 2)).await?;
    if head == b"db" && size > 16344 {
        return Err(Diagnostic::unsupported("big data (segmented) value").at(cell));
    }
    Ok(cell.sub(0, size.into()))
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
    let mut node = Node::new(name).span(vk);
    let vk_fields = vk.sub(0, 0x14u64.saturating_add(name_len.into()));
    let data = match value_data(cx, hive, vk, size, data_offset).await {
        Ok(span) => span,
        Err(e) => {
            return Ok(node
                .summary(type_name)
                .diag(e)
                .lazy(value_fields, (vk_fields, None)));
        }
    };
    let bytes = cx.read_avail(data.sub(0, MAX_DATA)).await?;
    let value = match kind {
        1 | 2 | 6 => Value::Text(crate::text::utf16z(&bytes, LE).0),
        7 => {
            let strings: Vec<String> = crate::text::utf16(&bytes, LE)
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
            Value::Text(strings.join(" | "))
        }
        4 if bytes.len() >= 4 => uint(u32_le(&bytes, 0).unwrap_or(0), 32),
        5 if bytes.len() >= 4 => uint(crate::bytes::u32_be(&bytes, 0).unwrap_or(0), 32),
        11 if bytes.len() >= 8 => uint(u64_le(&bytes, 0).unwrap_or(0), 64),
        _ => Value::Bytes(bytes.get(..32).unwrap_or(&bytes).to_vec()),
    };
    node = node
        .value(value)
        .summary(format!("{type_name}, {} bytes", size & 0x7fff_ffff))
        .lazy(value_fields, (vk_fields, Some(data)));
    Ok(node)
}

async fn value_fields(cx: Cx, (vk, data): (Span, Option<Span>)) -> Result<()> {
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
                n
            }
        })
        .emit()?;
    f.u32("Data offset").hex().emit()?;
    f.u32("Data type").enumeration(VALUE_TYPES).emit()?;
    let flags = f.u16("Flags").flags(VALUE_FLAGS).emit()?;
    f.u16("Spare").emit()?;
    if flags & 1 != 0 {
        f.ascii("Value name", len.into()).emit()?;
    } else {
        f.utf16("Value name", u64::from(len / 2)).emit()?;
    }
    if let Some(data) = data {
        cx.emit(
            Node::new("Data")
                .span(data)
                .summary(format!("{} bytes", data.len)),
        );
    }
    Ok(())
}

/// Hive bins, listed in pages.
async fn bins(cx: Cx, hive: H) -> Result<()> {
    let mut cur = Cursor::new(&cx, hive.bins, LE);
    while !cur.at_end() {
        let start = cur.pos();
        let (h, _) = cur.record::<BinHeader>().await?;
        if h.signature != "hbin" {
            return Err(Diagnostic::malformed("expected a hive bin").at(cur.since(start)));
        }
        if h.size < 0x20 || !u64::from(h.size).is_multiple_of(0x1000) {
            return Err(
                Diagnostic::malformed(format!("bad hive bin size {:#x}", h.size))
                    .at(hive.bins.sub(start, 0x20)),
            );
        }
        cur.seek(start.saturating_add(h.size.into()));
        let span = hive.bins.sub(start, h.size.into());
        cx.push(
            Node::new(format!("hbin at {start:#x}"))
                .span(span)
                .summary(format!("{:#x} bytes", h.size))
                .lazy(cells, (span, start)),
        )
        .await;
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
async fn cells(cx: Cx, (bin, base): (Span, u64)) -> Result<()> {
    cx.emit(BinHeader::node("Header", bin.sub(0, BinHeader::SIZE), LE));
    let mut cur = Cursor::new(&cx, bin, LE);
    cur.seek(BinHeader::SIZE);
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let size = cur.int::<i32>().await?;
        let len = u64::from(size.unsigned_abs());
        if len < 8 || !len.is_multiple_of(8) {
            return Err(
                Diagnostic::malformed(format!("bad cell size {size}")).at(bin.sub(start, 4))
            );
        }
        let sig = cur.peek(2).await?;
        let sig = u16_le(&sig, 0).unwrap_or(0);
        cur.seek(start.saturating_add(len));
        let node =
            Node::new(format!("Cell {:#x}", base.saturating_add(start))).span(bin.sub(start, len));
        let node = if size < 0 {
            let kind = lookup(CELL_TYPES, sig.into()).unwrap_or("data");
            node.value(enumv(sig, 16, CELL_TYPES))
                .summary(format!("{kind}, {len} bytes"))
        } else {
            node.summary(format!("free, {len} bytes"))
        };
        cx.push(node).await;
    }
    Ok(())
}
