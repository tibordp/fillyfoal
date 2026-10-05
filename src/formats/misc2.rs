//! Documents, captures, system databases and scientific data headers.

use crate::bytes::{to_u64, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

// ---------------------------------------------------------------------------
// TeX DVI

declare_format!(pub DVI = "dvi", "TeX device-independent output", ["dvi"], "application/x-dvi",
    Probe::Magic(&[(0, b"\xf7\x02"), (0, b"\xf7\x05")]), dvi);

async fn dvi(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 15)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u8("pre").hex().emit()?;
    let id = f.u8("Identification").emit()?;
    f.u32("Numerator").emit()?;
    f.u32("Denominator").emit()?;
    let mag = f.u32("Magnification").emit()?;
    let k = f.u8("Comment length").emit()?;
    let comment = cx.read_avail(file.sub(15, k.into())).await?;
    let comment = String::from_utf8_lossy(&comment).into_owned();
    cx.emit(Node::new("Comment").span(file.sub(15, k.into())).value(text(comment.trim())));
    // The postamble is found from the end: post_post, then 4+ 223 bytes.
    let tail = cx.read(file.sub(file.len.saturating_sub(64), 64)).await?;
    let end = tail.iter().rposition(|&b| b != 223).unwrap_or(0);
    let mut pages = None;
    if end >= 5 && tail.get(end.saturating_sub(5)) == Some(&249) {
        let post = u64::from(u32_be(&tail, end.saturating_sub(4)).unwrap_or(0));
        let p = cx.read_avail(file.sub(post, 29)).await?;
        pages = crate::bytes::u16_be(&p, 27);
        cx.emit(Node::new("Postamble").span(file.sub(post, file.len.saturating_sub(post))));
    }
    cx.emit(Node::new("Pages").span(file.sub(15u64.saturating_add(k.into()), file.len)));
    cx.annotate(format!(
        "DVI (id {id}), {}{}, magnification {mag}",
        comment.trim(),
        pages.map_or(String::new(), |p| format!(", {p} pages"))
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// WordPerfect, Windows Write, OneNote, FrameMaker

declare_format!(pub WORDPERFECT = "wordperfect", "WordPerfect document", ["wpd", "wp", "wp5", "wp6"], "application/vnd.wordperfect",
    Probe::Magic(&[(0, b"\xffWPC")]), wordperfect);

const WP_TYPES: EnumTable = &[(10, "document"), (11, "dictionary"), (12, "thesaurus"), (17, "macro"), (22, "graphics")];

async fn wordperfect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Magic", 4).emit()?;
    let doc = f.u32("Document area offset").hex().emit()?;
    f.u8("Product type").emit()?;
    let kind = f.u8("File type").enumeration(WP_TYPES).emit()?;
    let major = f.u8("Major version").emit()?;
    let minor = f.u8("Minor version").emit()?;
    f.u16("Encryption").hex().emit()?;
    cx.emit(Node::new("Prefix packets").span(file.sub(16, u64::from(doc).saturating_sub(16))));
    cx.emit(Node::new("Document area").span(file.tail(doc.into())));
    let version = match major {
        1 => "5.x",
        2 => "6.x or later",
        _ => "unknown version",
    };
    cx.annotate(format!("WordPerfect {version} {} (format {major}.{minor})", lookup(WP_TYPES, kind.into()).unwrap_or("file")));
    Ok(())
}

declare_format!(pub WRITE = "mswrite", "Microsoft Write document", ["wri"], "application/x-mswrite",
    Probe::Magic(&[(0, b"\x31\xbe\x00\x00\x00\xab"), (0, b"\x32\xbe\x00\x00\x00\xab")]), mswrite);

async fn mswrite(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 128)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u16("Identifier").hex().emit()?;
    f.u16("Reserved").emit()?;
    f.u16("Tool").hex().emit()?;
    f.bytes("Reserved", 8).emit()?;
    let text_end = f.u32("End of text (fcMac)").emit()?;
    let _ = f.u16("Paragraph info page (pnPara)").emit()?;
    let text_span = file.sub(128, u64::from(text_end).saturating_sub(128));
    let sample = cx.read_avail(text_span.sub(0, 120)).await?;
    cx.emit(Node::new("Text").span(text_span).summary(String::from_utf8_lossy(&sample).replace(['\r', '\n'], " ")));
    cx.annotate(format!("Write document, {} characters", text_span.len));
    Ok(())
}

declare_format!(pub ONENOTE = "onenote", "Microsoft OneNote section", ["one", "onetoc2"], "application/onenote",
    Probe::Magic(&[(0, b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3"), (0, b"\xa1\x2f\xff\x43\xd9\xef\x76\x4c\x9e\xe2\x10\xea\x57\x22\x76\x5f")]), onenote);

async fn onenote(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x100)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let kind = f.guid("File type").emit()?;
    f.guid("File").emit()?;
    f.guid("Legacy file version").emit()?;
    f.guid("File format").emit()?;
    let last_code = f.u32("Last code that accessed").hex().emit()?;
    f.u32("Oldest code that accessed").hex().emit()?;
    f.u32("Newest code that wrote").hex().emit()?;
    f.u32("Oldest code required").hex().emit()?;
    let toc = kind.data1 == 0x43ff_2fa1;
    cx.emit(Node::new("File data").span(file.tail(0x400)));
    cx.annotate(format!("OneNote {} (last accessed by code {last_code:#x})", if toc { "table of contents" } else { "section" }));
    Ok(())
}

declare_format!(pub FRAMEMAKER = "framemaker", "Adobe FrameMaker document", ["fm", "book", "mif"], "application/vnd.framemaker",
    Probe::Magic(&[(0, b"<MakerFile"), (0, b"<MIFFile"), (0, b"<BookFile"), (0, b"<MakerDictionary"), (0, b"<MakerScreenFont")]), framemaker);

async fn framemaker(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 64)).await?;
    let end = head.iter().position(|&b| b == b'>').unwrap_or(0);
    let tag = String::from_utf8_lossy(head.get(..end.saturating_add(1)).unwrap_or_default()).into_owned();
    cx.emit(Node::new("Identification").span(file.sub(0, to_u64(end).saturating_add(1))).value(text(tag.clone())));
    cx.emit(Node::new("Body").span(file.tail(to_u64(end).saturating_add(1))));
    cx.annotate(tag.trim_matches(['<', '>']).to_owned());
    Ok(())
}

// ---------------------------------------------------------------------------
// WARC web archives

declare_format!(pub WARC = "warc", "Web archive (WARC)", ["warc"], "application/warc",
    Probe::Magic(&[(0, b"WARC/1.0\r\n"), (0, b"WARC/1.1\r\n"), (0, b"WARC/0.")]), warc);

async fn warc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut records = 0u32;
    while pos < file.len {
        let head = cx.read_avail(file.sub(pos, 16384)).await?;
        let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") else {
            cx.diag(Diagnostic::malformed("record headers do not end").at(file.sub(pos, 4)));
            break;
        };
        let headers = String::from_utf8_lossy(head.get(..end).unwrap_or_default()).into_owned();
        let field = |name: &str| {
            headers
                .lines()
                .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_owned()))
        };
        let length: u64 = field("Content-Length").and_then(|v| v.parse().ok()).unwrap_or(0);
        let kind = field("WARC-Type").unwrap_or_default();
        let target = field("WARC-Target-URI").unwrap_or_default();
        let header_len = to_u64(end).saturating_add(4);
        let block = file.sub(pos.saturating_add(header_len), length);
        let total = header_len.saturating_add(length).saturating_add(4);
        records = records.saturating_add(1);
        cx.push(
            Node::new(format!("{kind} {target}").trim().to_owned())
                .span(file.sub(pos, total))
                .lazy(warc_record, (input, file.sub(pos, to_u64(end)), block, headers)),
        )
        .await;
        pos = pos.saturating_add(total);
    }
    cx.annotate(format!("WARC, {records} records"));
    Ok(())
}

async fn warc_record(cx: Cx, (input, header_span, block, headers): (Input, Span, Span, String)) -> Result<()> {
    let mut at = 0u64;
    for line in headers.split("\r\n") {
        let len = to_u64(line.len());
        if let Some((k, v)) = line.split_once(':') {
            cx.emit(Node::new(k.trim().to_owned()).span(header_span.sub(at, len)).value(text(v.trim())));
        } else {
            cx.emit(Node::new("Version").span(header_span.sub(at, len)).value(text(line)));
        }
        at = at.saturating_add(len).saturating_add(2);
    }
    cx.emit(embedded("Content block", input.nested(block)).summary(format!("{} bytes", block.len)));
    Ok(())
}

// ---------------------------------------------------------------------------
// age encryption

declare_format!(pub AGE = "age", "age-encrypted file", ["age"], "application/x-age",
    Probe::Magic(&[(0, b"age-encryption.org/v1\n")]), age);

async fn age(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 16384)).await?;
    let mac = head.windows(4).position(|w| w == b"\n---").ok_or_else(|| Diagnostic::malformed("no header MAC line"))?;
    let header = String::from_utf8_lossy(head.get(..mac).unwrap_or_default()).into_owned();
    let mut pos = 0u64;
    let mut kinds = Vec::new();
    for line in header.split('\n') {
        let len = to_u64(line.len()).saturating_add(1);
        if let Some(stanza) = line.strip_prefix("-> ") {
            let kind = stanza.split_whitespace().next().unwrap_or_default().to_owned();
            kinds.push(kind.clone());
            cx.emit(Node::new(format!("Recipient stanza ({kind})")).span(file.sub(pos, len)).value(text(stanza)));
        } else if pos == 0 {
            cx.emit(Node::new("Version").span(file.sub(pos, len)).value(text(line)));
        }
        pos = pos.saturating_add(len);
    }
    let mac_line_end = head.get(mac.saturating_add(1)..).and_then(|r| r.iter().position(|&b| b == b'\n')).map_or(head.len(), |p| mac.saturating_add(1).saturating_add(p).saturating_add(1));
    cx.emit(Node::new("Header MAC").span(file.sub(to_u64(mac).saturating_add(1), to_u64(mac_line_end.saturating_sub(mac).saturating_sub(1)))));
    cx.emit(Node::new("Payload").span(file.tail(to_u64(mac_line_end))).diag(Diagnostic::note("ChaCha20-Poly1305 encrypted")));
    cx.annotate(format!("age, recipients: {}", kinds.join(", ")));
    Ok(())
}

// ---------------------------------------------------------------------------
// Bitcoin block files (blk*.dat)

declare_format!(pub BITCOIN_BLOCKS = "bitcoin-blocks", "Bitcoin block file", ["dat"], "application/x-bitcoin-blocks",
    Probe::Magic(&[(0, b"\xf9\xbe\xb4\xd9"), (0, b"\x0b\x11\x09\x07"), (0, b"\x0a\x03\xcf\x40"), (0, b"\xfa\xbf\xb5\xda")]), bitcoin_blocks);

record! {
    pub struct BlockHeader {
        version: u32 "Version" .hex(),
        previous: bytes[32] "Previous block hash",
        merkle: bytes[32] "Merkle root",
        time: u32 "Time" .timestamp(),
        bits: u32 "Bits (target)" .hex(),
        nonce: u32 "Nonce",
    }
}

async fn bitcoin_blocks(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut blocks = 0u32;
    let mut first = None;
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let magic = cur.u32().await?;
        if magic == 0 {
            break; // preallocated zero tail
        }
        let size = cur.u32().await?;
        let header_span = cur.span(BlockHeader::SIZE);
        let header: BlockHeader = read_record(&cx, header_span, LE).await?;
        cur.seek(start.saturating_add(8).saturating_add(size.into()));
        blocks = blocks.saturating_add(1);
        first.get_or_insert(header.time);
        cx.push(
            BlockHeader::node(format!("Block {blocks}"), header_span, LE)
                .value(Value::Timestamp { unix_seconds: header.time.into() })
                .summary(format!("{size} bytes"))
                .target(cur.since(start)),
        )
        .await;
    }
    let network = match cx.read(file.sub(0, 4)).await?.as_slice() {
        b"\xf9\xbe\xb4\xd9" => "mainnet",
        b"\x0b\x11\x09\x07" => "testnet3",
        b"\x0a\x03\xcf\x40" => "signet",
        _ => "regtest",
    };
    cx.annotate(format!("Bitcoin {network}, {blocks} block(s)"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Bluetooth btsnoop and Microsoft Network Monitor captures

declare_format!(pub BTSNOOP = "btsnoop", "Bluetooth HCI capture (btsnoop)", ["log", "cfa", "btsnoop"], "application/x-btsnoop",
    Probe::Magic(&[(0, b"btsnoop\0")]), btsnoop);

const BTSNOOP_LINKS: EnumTable = &[(1001, "HCI UART (H4)"), (1002, "HCI UART (H4) without direction"), (1003, "HCI BSCP"), (1004, "HCI Serial (H5)")];

async fn btsnoop(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 8).emit()?;
    let version = f.u32("Version").emit()?;
    let link = f.u32("Datalink").enumeration(BTSNOOP_LINKS).emit()?;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(16);
    let mut packets = 0u32;
    while cur.remaining() >= 24 {
        let start = cur.pos();
        let original = cur.u32().await?;
        let included = cur.u32().await?;
        let flags = cur.u32().await?;
        let _drops = cur.u32().await?;
        let micros = cur.u64().await?;
        cur.skip(included.into());
        packets = packets.saturating_add(1);
        // Timestamps are microseconds since 0 AD; the Unix epoch is at
        // 0x00dcddb30f2f8000.
        let unix = i64::try_from(micros.saturating_sub(0x00dc_ddb3_0f2f_8000) / 1_000_000).unwrap_or(0);
        cx.push(
            Node::new(format!("Packet {packets}"))
                .span(cur.since(start))
                .value(Value::Timestamp { unix_seconds: unix })
                .summary(format!("{} {}, {included}/{original} bytes", if flags & 1 == 0 { "sent" } else { "received" }, if flags & 2 == 0 { "data" } else { "command/event" })),
        )
        .await;
    }
    cx.annotate(format!("btsnoop v{version}, {}, {packets} packets", lookup(BTSNOOP_LINKS, link.into()).unwrap_or("unknown link")));
    Ok(())
}

declare_format!(pub NETMON = "netmon", "Microsoft Network Monitor capture", ["cap"], "application/x-netmon",
    Probe::Magic(&[(0, b"GMBU"), (0, b"RTSS")]), netmon);

async fn netmon(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x30)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let magic = f.ascii("Magic", 4).emit()?;
    let minor = f.u8("Minor version").emit()?;
    let major = f.u8("Major version").emit()?;
    f.u16("MAC type").emit()?;
    f.bytes("Capture start time (SYSTEMTIME)", 16).emit()?;
    let table = f.u32("Frame table offset").hex().emit()?;
    let table_len = f.u32("Frame table length").emit()?;
    cx.emit(Node::new("Frame table").span(file.sub(table.into(), table_len.into())).summary(format!("{} frames", table_len / 4)));
    cx.annotate(format!("Network Monitor {major}.{minor} ({magic}), {} frames", table_len / 4));
    Ok(())
}

// ---------------------------------------------------------------------------
// Android A/B OTA payload

declare_format!(pub OTA_PAYLOAD = "ota-payload", "Android OTA update payload", ["bin"], "application/x-android-ota",
    Probe::Magic(&[(0, b"CrAU")]), ota_payload);

async fn ota_payload(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 24)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 4).emit()?;
    let version = f.u64("Format version").emit()?;
    let manifest = f.u64("Manifest size").emit()?;
    let signature = if version >= 2 { f.u32("Metadata signature size").emit()? } else { 0 };
    let at = if version >= 2 { 24u64 } else { 20 };
    cx.emit(Node::new("Manifest (protobuf)").span(file.sub(at, manifest)));
    let sig_at = at.saturating_add(manifest);
    if signature > 0 {
        cx.emit(Node::new("Metadata signature").span(file.sub(sig_at, signature.into())));
    }
    cx.emit(Node::new("Data blobs").span(file.tail(sig_at.saturating_add(signature.into()))));
    cx.annotate(format!("Android OTA payload v{version}, manifest {manifest} bytes"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Group Policy Registry.pol

declare_format!(pub REGISTRY_POL = "registry-pol", "Group Policy registry settings (Registry.pol)", ["pol"], "application/x-registry-pol",
    Probe::Magic(&[(0, b"PReg\x01\0\0\0")]), registry_pol);

const REG_TYPES: EnumTable = &[
    (0, "REG_NONE"),
    (1, "REG_SZ"),
    (2, "REG_EXPAND_SZ"),
    (3, "REG_BINARY"),
    (4, "REG_DWORD"),
    (5, "REG_DWORD_BIG_ENDIAN"),
    (7, "REG_MULTI_SZ"),
    (11, "REG_QWORD"),
];

async fn registry_pol(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Header").span(file.sub(0, 8)));
    let max = cx.limits().max_read;
    let data = cx.read_avail(file.sub(8, max)).await?;
    // Entries: [key;value;type;size;data] with UTF-16LE text and ';' separators.
    let mut at = 0usize;
    let mut count = 0u32;
    while at.saturating_add(2) <= data.len() {
        if u16_le(&data, at) != Some(u16::from(b'[')) {
            break;
        }
        let start = at;
        let mut fields: Vec<String> = Vec::new();
        let mut cursor = at.saturating_add(2);
        for _ in 0..2 {
            let (s, used, _) = crate::text::utf16z(data.get(cursor..).unwrap_or_default(), LE);
            fields.push(s);
            cursor = cursor.saturating_add(used).saturating_add(2); // NUL + ';'
        }
        let kind = u32_le(&data, cursor).unwrap_or(0);
        let size = u32_le(&data, cursor.saturating_add(6)).unwrap_or(0);
        let value_at = cursor.saturating_add(12);
        let value = data.get(value_at..value_at.saturating_add(usize::try_from(size).unwrap_or(0))).unwrap_or_default();
        let shown = match kind {
            1 | 2 | 7 => crate::text::utf16(value, LE).trim_end_matches('\0').replace('\0', " | "),
            4 => u32_le(value, 0).unwrap_or(0).to_string(),
            11 => crate::bytes::u64_le(value, 0).unwrap_or(0).to_string(),
            _ => format!("{} bytes", value.len()),
        };
        at = value_at.saturating_add(usize::try_from(size).unwrap_or(0)).saturating_add(2); // ']'
        count = count.saturating_add(1);
        cx.push(
            Node::new(format!("{}\\{}", fields.first().cloned().unwrap_or_default(), fields.get(1).cloned().unwrap_or_default()))
                .span(file.sub(8u64.saturating_add(to_u64(start)), to_u64(at.saturating_sub(start))))
                .value(text(shown))
                .summary(lookup(REG_TYPES, kind.into()).unwrap_or("unknown type")),
        )
        .await;
    }
    cx.annotate(format!("{count} policy settings"));
    Ok(())
}

// ---------------------------------------------------------------------------
// ESE (JET Blue) databases

fn ese_probe(h: &Head<'_>) -> bool {
    h.at(4, b"\xef\xcd\xab\x89")
}

declare_format!(pub ESE = "ese", "Extensible Storage Engine database", ["edb", "dat", "sdb"], "application/x-ese",
    Probe::Custom(ese_probe), ese);

const ESE_STATES: EnumTable = &[(1, "just created"), (2, "dirty shutdown"), (3, "clean shutdown"), (4, "being converted"), (5, "force detach")];

record! {
    pub struct EseHeader {
        checksum: u32 "Checksum" .hex(),
        signature: u32 "Signature" .hex(),
        version: u32 "Format version" .hex(),
        file_type: u32 "File type" .enumeration(&[(0, "database"), (1, "streaming file")]),
        db_time: u64 "Database time",
        db_signature: bytes[28] "Database signature",
        state: u32 "Database state" .enumeration(ESE_STATES),
    }
}

async fn ese(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: EseHeader = emit_record(&cx, file.sub(0, EseHeader::SIZE), LE).await?;
    let more = cx.read_avail(file.sub(0xe8, 12)).await?;
    let revision = u32_le(&more, 0).unwrap_or(0);
    let page_size = u32_le(&cx.read_avail(file.sub(0xec, 4)).await?, 0).unwrap_or(0);
    cx.emit(Node::new("Page size").span(file.sub(0xec, 4)).value(Value::UInt { value: page_size.into(), bits: 32, radix: Radix::Dec }));
    cx.emit(Node::new("Pages").span(file.tail(u64::from(page_size).saturating_mul(2))));
    let state = lookup(ESE_STATES, h.state.into()).unwrap_or("unknown state");
    cx.annotate(format!("ESE database v{:#x} rev {revision}, {} KiB pages, {state}", h.version, page_size / 1024));
    Ok(())
}

// ---------------------------------------------------------------------------
// Apple BOM (Bill of Materials; also Assets.car)

declare_format!(pub BOMSTORE = "bom", "Apple bill of materials (BOMStore)", ["bom", "car"], "application/x-bom",
    Probe::Magic(&[(0, b"BOMStore")]), bomstore);

record! {
    pub struct BomHeader {
        magic: ascii[8] "Magic",
        version: u32 "Version",
        blocks: u32 "Non-null blocks",
        index_offset: u32 "Block index offset" .hex(),
        index_length: u32 "Block index length",
        vars_offset: u32 "Variables offset" .hex(),
        vars_length: u32 "Variables length",
    }
}

async fn bomstore(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: BomHeader = read_record(&cx, file.sub(0, BomHeader::SIZE), BE).await?;
    cx.emit(BomHeader::node("Header", file.sub(0, BomHeader::SIZE), BE));
    let index = cx.read(file.sub(h.index_offset.into(), h.index_length.into())).await?;
    let block_count = u32_be(&index, 0).unwrap_or(0);
    let vars = file.sub(h.vars_offset.into(), h.vars_length.into());
    let mut cur = Cursor::new(&cx, vars, BE);
    let count = cur.u32().await?;
    let mut names = Vec::new();
    for _ in 0..count.min(1024) {
        let start = cur.pos();
        let block = cur.u32().await?;
        let len = cur.u8().await?;
        let name = String::from_utf8_lossy(&cur.bytes(len.into()).await?).into_owned();
        names.push(name.clone());
        let at = usize::try_from(block).unwrap_or(0).saturating_mul(8).saturating_add(4);
        let (offset, length) = (u32_be(&index, at).unwrap_or(0), u32_be(&index, at.saturating_add(4)).unwrap_or(0));
        cx.push(
            embedded(name, input.nested(file.sub(offset.into(), length.into())))
                .summary(format!("block {block}, {length} bytes"))
                .target(cur.since(start)),
        )
        .await;
    }
    cx.annotate(format!("BOMStore, {block_count} blocks, variables: {}", names.join(", ")));
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows application compatibility database (SDB)

fn sdb_probe(h: &Head<'_>) -> bool {
    h.at(8, b"sdbf")
}

declare_format!(pub SDB = "shim-sdb", "Windows shim database", ["sdb"], "application/x-ms-sdb",
    Probe::Custom(sdb_probe), shim_sdb);

async fn shim_sdb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let major = f.u32("Major version").emit()?;
    let minor = f.u32("Minor version").emit()?;
    f.ascii("Magic", 4).emit()?;
    cx.emit(Node::new("Tags").span(file.tail(12)));
    cx.annotate(format!("shim database v{major}.{minor}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Statistics and science: SPSS, SAS, Stata, ROOT, NIfTI, NRRD, HDF4, VTK

declare_format!(pub SPSS = "spss-sav", "SPSS data file", ["sav", "zsav"], "application/x-spss-sav",
    Probe::Magic(&[(0, b"$FL2"), (0, b"$FL3")]), spss);

record! {
    pub struct SpssHeader {
        magic: ascii[4] "Record type",
        product: ascii[60] "Product name",
        layout: i32 "Layout code",
        nominal_case_size: i32 "Nominal case size",
        compression: i32 "Compression" .enumeration(&[(0, "none"), (1, "bytecode"), (2, "zlib")]),
        weight: i32 "Weight variable index",
        cases: i32 "Number of cases",
        bias: f64 "Compression bias",
        date: ascii[9] "Creation date",
        time: ascii[8] "Creation time",
        label: ascii[64] "File label",
        _padding: bytes[3] "Padding",
    }
}

async fn spss(cx: Cx, input: Input) -> Result<()> {
    let h: SpssHeader = emit_record(&cx, input.span.sub(0, SpssHeader::SIZE), LE).await?;
    cx.emit(Node::new("Dictionary and data").span(input.span.tail(SpssHeader::SIZE)));
    cx.annotate(format!("SPSS, {} cases, {} ({} {})", h.cases, h.product.trim().trim_start_matches("@(#) "), h.date, h.time));
    Ok(())
}

const SAS_MAGIC: &[u8] = b"\0\0\0\0\0\0\0\0\0\0\0\0\xc2\xea\x81\x60\xb3\x14\x11\xcf\xbd\x92\x08\0\x09\xc7\x31\x8c\x18\x1f\x10\x11";

declare_format!(pub SAS7BDAT = "sas7bdat", "SAS data set", ["sas7bdat", "sas7bcat"], "application/x-sas-data",
    Probe::Magic(&[(0, SAS_MAGIC)]), sas7bdat);

async fn sas7bdat(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x120)).await?;
    let align = if head.get(32) == Some(&0x33) { 4u64 } else { 0 };
    let little = head.get(37) == Some(&0x01);
    let name = crate::text::until_nul(head.get(92..156).unwrap_or_default());
    let kind = crate::text::until_nul(head.get(156..164).unwrap_or_default());
    cx.emit(Node::new("Magic").span(file.sub(0, 32)));
    cx.emit(Node::new("Dataset name").span(file.sub(92, 64)).value(text(name.trim())));
    cx.emit(Node::new("File type").span(file.sub(156, 8)).value(text(kind.trim())));
    let version_at = 216u64.saturating_add(align.saturating_mul(2)).saturating_add(64);
    let version = crate::text::until_nul(&cx.read_avail(file.sub(version_at, 8)).await?);
    cx.emit(Node::new("SAS release").span(file.sub(version_at, 8)).value(text(version.trim())));
    cx.annotate(format!("SAS {} {:?}, release {}, {}-bit {}", kind.trim(), name.trim(), version.trim(), if align == 4 { 64 } else { 32 }, if little { "little-endian" } else { "big-endian" }));
    Ok(())
}

declare_format!(pub STATA = "stata-dta", "Stata data file", ["dta"], "application/x-stata-dta",
    Probe::Magic(&[(0, b"<stata_dta>")]), stata);

async fn stata(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 512)).await?;
    let text_head = String::from_utf8_lossy(&head).into_owned();
    let tag = |name: &str| {
        let open = format!("<{name}>");
        let start = text_head.find(&open)?.saturating_add(open.len());
        let end = text_head.get(start..)?.find(&format!("</{name}>"))?;
        Some((start, text_head.get(start..start.saturating_add(end))?.to_owned()))
    };
    let release = tag("release").map(|(_, r)| r).unwrap_or_default();
    let order = tag("byteorder").map(|(_, r)| r).unwrap_or_default();
    cx.emit(Node::new("Release").value(text(release.clone())));
    cx.emit(Node::new("Byte order").value(text(order.clone())));
    let little = order == "LSF";
    let mut vars = 0u64;
    let mut obs = 0u64;
    if let Some((k_at, _)) = tag("K") {
        let at = crate::bytes::to_u64(k_at);
        let raw = cx.read_avail(file.sub(at, 2)).await?;
        vars = u64::from(if little { u16_le(&raw, 0) } else { crate::bytes::u16_be(&raw, 0) }.unwrap_or(0));
        let n_at = text_head.find("<N>").map_or(0, |p| p.saturating_add(3));
        let raw = cx.read_avail(file.sub(crate::bytes::to_u64(n_at), 8)).await?;
        obs = if little { crate::bytes::u64_le(&raw, 0) } else { crate::bytes::u64_be(&raw, 0) }.unwrap_or(0);
    }
    cx.emit(Node::new("Data").span(file));
    cx.annotate(format!("Stata release {release}, {vars} variables, {obs} observations"));
    Ok(())
}

declare_format!(pub ROOT = "cern-root", "CERN ROOT file", ["root"], "application/x-root",
    Probe::Magic(&[(0, b"root\0")]), cern_root);

async fn cern_root(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 64)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 4).emit()?;
    let version = f.u32("Version").emit()?;
    let begin = f.u32("First data record").hex().emit()?;
    let big = version >= 1_000_000;
    if big {
        f.u64("End of file").hex().emit()?;
        f.u64("First free segment").hex().emit()?;
    } else {
        f.u32("End of file").hex().emit()?;
        f.u32("First free segment").hex().emit()?;
    }
    f.u32("Free segment record length").emit()?;
    f.u32("Deleted free segments").emit()?;
    f.u32("Header length (TFile)").emit()?;
    f.u8("Units (pointer size)").emit()?;
    let compression = f.u32("Compression").emit()?;
    cx.emit(Node::new("Records").span(file.tail(begin.into())));
    let v = version % 1_000_000;
    cx.annotate(format!("ROOT {}.{:02}/{:02}, compression {compression}", v / 10000, v / 100 % 100, v % 100));
    Ok(())
}

fn nifti_probe(h: &Head<'_>) -> bool {
    (u32_le(h.data, 0) == Some(348) && (h.at(344, b"n+1\0") || h.at(344, b"ni1\0")))
        || (u32_le(h.data, 0) == Some(540) && (h.at(4, b"n+2\0") || h.at(4, b"ni2\0")))
}

declare_format!(pub NIFTI = "nifti", "NIfTI neuroimaging volume", ["nii", "hdr"], "application/x-nifti",
    Probe::Custom(nifti_probe), nifti);

const NIFTI_TYPES: EnumTable = &[(2, "uint8"), (4, "int16"), (8, "int32"), (16, "float32"), (64, "float64"), (128, "rgb24"), (256, "int8"), (512, "uint16"), (768, "uint32")];

async fn nifti(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 348)).await?;
    if u32_le(&head, 0) == Some(540) {
        cx.emit(Node::new("NIfTI-2 header").span(file.sub(0, 540)));
        cx.annotate("NIfTI-2 volume");
        return Ok(());
    }
    let dims: Vec<String> = (0..usize::from(crate::bytes::i16_le(&head, 40).unwrap_or(0).clamp(0, 7) as u16))
        .map(|i| crate::bytes::i16_le(&head, 42usize.saturating_add(i.saturating_mul(2))).unwrap_or(0).to_string())
        .collect();
    let datatype = u16_le(&head, 70).unwrap_or(0);
    let description = crate::text::until_nul(head.get(148..228).unwrap_or_default());
    let offset = f32::from_le_bytes([head.get(108).copied().unwrap_or(0), head.get(109).copied().unwrap_or(0), head.get(110).copied().unwrap_or(0), head.get(111).copied().unwrap_or(0)]);
    cx.emit(Node::new("Header").span(file.sub(0, 348)).summary(description.clone()));
    cx.emit(Node::new("Dimensions").span(file.sub(40, 16)).value(text(dims.join("×"))));
    cx.emit(Node::new("Data type").span(file.sub(70, 2)).value(Value::Enum { raw: datatype.into(), bits: 16, name: lookup(NIFTI_TYPES, datatype.into()) }));
    let data_at = if offset.is_finite() && offset >= 348.0 { offset as u64 } else { 352 };
    cx.emit(Node::new("Voxel data").span(file.tail(data_at)));
    cx.annotate(format!("NIfTI-1, {} {}{}", dims.join("×"), lookup(NIFTI_TYPES, datatype.into()).unwrap_or("?"), if description.is_empty() { String::new() } else { format!(", {description:?}") }));
    Ok(())
}

declare_format!(pub NRRD = "nrrd", "Nearly raw raster data (NRRD)", ["nrrd", "nhdr"], "application/x-nrrd",
    Probe::Magic(&[(0, b"NRRD000")]), nrrd);

async fn nrrd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 8192)).await?;
    let end = head.windows(2).position(|w| w == b"\n\n").map_or(head.len(), |p| p.saturating_add(2));
    let header = String::from_utf8_lossy(head.get(..end).unwrap_or_default()).into_owned();
    let mut pos = 0u64;
    let mut fields = Vec::new();
    for line in header.lines() {
        let len = to_u64(line.len()).saturating_add(1);
        if let Some((k, v)) = line.split_once(':') {
            fields.push((k.trim().to_owned(), v.trim().to_owned()));
            cx.emit(Node::new(k.trim().to_owned()).span(file.sub(pos, len)).value(text(v.trim())));
        } else if !line.starts_with('#') && !line.is_empty() {
            cx.emit(Node::new("Magic").span(file.sub(pos, len)).value(text(line)));
        }
        pos = pos.saturating_add(len);
    }
    cx.emit(Node::new("Data").span(file.tail(to_u64(end))));
    let get = |k: &str| fields.iter().find(|(f, _)| f == k).map_or(String::new(), |(_, v)| v.clone());
    cx.annotate(format!("NRRD {} {}, {} encoding", get("sizes").replace(' ', "×"), get("type"), get("encoding")));
    Ok(())
}

declare_format!(pub HDF4 = "hdf4", "HDF4 scientific data", ["hdf", "hdf4", "h4"], "application/x-hdf4",
    Probe::Magic(&[(0, b"\x0e\x03\x13\x01")]), hdf4);

async fn hdf4(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Magic").span(file.sub(0, 4)));
    let mut at = 4u64;
    let mut blocks = 0u32;
    let mut descriptors = 0u32;
    while at != 0 && at < file.len && blocks < 1000 {
        let head = cx.read(file.sub(at, 6)).await?;
        let count = crate::bytes::u16_be(&head, 0).unwrap_or(0);
        let next = u64::from(u32_be(&head, 2).unwrap_or(0));
        blocks = blocks.saturating_add(1);
        descriptors = descriptors.saturating_add(count.into());
        cx.push(Node::new(format!("DD block {blocks}")).span(file.sub(at, 6u64.saturating_add(u64::from(count).saturating_mul(12)))).summary(format!("{count} descriptors"))).await;
        if next <= at {
            break;
        }
        at = next;
    }
    cx.annotate(format!("HDF4, {descriptors} data descriptors"));
    Ok(())
}

declare_format!(pub VTK = "vtk-legacy", "VTK legacy data file", ["vtk"], "application/x-vtk",
    Probe::Magic(&[(0, b"# vtk DataFile Version")]), vtk);

async fn vtk(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 1024)).await?;
    let mut lines = head.split(|&b| b == b'\n');
    let mut pos = 0u64;
    let mut values = Vec::new();
    for name in ["Version", "Title", "Encoding", "Dataset type"] {
        let line = lines.next().unwrap_or_default();
        let len = to_u64(line.len()).saturating_add(1);
        let s = String::from_utf8_lossy(line).trim().to_owned();
        values.push(s.clone());
        cx.emit(Node::new(name).span(file.sub(pos, len)).value(text(s)));
        pos = pos.saturating_add(len);
    }
    cx.emit(Node::new("Data").span(file.tail(pos)));
    cx.annotate(format!(
        "{} {}, {}",
        values.get(3).map_or("", |s| s.trim_start_matches("DATASET ")),
        values.get(2).cloned().unwrap_or_default(),
        values.get(1).cloned().unwrap_or_default()
    ));
    Ok(())
}
