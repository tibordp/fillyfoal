//! LUKS encrypted volumes (Linux Unified Key Setup), versions 1 and 2.
//!
//! LUKS1 has a fixed binary header with eight key slots. LUKS2 has a 4 KiB
//! binary header followed by a JSON area describing keyslots, segments and
//! digests, and a second copy of both.

use crate::bytes::{to_u64, u16_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::size;
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const BE: Endian = Endian::Big;
const MAGIC: &[u8] = b"LUKS\xba\xbe";
const MAGIC2: &[u8] = b"SKUL\xba\xbe";
/// Largest JSON area shown as text.
const MAX_JSON: u64 = 4 << 20;

pub static FORMAT: Format = Format {
    name: "luks",
    title: "LUKS encrypted volume",
    extensions: &["luks", "img"],
    mime: "application/x-luks",
    probe: Probe::Magic(&[(0, MAGIC)]),
    dissect: crate::expander!(dissect: Input),
};

const SLOT_STATE: EnumTable = &[(0x00ac_71f3, "enabled"), (0x0000_dead, "disabled")];

record! {
    /// The LUKS1 partition header.
    pub struct Luks1 {
        magic: bytes[6] "Magic",
        version: u16 "Version",
        cipher: ascii[32] "Cipher name",
        mode: ascii[32] "Cipher mode",
        hash: ascii[32] "Hash specification",
        payload: u32 "Payload offset (sectors)",
        key_bytes: u32 "Master key length (bytes)",
        digest: bytes[20] "Master key digest",
        salt: bytes[32] "Master key digest salt",
        iterations: u32 "Master key digest iterations",
        uuid: ascii[40] "UUID",
    }
}

record! {
    /// A LUKS1 key slot.
    pub struct KeySlot {
        state: u32 "State" .hex() .enumeration(SLOT_STATE),
        iterations: u32 "PBKDF2 iterations",
        salt: bytes[32] "Salt",
        material: u32 "Key material offset (sectors)",
        stripes: u32 "Anti-forensic stripes",
    }
}

record! {
    /// The LUKS2 binary header (the rest of its 4 KiB is padding).
    pub struct Luks2 {
        magic: bytes[6] "Magic",
        version: u16 "Version",
        header_size: u64 "Header size (binary + JSON)" .with(|&v, n| n.summary(size(v))),
        seqid: u64 "Sequence id",
        label: ascii[48] "Label",
        checksum_alg: ascii[32] "Checksum algorithm",
        salt: bytes[64] "Salt",
        uuid: ascii[40] "UUID",
        subsystem: ascii[48] "Subsystem",
        offset: u64 "Header offset",
        _padding: bytes[184] "Padding",
        checksum: bytes[64] "Checksum",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let disk = input.span;
    let head = cx.read(disk.sub(0, 8)).await?;
    match u16_be(&head, 6) {
        Some(1) => luks1(&cx, disk).await,
        Some(2) => luks2(&cx, disk).await,
        Some(v) => Err(Diagnostic::unsupported(format!("LUKS version {v}")).at(disk.sub(6, 2))),
        None => Err(Diagnostic::truncated(disk.sub(0, 8), to_u64(head.len()))),
    }
}

async fn luks1(cx: &Cx, disk: Span) -> Result<()> {
    let span = disk.sub(0, Luks1::SIZE);
    let h = parse(cx, span, BE, &(), Luks1::layout).await?;
    let slots_span = disk.sub(Luks1::SIZE, 8 * KeySlot::SIZE);
    let slots = cx.read_avail(slots_span).await?;
    let active = slots
        .as_chunks::<48>()
        .0
        .iter()
        .filter(|s| s.get(..4) == Some(&[0x00, 0xac, 0x71, 0xf3]))
        .count();
    cx.annotate(format!(
        "LUKS1 encrypted volume, {}-{} ({}-bit key), {active} of 8 key slots active",
        h.cipher,
        h.mode,
        u64::from(h.key_bytes).saturating_mul(8)
    ));
    cx.emit(Luks1::node("Header", span, BE).summary(format!("UUID {}", h.uuid)));
    cx.emit(
        Node::new("Key slots")
            .span(slots_span)
            .summary(format!("{active} active"))
            .lazy(key_slots, (disk, slots_span, h.key_bytes)),
    );
    let payload = disk.tail(u64::from(h.payload).saturating_mul(512));
    cx.emit(
        Node::new("Encrypted payload")
            .span(payload)
            .summary(size(payload.len)),
    );
    Ok(())
}

async fn key_slots(cx: Cx, (disk, span, key_bytes): (Span, Span, u32)) -> Result<()> {
    cx.set_count(Count::Exact(8));
    for i in 0..8u64 {
        let slot_span = span.sub(i.saturating_mul(KeySlot::SIZE), KeySlot::SIZE);
        let slot = parse(&cx, slot_span, BE, &(), KeySlot::layout).await?;
        let mut node = KeySlot::node(format!("Key slot {i}"), slot_span, BE);
        if slot.state == 0x00ac_71f3 {
            // Key material: key length × stripes, rounded up to sectors.
            let len = u64::from(key_bytes).saturating_mul(slot.stripes.into());
            let material = disk.sub(u64::from(slot.material).saturating_mul(512), len);
            node = node
                .summary(format!("enabled, {} iterations", slot.iterations))
                .target(material);
        } else {
            node = node.summary("disabled");
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn luks2(cx: &Cx, disk: Span) -> Result<()> {
    let span = disk.sub(0, Luks2::SIZE);
    let h = parse(cx, span, BE, &(), Luks2::layout).await?;
    let label = if h.label.is_empty() {
        String::new()
    } else {
        format!(" \"{}\"", h.label)
    };
    cx.annotate(format!("LUKS2 encrypted volume{label}, UUID {}", h.uuid));
    let header_size = h.header_size.clamp(4096, MAX_JSON);
    cx.emit(
        Luks2::node("Binary header", disk.sub(0, 4096), BE)
            .summary(format!("sequence {}", h.seqid)),
    );
    let json = disk.sub(4096, header_size.saturating_sub(4096));
    cx.emit(json_node("JSON metadata", cx, json).await?);

    // The secondary header follows the primary area.
    let second = disk.sub(header_size, Luks2::SIZE);
    let magic = cx.read_avail(second.sub(0, 6)).await?;
    if magic == MAGIC2 {
        cx.emit(Luks2::node(
            "Secondary binary header",
            disk.sub(header_size, 4096),
            BE,
        ));
        let json2 = disk.sub(
            header_size.saturating_add(4096),
            header_size.saturating_sub(4096),
        );
        cx.emit(Node::new("Secondary JSON metadata").span(json2));
    } else {
        cx.emit(
            Node::new("Secondary binary header")
                .span(second)
                .diag(Diagnostic::warning("secondary header missing")),
        );
    }
    let text = crate::text::until_nul(&cx.read_avail(json).await?);
    if let Some(offset) = segment_offset(&text) {
        let payload = disk.tail(offset);
        cx.emit(
            Node::new("Encrypted payload")
                .span(payload)
                .summary(format!("{} at {offset:#x}", size(payload.len))),
        );
    }
    Ok(())
}

async fn json_node(name: &'static str, cx: &Cx, span: Span) -> Result<Node> {
    let data = cx.read_avail(span).await?;
    let text = crate::text::until_nul(&data);
    let used = to_u64(text.len());
    Ok(Node::new(name)
        .span(span.sub(0, used))
        .summary(format!("{used} bytes of JSON in a {} area", size(span.len)))
        .value(Value::Text(text)))
}

/// The offset of the first data segment, found textually in the JSON:
/// `"segments":{"0":{..."offset":"16777216"...`. A full JSON parser is not
/// needed for this one value.
fn segment_offset(json: &str) -> Option<u64> {
    let segments = json.find("\"segments\"")?;
    let rest = json.get(segments..)?;
    let key = rest.find("\"offset\"")?;
    let after = rest.get(key.saturating_add(8)..)?;
    let digits: String = after
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}
