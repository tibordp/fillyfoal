//! LUKS encrypted volumes (Linux Unified Key Setup), versions 1 and 2.
//!
//! LUKS1 has a fixed binary header with eight key slots, each pointing at
//! its anti-forensic (AF) split key material. LUKS2 has a 4 KiB binary
//! header followed by a JSON area describing keyslots, segments, digests
//! and tokens, a second copy of both (each checksummed), then the keyslots
//! area holding the AF-split key material, then the encrypted data.

use std::sync::Arc;

use crate::bytes::{to_u64, u16_be, u32_be};
use crate::codec::crypto::{Sha1, Sha256, Sha512};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::qcow::Regions;
use crate::formats::disk::size;
use crate::formats::util::datakit::digest_paced;
use crate::formats::util::fmt::plural;
use crate::formats::{Format, Input, Probe, embedded_as};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::EnumTable;

const BE: Endian = Endian::Big;
const MAGIC: &[u8] = b"LUKS\xba\xbe";
const MAGIC2: &[u8] = b"SKUL\xba\xbe";
/// Largest header (binary + JSON) area read.
const MAX_JSON: u64 = 4 << 20;
/// Largest JSON text parsed for the keyslot and segment summaries.
const MAX_PARSE: usize = 256 << 10;
/// Nesting of JSON values parsed at most.
const MAX_JSON_DEPTH: usize = 32;
const LUKS1_SLOT_ACTIVE: u32 = 0x00ac_71f3;

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
        payload: u32 "Payload offset (sectors)" .with(|&v, n| n.summary(format!("at {:#x}", u64::from(v).saturating_mul(512)))),
        key_bytes: u32 "Master key length (bytes)" .with(|&v, n| n.summary(format!("{} bits", u64::from(v).saturating_mul(8)))),
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
        material: u32 "Key material offset (sectors)" .with(|&v, n| n.summary(format!("at {:#x}", u64::from(v).saturating_mul(512)))),
        stripes: u32 "Anti-forensic stripes",
    }
}

record! {
    /// The LUKS2 binary header (4 KiB).
    pub struct Luks2 {
        magic: bytes[6] "Magic",
        version: u16 "Version",
        header_size: u64 "Header size (binary + JSON)" .with(|&v, n| n.summary(size(v))),
        seqid: u64 "Sequence id" .desc("Incremented on every metadata update; the copies must agree"),
        label: ascii[48] "Label",
        checksum_alg: ascii[32] "Checksum algorithm",
        salt: bytes[64] "Salt",
        uuid: ascii[40] "UUID",
        subsystem: ascii[48] "Subsystem",
        offset: u64 "Header offset" .with(|&v, n| n.summary(format!("{v:#x} from the start of the device"))),
        _padding: bytes[184] "Padding",
        checksum: bytes[64] "Checksum",
        _padding2: bytes[3584] "Padding",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let disk = input.span;
    let head = cx.read(disk.sub(0, 8)).await?;
    match u16_be(&head, 6) {
        Some(1) => luks1(&cx, disk).await,
        Some(2) => luks2(&cx, input).await,
        Some(v) => Err(Diagnostic::unsupported(format!("LUKS version {v}")).at(disk.sub(6, 2))),
        None => Err(Diagnostic::truncated(disk.sub(0, 8), to_u64(head.len()))),
    }
}

// ---------------------------------------------------------------------------
// LUKS1

/// A LUKS1 slot's key material: key length × stripes, rounded up to sectors.
fn material_span(disk: Span, key_bytes: u32, offset: u32, stripes: u32) -> Span {
    let len = u64::from(key_bytes)
        .saturating_mul(stripes.into())
        .next_multiple_of(512);
    disk.sub(u64::from(offset).saturating_mul(512), len)
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
        .filter(|s| u32_be(s.as_slice(), 0) == Some(LUKS1_SLOT_ACTIVE))
        .count();
    cx.annotate(format!(
        "LUKS1 encrypted volume, {}-{} ({}-bit key), {}, {active} of 8 key slots active",
        h.cipher,
        h.mode,
        u64::from(h.key_bytes).saturating_mul(8),
        h.hash
    ));
    cx.emit(Luks1::node("Header", span, BE).summary(format!("UUID {}", h.uuid)));
    cx.emit(
        Node::new("Key slots")
            .span(slots_span)
            .summary(format!("{active} active"))
            .lazy(key_slots, (disk, slots_span, h.key_bytes)),
    );
    // The layout: header, key material areas, payload.
    let mut r = Regions::default();
    r.span(disk, span, "Header");
    r.span(disk, slots_span, "Key slots");
    for s in slots.as_chunks::<48>().0 {
        let state = u32_be(s.as_slice(), 0).unwrap_or(0);
        let offset = u32_be(s.as_slice(), 40).unwrap_or(0);
        let stripes = u32_be(s.as_slice(), 44).unwrap_or(0);
        if offset != 0 {
            r.span(
                disk,
                material_span(disk, h.key_bytes, offset, stripes),
                if state == LUKS1_SLOT_ACTIVE {
                    "Key material"
                } else {
                    "Key material (disabled slot)"
                },
            );
        }
    }
    let payload_at = u64::from(h.payload).saturating_mul(512);
    let payload = disk.tail(payload_at);
    r.span(disk, payload, "Encrypted payload");
    cx.emit(
        Node::new("Volume layout")
            .span(disk)
            .summary("header, key material and payload")
            .lazy(emit_regions, (disk, Arc::new(r))),
    );
    cx.emit(
        Node::new("Encrypted payload")
            .span(payload)
            .summary(format!("{} of {}-{}", size(payload.len), h.cipher, h.mode)),
    );
    Ok(())
}

async fn emit_regions(cx: Cx, (disk, regions): (Span, Arc<Regions>)) -> Result<()> {
    regions
        .as_ref()
        .clone()
        .emit(&cx, disk, "not used by the header or key slots")
        .await;
    Ok(())
}

async fn key_slots(cx: Cx, (disk, span, key_bytes): (Span, Span, u32)) -> Result<()> {
    cx.set_count(Count::Exact(8));
    for i in 0..8u64 {
        let slot_span = span.sub(i.saturating_mul(KeySlot::SIZE), KeySlot::SIZE);
        let slot = parse(&cx, slot_span, BE, &(), KeySlot::layout).await?;
        let material = material_span(disk, key_bytes, slot.material, slot.stripes);
        let mut node = KeySlot::node(format!("Key slot {i}"), slot_span, BE);
        if slot.state == LUKS1_SLOT_ACTIVE {
            node = node
                .summary(format!(
                    "enabled, {} PBKDF2 iterations, {} of AF-split key material ({} stripes)",
                    slot.iterations,
                    size(material.len),
                    slot.stripes
                ))
                .target(material);
        } else {
            node = node.summary("disabled");
        }
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// LUKS2

/// Verifies a LUKS2 header checksum: the hash of the binary header and the
/// JSON area with the checksum field zeroed.
async fn luks2_checksum(cx: &Cx, area: Span, alg: &str) -> Result<Option<Diagnostic>> {
    if area.len > MAX_JSON {
        return Ok(None);
    }
    let mut data = cx.read_avail(area).await?;
    let stored = data.get(448..512).unwrap_or_default().to_vec();
    if let Some(f) = data.get_mut(448..512) {
        f.fill(0);
    }
    let computed = match alg {
        "sha1" => digest_paced::<Sha1>(cx, &data).await,
        "sha256" => digest_paced::<Sha256>(cx, &data).await,
        "sha512" => digest_paced::<Sha512>(cx, &data).await,
        other => {
            return Ok(Some(Diagnostic::unsupported(format!(
                "checksum algorithm {other:?} not verified"
            ))));
        }
    };
    let n = computed.len();
    Ok((stored.get(..n) != Some(computed.as_slice()))
        .then(|| Diagnostic::warning(format!("{alg} checksum mismatch")).at(area.sub(448, 64))))
}

/// A header copy: binary header and JSON area, checked.
async fn header_copy(
    cx: &Cx,
    input: Input,
    at: u64,
    name: &'static str,
) -> Result<Option<(Luks2, String)>> {
    let disk = input.span;
    let span = disk.sub(at, 4096);
    let magic = cx.read_avail(span.sub(0, 6)).await?;
    if magic != MAGIC && magic != MAGIC2 {
        cx.emit(
            Node::new(name)
                .span(span)
                .diag(Diagnostic::warning("no LUKS2 header here")),
        );
        return Ok(None);
    }
    let h = parse(cx, span, BE, &(), Luks2::layout).await?;
    let hdr_size = h.header_size.clamp(4096, MAX_JSON);
    let mut node = Luks2::node(name, span, BE).summary(format!(
        "sequence {}, {} with the JSON area",
        h.seqid,
        size(hdr_size)
    ));
    if let Some(d) = luks2_checksum(cx, disk.sub(at, hdr_size), &h.checksum_alg).await? {
        node = node.diag(d);
    }
    cx.emit(node);
    let json_area = disk.sub(at.saturating_add(4096), hdr_size.saturating_sub(4096));
    let data = cx.read_avail(json_area).await?;
    let text = crate::text::until_nul(&data);
    let used = to_u64(text.len());
    let json_name = if at == 0 {
        "JSON metadata"
    } else {
        "Secondary JSON metadata"
    };
    cx.emit(
        embedded_as(
            json_name,
            input.nested(json_area.sub(0, used)),
            &crate::formats::text::json::FORMAT,
        )
        .summary(format!(
            "{used} bytes of JSON in a {} area",
            size(json_area.len)
        )),
    );
    if used < json_area.len {
        cx.emit(
            Node::new(if at == 0 {
                "JSON area padding"
            } else {
                "Secondary JSON area padding"
            })
            .span(json_area.tail(used))
            .summary(size(json_area.len.saturating_sub(used))),
        );
    }
    Ok(Some((h, text)))
}

async fn luks2(cx: &Cx, input: Input) -> Result<()> {
    let disk = input.span;
    let Some((h, text)) = header_copy(cx, input, 0, "Binary header").await? else {
        return Ok(());
    };
    let hdr_size = h.header_size.clamp(4096, MAX_JSON);
    // The secondary header follows the primary area.
    let second = header_copy(cx, input, hdr_size, "Secondary binary header").await?;
    if let Some((h2, text2)) = second
        && (h2.seqid != h.seqid || text2 != text)
    {
        cx.diag(Diagnostic::warning(
            "the secondary header differs from the primary (interrupted update?)",
        ));
    }
    cx.checkpoint().await;
    let json = if text.len() <= MAX_PARSE {
        Json::parse(&text)
    } else {
        None
    };
    let label = if h.label.is_empty() {
        String::new()
    } else {
        format!(" {:?}", h.label)
    };
    let Some(json) = json else {
        cx.annotate(format!("LUKS2 encrypted volume{label}, UUID {}", h.uuid));
        return Ok(());
    };
    let keyslots = json.get("keyslots").map(Json::members).unwrap_or_default();
    let tokens = json.get("tokens").map(Json::members).unwrap_or_default();
    let segment = json
        .get("segments")
        .and_then(|s| s.members().into_iter().next())
        .map(|(_, v)| v);
    let cipher = segment
        .and_then(|s| s.get("encryption"))
        .and_then(Json::as_str)
        .unwrap_or("?");
    cx.annotate(format!(
        "LUKS2 encrypted volume{label}, {cipher}, {}{}, UUID {}",
        plural(crate::bytes::to_u64(keyslots.len()), "keyslot"),
        if tokens.is_empty() {
            String::new()
        } else {
            format!(", {}", plural(crate::bytes::to_u64(tokens.len()), "token"))
        },
        h.uuid
    ));

    // The keyslots area and the slots in it.
    let area_size = json
        .get("config")
        .and_then(|c| c.get("keyslots_size"))
        .and_then(Json::as_u64)
        .unwrap_or(0);
    let area_start = hdr_size.saturating_mul(2);
    let mut slots = Vec::new();
    for (id, k) in &keyslots {
        let area = k.get("area");
        let offset = area
            .and_then(|a| a.get("offset"))
            .and_then(Json::as_u64)
            .unwrap_or(0);
        let len = area
            .and_then(|a| a.get("size"))
            .and_then(Json::as_u64)
            .unwrap_or(0);
        let key_size = k.get("key_size").and_then(Json::as_u64).unwrap_or(0);
        let af = k.get("af");
        let stripes = af
            .and_then(|a| a.get("stripes"))
            .and_then(Json::as_u64)
            .unwrap_or(0);
        let kdf = k
            .get("kdf")
            .and_then(|d| d.get("type"))
            .and_then(Json::as_str)
            .unwrap_or("?")
            .to_owned();
        let enc = area
            .and_then(|a| a.get("encryption"))
            .and_then(Json::as_str)
            .unwrap_or("?")
            .to_owned();
        let priority = match k.get("priority").and_then(Json::as_u64) {
            Some(0) => ", ignored",
            Some(2) => ", preferred",
            _ => "",
        };
        slots.push(Slot {
            id: id.clone(),
            area: disk.sub(offset, len),
            material: disk.sub(
                offset,
                key_size.saturating_mul(stripes).next_multiple_of(512),
            ),
            summary: format!(
                "{}-bit key, {kdf}, AF {stripes} stripes, area encrypted with {enc}{priority}",
                key_size.saturating_mul(8)
            ),
        });
    }
    let slots = Arc::new(slots);
    if area_size > 0 {
        let area = disk.sub(area_start, area_size);
        cx.emit(
            Node::new("Keyslots area")
                .span(area)
                .summary(format!("{} keyslots in {}", slots.len(), size(area.len)))
                .lazy(keyslots_area, (area, slots.clone())),
        );
    }
    if let Some(s) = segment {
        let offset = s.get("offset").and_then(Json::as_u64).unwrap_or(0);
        let len = match s.get("size").and_then(Json::as_str) {
            Some("dynamic") | None => disk.len.saturating_sub(offset),
            Some(n) => n.parse().unwrap_or(0),
        };
        let sector = s.get("sector_size").and_then(Json::as_u64).unwrap_or(512);
        let payload = disk.sub(offset, len);
        let gap_start = area_start.saturating_add(area_size);
        if area_size > 0 && offset > gap_start {
            cx.emit(
                Node::new("Unused")
                    .span(disk.sub(gap_start, offset.saturating_sub(gap_start)))
                    .summary("between the keyslots area and the data"),
            );
        }
        cx.emit(
            Node::new("Encrypted payload")
                .span(payload)
                .summary(format!(
                    "{} at {offset:#x}, {cipher}, {sector}-byte sectors",
                    size(payload.len)
                )),
        );
    }
    Ok(())
}

#[derive(Debug)]
struct Slot {
    id: String,
    area: Span,
    material: Span,
    summary: String,
}

async fn keyslots_area(cx: Cx, (area, slots): (Span, Arc<Vec<Slot>>)) -> Result<()> {
    let mut order: Vec<&Slot> = slots.iter().collect();
    order.sort_by_key(|s| s.area.offset);
    let mut pos = area.offset;
    let gap = |from: u64, to: u64| {
        Node::new("Unused")
            .span(Span::new(area.source, from, to.saturating_sub(from)))
            .summary(format!(
                "{} of free keyslot space",
                size(to.saturating_sub(from))
            ))
    };
    for s in order {
        if s.area.offset > pos {
            cx.push(gap(pos, s.area.offset.min(area.end()))).await;
        }
        let rest = s.area.len.saturating_sub(s.material.len);
        cx.push(
            Node::new(format!("Keyslot {}", s.id))
                .span(s.area)
                .summary(s.summary.clone())
                .lazy(slot_node, (s.area, s.material, rest)),
        )
        .await;
        pos = pos.max(s.area.end());
    }
    if pos < area.end() {
        cx.push(gap(pos, area.end())).await;
    }
    Ok(())
}

async fn slot_node(cx: Cx, (area, material, rest): (Span, Span, u64)) -> Result<()> {
    cx.emit(
        Node::new("AF-split key material")
            .span(material.sub(0, area.len))
            .summary(format!("{}, encrypted", size(material.len))),
    );
    if rest > 0 {
        cx.emit(
            Node::new("Unused")
                .span(area.tail(material.len))
                .summary(size(rest)),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// A small JSON reader, for the few values the summaries need. The JSON
// itself is shown by the JSON dissector.

#[derive(Debug, Clone)]
enum Json {
    Null,
    Bool,
    Num(String),
    Str(String),
    Arr,
    Obj(Vec<(String, Json)>),
}

impl Json {
    fn parse(text: &str) -> Option<Json> {
        let mut p = Parser {
            b: text.as_bytes(),
            at: 0,
        };
        p.value(0)
    }

    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// An object's members (in order).
    fn members(&self) -> Vec<(String, &Json)> {
        match self {
            Json::Obj(m) => m.iter().map(|(k, v)| (k.clone(), v)).collect(),
            _ => Vec::new(),
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    /// A number, or a string holding one (LUKS2 writes 64-bit values as
    /// strings).
    fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(s) | Json::Str(s) => s.parse().ok(),
            _ => None,
        }
    }
}

struct Parser<'a> {
    b: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn space(&mut self) {
        while self.b.get(self.at).is_some_and(u8::is_ascii_whitespace) {
            self.at = self.at.saturating_add(1);
        }
    }

    fn eat(&mut self, c: u8) -> bool {
        self.space();
        if self.b.get(self.at) == Some(&c) {
            self.at = self.at.saturating_add(1);
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Option<Json> {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        self.space();
        match *self.b.get(self.at)? {
            b'{' => {
                self.at = self.at.saturating_add(1);
                let mut m = Vec::new();
                if self.eat(b'}') {
                    return Some(Json::Obj(m));
                }
                loop {
                    self.space();
                    let k = self.string()?;
                    if !self.eat(b':') {
                        return None;
                    }
                    m.push((k, self.value(depth.saturating_add(1))?));
                    if self.eat(b'}') {
                        return Some(Json::Obj(m));
                    }
                    if !self.eat(b',') {
                        return None;
                    }
                }
            }
            b'[' => {
                self.at = self.at.saturating_add(1);
                // Arrays are only skipped: no summary needs their elements.
                if self.eat(b']') {
                    return Some(Json::Arr);
                }
                loop {
                    self.value(depth.saturating_add(1))?;
                    if self.eat(b']') {
                        return Some(Json::Arr);
                    }
                    if !self.eat(b',') {
                        return None;
                    }
                }
            }
            b'"' => self.string().map(Json::Str),
            b't' => self.word("true", Json::Bool),
            b'f' => self.word("false", Json::Bool),
            b'n' => self.word("null", Json::Null),
            _ => {
                let start = self.at;
                while self.b.get(self.at).is_some_and(|c| {
                    c.is_ascii_digit() || matches!(c, b'-' | b'+' | b'.' | b'e' | b'E')
                }) {
                    self.at = self.at.saturating_add(1);
                }
                (self.at > start).then(|| {
                    Json::Num(
                        String::from_utf8_lossy(self.b.get(start..self.at).unwrap_or_default())
                            .into_owned(),
                    )
                })
            }
        }
    }

    fn word(&mut self, w: &str, v: Json) -> Option<Json> {
        let end = self.at.saturating_add(w.len());
        (self.b.get(self.at..end) == Some(w.as_bytes())).then(|| {
            self.at = end;
            v
        })
    }

    /// A string (escapes other than `\"` and `\\` are kept as written).
    fn string(&mut self) -> Option<String> {
        if self.b.get(self.at) != Some(&b'"') {
            return None;
        }
        self.at = self.at.saturating_add(1);
        let mut out = Vec::new();
        loop {
            let c = *self.b.get(self.at)?;
            self.at = self.at.saturating_add(1);
            match c {
                b'"' => return Some(String::from_utf8_lossy(&out).into_owned()),
                b'\\' => {
                    let e = *self.b.get(self.at)?;
                    self.at = self.at.saturating_add(1);
                    if !matches!(e, b'"' | b'\\' | b'/') {
                        out.push(b'\\');
                    }
                    out.push(e);
                }
                _ => out.push(c),
            }
        }
    }
}
