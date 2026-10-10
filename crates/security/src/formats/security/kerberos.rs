//! Kerberos keytabs and credential caches.

use crate::bytes::{u16_be, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Head, Input, Probe, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn time(secs: u32) -> Value {
    Value::Timestamp {
        unix_seconds: secs.into(),
    }
}

/// Kerberos encryption types (RFC 3961 and successors).
const ENCTYPES: EnumTable = &[
    (1, "des-cbc-crc"),
    (3, "des-cbc-md5"),
    (16, "des3-cbc-sha1"),
    (17, "aes128-cts-hmac-sha1-96"),
    (18, "aes256-cts-hmac-sha1-96"),
    (19, "aes128-cts-hmac-sha256-128"),
    (20, "aes256-cts-hmac-sha384-192"),
    (23, "rc4-hmac"),
    (24, "rc4-hmac-exp"),
    (25, "camellia128-cts-cmac"),
    (26, "camellia256-cts-cmac"),
];

fn enctype(e: u16) -> &'static str {
    ENCTYPES
        .iter()
        .find(|(k, _)| *k == u64::from(e))
        .map_or("unknown", |(_, v)| v)
}

// ---------------------------------------------------------------------------
// Kerberos keytab

fn keytab_probe(h: &Head<'_>) -> bool {
    // Version 0x0502 (big-endian) or 0x0501 (native), then the first entry's
    // length: a plausible, non-zero size.
    let size = if h.at(1, b"\x02") {
        u32_be(h.data, 2)
    } else {
        u32_le(h.data, 2)
    };
    h.data.first() == Some(&5)
        && matches!(h.data.get(1), Some(1 | 2))
        && size.is_some_and(|s| {
            let s = i32::from_ne_bytes(s.to_ne_bytes()).unsigned_abs();
            (16..=0x10000).contains(&s)
        })
}

declare_format!(pub KEYTAB = "krb5-keytab", "Kerberos keytab", ["keytab", "kt"], "application/x-krb5-keytab",
    Probe::Custom(keytab_probe), keytab);

async fn keytab(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let v = cx.read(file.sub(0, 2)).await?;
    let endian = if v.get(1) == Some(&2) { BE } else { LE };
    cx.emit(
        Node::new("Version")
            .span(file.sub(0, 2))
            .value(hex(u16_be(&v, 0).unwrap_or(0), 16)),
    );
    let mut cur = Cursor::new(&cx, file, endian);
    cur.seek(2);
    let mut n = 0u32;
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let size = cur.u32().await?;
        let signed = i32::from_ne_bytes(size.to_ne_bytes());
        let len = u64::from(signed.unsigned_abs());
        let entry = cur.span(len);
        if entry.len < len {
            return Err(Diagnostic::truncated(
                Span::new(entry.source, entry.offset, len),
                entry.len,
            ));
        }
        cur.skip(len);
        if signed < 0 {
            cx.push(
                Node::new("Hole")
                    .span(cur.since(start))
                    .summary(format!("{len} bytes free")),
            )
            .await;
            continue;
        }
        if len == 0 {
            break;
        }
        // Parse the entry for its summary; the node expands to its fields.
        let mut e = Cursor::new(&cx, entry, endian);
        let mut count = u64::from(e.u16().await?);
        if endian == LE {
            count = count.saturating_sub(1);
        }
        let realm_len = u64::from(e.u16().await?);
        let realm = String::from_utf8_lossy(&e.bytes(realm_len).await?).into_owned();
        let mut parts = Vec::new();
        for _ in 0..count.min(16) {
            let l = u64::from(e.u16().await?);
            parts.push(String::from_utf8_lossy(&e.bytes(l).await?).into_owned());
        }
        e.skip(8);
        let kvno = e.u8().await?;
        let etype = e.u16().await?;
        let principal = format!("{}@{realm}", parts.join("/"));
        cx.push(
            Node::new(principal)
                .span(cur.since(start))
                .summary(format!("kvno {kvno}, {}", enctype(etype)))
                .lazy(keytab_entry, (entry, endian)),
        )
        .await;
        n = n.saturating_add(1);
    }
    cx.annotate(format!("Kerberos keytab, {n} keys"));
    Ok(())
}

async fn keytab_entry(cx: Cx, (entry, endian): (Span, Endian)) -> Result<()> {
    let mut e = Cursor::new(&cx, entry, endian);
    let at = e.pos();
    let count = e.u16().await?;
    cx.emit(
        Node::new("Components")
            .span(e.since(at))
            .value(uint(count, 16)),
    );
    let mut n = u64::from(count);
    if endian == LE {
        n = n.saturating_sub(1);
    }
    for i in 0..=n.min(16) {
        let at = e.pos();
        let l = u64::from(e.u16().await?);
        let s = String::from_utf8_lossy(&e.bytes(l).await?).into_owned();
        cx.emit(
            Node::new(if i == 0 {
                "Realm".to_owned()
            } else {
                format!("Component {i}")
            })
            .span(e.since(at))
            .value(text(s)),
        );
    }
    let at = e.pos();
    let kind = e.u32().await?;
    cx.emit(
        Node::new("Name type")
            .span(e.since(at))
            .value(uint(kind, 32)),
    );
    let at = e.pos();
    let stamp = e.u32().await?;
    cx.emit(Node::new("Timestamp").span(e.since(at)).value(time(stamp)));
    let at = e.pos();
    let kvno = e.u8().await?;
    cx.emit(
        Node::new("Key version (8-bit)")
            .span(e.since(at))
            .value(uint(kvno, 8)),
    );
    let at = e.pos();
    let etype = e.u16().await?;
    cx.emit(
        Node::new("Encryption type")
            .span(e.since(at))
            .value(Value::Enum {
                raw: etype.into(),
                bits: 16,
                name: Some(enctype(etype)),
            }),
    );
    let at = e.pos();
    let klen = u64::from(e.u16().await?);
    e.skip(klen);
    cx.emit(
        Node::new("Key")
            .span(e.since(at))
            .summary(format!("{klen} bytes")),
    );
    if e.remaining() >= 4 {
        let at = e.pos();
        let v = e.u32().await?;
        cx.emit(
            Node::new("Key version (32-bit)")
                .span(e.since(at))
                .value(uint(v, 32)),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Kerberos credential cache (MIT "The Kerberos Credential Cache File
// Format"): versions 1 and 2 in the writer's byte order (little-endian
// here), 3 and 4 big-endian; version 4 adds header tags.

declare_format!(pub CCACHE = "krb5-ccache", "Kerberos credential cache", ["ccache"], "application/x-krb5-ccache",
    Probe::Custom(ccache_probe), ccache);

fn ccache_probe(h: &Head<'_>) -> bool {
    // v4 has a header-tag length (usually 12); v1-v3 start with a principal.
    match h.data.get(..2) {
        Some(b"\x05\x04") => u16_be(h.data, 2).is_some_and(|l| l <= 64 && l % 4 == 0),
        Some(b"\x05\x03") => u32_be(h.data, 2).is_some_and(|t| t <= 11),
        // Name type (v2) or component count (v1), little-endian.
        Some(b"\x05\x02" | b"\x05\x01") => {
            u32_le(h.data, 2).is_some_and(|t| t <= 11)
                && u32_le(h.data, 6).is_some_and(|n| (1..=16).contains(&n))
        }
        _ => false,
    }
}

const NAME_TYPES: EnumTable = &[
    (0, "NT-UNKNOWN"),
    (1, "NT-PRINCIPAL"),
    (2, "NT-SRV-INST"),
    (3, "NT-SRV-HST"),
    (4, "NT-SRV-XHST"),
    (5, "NT-UID"),
    (6, "NT-X500-PRINCIPAL"),
    (7, "NT-SMTP-NAME"),
    (10, "NT-ENTERPRISE"),
    (11, "NT-WELLKNOWN"),
];

/// Ticket flags (RFC 4120 bit 0 is the most significant).
const TICKET_FLAGS: FlagTable = &[
    flag(0x8000_0000, "reserved"),
    flag(0x4000_0000, "forwardable"),
    flag(0x2000_0000, "forwarded"),
    flag(0x1000_0000, "proxiable"),
    flag(0x0800_0000, "proxy"),
    flag(0x0400_0000, "may-postdate"),
    flag(0x0200_0000, "postdated"),
    flag(0x0100_0000, "invalid"),
    flag(0x0080_0000, "renewable"),
    flag(0x0040_0000, "initial"),
    flag(0x0020_0000, "pre-authent"),
    flag(0x0010_0000, "hw-authent"),
    flag(0x0008_0000, "transited-policy-checked"),
    flag(0x0004_0000, "ok-as-delegate"),
    flag(0x0001_0000, "enc-pa-rep"),
    flag(0x0000_8000, "anonymous"),
];

const ADDRESS_TYPES: EnumTable = &[
    (2, "IPv4"),
    (3, "directional"),
    (5, "ChaosNet"),
    (6, "XNS"),
    (7, "ISO"),
    (12, "DECNET Phase IV"),
    (16, "AppleTalk DDP"),
    (20, "NetBIOS"),
    (24, "IPv6"),
];

const HEADER_TAGS: EnumTable = &[(1, "KDC time offset")];

/// Most components, addresses or authorization data entries read.
const MAX_ITEMS: u32 = 1024;

/// A ccache reader: decodes fields in order, emitting them when asked.
struct Reader<'a> {
    cur: Cursor<'a>,
    cx: &'a Cx,
    emit: bool,
    version: u16,
}

impl Reader<'_> {
    fn put(&self, node: Node) {
        if self.emit {
            self.cx.emit(node);
        }
    }

    async fn u32_field(&mut self, name: &'static str) -> Result<u32> {
        let at = self.cur.pos();
        let v = self.cur.u32().await?;
        self.put(Node::new(name).span(self.cur.since(at)).value(uint(v, 32)));
        Ok(v)
    }

    async fn time_field(&mut self, name: &'static str) -> Result<u32> {
        let at = self.cur.pos();
        let v = self.cur.u32().await?;
        let node = Node::new(name).span(self.cur.since(at));
        self.put(if v == 0 {
            node.summary("unset")
        } else {
            node.value(time(v))
        });
        Ok(v)
    }

    /// A counted octet string: its span (with the length) and data span.
    async fn counted(&mut self) -> Result<(Span, Span)> {
        let at = self.cur.pos();
        let l = u64::from(self.cur.u32().await?);
        if l > self.cur.remaining() {
            return Err(
                Diagnostic::truncated(self.cur.span(l), self.cur.remaining())
                    .at(self.cur.since(at)),
            );
        }
        let data = self.cur.span(l);
        self.cur.skip(l);
        Ok((self.cur.since(at), data))
    }

    async fn string(&mut self) -> Result<(String, Span)> {
        let (whole, data) = self.counted().await?;
        let raw = self.cx.read(data).await?;
        Ok((String::from_utf8_lossy(&raw).into_owned(), whole))
    }

    /// A principal: name type (not in v1), component count (with the realm
    /// in v1), realm, components. Returns `components@realm` and the parts.
    async fn principal(&mut self, name: &'static str) -> Result<(String, Vec<String>, String)> {
        let start = self.cur.pos();
        let kind = if self.version == 0x0501 {
            None
        } else {
            Some(self.cur.u32().await?)
        };
        let mut count = self.cur.u32().await?;
        if self.version == 0x0501 {
            count = count.saturating_sub(1);
        }
        let (realm, _) = self.string().await?;
        let mut parts = Vec::new();
        for _ in 0..count.min(MAX_ITEMS) {
            parts.push(self.string().await?.0);
        }
        let full = format!("{}@{realm}", parts.join("/"));
        let span = self.cur.since(start);
        let mut node = Node::new(name).span(span).value(text(full.clone()));
        if let Some(k) = kind {
            node = node.summary(lookup(NAME_TYPES, k.into()).unwrap_or("unknown name type"));
        }
        self.put(node.lazy(
            crate::expander!(self::principal_fields: (Span, u16, Endian)),
            (span, self.version, self.cur_endian()),
        ));
        Ok((full, parts, realm))
    }

    fn cur_endian(&self) -> Endian {
        if self.version >= 0x0503 { BE } else { LE }
    }
}

/// The fields of a principal at `span`.
async fn principal_fields(cx: Cx, (span, version, endian): (Span, u16, Endian)) -> Result<()> {
    let mut r = Reader {
        cur: Cursor::new(&cx, span, endian),
        cx: &cx,
        emit: true,
        version,
    };
    if version != 0x0501 {
        let at = r.cur.pos();
        let kind = r.cur.u32().await?;
        r.put(
            Node::new("Name type")
                .span(r.cur.since(at))
                .value(Value::Enum {
                    raw: kind.into(),
                    bits: 32,
                    name: lookup(NAME_TYPES, kind.into()),
                }),
        );
    }
    let count = r.u32_field("Component count").await?;
    let count = if version == 0x0501 {
        count.saturating_sub(1)
    } else {
        count
    };
    let (realm, span) = r.string().await?;
    r.put(Node::new("Realm").span(span).value(text(realm)));
    for i in 0..count.min(MAX_ITEMS) {
        let (part, span) = r.string().await?;
        r.put(
            Node::new(format!("Component {i}"))
                .span(span)
                .value(text(part)),
        );
    }
    Ok(())
}

async fn ccache(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 2)).await?;
    let version = u16_be(&head, 0).unwrap_or(0);
    let endian = if version >= 0x0503 { BE } else { LE };
    cx.emit(
        Node::new("Version")
            .span(file.sub(0, 2))
            .value(hex(version, 16))
            .summary(format!("version {}", version & 0xff)),
    );
    let mut r = Reader {
        cur: Cursor::new(&cx, file, endian),
        cx: &cx,
        emit: true,
        version,
    };
    r.cur.seek(2);
    if version == 0x0504 {
        let at = r.cur.pos();
        let len = u64::from(r.cur.u16().await?);
        let tags = r.cur.span(len);
        r.cur.skip(len);
        cx.emit(
            Node::new("Header")
                .span(r.cur.since(at))
                .summary(format!("{len} bytes of tags"))
                .lazy(crate::expander!(self::header_tags: Span), tags),
        );
    }
    let (default, _, _) = r.principal("Default principal").await?;
    let (pos, mut n, mut configs) = cx
        .resume::<(u64, u32, u32)>()
        .unwrap_or((r.cur.pos(), 0, 0));
    r.cur.seek(pos);
    r.emit = false;
    while r.cur.remaining() > 0 {
        let at = (r.cur.pos(), n, configs);
        cx.mark(move || at);
        let start = r.cur.pos();
        let (client, _, _) = r.principal("Client").await?;
        let (server, parts, realm) = r.principal("Server").await?;
        // The rest is skipped here and decoded on expansion.
        let etype = r.cur.u16().await?;
        if version == 0x0503 {
            r.cur.skip(2);
        }
        r.counted().await?;
        r.cur.skip(8);
        let end = r.cur.u32().await?;
        let _renew = r.cur.u32().await?;
        r.cur.skip(1);
        let flags = r.cur.u32().await?;
        for _ in 0..2 {
            let count = r.cur.u32().await?;
            for _ in 0..count.min(MAX_ITEMS) {
                r.cur.skip(2);
                r.counted().await?;
            }
        }
        let (_, ticket) = r.counted().await?;
        r.counted().await?;
        let span = r.cur.since(start);
        let state = (input, span, version);
        let node = if realm == "X-CACHECONF:" {
            // Configuration entries: krb5_ccache_conf_data/<key>[/<principal>].
            configs = configs.saturating_add(1);
            let key = parts.get(1).cloned().unwrap_or_default();
            let value = cx.read(ticket.sub(0, 256)).await?;
            Node::new(format!("Config: {key}"))
                .span(span)
                .summary(String::from_utf8_lossy(&value).into_owned())
        } else {
            n = n.saturating_add(1);
            let (set, _) = crate::value::decode_flags(TICKET_FLAGS, flags.into());
            Node::new(server).span(span).summary(format!(
                "for {client}, {}, until {}, {}",
                enctype(etype),
                crate::formats::util::civil::date(end.into()),
                set.join(" ")
            ))
        };
        cx.push(node.lazy(
            crate::expander!(self::credential: (Input, Span, u16)),
            state,
        ))
        .await;
        cx.progress_in(file, r.cur.region().offset.saturating_add(r.cur.pos()));
    }
    let mut summary = format!(
        "Kerberos credential cache v{}, {default}, {}",
        version & 0xff,
        crate::formats::util::fmt::plural(n, "credential")
    );
    if configs > 0 {
        summary = format!(
            "{summary}, {}",
            crate::formats::util::fmt::count(configs, "config entry", "config entries")
        );
    }
    cx.annotate(summary);
    Ok(())
}

/// Version 4 header tags.
async fn header_tags(cx: Cx, tags: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, tags, BE);
    while cur.remaining() >= 4 {
        cx.checkpoint().await;
        let start = cur.pos();
        let tag = cur.u16().await?;
        let len = u64::from(cur.u16().await?);
        let data = cur.span(len);
        cur.skip(len);
        let mut node = Node::new(
            lookup(HEADER_TAGS, tag.into())
                .unwrap_or("Unknown tag")
                .to_owned(),
        )
        .span(cur.since(start))
        .value(uint(tag, 16));
        if tag == 1 && len == 8 {
            let raw = cx.read(data).await?;
            let secs = u32_be(&raw, 0).map_or(0, |v| v.cast_signed());
            let usecs = u32_be(&raw, 4).map_or(0, |v| v.cast_signed());
            node = node.summary(format!("{secs} s {usecs} µs"));
        }
        cx.push(node).await;
    }
    Ok(())
}

/// One credential's fields.
async fn credential(cx: Cx, (input, span, version): (Input, Span, u16)) -> Result<()> {
    let endian = if version >= 0x0503 { BE } else { LE };
    let mut r = Reader {
        cur: Cursor::new(&cx, span, endian),
        cx: &cx,
        emit: true,
        version,
    };
    r.principal("Client").await?;
    let (_, _, realm) = r.principal("Server").await?;
    let config = realm == "X-CACHECONF:";
    let start = r.cur.pos();
    let etype = r.cur.u16().await?;
    if version == 0x0503 {
        r.cur.skip(2);
    }
    let (_, key) = r.counted().await?;
    r.put(
        Node::new("Session key")
            .span(r.cur.since(start))
            .value(Value::Enum {
                raw: etype.into(),
                bits: 16,
                name: Some(enctype(etype)),
            })
            .summary(format!("{} bytes", key.len)),
    );
    r.time_field("Authenticated").await?;
    r.time_field("Valid from").await?;
    r.time_field("Expires").await?;
    r.time_field("Renew until").await?;
    let at = r.cur.pos();
    let skey = r.cur.u8().await?;
    r.put(
        Node::new("Is session key")
            .span(r.cur.since(at))
            .value(Value::Bool(skey != 0)),
    );
    let at = r.cur.pos();
    let flags = r.cur.u32().await?;
    let (set, unknown) = crate::value::decode_flags(TICKET_FLAGS, flags.into());
    r.put(
        Node::new("Ticket flags")
            .span(r.cur.since(at))
            .value(Value::Flags {
                raw: flags.into(),
                bits: 32,
                set,
                unknown,
            }),
    );
    for (name, table) in [
        ("Addresses", ADDRESS_TYPES),
        ("Authorization data", &[][..]),
    ] {
        let at = r.cur.pos();
        let count = r.cur.u32().await?;
        let mut items = Vec::new();
        for _ in 0..count.min(MAX_ITEMS) {
            let kind = r.cur.u16().await?;
            let (_, data) = r.counted().await?;
            items.push((kind, data));
        }
        let mut node = Node::new(name).span(r.cur.since(at)).value(uint(count, 32));
        if !items.is_empty() {
            let mut texts = Vec::new();
            for (kind, data) in &items {
                let raw = cx.read(data.sub(0, 64)).await?;
                let addr = match (*kind, raw.len()) {
                    (2, 4) => <[u8; 4]>::try_from(raw.as_slice())
                        .ok()
                        .map(|a| std::net::Ipv4Addr::from(a).to_string()),
                    (24, 16) => <[u8; 16]>::try_from(raw.as_slice())
                        .ok()
                        .map(|a| std::net::Ipv6Addr::from(a).to_string()),
                    _ => None,
                };
                let label = lookup(table, (*kind).into())
                    .map_or_else(|| format!("type {kind}"), str::to_owned);
                texts.push(match addr {
                    Some(a) => format!("{label} {a}"),
                    None => format!("{label}, {} bytes", data.len),
                });
            }
            node = node.summary(texts.join(", "));
        }
        r.put(node);
    }
    let (whole, ticket) = r.counted().await?;
    if config {
        let raw = cx.read(ticket.sub(0, 4096)).await?;
        r.put(
            Node::new("Value")
                .span(whole)
                .value(text(String::from_utf8_lossy(&raw).into_owned())),
        );
    } else if ticket.len > 0 {
        r.put(embedded_as(
            "Ticket",
            input.nested(ticket),
            &crate::formats::asn1::KRB5_TICKET,
        ));
    } else {
        r.put(Node::new("Ticket").span(whole).summary("none"));
    }
    let (whole, second) = r.counted().await?;
    if second.len > 0 {
        r.put(embedded_as(
            "Second ticket",
            input.nested(second),
            &crate::formats::asn1::KRB5_TICKET,
        ));
    } else {
        r.put(Node::new("Second ticket").span(whole).summary("none"));
    }
    Ok(())
}
