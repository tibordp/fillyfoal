//! Java platform module files: JMOD (`JM\x01\x00` followed by a ZIP
//! archive) and the runtime image `lib/modules` (jimage, `0xCAFEDADA`),
//! whose resources are listed by name with their location and size.

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::binutil::text;
use crate::formats::{Format, Input, Probe, embedded_as};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;

const LE: Endian = Endian::Little;

pub static JMOD: Format = Format {
    name: "jmod",
    title: "Java module (JMOD)",
    extensions: &["jmod"],
    mime: "application/octet-stream",
    probe: Probe::Custom(|h| h.starts_with(b"JM\x01\x00") && h.at(4, b"PK\x03\x04")),
    dissect: crate::expander!(jmod: Input),
};

pub static JIMAGE: Format = Format {
    name: "jimage",
    title: "Java runtime image (jimage)",
    extensions: &["jimage"],
    mime: "application/octet-stream",
    probe: Probe::Magic(&[(0, b"\xda\xda\xfe\xca")]),
    dissect: crate::expander!(jimage: Input),
};

pub async fn jmod(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 4)).await?;
    cx.emit(Node::new("magic").span(file.sub(0, 2)).value(text("JM")));
    cx.emit(
        Node::new("version")
            .span(file.sub(2, 2))
            .value(text(format!("{}.{}", head.get(2).copied().unwrap_or(0), head.get(3).copied().unwrap_or(0)))),
    );
    cx.annotate("Java module (JMOD)");
    cx.emit(embedded_as("Contents", input.nested(file.tail(4)), &crate::formats::zip::FORMAT));
    Ok(())
}

record! {
    struct Header {
        magic: u32 "magic" .hex(),
        version: u32 "version" .hex() .with(|&v, n| n.summary(format!("{}.{}", v >> 16, v & 0xffff))),
        flags: u32 "flags" .hex(),
        resources: u32 "resourceCount",
        table: u32 "tableLength",
        locations: u32 "locationsSize" .hex(),
        strings: u32 "stringsSize" .hex(),
    }
}

/// One decoded location: name parts and content position.
#[derive(Default)]
struct Location {
    module: u64,
    parent: u64,
    base: u64,
    extension: u64,
    offset: u64,
    compressed: u64,
    uncompressed: u64,
}

fn location(data: &[u8], at: usize) -> Option<Location> {
    let mut loc = Location::default();
    let mut p = at;
    for _ in 0..8 {
        let byte = *data.get(p)?;
        let kind = byte >> 3;
        if kind == 0 {
            return Some(loc);
        }
        let len = usize::from(byte & 7).saturating_add(1);
        let bytes = data.get(p.checked_add(1)?..p.checked_add(1)?.checked_add(len)?)?;
        let value = bytes.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b));
        match kind {
            1 => loc.module = value,
            2 => loc.parent = value,
            3 => loc.base = value,
            4 => loc.extension = value,
            5 => loc.offset = value,
            6 => loc.compressed = value,
            7 => loc.uncompressed = value,
            _ => return None,
        }
        p = p.checked_add(1)?.checked_add(len)?;
    }
    Some(loc)
}

fn string(strings: &[u8], offset: u64) -> String {
    crate::text::until_nul(strings.get(to_usize(offset)..).unwrap_or_default())
}

pub async fn jimage(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, Header::SIZE);
    cx.emit(Header::node("Header", hspan, LE));
    let h = parse(&cx, hspan, LE, &(), Header::layout).await?;
    let table = u64::from(h.table);
    let redirect = file.sub(Header::SIZE, table.saturating_mul(4));
    let offsets = file.sub(redirect.end().saturating_sub(file.offset), table.saturating_mul(4));
    let locations = file.sub(offsets.end().saturating_sub(file.offset), h.locations.into());
    let strings = file.sub(locations.end().saturating_sub(file.offset), h.strings.into());
    let content = strings.end().saturating_sub(file.offset);
    cx.annotate(format!(
        "Java runtime image (jimage {}.{}), {} resources",
        h.version >> 16,
        h.version & 0xffff,
        h.resources
    ));
    cx.emit(Node::new("Redirect Table").span(redirect));
    cx.emit(Node::new("Strings").span(strings).lazy(crate::formats::binutil::cstrings, strings));
    cx.emit(
        Node::new("Resources")
            .span(offsets)
            .summary(format!("{} entries", h.table))
            .lazy(resources, (input, offsets, locations, strings, content)),
    );
    Ok(())
}

async fn resources(
    cx: Cx,
    (input, offsets, locations, strings, content): (Input, Span, Span, Span, u64),
) -> Result<()> {
    if locations.len.saturating_add(strings.len).saturating_add(offsets.len) > cx.limits().max_read {
        return Err(Diagnostic::limit("index too large").at(offsets));
    }
    let offs = cx.read(offsets).await?;
    let locs = cx.read(locations).await?;
    let strs = cx.read(strings).await?;
    let count = to_u64(offs.len()) / 4;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = u32_le(&offs, to_usize(i.saturating_mul(4))).unwrap_or(0);
        let entry = offsets.sub(i.saturating_mul(4), 4);
        let Some(loc) = location(&locs, to_usize(at.into())) else {
            cx.push(Node::new(format!("#{i}")).span(entry).diag(Diagnostic::malformed("bad location"))).await;
            continue;
        };
        let mut name = String::new();
        for (part, prefix, suffix) in [(loc.module, "/", "/"), (loc.parent, "", "/"), (loc.base, "", ""), (loc.extension, ".", "")] {
            let s = string(&strs, part);
            if !s.is_empty() {
                name.push_str(prefix);
                name.push_str(&s);
                name.push_str(suffix);
            }
        }
        let stored = if loc.compressed > 0 { loc.compressed } else { loc.uncompressed };
        let data = input.span.sub(content.saturating_add(loc.offset), stored);
        let mut summary = format!("{} bytes", loc.uncompressed);
        if loc.compressed > 0 {
            summary.push_str(&format!(", {} compressed", loc.compressed));
        }
        let node = Node::new(if name.is_empty() { format!("#{i}") } else { name })
            .span(entry)
            .summary(summary)
            .target(data);
        let node = if loc.compressed == 0 && loc.uncompressed > 0 {
            node.lazy(crate::formats::dissect_or_data, input.nested(data))
        } else {
            node
        };
        cx.push(node).await;
    }
    Ok(())
}
