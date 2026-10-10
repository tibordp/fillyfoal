//! Hermes bytecode bundles (React Native's JavaScript engine, `.hbc`,
//! `index.android.bundle`): the file header with table counts and sizes.

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::util::binutil::data_node;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::text::hex_lower;

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "hermes",
    title: "Hermes JavaScript bytecode",
    extensions: &["hbc", "bundle"],
    mime: "application/octet-stream",
    probe: Probe::Magic(&[(0, b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f")]),
    dissect: crate::expander!(dissect: Input),
};

record! {
    struct Header {
        magic: u64 "magic" .hex(),
        version: u32 "version",
        source_hash: bytes[20] "sourceHash" .with(|b, n| n.summary(hex_lower(b))),
        file_length: u32 "fileLength" .hex(),
        global_code: u32 "globalCodeIndex",
        functions: u32 "functionCount",
        string_kinds: u32 "stringKindCount",
        identifiers: u32 "identifierCount",
        strings: u32 "stringCount",
        overflow_strings: u32 "overflowStringCount",
        string_storage: u32 "stringStorageSize" .hex(),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, Header::SIZE);
    cx.emit(Header::node("Header", hspan, LE));
    let h = parse(&cx, hspan, LE, &(), Header::layout).await?;
    cx.annotate(format!(
        "Hermes bytecode v{}, {} functions, {} strings, {} identifiers",
        h.version, h.functions, h.strings, h.identifiers
    ));
    // The rest of the header (counts that vary between versions) is
    // padded to 128 bytes; the body follows.
    cx.emit(data_node(
        "Header (version-specific part)",
        file.sub(Header::SIZE, 128u64.saturating_sub(Header::SIZE)),
        128u64.saturating_sub(Header::SIZE),
    ));
    // The file ends with a 20-byte footer holding a SHA-1 of the rest.
    let footer_at = u64::from(h.file_length).saturating_sub(20).max(128);
    cx.emit(Node::new("Tables and bytecode").span(file.sub(128, footer_at.saturating_sub(128))));
    let footer = file.sub(footer_at, 20);
    let hash = cx.read_avail(footer).await?;
    cx.emit(
        Node::new("Footer")
            .span(footer)
            .value(crate::formats::util::val::text(hex_lower(&hash)))
            .desc("SHA-1 of everything before it"),
    );
    Ok(())
}
