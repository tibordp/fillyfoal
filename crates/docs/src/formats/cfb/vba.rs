//! VBA projects ([MS-OVBA]): the `PROJECT` and `PROJECTwm` streams, the
//! `VBA` storage's `_VBA_PROJECT` and `dir` streams, and module streams.
//! `dir` and module source code are compressed with the MS-OVBA scheme: a
//! signature byte, then LZNT1 chunks.

use std::sync::Arc;

use super::CfbRef;
use super::rec::{LE, quoted};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::Input;
use crate::formats::util::val::{hex, uint};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

/// Decompresses a CompressedContainer (a signature byte 1, then LZNT1
/// chunks) into a derived source, with the reason decoding stopped early if
/// it did.
async fn decompressed(cx: &Cx, span: Span) -> Result<(Span, Option<Diagnostic>)> {
    let signature = cx.read(span.sub(0, 1)).await?;
    if signature.first() != Some(&1) {
        return Err(Diagnostic::malformed("the signature byte is not 1").at(span.sub(0, 1)));
    }
    let codec = Codec::Lznt1 { size: None };
    let decoded = crate::codec::decode_span(cx, span.tail(1), &codec, None).await?;
    Ok((decoded.span, decoded.error))
}

const DIR_RECORDS: EnumTable = &[
    (0x0001, "PROJECTSYSKIND"),
    (0x0002, "PROJECTLCID"),
    (0x0003, "PROJECTCODEPAGE"),
    (0x0004, "PROJECTNAME"),
    (0x0005, "PROJECTDOCSTRING"),
    (0x0006, "PROJECTHELPFILEPATH"),
    (0x0007, "PROJECTHELPCONTEXT"),
    (0x0008, "PROJECTLIBFLAGS"),
    (0x0009, "PROJECTVERSION"),
    (0x000c, "PROJECTCONSTANTS"),
    (0x000d, "REFERENCEREGISTERED"),
    (0x000e, "REFERENCEPROJECT"),
    (0x000f, "PROJECTMODULES"),
    (0x0010, "Terminator"),
    (0x0013, "PROJECTCOOKIE"),
    (0x0014, "PROJECTLCIDINVOKE"),
    (0x0016, "REFERENCENAME"),
    (0x0019, "MODULENAME"),
    (0x001a, "MODULESTREAMNAME"),
    (0x001c, "MODULEDOCSTRING"),
    (0x001e, "MODULEHELPCONTEXT"),
    (0x0021, "MODULETYPE (procedural)"),
    (0x0022, "MODULETYPE (document, class or designer)"),
    (0x0025, "MODULEREADONLY"),
    (0x0028, "MODULEPRIVATE"),
    (0x002b, "Module terminator"),
    (0x002c, "MODULECOOKIE"),
    (0x002f, "REFERENCECONTROL"),
    (0x0030, "REFERENCECONTROL (extended)"),
    (0x0031, "MODULEOFFSET"),
    (0x0032, "MODULESTREAMNAME (Unicode)"),
    (0x0033, "REFERENCEORIGINAL"),
    (0x003c, "PROJECTCONSTANTS (Unicode)"),
    (0x003d, "PROJECTHELPFILEPATH (second)"),
    (0x003e, "REFERENCENAME (Unicode)"),
    (0x0040, "PROJECTDOCSTRING (Unicode)"),
    (0x0047, "MODULENAME (Unicode)"),
    (0x0048, "MODULEDOCSTRING (Unicode)"),
    (0x004a, "PROJECTCOMPATVERSION"),
];

const SYSKIND: EnumTable = &[
    (0, "16-bit Windows"),
    (1, "32-bit Windows"),
    (2, "Macintosh"),
    (3, "64-bit Windows"),
];

/// One record of the decompressed `dir` stream.
#[derive(Clone, Debug)]
struct DirRec {
    id: u16,
    at: u64,
    len: u64,
    data: Vec<u8>,
}

fn dir_records(data: &[u8]) -> Vec<DirRec> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at.saturating_add(6) <= data.len() && out.len() < 100_000 {
        let id = u16_le(data, at).unwrap_or(0);
        let mut size = to_usize(u32_le(data, at.saturating_add(2)).unwrap_or(0).into());
        if id == 0x0009 {
            // PROJECTVERSION: the size field is reserved (4); 6 bytes follow.
            size = 6;
        }
        let body = at.saturating_add(6);
        let end = body.saturating_add(size).min(data.len());
        out.push(DirRec {
            id,
            at: to_u64(at),
            len: to_u64(end.saturating_sub(at)),
            data: data.get(body..end).unwrap_or_default().to_vec(),
        });
        at = end;
        if id == 0x0010 {
            break;
        }
    }
    out
}

/// What module streams need from `dir`: stream name, module name, source
/// offset and type of each module, and the code page.
#[derive(Default)]
pub struct Project {
    pub codepage: u16,
    pub modules: Vec<(String, String, u32, bool)>,
}

async fn project(cx: &Cx, dir: Span) -> Arc<Project> {
    if let Some(found) = cx.cached::<Project>(dir, "vba-dir") {
        return found;
    }
    let mut p = Project {
        codepage: 1252,
        ..Project::default()
    };
    if let Ok((decoded, _)) = decompressed(cx, dir).await
        && let Ok(out) = cx.read(decoded).await
    {
        let mut current: Option<(String, String, u32, bool)> = None;
        for r in dir_records(&out) {
            match r.id {
                0x0003 => p.codepage = u16_le(&r.data, 0).unwrap_or(1252),
                0x0019 => {
                    current = Some((
                        String::new(),
                        super::rec::codepage_text(p.codepage, &r.data),
                        0,
                        false,
                    ))
                }
                0x001a => {
                    if let Some(m) = current.as_mut() {
                        m.0 = super::rec::codepage_text(p.codepage, &r.data);
                    }
                }
                0x0031 => {
                    if let Some(m) = current.as_mut() {
                        m.2 = u32_le(&r.data, 0).unwrap_or(0);
                    }
                }
                0x0022 => {
                    if let Some(m) = current.as_mut() {
                        m.3 = true;
                    }
                }
                0x002b => {
                    if let Some(m) = current.take() {
                        p.modules.push(m);
                    }
                }
                _ => {}
            }
        }
    }
    let p = Arc::new(p);
    cx.cache(dir, "vba-dir", p.clone());
    p
}

/// The `dir` stream: decompressed, then its records.
pub async fn dir(cx: &Cx, span: Span) -> Result<()> {
    let (out, error) = decompressed(cx, span).await?;
    let mut node = Node::new("Decompressed")
        .span(out)
        .summary(format!("{} bytes", out.len))
        .lazy(dir_node, out);
    if let Some(e) = error {
        node = node.diag(e);
    }
    cx.emit(node);
    Ok(())
}

async fn dir_node(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let records = dir_records(&data);
    let mut codepage = 1252u16;
    let mut module: Option<(String, u64, Vec<DirRec>)> = None;
    for r in records {
        if r.id == 0x0003 {
            codepage = u16_le(&r.data, 0).unwrap_or(1252);
        }
        if r.id == 0x0019 {
            module = Some((
                super::rec::codepage_text(codepage, &r.data),
                r.at,
                Vec::new(),
            ));
        }
        if module.is_some() {
            let done = r.id == 0x002b;
            if let Some(m) = module.as_mut() {
                m.2.push(r);
            }
            if done && let Some((name, at, list)) = module.take() {
                let end = list.last().map_or(at, |l| l.at.saturating_add(l.len));
                cx.push(
                    Node::new(format!("Module {}", quoted(&name, 40)))
                        .span(span.sub(at, end.saturating_sub(at)))
                        .summary(format!("{} records", list.len()))
                        .lazy(module_records, (span, Arc::new(list), codepage)),
                )
                .await;
            }
        } else {
            cx.push(record_node(span, &r, codepage)).await;
        }
    }
    if let Some((name, at, list)) = module {
        cx.push(
            Node::new(format!("Module {}", quoted(&name, 40)))
                .span(span.tail(at))
                .lazy(module_records, (span, Arc::new(list), codepage))
                .diag(Diagnostic::malformed("the module has no terminator")),
        )
        .await;
    }
    Ok(())
}

async fn module_records(
    cx: Cx,
    (span, list, codepage): (Span, Arc<Vec<DirRec>>, u16),
) -> Result<()> {
    for r in list.iter() {
        cx.push(record_node(span, r, codepage)).await;
    }
    Ok(())
}

fn record_node(span: Span, r: &DirRec, codepage: u16) -> Node {
    let name = lookup(DIR_RECORDS, r.id.into())
        .map_or_else(|| format!("Record {:#06x}", r.id), str::to_owned);
    let node = Node::new(name).span(span.sub(r.at, r.len));
    let d = &r.data;
    let unicode = matches!(r.id, 0x0032 | 0x003c | 0x003e | 0x0040 | 0x0047 | 0x0048);
    let text = matches!(
        r.id,
        0x0004 | 0x0005 | 0x0006 | 0x000c | 0x0016 | 0x0019 | 0x001a | 0x001c | 0x003d | 0x0033
    );
    if unicode {
        node.value(Value::Text(crate::text::utf16(d, LE)))
    } else if text {
        node.value(Value::Text(super::rec::codepage_text(codepage, d)))
    } else {
        match (r.id, d.len()) {
            (0x0001, 4) => node.value(crate::formats::util::val::enumv(
                u32_le(d, 0).unwrap_or(0),
                32,
                SYSKIND,
            )),
            (0x0002 | 0x0014, 4) => {
                let v = u32_le(d, 0).unwrap_or(0);
                node.value(hex(v, 32))
                    .summary(crate::formats::util::lcid::describe(v))
            }
            (0x0009, 6) => node.value(Value::Text(format!(
                "{}.{}",
                u32_le(d, 0).unwrap_or(0),
                u16_le(d, 4).unwrap_or(0)
            ))),
            (0x0031, 4) => node
                .value(hex(u32_le(d, 0).unwrap_or(0), 32))
                .summary("offset of the compressed source in the module stream"),
            (_, 2) => node.value(uint(u16_le(d, 0).unwrap_or(0), 16)),
            (_, 4) => node.value(uint(u32_le(d, 0).unwrap_or(0), 32)),
            (_, 0) => node.value(hex(r.id, 16)),
            _ => node
                .value(Value::Bytes(d.get(..64).unwrap_or(d).to_vec()))
                .summary(match r.id {
                    0x000d | 0x002f | 0x0030 | 0x000e => {
                        let libid = crate::text::latin1(d.get(4..).unwrap_or_default());
                        quoted(libid.trim_end_matches('\0'), 80)
                    }
                    _ => format!("{} bytes", d.len()),
                }),
        }
    }
}

/// `_VBA_PROJECT`: version information and the performance cache.
pub async fn vba_project(cx: &Cx, span: Span) -> Result<()> {
    cx.emit(struct_node("Header", span.sub(0, 7), LE, (), vba_header));
    if span.len > 7 {
        cx.emit(
            Node::new("PerformanceCache")
                .span(span.tail(7))
                .summary(format!(
                    "{} bytes of compiled code (version-specific)",
                    span.len.saturating_sub(7)
                )),
        );
    }
    Ok(())
}

fn vba_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Reserved1").hex().desc("0x61CC").emit()?;
    f.u16("Version")
        .hex()
        .desc("Version of the compiled code; 0xFFFF means the performance cache is to be ignored")
        .emit()?;
    f.u8("Reserved2").emit()?;
    f.u16("Reserved3").emit()?;
    Ok(())
}

/// A module stream: the performance cache, then the compressed source.
pub async fn module(
    cx: &Cx,
    cfb: &CfbRef,
    input: Input,
    storage: u32,
    name: &str,
    span: Span,
) -> Option<Result<()>> {
    let dir = super::child_stream(cx, cfb, storage, "dir").await?;
    let p = project(cx, dir).await;
    let (_, module, offset, document) = p.modules.iter().find(|(s, ..)| s == name)?.clone();
    Some(module_body(cx, input, span, &module, offset, document).await)
}

async fn module_body(
    cx: &Cx,
    input: Input,
    span: Span,
    module: &str,
    offset: u32,
    document: bool,
) -> Result<()> {
    let offset = u64::from(offset);
    cx.emit(
        Node::new("Module")
            .value(Value::Text(module.to_owned()))
            .summary(if document {
                "document, class or designer module"
            } else {
                "procedural module"
            }),
    );
    if offset > 0 {
        cx.emit(
            Node::new("PerformanceCache")
                .span(span.sub(0, offset))
                .summary(format!("{offset} bytes of compiled code")),
        );
    }
    let compressed = span.tail(offset);
    let (out, error) = decompressed(cx, compressed).await?;
    let preview = cx.read_avail(out.sub(0, 200)).await.unwrap_or_default();
    let mut node = Node::new("Source code")
        .span(out)
        .summary(format!(
            "{} bytes: {}",
            out.len,
            quoted(&crate::text::latin1(&preview), 60)
        ))
        .lazy(crate::formats::dissect_or_data, input.nested(out));
    if let Some(e) = error {
        node = node.diag(e);
    }
    cx.emit(
        Node::new("CompressedSourceCode")
            .span(compressed)
            .summary(format!("{} bytes", compressed.len)),
    );
    cx.emit(node);
    Ok(())
}

/// `PROJECT`: the project's text properties, line by line.
pub async fn project_stream(cx: &Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let mut at = 0usize;
    let mut section = String::new();
    while at < data.len() {
        cx.checkpoint().await;
        let end = data
            .get(at..)
            .and_then(|d| d.iter().position(|&b| b == b'\n'))
            .map_or(data.len(), |p| at.saturating_add(p).saturating_add(1));
        let line = crate::text::latin1(data.get(at..end).unwrap_or_default());
        let line = line.trim_end_matches(['\r', '\n']).to_owned();
        let node_span = span.sub(to_u64(at), to_u64(end.saturating_sub(at)));
        let node = if line.starts_with('[') {
            section = line.clone();
            Node::new(line)
                .span(node_span)
                .value(Value::Text(section.clone()))
                .summary("section")
        } else if let Some((k, v)) = line.split_once('=') {
            let desc = match k {
                "ID" => "Project CLSID",
                "Document" => "A document module and its version cookie",
                "Module" => "A procedural module",
                "Class" => "A class module",
                "BaseClass" => "A designer module",
                "Package" => "A designer's package CLSID",
                "HelpFile" => "Help file path",
                "HelpContextID" => "Help topic",
                "VersionCompatible32" => "Compatibility marker",
                "CMG" => "Protection state, encrypted (Data Encryption, MS-OVBA 2.4.3)",
                "DPB" => "Password hash, encrypted",
                "GC" => "Visibility state, encrypted",
                _ => "",
            };
            let mut n = Node::new(format!("{}{k}", if section.is_empty() { "" } else { "  " }))
                .span(node_span)
                .value(Value::Text(v.trim_matches('"').to_owned()));
            if !desc.is_empty() {
                n = n.desc(desc);
            }
            n
        } else {
            Node::new("Line").span(node_span).value(Value::Text(line))
        };
        cx.push(node).await;
        at = end;
    }
    Ok(())
}

/// `PROJECTwm`: module names in the project code page and in UTF-16.
pub async fn project_wm(cx: &Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let mut at = 0usize;
    while at < data.len() {
        cx.checkpoint().await;
        if u16_le(&data, at) == Some(0) && data.get(at) == Some(&0) {
            cx.push(
                Node::new("Terminator")
                    .span(span.sub(to_u64(at), 2))
                    .value(hex(0u16, 16)),
            )
            .await;
            break;
        }
        let Some(nul) = data.get(at..).and_then(|d| d.iter().position(|&b| b == 0)) else {
            break;
        };
        let mbcs = crate::text::latin1(data.get(at..at.saturating_add(nul)).unwrap_or_default());
        let w = at.saturating_add(nul).saturating_add(1);
        let (wide, used, _) = crate::text::utf16z(data.get(w..).unwrap_or_default(), LE);
        let end = w.saturating_add(used);
        cx.push(
            Node::new(format!("Module {}", quoted(&mbcs, 40)))
                .span(span.sub(to_u64(at), to_u64(end.saturating_sub(at))))
                .value(Value::Text(wide)),
        )
        .await;
        if end <= at {
            break;
        }
        at = end;
    }
    Ok(())
}
