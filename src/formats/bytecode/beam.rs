//! Erlang/Elixir BEAM modules: an IFF-style container (`FOR1`, `BEAM`) of
//! chunks such as the atom table, code, imports, exports and literals.
//!
//! The atom table is read when a chunk that refers to atoms is expanded, so
//! imports, exports and local functions are shown as `module:function/arity`.

use std::sync::Arc;

use crate::bytes::{to_u64, u32_be};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::binutil::{Reader, data_node, ellipsize, text};
use crate::formats::{Codec, Format, Input, Probe, content};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::EnumTable;

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "beam",
    title: "Erlang BEAM module",
    extensions: &["beam"],
    mime: "application/x-erlang-binary",
    probe: Probe::Custom(|h| h.starts_with(b"FOR1") && h.at(8, b"BEAM")),
    dissect: crate::expander!(dissect: Input),
};

const CHUNK: EnumTable = &[
    (u32::from_be_bytes(*b"Atom") as u64, "atom table (Latin-1)"),
    (u32::from_be_bytes(*b"AtU8") as u64, "atom table (UTF-8)"),
    (u32::from_be_bytes(*b"Code") as u64, "code"),
    (u32::from_be_bytes(*b"StrT") as u64, "string table"),
    (u32::from_be_bytes(*b"ImpT") as u64, "imports"),
    (u32::from_be_bytes(*b"ExpT") as u64, "exports"),
    (u32::from_be_bytes(*b"LocT") as u64, "local functions"),
    (u32::from_be_bytes(*b"FunT") as u64, "lambdas"),
    (u32::from_be_bytes(*b"LitT") as u64, "literals (zlib)"),
    (u32::from_be_bytes(*b"Attr") as u64, "attributes"),
    (u32::from_be_bytes(*b"CInf") as u64, "compile info"),
    (u32::from_be_bytes(*b"Line") as u64, "line table"),
    (u32::from_be_bytes(*b"Dbgi") as u64, "debug info"),
    (u32::from_be_bytes(*b"Docs") as u64, "documentation"),
    (u32::from_be_bytes(*b"ExCk") as u64, "Elixir checker data"),
    (u32::from_be_bytes(*b"Meta") as u64, "metadata"),
    (u32::from_be_bytes(*b"Type") as u64, "types"),
    (u32::from_be_bytes(*b"Abst") as u64, "abstract code"),
];

#[derive(Clone, Copy, Debug)]
struct Chunk {
    id: [u8; 4],
    span: Span,
    data: Span,
}

type Module = Arc<Vec<Chunk>>;

fn chunk_id(id: &[u8; 4]) -> String {
    String::from_utf8_lossy(id).into_owned()
}

/// The atoms of the module (index 1 is the module name).
async fn atoms(cx: &Cx, m: &Module) -> Vec<String> {
    let Some(c) = m.iter().find(|c| &c.id == b"AtU8" || &c.id == b"Atom") else {
        return Vec::new();
    };
    let Ok(data) = cx.read(c.data.sub(0, 4 << 20)).await else {
        return Vec::new();
    };
    parse_atoms(&data, &c.id == b"AtU8").unwrap_or_default()
}

/// `(atoms, byte ranges)`; a negative count (OTP 28) means lengths use the
/// compact term encoding.
fn parse_atoms(data: &[u8], utf8: bool) -> Option<Vec<String>> {
    Some(
        atom_entries(data, utf8)?
            .into_iter()
            .map(|(s, _, _)| s)
            .collect(),
    )
}

fn atom_entries(data: &[u8], utf8: bool) -> Option<Vec<(String, usize, usize)>> {
    let mut r = Reader::new(data);
    let count = r.int::<i32>(BE)?;
    let compact = count < 0;
    let mut out = vec![("".to_owned(), 0, 0)];
    for _ in 0..count.unsigned_abs().min(1 << 20) {
        let start = r.pos();
        let len = if compact {
            let b = r.u8()?;
            if b & 0x08 == 0 {
                usize::from(b >> 4)
            } else {
                let next = r.u8()?;
                (usize::from(b & 0xe0) << 3) | usize::from(next)
            }
        } else {
            usize::from(r.u8()?)
        };
        let bytes = r.bytes(len)?;
        let s = if utf8 {
            String::from_utf8_lossy(bytes).into_owned()
        } else {
            bytes.iter().map(|&b| char::from(b)).collect()
        };
        out.push((s, start, r.pos()));
    }
    Some(out)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("magic", 4).emit()?;
    let size = f.u32("size").hex().desc("Bytes after this field").emit()?;
    f.ascii("form type", 4).emit()?;
    let end = u64::from(size).saturating_add(8).min(file.len);
    let mut cur = Cursor::new(&cx, file.sub(0, end), BE);
    cur.seek(12);
    let mut chunks = Vec::new();
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let header = cur.bytes(8).await?;
        let mut id = [0u8; 4];
        id.copy_from_slice(header.get(..4).unwrap_or(&[0; 4]));
        let len = u64::from(u32_be(&header, 4).unwrap_or(0));
        let data = file.sub(start.saturating_add(8), len);
        cur.skip(len.checked_next_multiple_of(4).unwrap_or(u64::MAX));
        chunks.push(Chunk {
            id,
            span: cur.since(start),
            data,
        });
    }
    let m: Module = Arc::new(chunks);
    let names = atoms(&cx, &m).await;
    let exports = match m.iter().find(|c| &c.id == b"ExpT") {
        Some(c) => cx
            .read_avail(c.data.sub(0, 4))
            .await
            .ok()
            .and_then(|d| u32_be(&d, 0)),
        None => None,
    };
    let mut summary = format!(
        "Erlang BEAM module {}",
        names.get(1).map_or("?", String::as_str)
    );
    if let Some(n) = exports {
        summary.push_str(&format!(", {n} exports"));
    }
    summary.push_str(&format!(", {} chunks", m.len()));
    cx.annotate(summary);
    cx.set_count(Count::Exact(to_u64(m.len()).saturating_add(3)));
    for (i, c) in m.iter().enumerate() {
        let id = u64::from(u32::from_be_bytes(c.id));
        let what = crate::value::lookup(CHUNK, id).unwrap_or("chunk");
        cx.push(
            Node::new(chunk_id(&c.id))
                .span(c.span)
                .summary(format!("{what}, {:#x} bytes", c.data.len))
                .lazy(chunk, (m.clone(), i, input)),
        )
        .await;
    }
    Ok(())
}

async fn chunk(cx: Cx, (m, index, input): (Module, usize, Input)) -> Result<()> {
    let c = *m
        .get(index)
        .ok_or_else(|| Diagnostic::internal("chunk index out of range"))?;
    let head = cx.block(c.span.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("id", 4).emit()?;
    f.u32("size").emit()?;
    match &c.id {
        b"AtU8" | b"Atom" => {
            let data = cx.read(c.data.sub(0, 4 << 20)).await?;
            let entries = atom_entries(&data, &c.id == b"AtU8")
                .ok_or_else(|| Diagnostic::malformed("bad atom table").at(c.data))?;
            for (i, (s, start, end)) in entries.into_iter().enumerate().skip(1) {
                cx.push(
                    Node::new(format!("{i}"))
                        .span(c.data.sub(to_u64(start), to_u64(end.saturating_sub(start))))
                        .value(text(s)),
                )
                .await;
            }
        }
        b"ImpT" | b"ExpT" | b"LocT" => {
            let names = atoms(&cx, &m).await;
            let atom = |i: u32| {
                usize::try_from(i)
                    .ok()
                    .and_then(|i| names.get(i))
                    .cloned()
                    .unwrap_or_else(|| format!("atom#{i}"))
            };
            let data = cx.read(c.data.sub(0, 4 << 20)).await?;
            let count = u32_be(&data, 0).unwrap_or(0);
            let entries = (to_u64(data.len()).saturating_sub(4) / 12).min(count.into());
            for i in 0..entries {
                let at = crate::bytes::to_usize(i.saturating_mul(12).saturating_add(4));
                let w =
                    |k: usize| u32_be(&data, at.saturating_add(k.saturating_mul(4))).unwrap_or(0);
                let (label, extra) = if &c.id == b"ImpT" {
                    (
                        format!("{}:{}/{}", atom(w(0)), atom(w(1)), w(2)),
                        String::new(),
                    )
                } else {
                    (
                        format!("{}/{}", atom(w(0)), w(1)),
                        format!("label {}", w(2)),
                    )
                };
                let mut node = Node::new(label).span(c.data.sub(to_u64(at), 12));
                if !extra.is_empty() {
                    node = node.summary(extra);
                }
                cx.push(node).await;
            }
        }
        b"FunT" => {
            let names = atoms(&cx, &m).await;
            let data = cx.read(c.data.sub(0, 4 << 20)).await?;
            let count = u32_be(&data, 0).unwrap_or(0);
            let entries = (to_u64(data.len()).saturating_sub(4) / 24).min(count.into());
            for i in 0..entries {
                let at = crate::bytes::to_usize(i.saturating_mul(24).saturating_add(4));
                let w =
                    |k: usize| u32_be(&data, at.saturating_add(k.saturating_mul(4))).unwrap_or(0);
                let name = usize::try_from(w(0))
                    .ok()
                    .and_then(|i| names.get(i))
                    .cloned()
                    .unwrap_or_default();
                cx.push(
                    Node::new(format!("{name}/{}", w(1)))
                        .span(c.data.sub(to_u64(at), 24))
                        .summary(format!(
                            "label {}, index {}, {} free variables",
                            w(2),
                            w(3),
                            w(4)
                        )),
                )
                .await;
            }
        }
        b"Code" => {
            let block = cx.block(c.data.sub(0, 20)).await?;
            let mut f = Fields::emitting(&cx, &block, BE);
            let sub = f
                .u32("sub-size")
                .desc("Header bytes after this field")
                .emit()?;
            f.u32("instruction set").emit()?;
            f.u32("opcode max").emit()?;
            f.u32("labels").emit()?;
            f.u32("functions").emit()?;
            let code = c.data.tail(u64::from(sub).saturating_add(4));
            cx.emit(data_node("Bytecode", code, code.len));
        }
        b"StrT" => {
            let bytes = cx.read_avail(c.data.sub(0, 0x10000)).await?;
            cx.emit(
                Node::new("Strings")
                    .span(c.data)
                    .value(text(ellipsize(&String::from_utf8_lossy(&bytes), 4096))),
            );
        }
        b"LitT" => {
            let block = cx.block(c.data.sub(0, 4)).await?;
            let size = Fields::emitting(&cx, &block, BE)
                .u32("uncompressed size")
                .emit()?;
            let body = c.data.tail(4);
            if size == 0 {
                cx.emit(Node::new("Literals").span(body).summary("uncompressed"));
            } else {
                cx.emit(content(
                    "Literals",
                    input,
                    body,
                    Codec::Zlib,
                    Some(size.into()),
                ));
            }
        }
        b"Line" => {
            let block = cx.block(c.data.sub(0, 20)).await?;
            let mut f = Fields::emitting(&cx, &block, BE);
            for name in [
                "version",
                "flags",
                "instruction count",
                "item count",
                "name count",
            ] {
                f.u32(name).emit()?;
            }
            cx.emit(data_node(
                "Line items",
                c.data.tail(20),
                c.data.len.saturating_sub(20),
            ));
        }
        _ => {
            cx.emit(data_node("Data", c.data, c.data.len));
        }
    }
    Ok(())
}
