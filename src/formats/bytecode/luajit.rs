//! LuaJIT bytecode dumps (`\x1bLJ`, from `luajit -b`): a header with flags
//! and the chunk name, then the function prototypes (innermost first),
//! each with its header counts and line information.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::binutil::{Reader, dec, text};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::value::{FlagTable, Value, flag};

pub static FORMAT: Format = Format {
    name: "luajit",
    title: "LuaJIT bytecode",
    extensions: &["ljbc", "luac", "raw"],
    mime: "application/x-luajit-bytecode",
    probe: Probe::Custom(|h| {
        h.starts_with(b"\x1bLJ") && h.data.get(3).is_some_and(|v| (1..=2).contains(v))
    }),
    dissect: crate::expander!(dissect: Input),
};

const FLAGS: FlagTable = &[
    flag(1, "BE"),
    flag(2, "STRIP"),
    flag(4, "FFI"),
    flag(8, "FR2"),
];

const PROTO_FLAGS: FlagTable = &[
    flag(1, "CHILD"),
    flag(2, "VARARG"),
    flag(4, "FFI"),
    flag(8, "NOJIT"),
    flag(16, "ILOOP"),
];

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if file.len > cx.limits().max_read {
        return Err(Diagnostic::limit("chunk too large").at(file));
    }
    let data = cx.read(file).await?;
    let mut r = Reader::new(&data);
    let at = |start: usize, end: usize| file.sub(to_u64(start), to_u64(end.saturating_sub(start)));
    r.bytes(3);
    let version = r.u8().unwrap_or(0);
    cx.emit(
        Node::new("signature")
            .span(file.sub(0, 3))
            .value(text("\\x1bLJ")),
    );
    cx.emit(
        Node::new("version")
            .span(file.sub(3, 1))
            .value(dec(version.into(), 8)),
    );
    let start = r.pos();
    let flags = r
        .uleb()
        .ok_or_else(|| Diagnostic::malformed("bad flags").at(file.sub(4, 1)))?;
    let (set, unknown) = crate::value::decode_flags(FLAGS, flags);
    cx.emit(
        Node::new("flags")
            .span(at(start, r.pos()))
            .value(Value::Flags {
                raw: flags,
                bits: 32,
                set,
                unknown,
            }),
    );
    let mut name = None;
    if flags & 2 == 0 {
        let start = r.pos();
        let len = r.uleb().unwrap_or(0);
        let bytes = r
            .bytes(usize::try_from(len).unwrap_or(usize::MAX))
            .unwrap_or_default();
        let s = String::from_utf8_lossy(bytes).into_owned();
        cx.emit(
            Node::new("chunkname")
                .span(at(start, r.pos()))
                .value(text(s.clone())),
        );
        name = Some(s);
    }
    // Count the prototypes first, so the summary is available at once.
    let mut total = 0usize;
    let mut scan = Reader::at(&data, r.pos());
    while let Some(size) = scan.uleb() {
        if total.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        if size == 0
            || scan
                .bytes(usize::try_from(size).unwrap_or(usize::MAX))
                .is_none()
        {
            break;
        }
        total = total.saturating_add(1);
    }
    let mut summary = format!("LuaJIT {version} bytecode, {total} prototypes");
    if let Some(n) = &name {
        summary.push_str(&format!(", from {}", n.trim_start_matches(['@', '='])));
    }
    if flags & 1 != 0 {
        summary.push_str(", big-endian");
    }
    cx.annotate(summary);
    let mut count = 0usize;
    loop {
        let start = r.pos();
        let Some(size) = r.uleb() else { break };
        if size == 0 {
            cx.emit(Node::new("end").span(at(start, r.pos())));
            break;
        }
        let body_start = r.pos();
        let Some(body) = r.bytes(usize::try_from(size).unwrap_or(usize::MAX)) else {
            cx.diag(Diagnostic::truncated(at(start, data.len()), 0));
            break;
        };
        let mut p = Reader::new(body);
        let mut fields = Vec::new();
        let mut field = |label: &'static str, p: &mut Reader<'_>, wide: bool| -> Option<u64> {
            let s = p.pos();
            let v = if wide { p.uleb()? } else { u64::from(p.u8()?) };
            let span = at(
                body_start.saturating_add(s),
                body_start.saturating_add(p.pos()),
            );
            let value = if label == "flags" {
                let (set, unknown) = crate::value::decode_flags(PROTO_FLAGS, v);
                Value::Flags {
                    raw: v,
                    bits: 8,
                    set,
                    unknown,
                }
            } else {
                dec(v, 32)
            };
            fields.push(Node::new(label).span(span).value(value));
            Some(v)
        };
        let decoded = (|| {
            field("flags", &mut p, false)?;
            let params = field("numparams", &mut p, false)?;
            field("framesize", &mut p, false)?;
            field("numuv", &mut p, false)?;
            field("numkgc", &mut p, true)?;
            field("numkn", &mut p, true)?;
            let bc = field("numbc", &mut p, true)?;
            let mut line = None;
            if flags & 2 == 0 {
                let dbg = field("sizedbg", &mut p, true)?;
                if dbg > 0 {
                    line = Some(field("firstline", &mut p, true)?);
                    field("numline", &mut p, true)?;
                }
            }
            Some((params, bc, line))
        })();
        let header_end = body_start.saturating_add(p.pos());
        fields.push(
            Node::new("bytecode, constants and debug info")
                .span(at(header_end, body_start.saturating_add(body.len()))),
        );
        let mut node = Node::new(format!("Prototype {count}")).span(at(start, r.pos()));
        node = match decoded {
            Some((params, bc, line)) => {
                let mut s = format!("{bc} instructions, {params} parameters");
                if let Some(l) = line {
                    s.push_str(&format!(", line {l}"));
                }
                node.summary(s)
            }
            None => node.diag(Diagnostic::malformed("truncated prototype header")),
        };
        cx.push(node.lazy(emit_all, fields)).await;
        count = count.saturating_add(1);
    }
    Ok(())
}

async fn emit_all(cx: Cx, nodes: Vec<Node>) -> Result<()> {
    for n in nodes {
        cx.emit(n);
    }
    Ok(())
}
