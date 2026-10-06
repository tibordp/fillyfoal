//! Music-production files: VST presets and banks (FXP/FXB) and FL Studio
//! projects. Guitar Pro tablature lives in [`super::guitar_pro`].

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// VST presets (FXP/FXB), FL Studio projects

declare_format!(pub FXP = "fxp", "VST preset / bank", ["fxp", "fxb"], "application/x-vst-preset",
    Probe::Magic(&[(0, b"CcnK")]), fxp);

const FXP_KINDS: EnumTable = &[
    (0x4678_4363, "FxCk (regular preset)"),
    (0x4650_6368, "FPCh (opaque preset chunk)"),
    (0x4678_426b, "FxBk (regular bank)"),
    (0x4642_4368, "FBCh (opaque bank chunk)"),
];

async fn fxp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 56)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Chunk magic", 4).emit()?;
    f.u32("Byte size").emit()?;
    let kind = f.u32("FX magic").enumeration(FXP_KINDS).emit()?;
    f.u32("Format version").emit()?;
    let plugin = f.ascii("Plugin ID", 4).emit()?;
    f.u32("Plugin version").emit()?;
    let count = f.u32("Parameters / programs").emit()?;
    let name = if kind == 0x4678_4363 || kind == 0x4650_6368 {
        f.ascii("Program name", 28).emit()?
    } else {
        String::new()
    };
    cx.emit(Node::new("Data").span(file.tail(f.pos())));
    cx.annotate(format!(
        "{} for plugin '{plugin}', {count} entries{}",
        lookup(FXP_KINDS, kind.into()).unwrap_or("VST data"),
        if name.is_empty() {
            String::new()
        } else {
            format!(", {name:?}")
        }
    ));
    Ok(())
}

declare_format!(pub FLP = "flp", "FL Studio project", ["flp"], "application/x-flp",
    Probe::Magic(&[(0, b"FLhd")]), flp);

async fn flp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 14)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    f.u32("Header length").emit()?;
    f.u16("Format").emit()?;
    let channels = f.u16("Channels").emit()?;
    let ppq = f.u16("Pulses per quarter note").emit()?;
    let data = cx.read(file.sub(14, 8)).await?;
    let len = u32_le(&data, 4).unwrap_or(0);
    let events = file.sub(22, len.into());
    cx.emit(
        Node::new("Events (FLdt)")
            .span(events)
            .lazy(flp_events, events),
    );
    cx.annotate(format!("FL Studio project, {channels} channels, {ppq} PPQ"));
    Ok(())
}

async fn flp_events(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    while !cur.at_end() {
        let start = cur.pos();
        let id = cur.u8().await?;
        let size: u64 = match id {
            0..=63 => 1,
            64..=127 => 2,
            128..=191 => 4,
            _ => {
                // Variable length: 7-bit varint size.
                let mut len = 0u64;
                for i in 0..4u32 {
                    let b = cur.u8().await?;
                    len |= u64::from(b & 0x7f)
                        .checked_shl(i.saturating_mul(7))
                        .unwrap_or(0);
                    if b & 0x80 == 0 {
                        break;
                    }
                }
                len
            }
        };
        let body = cur.span(size);
        cur.skip(size);
        let mut node = Node::new(format!("Event {id}")).span(cur.since(start));
        if id >= 192 && size < 256 {
            let text = cx.read_avail(body).await?;
            if text.len() >= 2 && text.get(1) == Some(&0) {
                node = node.summary(crate::text::utf16z(&text, LE).0);
            }
        }
        cx.push(node).await;
    }
    Ok(())
}
