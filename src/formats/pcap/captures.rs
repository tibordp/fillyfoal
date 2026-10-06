//! Other packet captures: Bluetooth btsnoop and Microsoft Network Monitor.

use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Bluetooth btsnoop and Microsoft Network Monitor captures

declare_format!(pub BTSNOOP = "btsnoop", "Bluetooth HCI capture (btsnoop)", ["log", "cfa", "btsnoop"], "application/x-btsnoop",
    Probe::Magic(&[(0, b"btsnoop\0")]), btsnoop);

const BTSNOOP_LINKS: EnumTable = &[
    (1001, "HCI UART (H4)"),
    (1002, "HCI UART (H4) without direction"),
    (1003, "HCI BSCP"),
    (1004, "HCI Serial (H5)"),
];

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
        let unix =
            i64::try_from(micros.saturating_sub(0x00dc_ddb3_0f2f_8000) / 1_000_000).unwrap_or(0);
        cx.push(
            Node::new(format!("Packet {packets}"))
                .span(cur.since(start))
                .value(Value::Timestamp { unix_seconds: unix })
                .summary(format!(
                    "{} {}, {included}/{original} bytes",
                    if flags & 1 == 0 { "sent" } else { "received" },
                    if flags & 2 == 0 {
                        "data"
                    } else {
                        "command/event"
                    }
                )),
        )
        .await;
    }
    cx.annotate(format!(
        "btsnoop v{version}, {}, {packets} packets",
        lookup(BTSNOOP_LINKS, link.into()).unwrap_or("unknown link")
    ));
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
    cx.emit(
        Node::new("Frame table")
            .span(file.sub(table.into(), table_len.into()))
            .summary(format!("{} frames", table_len / 4)),
    );
    cx.annotate(format!(
        "Network Monitor {major}.{minor} ({magic}), {} frames",
        table_len / 4
    ));
    Ok(())
}
