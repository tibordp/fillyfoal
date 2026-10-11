//! Bitcoin Core block files (`blk*.dat`).
//!
//! Each block is prefixed by the network's message start bytes (mainnet,
//! testnet3, testnet4, signet, regtest) and its size. Bitcoin Core 28.0 and
//! later obfuscate new block files with a random XOR key kept in `xor.dat`
//! (`-blocksxor`); such files have no recognisable magic and are not
//! identified.

use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::{Input, Probe};
use crate::record;
use crate::value::Value;

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// Bitcoin block files (blk*.dat)

declare_format!(pub BITCOIN_BLOCKS = "bitcoin-blocks", "Bitcoin block file", ["dat"], "application/x-bitcoin-blocks",
    Probe::Magic(&[(0, b"\xf9\xbe\xb4\xd9"), (0, b"\x0b\x11\x09\x07"), (0, b"\x0a\x03\xcf\x40"), (0, b"\xfa\xbf\xb5\xda"), (0, b"\x1c\x16\x3f\x28")]), bitcoin_blocks);

record! {
    pub struct BlockHeader {
        version: u32 "Version" .hex(),
        previous: bytes[32] "Previous block hash",
        merkle: bytes[32] "Merkle root",
        time: u32 "Time" .timestamp(),
        bits: u32 "Bits (target)" .hex(),
        nonce: u32 "Nonce",
    }
}

async fn bitcoin_blocks(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut blocks = 0u32;
    let mut first = None;
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let magic = cur.u32().await?;
        if magic == 0 {
            break; // preallocated zero tail
        }
        let size = cur.u32().await?;
        let header_span = cur.span(BlockHeader::SIZE);
        let header: BlockHeader = read_record(&cx, header_span, LE).await?;
        cur.seek(start.saturating_add(8).saturating_add(size.into()));
        blocks = blocks.saturating_add(1);
        first.get_or_insert(header.time);
        cx.progress(cur.pos(), file.len);
        cx.push(
            BlockHeader::node(format!("Block {blocks}"), header_span, LE)
                .value(Value::Timestamp {
                    unix_seconds: header.time.into(),
                })
                .summary(format!("{size} bytes"))
                .target(cur.since(start)),
        )
        .await;
    }
    let network = match cx.read(file.sub(0, 4)).await?.as_slice() {
        b"\xf9\xbe\xb4\xd9" => "mainnet",
        b"\x0b\x11\x09\x07" => "testnet3",
        b"\x0a\x03\xcf\x40" => "signet",
        b"\x1c\x16\x3f\x28" => "testnet4",
        _ => "regtest",
    };
    cx.annotate(format!("Bitcoin {network}, {blocks} block(s)"));
    Ok(())
}
