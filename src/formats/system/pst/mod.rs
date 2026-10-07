//! Outlook personal folders (PST) and offline storage (OST) files.
//!
//! Written from memory of [MS-PST]; the specification could not be
//! consulted while writing this, so field names follow it but anything
//! not checked against real files is a best effort. The Unicode layout is
//! checked against files written by Aspose.Email (an independent
//! implementation); the ANSI layout (32-bit IDs, 512-byte pages with a
//! different trailer order) only against our own synthetic file.
//!
//! The layers, bottom up:
//!
//! - **NDB** (`ndb`): the header and its root (the B-tree roots), 512-byte
//!   pages holding the node B-tree (NID → data block, subnode block,
//!   parent) and the block B-tree (BID → file offset, size, references);
//!   blocks with their trailers, data trees (XBLOCK, XXBLOCK) and subnode
//!   trees (SLBLOCK, SIBLOCK). Block contents are obfuscated with the
//!   "compressible encryption" byte permutation or the cyclic cipher keyed
//!   by the block ID; both are undone into derived sources so spans of
//!   decoded structures point at readable bytes.
//! - **LTP** (`ltp`): the heap-on-node (allocations addressed by HID), BTHs
//!   on it, property contexts (one object's properties) and table contexts
//!   (rows with a column per property).
//! - **Messaging** (`store`): the message store, the folder tree (from
//!   each folder's hierarchy table), each folder's contents table (paged,
//!   with resume marks), messages with their properties, bodies (plain
//!   text, HTML and compressed RTF as embedded content), recipients and attachments (files as
//!   embedded content; attached messages recursively).
//!
//! A PST "password" (`PidTagPstPassword`) is only a CRC that Outlook
//! checks before opening the file; the data is not encrypted with it, so
//! nothing here asks for one.
//!
//! Not covered: the 4 KiB-page layout of Outlook 2013 OSTs (version 36),
//! whose B-tree pages and (compressed) blocks are not known well enough
//! here (only its header is shown), the allocation maps (AMap, PMap, FMap,
//! FPMap, DList pages) and search folders' internals. Compressed RTF bodies are
//! decoded with `Codec::Lzfu`.

mod ltp;
mod ndb;
mod props;
mod store;

use crate::bytes::{u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::{Input, Probe};
use crate::value::{EnumTable, lookup};

use ndb::{Bref, Kind, Pst};

const LE: Endian = Endian::Little;

declare_format!(pub PST = "pst", "Outlook personal folders", ["pst", "ost"], "application/vnd.ms-outlook",
    Probe::Custom(|h| h.at(0, b"!BDN") && (h.at(8, b"SM") || h.at(8, b"SO") || h.at(8, b"SA"))), dissect);

const VERSIONS: EnumTable = &[
    (14, "ANSI"),
    (15, "ANSI"),
    (23, "Unicode"),
    (36, "Unicode, 4 KiB pages"),
    (37, "Unicode, 4 KiB pages"),
];
const CRYPT: EnumTable = &[
    (0, "NDB_CRYPT_NONE"),
    (1, "NDB_CRYPT_PERMUTE"),
    (2, "NDB_CRYPT_CYCLIC"),
    (0x10, "NDB_CRYPT_EDPCRYPTED"),
];
const AMAP_VALID: EnumTable = &[
    (0, "INVALID_AMAP"),
    (1, "VALID_AMAP1"),
    (2, "VALID_AMAP2"),
];
const CLIENTS: EnumTable = &[
    (0x4d53, "SM (PST)"),
    (0x4f53, "SO (OST)"),
    (0x4153, "SA (PAB)"),
];

/// The NID types, in `rgnid` order.
const NID_TYPES: [&str; 32] = [
    "NID_TYPE_HID",
    "NID_TYPE_INTERNAL",
    "NID_TYPE_NORMAL_FOLDER",
    "NID_TYPE_SEARCH_FOLDER",
    "NID_TYPE_NORMAL_MESSAGE",
    "NID_TYPE_ATTACHMENT",
    "NID_TYPE_SEARCH_UPDATE_QUEUE",
    "NID_TYPE_SEARCH_CRITERIA_OBJECT",
    "NID_TYPE_ASSOC_MESSAGE",
    "type 0x09",
    "NID_TYPE_CONTENTS_TABLE_INDEX",
    "NID_TYPE_RECEIVE_FOLDER_TABLE",
    "NID_TYPE_OUTGOING_QUEUE_TABLE",
    "NID_TYPE_HIERARCHY_TABLE",
    "NID_TYPE_CONTENTS_TABLE",
    "NID_TYPE_ASSOC_CONTENTS_TABLE",
    "NID_TYPE_SEARCH_CONTENTS_TABLE",
    "NID_TYPE_ATTACHMENT_TABLE",
    "NID_TYPE_RECIPIENT_TABLE",
    "NID_TYPE_SEARCH_TABLE_INDEX",
    "type 0x14",
    "type 0x15",
    "type 0x16",
    "type 0x17",
    "type 0x18",
    "type 0x19",
    "type 0x1a",
    "type 0x1b",
    "type 0x1c",
    "type 0x1d",
    "type 0x1e",
    "NID_TYPE_LTP",
];

#[derive(Clone, Copy, Debug)]
struct HeaderCtx {
    kind: Kind,
    crc_partial: u32,
    crc_full: Option<u32>,
    file_len: u64,
}

fn crc_check(stored: u32, computed: u32) -> Option<Diagnostic> {
    (stored != computed).then(|| {
        Diagnostic::warning(format!(
            "CRC {stored:#010x} does not match the computed {computed:#010x}"
        ))
    })
}

fn header_layout(f: &mut Fields<'_>, cx: &HeaderCtx) -> Result<()> {
    let wide = cx.kind != Kind::Ansi;
    f.ascii("dwMagic", 4).emit()?;
    f.u32("dwCRCPartial")
        .hex()
        .desc("CRC of the 471 bytes from wMagicClient")
        .check(|&v| crc_check(v, cx.crc_partial))
        .emit()?;
    f.u16("wMagicClient").enumeration(CLIENTS).hex().emit()?;
    f.u16("wVer").enumeration(VERSIONS).emit()?;
    f.u16("wVerClient").emit()?;
    f.u8("bPlatformCreate").emit()?;
    f.u8("bPlatformAccess").emit()?;
    f.u32("dwReserved1").hex().emit()?;
    f.u32("dwReserved2").hex().emit()?;
    if wide {
        f.u64("bidUnused").hex().emit()?;
        f.u64("bidNextP").hex().desc("Next page BID").emit()?;
    } else {
        f.u32("bidNextB").hex().desc("Next block BID").emit()?;
        f.u32("bidNextP").hex().desc("Next page BID").emit()?;
    }
    f.u32("dwUnique").emit()?;
    f.node(struct_node("rgnid", f.peek_span(128), LE, (), rgnid_layout));
    f.skip(128);
    if wide {
        f.u64("qwUnused").hex().emit()?;
    }
    let root_len = if wide { 72 } else { 40 };
    f.node(
        struct_node("root", f.peek_span(root_len), LE, *cx, root_layout)
            .desc("File size, allocation map state and the two B-tree roots"),
    );
    f.skip(root_len);
    if wide {
        f.u32("dwAlign").hex().emit()?;
    }
    f.bytes("rgbFM", 128).desc("Deprecated free map").emit()?;
    f.bytes("rgbFP", 128).desc("Deprecated free page map").emit()?;
    f.u8("bSentinel").hex().emit()?;
    f.u8("bCryptMethod")
        .enumeration(CRYPT)
        .desc("How block data is obfuscated")
        .emit()?;
    f.u16("rgbReserved").hex().emit()?;
    if wide {
        f.u64("bidNextB").hex().desc("Next block BID").emit()?;
        let full = cx.crc_full.unwrap_or(0);
        f.u32("dwCRCFull")
            .hex()
            .desc("CRC of the 516 bytes from wMagicClient")
            .check(|&v| crc_check(v, full))
            .emit()?;
    } else {
        f.u64("ullReserved").hex().emit()?;
        f.u32("dwReserved").hex().emit()?;
    }
    f.bytes("rgbReserved2", 3).emit()?;
    f.u8("bReserved").emit()?;
    f.bytes("rgbReserved3", 32).emit()?;
    Ok(())
}

fn rgnid_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    for name in NID_TYPES {
        f.u32(name)
            .hex()
            .desc("Next free NID index of this type")
            .emit()?;
    }
    Ok(())
}

fn root_layout(f: &mut Fields<'_>, cx: &HeaderCtx) -> Result<()> {
    let wide = cx.kind != Kind::Ansi;
    let len = cx.file_len;
    f.u32("dwReserved").hex().emit()?;
    f.uword("ibFileEof", wide)
        .hex()
        .desc("File size")
        .check(|&v| {
            (v != len).then(|| Diagnostic::warning(format!("file is {len:#x} bytes, not {v:#x}")))
        })
        .emit()?;
    f.uword("ibAMapLast", wide)
        .hex()
        .desc("Offset of the last allocation map page")
        .emit()?;
    f.uword("cbAMapFree", wide).desc("Free bytes in all allocation maps").emit()?;
    f.uword("cbPMapFree", wide).emit()?;
    f.uword("BREFNBT.bid", wide).hex().desc("Node B-tree root page").emit()?;
    f.uword("BREFNBT.ib", wide).hex().emit()?;
    f.uword("BREFBBT.bid", wide).hex().desc("Block B-tree root page").emit()?;
    f.uword("BREFBBT.ib", wide).hex().emit()?;
    f.u8("fAMapValid").enumeration(AMAP_VALID).emit()?;
    f.u8("bReserved").emit()?;
    f.u16("wReserved").emit()?;
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 564)).await?;
    let version = u16_le(&head, 10).unwrap_or(0);
    let kind = match version {
        14 | 15 => Kind::Ansi,
        23 => Kind::Unicode,
        36 | 37 => Kind::Unicode4k,
        other => {
            return Err(Diagnostic::unsupported(format!("PST format version {other}")));
        }
    };
    let wide = kind != Kind::Ansi;
    let header_len = if wide { 564 } else { 512 };
    let crc = |len: usize| {
        head.get(8..8usize.saturating_add(len))
            .map_or(0, |d| ndb::PST_CRC.checksum(d) as u32)
    };
    let hctx = HeaderCtx {
        kind,
        crc_partial: crc(471),
        crc_full: wide.then(|| crc(516)),
        file_len: file.len,
    };
    cx.emit(struct_node(
        "Header",
        file.sub(0, header_len),
        LE,
        hctx,
        header_layout,
    ));
    let word = |at: usize| {
        if wide {
            u64_le(&head, at)
        } else {
            u32_le(&head, at).map(u64::from)
        }
        .unwrap_or(0)
    };
    // The root's B-tree references and the crypt method.
    let (root, crypt_at) = if wide { (180usize, 513usize) } else { (164, 461) };
    let id: usize = if wide { 8 } else { 4 };
    let brefs_at = root.saturating_add(4).saturating_add(id.saturating_mul(4));
    let pst = Pst {
        input,
        kind,
        crypt: head.get(crypt_at).copied().unwrap_or(0),
        nbt: Bref {
            bid: word(brefs_at),
            ib: word(brefs_at.saturating_add(id)),
        },
        bbt: Bref {
            bid: word(brefs_at.saturating_add(id.saturating_mul(2))),
            ib: word(brefs_at.saturating_add(id.saturating_mul(3))),
        },
    };
    let mut description = format!(
        "{} {}",
        lookup(VERSIONS, version.into()).unwrap_or("?"),
        if u16_le(&head, 8) == Some(0x4f53) {
            "OST"
        } else {
            "PST"
        }
    );
    if kind == Kind::Unicode4k {
        cx.annotate(description);
        return Err(Diagnostic::unsupported(
            "4 KiB-page B-trees and blocks (OST 2013): layout not known well enough",
        ));
    }
    match pst.crypt {
        0 => {}
        1 => description.push_str(", compressible encryption"),
        2 => description.push_str(", cyclic encryption"),
        other => description.push_str(&format!(", encoding {other:#04x}")),
    }
    cx.emit(store::btree_node("Node B-tree", pst, pst.nbt));
    cx.emit(store::btree_node("Block B-tree", pst, pst.bbt));
    match store::top(&cx, &pst).await {
        Ok(name) => {
            if let Some(name) = name {
                description.push_str(&format!(", {name:?}"));
            }
        }
        Err(e) => cx.diag(e),
    }
    cx.annotate(description);
    Ok(())
}
