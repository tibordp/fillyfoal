//! UFS / FFS (BSD Unix File System) superblocks, versions 1 and 2.
//!
//! The superblock is at 8 KiB for UFS1 (and some UFS2 volumes); the
//! standard UFS2 location, 64 KiB, is beyond what probes see.

use crate::bytes::{u32_be, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::size;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::value::Value;

const MAGIC_OFFSET: usize = 1372;
const MAGIC: u64 = 1372;
const UFS1: u32 = 0x0001_1954;
const UFS2: u32 = 0x1954_0119;
const LOCATIONS: [u64; 2] = [8192, 65536];

pub static FORMAT: Format = Format {
    name: "ufs",
    title: "UFS / FFS filesystem",
    extensions: &["img", "ufs", "ffs"],
    mime: "application/x-ufs",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// The magic (and byte order) of a superblock whose magic field is at `o`.
fn magic_at(data: &[u8], o: usize) -> Option<(u32, Endian)> {
    [(u32_le(data, o)?, Endian::Little), (u32_be(data, o)?, Endian::Big)]
        .into_iter()
        .find(|(m, _)| *m == UFS1 || *m == UFS2)
}

fn probe(h: &Head<'_>) -> bool {
    LOCATIONS
        .iter()
        .any(|&l| magic_at(h.data, crate::bytes::to_usize(l).saturating_add(MAGIC_OFFSET)).is_some())
}

record! {
    /// The leading fields of `struct fs`.
    pub struct Superblock {
        _link: u32 "Unused (link)",
        _rlink: u32 "Unused (rlink)",
        sblkno: u32 "Superblock offset in group (fragments)",
        cblkno: u32 "Group block offset (fragments)",
        iblkno: u32 "Inode block offset (fragments)",
        dblkno: u32 "Data block offset (fragments)",
        old_cgoffset: u32 "Group offset (UFS1)",
        old_cgmask: u32 "Group mask (UFS1)",
        old_time: u32 "Written (UFS1)" .timestamp(),
        old_size: u32 "Fragments (UFS1)",
        old_dsize: u32 "Data fragments (UFS1)",
        ncg: u32 "Cylinder groups",
        bsize: u32 "Block size",
        fsize: u32 "Fragment size",
        frag: u32 "Fragments per block",
        minfree: u32 "Minimum free (%)",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let mut found = None;
    for at in LOCATIONS {
        let raw = cx.read_avail(vol.sub(at.saturating_add(MAGIC), 4)).await?;
        if let Some((magic, endian)) = magic_at(&raw, 0) {
            found = Some((at, magic, endian));
            break;
        }
    }
    let Some((at, magic, endian)) = found else {
        return Err(Diagnostic::malformed("no UFS superblock"));
    };
    let span = vol.sub(at, Superblock::SIZE);
    let sb = parse(&cx, span, endian, &(), Superblock::layout).await?;
    cx.emit(Superblock::node("Superblock", vol.sub(at, 1376), endian));
    let ufs2 = magic == UFS2;
    let raw = cx.read_avail(vol.sub(at, 1376)).await?;
    let get_u64 = |o: usize| -> u64 {
        let b: [u8; 8] = raw.get(o..o.saturating_add(8)).and_then(|s| s.try_into().ok()).unwrap_or([0; 8]);
        match endian {
            Endian::Little => u64::from_le_bytes(b),
            Endian::Big => u64::from_be_bytes(b),
        }
    };
    let (fragments, mount, volume) = if ufs2 {
        (
            get_u64(1080),
            crate::text::until_nul(raw.get(212..680).unwrap_or_default()),
            crate::text::until_nul(raw.get(680..712).unwrap_or_default()),
        )
    } else {
        (u64::from(sb.old_size), crate::text::until_nul(raw.get(212..724).unwrap_or_default()), String::new())
    };
    cx.emit(Node::new("Last mount point").span(vol.sub(at.saturating_add(212), 468)).value(Value::Text(mount.clone())));
    if ufs2 {
        cx.emit(Node::new("Volume name").span(vol.sub(at.saturating_add(680), 32)).value(Value::Text(volume.clone())));
    }
    cx.emit(Node::new("Magic").span(vol.sub(at.saturating_add(MAGIC), 4)).value(Value::UInt {
        value: magic.into(),
        bits: 32,
        radix: crate::value::Radix::Hex,
    }));
    cx.annotate(format!(
        "{} filesystem{}{}, {}, {} cylinder groups, {}-byte blocks",
        if ufs2 { "UFS2" } else { "UFS1" },
        if volume.is_empty() { String::new() } else { format!(" \"{volume}\"") },
        if mount.is_empty() { String::new() } else { format!(" (last mounted on {mount})") },
        size(fragments.saturating_mul(sb.fsize.into())),
        sb.ncg,
        sb.bsize
    ));
    Ok(())
}
