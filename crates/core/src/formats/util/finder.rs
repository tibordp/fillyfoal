//! Classic Mac OS Finder information (`FInfo`), shared by AppleSingle and
//! AppleDouble, MacBinary, BinHex, StuffIt and HFS.

use crate::error::Result;
use crate::fields::Fields;
use crate::formats::util::fmt::fourcc_value;
use crate::value::{FlagTable, flag};

/// The Finder flags word.
pub const FINDER_FLAGS: FlagTable = &[
    flag(0x0001, "isOnDesk"),
    flag(0x0040, "isShared"),
    flag(0x0080, "hasNoINITs"),
    flag(0x0100, "hasBeenInited"),
    flag(0x0400, "hasCustomIcon"),
    flag(0x0800, "isStationery"),
    flag(0x1000, "nameLocked"),
    flag(0x2000, "hasBundle"),
    flag(0x4000, "isInvisible"),
    flag(0x8000, "isAlias"),
];

/// The high byte of the Finder flags, which MacBinary stores alone.
pub const FINDER_FLAGS_HIGH: FlagTable = &[
    flag(0x01, "hasBeenInited"),
    flag(0x04, "hasCustomIcon"),
    flag(0x08, "isStationery"),
    flag(0x10, "nameLocked"),
    flag(0x20, "hasBundle"),
    flag(0x40, "isInvisible"),
    flag(0x80, "isAlias"),
];

/// Emits the 16 bytes of an `FInfo` record: type, creator, flags, icon
/// location and folder. Returns the type and creator codes.
pub fn finder_info(f: &mut Fields<'_>) -> Result<([u8; 4], [u8; 4])> {
    let kind = f
        .bytes("File type", 4)
        .with(|b, n| n.value(fourcc_value(b)))
        .emit()?;
    let creator = f
        .bytes("Creator", 4)
        .with(|b, n| n.value(fourcc_value(b)))
        .emit()?;
    f.u16("Finder flags").flags(FINDER_FLAGS).emit()?;
    f.int::<i16>("Location v").emit()?;
    f.int::<i16>("Location h").emit()?;
    f.u16("Folder").emit()?;
    let code = |b: &[u8]| crate::bytes::array::<4>(b, 0).unwrap_or_default();
    Ok((code(&kind), code(&creator)))
}
