//! POSIX ACLs and extended attribute namespaces shared by the Linux
//! filesystems: `getfacl`-style entry text, the VFS `posix_acl_xattr`
//! encoding (EROFS, Btrfs, F2FS, tar's `LIBARCHIVE.xattr`), and the name
//! index → prefix table of ext and EROFS.

use crate::bytes::{u16_le, u32_le};
use crate::value::EnumTable;

/// Extended attribute name indexes (ext4 `EXT4_XATTR_INDEX_*`, EROFS
/// `EROFS_XATTR_INDEX_*`): the prefix each stands for.
pub const NAME_INDEXES: EnumTable = &[
    (1, "user."),
    (2, "system.posix_acl_access"),
    (3, "system.posix_acl_default"),
    (4, "trusted."),
    (5, "lustre."),
    (6, "security."),
    (7, "system."),
    (8, "system.richacl"),
];

/// Whether `name` is an attribute holding a POSIX ACL.
pub fn is_acl_name(name: &[u8]) -> bool {
    name == b"system.posix_acl_access" || name == b"system.posix_acl_default"
}

/// One ACL entry as `getfacl` shows it: `user::rw-`, `group:100:r-x`.
/// Entries without a qualifier (owner, owning group, mask, other) ignore
/// `id`.
pub fn entry(tag: u32, id: u32, perm: u16) -> String {
    let who = match tag {
        0x01 => "user::".to_owned(),
        0x02 => format!("user:{id}:"),
        0x04 => "group::".to_owned(),
        0x08 => format!("group:{id}:"),
        0x10 => "mask::".to_owned(),
        0x20 => "other::".to_owned(),
        _ => format!("tag {tag:#x}:"),
    };
    let bit = |b: u16, c: char| if perm & b != 0 { c } else { '-' };
    format!("{who}{}{}{}", bit(4, 'r'), bit(2, 'w'), bit(1, 'x'))
}

/// A `posix_acl_xattr` value (version 2: little-endian `{tag u16, perm
/// u16, id u32}` entries after a version word) as `getfacl` short text.
pub fn xattr_v2(value: &[u8]) -> Option<String> {
    if u32_le(value, 0)? != 2 {
        return None;
    }
    let entries = value.get(4..)?.as_chunks::<8>().0;
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        out.push(entry(u16_le(e, 0)?.into(), u32_le(e, 4)?, u16_le(e, 2)?));
    }
    Some(out.join(", "))
}
