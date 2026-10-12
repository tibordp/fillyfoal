//! Serialized property stores ([MS-PROPSTORE]): the Windows shell's way
//! of writing an `IPropertyStore` out, found in shell links
//! (PropertyStoreDataBlock), jump lists and shell item lists. A store is a
//! list of storages, each a size, the version `1SPS`, a format ID (FMTID)
//! and values keyed by integer ID, or by name in the
//! `D5CDD505-2E9C-101B-9397-08002B2CF9AE` storage; a size of zero ends
//! each list. Values are the `TypedPropertyValue`s of OLE property sets,
//! decoded by [`super::propset`].

use crate::bytes::{to_u64, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::datakit::guid_le;
use crate::formats::util::val::uint;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Guid, Value};

use super::propset;

const LE: Endian = Endian::Little;
/// "1SPS", little-endian.
const VERSION: &[u8; 4] = b"1SPS";
/// Bytes of a storage header: size, version, FMTID.
const STORAGE_HEADER: u64 = 24;
/// Bytes of a value read to decode it.
const MAX_VALUE: u64 = 1 << 20;
/// Property stores write 8-bit strings, rare as they are, in this code
/// page (MS-PROPSTORE 2.2: CP_WINUNICODE).
const CODEPAGE: u16 = 1200;

pub static FORMAT: Format = Format {
    name: "ms-propstore",
    title: "Windows serialized property store",
    extensions: &[],
    mime: "application/x-ms-propstore",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.data.get(4..8) == Some(VERSION)
        && u32_le(h.data, 0)
            .is_some_and(|size| u64::from(size) >= STORAGE_HEADER && u64::from(size) <= h.len)
}

/// Property keys (FMTID and ID) of the shell's well-known properties
/// (`propkey.h`) that shell links and jump lists carry.
const KNOWN: &[(Guid, u32, &str)] = &[
    (STORAGE, 2, "System.ItemFolderNameDisplay"),
    (STORAGE, 4, "System.ItemTypeText"),
    (STORAGE, 10, "System.ItemNameDisplay"),
    (STORAGE, 12, "System.Size"),
    (STORAGE, 13, "System.FileAttributes"),
    (STORAGE, 14, "System.DateModified"),
    (STORAGE, 15, "System.DateCreated"),
    (STORAGE, 16, "System.DateAccessed"),
    (APP_USER_MODEL, 2, "System.AppUserModel.RelaunchCommand"),
    (
        APP_USER_MODEL,
        3,
        "System.AppUserModel.RelaunchIconResource",
    ),
    (
        APP_USER_MODEL,
        4,
        "System.AppUserModel.RelaunchDisplayNameResource",
    ),
    (APP_USER_MODEL, 5, "System.AppUserModel.ID"),
    (APP_USER_MODEL, 9, "System.AppUserModel.PreventPinning"),
    (LINK, 2, "System.Link.TargetParsingPath"),
    (LINK, 8, "System.Link.TargetSFGAOFlags"),
    (SHELL_DETAILS, 24, "System.ParsingName"),
    (SHELL_DETAILS, 30, "System.ParsingPath"),
    (THUMBNAIL, 100, "System.ThumbnailCacheId"),
    (THUMBNAIL, 104, "System.VolumeId"),
    (FOLDER_PATH, 6, "System.ItemFolderPathDisplay"),
];

/// `B725F130-47EF-101A-A5F1-02608C9EEBAC`.
const STORAGE: Guid = Guid {
    data1: 0xb725_f130,
    data2: 0x47ef,
    data3: 0x101a,
    data4: [0xa5, 0xf1, 0x02, 0x60, 0x8c, 0x9e, 0xeb, 0xac],
};
/// `9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3`.
const APP_USER_MODEL: Guid = Guid {
    data1: 0x9f4c_2855,
    data2: 0x9f79,
    data3: 0x4b39,
    data4: [0xa8, 0xd0, 0xe1, 0xd4, 0x2d, 0xe1, 0xd5, 0xf3],
};
/// `B9B4B3FC-2B51-4A42-B5D8-324146AFCF25`.
const LINK: Guid = Guid {
    data1: 0xb9b4_b3fc,
    data2: 0x2b51,
    data3: 0x4a42,
    data4: [0xb5, 0xd8, 0x32, 0x41, 0x46, 0xaf, 0xcf, 0x25],
};
/// `28636AA6-953D-11D2-B5D6-00C04FD918D0`.
const SHELL_DETAILS: Guid = Guid {
    data1: 0x2863_6aa6,
    data2: 0x953d,
    data3: 0x11d2,
    data4: [0xb5, 0xd6, 0x00, 0xc0, 0x4f, 0xd9, 0x18, 0xd0],
};
/// `446D16B1-8DAD-4870-A748-402EA43D788C`.
const THUMBNAIL: Guid = Guid {
    data1: 0x446d_16b1,
    data2: 0x8dad,
    data3: 0x4870,
    data4: [0xa7, 0x48, 0x40, 0x2e, 0xa4, 0x3d, 0x78, 0x8c],
};

/// `E3E0584C-B788-4A5A-BB20-7F5A44C9ACDD`.
const FOLDER_PATH: Guid = Guid {
    data1: 0xe3e0_584c,
    data2: 0xb788,
    data3: 0x4a5a,
    data4: [0xbb, 0x20, 0x7f, 0x5a, 0x44, 0xc9, 0xac, 0xdd],
};

fn property_name(fmtid: &Guid, id: u32) -> String {
    KNOWN
        .iter()
        .find(|(g, i, _)| g == fmtid && *i == id)
        .map(|(_, _, n)| *n)
        .or_else(|| propset::known_name(fmtid, id))
        .map_or_else(|| format!("Property {id}"), str::to_owned)
}

/// Lists the storages, up to the terminating zero size.
pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut at = 0u64;
    let mut count = 0u64;
    while at.saturating_add(4) <= file.len {
        let head = cx.read_avail(file.sub(at, STORAGE_HEADER)).await?;
        let size = u64::from(u32_le(&head, 0).unwrap_or(0));
        if size == 0 {
            cx.push(Node::new("Terminator").span(file.sub(at, 4))).await;
            at = at.saturating_add(4);
            break;
        }
        let fmtid = head.get(8..24).map(guid_le);
        let (Some(fmtid), true, true) = (
            fmtid,
            head.get(4..8) == Some(VERSION),
            size >= STORAGE_HEADER,
        ) else {
            return Err(Diagnostic::malformed(format!(
                "no serialized property storage at {at:#x}"
            ))
            .at(file.sub(at, 8)));
        };
        let storage = file.sub(at, size);
        let mut node = Node::new(format!("Storage {count}"))
            .span(storage)
            .value(Value::Guid(fmtid))
            .lazy(self::storage, (input, storage, fmtid));
        if storage.len < size {
            node = node.diag(Diagnostic::truncated(storage, size));
        }
        cx.push(node).await;
        at = at.saturating_add(size);
        count = count.saturating_add(1);
    }
    if at < file.len {
        cx.push(
            Node::new("Trailing data")
                .span(file.tail(at))
                .summary("after the terminator"),
        )
        .await;
    }
    cx.annotate(format!(
        "serialized property store, {}",
        crate::formats::util::fmt::plural(count, "storage")
    ));
    Ok(())
}

/// A storage: its header, then its values up to the terminating zero size.
async fn storage(cx: Cx, (input, storage, fmtid): (Input, Span, Guid)) -> Result<()> {
    let header = cx.block(storage.sub(0, STORAGE_HEADER)).await?;
    let mut f = Fields::emitting(&cx, &header, LE);
    f.u32("StorageSize").emit()?;
    f.ascii("Version", 4).emit()?;
    f.guid("FormatID").emit()?;
    let named = propset::is_user_defined(&fmtid);
    let mut at = STORAGE_HEADER;
    while at.saturating_add(4) <= storage.len {
        let entry = storage.tail(at);
        let head = cx.read_avail(entry.sub(0, 4)).await?;
        let size = u64::from(u32_le(&head, 0).unwrap_or(0));
        if size == 0 {
            cx.push(Node::new("Terminator").span(entry.sub(0, 4))).await;
            return Ok(());
        }
        if size < 9 {
            cx.diag(Diagnostic::malformed(format!("value of {size} bytes")).at(entry.sub(0, 4)));
            return Ok(());
        }
        let value = entry.sub(0, size);
        let data = cx.read_avail(value.sub(0, MAX_VALUE)).await?;
        let (name, typed_at) = if named {
            let name_size = u32_le(&data, 4).unwrap_or(0);
            let end = 9usize.saturating_add(crate::bytes::to_usize(name_size.into()));
            let raw = data.get(9..end).unwrap_or_default();
            (crate::text::utf16_trimmed(raw, LE), end)
        } else {
            let id = u32_le(&data, 4).unwrap_or(0);
            (property_name(&fmtid, id), 9)
        };
        let typed = value.tail(to_u64(typed_at));
        let decoded = propset::typed_value(
            input,
            "Value",
            typed,
            data.get(typed_at..).unwrap_or_default(),
            CODEPAGE,
        );
        let mut node = Node::new(name).span(value);
        if let Some(v) = &decoded.value {
            node = node.value(v.clone());
        }
        if let Some(s) = &decoded.summary {
            node = node.summary(s.clone());
        }
        if value.len < size {
            node = node.diag(Diagnostic::truncated(value, size));
        }
        cx.push(node.lazy(self::value, (input, value, named, to_u64(typed_at))))
            .await;
        at = at.saturating_add(size);
    }
    Ok(())
}

/// A value's header (size, ID or name), then the typed value itself.
async fn value(cx: Cx, (input, value, named, typed_at): (Input, Span, bool, u64)) -> Result<()> {
    let head = cx.read_avail(value.sub(0, 9)).await?;
    cx.emit(
        Node::new("ValueSize")
            .span(value.sub(0, 4))
            .value(uint(value.len, 32)),
    );
    let field = u32_le(&head, 4).unwrap_or(0);
    if named {
        cx.emit(
            Node::new("NameSize")
                .span(value.sub(4, 4))
                .value(uint(field, 32)),
        );
    } else {
        cx.emit(Node::new("Id").span(value.sub(4, 4)).value(uint(field, 32)));
    }
    cx.emit(
        Node::new("Reserved")
            .span(value.sub(8, 1))
            .value(uint(head.get(8).copied().unwrap_or(0), 8)),
    );
    if named {
        let name = value.sub(9, field.into());
        let text = crate::text::utf16_trimmed(&cx.read_avail(name).await?, LE);
        cx.emit(Node::new("Name").span(name).value(Value::Text(text)));
    }
    let data = cx.read_avail(value.sub(typed_at, MAX_VALUE)).await?;
    cx.emit(propset::typed_value(
        input,
        "Value",
        value.tail(typed_at),
        &data,
        CODEPAGE,
    ));
    Ok(())
}
