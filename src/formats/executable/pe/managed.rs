//! .NET manifest resources: the blobs in the CLR header's resources
//! directory (each a 32-bit length and the data, 8-byte aligned), named by
//! the `ManifestResource` metadata table.
//!
//! Finding that table means sizing every table before it in the `#~`
//! stream, from the ECMA-335 (partition II, 22) column layouts as
//! remembered here; if that fails, the blobs are listed by walking the
//! directory, without names.

use super::Pe;
use crate::bytes::{to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::embedded;
use crate::node::Node;
use crate::span::Span;

/// Column kinds of the metadata tables.
#[derive(Clone, Copy)]
enum Col {
    U16,
    U32,
    Str,
    Guid,
    Blob,
    /// Index into one table.
    Idx(usize),
    /// Coded index over tables, with this many tag bits.
    Coded(&'static [usize], u32),
}

use Col::*;

const TYPE_DEF_OR_REF: Col = Coded(&[0x02, 0x01, 0x1b], 2);
const HAS_CONSTANT: Col = Coded(&[0x04, 0x08, 0x17], 2);
const HAS_CUSTOM_ATTRIBUTE: Col = Coded(
    &[
        0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20,
        0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b,
    ],
    5,
);
const HAS_FIELD_MARSHAL: Col = Coded(&[0x04, 0x08], 1);
const HAS_DECL_SECURITY: Col = Coded(&[0x02, 0x06, 0x20], 2);
const MEMBER_REF_PARENT: Col = Coded(&[0x02, 0x01, 0x1a, 0x06, 0x1b], 3);
const HAS_SEMANTICS: Col = Coded(&[0x14, 0x17], 1);
const METHOD_DEF_OR_REF: Col = Coded(&[0x06, 0x0a], 1);
const MEMBER_FORWARDED: Col = Coded(&[0x04, 0x06], 1);
const IMPLEMENTATION: Col = Coded(&[0x26, 0x23, 0x27], 2);
const CUSTOM_ATTRIBUTE_TYPE: Col = Coded(&[0x06, 0x0a], 3);
const RESOLUTION_SCOPE: Col = Coded(&[0x00, 0x1a, 0x23, 0x01], 2);

const MANIFEST_RESOURCE: usize = 0x28;

/// Columns of tables 0x00..=0x28 (the ones before and including
/// `ManifestResource`).
const TABLES: [&[Col]; 0x29] = [
    &[U16, Str, Guid, Guid, Guid],                           // Module
    &[RESOLUTION_SCOPE, Str, Str],                           // TypeRef
    &[U32, Str, Str, TYPE_DEF_OR_REF, Idx(0x04), Idx(0x06)], // TypeDef
    &[Idx(0x04)],                                            // FieldPtr
    &[U16, Str, Blob],                                       // Field
    &[Idx(0x06)],                                            // MethodPtr
    &[U32, U16, U16, Str, Blob, Idx(0x08)],                  // MethodDef
    &[Idx(0x08)],                                            // ParamPtr
    &[U16, U16, Str],                                        // Param
    &[Idx(0x02), TYPE_DEF_OR_REF],                           // InterfaceImpl
    &[MEMBER_REF_PARENT, Str, Blob],                         // MemberRef
    &[U16, HAS_CONSTANT, Blob],                              // Constant
    &[HAS_CUSTOM_ATTRIBUTE, CUSTOM_ATTRIBUTE_TYPE, Blob],    // CustomAttribute
    &[HAS_FIELD_MARSHAL, Blob],                              // FieldMarshal
    &[U16, HAS_DECL_SECURITY, Blob],                         // DeclSecurity
    &[U16, U32, Idx(0x02)],                                  // ClassLayout
    &[U32, Idx(0x04)],                                       // FieldLayout
    &[Blob],                                                 // StandAloneSig
    &[Idx(0x02), Idx(0x14)],                                 // EventMap
    &[Idx(0x14)],                                            // EventPtr
    &[U16, Str, TYPE_DEF_OR_REF],                            // Event
    &[Idx(0x02), Idx(0x17)],                                 // PropertyMap
    &[Idx(0x17)],                                            // PropertyPtr
    &[U16, Str, Blob],                                       // Property
    &[U16, Idx(0x06), HAS_SEMANTICS],                        // MethodSemantics
    &[Idx(0x02), METHOD_DEF_OR_REF, METHOD_DEF_OR_REF],      // MethodImpl
    &[Str],                                                  // ModuleRef
    &[Blob],                                                 // TypeSpec
    &[U16, MEMBER_FORWARDED, Str, Idx(0x1a)],                // ImplMap
    &[U32, Idx(0x04)],                                       // FieldRVA
    &[U32, U32],                                             // EncLog
    &[U32],                                                  // EncMap
    &[U32, U16, U16, U16, U16, U32, Blob, Str, Str],         // Assembly
    &[U32],                                                  // AssemblyProcessor
    &[U32, U32, U32],                                        // AssemblyOS
    &[U16, U16, U16, U16, U32, Blob, Str, Str, Blob],        // AssemblyRef
    &[U32, Idx(0x23)],                                       // AssemblyRefProcessor
    &[U32, U32, U32, Idx(0x23)],                             // AssemblyRefOS
    &[U32, Str, Blob],                                       // File
    &[U32, U32, Str, Str, IMPLEMENTATION],                   // ExportedType
    &[U32, U32, Str, IMPLEMENTATION],                        // ManifestResource
];

fn col_size(col: Col, rows: &[u32; 64], heaps: u8) -> u64 {
    let wide = |b: bool| if b { 4 } else { 2 };
    match col {
        U16 => 2,
        U32 => 4,
        Str => wide(heaps & 0x01 != 0),
        Guid => wide(heaps & 0x02 != 0),
        Blob => wide(heaps & 0x04 != 0),
        Idx(t) => wide(rows.get(t).copied().unwrap_or(0) > 0xffff),
        Coded(tables, bits) => {
            let max = tables
                .iter()
                .map(|&t| rows.get(t).copied().unwrap_or(0))
                .max()
                .unwrap_or(0);
            wide(u64::from(max) >= 1u64 << 16u32.saturating_sub(bits))
        }
    }
}

fn read_col(data: &[u8], at: usize, size: u64) -> u32 {
    if size == 2 {
        u16_le(data, at).map_or(0, u32::from)
    } else {
        u32_le(data, at).unwrap_or(0)
    }
}

struct Row {
    offset: u32,
    flags: u32,
    name: String,
    implementation: u32,
}

/// The `ManifestResource` rows, from the metadata root.
async fn manifest_rows(cx: &Cx, root: Span) -> Result<Vec<Row>> {
    let head = cx.read(root.sub(0, 16)).await?;
    let version_len = u64::from(u32_le(&head, 12).unwrap_or(0)).min(256);
    let mut at = 16u64.saturating_add(version_len);
    let counts = cx.read(root.sub(at, 4)).await?;
    let streams = u16_le(&counts, 2).unwrap_or(0);
    at = at.saturating_add(4);
    let (mut tables, mut strings) = (None, None);
    for _ in 0..streams.min(16) {
        let h = cx.read(root.sub(at, 8)).await?;
        let span = root.sub(
            u64::from(u32_le(&h, 0).unwrap_or(0)),
            u64::from(u32_le(&h, 4).unwrap_or(0)),
        );
        let (name, name_span) = cx.cstr(root.sub(at.saturating_add(8), 32)).await?;
        match name.as_str() {
            "#~" | "#-" => tables = Some(span),
            "#Strings" => strings = Some(span),
            _ => {}
        }
        at = at
            .saturating_add(8)
            .saturating_add(name_span.len.next_multiple_of(4));
    }
    let (Some(tables), Some(strings)) = (tables, strings) else {
        return Err(Diagnostic::malformed("no #~ or #Strings stream"));
    };
    let header = cx.read(tables.sub(0, 24)).await?;
    let heaps = header.get(6).copied().unwrap_or(0);
    let valid = u64_le(&header, 8).unwrap_or(0);
    if valid & (1 << MANIFEST_RESOURCE) == 0 {
        return Ok(Vec::new());
    }
    let present = u64::from(valid.count_ones());
    let counts = cx
        .read(tables.sub_exact(24, present.saturating_mul(4))?)
        .await?;
    let mut rows = [0u32; 64];
    let mut i = 0usize;
    for (t, slot) in rows.iter_mut().enumerate() {
        if valid & (1u64 << t) != 0 {
            *slot = u32_le(&counts, i.saturating_mul(4)).unwrap_or(0);
            i = i.saturating_add(1);
        }
    }
    let mut offset = 24u64.saturating_add(present.saturating_mul(4));
    if heaps & 0x40 != 0 {
        // Extra data after the row counts (seen in some obfuscated files).
        offset = offset.saturating_add(4);
    }
    let width = |t: usize| -> u64 {
        TABLES.get(t).map_or(0, |cols| {
            cols.iter().map(|&c| col_size(c, &rows, heaps)).sum()
        })
    };
    for t in 0..MANIFEST_RESOURCE {
        if valid & (1u64 << t) != 0 {
            let n = u64::from(rows.get(t).copied().unwrap_or(0));
            offset = offset.saturating_add(n.saturating_mul(width(t)));
        }
    }
    let row_width = width(MANIFEST_RESOURCE);
    let count = u64::from(rows.get(MANIFEST_RESOURCE).copied().unwrap_or(0));
    let table = cx
        .read(tables.sub_exact(offset, count.saturating_mul(row_width))?)
        .await?;
    let str_size = col_size(Str, &rows, heaps);
    let impl_size = col_size(IMPLEMENTATION, &rows, heaps);
    let mut out = Vec::new();
    for r in 0..count {
        cx.checkpoint().await;
        let base = to_usize(r.saturating_mul(row_width));
        let name_index = read_col(&table, base.saturating_add(8), str_size);
        let implementation = read_col(
            &table,
            base.saturating_add(8).saturating_add(to_usize(str_size)),
            impl_size,
        );
        let name = if u64::from(name_index) < strings.len {
            cx.cstr(strings.tail(name_index.into()).sub(0, 1024))
                .await
                .map(|(s, _)| s)
                .unwrap_or_default()
        } else {
            String::new()
        };
        out.push(Row {
            offset: u32_le(&table, base).unwrap_or(0),
            flags: u32_le(&table, base.saturating_add(4)).unwrap_or(0),
            name,
            implementation,
        });
    }
    Ok(out)
}

/// One resource blob: its length prefix and data.
async fn blob(cx: &Cx, res: Span, offset: u64) -> Result<Span> {
    let len = cx.read(res.sub_exact(offset, 4)?).await?;
    let len = u64::from(u32_le(&len, 0).unwrap_or(0));
    Ok(res.sub(offset.saturating_add(4), len))
}

pub(super) async fn resources(cx: Cx, (pe, root, res): (Pe, Span, Span)) -> Result<()> {
    match manifest_rows(&cx, root).await {
        Ok(rows) => {
            for row in rows {
                let visibility = match row.flags & 7 {
                    1 => "public",
                    2 => "private",
                    _ => "unknown visibility",
                };
                if row.implementation != 0 {
                    // Lives in another file or assembly.
                    let tag = match row.implementation & 3 {
                        0 => "file",
                        1 => "assembly",
                        _ => "exported type",
                    };
                    cx.push(Node::new(row.name).summary(format!(
                        "{visibility}, in {tag} #{}",
                        row.implementation >> 2
                    )))
                    .await;
                    continue;
                }
                let node = match blob(&cx, res, row.offset.into()).await {
                    Ok(span) => embedded(row.name, pe.input.nested(span))
                        .summary(format!("{visibility}, {} bytes", span.len)),
                    Err(e) => Node::new(row.name).diag(e),
                };
                cx.push(node).await;
            }
        }
        Err(e) => {
            cx.diag(Diagnostic::note(format!(
                "resource names unavailable ({}); listed in directory order",
                e.message
            )));
            let mut at = 0u64;
            let mut i = 0u32;
            while at.saturating_add(4) <= res.len {
                let span = blob(&cx, res, at).await?;
                cx.progress_in(res, span.end());
                cx.push(
                    embedded(format!("Resource {i}"), pe.input.nested(span))
                        .summary(format!("{} bytes", span.len)),
                )
                .await;
                at = at
                    .saturating_add(4)
                    .saturating_add(span.len)
                    .next_multiple_of(8);
                i = i.saturating_add(1);
            }
        }
    }
    Ok(())
}
