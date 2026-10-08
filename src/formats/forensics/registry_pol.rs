//! Group Policy registry files (`Registry.pol`).

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

// ---------------------------------------------------------------------------
// Group Policy Registry.pol

declare_format!(pub REGISTRY_POL = "registry-pol", "Group Policy registry settings (Registry.pol)", ["pol"], "application/x-registry-pol",
    Probe::Magic(&[(0, b"PReg\x01\0\0\0")]), registry_pol);

const REG_TYPES: EnumTable = &[
    (0, "REG_NONE"),
    (1, "REG_SZ"),
    (2, "REG_EXPAND_SZ"),
    (3, "REG_BINARY"),
    (4, "REG_DWORD"),
    (5, "REG_DWORD_BIG_ENDIAN"),
    (7, "REG_MULTI_SZ"),
    (11, "REG_QWORD"),
];

async fn registry_pol(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Header").span(file.sub(0, 8)));
    let max = cx.limits().max_read;
    let data = cx.read_avail(file.sub(8, max)).await?;
    // Entries: [key;value;type;size;data] with UTF-16LE text and ';' separators.
    let mut at = 0usize;
    let mut count = 0u32;
    while at.saturating_add(2) <= data.len() {
        if u16_le(&data, at) != Some(u16::from(b'[')) {
            break;
        }
        let start = at;
        cx.progress_in(
            file,
            file.offset.saturating_add(8).saturating_add(to_u64(at)),
        );
        let mut fields: Vec<String> = Vec::new();
        let mut cursor = at.saturating_add(2);
        for _ in 0..2 {
            let (s, used, _) = crate::text::utf16z(data.get(cursor..).unwrap_or_default(), LE);
            fields.push(s);
            cursor = cursor.saturating_add(used).saturating_add(2); // NUL + ';'
        }
        let kind = u32_le(&data, cursor).unwrap_or(0);
        let size = u32_le(&data, cursor.saturating_add(6)).unwrap_or(0);
        let value_at = cursor.saturating_add(12);
        let value = data
            .get(value_at..value_at.saturating_add(usize::try_from(size).unwrap_or(0)))
            .unwrap_or_default();
        let shown = match kind {
            1 | 2 | 7 => crate::text::utf16(value, LE)
                .trim_end_matches('\0')
                .replace('\0', " | "),
            4 => u32_le(value, 0).unwrap_or(0).to_string(),
            11 => crate::bytes::u64_le(value, 0).unwrap_or(0).to_string(),
            _ => format!("{} bytes", value.len()),
        };
        at = value_at
            .saturating_add(usize::try_from(size).unwrap_or(0))
            .saturating_add(2); // ']'
        count = count.saturating_add(1);
        cx.push(
            Node::new(format!(
                "{}\\{}",
                fields.first().cloned().unwrap_or_default(),
                fields.get(1).cloned().unwrap_or_default()
            ))
            .span(file.sub(
                8u64.saturating_add(to_u64(start)),
                to_u64(at.saturating_sub(start)),
            ))
            .value(text(shown))
            .summary(lookup(REG_TYPES, kind.into()).unwrap_or("unknown type")),
        )
        .await;
    }
    cx.annotate(format!("{count} policy settings"));
    Ok(())
}
