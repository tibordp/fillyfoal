//! PHP OPcache file cache entries (`opcache.file_cache`, `*.php.bin`): the
//! metadata header (system ID of the PHP build, sizes, timestamp,
//! checksum) followed by the serialized script and interned strings.

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::util::binutil::data_node;
use crate::formats::{Format, Input, Probe};
use crate::record;

pub static FORMAT: Format = Format {
    name: "php-opcache",
    title: "PHP OPcache file cache",
    extensions: &["bin"],
    mime: "application/octet-stream",
    probe: Probe::Magic(&[(0, b"OPCACHE\0")]),
    dissect: crate::expander!(dissect: Input),
};

record! {
    struct Header {
        magic: ascii[8] "magic",
        system_id: ascii[32] "system_id" .desc("Hash identifying the PHP build and settings"),
        mem_size: u64 "mem_size" .hex(),
        str_size: u64 "str_size" .hex(),
        script_offset: u64 "script_offset" .hex(),
        timestamp: u64 "timestamp" .timestamp(),
        checksum: u32 "checksum" .hex() .desc("Adler-32 of the body"),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    // The header is padded to 8 bytes (76 + 4).
    let hspan = file.sub(0, Header::SIZE);
    cx.emit(Header::node("Header", hspan, Endian::Little));
    let h = parse(&cx, hspan, Endian::Little, &(), Header::layout).await?;
    cx.annotate(format!(
        "PHP OPcache file, system ID {}, {:#x} bytes of script, {:#x} bytes of strings",
        h.system_id, h.mem_size, h.str_size
    ));
    let body = file.tail(80);
    let script = body.sub(0, h.mem_size);
    cx.emit(
        data_node("Script", script, h.mem_size)
            .summary(format!("script entry at {:#x}", h.script_offset)),
    );
    let strings = body.sub(h.mem_size, h.str_size);
    cx.emit(data_node("Interned Strings", strings, h.str_size));
    Ok(())
}
