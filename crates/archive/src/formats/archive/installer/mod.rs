//! Windows installer payloads: NSIS (`nsis`), Inno Setup (`inno`) and
//! InstallShield (`installshield`: `.z` archives and `data1.hdr`/`.cab`
//! cabinets).
//!
//! NSIS and Inno Setup installers are a small Windows program (`setup.exe`)
//! with the installer data appended or embedded: NSIS data is the PE
//! overlay, found by detecting the overlay; Inno Setup's loader keeps a
//! table of offsets in resource `RCDATA #11111` (or at file offset 0x30
//! in old versions), which the PE dissector looks for
//! ([`inno::loader_table`]).
//!
//! None of these formats has a public specification. The layouts are from
//! memory of the vendors' sources (NSIS `fileform.h`, Inno Setup's
//! `Struct.pas`) and of independent readers (7-Zip, innoextract,
//! unshield); each module says what was checked against what.

pub mod inno;
pub mod installshield;
pub mod nsis;

use crate::formats::util::arcutil::human_size;
use crate::node::Node;
use crate::value::Value;

/// A FILETIME field (`None` for 0 and all ones, which mean "not set").
fn filetime(name: &'static str, ticks: u64) -> Option<Node> {
    (ticks != 0 && ticks != u64::MAX).then(|| {
        Node::new(name).value(Value::Timestamp {
            unix_seconds: crate::text::filetime_to_unix(ticks),
        })
    })
}

/// "N bytes" for summaries.
fn size(n: u64) -> String {
    human_size(n)
}
