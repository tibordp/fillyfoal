//! Helpers shared across format families: value constructors (`val`),
//! summary formatting (`fmt`), calendar arithmetic (`civil`), unusual
//! float encodings (`floats`), Mac Finder info (`finder`), archive and compression helpers
//! (`arcutil`), executable and bytecode helpers (`binutil`), helpers for data,
//! system-artifact and font dissectors (`datakit`), audio (`sound`) and video
//! (`vidutil`) helpers, line-oriented reading for text formats (`lines`), a
//! small JSON reader for headers embedded in binary formats (`json`),
//! Windows locale identifiers (`lcid`), MAPI property tags shared by Outlook
//! messages and PST files (`mapi`), pacing for synchronous work over
//! in-memory buffers (`pace`), and readers for schema-driven binary
//! encodings (`wire`: protobuf, FlatBuffers, Thrift, Cap'n Proto).

pub mod arcutil;
pub mod binutil;
pub mod civil;
pub mod datakit;
pub mod finder;
pub mod floats;
pub mod fmt;
pub mod json;
pub mod lcid;
pub mod lines;
pub mod mapi;
pub mod pace;
pub mod sound;
pub mod val;
pub mod vidutil;
pub mod wire;
