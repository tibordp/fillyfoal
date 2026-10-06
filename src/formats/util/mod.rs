//! Helpers shared across format families: archive and compression helpers
//! (`arcutil`), executable and bytecode helpers (`binutil`), helpers for data,
//! system-artifact and font dissectors (`datakit`), audio (`sound`) and video
//! (`vidutil`) helpers, line-oriented reading for text formats (`lines`), and
//! a small JSON reader for headers embedded in binary formats (`json`).

pub mod arcutil;
pub(crate) mod binutil;
pub mod datakit;
pub mod json;
pub mod lines;
pub mod sound;
pub mod vidutil;
