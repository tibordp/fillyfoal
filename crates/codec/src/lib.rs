//! fillyfoal's byte primitives, diagnostics and spans, and the codecs it
//! decodes with: decompressors, character sets, filters and cryptography,
//! all incremental and free of I/O. The `fillyfoal` crate re-exports them.

pub mod bytes;
pub mod codec;
pub mod error;
pub mod span;
pub mod text;
