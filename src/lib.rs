//! Lazy, sans-I/O structural dissection of files.
//!
//! A [`Session`] holds a lazily expanded tree of [`Node`]s describing one or
//! more byte sources. The host drives it: it asks for a node's children with
//! [`Session::expand`], runs the dissectors with [`Session::poll`], and
//! answers [`Progress::NeedBytes`] with [`Session::supply`]. The core never
//! performs I/O itself; see [`sync::Driver`] for a blocking adapter.
//!
//! Dissectors are ordinary `async fn`s taking a [`Cx`]. They read bytes,
//! emit child nodes, and suspend whenever bytes are missing, the work budget
//! runs out, or the requested page of children is full. No executor is
//! involved: the session polls the futures directly.
//!
//! See `DESIGN.md` for goals, non-goals and the reasoning behind them.

pub mod bytes;
mod cache;
pub mod codec;
pub mod cx;
pub mod dsl;
pub mod error;
pub mod fields;
pub mod formats;
pub mod node;
pub mod render;
pub mod secret;
pub mod session;
pub mod span;
pub mod sync;
pub mod text;
pub mod value;

pub use cx::{Block, Cx};
pub use dsl::{Chunk, ChunkLayout, Cursor, Path, Record};
pub use error::{DiagKind, Diagnostic, Error, Result};
pub use fields::{Endian, Field, Fields};
pub use node::{Count, Node};
pub use secret::{Secret, SecretKind, SecretRequest};
pub use session::{
    Address, ByteRequest, ChildState, Children, Interpretation, Limits, NodeId, Progress,
    ReadProgress, Wait,
};
/// A session over every registered format.
pub type Session = session::Session<formats::All>;
pub use span::{Origin, SourceId, Span};
pub use value::{Guid, Radix, Value};
