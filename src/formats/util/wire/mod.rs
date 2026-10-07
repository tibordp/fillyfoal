//! Readers for schema-driven binary encodings, shared by the formats built
//! on them and by the schemaless dissectors in `data::wire`:
//!
//! - `protobuf`: Protocol Buffers wire format (in memory and through a
//!   cursor) and a schema-driven message walker;
//! - `flatbuffers`: FlatBuffers tables, vectors and strings (in memory and
//!   through the context);
//! - `thrift`: Thrift binary and compact protocols over bytes in memory;
//! - `capnp`: Cap'n Proto segment tables and pointers.

pub mod capnp;
pub mod flatbuffers;
pub mod protobuf;
pub mod thrift;
