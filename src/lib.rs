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
//! This crate gathers the workspace's crates: the core (`fillyfoal-core`,
//! with the codecs of `fillyfoal-codec`) and one crate per category of
//! formats, each behind a feature of its name (all on by default).
//!
//! See `DESIGN.md` for goals, non-goals and the reasoning behind them.

pub use fillyfoal_core::*;

pub mod formats;

/// A session over every format this build registers.
pub type Session = fillyfoal_core::session::Session<formats::All>;
