//! Diagnostics and errors.
//!
//! An error returned by a dissector and a diagnostic attached to a node are
//! the same thing: a kind, a message and optionally the bytes concerned.

use std::fmt;

use crate::span::Span;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DiagKind {
    /// The input ends before a structure does.
    Truncated,
    /// The input contradicts the format.
    Malformed,
    /// Valid (or plausibly valid) input that this dissector does not handle.
    Unsupported,
    /// A configured limit (read size, nesting depth, ...) was reached.
    Limit,
    /// Suspicious but tolerated, e.g. a checksum mismatch.
    Warning,
    /// Informational.
    Note,
    /// A bug in a dissector or in the framework.
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub kind: DiagKind,
    pub message: String,
    pub span: Option<Span>,
}

pub type Error = Diagnostic;
pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Diagnostic {
    pub fn new(kind: DiagKind, message: impl Into<String>) -> Self {
        Diagnostic {
            kind,
            message: message.into(),
            span: None,
        }
    }

    /// `wanted` could only be partially read: `available` bytes exist.
    pub fn truncated(wanted: Span, available: u64) -> Self {
        Diagnostic::new(
            DiagKind::Truncated,
            format!(
                "needed {:#x} bytes at {:#x}, only {:#x} available",
                wanted.len, wanted.offset, available
            ),
        )
        .at(wanted)
    }

    pub fn malformed(message: impl Into<String>) -> Self {
        Diagnostic::new(DiagKind::Malformed, message)
    }

    pub fn unsupported(message: impl Into<String>) -> Self {
        Diagnostic::new(DiagKind::Unsupported, message)
    }

    pub fn limit(message: impl Into<String>) -> Self {
        Diagnostic::new(DiagKind::Limit, message)
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Diagnostic::new(DiagKind::Warning, message)
    }

    pub fn note(message: impl Into<String>) -> Self {
        Diagnostic::new(DiagKind::Note, message)
    }

    /// Decoded output would exceed `limit` bytes (any integer type, `usize`
    /// included).
    pub fn output_limit(limit: impl TryInto<u64>) -> Self {
        Diagnostic::limit(format!(
            "decompressed data exceeds {:#x} bytes",
            limit.try_into().unwrap_or(u64::MAX)
        ))
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Diagnostic::new(DiagKind::Internal, message)
    }

    pub fn at(mut self, span: Span) -> Self {
        self.span = Some(span);
        self
    }
}

impl fmt::Display for DiagKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DiagKind::Truncated => "truncated",
            DiagKind::Malformed => "malformed",
            DiagKind::Unsupported => "unsupported",
            DiagKind::Limit => "limit",
            DiagKind::Warning => "warning",
            DiagKind::Note => "note",
            DiagKind::Internal => "internal",
        })
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)?;
        if let Some(span) = self.span {
            write!(f, " [{span}]")?;
        }
        Ok(())
    }
}

impl std::error::Error for Diagnostic {}
