//! Secrets (passwords and keys) that the host supplies on request.
//!
//! A dissector that meets encrypted content asks for a secret with
//! [`Cx::secret`](crate::Cx::secret) and suspends, just as it does for missing
//! bytes. [`Session::poll`](crate::Session::poll) then reports
//! [`Progress::NeedSecret`](crate::Progress::NeedSecret); the host prompts the
//! user (or consults a keychain) and answers with
//! [`Session::answer_secret`](crate::Session::answer_secret), or declines.
//!
//! Requests are keyed by *realm* (the container the secret unlocks: an
//! archive, a document, a key file) and *attempt*, so one answer serves every
//! entry of an encrypted archive, and a wrong password leads to a new request
//! with the next attempt number rather than to a loop. Answers are kept for
//! the lifetime of the session and are never rendered.

use std::fmt;
use std::sync::Arc;

use crate::span::Span;

/// How many times a dissector asks for a secret before giving up (verifying
/// each answer where the format allows).
pub const MAX_ATTEMPTS: u32 = 3;

/// What kind of secret is wanted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SecretKind {
    /// A password or passphrase (UTF-8 bytes).
    Password,
}

/// A request for a secret, reported by
/// [`Progress::NeedSecret`](crate::Progress::NeedSecret).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRequest {
    /// What the secret unlocks. One answer serves every request with the same
    /// realm and attempt.
    pub realm: Span,
    pub kind: SecretKind,
    /// A human-readable description, e.g. "Password for the encrypted ZIP
    /// entries".
    pub prompt: String,
    /// 0 for the first request; incremented after a wrong secret.
    pub attempt: u32,
}

impl SecretRequest {
    pub fn password(realm: Span, prompt: impl Into<String>, attempt: u32) -> Self {
        SecretRequest {
            realm,
            kind: SecretKind::Password,
            prompt: prompt.into(),
            attempt,
        }
    }

    pub(crate) fn key(&self) -> (Span, u32) {
        (self.realm, self.attempt)
    }
}

/// Secret bytes. `Debug` does not print them.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Arc<[u8]>);

impl Secret {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Secret(bytes.into().into())
    }

    pub fn password(password: &str) -> Self {
        Secret::new(password.as_bytes())
    }

    /// The secret bytes.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}
