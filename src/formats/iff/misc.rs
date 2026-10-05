//! Stub.

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::iff::{Chunk, Ctx, FourCc};
use crate::span::Span;

pub fn describe_id(_id: &FourCc) -> Option<&'static str> {
    None
}

pub async fn summary(_cx: &Cx, _chunk: &Chunk) -> Result<Option<String>> {
    Ok(None)
}

pub async fn chunk(_cx: &Cx, _chunk: &Chunk) -> Result<bool> {
    Ok(false)
}

pub async fn describe(_cx: &Cx, _ctx: &Ctx, _region: Span) -> Result<Option<String>> {
    Ok(None)
}
