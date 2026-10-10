//! NUT multimedia containers.

use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::formats::{Input, Probe};
use crate::node::Node;

// ---------------------------------------------------------------------------
// NUT container

declare_format!(pub NUT = "nut", "NUT multimedia container", ["nut"], "video/x-nut",
    Probe::Magic(&[(0, b"nut/multimedia container\0")]), nut);

async fn nut(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("File ID string").span(file.sub(0, 25)));
    let head = cx.read_avail(file.sub(0, 1 << 16)).await?;
    let count = |code: u64| head.windows(8).filter(|w| *w == code.to_be_bytes()).count();
    let main = count(0x4e4d_7a56_1f5f_04ad);
    let streams = count(0x4e53_1140_5bf2_f9db);
    cx.emit(Node::new("Packets").span(file.tail(25)));
    cx.annotate(format!(
        "NUT container, {main} main header(s), {streams} stream header(s) in the first 64 KiB"
    ));
    Ok(())
}
