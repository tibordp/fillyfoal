//! cpio archives: SVR4 "newc" (`070701`) and its CRC variant (`070702`),
//! POSIX "odc" (`070707`), and the old binary format in either byte order.
//!
//! Each member is a header, the NUL-terminated name and the data, with
//! format-specific alignment; `TRAILER!!!` ends the archive. Members are
//! listed in pages and dissected on expansion.

use crate::bytes::{align_up, u16_be, u16_le};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::arcutil::{Num, ascii_num, check_len, present, unix_kind};
use crate::formats::util::fmt;
use crate::formats::util::fmt::count;
use crate::formats::util::val::text;
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;

pub static FORMAT: Format = Format {
    name: "cpio",
    title: "cpio archive",
    extensions: &["cpio"],
    mime: "application/x-cpio",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    Newc,
    Crc,
    Odc,
    BinaryLe,
    BinaryBe,
}

impl Variant {
    fn of(data: &[u8]) -> Option<Variant> {
        match data.get(..6) {
            Some(b"070701") => Some(Variant::Newc),
            Some(b"070702") => Some(Variant::Crc),
            Some(b"070707") => Some(Variant::Odc),
            _ => match data.get(..2) {
                Some([0xc7, 0x71]) => Some(Variant::BinaryLe),
                Some([0x71, 0xc7]) => Some(Variant::BinaryBe),
                _ => None,
            },
        }
    }

    fn name(self) -> &'static str {
        match self {
            Variant::Newc => "SVR4 newc",
            Variant::Crc => "SVR4 with CRC",
            Variant::Odc => "POSIX odc",
            Variant::BinaryLe => "old binary, little-endian",
            Variant::BinaryBe => "old binary, big-endian",
        }
    }

    fn header_len(self) -> u64 {
        match self {
            Variant::Newc | Variant::Crc => 110,
            Variant::Odc => 76,
            Variant::BinaryLe | Variant::BinaryBe => 26,
        }
    }

    fn align(self) -> u64 {
        match self {
            Variant::Newc | Variant::Crc => 4,
            Variant::Odc => 1,
            Variant::BinaryLe | Variant::BinaryBe => 2,
        }
    }

    fn endian(self) -> Endian {
        if self == Variant::BinaryBe {
            Endian::Big
        } else {
            Endian::Little
        }
    }
}

fn probe(h: &Head<'_>) -> bool {
    match Variant::of(h.data) {
        Some(Variant::BinaryLe | Variant::BinaryBe) => {
            // Two magic bytes are weak: check that the name fits and is
            // NUL-terminated where the header says.
            let le = h.data.first() == Some(&0xc7);
            let namesize = if le {
                u16_le(h.data, 20)
            } else {
                u16_be(h.data, 20)
            };
            namesize
                .is_some_and(|n| n > 0 && h.data.get(25usize.saturating_add(n.into())) == Some(&0))
        }
        Some(_) => true,
        None => false,
    }
}

/// The numbers the walk needs from a header.
#[derive(Clone, Copy, Debug)]
struct Header {
    mode: u64,
    namesize: u64,
    filesize: u64,
    check: u64,
}

/// Decodes (and, when emitting, shows) a header of any variant.
fn header_layout(f: &mut Fields<'_>, variant: &Variant) -> Result<Header> {
    let variant = *variant;
    let missing = || Diagnostic::malformed("not a number");
    match variant {
        Variant::Newc | Variant::Crc => {
            f.ascii("Magic", 6).emit()?;
            let mut hex = |name, show| ascii_num(f, name, 8, 16, show);
            hex("Inode", Num::Dec).emit()?;
            let mode = hex("Mode", Num::Mode).emit()?.ok_or_else(missing)?;
            hex("UID", Num::Dec).emit()?;
            hex("GID", Num::Dec).emit()?;
            hex("Links", Num::Dec).emit()?;
            hex("Modification time", Num::Time).emit()?;
            let filesize = hex("File size", Num::Dec).emit()?.ok_or_else(missing)?;
            hex("Device major", Num::Dec).emit()?;
            hex("Device minor", Num::Dec).emit()?;
            hex("Special device major", Num::Dec).emit()?;
            hex("Special device minor", Num::Dec).emit()?;
            let namesize = hex("Name size", Num::Dec).emit()?.ok_or_else(missing)?;
            let check = hex("Checksum", Num::Hex).emit()?.unwrap_or(0);
            Ok(Header {
                mode,
                namesize,
                filesize,
                check,
            })
        }
        Variant::Odc => {
            f.ascii("Magic", 6).emit()?;
            let mut oct = |name, len, show| ascii_num(f, name, len, 8, show);
            oct("Device", 6, Num::Dec).emit()?;
            oct("Inode", 6, Num::Dec).emit()?;
            let mode = oct("Mode", 6, Num::Mode).emit()?.ok_or_else(missing)?;
            oct("UID", 6, Num::Dec).emit()?;
            oct("GID", 6, Num::Dec).emit()?;
            oct("Links", 6, Num::Dec).emit()?;
            oct("Special device", 6, Num::Dec).emit()?;
            oct("Modification time", 11, Num::Time).emit()?;
            let namesize = oct("Name size", 6, Num::Dec).emit()?.ok_or_else(missing)?;
            let filesize = oct("File size", 11, Num::Dec).emit()?.ok_or_else(missing)?;
            Ok(Header {
                mode,
                namesize,
                filesize,
                check: 0,
            })
        }
        Variant::BinaryLe | Variant::BinaryBe => {
            f.u16("Magic").hex().emit()?;
            f.u16("Device").emit()?;
            f.u16("Inode").emit()?;
            let mode = f
                .u16("Mode")
                .with(|&m, n| present(n, m.into(), Num::Mode))
                .emit()?;
            f.u16("UID").emit()?;
            f.u16("GID").emit()?;
            f.u16("Links").emit()?;
            f.u16("Special device").emit()?;
            let mtime = pair(f, "Modification time")?;
            f.node(Node::new("Modification time").span(span_back(f, 4)).value(
                crate::value::Value::Timestamp {
                    unix_seconds: i64::try_from(mtime).unwrap_or(0),
                },
            ));
            let namesize = f.u16("Name size").emit()?;
            let filesize = pair(f, "File size")?;
            f.node(
                Node::new("File size")
                    .span(span_back(f, 4))
                    .value(crate::formats::util::val::uint(filesize, 64)),
            );
            Ok(Header {
                mode: mode.into(),
                namesize: namesize.into(),
                filesize,
                check: 0,
            })
        }
    }
}

/// A 32-bit value stored as two 16-bit words, most significant first.
fn pair(f: &mut Fields<'_>, name: &'static str) -> Result<u64> {
    let hi = f.u16(name).get()?;
    let lo = f.u16(name).get()?;
    Ok(u64::from(hi) << 16 | u64::from(lo))
}

/// The span of the `len` bytes just read.
fn span_back(f: &Fields<'_>, len: u64) -> Span {
    let at = f.peek_span(0);
    Span::new(at.source, at.offset.saturating_sub(len), len)
}

struct Member {
    span: Span,
    name: String,
    header: Header,
}

async fn next_member(cx: &Cx, cur: &mut Cursor<'_>, variant: Variant) -> Result<Member> {
    let start = cur.pos();
    let hlen = variant.header_len();
    let header = crate::fields::parse(
        cx,
        cur.span(hlen),
        variant.endian(),
        &variant,
        header_layout,
    )
    .await?;
    let magic = cur.peek(6).await?;
    if Variant::of(&magic) != Some(variant) {
        return Err(Diagnostic::malformed("bad member magic").at(cur.span(6)));
    }
    cur.skip(hlen);
    let name_bytes = cur.peek(header.namesize.min(4096)).await?;
    let name = crate::text::until_nul(&name_bytes);
    let after_name = align_up(hlen.saturating_add(header.namesize), variant.align());
    cur.seek(start.saturating_add(after_name));
    cur.skip(align_up(header.filesize, variant.align()));
    Ok(Member {
        span: cur.since(start),
        name,
        header,
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 6)).await?;
    let variant = Variant::of(&head).ok_or_else(|| Diagnostic::malformed("not cpio").at(file))?;
    cx.annotate(format!("cpio archive ({})", variant.name()));
    let mut cur = Cursor::new(&cx, file, variant.endian());
    let mut members = 0u64;
    let mut total = 0u64;
    let mut ended = false;
    while cur.remaining() >= variant.header_len() {
        let m = next_member(&cx, &mut cur, variant).await?;
        let trailer = m.name == "TRAILER!!!";
        let summary = if trailer {
            "end of archive".to_owned()
        } else {
            let kind = unix_kind(m.header.mode);
            if kind == "file" {
                fmt::size(m.header.filesize)
            } else {
                kind.to_owned()
            }
        };
        if !trailer {
            members = members.saturating_add(1);
            total = total.saturating_add(m.header.filesize);
        }
        let node = Node::new(m.name)
            .span(m.span)
            .summary(summary)
            .lazy(member, (input, m.span, variant));
        let wanted = align_up(
            variant.header_len().saturating_add(m.header.namesize),
            variant.align(),
        )
        .saturating_add(m.header.filesize);
        cx.progress_in(file, file.offset.saturating_add(cur.pos()));
        cx.push(check_len(node, m.span, wanted)).await;
        if trailer {
            ended = true;
            break;
        }
    }
    if !ended {
        cx.diag(Diagnostic::warning("no TRAILER!!! entry"));
    }
    // What follows the archive, in the stream's real length (a stream that
    // records no size has only an upper bound until it has been decoded).
    let file = cx.known(file).await;
    if cur.pos() < file.len {
        let rest = file.tail(cur.pos());
        let data = cx.read_avail(rest.sub(0, 4096)).await?;
        let node = Node::new(if data.iter().all(|&b| b == 0) {
            "Padding"
        } else {
            "Trailing data"
        })
        .span(rest)
        .summary(fmt::size(rest.len));
        if Variant::of(&data).is_some() {
            // Some tools (initramfs) concatenate archives.
            cx.emit(embedded("Next archive", input.nested(rest)));
        } else {
            cx.emit(node);
        }
    }
    cx.annotate(format!(
        "cpio archive ({}), {}, {}",
        variant.name(),
        count(members, "entry", "entries"),
        fmt::size(total)
    ));
    Ok(())
}

async fn member(cx: Cx, (input, span, variant): (Input, Span, Variant)) -> Result<()> {
    let hlen = variant.header_len();
    let hspan = span.sub(0, hlen);
    let header =
        crate::fields::parse(&cx, hspan, variant.endian(), &variant, header_layout).await?;
    cx.emit(struct_node(
        "Header",
        hspan,
        variant.endian(),
        variant,
        header_layout,
    ));
    let name_span = span.sub(hlen, header.namesize);
    let name = cx.read_avail(name_span).await?;
    cx.emit(
        Node::new("Name")
            .span(name_span)
            .value(text(crate::text::until_nul(&name))),
    );
    let data_at = align_up(hlen.saturating_add(header.namesize), variant.align());
    let data = span.sub(data_at, header.filesize);
    match header.mode & 0o170_000 {
        0o120_000 => {
            let target = cx.read_avail(data.sub(0, 4096)).await?;
            cx.emit(
                Node::new("Link target")
                    .span(data)
                    .value(text(String::from_utf8_lossy(&target))),
            );
        }
        _ if header.filesize > 0 => {
            let mut node = embedded("Content", input.nested(data)).summary(fmt::size(data.len));
            if variant == Variant::Crc && data.len <= cx.limits().max_read {
                let bytes = cx.read(data).await?;
                let sum = bytes
                    .iter()
                    .fold(0u32, |a, &b| a.wrapping_add(u32::from(b)));
                if u64::from(sum) != header.check {
                    node = node.diag(Diagnostic::warning(format!(
                        "checksum mismatch: computed {sum:#010x}"
                    )));
                }
            }
            cx.emit(check_len(node, data, header.filesize));
        }
        _ => {}
    }
    Ok(())
}
