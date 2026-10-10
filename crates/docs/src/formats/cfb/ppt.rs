//! PowerPoint 97–2003 ([MS-PPT]): the `PowerPoint Document` record tree,
//! the `Current User` stream, and the chain of user edits (each with a
//! persist directory mapping persist object IDs to stream offsets) that
//! locates the live version of every object.

use std::collections::BTreeMap;

use super::officeart;
use super::rec::{K, quoted};
use crate::bytes::{i32_le, to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Fields;
use crate::formats::Input;
use crate::formats::util::val::{hex, uint};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

pub const NAMES: EnumTable = &[
    (0x03e8, "DocumentContainer"),
    (0x03e9, "DocumentAtom"),
    (0x03ea, "EndDocumentAtom"),
    (0x03eb, "Slide (unused)"),
    (0x03ec, "SlideBase"),
    (0x03ee, "SlideContainer"),
    (0x03ef, "SlideAtom"),
    (0x03f0, "NotesContainer"),
    (0x03f1, "NotesAtom"),
    (0x03f2, "EnvironmentContainer"),
    (0x03f3, "SlidePersistAtom"),
    (0x03f6, "SSlideLayoutAtom"),
    (0x03f8, "MainMasterContainer"),
    (0x03f9, "SlideShowSlideInfoAtom"),
    (0x03fa, "SlideViewInfoContainer"),
    (0x03fb, "GuideAtom"),
    (0x03fd, "ViewInfoAtom"),
    (0x03fe, "SlideViewInfoAtom"),
    (0x03ff, "VbaInfoContainer"),
    (0x0400, "VbaInfoAtom"),
    (0x0401, "SlideShowDocInfoAtom"),
    (0x0402, "Summary"),
    (0x0406, "DocRoutingSlipAtom"),
    (0x0407, "OutlineViewInfoContainer"),
    (0x0408, "SorterViewInfoContainer"),
    (0x0409, "ExternalObjectList"),
    (0x040a, "ExternalObjectListAtom"),
    (0x040b, "DrawingGroupContainer"),
    (0x040c, "DrawingContainer"),
    (0x0414, "GridSpacing10Atom"),
    (0x0415, "RoundTripTheme12Atom"),
    (0x0416, "RoundTripColorMapping12Atom"),
    (0x041c, "NamedShowsContainer"),
    (0x041d, "NamedShowContainer"),
    (0x041e, "NamedShowSlidesAtom"),
    (0x041f, "NotesTextViewInfo9Container"),
    (0x0420, "NormalViewSetInfo9Container"),
    (0x0421, "NormalViewSetInfo9Atom"),
    (0x0422, "RoundTripOriginalMainMasterId12Atom"),
    (0x0423, "RoundTripCompositeMasterId12Atom"),
    (0x0424, "RoundTripContentMasterInfo12Atom"),
    (0x0425, "RoundTripShapeId12Atom"),
    (0x0426, "RoundTripHFPlaceholder12Atom"),
    (0x0428, "RoundTripContentMasterId12Atom"),
    (0x0429, "RoundTripOArtTextStyles12Atom"),
    (0x042a, "RoundTripHeaderFooterDefaults12Atom"),
    (0x042b, "RoundTripDocFlags12Atom"),
    (0x042c, "RoundTripShapeCheckSumForCL12Atom"),
    (0x042d, "RoundTripNotesMasterTextStyles12Atom"),
    (0x042e, "RoundTripCustomTableStyles12Atom"),
    (0x07d0, "List"),
    (0x07d5, "FontCollectionContainer"),
    (0x07e3, "BookmarkCollection"),
    (0x07e4, "SoundCollectionContainer"),
    (0x07e5, "SoundCollectionAtom"),
    (0x07e6, "SoundContainer"),
    (0x07e7, "SoundDataBlob"),
    (0x07e9, "BookmarkSeedAtom"),
    (0x07f0, "ColorSchemeAtom"),
    (0x07f8, "BlipCollection9Container"),
    (0x07f9, "BlipEntity9Atom"),
    (0x0bc1, "ExternalObjectRefAtom"),
    (0x0bc3, "PlaceholderAtom"),
    (0x0bdb, "ShapeAtom"),
    (0x0bdc, "ShapeFlags10Atom"),
    (0x0bdd, "RoundTripNewPlaceholderId12Atom"),
    (0x0f9e, "OutlineTextRefAtom"),
    (0x0f9f, "TextHeaderAtom"),
    (0x0fa0, "TextCharsAtom"),
    (0x0fa1, "StyleTextPropAtom"),
    (0x0fa2, "MasterTextPropAtom"),
    (0x0fa3, "TextMasterStyleAtom"),
    (0x0fa4, "TextCharFormatExceptionAtom"),
    (0x0fa5, "TextParagraphFormatExceptionAtom"),
    (0x0fa6, "TextRulerAtom"),
    (0x0fa7, "TextBookmarkAtom"),
    (0x0fa8, "TextBytesAtom"),
    (0x0fa9, "TextSpecialInfoDefaultAtom"),
    (0x0faa, "TextSpecialInfoAtom"),
    (0x0fab, "DefaultRulerAtom"),
    (0x0fac, "StyleTextProp9Atom"),
    (0x0fad, "TextMasterStyle9Atom"),
    (0x0fae, "OutlineTextProps9Container"),
    (0x0faf, "OutlineTextPropsHeader9Atom"),
    (0x0fb0, "TextDefaults9Atom"),
    (0x0fb1, "StyleTextProp10Atom"),
    (0x0fb2, "TextMasterStyle10Atom"),
    (0x0fb3, "OutlineTextProps10Container"),
    (0x0fb4, "TextDefaults10Atom"),
    (0x0fb5, "OutlineTextProps11Container"),
    (0x0fb6, "StyleTextProp11Atom"),
    (0x0fb7, "FontEntityAtom"),
    (0x0fb8, "FontEmbedDataBlob"),
    (0x0fba, "CString"),
    (0x0fc1, "MetaFile"),
    (0x0fc3, "ExternalOleObjectAtom"),
    (0x0fc8, "KinsokuContainer"),
    (0x0fc9, "Handout"),
    (0x0fcc, "ExternalOleEmbed"),
    (0x0fcd, "ExternalOleEmbedAtom"),
    (0x0fce, "ExternalOleLink"),
    (0x0fd0, "BookmarkEntityAtom"),
    (0x0fd1, "ExternalOleLinkAtom"),
    (0x0fd2, "KinsokuAtom"),
    (0x0fd3, "ExternalHyperlinkAtom"),
    (0x0fd7, "ExternalHyperlink"),
    (0x0fd8, "SlideNumberMCAtom"),
    (0x0fd9, "HeadersFooters"),
    (0x0fda, "HeadersFootersAtom"),
    (0x0fdf, "TextInteractiveInfoAtom"),
    (0x0fe4, "ExternalHyperlink9"),
    (0x0fe7, "RecolorInfoAtom"),
    (0x0fee, "ExternalOleControl"),
    (0x0ff0, "SlideListWithText"),
    (0x0ff1, "AnimationInfoAtom"),
    (0x0ff2, "InteractiveInfo"),
    (0x0ff3, "InteractiveInfoAtom"),
    (0x0ff5, "UserEditAtom"),
    (0x0ff6, "CurrentUserAtom"),
    (0x0ff7, "DateTimeMCAtom"),
    (0x0ff8, "GenericDateMCAtom"),
    (0x0ff9, "HeaderMCAtom"),
    (0x0ffa, "FooterMCAtom"),
    (0x0ffb, "ExternalOleControlAtom"),
    (0x1004, "ExternalMediaAtom"),
    (0x1005, "ExternalVideo"),
    (0x1006, "ExternalAviMovie"),
    (0x1007, "ExternalMciMovie"),
    (0x100d, "ExternalMidiAudio"),
    (0x100e, "ExternalCdAudio"),
    (0x100f, "ExternalWavAudioEmbedded"),
    (0x1010, "ExternalWavAudioLink"),
    (0x1011, "ExternalOleObjectStg"),
    (0x1012, "ExternalCdAudioAtom"),
    (0x1013, "ExternalWavAudioEmbeddedAtom"),
    (0x1014, "AnimationInfo"),
    (0x1015, "RtfDateTimeMetaCharAtom"),
    (0x1018, "ExternalHyperlinkFlagsAtom"),
    (0x1388, "ProgTags"),
    (0x1389, "ProgStringTag"),
    (0x138a, "ProgBinaryTag"),
    (0x138b, "BinaryTagDataBlob"),
    (0x1770, "PrintOptionsAtom"),
    (0x1772, "PersistDirectoryAtom"),
    (0x177a, "PresentationAdvisorFlags9Atom"),
    (0x177b, "HtmlDocInfo9Atom"),
    (0x177c, "HtmlPublishInfoAtom"),
    (0x177d, "HtmlPublishInfo9Container"),
    (0x177e, "BroadcastDocInfo9Container"),
    (0x177f, "BroadcastDocInfo9Atom"),
    (0x1784, "EnvelopeFlags9Atom"),
    (0x1785, "EnvelopeData9Atom"),
    (0x2ee0, "Comment10Container"),
    (0x2ee1, "Comment10Atom"),
    (0x2eea, "CommentIndex10Container"),
    (0x2eeb, "CommentIndex10Atom"),
    (0x2eec, "LinkedShape10Atom"),
    (0x2eed, "LinkedSlide10Atom"),
    (0x2eee, "SlideFlags10Atom"),
    (0x2eef, "SlideTime10Atom"),
    (0x2ef1, "DiffTree10Container"),
    (0x2f14, "TimeExtTimeNodeContainer"),
    (0x36b0, "PhotoAlbumInfo10Atom"),
    (0x3714, "SmartTagStore11Container"),
];

const TEXT_TYPES: EnumTable = &[
    (0, "title"),
    (1, "body"),
    (2, "notes"),
    (4, "other"),
    (5, "center body"),
    (6, "center title"),
    (7, "half body"),
    (8, "quarter body"),
];

const SLIDE_SIZES: EnumTable = &[
    (0, "on-screen"),
    (1, "letter paper"),
    (2, "A4 paper"),
    (3, "35mm"),
    (4, "overhead"),
    (5, "banner"),
    (6, "custom"),
];

const SLIDE_LAYOUTS: EnumTable = &[
    (0, "title slide"),
    (1, "title and body"),
    (2, "master title"),
    (7, "master notes"),
    (8, "notes title and body"),
    (9, "handout"),
    (10, "title only"),
    (11, "two columns"),
    (12, "two rows"),
    (13, "column and two rows"),
    (14, "two rows and column"),
    (15, "two columns and row"),
    (16, "four objects"),
    (17, "big object"),
    (18, "blank"),
    (19, "vertical title and body"),
];

const PLACEHOLDERS: EnumTable = &[
    (0, "none"),
    (1, "master title"),
    (2, "master body"),
    (3, "master center title"),
    (4, "master subtitle"),
    (5, "master notes slide image"),
    (6, "master notes body"),
    (7, "master date"),
    (8, "master slide number"),
    (9, "master footer"),
    (10, "master header"),
    (11, "notes slide image"),
    (12, "notes body"),
    (13, "title"),
    (14, "body"),
    (15, "center title"),
    (16, "subtitle"),
    (17, "vertical title"),
    (18, "vertical body"),
    (19, "object"),
    (20, "graph"),
    (21, "table"),
    (22, "clip art"),
    (23, "organization chart"),
    (24, "media clip"),
    (25, "vertical object"),
    (26, "picture"),
];

const SLIDE_FLAGS: FlagTable = &[
    flag(0x1, "fMasterObjects"),
    flag(0x2, "fMasterScheme"),
    flag(0x4, "fMasterBackground"),
];

const PERSIST_FLAGS: FlagTable = &[flag(0x2, "fShouldCollapse"), flag(0x4, "fNonOutlineData")];

const VIEWS: EnumTable = &[
    (0, "none"),
    (1, "slide"),
    (2, "slide master"),
    (3, "notes"),
    (4, "handout master"),
    (5, "notes master"),
    (6, "outline"),
    (7, "slide sorter"),
    (8, "visual basic"),
    (9, "title master"),
    (10, "slide show"),
    (11, "slide show full screen"),
    (12, "notes text"),
    (13, "print preview"),
    (14, "thumbnails"),
    (15, "master thumbnails"),
    (16, "pod guides"),
];

/// A one-line summary of a PowerPoint atom.
pub fn atom_summary(kind: u16, inst: u16, data: &[u8], len: u64) -> String {
    let s = match kind {
        0x0fa0 => Some(officeart_text16(data, len)),
        0x0fa8 => Some(quoted(&crate::text::latin1(data), 60)),
        0x0fba => Some(officeart_text16(data, len)),
        0x0f9f => u32_le(data, 0)
            .map(|t| format!("{} text", lookup(TEXT_TYPES, t.into()).unwrap_or("unknown"))),
        0x0fb7 => Some(format!(
            "font {inst}: {}",
            quoted(
                &crate::text::utf16z(
                    data.get(..64).unwrap_or(data),
                    crate::fields::Endian::Little
                )
                .0,
                40
            )
        )),
        0x03f3 => u32_le(data, 0)
            .zip(u32_le(data, 12))
            .map(|(p, id)| format!("slide ID {id}, persist {p}")),
        0x03e9 => i32_le(data, 0).zip(i32_le(data, 4)).map(|(x, y)| {
            format!(
                "slide size {:.2}×{:.2} in",
                f64::from(x) / 576.0,
                f64::from(y) / 576.0
            )
        }),
        0x03ef => u32_le(data, 0).map(|g| {
            format!(
                "layout {}",
                lookup(SLIDE_LAYOUTS, g.into()).unwrap_or("unknown")
            )
        }),
        0x0bc3 => data.get(4).map(|&p| {
            lookup(PLACEHOLDERS, p.into())
                .unwrap_or("placeholder")
                .to_owned()
        }),
        0x0ff5 => u32_le(data, 8).zip(u32_le(data, 12)).map(|(last, dir)| {
            format!("previous edit at {last:#x}, persist directory at {dir:#x}")
        }),
        0x1772 => Some(format!("{} bytes of persist entries", len)),
        0x0ff6 => u32_le(data, 8).map(|o| format!("current edit at {o:#x}")),
        _ => None,
    };
    s.unwrap_or_else(|| format!("atom, {len} bytes"))
}

fn officeart_text16(data: &[u8], len: u64) -> String {
    let s = quoted(&crate::text::utf16(data, crate::fields::Endian::Little), 60);
    if len > to_u64(data.len()) {
        format!("{s} ({} characters)", len / 2)
    } else {
        s
    }
}

/// The fields of a PowerPoint atom.
pub async fn atom_fields(
    cx: &Cx,
    f: &mut Fields<'_>,
    kind: u16,
    inst: u16,
    input: Input,
    body: Span,
) -> Result<()> {
    let _ = (input, inst);
    match kind {
        0x0fa0 | 0x0fba => {
            let n = body.len / 2;
            f.utf16("Text", n).emit()?;
        }
        0x0fa8 => {
            let n = body.len;
            let text = crate::text::latin1(&f.block().data);
            f.node(
                Node::new("Text")
                    .span(f.peek_span(n))
                    .value(Value::Text(text)),
            );
            f.skip(n);
        }
        0x0f9f => {
            f.u32("textType").enumeration(TEXT_TYPES).emit()?;
        }
        0x0ff6 => current_user(f)?,
        0x0ff5 => {
            f.u32("lastSlideIdRef").emit()?;
            f.u16("version").hex().emit()?;
            f.u8("minorVersion").emit()?;
            f.u8("majorVersion").emit()?;
            f.u32("offsetLastEdit")
                .hex()
                .desc("Previous UserEditAtom (0: none)")
                .emit()?;
            f.u32("offsetPersistDirectory").hex().emit()?;
            f.u32("docPersistIdRef").emit()?;
            f.u32("persistIdSeed").emit()?;
            f.u16("lastView").enumeration(VIEWS).emit()?;
            f.u16("unused").emit()?;
            if f.remaining() >= 4 {
                f.u32("encryptSessionPersistIdRef").emit()?;
            }
        }
        0x1772 => {
            let data = f.block().data.clone();
            let mut at = 0usize;
            while at.saturating_add(4) <= data.len() {
                let head = u32_le(&data, at).unwrap_or(0);
                let first = head & 0x000f_ffff;
                let n = head >> 20;
                let len = to_u64(
                    4usize.saturating_add(usize::try_from(n).unwrap_or(0).saturating_mul(4)),
                );
                f.node(
                    Node::new(format!(
                        "Entry: IDs {first}–{}",
                        first.saturating_add(n).saturating_sub(1)
                    ))
                    .span(f.peek_span(len))
                    .value(uint(head, 32))
                    .summary(format!("{n} offsets")),
                );
                f.skip(len);
                at = at.saturating_add(usize::try_from(len).unwrap_or(usize::MAX));
            }
        }
        0x03e9 => {
            f.i32("slideSize.x")
                .desc("Master units (1/576 inch)")
                .emit()?;
            f.i32("slideSize.y").emit()?;
            f.i32("notesSize.x").emit()?;
            f.i32("notesSize.y").emit()?;
            f.i32("serverZoom.numerator").emit()?;
            f.i32("serverZoom.denominator").emit()?;
            f.u32("notesMasterPersistIdRef").emit()?;
            f.u32("handoutMasterPersistIdRef").emit()?;
            f.u16("firstSlideNumber").emit()?;
            f.u16("slideSizeType").enumeration(SLIDE_SIZES).emit()?;
            super::rec::field(f, "fSaveWithFonts", K::Bool8)?;
            super::rec::field(f, "fOmitTitlePlace", K::Bool8)?;
            super::rec::field(f, "fRightToLeft", K::Bool8)?;
            super::rec::field(f, "fShowComments", K::Bool8)?;
        }
        0x03ef => {
            f.u32("geom").enumeration(SLIDE_LAYOUTS).emit()?;
            f.bytes("rgPlaceholderTypes", 8).emit()?;
            f.u32("masterIdRef").emit()?;
            f.u32("notesIdRef").emit()?;
            f.u16("slideFlags").flags(SLIDE_FLAGS).emit()?;
            f.u16("unused").emit()?;
        }
        0x03f1 => {
            f.u32("slideIdRef").emit()?;
            f.u16("slideFlags").flags(SLIDE_FLAGS).emit()?;
            f.u16("unused").emit()?;
        }
        0x03f3 => {
            f.u32("persistIdRef").emit()?;
            f.u32("Flags").flags(PERSIST_FLAGS).emit()?;
            f.i32("cTexts").emit()?;
            f.u32("slideId").emit()?;
            f.u32("reserved").emit()?;
        }
        0x0bc3 => {
            f.i32("position")
                .desc("Index of the placeholder on the master, or -1")
                .emit()?;
            f.u8("placementId").enumeration(PLACEHOLDERS).emit()?;
            f.u8("size")
                .enumeration(&[(0, "full"), (1, "half"), (2, "quarter")])
                .emit()?;
            f.u16("unused").emit()?;
        }
        0x07f0 => {
            for name in [
                "background",
                "text and lines",
                "shadows",
                "title text",
                "fills",
                "accent",
                "accent and hyperlink",
                "accent and followed hyperlink",
            ] {
                f.u32(name)
                    .with(|&v, n| n.summary(officeart::color(v & 0x00ff_ffff)))
                    .emit()?;
            }
        }
        0x0fb7 => {
            f.utf16("lfFaceName", 32).emit()?;
            f.u8("lfCharSet")
                .enumeration(super::word::CHARSETS)
                .emit()?;
            f.u8("Flags").hex().emit()?;
            f.u8("lfQuality").emit()?;
            f.u8("lfPitchAndFamily").hex().emit()?;
        }
        0x0fd2 => {
            f.u32("level")
                .enumeration(&[(0, "none"), (1, "level 1"), (2, "custom")])
                .emit()?;
        }
        0x0400 => {
            f.u32("persistIdRef")
                .desc("The VbaProjectStg holding the VBA project")
                .emit()?;
            f.u32("fHasMacros").emit()?;
            f.u32("version").emit()?;
        }
        0x03fb => {
            f.u32("type")
                .enumeration(&[(0, "horizontal"), (1, "vertical")])
                .emit()?;
            f.i32("pos").desc("Master units").emit()?;
        }
        0x03fe => {
            super::rec::field(f, "fSnapToGrid", K::Bool8)?;
            super::rec::field(f, "fSnapToShape", K::Bool8)?;
            f.u8("reserved").emit()?;
        }
        0x03fd => {
            for name in [
                "curScale.x.numer",
                "curScale.x.denom",
                "curScale.y.numer",
                "curScale.y.denom",
                "prevScale.x.numer",
                "prevScale.x.denom",
                "prevScale.y.numer",
                "prevScale.y.denom",
                "viewSize.x",
                "viewSize.y",
                "origin.x",
                "origin.y",
            ] {
                f.i32(name).emit()?;
            }
            super::rec::field(f, "fZoomToFit", K::Bool8)?;
            super::rec::field(f, "fDraftMode", K::Bool8)?;
            f.u16("reserved").emit()?;
        }
        0x0fda => {
            f.int::<i16>("formatId").emit()?;
            f.u16("Flags").hex().emit()?;
        }
        _ => {}
    }
    let _ = cx;
    Ok(())
}

const HEADER_TOKENS: EnumTable = &[(0xe391_c05f, "not encrypted"), (0xf3d1_c4df, "encrypted")];

fn current_user(f: &mut Fields<'_>) -> Result<()> {
    f.u32("size").emit()?;
    f.u32("headerToken")
        .hex()
        .enumeration(HEADER_TOKENS)
        .emit()?;
    f.u32("offsetToCurrentEdit")
        .hex()
        .desc("Offset of the current UserEditAtom in the PowerPoint Document stream")
        .emit()?;
    let len = f.u16("lenUserName").emit()?;
    f.u16("docFileVersion").hex().emit()?;
    f.u8("majorVersion").emit()?;
    f.u8("minorVersion").emit()?;
    f.u16("unused").emit()?;
    let n = u64::from(len);
    let pos = crate::bytes::to_usize(f.pos());
    let name = crate::text::latin1(
        f.block()
            .data
            .get(pos..pos.saturating_add(crate::bytes::to_usize(n)))
            .unwrap_or_default(),
    );
    f.node(
        Node::new("ansiUserName")
            .span(f.peek_span(n))
            .value(Value::Text(name)),
    );
    f.skip(n);
    if f.remaining() >= 4 {
        f.u32("relVersion").hex().emit()?;
    }
    if f.remaining() >= n.saturating_mul(2) && n > 0 {
        f.utf16("unicodeUserName", n).emit()?;
    }
    Ok(())
}

/// The `PowerPoint Document` stream: its records, then the edit chain
/// located through the `Current User` stream (when present).
pub async fn document(cx: &Cx, input: Input, span: Span, current_user: Option<Span>) -> Result<()> {
    // Top-level records.
    let mut pos = 0u64;
    let mut slides = 0u32;
    let mut last_edit = None;
    while pos.saturating_add(8) <= span.len {
        let head = cx.read(span.sub(pos, 8)).await?;
        let kind = u16_le(&head, 2).unwrap_or(0);
        let len = u64::from(u32_le(&head, 4).unwrap_or(0));
        if kind == 0x03ee {
            slides = slides.saturating_add(1);
        }
        if kind == 0x0ff5 {
            last_edit = Some(pos);
        }
        pos = pos.saturating_add(8).saturating_add(len);
    }
    let edit = match current_user {
        Some(cu) => {
            let d = cx.read_avail(cu.sub(0, 20)).await?;
            u32_le(&d, 16).map(u64::from).or(last_edit)
        }
        None => last_edit,
    };
    if let Some(at) = edit {
        cx.emit(
            Node::new("Edit chain")
                .summary("user edits, newest first, with their persist directories")
                .lazy(edit_chain, (span, at)),
        );
    }
    cx.emit(
        Node::new("Records")
            .span(span)
            .summary(format!("{slides} slides"))
            .lazy(officeart::records_at, (input, span)),
    );
    cx.annotate(format!("PowerPoint 97–2003 presentation, {slides} slides"));
    Ok(())
}

/// The chain of UserEditAtoms from the current one back to the first,
/// and the persist object table they build (newer entries win).
async fn edit_chain(cx: Cx, (stream, first): (Span, u64)) -> Result<()> {
    let mut at = first;
    let mut seen = std::collections::BTreeSet::new();
    let mut table: BTreeMap<u32, (u32, Span)> = BTreeMap::new();
    let mut n = 0u32;
    while seen.insert(at) && n < 1024 {
        n = n.saturating_add(1);
        let head = cx.read(stream.sub_exact(at, 8)?).await?;
        if u16_le(&head, 2) != Some(0x0ff5) {
            cx.diag(Diagnostic::malformed(format!("no UserEditAtom at {at:#x}")));
            break;
        }
        let len = u64::from(u32_le(&head, 4).unwrap_or(0));
        let rec = stream.sub(at, len.saturating_add(8));
        let body = cx.read_avail(rec.tail(8)).await?;
        let prev = u32_le(&body, 8).unwrap_or(0);
        let dir = u64::from(u32_le(&body, 12).unwrap_or(0));
        cx.push(
            Node::new(format!("Edit at {at:#x}"))
                .span(rec)
                .value(hex(at, 32))
                .summary(atom_summary(0x0ff5, 0, &body, len)),
        )
        .await;
        // The persist directory of this edit.
        let dh = cx.read(stream.sub_exact(dir, 8)?).await?;
        if u16_le(&dh, 2) == Some(0x1772) {
            let dlen = u64::from(u32_le(&dh, 4).unwrap_or(0));
            let data = cx
                .read_avail(stream.sub(dir.saturating_add(8), dlen))
                .await?;
            let mut p = 0usize;
            while p.saturating_add(4) <= data.len() {
                cx.checkpoint().await;
                let h = u32_le(&data, p).unwrap_or(0);
                let id0 = h & 0x000f_ffff;
                let count = h >> 20;
                for k in 0..count {
                    let o = p
                        .saturating_add(4)
                        .saturating_add(usize::try_from(k).unwrap_or(0).saturating_mul(4));
                    let Some(off) = u32_le(&data, o) else { break };
                    let id = id0.saturating_add(k);
                    let entry = stream.sub(dir.saturating_add(8).saturating_add(to_u64(o)), 4);
                    table.entry(id).or_insert((off, entry));
                }
                p = p
                    .saturating_add(4)
                    .saturating_add(usize::try_from(count).unwrap_or(0).saturating_mul(4));
            }
        }
        if prev == 0 {
            break;
        }
        at = u64::from(prev);
    }
    for (id, (off, entry)) in table {
        let head = cx.read_avail(stream.sub(off.into(), 8)).await?;
        let kind = u16_le(&head, 2).unwrap_or(0);
        let len = u64::from(u32_le(&head, 4).unwrap_or(0));
        cx.push(
            Node::new(format!("Persist object {id}"))
                .span(entry)
                .value(hex(off, 32))
                .summary(officeart::name(kind))
                .target(stream.sub(off.into(), len.saturating_add(8))),
        )
        .await;
    }
    Ok(())
}
