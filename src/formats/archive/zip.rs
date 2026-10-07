//! ZIP archives and the many formats built on them (OOXML, ODF, EPUB, JAR,
//! APK, ...).
//!
//! The archive is located from its end: the End of Central Directory record
//! (and its ZIP64 variant) gives the central directory, which lists entries.
//! Entries are enumerated in pages; an entry's local header and content are
//! read only when it is expanded, and content is decompressed only when that
//! node is expanded.

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Codec, Format, Head, Input, Probe, content};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;
const LOCAL: &[u8] = b"PK\x03\x04";
const CENTRAL: u32 = 0x0201_4b50;
const EOCD: &[u8] = b"PK\x05\x06";
const EOCD64: &[u8] = b"PK\x06\x06";
const EOCD64_LOCATOR: &[u8] = b"PK\x06\x07";

macro_rules! zip_variant {
    ($id:ident, $name:literal, $title:literal, [$($ext:literal),*], $mime:literal, $probe:expr) => {
        pub static $id: Format = Format {
            name: $name,
            title: $title,
            extensions: &[$($ext),*],
            mime: $mime,
            probe: Probe::Custom($probe),
            dissect: crate::expander!(dissect: Input),
        };
    };
}

zip_variant!(
    EPUB,
    "epub",
    "EPUB e-book",
    ["epub"],
    "application/epub+zip",
    |h| mimetype(h, b"application/epub+zip")
);
zip_variant!(
    ODT,
    "odt",
    "OpenDocument text",
    ["odt", "ott"],
    "application/vnd.oasis.opendocument.text",
    |h| mimetype(h, b"application/vnd.oasis.opendocument.text")
);
zip_variant!(
    ODS,
    "ods",
    "OpenDocument spreadsheet",
    ["ods", "ots"],
    "application/vnd.oasis.opendocument.spreadsheet",
    |h| mimetype(h, b"application/vnd.oasis.opendocument.spreadsheet")
);
zip_variant!(
    ODP,
    "odp",
    "OpenDocument presentation",
    ["odp", "otp"],
    "application/vnd.oasis.opendocument.presentation",
    |h| mimetype(h, b"application/vnd.oasis.opendocument.presentation")
);
zip_variant!(
    ODG,
    "odg",
    "OpenDocument drawing",
    ["odg", "otg"],
    "application/vnd.oasis.opendocument.graphics",
    |h| mimetype(h, b"application/vnd.oasis.opendocument.graphics")
);
zip_variant!(
    DOCX,
    "docx",
    "Office Open XML document",
    ["docx", "docm", "dotx"],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    |h| ooxml(h, b"word/")
);
zip_variant!(
    XLSX,
    "xlsx",
    "Office Open XML workbook",
    ["xlsx", "xlsm", "xltx"],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    |h| ooxml(h, b"xl/")
);
zip_variant!(
    PPTX,
    "pptx",
    "Office Open XML presentation",
    ["pptx", "pptm", "potx"],
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    |h| ooxml(h, b"ppt/")
);
zip_variant!(
    VSDX,
    "vsdx",
    "Office Open XML drawing (Visio)",
    ["vsdx"],
    "application/vnd.ms-visio.drawing",
    |h| ooxml(h, b"visio/")
);
zip_variant!(
    XPS,
    "xps",
    "XML Paper Specification",
    ["xps", "oxps"],
    "application/vnd.ms-xpsdocument",
    |h| ooxml(h, b"Documents/") || has_entry(h, b"FixedDocSeq.fdseq")
);
zip_variant!(
    APK,
    "apk",
    "Android package",
    ["apk", "aab"],
    "application/vnd.android.package-archive",
    |h| has_entry(h, b"AndroidManifest.xml") || has_entry(h, b"classes.dex")
);
zip_variant!(
    JAR,
    "jar",
    "Java archive",
    ["jar", "war", "ear"],
    "application/java-archive",
    |h| has_entry(h, b"META-INF/MANIFEST.MF") || first_entry(h, b"META-INF/")
);
zip_variant!(
    XPI,
    "xpi",
    "Mozilla extension",
    ["xpi"],
    "application/x-xpinstall",
    |h| has_entry(h, b"install.rdf")
        || (has_entry(h, b"manifest.json") && has_entry(h, b"META-INF/mozilla"))
);
zip_variant!(
    NUPKG,
    "nupkg",
    "NuGet package",
    ["nupkg", "snupkg"],
    "application/zip",
    |h| has_entry_suffix(h, b".nuspec")
);
zip_variant!(
    VSIX,
    "vsix",
    "Visual Studio extension",
    ["vsix"],
    "application/zip",
    |h| has_entry(h, b"extension.vsixmanifest")
);
zip_variant!(
    WHL,
    "whl",
    "Python wheel",
    ["whl"],
    "application/zip",
    |h| has_entry_suffix(h, b".dist-info/WHEEL") || has_entry_suffix(h, b".dist-info/METADATA")
);
zip_variant!(
    IPA,
    "ipa",
    "iOS application archive",
    ["ipa"],
    "application/octet-stream",
    |h| first_entry(h, b"Payload/")
);
zip_variant!(
    KMZ,
    "kmz",
    "Keyhole Markup (zipped)",
    ["kmz"],
    "application/vnd.google-earth.kmz",
    |h| has_entry(h, b"doc.kml")
);
zip_variant!(
    THREE_MF,
    "3mf",
    "3D Manufacturing Format",
    ["3mf"],
    "model/3mf",
    |h| has_entry(h, b"3D/3dmodel.model")
);
zip_variant!(
    SKETCH,
    "sketch",
    "Sketch document",
    ["sketch"],
    "application/zip",
    |h| has_entry(h, b"document.json") && has_entry(h, b"meta.json")
);
zip_variant!(
    USDZ,
    "usdz",
    "Universal Scene Description (zipped)",
    ["usdz"],
    "model/vnd.usdz+zip",
    |h| has_entry_suffix(h, b".usdc") || has_entry_suffix(h, b".usda")
);

zip_variant!(
    KRITA,
    "krita",
    "Krita document",
    ["kra"],
    "application/x-krita",
    |h| mimetype(h, b"application/x-krita")
);
zip_variant!(
    ORA,
    "ora",
    "OpenRaster image",
    ["ora"],
    "image/openraster",
    |h| mimetype(h, b"image/openraster")
);
zip_variant!(
    IDML,
    "idml",
    "InDesign markup package",
    ["idml"],
    "application/vnd.adobe.indesign-idml-package",
    |h| mimetype(h, b"application/vnd.adobe.indesign-idml-package")
);
zip_variant!(
    ODF_FORMULA,
    "odf",
    "OpenDocument formula",
    ["odf"],
    "application/vnd.oasis.opendocument.formula",
    |h| mimetype(h, b"application/vnd.oasis.opendocument.formula")
);
zip_variant!(
    ODB,
    "odb",
    "OpenDocument database",
    ["odb"],
    "application/vnd.oasis.opendocument.base",
    |h| mimetype(h, b"application/vnd.oasis.opendocument.base")
);
zip_variant!(
    IWORK,
    "iwork",
    "Apple iWork document (Pages/Numbers/Keynote)",
    ["pages", "numbers", "key"],
    "application/x-iwork",
    |h| has_entry(h, b"Index/Document.iwa") || has_entry(h, b"Index.zip")
);
zip_variant!(
    APPX,
    "appx",
    "Windows app package (APPX/MSIX)",
    ["appx", "msix", "appxbundle", "msixbundle"],
    "application/vnd.ms-appx",
    |h| has_entry(h, b"AppxManifest.xml")
        || has_entry(h, b"AppxMetadata/AppxBundleManifest.xml")
        || has_entry(h, b"AppxSignature.p7x")
);
zip_variant!(
    XAP,
    "xap",
    "Silverlight / Windows Phone package",
    ["xap"],
    "application/x-silverlight-app",
    |h| has_entry(h, b"AppManifest.xaml")
);
zip_variant!(
    SCRATCH,
    "sb3",
    "Scratch 3 project",
    ["sb3", "sb2"],
    "application/x-scratch-project",
    |h| has_entry(h, b"project.json")
);
zip_variant!(
    MCPACK,
    "mcpack",
    "Minecraft Bedrock pack",
    ["mcpack", "mcaddon", "mcworld"],
    "application/zip",
    |h| has_entry(h, b"manifest.json")
        && (has_entry_suffix(h, b"pack_icon.png") || has_entry(h, b"level.dat"))
);
zip_variant!(
    AAR,
    "aar",
    "Android library archive",
    ["aar"],
    "application/zip",
    |h| has_entry(h, b"AndroidManifest.xml") && has_entry(h, b"classes.jar")
);
zip_variant!(
    XLSB,
    "xlsb",
    "Excel binary workbook",
    ["xlsb"],
    "application/vnd.ms-excel.sheet.binary.macroEnabled.12",
    |h| ooxml(h, b"xl/") && has_entry_suffix(h, b".bin")
);
zip_variant!(
    SNUPKG,
    "snupkg",
    "NuGet symbols package",
    ["snupkg"],
    "application/zip",
    |h| has_entry_suffix(h, b".nuspec") && has_entry_suffix(h, b".pdb")
);
zip_variant!(
    FBZ,
    "fbz",
    "FictionBook (zipped)",
    ["fbz"],
    "application/x-zip-compressed-fb2",
    |h| has_entry_suffix(h, b".fb2")
);
zip_variant!(
    CBZ,
    "cbz",
    "Comic book archive (ZIP)",
    ["cbz"],
    "application/vnd.comicbook+zip",
    |h| has_entry(h, b"ComicInfo.xml")
);
zip_variant!(
    GEOGEBRA,
    "ggb",
    "GeoGebra file",
    ["ggb"],
    "application/vnd.geogebra.file",
    |h| has_entry(h, b"geogebra.xml")
);
zip_variant!(
    ADOBE_XD,
    "adobe-xd",
    "Adobe XD document",
    ["xd"],
    "application/vnd.adobe.sparkler.project+dcxucf",
    |h| mimetype(h, b"application/vnd.adobe.sparkler.project+dcxucf")
);
zip_variant!(
    PROCREATE,
    "procreate",
    "Procreate artwork",
    ["procreate", "brush", "brushset", "swatches"],
    "application/x-procreate",
    |h| has_entry(h, b"Document.archive")
);
zip_variant!(
    XFL,
    "flash-fla",
    "Adobe Animate / Flash document (XFL)",
    ["fla", "xfl"],
    "application/vnd.adobe.fla",
    |h| has_entry(h, b"DOMDocument.xml")
);
zip_variant!(
    PYTORCH,
    "pytorch",
    "PyTorch model/checkpoint",
    ["pt", "pth", "ckpt", "bin"],
    "application/x-pytorch",
    |h| has_entry_suffix(h, b"/data.pkl") || has_entry(h, b"data.pkl")
);
zip_variant!(
    NPZ,
    "npz",
    "NumPy array archive (NPZ)",
    ["npz"],
    "application/x-npz",
    |h| is_zip(h)
        && entry_names(h).next().is_some()
        && entry_names(h).all(|n| n.ends_with(b".npy"))
);
zip_variant!(
    KERAS,
    "keras",
    "Keras v3 model",
    ["keras"],
    "application/x-keras",
    |h| has_entry(h, b"config.json")
        && (has_entry(h, b"model.weights.h5") || has_entry(h, b"metadata.json"))
);
zip_variant!(
    SIGROK,
    "sigrok",
    "sigrok logic analyzer session",
    ["sr"],
    "application/x-sigrok",
    |h| has_entry(h, b"version") && has_entry(h, b"metadata")
);
zip_variant!(
    DWFX,
    "dwfx",
    "Autodesk Design Web Format (XPS)",
    ["dwfx"],
    "model/vnd.dwfx+xps",
    |h| has_entry(h, b"manifest.xml") && has_entry_suffix(h, b".dwfseq")
);
// OpenOffice.org 1.x / StarOffice 6–7 (the predecessors of OpenDocument).
zip_variant!(
    SXW,
    "sxw",
    "OpenOffice.org 1.x text document",
    ["sxw", "stw", "sxg"],
    "application/vnd.sun.xml.writer",
    |h| mimetype(h, b"application/vnd.sun.xml.writer")
);
zip_variant!(
    SXC,
    "sxc",
    "OpenOffice.org 1.x spreadsheet",
    ["sxc", "stc"],
    "application/vnd.sun.xml.calc",
    |h| mimetype(h, b"application/vnd.sun.xml.calc")
);
zip_variant!(
    SXI,
    "sxi",
    "OpenOffice.org 1.x presentation",
    ["sxi", "sti"],
    "application/vnd.sun.xml.impress",
    |h| mimetype(h, b"application/vnd.sun.xml.impress")
);
zip_variant!(
    SXD,
    "sxd",
    "OpenOffice.org 1.x drawing",
    ["sxd", "std"],
    "application/vnd.sun.xml.draw",
    |h| mimetype(h, b"application/vnd.sun.xml.draw")
);
zip_variant!(
    SXM,
    "sxm",
    "OpenOffice.org 1.x formula",
    ["sxm"],
    "application/vnd.sun.xml.math",
    |h| mimetype(h, b"application/vnd.sun.xml.math")
);
zip_variant!(
    CDR_ZIP,
    "cdr-zip",
    "CorelDRAW X4+ drawing (ZIP)",
    ["cdr", "cdt"],
    "application/vnd.corel-draw",
    |h| has_entry(h, b"content/riffData.cdr") || has_entry(h, b"content/root.dat")
);
zip_variant!(
    IWORK09,
    "iwork09",
    "Apple iWork '09 document (Pages/Numbers/Keynote)",
    ["pages", "numbers", "key"],
    "application/x-iwork09",
    |h| has_entry(h, b"index.apxl")
        || has_entry(h, b"index.apxl.gz")
        || ((has_entry(h, b"index.xml") || has_entry(h, b"index.xml.gz"))
            && has_entry(h, b"buildVersionHistory.plist"))
);

// ML models and mobile platform packages (registered before the other
// variants: APEX and OTA packages also carry Android/JAR markers).
zip_variant!(
    TORCHSCRIPT,
    "torchscript",
    "TorchScript module (ZIP)",
    ["pt", "pth", "ptl"],
    "application/x-torchscript",
    |h| has_entry_suffix(h, b"/constants.pkl")
        || entry_names(h).any(|n| probe_contains(n, b"/code/"))
);
zip_variant!(
    APEX,
    "apex",
    "Android APEX package",
    ["apex", "capex"],
    "application/x-apex",
    |h| has_entry(h, b"apex_manifest.pb") || has_entry(h, b"apex_manifest.json")
);
zip_variant!(
    ANDROID_OTA,
    "android-ota",
    "Android OTA update package",
    ["zip"],
    "application/zip",
    |h| has_entry(h, b"META-INF/com/android/metadata") || has_entry(h, b"payload_properties.txt")
);
zip_variant!(
    ANDROID_DM,
    "android-dm",
    "Android dex metadata",
    ["dm"],
    "application/zip",
    |h| has_entry(h, b"primary.prof") || has_entry(h, b"primary.vdex")
);
zip_variant!(
    BUGREPORT,
    "android-bugreport",
    "Android bug report",
    ["zip"],
    "application/zip",
    |h| has_entry(h, b"main_entry.txt") && has_entry(h, b"version.txt")
);
zip_variant!(
    IPSW,
    "ipsw",
    "Apple firmware (IPSW)",
    ["ipsw"],
    "application/x-ipsw",
    |h| has_entry(h, b"BuildManifest.plist") || has_entry(h, b"Restore.plist")
);

fn probe_contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

pub static FORMAT: Format = Format {
    name: "zip",
    title: "ZIP archive",
    extensions: &["zip", "zipx"],
    mime: "application/zip",
    probe: Probe::Magic(&[
        (0, b"PK\x03\x04"),
        (0, b"PK\x05\x06"),
        (0, b"PK\x07\x08PK\x03\x04"),
    ]),
    dissect: crate::expander!(dissect: Input),
};

/// A ZIP archive after other data (self-extractor stubs, installers, a
/// script in front): recognised by its end record, which must sit at the
/// very end of the file (its comment, if any, filling the rest exactly).
/// Registered after every magic-based probe, so formats that carry a
/// trailing archive themselves (PE self-extractors) win.
pub static PREFIXED: Format = Format {
    name: "zip-prefixed",
    title: "ZIP archive after other data",
    extensions: &["zip", "sfx"],
    mime: "application/zip",
    probe: Probe::Custom(ends_with_eocd),
    dissect: crate::expander!(dissect: Input),
};

fn ends_with_eocd(h: &Head<'_>) -> bool {
    let tail = h.tail;
    (0..tail.len().saturating_sub(21)).rev().any(|i| {
        tail.get(i..i.saturating_add(4)) == Some(EOCD)
            && crate::bytes::u16_le(tail, i.saturating_add(20))
                .is_some_and(|c| i.saturating_add(22).saturating_add(c.into()) == tail.len())
            // The central directory lies before the record.
            && u32_le(tail, i.saturating_add(16)).is_some_and(|o| u64::from(o) < h.len)
    })
}

/// File names of the local headers found in the probe window.
fn entry_names<'a>(h: &'a Head<'_>) -> impl Iterator<Item = &'a [u8]> {
    let data = h.data;
    let mut at = 0usize;
    std::iter::from_fn(move || {
        if at.saturating_add(30) <= data.len() {
            if data.get(at..at.saturating_add(4)) != Some(LOCAL) {
                return None;
            }
            let name_len = usize::from(u16_le(data, at.saturating_add(26))?);
            let extra_len = usize::from(u16_le(data, at.saturating_add(28))?);
            let compressed = u32_le(data, at.saturating_add(18))?;
            let flags = u16_le(data, at.saturating_add(6))?;
            let name_start = at.saturating_add(30);
            let name = data.get(name_start..name_start.saturating_add(name_len))?;
            // Entries with a data descriptor do not record their size here;
            // stop walking after them.
            at = if flags & 0x08 != 0 {
                data.len()
            } else {
                name_start
                    .saturating_add(name_len)
                    .saturating_add(extra_len)
                    .saturating_add(usize::try_from(compressed).ok()?)
            };
            return Some(name);
        }
        None
    })
}

fn is_zip(h: &Head<'_>) -> bool {
    h.starts_with(LOCAL)
}

fn has_entry(h: &Head<'_>, name: &[u8]) -> bool {
    is_zip(h) && entry_names(h).any(|n| n == name)
}

fn has_entry_suffix(h: &Head<'_>, suffix: &[u8]) -> bool {
    is_zip(h) && entry_names(h).any(|n| n.ends_with(suffix))
}

fn first_entry(h: &Head<'_>, prefix: &[u8]) -> bool {
    is_zip(h) && entry_names(h).next().is_some_and(|n| n.starts_with(prefix))
}

/// OpenDocument and EPUB store an uncompressed `mimetype` entry first.
fn mimetype(h: &Head<'_>, mime: &[u8]) -> bool {
    is_zip(h)
        && h.at(30, b"mimetype")
        && h.data.get(38..).is_some_and(|rest| {
            let extra = usize::from(u16_le(h.data, 28).unwrap_or(0));
            rest.get(extra..).is_some_and(|r| r.starts_with(mime))
        })
}

fn ooxml(h: &Head<'_>, part: &[u8]) -> bool {
    is_zip(h)
        && entry_names(h).any(|n| n == b"[Content_Types].xml")
        && entry_names(h).any(|n| n.starts_with(part))
}

const METHOD: EnumTable = &[
    (0, "stored"),
    (1, "shrunk"),
    (2, "reduced (1)"),
    (3, "reduced (2)"),
    (4, "reduced (3)"),
    (5, "reduced (4)"),
    (6, "imploded"),
    (8, "deflate"),
    (9, "deflate64"),
    (10, "PKWARE DCL implode"),
    (12, "bzip2"),
    (14, "LZMA"),
    (16, "IBM z/OS CMPSC"),
    (18, "IBM TERSE"),
    (19, "IBM LZ77 z"),
    (20, "zstd (deprecated id)"),
    (93, "zstd"),
    (94, "MP3"),
    (95, "xz"),
    (96, "JPEG"),
    (97, "WavPack"),
    (98, "PPMd"),
    (99, "AES encrypted"),
];

const GP_FLAGS: FlagTable = &[
    flag(0x0001, "ENCRYPTED"),
    flag(0x0002, "OPTION1"),
    flag(0x0004, "OPTION2"),
    flag(0x0008, "DATA_DESCRIPTOR"),
    flag(0x0010, "ENHANCED_DEFLATE"),
    flag(0x0020, "PATCHED"),
    flag(0x0040, "STRONG_ENCRYPTION"),
    flag(0x0800, "UTF8"),
    flag(0x2000, "CENTRAL_DIRECTORY_ENCRYPTED"),
];

const HOST: EnumTable = &[
    (0, "MS-DOS"),
    (1, "Amiga"),
    (2, "OpenVMS"),
    (3, "Unix"),
    (4, "VM/CMS"),
    (5, "Atari ST"),
    (6, "OS/2 HPFS"),
    (7, "Macintosh"),
    (8, "Z-System"),
    (9, "CP/M"),
    (10, "NTFS"),
    (11, "MVS"),
    (12, "VSE"),
    (13, "Acorn RISC"),
    (14, "VFAT"),
    (15, "alternate MVS"),
    (16, "BeOS"),
    (17, "Tandem"),
    (18, "OS/400"),
    (19, "OS X (Darwin)"),
];

record! {
    pub struct EndOfCentralDirectory {
        signature: bytes[4] "Signature",
        disk: u16 "Number of this disk",
        cd_disk: u16 "Disk where the central directory starts",
        disk_entries: u16 "Entries on this disk",
        entries: u16 "Total entries",
        cd_size: u32 "Central directory size" .hex(),
        cd_offset: u32 "Central directory offset" .hex(),
        comment_len: u16 "Comment length",
    }
}

record! {
    pub struct Zip64Locator {
        signature: bytes[4] "Signature",
        disk: u32 "Disk with the ZIP64 end record",
        offset: u64 "ZIP64 end record offset" .hex(),
        disks: u32 "Total disks",
    }
}

record! {
    pub struct Zip64End {
        signature: bytes[4] "Signature",
        size: u64 "Record size" .hex(),
        made_by: u16 "Version made by",
        needed: u16 "Version needed",
        disk: u32 "Number of this disk",
        cd_disk: u32 "Disk where the central directory starts",
        disk_entries: u64 "Entries on this disk",
        entries: u64 "Total entries",
        cd_size: u64 "Central directory size" .hex(),
        cd_offset: u64 "Central directory offset" .hex(),
    }
}

record! {
    pub struct CentralHeader {
        signature: bytes[4] "Signature",
        made_by: u8 "Version made by",
        host: u8 "Host system" .enumeration(HOST),
        needed: u16 "Version needed to extract",
        flags: u16 "General purpose flags" .flags(GP_FLAGS),
        method: u16 "Compression method" .enumeration(METHOD),
        time: u16 "Modification time (DOS)" .hex() .with(|&t, n| n.summary(dos_time(t))),
        date: u16 "Modification date (DOS)" .hex() .with(|&d, n| n.summary(dos_date(d))),
        crc: u32 "CRC-32" .hex(),
        compressed: u32 "Compressed size",
        uncompressed: u32 "Uncompressed size",
        name_len: u16 "File name length",
        extra_len: u16 "Extra field length",
        comment_len: u16 "Comment length",
        disk: u16 "Disk number start",
        internal: u16 "Internal attributes" .hex(),
        external: u32 "External attributes" .hex(),
        offset: u32 "Local header offset" .hex(),
    }
}

record! {
    pub struct LocalHeader {
        signature: bytes[4] "Signature",
        needed: u16 "Version needed to extract",
        flags: u16 "General purpose flags" .flags(GP_FLAGS),
        method: u16 "Compression method" .enumeration(METHOD),
        time: u16 "Modification time (DOS)" .hex() .with(|&t, n| n.summary(dos_time(t))),
        date: u16 "Modification date (DOS)" .hex() .with(|&d, n| n.summary(dos_date(d))),
        crc: u32 "CRC-32" .hex(),
        compressed: u32 "Compressed size",
        uncompressed: u32 "Uncompressed size",
        name_len: u16 "File name length",
        extra_len: u16 "Extra field length",
    }
}

fn dos_time(t: u16) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        t >> 11,
        (t >> 5) & 0x3f,
        (t & 0x1f).saturating_mul(2)
    )
}

fn dos_date(d: u16) -> String {
    format!(
        "{:04}-{:02}-{:02}",
        1980u16.saturating_add(d >> 9),
        (d >> 5) & 0x0f,
        d & 0x1f
    )
}

/// Whether `span` holds `magic`.
async fn starts_with(cx: &Cx, span: Span, magic: &[u8]) -> bool {
    matches!(cx.read_avail(span).await, Ok(b) if b == magic)
}

#[derive(Clone, Copy, Debug)]
struct Directory {
    offset: u64,
    size: u64,
    entries: u64,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    // The EOCD is within the last 64 KiB + 22 bytes (the comment is at most
    // 0xffff bytes).
    let window_len = file.len.min(0xffff + 22);
    let window_start = file.len.saturating_sub(window_len);
    let window = cx.read(file.sub(window_start, window_len)).await?;
    let found = (0..window.len().saturating_sub(21))
        .rev()
        .find(|&i| window.get(i..i.saturating_add(4)) == Some(EOCD));
    let Some(at) = found else {
        cx.annotate("ZIP local entries (no central directory)");
        return local_entries(&cx, input).await;
    };
    let eocd_offset = window_start.saturating_add(to_u64(at));
    let eocd_span = file.sub(eocd_offset, EndOfCentralDirectory::SIZE);
    let eocd = crate::fields::parse(&cx, eocd_span, LE, &(), EndOfCentralDirectory::layout).await?;
    let mut dir = Directory {
        offset: eocd.cd_offset.into(),
        size: eocd.cd_size.into(),
        entries: eocd.entries.into(),
    };

    // ZIP64: a locator just before the EOCD points at the ZIP64 end record.
    // The central directory ends where the last end record starts: the
    // EOCD, or the ZIP64 end record when there is one.
    let mut nodes = Vec::new();
    let mut directory_end = eocd_offset;
    if let Some(loc_offset) = eocd_offset.checked_sub(Zip64Locator::SIZE) {
        let loc_span = file.sub(loc_offset, Zip64Locator::SIZE);
        let loc_bytes = cx.read_avail(loc_span).await?;
        if loc_bytes.starts_with(EOCD64_LOCATOR) {
            let recorded = u64_le(&loc_bytes, 8).unwrap_or(0);
            // The record is where the locator says, unless data was
            // prepended to the archive (offsets unadjusted): then it is
            // right before the locator.
            let end_offset = if starts_with(&cx, file.sub(recorded, 4), EOCD64).await {
                recorded
            } else {
                match loc_offset.checked_sub(Zip64End::SIZE) {
                    Some(o) if starts_with(&cx, file.sub(o, 4), EOCD64).await => o,
                    _ => recorded,
                }
            };
            directory_end = end_offset;
            let end_span = file.sub(end_offset, Zip64End::SIZE);
            match crate::fields::parse(&cx, end_span, LE, &(), Zip64End::layout).await {
                Ok(end) => {
                    dir = Directory {
                        offset: end.cd_offset,
                        size: end.cd_size,
                        entries: end.entries,
                    };
                    nodes.push(Zip64End::node(
                        "ZIP64 End of Central Directory",
                        end_span,
                        LE,
                    ));
                }
                Err(e) => cx.diag(e),
            }
            nodes.push(Zip64Locator::node(
                "ZIP64 End of Central Directory Locator",
                loc_span,
                LE,
            ));
        }
    }

    // Self-extracting archives and other prefixed data shift all offsets.
    let expected_end = dir.offset.saturating_add(dir.size);
    let prefix = directory_end.saturating_sub(expected_end);
    if prefix > 0 {
        cx.emit(
            crate::formats::embedded("Prefix data", input.nested(file.sub(0, prefix)))
                .summary(format!("{prefix:#x} bytes before the archive")),
        );
    }

    let owned = probe_head(&cx, file).await?;
    let label = match crate::formats::identify(&Head::from(&owned)) {
        Some(f) if f.name != "zip" => format!("{} ({} entries)", f.title, dir.entries),
        _ => format!("ZIP archive, {} entries", dir.entries),
    };
    cx.annotate(label);

    let cd_span = file.sub(dir.offset.saturating_add(prefix), dir.size);
    cx.emit(
        Node::new("Central Directory")
            .span(cd_span)
            .summary(format!("{} entries", dir.entries))
            .lazy(central_directory, (input, cd_span, dir.entries, prefix)),
    );
    for node in nodes.into_iter().rev() {
        cx.emit(node);
    }
    let mut eocd_node = EndOfCentralDirectory::node("End of Central Directory", eocd_span, LE);
    if eocd.comment_len > 0 {
        let comment = file.sub(
            eocd_offset.saturating_add(EndOfCentralDirectory::SIZE),
            eocd.comment_len.into(),
        );
        let text = cx.read_avail(comment).await?;
        cx.emit(
            Node::new("Archive comment")
                .span(comment)
                .value(Value::Text(String::from_utf8_lossy(&text).into_owned())),
        );
    }
    eocd_node = eocd_node.summary(format!("at {eocd_offset:#x}"));
    cx.emit(eocd_node);
    Ok(())
}

async fn probe_head(cx: &Cx, file: Span) -> Result<OwnedHead> {
    let (data, tail) = crate::formats::head(cx, file).await?;
    Ok(OwnedHead {
        data,
        tail,
        len: file.len,
    })
}

struct OwnedHead {
    data: Vec<u8>,
    tail: Vec<u8>,
    len: u64,
}

impl<'a> From<&'a OwnedHead> for Head<'a> {
    fn from(h: &'a OwnedHead) -> Head<'a> {
        Head {
            data: &h.data,
            tail: &h.tail,
            len: h.len,
        }
    }
}

async fn central_directory(
    cx: Cx,
    (input, span, entries, prefix): (Input, Span, u64, u64),
) -> Result<()> {
    cx.set_count(Count::Exact(entries));
    let mut cur = Cursor::new(&cx, span, LE);
    // Resume marks: (position, entries so far).
    let (pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    cur.seek(pos);
    // The directory is walked by its size: some writers store the entry
    // count modulo 65536 even in the ZIP64 record, so headers that continue
    // past the stated count are listed too (as `unzip` does).
    while !cur.at_end() {
        let start = cur.pos();
        if index >= entries {
            if cur.remaining() < CentralHeader::SIZE || cur.peek(4).await? != CENTRAL.to_le_bytes() {
                break;
            }
            if index == entries {
                cx.set_count(Count::AtLeast(entries.saturating_add(1)));
            }
        }
        let at = (start, index);
        cx.mark(move || at);
        let (header, _) = cur.record::<CentralHeader>().await?;
        if u32_le(&header.signature, 0) != Some(CENTRAL) {
            return Err(
                Diagnostic::malformed("expected a central directory header").at(cur.span(4))
            );
        }
        let name = decode_name(&cur.bytes(header.name_len.into()).await?, header.flags);
        cur.skip(u64::from(header.extra_len).saturating_add(header.comment_len.into()));
        let entry_span = cur.since(start);

        let extra_span = entry_span.sub(
            CentralHeader::SIZE.saturating_add(header.name_len.into()),
            header.extra_len.into(),
        );
        let sizes = zip64_sizes(&cx, extra_span, &header).await;
        let method = crate::value::lookup(METHOD, header.method.into())
            .map_or_else(|| format!("method {}", header.method), str::to_owned);
        let summary = if name.ends_with('/') {
            "directory".to_owned()
        } else {
            format!(
                "{method}, {} → {} bytes",
                sizes.compressed, sizes.uncompressed
            )
        };
        cx.push(
            Node::new(name)
                .span(entry_span)
                .summary(summary)
                .lazy(entry, (input, entry_span, prefix)),
        )
        .await;
        index = index.saturating_add(1);
    }
    if index > entries {
        cx.diag(Diagnostic::warning(format!(
            "the end record says {entries} entries, the central directory holds {index}{}",
            if index % 65536 == entries % 65536 { " (the count was stored modulo 65536)" } else { "" }
        )));
        cx.annotate(format!("{index} entries"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Sizes {
    compressed: u64,
    uncompressed: u64,
    offset: u64,
}

/// Sizes and offset, with 0xffffffff placeholders resolved from the ZIP64
/// extra field.
async fn zip64_sizes(cx: &Cx, extra: Span, h: &CentralHeader) -> Sizes {
    let mut sizes = Sizes {
        compressed: h.compressed.into(),
        uncompressed: h.uncompressed.into(),
        offset: h.offset.into(),
    };
    if h.compressed != u32::MAX && h.uncompressed != u32::MAX && h.offset != u32::MAX {
        return sizes;
    }
    let Ok(data) = cx.read_avail(extra).await else {
        return sizes;
    };
    let mut at = 0usize;
    while let (Some(id), Some(len)) = (u16_le(&data, at), u16_le(&data, at.saturating_add(2))) {
        let body = at.saturating_add(4);
        if id == 0x0001 {
            let mut field = body;
            let mut next = || {
                let v = u64_le(&data, field);
                field = field.saturating_add(8);
                v
            };
            if h.uncompressed == u32::MAX
                && let Some(v) = next()
            {
                sizes.uncompressed = v;
            }
            if h.compressed == u32::MAX
                && let Some(v) = next()
            {
                sizes.compressed = v;
            }
            if h.offset == u32::MAX
                && let Some(v) = next()
            {
                sizes.offset = v;
            }
            break;
        }
        at = body.saturating_add(len.into());
    }
    sizes
}

fn decode_name(bytes: &[u8], flags: u16) -> String {
    if flags & 0x0800 != 0 {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_owned(),
        Err(_) => bytes.iter().map(|&b| cp437(b)).collect(),
    }
}

/// IBM code page 437, the historical default for ZIP file names.
fn cp437(b: u8) -> char {
    const HIGH: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";
    if b < 0x80 {
        char::from(b)
    } else {
        HIGH.chars().nth(usize::from(b & 0x7f)).unwrap_or('?')
    }
}

async fn entry(cx: Cx, (input, span, prefix): (Input, Span, u64)) -> Result<()> {
    let file = input.span;
    let header = crate::fields::parse(
        &cx,
        span.sub(0, CentralHeader::SIZE),
        LE,
        &(),
        CentralHeader::layout,
    )
    .await?;
    cx.emit(CentralHeader::node(
        "Central Directory Header",
        span.sub(0, CentralHeader::SIZE),
        LE,
    ));
    let name_span = span.sub(CentralHeader::SIZE, header.name_len.into());
    let name = decode_name(&cx.read(name_span).await?, header.flags);
    cx.emit(
        Node::new("File name")
            .span(name_span)
            .value(Value::Text(name)),
    );
    let extra = span.sub(
        CentralHeader::SIZE.saturating_add(header.name_len.into()),
        header.extra_len.into(),
    );
    if header.extra_len > 0 {
        cx.emit(
            Node::new("Extra fields")
                .span(extra)
                .lazy(extra_fields, extra),
        );
    }
    if header.comment_len > 0 {
        let comment = span.sub(
            CentralHeader::SIZE
                .saturating_add(header.name_len.into())
                .saturating_add(header.extra_len.into()),
            header.comment_len.into(),
        );
        let text = cx.read(comment).await?;
        cx.emit(
            Node::new("Comment")
                .span(comment)
                .value(Value::Text(String::from_utf8_lossy(&text).into_owned())),
        );
    }

    let sizes = zip64_sizes(&cx, extra, &header).await;
    let local_offset = sizes.offset.saturating_add(prefix);
    let local_span = file.sub(local_offset, LocalHeader::SIZE);
    let local = crate::fields::parse(&cx, local_span, LE, &(), LocalHeader::layout).await?;
    let mut local_node = LocalHeader::node("Local File Header", local_span, LE);
    if !local.signature.starts_with(LOCAL) {
        local_node = local_node.diag(Diagnostic::malformed("bad local header signature"));
        cx.emit(local_node);
        return Ok(());
    }
    if local.name_len != header.name_len || local.method != header.method {
        local_node = local_node.diag(Diagnostic::warning(
            "local header disagrees with the central directory",
        ));
    }
    cx.emit(local_node);

    let data_offset = local_offset
        .saturating_add(LocalHeader::SIZE)
        .saturating_add(local.name_len.into())
        .saturating_add(local.extra_len.into());
    let data = file.sub(data_offset, sizes.compressed);
    if data.len < sizes.compressed {
        cx.diag(Diagnostic::truncated(
            Span::new(data.source, data.offset, sizes.compressed),
            data.len,
        ));
    }
    if header.flags & 0x0001 != 0 {
        let is_dir = name_is_dir(&cx, name_span).await;
        let node = encrypted_content(&cx, input, file, data, extra, &header, sizes.uncompressed).await?;
        if !is_dir {
            cx.emit(node);
        }
        return Ok(());
    }
    let codec = match method_codec(&cx, header.method, header.flags, data, sizes.uncompressed).await {
        Ok(codec) => codec,
        Err(e) => {
            cx.emit(Node::new("Compressed data").span(data).diag(e));
            return Ok(());
        }
    };
    match codec {
        Some((codec, stream)) if !(name_is_dir(&cx, name_span).await) => {
            if stream.offset != data.offset {
                cx.emit(lzma_header(data.sub(0, stream.offset.saturating_sub(data.offset)), &codec));
            }
            cx.emit(
                content("Content", input, stream, codec, Some(sizes.uncompressed))
                    .summary(format!("{:#x} bytes", sizes.uncompressed)),
            );
        }
        Some(_) => {}
        None => {
            let method = crate::value::lookup(METHOD, header.method.into()).unwrap_or("unknown");
            cx.emit(
                Node::new("Compressed data")
                    .span(data)
                    .diag(Diagnostic::unsupported(format!(
                        "compression method {method}"
                    ))),
            );
        }
    }
    Ok(())
}

/// The codec for compression `method` and the span of its stream (which
/// for LZMA follows a properties header); `None` for a method we do not
/// decode.
async fn method_codec(cx: &Cx, method: u16, flags: u16, data: Span, size: u64) -> Result<Option<(Codec, Span)>> {
    let codec = match method {
        0 => Codec::Stored,
        8 => Codec::Deflate,
        12 => Codec::Bzip2,
        20 | 93 => Codec::Zstd,
        95 => Codec::Xz,
        6 => implode(flags, size),
        10 => Codec::DclImplode,
        14 => {
            let head = cx.read(data.sub_exact(0, 4)?).await?;
            let (stream, codec) = lzma_stream(cx, &head, data, flags, size).await?;
            return Ok(Some((codec, stream)));
        }
        _ => return Ok(None),
    };
    Ok(Some((codec, data)))
}

/// ZIP method 6 (PKWARE implode): flag bit 1 selects the 8 KiB window and
/// bit 2 the literal tree; the stream does not record its own end.
fn implode(flags: u16, size: u64) -> Codec {
    Codec::Implode(crate::codec::implode::Implode {
        large_window: flags & 0x0002 != 0,
        literal_tree: flags & 0x0004 != 0,
        size: Some(size),
    })
}

/// ZIP method 14: a 2-byte LZMA SDK version, a 2-byte properties size, the
/// properties (lc/lp/pb byte, 4-byte dictionary size), then raw LZMA; flag
/// bit 1 says an end marker terminates the stream.
async fn lzma_stream(cx: &Cx, head: &[u8], data: Span, flags: u16, size: u64) -> Result<(Span, Codec)> {
    let props_len = u16_le(head, 2).ok_or_else(|| Diagnostic::malformed("truncated LZMA header").at(data))?;
    if props_len < 5 {
        return Err(Diagnostic::malformed("LZMA properties shorter than 5 bytes").at(data));
    }
    let raw = cx.read(data.sub_exact(4, props_len.into())?).await?;
    let props = crate::codec::lzma::Props::from_byte(raw.first().copied().unwrap_or(0xff))
        .map_err(|e| e.at(data.sub(4, 1)))?;
    let dict = u32_le(&raw, 1);
    let skip = 4u64.saturating_add(props_len.into());
    let stream = data.sub(skip, data.len.saturating_sub(skip));
    let size = (flags & 0x0002 == 0).then(|| usize::try_from(size).unwrap_or(usize::MAX));
    Ok((stream, Codec::LzmaRaw { props, size, dict }))
}

/// A node for the LZMA properties header of a method-14 entry.
fn lzma_header(span: Span, codec: &Codec) -> Node {
    let mut node = Node::new("LZMA header").span(span);
    if let Codec::LzmaRaw { props, size, .. } = codec {
        node = node.summary(format!(
            "lc={} lp={} pb={}{}",
            props.lc,
            props.lp,
            props.pb,
            if size.is_none() { ", end marker" } else { "" }
        ));
    }
    node
}

/// The content of an encrypted entry: asks for the archive's password,
/// verifies it, and decrypts then decompresses on expansion.
async fn encrypted_content(
    cx: &Cx,
    input: Input,
    archive: Span,
    data: Span,
    extra: Span,
    header: &CentralHeader,
    uncompressed: u64,
) -> Result<Node> {
    use crate::codec::crypto::{Key, Sha1, ZipCryptoKeys, pbkdf2};
    const PROMPT: &str = "Password for the encrypted ZIP entries";
    let locked = |why: &str| Node::new("Encrypted data").span(data).diag(Diagnostic::unsupported(why.to_owned()));
    if header.flags & 0x0040 != 0 {
        return Ok(locked("PKWARE strong encryption"));
    }
    let (decrypt, payload, method) = if header.method == 99 {
        // WinZip AES: salt, 2-byte password verifier, data, 10-byte MAC.
        let fields = cx.read_avail(extra).await?;
        let Some((strength, method)) = extra_field(&fields, 0x9901)
            .and_then(|f| Some((*f.get(4)?, u16_le(f, 5)?)))
        else {
            return Ok(locked("AES-encrypted entry without its 0x9901 extra field"));
        };
        if !(1..=3).contains(&strength) {
            return Ok(locked("unknown AES key strength"));
        }
        let key_len = 8usize.saturating_add(8usize.saturating_mul(strength.into()));
        let salt_len = key_len / 2;
        let head = cx.read(data.sub_exact(0, to_u64(salt_len.saturating_add(2)))?).await?;
        let (salt, verifier) = head.split_at(salt_len);
        let derive = |password: &[u8]| pbkdf2::<Sha1>(password, salt, 1000, key_len.saturating_mul(2).saturating_add(2));
        let Some(secret) = cx.unlock(archive, PROMPT, |s| derive(s.expose()).ends_with(verifier)).await else {
            return Ok(locked("encrypted entry (no password, or a wrong one)"));
        };
        let key = derive(secret.expose());
        let body = to_u64(salt_len.saturating_add(2));
        let payload = data.sub(body, data.len.saturating_sub(body).saturating_sub(10));
        (Codec::AesCtrLe(Key::new(key.get(..key_len).unwrap_or_default())), payload, method)
    } else {
        // ZipCrypto: a 12-byte header whose last byte checks the password.
        let head = cx.read(data.sub_exact(0, 12)?).await?;
        let check = if header.flags & 0x0008 != 0 {
            header.time.to_be_bytes()[0]
        } else {
            header.crc.to_be_bytes()[0]
        };
        let verify = |password: &[u8]| {
            let mut keys = ZipCryptoKeys::new(password);
            head.iter().map(|&c| keys.decrypt(c)).last() == Some(check)
        };
        let Some(secret) = cx.unlock(archive, PROMPT, |s| verify(s.expose())).await else {
            return Ok(locked("encrypted entry (no password, or a wrong one)"));
        };
        (Codec::ZipCrypto(Key::new(secret.expose())), data, header.method)
    };
    let zipcrypto = matches!(decrypt, Codec::ZipCrypto(_));
    let codec = match (method, zipcrypto) {
        (0, _) => decrypt,
        (8, true) => Codec::chain("zipcrypto+deflate", "zipcrypto+deflate (lazy)", vec![decrypt, Codec::Deflate]),
        (8, false) => Codec::chain("aes-ctr+deflate", "aes-ctr+deflate (lazy)", vec![decrypt, Codec::Deflate]),
        (12, true) => Codec::chain("zipcrypto+bzip2", "zipcrypto+bzip2 (lazy)", vec![decrypt, Codec::Bzip2]),
        (12, false) => Codec::chain("aes-ctr+bzip2", "aes-ctr+bzip2 (lazy)", vec![decrypt, Codec::Bzip2]),
        (20 | 93, true) => Codec::chain("zipcrypto+zstd", "zipcrypto+zstd (lazy)", vec![decrypt, Codec::Zstd]),
        (20 | 93, false) => Codec::chain("aes-ctr+zstd", "aes-ctr+zstd (lazy)", vec![decrypt, Codec::Zstd]),
        (95, true) => Codec::chain("zipcrypto+xz", "zipcrypto+xz (lazy)", vec![decrypt, Codec::Xz]),
        (95, false) => Codec::chain("aes-ctr+xz", "aes-ctr+xz (lazy)", vec![decrypt, Codec::Xz]),
        (6, true) => Codec::chain("zipcrypto+implode", "zipcrypto+implode (lazy)", vec![decrypt, implode(header.flags, uncompressed)]),
        (6, false) => Codec::chain("aes-ctr+implode", "aes-ctr+implode (lazy)", vec![decrypt, implode(header.flags, uncompressed)]),
        (10, true) => Codec::chain("zipcrypto+dcl-implode", "zipcrypto+dcl-implode (lazy)", vec![decrypt, Codec::DclImplode]),
        (10, false) => Codec::chain("aes-ctr+dcl-implode", "aes-ctr+dcl-implode (lazy)", vec![decrypt, Codec::DclImplode]),
        // The LZMA properties are encrypted too: decrypt first, then read them.
        (14, _) => {
            return Ok(Node::new("Content")
                .span(payload)
                .summary(format!("encrypted, {uncompressed:#x} bytes"))
                .lazy(encrypted_lzma, (input, payload, decrypt, header.flags, uncompressed)));
        }
        _ => {
            let name = crate::value::lookup(METHOD, method.into()).unwrap_or("unknown");
            return Ok(Node::new("Decrypted data")
                .span(payload)
                .diag(Diagnostic::unsupported(format!("compression method {name}"))));
        }
    };
    Ok(content("Content", input, payload, codec, Some(uncompressed))
        .summary(format!("encrypted, {uncompressed:#x} bytes")))
}

/// An encrypted LZMA entry: decrypts it, then decompresses the LZMA stream
/// after its properties header.
async fn encrypted_lzma(
    cx: Cx,
    (input, payload, decrypt, flags, uncompressed): (Input, Span, Codec, u16, u64),
) -> Result<()> {
    let plain = crate::codec::decode_span(&cx, payload, &decrypt, None).await?;
    if let Some(e) = plain.error {
        cx.diag(e);
    }
    let head = cx.read(plain.span.sub_exact(0, 4)?).await?;
    let (stream, codec) = lzma_stream(&cx, &head, plain.span, flags, uncompressed).await?;
    cx.emit(lzma_header(plain.span.sub(0, stream.offset.saturating_sub(plain.span.offset)), &codec));
    cx.emit(content("Decompressed", input, stream, codec, Some(uncompressed)));
    Ok(())
}

/// The body of extra field `id` in `fields`.
fn extra_field(fields: &[u8], id: u16) -> Option<&[u8]> {
    let mut at = 0usize;
    while let (Some(fid), Some(len)) = (u16_le(fields, at), u16_le(fields, at.saturating_add(2))) {
        let body = at.saturating_add(4);
        let end = body.saturating_add(len.into());
        if fid == id {
            return fields.get(body..end);
        }
        at = end;
    }
    None
}

async fn name_is_dir(cx: &Cx, name: Span) -> bool {
    cx.read(name).await.is_ok_and(|n| n.ends_with(b"/"))
}

const EXTRA_IDS: EnumTable = &[
    (0x0001, "ZIP64 extended information"),
    (0x000a, "NTFS"),
    (0x000d, "Unix"),
    (0x5455, "Extended timestamp"),
    (0x5855, "Info-ZIP Unix (old)"),
    (0x7855, "Info-ZIP Unix UID/GID"),
    (0x7875, "Info-ZIP Unix UID/GID (new)"),
    (0x6375, "Info-ZIP Unicode comment"),
    (0x7075, "Info-ZIP Unicode path"),
    (0x9901, "AE-x encryption"),
    (0xcafe, "JAR marker"),
    (0xd935, "Android alignment"),
];

async fn extra_fields(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let id = cur.u16().await?;
        let len = cur.u16().await?;
        cur.skip(len.into());
        let name = crate::value::lookup(EXTRA_IDS, id.into())
            .map_or_else(|| format!("{id:#06x}"), str::to_owned);
        cx.push(
            Node::new(name)
                .span(cur.since(start))
                .value(Value::UInt {
                    value: id.into(),
                    bits: 16,
                    radix: crate::value::Radix::Hex,
                })
                .summary(format!("{len} bytes")),
        )
        .await;
    }
    Ok(())
}

/// Archives without a central directory (truncated downloads, streams):
/// walk local headers from the start.
async fn local_entries(cx: &Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(cx, input.span, LE);
    // A split archive's first part starts with a spanning marker.
    if cur.remaining() >= 4 && cur.peek(4).await? == b"PK\x07\x08" {
        cur.skip(4);
    }
    let mut found = false;
    while cur.remaining() >= LocalHeader::SIZE {
        let start = cur.pos();
        let magic = cur.peek(4).await?;
        if magic != LOCAL {
            break;
        }
        found = true;
        let (header, header_span) = cur.record::<LocalHeader>().await?;
        let name = decode_name(&cur.bytes(header.name_len.into()).await?, header.flags);
        cur.skip(header.extra_len.into());
        let data = cur.span(header.compressed.into());
        cur.skip(header.compressed.into());
        let mut node = Node::new(name).span(cur.since(start));
        if header.flags & 0x08 != 0 {
            node = node.diag(Diagnostic::unsupported(
                "size recorded in a data descriptor; cannot continue without the central directory",
            ));
            cx.push(node).await;
            break;
        }
        let (codec, data) = match method_codec(cx, header.method, header.flags, data, header.uncompressed.into()).await {
            Ok(Some(found)) => found,
            Ok(None) => {
                cx.push(node.diag(Diagnostic::unsupported("compression method")))
                    .await;
                continue;
            }
            Err(e) => {
                cx.push(node.diag(e)).await;
                continue;
            }
        };
        cx.push(node.summary(format!("{} bytes", header.uncompressed)).lazy(
            local_entry,
            (
                input,
                header_span,
                data,
                codec,
                u64::from(header.uncompressed),
            ),
        ))
        .await;
    }
    if !found {
        // Only reachable when the format was chosen by hand ("inspect as").
        return Err(Diagnostic::malformed("no ZIP end record or local file header").at(input.span.sub(0, 4)));
    }
    Ok(())
}

async fn local_entry(
    cx: Cx,
    (input, header, data, codec, size): (Input, Span, Span, Codec, u64),
) -> Result<()> {
    cx.emit(LocalHeader::node("Local File Header", header, LE));
    cx.emit(content("Content", input, data, codec, Some(size)));
    Ok(())
}
