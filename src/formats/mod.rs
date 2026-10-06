//! Format identification and the dissectors themselves.
//!
//! Every format is a [`Format`] entry in [`FORMATS`]: a name, a probe that
//! recognises it from the first and last bytes of the input, and an entry
//! point. Adding a format means adding a module and one line to the registry.

use std::borrow::Cow;

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::node::{Expansion, Node};
use crate::span::Span;

// Modules, grouped by family. Keep each group sorted; parallel branches
// touch different groups, so they merge cleanly.

// -- archives & compression --
pub mod ace;
pub mod ar;
pub mod arcutil;
pub mod arj;
pub mod brotli;
pub mod bzip2;
pub mod cab;
pub mod compress;
pub mod compressors;
pub mod cpio;
pub mod dmg;
pub mod firmware;
pub mod gzip;
pub mod hexfile;
pub mod iso9660;
pub mod lha;
pub mod lz4;
pub mod lzma;
pub mod rar;
pub mod rpm;
pub mod sevenzip;
pub mod squashfs;
pub mod stuffit;
pub mod tar;
pub mod wim;
pub mod xar;
pub mod xz;
pub mod zip;
pub mod zoo;
pub mod zstd;
// -- end archives --

// -- executables & code --
pub mod android;
pub mod aout;
pub mod beam;
mod binutil;
pub mod bitcode;
pub mod coff;
pub mod dart;
pub mod dxbc;
pub mod elc;
pub mod elf;
pub mod fatbin;
pub mod hermes;
pub mod il2cpp;
pub mod java;
pub mod lua;
pub mod luajit;
pub mod lx;
pub mod macho;
pub mod minidump;
pub mod ne;
pub mod ocaml;
pub mod omf;
pub mod opcache;
pub mod pe;
pub mod pef;
pub mod pyc;
pub mod qvm;
pub mod spirv;
pub mod te;
pub mod wasm;
pub mod xcoff;
pub mod yarb;
// -- end executables --

// -- images --
pub mod image;
pub mod png;
// -- end images --

// -- audio & video --
// audio (riff/iff/flac/mp3/ogg/...)
pub mod ac3;
pub mod adts;
pub mod amr;
pub mod ape;
pub mod apetag;
pub mod au;
pub mod caf;
pub mod dsd;
pub mod dts;
pub mod flac;
pub mod id3;
pub mod iff;
pub mod lossless;
pub mod midi;
pub mod mpa;
pub mod musepack;
pub mod ogg;
pub mod simple_audio;
pub mod smaf;
pub mod sound;
pub mod tracker;
pub mod tta;
pub mod voc;
pub mod vorbis;
pub mod w64;
pub mod wavpack;
// video & containers (isobmff/matroska/ts/...)
pub mod annexb;
pub mod asf;
pub mod flv;
pub mod gamevideo;
pub mod isobmff;
pub mod ivf;
pub mod matroska;
pub mod mpeg;
pub mod mxf;
pub mod rad;
pub mod rawvideo;
pub mod realmedia;
pub mod swf;
pub mod vidutil;
pub mod y4m;
// -- end audio & video --

// -- documents & data --
// data, system artifacts, fonts
pub mod applesingle;
pub mod bencode;
pub mod bookmark;
pub mod bplist;
pub mod cbor;
pub mod chm;
pub mod crx;
pub mod datakit;
pub mod dsstore;
pub mod evt;
pub mod evtx;
pub mod font;
pub mod gguf;
pub mod git;
pub mod icc;
pub mod json;
pub mod lnk;
pub mod mo;
pub mod npy;
pub mod pcap;
pub mod pickle;
pub mod prefetch;
pub mod recyclebin;
pub mod regf;
pub mod terminfo;
pub mod thumbcache;
pub mod winhelp;
// graph-shaped: sqlite/cfb/pdf/asn1/pgp/...
pub mod arrow;
pub mod asn1;
pub mod avro;
pub mod bdb;
pub mod cfb;
pub mod hdf5;
pub mod jet;
pub mod matlab;
pub mod netcdf;
pub mod orc;
pub mod parquet;
pub mod pdf;
pub mod pem;
pub mod pgp;
pub mod sqlite;
pub mod sst;
// -- end documents --

// -- disk images & filesystems --
pub mod disk;
// -- end disk images --

// -- retro & consoles --
pub mod retro;
// -- end retro --

// -- games, 3D, science, e-books, misc --
pub mod archives2;
pub mod bio;
pub mod bio2;
pub mod biotext;
pub mod browser;
pub mod cad;
pub mod cad2;
pub mod devices;
pub mod devtools;
pub mod ebooks;
pub mod eda;
pub mod eda2;
pub mod evidence;
pub mod games;
pub mod geo2;
pub mod geoscience;
pub mod graphics;
pub mod instruments;
pub mod instruments2;
pub mod keyrings;
pub mod lines;
pub mod logs;
pub mod microscopy;
pub mod misc10;
pub mod misc2;
pub mod misc3;
pub mod misc4;
pub mod misc5;
pub mod misc6;
pub mod misc7;
pub mod misc8;
pub mod misc9;
pub mod models;
pub mod molecular;
pub mod office_legacy;
pub mod packages;
pub mod pdb;
pub mod platform;
pub mod science;
pub mod security;
pub mod system;
pub mod unixforensics;
pub mod userdata;
pub mod windiag;
pub mod winforensics;
// -- end misc --

// -- ml models & mobile platforms --
pub mod ml;
pub mod mobile;
// -- end ml --

// -- geospatial, telemetry & vehicle logs --
pub mod geo;
// -- end geo --

// -- publishing, design & multimedia authoring --
pub mod publishing;
// -- end publishing --

// -- text --
pub mod text;
// -- end text --

/// How many leading bytes probes see. Large enough for magic numbers deep in
/// a file, such as ISO 9660's volume descriptor at 0x8001 and the btrfs and
/// UFS2 superblocks at 64 KiB.
pub const HEAD_LEN: u64 = 0x10800;
/// How many trailing bytes probes see.
pub const TAIL_LEN: u64 = 0x400;

/// The region a format dissector works on, plus how deeply it is embedded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input {
    pub span: Span,
    pub nesting: u32,
    /// The region this input is embedded in (itself, for the root).
    pub outer: Span,
}

impl Input {
    pub fn root(span: Span) -> Self {
        Input {
            span,
            nesting: 0,
            outer: span,
        }
    }

    /// An input embedded in this one.
    pub fn nested(&self, span: Span) -> Self {
        Input {
            span,
            nesting: self.nesting.saturating_add(1),
            outer: self.span,
        }
    }
}

/// What a probe sees of an input.
pub struct Head<'a> {
    /// The first [`HEAD_LEN`] bytes (fewer if the input is shorter).
    pub data: &'a [u8],
    /// The last [`TAIL_LEN`] bytes (may overlap `data`).
    pub tail: &'a [u8],
    /// Length of the whole input.
    pub len: u64,
}

impl Head<'_> {
    /// Whether `magic` occurs at `offset`.
    pub fn at(&self, offset: usize, magic: &[u8]) -> bool {
        offset
            .checked_add(magic.len())
            .and_then(|end| self.data.get(offset..end))
            .is_some_and(|b| b == magic)
    }

    pub fn starts_with(&self, magic: &[u8]) -> bool {
        self.data.starts_with(magic)
    }
}

pub enum Probe {
    /// Any of these `(offset, bytes)` pairs matches.
    Magic(&'static [(usize, &'static [u8])]),
    Custom(fn(&Head<'_>) -> bool),
}

impl Probe {
    fn matches(&self, head: &Head<'_>) -> bool {
        match self {
            Probe::Magic(list) => list.iter().any(|(offset, magic)| head.at(*offset, magic)),
            Probe::Custom(f) => f(head),
        }
    }
}

/// A registered file format.
pub struct Format {
    /// Short identifier, e.g. `"png"`.
    pub name: &'static str,
    /// Human-readable name, e.g. `"Portable Network Graphics"`.
    pub title: &'static str,
    pub extensions: &'static [&'static str],
    pub mime: &'static str,
    pub probe: Probe,
    pub dissect: fn(Cx, Input) -> Expansion,
}

/// All formats, in probing order: specific before generic.
pub static FORMATS: &[&Format] = &[
    // -- executables & code --
    &pe::DOS_EXE,
    &pe::FORMAT,
    &misc7::APPIMAGE,
    &elf::FORMAT,
    &macho::FORMAT,
    &macho::fat::FORMAT,
    &macho::dyld_cache::FORMAT,
    // After the universal binary probe, which shares the 0xcafebabe magic.
    &java::class::FORMAT,
    &java::serialization::FORMAT,
    &java::keystore::FORMAT,
    &wasm::FORMAT,
    &android::dex::FORMAT,
    &android::dex::ODEX,
    &android::resources::AXML,
    &android::resources::ARSC,
    &android::vdex::FORMAT,
    &android::art::FORMAT,
    &minidump::FORMAT,
    &ne::FORMAT,
    &lx::FORMAT,
    &omf::FORMAT,
    &qvm::FORMAT,
    &fatbin::FORMAT,
    &elc::FORMAT,
    &il2cpp::FORMAT,
    &opcache::FORMAT,
    &spirv::FORMAT,
    &dxbc::FORMAT,
    &te::FORMAT,
    &xcoff::FORMAT,
    &pef::FORMAT,
    &ocaml::FORMAT,
    &hermes::FORMAT,
    &dart::FORMAT,
    &yarb::FORMAT,
    &pyc::FORMAT,
    &lua::FORMAT,
    &luajit::FORMAT,
    &bitcode::FORMAT,
    &beam::FORMAT,
    // Weaker probes (sizes and machine numbers rather than long magics).
    &coff::FORMAT,
    &coff::IMPORT,
    &aout::PLAN9,
    &aout::FORMAT,
    // -- end executables --

    // -- images --
    &png::FORMAT,
    &png::MNG,
    &png::JNG,
    &image::bmp::FORMAT,
    &image::gif::FORMAT,
    &image::jpeg::FORMAT,
    &image::psd::FORMAT,
    &image::ico::ICO,
    &image::ico::CUR,
    &image::qoi::FORMAT,
    &image::dds::FORMAT,
    &image::ktx::KTX,
    &image::ktx::KTX2,
    &image::exr::FORMAT,
    &image::xcf::FORMAT,
    &image::icns::FORMAT,
    &image::j2k::FORMAT,
    &image::jxl::FORMAT,
    &image::pcx::DCX,
    &image::farbfeld::FORMAT,
    &image::sunras::FORMAT,
    &image::sgi::FORMAT,
    &image::hdr::FORMAT,
    &image::xbm::XPM,
    &image::xbm::XBM,
    &image::pnm::PBM,
    &image::pnm::PGM,
    &image::pnm::PPM,
    &image::pnm::PAM,
    &image::pnm::PFM,
    // TIFF-based camera raw formats before plain TIFF.
    &image::tiff::DNG,
    &image::tiff::CR2,
    &image::tiff::NEF,
    &image::tiff::ARW,
    &image::tiff::PEF,
    &image::tiff::SRW,
    &image::tiff::ORF,
    &image::tiff::RW2,
    &image::raw::RAF,
    &image::raw::MRW,
    &image::crw::FORMAT,
    &image::jbig2::FORMAT,
    &image::tiff::FORMAT,
    // Weak probes (footer, header sanity checks) last.
    &image::xwd::FORMAT,
    &image::tga::FORMAT,
    &image::pcx::FORMAT,
    &image::wbmp::FORMAT,
    // Also implemented in src/formats/image/ but not registered, because main
    // has its own versions (graphics.rs, science.rs): fits, dpx, cineon, astc,
    // pvr, vtf, emf, wmf, bpg, flif, jxr. Swap in whichever is deeper.
    // -- end images --

    // -- audio & video --
    // audio (riff/iff/flac/mp3/ogg/...)
    &iff::WAV,
    &iff::AVI,
    &iff::WEBP,
    &iff::ANI,
    &iff::RMI,
    &iff::DLS,
    &iff::SF2,
    &iff::XWMA,
    &iff::CDXA,
    &iff::RIFF_PALETTE,
    &iff::RDIB,
    &iff::RMMP,
    &iff::QCP,
    &iff::CDR,
    &iff::FOURXM,
    &iff::AMV,
    &iff::AIFF,
    &iff::AIFC,
    &iff::SVX8,
    &iff::SVX16,
    &iff::ILBM,
    &iff::ANIM,
    &iff::SMUS,
    &iff::FTXT,
    &iff::MAUD,
    // RIFF/RIFX forms from the publishing family, before generic RIFF.
    &publishing::authoring::DIRECTOR,
    &publishing::authoring::AEP,
    &publishing::authoring::CMX,
    &iff::RIFF,
    // IFF-shaped formats with their own dissectors, before generic IFF.
    &misc5::REX2,
    &iff::IFF,
    &midi::FORMAT,
    &au::FORMAT,
    &voc::FORMAT,
    &caf::FORMAT,
    &amr::FORMAT,
    &w64::FORMAT,
    &ape::FORMAT,
    &wavpack::FORMAT,
    &musepack::FORMAT,
    &tta::FORMAT,
    &lossless::TAK,
    &lossless::OFR,
    &lossless::SHORTEN,
    &dsd::DSF,
    &dsd::DFF,
    &smaf::FORMAT,
    &simple_audio::SOX,
    &simple_audio::IRCAM,
    &simple_audio::ADX,
    &simple_audio::KVAG,
    &simple_audio::AST,
    &simple_audio::ILBC,
    &simple_audio::QOA,
    &tracker::it::FORMAT,
    &tracker::xm::FORMAT,
    &tracker::s3m::FORMAT,
    &tracker::more::MTM,
    &tracker::more::STM,
    &tracker::more::ULT,
    &tracker::more::MED,
    &tracker::more::OKT,
    &tracker::protracker::FORMAT,
    &tracker::more::COMPOSER669,
    &simple_audio::RSO,
    &flac::FORMAT,
    &ogg::OPUS,
    &ogg::OGG_FLAC,
    &ogg::SPEEX,
    &ogg::THEORA,
    &ogg::FORMAT,
    &adts::FORMAT,
    &ac3::FORMAT,
    &dts::FORMAT,
    &mpa::FORMAT,
    &id3::FORMAT,
    // video & containers (isobmff/matroska/ts/...)
    &isobmff::CR3,
    &isobmff::HEIF,
    &isobmff::AVIF,
    &isobmff::JP2,
    &isobmff::JPX,
    &isobmff::MJ2,
    &isobmff::THREE_GP,
    &isobmff::THREE_G2,
    &isobmff::M4A,
    &isobmff::M4V,
    &isobmff::MOV,
    &isobmff::MP4,
    &matroska::WEBM,
    &matroska::MKV,
    &flv::FORMAT,
    &mpeg::ts::M2TS,
    &mpeg::ts::FORMAT,
    &mpeg::ps::MPEG2_PS,
    &mpeg::ps::MPEG1_SYSTEM,
    &mpeg::video::MPEG2_VIDEO,
    &mpeg::video::MPEG1_VIDEO,
    &mpeg::mpeg4::FORMAT,
    &annexb::HEVC,
    &annexb::H264,
    &ivf::FORMAT,
    &ivf::OBU,
    &y4m::FORMAT,
    &asf::WMV,
    &asf::WMA,
    &asf::ASF,
    &realmedia::FORMAT,
    &rad::BINK,
    &rad::SMACKER,
    &mxf::FORMAT,
    &swf::FORMAT,
    &gamevideo::ROQ,
    &gamevideo::FILM,
    &gamevideo::SMJPEG,
    &gamevideo::FLIC,
    &gamevideo::MVE,
    &gamevideo::THP,
    &rawvideo::DIRAC,
    &rawvideo::DNXHD,
    &rawvideo::H263,
    // -- end audio & video --

    // -- documents & data --
    // data, system artifacts, fonts
    &bplist::FORMAT,
    &bencode::FORMAT,
    &cbor::FORMAT,
    &pcap::FORMAT,
    &pcap::ng::FORMAT,
    &lnk::FORMAT,
    &regf::FORMAT,
    &evtx::FORMAT,
    &evt::FORMAT,
    &prefetch::FORMAT,
    &recyclebin::FORMAT,
    &thumbcache::FORMAT,
    &thumbcache::INDEX,
    &icc::FORMAT,
    &font::SFNT,
    &font::TTC,
    &font::woff::WOFF,
    &font::woff::WOFF2,
    &font::eot::FORMAT,
    &font::pfb::FORMAT,
    &font::bitmap::PCF,
    &font::bitmap::BDF,
    &mo::FORMAT,
    &terminfo::FORMAT,
    &npy::NPY,
    &npy::SAFETENSORS,
    &crx::CRX,
    &crx::MOZLZ4,
    &applesingle::APPLESINGLE,
    &applesingle::APPLEDOUBLE,
    &gguf::FORMAT,
    &pickle::FORMAT,
    &git::PACK,
    &git::PACK_INDEX,
    &git::INDEX,
    &chm::FORMAT,
    &winhelp::FORMAT,
    &dsstore::FORMAT,
    &bookmark::FORMAT,
    // graph-shaped: sqlite/cfb/pdf/asn1/pgp/...
    &sqlite::GEOPACKAGE,
    &sqlite::MBTILES,
    &sqlite::FORMAT,
    &sqlite::WAL,
    &sqlite::JOURNAL,
    &cfb::DOC,
    &cfb::XLS,
    &cfb::PPT,
    &cfb::MSG,
    &cfb::MSI,
    &cfb::THUMBS,
    &cfb::PUBLISHER,
    &cfb::FORMAT,
    &pdf::FORMAT,
    &asn1::X509,
    &asn1::CRL,
    &asn1::CSR,
    &asn1::PKCS7,
    &asn1::PKCS12,
    &asn1::PKCS8_ENCRYPTED,
    &asn1::DER,
    &pgp::FORMAT,
    &pgp::ARMOR,
    &pem::FORMAT,
    &avro::FORMAT,
    &netcdf::FORMAT,
    &hdf5::MAT73,
    &hdf5::FORMAT,
    &matlab::FORMAT,
    &parquet::FORMAT,
    &orc::FORMAT,
    &sst::LEVELDB,
    &sst::ROCKSDB,
    &bdb::FORMAT,
    &jet::MDB,
    &jet::ACCDB,
    &arrow::FORMAT,
    // -- end documents --

    // -- disk images & filesystems --
    // Virtual disk containers first: their payload may start with an MBR.
    &disk::vhd::FORMAT,
    &disk::vhdx::FORMAT,
    &disk::qcow::FORMAT,
    &disk::vmdk::FORMAT,
    &disk::vmdk::DESCRIPTOR,
    &disk::vdi::FORMAT,
    &disk::parallels::FORMAT,
    // Partition tables and volumes with distinctive signatures.
    &disk::gpt::FORMAT,
    &disk::bitlocker::FORMAT,
    &disk::luks::FORMAT,
    &disk::lvm::FORMAT,
    &disk::mdraid::FORMAT,
    &disk::swap::FORMAT,
    &disk::xfs::FORMAT,
    &disk::apm::FORMAT,
    &disk::uefi::FORMAT,
    &disk::zfs::FORMAT,
    &disk::hfs::FORMAT,
    &disk::apfs::FORMAT,
    &disk::ext::FORMAT,
    &disk::minix::FORMAT,
    &disk::bfs::FORMAT,
    &disk::f2fs::FORMAT,
    &disk::erofs::FORMAT,
    &disk::jfs::FORMAT,
    &disk::nilfs::FORMAT,
    &disk::ufs::FORMAT,
    // Boot sectors ending in 0x55AA, before the plain MBR.
    &disk::ntfs::FORMAT,
    &disk::exfat::FORMAT,
    &disk::fat::FORMAT,
    &disk::mbr::FORMAT,
    &disk::bsdlabel::FORMAT,
    // Detected only if the probe window reaches 64 KiB.
    &disk::btrfs::FORMAT,
    // -- end disk images --

    // -- archives & compression --
    // BGZF (blocked gzip) members are gzip members; identify them first.
    &bio::BAM,
    &bio::BCF,
    &bio::VCF_BGZF,
    &bio::TABIX,
    &bio::CSI,
    &bio::BGZF,
    &gzip::FORMAT,
    &dmg::FORMAT,
    &tar::FORMAT,
    &bzip2::FORMAT,
    &xz::FORMAT,
    &lzma::LZIP,
    &zstd::FORMAT,
    &zstd::SKIPPABLE,
    &lz4::FORMAT,
    &lz4::LEGACY,
    &lz4::SNAPPY,
    &compress::COMPRESS,
    &compress::PACK,
    &compressors::SZDD,
    &compressors::KWAJ,
    &ar::DEB,
    &ar::FORMAT,
    &cpio::FORMAT,
    &rpm::FORMAT,
    &sevenzip::FORMAT,
    &rar::FORMAT,
    &cab::FORMAT,
    &arj::FORMAT,
    &xar::FORMAT,
    &iso9660::FORMAT,
    &iso9660::UDF,
    &firmware::ANDROID_SPARSE,
    &firmware::ANDROID_BOOT,
    &firmware::UIMAGE,
    &squashfs::SQUASHFS,
    &squashfs::CRAMFS,
    &wim::FORMAT,
    &stuffit::FORMAT,
    &stuffit::SIT5,
    &zoo::FORMAT,
    &ace::ACE,
    // ZIP-based formats before plain ZIP (more specific ones first).
    // (ml models & mobile platforms)
    &zip::TORCHSCRIPT,
    &zip::PYTORCH,
    &zip::KERAS,
    &zip::NPZ,
    &zip::SIGROK,
    &zip::APEX,
    &zip::ANDROID_OTA,
    &zip::ANDROID_DM,
    &zip::BUGREPORT,
    &zip::IPSW,
    // (end ml)
    &zip::AAR,
    &zip::XLSB,
    &zip::SNUPKG,
    &zip::EPUB,
    &zip::ODT,
    &zip::ODS,
    &zip::ODP,
    &zip::ODG,
    &zip::DOCX,
    &zip::XLSX,
    &zip::PPTX,
    &zip::VSDX,
    &zip::XPS,
    &zip::APK,
    &zip::XPI,
    &zip::NUPKG,
    &zip::VSIX,
    &zip::WHL,
    &zip::IPA,
    &zip::KMZ,
    &zip::THREE_MF,
    &zip::SKETCH,
    &zip::USDZ,
    &zip::KRITA,
    &zip::ORA,
    &zip::IDML,
    &zip::ODF_FORMULA,
    &zip::ODB,
    &zip::IWORK,
    &zip::APPX,
    &zip::XAP,
    &zip::FBZ,
    &zip::CBZ,
    &zip::GEOGEBRA,
    &zip::DWFX,
    &zip::ADOBE_XD,
    &zip::PROCREATE,
    &zip::XFL,
    &zip::SXW,
    &zip::SXC,
    &zip::SXI,
    &zip::SXD,
    &zip::SXM,
    &zip::CDR_ZIP,
    &zip::IWORK09,
    &zip::MCPACK,
    &zip::SCRATCH,
    &zip::JAR,
    &zip::FORMAT,
    // Weak probes last.
    &tar::V7,
    &lha::FORMAT,
    &ace::ARC,
    &lzma::LZMA,
    &hexfile::IHEX,
    &hexfile::SREC,
    // -- end archives --

    // -- retro & consoles --
    &retro::consoles::NES,
    &retro::consoles::FDS,
    // GBX footers wrap Game Boy ROMs.
    &retro::extras::GBX,
    &retro::consoles::GBC,
    &retro::consoles::GB,
    &retro::consoles::GBA,
    &retro::consoles::NDS,
    &retro::consoles::N64,
    // Sega disc system areas carry a Mega Drive style header at 0x100.
    &retro::discs::SEGA_CD,
    &retro::discs::SATURN,
    &retro::discs::DREAMCAST,
    &retro::consoles::GENESIS,
    &retro::consoles::PSX_EXE,
    &retro::consoles::PBP,
    &retro::consoles::SFO,
    &retro::consoles::XBE,
    &retro::consoles::WII,
    &retro::consoles::GAMECUBE,
    &retro::consoles::NRO,
    &retro::consoles::NSO,
    &retro::consoles::THREEDSX,
    &retro::consoles::NCSD,
    &retro::consoles::NCCH,
    &retro::consoles::LYNX,
    &retro::consoles::A7800,
    &retro::consoles::SNES,
    &retro::music::NSF,
    &retro::music::NSFE,
    &retro::music::GBS,
    &retro::music::SPC,
    &retro::music::VGM,
    &retro::music::PSF,
    &retro::music::SID,
    &retro::music::HES,
    &retro::music::KSS,
    &retro::music::AY,
    &retro::music::SAP,
    &retro::music::YM,
    &retro::computers::T64,
    &retro::computers::CRT,
    &retro::computers::AMIGA_HUNK,
    &retro::computers::TZX,
    &retro::computers::CPC_DSK,
    &retro::computers::MSA,
    &retro::computers::ATR,
    &retro::computers::WOZ,
    &retro::computers::TWO_IMG,
    &retro::computers::UEF,
    &retro::computers::ADF,
    &retro::computers::D64,
    &retro::patches::IPS,
    &retro::patches::IPS32,
    &retro::patches::UPS,
    &retro::patches::BPS,
    &retro::patches::VCDIFF,
    &retro::patches::BSDIFF,
    &retro::patches::BSDIFF43,
    &retro::patches::PPF,
    &retro::patches::APS_N64,
    &retro::patches::APS_GBA,
    &retro::patches::GDIFF,
    &retro::patches::MSDELTA,
    &retro::patches::RUP,
    &retro::discs::CHD,
    &retro::discs::MDS,
    &retro::discs::CCD,
    &retro::discs::ECM,
    &retro::discs::CSO,
    &retro::discs::DAX,
    &retro::discs::ISZ,
    &retro::discs::DAA,
    &retro::discs::WBFS,
    &retro::discs::GCZ,
    &retro::discs::WIA,
    &retro::discs::RVZ,
    &retro::discs::TGC,
    &retro::discs::WII_CISO,
    &retro::discs::OPERA,
    &retro::consoles2::GAME_GEAR,
    &retro::consoles2::SMS,
    &retro::consoles2::SMD,
    &retro::consoles2::NGPC,
    &retro::consoles2::NGP,
    &retro::consoles2::POKEMON_MINI,
    &retro::consoles2::NEO_GEO,
    &retro::consoles2::UNIF,
    &retro::consoles2::VECTREX,
    &retro::states::ZSNES,
    &retro::states::SNES9X,
    &retro::states::FCEUX,
    &retro::states::RETROARCH,
    &retro::states::DTM,
    &retro::states::SMV,
    &retro::states::VBM,
    &retro::states::FCM,
    &retro::states::M64,
    &retro::states::GMV,
    &retro::states::DEXDRIVE,
    &retro::states::PS2_MEMCARD,
    &retro::states::PSX_MEMCARD,
    &retro::trackers::FAMITRACKER,
    &retro::trackers::FURNACE,
    &retro::trackers::DEFLEMASK,
    &retro::trackers::S98,
    &retro::trackers::GYM,
    &retro::trackers::ORGANYA,
    &retro::trackers::GOATTRACKER,
    &retro::trackers::SNDH,
    &retro::trackers::PT3,
    &retro::trackers::PSG,
    &retro::tapes::PZX,
    &retro::tapes::CSW,
    &retro::tapes::C64_TAP,
    &retro::tapes::G64,
    &retro::tapes::P00,
    &retro::tapes::SCL,
    &retro::tapes::MSX_CAS,
    &retro::tapes::ATARI_CAR,
    &retro::floppies::HFE,
    &retro::floppies::IPF,
    &retro::floppies::STX,
    &retro::floppies::IMD,
    &retro::floppies::TD0,
    &retro::floppies::A2R,
    &retro::floppies::MOOF,
    &retro::floppies::AMIGA_RDB,
    &retro::systems::SMDH,
    &retro::systems::FIRM,
    &retro::systems::KIP1,
    &retro::systems::INI1,
    &retro::systems::STFS,
    &retro::systems::XISO,
    &retro::micros::CPC_SNA,
    &retro::micros::SZX,
    &retro::micros::RZX,
    &retro::micros::NIB,
    &retro::micros::VICE,
    &retro::micros::ATARI_CAS,
    &retro::micros::ATX,
    &retro::micros::NUFX_ARCHIVE,
    &retro::micros::BINHEX,
    &retro::consoles3::WUX,
    &retro::consoles3::NCZ,
    &retro::consoles3::NPDM,
    &retro::consoles3::PS3_PUP,
    &retro::consoles3::PS4_PKG,
    &retro::consoles3::PSP_PRX,
    &retro::consoles3::SHARKPORT,
    &retro::consoles3::MAME_INP,
    &retro::consoles3::MAME_STATE,
    &retro::graphics::KICKSTART,
    &retro::graphics::AMIGA_INFO,
    &retro::extras::DSV,
    &retro::extras::GC_BANNER,
    &retro::extras::WII_BANNER,
    &retro::extras::TPL,
    &retro::extras::CEL_3DO,
    &retro::extras::HXC_MFM,
    &retro::extras::FDI,
    // Weak probes: trailers and text.
    &retro::discs::NRG,
    &retro::discs::CDI,
    &retro::discs::GDI,
    &retro::consoles2::INTELLIVISION,
    &retro::consoles2::COLECOVISION,
    &retro::consoles2::MSX_ROM,
    &retro::consoles2::WONDERSWAN_COLOR,
    &retro::consoles2::WONDERSWAN,
    &retro::consoles2::VIRTUAL_BOY,
    &retro::states::GCI,
    &retro::states::FM2,
    &retro::tapes::ZX_TAP,
    &retro::tapes::TRD,
    &retro::tapes::ORIC_TAP,
    &retro::tapes::ATARI_ST_PRG,
    &retro::floppies::SCP,
    &retro::floppies::DC42,
    &retro::floppies::D88,
    &retro::systems::DOL,
    &retro::systems::VMI,
    &retro::micros::ZX_SNA,
    &retro::micros::ATARI_XEX,
    &retro::micros::MACBINARY,
    &retro::graphics::DEGAS,
    &retro::graphics::NEOCHROME,
    &retro::graphics::KOALA,
    &retro::graphics::MSX_BSAVE,
    &retro::graphics::AMSDOS,
    &retro::dats::CLRMAMEPRO,
    &retro::dats::LOGIQX,
    &retro::dats::SOFTLIST,
    &retro::dats::CDRDAO_TOC,
    &retro::dats::RETROARCH_CHT,
    // -- end retro --

    // -- ml models & mobile platforms --
    &ml::binary::GGML,
    &ml::binary::GGMF,
    &ml::binary::GGJT,
    &ml::binary::GGLA,
    &ml::binary::NCNN_BIN,
    &ml::binary::MXNET,
    &ml::binary::NNEF_TENSOR,
    &ml::binary::FASTTEXT,
    &ml::binary::MLIR,
    &ml::tflite::TFLITE,
    &ml::tflite::ORT,
    &ml::tflite::EXECUTORCH,
    &mobile::android::SUPER,
    &mobile::android::VENDOR_BOOT,
    &mobile::android::BOOTLDR,
    &mobile::android::MTK,
    &mobile::android::PIT,
    &mobile::android::QCDT,
    &mobile::android::ART_PROFILE,
    &mobile::android::FCONTEXT,
    &mobile::android::HPROF,
    &mobile::android::METHOD_TRACE,
    &mobile::apple::NIB,
    &mobile::apple::METALLIB,
    &mobile::apple::CAR,
    &mobile::apple::CODE_SIGNATURE,
    &mobile::apple::AEA,
    &mobile::apple::SWIFTMODULE,
    &ml::protos::TFRECORD,
    &ml::protos::SAVED_MODEL,
    &ml::protos::COREML,
    &ml::protos::ONNX,
    &ml::protos::GRAPHDEF,
    &ml::protos::SENTENCEPIECE,
    &mobile::apple::TRUSTCACHE,
    &mobile::android::LOGCAT,
    &mobile::android_text::TOMBSTONE_FORMAT,
    &mobile::android_text::ANR,
    &mobile::android_text::BUILD_PROP,
    &mobile::apple_text::PBXPROJ,
    &mobile::apple_text::BCSYMBOLMAP,
    &mobile::apple_text::CRASH,
    &mobile::apple_text::IPS,
    &mobile::apple_text::TBD,
    &mobile::apple_text::STRINGS,
    &ml::text::NCNN,
    &ml::text::CAFFE,
    &ml::text::DARKNET,
    &ml::text::NNEF_GRAPH,
    &ml::text::LIBSVM,
    &ml::text::LIBLINEAR,
    &ml::text::LIGHTGBM,
    &ml::text::OPENVINO,
    &ml::text::PMML,
    &ml::text::OPENCV,
    &ml::text::MXNET_SYMBOL,
    &ml::text::TFJS,
    &ml::text::HF_TOKENIZER,
    &ml::text::SAFETENSORS_INDEX,
    // -- end ml --

    // -- geospatial, telemetry & vehicle logs --
    &geo::fit::FIT,
    &geo::tiles::PMTILES,
    &geo::tiles::FLATGEOBUF,
    &geo::tiles::O5M,
    &geo::tiles::MVT,
    &geo::gis::GDBTABLE,
    &geo::gis::ISO8211,
    &geo::gis::NTV2,
    &geo::gis::CTABLE2,
    &geo::gis::LAZ,
    &geo::gis::GARMIN_IMG,
    &geo::gis::GARMIN_GDB,
    &geo::gis::OV2,
    &geo::gnss::UBX,
    &geo::gnss::RTCM3,
    &geo::gnss::SBF,
    &geo::gnss::NOVATEL,
    &geo::gnss::NMEA,
    &geo::rinex::OBS,
    &geo::rinex::NAV,
    &geo::rinex::MET,
    &geo::rinex::CLOCK,
    &geo::rinex::CRINEX,
    &geo::rinex::ANTEX,
    &geo::rinex::IONEX,
    &geo::rinex::SP3,
    &geo::rinex::SINEX,
    &geo::mdf::MDF,
    &geo::vehicle::BLF,
    &geo::vehicle::ASC,
    &geo::vehicle::CANDUMP,
    &geo::vehicle::TRC,
    &geo::vehicle::DBC,
    &geo::vehicle::LDF,
    &geo::vehicle::A2L,
    &geo::robotics::ULOG,
    &geo::robotics::DATAFLASH,
    &geo::robotics::ARDUPILOT_LOG,
    &geo::robotics::TLOG,
    &geo::robotics::GPMF,
    &geo::robotics::ROSBAG,
    &geo::robotics::MCAP,
    &geo::robotics::BLACKBOX_LOG,
    &geo::gistext::IGC,
    &geo::gistext::OZI_TRACK,
    &geo::gistext::OZI_WAYPOINTS,
    &geo::gistext::OZI_ROUTE,
    &geo::gistext::OZI_MAP,
    &geo::gistext::MIF,
    &geo::gistext::TAB,
    &geo::gistext::GRASS_ASCII,
    &geo::gistext::GRASS_VECTOR,
    &geo::gistext::IDRISI,
    &geo::gistext::WKT,
    &geo::gistext::BIL_HDR,
    &geo::gistext::HRM,
    &geo::gistext::ERG,
    &geo::gistext::SRM,
    &geo::markup::TCX,
    &geo::markup::PWX,
    &geo::markup::FITLOG,
    &geo::markup::ZWO,
    &geo::markup::OSC,
    &geo::markup::GML,
    &geo::markup::ARXML,
    &geo::markup::ODX,
    &geo::markup::TILEJSON,
    &geo::markup::MAPBOX_STYLE,
    &geo::markup::QGC_PLAN,
    // -- end geo --

    // -- publishing, design & multimedia authoring --
    &publishing::adobe::PAT,
    &publishing::adobe::ABR,
    &publishing::adobe::GRD,
    &publishing::adobe::ASL,
    &publishing::adobe::ATN,
    &publishing::adobe::ACB,
    &publishing::adobe::CSH,
    &publishing::adobe::ACV,
    &publishing::fonts::CFF,
    &publishing::fonts::FNT,
    &publishing::fonts::PFM,
    &publishing::fonts::TFM,
    &publishing::fonts::VF,
    &publishing::fonts::AMIGA_FONT,
    &publishing::fonts::PFR,
    &publishing::fonts::BGI,
    &publishing::fonts::VFB,
    &publishing::fonts::SFD,
    &publishing::fonts::GLYPHS,
    &publishing::fonts::GLIF,
    &publishing::fonts::DESIGNSPACE,
    &publishing::dtp::INDESIGN,
    &publishing::dtp::QUARK,
    &publishing::dtp::XARA,
    &publishing::dtp::SCRIBUS,
    &publishing::dtp::XMP,
    &publishing::authoring::HYPERCARD,
    &publishing::authoring::FIGMA,
    &publishing::authoring::RIVE,
    &publishing::authoring::MOC3,
    &publishing::printing::PJL,
    &publishing::printing::PCLXL,
    &publishing::printing::PCL,
    &publishing::printing::CUPS_RASTER,
    &publishing::printing::URF,
    &publishing::printing::PPD,
    &publishing::printing::GPD,
    &publishing::printing::HPGL,
    &publishing::printing::ZPL,
    &publishing::printing::ESCP,
    &publishing::design::ASEPRITE,
    &publishing::design::PICT,
    &publishing::design::JASC_PAL,
    &publishing::design::GGR,
    &publishing::design::CUBE,
    &publishing::design::CGM,
    &publishing::design::GEM,
    // Identified by size alone: last.
    &publishing::adobe::ACT,
    // -- end publishing --

    // -- games, 3D, science, e-books, misc --
    &games::WAD,
    &games::PAK,
    &games::WAD2,
    &games::VPK,
    &games::MDL,
    &games::MD2,
    &games::MD3,
    &games::UNREAL,
    &games::BSP,
    &models::GLB,
    &models::FBX,
    &models::BLEND,
    &models::USDC,
    &models::VOX,
    &models::PLY,
    &models::DWG,
    &models::THREE_DS,
    &models::STL_ASCII,
    &models::DXF,
    &science::FITS,
    &science::DICOM,
    &science::SHX,
    &science::SHP,
    &science::LAS,
    &science::GRIB,
    &science::BUFR,
    &science::DBF,
    &ebooks::MOBI,
    &ebooks::PALMDOC,
    &ebooks::DJVU,
    &ebooks::LIT,
    &security::KDBX,
    &security::KDB,
    &security::OPENSSH_KEY,
    &security::KEYBOX,
    &security::KEYCHAIN,
    &security::ANDROID_BACKUP,
    &system::DTB,
    &system::BZIMAGE,
    &system::JOURNAL,
    &system::REDIS_RDB,
    &system::PST,
    &system::DOTNET_RESOURCES,
    &system::SNOOP,
    &system::ACPI,
    &graphics::EMF,
    &graphics::DPX,
    &graphics::CINEON,
    &graphics::VTF,
    &graphics::PVR,
    &graphics::ASTC,
    &graphics::PKM,
    &graphics::ASE,
    &graphics::GBR,
    &graphics::GPAT,
    &graphics::PDN,
    &graphics::BPG,
    &graphics::FLIF,
    &graphics::JXR,
    &graphics::WMF,
    &graphics::ACO,
    &packages::GODOT_PCK,
    &packages::UNITYFS,
    &packages::GAMEMAKER,
    &packages::RPA,
    &packages::APPLE_ARCHIVE,
    &packages::LZFSE,
    &packages::PBZX,
    &packages::LZOP,
    &packages::LZF,
    &packages::LRZIP,
    &packages::ZSTD_DICT,
    &packages::POWERPACKER,
    &packages::ZPAQ,
    &packages::PGS,
    &archives2::SARC,
    &archives2::YAZ0,
    &archives2::U8,
    &archives2::NARC,
    &archives2::PSARC,
    &archives2::XNB,
    &archives2::BSA,
    &archives2::BA2,
    &archives2::MPQ,
    &archives2::RGSSAD,
    &archives2::FXP,
    &archives2::FLP,
    &archives2::GUITAR_PRO,
    &archives2::UNREAL_PAK,
    &misc2::DVI,
    &misc2::WORDPERFECT,
    &misc2::WRITE,
    &misc2::ONENOTE,
    &misc2::FRAMEMAKER,
    &misc2::WARC,
    &misc2::AGE,
    &misc2::BITCOIN_BLOCKS,
    &misc2::BTSNOOP,
    &misc2::NETMON,
    &misc2::OTA_PAYLOAD,
    &misc2::REGISTRY_POL,
    &misc2::ESE,
    &misc2::BOMSTORE,
    &misc2::SDB,
    &misc2::SPSS,
    &misc2::SAS7BDAT,
    &misc2::STATA,
    &misc2::ROOT,
    &misc2::NIFTI,
    &misc2::NRRD,
    &misc2::HDF4,
    &misc2::VTK,
    &pdb::PDB,
    &pdb::PDB2,
    &platform::PERF,
    &platform::LDSO_CACHE,
    &platform::SELINUX,
    &platform::VBMETA,
    &platform::DTBO,
    &platform::INTEL_FLASH,
    &platform::CBFS,
    &platform::ARM_FIP,
    &platform::NSIS,
    &platform::INNO,
    &platform::JMOD,
    &platform::JIMAGE,
    &platform::MAC_RESOURCE,
    &devices::ROMFS,
    &devices::JFFS2,
    &devices::UBI,
    &devices::UBIFS,
    &devices::TRX,
    &devices::IMG3,
    &devices::XEX,
    &devices::PS3_SELF,
    &devices::PS3_PKG,
    &devices::NSP,
    &devices::XCI,
    &devices::WII_WAD,
    &devices::CIA,
    &devices::KERNEL_DUMP,
    // NTFS $LogFile restart pages also start with RSTR; check them first.
    &winforensics::LOGFILE,
    &devices::HIBERFIL,
    &devices::VERITY,
    &devices::BTRFS_SEND,
    &devtools::GCC_PCH,
    &devtools::CLANG_PCH,
    &devtools::WIN_RES,
    &devtools::ILK,
    &devtools::TYPELIB,
    &devtools::NAR,
    &devtools::GIT_BUNDLE,
    &devtools::HG_BUNDLE,
    &devtools::SVN_DUMP,
    &devtools::DUCKDB,
    &devtools::LMDB,
    &devtools::BOLT,
    &devtools::PROM_CHUNKS,
    &devtools::PROM_INDEX,
    &devtools::INFLUX_TSM,
    &devtools::LUCENE,
    &ebooks::PDB,
    // bioinformatics (BGZF-based ones are listed before gzip)
    &bio::BAI,
    &bio::CRAM,
    &bio::TWOBIT,
    &bio::BIGWIG,
    &bio::BIGBED,
    &bio::ABIF,
    &bio::SCF,
    &biotext::VCF,
    &biotext::SAM,
    &biotext::GFF3,
    &biotext::GENBANK,
    &biotext::STOCKHOLM,
    &biotext::CLUSTAL,
    &biotext::MAF,
    &biotext::NEXUS,
    &biotext::GFA,
    &biotext::JCAMP,
    &biotext::PDB_STRUCTURE,
    &biotext::SDF,
    &biotext::MOLFILE,
    &biotext::CIF,
    &biotext::WIG,
    &biotext::BED,
    &biotext::FASTQ,
    &biotext::FASTA,
    &instruments::FCS,
    &instruments::THERMO_RAW,
    &instruments::ABF,
    &instruments::ABF2,
    &instruments::EDF,
    &instruments::BDF,
    &instruments::GDF,
    &instruments::INTAN_RHD,
    &instruments::TDMS,
    &instruments::TDMS_INDEX,
    &instruments::NEV,
    &instruments::NSX,
    &instruments::PLEXON,
    &instruments::BRAINVISION_HEADER,
    &instruments::BRAINVISION_MARKERS,
    &instruments::NEURALYNX,
    &instruments::IDX,
    &geoscience::SEGY,
    &geoscience::SEG2,
    &geoscience::MSEED3,
    &geoscience::SAC,
    &geoscience::ERDAS_IMG,
    &geoscience::E57,
    &geoscience::PCD,
    &geoscience::LAS_LOG,
    &geoscience::SURFER_GRID,
    &geoscience::ESRI_GRID,
    &geoscience::ENVI_HDR,
    &geoscience::PDS3,
    &geoscience::VICAR,
    &geoscience::MSEED2,
    &eda::GDSII,
    &eda::OASIS,
    &eda::KICAD_PCB,
    &eda::KICAD_SCH,
    &eda::KICAD_SYM,
    &eda::KICAD_MOD,
    &eda::EDIF,
    &eda::SDF_TIMING,
    &eda::VCD,
    &eda::CITI,
    &eda::SPICE_RAW,
    &eda::IBIS,
    &eda::SPEF,
    &eda::XILINX_BIT,
    &eda::JEDEC,
    &eda::EXCELLON,
    &eda::GERBER,
    &eda::TOUCHSTONE,
    &browser::IE_INDEX,
    &browser::BINARYCOOKIES,
    &browser::CHROME_CACHE_INDEX,
    &browser::CHROME_CACHE_BLOCK,
    &browser::CHROME_SIMPLE,
    &browser::CHROME_VISITED,
    &browser::SNSS,
    &browser::MORK,
    &winforensics::CUSTOM_DESTINATIONS,
    &winforensics::INFO2,
    &winforensics::MFT,
    &winforensics::INDX,
    &winforensics::JOB,
    &winforensics::NK2,
    &winforensics::DBX,
    &winforensics::RDP_CACHE,
    &winforensics::SCF,
    &winforensics::GRP,
    &winforensics::CARDFILE,
    &winforensics::CLP,
    &winforensics::USN,
    &unixforensics::FSEVENTS,
    &unixforensics::TIMESYNC,
    &unixforensics::TRACEV3,
    &unixforensics::ASL,
    &unixforensics::MBDB,
    &unixforensics::ABX,
    &unixforensics::UTMPX,
    &unixforensics::UUIDTEXT,
    &unixforensics::MBDX,
    &browser::CHROME_SIMPLE_INDEX,
    &office_legacy::LOTUS,
    &office_legacy::LOTUS3,
    &office_legacy::QUATTRO,
    &office_legacy::WORKS_WKS,
    &office_legacy::XLS_BIFF,
    &office_legacy::CLARISWORKS,
    &office_legacy::SKETCHUP,
    &office_legacy::SYLK,
    &office_legacy::DIF,
    &office_legacy::QIF,
    &office_legacy::OFX,
    &office_legacy::MPX,
    &office_legacy::AMIPRO,
    &office_legacy::MONEY,
    &office_legacy::WORDPRO,
    &windiag::WER,
    &windiag::PIF,
    &logs::SETUPAPI,
    &logs::W3C,
    &logs::TRANSCRIPT,
    &logs::AUDIT,
    &logs::VIMINFO,
    &evidence::EWF,
    &evidence::AFF,
    &evidence::LIME,
    &evidence::KDUMP,
    &evidence::VMSS,
    &evidence::VBOX_SAV,
    &userdata::ZSH,
    &userdata::BASH,
    &userdata::FISH,
    &userdata::LIBEDIT,
    &userdata::LESS,
    &userdata::WGET_HSTS,
    &userdata::COOKIES_TXT,
    &userdata::BOOKMARKS,
    &userdata::OPERA_HOTLIST,
    &userdata::FIREFOX_PREFS,
    &userdata::CERT_OVERRIDE,
    &userdata::TRASHINFO,
    &userdata::XBEL,
    &keyrings::GNOME_KEYRING,
    &keyrings::KWALLET,
    &office_legacy::WINWORD2,
    &office_legacy::HWP3,
    &office_legacy::HWP5_HEADER,
    &winforensics::ODL,
    &misc3::OSM_PBF,
    &misc3::DTED,
    &misc3::NITF,
    &misc3::ALZ,
    &misc3::EGG,
    &misc3::KGB,
    &misc3::ISCAB,
    &misc3::ISZ,
    &misc3::PHOTO_CD,
    &misc3::X3F,
    &misc3::EBU_STL,
    &misc3::SCC,
    &misc3::VOBSUB,
    &misc3::NUT,
    &misc3::VRML,
    &misc3::OFF,
    &misc3::MD5MESH,
    &misc3::SOURCE_MDL,
    &misc3::PSK,
    &misc3::LRF,
    &misc3::AFM,
    &misc3::PFA,
    &misc4::BLP,
    &misc4::M2,
    &misc4::W3M,
    &misc4::TES,
    &misc4::GTA_IMG,
    &misc4::HOG,
    &misc4::GRP,
    &misc4::BIG,
    &misc4::RFF,
    &misc4::BND,
    &misc4::NW4,
    &misc4::NW4R,
    &misc4::MUS,
    &misc4::HMI,
    &misc4::AHX,
    &misc4::MO3,
    &misc4::DBM,
    &misc4::FAR,
    &misc4::PSF_FONT,
    &misc4::BMFONT,
    &misc4::FIGLET,
    &misc4::TEX_PK,
    &misc4::TEX_GF,
    &misc4::PPK,
    &misc4::SPHERE,
    &misc4::AVR,
    &misc4::PVF,
    &misc4::MIFF,
    &misc4::UTAH_RLE,
    &misc4::PSP,
    &misc5::FSB,
    &misc5::XWB,
    &misc5::WWISE_BNK,
    &misc5::VAG,
    &misc5::OMA,
    &misc5::HCA,
    &misc5::USM,
    &misc5::CPK,
    &misc5::AFS,
    &misc5::EA_SCHL,
    &misc5::NSV,
    &misc5::NUV,
    &misc5::R3D,
    &misc5::DPAINT_ANM,
    &misc5::TWINVQ,
    &misc5::EXS,
    &misc5::PTAB,
    &cad::STEP,
    &cad::IGES,
    &cad::PARASOLID,
    &cad::JT,
    &cad::GMSH,
    &cad::OPENFOAM,
    &cad::ABAQUS,
    &cad::LSDYNA,
    &microscopy::MRC,
    &microscopy::CZI,
    &microscopy::ND2,
    &microscopy::LIF,
    &microscopy::SER,
    &microscopy::GATAN_DM,
    &molecular::DCD,
    &molecular::XTC,
    &molecular::TRR,
    &molecular::MOL2,
    &molecular::CHARMM_PSF,
    &molecular::MSP,
    &molecular::MGF,
    &instruments2::NMRPIPE,
    &instruments2::SPARKY,
    &instruments2::RIGAKU_RAS,
    &instruments2::IMAGEJ_ROI,
    &instruments2::PRINCETON_SPE,
    &instruments2::ICS,
    &instruments2::IMOD,
    &instruments2::FREESURFER_SURF,
    &instruments2::SPIKE2,
    &instruments2::AXON_ATF,
    &instruments2::IGOR_ITX,
    &instruments2::LABVIEW_LVM,
    &instruments2::KEYSIGHT_BIN,
    &instruments2::TEKTRONIX_ISF,
    &instruments2::LECROY_TRC,
    &instruments2::FST,
    &instruments2::BIORAD_PIC,
    &instruments2::MGH,
    &instruments2::ANALYZE,
    &instruments2::GALACTIC_SPC,
    &bio2::SFF,
    &bio2::ZTR,
    &bio2::SLOW5,
    &bio2::BLOW5,
    &bio2::HIC,
    &bio2::HMMER3,
    &bio2::EMBL,
    &bio2::PSL,
    &bio2::MZTAB,
    &bio2::AMBER_PRMTOP,
    &bio2::GTF,
    &cad2::RHINO_3DM,
    &cad2::ACIS_SAB,
    &cad2::ANSYS_CDB,
    &cad2::TECPLOT,
    &cad2::ENSIGHT_CASE,
    &cad2::ENSIGHT_GOLD,
    &cad2::OPENVDB,
    &cad2::NASTRAN,
    &geo2::ERMAPPER_ERS,
    &geo2::DLIS,
    &eda::SAIF,
    &eda::SPECCTRA_DSN,
    &eda::SPECCTRA_SES,
    &eda2::LTSPICE_ASC,
    &eda2::LTSPICE_ASY,
    &eda2::KICAD_LEGACY_SCH,
    &eda2::KICAD_LEGACY_LIB,
    &eda2::KICAD_LEGACY_PCB,
    &eda2::GEDA_SCH,
    &eda2::PADS_ASCII,
    &eda2::DEF,
    &eda2::LEF,
    &misc6::HA,
    &misc6::UHARC,
    &misc6::YZ1,
    &misc6::DGCA,
    &misc6::GCA,
    &misc6::PAQ8,
    &misc6::FREEZE,
    &misc6::COMPACT,
    &misc6::XPK,
    &misc6::AMIGA_LZX,
    &misc6::PACKIT,
    &misc6::CPT,
    &misc6::CLIP,
    &misc6::MDP,
    &misc6::GIMP_GPL,
    &misc6::PGF,
    &misc6::XV_THUMB,
    &misc6::VIFF,
    &misc6::OS2_INF,
    &misc6::TCR,
    &misc6::AMIGAGUIDE,
    &misc6::TOKYO,
    &misc6::KYOTO,
    &misc6::GDBM,
    &misc6::RRD,
    &misc6::WIREDTIGER,
    &misc6::REALM,
    &misc7::KEYTAB,
    &misc7::CCACHE,
    &misc7::PWSAFE,
    &misc7::OPENSSL_ENC,
    &misc7::AESCRYPT,
    &misc7::AXCRYPT,
    &misc7::MINISIGN,
    &misc7::MTF,
    &misc7::ORACLE_EXP,
    &misc7::PG_DUMP,
    &misc7::MYSQL_FRM,
    &misc7::MYISAM,
    &misc7::H2,
    &misc7::FILEMAKER,
    &misc7::R_DATA,
    &misc7::ASDF,
    &misc7::WAB,
    &misc7::APPLESCRIPT,
    &misc7::SOLARIS_PKG,
    &misc7::HPKG,
    &misc7::ASAR,
    &misc8::DIRECTX_X,
    &misc8::MS3D,
    &misc8::CAL3D,
    &misc8::OGRE,
    &misc8::MAYA,
    &misc8::C4D,
    &misc8::BGEO,
    &misc8::ALEMBIC,
    &misc8::NIF,
    &misc8::HKX,
    &misc8::BGSM,
    &misc8::WOW_CHUNKED,
    &misc8::WOW_DB,
    &misc8::WC3_MDX,
    &misc8::QUAKE_SPR,
    &misc8::QUAKE2_SP2,
    &misc8::RTCW_MODEL,
    &misc8::HEXEN2_MDL,
    &misc8::VVD,
    &misc8::DMX,
    &misc8::UTOC,
    &misc8::XP3,
    &misc8::ALLEGRO,
    &misc8::RPYC,
    &misc9::BFRES,
    &misc9::BNTX,
    &misc9::MSBT,
    &misc9::CGFX,
    &misc9::J3D,
    &misc9::RARC,
    &misc9::BRRES,
    &misc9::GIM,
    &misc9::GXT,
    &misc9::RCO,
    &misc9::NPD,
    &misc9::XDBF,
    &misc9::XPR,
    &misc9::XACT,
    &misc9::SEGA_TEXTURE,
    &misc9::NINJA,
    &misc10::PTM,
    &misc10::DMF,
    &misc10::IMF,
    &misc10::J2B,
    &misc10::GDM,
    &misc10::MT2,
    &misc10::AMS,
    &misc10::SYMPHONIE,
    &misc10::DIGITRAKKER,
    &misc10::PLM,
    &misc10::PSM,
    &misc10::AMF,
    &misc10::GUS_PAT,
    &misc10::REALAUDIO,
    &misc10::PSION_WVE,
    &misc10::EVS,
    &misc10::SMUSH,
    &misc10::DXA,
    &misc10::ARMOVIE,
    &misc10::SGI_MOVIE,
    // Weak, size-based probes last.
    &misc9::BYML,
    &misc6::SQUEEZE,
    &misc6::CRUNCH,
    &misc4::NBT,
    &misc3::HGT,
    &unixforensics::UTMP,
    &browser::FIREFOX_CACHE2,
    &logs::ACCT,
    &winforensics::RDP_FILE,
    &unixforensics::LASTLOG,
    &winforensics::DESTLIST,
    &winforensics::AUTORUN,
    &winforensics::DESKTOP_INI,
    &models::STL,
    // -- end misc --

    // -- text (generic probes, keep last) --
    // Documents with a fixed signature.
    &text::rtf::FORMAT,
    &text::postscript::DOS_EPS,
    &text::postscript::EPS,
    &text::postscript::POSTSCRIPT,
    // Binary formats found inside text armor.
    &text::ssh::BLOB,
    // Armor and keys.
    &text::pem::SSH2,
    &text::ssh::KEYS,
    // Messages (header blocks look like YAML; keep them before it).
    &text::mime::MBOX,
    &text::mime::MHTML,
    &text::mime::EML,
    &text::yenc::FORMAT,
    &text::ldif::FORMAT,
    &text::diff::FORMAT,
    &text::vcard::VCARD,
    &text::vcard::ICALENDAR,
    // Timed text and playlists.
    &text::subtitles::WEBVTT,
    &text::subtitles::SRT,
    &text::subtitles::LRC,
    &text::playlist::HLS,
    &text::playlist::M3U,
    &text::playlist::PLS,
    &text::playlist::CUE,
    &text::subtitles::MICRODVD,
    &text::sln::FORMAT,
    &text::dockerfile::FORMAT,
    &text::dot::FORMAT,
    // Line-oriented data with distinctive keywords.
    &text::uuencode::FORMAT,
    &text::po::FORMAT,
    &text::bibtex::FORMAT,
    &text::checksums::FORMAT,
    &text::obj::OBJ,
    &text::obj::MTL,
    // Markup: specific XML vocabularies, then HTML, then generic XML.
    &text::plist::FORMAT,
    &text::xml::XHTML,
    &text::xml::SVG,
    &text::xml::RSS,
    &text::xml::ATOM,
    &text::xml::GPX,
    &text::xml::KML,
    &text::xml::POM,
    &text::xml::XAML,
    &text::xml::MATHML,
    &text::xml::XSLT,
    &text::xml::XSD,
    &text::xml::MSBUILD,
    &text::xml::COLLADA,
    &text::xml::TTML,
    &text::xml::DASH,
    &text::xml::XLIFF,
    &text::xml::OPF,
    &text::xml::OSM,
    &text::xml::XSPF,
    &text::xml::TEI,
    &text::xml::DOCBOOK,
    &text::xml::ANDROID_MANIFEST,
    &text::xml::WSDL,
    &text::xml::SOAP,
    &text::xml::SITEMAP,
    &text::xml::DRAWIO,
    &text::xml::OPML,
    &text::xml::FB2,
    &text::xml::GRAPHML,
    &text::xml::SMIL,
    &text::xml::NZB,
    &text::xml::JUNIT,
    &text::xml::MUSICXML,
    &text::xml::X3D,
    &text::xml::WIX,
    &text::xml::NUSPEC,
    &text::xml::XIB,
    &text::xml::GLADE,
    &text::xml::FLAT_ODF,
    &text::xml::VSTEMPLATE,
    &text::html::FORMAT,
    &text::xml::FORMAT,
    // JSON and its vocabularies.
    &text::json::IPYNB,
    &text::json::GLTF,
    &text::json::JSON_SCHEMA,
    &text::json::TOPOJSON,
    &text::json::WEB_MANIFEST,
    &text::json::EXTENSION_MANIFEST,
    &text::json::LOTTIE,
    &text::json::EXCALIDRAW,
    &text::json::SARIF,
    &text::json::OPENAPI,
    &text::json::TSCONFIG,
    &text::json::NPM_PACKAGE,
    &text::json::GEOJSON,
    &text::json::HAR,
    &text::json::NDJSON,
    &text::json::FORMAT,
    // TOML before INI: its values are typed, INI's are not.
    &text::ini::EDITORCONFIG,
    &text::toml::FORMAT,
    // INI family: specific first.
    &text::ini::REG,
    &text::ini::DESKTOP,
    &text::ini::URL,
    &text::ini::SYSTEMD,
    &text::ini::INF,
    &text::ini::ASS,
    &text::ini::FORMAT,
    // Markdown before YAML: front matter starts like a YAML document.
    &text::markdown::FORMAT,
    &text::yaml::KUBERNETES,
    &text::yaml::COMPOSE,
    &text::yaml::GITHUB_WORKFLOW,
    &text::yaml::OPENAPI,
    &text::yaml::FORMAT,
    &text::plain::SCRIPT,
    // Brotli has no magic: only small files that decode as exactly one
    // complete stream (a trial decode, so after everything with magic).
    &brotli::FORMAT,
    // Weak, statistical probes.
    &text::csv::TSV,
    &text::csv::CSV,
    // Plain text matches anything textual: keep it last.
    &text::plain::FORMAT,
    // -- end text --
];

pub fn by_name(name: &str) -> Option<&'static Format> {
    FORMATS.iter().copied().find(|f| f.name == name)
}

/// Picks the first format whose probe matches.
pub fn identify(head: &Head<'_>) -> Option<&'static Format> {
    FORMATS.iter().copied().find(|f| f.probe.matches(head))
}

/// A top-level node that identifies and dissects `span` when expanded.
pub fn root(name: impl Into<Cow<'static, str>>, span: Span) -> Node {
    Node::new(name).span(span).lazy(dissect, Input::root(span))
}

/// A node for embedded content, identified and dissected on expansion.
pub fn embedded(name: impl Into<Cow<'static, str>>, input: Input) -> Node {
    Node::new(name).span(input.span).lazy(dissect, input)
}

/// A node for embedded content of a known format.
pub fn embedded_as(
    name: impl Into<Cow<'static, str>>,
    input: Input,
    format: &'static Format,
) -> Node {
    Node::new(name)
        .span(input.span)
        .lazy(dissect_as, (input, format.name))
}

fn check_nesting(cx: &Cx, input: &Input) -> Result<()> {
    let max = cx.limits().max_nesting;
    if input.nesting > max {
        return Err(
            Diagnostic::limit(format!("embedded objects nested deeper than {max}")).at(input.span),
        );
    }
    Ok(())
}

/// Reads what probes need: the head and the tail of the input.
pub async fn head(cx: &Cx, span: Span) -> Result<(Vec<u8>, Vec<u8>)> {
    let max = cx.limits().max_read;
    let data = cx.read_avail(span.sub(0, HEAD_LEN.min(max))).await?;
    // Reading the tail of a lazily decoded stream would decode all of it.
    let tail = if span.len > HEAD_LEN && cx.is_lazy(span.source) {
        Vec::new()
    } else if span.len > HEAD_LEN {
        cx.read_avail(span.tail(span.len.saturating_sub(TAIL_LEN.min(max))))
            .await?
    } else {
        data.clone()
    };
    Ok((data, tail))
}

/// Identifies the format of `input` and dissects it.
pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    check_nesting(&cx, &input)?;
    let (data, tail) = head(&cx, input.span).await?;
    let probe = Head {
        data: &data,
        tail: &tail,
        len: input.span.len,
    };
    match identify(&probe) {
        Some(format) => (format.dissect)(cx, input).await,
        None if data.is_empty() => Err(Diagnostic::note("empty").at(input.span)),
        None => Err(Diagnostic::unsupported("unrecognized format").at(input.span)),
    }
}

/// Dissects `input`, or, if its format is not recognised, shows it as a
/// plain data leaf so its bytes stay reachable (e.g. decompressed content).
pub async fn dissect_or_data(cx: Cx, input: Input) -> Result<()> {
    check_nesting(&cx, &input)?;
    let (data, tail) = head(&cx, input.span).await?;
    let probe = Head {
        data: &data,
        tail: &tail,
        len: input.span.len,
    };
    match identify(&probe) {
        Some(format) => (format.dissect)(cx, input).await,
        None => {
            cx.emit(Node::new("Data").span(input.span));
            Ok(())
        }
    }
}

/// Members larger than this are decompressed lazily rather than up front.
const LAZY_THRESHOLD: u64 = 1024 * 1024;

pub use crate::codec::Codec;

/// A node for content stored in `span` with `codec`. Nothing is read or
/// decompressed until it is expanded; then the content is decoded into a
/// derived source and dissected in place.
pub fn content(
    name: impl Into<Cow<'static, str>>,
    input: Input,
    span: Span,
    codec: Codec,
    expected: Option<u64>,
) -> Node {
    Node::new(name)
        .span(span)
        .lazy(expand_content, (input, span, codec, expected))
}

async fn expand_content(
    cx: Cx,
    (input, span, codec, expected): (Input, Span, Codec, Option<u64>),
) -> Result<()> {
    let inner = match codec {
        Codec::Stored => input.nested(span),
        // Large members are decoded lazily: listing the first entries of a
        // multi-gigabyte tarball only decodes what those entries need. A
        // claimed size beyond the codec's maximum ratio is bogus and gets the
        // eager path (which reports the real size).
        codec
            if expected.is_some_and(|e| {
                e > LAZY_THRESHOLD && e <= span.len.saturating_mul(codec.max_ratio())
            }) =>
        {
            let len = expected.unwrap_or(0);
            let decoded = cx.decode_lazy(span, &codec, len)?;
            cx.annotate(format!("{len:#x} bytes, decoded on demand"));
            input.nested(decoded)
        }
        codec => {
            let decoded = crate::codec::decode_span(&cx, span, &codec, expected).await?;
            cx.annotate(format!("{:#x} bytes {}", decoded.span.len, codec.verb()));
            if let Some(e) = decoded.error {
                cx.diag(e);
            } else if decoded.consumed < span.len {
                cx.diag(Diagnostic::note(format!(
                    "{:#x} bytes follow the encoded stream",
                    span.len.saturating_sub(decoded.consumed)
                )));
            }
            input.nested(decoded.span)
        }
    };
    dissect_or_data(cx, inner).await
}

async fn dissect_as(cx: Cx, (input, name): (Input, &'static str)) -> Result<()> {
    check_nesting(&cx, &input)?;
    let format =
        by_name(name).ok_or_else(|| Diagnostic::internal(format!("unknown format {name}")))?;
    (format.dissect)(cx, input).await
}
