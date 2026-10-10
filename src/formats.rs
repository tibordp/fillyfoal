//! Every format this build registers, in probing order, on top of the
//! core's plumbing ([`fillyfoal_core::formats`]). Each family lives in the
//! crate of its category, enabled by the feature of the same name.

pub use fillyfoal_core::formats::*;

#[cfg(feature = "archive")]
pub use fillyfoal_archive::formats::archive;
#[cfg(feature = "archive")]
pub use fillyfoal_archive::formats::compression;
#[cfg(feature = "archive")]
pub use fillyfoal_archive::formats::disk;
#[cfg(feature = "av")]
pub use fillyfoal_av::formats::audio;
#[cfg(feature = "av")]
pub use fillyfoal_av::formats::iff;
#[cfg(feature = "av")]
pub use fillyfoal_av::formats::isobmff;
#[cfg(feature = "av")]
pub use fillyfoal_av::formats::mpeg;
#[cfg(feature = "av")]
pub use fillyfoal_av::formats::tracker;
#[cfg(feature = "av")]
pub use fillyfoal_av::formats::video;
#[cfg(feature = "data")]
pub use fillyfoal_data::formats::data;
#[cfg(feature = "data")]
pub use fillyfoal_data::formats::sqlite;
#[cfg(feature = "docs")]
pub use fillyfoal_docs::formats::cfb;
#[cfg(feature = "docs")]
pub use fillyfoal_docs::formats::documents;
#[cfg(feature = "docs")]
pub use fillyfoal_docs::formats::pdf;
#[cfg(feature = "docs")]
pub use fillyfoal_docs::formats::publishing;
#[cfg(feature = "exec")]
pub use fillyfoal_exec::formats::android;
#[cfg(feature = "exec")]
pub use fillyfoal_exec::formats::bytecode;
#[cfg(feature = "exec")]
pub use fillyfoal_exec::formats::executable;
#[cfg(feature = "exec")]
pub use fillyfoal_exec::formats::java;
#[cfg(feature = "games")]
pub use fillyfoal_games::formats::games;
#[cfg(feature = "games")]
pub use fillyfoal_games::formats::retro;
#[cfg(feature = "image")]
pub use fillyfoal_image::formats::font;
#[cfg(feature = "image")]
pub use fillyfoal_image::formats::image;
#[cfg(feature = "science")]
pub use fillyfoal_science::formats::engineering;
#[cfg(feature = "science")]
pub use fillyfoal_science::formats::geo;
#[cfg(feature = "science")]
pub use fillyfoal_science::formats::science;
#[cfg(feature = "security")]
pub use fillyfoal_security::formats::asn1;
#[cfg(feature = "security")]
pub use fillyfoal_security::formats::pcap;
#[cfg(feature = "security")]
pub use fillyfoal_security::formats::security;
#[cfg(feature = "system")]
pub use fillyfoal_system::formats::forensics;
#[cfg(feature = "system")]
pub use fillyfoal_system::formats::ml;
#[cfg(feature = "system")]
pub use fillyfoal_system::formats::mobile;
#[cfg(feature = "system")]
pub use fillyfoal_system::formats::system;
#[cfg(feature = "text")]
pub use fillyfoal_text::formats::text;

/// Formats that dissect their input from the front without needing its
/// length: content decoded on demand whose size nothing records (a
/// `.tar.zst` written to a pipe, a `.log.gz`) is dissected as soon as it is
/// identified as one of these. Any other format first has the stream decoded
/// to its end, in budgeted steps, so that it sees its real length (see
/// [`dissect_unsized`]). A format joins this list only if it gives the same
/// tree with its length unknown (`tests/unsized.rs`).
pub static STREAMING: &[&Format] = &[
    #[cfg(feature = "archive")]
    &archive::tar::FORMAT,
    #[cfg(feature = "archive")]
    &archive::cpio::FORMAT,
    #[cfg(feature = "text")]
    &text::plain::FORMAT,
];

/// Every format.
pub static REGISTRY: Registry = Registry {
    formats: FORMATS,
    streaming: STREAMING,
};

/// The catalog of every format.
pub struct All;

impl Catalog for All {
    const REGISTRY: &'static Registry = &REGISTRY;
}

/// All formats, in probing order: specific before generic.
pub static FORMATS: &[&Format] = &[
    // -- executables & code --
    #[cfg(feature = "exec")]
    &executable::pe::DOS_EXE,
    #[cfg(feature = "exec")]
    &executable::pe::FORMAT,
    #[cfg(feature = "archive")]
    &archive::packaging::APPIMAGE,
    #[cfg(feature = "exec")]
    &android::oat::FORMAT,
    #[cfg(feature = "exec")]
    &executable::elf::FORMAT,
    #[cfg(feature = "exec")]
    &executable::macho::FORMAT,
    #[cfg(feature = "exec")]
    &executable::macho::fat::FORMAT,
    #[cfg(feature = "exec")]
    &executable::macho::dyld_cache::FORMAT,
    // After the universal binary probe, which shares the 0xcafebabe magic.
    #[cfg(feature = "exec")]
    &java::class::FORMAT,
    #[cfg(feature = "exec")]
    &java::serialization::FORMAT,
    #[cfg(feature = "exec")]
    &java::keystore::FORMAT,
    #[cfg(feature = "exec")]
    &bytecode::wasm::FORMAT,
    #[cfg(feature = "exec")]
    &android::dex::FORMAT,
    #[cfg(feature = "exec")]
    &android::dex::ODEX,
    #[cfg(feature = "exec")]
    &android::resources::AXML,
    #[cfg(feature = "exec")]
    &android::resources::ARSC,
    #[cfg(feature = "exec")]
    &android::vdex::FORMAT,
    #[cfg(feature = "exec")]
    &android::art::FORMAT,
    #[cfg(feature = "exec")]
    &android::apksig::LINEAGE,
    #[cfg(feature = "exec")]
    &android::apksig::IDSIG,
    #[cfg(feature = "exec")]
    &android::apksig::SIGNING_BLOCK,
    #[cfg(feature = "system")]
    &forensics::minidump::FORMAT,
    #[cfg(feature = "exec")]
    &executable::ne::FORMAT,
    #[cfg(feature = "exec")]
    &executable::lx::FORMAT,
    #[cfg(feature = "exec")]
    &executable::omf::FORMAT,
    #[cfg(feature = "exec")]
    &executable::dcu::FORMAT,
    #[cfg(feature = "exec")]
    &bytecode::qvm::FORMAT,
    #[cfg(feature = "exec")]
    &executable::fatbin::FORMAT,
    #[cfg(feature = "exec")]
    &bytecode::elc::FORMAT,
    #[cfg(feature = "exec")]
    &bytecode::il2cpp::FORMAT,
    #[cfg(feature = "exec")]
    &bytecode::opcache::FORMAT,
    #[cfg(feature = "exec")]
    &bytecode::spirv::FORMAT,
    #[cfg(feature = "exec")]
    &bytecode::dxbc::FORMAT,
    #[cfg(feature = "exec")]
    &executable::te::FORMAT,
    #[cfg(feature = "exec")]
    &executable::xcoff::FORMAT,
    #[cfg(feature = "exec")]
    &executable::pef::FORMAT,
    #[cfg(feature = "exec")]
    &bytecode::ocaml::FORMAT,
    #[cfg(feature = "exec")]
    &bytecode::hermes::FORMAT,
    #[cfg(feature = "exec")]
    &bytecode::dart::FORMAT,
    #[cfg(feature = "exec")]
    &bytecode::yarb::FORMAT,
    #[cfg(feature = "exec")]
    &bytecode::pyc::FORMAT,
    #[cfg(feature = "exec")]
    &bytecode::lua::FORMAT,
    #[cfg(feature = "exec")]
    &bytecode::luajit::FORMAT,
    #[cfg(feature = "exec")]
    &bytecode::bitcode::FORMAT,
    #[cfg(feature = "exec")]
    &bytecode::beam::FORMAT,
    // Weaker probes (sizes and machine numbers rather than long magics).
    #[cfg(feature = "exec")]
    &executable::coff::FORMAT,
    #[cfg(feature = "exec")]
    &executable::coff::IMPORT,
    #[cfg(feature = "exec")]
    &executable::aout::PLAN9,
    #[cfg(feature = "exec")]
    &executable::aout::FORMAT,
    // -- end executables --

    // -- images --
    #[cfg(feature = "image")]
    &image::png::FORMAT,
    #[cfg(feature = "image")]
    &image::png::MNG,
    #[cfg(feature = "image")]
    &image::png::JNG,
    #[cfg(feature = "image")]
    &image::bmp::FORMAT,
    #[cfg(feature = "image")]
    &image::gif::FORMAT,
    #[cfg(feature = "image")]
    &image::jpeg::FORMAT,
    #[cfg(feature = "image")]
    &image::psd::FORMAT,
    #[cfg(feature = "image")]
    &image::psd::IRB,
    #[cfg(feature = "image")]
    &image::bmp::DIB,
    #[cfg(feature = "image")]
    &image::iptc::FORMAT,
    #[cfg(feature = "image")]
    &image::jpeg::JUMBF,
    #[cfg(feature = "image")]
    &image::ico::ICO,
    #[cfg(feature = "image")]
    &image::ico::CUR,
    #[cfg(feature = "image")]
    &image::qoi::FORMAT,
    #[cfg(feature = "image")]
    &image::dds::FORMAT,
    #[cfg(feature = "image")]
    &image::ktx::KTX,
    #[cfg(feature = "image")]
    &image::ktx::KTX2,
    #[cfg(feature = "image")]
    &image::exr::FORMAT,
    #[cfg(feature = "image")]
    &image::xcf::FORMAT,
    #[cfg(feature = "image")]
    &image::icns::FORMAT,
    #[cfg(feature = "image")]
    &image::j2k::FORMAT,
    #[cfg(feature = "image")]
    &image::jxl::FORMAT,
    #[cfg(feature = "image")]
    &image::pcx::DCX,
    #[cfg(feature = "image")]
    &image::farbfeld::FORMAT,
    #[cfg(feature = "image")]
    &image::sunras::FORMAT,
    #[cfg(feature = "image")]
    &image::sgi::FORMAT,
    #[cfg(feature = "image")]
    &image::hdr::FORMAT,
    #[cfg(feature = "image")]
    &image::xbm::XPM,
    #[cfg(feature = "image")]
    &image::xbm::XBM,
    #[cfg(feature = "image")]
    &image::pnm::PBM,
    #[cfg(feature = "image")]
    &image::pnm::PGM,
    #[cfg(feature = "image")]
    &image::pnm::PPM,
    #[cfg(feature = "image")]
    &image::pnm::PAM,
    #[cfg(feature = "image")]
    &image::pnm::PFM,
    // TIFF-based camera raw formats before plain TIFF.
    #[cfg(feature = "image")]
    &image::tiff::DNG,
    #[cfg(feature = "image")]
    &image::tiff::CR2,
    #[cfg(feature = "image")]
    &image::tiff::NEF,
    #[cfg(feature = "image")]
    &image::tiff::ARW,
    #[cfg(feature = "image")]
    &image::tiff::PEF,
    #[cfg(feature = "image")]
    &image::tiff::SRW,
    #[cfg(feature = "image")]
    &image::tiff::ORF,
    #[cfg(feature = "image")]
    &image::tiff::RW2,
    #[cfg(feature = "image")]
    &image::raw::RAF,
    #[cfg(feature = "image")]
    &image::raw::MRW,
    #[cfg(feature = "image")]
    &image::crw::FORMAT,
    #[cfg(feature = "image")]
    &image::jbig2::FORMAT,
    &image::jbig2::EMBEDDED,
    #[cfg(feature = "image")]
    &image::tiff::FORMAT,
    // Weak probes (footer, header sanity checks) last.
    #[cfg(feature = "image")]
    &image::xwd::FORMAT,
    #[cfg(feature = "image")]
    &image::tga::FORMAT,
    #[cfg(feature = "image")]
    &image::pcx::FORMAT,
    #[cfg(feature = "image")]
    &image::wbmp::FORMAT,
    // -- end images --

    // -- audio & video --
    // audio (riff/iff/flac/mp3/ogg/...)
    #[cfg(feature = "av")]
    &iff::WAV,
    #[cfg(feature = "av")]
    &iff::AVI,
    #[cfg(feature = "av")]
    &iff::WEBP,
    #[cfg(feature = "av")]
    &iff::ANI,
    #[cfg(feature = "av")]
    &iff::RMI,
    #[cfg(feature = "av")]
    &iff::DLS,
    #[cfg(feature = "av")]
    &iff::SF2,
    #[cfg(feature = "av")]
    &iff::XWMA,
    #[cfg(feature = "av")]
    &iff::CDXA,
    #[cfg(feature = "av")]
    &iff::RIFF_PALETTE,
    #[cfg(feature = "av")]
    &iff::RDIB,
    #[cfg(feature = "av")]
    &iff::RMMP,
    #[cfg(feature = "av")]
    &iff::QCP,
    #[cfg(feature = "av")]
    &iff::CDR,
    #[cfg(feature = "av")]
    &iff::FOURXM,
    #[cfg(feature = "av")]
    &iff::AMV,
    #[cfg(feature = "av")]
    &iff::AIFF,
    #[cfg(feature = "av")]
    &iff::AIFC,
    #[cfg(feature = "av")]
    &iff::SVX8,
    #[cfg(feature = "av")]
    &iff::SVX16,
    #[cfg(feature = "av")]
    &iff::ILBM,
    #[cfg(feature = "av")]
    &iff::ANIM,
    #[cfg(feature = "av")]
    &iff::SMUS,
    #[cfg(feature = "av")]
    &iff::FTXT,
    #[cfg(feature = "av")]
    &iff::MAUD,
    // RIFF/RIFX forms from the publishing family, before generic RIFF.
    #[cfg(feature = "docs")]
    &publishing::authoring::DIRECTOR,
    #[cfg(feature = "docs")]
    &publishing::authoring::AEP,
    #[cfg(feature = "docs")]
    &publishing::authoring::CMX,
    #[cfg(feature = "av")]
    &iff::RIFF,
    // IFF-shaped formats with their own dissectors, before generic IFF.
    #[cfg(feature = "av")]
    &audio::production::REX2,
    #[cfg(feature = "av")]
    &iff::IFF,
    #[cfg(feature = "av")]
    &audio::midi::FORMAT,
    #[cfg(feature = "av")]
    &audio::au::FORMAT,
    #[cfg(feature = "av")]
    &audio::voc::FORMAT,
    #[cfg(feature = "av")]
    &audio::caf::FORMAT,
    #[cfg(feature = "av")]
    &audio::amr::FORMAT,
    #[cfg(feature = "av")]
    &audio::w64::FORMAT,
    #[cfg(feature = "av")]
    &audio::ape::FORMAT,
    #[cfg(feature = "av")]
    &audio::wavpack::FORMAT,
    #[cfg(feature = "av")]
    &audio::musepack::FORMAT,
    #[cfg(feature = "av")]
    &audio::tta::FORMAT,
    #[cfg(feature = "av")]
    &audio::lossless::TAK,
    #[cfg(feature = "av")]
    &audio::lossless::OFR,
    #[cfg(feature = "av")]
    &audio::lossless::SHORTEN,
    #[cfg(feature = "av")]
    &audio::dsd::DSF,
    #[cfg(feature = "av")]
    &audio::dsd::DFF,
    #[cfg(feature = "av")]
    &audio::smaf::FORMAT,
    #[cfg(feature = "av")]
    &audio::simple_audio::SOX,
    #[cfg(feature = "av")]
    &audio::simple_audio::IRCAM,
    #[cfg(feature = "av")]
    &audio::simple_audio::ADX,
    #[cfg(feature = "av")]
    &audio::simple_audio::KVAG,
    #[cfg(feature = "av")]
    &audio::simple_audio::AST,
    #[cfg(feature = "av")]
    &audio::simple_audio::ILBC,
    #[cfg(feature = "av")]
    &audio::simple_audio::QOA,
    #[cfg(feature = "av")]
    &tracker::it::FORMAT,
    #[cfg(feature = "av")]
    &tracker::xm::FORMAT,
    #[cfg(feature = "av")]
    &tracker::s3m::FORMAT,
    #[cfg(feature = "av")]
    &tracker::more::MTM,
    #[cfg(feature = "av")]
    &tracker::more::STM,
    #[cfg(feature = "av")]
    &tracker::more::ULT,
    #[cfg(feature = "av")]
    &tracker::more::MED,
    #[cfg(feature = "av")]
    &tracker::more::OKT,
    #[cfg(feature = "av")]
    &tracker::protracker::FORMAT,
    #[cfg(feature = "av")]
    &tracker::more::COMPOSER669,
    #[cfg(feature = "av")]
    &audio::simple_audio::RSO,
    #[cfg(feature = "av")]
    &audio::flac::FORMAT,
    #[cfg(feature = "av")]
    &audio::ogg::OPUS,
    #[cfg(feature = "av")]
    &audio::ogg::OGG_FLAC,
    #[cfg(feature = "av")]
    &audio::ogg::SPEEX,
    #[cfg(feature = "av")]
    &audio::ogg::THEORA,
    #[cfg(feature = "av")]
    &audio::ogg::FORMAT,
    #[cfg(feature = "av")]
    &audio::adts::FORMAT,
    #[cfg(feature = "av")]
    &audio::ac3::FORMAT,
    #[cfg(feature = "av")]
    &audio::dts::FORMAT,
    #[cfg(feature = "av")]
    &audio::mpa::FORMAT,
    #[cfg(feature = "av")]
    &audio::id3::FORMAT,
    // video & containers (isobmff/matroska/ts/...)
    #[cfg(feature = "av")]
    &isobmff::CR3,
    #[cfg(feature = "av")]
    &isobmff::HEIF,
    #[cfg(feature = "av")]
    &isobmff::AVIF,
    #[cfg(feature = "av")]
    &isobmff::JP2,
    #[cfg(feature = "av")]
    &isobmff::JPX,
    #[cfg(feature = "av")]
    &isobmff::MJ2,
    #[cfg(feature = "av")]
    &isobmff::THREE_GP,
    #[cfg(feature = "av")]
    &isobmff::THREE_G2,
    #[cfg(feature = "av")]
    &isobmff::M4A,
    #[cfg(feature = "av")]
    &isobmff::M4V,
    #[cfg(feature = "av")]
    &isobmff::MOV,
    #[cfg(feature = "av")]
    &isobmff::MP4,
    #[cfg(feature = "av")]
    &video::matroska::WEBM,
    #[cfg(feature = "av")]
    &video::matroska::MKV,
    #[cfg(feature = "av")]
    &video::flv::FORMAT,
    #[cfg(feature = "av")]
    &mpeg::ts::M2TS,
    #[cfg(feature = "av")]
    &mpeg::ts::FORMAT,
    #[cfg(feature = "av")]
    &mpeg::ps::MPEG2_PS,
    #[cfg(feature = "av")]
    &mpeg::ps::MPEG1_SYSTEM,
    #[cfg(feature = "av")]
    &mpeg::video::MPEG2_VIDEO,
    #[cfg(feature = "av")]
    &mpeg::video::MPEG1_VIDEO,
    #[cfg(feature = "av")]
    &mpeg::mpeg4::FORMAT,
    #[cfg(feature = "av")]
    &video::annexb::HEVC,
    #[cfg(feature = "av")]
    &video::annexb::H264,
    #[cfg(feature = "av")]
    &video::ivf::FORMAT,
    #[cfg(feature = "av")]
    &video::ivf::OBU,
    #[cfg(feature = "av")]
    &video::y4m::FORMAT,
    #[cfg(feature = "av")]
    &video::asf::WMV,
    #[cfg(feature = "av")]
    &video::asf::WMA,
    #[cfg(feature = "av")]
    &video::asf::ASF,
    #[cfg(feature = "av")]
    &video::realmedia::FORMAT,
    #[cfg(feature = "av")]
    &video::rad::BINK,
    #[cfg(feature = "av")]
    &video::rad::SMACKER,
    #[cfg(feature = "av")]
    &video::mxf::FORMAT,
    #[cfg(feature = "av")]
    &video::swf::FORMAT,
    #[cfg(feature = "av")]
    &video::gamevideo::ROQ,
    #[cfg(feature = "av")]
    &video::gamevideo::FILM,
    #[cfg(feature = "av")]
    &video::gamevideo::SMJPEG,
    #[cfg(feature = "av")]
    &video::gamevideo::FLIC,
    #[cfg(feature = "av")]
    &video::gamevideo::MVE,
    #[cfg(feature = "av")]
    &video::gamevideo::THP,
    #[cfg(feature = "av")]
    &video::rawvideo::DIRAC,
    #[cfg(feature = "av")]
    &video::rawvideo::DNXHD,
    #[cfg(feature = "av")]
    &video::rawvideo::H263,
    // -- end audio & video --

    // -- documents & data --
    // data, system artifacts, fonts
    #[cfg(feature = "data")]
    &data::bplist::FORMAT,
    #[cfg(feature = "data")]
    &data::bencode::FORMAT,
    #[cfg(feature = "data")]
    &data::cbor::FORMAT,
    #[cfg(feature = "data")]
    &data::smile::FORMAT,
    #[cfg(feature = "data")]
    &data::ion::FORMAT,
    #[cfg(feature = "data")]
    &data::ion::TEXT,
    #[cfg(feature = "security")]
    &pcap::FORMAT,
    #[cfg(feature = "security")]
    &pcap::ng::FORMAT,
    #[cfg(feature = "system")]
    &forensics::lnk::FORMAT,
    #[cfg(feature = "system")]
    &forensics::regf::FORMAT,
    #[cfg(feature = "system")]
    &forensics::evtx::FORMAT,
    #[cfg(feature = "system")]
    &forensics::evt::FORMAT,
    #[cfg(feature = "system")]
    &forensics::etl::FORMAT,
    #[cfg(feature = "system")]
    &forensics::prefetch::FORMAT,
    #[cfg(feature = "system")]
    &forensics::recyclebin::FORMAT,
    #[cfg(feature = "system")]
    &forensics::thumbcache::FORMAT,
    #[cfg(feature = "system")]
    &forensics::thumbcache::INDEX,
    #[cfg(feature = "image")]
    &image::icc_profile::FORMAT,
    #[cfg(feature = "image")]
    &font::SFNT,
    #[cfg(feature = "image")]
    &font::TTC,
    #[cfg(feature = "image")]
    &font::woff::WOFF,
    #[cfg(feature = "image")]
    &font::woff::WOFF2,
    #[cfg(feature = "image")]
    &font::eot::FORMAT,
    #[cfg(feature = "image")]
    &font::pfb::FORMAT,
    #[cfg(feature = "image")]
    &font::bitmap::PCF,
    #[cfg(feature = "image")]
    &font::bitmap::BDF,
    #[cfg(feature = "system")]
    &system::mo::FORMAT,
    #[cfg(feature = "system")]
    &system::terminfo::FORMAT,
    #[cfg(feature = "data")]
    &data::npy::NPY,
    #[cfg(feature = "data")]
    &data::npy::SAFETENSORS,
    #[cfg(feature = "archive")]
    &archive::crx::CRX,
    #[cfg(feature = "archive")]
    &archive::crx::MOZLZ4,
    #[cfg(feature = "archive")]
    &archive::applesingle::APPLESINGLE,
    #[cfg(feature = "archive")]
    &archive::applesingle::APPLEDOUBLE,
    #[cfg(feature = "system")]
    &ml::gguf::FORMAT,
    #[cfg(feature = "data")]
    &data::pickle::FORMAT,
    #[cfg(feature = "system")]
    &system::git::PACK,
    #[cfg(feature = "system")]
    &system::git::PACK_INDEX,
    #[cfg(feature = "system")]
    &system::git::INDEX,
    #[cfg(feature = "docs")]
    &documents::chm::FORMAT,
    #[cfg(feature = "docs")]
    &documents::winhelp::FORMAT,
    #[cfg(feature = "system")]
    &forensics::dsstore::FORMAT,
    #[cfg(feature = "system")]
    &forensics::bookmark::FORMAT,
    // graph-shaped: sqlite/cfb/pdf/asn1/pgp/...
    #[cfg(feature = "data")]
    &sqlite::GEOPACKAGE,
    #[cfg(feature = "data")]
    &sqlite::MBTILES,
    #[cfg(feature = "data")]
    &sqlite::FORMAT,
    #[cfg(feature = "data")]
    &sqlite::WAL,
    #[cfg(feature = "data")]
    &sqlite::JOURNAL,
    #[cfg(feature = "docs")]
    &cfb::DOC,
    #[cfg(feature = "docs")]
    &cfb::XLS,
    #[cfg(feature = "docs")]
    &cfb::PPT,
    #[cfg(feature = "docs")]
    &cfb::MSG,
    #[cfg(feature = "docs")]
    &cfb::MSI,
    #[cfg(feature = "docs")]
    &cfb::THUMBS,
    #[cfg(feature = "docs")]
    &cfb::PUBLISHER,
    #[cfg(feature = "docs")]
    &cfb::FORMAT,
    #[cfg(feature = "docs")]
    &pdf::FORMAT,
    #[cfg(feature = "security")]
    &asn1::X509,
    #[cfg(feature = "security")]
    &asn1::CRL,
    #[cfg(feature = "security")]
    &asn1::CSR,
    #[cfg(feature = "security")]
    &asn1::PKCS7,
    #[cfg(feature = "security")]
    &asn1::PKCS12,
    #[cfg(feature = "security")]
    &asn1::PKCS8_ENCRYPTED,
    #[cfg(feature = "security")]
    &asn1::DER,
    #[cfg(feature = "security")]
    &security::pgp::FORMAT,
    #[cfg(feature = "security")]
    &security::pgp::ARMOR,
    #[cfg(feature = "security")]
    &security::pem::FORMAT,
    #[cfg(feature = "data")]
    &data::avro::FORMAT,
    #[cfg(feature = "data")]
    &data::netcdf::FORMAT,
    #[cfg(feature = "data")]
    &data::hdf5::MAT73,
    #[cfg(feature = "data")]
    &data::hdf5::FORMAT,
    #[cfg(feature = "data")]
    &data::matlab::FORMAT,
    #[cfg(feature = "data")]
    &data::parquet::FORMAT,
    #[cfg(feature = "data")]
    &data::orc::FORMAT,
    #[cfg(feature = "data")]
    &data::sst::LEVELDB,
    #[cfg(feature = "data")]
    &data::sst::ROCKSDB,
    #[cfg(feature = "data")]
    &data::bdb::FORMAT,
    #[cfg(feature = "data")]
    &data::jet::MDB,
    #[cfg(feature = "data")]
    &data::jet::ACCDB,
    #[cfg(feature = "data")]
    &data::arrow::FORMAT,
    #[cfg(feature = "data")]
    &data::arrow::STREAM,
    // Schemaless wire encodings: by extension or "inspect as" only.
    #[cfg(feature = "data")]
    &data::wire::protobuf::FORMAT,
    #[cfg(feature = "data")]
    &data::wire::thrift::BINARY,
    #[cfg(feature = "data")]
    &data::wire::thrift::COMPACT,
    #[cfg(feature = "data")]
    &data::wire::flatbuffers::FORMAT,
    #[cfg(feature = "data")]
    &data::wire::capnp::PACKED,
    // -- end documents --

    // -- disk images & filesystems --
    // Virtual disk containers first: their payload may start with an MBR.
    #[cfg(feature = "archive")]
    &disk::vhd::FORMAT,
    #[cfg(feature = "archive")]
    &disk::vhdx::FORMAT,
    #[cfg(feature = "archive")]
    &disk::qcow::FORMAT,
    #[cfg(feature = "archive")]
    &disk::vmdk::FORMAT,
    #[cfg(feature = "archive")]
    &disk::vmdk::DESCRIPTOR,
    #[cfg(feature = "archive")]
    &disk::vdi::FORMAT,
    #[cfg(feature = "archive")]
    &disk::parallels::FORMAT,
    // Partition tables and volumes with distinctive signatures.
    #[cfg(feature = "archive")]
    &disk::gpt::FORMAT,
    #[cfg(feature = "archive")]
    &disk::bitlocker::FORMAT,
    #[cfg(feature = "archive")]
    &disk::luks::FORMAT,
    #[cfg(feature = "archive")]
    &disk::lvm::FORMAT,
    #[cfg(feature = "archive")]
    &disk::mdraid::FORMAT,
    #[cfg(feature = "archive")]
    &disk::swap::FORMAT,
    #[cfg(feature = "archive")]
    &disk::xfs::FORMAT,
    #[cfg(feature = "archive")]
    &disk::apm::FORMAT,
    #[cfg(feature = "archive")]
    &disk::uefi::FORMAT,
    #[cfg(feature = "archive")]
    &disk::zfs::FORMAT,
    #[cfg(feature = "archive")]
    &disk::hfs::FORMAT,
    #[cfg(feature = "archive")]
    &disk::apfs::FORMAT,
    #[cfg(feature = "archive")]
    &disk::ext::FORMAT,
    #[cfg(feature = "archive")]
    &disk::minix::FORMAT,
    #[cfg(feature = "archive")]
    &disk::bfs::FORMAT,
    #[cfg(feature = "archive")]
    &disk::f2fs::FORMAT,
    #[cfg(feature = "archive")]
    &disk::erofs::FORMAT,
    #[cfg(feature = "archive")]
    &disk::jfs::FORMAT,
    #[cfg(feature = "archive")]
    &disk::nilfs::FORMAT,
    #[cfg(feature = "archive")]
    &disk::ufs::FORMAT,
    // Boot sectors ending in 0x55AA, before the plain MBR.
    #[cfg(feature = "archive")]
    &disk::ntfs::FORMAT,
    #[cfg(feature = "archive")]
    &disk::exfat::FORMAT,
    #[cfg(feature = "archive")]
    &disk::fat::FORMAT,
    #[cfg(feature = "archive")]
    &disk::mbr::FORMAT,
    #[cfg(feature = "archive")]
    &disk::bsdlabel::FORMAT,
    // Detected only if the probe window reaches 64 KiB.
    #[cfg(feature = "archive")]
    &disk::btrfs::FORMAT,
    // -- end disk images --

    // -- archives & compression --
    // BGZF (blocked gzip) members are gzip members; identify them first.
    #[cfg(feature = "science")]
    &science::bio::binary::BAM,
    #[cfg(feature = "science")]
    &science::bio::binary::BCF,
    #[cfg(feature = "science")]
    &science::bio::binary::VCF_BGZF,
    #[cfg(feature = "science")]
    &science::bio::binary::TABIX,
    #[cfg(feature = "science")]
    &science::bio::binary::CSI,
    #[cfg(feature = "science")]
    &science::bio::binary::BGZF,
    #[cfg(feature = "archive")]
    &compression::gzip::FORMAT,
    #[cfg(feature = "archive")]
    &disk::dmg::FORMAT,
    #[cfg(feature = "archive")]
    &archive::tar::FORMAT,
    #[cfg(feature = "archive")]
    &compression::bzip2::FORMAT,
    #[cfg(feature = "archive")]
    &compression::xz::FORMAT,
    #[cfg(feature = "archive")]
    &compression::lzma::LZIP,
    #[cfg(feature = "archive")]
    &compression::zstd::FORMAT,
    #[cfg(feature = "archive")]
    &compression::zstd::SKIPPABLE,
    #[cfg(feature = "archive")]
    &compression::lz4::FORMAT,
    #[cfg(feature = "archive")]
    &compression::lz4::LEGACY,
    #[cfg(feature = "archive")]
    &compression::lz4::SNAPPY,
    #[cfg(feature = "archive")]
    &compression::compress::COMPRESS,
    #[cfg(feature = "archive")]
    &compression::compress::PACK,
    #[cfg(feature = "archive")]
    &compression::szdd::SZDD,
    #[cfg(feature = "archive")]
    &compression::szdd::KWAJ,
    #[cfg(feature = "archive")]
    &archive::ar::DEB,
    #[cfg(feature = "archive")]
    &archive::ar::FORMAT,
    #[cfg(feature = "archive")]
    &archive::cpio::FORMAT,
    #[cfg(feature = "archive")]
    &archive::rpm::FORMAT,
    #[cfg(feature = "archive")]
    &archive::sevenzip::FORMAT,
    #[cfg(feature = "archive")]
    &archive::rar::FORMAT,
    #[cfg(feature = "archive")]
    &archive::cab::FORMAT,
    #[cfg(feature = "archive")]
    &archive::arj::FORMAT,
    #[cfg(feature = "archive")]
    &archive::xar::FORMAT,
    #[cfg(feature = "archive")]
    &disk::iso9660::FORMAT,
    #[cfg(feature = "archive")]
    &disk::iso9660::UDF,
    #[cfg(feature = "system")]
    &system::firmware::ANDROID_SPARSE,
    #[cfg(feature = "system")]
    &system::firmware::ANDROID_BOOT,
    #[cfg(feature = "system")]
    &system::firmware::UIMAGE,
    #[cfg(feature = "archive")]
    &disk::squashfs::SQUASHFS,
    #[cfg(feature = "archive")]
    &disk::squashfs::CRAMFS,
    #[cfg(feature = "archive")]
    &archive::wim::FORMAT,
    #[cfg(feature = "archive")]
    &archive::stuffit::FORMAT,
    #[cfg(feature = "archive")]
    &archive::stuffit::SIT5,
    #[cfg(feature = "archive")]
    &archive::zoo::FORMAT,
    #[cfg(feature = "archive")]
    &archive::ace::ACE,
    // ZIP-based formats before plain ZIP (more specific ones first).
    // (ml models & mobile platforms)
    #[cfg(feature = "archive")]
    &archive::zip::TORCHSCRIPT,
    #[cfg(feature = "archive")]
    &archive::zip::PYTORCH,
    #[cfg(feature = "archive")]
    &archive::zip::KERAS,
    #[cfg(feature = "archive")]
    &archive::zip::NPZ,
    #[cfg(feature = "archive")]
    &archive::zip::SIGROK,
    #[cfg(feature = "archive")]
    &archive::zip::APEX,
    #[cfg(feature = "archive")]
    &archive::zip::ANDROID_OTA,
    #[cfg(feature = "archive")]
    &archive::zip::ANDROID_DM,
    #[cfg(feature = "archive")]
    &archive::zip::BUGREPORT,
    #[cfg(feature = "archive")]
    &archive::zip::IPSW,
    // (end ml)
    #[cfg(feature = "archive")]
    &archive::zip::AAR,
    #[cfg(feature = "archive")]
    &archive::zip::XLSB,
    #[cfg(feature = "archive")]
    &archive::zip::SNUPKG,
    #[cfg(feature = "archive")]
    &archive::zip::EPUB,
    #[cfg(feature = "archive")]
    &archive::zip::ODT,
    #[cfg(feature = "archive")]
    &archive::zip::ODS,
    #[cfg(feature = "archive")]
    &archive::zip::ODP,
    #[cfg(feature = "archive")]
    &archive::zip::ODG,
    #[cfg(feature = "archive")]
    &archive::zip::DOCX,
    #[cfg(feature = "archive")]
    &archive::zip::XLSX,
    #[cfg(feature = "archive")]
    &archive::zip::PPTX,
    #[cfg(feature = "archive")]
    &archive::zip::VSDX,
    #[cfg(feature = "archive")]
    &archive::zip::XPS,
    #[cfg(feature = "archive")]
    &archive::zip::APK,
    #[cfg(feature = "archive")]
    &archive::zip::XPI,
    #[cfg(feature = "archive")]
    &archive::zip::NUPKG,
    #[cfg(feature = "archive")]
    &archive::zip::VSIX,
    #[cfg(feature = "archive")]
    &archive::zip::WHL,
    #[cfg(feature = "archive")]
    &archive::zip::IPA,
    #[cfg(feature = "archive")]
    &archive::zip::KMZ,
    #[cfg(feature = "archive")]
    &archive::zip::THREE_MF,
    #[cfg(feature = "archive")]
    &archive::zip::SKETCH,
    #[cfg(feature = "archive")]
    &archive::zip::USDZ,
    #[cfg(feature = "archive")]
    &archive::zip::KRITA,
    #[cfg(feature = "archive")]
    &archive::zip::ORA,
    #[cfg(feature = "archive")]
    &archive::zip::IDML,
    #[cfg(feature = "archive")]
    &archive::zip::ODF_FORMULA,
    #[cfg(feature = "archive")]
    &archive::zip::ODB,
    #[cfg(feature = "archive")]
    &archive::zip::IWORK,
    #[cfg(feature = "archive")]
    &archive::zip::APPX,
    #[cfg(feature = "archive")]
    &archive::zip::XAP,
    #[cfg(feature = "archive")]
    &archive::zip::FBZ,
    #[cfg(feature = "archive")]
    &archive::zip::CBZ,
    #[cfg(feature = "archive")]
    &archive::zip::GEOGEBRA,
    #[cfg(feature = "archive")]
    &archive::zip::DWFX,
    #[cfg(feature = "archive")]
    &archive::zip::ADOBE_XD,
    #[cfg(feature = "archive")]
    &archive::zip::PROCREATE,
    #[cfg(feature = "archive")]
    &archive::zip::XFL,
    #[cfg(feature = "archive")]
    &archive::zip::SXW,
    #[cfg(feature = "archive")]
    &archive::zip::SXC,
    #[cfg(feature = "archive")]
    &archive::zip::SXI,
    #[cfg(feature = "archive")]
    &archive::zip::SXD,
    #[cfg(feature = "archive")]
    &archive::zip::SXM,
    #[cfg(feature = "archive")]
    &archive::zip::CDR_ZIP,
    #[cfg(feature = "archive")]
    &archive::zip::IWORK09,
    #[cfg(feature = "archive")]
    &archive::zip::MCPACK,
    #[cfg(feature = "archive")]
    &archive::zip::SCRATCH,
    #[cfg(feature = "archive")]
    &archive::zip::JAR,
    #[cfg(feature = "archive")]
    &archive::zip::FORMAT,
    // Weak probes last.
    #[cfg(feature = "archive")]
    &archive::tar::V7,
    #[cfg(feature = "archive")]
    &archive::lha::FORMAT,
    #[cfg(feature = "archive")]
    &archive::ace::ARC,
    #[cfg(feature = "archive")]
    &compression::lzma::LZMA,
    #[cfg(feature = "system")]
    &system::hexfile::IHEX,
    #[cfg(feature = "system")]
    &system::hexfile::SREC,
    // -- end archives --

    // -- retro & consoles --
    #[cfg(feature = "games")]
    &retro::consoles::NES,
    #[cfg(feature = "games")]
    &retro::consoles::FDS,
    // GBX footers wrap Game Boy ROMs.
    #[cfg(feature = "games")]
    &retro::extras::GBX,
    #[cfg(feature = "games")]
    &retro::consoles::GBC,
    #[cfg(feature = "games")]
    &retro::consoles::GB,
    #[cfg(feature = "games")]
    &retro::consoles::GBA,
    #[cfg(feature = "games")]
    &retro::consoles::NDS,
    #[cfg(feature = "games")]
    &retro::consoles::N64,
    // Sega disc system areas carry a Mega Drive style header at 0x100.
    #[cfg(feature = "games")]
    &retro::discs::SEGA_CD,
    #[cfg(feature = "games")]
    &retro::discs::SATURN,
    #[cfg(feature = "games")]
    &retro::discs::DREAMCAST,
    #[cfg(feature = "games")]
    &retro::consoles::GENESIS,
    #[cfg(feature = "games")]
    &retro::consoles::PSX_EXE,
    #[cfg(feature = "games")]
    &retro::consoles::PBP,
    #[cfg(feature = "games")]
    &retro::consoles::SFO,
    #[cfg(feature = "games")]
    &retro::consoles::XBE,
    #[cfg(feature = "games")]
    &retro::consoles::WII,
    #[cfg(feature = "games")]
    &retro::consoles::GAMECUBE,
    #[cfg(feature = "games")]
    &retro::consoles::NRO,
    #[cfg(feature = "games")]
    &retro::consoles::NSO,
    #[cfg(feature = "games")]
    &retro::consoles::THREEDSX,
    #[cfg(feature = "games")]
    &retro::consoles::NCSD,
    #[cfg(feature = "games")]
    &retro::consoles::NCCH,
    #[cfg(feature = "games")]
    &retro::consoles::LYNX,
    #[cfg(feature = "games")]
    &retro::consoles::A7800,
    #[cfg(feature = "games")]
    &retro::consoles::SNES,
    #[cfg(feature = "games")]
    &retro::music::NSF,
    #[cfg(feature = "games")]
    &retro::music::NSFE,
    #[cfg(feature = "games")]
    &retro::music::GBS,
    #[cfg(feature = "games")]
    &retro::music::SPC,
    #[cfg(feature = "games")]
    &retro::music::VGM,
    #[cfg(feature = "games")]
    &retro::music::PSF,
    #[cfg(feature = "games")]
    &retro::music::SID,
    #[cfg(feature = "games")]
    &retro::music::HES,
    #[cfg(feature = "games")]
    &retro::music::KSS,
    #[cfg(feature = "games")]
    &retro::music::AY,
    #[cfg(feature = "games")]
    &retro::music::SAP,
    #[cfg(feature = "games")]
    &retro::music::YM,
    #[cfg(feature = "games")]
    &retro::computers::T64,
    #[cfg(feature = "games")]
    &retro::computers::CRT,
    #[cfg(feature = "games")]
    &retro::computers::AMIGA_HUNK,
    #[cfg(feature = "games")]
    &retro::computers::TZX,
    #[cfg(feature = "games")]
    &retro::computers::CPC_DSK,
    #[cfg(feature = "games")]
    &retro::computers::MSA,
    #[cfg(feature = "games")]
    &retro::computers::ATR,
    #[cfg(feature = "games")]
    &retro::computers::WOZ,
    #[cfg(feature = "games")]
    &retro::computers::TWO_IMG,
    #[cfg(feature = "games")]
    &retro::computers::UEF,
    #[cfg(feature = "games")]
    &retro::computers::ADF,
    #[cfg(feature = "games")]
    &retro::computers::D64,
    #[cfg(feature = "games")]
    &retro::patches::IPS,
    #[cfg(feature = "games")]
    &retro::patches::IPS32,
    #[cfg(feature = "games")]
    &retro::patches::UPS,
    #[cfg(feature = "games")]
    &retro::patches::BPS,
    #[cfg(feature = "games")]
    &retro::patches::VCDIFF,
    #[cfg(feature = "games")]
    &retro::patches::BSDIFF,
    #[cfg(feature = "games")]
    &retro::patches::BSDIFF43,
    #[cfg(feature = "games")]
    &retro::patches::PPF,
    #[cfg(feature = "games")]
    &retro::patches::APS_N64,
    #[cfg(feature = "games")]
    &retro::patches::APS_GBA,
    #[cfg(feature = "games")]
    &retro::patches::GDIFF,
    #[cfg(feature = "games")]
    &retro::patches::MSDELTA,
    #[cfg(feature = "games")]
    &retro::patches::RUP,
    #[cfg(feature = "games")]
    &retro::discs::CHD,
    #[cfg(feature = "games")]
    &retro::discs::MDS,
    #[cfg(feature = "games")]
    &retro::discs::CCD,
    #[cfg(feature = "games")]
    &retro::discs::ECM,
    #[cfg(feature = "games")]
    &retro::discs::CSO,
    #[cfg(feature = "games")]
    &retro::discs::DAX,
    #[cfg(feature = "games")]
    &retro::discs::ISZ,
    #[cfg(feature = "games")]
    &retro::discs::DAA,
    #[cfg(feature = "games")]
    &retro::discs::WBFS,
    #[cfg(feature = "games")]
    &retro::discs::GCZ,
    #[cfg(feature = "games")]
    &retro::discs::WIA,
    #[cfg(feature = "games")]
    &retro::discs::RVZ,
    #[cfg(feature = "games")]
    &retro::discs::TGC,
    #[cfg(feature = "games")]
    &retro::discs::WII_CISO,
    #[cfg(feature = "games")]
    &retro::discs::OPERA,
    #[cfg(feature = "games")]
    &retro::cartridges::GAME_GEAR,
    #[cfg(feature = "games")]
    &retro::cartridges::SMS,
    #[cfg(feature = "games")]
    &retro::cartridges::SMD,
    #[cfg(feature = "games")]
    &retro::cartridges::NGPC,
    #[cfg(feature = "games")]
    &retro::cartridges::NGP,
    #[cfg(feature = "games")]
    &retro::cartridges::POKEMON_MINI,
    #[cfg(feature = "games")]
    &retro::cartridges::NEO_GEO,
    #[cfg(feature = "games")]
    &retro::cartridges::UNIF,
    #[cfg(feature = "games")]
    &retro::cartridges::VECTREX,
    #[cfg(feature = "games")]
    &retro::states::ZSNES,
    #[cfg(feature = "games")]
    &retro::states::SNES9X,
    #[cfg(feature = "games")]
    &retro::states::FCEUX,
    #[cfg(feature = "games")]
    &retro::states::RETROARCH,
    #[cfg(feature = "games")]
    &retro::states::DTM,
    #[cfg(feature = "games")]
    &retro::states::SMV,
    #[cfg(feature = "games")]
    &retro::states::VBM,
    #[cfg(feature = "games")]
    &retro::states::FCM,
    #[cfg(feature = "games")]
    &retro::states::M64,
    #[cfg(feature = "games")]
    &retro::states::GMV,
    #[cfg(feature = "games")]
    &retro::states::DEXDRIVE,
    #[cfg(feature = "games")]
    &retro::states::PS2_MEMCARD,
    #[cfg(feature = "games")]
    &retro::states::PSX_MEMCARD,
    #[cfg(feature = "games")]
    &retro::trackers::FAMITRACKER,
    #[cfg(feature = "games")]
    &retro::trackers::FURNACE,
    #[cfg(feature = "games")]
    &retro::trackers::DEFLEMASK,
    #[cfg(feature = "games")]
    &retro::trackers::S98,
    #[cfg(feature = "games")]
    &retro::trackers::GYM,
    #[cfg(feature = "games")]
    &retro::trackers::ORGANYA,
    #[cfg(feature = "games")]
    &retro::trackers::GOATTRACKER,
    #[cfg(feature = "games")]
    &retro::trackers::SNDH,
    #[cfg(feature = "games")]
    &retro::trackers::PT3,
    #[cfg(feature = "games")]
    &retro::trackers::PSG,
    #[cfg(feature = "games")]
    &retro::tapes::PZX,
    #[cfg(feature = "games")]
    &retro::tapes::CSW,
    #[cfg(feature = "games")]
    &retro::tapes::C64_TAP,
    #[cfg(feature = "games")]
    &retro::tapes::G64,
    #[cfg(feature = "games")]
    &retro::tapes::P00,
    #[cfg(feature = "games")]
    &retro::tapes::SCL,
    #[cfg(feature = "games")]
    &retro::tapes::MSX_CAS,
    #[cfg(feature = "games")]
    &retro::tapes::ATARI_CAR,
    #[cfg(feature = "games")]
    &retro::floppies::HFE,
    #[cfg(feature = "games")]
    &retro::floppies::IPF,
    #[cfg(feature = "games")]
    &retro::floppies::STX,
    #[cfg(feature = "games")]
    &retro::floppies::IMD,
    #[cfg(feature = "games")]
    &retro::floppies::TD0,
    #[cfg(feature = "games")]
    &retro::floppies::A2R,
    #[cfg(feature = "games")]
    &retro::floppies::MOOF,
    #[cfg(feature = "games")]
    &retro::floppies::AMIGA_RDB,
    #[cfg(feature = "games")]
    &retro::systems::SMDH,
    #[cfg(feature = "games")]
    &retro::systems::FIRM,
    #[cfg(feature = "games")]
    &retro::systems::KIP1,
    #[cfg(feature = "games")]
    &retro::systems::INI1,
    #[cfg(feature = "games")]
    &retro::systems::STFS,
    #[cfg(feature = "games")]
    &retro::systems::XISO,
    #[cfg(feature = "games")]
    &retro::micros::CPC_SNA,
    #[cfg(feature = "games")]
    &retro::micros::SZX,
    #[cfg(feature = "games")]
    &retro::micros::RZX,
    #[cfg(feature = "games")]
    &retro::micros::NIB,
    #[cfg(feature = "games")]
    &retro::micros::VICE,
    #[cfg(feature = "games")]
    &retro::micros::ATARI_CAS,
    #[cfg(feature = "games")]
    &retro::micros::ATX,
    #[cfg(feature = "games")]
    &retro::micros::NUFX_ARCHIVE,
    #[cfg(feature = "games")]
    &retro::micros::BINHEX,
    #[cfg(feature = "games")]
    &retro::console_packages::WUX,
    #[cfg(feature = "games")]
    &retro::console_packages::NCZ,
    #[cfg(feature = "games")]
    &retro::console_packages::NPDM,
    #[cfg(feature = "games")]
    &retro::console_packages::PS3_PUP,
    #[cfg(feature = "games")]
    &retro::console_packages::PS4_PKG,
    #[cfg(feature = "games")]
    &retro::console_packages::PSP_PRX,
    #[cfg(feature = "games")]
    &retro::console_packages::SHARKPORT,
    #[cfg(feature = "games")]
    &retro::console_packages::MAME_INP,
    #[cfg(feature = "games")]
    &retro::console_packages::MAME_STATE,
    #[cfg(feature = "games")]
    &retro::graphics::KICKSTART,
    #[cfg(feature = "games")]
    &retro::graphics::AMIGA_INFO,
    #[cfg(feature = "games")]
    &retro::extras::DSV,
    #[cfg(feature = "games")]
    &retro::extras::GC_BANNER,
    #[cfg(feature = "games")]
    &retro::extras::WII_BANNER,
    #[cfg(feature = "games")]
    &retro::extras::TPL,
    #[cfg(feature = "games")]
    &retro::extras::CEL_3DO,
    #[cfg(feature = "games")]
    &retro::extras::HXC_MFM,
    #[cfg(feature = "games")]
    &retro::extras::FDI,
    // Weak probes: trailers and text.
    #[cfg(feature = "games")]
    &retro::discs::NRG,
    #[cfg(feature = "games")]
    &retro::discs::CDI,
    #[cfg(feature = "games")]
    &retro::discs::GDI,
    #[cfg(feature = "games")]
    &retro::cartridges::INTELLIVISION,
    #[cfg(feature = "games")]
    &retro::cartridges::COLECOVISION,
    #[cfg(feature = "games")]
    &retro::cartridges::MSX_ROM,
    #[cfg(feature = "games")]
    &retro::cartridges::WONDERSWAN_COLOR,
    #[cfg(feature = "games")]
    &retro::cartridges::WONDERSWAN,
    #[cfg(feature = "games")]
    &retro::cartridges::VIRTUAL_BOY,
    #[cfg(feature = "games")]
    &retro::states::GCI,
    #[cfg(feature = "games")]
    &retro::states::FM2,
    #[cfg(feature = "games")]
    &retro::tapes::ZX_TAP,
    #[cfg(feature = "games")]
    &retro::tapes::TRD,
    #[cfg(feature = "games")]
    &retro::tapes::ORIC_TAP,
    #[cfg(feature = "games")]
    &retro::tapes::ATARI_ST_PRG,
    #[cfg(feature = "games")]
    &retro::floppies::SCP,
    #[cfg(feature = "games")]
    &retro::floppies::DC42,
    #[cfg(feature = "games")]
    &retro::floppies::D88,
    #[cfg(feature = "games")]
    &retro::systems::DOL,
    #[cfg(feature = "games")]
    &retro::systems::VMI,
    #[cfg(feature = "games")]
    &retro::micros::ZX_SNA,
    #[cfg(feature = "games")]
    &retro::micros::ATARI_XEX,
    #[cfg(feature = "games")]
    &retro::micros::MACBINARY,
    #[cfg(feature = "games")]
    &retro::graphics::DEGAS,
    #[cfg(feature = "games")]
    &retro::graphics::NEOCHROME,
    #[cfg(feature = "games")]
    &retro::graphics::KOALA,
    #[cfg(feature = "games")]
    &retro::graphics::MSX_BSAVE,
    #[cfg(feature = "games")]
    &retro::graphics::AMSDOS,
    #[cfg(feature = "games")]
    &retro::dats::CLRMAMEPRO,
    #[cfg(feature = "games")]
    &retro::dats::LOGIQX,
    #[cfg(feature = "games")]
    &retro::dats::SOFTLIST,
    #[cfg(feature = "games")]
    &retro::dats::CDRDAO_TOC,
    #[cfg(feature = "games")]
    &retro::dats::RETROARCH_CHT,
    // -- end retro --

    // -- ml models & mobile platforms --
    #[cfg(feature = "system")]
    &ml::binary::GGML,
    #[cfg(feature = "system")]
    &ml::binary::GGMF,
    #[cfg(feature = "system")]
    &ml::binary::GGJT,
    #[cfg(feature = "system")]
    &ml::binary::GGLA,
    #[cfg(feature = "system")]
    &ml::binary::NCNN_BIN,
    #[cfg(feature = "system")]
    &ml::binary::MXNET,
    #[cfg(feature = "system")]
    &ml::binary::NNEF_TENSOR,
    #[cfg(feature = "system")]
    &ml::binary::FASTTEXT,
    #[cfg(feature = "system")]
    &ml::binary::MLIR,
    #[cfg(feature = "system")]
    &ml::tflite::TFLITE,
    #[cfg(feature = "system")]
    &ml::tflite::ORT,
    #[cfg(feature = "system")]
    &ml::tflite::EXECUTORCH,
    #[cfg(feature = "system")]
    &mobile::android::SUPER,
    #[cfg(feature = "system")]
    &mobile::android::VENDOR_BOOT,
    #[cfg(feature = "system")]
    &mobile::android::BOOTLDR,
    #[cfg(feature = "system")]
    &mobile::android::MTK,
    #[cfg(feature = "system")]
    &mobile::android::PIT,
    #[cfg(feature = "system")]
    &mobile::android::QCDT,
    #[cfg(feature = "system")]
    &mobile::android::ART_PROFILE,
    #[cfg(feature = "system")]
    &mobile::android::FCONTEXT,
    #[cfg(feature = "system")]
    &mobile::android::HPROF,
    #[cfg(feature = "system")]
    &mobile::android::METHOD_TRACE,
    #[cfg(feature = "system")]
    &mobile::apple::NIB,
    #[cfg(feature = "system")]
    &mobile::apple::METALLIB,
    #[cfg(feature = "system")]
    &mobile::apple::CAR,
    #[cfg(feature = "system")]
    &mobile::apple::CODE_SIGNATURE,
    #[cfg(feature = "system")]
    &mobile::apple::AEA,
    #[cfg(feature = "system")]
    &mobile::apple::SWIFTMODULE,
    #[cfg(feature = "system")]
    &ml::protos::TFRECORD,
    #[cfg(feature = "system")]
    &ml::protos::SAVED_MODEL,
    #[cfg(feature = "system")]
    &ml::protos::COREML,
    #[cfg(feature = "system")]
    &ml::protos::ONNX,
    #[cfg(feature = "system")]
    &ml::protos::GRAPHDEF,
    #[cfg(feature = "system")]
    &ml::protos::SENTENCEPIECE,
    #[cfg(feature = "system")]
    &mobile::apple::TRUSTCACHE,
    #[cfg(feature = "system")]
    &mobile::android::LOGCAT,
    #[cfg(feature = "system")]
    &mobile::android_text::TOMBSTONE_FORMAT,
    #[cfg(feature = "system")]
    &mobile::android_text::ANR,
    #[cfg(feature = "system")]
    &mobile::android_text::BUILD_PROP,
    #[cfg(feature = "system")]
    &mobile::apple_text::PBXPROJ,
    #[cfg(feature = "system")]
    &mobile::apple_text::BCSYMBOLMAP,
    #[cfg(feature = "system")]
    &mobile::apple_text::CRASH,
    #[cfg(feature = "system")]
    &mobile::apple_text::IPS,
    #[cfg(feature = "system")]
    &mobile::apple_text::TBD,
    #[cfg(feature = "system")]
    &mobile::apple_text::STRINGS,
    #[cfg(feature = "system")]
    &ml::text::NCNN,
    #[cfg(feature = "system")]
    &ml::text::CAFFE,
    #[cfg(feature = "system")]
    &ml::text::DARKNET,
    #[cfg(feature = "system")]
    &ml::text::NNEF_GRAPH,
    #[cfg(feature = "system")]
    &ml::text::LIBSVM,
    #[cfg(feature = "system")]
    &ml::text::LIBLINEAR,
    #[cfg(feature = "system")]
    &ml::text::LIGHTGBM,
    #[cfg(feature = "system")]
    &ml::text::OPENVINO,
    #[cfg(feature = "system")]
    &ml::text::PMML,
    #[cfg(feature = "system")]
    &ml::text::OPENCV,
    #[cfg(feature = "system")]
    &ml::text::MXNET_SYMBOL,
    #[cfg(feature = "system")]
    &ml::text::TFJS,
    #[cfg(feature = "system")]
    &ml::text::HF_TOKENIZER,
    #[cfg(feature = "system")]
    &ml::text::SAFETENSORS_INDEX,
    // -- end ml --

    // -- geospatial, telemetry & vehicle logs --
    #[cfg(feature = "science")]
    &geo::fit::FIT,
    #[cfg(feature = "science")]
    &geo::tiles::PMTILES,
    #[cfg(feature = "science")]
    &geo::tiles::FLATGEOBUF,
    #[cfg(feature = "science")]
    &geo::tiles::O5M,
    #[cfg(feature = "science")]
    &geo::tiles::MVT,
    #[cfg(feature = "science")]
    &geo::gis::GDBTABLE,
    #[cfg(feature = "science")]
    &geo::gis::ISO8211,
    #[cfg(feature = "science")]
    &geo::gis::NTV2,
    #[cfg(feature = "science")]
    &geo::gis::CTABLE2,
    #[cfg(feature = "science")]
    &geo::gis::LAZ,
    #[cfg(feature = "science")]
    &geo::gis::GARMIN_IMG,
    #[cfg(feature = "science")]
    &geo::gis::GARMIN_GDB,
    #[cfg(feature = "science")]
    &geo::gis::OV2,
    #[cfg(feature = "science")]
    &geo::gnss::UBX,
    #[cfg(feature = "science")]
    &geo::gnss::RTCM3,
    #[cfg(feature = "science")]
    &geo::gnss::SBF,
    #[cfg(feature = "science")]
    &geo::gnss::NOVATEL,
    #[cfg(feature = "science")]
    &geo::gnss::NMEA,
    #[cfg(feature = "science")]
    &geo::rinex::OBS,
    #[cfg(feature = "science")]
    &geo::rinex::NAV,
    #[cfg(feature = "science")]
    &geo::rinex::MET,
    #[cfg(feature = "science")]
    &geo::rinex::CLOCK,
    #[cfg(feature = "science")]
    &geo::rinex::CRINEX,
    #[cfg(feature = "science")]
    &geo::rinex::ANTEX,
    #[cfg(feature = "science")]
    &geo::rinex::IONEX,
    #[cfg(feature = "science")]
    &geo::rinex::SP3,
    #[cfg(feature = "science")]
    &geo::rinex::SINEX,
    #[cfg(feature = "science")]
    &geo::mdf::MDF,
    #[cfg(feature = "science")]
    &geo::vehicle::BLF,
    #[cfg(feature = "science")]
    &geo::vehicle::ASC,
    #[cfg(feature = "science")]
    &geo::vehicle::CANDUMP,
    #[cfg(feature = "science")]
    &geo::vehicle::TRC,
    #[cfg(feature = "science")]
    &geo::vehicle::DBC,
    #[cfg(feature = "science")]
    &geo::vehicle::LDF,
    #[cfg(feature = "science")]
    &geo::vehicle::A2L,
    #[cfg(feature = "science")]
    &geo::robotics::ULOG,
    #[cfg(feature = "science")]
    &geo::robotics::DATAFLASH,
    #[cfg(feature = "science")]
    &geo::robotics::ARDUPILOT_LOG,
    #[cfg(feature = "science")]
    &geo::robotics::TLOG,
    #[cfg(feature = "science")]
    &geo::robotics::GPMF,
    #[cfg(feature = "science")]
    &geo::robotics::ROSBAG,
    #[cfg(feature = "science")]
    &geo::robotics::MCAP,
    #[cfg(feature = "science")]
    &geo::robotics::BLACKBOX_LOG,
    #[cfg(feature = "science")]
    &geo::gistext::IGC,
    #[cfg(feature = "science")]
    &geo::gistext::OZI_TRACK,
    #[cfg(feature = "science")]
    &geo::gistext::OZI_WAYPOINTS,
    #[cfg(feature = "science")]
    &geo::gistext::OZI_ROUTE,
    #[cfg(feature = "science")]
    &geo::gistext::OZI_MAP,
    #[cfg(feature = "science")]
    &geo::gistext::MIF,
    #[cfg(feature = "science")]
    &geo::gistext::TAB,
    #[cfg(feature = "science")]
    &geo::gistext::GRASS_ASCII,
    #[cfg(feature = "science")]
    &geo::gistext::GRASS_VECTOR,
    #[cfg(feature = "science")]
    &geo::gistext::IDRISI,
    #[cfg(feature = "science")]
    &geo::gistext::WKT,
    #[cfg(feature = "science")]
    &geo::gistext::BIL_HDR,
    #[cfg(feature = "science")]
    &geo::gistext::HRM,
    #[cfg(feature = "science")]
    &geo::gistext::ERG,
    #[cfg(feature = "science")]
    &geo::gistext::SRM,
    #[cfg(feature = "science")]
    &geo::markup::TCX,
    #[cfg(feature = "science")]
    &geo::markup::PWX,
    #[cfg(feature = "science")]
    &geo::markup::FITLOG,
    #[cfg(feature = "science")]
    &geo::markup::ZWO,
    #[cfg(feature = "science")]
    &geo::markup::OSC,
    #[cfg(feature = "science")]
    &geo::markup::GML,
    #[cfg(feature = "science")]
    &geo::markup::ARXML,
    #[cfg(feature = "science")]
    &geo::markup::ODX,
    #[cfg(feature = "science")]
    &geo::markup::TILEJSON,
    #[cfg(feature = "science")]
    &geo::markup::MAPBOX_STYLE,
    #[cfg(feature = "science")]
    &geo::markup::QGC_PLAN,
    // -- end geo --

    // -- publishing, design & multimedia authoring --
    #[cfg(feature = "docs")]
    &publishing::adobe::PAT,
    #[cfg(feature = "docs")]
    &publishing::adobe::ABR,
    #[cfg(feature = "docs")]
    &publishing::adobe::GRD,
    #[cfg(feature = "docs")]
    &publishing::adobe::ASL,
    #[cfg(feature = "docs")]
    &publishing::adobe::ATN,
    #[cfg(feature = "docs")]
    &publishing::adobe::ACB,
    #[cfg(feature = "docs")]
    &publishing::adobe::CSH,
    #[cfg(feature = "docs")]
    &publishing::adobe::ACV,
    #[cfg(feature = "docs")]
    &publishing::fonts::CFF,
    #[cfg(feature = "docs")]
    &publishing::fonts::FNT,
    #[cfg(feature = "docs")]
    &publishing::fonts::PFM,
    #[cfg(feature = "docs")]
    &publishing::fonts::TFM,
    #[cfg(feature = "docs")]
    &publishing::fonts::VF,
    #[cfg(feature = "docs")]
    &publishing::fonts::AMIGA_FONT,
    #[cfg(feature = "docs")]
    &publishing::fonts::PFR,
    #[cfg(feature = "docs")]
    &publishing::fonts::BGI,
    #[cfg(feature = "docs")]
    &publishing::fonts::VFB,
    #[cfg(feature = "docs")]
    &publishing::fonts::SFD,
    #[cfg(feature = "docs")]
    &publishing::fonts::GLYPHS,
    #[cfg(feature = "docs")]
    &publishing::fonts::GLIF,
    #[cfg(feature = "docs")]
    &publishing::fonts::DESIGNSPACE,
    #[cfg(feature = "docs")]
    &publishing::dtp::INDESIGN,
    #[cfg(feature = "docs")]
    &publishing::dtp::QUARK,
    #[cfg(feature = "docs")]
    &publishing::dtp::XARA,
    #[cfg(feature = "docs")]
    &publishing::dtp::SCRIBUS,
    #[cfg(feature = "image")]
    &image::xmp::FORMAT,
    #[cfg(feature = "docs")]
    &publishing::authoring::HYPERCARD,
    #[cfg(feature = "docs")]
    &publishing::authoring::FIGMA,
    #[cfg(feature = "docs")]
    &publishing::authoring::RIVE,
    #[cfg(feature = "docs")]
    &publishing::authoring::MOC3,
    #[cfg(feature = "docs")]
    &publishing::printing::PJL,
    #[cfg(feature = "docs")]
    &publishing::printing::PCLXL,
    #[cfg(feature = "docs")]
    &publishing::printing::PCL,
    #[cfg(feature = "docs")]
    &publishing::printing::CUPS_RASTER,
    #[cfg(feature = "docs")]
    &publishing::printing::URF,
    #[cfg(feature = "docs")]
    &publishing::printing::PPD,
    #[cfg(feature = "docs")]
    &publishing::printing::GPD,
    #[cfg(feature = "docs")]
    &publishing::printing::HPGL,
    #[cfg(feature = "docs")]
    &publishing::printing::ZPL,
    #[cfg(feature = "docs")]
    &publishing::printing::ESCP,
    #[cfg(feature = "docs")]
    &publishing::design::ASEPRITE,
    #[cfg(feature = "docs")]
    &publishing::design::PICT,
    #[cfg(feature = "docs")]
    &publishing::design::JASC_PAL,
    #[cfg(feature = "docs")]
    &publishing::design::GGR,
    #[cfg(feature = "docs")]
    &publishing::design::CUBE,
    #[cfg(feature = "docs")]
    &publishing::design::CGM,
    #[cfg(feature = "docs")]
    &publishing::design::GEM,
    // Identified by size alone: last.
    #[cfg(feature = "docs")]
    &publishing::adobe::ACT,
    // -- end publishing --

    // -- games, 3D, science, e-books, misc --
    #[cfg(feature = "games")]
    &games::engines::WAD,
    #[cfg(feature = "games")]
    &games::engines::PAK,
    #[cfg(feature = "games")]
    &games::engines::WAD2,
    #[cfg(feature = "games")]
    &games::engines::VPK,
    #[cfg(feature = "games")]
    &games::engines::MDL,
    #[cfg(feature = "games")]
    &games::engines::MD2,
    #[cfg(feature = "games")]
    &games::engines::MD3,
    #[cfg(feature = "games")]
    &games::engines::UNREAL,
    #[cfg(feature = "games")]
    &games::engines::BSP,
    #[cfg(feature = "games")]
    &games::dweep::FORMAT,
    #[cfg(feature = "science")]
    &engineering::models::GLB,
    #[cfg(feature = "science")]
    &engineering::models::FBX,
    #[cfg(feature = "science")]
    &engineering::models::BLEND,
    #[cfg(feature = "science")]
    &engineering::models::USDC,
    #[cfg(feature = "science")]
    &engineering::models::VOX,
    #[cfg(feature = "science")]
    &engineering::models::PLY,
    #[cfg(feature = "science")]
    &engineering::autocad::dwg::DWG,
    #[cfg(feature = "science")]
    &engineering::models::THREE_DS,
    #[cfg(feature = "science")]
    &engineering::models::STL_ASCII,
    #[cfg(feature = "science")]
    &engineering::autocad::dxf::DXF,
    #[cfg(feature = "image")]
    &image::fits::FORMAT,
    #[cfg(feature = "science")]
    &science::imaging::DICOM,
    #[cfg(feature = "science")]
    &geo::survey::SHX,
    #[cfg(feature = "science")]
    &geo::survey::SHP,
    #[cfg(feature = "science")]
    &geo::survey::LAS,
    #[cfg(feature = "science")]
    &geo::survey::GRIB,
    #[cfg(feature = "science")]
    &geo::survey::BUFR,
    #[cfg(feature = "science")]
    &geo::survey::DBF,
    #[cfg(feature = "docs")]
    &documents::ebooks::MOBI,
    #[cfg(feature = "docs")]
    &documents::ebooks::PALMDOC,
    #[cfg(feature = "docs")]
    &documents::djvu::DJVU,
    #[cfg(feature = "docs")]
    &documents::ebooks::LIT,
    #[cfg(feature = "security")]
    &security::credentials::KDBX,
    #[cfg(feature = "security")]
    &security::credentials::KDB,
    #[cfg(feature = "security")]
    &security::openssh::OPENSSH_KEY,
    #[cfg(feature = "security")]
    &security::credentials::KEYBOX,
    #[cfg(feature = "security")]
    &security::keychain::KEYCHAIN,
    #[cfg(feature = "security")]
    &security::credentials::ANDROID_BACKUP,
    #[cfg(feature = "system")]
    &system::artifacts::DTB,
    #[cfg(feature = "system")]
    &system::artifacts::BZIMAGE,
    #[cfg(feature = "system")]
    &system::artifacts::JOURNAL,
    #[cfg(feature = "system")]
    &system::artifacts::REDIS_RDB,
    #[cfg(feature = "system")]
    &system::pst::PST,
    #[cfg(feature = "system")]
    &system::dotnet::DOTNET_RESOURCES,
    #[cfg(feature = "system")]
    &system::dotnet::NRBF,
    #[cfg(feature = "security")]
    &pcap::snoop::SNOOP,
    #[cfg(feature = "system")]
    &system::artifacts::ACPI,
    #[cfg(feature = "image")]
    &image::metafile::EMF,
    #[cfg(feature = "image")]
    &image::dpx::DPX,
    #[cfg(feature = "image")]
    &image::dpx::CINEON,
    #[cfg(feature = "image")]
    &image::texture::VTF,
    #[cfg(feature = "image")]
    &image::texture::PVR,
    #[cfg(feature = "image")]
    &image::texture::ASTC,
    #[cfg(feature = "image")]
    &image::graphics::PKM,
    #[cfg(feature = "image")]
    &image::graphics::ASE,
    #[cfg(feature = "image")]
    &image::graphics::GBR,
    #[cfg(feature = "image")]
    &image::graphics::GPAT,
    #[cfg(feature = "image")]
    &image::graphics::PDN,
    #[cfg(feature = "image")]
    &image::modern::BPG,
    #[cfg(feature = "image")]
    &image::modern::FLIF,
    #[cfg(feature = "image")]
    &image::tiff::JXR,
    #[cfg(feature = "image")]
    &image::metafile::WMF,
    #[cfg(feature = "image")]
    &image::graphics::ACO,
    #[cfg(feature = "games")]
    &games::packages::GODOT_PCK,
    #[cfg(feature = "games")]
    &games::unity::UNITYFS,
    #[cfg(feature = "games")]
    &games::unity::UNITY_SERIALIZED,
    #[cfg(feature = "games")]
    &games::packages::GAMEMAKER,
    #[cfg(feature = "games")]
    &games::packages::RPA,
    #[cfg(feature = "archive")]
    &compression::containers::APPLE_ARCHIVE,
    #[cfg(feature = "archive")]
    &compression::containers::LZFSE,
    #[cfg(feature = "archive")]
    &compression::containers::PBZX,
    #[cfg(feature = "archive")]
    &compression::containers::LZOP,
    #[cfg(feature = "archive")]
    &compression::containers::LZF,
    #[cfg(feature = "archive")]
    &compression::containers::LRZIP,
    #[cfg(feature = "archive")]
    &compression::containers::ZSTD_DICT,
    #[cfg(feature = "archive")]
    &compression::containers::POWERPACKER,
    #[cfg(feature = "archive")]
    &compression::containers::ZPAQ,
    #[cfg(feature = "av")]
    &video::pgs::PGS,
    #[cfg(feature = "games")]
    &games::archives::SARC,
    #[cfg(feature = "games")]
    &games::archives::YAZ0,
    #[cfg(feature = "games")]
    &games::archives::U8,
    #[cfg(feature = "games")]
    &games::archives::NARC,
    #[cfg(feature = "games")]
    &games::archives::PSARC,
    #[cfg(feature = "games")]
    &games::archives::XNB,
    #[cfg(feature = "games")]
    &games::archives::BSA,
    #[cfg(feature = "games")]
    &games::archives::BA2,
    #[cfg(feature = "games")]
    &games::archives::MPQ,
    #[cfg(feature = "games")]
    &games::archives::RGSSAD,
    #[cfg(feature = "av")]
    &audio::cool_edit::SES,
    #[cfg(feature = "av")]
    &audio::projects::FXP,
    #[cfg(feature = "av")]
    &audio::projects::FLP,
    #[cfg(feature = "av")]
    &audio::guitar_pro::FORMAT,
    #[cfg(feature = "av")]
    &audio::guitar_pro::gpx::FORMAT,
    #[cfg(feature = "games")]
    &games::archives::UNREAL_PAK,
    #[cfg(feature = "docs")]
    &documents::dvi::DVI,
    #[cfg(feature = "docs")]
    &documents::wordprocessing::WORDPERFECT,
    #[cfg(feature = "docs")]
    &documents::wordprocessing::WRITE,
    #[cfg(feature = "docs")]
    &documents::onenote::ONENOTE,
    #[cfg(feature = "docs")]
    &documents::onenote::ONETOC2,
    #[cfg(feature = "docs")]
    &documents::wordprocessing::FRAMEMAKER,
    #[cfg(feature = "archive")]
    &archive::warc::WARC,
    #[cfg(feature = "security")]
    &security::age::AGE,
    #[cfg(feature = "data")]
    &data::bitcoin::BITCOIN_BLOCKS,
    #[cfg(feature = "security")]
    &pcap::captures::BTSNOOP,
    #[cfg(feature = "security")]
    &pcap::captures::NETMON,
    #[cfg(feature = "system")]
    &system::ota::OTA_PAYLOAD,
    #[cfg(feature = "system")]
    &forensics::registry_pol::REGISTRY_POL,
    #[cfg(feature = "data")]
    &data::ese::ESE,
    #[cfg(feature = "system")]
    &system::bom::BOMSTORE,
    #[cfg(feature = "system")]
    &system::shim_sdb::SDB,
    #[cfg(feature = "science")]
    &science::stats::spss::SPSS,
    #[cfg(feature = "science")]
    &science::stats::por::POR,
    #[cfg(feature = "science")]
    &science::stats::sas::SAS7BDAT,
    #[cfg(feature = "science")]
    &science::stats::xport::XPORT,
    #[cfg(feature = "science")]
    &science::stats::stata::STATA,
    #[cfg(feature = "science")]
    &science::datasets::ROOT,
    #[cfg(feature = "science")]
    &science::datasets::NIFTI,
    #[cfg(feature = "science")]
    &science::datasets::NRRD,
    #[cfg(feature = "science")]
    &science::datasets::HDF4,
    #[cfg(feature = "science")]
    &science::datasets::VTK,
    #[cfg(feature = "exec")]
    &executable::pdb::PDB,
    #[cfg(feature = "exec")]
    &executable::pdb::PDB2,
    #[cfg(feature = "system")]
    &system::platform::PERF,
    #[cfg(feature = "system")]
    &system::platform::LDSO_CACHE,
    #[cfg(feature = "system")]
    &system::platform::SELINUX,
    #[cfg(feature = "system")]
    &system::platform::VBMETA,
    #[cfg(feature = "system")]
    &system::platform::DTBO,
    #[cfg(feature = "system")]
    &system::platform::INTEL_FLASH,
    #[cfg(feature = "system")]
    &system::platform::CBFS,
    #[cfg(feature = "system")]
    &system::platform::ARM_FIP,
    #[cfg(feature = "archive")]
    &archive::installer::nsis::FORMAT,
    #[cfg(feature = "archive")]
    &archive::installer::inno::FORMAT,
    #[cfg(feature = "system")]
    &system::platform::JMOD,
    #[cfg(feature = "system")]
    &system::platform::JIMAGE,
    #[cfg(feature = "system")]
    &system::platform::MAC_RESOURCE,
    #[cfg(feature = "system")]
    &system::devices::ROMFS,
    #[cfg(feature = "system")]
    &system::devices::JFFS2,
    #[cfg(feature = "system")]
    &system::devices::UBI,
    #[cfg(feature = "system")]
    &system::devices::UBIFS,
    #[cfg(feature = "system")]
    &system::devices::TRX,
    #[cfg(feature = "system")]
    &system::devices::IMG3,
    #[cfg(feature = "system")]
    &system::devices::XEX,
    #[cfg(feature = "system")]
    &system::devices::PS3_SELF,
    #[cfg(feature = "system")]
    &system::devices::PS3_PKG,
    #[cfg(feature = "system")]
    &system::devices::NSP,
    #[cfg(feature = "system")]
    &system::devices::XCI,
    #[cfg(feature = "system")]
    &system::devices::WII_WAD,
    #[cfg(feature = "system")]
    &system::devices::CIA,
    #[cfg(feature = "system")]
    &system::devices::KERNEL_DUMP,
    // NTFS $LogFile restart pages also start with RSTR; check them first.
    #[cfg(feature = "system")]
    &forensics::windows::LOGFILE,
    #[cfg(feature = "system")]
    &system::devices::HIBERFIL,
    #[cfg(feature = "system")]
    &system::devices::VERITY,
    #[cfg(feature = "system")]
    &system::devices::BTRFS_SEND,
    #[cfg(feature = "system")]
    &system::devtools::GCC_PCH,
    #[cfg(feature = "system")]
    &system::devtools::CLANG_PCH,
    #[cfg(feature = "system")]
    &system::devtools::WIN_RES,
    #[cfg(feature = "system")]
    &system::delphi::DFM,
    #[cfg(feature = "system")]
    &system::devtools::ILK,
    #[cfg(feature = "system")]
    &system::devtools::TYPELIB,
    #[cfg(feature = "system")]
    &system::devtools::NAR,
    #[cfg(feature = "system")]
    &system::devtools::GIT_BUNDLE,
    #[cfg(feature = "system")]
    &system::devtools::HG_BUNDLE,
    #[cfg(feature = "system")]
    &system::devtools::SVN_DUMP,
    #[cfg(feature = "system")]
    &system::devtools::DUCKDB,
    #[cfg(feature = "system")]
    &system::devtools::LMDB,
    #[cfg(feature = "system")]
    &system::devtools::BOLT,
    #[cfg(feature = "system")]
    &system::devtools::PROM_CHUNKS,
    #[cfg(feature = "system")]
    &system::devtools::PROM_INDEX,
    #[cfg(feature = "system")]
    &system::devtools::INFLUX_TSM,
    #[cfg(feature = "system")]
    &system::devtools::LUCENE,
    #[cfg(feature = "docs")]
    &documents::ebooks::PDB,
    // bioinformatics (BGZF-based ones are listed before gzip)
    #[cfg(feature = "science")]
    &science::bio::binary::BAI,
    #[cfg(feature = "science")]
    &science::bio::binary::CRAM,
    #[cfg(feature = "science")]
    &science::bio::binary::TWOBIT,
    #[cfg(feature = "science")]
    &science::bio::binary::BIGWIG,
    #[cfg(feature = "science")]
    &science::bio::binary::BIGBED,
    #[cfg(feature = "science")]
    &science::bio::binary::ABIF,
    #[cfg(feature = "science")]
    &science::bio::binary::SCF,
    #[cfg(feature = "science")]
    &science::bio::text::VCF,
    #[cfg(feature = "science")]
    &science::bio::text::SAM,
    #[cfg(feature = "science")]
    &science::bio::text::GFF3,
    #[cfg(feature = "science")]
    &science::bio::text::GENBANK,
    #[cfg(feature = "science")]
    &science::bio::text::STOCKHOLM,
    #[cfg(feature = "science")]
    &science::bio::text::CLUSTAL,
    #[cfg(feature = "science")]
    &science::bio::text::MAF,
    #[cfg(feature = "science")]
    &science::bio::text::NEXUS,
    #[cfg(feature = "science")]
    &science::bio::text::GFA,
    #[cfg(feature = "science")]
    &science::bio::text::JCAMP,
    #[cfg(feature = "science")]
    &science::bio::text::PDB_STRUCTURE,
    #[cfg(feature = "science")]
    &science::bio::text::SDF,
    #[cfg(feature = "science")]
    &science::bio::text::MOLFILE,
    #[cfg(feature = "science")]
    &science::bio::text::CIF,
    #[cfg(feature = "science")]
    &science::bio::text::WIG,
    #[cfg(feature = "science")]
    &science::bio::text::BED,
    #[cfg(feature = "science")]
    &science::bio::text::FASTQ,
    #[cfg(feature = "science")]
    &science::bio::text::FASTA,
    #[cfg(feature = "science")]
    &science::instruments::FCS,
    #[cfg(feature = "science")]
    &science::instruments::THERMO_RAW,
    #[cfg(feature = "science")]
    &science::instruments::ABF,
    #[cfg(feature = "science")]
    &science::instruments::ABF2,
    #[cfg(feature = "science")]
    &science::instruments::EDF,
    #[cfg(feature = "science")]
    &science::instruments::BDF,
    #[cfg(feature = "science")]
    &science::instruments::GDF,
    #[cfg(feature = "science")]
    &science::instruments::INTAN_RHD,
    #[cfg(feature = "science")]
    &science::instruments::TDMS,
    #[cfg(feature = "science")]
    &science::instruments::TDMS_INDEX,
    #[cfg(feature = "science")]
    &science::instruments::NEV,
    #[cfg(feature = "science")]
    &science::instruments::NSX,
    #[cfg(feature = "science")]
    &science::instruments::PLEXON,
    #[cfg(feature = "science")]
    &science::instruments::BRAINVISION_HEADER,
    #[cfg(feature = "science")]
    &science::instruments::BRAINVISION_MARKERS,
    #[cfg(feature = "science")]
    &science::instruments::NEURALYNX,
    #[cfg(feature = "science")]
    &science::instruments::IDX,
    #[cfg(feature = "science")]
    &geo::geoscience::SEGY,
    #[cfg(feature = "science")]
    &geo::geoscience::SEG2,
    #[cfg(feature = "science")]
    &geo::geoscience::MSEED3,
    #[cfg(feature = "science")]
    &geo::geoscience::SAC,
    #[cfg(feature = "science")]
    &geo::geoscience::ERDAS_IMG,
    #[cfg(feature = "science")]
    &geo::geoscience::E57,
    #[cfg(feature = "science")]
    &geo::geoscience::PCD,
    #[cfg(feature = "science")]
    &geo::geoscience::LAS_LOG,
    #[cfg(feature = "science")]
    &geo::geoscience::SURFER_GRID,
    #[cfg(feature = "science")]
    &geo::geoscience::ESRI_GRID,
    #[cfg(feature = "science")]
    &geo::geoscience::ENVI_HDR,
    #[cfg(feature = "science")]
    &geo::geoscience::PDS3,
    #[cfg(feature = "science")]
    &geo::geoscience::VICAR,
    #[cfg(feature = "science")]
    &geo::geoscience::MSEED2,
    #[cfg(feature = "science")]
    &engineering::eda::GDSII,
    #[cfg(feature = "science")]
    &engineering::eda::OASIS,
    #[cfg(feature = "science")]
    &engineering::eda::KICAD_PCB,
    #[cfg(feature = "science")]
    &engineering::eda::KICAD_SCH,
    #[cfg(feature = "science")]
    &engineering::eda::KICAD_SYM,
    #[cfg(feature = "science")]
    &engineering::eda::KICAD_MOD,
    #[cfg(feature = "science")]
    &engineering::eda::EDIF,
    #[cfg(feature = "science")]
    &engineering::eda::SDF_TIMING,
    #[cfg(feature = "science")]
    &engineering::eda::VCD,
    #[cfg(feature = "science")]
    &engineering::eda::CITI,
    #[cfg(feature = "science")]
    &engineering::eda::SPICE_RAW,
    #[cfg(feature = "science")]
    &engineering::eda::IBIS,
    #[cfg(feature = "science")]
    &engineering::eda::SPEF,
    #[cfg(feature = "science")]
    &engineering::eda::XILINX_BIT,
    #[cfg(feature = "science")]
    &engineering::eda::JEDEC,
    #[cfg(feature = "science")]
    &engineering::eda::EXCELLON,
    #[cfg(feature = "science")]
    &engineering::eda::GERBER,
    #[cfg(feature = "science")]
    &engineering::eda::TOUCHSTONE,
    #[cfg(feature = "science")]
    &engineering::fabrication::BGCODE,
    // G-code has no magic: a strict content probe, after Gerber/Excellon.
    #[cfg(feature = "science")]
    &engineering::fabrication::GCODE,
    #[cfg(feature = "system")]
    &forensics::browser::IE_INDEX,
    #[cfg(feature = "system")]
    &forensics::browser::BINARYCOOKIES,
    #[cfg(feature = "system")]
    &forensics::browser::CHROME_CACHE_INDEX,
    #[cfg(feature = "system")]
    &forensics::browser::CHROME_CACHE_BLOCK,
    #[cfg(feature = "system")]
    &forensics::browser::CHROME_SIMPLE,
    #[cfg(feature = "system")]
    &forensics::browser::CHROME_VISITED,
    #[cfg(feature = "system")]
    &forensics::browser::SNSS,
    #[cfg(feature = "system")]
    &forensics::browser::MORK,
    #[cfg(feature = "system")]
    &forensics::windows::CUSTOM_DESTINATIONS,
    #[cfg(feature = "system")]
    &forensics::windows::INFO2,
    #[cfg(feature = "system")]
    &forensics::windows::MFT,
    #[cfg(feature = "system")]
    &forensics::windows::INDX,
    #[cfg(feature = "system")]
    &forensics::windows::JOB,
    #[cfg(feature = "system")]
    &forensics::windows::NK2,
    #[cfg(feature = "system")]
    &forensics::windows::DBX,
    #[cfg(feature = "system")]
    &forensics::windows::RDP_CACHE,
    #[cfg(feature = "system")]
    &forensics::windows::SCF,
    #[cfg(feature = "system")]
    &forensics::windows::GRP,
    #[cfg(feature = "system")]
    &forensics::windows::CARDFILE,
    #[cfg(feature = "system")]
    &forensics::windows::CLP,
    #[cfg(feature = "system")]
    &forensics::windows::USN,
    #[cfg(feature = "system")]
    &forensics::unix::FSEVENTS,
    #[cfg(feature = "system")]
    &forensics::unix::TIMESYNC,
    #[cfg(feature = "system")]
    &forensics::unix::TRACEV3,
    #[cfg(feature = "system")]
    &forensics::unix::ASL,
    #[cfg(feature = "system")]
    &forensics::unix::MBDB,
    #[cfg(feature = "system")]
    &forensics::unix::ABX,
    #[cfg(feature = "system")]
    &forensics::unix::UTMPX,
    #[cfg(feature = "system")]
    &forensics::unix::UUIDTEXT,
    #[cfg(feature = "system")]
    &forensics::unix::MBDX,
    #[cfg(feature = "system")]
    &forensics::browser::CHROME_SIMPLE_INDEX,
    #[cfg(feature = "docs")]
    &documents::office_legacy::LOTUS,
    #[cfg(feature = "docs")]
    &documents::office_legacy::LOTUS3,
    #[cfg(feature = "docs")]
    &documents::office_legacy::QUATTRO,
    #[cfg(feature = "docs")]
    &documents::office_legacy::WORKS_WKS,
    #[cfg(feature = "docs")]
    &documents::office_legacy::XLS_BIFF,
    #[cfg(feature = "docs")]
    &documents::office_legacy::CLARISWORKS,
    #[cfg(feature = "docs")]
    &documents::sketchup::SKETCHUP,
    #[cfg(feature = "docs")]
    &documents::office_legacy::SYLK,
    #[cfg(feature = "docs")]
    &documents::office_legacy::DIF,
    #[cfg(feature = "docs")]
    &documents::office_legacy::QIF,
    #[cfg(feature = "docs")]
    &documents::office_legacy::OFX,
    #[cfg(feature = "docs")]
    &documents::office_legacy::MPX,
    #[cfg(feature = "docs")]
    &documents::office_legacy::AMIPRO,
    #[cfg(feature = "docs")]
    &documents::office_legacy::MONEY,
    #[cfg(feature = "docs")]
    &documents::office_legacy::WORDPRO,
    #[cfg(feature = "system")]
    &forensics::windiag::WER,
    #[cfg(feature = "system")]
    &forensics::windiag::PIF,
    #[cfg(feature = "system")]
    &forensics::logs::SETUPAPI,
    #[cfg(feature = "system")]
    &forensics::logs::W3C,
    #[cfg(feature = "system")]
    &forensics::logs::TRANSCRIPT,
    #[cfg(feature = "system")]
    &forensics::logs::AUDIT,
    #[cfg(feature = "system")]
    &forensics::logs::VIMINFO,
    #[cfg(feature = "system")]
    &forensics::evidence::EWF,
    #[cfg(feature = "system")]
    &forensics::evidence::AFF,
    #[cfg(feature = "system")]
    &forensics::evidence::LIME,
    #[cfg(feature = "system")]
    &forensics::evidence::KDUMP,
    #[cfg(feature = "system")]
    &forensics::evidence::VMSS,
    #[cfg(feature = "system")]
    &forensics::evidence::VBOX_SAV,
    #[cfg(feature = "system")]
    &forensics::userdata::ZSH,
    #[cfg(feature = "system")]
    &forensics::userdata::BASH,
    #[cfg(feature = "system")]
    &forensics::userdata::FISH,
    #[cfg(feature = "system")]
    &forensics::userdata::LIBEDIT,
    #[cfg(feature = "system")]
    &forensics::userdata::LESS,
    #[cfg(feature = "system")]
    &forensics::userdata::WGET_HSTS,
    #[cfg(feature = "system")]
    &forensics::userdata::COOKIES_TXT,
    #[cfg(feature = "system")]
    &forensics::userdata::BOOKMARKS,
    #[cfg(feature = "system")]
    &forensics::userdata::OPERA_HOTLIST,
    #[cfg(feature = "system")]
    &forensics::userdata::FIREFOX_PREFS,
    #[cfg(feature = "system")]
    &forensics::userdata::CERT_OVERRIDE,
    #[cfg(feature = "system")]
    &forensics::userdata::TRASHINFO,
    #[cfg(feature = "system")]
    &forensics::userdata::XBEL,
    #[cfg(feature = "security")]
    &security::keyrings::GNOME_KEYRING,
    #[cfg(feature = "security")]
    &security::keyrings::KWALLET,
    #[cfg(feature = "docs")]
    &documents::office_legacy::WINWORD2,
    #[cfg(feature = "docs")]
    &documents::office_legacy::HWP3,
    #[cfg(feature = "docs")]
    &documents::office_legacy::HWP5_HEADER,
    #[cfg(feature = "system")]
    &forensics::windows::ODL,
    #[cfg(feature = "science")]
    &geo::osm::OSM_PBF,
    #[cfg(feature = "science")]
    &geo::elevation::DTED,
    #[cfg(feature = "science")]
    &geo::elevation::NITF,
    #[cfg(feature = "archive")]
    &archive::minor::ALZ,
    #[cfg(feature = "archive")]
    &archive::minor::EGG,
    #[cfg(feature = "archive")]
    &archive::minor::KGB,
    #[cfg(feature = "archive")]
    &archive::installer::installshield::ISCAB,
    #[cfg(feature = "archive")]
    &archive::installer::installshield::ISZ,
    #[cfg(feature = "image")]
    &image::camera::PHOTO_CD,
    #[cfg(feature = "image")]
    &image::camera::X3F,
    #[cfg(feature = "av")]
    &video::subtitles::EBU_STL,
    #[cfg(feature = "av")]
    &video::subtitles::SCC,
    #[cfg(feature = "av")]
    &video::subtitles::VOBSUB,
    #[cfg(feature = "av")]
    &video::nut::NUT,
    #[cfg(feature = "science")]
    &engineering::meshes::VRML,
    #[cfg(feature = "science")]
    &engineering::meshes::OFF,
    #[cfg(feature = "science")]
    &engineering::meshes::MD5MESH,
    #[cfg(feature = "science")]
    &engineering::meshes::SOURCE_MDL,
    #[cfg(feature = "science")]
    &engineering::meshes::PSK,
    #[cfg(feature = "docs")]
    &documents::lrf::LRF,
    #[cfg(feature = "image")]
    &font::adobe::AFM,
    #[cfg(feature = "image")]
    &font::adobe::PFA,
    #[cfg(feature = "games")]
    &games::blizzard::BLP,
    #[cfg(feature = "games")]
    &games::blizzard::M2,
    #[cfg(feature = "games")]
    &games::blizzard::W3M,
    #[cfg(feature = "games")]
    &games::bethesda::TES,
    #[cfg(feature = "games")]
    &games::packfiles::GTA_IMG,
    #[cfg(feature = "games")]
    &games::packfiles::HOG,
    #[cfg(feature = "games")]
    &games::packfiles::GRP,
    #[cfg(feature = "games")]
    &games::packfiles::BIG,
    #[cfg(feature = "games")]
    &games::packfiles::RFF,
    #[cfg(feature = "games")]
    &games::packfiles::BND,
    #[cfg(feature = "games")]
    &games::nw4::NW4,
    #[cfg(feature = "games")]
    &games::nw4::NW4R,
    #[cfg(feature = "av")]
    &audio::sequenced::MUS,
    #[cfg(feature = "av")]
    &audio::sequenced::HMI,
    #[cfg(feature = "av")]
    &audio::sequenced::AHX,
    #[cfg(feature = "av")]
    &audio::sequenced::MO3,
    #[cfg(feature = "av")]
    &audio::sequenced::DBM,
    #[cfg(feature = "av")]
    &audio::sequenced::FAR,
    #[cfg(feature = "image")]
    &font::raster::PSF_FONT,
    #[cfg(feature = "image")]
    &font::raster::BMFONT,
    #[cfg(feature = "image")]
    &font::raster::FIGLET,
    #[cfg(feature = "image")]
    &font::raster::TEX_PK,
    #[cfg(feature = "image")]
    &font::raster::TEX_GF,
    #[cfg(feature = "security")]
    &security::putty::PPK,
    #[cfg(feature = "av")]
    &audio::pcm_headers::SPHERE,
    #[cfg(feature = "av")]
    &audio::pcm_headers::AVR,
    #[cfg(feature = "av")]
    &audio::pcm_headers::PVF,
    #[cfg(feature = "image")]
    &image::toolkits::MIFF,
    #[cfg(feature = "image")]
    &image::toolkits::UTAH_RLE,
    #[cfg(feature = "image")]
    &image::toolkits::PSP,
    #[cfg(feature = "games")]
    &games::middleware::FSB,
    #[cfg(feature = "games")]
    &games::middleware::XWB,
    #[cfg(feature = "games")]
    &games::middleware::WWISE_BNK,
    #[cfg(feature = "games")]
    &games::middleware::VAG,
    #[cfg(feature = "games")]
    &games::middleware::OMA,
    #[cfg(feature = "games")]
    &games::middleware::HCA,
    #[cfg(feature = "games")]
    &games::middleware::USM,
    #[cfg(feature = "games")]
    &games::middleware::CPK,
    #[cfg(feature = "games")]
    &games::middleware::AFS,
    #[cfg(feature = "games")]
    &games::middleware::EA_SCHL,
    #[cfg(feature = "av")]
    &video::containers::NSV,
    #[cfg(feature = "av")]
    &video::containers::NUV,
    #[cfg(feature = "av")]
    &video::containers::R3D,
    #[cfg(feature = "av")]
    &video::containers::DPAINT_ANM,
    #[cfg(feature = "av")]
    &audio::production::TWINVQ,
    #[cfg(feature = "av")]
    &audio::production::EXS,
    #[cfg(feature = "av")]
    &audio::production::PTAB,
    #[cfg(feature = "science")]
    &engineering::cad::STEP,
    #[cfg(feature = "science")]
    &engineering::cad::IGES,
    #[cfg(feature = "science")]
    &engineering::cad::PARASOLID,
    #[cfg(feature = "science")]
    &engineering::cad::JT,
    #[cfg(feature = "science")]
    &engineering::cad::GMSH,
    #[cfg(feature = "science")]
    &engineering::cad::OPENFOAM,
    #[cfg(feature = "science")]
    &engineering::cad::ABAQUS,
    #[cfg(feature = "science")]
    &engineering::cad::LSDYNA,
    #[cfg(feature = "science")]
    &science::microscopy::MRC,
    #[cfg(feature = "science")]
    &science::microscopy::CZI,
    #[cfg(feature = "science")]
    &science::microscopy::ND2,
    #[cfg(feature = "science")]
    &science::microscopy::LIF,
    #[cfg(feature = "science")]
    &science::microscopy::SER,
    #[cfg(feature = "science")]
    &science::microscopy::GATAN_DM,
    #[cfg(feature = "science")]
    &science::molecular::DCD,
    #[cfg(feature = "science")]
    &science::molecular::XTC,
    #[cfg(feature = "science")]
    &science::molecular::TRR,
    #[cfg(feature = "science")]
    &science::molecular::MOL2,
    #[cfg(feature = "science")]
    &science::molecular::CHARMM_PSF,
    #[cfg(feature = "science")]
    &science::molecular::MSP,
    #[cfg(feature = "science")]
    &science::molecular::MGF,
    #[cfg(feature = "science")]
    &science::spectroscopy::NMRPIPE,
    #[cfg(feature = "science")]
    &science::spectroscopy::SPARKY,
    #[cfg(feature = "science")]
    &science::spectroscopy::RIGAKU_RAS,
    #[cfg(feature = "science")]
    &science::lab_images::IMAGEJ_ROI,
    #[cfg(feature = "science")]
    &science::lab_images::PRINCETON_SPE,
    #[cfg(feature = "science")]
    &science::lab_images::ICS,
    #[cfg(feature = "science")]
    &science::lab_images::IMOD,
    #[cfg(feature = "science")]
    &science::lab_images::FREESURFER_SURF,
    #[cfg(feature = "science")]
    &science::waveforms::SPIKE2,
    #[cfg(feature = "science")]
    &science::waveforms::AXON_ATF,
    #[cfg(feature = "science")]
    &science::waveforms::IGOR_ITX,
    #[cfg(feature = "science")]
    &science::waveforms::LABVIEW_LVM,
    #[cfg(feature = "science")]
    &science::waveforms::KEYSIGHT_BIN,
    #[cfg(feature = "science")]
    &science::waveforms::TEKTRONIX_ISF,
    #[cfg(feature = "science")]
    &science::waveforms::LECROY_TRC,
    #[cfg(feature = "science")]
    &science::waveforms::FST,
    #[cfg(feature = "science")]
    &science::lab_images::BIORAD_PIC,
    #[cfg(feature = "science")]
    &science::lab_images::MGH,
    #[cfg(feature = "science")]
    &science::lab_images::ANALYZE,
    #[cfg(feature = "science")]
    &science::spectroscopy::GALACTIC_SPC,
    #[cfg(feature = "science")]
    &science::bio::sequencing::SFF,
    #[cfg(feature = "science")]
    &science::bio::sequencing::ZTR,
    #[cfg(feature = "science")]
    &science::bio::sequencing::SLOW5,
    #[cfg(feature = "science")]
    &science::bio::sequencing::BLOW5,
    #[cfg(feature = "science")]
    &science::bio::sequencing::HIC,
    #[cfg(feature = "science")]
    &science::bio::records::HMMER3,
    #[cfg(feature = "science")]
    &science::bio::records::EMBL,
    #[cfg(feature = "science")]
    &science::bio::records::PSL,
    #[cfg(feature = "science")]
    &science::bio::records::MZTAB,
    #[cfg(feature = "science")]
    &science::bio::records::AMBER_PRMTOP,
    #[cfg(feature = "science")]
    &science::bio::records::GTF,
    #[cfg(feature = "science")]
    &engineering::brep::RHINO_3DM,
    #[cfg(feature = "science")]
    &engineering::brep::ACIS_SAB,
    #[cfg(feature = "science")]
    &engineering::simulation::ANSYS_CDB,
    #[cfg(feature = "science")]
    &engineering::simulation::TECPLOT,
    #[cfg(feature = "science")]
    &engineering::simulation::ENSIGHT_CASE,
    #[cfg(feature = "science")]
    &engineering::simulation::ENSIGHT_GOLD,
    #[cfg(feature = "science")]
    &engineering::simulation::OPENVDB,
    #[cfg(feature = "science")]
    &engineering::simulation::NASTRAN,
    #[cfg(feature = "science")]
    &geo::dlis::ERMAPPER_ERS,
    #[cfg(feature = "science")]
    &geo::dlis::DLIS,
    #[cfg(feature = "science")]
    &engineering::eda::SAIF,
    #[cfg(feature = "science")]
    &engineering::eda::SPECCTRA_DSN,
    #[cfg(feature = "science")]
    &engineering::eda::SPECCTRA_SES,
    #[cfg(feature = "science")]
    &engineering::eda_text::LTSPICE_ASC,
    #[cfg(feature = "science")]
    &engineering::eda_text::LTSPICE_ASY,
    #[cfg(feature = "science")]
    &engineering::eda_text::KICAD_LEGACY_SCH,
    #[cfg(feature = "science")]
    &engineering::eda_text::KICAD_LEGACY_LIB,
    #[cfg(feature = "science")]
    &engineering::eda_text::KICAD_LEGACY_PCB,
    #[cfg(feature = "science")]
    &engineering::eda_text::GEDA_SCH,
    #[cfg(feature = "science")]
    &engineering::eda_text::PADS_ASCII,
    #[cfg(feature = "science")]
    &engineering::eda_text::DEF,
    #[cfg(feature = "science")]
    &engineering::eda_text::LEF,
    #[cfg(feature = "archive")]
    &archive::legacy::HA,
    #[cfg(feature = "archive")]
    &archive::legacy::UHARC,
    #[cfg(feature = "archive")]
    &archive::legacy::YZ1,
    #[cfg(feature = "archive")]
    &archive::legacy::DGCA,
    #[cfg(feature = "archive")]
    &archive::legacy::GCA,
    #[cfg(feature = "archive")]
    &archive::legacy::PAQ8,
    #[cfg(feature = "archive")]
    &compression::legacy::FREEZE,
    #[cfg(feature = "archive")]
    &compression::legacy::COMPACT,
    #[cfg(feature = "archive")]
    &archive::legacy::XPK,
    #[cfg(feature = "archive")]
    &archive::legacy::AMIGA_LZX,
    #[cfg(feature = "archive")]
    &archive::legacy::PACKIT,
    #[cfg(feature = "image")]
    &image::paint::CPT,
    #[cfg(feature = "image")]
    &image::paint::CLIP,
    #[cfg(feature = "image")]
    &image::paint::MDP,
    #[cfg(feature = "image")]
    &image::paint::GIMP_GPL,
    #[cfg(feature = "image")]
    &image::minor::PGF,
    #[cfg(feature = "image")]
    &image::minor::XV_THUMB,
    #[cfg(feature = "image")]
    &image::minor::VIFF,
    #[cfg(feature = "docs")]
    &documents::help::OS2_INF,
    #[cfg(feature = "docs")]
    &documents::help::TCR,
    #[cfg(feature = "docs")]
    &documents::help::AMIGAGUIDE,
    #[cfg(feature = "data")]
    &data::embedded_db::TOKYO,
    #[cfg(feature = "data")]
    &data::embedded_db::KYOTO,
    #[cfg(feature = "data")]
    &data::embedded_db::GDBM,
    #[cfg(feature = "data")]
    &data::embedded_db::RRD,
    #[cfg(feature = "data")]
    &data::embedded_db::WIREDTIGER,
    #[cfg(feature = "data")]
    &data::wiredtiger::BTREE,
    #[cfg(feature = "data")]
    &data::wiredtiger::TURTLE,
    #[cfg(feature = "data")]
    &data::embedded_db::REALM,
    #[cfg(feature = "security")]
    &security::kerberos::KEYTAB,
    #[cfg(feature = "security")]
    &security::kerberos::CCACHE,
    #[cfg(feature = "security")]
    &security::encryption::PWSAFE,
    #[cfg(feature = "security")]
    &security::encryption::OPENSSL_ENC,
    #[cfg(feature = "security")]
    &security::encryption::AESCRYPT,
    #[cfg(feature = "security")]
    &security::encryption::AXCRYPT,
    #[cfg(feature = "security")]
    &security::encryption::MINISIGN,
    #[cfg(feature = "data")]
    &data::dumps::MTF,
    #[cfg(feature = "data")]
    &data::dumps::ORACLE_EXP,
    #[cfg(feature = "data")]
    &data::dumps::PG_DUMP,
    #[cfg(feature = "data")]
    &data::dumps::MYSQL_FRM,
    #[cfg(feature = "data")]
    &data::dumps::MYISAM,
    #[cfg(feature = "data")]
    &data::dumps::H2,
    #[cfg(feature = "data")]
    &data::dumps::FILEMAKER,
    #[cfg(feature = "data")]
    &data::rdata::R_DATA,
    #[cfg(feature = "data")]
    &data::rdata::ASDF,
    #[cfg(feature = "system")]
    &forensics::wab::WAB,
    #[cfg(feature = "exec")]
    &bytecode::applescript::APPLESCRIPT,
    #[cfg(feature = "archive")]
    &archive::packaging::SOLARIS_PKG,
    #[cfg(feature = "archive")]
    &archive::packaging::HPKG,
    #[cfg(feature = "archive")]
    &archive::packaging::ASAR,
    #[cfg(feature = "games")]
    &games::models::DIRECTX_X,
    #[cfg(feature = "games")]
    &games::models::MS3D,
    #[cfg(feature = "games")]
    &games::models::CAL3D,
    #[cfg(feature = "games")]
    &games::models::OGRE,
    #[cfg(feature = "science")]
    &engineering::dcc::MAYA,
    #[cfg(feature = "science")]
    &engineering::dcc::C4D,
    #[cfg(feature = "science")]
    &engineering::dcc::BGEO,
    #[cfg(feature = "science")]
    &engineering::dcc::ALEMBIC,
    #[cfg(feature = "games")]
    &games::models::NIF,
    #[cfg(feature = "games")]
    &games::engine_data::HKX,
    #[cfg(feature = "games")]
    &games::engine_data::BGSM,
    #[cfg(feature = "games")]
    &games::engine_data::WOW_CHUNKED,
    #[cfg(feature = "games")]
    &games::engine_data::WOW_DB,
    #[cfg(feature = "games")]
    &games::engine_data::WC3_MDX,
    #[cfg(feature = "games")]
    &games::models::QUAKE_SPR,
    #[cfg(feature = "games")]
    &games::models::QUAKE2_SP2,
    #[cfg(feature = "games")]
    &games::models::RTCW_MODEL,
    #[cfg(feature = "games")]
    &games::models::HEXEN2_MDL,
    #[cfg(feature = "games")]
    &games::models::VVD,
    #[cfg(feature = "games")]
    &games::models::DMX,
    #[cfg(feature = "games")]
    &games::engine_data::UTOC,
    #[cfg(feature = "games")]
    &games::engine_data::XP3,
    #[cfg(feature = "games")]
    &games::engine_data::ALLEGRO,
    #[cfg(feature = "games")]
    &games::engine_data::RPYC,
    #[cfg(feature = "games")]
    &games::consoles::BFRES,
    #[cfg(feature = "games")]
    &games::consoles::BNTX,
    #[cfg(feature = "games")]
    &games::consoles::MSBT,
    #[cfg(feature = "games")]
    &games::consoles::CGFX,
    #[cfg(feature = "games")]
    &games::consoles::J3D,
    #[cfg(feature = "games")]
    &games::consoles::RARC,
    #[cfg(feature = "games")]
    &games::consoles::BRRES,
    #[cfg(feature = "games")]
    &games::consoles::GIM,
    #[cfg(feature = "games")]
    &games::consoles::GXT,
    #[cfg(feature = "games")]
    &games::consoles::RCO,
    #[cfg(feature = "games")]
    &games::consoles::NPD,
    #[cfg(feature = "games")]
    &games::consoles::XDBF,
    #[cfg(feature = "games")]
    &games::consoles::XPR,
    #[cfg(feature = "games")]
    &games::consoles::XACT,
    #[cfg(feature = "games")]
    &games::consoles::SEGA_TEXTURE,
    #[cfg(feature = "games")]
    &games::consoles::NINJA,
    #[cfg(feature = "av")]
    &tracker::pc::PTM,
    #[cfg(feature = "av")]
    &tracker::pc::DMF,
    #[cfg(feature = "av")]
    &tracker::pc::IMF,
    #[cfg(feature = "av")]
    &tracker::pc::J2B,
    #[cfg(feature = "av")]
    &tracker::pc::GDM,
    #[cfg(feature = "av")]
    &tracker::pc::MT2,
    #[cfg(feature = "av")]
    &tracker::pc::AMS,
    #[cfg(feature = "av")]
    &tracker::pc::SYMPHONIE,
    #[cfg(feature = "av")]
    &tracker::pc::DIGITRAKKER,
    #[cfg(feature = "av")]
    &tracker::pc::PLM,
    #[cfg(feature = "av")]
    &tracker::pc::PSM,
    #[cfg(feature = "av")]
    &tracker::pc::AMF,
    #[cfg(feature = "av")]
    &tracker::pc::GUS_PAT,
    #[cfg(feature = "av")]
    &audio::codecs::REALAUDIO,
    #[cfg(feature = "av")]
    &audio::codecs::PSION_WVE,
    #[cfg(feature = "av")]
    &audio::codecs::EVS,
    #[cfg(feature = "av")]
    &video::movies::SMUSH,
    #[cfg(feature = "av")]
    &video::movies::DXA,
    #[cfg(feature = "av")]
    &video::movies::ARMOVIE,
    #[cfg(feature = "av")]
    &video::movies::SGI_MOVIE,
    // Weak, size-based probes last.
    #[cfg(feature = "games")]
    &games::consoles::BYML,
    #[cfg(feature = "archive")]
    &compression::legacy::SQUEEZE,
    #[cfg(feature = "archive")]
    &compression::legacy::CRUNCH,
    #[cfg(feature = "games")]
    &games::minecraft::NBT,
    #[cfg(feature = "science")]
    &geo::elevation::HGT,
    #[cfg(feature = "system")]
    &forensics::unix::UTMP,
    #[cfg(feature = "system")]
    &forensics::browser::FIREFOX_CACHE2,
    #[cfg(feature = "system")]
    &forensics::logs::ACCT,
    #[cfg(feature = "system")]
    &forensics::windows::RDP_FILE,
    #[cfg(feature = "system")]
    &forensics::unix::LASTLOG,
    #[cfg(feature = "system")]
    &forensics::windows::DESTLIST,
    #[cfg(feature = "system")]
    &forensics::windows::AUTORUN,
    #[cfg(feature = "system")]
    &forensics::windows::DESKTOP_INI,
    #[cfg(feature = "science")]
    &engineering::models::STL,
    // A ZIP after a stub or other data (its end record at the very end).
    #[cfg(feature = "archive")]
    &archive::zip::PREFIXED,
    // -- end misc --

    // -- text (generic probes, keep last) --
    // Documents with a fixed signature.
    #[cfg(feature = "text")]
    &text::rtf::FORMAT,
    #[cfg(feature = "text")]
    &text::postscript::DOS_EPS,
    #[cfg(feature = "text")]
    &text::postscript::EPS,
    #[cfg(feature = "text")]
    &text::postscript::POSTSCRIPT,
    // Binary formats found inside text armor.
    #[cfg(feature = "text")]
    &text::ssh::BLOB,
    // Armor and keys.
    #[cfg(feature = "text")]
    &text::pem::SSH2,
    #[cfg(feature = "text")]
    &text::ssh::KEYS,
    // Messages (header blocks look like YAML; keep them before it).
    #[cfg(feature = "text")]
    &text::mime::MBOX,
    #[cfg(feature = "text")]
    &text::mime::MHTML,
    #[cfg(feature = "text")]
    &text::mime::EML,
    #[cfg(feature = "text")]
    &text::yenc::FORMAT,
    #[cfg(feature = "text")]
    &text::ldif::FORMAT,
    #[cfg(feature = "text")]
    &text::diff::FORMAT,
    #[cfg(feature = "text")]
    &text::vcard::VCARD,
    #[cfg(feature = "text")]
    &text::vcard::ICALENDAR,
    // Timed text and playlists.
    #[cfg(feature = "text")]
    &text::subtitles::WEBVTT,
    #[cfg(feature = "text")]
    &text::subtitles::SRT,
    #[cfg(feature = "text")]
    &text::subtitles::LRC,
    #[cfg(feature = "text")]
    &text::playlist::HLS,
    #[cfg(feature = "text")]
    &text::playlist::M3U,
    #[cfg(feature = "text")]
    &text::playlist::PLS,
    #[cfg(feature = "text")]
    &text::playlist::CUE,
    #[cfg(feature = "text")]
    &text::subtitles::MICRODVD,
    #[cfg(feature = "text")]
    &text::sln::FORMAT,
    #[cfg(feature = "text")]
    &text::klc::FORMAT,
    #[cfg(feature = "text")]
    &text::dockerfile::FORMAT,
    #[cfg(feature = "text")]
    &text::dot::FORMAT,
    // Line-oriented data with distinctive keywords.
    #[cfg(feature = "text")]
    &text::uuencode::FORMAT,
    #[cfg(feature = "text")]
    &text::po::FORMAT,
    #[cfg(feature = "text")]
    &text::bibtex::FORMAT,
    #[cfg(feature = "text")]
    &text::checksums::FORMAT,
    #[cfg(feature = "text")]
    &text::obj::OBJ,
    #[cfg(feature = "text")]
    &text::obj::MTL,
    // Markup: specific XML vocabularies, then HTML, then generic XML.
    #[cfg(feature = "text")]
    &text::plist::FORMAT,
    #[cfg(feature = "text")]
    &text::xml::XHTML,
    #[cfg(feature = "text")]
    &text::xml::SVG,
    #[cfg(feature = "text")]
    &text::xml::RSS,
    #[cfg(feature = "text")]
    &text::xml::ATOM,
    #[cfg(feature = "text")]
    &text::xml::GPX,
    #[cfg(feature = "text")]
    &text::xml::KML,
    #[cfg(feature = "text")]
    &text::xml::POM,
    #[cfg(feature = "text")]
    &text::xml::XAML,
    #[cfg(feature = "text")]
    &text::xml::MATHML,
    #[cfg(feature = "text")]
    &text::xml::XSLT,
    #[cfg(feature = "text")]
    &text::xml::XSD,
    #[cfg(feature = "text")]
    &text::xml::MSBUILD,
    #[cfg(feature = "text")]
    &text::xml::COLLADA,
    #[cfg(feature = "text")]
    &text::xml::TTML,
    #[cfg(feature = "text")]
    &text::xml::DASH,
    #[cfg(feature = "text")]
    &text::xml::XLIFF,
    #[cfg(feature = "text")]
    &text::xml::OPF,
    #[cfg(feature = "text")]
    &text::xml::OSM,
    #[cfg(feature = "text")]
    &text::xml::XSPF,
    #[cfg(feature = "text")]
    &text::xml::TEI,
    #[cfg(feature = "text")]
    &text::xml::DOCBOOK,
    #[cfg(feature = "text")]
    &text::xml::ANDROID_MANIFEST,
    #[cfg(feature = "text")]
    &text::xml::WSDL,
    #[cfg(feature = "text")]
    &text::xml::SOAP,
    #[cfg(feature = "text")]
    &text::xml::SITEMAP,
    #[cfg(feature = "text")]
    &text::xml::DRAWIO,
    #[cfg(feature = "text")]
    &text::xml::OPML,
    #[cfg(feature = "text")]
    &text::xml::FB2,
    #[cfg(feature = "text")]
    &text::xml::GRAPHML,
    #[cfg(feature = "text")]
    &text::xml::SMIL,
    #[cfg(feature = "text")]
    &text::xml::NZB,
    #[cfg(feature = "text")]
    &text::xml::JUNIT,
    #[cfg(feature = "text")]
    &text::xml::MUSICXML,
    #[cfg(feature = "av")]
    &audio::guitar_pro::gpif::FORMAT,
    #[cfg(feature = "text")]
    &text::xml::X3D,
    #[cfg(feature = "text")]
    &text::xml::WIX,
    #[cfg(feature = "text")]
    &text::xml::NUSPEC,
    #[cfg(feature = "text")]
    &text::xml::XIB,
    #[cfg(feature = "text")]
    &text::xml::GLADE,
    #[cfg(feature = "text")]
    &text::xml::FLAT_ODF,
    #[cfg(feature = "text")]
    &text::xml::VSTEMPLATE,
    #[cfg(feature = "text")]
    &text::html::FORMAT,
    #[cfg(feature = "text")]
    &text::xml::FORMAT,
    // JSON and its vocabularies.
    #[cfg(feature = "text")]
    &text::json::IPYNB,
    #[cfg(feature = "text")]
    &text::json::GLTF,
    #[cfg(feature = "text")]
    &text::json::JSON_SCHEMA,
    #[cfg(feature = "text")]
    &text::json::TOPOJSON,
    #[cfg(feature = "text")]
    &text::json::WEB_MANIFEST,
    #[cfg(feature = "text")]
    &text::json::EXTENSION_MANIFEST,
    #[cfg(feature = "text")]
    &text::json::LOTTIE,
    #[cfg(feature = "text")]
    &text::json::EXCALIDRAW,
    #[cfg(feature = "text")]
    &text::json::SARIF,
    #[cfg(feature = "text")]
    &text::json::OPENAPI,
    #[cfg(feature = "text")]
    &text::json::TSCONFIG,
    #[cfg(feature = "text")]
    &text::json::NPM_PACKAGE,
    #[cfg(feature = "text")]
    &text::json::GEOJSON,
    #[cfg(feature = "text")]
    &text::json::HAR,
    #[cfg(feature = "text")]
    &text::json::NDJSON,
    #[cfg(feature = "text")]
    &text::json::FORMAT,
    // TOML before INI: its values are typed, INI's are not.
    #[cfg(feature = "text")]
    &text::ini::EDITORCONFIG,
    #[cfg(feature = "text")]
    &text::toml::FORMAT,
    // INI family: specific first.
    #[cfg(feature = "text")]
    &text::ini::REG,
    #[cfg(feature = "text")]
    &text::ini::DESKTOP,
    #[cfg(feature = "text")]
    &text::ini::URL,
    #[cfg(feature = "text")]
    &text::ini::SYSTEMD,
    #[cfg(feature = "text")]
    &text::ini::INF,
    #[cfg(feature = "text")]
    &text::ini::ASS,
    #[cfg(feature = "text")]
    &text::ini::FORMAT,
    // Markdown before YAML: front matter starts like a YAML document.
    #[cfg(feature = "text")]
    &text::markdown::FORMAT,
    #[cfg(feature = "text")]
    &text::yaml::KUBERNETES,
    #[cfg(feature = "text")]
    &text::yaml::COMPOSE,
    #[cfg(feature = "text")]
    &text::yaml::GITHUB_WORKFLOW,
    #[cfg(feature = "text")]
    &text::yaml::OPENAPI,
    #[cfg(feature = "text")]
    &text::yaml::FORMAT,
    #[cfg(feature = "text")]
    &text::plain::SCRIPT,
    // Cap'n Proto has no magic: a segment table that accounts for exactly
    // the whole file (after everything with magic).
    #[cfg(feature = "data")]
    &data::wire::capnp::FORMAT,
    // Brotli has no magic: only small files that decode as exactly one
    // complete stream (a trial decode, so after everything with magic).
    #[cfg(feature = "archive")]
    &compression::brotli::FORMAT,
    // Magic-less binary value encodings: only whole small files that parse
    // exactly to their end as one record (see each module).
    #[cfg(feature = "data")]
    &data::msgpack::FORMAT,
    #[cfg(feature = "data")]
    &data::ubjson::FORMAT,
    #[cfg(feature = "data")]
    &data::bson::FORMAT,
    // Weak, statistical probes.
    #[cfg(feature = "text")]
    &text::csv::TSV,
    #[cfg(feature = "text")]
    &text::csv::CSV,
    // Plain text matches anything textual: keep it last.
    #[cfg(feature = "text")]
    &text::plain::FORMAT,
    // -- end text --
];

/// The format registered as `name`.
pub fn by_name(name: &str) -> Option<&'static Format> {
    REGISTRY.by_name(name)
}

/// See [`Registry::by_extension`].
pub fn by_extension(extension: &str) -> Vec<&'static Format> {
    REGISTRY.by_extension(extension)
}

/// Picks the first format whose probe matches.
pub fn identify(head: &Head<'_>) -> Option<&'static Format> {
    REGISTRY.identify(head)
}
