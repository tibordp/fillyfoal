//! Compressed streams: gzip, zlib, bzip2, xz, Zstandard, LZ4 (and Snappy framing),
//! LZMA-family containers, Brotli, Unix `compress` and `pack`, TempleOS
//! `.Z` (`templeos`), MS-DOS SZDD
//! and KWAJ (`szdd`), less common compression containers (`containers`:
//! Apple Archive, LZFSE, pbzx, lzop, LZF, lrzip, zstd dictionaries,
//! PowerPacker, ZPAQ) and old Unix and CP/M compressors (`legacy`: freeze,
//! compact, squeeze, crunch).

pub mod brotli;
pub mod bzip2;
pub mod compress;
pub mod containers;
pub mod gzip;
pub mod legacy;
pub mod lz4;
pub mod lzma;
pub mod szdd;
pub mod templeos;
pub mod xz;
pub mod zlib;
pub mod zstd;
