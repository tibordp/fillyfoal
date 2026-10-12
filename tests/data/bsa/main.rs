//! Writes the BSA and BA2 fixtures with the `ba2` crate 3.0.1 (0BSD,
//! https://github.com/Ryan-rsm-McKenzie/bsa-rs). Run by make.sh as the
//! `main.rs` of a throwaway cargo project that depends on `ba2 = "=3.0.1"`.
//!
//! Usage: ba2w IN_DIR OUT_DIR, where IN_DIR holds the loose files make.sh
//! writes (readme.txt, data.bin, notes.txt, tiny.dds).

use ba2::prelude::*;
use ba2::{fo4, tes4, BString, Borrowed, CompressionResult};
use std::fs;
use std::path::Path;

fn tes4_archive(
    dir: &Path,
    out: &Path,
    version: tes4::Version,
    flags: tes4::ArchiveFlags,
) -> anyhow::Result<()> {
    let compressed = tes4::FileReadOptions::builder()
        .version(version)
        .compression_result(CompressionResult::Compressed)
        .build();
    let stored = tes4::FileReadOptions::builder()
        .version(version)
        .compression_result(CompressionResult::Decompressed)
        .build();
    let readme = fs::read(dir.join("readme.txt"))?;
    let data = fs::read(dir.join("data.bin"))?;
    let notes = fs::read(dir.join("notes.txt"))?;
    // readme and notes.txt follow the archive's default; data.bin is stored
    // raw in a compressed archive, so its size carries the 0x40000000 toggle.
    let readme = tes4::File::read(Borrowed(&readme), &compressed)?;
    let data = tes4::File::read(Borrowed(&data), &stored)?;
    let notes = tes4::File::read(Borrowed(&notes), &compressed)?;
    let docs: tes4::Directory = [
        (tes4::DirectoryKey::from("readme.txt"), readme),
        (tes4::DirectoryKey::from("data.bin"), data),
    ]
    .into_iter()
    .collect();
    let meshes: tes4::Directory = [(tes4::DirectoryKey::from("notes.txt"), notes)]
        .into_iter()
        .collect();
    let archive: tes4::Archive = [
        (tes4::ArchiveKey::from("docs"), docs),
        (tes4::ArchiveKey::from("meshes\\clutter"), meshes),
    ]
    .into_iter()
    .collect();
    let options = tes4::ArchiveOptions::builder()
        .version(version)
        .flags(flags)
        .types(tes4::ArchiveTypes::MESHES | tes4::ArchiveTypes::MISC)
        .build();
    let mut file = fs::File::create(out)?;
    archive.write(&mut file, &options)?;
    Ok(())
}

fn fo4_archive(
    dir: &Path,
    out: &Path,
    format: fo4::Format,
    version: fo4::Version,
    compression: fo4::CompressionFormat,
) -> anyhow::Result<()> {
    let read = fo4::FileReadOptions::builder()
        .format(format)
        .compression_format(compression)
        .compression_result(CompressionResult::Compressed)
        .build();
    let names: &[&str] = match format {
        fo4::Format::DX10 => &["tiny.dds"],
        _ => &["readme.txt", "notes.txt"],
    };
    let loose = names
        .iter()
        .map(|name| fs::read(dir.join(name)))
        .collect::<Result<Vec<_>, _>>()?;
    let mut entries = Vec::new();
    for (name, bytes) in names.iter().zip(&loose) {
        let file = fo4::File::read(Borrowed(bytes), &read)?;
        let path: BString = match format {
            fo4::Format::DX10 => format!("Textures\\Props\\{name}").into(),
            _ => format!("Misc\\{name}").into(),
        };
        entries.push((fo4::ArchiveKey::from(path), file));
    }
    let archive: fo4::Archive = entries.into_iter().collect();
    let options = fo4::ArchiveOptions::builder()
        .format(format)
        .version(version)
        .compression_format(compression)
        .strings(true)
        .build();
    let mut file = fs::File::create(out)?;
    archive.write(&mut file, &options)?;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let dir = Path::new(&args[1]);
    let out = Path::new(&args[2]);
    use tes4::ArchiveFlags as F;
    let names = F::DIRECTORY_STRINGS | F::FILE_STRINGS;
    tes4_archive(dir, &out.join("v104.bsa"), tes4::Version::v104, names | F::COMPRESSED)?;
    tes4_archive(
        dir,
        &out.join("v105-embedded.bsa"),
        tes4::Version::v105,
        names | F::COMPRESSED | F::EMBEDDED_FILE_NAMES,
    )?;
    fo4_archive(dir, &out.join("gnrl-v1.ba2"), fo4::Format::GNRL, fo4::Version::v1, fo4::CompressionFormat::Zip)?;
    fo4_archive(dir, &out.join("gnrl-v2.ba2"), fo4::Format::GNRL, fo4::Version::v2, fo4::CompressionFormat::Zip)?;
    fo4_archive(dir, &out.join("dx10-v3.ba2"), fo4::Format::DX10, fo4::Version::v3, fo4::CompressionFormat::LZ4)?;
    Ok(())
}
