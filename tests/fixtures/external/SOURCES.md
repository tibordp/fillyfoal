# External fixtures

Every file in this tree was written by an implementation other than
fillyfoal's own code: a real tool or library (compressors, archivers,
compilers, FFmpeg, OpenSSL, SQLite, macOS system tools, Python's standard
library, pyarrow, htslib, ...), or found in the wild. Their snapshots are
therefore some evidence of conformance: the dissector agrees with what a
real writer produced.

Policy:

- A fixture belongs here only with positive evidence of its producer: a
  commit message naming the tool, a producer string in the file (`Lavf`,
  `.comment`, `/Producer`, ...), a layout specific to one writer, or, best,
  re-running the tool and getting the same bytes ("reproduced
  byte-for-byte"). The evidence is recorded below.
- Minor edits are allowed and must be listed (scrubbed identifiers,
  truncation to a prefix, re-fixed checksums). Wrapping a disk image in
  `gzip -n`, or in `zstd -19` as `<name>.raw.zst`, for storage (the harness
  decompresses it) is not an edit.
- Anything our scripts assembled around real codec output (a hand-made
  container holding an encoder's frames, a real stream with a hand-made tag
  appended), or whose provenance is unclear, is synthetic and lives in
  `../synthetic/`.
- The content inside a container may be ours (test text, a hand-made PNG);
  what makes a fixture external is that the format named by its directory
  was written by the external implementation.

Every external fixture must be listed here, either by path or by its
`<format>/` directory when one producer made all of them; the
`fixtures_are_classified` test in `tests/formats.rs` checks this. Tool
versions are those that wrote or reproduced the file (FFmpeg outputs embed
libavformat 62.12.102 / libavcodec 62.28.102, i.e. FFmpeg 8).


## Compression tools

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `bzip2/bottles.txt.bz2` | bzip2 1.0.8 | reproduced byte-for-byte: `bzip2 -9` |
| `bzip2/empty.bz2` | bzip2 1.0.8 | reproduced byte-for-byte: `bzip2 -9` of empty input |
| `bzip2/multi-block.bz2` | bzip2 1.0.8 | reproduced byte-for-byte: `bzip2 -1` |
| `bzip2/two-streams.bz2` | bzip2 1.0.8 | two streams back to back: `printf 'first stream\n' \| bzip2 -9 > a.bz2; printf 'second stream, a little longer\n' \| bzip2 -1 > b.bz2; cat a.bz2 b.bz2` (each stream reproduced byte-for-byte) |
| `xz/bottles.txt.xz` | XZ Utils 5.8 | reproduced byte-for-byte: `xz -6` |
| `xz/large-member.tar.xz` | XZ Utils 5.8 | reproduced byte-for-byte: `xz -9`; commit f0d9d8d1 ("fixtures from xz and zstd CLIs"); the tarball inside is the bsdtar ustar archive of gzip/large-member.tar.gz |
| `xz/bcj-powerpc.xz` | XZ Utils 5.8.4 | pseudo machine code from `tests/data/xz/bcjdata.py`, reproduced byte-for-byte by `tests/data/xz/make_bcj.sh`: `xz --check=crc64 --powerpc --lzma2=preset=6` |
| `xz/bcj-ia64.xz` | XZ Utils 5.8.4 | pseudo machine code from `tests/data/xz/bcjdata.py`, reproduced byte-for-byte by `tests/data/xz/make_bcj.sh`: `xz --check=crc64 --ia64 --lzma2=preset=6` |
| `xz/bcj-armthumb.xz` | XZ Utils 5.8.4 | pseudo machine code from `tests/data/xz/bcjdata.py`, reproduced byte-for-byte by `tests/data/xz/make_bcj.sh`: `xz --check=crc64 --armthumb --lzma2=preset=6` |
| `xz/bcj-sparc.xz` | XZ Utils 5.8.4 | pseudo machine code from `tests/data/xz/bcjdata.py`, reproduced byte-for-byte by `tests/data/xz/make_bcj.sh`: `xz --check=crc64 --sparc --lzma2=preset=6` |
| `xz/bcj-riscv.xz` | XZ Utils 5.8.4 | pseudo machine code from `tests/data/xz/bcjdata.py`, reproduced byte-for-byte by `tests/data/xz/make_bcj.sh`: `xz --check=crc64 --riscv --lzma2=preset=6` |
| `xz/bcj-x86-start.xz` | XZ Utils 5.8.4 | pseudo machine code from `tests/data/xz/bcjdata.py`, reproduced byte-for-byte by `tests/data/xz/make_bcj.sh`: `xz --check=crc64 --x86=start=4096 --lzma2=preset=6` |
| `xz/bcj-riscv-start.xz` | XZ Utils 5.8.4 | pseudo machine code from `tests/data/xz/bcjdata.py`, reproduced byte-for-byte by `tests/data/xz/make_bcj.sh`: `xz --check=crc64 --riscv=start=4096 --lzma2=preset=6` |
| `lzma/bottles.txt.lzma` | XZ Utils 5.8 | reproduced byte-for-byte: `xz --format=lzma -6` |
| `zstd/bottles.txt.zst` | zstd 1.5.7 CLI | reproduced byte-for-byte: `zstd -13 FILE` (content size recorded) |
| `zstd/large-member.tar.zst` | zstd 1.5.7 CLI | reproduced byte-for-byte: `zstd -19 FILE`; commit f0d9d8d1 |
| `zstd-dict/words.zdict` | zstd 1.5.7 CLI | reproduced byte-for-byte by `crates/codec/src/codec/testdata/words-dict.sh` (`zstd --train` on 2000-byte pieces of the codec's `words.txt`, `--maxdict=4096 --dictID=4242`); the same file as that directory's `words.zdict` |
| `lz4/bottles.txt.lz4` | lz4 1.10 CLI | reproduced byte-for-byte: `lz4 -9 -BX --content-size FILE` |
| `lz4/uncompressed-block.lz4` | lz4 1.10 CLI | reproduced byte-for-byte: `lz4 -1 --no-frame-crc FILE` |
| `lz4-legacy/legacy.lz4` | lz4 1.10 CLI | reproduced byte-for-byte: `lz4 -l -1` |
| `brotli/page.html.br` | brotli 1.2 CLI | reproduced byte-for-byte: `brotli -q 10 -w 10` (commit 0b9b5a01: "verified against the brotli CLI") |
| `compress/bottles.txt.Z` | macOS compress(1) | reproduced byte-for-byte: `compress -c` |
| `zip/zip64-stdin.zip` | Info-ZIP Zip 3.0 (macOS `/usr/bin/zip`) | `printf 'hello zip64\n' \| zip -q zip64-stdin.zip -`: reading stdin, Info-ZIP writes ZIP64 end records and a ZIP64 extra field |
| `zip/piped-descriptor.zip` | Info-ZIP Zip 3.0 (macOS `/usr/bin/zip`) | `printf 'hello from stdin\n' \| zip -q -X - - \| cat`: writing to a pipe, Info-ZIP sets flag bit 3 and writes a ZIP64 local extra field and a signed data descriptor with 64-bit sizes; the DOS time is when it was made |
| `gzip/png.gz` | macOS gzip | deflate body reproduced byte-for-byte with `gzip -6`; header keeps FNAME `c.png` and its MTIME. The PNG inside is hand-made (synthetic) |
| `gzip/large-member.tar.gz` | macOS gzip + bsdtar 3.5.3 (libarchive 3.7.4) | `gzip -9 -n` of a bsdtar ustar archive (a.txt, a 2 MiB zeros.bin, z.txt). Edited: the tar owner name (uname) of every entry replaced with `fillyfoal` and the header checksums recomputed, then recompressed with the same `gzip -9 -n` (the original recorded the build account's user name) |
| `lzfse/test.lzfse` | macOS compression_tool | reproduced byte-for-byte: `compression_tool -encode -a lzfse` of `hello` |

## Archivers

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `tar/gnutar.tar` | bsdtar 3.5.3 (libarchive 3.7.4) | reproduced byte-for-byte: `bsdtar --format=gnutar --uid 1000 --gid 1000 --uname user --gname group` (mtimes set to 2024-01-02 03:04 UTC) |
| `tar/pax.tar` | bsdtar (libarchive) | libarchive pax writer: `./PaxHeader/...` names, `000755 \0` numeric fields, ctime/atime records; not byte-reproduced (ctime) |
| `tar-v7/v7.tar` | bsdtar 3.5.3 (libarchive 3.7.4) | reproduced byte-for-byte: `bsdtar --format=v7 --uid 1000 --gid 1000` |
| `cpio/newc.cpio` | bsdtar 3.5.3 (libarchive 3.7.4) | `bsdtar --format=newc`; identical to a fresh run except the (real APFS) inode numbers |
| `cpio/odc.cpio` | bsdtar 3.5.3 (libarchive 3.7.4) | reproduced byte-for-byte: `bsdtar --format=odc --uid 1000 --gid 1000` |
| `cpio/bin-le.cpio` | bsdtar 3.5.3 (libarchive 3.7.4) | reproduced byte-for-byte: `bsdtar --format=bin --uid 1000 --gid 1000` |
| `7z/` | 7-Zip (7zz) for macOS | the first ten (the later ones are listed below): lzma-solid-plain, bzip2-solid, lzma2-arm64, delta-lzma2, lzma-arm and lzma-bcj-x86 reproduced byte-for-byte with 7zz 26.03 (`-m0=...` methods as named, `-mhc=off` for plain headers); the other four match in size and layout |
| `zip/mixed.zip` | Info-ZIP Zip 3.0 (macOS /usr/bin/zip) | version made by 3.0/Unix, UT and ux extra fields, archive comment (`zip -z`). The entries (PNG, tar.gz, text) are hand-made. Rebuilt with `zip -q mixed.zip dir/ dir/notes.txt dir/img.png x.tar.gz b.txt` + `zip -z` from the extracted entries (same timestamps) after replacing the tar owner name inside `x.tar.gz` with `fillyfoal` (header checksums recomputed, `gzip -9 -n`); Info-ZIP now marks `b.txt` as text in the internal attributes |
| `zip/zipcrypto.zip` | Info-ZIP Zip 3.0 (macOS /usr/bin/zip) | `zip -e` (ZipCrypto), version made by 3.0/Unix, UT and ux extra fields; password `fillyfoal` |
| `zip/winzip-aes.zip` | bsdtar (libarchive) zip writer | `--options zip:encryption=aes...`; layout (version made by 2.0/Unix, ux before the AES extra, data descriptors) matches a fresh bsdtar run; password `fillyfoal` |
| `zip/encrypted-lzma-bzip2.zip` | 7-Zip (7zz) | two `7zz a -tzip` runs (AES-256 + BZip2, ZipCrypto + LZMA); NTFS extra fields and versions 51/63 as 7-Zip writes them; password `fillyfoal` |
| `7z/deflate64.7z` | 7-Zip (7zz) 26.03 for macOS | reproduced byte-for-byte by `tests/data/7z/make_codecs.sh`: `7zz a -t7z -m0=Deflate64 -mx=9`; content is the deterministic word salad of `tests/data/7z/salad.py`, mtime 2024-01-02 03:04 UTC |
| `7z/ppmd.7z` | 7-Zip (7zz) 26.03 for macOS | reproduced byte-for-byte by `tests/data/7z/make_codecs.sh`: `7zz a -t7z -m0=PPMd:o=6:mem=1m -mhc=off`; content is the deterministic word salad of `tests/data/7z/salad.py`, mtime 2024-01-02 03:04 UTC |
| `7z/bcj-armthumb.7z` | 7-Zip (7zz) 26.03 for macOS | pseudo machine code from `tests/data/xz/bcjdata.py`, reproduced byte-for-byte by `tests/data/xz/make_bcj.sh`: `7zz a -t7z -m0=ARMT -m1=LZMA2 -mhc=off` |
| `7z/bcj-sparc.7z` | 7-Zip (7zz) 26.03 for macOS | pseudo machine code from `tests/data/xz/bcjdata.py`, reproduced byte-for-byte by `tests/data/xz/make_bcj.sh`: `7zz a -t7z -m0=SPARC -m1=LZMA2 -mhc=off` |
| `7z/bcj-riscv.7z` | 7-Zip (7zz) 26.03 for macOS | pseudo machine code from `tests/data/xz/bcjdata.py`, reproduced byte-for-byte by `tests/data/xz/make_bcj.sh`: `7zz a -t7z -m0=RISCV -m1=LZMA2 -mhc=off` |
| `7z/bcj-arm64-start.7z` | 7-Zip (7zz) 26.03 for macOS | pseudo machine code from `tests/data/xz/bcjdata.py`, reproduced byte-for-byte by `tests/data/xz/make_bcj.sh`: `7zz a -t7z -m0=ARM64:4096 -m1=LZMA2 -mhc=off` (ARM64 coder with the 4-byte start offset property 0x1000) |
| `7z/bcj-riscv-start.7z` | 7-Zip (7zz) 26.03 for macOS | pseudo machine code from `tests/data/xz/bcjdata.py`, reproduced byte-for-byte by `tests/data/xz/make_bcj.sh`: `7zz a -t7z -m0=RISCV:4096 -m1=LZMA2 -mhc=off` (RISC-V coder with the start offset property 0x1000) |
| `7z/bcj2.7z` | 7-Zip (7zz) 26.03 for macOS | reproduced byte-for-byte by `tests/data/7z/make_bcj2.sh`: `7zz a -t7z -mf=BCJ2 -m0=LZMA2 -mhc=off` (BCJ2 + LZMA2 + 2 x LZMA, four packed streams) of a stripped x86-64 Mach-O the script builds with Apple clang 21 (`-target x86_64-apple-macos11 -O1`, generated C source); mtime 2024-01-02 03:04 UTC |
| `zip/deflate64.zip` | 7-Zip (7zz) 26.03 for macOS | reproduced byte-for-byte by `tests/data/7z/make_codecs.sh`: `7zz a -tzip -mm=Deflate64 -mx=9` (method 9, NTFS extra field); content is the deterministic word salad of `tests/data/7z/salad.py`, mtime 2024-01-02 03:04 UTC |
| `zip/ppmd.zip` | 7-Zip (7zz) 26.03 for macOS | `tests/data/zip/make_ppmd.sh`: two `7zz a -tzip -mm=PPMd -mtc=off` runs (method 98, PPMd var. I rev. 1 with 7-Zip's default order and memory; the second with `-pfillyfoal`, ZipCrypto, password `fillyfoal`) of generated text, mtime 2024-01-02 03:04 UTC. Byte-for-byte reproducible except the encrypted entry's data (ZipCrypto's random 12-byte header) |
| `xar/files.xar` | macOS xar(1) | TOC has real inode/device numbers and a `com.apple.provenance` extended attribute. Contents `hello.txt` (`hello tar\n`), `sub/pixel.png` and `sub/a-very-long-file-name-...-classic-tar-header.txt` (`x`), all with mtime `TZ=UTC touch -t 202401020304`, in a directory under `/tmp`; `xar -cf files.xar --prop-exclude user hello.txt sub` (no owner user name; uid, gid and group remain) |
| `pbzx/pbz4.aar` | macOS aa (Apple Archive) | `aa archive` with LZ4 compression; entries carry `com.apple.provenance` xattrs |
| `pbzx/pbze.aar` | macOS aa (Apple Archive) | `aa archive` with LZFSE compression; entries carry `com.apple.provenance` xattrs |
| `pbzx/pbzz.aar` | macOS aa (Apple Archive) | `aa archive` with zlib compression |
| `wim/` | wimlib-imagex 1.13.5 (Debian bookworm `wimtools`, Docker) | `tests/data/wim/make.sh`: `wimcapture` of the tree `make_tree.py` writes, image name `fillyfoal`: `lzms.wim` (`--compress=LZMS --chunk-size=32768`), `solid.esd` (`--solid --solid-chunk-size=32768`, solid LZMS), `solid-lzx.wim` (`--solid --solid-compress=LZX --solid-chunk-size=32768`, text file only). Not byte-reproducible (random GUID, creation times in the XML); every stream's SHA-1 in the lookup table checks against our decoding (`codec::wim` tests) |
| `wim/ntfs-acl.wim` | wimlib-imagex 1.13.5 (Debian bookworm `wimtools`, Docker) | `tests/data/wim/make_ntfs.sh`: NTFS volume capture (`wimcapture vol.img ... fillyfoal --compress=XPRESS`) of a 4 MiB volume made by mkntfs (ntfs-3g 2022.10.3, label `fillyfoal`) holding `hello.txt` with a named stream `extra` (both written by `ntfscp`); keeps the volume's two security descriptors and wimlib's extra stream entries. Not byte-reproducible (GUID, times); `wimlib-imagex dir --detailed` lists the same descriptors, hashes and stream names we show |
| `wim/boot.wim` | wimlib-imagex 1.13.5 (Debian bookworm `wimtools`, Docker) | `tests/data/wim/make_boot.sh`: `wimcapture tree boot.wim fillyfoal --boot --compress=XPRESS` of a two-file tree written in the container (mtimes 2024-01-02 03:04:05 UTC); the header's boot index is 1 and its boot metadata resource is the image's metadata resource. Not byte-reproducible (GUID, times in the XML) |
| `rar/` | RAR 6.23 for Linux (RARLAB; Debian bullseye non-free `rar` 2:6.23-1~deb11u1, amd64, Docker) | `tests/data/rar/make_external.sh` (commands in `make_external_inner.sh`), mtimes 2024-01-02 03:04:05 UTC: `v4-unicode.rar` (`-ma4 -m3`, names with the 0x200 Unicode encoding), `v4-solid-real.rar` (`-ma4 -m5 -s`), `v5-unicode.rar` (`-ma5 -m3`), `v5-encrypted.rar` (`-ma5 -pfillyfoal`, data encrypted with password `fillyfoal`), `v5-encrypted-solid.rar` (`-ma5 -m3 -s -r -pfillyfoal`, a solid run of encrypted files), `v5-encrypted-headers.rar` (`-ma5 -m3 -hpfillyfoal`, headers encrypted too). Byte-for-byte reproducible except for the RAR 5 encryption salts and IVs (the solid and header-encrypted ones come from a later run of the same script, which reproduced the others byte for byte) |
| `nsis/` | makensis 3.08 (Debian bookworm `nsis` 3.08-3+deb12u1, Docker) | `tests/data/nsis/make.sh` compiles `installer.nsi` (two files in two directories, a registry value, a shortcut, an uninstaller; payload mtimes 2024-01-02 03:04:05 UTC) as `lzma-solid-unicode` (`SetCompressor /SOLID lzma`, `Unicode true`), `zlib-ansi` (`zlib`, ANSI) and `bzip2-unicode` (`bzip2`). Edited: each fixture is only the installer data makensis appends to its Windows stub, from the first header (at a 512-byte boundary) to the end, cut out by `cut.py`; the stub is left out |

## Disk images (macOS)

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `dmg/fat-udco.dmg` | macOS hdiutil | commit 1aeb76a1 ("fixtures from hdiutil"); ADC (UDCO) chunks |
| `dmg/fat-ulfo.dmg` | macOS hdiutil | commit 1aeb76a1 ("fixtures from hdiutil"); LZFSE (ULFO) chunks |
| `dmg/fat-udzo.dmg` | macOS hdiutil | hdiutil resource-fork plist (`whole disk (DOS_FAT_16 : 0)` blkx names, mish tables) |
| `dmg/hfs-udbz.dmg` | macOS hdiutil | hdiutil resource-fork plist (`whole disk (Apple_HFS : 0)`), bzip2 chunks |
| `dmg/fat-ulmo.dmg` | macOS hdiutil | hdiutil resource-fork plist (`Master Boot Record (MBR : 0)` ...), LZMA (ULMO) chunks |
| `apfs/apfs.img.gz` | macOS newfs_apfs 2811.120.14.0.1 | formatter string in the superblock; populated on a mounted volume. Edit: `tests/data/apfs/scrub.py` zeroes the app id in its six `com.apple.provenance` attributes and recomputes the Fletcher-64 checksum of the block holding them. Stored with `gzip -9 -n` (the harness inflates it) |
| `apfs/tree.img.gz` | macOS 26.5 hdiutil/newfs_apfs and the APFS driver, `ditto --hfsCompression`, `ln`, `xattr` | `sh tests/data/apfs/make.sh <dir>`: a 4 MiB container with a directory tree, a file in several extents, a sparse file, a decmpfs LZVN file (`com.apple.ResourceFork`), a hard link pair, a symbolic link, a small and an 8 KiB (data stream) extended attribute. Edit: `tests/data/apfs/scrub.py` zeroes the 8-byte app id in each `com.apple.provenance` attribute and recomputes the Fletcher-64 checksum of the blocks it touched. Not byte-reproducible. Stored with `gzip -9 -n` |
| `exfat/exfat.img.gz` | macOS newfs_exfat | populated on a mounted volume (AppleDouble `._` files with `com.apple.provenance`). Stored with `gzip -n` |
| `hfsplus/hfsplus.img.gz` | macOS (newfs_hfs/hdiutil, inferred) | last-mounted version `10.0` (macOS); not byte-reproduced. Edit: `tests/data/hfsplus/scrub.py` zeroes the app id in its six `com.apple.provenance` attributes. Stored with `gzip -9 -n` |
| `hfsplus/features.img.gz` | macOS 26.5 hdiutil/newfs_hfs and the HFS+ driver, `ditto --hfsCompression`, `ln`, `xattr` | `sh tests/data/hfsplus/make.sh <dir>`: a 2 MiB volume with a 12-block file in 10 extents (two in the extents overflow file), two decmpfs LZVN resource-fork files, a hard link pair and an extended attribute. Edit: `tests/data/hfsplus/scrub.py` zeroes the 8-byte app id in each `com.apple.provenance` attribute the sandbox added. Not byte-reproducible (dates, ids). Stored with `gzip -9 -n` |
| `udf/udf-1.02.iso.gz` | macOS hdiutil (DiscRecording 9.0.3d5) | `sh tests/data/udf/gen.sh tests/fixtures/external` (`hdiutil makehybrid -udf -udf-version 1.02` / `1.50`; 2.00 and 2.01 produce the same bytes as 1.50); not byte-reproducible (recording times, volume set ID). Stored with `gzip -9 -n` |
| `udf/udf-1.50.iso.gz` | macOS hdiutil (DiscRecording 9.0.3d5) | same script, `-udf-version 1.50`; not byte-reproducible. Stored with `gzip -9 -n` |
| `iso9660/udf-bridge.iso.gz` | macOS hdiutil (DiscRecording 9.0.3d5) | same script: `hdiutil makehybrid -iso -udf` (ISO 9660 with Rock Ridge plus a UDF 1.50 bridge); not byte-reproducible |
| `iso9660/pycdlib-udf.iso.gz` | pycdlib 1.21.0 | same script: `uv run --with pycdlib==1.21.0 python tests/data/udf/pycdlib_udf.py` (`udf="2.60"`, though the descriptors it writes say UDF 1.02 and NSR02; includes a UDF symlink); not byte-reproducible (timestamps) |
| `swap/mkswap.img` | util-linux mkswap | commit 3dc63ea4 ("a real mkswap fixture"); label `realswap`, UUID chosen with `-U` |

## Disk images (Linux filesystem tools)

Made in a Debian trixie container (`tests/data/linux-fs/Dockerfile`, built as
`fillyfoal-fs-tools`) by the scripts next to it, which list the exact
commands; run each as its header says, with `--hostname fillyfoal` and the
output in `/tmp/fixtures/fs-*`. The populated tree is
`tests/data/linux-fs/tree.sh` (plus a few extended attributes). Images whose
smallest size is megabytes of zeros are stored as `<name>.raw.zst`
(`zstd -19`; the harness decompresses them). "Mounted" images were filled
through the kernel driver on a loop mount (`--privileged`), so their inode
change times and logs carry the time of the run and they are not
byte-reproducible; the others are (the scripts fix UUIDs, labels and times).

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `xfs/v4.xfs.raw.zst` | xfsprogs 6.13 mkfs.xfs | `make-xfs.sh`: `mkfs.xfs -m crc=0,uuid=… -b size=4096 -d agcount=2 -i size=256 -p proto` (a prototype file, no mount; `TEST_DIR`/`TEST_DEV`/`QA_CHECK_FS` allow a 32 MiB image) |
| `xfs/v5.xfs.raw.zst` | xfsprogs 6.13 mkfs.xfs, Linux 7.0 xfs | `make-xfs.sh`: `mkfs.xfs -m uuid=… -b size=1024 -d agcount=2 -i size=512`, then mounted and filled (short-form, block and leaf directories, a B+tree extent map, unwritten and reflinked extents, short-form/leaf/node attributes with a remote value, a POSIX ACL, bigtime timestamps before 1970 and after 2038) ; then `xfs_repair -L` gives it a fresh log holding only an unmount record (xfsprogs 6.13; regenerated 2026-10 to keep the snapshot under the size cap) |
| `erofs/` | erofs-utils 1.8.6 mkfs.erofs | `make-erofs.sh`: reproducible (`-T`, `-U`, `--all-root`, `--workers=1`); uncompressed with chunk-based files (block map and index forms), compact and extended inodes, shared and inline xattrs, a long xattr prefix; LZ4HC (big clusters, compact 2-byte index, fragments, dedupe), MicroLZMA (full index), DEFLATE (tail packing) and Zstandard. `plain` and `chunk-indexes` are stored as `.raw.zst` |
| `ext/mke2fs-ext2.img.raw.zst` | e2fsprogs 1.47.2 mke2fs | `make-ext.sh`: `mke2fs -t ext2 -b 1024 -d tree` (block maps with double indirect blocks), then `e2fsck -fyD` (which stamps the run's time) |
| `ext/mke2fs-ext3.img.raw.zst` | e2fsprogs 1.47.2 mke2fs | `make-ext.sh`: `mke2fs -t ext3 -J size=1 -d tree`, `e2fsck -fyD` (an htree directory, a journal) |
| `ext/mke2fs-ext4.img.raw.zst` | e2fsprogs 1.47.2 mke2fs | `make-ext.sh`: `mke2fs -t ext4 -O inline_data,^resize_inode -J size=1 -d tree`, `e2fsck -fyD` (extents, flex_bg, metadata_csum, inline data, an htree directory, attribute blocks, an orphan file, a journal) |
| `ext/mke2fs-metabg.img.raw.zst` | e2fsprogs 1.47.2 mke2fs | `make-ext.sh`: `mke2fs -t ext4 -b 1024 -O meta_bg,^resize_inode,^has_journal -g 256 -N 160 -d tree` (20 groups, 16 descriptors per block: groups 16-19 keep their descriptors in their own meta group; 140 empty files put inodes there), `e2fsck -fyD` |
| `ext/jbd2-dirty.img.raw.zst` | e2fsprogs 1.47.2 mke2fs, debugfs, e2fsck | `make-jbd2.sh`: `mke2fs -t ext4 -J size=1`, then debugfs `jo -c` / `jw` / `jc` write three JBD2 transactions with v3 checksums (data blocks, a revoke block), e2fsck replays them, and three more blocks in transaction 5 leave a stale revoke block of transaction 2 behind the log's end (needs recovery). debugfs stamps the commit blocks with the run's clock (`E2FSPROGS_FAKE_TIME` does not reach it) and puts the seconds in the high half of the big-endian `h_commit_sec`, so the commit time decodes as a date far in the future; not byte-reproducible |
| `xfs/wrapped-log.xfs.raw.zst` | xfsprogs 6.13 mkfs.xfs, Linux 7.0 xfs | `make-xfs-wrapped.sh` (mounted, `--privileged`): 16 MiB, 1 KiB blocks, the default 5.2 MiB log; 240 rounds of creating and removing 50 files wrap the log once (cycle 2, tail 6182, head 6233 by `xfs_logprint`), then `xfs_io -x -c shutdown` leaves it dirty |
| `xfs/split-log.xfs.raw.zst` | xfsprogs 6.13 mkfs.xfs, Linux 7.0 xfs | `make-xfs-split.sh` (mounted, `--privileged`): as wrapped-log, but files are created and removed one at a time until `xfs-split-check.py` sees the newest record's header at block 10719 of 10726 with its data continuing at the log's start, then `xfs_io -x -c shutdown`; `xfs_logprint -t` gives tail 10319, head 3, dirty. Not byte-reproducible (kernel timing) |
| `ufs/makefs-ufs1.img.raw.zst` | NetBSD makefs (Debian 20190105-3, debian:trixie-slim) | `make-ufs-nilfs.sh` (plain `debian:trixie-slim`, packages installed by the script): `makefs -t ffs -o version=1 -s 1m -T 1704067200` from a small tree; little-endian (built on arm64) |
| `ufs/makefs-ufs2.img.raw.zst` | NetBSD makefs (Debian 20190105-3, debian:trixie-slim) | `make-ufs-nilfs.sh`: the same with `-o version=2` |
| `ufs/makefs-tree-ufs1.img.raw.zst` | NetBSD makefs (Debian 20190105-3, debian:trixie-slim) | `make-ufs-tree.sh`: `makefs -t ffs -o version=1,bsize=4096,fsize=512,maxbpcg=512 -s 8m -T 1704067200` (four cylinder groups) from a tree with a 229 KiB file (single indirect block), a sparse file, nested directories, a 40-entry directory and short and long symbolic links; little-endian. makefs stamps change times with the time of the run, so not byte-reproducible; contents checked by `tests/ufs_tree.rs` |
| `ufs/makefs-tree-be-ufs2.img.raw.zst` | NetBSD makefs (as above) | `make-ufs-tree.sh`: the same tree with `-B be -o version=2,maxbpcg=128 -s 2m` (big-endian UFS2, two cylinder groups) |
| `nilfs2/mkfs.nilfs2.img.raw.zst` | nilfs-tools 2.2.11 mkfs.nilfs2 | `make-ufs-nilfs.sh`: `mkfs.nilfs2 -L fillyfoal -b 1024 -B 256` on 8 MiB (empty; random UUID and current time) |
| `squashfs/` | squashfs-tools 4.6.1 mksquashfs | `make-squashfs.sh`: reproducible; `-b 16K -xattrs` with gzip, LZMA, LZO, xz, LZ4 and zstd, and `-no-compression -no-fragments -no-exports` for `mksquashfs-plain.sqfs` |
| `btrfs/` | btrfs-progs 6.14 mkfs.btrfs | `make-btrfs.sh`: `mkfs.btrfs -r tree --shrink` (and `--compress zstd`; `lzo.btrfs.raw.zst`: `--compress lzo` with an extra 311 KiB `big.txt` in three 128 KiB extents); the chunk tree UUID is random, so not byte-reproducible |
| `f2fs/sload.f2fs.raw.zst` | f2fs-tools 1.16 mkfs.f2fs, sload.f2fs | `make-f2fs.sh`: `mkfs.f2fs -T … -U … -O extra_attr,inode_checksum,sb_checksum,inode_crtime`, `sload.f2fs -f tree`; the script bind-mounts a neutral `/proc/version` (`Linux version 6.12.0 (fillyfoal@fillyfoal)`), which the superblock records |
| `f2fs/large-nat.f2fs.raw.zst` | f2fs-tools 1.16 mkfs.f2fs | `make-f2fs.sh`: `mkfs.f2fs -i -T … -U … -l fillyfoal` on 64 MiB (empty; LARGE_NAT_BITMAP, so the checkpoint checksum sits at offset 192), same neutral `/proc/version` |
| `jfs/mkfs.jfs.raw.zst` | jfsutils 1.1.15 mkfs.jfs | `make-small.sh`: an empty 16 MiB aggregate (no tool fills JFS without a mount, and the kernel used has no JFS); random UUID |
| `cramfs/mkcramfs.cramfs` | util-linux 2.41 mkfs.cramfs | `make-small.sh`: `mkfs.cramfs -N little -n fillyfoal tree` |
| `cramfs/mkcramfs-padded.cramfs` | util-linux 2.41 mkfs.cramfs | `make-small.sh`: `mkfs.cramfs -p -N little -n fillyfoal tree` (a zero 512-byte boot block in front) |
| `minix/` | util-linux 2.41 mkfs.minix | `make-small.sh`: empty 64 KiB filesystems of versions 1, 2 and 3 (`mkfs.minix -1/-2/-3`; no tool fills them without a mount) |
| `fat/` | dosfstools 4.2 mkfs.fat, mtools 4.0 | `make-fat.sh`: `mkfs.fat -F 12/16/32 -i … -n FILLYFOAL`, filled with `mcopy -s -m` (long names, subdirectories) under `SOURCE_DATE_EPOCH` |
| `exfat/linux-exfat.img.raw.zst` | exfatprogs mkfs.exfat, Linux 7.0 exfat | `make-fat.sh`: `mkfs.exfat -L fillyfoal -c 4K -b 4K`, mounted and filled; random volume serial |
| `ntfs/mkntfs.img.raw.zst` | ntfs-3g 2022.10 mkntfs, Linux 7.0 ntfs3 | `make-fat.sh`: `mkntfs -T -F -L fillyfoal` (1100 KiB), mounted with ntfs3 and filled. 128 KiB compressed: the 128 KiB `$UpCase` table does not compress |
## Disk images (Linux tools)

All made by `sh tests/data/disk/make-fixtures.sh` in a Debian trixie
container (`tests/data/disk/Dockerfile`, host name `fillyfoal`) running
`tests/data/disk/inner.sh`; the commands are in that script. Tools: QEMU
10.0.13 (`qemu-img`, `qemu-io`), util-linux 2.41 `sfdisk`, gdisk 1.0.10
`sgdisk`, mtools `mformat`/`mcopy`, xorriso 1.5.6, genisoimage 1.1.11,
udftools 2.3 `mkudffs`, cryptsetup 2.7.5. None is byte-reproducible
(timestamps, random UUIDs and salts). The guest content is a small FAT
volume (`mkfs.fat`, two text files). Images over 64 KiB are stored whole as
`<name>.raw.zst` (`zstd -19`; the harness decompresses them).

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `qcow/qemu-v1.qcow` | qemu-img | `qemu-img convert -O qcow -c` (QCOW version 1, compressed clusters) |
| `qcow/qemu-v2-backing.qcow2` | qemu-img, qemu-io | `qemu-img create -o compat=0.10,cluster_size=4096 -b base.qcow2 -F qcow2`, then plain and compressed writes; backing file not included |
| `qcow/qemu-v3.qcow2` | qemu-img, qemu-io | `compat=1.1,cluster_size=4096`: zero and compressed clusters, internal snapshot, writes after it (copy on write), persistent bitmap |
| `qcow/qemu-extl2-zstd.qcow2.raw.zst` | qemu-img, qemu-io | `extended_l2=on,cluster_size=16k,compression_type=zstd`: subcluster writes and zeroes, a zstd-compressed cluster |
| `qcow/qemu-luks.qcow2.raw.zst` | qemu-img | `encrypt.format=luks` (passphrase `fillyfoal`); edit: LUKS key material zeroed (`zero-key-material.py`) |
| `qcow/qemu-datafile.qcow2` | qemu-img | `data_file=qemu-datafile.raw,data_file_raw=on`; data file not included |
| `vmdk/qemu-monolithic-sparse.vmdk.raw.zst` | qemu-img | `convert -O vmdk -o subformat=monolithicSparse` (redundant grain tables) |
| `vmdk/qemu-stream-optimized.vmdk.raw.zst` | qemu-img | `subformat=streamOptimized` (QEMU keeps the tables up front; compressed grains with grain markers) |
| `vmdk/qemu-twogb-s001.vmdk.raw.zst` | qemu-img | the extent of `subformat=twoGbMaxExtentSparse` (no embedded descriptor) |
| `vmdk-descriptor/qemu-twogb.vmdk` | qemu-img | its descriptor file |
| `vmdk-descriptor/qemu-flat.vmdk` | qemu-img | `subformat=monolithicFlat,hwversion=6` descriptor (flat extent not included) |
| `vhd/qemu-dynamic.vhd.raw.zst` | qemu-img | `convert -O vpc -o subformat=dynamic` |
| `vhd/qemu-fixed.vhd.raw.zst` | qemu-img | `subformat=fixed` |
| `vhdx/qemu-dynamic.vhdx.raw.zst` | qemu-img, qemu-io | `convert -O vhdx -o subformat=dynamic,block_size=1M`, then a write (leaves a log entry) |
| `mbr/sfdisk-extended.img.raw.zst` | sfdisk, mtools | `sfdisk` script with primary, extended and logical partitions and gaps; FAT in partition 1 (`mformat -i img@@32768`) |
| `gpt/sgdisk.img.raw.zst` | sgdisk, mtools | five partitions with names, type codes, fixed GUIDs and attributes (`-A 3:set:2`, `-A 4:set:60/63`); FAT in the ESP |
| `gpt/sgdisk-hybrid.img.raw.zst` | sgdisk | the same, then `sgdisk -h 1:3` (hybrid MBR) |
| `iso9660/xorriso-eltorito.iso.raw.zst` | xorriso | Rock Ridge (symlinks, device node, long names), Joliet, zisofs (`-set_filter_r --zisofs`), El Torito BIOS and UEFI entries |
| `iso9660/genisoimage-1999.iso.raw.zst` | genisoimage | `-iso-level 4` (enhanced volume descriptor), Joliet, Rock Ridge 1.09 (`RR`), floppy-emulation El Torito |
| `iso9660/genisoimage-relocated.iso.raw.zst` | genisoimage | `-R`: deep directories relocated to `rr_moved` (`CL`/`PL`/`RE`), a long name continued in a `CE` area, device node, symlink |
| `udf/mkudffs.udf.raw.zst` | mkudffs (udftools 2.3) | `mkudffs --media-type=hd --blocksize=2048` on a 1 MiB file (empty UDF 2.01 volume) |
| `luks/cryptsetup-luks1.img.raw.zst` | cryptsetup | `luksFormat --type luks1` (aes-cbc-essiv:sha256), `luksAddKey`; edits: truncated after 4 KiB of payload, key material zeroed |
| `luks/cryptsetup-luks2.img.raw.zst` | cryptsetup | `luksFormat --type luks2` (argon2id), `luksAddKey --pbkdf pbkdf2`, `config --priority prefer`, `token import`; edits: truncated after 4 KiB of payload, keyslot areas zeroed |

## Compilers, linkers and toolchains

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `elf/aarch64-debug.o` | Apple clang 21.0.0 | `.comment` and DWARF producer; source `tests/data/elf/obj.c` (its MD5 matches the DWARF line table's). Built in `/tmp/fixtures/elf` with `clang --target=aarch64-linux-gnu -O2 -g -gz=zlib -ffile-prefix-map=/tmp/fixtures/elf=$P -fdebug-prefix-map=/tmp/fixtures/elf=$P -c obj.c -o aarch64-debug.o`, `P=/build/fillyfoal/tests/fixtures/external/elf/aarch64-debug` (a path long enough that `.debug_str` is still worth compressing), so `DW_AT_comp_dir` names no real directory |
| `elf/armeb.o` | Apple clang 21.0.0 | `.comment`; big-endian ARM target |
| `elf/i386-static` | Homebrew clang + LLD 20.1.8 | `.comment` names both; the Go build-id and SystemTap notes come from inline assembly in the source |
| `elf/ppc64.o` | Homebrew clang 20.1.8 | `.comment` |
| `elf/mips64.o` | Debian clang 19.1.7 (Docker, Debian trixie `clang llvm` packages) | reproduced byte-for-byte by `sh tests/data/elf/make-mips64.sh` from `tests/data/elf/obj.c` (`clang --target=mips64-linux-gnuabi64 -O2 -fPIC -fno-ident -c`, no debug info); big-endian N64 relocations composing three types per `r_info`, checked against `llvm-readelf -r` |
| `elf/mips64el.o` | Debian clang 19.1.7 (Docker, Debian trixie `clang llvm` packages) | same script, `--target=mips64el-linux-gnuabi64`: the little-endian layout of the same relocations, checked against `llvm-readelf -r` |
| `elf/x86_64-pie` | Homebrew clang + LLD 20.1.8 | `.comment` names both |
| `elf/x86_64-relr.so` | Debian clang 19.1.7 + LLD (Docker, Debian trixie `clang lld llvm` packages) | reproduced byte-for-byte by `sh tests/data/elf/make-relr.sh` from `tests/data/elf/relr.c` (`-shared -nostdlib -fuse-ld=lld -z pack-relative-relocs --hash-style=both`, no `.comment`): `.relr.dyn` with an address entry and two bitmaps, `.hash` and `.gnu.hash`, `.eh_frame` and `.eh_frame_hdr`; checked against `llvm-readelf -r` and `llvm-dwarfdump --eh-frame` |
| `elf/s390x-versioned.so` | Debian clang 19.1.7 + LLD 19.1.7 (Docker, Debian trixie `clang lld llvm` packages) | reproduced byte-for-byte by `sh tests/data/elf/make-dynamic.sh` from `tests/data/elf/versioned.c` and `versioned.map` (`--target=s390x-linux-gnu -fPIC -shared -nostdlib`, version script, `.symver`): big-endian shared object with `.gnu.version_d` (base, FILLY_1.0, FILLY_2.0 inheriting it), a hidden non-default version and `.gnu.hash`; checked against `llvm-readelf -h -l -d -r -V --dyn-syms` |
| `elf/s390x-dynamic` | Debian clang 19.1.7 + LLD 19.1.7 (Docker, Debian trixie) | same script, from `tests/data/elf/dynamic.c` linked against `s390x-versioned.so` (`-fPIE -pie`, interpreter `/lib/ld64.so.1`): big-endian dynamically linked executable with PT_INTERP, `.dynamic`, `.gnu.version_r`, GLOB_DAT and JMP_SLOT relocations; checked against `llvm-readelf` |
| `elf/aarch64-kernel.core.gz` | Linux kernel core dump (OrbStack 7.0 kernel, Docker `debian:trixie` arm64; the process built with Debian clang 19.1.7 + LLD) | `sh tests/data/elf/make-core.sh`: a static process without libc (`tests/data/elf/core.c`) run from `/build/elf` with an empty environment and killed with SIGSEGV, `core_pattern` = `core`; not reproducible byte for byte (AT_RANDOM, address layout). Edited: `tests/data/elf/scrub_core.py` zeroes the dumped vDSO segment (kernel code); stored with `gzip -9 -n`. Notes NT_PRSTATUS, NT_PRPSINFO, NT_SIGINFO, NT_AUXV, NT_FILE, NT_PRFPREG and the arm64 register sets (TLS, hardware break/watchpoints, SSVE, ZA, ZT) |
| `elf/x86_64-dwarf5` | Debian clang 19.1.7 + LLD 19.1.7 (Docker, Debian trixie) | reproduced byte-for-byte by `sh tests/data/elf/make-dwarf.sh` from `tests/data/elf/dwarf.c` (`-O1 -g -gdwarf-5 -gdwarf-aranges -ffreestanding -nostdlib -static -fuse-ld=lld`, prefix maps): DWARF 5 with strx/addrx forms, `.debug_str_offsets`, `.debug_addr`, `.debug_rnglists`, `.debug_loclists`, `.debug_aranges`, a version 5 line table with `.debug_line_str`, and `.debug_frame`; checked against `llvm-dwarfdump` 21 (`--debug-info --debug-line -v --debug-frame --debug-aranges --debug-rnglists --debug-loclists --debug-str-offsets --debug-addr`; `--verify` reports no errors) |
| `elf/aarch64-gcc-dwarf4` | Debian GCC 14.2.0 + GNU ld 2.44 (Docker, Debian trixie arm64) | same script: `gcc -O1 -g -gdwarf-4 -ffreestanding -nostdlib -static -Wl,-z,max-page-size=0x1000`: DWARF 4 with `DW_FORM_strp`, `.debug_aranges`, `.debug_ranges`, `.debug_loc`, a version 4 line table and `.eh_frame`; checked against `llvm-dwarfdump` 21 (its `--verify` does not finish on this file; the dumps do) |
| `macho/hello-arm64.o` | clang (Apple) | LLVM integrated-assembler output (`ltmp` symbols, `__compact_unwind`) |
| `macho/hello-x86_64` | clang + ld64 + codesign (Apple) | linked executable with stubs, dyld info and an entitlements code signature |
| `macho-fat/libfilly-fat.dylib` | clang + lipo (Apple) | two linked dylib slices |
| `macho/hello-arm64` | clang + ld (Apple clang 21.0.0, ld 1267) | arm64 executable with chained fixups, linked with `-segalign 0x1000`; reproduced byte-for-byte by `sh tests/data/macho/build-fixtures.sh <repo>` (sources and commands in `tests/data/macho/`, built in `/tmp/fixtures/macho` with prefix maps, `-oso_prefix`, `ZERO_AR_DATE=1`) |
| `macho/hello-arm64-classic` | clang + ld (Apple) | `-no_fixup_chains` (dyld info opcodes) and a stabs debug map; reproduced byte-for-byte by `sh tests/data/macho/build-fixtures.sh <repo>` (sources and commands in `tests/data/macho/`, built in `/tmp/fixtures/macho` with prefix maps, `-oso_prefix`, `ZERO_AR_DATE=1`) |
| `macho/hello-signed` | clang + ld + codesign (Apple) | `hello-arm64` re-signed ad hoc with entitlements and an explicit requirement; reproduced byte-for-byte by `sh tests/data/macho/build-fixtures.sh <repo>` (sources and commands in `tests/data/macho/`, built in `/tmp/fixtures/macho` with prefix maps, `-oso_prefix`, `ZERO_AR_DATE=1`) |
| `macho/libfilly.dylib` | clang + ld (Apple) | dylib with an exports trie, weak definition, thread-local, weak library; reproduced byte-for-byte by `sh tests/data/macho/build-fixtures.sh <repo>` (sources and commands in `tests/data/macho/`, built in `/tmp/fixtures/macho` with prefix maps, `-oso_prefix`, `ZERO_AR_DATE=1`) |
| `macho/reloc-x86_64.o` | clang (Apple) | x86_64 object with DWARF and relocations; reproduced byte-for-byte by `sh tests/data/macho/build-fixtures.sh <repo>` (sources and commands in `tests/data/macho/`, built in `/tmp/fixtures/macho` with prefix maps, `-oso_prefix`, `ZERO_AR_DATE=1`) |
| `macho/reloc-i386.o` | clang (Apple) | i386 object (scattered relocations); reproduced byte-for-byte by `sh tests/data/macho/build-fixtures.sh <repo>` (sources and commands in `tests/data/macho/`, built in `/tmp/fixtures/macho` with prefix maps, `-oso_prefix`, `ZERO_AR_DATE=1`) |
| `macho/hello-swift` | swiftc 6.3.3 (Apple) | Swift executable (`__swift5_*` sections); reproduced byte-for-byte by `sh tests/data/macho/build-fixtures.sh <repo>` (sources and commands in `tests/data/macho/`, built in `/tmp/fixtures/macho` with prefix maps, `-oso_prefix`, `ZERO_AR_DATE=1`) |
| `macho-fat/hello-fat64` | clang + ld + lipo (Apple) | `lipo -create -fat64` of x86_64 and arm64e executables; reproduced byte-for-byte by `sh tests/data/macho/build-fixtures.sh <repo>` (sources and commands in `tests/data/macho/`, built in `/tmp/fixtures/macho` with prefix maps, `-oso_prefix`, `ZERO_AR_DATE=1`) |
| `coff/` | Homebrew clang 22.1.8 | the four `.obj` objects (`Homebrew clang version 22.1.8` producer string); the `shapes-*.o` objects have their own rows |
| `pe/filly64.dll` | zig 0.15.2 (clang 20, lld-link, llvm-dlltool, `zig rc`) | reproduced byte-for-byte by `sh tests/data/pe/make.sh` (sources in `tests/data/pe/`: C without a C runtime, `.def` export and import-library files, a resource script whose icon, cursor, bitmap, manifest and message-table inputs are written by `resources.py` with Pillow 12.0.0); x64 DLL with named, data, NONAME and forwarded exports, imports by name and ordinal, delay imports, TLS callbacks, a CFG load configuration, `.pdata`, resources, CodeView (`/pdbaltpath:filly64.pdb`), REPRO and EX_DLLCHARACTERISTICS debug entries and a `/release` checksum; i386 console EXE with a SafeSEH table; ARM64 EXE with ARM64 unwind data; checked against pefile 2024.8.26 and `objdump -p` (Apple LLVM) |
| `pe/filly32.exe` | zig 0.15.2 (clang 20, lld-link, llvm-dlltool, `zig rc`) | built with filly64.dll by the same script (see that row) |
| `pe/fillyarm64.exe` | zig 0.15.2 (clang 20, lld-link, llvm-dlltool) | built with filly64.dll by the same script (see that row) |
| `pe/mingw-symbols.exe` | Debian trixie mingw-w64 GCC 14 (`14-win32`) + GNU ld 2.44 (Docker, `gcc-mingw-w64-x86-64`) | reproduced byte-for-byte by `sh tests/data/pe/make-mingw.sh` from `tests/data/pe/fillymingw.c`: `x86_64-w64-mingw32-gcc -g -O1 -nostdlib -ffreestanding` with prefix maps, entry `filly_start`, `--no-insert-timestamp`; x64 EXE whose COFF symbol table (82 records) and string table follow the last section, DWARF sections with `/N` long names, one export; checked against `x86_64-w64-mingw32-objdump -h -t` |
| `ne/fillyne.exe` | Open Watcom V2 `wcc` + `wlink` (2026-10-01-Build, the project's `ow-snapshot.tar.xz` release, run in Docker `debian:trixie`) | reproduced byte-for-byte by `OW=<unpacked snapshot> sh tests/data/ne/make.sh` from `tests/data/ne/fillyne.c` and `fillyne2.c`: Windows 3.0 large-model program linked with no C runtime and no default libraries (`wcc -zl`, `wlink option nodefaultlibs`, entry `filly_start`), so it holds only our code; four segments, five relocation records (an internal far reference, a SEGMENT fixup to a far data segment, imports by ordinal USER.1 and KERNEL.4 and by name FILLYHLP.FILLYHELPER via IMPORT directives); records checked against `wdump -a -r` |
| `pdb/lld-link.pdb` | Debian clang 19.1.7 + LLD 19.1.7 (Docker, Debian trixie `clang lld llvm` packages) | reproduced byte-for-byte by `sh tests/data/pdb/make.sh` from `tests/data/pdb/fillypdb.c`: `clang --target=x86_64-pc-windows-msvc -O1 -gcodeview -g` with prefix maps, then `lld-link /nodefaultlib /entry:filly_main /debug /pdbaltpath:lld-link.pdb /Brepro`, built in the container's `/build/pdb` (the only directory named in the PDB); 15 streams (PDB info, TPI, DBI, IPI, `/LinkInfo`, globals, publics, symbol records, TPI hash, section headers, two modules, `/names`, IPI hash) checked against `llvm-pdbutil dump -summary -streams` |
| `pdb/lld-link-cpp.pdb` | Debian clang 19.1.7 + LLD 19.1.7 (Docker, Debian trixie `clang lld llvm` packages) | reproduced byte-for-byte by the same script from `tests/data/pdb/fillycpp.cpp` (`-O1 -gcodeview -g -fno-exceptions -fno-rtti`, `lld-link /nodefaultlib /debug /Brepro`): C++ classes with a base class, virtual and overloaded methods (LF_MFUNCTION, LF_ONEMETHOD, LF_METHODLIST, LF_VFUNCTAB, LF_BCLASS), a nested enum, bitfields, a union, pointers and references; module symbols with locals, S_DEFRANGE_* ranges, inline sites and inlinee lines; every record checked against `llvm-pdbutil dump -types -ids -symbols -globals -publics -l -il` |
| `pdb/lld-link-x86.pdb` | Debian clang 19.1.7 + LLD 19.1.7 (Docker, Debian trixie `clang lld llvm` packages) | reproduced byte-for-byte by the same script: `fillypdb.c` for `--target=i686-pc-windows-msvc -O2 -fomit-frame-pointer` (clang writes FRAMEDATA, which lld-link moves into the new FPO stream with its frame programs in `/names`) and `tests/data/pdb/fpo.s`, a function with a hand-written `.debug$F` FPO_DATA record (lld-link copies it into the old FPO stream); both FPO streams checked against `llvm-pdbutil dump -fpo` |
| `pe/clrloader-amd64.dll` | Microsoft C# compiler / .NET SDK (via the clr_loader 0.3.1 wheel) | `clr_loader/ffi/dlls/amd64/ClrLoader.dll` from `clr_loader-0.3.1-py3-none-any.whl` on PyPI (wheel SHA-256 cbad189de20d202a7d621956b0fc38049e13c9bf7ca2923441eff725cd121aa1), unchanged; MIT license, Copyright (c) 2019-2026 Benedikt Reinartz (see THIRD-PARTY.md); its CodeView record holds the upstream build machine's PDB path; checked against dnfile 0.18.0 (table row counts, streams) and pefile |
| `dex/shapes.dex` | javac 21 (Android Studio JBR) + d8 (Android SDK build-tools 36.0.0) | reproduced byte-for-byte by `sh tests/data/dex/make.sh` (`javac --release 8 -g`, `d8 --debug --min-api 26`) from `tests/data/dex/src/`; checked against `dexdump -f -d` |
| `apk/signed.apk` | Android SDK build-tools 36.0.0 (aapt2, d8, zipalign, apksigner) + javac 21 (Android Studio JBR) | `sh tests/data/apk/make.sh` from `tests/data/apk/src/`, without `classes.dex` and the drawable (`zip -d` before signing, so the snapshot stays under its size cap; `stamped.apk` keeps the full package) (fresh throwaway EC P-256 keys `CN=fillyfoal test old/new, O=Example, C=US`, so signatures and certificates differ per run): JAR (v1) + v2 + v3 (SDK 24–32, old key) + v3.1 (SDK 33+, rotated key with a proof-of-rotation lineage) signatures and verity padding; `apksigner verify -v --print-certs --v4-signature-file` verifies all schemes; signer DNs and SDK ranges checked against its output |
| `apk/stamped.apk` | Android SDK build-tools 36.0.0 (apksigner) | same script: RSA-2048 key, v1 + v2 + v3 and a v2 source stamp (RSA key `CN=fillyfoal test stamp`); `apksigner verify` reports the stamp signer and its timestamp, matching ours |
| `apk-idsig/signed.apk.idsig` | Android SDK build-tools 36.0.0 (apksigner) | same script (`--v4-signing-enabled true`): v4 version 2 with a second signing info for the v3.1 key and the Merkle tree |
| `apk-lineage/rotation.lineage` | Android SDK build-tools 36.0.0 (apksigner) | same script: `apksigner rotate` output for the old → new key rotation |
| `android-resources/aapt2.arsc` | Android SDK build-tools 36.0.0 (aapt2) | same script: `resources.arsc` from `apk/signed.apk`, unchanged (strings, styled string, plurals, arrays, colors, dimensions, fractions, integers, bools, an attr with enum values, a styleable, a style, a `de` configuration) |
| `android-xml/aapt2-manifest.xml` | Android SDK build-tools 36.0.0 (aapt2) | same script: the binary manifest from `apk/signed.apk`, unchanged |
| `android-xml/main-layout.xml` | Android SDK build-tools 36.0.0 (aapt2) | same script: `res/layout/main.xml` from `apk/signed.apk`, unchanged |
| `android-resources/configs.arsc` | Android SDK build-tools 36.0.0 (aapt2) | reproduced byte-for-byte by `sh tests/data/android-resources/make-configs.sh` (`aapt2 compile` + `aapt2 link --min-sdk-version 21`): one string in 31 qualifier directories covering every `ResTable_config` axis (MCC/MNC, legacy and `b+` locales with script, variant, 3-letter language and numeric region, grammatical gender, layout direction, sw/w/h dp, screen size and length, round, wide gamut and HDR, orientation, UI mode type and night, densities, touchscreen, keyboard, navigation, SDK version); config names checked against `aapt2 dump configurations` (which spells MNC 00 as `mnc65535`) |
| `android-resources/configs-sparse-compact.arsc` | Android SDK build-tools 36.0.0 (aapt2) | same script, linked with `--min-sdk-version 34 --enable-sparse-encoding --enable-compact-entries`: sparse type chunks, an OFFSET16 type chunk and compact entries; values checked against `aapt2 dump resources` |
| `android-xml/namespaces-layout.xml` | Android SDK build-tools 36.0.0 (aapt2) | reproduced byte-for-byte by `sh tests/data/android-xml/make.sh` (`aapt2 compile` + `aapt2 link` from `tests/data/android-xml/src/`): a layout with `android:`, `app:` (res-auto, two attrs of our own), `tools:` (dropped by aapt2) and a custom `x:` namespace; checked against `aapt2 dump xmltree` |
| `java-class/` | javac 21.0.12.1 (Docker `eclipse-temurin:21-jdk`) | reproduced byte-for-byte by `sh tests/data/java-class/make.sh` (`javac --release 21 -g -parameters` from `tests/data/java-class/src/`): `Shapes.class` (pattern and string switches, tableswitch/lookupswitch, lambdas and method references, string concatenation, StackMapTable, exception table, generic Signature, MethodParameters, parameter and type annotations), `Shape.class` (sealed interface, annotation with enum and array values), `Shape-Circle.class` (javac's `Shape$Circle.class`, a record), `Tag.class` (annotation interface with AnnotationDefault) and `module-info.class` (Module); checked against `javap -v -p` |
| `android-boot/` | AOSP mkbootimg 34.0.5 (Debian trixie `mkbootimg` package) | reproduced byte-for-byte by `sh tests/data/android-boot/make.sh` (Docker `debian:trixie-slim`, `tests/data/android-boot/inside.sh`): boot images v0 (second stage), v1 (recovery DTBO), v2 (DTB), v3, v4 and a v4 init_boot (ramdisk only) around a fake gzip'd arm64 kernel, gzip/lz4-legacy cpio ramdisks (GNU cpio `--reproducible`) and a dtc-compiled DTB; every header field checked against `unpack_bootimg` output |
| `android-vendor-boot/` | AOSP mkbootimg 34.0.5 (Debian trixie `mkbootimg` package) | same script: vendor_boot v3 and v4 (two vendor ramdisk fragments of types platform and dlkm, the ramdisk table, bootconfig); checked against `unpack_bootimg` |
| `oat/app.odex` | ART dex2oat64 (Android emulator system image android-37.1 google_apis_playstore_ps16k arm64-v8a rev 7; OAT version 279) | `sh tests/data/apk/emulator-oat.sh`: `apk/signed.apk` of an earlier run of `make.sh`, which still carried the `classes.dex` that `apk/stamped.apk` carries (the script now compiles that one), compiled with `--compiler-filter=speed --app-image-file=app.art` from the device shell; every OAT header field, key-value pair, OatDexFile, OatClass, CodeInfo header (code size, frame size, spill masks) and method offset checked against the device's `oatdump`. The app image load address is random, so reruns differ there |
| `vdex/app.vdex` | ART dex2oat64 (same emulator image; VDEX 027) | same command: checksum, DEX, verifier dependency and type lookup table sections; the dependency (Main assignable to Activity) and the lookup table checked against `oatdump` |
| `art-image/app.art` | ART dex2oat64 (same emulator image; image version 119) | same command (`--app-image-file`): header, sections, image methods, intern and class tables, string reference offsets and bitmap checked against `oatdump --app-image` |
| `dex/shapes-v041.dex` | javac 21 (Android Studio JBR) + d8 (Android SDK build-tools 36.0.0) | same script, byte for byte: the same classes with `--min-api 36` and `-Dcom.android.tools.r8.dexContainerExperiment=true`, giving a DEX 041 container (header size 0x78, container_size, header_offset, data_size 0); checked against `dexdump -f` |
| `coff-import/` | LLVM llvm-dlltool / llvm-lib | the three short import records are members of ar/filly-import.lib, extracted unchanged |
| `ar/filly-import.lib` | LLVM llvm-dlltool / llvm-lib (20-22) | reproduced byte-for-byte from a three-line .def file (`fillyfoal_answer`, `fillyfoal_data DATA`, `fillyfoal_ordinal @7 NONAME`) |
| `ar/libbsd.a` | macOS ar/libtool (cctools) | reproduced byte-for-byte from its own members with `ZERO_AR_DATE=1 ar rcs` / `libtool -static`; members are clang objects |
| `wasm/rust-cdylib.wasm` | rustc 1.98.1 (48a229cea 2026-09-01), wasm32-unknown-unknown | `producers` section names rustc; reproduced byte-for-byte in `/tmp/fixtures/exec-wasm` from `tests/data/wasm/rust-cdylib.rs` (copied there as `lib.rs`) by `rustc --target wasm32-unknown-unknown --crate-type cdylib -C opt-level=1 -C panic=abort -o rust-cdylib.wasm lib.rs` (no debug info, so no paths) |
| `wasm/component.wasm` | wasm-tools 1.240.0 (Bytecode Alliance; `cargo install --locked` in Docker `rust:1-slim-bookworm`) | reproduced byte-for-byte by `sh tests/data/wasm/make-component.sh` (`wasm-tools parse` of `tests/data/wasm/component.wat`, then `wasm-tools validate`): a layer-1 component with two core modules, a nested component, core and component instances, aliases, canonical lift/lower, imports (versioned function, instance, resource type bound) and exports; structure checked against `wasm-tools print` |
| `wasm/component-types.wasm` | wasm-tools 1.240.0 (same build) | reproduced byte-for-byte by `sh tests/data/wasm/make-component.sh` (`wasm-tools parse` of `tests/data/wasm/component-types.wat`, then `wasm-tools validate --features all`): core module and function types, every kind of component value type (record, variant, list, tuple, flags, enum, option, result, own), a resource, function, instance and component types, canonical lift (with options) and resource built-ins, core and component instances (instantiations and inline exports), an imported value and a start function; decoded entries checked against `wasm-tools print` |
| `spirv/shader.spv` | glslang 1.4.341.0 (Docker `alpine:edge` package `glslang`) | reproduced byte-for-byte by `sh tests/data/spirv/make-shader.sh` (`glslangValidator -V`) from `tests/data/spirv/shader.frag`; instructions checked against `spirv-dis` (spirv-tools 1.4.357.0) |
| `xcoff/` | Homebrew LLVM 22.1.8 | both objects (`Homebrew LLVM version 22.1.8` producer string) |
| `llvm-bitcode/apple.bc` | Apple clang 21.0.0 | IDENTIFICATION block / producer string |
| `llvm-bitcode/linux.bc` | Homebrew clang 22.1.8 | IDENTIFICATION block / producer string |
| `win-res/llvm-rc.res` | Homebrew llvm-rc 22.1.8 | `llvm-rc -no-preprocess -fo llvm-rc.res app.rc`; the script covers icons (a DIB and a PNG image), a cursor, a bitmap, a manifest, RCDATA (a synthetic Delphi form, the same bytes as synthetic/delphi-dfm/form.dfm, and inline data), string tables in two languages, accelerators, version info, a menu, a DIALOGEX and a custom-typed resource; the image files it includes were written by our generator |
| `lua/fib-5.5.luac` | luac 5.5 | chunk name `@target/fx/lua/fib.lua`; `luac -l` lists it |
| `lua/sample-5.1.luac` | luac 5.1.5 (Docker `alpine:edge` package `lua5.1`) | reproduced byte-for-byte by `sh tests/data/lua/make.sh` (`luac5.1 -o`) from `tests/data/lua/sample.lua`: nested closures, upvalues, integer, float and short/long string constants (one over 255 bytes), varargs and locals; constants, locals and upvalues checked against `luac5.1 -l -l` |
| `lua/sample-5.2.luac` | luac 5.2.4 (Docker `alpine:edge` package `lua5.2`) | reproduced byte-for-byte by `sh tests/data/lua/make.sh` (`luac5.2 -o`) from `tests/data/lua/sample.lua`: nested closures, upvalues, integer, float and short/long string constants (one over 255 bytes), varargs and locals; constants, locals and upvalues checked against `luac5.2 -l -l` |
| `lua/sample-5.3.luac` | luac 5.3.6 (Docker `alpine:edge` package `lua5.3`) | reproduced byte-for-byte by `sh tests/data/lua/make.sh` (`luac5.3 -o`) from `tests/data/lua/sample.lua`: nested closures, upvalues, integer, float and short/long string constants (one over 255 bytes), varargs and locals; constants, locals and upvalues checked against `luac5.3 -l -l` |
| `lua/sample-5.4.luac` | luac 5.4.9 (Docker `alpine:edge` package `lua5.4`) | reproduced byte-for-byte by `sh tests/data/lua/make.sh` (`luac5.4 -o`) from `tests/data/lua/sample.lua`: nested closures, upvalues, integer, float and short/long string constants (one over 255 bytes), varargs and locals; constants, locals and upvalues checked against `luac5.4 -l -l` |
| `lua/sample-5.5.luac` | luac 5.5.1 (Docker `alpine:edge` package `lua5.5`) | reproduced byte-for-byte by `sh tests/data/lua/make.sh` (`luac5.5 -o`) from `tests/data/lua/sample.lua`: nested closures, upvalues, integer, float and short/long string constants (one over 255 bytes), varargs and locals; constants, locals and upvalues checked against `luac5.5 -l -l` |
| `lua/sample-5.4-stripped.luac` | luac 5.4.9 (Docker `alpine:edge` package `lua5.4`) | same script, `luac5.4 -s` (no debug information) |
| `lua/ops-5.1.luac` | luac 5.1.5 (Docker `alpine:edge` package `lua5.1`) | reproduced byte-for-byte by `sh tests/data/lua/make.sh` (`luac5.1 -o`) from `tests/data/lua/ops.lua`, an opcode sampler; every instruction's opcode, operands and jump target checked against `luac5.1 -l -l` |
| `lua/ops-5.2.luac` | luac 5.2.4 (Docker `alpine:edge` package `lua5.2`) | reproduced byte-for-byte by `sh tests/data/lua/make.sh` (`luac5.2 -o`) from `tests/data/lua/ops.lua`, an opcode sampler; every instruction's opcode, operands and jump target checked against `luac5.2 -l -l` |
| `lua/ops-5.3.luac` | luac 5.3.6 (Docker `alpine:edge` package `lua5.3`) | reproduced byte-for-byte by `sh tests/data/lua/make.sh` (`luac5.3 -o`) from `tests/data/lua/ops.lua`, an opcode sampler; every instruction's opcode, operands and jump target checked against `luac5.3 -l -l` |
| `lua/ops-5.4.luac` | luac 5.4.9 (Docker `alpine:edge` package `lua5.4`) | reproduced byte-for-byte by `sh tests/data/lua/make.sh` (`luac5.4 -o`) from `tests/data/lua/ops.lua`, an opcode sampler; every instruction's opcode, operands and jump target checked against `luac5.4 -l -l` |
| `lua/ops-5.5.luac` | luac 5.5.1 (Docker `alpine:edge` package `lua5.5`) | reproduced byte-for-byte by `sh tests/data/lua/make.sh` (`luac5.5 -o`) from `tests/data/lua/ops.lua`, an opcode sampler; every instruction's opcode, operands and jump target checked against `luac5.5 -l -l` |
| `pyc/filly.cpython-39.pyc` | CPython 3.9 (py_compile) | bytecode of the matching interpreter version |
| `pyc/filly.cpython-311.pyc` | CPython 3.11 (py_compile) | bytecode of the matching interpreter version |
| `pyc/filly.cpython-314.pyc` | CPython 3.14 (py_compile) | bytecode of the matching interpreter version |
| `pyc/filly-hash.cpython-314.pyc` | CPython 3.14 (py_compile, checked hash-based) | bytecode of the matching interpreter version |
| `pyc/interned.python27.pyc` | CPython 2.7.18 (Docker `python:2.7-slim`, `py_compile`) | reproduced byte-for-byte by `sh tests/data/pyc/make-py2.sh` (source mtime pinned to 2026-01-01 UTC): interned strings (`t`) and back-references (`R`); names checked against the source |
| `pyc/tables.cpython-38.pyc` | CPython 3.8 (Docker `python:3.8-slim`, `py_compile`) | reproduced byte-for-byte by `sh tests/data/pyc/make-tables.sh` from `tests/data/pyc/tables.py` (source mtime pinned); decoded line tables checked entry by entry against `dis.findlinestarts` in the same image |
| `pyc/tables.cpython-310.pyc` | CPython 3.10 (Docker `python:3.10-slim`, `py_compile`) | reproduced byte-for-byte by `sh tests/data/pyc/make-tables.sh` from `tests/data/pyc/tables.py` (source mtime pinned); decoded line tables checked entry by entry against `co_lines()` in the same image |
| `pyc/tables.cpython-313.pyc` | CPython 3.13 (Docker `python:3.13-slim`, `py_compile`) | reproduced byte-for-byte by `sh tests/data/pyc/make-tables.sh` from `tests/data/pyc/tables.py` (source mtime pinned); decoded line and exception tables checked entry by entry against `co_positions()` and `dis._parse_exception_table` in the same image |
| `mo/de.mo` | GNU gettext msgfmt | reproduced byte-for-byte: `msgunfmt de.mo \| msgfmt -` |
| `terminfo/fillyfoal-term` | ncurses tic 6.0 (macOS) | reproduced byte-for-byte: `infocmp -x \| tic -x`; the terminal description itself is ours |

## Python standard library

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `pickle/protocol2.pkl` | CPython pickle | reproduced byte-for-byte: `pickle.dumps(pickle.loads(data), protocol=2)` |
| `pickle/protocol5.pkl` | CPython pickle | reproduced byte-for-byte: `pickle.dumps(pickle.loads(data), protocol=5)` |
| `bplist/foundation-archive.plist` | Foundation NSKeyedArchiver (macOS 26, Swift 6) | reproduced byte-for-byte by `swift tests/data/bplist/archive.swift OUT`: an NSDictionary of strings, numbers, a date, data, a URL, a UUID, an array, a set and a nested dictionary sharing a string; checked against `plutil -p` (UIDs, `$objects`, `$class` dictionaries) |
| `asset-catalog/actool.car` | Xcode 26.6 actool (CoreUI 975, CoreThemeDefinition 653.4) | reproduced byte-for-byte by `sh tests/data/asset-catalog/make.sh` (`--platform macosx --minimum-deployment-target 14.0`): an image set (1x/2x PNGs from `png.py`), a color set with a dark appearance and a data set; renditions, keys, TLVs, colour components, facets and appearances checked against `xcrun assetutil --info` |
| `bplist/keyed-archive.plist` | CPython plistlib | reproduced byte-for-byte: `plistlib.dumps(plistlib.loads(data), fmt=FMT_BINARY)`; the NSKeyedArchiver structure inside was assembled by hand |
| `eml/charsets.eml` | CPython email package | `email.mime` generator output (`===============N==` boundaries, header order); the encoded words in the headers were chosen by us |
| `eml/big5-hkscs.eml` | CPython 3.13.13 email package and `big5hkscs` codec | reproduced byte for byte by `uv run --python 3.13 python3 -I tests/data/eml/big5_hkscs.py OUT.eml`: a Big5-HKSCS subject and body with characters code page 950 lacks (U+2010C, U+00CA U+0304) |

## Libraries

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `sqlite/autovacuum.sqlite` | SQLite 3.51.0 | header records SQLite version 3051000 |
| `sqlite/shop.sqlite` | SQLite 3.51.0 | header records SQLite version 3051000 |
| `sqlite-wal/t.db-wal` | SQLite 3.51 | WAL of a `t.db` written by the same library |
| `sqlite-journal/t.db-journal` | SQLite 3.51 | rollback journal of the same `t.db` |
| `sqlite/catalog.sqlite` | SQLite 3.50.4 (Python 3 `sqlite3`) | `uv run python3 -I tests/data/sqlite/make_fixtures.py /tmp/fixtures/sqlite-out` (reproduces it byte for byte): 512-byte pages, tables with AUTOINCREMENT, UNIQUE (automatic indexes), an explicit DESC index, a WITHOUT ROWID table, a view, a trigger, overflow rows, a freelist left by DELETE, `sqlite_stat1` from ANALYZE |
| `sqlite/utf16.sqlite` | SQLite 3.50.4 (Python 3 `sqlite3`) | same script, byte for byte: `PRAGMA encoding = 'UTF-16le'`, an indexed text column |
| `sqlite/incremental.sqlite` | SQLite 3.50.4 (Python 3 `sqlite3`) | same script, byte for byte: `auto_vacuum = INCREMENTAL` (pointer-map page), overflow chains, free pages |
| `sqlite/wal.sqlite` | SQLite 3.50.4 (Python 3 `sqlite3`) | same script: the database file copied while a connection had a transaction open in WAL mode (`wal-copy.sqlite`); its WAL is `sqlite-wal/wal.sqlite-wal` |
| `sqlite-wal/wal.sqlite-wal` | SQLite 3.50.4 (Python 3 `sqlite3`) | same script (`wal-copy.sqlite-wal`), copied while the last transaction was open: a restarted log (stale frames of the first generation after the new ones), committed frames, an open transaction's frames; salts are random, so not reproducible byte for byte |
| `sqlite-journal/journal.sqlite-journal` | SQLite 3.50.4 (Python 3 `sqlite3`) | same script (`journal-copy.sqlite-journal`), copied during a transaction with a one-page cache: two segments (each spill syncs the journal); the nonces are random, so not reproducible byte for byte |
| `sqlite-shm/t.db-shm` | SQLite 3.53.4 (Python 3 `sqlite3`, macOS arm64) | `python3 -I tests/data/sqlite/make_shm.py OUTDIR`: the WAL index of a 1 KiB-page database in WAL mode with automatic checkpoints off, copied while open: 31 frames, a passive checkpoint stopped at a reader's mark (16 backfilled), two read marks; little-endian. Salts are random, so not reproducible byte for byte |
| `gpkg/geo.gpkg` | GDAL 3.14.0dev-404da16b (ghcr.io/osgeo/gdal:alpine-small-latest, 2026-10-02) `ogr2ogr` | `tests/data/gpkg/make.sh`: a 3-feature GeoJSON (a point, a line, a polygon) into layer `features`, 1 KiB pages, no spatial index, no metadata tables or `gpkg_ogr_contents`; application ID `GPKG`. Not byte-for-byte reproducible (`gpkg_contents.last_change`) |
| `mbtiles/tiles.mbtiles` | GDAL 3.14.0dev-404da16b (same image) `gdal_translate -of MBTILES` | same script: a 64×64 RGB GeoTIFF from `gdal_create` as zoom-14 PNG tiles of 64 pixels (4 tiles) with the `metadata` table; GDAL sets no application ID |
| `wkb/collection-z.wkb` | Shapely 2.1.2 (GEOS 3.13.1) `to_wkb` | `uv run --with shapely==2.1.2 python3 -I tests/data/wkb/make.py OUTDIR`, byte for byte: ISO WKB, little-endian, a GeometryCollection Z of a point, a line string and a polygon with a hole |
| `wkb/multipolygon-srid.ewkb` | Shapely 2.1.2 (GEOS 3.13.1) `to_wkb` | same script, byte for byte: extended (PostGIS EWKB) flavour, big-endian, a MultiPolygon with SRID 4326 |
| `bgcode/` | libbgcode (pybgcode built from prusa3d/libbgcode commit d4da907) | reproduced byte-for-byte by `tests/data/bgcode/make_bgcode.py`: `from_ascii_to_binary` of our PrusaSlicer-style `synthetic/gcode/prusaslicer.gcode` (thumbnails made with Pillow 12.3), one file per compression (none, zlib, Heatshrink 11/4 and 12/4), G-code encoding (none, MeatPack, MeatPack with comments) and checksum type (none, CRC-32) |
| `orc/lz4.orc` | pyarrow 25 (Apache ORC C++ 2.2.2) | reproduced byte-for-byte by re-writing the table with `pyarrow.orc.write_table(compression="lz4")` |
| `orc/snappy.orc` | pyarrow 25 (Apache ORC C++ 2.2.2) | reproduced byte-for-byte (`compression="snappy"`) |
| `orc/zstd.orc` | pyarrow 25 (Apache ORC C++ 2.2.2) | reproduced byte-for-byte (`compression="zstd"`) |
| `hdf5/earliest.h5` | h5py 3.16.0 (HDF5 2.0.0) | `tests/data/hdf5/make_fixtures.py` (`libver="earliest"`): superblock 0, symbol-table groups, every datatype class h5py writes, deflate/shuffle/Fletcher-32 and scale-offset chunks, compact data, soft and external links; reproduced except the modification times of `chunked` and `compact` |
| `hdf5/latest.h5` | h5py 3.16.0 (HDF5 2.0.0) | same script (`libver="latest"`): superblock 3, dense links and attributes (fractal heaps, v2 B-trees), single-chunk, implicit, fixed-array, extensible-array and v2 B-tree chunk indexes; reproduced except the times in the `implicit` dataset's object header |
| `hdf5/userblock-v2.h5` | h5py 3.16.0 (HDF5 2.0.0) | same script (`libver=("v108", "v108")`, 512-byte user block): superblock 2; the script writes `fillyfoal user block` into the user block; reproduced byte-for-byte |
| `hdf5/lz4.h5` | h5py 3.16.0 (HDF5 2.0.0), hdf5plugin 6.0.0 (H5Zlz4) | `tests/data/hdf5/make_lz4.py` (`track_times=False`): a uint8 dataset filtered with LZ4 (filter 32004, 512-byte blocks: two compressed blocks of text, then 256 bytes of noise stored raw) and an int32 dataset with shuffle then LZ4; reproduced byte-for-byte |
| `hdf5/netcdf4.nc` | netCDF4-python 1.7.4 (netCDF-C 4.9.3, HDF5 1.14.6) | `tests/data/netcdf/make_fixtures.py` (`format="NETCDF4"`): dimension scales, a group, a compound type, a vlen string variable, a deflate+shuffle variable; `_NCProperties` records the library versions |
| `netcdf/classic.nc` | netCDF4-python 1.7.4 (netCDF-C 4.9.3) | `tests/data/netcdf/make_fixtures.py` (`NETCDF3_CLASSIC`); reproduced byte-for-byte |
| `netcdf/offset64.nc` | netCDF4-python 1.7.4 (netCDF-C 4.9.3) | same script (`NETCDF3_64BIT_OFFSET`); reproduced byte-for-byte |
| `netcdf/cdf5.nc` | netCDF4-python 1.7.4 (netCDF-C 4.9.3) | same script (`NETCDF3_64BIT_DATA`), with `uint64` and `ushort` variables; reproduced byte-for-byte |
| `netcdf/scipy.nc` | SciPy 1.18.1 (`scipy.io.netcdf_file`) | same script; one record variable; reproduced byte-for-byte |
| `arrow/` | pyarrow 26.0.0 | `tests/data/arrow/make_fixtures.py`: an IPC file with two record batches (`plain.arrow`), LZ4-frame and Zstandard compressed bodies (`lz4.arrow`, `zstd.arrow`) and `feather.write_feather` (`table.feather`), with dictionary-encoded, list, struct, boolean and timestamp columns; reproduced byte-for-byte |
| `arrow-stream/table.arrows` | pyarrow 26.0.0 | same script (`ipc.new_stream`); reproduced byte-for-byte |
| `parquet/indexed.parquet` | pyarrow 26.0.0 (parquet-cpp-arrow 26.0.0) | `tests/data/parquet/make_fixtures.py`: two row groups, dictionary and PLAIN encodings, Snappy, statistics, the page index and a bloom filter; reproduced byte-for-byte |
| `parquet/v2.parquet` | pyarrow 26.0.0 (parquet-cpp-arrow 26.0.0) | same script: data page v2, Zstandard, page CRCs; reproduced byte-for-byte |
| `parquet/gzip.parquet` | pyarrow 26.0.0 (parquet-cpp-arrow 26.0.0) | same script: GZIP pages (whole RFC 1952 streams), no dictionary; reproduced byte-for-byte |
| `parquet/byte-stream-split.parquet` | pyarrow 26.0.0 (parquet-cpp-arrow 26.0.0) | same script: BYTE_STREAM_SPLIT INT64 and FLOAT columns, uncompressed, no dictionary; reproduced byte-for-byte |
| `rocksdb-sst/bzip2.sst` | RocksDB via rocksdict | edit: db/host/session identity properties overwritten with `x`; RocksDB still ingests the file |
| `rocksdb-sst/lz4.sst` | RocksDB via rocksdict | edit: identity properties overwritten with `x`; RocksDB still ingests the file |
| `rocksdb-sst/snappy.sst` | RocksDB via rocksdict | edit: identity properties overwritten with `x`; RocksDB still ingests the file |
| `rocksdb-sst/zstd.sst` | RocksDB via rocksdict | edit: identity properties overwritten with `x`; RocksDB still ingests the file |
| `rocksdb-sst/default-v6.sst` | RocksDB via rocksdict 0.3.29 (`SstFileWriter`, python:3.12-slim, host name `fillyfoal`) | `tests/data/rocksdb-sst/make.sh`: 150 keys, default table options (format version 6, XXH3 checksums with context, Snappy) and 1 KiB blocks; unedited (host identity `fillyfoal`, db identity `SST Writer`, random session identity) |
| `rocksdb-sst/v5-crc32c.sst` | RocksDB via rocksdict 0.3.29 | same script: format version 5, CRC-32C, no compression, 512-byte blocks, index restart interval 4 (delta-encoded index values after shared keys) |
| `rocksdb-sst/v6-xxhash.sst` | RocksDB via rocksdict 0.3.29 | same script: format version 6, xxHash32 checksums, no compression |
| `rocksdb-sst/v4-xxhash64.sst` | RocksDB via rocksdict 0.3.29 | same script: format version 4, xxHash64 checksums, no compression |
| `rocksdb-sst/zstd-dict.sst` | RocksDB via rocksdict 0.3.29 | same script: ZSTD with a 2 KiB compression dictionary of raw samples (`rocksdb.compression_dict`), 512-byte blocks; unedited |
| `rocksdb-sst/zstd-trained.sst` | RocksDB via rocksdict 0.3.29 | same script: the same with `zstd_max_train_bytes` set, so the dictionary is a formatted one from zstd's trainer; 400 rows; unedited |
| `bam/small.bam` | htslib (via pysam, inferred) | htslib BGZF block layout; `@PG ID:gen PN:python` in the header; indexed by bai/small.bam.bai |
| `bam/many-blocks.bam` | samtools 1.16.1 (htslib, Debian bookworm) | `tests/data/bam/many-blocks.sh` in `debian:bookworm-slim`: `samtools view -b --no-PG` of 100 synthetic reads with 60000-byte array tags, 102 BGZF blocks (5.7 MiB of records, most spanning two blocks) ending in the EOF block; reproduced byte-for-byte |
| `bai/small.bam.bai` | htslib (via pysam, inferred) | htslib index with metadata pseudo-bins (bin 37450) |
| `bcf/small.bcf` | htslib (via pysam, inferred) | header has the `##FILTER=<ID=PASS...>` line htslib inserts |
| `vcf-bgzf/small.vcf.bgz` | htslib (via pysam, inferred) | header has the `##FILTER=<ID=PASS...>` line htslib inserts; BGZF with EOF block |
| `tabix/small.vcf.bgz.tbi` | htslib (via pysam, inferred) | tabix index with metadata pseudo-bins |
| `csi/small.vcf.bgz.csi` | htslib (via pysam, inferred) | CSI index with metadata pseudo-bins |
| `cram/small.cram` | htslib (via pysam, inferred) | CRAM file id holds the file name, as htslib writes it |
| `cram/bzip2-lzma.cram` | htslib (via pysam, inferred) | CRAM file id holds the file name; bzip2 and lzma blocks |
| `guitar-pro/` | PyGuitarPro 0.11 (`guitarpro.write`, versions 3.00, 4.06, 5.10, 5.00) | reproduced byte-for-byte: `uv run --with pyguitarpro==0.11 python tests/data/guitar-pro/make.py gp`; the song (notes, effects, names) is ours |
| `pdf/encrypted-empty-aes-128.pdf` | pypdf | `/Producer (pypdf)` (encrypted); the page content is ours. Owner/user passwords: empty |
| `pdf/encrypted-empty-aes-256-r5.pdf` | pypdf | `/Producer (pypdf)`; empty user password |
| `pdf/encrypted-empty-aes-256.pdf` | pypdf | `/Producer (pypdf)`; empty user password |
| `pdf/encrypted-empty-rc4-128.pdf` | pypdf | `/Producer (pypdf)`; empty user password |
| `pdf/encrypted-empty-rc4-40.pdf` | pypdf | `/Producer (pypdf)`; empty user password |
| `pdf/encrypted-password-aes-256.pdf` | pypdf | `/Producer (pypdf)`; user password `fillyfoal` |
| `pdf/encrypted-password-rc4-128.pdf` | pypdf | `/Producer (pypdf)`; user password `fillyfoal` |
| `pdf/gs-1.4.pdf` | Ghostscript 10.07.1 pdfwrite (`-dCompatibilityLevel=1.4 -dPDFSETTINGS=/prepress`, DCT-encoded colour images) | `/Producer (GPL Ghostscript 10.07.1)`; `sh tests/data/pdf/make.sh` run in an empty directory outside the repository (e.g. `/tmp/fixtures/pdf-gen`) with `page.ps`, `make.py` and `make.sh` copied there; reproduces it except for the dates and the XMP/trailer IDs. Classic table, CFF (`/FontFile3 /Type1C`) font subsets, a JPEG image, XMP metadata; the page description `tests/data/pdf/page.ps` is ours |
| `pdf/gs-1.7.pdf` | Ghostscript 10.07.1 pdfwrite (`-dCompatibilityLevel=1.7 -dWriteObjStms=true -dWriteXRefStm=true`) | `/Producer (GPL Ghostscript 10.07.1)`; same command; object streams and a cross-reference stream |
| `pdf/qpdf-linearized.pdf` | qpdf 12.4.2 via pikepdf 10.16.0 (`save(linearize=True)`) of `gs-1.4.pdf` | `tests/data/pdf/make.py`; reproducible given the same `gs-1.4.pdf` (deterministic ID). Linearization dictionary, first-page section, primary hint stream |
| `pdf/qpdf-objstm.pdf` | qpdf 12.4.2 via pikepdf 10.16.0 (`object_stream_mode=generate`) | `make.py`; `gs-1.4.pdf` plus an attached file, an ICC output intent (LittleCMS sRGB from Pillow 12.3) and an `/ICCBased` colour space |
| `pdf/qpdf-aes128-r4.pdf` | qpdf 12.4.2 via pikepdf 10.16.0 (`Encryption(R=4, aes=True)`) | `make.py`; empty user password, owner password `fillyfoal`; extract and annotate denied. Random key material, so not byte-reproducible |
| `pdf/qpdf-aes256-r6.pdf` | qpdf 12.4.2 via pikepdf 10.16.0 (`Encryption(R=6)`, object streams) | `make.py`; empty user password, owner password `fillyfoal`; high-quality printing denied. Random key material |
| `pdf/pypdf-incremental.pdf` | pypdf 6.20.0 (`PdfWriter(..., incremental=True)`, twice) | `make.py`; two incremental updates (cross-reference streams) appended to `gs-1.4.pdf`, each changing `/Title` |
| `pdf/reportlab-form.pdf` | ReportLab 5.0.1 (`rl_config.invariant = 1`) | `/Producer (ReportLab PDF Library - (opensource))`; `make.py` reproduces it except for the timestamps in the embedded font's `head` table. AcroForm text field and check box, link annotation, outlines, a JPEG image, and a TrueType subset (`/FontFile2`) of a box-glyph font `make.py` builds with fontTools |
| `pdf/pyhanko-signed.pdf` | pyHanko 0.37.0 | `/Producer (...; pyHanko 0.37.0)`; `make.py` signs `reportlab-form.pdf` in an incremental update with a throwaway self-signed P-256 key made by OpenSSL (`CN=fillyfoal test`); `/adbe.pkcs7.detached` signature. Not byte-reproducible (fresh key, signing time) |
| `pdf/gs-lzw.pdf` | Ghostscript 10.07.1 pdfwrite (`-dCompatibilityLevel=1.1`) | `/Producer (GPL Ghostscript 10.07.1)`; `sh tests/data/pdf/filters.sh` run in an empty directory outside the repository (e.g. `/tmp/fixtures/pdf-filters`) with `page.ps` copied there; reproduces it except for the dates and IDs. At PDF 1.1 pdfwrite writes `/LZWDecode` streams (the `/ToUnicode` CMaps) |
| `pdf/img2pdf-jpx.pdf` | img2pdf 0.6.1 (pikepdf 10.16.0 engine) of a JPEG 2000 file from OpenJPEG 2.5.4 (`opj_compress -n 3`) | `/Producer (img2pdf 0.6.1)`; `filters.sh`, except for the dates. A `/JPXDecode` image; the 16×16 gradient is ours |
| `pdf/pdftex-type1.pdf` | pdfTeX 1.40.29 (TeX Live 2026) | `/Producer (pdfTeX-1.40.29)`; `filters.sh` reproduces it byte for byte. A Type 1 font program (`/FontFile` with `/Length1`, `/Length2`, `/Length3`) subset by pdfTeX from a box-glyph font of ours assembled by t1asm (metrics by t1rawafm and afm2tfm) |
| `pdf/pdftex-jbig2.pdf` | pdfTeX 1.40.29 (TeX Live 2026) | `/Producer (pdfTeX-1.40.29)`; `filters.sh` reproduces it byte for byte. pdfTeX's JBIG2 inclusion: a `/JBIG2Decode` image in the embedded organisation and its page-0 segments in a `/JBIG2Globals` stream. The JBIG2 file it includes is ours (segment headers from the script, filler data; no JBIG2 encoder was available) |
| `tiff/exif-piexif.tif` | piexif 1.1.3 (thumbnail by Pillow 12.3) | reproduced byte-for-byte: `uv run --with pillow==12.3.0 --with piexif==1.1.3 python tests/data/tiff/exif_piexif.py tests/fixtures/external/tiff/exif-piexif.tif`; the Exif block of a JPEG APP1 segment without its `Exif\0\0` prefix; tag values are ours |
| `tiff/geotiff-bigtiff.tif` | tifffile 2026.9.20 (numpy 2.5.3; ICC profile by Pillow 12.3's LittleCMS) | `uv run --with tifffile==2026.9.20 --with numpy==2.5.3 --with pillow==12.3.0 python tests/data/tiff/geotiff_tifffile.py tests/fixtures/external/tiff/geotiff-bigtiff.tif` reproduces it except for the embedded profile's creation time; the GeoTIFF key values are ours |
| `fits/astropy-tables.fits` | astropy 7.1.1 (numpy 2.3.4) | reproduced byte-for-byte: `uv run --with astropy==7.1.1 --with numpy==2.3.4 python tests/data/fits/astropy_fits.py tests/fixtures/external/fits/astropy-tables.fits`; an unsigned 16-bit image, a binary table with a variable-length array column (heap) and an ASCII table; values are ours |
| `icc/lcms-srgb.icc` | LittleCMS 2 via Pillow 12.3 (`ImageCms.createProfile("sRGB")`) | `uv run --with pillow==12.3.0 python -c "from PIL import ImageCms; open('lcms-srgb.icc','wb').write(ImageCms.ImageCmsProfile(ImageCms.createProfile('sRGB')).tobytes())"` reproduces it except for the creation time in the header |
| `dicom/implicit-nested.dcm` | pydicom 3.0.2 | reproduced byte-for-byte: `uv run --with pydicom==3.0.2 --with numpy==2.3.4 python tests/data/dicom/make_pydicom.py OUTDIR`; Implicit VR Little Endian, an undefined-length sequence of undefined-length items with a nested undefined-length sequence, and a private undefined-length sequence; patient data is neutral (`FILLYFOAL^TEST`) and all UIDs are fixed |
| `dicom/implicit-defined-items.dcm` | pydicom 3.0.2 | same script, byte for byte: Implicit VR Little Endian, defined-length items in an undefined-length sequence |
| `dicom/explicit-undefined-items.dcm` | pydicom 3.0.2 | same script, byte for byte: Explicit VR Little Endian, the nested undefined-length sequences and items of `implicit-nested.dcm` |
| `dicom/rle-encapsulated.dcm` | pydicom 3.0.2 (numpy 2.3.4) | same script, byte for byte: `explicit-undefined-items.dcm` compressed by pydicom's own RLE Lossless encoder, so Pixel Data is encapsulated (Basic Offset Table, one fragment, Sequence Delimitation Item) |
| `dicom/explicit-big-endian.dcm` | pydicom 3.0.2 | same script, byte for byte: the data of `explicit-undefined-items.dcm` in Explicit VR Big Endian |
| `dicom/deflated.dcm` | pydicom 3.0.2 | same script, byte for byte: the same data in Deflated Explicit VR Little Endian (one raw DEFLATE stream, padded to an even length) |
| `dbf/vfp.dbf` | `dbf` 0.99.11 (Python, Ethan Furman) | `uv run --with dbf==0.99.11 python tests/data/dbf/make_dbf.py OUTDIR`; reproduced except the last-update date (bytes 1-3). Visual FoxPro table (version 0x30, code page 0x03) with C, N, F, L, D, I, B, Y and T fields, the 263-byte database backlink, three records (one deleted); dbfread 2.0.7 reads the same values |
| `dbf/db3.dbf` | `dbf` 0.99.11 (Python, Ethan Furman) | same script, same date caveat: dBase III table (code page 0x01) with C, N, L and D fields, two records |
| `segy/big.sgy` | segyio 1.9.13 (numpy 2.3.4) | reproduced byte-for-byte: `uv run --with segyio==1.9.13 --with numpy==2.3.4 python tests/data/segy/make_segyio.py OUTDIR`; big-endian SEG-Y, four traces of ten IEEE float32 samples, our own EBCDIC textual header |
| `segy/little.sgy` | segyio 1.9.13 (numpy 2.3.4) | same script, byte for byte: the same data with `spec.endian = "little"` (segyio writes no byte-order constant) |
| `bed/random.bed` | bedtools 2.30.0 (Debian bookworm) | reproduced byte-for-byte by `tests/data/bed/make_bedtools.sh` in `debian:bookworm-slim` (command in the script): `bedtools random -seed 42` piped to `bedtools sort`, six-column BED with no track line, on a two-chromosome genome of ours |
| `bed/windows.bed` | bedtools 2.30.0 (Debian bookworm) | same script, byte for byte: `bedtools makewindows -w 1000`, three-column BED with no track line |
| `ply/` | plyfile 1.1.5 (numpy 2.5.4) | reproduced byte-for-byte: `uv run --with plyfile==1.1.5 --with numpy==2.5.4 python tests/data/ply/make_plyfile.py OUTDIR`; one cube as `cube-ascii.ply`, `cube-le.ply` and `cube-be.ply`: float/uchar vertices, a `list uchar int` face element (quads and triangles) and an edge element after it; values are ours |
| `shp/` | GDAL 3.14.0dev (404da16b1b) ESRI Shapefile driver, `ghcr.io/osgeo/gdal:alpine-small-latest` (sha256:ce0607777a3c) | reproduced byte-for-byte by `tests/data/shp/make_ogr.sh` (commands in the script) run in that image: `ogr2ogr -lco SHPT=POLYGONZ / ARCM / MULTIPOINTZ / POINT` from hand-written WKT. `polygonz.shp`: a polygon with a hole and a two-part multipolygon (Z); `arcm.shp`: a two-part line with M and a line with no M (no-data); `multipointz.shp`: three Z points; `point.shp`: two points and a null shape. `empty.shp`: a POINT layer with no features (the 100-byte header alone) `ogrinfo -al` reads back the same geometries |
| `shx/polygonz.shx` | GDAL 3.14.0dev, same script | byte for byte: the index written next to `polygonz.shp` |
| `shx/empty.shx` | GDAL 3.14.0dev, same script | byte for byte: the index written next to `empty.shp`, identical to it (told apart by name only) |
| `dbf/gdal-polygonz.dbf` | GDAL 3.14.0dev, same script | the attribute table written next to `polygonz.shp` (dBase III, two C fields, LDID 0x57); reproduced except the last-update date (bytes 1-3) |
| `pdb-structure/ethanol.pdb` | Open Babel 3.1.1 (Debian bookworm) | reproduced byte-for-byte by `tests/data/pdb-structure/make_obabel.sh` in `debian:bookworm-slim`: `obabel -ixyz -opdb` of our XYZ coordinates of ethanol; starts with COMPND and AUTHOR records (no HEADER), HETATM and CONECT records |
| `vector-blf/straddle.blf` | python-can 4.6.1 (`can.BLFWriter`) | reproduced byte-for-byte: `uv run --with python-can==4.6.1 python tests/data/vector-blf/make_python_can.py OUT.blf`; 120 CAN frames in six zlib LOG_CONTAINERs cut at 1000 uncompressed bytes (`max_container_size`), so frames straddle containers; `can.BLFReader` reads all 120 back |
| `las/las14.las` | laspy 2.6.1 (numpy 2.3.4) | reproduced byte-for-byte: `uv run --with laspy==2.6.1 --with lazrs==0.7.0 --with numpy==2.3.4 python tests/data/las/make_laspy.py OUTDIR`; LAS 1.4, point format 6, five points (legacy 32-bit count 0, 64-bit count 5), one VLR and one extended VLR after the points |
| `las/las12.las` | laspy 2.6.1 (numpy 2.3.4) | same script, byte for byte: LAS 1.2, point format 1, the same points and VLR |
| `laz/las14.laz` | laspy 2.6.1 with lazrs 0.7.0 | same script, byte for byte: `las14.las` compressed (layered chunked LASzip), the extended VLR after the chunk table |
| `3ds/pyramid.3ds` | Assimp 5.2.5 (Debian bookworm `assimp-utils`) | reproduced byte-for-byte by `tests/data/3ds/make_assimp.sh` in `debian:bookworm-slim` (`assimp export pyramid.obj pyramid.3ds -f3ds` of our OBJ/MTL): two meshes whose face arrays (0x4120) carry material groups (0x4130), three materials, a keyframer section |
| `sas7bdat/readstat.sas7bdat` | ReadStat 1.1.8 (Debian bookworm `readstat`) | `tests/data/sas7bdat/make_readstat.sh` in `debian:bookworm-slim`: our CSV and JSON metadata to Stata, then `readstat cars.dta readstat.sas7bdat`; 64-bit little-endian, uncompressed, three columns with labels, four rows, one missing value; reproduces it except the creation and modification times. pandas 2.3.3 and pyreadstat 1.3.1 read the same rows |

## Binary value encodings

The values are ours; the generator scripts live in `tests/data/<format>/`
and reproduce every file byte for byte.

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `msgpack/sample.msgpack` | msgpack-python 1.1.2 | `uv run --with msgpack==1.1.2 python tests/data/msgpack/make.py`; a map16 header followed by keys and values each written by `msgpack.packb` (so one value can be single-precision) |
| `bson/` | PyMongo 4.15.3 (`bson.encode`) | `uv run --with pymongo==4.15.3 python tests/data/bson/make.py`; `dump.bson` is four encoded documents concatenated, as mongodump writes a collection |
| `ion/sample.10n` | ion-python (`amazon.ion`) 0.13.0 | `uv run --with amazon.ion==0.13.0 python tests/data/ion/make.py` (`simpleion.dumps(binary=True)`) |
| `ion-text/sample.ion` | ion-python (`amazon.ion`) 0.13.0 | same script, `simpleion.dumps(binary=False, indent="  ")` |
| `ubjson/` | py-ubjson 0.16.1 | `uv run --with py-ubjson==0.16.1 python tests/data/ubjson/make.py`; `counted.ubj` with `container_count=True` |
| `smile/` | smile-js 0.10.1 (npm) | `node tests/data/smile/make.mjs .../smile-js/dist/smile-js.js`; pysmile, the Python binding, is Python 2 only, so the JavaScript encoder stands in |

## OpenSSL

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `x509/leaf.cer` | OpenSSL 3 (openssl CLI) | ECDSA P-256 leaf signed by the test CA in pem/chain.pem; signature verifies |
| `crl/ca.crl` | OpenSSL 3 (openssl CLI) | CRL signed by the test CA |
| `csr/leaf.csr` | OpenSSL 3 (openssl CLI) | self-signature verifies (`openssl req -verify`) |
| `spki/leaf-pub.der` | OpenSSL 3 (openssl CLI, inferred) | SubjectPublicKeyInfo of the leaf key (was `der/leaf-pub.der`) |
| `pkcs7/signed.p7s` | OpenSSL 3 (openssl CLI) | CMS signature verifies (`openssl cms -verify`) |
| `pkcs12/empty-password.p12` | OpenSSL 3 (`openssl pkcs12 -export`) | all four: OpenSSL 3 defaults (SHA-256 MAC, 2048 iterations, PBES2/AES-256-CBC) or `-legacy` (RC2/3DES, SHA-1 MAC); password `fillyfoal` (empty for empty-password.p12) |
| `pkcs12/leaf.p12` | OpenSSL 3 (`openssl pkcs12 -export`) | all four: OpenSSL 3 defaults (SHA-256 MAC, 2048 iterations, PBES2/AES-256-CBC) or `-legacy` (RC2/3DES, SHA-1 MAC); password `fillyfoal` (empty for empty-password.p12) |
| `pkcs12/legacy-rc2-3des.p12` | OpenSSL 3 (`openssl pkcs12 -export`) | all four: OpenSSL 3 defaults (SHA-256 MAC, 2048 iterations, PBES2/AES-256-CBC) or `-legacy` (RC2/3DES, SHA-1 MAC); password `fillyfoal` (empty for empty-password.p12) |
| `pkcs12/modern-aes.p12` | OpenSSL 3 (`openssl pkcs12 -export`) | all four: OpenSSL 3 defaults (SHA-256 MAC, 2048 iterations, PBES2/AES-256-CBC) or `-legacy` (RC2/3DES, SHA-1 MAC); password `fillyfoal` (empty for empty-password.p12) |
| `pkcs12/keytool.p12` | keytool (Eclipse Temurin 21.0.12 JRE) | `sh tests/data/jks/make-keytool.sh` in Docker with no network: an EC private key entry, a trusted certificate and an AES secret key; password `fillyfoal` |
| `pkcs8-encrypted/` | OpenSSL 3 (`openssl pkcs8 -topk8`) | both: `-v1 PBE-SHA1-3DES` and the PBES2/AES-256 default; password `fillyfoal` |
| `x509/ca-rsa.cer` | OpenSSL 3.6.3 (openssl CLI) | `sh tests/data/x509/make.sh` (fresh keys each run: same structure, new bytes): RSA-2048 root CA with name constraints (DNS, email, IPv4/IPv6 ranges, directory name), certificate policies (CPS URI, user notice), policy constraints, inhibitAnyPolicy, Microsoft CA version; checked against `openssl x509 -text` |
| `x509/leaf-p256.cer` | OpenSSL 3.6.3 (openssl CLI) | the same script: P-256 leaf signed by `x509/ca-rsa.cer` with a SAN of every name type, key usage, EKU, AKI with issuer and serial, issuer alternative name, CRL distribution point with reasons and CRL issuer, AIA, TLS feature, Microsoft template name and template, Netscape cert type and comment, and a fabricated RFC 6962 SCT list (two SCTs with filler signatures, handed to openssl as the extension's DER); checked against `openssl x509 -text` |
| `x509/p384.cer` | OpenSSL 3.6.3 (openssl CLI) | the same script: self-signed P-384, ECDSA with SHA-384 |
| `x509/ed25519.cer` | OpenSSL 3.6.3 (openssl CLI) | the same script: self-signed Ed25519 |
| `x509/x25519.cer` | OpenSSL 3.6.3 (openssl CLI) | the same script: X25519 key certified by the CA (`-force_pubkey`) |
| `x509/rsa-pss.cer` | OpenSSL 3.6.3 (openssl CLI) | the same script: RSA-PSS key and signature (SHA-384, MGF1 SHA-384, salt 48) |
| `x509/uuid-oid.cer` | OpenSSL 3.6.3 (openssl CLI) | `sh tests/data/x509/make-uuid-oid.sh` (fresh key each run): self-signed Ed25519 whose certificate policy and one private extension are UUID OIDs (`2.25.<128-bit arc>`); checked against `openssl x509 -text` |
| `crl/revoked.crl` | OpenSSL 3.6.3 (`openssl ca -gencrl`) | the same script: three revocations (keyCompromise, `-crl_compromise` invalidity date, `-crl_hold` hold instruction), issuing distribution point with reasons, AKI, CRL number; checked against `openssl crl -text` |
| `ocsp-request/` | OpenSSL 3.6.3 (`openssl ocsp`) | the same script: a request for three certificates signed by the leaf key with a nonce, and a plain one |
| `ocsp-response/` | OpenSSL 3.6.3 (`openssl ocsp -index`) | the same script: responses over the CA database (revoked with reason, unknown, good; responder by name with certificates, and `-resp_key_id -resp_no_certs`); checked against `openssl ocsp -resp_text` |
| `tsq/` | OpenSSL 3.6.3 (`openssl ts -query`) | the same script: SHA-256 imprint, nonce, certificate requested |
| `tsr/` | OpenSSL 3.6.3 (`openssl ts -reply`) | the same script: TSA with accuracy, ordering, TSA name and ESS signingCertificateV2; checked against `openssl ts -reply -text` |
| `pkcs7/bundle.p7b` | OpenSSL 3.6.3 (`openssl crl2pkcs7`) | the same script: certificates-only SignedData (CA and leaf) |
| `pkcs7/bundle-crl.p7c` | OpenSSL 3.6.3 (`openssl crl2pkcs7`) | the same script: SignedData with the CA certificate and the CRL |
| `pkcs7/enveloped.p7m` | OpenSSL 3.6.3 (`openssl cms -encrypt`) | the same script: EnvelopedData with a key-transport (RSA) and a key-agreement (ECDH) recipient |
| `pkcs7/auth-enveloped.p7m` | OpenSSL 3.6.3 (`openssl cms -encrypt -aes-256-gcm`) | the same script: AuthEnvelopedData, ECDH recipient |
| `pkcs7/password.p7m` | OpenSSL 3.6.3 (`openssl cms -encrypt -pwri_password`) | the same script: password recipient (PBKDF2, PWRI-KEK) |
| `pkcs7/kek.p7m` | OpenSSL 3.6.3 (`openssl cms -encrypt -secretkey`) | the same script: KEK recipient (AES-128 key wrap) |
| `pkcs7/encrypted-data.p7m` | OpenSSL 3.6.3 (`openssl cms -EncryptedData_encrypt`) | the same script: EncryptedData |
| `pkcs7/digested.p7m` | OpenSSL 3.6.3 (`openssl cms -digest_create`) | the same script: DigestedData (SHA-256) |
| `rsa-private-key/` | OpenSSL 3.6.3 (`openssl rsa -traditional -outform DER`) | the same script: PKCS#1 RSA-1024 private key |
| `rsa-public-key/` | OpenSSL 3.6.3 (`openssl rsa -RSAPublicKey_out`) | the same script: PKCS#1 RSAPublicKey of that key |
| `ec-private-key/` | OpenSSL 3.6.3 (`openssl ec -outform DER`) | the same script: SEC 1 P-256 key with its public key, P-384 key `-no_public` |
| `pkcs8/` | OpenSSL 3.6.3 (`openssl pkey -outform DER`) | the same script: unencrypted PKCS#8 of RSA, P-256, Ed25519 and X25519 keys |
| `spki/rsa1024.der` | OpenSSL 3.6.3 (`openssl pkey -pubout`) | the same script: SubjectPublicKeyInfo of the RSA key |
| `spki/p384.der` | OpenSSL 3.6.3 (`openssl pkey -pubout`) | the same script: SubjectPublicKeyInfo of the P-384 key |
| `spki/ed25519.der` | OpenSSL 3.6.3 (`openssl pkey -pubout`) | the same script: SubjectPublicKeyInfo of the Ed25519 key |
| `dh-params/` | OpenSSL 3.6.3 (`openssl dhparam -outform DER`) | the same script: ffdhe2048 as PKCS#3 DHParameter |
| `dsa-params/` | OpenSSL 3.6.3 (`openssl dsaparam`) | the same script: DSA-1024 parameters |
| `dsa-private-key/` | OpenSSL 3.6.3 (`openssl dsa -outform DER`) | the same script: DSA private key (OpenSSL's traditional encoding) |
| `der/generic.der` | OpenSSL 3.6.3 (`openssl asn1parse -genconf`) | the same script: one SEQUENCE of assorted universal types (BOOLEAN, INTEGERs, NULL, OID, strings, times, BIT/OCTET STRING, ENUMERATED, SET, implicit and explicit tags) |
| `pem/chain.pem` | OpenSSL 3 (openssl CLI) | leaf + CA chain; `openssl verify` accepts it |
| `pkcs12/large-plain.p12` | OpenSSL 3.6.3 (`openssl pkcs12 -export -keypbe NONE -certpbe NONE -nomac`) | `sh tests/data/pkcs12/make-large.sh`: a password-less store larger than the probe window, its size from a certificate with a 40,000-byte private extension (1.3.6.1.4.1.55555.9); checked against `openssl pkcs12 -info` |
| `pkcs12/nss-pk12util.p12` | NSS 3.105 `pk12util -o` (Alpine 3.20 nss-tools) | `sh tests/data/pkcs12/make-nss.sh` (Docker, fresh NSS database): an EC P-256 key and certificate made by the host's openssl, imported and exported again; BER throughout (indefinite lengths, segmented OCTET STRINGs), PBES2 with 600,000 iterations, SHA-256 MAC; password `fillyfoal`; checked against `openssl pkcs12 -info` |
| `crl/large.crl` | OpenSSL 3.6.3 (`openssl ca -gencrl`) | `sh tests/data/crl/make-large.sh`: 1000 revoked 20-byte serials from a CA database written by the script (about 39 KB, more than the probe window); checked against `openssl crl -text` |
| `pkcs7/signed-stream.p7m` | OpenSSL 3.6.3 (`openssl cms -sign -stream -outform DER`) | `sh tests/data/pkcs7/make-stream.sh`: BER-streamed SignedData (indefinite lengths, segmented eContent), content attached, no certificates; checked against `openssl asn1parse` |
| `pkcs7/enveloped-stream.p7m` | OpenSSL 3.6.3 (`openssl cms -encrypt -stream -outform DER`) | the same script: BER-streamed EnvelopedData, AES-256-CBC, RSA key-transport recipient |

## Keyrings, Kerberos and age (Docker)

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `age/` | age 1.2.1 (Alpine 3.20 package) | `sh tests/data/age/make.sh` (random keys and file keys): X25519 recipient, passphrase `fillyfoal` (scrypt, work factor 18), ssh-ed25519 and ssh-rsa recipients; stanzas checked against the age v1 specification |
| `pem/age-armored.age` | age 1.2.1 (Alpine 3.20 package) | the same script: `age -a`, an ASCII-armored X25519 file |
| `gnome-keyring/secret-tool.keyring` | gnome-keyring-daemon 48.0 and libsecret's secret-tool (Debian trixie) | `sh tests/data/gnome-keyring/make.sh` in Docker with no network: login keyring unlocked with `fillyfoal`, two items stored with secret-tool; decrypts with the test password (MD5 check of the decrypted items matches) |
| `pgp/gpg-key.gpg` | GnuPG 2.4.9 (Alpine 3.20) | `sh tests/data/pgp/make-gpg.sh` (Docker, throwaway GNUPGHOME): Ed25519 primary key with signing, Curve25519 encryption and authentication subkeys (embedded back-signature), expiries and a second user ID; checked against `gpg --list-packets --verbose` |
| `pgp/gpg-signed-encrypted.gpg` | GnuPG 2.4.9 (Alpine 3.20) | the same script: signed (with a notation), ZLIB-compressed and encrypted to the key (ECDH, AES-256 OCB AEAD packet) |
| `pgp/gpg-symmetric.gpg` | GnuPG 2.4.9 (Alpine 3.20) | the same script: `--symmetric` with passphrase `fillyfoal` (iterated SHA-512 S2K, AES-256, SEIPD v1 with MDC); decrypts with the test passphrase |
| `pgp/gpg-detached.sig` | GnuPG 2.4.9 (Alpine 3.20) | the same script: a detached signature by the signing subkey |
| `pgp/gpg-signed.gpg` | GnuPG 2.4.9 (Alpine 3.20) | `sh tests/data/pgp/make-gpg-wave-a.sh` (Docker, throwaway GNUPGHOME, unprotected throwaway key): plain `gpg -s`, a ZIP Compressed Data packet of indeterminate length (old format, `a3 01`); checked against `gpg --list-packets --verbose` |
| `pgp/gpg-secret-subkeys.gpg` | GnuPG 2.4.9 (Alpine 3.20) | the same script: `--export-secret-subkeys`; the primary key is a GNU-dummy stub (S2K specifier 101, mode 1001), the encryption subkey unprotected |
| `keybox/gnupg-2.2.kbx` | GnuPG 2.2.40 (gpg and gpgsm, Debian bookworm), OpenSSL 3.0 for the certificate | `sh tests/data/keybox/make.sh` (Docker, fresh GNUPGHOME, unprotected throwaway keys, neutral user IDs): the `pubring.kbx` holding an Ed25519/Curve25519 key with two user IDs, an RSA-2048 key, and a P-256 certificate made with `openssl req -x509` and imported with `gpgsm --import`; every field checked against `kbxutil` (all three SHA-1 checksums valid). GnuPG 2.4.7 (Debian trixie) writes the same blob layout (version 1, 28-byte key entries) for these keys |
| `keybox/gnupg-2.4-v5.kbx` | GnuPG 2.4.9 (Alpine 3.20) | `sh tests/data/keybox/make-v5.sh` (Docker, fresh GNUPGHOME, unprotected throwaway keys, neutral user IDs): an Ed25519/Curve25519 v5 key (`--rfc4880bis`, `Key-Version: 5`) in a version 2 blob (56-byte key entries, 32-byte fingerprints) and an Ed25519 v4 key in a version 1 blob; every field checked against `kbxutil` (both SHA-1 checksums valid) and the v2 entry layout against `kbx/keybox-blob.c` (fingerprint, flags, reserved, 20-byte keygrip slot written as zeros) |
| `pgp/gpg-bzip2.gpg` | GnuPG 2.4.9 (Alpine 3.20) | `sh tests/data/pgp/make-gpg-bzip2.sh` (Docker, throwaway GNUPGHOME, unprotected throwaway key): `gpg --compress-algo bzip2 -s`, a BZip2 Compressed Data packet of indeterminate length holding the one-pass signature, literal data and signature; checked against `gpg --list-packets --verbose` |
| `pgp-armor/gpg-clearsigned.asc` | GnuPG 2.4.9 (Alpine 3.20) | the same script: `--clearsign` (SHA-512) of a text with dash-escaped lines |
| `krb5-ccache/` | MIT Kerberos 1.21.3 (Debian trixie krb5-kdc, krb5-user) | `sh tests/data/krb5-ccache/make.sh` in Docker with no network: a throwaway KDC for FILLYFOAL.TEST; `kinit -f -r 2d` and `kvno` into a version 4 cache (TGT and two service tickets, a `fast_avail` config entry), `ccache_type = 3` for a version 3 cache; checked against `klist -e -f -a` |
| `putty-key/` | PuTTYgen 0.83 (Debian trixie putty-tools) | `sh tests/data/putty-key/make-puttygen.sh` in Docker with no network: PPK v3 Ed25519 and ECDSA P-384 keys without a passphrase, an RSA-1024 key encrypted with Argon2id (64 KiB, 1 pass), a PPK v2 encrypted Ed25519 key; passphrase `fillyfoal`; every MAC verifies |
| `jks/keytool.jks` | keytool (Eclipse Temurin 21.0.12 JRE) | `sh tests/data/jks/make-keytool.sh` in Docker with no network: an EC private key entry with its certificate and a trusted certificate; password `fillyfoal` |
| `jks/keytool.jceks` | keytool (Eclipse Temurin 21.0.12 JRE) | the same script: JCEKS with an EC private key entry, a trusted certificate and an AES-128 secret key |
| `krb5-keytab/` | MIT Kerberos 1.21.3 (`kadmin.local ktadd`) | the same script: keys of two service principals (AES-256, AES-128, AES-256-SHA384) |

## FFmpeg: images

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `bmp/testsrc-bgr24.bmp` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=12x8:rate=1 -frames:v 1 -pix_fmt bgr24` |
| `bmp/testsrc-bgra.bmp` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=12x8:rate=1 -frames:v 1 -pix_fmt bgra` |
| `bmp/testsrc-monob.bmp` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=12x8:rate=1 -frames:v 1 -pix_fmt monob` |
| `bmp/testsrc-rgb565.bmp` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=12x8:rate=1 -frames:v 1 -pix_fmt rgb565le` |
| `bmp/testsrc-pal8.bmp` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=12x8:rate=1 -frames:v 1 -pix_fmt pal8` |
| `bmp/testsrc-rgb555.bmp` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=12x8:rate=1 -frames:v 1 -pix_fmt rgb555le` |
| `png/apng.png` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=8x6:rate=10 -frames:v 3 -plays 0 -f apng` |
| `png/cicp-bt709.png` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=8x6:rate=1 -frames:v 1 -vf setparams=color_primaries=bt709:color_trc=bt709:colorspace=bt709` (cICP, cHRM, gAMA) |
| `png/hdr10.png` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) with libx265 4.2 | reproduced byte-for-byte with ffmpeg 8.1.2 in two steps: `-f lavfi -i testsrc=size=64x64:rate=1 -frames:v 1 -pix_fmt yuv420p10le -c:v libx265 -x265-params "log-level=error:hdr10=1:colorprim=bt2020:transfer=smpte2084:colormatrix=bt2020nc:master-display=G(13250,34500)B(7500,3000)R(34000,16000)WP(15635,16450)L(10000000,1):max-cll=1000,400" hdr.hevc`, then `-i hdr.hevc -frames:v 1 -vf scale=8:6,format=rgb48be hdr10.png` (cICP, cLLI, mDCV). Note: FFmpeg 8.1.2's PNG encoder writes the mDCV primaries out of order (34000, 13250, 7500, 3000, 2, 0 for red, green, blue x/y); `ffprobe -show_frames` of the PNG reads back the same values as the dissector |
| `dpx/testsrc-rgb10.dpx` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=4x2:rate=1 -frames:v 1 -pix_fmt gbrp10le` |
| `dpx/testsrc-rgb48.dpx` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=4x2:rate=1 -frames:v 1 -pix_fmt rgb48le` |
| `exr/testsrc-none.exr` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=2x2:rate=25 -frames:v 1 -pix_fmt gbrapf32le` |
| `exr/testsrc-zip.exr` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=4x3:rate=25 -frames:v 1 -pix_fmt gbrpf32le -compression zip1` |
| `fits/testsrc-gray16.fits` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=6x4:rate=1 -frames:v 1 -pix_fmt gray16le` |
| `hdr/testsrc.hdr` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=8x4:rate=1 -frames:v 1 -pix_fmt gbrpf32le` |
| `pam/testsrc.pam` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=4x3:rate=1 -frames:v 1 -pix_fmt rgba` |
| `pbm/testsrc.pbm` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=12x4:rate=1 -frames:v 1 -pix_fmt monow` |
| `pcx/testsrc-pal8.pcx` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=8x6:rate=1 -frames:v 1 -pix_fmt pal8` |
| `pcx/testsrc-rgb24.pcx` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=8x6:rate=1 -frames:v 1 -pix_fmt rgb24` |
| `pfm/testsrc.pfm` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=3x2:rate=1 -frames:v 1 -pix_fmt gbrpf32le` |
| `pgm/testsrc-16bit.pgm` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=4x3:rate=1 -frames:v 1 -pix_fmt gray16le` |
| `pgm/testsrc.pgm` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=6x4:rate=1 -frames:v 1 -pix_fmt gray` |
| `ppm/testsrc.ppm` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=6x4:rate=1 -frames:v 1 -pix_fmt rgb24` |
| `qoi/testsrc.qoi` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=8x6:rate=1 -frames:v 1 -pix_fmt rgba` |
| `sgi/testsrc-rle.sgi` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=8x6:rate=1 -frames:v 1 -pix_fmt gbrp` |
| `sgi/testsrc-verbatim.sgi` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=8x6:rate=1 -frames:v 1 -pix_fmt gray -rle 0` |
| `sunras/testsrc-rle-pal8.ras` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=8x6:rate=1 -frames:v 1 -pix_fmt pal8` |
| `sunras/testsrc.ras` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=8x6:rate=1 -frames:v 1 -pix_fmt bgr24 -rle 0` |
| `tga/testsrc.tga` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=8x6:rate=1 -frames:v 1 -pix_fmt bgr24` |
| `tiff/testsrc-rgb24.tif` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=8x6:rate=1 -frames:v 1 -pix_fmt rgb24` |
| `wbmp/testsrc.wbmp` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=10x4:rate=1 -frames:v 1 -pix_fmt monob` |
| `xbm/testsrc.xbm` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=10x3:rate=1 -frames:v 1 -pix_fmt monow` |
| `xwd/testsrc-pal8.xwd` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=4x2:rate=1 -frames:v 1 -pix_fmt pal8` |
| `xwd/testsrc-rgb24.xwd` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=4x3:rate=1 -frames:v 1 -pix_fmt rgb24` |
| `gif/anim.gif` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=8x6:rate=25 -frames:v 3` (bitexact) |
| `j2k/testsrc.j2k` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | `Lavc` comment marker in the codestream; not byte-reproduced |
| `j2k/tiled-gray.j2k` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | `Lavc` comment marker in the codestream; not byte-reproduced |
| `j2k/opj-tile-parts.j2k` | OpenJPEG 2.5.4 (`opj_compress`) | reproduced byte-for-byte: `sh tests/data/j2k/tile_parts.sh opj-tile-parts.j2k` (`opj_compress -t 32,32 -TP R -n 3` on a 64×64 greyscale gradient of ours); four tiles of three tile-parts each (TPsot 0..2, TNsot 3) |
| `jp2/ffmpeg.jp2` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | commit b86c5c84 ("fixtures generated with ffmpeg"); `Lavc` marker |
| `avif/svtav1.avif` | FFmpeg 8 with libsvtav1 | commit b86c5c84 ("fixtures generated with ffmpeg and sips") |
| `jpeg/ffmpeg-420.jpg` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=32x24:rate=1 -frames:v 1 -pix_fmt yuvj420p` (`Lavc` comment) |
| `jpeg/ffmpeg-jpegls.jpg` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=32x24:rate=1 -frames:v 1 -c:v jpegls` (JPEG-LS, RGB) |
| `avif/grid-alpha.avif` | avifenc 1.4.2 (aom 3.15.0) | reproduced byte-for-byte: `avifenc -q 20 --qalpha 20 -s 10 -y 420 -g 2x1 --exif exif.bin --xmp xmp.xml --irot 1 --imir 0 --pasp 1,1 --clli 1000,400 --cicp 1/13/6 tile.png tile.png`; tile.png from FFmpeg `testsrc=size=64x64,format=rgba,geq=...:a='X*4'`; exif.bin from piexif 1.1.3 (Make fillyfoal, Model Fixture, ISO 400); xmp.xml a one-element XMP packet |
| `avif/sequence.avifs` | avifenc 1.4.2 (aom 3.15.0) | `avifenc -q 30 -s 10 --fps 10 frame1.png frame2.png frame3.png` on three 16×16 `testsrc` frames from FFmpeg; reproduced except the creation/modification times avifenc writes |

## FFmpeg: audio

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `adx/tone.adx` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.05 -ac 1 -fflags +bitexact -flags:a +bitexact` |
| `ast/tone.ast` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.05 -ac 1 -fflags +bitexact -flags:a +bitexact` |
| `ircam/tone.sf` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.05 -ac 1 -fflags +bitexact -flags:a +bitexact` |
| `kvag/tone.vag` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.05 -ac 1 -fflags +bitexact -flags:a +bitexact` |
| `rso/tone.rso` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.05 -ac 1 -fflags +bitexact -flags:a +bitexact` |
| `smaf/tone.mmf` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.05 -ac 1` |
| `w64/tone.w64` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.05 -ac 1 -fflags +bitexact -flags:a +bitexact` |
| `voc/tone.voc` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.05 -ac 1 -c:a pcm_u8 -fflags +bitexact -flags:a +bitexact` |
| `voc/pcm16.voc` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.05 -ac 1 -c:a pcm_s16le -fflags +bitexact -flags:a +bitexact` |
| `au/mulaw.au` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.05 -ac 1 -c:a pcm_mulaw -fflags +bitexact -flags:a +bitexact` |
| `caf/pcm.caf` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.05 -ac 1 -c:a pcm_s16be -metadata title=Tone -fflags +bitexact -flags:a +bitexact` |
| `caf/alac.caf` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.1 -ac 1 -c:a alac -fflags +bitexact -flags:a +bitexact` |
| `tta/tone.tta` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.1 -ac 1 -fflags +bitexact -flags:a +bitexact` |
| `ilbc/tone.lbc` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.1 -ac 1 -fflags +bitexact -flags:a +bitexact` |
| `ogg-flac/tone.oga` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.1 -ac 1 -fflags +bitexact -flags:a +bitexact` |
| `wavpack/tone.wv` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.1 -ac 1 -metadata title=Tone -fflags +bitexact -flags:a +bitexact` |
| `aac/tone.aac` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.1 -ac 1 -b:a 16k` |
| `ac3/tone.ac3` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=32000:duration=0.1 -ac 1 -b:a 32k -fflags +bitexact -flags:a +bitexact` |
| `ac3/tone.eac3` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=32000:duration=0.1 -ac 1 -b:a 32k -fflags +bitexact -flags:a +bitexact` |
| `aiff/tone.aiff` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.02 -ac 1 -metadata title=Tone -metadata artist=fillyfoal -metadata copyright=none -metadata comment=annotation -write_id3v2 1 -fflags +bitexact -flags:a +bitexact` |
| `aifc/alaw.aifc` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.02 -ac 1 -c:a pcm_alaw -f aiff -fflags +bitexact -flags:a +bitexact` |
| `aifc/sowt.aifc` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=11025:duration=0.02 -ac 1 -c:a pcm_s16le -f aiff -fflags +bitexact -flags:a +bitexact` |
| `sox/tone.sox` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.05 -ac 1 -metadata "comment=sox comment" -fflags +bitexact -flags:a +bitexact` |
| `wav/extensible.wav` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=4000:duration=0.02 -ac 3 -c:a pcm_s24le` (bitexact) |
| `wav/rf64.wav` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=4000:duration=0.02 -ac 1 -c:a pcm_mulaw -rf64 always` (bitexact) |
| `wav/info-bext.wav` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | `Lavf` software tag next to the bext and INFO chunks; not byte-reproduced |
| `wav/float-5.1.wav` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.01 -af 'pan=5.1\|c0=c0\|c1=c0\|c2=c0\|c3=c0\|c4=c0\|c5=c0' -c:a pcm_f32le -fflags +bitexact -flags:a +bitexact` (WAVE_FORMAT_EXTENSIBLE, IEEE float, mask 0x3f) |
| `wav/adpcm-ms.wav` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.05 -ac 1 -c:a adpcm_ms -fflags +bitexact -flags:a +bitexact` |
| `wav/adpcm-ima.wav` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.1 -ac 1 -c:a adpcm_ima_wav -fflags +bitexact -flags:a +bitexact` |
| `wav/mp3.wav` | FFmpeg 8 (libavformat 62.12.102) with LAME (libmp3lame) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.2 -ac 1 -c:a libmp3lame -b:a 8k -fflags +bitexact -flags:a +bitexact` (MPEGLAYER3WAVEFORMAT) |
| `wav/ac3.wav` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte by `tests/data/video/make.sh` (ffmpeg 8.1.2): `-f lavfi -i sine=frequency=440:sample_rate=32000:duration=0.1 -ac 1 -c:a ac3 -b:a 32k -fflags +bitexact -flags:a +bitexact` (format tag 0x2000) |
| `wav/adpcm-ima-stereo.wav` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte by `tests/data/video/make.sh` (ffmpeg 8.1.2): `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.1 -ac 2 -c:a adpcm_ima_wav -block_size 256 -fflags +bitexact -flags:a +bitexact` (four 256-byte blocks) |
| `wav/bext-levl.wav` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.05 -ac 1 -c:a pcm_s16le -write_bext 1 -write_peak on -peak_block_size 64 -metadata description="Test tone for bext" -metadata originator="fillyfoal" -metadata originator_reference="FF-REF-0001" -metadata origination_date="2026-10-09" -metadata origination_time="12:34:56" -metadata time_reference=172800000 -metadata umid=0x060A2B340101010501010D4313000000AABBCCDDEEFF00112233445566778899 -metadata coding_history="A=PCM,F=8000,W=16,M=mono,T=fillyfoal" -metadata title="Tone" -metadata artist="fillyfoal" -fflags +bitexact -flags:a +bitexact` |
| `aifc/fl32.aifc` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=44100:duration=0.005 -ac 2 -c:a pcm_f32be -f aiff -fflags +bitexact -flags:a +bitexact` |
| `aifc/ima4.aifc` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.05 -ac 1 -c:a adpcm_ima_qt -f aiff -fflags +bitexact -flags:a +bitexact` |
| `aifc/ima4-afconvert.aifc` | macOS 26.5 `afconvert` (Audio File Convert 2.0) | reproduced byte-for-byte: `afconvert -f AIFC -d ima4 src16k.wav`, where `src16k.wav` is ffmpeg's `-f lavfi -i sine=frequency=440:sample_rate=16000:duration=0.2 -ac 1 -c:a pcm_s16le -fflags +bitexact -flags:a +bitexact` (CHAN and FLLR chunks, compression name) |
| `caf/aac-afconvert.caf` | macOS 26.5 `afconvert` (Audio File Convert 2.0) with Apple's AAC encoder | reproduced byte-for-byte: `afconvert -f caff -d aac -b 32000 src16k.wav` (same source as above; kuki ES descriptor, pakt, info, free) |
| `caf/alac-afconvert.caf` | macOS 26.5 `afconvert` (Audio File Convert 2.0) | reproduced byte-for-byte: `afconvert -f caff -d alac src16k.wav` (bare ALACSpecificConfig cookie) |
| `caf/opus-afconvert.caf` | macOS 26.5 `afconvert` (Audio File Convert 2.0) | reproduced byte-for-byte: `afconvert -f caff -d opus src16k.wav` |
| `caf/surround.caf` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.01 -af 'pan=5.1\|c0=c0\|c1=c0\|c2=c0\|c3=c0\|c4=c0\|c5=c0' -c:a pcm_s16le -fflags +bitexact -flags:a +bitexact` (chan tag MPEG 5.1 A) |
| `wavpack/float-5.1.wv` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.02 -af 'pan=5.1\|c0=c0\|c1=c0\|c2=c0\|c3=c0\|c4=c0\|c5=c0' -sample_fmt fltp -c:a wavpack -fflags +bitexact -flags:a +bitexact` (three blocks per sample block, channel info) |
| `midi/band.mid` | mido 1.3.3 (`MidiFile.save`) | reproduced byte-for-byte: `uv run --with mido==1.3.3 python tests/data/midi/make.py`; the music is ours; mido writes running status |
| `wma/wmav2.wma` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.2 -ac 1 -c:a wmav2 -b:a 32k` |
| `mp3/layer2.mp2` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=16000:duration=0.1 -ac 1 -c:a mp2 -b:a 32k -f mp2` |
| `mp3/cbr-id3v23.mp3` | FFmpeg 8 with libmp3lame | `Lavf`/`Lavc` strings and Info/LAME tag; ID3v2.3 tag |
| `mp3/vbr-id3v24.mp3` | FFmpeg 8 with libmp3lame | `Lavf`/`Lavc` strings and Xing/LAME tag; ID3v2.4 with an attached picture |
| `id3/tag-only.id3` | FFmpeg 8 with libmp3lame | edit: the first 279 bytes (the ID3v2.4 tag) of mp3/vbr-id3v24.mp3, unchanged |
| `flac/tone.flac` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | vendor string `ffmpeg` (what FFmpeg writes with `-fflags +bitexact`), attached PNG picture; not byte-reproduced |
| `ogg/vorbis.ogg` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | `encoder=Lavc vorbis` comment, `ffmpeg` vendor string |
| `opus/tone.opus` | FFmpeg 8 with libopus | `encoder=Lavc libopus` comment |
| `mp3/lame-vbr-tags.mp3` | LAME 4.0, then mutagen 1.48.1 | written by `tests/data/mp3/make.py`: `lame -V 6 -m m` (VBR, Xing + LAME tag), then mutagen's ID3v2.4 (pictures, chapters, SYLT, ETCO, RVA2, POPM, PRIV, UFID, GEOB, ...) and ID3v1.1, then mutagen's APEv2 with cover art; pictures drawn by FFmpeg's `testsrc` |
| `mp3/lame-crc-v23.mp3` | LAME 4.0, then mutagen 1.48.1 | written by `tests/data/mp3/make.py`: `lame -p -b 32 -m m` (CRC-protected frames, Info + LAME tag), then mutagen's ID3v2.3 with chapters and a PNG picture |
| `mp3/freeformat.mp3` | LAME 4.0 | written by `tests/data/mp3/make.py`: `lame --freeformat -b 400 -t` (free-format bitstream, no Xing frame) |
| `flac/cuesheet.flac` | FFmpeg 8.1.2, then mutagen 1.48.1 | written by `tests/data/mp3/make.py`: FFmpeg FLAC with an attached PNG picture, then mutagen adds a CUESHEET, a SEEKTABLE (with a placeholder), an APPLICATION block and padding |
| `opus/picture.opus` | FFmpeg 8.1.2 with libopus, then mutagen 1.48.1 | written by `tests/data/mp3/make.py`: mutagen adds a METADATA_BLOCK_PICTURE comment |
| `aac/tone.loas` | FFmpeg 8.1.2 | written by `tests/data/mp3/make.py`: `-c:a aac -b:a 16k -smc-interval 4 -f latm` (bitexact) |
| `ac3/surround.ac3` | FFmpeg 8.1.2 | written by `tests/data/mp3/make.py`: 5.1 at 192 kbps with dialnorm, mixing level, room type and the alternate bit stream syntax options (`-dmix_mode ltrt`, `-dsurex_mode on`, `-ad_conv_type hdcd`, ...) |
| `ac3/surround.eac3` | FFmpeg 8.1.2 | written by `tests/data/mp3/make.py`: E-AC-3 5.1 at 192 kbps with mixing metadata (`-dmix_mode loro`, mix levels, room type) |
| `dts/surround.dts` | FFmpeg 8.1.2 (experimental `dca` encoder) | written by `tests/data/mp3/make.py`: 5.1(side) at 768 kbps, `-f dts` |
| `ac3/id3v2.ac3` | FFmpeg 8.1.2, mutagen 1.47.0 | written by `tests/data/ac3/tagged.py` (reproduces byte for byte): mono AC-3 at 32 kbps, then an ID3v2.3 tag (title, artist) before it and an ID3v1 tag after it, written by mutagen without padding |
| `dts/id3v2.dts` | FFmpeg 8.1.2 (experimental `dca` encoder), mutagen 1.47.0 | written by `tests/data/ac3/tagged.py` (reproduces byte for byte): one 5.1(side) DTS frame at 768 kbps, tagged as above |

## FFmpeg: video and containers

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `y4m/420jpeg.y4m` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=16x16:rate=5 -frames:v 1 -pix_fmt yuv420p -f yuv4mpegpipe` (bitexact) |
| `y4m/two-frames-422.y4m` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=8x8:rate=5 -frames:v 2 -pix_fmt yuv422p -f yuv4mpegpipe` (bitexact) |
| `ivf/vp8.ivf` | FFmpeg 8 with libvpx | reproduced byte-for-byte with ffmpeg 8.1.2: `testsrc=size=16x16:rate=5 -frames:v 1 -c:v libvpx -f ivf` (bitexact) |
| `ivf/vp9.ivf` | FFmpeg 8 with libvpx-vp9 | reproduced byte-for-byte with ffmpeg 8.1.2: `testsrc=size=16x16:rate=5 -frames:v 1 -c:v libvpx-vp9 -pix_fmt gbrp -f ivf` (bitexact) |
| `ivf/av1.ivf` | FFmpeg 8 with libsvtav1 (SVT-AV1 4.1) | reproduced byte-for-byte with ffmpeg 8.1.2: `testsrc=size=16x16:rate=5 -frames:v 2 -c:v libsvtav1 -f ivf` (bitexact) |
| `obu/av1.obu` | FFmpeg 8 with libsvtav1 (SVT-AV1 4.1) | reproduced byte-for-byte with ffmpeg 8.1.2: as ivf/av1.ivf with `-f obu` |
| `film/cinepak.cpk` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `testsrc=size=16x16:rate=5 -frames:v 2 -c:v cinepak -pix_fmt rgb24 -f film_cpk` (bitexact) |
| `swf/flv-video.swf` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `testsrc=size=16x16:rate=5 -frames:v 2 -c:v flv1 -f swf` (bitexact) |
| `mpeg1video/three-frames.m1v` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `testsrc=size=16x16:rate=25 -frames:v 3 -c:v mpeg1video` (bitexact) |
| `mpeg2video/three-frames.m2v` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `testsrc=size=16x16:rate=5 -frames:v 1 -c:v mpeg2video` (bitexact) |
| `h263/sqcif.h263` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `testsrc=size=128x96:rate=5 -frames:v 2 -c:v h263` (bitexact) |
| `dnxhd/dnxhr-lb.dnxhd` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `testsrc=size=256x120:rate=25 -frames:v 1 -c:v dnxhd -profile:v dnxhr_lb -pix_fmt yuv422p` (bitexact) |
| `mpeg-ps/mpeg2.vob` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `testsrc=size=16x16:rate=25` + `sine=sample_rate=48000:duration=0.12`, `-frames:v 3 -c:v mpeg2video -c:a mp2 -ac 1 -f vob` |
| `mpeg1-system/mpeg1.mpg` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | inferred: carries the same MPEG-1 video as mpeg1video/three-frames.m1v in FFmpeg's MPEG-PS pack layout; not byte-reproduced |
| `dirac/vc2-hq.drc` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | `Lavc` marker (FFmpeg VC-2 encoder) |
| `mpeg4video/three-vops.m4v` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | `Lavc` user data |
| `h264/x264-three-frames.h264` | FFmpeg/x264 (x264 core 165) | x264 settings SEI |
| `hevc/x265-three-frames.hevc` | x265 | inferred: a raw HEVC stream from a real encoder (x265 is the only one used here); no info SEI, exact invocation unknown |
| `3g2/h263-aac.3g2` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | `Lavc` marker; commit b86c5c84 ("fixtures generated with ffmpeg") |
| `3gp/h263-aac.3gp` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | `Lavc` marker; commit b86c5c84 |
| `m4a/song.m4a` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | `Lavf`/`Lavc` markers; commit b86c5c84 |
| `m4a/tags.m4a` | FFmpeg 8.1.2 (aac), then mutagen 1.48.1 | reproduced byte-for-byte: FFmpeg `sine=sample_rate=22050:duration=0.1` + an 8×8 red PNG (`color=c=red:size=8x8`, bitexact) + the chapters of mov/hevc-pcm.mov, `-c:a aac -b:a 24k -ac 1 -c:v copy -disposition:v attached_pic` with title/artist/album/album_artist/genre/date/track 3/12/disc 1/2/composer/comment/compilation/gapless_playback/media_type metadata, `-fflags +bitexact -flags:a +bitexact`; then mutagen added `----:com.apple.iTunes:REPLAYGAIN_TRACK_GAIN` = `-6.50 dB` and `tmpo` = 120 |
| `mov/mpeg4.mov` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | `Lavf`/`Lavc` markers; commit b86c5c84 |
| `mov/hevc-pcm.mov` | FFmpeg 8.1.2 (libx265, pcm_s16le, mov muxer) | reproduced byte-for-byte in two steps: (1) `testsrc=size=64x48:rate=30000/1001,format=yuv420p` + `sine=sample_rate=8000:duration=0.1`, `-frames:v 3 -c:v libx265 -tag:v hvc1 -c:a pcm_s16le -t 0.1` `-fflags +bitexact -flags:v +bitexact -flags:a +bitexact` → stage1.mov; (2) `-display_rotation:v:0 90 -i stage1.mov -i chapters.ffmeta -map 0:v -map 0:a -map_metadata 1 -map_chapters 1 -c copy -timecode "01:02:03;04" -metadata com.apple.quicktime.make=fillyfoal -metadata com.apple.quicktime.location.ISO6709=+46.0500+014.5000/ -movflags use_metadata_tags -fflags +bitexact`; chapters.ffmeta: title "Chaptered", chapters "Opening" 0–40 ms and "Ending" 40–80 ms |
| `mp4/fragmented.mp4` | FFmpeg 8 with libx264 | `Lavf`/`Lavc`/x264 markers; commit b86c5c84 |
| `mp4/h264-aac.mp4` | FFmpeg 8 with libx264 | `Lavf`/`Lavc`/x264 markers; commit b86c5c84 |
| `mp4/hevc.mp4` | FFmpeg 8 with libx265 | `Lavf`/`Lavc`/x265 markers; commit b86c5c84 |
| `mp4/audio-codecs.mp4` | FFmpeg 8.1.2 (libopus, ac3, flac, eac3, alac, AudioToolbox aac_at) | reproduced byte-for-byte: `sine=frequency=440:sample_rate=48000:duration=0.1` and `...:sample_rate=44100...` inputs, `-map 0 -map 0 -map 1 -map 0 -map 1 -map 1 -c:a:0 libopus -b:a:0 16k -ac:a:0 1 -c:a:1 ac3 -b:a:1 96k -ac:a:1 6 -c:a:2 flac -ac:a:2 1 -c:a:3 eac3 -b:a:3 64k -ac:a:3 2 -c:a:4 alac -ac:a:4 2 -c:a:5 aac_at -profile:a:5 28 -ac:a:5 2 -b:a:5 32k -map_metadata -1` `-fflags +bitexact -flags:v +bitexact -flags:a +bitexact` (profile 28 = HE-AACv2) |
| `mp4/mp3-dts.mp4` | FFmpeg 8.1.2 (libmp3lame / LAME, experimental `dca` encoder) | reproduced byte-for-byte: `-f lavfi -i sine=frequency=440:sample_rate=48000:duration=0.06 -map 0 -map 0 -c:a:0 libmp3lame -b:a:0 32k -ac:a:0 1 -c:a:1 dca -strict -2 -b:a:1 768k -filter:a:1 "aformat=channel_layouts=5.1(side)" -map_metadata -1 -fflags +bitexact -flags:a +bitexact` (both tracks are `mp4a` with `esds` object types 0x6B and 0xA9) |
| `mp4/video-codecs.mp4` | FFmpeg 8.1.2 (libvpx-vp9, libsvtav1 4.1.0) | reproduced byte-for-byte: `testsrc=size=64x64:rate=25,format=yuv420p`, `-map 0 -map 0 -frames:v 2 -c:v:0 libvpx-vp9 -b:v:0 30k -c:v:1 libsvtav1 -preset:v:1 12 -crf:v:1 55 -color_primaries:v bt709 -color_trc:v bt709 -colorspace:v bt709 -color_range:v tv -map_metadata -1` `-fflags +bitexact -flags:v +bitexact -flags:a +bitexact` |
| `mp4/subtitles.mp4` | FFmpeg 8.1.2 (mov_text, ttml) | reproduced byte-for-byte: a two-cue SRT ("Hello" 0–0.5 s, "World" 0.6–1 s) given twice, `-map 0 -map 1 -c:s:0 mov_text -c:s:1 ttml -metadata:s:s:0 language=eng -metadata:s:s:1 language=deu -fflags +bitexact` |
| `mp4/cenc-fragmented.mp4` | FFmpeg 8.1.2 (libx264, aac, CENC encryption) | reproduced byte-for-byte: `testsrc=size=32x32:rate=10,format=yuv420p` + `sine=sample_rate=16000:duration=0.4`, `-frames:v 4 -t 0.4 -c:v libx264 -g 2 -c:a aac -b:a 16k -ac 1 -encryption_scheme cenc-aes-ctr -encryption_key 00112233445566778899aabbccddeeff -encryption_kid 0123456789abcdef0123456789abcdef -movflags frag_keyframe+empty_moov+default_base_moof+separate_moof -write_prft pts` `-fflags +bitexact -flags:v +bitexact -flags:a +bitexact` (a test key, not a secret) |
| `avi/mjpeg-pcm.avi` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | `Lavc` marker in the MJPEG frames |
| `flv/h263-nellymoser.flv` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | `Lavf` encoder metadata |
| `flv/h264-aac.flv` | FFmpeg 8 with libx264 | `Lavf`/`Lavc`/x264 markers |
| `mkv/h264-aac.mkv` | FFmpeg 8 with libx264 | `Lavf`/`Lavc`/x264 markers |
| `webm/live-vp8.webm` | FFmpeg 8 with libvpx | `Lavf`/`Lavc` ENCODER tags |
| `webm/vp9-opus.webm` | FFmpeg 8 with libvpx-vp9 and libopus | `Lavf`/`Lavc` ENCODER tags |
| `mpegts/h264-aac.ts` | FFmpeg 8 with libx264 | FFmpeg service provider name, `Lavc`/x264 markers |
| `m2ts/h264-ac3.m2ts` | FFmpeg 8 with libx264 | FFmpeg service provider name, x264 marker |
| `smjpeg/mjpeg-pcm.mjpg` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | `Lavf`/`Lavc` markers |
| `mxf/op1a-mpeg2-pcm.mxf` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | identification set: company FFmpeg, product `OP1a Muxer`, version 62.12.102 |
| `rm/rv10-ra.rm` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | inferred: `The Video Stream`/`The Audio Stream` MDPR names as FFmpeg's rmenc writes them, RV10 and RealAudio 1.0 (14.4) encoders only FFmpeg has here; not byte-reproduced |
| `wmv/wmv1-wma.wmv` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | inferred: ASF header objects in FFmpeg's order, WMV1/WMAv1 encoders only FFmpeg has here; not byte-reproduced |
| `webm/vp9-opus-chapters.webm` | FFmpeg 8.1.2 with libvpx-vp9 and libopus | reproduced byte-for-byte: `-f lavfi -i testsrc=size=32x16:rate=10:duration=0.4 -f lavfi -i sine=frequency=440:sample_rate=48000:duration=0.4 -i chapters.txt -map 0 -map 1 -map_metadata 2 -map_chapters 2 -c:v libvpx-vp9 -b:v 20k -pix_fmt yuv420p -color_primaries bt709 -color_trc bt709 -colorspace bt709 -color_range tv -c:a libopus -b:a 16k -ac 2 -metadata:s:a:0 language=eng -metadata:s:a:0 title="Stereo tone" -metadata:s:v:0 stereo_mode=left_right` `-fflags +bitexact -flags:v +bitexact -flags:a +bitexact`; `chapters.txt` is an FFMETADATA1 file with `title=Chapters test`, `artist=fillyfoal` and two chapters (`Opening` 0–200 ms, `Ending` 200–400 ms, TIMEBASE 1/1000) |
| `mkv/h264-vorbis-flac-srt.mkv` | FFmpeg 8.1.2 with libx264 | reproduced byte-for-byte: `-f lavfi -i testsrc=size=16x16:rate=5:duration=0.4 -f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.4 -i sub.srt -i chapters.txt -map 0 -map 1 -map 1 -map 2 -map_metadata 3 -map_chapters 3 -c:v libx264 -preset ultrafast -pix_fmt yuv420p -c:a:0 vorbis -strict -2 -ac:a:0 2 -c:a:1 flac -c:s srt -metadata:s:s:0 language=ger -metadata:s:a:1 language=fre -attach red.png -metadata:s:t mimetype=image/png -metadata:s:t:0 filename=red.png` `-fflags +bitexact -flags:v +bitexact -flags:a +bitexact`; `sub.srt` holds one cue (`Hello`, 0–300 ms), `red.png` is `-f lavfi -i color=c=red:size=4x4:duration=0.1 -frames:v 1`, `chapters.txt` is an FFMETADATA1 file with `title=Chapters test`, `artist=fillyfoal` and two chapters (`Opening` 0–200 ms, `Ending` 200–400 ms, TIMEBASE 1/1000) |
| `mkv/hevc-alac.mkv` | FFmpeg 8.1.2 with libx265 | reproduced byte-for-byte: `-f lavfi -i testsrc=size=16x16:rate=5:duration=0.2 -f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.2 -c:v libx265 -preset ultrafast -x265-params log-level=none -pix_fmt yuv420p10le -c:a alac` `-fflags +bitexact -flags:v +bitexact -flags:a +bitexact` |
| `avi/mpeg4-adpcm.avi` | FFmpeg 8.1.2 | reproduced byte-for-byte: `-f lavfi -i testsrc=size=16x16:rate=5:duration=0.4 -f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.4 -c:v mpeg4 -vtag XVID -c:a adpcm_ima_wav -metadata title="AVI test" -metadata artist=fillyfoal -metadata comment="ADPCM audio"` `-fflags +bitexact -flags:v +bitexact -flags:a +bitexact` |
| `wmv/wmv2-chapters.wmv` | FFmpeg 8.1.2 | reproduced byte-for-byte: `-f lavfi -i testsrc=size=16x16:rate=5:duration=0.4 -f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.4 -i chapters.txt -map 0 -map 1 -map_metadata 2 -map_chapters 2 -c:v wmv2 -c:a wmav2 -b:a 32k -ac 1 -metadata author=fillyfoal -metadata copyright="Public domain" -metadata comment="ASF test" -metadata genre=Test -metadata year=2026 -metadata:s:a:0 language=eng` `-fflags +bitexact -flags:v +bitexact -flags:a +bitexact`; `chapters.txt` is an FFMETADATA1 file with `title=Chapters test`, `artist=fillyfoal` and two chapters (`Opening` 0–200 ms, `Ending` 200–400 ms, TIMEBASE 1/1000) |
| `h264/high-vui-crop.h264` | FFmpeg 8 with libx264 (x264 core 165) | reproduced byte-for-byte with ffmpeg 8.1.2: `sh tests/data/video/make.sh` (bitexact); High profile, cropped 40×30, SAR 4:3, VUI timing and colour, JVT scaling matrices |
| `h264/high422-10-interlaced-hrd.h264` | FFmpeg 8 with libx264 (x264 core 165) | reproduced byte-for-byte with ffmpeg 8.1.2: `sh tests/data/video/make.sh` (bitexact); High 4:2:2 10-bit, interlaced, NAL HRD with buffering period and picture timing SEI |
| `hevc/main10-hdr10.hevc` | FFmpeg 8 with libx265 (x265 4.2) | reproduced byte-for-byte with ffmpeg 8.1.2: `sh tests/data/video/make.sh` (bitexact); Main 10, BT.2020/PQ VUI, mastering display and content light level SEI |
| `ivf/av1-10bit-hdr.ivf` | FFmpeg 8 with libsvtav1 (SVT-AV1 4.1) | reproduced byte-for-byte with ffmpeg 8.1.2: `sh tests/data/video/make.sh` (bitexact); 10-bit, HDR metadata OBUs (content light level, mastering display) |
| `ivf/vp9-profile2.ivf` | FFmpeg 8 with libvpx-vp9 | reproduced byte-for-byte with ffmpeg 8.1.2: `sh tests/data/video/make.sh` (bitexact); profile 2, 10-bit 4:2:0 |
| `mpegts/hevc-ac3.ts` | FFmpeg 8 with libx265 | reproduced byte-for-byte with ffmpeg 8.1.2: `sh tests/data/video/make.sh` (bitexact); HEVC + AC-3 with language, service name and provider |
| `mpegts/h264-mp2-eac3.ts` | FFmpeg 8 with libx264 | reproduced byte-for-byte with ffmpeg 8.1.2: `sh tests/data/video/make.sh` (bitexact); H.264 + MP2 + E-AC-3, two languages |
| `mpeg-ps/mpeg2-ac3-lpcm.vob` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `sh tests/data/video/make.sh` (bitexact); MPEG-2 video, AC-3 and LPCM in private stream 1 |
| `flv/hevc-aac.flv` | FFmpeg 8 with libx265 | reproduced byte-for-byte with ffmpeg 8.1.2: `sh tests/data/video/make.sh` (bitexact); Enhanced FLV `hvc1` + AAC |
| `flv/av1-opus.flv` | FFmpeg 8 with libsvtav1 and libopus | reproduced byte-for-byte with ffmpeg 8.1.2: `sh tests/data/video/make.sh` (bitexact); Enhanced FLV `av01` (with colorInfo metadata) + enhanced audio `Opus` (multichannel config) |
| `flv/vp9.flv` | FFmpeg 8 with libvpx-vp9 | reproduced byte-for-byte with ffmpeg 8.1.2: `sh tests/data/video/make.sh` (bitexact); Enhanced FLV `vp09` |
| `y4m/420p10-tff.y4m` | FFmpeg 8 (libavformat 62.12.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `sh tests/data/video/make.sh` (bitexact); 10-bit 4:2:0, top field first, PAR 10:11, 30000/1001 fps |
| `mpeg1video/pel-aspect-625.m1v` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `sh tests/data/video/make.sh` (bitexact); MPEG-1 pel aspect code 8 (CCIR 601, 625 lines) |
| `wav/piped.wav` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `sh tests/data/video/make.sh` (bitexact); written to a pipe, so the RIFF and data sizes stay 0xffffffff |
| `mkv/av1.mkv` | FFmpeg 8 with libsvtav1 | reproduced byte-for-byte with ffmpeg 8.1.2: `sh tests/data/video/make.sh` (bitexact); `V_AV1` with an `av1C` CodecPrivate, two frames as OBUs |

## Other image tools

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `heif/sips.heic` | macOS sips (ImageIO) | commit b86c5c84 ("generated with ffmpeg and sips (HEIC)") |
| `heif/grid-exif.heic` | macOS 26.5 sips (ImageIO) | reproduced byte-for-byte: `sips -s format heic -s formatOptions 10` on a 1100×520 blue JPEG (FFmpeg `color=c=blue:size=1100x520`) with the Exif of avif/grid-alpha.avif inserted by piexif; sips tiles it as a 3×2 grid |
| `ktx/sips.ktx` | macOS sips (ImageIO) | ImageIO key/value data (`AlphaInfo_APPLE`) |
| `ktx2/sips.ktx2` | macOS sips (ImageIO / libktx 4.0) | `KTXwriter: ImageIO / libktx v4.0` |
| `astc/sips.astc` | macOS sips (ImageIO) | named for its producer like the other sips fixtures; real ASTC block data (compare the hand-made astc/tex.astc) |
| `pvr/sips.pvr` | macOS 26.5 sips (ImageIO) | reproduced byte-for-byte: `sips -s format pvr` of a 16x16 ffmpeg testsrc frame saved as PNG (`-f lavfi -i testsrc=size=16x16:rate=1 -frames:v 1`); PVR v3, PVRTC 4bpp RGB |
| `psd/sips.psd` | macOS sips (ImageIO) | named for its producer; ImageIO image resources with an embedded sRGB profile |
| `webp/lossless.webp` | libwebp cwebp 1.6 | reproduced byte-for-byte: `cwebp -lossless` of a 16x16 ffmpeg testsrc frame |
| `webp/lossy.webp` | libwebp cwebp 1.6 | reproduced byte-for-byte: `cwebp -q 50` of the same frame |
| `jpeg/progressive-420.jpg` | libjpeg-turbo 3.2.0 cjpeg | reproduced byte-for-byte: `cjpeg -progressive -sample 2x2 -quality 75` of a 32x24 ffmpeg testsrc frame (`-f lavfi -i testsrc=size=32x24:rate=1 -frames:v 1`, as PPM; `-pix_fmt gray` as PGM for the grayscale one) |
| `jpeg/restart-422.jpg` | libjpeg-turbo 3.2.0 cjpeg | reproduced byte-for-byte: `cjpeg -restart 1 -sample 2x1 -quality 90` of the same frame |
| `jpeg/arithmetic-444.jpg` | libjpeg-turbo 3.2.0 cjpeg | reproduced byte-for-byte: `cjpeg -arithmetic -sample 1x1 -quality 50` of the same frame |
| `jpeg/lossless-gray.jpg` | libjpeg-turbo 3.2.0 cjpeg | reproduced byte-for-byte: `cjpeg -lossless 1` of the grayscale frame |
| `jpeg/precision12.jpg` | libjpeg-turbo 3.2.0 cjpeg | reproduced byte-for-byte: `cjpeg -precision 12 -quality 85` of the same frame |
| `jpeg/cmyk-adobe.jpg` | Pillow 12.3.0 (libjpeg-turbo) | reproduced byte-for-byte: the PPM frame `.convert("CMYK").save(..., quality=80)` (Adobe APP14) |
| `jpeg/pillow-pair.mpo` | Pillow 12.3.0 (libjpeg-turbo) | reproduced byte-for-byte: the PPM frame resized to 16x16 and its mirror image, `save("x.mpo", save_all=True, append_images=[mirror], quality=70)` (MPF index, two images) |
| `webp/lossless-alpha.webp` | libwebp cwebp 1.6.0 | reproduced byte-for-byte: `cwebp -quiet -lossless -exact rgba.png`, input from `tests/data/webp/make_inputs.py` (Pillow 12.3.0) |
| `webp/lossy-alpha-raw.webp` | libwebp cwebp 1.6.0 | reproduced byte-for-byte: `cwebp -quiet -q 60 -alpha_method 0 rgba.png` (uncompressed ALPH) |
| `webp/lossy-alpha-meta.webp` | libwebp cwebp 1.6.0 | `cwebp -quiet -q 50 -alpha_filter best -metadata icc,exif,xmp rgba-meta.png`; the input's LittleCMS sRGB profile carries its creation time, so only that profile's date differs on a re-run |
| `webp/anim-mixed.webp` | libwebp img2webp 1.6.0 | reproduced byte-for-byte: `img2webp -loop 3 -d 120 -lossless frame0.png -lossy -q 40 -d 80 frame1.png -lossless -d 200 frame2.png` |
| `png/palette-metadata.png` | Pillow 12.3.0 (zlib-ng 2.19, LittleCMS) | `tests/data/png/make_external.py`; reproduced byte-for-byte except the embedded LittleCMS sRGB profile's creation time (in the zlib-compressed iCCP) |
| `png/interlaced-sbit.png` | pypng 0.20220715.0 | reproduced byte-for-byte by `tests/data/png/make_external.py` (Adam7, sBIT, gAMA, bKGD, tRNS, pHYs, the zlib stream split over two IDAT chunks) |
| `png/gray-alpha16.png` | pypng 0.20220715.0 | reproduced byte-for-byte by `tests/data/png/make_external.py` |
| `png/gray2-trns.png` | pypng 0.20220715.0 | reproduced byte-for-byte by `tests/data/png/make_external.py` |
| `gif/pillow-anim.gif` | Pillow 12.3.0 | reproduced byte-for-byte by `tests/data/gif/make_external.py` |
| `ico/` | Pillow 12.3.0 | reproduced byte-for-byte by `tests/data/ico/make_external.py` |

## Version control

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `git-pack/small.pack` | git | `git verify-pack` accepts it; commits by `Fixture Author <author@example.invalid>`, one delta object |
| `git-pack-index/small.idx` | git | v2 index of git-pack/small.pack |
| `git-bundle/repo.bundle` | git | `git bundle verify` accepts it |

## Serialisation libraries (schemaless wire formats)

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `protobuf/` | protoc (libprotoc 34.1) | reproduced byte-for-byte: `sh tests/data/protobuf/make.sh` (`protoc --encode` of `sample.txtpb` and a generated track with `sample.proto`) |
| `thrift-binary/` | Apache Thrift Python library 0.25.0 (`TBinaryProtocol`) | reproduced byte-for-byte: `uv run --with thrift==0.25.0 python tests/data/thrift/make.py` (protocol API over `TMemoryBuffer`, no IDL) |
| `thrift-compact/` | Apache Thrift Python library 0.25.0 (`TCompactProtocol`) | reproduced byte-for-byte by the same script |
| `flatbuffers/` | FlatBuffers Python library 25.12.19 (`Builder`) | reproduced byte-for-byte: `uv run --with flatbuffers==25.12.19 python tests/data/flatbuffers/make.py` (tutorial `Monster` layout, a size-prefixed copy, a long vector of strings) |
| `capnp/` | pycapnp 2.2.4 (Cap'n Proto C++ library) | reproduced byte-for-byte: `uv run --with pycapnp==2.2.4 python tests/data/capnp/make.py` (`to_bytes`; `book-segments.bin` with an 8-word first segment, so later objects sit in other segments behind far pointers) |
| `capnp-packed/` | pycapnp 2.2.4 (Cap'n Proto C++ library) | reproduced byte-for-byte by the same script (`to_bytes_packed`) |
| `lmdb/multi.mdb.gz` | py-lmdb 1.6.2 (bundled liblmdb 0.9.x, `lmdb.version()` 0.9.36), x86_64 build | reproduced byte-for-byte: `uv run --python cpython-3.12-macos-x86_64-none --with lmdb==1.6.2 python tests/data/lmdb/make.py OUT` (run under Rosetta so LMDB uses 4 KiB pages); named databases, DUPSORT sub-page and sub-database, DUPFIXED LEAF2 sub-page, an overflow value, a free-DB record. Stored with `gzip -9 -n` (72 KiB raw) |

## Password managers

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `kdbx/` | pykeepass 4.2.0 (with argon2-cffi, pycryptodomex) | reproduced byte-for-byte: `uv run --with pykeepass==4.2.0 python tests/data/kdbx/make.py tests/fixtures/external/kdbx` (password `fillyfoal`; seeded randomness and fixed clock; cheap KDF parameters; `kdbx3.kdbx` is pykeepass writing a KDBX 3.1 header we swapped into its object model) |

## Statistics packages

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `spss-sav/` | pyreadstat 1.3.6 (ReadStat), pandas 3.0.6 | reproduced byte-for-byte: `uv run --with pyreadstat==1.3.6 --with pandas==3.0.6 python -I tests/data/spss-sav/make.py` (`write_sav`: uncompressed, `row_compress` bytecode, `compress` zsav); edit: the creation date and time in the header are overwritten with a fixed value |
| `spss-por/` | pyreadstat 1.3.6 (ReadStat) | reproduced byte-for-byte: `uv run --with pyreadstat==1.3.6 --with pandas==3.0.6 python -I tests/data/spss-por/make.py` (`write_por`); edit: the creation date and time digits are overwritten with a fixed value |
| `sas-xport/` | pyreadstat 1.3.6 (ReadStat) | reproduced byte-for-byte: `uv run --with pyreadstat==1.3.6 --with pandas==3.0.6 python -I tests/data/sas-xport/make.py` (`write_xport`, versions 5 and 8); edit: the `ddMMMyy:hh:mm:ss` time stamps are overwritten with a fixed value |
| `stata-dta/readstat-113.dta` | pyreadstat 1.3.6 (ReadStat) | reproduced byte-for-byte: `uv run --with pyreadstat==1.3.6 --with pandas==3.0.6 python -I tests/data/stata-dta/make.py` (`write_dta` version 8); edit: the time stamp is overwritten with a fixed value of the same length |
| `stata-dta/readstat-115.dta` | pyreadstat 1.3.6 (ReadStat) | reproduced byte-for-byte: `uv run --with pyreadstat==1.3.6 --with pandas==3.0.6 python -I tests/data/stata-dta/make.py` (`write_dta` version 12); edit: the time stamp is overwritten with a fixed value of the same length |
| `stata-dta/readstat-118.dta` | pyreadstat 1.3.6 (ReadStat) | reproduced byte-for-byte: `uv run --with pyreadstat==1.3.6 --with pandas==3.0.6 python -I tests/data/stata-dta/make.py` (`write_dta` version 14); edit: the time stamp is overwritten with a fixed value of the same length |
| `stata-dta/pandas-114.dta` | pandas 3.0.6 (`DataFrame.to_stata`) | reproduced byte-for-byte by the same script (`version=114`, fixed `time_stamp`), no edits |
| `stata-dta/pandas-117.dta` | pandas 3.0.6 (`DataFrame.to_stata`) | reproduced byte-for-byte by the same script (`version=117`, a strL, fixed `time_stamp`), no edits |
| `stata-dta/pandas-118.dta` | pandas 3.0.6 (`DataFrame.to_stata`) | reproduced byte-for-byte by the same script (`version=118`, fixed `time_stamp`), no edits |
| `stata-dta/pandas-119.dta` | pandas 3.0.6 (`DataFrame.to_stata`) | reproduced byte-for-byte by the same script (`version=119`, fixed `time_stamp`), no edits |
| `dxf/` | ezdxf 1.4.4 (`saveas`, ASCII R12 and R2018, binary R2018) | reproduced byte-for-byte: `PYTHONHASHSEED=0 uv run --with ezdxf==1.4.4 python tests/data/dxf/make.py tests/fixtures/external/dxf` (ezdxf's `write_fixed_meta_data_for_testing` pins dates and GUIDs; the hash seed pins the CLASSES order); the drawing is ours |
| `dwg/` | GNU LibreDWG 0.14.8413 `dwgwrite` (openSUSE Tumbleweed `libredwg-tools`, GPL-3.0-or-later), from an ezdxf 1.4.4 DXF | reproduced byte-for-byte: `sh tests/data/dwg/make-libredwg.sh .` (Docker; `PYTHONHASHSEED=0 uv run --with ezdxf==1.4.4 python -I tests/data/dwg/libredwg_dxf.py` writes the R2000 DXF, then `dwgwrite --as r13/r14/r2000/r2004/r2010/r2013/r2018`; each reads back with `dwgread -O JSON`, whose object list (handles, types, sizes) and classes the snapshots match). R2004+ files are 0.3-1.6 MB of zero-padded stored pages, kept as `.dwg.raw.zst` (`zstd -19`). Not committed: `--as r2007` (writes AC1024), r9-r11 (dwgread rejects them). LibreDWG compresses only the page map and section map. LibreDWG quirks the snapshots show: a preview address with no preview (R13-R2000), a preview size of 5 for an empty preview, section-map entries for the system pages; the drawing is ours |
| `duckdb/` | DuckDB 1.5.6 (Python package) | `uv run --with duckdb==1.5.6 python tests/data/duckdb/make_fixture.py OUT` then `gzip -9 -n` (stored compressed: whole 256 KiB / 16 KiB blocks of zeros); `shop.duckdb` reproduced byte-for-byte, `types.duckdb` (16 KiB blocks, `STORAGE_VERSION 'v1.5.0'`) is not byte-reproducible (differs between runs) |
| `realm/` | Realm JS 20.2.0 (npm `realm`, prebuilt Realm Core, file format 24) | `node tests/data/realm/make_fixture.mjs OUT` from a scratch directory with `npm install realm@20.2.0` (`REALM_DISABLE_ANALYTICS=1`); compacted; not byte-reproducible (per-run identifiers) |

## Game engines

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `unityfs/lz4hc.bundle` | UnityPy 1.25.4 (`BundleFile.save(packer="lz4hc")`, `SerializedFile.save`, type-tree writer; LZ4HC from python-lz4) | reproduced byte-for-byte: `uv run --with UnityPy==1.25.4 python tests/data/unityfs/make.py`. UnityPy cannot create files from nothing: the script hands it a seed with empty tables (bytes written by the script), then adds types (UnityPy's type-tree database for Unity 2022.3), objects (two TextAssets, one a JSON document; a Texture2D with pixels in a `.resS` node, GameObject, MonoBehaviour, MonoScript, AssetBundle), a script type and an external through UnityPy's object model; UnityFS 8, SerializedFile 22 |
| `unityfs/lzma.bundle` | UnityPy 1.25.4 (`packer="lzma"`) | same script; Unity 2018.4, UnityFS 6, SerializedFile 17 |
| `unityfs/plain.bundle` | UnityPy 1.25.4 (`packer="none"`) | same script; Unity 2020.3, UnityFS 7, SerializedFile 21 |
| `unityfs/raw.unity3d` | UnityPy 1.25.4 (`save_web_raw`) | same script; UnityRaw 3, Unity 5.2, SerializedFile 15 |
| `unityfs/web.unity3d` | UnityPy 1.25.4 (`save_web_raw`, LZMA) | same script; UnityWeb 3 |
| `unity-serialized/sharedassets0.assets` | UnityPy 1.25.4 (`SerializedFile.save`) | same script; standalone SerializedFile 19, Unity 2019.4 |
| `dweep/kitchen-sink.dwp` | Dweep Gold level editor (Dexterity Software, 2000) | made for fillyfoal: every placeable tile (each fixed object and item in all directions, wrenches, bucket, torch, hammer), Dweep at (0, 0) and the goal at (15, 9), a 39-character title (the most its 40-byte buffer holds) and a 155-character tip, a starting inventory of the second mirror, bomb, bucket, both wrenches, torch and hammer, theme 1. The 8 unused bytes at the end of the record are 1, 1: memory the editor never clears |
| `dweep/empty.dwp` | Dweep Gold level editor | made for fillyfoal: only Dweep and the goal, at (0, 0) and (1, 0); empty title and tip, whose bytes after the terminator are leftover memory (the words "level title" and "level tip" from an earlier edit, and heap pointers) |

## Mail stores

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `pst/unicode.pst.gz` | Aspose.Email for Python via .NET 26.8 (unlicensed evaluation mode) | `uv run --with aspose-email-for-python-via-net==26.8 python -I tests/data/pst/generate.py OUT`; not byte-for-byte reproducible (fresh entry IDs, record keys and modification times). Evaluation mode appends "(Aspose.Email Evaluation)" to subjects and an evaluation banner to bodies. Stored as `gzip -9 -n` (mostly zero-filled preallocated pages). Aspose cannot create ANSI files |
| `nifti/` | nibabel 5.4.2 (`Nifti1Image`, `Nifti1Pair`, `Nifti2Image`) | reproduced byte-for-byte: `uv run --with nibabel==5.4.2 --with numpy python tests/data/nifti/make.py` (4-D int16 series with AFNI and comment extensions, a t-statistic map, a `.hdr` of a header/image pair with the `.img` deleted, a NIfTI-2 volume) |
| `grib/` | ecCodes 2.49.0 (Python bindings with the bundled C library and samples) | reproduced byte-for-byte: `uv run --with eccodes==2.49.0 python tests/data/grib/make.py` (GRIB2 2 m temperature and accumulated precipitation with a bit-map; GRIB1 mean sea level pressure with the ECMWF local PDS extension) |
| `bufr/` | ecCodes 2.49.0 (Python bindings with the bundled C library and samples) | reproduced byte-for-byte: `uv run --with eccodes==2.49.0 python tests/data/bufr/make.py` (two-subset surface observations, editions 3 and 4, and ECMWF's local sample with section 2 and compression) |
| `hdf4/` | pyhdf 0.11.6 (bundled HDF 4.3.0 library) | reproduced byte-for-byte: `uv run --with pyhdf==0.11.6 --with numpy python tests/data/hdf4/make.py` (SD datasets with dimension scales, attributes and deflate compression; a vdata in a vgroup; a vdata appended into linked blocks). `grid.hdf` records its path relative to the repository root as the `CDF0.0` vgroup name |
## Credential tools

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `openssh-key/` | ssh-keygen (OpenSSH_10.2p1, macOS) | `sh tests/data/openssh-key/make.sh` (keys are random: same structure, new bytes); passphrase `fillyfoal`, `-a 4`, `-Z aes256-ctr` / `aes256-cbc` / `aes256-gcm@openssh.com` / `chacha20-poly1305@openssh.com`; edit: the PEM armor removed (`base64 -d` of the body) to get the binary format; every encrypted key decrypts with matching check values (and AEAD tag) |
| `openssh-keys/ssh-keygen.pub` | ssh-keygen (OpenSSH_10.2p1, macOS) | the same script: `.pub` files of the keys above and an ed25519 user certificate (`ssh-keygen -s ca -I fillyfoal-user -n alice,bob`), concatenated |
| `openssh-keys/certificates.pub` | ssh-keygen (OpenSSH_10.2p1, macOS) | `sh tests/data/openssh-cert/make.sh` (random keys): an Ed25519 host certificate signed by an RSA CA (`rsa-sha2-512`, serial 42, two principals, validity window) and an ECDSA P-384 user certificate signed by an Ed25519 CA (`force-command`, `source-address`, `permit-pty` only, valid forever); checked against `ssh-keygen -L` |
| `openssh-krl/revoked.krl` | ssh-keygen (OpenSSH_10.2p1, macOS) | the same script: `ssh-keygen -k -z 3` over serials, a serial range and key IDs under the Ed25519 CA, an explicit key, a key by SHA-256 and a SHA-256 fingerprint; checked against `ssh-keygen -Q -l` |
| `pem/openssh-rsa.key` | ssh-keygen (OpenSSH_10.2p1, macOS) | the same script: `ssh-keygen -t rsa -b 1024 -N ''`, unedited |
| `keychain/items.keychain` | macOS `security` (Security.framework, macOS 26) | `sh tests/data/keychain/make.sh` (random salts and keys: same structure, new bytes): `security create-keychain -p fillyfoal`, a generic and an internet password, an OpenSSL self-signed certificate and its EC private key imported; unedited |

## Packet captures

Captured with tcpdump 4.99.5 / libpcap 1.10.5 and dumpcap, tshark and
editcap from Wireshark 4.4.19 in a Debian trixie image
(`tests/data/pcap/Dockerfile`, built as `fillyfoal-pcap-tools`), on an
`--internal` Docker network (10.99.0.0/24, fd99::/64, no route out) between
a server container (`server.sh`: unbound, dnsmasq DHCP, python http.server,
`openssl s_server` with a throwaway P-256 certificate for www.example.com,
chrony) and a client container (`client.sh`) that captures on its own
interface; `bash tests/data/pcap/run.sh` runs both, then
`convert.sh` in a container without network for the other formats. MAC
addresses are the containers' random ones. Not byte-reproducible (times,
ports, random values). Checked against `tshark -V` from the same image:
addresses, ports, DNS names and record data, TLS cipher suites, extensions
and certificate, DHCP options, NTP timestamps, ICMP types and quoted
datagrams, checksums (tshark with checksum validation on reports the same
correct / pseudo-header-only values), pcapng block and option values.

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `pcap/dns.pcap` | tcpdump | `dig` against unbound: A, AAAA, MX, TXT, NS, SOA, SRV, CNAME, HTTPS (SVCB params), CAA, NXDOMAIN with SOA, PTR, and one query over TCP; EDNS OPT records |
| `pcap/http.pcap` | tcpdump | curl to python http.server: two GETs and a 404 |
| `pcap/tls12.pcap` | tcpdump | `openssl s_client -tls1_2` with SNI and ALPN; the handshake carries the certificate in the clear |
| `pcap/tls13.pcap` | tcpdump | `openssl s_client -tls1_3` with SNI and ALPN (x25519 key share) |
| `pcap/icmp.pcap` | tcpdump | ARP, ping and ping -6 (with NDP), fragmented echo (IPv4 fragments, IPv6 fragment headers), record-route option, IGMPv3 (router-alert option) and MLDv2 reports (hop-by-hop header) from `mcast-join.py` |
| `pcap/udp.pcap` | tcpdump | busybox udhcpc against dnsmasq, chrony NTP, logger (syslog), SSDP / mDNS / LLMNR queries from `udp-probes.py`, snmpget, a curl HTTP/3 attempt (QUIC Initial packets) and the ICMP port-unreachable replies |
| `pcap/sll.pcap` | tcpdump `-i any -y LINUX_SLL` | Linux cooked capture v1 |
| `pcap/sll2.pcap` | tcpdump `-i any` | Linux cooked capture v2 |
| `pcap/nano.pcap` | tcpdump `--time-stamp-precision=nano` | nanosecond pcap |
| `pcap/vlan.pcap` | tcpdump | pings over an 802.1Q VLAN interface and an 802.1ad + 802.1Q (QinQ) stack |
| `pcap/kuznetzov.pcap` | editcap `-F modpcap` | nano.pcap in Kuznetzov's modified pcap format |
| `pcapng/dumpcap.pcapng` | dumpcap | two interfaces (eth0 with a capture filter, lo) with interface statistics blocks; TLS 1.3 session and a loopback ping |
| `pcapng/tls-secrets.pcapng` | editcap `--inject-secrets tls,keylog.txt -a 4:…` | dumpcap.pcapng with a Decryption Secrets Block (the client's SSLKEYLOGFILE) and a packet comment |
| `pcapng/names.pcapng` | tshark `-P -N dn -W n -F pcapng` | dns.pcap with a Name Resolution Block |
| `pcapng/sections.pcapng` | tshark `-F pcapng`, concatenated | sll2.pcap and vlan.pcap converted to pcapng and joined (`cat`): two sections |
| `snoop/http.snoop` | editcap `-F snoop` | http.pcap as a Solaris snoop file |
| `netmon/dns.cap` | editcap `-F netmon2` | dns.pcap as a Network Monitor 2.0 file |
| `btsnoop/hci.btsnoop` | text2pcap `-l 201`, editcap `-F btsnoop -C 4` | HCI H4 packets written by hand in `hci.txt` (reset, read BD_ADDR, LE scan enable, an advertising report, an L2CAP information request); editcap writes the container, keeps the original lengths and marks every record received |

Edits: in the four pcapng files the `shb_os` and `if_os` options (the
Docker host's kernel release) were rewritten to "Linux" by
`tests/data/pcap/scrub-pcapng.py`, which recomputes option and block
lengths and copies everything else.

## Office documents and installers (Compound File)

LibreOffice fixtures are converted from flat ODF sources in `tests/data/`
in a throwaway profile (`tests/data/cfb/lo-profile.py` sets the user name to
"fillyfoal" and turns off the preview images Impress embeds), with
`sh tests/data/cfb/lo-convert.sh <format> <source> <outdir>`. LibreOffice
stamps the conversion time into the summary information, so they are not
reproducible byte for byte.

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `doc/letter.doc` | LibreOffice 26.8.1.1 ("MS Word 97" filter) | `lo-convert.sh doc tests/data/doc/letter.fodt`: heading, bold/coloured runs, PAGE and HYPERLINK fields, a list, a table, a two-column section with a footnote |
| `doc/note.doc` | macOS 26.5 `textutil` | `textutil -convert doc -output note.doc tests/data/doc/note.html` |
| `xls/budget.xls` | LibreOffice 26.8.1.1 ("MS Excel 97" filter) | `lo-convert.sh xls tests/data/xls/budget.fods`: shared formulas, IF/SUM/AVERAGE/MAX/ISERROR, a cross-sheet reference, a cell comment and a drawn rectangle (Office Art) |
| `xls/xlwt.xls` | xlwt 1.3.0 | `uv run --with xlwt==1.3.0 python tests/data/xls/make_xlwt.py xlwt.xls`; reproduced byte-for-byte |
| `ppt/deck.ppt` | LibreOffice 26.8.1.1 ("MS PowerPoint 97" filter) | `lo-convert.sh ppt tests/data/ppt/deck.fodp`: two slides with titles, bullets, notes, a rectangle and an ellipse |
| `msi/hello.msi` | msitools 0.106 (`wixl`) | `wixl -o hello.msi tests/data/msi/hello.wxs` next to `tests/data/msi/readme.txt`; the package code and times differ on each run |
| `doc/long.doc` | LibreOffice 26.8.1.1 ("MS Word 97" filter) | `python3 tests/data/doc/make_long.py long.fodt`, then `lo-convert.sh doc long.fodt <outdir>`: 400 plain paragraphs, 78,848 bytes; LibreOffice writes the directory in the last sectors (sector 151, inside the last 1 KiB), beyond the 66 KiB probe head |
| `xls/embedded.xls` | LibreOffice 26.8.1.1 ("MS Excel 97" filter) | `soffice -env:UserInstallation=file:///tmp/fixtures/office-cfb/lo-profile --headless --infilter="OpenDocument Spreadsheet Flat XML" --convert-to xls --outdir <outdir> embedded.fods` (the nested document in `tests/data/xls/embedded.fods` defeats type detection, hence `--infilter`): a sheet with an embedded Writer object, exported as a Word document in a root-level `MBD…` storage |
| `xls/encrypted-rc4.xls` | LibreOffice 26.8.1.1 ("MS Excel 97" filter with a password) | `sh tests/data/xls/encrypt.sh <profile> encrypted-rc4.xls`: runs `tests/data/xls/encrypt.bas` as a Basic macro in a throwaway profile (headless `--convert-to` ignores the password); password `fillyfoal`. FILEPASS with RC4 (version 1.1); msoffcrypto-tool 5.4.2 decrypts it with that password |
| `doc/pictures.doc` | LibreOffice 26.8.1.1 ("MS Word 97" filter) | `python3 tests/data/doc/make_pictures.py pictures.fodt`, then `lo-convert.sh doc pictures.fodt <outdir>`: an 8×8 PNG inline (a run with sprmCPicLocation into the Data stream: PICF, shape, FBSE with the BLIP) and one anchored to a paragraph (DggInfo FBSE whose foDelay points into WordDocument) |
| `doc/encrypted-rc4.doc` | LibreOffice 26.8.1.1 ("MS Word 97" filter with a password) | `sh tests/data/cfb/encrypt.sh <profile> swriter "MS Word 97" encrypted-rc4.doc` (runs `tests/data/cfb/encrypt.bas` in a throwaway profile); password `fillyfoal`. fEncrypted with an RC4 1.1 header at the start of 1Table; msoffcrypto-tool 6.0.0 decrypts it |
| `ppt/picture.ppt` | LibreOffice 26.8.1.1 ("MS PowerPoint 97" filter) | `lo-convert.sh ppt tests/data/ppt/picture.fodp <outdir>` (in a throwaway profile set up as above): one slide with a 4×4 PNG, whose BLIP LibreOffice writes to the `Pictures` stream, an FBSE in the drawing group pointing at it with foDelay |
| `cfb/encrypted-standard.docx` | LibreOffice 26.8.1.1 ("MS Word 2007 XML" filter with a password) | `sh tests/data/cfb/encrypt.sh <profile> swriter "MS Word 2007 XML" encrypted-standard.docx`; password `fillyfoal`. ECMA-376 standard encryption (EncryptionInfo 3.2, AES-128); msoffcrypto-tool 6.0.0 reports "standard" and decrypts it |
| `cfb/encrypted-agile.docx` | msoffcrypto-tool 6.0.0 | `msoffcrypto-tool -p fillyfoal encrypted-standard.docx plain.docx`, then `msoffcrypto-tool -e -p fillyfoal plain.docx encrypted-agile.docx`: agile encryption (EncryptionInfo 4.4, AES-256, SHA-512) with `\x06DataSpaces`; salts are random, so not byte-reproducible |

## Windows

Made by Windows' own components on an ARM64 Windows 11 VM (build 26200,
`ge_release` 26100 binaries) named FILLYFOAL, via
`tests/data/windows/make-fixtures.ps1` (event log service + `wevtutil`,
`RegSaveKeyEx`, `esent.dll`, `dbghelp`), which refuses to run unless the
computer is named FILLYFOAL, sets registry ownership to
BUILTIN\Administrators and scans its outputs for the account's names and
SID. The files are unchanged; not byte-for-byte reproducible (times, record
numbers, random signatures, process memory). The minidumps record the VM's
time zone.

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `evtx/fillyfoal.evtx` | Windows (event log service + wevtutil / RegSaveKeyEx / esent.dll / dbghelp), via tests/data/windows/make-fixtures.ps1, on a VM named FILLYFOAL | `wevtutil epl` of a 1 MiB classic log `Fillyfoal` after 600 `Write-EventLog` calls: sources FillyfoalSource/FillyfoalOther alternating, event IDs 1000–1016, all five entry types, categories 0–3, a two-line message and 1–40 bytes of raw data each; 4 chunks (records 1–181, 182–360, 361–540, 541–600), 17 chunks allocated. Checked against python-evtx 0.8.1 (every record's number, time, event ID, level, provider, keywords, task and binary data) |
| `regf/fillyfoal-latest.hiv` | Windows (event log service + wevtutil / RegSaveKeyEx / esent.dll / dbghelp), via tests/data/windows/make-fixtures.ps1, on a VM named FILLYFOAL | `RegSaveKeyEx(REG_LATEST_FORMAT)` of `HKCU\Software\Fillyfoal`: hive 1.5 with values of every common type (REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_DWORD, REG_QWORD, a 4-byte and a 40 000-byte REG_BINARY (big data `db` cell), the default value, a 208-character value name, REG_NONE), subkeys `Many` (2 100 subkeys: an `ri` over `lh` lists) and `Nested\Deeper\Deepest` (REG_DWORD 42), one shared security descriptor (Administrators/SYSTEM full control, Everyone read). Checked against python-registry 1.3.1 (all values, subkey counts) |
| `regf/fillyfoal-standard.hiv` | Windows (event log service + wevtutil / RegSaveKeyEx / esent.dll / dbghelp), via tests/data/windows/make-fixtures.ps1, on a VM named FILLYFOAL | the same key saved with `REG_STANDARD_FORMAT`: hive 1.3, `lf`/`li` index lists, the 40 000-byte value in one data cell. Checked against python-registry 1.3.1 |
| `ese/fillyfoal.edb` | Windows (event log service + wevtutil / RegSaveKeyEx / esent.dll / dbghelp), via tests/data/windows/make-fixtures.ps1, on a VM named FILLYFOAL | esent.dll database (format 0x620, update 300, 4 KiB pages, clean shutdown) with table `Fixtures` (400 rows; every column type: Bit, UnsignedByte, Short, Long autoincrement, Currency, IEEESingle, IEEEDouble, DateTime, Binary, Text in UTF-16 and Windows-1252, LongBinary and LongText (20 000-byte and 6 000-character separated long values every 50th row), UnsignedLong, LongLong, GUID, UnsignedShort, a tagged multi-valued Text column), a primary index and a two-column secondary index, and table `Small` (3 rows). Checked against dissect.esedb 3.18 (catalog, column types, every row value of both tables; dissect cannot reassemble one of the 20 000-byte long values) and our page checksums (ECC + XOR, every page valid) |
| `ese/ese_32k_pages_lv.edb.raw.zst` | esent.dll 10.0.26100.9278 (Windows 11 Pro 25H2 build 26200.9457, ARM64), driven by a .NET 8 P/Invoke program; written on a Windows 11 25H2 ARM64 VM, see `tests/data/windows/ese/` | `build.ps1` runs `EseFixtures plain 32768 <work> ese_32k_pages_lv.edb 16` (recovery off, clean shutdown, shrunk with JetResizeDatabase): 32 KiB pages, table `fillyfoal_test` (60 rows: Long, Text cp1252, tagged LongText UTF-16, tagged LongBinary, DateTime, GUID; rows 20/40/60 carry ~40 KiB long values in the long-value tree). `esentutl /mh`: clean shutdown, format 0x620 update 300, efv 9620. Every long value checked byte for byte against the generator's deterministic content. The same content with 8 KiB pages (`ese_8k_pages_lv.edb` from build.ps1) decodes the same and is not included. Stored `zstd -19`; not byte-reproducible (creation times, random signatures) |
| `ese/ese_8k_compressed_columns.edb.raw.zst` | esent.dll 10.0.26100.9278 (Windows 11 Pro 25H2 build 26200.9457, ARM64), driven by a .NET 8 P/Invoke program; written on a Windows 11 25H2 ARM64 VM, see `tests/data/windows/ese/` | `EseFixtures compressed 8192 <work> ese_8k_compressed_columns.edb 16`: table `fillyfoal_compressed` with three tagged columns created with JET_bitColumnCompressed and set with JET_bitSetCompressed; esent.dll stored short values as 7-bit ASCII / 7-bit Unicode and each separated long-value chunk as LZ4 (scheme 7) or, for short last chunks, 7-bit. All 50 compressed values decode byte for byte to the generator's content. Stored `zstd -19` |
| `ms-money/fillyfoal-nopasswd.mny.raw.zst` | Microsoft Money Plus Sunset Deluxe 17.00.3817 (x86 under emulation); written on a Windows 11 25H2 ARM64 VM (build 26200.9457), by hand in the Money UI, so there is no script; the click path is in `tests/data/windows/money/README.md` | File > New, account `fillyfoal checking` at bank `fillyfoal bank` (opening balance 1000.00) and three transactions (-12.34, -56.78, 78.90). MSISAM with page encryption flags 0x3d (SHA-1 digest of the empty password; pages 1-14 RC4); decrypted as Jackcess-encrypt's MSISAMCryptCodecHandler does, the catalog lists 91 MSysObjects rows and TRN holds the three amounts. Unchanged apart from `zstd -19` (3.3 MiB is the smallest new Money file) |
| `ms-money/fillyfoal-passwd.mny.raw.zst` | Microsoft Money Plus Sunset Deluxe 17.00.3817 (x86 under emulation); written on a Windows 11 25H2 ARM64 VM (build 26200.9457), by hand in the Money UI, so there is no script; the click path is in `tests/data/windows/money/README.md` | a copy of the file above, opened in Money and given the password `fillyfoal` (File > Password protection); the check bytes verify only with that password, and the decrypted pages match. Stored `zstd -19` |
| `xls/excel-rc4-cryptoapi.xls` | Microsoft Excel LTSC 2024 16.0.17932.21000 (Click-to-Run, x64 under emulation); written on a Windows 11 25H2 ARM64 VM (build 26200.9457) via COM, see `tests/data/windows/office/` | `make_excel.ps1`: sheet `fillyfoal test`, four rows with `=B3*C3` formulas and `=SUM(D3:D6)`, `SaveAs(path, 56, "fillyfoal")`; password `fillyfoal`. FILEPASS RC4 CryptoAPI 4.2 (RC4, SHA-1, 128-bit, Microsoft Enhanced Cryptographic Provider v1.0); decrypts to A1 "fillyfoal test" and D7 = 49.5 as Excel shows. Its DocumentSummaryInformation packs vector strings without padding. Not byte-reproducible (random salt) |
| `ppt/powerpoint-encrypted.ppt` | Microsoft PowerPoint LTSC 2024 16.0.17932.21000 (Click-to-Run, x64 under emulation); written on a Windows 11 25H2 ARM64 VM (build 26200.9457) via COM, see `tests/data/windows/office/` | `make_powerpoint.ps1`: two slides (title "fillyfoal test" / "synthetic presentation", lorem bullets), `Presentation.Password = "fillyfoal"`, saved as PowerPoint 97-2003; CryptSession10Container RC4 CryptoAPI 4.2, the Current User user names empty. Decrypts with `fillyfoal`. Random salt |
| `vsd/visio-drawing.vsd` | Microsoft Visio Professional LTSC 2024 16.0.17932.21000 (Click-to-Run, x64 under emulation); written on a Windows 11 25H2 ARM64 VM (build 26200.9457) via COM, see `tests/data/windows/office/` | `make_visio.ps1`: `Visio.InvisibleApp`, two rectangles and an oval with text and two connectors (one labelled `link`), saved as `.vsd` (Visio 2003-2010 drawing, version byte 11); the page stream decompresses to the shapes' UTF-16 text |
| `onenote/fillyfoal-section.one` | Microsoft OneNote (desktop) LTSC 2024 16.0.17932.21000 (Click-to-Run, x64 under emulation); written on a Windows 11 25H2 ARM64 VM (build 26200.9457) via COM, see `tests/data/windows/office/` | `make_onenote.ps1`: `OneNote.Application` COM, notebook `fillyfoal-notebook`, section `fillyfoal-section.one`, one page from 2013-schema XML (title "fillyfoal test", three paragraphs, a 2x3 table); every paragraph and cell shows up under Pages |
| `onetoc2/open-notebook.onetoc2` | Microsoft OneNote (desktop) LTSC 2024 16.0.17932.21000 (Click-to-Run, x64 under emulation); written on a Windows 11 25H2 ARM64 VM (build 26200.9457) via COM, see `tests/data/windows/office/` | written by the same script: the notebook's `Open Notebook.onetoc2` (renamed), naming `fillyfoal-section.one`; three revisions, the later ones copying global ID table entries from their dependency (GlobalIdTableEntry2/3FNDX) |
| `msi/fillyfoal-test-1.0.0.msi` | WiX Toolset 6.0.2 (`wix build -arch x86`); written on a Windows 11 25H2 ARM64 VM (build 26200.9457), see `tests/data/windows/msi/build.ps1` | `product.wxs` with `-d Version=1.0.0`: per-machine package with an embedded cabinet (readme.txt, data.txt), an HKCU registry value, MajorUpgrade; 19 standard tables. Fixed product/upgrade/component GUIDs, but a new PackageCode and build times per run |
| `msi/fillyfoal-test-1.0.0-to-1.0.1.mst` | Windows SDK 10.0.26100 `MsiTran.exe` 5.0.26100.8249; written on a Windows 11 25H2 ARM64 VM (build 26200.9457), see `tests/data/windows/msi/build.ps1` | `MsiTran -g` between the package above and the same product built as 1.0.1 (not included: it adds nothing new); the decoded changes are the expected ones (ProductVersion and registry value 1.0.1, readme.txt's new size 89 and its MsiFileHash parts = the MD5 of `files/1.0.1/readme.txt`, the Upgrade rows replaced); `MsiTran -a` applied it cleanly |
| `msi/fillyfoal-test-1.0.1.msp` | WiX Toolset 6.0.2 (`wix build` of `patch.wxs`); written on a Windows 11 25H2 ARM64 VM (build 26200.9457), see `tests/data/windows/msi/build.ps1` | patch from the two builds' .wixpdb files: transforms `RTM.1` and `#RTM.1` (the same changes, and the patch's Media row, PatchPackage and `_Columns` rows), `patch.cab`, MsiPatchMetadata and MsiPatchSequence; summary Template = target ProductCode, LastAuthor `:RTM.1;:#RTM.1` |
| `minidump/ping-normal.dmp` | Windows (event log service + wevtutil / RegSaveKeyEx / esent.dll / dbghelp), via tests/data/windows/make-fixtures.ps1, on a VM named FILLYFOAL | `MiniDumpWriteDump(MiniDumpNormal)` of a running `PING.EXE` on ARM64: thread list (6 threads, ARM64 contexts), module list (12 modules with RSDS CodeView records), function table, memory list, system info, misc info (version 5), system memory info, process VM counters. The skelsec `minidump` package rejects ARM64 dumps, so the streams were checked with a short `struct` script against dbghelp's documented layouts |
| `minidump/ping-info.dmp` | Windows (event log service + wevtutil / RegSaveKeyEx / esent.dll / dbghelp), via tests/data/windows/make-fixtures.ps1, on a VM named FILLYFOAL | the same process with `MiniDumpWithUnloadedModules \| MiniDumpWithFullMemoryInfo \| MiniDumpWithThreadInfo` (0x1820): adds the thread info list and the memory info list (240 regions); no module had been unloaded, so there is no unloaded-module stream |

## Scientific and columnar data writers

Generated in `/tmp/fixtures/<format>` with the scripts named below
(`uv run --with <pinned package>`, or Docker for Octave and R).

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `mat/compressed.mat` | SciPy 1.16.2 (`scipy.io.savemat`, NumPy 2.3.3) | `tests/data/mat/make_scipy.py`: every variable (double, uint8 with zeros, logical, char, struct, cell, sparse) in its own miCOMPRESSED element, written back to back without padding; the creation time in the header text is replaced by a fixed one of the same length; reproduced byte-for-byte |
| `mat/plain.mat` | SciPy 1.16.2 (`scipy.io.savemat`, NumPy 2.3.3) | same script, `do_compression=False`: the same variables as plain miMATRIX elements; same header edit; reproduced byte-for-byte |
| `mat/octave-v7.mat` | GNU Octave 9.4.0 (Debian trixie, `debian:trixie-slim` + `apt-get install octave`) | `tests/data/mat/make_octave.sh` running `make_octave.m`: `save -v7` (compressed) of double, uint8 with zeros, logical, char (miUTF16), struct, cell, sparse; the creation time in the header text is replaced by `2026-01-01 00:00:00` (same length); reproduced byte-for-byte |
| `mat/octave-v6.mat` | GNU Octave 9.4.0 | same script, `save -v6` (uncompressed); same header edit; reproduced byte-for-byte |
| `parquet/encrypted-footer.parquet` | pyarrow 26.0.0 (parquet-cpp-arrow 26.0.0) | `tests/data/parquet/make_encrypted.py`: modular encryption with an encrypted footer (`PARE` at both ends), AES-GCM, one encrypted and one plaintext column, throwaway keys from a toy in-memory KMS; data keys and nonces are random, so not byte-reproducible; read back with pyarrow |
| `parquet/delta.parquet` | pyarrow 26.0.0 (parquet-cpp-arrow 26.0.0) | `tests/data/parquet/make_fixtures.py`: DELTA_BINARY_PACKED, DELTA_BYTE_ARRAY and DELTA_LENGTH_BYTE_ARRAY columns (300 rows) and an INT96 timestamp column, uncompressed; reproduced byte-for-byte |
| `parquet/duckdb.parquet` | DuckDB 1.4.1 (Python package; `created_by` "DuckDB version v1.4.1") | `tests/data/parquet/make_duckdb.py`: DuckDB's own writer, one row group, Snappy, dictionary strings, nulls, a list and a struct column; reproduced byte-for-byte |
| `npy/f8-2d.npy` | NumPy 2.3.3 (`numpy.save`) | `tests/data/npy/make_numpy.py`: `<f8`, shape (3, 4); reproduced byte-for-byte |
| `npy/fortran.npy` | NumPy 2.3.3 | same script: `>i4`, `fortran_order: True`; reproduced byte-for-byte |
| `npy/structured.npy` | NumPy 2.3.3 | same script: structured dtype (`<i2`, `<f4`, `S3`); reproduced byte-for-byte |
| `npy/unicode.npy` | NumPy 2.3.3 | same script: `<U5`; reproduced byte-for-byte |
| `npy/object.npy` | NumPy 2.3.3 | same script: object array, the data is a pickle stream; reproduced byte-for-byte |
| `npy/structured-object.npy` | NumPy 2.3.3 | same script: structured dtype with an `O` field, also pickled; reproduced byte-for-byte |
| `r-serialized/workspace.RData` | R 4.4.1 (`r-base:4.4.1` Docker image) | `tests/data/r-serialized/make_r.R`: `save(..., compress = FALSE)` (RDX3) of a double vector with NA, a named list, a factor and a data frame; reproduced byte-for-byte |
| `r-serialized/altrep-v3.rds` | R 4.4.1 | same script: `saveRDS(1:10, compress = FALSE)`, version 3 with an ALTREP compact sequence; reproduced byte-for-byte |
| `r-serialized/df-v2.rds` | R 4.4.1 | same script: a data frame, serialization version 2; reproduced byte-for-byte |
| `avro/events.avro` | fastavro 1.12.1 | `tests/data/avro/make_fastavro.py`: record schema with an enum, a nullable union, a three-branch union, a map, an array and a fixed; 12 records in 4 blocks, null codec, fixed sync marker; reproduced byte-for-byte |
| `avro/events-deflate.avro` | fastavro 1.12.1 | same script, deflate codec; reproduced byte-for-byte |
| `avro/logical.avro` | fastavro 1.12.1 | same script: timestamp-millis, timestamp-micros and date logical types and a recursive record (a linked list through a `["null", "Node"]` union), null codec; reproduced byte-for-byte |
| `parquet/_metadata` | pyarrow 26.0.0 (parquet-cpp-arrow 26.0.0) | `tests/data/parquet/make_fixtures.py`: `pq.write_metadata` summary file of a one-file dataset, column chunks pointing into `part0.parquet` (`ColumnChunk.file_path`; that file is written and deleted again); reproduced byte-for-byte |
| `parquet/plaintext-footer.parquet` | pyarrow 26.0.0 (parquet-cpp-arrow 26.0.0) | `tests/data/parquet/make_plaintext_footer.py`: modular encryption with a plaintext (signed) footer, `PAR1` at both ends, AES-GCM, one encrypted column (its page headers encrypted too) and one plaintext column, throwaway keys from a toy in-memory KMS; data keys and nonces are random, so not byte-reproducible; read back with pyarrow |
| `r-serialized/ascii.rds` | R 4.4.1 | `tests/data/r-serialized/make_r.R`: `saveRDS(..., ascii = TRUE, compress = FALSE)` (`A\n` format) of a named list with escaped strings, NA, Inf, NaN, logicals, a complex and a raw vector; reproduced byte-for-byte |
| `r-serialized/ascii.RData` | R 4.4.1 | same script: `save(..., ascii = TRUE, compress = FALSE)` (RDA3); reproduced byte-for-byte |
| `r-serialized/native.rds` | R 4.4.1 | same script: `serialize(..., xdr = FALSE)` (`B\n`, little-endian) of the same list, written with `writeBin`; reproduced byte-for-byte |
| `r-serialized/closure.rds` | R 4.4.1 | same script: a list of a closure, an environment (`new.env()`, hashed) and a byte-compiled closure (`compiler::cmpfun`); reproduced byte-for-byte |
## Embedded databases and torrents
| `gdbm/dbm-gnu.gdbm` | GNU dbm 1.23 via Python 3.12 `dbm.gnu` (python:3.12-slim, Debian) | `tests/data/gdbm/make.sh`: 5 keys, 64-bit offsets (magic 0x13579acf), 4 KiB blocks; reproduced byte-for-byte |
| `gdbm/numsync.gdbm` | GNU dbm 1.23 `gdbmtool -n -x -b 512` (debian:bookworm-slim) | same script: extended (numsync) header, magic 0x13579ad1, 512-byte blocks, 3 keys; reproduced byte-for-byte |
| `bdb/` | Berkeley DB 4.7.25 `db_load` (macOS /usr/bin) | `tests/data/bdb/make.sh`: `btree47.db` (512-byte pages, 41 pairs, one value on overflow pages), `hash47.db` (the same pairs), `chksum47.db` (B-tree with `-c chksum=1`), `recno47.db` (300 records, 512-byte pages, internal and leaf pages). Not byte-for-byte reproducible: the file ID is per file, and unused page bytes are whatever db_load's buffers held (checked: only the test data) |
| `torrent/` | libtorrent 2.1.1 (Python wheel via `uv run --with libtorrent==2.1.1`) | `tests/data/torrent/make.py`: a 2-file directory as `v1.torrent` (v1 only), `v2.torrent` (BEP 52 only) and `hybrid.torrent` (v1 + v2 with BEP 47 padding files), 16 KiB pieces, creator `fillyfoal`, creation date fixed; reproduced byte-for-byte |
| `wiredtiger/mongod7-WiredTiger` | MongoDB 7 (WiredTiger 11.2.0), the official mongo:7 image, host name `fillyfoal` | `tests/data/wiredtiger/mongod.sh`: the `WiredTiger` marker of a fresh dbpath after inserting 300 documents and a clean shutdown; renamed with a `mongod7-` prefix |
| `wiredtiger-turtle/mongod7-WiredTiger.turtle` | MongoDB 7 (WiredTiger 11.2.0) | same run: the turtle file; renamed with a `mongod7-` prefix |
| `wiredtiger-btree/mongod7-WiredTiger.wt` | MongoDB 7 (WiredTiger 11.2.0) | same run: the metadata table; renamed with a `mongod7-` prefix |
| `wiredtiger-btree/collection-items.wt` | MongoDB 7 (WiredTiger 11.2.0) | same run: the `fillyfoal.items` collection (Snappy row-store leaves, BSON values, every 50th document with a 6000-byte string), renamed from its random ident `collection-7-<n>.wt` |
| `wiredtiger-btree/index-items-id.wt` | MongoDB 7 (WiredTiger 11.2.0) | same run: the collection's `_id_` index (`index-8-<n>.wt`) |
| `wiredtiger-btree/index-items-n.wt` | MongoDB 7 (WiredTiger 11.2.0) | same run: the secondary index on `n` (`index-9-<n>.wt`). The run's journal, catalog, other tables and `diagnostic.data` are not kept; times and idents differ per run |
## ZIP-based office documents, JAR and gzip members
The office files are made by `sh tests/data/docx/make-office.sh` with
LibreOffice 25.2.3.2 (Debian trixie `libreoffice-*-nogui` in Docker) in a
throwaway profile whose user name is "fillyfoal", from the flat ODF sources
`tests/data/doc/letter.fodt` and `tests/data/xls/budget.fods`. LibreOffice
stamps the conversion time into the metadata, so they are not reproducible
byte for byte. Its OOXML and ODF writers stream every deflated entry with a
data descriptor (general purpose bit 3).
| `docx/letter.docx` | LibreOffice 25.2.3.2 ("Office Open XML Text") | `soffice --convert-to docx`; all 12 entries have bit 3 set |
| `docx/letter-zipfile.docx` | CPython 3.12 `zipfile` (python:3.12-slim) | `tests/data/docx/rewrite.py letter.docx letter-zipfile.docx`: the LibreOffice package rewritten entry by entry into a seekable file (same names, order, times and methods), so no entry has bit 3 |
| `xlsx/budget.xlsx` | LibreOffice 25.2.3.2 ("Calc MS Excel 2007 XML") | `soffice --convert-to xlsx`; all 15 entries have bit 3 set |
| `odt/letter.odt` | LibreOffice 25.2.3.2 (writer8) | `soffice --convert-to odt`; stored `mimetype` first, the deflated entries with bit 3 |
| `epub/letter.epub` | LibreOffice 25.2.3.2 (EPUB export) | `soffice --convert-to epub` |
| `jar/hello.jar` | Eclipse Temurin 21 JDK `javac` + `jar` (Docker `eclipse-temurin:21-jdk`) | `sh tests/data/jar/make.sh`: `jar --create --date=2026-01-01T00:00:00Z --main-class fillyfoal.Hello` of `tests/data/jar/Hello.java` compiled with `javac --release 11`; directories stored, files deflated with data descriptors |
| `gzip/two-members.gz` | Apple gzip 479 | `sh tests/data/gzip/make-members.sh`: `gzip -9 -n -c a.txt b.txt` writes one member per file (13 + 28 bytes) |
## System and ML (review fixes)
| File | Producer | Evidence |
|---|---|---|
| `journald/compact.journal.gz` | systemd-journal-remote, systemd 257 (257.13-1~deb13u1, Debian trixie) | `sh tests/data/journald/make.sh` (Docker `debian:trixie`, `inside.sh`): three entries from a fixed export-format stream (fixed boot/machine IDs, timestamps, hostname `fillyfoal`) with `SYSTEMD_JOURNAL_COMPACT=1` and `MaxFileSize=1M` (minimum hash tables). Edited: cut after the tail object and `arena_size` set to match (`trim.py`; the rest was fallocated zeros), then `gzip -9 -n`. The trimmed file passes `journalctl --verify`; header and entries checked against `journalctl --header` / `-o export`. File and seqnum IDs are random per run |
| `journald/regular.journal.gz` | same | same script, `SYSTEMD_JOURNAL_COMPACT=0` (regular layout, DATA payload at +64) |
| `journald/zstd.journal.gz` | same | same script: the three entries and a fourth with a 1 KiB `MESSAGE` (above journald's 512-byte compression threshold), compact, `SYSTEMD_JOURNAL_COMPRESS=ZSTD` (a zstd-compressed DATA object, header flag COMPRESSED_ZSTD); trimmed and verified the same way |
| `journald/lz4.journal.gz` | same | as `zstd.journal.gz` with `SYSTEMD_JOURNAL_COMPRESS=LZ4` (u64 size, then an LZ4 block) |
| `journald/xz.journal.gz` | same | as `zstd.journal.gz` with `SYSTEMD_JOURNAL_COMPRESS=XZ` (an .xz stream) |
| `arm-fip/fip.bin` | TF-A fiptool 2.12.1 (Debian trixie `arm-trusted-firmware-tools` 2.12.1+dfsg-1) | reproduced byte for byte by `sh tests/data/arm-fip/fip.sh` (`fiptool create --align 16 --tb-fw --soc-fw --tos-fw --nt-fw` with one-line text payloads); entries checked against `fiptool info`. The same script prints the ToC UUID table in platform.rs from a FIP holding every image type |
| `git-pack/signed.pack` | git 2.47.3 (Debian trixie) | `sh tests/data/git-pack/signed.sh` (Docker, `inside.sh`): four commits and an annotated tag by `fillyfoal <test@example.com>`, the last two commits and the tag SSH-signed with a throwaway ed25519 key made in the container (multi-line `gpgsig` headers), `git repack -a -d -f` giving ofs-deltas; `git verify-pack -v` accepts it. The key is new per run, so signatures and object IDs differ between runs |
| `git-pack/ref-delta.pack` | git 2.47.3 (Debian trixie) | reproduced byte for byte by `sh tests/data/git-pack/ref-delta.sh` (Docker, `inside-ref-delta.sh`): four commits by `fillyfoal <test@example.com>` with fixed dates, packed by `git pack-objects` without `--delta-base-offset`, so delta bases are named by object ID (ref-deltas; a chain of three blobs); `git index-pack` and `git verify-pack -v` accept it, and the rebuilt blobs hash to the IDs it lists (`tests/system_depth.rs`) |
| `git-pack/thin.pack` | git 2.47.3 | same script: the last commit's objects packed with `--revs --thin`, so its one ref-delta's base is outside the pack; `git index-pack --fix-thin` completes it from the repository |
| `gguf/nested.gguf` | gguf-py 0.17.1 (`GGUFWriter`) | reproduced byte for byte by `uv run --with gguf==0.17.1 --with numpy python3 -I tests/data/gguf/nested.py OUT`: nested arrays (`add_array` of lists of lists, two and three levels) before two tensors; checked against `GGUFReader` (field types, tensor shapes and offsets) |
| `onnx/minimal.onnx` | onnx 1.19.1 (`onnx.helper`, `onnx.save`) | reproduced byte for byte by `uv run --with onnx==1.19.1 python3 -I tests/data/onnx/make.py OUTDIR`; passes `onnx.checker`. No producer fields: the graph follows `ir_version` |
| `onnx/named.onnx` | onnx 1.19.1 | same script: producer, domain, model version, doc string, two opset imports and metadata; passes `onnx.checker` |
| `protobuf/person.pb` | protoc (libprotoc 34.1) | reproduced byte for byte by `sh tests/data/protobuf/lookalike.sh` (`protoc --encode=demo.Person lookalike.proto`): a generic message that starts like an ONNX model (`08 03 12 05 alice`); negative for the ONNX probe |
| `protobuf/client-config.pb` | protoc (libprotoc 34.1) | same script (`demo.ClientConfig`): `08 01 12 0b some-client 22 ...`; negative for the ONNX probe |
## E-books (calibre)

| Path | Producer | Evidence |
|---|---|---|
| `mobi/calibre.mobi` | calibre 6.13.0 `ebook-convert` (debian:bookworm) | `tests/data/mobi/calibre.sh`: `--mobi-file-type old` from generated text (MOBI 6, PalmDOC LZ77, trailing entries); calibre records the conversion time and a random UUID, so not byte-reproducible; unedited. The decoded text matches calibre's own `MobiReader.extract_text` (SHA-256 compared) |
| `palmdoc/calibre.pdb` | calibre 6.13.0 `ebook-convert` | same script: `--format doc` (PalmDOC, LZ77); unedited. The decoded text matches calibre's `decompress_doc` over the text records |

## Printer languages, TeX output and fonts
| `pcl/gs-cdj550.pcl` | Ghostscript 10.07.1 (`cdj550` device) | `tests/data/pcl/make.sh`: three small colour rectangles on a 2-inch page at 75 dpi; bare PCL 5 colour, starts with `ESC*rbC` (no reset), raster rows sent plane by plane (`ESC*b#V` / `#v` in combined sequences); reproduced byte-for-byte |
| `pjl/gs-pjxl300.pcl` | Ghostscript 10.07.1 (`pjxl300` device) | `tests/data/pcl/make.sh`: the same page as PJL `ENTER LANGUAGE = PCL` around PCL 5 colour starting with `ESC*rbC`; reproduced byte-for-byte |
| `pjl/gs-pxlmono.pxl` | Ghostscript 10.07.1 (`pxlmono` device) | `tests/data/pcl/make.sh`: the same page as PJL around a PCL XL 1.1 stream (rectangles, a path, clip, NewPath/PaintPath); reproduced byte-for-byte |
| `pjl/gs-pxlcolor.pxl` | Ghostscript 10.07.1 (`pxlcolor` device) | `tests/data/pcl/make.sh`: as `gs-pxlmono.pxl` in RGB; reproduced byte-for-byte |
| `dvi/latex.dvi` | pdfTeX 3.141592653-2.6-1.40.29 (TeX Live 2026, `latex`) | `tests/data/dvi/make.sh`: a two-page article (DVI id 2) with `SOURCE_DATE_EPOCH=1700000000`; reproduced byte-for-byte |
| `dvi/xelatex.xdv` | XeTeX 3.141592653-2.6-0.999998 (TeX Live 2026, `xelatex -no-pdf`) | `tests/data/dvi/make.sh`: the same document as extended DVI (id 7); it names Latin Modern Roman by its standard TeX Live path; reproduced byte-for-byte |
| `cff/variable.cff2` | fontTools 4.66.1 (`FontBuilder.setupCFF2`) | `uv run --with fonttools==4.66.1 python3 tests/data/cff/variable.py variable.cff2`: the CFF2 table of a one-axis (wght) variable font; Top DICT with FDArray, CharStrings and `vstore`, a one-region variation store, glyph "A" using `blend`; reproduced byte-for-byte |
## Fonts (GNU FreeFont subsets)
GNU FreeFont 20120503 (GPL-3.0-or-later with the GPL font exception; notice
in THIRD-PARTY.md), taken from TeX Live 2026's `gnu-freefont` package, and
subset with fontTools 4.66.1 (Brotli 1.2.0) by
`uv run --with fonttools==4.66.1 --with brotli==1.2.0 python3 tests/data/sfnt/freefont_subsets.py FREEFONT_DIR OUTDIR`,
which reproduces all five byte for byte. Each keeps the glyphs for
"FreeFont fi fl 0123 ffi?!" plus layout closure (24 glyphs in FreeSerif),
GSUB/GPOS/GDEF, hinting tables, and every name record.
| `sfnt/freeserif-subset.ttf` | fontTools 4.66.1 `subset` of FreeSerif.ttf (FontForge-built, `FFTM` dropped) | reproduced byte-for-byte; TrueType outlines |
| `sfnt/freeserif-subset.otf` | fontTools 4.66.1 `subset` of FreeSerif.otf | reproduced byte-for-byte; CFF outlines |
| `sfnt/fonttools-cff2-svg-dsig.otf` | fontTools 4.66.1 `FontBuilder`, OpenSSL 3.6.3 | `sh tests/data/sfnt/make_cff2_svg_dsig.sh`: two glyphs with CFF2 outlines, an `SVG ` table with one plain and one gzipped document (gzipped by fontTools), and a `DSIG` table whose format 1 block holds a detached DER PKCS#7 SignedData made by `openssl cms -sign` with a throwaway self-signed EC key (CN=fillyfoal) over a fixed text, not over the font; key, certificate and signing time are new each run |
| `woff/freeserif-subset.woff` | fontTools 4.66.1 (`flavor=woff`, zlib) | reproduced byte-for-byte; the TrueType subset |
| `woff2/freeserif-subset.woff2` | fontTools 4.66.1 (`flavor=woff2`, Brotli 1.2.0) | reproduced byte-for-byte; the TrueType subset with fontTools' default glyf/loca transform |
| `ttc/freefont-subset.ttc` | fontTools 4.66.1 `TTCollection` | reproduced byte-for-byte; FreeSans and FreeSerif TrueType subsets, identical tables shared |
| `eot/freeserif-subset.eot` | mkeot (W3C eot-utils 1.1, Debian bookworm `eot-utils 1.1-1+b1`, Docker `debian:bookworm-slim`) | reproduced byte-for-byte: `sh tests/data/eot/mkeot.sh DIR` (`mkeot sfnt/freeserif-subset.ttf https://example.org/`); EOT version 0x00020002, uncompressed, one root string. mkeot copies the four names from the name table unswapped, so they are UTF-16BE where the format has UTF-16LE (its own `eotinfo` shows them byte-swapped too) |
## Disk images with mounted or loop-device writes (Linux), and UDRO
`ntfs`, `lvm2` and `iso9660` rows: made by `sh tests/data/disk/make-volumes.sh`
in a privileged Debian trixie container (host name `fillyfoal`) running
`tests/data/disk/volumes-inner.sh`, whose commands are the evidence; tool
versions are those it prints. Timestamps are those of the run and NTFS
serials and LVM UUIDs are random, so the images are not byte-reproducible.
Stored whole as `.raw.zst` (zstd -19).
| `ntfs/ntfs3g-attrlist.img.raw.zst` | ntfs-3g 2022.10.3 mkntfs and FUSE driver, Linux 7.0 ntfs3 | `make-volumes.sh /tmp/fixtures/disk-volumes ntfs`; 8 MiB, 4 KiB clusters: `ads.txt` with 20 named streams and `linked.txt` with 6 long hard links (attributes in extension records through an $ATTRIBUTE_LIST); `big/` with 32 files with 200-character names of which 28 deleted (freed index records with stale entries); `xdir/` with 9 user xattrs (named streams) and then 4 files, its $INDEX_ROOT with the 4 entries moved to an extension record by ntfs-3g; `sparse.bin` written through ntfs3 (`-o sparse`), 300 blocks each followed by a hole, its $DATA runlist split over three records (the VCN 0 part in an extension record) |
| `lvm2/lvm-wrapped.img.raw.zst` | lvm2 2.03.31 | 8 MiB PV, `pvcreate --dataalignment 64k --metadatasize 40k`, VG `vgw` with four 1 MiB LVs, then `lvchange --addtag` until a commit's metadata text wraps around the 60 KiB circular buffer 512 bytes before its end |
| `iso9660/xorriso-gpt.iso.raw.zst` | xorriso 1.5.6 | `xorriso -as mkisofs -R -J -append_partition 2 0xef efi.img -appended_part_as_gpt` (a hybrid image: GPT at 0x200, ISO 9660 at 0x8000) |
| `dmg/hfs-udro.dmg.raw.zst` | macOS 26.5 hdiutil | `hdiutil create -size 1m -fs HFS+ -volname fillyfoal -layout GPTSPUD rw.dmg`, then `hdiutil convert rw.dmg -format UDRO -o hfs-udro.dmg` (a GPT at 0x200 and a koly trailer) |
## macOS Foundation
| `bookmark/notes.alias` | Foundation `URL.bookmarkData(options: .suitableForBookmarkFile)` + `URL.writeBookmarkData`, macOS 26.5 (Swift 6.3.3), via tests/data/bookmark/make_alias.sh | alias file (`book`/`mark` header, bookmark data at 0x38) for `notes.txt` on a throwaway 4 MiB HFS+ RAM disk named `fillyfoal` mounted at `/tmp/fixtures/forensics-bookmark/mnt`. Edit: the two volume UUID strings (the RAM disk and the boot volume holding the mount point) were replaced by `00000000-0000-4000-8000-00000000000N` (same length), and the boot volume's size and creation date were zeroed, by tests/data/bookmark/scrub_alias.py; the RAM disk's file IDs and dates are as written |
## Text writers
| `jar-manifest/MANIFEST.MF` | OpenJDK 21.0.12.1 `jar` (eclipse-temurin:21-jdk image) | extracted from a jar made by `jar --create --main-class com.example.Main --manifest m.txt`; `jar` wrapped the long `Class-Path` at 72 bytes mid-word and added `Created-By`; input manifest and commands in `tests/data/jar-manifest/make.sh` |
| `python-metadata/PKG-INFO` | setuptools 80.9.0 (via build 1.2.2) | the sdist's `PKG-INFO` for a throwaway project with neutral metadata; reproduced byte-for-byte by `tests/data/python-metadata/make.sh` |
| `deb822/hello_1.0.dsc` | dpkg-source 1.21.23 (debian:bookworm image) | `dpkg-source -b` on a throwaway native source package (`tests/data/deb822/make.sh`); unsigned; the checksums of the generated `.tar.xz` may differ on a re-run with another xz or tar |
| `csv/records.csv` | CPython 3.14 `csv.writer` | `tests/data/text/large.sh` (QUOTE_MINIMAL, CRLF records, quoted fields with commas, quotes and line breaks); reproduced byte-for-byte |
| `json/items.json` | jq 1.8.1 | `tests/data/text/large.sh` (`jq -n` pretty-printing an array of 240 objects); reproduced byte-for-byte |
| `text/lines-utf16le.txt` | macOS `iconv` (UTF-8 to UTF-16LE) | `tests/data/text/large.sh`; the byte order mark is prepended by the script, the text is ours |
## NTFS master file table
| `ntfs-mft/ntfs3g.mft.raw.zst` | ntfs-3g 2022.10.3 mkntfs and FUSE driver, Linux 7.0 ntfs3 (debian:trixie-slim, privileged) | `sh tests/data/ntfs-mft/make-mft.sh`: a 2 MiB volume (`mkntfs -q -F -f -L fillyfoal -c 4096`); through ntfs-3g `ads.txt` with two named streams and `objid.txt` with an object id (`setfattr -n system.ntfs_object_id`), through ntfs3 `linked.txt` with 12 hard links (names in extension records, a non-resident $ATTRIBUTE_LIST; ntfs3 also writes $EA_INFORMATION/$EA) and two symbolic links (IO_REPARSE_TAG_SYMLINK reparse points). The $MFT is copied out as stored, sector fixups included, by `tests/data/ntfs-mft/raw-mft.py` (the clusters record 0's $DATA runlist names; `ntfscat` would return fixed-up records). Timestamps are those of the run; not byte-reproducible. Stored as `.raw.zst` (zstd -19) |
## Shell links (.NET writers)
| `lnk/console-propstore.lnk` | securifybv.ShellLink 0.1.0 and securifybv.PropertyStore 0.1.0 (NuGet), .NET SDK 8.0.425 (mcr.microsoft.com/dotnet/sdk:8.0) | `sh tests/data/lnk/make-lnk.sh` runs `tests/data/lnk/Program.cs`: `Shortcut.CreateShortcut` for `C:\Windows\System32\cmd.exe` with arguments, plus a ConsoleDataBlock and a PropertyStoreDataBlock of two storages (AppUserModel ID and PreventPinning; Storage Size and DateModified). The libraries write the link, the blocks and the property store framing; the TypedPropertyValue bodies are bytes built by Program.cs per MS-OLEPS. No name-keyed storage: the library writes names wrongly (see `ms-propstore/named.propstore` in the synthetic tree); it also counts a trailing NUL in the StringData strings and leaves the header times zero. Byte-reproducible |
## Robotics recordings
| `mcap/zstd.mcap` | Python `mcap` 1.2.2 `Writer` (zstandard 0.25.0) | `uv run --with mcap==1.2.2 --with zstandard==0.25.0 --with lz4==4.4.5 python3 -I tests/data/mcap/make.py OUTDIR`; reproduced byte-for-byte; one zstd chunk with a schema, two channels and nine JSON messages, then the summary section |
| `mcap/lz4.mcap` | Python `mcap` 1.2.2 `Writer` (lz4 4.4.5) | same script; the same records in one LZ4-frame chunk |
## Bitmap fonts (fontTools)
| `sfnt/fonttools-glyf-bitmaps.ttf` | fontTools 4.66.1 `FontBuilder` and TTX import, Pillow 11.3.0 | reproduced byte-for-byte with `SOURCE_DATE_EPOCH=1767225600 uv run --with fonttools==4.66.1 --with pillow==11.3.0 python3 -I tests/data/sfnt/make_bitmap_glyphs.py OUT`: five TrueType glyphs (empty, simple, composite with a scale), hmtx/vmtx, an `sbix` strike (PNG and `dupe`), a `CBDT`/`CBLC` strike (format 17 PNGs, index format 1) and an `EBDT`/`EBLC` strike (format 5, index format 2) |
## JPEG XL and JPEG metadata
| `jxl/cjxl-alpha-lossless.jxl` | libjxl cjxl 0.11.2 (Debian trixie `libjxl-tools 0.11.2-0.1~deb13u2`, Docker) | reproduced byte-for-byte: `sh tests/data/jxl/make.sh ROOT` (`cjxl -d 0` of a 40x40 ImageMagick PNG with alpha); bare codestream, not XYB, one alpha extra channel |
| `jxl/cjxl-grey16.jxl` | libjxl cjxl 0.11.2 | same script: `cjxl -d 0` of a 16-bit greyscale gradient PNG; bare codestream, greyscale colour encoding |
| `jxl/cjxl-anim-jxlp.jxl` | libjxl cjxl 0.11.2 | same script: `cjxl -d 1 --container=1` of a three-frame ImageMagick GIF; the codestream is split over three `jxlp` boxes; animation header, alpha |
| `jxl/cjxl-jpeg-recon.jxl` | libjxl cjxl 0.11.2 | same script: `cjxl --lossless_jpeg=1` of a 32x24 ImageMagick JPEG carrying an ExifTool-written Exif block (Artist/Copyright `fillyfoal`): `jxlp`, `jbrd`, `brob` (Brotli Exif), last `jxlp` |
| `jxl/cjxl-exif.jxl` | libjxl cjxl 0.11.2, ExifTool 13.25 | same script: `cjxl -q 90 --container=1`, then ExifTool appends an `Exif` box (`-Artist=fillyfoal`) |
| `jxl/cjxl-upsampling-nn.jxl` | libjxl cjxl 0.11.2 | same script: `cjxl -d 1 --resampling=2 --already_downsampled --upsampling_mode=0` of the 32x24 gradient PNG; bare codestream, all-default image metadata with non-default CustomTransformData (custom 2x upsampling weights) |
| `jpeg/exiftool-metadata.jpg` | ExifTool 13.25, ImageMagick 7.1.1.43, Pillow 11.1.0 / LittleCMS (Debian trixie, Docker) | reproduced byte-for-byte: `sh tests/data/jpeg/exiftool_metadata.sh ROOT`: a 32x24 ImageMagick JPEG to which ExifTool writes IFD0, Exif and GPS tags, an IFD1 thumbnail (8x6 ImageMagick JPEG), IPTC in a Photoshop APP13 block, XMP, and an ICC profile (LittleCMS's built-in sRGB written by Pillow's `ImageCms`; the script sets the profile's creation date, which LittleCMS takes from the clock, to 2026-01-01) |
| `jpeg/ultrahdr-gainmap.jpg` | libultrahdr 1.4.0 `ultrahdr_app` (built from the v1.4.0 tag against Debian trixie's libjpeg-turbo, Docker) | `sh tests/data/jpeg/ultrahdr.sh ROOT`: encode scenario 0 from a 32x24 RGBA1010102 PQ gradient the script writes (`-a 5 -t 2 -C 2 -R 1 -q 80 -Q 80 -s 4 -M 0`): primary JPEG and gain-map JPEG with MPF, ISO 21496-1 APP2 metadata and the ICC profiles libultrahdr embeds (its own Display P3 and Lab profiles, Apache-2.0 data from the library) |
| `jpeg/ultrahdr-xmp.jpg` | libultrahdr 1.4.0 `ultrahdr_app`, built with `-DUHDR_WRITE_XMP=ON -DUHDR_WRITE_ISO=OFF` | same script, same input and options: the gain-map metadata as hdrgm XMP only (primary XMP with the Google Container directory, gain-map XMP with the hdrgm parameters), as libultrahdr 1.0 and Android 14 wrote it; no ISO 21496-1 APP2 |
## DNG (PiDNG)
| `dng/pidng-bayer.dng` | PiDNG 4.0.9 (numpy 2.5.4) | reproduced byte-for-byte: `uv run --with pidng==4.0.9 --with numpy==2.5.4 python3 -I tests/data/dng/pidng_bayer.py OUT` (PiDNG appends `.dng`): a 32x24 uncompressed 12-bit RGGB Bayer tile from a gradient the script makes, DNG 1.4 tags (CFA pattern, black/white level, ColorMatrix1, AsShotNeutral), Make/Model `fillyfoal`/`Bayer Test` |
## Unreal Engine paks (repak)
| `unreal-pak/` (`repak-v3-zlib.pak`, `repak-v8b-zlib.pak`, `repak-v11-zlib.pak`, `repak-v11-zstd.pak`) | repak_cli 0.2.3 (github.com/trumank/repak commit 355b5f62, built with `cargo install --locked` in Docker `rust:1-bookworm`) | `sh tests/data/unreal-pak/make-repak.sh` (in the same image): `repak pack --version V3/V8B/V11 --compression Zlib/Zstd` over a three-file tree the script writes (an 80 KiB file that compresses in two 64 KiB blocks); v3 has absolute block offsets, v8b five method names, v11 the path-hash and full-directory indexes with encoded entries. All six reproduce byte for byte with one rayon thread (the script sets `RAYON_NUM_THREADS=1`; with more, the order of the files' data varied between runs), and were regenerated that way |
| `unreal-pak/repak-v8a-lz4.pak`, `unreal-pak/repak-v9-gzip.pak` | repak_cli 0.2.3 (same build) | same script, `repak pack --version V8A --compression LZ4` and `--version V9 --compression Gzip`: v8a with four method names (a one-byte method in each entry), v9 with the frozen-index byte clear; repak writes each LZ4 and gzip file as one block |
## Bethesda archives (ba2 crate)
| `bsa/` (`v104.bsa`, `v105-embedded.bsa`) | ba2 crate 3.0.1 (Rust, 0BSD, github.com/Ryan-rsm-McKenzie/bsa-rs), Docker `rust:1-bookworm` | reproduced byte-for-byte by `sh tests/data/bsa/make.sh` (runs `tests/data/bsa/main.rs`): two folders, three files; directory and file strings, compressed (v104 zlib, v105 LZ4 frames), `data.bin` stored raw through the 0x40000000 size toggle; v105 also with embedded file names |
| `ba2/` (`gnrl-v1.ba2`, `gnrl-v2.ba2`, `dx10-v3.ba2`) | ba2 crate 3.0.1, same run | GNRL v1 (Fallout 4) and v2 (Starfield) with zlib chunks, DX10 v3 (Starfield, LZ4 block) from a 4x4 three-mip DDS the script writes; all with name tables |
## MAME CHD (chdman)
| `chd/` (`chdman-hd.chd`, `chdman-cd.chd`) | chdman 0.251 (Debian bookworm `mame-tools`, Docker `debian:bookworm-slim`, linux/amd64) | `sh tests/data/chd/make-chdman.sh`: `chdman createhd -hs 4096` over a 64 KiB image the script writes (repeated and zero hunks, so the compressed v5 map has self references and RLE runs; default codecs lzma/zlib/huff/flac; byte-reproducible) and `chdman createcd` over a cue sheet for a padded xorriso 1.5.4 ISO (default codecs cdlz/cdzl/cdfl; the ISO timestamps differ per run). On linux/arm64 and for an unpadded 34-frame ISO, chdman 0.251 wrote CD images it could not reopen ("Decompression error"); the padded amd64 run is the one used |
## Apple AVFoundation and GPAC muxers

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `mov/avconvert-aac.mov` | macOS 26.5 `avconvert` (AVFoundation, Core Media) | `sh tests/data/mov/make-apple.sh` (`-p PresetLowQuality` of an FFmpeg 8.1.2 H.264/PCM source with 4:3 sample aspect): HE-AAC in a version 1 sound description with a `wave` atom (frma, mp4a, esds, terminator), H.264 passed through, `tapt` clef/prof/enof; not byte-reproducible (creation times) |
| `mov/avconvert-prores.mov` | macOS 26.5 `avconvert` (AVFoundation, Apple ProRes encoder) | same script (`-p PresetAppleProRes422LPCM --duration 0.1`): ProRes 422 with `colr` nclc and `fiel`, 32-bit float LPCM in a version 2 sound description, `tapt`; not byte-reproducible |
| `m4a/avconvert.m4a` | macOS 26.5 `avconvert` (AVFoundation, Apple AAC encoder) | same script (`-p PresetAppleM4A`): AAC-LC, `iTunSMPB` gapless tag; not byte-reproducible |
| `mp4/gpac.mp4` | GPAC MP4Box 2.4.0 (built from the v2.4.0 release tarball in Debian trixie) | `sh tests/data/mp4/make-gpac.sh` (inner commands in `tests/data/mp4/gpac-inner.sh`): `MP4Box -add in.h264:fps=10 -add in.aac -new` of FFmpeg 8.1.2 raw H.264 and ADTS AAC (`iods`, `btrt`, `stss`, GPAC handler names); not byte-reproducible (creation times) |
| `mp4/gpac-frag.mp4` | GPAC MP4Box 2.4.0 | same script, with `-frag 200`: `mvex`/`mehd`/`trex`, then `moof`/`traf`/`trun` fragments of both tracks; not byte-reproducible |
| `mp4/webvtt.mp4` | GPAC MP4Box 2.4.0 (built from the v2.4.0 release tarball in Debian trixie) | `sh tests/data/mp4/make-webvtt.sh`: `MP4Box -add cues.vtt:lang=eng -new` of the two-cue WebVTT file in the script (`wvtt`/`vttC` sample entry, `vttc` samples with `iden`, `sttg` and `payl`, `vtte` gaps); not byte-reproducible (creation times) |
## Tracker modules (Schism Tracker, MilkyTracker)
Made by `sh tests/data/tracker/make.sh OUTDIR` (debian:trixie-slim, `tests/data/tracker/inside.sh`): our seed `song.mod` (`tests/data/tracker/song.py`: four channels, two looped samples, two patterns with common effects) is loaded into each tracker and saved through its user interface on a virtual X display (Xvfb, xdotool), since neither has a command-line save. Schism Tracker writes its build date and the save time (IT edit history, two S3M reserved bytes) into its files, so those bytes differ on a re-run; the rest reproduces.
| `it/schism.it` | Schism Tracker 20250313 (Debian `schism 2:20250313-2`) | Save Module (F10), format IT: sample mode, 235 sample headers (Schism counts up to its internal preview slot), edit history entry, no MIDI configuration |
| `s3m/schism.s3m` | Schism Tracker 20250313 | Save Module, format S3M: 99 instrument headers, two packed patterns, Schism version date in the reserved bytes |
| `mod/schism.mod` | Schism Tracker 20250313 | Save Module, format MOD (M.K., 31 samples) |
| `xm/milkytracker.xm` | MilkyTracker 1.05.01 (Debian source `1.05.01+dfsg-1`, built without ALSA/JACK MIDI) | disk operations (Ctrl+Shift+S), type `.xm`: XM 1.04, two instruments of one sample each, packed patterns; reproduced byte-for-byte |
## APE, Musepack and Speex reference encoders (Fedora 42)
Made by `sh tests/data/audio-codecs/make.sh OUTDIR` (fedora:42, `tests/data/audio-codecs/inside.sh`) from sine tones written by `tests/data/audio-codecs/tone.py` (16-bit PCM WAV: 44.1 kHz stereo 0.1 s; 16 kHz mono 0.25 s).
| `ape/mac-normal.ape` | Monkey's Audio 12.63 (`mac`, Fedora `mac-12.63-1.fc42`) | `mac tone44.wav mac-normal.ape -c2000`: file version 3.99, one frame, stored WAV header |
| `ape/mac-extra-high.ape` | Monkey's Audio 12.63 | `mac tone44.wav mac-extra-high.ape -c4000` |
| `musepack/mpcenc.mpc` | mpcenc 1.30.1 (Fedora `musepack-tools-1.3.0^20110810svn475-3.fc42`) | `mpcenc --silent --standard tone44.wav mpcenc.mpc`: SV8 with stream header, replay gain, encoder info, seek table offset, one audio packet, seek table, stream end |
| `speex/speexenc.spx` | speexenc (Fedora 42 `speex-tools`, libspeex 1.2.0 per the vendor string) | `speexenc --wideband --quality 6 tone16.wav speexenc.spx`: Ogg Speex, wideband mode; the Ogg serial number is random, so reruns differ in it and in the page CRCs |
## Documents, e-books and printer rasters (Debian bookworm tools in Docker)
| `pict/imagemagick-direct.pict` | ImageMagick 6.9.11-60 (Debian bookworm `imagemagick`) | `sh tests/data/pict/make.sh OUTDIR`: `convert -size 48x32 gradient:red-blue -depth 8 PICT:...`; version 2 PICT with a 512-byte header, DirectBitsRect (0x9A, packType 4); reproduced byte-for-byte |
| `pict/imagemagick-packbits.pict` | ImageMagick 6.9.11-60 | same script, `-colors 4`: PackBitsRect (0x98) with a colour table; reproduced byte-for-byte |
| `cups-raster/gs-pwgraster.ras` | Ghostscript 10.00.0 (Debian bookworm `ghostscript`) | `sh tests/data/cups-raster/make.sh OUTDIR`: `-sDEVICE=pwgraster -r72` on a 1 x 0.75 inch page with three bars; reproduced byte-for-byte |
| `cups-raster/gs-cups.ras` | Ghostscript 10.00.0 | same script, `-sDEVICE=cups` (little-endian `3SaR`); reproduced byte-for-byte |
| `urf/gs-urf.urf` | Ghostscript 10.00.0 | same script, `-sDEVICE=urf` (Apple raster, `UNIRAST`); reproduced byte-for-byte |
| `djvu/c44.djvu` | DjVuLibre 3.5.28 (Debian bookworm `djvulibre-bin`) | `sh tests/data/djvu/make.sh OUTDIR`: `c44` of a generated 64x48 colour gradient (IW44 BG44 chunks); reproduced byte-for-byte |
| `djvu/cjb2.djvu` | DjVuLibre 3.5.28 | same script: `cjb2` of a generated 64x48 checkerboard (JB2 Sjbz); reproduced byte-for-byte |
| `djvu/djvm-bundled.djvu` | DjVuLibre 3.5.28 | same script: `djvm -c` of the two pages (bundled DJVM with DIRM); reproduced byte-for-byte |
| `chm/chmcmd.chm` | chmcmd from Free Pascal 3.2.2 (Debian bookworm `fp-utils`) | `sh tests/data/chm/make.sh OUTDIR`: a project of 40 generated HTML pages (about 130 KB, several LZX reset intervals), a contents and an index file, title and default topic; the ITSF header and the `#SYSTEM` timestamp record take the time of the run, so a re-run differs in those bytes |
| `cff/fonttools.cff` | fontTools 4.66.1 (`FontBuilder.setupCFF`) | `uv run --with fonttools==4.66.1 python3 tests/data/cff/cff1.py fonttools.cff`: the CFF table of a three-glyph OpenType font with a Private DICT (BlueValues, OtherBlues, StdHW/StdVW, StemSnapH, widths) and one local subroutine; reproduced byte-for-byte |
| `mobi/calibre-kf8.azw3` | calibre 6.13 (Debian bookworm) | `sh tests/data/mobi/calibre-kf8.sh OUTDIR`: `ebook-convert book.txt x.azw3` on ~3 KB of generated sentences (KF8 only, MOBI header version 8); calibre records the conversion time and a random UUID, so a re-run differs in those bytes |
| `mobi/calibre-both.mobi` | calibre 6.13 | same script, `--mobi-file-type both`: MOBI 6, a BOUNDARY record, then the KF8 half (EXTH 121 = 6); not byte-reproducible (time, UUID) |
| `lrf/calibre.lrf` | calibre 6.13 | same script, `ebook-convert book.txt x.lrf`; not byte-reproducible (time, UUID) |
| `palm-pdb/calibre-ereader.pdb` | calibre 6.13 | same script, `--format ereader` (calibre's zTXT writer fails on Python 3); not byte-reproducible (time) |
| `tex-tfm/pltotf.tfm` | PLtoTF 3.6 (TeX Live 2026) | `sh tests/data/tex-tfm/make.sh OUTDIR`: a property list written by the script (three characters, a kern and a ligature, seven parameters, design size 10pt); reproduced byte-for-byte |
| `tex-vf/vptovf.vf` | VPtoVF (TeX Live 2026) | same script: a virtual property list mapping two characters onto `pltotf` (a SETCHAR, a SETCHAR plus SETRULE); reproduced byte-for-byte |
## Access databases (Jackcess)
| `mdb/jet4.mdb.raw.zst` | Jackcess 4.0.5 (Maven Central, sha1-checked), OpenJDK 21 (eclipse-temurin:21-jdk) | `sh tests/data/mdb/make.sh OUTDIR` runs `tests/data/mdb/Gen.java`: `FileFormat.V2000` (Jet 4) database with table `Parts` (autonumber key, Text, Integer, Boolean, Currency, Double, Single, Date/Time, Replication ID, Byte, Binary, Memo, OLE, Decimal(18,4); memos inline, on one long-value page and chained over several; a deleted row; primary key and an index on Name), built on Jackcess's bundled empty Access 2000 database (its system tables and template objects). Values checked with mdbtools 1.0.0 `mdb-export` (Debian bookworm). Not byte-for-byte reproducible (creation times in MSysObjects). Contains Jackcess's empty-database template (Apache-2.0; see THIRD-PARTY.md). Stored with `zstd -19` (156 KiB raw) |
| `accdb/ace.accdb.raw.zst` | same | same script, `FileFormat.V2010` (ACE 14) on Jackcess's bundled empty Access 2010 database; same table and values. Contains Jackcess's empty-database template (Apache-2.0; see THIRD-PARTY.md). Stored with `zstd -19` (396 KiB raw) |
## System: rebuilt content (sparse images, tensors, AVB, SHA-256 git)
| `android-sparse/ext4.simg` | AOSP img2simg 34.0.5 (Debian trixie `android-sdk-libsparse-utils` 1:34.0.5-12), mke2fs 1.47.2 (`e2fsprogs` 1.47.2-3+b12) | reproduced byte for byte by `sh tests/data/android-sparse/make.sh` (Docker `debian:trixie-slim`, `inside.sh`): a 2 MiB ext4 file system (`mke2fs -d`, fixed UUID and hash seed, `E2FSPROGS_FAKE_TIME`, inode times pinned with `debugfs`) with two text files and a 16 KiB file of `0xff` bytes, converted with `img2simg`: raw chunks, zero fills and a `0xffffffff` fill. `simg2img` rebuilds the original image (CRC-32 0xd159787d, checked in `tests/system_depth.rs`) |
| `gguf/quant.gguf` | gguf-py 0.17.1 (`GGUFWriter`, `gguf.quants.quantize`) | reproduced byte for byte by `uv run --with gguf==0.17.1 --with numpy python3 -I tests/data/gguf/quant.py OUT`: 2x256 tensors in F32, F16, BF16, Q4_0, Q4_1, Q5_0, Q5_1, Q8_0, TQ1_0 and TQ2_0 and a 1x256 I8 tensor; tensor byte sizes checked against `GGUFReader` (`n_bytes`) |
| `vbmeta/avbtool.img` | AOSP avbtool 1.3.0 (`avbtool.py` from platform/external/avb at 761178607206f4cb2af79ed9eec52d8cbd814adb, MIT; fetched into /tmp, not committed), Python 3 and OpenSSL 3.5 in Debian trixie | `sh tests/data/vbmeta/make.sh` (Docker `debian:trixie-slim`, `inside.sh`): `make_vbmeta_image` signed SHA256_RSA2048 with a throwaway key made in the container, rollback index 3, descriptors from the footed boot image (hash, property) and from a data partition with a hashtree footer (`add_hashtree_footer`, no FEC), a chain partition descriptor, a kernel command line and a property; every field checked against `avbtool info_image`. The key is new per run, so key and signature bytes differ between runs |
| `android-boot/boot-avb.img.gz` | AOSP mkbootimg 34.0.5 (Debian trixie) and avbtool 1.3.0 as above | same script: a v2 boot image (fake kernel, gzip ramdisk, DTB) given an AVB hash footer by `add_hash_footer` in an 80 KiB partition (vbmeta at 0x2000 after the 8 KiB image, the footer in the last 64 bytes); stored `gzip -9 -n` |
| `android-vendor-boot/vendor_boot-avb.img.gz` | as above | same script: a v3 vendor_boot image with an AVB hash footer; stored `gzip -9 -n` |
| `ext/ext4-avb.img.gz` | e2fsprogs 1.47.2 `mke2fs` and AOSP avbtool 1.3.0 (as above), Debian trixie | reproduced byte for byte by `sh tests/data/vbmeta/footers.sh` (Docker `debian:trixie-slim`, `inside-footers.sh`): a 256 KiB ext4 file system (fixed time, UUID and hash seed) given `add_hashtree_footer` in a 384 KiB partition (4 KiB hash tree, no FEC, unsigned vbmeta with a property, footer in the last 64 bytes); checked against `avbtool info_image`; stored `gzip -9 -n` |
| `erofs/avb-hashtree.erofs.gz` | erofs-utils 1.8.6 `mkfs.erofs` and avbtool 1.3.0 | same script: a one-block EROFS image (`-T0 --all-root`, fixed UUID) with a hashtree footer in an 88 KiB partition (a one-block image has no hash tree levels, so the vbmeta follows the image directly); stored `gzip -9 -n` |
| `avb-footer/data.img.gz` | avbtool 1.3.0 | same script: 16 KiB of a byte ramp (no file system) with a hashtree footer in a 96 KiB partition; stored `gzip -9 -n` |
| `git-pack/sha256.pack` | git 2.47.3 (Debian trixie) | reproduced byte for byte by `sh tests/data/git-pack/sha256.sh` (Docker, `inside-sha256.sh`): a `git init --object-format=sha256` repository of three commits by `fillyfoal <test@example.com>` with fixed dates, `git repack -a -d -f` giving two ofs-deltas (checked against `git verify-pack -v`: the rebuilt blobs hash to the object IDs it lists, `tests/system_depth.rs`) |
| `git-pack-index/sha256.idx` | git 2.47.3 | same script: the v2 index of `git-pack/sha256.pack` (32-byte object names) |
| `git-index/sha256.index` | git 2.47.3 | same script: the repository's `.git/index` (32-byte object names; `git ls-files -s`). Its entries hold the container's stat data (times, device, inode), so it differs between runs |
## Misc formats: UEFI LZMA sections, CAD and Visio compound files, zip and PDF variants
| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `uefi-fv/edk2-lzma.fv` | EDK2 BaseTools (edk2-stable202405: GenSec, GenFfs, GenFv, LzmaCompress), built in Docker `debian:bookworm` by `tests/data/uefi-fv/build-tools.sh` | reproduced byte for byte by `tests/data/uefi-fv/mklzma.sh` (Docker, see the script): an FFS v3 volume of three freeform files: a GUID-defined section of the LZMA custom decompression GUID (`LzmaCompress -e`), one of the LZMA x86 GUID (`LzmaCompress --f86 -e`), each holding a raw and a user interface section, and a plain user interface section |
| `uefi-fv/edk2-compress.fv` | EDK2 BaseTools (edk2-stable202405: GenSec with its EfiCompress, TianoCompress, BrotliCompress with google/brotli at f4153a09, GenFfs, GenFv), built in Docker `debian:bookworm` by `tests/data/uefi-fv/build-tools.sh` | reproduced byte for byte by `tests/data/uefi-fv/mkcompress.sh` (Docker, see the script): an FFS v3 volume of three freeform files, each wrapping a raw and a user interface section: a compression section of the standard (EFI) compression (`GenSec -c PI_STD`), a GUID-defined section of the Tiano GUID (`TianoCompress -e`) and one of the Brotli GUID (`BrotliCompress -e`) |
| `pkpass/boarding.pkpass` | passkit-generator 3.3.1 (npm, node-forge signature, do-not-zip writer) in Docker `node:20-bookworm-slim` | `tests/data/pkpass/make.sh` runs `gen.js`: a generic pass (QR barcode, 2x2 icon), its manifest of SHA-1 digests and a detached PKCS #7 signature by throwaway certificates (CN `fillyfoal WWDR` and `fillyfoal pass signer`, made with OpenSSL in the container). Keys, signature and signing time differ between runs |
## Profiling and coverage data (GCC, LLVM, Temurin in Docker)
| `gcno/prog.gcno` | GCC 14.2.0 (Debian trixie `gcc` 14.2.0-19) | `sh tests/data/profile/make.sh`: `gcc --coverage -O0 -c prog.c` of `tests/data/profile/prog.c` in `/src` (the working directory recorded in the file); GCC 12+ layout (byte lengths, unpadded strings, checksum). The stamp is the compile time, so a rerun differs in it |
| `gcda/prog.gcda` | GCC 14.2.0 (libgcov) | same script: written when the linked program exits; one run, three functions' arc counters |
| `gcno/prog-gcc10.gcno` | GCC 10.3.1 (Alpine 3.14 `gcc` 10.3.1_git20210424) | same script, second container: the pre-GCC 12 layout (lengths in words, word-padded strings, no checksum); the stamp is the compile time |
| `gcda/prog-gcc10.gcda` | GCC 10.3.1 (libgcov) | same script: the counts of that build |
| `profraw/prog.profraw` | clang/compiler-rt 19.1.7 (Debian trixie `clang`, `libclang-rt-19-dev`) | same script: `clang -fprofile-instr-generate -fcoverage-mapping -O0`, run with `LLVM_PROFILE_FILE`: raw profile version 10, front-end instrumentation, a binary ID, three data records, zlib-compressed names. The build ID and address deltas differ between builds |
| `profraw/prog-ir.profraw` | clang/compiler-rt 19.1.7 | same script: `clang -fprofile-generate -O0` (IR instrumentation variant bit) |
| `profdata/prog.profdata` | llvm-profdata 19.1.7 (Debian trixie `llvm`) | same script: `llvm-profdata merge -o prog.profdata prog.profraw`: indexed profile version 12 (summary, hash table of three functions, binary IDs, empty virtual table names) |
| `profdata/prog-ir.profdata` | llvm-profdata 19.1.7 | same script, from `prog-ir.profraw` |
| `jfr/events.jfr.gz` | OpenJDK 21.0.12.1 (Temurin, `eclipse-temurin:21-jdk`) | `sh tests/data/jfr/make.sh`: `java -XX:StartFlightRecording:filename=events.jfr,settings=events.jfc Hello` with `tests/data/jfr/Hello.java` and `events.jfc`; only `jdk.ThreadStart` (with stack traces), `jdk.ThreadEnd` and `jdk.GarbageCollection` are enabled, so no system properties, environment or CPU details are recorded; one chunk of format 2.1 (metadata, checkpoints, ten events). Times and thread IDs differ between runs. Stored with `gzip -9 -n` (about 110 KB raw) |
## Database servers (Docker)
| `innodb/mysql-fruit.ibd.gz` | MySQL Community Server 9.7.1 (official `mysql:9.7.1` image) | `sh tests/data/innodb/make.sh .` runs `tests/data/innodb/mysql.sql` and shuts the server down cleanly: a file-per-table tablespace with dynamic rows, a secondary index, a deleted row and the SDI dictionary, and one with redundant rows and a 20,000-byte value in LOB pages; the SDI JSON was checked with Python's zlib and json modules, the decoded rows against the inserted values, the CRC-32C page checksums against every page. Not byte-reproducible (LSNs, transaction IDs, times). Stored with `gzip -9 -n` |
| `innodb/mysql-notes.ibd.gz` | MySQL 9.7.1 | the same script and table file as above |
| `innodb/mysql-4k.ibd.gz` | MySQL 9.7.1 | the same script, a second server started with `--innodb-page-size=4k` and `tests/data/innodb/mysql-4k.sql`: a 4 KiB-page tablespace with CHAR, ENUM, SET, DATE, DATETIME(3), FLOAT, DOUBLE and BIGINT columns, the decoded values checked against the inserted ones; `gzip -9 -n` |
| `innodb/mysql-ibdata1-head.gz` | MySQL 9.7.1 | same script: the first 16 pages (256 KiB) of the 12 MiB system tablespace and the first 8 pages (128 KiB) of a 16 MiB undo tablespace. **Truncated** to those prefixes; `gzip -9 -n` |
| `innodb/mysql-undo_001-head.gz` | MySQL 9.7.1 | the undo tablespace prefix of the row above (**truncated**) |
| `innodb/mariadb-fruit.ibd.gz` | MariaDB 10.5.29 (official `mariadb:10.5.29` image) | same script, `tests/data/innodb/mariadb.sql`: a dynamic-row tablespace with `full_crc32` checksums, and a `ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=4` one; `gzip -9 -n` |
| `innodb/mariadb-packed.ibd.gz` | MariaDB 10.5.29 | the compressed tablespace of the row above |
| `innodb/mysql-stock.ibd.gz` | MySQL 9.7.1 (official `mysql:9.7.1` image) | `sh tests/data/innodb/make-zip.sh .` runs `tests/data/innodb/zip.sql` and shuts the server down cleanly: a `ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=1` table of 40 rows (node pointer pages, a secondary index, deleted and updated rows, NULLs, two values stored off-page in compressed BLOB pages, the SDI in compressed SDI BLOB pages); records both in the compressed streams and in the modification logs. Every decoded row of both indexes was checked against the rows the script leaves. Not byte-reproducible (LSNs, transaction IDs, times). `gzip -9 -n` |
| `innodb/mariadb-stock.ibd.gz` | MariaDB 10.5.29 (official `mariadb:10.5.29` image) | the same script and `zip.sql` on MariaDB, checked the same way |
| `innodb/mysql-inst.ibd.gz` | MySQL 9.7.1 | the same script, `tests/data/innodb/instant.sql`: a table altered with `ALGORITHM=INSTANT` ADD COLUMN (at the end and after the first column) and DROP COLUMN, with rows inserted between the changes, so records carry row versions 0 to 3; the decoded rows were checked against the inserted ones. `gzip -9 -n` |
| `innodb-redo/mysql-ib_redo.gz` | MySQL 9.7.1 | same script: the redo file in use (`#innodb_redo/#ib_redoN`, 256 KiB with `--innodb-redo-log-capacity=8M`), format 6; `gzip -9 -n` |
| `innodb-redo/mariadb-ib_logfile0.gz` | MariaDB 10.5.29 | same script: `ib_logfile0` (`--innodb-log-file-size=2M`), format `PHYS`; `gzip -9 -n` |
| `innodb-redo/mariadb11-ib_logfile0.gz` | MariaDB 11.4.13 (official `mariadb:11.4.13` image) | `sh tests/data/innodb/make-redo108.sh .`: the 4 MiB `ib_logfile0` of a fresh server (10.8+ unframed `Phys` format) after `tests/data/innodb/redo.sql` and a clean shutdown; all 411 mini-transactions' CRC-32Cs match and the walk ends at the latest checkpoint's end LSN. Not byte-reproducible (LSNs, records). `gzip -9 -n` |
| `myisam-data/` | MySQL 9.7.1 and MariaDB 10.5.29 | same script: MyISAM data files of a dynamic-row table (`mysql-dynamic.MYD`), a fixed-row table with a deleted row (`mysql-fixed.MYD`) and a dynamic-row table where a longer row reused a deleted block and was split (`mariadb-split.MYD`) |
| `myisam-packed/` | MariaDB 11.4.13 (official `mariadb:11.4.13` image) and its `myisampack` | `sh tests/data/innodb/make-myisampack.sh .`: two MyISAM tables made by `tests/data/innodb/myisampack.sql`, copied out after a clean shutdown and compressed with `myisampack -f`: `crate.MYD` (CHAR, VARCHAR, ENUM, a constant column, NULLs, a DATE; a byte tree and a distinct-value tree) and `memo.MYD` (a TEXT column, so records carry a BLOB length). The trees fill the header exactly with the tables' column counts (8 and 3 with the null flags), the byte tree's codes are complete and prefix-free, and the first symbols of the records decode to the rows' null flags and IDs. Byte-reproducible: running the script again gives the same files |
| `pg-relation/` | PostgreSQL 17.9 (official `postgres:17.9` image) | `sh tests/data/postgres/make.sh .` (`initdb --data-checksums --wal-segsize=1`, `tests/data/postgres/shop.sql`, clean shutdown): a table's heap after an update and a delete, its free space and visibility maps after VACUUM, its primary key B-tree, the control file, and a WAL segment ending in a log switch. Page checksums checked against PostgreSQL's `page_checksum()` (pageinspect), the control file against `pg_controldata`, the records against `pg_waldump`. Not byte-reproducible (OIDs, LSNs, system identifier, times); the WAL segment is stored with `gzip -9 -n` |
| `pg-control/pg_control` | PostgreSQL 17.9 | the control file of the row above |
| `pg-control/pg_control-10` | PostgreSQL 10.21, 11.16 and 12.22 (official `postgres:10.21`, `postgres:11.16`, `postgres:12.22` images) | `sh tests/data/postgres/make-control-old.sh .`: the control files (versions 1002, 1100, 1201) of fresh clusters after a clean shutdown; every field `pg_controldata` of the same version prints was checked against the dissected values (38 or 39 per file). Not byte-reproducible (system identifier, times) |
| `pg-control/pg_control-11` | PostgreSQL 11.16 | the PostgreSQL 11 control file of the row above |
| `pg-control/pg_control-12` | PostgreSQL 12.22 | the PostgreSQL 12 control file of the row above |
| `pg-wal/00000001000000000000000D.gz` | PostgreSQL 17.9 | the WAL segment of the row above |
| `mssql-data/shop_extra.ndf.gz` | Microsoft SQL Server 2022 16.0.4295.3 Developer Edition (`mcr.microsoft.com/mssql/server:2022-latest`, linux/amd64) | `sh tests/data/mssql/make.sh .` runs `tests/data/mssql/shop.sql` and detaches the database: a secondary data file with a table's data and IAM pages. Page layouts and checksums checked against `DBCC PAGE`. Not byte-reproducible (GUIDs, LSNs, times); `gzip -9 -n` |
| `mssql-data/shop-head.mdf.gz` | the same | same script: the first 16 pages (128 KiB) of the 5 MiB primary data file (file header, allocation pages, boot page). **Truncated**; `gzip -9 -n` |
| `mssql-log/shop_log-head.ldf.gz` | the same | same script: the first 64 KiB of the 1 MiB transaction log (file header page, the first virtual log file's header and log blocks). **Truncated**; `gzip -9 -n` |
## GLib and OSTree (Alpine 3.22 in Docker)
| `gresource/demo.gresource` | glib-compile-resources (GLib 2.84.4, Alpine 3.22 `glib-dev`) | reproduced byte for byte by `sh tests/data/gvdb/make.sh OUTDIR` (`gresource.sh`): three files under `/org/example/demo`, one aliased to `ui/window.ui`, one `compressed="true"` (zlib) |
| `dconf/local` | dconf compile (dconf 0.40, Alpine 3.22 `dconf`) | same script (`dconf.sh`): a keyfile with boolean, integer, double, string, object path, array, tuple, maybe, dictionary, byte and int64 keys and one lock (the nested `.locks` table); reproduced byte for byte |
| `gvdb/gschemas.compiled` | glib-compile-schemas (GLib 2.84.4) | same script (`gschemas.sh`): one schema with an enum key, a ranged key and a summary; reproduced byte for byte |
| `ostree-commit/` | libostree 2025.2 (Alpine 3.22 `ostree`) | `sh tests/data/ostree/make.sh OUTDIR` (`ostree.sh`): an archive-mode repository holding two commits of a small tree with fixed times (`ostree commit --timestamp`, owner 0:0, no xattrs, metadata strings, a detached metadata string); its objects are copied out under short names (`demo.commit` for `<checksum>.commit`, ...). Objects reproduce byte for byte |
| `ostree-commitmeta/` | libostree 2025.2 | same script: the first commit's detached metadata |
| `ostree-dirtree/` | libostree 2025.2 | same script: the root tree (two directories) and `/etc` (a file and a symbolic link) |
| `ostree-dirmeta/` | libostree 2025.2 | same script: the metadata shared by every directory (0755, 0:0) |
| `ostree-filez/` | libostree 2025.2 | same script: a regular file (raw DEFLATE content) and a symbolic link |
| `ostree-summary/` | libostree 2025.2 | same script, `ostree summary -u`: one ref; records the time it was written |
| `ostree-delta/` | libostree 2025.2 | same script: the superblock of `ostree static-delta generate --empty --inline` (`inline.superblock`, its xz part inline in the metadata) and of the delta between the two commits (`superblock`); they record the time they were written |
| `ostree-delta-part/` | libostree 2025.2 | same script: part `0` of the delta between the commits (xz) |
| `flatpak/demo.flatpak` | flatpak 1.16.1 (Alpine 3.22 `flatpak`) | same script (`flatpak.sh`): `flatpak build-export` of a hand-made app directory (metadata keyfile, one shell script) with a fixed timestamp, then `flatpak build-bundle`; the superblock records the time it was written |
## Forensic images (libewf ewfacquire, pyaff4)
| `ewf2/fat-deflate.Ex01` | libewf-experimental 20260924 `ewfacquire` (built from the release tarball, sha256 checked) | `sh tests/data/ewf2/make.sh` (Docker `debian:trixie`, `--hostname fillyfoal`): `-f encase7-v2 -c deflate:best -b 16 -d sha1` of a 96 KiB FAT12 volume (`mkfs.fat`, one file, `mcopy`); device information, case data, sector data, sector table (zlib chunks and pattern fills), MD5 and SHA-1 sections; `ewfverify` succeeds. Not byte-reproducible (acquisition time in the case data) |
| `ewf2/fat-stored.Ex01` | same | same script, `-c none`: stored chunks with checksums and pattern fills |
| `ewf/fat-libewf.E01` | same | same script, `-f encase7` (EWF1: header2, header, volume, sectors, table, table2, data, hash, done) |
| `aff4/fat-zlib.aff4` | pyaff4 0.31 | `sh tests/data/aff4/run.sh` (Docker `debian:bookworm`, `--hostname fillyfoal`) runs `tests/data/aff4/gen.py`: an AFF4 1.0 volume with an `aff4:DiskImage` whose data stream is an `aff4:Map` over an `aff4:ImageStream` of zlib chunks (32 KiB, one bevy), of a 96 KiB FAT12 volume made the same way as above; read back with pyaff4 by `check.py`. Volume URNs are random |
| `aff4/fat-snappy-hole.aff4` | pyaff4 0.31 | same script: snappy chunks of 8 KiB, 4 per bevy (three bevies), and a map that leaves 16-32 KiB unmapped (pyaff4 reads it as zeros) |
| `aff4/logical.aff4` | pyaff4 0.31 | same script: an AFF4 1.1 logical container (`Container.createURN`, `writeLogical`) with a 21-byte file stored as a ZIP member and the 96 KiB volume as a snappy `aff4:ImageStream` (the resident-size threshold lowered to 4 KiB) |
## Disc navigation: DVD-Video (dvdauthor) and Blu-ray (tsMuxer)
| `dvd-ifo/dvdauthor-vmg.ifo` | dvdauthor 0.7.2 (Debian bookworm `dvdauthor`), FFmpeg 5.1 (`-target pal-dvd`) | reproduced byte-for-byte by `sh tests/data/dvd-ifo/make.sh` (Docker `debian:bookworm-slim`, `inside.sh`): `VIDEO_TS.IFO` of a PAL disc with a first-play PGC, a VMGM title menu PGC with commands, two titles in one title set, VTS attributes; checked against `lsdvd -x` and `dvdunauthor` (command mnemonics) |
| `dvd-ifo/dvdauthor-vts.ifo` | dvdauthor 0.7.2 | same script: `VTS_01_0.IFO`: chapter map, two title PGCs (two programs and three cells over two VOBs; one cell) with branching post commands, a VTSM language unit with root (still cell) and chapter menu PGCs, time maps, cell address tables and VOBU maps |
| `bdmv-index/` | tsMuxer git `c6b1186209e42c877052e762c9185f3226ef8ea2` (2025-04-21, Apache-2.0; built from source in Docker `debian:bookworm-slim`, not committed), FFmpeg 5.1 with x264/x265 | reproduced byte-for-byte by `sh tests/data/bdmv/make.sh` (`inside.sh`): `tsmuxer-*` are `index.bdmv`, `MovieObject.bdmv`, `PLAYLIST/00000.mpls` and `CLIPINF/00000.clpi` of a `--blu-ray` mux (H.264 1080p, AC-3, SRT rendered to PGS, two chapters); `tsmuxer-uhd-*` of a `--blu-ray-v3` mux (HEVC, AC-3; version 0300, UHD index extension, playlist static metadata extension). Checked against libbluray's `mobj_dump`, `mpls_dump` and `clpi_dump` (git `a24f4fad`, built with `-Denable_devtools=true`) |
| `bdmv-movieobject/` | tsMuxer as above | same script as `bdmv-index/` |
| `bdmv-playlist/` | tsMuxer as above | same script as `bdmv-index/` |
| `bdmv-clipinfo/` | tsMuxer as above | same script as `bdmv-index/` |
| `macho/shapes-arm64.dwarf` | Apple clang 21.0.0 + ld + dsymutil (Apple LLVM 21.0.0) | reproduced byte-for-byte by `sh tests/data/macho/build-dsym.sh <repo>` from `tests/data/dwarf/shapes.c` and `shapes.h` (built in `/tmp/fixtures/dwarf-macho` with prefix maps to `/src`, `-oso_prefix`, `ZERO_AR_DATE=1`): the DWARF companion file (`MH_DSYM`) from inside `shapes.dSYM`, an arm64 `-g -O1` executable's DWARF 4 in the `__DWARF` segment; checked with `llvm-dwarfdump --verify` and against `llvm-dwarfdump --debug-info` |
| `coff/shapes-mingw-x64.o` | Debian trixie mingw-w64 GCC 14 (`14-win32`, Docker `debian:trixie`, `gcc-mingw-w64-x86-64`) | reproduced byte-for-byte by `sh tests/data/coff/make-dwarf.sh <repo>` from `tests/data/dwarf/shapes.c` (`x86_64-w64-mingw32-gcc -g -O1 -c` with prefix maps, built in the container's `/build/dwarf`): x64 object with DWARF 5 `.debug_*` sections (long names in the string table) and their SECREL/ADDR64 relocations, `.debug_frame`; checked with `llvm-dwarfdump --verify` and against `llvm-dwarfdump --debug-info` |
| `coff/shapes-clang-arm64.o` | Debian clang 19.1.7 (Docker, Debian trixie `clang llvm` packages) | same script: `clang --target=aarch64-w64-windows-gnu -g -O1 -c`; ARM64 object with DWARF 4 and relocations against section symbols and against `shape_counter` (value 4); checked as above |

## Windows VM fixtures: ETW logs

Written on a Windows 11 Pro 25H2 ARM64 VM (build 10.0.26200.9457, local
account `fillyfoal`, computer `FILLYFOAL-VM`, time zone UTC); see
`tests/data/windows/etl/` (`gen_etl.ps1` and `gen_kernel_procthread.ps1`,
run elevated through `elevate.ps1`; the helper programs `fillyfoal_tlg.c`,
`ff_comp.c` and `ff_klog.c` built by `build_tlg.cmd` with MSVC cl 19.51
for ARM64). Each file was decoded by `tracerpt` 10.0.26100.1 and our event
counts per provider, group and opcode match its summary. The files are
unchanged (the larger ones stored as `.raw.zst`); not byte-for-byte
reproducible (times, process IDs, whatever ran on the machine).

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `etl/kernel-process-manifest.etl.raw.zst` | Windows ETW, logman.exe 10.0.26100.1 | `logman start ff-kproc -p Microsoft-Windows-Kernel-Process 0x10 0x4 -bs 16 -nb 2 8 -ets`, two `cmd /c echo`, stop: 9 buffers of 16 KiB, manifest events ProcessStart (id 1, v4) ×25 and ProcessStop (id 2, v2) ×21, header and PartitionInfoExtensionV2; LogFileMode 0. tracerpt: 48 events |
| `etl/tracelogging-fillyfoal.etl.raw.zst` | Windows ETW, logman.exe; events from `fillyfoal_tlg.exe` (TraceLoggingProvider.h, Windows SDK 10.0.26100) | `logman start ff-tlg -p {a946bbbd-88e8-5895-7beb-4d343c1d945f} 0xFFFFFFFFFFFFFFFF 0x5 ...`: 3 × 3 TraceLogging events of provider `fillyfoal-test` (scalars incl. BOOLEAN and HEX out-types, ANSI/UTF-16/counted strings, GUID, FILETIME, SYSTEMTIME, binary, constant- and variable-count INT32 arrays, a nested struct). tracerpt: 11 events; every value checked against `fillyfoal_tlg.c` |
| `etl/tracelogging-fillyfoal-xperf-compressed.etl` | xperf.exe 10.0.26100.8249 (Windows Performance Toolkit) | `xperf -merge tracelogging-fillyfoal.etl <out> -mergeonly -compress`: LogFileMode 0x04010001 (COMPRESSED, RELOG, SEQUENTIAL); a 1 KiB uncompressed first buffer, then 3 Xpress-compressed buffers. tracerpt: 12 events |
| `etl/compressed-session-kproc-tlg.etl.raw.zst` | Windows ETW session started by `ff_comp.exe` (StartTrace with EVENT_TRACE_COMPRESSED_MODE) | `ff_comp.exe <out> fillyfoal_tlg.exe`: 64 KiB buffers compressed by the live session (LogFileMode 0x04000001), Kernel-Process and fillyfoal-test events. tracerpt: 9 buffers, 41 events |
| `etl/kernel-logger-procthread-raw.etl.raw.zst` | NT Kernel Logger, controlled by `ff_klog.exe` | `ff_klog.exe kernel <out> 10000003 500` (PROCESS \| THREAD \| NO_SYSCONFIG, 8 KiB buffers, 0.5 s): MOF Process (v4 rundown of 187 processes, Start/End/Terminate, v5 Defunct) and Thread (v3, SetName) events with compact and perfinfo headers. tracerpt: 103 buffers, 5064 events. Every command line was reviewed by hand (only Windows, Program Files and `C:\Users\fillyfoal` paths) |
| `etl/kernel-logger-thread-merged.etl.raw.zst` | xperf.exe 10.0.26100.8249 | `xperf -merge kernel-logger-thread-raw.etl <out> -suppresspii` of a thread-only kernel log (`ff_klog.exe kernel <raw> 10000002 500`): the thread events plus xperf's own FULL_HEADER64 events (provider {9b79ee91-b5fd-41c0-a243-4248e266e9d0}, opcodes 32-37), LogFileMode 0x00010001; the relogged header buffer records its end in `Offset`, not `SavedOffset`. tracerpt: 117 buffers, 6976 events |

## Windows VM fixtures: kernel crash dump

Written on the same Windows 11 Pro 25H2 ARM64 VM (build 10.0.26200.9457);
see `tests/data/windows/kernel-dump/` (`setup.ps1` arms a SYSTEM startup
task, `crashloop.ps1` crashes with Sysinternals NotMyFault and collects the
dump; run elevated through `elevate.ps1`). Unchanged, stored as `.raw.zst`;
not reproducible (a crash).

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `windows-kernel-dump/minidump-small-memory-dump.dmp.raw.zst` | Windows kernel crash dump writer (CrashDumpEnabled=3, small memory dump), crash by NotMyFault v4.60 (`notmyfaultc64a.exe /crash 0x01`, `myfault.sys`, no user logged on) | `C:\Windows\Minidump\101226-6203-01.dmp`, renamed: `PAGEDU64` header, DumpType 4 (triage), bug check 0xD1, then `TRIAGE_DUMP64` (context, PRCB, process, thread, call stack, 188 drivers with a string pool, 6 unloaded drivers, KDDEBUGGER_DATA64, 61 data blocks, the `TRGD` marker) and, past SizeOfDump, the `DumpBlob` secondary data (17 blobs). Every header and `TRIAGE_DUMP64` field checked against WinDbg 10.0.29661.1004 `kd -z <dump> -c ".dumpdebug; vertarget"` |

## Windows VM fixtures: shell links and jump lists

Written on the same Windows 11 Pro 25H2 ARM64 VM (build 10.0.26200.9457;
explorer.exe 10.0.26100.8117, windows.storage.dll 10.0.26100.9278,
wshom.ocx 10.0.26100.4768) to `C:\fillyfoal\note.txt` and the folder
`C:\fillyfoal\notes\`; see `tests/data/windows/lnk/jumplist.ps1`. The links
carry the VM's volume serial and a TrackerDataBlock (machine `fillyfoal-vm`,
droids embedding the VM's virtual NIC MAC). Unchanged; not reproducible
(times, object IDs).

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `lnk/explorer-file-note.txt.lnk` | Windows Explorer shell ("Create shortcut" verb) | `(New-Object -ComObject Shell.Application).Namespace('C:\fillyfoal').ParseName('note.txt').InvokeVerb('link')`, renamed: ID list with 0xBEEF0004 blocks (v9, 8.3 name `FILLYF~2`), LinkInfo, relative path, working dir, TrackerDataBlock, PropertyStoreDataBlock (4 storages) |
| `lnk/explorer-folder-notes.lnk` | Windows Explorer shell | the same verb on the folder `C:\fillyfoal\notes`: a directory target |
| `lnk/wscript-file-note.txt.lnk` | Windows Script Host `WScript.Shell` (wshom.ocx), from Windows PowerShell 5.1 | `CreateShortcut(...)`, TargetPath `C:\fillyfoal\note.txt`, WorkingDirectory `C:\fillyfoal`, Description `fillyfoal test`, `Save()`: NAME_STRING, one property storage |
| `lnk/recent-note.lnk` | Windows shell recent-documents tracking (`SHAddToRecentDocs`) | written by Windows into `%APPDATA%\Microsoft\Windows\Recent\note.lnk` by `jumplist.ps1`; a relative path climbing out of the profile |
| `custom-destinations/6b16a059c2e70543.customDestinations-ms` | Windows `ICustomDestinationList` (windows.storage.dll) | `jumplist.ps1` with AppUserModelID `fillyfoal.test`: custom category "fillyfoal" (2 links with PKEY_Title), user tasks (1 link), known category Recent, 0xBABFFBAB footers |
| `cfb/a61657a5e5dfbdc.automaticDestinations-ms` | Windows 11 jump-list machinery for Notepad 11.2607.14.0 | `Start-Process C:\fillyfoal\note.txt`, then `C:\fillyfoal\notes\readme.txt`, Notepad closed; copied from `AutomaticDestinations\`: compound file with a version 6 `DestList` (2 entries), link streams `1` and `2` (with a 0xBEEF001A ProgID extension block) and an empty `DestListPropertyStore` |

## Windows VM fixtures: NTFS volumes

Written on the same Windows 11 Pro 25H2 ARM64 VM (build 10.0.26200.9457) by
`tests/data/windows/ntfs/build.ps1` (run elevated through `elevate.ps1`):
DiskPart 10.0.26100.1 creates a 16 MiB fixed VHD (`diskpart-create.txt`:
MBR, one primary partition at LBA 128, `format fs=ntfs quick
label=FILLYFOAL`: NTFS 3.1, 4 KiB clusters, 1 KiB records), the script
populates it with PowerShell, `compact.exe` and `fsutil.exe`, and
`diskpart-detach.txt` detaches it; `mftdump.py` checked each detached image
(output in the rows below). Unchanged, stored as `.raw.zst`; not
reproducible (times, serial numbers, the VHD's random UUID).

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `vhd/ntfs-attrlist.vhd.raw.zst` | Windows NTFS driver (DiskPart, PowerShell) | `$ATTRIBUTE_LIST` four ways: `attrlist-resident.txt` (6 named streams, resident list of 9 entries over records 38-39), `attrlist-nonresident.txt` (60 streams, non-resident list of 63 entries over records 40-54), `attrlist-resident-hardlinks\target.txt` (7 names over records 56-61) and `attrlist-nonresident-hardlinks\target.txt` (11 names over records 63-70); every stream, name and record matches `mftdump.py` and `fsutil file layout` |
| `vhd/ntfs-wof.vhd.raw.zst` | Windows NTFS driver, `compact.exe` (wof.sys) | `compact /c /exe:xpress4k`, `xpress8k`, `xpress16k`, `lzx` on four 320 KiB text files (sparse unnamed `$DATA`, `WofCompressedData` stream, `IO_REPARSE_TAG_WOF` reparse point, algorithms 0/2/3/1) and an uncompressed control file; every decompressed file matches the text `build.ps1` wrote, line for line |
| `vhd/ntfs-lznt1.vhd.raw.zst` | Windows NTFS driver, `compact.exe` | `compact /c` on a 320 KiB file and on a directory before a file was written into it (inherited compression): LZNT1, compression unit 2^4 clusters; both decompressed files match the text `build.ps1` wrote |
## Windows-only writers: MSVC, signtool, Inno Setup, OpenMPT
account and computer named for fillyfoal, time zone UTC); see
`tests/data/windows/<item>/` for the scripts, kept as they ran. The files
are unchanged apart from storage (`.raw.zst`); not byte-for-byte
reproducible (link times, GUIDs, signing and timestamp times).
| `pe/fixture_hello_x64_signed.exe` | MSVC cl 19.51.36243 (x64 cross, VS Build Tools 2026) + link 14.51.36243.0; signtool 4.00 (Windows SDK 10.0.26100) | `tests/data/windows/pe/build_x64.cmd` (`cl /c /Zi /O1 /MD`, `link /DEBUG:FULL /INCREMENTAL:NO`), then `sign.ps1`: a throwaway self-signed RSA-2048 code-signing certificate `CN=fillyfoal test, O=fillyfoal` (deleted with its key afterwards), `signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 /d "fillyfoal test"`. Rich header, debug directory (RSDS, VC_FEATURE, POGO), 0x140-byte load config, Authenticode with an RFC 3161 DigiCert timestamp. Checked against `dumpbin /headers` (certificate directory at 0x3400, 0x1D50 bytes; RSDS `{D5E0DF05-…}`); the image digest our dissector recomputes matches the signed SHA-256 |
| `pe/fixture_lib.dll` | MSVC cl + link 14.51.36243.0 (x64) | `build_x64.cmd` step 5: `/DLL /DEF:fixture_lib.def ... delayimp.lib /DELAYLOAD:version.dll`; exports with ordinal base 1 (named, DATA, a forwarder to `kernel32.GetTickCount`, a NONAME ordinal), a delay-load import of VERSION.dll. Checked against `dumpbin /exports` (export TimeDateStamp 0xFFFFFFFF as this linker writes it) |
| `pe/fixture_use.exe` | MSVC cl + link 14.51.36243.0 (x64) | `build_x64.cmd` step 5: imports ordinals 1, 3 and 7 from `fixture_lib.dll` through its import library |
| `pe/fixture_hello_arm64.exe` | MSVC cl 19.51.36243 for ARM64 + link 14.51.36243.0 (VS Community 2026) | `build_arm64.cmd` step 1a: native ARM64 image with `.xdata` unwind records and packed unwind data |
| `pe/fixture_hello_arm64ec.exe` | MSVC cl 19.51.36243 for ARM64 `/arm64EC` + link 14.51.36243.0 | `build_arm64.cmd` step 4a: machine 0x8664 with ARM64EC metadata (2 code ranges, entry-point ranges, redirection metadata, the ARM64 function table) as `dumpbin /loadconfig` shows |
| `pe/fixture_lib_arm64x.dll` | MSVC cl 19.51.36243 for ARM64 (with and without `/arm64EC`) + link 14.51.36243.0 `/MACHINE:ARM64X` | `build_arm64.cmd` step 4b: ARM64X hybrid DLL; its dynamic value relocation table (ARM64X fixups switching Machine, the entry point and the export, exception and load config directories to the ARM64EC view), 3 code ranges, 6 entry-point ranges and redirections, x64 function table, as `dumpbin /loadconfig` shows |
| `pdb/fixture_hello_x64.pdb.raw.zst` | link 14.51.36243.0 `/DEBUG:FULL` | the PDB of `pe/fixture_hello_x64_signed.exe` (same RSDS GUID and age); stored with `zstd -19` |
| `pdb/fixture_hello_x64_fastlink.pdb.raw.zst` | link 14.44.35227.0 `/DEBUG:FASTLINK` (VS 2022 v143 toolset 14.44.35207 added to Build Tools 2026; link 14.51 no longer supports FASTLINK) | `build_fastlink.cmd`: a FASTLINK PDB (feature "minimal debug info", no type records, `S_FASTLINK` stand-ins in the module streams, which name the object by absolute path); stored with `zstd -19` |
| `pdb/fixture_hello_fastlink_cc.pdb.raw.zst` | cl 19.44.35227 `/Zi` (mspdbsrv) | the compiler PDB `build_fastlink.cmd` kept: TPI and IPI only, the type server `coff/fixture_hello_fastlink.obj` names (GUID `{5FD1A816-…}`); stored with `zstd -19` |
| `coff/fixture_hello_fastlink.obj` | cl 19.44.35227 (x64) `/c /Zi /O1 /MD` | `build_fastlink.cmd`: `.debug$S` C13 CodeView (symbols, file checksums, lines, string table) and `.debug$T` holding one `LF_TYPESERVER2` that names `fixture_hello_fastlink_cc.pdb` |
| `x509/fixture_codesign.cer` | New-SelfSignedCertificate / Export-Certificate (PowerShell 5.1) | `sign.ps1`: the public certificate that signed `pe/fixture_hello_x64_signed.exe` |
| `pe/inno-setup-6.3.3.exe` | Inno Setup 6.3.3 ISCC (official signed release from jrsoftware/issrc on GitHub, installed portable) | `tests/data/windows/installers/build.ps1` compiles `fillyfoal-test.iss` (two text files, one HKCU registry value, a `[Code]` InitializeSetup, LZMA2 solid, PrivilegesRequired=lowest, WizardStyle=modern, unsigned): data version 6.3.0, the 75-byte file locations with a Sign byte, architectures as header strings. Checked against `Shared.Struct.pas` at tag `is-6_3_3`; both files' SHA-1s in the location entries match their decompressed content |
| `pe/inno-setup-6.4.3.exe` | Inno Setup 6.4.3 ISCC (as above) | same script: data version 6.4.3, SHA-256 file hashes, XChaCha20/PBKDF2 encryption fields in the setup header. Checked against `is-6_4_3`; SHA-256s match |
| `pe/inno-setup-6.5.4.exe` | Inno Setup 6.5.4 ISCC (as above) | same script: data version 6.5.2, loader table version 2 (64-bit offsets, its CRC checked), the CRC-protected encryption header before the blocks, ISSig key count, 16-string file entries with TSetupFileVerification, 64-bit chunk offsets. Checked against `is-6_5_4` |
| `pe/inno-setup-6.6.1.exe` | Inno Setup 6.6.1 ISCC (as above) | same script: data version 6.6.1, dark-style wizard settings and the four-font language entry. Checked against `is-6_6_1` |
| `pe/inno-setup-6.7.3.exe` | Inno Setup 6.7.3 ISCC (as above) | same script: data version 6.7.0, 64-bit block sizes, UsePrevious* header strings, 8-byte option sets. Checked against `is-6_7_3` |
| `pe/inno-setup-7.1.0.exe` | Inno Setup 7.1.0 ISCC (`innosetup-7.1.0-x64.exe` release, as above) | same script: data version 7.0.0.3 (also written by 7.0.2, whose installer has the same layout and was left out), CompiledCodeVersion 7.1.0.0, file entry Bitness. Checked against `is-7_1_0`; SHA-256s match |
| `it/fillyfoal-compressed.it` | OpenMPT 1.32.11.00 (portable ARM64 build, Windows 11) | `tests/data/windows/tracker/run_all.ps1`: `make_seed_it.py` writes a seed module (2 channels, one 32-row pattern, an 8-bit and a 16-bit looped synthetic sample, 256 frames each), OpenMPT opens it, the artist is set to `fillyfoal` and File > Save As writes it with `[Misc] ITCompressionMono=7`: IT 2.14 compressed samples (Cvt 0x01) and OpenMPT's STPM song extensions (artist, channel colours, last-saved version 1.32.11.00). Our IT 2.14 decompressor reproduces `fillyfoal-uncompressed.it`'s PCM exactly |
| `it/fillyfoal-compat-compressed.it` | OpenMPT 1.32.11.00 (as above) | same, File > Compatibility Export: no OpenMPT extensions, reserved field 0x1100 |
| `it/fillyfoal-uncompressed.it` | OpenMPT 1.32.11.00 (as above) | same song saved with `ITCompressionMono=0`: plain signed PCM |
| `it/fillyfoal-compat-uncompressed.it` | OpenMPT 1.32.11.00 (as above) | Compatibility Export of the uncompressed song |
| `it/fillyfoal.mptm` | OpenMPT 1.32.11.00 (as above) | the compressed song converted to MPTM (Song Properties) and saved as `.mptm`: "Created with" 0x891, "Compatible with" 0x888, IT 2.15 compressed samples (Cvt 0x05; they also decompress to the uncompressed file's PCM), STPM extensions, then the MPTM data in OpenMPT's serialization (sequences) |

## Linux VM fixtures: ZFS pools, md RAID members, dynamic partitions

Written on a disposable Ubuntu 26.04.1 LTS aarch64 VM (kernel
7.0.0-38-generic; host name `fillyfoal`, TZ=UTC) by the scripts in
`tests/data/zfs/`, `tests/data/mdraid/` and `tests/data/android-super/`,
kept as they ran; the reference tools' output for every committed file is
in `reference.txt` next to each script. Members of each pool or array not
committed are near-duplicates of the committed one. Unchanged apart from
storage (`.raw.zst`).

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `zfs/tank.img.raw.zst` | OpenZFS 2.4.1 (zfsutils-linux 2.4.1-1ubuntu5.1, kernel module 2.4.1) | `make-zfs.sh`: `zpool create -o ashift=9` on a 64 MiB file, `compression=lz4` and `compression=zstd` datasets with small files, a snapshot, a 4 MiB zvol, `zpool export`; label configuration, the four labels and the uberblock ring checked against `zdb -l` and `zdb -uuu` (root block pointer identical to zdb's). Not reproducible (GUIDs, times) |
| `zfs/mirror-a.img.raw.zst` | OpenZFS 2.4.1 (as above) | same script: first member of a two-way mirror pool `mpool` (ashift 9), exported; `zdb -l` |
| `zfs/raidz-a.img.raw.zst` | OpenZFS 2.4.1 (as above) | same script: first member of a three-file raidz1 pool `rz` with `ashift=12` (4 KiB uberblock slots), exported; `zdb -l`, `zdb -uuu` |
| `mdraid/r1-v090-a.img.raw.zst` | mdadm 4.5 (Ubuntu 4.5-5ubuntu1.1), Linux md, e2fsprogs 1.47.2 | `make-mdraid.sh`: `mdadm --create --metadata=0.90 --level=1` over two 8 MiB loop devices, `mke2fs -t ext4 -d` on the array, `mdadm --stop`; first member; `mdadm --examine` (checksum, events, disk table). Not reproducible (times, device UUIDs) |
| `mdraid/r1-v10-a.img.raw.zst` | as above | same script, `--metadata=1.0` (superblock 8 KiB before the end, component size smaller than the data area) |
| `mdraid/r1-v11-a.img.raw.zst` | as above | same script, `--metadata=1.1` (superblock at 0) |
| `mdraid/r1-v12-a.img.raw.zst` | as above | same script, `--metadata=1.2` (superblock at 4 KiB) |
| `mdraid/r5-a.img.raw.zst` | as above | same script: first member of a three-disk RAID5, metadata 1.2, left-symmetric, 512 KiB chunks |
| `android-super/super-avb.img.raw.zst` | AOSP lpmake (system/extras `partition_tools` fc2494a2abd7ab21774d03deb09c1362bbb0bba8, system/core `fs_mgr/liblp` a3b721a32242006b59cb12bd62c9133632af3a2d, built by `build-lptools.sh` against Ubuntu's android-libbase 34.0.5), AOSP avbtool 1.4.0 (platform/external/avb c5066a96caa7bf4150c0a8cc8cc14ab81733fdc7, MIT; fetched into /tmp, not committed), OpenSSL 3.5.5 | `make-super.sh`: a 4 MiB super device with two 8 KiB metadata slots, group `main` with `system` (48 KiB of filler with an AVB hashtree footer, no FEC, in 128 KiB) and `vendor` (48 KiB of filler with an AVB hash footer in 128 KiB), then `avbtool add_hash_footer` over the whole image in a 5 MiB partition `super`, signed SHA256_RSA2048 with a throwaway key; checked against `lpdump` and `avbtool info_image`. The key is new per run, so key and signature bytes differ between runs |
| `android-super/super-ab.img.raw.zst` | AOSP lpmake (as above) | same script: three metadata slots, groups `main_a`/`main_b`, `system_a`/`vendor_a` with the images above and empty `system_b`/`vendor_b`; no footer; reproduced byte-for-byte; checked against `lpdump` |
