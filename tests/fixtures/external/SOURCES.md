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
  `gzip -n` for storage (the harness inflates it) is not an edit.
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
| `xz/bottles.txt.xz` | XZ Utils 5.8 | reproduced byte-for-byte: `xz -6` |
| `xz/large-member.tar.xz` | XZ Utils 5.8 | reproduced byte-for-byte: `xz -9`; commit f0d9d8d1 ("fixtures from xz and zstd CLIs"); the tarball inside is the bsdtar ustar archive of gzip/large-member.tar.gz |
| `lzma/bottles.txt.lzma` | XZ Utils 5.8 | reproduced byte-for-byte: `xz --format=lzma -6` |
| `zstd/bottles.txt.zst` | zstd 1.5.7 CLI | reproduced byte-for-byte: `zstd -13 FILE` (content size recorded) |
| `zstd/large-member.tar.zst` | zstd 1.5.7 CLI | reproduced byte-for-byte: `zstd -19 FILE`; commit f0d9d8d1 |
| `lz4/bottles.txt.lz4` | lz4 1.10 CLI | reproduced byte-for-byte: `lz4 -9 -BX --content-size FILE` |
| `lz4/uncompressed-block.lz4` | lz4 1.10 CLI | reproduced byte-for-byte: `lz4 -1 --no-frame-crc FILE` |
| `lz4-legacy/legacy.lz4` | lz4 1.10 CLI | reproduced byte-for-byte: `lz4 -l -1` |
| `brotli/page.html.br` | brotli 1.2 CLI | reproduced byte-for-byte: `brotli -q 10 -w 10` (commit 0b9b5a01: "verified against the brotli CLI") |
| `compress/bottles.txt.Z` | macOS compress(1) | reproduced byte-for-byte: `compress -c` |
| `zip/zip64-stdin.zip` | Info-ZIP Zip 3.0 (macOS `/usr/bin/zip`) | `printf 'hello zip64\n' \| zip -q zip64-stdin.zip -`: reading stdin, Info-ZIP writes ZIP64 end records and a ZIP64 extra field |
| `gzip/png.gz` | macOS gzip | deflate body reproduced byte-for-byte with `gzip -6`; header keeps FNAME `c.png` and its MTIME. The PNG inside is hand-made (synthetic) |
| `gzip/large-member.tar.gz` | macOS gzip + bsdtar 3.5.3 (libarchive 3.7.4) | reproduced byte-for-byte: `gzip -9 -n` of a bsdtar ustar archive (a.txt, a 2 MiB zeros.bin, z.txt) |
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
| `7z/` | 7-Zip (7zz) for macOS | all ten: lzma-solid-plain, bzip2-solid, lzma2-arm64, delta-lzma2, lzma-arm and lzma-bcj-x86 reproduced byte-for-byte with 7zz 26.03 (`-m0=...` methods as named, `-mhc=off` for plain headers); the other four match in size and layout |
| `zip/mixed.zip` | Info-ZIP Zip 3.0 (macOS /usr/bin/zip) | version made by 3.0/Unix, UT and ux extra fields, archive comment (`zip -z`). The entries (PNG, tar.gz, text) are hand-made |
| `zip/zipcrypto.zip` | Info-ZIP Zip 3.0 (macOS /usr/bin/zip) | `zip -e` (ZipCrypto), version made by 3.0/Unix, UT and ux extra fields; password `fillyfoal` |
| `zip/winzip-aes.zip` | bsdtar (libarchive) zip writer | `--options zip:encryption=aes...`; layout (version made by 2.0/Unix, ux before the AES extra, data descriptors) matches a fresh bsdtar run; password `fillyfoal` |
| `zip/encrypted-lzma-bzip2.zip` | 7-Zip (7zz) | two `7zz a -tzip` runs (AES-256 + BZip2, ZipCrypto + LZMA); NTFS extra fields and versions 51/63 as 7-Zip writes them; password `fillyfoal` |
| `xar/files.xar` | macOS xar(1) | TOC has real inode/device numbers and a `com.apple.provenance` extended attribute |
| `pbzx/pbz4.aar` | macOS aa (Apple Archive) | `aa archive` with LZ4 compression; entries carry `com.apple.provenance` xattrs |
| `pbzx/pbze.aar` | macOS aa (Apple Archive) | `aa archive` with LZFSE compression; entries carry `com.apple.provenance` xattrs |
| `pbzx/pbzz.aar` | macOS aa (Apple Archive) | `aa archive` with zlib compression |

## Disk images (macOS)

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `dmg/fat-udco.dmg` | macOS hdiutil | commit 1aeb76a1 ("fixtures from hdiutil"); ADC (UDCO) chunks |
| `dmg/fat-ulfo.dmg` | macOS hdiutil | commit 1aeb76a1 ("fixtures from hdiutil"); LZFSE (ULFO) chunks |
| `dmg/fat-udzo.dmg` | macOS hdiutil | hdiutil resource-fork plist (`whole disk (DOS_FAT_16 : 0)` blkx names, mish tables) |
| `dmg/hfs-udbz.dmg` | macOS hdiutil | hdiutil resource-fork plist (`whole disk (Apple_HFS : 0)`), bzip2 chunks |
| `dmg/fat-ulmo.dmg` | macOS hdiutil | hdiutil resource-fork plist (`Master Boot Record (MBR : 0)` ...), LZMA (ULMO) chunks |
| `apfs/apfs.img.gz` | macOS newfs_apfs 2811.120.14.0.1 | formatter string in the superblock; populated on a mounted volume. Stored with `gzip -n` (the harness inflates it) |
| `exfat/exfat.img.gz` | macOS newfs_exfat | populated on a mounted volume (AppleDouble `._` files with `com.apple.provenance`). Stored with `gzip -n` |
| `hfsplus/hfsplus.img.gz` | macOS (newfs_hfs/hdiutil, inferred) | last-mounted version `10.0` (macOS); not byte-reproduced. Stored with `gzip -n` |
| `swap/mkswap.img` | util-linux mkswap | commit 3dc63ea4 ("a real mkswap fixture"); label `realswap`, UUID chosen with `-U` |

## Compilers, linkers and toolchains

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `elf/aarch64-debug.o` | Apple clang 21.0.0 | `.comment` and DWARF producer; built from target/fx/elf/obj.c |
| `elf/armeb.o` | Apple clang 21.0.0 | `.comment`; big-endian ARM target |
| `elf/i386-static` | Homebrew clang + LLD 20.1.8 | `.comment` names both; the Go build-id and SystemTap notes come from inline assembly in the source |
| `elf/ppc64.o` | Homebrew clang 20.1.8 | `.comment` |
| `elf/x86_64-pie` | Homebrew clang + LLD 20.1.8 | `.comment` names both |
| `macho/hello-arm64.o` | clang (Apple) | LLVM integrated-assembler output (`ltmp` symbols, `__compact_unwind`) |
| `macho/hello-x86_64` | clang + ld64 + codesign (Apple) | linked executable with stubs, dyld info and an entitlements code signature |
| `macho-fat/libfilly-fat.dylib` | clang + lipo (Apple) | two linked dylib slices |
| `coff/` | Homebrew clang 22.1.8 | all four objects (`Homebrew clang version 22.1.8` producer string) |
| `coff-import/` | LLVM llvm-dlltool / llvm-lib | the three short import records are members of ar/filly-import.lib, extracted unchanged |
| `ar/filly-import.lib` | LLVM llvm-dlltool / llvm-lib (20-22) | reproduced byte-for-byte from a three-line .def file (`fillyfoal_answer`, `fillyfoal_data DATA`, `fillyfoal_ordinal @7 NONAME`) |
| `ar/libbsd.a` | macOS ar/libtool (cctools) | reproduced byte-for-byte from its own members with `ZERO_AR_DATE=1 ar rcs` / `libtool -static`; members are clang objects |
| `xcoff/` | Homebrew LLVM 22.1.8 | both objects (`Homebrew LLVM version 22.1.8` producer string) |
| `llvm-bitcode/apple.bc` | Apple clang 21.0.0 | IDENTIFICATION block / producer string |
| `llvm-bitcode/linux.bc` | Homebrew clang 22.1.8 | IDENTIFICATION block / producer string |
| `win-res/llvm-rc.res` | Homebrew llvm-rc 22.1.8 | `llvm-rc -no-preprocess -fo llvm-rc.res app.rc`; the script covers icons (a DIB and a PNG image), a cursor, a bitmap, a manifest, RCDATA (a synthetic Delphi form, the same bytes as synthetic/delphi-dfm/form.dfm, and inline data), string tables in two languages, accelerators, version info, a menu, a DIALOGEX and a custom-typed resource; the image files it includes were written by our generator |
| `lua/fib-5.5.luac` | luac 5.5 | chunk name `@target/fx/lua/fib.lua`; `luac -l` lists it |
| `pyc/filly.cpython-39.pyc` | CPython 3.9 (py_compile) | bytecode of the matching interpreter version |
| `pyc/filly.cpython-311.pyc` | CPython 3.11 (py_compile) | bytecode of the matching interpreter version |
| `pyc/filly.cpython-314.pyc` | CPython 3.14 (py_compile) | bytecode of the matching interpreter version |
| `pyc/filly-hash.cpython-314.pyc` | CPython 3.14 (py_compile, checked hash-based) | bytecode of the matching interpreter version |
| `mo/de.mo` | GNU gettext msgfmt | reproduced byte-for-byte: `msgunfmt de.mo \| msgfmt -` |
| `terminfo/fillyfoal-term` | ncurses tic 6.0 (macOS) | reproduced byte-for-byte: `infocmp -x \| tic -x`; the terminal description itself is ours |

## Python standard library

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `pickle/protocol2.pkl` | CPython pickle | reproduced byte-for-byte: `pickle.dumps(pickle.loads(data), protocol=2)` |
| `pickle/protocol5.pkl` | CPython pickle | reproduced byte-for-byte: `pickle.dumps(pickle.loads(data), protocol=5)` |
| `bplist/keyed-archive.plist` | CPython plistlib | reproduced byte-for-byte: `plistlib.dumps(plistlib.loads(data), fmt=FMT_BINARY)`; the NSKeyedArchiver structure inside was assembled by hand |
| `eml/charsets.eml` | CPython email package | `email.mime` generator output (`===============N==` boundaries, header order); the encoded words in the headers were chosen by us |

## Libraries

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `sqlite/autovacuum.sqlite` | SQLite 3.51.0 | header records SQLite version 3051000 |
| `sqlite/shop.sqlite` | SQLite 3.51.0 | header records SQLite version 3051000 |
| `sqlite-wal/t.db-wal` | SQLite 3.51 | WAL of a `t.db` written by the same library |
| `sqlite-journal/t.db-journal` | SQLite 3.51 | rollback journal of the same `t.db` |
| `gpkg/geo.gpkg` | SQLite 3.51.0 | header records SQLite version 3051000; GeoPackage tables created with SQL by us |
| `mbtiles/tiles.mbtiles` | SQLite 3.51.0 | header records SQLite version 3051000; MBTiles tables created with SQL by us |
| `bgcode/` | libbgcode (pybgcode built from prusa3d/libbgcode commit d4da907) | reproduced byte-for-byte by `tests/data/bgcode/make_bgcode.py`: `from_ascii_to_binary` of our PrusaSlicer-style `synthetic/gcode/prusaslicer.gcode` (thumbnails made with Pillow 12.3), one file per compression (none, zlib, Heatshrink 11/4 and 12/4), G-code encoding (none, MeatPack, MeatPack with comments) and checksum type (none, CRC-32) |
| `orc/lz4.orc` | pyarrow 25 (Apache ORC C++ 2.2.2) | reproduced byte-for-byte by re-writing the table with `pyarrow.orc.write_table(compression="lz4")` |
| `orc/snappy.orc` | pyarrow 25 (Apache ORC C++ 2.2.2) | reproduced byte-for-byte (`compression="snappy"`) |
| `orc/zstd.orc` | pyarrow 25 (Apache ORC C++ 2.2.2) | reproduced byte-for-byte (`compression="zstd"`) |
| `rocksdb-sst/bzip2.sst` | RocksDB via rocksdict | edit: db/host/session identity properties overwritten with `x`; RocksDB still ingests the file |
| `rocksdb-sst/lz4.sst` | RocksDB via rocksdict | edit: identity properties overwritten with `x`; RocksDB still ingests the file |
| `rocksdb-sst/snappy.sst` | RocksDB via rocksdict | edit: identity properties overwritten with `x`; RocksDB still ingests the file |
| `rocksdb-sst/zstd.sst` | RocksDB via rocksdict | edit: identity properties overwritten with `x`; RocksDB still ingests the file |
| `bam/small.bam` | htslib (via pysam, inferred) | htslib BGZF block layout; `@PG ID:gen PN:python` in the header; indexed by bai/small.bam.bai |
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
| `der/leaf-pub.der` | OpenSSL 3 (openssl CLI, inferred) | SubjectPublicKeyInfo of the leaf key |
| `pkcs7/signed.p7s` | OpenSSL 3 (openssl CLI) | CMS signature verifies (`openssl cms -verify`) |
| `pkcs12/` | OpenSSL 3 (`openssl pkcs12 -export`) | all four: OpenSSL 3 defaults (SHA-256 MAC, 2048 iterations, PBES2/AES-256-CBC) or `-legacy` (RC2/3DES, SHA-1 MAC); password `fillyfoal` (empty for empty-password.p12) |
| `pkcs8-encrypted/` | OpenSSL 3 (`openssl pkcs8 -topk8`) | both: `-v1 PBE-SHA1-3DES` and the PBES2/AES-256 default; password `fillyfoal` |
| `pem/chain.pem` | OpenSSL 3 (openssl CLI) | leaf + CA chain; `openssl verify` accepts it |

## FFmpeg: images

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `bmp/testsrc-bgr24.bmp` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=12x8:rate=1 -frames:v 1 -pix_fmt bgr24` |
| `bmp/testsrc-bgra.bmp` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=12x8:rate=1 -frames:v 1 -pix_fmt bgra` |
| `bmp/testsrc-monob.bmp` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=12x8:rate=1 -frames:v 1 -pix_fmt monob` |
| `bmp/testsrc-rgb565.bmp` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i testsrc=size=12x8:rate=1 -frames:v 1 -pix_fmt rgb565le` |
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
| `jp2/ffmpeg.jp2` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | commit b86c5c84 ("fixtures generated with ffmpeg"); `Lavc` marker |
| `avif/svtav1.avif` | FFmpeg 8 with libsvtav1 | commit b86c5c84 ("fixtures generated with ffmpeg and sips") |

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
| `wma/wmav2.wma` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=8000:duration=0.2 -ac 1 -c:a wmav2 -b:a 32k` |
| `mp3/layer2.mp2` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | reproduced byte-for-byte with ffmpeg 8.1.2: `-f lavfi -i sine=frequency=440:sample_rate=16000:duration=0.1 -ac 1 -c:a mp2 -b:a 32k -f mp2` |
| `mp3/cbr-id3v23.mp3` | FFmpeg 8 with libmp3lame | `Lavf`/`Lavc` strings and Info/LAME tag; ID3v2.3 tag |
| `mp3/vbr-id3v24.mp3` | FFmpeg 8 with libmp3lame | `Lavf`/`Lavc` strings and Xing/LAME tag; ID3v2.4 with an attached picture |
| `id3/tag-only.id3` | FFmpeg 8 with libmp3lame | edit: the first 279 bytes (the ID3v2.4 tag) of mp3/vbr-id3v24.mp3, unchanged |
| `flac/tone.flac` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | vendor string `ffmpeg` (what FFmpeg writes with `-fflags +bitexact`), attached PNG picture; not byte-reproduced |
| `ogg/vorbis.ogg` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | `encoder=Lavc vorbis` comment, `ffmpeg` vendor string |
| `opus/tone.opus` | FFmpeg 8 with libopus | `encoder=Lavc libopus` comment |

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
| `mov/mpeg4.mov` | FFmpeg 8 (libavformat 62.12.102, libavcodec 62.28.102) | `Lavf`/`Lavc` markers; commit b86c5c84 |
| `mp4/fragmented.mp4` | FFmpeg 8 with libx264 | `Lavf`/`Lavc`/x264 markers; commit b86c5c84 |
| `mp4/h264-aac.mp4` | FFmpeg 8 with libx264 | `Lavf`/`Lavc`/x264 markers; commit b86c5c84 |
| `mp4/hevc.mp4` | FFmpeg 8 with libx265 | `Lavf`/`Lavc`/x265 markers; commit b86c5c84 |
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

## Other image tools

| Fixture | Producer | Evidence and edits |
| --- | --- | --- |
| `heif/sips.heic` | macOS sips (ImageIO) | commit b86c5c84 ("generated with ffmpeg and sips (HEIC)") |
| `ktx/sips.ktx` | macOS sips (ImageIO) | ImageIO key/value data (`AlphaInfo_APPLE`) |
| `ktx2/sips.ktx2` | macOS sips (ImageIO / libktx 4.0) | `KTXwriter: ImageIO / libktx v4.0` |
| `astc/sips.astc` | macOS sips (ImageIO) | named for its producer like the other sips fixtures; real ASTC block data (compare the hand-made astc/tex.astc) |
| `psd/sips.psd` | macOS sips (ImageIO) | named for its producer; ImageIO image resources with an embedded sRGB profile |
| `webp/lossless.webp` | libwebp cwebp 1.6 | reproduced byte-for-byte: `cwebp -lossless` of a 16x16 ffmpeg testsrc frame |
| `webp/lossy.webp` | libwebp cwebp 1.6 | reproduced byte-for-byte: `cwebp -q 50` of the same frame |

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
