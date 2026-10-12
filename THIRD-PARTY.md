# Third-party material

fillyfoal is licensed under the GNU General Public License, version 3 or
(at your option) any later version (see `COPYING`). Some parts are derived
from, or follow closely, other works whose licenses are compatible with that;
their notices and credits follow. Format specifications and documentation
consulted (Microsoft Open Specifications, RFCs, vendor technotes) are cited
in the module documentation of the code that implements them.

Much of fillyfoal was written with AI assistance. Where a module was written
from knowledge of a particular implementation, its documentation says so.
In October 2026 the library was compared against the reference sources of
its decoders and against GPL-incompatible codebases; the notices below are
the result, and code that followed an incompatible source was rewritten.

## Brotli static dictionary and decoder parts

`crates/codec/src/codec/brotli_dictionary.bin` is the static dictionary of RFC 7932
(Appendix A), as distributed with the reference implementation
(<https://github.com/google/brotli>) under the MIT license; the
code-length prefix lookup in `crates/codec/src/codec/brotli.rs` also follows its
`decode.c`:

```text
Copyright (c) 2009, 2010, 2013-2016 by the Brotli Authors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

## DEFLATE and DCL implode — puff and blast

`crates/codec/src/codec/inflate.rs` (Huffman table construction and decoding) is an
altered Rust version of Mark Adler's `puff`, and the DCL implode decoder and
its packed code tables in `crates/codec/src/codec/implode.rs` an altered Rust version of
his `blast`; `crates/codec/src/codec/brotli.rs` uses the same decoding technique. Both
are in zlib's `contrib/` (<https://github.com/madler/zlib>):

```text
Copyright (C) 2002-2013 Mark Adler, all rights reserved
version 2.3, 21 Jan 2013

This software is provided 'as-is', without any express or implied
warranty.  In no event will the author be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
```

```text
Copyright (C) 2003, 2012, 2013 Mark Adler
version 1.3, 24 Aug 2013

This software is provided 'as-is', without any express or implied
warranty.  In no event will the author be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
```

## LZFSE — Apple's reference implementation

The FSE decoding-table construction and the frequency and L/M/D code tables
in `crates/codec/src/codec/lzfse.rs` follow Apple's reference implementation
(<https://github.com/lzfse/lzfse>):

```text
Copyright (c) 2015-2016, Apple Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1.  Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2.  Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
    in the documentation and/or other materials provided with the distribution.

3.  Neither the name of the copyright holder(s) nor the names of any contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## bcrypt_pbkdf and Blowfish — OpenBSD

`bcrypt_hash`, the key interleave and the Blowfish key schedule in
`crates/codec/src/codec/crypto/bcrypt.rs` follow OpenBSD's `bcrypt_pbkdf.c` and
`blowfish.c` (as in <https://github.com/openssh/openssh-portable>):

```text
Copyright (c) 2013 Ted Unangst <tedu@openbsd.org>

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
```

```text
Copyright 1997 Niels Provos <provos@physnet.uni-hamburg.de>
All rights reserved.

Implementation advice by David Mazieres <dm@lcs.mit.edu>.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## ACE decompression — acefile

`crates/codec/src/codec/ace.rs` follows the structure of acefile, a Python
implementation of ACE decompression:

```text
Copyright (c) 2017-2026, Daniel Roethlisberger and contributors.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions, and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

The ACE archive format and its compression algorithms were designed by
Marcel Lemke.

## StuffIt methods 13 and 15 (Arsenic) — XADMaster

Parts of `crates/codec/src/codec/stuffit.rs` (the method 13 decoder and the Arsenic
decoder) are derived from XADMaster (The Unarchiver), Copyright (c)
2017-present MacPaw Way Ltd (and its earlier authors), licensed under the GNU
Lesser General Public License version 2.1 or later, used here under the GNU
GPL version 3 as LGPL-2.1 section 3 permits.

## StuffIt method 5 (LZAH) and LHA `-lh1-` — LZHUF

The adaptive-Huffman LZ decoders for StuffIt method 5 in
`crates/codec/src/codec/stuffit.rs` and LHA's `-lh1-` in `crates/codec/src/codec/lzh.rs` follow
Haruhiko Okumura's `LZHUF.C` (1988), distributed by its author for free use,
distribution and modification.

## Quantum and parts of LZX — libmspack

`crates/codec/src/codec/quantum.rs` (the arithmetic coder and model) and parts of
`crates/codec/src/codec/lzx.rs` follow libmspack, (C) 2003-2023 Stuart Caie, licensed
under the GNU Lesser General Public License version 2.1, used here under the
GNU GPL version 3 as LGPL-2.1 section 3 permits. libmspack's Quantum
decompressor is in turn based on an implementation by Matthew Russotto; the
Quantum method was created by David Stafford.

## DjVu BZZ — DjVuLibre

`crates/codec/src/codec/bzz.rs` (the ZP-coder decoder, its adaptation table, and the BZZ
block decoding) follows DjVuLibre, Copyright (c) 2002 Leon Bottou and Yann Le
Cun, Copyright (c) 2001 AT&T, licensed under the GNU General Public License
version 2 or (at your option) any later version.

## PPMd variant H

The PPMd model in `crates/codec/src/codec/rar/ppmd.rs` implements Dmitry Shkarin's PPMd
variant H (public domain), organised after Igor Pavlov's `Ppmd7` in 7-Zip /
the LZMA SDK (public domain).

## PPMd variant I

The PPMd model in `crates/codec/src/codec/ppmd8.rs` (ZIP method 98) implements
Dmitry Shkarin's PPMd variant I revision 1 (public domain), organised after
`Ppmd8.c` and `Ppmd8Dec.c` of Igor Pavlov's LZMA SDK (public domain). Its
test vectors (`crates/codec/src/codec/testdata/ppmd8-*.bin`) are written by
that code through pyppmd (`tests/data/zip/ppmd8.py`).

## RAR decompression — libarchive

The RAR 2.9/3.x and RAR 5.0 decoders in `crates/codec/src/codec/rar/` (`bits.rs`,
`huffman.rs`, `v3.rs`, `v5.rs`, `filters.rs`) were written from libarchive's
RAR readers, `libarchive/archive_read_support_format_rar.c` and
`libarchive/archive_read_support_format_rar5.c`
(<https://github.com/libarchive/libarchive>), and follow their behaviour,
constant tables and limits; the test encoder `tests/data/rar/rarenc.py` is
written against the same readers. The RAR 4.x Unicode file name decoding in
`crates/archive/src/formats/archive/rar.rs` (`name4`, `decode_unicode_name`)
follows the same file's `read_header` (the high byte, flag bits and run
loop). They replace an earlier version that had
been transliterated from unRAR (see the module documentation of
`crates/codec/src/codec/rar/mod.rs`). libarchive's notice:

```text
Copyright (c) 2003-2007 Tim Kientzle
Copyright (c) 2011 Andres Mejia
Copyright (c) 2018 Grzegorz Antoniak (http://antoniak.org)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

(The first two copyright lines are from the header of
`archive_read_support_format_rar.c`, the third from that of
`archive_read_support_format_rar5.c`.)

## LZMS decompression — wimlib

The LZMS decoder in `crates/codec/src/codec/lzms.rs` was written from the
format description at the top of wimlib's `src/lzms_decompress.c` and checked
against that file and `src/lzms_common.c` in wimlib 1.13.6
(<https://wimlib.net/>). It follows them closely: the range decoder and
probability updates, the delayed repeat-offset queues, the adaptive Huffman
rebuild schedule, the offset and length slot tables (generated here from run
lengths; identical to wimlib's `lzms_offset_slot_base`,
`lzms_extra_offset_bits`, `lzms_length_slot_base` and
`lzms_extra_length_bits`), the constants of `include/wimlib/lzms_constants.h`,
and the x86 filter (`lzms_x86_filter` and `translate_if_needed`, including the
skipped first byte and the extra MOV conditions). The Huffman code lengths are
computed as wimlib's `make_canonical_huffman_code` in `src/compress_common.c`
does (leaves sorted by frequency then symbol, two-queue tree construction with
ties to leaves, its length-limiting step), because the decoder must build the
same codes the compressor did. The solid-resource framing in
`crates/codec/src/codec/wim.rs` and the solid lookup-table runs in
`crates/archive/src/formats/archive/wim.rs` follow the descriptions in
`src/resource.c` and `src/blob_table.c`. No code was copied; the Rust is our
own.

`lzms_decompress.c` and `lzms_common.c` carry this notice (comment markers
removed):

```text
Copyright (C) 2013-2016 Eric Biggers

This file is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation; either version 3 of the License, or (at your option) any
later version.

This file is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
details.

You should have received a copy of the GNU Lesser General Public License
along with this file; if not, see http://www.gnu.org/licenses/.
```

`resource.c` carries the same text with `Copyright (C) 2012, 2013, 2015 Eric
Biggers`, and `blob_table.c` with `Copyright (C) 2012-2016 Eric Biggers`.
`lzms_constants.h` has no header of its own; wimlib's `COPYING` puts every
file of the project under the GNU GPL version 3 or later (and the library,
which these files belong to, alternatively under the LGPL version 3 or later).
`compress_common.c` carries this notice:

```text
Copyright 2022 Eric Biggers

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the "Software"), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
```

## Guitar Pro field names — PyGuitarPro

Flag and enumeration labels in `crates/av/src/formats/audio/guitar_pro/` follow
PyGuitarPro (licensed under the GNU Lesser General Public License version 3),
whose source was also consulted for the GP3-GP5 layout.

## Delphi DCU — DCU32INT

The DCU packed-index encoding and version magics in
`crates/exec/src/formats/executable/dcu.rs` follow DCU32INT by Alexei Hmelnov
(<http://hmelnov.icc.ru/DCU/>), whose license reads:

```text
This software is provided 'as-is', without any expressed or implied warranty.
In no event will the author be held liable for any damages arising from the
use of this software.
Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:
1. The origin of this software must not be misrepresented, you must not
   claim that you wrote the original software.
2. Altered source versions must be plainly marked as such, and must not
   be misrepresented as being the original software.
3. This notice may not be removed or altered from any source
   distribution.
```

## MeatPack — OctoPrint-MeatPack

The MeatPack decoder in `crates/codec/src/codec/meatpack.rs` is derived as the inverse of
the packer in Scott Mudge's OctoPrint-MeatPack
(<https://github.com/scottmudge/OctoPrint-MeatPack>, `meatpack.py`) and the
format description in its README, licensed as follows:

```text
Copyright (c) 2025 Scott Mudge

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## ESE column compression — Microsoft Extensible Storage Engine

The compressed-value handling in `crates/data/src/formats/data/ese/compress.rs`
follows Microsoft's open-source ESE (<https://github.com/microsoft/Extensible-Storage-Engine>,
`dev/ese/src/ese/compression.cxx`, consulted at commit
`7030fe7407615160e54d152e4ef704eede2fdd7e`): the `COMPRESSION_SCHEME` numbers
(7-bit ASCII 1, 7-bit Unicode 2, Xpress 3, Scrub 4, Xpress9 5, Xpress10 6,
LZ4 7, in the top five bits of the first byte), the 3-byte `Lz4Header` and
Xpress header (scheme byte, then the uncompressed size as a little-endian
WORD) and the 7-bit header's low three bits (bits used in the last byte,
minus one). No code was copied. ESE is under the MIT License; its
`LICENSE` at that commit:

```text
    MIT License

    Copyright (c) Microsoft Corporation.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
```

## MSISAM page encryption — Jackcess Encrypt

The Microsoft Money (MSISAM) page decryption in
`crates/data/src/formats/data/jet/mod.rs` (`Msisam`, `plain_input`) follows
Jackcess Encrypt's `MSISAMCryptCodecHandler` and
`BaseCryptCodecHandler.applyPageNumber`
(<https://jackcessencrypt.sourceforge.io>; Copyright (c) 2010 Vladimir
Berezniker, per the source headers): the encryption flags at 0x298 (0x06 the
hashed scheme, 0x20 SHA-1 instead of MD5), the 8-byte salt at 0x72, the
upper-cased password in 40 zero bytes hashed and cut to 16 bytes, the check
bytes at 0x2e9 plus the salt's first byte, the key made of the digest and the
first four salt bytes with the page number XORed in, and the 14 encrypted
pages. It was first written from memory of that class and checked only
against two files Money wrote; the source of `jackcess-encrypt` 5.0.2 (its
Maven Central sources jar) was then re-read and agrees. No code was copied.
Jackcess Encrypt is under the Apache License, Version 2.0; the
`jackcess-encrypt-5.0.2` tag of its source tree has no NOTICE file, and its
`LICENSE.txt` is byte-for-byte the Apache License 2.0 text reproduced under
"Test fixtures: Access database templates — Jackcess" below.

## Test fixture: ClrLoader.dll — clr_loader

`tests/fixtures/external/pe/clrloader-amd64.dll` is
`clr_loader/ffi/dlls/amd64/ClrLoader.dll` from the clr_loader 0.3.1 wheel
(<https://github.com/pythonnet/clr-loader>), unchanged, under the MIT
license:

```text
MIT License

Copyright (c) 2019-2026 Benedikt Reinartz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Test fixtures: GNU FreeFont subsets

The font fixtures `tests/fixtures/external/sfnt/freeserif-subset.ttf`,
`sfnt/freeserif-subset.otf`, `woff/freeserif-subset.woff`,
`woff2/freeserif-subset.woff2`, `ttc/freefont-subset.ttc` and
`eot/freeserif-subset.eot` are subsets of GNU FreeFont 20120503
(<https://savannah.gnu.org/projects/freefont/>; FreeSerif and FreeSans),
made with fontTools (see `tests/fixtures/external/SOURCES.md`). They keep
the fonts' name records, including this notice:

```text
Copyright 2002, 2003, 2005, 2008, 2009, 2010, 2012 GNU Freefont contributors.

This computer font is part of GNU FreeFont.  It is free software: you can
redistribute it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either version 3 of
the License, or (at your option) any later version.

This font is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

As a special exception, if you create a document which uses this font, and
embed this font or unaltered portions of this font into the document, this
font does not by itself cause the resulting document to be covered by the
GNU General Public License. [...]
```

## Test fixtures: Access database templates — Jackcess

`tests/fixtures/external/mdb/jet4.mdb.raw.zst` and
`tests/fixtures/external/accdb/ace.accdb.raw.zst` were written by Jackcess
4.0.5 (<https://jackcess.sourceforge.io>; Copyright (c) Health Market Science,
Inc. and James Ahlborn, per its source headers). Jackcess builds every new
database from an empty database it ships
(`com/healthmarketscience/jackcess/empty.mdb` and `empty2010.accdb` in its
jar), so these files contain that template data: the system tables, their
rows and the template objects. Jackcess is under the Apache License,
Version 2.0. Its jar carries no NOTICE file; the source tree of the
`jackcess-4.0.5` tag has this `NOTICE.txt` (it concerns code in Jackcess's
expression engine, not the templates, and is reproduced as Apache-2.0 asks):

```text
Many of the financial functions in the expression engine have been originally
copied from the Apache POI project (Apache Software Foundation) and the
UCanAccess Project.  They have been then modified and adapted so that they are
integrated with Jackcess, in a consistent manner.  The Apache POI and
UCanAccess projects are both licensed under Apache License, Version 2.0
http://www.apache.org/licenses/LICENSE-2.0.
```

The license, as `LICENSE.txt` in the same tag:

```text

                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```

## Acknowledgements

No notice is required for the following, but parts of fillyfoal follow them
closely enough to credit:

- LZO1X decoding (`crates/codec/src/codec/lzo.rs`): the LZO format by Markus F.X.J.
  Oberhumer (LZO is GPL-2.0-or-later).
- LZMA, LZMA2, the BCJ filters and BCJ2 (`crates/codec/src/codec/lzma.rs`, `crates/codec/src/codec/xz.rs`, `crates/codec/src/codec/bcj2.rs`):
  Igor Pavlov's LZMA SDK and XZ Utils (public domain / 0BSD).
- Poly1305 (`crates/codec/src/codec/crypto/poly1305.rs`): Andrew Moon's poly1305-donna
  (public domain / MIT).
- The static-Huffman LHA/ARJ layout (`crates/codec/src/codec/lzh.rs`): Haruhiko Okumura's
  ar002 (free).
- UEFI and Tiano decompression (`Method::Uefi` in `crates/codec/src/codec/lzh.rs`): the
  parameters of EDK2's `MdePkg/Library/BaseUefiDecompressLib` (BSD-2-Clause-Patent).
- MBR and GPT partition-type names (`crates/archive/src/formats/disk/ptypes.rs`): util-linux
  `include/pt-mbr-partnames.h` and `pt-gpt-partnames.h` (public domain).
- macOS keychain field naming (`crates/security/src/formats/security/keychain.rs`):
  chainbreaker (GPL-2.0-or-later).
- SAS and SPSS decompression (`crates/codec/src/codec/statdata.rs`): ReadStat (MIT) and
  pandas' SAS reader (BSD-3-Clause).
- Camera maker-note tag names (`crates/image/src/formats/image/tiff/maker.rs`): Phil
  Harvey's ExifTool tag documentation (Perl's licence: GPL or Artistic).
- Installer layouts (`crates/archive/src/formats/archive/installer/`): NSIS (zlib),
  innoextract (zlib), unshield (MIT) and 7-Zip's NSIS handler (LGPL-2.1+).
- Double-byte code page tables (`crates/codec/src/codec/charset/cp9*.bin`, `big5hkscs.bin`):
  generated by `tests/data/charset/multibyte.py` from CPython's `cp932`, `gbk`, `cp949`,
  `cp950` and `big5hkscs` codecs (PSF License 2.0), whose mappings follow the Unicode
  Consortium's and Microsoft's published code page tables and the Hong Kong SAR
  government's HKSCS-2004.
