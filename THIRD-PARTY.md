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

## RAR decompression — libarchive

The RAR 2.9/3.x and RAR 5.0 decoders in `crates/codec/src/codec/rar/` (`bits.rs`,
`huffman.rs`, `v3.rs`, `v5.rs`, `filters.rs`) were written from libarchive's
RAR readers, `libarchive/archive_read_support_format_rar.c` and
`libarchive/archive_read_support_format_rar5.c`
(<https://github.com/libarchive/libarchive>), and follow their behaviour,
constant tables and limits; the test encoder `tests/data/rar/rarenc.py` is
written against the same readers. They replace an earlier version that had
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

## Acknowledgements

No notice is required for the following, but parts of fillyfoal follow them
closely enough to credit:

- LZO1X decoding (`crates/codec/src/codec/lzo.rs`): the LZO format by Markus F.X.J.
  Oberhumer (LZO is GPL-2.0-or-later).
- LZMA, LZMA2 and the BCJ filters (`crates/codec/src/codec/lzma.rs`, `crates/codec/src/codec/xz.rs`):
  Igor Pavlov's LZMA SDK and XZ Utils (public domain / 0BSD).
- Poly1305 (`crates/codec/src/codec/crypto/poly1305.rs`): Andrew Moon's poly1305-donna
  (public domain / MIT).
- The static-Huffman LHA/ARJ layout (`crates/codec/src/codec/lzh.rs`): Haruhiko Okumura's
  ar002 (free).
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
