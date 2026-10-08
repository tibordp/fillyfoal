# Third-party material

fillyfoal is licensed under the GNU General Public License, version 3 or
(at your option) any later version (see `COPYING`). Some parts are derived
from, or follow closely, other works whose licenses are compatible with that;
their notices and credits follow. Format specifications and documentation
consulted (Microsoft Open Specifications, RFCs, vendor technotes) are cited
in the module documentation of the code that implements them.

Much of fillyfoal was written with AI assistance. Where a module was written
from knowledge of a particular implementation, its documentation says so;
`LICENSE-REVIEW.md` in the repository records how such modules were checked.

## Brotli static dictionary

`src/codec/brotli_dictionary.bin` is the static dictionary of RFC 7932
(Appendix A), as distributed with the reference implementation
(<https://github.com/google/brotli>) under the MIT license:

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

## ACE decompression — acefile

`src/codec/ace.rs` follows the structure of acefile, a Python
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

Parts of `src/codec/stuffit.rs` (the method 13 decoder and the Arsenic
decoder) are derived from XADMaster (The Unarchiver), Copyright (c)
2017-present MacPaw Way Ltd (and its earlier authors), licensed under the GNU
Lesser General Public License version 2.1 or later, used here under the GNU
GPL version 3 as LGPL-2.1 section 3 permits.

## StuffIt method 5 (LZAH) — LZHUF

The adaptive-Huffman LZ decoder for StuffIt method 5 in
`src/codec/stuffit.rs` follows Haruhiko Okumura's `LZHUF.C` (1988),
distributed by its author for free use, distribution and modification.

## Quantum and parts of LZX — libmspack

`src/codec/quantum.rs` (the arithmetic coder and model) and parts of
`src/codec/lzx.rs` follow libmspack, (C) 2003-2023 Stuart Caie, licensed
under the GNU Lesser General Public License version 2.1, used here under the
GNU GPL version 3 as LGPL-2.1 section 3 permits. libmspack's Quantum
decompressor is in turn based on an implementation by Matthew Russotto; the
Quantum method was created by David Stafford.

## DjVu BZZ — DjVuLibre

`src/codec/bzz.rs` (the ZP-coder decoder, its adaptation table, and the BZZ
block decoding) follows DjVuLibre, Copyright (c) 2002 Leon Bottou and Yann Le
Cun, Copyright (c) 2001 AT&T, licensed under the GNU General Public License
version 2 or (at your option) any later version.

## PPMd variant H

The PPMd model in `src/codec/rar/ppmd.rs` implements Dmitry Shkarin's PPMd
variant H (public domain), organised after Igor Pavlov's `Ppmd7` in 7-Zip /
the LZMA SDK (public domain).

## Guitar Pro field names — PyGuitarPro

Flag and enumeration labels in `src/formats/audio/guitar_pro/` follow
PyGuitarPro (licensed under the GNU Lesser General Public License version 3),
whose source was also consulted for the GP3-GP5 layout.

## Delphi DCU — DCU32INT

The DCU packed-index encoding and version magics in
`src/formats/executable/dcu.rs` follow DCU32INT by Alexei Hmelnov
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
