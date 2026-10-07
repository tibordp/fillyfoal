"""A reference BZZ encoder (DjVuLibre's BSByteStream: Burrows-Wheeler
transform, a frequency-ranked move-to-front and the ZP adaptive binary
arithmetic coder), used to build the synthetic DjVu fixtures and the BZZ
test vectors of `src/codec/bzz.rs`.

Written from memory of DjVuLibre's ZPCodec.cpp and BSEncodeByteStream.cpp
(not fetched, and not checked against DjVuLibre output: no DjVuLibre tools
were available). The decoder in `src/codec/bzz.rs` mirrors the same
recollection, so the round trip only shows the two agree with each other.

Usage: python3 bzz.py IN OUT   (or import `encode`)
"""

import sys

# The ZP-coder state table (`default_ztable`): (p, m, up, dn); states
# 251..255 are unused. The trailing comments are the (n0, n1) counts the
# original annotates its adaptive states with.
TABLE = [
    (0x8000, 0x0000, 84, 145),  # 000
    (0x8000, 0x0000, 3, 4),  # 001
    (0x8000, 0x0000, 4, 3),  # 002
    (0x6BBD, 0x10A5, 5, 1),  # 003
    (0x6BBD, 0x10A5, 6, 2),  # 004
    (0x5D45, 0x1F28, 7, 3),  # 005
    (0x5D45, 0x1F28, 8, 4),  # 006
    (0x51B9, 0x2BD3, 9, 5),  # 007
    (0x51B9, 0x2BD3, 10, 6),  # 008
    (0x4813, 0x36E3, 11, 7),  # 009
    (0x4813, 0x36E3, 12, 8),  # 010
    (0x3FD5, 0x408C, 13, 9),  # 011
    (0x3FD5, 0x408C, 14, 10),  # 012
    (0x38B1, 0x48FD, 15, 11),  # 013
    (0x38B1, 0x48FD, 16, 12),  # 014
    (0x3275, 0x505D, 17, 13),  # 015
    (0x3275, 0x505D, 18, 14),  # 016
    (0x2CFD, 0x56D0, 19, 15),  # 017
    (0x2CFD, 0x56D0, 20, 16),  # 018
    (0x2825, 0x5C71, 21, 17),  # 019
    (0x2825, 0x5C71, 22, 18),  # 020
    (0x23AB, 0x615B, 23, 19),  # 021
    (0x23AB, 0x615B, 24, 20),  # 022
    (0x1F87, 0x65A5, 25, 21),  # 023
    (0x1F87, 0x65A5, 26, 22),  # 024
    (0x1BBB, 0x6962, 27, 23),  # 025
    (0x1BBB, 0x6962, 28, 24),  # 026
    (0x1845, 0x6CA2, 29, 25),  # 027
    (0x1845, 0x6CA2, 30, 26),  # 028
    (0x1523, 0x6F74, 31, 27),  # 029
    (0x1523, 0x6F74, 32, 28),  # 030
    (0x1253, 0x71E6, 33, 29),  # 031
    (0x1253, 0x71E6, 34, 30),  # 032
    (0x0FCF, 0x7404, 35, 31),  # 033
    (0x0FCF, 0x7404, 36, 32),  # 034
    (0x0D95, 0x75D6, 37, 33),  # 035
    (0x0D95, 0x75D6, 38, 34),  # 036
    (0x0B9D, 0x7768, 39, 35),  # 037
    (0x0B9D, 0x7768, 40, 36),  # 038
    (0x09E3, 0x78C2, 41, 37),  # 039
    (0x09E3, 0x78C2, 42, 38),  # 040
    (0x0861, 0x79EA, 43, 39),  # 041
    (0x0861, 0x79EA, 44, 40),  # 042
    (0x0711, 0x7AE7, 45, 41),  # 043
    (0x0711, 0x7AE7, 46, 42),  # 044
    (0x05F1, 0x7BBE, 47, 43),  # 045
    (0x05F1, 0x7BBE, 48, 44),  # 046
    (0x04F9, 0x7C75, 49, 45),  # 047
    (0x04F9, 0x7C75, 50, 46),  # 048
    (0x0425, 0x7D0F, 51, 47),  # 049
    (0x0425, 0x7D0F, 52, 48),  # 050
    (0x0371, 0x7D91, 53, 49),  # 051
    (0x0371, 0x7D91, 54, 50),  # 052
    (0x02D9, 0x7DFE, 55, 51),  # 053
    (0x02D9, 0x7DFE, 56, 52),  # 054
    (0x0259, 0x7E5A, 57, 53),  # 055
    (0x0259, 0x7E5A, 58, 54),  # 056
    (0x01ED, 0x7EA6, 59, 55),  # 057
    (0x01ED, 0x7EA6, 60, 56),  # 058
    (0x0193, 0x7EE6, 61, 57),  # 059
    (0x0193, 0x7EE6, 62, 58),  # 060
    (0x0149, 0x7F1A, 63, 59),  # 061
    (0x0149, 0x7F1A, 64, 60),  # 062
    (0x010B, 0x7F45, 65, 61),  # 063
    (0x010B, 0x7F45, 66, 62),  # 064
    (0x00D5, 0x7F6B, 67, 63),  # 065
    (0x00D5, 0x7F6B, 68, 64),  # 066
    (0x00A5, 0x7F8D, 69, 65),  # 067
    (0x00A5, 0x7F8D, 70, 66),  # 068
    (0x007B, 0x7FAA, 71, 67),  # 069
    (0x007B, 0x7FAA, 72, 68),  # 070
    (0x0057, 0x7FC3, 73, 69),  # 071
    (0x0057, 0x7FC3, 74, 70),  # 072
    (0x003B, 0x7FD7, 75, 71),  # 073
    (0x003B, 0x7FD7, 76, 72),  # 074
    (0x0023, 0x7FE7, 77, 73),  # 075
    (0x0023, 0x7FE7, 78, 74),  # 076
    (0x0013, 0x7FF2, 79, 75),  # 077
    (0x0013, 0x7FF2, 80, 76),  # 078
    (0x0007, 0x7FFA, 81, 77),  # 079
    (0x0007, 0x7FFA, 82, 78),  # 080
    (0x0001, 0x7FFF, 81, 79),  # 081
    (0x0001, 0x7FFF, 82, 80),  # 082
    (0x5695, 0x0000, 9, 85),  # 083 (2, 3)
    (0x24EE, 0x0000, 86, 226),  # 084 (1, 0)
    (0x8000, 0x0000, 5, 6),  # 085 (3, 3)
    (0x0D30, 0x0000, 88, 176),  # 086 (4, 0)
    (0x481A, 0x0000, 89, 143),  # 087 (1, 2)
    (0x0481, 0x0000, 90, 138),  # 088 (13, 0)
    (0x3579, 0x0000, 91, 141),  # 089 (1, 3)
    (0x017A, 0x0000, 92, 112),  # 090 (41, 0)
    (0x24EF, 0x0000, 93, 135),  # 091 (1, 5)
    (0x007B, 0x0000, 94, 104),  # 092 (127, 0)
    (0x1978, 0x0000, 95, 133),  # 093 (1, 8)
    (0x0028, 0x0000, 96, 100),  # 094 (392, 0)
    (0x10CA, 0x0000, 97, 129),  # 095 (1, 13)
    (0x000D, 0x0000, 82, 98),  # 096 (1208, 0)
    (0x0B5D, 0x0000, 99, 127),  # 097 (1, 20)
    (0x0034, 0x0000, 76, 72),  # 098 (1208, 1)
    (0x078A, 0x0000, 101, 125),  # 099 (1, 31)
    (0x00A0, 0x0000, 70, 102),  # 100 (392, 1)
    (0x050F, 0x0000, 103, 123),  # 101 (1, 47)
    (0x0117, 0x0000, 66, 60),  # 102 (392, 2)
    (0x0358, 0x0000, 105, 121),  # 103 (1, 72)
    (0x01EA, 0x0000, 106, 110),  # 104 (127, 1)
    (0x0234, 0x0000, 107, 119),  # 105 (1, 110)
    (0x0144, 0x0000, 66, 108),  # 106 (193, 1)
    (0x0173, 0x0000, 109, 117),  # 107 (1, 168)
    (0x0234, 0x0000, 60, 54),  # 108 (193, 2)
    (0x00F5, 0x0000, 111, 115),  # 109 (1, 256)
    (0x0353, 0x0000, 56, 48),  # 110 (127, 2)
    (0x00A1, 0x0000, 69, 113),  # 111 (1, 389)
    (0x05C5, 0x0000, 114, 134),  # 112 (41, 1)
    (0x011A, 0x0000, 65, 59),  # 113 (2, 389)
    (0x03CF, 0x0000, 116, 132),  # 114 (63, 1)
    (0x01AA, 0x0000, 61, 55),  # 115 (2, 256)
    (0x0285, 0x0000, 118, 130),  # 116 (96, 1)
    (0x0286, 0x0000, 57, 51),  # 117 (2, 168)
    (0x01AB, 0x0000, 120, 128),  # 118 (146, 1)
    (0x03D3, 0x0000, 53, 47),  # 119 (2, 110)
    (0x011A, 0x0000, 122, 126),  # 120 (222, 1)
    (0x05C5, 0x0000, 49, 41),  # 121 (2, 72)
    (0x00BA, 0x0000, 124, 62),  # 122 (338, 1)
    (0x08AD, 0x0000, 43, 37),  # 123 (2, 47)
    (0x007A, 0x0000, 72, 66),  # 124 (514, 1)
    (0x0CCC, 0x0000, 39, 31),  # 125 (2, 31)
    (0x01EB, 0x0000, 60, 54),  # 126 (222, 2)
    (0x1302, 0x0000, 33, 25),  # 127 (2, 20)
    (0x02E6, 0x0000, 56, 50),  # 128 (146, 2)
    (0x1B81, 0x0000, 29, 131),  # 129 (2, 13)
    (0x045E, 0x0000, 52, 46),  # 130 (96, 2)
    (0x24EF, 0x0000, 23, 17),  # 131 (3, 13)
    (0x0690, 0x0000, 48, 40),  # 132 (63, 2)
    (0x2865, 0x0000, 23, 15),  # 133 (2, 8)
    (0x09DE, 0x0000, 42, 136),  # 134 (41, 2)
    (0x3987, 0x0000, 137, 7),  # 135 (2, 5)
    (0x0DC8, 0x0000, 38, 32),  # 136 (41, 3)
    (0x2C99, 0x0000, 21, 139),  # 137 (2, 7)
    (0x10CA, 0x0000, 140, 172),  # 138 (13, 1)
    (0x3B5F, 0x0000, 15, 9),  # 139 (3, 7)
    (0x0B5D, 0x0000, 142, 170),  # 140 (20, 1)
    (0x5695, 0x0000, 9, 85),  # 141 (2, 3)
    (0x078A, 0x0000, 144, 168),  # 142 (31, 1)
    (0x8000, 0x0000, 141, 248),  # 143 (2, 2)
    (0x050F, 0x0000, 146, 166),  # 144 (47, 1)
    (0x24EE, 0x0000, 147, 247),  # 145 (0, 1)
    (0x0358, 0x0000, 148, 164),  # 146 (72, 1)
    (0x0D30, 0x0000, 149, 197),  # 147 (0, 4)
    (0x0234, 0x0000, 150, 162),  # 148 (110, 1)
    (0x0481, 0x0000, 151, 95),  # 149 (0, 13)
    (0x0173, 0x0000, 152, 160),  # 150 (168, 1)
    (0x017A, 0x0000, 153, 173),  # 151 (0, 41)
    (0x00F5, 0x0000, 154, 158),  # 152 (256, 1)
    (0x007B, 0x0000, 155, 165),  # 153 (0, 127)
    (0x00A1, 0x0000, 70, 156),  # 154 (389, 1)
    (0x0028, 0x0000, 157, 161),  # 155 (0, 392)
    (0x011A, 0x0000, 66, 60),  # 156 (389, 2)
    (0x000D, 0x0000, 81, 159),  # 157 (0, 1208)
    (0x01AA, 0x0000, 62, 56),  # 158 (256, 2)
    (0x0034, 0x0000, 75, 71),  # 159 (1, 1208)
    (0x0286, 0x0000, 58, 52),  # 160 (168, 2)
    (0x00A0, 0x0000, 69, 163),  # 161 (1, 392)
    (0x03D3, 0x0000, 54, 48),  # 162 (110, 2)
    (0x0117, 0x0000, 65, 59),  # 163 (2, 392)
    (0x05C5, 0x0000, 50, 42),  # 164 (72, 2)
    (0x01EA, 0x0000, 167, 171),  # 165 (1, 127)
    (0x08AD, 0x0000, 44, 38),  # 166 (47, 2)
    (0x0144, 0x0000, 65, 169),  # 167 (1, 193)
    (0x0CCC, 0x0000, 40, 32),  # 168 (31, 2)
    (0x0234, 0x0000, 59, 53),  # 169 (2, 193)
    (0x1302, 0x0000, 34, 26),  # 170 (20, 2)
    (0x0353, 0x0000, 55, 47),  # 171 (2, 127)
    (0x1B81, 0x0000, 30, 174),  # 172 (13, 2)
    (0x05C5, 0x0000, 175, 193),  # 173 (1, 41)
    (0x24EF, 0x0000, 24, 18),  # 174 (13, 3)
    (0x03CF, 0x0000, 177, 191),  # 175 (1, 63)
    (0x2B74, 0x0000, 178, 222),  # 176 (4, 1)
    (0x0285, 0x0000, 179, 189),  # 177 (1, 96)
    (0x201D, 0x0000, 180, 218),  # 178 (6, 1)
    (0x01AB, 0x0000, 181, 187),  # 179 (1, 146)
    (0x1715, 0x0000, 182, 216),  # 180 (9, 1)
    (0x011A, 0x0000, 183, 185),  # 181 (1, 222)
    (0x0FB7, 0x0000, 184, 214),  # 182 (14, 1)
    (0x00BA, 0x0000, 69, 61),  # 183 (1, 338)
    (0x0A67, 0x0000, 186, 212),  # 184 (22, 1)
    (0x01EB, 0x0000, 59, 53),  # 185 (2, 222)
    (0x06E7, 0x0000, 188, 210),  # 186 (34, 1)
    (0x02E6, 0x0000, 55, 49),  # 187 (2, 146)
    (0x0496, 0x0000, 190, 208),  # 188 (52, 1)
    (0x045E, 0x0000, 51, 45),  # 189 (2, 96)
    (0x030D, 0x0000, 192, 206),  # 190 (79, 1)
    (0x0690, 0x0000, 47, 39),  # 191 (2, 63)
    (0x0206, 0x0000, 194, 204),  # 192 (120, 1)
    (0x09DE, 0x0000, 41, 195),  # 193 (2, 41)
    (0x0155, 0x0000, 196, 202),  # 194 (183, 1)
    (0x0DC8, 0x0000, 37, 31),  # 195 (3, 41)
    (0x00E1, 0x0000, 198, 200),  # 196 (279, 1)
    (0x2B74, 0x0000, 199, 243),  # 197 (1, 4)
    (0x0094, 0x0000, 72, 64),  # 198 (424, 1)
    (0x201D, 0x0000, 201, 239),  # 199 (1, 6)
    (0x0188, 0x0000, 62, 56),  # 200 (279, 2)
    (0x1715, 0x0000, 203, 237),  # 201 (1, 9)
    (0x0252, 0x0000, 58, 52),  # 202 (183, 2)
    (0x0FB7, 0x0000, 205, 235),  # 203 (1, 14)
    (0x0383, 0x0000, 54, 48),  # 204 (120, 2)
    (0x0A67, 0x0000, 207, 233),  # 205 (1, 22)
    (0x0547, 0x0000, 50, 44),  # 206 (79, 2)
    (0x06E7, 0x0000, 209, 231),  # 207 (1, 34)
    (0x07E2, 0x0000, 46, 38),  # 208 (52, 2)
    (0x0496, 0x0000, 211, 229),  # 209 (1, 52)
    (0x0BC0, 0x0000, 40, 34),  # 210 (34, 2)
    (0x030D, 0x0000, 213, 227),  # 211 (1, 79)
    (0x1178, 0x0000, 36, 28),  # 212 (22, 2)
    (0x0206, 0x0000, 215, 225),  # 213 (1, 120)
    (0x19DA, 0x0000, 30, 22),  # 214 (14, 2)
    (0x0155, 0x0000, 217, 223),  # 215 (1, 183)
    (0x24EF, 0x0000, 26, 16),  # 216 (9, 2)
    (0x00E1, 0x0000, 219, 221),  # 217 (1, 279)
    (0x320E, 0x0000, 20, 220),  # 218 (6, 2)
    (0x0094, 0x0000, 71, 63),  # 219 (1, 424)
    (0x432A, 0x0000, 14, 8),  # 220 (6, 3)
    (0x0188, 0x0000, 61, 55),  # 221 (2, 279)
    (0x447D, 0x0000, 14, 224),  # 222 (4, 2)
    (0x0252, 0x0000, 57, 51),  # 223 (2, 183)
    (0x5ECE, 0x0000, 8, 2),  # 224 (4, 3)
    (0x0383, 0x0000, 53, 47),  # 225 (2, 120)
    (0x8000, 0x0000, 228, 87),  # 226 (1, 1)
    (0x0547, 0x0000, 49, 43),  # 227 (2, 79)
    (0x481A, 0x0000, 230, 246),  # 228 (2, 1)
    (0x07E2, 0x0000, 45, 37),  # 229 (2, 52)
    (0x3579, 0x0000, 232, 244),  # 230 (3, 1)
    (0x0BC0, 0x0000, 39, 33),  # 231 (2, 34)
    (0x24EF, 0x0000, 234, 238),  # 232 (5, 1)
    (0x1178, 0x0000, 35, 27),  # 233 (2, 22)
    (0x1978, 0x0000, 138, 236),  # 234 (8, 1)
    (0x19DA, 0x0000, 29, 21),  # 235 (2, 14)
    (0x2865, 0x0000, 24, 16),  # 236 (8, 2)
    (0x24EF, 0x0000, 25, 15),  # 237 (2, 9)
    (0x3987, 0x0000, 240, 8),  # 238 (5, 2)
    (0x320E, 0x0000, 19, 241),  # 239 (2, 6)
    (0x2C99, 0x0000, 22, 242),  # 240 (7, 2)
    (0x432A, 0x0000, 13, 7),  # 241 (3, 6)
    (0x3B5F, 0x0000, 16, 10),  # 242 (7, 3)
    (0x447D, 0x0000, 13, 245),  # 243 (2, 4)
    (0x5695, 0x0000, 10, 2),  # 244 (3, 2)
    (0x5ECE, 0x0000, 7, 1),  # 245 (3, 4)
    (0x8000, 0x0000, 244, 83),  # 246 (2, 2)
    (0x8000, 0x0000, 249, 250),  # 247 (1, 1)
    (0x5695, 0x0000, 10, 2),  # 248 (3, 2)
    (0x481A, 0x0000, 89, 143),  # 249 (1, 2)
    (0x481A, 0x0000, 230, 246),  # 250 (2, 1)
] + [(0, 0, 0, 0)] * 5

P = [t[0] for t in TABLE]
M = [t[1] for t in TABLE]
UP = [t[2] for t in TABLE]
DN = [t[3] for t in TABLE]


class ZPEncoder:
    """ZPCodec's encoder (with the ZP interval-reversion fix)."""

    def __init__(self):
        self.out = bytearray()
        self.a = 0
        self.scount = 0
        self.byte = 0
        self.delay = 25
        self.subend = 0
        self.buffer = 0xFFFFFF
        self.nrun = 0

    def outbit(self, bit):
        if self.delay > 0:
            if self.delay < 0xFF:
                self.delay -= 1
        else:
            self.byte = (self.byte << 1) | bit
            self.scount += 1
            if self.scount == 8:
                self.out.append(self.byte)
                self.scount = 0
                self.byte = 0

    def zemit(self, b):
        self.buffer = ((self.buffer << 1) + b) & 0xFFFFFFFF
        b = self.buffer >> 24
        self.buffer &= 0xFFFFFF
        if b == 1:
            self.outbit(1)
            while self.nrun > 0:
                self.outbit(0)
                self.nrun -= 1
            self.nrun = 0
        elif b == 0xFF:
            self.outbit(0)
            while self.nrun > 0:
                self.outbit(1)
                self.nrun -= 1
            self.nrun = 0
        elif b == 0:
            self.nrun += 1
        else:
            raise AssertionError(b)

    def _export(self):
        while self.a >= 0x8000:
            self.zemit(1 - (self.subend >> 15))
            self.subend = (self.subend << 1) & 0xFFFF
            self.a = (self.a << 1) & 0xFFFF

    def encode(self, bit, ctx, i):
        """Codes `bit` with adaptive context `ctx[i]`."""
        state = ctx[i]
        z = self.a + P[state]
        if bit != (state & 1):
            d = 0x6000 + ((z + self.a) >> 2)
            if z > d:
                z = d
            ctx[i] = DN[state]
            z = 0x10000 - z
            self.subend += z
            self.a += z
            self._export()
        elif z >= 0x8000:
            d = 0x6000 + ((z + self.a) >> 2)
            if z > d:
                z = d
            if self.a >= M[state]:
                ctx[i] = UP[state]
            self.a = z
            if self.a >= 0x8000:
                self.zemit(1 - (self.subend >> 15))
                self.subend = (self.subend << 1) & 0xFFFF
                self.a = (self.a << 1) & 0xFFFF
        else:
            self.a = z

    def encode_raw(self, bit):
        """Codes `bit` without a context (probability one half)."""
        z = 0x8000 + (self.a >> 1)
        if bit:
            z = 0x10000 - z
            self.subend += z
            self.a += z
            self._export()
        else:
            self.a = z
            if self.a >= 0x8000:
                self.zemit(1 - (self.subend >> 15))
                self.subend = (self.subend << 1) & 0xFFFF
                self.a = (self.a << 1) & 0xFFFF

    def flush(self):
        if self.subend > 0x8000:
            self.subend = 0x10000
        elif self.subend > 0:
            self.subend = 0x8000
        while self.buffer != 0xFFFFFF or self.subend:
            self.zemit(1 - (self.subend >> 15))
            self.subend = (self.subend << 1) & 0xFFFF
        self.outbit(1)
        while self.nrun > 0:
            self.outbit(0)
            self.nrun -= 1
        self.nrun = 0
        while self.scount > 0:
            self.outbit(1)
        self.delay = 0xFF
        return bytes(self.out)


def _raw(zp, bits, value):
    for i in range(bits - 1, -1, -1):
        zp.encode_raw((value >> i) & 1)


def _binary(zp, ctx, base, bits, value):
    n = 1
    for i in range(bits - 1, -1, -1):
        b = (value >> i) & 1
        zp.encode(b, ctx, base - 1 + n)
        n = (n << 1) | b


FREQMAX = 4
CTXIDS = 3


def _block(zp, ctx, data):
    n = len(data)
    size = n + 1
    # Suffix order of data + sentinel (the sentinel sorts first).
    order = sorted(range(size), key=lambda i: data[i:])
    last = []
    markerpos = -1
    for j, i in enumerate(order):
        if i == 0:
            markerpos = j
            last.append(None)
        else:
            last.append(data[i - 1])
    _raw(zp, 24, size)
    fshift = 0 if size < 100000 else (1 if size < 1000000 else 2)
    zp.encode_raw(1 if fshift > 0 else 0)
    if fshift > 0:
        zp.encode_raw(1 if fshift > 1 else 0)
    mtf = list(range(256))
    freq = [0] * FREQMAX
    fadd = 4
    mtfno = 3
    for c in last:
        ctxid = min(CTXIDS - 1, mtfno)
        mtfno = 256 if c is None else mtf.index(c)
        base = 0
        zp.encode(1 if mtfno == 0 else 0, ctx, base + ctxid)
        if mtfno != 0:
            base += CTXIDS
            zp.encode(1 if mtfno == 1 else 0, ctx, base + ctxid)
            if mtfno != 1:
                base += CTXIDS
                lo = 2
                for bits in range(1, 8):
                    hit = lo <= mtfno < 2 * lo
                    zp.encode(1 if hit else 0, ctx, base)
                    if hit:
                        _binary(zp, ctx, base + 1, bits, mtfno - lo)
                        break
                    base += 1 << bits
                    lo *= 2
        if c is None:
            continue
        fadd = fadd + (fadd >> fshift)
        if fadd > 0x10000000:
            fadd >>= 24
            freq = [f >> 24 for f in freq]
        fc = fadd
        if mtfno < FREQMAX:
            fc += freq[mtfno]
        k = mtfno
        while k >= FREQMAX:
            mtf[k] = mtf[k - 1]
            k -= 1
        while k > 0 and fc >= freq[k - 1]:
            mtf[k] = mtf[k - 1]
            freq[k] = freq[k - 1]
            k -= 1
        mtf[k] = c
        freq[k] = fc
    assert markerpos >= 1


def encode(data, blocksize=1 << 20):
    zp = ZPEncoder()
    ctx = [0] * 300
    for at in range(0, len(data), blocksize):
        _block(zp, ctx, data[at : at + blocksize])
    _raw(zp, 24, 0)
    return zp.flush()


if __name__ == "__main__":
    with open(sys.argv[1], "rb") as f:
        raw = f.read()
    with open(sys.argv[2], "wb") as f:
        f.write(encode(raw))
