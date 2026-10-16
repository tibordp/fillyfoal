#!/usr/bin/env python3
"""Writes shift-space.DD: a small DolDoc document with shift-spaces
(CH_SHIFT_SPACE, 0x1f: a space the editor does not break a line at),
which Doc2TXT (Adam/Opt/Utils/ToTXT.HC) turns into spaces. Real files have
them (e.g. DocCodeTools.HC on the V5.03 ISO); this one is made by hand.

    python3 make_shift_space.py ../../fixtures/synthetic/doldoc/shift-space.DD
"""
import sys

SHIFT_SPACE = '\x1f'
text = (
    '$WW,1$$FG,5$Shift-spaces$FG$\n'
    '\n'
    'Words joined by$FG,2$ shift-spaces$FG$ stay on one line: '
    + SHIFT_SPACE.join(['one', 'two', 'three']) + '.\n'
)
open(sys.argv[1], 'wb').write(text.encode('ascii'))
