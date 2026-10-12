# Prints the running interpreter's opcode table as JSON (Python 2.7 and
# 3.6+): names of opcodes 0-255, argument categories, inline cache sizes.
# Run by tests/data/pyc/make-opcodes.sh in each python:X.Y-slim image.
from __future__ import print_function

import dis
import json
import opcode
import sys

names = list(dis.opname[:256])
caches = [0] * 256
entries = getattr(opcode, "_inline_cache_entries", None)
if entries is None:
    entries = getattr(dis, "_inline_cache_entries", None)
if isinstance(entries, dict):
    for name, n in entries.items():
        op = opcode.opmap.get(name)
        if op is not None and op < 256:
            caches[op] = n
elif entries is not None:
    for op, n in enumerate(entries):
        if op < 256:
            caches[op] = n


def ops(attr):
    return sorted(set(o for o in getattr(dis, attr, []) if o < 256))


jumps = sorted(set(ops("hasjrel")) | set(ops("hasjabs")) | set(ops("hasjump")))
print(json.dumps({
    "version": "%d.%d" % sys.version_info[:2],
    "names": names,
    "caches": caches,
    "have_argument": getattr(opcode, "HAVE_ARGUMENT", 90),
    "extended_arg": opcode.opmap.get("EXTENDED_ARG", 0),
    "const": ops("hasconst"),
    "name": ops("hasname"),
    "local": ops("haslocal"),
    "free": ops("hasfree"),
    "jrel": ops("hasjrel"),
    "jabs": ops("hasjabs"),
    "jump": jumps,
    "compare": ops("hascompare"),
    "cmp_op": list(getattr(dis, "cmp_op", ())),
}))
