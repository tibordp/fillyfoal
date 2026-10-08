"""Generates the MeatPack round-trip vectors with Scott Mudge's packer,
`OctoPrint_MeatPack/meatpack.py` from OctoPrint-MeatPack (BSD-3-Clause;
tested with commit cc3af5a5ed8eee8775425366df426cf7baca6f61, v1.5.23):

    git clone https://github.com/scottmudge/OctoPrint-MeatPack
    uv run --no-project python tests/data/meatpack/make_meatpack.py OctoPrint-MeatPack

`meatpack.py` only needs the standard library, so it is loaded directly
from its file (not through the plugin package, which needs OctoPrint).

For each input (`edge.gcode`, written here, and the synthetic
`tests/fixtures/synthetic/gcode/prusaslicer.gcode`) and each mode
(`spaces`, `nospaces`), writes:
- `<name>.<mode>.mp`: the packed stream, laid out like `pack_file`'s
  output: the enable-packing command, (for `nospaces`) the
  enable-no-spaces command, every packed line, the reset command;
- `<name>.<mode>.txt`: the text the packer actually packed, line by line
  (its comment stripping and no-spaces rewriting applied), as it reports
  it through `pack_line`'s logger.
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))

EDGE = """\
; a full-line comment
G1 X113.214 Y91.45 E1.3154
G1 X-5.5 Y-3 E-.8 F2100 ; trailing comment
G1 Z.2
G0 X1 Y2
g1 x5 y6 e7
G1 x5 y6 e7
M117 Hello World 42%
M862.3 P "MK4S"
T0
G28 W
G28 X Y
N3 G1 X5 Y5*99
M104 S215
G4 P500
M73 P50 R1
G1 X0.123456789 Y98765.4321 E0
@pause
G1 E#$%&
"""


class Capture:
    """Stands in for the logger `pack_line` reports each packed line to."""

    def __init__(self):
        self.lines = []

    def info(self, message):
        prefix = "[Test] Line sent: "
        assert message.startswith(prefix)
        self.lines.append(message[len(prefix):])


def main(repo):
    path = os.path.join(repo, "OctoPrint_MeatPack", "meatpack.py")
    spec = importlib.util.spec_from_file_location("meatpack", path)
    mp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mp)
    mp.initialize()

    with open(os.path.join(HERE, "edge.gcode"), "w", newline="\n") as f:
        f.write(EDGE)
    inputs = {
        "edge": os.path.join(HERE, "edge.gcode"),
        "prusaslicer": os.path.join(ROOT, "tests/fixtures/synthetic/gcode/prusaslicer.gcode"),
    }
    for name, source in inputs.items():
        with open(source, "r", newline="") as f:
            lines = f.readlines()
        for mode, no_spaces in [("spaces", False), ("nospaces", True)]:
            mp.set_no_spaces(no_spaces)
            log = Capture()
            out = bytearray(mp.get_command_bytes(mp.MPCommand_EnablePacking))
            if no_spaces:
                out += mp.get_command_bytes(mp.MPCommand_EnableNoSpaces)
            for line in lines:
                out += mp.pack_line(line, log)
            out += mp.get_command_bytes(mp.MPCommand_ResetAll)
            with open(os.path.join(HERE, f"{name}.{mode}.mp"), "wb") as f:
                f.write(out)
            with open(os.path.join(HERE, f"{name}.{mode}.txt"), "w", newline="") as f:
                f.write("".join(log.lines))
        mp.set_no_spaces(False)


if __name__ == "__main__":
    main(sys.argv[1])
