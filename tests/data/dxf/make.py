"""Writes the external DXF fixtures with ezdxf.

    PYTHONHASHSEED=0 uv run --with ezdxf==1.4.4 python tests/data/dxf/make.py tests/fixtures/external/dxf

(ezdxf orders the CLASSES section by iterating a set, hence the hash seed.)

The drawing (layers, a linetype, a text style, a block and its insert, a few
entity types) is ours; everything about the DXF encoding is ezdxf's. The
time stamps and GUIDs ezdxf would take from the clock and the random number
generator are pinned (ezdxf's `write_fixed_meta_data_for_testing` option),
so the output is reproducible byte for byte.
"""

import sys
from pathlib import Path

import ezdxf
from ezdxf.enums import TextEntityAlignment


def drawing(version):
    doc = ezdxf.new(version, setup=False)
    doc.layers.add("WALLS", color=1)
    doc.linetypes.add("DASHED", pattern=[0.75, 0.5, -0.25], description="Dashed __ __ __")
    doc.layers.add("DOORS", color=3, linetype="DASHED")
    doc.styles.add("NOTES", font="arial.ttf")
    block = doc.blocks.new("DOOR")
    block.add_line((0, 0), (0, 1), dxfattribs={"layer": "DOORS"})
    block.add_arc((0, 0), 1, 0, 90, dxfattribs={"layer": "DOORS"})
    msp = doc.modelspace()
    for a, b in [((0, 0), (10, 0)), ((10, 0), (10, 8)), ((10, 8), (0, 8)), ((0, 8), (0, 0))]:
        msp.add_line(a, b, dxfattribs={"layer": "WALLS"})
    msp.add_circle((5, 4), 1.5)
    msp.add_blockref("DOOR", (2, 0))
    msp.add_text("fillyfoal", dxfattribs={"style": "NOTES", "height": 0.5}).set_placement(
        (1, 9), align=TextEntityAlignment.LEFT
    )
    if version != "R12":
        msp.add_lwpolyline([(12, 0), (14, 0), (14, 2)], close=True)
    return doc


def main(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    # ezdxf's own switch for reproducible output: fixed time stamps, GUIDs
    # and marker string instead of the clock and the RNG.
    ezdxf.options.write_fixed_meta_data_for_testing = True
    for version, name, binary in [
        ("R12", "r12.dxf", False),
        ("R2018", "r2018.dxf", False),
        ("R2018", "binary.dxf", True),
    ]:
        doc = drawing(version)
        doc.saveas(out / name, fmt="bin" if binary else "asc")


if __name__ == "__main__":
    main(sys.argv[1])
