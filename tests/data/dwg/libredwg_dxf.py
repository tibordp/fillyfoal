"""Writes the DXF drawing that make-libredwg.sh converts to DWG.

    PYTHONHASHSEED=0 uv run --with ezdxf==1.4.4 python -I tests/data/dwg/libredwg_dxf.py OUT.dxf

An R2000 DXF: a layer, three lines on it, a circle, a text and a block
(a circle and a line) inserted once. Dates and GUIDs are pinned with
ezdxf's `write_fixed_meta_data_for_testing`; the hash seed pins the order
of the CLASSES section.
"""

import sys

import ezdxf


def main():
    # Set before the document exists: it also pins the creation stamp.
    ezdxf.options.write_fixed_meta_data_for_testing = True
    doc = ezdxf.new("R2000", setup=False)
    doc.header["$LASTSAVEDBY"] = "fillyfoal"
    doc.layers.add("Walls", color=1)
    block = doc.blocks.new("Marker")
    block.add_circle((0, 0), 0.5)
    block.add_line((-0.5, 0), (0.5, 0))
    msp = doc.modelspace()
    for a, b in [((0, 0), (10, 0)), ((10, 0), (10, 5)), ((10, 5), (0, 5))]:
        msp.add_line(a, b, dxfattribs={"layer": "Walls"})
    msp.add_circle((5, 2.5), 1.5)
    msp.add_text("fillyfoal", dxfattribs={"height": 0.5, "insert": (1, 1)})
    msp.add_blockref("Marker", (2, 4))
    doc.saveas(sys.argv[1])


if __name__ == "__main__":
    main()
