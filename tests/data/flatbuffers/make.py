"""Writes the external FlatBuffers fixtures with the Python `flatbuffers`
package's Builder (no flatc, no generated code). The layout follows the
`monster.fbs` tutorial schema:

    table Monster { pos: Vec3 (struct); mana: short = 150; hp: short = 100;
      name: string; friendly: bool (deprecated); inventory: [ubyte];
      color: Color (ubyte) = Blue; weapons: [Weapon]; equipped: Equipment
      (union: type ubyte + table); path: [Vec3]; score: double; id: ulong;
      tags: [string]; }
    table Weapon { name: string; damage: short; }

    uv run --with flatbuffers==25.12.19 python make.py
"""

import os

import flatbuffers

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "..", "fixtures", "external", "flatbuffers")


def vec3(b, x, y, z):
    b.Prep(4, 12)
    b.PrependFloat32(z)
    b.PrependFloat32(y)
    b.PrependFloat32(x)
    return b.Offset()


def weapon(b, name, damage):
    n = b.CreateString(name)
    b.StartObject(2)
    b.PrependUOffsetTRelativeSlot(0, n, 0)
    b.PrependInt16Slot(1, damage, 0)
    return b.EndObject()


def monster(b):
    name = b.CreateString("Orc")
    inventory = b.CreateByteVector(bytes(range(10)))
    sword = weapon(b, "Sword", 3)
    axe = weapon(b, "Axe", 5)
    b.StartVector(4, 2, 4)
    b.PrependUOffsetTRelative(axe)
    b.PrependUOffsetTRelative(sword)
    weapons = b.EndVector()
    tags = [b.CreateString(t) for t in ("green", "angry")]
    b.StartVector(4, len(tags), 4)
    for t in reversed(tags):
        b.PrependUOffsetTRelative(t)
    tag_vec = b.EndVector()
    b.StartVector(12, 2, 4)
    vec3(b, 4.0, 5.0, 6.0)
    vec3(b, 1.0, 2.0, 3.0)
    path = b.EndVector()

    b.StartObject(14)
    b.PrependStructSlot(0, vec3(b, 1.0, 2.0, 3.0), 0)
    b.PrependInt16Slot(2, 300, 100)
    b.PrependUOffsetTRelativeSlot(3, name, 0)
    b.PrependUOffsetTRelativeSlot(5, inventory, 0)
    b.PrependUint8Slot(6, 2, 2)  # the default: not written
    b.PrependUOffsetTRelativeSlot(7, weapons, 0)
    b.PrependUint8Slot(8, 1, 0)  # equipped_type = Weapon
    b.PrependUOffsetTRelativeSlot(9, axe, 0)
    b.PrependUOffsetTRelativeSlot(10, path, 0)
    b.PrependFloat64Slot(11, 3.5, 0.0)
    b.PrependUint64Slot(12, 0x0123456789ABCDEF, 0)
    b.PrependUOffsetTRelativeSlot(13, tag_vec, 0)
    return b.EndObject()


def write(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)


b = flatbuffers.Builder(0)
b.Finish(monster(b), file_identifier=b"MONS")
write("monster.mon", b.Output())

b = flatbuffers.Builder(0)
b.FinishSizePrefixed(monster(b))
write("monster-size-prefixed.bin", b.Output())

# A long vector of strings, for paging.
b = flatbuffers.Builder(0)
items = [b.CreateString(format(i, "x")) for i in range(1100)]
b.StartVector(4, len(items), 4)
for t in reversed(items):
    b.PrependUOffsetTRelative(t)
vec = b.EndVector()
b.StartObject(1)
b.PrependUOffsetTRelativeSlot(0, vec, 0)
b.Finish(b.EndObject())
write("series.bin", b.Output())
