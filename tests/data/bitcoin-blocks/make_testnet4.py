#!/usr/bin/env python3
"""Writes tests/fixtures/synthetic/bitcoin-blocks/testnet4-blk00000.dat.

A hand-made block file framed with the testnet4 message start bytes
(1c 16 3f 28, BIP 94). The first block carries the testnet4 genesis header
fields (version 1, time 1714777860, bits 0x1d00ffff, nonce 393743547) with
a zero merkle root and no transactions, so it is not a valid block; the
second block's header is invented. Only the framing is under test.
"""
import pathlib
import struct

MAGIC = bytes.fromhex("1c163f28")


def block(version, prev, merkle, time, bits, nonce):
    header = struct.pack("<I32s32sIII", version, prev, merkle, time, bits, nonce)
    body = header + b"\x00"  # zero transactions
    return MAGIC + struct.pack("<I", len(body)) + body


out = block(1, bytes(32), bytes(32), 1714777860, 0x1D00FFFF, 393743547)
out += block(0x20000000, bytes(range(32)), bytes(32), 1714778000, 0x1D00FFFF, 1)
out += bytes(16)  # preallocated zero tail

root = pathlib.Path(__file__).resolve().parents[2]
dest = root / "fixtures/synthetic/bitcoin-blocks/testnet4-blk00000.dat"
dest.write_bytes(out)
