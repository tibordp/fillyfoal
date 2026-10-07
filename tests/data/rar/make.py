"""Writes the compressed RAR fixtures in tests/fixtures/synthetic/rar/ with
our test encoder (`rarenc.py`): no RAR compressor is available. Each archive
is checked with libarchive (`bsdtar -xf`, an independent RAR decoder) where
libarchive supports what it holds:

    uv run --with pyppmd==1.3.1 python tests/data/rar/make.py

libarchive 3.7 does not decode RAR 4 solid files ("RAR solid archive
support unavailable"), and does not reset the RAR 3 low-distance repeat
state when it reads new tables (unrar and 7-Zip do), so `v4-solid.rar`
and the multi-table low-distance repeats are checked by our decoder only.

The PPMd fixture encodes its symbols with 7-Zip's PPMd encoder (pyppmd)
and re-encodes the range coder's operations with RAR's coder; that step
runs our decoder's PPMd model (`cargo test ppmd_rar_stream`), which the
unit tests check against 7-Zip byte for byte.
"""

import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..", "..")
OUT = os.path.join(ROOT, "tests", "fixtures", "synthetic", "rar")
sys.path.insert(0, HERE)

import rarenc  # noqa: E402

WORDS = (
    b"the of and to in is that for it as was with be by on not he this are or his from at "
    b"which but have an they you were her she there been one all we their has would when if "
    b"so no will can more other into some could them than then its time only new these two"
).split()


def text(rng, size):
    out = bytearray()
    line = 0
    while len(out) < size:
        out += rng.choice(WORDS)
        line += 1
        out += b"\n" if line % 12 == 0 else b" "
    return bytes(out[:size])


def x86(rng, size):
    """Bytes with CALL/JMP opcodes and ARM BL words sprinkled in."""
    out = bytearray(text(rng, size))
    for _ in range(size // 24):
        p = rng.randrange(size - 5)
        out[p] = rng.choice([0xE8, 0xE9])
        out[p + 1 : p + 5] = rng.randrange(-4000, 4000).to_bytes(4, "little", signed=True)
    for _ in range(size // 48):
        p = rng.randrange(size - 4) & ~3
        out[p + 3] = 0xEB
    return bytes(out)


def samples(rng, size):
    """16-bit stereo-ish audio and an RGB gradient."""
    out = bytearray()
    v = 0
    for i in range(size):
        v = (v + rng.randrange(-3, 4)) & 0xFF
        out.append((v + (i % 4) * 10) & 0xFF)
    return bytes(out)


def check(path, files, verify=True):
    if not verify:
        return
    with tempfile.TemporaryDirectory() as d:
        r = subprocess.run(["bsdtar", "-xf", path, "-C", d], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        for name, data in files:
            with open(os.path.join(d, name), "rb") as f:
                assert f.read() == data, name
    print("libarchive ok:", os.path.basename(path))


def write(name, arc, files, verify=True):
    path = os.path.join(OUT, name)
    with open(path, "wb") as f:
        f.write(arc)
    print(name, len(arc))
    check(path, files, verify)


def v5_normal():
    rng = random.Random(5)
    a = text(rng, 6000)
    b = x86(rng, 2400)
    # Filters on b: E8 over the first part, DELTA (2 channels), ARM.
    enc = rarenc.e8_encode(b[:800], 0, False, True)
    enc += rarenc.delta_encode(b[800:1400], 2)
    enc += rarenc.arm_encode(b[1400:2000], 1400)
    enc += rarenc.e8_encode(b[2000:], 2000, True, True)
    filters = {1: [(0, 800, 1, 1), (800, 600, 0, 2), (1400, 600, 3, 1), (2000, 400, 2, 1)]}
    packed = rarenc.compress5([a, enc], False, rng, block_tokens=700, filters=filters)
    files = [("text.txt", a), ("code.bin", b)]
    entries = [(n, p, d, 3, 1, False, 0) for (n, d), p in zip(files, packed)]
    write("v5-normal.rar", rarenc.rar5(entries), files)


def v5_solid():
    rng = random.Random(6)
    parts = [text(rng, 2500), text(rng, 1800), text(rng, 2200)]
    packed = rarenc.compress5(parts, True, rng, block_tokens=900)
    files = [("one.txt", parts[0]), ("two.txt", parts[1]), ("stored.txt", b"stored, not compressed\n"), ("three.txt", parts[2])]
    entries = [
        ("one.txt", packed[0], parts[0], 3, 2, False, 0),
        ("two.txt", packed[1], parts[1], 3, 2, True, 0),
        ("stored.txt", files[2][1], files[2][1], 0, 2, False, 0),
        ("three.txt", packed[2], parts[2], 3, 2, True, 0),
    ]
    write("v5-solid.rar", rarenc.rar5(entries, solid=True), files)


def v4_normal():
    rng = random.Random(4)
    a = text(rng, 5000)
    b = x86(rng, 1500)
    c = samples(rng, 1800)
    enc_b = rarenc.e8_encode(b[:700], 0, False, False) + rarenc.e8_encode(b[700:], 700, True, False)
    enc_c = (
        rarenc.delta_encode(c[:600], 2)
        + rarenc.rgb_encode(c[600:1200], 30, 1)
        + rarenc.audio_encode(c[1200:], 2)
    )
    filters = {
        1: [(0, 700, "e8", {}), (700, 800, "e8e9", {})],
        2: [(0, 600, "delta", {0: 2}), (600, 600, "rgb", {0: 33, 1: 1}), (1200, 600, "audio", {0: 2})],
    }
    # One table per file (block_tokens large): libarchive agrees on
    # low-distance repeats then.
    packed = rarenc.compress3([a, enc_b, enc_c], False, rng, block_tokens=100000, filters=filters)
    files = [("text.txt", a), ("code.bin", b), ("samples.bin", c)]
    entries = [(n, p, d, 0x33, 1, False, 29) for (n, d), p in zip(files, packed)]
    arc = rarenc.rar4(entries)
    write("v4-normal.rar", arc, files, verify=False)
    # libarchive keeps filter state across files: check each file's stream
    # in an archive of its own.
    for (n, d), p in zip(files, packed):
        one = rarenc.rar4([(n, p, d, 0x33, 1, False, 29)])
        tmp = os.path.join(tempfile.gettempdir(), "fillyfoal-rar-check.rar")
        with open(tmp, "wb") as f:
            f.write(one)
        check(tmp, [(n, d)])


def v4_solid():
    rng = random.Random(7)
    parts = [text(rng, 2000), text(rng, 1500), text(rng, 2500), text(rng, 900)]
    packed = rarenc.compress3(parts, True, rng, block_tokens=600)
    files = [(f"part{i}.txt", d) for i, d in enumerate(parts)]
    entries = [(n, p, d, 0x33, 2, i > 0, 29) for i, ((n, d), p) in enumerate(zip(files, packed))]
    write("v4-solid.rar", rarenc.rar4(entries, solid=True), files, verify=False)


def ppm_symbols(data):
    """RAR PPMd symbols for `data`: the escape byte (2) doubled as 2, 1;
    runs as 2, 5, n (n + 4 copies of the byte before); repeats of 32+ bytes
    as 2, 4, distance (3 bytes, - 2), length - 32; then 2, 2 (end of file)."""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        # A long repeat from earlier?
        best = None
        if i >= 64:
            for d in (1000, 500, 250, 128, 64):
                if i - d >= 0:
                    k = 0
                    while i + k < n and k < 255 + 32 and data[i - d + k] == data[i + k]:
                        k += 1
                    if k >= 32 and (best is None or k > best[0]):
                        best = (k, d)
        if best:
            k, d = best
            out += bytes([2, 4, (d - 2) >> 16 & 0xFF, (d - 2) >> 8 & 0xFF, (d - 2) & 0xFF, k - 32])
            i += k
            continue
        b = data[i]
        run = 1
        while i + run < n and data[i + run] == b and run < 260:
            run += 1
        out += bytes([2, 1]) if b == 2 else bytes([b])
        if run - 1 >= 4:
            out += bytes([2, 5, run - 1 - 4])
            i += run
        else:
            i += 1
    out += bytes([2, 2])
    return bytes(out)


def v4_ppmd():
    import pyppmd

    rng = random.Random(8)
    data = text(rng, 3000) + b"\x02 escape \x02\x02 bytes " + b"=" * 40 + text(rng, 1500) + text(random.Random(8), 600)
    syms = ppm_symbols(data)
    order, mb = 6, 1
    enc = pyppmd.Ppmd7Encoder(order, mb << 20)
    seven = enc.encode(syms) + enc.flush(endmark=False)
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "in.bin")
        dst = os.path.join(d, "out.bin")
        with open(src, "wb") as f:
            f.write(seven)
        env = dict(os.environ, RAR_PPMD=f"{src},{len(syms)},{order},{mb << 20},{dst}", CARGO_INCREMENTAL="0")
        cargo = os.environ.get("CARGO", "cargo").split()
        subprocess.run(cargo + ["test", "--lib", "ppmd_rar_stream", "--", "--ignored"], cwd=ROOT, env=env, check=True)
        with open(dst, "rb") as f:
            coded = f.read()
    # PPMd block header: PPMd flag, reset, order - 1; memory in MiB - 1.
    packed = bytes([0x80 | 0x20 | (order - 1), mb - 1]) + coded
    files = [("ppmd.txt", data)]
    write("v4-ppmd.rar", rarenc.rar4([("ppmd.txt", packed, data, 0x35, 2, False, 29)]), files)


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    v5_normal()
    v5_solid()
    v4_normal()
    v4_solid()
    v4_ppmd()
