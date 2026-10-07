"""KeePass KDBX fixtures written by pykeepass (KDBX 4.x and 3.1).

    uv run --with pykeepass==4.2.0 python tests/data/kdbx/make.py OUTDIR

Password "fillyfoal". Key derivations are made cheap on purpose (a few
AES-KDF rounds, Argon2 with 32-64 KiB) so tests stay fast. Seeds, IVs and
UUIDs come from a seeded generator and timestamps are fixed, so a rerun
reproduces the files byte for byte.
"""

import datetime
import random
import sys
import uuid
from pathlib import Path

import pykeepass.kdbx_parsing.common as common
from construct import Container
from pykeepass import PyKeePass, create_database
from pykeepass.kdbx_parsing import kdbx4

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
PASSWORD = "fillyfoal"
NOW = datetime.datetime(2024, 5, 6, 7, 8, 9, tzinfo=datetime.timezone.utc)

rng = random.Random(0)
common.get_random_bytes = lambda n: rng.randbytes(n)
uuid.uuid4 = lambda: uuid.UUID(bytes=rng.randbytes(16), version=4)
uuid.uuid1 = lambda *a, **k: uuid.UUID(bytes=rng.randbytes(16), version=1)


class FixedDatetime(datetime.datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW


for mod in list(sys.modules.values()):
    if (
        mod
        and getattr(mod, "__name__", "").startswith("pykeepass")
        and getattr(mod, "datetime", None) is datetime.datetime
    ):
        mod.datetime = FixedDatetime


def populate(kp, attachments=True):
    root = kp.root_group
    web = kp.add_group(root, "Web")
    mail = kp.add_group(web, "Mail")
    kp.add_group(root, "Empty")
    kp.add_entry(root, "Router", "admin", "hunter2", url="http://192.168.0.1/", notes="Behind the TV")
    e = kp.add_entry(web, "Example", "alice", "correct horse", url="https://example.com/login")
    e.set_custom_property("PIN", "1234", protect=True)
    e.set_custom_property("Account", "A-17")
    m = kp.add_entry(mail, "Mailbox", "alice@example.com", "s3cret", url="imaps://mail.example.com")
    if attachments:
        att = kp.add_binary(b"Hello from an attachment.\n", compressed=False, protected=False)
        m.add_attachment(att, "hello.txt")
    # A second revision of an entry, so the history is not empty.
    m.save_history()
    m.notes = "changed once"


def kdf4(kp, kind, **params):
    d = kp.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
    if kind == "aes":
        d.clear()
        d["$UUID"] = Container(type=0x42, key="$UUID", value=kdbx4.kdf_uuids["aeskdf"], next_byte=0x05)
        d["R"] = Container(type=0x05, key="R", value=params["rounds"], next_byte=0x42)
        d["S"] = Container(type=0x42, key="S", value=rng.randbytes(32), next_byte=0)
    else:
        d["$UUID"].value = kdbx4.kdf_uuids[kind]
        d["I"].value = params["iterations"]
        d["M"].value = params["memory"]
        d["P"].value = params["parallelism"]


def v4(name, kind, cipher, **params):
    kp = create_database(str(OUT / name), password=PASSWORD)
    kp.kdbx.header.value.dynamic_header.cipher_id.data = cipher
    kdf4(kp, kind, **params)
    populate(kp)
    kp.save()
    PyKeePass(str(OUT / name), password=PASSWORD)  # round trip


def v3(name):
    """KDBX 3.1: pykeepass writes whatever header version it holds, so
    swap a KDBX 3 header in (attachments would need Meta/Binaries)."""
    kp = create_database(str(OUT / name), password=PASSWORD)
    populate(kp, attachments=False)
    h = kp.kdbx.header.value

    def item(id, data):
        return Container(id=id, data=data)

    h.major_version = 3
    h.minor_version = 1
    h.dynamic_header = Container(
        cipher_id=item("cipher_id", "aes256"),
        compression_flags=item("compression_flags", Container(compression=True)),
        master_seed=item("master_seed", rng.randbytes(32)),
        transform_seed=item("transform_seed", rng.randbytes(32)),
        transform_rounds=item("transform_rounds", 1000),
        encryption_iv=item("encryption_iv", rng.randbytes(16)),
        protected_stream_key=item("protected_stream_key", rng.randbytes(32)),
        stream_start_bytes=item("stream_start_bytes", rng.randbytes(32)),
        protected_stream_id=item("protected_stream_id", "salsa20"),
        end=item("end", b"\r\n\r\n"),
    )
    kp.kdbx.body.payload = Container(xml=kp.kdbx.body.payload.xml)
    kp.save()
    PyKeePass(str(OUT / name), password=PASSWORD)


v4("argon2d-chacha20.kdbx", "argon2", "chacha20", iterations=2, memory=64 * 1024, parallelism=2)
v4("argon2id-twofish.kdbx", "argon2id", "twofish", iterations=1, memory=32 * 1024, parallelism=1)
v4("aeskdf-aes.kdbx", "aes", "aes256", rounds=1000)
v3("kdbx3.kdbx")
