"""Writes tests/fixtures/external/parquet/encrypted-footer.parquet with
pyarrow's Parquet modular encryption (AES-GCM, encrypted footer, so the
file starts and ends with `PARE`).

    cd /tmp/fixtures/parquet && uv run --with pyarrow==26.0.0 python3 -I make_encrypted.py

The keys are throwaway constants handed out by a toy in-memory KMS. The
data keys and AES-GCM nonces are random, so the output is not
reproducible byte for byte (only its layout is).
"""

import base64

import pyarrow as pa
import pyarrow.parquet as pq
import pyarrow.parquet.encryption as pe

MASTER_KEYS = {"footer": b"0123456789abcdef", "col": b"fedcba9876543210"}


class ToyKms(pe.KmsClient):
    """Wraps data keys by XOR with a master key: a test KMS, not security."""

    def __init__(self, config):
        pe.KmsClient.__init__(self)

    def wrap_key(self, key, master_key_identifier):
        master = MASTER_KEYS[master_key_identifier]
        return base64.b64encode(bytes(a ^ b for a, b in zip(key, master)))

    def unwrap_key(self, wrapped, master_key_identifier):
        master = MASTER_KEYS[master_key_identifier]
        return bytes(a ^ b for a, b in zip(base64.b64decode(wrapped), master))


t = pa.table({"id": pa.array(range(8), pa.int32()), "name": ["a", "b"] * 4})
factory = pe.CryptoFactory(lambda config: ToyKms(config))
kms = pe.KmsConnectionConfig()
enc = pe.EncryptionConfiguration(
    footer_key="footer",
    column_keys={"col": ["name"]},
    plaintext_footer=False,
    double_wrapping=False,
)
props = factory.file_encryption_properties(kms, enc)
pq.write_table(t, "encrypted-footer.parquet", encryption_properties=props)

# Check it reads back with the same toy KMS.
dec = factory.file_decryption_properties(kms, pe.DecryptionConfiguration())
assert pq.read_table("encrypted-footer.parquet", decryption_properties=dec).equals(t)
