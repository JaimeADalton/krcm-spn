import json
import struct
import unittest
from pathlib import Path

from krcm import core


WARNING = "Test vector only. Password and data are not secret."
VECTOR_ROOT = Path(__file__).resolve().parents[1] / "test-vectors" / "v4"


class ReplayRng:
    def __init__(self, chunks):
        self.chunks = [bytes.fromhex(chunk) for chunk in chunks]

    def __call__(self, n):
        if not self.chunks:
            raise AssertionError("rng exhausted")
        chunk = self.chunks.pop(0)
        if len(chunk) != n:
            raise AssertionError(f"rng returned {len(chunk)} bytes, expected {n}")
        return chunk


def parse_container(container):
    header_len = struct.unpack(">I", container[len(core.MAGIC):len(core.MAGIC) + 4])[0]
    start = len(core.MAGIC) + 4
    end = start + header_len
    return container[start:end], container[end:-core.TAG_BYTES], container[-core.TAG_BYTES:]


class V4VectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.container_vectors = json.loads((VECTOR_ROOT / "container_vectors.json").read_text())
        cls.block_vector = json.loads((VECTOR_ROOT / "block_vectors.json").read_text())

    def test_container_vectors_have_required_cases_and_warning(self):
        self.assertEqual(len(self.container_vectors), 12)
        for vector in self.container_vectors:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(vector["version"], 4)
                self.assertEqual(vector["warning"], WARNING)
                for field in [
                    "password_hex",
                    "plaintext_hex",
                    "rng_outputs_hex",
                    "container_hex",
                    "container_sha256",
                    "header_hex",
                    "ciphertext_hex",
                    "tag_hex",
                ]:
                    self.assertIn(field, vector)

    def test_container_vectors_decrypt_and_reproduce_exactly(self):
        for vector in self.container_vectors:
            with self.subTest(vector=vector["name"]):
                password = bytes.fromhex(vector["password_hex"])
                plaintext = bytes.fromhex(vector["plaintext_hex"])
                container = bytes.fromhex(vector["container_hex"])
                self.assertEqual(core.decrypt_bytes(container, password), plaintext)

                regenerated = core.encrypt_bytes(
                    plaintext,
                    password,
                    iterations=1_000,
                    rng=ReplayRng(vector["rng_outputs_hex"]),
                )
                self.assertEqual(regenerated, container)
                header, ciphertext, tag = parse_container(container)
                self.assertEqual(header.hex(), vector["header_hex"])
                self.assertEqual(ciphertext.hex(), vector["ciphertext_hex"])
                self.assertEqual(tag.hex(), vector["tag_hex"])

    def test_block_vector_encrypts_and_decrypts(self):
        vector = self.block_vector
        self.assertEqual(vector["version"], 4)
        self.assertEqual(vector["warning"], WARNING)
        enc_key = bytes.fromhex(vector["enc_key_hex"])
        nonce = bytes.fromhex(vector["nonce_hex"])
        padded = bytes.fromhex(vector["padded_plaintext_hex"])
        ciphertext = bytes.fromhex(vector["ciphertext_hex"])
        self.assertEqual(core._encrypt_blocks(padded, enc_key, nonce, 4), ciphertext)
        self.assertEqual(core._decrypt_blocks(ciphertext, enc_key, nonce, 4), padded)
        self.assertEqual(bytes.fromhex(vector["decrypted_padded_plaintext_hex"]), padded)


if __name__ == "__main__":
    unittest.main()
