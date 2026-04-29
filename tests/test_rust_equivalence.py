import importlib
import unittest

from krcm import core


class RustEquivalenceTests(unittest.TestCase):
    def setUp(self):
        try:
            self.rust = importlib.import_module("krcm._krcm_rust")
        except ImportError:
            self.skipTest("Rust extension is not built")

    def test_encrypt_decrypt_blocks_match_python_reference(self):
        enc_key = bytes((i * 3 + 1) & 0xFF for i in range(32))
        nonce = bytes((i * 5 + 7) & 0xFF for i in range(core.NONCE_BYTES))
        padded = bytes((i * 11 + 13) & 0xFF for i in range(core.BLOCK_BYTES * 4))

        saved_encrypt = core._rust_encrypt_blocks
        saved_decrypt = core._rust_decrypt_blocks
        try:
            core._rust_encrypt_blocks = None
            core._rust_decrypt_blocks = None
            py_cipher = core._encrypt_blocks(padded, enc_key, nonce, 4)
            rs_cipher = self.rust.encrypt_blocks(padded, enc_key, nonce, 4)
            self.assertEqual(rs_cipher, py_cipher)
            self.assertEqual(self.rust.decrypt_blocks(rs_cipher, enc_key, nonce, 4), padded)
            self.assertEqual(core._decrypt_blocks(py_cipher, enc_key, nonce, 4), padded)
        finally:
            core._rust_encrypt_blocks = saved_encrypt
            core._rust_decrypt_blocks = saved_decrypt


if __name__ == "__main__":
    unittest.main()
