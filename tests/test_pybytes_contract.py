import importlib
import unittest


class PyBytesContractTests(unittest.TestCase):
    def setUp(self):
        try:
            self.krcm_rust = importlib.import_module("krcm._krcm_rust")
        except ImportError:
            self.skipTest("Rust Python bindings are not built")

    def test_encrypt_returns_bytes(self):
        ct = self.krcm_rust.encrypt_bytes(b"hello world", b"testpassword")
        self.assertIsInstance(ct, bytes)
        self.assertGreater(len(ct), 0)

    def test_decrypt_returns_bytes(self):
        ct = self.krcm_rust.encrypt_bytes(b"hello world", b"testpassword")
        pt = self.krcm_rust.decrypt_bytes(ct, b"testpassword")
        self.assertIsInstance(pt, bytes)
        self.assertEqual(pt, b"hello world")

    def test_roundtrip_empty(self):
        ct = self.krcm_rust.encrypt_bytes(b"", b"pass")
        pt = self.krcm_rust.decrypt_bytes(ct, b"pass")
        self.assertIsInstance(pt, bytes)
        self.assertEqual(pt, b"")

    def test_roundtrip_binary(self):
        data = bytes(range(256))
        ct = self.krcm_rust.encrypt_bytes(data, b"pass")
        pt = self.krcm_rust.decrypt_bytes(ct, b"pass")
        self.assertIsInstance(pt, bytes)
        self.assertEqual(pt, data)


if __name__ == "__main__":
    unittest.main()
