import unittest

from krcm.core import AuthenticationError, decrypt_bytes, encrypt_bytes


class DeterministicRng:
    def __init__(self):
        self.counter = 0

    def __call__(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            out.extend((self.counter + i) & 0xFF for i in range(32))
            self.counter = (self.counter + 32) & 0xFF
        return bytes(out[:n])


class ReferenceRoundTripTests(unittest.TestCase):
    def test_round_trips(self):
        for size in [0, 1, 31, 32, 33, 64, 127, 1024]:
            with self.subTest(size=size):
                data = bytes((i * 17 + size) & 0xFF for i in range(size))
                blob = encrypt_bytes(data, "correct horse battery staple", iterations=1_000, rng=DeterministicRng())
                self.assertEqual(decrypt_bytes(blob, "correct horse battery staple"), data)

    def test_tamper_rejected(self):
        data = b"KRCM reference test" * 4
        blob = bytearray(encrypt_bytes(data, b"pw", iterations=1_000, rng=DeterministicRng()))
        blob[-40] ^= 0x80
        with self.assertRaises(AuthenticationError):
            decrypt_bytes(bytes(blob), b"pw")


if __name__ == "__main__":
    unittest.main()
