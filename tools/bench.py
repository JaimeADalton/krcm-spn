from __future__ import annotations

import os
import time

from krcm.core import decrypt_bytes, encrypt_bytes


def main() -> None:
    data = os.urandom(64 * 1024)
    password = b"benchmark-password"
    start = time.perf_counter()
    blob = encrypt_bytes(data, password, iterations=1_000)
    enc = time.perf_counter() - start
    start = time.perf_counter()
    recovered = decrypt_bytes(blob, password)
    dec = time.perf_counter() - start
    assert recovered == data
    print(f"encrypt 64 KiB: {enc:.3f}s")
    print(f"decrypt 64 KiB: {dec:.3f}s")


if __name__ == "__main__":
    main()
