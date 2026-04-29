"""Generate deterministic KRCM-SPN v4 test vectors from the Python reference."""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from krcm import core


WARNING = "Test vector only. Password and data are not secret."


class FixedRng:
    def __init__(self, chunks: list[bytes]):
        self.chunks = list(chunks)
        self.outputs: list[bytes] = []

    def __call__(self, n: int) -> bytes:
        if not self.chunks:
            raise RuntimeError("rng exhausted")
        chunk = self.chunks.pop(0)
        if len(chunk) != n:
            raise RuntimeError(f"rng chunk has {len(chunk)} bytes, expected {n}")
        self.outputs.append(chunk)
        return chunk


def pattern(size: int) -> bytes:
    return bytes((i * 17 + size) & 0xFF for i in range(size))


def binary_repeated(size: int) -> bytes:
    base = bytes(range(256))
    return (base * ((size + len(base) - 1) // len(base)))[:size]


def parse_container(container: bytes) -> tuple[bytes, bytes, bytes]:
    if not container.startswith(core.MAGIC):
        raise RuntimeError("unexpected magic")
    header_len = struct.unpack(">I", container[len(core.MAGIC):len(core.MAGIC) + 4])[0]
    header_start = len(core.MAGIC) + 4
    header_end = header_start + header_len
    header = container[header_start:header_end]
    ciphertext = container[header_end:-core.TAG_BYTES]
    tag = container[-core.TAG_BYTES:]
    return header, ciphertext, tag


def container_vectors() -> list[dict[str, object]]:
    cases: list[tuple[str, bytes]] = [
        ("v4-empty", b""),
        ("v4-1-byte", pattern(1)),
        ("v4-31-bytes", pattern(31)),
        ("v4-32-bytes", pattern(32)),
        ("v4-33-bytes", pattern(33)),
        ("v4-63-bytes", pattern(63)),
        ("v4-64-bytes", pattern(64)),
        ("v4-65-bytes", pattern(65)),
        ("v4-127-bytes", pattern(127)),
        ("v4-1024-bytes", pattern(1024)),
        ("v4-65536-bytes", pattern(65536)),
        ("v4-binary-00-ff-repeated", binary_repeated(4096)),
    ]
    vectors: list[dict[str, object]] = []
    for index, (name, plaintext) in enumerate(cases):
        password = f"krcm-vector-password-{index}".encode("utf-8")
        salt = hashlib.sha256(b"salt" + index.to_bytes(4, "big")).digest()[:core.SALT_BYTES]
        nonce = hashlib.sha256(b"nonce" + index.to_bytes(4, "big")).digest()[:core.NONCE_BYTES]
        rng = FixedRng([salt, nonce])
        container = core.encrypt_bytes(
            plaintext,
            password,
            iterations=1_000,
            rng=rng,
        )
        header, ciphertext, tag = parse_container(container)
        vectors.append(
            {
                "name": name,
                "version": core.VERSION,
                "password_hex": password.hex(),
                "plaintext_hex": plaintext.hex(),
                "rng_outputs_hex": [chunk.hex() for chunk in rng.outputs],
                "container_hex": container.hex(),
                "container_sha256": hashlib.sha256(container).hexdigest(),
                "header_hex": header.hex(),
                "ciphertext_hex": ciphertext.hex(),
                "tag_hex": tag.hex(),
                "warning": WARNING,
            }
        )
    return vectors


def block_vectors() -> dict[str, object]:
    enc_key = hashlib.sha256(b"krcm-v4-block-enc-key").digest()
    nonce = hashlib.sha256(b"krcm-v4-block-nonce").digest()[:core.NONCE_BYTES]
    padded_plaintext = core._pad(binary_repeated(96) + b"block-vector")
    ciphertext = core._encrypt_blocks(padded_plaintext, enc_key, nonce, core.VERSION)
    decrypted = core._decrypt_blocks(ciphertext, enc_key, nonce, core.VERSION)
    if decrypted != padded_plaintext:
        raise RuntimeError("block decrypt mismatch")
    return {
        "version": core.VERSION,
        "enc_key_hex": enc_key.hex(),
        "nonce_hex": nonce.hex(),
        "padded_plaintext_hex": padded_plaintext.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "decrypted_padded_plaintext_hex": decrypted.hex(),
        "warning": WARNING,
    }


def main() -> None:
    root = Path("test-vectors/v4")
    root.mkdir(parents=True, exist_ok=True)
    (root / "container_vectors.json").write_text(
        json.dumps(container_vectors(), indent=2) + "\n",
        encoding="utf-8",
    )
    (root / "block_vectors.json").write_text(
        json.dumps(block_vectors(), indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
