"""Formato compacto heredado para KRCM-SPN.

Mantiene la transformación experimental actual de `core.py`, pero sustituye la cabecera
JSON por una cabecera binaria fija para reducir sobrecoste en ficheros pequeños.

No usa cifradores simétricos estándar. Reutiliza la construcción propia del núcleo:
sustitución/permutación, difusión, mezcla matricial 2x2 módulo 2^64 y encadenamiento por bloque.
"""
from __future__ import annotations

import hmac
import secrets
import struct
from typing import Callable, Optional

from .core import (
    AuthenticationError,
    DEFAULT_ITERATIONS,
    FormatError,
    MAX_PBKDF2_ITERATIONS,
    SALT_BYTES,
    NONCE_BYTES,
    TAG_BYTES,
    derive_keys,
    _ensure_bytes,
    _encrypt_blocks,
    _decrypt_blocks,
    _make_tag,
    _pad,
    _unpad,
)

COMPACT_MAGIC = b"AMPCMPCT"
COMPACT_VERSION = 4
SUPPORTED_COMPACT_VERSIONS = {3, 4}
COMPACT_HEADER = struct.Struct(">BIQ16s16s")
# version:uint8, iterations:uint32, original_length:uint64, salt:16, nonce:16
COMPACT_HEADER_BYTES = COMPACT_HEADER.size
COMPACT_OVERHEAD_BYTES = len(COMPACT_MAGIC) + COMPACT_HEADER_BYTES + TAG_BYTES


def _pack_header(iterations: int, original_length: int, salt: bytes, nonce: bytes) -> bytes:
    if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES:
        raise ValueError("salt o nonce inválido")
    if iterations < 1 or iterations > MAX_PBKDF2_ITERATIONS:
        raise ValueError("iterations fuera de rango para formato compacto")
    if original_length < 0 or original_length > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("longitud original fuera de rango")
    return COMPACT_HEADER.pack(COMPACT_VERSION, iterations, original_length, salt, nonce)


def _unpack_header(header: bytes) -> tuple[int, int, int, bytes, bytes]:
    if len(header) != COMPACT_HEADER_BYTES:
        raise FormatError("Cabecera compacta con longitud inválida")
    version, iterations, original_length, salt, nonce = COMPACT_HEADER.unpack(header)
    if version not in SUPPORTED_COMPACT_VERSIONS:
        raise FormatError("Versión compacta no soportada")
    if iterations < 1 or iterations > MAX_PBKDF2_ITERATIONS:
        raise FormatError("Iteraciones inválidas")
    if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES:
        raise FormatError("Salt o nonce inválido")
    return version, iterations, original_length, salt, nonce


def encrypt_bytes_compact(
    data: bytes | bytearray | memoryview,
    password: str | bytes,
    *,
    iterations: int = DEFAULT_ITERATIONS,
    rng: Optional[Callable[[int], bytes]] = None,
) -> bytes:
    """Cifra bytes usando cabecera binaria fija y autenticada."""
    plain = _ensure_bytes(data)
    random_bytes = rng or secrets.token_bytes
    salt = random_bytes(SALT_BYTES)
    nonce = random_bytes(NONCE_BYTES)
    if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES:
        raise ValueError("rng devolvió longitudes inválidas")
    enc_key, auth_key = derive_keys(password, salt, iterations)
    header = _pack_header(iterations, len(plain), salt, nonce)
    ciphertext = _encrypt_blocks(_pad(plain), enc_key, nonce, COMPACT_VERSION)
    tag = _make_tag(auth_key, header, ciphertext)
    return COMPACT_MAGIC + header + ciphertext + tag


def decrypt_bytes_compact(container: bytes | bytearray | memoryview, password: str | bytes) -> bytes:
    """Descifra el formato compacto. Lanza AuthenticationError si falla la autenticación."""
    blob = _ensure_bytes(container)
    min_len = len(COMPACT_MAGIC) + COMPACT_HEADER_BYTES + TAG_BYTES
    if len(blob) < min_len:
        raise FormatError("Contenedor compacto demasiado corto")
    if not blob.startswith(COMPACT_MAGIC):
        raise FormatError("Magic compacto inválido")
    header_start = len(COMPACT_MAGIC)
    header_end = header_start + COMPACT_HEADER_BYTES
    header = blob[header_start:header_end]
    version, iterations, original_length, salt, nonce = _unpack_header(header)
    ciphertext = blob[header_end:-TAG_BYTES]
    tag = blob[-TAG_BYTES:]
    enc_key, auth_key = derive_keys(password, salt, iterations)
    expected = _make_tag(auth_key, header, ciphertext)
    if not hmac.compare_digest(tag, expected):
        raise AuthenticationError("Contraseña incorrecta o contenedor compacto manipulado")
    plain = _unpad(_decrypt_blocks(ciphertext, enc_key, nonce, version))
    if len(plain) != original_length:
        raise AuthenticationError("Longitud descifrada inesperada")
    return plain
