"""
KRCM-SPN: cifrado experimental por sustitución/permutación y matrices 2x2.

IMPORTANTE: no usa AES/ChaCha ni otro cifrado simétrico estándar como motor de cifrado.
Sí usa primitivas estándar de hash/KDF/MAC de la biblioteca estándar para derivar semillas
 y autenticar datos. El diseño de cifrado sigue siendo experimental.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

# Optional native accelerator. The Python implementation remains the reference and
# fallback. Runtime errors from the native module are deliberately not swallowed:
# a native/backend mismatch must fail loudly rather than silently changing behavior.
try:
    from ._krcm_rust import encrypt_blocks as _rust_encrypt_blocks, decrypt_blocks as _rust_decrypt_blocks
except ImportError:  # pragma: no cover - normal when the Rust extension is not built
    _rust_encrypt_blocks = None
    _rust_decrypt_blocks = None


MODULUS = 2 ** 64
BLOCK_BYTES = 32
WORD_COUNT = 4
WORD_BYTES = 8
TAG_BYTES = 32
SALT_BYTES = 16
ROUNDS = 10
NONCE_BYTES = 16
DEFAULT_ITERATIONS = 200_000
MAX_PBKDF2_ITERATIONS = 1_000_000
MAX_HEADER_BYTES = 4096
MAGIC = b"AMPCRYPT"
VERSION = 4
SUPPORTED_VERSIONS = {2, 3, 4}


class AMPCError(Exception):
    """Error base del paquete KRCM-SPN."""


class AuthenticationError(AMPCError):
    """La contraseña, la etiqueta de integridad o el contenedor no son válidos."""


class FormatError(AMPCError):
    """El contenedor cifrado no tiene el formato esperado."""


@dataclass(frozen=True)
class Header:
    version: int
    iterations: int
    salt: bytes
    nonce: bytes
    original_length: int

    def to_json_bytes(self) -> bytes:
        payload = {
            "magic": MAGIC.decode("ascii"),
            "version": self.version,
            "iterations": self.iterations,
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "original_length": self.original_length,
            "block_bytes": BLOCK_BYTES,
            "word_bits": 64,
            "rounds": ROUNDS,
            "construction": "AMPC-AffineSubstitution-Matrix-v3" if self.version == 3 else "AMPC-Permutation-Matrix-v4",
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def from_json_bytes(data: bytes) -> "Header":
        try:
            payload = json.loads(data.decode("utf-8"))
            if payload.get("magic") != MAGIC.decode("ascii"):
                raise FormatError("Magic inválido")
            version = int(payload["version"])
            if version not in SUPPORTED_VERSIONS:
                raise FormatError("Versión no soportada")
            if int(payload["block_bytes"]) != BLOCK_BYTES:
                raise FormatError("Tamaño de bloque no soportado")
            if int(payload.get("rounds", -1)) != ROUNDS:
                raise FormatError("Número de rondas no soportado")
            salt = base64.b64decode(payload["salt"], validate=True)
            nonce = base64.b64decode(payload["nonce"], validate=True)
            if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES:
                raise FormatError("Salt o nonce con longitud inválida")
            original_length = int(payload["original_length"])
            iterations = int(payload["iterations"])
            if original_length < 0 or iterations < 1 or iterations > MAX_PBKDF2_ITERATIONS:
                raise FormatError("Longitudes o iteraciones inválidas")
            return Header(version, iterations, salt, nonce, original_length)
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise FormatError("Cabecera JSON inválida") from exc


def _ensure_bytes(data: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data debe ser bytes, bytearray o memoryview")
    return bytes(data)


def _ensure_password(password: str | bytes) -> bytes:
    if isinstance(password, str):
        encoded = password.encode("utf-8")
    elif isinstance(password, bytes):
        encoded = password
    else:
        raise TypeError("password debe ser str o bytes")
    if not encoded:
        raise ValueError("password no puede estar vacío")
    return encoded


def _safe_name(name: str) -> str:
    if not isinstance(name, str):
        raise TypeError("file_name debe ser str")
    if not name or name.strip() != name:
        raise ValueError("file_name no puede estar vacío ni contener espacios externos")
    path = Path(name)
    if path.name != name or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("file_name debe ser un nombre simple, sin rutas")
    if any(ch in name for ch in ('/', '\\', ':', '\x00')):
        raise ValueError("file_name contiene caracteres no permitidos")
    return name


def _hkdf_expand_like(key: bytes, label: bytes, length: int) -> bytes:
    """Expansor determinista basado en HMAC-SHA256 para semillas internas."""
    if length < 0:
        raise ValueError("length inválido")
    out = bytearray()
    counter = 1
    previous = b""
    while len(out) < length:
        previous = hmac.new(key, previous + label + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        out.extend(previous)
        counter += 1
    return bytes(out[:length])


def _hkdf_expand_64(key: bytes, label: bytes) -> bytes:
    first = hmac.new(key, label + b"\x00\x00\x00\x01", hashlib.sha256).digest()
    second = hmac.new(key, first + label + b"\x00\x00\x00\x02", hashlib.sha256).digest()
    return first + second


def derive_keys(password: str | bytes, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> Tuple[bytes, bytes]:
    """Deriva claves separadas para transformación y autenticación."""
    password_bytes = _ensure_password(password)
    if len(salt) != SALT_BYTES:
        raise ValueError("salt inválido")
    if iterations < 1 or iterations > MAX_PBKDF2_ITERATIONS:
        raise ValueError("iterations fuera de rango")
    root = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, iterations, dklen=64)
    enc_key = hmac.new(root[:32], b"AMPC-ENC", hashlib.sha256).digest()
    auth_key = hmac.new(root[32:], b"AMPC-AUTH", hashlib.sha256).digest()
    return enc_key, auth_key


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(a: int, modulus: int = MODULUS) -> int:
    d, x, _ = extended_gcd(a % modulus, modulus)
    if d != 1:
        raise ValueError("No existe inverso modular")
    return x % modulus


def matrix_det(matrix: Sequence[int]) -> int:
    if len(matrix) != 4:
        raise ValueError("La matriz debe contener 4 enteros")
    a, b, c, d = [int(x) % MODULUS for x in matrix]
    return (a * d - b * c) % MODULUS


def matrix_mul(left: Sequence[int], right: Sequence[int]) -> List[int]:
    if len(left) != 4 or len(right) != 4:
        raise ValueError("Las matrices deben contener 4 enteros")
    a, b, c, d = [int(x) % MODULUS for x in left]
    e, f, g, h = [int(x) % MODULUS for x in right]
    return [
        (a * e + b * g) % MODULUS,
        (a * f + b * h) % MODULUS,
        (c * e + d * g) % MODULUS,
        (c * f + d * h) % MODULUS,
    ]


def matrix_inv(matrix: Sequence[int]) -> List[int]:
    if len(matrix) != 4:
        raise ValueError("La matriz debe contener 4 enteros")
    a, b, c, d = [int(x) % MODULUS for x in matrix]
    det = matrix_det([a, b, c, d])
    inv_det = modinv(det, MODULUS)
    return [
        (d * inv_det) % MODULUS,
        (-b * inv_det) % MODULUS,
        (-c * inv_det) % MODULUS,
        (a * inv_det) % MODULUS,
    ]


def _words_from_block(block: bytes) -> List[int]:
    if len(block) != BLOCK_BYTES:
        raise ValueError("Bloque con longitud incorrecta")
    return list(struct.unpack(">QQQQ", block))


def _block_from_words(words: Sequence[int]) -> bytes:
    if len(words) != WORD_COUNT:
        raise ValueError("Se esperaban cuatro palabras de 64 bits")
    return struct.pack(">QQQQ", *[int(w) % MODULUS for w in words])


def _matrix_from_seed(seed: bytes) -> List[int]:
    material = bytearray(_hkdf_expand_like(seed, b"matrix", 64))
    # Forzamos determinante impar eligiendo diagonal impar y off-diagonal par.
    a = int.from_bytes(material[0:8], "big") | 1
    b = int.from_bytes(material[8:16], "big") & ~1
    c = int.from_bytes(material[16:24], "big") & ~1
    d = int.from_bytes(material[24:32], "big") | 1
    matrix = [a % MODULUS, b % MODULUS, c % MODULUS, d % MODULUS]
    if matrix_det(matrix) % 2 == 0:
        # Defensa adicional: en Z/(2^64), el determinante invertible debe ser impar.
        matrix[3] ^= 1
    return matrix


def _permutation_from_seed(seed: bytes) -> List[int]:
    """Permutación Fisher-Yates determinista de 0..255 basada en HMAC-SHA256."""
    values = list(range(256))
    stream = bytearray()
    cursor = 0

    def take_u64() -> int:
        nonlocal cursor, stream
        if cursor + 8 > len(stream):
            stream.extend(_hkdf_expand_64(seed, b"perm" + len(stream).to_bytes(4, "big")))
        chunk = stream[cursor:cursor + 8]
        cursor += 8
        return int.from_bytes(chunk, "big")

    for i in range(255, 0, -1):
        # Muestreo por rechazo para reducir sesgo de módulo.
        limit = (1 << 64) - ((1 << 64) % (i + 1))
        r = take_u64()
        while r >= limit:
            r = take_u64()
        j = r % (i + 1)
        values[i], values[j] = values[j], values[i]
    return values


def _inverse_permutation(perm: Sequence[int]) -> List[int]:
    inv = [0] * 256
    for i, v in enumerate(perm):
        inv[int(v)] = i
    return inv


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _pad(data: bytes) -> bytes:
    pad_len = BLOCK_BYTES - (len(data) % BLOCK_BYTES)
    if pad_len == 0:
        pad_len = BLOCK_BYTES
    return data + bytes([pad_len]) * pad_len


def _unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_BYTES != 0:
        raise FormatError("Datos con padding inválido")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_BYTES:
        raise AuthenticationError("Padding inválido")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise AuthenticationError("Padding inválido")
    return data[:-pad_len]


def _block_seed(enc_key: bytes, nonce: bytes, block_index: int, feedback: bytes) -> bytes:
    label = b"block" + nonce + block_index.to_bytes(8, "big") + hashlib.sha256(feedback).digest()
    return hmac.new(enc_key, label, hashlib.sha256).digest()


def _pre_substitute(block: bytes, seed: bytes) -> bytes:
    perm = _permutation_from_seed(seed)
    mask = _hkdf_expand_like(seed, b"mask", BLOCK_BYTES)
    out = bytearray(BLOCK_BYTES)
    for i, byte in enumerate(block):
        out[i] = perm[(byte + mask[i]) & 0xFF]
    return bytes(out)


def _post_unsubstitute(block: bytes, seed: bytes) -> bytes:
    perm = _permutation_from_seed(seed)
    inv = _inverse_permutation(perm)
    mask = _hkdf_expand_like(seed, b"mask", BLOCK_BYTES)
    out = bytearray(BLOCK_BYTES)
    for i, byte in enumerate(block):
        out[i] = (inv[byte] - mask[i]) & 0xFF
    return bytes(out)


def _byte_affine_params(seed: bytes) -> Tuple[int, int, int]:
    a = seed[0] | 1
    b = seed[1]
    inv_a = pow(a, -1, 256)
    return a, b, inv_a


def _pre_substitute_v3(block: bytes, seed: bytes) -> bytes:
    mask = _hkdf_expand_like(seed, b"mask", BLOCK_BYTES)
    a, b, _ = _byte_affine_params(seed)
    out = bytearray(BLOCK_BYTES)
    for i, byte in enumerate(block):
        out[i] = (a * ((byte + mask[i]) & 0xFF) + b) & 0xFF
    return bytes(out)


def _post_unsubstitute_v3(block: bytes, seed: bytes) -> bytes:
    mask = _hkdf_expand_like(seed, b"mask", BLOCK_BYTES)
    _, b, inv_a = _byte_affine_params(seed)
    out = bytearray(BLOCK_BYTES)
    for i, byte in enumerate(block):
        out[i] = ((inv_a * ((byte - b) & 0xFF)) - mask[i]) & 0xFF
    return bytes(out)




def _diffuse_bytes(block: bytes, seed: bytes) -> bytes:
    """Capa reversible de difusión byte a byte.

    No añade seguridad por ocultación: solo aumenta la propagación local de cambios antes
    y después de la mezcla matricial. La inversa está implementada explícitamente abajo.
    """
    if len(block) != BLOCK_BYTES:
        raise ValueError("Bloque con longitud incorrecta")
    mask = _hkdf_expand_like(seed, b"diffuse", BLOCK_BYTES * 2)
    state = bytearray(block)
    for i in range(1, BLOCK_BYTES):
        state[i] = (state[i] + state[i - 1] + mask[i]) & 0xFF
    for i in range(BLOCK_BYTES - 2, -1, -1):
        state[i] = (state[i] + state[i + 1] + mask[BLOCK_BYTES + i]) & 0xFF
    return bytes(state)


def _undiffuse_bytes(block: bytes, seed: bytes) -> bytes:
    if len(block) != BLOCK_BYTES:
        raise ValueError("Bloque con longitud incorrecta")
    mask = _hkdf_expand_like(seed, b"diffuse", BLOCK_BYTES * 2)
    state = bytearray(block)
    for i in range(0, BLOCK_BYTES - 1):
        state[i] = (state[i] - state[i + 1] - mask[BLOCK_BYTES + i]) & 0xFF
    for i in range(BLOCK_BYTES - 1, 0, -1):
        state[i] = (state[i] - state[i - 1] - mask[i]) & 0xFF
    return bytes(state)

def _small_permutation(seed: bytes, size: int) -> List[int]:
    values = list(range(size))
    stream = bytearray()
    cursor = 0

    def take_u64() -> int:
        nonlocal cursor, stream
        if cursor + 8 > len(stream):
            stream.extend(_hkdf_expand_64(seed, b"small-perm" + len(stream).to_bytes(4, "big")))
        chunk = stream[cursor:cursor + 8]
        cursor += 8
        return int.from_bytes(chunk, "big")

    for i in range(size - 1, 0, -1):
        limit = (1 << 64) - ((1 << 64) % (i + 1))
        r = take_u64()
        while r >= limit:
            r = take_u64()
        j = r % (i + 1)
        values[i], values[j] = values[j], values[i]
    return values


def _apply_position_permutation(block: bytes, perm: Sequence[int]) -> bytes:
    # out[i] = block[perm[i]]; la inversa reconstruye block[perm[i]] = out[i].
    return bytes(block[perm[i]] for i in range(len(perm)))


def _invert_position_permutation(block: bytes, perm: Sequence[int]) -> bytes:
    out = bytearray(len(perm))
    for i, source in enumerate(perm):
        out[source] = block[i]
    return bytes(out)


def _position_affine_params(seed: bytes) -> Tuple[int, int]:
    a = (seed[2] | 1) & (BLOCK_BYTES - 1)
    b = seed[3] & (BLOCK_BYTES - 1)
    return a or 1, b


def _apply_position_affine(block: bytes, seed: bytes) -> bytes:
    a, b = _position_affine_params(seed)
    return bytes(block[(a * i + b) & (BLOCK_BYTES - 1)] for i in range(BLOCK_BYTES))


def _invert_position_affine(block: bytes, seed: bytes) -> bytes:
    a, b = _position_affine_params(seed)
    out = bytearray(BLOCK_BYTES)
    for i, byte in enumerate(block):
        out[(a * i + b) & (BLOCK_BYTES - 1)] = byte
    return bytes(out)


def _encrypt_one_block(block: bytes, seed: bytes) -> bytes:
    state = block
    for round_index in range(ROUNDS):
        round_seed = hmac.new(seed, b"round" + round_index.to_bytes(2, "big"), hashlib.sha256).digest()
        state = _pre_substitute(state, round_seed)
        state = _diffuse_bytes(state, round_seed)
        words = _words_from_block(state)
        left = _matrix_from_seed(hmac.new(round_seed, b"left", hashlib.sha256).digest())
        right = _matrix_from_seed(hmac.new(round_seed, b"right", hashlib.sha256).digest())
        mixed = matrix_mul(left, matrix_mul(words, right))
        state = _block_from_words(mixed)
        perm = _small_permutation(round_seed, BLOCK_BYTES)
        state = _apply_position_permutation(state, perm)
    return state


def _encrypt_one_block_v3(block: bytes, seed: bytes) -> bytes:
    state = block
    for round_index in range(ROUNDS):
        round_seed = hmac.new(seed, b"round" + round_index.to_bytes(2, "big"), hashlib.sha256).digest()
        state = _pre_substitute_v3(state, round_seed)
        state = _diffuse_bytes(state, round_seed)
        words = _words_from_block(state)
        left = _matrix_from_seed(hmac.new(round_seed, b"left", hashlib.sha256).digest())
        right = _matrix_from_seed(hmac.new(round_seed, b"right", hashlib.sha256).digest())
        mixed = matrix_mul(left, matrix_mul(words, right))
        state = _block_from_words(mixed)
        state = _apply_position_affine(state, round_seed)
    return state


def _decrypt_one_block(block: bytes, seed: bytes) -> bytes:
    state = block
    for round_index in range(ROUNDS - 1, -1, -1):
        round_seed = hmac.new(seed, b"round" + round_index.to_bytes(2, "big"), hashlib.sha256).digest()
        perm = _small_permutation(round_seed, BLOCK_BYTES)
        state = _invert_position_permutation(state, perm)
        words = _words_from_block(state)
        left = _matrix_from_seed(hmac.new(round_seed, b"left", hashlib.sha256).digest())
        right = _matrix_from_seed(hmac.new(round_seed, b"right", hashlib.sha256).digest())
        unmixed = matrix_mul(matrix_inv(left), matrix_mul(words, matrix_inv(right)))
        state = _block_from_words(unmixed)
        state = _undiffuse_bytes(state, round_seed)
        state = _post_unsubstitute(state, round_seed)
    return state


def _decrypt_one_block_v3(block: bytes, seed: bytes) -> bytes:
    state = block
    for round_index in range(ROUNDS - 1, -1, -1):
        round_seed = hmac.new(seed, b"round" + round_index.to_bytes(2, "big"), hashlib.sha256).digest()
        state = _invert_position_affine(state, round_seed)
        words = _words_from_block(state)
        left = _matrix_from_seed(hmac.new(round_seed, b"left", hashlib.sha256).digest())
        right = _matrix_from_seed(hmac.new(round_seed, b"right", hashlib.sha256).digest())
        unmixed = matrix_mul(matrix_inv(left), matrix_mul(words, matrix_inv(right)))
        state = _block_from_words(unmixed)
        state = _undiffuse_bytes(state, round_seed)
        state = _post_unsubstitute_v3(state, round_seed)
    return state


def _encrypt_blocks(padded: bytes, enc_key: bytes, nonce: bytes, version: int = VERSION) -> bytes:
    if _rust_encrypt_blocks is not None and int(version) == 4:
        return _rust_encrypt_blocks(padded, enc_key, nonce, int(version))
    if len(padded) % BLOCK_BYTES != 0:
        raise ValueError("Datos no alineados a bloque")
    ciphertext = bytearray()
    feedback = nonce
    encrypt_block = _encrypt_one_block_v3 if version == 3 else _encrypt_one_block
    for block_index, offset in enumerate(range(0, len(padded), BLOCK_BYTES)):
        block = padded[offset:offset + BLOCK_BYTES]
        seed = _block_seed(enc_key, nonce, block_index, feedback)
        encrypted_block = encrypt_block(block, seed)
        ciphertext.extend(encrypted_block)
        feedback = encrypted_block
    return bytes(ciphertext)


def _decrypt_blocks(ciphertext: bytes, enc_key: bytes, nonce: bytes, version: int) -> bytes:
    if _rust_decrypt_blocks is not None and int(version) == 4:
        return _rust_decrypt_blocks(ciphertext, enc_key, nonce, int(version))
    if len(ciphertext) % BLOCK_BYTES != 0:
        raise FormatError("Texto cifrado no alineado a bloque")
    padded = bytearray()
    feedback = nonce
    decrypt_block = _decrypt_one_block_v3 if version == 3 else _decrypt_one_block
    for block_index, offset in enumerate(range(0, len(ciphertext), BLOCK_BYTES)):
        encrypted_block = ciphertext[offset:offset + BLOCK_BYTES]
        seed = _block_seed(enc_key, nonce, block_index, feedback)
        block = decrypt_block(encrypted_block, seed)
        padded.extend(block)
        feedback = encrypted_block
    return bytes(padded)


def _make_tag(auth_key: bytes, header_bytes: bytes, ciphertext: bytes) -> bytes:
    return hmac.new(auth_key, header_bytes + ciphertext, hashlib.sha256).digest()


def encrypt_bytes(
    data: bytes | bytearray | memoryview,
    password: str | bytes,
    *,
    iterations: int = DEFAULT_ITERATIONS,
    rng: Optional[Callable[[int], bytes]] = None,
) -> bytes:
    """Devuelve un contenedor binario KRCM-SPN v4 autenticado."""
    plain = _ensure_bytes(data)
    if iterations < 1:
        raise ValueError("iterations debe ser positivo")
    random_bytes = rng or secrets.token_bytes
    salt = random_bytes(SALT_BYTES)
    nonce = random_bytes(NONCE_BYTES)
    if len(salt) != SALT_BYTES or len(nonce) != NONCE_BYTES:
        raise ValueError("rng devolvió longitudes inválidas")
    header = Header(VERSION, iterations, salt, nonce, len(plain))
    enc_key, auth_key = derive_keys(password, salt, iterations)
    padded = _pad(plain)
    ciphertext = _encrypt_blocks(padded, enc_key, nonce, VERSION)
    header_bytes = header.to_json_bytes()
    tag = _make_tag(auth_key, header_bytes, ciphertext)
    return MAGIC + struct.pack(">I", len(header_bytes)) + header_bytes + ciphertext + tag


def decrypt_bytes(container: bytes | bytearray | memoryview, password: str | bytes) -> bytes:
    """Descifra un contenedor KRCM-SPN v4. Lanza AuthenticationError si falla."""
    blob = _ensure_bytes(container)
    min_len = len(MAGIC) + 4 + TAG_BYTES
    if len(blob) < min_len:
        raise FormatError("Contenedor demasiado corto")
    if not blob.startswith(MAGIC):
        raise FormatError("Magic inválido")
    header_len = struct.unpack(">I", blob[len(MAGIC):len(MAGIC) + 4])[0]
    start = len(MAGIC) + 4
    end = start + header_len
    if header_len <= 0 or header_len > MAX_HEADER_BYTES or end + TAG_BYTES > len(blob):
        raise FormatError("Longitud de cabecera inválida")
    header_bytes = blob[start:end]
    header = Header.from_json_bytes(header_bytes)
    ciphertext = blob[end:-TAG_BYTES]
    tag = blob[-TAG_BYTES:]
    enc_key, auth_key = derive_keys(password, header.salt, header.iterations)
    expected = _make_tag(auth_key, header_bytes, ciphertext)
    if not hmac.compare_digest(tag, expected):
        raise AuthenticationError("Contraseña incorrecta o contenedor manipulado")
    padded = _decrypt_blocks(ciphertext, enc_key, header.nonce, header.version)
    plain = _unpad(padded)
    if len(plain) != header.original_length:
        raise AuthenticationError("Longitud descifrada inesperada")
    return plain


def encrypt_text(text: str, password: str | bytes, *, encoding: str = "utf-8", **kwargs) -> bytes:
    if not isinstance(text, str):
        raise TypeError("text debe ser str")
    return encrypt_bytes(text.encode(encoding), password, **kwargs)


def decrypt_text(container: bytes | bytearray | memoryview, password: str | bytes, *, encoding: str = "utf-8") -> str:
    return decrypt_bytes(container, password).decode(encoding)


def encrypt_to_file(data: bytes | bytearray | memoryview, password: str | bytes, directory: str | os.PathLike, file_name: str, **kwargs) -> Path:
    name = _safe_name(file_name)
    directory_path = Path(directory)
    directory_path.mkdir(parents=True, exist_ok=True)
    out = directory_path / f"{name}.ampc"
    out.write_bytes(encrypt_bytes(data, password, **kwargs))
    return out


def decrypt_from_file(password: str | bytes, directory: str | os.PathLike, file_name: str) -> bytes:
    name = _safe_name(file_name)
    path = Path(directory) / f"{name}.ampc"
    return decrypt_bytes(path.read_bytes(), password)


# Compatibilidad deliberadamente delgada con los nombres anteriores.
ENCRYPTED_FILES_PATH = os.path.join(os.getcwd(), "KRCM_FILES")


def encrypt_process(plain_text: str, key_word: str, file_name: str, **kwargs) -> None:
    encrypted = encrypt_text(plain_text, key_word, **kwargs)
    Path(ENCRYPTED_FILES_PATH).mkdir(parents=True, exist_ok=True)
    safe = _safe_name(file_name)
    (Path(ENCRYPTED_FILES_PATH) / f"{safe}.ampc").write_bytes(encrypted)


def decrypt_process(key_word: str, file_name: str) -> Optional[str]:
    try:
        safe = _safe_name(file_name)
        blob = (Path(ENCRYPTED_FILES_PATH) / f"{safe}.ampc").read_bytes()
        return decrypt_text(blob, key_word)
    except (AMPCError, OSError, UnicodeDecodeError, ValueError):
        return None
