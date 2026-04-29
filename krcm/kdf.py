"""Password-based key derivation helpers for KRCM-SPN experimental formats.

These helpers do not make the experimental cipher construction standard or approved.
They only harden the password-to-key step against offline guessing.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Tuple

from .core import MAX_PBKDF2_ITERATIONS, SALT_BYTES, _ensure_password

KDF_PBKDF2_SHA256 = 1
KDF_SCRYPT_SHA256 = 2

SCRYPT_DEFAULT_N = 2 ** 14
SCRYPT_DEFAULT_R = 8
SCRYPT_DEFAULT_P = 1
SCRYPT_MAX_N = 2 ** 15
SCRYPT_MAX_R = 8
SCRYPT_MAX_P = 2
SCRYPT_MAXMEM = 64 * 1024 * 1024
SCRYPT_DKLEN = 64


@dataclass(frozen=True)
class KDFParams:
    kdf_id: int = KDF_SCRYPT_SHA256
    n: int = SCRYPT_DEFAULT_N
    r: int = SCRYPT_DEFAULT_R
    p: int = SCRYPT_DEFAULT_P

    def validate(self) -> None:
        if self.kdf_id not in (KDF_PBKDF2_SHA256, KDF_SCRYPT_SHA256):
            raise ValueError("KDF no soportada")
        if self.kdf_id == KDF_SCRYPT_SHA256:
            if self.n < 2 or self.n & (self.n - 1):
                raise ValueError("scrypt N debe ser potencia de dos")
            if self.r < 1 or self.p < 1:
                raise ValueError("scrypt r y p deben ser positivos")
            if self.n > SCRYPT_MAX_N or self.r > SCRYPT_MAX_R or self.p > SCRYPT_MAX_P:
                raise ValueError("scrypt excede el perfil máximo permitido")
        else:
            if self.n < 1 or self.n > MAX_PBKDF2_ITERATIONS:
                raise ValueError("PBKDF2 iterations fuera de rango")


def _split_root(root: bytes, domain: bytes = b"AMPC-KDF-V1") -> Tuple[bytes, bytes]:
    enc_key = hmac.new(root[:32], domain + b"-ENC", hashlib.sha256).digest()
    auth_key = hmac.new(root[32:], domain + b"-AUTH", hashlib.sha256).digest()
    return enc_key, auth_key


def derive_keys_kdf(password: str | bytes, salt: bytes, params: KDFParams) -> Tuple[bytes, bytes]:
    params.validate()
    password_bytes = _ensure_password(password)
    if len(salt) != SALT_BYTES:
        raise ValueError("salt invalido")
    if params.kdf_id == KDF_SCRYPT_SHA256:
        root = hashlib.scrypt(
            password_bytes,
            salt=salt,
            n=params.n,
            r=params.r,
            p=params.p,
            dklen=SCRYPT_DKLEN,
            maxmem=SCRYPT_MAXMEM,
        )
        return _split_root(root, b"AMPC-SCRYPT-V1")
    root = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, params.n, dklen=SCRYPT_DKLEN)
    return _split_root(root, b"AMPC-PBKDF2-V1")
