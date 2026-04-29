"""CLI mínima para KRCM-SPN.

Cifra y descifra ficheros con el contenedor `core` (PBKDF2-HMAC-SHA256 + HMAC).
El motor sigue siendo experimental: no debe presentarse como cifrado aprobado
para producción.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from .core import AMPCError, encrypt_bytes, decrypt_bytes


def _atomic_write(path: Path, data: bytes, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"no se sobrescribe sin --force: {path}")
    tmp = path.with_name(path.name + ".tmp")
    try:
        with open(tmp, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="KRCM-SPN experimental encryption CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("input", type=Path)
        p.add_argument("output", type=Path)
        p.add_argument("--force", action="store_true", help="permitir sobrescribir salida")

    enc = sub.add_parser("encrypt")
    common(enc)
    enc.add_argument("--confirm-password", action="store_true")

    dec = sub.add_parser("decrypt")
    common(dec)

    args = parser.parse_args(argv)
    try:
        if args.output.exists() and not args.force:
            raise FileExistsError(f"no se sobrescribe sin --force: {args.output}")
        password = getpass.getpass("Contraseña: ")
        if args.cmd == "encrypt" and args.confirm_password:
            password2 = getpass.getpass("Repite contraseña: ")
            if password != password2:
                print("Las contraseñas no coinciden.", file=sys.stderr)
                return 2
        source = args.input.read_bytes()
        if args.cmd == "encrypt":
            result = encrypt_bytes(source, password)
        else:
            result = decrypt_bytes(source, password)
        _atomic_write(args.output, result, args.force)
        return 0
    except (OSError, AMPCError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
