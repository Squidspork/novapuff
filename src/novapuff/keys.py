"""Ed25519 keys for NovaPuff. The private key stays on your machine."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from novapuff.errors import SealError


@dataclass(frozen=True)
class Keys:
    private: Path
    public: Path


def keygen(private_path: Path) -> Keys:
    private_path = private_path.expanduser().resolve()
    public_path = public_path_for(private_path)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise SealError(f"Refusing to overwrite {private_path}") from exc
    opened = True
    try:
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with os.fdopen(fd, "wb") as handle:
            opened = False
            handle.write(pem)
        public_path.write_text(public_pem(key.public_key()), encoding="utf-8")
    except Exception:
        if opened:
            os.close(fd)
        private_path.unlink(missing_ok=True)
        public_path.unlink(missing_ok=True)
        raise
    return Keys(private_path, public_path)


def public_path_for(private_path: Path) -> Path:
    name = private_path.name
    if name.endswith(".key"):
        name = name[:-4] + ".pub"
    else:
        name = name + ".pub"
    return private_path.with_name(name)


def load_private(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError) as exc:
        raise SealError(f"Could not read the NovaPuff private key: {path}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise SealError("NovaPuff expected an Ed25519 private key.")
    return key


def load_public(pem: str) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(pem.encode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise SealError("NovaPuff expected an Ed25519 public key.") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise SealError("NovaPuff expected an Ed25519 public key.")
    return key


def public_pem(key: Ed25519PublicKey) -> str:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]
