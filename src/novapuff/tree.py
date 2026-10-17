"""Which files in a demo folder are part of the seal."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from novapuff.const import SEAL_NAME
from novapuff.errors import Popped, SealError

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}
SKIP_FILES = {SEAL_NAME, ".DS_Store"}
SKIP_SUFFIXES = {".pyc", ".pyo"}
SECRET_NAMES = {"novapuff.key", "id_rsa", "id_ed25519"}
SECRET_SUFFIXES = {".key", ".p12", ".pfx"}
PRIVATE_MARKERS = (
    b"BEGIN PRIVATE KEY",
    b"BEGIN OPENSSH PRIVATE KEY",
    b"BEGIN RSA PRIVATE KEY",
    b"BEGIN EC PRIVATE KEY",
    b"BEGIN ENCRYPTED PRIVATE KEY",
)


def demo_root(root: Path) -> Path:
    resolved = root.expanduser().resolve()
    if not resolved.is_dir():
        raise SealError(f"Demo folder not found: {root}")
    home = Path.home().resolve()
    if resolved == home or resolved == Path(resolved.anchor):
        raise SealError("Choose the demo folder itself, not your home directory or a disk root.")
    return resolved


def inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def collect(root: Path) -> list[Path]:
    reject_named_secrets(root)
    paths = list_demo_files(root)
    for path in paths:
        if head_has_private_key(path):
            raise SealError(f"Move this private key out of the demo before sealing: {path}")
    return paths


def list_demo_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in SKIP_DIRS)
        current = Path(dirpath)
        for name in sorted(filenames):
            if name in SKIP_FILES or Path(name).suffix in SKIP_SUFFIXES:
                continue
            path = current / name
            if path.is_symlink():
                raise SealError(f"NovaPuff will not follow a symlink: {path}")
            if path.is_file():
                found.append(path)
    return found


def file_record(root: Path, path: Path) -> dict[str, object]:
    return {
        "path": relative(root, path),
        "sha256": hash_file(path),
        "bytes": path.stat().st_size,
    }


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sealed_path(root: Path, rel: str) -> Path:
    """Return a file that stays inside the demo, without following links."""
    safe = safe_relative(rel)
    current = root
    for part in Path(safe).parts:
        current = current / part
        if current.is_symlink():
            raise Popped("The seal contains a bad path.")
    if not current.is_file():
        raise Popped(f"Missing file: {safe}")
    return current


def safe_relative(rel: str) -> str:
    if rel == "" or rel.startswith(("/", "\\")) or "\\" in rel:
        raise Popped("The seal contains a bad path.")
    parts = Path(rel).parts
    if any(part in {"..", ""} for part in parts):
        raise Popped("The seal contains a bad path.")
    return Path(*parts).as_posix()


def relative(root: Path, path: Path) -> str:
    try:
        rel = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise SealError(f"NovaPuff will not follow a path outside the demo: {path}") from exc
    return safe_relative(rel)


def reject_named_secrets(root: Path) -> None:
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            secret_name = name in SECRET_NAMES or name.startswith(".env")
            secret_suffix = Path(name).suffix.lower() in SECRET_SUFFIXES
            if secret_name or secret_suffix:
                found = Path(dirpath) / name
                raise SealError(f"Move this secret out of the demo before sealing: {found}")


def head_has_private_key(path: Path) -> bool:
    with path.open("rb") as handle:
        head = handle.read(8192)
    return any(marker in head for marker in PRIVATE_MARKERS)
