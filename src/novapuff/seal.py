"""Sign a demo folder for one recipient, and notice when those files change.

The person you send the folder to can still read it. NovaPuff records who
received that copy and pops when the sealed files change.
"""

from __future__ import annotations

import base64
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature

from novapuff.const import (
    FILE_LIMIT,
    FORMAT,
    HOLDER,
    PRODUCT,
    PUBLIC_NAME,
    SEAL_NAME,
    STAMP_NAME,
)
from novapuff.errors import Popped, SealError
from novapuff.keys import key_id, load_private, load_public, public_pem
from novapuff.tree import (
    collect,
    demo_root,
    file_record,
    hash_file,
    inside,
    list_demo_files,
    relative,
    safe_relative,
    sealed_path,
)


@dataclass(frozen=True)
class Seal:
    recipient: str
    issued_at: str
    key_id: str
    holder: str
    root: Path
    files: tuple[str, ...]


def seal(
    root: Path,
    private_key: Path,
    recipient: str,
    *,
    issued_at: str | None = None,
    allow_big: bool = False,
) -> Seal:
    root = demo_root(root)
    private_key = private_key.expanduser().resolve()
    if inside(private_key, root):
        raise SealError("Keep the private key outside the demo folder.")
    recipient = clean_recipient(recipient)
    issued = issued_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if any(char.isspace() for char in issued):
        raise SealError("issued_at must not contain spaces.")

    paths = collect(root)
    if len(paths) > FILE_LIMIT and not allow_big:
        raise SealError(
            f"This folder has {len(paths)} files. "
            "Pass --big if that is the demo you mean to seal."
        )

    signing_key = load_private(private_key)
    public_key = signing_key.public_key()
    fingerprint = key_id(public_key)
    (root / STAMP_NAME).write_text(_stamp_text(recipient, issued, fingerprint), encoding="utf-8")
    (root / PUBLIC_NAME).write_text(public_pem(public_key), encoding="utf-8")

    records = [file_record(root, path) for path in list_demo_files(root)]
    body = {
        "novapuff": FORMAT,
        "product": PRODUCT,
        "holder": HOLDER,
        "recipient": recipient,
        "issued_at": issued,
        "key_id": fingerprint,
        "files": records,
    }
    signature = signing_key.sign(signed_bytes(body))
    document = {**body, "signature": base64.b64encode(signature).decode("ascii")}
    (root / SEAL_NAME).write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return Seal(recipient, issued, fingerprint, HOLDER, root, tuple(item["path"] for item in records))


def check(root: Path, public_key_pem: str) -> Seal:
    root = demo_root(root)
    path = root / SEAL_NAME
    if not path.is_file():
        raise Popped("The seal file is missing.")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise Popped("The seal file is unreadable.") from exc
    body = _signed_body(document)
    try:
        public_key = load_public(public_key_pem)
        raw_signature = base64.b64decode(document["signature"], validate=True)
        public_key.verify(raw_signature, signed_bytes(body))
        if body["key_id"] != key_id(public_key):
            raise InvalidSignature
    except (InvalidSignature, ValueError, SealError, KeyError) as exc:
        raise Popped("The signature does not match this public key.") from exc

    recipient = body["recipient"]
    try:
        expected = _expected_files(body["files"])
        actual = {relative(root, item) for item in list_demo_files(root)}
    except SealError as exc:
        raise Popped(str(exc), recipient) from exc

    missing = sorted(set(expected) - actual)
    extra = sorted(actual - set(expected))
    if missing:
        raise Popped(f"Missing file: {missing[0]}", recipient)
    if extra:
        raise Popped(f"New file: {extra[0]}", recipient)
    for rel, digest in expected.items():
        got = hash_file(sealed_path(root, rel))
        if not hmac.compare_digest(got, digest):
            raise Popped(f"Changed file: {rel}", recipient)
    return Seal(recipient, body["issued_at"], body["key_id"], body["holder"], root, tuple(sorted(expected)))


def describe(root: Path, public_key_pem: str) -> str:
    sealed = check(root, public_key_pem)
    return (
        f"Recipient: {sealed.recipient}\n"
        f"Issued: {sealed.issued_at}\n"
        f"Key: {sealed.key_id}\n"
        f"Files: {len(sealed.files)}\n"
        f"Holder: {sealed.holder}\n"
    )


def guard(root: Path) -> Seal:
    demo = demo_root(root)
    pub = demo / PUBLIC_NAME
    if not pub.is_file():
        raise SealError("This demo has no novapuff.pub yet. Seal it before you send it.")
    try:
        return check(demo, pub.read_text(encoding="utf-8"))
    except Popped as exc:
        from novapuff.puff import show

        show(exc.reason, exc.recipient)
        raise SystemExit(2) from exc


def signed_bytes(body: dict) -> bytes:
    return json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def clean_recipient(value: str) -> str:
    text = " ".join(value.split())
    if not text or len(text) > 200:
        raise SealError("Give the recipient's name, up to 200 characters.")
    return text


def _signed_body(document: object) -> dict:
    if not isinstance(document, dict):
        raise Popped("This is not a NovaPuff seal.")
    signature = document.get("signature")
    if not isinstance(signature, str):
        raise Popped("This is not a NovaPuff seal.")
    body = {key: value for key, value in document.items() if key != "signature"}
    if body.get("novapuff") != FORMAT or body.get("product") != PRODUCT:
        raise Popped("This is not a NovaPuff seal.")
    for field in ("holder", "recipient", "issued_at", "key_id"):
        if not isinstance(body.get(field), str) or not body[field]:
            raise Popped("This is not a NovaPuff seal.")
    if not isinstance(body.get("files"), list):
        raise Popped("This is not a NovaPuff seal.")
    return body


def _expected_files(records: list) -> dict[str, str]:
    expected: dict[str, str] = {}
    for item in records:
        if not isinstance(item, dict):
            raise Popped("This is not a NovaPuff seal.")
        rel = item.get("path")
        digest = item.get("sha256")
        if not isinstance(rel, str) or not isinstance(digest, str):
            raise Popped("This is not a NovaPuff seal.")
        rel = safe_relative(rel)
        bad_digest = len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest)
        if rel in expected or bad_digest:
            raise Popped("This is not a NovaPuff seal.")
        expected[rel] = digest
    return expected


def _stamp_text(recipient: str, issued_at: str, fingerprint: str) -> str:
    return (
        "NovaPuff\n"
        "A Hungry Nova Labs seal\n"
        "\n"
        f"This copy was made for {recipient}.\n"
        f"Issued {issued_at}.\n"
        f"Key {fingerprint}.\n"
        "\n"
        "Start the demo as you received it.\n"
        "If these files have been poked, NovaPuff pops.\n"
    )
