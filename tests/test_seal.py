import base64
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from novapuff.errors import Popped, SealError
from novapuff.keys import key_id, keygen, load_private
from novapuff.seal import check, describe, guard, seal, signed_bytes

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "tiny-demo"


def _pair(tmp_path: Path, name: str = "novapuff.key"):
    folder = tmp_path / name
    folder.mkdir()
    return keygen(folder / "novapuff.key")


def _demo(tmp_path: Path) -> Path:
    demo = tmp_path / "demo"
    demo.mkdir()
    (demo / "note.txt").write_text("hello\n", encoding="utf-8")
    return demo


def test_roundtrip_names_the_recipient(tmp_path: Path):
    keys = _pair(tmp_path, "keys")
    demo = _demo(tmp_path)
    sealed = seal(demo, keys.private, "Ada's Café", issued_at="2026-10-17T14:00:00Z")

    assert sealed.recipient == "Ada's Café"
    again = check(demo, keys.public.read_text(encoding="utf-8"))
    assert again.recipient == "Ada's Café"
    assert again.issued_at == "2026-10-17T14:00:00Z"
    text = describe(demo, keys.public.read_text(encoding="utf-8"))
    assert "Ada's Café" in text
    assert "This copy was made for Ada's Café." in (demo / "NOVAPUFF.txt").read_text(encoding="utf-8")
    assert "BEGIN PRIVATE KEY" not in (demo / "novapuff.pub").read_text(encoding="utf-8")


def test_changed_file_pops(tmp_path: Path):
    keys = _pair(tmp_path, "keys")
    demo = _demo(tmp_path)
    seal(demo, keys.private, "Ada")
    (demo / "note.txt").write_text("poked\n", encoding="utf-8")

    with pytest.raises(Popped, match="Changed file: note.txt"):
        check(demo, keys.public.read_text(encoding="utf-8"))


def test_new_file_pops(tmp_path: Path):
    keys = _pair(tmp_path, "keys")
    demo = _demo(tmp_path)
    seal(demo, keys.private, "Ada")
    (demo / "extra.txt").write_text("hi\n", encoding="utf-8")

    with pytest.raises(Popped, match="New file: extra.txt"):
        check(demo, keys.public.read_text(encoding="utf-8"))


def test_reseal_with_another_key_fails_the_publisher_check(tmp_path: Path):
    first = _pair(tmp_path, "first")
    second = _pair(tmp_path, "second")
    demo = _demo(tmp_path)
    seal(demo, first.private, "Ada")
    seal(demo, second.private, "Someone else")

    with pytest.raises(Popped, match="signature"):
        check(demo, first.public.read_text(encoding="utf-8"))
    assert check(demo, second.public.read_text(encoding="utf-8")).recipient == "Someone else"


def test_guard_pops_on_a_poked_demo(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    keys = _pair(tmp_path, "keys")
    demo = _demo(tmp_path)
    seal(demo, keys.private, "Ada")
    (demo / "note.txt").write_text("poked\n", encoding="utf-8")

    with pytest.raises(SystemExit) as caught:
        guard(demo)
    assert caught.value.code == 2
    assert "popped" in capsys.readouterr().err.lower()


def test_private_key_inside_the_demo_is_refused(tmp_path: Path):
    demo = _demo(tmp_path)
    keys = keygen(demo / "novapuff.key")
    with pytest.raises(SealError, match="outside"):
        seal(demo, keys.private, "Ada")


def test_env_file_is_refused(tmp_path: Path):
    keys = _pair(tmp_path, "keys")
    demo = _demo(tmp_path)
    (demo / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    with pytest.raises(SealError, match="secret"):
        seal(demo, keys.private, "Ada")


def test_symlink_pops_without_reading_the_target(tmp_path: Path):
    keys = _pair(tmp_path, "keys")
    demo = _demo(tmp_path)
    seal(demo, keys.private, "Ada")
    outside = tmp_path / "outside.txt"
    outside.write_text("leave me alone", encoding="utf-8")
    (demo / "note.txt").unlink()
    (demo / "note.txt").symlink_to(outside)

    with pytest.raises(Popped, match="symlink"):
        check(demo, keys.public.read_text(encoding="utf-8"))
    assert outside.read_text(encoding="utf-8") == "leave me alone"


def test_escape_path_in_a_signed_manifest_is_rejected(tmp_path: Path):
    keys = _pair(tmp_path, "keys")
    demo = _demo(tmp_path)
    outside = tmp_path / "secret.txt"
    outside.write_text("nope", encoding="utf-8")
    fingerprint = key_id(load_private(keys.private).public_key())
    body = {
        "novapuff": 1,
        "product": "NovaPuff",
        "holder": "Hungry Nova Labs LLC",
        "recipient": "Ada",
        "issued_at": "2026-10-17T00:00:00Z",
        "key_id": fingerprint,
        "files": [{"path": "../secret.txt", "sha256": "ab" * 32, "bytes": 4}],
    }
    signature = load_private(keys.private).sign(signed_bytes(body))
    document = {**body, "signature": base64.b64encode(signature).decode("ascii")}
    (demo / "novapuff-seal.json").write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(Popped, match="bad path"):
        check(demo, keys.public.read_text(encoding="utf-8"))
    assert outside.read_text(encoding="utf-8") == "nope"


def test_home_directory_is_refused(tmp_path: Path):
    keys = _pair(tmp_path, "keys")
    with pytest.raises(SealError, match="home"):
        seal(Path.home(), keys.private, "Ada")


def test_example_demo_runs_and_pops(tmp_path: Path):
    keys = _pair(tmp_path, "keys")
    demo = tmp_path / "tiny-demo"
    shutil.copytree(EXAMPLE, demo)
    seal(demo, keys.private, "Ada Lovelace", issued_at="2026-10-17T14:00:00Z")

    ran = subprocess.run(
        [sys.executable, "demo.py"],
        cwd=demo,
        check=False,
        capture_output=True,
        text=True,
    )
    assert ran.returncode == 0
    assert "Ada Lovelace" in ran.stdout
    assert "it puffs" in ran.stdout

    (demo / "story.txt").write_text("poked\n", encoding="utf-8")
    poked = subprocess.run(
        [sys.executable, "demo.py"],
        cwd=demo,
        check=False,
        capture_output=True,
        text=True,
    )
    assert poked.returncode == 2
    assert "popped" in poked.stderr.lower()
