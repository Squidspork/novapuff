"""Command line for sealing a demo and checking who it was made for."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from novapuff.const import FILE_LIMIT
from novapuff.errors import Popped, SealError
from novapuff.keys import keygen, public_path_for
from novapuff.puff import show
from novapuff.seal import check, describe, seal


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="novapuff",
        description="Stamp a demo for one recipient. A modified copy pops.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    generate = commands.add_parser("keygen", help="Create a signing key. Keep the private key.")
    generate.add_argument(
        "-o",
        "--out",
        type=Path,
        default=Path("novapuff.key"),
        help="Where to write the private key (default: ./novapuff.key)",
    )

    stamp = commands.add_parser("seal", help="Seal a demo folder for one recipient.")
    stamp.add_argument("demo", type=Path)
    stamp.add_argument("--key", type=Path, required=True, help="Private key from keygen")
    stamp.add_argument("--recipient", required=True, help="Name of the person this copy is for")
    stamp.add_argument(
        "--big",
        action="store_true",
        help=f"Seal a folder with more than {FILE_LIMIT} files",
    )

    verify = commands.add_parser("check", help="Check a folder with your public key.")
    verify.add_argument("demo", type=Path)
    verify.add_argument("--pub", type=Path, required=True, help="Your novapuff.pub")

    who = commands.add_parser("who", help="Show who a sealed copy was made for.")
    who.add_argument("demo", type=Path)
    who.add_argument("--pub", type=Path, required=True, help="Your novapuff.pub")

    args = parser.parse_args(argv)
    try:
        return _run(args)
    except Popped as exc:
        show(exc.reason, exc.recipient)
        return 2
    except SealError as exc:
        print(f"novapuff: {exc}", file=sys.stderr)
        return 1


def _run(args: argparse.Namespace) -> int:
    if args.command == "keygen":
        keys = keygen(args.out)
        print(f"Private key: {keys.private}")
        print(f"Public key:  {keys.public}")
        return 0
    if args.command == "seal":
        sealed = seal(args.demo, args.key, args.recipient, allow_big=args.big)
        print(f"Sealed {sealed.root} for {sealed.recipient}.")
        print(f"Key id: {sealed.key_id}")
        print(f"Keep this public key for later checks: {public_path_for(args.key.expanduser().resolve())}")
        return 0
    public_key = args.pub.expanduser().read_text(encoding="utf-8")
    if args.command == "check":
        sealed = check(args.demo, public_key)
        print(f"Intact. Sealed for {sealed.recipient}.")
        return 0
    print(describe(args.demo, public_key), end="")
    return 0
