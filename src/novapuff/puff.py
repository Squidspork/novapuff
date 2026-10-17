"""The Dalmatian pufferfish NovaPuff prints when a sealed demo has been poked."""

from __future__ import annotations

import sys

PUFF = r"""
         .-~~~-.
      .-'  o    `-.
    .'   o .---.   `.
   /  o  /       \  o \
  |     |   o o   |     |
  |  o  |    ^    |  o  |
   \    |   \_/   |    /
    `. o \ ----- / o .'
      `-. `-----' .-'
         `-.____.-'
      NovaPuff popped.
"""


def show(reason: str, recipient: str | None) -> None:
    print(PUFF, file=sys.stderr)
    print("The Hungry Nova Labs seal on this copy has burst.", file=sys.stderr)
    if recipient:
        print(f"This copy was sealed for {recipient}.", file=sys.stderr)
    print(reason, file=sys.stderr)
