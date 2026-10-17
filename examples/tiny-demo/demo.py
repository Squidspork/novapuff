"""A showing you can send. Keep the mechanism you care about on your own server."""

from pathlib import Path

import novapuff


def main() -> None:
    root = Path(__file__).resolve().parent
    seal = novapuff.guard(root)
    print(f"This copy was sealed for {seal.recipient}.")
    print((root / "story.txt").read_text(encoding="utf-8"), end="")


if __name__ == "__main__":
    main()
