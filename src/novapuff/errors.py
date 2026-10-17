"""Failures a caller can show to a person."""


class Popped(Exception):
    """Sealed files no longer match the signature."""

    def __init__(self, reason: str, recipient: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.recipient = recipient


class SealError(Exception):
    """The demo could not be sealed."""
