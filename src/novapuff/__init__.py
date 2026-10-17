"""NovaPuff stamps a demo for one recipient.

Someone you send the folder to can still read it. The seal records their
name and pops when the sealed files change.
"""

from novapuff.errors import Popped, SealError
from novapuff.keys import keygen
from novapuff.seal import Seal, check, guard, seal

__version__ = "0.1.0"
__all__ = [
    "Popped",
    "Seal",
    "SealError",
    "check",
    "guard",
    "keygen",
    "seal",
]
