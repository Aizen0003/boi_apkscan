"""Low-level static heuristics (pure)."""

import math
from collections import Counter

DEX_MAGIC = b"dex\n"
ENCRYPTED_ENTROPY_THRESHOLD = 7.2  # high entropy => likely compressed/encrypted


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte (0..8)."""

    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_dex_magic(header: bytes) -> bool:
    """True if the bytes begin with the DEX file magic (``dex\\n035`` etc.)."""

    return header[:4] == DEX_MAGIC


def looks_encrypted(entropy: float) -> bool:
    return entropy >= ENCRYPTED_ENTROPY_THRESHOLD
