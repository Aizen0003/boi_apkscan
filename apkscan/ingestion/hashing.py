"""Streaming file hashing for ingestion + dedupe (FR1)."""

import hashlib
from pathlib import Path
from typing import BinaryIO, Dict

_CHUNK = 1024 * 1024  # 1 MiB


def hash_stream(stream: BinaryIO) -> Dict[str, str]:
    """Compute sha256/sha1/md5 over a binary stream in one pass."""

    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    size = 0
    while True:
        chunk = stream.read(_CHUNK)
        if not chunk:
            break
        size += len(chunk)
        sha256.update(chunk)
        sha1.update(chunk)
        md5.update(chunk)
    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
        "size": str(size),
    }


def hash_file(path) -> Dict[str, str]:
    with Path(path).open("rb") as fh:
        return hash_stream(fh)


def hash_bytes(data: bytes) -> Dict[str, str]:
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size": str(len(data)),
    }
