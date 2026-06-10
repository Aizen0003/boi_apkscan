"""Object-store interface."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional


class StorageError(Exception):
    pass


def validate_key(key: str) -> str:
    """Reject keys that could escape the store root (path traversal)."""

    if not key or key.startswith("/") or ".." in key.split("/"):
        raise StorageError(f"invalid storage key: {key!r}")
    return key.strip("/")


class ObjectStore(ABC):
    """Minimal content-addressable-friendly object store."""

    @abstractmethod
    def put_bytes(self, key: str, data: bytes, *, overwrite: bool = False) -> str: ...

    @abstractmethod
    def put_file(self, key: str, src: Path, *, overwrite: bool = False) -> str: ...

    @abstractmethod
    def get_bytes(self, key: str) -> bytes: ...

    @abstractmethod
    def exists(self, key: str) -> bool: ...

    @abstractmethod
    def delete(self, key: str) -> None: ...

    @abstractmethod
    def uri(self, key: str) -> str: ...

    def local_path(self, key: str) -> Optional[Path]:
        """Return a real local path for a key, if the backend has one."""

        return None
