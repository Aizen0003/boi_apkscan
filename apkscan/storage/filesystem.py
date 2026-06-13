"""Filesystem-backed object store (default single-host backend)."""

import shutil
from pathlib import Path

from apkscan.storage.base import ObjectStore, StorageError, validate_key


class FilesystemObjectStore(ObjectStore):
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        try:
            self.root.mkdir(parents=True, exist_ok=True)
        except (PermissionError, FileNotFoundError, OSError) as e:
            import logging
            logging.getLogger("apkscan.storage").warning(
                f"Failed to create storage root {root} ({e}). Falling back to local './storage'"
            )
            self.root = Path("./storage")
            self.root.mkdir(parents=True, exist_ok=True)


    def _path(self, key: str) -> Path:
        return self.root / validate_key(key)

    def put_bytes(self, key: str, data: bytes, *, overwrite: bool = False) -> str:
        dest = self._path(key)
        if dest.exists() and not overwrite:
            return self.uri(key)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        tmp.write_bytes(data)
        tmp.replace(dest)  # atomic within the same filesystem
        return self.uri(key)

    def put_file(self, key: str, src: Path, *, overwrite: bool = False) -> str:
        src = Path(src)
        if not src.is_file():
            raise StorageError(f"source file not found: {src}")
        dest = self._path(key)
        if dest.exists() and not overwrite:
            return self.uri(key)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        shutil.copyfile(src, tmp)
        tmp.replace(dest)
        return self.uri(key)

    def get_bytes(self, key: str) -> bytes:
        path = self._path(key)
        if not path.is_file():
            raise StorageError(f"key not found: {key}")
        return path.read_bytes()

    def exists(self, key: str) -> bool:
        return self._path(key).is_file()

    def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)

    def uri(self, key: str) -> str:
        return self._path(key).resolve().as_uri()

    def local_path(self, key: str) -> Path:
        return self._path(key)
