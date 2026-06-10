"""Object storage abstraction for samples and reports.

Filesystem-backed by default (single-host MVP); an S3/MinIO backend is available
via config. Both keep artifacts on-prem. Samples may be live malware: they are
stored verbatim and never executed.
"""

from apkscan.storage.base import ObjectStore, StorageError
from apkscan.storage.factory import get_object_store
from apkscan.storage.filesystem import FilesystemObjectStore

__all__ = ["ObjectStore", "StorageError", "FilesystemObjectStore", "get_object_store"]
