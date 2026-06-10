"""Object-store factory."""

from typing import Optional

from apkscan.config import Settings, get_settings
from apkscan.storage.base import ObjectStore, StorageError
from apkscan.storage.filesystem import FilesystemObjectStore


def get_object_store(settings: Optional[Settings] = None) -> ObjectStore:
    settings = settings or get_settings()
    if settings.storage_backend == "filesystem":
        return FilesystemObjectStore(settings.storage_root)
    if settings.storage_backend == "s3":
        from apkscan.storage.s3 import S3ObjectStore

        if not settings.s3_endpoint:
            raise StorageError("storage_backend=s3 requires APKSCAN_S3_ENDPOINT")
        return S3ObjectStore(
            endpoint=settings.s3_endpoint,
            bucket=settings.s3_bucket,
            access_key=settings.s3_access_key or "",
            secret_key=settings.s3_secret_key or "",
        )
    raise StorageError(f"unknown storage backend: {settings.storage_backend}")
