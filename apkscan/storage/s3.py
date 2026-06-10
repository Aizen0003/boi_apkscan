"""S3 / MinIO object store (optional backend).

``boto3`` is imported lazily so selecting this backend without the dependency
installed yields a clear error instead of a stack trace at import time.
"""

from pathlib import Path

from apkscan.storage.base import ObjectStore, StorageError, validate_key


class S3ObjectStore(ObjectStore):
    def __init__(self, endpoint: str, bucket: str, access_key: str, secret_key: str) -> None:
        try:
            import boto3  # noqa: WPS433 (lazy, optional dependency)
        except ImportError as exc:  # pragma: no cover - exercised only when selected
            raise StorageError(
                "S3 storage backend selected but boto3 is not installed; "
                "install with `pip install boto3` or use the filesystem backend."
            ) from exc

        self.bucket = bucket
        self._endpoint = endpoint
        self._s3 = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )
        try:
            self._s3.head_bucket(Bucket=bucket)
        except Exception:  # noqa: BLE001 - create the bucket if absent
            self._s3.create_bucket(Bucket=bucket)

    def put_bytes(self, key: str, data: bytes, *, overwrite: bool = False) -> str:
        key = validate_key(key)
        if not overwrite and self.exists(key):
            return self.uri(key)
        self._s3.put_object(Bucket=self.bucket, Key=key, Body=data)
        return self.uri(key)

    def put_file(self, key: str, src: Path, *, overwrite: bool = False) -> str:
        key = validate_key(key)
        if not overwrite and self.exists(key):
            return self.uri(key)
        self._s3.upload_file(str(src), self.bucket, key)
        return self.uri(key)

    def get_bytes(self, key: str) -> bytes:
        key = validate_key(key)
        try:
            return self._s3.get_object(Bucket=self.bucket, Key=key)["Body"].read()
        except Exception as exc:  # noqa: BLE001
            raise StorageError(f"key not found: {key}") from exc

    def exists(self, key: str) -> bool:
        try:
            self._s3.head_object(Bucket=self.bucket, Key=validate_key(key))
            return True
        except Exception:  # noqa: BLE001
            return False

    def delete(self, key: str) -> None:
        self._s3.delete_object(Bucket=self.bucket, Key=validate_key(key))

    def uri(self, key: str) -> str:
        return f"s3://{self.bucket}/{validate_key(key)}"
