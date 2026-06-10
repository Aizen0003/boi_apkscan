"""Password hashing (bcrypt) and JWT issuance/verification."""

from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
import jwt

from apkscan.config import Settings, get_settings

# bcrypt operates on at most 72 bytes; truncate defensively.
_BCRYPT_MAX = 72


def hash_password(password: str) -> str:
    pw = password.encode("utf-8")[:_BCRYPT_MAX]
    return bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8")[:_BCRYPT_MAX], password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(
    *, subject: str, role: str, settings: Optional[Settings] = None, expires_minutes: Optional[int] = None
) -> str:
    settings = settings or get_settings()
    ttl = expires_minutes if expires_minutes is not None else settings.access_token_ttl_minutes
    now = datetime.now(timezone.utc)
    payload = {"sub": subject, "role": role, "iat": now, "exp": now + timedelta(minutes=ttl)}
    return jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str, settings: Optional[Settings] = None) -> dict:
    settings = settings or get_settings()
    return jwt.decode(token, settings.secret_key, algorithms=[settings.jwt_algorithm])
