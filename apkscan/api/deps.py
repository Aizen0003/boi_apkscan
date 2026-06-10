"""FastAPI dependencies: auth, RBAC, object store."""

from typing import Iterable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from apkscan.auth.security import decode_token
from apkscan.auth.service import get_user
from apkscan.db.base import get_db
from apkscan.db.models import Role, User
from apkscan.storage.factory import get_object_store

_bearer = HTTPBearer(auto_error=False)


def get_store():
    return get_object_store()


def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    if creds is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing bearer token")
    try:
        payload = decode_token(creds.credentials)
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or expired token")
    username = payload.get("sub")
    user = get_user(db, username) if username else None
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="unknown or inactive user")
    return user


def require_roles(*allowed: str):
    """Dependency factory enforcing RBAC. Admin is a superuser."""

    allowed_set = set(allowed)

    def _dep(user: User = Depends(get_current_user)) -> User:
        if user.role != Role.ADMIN and user.role not in allowed_set:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role")
        return user

    return _dep


# common role groups
require_reader = require_roles(Role.VIEWER, Role.ANALYST)
require_analyst = require_roles(Role.ANALYST)
require_admin = require_roles(Role.ADMIN)
