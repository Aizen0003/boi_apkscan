"""User management + authentication against the database."""

import os
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from apkscan.auth.security import hash_password, verify_password
from apkscan.db.models import Role, User


def get_user(session: Session, username: str) -> Optional[User]:
    return session.execute(select(User).where(User.username == username)).scalar_one_or_none()


def create_user(session: Session, *, username: str, password: str, role: str = Role.ANALYST) -> User:
    if role not in Role.ALL:
        raise ValueError(f"unknown role: {role}")
    if get_user(session, username) is not None:
        raise ValueError(f"user already exists: {username}")
    user = User(username=username, password_hash=hash_password(password), role=role)
    session.add(user)
    session.flush()
    return user


def authenticate(session: Session, username: str, password: str) -> Optional[User]:
    user = get_user(session, username)
    if user is None or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def ensure_default_admin(session: Session) -> Optional[User]:
    """Bootstrap an admin from env on an empty user table (dev convenience)."""

    if session.execute(select(User.id).limit(1)).first() is not None:
        return None
    username = os.environ.get("APKSCAN_ADMIN_USER", "admin")
    password = os.environ.get("APKSCAN_ADMIN_PASSWORD", "admin")
    return create_user(session, username=username, password=password, role=Role.ADMIN)
