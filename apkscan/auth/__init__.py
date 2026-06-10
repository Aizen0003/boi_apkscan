"""Authentication & RBAC (T0.17 / NFR6).

JWT bearer auth with three roles (admin/analyst/viewer). Access to the tool,
samples, and reports is authenticated and role-checked.
"""

from apkscan.auth.security import create_access_token, decode_token, hash_password, verify_password
from apkscan.auth.service import authenticate, create_user, ensure_default_admin, get_user

__all__ = [
    "create_access_token",
    "decode_token",
    "hash_password",
    "verify_password",
    "authenticate",
    "create_user",
    "ensure_default_admin",
    "get_user",
]
