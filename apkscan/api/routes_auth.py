"""Auth routes: token issuance + (admin) user management."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from apkscan import audit
from apkscan.api.deps import require_admin
from apkscan.api.schemas import CreateUserRequest, LoginRequest, TokenResponse, UserResponse
from apkscan.auth.security import create_access_token
from apkscan.auth.service import authenticate, create_user
from apkscan.db.base import get_db

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/token", response_model=TokenResponse)
def login(body: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    user = authenticate(db, body.username, body.password)
    if user is None:
        # do not record the attempted username verbatim beyond audit necessity
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")
    token = create_access_token(subject=user.username, role=user.role)
    audit.record(db, action="auth.login", actor=user.username)
    return TokenResponse(access_token=token, role=user.role)


@router.post("/users", response_model=UserResponse, dependencies=[Depends(require_admin)])
def create_user_endpoint(body: CreateUserRequest, db: Session = Depends(get_db)) -> UserResponse:
    try:
        user = create_user(db, username=body.username, password=body.password, role=body.role)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    audit.record(db, action="user.created", detail={"username": user.username, "role": user.role})
    return UserResponse(username=user.username, role=user.role, is_active=user.is_active)
