from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.database import get_db
from app.core.config import settings
from app.core.security import decode_token, create_access_token
from app.core.redis_client import blacklist_token, is_token_blacklisted
from app.schemas.auth import (
    UserRegister, UserLogin, UserResponse,
    TokenResponse, RefreshRequest, AccessTokenResponse, MessageResponse,
)
from app.services.auth_service import register_user, login_user
from app.middleware.auth_middleware import get_current_user
from app.models.user import User
from fastapi import HTTPException
from datetime import timezone

router = APIRouter(prefix="/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)


@router.post("/register", response_model=UserResponse, status_code=201)
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def register(request: Request, data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user account."""
    user = await register_user(db, data)
    return user


@router.post("/login", response_model=TokenResponse)
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def login(request: Request, data: UserLogin, db: Session = Depends(get_db)):
    """Login and receive access + refresh tokens."""
    tokens = await login_user(db, data)
    return tokens


@router.post("/refresh", response_model=AccessTokenResponse)
async def refresh_token(data: RefreshRequest):
    """Exchange a valid refresh token for a new access token."""
    if await is_token_blacklisted(data.refresh_token):
        raise HTTPException(status_code=401, detail="Refresh token has been revoked")

    payload = decode_token(data.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    token_data = {"sub": payload["sub"], "role": payload["role"], "email": payload["email"]}
    new_access_token = create_access_token(token_data)
    return {"access_token": new_access_token}


@router.post("/logout", response_model=MessageResponse)
async def logout(
    data: RefreshRequest,
    current_user: User = Depends(get_current_user),
):
    """Logout: blacklist both tokens."""
    # Blacklist refresh token for its remaining TTL
    payload = decode_token(data.refresh_token)
    if payload:
        from datetime import datetime
        exp = payload.get("exp", 0)
        remaining = int(exp - datetime.now(timezone.utc).timestamp())
        if remaining > 0:
            await blacklist_token(data.refresh_token, remaining)

    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    """Get current authenticated user's profile."""
    return current_user