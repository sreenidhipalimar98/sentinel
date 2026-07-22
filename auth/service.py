"""Authentication service — JWT tokens, password hashing, user lookup."""
from datetime import datetime, timedelta, timezone

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database.engine import get_db
from database.models import User, OrgMember, Organization

security_scheme = HTTPBearer()


class AuthService:
    @staticmethod
    def hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    @staticmethod
    def verify_password(plain: str, hashed: str) -> bool:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

    @staticmethod
    def create_token(user_id: str, org_id: str = None) -> str:
        expire = datetime.now(timezone.utc) + timedelta(hours=settings.JWT_EXPIRY_HOURS)
        payload = {
            "sub": user_id,
            "org": org_id,
            "exp": expire,
        }
        return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

    @staticmethod
    def decode_token(token: str) -> dict:
        try:
            return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Dependency that extracts and validates the current user from JWT."""
    payload = AuthService.decode_token(credentials.credentials)
    user_id = payload.get("sub")
    org_id = payload.get("org")

    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    # Get org membership role
    role = None
    if org_id:
        result = await db.execute(
            select(OrgMember).where(OrgMember.user_id == user_id, OrgMember.org_id == org_id)
        )
        membership = result.scalar_one_or_none()
        if membership:
            role = membership.role.value

    return {
        "user_id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "org_id": org_id,
        "role": role,
        "is_superuser": user.is_superuser,
    }
