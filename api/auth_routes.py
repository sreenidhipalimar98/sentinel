"""Auth endpoints — signup, login, me."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from auth.schemas import UserCreate, UserLogin, Token, UserResponse
from auth.service import AuthService, get_current_user
from database.engine import get_db
from database.models import User, Organization, OrgMember, UserRole

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/signup", response_model=Token, status_code=201)
async def signup(data: UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == data.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        email=data.email,
        hashed_password=AuthService.hash_password(data.password),
        full_name=data.full_name,
    )
    db.add(user)
    await db.flush()

    org_name = data.org_name or f"{data.full_name or data.email.split('@')[0]}'s workspace"
    slug = org_name.lower().replace(" ", "-").replace("'", "")[:100]

    result = await db.execute(select(Organization).where(Organization.slug == slug))
    if result.scalar_one_or_none():
        slug = f"{slug}-{user.id[:6]}"

    org = Organization(name=org_name, slug=slug)
    db.add(org)
    await db.flush()

    membership = OrgMember(user_id=user.id, org_id=org.id, role=UserRole.OWNER)
    db.add(membership)
    await db.commit()

    token = AuthService.create_token(user.id, org.id)
    return Token(access_token=token, user_id=user.id, org_id=org.id)


@router.post("/login", response_model=Token)
async def login(data: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    if not user or not AuthService.verify_password(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    user.last_login = datetime.now(timezone.utc)

    result = await db.execute(select(OrgMember).where(OrgMember.user_id == user.id))
    membership = result.scalars().first()
    org_id = membership.org_id if membership else None

    await db.commit()

    token = AuthService.create_token(user.id, org_id)
    return Token(access_token=token, user_id=user.id, org_id=org_id)


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    org_name = None
    if current_user["org_id"]:
        result = await db.execute(
            select(Organization).where(Organization.id == current_user["org_id"])
        )
        org = result.scalar_one_or_none()
        if org:
            org_name = org.name

    return UserResponse(
        id=current_user["user_id"],
        email=current_user["email"],
        full_name=current_user["full_name"],
        is_active=True,
        org_id=current_user["org_id"],
        org_name=org_name,
        role=current_user["role"],
    )
