"""Organization management endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List

from auth.service import get_current_user
from database.engine import get_db
from database.models import Organization, OrgMember, User, UserRole

router = APIRouter(prefix="/org", tags=["organization"])


class OrgResponse(BaseModel):
    id: str
    name: str
    slug: str
    plan: str
    max_targets: int
    max_scans_per_month: int


class InviteMemberRequest(BaseModel):
    email: EmailStr
    role: str = "analyst"


class MemberResponse(BaseModel):
    user_id: str
    email: str
    full_name: str
    role: str
    joined_at: Optional[str] = None


@router.get("/", response_model=OrgResponse)
async def get_org(current_user: dict = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    if not current_user["org_id"]:
        raise HTTPException(status_code=404, detail="No organization found")
    result = await db.execute(
        select(Organization).where(Organization.id == current_user["org_id"])
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    return OrgResponse(
        id=org.id, name=org.name, slug=org.slug,
        plan=org.plan, max_targets=org.max_targets,
        max_scans_per_month=org.max_scans_per_month,
    )


@router.get("/members", response_model=List[MemberResponse])
async def list_members(current_user: dict = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(OrgMember, User)
        .join(User, OrgMember.user_id == User.id)
        .where(OrgMember.org_id == current_user["org_id"])
    )
    members = []
    for membership, user in result.all():
        members.append(MemberResponse(
            user_id=user.id, email=user.email, full_name=user.full_name,
            role=membership.role.value,
            joined_at=membership.joined_at.isoformat() if membership.joined_at else None,
        ))
    return members


@router.post("/invite", response_model=MemberResponse, status_code=201)
async def invite_member(
    data: InviteMemberRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if current_user["role"] not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only owners and admins can invite members")
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found. They must sign up first.")
    result = await db.execute(
        select(OrgMember).where(OrgMember.user_id == user.id, OrgMember.org_id == current_user["org_id"])
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="User is already a member")
    role = UserRole(data.role) if data.role in [r.value for r in UserRole] else UserRole.ANALYST
    membership = OrgMember(user_id=user.id, org_id=current_user["org_id"], role=role)
    db.add(membership)
    await db.commit()
    return MemberResponse(user_id=user.id, email=user.email, full_name=user.full_name, role=role.value)
