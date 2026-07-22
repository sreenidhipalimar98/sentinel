"""Target (asset) management endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List

from auth.service import get_current_user
from database.engine import get_db
from database.models import Target, Organization, Scan, ScanStatus

router = APIRouter(prefix="/targets", tags=["targets"])


class TargetCreate(BaseModel):
    url: str
    name: str = ""
    environment: str = "production"
    auth_config: Optional[dict] = None


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    environment: Optional[str] = None
    auth_config: Optional[dict] = None
    is_active: Optional[bool] = None


class TargetResponse(BaseModel):
    id: str
    url: str
    name: str
    environment: str
    is_active: bool
    created_at: str
    last_scanned_at: Optional[str] = None
    total_scans: int = 0
    open_findings: int = 0


@router.get("/", response_model=List[TargetResponse])
async def list_targets(current_user: dict = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Target).where(
            Target.org_id == current_user["org_id"],
            Target.is_active == True,
        ).order_by(Target.created_at.desc())
    )
    targets = result.scalars().all()

    response = []
    for t in targets:
        # Count scans
        scan_count = await db.execute(
            select(func.count(Scan.id)).where(Scan.target_id == t.id)
        )
        total_scans = scan_count.scalar() or 0

        response.append(TargetResponse(
            id=t.id, url=t.url, name=t.name,
            environment=t.environment, is_active=t.is_active,
            created_at=t.created_at.isoformat(),
            last_scanned_at=t.last_scanned_at.isoformat() if t.last_scanned_at else None,
            total_scans=total_scans,
        ))
    return response


@router.post("/", response_model=TargetResponse, status_code=201)
async def create_target(
    data: TargetCreate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if current_user["role"] == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot create targets")

    # Check org target limit
    result = await db.execute(
        select(Organization).where(Organization.id == current_user["org_id"])
    )
    org = result.scalar_one_or_none()

    target_count = await db.execute(
        select(func.count(Target.id)).where(
            Target.org_id == current_user["org_id"],
            Target.is_active == True,
        )
    )
    count = target_count.scalar() or 0
    if count >= org.max_targets:
        raise HTTPException(
            status_code=403,
            detail=f"Target limit reached ({org.max_targets}). Upgrade your plan.",
        )

    # Normalize URL
    url = data.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    target = Target(
        org_id=current_user["org_id"],
        url=url,
        name=data.name or url,
        environment=data.environment,
        auth_config=data.auth_config,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    return TargetResponse(
        id=target.id, url=target.url, name=target.name,
        environment=target.environment, is_active=target.is_active,
        created_at=target.created_at.isoformat(),
    )


@router.patch("/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: str,
    data: TargetUpdate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Target).where(Target.id == target_id, Target.org_id == current_user["org_id"])
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if data.name is not None:
        target.name = data.name
    if data.environment is not None:
        target.environment = data.environment
    if data.auth_config is not None:
        target.auth_config = data.auth_config
    if data.is_active is not None:
        target.is_active = data.is_active

    await db.commit()
    await db.refresh(target)

    return TargetResponse(
        id=target.id, url=target.url, name=target.name,
        environment=target.environment, is_active=target.is_active,
        created_at=target.created_at.isoformat(),
        last_scanned_at=target.last_scanned_at.isoformat() if target.last_scanned_at else None,
    )


@router.delete("/{target_id}", status_code=204)
async def delete_target(
    target_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if current_user["role"] not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only owners and admins can delete targets")

    result = await db.execute(
        select(Target).where(Target.id == target_id, Target.org_id == current_user["org_id"])
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    target.is_active = False  # Soft delete
    await db.commit()
