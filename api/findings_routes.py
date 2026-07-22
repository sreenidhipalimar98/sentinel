"""Findings management — view, triage, resolve."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List

from auth.service import get_current_user
from database.engine import get_db
from database.models import Finding, Scan, Target, FindingSeverity, FindingStatus

router = APIRouter(prefix="/findings", tags=["findings"])


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    category: str
    check: str
    severity: str
    status: str
    title: str
    description: str
    detail: Optional[dict | list | str] = None
    screenshot_path: Optional[str] = None
    first_seen_at: Optional[str] = None
    resolved_at: Optional[str] = None
    notes: str = ""


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    notes: Optional[str] = None
    assigned_to: Optional[str] = None


class FindingsSummary(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    open: int = 0
    fixed: int = 0


@router.get("/summary", response_model=FindingsSummary)
async def findings_summary(
    target_id: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(Finding.severity, Finding.status, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .where(Target.org_id == current_user["org_id"])
        .group_by(Finding.severity, Finding.status)
    )
    if target_id:
        query = query.where(Finding.target_id == target_id)

    result = await db.execute(query)

    summary = FindingsSummary()
    for severity, status, count in result.all():
        summary.total += count
        if hasattr(severity, 'value'):
            sev_val = severity.value
        else:
            sev_val = severity
        if sev_val == "critical":
            summary.critical += count
        elif sev_val == "high":
            summary.high += count
        elif sev_val == "medium":
            summary.medium += count
        elif sev_val == "low":
            summary.low += count
        elif sev_val == "info":
            summary.info += count

        if hasattr(status, 'value'):
            stat_val = status.value
        else:
            stat_val = status
        if stat_val == "open":
            summary.open += count
        elif stat_val == "fixed":
            summary.fixed += count

    return summary


@router.get("/", response_model=List[FindingResponse])
async def list_findings(
    target_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .where(Target.org_id == current_user["org_id"])
        .order_by(Finding.first_seen_at.desc())
        .limit(limit)
    )

    if target_id:
        query = query.where(Finding.target_id == target_id)
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)

    result = await db.execute(query)
    findings = result.scalars().all()

    return [
        FindingResponse(
            id=f.id, scan_id=f.scan_id, category=f.category,
            check=f.check, severity=f.severity.value if hasattr(f.severity, 'value') else f.severity,
            status=f.status.value if hasattr(f.status, 'value') else f.status,
            title=f.title, description=f.description, detail=f.detail,
            screenshot_path=f.screenshot_path,
            first_seen_at=f.first_seen_at.isoformat() if f.first_seen_at else None,
            resolved_at=f.resolved_at.isoformat() if f.resolved_at else None,
            notes=f.notes or "",
        )
        for f in findings
    ]


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: str,
    data: FindingUpdate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Verify access
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(Target, Scan.target_id == Target.id)
        .where(Finding.id == finding_id, Target.org_id == current_user["org_id"])
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if data.status:
        finding.status = FindingStatus(data.status)
        if data.status == "fixed":
            finding.resolved_at = datetime.now(timezone.utc)
    if data.notes is not None:
        finding.notes = data.notes
    if data.assigned_to is not None:
        finding.assigned_to = data.assigned_to

    await db.commit()
    await db.refresh(finding)

    return FindingResponse(
        id=finding.id, scan_id=finding.scan_id, category=finding.category,
        check=finding.check,
        severity=finding.severity.value if hasattr(finding.severity, 'value') else finding.severity,
        status=finding.status.value if hasattr(finding.status, 'value') else finding.status,
        title=finding.title, description=finding.description, detail=finding.detail,
        screenshot_path=finding.screenshot_path,
        first_seen_at=finding.first_seen_at.isoformat() if finding.first_seen_at else None,
        resolved_at=finding.resolved_at.isoformat() if finding.resolved_at else None,
        notes=finding.notes or "",
    )
