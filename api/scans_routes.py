"""Scan execution and status endpoints."""
import threading
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List

from auth.service import get_current_user
from database.engine import get_db
from database.models import Target, Scan, ScanStatus, Finding, FindingSeverity, FindingStatus
from scanner.auth import AuthConfig, create_authenticated_session
from scanner.security_checks import run_all_security_checks
from scanner.functionality_checks import run_all_functionality_checks
from scanner.screenshots import capture_screenshots
from scanner.report import build_html_report

router = APIRouter(prefix="/scans", tags=["scans"])


class ScanCreate(BaseModel):
    target_id: str
    max_pages: int = 50
    max_depth: int = 4


class ScanResponse(BaseModel):
    id: str
    target_id: str
    target_url: str = ""
    status: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    pages_crawled: int = 0
    forms_found: int = 0
    duration_seconds: Optional[float] = None
    error_message: Optional[str] = None
    findings_count: dict = {}


class ScanDetailResponse(ScanResponse):
    result: Optional[dict] = None
    screenshots: list = []


@router.get("/", response_model=List[ScanResponse])
async def list_scans(
    target_id: Optional[str] = None,
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(Scan, Target)
        .join(Target, Scan.target_id == Target.id)
        .where(Target.org_id == current_user["org_id"])
        .order_by(Scan.created_at.desc())
        .limit(limit)
    )
    if target_id:
        query = query.where(Scan.target_id == target_id)

    result = await db.execute(query)
    scans = []
    for scan, target in result.all():
        scans.append(ScanResponse(
            id=scan.id, target_id=scan.target_id, target_url=target.url,
            status=scan.status.value,
            started_at=scan.started_at.isoformat() if scan.started_at else None,
            finished_at=scan.finished_at.isoformat() if scan.finished_at else None,
            pages_crawled=scan.pages_crawled, forms_found=scan.forms_found,
            duration_seconds=scan.duration_seconds,
            error_message=scan.error_message,
        ))
    return scans


@router.post("/", response_model=ScanResponse, status_code=201)
async def start_scan(
    data: ScanCreate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if current_user["role"] == "viewer":
        raise HTTPException(status_code=403, detail="Viewers cannot start scans")

    # Verify target belongs to org
    result = await db.execute(
        select(Target).where(
            Target.id == data.target_id,
            Target.org_id == current_user["org_id"],
        )
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Create scan record
    scan = Scan(
        target_id=target.id,
        triggered_by=current_user["user_id"],
        status=ScanStatus.RUNNING,
        started_at=datetime.now(timezone.utc),
        config={"max_pages": data.max_pages, "max_depth": data.max_depth},
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Run scan in background thread
    thread = threading.Thread(
        target=_execute_scan,
        args=(scan.id, target.url, target.auth_config, data.max_pages, data.max_depth),
        daemon=True,
    )
    thread.start()

    return ScanResponse(
        id=scan.id, target_id=scan.target_id, target_url=target.url,
        status=scan.status.value,
        started_at=scan.started_at.isoformat(),
    )


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Scan, Target)
        .join(Target, Scan.target_id == Target.id)
        .where(Scan.id == scan_id, Target.org_id == current_user["org_id"])
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan, target = row
    return ScanDetailResponse(
        id=scan.id, target_id=scan.target_id, target_url=target.url,
        status=scan.status.value,
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        finished_at=scan.finished_at.isoformat() if scan.finished_at else None,
        pages_crawled=scan.pages_crawled, forms_found=scan.forms_found,
        duration_seconds=scan.duration_seconds,
        error_message=scan.error_message,
        result=scan.result_json,
    )


@router.get("/{scan_id}/report")
async def get_scan_report(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Scan, Target)
        .join(Target, Scan.target_id == Target.id)
        .where(Scan.id == scan_id, Target.org_id == current_user["org_id"])
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan, target = row
    if scan.status != ScanStatus.DONE or not scan.result_json:
        raise HTTPException(status_code=404, detail="Report not available yet")

    html = build_html_report(scan.result_json)
    return HTMLResponse(content=html)


def _execute_scan(scan_id: str, url: str, auth_config_dict: dict, max_pages: int, max_depth: int):
    """Run the actual scan in a background thread (sync code)."""
    import sqlite3
    import json
    from config import settings

    # We use sync SQLite here since scanner code is sync
    # In production with PostgreSQL, use Celery workers instead
    db_url = str(settings.DATABASE_URL).replace("sqlite+aiosqlite:///", "")
    conn = sqlite3.connect(db_url)

    try:
        # Set up auth session
        session = None
        pw_cookies = []
        if auth_config_dict:
            auth_conf = AuthConfig.from_dict(dict(auth_config_dict))
            session, pw_cookies, auth_error = create_authenticated_session(url, auth_conf)
            if auth_error:
                conn.execute(
                    "UPDATE scans SET status=?, finished_at=?, error_message=? WHERE id=?",
                    ("ERROR", datetime.now(timezone.utc).isoformat(), f"Auth failed: {auth_error}", scan_id),
                )
                conn.commit()
                return

        # Run checks
        security_findings = run_all_security_checks(url)
        functionality_findings, functionality_summary = run_all_functionality_checks(
            url, max_pages=max_pages, max_depth=max_depth, session=session
        )

        # Capture screenshots for error pages
        screenshots = []
        error_pages = []
        for f in functionality_findings:
            if f["check"] in ("broken_links", "server_errors") and f.get("detail"):
                for item in f["detail"][:10]:
                    page_url = item.get("url", "")
                    if page_url:
                        error_pages.append({"url": page_url, "reason": item.get("reason", "error")})

        if error_pages:
            try:
                screenshots = capture_screenshots(error_pages, scan_id, cookies=pw_cookies)
            except Exception:
                pass

        finished_at = datetime.now(timezone.utc)
        started_row = conn.execute("SELECT started_at FROM scans WHERE id=?", (scan_id,)).fetchone()
        started_at_str = started_row[0] if started_row else finished_at.isoformat()

        result = {
            "url": url,
            "started_at": started_at_str,
            "finished_at": finished_at.isoformat(),
            "security_findings": security_findings,
            "functionality_findings": functionality_findings,
            "functionality_summary": functionality_summary,
            "screenshots": screenshots,
            "authenticated": auth_config_dict is not None,
        }

        # Calculate duration
        try:
            started_dt = datetime.fromisoformat(started_at_str)
            duration = (finished_at - started_dt).total_seconds()
        except (ValueError, TypeError):
            duration = 0

        conn.execute(
            """UPDATE scans SET status=?, finished_at=?, pages_crawled=?,
               forms_found=?, duration_seconds=?, result_json=? WHERE id=?""",
            ("DONE", finished_at.isoformat(), functionality_summary["pages_crawled"],
             functionality_summary["forms_found"], duration, json.dumps(result), scan_id),
        )

        # Store individual findings
        for f in security_findings + functionality_findings:
            category = "security" if f in security_findings else "functionality"
            conn.execute(
                """INSERT INTO findings (id, scan_id, target_id, category, "check",
                   severity, status, title, description, detail)
                   SELECT ?, ?, target_id, ?, ?, ?, ?, ?, ?, ? FROM scans WHERE id=?""",
                (str(__import__('uuid').uuid4()), scan_id, category, f["check"],
                 f["severity"].upper(), "OPEN", f.get("message", ""), f.get("message", ""),
                 json.dumps(f.get("detail", "")), scan_id),
            )

        conn.commit()

    except Exception as e:
        conn.execute(
            "UPDATE scans SET status=?, finished_at=?, error_message=? WHERE id=?",
            ("ERROR", datetime.now(timezone.utc).isoformat(), str(e)[:1000], scan_id),
        )
        conn.commit()
    finally:
        conn.close()
