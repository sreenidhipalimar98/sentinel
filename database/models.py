"""SQLAlchemy models for the enterprise platform."""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Boolean, Integer, Float, Text, DateTime,
    ForeignKey, JSON, Enum as SAEnum, Index
)
from sqlalchemy.orm import DeclarativeBase, relationship
import enum


class Base(DeclarativeBase):
    pass


def _uuid():
    return str(uuid.uuid4())


def _now():
    return datetime.now(timezone.utc)


# --- Enums ---

class UserRole(str, enum.Enum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    CANCELLED = "cancelled"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"


class ScheduleFrequency(str, enum.Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


# --- Models ---

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), default="")
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_now)
    last_login = Column(DateTime, nullable=True)

    # Relationships
    memberships = relationship("OrgMember", back_populates="user", cascade="all, delete-orphan")


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    plan = Column(String(50), default="free")  # free, pro, team, enterprise
    max_targets = Column(Integer, default=3)
    max_scans_per_month = Column(Integer, default=10)
    created_at = Column(DateTime, default=_now)

    # Relationships
    members = relationship("OrgMember", back_populates="organization", cascade="all, delete-orphan")
    targets = relationship("Target", back_populates="organization", cascade="all, delete-orphan")


class OrgMember(Base):
    __tablename__ = "org_members"

    id = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    role = Column(SAEnum(UserRole), default=UserRole.ANALYST)
    joined_at = Column(DateTime, default=_now)

    # Relationships
    user = relationship("User", back_populates="memberships")
    organization = relationship("Organization", back_populates="members")

    __table_args__ = (
        Index("ix_org_members_user_org", "user_id", "org_id", unique=True),
    )


class Target(Base):
    __tablename__ = "targets"

    id = Column(String, primary_key=True, default=_uuid)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    url = Column(String(2048), nullable=False)
    name = Column(String(255), default="")  # friendly label
    environment = Column(String(50), default="production")  # production, staging, dev
    auth_config = Column(JSON, nullable=True)  # stored auth settings
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=_now)
    last_scanned_at = Column(DateTime, nullable=True)

    # Relationships
    organization = relationship("Organization", back_populates="targets")
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")
    schedules = relationship("ScheduledScan", back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=_uuid)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    triggered_by = Column(String, ForeignKey("users.id"), nullable=True)  # null = scheduled
    status = Column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    pages_crawled = Column(Integer, default=0)
    forms_found = Column(Integer, default=0)
    duration_seconds = Column(Float, nullable=True)
    error_message = Column(Text, nullable=True)
    config = Column(JSON, nullable=True)  # max_pages, max_depth, etc.
    result_json = Column(JSON, nullable=True)  # full raw result
    created_at = Column(DateTime, default=_now)

    # Relationships
    target = relationship("Target", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_scans_target_status", "target_id", "status"),
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=_uuid)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    category = Column(String(50), nullable=False)  # security, functionality
    check = Column(String(100), nullable=False)  # headers, tls, broken_links, etc.
    severity = Column(SAEnum(FindingSeverity), nullable=False)
    status = Column(SAEnum(FindingStatus), default=FindingStatus.OPEN)
    title = Column(String(500), nullable=False)
    description = Column(Text, default="")
    detail = Column(JSON, nullable=True)
    screenshot_path = Column(String(500), nullable=True)
    first_seen_at = Column(DateTime, default=_now)
    resolved_at = Column(DateTime, nullable=True)
    assigned_to = Column(String, ForeignKey("users.id"), nullable=True)
    notes = Column(Text, default="")

    # Relationships
    scan = relationship("Scan", back_populates="findings")

    __table_args__ = (
        Index("ix_findings_target_status", "target_id", "status"),
        Index("ix_findings_severity", "severity"),
    )


class ScheduledScan(Base):
    __tablename__ = "scheduled_scans"

    id = Column(String, primary_key=True, default=_uuid)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    frequency = Column(SAEnum(ScheduleFrequency), nullable=False)
    is_active = Column(Boolean, default=True)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    config = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=_now)

    # Relationships
    target = relationship("Target", back_populates="schedules")
