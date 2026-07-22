"""API route registration."""
from fastapi import APIRouter

from .auth_routes import router as auth_router
from .targets_routes import router as targets_router
from .scans_routes import router as scans_router
from .findings_routes import router as findings_router
from .org_routes import router as org_router

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth_router)
api_router.include_router(org_router)
api_router.include_router(targets_router)
api_router.include_router(scans_router)
api_router.include_router(findings_router)
