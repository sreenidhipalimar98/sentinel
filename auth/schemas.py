"""Pydantic schemas for auth endpoints."""
from pydantic import BaseModel, EmailStr
from typing import Optional


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: str = ""
    org_name: Optional[str] = None  # Creates an org on signup if provided


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    org_id: Optional[str] = None


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    is_active: bool
    org_id: Optional[str] = None
    org_name: Optional[str] = None
    role: Optional[str] = None
