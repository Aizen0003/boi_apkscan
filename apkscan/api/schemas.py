"""API request/response models."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


class LoginRequest(BaseModel):
    username: str
    password: str


class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "analyst"


class UserResponse(BaseModel):
    username: str
    role: str
    is_active: bool


class UploadResponse(BaseModel):
    sample_sha256: str
    job_id: str
    deduped: bool
    reused_job: bool
    status: str


class JobStatusResponse(BaseModel):
    job_id: str
    sample_sha256: str
    status: str
    priority: str
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error: Optional[str] = None
    report_id: Optional[str] = None


class SignOffRequest(BaseModel):
    decision: str  # approve | reject
    note: str = ""


class ReportSummary(BaseModel):
    report_id: str
    sample_sha256: str
    verdict: str
    severity: str
    risk_score: float
    confidence: float
    status: str
    requires_signoff: bool


class ExportResponse(BaseModel):
    sample_sha256: str
    verdict: str
    severity: str
    risk_score: float
    confidence: float
    attack_techniques: List[str]
    iocs: dict
    stix_bundle: dict
