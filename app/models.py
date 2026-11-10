"""Pydantic models for SecretScope."""
from pydantic import BaseModel


class ScanTarget(BaseModel):
    url: str | None = None
    domain: str | None = None


class Finding(BaseModel):
    id: int | None = None
    scan_id: int | None = None
    url: str
    pattern_name: str
    severity: str  # critical, high, medium, low
    redacted_value: str
    line_number: int
    context_snippet: str = ""
    validated: bool = False
    validation_note: str = ""


class ScanResult(BaseModel):
    id: int | None = None
    target: str
    scan_type: str
    timestamp: str
    finding_count: int = 0
    findings: list[Finding] = []


class ScopeUpdate(BaseModel):
    domains: list[str]
