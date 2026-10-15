"""Pydantic schemas for scan configuration, results, and findings."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class AuthState(str, Enum):
    VALID = "valid"
    MISSING = "missing"
    INVALID = "invalid"
    EXPIRED = "expired"


class Verdict(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"


class FindingCategory(str, Enum):
    BOLA = "BOLA"
    IDOR = "IDOR"
    BROKEN_ACCESS = "BrokenAccessControl"
    AUTHN = "Authentication"
    ROLE = "RoleEnforcement"
    CONSISTENCY = "Consistency"
    INFO_LEAK = "InfoExposure"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    SUSPICIOUS = "suspicious"
    INCONCLUSIVE = "inconclusive"


class EndpointPolicy(BaseModel):
    id: str = Field(description="Unique endpoint id, e.g. get-user-by-id")
    path: str = Field(description="Path with {id} placeholders, e.g. /api/users/{id}")
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    requires_auth: bool = True
    allowed_roles: List[str] = Field(default_factory=lambda: ["admin", "user"])
    ownership_required: bool = False
    sensitivity: Literal["public", "private", "admin", "write"] = "private"
    description: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    params: Dict[str, str] = Field(default_factory=dict)
    safe_payload: Optional[Dict[str, Any]] = None

    @field_validator("path")
    @classmethod
    def _path_valid(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("path must start with /")
        if " " in v:
            raise ValueError("path must not contain spaces")
        return v


class IdentityConfig(BaseModel):
    name: str = Field(description="e.g. alice, bob, admin, readonly, anonymous")
    role: str = Field(description="e.g. admin, user, readonly, none")
    auth_state: AuthState = AuthState.VALID
    token: Optional[str] = None
    own_resource_id: Optional[str] = None
    other_resource_id: Optional[str] = None
    resources: Dict[str, Dict[str, str]] = Field(
        default_factory=dict,
        description="Per-endpoint resource override, e.g. {'get-order': {'own': 'o_alice1', 'other': 'o_bob1'}}",
    )

    @field_validator("token")
    @classmethod
    def _strip(cls, v: Any) -> Any:
        return v.strip() if isinstance(v, str) else v


class ScanOptions(BaseModel):
    include_destructive: bool = False  # allow PUT/PATCH/DELETE/POST tests
    timeout_secs: float = 10.0
    max_concurrency: int = 5
    rate_delay_secs: float = 0.05
    follow_redirects: bool = False


class ScanRequest(BaseModel):
    target_base_url: str
    endpoints: List[EndpointPolicy]
    identities: List[IdentityConfig]
    options: ScanOptions = ScanOptions()
    confirm_target: bool = Field(description="Operator confirms they may test this target")

    @field_validator("endpoints")
    @classmethod
    def _nonempty(cls, v: List[EndpointPolicy]) -> List[EndpointPolicy]:
        if not v:
            raise ValueError("at least one endpoint is required")
        ids = [e.id for e in v]
        if len(ids) != len(set(ids)):
            raise ValueError("endpoint ids must be unique")
        return v

    @field_validator("identities")
    @classmethod
    def _ident_nonempty(cls, v: List[IdentityConfig]) -> List[IdentityConfig]:
        if not v:
            raise ValueError("at least one identity is required")
        return v


class TestResult(BaseModel):
    test_id: str
    endpoint_id: str
    method: str
    path_rendered: str
    identity: str
    role: str
    auth_state: str
    resource_variant: str = "n/a"  # own | other | n/a
    expected: Literal["allow", "deny"]
    actual_status: Optional[int] = None
    verdict: Verdict = Verdict.INCONCLUSIVE
    leak_detected: bool = False
    body_excerpt: str = ""  # redacted, truncated
    body_keys: List[str] = Field(default_factory=list)
    duration_ms: int = 0
    error: str = ""
    evidence: Dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    finding_id: str
    endpoint_id: str
    method: str
    path: str
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    expected: str
    actual: str
    explanation: str
    reproduction: List[str] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""
    fingerprint: str = ""


class ScanSummary(BaseModel):
    total: int = 0
    passed: int = 0
    failed: int = 0
    inconclusive: int = 0
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_category: Dict[str, int] = Field(default_factory=dict)
    by_endpoint: Dict[str, Dict[str, int]] = Field(default_factory=dict)
    duration_secs: float = 0.0
    started_at: str = ""
    finished_at: str = ""


class ScanRecord(BaseModel):
    scan_id: str
    target_base_url: str
    status: Literal["running", "completed", "failed"] = "running"
    progress: Dict[str, Any] = Field(default_factory=dict)
    summary: ScanSummary = ScanSummary()
    results: List[TestResult] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    config_echo: Dict[str, Any] = Field(default_factory=dict)  # tokens stripped


class DiffEntry(BaseModel):
    fingerprint: str
    status: Literal["new", "resolved", "unchanged"]
    finding: Optional[Finding] = None
