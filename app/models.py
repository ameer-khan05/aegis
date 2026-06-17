"""Pydantic models for Aegis domain objects."""

from pydantic import BaseModel


class Finding(BaseModel):
    """A security finding from SonarCloud."""

    key: str
    rule: str
    severity: str
    component: str
    line: int | None = None
    message: str
    type: str = "VULNERABILITY"


class SessionResult(BaseModel):
    """Structured output returned by a Devin session."""

    finding_key: str
    fixed: bool
    tests_passed: bool
    pr_url: str | None = None
    failure_reason: str | None = None


class AuditEntry(BaseModel):
    """A single row in the audit log."""

    timestamp: str
    scan_task_id: str
    finding_key: str
    finding_rule: str
    finding_file: str
    severity: str
    github_issue_url: str | None = None
    devin_session_id: str | None = None
    devin_session_url: str | None = None
    status: str = "pending"
    pr_url: str | None = None
    tests_passed: bool | None = None
    failure_reason: str | None = None
    acu_consumed: float = 0.0
    duration_seconds: int | None = None
