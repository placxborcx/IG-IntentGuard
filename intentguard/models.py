"""Pydantic data models for IntentGuard."""

from datetime import datetime
from typing import List, Optional
from enum import Enum

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    """Risk levels for changes."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Decision(str, Enum):
    """Decision types for file changes."""

    ALLOW_WITH_AUDIT = "ALLOW_WITH_AUDIT"
    WARN_OUT_OF_SCOPE = "WARN_OUT_OF_SCOPE"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"


class ChangeType(str, Enum):
    """Git change types."""

    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"


class TaskSession(BaseModel):
    """Task session for an AI coding task."""

    task_id: str
    intent: str
    agent: Optional[str] = None
    allowed_paths: List[str] = Field(default_factory=list)
    blocked_paths: List[str] = Field(default_factory=list)
    allowed_deploy_target: str = "none"  # none | staging | production
    status: str = "active"  # active | completed | archived
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ChangedFile(BaseModel):
    """A file that changed in Git."""

    path: str
    change_type: ChangeType
    risk: RiskLevel
    decision: Decision
    reason: str


class ScanResult(BaseModel):
    """Result of a diff scan."""

    scan_id: str
    task_id: Optional[str] = None
    repo_path: str
    changed_files: List[ChangedFile] = Field(default_factory=list)
    overall_risk: RiskLevel = RiskLevel.LOW
    final_decision: Decision = Decision.ALLOW_WITH_AUDIT
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AuditEvent(BaseModel):
    """Audit event for policy decisions."""

    event_id: str
    task_id: Optional[str] = None
    scan_id: Optional[str] = None
    agent: Optional[str] = None
    action: str
    target: str
    risk: RiskLevel
    decision: Decision
    reason: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class Approval(BaseModel):
    """Approval record for a scan."""

    approval_id: str
    scan_id: str
    task_id: Optional[str] = None
    approved_files: List[str] = Field(default_factory=list)
    approver: str
    reason: str
    expires_at: datetime
    created_at: datetime = Field(default_factory=datetime.utcnow)


class FileChangeType(str, Enum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"
    COPIED = "copied"
    TYPE_CHANGED = "type_changed"
    UNMERGED = "unmerged"
    UNKNOWN = "unknown"


class ScannedFile(BaseModel):
    path: str
    change_type: FileChangeType
    is_staged: bool
    old_path: Optional[str] = None
    is_binary: Optional[bool] = None
    secret_findings: List[dict] = Field(default_factory=list)


class DiffScanResult(BaseModel):
    scan_id: str
    task_id: Optional[str] = None
    is_staged: bool
    changed_files: List[ScannedFile] = Field(default_factory=list)
    git_root: Optional[str] = None
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    error: Optional[str] = None

    @property
    def has_error(self) -> bool:
        return self.error is not None
