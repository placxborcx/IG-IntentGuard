"""Tests for IntentGuard data models."""

from datetime import datetime, timedelta
from intentguard.models import (
    TaskSession,
    ScanResult,
    ChangedFile,
    AuditEvent,
    Approval,
    RiskLevel,
    Decision,
    ChangeType,
)


def test_task_session_creation():
    """Test creating a task session."""
    task = TaskSession(
        task_id="task_001",
        intent="Fix login bug",
        agent="claude-code",
        allowed_paths=["src/auth/**", "tests/**"],
    )
    assert task.task_id == "task_001"
    assert task.intent == "Fix login bug"
    assert task.agent == "claude-code"
    assert len(task.allowed_paths) == 2
    assert task.status == "active"


def test_changed_file_creation():
    """Test creating a changed file record."""
    file = ChangedFile(
        path=".env",
        change_type=ChangeType.MODIFIED,
        risk=RiskLevel.HIGH,
        decision=Decision.BLOCK,
        reason="Hard-blocked path: .env file contains secrets",
    )
    assert file.path == ".env"
    assert file.change_type == ChangeType.MODIFIED
    assert file.risk == RiskLevel.HIGH
    assert file.decision == Decision.BLOCK


def test_scan_result_creation():
    """Test creating a scan result."""
    scan = ScanResult(
        scan_id="scan_001",
        task_id="task_001",
        repo_path="/tmp/repo",
        changed_files=[
            ChangedFile(
                path=".env",
                change_type=ChangeType.MODIFIED,
                risk=RiskLevel.HIGH,
                decision=Decision.BLOCK,
                reason="Hard-blocked path",
            ),
        ],
        overall_risk=RiskLevel.HIGH,
        final_decision=Decision.BLOCK,
    )
    assert scan.scan_id == "scan_001"
    assert len(scan.changed_files) == 1
    assert scan.final_decision == Decision.BLOCK


def test_audit_event_creation():
    """Test creating an audit event."""
    event = AuditEvent(
        event_id="evt_001",
        task_id="task_001",
        scan_id="scan_001",
        agent="claude-code",
        action="scan",
        target=".env",
        risk=RiskLevel.HIGH,
        decision=Decision.BLOCK,
        reason="Hard-blocked path",
    )
    assert event.event_id == "evt_001"
    assert event.action == "scan"
    assert event.decision == Decision.BLOCK


def test_approval_creation():
    """Test creating an approval record."""
    expires_at = datetime.utcnow() + timedelta(minutes=30)
    approval = Approval(
        approval_id="apr_001",
        scan_id="scan_001",
        task_id="task_001",
        approved_files=[".github/workflows/deploy.yml"],
        approver="user@example.com",
        reason="CI/CD change is intentional",
        expires_at=expires_at,
    )
    assert approval.approval_id == "apr_001"
    assert len(approval.approved_files) == 1
    assert approval.expires_at > datetime.utcnow()
