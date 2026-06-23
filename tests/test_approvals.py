from __future__ import annotations

from datetime import UTC, datetime, timedelta

from intentguard.approvals import (
    append_approval,
    load_approvals,
    make_approval_id,
    build_approval_expiry,
    is_approval_expired,
    approval_required_files,
    build_approval_record,
    scan_has_blocking_decision,
)


def test_make_approval_id_uses_apr_prefix() -> None:
    approval_id = make_approval_id()

    assert approval_id.startswith("apr_")
    assert len(approval_id) > len("apr_")


def test_load_approvals_returns_empty_list_when_file_missing(tmp_path) -> None:
    approvals_path = tmp_path / "approvals.json"

    approvals = load_approvals(approvals_path)

    assert approvals == []


def test_append_approval_creates_file_and_stores_record(tmp_path) -> None:
    approvals_path = tmp_path / "approvals.json"
    now = datetime.now(UTC).replace(microsecond=0)

    approval = {
        "approval_id": "apr_001",
        "scan_id": "scan_001",
        "task_id": "task_001",
        "approved_files": [".github/workflows/deploy.yml"],
        "approver": "human",
        "reason": "Manual review approved.",
        "expires_at": (now + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
        "created_at": now.isoformat().replace("+00:00", "Z"),
    }

    append_approval(approvals_path, approval)

    approvals = load_approvals(approvals_path)

    assert len(approvals) == 1
    assert approvals[0]["approval_id"] == "apr_001"
    assert approvals[0]["scan_id"] == "scan_001"
    assert approvals[0]["approved_files"] == [".github/workflows/deploy.yml"]


def test_append_approval_appends_without_overwriting(tmp_path) -> None:
    approvals_path = tmp_path / "approvals.json"

    first = {
        "approval_id": "apr_001",
        "scan_id": "scan_001",
        "task_id": None,
        "approved_files": ["infra/main.tf"],
        "approver": "human",
        "reason": "First approval.",
        "expires_at": "2026-05-26T10:30:00Z",
        "created_at": "2026-05-26T10:00:00Z",
    }
    second = {
        "approval_id": "apr_002",
        "scan_id": "scan_002",
        "task_id": None,
        "approved_files": [".github/workflows/deploy.yml"],
        "approver": "human",
        "reason": "Second approval.",
        "expires_at": "2026-05-26T10:31:00Z",
        "created_at": "2026-05-26T10:01:00Z",
    }

    append_approval(approvals_path, first)
    append_approval(approvals_path, second)

    approvals = load_approvals(approvals_path)

    assert [approval["approval_id"] for approval in approvals] == [
        "apr_001",
        "apr_002",
    ]


def test_build_approval_expiry_uses_ttl_minutes() -> None:
    created_at = datetime(2026, 5, 26, 10, 0, 0, tzinfo=UTC)

    expires_at = build_approval_expiry(
        created_at=created_at,
        ttl_minutes=30,
    )

    assert expires_at == "2026-05-26T10:30:00Z"


def test_is_approval_expired_returns_false_before_expiry() -> None:
    now = datetime(2026, 5, 26, 10, 10, 0, tzinfo=UTC)

    approval = {
        "expires_at": "2026-05-26T10:30:00Z",
    }

    assert is_approval_expired(approval, now=now) is False


def test_is_approval_expired_returns_true_after_expiry() -> None:
    now = datetime(2026, 5, 26, 10, 31, 0, tzinfo=UTC)

    approval = {
        "expires_at": "2026-05-26T10:30:00Z",
    }

    assert is_approval_expired(approval, now=now) is True


def test_approval_required_files_returns_require_approval_paths_only() -> None:
    scan_record = {
        "scan_id": "scan_001",
        "changed_files": [
            {
                "path": ".github/workflows/deploy.yml",
                "decision": "REQUIRE_APPROVAL",
            },
            {
                "path": ".env",
                "decision": "BLOCK",
            },
            {
                "path": "README.md",
                "decision": "ALLOW_WITH_AUDIT",
            },
        ],
    }

    files = approval_required_files(scan_record)

    assert files == [".github/workflows/deploy.yml"]


def test_approval_required_files_returns_empty_when_no_approval_needed() -> None:
    scan_record = {
        "scan_id": "scan_001",
        "changed_files": [
            {
                "path": ".env",
                "decision": "BLOCK",
            },
            {
                "path": "README.md",
                "decision": "ALLOW_WITH_AUDIT",
            },
        ],
    }

    files = approval_required_files(scan_record)

    assert files == []


def test_build_approval_record_uses_scan_metadata_and_ttl() -> None:
    created_at = datetime(2026, 5, 26, 10, 0, 0, tzinfo=UTC)
    scan_record = {
        "scan_id": "scan_001",
        "task_id": "task_001",
    }

    approval = build_approval_record(
        scan_record=scan_record,
        approved_files=[".github/workflows/deploy.yml"],
        approver="human",
        reason="Manual review approved.",
        ttl_minutes=30,
        created_at=created_at,
    )

    assert approval["approval_id"].startswith("apr_")
    assert approval["scan_id"] == "scan_001"
    assert approval["task_id"] == "task_001"
    assert approval["approved_files"] == [".github/workflows/deploy.yml"]
    assert approval["approver"] == "human"
    assert approval["reason"] == "Manual review approved."
    assert approval["created_at"] == "2026-05-26T10:00:00Z"
    assert approval["expires_at"] == "2026-05-26T10:30:00Z"


def test_scan_has_blocking_decision_returns_true_for_blocked_file() -> None:
    scan_record = {
        "scan_id": "scan_001",
        "changed_files": [
            {
                "path": ".env",
                "decision": "BLOCK",
            },
            {
                "path": ".github/workflows/deploy.yml",
                "decision": "REQUIRE_APPROVAL",
            },
        ],
    }

    assert scan_has_blocking_decision(scan_record) is True


def test_scan_has_blocking_decision_returns_false_without_blocked_file() -> None:
    scan_record = {
        "scan_id": "scan_001",
        "changed_files": [
            {
                "path": ".github/workflows/deploy.yml",
                "decision": "REQUIRE_APPROVAL",
            },
        ],
    }

    assert scan_has_blocking_decision(scan_record) is False